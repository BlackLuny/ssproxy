use std::collections::VecDeque;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::config::{ClientConfig, ServerConfig};
use crate::crypto::{derive_block, padding_len, CipherKind, DirectionKeys, MAX_PACKET};
use crate::error::{Error, Result};
use crate::proto::msg::{
    list_has, negotiate, KexInit, CLIENT_KEX, SERVER_CIPHERS, SERVER_COMP, SERVER_HOST_KEY,
    SERVER_KEX, SERVER_MACS,
};
use crate::proto::*;
use crate::wire::{self, Parser};

use super::channel::{Channel, ChannelKind, ChannelTable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

#[derive(Debug)]
pub enum Event {
    HandshakeComplete {
        user: String,
    },
    OpenDirectTcpIp {
        local_id: u32,
        host: String,
        port: u32,
    },
    OpenSession {
        local_id: u32,
    },
    ChannelOpenConfirmation {
        local_id: u32,
    },
    ChannelOpenFailure {
        local_id: u32,
        reason: u32,
        message: String,
    },
    ChannelData {
        local_id: u32,
    },
    ChannelEof {
        local_id: u32,
    },
    ChannelClose {
        local_id: u32,
    },
    Disconnect {
        reason: u32,
        message: String,
    },
}

struct PendingKeys {
    send: DirectionKeys,
    recv: DirectionKeys,
}

struct KexState {
    ours: KexInit,
    theirs: Option<KexInit>,
    secret: Option<EphemeralSecret>,
    local_pub: Option<[u8; 32]>,
    cipher_c2s: Option<CipherKind>,
    cipher_s2c: Option<CipherKind>,
}

pub struct Connection {
    role: Role,
    server: Option<Arc<ServerConfig>>,
    client: Option<Arc<ClientConfig>>,
    ident_local: String,
    ident_peer: Option<String>,
    ident_acc: Vec<u8>,
    ident_in_done: bool,
    ident_out: Option<Bytes>,
    read_buf: BytesMut,
    send_seq: u32,
    recv_seq: u32,
    send_cipher: DirectionKeys,
    recv_cipher: DirectionKeys,
    bytes_io: u64,
    packets_io: u32,
    strict_kex: bool,
    peer_ext_info: bool,
    session_id: Option<Vec<u8>>,
    last_h: Option<Vec<u8>>,
    peer_ks: Option<Vec<u8>>,
    kex: Option<KexState>,
    pending_keys: Option<PendingKeys>,
    sent_kexinit: bool,
    sent_newkeys: bool,
    recv_newkeys: bool,
    /// Single FIFO of already-sealed packets. A priority/data split would
    /// let WINDOW_ADJUST or KEXINIT overtake CHANNEL_DATA and desync seq/MAC.
    write_q: VecDeque<Bytes>,
    current_out: Option<Bytes>,
    current_is_ident: bool,
    write_bytes: usize,
    write_soft: usize,
    write_hard: usize,
    rekey_after_bytes: u64,
    rekey_after_packets: u32,
    channels: ChannelTable,
    window: u32,
    max_packet: u32,
    events: VecDeque<Event>,
    auth_fails: u32,
    user: Option<String>,
    authed: bool,
    closed: bool,
    kex_blocks_app: bool,
    first_kex_done: bool,
    rr: u32,
}

impl Connection {
    pub fn server(cfg: Arc<ServerConfig>) -> Self {
        let ident = cfg.ident.clone();
        let mut c = Self::new(
            Role::Server,
            ident,
            cfg.write_buf_soft,
            cfg.write_buf_hard,
            cfg.rekey_after_bytes,
            cfg.rekey_after_packets,
            cfg.max_channels,
            cfg.window,
            cfg.max_packet,
        );
        c.server = Some(cfg);
        c.queue_ident();
        c
    }

    pub fn client(cfg: Arc<ClientConfig>) -> Self {
        let ident = cfg.ident.clone();
        let mut c = Self::new(
            Role::Client,
            ident,
            cfg.write_buf_soft,
            cfg.write_buf_hard,
            cfg.rekey_after_bytes,
            cfg.rekey_after_packets,
            256,
            cfg.window,
            cfg.max_packet,
        );
        c.client = Some(cfg);
        c.queue_ident();
        c
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        role: Role,
        ident: String,
        write_soft: usize,
        write_hard: usize,
        rekey_after_bytes: u64,
        rekey_after_packets: u32,
        max_channels: u32,
        window: u32,
        max_packet: u32,
    ) -> Self {
        Self {
            role,
            server: None,
            client: None,
            ident_local: ident,
            ident_peer: None,
            ident_acc: Vec::new(),
            ident_in_done: false,
            ident_out: None,
            read_buf: BytesMut::with_capacity(64 * 1024),
            send_seq: 0,
            recv_seq: 0,
            send_cipher: DirectionKeys::Clear,
            recv_cipher: DirectionKeys::Clear,
            bytes_io: 0,
            packets_io: 0,
            strict_kex: false,
            peer_ext_info: false,
            session_id: None,
            last_h: None,
            peer_ks: None,
            kex: None,
            pending_keys: None,
            sent_kexinit: false,
            sent_newkeys: false,
            recv_newkeys: false,
            write_q: VecDeque::new(),
            current_out: None,
            current_is_ident: false,
            write_bytes: 0,
            write_soft,
            write_hard,
            rekey_after_bytes,
            rekey_after_packets,
            channels: ChannelTable::new(max_channels),
            window,
            max_packet,
            events: VecDeque::new(),
            auth_fails: 0,
            user: None,
            authed: false,
            closed: false,
            kex_blocks_app: false,
            first_kex_done: false,
            rr: 0,
        }
    }

    fn queue_ident(&mut self) {
        let s = format!("{}\r\n", self.ident_local);
        self.ident_out = Some(Bytes::from(s.into_bytes()));
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn is_finished(&self) -> bool {
        self.closed && !self.wants_write()
    }

    pub fn authed(&self) -> bool {
        self.authed
    }

    pub fn wants_write(&self) -> bool {
        self.ident_out.as_ref().is_some_and(|b| !b.is_empty())
            || self.current_out.as_ref().is_some_and(|b| !b.is_empty())
            || !self.write_q.is_empty()
    }

    pub fn queued_write_bytes(&self) -> usize {
        let ident = if self.current_is_ident {
            self.current_out.as_ref().map(|b| b.len()).unwrap_or(0)
        } else {
            0
        };
        self.write_bytes + ident + self.ident_out.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    fn pull_current_out(&mut self) {
        if self.current_out.as_ref().is_some_and(|b| b.is_empty()) {
            self.current_out = None;
            self.current_is_ident = false;
        }
        if self.current_out.is_some() {
            return;
        }
        if let Some(b) = self.ident_out.take() {
            if !b.is_empty() {
                self.current_out = Some(b);
                self.current_is_ident = true;
                return;
            }
        }
        self.current_is_ident = false;
        if let Some(b) = self.write_q.pop_front() {
            self.current_out = Some(b);
        }
    }

    pub fn peek_out(&mut self) -> Option<&[u8]> {
        self.pull_current_out();
        self.current_out
            .as_ref()
            .filter(|b| !b.is_empty())
            .map(|b| b.as_ref())
    }

    pub fn consume_out(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        self.pull_current_out();
        let Some(b) = self.current_out.as_mut() else {
            return;
        };
        let take = n.min(b.len());
        let was_ident = self.current_is_ident;
        if take == b.len() {
            self.current_out = None;
            self.current_is_ident = false;
        } else {
            let _ = b.split_to(take);
        }
        if !was_ident {
            self.write_bytes = self.write_bytes.saturating_sub(take);
        }
        if self.current_out.is_none() && was_ident {
            self.maybe_start_kex();
        }
    }

    fn maybe_start_kex(&mut self) {
        if self.ident_out.is_none() && self.ident_in_done && !self.sent_kexinit {
            let _ = self.start_kex();
        }
    }

    pub fn read_buf_mut(&mut self) -> &mut BytesMut {
        if self.read_buf.capacity() - self.read_buf.len() < 16 * 1024 {
            self.read_buf.reserve(64 * 1024);
        }
        &mut self.read_buf
    }

    pub fn process_in(&mut self) -> Result<()> {
        if !self.ident_in_done {
            self.try_ident()?;
            if self.ident_in_done {
                self.maybe_start_kex();
            } else {
                return Ok(());
            }
        }
        while self.try_one_packet()? {}
        self.maybe_rekey();
        self.flush_pending_all();
        Ok(())
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn peek_inbound(&self, local_id: u32) -> Option<&[u8]> {
        self.channels
            .get(local_id)
            .ok()
            .and_then(|c| c.in_q.front().map(|b| b.as_ref()))
    }

    pub fn consume_inbound(&mut self, local_id: u32, n: usize) {
        {
            let Ok(ch) = self.channels.get_mut(local_id) else {
                return;
            };
            let Some(front) = ch.in_q.front_mut() else {
                return;
            };
            let take = n.min(front.len());
            if take == front.len() {
                let b = ch.in_q.pop_front().unwrap();
                ch.in_q_bytes = ch.in_q_bytes.saturating_sub(b.len());
            } else {
                let _ = front.split_to(take);
                ch.in_q_bytes = ch.in_q_bytes.saturating_sub(take);
            }
        }
        self.maybe_adjust(local_id);
    }

    pub fn outbound_allowance(&self, local_id: u32) -> usize {
        let Ok(ch) = self.channels.get(local_id) else {
            return 0;
        };
        let pend_room = (256 * 1024usize).saturating_sub(ch.pending_out_bytes);
        if self.kex_blocks_app {
            return pend_room.min(self.max_packet as usize);
        }
        if self.queued_write_bytes() >= self.write_soft {
            return 0;
        }
        ch.outbound_allowance().min(pend_room)
    }

    pub fn send_data(&mut self, local_id: u32, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut sent = 0;
        while sent < data.len() {
            let allow = self.outbound_allowance(local_id);
            if allow == 0 {
                break;
            }
            let n = allow.min(data.len() - sent);
            let chunk = Bytes::copy_from_slice(&data[sent..sent + n]);
            self.enqueue_or_send(local_id, chunk)?;
            sent += n;
        }
        Ok(sent)
    }

    pub fn send_eof(&mut self, local_id: u32) -> Result<()> {
        {
            let ch = self.channels.get_mut(local_id)?;
            if ch.sent_eof || ch.sent_close {
                return Ok(());
            }
            ch.sent_eof = true;
        }
        self.emit_eof_if_ready(local_id)
    }

    pub fn send_close(&mut self, local_id: u32) -> Result<()> {
        {
            let ch = self.channels.get_mut(local_id)?;
            if ch.sent_close {
                return Ok(());
            }
            ch.sent_close = true;
            ch.sent_eof = true;
        }
        self.emit_close_if_ready(local_id)
    }

    fn emit_eof_if_ready(&mut self, local_id: u32) -> Result<()> {
        if self.kex_blocks_app {
            return Ok(());
        }
        let remote = {
            let Ok(ch) = self.channels.get_mut(local_id) else {
                return Ok(());
            };
            if !ch.sent_eof || ch.wire_eof {
                return Ok(());
            }
            ch.wire_eof = true;
            ch.remote_id
        };
        if let Some(r) = remote {
            let mut p = vec![SSH_MSG_CHANNEL_EOF];
            wire::put_u32(&mut p, r);
            self.queue_msg(&p, true)?;
        }
        Ok(())
    }

    fn emit_close_if_ready(&mut self, local_id: u32) -> Result<()> {
        if self.kex_blocks_app {
            return Ok(());
        }
        let remote = {
            let Ok(ch) = self.channels.get_mut(local_id) else {
                return Ok(());
            };
            if !ch.sent_close {
                return Ok(());
            }
            if ch.wire_close {
                None
            } else {
                ch.wire_close = true;
                ch.wire_eof = true;
                ch.remote_id
            }
        };
        if let Some(r) = remote {
            let mut p = vec![SSH_MSG_CHANNEL_CLOSE];
            wire::put_u32(&mut p, r);
            self.queue_msg(&p, true)?;
        }
        if self
            .channels
            .get(local_id)
            .map(|c| c.got_close && c.wire_close)
            .unwrap_or(false)
        {
            self.channels.free(local_id);
        }
        Ok(())
    }

    pub fn confirm_open(&mut self, local_id: u32) -> Result<()> {
        let (remote, window, max_pkt) = {
            let ch = self.channels.get_mut(local_id)?;
            ch.open_confirmed = true;
            (
                ch.remote_id
                    .ok_or(Error::protocol("confirm without remote"))?,
                ch.recv_max,
                ch.max_local_packet,
            )
        };
        let mut p = vec![SSH_MSG_CHANNEL_OPEN_CONFIRMATION];
        wire::put_u32(&mut p, remote);
        wire::put_u32(&mut p, local_id);
        wire::put_u32(&mut p, window);
        wire::put_u32(&mut p, max_pkt);
        self.queue_msg(&p, true)
    }

    pub fn fail_open(&mut self, local_id: u32, reason: u32, msg: &str) -> Result<()> {
        let remote = {
            let ch = self.channels.get(local_id)?;
            ch.remote_id.ok_or(Error::protocol("fail without remote"))?
        };
        let mut p = vec![SSH_MSG_CHANNEL_OPEN_FAILURE];
        wire::put_u32(&mut p, remote);
        wire::put_u32(&mut p, reason);
        wire::put_str(&mut p, msg);
        wire::put_str(&mut p, "");
        self.channels.free(local_id);
        self.queue_msg(&p, true)
    }

    pub fn open_direct_tcpip(&mut self, host: &str, port: u32) -> Result<u32> {
        if self.role != Role::Client || !self.authed {
            return Err(Error::protocol("open_direct before ready"));
        }
        let mut ch = Channel::new(
            0,
            ChannelKind::DirectTcpIp,
            self.window,
            self.max_packet,
            0,
            0,
        );
        ch.host = Some(host.to_string());
        ch.port = port;
        let id = self.channels.alloc(ch)?;
        let mut p = vec![SSH_MSG_CHANNEL_OPEN];
        wire::put_str(&mut p, "direct-tcpip");
        wire::put_u32(&mut p, id);
        wire::put_u32(&mut p, self.window);
        wire::put_u32(&mut p, self.max_packet);
        wire::put_str(&mut p, host);
        wire::put_u32(&mut p, port);
        wire::put_str(&mut p, "127.0.0.1");
        wire::put_u32(&mut p, 0);
        self.queue_msg(&p, true)?;
        Ok(id)
    }

    pub fn channel_kind(&self, id: u32) -> Option<ChannelKind> {
        self.channels.get(id).ok().map(|c| c.kind)
    }

    pub fn channel_got_eof(&self, id: u32) -> bool {
        self.channels.get(id).map(|c| c.got_eof).unwrap_or(true)
    }

    pub fn channel_alive(&self, id: u32) -> bool {
        self.channels.get(id).is_ok()
    }

    pub fn round_robin_ids(&mut self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.channels.iter_ids().collect();
        if ids.is_empty() {
            return ids;
        }
        let n = ids.len();
        let start = (self.rr as usize) % n;
        self.rr = self.rr.wrapping_add(1);
        ids.rotate_left(start);
        ids
    }

    fn enqueue_or_send(&mut self, local_id: u32, chunk: Bytes) -> Result<()> {
        let (remote, can_wire, max_pkt, send_window) = {
            let ch = self.channels.get(local_id)?;
            (
                ch.remote_id,
                ch.open_confirmed && !self.kex_blocks_app && !ch.sent_eof,
                ch.max_remote_packet,
                ch.send_window,
            )
        };
        if !can_wire || remote.is_none() || send_window == 0 {
            let ch = self.channels.get_mut(local_id)?;
            ch.pending_out_bytes += chunk.len();
            ch.pending_out.push_back(chunk);
            return Ok(());
        }
        let remote = remote.unwrap();
        let n = chunk.len().min(max_pkt as usize).min(send_window as usize);
        if n < chunk.len() {
            let ch = self.channels.get_mut(local_id)?;
            let rest = chunk.slice(n..);
            ch.pending_out.push_front(rest);
            ch.pending_out_bytes += chunk.len() - n;
        }
        {
            let ch = self.channels.get_mut(local_id)?;
            ch.send_window -= n as u32;
        }
        self.send_channel_data_pkt(remote, &chunk[..n])
    }

    fn send_channel_data_pkt(&mut self, remote: u32, data: &[u8]) -> Result<()> {
        let mut p = Vec::with_capacity(9 + data.len());
        p.push(SSH_MSG_CHANNEL_DATA);
        wire::put_u32(&mut p, remote);
        wire::put_bytes(&mut p, data);
        self.queue_msg(&p, false)
    }

    fn flush_pending_all(&mut self) {
        if self.kex_blocks_app {
            return;
        }
        let ids: Vec<u32> = self.channels.iter_ids().collect();
        for id in ids {
            self.flush_pending(id);
        }
    }

    fn flush_pending(&mut self, local_id: u32) {
        if self.kex_blocks_app {
            return;
        }
        loop {
            let (remote, n, max_pkt, window, confirmed, sent_eof) = {
                let Ok(ch) = self.channels.get(local_id) else {
                    return;
                };
                (
                    ch.remote_id,
                    ch.pending_out.front().map(|b| b.len()).unwrap_or(0),
                    ch.max_remote_packet,
                    ch.send_window,
                    ch.open_confirmed,
                    ch.sent_eof,
                )
            };
            if !confirmed || sent_eof || remote.is_none() || window == 0 || n == 0 {
                return;
            }
            if self.queued_write_bytes() >= self.write_soft {
                return;
            }
            let take = n.min(max_pkt as usize).min(window as usize);
            let chunk = {
                let ch = match self.channels.get_mut(local_id) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let front = match ch.pending_out.front_mut() {
                    Some(f) => f,
                    None => return,
                };
                let b = if take >= front.len() {
                    ch.pending_out.pop_front().unwrap()
                } else {
                    front.split_to(take)
                };
                ch.pending_out_bytes = ch.pending_out_bytes.saturating_sub(b.len());
                ch.send_window -= b.len() as u32;
                b
            };
            if self.send_channel_data_pkt(remote.unwrap(), &chunk).is_err() {
                return;
            }
        }
    }

    fn maybe_adjust(&mut self, local_id: u32) {
        if self.kex_blocks_app {
            return;
        }
        let (remote, add) = {
            let Ok(ch) = self.channels.get(local_id) else {
                return;
            };
            (ch.remote_id, ch.window_adjust_amount())
        };
        if add == 0 {
            return;
        }
        if let Ok(ch) = self.channels.get_mut(local_id) {
            ch.recv_window += add;
        }
        if let Some(r) = remote {
            let mut p = vec![SSH_MSG_CHANNEL_WINDOW_ADJUST];
            wire::put_u32(&mut p, r);
            wire::put_u32(&mut p, add);
            let _ = self.queue_msg(&p, true);
        }
    }

    fn try_ident(&mut self) -> Result<()> {
        if !self.read_buf.is_empty() {
            self.ident_acc.extend_from_slice(&self.read_buf);
            self.read_buf.clear();
        }
        let Some(pos) = self.ident_acc.iter().position(|&b| b == b'\n') else {
            if self.ident_acc.len() > 255 {
                return Err(Error::protocol("ident too long"));
            }
            return Ok(());
        };
        if pos > 254 {
            return Err(Error::protocol("ident too long"));
        }
        let mut line: Vec<u8> = self.ident_acc.drain(..=pos).collect();
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let s = std::str::from_utf8(&line).map_err(|_| Error::protocol("ident utf8"))?;
        if !s.starts_with("SSH-2.0-") && !s.starts_with("SSH-1.99-") {
            return Err(Error::protocol("unsupported ident"));
        }
        self.ident_peer = Some(s.to_string());
        self.ident_in_done = true;
        if !self.ident_acc.is_empty() {
            self.read_buf.extend_from_slice(&self.ident_acc);
            self.ident_acc.clear();
        }
        Ok(())
    }

    fn start_kex(&mut self) -> Result<()> {
        let kex_list = match self.role {
            Role::Server => SERVER_KEX,
            Role::Client => CLIENT_KEX,
        };
        let ours = KexInit::build(kex_list, SERVER_HOST_KEY, SERVER_CIPHERS, SERVER_MACS);
        self.queue_msg(&ours.raw, true)?;
        self.sent_kexinit = true;
        self.sent_newkeys = false;
        self.recv_newkeys = false;
        self.kex_blocks_app = true;
        let mut secret = None;
        let mut local_pub = None;
        if self.role == Role::Client {
            let s = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
            let p = PublicKey::from(&s);
            local_pub = Some(*p.as_bytes());
            secret = Some(s);
        }
        self.kex = Some(KexState {
            ours,
            theirs: None,
            secret,
            local_pub,
            cipher_c2s: None,
            cipher_s2c: None,
        });
        Ok(())
    }

    fn maybe_rekey(&mut self) {
        if !self.authed || !self.first_kex_done || self.closed {
            return;
        }
        if self.kex.is_some() || self.kex_blocks_app || self.sent_kexinit {
            return;
        }
        // Only the server starts rekey. The client still responds to KEXINIT.
        // Bidirectional initiate on an echo path hits the threshold together
        // and used to interleave NEWKEYS with already-sealed CHANNEL_DATA.
        if self.role != Role::Server {
            return;
        }
        if self.bytes_io >= self.rekey_after_bytes || self.packets_io >= self.rekey_after_packets {
            let _ = self.start_kex();
        }
    }

    fn try_one_packet(&mut self) -> Result<bool> {
        if self.read_buf.len() < 4 {
            return Ok(false);
        }
        let enc_len: [u8; 4] = self.read_buf[..4].try_into().unwrap();
        let plain_len_bytes = self.recv_cipher.decrypt_length(self.recv_seq, enc_len);
        let length = u32::from_be_bytes(plain_len_bytes);
        if length < 4 || length as usize > MAX_PACKET {
            return Err(Error::proto_fmt(format!(
                "bad packet length {length} seq={} cipher={:?}",
                self.recv_seq,
                self.recv_cipher.kind()
            )));
        }
        let tag = self.recv_cipher.kind().tag_len();
        let total = 4 + length as usize + tag;
        if self.read_buf.len() < total {
            return Ok(false);
        }
        let mut pkt = self.read_buf.split_to(total);
        let body_end = 4 + length as usize;
        {
            let (body, tagb) = pkt.split_at_mut(body_end);
            self.recv_cipher.open(self.recv_seq, body, tagb)?;
            body[..4].copy_from_slice(&plain_len_bytes);
        }
        let pad = pkt[4] as usize;
        if pad < 4 {
            return Err(Error::protocol("bad padding"));
        }
        if 1 + pad >= length as usize {
            return Err(Error::protocol("padding vs length"));
        }
        let payload_end = 4 + length as usize - pad;
        let mut payload = pkt.split_off(5);
        payload.truncate(payload_end - 5);
        let payload = payload.freeze();
        if payload.is_empty() {
            return Err(Error::protocol("empty payload"));
        }
        self.recv_seq = self.recv_seq.wrapping_add(1);
        self.bytes_io += total as u64;
        self.packets_io = self.packets_io.wrapping_add(1);
        let msg = payload[0];
        if self.strict_kex && !self.first_kex_done {
            if is_transport_ignore(msg) {
                return Err(Error::protocol("strict kex ignore"));
            }
            if !is_kex_msg(msg) && msg != SSH_MSG_EXT_INFO {
                return Err(Error::protocol("strict kex unexpected"));
            }
        }
        if msg == SSH_MSG_NEWKEYS && self.strict_kex {
            self.recv_seq = 0;
        }
        self.handle_payload(payload)?;
        Ok(true)
    }

    fn handle_payload(&mut self, payload: Bytes) -> Result<()> {
        let t = payload[0];
        match t {
            SSH_MSG_DISCONNECT => {
                let mut p = Parser::new(&payload);
                p.u8()?;
                let reason = p.u32().unwrap_or(0);
                let message = p.str().unwrap_or("").to_string();
                self.closed = true;
                self.events.push_back(Event::Disconnect { reason, message });
                Ok(())
            }
            SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED => Ok(()),
            SSH_MSG_KEXINIT => self.on_kexinit(&payload),
            SSH_MSG_KEX_ECDH_INIT => self.on_ecdh_init(&payload),
            SSH_MSG_KEX_ECDH_REPLY => self.on_ecdh_reply(&payload),
            SSH_MSG_NEWKEYS => self.on_newkeys(),
            SSH_MSG_EXT_INFO => Ok(()),
            SSH_MSG_SERVICE_REQUEST => self.on_service_request(&payload),
            SSH_MSG_SERVICE_ACCEPT => self.on_service_accept(),
            SSH_MSG_USERAUTH_REQUEST => self.on_userauth_request(&payload),
            SSH_MSG_USERAUTH_FAILURE => Err(Error::Auth),
            SSH_MSG_USERAUTH_SUCCESS => {
                self.authed = true;
                let user = self
                    .client
                    .as_ref()
                    .map(|c| c.username.clone())
                    .unwrap_or_default();
                self.user = Some(user.clone());
                self.kex_blocks_app = false;
                self.events.push_back(Event::HandshakeComplete { user });
                Ok(())
            }
            SSH_MSG_USERAUTH_BANNER => Ok(()),
            SSH_MSG_GLOBAL_REQUEST => self.on_global_request(&payload),
            SSH_MSG_REQUEST_SUCCESS | SSH_MSG_REQUEST_FAILURE => Ok(()),
            SSH_MSG_CHANNEL_OPEN => self.on_channel_open(&payload),
            SSH_MSG_CHANNEL_OPEN_CONFIRMATION => self.on_open_confirm(&payload),
            SSH_MSG_CHANNEL_OPEN_FAILURE => self.on_open_fail(&payload),
            SSH_MSG_CHANNEL_WINDOW_ADJUST => self.on_window_adjust(&payload),
            SSH_MSG_CHANNEL_DATA => self.on_channel_data(payload),
            SSH_MSG_CHANNEL_EXTENDED_DATA => self.on_ext_data(&payload),
            SSH_MSG_CHANNEL_EOF => self.on_channel_eof(&payload),
            SSH_MSG_CHANNEL_CLOSE => self.on_channel_close(&payload),
            SSH_MSG_CHANNEL_REQUEST => self.on_channel_request(&payload),
            SSH_MSG_CHANNEL_SUCCESS | SSH_MSG_CHANNEL_FAILURE => Ok(()),
            SSH_MSG_PING => self.on_ping(&payload),
            SSH_MSG_PONG => Ok(()),
            _ => {
                let mut p = vec![SSH_MSG_UNIMPLEMENTED];
                wire::put_u32(&mut p, self.recv_seq.wrapping_sub(1));
                self.queue_msg(&p, true)
            }
        }
    }

    fn on_kexinit(&mut self, payload: &[u8]) -> Result<()> {
        let theirs = KexInit::parse(payload)?;
        if self.kex.is_none() {
            self.start_kex()?;
        }
        let strict_name = match self.role {
            Role::Server => KEX_STRICT_C,
            Role::Client => KEX_STRICT_S,
        };
        let ext_name = match self.role {
            Role::Server => EXT_INFO_C,
            Role::Client => EXT_INFO_S,
        };
        let peer_strict = list_has(&theirs.kex, strict_name);
        let peer_ext = list_has(&theirs.kex, ext_name);
        {
            let kex = self.kex.as_mut().unwrap();
            let c2s = negotiate(SERVER_CIPHERS, &theirs.enc_c2s, false)
                .ok_or(Error::protocol("no cipher c2s"))?;
            let s2c = negotiate(SERVER_CIPHERS, &theirs.enc_s2c, false)
                .ok_or(Error::protocol("no cipher s2c"))?;
            let host = negotiate(SERVER_HOST_KEY, &theirs.host_key, false)
                .ok_or(Error::protocol("no host key alg"))?;
            if host != "ssh-ed25519" {
                return Err(Error::protocol("host key alg"));
            }
            let _ = negotiate(
                &["curve25519-sha256", "curve25519-sha256@libssh.org"],
                &theirs.kex,
                true,
            )
            .ok_or(Error::protocol("no kex alg"))?;
            let _ = negotiate(SERVER_COMP, &theirs.comp_c2s, false)
                .ok_or(Error::protocol("no compression"))?;
            kex.cipher_c2s = CipherKind::from_name(&c2s);
            kex.cipher_s2c = CipherKind::from_name(&s2c);
            kex.theirs = Some(theirs);
        }
        if peer_strict {
            self.strict_kex = true;
        }
        self.peer_ext_info = peer_ext;
        if self.role == Role::Client {
            self.send_ecdh_init()?;
        }
        Ok(())
    }

    fn send_ecdh_init(&mut self) -> Result<()> {
        let q = self
            .kex
            .as_ref()
            .and_then(|k| k.local_pub)
            .ok_or(Error::protocol("no client ecdh pub"))?;
        let mut p = vec![SSH_MSG_KEX_ECDH_INIT];
        wire::put_bytes(&mut p, &q);
        self.queue_msg(&p, true)
    }

    fn on_ecdh_init(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Server {
            return Err(Error::protocol("ecdh init as client"));
        }
        let mut p = Parser::new(payload);
        if p.u8()? != SSH_MSG_KEX_ECDH_INIT {
            return Err(Error::protocol("bad ecdh init"));
        }
        let q_c = p.bytes()?;
        if q_c.len() != 32 {
            return Err(Error::Crypto("q_c len"));
        }
        let mut q_c_arr = [0u8; 32];
        q_c_arr.copy_from_slice(q_c);
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let q_s = PublicKey::from(&secret);
        let q_s_bytes = *q_s.as_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(q_c_arr));
        if is_zero(shared.as_bytes()) {
            return Err(Error::Crypto("weak shared secret"));
        }
        if self.kex.as_ref().and_then(|k| k.theirs.as_ref()).is_none() {
            return Err(Error::protocol("ecdh before kexinit"));
        }
        let host = self.server.as_ref().unwrap().host_key.clone();
        self.peer_ks = Some(host.public_blob());
        self.finish_kex(q_c_arr, q_s_bytes, shared.as_bytes())?;
        let h_now = self.last_h.clone().unwrap();
        let sig = host.sign(&h_now);
        let ks = host.public_blob();
        let mut reply = vec![SSH_MSG_KEX_ECDH_REPLY];
        wire::put_bytes(&mut reply, &ks);
        wire::put_bytes(&mut reply, &q_s_bytes);
        wire::put_bytes(&mut reply, &sig);
        self.queue_msg(&reply, true)?;
        self.send_newkeys()
    }

    fn on_ecdh_reply(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Client {
            return Err(Error::protocol("ecdh reply as server"));
        }
        let mut p = Parser::new(payload);
        if p.u8()? != SSH_MSG_KEX_ECDH_REPLY {
            return Err(Error::protocol("bad ecdh reply"));
        }
        let ks = p.bytes()?.to_vec();
        let q_s = p.bytes()?;
        let _sig = p.bytes()?;
        if q_s.len() != 32 {
            return Err(Error::Crypto("q_s len"));
        }
        let mut q_s_arr = [0u8; 32];
        q_s_arr.copy_from_slice(q_s);
        let q_c = self
            .kex
            .as_ref()
            .and_then(|k| k.local_pub)
            .ok_or(Error::protocol("no client pub"))?;
        let secret = self
            .kex
            .as_mut()
            .and_then(|k| k.secret.take())
            .ok_or(Error::protocol("no client secret"))?;
        let shared = secret.diffie_hellman(&PublicKey::from(q_s_arr));
        if is_zero(shared.as_bytes()) {
            return Err(Error::Crypto("weak shared secret"));
        }
        self.peer_ks = Some(ks);
        self.finish_kex(q_c, q_s_arr, shared.as_bytes())?;
        self.send_newkeys()
    }

    fn finish_kex(&mut self, q_c: [u8; 32], q_s: [u8; 32], shared: &[u8]) -> Result<()> {
        let kex = self.kex.as_ref().ok_or(Error::protocol("no kex"))?;
        let theirs = kex
            .theirs
            .as_ref()
            .ok_or(Error::protocol("no peer kexinit"))?;
        let (v_c, v_s, i_c, i_s) = match self.role {
            Role::Server => (
                self.ident_peer.as_ref().unwrap().as_str(),
                self.ident_local.as_str(),
                theirs.raw.as_slice(),
                kex.ours.raw.as_slice(),
            ),
            Role::Client => (
                self.ident_local.as_str(),
                self.ident_peer.as_ref().unwrap().as_str(),
                kex.ours.raw.as_slice(),
                theirs.raw.as_slice(),
            ),
        };
        let ks = self
            .peer_ks
            .as_ref()
            .ok_or(Error::protocol("no host blob"))?;
        let k_mpint = wire::encode_mpint(shared);
        let h = compute_h(v_c, v_s, i_c, i_s, ks, &q_c, &q_s, &k_mpint);
        if self.session_id.is_none() {
            self.session_id = Some(h.to_vec());
        }
        self.last_h = Some(h.to_vec());
        let sid = self.session_id.as_ref().unwrap().clone();
        let c2s = kex.cipher_c2s.ok_or(Error::protocol("no c2s cipher"))?;
        let s2c = kex.cipher_s2c.ok_or(Error::protocol("no s2c cipher"))?;
        let is_server = self.role == Role::Server;
        let (send_kind, recv_kind, send_k, recv_k, send_ivl, recv_ivl) = if is_server {
            (s2c, c2s, b'D', b'C', b'B', b'A')
        } else {
            (c2s, s2c, b'C', b'D', b'A', b'B')
        };
        let send = make_keys(&k_mpint, &h, &sid, send_k, send_ivl, send_kind)?;
        let recv = make_keys(&k_mpint, &h, &sid, recv_k, recv_ivl, recv_kind)?;
        self.pending_keys = Some(PendingKeys { send, recv });
        Ok(())
    }

    fn send_newkeys(&mut self) -> Result<()> {
        self.queue_msg(&[SSH_MSG_NEWKEYS], true)?;
        if let Some(pk) = &mut self.pending_keys {
            self.send_cipher = std::mem::replace(&mut pk.send, DirectionKeys::Clear);
        }
        self.sent_newkeys = true;
        if self.strict_kex {
            self.send_seq = 0;
        }
        tracing::debug!(role = ?self.role, seq = self.send_seq, "sent NEWKEYS");
        if self.peer_ext_info && !self.first_kex_done && self.role == Role::Server {
            self.send_ext_info()?;
        }
        self.try_complete_kex()
    }

    fn on_newkeys(&mut self) -> Result<()> {
        let Some(pk) = self.pending_keys.take() else {
            return Err(Error::protocol("newkeys without pending"));
        };
        self.recv_cipher = pk.recv;
        // send keys already applied in send_newkeys; if peer NEWKEYS arrives first, send still pending
        if !self.sent_newkeys {
            self.pending_keys = Some(PendingKeys {
                send: pk.send,
                recv: DirectionKeys::Clear,
            });
        }
        self.recv_newkeys = true;
        tracing::debug!(role = ?self.role, "recv NEWKEYS");
        self.try_complete_kex()
    }

    fn try_complete_kex(&mut self) -> Result<()> {
        if !self.sent_newkeys || !self.recv_newkeys {
            return Ok(());
        }
        self.kex = None;
        self.sent_kexinit = false;
        self.pending_keys = None;
        self.bytes_io = 0;
        self.packets_io = 0;
        if !self.first_kex_done {
            self.first_kex_done = true;
            if self.role == Role::Client {
                self.send_service_request()?;
            }
            // Keep kex_blocks_app until userauth success so no CHANNEL_DATA
            // sneaks out before the connection layer is ready.
            return Ok(());
        }
        self.kex_blocks_app = false;
        self.flush_post_rekey();
        // The post-rekey flush must not immediately trip another kex.
        self.bytes_io = 0;
        self.packets_io = 0;
        Ok(())
    }

    fn flush_post_rekey(&mut self) {
        let ids: Vec<u32> = self.channels.iter_ids().collect();
        for id in ids {
            self.maybe_adjust(id);
            self.flush_pending(id);
            let _ = self.emit_eof_if_ready(id);
            let _ = self.emit_close_if_ready(id);
        }
    }

    fn send_ext_info(&mut self) -> Result<()> {
        let mut p = vec![SSH_MSG_EXT_INFO];
        wire::put_u32(&mut p, 1);
        wire::put_str(&mut p, "server-sig-algs");
        wire::put_str(&mut p, "ssh-ed25519");
        self.queue_msg(&p, true)
    }

    fn send_service_request(&mut self) -> Result<()> {
        let mut p = vec![SSH_MSG_SERVICE_REQUEST];
        wire::put_str(&mut p, "ssh-userauth");
        self.queue_msg(&p, true)
    }

    fn on_service_request(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Server {
            return Ok(());
        }
        let mut p = Parser::new(payload);
        p.u8()?;
        let name = p.str()?;
        if name != "ssh-userauth" && name != "ssh-connection" {
            return Err(Error::protocol("unknown service"));
        }
        let mut r = vec![SSH_MSG_SERVICE_ACCEPT];
        wire::put_str(&mut r, name);
        self.queue_msg(&r, true)
    }

    fn on_service_accept(&mut self) -> Result<()> {
        if self.role != Role::Client {
            return Ok(());
        }
        let cfg = self.client.as_ref().unwrap().clone();
        let mut p = vec![SSH_MSG_USERAUTH_REQUEST];
        wire::put_str(&mut p, &cfg.username);
        wire::put_str(&mut p, "ssh-connection");
        wire::put_str(&mut p, "password");
        wire::put_bool(&mut p, false);
        wire::put_str(&mut p, &cfg.password);
        self.queue_msg(&p, true)
    }

    fn on_userauth_request(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Server {
            return Ok(());
        }
        let cfg = self.server.as_ref().unwrap().clone();
        let mut p = Parser::new(payload);
        p.u8()?;
        let user = p.str()?.to_string();
        let service = p.str()?;
        let method = p.str()?;
        if service != "ssh-connection" {
            return Err(Error::protocol("auth service"));
        }
        if method == "none" {
            return self.auth_fail(&cfg);
        }
        if method != "password" {
            return self.auth_fail(&cfg);
        }
        let changing = p.bool()?;
        if changing {
            return self.auth_fail(&cfg);
        }
        let password = p.str()?;
        if cfg.check_password(&user, password) {
            self.authed = true;
            self.user = Some(user.clone());
            self.kex_blocks_app = false;
            self.queue_msg(&[SSH_MSG_USERAUTH_SUCCESS], true)?;
            self.events.push_back(Event::HandshakeComplete { user });
            Ok(())
        } else {
            self.auth_fails += 1;
            self.auth_fail(&cfg)
        }
    }

    fn auth_fail(&mut self, cfg: &ServerConfig) -> Result<()> {
        if self.auth_fails >= cfg.max_auth_fails {
            self.disconnect(
                SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
                "too many failures",
            );
            return Ok(());
        }
        let mut p = vec![SSH_MSG_USERAUTH_FAILURE];
        wire::put_str(&mut p, "password");
        wire::put_bool(&mut p, false);
        self.queue_msg(&p, true)
    }

    fn on_global_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let name = p.str().unwrap_or("");
        let want = p.bool().unwrap_or(false);
        if want {
            if name == "keepalive@openssh.com"
                || name == "no-more-sessions@openssh.com"
                || name == "ping@openssh.com"
            {
                self.queue_msg(&[SSH_MSG_REQUEST_SUCCESS], true)?;
            } else {
                self.queue_msg(&[SSH_MSG_REQUEST_FAILURE], true)?;
            }
        }
        Ok(())
    }

    fn on_channel_open(&mut self, payload: &[u8]) -> Result<()> {
        if !self.authed {
            return Err(Error::protocol("channel before auth"));
        }
        let mut p = Parser::new(payload);
        p.u8()?;
        let typ = p.str()?;
        let remote = p.u32()?;
        let send_window = p.u32()?;
        let max_remote_packet = p.u32()?;
        match typ {
            "session" => {
                let mut ch = Channel::new(
                    0,
                    ChannelKind::Session,
                    self.window,
                    self.max_packet,
                    send_window,
                    max_remote_packet,
                );
                ch.remote_id = Some(remote);
                let id = self.channels.alloc(ch)?;
                self.events.push_back(Event::OpenSession { local_id: id });
            }
            "direct-tcpip" => {
                let host = p.str()?.to_string();
                let port = p.u32()?;
                let _orig = p.str()?;
                let _oport = p.u32()?;
                let mut ch = Channel::new(
                    0,
                    ChannelKind::DirectTcpIp,
                    self.window,
                    self.max_packet,
                    send_window,
                    max_remote_packet,
                );
                ch.remote_id = Some(remote);
                ch.host = Some(host.clone());
                ch.port = port;
                let id = self.channels.alloc(ch)?;
                self.events.push_back(Event::OpenDirectTcpIp {
                    local_id: id,
                    host,
                    port,
                });
            }
            _ => {
                let mut f = vec![SSH_MSG_CHANNEL_OPEN_FAILURE];
                wire::put_u32(&mut f, remote);
                wire::put_u32(&mut f, SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
                wire::put_str(&mut f, "unknown channel type");
                wire::put_str(&mut f, "");
                self.queue_msg(&f, true)?;
            }
        }
        Ok(())
    }

    fn on_open_confirm(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let remote = p.u32()?;
        let window = p.u32()?;
        let max_pkt = p.u32()?;
        {
            let ch = self.channels.get_mut(local)?;
            ch.remote_id = Some(remote);
            ch.send_window = window;
            ch.max_remote_packet = max_pkt;
            ch.open_confirmed = true;
        }
        self.events
            .push_back(Event::ChannelOpenConfirmation { local_id: local });
        self.flush_pending(local);
        Ok(())
    }

    fn on_open_fail(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let reason = p.u32()?;
        let message = p.str().unwrap_or("").to_string();
        self.channels.free(local);
        self.events.push_back(Event::ChannelOpenFailure {
            local_id: local,
            reason,
            message,
        });
        Ok(())
    }

    fn on_window_adjust(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let add = p.u32()?;
        {
            let ch = self.channels.get_mut(local)?;
            ch.send_window = ch.send_window.saturating_add(add);
        }
        self.flush_pending(local);
        Ok(())
    }

    fn on_channel_data(&mut self, payload: Bytes) -> Result<()> {
        if payload.len() < 9 {
            return Err(Error::protocol("short channel data"));
        }
        let local = u32::from_be_bytes(payload[1..5].try_into().unwrap());
        let dlen = u32::from_be_bytes(payload[5..9].try_into().unwrap()) as usize;
        if payload.len() < 9 + dlen {
            return Err(Error::protocol("truncated channel data"));
        }
        let data = payload.slice(9..9 + dlen);
        self.channels.get_mut(local)?.push_in(data)?;
        self.events
            .push_back(Event::ChannelData { local_id: local });
        Ok(())
    }

    fn on_ext_data(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let _code = p.u32()?;
        let data = Bytes::copy_from_slice(p.bytes()?);
        self.channels.get_mut(local)?.push_in(data)?;
        self.events
            .push_back(Event::ChannelData { local_id: local });
        Ok(())
    }

    fn on_channel_eof(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        if let Ok(ch) = self.channels.get_mut(local) {
            ch.got_eof = true;
        }
        self.events.push_back(Event::ChannelEof { local_id: local });
        Ok(())
    }

    fn on_channel_close(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let already_sent = {
            if let Ok(ch) = self.channels.get_mut(local) {
                ch.got_close = true;
                ch.got_eof = true;
                ch.sent_close
            } else {
                return Ok(());
            }
        };
        if !already_sent {
            let _ = self.send_close(local);
        } else {
            let _ = self.emit_close_if_ready(local);
        }
        self.events
            .push_back(Event::ChannelClose { local_id: local });
        Ok(())
    }

    fn on_channel_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let name = p.str().unwrap_or("");
        let want = p.bool().unwrap_or(false);
        if !want {
            return Ok(());
        }
        let remote = self.channels.get(local).ok().and_then(|c| c.remote_id);
        let Some(r) = remote else {
            return Ok(());
        };
        let ok = matches!(
            name,
            "pty-req"
                | "env"
                | "shell"
                | "window-change"
                | "eow@openssh.com"
                | "keepalive@openssh.com"
                | "simple@putty.projects.tartarus.org"
        );
        let mut m = vec![if ok {
            SSH_MSG_CHANNEL_SUCCESS
        } else {
            SSH_MSG_CHANNEL_FAILURE
        }];
        wire::put_u32(&mut m, r);
        self.queue_msg(&m, true)
    }

    fn on_ping(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let data = p.bytes().unwrap_or(b"");
        let mut m = vec![SSH_MSG_PONG];
        wire::put_bytes(&mut m, data);
        self.queue_msg(&m, true)
    }

    pub fn disconnect(&mut self, reason: u32, msg: &str) {
        if self.closed {
            return;
        }
        let mut p = vec![SSH_MSG_DISCONNECT];
        wire::put_u32(&mut p, reason);
        wire::put_str(&mut p, msg);
        wire::put_str(&mut p, "");
        let _ = self.queue_msg(&p, true);
        self.closed = true;
        self.events.push_back(Event::Disconnect {
            reason,
            message: msg.into(),
        });
    }

    fn queue_msg(&mut self, payload: &[u8], priority: bool) -> Result<()> {
        if payload.is_empty() {
            return Err(Error::protocol("empty msg"));
        }
        if !priority && self.write_bytes >= self.write_hard {
            return Err(Error::protocol("write backlog"));
        }
        let kind = self.send_cipher.kind();
        let block = kind.block_size();
        let tag = kind.tag_len();
        let pad = padding_len(payload.len(), block);
        let packet_length = 1 + payload.len() + pad;
        let total = 4 + packet_length + tag;
        let mut buf = BytesMut::with_capacity(total);
        buf.resize(total, 0);
        buf[..4].copy_from_slice(&(packet_length as u32).to_be_bytes());
        buf[4] = pad as u8;
        buf[5..5 + payload.len()].copy_from_slice(payload);
        rand::rngs::OsRng.fill_bytes(&mut buf[5 + payload.len()..5 + payload.len() + pad]);
        {
            let (pkt, tag_out) = buf.split_at_mut(4 + packet_length);
            self.send_cipher.seal(self.send_seq, pkt, tag_out)?;
        }
        self.send_seq = self.send_seq.wrapping_add(1);
        self.bytes_io += total as u64;
        self.packets_io = self.packets_io.wrapping_add(1);
        let frozen = buf.freeze();
        self.write_bytes += frozen.len();
        let _ = priority;
        self.write_q.push_back(frozen);
        Ok(())
    }
}

fn is_zero(b: &[u8]) -> bool {
    let mut acc = 0u8;
    for x in b {
        acc |= *x;
    }
    acc == 0
}

fn compute_h(
    v_c: &str,
    v_s: &str,
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8; 32],
    q_s: &[u8; 32],
    k_mpint: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(256 + i_c.len() + i_s.len());
    wire::put_str(&mut buf, v_c);
    wire::put_str(&mut buf, v_s);
    wire::put_bytes(&mut buf, i_c);
    wire::put_bytes(&mut buf, i_s);
    wire::put_bytes(&mut buf, k_s);
    wire::put_bytes(&mut buf, q_c);
    wire::put_bytes(&mut buf, q_s);
    buf.extend_from_slice(k_mpint);
    Sha256::digest(&buf).into()
}

fn make_keys(
    k_mpint: &[u8],
    h: &[u8],
    sid: &[u8],
    key_letter: u8,
    iv_letter: u8,
    kind: CipherKind,
) -> Result<DirectionKeys> {
    let mut key = vec![0u8; kind.key_len()];
    let iv_need = if kind.iv_len() == 0 { 8 } else { kind.iv_len() };
    let mut iv = vec![0u8; iv_need];
    if kind.key_len() > 0 {
        derive_block(k_mpint, h, sid, key_letter, &mut key);
    }
    derive_block(k_mpint, h, sid, iv_letter, &mut iv);
    if kind.iv_len() == 0 {
        iv.clear();
    } else {
        iv.truncate(kind.iv_len());
    }
    DirectionKeys::from_material(kind, &key, &iv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientConfig, ServerConfig};

    fn xfer_limited(from: &mut Connection, to: &mut Connection, max: usize) -> bool {
        let n = match from.peek_out() {
            Some(c) if !c.is_empty() => c.len().min(max),
            _ => return false,
        };
        let chunk = from.peek_out().unwrap()[..n].to_vec();
        to.read_buf_mut().extend_from_slice(&chunk);
        from.consume_out(n);
        to.process_in().expect("process_in");
        true
    }

    fn pump(a: &mut Connection, b: &mut Connection) {
        pump_limited(a, b, usize::MAX);
    }

    fn pump_limited(a: &mut Connection, b: &mut Connection, max: usize) {
        for _ in 0..200_000 {
            let p1 = xfer_limited(a, b, max);
            let p2 = xfer_limited(b, a, max);
            if !p1 && !p2 {
                return;
            }
        }
        panic!("pump did not settle");
    }

    fn drain_server(s: &mut Connection) {
        while let Some(ev) = s.pop_event() {
            match ev {
                Event::OpenSession { local_id } | Event::OpenDirectTcpIp { local_id, .. } => {
                    s.confirm_open(local_id).unwrap();
                }
                Event::ChannelData { local_id } => {
                    while let Some(data) = s.peek_inbound(local_id).map(|d| d.to_vec()) {
                        let n = data.len();
                        s.consume_inbound(local_id, n);
                        s.send_data(local_id, &data).unwrap();
                    }
                }
                Event::ChannelEof { local_id } => {
                    s.send_eof(local_id).unwrap();
                    s.send_close(local_id).unwrap();
                }
                Event::ChannelClose { local_id } => {
                    let _ = s.send_close(local_id);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn handshake_and_echo_channel() {
        let scfg = Arc::new(ServerConfig::test_config());
        let ccfg = Arc::new(ClientConfig::new("proxy", "proxy"));
        let mut s = Connection::server(scfg);
        let mut c = Connection::client(ccfg);
        for _ in 0..200 {
            pump(&mut s, &mut c);
            drain_server(&mut s);
            let mut done = false;
            while let Some(ev) = c.pop_event() {
                if matches!(ev, Event::HandshakeComplete { .. }) {
                    done = true;
                }
            }
            if done && s.authed() && c.authed() {
                break;
            }
        }
        assert!(s.authed() && c.authed(), "auth failed");

        let id = c.open_direct_tcpip("example.com", 443).unwrap();
        for _ in 0..50 {
            pump(&mut s, &mut c);
            drain_server(&mut s);
            let mut confirmed = false;
            while let Some(ev) = c.pop_event() {
                if matches!(ev, Event::ChannelOpenConfirmation { local_id } if local_id == id) {
                    confirmed = true;
                }
            }
            if confirmed {
                break;
            }
        }
        assert!(c.channel_alive(id));

        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(c.send_data(id, payload).unwrap(), payload.len());
        let mut got = Vec::new();
        for _ in 0..50 {
            pump(&mut s, &mut c);
            drain_server(&mut s);
            while let Some(d) = c.peek_inbound(id).map(|x| x.to_vec()) {
                let n = d.len();
                c.consume_inbound(id, n);
                got.extend_from_slice(&d);
            }
            if got == payload {
                break;
            }
        }
        assert_eq!(got, payload, "echo mismatch");
    }

    #[test]
    fn rekey_during_echo() {
        let mut scfg = ServerConfig::test_config();
        scfg.rekey_after_bytes = 8 * 1024;
        let mut ccfg = ClientConfig::new("proxy", "proxy");
        ccfg.rekey_after_bytes = 8 * 1024;
        let mut s = Connection::server(Arc::new(scfg));
        let mut c = Connection::client(Arc::new(ccfg));
        for _ in 0..200 {
            pump(&mut s, &mut c);
            drain_server(&mut s);
            if s.authed() && c.authed() {
                break;
            }
        }
        assert!(s.authed() && c.authed());
        let id = c.open_direct_tcpip("example.com", 443).unwrap();
        for _ in 0..50 {
            pump(&mut s, &mut c);
            drain_server(&mut s);
            if c.outbound_allowance(id) > 0 {
                break;
            }
            while c.pop_event().is_some() {}
        }
        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let mut sent = 0usize;
        let mut got = Vec::new();
        for _ in 0..5000 {
            if sent < payload.len() {
                sent += c.send_data(id, &payload[sent..]).unwrap();
            }
            pump(&mut s, &mut c);
            drain_server(&mut s);
            while let Some(d) = c.peek_inbound(id).map(|x| x.to_vec()) {
                let n = d.len();
                c.consume_inbound(id, n);
                got.extend_from_slice(&d);
            }
            while c.pop_event().is_some() {}
            if sent == payload.len() && got.len() == payload.len() {
                break;
            }
        }
        assert_eq!(
            got,
            payload,
            "rekey echo mismatch {} vs {}",
            got.len(),
            payload.len()
        );
    }

    #[test]
    fn rekey_during_echo_bytewise() {
        let mut scfg = ServerConfig::test_config();
        scfg.rekey_after_bytes = 4 * 1024;
        let mut ccfg = ClientConfig::new("proxy", "proxy");
        ccfg.rekey_after_bytes = 4 * 1024;
        let mut s = Connection::server(Arc::new(scfg));
        let mut c = Connection::client(Arc::new(ccfg));
        for _ in 0..400 {
            pump_limited(&mut s, &mut c, 3);
            drain_server(&mut s);
            if s.authed() && c.authed() {
                break;
            }
        }
        assert!(s.authed() && c.authed());
        let id = c.open_direct_tcpip("example.com", 443).unwrap();
        for _ in 0..200 {
            pump_limited(&mut s, &mut c, 3);
            drain_server(&mut s);
            if c.outbound_allowance(id) > 0 {
                break;
            }
            while c.pop_event().is_some() {}
        }
        let payload: Vec<u8> = (0..24 * 1024).map(|i| (i % 251) as u8).collect();
        let mut sent = 0usize;
        let mut got = Vec::new();
        for _ in 0..200_000 {
            if sent < payload.len() {
                sent += c.send_data(id, &payload[sent..]).unwrap();
            }
            pump_limited(&mut s, &mut c, 3);
            drain_server(&mut s);
            while let Some(d) = c.peek_inbound(id).map(|x| x.to_vec()) {
                let n = d.len();
                c.consume_inbound(id, n);
                got.extend_from_slice(&d);
            }
            while c.pop_event().is_some() {}
            if sent == payload.len() && got.len() == payload.len() {
                break;
            }
        }
        assert_eq!(
            got,
            payload,
            "bytewise rekey echo {} vs {}",
            got.len(),
            payload.len()
        );
    }
}
