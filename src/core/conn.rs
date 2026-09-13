use std::collections::VecDeque;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use rand::rngs::{OsRng, StdRng};
use rand::{RngCore, SeedableRng};

use crate::config::{ClientConfig, Config, ServerConfig};
use crate::core::channel::{Channel, ChannelKind, ChannelTable};
use crate::crypto::{padding_len, CipherKind, DirectionKeys, HashAlg, MacKind, MAX_PACKET};
use crate::error::{Error, Result};
use crate::kex::{self, ClientKex, KexAlgo};
use crate::proto::msg::{self, KexInit};
use crate::proto::*;
use crate::wire::{self, Parser};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

/// Events surfaced to the driver. Owned data keeps the borrow simple; all of
/// these except channel data are low-frequency.
#[derive(Debug)]
pub enum Event {
    /// First key exchange finished; transport is encrypted.
    KexDone,
    /// Password attempt awaiting `resolve_auth`.
    AuthPassword { user: String, password: String },
    /// Public-key probe (no signature) awaiting `resolve_auth`.
    AuthPublicKeyProbe { user: String, algo: String, key_blob: Vec<u8> },
    /// Public key with a valid signature, awaiting authorization via `resolve_auth`.
    AuthPublicKey { user: String, algo: String, key_blob: Vec<u8> },
    Authenticated { user: String },
    OpenDirectTcpIp { local_id: u32, host: String, port: u16 },
    OpenSession { local_id: u32 },
    OpenConfirmed { local_id: u32 },
    OpenFailed { local_id: u32, reason: u32, message: String },
    ChannelData { local_id: u32 },
    ChannelWindow { local_id: u32 },
    ChannelEof { local_id: u32 },
    ChannelClose { local_id: u32 },
    Disconnect { reason: u32, message: String },
}

enum AuthKind {
    Password,
    PubkeyProbe,
    Pubkey,
}

/// Context for the auth attempt awaiting the driver's verdict.
struct AuthCtx {
    kind: AuthKind,
    user: String,
    /// For a probe: the algorithm + key blob to echo back in PK_OK.
    probe: Option<(String, Vec<u8>)>,
}

struct KexRun {
    ours: Vec<u8>,
    algo: KexAlgo,
    cipher_c2s: CipherKind,
    cipher_s2c: CipherKind,
    mac_c2s: Option<MacKind>,
    mac_s2c: Option<MacKind>,
    hash: HashAlg,
    theirs: Vec<u8>,
    client: Option<ClientKex>,
    /// Client role: our Q_C, needed for the exchange hash.
    q_c: Vec<u8>,
}

struct PendingKeys {
    send: DirectionKeys,
    recv: DirectionKeys,
}

/// A frame whose length is known but whose body has not fully arrived. Kept so
/// CTR-without-ETM head decryption (which mutates keystream) happens once.
struct PartialFrame {
    length: u32,
    head: [u8; 16],
    head_len: usize,
}

pub struct Connection {
    role: Role,
    cfg: Arc<Config>,
    server: Option<Arc<ServerConfig>>,
    client: Option<Arc<ClientConfig>>,

    // Our offered algorithm name-lists (owned; drive client-side negotiation).
    our_kex: String,
    our_ciphers: String,
    our_macs: String,

    // Identification strings.
    ident_local: String,
    ident_peer: Option<String>,
    ident_acc: Vec<u8>,
    ident_done: bool,
    ident_out: Option<Bytes>,

    // Framing / transport.
    /// 每连接的用户态 CSPRNG，**只**用来填 SSH 包 padding。
    /// 原先每封包一次 `OsRng.fill_bytes` = 每包一次 getrandom 系统调用
    /// （真机 strace：8s 内 115602 次，约每 2.3 次 sendto 一次）。padding 只为掩盖
    /// 长度，用系统熵播种的 CSPRNG 完全合规（russh 的 safe_rng 同样做法）。
    /// KEX 密钥与 KEXINIT cookie 仍走 OsRng，不受影响。
    pad_rng: StdRng,
    read_buf: BytesMut,
    partial: Option<PartialFrame>,
    send_seq: u32,
    recv_seq: u32,
    send_cipher: DirectionKeys,
    recv_cipher: DirectionKeys,
    write_q: VecDeque<Bytes>,
    current: Option<(Bytes, bool)>, // (bytes, is_ident)
    write_bytes: usize,

    // Rekey accounting.
    bytes_since_kex: u64,

    // Key exchange.
    strict_kex: bool,
    peer_ext_info: bool,
    session_id: Option<Vec<u8>>,
    peer_hostkey: Option<Vec<u8>>,
    kex: Option<KexRun>,
    pending_keys: Option<PendingKeys>,
    sent_kexinit: bool,
    sent_newkeys: bool,
    recv_newkeys: bool,
    first_kex_done: bool,
    kex_blocks_app: bool,

    // Auth.
    authed: bool,
    user: Option<String>,
    auth_fails: u32,
    auth_ctx: Option<AuthCtx>,

    // Connection layer.
    channels: ChannelTable,
    window_used: u64,
    events: VecDeque<Event>,
    closed: bool,
    keepalive_outstanding: u32,
}

impl Connection {
    pub fn server(cfg: Arc<ServerConfig>) -> Self {
        let base = Arc::new(cfg.base.clone());
        let mut c = Self::new(Role::Server, base);
        c.server = Some(cfg);
        c.start();
        c
    }

    pub fn client(cfg: Arc<ClientConfig>) -> Self {
        let base = Arc::new(cfg.base.clone());
        let mut c = Self::new(Role::Client, base);
        c.client = Some(cfg);
        c.start();
        c
    }

    fn new(role: Role, cfg: Arc<Config>) -> Self {
        let a = &cfg.algorithms;
        let (kex_ext, strict) = match role {
            Role::Server => (EXT_INFO_S, KEX_STRICT_S),
            Role::Client => (EXT_INFO_C, KEX_STRICT_C),
        };
        let mut our_kex: String =
            a.kex.iter().map(|k| k.name()).collect::<Vec<_>>().join(",");
        our_kex.push(',');
        our_kex.push_str(kex_ext);
        our_kex.push(',');
        our_kex.push_str(strict);
        let our_ciphers = a.ciphers.iter().map(|c| c.name()).collect::<Vec<_>>().join(",");
        let our_macs = a.macs.iter().map(|m| m.name()).collect::<Vec<_>>().join(",");
        Self {
            role,
            our_kex,
            our_ciphers,
            our_macs,
            ident_local: cfg.ident.clone(),
            channels: ChannelTable::new(cfg.max_channels),
            ident_peer: None,
            ident_acc: Vec::new(),
            ident_done: false,
            ident_out: None,
            pad_rng: StdRng::from_entropy(),
            read_buf: BytesMut::with_capacity(16 * 1024),
            partial: None,
            send_seq: 0,
            recv_seq: 0,
            send_cipher: DirectionKeys::Clear,
            recv_cipher: DirectionKeys::Clear,
            write_q: VecDeque::new(),
            current: None,
            write_bytes: 0,
            bytes_since_kex: 0,
            strict_kex: false,
            peer_ext_info: false,
            session_id: None,
            peer_hostkey: None,
            kex: None,
            pending_keys: None,
            sent_kexinit: false,
            sent_newkeys: false,
            recv_newkeys: false,
            first_kex_done: false,
            kex_blocks_app: true,
            authed: false,
            user: None,
            auth_fails: 0,
            auth_ctx: None,
            window_used: 0,
            events: VecDeque::new(),
            closed: false,
            keepalive_outstanding: 0,
            server: None,
            client: None,
            cfg,
        }
    }

    fn start(&mut self) {
        let line = format!("{}\r\n", self.ident_local);
        self.ident_out = Some(Bytes::from(line.into_bytes()));
        if self.cfg.early_kexinit {
            let _ = self.start_kex();
        }
    }

    // ── introspection ──────────────────────────────────────────────────────

    pub fn role(&self) -> Role {
        self.role
    }
    pub fn authed(&self) -> bool {
        self.authed
    }
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }
    pub fn peer_ident(&self) -> Option<&str> {
        self.ident_peer.as_deref()
    }
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    pub fn active_channels(&self) -> u32 {
        self.channels.active()
    }
    pub fn wants_write(&self) -> bool {
        self.current.is_some()
            || !self.write_q.is_empty()
            || self.ident_out.as_ref().is_some_and(|b| !b.is_empty())
    }
    pub fn is_finished(&self) -> bool {
        self.closed && !self.wants_write()
    }
    pub fn queued_out_bytes(&self) -> usize {
        self.write_bytes
    }
    /// Stop reading the transport when true (write backlog too large).
    pub fn write_saturated(&self) -> bool {
        self.write_bytes >= self.cfg.out_hard
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    // ── outbound framing ─────────────────────────────────────────────────────

    pub fn peek_out(&mut self) -> Option<&[u8]> {
        if self.current.as_ref().is_some_and(|(b, _)| b.is_empty()) {
            self.current = None;
        }
        if self.current.is_none() {
            if let Some(b) = self.ident_out.take() {
                if !b.is_empty() {
                    self.current = Some((b, true));
                }
            }
        }
        if self.current.is_none() {
            if let Some(b) = self.write_q.pop_front() {
                self.current = Some((b, false));
            }
        }
        self.current.as_ref().map(|(b, _)| b.as_ref()).filter(|b| !b.is_empty())
    }

    pub fn consume_out(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let Some((buf, is_ident)) = self.current.as_mut() else {
            return;
        };
        let take = n.min(buf.len());
        let was_ident = *is_ident;
        if take == buf.len() {
            self.current = None;
        } else {
            let _ = buf.split_to(take);
        }
        if !was_ident {
            self.write_bytes = self.write_bytes.saturating_sub(take);
        } else if self.current.is_none() && !self.sent_kexinit {
            // Our identification line just went out; open with KEXINIT.
            let _ = self.start_kex();
        }
    }

    pub fn read_buf_mut(&mut self) -> &mut BytesMut {
        if self.read_buf.capacity() - self.read_buf.len() < 4096 {
            self.read_buf.reserve(16 * 1024);
        }
        &mut self.read_buf
    }

    // ── inbound framing ──────────────────────────────────────────────────────

    pub fn process_in(&mut self) -> Result<()> {
        if !self.ident_done {
            self.try_ident()?;
            if !self.ident_done {
                return Ok(());
            }
            if !self.sent_kexinit {
                self.start_kex()?;
            }
        }
        while self.try_one_packet()? {}
        self.maybe_rekey();
        Ok(())
    }

    fn try_ident(&mut self) -> Result<()> {
        if !self.read_buf.is_empty() {
            self.ident_acc.extend_from_slice(&self.read_buf);
            self.read_buf.clear();
        }
        loop {
            let Some(pos) = self.ident_acc.iter().position(|&b| b == b'\n') else {
                if self.ident_acc.len() > 4096 {
                    return Err(Error::protocol("ident line too long"));
                }
                return Ok(());
            };
            let mut line: Vec<u8> = self.ident_acc.drain(..=pos).collect();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.starts_with(b"SSH-") {
                let s = std::str::from_utf8(&line).map_err(|_| Error::protocol("ident utf8"))?;
                if !s.starts_with("SSH-2.0-") && !s.starts_with("SSH-1.99-") {
                    return Err(Error::protocol("unsupported SSH version"));
                }
                self.ident_peer = Some(s.to_string());
                self.ident_done = true;
                if !self.ident_acc.is_empty() {
                    self.read_buf.extend_from_slice(&self.ident_acc);
                    self.ident_acc.clear();
                }
                return Ok(());
            }
            // Pre-banner lines (RFC 4253 §4.2) are ignored.
            if self.ident_acc.is_empty() && self.read_buf.is_empty() {
                return Ok(());
            }
        }
    }

    fn try_one_packet(&mut self) -> Result<bool> {
        // Reuse an already-decrypted head from a previous partial read so CTR
        // keystream is never advanced twice for the same packet.
        let (length, head, head_len) = if let Some(pf) = self.partial.as_ref() {
            (pf.length as usize, pf.head, pf.head_len)
        } else {
            let head_len = self.recv_cipher.head_len();
            if self.read_buf.len() < head_len {
                return Ok(false);
            }
            let mut head = [0u8; 16];
            head[..head_len].copy_from_slice(&self.read_buf[..head_len]);
            let length =
                self.recv_cipher.read_length(self.recv_seq, &mut head[..head_len])? as usize;
            if length < 5 || length > MAX_PACKET {
                return Err(Error::proto_fmt(format!("bad packet length {length}")));
            }
            (length, head, head_len)
        };
        let tag = self.recv_cipher.tag_len();
        let total = 4 + length + tag;
        if self.read_buf.len() < total {
            if self.partial.is_none() {
                self.partial = Some(PartialFrame {
                    length: length as u32,
                    head,
                    head_len,
                });
            }
            return Ok(false);
        }
        self.partial = None;
        let mut pkt = self.read_buf.split_to(total);
        // Restore decrypted head bytes (CTR non-ETM decrypted them above).
        pkt[..head_len].copy_from_slice(&head[..head_len]);
        let (body, tagb) = pkt.split_at_mut(4 + length);
        self.recv_cipher.open(self.recv_seq, body, tagb)?;
        let pad = pkt[4] as usize;
        if pad < 4 || 1 + pad > length {
            return Err(Error::protocol("bad padding"));
        }
        let pkt = pkt.freeze();
        let payload = pkt.slice(5..4 + length - pad);
        if payload.is_empty() {
            return Err(Error::protocol("empty payload"));
        }
        self.recv_seq = self.recv_seq.wrapping_add(1);
        self.bytes_since_kex += total as u64;
        let msg = payload[0];
        if self.strict_kex && !self.first_kex_done && !allowed_during_kex(msg) {
            return Err(Error::protocol("strict-kex violation"));
        }
        // Strict-kex (Terrapin mitigation) resets the receive sequence number to
        // zero after *every* NEWKEYS — the initial exchange and every rekey.
        // OpenSSH does this, so both directions must.
        if msg == SSH_MSG_NEWKEYS && self.strict_kex {
            self.recv_seq = 0;
        }
        self.handle(payload)?;
        Ok(true)
    }

    // ── KEXINIT / KEX ────────────────────────────────────────────────────────

    fn start_kex(&mut self) -> Result<()> {
        if self.sent_kexinit {
            return Ok(());
        }
        let mut cookie = [0u8; 16];
        OsRng.fill_bytes(&mut cookie);
        let kex: Vec<&str> = wire::names(&self.our_kex).collect();
        let ciphers: Vec<&str> = wire::names(&self.our_ciphers).collect();
        let macs: Vec<&str> = wire::names(&self.our_macs).collect();
        let ours = msg::build_kexinit(cookie, &kex, &["ssh-ed25519"], &ciphers, &macs);
        self.kex = Some(KexRun {
            ours: ours.clone(),
            algo: KexAlgo::Curve25519Sha256,
            cipher_c2s: CipherKind::Clear,
            cipher_s2c: CipherKind::Clear,
            mac_c2s: None,
            mac_s2c: None,
            hash: HashAlg::Sha256,
            theirs: Vec::new(),
            client: None,
            q_c: Vec::new(),
        });
        self.sent_kexinit = true;
        self.sent_newkeys = false;
        self.recv_newkeys = false;
        self.kex_blocks_app = true;
        self.queue(&ours)
    }

    fn maybe_rekey(&mut self) {
        if self.role != Role::Server
            || !self.first_kex_done
            || self.kex.is_some()
            || self.kex_blocks_app
            || self.sent_kexinit
            || self.closed
            || !self.authed
        {
            return;
        }
        if self.bytes_since_kex >= self.cfg.rekey_bytes {
            let _ = self.start_kex();
        }
    }

    fn on_kexinit(&mut self, payload: &[u8]) -> Result<()> {
        let theirs = KexInit::parse(payload)?;
        if self.kex.is_none() {
            self.start_kex()?;
        }
        let (strict, ext) = match self.role {
            Role::Server => (KEX_STRICT_C, EXT_INFO_C),
            Role::Client => (KEX_STRICT_S, EXT_INFO_S),
        };
        self.strict_kex |= theirs.has(msg::L_KEX, strict);
        self.peer_ext_info = theirs.has(msg::L_KEX, ext);

        // RFC 4253 §7.1: the client's ordered preference wins each list.
        let is_server = self.role == Role::Server;
        let pick = |client: &str, server: &str| -> Option<String> {
            msg::negotiate(client, server).map(|s| s.to_string())
        };
        let (kex_c, kex_s) = if is_server {
            (theirs.list(msg::L_KEX).to_string(), self.our_kex.clone())
        } else {
            (self.our_kex.clone(), theirs.list(msg::L_KEX).to_string())
        };
        let (enc_c_client, enc_c_server, enc_s_client, enc_s_server) = if is_server {
            (
                theirs.list(msg::L_ENC_C2S).to_string(),
                self.our_ciphers.clone(),
                theirs.list(msg::L_ENC_S2C).to_string(),
                self.our_ciphers.clone(),
            )
        } else {
            (
                self.our_ciphers.clone(),
                theirs.list(msg::L_ENC_C2S).to_string(),
                self.our_ciphers.clone(),
                theirs.list(msg::L_ENC_S2C).to_string(),
            )
        };
        let (mac_c_client, mac_c_server, mac_s_client, mac_s_server) = if is_server {
            (
                theirs.list(msg::L_MAC_C2S).to_string(),
                self.our_macs.clone(),
                theirs.list(msg::L_MAC_S2C).to_string(),
                self.our_macs.clone(),
            )
        } else {
            (
                self.our_macs.clone(),
                theirs.list(msg::L_MAC_C2S).to_string(),
                self.our_macs.clone(),
                theirs.list(msg::L_MAC_S2C).to_string(),
            )
        };

        if !theirs.has(msg::L_HOSTKEY, "ssh-ed25519") {
            return Err(Error::protocol("no ssh-ed25519 host key"));
        }
        let algo = KexAlgo::from_name(&pick(&kex_c, &kex_s).ok_or(Error::protocol("no common kex"))?)
            .ok_or(Error::protocol("kex algo"))?;
        let cipher_c2s = CipherKind::from_name(
            &pick(&enc_c_client, &enc_c_server).ok_or(Error::protocol("no cipher c2s"))?,
        )
        .ok_or(Error::protocol("cipher c2s"))?;
        let cipher_s2c = CipherKind::from_name(
            &pick(&enc_s_client, &enc_s_server).ok_or(Error::protocol("no cipher s2c"))?,
        )
        .ok_or(Error::protocol("cipher s2c"))?;
        let mac_c2s = if cipher_c2s.is_aead() {
            None
        } else {
            Some(
                MacKind::from_name(&pick(&mac_c_client, &mac_c_server).ok_or(Error::protocol("no mac c2s"))?)
                    .ok_or(Error::protocol("mac c2s"))?,
            )
        };
        let mac_s2c = if cipher_s2c.is_aead() {
            None
        } else {
            Some(
                MacKind::from_name(&pick(&mac_s_client, &mac_s_server).ok_or(Error::protocol("no mac s2c"))?)
                    .ok_or(Error::protocol("mac s2c"))?,
            )
        };

        let run = self.kex.as_mut().ok_or(Error::protocol("kex state"))?;
        run.algo = algo;
        run.hash = algo.hash();
        run.cipher_c2s = cipher_c2s;
        run.cipher_s2c = cipher_s2c;
        run.mac_c2s = mac_c2s;
        run.mac_s2c = mac_s2c;
        run.theirs = theirs.raw.clone();

        if self.role == Role::Client {
            let (state, q_c) = ClientKex::start(algo);
            let run = self.kex.as_mut().unwrap();
            run.client = Some(state);
            run.q_c = q_c.clone();
            let mut p = vec![SSH_MSG_KEX_ECDH_INIT];
            wire::put_bytes(&mut p, &q_c);
            self.queue(&p)?;
        }
        Ok(())
    }

    fn on_ecdh_init(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Server {
            return Err(Error::protocol("ecdh init on client"));
        }
        let mut p = Parser::new(payload);
        p.u8()?;
        let q_c = p.bytes()?.to_vec();
        let run = self.kex.as_ref().ok_or(Error::protocol("no kex"))?;
        let algo = run.algo;
        let hash = run.hash;
        let theirs = run.theirs.clone();
        let ours = run.ours.clone();
        let host = self.server.as_ref().ok_or(Error::protocol("no host key"))?.host_key.public_blob().to_vec();
        let (q_s, k) = kex::server_exchange(algo, &q_c)?;
        let v_c = self.ident_peer.clone().ok_or(Error::protocol("no peer ident"))?;
        let v_s = self.ident_local.clone();
        let h = exchange_hash(hash, &v_c, &v_s, &theirs, &ours, &host, &q_c, &q_s, &k);
        let sig = self.server.as_ref().unwrap().host_key.sign(&h);
        self.peer_hostkey = Some(host.clone());
        self.derive_and_stage(hash, &k, &h)?;
        let mut reply = vec![SSH_MSG_KEX_ECDH_REPLY];
        wire::put_bytes(&mut reply, &host);
        wire::put_bytes(&mut reply, &q_s);
        wire::put_bytes(&mut reply, &sig);
        self.queue(&reply)?;
        self.send_newkeys()
    }

    fn on_ecdh_reply(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Client {
            return Err(Error::protocol("ecdh reply on server"));
        }
        let mut p = Parser::new(payload);
        p.u8()?;
        let host = p.bytes()?.to_vec();
        let q_s = p.bytes()?.to_vec();
        let _sig = p.bytes()?;
        let run = self.kex.as_mut().ok_or(Error::protocol("no kex"))?;
        let hash = run.hash;
        let theirs = run.theirs.clone();
        let ours = run.ours.clone();
        let client = run.client.take().ok_or(Error::protocol("no client kex"))?;
        let q_c = std::mem::take(&mut run.q_c);
        let k = client.finish(&q_s)?;
        let v_c = self.ident_local.clone();
        let v_s = self.ident_peer.clone().ok_or(Error::protocol("no peer ident"))?;
        let h = exchange_hash(hash, &v_c, &v_s, &ours, &theirs, &host, &q_c, &q_s, &k);
        self.peer_hostkey = Some(host);
        self.derive_and_stage(hash, &k, &h)?;
        self.send_newkeys()
    }

    fn derive_and_stage(&mut self, hash: HashAlg, k: &[u8], h: &[u8]) -> Result<()> {
        if self.session_id.is_none() {
            self.session_id = Some(h.to_vec());
        }
        let sid = self.session_id.clone().unwrap();
        let run = self.kex.as_ref().ok_or(Error::protocol("no kex"))?;
        let (c2s, s2c, mac_c2s, mac_s2c) = (run.cipher_c2s, run.cipher_s2c, run.mac_c2s, run.mac_s2c);
        let is_server = self.role == Role::Server;
        // Letters per RFC 4253 §7.2: A/B ivs c2s/s2c, C/D keys c2s/s2c, E/F macs.
        let mk = |kind: CipherKind, mac: Option<MacKind>, iv_l: u8, key_l: u8, mac_l: u8| -> Result<DirectionKeys> {
            let mut key = vec![0u8; kind.key_len()];
            let mut iv = vec![0u8; kind.iv_len()];
            let mut mac_key = vec![0u8; mac.map(|m| m.key_len()).unwrap_or(0)];
            if !key.is_empty() {
                kdf_block(hash, k, h, &sid, key_l, &mut key);
            }
            if !iv.is_empty() {
                kdf_block(hash, k, h, &sid, iv_l, &mut iv);
            }
            if !mac_key.is_empty() {
                kdf_block(hash, k, h, &sid, mac_l, &mut mac_key);
            }
            DirectionKeys::new(kind, mac, &key, &iv, &mac_key)
        };
        let (send, recv) = if is_server {
            (
                mk(s2c, mac_s2c, b'B', b'D', b'F')?,
                mk(c2s, mac_c2s, b'A', b'C', b'E')?,
            )
        } else {
            (
                mk(c2s, mac_c2s, b'A', b'C', b'E')?,
                mk(s2c, mac_s2c, b'B', b'D', b'F')?,
            )
        };
        self.pending_keys = Some(PendingKeys { send, recv });
        Ok(())
    }

    fn send_newkeys(&mut self) -> Result<()> {
        self.queue(&[SSH_MSG_NEWKEYS])?;
        if let Some(pk) = self.pending_keys.as_mut() {
            self.send_cipher = std::mem::replace(&mut pk.send, DirectionKeys::Clear);
        }
        self.sent_newkeys = true;
        if self.strict_kex {
            self.send_seq = 0;
        }
        self.try_finish_kex()
    }

    fn on_newkeys(&mut self) -> Result<()> {
        let pk = self.pending_keys.take().ok_or(Error::protocol("newkeys without keys"))?;
        self.recv_cipher = pk.recv;
        if !self.sent_newkeys {
            self.pending_keys = Some(PendingKeys {
                send: pk.send,
                recv: DirectionKeys::Clear,
            });
        }
        self.recv_newkeys = true;
        self.try_finish_kex()
    }

    fn try_finish_kex(&mut self) -> Result<()> {
        if !self.sent_newkeys || !self.recv_newkeys {
            return Ok(());
        }
        self.kex = None;
        self.pending_keys = None;
        self.sent_kexinit = false;
        self.bytes_since_kex = 0;
        if !self.first_kex_done {
            self.first_kex_done = true;
            self.events.push_back(Event::KexDone);
            if self.role == Role::Server && self.peer_ext_info {
                self.send_ext_info()?;
            }
            if self.role == Role::Client {
                let mut p = vec![SSH_MSG_SERVICE_REQUEST];
                wire::put_str(&mut p, "ssh-userauth");
                self.queue(&p)?;
            }
            // Connection layer stays blocked until userauth success.
            return Ok(());
        }
        // Rekey finished: unblock and flush every channel.
        self.kex_blocks_app = false;
        for id in self.channels.ids() {
            self.flush_channel(id);
            let _ = self.emit_eof(id);
            let _ = self.emit_close(id);
            self.channels.mark(id);
            // Credits withheld while the key exchange was running have to be
            // re-offered here: the application already drained those bytes, so
            // nothing else will ever call `maybe_adjust_window` again and the
            // peer would sit at a zero window forever.
            self.maybe_adjust_window(id);
        }
        Ok(())
    }

    fn send_ext_info(&mut self) -> Result<()> {
        let mut p = vec![SSH_MSG_EXT_INFO];
        wire::put_u32(&mut p, 1);
        wire::put_str(&mut p, "server-sig-algs");
        wire::put_str(&mut p, &crate::pubkey::SIG_ALGS.join(","));
        self.queue(&p)
    }

    // ── dispatch ─────────────────────────────────────────────────────────────

    fn handle(&mut self, payload: Bytes) -> Result<()> {
        match payload[0] {
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
            SSH_MSG_USERAUTH_REQUEST => self.on_userauth(&payload),
            SSH_MSG_USERAUTH_SUCCESS => {
                self.authed = true;
                self.kex_blocks_app = false;
                let user = self.client.as_ref().map(|c| c.user.clone()).unwrap_or_default();
                self.user = Some(user.clone());
                self.events.push_back(Event::Authenticated { user });
                Ok(())
            }
            SSH_MSG_USERAUTH_FAILURE => Err(Error::Auth),
            SSH_MSG_USERAUTH_BANNER => Ok(()),
            SSH_MSG_GLOBAL_REQUEST => self.on_global_request(&payload),
            SSH_MSG_REQUEST_SUCCESS | SSH_MSG_REQUEST_FAILURE => {
                self.keepalive_outstanding = 0;
                Ok(())
            }
            SSH_MSG_CHANNEL_OPEN => self.on_channel_open(&payload),
            SSH_MSG_CHANNEL_OPEN_CONFIRMATION => self.on_open_confirm(&payload),
            SSH_MSG_CHANNEL_OPEN_FAILURE => self.on_open_failure(&payload),
            SSH_MSG_CHANNEL_WINDOW_ADJUST => self.on_window_adjust(&payload),
            SSH_MSG_CHANNEL_DATA => self.on_channel_data(payload),
            SSH_MSG_CHANNEL_EXTENDED_DATA => self.on_ext_data(&payload),
            SSH_MSG_CHANNEL_EOF => self.on_channel_eof(&payload),
            SSH_MSG_CHANNEL_CLOSE => self.on_channel_close(&payload),
            SSH_MSG_CHANNEL_REQUEST => self.on_channel_request(&payload),
            SSH_MSG_CHANNEL_SUCCESS | SSH_MSG_CHANNEL_FAILURE => Ok(()),
            SSH_MSG_PING => {
                let mut p = Parser::new(&payload);
                p.u8()?;
                let data = p.bytes().unwrap_or(b"");
                let mut m = vec![SSH_MSG_PONG];
                wire::put_bytes(&mut m, data);
                self.queue(&m)
            }
            SSH_MSG_PONG => Ok(()),
            other => {
                let mut p = vec![SSH_MSG_UNIMPLEMENTED];
                wire::put_u32(&mut p, self.recv_seq.wrapping_sub(1));
                let _ = other;
                self.queue(&p)
            }
        }
    }

    fn on_service_request(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Server {
            return Ok(());
        }
        let mut p = Parser::new(payload);
        p.u8()?;
        let name = p.str()?;
        if name != "ssh-userauth" && name != "ssh-connection" {
            self.disconnect(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "unknown service");
            return Ok(());
        }
        let mut r = vec![SSH_MSG_SERVICE_ACCEPT];
        wire::put_str(&mut r, name);
        self.queue(&r)
    }

    fn on_service_accept(&mut self) -> Result<()> {
        if self.role != Role::Client {
            return Ok(());
        }
        let cfg = self.client.as_ref().ok_or(Error::protocol("no client cfg"))?.clone();
        let mut p = vec![SSH_MSG_USERAUTH_REQUEST];
        wire::put_str(&mut p, &cfg.user);
        wire::put_str(&mut p, "ssh-connection");
        wire::put_str(&mut p, "password");
        wire::put_bool(&mut p, false);
        wire::put_str(&mut p, &cfg.password);
        self.queue(&p)
    }

    // ── auth (server) ────────────────────────────────────────────────────────

    fn on_userauth(&mut self, payload: &[u8]) -> Result<()> {
        if self.role != Role::Server || self.authed || self.auth_ctx.is_some() {
            return Ok(());
        }
        let mut p = Parser::new(payload);
        p.u8()?;
        let user = p.str()?.to_string();
        let service = p.str()?;
        let method = p.str()?;
        if service != "ssh-connection" {
            return self.auth_failure();
        }
        let methods = self.server.as_ref().map(|s| s.methods).unwrap_or_default();
        match method {
            "password" if methods.password => {
                let changing = p.bool()?;
                if changing {
                    return self.auth_failure();
                }
                let password = p.str()?.to_string();
                self.auth_ctx = Some(AuthCtx {
                    kind: AuthKind::Password,
                    user: user.clone(),
                    probe: None,
                });
                self.events.push_back(Event::AuthPassword { user, password });
                Ok(())
            }
            "publickey" if methods.publickey && cfg!(feature = "pubkey") => {
                let has_sig = p.bool()?;
                let algo = p.str()?.to_string();
                let key_blob = p.bytes()?.to_vec();
                if !crate::pubkey::is_supported(&algo) || !crate::pubkey::blob_matches(&algo, &key_blob) {
                    return self.auth_failure();
                }
                if !has_sig {
                    self.auth_ctx = Some(AuthCtx {
                        kind: AuthKind::PubkeyProbe,
                        user: user.clone(),
                        probe: Some((algo.clone(), key_blob.clone())),
                    });
                    self.events.push_back(Event::AuthPublicKeyProbe { user, algo, key_blob });
                    return Ok(());
                }
                let sig = p.bytes()?.to_vec();
                let signed = self.pubkey_signed_data(&user, &algo, &key_blob);
                if !crate::pubkey::verify(&algo, &key_blob, &sig, &signed) {
                    return self.auth_failure();
                }
                self.auth_ctx = Some(AuthCtx {
                    kind: AuthKind::Pubkey,
                    user: user.clone(),
                    probe: None,
                });
                self.events.push_back(Event::AuthPublicKey { user, algo, key_blob });
                Ok(())
            }
            _ => self.auth_failure(),
        }
    }

    fn pubkey_signed_data(&self, user: &str, algo: &str, key_blob: &[u8]) -> Vec<u8> {
        let sid = self.session_id.clone().unwrap_or_default();
        let mut m = Vec::with_capacity(sid.len() + key_blob.len() + 64);
        wire::put_bytes(&mut m, &sid);
        m.push(SSH_MSG_USERAUTH_REQUEST);
        wire::put_str(&mut m, user);
        wire::put_str(&mut m, "ssh-connection");
        wire::put_str(&mut m, "publickey");
        wire::put_bool(&mut m, true);
        wire::put_str(&mut m, algo);
        wire::put_bytes(&mut m, key_blob);
        m
    }

    /// Driver's verdict on the pending auth event.
    pub fn resolve_auth(&mut self, accept: bool) -> Result<()> {
        let Some(ctx) = self.auth_ctx.take() else {
            return Ok(());
        };
        if !accept {
            return self.auth_failure();
        }
        match ctx.kind {
            AuthKind::PubkeyProbe => {
                // PK_OK: this key is acceptable; the client re-sends with a signature.
                let (algo, blob) = ctx.probe.unwrap_or_default();
                let mut p = vec![SSH_MSG_USERAUTH_PK_OK];
                wire::put_str(&mut p, &algo);
                wire::put_bytes(&mut p, &blob);
                self.queue(&p)
            }
            AuthKind::Password | AuthKind::Pubkey => {
                self.authed = true;
                self.kex_blocks_app = false;
                self.user = Some(ctx.user.clone());
                self.queue(&[SSH_MSG_USERAUTH_SUCCESS])?;
                self.events.push_back(Event::Authenticated { user: ctx.user });
                Ok(())
            }
        }
    }

    fn auth_failure(&mut self) -> Result<()> {
        self.auth_ctx = None;
        self.auth_fails += 1;
        if self.auth_fails >= self.cfg.max_auth_attempts {
            self.disconnect(SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "too many failures");
            return Ok(());
        }
        let methods = self.server.as_ref().map(|s| s.methods.namelist()).unwrap_or("");
        let mut p = vec![SSH_MSG_USERAUTH_FAILURE];
        wire::put_str(&mut p, methods);
        wire::put_bool(&mut p, false);
        self.queue(&p)
    }

    // ── connection layer ───────────────────────────────────────────────────

    fn on_global_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let _name = p.str().unwrap_or("");
        let want = p.bool().unwrap_or(false);
        if want {
            // We refuse reverse forwarding and every other global request.
            self.queue(&[SSH_MSG_REQUEST_FAILURE])?;
        }
        Ok(())
    }

    fn on_channel_open(&mut self, payload: &[u8]) -> Result<()> {
        if !self.authed {
            return Err(Error::protocol("channel before auth"));
        }
        let mut p = Parser::new(payload);
        p.u8()?;
        let typ = p.str()?.to_string();
        let remote = p.u32()?;
        let send_window = p.u32()?;
        let peer_max_packet = p.u32()?.min(MAX_PACKET as u32);
        let refuse = |me: &mut Self, reason: u32, msg: &str| -> Result<()> {
            let mut f = vec![SSH_MSG_CHANNEL_OPEN_FAILURE];
            wire::put_u32(&mut f, remote);
            wire::put_u32(&mut f, reason);
            wire::put_str(&mut f, msg);
            wire::put_str(&mut f, "");
            me.queue(&f)
        };
        if self.channels.is_full() {
            return refuse(self, SSH_OPEN_RESOURCE_SHORTAGE, "too many channels");
        }
        let window = self.next_window();
        if window == 0 {
            return refuse(self, SSH_OPEN_RESOURCE_SHORTAGE, "window budget");
        }
        match typ.as_str() {
            "session" => {
                let accept = self.server.as_ref().map(|s| s.accept_session_channels).unwrap_or(false);
                if !accept {
                    return refuse(self, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "no session");
                }
                let mut ch = Channel::new(ChannelKind::Session, window, self.cfg.max_packet, send_window, peer_max_packet);
                ch.remote_id = Some(remote);
                let id = self.channels.alloc(ch).unwrap();
                self.window_used += window as u64;
                self.events.push_back(Event::OpenSession { local_id: id });
            }
            "direct-tcpip" => {
                let host = p.str()?.to_string();
                let port = p.u32()?;
                let port: u16 = match port.try_into() {
                    Ok(p) => p,
                    Err(_) => return refuse(self, SSH_OPEN_CONNECT_FAILED, "bad port"),
                };
                let mut ch = Channel::new(ChannelKind::DirectTcpIp, window, self.cfg.max_packet, send_window, peer_max_packet);
                ch.remote_id = Some(remote);
                ch.host = Some(host.clone());
                ch.port = port;
                let id = self.channels.alloc(ch).unwrap();
                self.window_used += window as u64;
                self.events.push_back(Event::OpenDirectTcpIp { local_id: id, host, port });
            }
            _ => return refuse(self, SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "unknown"),
        }
        Ok(())
    }

    fn next_window(&self) -> u32 {
        let room = self.cfg.window_budget.saturating_sub(self.window_used);
        let per_channel = self.cfg.window_initial.min(self.cfg.window_max);
        (per_channel as u64).min(room) as u32
    }

    /// Confirm a channel the driver accepted.
    pub fn accept_channel(&mut self, id: u32) -> Result<()> {
        let (remote, window, max_pkt) = {
            let ch = self.channels.get_mut(id).ok_or(Error::protocol("no channel"))?;
            ch.open_confirmed = true;
            (ch.remote_id.ok_or(Error::protocol("no remote id"))?, ch.recv_max, ch.local_max_packet)
        };
        let mut m = vec![SSH_MSG_CHANNEL_OPEN_CONFIRMATION];
        wire::put_u32(&mut m, remote);
        wire::put_u32(&mut m, id);
        wire::put_u32(&mut m, window);
        wire::put_u32(&mut m, max_pkt);
        self.queue(&m)
    }

    /// Refuse a channel the driver rejected.
    pub fn reject_channel(&mut self, id: u32, reason: u32, msg: &str) -> Result<()> {
        let remote = self.channels.get(id).and_then(|c| c.remote_id);
        let window = self.channels.get(id).map(|c| c.recv_max as u64).unwrap_or(0);
        self.window_used = self.window_used.saturating_sub(window);
        self.channels.free(id);
        if let Some(remote) = remote {
            let mut f = vec![SSH_MSG_CHANNEL_OPEN_FAILURE];
            wire::put_u32(&mut f, remote);
            wire::put_u32(&mut f, reason);
            wire::put_str(&mut f, msg);
            wire::put_str(&mut f, "");
            self.queue(&f)?;
        }
        Ok(())
    }

    fn on_open_confirm(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let remote = p.u32()?;
        let window = p.u32()?;
        let max_pkt = p.u32()?.min(MAX_PACKET as u32);
        if let Some(ch) = self.channels.get_mut(local) {
            ch.remote_id = Some(remote);
            ch.send_window = window;
            ch.peer_max_packet = max_pkt;
            ch.open_confirmed = true;
        }
        self.flush_channel(local);
        self.events.push_back(Event::OpenConfirmed { local_id: local });
        Ok(())
    }

    fn on_open_failure(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let reason = p.u32()?;
        let message = p.str().unwrap_or("").to_string();
        let window = self.channels.get(local).map(|c| c.recv_max as u64).unwrap_or(0);
        self.window_used = self.window_used.saturating_sub(window);
        self.channels.free(local);
        self.events.push_back(Event::OpenFailed { local_id: local, reason, message });
        Ok(())
    }

    fn on_window_adjust(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let add = p.u32()?;
        if let Some(ch) = self.channels.get_mut(local) {
            ch.send_window = ch.send_window.saturating_add(add);
        }
        self.flush_channel(local);
        self.events.push_back(Event::ChannelWindow { local_id: local });
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
        if let Some(ch) = self.channels.get_mut(local) {
            if dlen as u32 > ch.recv_window {
                return Err(Error::protocol("window exceeded"));
            }
            ch.recv_window -= dlen as u32;
            ch.in_q_bytes += dlen;
            ch.in_q.push_back(data);
            self.events.push_back(Event::ChannelData { local_id: local });
        }
        Ok(())
    }

    fn on_ext_data(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let _code = p.u32()?;
        let data = Bytes::copy_from_slice(p.bytes()?);
        if let Some(ch) = self.channels.get_mut(local) {
            let dlen = data.len();
            if dlen as u32 > ch.recv_window {
                return Err(Error::protocol("window exceeded"));
            }
            ch.recv_window -= dlen as u32;
            ch.in_q_bytes += dlen;
            ch.in_q.push_back(data);
            self.events.push_back(Event::ChannelData { local_id: local });
        }
        Ok(())
    }

    fn on_channel_eof(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        if let Some(ch) = self.channels.get_mut(local) {
            ch.got_eof = true;
        }
        self.events.push_back(Event::ChannelEof { local_id: local });
        Ok(())
    }

    fn on_channel_close(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let already = match self.channels.get_mut(local) {
            Some(ch) => {
                ch.got_close = true;
                ch.got_eof = true;
                ch.sent_close
            }
            None => return Ok(()),
        };
        if already {
            self.finalize_channel(local);
        } else {
            let _ = self.send_close(local);
        }
        self.events.push_back(Event::ChannelClose { local_id: local });
        Ok(())
    }

    fn on_channel_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut p = Parser::new(payload);
        p.u8()?;
        let local = p.u32()?;
        let _name = p.str().unwrap_or("");
        let want = p.bool().unwrap_or(false);
        if want {
            if let Some(remote) = self.channels.get(local).and_then(|c| c.remote_id) {
                // We support no channel requests (no shell/pty/exec).
                let mut m = vec![SSH_MSG_CHANNEL_FAILURE];
                wire::put_u32(&mut m, remote);
                self.queue(&m)?;
            }
        }
        Ok(())
    }

    // ── channel data plane API (driver side) ─────────────────────────────────

    /// Peer bytes waiting to be handed to the application.
    pub fn inbound_front(&self, id: u32) -> Option<&[u8]> {
        self.channels.get(id).and_then(|c| c.in_q.front().map(|b| b.as_ref()))
    }

    pub fn consume_inbound(&mut self, id: u32, n: usize) {
        {
            let Some(ch) = self.channels.get_mut(id) else {
                return;
            };
            let Some(front) = ch.in_q.front_mut() else {
                return;
            };
            let take = n.min(front.len());
            if take == front.len() {
                let b = ch.in_q.pop_front().unwrap();
                ch.in_q_bytes -= b.len();
            } else {
                let _ = front.split_to(take);
                ch.in_q_bytes -= take;
            }
        }
        self.maybe_adjust_window(id);
        // Draining the last bytes of an already-closed channel releases it.
        self.finalize_channel(id);
    }

    /// Discard peer bytes the application will never read (its stream is gone).
    pub fn discard_inbound(&mut self, id: u32) {
        if let Some(ch) = self.channels.get_mut(id) {
            ch.in_q.clear();
            ch.in_q_bytes = 0;
        }
        self.finalize_channel(id);
    }

    fn maybe_adjust_window(&mut self, id: u32) {
        if self.kex_blocks_app {
            return;
        }
        let (remote, add) = {
            let Some(ch) = self.channels.get(id) else {
                return;
            };
            (ch.remote_id, ch.window_adjust())
        };
        if add == 0 {
            return;
        }
        if let Some(ch) = self.channels.get_mut(id) {
            ch.recv_window += add;
        }
        if let Some(r) = remote {
            let mut m = vec![SSH_MSG_CHANNEL_WINDOW_ADJUST];
            wire::put_u32(&mut m, r);
            wire::put_u32(&mut m, add);
            let _ = self.queue(&m);
        }
    }

    /// How much application data we may hand to `send_data` right now.
    pub fn send_capacity(&self, id: u32) -> usize {
        if self.write_bytes >= self.cfg.out_soft && !self.kex_blocks_app {
            return 0;
        }
        let Some(ch) = self.channels.get(id) else {
            return 0;
        };
        if !ch.can_send() {
            return 0;
        }
        if self.kex_blocks_app {
            // During rekey we may buffer up to one packet per channel.
            return (self.cfg.max_packet as usize).saturating_sub(ch.pending_out_bytes);
        }
        (ch.send_window as usize).min(ch.peer_max_packet as usize)
    }

    pub fn send_data(&mut self, id: u32, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut sent = 0;
        loop {
            let cap = self.send_capacity(id);
            if cap == 0 || sent >= data.len() {
                break;
            }
            let n = cap.min(data.len() - sent);
            self.enqueue_out(id, &data[sent..sent + n])?;
            sent += n;
        }
        Ok(sent)
    }

    /// Hand `data` to the channel. Copies only when it has to be parked
    /// (window exhausted, or a key exchange is running); the straight-to-wire
    /// path seals the caller's bytes directly.
    fn enqueue_out(&mut self, id: u32, data: &[u8]) -> Result<()> {
        let (remote, wire_now, max_pkt, window) = {
            let Some(ch) = self.channels.get(id) else {
                return Ok(());
            };
            (
                ch.remote_id,
                ch.can_send() && !self.kex_blocks_app,
                ch.peer_max_packet,
                ch.send_window,
            )
        };
        if !wire_now || remote.is_none() || window == 0 {
            if let Some(ch) = self.channels.get_mut(id) {
                ch.pending_out_bytes += data.len();
                ch.pending_out.push_back(Bytes::copy_from_slice(data));
            }
            return Ok(());
        }
        let n = data.len().min(max_pkt as usize).min(window as usize);
        if n < data.len() {
            if let Some(ch) = self.channels.get_mut(id) {
                ch.pending_out.push_front(Bytes::copy_from_slice(&data[n..]));
                ch.pending_out_bytes += data.len() - n;
            }
        }
        if let Some(ch) = self.channels.get_mut(id) {
            ch.send_window -= n as u32;
        }
        self.send_channel_data(remote.unwrap(), &data[..n])
    }

    fn send_channel_data(&mut self, remote: u32, data: &[u8]) -> Result<()> {
        let len = data.len() as u32;
        let mut hdr = [0u8; 9];
        hdr[0] = SSH_MSG_CHANNEL_DATA;
        hdr[1..5].copy_from_slice(&remote.to_be_bytes());
        hdr[5..9].copy_from_slice(&len.to_be_bytes());
        self.queue_parts(&[&hdr, data])
    }

    fn flush_channel(&mut self, id: u32) {
        if self.kex_blocks_app {
            return;
        }
        loop {
            let (remote, len, max_pkt, window, can) = {
                let Some(ch) = self.channels.get(id) else {
                    return;
                };
                (
                    ch.remote_id,
                    ch.pending_out.front().map(|b| b.len()).unwrap_or(0),
                    ch.peer_max_packet,
                    ch.send_window,
                    ch.can_write(),
                )
            };
            if !can || remote.is_none() || window == 0 || len == 0 || self.write_bytes >= self.cfg.out_soft
            {
                return;
            }
            let take = len.min(max_pkt as usize).min(window as usize);
            let chunk = {
                let ch = self.channels.get_mut(id).unwrap();
                let front = ch.pending_out.front_mut().unwrap();
                let b = if take >= front.len() {
                    ch.pending_out.pop_front().unwrap()
                } else {
                    front.split_to(take)
                };
                ch.pending_out_bytes -= b.len();
                ch.send_window -= b.len() as u32;
                b
            };
            if self.send_channel_data(remote.unwrap(), &chunk).is_err() {
                return;
            }
        }
    }

    pub fn open_direct_tcpip(&mut self, host: &str, port: u16) -> Result<u32> {
        if self.role != Role::Client || !self.authed {
            return Err(Error::protocol("open before ready"));
        }
        let window = self.next_window();
        let mut ch = Channel::new(ChannelKind::DirectTcpIp, window, self.cfg.max_packet, 0, 0);
        ch.host = Some(host.to_string());
        ch.port = port;
        let id = self.channels.alloc(ch).ok_or(Error::protocol("too many channels"))?;
        self.window_used += window as u64;
        let mut p = vec![SSH_MSG_CHANNEL_OPEN];
        wire::put_str(&mut p, "direct-tcpip");
        wire::put_u32(&mut p, id);
        wire::put_u32(&mut p, window);
        wire::put_u32(&mut p, self.cfg.max_packet);
        wire::put_str(&mut p, host);
        wire::put_u32(&mut p, port as u32);
        wire::put_str(&mut p, "127.0.0.1");
        wire::put_u32(&mut p, 0);
        self.queue(&p)?;
        Ok(id)
    }

    pub fn send_eof(&mut self, id: u32) -> Result<()> {
        {
            let Some(ch) = self.channels.get_mut(id) else {
                return Ok(());
            };
            if ch.sent_close {
                return Ok(());
            }
            ch.sent_eof = true;
        }
        // Not short-circuited on an already-set flag: `emit_eof` defers while
        // `pending_out` is non-empty, and this call is the retry.
        self.emit_eof(id)
    }

    pub fn send_close(&mut self, id: u32) -> Result<()> {
        {
            let Some(ch) = self.channels.get_mut(id) else {
                return Ok(());
            };
            ch.sent_close = true;
            ch.sent_eof = true;
        }
        // Retried on every call: a first attempt made while `pending_out` still
        // held bytes would otherwise never be repeated, leaving the channel open
        // with a tail the peer never receives.
        self.emit_close(id)
    }

    /// Push the connection's own queued channel data out while peer credit
    /// allows. `pending_out` fills up only while a key exchange blocks
    /// application data, and nothing else re-drives it afterwards.
    pub fn flush_pending(&mut self, id: u32) {
        self.flush_channel(id);
    }

    fn emit_eof(&mut self, id: u32) -> Result<()> {
        if self.kex_blocks_app {
            return Ok(());
        }
        let remote = {
            let Some(ch) = self.channels.get_mut(id) else {
                return Ok(());
            };
            if !ch.sent_eof || ch.wire_eof || !ch.pending_out.is_empty() {
                return Ok(());
            }
            ch.wire_eof = true;
            ch.remote_id
        };
        if let Some(r) = remote {
            let mut p = vec![SSH_MSG_CHANNEL_EOF];
            wire::put_u32(&mut p, r);
            self.queue(&p)?;
        }
        Ok(())
    }

    fn emit_close(&mut self, id: u32) -> Result<()> {
        if self.kex_blocks_app {
            return Ok(());
        }
        let remote = {
            let Some(ch) = self.channels.get_mut(id) else {
                return Ok(());
            };
            if !ch.sent_close || ch.wire_close || !ch.pending_out.is_empty() {
                return Ok(());
            }
            ch.wire_close = true;
            ch.wire_eof = true;
            ch.remote_id
        };
        if let Some(r) = remote {
            let mut p = vec![SSH_MSG_CHANNEL_CLOSE];
            wire::put_u32(&mut p, r);
            self.queue(&p)?;
        }
        self.finalize_channel(id);
        Ok(())
    }

    /// Release a fully closed channel. A CHANNEL_CLOSE says the peer will send
    /// no more data — it does not cancel bytes that already arrived, so the slot
    /// (and its `in_q`) is kept until the application has drained them.
    fn finalize_channel(&mut self, id: u32) {
        let done = self
            .channels
            .get(id)
            .map(|c| c.got_close && c.wire_close && c.in_q.is_empty())
            .unwrap_or(false);
        if done {
            let window = self.channels.get(id).map(|c| c.recv_max as u64).unwrap_or(0);
            self.window_used = self.window_used.saturating_sub(window);
            self.channels.free(id);
        }
    }

    pub fn channel_alive(&self, id: u32) -> bool {
        self.channels.get(id).is_some()
    }
    pub fn channel_kind(&self, id: u32) -> Option<ChannelKind> {
        self.channels.get(id).map(|c| c.kind)
    }
    pub fn channel_got_eof(&self, id: u32) -> bool {
        self.channels.get(id).map(|c| c.got_eof).unwrap_or(true)
    }
    pub fn next_dirty(&mut self) -> Option<u32> {
        self.channels.next_dirty()
    }

    /// Debug snapshot: (kex_blocks_app, needs_kex, send_window, pending_out, recv_window, in_q).
    pub fn dbg_channel(&self, id: u32) -> (bool, bool, u32, usize, u32, usize) {
        let ch = self.channels.get(id);
        (
            self.kex_blocks_app,
            self.kex.is_some() || self.sent_kexinit,
            ch.map(|c| c.send_window).unwrap_or(0),
            ch.map(|c| c.pending_out_bytes).unwrap_or(0),
            ch.map(|c| c.recv_window).unwrap_or(0),
            ch.map(|c| c.in_q_bytes).unwrap_or(0),
        )
    }

    // ── timers / keepalive ───────────────────────────────────────────────────

    pub fn needs_kex(&self) -> bool {
        self.kex.is_some() || !self.first_kex_done
    }

    /// Force a key exchange (test/manual). No-op if one is already running or
    /// the first exchange has not completed.
    pub fn trigger_rekey(&mut self) -> Result<()> {
        if self.first_kex_done && self.kex.is_none() && !self.sent_kexinit && !self.closed {
            self.start_kex()?;
        }
        Ok(())
    }

    /// Send a keepalive global request; returns false if the budget is spent.
    pub fn send_keepalive(&mut self) -> Result<bool> {
        if self.keepalive_outstanding >= self.cfg.keepalive_max {
            return Ok(false);
        }
        self.keepalive_outstanding += 1;
        let mut p = vec![SSH_MSG_GLOBAL_REQUEST];
        wire::put_str(&mut p, "keepalive@openssh.com");
        wire::put_bool(&mut p, true);
        self.queue(&p)?;
        Ok(true)
    }

    pub fn disconnect(&mut self, reason: u32, msg: &str) {
        if self.closed {
            return;
        }
        let mut p = vec![SSH_MSG_DISCONNECT];
        wire::put_u32(&mut p, reason);
        wire::put_str(&mut p, msg);
        wire::put_str(&mut p, "");
        let _ = self.queue(&p);
        self.closed = true;
    }

    // ── low-level packet sealing ─────────────────────────────────────────────

    fn queue(&mut self, payload: &[u8]) -> Result<()> {
        self.queue_parts(&[payload])
    }

    /// Seal `parts` as one packet's payload. Callers that assemble a payload
    /// from a header plus a body pass both slices and skip the intermediate
    /// buffer — the sealed frame is the only allocation on the wire path.
    fn queue_parts(&mut self, parts: &[&[u8]]) -> Result<()> {
        let payload_len: usize = parts.iter().map(|p| p.len()).sum();
        if payload_len == 0 {
            return Err(Error::protocol("empty payload"));
        }
        let block = self.send_cipher.block_size();
        let tag = self.send_cipher.tag_len();
        let aad = self.send_cipher.length_is_aad();
        let pad = padding_len(payload_len, block, aad);
        let plen = 1 + payload_len + pad;
        let total = 4 + plen + tag;
        // Every byte of the frame is written below — length, pad byte, payload,
        // random padding, and then `seal` fills the tag and encrypts in place —
        // so there is nothing to pre-zero. `BytesMut::zeroed` would memset a
        // 32 KiB buffer per packet on a path measured at ~4.6 ns/byte.
        let mut buf = BytesMut::with_capacity(total);
        // SAFETY: capacity for exactly `total` was just reserved; the bytes are
        // uninitialised and every one of them is overwritten before any read of
        // the buffer (the writes below, then `seal`, which reads only what was
        // written and overwrites the packet in place).
        unsafe { buf.set_len(total) };
        buf[..4].copy_from_slice(&(plen as u32).to_be_bytes());
        buf[4] = pad as u8;
        let mut off = 5;
        for part in parts {
            buf[off..off + part.len()].copy_from_slice(part);
            off += part.len();
        }
        self.pad_rng.fill_bytes(&mut buf[off..off + pad]);
        let (pkt, tag_out) = buf.split_at_mut(4 + plen);
        self.send_cipher.seal(self.send_seq, pkt, tag_out)?;
        self.send_seq = self.send_seq.wrapping_add(1);
        self.bytes_since_kex += total as u64;
        let frozen = buf.freeze();
        self.write_bytes += frozen.len();
        self.write_q.push_back(frozen);
        Ok(())
    }
}

fn kdf_block(hash: HashAlg, k: &[u8], h: &[u8], sid: &[u8], letter: u8, out: &mut [u8]) {
    crate::crypto::kdf::derive(hash, k, h, sid, letter, out);
}

#[allow(clippy::too_many_arguments)]
fn exchange_hash(
    hash: HashAlg,
    v_c: &str,
    v_s: &str,
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8],
    q_s: &[u8],
    k: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256 + i_c.len() + i_s.len());
    wire::put_str(&mut buf, v_c);
    wire::put_str(&mut buf, v_s);
    wire::put_bytes(&mut buf, i_c);
    wire::put_bytes(&mut buf, i_s);
    wire::put_bytes(&mut buf, k_s);
    wire::put_bytes(&mut buf, q_c);
    wire::put_bytes(&mut buf, q_s);
    buf.extend_from_slice(k);
    hash.digest_parts(&[&buf])
}
