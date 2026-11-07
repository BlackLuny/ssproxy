//! Shared harness for the integration tests: a driver-backed echo server on
//! one end of a duplex pipe, a sans-IO client `Connection` pump on the other,
//! and a sans-IO server core pump for tests that poke protocol state directly.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use ssproxy::config::{ClientConfig, ServerConfig};
use ssproxy::core::{Connection, Event};
use ssproxy::driver::{self, AuthOutcome, Hooks, OpenOutcome};
use ssproxy::hostkey::HostKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

pub fn server_cfg() -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::new(HostKey::generate());
    cfg.methods.publickey = false;
    Arc::new(cfg)
}

pub fn hooks() -> Hooks {
    Hooks {
        auth_password: Box::new(|u, p| {
            if u == "proxy" && p == "proxy" {
                AuthOutcome::Accept
            } else {
                AuthOutcome::Reject { delay: Duration::from_millis(10) }
            }
        }),
        open: Box::new(|_, _, _| OpenOutcome::Accept),
        ..Hooks::default()
    }
}

/// Spawn the server driver on one end of a duplex pipe; echo every incoming
/// channel back to itself. Returns the client end.
pub fn spawn_server(cfg: Arc<ServerConfig>) -> DuplexStream {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<driver::IncomingChannel>();
    tokio::spawn(async move {
        while let Some(ch) = rx.recv().await {
            tokio::spawn(async move {
                let mut s = ch.stream;
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = s.shutdown().await;
            });
        }
    });
    tokio::spawn(async move {
        if let Err(e) = driver::serve(server_io, cfg, hooks(), tx).await {
            eprintln!("[test server] session ended: {e:?}");
        }
    });
    client_io
}

/// Minimal async pump for the sans-IO client `Connection`.
/// Outcome of one pump round.
#[derive(Debug, Clone, Copy)]
pub enum Pump {
    /// Bytes were read and processed.
    Progress,
    /// Nothing arrived this round; the peer may still be working.
    Idle,
    /// The connection is gone, for this reason.
    Dead(&'static str),
}

impl Pump {
    pub fn why(&self) -> &'static str {
        match self {
            Pump::Dead(why) => why,
            Pump::Progress => "made progress",
            Pump::Idle => "idle",
        }
    }
}

pub struct Client {
    pub io: DuplexStream,
    pub conn: Connection,
    pub buf: Vec<u8>,
}

impl Client {
    pub async fn connect(io: DuplexStream, user: &str, pw: &str) -> Self {
        let conn = Connection::client(Arc::new(ClientConfig::new(user, pw)));
        let mut c = Self { io, conn, buf: vec![0u8; 32 * 1024] };
        c.pump_until(|conn| conn.authed()).await;
        c
    }

    pub async fn flush(&mut self) {
        loop {
            let res = {
                let Some(chunk) = self.conn.peek_out() else { break };
                self.io.write(chunk).await
            };
            match res {
                Ok(n) if n > 0 => self.conn.consume_out(n),
                _ => break,
            }
        }
        let _ = self.io.flush().await;
    }

    pub async fn pump_once(&mut self) -> bool {
        matches!(self.pump_round().await, Pump::Progress)
    }

    /// One round, distinguishing "the peer had nothing to say yet" from "the
    /// connection is gone". A quiet round is normal under load; only the latter
    /// ends a wait.
    pub async fn pump_round(&mut self) -> Pump {
        self.flush().await;
        match tokio::time::timeout(Duration::from_millis(200), self.io.read(&mut self.buf)).await {
            Ok(Ok(0)) => Pump::Dead("peer closed"),
            Ok(Err(_)) => Pump::Dead("read error"),
            Err(_) => Pump::Idle,
            Ok(Ok(n)) => {
                self.conn.read_buf_mut().extend_from_slice(&self.buf[..n]);
                match self.conn.process_in() {
                    Ok(()) => {
                        self.flush().await;
                        Pump::Progress
                    }
                    Err(_) => Pump::Dead("protocol error"), // e.g. auth rejection
                }
            }
        }
    }

    /// Wait for `cond` while pumping. A round that reads nothing is *not* a
    /// failure — under a loaded machine the peer can take longer than
    /// `pump_once`'s read timeout to produce the next packet — so only the
    /// deadline ends the wait.
    pub async fn pump_until(&mut self, cond: impl Fn(&Connection) -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut last = Pump::Idle;
        for _ in 0..2000 {
            if cond(&self.conn) {
                return;
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            last = self.pump_round().await;
            if matches!(last, Pump::Dead(_)) {
                break;
            }
        }
        assert!(
            cond(&self.conn),
            "condition not reached (last round: {}, authed={}, peer={:?})",
            last.why(),
            self.conn.authed(),
            self.conn.peer_ident(),
        );
    }

    pub async fn open(&mut self, host: &str, port: u16) -> u32 {
        let id = self.conn.open_direct_tcpip(host, port).unwrap();
        // Wait for the open to be *answered*. The channel may already be past
        // its confirmation: a peer that writes and closes immediately can land
        // CONFIRMATION, DATA and CLOSE in one read, leaving no send credit to
        // wait for while the channel is still delivering what it buffered.
        self.pump_until(|c| {
            c.send_capacity(id) > 0 || c.channel_got_eof(id) || !c.channel_alive(id)
        })
        .await;
        assert!(self.conn.channel_alive(id), "channel refused");
        id
    }

    pub async fn echo_roundtrip(&mut self, id: u32, payload: &[u8]) -> Vec<u8> {
        let mut sent = 0;
        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        for _ in 0..100_000 {
            if sent < payload.len() {
                sent += self.conn.send_data(id, &payload[sent..]).unwrap();
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            self.pump_once().await;
            while let Some(d) = self.conn.inbound_front(id).map(|d| d.to_vec()) {
                let n = d.len();
                self.conn.consume_inbound(id, n);
                got.extend_from_slice(&d);
            }
            while self.conn.pop_event().is_some() {}
            if sent == payload.len() && got.len() == payload.len() {
                break;
            }
        }
        got
    }
}

/// Server-side sans-IO core pump. The driver normally owns the `Connection`;
/// this test pokes connection state directly, so it drives the core itself.
pub struct ServerCore {
    pub io: DuplexStream,
    pub conn: Connection,
    pub buf: Vec<u8>,
    pub channel: Option<u32>,
    /// Every channel accepted, in order.
    pub channels: Vec<u32>,
}

impl ServerCore {
    pub async fn pump(&mut self) -> bool {
        loop {
            let res = {
                let Some(chunk) = self.conn.peek_out() else { break };
                self.io.write(chunk).await
            };
            match res {
                Ok(n) if n > 0 => self.conn.consume_out(n),
                _ => break,
            }
        }
        let _ = self.io.flush().await;
        match tokio::time::timeout(Duration::from_millis(200), self.io.read(&mut self.buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return false,
            Ok(Ok(n)) => {
                self.conn.read_buf_mut().extend_from_slice(&self.buf[..n]);
                if self.conn.process_in().is_err() {
                    return false;
                }
            }
        }
        while let Some(ev) = self.conn.pop_event() {
            match ev {
                Event::AuthPassword { .. }
                | Event::AuthPublicKeyProbe { .. }
                | Event::AuthPublicKey { .. } => self.conn.resolve_auth(true).unwrap(),
                Event::OpenDirectTcpIp { local_id, .. } => {
                    self.conn.accept_channel(local_id).unwrap();
                    self.channel = Some(local_id);
                    self.channels.push(local_id);
                }
                _ => {}
            }
        }
        true
    }
}


impl ServerCore {
    pub fn new(io: DuplexStream, cfg: Arc<ServerConfig>) -> Self {
        Self {
            io,
            conn: Connection::server(cfg),
            buf: vec![0u8; 16 * 1024],
            channel: None,
            channels: Vec::new(),
        }
    }
}

/// One short write: move at most `max` of what `src` has sealed into `dst`'s
/// read buffer. Returns the bytes moved.
pub fn xfer_max(src: &mut Connection, dst: &mut Connection, max: usize) -> usize {
    let n = {
        let Some(chunk) = src.peek_out() else { return 0 };
        let n = chunk.len().min(max);
        dst.read_buf_mut().extend_from_slice(&chunk[..n]);
        n
    };
    src.consume_out(n);
    n
}

/// Move everything `src` has sealed into `dst`.
pub fn xfer(src: &mut Connection, dst: &mut Connection) {
    while xfer_max(src, dst, usize::MAX) > 0 {}
}

/// Exchange core <-> core until the client is authenticated and (if
/// `want_open`) the client's channel is confirmed. Returns the server-side
/// local id of the last accepted channel.
pub fn core_handshake(c: &mut Connection, s: &mut Connection, want_open: bool) -> Option<u32> {
    let mut sch = None;
    for _ in 0..1000 {
        if c.authed() && (!want_open || sch.is_some()) {
            return sch;
        }
        xfer(c, s);
        xfer(s, c);
        s.process_in().unwrap();
        c.process_in().unwrap();
        while let Some(ev) = s.pop_event() {
            match ev {
                Event::AuthPassword { .. }
                | Event::AuthPublicKeyProbe { .. }
                | Event::AuthPublicKey { .. } => s.resolve_auth(true).unwrap(),
                Event::OpenDirectTcpIp { local_id, .. } => {
                    s.accept_channel(local_id).unwrap();
                    sch = Some(local_id);
                }
                _ => {}
            }
        }
        while c.pop_event().is_some() {}
    }
    panic!("core handshake did not converge");
}
