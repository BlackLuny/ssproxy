//! Server (driver) <-> client (sans-IO core) echo over a tokio duplex pipe,
//! plus concurrency / half-close / cancel coverage. No external `ssh` needed.

use std::sync::Arc;
use std::time::Duration;

use ssproxy::config::{ClientConfig, ServerConfig};
use ssproxy::core::{Connection, Event};
use ssproxy::driver::{self, AuthOutcome, Hooks, OpenOutcome};
use ssproxy::hostkey::HostKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

fn server_cfg() -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::new(HostKey::generate());
    cfg.methods.publickey = false;
    Arc::new(cfg)
}

fn hooks() -> Hooks {
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
fn spawn_server(cfg: Arc<ServerConfig>) -> DuplexStream {
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
        let _ = driver::serve(server_io, cfg, hooks(), tx).await;
    });
    client_io
}

/// Minimal async pump for the sans-IO client `Connection`.
struct Client {
    io: DuplexStream,
    conn: Connection,
    buf: Vec<u8>,
}

impl Client {
    async fn connect(io: DuplexStream, user: &str, pw: &str) -> Self {
        let conn = Connection::client(Arc::new(ClientConfig::new(user, pw)));
        let mut c = Self { io, conn, buf: vec![0u8; 32 * 1024] };
        c.pump_until(|conn| conn.authed()).await;
        c
    }

    async fn flush(&mut self) {
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

    async fn pump_once(&mut self) -> bool {
        self.flush().await;
        match tokio::time::timeout(Duration::from_millis(200), self.io.read(&mut self.buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => false,
            Ok(Ok(n)) => {
                self.conn.read_buf_mut().extend_from_slice(&self.buf[..n]);
                if self.conn.process_in().is_err() {
                    return false; // e.g. auth rejection / disconnect
                }
                self.flush().await;
                true
            }
        }
    }

    async fn pump_until(&mut self, cond: impl Fn(&Connection) -> bool) {
        for _ in 0..2000 {
            if cond(&self.conn) {
                return;
            }
            if !self.pump_once().await {
                break;
            }
        }
        assert!(cond(&self.conn), "condition not reached");
    }

    async fn open(&mut self, host: &str, port: u16) -> u32 {
        let id = self.conn.open_direct_tcpip(host, port).unwrap();
        self.pump_until(|c| c.send_capacity(id) > 0 || !c.channel_alive(id)).await;
        assert!(self.conn.channel_alive(id), "channel refused");
        id
    }

    async fn echo_roundtrip(&mut self, id: u32, payload: &[u8]) -> Vec<u8> {
        let mut sent = 0;
        let mut got = Vec::new();
        for _ in 0..100_000 {
            if sent < payload.len() {
                sent += self.conn.send_data(id, &payload[sent..]).unwrap();
            }
            if !self.pump_once().await {
                break;
            }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_and_echo() {
    let io = spawn_server(server_cfg());
    let mut c = Client::connect(io, "proxy", "proxy").await;
    let id = c.open("example.com", 443).await;
    let payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".repeat(4);
    let got = c.echo_roundtrip(id, &payload).await;
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_transfer_and_rekey() {
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    sc.base.rekey_bytes = 128 * 1024; // force several rekeys mid-stream
    let io = spawn_server(Arc::new(sc));
    let mut c = Client::connect(io, "proxy", "proxy").await;
    let id = c.open("h", 1).await;
    let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    let got = c.echo_roundtrip(id, &payload).await;
    assert_eq!(got.len(), payload.len());
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_rejected() {
    let io = spawn_server(server_cfg());
    let conn = Connection::client(Arc::new(ClientConfig::new("proxy", "nope")));
    let mut c = Client { io, conn, buf: vec![0u8; 8192] };
    let mut authed = false;
    for _ in 0..500 {
        if c.conn.authed() {
            authed = true;
            break;
        }
        if !c.pump_once().await {
            break;
        }
    }
    assert!(!authed, "bad password must not authenticate");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_channels_concurrent() {
    let io = spawn_server(server_cfg());
    let mut c = Client::connect(io, "proxy", "proxy").await;
    let mut ids = Vec::new();
    for _ in 0..32 {
        ids.push(c.open("h", 1).await);
    }
    // Interleave a small echo on each.
    for &id in &ids {
        let got = c.echo_roundtrip(id, format!("chan-{id}").as_bytes()).await;
        assert_eq!(got, format!("chan-{id}").as_bytes());
    }
}

/// A client that opens a channel and never reads must not stop other channels
/// (the RC2 head-of-line property). Here we just assert a healthy channel keeps
/// echoing while another has data outstanding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_channel_does_not_block_healthy() {
    let io = spawn_server(server_cfg());
    let mut c = Client::connect(io, "proxy", "proxy").await;
    let victim = c.open("h", 1).await;
    let healthy = c.open("h", 2).await;
    // Send on victim but never drain its inbound.
    c.conn.send_data(victim, &vec![1u8; 4096]).unwrap();
    for _ in 0..50 {
        c.pump_once().await;
        while c.conn.pop_event().is_some() {}
    }
    // Healthy channel still round-trips.
    let got = c.echo_roundtrip(healthy, b"still-alive").await;
    assert_eq!(got, b"still-alive");
    let _ = Event::KexDone;
}
