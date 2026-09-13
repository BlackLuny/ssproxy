//! Server (driver) <-> client (sans-IO core) echo over a tokio duplex pipe,
//! plus concurrency / half-close / cancel coverage. No external `ssh` needed.

use std::sync::Arc;
use std::time::Duration;

use ssproxy::config::{ClientConfig, ServerConfig};
use ssproxy::core::{Connection, Event};
use ssproxy::driver;
use ssproxy::hostkey::HostKey;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

mod common;
use common::*;

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

/// A channel must keep getting window credit back as the application drains it.
/// With `window_max == window_initial` the old replenishment rule produced no
/// adjust at all, so a transfer wedged after exactly one window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_window_replenishes_when_max_equals_initial() {
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    sc.base.window_initial = 16 * 1024;
    sc.base.window_max = 16 * 1024; // no headroom above the initial window
    let io = spawn_server(Arc::new(sc));
    let mut c = Client::connect(io, "proxy", "proxy").await;
    let id = c.open("h", 1).await;

    // Several windows' worth, so the channel must be replenished repeatedly.
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let got = c.echo_roundtrip(id, &payload).await;
    assert_eq!(got.len(), payload.len(), "flow control wedged after one window");
    assert_eq!(got, payload);
}

/// A stream that closes while bytes are still buffered for it must deliver
/// those bytes first. The bytes pile up in `pending_out` when a key exchange
/// blocks application data; a close arriving in that window used to make the
/// channel unwritable, so the tail was stranded and the CLOSE never emitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_flushes_data_buffered_during_rekey() {
    const PAYLOAD: usize = 8 * 1024;
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut s = ServerCore::new(server_io, Arc::new(sc));
    let mut c = Client {
        io: client_io,
        conn: Connection::client(Arc::new(ClientConfig::new("proxy", "proxy"))),
        buf: vec![0u8; 32 * 1024],
    };

    // Both ends are cores here, so both have to be pumped for anything to move.
    for _ in 0..2000 {
        if c.conn.authed() {
            break;
        }
        s.pump().await;
        c.pump_once().await;
    }
    assert!(c.conn.authed(), "handshake stalled");

    let id = c.conn.open_direct_tcpip("h", 1).unwrap();
    for _ in 0..2000 {
        if c.conn.send_capacity(id) > 0 && s.channel.is_some() {
            break;
        }
        s.pump().await;
        c.pump_once().await;
    }
    let sch = s.channel.expect("server accepted the channel");

    // Start a rekey, buffer payload behind it, then close the channel.
    s.conn.trigger_rekey().unwrap();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let queued = s.conn.send_data(sch, &payload).unwrap();
    assert_eq!(queued, PAYLOAD, "rekey must buffer, not drop");
    s.conn.send_close(sch).unwrap();

    // Let the key exchange finish, then give the connection its retry chance.
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while got.len() < PAYLOAD && std::time::Instant::now() < deadline {
        s.pump().await;
        c.pump_once().await;
        while let Some(front) = c.conn.inbound_front(id) {
            let n = front.len();
            got.extend_from_slice(front);
            c.conn.consume_inbound(id, n);
        }
        s.conn.flush_pending(sch);
        while c.conn.pop_event().is_some() {}
    }
    assert_eq!(got.len(), PAYLOAD, "bytes buffered during rekey were stranded");
    assert_eq!(got, payload);
}

/// Bytes the peer sent before its CHANNEL_CLOSE must still reach the
/// application. The close used to free the channel slot — and with it the
/// already-received, not-yet-drained inbound queue — so the tail of every
/// stream could vanish when data and close landed in the same read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_does_not_discard_received_bytes() {
    const PAYLOAD: usize = 8 * 1024;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<driver::IncomingChannel>();
    tokio::spawn(async move {
        while let Some(ch) = rx.recv().await {
            tokio::spawn(async move {
                let mut s = ch.stream;
                let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
                let _ = s.write_all(&payload).await;
                // Drop immediately: the driver closes the channel right behind
                // the data, so both arrive in one read on the far side.
            });
        }
    });
    tokio::spawn(async move {
        let _ = driver::serve(server_io, server_cfg(), hooks(), tx).await;
    });

    let mut c = Client::connect(client_io, "proxy", "proxy").await;
    let id = c.open("h", 1).await;
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while got.len() < PAYLOAD && std::time::Instant::now() < deadline {
        // A quiet round is not a failure: under load the peer can take longer
        // than the pump's read timeout to produce the next packet.
        c.pump_once().await;
        while let Some(front) = c.conn.inbound_front(id) {
            let n = front.len();
            got.extend_from_slice(front);
            c.conn.consume_inbound(id, n);
        }
        while c.conn.pop_event().is_some() {}
    }
    assert_eq!(got.len(), PAYLOAD, "tail sent before CHANNEL_CLOSE was dropped");
    assert_eq!(got, (0..PAYLOAD).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
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
