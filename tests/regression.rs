//! Regression tests for the resource and ordering invariants of the driver
//! and stream layer (the P0 list from the 2026-09-13 review): bounded output
//! memory under short writes, no data lost before EOF, every termination
//! path wakes the streams, one FIFO per channel across a rekey, explicit
//! window admission, buffered transports, slow-channel isolation, and the
//! rekey timers.

mod common;
use common::*;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ssproxy::config::{ClientConfig, ServerConfig};
use ssproxy::core::{Connection, Event};
use ssproxy::driver::{self, IncomingChannel, SessionHandle};
use ssproxy::hostkey::HostKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot};

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// A transport that takes a little less than the core appends must not let
/// the output buffer's consumed prefix grow without bound: pending bytes were
/// always bounded, the *retained* allocation was not.
#[test]
fn out_retained_capacity_bounded_under_short_writes() {
    let mut c = Connection::client(Arc::new(ClientConfig::new("proxy", "proxy")));
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    let out_soft = sc.base.out_soft;
    let mut s = Connection::server(Arc::new(sc));
    core_handshake(&mut c, &mut s, false);
    let cch = c.open_direct_tcpip("h", 1).unwrap();
    let sch = core_handshake(&mut c, &mut s, true).unwrap();

    const TOTAL: usize = 8 * 1024 * 1024;
    let payload = pattern(TOTAL);
    let mut sent = 0;
    let mut got = Vec::with_capacity(TOTAL);
    // Live data never exceeds the soft limit plus one frame (the core stops
    // sealing channel data at the soft limit); the allocation may be up to
    // twice that (growth by doubling). Anything beyond is a leak.
    let bound = 2 * (out_soft + 64 * 1024);
    let mut peak = 0;
    let mut steps = 0;
    while got.len() < TOTAL {
        steps += 1;
        assert!(steps < 200_000, "stalled: sent={sent} got={}", got.len());
        while sent < TOTAL {
            let cap = s.send_capacity(sch);
            if cap == 0 {
                break;
            }
            let n = cap.min(32 * 1024).min(TOTAL - sent);
            let k = s.send_data(sch, &payload[sent..sent + n]).unwrap();
            if k == 0 {
                break;
            }
            sent += k;
        }
        peak = peak.max(s.out_capacity());
        assert!(
            s.out_capacity() <= bound,
            "output buffer grew to {} (> {bound}) after {} bytes",
            s.out_capacity(),
            sent
        );
        // Short writes: the transport takes at most 7 KiB per step.
        xfer_max(&mut s, &mut c, 7 * 1024);
        xfer(&mut c, &mut s);
        c.process_in().unwrap();
        s.process_in().unwrap();
        while c.pop_event().is_some() {}
        while s.pop_event().is_some() {}
        while let Some(front) = c.inbound_front(cch) {
            let n = front.len();
            got.extend_from_slice(front);
            c.consume_inbound(cch, n);
        }
    }
    assert_eq!(got, payload);
    assert!(peak > 0);
}

/// Bytes queued for a channel must all reach a slow reader before it sees
/// EOF, even when they exceed the app-side queue and CLOSE arrives while most
/// of them are still in the core.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_channel_stream_close_preserves_large_tail() {
    // Default app queue (the driver refills ahead of the reader), and a
    // one-chunk queue where the reader empties it between every refill —
    // the case where "closed" must not be mistaken for "drained".
    for rx_cap in [256 * 1024usize, 1] {
        large_tail_with_rx_cap(rx_cap).await;
    }
}

async fn large_tail_with_rx_cap(rx_cap: usize) {
    const TOTAL: usize = 1024 * 1024; // 4x the app queue, half the window
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    sc.base.channel_rx_cap = rx_cap;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<IncomingChannel>();
    let (done_tx, done_rx) = oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let ch = rx.recv().await.unwrap();
        let mut s = ch.stream;
        // Slow reader: let the whole payload and the CLOSE land first.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut all = Vec::new();
        s.read_to_end(&mut all).await.unwrap();
        let _ = done_tx.send(all);
    });
    tokio::spawn(async move {
        let _ = driver::serve(server_io, Arc::new(sc), hooks(), tx).await;
    });

    let mut c = Client::connect(client_io, "proxy", "proxy").await;
    let id = c.open("h", 1).await;
    let payload = pattern(TOTAL);
    let mut sent = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while sent < TOTAL {
        assert!(Instant::now() < deadline, "send stalled at {sent}");
        sent += c.conn.send_data(id, &payload[sent..]).unwrap();
        c.pump_once().await;
        while c.conn.pop_event().is_some() {}
    }
    c.conn.send_close(id).unwrap();
    let mut done_rx = done_rx;
    let got = loop {
        c.pump_once().await;
        while c.conn.pop_event().is_some() {}
        match done_rx.try_recv() {
            Ok(v) => break v,
            Err(oneshot::error::TryRecvError::Empty) => {
                assert!(Instant::now() < deadline, "reader never finished");
            }
            Err(e) => panic!("reader task died: {e}"),
        }
    };
    assert_eq!(got.len(), TOTAL, "tail lost before EOF (rx_cap={rx_cap})");
    assert_eq!(got, payload);
}

/// An empty channel that the peer CLOSEs must wake a pending reader with EOF
/// and drop the driver's map entry. Previously the driver skipped a core slot
/// that was already freed, so the shared state leaked until the session ended
/// and the reader waited forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_close_on_idle_channel_yields_eof() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<IncomingChannel>();
    let handle = SessionHandle::new();
    let (done_tx, done_rx) = oneshot::channel::<io::Result<Vec<u8>>>();
    tokio::spawn(async move {
        let ch = rx.recv().await.unwrap();
        let mut s = ch.stream;
        let mut all = Vec::new();
        let _ = done_tx.send(s.read_to_end(&mut all).await.map(|_| all));
    });
    let server_handle = handle.clone();
    tokio::spawn(async move {
        let _ = driver::serve_with_handle(server_io, server_cfg(), hooks(), tx, server_handle).await;
    });

    let mut c = Client::connect(client_io, "proxy", "proxy").await;
    let id = c.open("h", 1).await;
    c.conn.send_close(id).unwrap();
    let mut done_rx = done_rx;
    let deadline = Instant::now() + Duration::from_secs(3);
    let got = loop {
        c.pump_once().await;
        while c.conn.pop_event().is_some() {}
        match done_rx.try_recv() {
            Ok(v) => break v,
            Err(oneshot::error::TryRecvError::Empty) => {
                assert!(Instant::now() < deadline, "reader still pending after peer CLOSE");
            }
            Err(e) => panic!("reader task died: {e}"),
        }
    };
    let body = got.expect("reader error after idle CLOSE");
    assert!(body.is_empty(), "idle channel CLOSE must yield empty EOF, got {} bytes", body.len());
    let t0 = Instant::now();
    while handle.channel_count() > 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "driver still tracks {} closed channel(s)",
            handle.channel_count()
        );
        c.pump_once().await;
        tokio::task::yield_now().await;
    }
}

/// Open/CLOSE many channels on one long-lived session. Each one must leave
/// the driver's map, otherwise a SOCKS-style embedder leaks per-channel
/// buffers for the life of the SSH connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_channels_do_not_accumulate_in_driver() {
    const N: usize = 64;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<IncomingChannel>();
    let handle = SessionHandle::new();
    tokio::spawn(async move {
        while let Some(ch) = rx.recv().await {
            drop(ch.stream);
        }
    });
    let server_handle = handle.clone();
    tokio::spawn(async move {
        let _ = driver::serve_with_handle(server_io, server_cfg(), hooks(), tx, server_handle).await;
    });

    let mut c = Client::connect(client_io, "proxy", "proxy").await;
    for i in 0..N {
        let id = c.conn.open_direct_tcpip("h", (i + 1) as u16).unwrap();
        // Server drops the stream at once, so CONFIRMATION and CLOSE can land
        // together; the channel may already be gone by the time we look.
        c.pump_until(|conn| {
            conn.send_capacity(id) > 0 || conn.channel_got_eof(id) || !conn.channel_alive(id)
        })
        .await;
        if c.conn.channel_alive(id) {
            c.conn.send_close(id).unwrap();
            c.pump_until(|conn| !conn.channel_alive(id)).await;
        }
    }
    let t0 = Instant::now();
    while handle.channel_count() > 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "driver leaked {} channel(s) after {N} close cycles",
            handle.channel_count()
        );
        c.pump_once().await;
        tokio::task::yield_now().await;
    }
    assert_eq!(c.conn.active_channels(), 0, "core table still holds closed channels");
}

/// Every way the driver can end — peer gone, future dropped — must wake a
/// pending reader and a blocked writer with an error, not leave them hanging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_eof_wakes_channel_readers_and_writers() {
    for abort_driver in [false, true] {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (tx, mut rx) = mpsc::unbounded_channel::<IncomingChannel>();
        let (rd_tx, rd_rx) = oneshot::channel::<io::Result<usize>>();
        let (wr_tx, wr_rx) = oneshot::channel::<io::Result<()>>();
        tokio::spawn(async move {
            let ch = rx.recv().await.unwrap();
            let (mut r, mut w) = tokio::io::split(ch.stream);
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = rd_tx.send(r.read(&mut b).await);
            });
            tokio::spawn(async move {
                // More than tx_cap + out_soft + the pipe: the writer must block.
                let big = vec![7u8; 4 * 1024 * 1024];
                let _ = wr_tx.send(w.write_all(&big).await);
            });
        });
        let server = tokio::spawn(async move {
            driver::serve(server_io, server_cfg(), hooks(), tx).await
        });

        let mut c = Client::connect(client_io, "proxy", "proxy").await;
        let _id = c.open("h", 1).await;
        // Let the writer fill every buffer; the client stops pumping so the
        // pipe backs up.
        tokio::time::sleep(Duration::from_millis(200)).await;

        if abort_driver {
            server.abort();
        } else {
            drop(c); // transport EOF from the peer
        }
        let rd = tokio::time::timeout(Duration::from_secs(2), rd_rx)
            .await
            .unwrap_or_else(|_| panic!("reader still pending (abort={abort_driver})"))
            .unwrap();
        let wr = tokio::time::timeout(Duration::from_secs(2), wr_rx)
            .await
            .unwrap_or_else(|_| panic!("writer still pending (abort={abort_driver})"))
            .unwrap();
        assert!(rd.is_err(), "reader got {rd:?}, expected an error (abort={abort_driver})");
        assert!(wr.is_err(), "writer got {wr:?}, expected an error (abort={abort_driver})");
    }
}

/// Data parked behind a key exchange must reach the wire before anything the
/// application hands over afterwards — one FIFO per channel, even when the
/// post-rekey flush stops early on the output soft limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rekey_pending_precedes_fresh_data() {
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    sc.base.out_soft = 4096; // the post-rekey flush drains one small packet, then stops
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let mut s = ServerCore::new(server_io, Arc::new(sc));
    // A small peer packet size makes the parked data span many frames.
    let mut cc = ClientConfig::new("proxy", "proxy");
    cc.base.max_packet = 4096;
    let mut c = Client {
        io: client_io,
        conn: Connection::client(Arc::new(cc)),
        buf: vec![0u8; 32 * 1024],
    };
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

    let a: Vec<u8> = vec![0xAA; 32 * 1024];
    let b: Vec<u8> = vec![0xBB; 32 * 1024];
    s.conn.trigger_rekey().unwrap();
    assert_eq!(s.conn.send_data(sch, &a).unwrap(), a.len(), "rekey must park, not drop");

    let mut sent_b = 0;
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while got.len() < a.len() + b.len() && Instant::now() < deadline {
        s.pump().await; // drains the output buffer: the soft limit is not what holds B back
        c.pump_once().await;
        if sent_b < b.len() {
            // Offered *before* the parked bytes are re-driven, with the output
            // buffer empty: only the per-channel FIFO can hold it back. Returns
            // 0 while parked data is still ahead — the invariant under test.
            sent_b += s.conn.send_data(sch, &b[sent_b..]).unwrap();
        }
        s.conn.flush_pending(sch);
        while let Some(front) = c.conn.inbound_front(id) {
            let n = front.len();
            got.extend_from_slice(front);
            c.conn.consume_inbound(id, n);
        }
        while c.conn.pop_event().is_some() {}
    }
    assert_eq!(got.len(), a.len() + b.len(), "bytes lost across rekey");
    assert!(got[..a.len()].iter().all(|&x| x == 0xAA), "fresh data overtook parked data");
    assert!(got[a.len()..].iter().all(|&x| x == 0xBB));
}

/// Window admission is a contract: full windows while the session budget
/// lasts, then the floor — and refusal only when the floor is 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn window_budget_admission_is_explicit() {
    for (floor, third_alive, third_window) in [(256 * 1024u32, true, 256 * 1024u32), (0, false, 0)] {
        let mut sc = ServerConfig::new(HostKey::generate());
        sc.methods.publickey = false;
        sc.base.window_initial = 2 * 1024 * 1024;
        sc.base.window_budget = 4 * 1024 * 1024;
        sc.base.window_floor = floor;
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut s = ServerCore::new(server_io, Arc::new(sc));
        let mut c = Client {
            io: client_io,
            conn: Connection::client(Arc::new(ClientConfig::new("proxy", "proxy"))),
            buf: vec![0u8; 32 * 1024],
        };
        for _ in 0..2000 {
            if c.conn.authed() {
                break;
            }
            s.pump().await;
            c.pump_once().await;
        }
        assert!(c.conn.authed());
        let ids: Vec<u32> = (0..3).map(|i| c.conn.open_direct_tcpip("h", i + 1).unwrap()).collect();
        let mut failed = Vec::new();
        for _ in 0..2000 {
            let settled = ids.iter().all(|&id| {
                c.conn.send_capacity(id) > 0 || !c.conn.channel_alive(id)
            });
            if settled && s.channels.len() + failed.len() >= 3 {
                break;
            }
            s.pump().await;
            c.pump_once().await;
            while let Some(ev) = c.conn.pop_event() {
                if let Event::OpenFailed { local_id, .. } = ev {
                    failed.push(local_id);
                }
            }
        }
        let windows: Vec<u32> = s.channels.iter().map(|&id| s.conn.dbg_channel(id).4).collect();
        assert_eq!(&windows[..2], &[2 * 1024 * 1024, 2 * 1024 * 1024], "floor={floor}");
        assert_eq!(c.conn.channel_alive(ids[2]), third_alive, "floor={floor}");
        if third_alive {
            assert_eq!(windows[2], third_window, "floor={floor}");
        } else {
            assert_eq!(failed, vec![ids[2]], "floor={floor}: third open must be refused");
        }
    }
}

/// An `AsyncWrite` that only hands bytes on when flushed. Without a flush at
/// batch boundaries nothing the driver writes ever reaches the peer.
struct Buffered<S> {
    inner: S,
    pending: Vec<u8>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Buffered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Buffered<S> {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        self.pending.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let me = &mut *self;
            match Pin::new(&mut me.inner).poll_write(cx, &me.pending) {
                Poll::Ready(Ok(n)) => {
                    me.pending.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffered_transport_flush_progress() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<IncomingChannel>();
    tokio::spawn(async move {
        while let Some(ch) = rx.recv().await {
            tokio::spawn(async move {
                let mut s = ch.stream;
                let mut buf = vec![0u8; 16 * 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let io = Buffered { inner: server_io, pending: Vec::new() };
    tokio::spawn(async move {
        let _ = driver::serve(io, server_cfg(), hooks(), tx).await;
    });
    let mut c = Client::connect(client_io, "proxy", "proxy").await;
    let id = c.open("h", 1).await;
    let payload = pattern(200 * 1024);
    let got = c.echo_roundtrip(id, &payload).await;
    assert_eq!(got, payload);
}

/// A channel whose reader never drains (its window fills, the echo backs up)
/// must not delay a healthy channel on the same session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_channel_does_not_block_other_channels() {
    let io = spawn_server(server_cfg());
    let mut c = Client::connect(io, "proxy", "proxy").await;
    let victim = c.open("h", 1).await;
    let healthy = c.open("h", 2).await;
    // Push a full window plus the app queue into the victim and never read
    // the echo back: the server's relay for it wedges on write.
    let blob = vec![1u8; 32 * 1024];
    let mut pushed = 0usize;
    for _ in 0..400 {
        let n = c.conn.send_data(victim, &blob).unwrap();
        pushed += n;
        c.pump_once().await;
        while c.conn.pop_event().is_some() {}
        if pushed >= 3 * 1024 * 1024 {
            break;
        }
    }
    assert!(pushed >= 2 * 1024 * 1024, "could not fill the victim ({pushed} bytes)");
    let t0 = Instant::now();
    let got = c.echo_roundtrip(healthy, b"still-alive").await;
    assert_eq!(got, b"still-alive");
    assert!(t0.elapsed() < Duration::from_secs(3), "healthy channel delayed {:?}", t0.elapsed());
}

/// Time-based rekey actually fires, and a rekey that stalls is cut off by the
/// kex deadline like the first exchange is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rekey_interval_and_each_kex_deadline_fire() {
    // (a) periodic rekey: several KexDone at the client within a second.
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    sc.base.rekey_interval = Some(Duration::from_millis(120));
    let io = spawn_server(Arc::new(sc));
    let mut c = Client::connect(io, "proxy", "proxy").await;
    while c.conn.pop_event().is_some() {}
    let mut kex_done = 0;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(900) {
        c.pump_once().await;
        while let Some(ev) = c.conn.pop_event() {
            if matches!(ev, Event::KexDone) {
                kex_done += 1;
            }
        }
    }
    assert!(kex_done >= 3, "only {kex_done} rekeys in 900ms with a 120ms interval");

    // (b) a stalled rekey hits the kex deadline: the client stops answering.
    let mut sc = ServerConfig::new(HostKey::generate());
    sc.methods.publickey = false;
    sc.base.rekey_interval = Some(Duration::from_millis(100));
    sc.base.kex_timeout = Duration::from_millis(400);
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, _rx) = mpsc::unbounded_channel::<IncomingChannel>();
    let server = tokio::spawn(async move { driver::serve(server_io, Arc::new(sc), hooks(), tx).await });
    let mut c = Client::connect(client_io, "proxy", "proxy").await;
    // Read and discard: the server's KEXINIT is never answered.
    let mut sink = vec![0u8; 4096];
    let t0 = Instant::now();
    let res = loop {
        if server.is_finished() {
            break server.await.unwrap();
        }
        assert!(t0.elapsed() < Duration::from_secs(3), "stalled rekey was not cut off");
        let _ = tokio::time::timeout(Duration::from_millis(50), c.io.read(&mut sink)).await;
    };
    let err = res.expect_err("driver must fail on a stalled rekey");
    assert!(err.to_string().contains("kex"), "unexpected error: {err}");
    assert!(t0.elapsed() < Duration::from_millis(1500), "deadline fired late: {:?}", t0.elapsed());
}

/// Several channels transmitting at once: the ones the output soft limit
/// stops mid-drain must be revisited when the socket drains, not when some
/// unrelated event happens to touch them. The client's window is huge so no
/// WINDOW_ADJUST can mask a channel that was simply forgotten.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backlog_blocked_channels_are_revisited() {
    const CHANNELS: usize = 8;
    const PER_CHANNEL: usize = 512 * 1024;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (tx, mut rx) = mpsc::unbounded_channel::<IncomingChannel>();
    tokio::spawn(async move {
        while let Some(ch) = rx.recv().await {
            tokio::spawn(async move {
                let mut s = ch.stream;
                let blob = vec![ch.port as u8; PER_CHANNEL];
                let _ = s.write_all(&blob).await;
                let _ = s.shutdown().await;
            });
        }
    });
    tokio::spawn(async move {
        let _ = driver::serve(server_io, server_cfg(), hooks(), tx).await;
    });
    let mut cc = ClientConfig::new("proxy", "proxy");
    cc.base.window_initial = 16 * 1024 * 1024;
    cc.base.window_max = 16 * 1024 * 1024;
    cc.base.window_budget = 256 * 1024 * 1024;
    let conn = Connection::client(Arc::new(cc));
    let mut c = Client { io: client_io, conn, buf: vec![0u8; 32 * 1024] };
    c.pump_until(|conn| conn.authed()).await;
    let mut ids = Vec::new();
    for i in 0..CHANNELS {
        ids.push(c.open("h", (i + 1) as u16).await);
    }
    let mut got = vec![0usize; CHANNELS];
    let t0 = Instant::now();
    while got.iter().any(|&n| n < PER_CHANNEL) {
        assert!(
            t0.elapsed() < Duration::from_secs(8),
            "transmit stalled: {got:?} of {PER_CHANNEL} each"
        );
        c.pump_once().await;
        while c.conn.pop_event().is_some() {}
        for (i, &id) in ids.iter().enumerate() {
            while let Some(front) = c.conn.inbound_front(id) {
                let n = front.len();
                assert!(front.iter().all(|&b| b == (i + 1) as u8), "channel {i} data mixed");
                c.conn.consume_inbound(id, n);
                got[i] += n;
            }
        }
    }
}

// Keep `DuplexStream` referenced so the import stays meaningful across edits.
#[allow(dead_code)]
fn _ty(_: DuplexStream) {}
