//! Local throughput bench for the ssproxy engine.
//!
//! Three instruments, all measuring the same thing (bytes/second through one
//! `direct-tcpip` channel) at increasing levels of realism:
//!
//! * `plain`  — raw loopback TCP + a relay task. No SSH at all: the harness's
//!   own ceiling on this machine.
//! * `core`   — sans-IO client core <-> server core, no sockets, no tasks. The
//!   protocol + crypto cost per byte.
//! * `driver` — real loopback TCP, the tokio driver, relay tasks on both ends.
//!   What production runs.
//!
//! Comparing them localises a throughput gap: `core` far above `driver` means
//! the adapter (task wakeups, locking, syscalls) is the limit, not the wire
//! format or the cipher.
//!
//! Usage: bench_engine <plain|core|driver> <up|down> <MiB> [relay_buf_bytes]
//!   cargo run --release --example bench_engine -- driver up 512 8192

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ssproxy::config::{ClientConfig, ServerConfig};
use ssproxy::core::{Connection, Event};
use ssproxy::driver::{self, AuthOutcome, Hooks, OpenOutcome};
use ssproxy::hostkey::HostKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const CHUNK: usize = 32 * 1024;

fn server_cfg() -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::new(HostKey::generate());
    cfg.methods.publickey = false;
    if let Some(n) = rekey_bytes() {
        cfg.base.rekey_bytes = n;
    }
    if let Ok(w) = std::env::var("BENCH_WINDOW") {
        if let Ok(w) = w.parse::<u32>() {
            if std::env::var_os("BENCH_MAX_ONLY").is_some() {
                cfg.base.window_max = w;
            } else {
                cfg.base.window_initial = w;
                cfg.base.window_max = w;
            }
        }
    }
    Arc::new(cfg)
}

/// Rekey after this many transport bytes (0 = library default).
static REKEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn shallow() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("BENCH_SHALLOW").is_some())
}

static PROGRESS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ITERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
use std::sync::atomic::Ordering;

fn rekey_bytes() -> Option<u64> {
    match REKEY.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

fn hooks() -> Hooks {
    Hooks {
        auth_password: Box::new(|u, p| {
            if u == "proxy" && p == "proxy" {
                AuthOutcome::Accept
            } else {
                AuthOutcome::Reject { delay: Duration::from_millis(1) }
            }
        }),
        open: Box::new(|_, _, _| OpenOutcome::Accept),
        ..Hooks::default()
    }
}

fn to_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn stall(id: u32, done: usize, total: usize, e: io::Error, conn: &Connection) -> ! {
    eprintln!("STALL client: {e}; {done}/{total} bytes, {id} {:?}", conn.dbg_channel(id));
    std::process::exit(3)
}

/// What the far end of the relay does.
#[derive(Clone, Copy)]
enum Sink {
    /// Read and discard: measures the client -> server direction.
    Drain,
    /// Write `n` bytes: measures the server -> client direction.
    Source(usize),
}

/// One relay leg: `Sink::Drain` reads `relay_buf` at a time, `Source` writes it.
async fn serve_sink<S>(mut s: S, sink: Sink, relay_buf: usize)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match sink {
        Sink::Drain => {
            let mut buf = vec![0u8; relay_buf];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        Sink::Source(total) => {
            let buf = vec![0x5Au8; relay_buf];
            let mut written = 0usize;
            while written < total {
                let want = relay_buf.min(total - written);
                match s.write(&buf[..want]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => written += n,
                }
            }
            let _ = s.flush().await;
        }
    }
}

// ── client: sans-IO core over a real socket ─────────────────────────────────

struct Client {
    io: TcpStream,
    conn: Connection,
    rbuf: Vec<u8>,
}

impl Client {
    async fn connect(io: TcpStream) -> io::Result<Self> {
        io.set_nodelay(true)?;
        let mut me = Self {
            io,
            conn: Connection::client(Arc::new(ClientConfig::new("proxy", "proxy"))),
            rbuf: vec![0u8; 256 * 1024],
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while !me.conn.authed() {
            if Instant::now() > deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake"));
            }
            me.round().await?;
        }
        Ok(me)
    }

    /// Flush everything the core has sealed, then take one read from the socket.
    async fn round(&mut self) -> io::Result<()> {
        let Self { io, conn, rbuf } = self;
        match tokio::time::timeout(Duration::from_secs(20), flush_core(io, conn)).await {
            Ok(r) => r?,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "flush blocked 20s")),
        }
        let n = match tokio::time::timeout(Duration::from_secs(10), io.read(rbuf)).await {
            Ok(r) => r?,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "socket quiet 10s")),
        };
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        }
        conn.read_buf_mut().extend_from_slice(&rbuf[..n]);
        conn.process_in().map_err(to_io)?;
        while conn.pop_event().is_some() {}
        match tokio::time::timeout(Duration::from_secs(20), flush_core(io, conn)).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "post-read flush blocked 20s")),
        }
    }

    async fn open(&mut self, host: &str, port: u16) -> u32 {
        let id = self.conn.open_direct_tcpip(host, port).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.conn.send_capacity(id) == 0 && self.conn.channel_alive(id) {
            assert!(Instant::now() < deadline, "channel open timed out");
            self.round().await.unwrap();
        }
        assert!(self.conn.channel_alive(id), "channel refused");
        id
    }

    fn drain_inbound(&mut self, id: u32) -> usize {
        let mut n = 0;
        while let Some(front) = self.conn.inbound_front(id) {
            let len = front.len();
            self.conn.consume_inbound(id, len);
            n += len;
        }
        n
    }

    /// Push `total` bytes into the channel as fast as the window allows.
    ///
    /// Fill, flush, and only park on a read when the *peer's window* is what
    /// stops us. Parking every time our own output buffer filled would make the
    /// instrument the bottleneck instead of the engine under test.
    async fn upload(&mut self, id: u32, total: usize) -> Duration {
        let payload = vec![0x5Au8; CHUNK];
        let mut sent = 0usize;
        let t0 = Instant::now();
        while sent < total {
            while sent < total {
                let cap = self.conn.send_capacity(id);
                if cap == 0 {
                    break;
                }
                let want = cap.min(CHUNK).min(total - sent);
                match self.conn.send_data(id, &payload[..want]) {
                    Ok(n) if n > 0 => sent += n,
                    _ => break,
                }
            }
            match tokio::time::timeout(Duration::from_secs(20), flush_core(&mut self.io, &mut self.conn)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => stall(id, sent, total, e, &self.conn),
                Err(_) => stall(
                    id,
                    sent,
                    total,
                    io::Error::new(io::ErrorKind::TimedOut, "flush blocked 20s"),
                    &self.conn,
                ),
            }
            // BENCH_SHALLOW=1 reproduces a client whose event loop parks on a
            // read as soon as its own output buffer fills — the shape that
            // matches the real-machine single-stream numbers.
            if self.conn.send_capacity(id) == 0 || shallow() {
                if let Err(e) = self.round().await {
                    stall(id, sent, total, e, &self.conn);
                }
            }
        }
        t0.elapsed()
    }

    /// Drain `total` bytes arriving from the channel.
    async fn download(&mut self, id: u32, total: usize) -> Duration {
        let mut got = 0usize;
        let mut iters = 0u64;
        let t0 = Instant::now();
        while got < total {
            iters += 1;
            PROGRESS.store(got as u64, Ordering::Relaxed);
            ITERS.store(iters, Ordering::Relaxed);
            if std::env::var_os("BENCH_TRACE").is_some() && iters % 64 == 0 {
                eprintln!("[dl {iters}] got={got} {:?}", self.conn.dbg_channel(id));
            }
            if let Err(e) = self.round().await {
                stall(id, got, total, e, &self.conn);
            }
            got += self.drain_inbound(id);
        }
        t0.elapsed()
    }

    async fn run(&mut self, id: u32, total: usize, up: bool) -> Duration {
        if up {
            self.upload(id, total).await
        } else {
            self.download(id, total).await
        }
    }
}

async fn flush_core(io: &mut TcpStream, conn: &mut Connection) -> io::Result<()> {
    loop {
        let n = {
            let Some(chunk) = conn.peek_out() else { break };
            let len = chunk.len();
            let n = io.write(chunk).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
            }
            if n < len {
                conn.consume_out(n);
                return Ok(());
            }
            n
        };
        conn.consume_out(n);
    }
    Ok(())
}

// ── servers ─────────────────────────────────────────────────────────────────

async fn run_driver_server(cfg: Arc<ServerConfig>, sink: Sink, relay_buf: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<driver::IncomingChannel>();
    tokio::spawn(async move {
        while let Some(ch) = rx.recv().await {
            tokio::spawn(serve_sink(ch.stream, sink, relay_buf));
        }
    });
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            stream.set_nodelay(true).unwrap();
            let cfg = cfg.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = driver::serve(stream, cfg, hooks(), tx).await;
            });
        }
    });
    addr
}

async fn run_plain_server(sink: Sink, relay_buf: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            stream.set_nodelay(true).unwrap();
            tokio::spawn(serve_sink(stream, sink, relay_buf));
        }
    });
    addr
}

async fn plain_client(addr: SocketAddr, total: usize, up: bool) -> Duration {
    let mut io = TcpStream::connect(addr).await.unwrap();
    io.set_nodelay(true).unwrap();
    let t0 = Instant::now();
    if up {
        let buf = vec![0x5Au8; CHUNK];
        let mut sent = 0usize;
        while sent < total {
            let n = io.write(&buf[..CHUNK.min(total - sent)]).await.unwrap();
            if n == 0 {
                break;
            }
            sent += n;
        }
    } else {
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0usize;
        while got < total {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
    }
    t0.elapsed()
}

// ── core-only instrument ────────────────────────────────────────────────────

fn xfer(src: &mut Connection, dst: &mut Connection) {
    loop {
        let n = {
            let Some(chunk) = src.peek_out() else { break };
            dst.read_buf_mut().extend_from_slice(chunk);
            chunk.len()
        };
        src.consume_out(n);
    }
}

/// Exchange until both sides are authenticated and (if `want_open`) the client's
/// channel is confirmed. Returns the server-side local channel id.
fn core_handshake(c: &mut Connection, s: &mut Connection, want_open: bool) -> Option<u32> {
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
    if c.authed() {
        sch
    } else {
        panic!("core handshake did not converge");
    }
}

fn core_bench(total: usize, up: bool) -> Duration {
    let mut c = Connection::client(Arc::new(ClientConfig::new("proxy", "proxy")));
    let mut s = Connection::server(server_cfg());
    core_handshake(&mut c, &mut s, false);
    let cch = c.open_direct_tcpip("h", 1).unwrap();
    let sch = core_handshake(&mut c, &mut s, true).expect("channel opened");

    let payload = vec![0x5Au8; CHUNK];
    let (push, pull) = if up { (true, false) } else { (false, true) };
    let mut sent = 0usize;
    let mut got = 0usize;
    let mut last = (0usize, 0usize, Instant::now());
    let t0 = Instant::now();
    while got < total {
        if (sent, got) != (last.0, last.1) {
            last = (sent, got, Instant::now());
        } else if last.2.elapsed() > Duration::from_secs(2) {
            eprintln!(
                "STALL core {}: sent={sent} got={got}/{total}\n  client {:?}\n  server {:?}",
                if up { "up" } else { "down" },
                c.dbg_channel(cch),
                s.dbg_channel(sch),
            );
            std::process::exit(3);
        }
        if push {
            while sent < total {
                let cap = c.send_capacity(cch);
                if cap == 0 {
                    break;
                }
                let want = cap.min(CHUNK).min(total - sent);
                match c.send_data(cch, &payload[..want]) {
                    Ok(n) if n > 0 => sent += n,
                    _ => break,
                }
            }
        } else {
            while sent < total {
                let cap = s.send_capacity(sch);
                if cap == 0 {
                    break;
                }
                let want = cap.min(CHUNK).min(total - sent);
                match s.send_data(sch, &payload[..want]) {
                    Ok(n) if n > 0 => sent += n,
                    _ => break,
                }
            }
        }
        xfer(&mut c, &mut s);
        xfer(&mut s, &mut c);
        s.process_in().unwrap();
        c.process_in().unwrap();
        while s.pop_event().is_some() {}
        while c.pop_event().is_some() {}
        if pull {
            while let Some(front) = c.inbound_front(cch) {
                let n = front.len();
                c.consume_inbound(cch, n);
                got += n;
            }
        } else {
            while let Some(front) = s.inbound_front(sch) {
                let n = front.len();
                s.consume_inbound(sch, n);
                got += n;
            }
        }
    }
    t0.elapsed()
}

// ── main ────────────────────────────────────────────────────────────────────

fn report(mode: &str, dir: &str, mib: usize, d: Duration, relay_buf: usize) {
    let bits = (mib as f64) * 8.0 * 1024.0 * 1024.0;
    let mbps = bits / d.as_secs_f64() / 1e6;
    let mib_s = (mib as f64) / d.as_secs_f64();
    println!(
        "{mode:6} {dir:4} {mib:5} MiB in {:>7.3}s = {:>8.0} Mbit/s ({:>7.1} MiB/s) relay_buf={relay_buf}",
        d.as_secs_f64(),
        mbps,
        mib_s,
    );
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "driver".into());
    let dir = args.next().unwrap_or_else(|| "up".into());
    let mib: usize = args.next().unwrap_or_else(|| "256".into()).parse().unwrap();
    let relay_buf: usize = args.next().unwrap_or_else(|| "8192".into()).parse().unwrap();
    let rekey: u64 = args.next().unwrap_or_else(|| "0".into()).parse().unwrap();
    REKEY.store(rekey, std::sync::atomic::Ordering::Relaxed);
    let total = mib * 1024 * 1024;
    let up = dir == "up";
    let sink = if up { Sink::Drain } else { Sink::Source(total) };

    match mode.as_str() {
        "core" => {
            let d = core_bench(total, up);
            report("core", &dir, mib, d, relay_buf);
        }
        "plain" => {
            let addr = run_plain_server(sink, relay_buf).await;
            let d = plain_client(addr, total, up).await;
            report("plain", &dir, mib, d, relay_buf);
        }
        "driver" => {
            if std::env::var_os("BENCH_HEARTBEAT").is_some() {
                tokio::spawn(async {
                    let t0 = Instant::now();
                    loop {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        eprintln!(
                            "[hb {:>6.1}s] got={} iters={}",
                            t0.elapsed().as_secs_f64(),
                            PROGRESS.load(Ordering::Relaxed),
                            ITERS.load(Ordering::Relaxed),
                        );
                    }
                });
            }
            let addr = run_driver_server(server_cfg(), sink, relay_buf).await;
            let task = tokio::spawn(async move {
                let mut c = Client::connect(TcpStream::connect(addr).await.unwrap())
                    .await
                    .unwrap();
                let id = c.open("target", 1).await;
                c.run(id, total, up).await
            });
            match tokio::time::timeout(Duration::from_secs(90), task).await {
                Ok(Ok(d)) => report("driver", &dir, mib, d, relay_buf),
                Ok(Err(e)) => eprintln!("client task failed: {e}"),
                Err(_) => eprintln!(
                    "WATCHDOG: client stalled after 90s (got={} bytes)",
                    PROGRESS.load(Ordering::Relaxed)
                ),
            }
        }
        other => eprintln!("unknown mode {other} (plain|core|driver)"),
    }
}
