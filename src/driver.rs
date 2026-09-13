//! Tokio adapter that drives a [`Connection`] over a byte stream and exposes
//! `direct-tcpip` channels as [`ChannelStream`]s. The protocol core stays
//! sans-IO; this is the only place `.await` happens.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio::time::{Instant, Sleep};

use crate::config::ServerConfig;
use crate::core::conn::{Connection, Event};
use crate::error::{Error, Result};
use crate::proto::SSH_DISCONNECT_BY_APPLICATION;
use crate::stream::{ChanShared, ChannelStream};

/// Verdict for an authentication attempt. `Reject{delay}` sleeps before the
/// failure is sent (timing-attack / brute-force jitter), without blocking the
/// session — other channels keep flowing while the timer runs.
pub enum AuthOutcome {
    Accept,
    Reject { delay: Duration },
}

/// Verdict for a `direct-tcpip` open.
pub enum OpenOutcome {
    Accept,
    Reject(u32, &'static str),
}

type AuthPwFn = dyn FnMut(&str, &str) -> AuthOutcome + Send;
type AuthPkProbeFn = dyn FnMut(&str, &str, &[u8]) -> bool + Send;
type AuthPkFn = dyn FnMut(&str, &str, &[u8]) -> AuthOutcome + Send;
type OnAuthFn = dyn FnMut(&str, Option<&str>) + Send;
type OpenFn = dyn FnMut(&str, &str, u16) -> OpenOutcome + Send;

/// Policy callbacks. All are synchronous; put the (bounded) waiting the caller
/// wants into `AuthOutcome::Reject{delay}` rather than blocking here.
pub struct Hooks {
    pub auth_password: Box<AuthPwFn>,
    pub auth_pubkey_probe: Box<AuthPkProbeFn>,
    pub auth_pubkey: Box<AuthPkFn>,
    pub on_authenticated: Box<OnAuthFn>,
    pub open: Box<OpenFn>,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            auth_password: Box::new(|_, _| AuthOutcome::Reject { delay: Duration::ZERO }),
            auth_pubkey_probe: Box::new(|_, _, _| false),
            auth_pubkey: Box::new(|_, _, _| AuthOutcome::Reject { delay: Duration::ZERO }),
            on_authenticated: Box::new(|_, _| {}),
            open: Box::new(|_, _, _| OpenOutcome::Accept),
        }
    }
}

/// A newly opened, already-confirmed `direct-tcpip` channel.
pub struct IncomingChannel {
    pub stream: ChannelStream,
    pub host: String,
    pub port: u16,
}

/// Cancel a running session from outside.
#[derive(Clone)]
pub struct SessionHandle {
    cancel: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl SessionHandle {
    /// A fresh handle, to pass to [`serve_with_handle`] and cancel externally.
    pub fn new() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn shutdown(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }
}

impl Default for SessionHandle {
    fn default() -> Self {
        Self::new()
    }
}

struct Deadline {
    at: Option<Instant>,
}
impl Deadline {
    fn new() -> Self {
        Self { at: None }
    }
    fn arm(&mut self, from: Instant, dur: Option<Duration>) {
        self.at = dur.map(|d| from + d);
    }
    fn disarm(&mut self) {
        self.at = None;
    }
}

/// Drive one accepted SSH server connection to completion.
///
/// Returns `Ok(())` on a clean close (peer disconnect, shutdown, idle timeout).
pub async fn serve<S>(
    io: S,
    cfg: Arc<ServerConfig>,
    hooks: Hooks,
    incoming: mpsc::UnboundedSender<IncomingChannel>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    serve_with_handle(io, cfg, hooks, incoming, SessionHandle::new()).await
}

/// Like [`serve`] but with a caller-provided [`SessionHandle`] for cancellation.
pub async fn serve_with_handle<S>(
    io: S,
    cfg: Arc<ServerConfig>,
    mut hooks: Hooks,
    incoming: mpsc::UnboundedSender<IncomingChannel>,
    handle: SessionHandle,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let base = cfg.base.clone();
    let mut conn = Connection::server(cfg);
    let driver_notify = handle.notify.clone();
    let mut chans: HashMap<u32, Arc<Mutex<ChanShared>>> = HashMap::new();
    let mut read_buf = vec![0u8; 32 * 1024];

    // Split so reads and writes interleave: a blocking full flush before every
    // read would deadlock against a peer doing the same on a full socket buffer.
    let (mut rd, mut wr) = tokio::io::split(io);
    // Sealed output waiting for the socket. Drained from `conn` each iteration;
    // its size, plus what `conn` still holds, is the write backpressure signal.
    let mut out = bytes::BytesMut::new();
    const OUT_CAP: usize = 256 * 1024;

    // Pending rejected-auth timer: (fire time). When it elapses we send FAILURE.
    let mut auth_reject_at: Option<Instant> = None;

    let mut kex_dl = Deadline::new();
    let mut auth_dl = Deadline::new();
    let mut idle_dl = Deadline::new();
    let mut keepalive_dl = Deadline::new();
    let now = Instant::now();
    kex_dl.arm(now, Some(base.kex_timeout));
    auth_dl.arm(now, base.auth_timeout);

    let timer: Sleep = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(timer);

    loop {
        // 1. Handle protocol events (auth hooks, channel opens, closes).
        while let Some(ev) = conn.pop_event() {
            match ev {
                Event::KexDone => kex_dl.disarm(),
                Event::AuthPassword { user, password } => {
                    match (hooks.auth_password)(&user, &password) {
                        AuthOutcome::Accept => conn.resolve_auth(true)?,
                        AuthOutcome::Reject { delay } => {
                            schedule_reject(&mut conn, &mut auth_reject_at, delay)?
                        }
                    }
                }
                Event::AuthPublicKeyProbe { user, algo, key_blob } => {
                    let ok = (hooks.auth_pubkey_probe)(&user, &algo, &key_blob);
                    conn.resolve_auth(ok)?;
                }
                Event::AuthPublicKey { user, algo, key_blob } => {
                    match (hooks.auth_pubkey)(&user, &algo, &key_blob) {
                        AuthOutcome::Accept => conn.resolve_auth(true)?,
                        AuthOutcome::Reject { delay } => {
                            schedule_reject(&mut conn, &mut auth_reject_at, delay)?
                        }
                    }
                }
                Event::Authenticated { user } => {
                    auth_dl.disarm();
                    (hooks.on_authenticated)(&user, conn.peer_ident());
                    // Idle timer starts now (no channels yet).
                    idle_dl.arm(Instant::now(), base.idle_timeout);
                    keepalive_dl.arm(Instant::now(), base.keepalive_interval);
                }
                Event::OpenDirectTcpIp { local_id, host, port } => {
                    let user = conn.user().unwrap_or("").to_string();
                    match (hooks.open)(&user, &host, port) {
                        OpenOutcome::Accept => {
                            let shared = Arc::new(Mutex::new(ChanShared::new(
                                base.channel_tx_cap,
                                driver_notify.clone(),
                            )));
                            chans.insert(local_id, shared.clone());
                            conn.accept_channel(local_id)?;
                            idle_dl.disarm();
                            let _ = incoming.send(IncomingChannel {
                                stream: ChannelStream::new(shared),
                                host,
                                port,
                            });
                        }
                        OpenOutcome::Reject(reason, msg) => {
                            conn.reject_channel(local_id, reason, msg)?;
                        }
                    }
                }
                Event::OpenSession { local_id } => {
                    // Accepted so `ssh -D`/`-N` clients can open it; all its
                    // requests are refused by the core. No stream is exposed.
                    conn.accept_channel(local_id)?;
                }
                Event::ChannelEof { local_id } => {
                    if let Some(sh) = chans.get(&local_id) {
                        let mut s = sh.lock();
                        s.to_app_eof = true;
                        s.wake_reader();
                    }
                }
                Event::ChannelClose { local_id } => {
                    if let Some(sh) = chans.get(&local_id) {
                        let mut s = sh.lock();
                        s.to_app_eof = true;
                        s.closed = true;
                        s.wake_reader();
                        s.wake_writer();
                    }
                }
                Event::Disconnect { .. } => {}
                _ => {}
            }
        }

        // 2. Shuttle bytes between channel streams and the connection.
        pump_channels(&mut conn, &mut chans);

        // 3. Rearm idle timer when the last channel goes away.
        if conn.authed() && conn.active_channels() == 0 && idle_dl.at.is_none() {
            idle_dl.arm(Instant::now(), base.idle_timeout);
        }

        // 4. Move sealed output out of `conn` into the local buffer (bounded so
        //    `conn`'s own backlog keeps signalling backpressure).
        while out.len() < OUT_CAP {
            let Some(chunk) = conn.peek_out() else { break };
            let take = chunk.len().min(OUT_CAP - out.len());
            out.extend_from_slice(&chunk[..take]);
            conn.consume_out(take);
        }

        if conn.is_finished() && out.is_empty() {
            return Ok(());
        }
        if handle.cancel.load(Ordering::SeqCst) {
            conn.disconnect(SSH_DISCONNECT_BY_APPLICATION, "server shutting down");
            drain_out(&mut wr, &mut conn, &mut out, base.linger).await;
            return Ok(());
        }

        // 5. Compute the next deadline and wait for progress. Reads, writes and
        //    timers race so neither direction can wedge the other.
        let next = [kex_dl.at, auth_dl.at, idle_dl.at, keepalive_dl.at, auth_reject_at]
            .into_iter()
            .flatten()
            .min();
        match next {
            Some(at) => timer.as_mut().reset(at),
            None => timer.as_mut().reset(Instant::now() + Duration::from_secs(3600)),
        }

        // Stop reading while our unwritten output is already large.
        let read_allowed = out.len() + conn.queued_out_bytes() < base.out_hard;
        let want_write = !out.is_empty();

        tokio::select! {
            _ = handle.notify.notified() => {}
            n = wr.write(&out), if want_write => match n {
                Ok(0) => return finish(conn, Error::Closed),
                Ok(n) => { out.advance(n); }
                Err(e) => return finish(conn, e.into()),
            },
            _ = &mut timer => {
                let now = Instant::now();
                if fired(&mut kex_dl, now) {
                    return finish(conn, Error::TimedOut("kex"));
                }
                if fired(&mut auth_dl, now) {
                    conn.disconnect(SSH_DISCONNECT_BY_APPLICATION, "authentication timeout");
                    drain_out(&mut wr, &mut conn, &mut out, base.linger).await;
                    return Ok(());
                }
                if fired(&mut idle_dl, now) {
                    conn.disconnect(SSH_DISCONNECT_BY_APPLICATION, "idle timeout");
                    drain_out(&mut wr, &mut conn, &mut out, base.linger).await;
                    return Ok(());
                }
                if let Some(at) = auth_reject_at {
                    if now >= at {
                        auth_reject_at = None;
                        conn.resolve_auth(false)?;
                    }
                }
                if fired(&mut keepalive_dl, now) {
                    match conn.send_keepalive() {
                        Ok(true) => keepalive_dl.arm(now, base.keepalive_interval),
                        Ok(false) => return finish(conn, Error::TimedOut("keepalive")),
                        Err(e) => return finish(conn, e),
                    }
                }
            }
            r = rd.read(&mut read_buf), if read_allowed => match r {
                Ok(0) => return finish(conn, Error::Closed),
                Ok(n) => {
                    conn.read_buf_mut().extend_from_slice(&read_buf[..n]);
                    if let Err(e) = conn.process_in() {
                        if !e.is_benign() {
                            return finish(conn, e);
                        }
                    }
                    if conn.authed() {
                        keepalive_dl.arm(Instant::now(), base.keepalive_interval);
                    }
                }
                Err(e) => return finish(conn, e.into()),
            },
        }
    }
}

fn fired(dl: &mut Deadline, now: Instant) -> bool {
    match dl.at {
        Some(at) if now >= at => {
            dl.disarm();
            true
        }
        _ => false,
    }
}

fn schedule_reject(
    conn: &mut Connection,
    slot: &mut Option<Instant>,
    delay: Duration,
) -> Result<()> {
    if delay.is_zero() {
        conn.resolve_auth(false)
    } else {
        *slot = Some(Instant::now() + delay);
        Ok(())
    }
}

fn finish(conn: Connection, e: Error) -> Result<()> {
    if e.is_benign() || conn.is_closed() {
        Ok(())
    } else {
        Err(e)
    }
}

/// Best-effort flush of leftover + queued output within `linger` (used on close).
async fn drain_out<W: AsyncWrite + Unpin>(
    wr: &mut W,
    conn: &mut Connection,
    out: &mut bytes::BytesMut,
    linger: Duration,
) {
    let deadline = Instant::now() + linger;
    while !conn.is_finished() || !out.is_empty() {
        while out.len() < 64 * 1024 {
            let Some(chunk) = conn.peek_out() else { break };
            out.extend_from_slice(&chunk);
            let n = chunk.len();
            conn.consume_out(n);
        }
        if out.is_empty() {
            break;
        }
        match tokio::time::timeout_at(deadline, wr.write(out)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                out.advance(n);
            }
        }
    }
    let _ = tokio::time::timeout_at(deadline, wr.flush()).await;
}

/// Move bytes both directions for every channel with pending work.
fn pump_channels(conn: &mut Connection, chans: &mut HashMap<u32, Arc<Mutex<ChanShared>>>) {
    let mut gone = Vec::new();
    // Visit only channels with protocol-side activity plus any with app-side
    // buffers to service. We iterate the map (bounded by max_channels).
    for (&id, shared) in chans.iter() {
        if !conn.channel_alive(id) {
            let mut s = shared.lock();
            s.closed = true;
            s.to_app_eof = true;
            s.wake_reader();
            s.wake_writer();
            gone.push(id);
            continue;
        }
        let mut s = shared.lock();

        // peer -> app (bounded by tx_cap so a slow reader backpressures window)
        loop {
            if s.to_app.len() >= s.tx_cap {
                break;
            }
            let Some(front) = conn.inbound_front(id) else { break };
            let room = s.tx_cap - s.to_app.len();
            let take = front.len().min(room);
            let chunk = front[..take].to_vec();
            s.to_app.extend_from_slice(&chunk);
            conn.consume_inbound(id, take);
            s.wake_reader();
        }
        if conn.channel_got_eof(id) && conn.inbound_front(id).is_none() {
            s.to_app_eof = true;
            s.wake_reader();
        }

        // app -> peer
        while !s.from_app.is_empty() {
            let cap = conn.send_capacity(id);
            if cap == 0 {
                break;
            }
            let take = s.from_app.len().min(cap);
            let n = match conn.send_data(id, &s.from_app[..take]) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            s.from_app.advance(n);
            s.wake_writer();
        }

        // Half-close / close propagation.
        if s.from_app.is_empty() && s.from_app_fin {
            let _ = conn.send_eof(id);
        }
        if s.dropped {
            let _ = conn.send_close(id);
        }
    }
    for id in gone {
        chans.remove(&id);
    }
}
