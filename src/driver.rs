//! Tokio adapter that drives a [`Connection`] over a byte stream and exposes
//! `direct-tcpip` channels as [`ChannelStream`]s. The protocol core stays
//! sans-IO; this is the only place `.await` happens.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio::time::{Instant, Sleep};

use crate::config::ServerConfig;
use crate::core::conn::{Connection, Event};
use crate::error::{Error, Result};
use crate::proto::SSH_DISCONNECT_BY_APPLICATION;
use crate::stream::{ChanShared, ChannelStream, ReadyList};

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

/// `SSPROXY_DEBUG_TICK=1` makes every session wake once a second and dump its
/// per-channel state (queues, windows, close flags). Wedges that used to be
/// invisible — a channel stuck with data queued and no reason to run — show up
/// here directly. Read once per process; the hot loop only sees a load.
fn debug_tick() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("SSPROXY_DEBUG_TICK").is_some())
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
    /// Live `direct-tcpip` streams still tracked by the driver (including
    /// ones whose core slot is already gone). Embedders can watch this to
    /// detect a session-lifetime leak of closed channels.
    live: Arc<AtomicUsize>,
}

impl SessionHandle {
    /// A fresh handle, to pass to [`serve_with_handle`] and cancel externally.
    pub fn new() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            live: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn shutdown(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Number of channel streams the driver still holds. Drops to zero once
    /// every `direct-tcpip` channel has been fully closed (or the session ends).
    pub fn channel_count(&self) -> usize {
        self.live.load(Ordering::Relaxed)
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

/// Spare capacity kept available in the read buffer; one `read` fills up to
/// the whole spare, so this is also the read batch size.
const READ_CHUNK: usize = 32 * 1024;

/// Application state of every live channel, keyed by the core's local id.
/// Dropping it — however the driver exits: clean close, error, timeout,
/// cancellation, or the future being dropped mid-await — terminates every
/// stream so no reader or writer is left pending forever.
struct Chans {
    map: HashMap<u32, Arc<Mutex<ChanShared>>>,
    clean: bool,
    /// Channels that still had application data when the output soft limit
    /// stopped them. Nothing on the channel itself changes when the socket
    /// drains, so they are revisited from here once there is room again;
    /// without this a channel parked by the backlog waits for an unrelated
    /// event (a WINDOW_ADJUST, more writes) to be looked at.
    out_blocked: Vec<u32>,
    live: Arc<AtomicUsize>,
}

impl Chans {
    fn new(live: Arc<AtomicUsize>) -> Self {
        Self {
            map: HashMap::new(),
            clean: false,
            out_blocked: Vec::new(),
            live,
        }
    }

    fn insert(&mut self, id: u32, shared: Arc<Mutex<ChanShared>>) {
        if self.map.insert(id, shared).is_none() {
            self.live.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn remove(&mut self, id: u32) {
        if self.map.remove(&id).is_some() {
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for Chans {
    fn drop(&mut self) {
        for sh in self.map.values() {
            sh.lock().terminate(self.clean);
        }
        self.live.store(0, Ordering::Relaxed);
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
    let ready = Arc::new(ReadyList::new(handle.notify.clone()));
    let mut chans = Chans::new(handle.live.clone());
    // Transport bytes land here directly; the core consumes whole frames from
    // the front. Grown lazily: an idle session holds no read buffer.
    let mut inbuf = BytesMut::new();

    // Split so reads and writes interleave: a blocking full flush before every
    // read would deadlock against a peer doing the same on a full socket buffer.
    let (mut rd, mut wr) = tokio::io::split(io);
    // A write happened since the last flush. Flushed only when there is
    // nothing left to write, so a buffering transport sees the batch, not
    // every packet.
    let mut need_flush = false;

    // Pending rejected-auth timer: (fire time). When it elapses we send FAILURE.
    let mut auth_reject_at: Option<Instant> = None;

    let mut kex_dl = Deadline::new();
    let mut auth_dl = Deadline::new();
    let mut idle_dl = Deadline::new();
    let mut keepalive_dl = Deadline::new();
    let mut rekey_dl = Deadline::new();
    let now = Instant::now();
    kex_dl.arm(now, Some(base.kex_timeout));
    auth_dl.arm(now, base.auth_timeout);

    let timer: Sleep = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(timer);

    loop {
        // 1. Handle protocol events (auth hooks, channel opens, closes).
        while let Some(ev) = conn.pop_event() {
            match ev {
                // Every exchange — first and each rekey — runs under the kex
                // deadline; a stalled rekey is as dead as a stalled handshake.
                Event::KexStarted => kex_dl.arm(Instant::now(), Some(base.kex_timeout)),
                Event::KexDone => {
                    kex_dl.disarm();
                    rekey_dl.arm(Instant::now(), base.rekey_interval);
                }
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
                                local_id,
                                base.channel_tx_cap,
                                base.channel_rx_cap,
                                ready.clone(),
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
                Event::ChannelEof { local_id: _ } => {
                    // Surfaced by `pump_one`, which raises EOF only after the
                    // bytes received before it have been handed over.
                }
                Event::ChannelClose { local_id } => {
                    if let Some(sh) = chans.map.get(&local_id).cloned() {
                        {
                            let mut s = sh.lock();
                            s.closed = true; // peer accepts no more; reads still drain
                            s.wake_writer();
                        }
                        // The core may already have freed the slot (both CLOSEs
                        // done, queues empty). Pump anyway: that is what drops
                        // the driver map entry and wakes a pending reader.
                        pump_one(&mut conn, &mut chans, local_id);
                    } else {
                        // A `session` channel has no stream here (every request on it
                        // is refused), so nothing will ever read what it buffered —
                        // drop it now rather than hold the slot and its window.
                        conn.discard_inbound(local_id);
                    }
                }
                Event::Disconnect { .. } => {}
                _ => {}
            }
        }

        // 2. Shuttle bytes for every channel with work: those the core marked
        //    (data, window, eof, close arrived), those the application
        //    signalled (wrote, consumed, shut down, dropped), and those the
        //    output backlog stopped last time, now that it has drained.
        //    Idle channels cost nothing here.
        if !chans.out_blocked.is_empty() && conn.queued_out_bytes() < base.out_soft {
            for id in std::mem::take(&mut chans.out_blocked) {
                if let Some(sh) = chans.map.get(&id) {
                    sh.lock().out_blocked = false;
                }
                pump_one(&mut conn, &mut chans, id);
            }
        }
        for id in ready.take() {
            pump_one(&mut conn, &mut chans, id);
        }
        while let Some(id) = conn.next_dirty() {
            pump_one(&mut conn, &mut chans, id);
        }

        // 3. Rearm idle timer when the last channel goes away.
        if conn.authed() && conn.active_channels() == 0 && idle_dl.at.is_none() {
            idle_dl.arm(Instant::now(), base.idle_timeout);
        }

        if conn.is_finished() {
            chans.clean = true;
            return Ok(());
        }
        if handle.cancel.load(Ordering::SeqCst) {
            conn.disconnect(SSH_DISCONNECT_BY_APPLICATION, "server shutting down");
            drain_out(&mut wr, &mut conn, base.linger).await;
            chans.clean = true;
            return Ok(());
        }

        // 4. Compute the next deadline and wait for progress. Reads, writes and
        //    timers race so neither direction can wedge the other.
        let next = [kex_dl.at, auth_dl.at, idle_dl.at, keepalive_dl.at, rekey_dl.at, auth_reject_at]
            .into_iter()
            .flatten()
            .min();
        let next = if debug_tick() {
            let tick = Instant::now() + Duration::from_secs(1);
            Some(next.map_or(tick, |n| n.min(tick)))
        } else {
            next
        };
        match next {
            Some(at) => timer.as_mut().reset(at),
            None => timer.as_mut().reset(Instant::now() + Duration::from_secs(3600)),
        }
        if debug_tick() {
            let mut line = String::new();
            for (&id, sh) in chans.map.iter() {
                let s = sh.lock();
                let (kex_block, needs_kex, send_wnd, pending, recv_wnd, unacked) = conn.dbg_channel(id);
                line.push_str(&format!(
                    "  ch{id} app: to_app={} starved={} from_app={} eof={} fin={} drop={} closed={} \
                     | kex={kex_block} needs={needs_kex} send_wnd={send_wnd} pending={pending} \
                     recv_wnd={recv_wnd} unacked={unacked}\n",
                    s.to_app_bytes,
                    s.starved,
                    s.from_app.len(),
                    s.to_app_eof,
                    s.from_app_fin,
                    s.dropped,
                    s.closed,
                ));
            }
            eprintln!("[drv] out={} inbuf={}\n{}", conn.queued_out_bytes(), inbuf.len(), line);
        }

        // Stop reading while our unwritten output is already large.
        let read_allowed = !conn.write_saturated();
        let want_write = conn.wants_write();
        let want_flush = !want_write && need_flush;
        if read_allowed {
            if inbuf.capacity() - inbuf.len() < READ_CHUNK {
                inbuf.reserve(READ_CHUNK);
            }
        } else if inbuf.is_empty() {
            inbuf = BytesMut::new();
        }
        // An idle session (no channels, nothing in flight) keeps no buffers.
        if !want_write && conn.active_channels() == 0 {
            conn.shrink_idle();
        }

        tokio::select! {
            _ = handle.notify.notified() => {}
            r = write_or_flush(&mut wr, conn.out_pending(), want_write), if want_write || want_flush => match r {
                Ok(Io::Wrote(0)) => return finish(conn, &mut chans, Error::Closed),
                Ok(Io::Wrote(n)) => {
                    conn.consume_out(n);
                    need_flush = true;
                }
                Ok(Io::Flushed) => need_flush = false,
                Err(e) => return finish(conn, &mut chans, e.into()),
            },
            _ = &mut timer => {
                let now = Instant::now();
                if fired(&mut kex_dl, now) {
                    return finish(conn, &mut chans, Error::TimedOut("kex"));
                }
                if fired(&mut auth_dl, now) {
                    conn.disconnect(SSH_DISCONNECT_BY_APPLICATION, "authentication timeout");
                    drain_out(&mut wr, &mut conn, base.linger).await;
                    chans.clean = true;
                    return Ok(());
                }
                if fired(&mut idle_dl, now) {
                    conn.disconnect(SSH_DISCONNECT_BY_APPLICATION, "idle timeout");
                    drain_out(&mut wr, &mut conn, base.linger).await;
                    chans.clean = true;
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
                        Ok(false) => return finish(conn, &mut chans, Error::TimedOut("keepalive")),
                        Err(e) => return finish(conn, &mut chans, e),
                    }
                }
                if fired(&mut rekey_dl, now) {
                    // Time-based rekey. Re-armed on the KexDone it produces;
                    // armed again here too in case the exchange could not
                    // start right now (one already running).
                    if let Err(e) = conn.trigger_rekey() {
                        return finish(conn, &mut chans, e);
                    }
                    rekey_dl.arm(now, base.rekey_interval);
                }
            }
            r = rd.read_buf(&mut inbuf), if read_allowed => match r {
                Ok(0) => return finish(conn, &mut chans, Error::Closed),
                Ok(_) => {
                    if let Err(e) = conn.process_from(&mut inbuf) {
                        if !e.is_benign() {
                            return finish(conn, &mut chans, e);
                        }
                    }
                    if conn.authed() {
                        keepalive_dl.arm(Instant::now(), base.keepalive_interval);
                    }
                }
                Err(e) => return finish(conn, &mut chans, e.into()),
            },
        }
    }
}

enum Io {
    Wrote(usize),
    Flushed,
}

/// One branch for the write half: write what is pending, or — when nothing
/// is — flush, so a buffering transport gets pushed before we wait.
async fn write_or_flush<W: AsyncWrite + Unpin>(
    wr: &mut W,
    pending: &[u8],
    want_write: bool,
) -> std::io::Result<Io> {
    if want_write {
        wr.write(pending).await.map(Io::Wrote)
    } else {
        wr.flush().await.map(|_| Io::Flushed)
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

fn finish(conn: Connection, chans: &mut Chans, e: Error) -> Result<()> {
    if e.is_benign() || conn.is_closed() {
        // The peer said goodbye (or we did): every queued byte is real, the
        // streams end with EOF once drained.
        chans.clean = conn.is_closed();
        Ok(())
    } else {
        Err(e)
    }
}

/// Best-effort flush of leftover + queued output within `linger` (used on close).
async fn drain_out<W: AsyncWrite + Unpin>(wr: &mut W, conn: &mut Connection, linger: Duration) {
    let deadline = Instant::now() + linger;
    while conn.wants_write() {
        let r = tokio::time::timeout_at(deadline, wr.write(conn.out_pending())).await;
        match r {
            Ok(Ok(n)) if n > 0 => conn.consume_out(n),
            _ => break,
        }
    }
    let _ = tokio::time::timeout_at(deadline, wr.flush()).await;
}

/// Move bytes both directions for one channel.
///
/// The channel lock is held only to swap owned data and flags in and out;
/// framing and encryption (`send_data`) run outside it, so a relay writer is
/// never parked behind the cipher.
fn pump_one(conn: &mut Connection, chans: &mut Chans, id: u32) {
    let Some(shared) = chans.map.get(&id).cloned() else {
        // No stream for this channel (a `session` channel, or one the
        // application never got): nothing will read what the peer sends.
        if conn.channel_alive(id) && conn.has_inbound(id) {
            conn.discard_inbound(id);
        }
        return;
    };
    if !conn.channel_alive(id) {
        shared.lock().terminate(true);
        chans.remove(id);
        return;
    }

    // ── in the lock: swap ───────────────────────────────────────────────────
    let (credited, mut data, fin, dropped) = {
        let mut s = shared.lock();
        s.queued = false;
        // peer -> app: move chunks in while the app queue has room. Credit
        // for them is returned to the peer right here (see `stream.rs` for
        // why not at consumption); what does not fit stays in the core,
        // un-credited, and the reader asks for a refill when it has room.
        let mut credited = 0usize;
        if s.dropped {
            // The stream is gone: unread peer bytes will never be consumed.
            s.to_app.clear();
            s.to_app_bytes = 0;
        } else {
            let mut moved = false;
            while s.to_app_bytes < s.rx_cap {
                let Some(b) = conn.take_inbound(id) else { break };
                s.to_app_bytes += b.len();
                credited += b.len();
                s.to_app.push_back(b);
                moved = true;
            }
            s.starved = conn.has_inbound(id);
            if conn.channel_got_eof(id) && !conn.has_inbound(id) && !s.to_app_eof {
                s.to_app_eof = true;
                moved = true;
            }
            if moved {
                s.wake_reader();
            }
        }
        (
            credited,
            std::mem::take(&mut s.from_app),
            s.from_app_fin,
            s.dropped,
        )
    };

    // ── outside the lock: protocol work ─────────────────────────────────────
    if credited > 0 {
        conn.consume_credit(id, credited);
    }
    if dropped {
        // Nobody will read these; free the window they hold.
        conn.discard_inbound(id);
    }
    // Bytes parked behind a rekey / zero window go out first (one FIFO per
    // channel), then whatever the application wrote since.
    conn.flush_pending(id);
    if !data.is_empty() {
        let sent = conn.send_data(id, &data).unwrap_or(0);
        if sent == data.len() {
            data.clear(); // keeps the allocation for the next batch
        } else {
            data.advance(sent);
        }
    }
    // Stopped by the output backlog (not by the peer's window, which comes
    // back as a WINDOW_ADJUST and marks the channel): revisit when it drains.
    let backlog_blocked = (!data.is_empty() || conn.has_pending_out(id))
        && conn.queued_out_bytes() >= conn.out_soft();

    // ── in the lock again: return what is left, wake the writer ─────────────
    let from_app_empty = {
        let mut s = shared.lock();
        if s.from_app.is_empty() {
            // Nothing arrived meanwhile: hand the buffer (and its capacity)
            // back, with any unsent tail still at the front.
            s.from_app = data;
        } else if !data.is_empty() {
            // The writer appended while we were sealing; our tail precedes it.
            data.extend_from_slice(&s.from_app);
            s.from_app = data;
        }
        if s.from_app.len() < s.tx_cap {
            s.wake_writer();
        }
        if backlog_blocked && !s.out_blocked {
            s.out_blocked = true;
            chans.out_blocked.push(id);
        }
        s.from_app.is_empty()
    };

    // Half-close / close propagation.
    if from_app_empty && fin {
        let _ = conn.send_eof(id);
    }
    // CLOSE only once everything the app wrote has reached the connection:
    // a CLOSE strands whatever is still sitting in `from_app` (the channel
    // refuses further data after `sent_close`).
    if dropped && from_app_empty {
        let _ = conn.send_close(id);
    }
    // `consume_credit` / `send_close` may have just freed the core slot.
    // Drop our map entry even if the stream handle is still draining `to_app`;
    // the handle holds the remaining Arc.
    if !conn.channel_alive(id) {
        shared.lock().terminate(true);
        chans.remove(id);
    }
}
