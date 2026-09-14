//! `ChannelStream`: an `AsyncRead + AsyncWrite` handle over one SSH
//! `direct-tcpip` channel. It shares a bounded buffer with the driver task; a
//! full write buffer or an undrained read queue applies backpressure to that
//! one channel only and never blocks the session.
//!
//! Peer → application is a bounded queue of *owned* chunks moved straight out
//! of the protocol core (no copy); the reader keeps the chunk it is currently
//! serving to itself and touches the shared state only at chunk boundaries.
//!
//! Window credit is returned when a chunk is moved into this queue, not when
//! the application reads it. Returning it on consumption instead was measured
//! to cost 25–35% single-stream throughput: it makes the peer's window an
//! end-to-end control loop through the relay task's scheduling, and every
//! WINDOW_ADJUST then waits on another task getting CPU. The queue is capped
//! (`rx_cap`, plus at most one chunk) so the memory commitment per channel
//! stays `window + rx_cap`; a full queue simply leaves further chunks in the
//! core, un-credited, and the peer stops at its window.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes, BytesMut};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

/// Channels with application-side work for the driver, deduplicated: a
/// channel is listed at most once until the driver has looked at it.
pub(crate) struct ReadyList {
    list: Mutex<Vec<u32>>,
    driver: Arc<Notify>,
}

impl ReadyList {
    pub fn new(driver: Arc<Notify>) -> Self {
        Self {
            list: Mutex::new(Vec::new()),
            driver,
        }
    }

    /// Take everything queued so far.
    pub fn take(&self) -> Vec<u32> {
        std::mem::take(&mut *self.list.lock())
    }
}

pub(crate) struct ChanShared {
    id: u32,
    /// Peer → application: owned chunks, in order.
    pub to_app: VecDeque<Bytes>,
    pub to_app_bytes: usize,
    /// Every byte the peer will ever send has been queued.
    pub to_app_eof: bool,
    /// The session died; reads fail once the queue is drained.
    pub aborted: bool,
    /// Stop moving chunks in once `to_app_bytes` reaches this.
    pub rx_cap: usize,
    /// The driver left chunks in the core because the queue was full; the
    /// reader signals for a refill once it has drained half the cap.
    pub starved: bool,
    /// Application → peer.
    pub from_app: BytesMut,
    /// Emptied buffer the driver lends the writer while it seals `from_app`.
    /// Only held after a write actually overlapped a seal, so the two buffers
    /// alternate instead of being regrown and freed on every pump (#585).
    pub spare: BytesMut,
    pub from_app_fin: bool,
    /// The stream handle was dropped.
    pub dropped: bool,
    /// The channel accepts no more application data.
    pub closed: bool,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
    /// Listed in `ready` and not yet visited by the driver.
    pub queued: bool,
    /// Listed in the driver's output-backlog retry list.
    pub out_blocked: bool,
    ready: Arc<ReadyList>,
    pub tx_cap: usize,
}

impl ChanShared {
    pub fn new(id: u32, tx_cap: usize, rx_cap: usize, ready: Arc<ReadyList>) -> Self {
        Self {
            id,
            to_app: VecDeque::new(),
            to_app_bytes: 0,
            to_app_eof: false,
            aborted: false,
            rx_cap,
            starved: false,
            from_app: BytesMut::new(),
            spare: BytesMut::new(),
            from_app_fin: false,
            dropped: false,
            closed: false,
            read_waker: None,
            write_waker: None,
            queued: false,
            out_blocked: false,
            ready,
            tx_cap,
        }
    }

    /// Tell the driver this channel has application-side work. A channel
    /// already listed is not re-notified: the driver will get to it.
    pub fn signal(&mut self) {
        if !self.queued {
            self.queued = true;
            self.ready.list.lock().push(self.id);
            self.ready.driver.notify_one();
        }
    }
    pub fn wake_reader(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
    }
    pub fn wake_writer(&mut self) {
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
    /// Terminal state for a session that is going away: no more writes, and
    /// reads end (with EOF if `clean`, else with an error) once drained.
    pub fn terminate(&mut self, clean: bool) {
        self.closed = true;
        if clean {
            self.to_app_eof = true;
        } else {
            self.aborted = true;
        }
        self.wake_reader();
        self.wake_writer();
    }
}

/// One SSH direct-tcpip channel as a byte stream.
pub struct ChannelStream {
    shared: Arc<Mutex<ChanShared>>,
    /// Chunk currently being served to the reader; owned here, so the shared
    /// state is touched once per chunk rather than once per `poll_read`.
    cur: Bytes,
}

impl ChannelStream {
    pub(crate) fn new(shared: Arc<Mutex<ChanShared>>) -> Self {
        Self {
            shared,
            cur: Bytes::new(),
        }
    }
}

impl AsyncRead for ChannelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.cur.is_empty() {
                let n = me.cur.len().min(buf.remaining());
                buf.put_slice(&me.cur[..n]);
                me.cur.advance(n);
                return Poll::Ready(Ok(()));
            }
            let mut s = me.shared.lock();
            if let Some(b) = s.to_app.pop_front() {
                s.to_app_bytes -= b.len();
                if s.starved && s.to_app_bytes <= s.rx_cap / 2 {
                    s.starved = false;
                    s.signal(); // room again: let the driver refill from the core
                }
                drop(s);
                me.cur = b;
                continue;
            }
            if s.to_app_eof {
                return Poll::Ready(Ok(())); // EOF, after every queued byte
            }
            if s.aborted {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "ssh session ended",
                )));
            }
            s.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut s = self.shared.lock();
        if s.closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")));
        }
        let room = s.tx_cap.saturating_sub(s.from_app.len());
        if room == 0 {
            s.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = data.len().min(room);
        s.from_app.extend_from_slice(&data[..n]);
        s.signal();
        Poll::Ready(Ok(n))
    }

    /// Ready at once: every accepted byte is already queued for the driver,
    /// which was signalled by `poll_write`, and EOF/CLOSE wait for the queue
    /// to drain, so nothing depends on a flush to be delivered.
    ///
    /// Waiting here until the driver had sealed the queue cost ~40% of
    /// single-stream download throughput (#585): relays flush after every
    /// write, so each relay read became its own small SSH packet plus a
    /// relay↔driver round trip, and `tx_cap` never got to batch. Same
    /// contract as russh's `ChannelTx`.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut s = self.shared.lock();
        s.from_app_fin = true;
        s.signal();
        Poll::Ready(Ok(()))
    }
}

impl Drop for ChannelStream {
    fn drop(&mut self) {
        let mut s = self.shared.lock();
        s.dropped = true;
        // Nobody will read these; release them immediately rather than
        // waiting for the driver (which may not visit us until the peer CLOSE).
        s.to_app.clear();
        s.to_app_bytes = 0;
        s.signal();
    }
}
