//! `ChannelStream`: an `AsyncRead + AsyncWrite` handle over one SSH
//! `direct-tcpip` channel. It shares a bounded buffer with the driver task; a
//! full write buffer or an undrained read buffer applies backpressure to that
//! one channel only and never blocks the session.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

pub(crate) struct ChanShared {
    /// Peer → application.
    pub to_app: BytesMut,
    pub to_app_eof: bool,
    /// Application → peer.
    pub from_app: BytesMut,
    pub from_app_fin: bool,
    /// The stream handle was dropped.
    pub dropped: bool,
    /// The channel no longer exists on the protocol side.
    pub closed: bool,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
    driver: Arc<Notify>,
    pub tx_cap: usize,
}

impl ChanShared {
    pub fn new(tx_cap: usize, driver: Arc<Notify>) -> Self {
        Self {
            to_app: BytesMut::new(),
            to_app_eof: false,
            from_app: BytesMut::new(),
            from_app_fin: false,
            dropped: false,
            closed: false,
            read_waker: None,
            write_waker: None,
            driver,
            tx_cap,
        }
    }

    pub fn wake_driver(&mut self) {
        self.driver.notify_one();
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
}

/// One SSH direct-tcpip channel as a byte stream.
pub struct ChannelStream {
    shared: Arc<Mutex<ChanShared>>,
}

impl ChannelStream {
    pub(crate) fn new(shared: Arc<Mutex<ChanShared>>) -> Self {
        Self { shared }
    }
}

impl AsyncRead for ChannelStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut s = self.shared.lock();
        if !s.to_app.is_empty() {
            let n = s.to_app.len().min(buf.remaining());
            let chunk = s.to_app.split_to(n);
            buf.put_slice(&chunk);
            s.wake_driver(); // draining may re-open the receive window
            return Poll::Ready(Ok(()));
        }
        if s.to_app_eof || s.closed {
            return Poll::Ready(Ok(())); // EOF
        }
        s.read_waker = Some(cx.waker().clone());
        Poll::Pending
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
        s.wake_driver();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut s = self.shared.lock();
        if s.closed || s.from_app.is_empty() {
            return Poll::Ready(Ok(()));
        }
        s.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut s = self.shared.lock();
        s.from_app_fin = true;
        s.wake_driver();
        Poll::Ready(Ok(()))
    }
}

impl Drop for ChannelStream {
    fn drop(&mut self) {
        let mut s = self.shared.lock();
        s.dropped = true;
        s.wake_driver();
    }
}
