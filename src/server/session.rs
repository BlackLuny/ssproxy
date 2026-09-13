use std::collections::HashMap;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::config::ServerConfig;
use crate::core::channel::ChannelKind;
use crate::core::conn::{Connection, Event};
use crate::error::{Error, Result};
use crate::proto::{SSH_DISCONNECT_BY_APPLICATION, SSH_OPEN_CONNECT_FAILED};

enum Dest {
    Connecting {
        fut: Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>,
        deadline: Instant,
    },
    Up {
        stream: TcpStream,
        write_shutdown: bool,
        read_eof: bool,
    },
}

/// Poll-driven SSH session. No async/await in the state machine.
pub struct Session {
    ssh: TcpStream,
    conn: Connection,
    dests: HashMap<u32, Dest>,
    cfg: Arc<ServerConfig>,
    tmp: Vec<u8>,
    ssh_tmp: Vec<u8>,
}

impl Session {
    pub fn new(ssh: TcpStream, cfg: Arc<ServerConfig>) -> Self {
        let _ = ssh.set_nodelay(true);
        tcp_quickack(&ssh);
        let conn = Connection::server(cfg.clone());
        let max_packet = cfg.max_packet as usize;
        Self {
            ssh,
            conn,
            dests: HashMap::new(),
            cfg,
            tmp: vec![0u8; max_packet.max(16384)],
            ssh_tmp: vec![0u8; 64 * 1024],
        }
    }

    fn handle_events(&mut self) -> Result<()> {
        while let Some(ev) = self.conn.pop_event() {
            match ev {
                Event::HandshakeComplete { user } => {
                    tracing::info!(%user, "auth ok");
                }
                Event::OpenSession { local_id } => {
                    self.conn.confirm_open(local_id)?;
                }
                Event::OpenDirectTcpIp {
                    local_id,
                    host,
                    port,
                } => {
                    self.start_connect(local_id, host, port as u16);
                }
                Event::ChannelEof { local_id } => {
                    if let Some(Dest::Up { write_shutdown, .. }) = self.dests.get_mut(&local_id) {
                        *write_shutdown = true;
                    }
                }
                Event::ChannelClose { local_id } => {
                    self.dests.remove(&local_id);
                }
                Event::Disconnect { reason, message } => {
                    tracing::debug!(reason, %message, "peer disconnect");
                }
                Event::ChannelData { .. }
                | Event::ChannelOpenConfirmation { .. }
                | Event::ChannelOpenFailure { .. } => {}
            }
        }
        Ok(())
    }

    fn start_connect(&mut self, local_id: u32, host: String, port: u16) {
        let deadline = Instant::now() + self.cfg.connect_timeout;
        let fut = Box::pin(async move {
            let s = TcpStream::connect((host.as_str(), port)).await?;
            let _ = s.set_nodelay(true);
            Ok(s)
        });
        self.dests
            .insert(local_id, Dest::Connecting { fut, deadline });
    }

    fn poll_ssh_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool>> {
        let mut progress = false;
        #[allow(clippy::while_let_loop)]
        loop {
            let Some(chunk) = self.conn.peek_out() else {
                break;
            };
            match Pin::new(&mut self.ssh).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::Closed));
                }
                Poll::Ready(Ok(n)) => {
                    self.conn.consume_out(n);
                    progress = true;
                }
                Poll::Ready(Err(e)) if e.kind() == ErrorKind::WouldBlock => break,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => break,
            }
        }
        let _ = Pin::new(&mut self.ssh).poll_flush(cx);
        Poll::Ready(Ok(progress))
    }

    fn poll_ssh_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool>> {
        let mut rb = ReadBuf::new(&mut self.ssh_tmp);
        let n = match Pin::new(&mut self.ssh).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => rb.filled().len(),
            Poll::Ready(Err(e)) if e.kind() == ErrorKind::WouldBlock => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => return Poll::Pending,
        };
        if n == 0 {
            self.conn
                .disconnect(SSH_DISCONNECT_BY_APPLICATION, "connection lost");
            return Poll::Ready(Ok(true));
        }
        // OpenSSH leaves Nagle on until after auth. A read with no immediate
        // reply (KEXINIT, NEWKEYS) otherwise waits for Linux delayed ACK (~40ms).
        tcp_quickack(&self.ssh);
        self.conn
            .read_buf_mut()
            .extend_from_slice(&self.ssh_tmp[..n]);
        self.conn.process_in()?;
        Poll::Ready(Ok(true))
    }

    fn poll_connects(&mut self, cx: &mut Context<'_>) -> Result<bool> {
        let mut progress = false;
        let mut done: Vec<(u32, io::Result<TcpStream>)> = Vec::new();
        let mut timeout: Vec<u32> = Vec::new();
        for (id, dest) in self.dests.iter_mut() {
            if let Dest::Connecting { fut, deadline } = dest {
                if Instant::now() > *deadline {
                    timeout.push(*id);
                    continue;
                }
                match fut.as_mut().poll(cx) {
                    Poll::Ready(r) => done.push((*id, r)),
                    Poll::Pending => {}
                }
            }
        }
        for id in timeout {
            self.dests.remove(&id);
            self.conn
                .fail_open(id, SSH_OPEN_CONNECT_FAILED, "timeout")?;
            progress = true;
        }
        for (id, r) in done {
            self.dests.remove(&id);
            match r {
                Ok(stream) => {
                    self.conn.confirm_open(id)?;
                    self.dests.insert(
                        id,
                        Dest::Up {
                            stream,
                            write_shutdown: false,
                            read_eof: false,
                        },
                    );
                    progress = true;
                }
                Err(e) => {
                    self.conn
                        .fail_open(id, SSH_OPEN_CONNECT_FAILED, &e.to_string())?;
                    progress = true;
                }
            }
        }
        Ok(progress)
    }

    fn poll_dests(&mut self, cx: &mut Context<'_>) -> Result<bool> {
        let mut progress = false;
        let ids = self.conn.round_robin_ids();
        for id in ids {
            if !self.conn.channel_alive(id) {
                self.dests.remove(&id);
                continue;
            }
            if matches!(self.conn.channel_kind(id), Some(ChannelKind::Session)) {
                continue;
            }
            progress |= self.poll_dest_one(cx, id)?;
        }
        Ok(progress)
    }

    fn poll_dest_one(&mut self, cx: &mut Context<'_>, id: u32) -> Result<bool> {
        let mut progress = false;
        // inbound SSH -> dest write
        #[allow(clippy::while_let_loop)]
        loop {
            let Some(chunk) = self.conn.peek_inbound(id).map(|s| s.to_vec()) else {
                break;
            };
            let dest = match self.dests.get_mut(&id) {
                Some(d) => d,
                None => break,
            };
            let Dest::Up { stream, .. } = dest else {
                break;
            };
            match Pin::new(stream).poll_write(cx, &chunk) {
                Poll::Ready(Ok(0)) => {
                    if let Some(Dest::Up { write_shutdown, .. }) = self.dests.get_mut(&id) {
                        *write_shutdown = true;
                    }
                    break;
                }
                Poll::Ready(Ok(n)) => {
                    self.conn.consume_inbound(id, n);
                    progress = true;
                }
                Poll::Ready(Err(e)) if e.kind() == ErrorKind::WouldBlock => break,
                Poll::Ready(Err(_)) => {
                    let _ = self.conn.send_eof(id);
                    let _ = self.conn.send_close(id);
                    self.dests.remove(&id);
                    progress = true;
                    return Ok(progress);
                }
                Poll::Pending => break,
            }
        }

        // dest read -> SSH
        let allow = self.conn.outbound_allowance(id);
        if allow > 0 {
            if let Some(Dest::Up {
                stream, read_eof, ..
            }) = self.dests.get_mut(&id)
            {
                if !*read_eof {
                    let nmax = allow.min(self.tmp.len());
                    let mut rb = ReadBuf::new(&mut self.tmp[..nmax]);
                    match Pin::new(stream).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                *read_eof = true;
                                self.conn.send_eof(id)?;
                                progress = true;
                            } else {
                                let _ = self.conn.send_data(id, &self.tmp[..n])?;
                                progress = true;
                            }
                        }
                        Poll::Ready(Err(e)) if e.kind() == ErrorKind::WouldBlock => {}
                        Poll::Ready(Err(_)) => {
                            self.conn.send_eof(id)?;
                            self.conn.send_close(id)?;
                            self.dests.remove(&id);
                            return Ok(true);
                        }
                        Poll::Pending => {}
                    }
                }
            }
        }

        if let Some(Dest::Up {
            stream,
            read_eof,
            write_shutdown,
        }) = self.dests.get_mut(&id)
        {
            let inbound_empty = self
                .conn
                .peek_inbound(id)
                .map(|d| d.is_empty())
                .unwrap_or(true);
            if *write_shutdown && inbound_empty {
                let _ = Pin::new(stream).poll_shutdown(cx);
            }
            let done = *read_eof && (*write_shutdown || self.conn.channel_got_eof(id));
            if done && inbound_empty {
                self.conn.send_close(id)?;
                self.dests.remove(&id);
                progress = true;
            }
        }
        Ok(progress)
    }
}

/// Linux `TCP_QUICKACK` is not sticky; re-arm after each read so the kernel
/// ACKs immediately instead of waiting up to ~40ms to piggyback.
fn tcp_quickack(_stream: &TcpStream) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let fd = _stream.as_raw_fd();
        let on: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of_val(&on) as libc::socklen_t,
            );
        }
    }
}

impl Future for Session {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let mut progress = false;
            match this.poll_ssh_write(cx) {
                Poll::Ready(Ok(p)) => progress |= p,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            match this.poll_ssh_read(cx) {
                Poll::Ready(Ok(p)) => progress |= p,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            // Drain sealed packets before dest I/O queues more CHANNEL_DATA /
            // WINDOW_ADJUST onto the write FIFO.
            match this.poll_ssh_write(cx) {
                Poll::Ready(Ok(p)) => progress |= p,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            this.handle_events()?;
            progress |= this.poll_connects(cx)?;
            progress |= this.poll_dests(cx)?;
            this.handle_events()?;
            match this.poll_ssh_write(cx) {
                Poll::Ready(Ok(p)) => progress |= p,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            if this.conn.is_finished() {
                return Poll::Ready(Ok(()));
            }
            if this.conn.is_closed() && !this.conn.wants_write() {
                return Poll::Ready(Ok(()));
            }
            if !progress {
                return Poll::Pending;
            }
        }
    }
}
