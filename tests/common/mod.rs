#![allow(dead_code)]

use std::future::poll_fn;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ssproxy::config::{ClientConfig, ServerConfig};
use ssproxy::core::{Connection, Event};
use ssproxy::{serve, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

pub async fn start_server(cfg: ServerConfig) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Arc::new(cfg)).await;
    });
    addr
}

pub async fn spawn_echo() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

pub async fn spawn_http(body: &'static [u8]) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = s.read(&mut buf).await;
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(hdr.as_bytes()).await;
                let _ = s.write_all(body).await;
            });
        }
    });
    addr
}

/// Slow reader: accepts and reads 1 byte every `delay`.
pub async fn spawn_trickle(delay: std::time::Duration) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1];
                loop {
                    tokio::time::sleep(delay).await;
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    addr
}

pub fn askpass_script() -> PathBuf {
    let p = std::env::temp_dir().join(format!("ssproxy-askpass-{}.sh", std::process::id()));
    std::fs::write(&p, "#!/bin/sh\nexec printf '%s' 'proxy'\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

pub struct ClientPump {
    ssh: TcpStream,
    pub conn: Connection,
    ssh_tmp: Vec<u8>,
}

impl ClientPump {
    pub fn new(ssh: TcpStream, cfg: ClientConfig) -> Self {
        let _ = ssh.set_nodelay(true);
        Self {
            ssh,
            conn: Connection::client(Arc::new(cfg)),
            ssh_tmp: vec![0u8; 64 * 1024],
        }
    }

    fn poll_io(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool>> {
        let mut progress = false;
        let mut pending = false;
        loop {
            let Some(chunk) = self.conn.peek_out() else {
                break;
            };
            match Pin::new(&mut self.ssh).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(ssproxy::Error::Closed)),
                Poll::Ready(Ok(n)) => {
                    self.conn.consume_out(n);
                    progress = true;
                }
                Poll::Ready(Err(e)) if e.kind() == ErrorKind::WouldBlock => {
                    pending = true;
                    break;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => {
                    pending = true;
                    break;
                }
            }
        }
        let _ = Pin::new(&mut self.ssh).poll_flush(cx);
        let mut rb = ReadBuf::new(&mut self.ssh_tmp);
        let n = match Pin::new(&mut self.ssh).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => rb.filled().len(),
            Poll::Ready(Err(e)) if e.kind() == ErrorKind::WouldBlock => {
                pending = true;
                0
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => {
                pending = true;
                0
            }
        };
        if n == 0 && pending && !progress && self.conn.peek_out().is_none() {
            return Poll::Pending;
        }
        if n == 0 && !pending && !progress {
            return Poll::Ready(Err(ssproxy::Error::Closed));
        }
        if n > 0 {
            self.conn
                .read_buf_mut()
                .extend_from_slice(&self.ssh_tmp[..n]);
            self.conn.process_in()?;
            progress = true;
            // Drain newly sealed packets before returning so WINDOW_ADJUST
            // produced by later consume_inbound cannot be observed first.
            loop {
                let Some(chunk) = self.conn.peek_out() else {
                    break;
                };
                match Pin::new(&mut self.ssh).poll_write(cx, chunk) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(ssproxy::Error::Closed)),
                    Poll::Ready(Ok(wn)) => {
                        self.conn.consume_out(wn);
                        progress = true;
                    }
                    Poll::Ready(Err(e)) if e.kind() == ErrorKind::WouldBlock => break,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => break,
                }
            }
        } else if self.conn.read_buf_mut().len() > 0 {
            self.conn.process_in()?;
        }
        if pending && !progress {
            return Poll::Pending;
        }
        Poll::Ready(Ok(progress))
    }

    fn take_poll_io(&mut self, cx: &mut Context<'_>) -> Result<bool> {
        match self.poll_io(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Ok(false),
        }
    }

    pub async fn wait_handshake(&mut self) -> Result<String> {
        poll_fn(|cx| loop {
            match self.poll_io(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) | Poll::Pending => {
                    while let Some(ev) = self.conn.pop_event() {
                        if let Event::HandshakeComplete { user } = ev {
                            return Poll::Ready(Ok(user));
                        }
                        if let Event::Disconnect { message, .. } = ev {
                            return Poll::Ready(Err(ssproxy::Error::proto_fmt(message)));
                        }
                    }
                    if self.conn.authed() {
                        return Poll::Ready(Ok(String::new()));
                    }
                    return Poll::Pending;
                }
            }
            while let Some(ev) = self.conn.pop_event() {
                if let Event::HandshakeComplete { user } = ev {
                    return Poll::Ready(Ok(user));
                }
                if let Event::Disconnect { message, .. } = ev {
                    return Poll::Ready(Err(ssproxy::Error::proto_fmt(message)));
                }
            }
            if self.conn.authed() {
                return Poll::Ready(Ok(String::new()));
            }
        })
        .await
    }

    pub async fn wait_channel_up(&mut self, id: u32) -> Result<()> {
        poll_fn(|cx| loop {
            match self.poll_io(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) | Poll::Pending => {
                    while let Some(ev) = self.conn.pop_event() {
                        match ev {
                            Event::ChannelOpenConfirmation { local_id } if local_id == id => {
                                return Poll::Ready(Ok(()));
                            }
                            Event::ChannelOpenFailure {
                                local_id, message, ..
                            } if local_id == id => {
                                return Poll::Ready(Err(ssproxy::Error::proto_fmt(message)));
                            }
                            Event::Disconnect { message, .. } => {
                                return Poll::Ready(Err(ssproxy::Error::proto_fmt(message)));
                            }
                            _ => {}
                        }
                    }
                    if self.conn.outbound_allowance(id) > 0 {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
            while let Some(ev) = self.conn.pop_event() {
                match ev {
                    Event::ChannelOpenConfirmation { local_id } if local_id == id => {
                        return Poll::Ready(Ok(()));
                    }
                    Event::ChannelOpenFailure {
                        local_id, message, ..
                    } if local_id == id => {
                        return Poll::Ready(Err(ssproxy::Error::proto_fmt(message)));
                    }
                    _ => {}
                }
            }
            if self.conn.outbound_allowance(id) > 0 {
                return Poll::Ready(Ok(()));
            }
        })
        .await
    }

    pub async fn flush_out(&mut self) -> Result<()> {
        poll_fn(|cx| loop {
            match self.poll_io(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => {
                    if self.conn.peek_out().is_none() {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Ok(false)) | Poll::Pending => {
                    if self.conn.peek_out().is_none() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        })
        .await
    }

    pub async fn write_all(&mut self, id: u32, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let n = poll_fn(|cx| loop {
                match self.poll_io(cx) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) | Poll::Pending => {
                        let allow = self.conn.outbound_allowance(id);
                        if allow == 0 {
                            return Poll::Pending;
                        }
                        return match self.conn.send_data(id, &data[..data.len().min(allow)]) {
                            Ok(n) => Poll::Ready(Ok(n)),
                            Err(e) => Poll::Ready(Err(e)),
                        };
                    }
                }
                let allow = self.conn.outbound_allowance(id);
                if allow > 0 {
                    return match self.conn.send_data(id, &data[..data.len().min(allow)]) {
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(e) => Poll::Ready(Err(e)),
                    };
                }
            })
            .await?;
            if n == 0 {
                self.flush_out().await?;
            } else {
                data = &data[n..];
            }
        }
        self.flush_out().await
    }

    pub async fn read_exact(&mut self, id: u32, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        poll_fn(|cx| loop {
            match self.poll_io(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) | Poll::Pending => {}
            }
            while let Some(d) = self.conn.peek_inbound(id) {
                let take = (n - out.len()).min(d.len());
                out.extend_from_slice(&d[..take]);
                self.conn.consume_inbound(id, take);
                if out.len() == n {
                    return Poll::Ready(Ok(()));
                }
            }
            match self.poll_io(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
            }
        })
        .await?;
        Ok(out)
    }

    pub async fn pump_for(&mut self, dur: std::time::Duration) {
        let _ = tokio::time::timeout(
            dur,
            poll_fn(|cx| {
                let _ = self.poll_io(cx);
                Poll::<()>::Pending
            }),
        )
        .await;
    }
}

pub fn ssh_base_args(port: u16) -> Vec<String> {
    vec![
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "PreferredAuthentications=password".into(),
        "-o".into(),
        "PubkeyAuthentication=no".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=1".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "KbdInteractiveAuthentication=no".into(),
        "-p".into(),
        port.to_string(),
    ]
}

pub async fn ssh_env() -> Vec<(String, String)> {
    let ask = askpass_script();
    vec![
        ("SSH_ASKPASS".into(), ask.display().to_string()),
        ("SSH_ASKPASS_REQUIRE".into(), "force".into()),
        ("DISPLAY".into(), ":0".into()),
        ("SSH_AUTH_SOCK".into(), "".into()),
    ]
}

pub async fn run_ssh_stdio(
    ssh_port: u16,
    target: &str,
    extra: &[&str],
    payload: &[u8],
    read_n: usize,
) -> Vec<u8> {
    let mut args = ssh_base_args(ssh_port);
    for e in extra {
        args.push((*e).into());
    }
    args.push("-W".into());
    args.push(target.into());
    args.push("proxy@127.0.0.1".into());
    let mut cmd = Command::new("ssh");
    cmd.args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in ssh_env().await {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn ssh");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(payload).await.unwrap();
        let _ = stdin.shutdown().await;
    }
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; read_n];
    stdout.read_exact(&mut buf).await.expect("ssh stdout");
    let _ = child.kill().await;
    buf
}
