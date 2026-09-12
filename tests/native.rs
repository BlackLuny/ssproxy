mod common;

use std::time::Duration;

use ssproxy::config::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;

use common::{spawn_echo, start_server, ClientPump};

#[tokio::test(flavor = "multi_thread")]
async fn native_direct_tcpip_echo() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut c = ClientPump::new(stream, ClientConfig::new("proxy", "proxy"));
    c.wait_handshake().await.unwrap();
    let id = c
        .conn
        .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
        .unwrap();
    c.wait_channel_up(id).await.unwrap();
    let msg = b"hello-ssproxy-echo";
    c.write_all(id, msg).await.unwrap();
    let got = c.read_exact(id, msg.len()).await.unwrap();
    assert_eq!(got, msg);
}

#[tokio::test(flavor = "multi_thread")]
async fn native_many_channels() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut c = ClientPump::new(stream, ClientConfig::new("proxy", "proxy"));
    c.wait_handshake().await.unwrap();

    let mut ids = Vec::new();
    for _ in 0..32 {
        let id = c
            .conn
            .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
            .unwrap();
        ids.push(id);
    }
    for &id in &ids {
        c.wait_channel_up(id).await.unwrap();
    }
    for (i, &id) in ids.iter().enumerate() {
        let msg = format!("chan-{i}-payload").into_bytes();
        c.write_all(id, &msg).await.unwrap();
        let got = c.read_exact(id, msg.len()).await.unwrap();
        assert_eq!(got, msg);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn native_megabyte_transfer() {
    let mut cfg = ServerConfig::test_config();
    cfg.rekey_after_bytes = 128 * 1024;
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut ccfg = ClientConfig::new("proxy", "proxy");
    ccfg.rekey_after_bytes = 128 * 1024;
    let mut c = ClientPump::new(stream, ccfg);
    c.wait_handshake().await.unwrap();
    let id = c
        .conn
        .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
        .unwrap();
    c.wait_channel_up(id).await.unwrap();

    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    for round in 0..5 {
        c.write_all(id, &payload).await.unwrap();
        let got = c.read_exact(id, payload.len()).await.unwrap();
        assert_eq!(got, payload, "round {round}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn duplex_rekey_fragmented() {
    use tokio::io::DuplexStream;
    async fn drive(
        mut sock: DuplexStream,
        mut conn: ssproxy::Connection,
        is_server: bool,
    ) -> Vec<u8> {
        use bytes::BufMut;
        use std::pin::Pin;
        use std::task::Poll;
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
        let mut got = Vec::new();
        let mut sent_open = false;
        let mut chan = None;
        let payload: Vec<u8> = (0..48 * 1024).map(|i| (i % 251) as u8).collect();
        let mut sent = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                panic!("duplex timeout got={} sent={sent}", got.len());
            }
            std::future::poll_fn(|cx| loop {
                let mut progress = false;
                if let Some(chunk) = conn.peek_out() {
                    match Pin::new(&mut sock).poll_write(cx, chunk) {
                        Poll::Ready(Ok(0)) => return Poll::Ready(Err(ssproxy::Error::Closed)),
                        Poll::Ready(Ok(n)) => {
                            conn.consume_out(n);
                            progress = true;
                        }
                        Poll::Pending => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    }
                }
                {
                    let buf = conn.read_buf_mut();
                    buf.reserve(4096);
                    let spare = buf.spare_capacity_mut();
                    if !spare.is_empty() {
                        let mut rb = ReadBuf::uninit(spare);
                        match Pin::new(&mut sock).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n > 0 {
                                    unsafe {
                                        buf.advance_mut(n);
                                    }
                                    progress = true;
                                }
                            }
                            Poll::Pending => {}
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        }
                    }
                }
                if let Err(e) = conn.process_in() {
                    return Poll::Ready(Err(e));
                }
                while let Some(ev) = conn.pop_event() {
                    match ev {
                        ssproxy::Event::OpenDirectTcpIp { local_id, .. } if is_server => {
                            conn.confirm_open(local_id).unwrap();
                            chan = Some(local_id);
                        }
                        ssproxy::Event::ChannelOpenConfirmation { local_id } => {
                            chan = Some(local_id);
                        }
                        ssproxy::Event::ChannelData { local_id } => {
                            if is_server {
                                while let Some(d) = conn.peek_inbound(local_id).map(|x| x.to_vec())
                                {
                                    let n = d.len();
                                    conn.consume_inbound(local_id, n);
                                    conn.send_data(local_id, &d).unwrap();
                                }
                            } else {
                                while let Some(d) = conn.peek_inbound(local_id).map(|x| x.to_vec())
                                {
                                    let n = d.len();
                                    conn.consume_inbound(local_id, n);
                                    got.extend_from_slice(&d);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if !is_server && conn.authed() && !sent_open {
                    let id = conn.open_direct_tcpip("x", 1).unwrap();
                    chan = Some(id);
                    sent_open = true;
                    progress = true;
                }
                if !is_server {
                    if let Some(id) = chan {
                        if sent < payload.len() {
                            let n = conn.send_data(id, &payload[sent..]).unwrap();
                            if n > 0 {
                                sent += n;
                                progress = true;
                            }
                        }
                    }
                }
                if !is_server && got.len() == payload.len() {
                    return Poll::Ready(Ok(()));
                }
                if !progress {
                    return Poll::Pending;
                }
            })
            .await
            .unwrap();
            if got.len() == payload.len() {
                return got;
            }
        }
    }

    let (a, b) = tokio::io::duplex(8192);
    let mut scfg = ServerConfig::test_config();
    scfg.rekey_after_bytes = 4096;
    let mut ccfg = ClientConfig::new("proxy", "proxy");
    ccfg.rekey_after_bytes = 4096;
    let sconn = ssproxy::Connection::server(std::sync::Arc::new(scfg));
    let cconn = ssproxy::Connection::client(std::sync::Arc::new(ccfg));
    let server = tokio::spawn(async move { drive(a, sconn, true).await });
    let got = drive(b, cconn, false).await;
    server.abort();
    let expect: Vec<u8> = (0..48 * 1024).map(|i| (i % 251) as u8).collect();
    assert_eq!(got, expect);
}

#[tokio::test(flavor = "multi_thread")]
async fn native_wrong_password() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut c = ClientPump::new(stream, ClientConfig::new("proxy", "nope"));
    let r = tokio::time::timeout(Duration::from_secs(5), c.wait_handshake()).await;
    assert!(r.is_err() || r.unwrap().is_err());
}
