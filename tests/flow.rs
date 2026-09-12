mod common;

use std::time::{Duration, Instant};

use ssproxy::config::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;

use common::{spawn_echo, spawn_trickle, start_server, ClientPump};

#[tokio::test(flavor = "multi_thread")]
async fn hol_fast_channel_not_blocked_by_slow() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    let slow = spawn_trickle(Duration::from_millis(20)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut c = ClientPump::new(stream, ClientConfig::new("proxy", "proxy"));
    c.wait_handshake().await.unwrap();

    let slow_id = c
        .conn
        .open_direct_tcpip(&slow.ip().to_string(), slow.port() as u32)
        .unwrap();
    let fast_id = c
        .conn
        .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
        .unwrap();
    c.wait_channel_up(slow_id).await.unwrap();
    c.wait_channel_up(fast_id).await.unwrap();

    let bulky = vec![0xABu8; 128 * 1024];
    // Fill the slow channel (do not wait for echo).
    let _ = c.conn.send_data(slow_id, &bulky).unwrap();

    let ping = b"fast-path";
    let t0 = Instant::now();
    c.write_all(fast_id, ping).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), c.read_exact(fast_id, ping.len()))
        .await
        .expect("fast channel HOL timeout")
        .unwrap();
    assert_eq!(got, ping);
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "fast channel stalled behind slow HOL: {:?}",
        t0.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn window_backpressure_survives() {
    let mut cfg = ServerConfig::test_config();
    cfg.window = 32 * 1024;
    cfg.max_packet = 8 * 1024;
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(40)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut ccfg = ClientConfig::new("proxy", "proxy");
    ccfg.window = 32 * 1024;
    ccfg.max_packet = 8 * 1024;
    let mut c = ClientPump::new(stream, ccfg);
    c.wait_handshake().await.unwrap();
    let id = c
        .conn
        .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
        .unwrap();
    c.wait_channel_up(id).await.unwrap();

    let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 199) as u8).collect();
    c.write_all(id, &payload).await.unwrap();
    let got = c.read_exact(id, payload.len()).await.unwrap();
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_clients() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(40)).await;

    let mut joins = Vec::new();
    for i in 0..16 {
        joins.push(tokio::spawn(async move {
            let stream = TcpStream::connect(ssh_addr).await.unwrap();
            let mut c = ClientPump::new(stream, ClientConfig::new("proxy", "proxy"));
            c.wait_handshake().await.unwrap();
            let id = c
                .conn
                .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
                .unwrap();
            c.wait_channel_up(id).await.unwrap();
            let msg = format!("client-{i}").into_bytes();
            c.write_all(id, &msg).await.unwrap();
            let got = c.read_exact(id, msg.len()).await.unwrap();
            assert_eq!(got, msg);
        }));
    }
    for j in joins {
        j.await.unwrap();
    }
}
