mod common;

use std::time::{Duration, Instant};

use ssproxy::config::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;

use common::{spawn_echo, start_server, ClientPump};

#[tokio::test(flavor = "multi_thread")]
async fn stress_parallel_channels_and_bytes() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut c = ClientPump::new(stream, ClientConfig::new("proxy", "proxy"));
    c.wait_handshake().await.unwrap();

    let nchan = 24usize;
    let nbytes = 64 * 1024usize;
    let mut ids = Vec::new();
    for _ in 0..nchan {
        let id = c
            .conn
            .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
            .unwrap();
        ids.push(id);
    }
    for &id in &ids {
        c.wait_channel_up(id).await.unwrap();
    }

    let payloads: Vec<Vec<u8>> = (0..nchan)
        .map(|i| (0..nbytes).map(|j| ((i + j) % 251) as u8).collect())
        .collect();

    let t0 = Instant::now();
    for (id, p) in ids.iter().zip(payloads.iter()) {
        c.write_all(*id, p).await.unwrap();
    }
    for (id, p) in ids.iter().zip(payloads.iter()) {
        let got = c.read_exact(*id, p.len()).await.unwrap();
        assert_eq!(&got, p);
    }
    eprintln!(
        "stress {} ch x {} bytes in {:?}",
        nchan,
        nbytes,
        t0.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn steady_state_repeated_transfers() {
    let mut cfg = ServerConfig::test_config();
    cfg.rekey_after_bytes = 256 * 1024;
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(40)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut ccfg = ClientConfig::new("proxy", "proxy");
    ccfg.rekey_after_bytes = 256 * 1024;
    let mut c = ClientPump::new(stream, ccfg);
    c.wait_handshake().await.unwrap();
    let id = c
        .conn
        .open_direct_tcpip(&echo.ip().to_string(), echo.port() as u32)
        .unwrap();
    c.wait_channel_up(id).await.unwrap();

    let rounds = std::env::var("SSPROXY_STEADY_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20u32);
    let chunk: Vec<u8> = (0..48 * 1024).map(|i| (i % 241) as u8).collect();
    let t0 = Instant::now();
    for r in 0..rounds {
        c.write_all(id, &chunk).await.unwrap();
        let got = c.read_exact(id, chunk.len()).await.unwrap();
        assert_eq!(got, chunk, "round {r}");
    }
    eprintln!("steady {rounds} rounds in {:?}", t0.elapsed());
}
