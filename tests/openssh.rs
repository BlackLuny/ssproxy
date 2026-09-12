mod common;

use std::process::Stdio;
use std::time::Duration;

use ssproxy::config::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use common::{
    askpass_script, run_ssh_stdio, spawn_echo, spawn_http, ssh_base_args, ssh_env, start_server,
};

#[tokio::test(flavor = "multi_thread")]
async fn openssh_stdio_forward_echo() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(80)).await;

    let payload = b"openssh-interop-ping";
    let target = format!("{}:{}", echo.ip(), echo.port());
    let got = tokio::time::timeout(
        Duration::from_secs(15),
        run_ssh_stdio(ssh_addr.port(), &target, &[], payload, payload.len()),
    )
    .await
    .expect("timeout");
    assert_eq!(got.as_slice(), payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_chacha_and_aesgcm() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let target = format!("{}:{}", echo.ip(), echo.port());
    let payload = b"cipher-check-ok!!";

    for cipher in [
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
    ] {
        let extra = ["-c", cipher];
        let got = tokio::time::timeout(
            Duration::from_secs(15),
            run_ssh_stdio(ssh_addr.port(), &target, &extra, payload, payload.len()),
        )
        .await
        .unwrap_or_else(|_| panic!("timeout {cipher}"));
        assert_eq!(got.as_slice(), payload, "{cipher}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_dynamic_socks_http() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let http = spawn_http(b"hello-web").await;
    tokio::time::sleep(Duration::from_millis(80)).await;

    let socks = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let mut args = ssh_base_args(ssh_addr.port());
    args.extend([
        "-N".into(),
        "-D".into(),
        format!("127.0.0.1:{socks}"),
        "proxy@127.0.0.1".into(),
    ]);
    let mut cmd = Command::new("ssh");
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in ssh_env().await {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();

    let url = format!("http://{}:{}/", http.ip(), http.port());
    let mut body = String::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let out = Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "2",
                "--socks5-hostname",
                &format!("127.0.0.1:{socks}"),
                &url,
            ])
            .output()
            .await
            .unwrap();
        if out.status.success() {
            body = String::from_utf8_lossy(&out.stdout).into_owned();
            break;
        }
    }
    let _ = child.kill().await;
    assert_eq!(body, "hello-web");
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_large_transfer() {
    let cfg = ServerConfig::test_config();
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(80)).await;

    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let target = format!("{}:{}", echo.ip(), echo.port());
    let got = tokio::time::timeout(
        Duration::from_secs(30),
        run_ssh_stdio(ssh_addr.port(), &target, &[], &payload, payload.len()),
    )
    .await
    .expect("timeout");
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_rekey_during_forward() {
    let mut cfg = ServerConfig::test_config();
    cfg.rekey_after_bytes = 64 * 1024;
    let ssh_addr = start_server(cfg).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(80)).await;

    let payload: Vec<u8> = (0..400 * 1024).map(|i| (i % 251) as u8).collect();
    let target = format!("{}:{}", echo.ip(), echo.port());
    let got = tokio::time::timeout(
        Duration::from_secs(30),
        run_ssh_stdio(ssh_addr.port(), &target, &[], &payload, payload.len()),
    )
    .await
    .expect("timeout");
    assert_eq!(got, payload);
}

// silence unused in some cfgs
#[allow(dead_code)]
fn _ask() {
    let _ = askpass_script();
}
