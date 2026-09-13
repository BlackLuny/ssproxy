//! Interop against the real OpenSSH client via the `ssproxyd`-style server.
//! Requires `ssh` (and `curl` for the SOCKS test) on PATH.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ssproxy::config::ServerConfig;
use ssproxy::driver::{self, AuthOutcome, Hooks, OpenOutcome};
use ssproxy::hostkey::HostKey;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

async fn start_server(publickey: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = ServerConfig::new(HostKey::generate());
    cfg.methods.publickey = publickey;
    let cfg = Arc::new(cfg);
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let _ = sock.set_nodelay(true);
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<driver::IncomingChannel>();
                let mut users = HashMap::new();
                users.insert("proxy".to_string(), "proxy".to_string());
                let hooks = Hooks {
                    auth_password: Box::new(move |u, p| {
                        if users.get(u).map(|s| s == p).unwrap_or(false) {
                            AuthOutcome::Accept
                        } else {
                            AuthOutcome::Reject { delay: Duration::from_millis(50) }
                        }
                    }),
                    open: Box::new(|_, _, _| OpenOutcome::Accept),
                    ..Hooks::default()
                };
                tokio::spawn(async move {
                    while let Some(ch) = rx.recv().await {
                        tokio::spawn(async move {
                            let mut s = ch.stream;
                            match TcpStream::connect((ch.host.as_str(), ch.port)).await {
                                Ok(mut up) => {
                                    let _ = up.set_nodelay(true);
                                    let _ = copy_bidirectional(&mut s, &mut up).await;
                                }
                                Err(_) => {
                                    let _ = s.shutdown().await;
                                }
                            }
                        });
                    }
                });
                if let Err(e) = driver::serve(sock, cfg, hooks, tx).await {
                    eprintln!("SERVER ended: {e}");
                }
            });
        }
    });
    port
}

async fn spawn_echo() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn askpass() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ssproxy-askpass-{}.sh", std::process::id()));
    std::fs::write(&p, "#!/bin/sh\nexec printf '%s' 'proxy'\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

fn ssh_base(port: u16) -> Vec<String> {
    [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "KbdInteractiveAuthentication=no",
        "-p", &port.to_string(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn ssh_env(cmd: &mut Command) {
    let ask = askpass();
    cmd.env("SSH_ASKPASS", ask.display().to_string())
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .env("SSH_AUTH_SOCK", "");
}

async fn ssh_forward(port: u16, target: &str, extra: &[&str], payload: &[u8], read_n: usize) -> Vec<u8> {
    let mut args = ssh_base(port);
    for e in extra {
        args.push((*e).to_string());
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
    ssh_env(&mut cmd);
    let mut child = cmd.spawn().expect("spawn ssh");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(payload).await.unwrap();
        let _ = stdin.shutdown().await;
    }
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; read_n];
    match stdout.read_exact(&mut buf).await {
        Ok(_) => {
            let _ = child.kill().await;
            buf
        }
        Err(e) => {
            let mut err = Vec::new();
            if let Some(mut es) = child.stderr.take() {
                let _ = es.read_to_end(&mut err).await;
            }
            let _ = child.kill().await;
            panic!("ssh read: {e}; stderr={}", String::from_utf8_lossy(&err));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_stdio_forward_echo() {
    let port = start_server(false).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let payload = b"openssh-interop-ping-01";
    let target = format!("{}:{}", echo.ip(), echo.port());
    let got = tokio::time::timeout(
        Duration::from_secs(15),
        ssh_forward(port, &target, &[], payload, payload.len()),
    )
    .await
    .expect("timeout");
    assert_eq!(got.as_slice(), payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_each_cipher_and_kex() {
    let port = start_server(false).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let target = format!("{}:{}", echo.ip(), echo.port());
    let payload = b"cipher-kex-matrix-ok";

    let ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes128-ctr"];
    let kexes = ["curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp521", "mlkem768x25519-sha256"];
    for c in ciphers {
        let got = tokio::time::timeout(
            Duration::from_secs(15),
            ssh_forward(port, &target, &["-c", c], payload, payload.len()),
        )
        .await
        .unwrap_or_else(|_| panic!("cipher timeout {c}"));
        assert_eq!(got.as_slice(), payload, "cipher {c}");
    }
    for k in kexes {
        let got = tokio::time::timeout(
            Duration::from_secs(15),
            ssh_forward(port, &target, &["-o", &format!("KexAlgorithms={k}")], payload, payload.len()),
        )
        .await
        .unwrap_or_else(|_| panic!("kex timeout {k}"));
        assert_eq!(got.as_slice(), payload, "kex {k}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_large_transfer_rekey() {
    let port = start_server(false).await;
    let echo = spawn_echo().await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let payload: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    let target = format!("{}:{}", echo.ip(), echo.port());
    let got = tokio::time::timeout(
        Duration::from_secs(30),
        // RekeyLimit forces the client to rekey mid-transfer too.
        ssh_forward(port, &target, &["-o", "RekeyLimit=128K"], &payload, payload.len()),
    )
    .await
    .expect("timeout");
    assert_eq!(got.len(), payload.len());
    assert_eq!(got, payload);
}
