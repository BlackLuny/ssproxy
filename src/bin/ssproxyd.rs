//! Standalone SSH TCP-proxy daemon (password auth), for manual/interop testing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ssproxy::config::ServerConfig;
use ssproxy::driver::{self, AuthOutcome, Hooks, OpenOutcome};
use ssproxy::hostkey::HostKey;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser, Debug)]
#[command(name = "ssproxyd", about = "Embeddable SSH TCP-proxy daemon")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:2222")]
    listen: String,
    /// user:password, repeatable (default proxy:proxy).
    #[arg(short, long)]
    user: Vec<String>,
    /// Ed25519 host key seed file (created if missing).
    #[arg(long, default_value = "ssproxy_host_ed25519")]
    host_key: std::path::PathBuf,
    #[arg(long, default_value = "SSH-2.0-OpenSSH_9.6")]
    ident: String,
}

fn load_host_key(path: &std::path::Path) -> HostKey {
    if let Ok(hex) = std::fs::read_to_string(path) {
        if let Ok(bytes) = decode_hex(hex.trim()) {
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return HostKey::from_seed(&seed);
            }
        }
    }
    let key = HostKey::generate();
    let seed = key.seed().expect("generated host key is ed25519");
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::write(path, hex);
    key
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let mut users: HashMap<String, String> = HashMap::new();
    if args.user.is_empty() {
        users.insert("proxy".into(), "proxy".into());
    } else {
        for u in &args.user {
            let (n, p) = u.split_once(':').unwrap_or((u.as_str(), ""));
            users.insert(n.into(), p.into());
        }
    }
    let users = Arc::new(users);

    let host_key = load_host_key(&args.host_key);
    log::info!("host key: {}", host_key.openssh_public_line("ssproxyd"));
    let mut cfg = ServerConfig::new(host_key);
    cfg.base.ident = args.ident;
    cfg.methods.publickey = false;
    let cfg = Arc::new(cfg);

    let listener = TcpListener::bind(&args.listen).await.expect("bind");
    log::info!("listening on {}", args.listen);

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("accept: {e}");
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let cfg = cfg.clone();
        let users = users.clone();
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let up = users.clone();
            let hooks = Hooks {
                auth_password: Box::new(move |user, pw| {
                    if up.get(user).map(|s| s == pw).unwrap_or(false) {
                        AuthOutcome::Accept
                    } else {
                        AuthOutcome::Reject { delay: Duration::from_secs(1) }
                    }
                }),
                open: Box::new(|_, _, _| OpenOutcome::Accept),
                ..Hooks::default()
            };
            tokio::spawn(async move {
                while let Some(ch) = rx.recv().await {
                    tokio::spawn(relay(ch));
                }
            });
            if let Err(e) = driver::serve(sock, cfg, hooks, tx).await {
                log::debug!("session {peer} ended: {e}");
            }
        });
    }
}

async fn relay(ch: driver::IncomingChannel) {
    let target = format!("{}:{}", ch.host, ch.port);
    let mut stream = ch.stream;
    match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(&target)).await {
        Ok(Ok(mut up)) => {
            let _ = up.set_nodelay(true);
            let _ = copy_bidirectional(&mut stream, &mut up).await;
        }
        Ok(Err(e)) => {
            log::debug!("connect {target}: {e}");
            let _ = stream.shutdown().await;
        }
        Err(_) => {
            log::debug!("connect {target}: timed out");
            let _ = stream.shutdown().await;
        }
    }
}
