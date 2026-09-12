use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use ssproxy::config::{load_or_create_host_key, ServerConfig, User};
use ssproxy::server::serve;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "ssproxyd", about = "High-performance SSH TCP-proxy daemon")]
struct Args {
    /// Listen address.
    #[arg(short, long, default_value = "0.0.0.0:2222")]
    listen: String,

    /// User in the form name:password. Repeatable. Default: proxy:proxy
    #[arg(short, long)]
    user: Vec<String>,

    /// Host key path (created if missing).
    #[arg(long, default_value = "ssproxy_host_ed25519")]
    host_key: PathBuf,

    /// Identification string sent to clients (banner / masquerade).
    #[arg(long, default_value = "SSH-2.0-OpenSSH_9.6")]
    ident: String,

    /// Initial channel window (bytes).
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    window: u32,

    /// Max SSH channel packet (bytes). Smaller reduces HOL latency.
    #[arg(long, default_value_t = 32 * 1024)]
    max_packet: u32,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ssproxy=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let users = if args.user.is_empty() {
        tracing::warn!("no --user, defaulting to proxy:proxy");
        vec![User {
            name: "proxy".into(),
            password: "proxy".into(),
        }]
    } else {
        args.user
            .iter()
            .map(|s| {
                let (n, p) = s.split_once(':').unwrap_or((s.as_str(), ""));
                User {
                    name: n.into(),
                    password: p.into(),
                }
            })
            .collect()
    };

    let host_key = load_or_create_host_key(&args.host_key).expect("host key");
    tracing::info!(
        "host key fingerprint line: {}",
        host_key.openssh_public_line("ssproxyd")
    );

    let mut cfg = ServerConfig::new(host_key, users);
    cfg.ident = args.ident;
    cfg.window = args.window;
    cfg.max_packet = args.max_packet;

    let listener = TcpListener::bind(&args.listen).await.expect("bind");
    tracing::info!("listening on {}", args.listen);
    let cfg = Arc::new(cfg);

    tokio::select! {
        r = serve(listener, cfg) => {
            if let Err(e) = r {
                tracing::error!("serve: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown");
        }
    }
}
