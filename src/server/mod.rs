mod session;

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::ServerConfig;
use crate::error::Result;

pub use session::Session;

pub async fn serve(listener: TcpListener, cfg: Arc<ServerConfig>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "accept");
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = Session::new(stream, cfg).await {
                tracing::debug!("session ended: {e}");
            }
        });
    }
}
