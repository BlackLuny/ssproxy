//! Embeddable SSH server/client with a sans-IO protocol core.
//!
//! The protocol state machine ([`core::Connection`]) does no I/O and no
//! `.await`: feed it bytes with [`core::Connection::process_in`], pull sealed
//! bytes with [`core::Connection::peek_out`]. [`driver`] is the Tokio adapter
//! that drives it over a stream and hands each `direct-tcpip` channel to the
//! embedder as a [`stream::ChannelStream`].
//!
//! ```no_run
//! use std::sync::Arc;
//! use ssproxy::{driver, config::ServerConfig, hostkey::HostKey};
//! # async fn run(tcp: tokio::net::TcpStream) -> ssproxy::Result<()> {
//! let cfg = Arc::new(ServerConfig::new(HostKey::generate()));
//! let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<driver::IncomingChannel>();
//! let mut hooks = driver::Hooks::default();
//! hooks.auth_password = Box::new(|user, pw| {
//!     if user == "proxy" && pw == "proxy" { driver::AuthOutcome::Accept }
//!     else { driver::AuthOutcome::Reject { delay: std::time::Duration::from_secs(2) } }
//! });
//! tokio::spawn(async move {
//!     while let Some(ch) = rx.recv().await {
//!         // ch.stream is AsyncRead + AsyncWrite; relay it to ch.host:ch.port.
//!         let _ = (ch.host, ch.port, ch.stream);
//!     }
//! });
//! driver::serve(tcp, cfg, hooks, tx).await
//! # }
//! ```

pub mod config;
pub mod core;
pub mod crypto;
pub mod driver;
pub mod error;
pub mod hostkey;
pub mod kex;
pub mod proto;
pub mod pubkey;
pub mod stream;
pub mod wire;

pub use config::{ClientConfig, Config, ServerConfig};
pub use core::{Connection, Event, Role};
pub use driver::{serve, AuthOutcome, Hooks, IncomingChannel, OpenOutcome, SessionHandle};
pub use error::{Error, Result};
pub use hostkey::HostKey;
pub use stream::ChannelStream;
