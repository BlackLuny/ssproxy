//! High-performance sans-IO SSH TCP proxy (`ssproxyd`).
//!
//! The protocol core (`core::Connection`) is a rustls-style state machine:
//! feed bytes in, pull bytes out. No `.await` in the core. The server adapter
//! implements `Future::poll` directly and proxies `direct-tcpip` channels.

pub mod config;
pub mod core;
pub mod crypto;
pub mod error;
pub mod proto;
pub mod server;
pub mod wire;

pub use config::{ClientConfig, ServerConfig, User};
pub use core::{Connection, Event, Role};
pub use error::{Error, Result};
pub use server::{serve, Session};
