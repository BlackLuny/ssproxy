use std::time::Duration;

use crate::crypto::{CipherKind, MacKind};
use crate::hostkey::HostKey;
use crate::kex::KexAlgo;

/// Offered algorithms, in preference order.
#[derive(Clone, Debug)]
pub struct Algorithms {
    pub kex: Vec<KexAlgo>,
    pub ciphers: Vec<CipherKind>,
    pub macs: Vec<MacKind>,
}

impl Algorithms {
    /// Order modelled on OpenSSH 9.x/10.x defaults, minus what we don't
    /// implement (sntrup, DH groups, umac, sha1).
    pub fn openssh_like() -> Self {
        let mut kex = Vec::new();
        #[cfg(feature = "mlkem")]
        kex.push(KexAlgo::MlKem768X25519Sha256);
        kex.push(KexAlgo::Curve25519Sha256);
        kex.push(KexAlgo::Curve25519Sha256Libssh);
        #[cfg(feature = "ecdh")]
        kex.extend([
            KexAlgo::EcdhSha2NistP256,
            KexAlgo::EcdhSha2NistP384,
            KexAlgo::EcdhSha2NistP521,
        ]);
        Self {
            kex,
            ciphers: vec![
                CipherKind::ChaCha20Poly1305,
                CipherKind::Aes128Ctr,
                CipherKind::Aes192Ctr,
                CipherKind::Aes256Ctr,
                CipherKind::Aes128Gcm,
                CipherKind::Aes256Gcm,
            ],
            macs: vec![
                MacKind::HmacSha256Etm,
                MacKind::HmacSha512Etm,
                MacKind::HmacSha256,
                MacKind::HmacSha512,
            ],
        }
    }

    /// AEAD-only, fastest-first.
    pub fn performance() -> Self {
        let mut a = Self::openssh_like();
        a.ciphers = vec![
            CipherKind::Aes128Gcm,
            CipherKind::Aes256Gcm,
            CipherKind::ChaCha20Poly1305,
            CipherKind::Aes128Ctr,
            CipherKind::Aes256Ctr,
        ];
        a
    }
}

impl Default for Algorithms {
    fn default() -> Self {
        Self::openssh_like()
    }
}

/// Transport, flow-control and timer settings shared by both roles.
#[derive(Clone, Debug)]
pub struct Config {
    /// Identification string without CRLF, e.g. `SSH-2.0-OpenSSH_9.6`.
    pub ident: String,
    pub algorithms: Algorithms,
    /// Largest CHANNEL_DATA payload we accept (advertised maximum packet).
    pub max_packet: u32,
    /// Initial per-channel receive window.
    pub window_initial: u32,
    /// Ceiling on a channel's receive window: the advertised window is
    /// `min(window_initial, window_max)`. It is fixed for the channel's life —
    /// window credit is replenished, never grown, so this is a hard cap on the
    /// bytes one channel may keep in flight.
    pub window_max: u32,
    /// Sum of all channel windows in one session may not exceed this.
    pub window_budget: u64,
    pub max_channels: u32,
    /// Bytes a `ChannelStream` writer may buffer before `poll_write` pends.
    pub channel_tx_cap: usize,
    /// Stop sealing channel data while this many bytes wait for the socket.
    pub out_soft: usize,
    /// Stop reading from the peer while this many bytes wait for the socket.
    pub out_hard: usize,
    /// Initiate rekey after this many transport bytes (server role only).
    pub rekey_bytes: u64,
    pub rekey_interval: Option<Duration>,
    /// Abort when a key exchange does not finish in time.
    pub kex_timeout: Duration,
    /// Close unauthenticated connections after this long.
    pub auth_timeout: Option<Duration>,
    pub max_auth_attempts: u32,
    /// Close authenticated sessions that have had no channel for this long.
    pub idle_timeout: Option<Duration>,
    /// Send `keepalive@openssh.com` after this much inbound silence.
    pub keepalive_interval: Option<Duration>,
    /// Close after this many unanswered keepalives.
    pub keepalive_max: u32,
    /// How long a closing session keeps flushing queued output.
    pub linger: Duration,
    /// Send our KEXINIT before the peer identification arrives.
    pub early_kexinit: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ident: "SSH-2.0-OpenSSH_9.6".into(),
            algorithms: Algorithms::default(),
            max_packet: 32 * 1024,
            window_initial: 1024 * 1024,
            window_max: 16 * 1024 * 1024,
            window_budget: 64 * 1024 * 1024,
            max_channels: 4096,
            channel_tx_cap: 64 * 1024,
            out_soft: 256 * 1024,
            out_hard: 4 * 1024 * 1024,
            rekey_bytes: 1 << 30,
            rekey_interval: Some(Duration::from_secs(3600)),
            kex_timeout: Duration::from_secs(60),
            auth_timeout: Some(Duration::from_secs(120)),
            max_auth_attempts: 6,
            idle_timeout: None,
            keepalive_interval: Some(Duration::from_secs(60)),
            keepalive_max: 3,
            linger: Duration::from_secs(2),
            early_kexinit: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AuthMethods {
    pub password: bool,
    pub publickey: bool,
}

impl AuthMethods {
    pub fn namelist(&self) -> &'static str {
        match (self.publickey && cfg!(feature = "pubkey"), self.password) {
            (true, true) => "publickey,password",
            (true, false) => "publickey",
            (false, true) => "password",
            (false, false) => "",
        }
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    pub base: Config,
    pub host_key: HostKey,
    pub methods: AuthMethods,
    /// Accept `session` channels (their requests are always refused).
    pub accept_session_channels: bool,
}

impl ServerConfig {
    pub fn new(host_key: HostKey) -> Self {
        Self {
            base: Config::default(),
            host_key,
            methods: AuthMethods {
                password: true,
                publickey: true,
            },
            accept_session_channels: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub base: Config,
    pub user: String,
    pub password: String,
}

impl ClientConfig {
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        let base = Config {
            ident: "SSH-2.0-ssproxy".into(),
            early_kexinit: true,
            auth_timeout: None,
            ..Config::default()
        };
        Self {
            base,
            user: user.into(),
            password: password.into(),
        }
    }
}
