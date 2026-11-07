use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol(&'static str),
    ProtocolFmt(String),
    Crypto(&'static str),
    /// Authentication failed (client role) or too many failures (server role).
    Auth,
    /// Peer sent SSH_MSG_DISCONNECT.
    Disconnect { reason: u32, message: String },
    /// Channel open refused by the peer.
    OpenFailed { reason: u32, message: String },
    /// Transport closed by the peer.
    Closed,
    /// A session timer fired (preauth, idle, keepalive, kex).
    TimedOut(&'static str),
    /// Local shutdown requested through the session handle.
    Shutdown,
}

impl Error {
    pub fn protocol(msg: &'static str) -> Self {
        Self::Protocol(msg)
    }

    pub fn proto_fmt(msg: impl Into<String>) -> Self {
        Self::ProtocolFmt(msg.into())
    }

    /// `true` for endings that are normal operation rather than faults.
    pub fn is_benign(&self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Shutdown | Self::Disconnect { .. } | Self::TimedOut("idle")
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::ProtocolFmt(m) => write!(f, "protocol: {m}"),
            Self::Crypto(m) => write!(f, "crypto: {m}"),
            Self::Auth => write!(f, "authentication failed"),
            Self::Disconnect { reason, message } => {
                write!(f, "disconnect ({reason}): {message}")
            }
            Self::OpenFailed { reason, message } => {
                write!(f, "channel open failed ({reason}): {message}")
            }
            Self::Closed => write!(f, "connection closed"),
            Self::TimedOut(what) => write!(f, "{what} timeout"),
            Self::Shutdown => write!(f, "shutdown"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
