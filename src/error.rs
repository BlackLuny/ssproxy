use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol(&'static str),
    ProtocolFmt(String),
    Crypto(&'static str),
    Auth,
    Disconnect { reason: u32, message: String },
    Closed,
    TimedOut,
}

impl Error {
    pub fn protocol(msg: &'static str) -> Self {
        Self::Protocol(msg)
    }

    pub fn proto_fmt(msg: impl Into<String>) -> Self {
        Self::ProtocolFmt(msg.into())
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
            Self::Closed => write!(f, "connection closed"),
            Self::TimedOut => write!(f, "timed out"),
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
