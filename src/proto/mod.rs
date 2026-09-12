pub mod msg;

pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub const SSH_MSG_DEBUG: u8 = 4;
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub const SSH_MSG_EXT_INFO: u8 = 7;
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;
pub const SSH_MSG_PING: u8 = 192;
pub const SSH_MSG_PONG: u8 = 193;

pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
pub const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
pub const SSH_DISCONNECT_MAC_ERROR: u32 = 5;
pub const SSH_DISCONNECT_COMPRESSION_ERROR: u32 = 6;
pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u32 = 9;
pub const SSH_DISCONNECT_CONNECTION_LOST: u32 = 10;
pub const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 12;
pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;
pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u32 = 15;

pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

pub const KEX_STRICT_C: &str = "kex-strict-c-v00@openssh.com";
pub const KEX_STRICT_S: &str = "kex-strict-s-v00@openssh.com";
pub const EXT_INFO_C: &str = "ext-info-c";
pub const EXT_INFO_S: &str = "ext-info-s";

pub fn is_kex_msg(t: u8) -> bool {
    matches!(t, SSH_MSG_KEXINIT | SSH_MSG_NEWKEYS | 30..=49)
}

pub fn is_transport_ignore(t: u8) -> bool {
    matches!(t, SSH_MSG_IGNORE | SSH_MSG_DEBUG | SSH_MSG_UNIMPLEMENTED)
}
