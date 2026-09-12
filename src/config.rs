use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::HostKey;
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct User {
    pub name: String,
    pub password: String,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub ident: String,
    pub host_key: Arc<HostKey>,
    pub users: Arc<Vec<User>>,
    pub window: u32,
    pub max_packet: u32,
    pub max_channels: u32,
    pub max_auth_fails: u32,
    pub rekey_after_bytes: u64,
    pub rekey_after_packets: u32,
    pub keepalive: Duration,
    pub connect_timeout: Duration,
    pub write_buf_soft: usize,
    pub write_buf_hard: usize,
}

impl ServerConfig {
    pub fn new(host_key: HostKey, users: Vec<User>) -> Self {
        Self {
            ident: "SSH-2.0-OpenSSH_9.6".into(),
            host_key: Arc::new(host_key),
            users: Arc::new(users),
            window: 2 * 1024 * 1024,
            max_packet: 32 * 1024,
            max_channels: 256,
            max_auth_fails: 3,
            rekey_after_bytes: 1024 * 1024 * 1024,
            rekey_after_packets: (1u32 << 31) - 1,
            keepalive: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(15),
            write_buf_soft: 256 * 1024,
            write_buf_hard: 1024 * 1024,
        }
    }

    pub fn test_config() -> Self {
        Self::new(
            HostKey::generate(),
            vec![User {
                name: "proxy".into(),
                password: "proxy".into(),
            }],
        )
    }

    pub fn check_password(&self, user: &str, password: &str) -> bool {
        use subtle::ConstantTimeEq;
        let mut ok = false;
        for u in self.users.iter() {
            let user_match = u.name.as_bytes().ct_eq(user.as_bytes()).unwrap_u8() == 1;
            let pw_match = u.password.as_bytes().ct_eq(password.as_bytes()).unwrap_u8() == 1;
            ok |= user_match && pw_match;
        }
        ok
    }
}

pub fn load_or_create_host_key(path: &Path) -> Result<HostKey> {
    if path.exists() {
        load_host_key(path)
    } else {
        let key = HostKey::generate();
        save_host_key(path, &key)?;
        let pub_path = public_path(path);
        let _ = std::fs::write(
            &pub_path,
            format!("{}\n", key.openssh_public_line("ssproxyd")),
        );
        Ok(key)
    }
}

fn public_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".pub");
    PathBuf::from(p)
}

pub fn save_host_key(path: &Path, key: &HostKey) -> Result<()> {
    let seed = key.seed();
    let mut hex = String::with_capacity(64);
    for b in seed {
        hex.push_str(&format!("{b:02x}"));
    }
    let body = format!("ssproxy-ed25519-seed-v1\n{hex}\n");
    std::fs::write(path, body).map_err(Error::from)
}

pub fn load_host_key(path: &Path) -> Result<HostKey> {
    let text = std::fs::read_to_string(path)?;
    parse_host_key(&text)
}

fn parse_host_key(text: &str) -> Result<HostKey> {
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("");
    if header.trim() != "ssproxy-ed25519-seed-v1" {
        return Err(Error::protocol("unsupported host key format"));
    }
    let hex = lines.next().unwrap_or("").trim();
    if hex.len() != 64 {
        return Err(Error::protocol("bad host key seed"));
    }
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::protocol("bad host key hex"))?;
    }
    Ok(HostKey::from_seed(&seed))
}

#[derive(Clone)]
pub struct ClientConfig {
    pub ident: String,
    pub username: String,
    pub password: String,
    pub window: u32,
    pub max_packet: u32,
    pub write_buf_soft: usize,
    pub write_buf_hard: usize,
    pub rekey_after_bytes: u64,
    pub rekey_after_packets: u32,
}

impl ClientConfig {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            ident: "SSH-2.0-ssproxy_client_0.1".into(),
            username: username.into(),
            password: password.into(),
            window: 2 * 1024 * 1024,
            max_packet: 32 * 1024,
            write_buf_soft: 256 * 1024,
            write_buf_hard: 1024 * 1024,
            rekey_after_bytes: 1024 * 1024 * 1024,
            rekey_after_packets: (1u32 << 31) - 1,
        }
    }
}
