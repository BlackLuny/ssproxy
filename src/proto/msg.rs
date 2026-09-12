use rand::RngCore;

use crate::proto::{EXT_INFO_C, EXT_INFO_S, KEX_STRICT_C, KEX_STRICT_S, SSH_MSG_KEXINIT};
use crate::wire::{self, Parser};

pub const SERVER_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    EXT_INFO_S,
    KEX_STRICT_S,
];

pub const SERVER_HOST_KEY: &[&str] = &["ssh-ed25519"];

pub const SERVER_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
];

pub const SERVER_MACS: &[&str] = &["hmac-sha2-256", "hmac-sha2-512"];
pub const SERVER_COMP: &[&str] = &["none"];

pub const CLIENT_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    EXT_INFO_C,
    KEX_STRICT_C,
];

#[derive(Clone, Debug)]
pub struct KexInit {
    pub cookie: [u8; 16],
    pub kex: Vec<String>,
    pub host_key: Vec<String>,
    pub enc_c2s: Vec<String>,
    pub enc_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub comp_c2s: Vec<String>,
    pub comp_s2c: Vec<String>,
    pub lang_c2s: Vec<String>,
    pub lang_s2c: Vec<String>,
    pub first_kex_packet_follows: bool,
    /// Full payload including the SSH_MSG_KEXINIT byte (used in exchange hash).
    pub raw: Vec<u8>,
}

impl KexInit {
    pub fn build(kex: &[&str], host: &[&str], ciphers: &[&str], macs: &[&str]) -> Self {
        let mut cookie = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut cookie);
        let mut raw = Vec::with_capacity(256);
        raw.push(SSH_MSG_KEXINIT);
        raw.extend_from_slice(&cookie);
        wire::put_namelist(&mut raw, kex);
        wire::put_namelist(&mut raw, host);
        wire::put_namelist(&mut raw, ciphers);
        wire::put_namelist(&mut raw, ciphers);
        wire::put_namelist(&mut raw, macs);
        wire::put_namelist(&mut raw, macs);
        wire::put_namelist(&mut raw, SERVER_COMP);
        wire::put_namelist(&mut raw, SERVER_COMP);
        wire::put_namelist(&mut raw, &[]);
        wire::put_namelist(&mut raw, &[]);
        wire::put_bool(&mut raw, false);
        wire::put_u32(&mut raw, 0);
        Self {
            cookie,
            kex: kex.iter().map(|s| (*s).to_string()).collect(),
            host_key: host.iter().map(|s| (*s).to_string()).collect(),
            enc_c2s: ciphers.iter().map(|s| (*s).to_string()).collect(),
            enc_s2c: ciphers.iter().map(|s| (*s).to_string()).collect(),
            mac_c2s: macs.iter().map(|s| (*s).to_string()).collect(),
            mac_s2c: macs.iter().map(|s| (*s).to_string()).collect(),
            comp_c2s: vec!["none".into()],
            comp_s2c: vec!["none".into()],
            lang_c2s: vec![],
            lang_s2c: vec![],
            first_kex_packet_follows: false,
            raw,
        }
    }

    pub fn parse(payload: &[u8]) -> crate::error::Result<Self> {
        let mut p = Parser::new(payload);
        if p.u8()? != SSH_MSG_KEXINIT {
            return Err(crate::error::Error::protocol("not kexinit"));
        }
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(p.take(16)?);
        let to_owned = |v: Vec<&str>| v.into_iter().map(|s| s.to_string()).collect();
        Ok(Self {
            cookie,
            kex: to_owned(p.namelist()?),
            host_key: to_owned(p.namelist()?),
            enc_c2s: to_owned(p.namelist()?),
            enc_s2c: to_owned(p.namelist()?),
            mac_c2s: to_owned(p.namelist()?),
            mac_s2c: to_owned(p.namelist()?),
            comp_c2s: to_owned(p.namelist()?),
            comp_s2c: to_owned(p.namelist()?),
            lang_c2s: to_owned(p.namelist()?),
            lang_s2c: to_owned(p.namelist()?),
            first_kex_packet_follows: p.bool()?,
            raw: payload.to_vec(),
        })
    }
}

pub fn negotiate(server: &[&str], client: &[String], skip_ext: bool) -> Option<String> {
    for s in server {
        if skip_ext
            && (*s == EXT_INFO_C || *s == EXT_INFO_S || *s == KEX_STRICT_C || *s == KEX_STRICT_S)
        {
            continue;
        }
        if client.iter().any(|c| c == s) {
            return Some((*s).to_string());
        }
    }
    None
}

pub fn list_has(list: &[String], name: &str) -> bool {
    list.iter().any(|s| s == name)
}
