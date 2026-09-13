use crate::error::{Error, Result};
use crate::proto::SSH_MSG_KEXINIT;
use crate::wire::{self, Parser};

/// Parsed peer KEXINIT. Name-lists borrow from `raw`.
pub struct KexInit {
    pub raw: Vec<u8>,
    lists: [(usize, usize); 10],
    pub first_kex_packet_follows: bool,
}

pub const L_KEX: usize = 0;
pub const L_HOSTKEY: usize = 1;
pub const L_ENC_C2S: usize = 2;
pub const L_ENC_S2C: usize = 3;
pub const L_MAC_C2S: usize = 4;
pub const L_MAC_S2C: usize = 5;
pub const L_COMP_C2S: usize = 6;
pub const L_COMP_S2C: usize = 7;

impl KexInit {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut p = Parser::new(payload);
        if p.u8()? != SSH_MSG_KEXINIT {
            return Err(Error::protocol("not kexinit"));
        }
        p.take(16)?;
        let mut lists = [(0usize, 0usize); 10];
        for slot in lists.iter_mut() {
            let s = p.bytes()?;
            std::str::from_utf8(s).map_err(|_| Error::protocol("kexinit utf8"))?;
            let end = p.offset();
            *slot = (end - s.len(), end);
        }
        let first_kex_packet_follows = p.bool()?;
        p.u32()?;
        Ok(Self {
            raw: payload.to_vec(),
            lists,
            first_kex_packet_follows,
        })
    }

    pub fn list(&self, idx: usize) -> &str {
        let (a, b) = self.lists[idx];
        // Validated as UTF-8 in parse().
        std::str::from_utf8(&self.raw[a..b]).unwrap_or("")
    }

    pub fn has(&self, idx: usize, name: &str) -> bool {
        wire::names(self.list(idx)).any(|n| n == name)
    }

    pub fn first(&self, idx: usize) -> Option<&str> {
        wire::names(self.list(idx)).next()
    }
}

/// Build a KEXINIT payload from name-lists.
pub fn build_kexinit(
    cookie: [u8; 16],
    kex: &[&str],
    hostkey: &[&str],
    ciphers: &[&str],
    macs: &[&str],
) -> Vec<u8> {
    let mut raw = Vec::with_capacity(512);
    raw.push(SSH_MSG_KEXINIT);
    raw.extend_from_slice(&cookie);
    wire::put_namelist(&mut raw, kex);
    wire::put_namelist(&mut raw, hostkey);
    wire::put_namelist(&mut raw, ciphers);
    wire::put_namelist(&mut raw, ciphers);
    wire::put_namelist(&mut raw, macs);
    wire::put_namelist(&mut raw, macs);
    wire::put_namelist(&mut raw, &["none"]);
    wire::put_namelist(&mut raw, &["none"]);
    wire::put_namelist::<&str>(&mut raw, &[]);
    wire::put_namelist::<&str>(&mut raw, &[]);
    wire::put_bool(&mut raw, false);
    wire::put_u32(&mut raw, 0);
    raw
}

/// RFC 4253 §7.1: first entry of the *client* list also on the server list.
pub fn negotiate<'a>(client: &'a str, server: &str) -> Option<&'a str> {
    wire::names(client).find(|c| wire::names(server).any(|s| s == *c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip_and_client_preference() {
        let raw = build_kexinit([1; 16], &["a", "b"], &["ssh-ed25519"], &["x", "y"], &["m"]);
        let k = KexInit::parse(&raw).unwrap();
        assert_eq!(k.list(L_KEX), "a,b");
        assert_eq!(k.list(L_ENC_S2C), "x,y");
        assert!(k.has(L_HOSTKEY, "ssh-ed25519"));
        assert!(!k.first_kex_packet_follows);
        assert_eq!(negotiate("y,x", "x,y"), Some("y"));
        assert_eq!(negotiate("z", "x,y"), None);
    }
}
