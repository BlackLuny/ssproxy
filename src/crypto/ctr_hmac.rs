use aes::{Aes128, Aes192, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::crypto::CipherKind;
use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacKind {
    HmacSha256,
    HmacSha512,
    HmacSha256Etm,
    HmacSha512Etm,
}

impl MacKind {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "hmac-sha2-256" => Self::HmacSha256,
            "hmac-sha2-512" => Self::HmacSha512,
            "hmac-sha2-256-etm@openssh.com" => Self::HmacSha256Etm,
            "hmac-sha2-512-etm@openssh.com" => Self::HmacSha512Etm,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha2-256",
            Self::HmacSha512 => "hmac-sha2-512",
            Self::HmacSha256Etm => "hmac-sha2-256-etm@openssh.com",
            Self::HmacSha512Etm => "hmac-sha2-512-etm@openssh.com",
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::HmacSha256 | Self::HmacSha256Etm => 32,
            Self::HmacSha512 | Self::HmacSha512Etm => 64,
        }
    }

    pub fn etm(self) -> bool {
        matches!(self, Self::HmacSha256Etm | Self::HmacSha512Etm)
    }
}

enum Stream {
    A128(Ctr128BE<Aes128>),
    A192(Ctr128BE<Aes192>),
    A256(Ctr128BE<Aes256>),
}

impl Stream {
    #[inline]
    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::A128(c) => c.apply_keystream(data),
            Self::A192(c) => c.apply_keystream(data),
            Self::A256(c) => c.apply_keystream(data),
        }
    }
}

enum Keyed {
    S256(Hmac<Sha256>),
    S512(Hmac<Sha512>),
}

/// `aes*-ctr` with `hmac-sha2-*` (classic or encrypt-then-MAC).
pub struct CtrHmac {
    stream: Stream,
    mac: Keyed,
    kind: MacKind,
    /// Non-ETM receive: bytes of the current packet already decrypted by
    /// `decrypt_head`.
    head_done: usize,
}

impl CtrHmac {
    pub fn new(cipher: CipherKind, mac: MacKind, key: &[u8], iv: &[u8], mac_key: &[u8]) -> Result<Self> {
        let bad = |_| Error::Crypto("ctr key/iv");
        let stream = match cipher {
            CipherKind::Aes128Ctr => Stream::A128(Ctr128BE::new_from_slices(key, iv).map_err(bad)?),
            CipherKind::Aes192Ctr => Stream::A192(Ctr128BE::new_from_slices(key, iv).map_err(bad)?),
            CipherKind::Aes256Ctr => Stream::A256(Ctr128BE::new_from_slices(key, iv).map_err(bad)?),
            _ => return Err(Error::Crypto("not ctr")),
        };
        let mac_state = match mac {
            MacKind::HmacSha256 | MacKind::HmacSha256Etm => Keyed::S256(
                Hmac::new_from_slice(mac_key).map_err(|_| Error::Crypto("mac key"))?,
            ),
            MacKind::HmacSha512 | MacKind::HmacSha512Etm => Keyed::S512(
                Hmac::new_from_slice(mac_key).map_err(|_| Error::Crypto("mac key"))?,
            ),
        };
        Ok(Self {
            stream,
            mac: mac_state,
            kind: mac,
            head_done: 0,
        })
    }

    pub fn etm(&self) -> bool {
        self.kind.etm()
    }

    pub fn mac_len(&self) -> usize {
        self.kind.key_len()
    }

    fn compute(&self, seq: u32, data: &[u8], out: &mut [u8]) {
        match &self.mac {
            Keyed::S256(m) => {
                let mut m = m.clone();
                m.update(&seq.to_be_bytes());
                m.update(data);
                out[..32].copy_from_slice(&m.finalize().into_bytes());
            }
            Keyed::S512(m) => {
                let mut m = m.clone();
                m.update(&seq.to_be_bytes());
                m.update(data);
                out[..64].copy_from_slice(&m.finalize().into_bytes());
            }
        }
    }

    fn verify(&self, seq: u32, data: &[u8], tag: &[u8]) -> Result<()> {
        let ok = match &self.mac {
            Keyed::S256(m) => {
                let mut m = m.clone();
                m.update(&seq.to_be_bytes());
                m.update(data);
                m.verify_slice(tag).is_ok()
            }
            Keyed::S512(m) => {
                let mut m = m.clone();
                m.update(&seq.to_be_bytes());
                m.update(data);
                m.verify_slice(tag).is_ok()
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::Crypto("mac"))
        }
    }

    /// Non-ETM: decrypt the first cipher block so the length is readable.
    pub fn decrypt_head(&mut self, head: &mut [u8]) {
        self.stream.apply(head);
        self.head_done = head.len();
    }

    pub fn seal(&mut self, seq: u32, pkt: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        if self.kind.etm() {
            self.stream.apply(&mut pkt[4..]);
            self.compute(seq, pkt, tag_out);
        } else {
            self.compute(seq, pkt, tag_out);
            self.stream.apply(pkt);
        }
        Ok(())
    }

    pub fn open(&mut self, seq: u32, pkt: &mut [u8], tag: &[u8]) -> Result<()> {
        if self.kind.etm() {
            self.verify(seq, pkt, tag)?;
            self.stream.apply(&mut pkt[4..]);
            Ok(())
        } else {
            let done = std::mem::take(&mut self.head_done);
            self.stream.apply(&mut pkt[done..]);
            self.verify(seq, pkt, tag)
        }
    }
}
