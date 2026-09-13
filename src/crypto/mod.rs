mod aesgcm;
mod chacha20poly1305;
mod ctr_hmac;
pub mod kdf;

use crate::error::{Error, Result};

pub use aesgcm::AesGcmSsh;
pub use chacha20poly1305::ChaCha20Poly1305Ssh;
pub use ctr_hmac::{CtrHmac, MacKind};
pub use kdf::HashAlg;

/// Largest packet (`packet_length` field) we accept or produce.
pub const MAX_PACKET: usize = 256 * 1024;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    Clear,
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
}

impl CipherKind {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "chacha20-poly1305@openssh.com" => Self::ChaCha20Poly1305,
            "aes128-gcm@openssh.com" => Self::Aes128Gcm,
            "aes256-gcm@openssh.com" => Self::Aes256Gcm,
            "aes128-ctr" => Self::Aes128Ctr,
            "aes192-ctr" => Self::Aes192Ctr,
            "aes256-ctr" => Self::Aes256Ctr,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Clear => "none",
            Self::ChaCha20Poly1305 => "chacha20-poly1305@openssh.com",
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
            Self::Aes256Gcm => "aes256-gcm@openssh.com",
            Self::Aes128Ctr => "aes128-ctr",
            Self::Aes192Ctr => "aes192-ctr",
            Self::Aes256Ctr => "aes256-ctr",
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Clear => 0,
            Self::ChaCha20Poly1305 => 64,
            Self::Aes128Gcm | Self::Aes128Ctr => 16,
            Self::Aes192Ctr => 24,
            Self::Aes256Gcm | Self::Aes256Ctr => 32,
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            Self::Clear | Self::ChaCha20Poly1305 => 0,
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
            Self::Aes128Ctr | Self::Aes192Ctr | Self::Aes256Ctr => 16,
        }
    }

    /// AEAD ciphers ignore the negotiated MAC.
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Self::ChaCha20Poly1305 | Self::Aes128Gcm | Self::Aes256Gcm
        )
    }
}

/// Keys for one direction of the transport.
#[allow(clippy::large_enum_variant)]
pub enum DirectionKeys {
    Clear,
    ChaCha(ChaCha20Poly1305Ssh),
    Gcm(AesGcmSsh),
    Ctr(Box<CtrHmac>),
}

impl DirectionKeys {
    pub fn new(
        kind: CipherKind,
        mac: Option<MacKind>,
        key: &[u8],
        iv: &[u8],
        mac_key: &[u8],
    ) -> Result<Self> {
        Ok(match kind {
            CipherKind::Clear => Self::Clear,
            CipherKind::ChaCha20Poly1305 => {
                let k: &[u8; 64] = key.try_into().map_err(|_| Error::Crypto("chacha key"))?;
                Self::ChaCha(ChaCha20Poly1305Ssh::new(k))
            }
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
                Self::Gcm(AesGcmSsh::new(kind, key, iv)?)
            }
            CipherKind::Aes128Ctr | CipherKind::Aes192Ctr | CipherKind::Aes256Ctr => {
                let mac = mac.ok_or(Error::Crypto("ctr without mac"))?;
                Self::Ctr(Box::new(CtrHmac::new(kind, mac, key, iv, mac_key)?))
            }
        })
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::Clear | Self::ChaCha(_) => 8,
            Self::Gcm(_) | Self::Ctr(_) => 16,
        }
    }

    pub fn tag_len(&self) -> usize {
        match self {
            Self::Clear => 0,
            Self::ChaCha(_) | Self::Gcm(_) => TAG_LEN,
            Self::Ctr(c) => c.mac_len(),
        }
    }

    /// Whether the 4-byte length field is outside the padding alignment.
    pub fn length_is_aad(&self) -> bool {
        match self {
            Self::Clear => false,
            Self::ChaCha(_) | Self::Gcm(_) => true,
            Self::Ctr(c) => c.etm(),
        }
    }

    /// Bytes needed before the packet length can be determined.
    pub fn head_len(&self) -> usize {
        match self {
            Self::Ctr(c) if !c.etm() => 16,
            _ => 4,
        }
    }

    /// Recover `packet_length` from the first `head_len()` bytes.
    ///
    /// For CTR without ETM this decrypts the head in place and advances the
    /// keystream; the caller must not call it twice for the same packet.
    pub fn read_length(&mut self, seq: u32, head: &mut [u8]) -> Result<u32> {
        let mut len = [head[0], head[1], head[2], head[3]];
        match self {
            Self::Clear | Self::Gcm(_) => {}
            Self::ChaCha(c) => len = c.decrypt_length(seq, len),
            Self::Ctr(c) => {
                if !c.etm() {
                    c.decrypt_head(head);
                    len = [head[0], head[1], head[2], head[3]];
                }
            }
        }
        Ok(u32::from_be_bytes(len))
    }

    /// Authenticate and decrypt `pkt` (`length || padlen || payload || pad`) in
    /// place. On return the length field is plaintext.
    pub fn open(&mut self, seq: u32, pkt: &mut [u8], tag: &[u8]) -> Result<()> {
        match self {
            Self::Clear => Ok(()),
            Self::ChaCha(c) => c.open(seq, pkt, tag),
            Self::Gcm(c) => c.open(seq, pkt, tag),
            Self::Ctr(c) => c.open(seq, pkt, tag),
        }
    }

    /// Encrypt `pkt` in place and write the tag into `tag_out`.
    pub fn seal(&mut self, seq: u32, pkt: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        match self {
            Self::Clear => Ok(()),
            Self::ChaCha(c) => c.seal(seq, pkt, tag_out),
            Self::Gcm(c) => c.seal(seq, pkt, tag_out),
            Self::Ctr(c) => c.seal(seq, pkt, tag_out),
        }
    }
}

/// SSH packet padding (RFC 4253 §6), minimum 4 bytes.
pub fn padding_len(payload_len: usize, block: usize, length_is_aad: bool) -> usize {
    let block = block.max(8);
    let need = if length_is_aad {
        1 + payload_len
    } else {
        5 + payload_len
    };
    let mut pad = block - (need % block);
    if pad < 4 {
        pad += block;
    }
    pad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_min_four() {
        assert_eq!(padding_len(7, 8, false), 4);
        assert_eq!(padding_len(0, 8, false), 11);
        assert_eq!(padding_len(3, 8, false), 8);
        assert_eq!(padding_len(7, 8, true), 8);
        assert_eq!(padding_len(0, 8, true), 7);
        assert_eq!(padding_len(3, 8, true), 4);
        assert_eq!(padding_len(15, 16, true), 16);
        assert_eq!(padding_len(14, 16, true), 17);
    }

    fn roundtrip(kind: CipherKind, mac: Option<MacKind>) {
        let key = vec![7u8; kind.key_len()];
        let iv = vec![3u8; kind.iv_len()];
        let mk = vec![9u8; mac.map(|m| m.key_len()).unwrap_or(0)];
        let mut tx = DirectionKeys::new(kind, mac, &key, &iv, &mk).unwrap();
        let mut rx = DirectionKeys::new(kind, mac, &key, &iv, &mk).unwrap();
        for seq in 0..3u32 {
            let payload = vec![seq as u8; 37 + seq as usize];
            let pad = padding_len(payload.len(), tx.block_size(), tx.length_is_aad());
            let plen = 1 + payload.len() + pad;
            let mut pkt = vec![0u8; 4 + plen];
            pkt[..4].copy_from_slice(&(plen as u32).to_be_bytes());
            pkt[4] = pad as u8;
            pkt[5..5 + payload.len()].copy_from_slice(&payload);
            let orig = pkt.clone();
            let mut tag = vec![0u8; tx.tag_len()];
            tx.seal(seq, &mut pkt, &mut tag).unwrap();
            let head = rx.head_len();
            let len = rx.read_length(seq, &mut pkt[..head]).unwrap();
            assert_eq!(len as usize, plen, "{kind:?}");
            rx.open(seq, &mut pkt, &tag).unwrap();
            assert_eq!(pkt, orig, "{kind:?} {mac:?}");
        }
    }

    #[test]
    fn all_ciphers_roundtrip() {
        roundtrip(CipherKind::ChaCha20Poly1305, None);
        roundtrip(CipherKind::Aes128Gcm, None);
        roundtrip(CipherKind::Aes256Gcm, None);
        for mac in [
            MacKind::HmacSha256,
            MacKind::HmacSha512,
            MacKind::HmacSha256Etm,
            MacKind::HmacSha512Etm,
        ] {
            roundtrip(CipherKind::Aes128Ctr, Some(mac));
            roundtrip(CipherKind::Aes192Ctr, Some(mac));
            roundtrip(CipherKind::Aes256Ctr, Some(mac));
        }
    }

    #[test]
    fn tampered_tag_rejected() {
        for (kind, mac) in [
            (CipherKind::ChaCha20Poly1305, None),
            (CipherKind::Aes128Gcm, None),
            (CipherKind::Aes256Ctr, Some(MacKind::HmacSha256Etm)),
            (CipherKind::Aes128Ctr, Some(MacKind::HmacSha512)),
        ] {
            let key = vec![1u8; kind.key_len()];
            let iv = vec![2u8; kind.iv_len()];
            let mk = vec![3u8; mac.map(|m| m.key_len()).unwrap_or(0)];
            let mut tx = DirectionKeys::new(kind, mac, &key, &iv, &mk).unwrap();
            let mut rx = DirectionKeys::new(kind, mac, &key, &iv, &mk).unwrap();
            let mut pkt = vec![0u8; 4 + 32];
            pkt[..4].copy_from_slice(&32u32.to_be_bytes());
            pkt[4] = 10;
            let mut tag = vec![0u8; tx.tag_len()];
            tx.seal(0, &mut pkt, &mut tag).unwrap();
            tag[0] ^= 1;
            let head = rx.head_len();
            rx.read_length(0, &mut pkt[..head]).unwrap();
            assert!(rx.open(0, &mut pkt, &tag).is_err(), "{kind:?}");
        }
    }
}
