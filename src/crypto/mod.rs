mod aesgcm;
mod chacha20poly1305;
mod kdf;

use crate::error::{Error, Result};
use ed25519_dalek::SigningKey;

pub use aesgcm::AesGcmSsh;
pub use chacha20poly1305::ChaCha20Poly1305Ssh;
pub use kdf::{derive_block, derive_keys, DerivedKeys};

pub const MAX_PACKET: usize = 256 * 1024;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    Clear,
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl CipherKind {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "chacha20-poly1305@openssh.com" => Some(Self::ChaCha20Poly1305),
            "aes128-gcm@openssh.com" => Some(Self::Aes128Gcm),
            "aes256-gcm@openssh.com" => Some(Self::Aes256Gcm),
            "none" => Some(Self::Clear),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Clear => "none",
            Self::ChaCha20Poly1305 => "chacha20-poly1305@openssh.com",
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
            Self::Aes256Gcm => "aes256-gcm@openssh.com",
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Clear => 0,
            Self::ChaCha20Poly1305 => 64,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            Self::Clear | Self::ChaCha20Poly1305 => 0,
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
        }
    }

    pub fn tag_len(self) -> usize {
        match self {
            Self::Clear => 0,
            _ => TAG_LEN,
        }
    }

    pub fn block_size(self) -> usize {
        match self {
            Self::Clear | Self::ChaCha20Poly1305 => 8,
            Self::Aes128Gcm | Self::Aes256Gcm => 16,
        }
    }

    pub fn encrypts_length(self) -> bool {
        matches!(self, Self::ChaCha20Poly1305)
    }

    pub fn is_aead(self) -> bool {
        !matches!(self, Self::Clear)
    }
}

pub enum DirectionKeys {
    Clear,
    ChaCha(ChaCha20Poly1305Ssh),
    Aes(AesGcmSsh),
}

impl DirectionKeys {
    pub fn from_material(kind: CipherKind, key: &[u8], iv: &[u8]) -> Result<Self> {
        match kind {
            CipherKind::Clear => Ok(Self::Clear),
            CipherKind::ChaCha20Poly1305 => {
                let k: [u8; 64] = key
                    .try_into()
                    .map_err(|_| Error::Crypto("chacha key len"))?;
                Ok(Self::ChaCha(ChaCha20Poly1305Ssh::new(&k)))
            }
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
                Ok(Self::Aes(AesGcmSsh::new(kind, key, iv)?))
            }
        }
    }

    pub fn kind(&self) -> CipherKind {
        match self {
            Self::Clear => CipherKind::Clear,
            Self::ChaCha(_) => CipherKind::ChaCha20Poly1305,
            Self::Aes(a) => a.kind(),
        }
    }

    pub fn decrypt_length(&self, seq: u32, enc: [u8; 4]) -> [u8; 4] {
        match self {
            Self::Clear | Self::Aes(_) => enc,
            Self::ChaCha(c) => c.decrypt_length(seq, enc),
        }
    }

    /// `buf` is `packet_length_field || padlen||payload||padding` (no tag).
    /// On success, in-place decrypts the confidential region.
    pub fn open(&mut self, seq: u32, buf: &mut [u8], tag: &[u8]) -> Result<()> {
        match self {
            Self::Clear => {
                if !tag.is_empty() {
                    return Err(Error::Crypto("unexpected tag"));
                }
                Ok(())
            }
            Self::ChaCha(c) => c.open(seq, buf, tag),
            Self::Aes(c) => c.open(seq, buf, tag),
        }
    }

    /// Encrypts in place. `buf` is plaintext `len||padlen||payload||padding`.
    /// Writes 16-byte tag into `tag_out` when AEAD.
    pub fn seal(&mut self, seq: u32, buf: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        match self {
            Self::Clear => Ok(()),
            Self::ChaCha(c) => c.seal(seq, buf, tag_out),
            Self::Aes(c) => c.seal(seq, buf, tag_out),
        }
    }
}

pub struct HostKey {
    pub signing: SigningKey,
}

impl HostKey {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// SSH wire encoding of the host public key blob (without outer string wrapper).
    pub fn public_blob(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(51);
        crate::wire::put_str(&mut b, "ssh-ed25519");
        crate::wire::put_bytes(&mut b, &self.public_bytes());
        b
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = self.signing.sign(data);
        let mut blob = Vec::with_capacity(4 + 11 + 4 + 64);
        crate::wire::put_str(&mut blob, "ssh-ed25519");
        crate::wire::put_bytes(&mut blob, &sig.to_bytes());
        blob
    }

    pub fn openssh_public_line(&self, comment: &str) -> String {
        let blob = self.public_blob();
        format!("ssh-ed25519 {} {comment}", b64(&blob))
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            out.push(T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(T[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

pub fn padding_len(payload_len: usize, block: usize) -> usize {
    let need = 1 + payload_len;
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
        assert_eq!(padding_len(7, 8), 8); // 1+7=8, pad would be 8 then already %8==0 -> 8 >= 4
        assert_eq!(padding_len(0, 8), 7); // 1+0=1, pad=7
        assert_eq!(padding_len(3, 8), 4); // 1+3=4, pad=4
    }
}
