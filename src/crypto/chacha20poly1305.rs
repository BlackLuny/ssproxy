use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

const TAG: usize = 16;

/// OpenSSH `chacha20-poly1305@openssh.com`.
///
/// Key material is 64 bytes: first 32 = K_2 (payload + Poly1305), last 32 = K_1 (length).
pub struct ChaCha20Poly1305Ssh {
    payload_key: [u8; 32],
    length_key: [u8; 32],
}

impl ChaCha20Poly1305Ssh {
    pub fn new(key: &[u8; 64]) -> Self {
        let mut payload_key = [0u8; 32];
        let mut length_key = [0u8; 32];
        payload_key.copy_from_slice(&key[..32]);
        length_key.copy_from_slice(&key[32..]);
        Self {
            payload_key,
            length_key,
        }
    }

    fn nonce(seq: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[8..12].copy_from_slice(&seq.to_be_bytes());
        n
    }

    pub fn decrypt_length(&self, seq: u32, mut enc: [u8; 4]) -> [u8; 4] {
        let nonce = Self::nonce(seq);
        let mut c = ChaCha20::new((&self.length_key).into(), (&nonce).into());
        c.apply_keystream(&mut enc);
        enc
    }

    fn poly_key(&self, seq: u32) -> [u8; 32] {
        let nonce = Self::nonce(seq);
        let mut c = ChaCha20::new((&self.payload_key).into(), (&nonce).into());
        let mut block0 = [0u8; 64];
        c.apply_keystream(&mut block0);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&block0[..32]);
        pk
    }

    fn apply_payload(&self, seq: u32, data: &mut [u8]) {
        let nonce = Self::nonce(seq);
        let mut c = ChaCha20::new((&self.payload_key).into(), (&nonce).into());
        // Skip ChaCha block 0 (Poly1305 key + 32 unused bytes).
        let mut skip = [0u8; 64];
        c.apply_keystream(&mut skip);
        c.apply_keystream(data);
    }

    pub fn seal(&self, seq: u32, buf: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        if buf.len() < 4 || tag_out.len() < TAG {
            return Err(Error::Crypto("chacha seal buf"));
        }
        let nonce = Self::nonce(seq);
        let mut lc = ChaCha20::new((&self.length_key).into(), (&nonce).into());
        lc.apply_keystream(&mut buf[..4]);
        self.apply_payload(seq, &mut buf[4..]);
        let pk = self.poly_key(seq);
        let tag = Poly1305::new((&pk).into()).compute_unpadded(buf);
        tag_out[..TAG].copy_from_slice(tag.as_slice());
        Ok(())
    }

    pub fn open(&self, seq: u32, buf: &mut [u8], tag: &[u8]) -> Result<()> {
        if buf.len() < 4 || tag.len() != TAG {
            return Err(Error::Crypto("chacha open buf"));
        }
        let pk = self.poly_key(seq);
        let expected = Poly1305::new((&pk).into()).compute_unpadded(buf);
        if expected.as_slice().ct_eq(tag).unwrap_u8() == 0 {
            return Err(Error::Crypto("chacha tag"));
        }
        self.apply_payload(seq, &mut buf[4..]);
        let plain_len = self.decrypt_length(seq, buf[..4].try_into().unwrap());
        buf[..4].copy_from_slice(&plain_len);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let c = ChaCha20Poly1305Ssh::new(&key);
        let mut buf = vec![0, 0, 0, 12, 4, b'h', b'i', 1, 2, 3, 4, 5, 6, 7, 8];
        // packet_length = 12 (padlen + payload 2 + pad 8? wait we set 12 and 4 pad)
        let orig = buf.clone();
        let mut tag = [0u8; 16];
        c.seal(7, &mut buf, &mut tag).unwrap();
        assert_ne!(buf, orig);
        c.open(7, &mut buf, &tag).unwrap();
        assert_eq!(buf, orig);
        assert!(c.open(8, &mut buf, &tag).is_err());
    }
}
