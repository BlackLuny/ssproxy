use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

const TAG: usize = 16;

/// OpenSSH `chacha20-poly1305@openssh.com`. 64-byte key = K_2 (payload) || K_1
/// (length). For sequence numbers below 2^32 the IETF ChaCha20 state with a
/// 12-byte nonce `[0u8;8] || seq_be` coincides with OpenSSH's original-ChaCha
/// counter/nonce layout, so this interoperates with OpenSSH.
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
        n[8..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    pub fn decrypt_length(&self, seq: u32, mut enc: [u8; 4]) -> [u8; 4] {
        let mut c = ChaCha20::new((&self.length_key).into(), (&Self::nonce(seq)).into());
        c.apply_keystream(&mut enc);
        enc
    }

    fn poly_key(&self, seq: u32) -> [u8; 32] {
        let mut c = ChaCha20::new((&self.payload_key).into(), (&Self::nonce(seq)).into());
        let mut block0 = [0u8; 32];
        c.apply_keystream(&mut block0);
        block0
    }

    fn apply_payload(&self, seq: u32, data: &mut [u8]) {
        let mut c = ChaCha20::new((&self.payload_key).into(), (&Self::nonce(seq)).into());
        // Consume counter block 0 (the Poly1305 key) so payload uses block 1.
        let mut skip = [0u8; 64];
        c.apply_keystream(&mut skip);
        c.apply_keystream(data);
    }

    pub fn seal(&self, seq: u32, pkt: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        let mut lc = ChaCha20::new((&self.length_key).into(), (&Self::nonce(seq)).into());
        lc.apply_keystream(&mut pkt[..4]);
        self.apply_payload(seq, &mut pkt[4..]);
        let tag = Poly1305::new((&self.poly_key(seq)).into()).compute_unpadded(pkt);
        tag_out[..TAG].copy_from_slice(tag.as_slice());
        Ok(())
    }

    pub fn open(&self, seq: u32, pkt: &mut [u8], tag: &[u8]) -> Result<()> {
        let expected = Poly1305::new((&self.poly_key(seq)).into()).compute_unpadded(pkt);
        if expected.as_slice().ct_eq(tag).unwrap_u8() == 0 {
            return Err(Error::Crypto("poly1305 tag"));
        }
        self.apply_payload(seq, &mut pkt[4..]);
        let plain = self.decrypt_length(seq, pkt[..4].try_into().unwrap());
        pkt[..4].copy_from_slice(&plain);
        Ok(())
    }
}
