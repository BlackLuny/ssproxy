use aws_lc_rs::aead::chacha20_poly1305_openssh::{OpeningKey, SealingKey, TAG_LEN};

use crate::error::{Error, Result};

/// OpenSSH `chacha20-poly1305@openssh.com`, backed by aws-lc-rs's purpose-built
/// implementation of that exact construction (assembly-optimised; the same
/// backend russh uses, and already present in the zfc dependency tree).
///
/// The 64-byte key is handed over verbatim: aws-lc splits it as
/// `K_2 (payload) || K_1 (length)` — the same convention `kdf::derive` produces
/// and the same one the previous hand-rolled implementation used, so this is a
/// drop-in with no re-keying.
///
/// Both a sealing and an opening key are built from the same material because
/// `DirectionKeys` does not know which direction it serves; each is just a key
/// schedule, so the cost is negligible.
pub struct ChaCha20Poly1305Ssh {
    sealing: SealingKey,
    opening: OpeningKey,
}

impl ChaCha20Poly1305Ssh {
    pub fn new(key: &[u8; 64]) -> Self {
        Self {
            sealing: SealingKey::new(key),
            opening: OpeningKey::new(key),
        }
    }

    pub fn decrypt_length(&self, seq: u32, enc: [u8; 4]) -> [u8; 4] {
        self.opening.decrypt_packet_length(seq, enc)
    }

    pub fn seal(&self, seq: u32, pkt: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        let out = tag_out
            .get_mut(..TAG_LEN)
            .ok_or(Error::Crypto("chacha tag buffer"))?;
        let mut tag = [0u8; TAG_LEN];
        self.sealing.seal_in_place(seq, pkt, &mut tag);
        out.copy_from_slice(&tag);
        Ok(())
    }

    pub fn open(&self, seq: u32, pkt: &mut [u8], tag: &[u8]) -> Result<()> {
        let tag: &[u8; TAG_LEN] = tag
            .try_into()
            .map_err(|_| Error::Crypto("chacha tag len"))?;
        // aws-lc authenticates over `encrypted_length || ciphertext` and decrypts
        // only the payload, deliberately leaving the length field encrypted. Our
        // contract (see `DirectionKeys::open`) is that the length is plaintext on
        // return, so recover it here. Must be read before `open_in_place` borrows
        // the buffer; the value itself is independent of the payload decryption.
        let enc_len: [u8; 4] = pkt
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Crypto("chacha short packet"))?;
        let plain_len = self.opening.decrypt_packet_length(seq, enc_len);
        self.opening
            .open_in_place(seq, pkt, tag)
            .map_err(|_| Error::Crypto("poly1305 tag"))?;
        pkt[..4].copy_from_slice(&plain_len);
        Ok(())
    }
}
