use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};

use crate::crypto::CipherKind;
use crate::error::{Error, Result};

const TAG: usize = 16;

/// OpenSSH `aes{128,256}-gcm@openssh.com`, backed by aws-lc-rs (assembly, uses
/// AES-NI/CLMUL where available) — the same backend russh uses and the one
/// already present in the zfc dependency tree.
///
/// Length is plaintext AAD; the 12-byte IV's low 8 bytes increment per packet
/// (RFC 5647). We drive the nonce ourselves via `LessSafeKey` rather than
/// aws-lc's `NonceSequence`: the sequence type increments all 12 bytes with
/// carry, which is *not* the RFC 5647 rule, and keeping our own counter means
/// the on-wire behaviour is unchanged by this swap.
///
/// `LessSafeKey` is "less safe" only because it lets the caller pick the nonce;
/// that is exactly the requirement here, and uniqueness is guaranteed by the
/// per-packet counter (a rekey installs fresh keys long before it could wrap).
pub struct AesGcmSsh {
    key: LessSafeKey,
    iv: [u8; 12],
}

impl AesGcmSsh {
    pub fn new(kind: CipherKind, key: &[u8], iv: &[u8]) -> Result<Self> {
        let iv: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("gcm iv"))?;
        let alg = match kind {
            CipherKind::Aes128Gcm => &AES_128_GCM,
            CipherKind::Aes256Gcm => &AES_256_GCM,
            _ => return Err(Error::Crypto("not aes-gcm")),
        };
        let unbound = UnboundKey::new(alg, key).map_err(|_| Error::Crypto("aes-gcm key"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            iv,
        })
    }

    fn inc_iv(&mut self) {
        for i in (4..12).rev() {
            self.iv[i] = self.iv[i].wrapping_add(1);
            if self.iv[i] != 0 {
                break;
            }
        }
    }

    pub fn seal(&mut self, _seq: u32, pkt: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        let out = tag_out
            .get_mut(..TAG)
            .ok_or(Error::Crypto("gcm tag buffer"))?;
        let nonce = Nonce::assume_unique_for_key(self.iv);
        let (len_field, body) = pkt.split_at_mut(4);
        // `len_field` is authenticated but not encrypted (OpenSSH GCM sends the
        // packet length in the clear), so it goes in as AAD.
        let aad: [u8; 4] = len_field.try_into().map_err(|_| Error::Crypto("gcm aad"))?;
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&aad), body)
            .map_err(|_| Error::Crypto("gcm seal"))?;
        out.copy_from_slice(tag.as_ref());
        self.inc_iv();
        Ok(())
    }

    pub fn open(&mut self, _seq: u32, pkt: &mut [u8], tag: &[u8]) -> Result<()> {
        let nonce = Nonce::assume_unique_for_key(self.iv);
        let (len_field, body) = pkt.split_at_mut(4);
        let aad: [u8; 4] = len_field.try_into().map_err(|_| Error::Crypto("gcm aad"))?;
        self.key
            .open_in_place_separate_tag(nonce, Aad::from(&aad), tag, body)
            .map_err(|_| Error::Crypto("gcm tag"))?;
        // Only advance on success: a rejected packet must not desynchronise the
        // IV counter (the peer never counted it either).
        self.inc_iv();
        Ok(())
    }
}
