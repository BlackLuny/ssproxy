use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};

use crate::crypto::CipherKind;
use crate::error::{Error, Result};

#[allow(clippy::large_enum_variant)]
enum Inner {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

/// OpenSSH `aes{128,256}-gcm@openssh.com`. Length is plaintext AAD; the 12-byte
/// IV's low 8 bytes increment per packet (RFC 5647).
pub struct AesGcmSsh {
    inner: Inner,
    iv: [u8; 12],
}

impl AesGcmSsh {
    pub fn new(kind: CipherKind, key: &[u8], iv: &[u8]) -> Result<Self> {
        let iv: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("gcm iv"))?;
        let inner = match kind {
            CipherKind::Aes128Gcm => {
                Inner::Aes128(Aes128Gcm::new_from_slice(key).map_err(|_| Error::Crypto("aes128 key"))?)
            }
            CipherKind::Aes256Gcm => {
                Inner::Aes256(Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("aes256 key"))?)
            }
            _ => return Err(Error::Crypto("not aes-gcm")),
        };
        Ok(Self { inner, iv })
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
        let (len_field, body) = pkt.split_at_mut(4);
        let tag = match &self.inner {
            Inner::Aes128(c) => c.encrypt_in_place_detached((&self.iv).into(), len_field, body),
            Inner::Aes256(c) => c.encrypt_in_place_detached((&self.iv).into(), len_field, body),
        }
        .map_err(|_| Error::Crypto("gcm seal"))?;
        tag_out[..16].copy_from_slice(tag.as_slice());
        self.inc_iv();
        Ok(())
    }

    pub fn open(&mut self, _seq: u32, pkt: &mut [u8], tag: &[u8]) -> Result<()> {
        let (len_field, body) = pkt.split_at_mut(4);
        let tag = GenericArray::from_slice(tag);
        match &self.inner {
            Inner::Aes128(c) => c.decrypt_in_place_detached((&self.iv).into(), len_field, body, tag),
            Inner::Aes256(c) => c.decrypt_in_place_detached((&self.iv).into(), len_field, body, tag),
        }
        .map_err(|_| Error::Crypto("gcm tag"))?;
        self.inc_iv();
        Ok(())
    }
}
