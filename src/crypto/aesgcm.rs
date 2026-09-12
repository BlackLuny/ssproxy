use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};

use crate::crypto::CipherKind;
use crate::error::{Error, Result};

#[allow(clippy::large_enum_variant)]
enum Inner {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

/// OpenSSH `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com`.
///
/// Packet length is plaintext AAD. IV is 12 bytes; last 8 bytes increment per packet.
pub struct AesGcmSsh {
    kind: CipherKind,
    inner: Inner,
    iv: [u8; 12],
}

impl AesGcmSsh {
    pub fn new(kind: CipherKind, key: &[u8], iv: &[u8]) -> Result<Self> {
        if iv.len() != 12 {
            return Err(Error::Crypto("aes-gcm iv"));
        }
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(iv);
        let inner = match kind {
            CipherKind::Aes128Gcm => {
                if key.len() != 16 {
                    return Err(Error::Crypto("aes128 key"));
                }
                Inner::Aes128(Aes128Gcm::new(key.into()))
            }
            CipherKind::Aes256Gcm => {
                if key.len() != 32 {
                    return Err(Error::Crypto("aes256 key"));
                }
                Inner::Aes256(Aes256Gcm::new(key.into()))
            }
            _ => return Err(Error::Crypto("not aes-gcm")),
        };
        Ok(Self {
            kind,
            inner,
            iv: iv_arr,
        })
    }

    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    fn inc_iv(&mut self) {
        for i in (4..12).rev() {
            self.iv[i] = self.iv[i].wrapping_add(1);
            if self.iv[i] != 0 {
                break;
            }
        }
    }

    pub fn seal(&mut self, _seq: u32, buf: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        if buf.len() < 4 || tag_out.len() < 16 {
            return Err(Error::Crypto("gcm seal buf"));
        }
        let (len_field, body) = buf.split_at_mut(4);
        let tag = match &self.inner {
            Inner::Aes128(c) => c
                .encrypt_in_place_detached((&self.iv).into(), len_field, body)
                .map_err(|_| Error::Crypto("gcm seal"))?,
            Inner::Aes256(c) => c
                .encrypt_in_place_detached((&self.iv).into(), len_field, body)
                .map_err(|_| Error::Crypto("gcm seal"))?,
        };
        tag_out[..16].copy_from_slice(tag.as_slice());
        self.inc_iv();
        Ok(())
    }

    pub fn open(&mut self, _seq: u32, buf: &mut [u8], tag: &[u8]) -> Result<()> {
        if buf.len() < 4 || tag.len() != 16 {
            return Err(Error::Crypto("gcm open buf"));
        }
        let (len_field, body) = buf.split_at_mut(4);
        let tag_ga = GenericArray::from_slice(tag);
        let r = match &self.inner {
            Inner::Aes128(c) => {
                c.decrypt_in_place_detached((&self.iv).into(), len_field, body, tag_ga)
            }
            Inner::Aes256(c) => {
                c.decrypt_in_place_detached((&self.iv).into(), len_field, body, tag_ga)
            }
        };
        r.map_err(|_| Error::Crypto("gcm tag"))?;
        self.inc_iv();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_aes256() {
        let key = [7u8; 32];
        let iv = [3u8; 12];
        let mut a = AesGcmSsh::new(CipherKind::Aes256Gcm, &key, &iv).unwrap();
        let mut b = AesGcmSsh::new(CipherKind::Aes256Gcm, &key, &iv).unwrap();
        let mut buf = vec![
            0, 0, 0, 16, 15, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        ];
        let orig = buf.clone();
        let mut tag = [0u8; 16];
        a.seal(0, &mut buf, &mut tag).unwrap();
        assert_eq!(&buf[..4], &orig[..4]);
        assert_ne!(&buf[4..], &orig[4..]);
        b.open(0, &mut buf, &tag).unwrap();
        assert_eq!(buf, orig);
    }
}
