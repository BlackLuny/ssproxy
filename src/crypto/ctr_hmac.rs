//! `aes*-ctr` with `hmac-sha2-*` (classic or encrypt-then-MAC), on aws-lc.
//!
//! Measured on the real rig before this: the RustCrypto `ctr`+`hmac` path
//! cost the worker 10.0 ns/byte (aes128-ctr, 888 Mbps) against 3.3 ns/byte
//! for chacha20-poly1305 on aws-lc. Same library as the AEAD paths now.
//!
//! SSH CTR is one continuous counter stream across packets. aws-lc's one-shot
//! CTR takes an explicit IV per call, so the running counter is kept here and
//! advanced by the number of blocks each call consumed; every encrypted span
//! is block-aligned (the padding rule guarantees it), so no keystream is ever
//! split inside a block.

use aws_lc_rs::cipher::{EncryptingKey, EncryptionContext, UnboundCipherKey, AES_128, AES_192, AES_256};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;

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

/// One direction's keystream. CTR encrypt and decrypt are the same XOR, so a
/// single encrypting key serves both; the running block counter lives here.
struct Stream {
    enc: EncryptingKey,
    counter: [u8; 16],
}

impl Stream {
    fn new(cipher: CipherKind, key: &[u8], iv: &[u8]) -> Result<Self> {
        let alg = match cipher {
            CipherKind::Aes128Ctr => &AES_128,
            CipherKind::Aes192Ctr => &AES_192,
            CipherKind::Aes256Ctr => &AES_256,
            _ => return Err(Error::Crypto("not ctr")),
        };
        let bad = |_| Error::Crypto("ctr key/iv");
        let enc = EncryptingKey::ctr(UnboundCipherKey::new(alg, key).map_err(bad)?).map_err(bad)?;
        let counter: [u8; 16] = iv.try_into().map_err(|_| Error::Crypto("ctr iv"))?;
        Ok(Self { enc, counter })
    }

    /// Advance the big-endian 128-bit block counter.
    fn bump(&mut self, blocks: u64) {
        let c = u128::from_be_bytes(self.counter).wrapping_add(blocks as u128);
        self.counter = c.to_be_bytes();
    }

    #[inline]
    fn apply(&mut self, data: &mut [u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        debug_assert_eq!(data.len() % 16, 0, "ctr span not block aligned");
        let ctx = EncryptionContext::Iv128(FixedLength::from(self.counter));
        self.enc
            .less_safe_encrypt(data, ctx)
            .map_err(|_| Error::Crypto("ctr"))?;
        self.bump((data.len() / 16) as u64);
        Ok(())
    }
}

/// `aes*-ctr` with `hmac-sha2-*` (classic or encrypt-then-MAC).
pub struct CtrHmac {
    stream: Stream,
    mac: hmac::Key,
    kind: MacKind,
    /// Non-ETM receive: bytes of the current packet already decrypted by
    /// `decrypt_head`.
    head_done: usize,
}

impl CtrHmac {
    pub fn new(cipher: CipherKind, mac: MacKind, key: &[u8], iv: &[u8], mac_key: &[u8]) -> Result<Self> {
        let stream = Stream::new(cipher, key, iv)?;
        let alg = match mac {
            MacKind::HmacSha256 | MacKind::HmacSha256Etm => hmac::HMAC_SHA256,
            MacKind::HmacSha512 | MacKind::HmacSha512Etm => hmac::HMAC_SHA512,
        };
        Ok(Self {
            stream,
            mac: hmac::Key::new(alg, mac_key),
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
        let mut ctx = hmac::Context::with_key(&self.mac);
        ctx.update(&seq.to_be_bytes());
        ctx.update(data);
        let tag = ctx.sign();
        let n = self.mac_len();
        out[..n].copy_from_slice(&tag.as_ref()[..n]);
    }

    fn verify(&self, seq: u32, data: &[u8], tag: &[u8]) -> Result<()> {
        let mut ctx = hmac::Context::with_key(&self.mac);
        ctx.update(&seq.to_be_bytes());
        ctx.update(data);
        let ours = ctx.sign();
        let n = self.mac_len();
        if tag.len() < n {
            return Err(Error::Crypto("mac"));
        }
        verify_slices_are_equal(&ours.as_ref()[..n], &tag[..n]).map_err(|_| Error::Crypto("mac"))
    }

    /// Non-ETM: decrypt the first cipher block so the length is readable.
    pub fn decrypt_head(&mut self, head: &mut [u8]) {
        let _ = self.stream.apply(head);
        self.head_done = head.len();
    }

    pub fn seal(&mut self, seq: u32, pkt: &mut [u8], tag_out: &mut [u8]) -> Result<()> {
        if self.kind.etm() {
            self.stream.apply(&mut pkt[4..])?;
            self.compute(seq, pkt, tag_out);
        } else {
            self.compute(seq, pkt, tag_out);
            self.stream.apply(pkt)?;
        }
        Ok(())
    }

    pub fn open(&mut self, seq: u32, pkt: &mut [u8], tag: &[u8]) -> Result<()> {
        if self.kind.etm() {
            self.verify(seq, pkt, tag)?;
            self.stream.apply(&mut pkt[4..])
        } else {
            let done = std::mem::take(&mut self.head_done);
            self.stream.apply(&mut pkt[done..])?;
            self.verify(seq, pkt, tag)
        }
    }
}
