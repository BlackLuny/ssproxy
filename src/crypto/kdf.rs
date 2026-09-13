use sha2::{Digest, Sha256, Sha384, Sha512};

/// Exchange hash function selected by the KEX method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn digest_parts(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = D::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            Self::Sha256 => run::<Sha256>(parts),
            Self::Sha384 => run::<Sha384>(parts),
            Self::Sha512 => run::<Sha512>(parts),
        }
    }
}

/// RFC 4253 §7.2 key derivation.
///
/// `k_enc` is the shared secret *as encoded in the exchange hash* (mpint for
/// (EC)DH, string for the ML-KEM hybrid).
pub fn derive(hash: HashAlg, k_enc: &[u8], h: &[u8], session_id: &[u8], letter: u8, out: &mut [u8]) {
    let mut key = hash.digest_parts(&[k_enc, h, &[letter], session_id]);
    while key.len() < out.len() {
        let next = hash.digest_parts(&[k_enc, h, &key]);
        key.extend_from_slice(&next);
    }
    out.copy_from_slice(&key[..out.len()]);
}
