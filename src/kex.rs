//! Key exchange methods: shared-secret computation for both roles.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::HashAlg;
use crate::error::{Error, Result};
use crate::wire;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexAlgo {
    #[cfg(feature = "mlkem")]
    MlKem768X25519Sha256,
    Curve25519Sha256,
    Curve25519Sha256Libssh,
    #[cfg(feature = "ecdh")]
    EcdhSha2NistP256,
    #[cfg(feature = "ecdh")]
    EcdhSha2NistP384,
    #[cfg(feature = "ecdh")]
    EcdhSha2NistP521,
}

impl KexAlgo {
    pub fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "mlkem")]
            Self::MlKem768X25519Sha256 => "mlkem768x25519-sha256",
            Self::Curve25519Sha256 => "curve25519-sha256",
            Self::Curve25519Sha256Libssh => "curve25519-sha256@libssh.org",
            #[cfg(feature = "ecdh")]
            Self::EcdhSha2NistP256 => "ecdh-sha2-nistp256",
            #[cfg(feature = "ecdh")]
            Self::EcdhSha2NistP384 => "ecdh-sha2-nistp384",
            #[cfg(feature = "ecdh")]
            Self::EcdhSha2NistP521 => "ecdh-sha2-nistp521",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            #[cfg(feature = "mlkem")]
            "mlkem768x25519-sha256" => Self::MlKem768X25519Sha256,
            "curve25519-sha256" => Self::Curve25519Sha256,
            "curve25519-sha256@libssh.org" => Self::Curve25519Sha256Libssh,
            #[cfg(feature = "ecdh")]
            "ecdh-sha2-nistp256" => Self::EcdhSha2NistP256,
            #[cfg(feature = "ecdh")]
            "ecdh-sha2-nistp384" => Self::EcdhSha2NistP384,
            #[cfg(feature = "ecdh")]
            "ecdh-sha2-nistp521" => Self::EcdhSha2NistP521,
            _ => return None,
        })
    }

    pub fn hash(self) -> HashAlg {
        match self {
            #[cfg(feature = "ecdh")]
            Self::EcdhSha2NistP384 => HashAlg::Sha384,
            #[cfg(feature = "ecdh")]
            Self::EcdhSha2NistP521 => HashAlg::Sha512,
            _ => HashAlg::Sha256,
        }
    }
}

#[cfg(feature = "mlkem")]
mod mlkem {
    pub const PK_LEN: usize = 1184;
    pub const CT_LEN: usize = 1088;
}

fn x25519_shared(secret: x25519_dalek::EphemeralSecret, peer: &[u8]) -> Result<[u8; 32]> {
    let peer: [u8; 32] = peer.try_into().map_err(|_| Error::Crypto("x25519 key len"))?;
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
    let bytes = *shared.as_bytes();
    if bytes.iter().fold(0u8, |a, b| a | b) == 0 {
        return Err(Error::Crypto("x25519 low-order point"));
    }
    Ok(bytes)
}

fn x25519_keypair() -> (x25519_dalek::EphemeralSecret, [u8; 32]) {
    let s = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let p = x25519_dalek::PublicKey::from(&s);
    (s, *p.as_bytes())
}

fn mpint(raw: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(raw.len() + 5);
    wire::put_mpint(&mut v, raw);
    v
}

macro_rules! ecdh_server {
    ($krate:ident, $q_c:expr) => {{
        use $krate::elliptic_curve::sec1::ToEncodedPoint;
        let peer = $krate::PublicKey::from_sec1_bytes($q_c)
            .map_err(|_| Error::Crypto("ecdh point"))?;
        let secret = $krate::ecdh::EphemeralSecret::random(&mut OsRng);
        let q_s = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
        let shared = secret.diffie_hellman(&peer);
        Ok((q_s, mpint(shared.raw_secret_bytes().as_slice())))
    }};
}

/// Server side: returns `(Q_S, K)` where `K` is encoded for the exchange hash.
pub fn server_exchange(algo: KexAlgo, q_c: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    match algo {
        KexAlgo::Curve25519Sha256 | KexAlgo::Curve25519Sha256Libssh => {
            let (s, q_s) = x25519_keypair();
            let k = x25519_shared(s, q_c)?;
            Ok((q_s.to_vec(), mpint(&k)))
        }
        #[cfg(feature = "ecdh")]
        KexAlgo::EcdhSha2NistP256 => ecdh_server!(p256, q_c),
        #[cfg(feature = "ecdh")]
        KexAlgo::EcdhSha2NistP384 => ecdh_server!(p384, q_c),
        #[cfg(feature = "ecdh")]
        KexAlgo::EcdhSha2NistP521 => ecdh_server!(p521, q_c),
        #[cfg(feature = "mlkem")]
        KexAlgo::MlKem768X25519Sha256 => {
            use ml_kem::kem::TryKeyInit;
            if q_c.len() != mlkem::PK_LEN + 32 {
                return Err(Error::Crypto("mlkem client blob len"));
            }
            let (pq_pk, x_pk) = q_c.split_at(mlkem::PK_LEN);
            let ek = ml_kem::EncapsulationKey768::new_from_slice(pq_pk)
                .map_err(|_| Error::Crypto("mlkem public key"))?;
            let mut m = [0u8; 32];
            OsRng.fill_bytes(&mut m);
            let (ct, k_pq) = ek.encapsulate_deterministic(&m.into());
            let (s, x_pub) = x25519_keypair();
            let k_x = x25519_shared(s, x_pk)?;
            let digest = HashAlg::Sha256.digest_parts(&[k_pq.as_slice(), &k_x]);
            let mut q_s = Vec::with_capacity(mlkem::CT_LEN + 32);
            q_s.extend_from_slice(ct.as_slice());
            q_s.extend_from_slice(&x_pub);
            let mut k = Vec::with_capacity(36);
            wire::put_bytes(&mut k, &digest);
            Ok((q_s, k))
        }
    }
}

/// Client-side ephemeral state.
pub enum ClientKex {
    X25519(x25519_dalek::EphemeralSecret),
    #[cfg(feature = "ecdh")]
    P256(p256::ecdh::EphemeralSecret),
    #[cfg(feature = "ecdh")]
    P384(p384::ecdh::EphemeralSecret),
    #[cfg(feature = "ecdh")]
    P521(p521::ecdh::EphemeralSecret),
    #[cfg(feature = "mlkem")]
    MlKem(Box<(ml_kem::DecapsulationKey768, x25519_dalek::EphemeralSecret)>),
}

impl ClientKex {
    /// Returns the ephemeral state and `Q_C`.
    pub fn start(algo: KexAlgo) -> (Self, Vec<u8>) {
        match algo {
            KexAlgo::Curve25519Sha256 | KexAlgo::Curve25519Sha256Libssh => {
                let (s, p) = x25519_keypair();
                (Self::X25519(s), p.to_vec())
            }
            #[cfg(feature = "ecdh")]
            KexAlgo::EcdhSha2NistP256 => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let s = p256::ecdh::EphemeralSecret::random(&mut OsRng);
                let q = s.public_key().to_encoded_point(false).as_bytes().to_vec();
                (Self::P256(s), q)
            }
            #[cfg(feature = "ecdh")]
            KexAlgo::EcdhSha2NistP384 => {
                use p384::elliptic_curve::sec1::ToEncodedPoint;
                let s = p384::ecdh::EphemeralSecret::random(&mut OsRng);
                let q = s.public_key().to_encoded_point(false).as_bytes().to_vec();
                (Self::P384(s), q)
            }
            #[cfg(feature = "ecdh")]
            KexAlgo::EcdhSha2NistP521 => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;
                let s = p521::ecdh::EphemeralSecret::random(&mut OsRng);
                let q = s.public_key().to_encoded_point(false).as_bytes().to_vec();
                (Self::P521(s), q)
            }
            #[cfg(feature = "mlkem")]
            KexAlgo::MlKem768X25519Sha256 => {
                use ml_kem::kem::{FromSeed, KeyExport};
                let mut seed = [0u8; 64];
                OsRng.fill_bytes(&mut seed);
                let (dk, ek) = ml_kem::MlKem768::from_seed(&seed.into());
                let (xs, xp) = x25519_keypair();
                let mut q = Vec::with_capacity(mlkem::PK_LEN + 32);
                q.extend_from_slice(ek.to_bytes().as_slice());
                q.extend_from_slice(&xp);
                (Self::MlKem(Box::new((dk, xs))), q)
            }
        }
    }

    /// Consume `Q_S`, return `K` encoded for the exchange hash.
    pub fn finish(self, q_s: &[u8]) -> Result<Vec<u8>> {
        macro_rules! ecdh_client {
            ($krate:ident, $s:expr) => {{
                let peer = $krate::PublicKey::from_sec1_bytes(q_s)
                    .map_err(|_| Error::Crypto("ecdh point"))?;
                let shared = $s.diffie_hellman(&peer);
                Ok(mpint(shared.raw_secret_bytes().as_slice()))
            }};
        }
        match self {
            Self::X25519(s) => Ok(mpint(&x25519_shared(s, q_s)?)),
            #[cfg(feature = "ecdh")]
            Self::P256(s) => ecdh_client!(p256, s),
            #[cfg(feature = "ecdh")]
            Self::P384(s) => ecdh_client!(p384, s),
            #[cfg(feature = "ecdh")]
            Self::P521(s) => ecdh_client!(p521, s),
            #[cfg(feature = "mlkem")]
            Self::MlKem(b) => {
                use ml_kem::kem::Decapsulate;
                if q_s.len() != mlkem::CT_LEN + 32 {
                    return Err(Error::Crypto("mlkem server blob len"));
                }
                let (dk, xs) = *b;
                let (ct, x_pk) = q_s.split_at(mlkem::CT_LEN);
                let k_pq = dk
                    .decapsulate_slice(ct)
                    .map_err(|_| Error::Crypto("mlkem ciphertext"))?;
                let k_x = x25519_shared(xs, x_pk)?;
                let digest = HashAlg::Sha256.digest_parts(&[k_pq.as_slice(), &k_x]);
                let mut k = Vec::with_capacity(36);
                wire::put_bytes(&mut k, &digest);
                Ok(k)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<KexAlgo> {
        let mut v = vec![KexAlgo::Curve25519Sha256, KexAlgo::Curve25519Sha256Libssh];
        #[cfg(feature = "ecdh")]
        v.extend([
            KexAlgo::EcdhSha2NistP256,
            KexAlgo::EcdhSha2NistP384,
            KexAlgo::EcdhSha2NistP521,
        ]);
        #[cfg(feature = "mlkem")]
        v.push(KexAlgo::MlKem768X25519Sha256);
        v
    }

    #[test]
    fn client_server_agree() {
        for algo in all() {
            assert_eq!(KexAlgo::from_name(algo.name()), Some(algo));
            let (c, q_c) = ClientKex::start(algo);
            let (q_s, k_server) = server_exchange(algo, &q_c).unwrap();
            let k_client = c.finish(&q_s).unwrap();
            assert_eq!(k_server, k_client, "{}", algo.name());
        }
    }

    #[test]
    fn rejects_bad_points() {
        assert!(server_exchange(KexAlgo::Curve25519Sha256, &[0u8; 32]).is_err());
        assert!(server_exchange(KexAlgo::Curve25519Sha256, &[1u8; 31]).is_err());
        #[cfg(feature = "ecdh")]
        assert!(server_exchange(KexAlgo::EcdhSha2NistP256, &[4u8; 65]).is_err());
    }
}
