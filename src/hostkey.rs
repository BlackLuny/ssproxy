use ed25519_dalek::{Signer, SigningKey};

use crate::error::{Error, Result};
use crate::wire;

enum Key {
    Ed25519(SigningKey),
    #[cfg(feature = "pubkey")]
    Ecdsa(ssh_key::PrivateKey),
    /// Both digests are prepared at load; signing never re-derives CRT params.
    #[cfg(feature = "pubkey")]
    Rsa {
        sha512: rsa::pkcs1v15::SigningKey<sha2::Sha512>,
        sha256: rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    },
}

/// Server host key: `ssh-ed25519`, or (with `pubkey`) `ecdsa-sha2-nistp{256,384,521}`
/// and RSA (`rsa-sha2-512`, `rsa-sha2-256`; SHA-1 `ssh-rsa` is not offered).
pub struct HostKey {
    key: Key,
    blob: Vec<u8>,
    key_type: &'static str,
    algorithms: &'static [&'static str],
}

impl HostKey {
    pub const ALGORITHM: &'static str = "ssh-ed25519";

    pub fn generate() -> Self {
        Self::from_signing(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_signing(SigningKey::from_bytes(seed))
    }

    fn from_signing(signing: SigningKey) -> Self {
        let mut blob = Vec::with_capacity(51);
        wire::put_str(&mut blob, Self::ALGORITHM);
        wire::put_bytes(&mut blob, signing.verifying_key().as_bytes());
        Self {
            key: Key::Ed25519(signing),
            blob,
            key_type: Self::ALGORITHM,
            algorithms: &[Self::ALGORITHM],
        }
    }

    /// Parse an unencrypted OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    #[cfg(feature = "pubkey")]
    pub fn from_openssh_pem(pem: &str) -> Result<Self> {
        use ssh_key::private::KeypairData;
        use ssh_key::EcdsaCurve;

        let key = ssh_key::PrivateKey::from_openssh(pem.trim())
            .map_err(|_| Error::Crypto("host key: not an OpenSSH private key"))?;
        if key.is_encrypted() {
            return Err(Error::Crypto("host key: encrypted keys are not supported"));
        }
        let blob = key
            .public_key()
            .to_bytes()
            .map_err(|_| Error::Crypto("host key: public key encoding"))?;
        let (inner, key_type, algorithms): (Key, &'static str, &'static [&'static str]) = match key.key_data() {
            KeypairData::Ed25519(ed) => return Ok(Self::from_seed(&ed.private.to_bytes())),
            KeypairData::Ecdsa(ec) => {
                let name: &'static str = match ec.curve() {
                    EcdsaCurve::NistP256 => "ecdsa-sha2-nistp256",
                    EcdsaCurve::NistP384 => "ecdsa-sha2-nistp384",
                    EcdsaCurve::NistP521 => "ecdsa-sha2-nistp521",
                };
                let algorithms: &'static [&'static str] = match ec.curve() {
                    EcdsaCurve::NistP256 => &["ecdsa-sha2-nistp256"],
                    EcdsaCurve::NistP384 => &["ecdsa-sha2-nistp384"],
                    EcdsaCurve::NistP521 => &["ecdsa-sha2-nistp521"],
                };
                (Key::Ecdsa(key.clone()), name, algorithms)
            }
            KeypairData::Rsa(rk) => {
                // Not `RsaPrivateKey::try_from(&RsaKeypair)`: ssh-key 0.6.7 passes
                // `p` twice as the primes, so validation rejects every real key.
                let big = |m: &ssh_key::Mpint| -> Result<rsa::BigUint> {
                    m.as_positive_bytes()
                        .map(rsa::BigUint::from_bytes_be)
                        .ok_or(Error::Crypto("host key: invalid RSA key"))
                };
                let private = rsa::RsaPrivateKey::from_components(
                    big(&rk.public.n)?,
                    big(&rk.public.e)?,
                    big(&rk.private.d)?,
                    vec![big(&rk.private.p)?, big(&rk.private.q)?],
                )
                .map_err(|_| Error::Crypto("host key: invalid RSA key"))?;
                (
                    Key::Rsa {
                        sha512: rsa::pkcs1v15::SigningKey::new(private.clone()),
                        sha256: rsa::pkcs1v15::SigningKey::new(private),
                    },
                    "ssh-rsa",
                    &["rsa-sha2-512", "rsa-sha2-256"],
                )
            }
            _ => {
                return Err(Error::Crypto(
                    "host key: only ssh-ed25519, ecdsa-sha2-nistp256/384/521 and RSA are supported",
                ))
            }
        };
        Ok(Self { key: inner, blob, key_type, algorithms })
    }

    /// Ed25519 seed; `None` for other key types.
    pub fn seed(&self) -> Option<[u8; 32]> {
        match &self.key {
            Key::Ed25519(k) => Some(k.to_bytes()),
            #[cfg(feature = "pubkey")]
            _ => None,
        }
    }

    /// Host key signature algorithms this key can produce, in preference order.
    pub fn algorithms(&self) -> &'static [&'static str] {
        self.algorithms
    }

    /// SSH wire encoding of the public key.
    pub fn public_blob(&self) -> &[u8] {
        &self.blob
    }

    /// Signature blob (`string algo || string sig`) for a negotiated `algo`.
    pub fn sign(&self, algo: &str, data: &[u8]) -> Result<Vec<u8>> {
        if !self.algorithms.contains(&algo) {
            return Err(Error::Crypto("host key: algorithm not supported by this key"));
        }
        let sig: Vec<u8> = match &self.key {
            Key::Ed25519(k) => k.sign(data).to_bytes().to_vec(),
            #[cfg(feature = "pubkey")]
            Key::Ecdsa(k) => {
                let s: ssh_key::Signature = signature::Signer::try_sign(k, data)
                    .map_err(|_| Error::Crypto("host key: ecdsa sign"))?;
                s.as_bytes().to_vec()
            }
            #[cfg(feature = "pubkey")]
            Key::Rsa { sha512, sha256 } => {
                use signature::{RandomizedSigner, SignatureEncoding};
                // Randomized = blinded private-key operation.
                let mut rng = rand::rngs::OsRng;
                let s = if algo == "rsa-sha2-512" {
                    sha512.try_sign_with_rng(&mut rng, data)
                } else {
                    sha256.try_sign_with_rng(&mut rng, data)
                }
                .map_err(|_| Error::Crypto("host key: rsa sign"))?;
                s.to_vec()
            }
        };
        let mut out = Vec::with_capacity(algo.len() + sig.len() + 8);
        wire::put_str(&mut out, algo);
        wire::put_bytes(&mut out, &sig);
        Ok(out)
    }

    pub fn openssh_public_line(&self, comment: &str) -> String {
        let mut s = format!("{} {}", self.key_type, wire::b64_encode(&self.blob));
        if !comment.is_empty() {
            s.push(' ');
            s.push_str(comment);
        }
        s
    }
}

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostKey({})", self.key_type)
    }
}

#[cfg(all(test, feature = "pubkey"))]
mod tests {
    use super::*;

    const FIXTURES: &[(&str, &str, &str)] = &[
        ("ed25519", include_str!("../tests/fixtures/hostkey_ed25519"), include_str!("../tests/fixtures/hostkey_ed25519.pub")),
        ("ecdsa256", include_str!("../tests/fixtures/hostkey_ecdsa256"), include_str!("../tests/fixtures/hostkey_ecdsa256.pub")),
        ("ecdsa384", include_str!("../tests/fixtures/hostkey_ecdsa384"), include_str!("../tests/fixtures/hostkey_ecdsa384.pub")),
        ("ecdsa521", include_str!("../tests/fixtures/hostkey_ecdsa521"), include_str!("../tests/fixtures/hostkey_ecdsa521.pub")),
        ("rsa2048", include_str!("../tests/fixtures/hostkey_rsa2048"), include_str!("../tests/fixtures/hostkey_rsa2048.pub")),
    ];

    #[test]
    fn openssh_pem_roundtrip() {
        let k = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let pem = k.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let hk = HostKey::from_openssh_pem(&pem).unwrap();
        let line = k.public_key().to_openssh().unwrap();
        assert_eq!(hk.openssh_public_line(""), line);
        assert!(HostKey::from_openssh_pem("garbage").is_err());
    }

    /// Every supported key type: the public line matches ssh-keygen's, and every
    /// advertised algorithm yields a signature the independent ssh-key verifier
    /// accepts under exactly that algorithm name.
    #[test]
    fn each_key_type_signs_verifiably() {
        use signature::Verifier;
        let msg = b"exchange-hash-under-test";
        for (name, pem, publine) in FIXTURES {
            let hk = HostKey::from_openssh_pem(pem).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(hk.openssh_public_line(""), publine.trim(), "{name}: public line");
            let pk = ssh_key::PublicKey::from_openssh(publine.trim()).unwrap();
            assert_eq!(hk.public_blob(), pk.to_bytes().unwrap().as_slice(), "{name}: blob");
            assert!(!hk.algorithms().is_empty());
            for algo in hk.algorithms() {
                let blob = hk.sign(algo, msg).unwrap();
                let sig = ssh_key::Signature::try_from(blob.as_slice()).unwrap();
                assert_eq!(sig.algorithm().as_str(), *algo, "{name}: sig algo");
                Verifier::verify(&pk, msg, &sig).unwrap_or_else(|e| panic!("{name}/{algo}: verify {e}"));
                assert!(Verifier::verify(&pk, b"other", &sig).is_err(), "{name}/{algo}: wrong msg verified");
            }
            assert!(hk.sign("ssh-dss", msg).is_err(), "{name}: unsupported algo must fail");
        }
    }

    #[test]
    fn rsa_offers_sha2_only() {
        let hk = HostKey::from_openssh_pem(FIXTURES[4].1).unwrap();
        assert_eq!(hk.algorithms(), &["rsa-sha2-512", "rsa-sha2-256"]);
        assert!(hk.sign("ssh-rsa", b"x").is_err());
        assert_eq!(hk.seed(), None);
    }
}
