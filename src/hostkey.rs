use ed25519_dalek::{Signer, SigningKey};

use crate::error::{Error, Result};
use crate::wire;

/// Server host key (`ssh-ed25519`).
pub struct HostKey {
    signing: SigningKey,
    blob: Vec<u8>,
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
        Self { signing, blob }
    }

    /// Parse an unencrypted OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    #[cfg(feature = "pubkey")]
    pub fn from_openssh_pem(pem: &str) -> Result<Self> {
        let key = ssh_key::PrivateKey::from_openssh(pem.trim())
            .map_err(|_| Error::Crypto("host key: not an OpenSSH private key"))?;
        if key.is_encrypted() {
            return Err(Error::Crypto("host key: encrypted keys are not supported"));
        }
        let ed = key
            .key_data()
            .ed25519()
            .ok_or(Error::Crypto("host key: only ssh-ed25519 is supported"))?;
        Ok(Self::from_seed(&ed.private.to_bytes()))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// SSH wire encoding of the public key.
    pub fn public_blob(&self) -> &[u8] {
        &self.blob
    }

    /// Signature blob (`string "ssh-ed25519" || string sig`).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let sig = self.signing.sign(data);
        let mut out = Vec::with_capacity(83);
        wire::put_str(&mut out, Self::ALGORITHM);
        wire::put_bytes(&mut out, &sig.to_bytes());
        out
    }

    pub fn openssh_public_line(&self, comment: &str) -> String {
        let mut s = format!("{} {}", Self::ALGORITHM, wire::b64_encode(&self.blob));
        if !comment.is_empty() {
            s.push(' ');
            s.push_str(comment);
        }
        s
    }
}

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostKey(ssh-ed25519)")
    }
}

#[cfg(all(test, feature = "pubkey"))]
mod tests {
    use super::*;

    #[test]
    fn openssh_pem_roundtrip() {
        let k = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let pem = k.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let hk = HostKey::from_openssh_pem(&pem).unwrap();
        let line = k.public_key().to_openssh().unwrap();
        assert_eq!(hk.openssh_public_line(""), line);
        assert!(HostKey::from_openssh_pem("garbage").is_err());
    }
}
