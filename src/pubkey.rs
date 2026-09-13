//! Public-key user authentication (RFC 4252 §7).

/// Signature algorithms advertised in `server-sig-algs` and accepted.
pub const SIG_ALGS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

pub fn is_supported(algo: &str) -> bool {
    cfg!(feature = "pubkey") && SIG_ALGS.contains(&algo)
}

/// Verify `sig_blob` over `msg` with the SSH-encoded public key `key_blob`
/// for request algorithm `algo`.
#[cfg(feature = "pubkey")]
pub fn verify(algo: &str, key_blob: &[u8], sig_blob: &[u8], msg: &[u8]) -> bool {
    use signature::Verifier;

    if !is_supported(algo) {
        return false;
    }
    let Ok(key) = ssh_key::PublicKey::from_bytes(key_blob) else {
        return false;
    };
    let Ok(sig) = ssh_key::Signature::try_from(sig_blob) else {
        return false;
    };
    if sig.algorithm().as_str() != algo {
        return false;
    }
    let key_ok = match key.algorithm() {
        ssh_key::Algorithm::Rsa { .. } => algo.starts_with("rsa-sha2-"),
        other => other.as_str() == algo,
    };
    key_ok && Verifier::verify(&key, msg, &sig).is_ok()
}

#[cfg(not(feature = "pubkey"))]
pub fn verify(_: &str, _: &[u8], _: &[u8], _: &[u8]) -> bool {
    false
}

/// Key algorithm of a request must match the blob type.
#[cfg(feature = "pubkey")]
pub fn blob_matches(algo: &str, key_blob: &[u8]) -> bool {
    match ssh_key::PublicKey::from_bytes(key_blob) {
        Ok(k) => match k.algorithm() {
            ssh_key::Algorithm::Rsa { .. } => algo.starts_with("rsa-sha2-"),
            other => other.as_str() == algo,
        },
        Err(_) => false,
    }
}

#[cfg(not(feature = "pubkey"))]
pub fn blob_matches(_: &str, _: &[u8]) -> bool {
    false
}

#[cfg(all(test, feature = "pubkey"))]
mod tests {
    use super::*;
    use signature::Signer;
    use ssh_encoding::Encode;

    fn encode_vec<T: Encode>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        v.encode(&mut out).unwrap();
        out
    }

    fn check(alg: ssh_key::Algorithm, req_algo: &str) {
        let k = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, alg).unwrap();
        let blob = encode_vec(k.public_key().key_data());
        let msg = b"session-id-and-request";
        let sig: ssh_key::Signature = k.try_sign(msg).unwrap();
        let sig_blob = encode_vec(&sig);
        assert!(blob_matches(req_algo, &blob));
        assert!(verify(req_algo, &blob, &sig_blob, msg), "{req_algo}");
        assert!(!verify(req_algo, &blob, &sig_blob, b"other"));
    }

    #[test]
    fn ed25519_and_ecdsa() {
        check(ssh_key::Algorithm::Ed25519, "ssh-ed25519");
        check(
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            "ecdsa-sha2-nistp256",
        );
    }
}
