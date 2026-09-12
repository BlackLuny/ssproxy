use sha2::{Digest, Sha256};

use crate::crypto::CipherKind;

/// RFC 4253 §7.2 key derivation. `k_mpint` is the SSH mpint encoding of K.
pub fn derive_block(k_mpint: &[u8], h: &[u8], session_id: &[u8], letter: u8, out: &mut [u8]) {
    let mut key = {
        let mut hasher = Sha256::new();
        hasher.update(k_mpint);
        hasher.update(h);
        hasher.update([letter]);
        hasher.update(session_id);
        hasher.finalize().to_vec()
    };
    while key.len() < out.len() {
        let mut hasher = Sha256::new();
        hasher.update(k_mpint);
        hasher.update(h);
        hasher.update(&key);
        key.extend_from_slice(&hasher.finalize());
    }
    out.copy_from_slice(&key[..out.len()]);
}

pub struct DerivedKeys {
    pub send_key: Vec<u8>,
    pub send_iv: Vec<u8>,
    pub recv_key: Vec<u8>,
    pub recv_iv: Vec<u8>,
}

/// `is_server` selects C/D (keys) and A/B (IVs) mapping.
pub fn derive_keys(
    k_mpint: &[u8],
    h: &[u8],
    session_id: &[u8],
    cipher: CipherKind,
    is_server: bool,
) -> DerivedKeys {
    let kl = cipher.key_len();
    let il = cipher.iv_len().max(0);
    // Always derive something so letter usage is stable even when iv_len==0.
    let iv_need = if il == 0 { 8 } else { il };

    let (send_k, recv_k, send_iv, recv_iv) = if is_server {
        (b'D', b'C', b'B', b'A')
    } else {
        (b'C', b'D', b'A', b'B')
    };

    let mut send_key = vec![0u8; kl];
    let mut recv_key = vec![0u8; kl];
    let mut send_iv_buf = vec![0u8; iv_need];
    let mut recv_iv_buf = vec![0u8; iv_need];

    if kl > 0 {
        derive_block(k_mpint, h, session_id, send_k, &mut send_key);
        derive_block(k_mpint, h, session_id, recv_k, &mut recv_key);
    }
    derive_block(k_mpint, h, session_id, send_iv, &mut send_iv_buf);
    derive_block(k_mpint, h, session_id, recv_iv, &mut recv_iv_buf);

    if il == 0 {
        send_iv_buf.clear();
        recv_iv_buf.clear();
    }

    DerivedKeys {
        send_key,
        send_iv: send_iv_buf,
        recv_key,
        recv_iv: recv_iv_buf,
    }
}
