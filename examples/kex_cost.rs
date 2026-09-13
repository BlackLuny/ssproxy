//! Per-rekey server cost, split by component. A rekey every `rekey_bytes`
//! means this cost is paid once per `rekey_bytes` of traffic, so it sets a
//! hard ceiling on sustained throughput at small rekey intervals.
//!
//! cargo run --release --example kex_cost

use std::time::Instant;

use ssproxy::crypto::HashAlg;
use ssproxy::hostkey::HostKey;
use ssproxy::kex::{self, ClientKex, KexAlgo};

fn bench<F: FnMut()>(name: &str, iters: usize, mut f: F) {
    for _ in 0..iters / 10 {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let us = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
    println!("{name:34} {us:9.2} us");
}

fn main() {
    let iters = 20_000;

    let (client, q_c) = ClientKex::start(KexAlgo::Curve25519Sha256);
    let (q_s, _k) = kex::server_exchange(KexAlgo::Curve25519Sha256, &q_c).unwrap();
    let _ = (client, q_s);

    bench("kex server_exchange (x25519)", iters, || {
        let _ = kex::server_exchange(KexAlgo::Curve25519Sha256, &q_c).unwrap();
    });

    let (client, q_c) = ClientKex::start(KexAlgo::EcdhSha2NistP256);
    bench("kex server_exchange (p256)", iters, || {
        let _ = kex::server_exchange(KexAlgo::EcdhSha2NistP256, &q_c).unwrap();
    });
    drop(client);

    let hk = HostKey::generate();
    let h = [7u8; 32];
    bench("hostkey sign (ed25519)", iters, || {
        let _ = hk.sign(&h);
    });

    let buf = [0u8; 1024];
    bench("sha256(1024B)", iters, || {
        let _ = HashAlg::Sha256.digest_parts(&[&buf]);
    });

    // A rekey's KDF: two 64-byte blocks through the RFC 4253 expansion.
    bench("kdf 2x64B (chacha)", iters, || {
        use ssproxy::crypto::CipherKind;
        let _ = (CipherKind::ChaCha20Poly1305.key_len(), CipherKind::ChaCha20Poly1305.iv_len());
        let mut out = [0u8; 64];
        ssproxy::crypto::kdf::derive(HashAlg::Sha256, &[3u8; 32], &[4u8; 32], &[5u8; 32], b'C', &mut out);
        ssproxy::crypto::kdf::derive(HashAlg::Sha256, &[3u8; 32], &[4u8; 32], &[5u8; 32], b'D', &mut out);
    });
    let _ = q_s;
}
