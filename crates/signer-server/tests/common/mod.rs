//! Shared fixture helpers for signer-server integration tests.

#![allow(dead_code)]

use std::path::Path;

/// Create a cheap test keystore under `dir` and return its public key bytes.
pub fn create_test_keystore(dir: &Path, password: &str) -> [u8; 48] {
    use crypto::{EncryptionKdf, Keystore, SecretKey};
    let sk = SecretKey::generate();
    let pubkey = sk.public_key().to_bytes();
    let ks =
        Keystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::scrypt_cheap_for_tests())
            .expect("encrypt");
    let filename = format!("{}.json", hex::encode(pubkey));
    std::fs::write(dir.join(&filename), ks.to_json().unwrap()).unwrap();
    pubkey
}
