//! Test-only helpers for EIP-2335 keystore fixtures.
//!
//! Gated by the `test-utils` feature. Enable only from `[dev-dependencies]`:
//!
//! ```toml
//! [dev-dependencies]
//! crypto = { workspace = true, features = ["test-utils"] }
//! ```

use std::path::{Path, PathBuf};

use crate::{EncryptionKdf, Keystore, SecretKey, PUBLIC_KEY_BYTES_LEN};

/// On-disk test keystore produced by [`create_test_keystore`].
#[derive(Debug)]
pub struct TestKeystore {
    /// Absolute path of the written JSON file.
    pub path: PathBuf,
    /// Secret key that was encrypted into the file.
    pub secret_key: SecretKey,
    /// Encrypted keystore value (also serialized to [`Self::path`]).
    pub keystore: Keystore,
}

impl TestKeystore {
    /// Compressed BLS public key bytes for the fixture secret key.
    #[must_use]
    pub fn pubkey(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.secret_key.public_key().to_bytes()
    }
}

/// Create a cheap EIP-2335 keystore under `dir` for tests.
///
/// Covers the former local helpers (pubkey-only, `(path, sk)`, `(pubkey, sk)`):
/// - Generates a random secret key when `secret_key` is `None`.
/// - Writes `{hex(pubkey)}.json` using [`EncryptionKdf::scrypt_cheap_for_tests`].
/// - Returns path, secret key, and keystore so callers can take what they need.
///
/// # Panics
///
/// Panics on encryption or I/O failure (test helper).
pub fn create_test_keystore(
    dir: &Path,
    password: &str,
    secret_key: Option<SecretKey>,
) -> TestKeystore {
    let secret_key = secret_key.unwrap_or_else(SecretKey::generate);
    let pubkey = secret_key.public_key().to_bytes();
    let keystore = Keystore::encrypt(
        &secret_key,
        password.as_bytes(),
        "",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("test keystore encrypt");
    let path = dir.join(format!("{}.json", hex::encode(pubkey)));
    std::fs::write(&path, keystore.to_json().expect("serialize test keystore"))
        .expect("write test keystore");
    TestKeystore { path, secret_key, keystore }
}
