use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info, warn};

use super::bls::{PublicKey, SecretKey, PUBLIC_KEY_BYTES_LEN};
use super::decryption_tracker::DecryptionAttemptTracker;
use super::error::KeyManagerError;
use super::keystore::Keystore;

/// A prepared decryption work item. Produced by Phase 1, consumed by Phase 2.
struct DecryptionTask<'a> {
    file_path: PathBuf,
    keystore: Keystore,
    password: &'a [u8],
    declared_pubkey_hex: String,
}

/// Result of a single decryption attempt. Produced by Phase 2, consumed by Phase 3.
enum DecryptionOutcome {
    Success {
        pubkey_bytes: [u8; PUBLIC_KEY_BYTES_LEN],
        secret_key: SecretKey,
        pubkey_hex: String,
        file_path: PathBuf,
    },
    Failure {
        pubkey_hex: String,
        file_path: PathBuf,
        error: String,
    },
}

pub struct KeyManager {
    keys: HashMap<[u8; PUBLIC_KEY_BYTES_LEN], SecretKey>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    /// Loads all keystore files from a directory.
    ///
    /// The `passwords` map uses public key hex strings (without 0x prefix) as keys
    /// and `SecretString` values for secure password handling.
    ///
    /// Passwords are automatically zeroized when the HashMap is dropped.
    /// Corrupted or unreadable keystores are logged and skipped.
    /// Files outside the directory boundary (e.g., via symlinks) are also skipped
    /// to prevent directory traversal attacks.
    ///
    /// Delegates to `load_from_directory_with_threads` with auto-detected thread count.
    pub fn load_from_directory<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, SecretString>,
    ) -> Result<Self, KeyManagerError> {
        Self::load_from_directory_with_threads(path, passwords, None)
    }

    /// Loads all keystore files from a directory using parallel decryption.
    ///
    /// Uses a dedicated rayon thread pool to decrypt keystores in parallel.
    /// The `num_threads` parameter controls the pool size; `None` auto-detects
    /// from available CPU parallelism (clamped to 1..=32).
    ///
    /// The pipeline runs in 3 phases:
    /// 1. **Sequential** — directory scan, validation, keystore parsing, task collection
    /// 2. **Parallel** — keystore decryption and public key verification via rayon
    /// 3. **Sequential** — result aggregation, logging, KeyManager construction
    pub fn load_from_directory_with_threads<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, SecretString>,
        num_threads: Option<usize>,
    ) -> Result<Self, KeyManagerError> {
        let dir_path = path.as_ref();

        if !dir_path.exists() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        if !dir_path.is_dir() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        let canonical_dir = dir_path.canonicalize().map_err(KeyManagerError::Io)?;

        info!(path = ?canonical_dir, "Loading validator keys from directory");

        // ── Phase 1: Sequential scan ──────────────────────────────────────
        let mut tasks: Vec<DecryptionTask<'_>> = Vec::new();
        let mut found_any_keystore = false;

        let entries = fs::read_dir(&canonical_dir)?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("Failed to read directory entry: {}", e);
                    continue;
                }
            };

            let file_path = entry.path();

            let canonical_file = match file_path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to canonicalize {:?}: {}", file_path, e);
                    continue;
                }
            };

            if !canonical_file.starts_with(&canonical_dir) {
                warn!(
                    "Skipping file outside keystore directory (possible symlink attack): {:?}",
                    file_path
                );
                continue;
            }

            if !canonical_file.is_file() {
                continue;
            }

            let extension = file_path.extension().and_then(|ext| ext.to_str());
            if extension != Some("json") {
                continue;
            }

            found_any_keystore = true;

            let keystore = match Keystore::from_file(&file_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Failed to load keystore from {:?}: {}", file_path, e);
                    continue;
                }
            };

            let pubkey_hex = match &keystore.pubkey {
                Some(pk) => pk.clone(),
                None => {
                    warn!("Keystore {:?} has no public key field, skipping", file_path);
                    continue;
                }
            };

            let password = match passwords.get(&pubkey_hex) {
                Some(p) => p,
                None => {
                    warn!(
                        "No password found for public key {} in {:?}, skipping",
                        pubkey_hex, file_path
                    );
                    continue;
                }
            };

            tasks.push(DecryptionTask {
                file_path,
                keystore,
                password: password.expose_secret().as_bytes(),
                declared_pubkey_hex: pubkey_hex,
            });
        }

        if !found_any_keystore {
            return Err(KeyManagerError::NoKeystoreFiles);
        }

        // ── Phase 2: Parallel decryption ──────────────────────────────────
        let num_threads = num_threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
        let num_threads = num_threads.clamp(1, 32);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|i| format!("rvc-decrypt-{}", i))
            .build()
            .map_err(|e| KeyManagerError::ThreadPoolError(e.to_string()))?;

        let results: Vec<DecryptionOutcome> = pool.install(|| {
            tasks
                .into_par_iter()
                .map(|task| {
                    let secret_key = match task.keystore.decrypt(task.password) {
                        Ok(sk) => sk,
                        Err(e) => {
                            return DecryptionOutcome::Failure {
                                pubkey_hex: task.declared_pubkey_hex,
                                file_path: task.file_path,
                                error: e.to_string(),
                            };
                        }
                    };

                    let derived = secret_key.public_key();

                    let expected_bytes = match hex::decode(&task.declared_pubkey_hex) {
                        Ok(b) => b,
                        Err(_) => {
                            return DecryptionOutcome::Failure {
                                pubkey_hex: task.declared_pubkey_hex,
                                file_path: task.file_path,
                                error: "invalid pubkey hex".to_string(),
                            };
                        }
                    };

                    let expected = match PublicKey::from_bytes(&expected_bytes) {
                        Ok(pk) => pk,
                        Err(_) => {
                            return DecryptionOutcome::Failure {
                                pubkey_hex: task.declared_pubkey_hex,
                                file_path: task.file_path,
                                error: "invalid pubkey format".to_string(),
                            };
                        }
                    };

                    if derived.to_bytes() != expected.to_bytes() {
                        let error = format!(
                            "pubkey mismatch: declared {} but derived {}",
                            task.declared_pubkey_hex,
                            hex::encode(derived.to_bytes())
                        );
                        return DecryptionOutcome::Failure {
                            pubkey_hex: task.declared_pubkey_hex,
                            file_path: task.file_path,
                            error,
                        };
                    }

                    DecryptionOutcome::Success {
                        pubkey_bytes: derived.to_bytes(),
                        secret_key,
                        pubkey_hex: task.declared_pubkey_hex,
                        file_path: task.file_path,
                    }
                })
                .collect()
        });

        // ── Phase 3: Sequential aggregation ───────────────────────────────
        let mut keys = HashMap::new();

        for outcome in results {
            match outcome {
                DecryptionOutcome::Success { pubkey_bytes, secret_key, pubkey_hex, file_path } => {
                    debug!(pubkey = %pubkey_hex, file = ?file_path, "Loaded validator key");
                    keys.insert(pubkey_bytes, secret_key);
                }
                DecryptionOutcome::Failure { pubkey_hex, file_path, error } => {
                    warn!(
                        pubkey = %pubkey_hex,
                        file = ?file_path,
                        error = %error,
                        "Failed to decrypt keystore"
                    );
                }
            }
        }

        let loaded_pubkeys: Vec<String> =
            keys.keys().map(|k| format!("0x{}", hex::encode(k))).collect();
        info!(
            loaded = keys.len(),
            pubkeys = ?loaded_pubkeys,
            path = ?canonical_dir,
            "Finished loading validator keys"
        );

        Ok(Self { keys })
    }

    /// Loads all keystore files from a directory with decryption attempt tracking.
    ///
    /// This method is similar to `load_from_directory` but accepts a mutable reference
    /// to a `DecryptionAttemptTracker` for rate limiting and auditing failed decryption
    /// attempts.
    ///
    /// The tracker will:
    /// - Record all decryption attempts
    /// - Log warnings for failed attempts
    /// - Block attempts when rate limit is exceeded
    pub fn load_from_directory_with_tracker<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, String>,
        tracker: &mut DecryptionAttemptTracker,
    ) -> Result<Self, KeyManagerError> {
        let dir_path = path.as_ref();

        if !dir_path.exists() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        if !dir_path.is_dir() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        let mut manager = Self::new();
        let mut found_any_keystore = false;

        let entries = fs::read_dir(dir_path)?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("Failed to read directory entry: {}", e);
                    continue;
                }
            };

            let file_path = entry.path();

            if !file_path.is_file() {
                continue;
            }

            let extension = file_path.extension().and_then(|ext| ext.to_str());
            if extension != Some("json") {
                continue;
            }

            found_any_keystore = true;

            let keystore = match Keystore::from_file(&file_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Failed to load keystore from {:?}: {}", file_path, e);
                    continue;
                }
            };

            let pubkey_hex = match &keystore.pubkey {
                Some(pk) => pk.clone(),
                None => {
                    warn!("Keystore {:?} has no public key field, skipping", file_path);
                    continue;
                }
            };

            // Check rate limit before attempting decryption
            if !tracker.check_and_record(&pubkey_hex) {
                warn!(
                    pubkey = %pubkey_hex,
                    file = ?file_path,
                    "Skipping keystore due to rate limit"
                );
                continue;
            }

            let password = match passwords.get(&pubkey_hex) {
                Some(p) => p,
                None => {
                    warn!(
                        "No password found for public key {} in {:?}, skipping",
                        pubkey_hex, file_path
                    );
                    continue;
                }
            };

            let secret_key = match keystore.decrypt(password.as_bytes()) {
                Ok(sk) => sk,
                Err(e) => {
                    tracker.record_failure(&pubkey_hex);
                    warn!(
                        pubkey = %pubkey_hex,
                        file = ?file_path,
                        error = %e,
                        "Failed decryption attempt for keystore"
                    );
                    continue;
                }
            };

            let public_key = secret_key.public_key();
            manager.keys.insert(public_key.to_bytes(), secret_key);
        }

        if !found_any_keystore {
            return Err(KeyManagerError::NoKeystoreFiles);
        }

        Ok(manager)
    }

    pub fn get_secret_key(&self, pubkey: &PublicKey) -> Option<&SecretKey> {
        self.keys.get(&pubkey.to_bytes())
    }

    pub fn list_public_keys(&self) -> Vec<PublicKey> {
        self.keys.keys().filter_map(|bytes| PublicKey::from_bytes(bytes).ok()).collect()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Inserts a secret key into the key manager.
    /// This is only available for testing purposes.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn insert(&mut self, secret_key: SecretKey) {
        let pubkey = secret_key.public_key();
        self.keys.insert(pubkey.to_bytes(), secret_key);
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use secrecy::SecretString;
    use tempfile::TempDir;

    use super::*;

    const TEST_KEYSTORE_PBKDF2: &str = r#"
    {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32,
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
            }
        },
        "description": "Test keystore",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }
    "#;

    const TEST_PASSWORD: &[u8] = &[
        0x74, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xf0, 0x9f, 0x94,
        0x91,
    ];

    const TEST_PUBKEY_HEX: &str =
        "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

    fn create_test_keystore_file(dir: &TempDir, filename: &str, content: &str) {
        let file_path = dir.path().join(filename);
        let mut file = File::create(file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }

    fn test_password_string() -> String {
        String::from_utf8(TEST_PASSWORD.to_vec()).unwrap()
    }

    fn test_password_secret() -> SecretString {
        SecretString::from(test_password_string())
    }

    #[test]
    fn test_new_key_manager_is_empty() {
        let manager = KeyManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_load_from_directory_not_found() {
        let passwords = HashMap::new();
        let result = KeyManager::load_from_directory("/nonexistent/path", &passwords);
        assert!(matches!(result, Err(KeyManagerError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_load_from_directory_empty() {
        let temp_dir = TempDir::new().unwrap();
        let passwords = HashMap::new();
        let result = KeyManager::load_from_directory(temp_dir.path(), &passwords);
        assert!(matches!(result, Err(KeyManagerError::NoKeystoreFiles)));
    }

    #[test]
    fn test_load_from_directory_with_valid_keystore() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
        assert!(!manager.is_empty());
    }

    #[test]
    fn test_get_secret_key() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();

        let secret_key = manager.get_secret_key(&pubkey);
        assert!(secret_key.is_some());

        let sk = secret_key.unwrap();
        assert_eq!(sk.public_key().to_bytes(), pubkey.to_bytes());
    }

    #[test]
    fn test_get_secret_key_not_found() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let other_sk = SecretKey::generate();
        let other_pk = other_sk.public_key();

        assert!(manager.get_secret_key(&other_pk).is_none());
    }

    #[test]
    fn test_list_public_keys() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let public_keys = manager.list_public_keys();
        assert_eq!(public_keys.len(), 1);

        let expected_pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).unwrap();
        assert_eq!(public_keys[0].to_bytes().to_vec(), expected_pubkey_bytes);
    }

    #[test]
    fn test_graceful_handling_of_corrupted_keystore() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "corrupted.json", "{ invalid json }");
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_graceful_handling_of_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords
            .insert(TEST_PUBKEY_HEX.to_string(), SecretString::from("wrong_password".to_string()));

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_graceful_handling_of_missing_password() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let passwords = HashMap::new();

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_ignores_non_json_files() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "readme.txt", "This is not a keystore");
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_keystore_without_pubkey_field() {
        let keystore_without_pubkey = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "no_pubkey.json", keystore_without_pubkey);
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_default_impl() {
        let manager = KeyManager::default();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_secret_key_can_sign() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();

        let secret_key = manager.get_secret_key(&pubkey).unwrap();
        let message = b"test message";
        let signature = secret_key.sign(message);

        assert!(signature.verify(&pubkey, message).is_ok());
    }

    #[test]
    fn test_load_with_tracker_success() {
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

        let mut tracker = DecryptionAttemptTracker::new(5, Duration::from_secs(60));

        let manager =
            KeyManager::load_from_directory_with_tracker(temp_dir.path(), &passwords, &mut tracker)
                .unwrap();

        assert_eq!(manager.len(), 1);
        assert_eq!(tracker.attempt_count(TEST_PUBKEY_HEX), 1);
    }

    #[test]
    fn test_load_with_tracker_records_failure() {
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), "wrong_password".to_string());

        let mut tracker = DecryptionAttemptTracker::new(5, Duration::from_secs(60));

        let manager =
            KeyManager::load_from_directory_with_tracker(temp_dir.path(), &passwords, &mut tracker)
                .unwrap();

        assert!(manager.is_empty());
        // Attempt was recorded
        assert_eq!(tracker.attempt_count(TEST_PUBKEY_HEX), 1);
    }

    #[test]
    fn test_load_with_tracker_rate_limit() {
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), "wrong_password".to_string());

        // Only allow 2 attempts
        let mut tracker = DecryptionAttemptTracker::new(2, Duration::from_secs(60));

        // First load - will fail decryption but record attempt
        let _ =
            KeyManager::load_from_directory_with_tracker(temp_dir.path(), &passwords, &mut tracker);
        assert_eq!(tracker.attempt_count(TEST_PUBKEY_HEX), 1);

        // Second load - will fail decryption but record attempt
        let _ =
            KeyManager::load_from_directory_with_tracker(temp_dir.path(), &passwords, &mut tracker);
        assert_eq!(tracker.attempt_count(TEST_PUBKEY_HEX), 2);

        // Third load - should be rate limited, no new attempt recorded
        let _ =
            KeyManager::load_from_directory_with_tracker(temp_dir.path(), &passwords, &mut tracker);
        // Still 2 because the third attempt was blocked
        assert_eq!(tracker.attempt_count(TEST_PUBKEY_HEX), 2);
    }

    #[test]
    fn test_keystore_with_mismatched_pubkey_is_skipped() {
        // This keystore has a WRONG pubkey field - it declares a different public key
        // than what the secret key actually derives to.
        // The declared pubkey is all zeros (a valid hex string but wrong key).
        let keystore_with_wrong_pubkey = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "Test keystore with wrong pubkey",
            "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a84",
            "version": 4
        }
        "#;

        let wrong_pubkey_hex =
            "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c";

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "wrong_pubkey.json", keystore_with_wrong_pubkey);

        let mut passwords = HashMap::new();
        // We provide the password for the DECLARED (wrong) pubkey
        passwords.insert(wrong_pubkey_hex.to_string(), SecretString::from(test_password_string()));

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        // The keystore should be skipped because the derived pubkey doesn't match the declared one
        assert!(manager.is_empty());
    }

    #[test]
    fn test_keystore_with_invalid_pubkey_hex_is_skipped() {
        // This keystore has an invalid pubkey hex string (not valid hex / wrong length)
        let keystore_with_invalid_pubkey = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "Test keystore with invalid pubkey hex",
            "pubkey": "invalid_hex_string_not_valid_zzz",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a85",
            "version": 4
        }
        "#;

        let invalid_pubkey_hex = "invalid_hex_string_not_valid_zzz";

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "invalid_pubkey.json", keystore_with_invalid_pubkey);

        let mut passwords = HashMap::new();
        passwords
            .insert(invalid_pubkey_hex.to_string(), SecretString::from(test_password_string()));

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        // The keystore should be skipped because the pubkey hex is invalid
        assert!(manager.is_empty());
    }

    #[cfg(unix)]
    mod symlink_tests {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::path::PathBuf;

        fn create_keystore_file_at_path(path: &PathBuf, content: &str) {
            let mut file = File::create(path).unwrap();
            file.write_all(content.as_bytes()).unwrap();
        }

        #[test]
        fn test_symlink_outside_directory_is_skipped() {
            let keystore_dir = TempDir::new().unwrap();
            let outside_dir = TempDir::new().unwrap();

            let outside_keystore = outside_dir.path().join("secret_keystore.json");
            create_keystore_file_at_path(&outside_keystore, TEST_KEYSTORE_PBKDF2);

            let symlink_path = keystore_dir.path().join("malicious_link.json");
            symlink(&outside_keystore, &symlink_path).unwrap();

            let mut passwords = HashMap::new();
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

            let result = KeyManager::load_from_directory(keystore_dir.path(), &passwords);

            assert!(
                matches!(result, Err(KeyManagerError::NoKeystoreFiles)),
                "Symlink pointing outside directory should be skipped"
            );
        }

        #[test]
        fn test_symlink_within_directory_is_allowed() {
            let keystore_dir = TempDir::new().unwrap();

            let actual_keystore = keystore_dir.path().join("actual_keystore.json");
            create_keystore_file_at_path(&actual_keystore, TEST_KEYSTORE_PBKDF2);

            let symlink_path = keystore_dir.path().join("link_to_keystore.json");
            symlink(&actual_keystore, &symlink_path).unwrap();

            let mut passwords = HashMap::new();
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

            let manager = KeyManager::load_from_directory(keystore_dir.path(), &passwords).unwrap();

            assert_eq!(manager.len(), 1, "Symlink within directory should be allowed");
        }

        #[test]
        fn test_symlink_to_parent_directory_is_skipped() {
            let parent_dir = TempDir::new().unwrap();
            let keystore_dir_path = parent_dir.path().join("keystores");
            fs::create_dir(&keystore_dir_path).unwrap();

            let parent_keystore = parent_dir.path().join("parent_keystore.json");
            create_keystore_file_at_path(&parent_keystore, TEST_KEYSTORE_PBKDF2);

            let symlink_path = keystore_dir_path.join("parent_link.json");
            symlink(&parent_keystore, &symlink_path).unwrap();

            let mut passwords = HashMap::new();
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

            let result = KeyManager::load_from_directory(&keystore_dir_path, &passwords);

            assert!(
                matches!(result, Err(KeyManagerError::NoKeystoreFiles)),
                "Symlink pointing to parent directory should be skipped"
            );
        }
    }

    #[test]
    fn test_secret_string_password_is_not_exposed_in_debug() {
        let secret = test_password_secret();
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains(&test_password_string()));
    }
}
