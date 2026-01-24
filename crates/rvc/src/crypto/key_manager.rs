use std::collections::HashMap;
use std::fs;
use std::path::Path;

use tracing::warn;

use super::bls::{PublicKey, SecretKey, PUBLIC_KEY_BYTES_LEN};
use super::error::KeyManagerError;
use super::keystore::Keystore;

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
    /// and the corresponding password strings as values.
    ///
    /// Corrupted or unreadable keystores are logged and skipped.
    /// Files outside the directory boundary (e.g., via symlinks) are also skipped
    /// to prevent directory traversal attacks.
    pub fn load_from_directory<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, String>,
    ) -> Result<Self, KeyManagerError> {
        let dir_path = path.as_ref();

        if !dir_path.exists() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        if !dir_path.is_dir() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        let canonical_dir = dir_path.canonicalize().map_err(KeyManagerError::Io)?;

        let mut manager = Self::new();
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

            let secret_key = match keystore.decrypt(password.as_bytes()) {
                Ok(sk) => sk,
                Err(e) => {
                    warn!("Failed to decrypt keystore {:?}: {}", file_path, e);
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
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
        assert!(!manager.is_empty());
    }

    #[test]
    fn test_get_secret_key() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

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
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

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
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

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
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_graceful_handling_of_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), "wrong_password".to_string());

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
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

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
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

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
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();

        let secret_key = manager.get_secret_key(&pubkey).unwrap();
        let message = b"test message";
        let signature = secret_key.sign(message);

        assert!(signature.verify(&pubkey, message).is_ok());
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
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

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
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

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
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_string());

            let result = KeyManager::load_from_directory(&keystore_dir_path, &passwords);

            assert!(
                matches!(result, Err(KeyManagerError::NoKeystoreFiles)),
                "Symlink pointing to parent directory should be skipped"
            );
        }
    }
}
