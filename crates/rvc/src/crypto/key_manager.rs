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

            let derived_pubkey = secret_key.public_key();

            let expected_pubkey_bytes = match hex::decode(&pubkey_hex) {
                Ok(bytes) => bytes,
                Err(_) => {
                    warn!(
                        "Invalid public key hex format in keystore {:?}: {}",
                        file_path, pubkey_hex
                    );
                    continue;
                }
            };

            let expected_pubkey = match PublicKey::from_bytes(&expected_pubkey_bytes) {
                Ok(pk) => pk,
                Err(_) => {
                    warn!("Invalid public key format in keystore {:?}: {}", file_path, pubkey_hex);
                    continue;
                }
            };

            if derived_pubkey.to_bytes() != expected_pubkey.to_bytes() {
                warn!(
                    "Public key mismatch in keystore {:?}: declared {} but derived {}",
                    file_path,
                    pubkey_hex,
                    hex::encode(derived_pubkey.to_bytes())
                );
                continue;
            }

            manager.keys.insert(derived_pubkey.to_bytes(), secret_key);
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
        passwords.insert(wrong_pubkey_hex.to_string(), test_password_string());

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
        passwords.insert(invalid_pubkey_hex.to_string(), test_password_string());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        // The keystore should be skipped because the pubkey hex is invalid
        assert!(manager.is_empty());
    }
}
