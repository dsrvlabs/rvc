use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use async_trait::async_trait;
use crypto::{Keystore, SecretKey};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::{SigningBackend, SigningBackendError};

pub struct BasicSigner {
    #[allow(clippy::type_complexity)]
    keys: RwLock<HashMap<[u8; 48], (SecretKey, Mutex<()>)>>,
}

impl fmt::Debug for BasicSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_count = self.keys.try_read().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("BasicSigner").field("key_count", &key_count).finish()
    }
}

impl BasicSigner {
    pub fn load(
        keystore_dir: &Path,
        password: &Zeroizing<String>,
    ) -> Result<Self, SigningBackendError> {
        let mut keys = HashMap::new();

        let entries = std::fs::read_dir(keystore_dir).map_err(|e| {
            SigningBackendError::KeystoreLoadFailed(format!(
                "failed to read directory {}: {}",
                keystore_dir.display(),
                e
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SigningBackendError::KeystoreLoadFailed(format!("failed to read entry: {}", e))
            })?;

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let extension = path.extension().and_then(|e| e.to_str());
            if extension != Some("json") {
                continue;
            }

            check_file_permissions(&path);

            let keystore = Keystore::from_file(&path).map_err(|e| {
                SigningBackendError::KeystoreLoadFailed(format!(
                    "failed to load keystore {}: {}",
                    path.display(),
                    e
                ))
            })?;

            let secret_key = keystore.decrypt(password.as_bytes()).map_err(|e| {
                SigningBackendError::KeystoreLoadFailed(format!(
                    "failed to decrypt keystore {}: {}",
                    path.display(),
                    e
                ))
            })?;

            let pubkey = secret_key.public_key().to_bytes();
            info!(pubkey = %hex::encode(pubkey), path = %path.display(), "Loaded keystore");
            keys.insert(pubkey, (secret_key, Mutex::new(())));
        }

        info!(key_count = keys.len(), "BasicSigner loaded");
        Ok(Self { keys: RwLock::new(keys) })
    }

    pub async fn add_key(&self, pubkey: [u8; 48], secret_key: SecretKey) {
        let mut keys = self.keys.write().await;
        keys.insert(pubkey, (secret_key, Mutex::new(())));
    }

    pub async fn remove_key(&self, pubkey: &[u8; 48]) -> bool {
        let mut keys = self.keys.write().await;
        keys.remove(pubkey).is_some()
    }

    pub async fn loaded_pubkeys(&self) -> Vec<[u8; 48]> {
        let keys = self.keys.read().await;
        keys.keys().copied().collect()
    }
}

#[async_trait]
impl SigningBackend for BasicSigner {
    async fn sign(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<[u8; 96], SigningBackendError> {
        let keys = self.keys.read().await;
        let (secret_key, mutex): &(SecretKey, Mutex<()>) =
            keys.get(pubkey).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;

        let _guard = mutex.lock().await;
        let signature = secret_key.sign(signing_root);
        Ok(signature.to_bytes())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.keys.try_read().map(|k| k.keys().copied().collect()).unwrap_or_default()
    }
}

#[cfg(unix)]
fn check_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{:04o}", mode & 0o777),
                    "Keystore file is group/world-readable"
                );
            }
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to read file metadata");
        }
    }
}

#[cfg(not(unix))]
fn check_file_permissions(_path: &Path) {}

pub fn load_keystore_from_file(
    path: &Path,
    password: &Zeroizing<String>,
) -> Result<(SecretKey, [u8; 48]), SigningBackendError> {
    check_file_permissions(path);

    let keystore = Keystore::from_file(path).map_err(|e| {
        SigningBackendError::KeystoreLoadFailed(format!(
            "failed to load keystore {}: {}",
            path.display(),
            e
        ))
    })?;

    let secret_key = keystore.decrypt(password.as_bytes()).map_err(|e| {
        SigningBackendError::KeystoreLoadFailed(format!(
            "failed to decrypt keystore {}: {}",
            path.display(),
            e
        ))
    })?;

    let pubkey = secret_key.public_key().to_bytes();
    Ok((secret_key, pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{EncryptionKdf, Keystore as CryptoKeystore, Signature};
    use std::fs;
    use tempfile::TempDir;

    fn create_test_keystore(dir: &Path, password: &str) -> [u8; 48] {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();

        let keystore = CryptoKeystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2)
            .expect("encryption should succeed");

        let json = keystore.to_json().expect("serialize");
        let filename = format!("{}.json", hex::encode(pubkey));
        fs::write(dir.join(&filename), json).expect("write keystore");

        pubkey
    }

    #[tokio::test]
    async fn test_sign_verify_roundtrip() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);

        let signer = BasicSigner::load(dir.path(), &password).unwrap();

        let signing_root = [42u8; 32];
        let sig_bytes = signer.sign(&signing_root, &pubkey).await.unwrap();

        let sig = Signature::from_bytes(&sig_bytes).unwrap();
        let pk = crypto::PublicKey::from_bytes(&pubkey).unwrap();
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_unknown_key_returns_error() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let _pubkey = create_test_keystore(dir.path(), &password);

        let signer = BasicSigner::load(dir.path(), &password).unwrap();

        let unknown_pubkey = [0u8; 48];
        let signing_root = [1u8; 32];
        let result = signer.sign(&signing_root, &unknown_pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SigningBackendError::KeyNotFound(_)));
    }

    #[tokio::test]
    async fn test_empty_directory() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        assert!(signer.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_public_keys_returns_loaded_keys() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pk1 = create_test_keystore(dir.path(), &password);
        let pk2 = create_test_keystore(dir.path(), &password);

        let signer = BasicSigner::load(dir.path(), &password).unwrap();

        let keys = signer.public_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&pk1));
        assert!(keys.contains(&pk2));
    }

    #[tokio::test]
    async fn test_non_json_files_ignored() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        fs::write(dir.path().join("readme.txt"), "not a keystore").unwrap();
        fs::write(dir.path().join("data.bin"), b"\x00\x01\x02").unwrap();

        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        assert!(signer.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_subdirectories_ignored() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        fs::create_dir(dir.path().join("subdir")).unwrap();

        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        assert!(signer.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_invalid_keystore_returns_error() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        fs::write(dir.path().join("bad.json"), "not valid json").unwrap();

        let result = BasicSigner::load(dir.path(), &password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SigningBackendError::KeystoreLoadFailed(_)));
    }

    #[tokio::test]
    async fn test_wrong_password_returns_error() {
        let dir = TempDir::new().unwrap();
        let correct_password = Zeroizing::new("correct".to_string());
        let wrong_password = Zeroizing::new("wrong".to_string());
        create_test_keystore(dir.path(), &correct_password);

        let result = BasicSigner::load(dir.path(), &wrong_password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SigningBackendError::KeystoreLoadFailed(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_permission_check_warns_on_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);
        let filename = format!("{}.json", hex::encode(pubkey));
        let keystore_path = dir.path().join(&filename);

        // Set group-readable permissions
        fs::set_permissions(&keystore_path, fs::Permissions::from_mode(0o644)).unwrap();

        // Should still load successfully (permission check is warn-only)
        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        assert_eq!(signer.public_keys().len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_permission_check_no_warn_on_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);
        let filename = format!("{}.json", hex::encode(pubkey));
        let keystore_path = dir.path().join(&filename);

        fs::set_permissions(&keystore_path, fs::Permissions::from_mode(0o600)).unwrap();

        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        assert_eq!(signer.public_keys().len(), 1);
    }

    #[tokio::test]
    async fn test_nonexistent_directory_returns_error() {
        let password = Zeroizing::new("test".to_string());
        let result = BasicSigner::load(Path::new("/nonexistent/path"), &password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SigningBackendError::KeystoreLoadFailed(_)));
    }

    #[tokio::test]
    async fn test_concurrent_signing_same_key() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);

        let signer = std::sync::Arc::new(BasicSigner::load(dir.path(), &password).unwrap());

        let mut handles = Vec::new();
        for i in 0..10u8 {
            let signer = signer.clone();
            let pk = pubkey;
            handles.push(tokio::spawn(async move {
                let root = [i; 32];
                signer.sign(&root, &pk).await.unwrap()
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Each signing root is different, so signatures should differ
        for i in 1..results.len() {
            assert_ne!(results[0], results[i]);
        }
    }

    #[tokio::test]
    async fn test_add_key_makes_key_available() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let signer = BasicSigner::load(dir.path(), &password).unwrap();

        assert!(signer.public_keys().is_empty());

        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        signer.add_key(pubkey, sk).await;

        let keys = signer.public_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&pubkey));

        // Should be signable
        let signing_root = [42u8; 32];
        let result = signer.sign(&signing_root, &pubkey).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remove_key_makes_key_unavailable() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);

        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        assert_eq!(signer.public_keys().len(), 1);

        let removed = signer.remove_key(&pubkey).await;
        assert!(removed);
        assert!(signer.public_keys().is_empty());

        // Should no longer be signable
        let signing_root = [42u8; 32];
        let result = signer.sign(&signing_root, &pubkey).await;
        assert!(matches!(result.unwrap_err(), SigningBackendError::KeyNotFound(_)));
    }

    #[tokio::test]
    async fn test_remove_nonexistent_key_returns_false() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let signer = BasicSigner::load(dir.path(), &password).unwrap();

        let removed = signer.remove_key(&[0u8; 48]).await;
        assert!(!removed);
    }

    #[tokio::test]
    async fn test_load_keystore_from_file() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let expected_pubkey = create_test_keystore(dir.path(), &password);

        let filename = format!("{}.json", hex::encode(expected_pubkey));
        let path = dir.path().join(&filename);

        let (sk, pubkey) = load_keystore_from_file(&path, &password).unwrap();
        assert_eq!(pubkey, expected_pubkey);
        assert_eq!(sk.public_key().to_bytes(), expected_pubkey);
    }

    #[tokio::test]
    async fn test_load_keystore_from_file_wrong_password() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("correct".to_string());
        let wrong = Zeroizing::new("wrong".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);

        let filename = format!("{}.json", hex::encode(pubkey));
        let path = dir.path().join(&filename);

        let result = load_keystore_from_file(&path, &wrong);
        assert!(matches!(result.unwrap_err(), SigningBackendError::KeystoreLoadFailed(_)));
    }
}
