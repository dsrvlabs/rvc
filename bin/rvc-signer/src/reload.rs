use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crypto::logging::TruncatedPubkey;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::backend::basic::{load_keystore_from_file, BasicSigner};

pub struct KeystoreReloader {
    dir: PathBuf,
    password: Zeroizing<String>,
    interval: Duration,
    backend: Arc<BasicSigner>,
}

impl KeystoreReloader {
    pub fn new(
        dir: PathBuf,
        password: Zeroizing<String>,
        interval: Duration,
        backend: Arc<BasicSigner>,
    ) -> Self {
        Self { dir, password, interval, backend }
    }

    pub async fn run(&self, cancel: CancellationToken) {
        info!(
            dir = %self.dir.display(),
            interval_secs = self.interval.as_secs(),
            "Keystore reloader started"
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Keystore reloader shutting down");
                    return;
                }
                _ = tokio::time::sleep(self.interval) => {
                    self.scan_and_reload().await;
                }
            }
        }
    }

    async fn scan_and_reload(&self) {
        let disk_pubkeys = match self.scan_directory() {
            Ok(keys) => keys,
            Err(e) => {
                warn!(error = %e, "Failed to scan keystore directory");
                return;
            }
        };

        let loaded_pubkeys: HashSet<[u8; 48]> =
            self.backend.loaded_pubkeys().await.into_iter().collect();

        let on_disk: HashSet<[u8; 48]> = disk_pubkeys.into_iter().collect();

        let to_add: Vec<[u8; 48]> = on_disk.difference(&loaded_pubkeys).copied().collect();
        let to_remove: Vec<[u8; 48]> = loaded_pubkeys.difference(&on_disk).copied().collect();

        if to_add.is_empty() && to_remove.is_empty() {
            return;
        }

        let mut added = 0u64;
        let mut removed = 0u64;

        for pubkey in &to_add {
            let filename = format!("{}.json", hex::encode(pubkey));
            let path = self.dir.join(&filename);
            if !path.exists() {
                // Try to find by scanning (filename might not match pubkey)
                if let Some(sk) = self.try_load_pubkey(pubkey) {
                    self.backend.add_key(*pubkey, sk).await;
                    info!(
                        pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                        "Keystore added via reload"
                    );
                    added += 1;
                }
            } else {
                match load_keystore_from_file(&path, &self.password) {
                    Ok((sk, _)) => {
                        self.backend.add_key(*pubkey, sk).await;
                        info!(
                            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                            "Keystore added via reload"
                        );
                        added += 1;
                    }
                    Err(e) => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                            error = %e,
                            "Failed to load new keystore"
                        );
                    }
                }
            }
        }

        for pubkey in &to_remove {
            self.backend.remove_key(pubkey).await;
            info!(
                pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                "Keystore removed via reload"
            );
            removed += 1;
        }

        if added > 0 || removed > 0 {
            info!(
                keys_added = added,
                keys_removed = removed,
                "keystore reload: added {}, removed {}",
                added,
                removed
            );
        }
    }

    fn scan_directory(&self) -> Result<Vec<[u8; 48]>, Box<dyn std::error::Error>> {
        let mut pubkeys = Vec::new();

        let entries = std::fs::read_dir(&self.dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let extension = path.extension().and_then(|e| e.to_str());
            if extension != Some("json") {
                continue;
            }

            match load_keystore_from_file(&path, &self.password) {
                Ok((_sk, pubkey)) => {
                    pubkeys.push(pubkey);
                }
                Err(_) => {
                    // Skip files that can't be loaded (invalid or wrong password)
                }
            }
        }

        Ok(pubkeys)
    }

    fn try_load_pubkey(&self, target: &[u8; 48]) -> Option<crypto::SecretKey> {
        let entries = std::fs::read_dir(&self.dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok((sk, pubkey)) = load_keystore_from_file(&path, &self.password) {
                if pubkey == *target {
                    return Some(sk);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SigningBackend;
    use crypto::{EncryptionKdf, Keystore, SecretKey};
    use std::fs;
    use tempfile::TempDir;

    fn create_test_keystore(dir: &std::path::Path, password: &str) -> ([u8; 48], SecretKey) {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let ks = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let filename = format!("{}.json", hex::encode(pubkey));
        fs::write(dir.join(&filename), ks.to_json().unwrap()).unwrap();
        (pubkey, sk)
    }

    #[tokio::test]
    async fn test_reloader_detects_new_keystore() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        // Start with empty signer
        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        let signer = Arc::new(signer);

        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        // No keys initially
        assert!(signer.public_keys().is_empty());

        // Add a keystore file
        let (pubkey, _sk) = create_test_keystore(dir.path(), &password);

        // Trigger scan
        reloader.scan_and_reload().await;

        // Key should now be available
        let keys = signer.public_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&pubkey));
    }

    #[tokio::test]
    async fn test_reloader_detects_removed_keystore() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        // Start with one key
        let (pubkey, _sk) = create_test_keystore(dir.path(), &password);
        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        assert_eq!(signer.public_keys().len(), 1);

        let signer = Arc::new(signer);
        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        // Remove keystore file
        let filename = format!("{}.json", hex::encode(pubkey));
        fs::remove_file(dir.path().join(&filename)).unwrap();

        // Trigger scan
        reloader.scan_and_reload().await;

        // Key should be gone
        assert!(signer.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_reloader_no_changes_is_noop() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        let (pubkey, _sk) = create_test_keystore(dir.path(), &password);
        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        let signer = Arc::new(signer);

        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        reloader.scan_and_reload().await;

        let keys = signer.public_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&pubkey));
    }

    #[tokio::test]
    async fn test_reloader_run_with_cancellation() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        let signer = Arc::new(signer);

        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            reloader.run(cancel_clone).await;
        });

        // Let it run one cycle
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cancel
        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_reloader_add_and_remove_multiple() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        let signer = Arc::new(signer);

        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        // Add 3 keystores
        let (pk1, _) = create_test_keystore(dir.path(), &password);
        let (pk2, _) = create_test_keystore(dir.path(), &password);
        let (pk3, _) = create_test_keystore(dir.path(), &password);

        reloader.scan_and_reload().await;
        assert_eq!(signer.public_keys().len(), 3);

        // Remove 2
        fs::remove_file(dir.path().join(format!("{}.json", hex::encode(pk1)))).unwrap();
        fs::remove_file(dir.path().join(format!("{}.json", hex::encode(pk3)))).unwrap();

        reloader.scan_and_reload().await;

        let keys = signer.public_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&pk2));
    }

    #[tokio::test]
    async fn test_reloader_concurrent_sign_during_reload() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        let (pubkey, _sk) = create_test_keystore(dir.path(), &password);
        let signer = BasicSigner::load(dir.path(), &password).unwrap();
        let signer = Arc::new(signer);

        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        // Sign concurrently with reload
        let signer_clone = Arc::clone(&signer);
        let sign_handle = tokio::spawn(async move {
            use crate::backend::SigningBackend;
            let root = [42u8; 32];
            signer_clone.sign(&root, &pubkey).await.unwrap()
        });

        reloader.scan_and_reload().await;
        let _sig: [u8; 96] = sign_handle.await.unwrap();
    }
}
