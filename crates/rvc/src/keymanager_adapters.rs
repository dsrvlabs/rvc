use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crypto::{CompositeSigner, Keystore, RemoteSigner, RemoteSignerConfig};
use keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, DoppelgangerMonitor, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection,
    ValidatorManager,
};
use slashing::SlashingDb;
use tracing::{info, warn};
use validator_store::ValidatorStore;

pub struct KeystoreManagerAdapter {
    keystore_dir: PathBuf,
    composite_signer: Arc<CompositeSigner>,
    tracked_keys: Mutex<Vec<Pubkey>>,
}

impl KeystoreManagerAdapter {
    pub fn new(keystore_dir: PathBuf, composite_signer: Arc<CompositeSigner>) -> Self {
        Self { keystore_dir, composite_signer, tracked_keys: Mutex::new(Vec::new()) }
    }
}

impl KeystoreManager for KeystoreManagerAdapter {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.tracked_keys.lock().expect("tracked_keys lock poisoned").clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.tracked_keys.lock().expect("tracked_keys lock poisoned").contains(pubkey)
    }

    fn import_keystore(
        &self,
        keystore_json: &str,
        password: &str,
    ) -> Result<Pubkey, ImportKeystoreError> {
        let keystore: Keystore = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;

        let secret_key = keystore
            .decrypt(password.as_bytes())
            .map_err(|e| ImportKeystoreError::DecryptionFailed(e.to_string()))?;

        let pubkey_bytes = secret_key.public_key().to_bytes();

        // Hold lock for the entire check-and-insert to prevent TOCTOU race
        let mut keys = self.tracked_keys.lock().expect("tracked_keys lock poisoned");
        if keys.contains(&pubkey_bytes) {
            return Err(ImportKeystoreError::Duplicate);
        }

        // Save keystore file to disk with restricted permissions (0o600)
        let filename = format!("0x{}.json", hex::encode(pubkey_bytes));
        let file_path = self.keystore_dir.join(&filename);

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&file_path)
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
            file.write_all(keystore_json.as_bytes())
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&file_path, keystore_json)
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        }

        // Add to composite signer for signing
        self.composite_signer.add_local_key(secret_key);

        // Track the key (lock still held)
        keys.push(pubkey_bytes);

        info!(pubkey = %hex::encode(pubkey_bytes), "Imported keystore");
        Ok(pubkey_bytes)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let mut keys = self.tracked_keys.lock().expect("tracked_keys lock poisoned");
        if let Some(pos) = keys.iter().position(|k| k == pubkey) {
            // Delete file FIRST — if IO fails, memory state remains consistent
            let filename = format!("0x{}.json", hex::encode(pubkey));
            let file_path = self.keystore_dir.join(&filename);
            if file_path.exists() {
                std::fs::remove_file(&file_path)
                    .map_err(|e| DeleteKeystoreError::Io(e.to_string()))?;
            }

            // Only remove from memory after file delete succeeds
            keys.remove(pos);
            drop(keys);

            self.composite_signer.remove_local_key(pubkey);

            info!(pubkey = %hex::encode(pubkey), "Deleted keystore");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct SlashingProtectionAdapter {
    slashing_db: Arc<SlashingDb>,
    genesis_validators_root: String,
}

impl SlashingProtectionAdapter {
    pub fn new(slashing_db: Arc<SlashingDb>, genesis_validators_root: String) -> Self {
        Self { slashing_db, genesis_validators_root }
    }
}

impl SlashingProtection for SlashingProtectionAdapter {
    fn import_interchange(&self, interchange_json: &str) -> Result<(), String> {
        let interchange: slashing::InterchangeFormat =
            serde_json::from_str(interchange_json).map_err(|e| format!("invalid JSON: {e}"))?;
        self.slashing_db
            .import(&interchange, &self.genesis_validators_root)
            .map_err(|e| e.to_string())
    }

    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, String> {
        let interchange =
            self.slashing_db.export(&self.genesis_validators_root).map_err(|e| e.to_string())?;

        // Filter to only requested pubkeys
        let requested: std::collections::HashSet<String> =
            pubkeys.iter().map(|pk| format!("0x{}", hex::encode(pk))).collect();

        let filtered_data: Vec<_> = interchange
            .data
            .into_iter()
            .filter(|record| requested.contains(&record.pubkey))
            .collect();

        let filtered =
            slashing::InterchangeFormat { metadata: interchange.metadata, data: filtered_data };

        serde_json::to_string(&filtered).map_err(|e| format!("serialization failed: {e}"))
    }
}

pub struct ValidatorManagerAdapter {
    validator_store: Arc<ValidatorStore>,
}

impl ValidatorManagerAdapter {
    pub fn new(validator_store: Arc<ValidatorStore>) -> Self {
        Self { validator_store }
    }
}

impl ValidatorManager for ValidatorManagerAdapter {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let mut config = validator_store::ValidatorConfig::new(pubkey);
        config.enabled = enabled;
        self.validator_store.add_validator(config);
        info!(pubkey = %pubkey_hex, enabled, "Added validator to store");
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let removed = self.validator_store.remove_validator(pubkey).is_some();
        if removed {
            info!(pubkey = %pubkey_hex, "Removed validator from store");
        } else {
            warn!(pubkey = %pubkey_hex, "Validator not found in store for removal");
        }
        removed
    }
}

#[derive(Default)]
pub struct DoppelgangerMonitorAdapter;

impl DoppelgangerMonitorAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl DoppelgangerMonitor for DoppelgangerMonitorAdapter {
    fn start_monitoring(&self, pubkey: Pubkey) {
        info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Doppelganger monitoring requested for new key");
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Doppelganger monitoring stop requested");
    }
}

pub struct RemoteKeyManagerAdapter {
    composite_signer: Arc<CompositeSigner>,
    tracked_keys: Mutex<Vec<(Pubkey, String)>>,
    allowed_hosts: Option<Vec<String>>,
    warned_no_allowlist: AtomicBool,
}

impl RemoteKeyManagerAdapter {
    pub fn new(composite_signer: Arc<CompositeSigner>, allowed_hosts: Option<Vec<String>>) -> Self {
        Self {
            composite_signer,
            tracked_keys: Mutex::new(Vec::new()),
            allowed_hosts,
            warned_no_allowlist: AtomicBool::new(false),
        }
    }
}

impl RemoteKeyManager for RemoteKeyManagerAdapter {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        self.tracked_keys.lock().expect("tracked_keys lock poisoned").clone()
    }

    fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
        self.tracked_keys
            .lock()
            .expect("tracked_keys lock poisoned")
            .iter()
            .any(|(pk, _)| pk == pubkey)
    }

    fn import_remote_key(&self, pubkey: Pubkey, url: String) -> Result<(), ImportRemoteKeyError> {
        let parsed = url::Url::parse(&url)
            .map_err(|e| ImportRemoteKeyError::Other(format!("invalid remote signer URL: {e}")))?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(ImportRemoteKeyError::Other(format!(
                    "invalid URL scheme: must be http:// or https://, got: {scheme}://"
                )));
            }
        }

        if let Some(ref allowed) = self.allowed_hosts {
            let host = parsed.host_str().unwrap_or("");
            if !allowed.iter().any(|h| h == host) {
                return Err(ImportRemoteKeyError::Other(format!(
                    "remote signer host '{}' is not in the allowed hosts list",
                    host
                )));
            }
        } else if !self.warned_no_allowlist.swap(true, Ordering::Relaxed) {
            warn!(
                "No remote signer host allowlist configured; all HTTP/HTTPS hosts are accepted. \
                 Consider setting --remote-signer-allowed-hosts for production use"
            );
        }

        let mut keys = self.tracked_keys.lock().expect("tracked_keys lock poisoned");
        if keys.iter().any(|(pk, _)| *pk == pubkey) {
            return Err(ImportRemoteKeyError::Duplicate);
        }

        let config = RemoteSignerConfig::new(url.clone());
        let remote_signer = RemoteSigner::new(config, vec![pubkey])
            .map_err(|e| ImportRemoteKeyError::Other(e.to_string()))?;

        self.composite_signer.add_remote_key(pubkey, remote_signer);
        keys.push((pubkey, url));

        info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Imported remote key");
        Ok(())
    }

    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        let mut keys = self.tracked_keys.lock().expect("tracked_keys lock poisoned");
        if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
            keys.remove(pos);
            drop(keys);

            self.composite_signer.remove_remote_key(pubkey);

            info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Deleted remote key");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{KeyManager, LocalSigner, SecretKey, Signer};
    use tempfile::TempDir;

    fn test_pubkey(id: u8) -> Pubkey {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    fn create_empty_composite_signer() -> Arc<CompositeSigner> {
        Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
    }

    // --- KeystoreManagerAdapter tests ---

    #[test]
    fn test_keystore_manager_adapter_empty_list() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(adapter.list_keys().is_empty());
    }

    #[test]
    fn test_keystore_manager_adapter_has_key_false() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(!adapter.has_key(&test_pubkey(1)));
    }

    #[test]
    fn test_keystore_manager_adapter_delete_nonexistent() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(!adapter.delete_keystore(&test_pubkey(1)).unwrap());
    }

    #[test]
    fn test_keystore_manager_adapter_import_invalid_json() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
        let result = adapter.import_keystore("not valid json", "password");
        assert!(matches!(result, Err(ImportKeystoreError::InvalidKeystore(_))));
    }

    // --- SlashingProtectionAdapter tests ---

    #[test]
    fn test_slashing_adapter_import_invalid_json() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let adapter = SlashingProtectionAdapter::new(
            db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        let result = adapter.import_interchange("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_slashing_adapter_import_valid() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let adapter = SlashingProtectionAdapter::new(
            db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        let interchange = serde_json::json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": []
        });
        let result = adapter.import_interchange(&interchange.to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_slashing_adapter_export_empty() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let adapter = SlashingProtectionAdapter::new(
            db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        let result = adapter.export_interchange(&[]);
        assert!(result.is_ok());
        let export: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(export["data"].as_array().unwrap().is_empty());
    }

    // --- ValidatorManagerAdapter tests ---

    #[test]
    fn test_validator_manager_adapter_add_remove() {
        let store = Arc::new(ValidatorStore::new([0u8; 20], 100));
        let adapter = ValidatorManagerAdapter::new(store.clone());
        adapter.add_validator(test_pubkey(1), true);

        // Verify the validator was actually added to the store
        assert!(store.get_config(&test_pubkey(1)).is_some());

        // Remove and verify
        assert!(adapter.remove_validator(&test_pubkey(1)));
        assert!(store.get_config(&test_pubkey(1)).is_none());

        // Removing non-existent returns false
        assert!(!adapter.remove_validator(&test_pubkey(99)));
    }

    // --- DoppelgangerMonitorAdapter tests ---

    #[test]
    fn test_doppelganger_adapter_start_stop() {
        let adapter = DoppelgangerMonitorAdapter::new();
        adapter.start_monitoring(test_pubkey(1));
        adapter.stop_monitoring(&test_pubkey(1));
    }

    // --- RemoteKeyManagerAdapter tests ---

    #[test]
    fn test_remote_key_adapter_empty_list() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        assert!(adapter.list_remote_keys().is_empty());
    }

    #[test]
    fn test_remote_key_adapter_has_key_false() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        assert!(!adapter.has_remote_key(&test_pubkey(1)));
    }

    #[test]
    fn test_remote_key_adapter_import_and_list() {
        let composite = create_empty_composite_signer();
        let adapter = RemoteKeyManagerAdapter::new(composite.clone(), None);

        let pk = test_pubkey(1);
        let url = "https://signer.example.com".to_string();
        adapter.import_remote_key(pk, url.clone()).unwrap();

        let keys = adapter.list_remote_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, pk);
        assert_eq!(keys[0].1, url);
        assert!(adapter.has_remote_key(&pk));

        assert!(composite.public_keys().contains(&pk));
    }

    #[test]
    fn test_remote_key_adapter_import_duplicate() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
        let result = adapter.import_remote_key(pk, "https://signer.example.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)));
    }

    #[test]
    fn test_remote_key_adapter_delete() {
        let composite = create_empty_composite_signer();
        let adapter = RemoteKeyManagerAdapter::new(composite.clone(), None);

        let pk = test_pubkey(1);
        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
        assert!(adapter.has_remote_key(&pk));

        let deleted = adapter.delete_remote_key(&pk).unwrap();
        assert!(deleted);
        assert!(!adapter.has_remote_key(&pk));
        assert!(!composite.public_keys().contains(&pk));
    }

    #[test]
    fn test_remote_key_adapter_delete_nonexistent() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        assert!(!adapter.delete_remote_key(&test_pubkey(99)).unwrap());
    }

    #[test]
    fn test_remote_key_adapter_import_rejects_invalid_url_scheme() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);

        // file:// scheme — SSRF risk
        let result = adapter.import_remote_key(pk, "file:///etc/passwd".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));

        // ftp:// scheme
        let result = adapter.import_remote_key(pk, "ftp://evil.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));

        // No scheme
        let result = adapter.import_remote_key(pk, "signer.example.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));

        // Valid schemes should be accepted
        let pk2 = test_pubkey(2);
        let result = adapter.import_remote_key(pk2, "https://signer.example.com".to_string());
        assert!(result.is_ok());
    }

    // --- Keystore import with real secret key ---

    #[test]
    fn test_keystore_manager_tracks_imported_key_in_composite_signer() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        // Manually add key (simulating what would happen with a real keystore)
        composite.add_local_key(sk);
        adapter.tracked_keys.lock().unwrap().push(pk_bytes);

        assert!(adapter.has_key(&pk_bytes));
        assert!(composite.public_keys().contains(&pk_bytes));

        // Delete
        let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
        assert!(deleted);
        assert!(!adapter.has_key(&pk_bytes));
        assert!(!composite.public_keys().contains(&pk_bytes));
    }

    // --- Full lifecycle: adapters wired into KeymanagerServer ---

    fn build_test_server() -> keymanager_api::KeymanagerServer {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 100));

        let keystore_mgr = Arc::new(KeystoreManagerAdapter::new(dir.keep(), composite.clone()));
        let slashing_prot = Arc::new(SlashingProtectionAdapter::new(
            slashing_db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
        let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store));
        let doppelganger_mon = Arc::new(DoppelgangerMonitorAdapter::new());
        let remote_key_mgr = Arc::new(RemoteKeyManagerAdapter::new(composite, None));

        let token = "deadbeef".repeat(8);
        let addr = "127.0.0.1:0".parse().unwrap();

        keymanager_api::KeymanagerServer::new(
            keystore_mgr,
            slashing_prot,
            validator_mgr,
            doppelganger_mon,
            remote_key_mgr,
            token,
            addr,
        )
    }

    #[test]
    fn test_keymanager_server_builds_with_adapters() {
        let _server = build_test_server();
    }

    #[test]
    fn test_keymanager_server_router_builds() {
        let server = build_test_server();
        let _router = server.router();
    }

    #[tokio::test]
    async fn test_keymanager_server_list_keystores_requires_auth() {
        use tower::ServiceExt;

        let server = build_test_server();
        let router = server.router();

        // Request without auth token should be rejected
        let request = axum::http::Request::builder()
            .uri("/eth/v1/keystores")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_keymanager_server_list_keystores_empty() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let server = build_test_server();
        let router = server.router();
        let token = "deadbeef".repeat(8);

        let request = axum::http::Request::builder()
            .uri("/eth/v1/keystores")
            .header("Authorization", format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_keymanager_server_list_remote_keys_empty() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let server = build_test_server();
        let router = server.router();
        let token = "deadbeef".repeat(8);

        let request = axum::http::Request::builder()
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_keymanager_server_import_remote_key_lifecycle() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 100));

        let keystore_mgr = Arc::new(KeystoreManagerAdapter::new(dir.keep(), composite.clone()));
        let slashing_prot = Arc::new(SlashingProtectionAdapter::new(
            slashing_db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
        let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store));
        let doppelganger_mon = Arc::new(DoppelgangerMonitorAdapter::new());
        let remote_key_mgr = Arc::new(RemoteKeyManagerAdapter::new(composite.clone(), None));

        let token = "deadbeef".repeat(8);
        let addr = "127.0.0.1:0".parse().unwrap();

        let server = keymanager_api::KeymanagerServer::new(
            keystore_mgr,
            slashing_prot,
            validator_mgr,
            doppelganger_mon,
            remote_key_mgr,
            token.clone(),
            addr,
        );

        // 1. Import a remote key
        let pk = test_pubkey(42);
        let pk_hex = format!("0x{}", hex::encode(pk));
        let import_body = serde_json::json!({
            "remote_keys": [{
                "pubkey": pk_hex,
                "url": "https://signer.example.com"
            }]
        });

        let router = server.router();
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(import_body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let statuses = json["data"].as_array().unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["status"], "imported");

        // 2. Verify composite signer has the key
        assert!(composite.public_keys().contains(&pk));

        // 3. List remote keys - should contain the imported key
        let router = server.router();
        let request = axum::http::Request::builder()
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let keys = json["data"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["pubkey"], pk_hex);

        // 4. Delete the remote key
        let delete_body = serde_json::json!({
            "pubkeys": [pk_hex]
        });

        let router = server.router();
        let request = axum::http::Request::builder()
            .method("DELETE")
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(delete_body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let statuses = json["data"].as_array().unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["status"], "deleted");

        // 5. Verify composite signer no longer has the key
        assert!(!composite.public_keys().contains(&pk));
    }

    // --- Remote signer host allowlist tests ---

    #[test]
    fn test_import_remote_key_allowed_host_accepted() {
        let adapter = RemoteKeyManagerAdapter::new(
            create_empty_composite_signer(),
            Some(vec!["signer.example.com".to_string()]),
        );
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://signer.example.com/api".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_remote_key_blocked_host_rejected() {
        let adapter = RemoteKeyManagerAdapter::new(
            create_empty_composite_signer(),
            Some(vec!["trusted.host".to_string()]),
        );
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://evil.attacker.com/api".to_string());
        assert!(
            matches!(result, Err(ImportRemoteKeyError::Other(ref msg)) if msg.contains("not in the allowed hosts list"))
        );
    }

    #[test]
    fn test_import_remote_key_no_allowlist_allows_all() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://any.host.com".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_remote_key_allowlist_multiple_hosts() {
        let adapter = RemoteKeyManagerAdapter::new(
            create_empty_composite_signer(),
            Some(vec!["signer1.example.com".to_string(), "signer2.example.com".to_string()]),
        );
        let pk1 = test_pubkey(1);
        assert!(adapter.import_remote_key(pk1, "https://signer1.example.com".to_string()).is_ok());

        let pk2 = test_pubkey(2);
        assert!(adapter.import_remote_key(pk2, "https://signer2.example.com".to_string()).is_ok());

        let pk3 = test_pubkey(3);
        let result = adapter.import_remote_key(pk3, "https://signer3.example.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));
    }

    #[test]
    fn test_import_remote_key_invalid_url_parse_error() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "not a valid url".to_string());
        assert!(
            matches!(result, Err(ImportRemoteKeyError::Other(ref msg)) if msg.contains("invalid remote signer URL"))
        );
    }

    #[test]
    fn test_import_remote_key_allowlist_with_port() {
        let adapter = RemoteKeyManagerAdapter::new(
            create_empty_composite_signer(),
            Some(vec!["signer.example.com".to_string()]),
        );
        let pk = test_pubkey(1);
        // host_str() returns the host without port
        let result =
            adapter.import_remote_key(pk, "https://signer.example.com:9000/api".to_string());
        assert!(result.is_ok());
    }
}
