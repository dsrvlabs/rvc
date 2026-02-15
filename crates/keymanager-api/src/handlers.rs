use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use crate::error::ApiError;
use crate::traits::{
    DoppelgangerMonitor, ImportKeystoreError, ImportRemoteKeyError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, ValidatorManager,
};
use crate::types::{
    DeleteKeystoreResult, DeleteKeystoresRequest, DeleteKeystoresResponse, DeleteRemoteKeyResult,
    DeleteRemoteKeyStatus, DeleteRemoteKeysRequest, DeleteRemoteKeysResponse, DeleteStatus,
    ImportKeystoreResult, ImportKeystoresRequest, ImportKeystoresResponse, ImportRemoteKeyResult,
    ImportRemoteKeyStatus, ImportRemoteKeysRequest, ImportRemoteKeysResponse, ImportStatus,
    KeystoreInfo, ListKeystoresResponse, ListRemoteKeysResponse, RemoteKeyEntry,
};

pub struct AppState {
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
    pub remote_key_manager: Arc<dyn RemoteKeyManager>,
}

pub async fn list_keystores(State(state): State<Arc<AppState>>) -> Json<ListKeystoresResponse> {
    let local_keys = state.keystore_manager.list_keys();
    let remote_keys = state.remote_key_manager.list_remote_keys();

    let mut data: Vec<KeystoreInfo> = local_keys
        .into_iter()
        .map(|pk| KeystoreInfo {
            validating_pubkey: format!("0x{}", hex::encode(pk)),
            derivation_path: None,
            readonly: false,
        })
        .collect();

    for (pk, _url) in &remote_keys {
        data.push(KeystoreInfo {
            validating_pubkey: format!("0x{}", hex::encode(pk)),
            derivation_path: None,
            readonly: true,
        });
    }

    Json(ListKeystoresResponse { data })
}

pub async fn import_keystores(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ImportKeystoresRequest>,
) -> Result<Json<ImportKeystoresResponse>, ApiError> {
    if request.keystores.len() != request.passwords.len() {
        return Err(ApiError::BadRequest(
            "keystores and passwords arrays must have the same length".into(),
        ));
    }

    // Import slashing protection FIRST — before any keystores are activated.
    // This prevents a window where signing keys exist without slashing records.
    if let Some(ref slashing_json) = request.slashing_protection {
        if let Err(e) = state.slashing_protection.import_interchange(slashing_json) {
            return Err(ApiError::Internal(format!("failed to import slashing protection: {e}")));
        }
    }

    let mut results = Vec::with_capacity(request.keystores.len());

    for (keystore_json, password) in request.keystores.iter().zip(request.passwords.iter()) {
        match state.keystore_manager.import_keystore(keystore_json, password) {
            Ok(pubkey) => {
                state.validator_manager.add_validator(pubkey, false);
                state.doppelganger_monitor.start_monitoring(pubkey);
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Imported,
                    message: String::new(),
                });
            }
            Err(ImportKeystoreError::Duplicate) => {
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Duplicate,
                    message: "key already exists".into(),
                });
            }
            Err(e) => {
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Error,
                    message: e.to_string(),
                });
            }
        }
    }

    Ok(Json(ImportKeystoresResponse { data: results }))
}

pub async fn delete_keystores(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeleteKeystoresRequest>,
) -> Result<Json<DeleteKeystoresResponse>, ApiError> {
    // Parse all pubkeys and identify which ones exist for slashing export
    let parsed: Vec<Result<Pubkey, String>> =
        request.pubkeys.iter().map(|s| parse_pubkey(s)).collect();

    let existing_keys: Vec<Pubkey> = parsed
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .filter(|pk| state.keystore_manager.has_key(pk))
        .copied()
        .collect();

    // Export slashing protection BEFORE any deletions
    let slashing_protection = if existing_keys.is_empty() {
        empty_interchange()
    } else {
        state.slashing_protection.export_interchange(&existing_keys).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to export slashing protection");
            empty_interchange()
        })
    };

    // Now process deletions
    let mut results = Vec::with_capacity(request.pubkeys.len());
    for parse_result in &parsed {
        match parse_result {
            Ok(pubkey) => match state.keystore_manager.delete_keystore(pubkey) {
                Ok(true) => {
                    state.validator_manager.remove_validator(pubkey);
                    state.doppelganger_monitor.stop_monitoring(pubkey);
                    results.push(DeleteKeystoreResult {
                        status: DeleteStatus::Deleted,
                        message: String::new(),
                    });
                }
                Ok(false) => {
                    results.push(DeleteKeystoreResult {
                        status: DeleteStatus::NotFound,
                        message: String::new(),
                    });
                }
                Err(e) => {
                    results.push(DeleteKeystoreResult {
                        status: DeleteStatus::Error,
                        message: e.to_string(),
                    });
                }
            },
            Err(e) => {
                results
                    .push(DeleteKeystoreResult { status: DeleteStatus::Error, message: e.clone() });
            }
        }
    }

    Ok(Json(DeleteKeystoresResponse { data: results, slashing_protection }))
}

// --- Remote key handlers ---

pub async fn list_remote_keys(State(state): State<Arc<AppState>>) -> Json<ListRemoteKeysResponse> {
    let keys = state.remote_key_manager.list_remote_keys();
    let data = keys
        .into_iter()
        .map(|(pk, url)| RemoteKeyEntry {
            pubkey: format!("0x{}", hex::encode(pk)),
            url,
            readonly: false,
        })
        .collect();
    Json(ListRemoteKeysResponse { data })
}

pub async fn import_remote_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ImportRemoteKeysRequest>,
) -> Json<ImportRemoteKeysResponse> {
    let mut results = Vec::with_capacity(request.remote_keys.len());

    for key_import in &request.remote_keys {
        match parse_pubkey(&key_import.pubkey) {
            Ok(pubkey) => {
                match state.remote_key_manager.import_remote_key(pubkey, key_import.url.clone()) {
                    Ok(()) => {
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Imported,
                            message: String::new(),
                        });
                    }
                    Err(ImportRemoteKeyError::Duplicate) => {
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Duplicate,
                            message: "key already exists".into(),
                        });
                    }
                    Err(e) => {
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Error,
                            message: e.to_string(),
                        });
                    }
                }
            }
            Err(e) => {
                results.push(ImportRemoteKeyResult {
                    status: ImportRemoteKeyStatus::Error,
                    message: e,
                });
            }
        }
    }

    Json(ImportRemoteKeysResponse { data: results })
}

pub async fn delete_remote_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeleteRemoteKeysRequest>,
) -> Json<DeleteRemoteKeysResponse> {
    let mut results = Vec::with_capacity(request.pubkeys.len());

    for pubkey_str in &request.pubkeys {
        match parse_pubkey(pubkey_str) {
            Ok(pubkey) => match state.remote_key_manager.delete_remote_key(&pubkey) {
                Ok(true) => {
                    results.push(DeleteRemoteKeyResult {
                        status: DeleteRemoteKeyStatus::Deleted,
                        message: String::new(),
                    });
                }
                Ok(false) => {
                    results.push(DeleteRemoteKeyResult {
                        status: DeleteRemoteKeyStatus::NotFound,
                        message: String::new(),
                    });
                }
                Err(e) => {
                    results.push(DeleteRemoteKeyResult {
                        status: DeleteRemoteKeyStatus::Error,
                        message: e.to_string(),
                    });
                }
            },
            Err(e) => {
                results.push(DeleteRemoteKeyResult {
                    status: DeleteRemoteKeyStatus::Error,
                    message: e,
                });
            }
        }
    }

    Json(DeleteRemoteKeysResponse { data: results })
}

fn parse_pubkey(s: &str) -> Result<Pubkey, String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 48 {
        return Err(format!("invalid pubkey length: expected 48 bytes, got {}", bytes.len()));
    }
    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&bytes);
    Ok(pubkey)
}

fn empty_interchange() -> String {
    serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "data": []
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use crate::traits::{
        DeleteKeystoreError, DeleteRemoteKeyError, ImportRemoteKeyError, RemoteKeyManager,
    };
    use crate::types::{
        DeleteRemoteKeyStatus, DeleteRemoteKeysResponse, ImportRemoteKeyStatus,
        ImportRemoteKeysResponse, ListRemoteKeysResponse,
    };
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use std::sync::Mutex;
    use tower::ServiceExt;

    // --- Mock implementations ---

    struct MockKeystoreManager {
        keys: Mutex<Vec<Pubkey>>,
    }

    impl MockKeystoreManager {
        fn new() -> Self {
            Self { keys: Mutex::new(Vec::new()) }
        }

        fn with_keys(keys: Vec<Pubkey>) -> Self {
            Self { keys: Mutex::new(keys) }
        }
    }

    impl KeystoreManager for MockKeystoreManager {
        fn list_keys(&self) -> Vec<Pubkey> {
            self.keys.lock().unwrap().clone()
        }

        fn has_key(&self, pubkey: &Pubkey) -> bool {
            self.keys.lock().unwrap().contains(pubkey)
        }

        fn import_keystore(
            &self,
            keystore_json: &str,
            _password: &str,
        ) -> Result<Pubkey, ImportKeystoreError> {
            let parsed: serde_json::Value = serde_json::from_str(keystore_json)
                .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
            let pubkey_hex = parsed["pubkey"]
                .as_str()
                .ok_or_else(|| ImportKeystoreError::InvalidKeystore("missing pubkey".into()))?;
            let bytes = hex::decode(pubkey_hex)
                .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
            if bytes.len() != 48 {
                return Err(ImportKeystoreError::InvalidKeystore("invalid pubkey length".into()));
            }
            let mut pubkey = [0u8; 48];
            pubkey.copy_from_slice(&bytes);

            let mut keys = self.keys.lock().unwrap();
            if keys.contains(&pubkey) {
                return Err(ImportKeystoreError::Duplicate);
            }
            keys.push(pubkey);
            Ok(pubkey)
        }

        fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
            let mut keys = self.keys.lock().unwrap();
            if let Some(pos) = keys.iter().position(|k| k == pubkey) {
                keys.remove(pos);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    struct MockSlashingProtection {
        imported: Mutex<Vec<String>>,
    }

    impl MockSlashingProtection {
        fn new() -> Self {
            Self { imported: Mutex::new(Vec::new()) }
        }
    }

    impl SlashingProtection for MockSlashingProtection {
        fn import_interchange(&self, interchange_json: &str) -> Result<(), String> {
            self.imported.lock().unwrap().push(interchange_json.to_string());
            Ok(())
        }

        fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, String> {
            let data: Vec<serde_json::Value> = pubkeys
                .iter()
                .map(|pk| {
                    serde_json::json!({
                        "pubkey": format!("0x{}", hex::encode(pk)),
                        "signed_blocks": [],
                        "signed_attestations": []
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "metadata": {
                    "interchange_format_version": "5",
                    "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
                "data": data
            })
            .to_string())
        }
    }

    struct MockValidatorManager {
        validators: Mutex<Vec<(Pubkey, bool)>>,
    }

    impl MockValidatorManager {
        fn new() -> Self {
            Self { validators: Mutex::new(Vec::new()) }
        }
    }

    impl ValidatorManager for MockValidatorManager {
        fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
            self.validators.lock().unwrap().push((pubkey, enabled));
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> bool {
            let mut validators = self.validators.lock().unwrap();
            if let Some(pos) = validators.iter().position(|(pk, _)| pk == pubkey) {
                validators.remove(pos);
                true
            } else {
                false
            }
        }
    }

    struct MockDoppelgangerMonitor {
        monitored: Mutex<Vec<Pubkey>>,
    }

    impl MockDoppelgangerMonitor {
        fn new() -> Self {
            Self { monitored: Mutex::new(Vec::new()) }
        }
    }

    impl DoppelgangerMonitor for MockDoppelgangerMonitor {
        fn start_monitoring(&self, pubkey: Pubkey) {
            self.monitored.lock().unwrap().push(pubkey);
        }

        fn stop_monitoring(&self, pubkey: &Pubkey) {
            let mut monitored = self.monitored.lock().unwrap();
            if let Some(pos) = monitored.iter().position(|pk| pk == pubkey) {
                monitored.remove(pos);
            }
        }
    }

    struct MockRemoteKeyManager {
        keys: Mutex<Vec<(Pubkey, String)>>,
    }

    impl MockRemoteKeyManager {
        fn new() -> Self {
            Self { keys: Mutex::new(Vec::new()) }
        }

        fn with_keys(keys: Vec<(Pubkey, String)>) -> Self {
            Self { keys: Mutex::new(keys) }
        }
    }

    impl RemoteKeyManager for MockRemoteKeyManager {
        fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
            self.keys.lock().unwrap().clone()
        }

        fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
            self.keys.lock().unwrap().iter().any(|(pk, _)| pk == pubkey)
        }

        fn import_remote_key(
            &self,
            pubkey: Pubkey,
            url: String,
        ) -> Result<(), ImportRemoteKeyError> {
            let mut keys = self.keys.lock().unwrap();
            if keys.iter().any(|(pk, _)| *pk == pubkey) {
                return Err(ImportRemoteKeyError::Duplicate);
            }
            keys.push((pubkey, url));
            Ok(())
        }

        fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
            let mut keys = self.keys.lock().unwrap();
            if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
                keys.remove(pos);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    // --- Test helpers ---

    fn test_pubkey(id: u8) -> Pubkey {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    fn test_pubkey_hex(id: u8) -> String {
        hex::encode(test_pubkey(id))
    }

    fn mock_keystore_json(id: u8) -> String {
        serde_json::json!({ "pubkey": test_pubkey_hex(id) }).to_string()
    }

    struct TestApp {
        keystore_manager: Arc<MockKeystoreManager>,
        slashing_protection: Arc<dyn SlashingProtection>,
        validator_manager: Arc<MockValidatorManager>,
        doppelganger_monitor: Arc<MockDoppelgangerMonitor>,
        remote_key_manager: Arc<MockRemoteKeyManager>,
    }

    impl TestApp {
        fn new() -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
            }
        }

        fn with_keys(keys: Vec<Pubkey>) -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::with_keys(keys)),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
            }
        }

        fn with_remote_keys(keys: Vec<(Pubkey, String)>) -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::with_keys(keys)),
            }
        }

        fn with_failing_slashing() -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(FailingSlashingProtection),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
            }
        }

        fn with_key_aware_slashing(keys: Vec<Pubkey>) -> Self {
            let keystore_manager = Arc::new(MockKeystoreManager::with_keys(keys));
            Self {
                slashing_protection: Arc::new(KeyAwareSlashingProtection {
                    keystore_manager: keystore_manager.clone(),
                }),
                keystore_manager,
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
            }
        }

        fn router(&self) -> Router {
            let state = Arc::new(AppState {
                keystore_manager: self.keystore_manager.clone(),
                slashing_protection: self.slashing_protection.clone(),
                validator_manager: self.validator_manager.clone(),
                doppelganger_monitor: self.doppelganger_monitor.clone(),
                remote_key_manager: self.remote_key_manager.clone(),
            });
            Router::new()
                .route(
                    "/eth/v1/keystores",
                    get(list_keystores).post(import_keystores).delete(delete_keystores),
                )
                .route(
                    "/eth/v1/remotekeys",
                    get(list_remote_keys).post(import_remote_keys).delete(delete_remote_keys),
                )
                .with_state(state)
        }

        fn authed_router(&self, token: &str) -> Router {
            auth::with_auth(self.router(), Arc::new(token.to_string()))
        }
    }

    struct FailingSlashingProtection;

    impl SlashingProtection for FailingSlashingProtection {
        fn import_interchange(&self, _interchange_json: &str) -> Result<(), String> {
            Err("slashing DB corrupted".into())
        }

        fn export_interchange(&self, _pubkeys: &[Pubkey]) -> Result<String, String> {
            Err("export failed".into())
        }
    }

    /// Mock that checks key existence in a shared KeystoreManager at export time.
    struct KeyAwareSlashingProtection {
        keystore_manager: Arc<MockKeystoreManager>,
    }

    impl SlashingProtection for KeyAwareSlashingProtection {
        fn import_interchange(&self, _interchange_json: &str) -> Result<(), String> {
            Ok(())
        }

        fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, String> {
            // Only export data for keys that still exist in the keystore manager
            let existing: Vec<&Pubkey> =
                pubkeys.iter().filter(|pk| self.keystore_manager.has_key(pk)).collect();
            let data: Vec<serde_json::Value> = existing
                .iter()
                .map(|pk| {
                    serde_json::json!({
                        "pubkey": format!("0x{}", hex::encode(pk)),
                        "signed_blocks": [],
                        "signed_attestations": []
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "metadata": {
                    "interchange_format_version": "5",
                    "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
                "data": data
            })
            .to_string())
        }
    }

    // --- GET /eth/v1/keystores tests ---

    #[tokio::test]
    async fn test_list_keystores_empty() {
        let app = TestApp::new();
        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/keystores")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ListKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.data.is_empty());
    }

    #[tokio::test]
    async fn test_list_keystores_with_validators() {
        let app = TestApp::with_keys(vec![test_pubkey(1), test_pubkey(2)]);

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/keystores")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ListKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0].validating_pubkey, format!("0x{}", test_pubkey_hex(1)));
        assert_eq!(resp.data[1].validating_pubkey, format!("0x{}", test_pubkey_hex(2)));
        assert!(!resp.data[0].readonly);
        assert!(!resp.data[1].readonly);
    }

    // --- POST /eth/v1/keystores tests ---

    #[tokio::test]
    async fn test_import_single_keystore() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "keystores": [mock_keystore_json(1)],
            "passwords": ["password1"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, ImportStatus::Imported);

        assert!(app.keystore_manager.has_key(&test_pubkey(1)));

        let validators = app.validator_manager.validators.lock().unwrap();
        assert_eq!(validators.len(), 1);
        assert!(!validators[0].1); // disabled for doppelganger

        let monitored = app.doppelganger_monitor.monitored.lock().unwrap();
        assert_eq!(monitored.len(), 1);
    }

    #[tokio::test]
    async fn test_import_multiple_keystores() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "keystores": [mock_keystore_json(1), mock_keystore_json(2)],
            "passwords": ["password1", "password2"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0].status, ImportStatus::Imported);
        assert_eq!(resp.data[1].status, ImportStatus::Imported);
    }

    #[tokio::test]
    async fn test_import_duplicate_keystore() {
        let app = TestApp::with_keys(vec![test_pubkey(1)]);
        let request_body = serde_json::json!({
            "keystores": [mock_keystore_json(1)],
            "passwords": ["password1"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, ImportStatus::Duplicate);
    }

    #[tokio::test]
    async fn test_import_with_slashing_protection() {
        let mock_slashing = Arc::new(MockSlashingProtection::new());
        let app = TestApp {
            keystore_manager: Arc::new(MockKeystoreManager::new()),
            slashing_protection: mock_slashing.clone(),
            validator_manager: Arc::new(MockValidatorManager::new()),
            doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
            remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
        };
        let slashing_data = serde_json::json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": []
        })
        .to_string();

        let request_body = serde_json::json!({
            "keystores": [mock_keystore_json(1)],
            "passwords": ["password1"],
            "slashing_protection": slashing_data
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let imported = mock_slashing.imported.lock().unwrap();
        assert_eq!(imported.len(), 1);
    }

    #[tokio::test]
    async fn test_import_mismatched_lengths() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "keystores": [mock_keystore_json(1), mock_keystore_json(2)],
            "passwords": ["password1"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_import_invalid_keystore_json() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "keystores": ["not valid json"],
            "passwords": ["password1"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, ImportStatus::Error);
    }

    // --- DELETE /eth/v1/keystores tests ---

    #[tokio::test]
    async fn test_delete_existing_keystore() {
        let app = TestApp::with_keys(vec![test_pubkey(1)]);
        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
        assert!(!app.keystore_manager.has_key(&test_pubkey(1)));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_keystore() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(99))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, DeleteStatus::NotFound);
    }

    #[tokio::test]
    async fn test_delete_returns_slashing_export() {
        let app = TestApp::with_keys(vec![test_pubkey(1)]);
        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
        let export: serde_json::Value = serde_json::from_str(&resp.slashing_protection).unwrap();
        assert_eq!(export["data"].as_array().unwrap().len(), 1);
        assert_eq!(export["data"][0]["pubkey"], format!("0x{}", test_pubkey_hex(1)));
    }

    #[tokio::test]
    async fn test_delete_empty_returns_empty_interchange() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(99))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
        let export: serde_json::Value = serde_json::from_str(&resp.slashing_protection).unwrap();
        assert!(export["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_delete_invalid_pubkey_hex() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "pubkeys": ["not_valid_hex!"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, DeleteStatus::Error);
    }

    // --- Auth middleware tests ---

    #[tokio::test]
    async fn test_auth_middleware_rejects_unauthenticated_get() {
        let app = TestApp::new();
        let response = app
            .authed_router("test_token")
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/keystores")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_allows_valid_token() {
        let app = TestApp::new();
        let token = "test_token";

        let response = app
            .authed_router(token)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/keystores")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_unauthenticated_post() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "keystores": [],
            "passwords": []
        });

        let response = app
            .authed_router("test_token")
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_unauthenticated_delete() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "pubkeys": []
        });

        let response = app
            .authed_router("test_token")
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    // --- Finding #1 & #2: Slashing import must happen FIRST and failure is a hard error ---

    #[tokio::test]
    async fn test_import_slashing_failure_returns_error_no_keys_imported() {
        let app = TestApp::with_failing_slashing();
        let slashing_data = serde_json::json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": []
        })
        .to_string();

        let request_body = serde_json::json!({
            "keystores": [mock_keystore_json(1)],
            "passwords": ["password1"],
            "slashing_protection": slashing_data
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Must return an error status, NOT 200
        assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);

        // No keys should have been imported
        assert!(!app.keystore_manager.has_key(&test_pubkey(1)));

        // No validators should have been added
        let validators = app.validator_manager.validators.lock().unwrap();
        assert!(validators.is_empty());

        // No doppelganger monitoring started
        let monitored = app.doppelganger_monitor.monitored.lock().unwrap();
        assert!(monitored.is_empty());
    }

    #[tokio::test]
    async fn test_import_without_slashing_data_succeeds() {
        // When no slashing_protection is provided, import should still work
        let app = TestApp::with_failing_slashing();
        let request_body = serde_json::json!({
            "keystores": [mock_keystore_json(1)],
            "passwords": ["password1"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(app.keystore_manager.has_key(&test_pubkey(1)));
    }

    // --- Finding #3: message field should be omitted when empty ---

    #[test]
    fn test_import_success_result_omits_empty_message() {
        let result =
            ImportKeystoreResult { status: ImportStatus::Imported, message: String::new() };
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            json.get("message").is_none(),
            "success result should not have 'message' key, got: {json}"
        );
    }

    #[test]
    fn test_delete_success_result_omits_empty_message() {
        let result = DeleteKeystoreResult { status: DeleteStatus::Deleted, message: String::new() };
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            json.get("message").is_none(),
            "success result should not have 'message' key, got: {json}"
        );
    }

    #[test]
    fn test_error_result_includes_message() {
        let result = ImportKeystoreResult {
            status: ImportStatus::Error,
            message: "something went wrong".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["message"], "something went wrong");
    }

    // --- Finding #4: Delete must export slashing BEFORE deleting keystores ---

    #[tokio::test]
    async fn test_delete_exports_slashing_before_deletion() {
        // Uses key-aware slashing mock that only returns data for keys
        // that still exist in the keystore manager
        let app = TestApp::with_key_aware_slashing(vec![test_pubkey(1)]);
        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteKeystoresResponse = serde_json::from_slice(&body).unwrap();

        // Key should be deleted
        assert_eq!(resp.data[0].status, DeleteStatus::Deleted);
        assert!(!app.keystore_manager.has_key(&test_pubkey(1)));

        // Slashing export should contain the deleted key's data
        // (only possible if export happened BEFORE deletion)
        let export: serde_json::Value = serde_json::from_str(&resp.slashing_protection).unwrap();
        assert_eq!(
            export["data"].as_array().unwrap().len(),
            1,
            "export should contain data for the deleted key (export must happen before delete)"
        );
    }

    // --- Finding #5: Delete must call stop_monitoring ---

    #[tokio::test]
    async fn test_delete_calls_stop_monitoring() {
        let app = TestApp::with_keys(vec![test_pubkey(1), test_pubkey(2)]);
        // Pre-populate monitoring
        app.doppelganger_monitor.start_monitoring(test_pubkey(1));
        app.doppelganger_monitor.start_monitoring(test_pubkey(2));

        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/keystores")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Key 1 should no longer be monitored, key 2 should remain
        let monitored = app.doppelganger_monitor.monitored.lock().unwrap();
        assert_eq!(monitored.len(), 1);
        assert_eq!(monitored[0], test_pubkey(2));
    }

    // --- GET /eth/v1/remotekeys tests ---

    #[tokio::test]
    async fn test_list_remote_keys_empty() {
        let app = TestApp::new();
        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/remotekeys")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ListRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.data.is_empty());
    }

    #[tokio::test]
    async fn test_list_remote_keys_with_entries() {
        let app = TestApp::with_remote_keys(vec![
            (test_pubkey(1), "https://signer1.example.com".into()),
            (test_pubkey(2), "https://signer2.example.com".into()),
        ]);

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/remotekeys")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ListRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0].pubkey, format!("0x{}", test_pubkey_hex(1)));
        assert_eq!(resp.data[0].url, "https://signer1.example.com");
        assert!(!resp.data[0].readonly);
        assert_eq!(resp.data[1].pubkey, format!("0x{}", test_pubkey_hex(2)));
        assert_eq!(resp.data[1].url, "https://signer2.example.com");
    }

    // --- POST /eth/v1/remotekeys tests ---

    #[tokio::test]
    async fn test_import_single_remote_key() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "remote_keys": [{
                "pubkey": format!("0x{}", test_pubkey_hex(1)),
                "url": "https://signer.example.com"
            }]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Imported);

        assert!(app.remote_key_manager.has_remote_key(&test_pubkey(1)));
    }

    #[tokio::test]
    async fn test_import_multiple_remote_keys() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "remote_keys": [
                {"pubkey": format!("0x{}", test_pubkey_hex(1)), "url": "https://signer1.example.com"},
                {"pubkey": format!("0x{}", test_pubkey_hex(2)), "url": "https://signer2.example.com"}
            ]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Imported);
        assert_eq!(resp.data[1].status, ImportRemoteKeyStatus::Imported);
    }

    #[tokio::test]
    async fn test_import_duplicate_remote_key() {
        let app =
            TestApp::with_remote_keys(vec![(test_pubkey(1), "https://signer.example.com".into())]);
        let request_body = serde_json::json!({
            "remote_keys": [{
                "pubkey": format!("0x{}", test_pubkey_hex(1)),
                "url": "https://signer.example.com"
            }]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Duplicate);
    }

    #[tokio::test]
    async fn test_import_remote_key_invalid_pubkey() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "remote_keys": [{
                "pubkey": "not_valid_hex!",
                "url": "https://signer.example.com"
            }]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
    }

    // --- DELETE /eth/v1/remotekeys tests ---

    #[tokio::test]
    async fn test_delete_existing_remote_key() {
        let app =
            TestApp::with_remote_keys(vec![(test_pubkey(1), "https://signer.example.com".into())]);
        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, DeleteRemoteKeyStatus::Deleted);
        assert!(!app.remote_key_manager.has_remote_key(&test_pubkey(1)));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_remote_key() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "pubkeys": [format!("0x{}", test_pubkey_hex(99))]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, DeleteRemoteKeyStatus::NotFound);
    }

    #[tokio::test]
    async fn test_delete_remote_key_invalid_pubkey() {
        let app = TestApp::new();
        let request_body = serde_json::json!({
            "pubkeys": ["not_valid_hex!"]
        });

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: DeleteRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].status, DeleteRemoteKeyStatus::Error);
    }

    // --- Remote key readonly in list_keystores ---

    #[tokio::test]
    async fn test_list_keystores_remote_keys_readonly() {
        let app = TestApp {
            keystore_manager: Arc::new(MockKeystoreManager::with_keys(vec![test_pubkey(1)])),
            slashing_protection: Arc::new(MockSlashingProtection::new()),
            validator_manager: Arc::new(MockValidatorManager::new()),
            doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
            remote_key_manager: Arc::new(MockRemoteKeyManager::with_keys(vec![(
                test_pubkey(2),
                "https://signer.example.com".into(),
            )])),
        };

        let response = app
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/keystores")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: ListKeystoresResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.data.len(), 2);
        // Local key: not readonly
        assert_eq!(resp.data[0].validating_pubkey, format!("0x{}", test_pubkey_hex(1)));
        assert!(!resp.data[0].readonly);
        // Remote key: readonly
        assert_eq!(resp.data[1].validating_pubkey, format!("0x{}", test_pubkey_hex(2)));
        assert!(resp.data[1].readonly);
    }

    // --- Auth tests for remote key endpoints ---

    #[tokio::test]
    async fn test_auth_rejects_unauthenticated_get_remotekeys() {
        let app = TestApp::new();
        let response = app
            .authed_router("test_token")
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/remotekeys")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_rejects_unauthenticated_post_remotekeys() {
        let app = TestApp::new();
        let request_body = serde_json::json!({"remote_keys": []});

        let response = app
            .authed_router("test_token")
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_rejects_unauthenticated_delete_remotekeys() {
        let app = TestApp::new();
        let request_body = serde_json::json!({"pubkeys": []});

        let response = app
            .authed_router("test_token")
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/eth/v1/remotekeys")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_allows_valid_token_remotekeys() {
        let app = TestApp::new();
        let token = "test_token";

        let response = app
            .authed_router(token)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/remotekeys")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    // --- Import remote key result message omission ---

    #[test]
    fn test_import_remote_key_success_omits_empty_message() {
        let result = ImportRemoteKeyResult {
            status: ImportRemoteKeyStatus::Imported,
            message: String::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            json.get("message").is_none(),
            "success result should not have 'message' key, got: {json}"
        );
    }

    #[test]
    fn test_delete_remote_key_success_omits_empty_message() {
        let result = DeleteRemoteKeyResult {
            status: DeleteRemoteKeyStatus::Deleted,
            message: String::new(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            json.get("message").is_none(),
            "success result should not have 'message' key, got: {json}"
        );
    }
}
