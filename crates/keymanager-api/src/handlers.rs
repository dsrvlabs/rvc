use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use crate::error::ApiError;
use crate::traits::{
    DoppelgangerMonitor, ImportKeystoreError, KeystoreManager, Pubkey, SlashingProtection,
    ValidatorManager,
};
use crate::types::{
    DeleteKeystoreResult, DeleteKeystoresRequest, DeleteKeystoresResponse, DeleteStatus,
    ImportKeystoreResult, ImportKeystoresRequest, ImportKeystoresResponse, ImportStatus,
    KeystoreInfo, ListKeystoresResponse,
};

pub struct AppState {
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
}

pub async fn list_keystores(State(state): State<Arc<AppState>>) -> Json<ListKeystoresResponse> {
    let pubkeys = state.keystore_manager.list_keys();
    let data = pubkeys
        .into_iter()
        .map(|pk| KeystoreInfo {
            validating_pubkey: format!("0x{}", hex::encode(pk)),
            derivation_path: None,
            readonly: false,
        })
        .collect();
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

    if let Some(ref slashing_json) = request.slashing_protection {
        if let Err(e) = state.slashing_protection.import_interchange(slashing_json) {
            tracing::warn!(error = %e, "Failed to import slashing protection data");
        }
    }

    Ok(Json(ImportKeystoresResponse { data: results }))
}

pub async fn delete_keystores(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeleteKeystoresRequest>,
) -> Result<Json<DeleteKeystoresResponse>, ApiError> {
    let mut results = Vec::with_capacity(request.pubkeys.len());
    let mut deleted_pubkeys = Vec::new();

    for pubkey_str in &request.pubkeys {
        let pubkey = match parse_pubkey(pubkey_str) {
            Ok(pk) => pk,
            Err(e) => {
                results.push(DeleteKeystoreResult { status: DeleteStatus::Error, message: e });
                continue;
            }
        };

        match state.keystore_manager.delete_keystore(&pubkey) {
            Ok(true) => {
                state.validator_manager.remove_validator(&pubkey);
                deleted_pubkeys.push(pubkey);
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
        }
    }

    let slashing_protection = if deleted_pubkeys.is_empty() {
        empty_interchange()
    } else {
        state.slashing_protection.export_interchange(&deleted_pubkeys).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to export slashing protection");
            empty_interchange()
        })
    };

    Ok(Json(DeleteKeystoresResponse { data: results, slashing_protection }))
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
    use crate::traits::DeleteKeystoreError;
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
        slashing_protection: Arc<MockSlashingProtection>,
        validator_manager: Arc<MockValidatorManager>,
        doppelganger_monitor: Arc<MockDoppelgangerMonitor>,
    }

    impl TestApp {
        fn new() -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
            }
        }

        fn with_keys(keys: Vec<Pubkey>) -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::with_keys(keys)),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
            }
        }

        fn router(&self) -> Router {
            let state = Arc::new(AppState {
                keystore_manager: self.keystore_manager.clone(),
                slashing_protection: self.slashing_protection.clone(),
                validator_manager: self.validator_manager.clone(),
                doppelganger_monitor: self.doppelganger_monitor.clone(),
            });
            Router::new()
                .route(
                    "/eth/v1/keystores",
                    get(list_keystores).post(import_keystores).delete(delete_keystores),
                )
                .with_state(state)
        }

        fn authed_router(&self, token: &str) -> Router {
            auth::with_auth(self.router(), Arc::new(token.to_string()))
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
        let app = TestApp::new();
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
        let imported = app.slashing_protection.imported.lock().unwrap();
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
}
