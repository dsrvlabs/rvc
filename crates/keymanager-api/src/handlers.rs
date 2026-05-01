use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use crypto::logging::{RedactedUrl, TruncatedPubkey};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::error::ApiError;
use crate::traits::{
    DoppelgangerMonitor, ImportKeystoreError, ImportRemoteKeyError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, ValidatorConfigManager, ValidatorManager,
    VoluntaryExitManager,
};
use crate::types::{
    DeleteKeystoreResult, DeleteKeystoresRequest, DeleteKeystoresResponse, DeleteRemoteKeyResult,
    DeleteRemoteKeyStatus, DeleteRemoteKeysRequest, DeleteRemoteKeysResponse, DeleteStatus,
    FeeRecipientData, FeeRecipientResponse, GasLimitData, GasLimitResponse, GraffitiData,
    GraffitiResponse, ImportKeystoreResult, ImportKeystoresRequest, ImportKeystoresResponse,
    ImportRemoteKeyResult, ImportRemoteKeyStatus, ImportRemoteKeysRequest,
    ImportRemoteKeysResponse, ImportStatus, KeystoreInfo, ListKeystoresResponse,
    ListRemoteKeysResponse, RemoteKeyEntry, SetFeeRecipientRequest, SetGasLimitRequest,
    SetGraffitiRequest, VoluntaryExitQuery, VoluntaryExitResponse,
};
use crate::url_validator;

pub struct AppState {
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
    pub remote_key_manager: Arc<dyn RemoteKeyManager>,
    pub config_manager: Arc<dyn ValidatorConfigManager>,
    pub exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
    pub allow_insecure_remote_signer: bool,
    pub attesting_enabled: Arc<AtomicBool>,
}

#[derive(Debug, Deserialize)]
pub struct SetAttestingRequest {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct SetAttestingResponse {
    pub enabled: bool,
}

pub async fn list_keystores(State(state): State<Arc<AppState>>) -> Json<ListKeystoresResponse> {
    // Per Keymanager API spec, GET /eth/v1/keystores returns only local keys.
    // Remote keys are returned by GET /eth/v1/remotekeys.
    let local_keys = state.keystore_manager.list_keys();

    let data: Vec<KeystoreInfo> = local_keys
        .into_iter()
        .map(|pk| KeystoreInfo {
            validating_pubkey: format!("0x{}", hex::encode(pk)),
            derivation_path: None,
            readonly: false,
        })
        .collect();

    info!(count = data.len(), "Listed local keystores");

    Json(ListKeystoresResponse { data })
}

pub async fn import_keystores(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ImportKeystoresRequest>,
) -> Result<Json<ImportKeystoresResponse>, ApiError> {
    let span = tracing::info_span!(
        "rvc.keymanager.import_keystores",
        rvc.keymanager.count = request.keystores.len(),
    );
    let _guard = span.enter();

    info!(count = request.keystores.len(), "Importing keystores");

    if request.keystores.len() != request.passwords.len() {
        return Err(ApiError::BadRequest(
            "keystores and passwords arrays must have the same length".into(),
        ));
    }

    // Import slashing protection FIRST — before any keystores are activated.
    // This prevents a window where signing keys exist without slashing records.
    if let Some(ref slashing_json) = request.slashing_protection {
        if let Err(e) = state.slashing_protection.import_interchange(slashing_json) {
            return Err(sanitize_internal(e, "slashing protection import failed"));
        }
    }

    let mut results = Vec::with_capacity(request.keystores.len());

    for (keystore_json, password) in request.keystores.iter().zip(request.passwords.iter()) {
        match state.keystore_manager.import_keystore(keystore_json, password) {
            Ok(pubkey) => {
                let pubkey_hex = format!("0x{}", hex::encode(pubkey));
                info!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    status = "imported",
                    "Keystore import result"
                );
                state.validator_manager.add_validator(pubkey, false);
                state.doppelganger_monitor.start_monitoring(pubkey);
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Imported,
                    message: String::new(),
                });
            }
            Err(ImportKeystoreError::Duplicate) => {
                info!(status = "duplicate", "Keystore import result");
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Duplicate,
                    message: "key already exists".into(),
                });
            }
            Err(e) => {
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Error,
                    message: sanitize_item_err(e, "keystore import failed"),
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
    let span = tracing::info_span!(
        "rvc.keymanager.delete_keystores",
        rvc.keymanager.count = request.pubkeys.len(),
    );
    let _guard = span.enter();

    warn!(count = request.pubkeys.len(), "Deleting keystores");

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
    for (i, parse_result) in parsed.iter().enumerate() {
        let pubkey_hex = &request.pubkeys[i];
        match parse_result {
            Ok(pubkey) => match state.keystore_manager.delete_keystore(pubkey) {
                Ok(true) => {
                    warn!(
                        pubkey = %TruncatedPubkey::new(pubkey_hex),
                        status = "deleted",
                        "Keystore delete result"
                    );
                    state.validator_manager.remove_validator(pubkey);
                    state.doppelganger_monitor.stop_monitoring(pubkey);
                    results.push(DeleteKeystoreResult {
                        status: DeleteStatus::Deleted,
                        message: String::new(),
                    });
                }
                Ok(false) => {
                    warn!(
                        pubkey = %TruncatedPubkey::new(pubkey_hex),
                        status = "not_found",
                        "Keystore delete result"
                    );
                    results.push(DeleteKeystoreResult {
                        status: DeleteStatus::NotFound,
                        message: String::new(),
                    });
                }
                Err(e) => {
                    // M-8: sanitize underlying error (paths, errno, etc.) before
                    // returning to the client. The full chain is logged inside
                    // sanitize_item_err with a request_id correlator.
                    let message = sanitize_item_err(&e, "keystore delete failed");
                    results.push(DeleteKeystoreResult { status: DeleteStatus::Error, message });
                }
            },
            Err(e) => {
                // Pubkey-parse error — the value of `e` here is generated
                // server-side from caller input (parse_pubkey), so it is
                // BadRequest-class and safe to echo as-is.
                warn!(
                    pubkey = %TruncatedPubkey::new(pubkey_hex),
                    status = "error",
                    error = %e,
                    "Keystore delete result"
                );
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
    let data: Vec<RemoteKeyEntry> = keys
        .into_iter()
        .map(|(pk, url)| RemoteKeyEntry {
            pubkey: format!("0x{}", hex::encode(pk)),
            url,
            readonly: false,
        })
        .collect();

    info!(count = data.len(), "Listed remote keys");

    Json(ListRemoteKeysResponse { data })
}

pub async fn import_remote_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ImportRemoteKeysRequest>,
) -> Json<ImportRemoteKeysResponse> {
    let span = tracing::info_span!(
        "rvc.keymanager.import_remote_keys",
        rvc.keymanager.count = request.remote_keys.len(),
    );
    let _guard = span.enter();

    info!(count = request.remote_keys.len(), "Importing remote keys");

    let mut results = Vec::with_capacity(request.remote_keys.len());

    for key_import in &request.remote_keys {
        match parse_pubkey(&key_import.pubkey) {
            Ok(pubkey) => {
                if let Err(e) = url_validator::validate_remote_signer_url(
                    &key_import.url,
                    state.allow_insecure_remote_signer,
                ) {
                    warn!(
                        pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                        status = "error",
                        error = %e,
                        "Remote key import result"
                    );
                    results.push(ImportRemoteKeyResult {
                        status: ImportRemoteKeyStatus::Error,
                        message: e,
                    });
                    continue;
                }
                match state.remote_key_manager.import_remote_key(pubkey, key_import.url.clone()) {
                    Ok(()) => {
                        info!(
                            pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                            url = %RedactedUrl(&key_import.url),
                            status = "imported",
                            "Remote key import result"
                        );
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Imported,
                            message: String::new(),
                        });
                    }
                    Err(ImportRemoteKeyError::Duplicate) => {
                        info!(
                            pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                            status = "duplicate",
                            "Remote key import result"
                        );
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Duplicate,
                            message: "key already exists".into(),
                        });
                    }
                    Err(e) => {
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Error,
                            message: sanitize_item_err(e, "remote key import failed"),
                        });
                    }
                }
            }
            Err(e) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                    status = "error",
                    error = %e,
                    "Remote key import result"
                );
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
    let span = tracing::info_span!(
        "rvc.keymanager.delete_remote_keys",
        rvc.keymanager.count = request.pubkeys.len(),
    );
    let _guard = span.enter();

    warn!(count = request.pubkeys.len(), "Deleting remote keys");

    let mut results = Vec::with_capacity(request.pubkeys.len());

    for pubkey_str in &request.pubkeys {
        match parse_pubkey(pubkey_str) {
            Ok(pubkey) => match state.remote_key_manager.delete_remote_key(&pubkey) {
                Ok(true) => {
                    warn!(
                        pubkey = %TruncatedPubkey::new(pubkey_str),
                        status = "deleted",
                        "Remote key delete result"
                    );
                    results.push(DeleteRemoteKeyResult {
                        status: DeleteRemoteKeyStatus::Deleted,
                        message: String::new(),
                    });
                }
                Ok(false) => {
                    warn!(
                        pubkey = %TruncatedPubkey::new(pubkey_str),
                        status = "not_found",
                        "Remote key delete result"
                    );
                    results.push(DeleteRemoteKeyResult {
                        status: DeleteRemoteKeyStatus::NotFound,
                        message: String::new(),
                    });
                }
                Err(e) => {
                    // M-8: DeleteRemoteKeyError::Other is `#[error("{0}")]`
                    // — passes through whatever the backend put in the inner
                    // String (DB sockets, internal service names). Sanitize.
                    let message = sanitize_item_err(&e, "remote key delete failed");
                    results.push(DeleteRemoteKeyResult {
                        status: DeleteRemoteKeyStatus::Error,
                        message,
                    });
                }
            },
            Err(e) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(pubkey_str),
                    status = "error",
                    error = %e,
                    "Remote key delete result"
                );
                results.push(DeleteRemoteKeyResult {
                    status: DeleteRemoteKeyStatus::Error,
                    message: e,
                });
            }
        }
    }

    Json(DeleteRemoteKeysResponse { data: results })
}

// --- Fee Recipient ---

pub async fn get_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<FeeRecipientResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let addr = state.config_manager.get_fee_recipient(&pubkey)?;
    Ok(Json(FeeRecipientResponse {
        data: FeeRecipientData {
            pubkey: format_pubkey(&pubkey),
            ethaddress: format!("0x{}", hex::encode(addr)),
        },
    }))
}

pub async fn set_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetFeeRecipientRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let addr = parse_eth_address(&request.ethaddress)?;
    if addr == [0u8; 20] {
        return Err(ApiError::BadRequest("fee recipient cannot be zero address".into()));
    }
    state.config_manager.set_fee_recipient(&pubkey, addr)?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    state.config_manager.delete_fee_recipient(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Gas Limit ---

pub async fn get_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<GasLimitResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let gas_limit = state.config_manager.get_gas_limit(&pubkey)?;
    Ok(Json(GasLimitResponse {
        data: GasLimitData { pubkey: format_pubkey(&pubkey), gas_limit: gas_limit.to_string() },
    }))
}

pub async fn set_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetGasLimitRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let limit = request
        .gas_limit
        .parse::<u64>()
        .map_err(|_| ApiError::BadRequest("invalid gas_limit: must be a numeric string".into()))?;
    state.config_manager.set_gas_limit(&pubkey, limit)?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    state.config_manager.delete_gas_limit(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Graffiti ---

pub async fn get_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<GraffitiResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let graffiti = state.config_manager.get_graffiti(&pubkey)?;
    Ok(Json(GraffitiResponse { data: GraffitiData { pubkey: format_pubkey(&pubkey), graffiti } }))
}

pub async fn set_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetGraffitiRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    if request.graffiti.len() > 32 {
        return Err(ApiError::BadRequest("graffiti must be 32 bytes or less".into()));
    }
    state.config_manager.set_graffiti(&pubkey, &request.graffiti)?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    state.config_manager.delete_graffiti(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Voluntary Exit ---

pub async fn sign_voluntary_exit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Query(query): Query<VoluntaryExitQuery>,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;

    let epoch = query
        .epoch
        .map(|e| e.parse::<u64>())
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid epoch".into()))?;

    let exit_manager = state.exit_manager.as_ref().ok_or_else(|| {
        ApiError::Internal("voluntary exit not available: beacon node not configured".into())
    })?;

    warn!(pubkey = %pubkey_hex, epoch = ?epoch, "Voluntary exit requested — THIS IS IRREVERSIBLE");

    let signed_exit = exit_manager.sign_voluntary_exit(&pubkey, epoch).await?;

    Ok(Json(VoluntaryExitResponse { data: signed_exit }))
}

/// Pre-signed exit: signs the voluntary exit and returns it without submitting.
///
/// `POST /rvc/v1/validator/:pubkey/prepare_exit`
pub async fn prepare_exit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Query(query): Query<VoluntaryExitQuery>,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;

    let epoch = query
        .epoch
        .map(|e| e.parse::<u64>())
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid epoch".into()))?;

    let exit_manager = state.exit_manager.as_ref().ok_or_else(|| {
        ApiError::Internal("voluntary exit not available: beacon node not configured".into())
    })?;

    info!(pubkey = %pubkey_hex, epoch = ?epoch, "Preparing pre-signed voluntary exit (not submitting)");

    let signed_exit = exit_manager.sign_voluntary_exit(&pubkey, epoch).await?;

    Ok(Json(VoluntaryExitResponse { data: signed_exit }))
}

/// Escape ASCII control characters in `s` (notably `\n`, `\r`) to their
/// `\xHH` form so that an attacker cannot smuggle a forged log line through
/// a user-controllable error string when the tracing-subscriber formatter is
/// in text mode (CWE-117 / OWASP A09:2021).  Defense-in-depth in addition
/// to the JSON-mode formatter recommended in the deployment guide.
fn escape_log_control_chars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() {
            out.push_str(&format!("\\x{:02x}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Logs `err` at `error!` level with a fresh request ID and returns a generic
/// `ApiError::Internal` whose message is safe to send to API clients.
fn sanitize_internal<E: std::fmt::Display>(err: E, ctx: &str) -> ApiError {
    let req_id = Uuid::new_v4();
    let safe = escape_log_control_chars(&err.to_string());
    error!(request_id = %req_id, error = %safe, "{ctx}");
    ApiError::Internal(format!("internal error (request_id={req_id})"))
}

/// Logs `err` at `error!` level with a fresh request ID and returns a generic
/// string suitable for the per-item `message` field in bulk-operation responses.
fn sanitize_item_err<E: std::fmt::Display>(err: E, ctx: &str) -> String {
    let req_id = Uuid::new_v4();
    let safe = escape_log_control_chars(&err.to_string());
    error!(request_id = %req_id, error = %safe, "{ctx}");
    format!("key error (request_id={req_id})")
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

pub(crate) fn parse_eth_address(s: &str) -> Result<[u8; 20], ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| ApiError::BadRequest(format!("invalid hex: {e}")))?;
    let addr: [u8; 20] =
        bytes.try_into().map_err(|_| ApiError::BadRequest("address must be 20 bytes".into()))?;
    Ok(addr)
}

pub(crate) fn format_pubkey(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

pub async fn set_attesting_enabled(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SetAttestingRequest>,
) -> Json<SetAttestingResponse> {
    let previous = state.attesting_enabled.swap(request.enabled, Ordering::Relaxed);
    let current = request.enabled;

    if previous && !current {
        warn!("Attestation duties disabled via API");
    } else if !previous && current {
        info!("Attestation duties re-enabled via API");
    }

    metrics::definitions::RVC_ATTESTING_ENABLED.set(if current { 1.0 } else { 0.0 });

    Json(SetAttestingResponse { enabled: current })
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
    use parking_lot::Mutex;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

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
            self.keys.lock().clone()
        }

        fn has_key(&self, pubkey: &Pubkey) -> bool {
            self.keys.lock().contains(pubkey)
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

            let mut keys = self.keys.lock();
            if keys.contains(&pubkey) {
                return Err(ImportKeystoreError::Duplicate);
            }
            keys.push(pubkey);
            Ok(pubkey)
        }

        fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
            let mut keys = self.keys.lock();
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
            self.imported.lock().push(interchange_json.to_string());
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
            self.validators.lock().push((pubkey, enabled));
        }

        fn remove_validator(&self, pubkey: &Pubkey) -> bool {
            let mut validators = self.validators.lock();
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
            self.monitored.lock().push(pubkey);
        }

        fn stop_monitoring(&self, pubkey: &Pubkey) {
            let mut monitored = self.monitored.lock();
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
            self.keys.lock().clone()
        }

        fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
            self.keys.lock().iter().any(|(pk, _)| pk == pubkey)
        }

        fn import_remote_key(
            &self,
            pubkey: Pubkey,
            url: String,
        ) -> Result<(), ImportRemoteKeyError> {
            let mut keys = self.keys.lock();
            if keys.iter().any(|(pk, _)| *pk == pubkey) {
                return Err(ImportRemoteKeyError::Duplicate);
            }
            keys.push((pubkey, url));
            Ok(())
        }

        fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
            let mut keys = self.keys.lock();
            if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
                keys.remove(pos);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    struct MockValidatorConfigManager {
        fee_recipients: Mutex<std::collections::HashMap<Pubkey, [u8; 20]>>,
        gas_limits: Mutex<std::collections::HashMap<Pubkey, u64>>,
        graffiti: Mutex<std::collections::HashMap<Pubkey, String>>,
        known_pubkeys: Mutex<Vec<Pubkey>>,
    }

    impl MockValidatorConfigManager {
        fn new() -> Self {
            Self {
                fee_recipients: Mutex::new(std::collections::HashMap::new()),
                gas_limits: Mutex::new(std::collections::HashMap::new()),
                graffiti: Mutex::new(std::collections::HashMap::new()),
                known_pubkeys: Mutex::new(Vec::new()),
            }
        }

        fn with_validator(pubkey: Pubkey) -> Self {
            let m = Self::new();
            m.known_pubkeys.lock().push(pubkey);
            m
        }
    }

    impl ValidatorConfigManager for MockValidatorConfigManager {
        fn get_fee_recipient(&self, pubkey: &Pubkey) -> Result<[u8; 20], ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.fee_recipients
                .lock()
                .get(pubkey)
                .copied()
                .ok_or_else(|| ApiError::NotFound("fee recipient not set".into()))
        }

        fn set_fee_recipient(&self, pubkey: &Pubkey, address: [u8; 20]) -> Result<(), ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.fee_recipients.lock().insert(*pubkey, address);
            Ok(())
        }

        fn delete_fee_recipient(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.fee_recipients.lock().remove(pubkey);
            Ok(())
        }

        fn get_gas_limit(&self, pubkey: &Pubkey) -> Result<u64, ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.gas_limits
                .lock()
                .get(pubkey)
                .copied()
                .ok_or_else(|| ApiError::NotFound("gas limit not set".into()))
        }

        fn set_gas_limit(&self, pubkey: &Pubkey, limit: u64) -> Result<(), ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.gas_limits.lock().insert(*pubkey, limit);
            Ok(())
        }

        fn delete_gas_limit(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.gas_limits.lock().remove(pubkey);
            Ok(())
        }

        fn get_graffiti(&self, pubkey: &Pubkey) -> Result<String, ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            Ok(self.graffiti.lock().get(pubkey).cloned().unwrap_or_default())
        }

        fn set_graffiti(&self, pubkey: &Pubkey, graffiti: &str) -> Result<(), ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.graffiti.lock().insert(*pubkey, graffiti.to_string());
            Ok(())
        }

        fn delete_graffiti(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound("validator not found".into()));
            }
            self.graffiti.lock().remove(pubkey);
            Ok(())
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
        config_manager: Arc<MockValidatorConfigManager>,
    }

    impl TestApp {
        fn new() -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
                config_manager: Arc::new(MockValidatorConfigManager::new()),
            }
        }

        fn with_keys(keys: Vec<Pubkey>) -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::with_keys(keys)),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
                config_manager: Arc::new(MockValidatorConfigManager::new()),
            }
        }

        fn with_remote_keys(keys: Vec<(Pubkey, String)>) -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::with_keys(keys)),
                config_manager: Arc::new(MockValidatorConfigManager::new()),
            }
        }

        fn with_failing_slashing() -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(FailingSlashingProtection),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
                config_manager: Arc::new(MockValidatorConfigManager::new()),
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
                config_manager: Arc::new(MockValidatorConfigManager::new()),
            }
        }

        fn with_config_manager(config_manager: MockValidatorConfigManager) -> Self {
            Self {
                keystore_manager: Arc::new(MockKeystoreManager::new()),
                slashing_protection: Arc::new(MockSlashingProtection::new()),
                validator_manager: Arc::new(MockValidatorManager::new()),
                doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
                remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
                config_manager: Arc::new(config_manager),
            }
        }

        fn router(&self) -> Router {
            let state = Arc::new(AppState {
                keystore_manager: self.keystore_manager.clone(),
                slashing_protection: self.slashing_protection.clone(),
                validator_manager: self.validator_manager.clone(),
                doppelganger_monitor: self.doppelganger_monitor.clone(),
                remote_key_manager: self.remote_key_manager.clone(),
                config_manager: self.config_manager.clone(),
                exit_manager: None,
                allow_insecure_remote_signer: true,
                attesting_enabled: Arc::new(AtomicBool::new(true)),
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
            auth::with_auth(self.router(), Arc::new(Zeroizing::new(token.to_string())))
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

        let validators = app.validator_manager.validators.lock();
        assert_eq!(validators.len(), 1);
        assert!(!validators[0].1); // disabled for doppelganger

        let monitored = app.doppelganger_monitor.monitored.lock();
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
            config_manager: Arc::new(MockValidatorConfigManager::new()),
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
        let imported = mock_slashing.imported.lock();
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
        let validators = app.validator_manager.validators.lock();
        assert!(validators.is_empty());

        // No doppelganger monitoring started
        let monitored = app.doppelganger_monitor.monitored.lock();
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
        let monitored = app.doppelganger_monitor.monitored.lock();
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
            config_manager: Arc::new(MockValidatorConfigManager::new()),
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
        // COR-05: list_keystores now returns only local keys
        assert_eq!(resp.data.len(), 1);
        // Only local key present
        assert_eq!(resp.data[0].validating_pubkey, format!("0x{}", test_pubkey_hex(1)));
        assert!(!resp.data[0].readonly);
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

    // --- SEC-07: Body size limit tests ---

    #[tokio::test]
    async fn test_body_limit_rejects_oversized_payload() {
        use crate::server::KeymanagerServer;

        let app = TestApp::new();
        let server = KeymanagerServer::new(
            app.keystore_manager.clone(),
            app.slashing_protection.clone(),
            app.validator_manager.clone(),
            app.doppelganger_monitor.clone(),
            app.remote_key_manager.clone(),
            app.config_manager.clone(),
            None,
            "test_token".to_string(),
            "127.0.0.1:0".parse().unwrap(),
            vec![],
            1024, // 1 KB limit
            true,
            Arc::new(AtomicBool::new(true)),
        );

        let big_body = "x".repeat(2048); // 2 KB > 1 KB limit
        let response = server
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("Authorization", "Bearer test_token")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(big_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_body_limit_allows_normal_payload() {
        use crate::server::KeymanagerServer;

        let app = TestApp::new();
        let server = KeymanagerServer::new(
            app.keystore_manager.clone(),
            app.slashing_protection.clone(),
            app.validator_manager.clone(),
            app.doppelganger_monitor.clone(),
            app.remote_key_manager.clone(),
            app.config_manager.clone(),
            None,
            "test_token".to_string(),
            "127.0.0.1:0".parse().unwrap(),
            vec![],
            10 * 1024 * 1024, // 10 MB
            true,
            Arc::new(AtomicBool::new(true)),
        );

        let body = serde_json::json!({
            "keystores": [],
            "passwords": []
        })
        .to_string();

        let response = server
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/keystores")
                    .header("Authorization", "Bearer test_token")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    // --- SEC-06: CORS tests ---

    #[tokio::test]
    async fn test_cors_no_origins_no_header() {
        use crate::server::KeymanagerServer;

        let app = TestApp::new();
        let server = KeymanagerServer::new(
            app.keystore_manager.clone(),
            app.slashing_protection.clone(),
            app.validator_manager.clone(),
            app.doppelganger_monitor.clone(),
            app.remote_key_manager.clone(),
            app.config_manager.clone(),
            None,
            "test_token".to_string(),
            "127.0.0.1:0".parse().unwrap(),
            vec![],
            10 * 1024 * 1024,
            true,
            Arc::new(AtomicBool::new(true)),
        );

        let response = server
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/keystores")
                    .header("Authorization", "Bearer test_token")
                    .header("Origin", "http://evil.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.headers().get("access-control-allow-origin").is_none(),
            "No CORS headers should be set when no origins configured"
        );
    }

    #[tokio::test]
    async fn test_cors_with_allowed_origin() {
        use crate::server::KeymanagerServer;

        let app = TestApp::new();
        let server = KeymanagerServer::new(
            app.keystore_manager.clone(),
            app.slashing_protection.clone(),
            app.validator_manager.clone(),
            app.doppelganger_monitor.clone(),
            app.remote_key_manager.clone(),
            app.config_manager.clone(),
            None,
            "test_token".to_string(),
            "127.0.0.1:0".parse().unwrap(),
            vec!["http://localhost:3000".to_string()],
            10 * 1024 * 1024,
            true,
            Arc::new(AtomicBool::new(true)),
        );

        let response = server
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/eth/v1/keystores")
                    .header("Authorization", "Bearer test_token")
                    .header("Origin", "http://localhost:3000")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("access-control-allow-origin").map(|v| v.to_str().unwrap()),
            Some("http://localhost:3000"),
        );
    }

    #[tokio::test]
    async fn test_cors_preflight_options() {
        use crate::server::KeymanagerServer;

        let app = TestApp::new();
        let server = KeymanagerServer::new(
            app.keystore_manager.clone(),
            app.slashing_protection.clone(),
            app.validator_manager.clone(),
            app.doppelganger_monitor.clone(),
            app.remote_key_manager.clone(),
            app.config_manager.clone(),
            None,
            "test_token".to_string(),
            "127.0.0.1:0".parse().unwrap(),
            vec!["http://localhost:3000".to_string()],
            10 * 1024 * 1024,
            true,
            Arc::new(AtomicBool::new(true)),
        );

        let response = server
            .router()
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/eth/v1/keystores")
                    .header("Origin", "http://localhost:3000")
                    .header("Access-Control-Request-Method", "POST")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(response.headers().get("access-control-allow-origin").is_some());
    }

    // --- SEC-05: URL validation in import_remote_keys ---

    #[tokio::test]
    async fn test_import_remote_key_rejects_http_without_flag() {
        let app = TestApp::new();
        let state = Arc::new(AppState {
            keystore_manager: app.keystore_manager.clone(),
            slashing_protection: app.slashing_protection.clone(),
            validator_manager: app.validator_manager.clone(),
            doppelganger_monitor: app.doppelganger_monitor.clone(),
            remote_key_manager: app.remote_key_manager.clone(),
            config_manager: app.config_manager.clone(),
            exit_manager: None,
            allow_insecure_remote_signer: false,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        });

        let router = Router::new()
            .route("/eth/v1/remotekeys", axum::routing::post(import_remote_keys))
            .with_state(state);

        let body = serde_json::json!({
            "remote_keys": [{
                "pubkey": format!("0x{}", test_pubkey_hex(1)),
                "url": "http://signer.example.com:9000"
            }]
        })
        .to_string();

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes =
            http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
        let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
        assert!(resp.data[0].message.contains("HTTP not allowed"));
    }

    #[tokio::test]
    async fn test_import_remote_key_rejects_file_scheme() {
        let app = TestApp::new();
        let state = Arc::new(AppState {
            keystore_manager: app.keystore_manager.clone(),
            slashing_protection: app.slashing_protection.clone(),
            validator_manager: app.validator_manager.clone(),
            doppelganger_monitor: app.doppelganger_monitor.clone(),
            remote_key_manager: app.remote_key_manager.clone(),
            config_manager: app.config_manager.clone(),
            exit_manager: None,
            allow_insecure_remote_signer: false,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        });

        let router = Router::new()
            .route("/eth/v1/remotekeys", axum::routing::post(import_remote_keys))
            .with_state(state);

        let body = serde_json::json!({
            "remote_keys": [{
                "pubkey": format!("0x{}", test_pubkey_hex(1)),
                "url": "file:///etc/passwd"
            }]
        })
        .to_string();

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes =
            http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
        let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
        assert!(resp.data[0].message.contains("Unsupported URL scheme"));
    }

    #[tokio::test]
    async fn test_import_remote_key_rejects_private_ip() {
        let app = TestApp::new();
        let state = Arc::new(AppState {
            keystore_manager: app.keystore_manager.clone(),
            slashing_protection: app.slashing_protection.clone(),
            validator_manager: app.validator_manager.clone(),
            doppelganger_monitor: app.doppelganger_monitor.clone(),
            remote_key_manager: app.remote_key_manager.clone(),
            config_manager: app.config_manager.clone(),
            exit_manager: None,
            allow_insecure_remote_signer: false,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        });

        let router = Router::new()
            .route("/eth/v1/remotekeys", axum::routing::post(import_remote_keys))
            .with_state(state);

        let body = serde_json::json!({
            "remote_keys": [{
                "pubkey": format!("0x{}", test_pubkey_hex(1)),
                "url": "https://127.0.0.1:9000"
            }]
        })
        .to_string();

        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/eth/v1/remotekeys")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes =
            http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
        let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
        assert!(resp.data[0].message.contains("Private/reserved IP"));
    }

    // --- parse_eth_address tests ---

    #[test]
    fn test_parse_eth_address_valid_with_prefix() {
        let addr = parse_eth_address("0xAbcF8e0d4e9587369b2301D0790347320302cc09").unwrap();
        assert_eq!(addr.len(), 20);
        assert_eq!(hex::encode(addr), "abcf8e0d4e9587369b2301d0790347320302cc09");
    }

    #[test]
    fn test_parse_eth_address_valid_without_prefix() {
        let addr = parse_eth_address("AbcF8e0d4e9587369b2301D0790347320302cc09").unwrap();
        assert_eq!(hex::encode(addr), "abcf8e0d4e9587369b2301d0790347320302cc09");
    }

    #[test]
    fn test_parse_eth_address_invalid_hex() {
        let result = parse_eth_address("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_eth_address_wrong_length() {
        let result = parse_eth_address("0xabcdef");
        assert!(result.is_err());
    }

    // --- format_pubkey tests ---

    #[test]
    fn test_format_pubkey() {
        let mut pubkey = [0u8; 48];
        pubkey[0] = 0x93;
        pubkey[1] = 0x24;
        pubkey[47] = 0x4a;
        let formatted = format_pubkey(&pubkey);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 98); // 0x + 96 hex chars
        assert_eq!(&formatted[..6], "0x9324");
        assert!(formatted.ends_with("4a"));
    }

    // --- Fee recipient handler tests ---

    fn config_router(config_manager: MockValidatorConfigManager) -> Router {
        let app = TestApp::with_config_manager(config_manager);
        let state = Arc::new(AppState {
            keystore_manager: app.keystore_manager.clone(),
            slashing_protection: app.slashing_protection.clone(),
            validator_manager: app.validator_manager.clone(),
            doppelganger_monitor: app.doppelganger_monitor.clone(),
            remote_key_manager: app.remote_key_manager.clone(),
            config_manager: app.config_manager.clone(),
            exit_manager: None,
            allow_insecure_remote_signer: true,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        });
        Router::new()
            .route(
                "/eth/v1/validator/:pubkey/feerecipient",
                get(get_fee_recipient).post(set_fee_recipient).delete(delete_fee_recipient),
            )
            .route(
                "/eth/v1/validator/:pubkey/gas_limit",
                get(get_gas_limit).post(set_gas_limit).delete(delete_gas_limit),
            )
            .route(
                "/eth/v1/validator/:pubkey/graffiti",
                get(get_graffiti).post(set_graffiti).delete(delete_graffiti),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn test_get_fee_recipient_returns_value() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let addr = [0xABu8; 20];
        mock.fee_recipients.lock().insert(pk, addr);

        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder().uri(&uri).body(axum::body::Body::empty()).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["ethaddress"], format!("0x{}", hex::encode(addr)));
    }

    #[tokio::test]
    async fn test_get_fee_recipient_unknown_pubkey_404() {
        let mock = MockValidatorConfigManager::new();
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder().uri(&uri).body(axum::body::Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_set_fee_recipient_valid_202() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
        let body = serde_json::json!({"ethaddress": "0xAbcF8e0d4e9587369b2301D0790347320302cc09"});
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_set_fee_recipient_zero_address_400() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
        let body = serde_json::json!({"ethaddress": "0x0000000000000000000000000000000000000000"});
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_fee_recipient_204() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_fee_recipient_unknown_pubkey_404() {
        let mock = MockValidatorConfigManager::new();
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/feerecipient", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // --- Gas limit handler tests ---

    #[tokio::test]
    async fn test_get_gas_limit_returns_value() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        mock.gas_limits.lock().insert(pk, 30_000_000);

        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder().uri(&uri).body(axum::body::Body::empty()).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["gas_limit"], "30000000");
    }

    #[tokio::test]
    async fn test_get_gas_limit_unknown_pubkey_404() {
        let mock = MockValidatorConfigManager::new();
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder().uri(&uri).body(axum::body::Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_set_gas_limit_valid_202() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
        let body = serde_json::json!({"gas_limit": "30000000"});
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_set_gas_limit_non_numeric_400() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
        let body = serde_json::json!({"gas_limit": "not_a_number"});
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_gas_limit_204() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_gas_limit_unknown_pubkey_404() {
        let mock = MockValidatorConfigManager::new();
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/gas_limit", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // --- Graffiti handler tests ---

    #[tokio::test]
    async fn test_get_graffiti_returns_value() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        mock.graffiti.lock().insert(pk, "hello world".to_string());

        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder().uri(&uri).body(axum::body::Body::empty()).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["graffiti"], "hello world");
    }

    #[tokio::test]
    async fn test_get_graffiti_unknown_pubkey_404() {
        let mock = MockValidatorConfigManager::new();
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder().uri(&uri).body(axum::body::Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_set_graffiti_valid_202() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
        let body = serde_json::json!({"graffiti": "my graffiti"});
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_set_graffiti_too_long_400() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
        let body = serde_json::json!({"graffiti": "a]".repeat(17)}); // 34 bytes > 32
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_graffiti_204() {
        let pk = test_pubkey(1);
        let mock = MockValidatorConfigManager::with_validator(pk);
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_graffiti_unknown_pubkey_404() {
        let mock = MockValidatorConfigManager::new();
        let router = config_router(mock);
        let uri = format!("/eth/v1/validator/0x{}/graffiti", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // --- Voluntary exit handler tests ---

    use crate::types::VoluntaryExitResponse;

    struct MockVoluntaryExitManager {
        known_pubkeys: Mutex<Vec<Pubkey>>,
    }

    impl MockVoluntaryExitManager {
        fn new() -> Self {
            Self { known_pubkeys: Mutex::new(Vec::new()) }
        }

        fn with_validator(pubkey: Pubkey) -> Self {
            let m = Self::new();
            m.known_pubkeys.lock().push(pubkey);
            m
        }
    }

    #[async_trait::async_trait]
    impl VoluntaryExitManager for MockVoluntaryExitManager {
        async fn sign_voluntary_exit(
            &self,
            pubkey: &Pubkey,
            epoch: Option<u64>,
        ) -> Result<eth_types::SignedVoluntaryExit, ApiError> {
            if !self.known_pubkeys.lock().contains(pubkey) {
                return Err(ApiError::NotFound(format!(
                    "validator 0x{} not found",
                    hex::encode(pubkey)
                )));
            }
            let epoch = epoch.unwrap_or(100);
            Ok(eth_types::SignedVoluntaryExit {
                message: eth_types::VoluntaryExit { epoch, validator_index: 42 },
                signature: vec![0xaa; 96],
            })
        }
    }

    fn exit_router(exit_manager: Option<Arc<dyn VoluntaryExitManager>>) -> Router {
        let app = TestApp::new();
        let state = Arc::new(AppState {
            keystore_manager: app.keystore_manager.clone(),
            slashing_protection: app.slashing_protection.clone(),
            validator_manager: app.validator_manager.clone(),
            doppelganger_monitor: app.doppelganger_monitor.clone(),
            remote_key_manager: app.remote_key_manager.clone(),
            config_manager: app.config_manager.clone(),
            exit_manager,
            allow_insecure_remote_signer: true,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        });
        Router::new()
            .route(
                "/eth/v1/validator/:pubkey/voluntary_exit",
                axum::routing::post(sign_voluntary_exit),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn test_voluntary_exit_with_explicit_epoch() {
        let pk = test_pubkey(1);
        let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let router = exit_router(Some(mock));

        let uri = format!("/eth/v1/validator/0x{}/voluntary_exit?epoch=300000", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
        let resp: VoluntaryExitResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp.data.message.epoch, 300000);
        assert_eq!(resp.data.message.validator_index, 42);
    }

    #[tokio::test]
    async fn test_voluntary_exit_without_epoch_auto_detect() {
        let pk = test_pubkey(1);
        let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let router = exit_router(Some(mock));

        let uri = format!("/eth/v1/validator/0x{}/voluntary_exit", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
        let resp: VoluntaryExitResponse = serde_json::from_slice(&body_bytes).unwrap();
        // Mock returns epoch=100 when None is passed
        assert_eq!(resp.data.message.epoch, 100);
    }

    #[tokio::test]
    async fn test_voluntary_exit_invalid_epoch_400() {
        let pk = test_pubkey(1);
        let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let router = exit_router(Some(mock));

        let uri = format!("/eth/v1/validator/0x{}/voluntary_exit?epoch=abc", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_voluntary_exit_unknown_pubkey_404() {
        let mock = Arc::new(MockVoluntaryExitManager::new());
        let router = exit_router(Some(mock));

        let uri = format!("/eth/v1/validator/0x{}/voluntary_exit", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_voluntary_exit_no_exit_manager_500() {
        let router = exit_router(None);

        let uri = format!("/eth/v1/validator/0x{}/voluntary_exit", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // --- prepare_exit handler tests ---

    fn prepare_exit_router(exit_manager: Option<Arc<dyn VoluntaryExitManager>>) -> Router {
        let app = TestApp::new();
        let state = Arc::new(AppState {
            keystore_manager: app.keystore_manager.clone(),
            slashing_protection: app.slashing_protection.clone(),
            validator_manager: app.validator_manager.clone(),
            doppelganger_monitor: app.doppelganger_monitor.clone(),
            remote_key_manager: app.remote_key_manager.clone(),
            config_manager: app.config_manager.clone(),
            exit_manager,
            allow_insecure_remote_signer: true,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        });
        Router::new()
            .route("/rvc/v1/validator/:pubkey/prepare_exit", axum::routing::post(prepare_exit))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_prepare_exit_returns_signed_exit() {
        let pk = test_pubkey(1);
        let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let router = prepare_exit_router(Some(mock));

        let uri = format!("/rvc/v1/validator/0x{}/prepare_exit?epoch=300000", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
        let resp: VoluntaryExitResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp.data.message.epoch, 300000);
        assert_eq!(resp.data.message.validator_index, 42);
    }

    #[tokio::test]
    async fn test_prepare_exit_unknown_pubkey_404() {
        let mock = Arc::new(MockVoluntaryExitManager::new());
        let router = prepare_exit_router(Some(mock));

        let uri = format!("/rvc/v1/validator/0x{}/prepare_exit", test_pubkey_hex(99));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_prepare_exit_no_exit_manager_500() {
        let router = prepare_exit_router(None);

        let uri = format!("/rvc/v1/validator/0x{}/prepare_exit", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_prepare_exit_invalid_epoch_400() {
        let pk = test_pubkey(1);
        let mock = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let router = prepare_exit_router(Some(mock));

        let uri = format!("/rvc/v1/validator/0x{}/prepare_exit?epoch=abc", test_pubkey_hex(1));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ================================================================
    // Integration tests: full HTTP round-trip with auth (Issues 4.1–4.3)
    // ================================================================

    fn full_authed_router(
        config_manager: MockValidatorConfigManager,
        exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
    ) -> (Router, String) {
        let token = "test_integration_token_1234567890abcdef".to_string();
        let state = Arc::new(AppState {
            keystore_manager: Arc::new(MockKeystoreManager::new()),
            slashing_protection: Arc::new(MockSlashingProtection::new()),
            validator_manager: Arc::new(MockValidatorManager::new()),
            doppelganger_monitor: Arc::new(MockDoppelgangerMonitor::new()),
            remote_key_manager: Arc::new(MockRemoteKeyManager::new()),
            config_manager: Arc::new(config_manager),
            exit_manager,
            allow_insecure_remote_signer: true,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        });

        let api = Router::new()
            .route(
                "/eth/v1/validator/:pubkey/feerecipient",
                get(get_fee_recipient).post(set_fee_recipient).delete(delete_fee_recipient),
            )
            .route(
                "/eth/v1/validator/:pubkey/gas_limit",
                get(get_gas_limit).post(set_gas_limit).delete(delete_gas_limit),
            )
            .route(
                "/eth/v1/validator/:pubkey/graffiti",
                get(get_graffiti).post(set_graffiti).delete(delete_graffiti),
            )
            .route(
                "/eth/v1/validator/:pubkey/voluntary_exit",
                axum::routing::post(sign_voluntary_exit),
            )
            .with_state(state);

        let router = auth::with_auth(api, Arc::new(Zeroizing::new(token.clone())));
        (router, token)
    }

    fn authed_get(token: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn authed_post(token: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn authed_post_json(
        token: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    fn authed_delete(token: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn unauthenticated_request(method: &str, uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    // --- Issue 4.1: Fee recipient integration tests ---

    #[tokio::test]
    async fn test_fee_recipient_lifecycle() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");
        let eth_addr = "0xAbcF8e0d4e9587369b2301D0790347320302cc09";

        // POST: set fee recipient → 202
        let resp = router
            .clone()
            .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "ethaddress": eth_addr })))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // GET: verify it was set → 200
        let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["data"]["ethaddress"].as_str().unwrap().to_lowercase(),
            eth_addr.to_lowercase()
        );

        // DELETE: remove fee recipient → 204
        let resp = router.clone().oneshot(authed_delete(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // GET: verify it returns 404 after deletion
        let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_fee_recipient_auth_required() {
        let pk = test_pubkey(1);
        let (router, _token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");

        let resp = router.oneshot(unauthenticated_request("GET", &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_fee_recipient_unknown_pubkey() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let unknown_hex = format!("0x{}", test_pubkey_hex(99));
        let uri = format!("/eth/v1/validator/{unknown_hex}/feerecipient");

        let resp = router.oneshot(authed_get(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_fee_recipient_invalid_address() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");

        let resp = router
            .oneshot(authed_post_json(
                &token,
                &uri,
                serde_json::json!({ "ethaddress": "0xinvalid" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_fee_recipient_zero_address() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");

        let resp = router
            .oneshot(authed_post_json(
                &token,
                &uri,
                serde_json::json!({ "ethaddress": "0x0000000000000000000000000000000000000000" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // --- Issue 4.2: Gas limit + graffiti integration tests ---

    #[tokio::test]
    async fn test_gas_limit_lifecycle() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/gas_limit");

        // POST: set gas limit → 202
        let resp = router
            .clone()
            .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "gas_limit": "30000000" })))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // GET: verify → 200
        let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["gas_limit"], "30000000");

        // DELETE → 204
        let resp = router.clone().oneshot(authed_delete(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // GET: verify 404 after deletion
        let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_gas_limit_string_encoding() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/gas_limit");

        router
            .clone()
            .oneshot(authed_post_json(&token, &uri, serde_json::json!({ "gas_limit": "30000000" })))
            .await
            .unwrap();

        let resp = router.oneshot(authed_get(&token, &uri)).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["data"]["gas_limit"].is_string(),
            "gas_limit must be a JSON string, not number"
        );
        assert_eq!(json["data"]["gas_limit"].as_str().unwrap(), "30000000");
    }

    #[tokio::test]
    async fn test_gas_limit_invalid_value() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/gas_limit");

        let resp = router
            .oneshot(authed_post_json(
                &token,
                &uri,
                serde_json::json!({ "gas_limit": "not_a_number" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_graffiti_lifecycle() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/graffiti");

        // POST: set graffiti → 202
        let resp = router
            .clone()
            .oneshot(authed_post_json(
                &token,
                &uri,
                serde_json::json!({ "graffiti": "hello world" }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // GET: verify → 200
        let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["graffiti"], "hello world");

        // DELETE → 204
        let resp = router.clone().oneshot(authed_delete(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // GET: after delete returns empty default
        let resp = router.clone().oneshot(authed_get(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["graffiti"], "");
    }

    #[tokio::test]
    async fn test_graffiti_max_length() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/graffiti");

        // 33 bytes → 400
        let resp = router
            .clone()
            .oneshot(authed_post_json(
                &token,
                &uri,
                serde_json::json!({ "graffiti": "a".repeat(33) }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 32 bytes → 202
        let resp = router
            .oneshot(authed_post_json(
                &token,
                &uri,
                serde_json::json!({ "graffiti": "a".repeat(32) }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_graffiti_auth_required() {
        let pk = test_pubkey(1);
        let (router, _token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/graffiti");

        let resp = router.oneshot(unauthenticated_request("GET", &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Issue 4.3: Voluntary exit integration tests ---

    #[tokio::test]
    async fn test_voluntary_exit_with_epoch_integration() {
        let pk = test_pubkey(1);
        let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), Some(exit_mgr));
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit?epoch=300000");

        let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["message"]["epoch"], "300000");
    }

    #[tokio::test]
    async fn test_voluntary_exit_auto_epoch_integration() {
        let pk = test_pubkey(1);
        let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), Some(exit_mgr));
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit");

        let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Mock defaults to epoch 100 when not specified
        assert_eq!(json["data"]["message"]["epoch"], "100");
    }

    #[tokio::test]
    async fn test_voluntary_exit_invalid_epoch_integration() {
        let pk = test_pubkey(1);
        let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), Some(exit_mgr));
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit?epoch=abc");

        let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_voluntary_exit_unknown_pubkey_integration() {
        let pk = test_pubkey(1);
        let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), Some(exit_mgr));
        let unknown_hex = format!("0x{}", test_pubkey_hex(99));
        let uri = format!("/eth/v1/validator/{unknown_hex}/voluntary_exit");

        let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_voluntary_exit_no_manager_integration() {
        let pk = test_pubkey(1);
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), None);
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit");

        let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_voluntary_exit_auth_required_integration() {
        let pk = test_pubkey(1);
        let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let (router, _token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), Some(exit_mgr));
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit");

        let resp = router.oneshot(unauthenticated_request("POST", &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_voluntary_exit_response_schema() {
        let pk = test_pubkey(1);
        let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
        let (router, token) =
            full_authed_router(MockValidatorConfigManager::with_validator(pk), Some(exit_mgr));
        let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
        let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit?epoch=300000");

        let resp = router.oneshot(authed_post(&token, &uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // epoch and validator_index must be strings per Eth2 spec
        assert!(json["data"]["message"]["epoch"].is_string(), "epoch must be a string");
        assert!(
            json["data"]["message"]["validator_index"].is_string(),
            "validator_index must be a string"
        );

        // signature must be 0x-prefixed hex
        let sig = json["data"]["signature"].as_str().expect("signature must be a string");
        assert!(sig.starts_with("0x"), "signature must start with 0x");
        assert!(
            hex::decode(sig.strip_prefix("0x").unwrap()).is_ok(),
            "signature must be valid hex"
        );
    }
}
