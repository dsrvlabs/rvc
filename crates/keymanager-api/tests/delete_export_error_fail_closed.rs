//! Integration test — KM-1: DELETE `/eth/v1/keystores` must fail CLOSED when
//! slashing-protection export fails.
//!
//! # Spec-correct (fail-closed) behavior verified here
//!
//! When `SlashingProtection::export_interchange` returns `Err`, the handler
//! MUST:
//!   1. Return `ApiError::Internal` (HTTP 500) — NOT `Ok`.
//!   2. NOT delete any keystores (keys remain present after the call).
//!   3. NOT produce an empty-interchange success response (covered by #1).
//!
//! # Schema-agnostic design
//!
//! All assertions are driven through the `SlashingProtection` trait interface
//! (`pubkeys in → Result<String, String> out`).  The test does NOT inspect any
//! on-disk SQLite layout, column names, or file paths.  This means it passes
//! against both the current slashing-DB schema and any future schema revision
//! (e.g., the v2 schema added by Issue 2.4).

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::handlers::{delete_keystores, AppState};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DoppelgangerMonitor, ImportKeystoreError, KeystoreManager, Pubkey,
    RemoteKeyManager, SlashingProtection, ValidatorConfigManager, ValidatorManager,
};
use rvc_keymanager_api::types::DeleteKeystoresRequest;

use axum::extract::{Json, State};

// ── Helper ────────────────────────────────────────────────────────────────────

/// Returns a deterministic 48-byte pubkey seeded by `id`.
fn test_pubkey(id: u8) -> Pubkey {
    let mut pk = [0u8; 48];
    pk[0] = id;
    pk
}

fn test_pubkey_hex(id: u8) -> String {
    format!("0x{}", hex::encode(test_pubkey(id)))
}

// ── Mock: slashing-protection that always fails export ────────────────────────

/// A `SlashingProtection` implementation whose `export_interchange` always
/// returns `Err`.  Used to simulate a corrupt or unavailable slashing DB.
struct FailingExport;

impl SlashingProtection for FailingExport {
    fn import_interchange(&self, _interchange_json: &str) -> Result<(), String> {
        Ok(())
    }

    fn export_interchange(&self, _pubkeys: &[Pubkey]) -> Result<String, String> {
        Err("boom: slashing DB unavailable".into())
    }
}

// ── Mock: keystore manager that tracks deletion attempts ──────────────────────

/// A `KeystoreManager` that:
///   * Reports the registered pubkeys as present via `has_key`.
///   * Counts how many times `delete_keystore` is invoked.
///   * Succeeds if `delete_keystore` is called (so the test isolates the
///     handler's abort logic, not a downstream deletion error).
struct CountingKeystoreManager {
    keys: Vec<Pubkey>,
    delete_call_count: AtomicU32,
}

impl CountingKeystoreManager {
    fn with_keys(keys: Vec<Pubkey>) -> Self {
        Self { keys, delete_call_count: AtomicU32::new(0) }
    }

    fn delete_call_count(&self) -> u32 {
        self.delete_call_count.load(Ordering::SeqCst)
    }
}

impl KeystoreManager for CountingKeystoreManager {
    fn list_keys(&self) -> Vec<Pubkey> {
        self.keys.clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.keys.contains(pubkey)
    }

    fn import_keystore(&self, _: &str, _: &str) -> Result<Pubkey, ImportKeystoreError> {
        unimplemented!("not exercised in this test")
    }

    fn delete_keystore(&self, _pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        self.delete_call_count.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

// ── Minimal no-op mocks for the remaining AppState fields ────────────────────

struct NoopValidatorManager;
impl ValidatorManager for NoopValidatorManager {
    fn add_validator(&self, _: Pubkey, _: bool) {}
    fn remove_validator(&self, _: &Pubkey) -> bool {
        false
    }
    fn set_validator_enabled(&self, _: &Pubkey, _: bool) {}
}

struct NoopDoppelgangerMonitor;
impl DoppelgangerMonitor for NoopDoppelgangerMonitor {
    fn start_monitoring(&self, _: Pubkey) {}
    fn stop_monitoring(&self, _: &Pubkey) {}
    fn is_doppelganger_safe(&self, _: &Pubkey) -> bool {
        true
    }
}

struct NoopRemoteKeyManager;
impl RemoteKeyManager for NoopRemoteKeyManager {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        vec![]
    }
    fn has_remote_key(&self, _: &Pubkey) -> bool {
        false
    }
    fn import_remote_key(
        &self,
        _: Pubkey,
        _: String,
    ) -> Result<(), rvc_keymanager_api::traits::ImportRemoteKeyError> {
        unimplemented!()
    }
    fn delete_remote_key(
        &self,
        _: &Pubkey,
    ) -> Result<bool, rvc_keymanager_api::traits::DeleteRemoteKeyError> {
        Ok(false)
    }
}

struct NoopConfigManager;
impl ValidatorConfigManager for NoopConfigManager {
    fn get_fee_recipient(&self, _: &Pubkey) -> Result<[u8; 20], ApiError> {
        Err(ApiError::NotFound("not found".into()))
    }
    fn set_fee_recipient(&self, _: &Pubkey, _: [u8; 20]) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_fee_recipient(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
    fn get_gas_limit(&self, _: &Pubkey) -> Result<u64, ApiError> {
        Err(ApiError::NotFound("not found".into()))
    }
    fn set_gas_limit(&self, _: &Pubkey, _: u64) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_gas_limit(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
    fn get_graffiti(&self, _: &Pubkey) -> Result<String, ApiError> {
        Ok(String::new())
    }
    fn set_graffiti(&self, _: &Pubkey, _: &str) -> Result<(), ApiError> {
        Ok(())
    }
    fn delete_graffiti(&self, _: &Pubkey) -> Result<(), ApiError> {
        Ok(())
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// KM-1: when `export_interchange` returns `Err`, `delete_keystores` must:
///   1. Return `Err(ApiError::Internal(_))` — not swallow the error and return
///      `Ok` with an empty interchange.
///   2. Not invoke `delete_keystore` on any keystore (fail before the
///      deletion loop).
///
/// On the un-patched code this test fails because the handler uses
/// `unwrap_or_else(|e| empty_interchange())`, proceeds to delete all
/// keystores, and returns `Ok` with an empty interchange.
#[tokio::test]
async fn test_delete_keystores_export_error_fails_closed_no_deletion() {
    let known_key = test_pubkey(42);
    let keystore_manager = Arc::new(CountingKeystoreManager::with_keys(vec![known_key]));

    let state = Arc::new(AppState {
        keystore_manager: keystore_manager.clone(),
        slashing_protection: Arc::new(FailingExport),
        validator_manager: Arc::new(NoopValidatorManager),
        doppelganger_monitor: Arc::new(NoopDoppelgangerMonitor),
        remote_key_manager: Arc::new(NoopRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
        doppelganger_window: std::time::Duration::ZERO,
        cancel_tokens: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let request = DeleteKeystoresRequest { pubkeys: vec![test_pubkey_hex(42)] };

    let result = delete_keystores(State(state.clone()), Json(request)).await;

    // Assertion 1: the handler must return Err(ApiError::Internal(_)) — HTTP 500.
    // On the bug-affected code this is Ok(...) with an empty interchange.
    match &result {
        Err(ApiError::Internal(_)) => {} // correct fail-closed behavior
        Ok(_) => panic!(
            "KM-1 BUG: handler returned Ok (success) when export failed; \
             expected Err(ApiError::Internal). Keys would have been deleted \
             with an empty slashing-protection interchange — double-sign hazard."
        ),
        Err(other) => panic!("expected ApiError::Internal, got {other:?}"),
    }

    // Assertion 2: no keystore must have been deleted.
    // The fix aborts before the deletion loop, so delete_call_count stays 0.
    let delete_calls = keystore_manager.delete_call_count();
    assert_eq!(
        delete_calls,
        0,
        "KM-1 BUG: delete_keystore was called {delete_calls} time(s) even though \
         slashing-protection export failed — keys must NOT be deleted when export errors."
    );

    // Assertion 3: the key must still be present (covered by counting mock above,
    // but assert explicitly for clarity).
    assert!(
        keystore_manager.has_key(&known_key),
        "KM-1 BUG: key was removed from the keystore despite a failed export"
    );

    // Note: assertion on "no empty interchange in response body" is covered by
    // assertion 1 — a 500 Err result has no success body at all.
}
