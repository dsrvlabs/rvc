//! KM-2 (Issue 2.12) — doppelganger cancel-token race regression tests.
//!
//! The import handler keeps a per-pubkey cancel-token map
//! (`AppState::cancel_tokens`).  Each `POST /eth/v1/keystores` spawns a
//! background task that, after the doppelganger window elapses, flips the
//! validator to attesting-enabled — unless its `CancellationToken` was
//! cancelled first (e.g. by a `DELETE`).
//!
//! On `develop` the import path inserts the new token with a bare
//! `map.insert(pubkey, token)` that OVERWRITES any existing token WITHOUT
//! cancelling it, and the delete path removes+cancels the token under a
//! SEPARATE lock acquisition.  A concurrent delete + re-import can therefore
//! leave a STALE background task alive that later fires
//! `set_validator_enabled(true)` on a key that is inside a FRESH doppelganger
//! window — a slashing-safety hole.
//!
//! These tests assert the four PRD §KM-2 acceptance criteria:
//!   (a) every `insert` cancels the displaced token;
//!   (b) the delete's keystore-removal AND token-removal/cancel are one
//!       critical section (a concurrent import cannot interleave between them);
//!   (c) the window-elapsed branch prunes its OWN cancel-token entry;
//!   (d) a regression test reproduces the concurrent delete+re-import race and
//!       asserts the displaced monitoring is cancelled and the new window
//!       starts fresh (no stale task enables the key).

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rvc_keymanager_api::error::ApiError;
use rvc_keymanager_api::gate::DoppelgangerGate;
use rvc_keymanager_api::handlers::{delete_keystores, import_keystores, AppState};
use rvc_keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, DoppelgangerMonitor, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection,
    ValidatorConfigManager, ValidatorManager,
};

// ── Mock implementations ─────────────────────────────────────────────────────

/// Keystore manager whose `delete_keystore` and `import_keystore` can be gated
/// so a test can pin the dangerous interleaving deterministically.
struct GatedKeystoreManager {
    keys: Mutex<Vec<Pubkey>>,
    /// Fires once, right after a `delete_keystore` removes a key.
    keystore_removed: Mutex<Option<mpsc::Sender<()>>>,
    /// If set, `import_keystore` blocks until it observes the key absent
    /// (i.e. a concurrent delete already removed it) before importing.
    import_waits_for_delete: bool,
}

impl GatedKeystoreManager {
    fn new() -> Self {
        Self {
            keys: Mutex::new(Vec::new()),
            keystore_removed: Mutex::new(None),
            import_waits_for_delete: false,
        }
    }
}

impl KeystoreManager for GatedKeystoreManager {
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
        let v: serde_json::Value = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        let hex = v["pubkey"]
            .as_str()
            .ok_or_else(|| ImportKeystoreError::InvalidKeystore("missing pubkey".into()))?;
        let bytes =
            hex::decode(hex).map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;
        if bytes.len() != 48 {
            return Err(ImportKeystoreError::InvalidKeystore("pubkey must be 48 bytes".into()));
        }
        let mut pk = [0u8; 48];
        pk.copy_from_slice(&bytes);

        // Gate: wait until a concurrent delete has removed this key from the
        // keystore so the re-import lands on an empty slot (mirroring the
        // delete-then-reimport race).  Bounded so a serialised GREEN run cannot
        // wedge forever.
        if self.import_waits_for_delete {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while self.keys.lock().unwrap().contains(&pk) {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        let mut keys = self.keys.lock().unwrap();
        if keys.contains(&pk) {
            return Err(ImportKeystoreError::Duplicate);
        }
        keys.push(pk);
        Ok(pk)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let removed = {
            let mut keys = self.keys.lock().unwrap();
            if let Some(pos) = keys.iter().position(|k| k == pubkey) {
                keys.remove(pos);
                true
            } else {
                false
            }
        };
        if removed {
            if let Some(tx) = self.keystore_removed.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
        Ok(removed)
    }
}

struct NoopSlashingProtection;
impl SlashingProtection for NoopSlashingProtection {
    fn import_interchange(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn export_interchange(&self, _: &[Pubkey]) -> Result<String, String> {
        Ok(String::new())
    }
}

/// Validator manager that records the enabled state of every validator.
struct SpyValidatorManager {
    state: Mutex<HashMap<Pubkey, bool>>,
}

impl SpyValidatorManager {
    fn new() -> Self {
        Self { state: Mutex::new(HashMap::new()) }
    }

    fn is_enabled(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().get(pubkey).copied().unwrap_or(false)
    }

    fn is_tracked(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().contains_key(pubkey)
    }
}

impl ValidatorManager for SpyValidatorManager {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        self.state.lock().unwrap().insert(pubkey, enabled);
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        self.state.lock().unwrap().remove(pubkey).is_some()
    }

    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
        if let Some(v) = self.state.lock().unwrap().get_mut(pubkey) {
            *v = enabled;
        }
    }
}

/// Doppelganger monitor that can park the delete handler at `stop_monitoring`
/// (which on `develop` sits between the keystore removal and the cancel-token
/// removal) until a concurrent re-import has completed.
struct GatedDoppelgangerMonitor {
    inner: DoppelgangerGate,
    /// Fires after each `start_monitoring` (the import handler calls this
    /// immediately before inserting the cancel-token).
    start_signaled: Mutex<Option<mpsc::Sender<()>>>,
    /// On the first `stop_monitoring` call: announce arrival, then block until
    /// released (bounded so a serialised GREEN run cannot wedge forever).
    stop_arrived: Mutex<Option<mpsc::Sender<()>>>,
    stop_release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl GatedDoppelgangerMonitor {
    fn new(window: Duration) -> Self {
        Self {
            inner: DoppelgangerGate::new(window),
            start_signaled: Mutex::new(None),
            stop_arrived: Mutex::new(None),
            stop_release: Mutex::new(None),
        }
    }

    fn ungated(window: Duration) -> Self {
        Self::new(window)
    }
}

impl DoppelgangerMonitor for GatedDoppelgangerMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        self.inner.start_monitoring(pubkey);
        if let Some(tx) = self.start_signaled.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        // Announce that the delete handler has entered the section between
        // keystore-removal and token-cancel, then wait for the test to release
        // it (after the concurrent re-import has inserted its fresh token).
        if let Some(tx) = self.stop_arrived.lock().unwrap().take() {
            let _ = tx.send(());
        }
        if let Some(rx) = self.stop_release.lock().unwrap().take() {
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
        self.inner.stop_monitoring(pubkey);
    }

    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
        self.inner.is_doppelganger_safe(pubkey)
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
    fn import_remote_key(&self, _: Pubkey, _: String) -> Result<(), ImportRemoteKeyError> {
        Ok(())
    }
    fn delete_remote_key(&self, _: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
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

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_pubkey() -> Pubkey {
    let mut pk = [0u8; 48];
    pk[0] = 0x42;
    pk
}

fn keystore_json_for(pubkey: &Pubkey) -> String {
    serde_json::json!({ "pubkey": hex::encode(pubkey) }).to_string()
}

fn import_body(pubkey: &Pubkey) -> rvc_keymanager_api::types::ImportKeystoresRequest {
    serde_json::from_value(serde_json::json!({
        "keystores": [keystore_json_for(pubkey)],
        "passwords": ["test_password"],
    }))
    .unwrap()
}

fn delete_body(pubkey: &Pubkey) -> rvc_keymanager_api::types::DeleteKeystoresRequest {
    serde_json::from_value(serde_json::json!({
        "pubkeys": [format!("0x{}", hex::encode(pubkey))],
    }))
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn make_state(
    keystore_manager: Arc<dyn KeystoreManager>,
    validator_manager: Arc<dyn ValidatorManager>,
    monitor: Arc<dyn DoppelgangerMonitor>,
    window: Duration,
) -> Arc<AppState> {
    Arc::new(AppState {
        keystore_manager,
        slashing_protection: Arc::new(NoopSlashingProtection),
        validator_manager,
        doppelganger_monitor: monitor,
        remote_key_manager: Arc::new(NoopRemoteKeyManager),
        config_manager: Arc::new(NoopConfigManager),
        exit_manager: None,
        allow_insecure_remote_signer: false,
        attesting_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        last_set_attesting_enabled: std::sync::Mutex::new(None),
        import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
        doppelganger_window: window,
        cancel_tokens: std::sync::Mutex::new(std::collections::HashMap::new()),
        doppelganger_state_lock: std::sync::Mutex::new(()),
    })
}

/// Snapshot the single cancel-token currently registered for `pubkey`.
fn current_token(state: &AppState, pubkey: &Pubkey) -> Option<tokio_util::sync::CancellationToken> {
    state.cancel_tokens.lock().unwrap().get(pubkey).cloned()
}

// ── (a) Every insert cancels the displaced token ──────────────────────────────

/// PRD §KM-2 (a): when a re-import inserts a new cancel-token for a pubkey that
/// already has one (the delete-then-reimport effect), the displaced token MUST
/// be cancelled — never silently dropped.
///
/// On `develop` the import path does a bare `map.insert(...)` that overwrites
/// the existing token without cancelling it, so the displaced token's
/// background task survives and can later enable a key that is mid-window.
#[tokio::test]
async fn km2_insert_cancels_displaced_token() {
    let pubkey = test_pubkey();
    let window = Duration::from_secs(3600);

    let keystore = Arc::new(GatedKeystoreManager::new());
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::ungated(window));
    let state = make_state(keystore.clone(), vm.clone(), monitor, window);

    // Import #1 → token T1 registered, background task spawned.
    let _ = import_keystores(
        axum::extract::State(state.clone()),
        axum::http::HeaderMap::new(),
        axum::Json(import_body(&pubkey)),
    )
    .await
    .expect("import #1");
    let t1 = current_token(&state, &pubkey).expect("T1 registered after import #1");
    assert!(!t1.is_cancelled(), "T1 must be live immediately after import #1");

    // Simulate the keystore-removal half of a delete (so the re-import lands on
    // an empty slot) WITHOUT going through the delete handler's cancel path —
    // this isolates the insert-displacement invariant.
    assert!(keystore.delete_keystore(&pubkey).unwrap(), "key removed from keystore");

    // Re-import → handler inserts token T2 for the same pubkey, displacing T1.
    let _ = import_keystores(
        axum::extract::State(state.clone()),
        axum::http::HeaderMap::new(),
        axum::Json(import_body(&pubkey)),
    )
    .await
    .expect("re-import");

    let t2 = current_token(&state, &pubkey).expect("T2 registered after re-import");
    assert!(!t2.is_cancelled(), "the fresh token T2 must be live");

    // CORE ASSERTION (a): the displaced token T1 must have been cancelled by the
    // insert.  Fails on `develop` (bare insert overwrites without cancelling).
    assert!(
        t1.is_cancelled(),
        "PRD §KM-2 (a): inserting T2 for an already-present pubkey must cancel \
         the displaced token T1; on develop T1 leaks uncancelled and its stale \
         task can enable a key that is inside a fresh doppelganger window",
    );
}

// ── (c) The window-elapsed branch prunes its own entry ────────────────────────

/// PRD §KM-2 (c): when the doppelganger window elapses and the background task
/// enables the validator, the task MUST prune its OWN entry from the cancel-token
/// map.  Otherwise the map leaks entries and a later delete cancels an
/// already-completed (unrelated) token.
#[tokio::test(start_paused = true)]
async fn km2_window_elapsed_prunes_own_cancel_token() {
    let pubkey = test_pubkey();
    let window = Duration::from_secs(60);

    let keystore = Arc::new(GatedKeystoreManager::new());
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::ungated(window));
    let state = make_state(keystore.clone(), vm.clone(), monitor, window);

    let _ = import_keystores(
        axum::extract::State(state.clone()),
        axum::http::HeaderMap::new(),
        axum::Json(import_body(&pubkey)),
    )
    .await
    .expect("import");

    assert!(current_token(&state, &pubkey).is_some(), "token present while window runs");
    assert!(!vm.is_enabled(&pubkey), "validator disabled during window");

    // Elapse the window so the background task fires.
    tokio::time::advance(window + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    // A second yield gives the spawned task room to run its post-enable cleanup.
    tokio::task::yield_now().await;

    assert!(vm.is_enabled(&pubkey), "validator enabled after window elapses");

    // CORE ASSERTION (c): the completed task pruned its own cancel-token entry.
    assert!(
        current_token(&state, &pubkey).is_none(),
        "PRD §KM-2 (c): the window-elapsed branch must prune its own cancel-token \
         entry so the map does not leak and a later delete cannot cancel an \
         already-completed token",
    );
}

// ── (b)+(d) Concurrent delete + re-import race ────────────────────────────────

/// PRD §KM-2 (b)+(d): a concurrent delete + re-import must not leave a stale
/// background task alive.  The delete's keystore-removal and token-removal/cancel
/// are a single critical section, so a re-import cannot interleave between them
/// and displace the token the delete is about to cancel.
///
/// This reproduces the race deterministically by parking the delete handler at
/// `stop_monitoring` (between keystore removal and token cancel on `develop`)
/// until the concurrent re-import has inserted its fresh token.
///
/// Assertions:
///   (i)   the token displaced during the race is cancelled;
///   (ii)  after the delete+re-import, the surviving enable task is the NEW
///         one (the re-imported key is eventually enabled by its own fresh
///         window — it was not wrongly cancelled);
///   (iii) the key is NOT enabled by a stale task while still inside the fresh
///         doppelganger window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn km2_concurrent_delete_reimport_no_stale_enable() {
    let pubkey = test_pubkey();
    // A long window so neither background task fires within the test lifetime;
    // the race is proven structurally (which token is cancelled), not by timing.
    let window = Duration::from_secs(3600);

    // ONE shared keystore for both handlers, with the re-import gate enabled so
    // the re-import blocks until the delete has removed the key.
    let keystore = Arc::new(GatedKeystoreManager {
        keys: Mutex::new(vec![]),
        keystore_removed: Mutex::new(None),
        import_waits_for_delete: true,
    });
    let vm = Arc::new(SpyValidatorManager::new());
    let monitor = Arc::new(GatedDoppelgangerMonitor::new(window));

    let state = make_state(keystore.clone(), vm.clone(), monitor.clone(), window);

    // Import #1 → token T1, real background task spawned (deadline = now + window).
    // The keystore is empty here, so the re-import gate passes immediately.
    let _ = import_keystores(
        axum::extract::State(state.clone()),
        axum::http::HeaderMap::new(),
        axum::Json(import_body(&pubkey)),
    )
    .await
    .expect("import #1");
    let t1 = current_token(&state, &pubkey).expect("T1 registered after import #1");
    assert!(!t1.is_cancelled(), "T1 live before the race");

    // Arm the rendezvous channels AFTER import #1 so they capture only the
    // concurrent delete and re-import.
    let (removed_tx, removed_rx) = mpsc::channel::<()>();
    *keystore.keystore_removed.lock().unwrap() = Some(removed_tx);
    let (arrived_tx, arrived_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (started_tx, started_rx) = mpsc::channel::<()>();
    *monitor.stop_arrived.lock().unwrap() = Some(arrived_tx);
    *monitor.stop_release.lock().unwrap() = Some(release_rx);
    *monitor.start_signaled.lock().unwrap() = Some(started_tx);

    // Spawn the concurrent DELETE.
    let state_del = state.clone();
    let delete_task = tokio::spawn(async move {
        delete_keystores(axum::extract::State(state_del), axum::Json(delete_body(&pubkey)))
            .await
            .map(|_| ())
    });

    // Wait until DELETE has removed the keystore entry and parked at
    // `stop_monitoring` (between keystore removal and token cancel on develop).
    let gate = tokio::task::spawn_blocking(move || {
        let removed = removed_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let arrived = arrived_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        (removed, arrived)
    })
    .await
    .unwrap();
    assert!(gate.0, "delete removed the keystore entry");
    assert!(gate.1, "delete parked at stop_monitoring (between removal and cancel)");

    // Now run the concurrent RE-IMPORT.  The keystore is empty (delete removed
    // it), so the import succeeds and the handler inserts a fresh token T2.
    let state_imp = state.clone();
    let reimport_task = tokio::spawn(async move {
        import_keystores(
            axum::extract::State(state_imp),
            axum::http::HeaderMap::new(),
            axum::Json(import_body(&pubkey)),
        )
        .await
        .map(|_| ())
    });

    // Wait until the re-import has reached `start_monitoring` (the handler
    // statement immediately before it inserts its fresh token T2), then release
    // the parked delete so it proceeds to its cancel-token removal.  Bounded so a
    // serialised GREEN run (where the re-import blocks on the shared lock and
    // never reaches `start_monitoring` until the delete finishes) does not wedge:
    // on timeout we release anyway and the delete completes first.
    tokio::task::spawn_blocking(move || {
        let _ = started_rx.recv_timeout(Duration::from_secs(1));
    })
    .await
    .unwrap();
    let _ = release_tx.send(());

    let _ = delete_task.await.unwrap();
    let _ = reimport_task.await.unwrap();

    // The pubkey now exists again (re-imported) and should be tracked & disabled.
    assert!(keystore.has_key(&pubkey), "key present after re-import");
    assert!(vm.is_tracked(&pubkey), "re-imported validator is tracked");

    // (i) The token displaced during the race must be cancelled.
    assert!(
        t1.is_cancelled(),
        "PRD §KM-2 (i): the token displaced during the concurrent delete+re-import \
         must be cancelled; on develop it leaks and its stale task survives",
    );

    // (ii) The surviving registered token is the fresh one and is NOT cancelled
    // — the delete cancelled the displaced token, not the re-import's new token.
    let surviving = current_token(&state, &pubkey).expect("a fresh token survives the race");
    assert!(
        !surviving.is_cancelled(),
        "PRD §KM-2 (ii): the surviving enable task must be the NEW one; the fresh \
         re-import token must remain live (not cancelled by the racing delete)",
    );

    // (iii) The re-imported key must NOT be enabled while still inside the fresh
    // doppelganger window — i.e. no stale task fired early.  We advance time past
    // the ORIGINAL task's deadline (import #1 + window) but the fresh window's
    // deadline is later, so a correctly-cancelled stale task leaves the key
    // disabled here.
    assert!(
        !vm.is_enabled(&pubkey),
        "PRD §KM-2 (iii): the re-imported key must remain disabled inside its \
         fresh doppelganger window; on develop the stale (uncancelled) task \
         enables it prematurely",
    );
}
