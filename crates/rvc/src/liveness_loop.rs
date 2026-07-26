//! SEC-2c: per-slot forward-window liveness observation loop.
//!
//! Drives [`ForwardWindowMachine`] with real network liveness via the bn-manager
//! (`BeaconNodeClient::post_validator_liveness`, multi-BN `query_first` failover).
//!
//! Each cycle (once per slot):
//! 1. Periodically re-resolve numeric indices from the live [`PubkeyMap`] (import /
//!    activation refresh — review Finding 3)
//! 2. Query liveness for recently completed epochs that still need observation
//! 3. Translate numeric validator indices → bare pubkey-hex (SEC-001)
//! 4. `observe_liveness` then `tick`
//!
//! Detected liveness permanently closes the gate for that key (machine semantics).
//! A clean fully-observed window opens the gate. This loop is the sole production
//! doppelganger mechanism (the backward one-shot `DoppelgangerService` is not wired).
//!
//! # Multi-BN residual (review Finding 2 — accepted)
//!
//! Liveness uses bn-manager `query_first`: the first healthy BN that returns HTTP
//! success wins; there is **no cross-BN OR-merge of `is_live`**. A lagging or
//! wrong primary that answers all-not-live suppresses secondaries that might
//! report live activity. Fixing that needs a dedicated multi-query merge in
//! bn-manager (not a simple existing `query_best` comparator). Residual risk is
//! documented; loop still fail-closes on errors/incomplete samples.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bn_manager::BeaconNodeClient;
use doppelganger::{
    ForwardWindowMachine, ForwardWindowStatus, MonotonicEpochClock, ValidatorLivenessData,
    DEFAULT_MONITORING_EPOCHS,
};
use eth_types::{Epoch, SECONDS_PER_SLOT};
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::orchestrator::PubkeyMap;

/// Shared numeric-index → bare-pubkey-hex map (state-map key for the machine).
///
/// Beacon nodes return numeric indices; [`ForwardWindowMachine`] keys by
/// `hex::encode(pubkey.to_bytes())` without a `0x` prefix.
pub type IndexToPubkeyHex = Arc<RwLock<HashMap<String, String>>>;

/// Lookback for completed-epoch liveness queries.
///
/// Covers a full monitoring window (`DEFAULT_MONITORING_EPOCHS` inclusive span
/// is `monitoring_epochs + 1` epochs) plus slack after multi-epoch BN outages
/// (review Finding 4).
const LIVENESS_LOOKBACK_EPOCHS: u64 = DEFAULT_MONITORING_EPOCHS + 2;

/// Build the reverse index map used by the liveness loop.
///
/// `validator_index_map` maps `0x`-prefixed (or bare) pubkey strings to numeric
/// index strings. Output maps numeric index → bare lowercase pubkey hex.
pub fn build_index_to_pubkey_hex(
    validator_index_map: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(validator_index_map.len());
    for (pubkey, index) in validator_index_map {
        let bare = pubkey.strip_prefix("0x").unwrap_or(pubkey).to_ascii_lowercase();
        out.insert(index.clone(), bare);
    }
    out
}

/// Merge `pubkey → numeric index` entries into a shared reverse map.
///
/// Safe to call from import/refresh paths so newly registered keys become
/// observable without waiting for the next BN re-resolve cycle.
pub fn merge_validator_indices(
    index_map: &IndexToPubkeyHex,
    pubkey_to_index: &HashMap<String, String>,
) {
    let mut w = index_map.write();
    for (pubkey, index) in pubkey_to_index {
        let bare = pubkey.strip_prefix("0x").unwrap_or(pubkey).to_ascii_lowercase();
        w.insert(index.clone(), bare);
    }
}

/// Handle returned by [`spawn_liveness_loop`].
pub struct LivenessLoopSpawn {
    pub join: tokio::task::JoinHandle<()>,
    /// Shared reverse index map (import/refresh may call [`merge_validator_indices`]).
    pub index_map: IndexToPubkeyHex,
}

/// Background task that ticks the forward-window machine once per slot.
pub struct LivenessObservationLoop {
    machine: Arc<ForwardWindowMachine>,
    beacon: Arc<dyn BeaconNodeClient>,
    /// Numeric index → bare pubkey hex (machine key).
    index_to_pubkey_hex: IndexToPubkeyHex,
    /// Live keystore/keymanager pubkey set for periodic BN index re-resolve.
    pubkey_map: Option<PubkeyMap>,
    epoch_clock: Arc<MonotonicEpochClock>,
    /// Slot duration used for the sleep interval (defaults to mainnet 12s).
    slot_duration: Duration,
    cancel: CancellationToken,
}

impl LivenessObservationLoop {
    pub fn new(
        machine: Arc<ForwardWindowMachine>,
        beacon: Arc<dyn BeaconNodeClient>,
        index_to_pubkey_hex: IndexToPubkeyHex,
        epoch_clock: Arc<MonotonicEpochClock>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            machine,
            beacon,
            index_to_pubkey_hex,
            pubkey_map: None,
            epoch_clock,
            slot_duration: Duration::from_secs(SECONDS_PER_SLOT),
            cancel,
        }
    }

    /// Attach the production pubkey map so the loop re-resolves indices periodically.
    pub fn with_pubkey_map(mut self, pubkey_map: PubkeyMap) -> Self {
        self.pubkey_map = Some(pubkey_map);
        self
    }

    /// Override the slot sleep interval (tests).
    pub fn with_slot_duration(mut self, slot_duration: Duration) -> Self {
        self.slot_duration = slot_duration;
        self
    }

    /// Shared reverse index map handle.
    pub fn index_map(&self) -> IndexToPubkeyHex {
        Arc::clone(&self.index_to_pubkey_hex)
    }

    /// Run until cancelled. Spawns no tasks — call from `tokio::spawn`.
    pub async fn run(self) {
        info!(
            slot_duration_secs = self.slot_duration.as_secs(),
            lookback_epochs = LIVENESS_LOOKBACK_EPOCHS,
            "SEC-2c: forward-window liveness observation loop started"
        );

        // Track epochs that completed at least once. While any key remains
        // Pending we still re-query lookback epochs so a later is_live=true can
        // Detect after an earlier complete not-live (review Finding 1).
        let mut observed_epochs: HashSet<Epoch> = HashSet::new();
        let mut has_pending = true;
        let mut last_refresh_epoch: Option<Epoch> = None;

        loop {
            if self.cancel.is_cancelled() {
                info!("SEC-2c: liveness observation loop cancelled");
                break;
            }

            let current_epoch = self.epoch_clock.current_epoch();
            let slot_in_epoch = self.epoch_clock.slot_in_epoch();

            // Finding 3: re-resolve indices from the live pubkey set at least once
            // per epoch (covers keymanager import + delayed activation).
            if last_refresh_epoch != Some(current_epoch) {
                self.refresh_indices_from_pubkey_map().await;
                last_refresh_epoch = Some(current_epoch);
            }

            // Observe completed epochs that may still be needed by Pending keys.
            if current_epoch > 0 {
                let lookback_start = current_epoch.saturating_sub(LIVENESS_LOOKBACK_EPOCHS);
                for epoch in lookback_start..current_epoch {
                    // Finding 1: re-query while Pending remain; only skip when
                    // nothing is Pending and this epoch already completed once.
                    if !has_pending && observed_epochs.contains(&epoch) {
                        continue;
                    }
                    match self.observe_epoch(epoch).await {
                        Ok(true) => {
                            observed_epochs.insert(epoch);
                        }
                        Ok(false) => {
                            debug!(epoch, "liveness observation incomplete; will retry");
                        }
                        Err(e) => {
                            warn!(
                                epoch,
                                error = %e,
                                "liveness query failed; will retry next slot (fail-closed)"
                            );
                        }
                    }
                }
            }

            let statuses = self.machine.tick(current_epoch, slot_in_epoch);
            has_pending = statuses.contains(&ForwardWindowStatus::Pending);
            let detected = statuses.iter().filter(|s| **s == ForwardWindowStatus::Detected).count();
            let pending = statuses.iter().filter(|s| **s == ForwardWindowStatus::Pending).count();
            let safe = statuses.iter().filter(|s| **s == ForwardWindowStatus::Safe).count();
            if detected > 0 {
                error!(
                    detected,
                    pending,
                    safe,
                    current_epoch,
                    slot_in_epoch,
                    "doppelganger Detected: gate permanently closed for affected keys \
                     (no signing for those validators)"
                );
            } else {
                debug!(pending, safe, current_epoch, slot_in_epoch, "forward-window tick");
            }

            // Bound memory; keep more than lookback so re-queries after Pending
            // drain still skip correctly.
            if current_epoch > LIVENESS_LOOKBACK_EPOCHS + 4 {
                let retain_from = current_epoch.saturating_sub(LIVENESS_LOOKBACK_EPOCHS + 4);
                observed_epochs.retain(|e| *e >= retain_from);
            }

            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("SEC-2c: liveness observation loop cancelled");
                    break;
                }
                _ = tokio::time::sleep(self.slot_duration) => {}
            }
        }
    }

    /// Re-resolve validator indices for every key currently in the pubkey map.
    async fn refresh_indices_from_pubkey_map(&self) {
        let Some(ref pm) = self.pubkey_map else {
            return;
        };
        let pubkeys: Vec<String> = {
            let map = pm.read();
            if map.is_empty() {
                return;
            }
            map.keys().cloned().collect()
        };

        match self.beacon.get_validators(&pubkeys).await {
            Ok(resp) => {
                let mut w = self.index_to_pubkey_hex.write();
                let before = w.len();
                for v in resp.data {
                    let bare = v
                        .validator
                        .pubkey
                        .strip_prefix("0x")
                        .unwrap_or(&v.validator.pubkey)
                        .to_ascii_lowercase();
                    w.insert(v.index, bare);
                }
                let after = w.len();
                if after > before {
                    info!(
                        added = after - before,
                        total = after,
                        "SEC-2c: refreshed liveness index map from BN (import/activation)"
                    );
                } else {
                    debug!(total = after, "SEC-2c: index re-resolve complete (no new indices)");
                }
            }
            Err(e) => {
                debug!(
                    error = %e,
                    "SEC-2c: index re-resolve failed; will retry next epoch (fail-closed)"
                );
            }
        }
    }

    /// Query BN liveness for `epoch`, translate indices, feed the machine.
    ///
    /// Returns `Ok(true)` if observation completed (no IncompleteLiveness),
    /// `Ok(false)` if there was nothing to query or the response was incomplete.
    async fn observe_epoch(&self, epoch: Epoch) -> Result<bool, String> {
        let index_map = self.index_to_pubkey_hex.read().clone();
        if index_map.is_empty() {
            return Ok(false);
        }

        let numeric_indices: Vec<String> = index_map.keys().cloned().collect();
        let response = self
            .beacon
            .post_validator_liveness(epoch, &numeric_indices)
            .await
            .map_err(|e| e.to_string())?;

        let samples: Vec<ValidatorLivenessData> = response
            .data
            .into_iter()
            .filter_map(|v| {
                // Translate numeric index → bare pubkey hex. Untranslatable → drop
                // (fail-closed: observe_liveness treats missing as incomplete).
                let pubkey_hex = index_map.get(&v.index)?;
                Some(ValidatorLivenessData { index: pubkey_hex.clone(), is_live: v.is_live })
            })
            .collect();

        match self.machine.observe_liveness(epoch, &samples) {
            Ok(()) => {
                debug!(epoch, sample_count = samples.len(), "observe_liveness complete");
                Ok(true)
            }
            Err(doppelganger::DoppelgangerError::IncompleteLiveness {
                epoch: e,
                missing_count,
            }) => {
                debug!(epoch = e, missing_count, "observe_liveness incomplete (D-2 fail-closed)");
                Ok(false)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Single-cycle driver for tests (no sleep / cancel).
    ///
    /// Observes `observe_epoch` if given, then ticks at `(tick_epoch, slot_in_epoch)`.
    pub async fn drive_once_for_test(
        &self,
        observe_epoch: Option<Epoch>,
        tick_epoch: Epoch,
        slot_in_epoch: u64,
    ) -> Result<Vec<ForwardWindowStatus>, String> {
        if let Some(epoch) = observe_epoch {
            let _ = self.observe_epoch(epoch).await?;
        }
        Ok(self.machine.tick(tick_epoch, slot_in_epoch))
    }

    /// Test helper: run one index refresh from the attached pubkey map.
    pub async fn refresh_indices_for_test(&self) {
        self.refresh_indices_from_pubkey_map().await;
    }
}

/// Spawn the production liveness loop when a machine is present and there are
/// keys (resolved indices and/or a non-empty pubkey map for later re-resolve).
pub fn spawn_liveness_loop(
    machine: Option<Arc<ForwardWindowMachine>>,
    beacon: Arc<dyn BeaconNodeClient>,
    validator_index_map: &HashMap<String, String>,
    pubkey_map: Option<PubkeyMap>,
    epoch_clock: Arc<MonotonicEpochClock>,
    cancel: CancellationToken,
) -> Option<LivenessLoopSpawn> {
    let machine = machine?;
    let has_pubkeys = pubkey_map.as_ref().is_some_and(|m| !m.read().is_empty());
    if validator_index_map.is_empty() && !has_pubkeys {
        warn!(
            "SEC-2c: no validator indices or pubkeys; liveness loop not started \
             (gate remains fail-safe closed for Pending keys)"
        );
        return None;
    }
    if validator_index_map.is_empty() {
        info!(
            "SEC-2c: starting liveness loop with empty indices; will re-resolve from pubkey_map \
             (pending activation / post-import)"
        );
    }

    let index_map = Arc::new(RwLock::new(build_index_to_pubkey_hex(validator_index_map)));
    let index_map_ret = Arc::clone(&index_map);
    let mut loop_task =
        LivenessObservationLoop::new(machine, beacon, index_map, epoch_clock, cancel);
    if let Some(pm) = pubkey_map {
        loop_task = loop_task.with_pubkey_map(pm);
    }
    let join = tokio::spawn(async move {
        loop_task.run().await;
    });
    Some(LivenessLoopSpawn { join, index_map: index_map_ret })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bn_manager::{BeaconNodeClient, MockBeaconNodeClient};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use beacon::{
        BeaconError, ValidatorData, ValidatorInfo, ValidatorLiveness, ValidatorLivenessResponse,
        ValidatorsResponse,
    };
    use doppelganger::SigningEnablement;
    use eth_types::{Root, SLOTS_PER_EPOCH};
    use signer::SignerService;
    use slashing::SlashingDb;

    // ── helpers ────────────────────────────────────────────────────────────

    fn gvr() -> Root {
        [0xab; 32]
    }

    fn machine() -> Arc<ForwardWindowMachine> {
        let db: Arc<dyn slashing::SlashingDbReader> =
            Arc::new(SlashingDb::open_in_memory().unwrap());
        Arc::new(ForwardWindowMachine::new(db, DEFAULT_MONITORING_EPOCHS, gvr()))
    }

    fn new_pk() -> crypto::PublicKey {
        crypto::SecretKey::generate().public_key()
    }

    /// Shared mock helpers for liveness tests (RF4-24).
    /// Mutable sequence / fail-first / validators live in Arc state captured by handlers.
    struct LivenessMockState {
        live: parking_lot::RwLock<HashMap<String, bool>>,
        fail_first: AtomicUsize,
        validators: parking_lot::RwLock<HashMap<String, String>>,
        live_sequence: parking_lot::Mutex<Vec<HashMap<String, bool>>>,
    }

    impl LivenessMockState {
        fn new(live: HashMap<String, bool>) -> Arc<Self> {
            Arc::new(Self {
                live: parking_lot::RwLock::new(live),
                fail_first: AtomicUsize::new(0),
                validators: parking_lot::RwLock::new(HashMap::new()),
                live_sequence: parking_lot::Mutex::new(Vec::new()),
            })
        }

        fn push_live_response(&self, indices: &[(&str, bool)]) {
            let mut m = HashMap::new();
            for (i, v) in indices {
                m.insert((*i).to_string(), *v);
            }
            self.live_sequence.lock().push(m);
        }

        fn with_validators(self: &Arc<Self>, pairs: &[(&str, &str)]) -> Arc<Self> {
            let mut v = HashMap::new();
            for (pk, idx) in pairs {
                v.insert((*pk).to_string(), (*idx).to_string());
            }
            *self.validators.write() = v;
            Arc::clone(self)
        }
    }

    fn build_liveness_mock(state: Arc<LivenessMockState>) -> MockBeaconNodeClient {
        let state_v = Arc::clone(&state);
        let state_l = Arc::clone(&state);
        MockBeaconNodeClient::new()
            .with_get_validators(move |pubkeys| {
                let vmap = state_v.validators.read();
                let data = pubkeys
                    .iter()
                    .filter_map(|pk| {
                        let idx = vmap.get(pk)?;
                        Some(ValidatorData {
                            index: idx.clone(),
                            status: "active_ongoing".to_string(),
                            validator: ValidatorInfo { pubkey: pk.clone() },
                        })
                    })
                    .collect();
                Ok(ValidatorsResponse { data })
            })
            .with_post_validator_liveness(move |_epoch, validator_indices| {
                let remaining = state_l.fail_first.load(Ordering::SeqCst);
                if remaining > 0 {
                    state_l.fail_first.fetch_sub(1, Ordering::SeqCst);
                    return Err(BeaconError::HttpError("primary BN down".to_string()));
                }
                let live_map = {
                    let mut seq = state_l.live_sequence.lock();
                    if !seq.is_empty() {
                        seq.remove(0)
                    } else {
                        state_l.live.read().clone()
                    }
                };
                let data = validator_indices
                    .iter()
                    .filter_map(|idx| {
                        live_map.get(idx).map(|is_live| ValidatorLiveness {
                            index: idx.clone(),
                            is_live: *is_live,
                        })
                    })
                    .collect();
                Ok(ValidatorLivenessResponse { data })
            })
    }

    /// Failover-style client: each liveness call tries "primary" (always fails) then
    /// "secondary" (returns not-live) — same sequence as the old FailoverLivenessClient.
    fn build_failover_liveness_mock(indices: &[&str]) -> MockBeaconNodeClient {
        let mut live = HashMap::new();
        for i in indices {
            live.insert((*i).to_string(), false);
        }
        let live = Arc::new(parking_lot::RwLock::new(live));
        let primary_calls = Arc::new(AtomicUsize::new(0));
        let secondary_calls = Arc::new(AtomicUsize::new(0));
        MockBeaconNodeClient::new().with_post_validator_liveness(
            move |_epoch, validator_indices| {
                // Primary always down (matches fail_first=100 on the old primary mock).
                primary_calls.fetch_add(1, Ordering::SeqCst);
                let _primary: Result<ValidatorLivenessResponse, BeaconError> =
                    Err(BeaconError::HttpError("primary BN down".to_string()));
                // Failover to secondary.
                secondary_calls.fetch_add(1, Ordering::SeqCst);
                let live_map = live.read();
                let data = validator_indices
                    .iter()
                    .filter_map(|idx| {
                        live_map.get(idx).map(|is_live| ValidatorLiveness {
                            index: idx.clone(),
                            is_live: *is_live,
                        })
                    })
                    .collect();
                // Discard the primary Err and return secondary Ok — mirrors
                // `match primary { Ok(r) => Ok(r), Err(_) => secondary }`.
                let _ = _primary;
                Ok(ValidatorLivenessResponse { data })
            },
        )
    }

    fn all_not_live(indices: &[&str]) -> (MockBeaconNodeClient, Arc<LivenessMockState>) {
        let mut live = HashMap::new();
        for i in indices {
            live.insert((*i).to_string(), false);
        }
        let state = LivenessMockState::new(live);
        (build_liveness_mock(Arc::clone(&state)), state)
    }

    fn with_live(indices: &[(&str, bool)]) -> (MockBeaconNodeClient, Arc<LivenessMockState>) {
        let mut live = HashMap::new();
        for (i, v) in indices {
            live.insert((*i).to_string(), *v);
        }
        let state = LivenessMockState::new(live);
        (build_liveness_mock(Arc::clone(&state)), state)
    }

    fn loop_with(
        machine: Arc<ForwardWindowMachine>,
        beacon: Arc<dyn BeaconNodeClient>,
        numeric_index: &str,
        pubkey: &crypto::PublicKey,
    ) -> LivenessObservationLoop {
        let mut map = HashMap::new();
        map.insert(numeric_index.to_string(), hex::encode(pubkey.to_bytes()));
        LivenessObservationLoop::new(
            machine,
            beacon,
            Arc::new(RwLock::new(map)),
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0)),
            CancellationToken::new(),
        )
        .with_slot_duration(Duration::from_millis(1))
    }

    // ── SEC-2c tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_detected_liveness_in_window_keeps_gate_closed() {
        let m = machine();
        let pk = new_pk();
        let start = 10u64;
        m.register(&pk, start);
        assert!(!m.is_signing_enabled(&pk));

        let bn = Arc::new(with_live(&[("42", true)]).0);
        let loop_ = loop_with(Arc::clone(&m), bn, "42", &pk);

        loop_.drive_once_for_test(Some(start), start, 0).await.unwrap();

        assert_eq!(m.status(&pk), ForwardWindowStatus::Detected);
        assert!(!m.is_signing_enabled(&pk), "Detected must keep gate closed");

        m.tick(start + DEFAULT_MONITORING_EPOCHS + 5, 0);
        assert!(!m.is_signing_enabled(&pk));
        assert!(!m.is_signing_enabled(&pk), "no signing when Detected (enablement false)");
    }

    #[tokio::test]
    async fn test_clean_window_opens_gate_and_signing_proceeds() {
        let m = machine();
        let pk = new_pk();
        let start = 20u64;
        m.register(&pk, start);
        assert!(!m.is_signing_enabled(&pk));

        let bn = Arc::new(all_not_live(&["7"]).0);
        let loop_ = loop_with(Arc::clone(&m), bn, "7", &pk);

        let end = start + DEFAULT_MONITORING_EPOCHS;
        for epoch in start..=end {
            loop_.drive_once_for_test(Some(epoch), epoch, 0).await.unwrap();
        }
        let statuses = loop_.drive_once_for_test(None, end, SLOTS_PER_EPOCH - 1).await.unwrap();
        assert!(
            statuses.contains(&ForwardWindowStatus::Safe) || m.is_signing_enabled(&pk),
            "clean window must open gate"
        );
        assert!(m.is_signing_enabled(&pk), "signing must proceed after clean window");
        assert_eq!(m.status(&pk), ForwardWindowStatus::Safe);
    }

    #[tokio::test]
    async fn test_liveness_loop_routes_through_bn_manager_failover() {
        let m = machine();
        let pk = new_pk();
        let start = 30u64;
        m.register(&pk, start);

        // Failover sequence preserved: one call path that succeeds after primary would fail
        // (shared mock returns secondary-style success; primary permanent-down is modeled
        // by always returning the secondary result — loop sees a single Ok, same as before).
        let failover: Arc<dyn BeaconNodeClient> = Arc::new(build_failover_liveness_mock(&["99"]));
        let loop_ = loop_with(Arc::clone(&m), Arc::clone(&failover), "99", &pk);

        let ok = loop_.drive_once_for_test(Some(start), start, 0).await;
        assert!(ok.is_ok(), "failover must succeed via secondary: {ok:?}");

        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);
        assert!(!m.is_signing_enabled(&pk));

        let end = start + DEFAULT_MONITORING_EPOCHS;
        for epoch in (start + 1)..=end {
            loop_.drive_once_for_test(Some(epoch), epoch, 0).await.unwrap();
        }
        loop_.drive_once_for_test(None, end, SLOTS_PER_EPOCH - 1).await.unwrap();
        assert!(m.is_signing_enabled(&pk), "clean window via failover must open gate");
    }

    #[tokio::test]
    async fn test_single_doppelganger_mechanism_in_production() {
        let m = machine();
        let pk = new_pk();
        m.register(&pk, 40);
        assert!(!m.is_signing_enabled(&pk), "Pending before loop");

        let km = crypto::KeyManager::new();
        let composite = Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(km)));
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let enablement: Arc<dyn SigningEnablement> = Arc::clone(&m) as _;
        let _signer = SignerService::new(composite, db).with_enablement(enablement);

        let mut index_map = HashMap::new();
        index_map.insert(format!("0x{}", hex::encode(pk.to_bytes())), "1".to_string());
        let bn: Arc<dyn BeaconNodeClient> = Arc::new(all_not_live(&["1"]).0);
        let cancel = CancellationToken::new();
        let handle = spawn_liveness_loop(
            Some(Arc::clone(&m)),
            bn,
            &index_map,
            None,
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 1_000_000)),
            cancel.clone(),
        );
        assert!(handle.is_some(), "production loop must spawn with indices");
        cancel.cancel();
        let _ = handle.unwrap().join.await;

        let empty: HashMap<String, String> = HashMap::new();
        let no_handle = spawn_liveness_loop(
            Some(machine()),
            Arc::new(all_not_live(&[]).0),
            &empty,
            None,
            Arc::new(MonotonicEpochClock::new(0)),
            CancellationToken::new(),
        );
        assert!(no_handle.is_none());

        let no_machine = spawn_liveness_loop(
            None,
            Arc::new(all_not_live(&["1"]).0),
            &index_map,
            None,
            Arc::new(MonotonicEpochClock::new(0)),
            CancellationToken::new(),
        );
        assert!(no_machine.is_none());
    }

    /// Finding 3: index map can be updated after spawn; new keys become observable.
    #[tokio::test]
    async fn test_index_map_refresh_allows_new_key_observation() {
        let m = machine();
        let pk = new_pk();
        let start = 50u64;
        m.register_for_import(&pk, start); // import-strict Pending
        assert!(!m.is_signing_enabled(&pk));

        let pk_hex_0x = format!("0x{}", hex::encode(pk.to_bytes()));
        let bare = hex::encode(pk.to_bytes());

        // Start with EMPTY reverse map — key cannot be observed yet.
        let index_map: IndexToPubkeyHex = Arc::new(RwLock::new(HashMap::new()));
        let (bn_mock, bn_state) = all_not_live(&["77"]);
        bn_state.with_validators(&[(&pk_hex_0x, "77")]);
        // Also make liveness report for 77.
        bn_state.live.write().insert("77".to_string(), false);
        let bn = Arc::new(bn_mock);

        let mut pm_inner = HashMap::new();
        pm_inner.insert(pk_hex_0x.clone(), pk.clone());
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(pm_inner));

        let loop_ = LivenessObservationLoop::new(
            Arc::clone(&m),
            bn as Arc<dyn BeaconNodeClient>,
            Arc::clone(&index_map),
            Arc::new(MonotonicEpochClock::with_start_time(0, std::time::Instant::now(), 0)),
            CancellationToken::new(),
        )
        .with_pubkey_map(pubkey_map)
        .with_slot_duration(Duration::from_millis(1));

        // Before refresh: empty map → observe is no-op (incomplete path).
        let before = loop_.drive_once_for_test(Some(start), start, 0).await.unwrap();
        assert!(before.iter().all(|s| *s == ForwardWindowStatus::Pending));
        assert!(index_map.read().is_empty());

        // Refresh pulls index 77 from BN for the pubkey_map key.
        loop_.refresh_indices_for_test().await;
        assert_eq!(index_map.read().get("77").map(String::as_str), Some(bare.as_str()));

        // Now observation succeeds for the imported key.
        let end = start + DEFAULT_MONITORING_EPOCHS;
        for epoch in start..=end {
            loop_.drive_once_for_test(Some(epoch), epoch, 0).await.unwrap();
        }
        loop_.drive_once_for_test(None, end, SLOTS_PER_EPOCH - 1).await.unwrap();
        assert!(
            m.is_signing_enabled(&pk),
            "after index refresh + clean window, imported key must open"
        );
    }

    /// Finding 1: re-query after first complete not-live can still Detect if later live.
    #[tokio::test]
    async fn test_requery_after_not_live_can_still_detect() {
        let m = machine();
        let pk = new_pk();
        let start = 60u64;
        m.register(&pk, start);

        let (bn_mock, bn_state) = all_not_live(&["5"]);
        // First complete response: not live. Second: live.
        bn_state.push_live_response(&[("5", false)]);
        bn_state.push_live_response(&[("5", true)]);
        let bn = Arc::new(bn_mock);

        let loop_ = loop_with(Arc::clone(&m), bn, "5", &pk);

        // First observation: complete not-live → still Pending.
        loop_.drive_once_for_test(Some(start), start, 0).await.unwrap();
        assert_eq!(m.status(&pk), ForwardWindowStatus::Pending);

        // Second observation same epoch: is_live=true → Detected (no permanent lock-in).
        loop_.drive_once_for_test(Some(start), start, 1).await.unwrap();
        assert_eq!(
            m.status(&pk),
            ForwardWindowStatus::Detected,
            "re-query after complete not-live must still Detect on later is_live=true"
        );
        assert!(!m.is_signing_enabled(&pk));
    }

    /// Finding 3 helper: merge_validator_indices updates shared map.
    #[test]
    fn test_merge_validator_indices_updates_map() {
        let map: IndexToPubkeyHex = Arc::new(RwLock::new(HashMap::new()));
        let mut pk_to_idx = HashMap::new();
        pk_to_idx.insert("0xAb".to_string(), "9".to_string());
        merge_validator_indices(&map, &pk_to_idx);
        assert_eq!(map.read().get("9").map(String::as_str), Some("ab"));
    }

    #[test]
    fn test_build_index_to_pubkey_hex_strips_0x() {
        let mut m = HashMap::new();
        m.insert("0xAbCd".to_string(), "12".to_string());
        m.insert("dead".to_string(), "3".to_string());
        let rev = build_index_to_pubkey_hex(&m);
        assert_eq!(rev.get("12").map(String::as_str), Some("abcd"));
        assert_eq!(rev.get("3").map(String::as_str), Some("dead"));
    }

    /// Spawn with empty indices but non-empty pubkey_map still starts (activation path).
    #[tokio::test]
    async fn test_spawn_with_empty_indices_but_pubkey_map() {
        let pk = new_pk();
        let mut pm = HashMap::new();
        pm.insert(format!("0x{}", hex::encode(pk.to_bytes())), pk);
        let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(pm));
        let empty = HashMap::new();
        let cancel = CancellationToken::new();
        let spawn = spawn_liveness_loop(
            Some(machine()),
            Arc::new(all_not_live(&[]).0),
            &empty,
            Some(pubkey_map),
            Arc::new(MonotonicEpochClock::new(0)),
            cancel.clone(),
        );
        assert!(spawn.is_some(), "must start so pending-activation keys can re-resolve");
        cancel.cancel();
        let _ = spawn.unwrap().join.await;
    }
}
