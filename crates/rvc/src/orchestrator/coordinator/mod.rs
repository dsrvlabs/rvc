//! Main duty orchestrator implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, info, info_span, warn, Instrument};

use block_service::{BeaconBlockClient, BlockService};
use bn_manager::{BeaconNodeClient, OperationTimeouts};
use builder::{BuilderService, CircuitBreakerState};
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{ForkSchedule, Root, Slot};
use metrics::definitions::{
    attestation_status, RVC_ATTESTATIONS_TOTAL, RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL,
    RVC_BUILDER_CONSECUTIVE_MISSES, RVC_BUILDER_EPOCH_MISSES,
};
use propagator::{AttestationSubmitter, Propagator};
use signer::SignerService;
use timing::{due_ms, SlotClock, AGGREGATE_DUE_BPS, ATTESTATION_DUE_BPS, SLOTS_PER_EPOCH};

use super::aggregation::AggregationService;
use super::attestation::AttestationService;
use super::duty_management::DutyManagementService;
use super::error::OrchestratorError;
use super::slot_context::SlotContext;
use super::sync_committee::SyncCommitteeService;
use super::utils;

/// Shared, dynamically-updatable public key map.
///
/// Wrapped in `Arc<RwLock>` so the keymanager API can insert/remove keys at
/// runtime while the orchestrator reads them each slot.
pub type PubkeyMap = Arc<parking_lot::RwLock<HashMap<String, PublicKey>>>;

/// Configuration for the duty orchestrator.
#[derive(Clone)]
pub struct OrchestratorConfig {
    pub genesis_validators_root: Root,
    pub fork_schedule: Arc<ForkSchedule>,
    pub shutdown_timeout: Duration,
    pub timeouts: OperationTimeouts,
}

impl OrchestratorConfig {
    pub fn new(genesis_validators_root: Root, fork_schedule: Arc<ForkSchedule>) -> Self {
        Self {
            genesis_validators_root,
            fork_schedule,
            shutdown_timeout: Duration::from_secs(30),
            timeouts: OperationTimeouts::default(),
        }
    }

    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    pub fn with_timeouts(mut self, timeouts: OperationTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
}

/// Handle for controlling the orchestrator.
pub struct OrchestratorHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl OrchestratorHandle {
    /// Signals the orchestrator to shut down gracefully.
    ///
    /// The orchestrator will complete processing of the current slot (if any)
    /// before stopping. The signal is delivered via a watch channel, ensuring
    /// the orchestrator receives it even if waiting for the next slot.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Result of processing a single attestation duty.
#[derive(Debug)]
pub struct AttestationResult {
    pub validator_index: String,
    pub slot: Slot,
    pub success: bool,
    pub error: Option<String>,
}

/// Timeout for builder registration API calls.
const BUILDER_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Dependencies required to construct a [`DutyOrchestrator`].
///
/// Bundling construction args into a single struct makes omissions (notably
/// `key_gen_rx` and `attesting_enabled`) a compile error rather than a silent
/// runtime defect. There is exactly one constructor: [`DutyOrchestrator::new`].
pub struct OrchestratorDeps<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    pub clock: Arc<C>,
    pub duty_tracker: Arc<DutyTracker>,
    pub signer: Arc<SignerService>,
    pub propagator: Arc<Propagator<S>>,
    pub beacon: Arc<dyn BeaconNodeClient>,
    pub block_beacon: Arc<B>,
    pub builder_service: Option<Arc<BuilderService>>,
    pub validator_store: Arc<validator_store::ValidatorStore>,
    pub config: OrchestratorConfig,
    pub pubkey_map: PubkeyMap,
    /// Receiver half of the key-generation watch channel shared with keymanager
    /// adapters. When the generation increments, the duty cache is cleared so
    /// newly imported keys participate in duty matching without a restart.
    /// Always supplied by the caller — never fabricated inside the constructor.
    pub key_gen_rx: watch::Receiver<u64>,
    pub circuit_breaker: Arc<CircuitBreakerState>,
    /// Global attesting gate. When false, attestation duties are skipped.
    /// Independent of sync-committee processing (`sync_enabled`, H-7).
    pub attesting_enabled: Arc<AtomicBool>,
}

impl<C, S, B> OrchestratorDeps<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    /// Test helper with defaults for fields that most unit tests do not vary.
    ///
    /// Defaults:
    /// - `key_gen_rx`: a discarded channel (not paired with any adapter)
    /// - `circuit_breaker`: `CircuitBreakerState::new(0, 0)`
    /// - `attesting_enabled`: `true`
    ///
    /// Override via struct-update syntax when a test needs a real
    /// `key_gen_rx`, a shared circuit breaker, or a custom attesting flag.
    /// Production code must construct [`OrchestratorDeps`] explicitly with the
    /// real receiver from the channel shared with keymanager adapters.
    #[allow(clippy::too_many_arguments)]
    pub fn for_test(
        clock: Arc<C>,
        duty_tracker: Arc<DutyTracker>,
        signer: Arc<SignerService>,
        propagator: Arc<Propagator<S>>,
        beacon: Arc<dyn BeaconNodeClient>,
        block_beacon: Arc<B>,
        builder_service: Option<Arc<BuilderService>>,
        validator_store: Arc<validator_store::ValidatorStore>,
        config: OrchestratorConfig,
        pubkey_map: PubkeyMap,
    ) -> Self {
        let (_key_gen_tx, key_gen_rx) = watch::channel(0u64);
        Self {
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            block_beacon,
            builder_service,
            validator_store,
            config,
            pubkey_map,
            key_gen_rx,
            circuit_breaker: Arc::new(CircuitBreakerState::new(0, 0)),
            attesting_enabled: Arc::new(AtomicBool::new(true)),
        }
    }
}

/// Main orchestrator for coordinating validator duties.
pub struct DutyOrchestrator<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    clock: Arc<C>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    block_service: BlockService<SignerService, B>,
    builder_service: Option<Arc<BuilderService>>,
    circuit_breaker: Arc<CircuitBreakerState>,
    config: OrchestratorConfig,
    pubkey_map: PubkeyMap,
    attestation_service: AttestationService<C, S>,
    aggregation_service: AggregationService,
    sync_committee_service: SyncCommitteeService,
    duty_management: DutyManagementService<C>,
    key_gen_rx: watch::Receiver<u64>,
    shutdown_rx: watch::Receiver<bool>,
    attesting_enabled: Arc<AtomicBool>,
    /// Controls whether sync-committee duties are processed independently of
    /// `attesting_enabled`. Defaults to `true`; can be toggled at runtime via
    /// [`set_sync_enabled`]. Internal-only — not wired to any Keymanager API (H-7).
    sync_enabled: Arc<AtomicBool>,
    /// D-3: per-validator doppelganger gate for block proposals.
    /// Shared reference to the ValidatorStore for `is_signing_enabled` checks.
    validator_store: Arc<validator_store::ValidatorStore>,
}

impl<C, S, B> DutyOrchestrator<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    /// Creates a new DutyOrchestrator from the given dependencies.
    ///
    /// The sole constructor. Callers must supply a real `key_gen_rx` (production)
    /// or use [`OrchestratorDeps::for_test`] (unit tests that do not exercise
    /// key-import notifications).
    pub fn new(deps: OrchestratorDeps<C, S, B>) -> (Self, OrchestratorHandle) {
        let OrchestratorDeps {
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            block_beacon,
            builder_service,
            validator_store,
            config,
            pubkey_map,
            key_gen_rx,
            circuit_breaker,
            attesting_enabled,
        } = deps;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let block_service = BlockService::with_circuit_breaker(
            signer.clone(),
            block_beacon,
            validator_store.clone(),
            config.fork_schedule.clone(),
            config.genesis_validators_root,
            circuit_breaker.clone(),
        );

        let aggregation_service = AggregationService::new(
            signer.clone(),
            beacon.clone(),
            duty_tracker.clone(),
            pubkey_map.clone(),
            config.clone(),
            validator_store.clone(),
        );

        let sync_committee_service = SyncCommitteeService::new(
            signer.clone(),
            beacon.clone(),
            duty_tracker.clone(),
            pubkey_map.clone(),
            config.clone(),
            validator_store.clone(),
        );

        let attestation_service = AttestationService::new(
            clock.clone(),
            signer.clone(),
            propagator.clone(),
            beacon.clone(),
            duty_tracker.clone(),
            pubkey_map.clone(),
            config.clone(),
            validator_store.clone(),
        );

        let duty_management = DutyManagementService::new(
            clock.clone(),
            signer,
            beacon.clone(),
            duty_tracker.clone(),
            validator_store.clone(),
            pubkey_map.clone(),
            config.clone(),
        );

        let sync_enabled = Arc::new(AtomicBool::new(true));

        let orchestrator = Self {
            clock,
            beacon,
            duty_tracker,
            block_service,
            builder_service,
            circuit_breaker,
            config,
            pubkey_map,
            attestation_service,
            aggregation_service,
            sync_committee_service,
            duty_management,
            key_gen_rx,
            shutdown_rx,
            attesting_enabled,
            sync_enabled,
            validator_store,
        };

        let handle = OrchestratorHandle { shutdown_tx };

        (orchestrator, handle)
    }

    /// Runs the orchestrator main loop with three-phase slot processing:
    /// - t=0: epoch boundary duty fetch + block proposal
    /// - t=slot/3: attestations + sync committee messages
    /// - t=2*slot/3: sync committee contributions
    pub async fn run(&mut self) -> Result<(), OrchestratorError> {
        info!("Starting duty orchestrator");

        loop {
            if *self.shutdown_rx.borrow() {
                info!("Shutdown signal received, stopping orchestrator");
                return Ok(());
            }

            let current_slot = match self.clock.current_slot() {
                Ok(slot) => slot,
                Err(e) => {
                    warn!(error = %e, "Failed to get current slot, waiting...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let current_epoch = current_slot / SLOTS_PER_EPOCH;

            let slot_span = info_span!("slot.process", slot = current_slot, epoch = current_epoch,);

            // Check if keys changed (dynamic key import/delete via keymanager API).
            // has_changed() does NOT mark the value as seen — mark_unchanged() so
            // subsequent slots do not clear forever after a single notify (S1).
            self.apply_key_gen_cache_invalidation().await;

            // === Epoch boundary: fetch all duty types ===
            self.duty_management
                .fetch_epoch_duties(current_epoch)
                .instrument(slot_span.clone())
                .await;
            self.duty_management
                .fetch_epoch_duties(current_epoch + 1)
                .instrument(slot_span.clone())
                .await;

            // Proposer preparation and committee subscriptions (non-fatal)
            if current_slot % SLOTS_PER_EPOCH == 0 {
                self.circuit_breaker.reset_epoch(current_epoch);
                self.update_circuit_breaker_metrics();
                info!(epoch = current_epoch, "Circuit breaker reset at epoch boundary");

                let epoch_span =
                    info_span!(parent: &slot_span, "epoch.boundary", epoch = current_epoch);
                async {
                    self.duty_management.check_reorg_at_epoch_boundary(current_epoch).await;
                    self.duty_management.prepare_proposers().await;
                    self.duty_management.submit_committee_subscriptions(current_epoch).await;
                    self.duty_management.submit_committee_subscriptions(current_epoch + 1).await;

                    // Epoch boundary summary
                    let mut attester_count = 0usize;
                    for slot_offset in 0..SLOTS_PER_EPOCH {
                        let slot = current_epoch * SLOTS_PER_EPOCH + slot_offset;
                        attester_count += self.duty_tracker.get_duties_for_slot(slot).await.len();
                    }
                    let mut proposer_count = 0usize;
                    for slot_offset in 0..SLOTS_PER_EPOCH {
                        let slot = current_epoch * SLOTS_PER_EPOCH + slot_offset;
                        if self.duty_tracker.get_proposer_duty(slot).await.is_some() {
                            proposer_count += 1;
                        }
                    }
                    let sync_count =
                        self.duty_tracker.get_sync_committee_duties(current_slot).await.len();
                    info!(
                        epoch = current_epoch,
                        attester_count, proposer_count, sync_count, "Epoch boundary summary"
                    );
                }
                .instrument(epoch_span)
                .await;
            }

            // === Phase 1: t=0 — Block proposal ===
            // Capture slot context once; downstream phases reuse the same head root
            // to avoid TOCTOU races (H-5). Uses slot-qualified query, not "head" (L-5).
            let ctx = SlotContext::capture(&*self.beacon, current_slot, current_epoch).await;
            {
                let phase_span = info_span!(parent: &slot_span, "slot.phase.block");
                self.maybe_propose_block(ctx.slot, ctx.epoch, &ctx).instrument(phase_span).await;
            }

            if self.check_shutdown() {
                return Ok(());
            }

            // === Phase 2: t=slot/3 — Attestations + sync committee messages ===
            {
                let att_phase_span = info_span!(parent: &slot_span, "slot.phase.attestation");

                let time_until_attestation = self.clock.time_until_attestation(current_slot)?;
                if !time_until_attestation.is_zero() {
                    let _guard = att_phase_span.enter();
                    debug!(
                        slot = current_slot,
                        wait_ms = time_until_attestation.as_millis(),
                        "Waiting for attestation time"
                    );
                    drop(_guard);

                    tokio::select! {
                        _ = tokio::time::sleep(time_until_attestation).instrument(att_phase_span.clone()) => {}
                        _ = self.shutdown_rx.changed() => {
                            if self.check_shutdown() {
                                return Ok(());
                            }
                        }
                    }
                }

                if self.check_shutdown() {
                    return Ok(());
                }

                // Check for missed attestation deadline.
                // Basis-points formula in milliseconds (report §4.3), consistent
                // with `time_until_attestation`: mainnet 1/3 = 3999 ms.
                {
                    let slot_duration_ms = self.clock.slot_duration().as_millis() as u64;
                    let att_window_ms = due_ms(ATTESTATION_DUE_BPS, slot_duration_ms);
                    let slot_start_ms = self.clock.slot_start_time(current_slot) * 1000;
                    let expected_att_ms = slot_start_ms + att_window_ms;
                    let now_ms = self.clock.current_time_secs() * 1000;
                    if now_ms > expected_att_ms {
                        let delay_ms = now_ms - expected_att_ms;
                        // Only warn if the delay exceeds the expected attestation window
                        // (i.e., we're past 2/3 of the slot).
                        if delay_ms > att_window_ms {
                            warn!(slot = current_slot, delay_ms, "Missed attestation deadline");
                        }
                    }
                }

                if self.attesting_enabled.load(Ordering::Relaxed) {
                    if let Err(e) = self
                        .attestation_service
                        .process_slot(current_slot)
                        .instrument(att_phase_span.clone())
                        .await
                    {
                        let _guard = att_phase_span.enter();
                        match &e {
                            OrchestratorError::SlotMissed { slot, current_slot } => {
                                warn!(slot = slot, current_slot = current_slot, "Missed slot");
                                RVC_ATTESTATIONS_TOTAL
                                    .with_label_values(&[attestation_status::SKIPPED])
                                    .inc();
                            }
                            OrchestratorError::NoDutiesForSlot { slot } => {
                                debug!(slot = slot, "No duties for slot");
                            }
                            _ => {
                                error!(slot = current_slot, error = %e, "Error processing slot");
                            }
                        }
                    }
                } else {
                    debug!(slot = current_slot, "Attestation duties skipped (disabled)");
                }

                // H-7: sync-committee messages are gated by `sync_enabled`,
                // which is independent of `attesting_enabled`. Disabling
                // attestations no longer silently disables sync-committee duties.
                self.run_sync_messages_phase(current_slot, current_epoch, &ctx)
                    .instrument(att_phase_span)
                    .await;
            }

            if self.check_shutdown() {
                return Ok(());
            }

            // === Phase 3: t=2*slot/3 — Aggregation + sync committee contributions ===
            {
                let agg_phase_span = info_span!(parent: &slot_span, "slot.phase.aggregation");

                // Basis-points formula in milliseconds (report §4.3): mainnet
                // 2/3 = 6667 * 12000 / 10000 = 8000 ms (unchanged from the legacy
                // `as_secs() * 2 / 3`), but exact for non-12 s / Gloas slots.
                let slot_duration_ms = self.clock.slot_duration().as_millis() as u64;
                let two_thirds_offset_ms = due_ms(AGGREGATE_DUE_BPS, slot_duration_ms);
                let slot_start_ms = self.clock.slot_start_time(current_slot) * 1000;
                let two_thirds_ms = slot_start_ms + two_thirds_offset_ms;
                let now_ms = self.clock.current_time_secs() * 1000;

                if now_ms < two_thirds_ms {
                    let wait_duration = Duration::from_millis(two_thirds_ms - now_ms);
                    {
                        let _guard = agg_phase_span.enter();
                        debug!(
                            slot = current_slot,
                            wait_ms = wait_duration.as_millis(),
                            "Waiting for 2/3 slot time"
                        );
                    }

                    tokio::select! {
                        _ = tokio::time::sleep(wait_duration).instrument(agg_phase_span.clone()) => {}
                        _ = self.shutdown_rx.changed() => {
                            if self.check_shutdown() {
                                return Ok(());
                            }
                        }
                    }
                }

                if self.check_shutdown() {
                    return Ok(());
                }

                // H-7: sync contributions gated by `sync_enabled` independently.
                self.run_sync_contributions_phase(current_slot, current_epoch, &ctx)
                    .instrument(agg_phase_span.clone())
                    .await;

                if self.attesting_enabled.load(Ordering::Relaxed) {
                    self.aggregation_service
                        .maybe_produce_aggregations(current_slot, current_epoch)
                        .instrument(agg_phase_span)
                        .await;
                } else {
                    debug!(slot = current_slot, "Aggregation duties skipped (attesting disabled)");
                }
            }

            // === Post-duty: builder registration (epoch boundary only) ===
            // Runs concurrently with the next-slot wait via select! so it
            // doesn't block slot processing. If the next slot arrives before
            // registration completes, registration is abandoned (non-critical).
            let next_slot = current_slot + 1;
            let time_until_next_slot = self.clock.time_until_slot(next_slot)?;
            let should_register = current_slot % SLOTS_PER_EPOCH == 0;

            if should_register && !time_until_next_slot.is_zero() {
                // Clone builder_service before borrowing self for shutdown_rx
                let builder_service = self.builder_service.clone();
                let builder_fut = async {
                    if let Some(bs) = builder_service {
                        let jitter = Duration::from_secs(BuilderService::jitter_seconds());
                        debug!(
                            jitter_secs = jitter.as_secs(),
                            "Delaying builder registration with jitter"
                        );
                        tokio::time::sleep(jitter).await;
                        match tokio::time::timeout(
                            BUILDER_REGISTRATION_TIMEOUT,
                            bs.register_validators(),
                        )
                        .await
                        {
                            Ok(Ok(_)) => info!("Builder registration completed"),
                            Ok(Err(e)) => {
                                warn!(error = %e, "Builder registration failed (non-fatal)")
                            }
                            Err(_) => warn!(
                                "Builder registration timed out after {}s (non-fatal)",
                                BUILDER_REGISTRATION_TIMEOUT.as_secs()
                            ),
                        }
                    }
                };
                tokio::pin!(builder_fut);

                tokio::select! {
                    _ = tokio::time::sleep(time_until_next_slot) => {}
                    _ = &mut builder_fut => {}
                    _ = self.shutdown_rx.changed() => {
                        if self.check_shutdown() {
                            return Ok(());
                        }
                    }
                }
            } else if !time_until_next_slot.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(time_until_next_slot) => {}
                    _ = self.shutdown_rx.changed() => {
                        if self.check_shutdown() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    /// Clears attester/proposer duty caches when keymanager has notified a key
    /// set change. Marks the watch generation as seen so a single notification
    /// produces exactly one clear; further slots do not re-clear until another
    /// `key_gen_tx` send.
    ///
    /// Note: `watch::Receiver::has_changed` does **not** mark the value as seen
    /// (tokio 1.x). Without `mark_unchanged` / `borrow_and_update`, the first
    /// import/delete would thrash duty caches every subsequent slot.
    async fn apply_key_gen_cache_invalidation(&mut self) {
        if self.key_gen_rx.has_changed().unwrap_or(false) {
            self.key_gen_rx.mark_unchanged();
            info!("Key set changed, clearing duty cache to trigger refetch");
            self.duty_tracker.clear_cache().await;
        }
    }

    fn check_shutdown(&self) -> bool {
        if *self.shutdown_rx.borrow() {
            info!("Shutdown signal received, stopping orchestrator");
            true
        } else {
            false
        }
    }

    fn update_circuit_breaker_metrics(&self) {
        RVC_BUILDER_CONSECUTIVE_MISSES.set(self.circuit_breaker.consecutive_misses() as i64);
        RVC_BUILDER_EPOCH_MISSES.set(self.circuit_breaker.epoch_misses() as i64);
    }

    #[tracing::instrument(name = "orchestrator.maybe_propose_block", level = "debug", skip_all, fields(slot = slot, epoch = epoch))]
    async fn maybe_propose_block(&self, slot: Slot, epoch: u64, ctx: &SlotContext) {
        let proposer_duty = match self.duty_tracker.get_proposer_duty(slot).await {
            Some(duty) => duty,
            None => return,
        };

        // Check if the proposer is one of our validators
        let pubkey = match utils::find_pubkey(&self.pubkey_map, &proposer_duty.pubkey) {
            Some(pk) => pk,
            None => return,
        };

        // D-3: per-validator doppelganger gate (mirrors attestation.rs M-12 check).
        // Skip block proposal for validators still inside the post-import
        // doppelganger window (`enabled = false`).
        {
            let pk_bytes = pubkey.to_bytes();
            if !self.validator_store.is_signing_enabled(&pk_bytes) {
                warn!(
                    slot,
                    pubkey = %observability::logging::TruncatedPubkey::new(&proposer_duty.pubkey),
                    "Skipping block proposal: validator is inside the \
                     post-import doppelganger window (D-3)"
                );
                return;
            }
        }

        // H-4: parse validator_index for proposer_index validation (returned as String by the BN type)
        let expected_proposer_index: u64 = match proposer_duty.validator_index.parse() {
            Ok(v) => v,
            Err(_) => {
                error!(slot, raw = %proposer_duty.validator_index,
                    "Cannot parse proposer duty validator_index as u64 — dropping duty");
                return;
            }
        };

        info!(slot, validator_index = %proposer_duty.validator_index, "Proposing block");

        // Wrap with combined produce + publish timeout
        match tokio::time::timeout(
            self.config.timeouts.block_production + self.config.timeouts.block_publication,
            self.block_service.propose_block(slot, &pubkey, expected_proposer_index, ctx.head_root),
        )
        .await
        {
            Ok(Ok(result)) => {
                let was_tripped = self.circuit_breaker.is_tripped();
                self.circuit_breaker.record_success();
                self.update_circuit_breaker_metrics();
                if was_tripped && !self.circuit_breaker.is_tripped() {
                    info!(slot, "Builder circuit breaker reset after successful proposal");
                }
                info!(
                    slot,
                    blinded = result.is_blinded,
                    consensus_version = %result.consensus_version,
                    "Block proposed successfully"
                );
            }
            Ok(Err(e)) => {
                // H-3: only record a miss when the failure originated from the
                // builder path.  Signer errors, BN errors on the local-only
                // path (boost = 0), and validation failures must not trip the
                // builder circuit breaker.
                let is_builder_failure = matches!(
                    e,
                    block_service::BlockServiceError::BuilderFailure(_)
                        | block_service::BlockServiceError::BuilderOnly(_)
                );
                if is_builder_failure {
                    let was_tripped = self.circuit_breaker.is_tripped();
                    self.circuit_breaker.record_miss();
                    self.update_circuit_breaker_metrics();
                    if !was_tripped && self.circuit_breaker.is_tripped() {
                        RVC_BUILDER_CIRCUIT_BREAKER_TRIPS_TOTAL.inc();
                        warn!(slot, "Builder circuit breaker tripped");
                    }
                }
                error!(
                    slot,
                    epoch,
                    error = %e,
                    "Failed to propose block"
                );
            }
            Err(_) => {
                // Outer timeout: we cannot determine whether the builder relay
                // was involved.  Do not record a miss — a transient BN or
                // network slowdown that fires the outer timeout should not
                // disable MEV for a full epoch (H-3).
                error!(
                    slot,
                    epoch,
                    "Block proposal timed out after {}s",
                    (self.config.timeouts.block_production
                        + self.config.timeouts.block_publication)
                        .as_secs()
                );
            }
        }
    }

    pub async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        self.attestation_service.process_slot(slot).await
    }

    /// Sets the sync-committee duty participation flag.
    ///
    /// When `false`, sync-committee messages and contributions are silently
    /// skipped for all subsequent slots until re-enabled. This flag is
    /// independent of `attesting_enabled`, closing H-7: disabling attestations
    /// no longer silently disables sync-committee duties.
    ///
    /// Internal-only — NOT wired to any Keymanager API endpoint (per OQ-A3
    /// decision deferred to Tier-1 follow-up).
    pub fn set_sync_enabled(&self, enabled: bool) {
        self.sync_enabled.store(enabled, Ordering::Release);
    }

    /// Runs the sync-committee messages phase, gated by `sync_enabled`.
    ///
    /// Extracted so both the run loop and tests can invoke the guarded phase
    /// in isolation.
    async fn run_sync_messages_phase(&self, slot: Slot, epoch: u64, ctx: &SlotContext) {
        if self.sync_enabled.load(Ordering::Acquire) {
            self.sync_committee_service.maybe_produce_sync_messages(slot, epoch, ctx).await;
        }
    }

    /// Runs the sync-committee contributions phase, gated by `sync_enabled`.
    async fn run_sync_contributions_phase(&self, slot: Slot, epoch: u64, ctx: &SlotContext) {
        if self.sync_enabled.load(Ordering::Acquire) {
            self.sync_committee_service.maybe_produce_sync_contributions(slot, epoch, ctx).await;
        }
    }
}

#[cfg(test)]
mod tests;
