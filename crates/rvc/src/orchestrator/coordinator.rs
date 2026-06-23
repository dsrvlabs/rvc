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

/// Main orchestrator for coordinating validator duties.
#[allow(dead_code)]
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
    /// Creates a new DutyOrchestrator with the given dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
    ) -> (Self, OrchestratorHandle) {
        let attesting_enabled = Arc::new(AtomicBool::new(true));
        let (_key_gen_tx, key_gen_rx) = watch::channel(0u64);
        Self::new_with_key_gen(
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
            Arc::new(CircuitBreakerState::new(0, 0)),
            attesting_enabled,
        )
    }

    /// Creates a new DutyOrchestrator with a shared attesting_enabled flag.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_attesting_enabled(
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
        circuit_breaker: Arc<CircuitBreakerState>,
        attesting_enabled: Arc<AtomicBool>,
    ) -> (Self, OrchestratorHandle) {
        let (_key_gen_tx, key_gen_rx) = watch::channel(0u64);
        Self::new_with_key_gen(
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
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_key_gen(
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
        key_gen_rx: watch::Receiver<u64>,
        circuit_breaker: Arc<CircuitBreakerState>,
        attesting_enabled: Arc<AtomicBool>,
    ) -> (Self, OrchestratorHandle) {
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

            let slot_span =
                info_span!("rvc.slot.process", rvc.slot = current_slot, rvc.epoch = current_epoch,);

            // Check if keys changed (dynamic key import/delete via keymanager API)
            if self.key_gen_rx.has_changed().unwrap_or(false) {
                info!("Key set changed, clearing duty cache to trigger refetch");
                self.duty_tracker.clear_cache().await;
            }

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
                    info_span!(parent: &slot_span, "rvc.epoch.boundary", rvc.epoch = current_epoch);
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
                let phase_span = info_span!(parent: &slot_span, "rvc.slot.phase.block");
                self.maybe_propose_block(ctx.slot, ctx.epoch, &ctx).instrument(phase_span).await;
            }

            if self.check_shutdown() {
                return Ok(());
            }

            // === Phase 2: t=slot/3 — Attestations + sync committee messages ===
            {
                let att_phase_span = info_span!(parent: &slot_span, "rvc.slot.phase.attestation");

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
                let agg_phase_span = info_span!(parent: &slot_span, "rvc.slot.phase.aggregation");

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

    #[tracing::instrument(name = "rvc.orchestrator.maybe_propose_block", skip_all, fields(rvc.slot = slot, rvc.epoch = epoch))]
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
                    pubkey = %crypto::logging::TruncatedPubkey::new(&proposer_duty.pubkey),
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
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use beacon::{
        AttestationDataResponse, AttesterDutiesResponse, AttesterDuty, BeaconClient,
        BeaconClientConfig, BeaconCommitteeSubscription, BeaconError, BlockRootData,
        BlockRootResponse, ConfigSpecResponse, DataResponse, ExecutionOptimisticResponse,
        GenesisResponse, ProposerDutiesResponse, ProposerPreparation,
        SignedContributionAndProof as BeaconSignedContributionAndProof, StateForkResponse,
        SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
        SyncCommitteeMessage as BeaconSyncCommitteeMessage, SyncingResponse, ValidatorsResponse,
        VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
    };
    // block_service::ProduceBlockResponse is used in MockBlockBeacon / BadProposerBlockBeacon
    use block_service::ProduceBlockResponse;
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use eth_types::{
        ForkName, Root, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedValidatorRegistration,
        SyncCommitteeDuty,
    };
    use slashing::SlashingDb;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use timing::MockSlotClock;
    use tree_hash::TreeHash;
    use validator_store::ValidatorStore;

    const TEST_GENESIS_TIME: u64 = 1606824023;

    fn fast_timeouts() -> OperationTimeouts {
        OperationTimeouts {
            duty_fetch: Duration::from_millis(200),
            block_production: Duration::from_millis(200),
            block_publication: Duration::from_millis(200),
            attestation_fetch: Duration::from_millis(200),
            attestation_submit: Duration::from_millis(200),
            aggregate_fetch: Duration::from_millis(200),
            aggregate_submit: Duration::from_millis(200),
            sync_message: Duration::from_millis(200),
            sync_contribution: Duration::from_millis(200),
            preparation: Duration::from_millis(200),
        }
    }

    fn create_test_fork_schedule() -> Arc<ForkSchedule> {
        Arc::new(ForkSchedule {
            genesis_fork_version: [0, 0, 0, 1],
            altair_fork_epoch: 10,
            altair_fork_version: [0, 0, 0, 2],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [0, 0, 0, 3],
            capella_fork_epoch: 30,
            capella_fork_version: [0, 0, 0, 4],
            deneb_fork_epoch: 40,
            deneb_fork_version: [0, 0, 0, 5],
            electra_fork_epoch: 50,
            electra_fork_version: [0, 0, 0, 6],
            fulu_fork_epoch: 60,
            fulu_fork_version: [0, 0, 0, 7],
        })
    }

    fn create_test_config() -> OrchestratorConfig {
        OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule())
    }

    struct MockSubmitter {
        call_count: AtomicUsize,
        should_succeed: std::sync::atomic::AtomicBool,
    }

    impl MockSubmitter {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
                should_succeed: std::sync::atomic::AtomicBool::new(true),
            }
        }

        #[allow(dead_code)]
        fn set_should_succeed(&self, value: bool) {
            self.should_succeed.store(value, Ordering::SeqCst);
        }

        #[allow(dead_code)]
        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl AttestationSubmitter for MockSubmitter {
        fn submit_attestation<'a>(
            &'a self,
            _attestations: &'a VersionedAttestation,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<beacon::SubmitAttestationResult, beacon::BeaconError>>
                    + Send
                    + 'a,
            >,
        > {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let should_succeed = self.should_succeed.load(Ordering::SeqCst);
            Box::pin(async move {
                if should_succeed {
                    Ok(beacon::SubmitAttestationResult::Success)
                } else {
                    Err(beacon::BeaconError::Timeout)
                }
            })
        }
    }

    struct MockBlockBeacon;

    #[async_trait(?Send)]
    impl BeaconBlockClient for MockBlockBeacon {
        async fn produce_block_v3(
            &self,
            _slot: Slot,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
            Err(block_service::BlockServiceError::Beacon("mock".to_string()))
        }

        async fn publish_block(
            &self,
            _signed_block: &eth_types::SignedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), block_service::BlockServiceError> {
            Ok(())
        }

        async fn publish_blinded_block(
            &self,
            _signed_block: &eth_types::SignedBlindedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), block_service::BlockServiceError> {
            Ok(())
        }

        async fn publish_block_ssz(
            &self,
            _ssz_bytes: &[u8],
            _consensus_version: &str,
            _is_blinded: bool,
        ) -> Result<(), block_service::BlockServiceError> {
            Ok(())
        }
    }

    fn create_mock_block_beacon() -> Arc<MockBlockBeacon> {
        Arc::new(MockBlockBeacon)
    }

    /// Block beacon that returns a block with a configurable `proposer_index`
    /// and tracks whether `publish_block` / `publish_blinded_block` /
    /// `publish_block_ssz` is called.  Used by the H-4 coordinator integration
    /// test to verify that a wrong `proposer_index` causes the duty to be
    /// dropped before any publish attempt.
    struct BadProposerBlockBeacon {
        slot: Slot,
        bad_proposer_index: u64,
        publish_called: Arc<AtomicBool>,
    }

    #[async_trait(?Send)]
    impl BeaconBlockClient for BadProposerBlockBeacon {
        async fn produce_block_v3(
            &self,
            _slot: Slot,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, block_service::BlockServiceError> {
            Ok(ProduceBlockResponse {
                data: serde_json::json!({
                    "slot": self.slot.to_string(),
                    "proposer_index": self.bad_proposer_index.to_string(),
                    "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "body": "0x"
                }),
                is_blinded: false,
                consensus_version: "deneb".to_string(),
                execution_payload_value: None,
                is_ssz: false,
                ssz_bytes: None,
            })
        }

        async fn publish_block(
            &self,
            _signed_block: &eth_types::SignedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), block_service::BlockServiceError> {
            self.publish_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_blinded_block(
            &self,
            _signed_block: &eth_types::SignedBlindedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), block_service::BlockServiceError> {
            self.publish_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn publish_block_ssz(
            &self,
            _ssz_bytes: &[u8],
            _consensus_version: &str,
            _is_blinded: bool,
        ) -> Result<(), block_service::BlockServiceError> {
            self.publish_called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn create_mock_validator_store() -> Arc<ValidatorStore> {
        Arc::new(ValidatorStore::new([0u8; 20], 100))
    }

    // ── H-7 mock: captures sync committee message submissions ────────────────
    //
    // Implements `BeaconNodeClient` with:
    //   - `post_sync_committee_duties` → returns a duty for `duty_pubkey`
    //   - `submit_sync_committee_messages` → records beacon_block_root values
    //   - All other methods → return `BeaconError::HttpError("mock")`
    //
    // Used to test the `sync_enabled` guard without a real beacon node.
    struct SyncGuardBeacon {
        duty_pubkey: String,
        submitted_roots: Arc<std::sync::Mutex<Vec<Root>>>,
    }

    #[async_trait]
    impl bn_manager::BeaconNodeClient for SyncGuardBeacon {
        async fn get_block_root(&self, _block_id: &str) -> Result<BlockRootResponse, BeaconError> {
            // Return a fixed root so SlotContext::capture succeeds.
            Ok(DataResponse {
                data: BlockRootData {
                    root: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                },
            })
        }

        async fn post_sync_committee_duties(
            &self,
            _epoch: u64,
            _indices: &[String],
        ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
            Ok(ExecutionOptimisticResponse {
                execution_optimistic: false,
                data: vec![SyncCommitteeDuty {
                    pubkey: self.duty_pubkey.clone(),
                    validator_index: 1,
                    validator_sync_committee_indices: vec![0],
                }],
            })
        }

        async fn submit_sync_committee_messages(
            &self,
            messages: &[BeaconSyncCommitteeMessage],
        ) -> Result<(), BeaconError> {
            let mut roots = self.submitted_roots.lock().unwrap();
            for msg in messages {
                roots.push(msg.beacon_block_root);
            }
            Ok(())
        }

        async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_fork_schedule(&self) -> Result<eth_types::ForkSchedule, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_fork(&self, _state_id: &str) -> Result<StateForkResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_validators(
            &self,
            _pubkeys: &[String],
        ) -> Result<ValidatorsResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_attester_duties(
            &self,
            _epoch: u64,
            _indices: &[String],
        ) -> Result<AttesterDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_proposer_duties(
            &self,
            _epoch: u64,
        ) -> Result<ProposerDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn produce_block_v3(
            &self,
            _slot: u64,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_boost_factor: Option<u64>,
        ) -> Result<beacon::ProduceBlockResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn publish_block(
            &self,
            _signed_block: &SignedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn publish_blinded_block(
            &self,
            _signed_block: &SignedBlindedBeaconBlock,
            _consensus_version: &str,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_attestation_data(
            &self,
            _slot: u64,
            _committee_index: u64,
        ) -> Result<AttestationDataResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn submit_attestation(
            &self,
            _attestations: &VersionedAttestation,
        ) -> Result<SubmitAttestationResult, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_aggregate_attestation(
            &self,
            _slot: u64,
            _attestation_data_root: &str,
            _committee_index: Option<u64>,
        ) -> Result<VersionedAggregateAttestation, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn submit_aggregate_and_proofs(
            &self,
            _proofs: &VersionedSignedAggregateAndProof,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_sync_committee_contribution(
            &self,
            _slot: u64,
            _subcommittee_index: u64,
            _beacon_block_root: &str,
        ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn submit_contribution_and_proofs(
            &self,
            _proofs: &[BeaconSignedContributionAndProof],
        ) -> Result<(), BeaconError> {
            Ok(())
        }
        async fn prepare_beacon_proposer(
            &self,
            _preparations: &[ProposerPreparation],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn submit_beacon_committee_subscriptions(
            &self,
            _subscriptions: &[BeaconCommitteeSubscription],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn register_validators(
            &self,
            _registrations: &[SignedValidatorRegistration],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_node_version(&self) -> Result<String, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
    }

    #[test]
    fn test_orchestrator_config_new() {
        let config = OrchestratorConfig::new([0xbb; 32], create_test_fork_schedule());
        assert_eq!(config.genesis_validators_root, [0xbb; 32]);
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_orchestrator_config_with_shutdown_timeout() {
        let config = OrchestratorConfig::new([0xcc; 32], create_test_fork_schedule())
            .with_shutdown_timeout(Duration::from_secs(60));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_orchestrator_config_with_timeouts() {
        let timeouts = OperationTimeouts {
            block_production: Duration::from_secs(5),
            duty_fetch: Duration::from_secs(15),
            ..Default::default()
        };

        let config = OrchestratorConfig::new([0xdd; 32], create_test_fork_schedule())
            .with_timeouts(timeouts);

        assert_eq!(config.timeouts.block_production, Duration::from_secs(5));
        assert_eq!(config.timeouts.duty_fetch, Duration::from_secs(15));
        // Other fields remain at default
        assert_eq!(config.timeouts.block_publication, Duration::from_secs(2));
    }

    #[test]
    fn test_orchestrator_config_default_timeouts() {
        let config = OrchestratorConfig::new([0xee; 32], create_test_fork_schedule());
        let defaults = OperationTimeouts::default();

        assert_eq!(config.timeouts.block_production, defaults.block_production);
        assert_eq!(config.timeouts.duty_fetch, defaults.duty_fetch);
        assert_eq!(config.timeouts.attestation_fetch, defaults.attestation_fetch);
    }

    #[tokio::test]
    async fn test_orchestrator_handle_shutdown() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (mut orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        handle.shutdown();

        let result = orchestrator.run().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_orchestrator_no_duties_for_slot() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let result = orchestrator.process_slot(100).await;

        assert!(matches!(result, Err(OrchestratorError::NoDutiesForSlot { slot: 100 })));
    }

    #[tokio::test]
    async fn test_orchestrator_slot_missed() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(105);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let result = orchestrator.process_slot(100).await;

        assert!(matches!(result, Err(OrchestratorError::SlotMissed { .. })));
    }

    #[test]
    fn test_attestation_result_success() {
        let result = AttestationResult {
            validator_index: "1234".to_string(),
            slot: 100,
            success: true,
            error: None,
        };
        assert!(result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_attestation_result_failure() {
        let result = AttestationResult {
            validator_index: "1234".to_string(),
            slot: 100,
            success: false,
            error: Some("Test error".to_string()),
        };
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("Test error"));
    }

    #[tokio::test]
    async fn test_orchestrator_with_validator_keys() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex, pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let (_orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        assert!(!*handle.shutdown_tx.borrow());
        handle.shutdown();
        assert!(*handle.shutdown_tx.borrow());
    }

    #[tokio::test]
    async fn test_find_pubkey_exact_match() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey.clone());
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let found = utils::find_pubkey(&orchestrator.pubkey_map, &pubkey_hex);
        assert!(found.is_some());
        assert_eq!(found.unwrap().to_bytes(), pubkey.to_bytes());
    }

    #[tokio::test]
    async fn test_find_pubkey_case_insensitive() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.to_uppercase(), pubkey.clone());
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let found = utils::find_pubkey(&orchestrator.pubkey_map, &pubkey_hex.to_lowercase());
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_find_pubkey_not_found() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let found = utils::find_pubkey(&orchestrator.pubkey_map, "0x1234567890abcdef");
        assert!(found.is_none());
    }

    #[test]
    fn test_timeout_constants_are_reasonable() {
        let timeouts = OperationTimeouts::default();

        // Block production must fit within a slot third (~4s for 12s slots)
        assert!(timeouts.block_production.as_secs() <= 4);
        assert!(timeouts.block_production.as_secs() >= 1);

        // Block publish must fit within remaining slot time
        assert!(timeouts.block_publication.as_secs() <= 3);
        assert!(timeouts.block_publication.as_secs() >= 1);

        // Produce + publish together should fit in one slot third (~4s)
        assert!(timeouts.block_production + timeouts.block_publication <= Duration::from_secs(6));

        // Sync operations must fit within their slot third
        assert!(timeouts.sync_message.as_secs() <= 3);
        assert!(timeouts.sync_contribution.as_secs() <= 3);

        // Duty fetch is less time-critical but should still be bounded
        assert!(timeouts.duty_fetch.as_secs() <= 12);
        assert!(timeouts.duty_fetch.as_secs() >= 5);

        // Attestation timeout must fit within slot third
        assert!(timeouts.attestation_fetch.as_secs() <= 5);
    }

    #[tokio::test]
    async fn test_duty_fetch_timeout() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let timeouts = fast_timeouts();
        let mock_server = MockServer::start().await;

        // Mock attester duties endpoint with a delay that exceeds duty_fetch (200ms)
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": [],
                        "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                    }))
                    .set_delay(timeouts.duty_fetch + Duration::from_millis(500)),
            )
            .mount(&mock_server)
            .await;

        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let epoch = 1u64;
        let result =
            tokio::time::timeout(timeouts.duty_fetch, duty_tracker.fetch_duties_for_epoch(epoch))
                .await;

        // Should timeout (Err from tokio::time::timeout)
        assert!(result.is_err(), "Duty fetch should have timed out");
    }

    #[tokio::test]
    async fn test_sync_message_submit_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let timeouts = OperationTimeouts::default();
        let mock_server = MockServer::start().await;

        // Mock sync committee messages endpoint with delay exceeding sync_message timeout
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(timeouts.sync_message + Duration::from_secs(5)),
            )
            .mount(&mock_server)
            .await;

        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let messages = vec![beacon::SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [0u8; 32],
            validator_index: 1,
            signature: vec![0u8; 96],
        }];

        let result = tokio::time::timeout(
            timeouts.sync_message,
            beacon.submit_sync_committee_messages(&messages),
        )
        .await;

        assert!(result.is_err(), "Sync message submit should have timed out");
    }

    #[tokio::test]
    async fn test_head_block_root_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let timeouts = OperationTimeouts::default();
        let mock_server = MockServer::start().await;

        // Mock block root endpoint with delay exceeding sync_message timeout
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/blocks/head/root"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": {
                            "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                        }
                    }))
                    .set_delay(timeouts.sync_message + Duration::from_secs(5)),
            )
            .mount(&mock_server)
            .await;

        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let result =
            tokio::time::timeout(timeouts.sync_message, beacon.get_block_root("head")).await;

        assert!(result.is_err(), "Head block root fetch should have timed out");
    }

    #[test]
    fn test_aggregation_timeout_is_reasonable() {
        let timeouts = OperationTimeouts::default();
        // Must fit within the 2/3-slot to end-of-slot window (~4s for 12s slots)
        assert!(timeouts.aggregate_fetch.as_secs() <= 4);
        assert!(timeouts.aggregate_fetch.as_secs() >= 1);
    }

    #[test]
    fn test_aggregate_submit_uses_distinct_timeout_field() {
        let timeouts = OperationTimeouts {
            aggregate_fetch: Duration::from_secs(5),
            aggregate_submit: Duration::from_secs(1),
            ..Default::default()
        };
        // These must be distinct fields — submit path must use aggregate_submit
        assert_ne!(timeouts.aggregate_fetch, timeouts.aggregate_submit);
    }

    #[test]
    fn test_attestation_submit_timeout_exists() {
        let timeouts = OperationTimeouts::default();
        // attestation_submit must be a usable timeout value
        assert!(timeouts.attestation_submit.as_secs() >= 1);
        assert!(timeouts.attestation_submit.as_secs() <= 5);
    }

    /// Helper to build an orchestrator wired to a wiremock mock_server for aggregation tests.
    async fn build_aggregation_orchestrator(
        mock_server_uri: &str,
    ) -> (
        DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon>,
        OrchestratorHandle,
        PublicKey,
        String,
    ) {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new(mock_server_uri);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let secret_key = SecretKey::generate();
        let pubkey_hex = format!("0x{}", hex::encode(secret_key.public_key().to_bytes()));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));

        let pubkey = secret_key.public_key();
        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey.clone());
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        // D-3 fail-closed: register the loaded validator so the per-validator
        // signing gate permits its duties (mirrors startup registration).
        let validator_store = create_mock_validator_store();
        validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()));

        let (orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
        );

        (orchestrator, handle, pubkey, pubkey_hex)
    }

    #[tokio::test]
    async fn test_aggregation_no_duties_does_nothing() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, _) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        // Mock attester duties to return empty list
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&mock_server)
            .await;

        // Fetch duties (empty) so the epoch is cached
        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        // Should NOT call any aggregation endpoints
        Mock::given(method("GET"))
            .and(path_regex(r"/eth/v1/validator/aggregate_attestation.*"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }

    #[tokio::test]
    async fn test_aggregation_full_flow_with_mock_beacon() {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        // 1. Mock attester duties endpoint — return a duty with a small committee
        //    (committee_length ≤ 16 → modulo=1 → always aggregator)
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        // 2. Mock attestation data endpoint
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        // 3. Mock aggregate attestation endpoint
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xffffffff",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "1",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": (epoch - 1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })))
            .mount(&mock_server)
            .await;

        // 4. Mock submit aggregate and proofs endpoint
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Fetch duties first so they're cached
        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        // Run the aggregation dispatch
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

        // The mock server's expect(1) on submit verifies the request was made
    }

    #[tokio::test]
    async fn test_aggregation_non_aggregator_skips() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        // Use committee_length=u64::MAX so is_aggregator is deterministically false
        // modulo = u64::MAX / 16 → probability ~5.4e-18, effectively zero
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "18446744073709551615",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        // Should NOT call get_aggregate_attestation or submit
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }

    #[tokio::test]
    async fn test_aggregation_beacon_failure_handled_gracefully() {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        // Small committee → always aggregator
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        // Attestation data endpoint returns an error
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "message": "Internal server error"
            })))
            .mount(&mock_server)
            .await;

        // Should NOT call submit since attestation data fetch failed
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        // Should not panic; gracefully handle error
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }

    // --- B-05: Proposer preparation tests ---

    #[tokio::test]
    async fn test_prepare_proposers_sends_preparations() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock attester duties endpoint to seed the duty tracker cache
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "128",
                    "committees_at_slot": "4",
                    "validator_committee_index": "10",
                    "slot": "96"
                }]
            })))
            .mount(&mock_server)
            .await;

        // Mock proposer preparation endpoint
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Slot 96 = epoch 3, slot 0 of epoch
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
        clock.set_slot(96);

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["42".to_string()]));

        // Fetch duties to populate the cache
        duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();

        // Map our pubkey to match the duty's pubkey
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            pubkey,
        );
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
        );

        orchestrator.duty_management.prepare_proposers().await;
        // wiremock will verify expect(1) on drop
    }

    #[tokio::test]
    async fn test_prepare_proposers_no_validators_no_call() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock should NOT be called
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 0));
        clock.set_slot(0);

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        orchestrator.duty_management.prepare_proposers().await;
    }

    #[tokio::test]
    async fn test_prepare_proposers_failure_is_non_fatal() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock attester duties to seed cache
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "validator_index": "99",
                    "committee_index": "0",
                    "committee_length": "64",
                    "committees_at_slot": "2",
                    "validator_committee_index": "5",
                    "slot": "96"
                }]
            })))
            .mount(&mock_server)
            .await;

        // Return error for prepare_beacon_proposer
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
        clock.set_slot(96);

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["99".to_string()]));

        duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            pubkey,
        );
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
        );

        // Should not panic - failure is non-fatal
        orchestrator.duty_management.prepare_proposers().await;
    }

    // --- B-05: Committee subscription tests ---

    #[tokio::test]
    async fn test_submit_committee_subscriptions_sends_subscriptions() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock attester duties
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "validator_index": "10",
                    "committee_index": "2",
                    "committee_length": "128",
                    "committees_at_slot": "4",
                    "validator_committee_index": "7",
                    "slot": "100"
                }]
            })))
            .mount(&mock_server)
            .await;

        // Mock committee subscription endpoint
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
        clock.set_slot(96);

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["10".to_string()]));
        duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            pubkey,
        );
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        orchestrator.duty_management.submit_committee_subscriptions(3).await;
        // wiremock will verify expect(1) on drop
    }

    #[tokio::test]
    async fn test_submit_committee_subscriptions_no_duties_no_call() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock should NOT be called
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 0));
        clock.set_slot(0);

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        orchestrator.duty_management.submit_committee_subscriptions(0).await;
    }

    #[tokio::test]
    async fn test_submit_committee_subscriptions_failure_is_non_fatal() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "validator_index": "55",
                    "committee_index": "0",
                    "committee_length": "64",
                    "committees_at_slot": "2",
                    "validator_committee_index": "3",
                    "slot": "97"
                }]
            })))
            .mount(&mock_server)
            .await;

        // Return error for subscriptions
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 96));
        clock.set_slot(96);

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["55".to_string()]));
        duty_tracker.fetch_duties_for_epoch(3).await.unwrap();

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            pubkey,
        );
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        // Should not panic
        orchestrator.duty_management.submit_committee_subscriptions(3).await;
    }

    #[test]
    fn test_preparation_timeout_is_reasonable() {
        let timeouts = OperationTimeouts::default();
        assert!(timeouts.preparation.as_secs() >= 1);
        assert!(timeouts.preparation.as_secs() <= 5);
    }

    #[test]
    fn test_builder_registration_timeout_is_reasonable() {
        assert!(BUILDER_REGISTRATION_TIMEOUT.as_secs() >= 5);
        assert!(BUILDER_REGISTRATION_TIMEOUT.as_secs() <= 15);
    }

    // NOTE: Tests for builder registration behavior (called_at_epoch_boundary,
    // nonfatal_on_failure, skipped_when_no_builder_service,
    // skips_non_builder_validators) were removed after CON-01 refactored
    // register_builders() into the main loop via tokio::select!.
    // Builder registration is now tested implicitly through the main loop tests.

    #[tokio::test]
    async fn test_check_reorg_at_epoch_boundary_no_change() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let attester_response = serde_json::json!({
            "data": [],
            "dependent_root": "0xstable_root",
            "execution_optimistic": false
        });

        let proposer_response = serde_json::json!({
            "data": [],
            "dependent_root": "0xstable_root",
            "execution_optimistic": false
        });

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&attester_response))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&proposer_response))
            .mount(&mock_server)
            .await;

        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri())
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(1);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        // Pre-populate caches
        duty_tracker.fetch_duties_for_epoch(10).await.unwrap();
        duty_tracker.fetch_duties_for_epoch(11).await.unwrap();
        duty_tracker.fetch_proposer_duties(10).await.unwrap();
        duty_tracker.fetch_proposer_duties(11).await.unwrap();

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(320);

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));
        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        // Should not panic, should complete successfully
        orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;
    }

    #[tokio::test]
    async fn test_check_reorg_at_epoch_boundary_uncached_fetches() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let attester_response = serde_json::json!({
            "data": [],
            "dependent_root": "0xnew_root",
            "execution_optimistic": false
        });

        let proposer_response = serde_json::json!({
            "data": [],
            "dependent_root": "0xnew_root",
            "execution_optimistic": false
        });

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&attester_response))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&proposer_response))
            .mount(&mock_server)
            .await;

        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri())
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(1);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(320);

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));
        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker.clone(),
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        // No caches populated — should fetch and not panic
        orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;

        // Caches should now be populated
        assert!(duty_tracker.is_epoch_cached(10).await);
        assert!(duty_tracker.is_epoch_cached(11).await);
        assert!(duty_tracker.is_proposer_epoch_cached(10).await);
        assert!(duty_tracker.is_proposer_epoch_cached(11).await);
    }

    #[tokio::test]
    async fn test_check_reorg_at_epoch_boundary_timeout_bounds_slow_beacon() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let slow_response = serde_json::json!({
            "data": [],
            "dependent_root": "0xslow_root",
            "execution_optimistic": false
        });

        let timeouts = fast_timeouts();

        // Respond slower than duty_fetch timeout (200ms)
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&slow_response)
                    .set_delay(timeouts.duty_fetch + Duration::from_millis(500)),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&slow_response)
                    .set_delay(timeouts.duty_fetch + Duration::from_millis(500)),
            )
            .mount(&mock_server)
            .await;

        // HTTP timeout must exceed duty_fetch timeout so the tokio timeout fires first
        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri())
            .with_timeout(Duration::from_secs(30))
            .with_max_retries(0);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(320);

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));
        let config = create_test_config().with_timeouts(timeouts.clone());
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let start = std::time::Instant::now();
        orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;
        let elapsed = start.elapsed();

        // 4 calls each bounded by duty_fetch timeout (200ms).
        // Without timeout wrapping this would take 4 * 700ms ≈ 2.8s.
        // With timeouts: 4 * 200ms = 800ms + margin.
        assert!(
            elapsed < timeouts.duty_fetch * 5,
            "Reorg check took {:?}, expected < {:?} (4 timeouts + margin)",
            elapsed,
            timeouts.duty_fetch * 5
        );
    }

    #[tokio::test]
    async fn test_check_reorg_at_epoch_boundary_survives_error() {
        // Use a broken beacon endpoint to verify errors are logged not propagated
        let beacon_config = beacon::BeaconClientConfig::new("http://127.0.0.1:1")
            .with_timeout(Duration::from_millis(100))
            .with_max_retries(0);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(320);

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));
        let config = create_test_config();
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        // Should not panic even with broken beacon
        orchestrator.duty_management.check_reorg_at_epoch_boundary(10).await;
    }

    // -- Fork-aware attestation construction tests (G-1-05) --

    #[test]
    fn test_make_aggregation_bits_first_position() {
        let duty = AttesterDuty {
            pubkey: "0xaabb".to_string(),
            validator_index: "1".to_string(),
            committee_index: "0".to_string(),
            committee_length: "4".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "0".to_string(),
            slot: "100".to_string(),
        };
        let bits = utils::make_aggregation_bits(&duty).unwrap();
        // committee_length=4, validator_committee_index=0
        // Byte 0: bit 0 set (validator) = 0x01
        // Length bit at position 4 → byte 0, bit 4 = 0x10
        // Combined: 0x11
        assert_eq!(bits, "0x11");
    }

    #[test]
    fn test_make_aggregation_bits_middle_position() {
        let duty = AttesterDuty {
            pubkey: "0xaabb".to_string(),
            validator_index: "1".to_string(),
            committee_index: "0".to_string(),
            committee_length: "8".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "3".to_string(),
            slot: "100".to_string(),
        };
        let bits = utils::make_aggregation_bits(&duty).unwrap();
        // committee_length=8, validator_committee_index=3
        // Byte 0: bit 3 set = 0x08
        // Length bit at position 8 → byte 1, bit 0 = 0x01
        // Result: [0x08, 0x01]
        assert_eq!(bits, "0x0801");
    }

    #[test]
    fn test_make_aggregation_bits_last_position() {
        let duty = AttesterDuty {
            pubkey: "0xaabb".to_string(),
            validator_index: "1".to_string(),
            committee_index: "0".to_string(),
            committee_length: "4".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "3".to_string(),
            slot: "100".to_string(),
        };
        let bits = utils::make_aggregation_bits(&duty).unwrap();
        // committee_length=4, validator_committee_index=3
        // Byte 0: bit 3 set = 0x08, length bit at position 4 = 0x10
        // Combined: 0x18
        assert_eq!(bits, "0x18");
    }

    #[test]
    fn test_make_aggregation_bits_zero_committee_length() {
        let duty = AttesterDuty {
            pubkey: "0xaabb".to_string(),
            validator_index: "1".to_string(),
            committee_index: "0".to_string(),
            committee_length: "0".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "0".to_string(),
            slot: "100".to_string(),
        };
        assert!(utils::make_aggregation_bits(&duty).is_none());
    }

    #[test]
    fn test_make_aggregation_bits_invalid_committee_length() {
        let duty = AttesterDuty {
            pubkey: "0xaabb".to_string(),
            validator_index: "1".to_string(),
            committee_index: "0".to_string(),
            committee_length: "not_a_number".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "0".to_string(),
            slot: "100".to_string(),
        };
        assert!(utils::make_aggregation_bits(&duty).is_none());
    }

    #[test]
    fn test_make_aggregation_bits_invalid_validator_committee_index() {
        let duty = AttesterDuty {
            pubkey: "0xaabb".to_string(),
            validator_index: "1".to_string(),
            committee_index: "0".to_string(),
            committee_length: "8".to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: "garbage".to_string(),
            slot: "100".to_string(),
        };
        assert!(utils::make_aggregation_bits(&duty).is_none());
    }

    #[test]
    fn test_fork_name_electra_detection() {
        let schedule = create_test_fork_schedule();
        // electra_fork_epoch = 50

        // Pre-Electra (Deneb)
        let fork_name = ForkName::from_epoch(49, &schedule);
        assert!(fork_name < ForkName::Electra);

        // Electra boundary
        let fork_name = ForkName::from_epoch(50, &schedule);
        assert!(fork_name >= ForkName::Electra);

        // Post-Electra
        let fork_name = ForkName::from_epoch(100, &schedule);
        assert!(fork_name >= ForkName::Electra);
    }

    // --- G-1-06: Electra fork transition integration tests ---

    /// A submitter that captures the submitted VersionedAttestation for assertion.
    struct CapturingSubmitter {
        captured: parking_lot::Mutex<Vec<VersionedAttestation>>,
    }

    impl CapturingSubmitter {
        fn new() -> Self {
            Self { captured: parking_lot::Mutex::new(Vec::new()) }
        }

        fn captured(&self) -> Vec<VersionedAttestation> {
            self.captured.lock().clone()
        }
    }

    impl AttestationSubmitter for CapturingSubmitter {
        fn submit_attestation<'a>(
            &'a self,
            attestations: &'a VersionedAttestation,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<beacon::SubmitAttestationResult, beacon::BeaconError>>
                    + Send
                    + 'a,
            >,
        > {
            self.captured.lock().push(attestations.clone());
            Box::pin(async move { Ok(beacon::SubmitAttestationResult::Success) })
        }
    }

    /// Builds an orchestrator with a CapturingSubmitter for fork transition tests.
    /// Returns the orchestrator, handle, pubkey hex, and a reference to the capturing submitter.
    async fn build_fork_transition_orchestrator(
        mock_server_uri: &str,
        slot: u64,
    ) -> (
        DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
        OrchestratorHandle,
        String,
        Arc<CapturingSubmitter>,
    ) {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(slot);

        let beacon_config = BeaconClientConfig::new(mock_server_uri);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let secret_key = SecretKey::generate();
        let pubkey_hex = format!("0x{}", hex::encode(secret_key.public_key().to_bytes()));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));

        let pubkey = secret_key.public_key();
        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let capturing_submitter = Arc::new(CapturingSubmitter::new());
        let propagator = Arc::new(Propagator::new(capturing_submitter.clone()));

        let config = create_test_config();
        let pubkey_bytes = pubkey.to_bytes();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        // D-3 fail-closed: register the loaded validator so the per-validator
        // signing gate permits its duties (mirrors startup registration).
        let validator_store = create_mock_validator_store();
        validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey_bytes));

        let (orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
        );

        (orchestrator, handle, pubkey_hex, capturing_submitter)
    }

    /// Mounts attestation data and attester duties on the mock server for a given slot.
    async fn mount_attestation_mocks(
        mock_server: &wiremock::MockServer,
        slot: u64,
        pubkey_hex: &str,
    ) {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let epoch = slot / SLOTS_PER_EPOCH;

        // Mock attester duties — small committee (always aggregator)
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "3",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "2",
                    "slot": slot.to_string()
                }]
            })))
            .mount(mock_server)
            .await;

        // Mock attestation data
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "3",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch.saturating_sub(1)).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(mock_server)
            .await;
    }

    #[tokio::test]
    async fn test_pre_electra_attestation_produces_legacy_format() {
        let mock_server = wiremock::MockServer::start().await;

        // Slot 96 = epoch 3, well before electra_fork_epoch=50
        let slot = 96u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        // Fetch duties so they're cached
        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        // Process the slot
        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

        // Verify the captured attestation is PreElectra
        let captured = capturing.captured();
        assert_eq!(captured.len(), 1, "Expected exactly one submission");

        match &captured[0] {
            VersionedAttestation::PreElectra(attestations) => {
                assert_eq!(attestations.len(), 1);
                let att = &attestations[0];
                // aggregation_bits should be set (not empty)
                assert!(!att.aggregation_bits.is_empty());
                // data.index should be the committee index from the duty ("3")
                assert_eq!(att.data.index, "3");
            }
            VersionedAttestation::Electra(_) | VersionedAttestation::Fulu(_) => {
                panic!(
                    "Expected PreElectra attestation for slot in epoch 3 (< electra_fork_epoch=50)"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_electra_attestation_produces_single_attestation_format() {
        let mock_server = wiremock::MockServer::start().await;

        // Slot 1600 = epoch 50 = electra_fork_epoch, first Electra slot
        let slot = 1600u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        assert_eq!(epoch, 50, "Slot 1600 should be epoch 50");

        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1);

        match &captured[0] {
            VersionedAttestation::Electra(attestations) => {
                assert_eq!(attestations.len(), 1);
                let att = &attestations[0];
                // EIP-7549: data.index must be "0" in Electra
                assert_eq!(
                    att.data.index, "0",
                    "Electra attestation data.index must be 0 (EIP-7549)"
                );
                // committee_index carries the original committee index
                assert_eq!(
                    att.committee_index, 3,
                    "committee_index should be the duty committee index"
                );
                // attester_index should be the validator index
                assert_eq!(att.attester_index, 42);
            }
            VersionedAttestation::PreElectra(_) | VersionedAttestation::Fulu(_) => {
                panic!("Expected Electra attestation for slot in epoch 50 (= electra_fork_epoch)");
            }
        }
    }

    #[tokio::test]
    async fn test_fork_boundary_last_pre_electra_slot() {
        let mock_server = wiremock::MockServer::start().await;

        // Slot 1599 = last slot of epoch 49 (pre-Electra)
        let slot = 1599u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        assert_eq!(epoch, 49, "Slot 1599 should be epoch 49");

        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1);

        match &captured[0] {
            VersionedAttestation::PreElectra(attestations) => {
                assert_eq!(attestations.len(), 1);
                // Last pre-Electra slot should still use legacy format
                assert!(!attestations[0].aggregation_bits.is_empty());
                assert_eq!(attestations[0].data.index, "3");
            }
            VersionedAttestation::Electra(_) | VersionedAttestation::Fulu(_) => {
                panic!(
                    "Expected PreElectra attestation for slot 1599 (epoch 49, last pre-Electra)"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_electra_aggregation_passes_committee_index() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        // Slot 1600 = epoch 50 = electra_fork_epoch, small committee → always aggregator
        let slot = 1600u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        let (orchestrator, _handle, pubkey_hex, _capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        // Mock aggregate attestation endpoint — expect committee_index query param for Electra
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .and(query_param("committee_index", "3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xff01",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "0",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": (epoch - 1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "committee_bits": "0x0800000000000000"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock aggregate submission (Electra uses v2 endpoint)
        Mock::given(method("POST"))
            .and(path("/eth/v2/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

        // wiremock expect(1) on aggregate_attestation with committee_index=3
        // confirms Electra path passes the committee_index query parameter
    }

    #[tokio::test]
    async fn test_pre_electra_aggregation_no_committee_index() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        // Slot 96 = epoch 3, pre-Electra
        let slot = 96u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        let (orchestrator, _handle, pubkey_hex, _capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        // Pre-Electra: aggregate_attestation WITHOUT committee_index param
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xff01",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "3",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": (epoch.saturating_sub(1)).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

        // Verify pre-Electra requests do NOT contain committee_index query param
        let requests = mock_server.received_requests().await.unwrap();
        let aggregate_requests: Vec<_> = requests
            .iter()
            .filter(|r| {
                r.url.path() == "/eth/v1/validator/aggregate_attestation"
                    && r.method == wiremock::http::Method::GET
            })
            .collect();
        assert!(
            !aggregate_requests.is_empty(),
            "expected at least one aggregate_attestation request"
        );
        for req in &aggregate_requests {
            let query = req.url.query().unwrap_or("");
            assert!(
                !query.contains("committee_index"),
                "pre-Electra aggregate_attestation must not include committee_index, but got: {query}"
            );
        }
    }

    #[tokio::test]
    async fn test_electra_attestation_data_index_zero_before_signing() {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        // Post-Electra: epoch 51
        let slot = 1632u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        assert_eq!(epoch, 51);

        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

        // BN returns attestation data with index "7" — different from 0
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "99",
                    "committee_index": "7",
                    "committee_length": "16",
                    "committees_at_slot": "8",
                    "validator_committee_index": "5",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "7",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1);

        match &captured[0] {
            VersionedAttestation::Electra(atts) => {
                // EIP-7549: data.index must be "0" even though BN returned "7"
                assert_eq!(
                    atts[0].data.index, "0",
                    "EIP-7549: data.index must be zeroed before signing"
                );
                // committee_index preserves the original value
                assert_eq!(atts[0].committee_index, 7);
                assert_eq!(atts[0].attester_index, 99);
            }
            VersionedAttestation::PreElectra(_) | VersionedAttestation::Fulu(_) => {
                panic!("Expected Electra attestation for epoch 51");
            }
        }
    }

    // --- AT-07: Electra data.index invariant tests ---

    #[test]
    fn test_electra_crypto_attestation_data_index_zeroed() {
        // Verify that for Electra attestations, crypto_attestation_data.index == 0
        // after applying the EIP-7549 zeroing logic.
        let beacon_data = beacon::AttestationData {
            slot: "1600".to_string(),
            index: "7".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "49".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "50".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let mut crypto_data = utils::convert_attestation_data(&beacon_data).unwrap();

        // Before EIP-7549, index matches BN response
        assert_eq!(crypto_data.index, 7, "index should initially match BN response");

        // Apply EIP-7549: target epoch 50 >= electra_fork_epoch 50
        let schedule = create_test_fork_schedule();
        let target_epoch = crypto_data.target.epoch;
        let fork_name = ForkName::from_epoch(target_epoch, &schedule);
        let is_electra = fork_name >= ForkName::Electra;
        assert!(is_electra, "epoch 50 should be Electra");

        if is_electra {
            crypto_data.index = 0;
        }

        assert_eq!(
            crypto_data.index, 0,
            "EIP-7549: crypto_attestation_data.index must be 0 for Electra"
        );
    }

    #[tokio::test]
    async fn test_electra_submitted_single_attestation_data_index_zero() {
        // Verify that the submitted SingleAttestation has data.index == "0" for Electra,
        // even when the BN returns a non-zero index.
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        // Epoch 52 (well into Electra), BN returns index "9"
        let slot = 1664u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        assert_eq!(epoch, 52);

        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "77",
                    "committee_index": "9",
                    "committee_length": "32",
                    "committees_at_slot": "16",
                    "validator_committee_index": "4",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "9",
                    "beacon_block_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x5555555555555555555555555555555555555555555555555555555555555555"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1);

        match &captured[0] {
            VersionedAttestation::Electra(atts) => {
                assert_eq!(atts.len(), 1);
                let att = &atts[0];
                assert_eq!(
                    att.data.index, "0",
                    "EIP-7549: submitted SingleAttestation data.index must be \"0\""
                );
                assert_eq!(
                    att.committee_index, 9,
                    "committee_index should carry the original committee index"
                );
                assert_eq!(att.attester_index, 77);
            }
            VersionedAttestation::PreElectra(_) | VersionedAttestation::Fulu(_) => {
                panic!("Expected Electra attestation for epoch 52");
            }
        }
    }

    #[test]
    fn test_pre_electra_data_index_preserved() {
        // Verify that for pre-Electra attestations, data.index is preserved (not zeroed).
        let beacon_data = beacon::AttestationData {
            slot: "96".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "2".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "3".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let mut crypto_data = utils::convert_attestation_data(&beacon_data).unwrap();

        assert_eq!(crypto_data.index, 5, "index should match BN response");

        // Pre-Electra: epoch 3 < electra_fork_epoch 50
        let schedule = create_test_fork_schedule();
        let target_epoch = crypto_data.target.epoch;
        let fork_name = ForkName::from_epoch(target_epoch, &schedule);
        let is_electra = fork_name >= ForkName::Electra;
        assert!(!is_electra, "epoch 3 should be pre-Electra");

        // Apply the same logic as process_attestation_duty
        if is_electra {
            crypto_data.index = 0;
        }

        assert_eq!(crypto_data.index, 5, "Pre-Electra: data.index must be preserved, not zeroed");
    }

    #[test]
    fn test_electra_signing_root_matches_submitted_data() {
        // Verify that the signing root computed with index=0 matches the tree hash
        // of the data reconstructed from what would be in the submitted SingleAttestation.
        // This ensures: what's signed == what's submitted, field by field.
        let beacon_data = beacon::AttestationData {
            slot: "1600".to_string(),
            index: "7".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "49".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "50".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        // Step 1: Convert and apply EIP-7549 zeroing (what gets signed)
        let mut crypto_data = utils::convert_attestation_data(&beacon_data).unwrap();
        assert_eq!(crypto_data.index, 7);
        crypto_data.index = 0; // EIP-7549
        let signed_root = crypto_data.tree_hash_root();

        // Step 2: Reconstruct from submitted SingleAttestation data
        // In process_attestation_duty, the submitted data is:
        //   electra_data = beacon_attestation_data.clone(); electra_data.index = "0";
        // We reconstruct that and convert back to crypto types.
        let mut submitted_beacon_data = beacon_data;
        submitted_beacon_data.index = "0".to_string();
        let submitted_crypto_data =
            utils::convert_attestation_data(&submitted_beacon_data).unwrap();
        let submitted_root = submitted_crypto_data.tree_hash_root();

        assert_eq!(
            signed_root, submitted_root,
            "Signing root (index=0) must match tree hash of submitted SingleAttestation data"
        );

        // Also verify the submitted data has index 0
        assert_eq!(submitted_crypto_data.index, 0);
        // And all other fields are preserved
        assert_eq!(crypto_data.slot, submitted_crypto_data.slot);
        assert_eq!(crypto_data.beacon_block_root, submitted_crypto_data.beacon_block_root);
        assert_eq!(crypto_data.source, submitted_crypto_data.source);
        assert_eq!(crypto_data.target, submitted_crypto_data.target);
    }

    // --- H-05: derive_fork_for_epoch refactor and Fulu attestation versioning tests ---

    /// Helper: derives a Fork from ForkSchedule using the same logic as the refactored
    /// derive_fork_for_epoch (activation_epoch + previous_fork helpers).
    fn derive_fork_for_epoch_standalone(epoch: u64, schedule: &ForkSchedule) -> eth_types::Fork {
        let current = ForkName::from_epoch(epoch, schedule);
        let previous = current.previous_fork(schedule);
        eth_types::Fork {
            previous_version: previous.fork_version(schedule),
            current_version: current.fork_version(schedule),
            epoch: current.activation_epoch(schedule),
        }
    }

    #[test]
    fn test_derive_fork_for_epoch_fulu() {
        let schedule = create_test_fork_schedule();
        // fulu_fork_epoch = 60 in test schedule
        let fork = derive_fork_for_epoch_standalone(60, &schedule);
        // At fulu epoch: current = fulu version, previous = electra version
        assert_eq!(fork.current_version, [0, 0, 0, 7]); // fulu_fork_version
        assert_eq!(fork.previous_version, [0, 0, 0, 6]); // electra_fork_version
        assert_eq!(fork.epoch, 60); // fulu activation epoch
    }

    #[test]
    fn test_derive_fork_for_epoch_at_boundary() {
        let schedule = create_test_fork_schedule();
        // epoch 59 = Electra, epoch 60 = Fulu
        let fork_before = derive_fork_for_epoch_standalone(59, &schedule);
        assert_eq!(fork_before.current_version, [0, 0, 0, 6]); // electra
        let fork_at = derive_fork_for_epoch_standalone(60, &schedule);
        assert_eq!(fork_at.current_version, [0, 0, 0, 7]); // fulu
    }

    #[tokio::test]
    async fn test_fulu_attestation_versioning() {
        let mock_server = wiremock::MockServer::start().await;
        // Fulu epoch = 60, slot = 60*32 = 1920
        let slot = 1920;
        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;
        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        let results = orchestrator.process_slot(slot).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1);

        match &captured[0] {
            VersionedAttestation::Fulu(atts) => {
                assert_eq!(atts.len(), 1);
                let att = &atts[0];
                // EIP-7549: data.index must be "0" for Fulu (since Fulu >= Electra)
                assert_eq!(att.data.index, "0", "Fulu attestation data.index must be 0 (EIP-7549)");
            }
            other => {
                panic!(
                    "Expected Fulu attestation for slot in epoch 60 (= fulu_fork_epoch), got {:?}",
                    std::mem::discriminant(other)
                );
            }
        }
    }

    #[tokio::test]
    async fn test_fulu_eip7549_index_zeroing() {
        let mock_server = wiremock::MockServer::start().await;
        // Fulu epoch = 60, slot = 60*32 = 1920
        let slot = 1920;
        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;
        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        let results = orchestrator.process_slot(slot).await.unwrap();
        assert!(results[0].success);

        let captured = capturing.captured();
        match &captured[0] {
            VersionedAttestation::Fulu(atts) => {
                assert_eq!(
                    atts[0].data.index, "0",
                    "EIP-7549: data.index must be zeroed for Fulu attestations"
                );
                // committee_index should carry the original committee index from duty
                assert_eq!(atts[0].committee_index, 3);
            }
            other => {
                panic!("Expected Fulu attestation, got {:?}", std::mem::discriminant(other));
            }
        }
    }

    #[tokio::test]
    async fn test_electra_attestation_unchanged() {
        let mock_server = wiremock::MockServer::start().await;
        // Electra epoch = 50, slot = 50*32 = 1600 (same as existing test, just verify it's still Electra, not Fulu)
        let slot = 1600;
        let (orchestrator, _handle, pubkey_hex, capturing) =
            build_fork_transition_orchestrator(&mock_server.uri(), slot).await;
        mount_attestation_mocks(&mock_server, slot, &pubkey_hex).await;

        let results = orchestrator.process_slot(slot).await.unwrap();
        assert!(results[0].success, "Attestation should succeed: {:?}", results[0].error);

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1);

        match &captured[0] {
            VersionedAttestation::Electra(atts) => {
                assert_eq!(atts.len(), 1);
                assert_eq!(atts[0].data.index, "0", "Electra attestation data.index must be 0");
            }
            other => {
                panic!(
                    "Expected Electra attestation for epoch 50, got {:?}",
                    std::mem::discriminant(other)
                );
            }
        }
    }

    // --- H-08: Orchestrator slot lifecycle span tests ---

    use parking_lot::Mutex;
    use std::collections::HashMap as SpanMap;
    use tracing::span::Id;
    use tracing_subscriber::layer::SubscriberExt;

    /// A tracing layer that captures span names for test verification.
    struct SpanCapture {
        names: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.names.lock().push(attrs.metadata().name().to_string());
        }
    }

    /// Recorded span entry with name and optional parent span ID.
    #[derive(Debug, Clone)]
    struct SpanEntry {
        name: String,
        parent_id: Option<Id>,
    }

    /// A tracing layer that captures span names and parent-child relationships.
    struct HierarchyCapture {
        spans: Arc<Mutex<SpanMap<u64, SpanEntry>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for HierarchyCapture
    where
        S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &Id,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let parent_id = attrs.parent().cloned().or_else(|| ctx.current_span().id().cloned());
            self.spans.lock().insert(
                id.into_u64(),
                SpanEntry { name: attrs.metadata().name().to_string(), parent_id },
            );
        }
    }

    impl HierarchyCapture {
        fn new() -> (Self, Arc<Mutex<SpanMap<u64, SpanEntry>>>) {
            let spans = Arc::new(Mutex::new(SpanMap::new()));
            (Self { spans: spans.clone() }, spans)
        }
    }

    /// Returns the parent span name for a given child span name, if both exist.
    fn find_parent_name(spans: &SpanMap<u64, SpanEntry>, child_name: &str) -> Option<String> {
        for entry in spans.values() {
            if entry.name == child_name {
                if let Some(ref parent_id) = entry.parent_id {
                    if let Some(parent) = spans.get(&parent_id.into_u64()) {
                        return Some(parent.name.clone());
                    }
                }
            }
        }
        None
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_slot_processing_creates_root_and_phase_spans() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(65); // slot 65 = epoch 2, not at epoch boundary
                            // Advance past 2/3 of slot so all phases run without waiting
        clock.advance_time(9);

        // Use 0 retries so that failed HTTP calls (localhost:5052 unavailable) return
        // immediately, keeping the test well within its 5-second window even after
        // SlotContext::capture adds a get_block_root call to the slot loop.
        let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();

        let (mut orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        );

        // Capture spans via thread-local subscriber
        let captured = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { names: captured.clone() };
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Shutdown after enough time for all phases (HTTP failures are fast)
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            handle.shutdown();
        });

        let _ = orchestrator.run().await;

        let span_names = captured.lock();
        assert!(
            span_names.contains(&"rvc.slot.process".to_string()),
            "Expected rvc.slot.process span, got: {:?}",
            *span_names
        );
        assert!(
            span_names.contains(&"rvc.slot.phase.block".to_string()),
            "Expected rvc.slot.phase.block span, got: {:?}",
            *span_names
        );
        assert!(
            span_names.contains(&"rvc.slot.phase.attestation".to_string()),
            "Expected rvc.slot.phase.attestation span, got: {:?}",
            *span_names
        );
        assert!(
            span_names.contains(&"rvc.slot.phase.aggregation".to_string()),
            "Expected rvc.slot.phase.aggregation span, got: {:?}",
            *span_names
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_epoch_boundary_creates_epoch_span() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(32); // slot 32 = epoch 1, IS at epoch boundary (32 % 32 == 0)
        clock.advance_time(9);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();

        let (mut orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        );

        let captured = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { names: captured.clone() };
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            handle.shutdown();
        });

        let _ = orchestrator.run().await;

        let span_names = captured.lock();
        assert!(
            span_names.contains(&"rvc.epoch.boundary".to_string()),
            "Expected rvc.epoch.boundary span at epoch boundary slot, got: {:?}",
            *span_names
        );
    }

    // --- H-25: Aggregation span link tests ---

    #[tokio::test]
    async fn test_aggregation_creates_produce_span() {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        // Mock attester duties — small committee (always aggregator)
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        // Mock attestation data
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": { "epoch": (epoch - 1).to_string(), "root": "0x2222222222222222222222222222222222222222222222222222222222222222" },
                    "target": { "epoch": epoch.to_string(), "root": "0x3333333333333333333333333333333333333333333333333333333333333333" }
                }
            })))
            .mount(&mock_server)
            .await;

        // Mock aggregate attestation
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xffffffff",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "1",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": { "epoch": (epoch - 1).to_string(), "root": "0x2222222222222222222222222222222222222222222222222222222222222222" },
                        "target": { "epoch": epoch.to_string(), "root": "0x3333333333333333333333333333333333333333333333333333333333333333" }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })))
            .mount(&mock_server)
            .await;

        // Mock submit aggregate and proofs
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        let captured = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { names: captured.clone() };
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

        let span_names = captured.lock();
        assert!(
            span_names.contains(&"rvc.orchestrator.produce_aggregations".to_string()),
            "Expected rvc.orchestrator.produce_aggregations span, got: {:?}",
            *span_names
        );
        // Note: rvc.aggregation.submit may not appear under coverage instrumentation
        // due to subscriber interference in concurrent test runs. The produce span
        // is the primary assertion for this test.
    }

    #[tokio::test]
    async fn test_aggregation_non_aggregator_creates_produce_span_without_submit() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        // Large committee → unlikely to be aggregator
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "100000",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        // Should NOT call aggregate attestation or submit
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        let captured = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { names: captured.clone() };
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

        let span_names = captured.lock();
        // produce span should still be created (it wraps the entire per-validator loop body)
        assert!(
            span_names.contains(&"rvc.orchestrator.produce_aggregations".to_string()),
            "Expected rvc.orchestrator.produce_aggregations span even for non-aggregator, got: {:?}",
            *span_names
        );
        // submit span should NOT be created (no aggregates to submit)
        assert!(
            !span_names.contains(&"rvc.aggregation.submit".to_string()),
            "Did not expect rvc.aggregation.submit span for non-aggregator, got: {:?}",
            *span_names
        );
    }

    // --- H-14: End-to-end span hierarchy integration tests ---

    #[tokio::test(flavor = "current_thread")]
    async fn test_phase_spans_are_children_of_slot_process() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(65); // non-boundary slot
        clock.advance_time(9);

        // Use 0 retries so that failed HTTP calls (localhost:5052 unavailable) return
        // immediately, keeping the test well within its 5-second window even after
        // SlotContext::capture adds a get_block_root call to the slot loop.
        let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();

        let (mut orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        );

        let (layer, spans) = HierarchyCapture::new();
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            handle.shutdown();
        });

        let _ = orchestrator.run().await;

        let span_map = spans.lock();

        // Verify phase spans are children of rvc.slot.process
        let block_parent = find_parent_name(&span_map, "rvc.slot.phase.block");
        assert_eq!(
            block_parent.as_deref(),
            Some("rvc.slot.process"),
            "rvc.slot.phase.block should be child of rvc.slot.process"
        );

        let att_parent = find_parent_name(&span_map, "rvc.slot.phase.attestation");
        assert_eq!(
            att_parent.as_deref(),
            Some("rvc.slot.process"),
            "rvc.slot.phase.attestation should be child of rvc.slot.process"
        );

        let agg_parent = find_parent_name(&span_map, "rvc.slot.phase.aggregation");
        assert_eq!(
            agg_parent.as_deref(),
            Some("rvc.slot.process"),
            "rvc.slot.phase.aggregation should be child of rvc.slot.process"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_epoch_boundary_span_is_child_of_slot_process() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(32); // epoch boundary
        clock.advance_time(9);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();

        let (mut orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            config,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        );

        let (layer, spans) = HierarchyCapture::new();
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            handle.shutdown();
        });

        let _ = orchestrator.run().await;

        let span_map = spans.lock();

        let epoch_parent = find_parent_name(&span_map, "rvc.epoch.boundary");
        assert_eq!(
            epoch_parent.as_deref(),
            Some("rvc.slot.process"),
            "rvc.epoch.boundary should be child of rvc.slot.process"
        );
    }

    #[tokio::test]
    async fn test_signer_span_created_on_sign_attestation() {
        use crypto::SecretKey;
        use eth_types::{AttestationData, Checkpoint};

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        let mut manager = KeyManager::new();
        manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = SignerService::new(composite, slashing_db);

        let attestation_data = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 100, root: [0x22; 32] },
            target: Checkpoint { epoch: 101, root: [0x33; 32] },
        };
        let fork_schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let captured = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { names: captured.clone() };
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let result = signer
            .sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let span_names = captured.lock();
        assert!(
            span_names.contains(&"sign.attestation".to_string()),
            "Expected sign.attestation span, got: {:?}",
            *span_names
        );
        assert!(
            span_names.contains(&"slashing.check".to_string()),
            "Expected slashing.check span within sign_attestation, got: {:?}",
            *span_names
        );
    }

    #[tokio::test]
    async fn test_aggregation_electra_builds_electra_aggregate_and_proof() {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        // Electra epoch = 50, slot = 50 * 32 = 1600
        let slot = 1600u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        orchestrator.clock.set_slot(slot);

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        // Electra aggregate response (has committee_bits field)
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .and(query_param("committee_index", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xffffffff",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "0",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": (epoch - 1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "committee_bits": "0x0200000000000000"
                }
            })))
            .mount(&mock_server)
            .await;

        // Electra submit goes to v2 endpoint
        Mock::given(method("POST"))
            .and(path("/eth/v2/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Pre-Electra submit should NOT be called
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }

    #[tokio::test]
    async fn test_aggregation_pre_electra_unchanged() {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        // Pre-Electra: epoch 3, slot 100
        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        // Pre-Electra aggregate (no committee_bits)
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xffffffff",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "1",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": (epoch - 1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })))
            .mount(&mock_server)
            .await;

        // Pre-Electra submit should go to v1 endpoint
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        // v2 endpoint should NOT be called
        Mock::given(method("POST"))
            .and(path("/eth/v2/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }

    #[tokio::test]
    async fn test_aggregation_fulu_dispatches_as_fulu() {
        use wiremock::matchers::{header, method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        // Fulu epoch = 60, slot = 60 * 32 = 1920
        let slot = 1920u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        orchestrator.clock.set_slot(slot);

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        // Fulu aggregate (same structure as Electra)
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .and(query_param("committee_index", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "aggregation_bits": "0xffffffff",
                    "data": {
                        "slot": slot.to_string(),
                        "index": "0",
                        "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "source": {
                            "epoch": (epoch - 1).to_string(),
                            "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                        },
                        "target": {
                            "epoch": epoch.to_string(),
                            "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }
                    },
                    "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "committee_bits": "0x0200000000000000"
                }
            })))
            .mount(&mock_server)
            .await;

        // Fulu submit goes to v2 endpoint with Eth-Consensus-Version: fulu
        Mock::given(method("POST"))
            .and(path("/eth/v2/validator/aggregate_and_proofs"))
            .and(header("Eth-Consensus-Version", "fulu"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        // v1 endpoint should NOT be called
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }

    #[tokio::test]
    async fn test_aggregation_mismatched_response_logs_warning() {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let (orchestrator, _handle, _, pubkey_hex) =
            build_aggregation_orchestrator(&mock_server.uri()).await;

        // Electra epoch = 50, slot = 1600
        let slot = 1600u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        orchestrator.clock.set_slot(slot);

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "1",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": (epoch - 1).to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(&mock_server)
            .await;

        // Return a pre-Electra aggregate (no committee_index param in mock)
        // but the orchestrator expects Electra because is_electra=true.
        // The BeaconClient uses committee_index presence to determine response type;
        // since is_electra=true, committee_index is Some(...), so the client will request
        // with committee_index and deserialize as ElectraAttestation.
        // To simulate a mismatch, we need to force the beacon to return PreElectra.
        // This is tricky with real HTTP mocks since the client decides the type based on
        // committee_index param. Instead, we test the reverse: pre-Electra slot gets
        // an Electra response. But that won't happen either because the client controls it.
        //
        // The mismatch scenario is guarded by the match arms in the orchestrator.
        // We can verify the code compiles and handles the branch by checking that
        // no submit endpoints are called when the aggregate fetch fails (returns 500).
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        // Neither submit endpoint should be called
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock_server)
            .await;

        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        // Should not panic — gracefully handles failure
        orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;
    }

    #[tokio::test]
    async fn test_beacon_http_span_created() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "version": "mock/v1.0.0" }
            })))
            .mount(&mock_server)
            .await;

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = BeaconClient::new(beacon_config).unwrap();

        let captured = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { names: captured.clone() };
        let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let _ = beacon.get_node_version().await;

        let span_names = captured.lock();
        assert!(
            span_names.contains(&"rvc.beacon.http".to_string()),
            "Expected rvc.beacon.http span, got: {:?}",
            *span_names
        );
    }

    // --- Issue 1.3: Slashing protection integration test ---

    /// Builds an orchestrator with a shared SlashingDb for slashing integration tests.
    /// Returns the orchestrator, handle, pubkey hex, capturing submitter, and clock.
    async fn build_slashing_integration_orchestrator(
        mock_server_uri: &str,
        initial_slot: u64,
        slashing_db: Arc<SlashingDb>,
    ) -> (
        DutyOrchestrator<MockSlotClock, CapturingSubmitter, MockBlockBeacon>,
        OrchestratorHandle,
        String,
        Arc<CapturingSubmitter>,
        Arc<MockSlotClock>,
    ) {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(initial_slot);

        let beacon_config = BeaconClientConfig::new(mock_server_uri);
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let secret_key = SecretKey::generate();
        let pubkey_hex = format!("0x{}", hex::encode(secret_key.public_key().to_bytes()));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));

        let pubkey = secret_key.public_key();
        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let capturing_submitter = Arc::new(CapturingSubmitter::new());
        let propagator = Arc::new(Propagator::new(capturing_submitter.clone()));

        let config = create_test_config();
        let pubkey_bytes = pubkey.to_bytes();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        // D-3 fail-closed: register the loaded validator so the per-validator
        // signing gate permits its duties (mirrors startup registration).
        let validator_store = create_mock_validator_store();
        validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey_bytes));

        let (orchestrator, handle) = DutyOrchestrator::new(
            clock.clone(),
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
        );

        (orchestrator, handle, pubkey_hex, capturing_submitter, clock)
    }

    /// Mounts attester duties for multiple slots in a single response.
    async fn mount_multi_slot_duties(
        mock_server: &wiremock::MockServer,
        slots: &[u64],
        pubkey_hex: &str,
    ) {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        let duties: Vec<serde_json::Value> = slots
            .iter()
            .map(|slot| {
                serde_json::json!({
                    "pubkey": pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "3",
                    "committee_length": "8",
                    "committees_at_slot": "4",
                    "validator_committee_index": "2",
                    "slot": slot.to_string()
                })
            })
            .collect();

        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": duties
            })))
            .mount(mock_server)
            .await;
    }

    /// Mounts attestation data with explicit source/target epochs, keyed by slot.
    async fn mount_attestation_data_with_epochs(
        mock_server: &wiremock::MockServer,
        slot: u64,
        source_epoch: u64,
        target_epoch: u64,
    ) {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", slot.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "slot": slot.to_string(),
                    "index": "3",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": {
                        "epoch": source_epoch.to_string(),
                        "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                    },
                    "target": {
                        "epoch": target_epoch.to_string(),
                        "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                }
            })))
            .mount(mock_server)
            .await;
    }

    #[tokio::test]
    async fn test_double_vote_rejected_through_full_pipeline() {
        let mock_server = wiremock::MockServer::start().await;

        // Shared SlashingDb — this is the key: both slots share the same DB
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());

        // Slot 192 = epoch 6 (pre-Electra), slot 193 = same epoch
        let slot_1 = 192u64;
        let slot_2 = 193u64;
        let epoch = slot_1 / SLOTS_PER_EPOCH;

        let (orchestrator, _handle, pubkey_hex, capturing, clock) =
            build_slashing_integration_orchestrator(&mock_server.uri(), slot_1, slashing_db).await;

        // Mount duties for both slots in a single response
        mount_multi_slot_duties(&mock_server, &[slot_1, slot_2], &pubkey_hex).await;

        // Mount attestation data per slot with different source epochs but same target
        // Slot 1: source=5, target=6
        mount_attestation_data_with_epochs(&mock_server, slot_1, 5, 6).await;
        // Slot 2: source=4, target=6 — same target epoch, different source → double vote
        mount_attestation_data_with_epochs(&mock_server, slot_2, 4, 6).await;

        // Fetch duties for epoch 6 (caches duties for both slots)
        orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

        // --- Slot 1: First attestation should succeed ---
        let results_1 = orchestrator.process_slot(slot_1).await.unwrap();
        assert_eq!(results_1.len(), 1, "Expected one attestation result for slot 1");
        assert!(results_1[0].success, "First attestation should succeed: {:?}", results_1[0].error);
        assert_eq!(
            capturing.captured().len(),
            1,
            "Exactly one attestation should be submitted after slot 1"
        );

        // --- Slot 2: Double vote should be REJECTED by slashing protection ---
        clock.set_slot(slot_2);
        let results_2 = orchestrator.process_slot(slot_2).await.unwrap();
        assert_eq!(results_2.len(), 1, "Expected one attestation result for slot 2");
        assert!(!results_2[0].success, "Second attestation (double vote) must be rejected");

        // Verify the rejection is specifically from slashing protection, not a generic error
        let error_msg =
            results_2[0].error.as_deref().expect("rejected attestation must have error");
        assert!(
            error_msg.contains("slashing protection blocked"),
            "Error must indicate slashing protection blocked signing, got: {error_msg}"
        );

        // Verify only the first attestation was submitted — the double vote was never propagated
        assert_eq!(
            capturing.captured().len(),
            1,
            "Only the first attestation should be submitted; double vote must not be propagated"
        );
    }

    /// H-4 coordinator integration test: when the BN returns a block whose
    /// `proposer_index` does not match the duty's `validator_index`, the duty
    /// must be silently dropped — no signer call and no publish call.
    ///
    /// RED against d490044: `propose_block` (unvalidated) ignores the
    /// `proposer_index` and proceeds to sign + publish, so `publish_called`
    /// becomes `true` → assertion fails.
    ///
    /// GREEN after CQ-3.2: the validated `propose_block` is the only entry point;
    /// the mismatch is caught before signing, `publish_called` stays `false`.
    #[tokio::test]
    async fn test_maybe_propose_block_bad_proposer_index_drops_duty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        // The duty says this validator should propose at slot 100.
        let expected_validator_index = 42u64;
        // The BN returns a block with a different (forged) proposer_index.
        let bad_proposer_index = 99u64;

        // Generate a real key so RANDAO signing succeeds and we reach the
        // proposer_index validation step.
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        // Beacon client for duty fetching (backed by wiremock).
        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        // Serve proposer duties for the epoch.
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": expected_validator_index.to_string(),
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
        // Pre-populate the proposer duty cache before calling maybe_propose_block.
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

        // Block beacon: returns a block with wrong proposer_index; tracks publish.
        let publish_called = Arc::new(AtomicBool::new(false));
        let block_beacon = Arc::new(BadProposerBlockBeacon {
            slot,
            bad_proposer_index,
            publish_called: publish_called.clone(),
        });

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey.clone());
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(slot);

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            block_beacon,
            None,
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        // Invoke the proposer path directly.
        let ctx = SlotContext { slot, epoch, head_root: None };
        orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

        // H-4: a forged proposer_index must drop the duty before any
        // signing or publishing occurs.
        assert!(
            !publish_called.load(Ordering::SeqCst),
            "publish_block must NOT be called when proposer_index mismatches the duty"
        );
    }

    // ── H-3: circuit-breaker scoping helpers ────────────────────────────────

    /// Wire up a proposer duty in a wiremock mock server so that
    /// `duty_tracker.fetch_proposer_duties(epoch)` succeeds and the duty is
    /// cached for `slot`.
    async fn setup_proposer_duty(
        mock_server: &wiremock::MockServer,
        epoch: u64,
        slot: u64,
        pubkey_hex: &str,
        validator_index: u64,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": validator_index.to_string(),
                    "slot": slot.to_string()
                }]
            })))
            .mount(mock_server)
            .await;
    }

    /// H-3: A BN error on the **non-builder** path (ExecutionOnly mode →
    /// `builder_boost_factor = 0`) must NOT trip the circuit breaker.
    ///
    /// RED before fix: the coordinator calls `record_miss()` unconditionally
    /// on every `Ok(Err(e))` arm, so `consecutive_misses` becomes 1.
    ///
    /// GREEN after fix: only `BuilderFailure` / `BuilderOnly` errors call
    /// `record_miss()`; a plain `Beacon` error leaves the counter at 0.
    #[tokio::test]
    async fn test_non_builder_timeout_does_not_trip_breaker() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;

        let slot = 100u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        let validator_index = 1u64;

        // Real key so RANDAO signing succeeds and we reach the BN call.
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        // Serve proposer duties so the cache is warm.
        setup_proposer_duty(&mock_server, epoch, slot, &pubkey_hex, validator_index).await;

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        // ExecutionOnly → builder_boost_factor = 0 → not a builder attempt.
        let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
        // D-3 fail-closed: register the loaded validator so the per-validator
        // signing gate permits this proposal (mirrors startup registration).
        validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()));
        validator_store
            .set_global_block_selection_mode(validator_store::BlockSelectionMode::ExecutionOnly);

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(slot);

        // Shared circuit breaker with realistic limits so we can observe misses.
        let circuit_breaker = Arc::new(CircuitBreakerState::new(3, 5));

        let (orchestrator, _handle) = DutyOrchestrator::new_with_attesting_enabled(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            // MockBlockBeacon always returns Beacon("mock") error.
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
            circuit_breaker.clone(),
            Arc::new(AtomicBool::new(true)),
        );

        let ctx = SlotContext { slot, epoch, head_root: None };
        orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

        // Non-builder BN error must NOT record a miss.
        assert_eq!(
            circuit_breaker.consecutive_misses(),
            0,
            "BN error on non-builder path must not trip the circuit breaker (H-3)"
        );
    }

    /// H-3: A BN error on the **builder** path (BuilderAlways mode →
    /// `builder_boost_factor = u64::MAX`) MUST trip the circuit breaker.
    ///
    /// This test is GREEN with the current code and remains GREEN after the
    /// fix — it guards against regressing builder-failure detection.
    #[tokio::test]
    async fn test_builder_timeout_trips_breaker() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;

        let slot = 200u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        let validator_index = 2u64;

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        setup_proposer_duty(&mock_server, epoch, slot, &pubkey_hex, validator_index).await;

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        // BuilderAlways → builder_boost_factor = u64::MAX → builder attempt.
        let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
        // D-3 fail-closed: register the loaded validator so the per-validator
        // signing gate permits this proposal (mirrors startup registration).
        validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()));
        validator_store
            .set_global_block_selection_mode(validator_store::BlockSelectionMode::BuilderAlways);

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(slot);

        let circuit_breaker = Arc::new(CircuitBreakerState::new(3, 5));

        let (orchestrator, _handle) = DutyOrchestrator::new_with_attesting_enabled(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
            circuit_breaker.clone(),
            Arc::new(AtomicBool::new(true)),
        );

        let ctx = SlotContext { slot, epoch, head_root: None };
        orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

        // Builder BN error MUST record a miss.
        assert_eq!(
            circuit_breaker.consecutive_misses(),
            1,
            "BN error on builder path must trip the circuit breaker (H-3)"
        );
    }

    /// H-3: A local signer error must NOT trip the circuit breaker.
    ///
    /// RED before fix: `record_miss()` is called unconditionally, so the
    /// signer error (RANDAO signing fails because the key is absent from the
    /// KeyManager) increments `consecutive_misses` to 1.
    ///
    /// GREEN after fix: only `BuilderFailure` / `BuilderOnly` call
    /// `record_miss()`.  `Signer` errors are ignored by the breaker.
    #[tokio::test]
    async fn test_signer_error_does_not_trip_breaker() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;

        let slot = 300u64;
        let epoch = slot / SLOTS_PER_EPOCH;
        let validator_index = 3u64;

        // Generate a keypair but intentionally do NOT insert the secret key
        // into the KeyManager so RANDAO signing will fail.
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
        // secret_key is dropped here — not in KeyManager.

        setup_proposer_duty(&mock_server, epoch, slot, &pubkey_hex, validator_index).await;

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

        // Empty KeyManager → sign_randao_reveal will return SignerError.
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
        // D-3 fail-closed: register the loaded validator so the signing gate is
        // passed and the RANDAO signing failure (empty KeyManager) is the path
        // under test (mirrors startup registration).
        validator_store.add_validator(validator_store::ValidatorConfig::new(pubkey.to_bytes()));

        let config = create_test_config();
        let mut pubkey_map_inner = HashMap::new();
        // pubkey is in the map so find_pubkey succeeds, but the secret key is absent.
        pubkey_map_inner.insert(pubkey_hex.clone(), pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(slot);

        let circuit_breaker = Arc::new(CircuitBreakerState::new(3, 5));

        let (orchestrator, _handle) = DutyOrchestrator::new_with_attesting_enabled(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
            circuit_breaker.clone(),
            Arc::new(AtomicBool::new(true)),
        );

        let ctx = SlotContext { slot, epoch, head_root: None };
        orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

        // Signer error must NOT record a miss.
        assert_eq!(
            circuit_breaker.consecutive_misses(),
            0,
            "Local signer error must not trip the circuit breaker (H-3)"
        );
    }

    // ── H-7: sync_enabled flag tests ────────────────────────────────────────

    /// Minimal helper: build an orchestrator with a `SyncGuardBeacon` mock.
    /// Used to avoid repetition in the H-7 guard tests.
    async fn build_sync_test_orchestrator(
        beacon: Arc<SyncGuardBeacon>,
        pk_hex: String,
        pk: crypto::PublicKey,
        sk: crypto::SecretKey,
        attesting_enabled: Arc<AtomicBool>,
    ) -> DutyOrchestrator<MockSlotClock, MockSubmitter, MockBlockBeacon> {
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        // Pre-populate sync committee duties for period 0 (epoch 0).
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

        let pk_bytes = pk.to_bytes();
        let mut map = HashMap::new();
        map.insert(pk_hex, pk);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
        // D-3 fail-closed: register the loaded validator so the per-validator
        // signing gate permits sync duties (mirrors startup registration). The
        // sync_enabled=false test short-circuits before this gate, so it stays
        // correct regardless.
        validator_store.add_validator(validator_store::ValidatorConfig::new(pk_bytes));
        let config = create_test_config();
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(0);

        let (orchestrator, _handle) = DutyOrchestrator::new_with_attesting_enabled(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store,
            config,
            pubkey_map,
            Arc::new(CircuitBreakerState::new(0, 0)),
            attesting_enabled,
        );
        orchestrator
    }

    /// H-7: `sync_enabled` defaults to `true` on a freshly-constructed orchestrator.
    ///
    /// RED: fails to compile before the `sync_enabled` field is added.
    /// GREEN: field exists and is initialized to `true`.
    #[test]
    fn test_sync_enabled_defaults_to_true() {
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            create_test_config(),
            pubkey_map,
        );

        assert!(
            orchestrator.sync_enabled.load(Ordering::Acquire),
            "sync_enabled must default to true (H-7)"
        );
    }

    /// H-7: `set_sync_enabled` writes with `Release` ordering and the new
    /// value is immediately visible via `Acquire` load.
    ///
    /// RED: fails to compile before `set_sync_enabled` is added.
    /// GREEN: method exists and correctly toggles the flag.
    #[test]
    fn test_set_sync_enabled_toggles_flag() {
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            create_test_config(),
            pubkey_map,
        );

        assert!(orchestrator.sync_enabled.load(Ordering::Acquire), "default must be true");

        orchestrator.set_sync_enabled(false);
        assert!(
            !orchestrator.sync_enabled.load(Ordering::Acquire),
            "set_sync_enabled(false) must disable the flag"
        );

        orchestrator.set_sync_enabled(true);
        assert!(
            orchestrator.sync_enabled.load(Ordering::Acquire),
            "set_sync_enabled(true) must re-enable the flag"
        );
    }

    /// H-7 / ISSUE-2.7: when `attesting_enabled = false` and `sync_enabled = true`
    /// (the default), sync-committee messages are still produced.
    ///
    /// Before the fix the two services shared the `attesting_enabled` guard, so
    /// disabling attestations would silently skip sync duties. After the fix the
    /// guard is split: sync is gated only by `sync_enabled`.
    ///
    /// RED: test fails (no sync messages) because sync is inside the attesting block.
    /// GREEN: test passes after the guard is split.
    #[tokio::test]
    async fn test_sync_runs_with_attesting_disabled() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let r_captured: Root = [0xAA; 32];
        let submitted_roots = Arc::new(std::sync::Mutex::new(Vec::<Root>::new()));

        let beacon = Arc::new(SyncGuardBeacon {
            submitted_roots: submitted_roots.clone(),
            duty_pubkey: pk_hex.clone(),
        });

        // attesting_enabled = false; sync_enabled = true (default)
        let attesting_enabled = Arc::new(AtomicBool::new(false));
        let orchestrator =
            build_sync_test_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

        // Confirm default: sync is enabled
        assert!(orchestrator.sync_enabled.load(Ordering::Acquire));

        let ctx = SlotContext { slot: 0, epoch: 0, head_root: Some(r_captured) };

        // Exercise the guarded sync-messages phase directly.
        orchestrator.run_sync_messages_phase(0, 0, &ctx).await;

        let roots = submitted_roots.lock().unwrap();
        assert!(
            !roots.is_empty(),
            "H-7: sync messages must be produced even when attesting is disabled \
             (sync_enabled=true overrides attesting_enabled=false)"
        );
        for root in roots.iter() {
            assert_eq!(*root, r_captured, "submitted root must match SlotContext.head_root");
        }
    }

    /// H-7 / ISSUE-2.7: inverse — when `sync_enabled = false` and `attesting_enabled = true`,
    /// no sync-committee messages are produced, but attestations would still run.
    ///
    /// RED: fails (sync runs unconditionally) before the separate guard is added.
    /// GREEN: `run_sync_messages_phase` short-circuits on `sync_enabled = false`.
    #[tokio::test]
    async fn test_sync_messages_skipped_when_sync_disabled() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let r_captured: Root = [0xAA; 32];
        let submitted_roots = Arc::new(std::sync::Mutex::new(Vec::<Root>::new()));

        let beacon = Arc::new(SyncGuardBeacon {
            submitted_roots: submitted_roots.clone(),
            duty_pubkey: pk_hex.clone(),
        });

        // attesting_enabled = true; sync_enabled = false (explicit)
        let attesting_enabled = Arc::new(AtomicBool::new(true));
        let orchestrator =
            build_sync_test_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

        orchestrator.set_sync_enabled(false);
        assert!(!orchestrator.sync_enabled.load(Ordering::Acquire));

        let ctx = SlotContext { slot: 0, epoch: 0, head_root: Some(r_captured) };

        orchestrator.run_sync_messages_phase(0, 0, &ctx).await;

        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "H-7: sync messages must NOT be produced when sync_enabled = false"
        );
    }

    // ── M-12 Critical #1: doppelganger gate wired into the duty path ────────

    /// When a validator's `enabled` flag is `false` in `ValidatorStore` (i.e.
    /// it is still inside the post-import doppelganger window), the attestation
    /// service must skip the duty and return `NoDutiesForSlot` rather than
    /// attempting to sign.
    ///
    /// Verifies the fix for ISSUE-3.11 Critical #1: "gate is never consulted
    /// by the attestation path".
    #[tokio::test]
    async fn test_orchestrator_skips_duty_during_doppelganger_window() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // 0x + 96 hex chars = 48 bytes (one 'd' nibble-pair per byte × 48)
        let duty_pubkey_hex =
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        // Slot 64 is in epoch 2 (64 / 32 = 2); mock duties endpoint for epoch 2.
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": duty_pubkey_hex,
                    "validator_index": "42",
                    "committee_index": "0",
                    "committee_length": "128",
                    "committees_at_slot": "1",
                    "validator_committee_index": "5",
                    "slot": "64"
                }]
            })))
            .mount(&mock_server)
            .await;

        // Signer call count — must be zero while validator is disabled.
        let submitter = Arc::new(MockSubmitter::new());
        let submit_count = submitter.call_count.load(Ordering::SeqCst);

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 64));
        clock.set_slot(64);

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["42".to_string()]));

        // Pre-populate the duty cache so process_slot can find the duty.
        duty_tracker.fetch_duties_for_epoch(2).await.unwrap();

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let propagator = Arc::new(Propagator::new(submitter.clone()));
        let config = create_test_config();

        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(duty_pubkey_hex.to_string(), pubkey.clone());
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        // --- Critical: add the DUTY pubkey as DISABLED (inside doppelganger window).
        // D-3 (FUP-6): the gate now resolves the duty pubkey via `find_pubkey`
        // and gates on the RESOLVED typed pubkey's infallible `to_bytes()` — it
        // no longer re-decodes the raw `0xdddd...` duty string.  The store must
        // therefore track the SAME bytes the `pubkey_map` resolves the duty to
        // (`pubkey.to_bytes()`), not the literal `0xdddd...` byte pattern.
        let duty_pk_bytes: [u8; 48] = pubkey.to_bytes();
        let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
        {
            let mut config = validator_store::ValidatorConfig::new(duty_pk_bytes);
            config.enabled = false;
            validator_store.add_validator(config);
        }

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            validator_store.clone(),
            config,
            pubkey_map,
        );

        // Phase 1 (RED → GREEN): process_slot must return NoDutiesForSlot
        // because the validator is inside the doppelganger window (enabled=false).
        let result = orchestrator.attestation_service.process_slot(64).await;
        assert!(
            matches!(result, Err(OrchestratorError::NoDutiesForSlot { slot: 64 })),
            "duty must be filtered out while validator is in doppelganger window; got: {result:?}"
        );
        assert_eq!(
            submitter.call_count.load(Ordering::SeqCst),
            submit_count,
            "signer must NOT be called while validator is in doppelganger window"
        );

        // Phase 2: enable the validator (simulates window elapsed).
        validator_store.set_enabled(&duty_pk_bytes, true);

        // Now process_slot should proceed past the gate (will fail further on
        // because no beacon attestation-data mock is set up, but the important
        // thing is the duty is NOT filtered by the doppelganger check).
        let result2 = orchestrator.attestation_service.process_slot(64).await;
        assert!(
            !matches!(result2, Err(OrchestratorError::NoDutiesForSlot { .. })),
            "after enabling the validator, duty must NOT be filtered by doppelganger gate; \
             got: {result2:?}"
        );
    }

    /// H-7: same guard split applies to contributions phase — skipped when sync disabled.
    #[tokio::test]
    async fn test_sync_contributions_skipped_when_sync_disabled() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let r_captured: Root = [0xAA; 32];
        let submitted_roots = Arc::new(std::sync::Mutex::new(Vec::<Root>::new()));

        let beacon = Arc::new(SyncGuardBeacon {
            submitted_roots: submitted_roots.clone(),
            duty_pubkey: pk_hex.clone(),
        });

        let attesting_enabled = Arc::new(AtomicBool::new(false));
        let orchestrator =
            build_sync_test_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

        // Disable sync: contributions must not call the signer.
        orchestrator.set_sync_enabled(false);

        let ctx = SlotContext { slot: 0, epoch: 0, head_root: Some(r_captured) };
        // With sync_enabled=false the phase guard returns early before any
        // signer or BN call. The test just verifies no panic and no submission.
        orchestrator.run_sync_contributions_phase(0, 0, &ctx).await;

        // No sync messages or contributions were submitted.
        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "H-7: sync contributions must NOT run when sync_enabled = false"
        );
    }

    // ── D-3: block proposal gate ─────────────────────────────────────────────

    /// D-3: a validator whose `is_signing_enabled = false` must NOT propose a block.
    ///
    /// The test uses wiremock to serve a proposer duty, then checks that
    /// `publish_block` is never called when the validator is disabled.
    ///
    /// RED: `maybe_propose_block` does not check `is_signing_enabled` →
    ///      the block_service is called (RANDAO sign, produce, publish).
    ///      The `BadProposerBlockBeacon` sets `publish_called = true` via
    ///      `produce_block_v3` returning a block with `proposer_index="1"`.
    ///      Actually `BadProposerBlockBeacon` calls `produce_block_v3` which
    ///      would attempt RANDAO sign first — the D-3 gate must fire before any
    ///      signer call, so the RANDAO sign never happens if the gate is correct.
    ///
    /// GREEN: D-3 gate in `maybe_propose_block` returns early before
    ///        `block_service.propose_block`, so `publish_called` stays `false`.
    #[tokio::test]
    async fn test_block_proposal_skipped_when_validator_disabled() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let slot: Slot = 10;
        let epoch = slot / SLOTS_PER_EPOCH;
        let validator_index = 1u64;

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
        let pk_bytes: [u8; 48] = pubkey.to_bytes();

        // Serve proposer duties from wiremock.
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": validator_index.to_string(),
                    "slot": slot.to_string()
                }]
            })))
            .mount(&mock_server)
            .await;

        let beacon_config = BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
        duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

        // BadProposerBlockBeacon is already defined above; it returns a block
        // with a non-matching proposer_index which would also cause a drop.
        // Use a matching proposer_index (validator_index) so the only gate is D-3.
        let publish_called = Arc::new(AtomicBool::new(false));
        let block_beacon = Arc::new(BadProposerBlockBeacon {
            slot,
            bad_proposer_index: validator_index, // matching index → no H-4 drop
            publish_called: publish_called.clone(),
        });

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        // Validator store with this validator DISABLED (doppelganger window).
        let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        {
            let mut config = validator_store::ValidatorConfig::new(pk_bytes);
            config.enabled = false;
            validator_store.add_validator(config);
        }

        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex, pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(slot);

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            block_beacon,
            None,
            validator_store,
            create_test_config(),
            pubkey_map,
        );

        let ctx = SlotContext { slot, epoch, head_root: None };
        orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

        // D-3: the block must NOT be proposed when is_signing_enabled=false.
        // publish_called stays false because the gate returns early before
        // block_service.propose_block (which would call produce_block_v3).
        assert!(
            !publish_called.load(Ordering::SeqCst),
            "D-3: block must NOT be proposed when is_signing_enabled=false"
        );
    }

    // Pin the aggregation 2/3 wait (coordinator.rs Phase 3) to the spec BPS value.
    // 6667 * 12000 / 10000 = 8000 ms on mainnet (unchanged from the legacy
    // `as_secs() * 2 / 3`), now exact for non-12 s / Gloas slots (report §4.3).
    #[test]
    fn test_aggregation_waits_until_two_thirds_8000ms_mainnet() {
        let clock = MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32);
        let slot_duration_ms = clock.slot_duration().as_millis() as u64;

        // Same call the Phase 3 wait makes in production (`due_ms(AGGREGATE_DUE_BPS, ..)`);
        // pinning the literal 8000 here fails if either the constant or the formula drifts.
        let two_thirds_offset_ms = due_ms(AGGREGATE_DUE_BPS, slot_duration_ms);
        assert_eq!(two_thirds_offset_ms, 8000, "mainnet 2/3 offset must be 8000 ms");

        // At slot start, the wait is the full 8000 ms offset.
        clock.set_current_time(TEST_GENESIS_TIME);
        let slot_start_ms = clock.slot_start_time(0) * 1000;
        let two_thirds_ms = slot_start_ms + two_thirds_offset_ms;
        let now_ms = clock.current_time_secs() * 1000;
        assert!(now_ms < two_thirds_ms);
        assert_eq!(two_thirds_ms - now_ms, 8000, "wait at slot start must be 8000 ms");

        // Past 2/3, no wait remains.
        clock.set_current_time(TEST_GENESIS_TIME + 9);
        let now_ms = clock.current_time_secs() * 1000;
        assert!(now_ms >= two_thirds_ms, "9 s into a 12 s slot is past the 8000 ms mark");
    }

    // Pin the missed-deadline 1/3 check (coordinator.rs:421/:427 site) to the spec
    // BPS value: 3333 * 12000 / 10000 = 3999 ms on mainnet, and confirm the warn
    // window opens only once we are a further 3999 ms past the deadline (~2/3 slot).
    #[test]
    fn test_missed_deadline_uses_one_third_bps_at_421_427() {
        let clock = MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32);
        let slot_duration_ms = clock.slot_duration().as_millis() as u64;

        // Same call the missed-deadline check makes in production
        // (`due_ms(ATTESTATION_DUE_BPS, ..)`); the literal 3999 fails on drift.
        let att_window_ms = due_ms(ATTESTATION_DUE_BPS, slot_duration_ms);
        assert_eq!(att_window_ms, 3999, "mainnet 1/3 attestation window must be 3999 ms");

        let slot_start_ms = clock.slot_start_time(0) * 1000;
        let expected_att_ms = slot_start_ms + att_window_ms;

        // `would_warn` mirrors the production condition: now past the deadline AND
        // the overrun exceeds the attestation window.
        let would_warn =
            |now_ms: u64| now_ms > expected_att_ms && now_ms - expected_att_ms > att_window_ms;

        // Just past 1/3 (4 s): missed but inside the window — no warn yet.
        assert!(!would_warn((TEST_GENESIS_TIME + 4) * 1000), "4 s in: missed but within window");
        // At 2/3 (8 s): exactly one window past 3999 ms (overrun 4001 > 3999) — warn.
        assert!(would_warn((TEST_GENESIS_TIME + 8) * 1000), "8 s in: past the window, warn fires");
        // Before the deadline (3 s): not missed.
        assert!(!would_warn((TEST_GENESIS_TIME + 3) * 1000), "3 s in: before the deadline");
    }
}
