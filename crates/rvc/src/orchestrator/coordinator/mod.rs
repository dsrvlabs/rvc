//! Main duty orchestrator implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, info, info_span, warn, Instrument};

use block_service::{BeaconBlockClient, BlockService};
use bn_manager::{AttestationSubmitter, BeaconNodeClient, OperationTimeouts, Propagator};
use builder::BuilderService;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{ForkSchedule, Root, Slot};
use metrics::definitions::{attestation_status, RVC_ATTESTATIONS_TOTAL};
use signer::{CircuitBreakerState, SignerService};
use timing::{due_ms, SlotClock, AGGREGATE_DUE_BPS, ATTESTATION_DUE_BPS, SLOTS_PER_EPOCH};

use super::aggregation::AggregationService;
use super::attestation::AttestationService;
use super::duty_management::DutyManagementService;
use super::error::OrchestratorError;
use super::slot_context::SlotContext;
use super::sync_committee::SyncCommitteeService;

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

/// Outcome of a timed wait that can be interrupted by shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitOutcome {
    /// The wait completed (or was zero-length); continue the slot loop.
    Continue,
    /// Shutdown was requested; the caller must exit `run()`.
    Shutdown,
}

/// Phase deadline relative to a slot: offset from slot start, remaining wait,
/// and how far past the deadline we already are.
#[derive(Debug, Clone, Copy)]
struct PhaseDeadline {
    /// Duration from slot start to this phase (bps → ms of slot duration).
    offset: Duration,
    /// Time remaining until the deadline (`ZERO` if already at/past it).
    remaining: Duration,
    /// How far past the deadline we are in ms (`0` if not past).
    overrun_ms: u64,
}

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
///
/// Fields used by sibling `impl` blocks (e.g. [`crate::orchestrator::block_proposal`])
/// are `pub(crate)` so methods can live outside this module without a service seam.
pub struct DutyOrchestrator<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    pub(crate) clock: Arc<C>,
    pub(crate) beacon: Arc<dyn BeaconNodeClient>,
    pub(crate) duty_tracker: Arc<DutyTracker>,
    pub(crate) block_service: BlockService<SignerService, B>,
    pub(crate) builder_service: Option<Arc<BuilderService>>,
    pub(crate) circuit_breaker: Arc<CircuitBreakerState>,
    pub(crate) config: OrchestratorConfig,
    pub(crate) pubkey_map: PubkeyMap,
    pub(crate) attestation_service: AttestationService<C, S>,
    pub(crate) aggregation_service: AggregationService,
    pub(crate) sync_committee_service: SyncCommitteeService,
    pub(crate) duty_management: DutyManagementService<C>,
    pub(crate) key_gen_rx: watch::Receiver<u64>,
    pub(crate) shutdown_rx: watch::Receiver<bool>,
    pub(crate) attesting_enabled: Arc<AtomicBool>,
    /// Controls whether sync-committee duties are processed independently of
    /// `attesting_enabled`. Defaults to `true`; can be toggled at runtime via
    /// [`set_sync_enabled`]. Internal-only — not wired to any Keymanager API (H-7).
    pub(crate) sync_enabled: Arc<AtomicBool>,
    /// D-3: per-validator doppelganger gate for block proposals.
    /// Shared reference to the ValidatorStore for `is_signing_enabled` checks.
    pub(crate) validator_store: Arc<validator_store::ValidatorStore>,
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
                self.duty_management
                    .on_epoch_boundary(current_epoch, current_slot)
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

                    if matches!(
                        self.wait_for(time_until_attestation)
                            .instrument(att_phase_span.clone())
                            .await,
                        WaitOutcome::Shutdown
                    ) {
                        return Ok(());
                    }
                }

                if self.check_shutdown() {
                    return Ok(());
                }

                // Check for missed attestation deadline.
                // Basis-points formula in milliseconds (report §4.3), consistent
                // with `time_until_attestation`: mainnet 1/3 = 3999 ms.
                {
                    let deadline = self.phase_deadline(current_slot, ATTESTATION_DUE_BPS);
                    let att_window_ms = deadline.offset.as_millis() as u64;
                    // Only warn if the delay exceeds the expected attestation window
                    // (i.e., we're past 2/3 of the slot).
                    if deadline.overrun_ms > att_window_ms {
                        warn!(
                            slot = current_slot,
                            delay_ms = deadline.overrun_ms,
                            "Missed attestation deadline"
                        );
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
                let deadline = self.phase_deadline(current_slot, AGGREGATE_DUE_BPS);
                if !deadline.remaining.is_zero() {
                    {
                        let _guard = agg_phase_span.enter();
                        debug!(
                            slot = current_slot,
                            wait_ms = deadline.remaining.as_millis(),
                            "Waiting for 2/3 slot time"
                        );
                    }

                    if matches!(
                        self.wait_for(deadline.remaining).instrument(agg_phase_span.clone()).await,
                        WaitOutcome::Shutdown
                    ) {
                        return Ok(());
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
                // Clone builder_service before borrowing self for wait_for
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

                // Race next-slot wait (incl. shutdown) against registration so a
                // long registration cannot block the slot loop; registration is
                // abandoned if the next slot arrives first.
                tokio::select! {
                    outcome = self.wait_for(time_until_next_slot) => {
                        if matches!(outcome, WaitOutcome::Shutdown) {
                            return Ok(());
                        }
                    }
                    _ = &mut builder_fut => {}
                }
            } else if !time_until_next_slot.is_zero()
                && matches!(self.wait_for(time_until_next_slot).await, WaitOutcome::Shutdown)
            {
                return Ok(());
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

    /// Wait up to `duration`, returning early if shutdown is requested.
    ///
    /// Single implementation of the sleep / shutdown-watch race used by every
    /// phase of the slot loop. Callers must handle [`WaitOutcome::Shutdown`]
    /// explicitly (the enum forces it).
    async fn wait_for(&mut self, duration: Duration) -> WaitOutcome {
        if !duration.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(duration) => {}
                _ = self.shutdown_rx.changed() => {}
            }
        }
        if self.check_shutdown() {
            WaitOutcome::Shutdown
        } else {
            WaitOutcome::Continue
        }
    }

    /// Phase deadline at `bps` basis points into `slot`.
    ///
    /// Single source for the bps-in-milliseconds arithmetic previously inlined
    /// at the attestation missed-deadline check and the aggregation 2/3 wait
    /// (report §4.3). Mainnet examples: 1/3 → 3999 ms, 2/3 → 8000 ms.
    fn phase_deadline(&self, slot: Slot, bps: u64) -> PhaseDeadline {
        let offset_ms = due_ms(bps, self.clock.slot_duration().as_millis() as u64);
        let deadline_ms = self.clock.slot_start_time(slot) * 1000 + offset_ms;
        let now_ms = self.clock.current_time_secs() * 1000;
        if now_ms < deadline_ms {
            PhaseDeadline {
                offset: Duration::from_millis(offset_ms),
                remaining: Duration::from_millis(deadline_ms - now_ms),
                overrun_ms: 0,
            }
        } else {
            PhaseDeadline {
                offset: Duration::from_millis(offset_ms),
                remaining: Duration::ZERO,
                overrun_ms: now_ms - deadline_ms,
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
pub(crate) mod tests;
