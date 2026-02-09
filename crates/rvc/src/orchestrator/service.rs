//! Main duty orchestrator implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use beacon::{
    Attestation, AttesterDuty, BeaconClient, BeaconCommitteeSubscription, ProposerPreparation,
};
use block_service::{BeaconBlockClient, BlockService};
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{
    AggregateAndProof, ContributionAndProof, ForkName, ForkSchedule, Root, SignedAggregateAndProof,
    SignedContributionAndProof, Slot, SyncCommitteeDuty,
};
use metrics::definitions::{
    attestation_status, orchestrator_result, RVC_AGGREGATIONS_TOTAL, RVC_ATTESTATIONS_TOTAL,
    RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS, RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL,
    RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL, RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS,
};
use propagator::{AttestationSubmitter, Propagator};
use signer::{is_aggregator, SignerService};
use sync_service::is_sync_committee_aggregator;
use timing::{SlotClock, SLOTS_PER_EPOCH};
use tree_hash::TreeHash;

use super::error::OrchestratorError;

/// Timeout for block production beacon API calls.
const BLOCK_PRODUCE_TIMEOUT: Duration = Duration::from_secs(3);

/// Timeout for block publication beacon API calls.
const BLOCK_PUBLISH_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout for sync committee message operations.
const SYNC_MESSAGE_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout for sync committee contribution operations.
const SYNC_CONTRIBUTION_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout for duty fetching operations.
const DUTY_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for attestation data fetch.
const ATTESTATION_TIMEOUT: Duration = Duration::from_secs(4);

/// Timeout for aggregate attestation fetch and submission.
const AGGREGATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout for proposer preparation and committee subscription calls.
const PREPARATION_TIMEOUT: Duration = Duration::from_secs(3);

/// Total validators in a sync committee.
const SYNC_COMMITTEE_SIZE: u64 = 512;

/// Number of subnets the sync committee is split across.
const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;

/// Configuration for the duty orchestrator.
#[derive(Clone)]
pub struct OrchestratorConfig {
    pub genesis_validators_root: Root,
    pub fork_schedule: Arc<ForkSchedule>,
    pub shutdown_timeout: Duration,
}

impl OrchestratorConfig {
    pub fn new(genesis_validators_root: Root, fork_schedule: Arc<ForkSchedule>) -> Self {
        Self { genesis_validators_root, fork_schedule, shutdown_timeout: Duration::from_secs(30) }
    }

    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
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

/// Main orchestrator for coordinating validator duties.
pub struct DutyOrchestrator<C, S, B>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
    B: BeaconBlockClient + 'static,
{
    clock: Arc<C>,
    duty_tracker: Arc<DutyTracker>,
    signer: Arc<SignerService>,
    propagator: Arc<Propagator<S>>,
    beacon: Arc<BeaconClient>,
    block_service: BlockService<SignerService, B>,
    validator_store: Arc<validator_store::ValidatorStore>,
    config: OrchestratorConfig,
    pubkey_map: HashMap<String, PublicKey>,
    shutdown_rx: watch::Receiver<bool>,
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
        beacon: Arc<BeaconClient>,
        block_beacon: Arc<B>,
        validator_store: Arc<validator_store::ValidatorStore>,
        config: OrchestratorConfig,
        pubkey_map: HashMap<String, PublicKey>,
    ) -> (Self, OrchestratorHandle) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let block_service = BlockService::new(
            signer.clone(),
            block_beacon,
            validator_store.clone(),
            config.fork_schedule.clone(),
            config.genesis_validators_root,
        );

        let orchestrator = Self {
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            block_service,
            validator_store,
            config,
            pubkey_map,
            shutdown_rx,
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

            // === Epoch boundary: fetch all duty types ===
            self.fetch_epoch_duties(current_epoch).await;
            self.fetch_epoch_duties(current_epoch + 1).await;

            // Proposer preparation and committee subscriptions (non-fatal)
            if current_slot % SLOTS_PER_EPOCH == 0 {
                self.prepare_proposers().await;
                self.submit_committee_subscriptions(current_epoch).await;
                self.submit_committee_subscriptions(current_epoch + 1).await;
            }

            // === Phase 1: t=0 — Block proposal ===
            self.maybe_propose_block(current_slot, current_epoch).await;

            if self.check_shutdown() {
                return Ok(());
            }

            // === Phase 2: t=slot/3 — Attestations + sync committee messages ===
            let time_until_attestation = self.clock.time_until_attestation(current_slot)?;
            if !time_until_attestation.is_zero() {
                debug!(
                    slot = current_slot,
                    wait_ms = time_until_attestation.as_millis(),
                    "Waiting for attestation time"
                );

                tokio::select! {
                    _ = tokio::time::sleep(time_until_attestation) => {}
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

            if let Err(e) = self.process_slot(current_slot).await {
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

            self.maybe_produce_sync_messages(current_slot, current_epoch).await;

            if self.check_shutdown() {
                return Ok(());
            }

            // === Phase 3: t=2*slot/3 — Sync committee contributions ===
            let slot_duration = self.clock.slot_duration();
            let two_thirds_offset = slot_duration.as_secs() * 2 / 3;
            let two_thirds_time = self.clock.slot_start_time(current_slot) + two_thirds_offset;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time went backwards")
                .as_secs();

            if now < two_thirds_time {
                let wait_duration = Duration::from_secs(two_thirds_time - now);
                debug!(
                    slot = current_slot,
                    wait_ms = wait_duration.as_millis(),
                    "Waiting for 2/3 slot time"
                );

                tokio::select! {
                    _ = tokio::time::sleep(wait_duration) => {}
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

            self.maybe_produce_sync_contributions(current_slot, current_epoch).await;
            self.maybe_produce_aggregations(current_slot, current_epoch).await;

            // === Wait for next slot ===
            let next_slot = current_slot + 1;
            let time_until_next_slot = self.clock.time_until_slot(next_slot)?;

            if !time_until_next_slot.is_zero() {
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

    async fn fetch_epoch_duties(&self, epoch: u64) {
        // Evict old caches to prevent unbounded growth
        self.duty_tracker.evict_old_caches(epoch).await;

        // Attester duties
        if !self.duty_tracker.is_epoch_cached(epoch).await {
            debug!(epoch, "Fetching attester duties for epoch");
            match tokio::time::timeout(
                DUTY_FETCH_TIMEOUT,
                self.duty_tracker.fetch_duties_for_epoch(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch attester duties"),
                Err(_) => warn!(
                    epoch,
                    "Attester duty fetch timed out after {}s",
                    DUTY_FETCH_TIMEOUT.as_secs()
                ),
            }
        }

        // Proposer duties
        if !self.duty_tracker.is_proposer_epoch_cached(epoch).await {
            debug!(epoch, "Fetching proposer duties for epoch");
            match tokio::time::timeout(
                DUTY_FETCH_TIMEOUT,
                self.duty_tracker.fetch_proposer_duties(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch proposer duties"),
                Err(_) => warn!(
                    epoch,
                    "Proposer duty fetch timed out after {}s",
                    DUTY_FETCH_TIMEOUT.as_secs()
                ),
            }
        }

        // Sync committee duties (at period boundaries)
        if !self.duty_tracker.is_sync_period_cached(epoch).await {
            debug!(epoch, "Fetching sync committee duties");
            match tokio::time::timeout(
                DUTY_FETCH_TIMEOUT,
                self.duty_tracker.fetch_sync_committee_duties(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch sync committee duties"),
                Err(_) => warn!(
                    epoch,
                    "Sync committee duty fetch timed out after {}s",
                    DUTY_FETCH_TIMEOUT.as_secs()
                ),
            }
        }
    }

    async fn prepare_proposers(&self) {
        let mut preparations = Vec::new();

        for (pubkey_hex, pubkey) in &self.pubkey_map {
            let fee_recipient = self.validator_store.effective_fee_recipient(&pubkey.to_bytes());
            let fee_recipient_hex = format!("0x{}", hex::encode(fee_recipient));

            // We need the validator_index. Look it up from cached attester duties.
            // Iterate over current and next epoch slots to find a duty with this pubkey.
            let normalized = Self::normalize_pubkey(pubkey_hex);
            let mut found_index = None;

            if let Ok(current_slot) = self.clock.current_slot() {
                let current_epoch = current_slot / SLOTS_PER_EPOCH;
                for epoch in [current_epoch, current_epoch + 1] {
                    for slot_offset in 0..SLOTS_PER_EPOCH {
                        let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
                        let duties = self.duty_tracker.get_duties_for_slot(slot).await;
                        for duty in &duties {
                            if Self::normalize_pubkey(&duty.pubkey) == normalized {
                                found_index = Some(duty.validator_index.clone());
                                break;
                            }
                        }
                        if found_index.is_some() {
                            break;
                        }
                    }
                    if found_index.is_some() {
                        break;
                    }
                }
            }

            if let Some(validator_index) = found_index {
                preparations.push(ProposerPreparation {
                    validator_index,
                    fee_recipient: fee_recipient_hex,
                });
            } else {
                debug!(pubkey = %pubkey_hex, "No validator index found for proposer preparation");
            }
        }

        if preparations.is_empty() {
            return;
        }

        let count = preparations.len();
        match tokio::time::timeout(
            PREPARATION_TIMEOUT,
            self.beacon.prepare_beacon_proposer(&preparations),
        )
        .await
        {
            Ok(Ok(_)) => info!(count, "Sent proposer preparations"),
            Ok(Err(e)) => warn!(error = %e, "Failed to send proposer preparations"),
            Err(_) => {
                warn!("Proposer preparation timed out after {}s", PREPARATION_TIMEOUT.as_secs())
            }
        }
    }

    async fn submit_committee_subscriptions(&self, epoch: u64) {
        let mut subscriptions = Vec::new();

        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            let duties = self.duty_tracker.get_duties_for_slot(slot).await;

            for duty in &duties {
                // Only subscribe for our own validators
                let normalized = Self::normalize_pubkey(&duty.pubkey);
                let pubkey =
                    self.pubkey_map.iter().find(|(k, _)| Self::normalize_pubkey(k) == normalized);

                let pubkey = match pubkey {
                    Some((_, pk)) => pk.clone(),
                    None => continue,
                };

                let committee_length: u64 = match duty.committee_length.parse() {
                    Ok(cl) => cl,
                    Err(_) => {
                        warn!(
                            validator_index = %duty.validator_index,
                            "Invalid committee_length in duty: {}",
                            duty.committee_length
                        );
                        continue;
                    }
                };

                // Compute selection proof and determine if aggregator
                let selection_proof = match self.signer.sign_selection_proof(
                    slot,
                    &pubkey,
                    &self.config.fork_schedule,
                    &self.config.genesis_validators_root,
                ) {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            validator_index = %duty.validator_index,
                            slot,
                            error = %e,
                            "Failed to sign selection proof for subscription"
                        );
                        continue;
                    }
                };

                let is_agg = is_aggregator(committee_length, &selection_proof.to_bytes());

                subscriptions.push(BeaconCommitteeSubscription {
                    validator_index: duty.validator_index.clone(),
                    committee_index: duty.committee_index.clone(),
                    committees_at_slot: duty.committees_at_slot.clone(),
                    slot: duty.slot.clone(),
                    is_aggregator: is_agg,
                });
            }
        }

        if subscriptions.is_empty() {
            return;
        }

        let count = subscriptions.len();
        match tokio::time::timeout(
            PREPARATION_TIMEOUT,
            self.beacon.submit_beacon_committee_subscriptions(&subscriptions),
        )
        .await
        {
            Ok(Ok(_)) => info!(count, epoch, "Sent committee subscriptions"),
            Ok(Err(e)) => warn!(epoch, error = %e, "Failed to send committee subscriptions"),
            Err(_) => warn!(
                epoch,
                "Committee subscription timed out after {}s",
                PREPARATION_TIMEOUT.as_secs()
            ),
        }
    }

    async fn maybe_propose_block(&self, slot: Slot, epoch: u64) {
        let proposer_duty = match self.duty_tracker.get_proposer_duty(slot).await {
            Some(duty) => duty,
            None => return,
        };

        // Check if the proposer is one of our validators
        let pubkey = match self.find_pubkey(&proposer_duty.pubkey) {
            Some(pk) => pk,
            None => return,
        };

        info!(slot, validator_index = proposer_duty.validator_index, "Proposing block");

        // Wrap with combined produce + publish timeout
        match tokio::time::timeout(
            BLOCK_PRODUCE_TIMEOUT + BLOCK_PUBLISH_TIMEOUT,
            self.block_service.propose_block(slot, &pubkey),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!(
                    slot,
                    blinded = result.is_blinded,
                    consensus_version = %result.consensus_version,
                    "Block proposed successfully"
                );
            }
            Ok(Err(e)) => {
                error!(
                    slot,
                    epoch,
                    error = %e,
                    "Failed to propose block"
                );
            }
            Err(_) => {
                error!(
                    slot,
                    epoch,
                    "Block proposal timed out after {}s",
                    (BLOCK_PRODUCE_TIMEOUT + BLOCK_PUBLISH_TIMEOUT).as_secs()
                );
            }
        }
    }

    async fn maybe_produce_sync_messages(&self, slot: Slot, _epoch: u64) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
            return;
        }

        let head_root = match self.get_head_block_root().await {
            Some(root) => root,
            None => return,
        };

        let mut messages = Vec::new();

        for (duty, pubkey) in matching_duties.iter().zip(matching_pubkeys.iter()) {
            match SignerService::sign_sync_committee_message(
                &self.signer,
                &head_root,
                slot,
                pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            ) {
                Ok(sig) => {
                    messages.push(beacon::SyncCommitteeMessage {
                        slot,
                        beacon_block_root: head_root,
                        validator_index: duty.validator_index,
                        signature: sig.to_bytes().to_vec(),
                    });
                }
                Err(e) => {
                    warn!(
                        slot,
                        validator_index = duty.validator_index,
                        error = %e,
                        "Failed to sign sync committee message"
                    );
                }
            }
        }

        if !messages.is_empty() {
            let count = messages.len();
            match tokio::time::timeout(
                SYNC_MESSAGE_TIMEOUT,
                self.beacon.submit_sync_committee_messages(&messages),
            )
            .await
            {
                Ok(Ok(_)) => info!(slot, count, "Submitted sync committee messages"),
                Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit sync committee messages"),
                Err(_) => warn!(
                    slot,
                    "Sync committee message submit timed out after {}s",
                    SYNC_MESSAGE_TIMEOUT.as_secs()
                ),
            }
        }
    }

    async fn maybe_produce_sync_contributions(&self, slot: Slot, _epoch: u64) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
            return;
        }

        let head_root = match self.get_head_block_root().await {
            Some(root) => root,
            None => return,
        };

        let head_root_hex = format!("0x{}", hex::encode(head_root));
        let mut signed_proofs = Vec::new();

        for (duty, pubkey) in matching_duties.iter().zip(matching_pubkeys.iter()) {
            let subcommittee_indices: std::collections::BTreeSet<u64> = duty
                .validator_sync_committee_indices
                .iter()
                .map(|&pos| pos / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT))
                .collect();

            let secret_key = match self.signer.key_manager().get_secret_key(pubkey) {
                Some(sk) => sk,
                None => {
                    warn!(
                        validator_index = duty.validator_index,
                        "Secret key not found for sync contribution signing"
                    );
                    continue;
                }
            };

            for subcommittee_index in &subcommittee_indices {
                let selection_proof = crypto::sign_sync_committee_selection_proof(
                    slot,
                    *subcommittee_index,
                    secret_key,
                    &self.config.fork_schedule,
                    self.config.genesis_validators_root,
                );

                if !is_sync_committee_aggregator(&selection_proof.to_bytes()) {
                    debug!(
                        slot,
                        subcommittee_index,
                        validator_index = duty.validator_index,
                        "Not selected as sync committee aggregator"
                    );
                    continue;
                }

                debug!(
                    slot,
                    subcommittee_index,
                    validator_index = duty.validator_index,
                    "Selected as sync committee aggregator"
                );

                let contribution = match tokio::time::timeout(
                    SYNC_CONTRIBUTION_TIMEOUT,
                    self.beacon.get_sync_committee_contribution(
                        slot,
                        *subcommittee_index,
                        &head_root_hex,
                    ),
                )
                .await
                {
                    Ok(Ok(resp)) => resp.data,
                    Ok(Err(e)) => {
                        warn!(
                            slot,
                            subcommittee_index,
                            error = %e,
                            "Failed to get sync committee contribution"
                        );
                        continue;
                    }
                    Err(_) => {
                        warn!(
                            slot,
                            subcommittee_index,
                            "Sync committee contribution fetch timed out after {}s",
                            SYNC_CONTRIBUTION_TIMEOUT.as_secs()
                        );
                        continue;
                    }
                };

                let proof = ContributionAndProof {
                    aggregator_index: duty.validator_index,
                    contribution,
                    selection_proof: selection_proof.to_bytes().to_vec(),
                };

                let sig = crypto::sign_contribution_and_proof(
                    &proof,
                    secret_key,
                    &self.config.fork_schedule,
                    self.config.genesis_validators_root,
                );

                signed_proofs.push(SignedContributionAndProof {
                    message: proof,
                    signature: sig.to_bytes().to_vec(),
                });
            }
        }

        if !signed_proofs.is_empty() {
            let count = signed_proofs.len();
            match tokio::time::timeout(
                SYNC_CONTRIBUTION_TIMEOUT,
                self.beacon.submit_contribution_and_proofs(&signed_proofs),
            )
            .await
            {
                Ok(Ok(_)) => info!(slot, count, "Submitted sync committee contribution and proofs"),
                Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit contribution and proofs"),
                Err(_) => warn!(
                    slot,
                    "Contribution and proofs submit timed out after {}s",
                    SYNC_CONTRIBUTION_TIMEOUT.as_secs()
                ),
            }
        }
    }

    async fn maybe_produce_aggregations(&self, slot: Slot, _epoch: u64) {
        let duties = match self.get_duties_for_slot(slot).await {
            Ok(d) => d,
            Err(_) => return,
        };

        if duties.is_empty() {
            return;
        }

        let mut signed_aggregates: Vec<SignedAggregateAndProof> = Vec::new();

        for duty in &duties {
            let committee_length: u64 = match duty.committee_length.parse() {
                Ok(c) => c,
                Err(_) => continue,
            };

            let pubkey = match self.find_pubkey(&duty.pubkey) {
                Some(pk) => pk,
                None => continue,
            };

            let selection_proof = match SignerService::sign_selection_proof(
                &self.signer,
                slot,
                &pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        error = %e,
                        "Failed to sign selection proof for aggregation"
                    );
                    continue;
                }
            };

            if !is_aggregator(committee_length, &selection_proof.to_bytes()) {
                debug!(
                    slot,
                    validator_index = %duty.validator_index,
                    "Not selected as attestation aggregator"
                );
                continue;
            }

            info!(
                slot,
                validator_index = %duty.validator_index,
                "Selected as attestation aggregator"
            );

            // Compute attestation data root for fetching the aggregate
            let committee_index: u64 = match duty.committee_index.parse() {
                Ok(c) => c,
                Err(_) => continue,
            };

            let attestation_data_response = match tokio::time::timeout(
                AGGREGATION_TIMEOUT,
                self.beacon.get_attestation_data(slot, committee_index),
            )
            .await
            {
                Ok(Ok(resp)) => resp,
                Ok(Err(e)) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        error = %e,
                        "Failed to get attestation data for aggregation"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    continue;
                }
                Err(_) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        "Attestation data fetch timed out for aggregation"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    continue;
                }
            };

            let crypto_attestation_data =
                match Self::convert_attestation_data(&attestation_data_response.data) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!(
                            slot,
                            validator_index = %duty.validator_index,
                            error = %e,
                            "Failed to convert attestation data for aggregation"
                        );
                        RVC_AGGREGATIONS_TOTAL
                            .with_label_values(&[attestation_status::FAILED])
                            .inc();
                        continue;
                    }
                };

            let att_data_root = crypto_attestation_data.tree_hash_root();
            let att_data_root_hex = format!("0x{}", hex::encode(att_data_root.0));

            // Fetch the aggregate attestation
            let aggregate = match tokio::time::timeout(
                AGGREGATION_TIMEOUT,
                self.beacon.get_aggregate_attestation(slot, &att_data_root_hex),
            )
            .await
            {
                Ok(Ok(resp)) => resp.data,
                Ok(Err(e)) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        error = %e,
                        "Failed to get aggregate attestation"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    continue;
                }
                Err(_) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        "Aggregate attestation fetch timed out"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    continue;
                }
            };

            let aggregator_index: u64 = match duty.validator_index.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            let aggregate_and_proof = AggregateAndProof {
                aggregator_index,
                aggregate,
                selection_proof: selection_proof.to_bytes().to_vec(),
            };

            let signature = match SignerService::sign_aggregate_and_proof(
                &self.signer,
                &aggregate_and_proof,
                &pubkey,
                &self.config.fork_schedule,
                &self.config.genesis_validators_root,
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        error = %e,
                        "Failed to sign aggregate and proof"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    continue;
                }
            };

            signed_aggregates.push(SignedAggregateAndProof {
                message: aggregate_and_proof,
                signature: signature.to_bytes().to_vec(),
            });
        }

        if !signed_aggregates.is_empty() {
            let count = signed_aggregates.len();
            match tokio::time::timeout(
                AGGREGATION_TIMEOUT,
                self.beacon.submit_aggregate_and_proofs(&signed_aggregates),
            )
            .await
            {
                Ok(Ok(_)) => {
                    info!(slot, count, "Submitted aggregate and proofs");
                    RVC_AGGREGATIONS_TOTAL
                        .with_label_values(&[attestation_status::SUCCESS])
                        .inc_by(count as u64);
                }
                Ok(Err(e)) => {
                    warn!(slot, error = %e, "Failed to submit aggregate and proofs");
                    RVC_AGGREGATIONS_TOTAL
                        .with_label_values(&[attestation_status::FAILED])
                        .inc_by(count as u64);
                }
                Err(_) => {
                    warn!(
                        slot,
                        "Aggregate and proofs submit timed out after {}s",
                        AGGREGATION_TIMEOUT.as_secs()
                    );
                    RVC_AGGREGATIONS_TOTAL
                        .with_label_values(&[attestation_status::FAILED])
                        .inc_by(count as u64);
                }
            }
        }
    }

    fn filter_sync_duties(
        &self,
        duties: &[SyncCommitteeDuty],
    ) -> (Vec<SyncCommitteeDuty>, Vec<PublicKey>) {
        let mut matching_duties = Vec::new();
        let mut matching_pubkeys = Vec::new();

        for duty in duties {
            if let Some(pk) = self.find_pubkey(&duty.pubkey) {
                matching_duties.push(duty.clone());
                matching_pubkeys.push(pk);
            }
        }

        (matching_duties, matching_pubkeys)
    }

    async fn get_head_block_root(&self) -> Option<Root> {
        match tokio::time::timeout(SYNC_MESSAGE_TIMEOUT, self.beacon.get_block_root("head")).await {
            Ok(Ok(response)) => {
                let root_hex = response.data.root;
                match Self::parse_hex_root(&root_hex) {
                    Ok(root) => Some(root),
                    Err(e) => {
                        warn!(error = %e, "Failed to parse head block root");
                        None
                    }
                }
            }
            Ok(Err(e)) => {
                warn!(error = %e, "Failed to fetch head block root");
                None
            }
            Err(_) => {
                warn!("Head block root fetch timed out after {}s", SYNC_MESSAGE_TIMEOUT.as_secs());
                None
            }
        }
    }

    /// Processes all attestation duties for a given slot.
    ///
    /// Validators are processed sequentially within each slot to work with
    /// the non-Send/Sync `SlashingDb`. For high validator counts, consider
    /// making `SlashingDb` thread-safe with proper locking for concurrent processing.
    pub async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        let _timer =
            RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS.with_label_values(&[]).start_timer();

        info!(slot = slot, "Processing attestation duties for slot");

        let current_slot = self.clock.current_slot()?;

        if current_slot > slot {
            RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL.with_label_values(&[]).inc();
            return Err(OrchestratorError::SlotMissed { slot, current_slot });
        }

        let duties = self.get_duties_for_slot(slot).await?;

        if duties.is_empty() {
            debug!(slot = slot, "No attestation duties for this slot");
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::NO_DUTIES])
                .inc();
            return Err(OrchestratorError::NoDutiesForSlot { slot });
        }

        info!(slot = slot, duty_count = duties.len(), "Found attestation duties");
        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(duties.len() as f64);

        let mut results = Vec::new();

        for duty in duties {
            let result = self.process_attestation_duty(duty).await;

            if result.success {
                info!(
                    validator = %result.validator_index,
                    slot = result.slot,
                    "Attestation completed successfully"
                );
            } else {
                warn!(
                    validator = %result.validator_index,
                    slot = result.slot,
                    error = ?result.error,
                    "Attestation failed"
                );
            }
            results.push(result);
        }

        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(0.0);

        let success_count = results.iter().filter(|r| r.success).count();
        let failure_count = results.len() - success_count;

        if failure_count > 0 {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::FAILED])
                .inc();
        } else {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::SUCCESS])
                .inc();
        }

        info!(
            slot = slot,
            total = results.len(),
            success = success_count,
            failed = failure_count,
            "Slot processing complete"
        );

        Ok(results)
    }

    async fn get_duties_for_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttesterDuty>, OrchestratorError> {
        if self.pubkey_map.is_empty() {
            return Ok(Vec::new());
        }

        let epoch = slot / SLOTS_PER_EPOCH;

        if !self.duty_tracker.is_epoch_cached(epoch).await {
            self.duty_tracker.fetch_duties_for_epoch(epoch).await?;
        }

        let normalized_pubkeys: std::collections::HashSet<String> =
            self.pubkey_map.keys().map(|k| Self::normalize_pubkey(k)).collect();

        let all_duties = self.duty_tracker.get_duties_for_slot(slot).await;
        let duties: Vec<AttesterDuty> = all_duties
            .into_iter()
            .filter(|duty| {
                let normalized_duty_pubkey = Self::normalize_pubkey(&duty.pubkey);
                normalized_pubkeys.contains(&normalized_duty_pubkey)
            })
            .collect();

        Ok(duties)
    }

    /// Normalizes a pubkey to lowercase without 0x/0X prefix for comparison.
    fn normalize_pubkey(pubkey: &str) -> String {
        let without_prefix =
            pubkey.strip_prefix("0x").or_else(|| pubkey.strip_prefix("0X")).unwrap_or(pubkey);
        without_prefix.to_lowercase()
    }

    async fn process_attestation_duty(&self, duty: AttesterDuty) -> AttestationResult {
        let validator_index = duty.validator_index.clone();

        let slot: Slot = match duty.slot.parse() {
            Ok(s) => s,
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot: 0,
                    success: false,
                    error: Some(format!("Invalid slot in duty: {}", duty.slot)),
                };
            }
        };

        let committee_index: u64 = match duty.committee_index.parse() {
            Ok(c) => c,
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!(
                        "Invalid committee_index in duty: {}",
                        duty.committee_index
                    )),
                };
            }
        };

        debug!(
            validator = %validator_index,
            slot = slot,
            committee_index = committee_index,
            "Processing attestation duty"
        );

        let pubkey = match self.find_pubkey(&duty.pubkey) {
            Some(pk) => pk,
            None => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Public key not found: {}", duty.pubkey)),
                };
            }
        };

        // Apply timeout to beacon client call to prevent blocking
        let attestation_data_result = tokio::time::timeout(
            ATTESTATION_TIMEOUT,
            self.beacon.get_attestation_data(slot, committee_index),
        )
        .await;

        let attestation_data_response = match attestation_data_result {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to get attestation data: {}", e)),
                };
            }
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some("Timeout getting attestation data from beacon node".to_string()),
                };
            }
        };

        let beacon_attestation_data = attestation_data_response.data;

        let crypto_attestation_data = match Self::convert_attestation_data(&beacon_attestation_data)
        {
            Ok(data) => data,
            Err(e) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to convert attestation data: {}", e)),
                };
            }
        };

        let target_epoch = crypto_attestation_data.target.epoch;
        let fork = self.derive_fork_for_epoch(target_epoch);

        let signature = match self.signer.sign_attestation(
            &crypto_attestation_data,
            &pubkey,
            &fork,
            self.config.genesis_validators_root,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to sign attestation: {}", e)),
                };
            }
        };

        let attester_index: u64 = match validator_index.parse() {
            Ok(v) => v,
            Err(_) => {
                let error = format!("Invalid validator_index in duty: {}", validator_index);
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(error),
                };
            }
        };

        let attestation = Attestation {
            committee_index,
            attester_index,
            data: beacon_attestation_data,
            signature: format!("0x{}", hex::encode(signature.to_bytes())),
        };

        match self.propagator.propagate(attestation).await {
            Ok(()) => AttestationResult { validator_index, slot, success: true, error: None },
            Err(e) => AttestationResult {
                validator_index,
                slot,
                success: false,
                error: Some(format!("Failed to propagate attestation: {}", e)),
            },
        }
    }

    fn derive_fork_for_epoch(&self, epoch: u64) -> eth_types::Fork {
        let schedule = &self.config.fork_schedule;
        let fork_name = ForkName::from_epoch(epoch, schedule);
        let current_version = fork_name.fork_version(schedule);
        let prior_fork_name = if epoch > 0 {
            ForkName::from_epoch(epoch - 1, schedule)
        } else {
            ForkName::from_epoch(0, schedule)
        };
        let previous_version = prior_fork_name.fork_version(schedule);

        eth_types::Fork {
            previous_version,
            current_version,
            epoch: if current_version != previous_version { epoch } else { 0 },
        }
    }

    /// Finds a public key by matching against duty pubkey.
    ///
    /// Pubkeys are matched case-insensitively and with/without "0x" prefix.
    fn find_pubkey(&self, duty_pubkey: &str) -> Option<PublicKey> {
        // Try exact match first
        if let Some(pk) = self.pubkey_map.get(duty_pubkey) {
            return Some(pk.clone());
        }

        // Try with/without 0x prefix
        let normalized_pubkey = if duty_pubkey.starts_with("0x") {
            duty_pubkey.to_string()
        } else {
            format!("0x{}", duty_pubkey)
        };

        if let Some(pk) = self.pubkey_map.get(&normalized_pubkey) {
            return Some(pk.clone());
        }

        // Normalize for case-insensitive matching
        let duty_normalized = Self::normalize_pubkey(duty_pubkey);

        for (key, pk) in &self.pubkey_map {
            if Self::normalize_pubkey(key) == duty_normalized {
                return Some(pk.clone());
            }
        }

        None
    }

    fn convert_attestation_data(
        beacon_data: &beacon::AttestationData,
    ) -> Result<eth_types::AttestationData, OrchestratorError> {
        let slot: u64 = beacon_data
            .slot
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid slot".to_string()))?;

        let index: u64 = beacon_data
            .index
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid index".to_string()))?;

        let beacon_block_root = Self::parse_hex_root(&beacon_data.beacon_block_root)?;

        let source_epoch: u64 = beacon_data
            .source
            .epoch
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid source epoch".to_string()))?;

        let source_root = Self::parse_hex_root(&beacon_data.source.root)?;

        let target_epoch: u64 = beacon_data
            .target
            .epoch
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid target epoch".to_string()))?;

        let target_root = Self::parse_hex_root(&beacon_data.target.root)?;

        Ok(eth_types::AttestationData {
            slot,
            index,
            beacon_block_root,
            source: eth_types::Checkpoint { epoch: source_epoch, root: source_root },
            target: eth_types::Checkpoint { epoch: target_epoch, root: target_root },
        })
    }

    fn parse_hex_root(hex_str: &str) -> Result<Root, OrchestratorError> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        let bytes = hex::decode(hex_str)
            .map_err(|e| OrchestratorError::ParseError(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(OrchestratorError::ParseError(format!(
                "Invalid root length: expected 32, got {}",
                bytes.len()
            )));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Ok(root)
    }
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use beacon::BeaconClientConfig;
    use block_service::ProduceBlockResponse;
    use crypto::{KeyManager, SecretKey};
    use slashing::SlashingDb;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use timing::MockSlotClock;
    use validator_store::ValidatorStore;

    const TEST_GENESIS_TIME: u64 = 1606824023;

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
            _attestations: &'a [Attestation],
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
    }

    fn create_mock_block_beacon() -> Arc<MockBlockBeacon> {
        Arc::new(MockBlockBeacon)
    }

    fn create_mock_validator_store() -> Arc<ValidatorStore> {
        Arc::new(ValidatorStore::new([0u8; 20], 100))
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
    fn test_parse_hex_root_with_prefix() {
        let root =
            DutyOrchestrator::<MockSlotClock, MockSubmitter, MockBlockBeacon>::parse_hex_root(
                "0x1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap();
        assert_eq!(root, [0x11; 32]);
    }

    #[test]
    fn test_parse_hex_root_without_prefix() {
        let root =
            DutyOrchestrator::<MockSlotClock, MockSubmitter, MockBlockBeacon>::parse_hex_root(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap();
        assert_eq!(root, [0x22; 32]);
    }

    #[test]
    fn test_parse_hex_root_invalid_length() {
        let result =
            DutyOrchestrator::<MockSlotClock, MockSubmitter, MockBlockBeacon>::parse_hex_root(
                "0x1111111111",
            );
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_root_invalid_hex() {
        let result =
            DutyOrchestrator::<MockSlotClock, MockSubmitter, MockBlockBeacon>::parse_hex_root(
                "0xgggggggg",
            );
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_attestation_data_success() {
        let beacon_data = beacon::AttestationData {
            slot: "1000".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let crypto_data =
            DutyOrchestrator::<MockSlotClock, MockSubmitter, MockBlockBeacon>::convert_attestation_data(
                &beacon_data,
            )
            .unwrap();

        assert_eq!(crypto_data.slot, 1000);
        assert_eq!(crypto_data.index, 5);
        assert_eq!(crypto_data.beacon_block_root, [0x11; 32]);
        assert_eq!(crypto_data.source.epoch, 100);
        assert_eq!(crypto_data.source.root, [0x22; 32]);
        assert_eq!(crypto_data.target.epoch, 101);
        assert_eq!(crypto_data.target.root, [0x33; 32]);
    }

    #[test]
    fn test_convert_attestation_data_invalid_slot() {
        let beacon_data = beacon::AttestationData {
            slot: "invalid".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let result = DutyOrchestrator::<MockSlotClock, MockSubmitter, MockBlockBeacon>::convert_attestation_data(
            &beacon_data,
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_orchestrator_handle_shutdown() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (mut orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
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

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
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

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
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
        let key_manager = Arc::new(key_manager);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(pubkey_hex, pubkey);

        let (_orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
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

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(pubkey_hex.clone(), pubkey.clone());

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let found = orchestrator.find_pubkey(&pubkey_hex);
        assert!(found.is_some());
        assert_eq!(found.unwrap().to_bytes(), pubkey.to_bytes());
    }

    #[tokio::test]
    async fn test_find_pubkey_case_insensitive() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(pubkey_hex.to_uppercase(), pubkey.clone());

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let found = orchestrator.find_pubkey(&pubkey_hex.to_lowercase());
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_find_pubkey_not_found() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        let found = orchestrator.find_pubkey("0x1234567890abcdef");
        assert!(found.is_none());
    }

    #[test]
    fn test_timeout_constants_are_reasonable() {
        // Block production must fit within a slot third (~4s for 12s slots)
        assert!(BLOCK_PRODUCE_TIMEOUT.as_secs() <= 4);
        assert!(BLOCK_PRODUCE_TIMEOUT.as_secs() >= 1);

        // Block publish must fit within remaining slot time
        assert!(BLOCK_PUBLISH_TIMEOUT.as_secs() <= 3);
        assert!(BLOCK_PUBLISH_TIMEOUT.as_secs() >= 1);

        // Produce + publish together should fit in one slot third (~4s)
        assert!(BLOCK_PRODUCE_TIMEOUT + BLOCK_PUBLISH_TIMEOUT <= Duration::from_secs(6));

        // Sync operations must fit within their slot third
        assert!(SYNC_MESSAGE_TIMEOUT.as_secs() <= 3);
        assert!(SYNC_CONTRIBUTION_TIMEOUT.as_secs() <= 3);

        // Duty fetch is less time-critical but should still be bounded
        assert!(DUTY_FETCH_TIMEOUT.as_secs() <= 12);
        assert!(DUTY_FETCH_TIMEOUT.as_secs() >= 5);

        // Attestation timeout must fit within slot third
        assert!(ATTESTATION_TIMEOUT.as_secs() <= 5);
    }

    #[tokio::test]
    async fn test_duty_fetch_timeout() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock attester duties endpoint with a 15s delay (exceeds DUTY_FETCH_TIMEOUT of 10s)
        Mock::given(method("POST"))
            .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": [],
                        "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                    }))
                    .set_delay(DUTY_FETCH_TIMEOUT + Duration::from_secs(5)),
            )
            .mount(&mock_server)
            .await;

        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let epoch = 1u64;
        let result =
            tokio::time::timeout(DUTY_FETCH_TIMEOUT, duty_tracker.fetch_duties_for_epoch(epoch))
                .await;

        // Should timeout (Err from tokio::time::timeout)
        assert!(result.is_err(), "Duty fetch should have timed out");
    }

    #[tokio::test]
    async fn test_sync_message_submit_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock sync committee messages endpoint with delay exceeding SYNC_MESSAGE_TIMEOUT
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(
                ResponseTemplate::new(200).set_delay(SYNC_MESSAGE_TIMEOUT + Duration::from_secs(5)),
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
            SYNC_MESSAGE_TIMEOUT,
            beacon.submit_sync_committee_messages(&messages),
        )
        .await;

        assert!(result.is_err(), "Sync message submit should have timed out");
    }

    #[tokio::test]
    async fn test_head_block_root_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock block root endpoint with delay exceeding SYNC_MESSAGE_TIMEOUT
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/blocks/head/root"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": {
                            "root": "0x0000000000000000000000000000000000000000000000000000000000000000"
                        }
                    }))
                    .set_delay(SYNC_MESSAGE_TIMEOUT + Duration::from_secs(5)),
            )
            .mount(&mock_server)
            .await;

        let beacon_config = beacon::BeaconClientConfig::new(mock_server.uri());
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let result =
            tokio::time::timeout(SYNC_MESSAGE_TIMEOUT, beacon.get_block_root("head")).await;

        assert!(result.is_err(), "Head block root fetch should have timed out");
    }

    #[test]
    fn test_aggregation_timeout_is_reasonable() {
        // Must fit within the 2/3-slot to end-of-slot window (~4s for 12s slots)
        assert!(AGGREGATION_TIMEOUT.as_secs() <= 4);
        assert!(AGGREGATION_TIMEOUT.as_secs() >= 1);
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
        let key_manager = Arc::new(key_manager);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(pubkey_hex.clone(), pubkey.clone());

        let (orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
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

        orchestrator.maybe_produce_aggregations(slot, epoch).await;
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
        orchestrator.maybe_produce_aggregations(slot, epoch).await;

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

        // Use a very large committee_length so is_aggregator is very unlikely
        // committee_length=100000 → modulo=6250 → ~0.016% chance
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
        orchestrator.maybe_produce_aggregations(slot, epoch).await;
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
        orchestrator.maybe_produce_aggregations(slot, epoch).await;
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
        let key_manager = Arc::new(key_manager);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();

        // Map our pubkey to match the duty's pubkey
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            pubkey,
        );

        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            validator_store,
            config,
            pubkey_map,
        );

        orchestrator.prepare_proposers().await;
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

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        orchestrator.prepare_proposers().await;
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
        let key_manager = Arc::new(key_manager);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            pubkey,
        );

        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            validator_store,
            config,
            pubkey_map,
        );

        // Should not panic - failure is non-fatal
        orchestrator.prepare_proposers().await;
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
        let key_manager = Arc::new(key_manager);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            pubkey,
        );

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        orchestrator.submit_committee_subscriptions(3).await;
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

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        orchestrator.submit_committee_subscriptions(0).await;
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
        let key_manager = Arc::new(key_manager);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            pubkey,
        );

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            create_mock_validator_store(),
            config,
            pubkey_map,
        );

        // Should not panic
        orchestrator.submit_committee_subscriptions(3).await;
    }

    #[test]
    fn test_preparation_timeout_is_reasonable() {
        assert!(PREPARATION_TIMEOUT.as_secs() >= 1);
        assert!(PREPARATION_TIMEOUT.as_secs() <= 5);
    }
}
