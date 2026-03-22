use std::sync::Arc;

use tracing::{debug, info, warn};

use beacon::{BeaconCommitteeSubscription, ProposerPreparation};
use bn_manager::BeaconNodeClient;
use duty_tracker::DutyTracker;
use metrics::definitions::RVC_DUTY_REORG_DETECTED_TOTAL;
use signer::{is_aggregator, SignerService};
use timing::{SlotClock, SLOTS_PER_EPOCH};

use super::service::{OrchestratorConfig, PubkeyMap};
use super::utils;

pub(crate) struct DutyManagementService<C: SlotClock + 'static> {
    clock: Arc<C>,
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    validator_store: Arc<validator_store::ValidatorStore>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
}

impl<C: SlotClock + 'static> DutyManagementService<C> {
    pub(crate) fn new(
        clock: Arc<C>,
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        validator_store: Arc<validator_store::ValidatorStore>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
    ) -> Self {
        Self { clock, signer, beacon, duty_tracker, validator_store, pubkey_map, config }
    }

    #[tracing::instrument(name = "rvc.orchestrator.fetch_epoch_duties", skip_all, fields(rvc.epoch = epoch))]
    pub(crate) async fn fetch_epoch_duties(&self, epoch: u64) {
        // Evict old caches to prevent unbounded growth
        self.duty_tracker.evict_old_caches(epoch).await;

        // Attester duties
        if !self.duty_tracker.is_epoch_cached(epoch).await {
            debug!(epoch, "Fetching attester duties for epoch");
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_duties_for_epoch(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch attester duties"),
                Err(_) => warn!(
                    epoch,
                    "Attester duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        // Proposer duties
        if !self.duty_tracker.is_proposer_epoch_cached(epoch).await {
            debug!(epoch, "Fetching proposer duties for epoch");
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_proposer_duties(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch proposer duties"),
                Err(_) => warn!(
                    epoch,
                    "Proposer duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        // Sync committee duties (at period boundaries)
        if !self.duty_tracker.is_sync_period_cached(epoch).await {
            debug!(epoch, "Fetching sync committee duties");
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_sync_committee_duties(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch sync committee duties"),
                Err(_) => warn!(
                    epoch,
                    "Sync committee duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        let (attester_count, proposer_count, sync_count) =
            self.duty_tracker.cached_duty_counts(epoch).await;
        debug!(epoch, attester_count, proposer_count, sync_count, "Duty counts for epoch");
    }

    #[tracing::instrument(name = "rvc.orchestrator.check_reorg", skip_all, fields(rvc.epoch = current_epoch))]
    pub(crate) async fn check_reorg_at_epoch_boundary(&self, current_epoch: u64) {
        for epoch in [current_epoch, current_epoch + 1] {
            let attester_cached = self.duty_tracker.is_epoch_cached(epoch).await;
            let old_attester_root = self.duty_tracker.get_cached_dependent_root(epoch).await;
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.check_and_refetch_if_root_changed(epoch),
            )
            .await
            {
                Ok(Ok(true)) if attester_cached => {
                    let new_root = self.duty_tracker.get_cached_dependent_root(epoch).await;
                    warn!(
                        epoch,
                        old_head = ?old_attester_root,
                        new_head = ?new_root,
                        "Reorg detected: attester duties refetched"
                    );
                    RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["attester"]).inc();
                }
                Ok(Ok(true)) => {
                    debug!(epoch, "Attester duties fetched (was uncached)");
                }
                Ok(Ok(false)) => {}
                Ok(Err(e)) => {
                    warn!(epoch, error = %e, "Failed to check attester dependent root");
                }
                Err(_) => {
                    warn!(
                        epoch,
                        "Attester reorg check timed out after {}s",
                        self.config.timeouts.duty_fetch.as_secs()
                    );
                }
            }

            let proposer_cached = self.duty_tracker.is_proposer_epoch_cached(epoch).await;
            let old_proposer_root =
                self.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.check_and_refetch_proposer_if_root_changed(epoch),
            )
            .await
            {
                Ok(Ok(true)) if proposer_cached => {
                    let new_root =
                        self.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
                    warn!(
                        epoch,
                        old_head = ?old_proposer_root,
                        new_head = ?new_root,
                        "Reorg detected: proposer duties refetched"
                    );
                    RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["proposer"]).inc();
                }
                Ok(Ok(true)) => {
                    debug!(epoch, "Proposer duties fetched (was uncached)");
                }
                Ok(Ok(false)) => {}
                Ok(Err(e)) => {
                    warn!(epoch, error = %e, "Failed to check proposer dependent root");
                }
                Err(_) => {
                    warn!(
                        epoch,
                        "Proposer reorg check timed out after {}s",
                        self.config.timeouts.duty_fetch.as_secs()
                    );
                }
            }
        }
    }

    #[tracing::instrument(name = "rvc.orchestrator.prepare_proposers", skip_all)]
    pub(crate) async fn prepare_proposers(&self) {
        let mut preparations = Vec::new();

        let pubkey_snapshot = self.pubkey_map.read().clone();
        for (pubkey_hex, pubkey) in &pubkey_snapshot {
            let fee_recipient = self.validator_store.effective_fee_recipient(&pubkey.to_bytes());
            let fee_recipient_hex = format!("0x{}", hex::encode(fee_recipient));

            // We need the validator_index. Look it up from cached attester duties.
            // Iterate over current and next epoch slots to find a duty with this pubkey.
            let normalized = utils::normalize_pubkey(pubkey_hex);
            let mut found_index = None;

            if let Ok(current_slot) = self.clock.current_slot() {
                let current_epoch = current_slot / SLOTS_PER_EPOCH;
                for epoch in [current_epoch, current_epoch + 1] {
                    for slot_offset in 0..SLOTS_PER_EPOCH {
                        let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
                        let duties = self.duty_tracker.get_duties_for_slot(slot).await;
                        for duty in &duties {
                            if utils::normalize_pubkey(&duty.pubkey) == normalized {
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
            self.config.timeouts.preparation,
            self.beacon.prepare_beacon_proposer(&preparations),
        )
        .await
        {
            Ok(Ok(_)) => info!(count, "Sent proposer preparations"),
            Ok(Err(e)) => warn!(error = %e, "Failed to send proposer preparations"),
            Err(_) => {
                warn!(
                    "Proposer preparation timed out after {}s",
                    self.config.timeouts.preparation.as_secs()
                )
            }
        }
    }

    #[tracing::instrument(name = "rvc.orchestrator.submit_committee_subscriptions", skip_all, fields(rvc.epoch = epoch))]
    pub(crate) async fn submit_committee_subscriptions(&self, epoch: u64) {
        let mut subscriptions = Vec::new();
        let pubkey_snapshot = self.pubkey_map.read().clone();

        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            let duties = self.duty_tracker.get_duties_for_slot(slot).await;

            for duty in &duties {
                // Only subscribe for our own validators
                let normalized = utils::normalize_pubkey(&duty.pubkey);
                let pubkey =
                    pubkey_snapshot.iter().find(|(k, _)| utils::normalize_pubkey(k) == normalized);

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
                let selection_proof = match self
                    .signer
                    .sign_selection_proof(
                        slot,
                        &pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .await
                {
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
            self.config.timeouts.preparation,
            self.beacon.submit_beacon_committee_subscriptions(&subscriptions),
        )
        .await
        {
            Ok(Ok(_)) => info!(count, epoch, "Sent committee subscriptions"),
            Ok(Err(e)) => warn!(epoch, error = %e, "Failed to send committee subscriptions"),
            Err(_) => warn!(
                epoch,
                "Committee subscription timed out after {}s",
                self.config.timeouts.preparation.as_secs()
            ),
        }
    }
}
