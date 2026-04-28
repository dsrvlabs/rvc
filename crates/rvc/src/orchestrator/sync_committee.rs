use std::collections::BTreeSet;
use std::sync::Arc;

use tracing::{debug, info, warn};

use bn_manager::BeaconNodeClient;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{ContributionAndProof, Root, SignedContributionAndProof, Slot, SyncCommitteeDuty};
use signer::SignerService;
use sync_service::is_sync_committee_aggregator;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::slot_context::SlotContext;
use super::utils;

/// Total validators in a sync committee.
const SYNC_COMMITTEE_SIZE: u64 = 512;

/// Number of subnets the sync committee is split across.
const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;

pub(crate) struct SyncCommitteeService {
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
}

impl SyncCommitteeService {
    pub(crate) fn new(
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
    ) -> Self {
        Self { signer, beacon, duty_tracker, pubkey_map, config }
    }

    #[tracing::instrument(name = "rvc.orchestrator.produce_sync_messages", skip_all, fields(rvc.slot = slot))]
    pub(crate) async fn maybe_produce_sync_messages(
        &self,
        slot: Slot,
        _epoch: u64,
        _ctx: &SlotContext,
    ) {
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
            match self
                .signer
                .sign_sync_committee_message(
                    &head_root,
                    slot,
                    pubkey,
                    &self.config.fork_schedule,
                    &self.config.genesis_validators_root,
                )
                .await
            {
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
                self.config.timeouts.sync_message,
                self.beacon.submit_sync_committee_messages(&messages),
            )
            .await
            {
                Ok(Ok(_)) => info!(slot, count, "Submitted sync committee messages"),
                Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit sync committee messages"),
                Err(_) => warn!(
                    slot,
                    "Sync committee message submit timed out after {}s",
                    self.config.timeouts.sync_message.as_secs()
                ),
            }
        }
    }

    #[tracing::instrument(name = "rvc.orchestrator.produce_sync_contributions", skip_all, fields(rvc.slot = slot))]
    pub(crate) async fn maybe_produce_sync_contributions(
        &self,
        slot: Slot,
        _epoch: u64,
        _ctx: &SlotContext,
    ) {
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
            let subcommittee_indices: BTreeSet<u64> = duty
                .validator_sync_committee_indices
                .iter()
                .map(|&pos| pos / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT))
                .collect();

            for subcommittee_index in &subcommittee_indices {
                let selection_proof = match self
                    .signer
                    .sign_sync_committee_selection_proof(
                        slot,
                        *subcommittee_index,
                        pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            slot,
                            subcommittee_index,
                            validator_index = duty.validator_index,
                            error = %e,
                            "Failed to sign sync committee selection proof"
                        );
                        continue;
                    }
                };

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
                    self.config.timeouts.sync_contribution,
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
                            self.config.timeouts.sync_contribution.as_secs()
                        );
                        continue;
                    }
                };

                let proof = ContributionAndProof {
                    aggregator_index: duty.validator_index,
                    contribution,
                    selection_proof: selection_proof.to_bytes().to_vec(),
                };

                let sig = match self
                    .signer
                    .sign_contribution_and_proof(
                        &proof,
                        pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            slot,
                            subcommittee_index,
                            validator_index = duty.validator_index,
                            error = %e,
                            "Failed to sign contribution and proof"
                        );
                        continue;
                    }
                };

                signed_proofs.push(SignedContributionAndProof {
                    message: proof,
                    signature: sig.to_bytes().to_vec(),
                });
            }
        }

        if !signed_proofs.is_empty() {
            let count = signed_proofs.len();
            match tokio::time::timeout(
                self.config.timeouts.sync_contribution,
                self.beacon.submit_contribution_and_proofs(&signed_proofs),
            )
            .await
            {
                Ok(Ok(_)) => info!(slot, count, "Submitted sync committee contribution and proofs"),
                Ok(Err(e)) => warn!(slot, error = %e, "Failed to submit contribution and proofs"),
                Err(_) => warn!(
                    slot,
                    "Contribution and proofs submit timed out after {}s",
                    self.config.timeouts.sync_contribution.as_secs()
                ),
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
            if let Some(pk) = utils::find_pubkey(&self.pubkey_map, &duty.pubkey) {
                matching_duties.push(duty.clone());
                matching_pubkeys.push(pk);
            }
        }

        (matching_duties, matching_pubkeys)
    }

    async fn get_head_block_root(&self) -> Option<Root> {
        match tokio::time::timeout(
            self.config.timeouts.sync_message,
            self.beacon.get_block_root("head"),
        )
        .await
        {
            Ok(Ok(response)) => {
                let root_hex = response.data.root;
                match utils::parse_hex_root(&root_hex) {
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
                warn!(
                    "Head block root fetch timed out after {}s",
                    self.config.timeouts.sync_message.as_secs()
                );
                None
            }
        }
    }
}
