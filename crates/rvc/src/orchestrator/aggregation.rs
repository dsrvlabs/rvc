use std::sync::Arc;

use tracing::{debug, info, info_span, warn, Instrument};

use beacon::{VersionedAggregateAttestation, VersionedSignedAggregateAndProof};
use bn_manager::BeaconNodeClient;
use crypto::logging::TruncatedPubkey;
use duty_tracker::DutyTracker;
use eth_types::{
    AggregateAndProof, ElectraAggregateAndProof, ForkName, SignedAggregateAndProof,
    SignedElectraAggregateAndProof, Slot,
};
use metrics::definitions::{attestation_status, RVC_AGGREGATIONS_TOTAL};
use signer::{is_aggregator, SignerService};
use tree_hash::TreeHash;

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::utils;

pub(crate) struct AggregationService {
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
}

impl AggregationService {
    pub(crate) fn new(
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
    ) -> Self {
        Self { signer, beacon, duty_tracker, pubkey_map, config }
    }

    #[tracing::instrument(name = "rvc.orchestrator.produce_aggregations", skip_all, fields(rvc.slot = slot, rvc.epoch = epoch))]
    pub(crate) async fn maybe_produce_aggregations(&self, slot: Slot, epoch: u64) {
        let duties =
            match utils::get_duties_for_slot(&self.pubkey_map, &self.duty_tracker, slot).await {
                Ok(d) => d,
                Err(_) => return,
            };

        if duties.is_empty() {
            return;
        }

        let fork_name = ForkName::from_epoch(epoch, &self.config.fork_schedule);
        let is_electra = fork_name >= ForkName::Electra;

        let mut pre_electra_aggregates: Vec<SignedAggregateAndProof> = Vec::new();
        let mut electra_aggregates: Vec<SignedElectraAggregateAndProof> = Vec::new();
        let mut source_validators: Vec<String> = Vec::new();

        let fork_label = if fork_name >= ForkName::Fulu {
            "fulu"
        } else if is_electra {
            "electra"
        } else {
            "pre_electra"
        };

        for duty in &duties {
            let agg_span = info_span!(
                "rvc.aggregation.produce",
                rvc.slot = slot,
                rvc.validator_index = %duty.validator_index,
                rvc.pubkey = %TruncatedPubkey::new(&duty.pubkey),
                rvc.aggregation.fork = fork_label,
            );

            let committee_length: u64 = match duty.committee_length.parse() {
                Ok(c) => c,
                Err(_) => continue,
            };

            let pubkey = match utils::find_pubkey(&self.pubkey_map, &duty.pubkey) {
                Some(pk) => pk,
                None => continue,
            };

            let selection_proof = match self
                .signer
                .sign_selection_proof(
                    slot,
                    &pubkey,
                    &self.config.fork_schedule,
                    &self.config.genesis_validators_root,
                )
                .instrument(agg_span.clone())
                .await
            {
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
            source_validators.push(duty.validator_index.clone());

            // Compute attestation data root for fetching the aggregate
            let committee_index: u64 = match duty.committee_index.parse() {
                Ok(c) => c,
                Err(_) => continue,
            };

            let attestation_data_response = match tokio::time::timeout(
                self.config.timeouts.aggregate_fetch,
                self.beacon.get_attestation_data(slot, committee_index),
            )
            .instrument(agg_span.clone())
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
                match utils::convert_attestation_data(&attestation_data_response.data) {
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
            // Electra: pass committee_index for per-committee aggregation
            let electra_committee_index = if is_electra { Some(committee_index) } else { None };
            let aggregate = match tokio::time::timeout(
                self.config.timeouts.aggregate_fetch,
                self.beacon.get_aggregate_attestation(
                    slot,
                    &att_data_root_hex,
                    electra_committee_index,
                ),
            )
            .instrument(agg_span.clone())
            .await
            {
                Ok(Ok(resp)) => resp,
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

            if is_electra {
                let electra_agg = match aggregate {
                    VersionedAggregateAttestation::Electra(a)
                    | VersionedAggregateAttestation::Fulu(a) => a,
                    _ => {
                        warn!(
                            slot,
                            validator_index = %duty.validator_index,
                            "Expected Electra aggregate but got pre-Electra"
                        );
                        RVC_AGGREGATIONS_TOTAL
                            .with_label_values(&[attestation_status::FAILED])
                            .inc();
                        continue;
                    }
                };
                let aggregate_and_proof = ElectraAggregateAndProof {
                    aggregator_index,
                    aggregate: electra_agg,
                    selection_proof: selection_proof.to_bytes().to_vec(),
                };
                if let Err(e) = aggregate_and_proof.try_tree_hash_root() {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        error = %e,
                        "Skipping aggregate with invalid aggregation bits"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    continue;
                }
                let signature = match self
                    .signer
                    .sign_electra_aggregate_and_proof(
                        &aggregate_and_proof,
                        &pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .instrument(agg_span.clone())
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            slot,
                            validator_index = %duty.validator_index,
                            error = %e,
                            "Failed to sign Electra aggregate and proof"
                        );
                        RVC_AGGREGATIONS_TOTAL
                            .with_label_values(&[attestation_status::FAILED])
                            .inc();
                        continue;
                    }
                };
                electra_aggregates.push(SignedElectraAggregateAndProof {
                    message: aggregate_and_proof,
                    signature: signature.to_bytes().to_vec(),
                });
            } else {
                let pre_electra_agg = match aggregate {
                    VersionedAggregateAttestation::PreElectra(a) => a,
                    _ => {
                        warn!(
                            slot,
                            validator_index = %duty.validator_index,
                            "Expected pre-Electra aggregate but got Electra"
                        );
                        RVC_AGGREGATIONS_TOTAL
                            .with_label_values(&[attestation_status::FAILED])
                            .inc();
                        continue;
                    }
                };
                let aggregate_and_proof = AggregateAndProof {
                    aggregator_index,
                    aggregate: pre_electra_agg,
                    selection_proof: selection_proof.to_bytes().to_vec(),
                };
                if let Err(e) = aggregate_and_proof.try_tree_hash_root() {
                    warn!(
                        slot,
                        validator_index = %duty.validator_index,
                        error = %e,
                        "Skipping aggregate with invalid aggregation bits"
                    );
                    RVC_AGGREGATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
                    continue;
                }
                let signature = match self
                    .signer
                    .sign_aggregate_and_proof(
                        &aggregate_and_proof,
                        &pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .instrument(agg_span.clone())
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            slot,
                            validator_index = %duty.validator_index,
                            error = %e,
                            "Failed to sign aggregate and proof"
                        );
                        RVC_AGGREGATIONS_TOTAL
                            .with_label_values(&[attestation_status::FAILED])
                            .inc();
                        continue;
                    }
                };
                pre_electra_aggregates.push(SignedAggregateAndProof {
                    message: aggregate_and_proof,
                    signature: signature.to_bytes().to_vec(),
                });
            }
        }

        if !pre_electra_aggregates.is_empty() {
            let count = pre_electra_aggregates.len();
            let source_validators_str = source_validators.join(",");

            let submit_span = info_span!(
                "rvc.aggregation.submit",
                rvc.slot = slot,
                rvc.aggregation.count = count,
                rvc.aggregation.source_validators = %source_validators_str,
            );

            let versioned = VersionedSignedAggregateAndProof::PreElectra(pre_electra_aggregates);
            match tokio::time::timeout(
                self.config.timeouts.aggregate_submit,
                self.beacon.submit_aggregate_and_proofs(&versioned),
            )
            .instrument(submit_span)
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
                        self.config.timeouts.aggregate_submit.as_secs()
                    );
                    RVC_AGGREGATIONS_TOTAL
                        .with_label_values(&[attestation_status::FAILED])
                        .inc_by(count as u64);
                }
            }
        }

        if !electra_aggregates.is_empty() {
            let count = electra_aggregates.len();
            let source_validators_str = source_validators.join(",");

            let submit_span = info_span!(
                "rvc.aggregation.submit",
                rvc.slot = slot,
                rvc.aggregation.count = count,
                rvc.aggregation.source_validators = %source_validators_str,
            );

            let versioned = if fork_name >= ForkName::Fulu {
                VersionedSignedAggregateAndProof::Fulu(electra_aggregates)
            } else {
                VersionedSignedAggregateAndProof::Electra(electra_aggregates)
            };
            match tokio::time::timeout(
                self.config.timeouts.aggregate_submit,
                self.beacon.submit_aggregate_and_proofs(&versioned),
            )
            .instrument(submit_span)
            .await
            {
                Ok(Ok(_)) => {
                    info!(slot, count, "Submitted Electra aggregate and proofs");
                    RVC_AGGREGATIONS_TOTAL
                        .with_label_values(&[attestation_status::SUCCESS])
                        .inc_by(count as u64);
                }
                Ok(Err(e)) => {
                    warn!(slot, error = %e, "Failed to submit Electra aggregate and proofs");
                    RVC_AGGREGATIONS_TOTAL
                        .with_label_values(&[attestation_status::FAILED])
                        .inc_by(count as u64);
                }
                Err(_) => {
                    warn!(
                        slot,
                        "Electra aggregate and proofs submit timed out after {}s",
                        self.config.timeouts.aggregate_submit.as_secs()
                    );
                    RVC_AGGREGATIONS_TOTAL
                        .with_label_values(&[attestation_status::FAILED])
                        .inc_by(count as u64);
                }
            }
        }
    }
}
