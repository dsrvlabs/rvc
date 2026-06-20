use std::collections::BTreeSet;
use std::sync::Arc;

use tracing::{debug, info, warn};

use bn_manager::BeaconNodeClient;
use crypto::logging::TruncatedPubkey;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{ContributionAndProof, SignedContributionAndProof, Slot, SyncCommitteeDuty};
use signer::SignerService;
use sync_service::is_sync_committee_aggregator;
use validator_store::ValidatorStore;

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
    /// D-3: per-validator doppelganger gate.  Mirrors the M-12 check already
    /// present in attestation.rs so that sync messages and contributions
    /// are also suppressed during the post-import doppelganger window.
    validator_store: Arc<ValidatorStore>,
}

impl SyncCommitteeService {
    pub(crate) fn new(
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
        validator_store: Arc<ValidatorStore>,
    ) -> Self {
        Self { signer, beacon, duty_tracker, pubkey_map, config, validator_store }
    }

    #[tracing::instrument(name = "rvc.orchestrator.produce_sync_messages", skip_all, fields(rvc.slot = slot))]
    pub(crate) async fn maybe_produce_sync_messages(
        &self,
        slot: Slot,
        _epoch: u64,
        ctx: &SlotContext,
    ) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
            return;
        }

        // H-5: use the head_root captured once at slot start instead of
        // fetching independently. If the BN failed during capture, skip
        // rather than falling back to a fresh (potentially drifted) fetch.
        let head_root = match ctx.head_root {
            Some(root) => root,
            None => {
                warn!(
                    slot,
                    "Skipping sync committee messages: head_root unavailable in slot context"
                );
                return;
            }
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
        ctx: &SlotContext,
    ) {
        let duties = self.duty_tracker.get_sync_committee_duties(slot).await;
        if duties.is_empty() {
            return;
        }

        let (matching_duties, matching_pubkeys) = self.filter_sync_duties(&duties);
        if matching_duties.is_empty() {
            return;
        }

        // H-5: use the head_root captured once at slot start instead of
        // fetching independently. If the BN failed during capture, skip
        // rather than falling back to a fresh (potentially drifted) fetch.
        let head_root = match ctx.head_root {
            Some(root) => root,
            None => {
                warn!(
                    slot,
                    "Skipping sync committee contributions: head_root unavailable in slot context"
                );
                return;
            }
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
                // D-3: per-validator doppelganger gate (mirrors attestation.rs M-12 check).
                // `pk` is the already-resolved typed PublicKey — use its infallible
                // `to_bytes()` instead of re-decoding the hex string (no fail-open).
                let pk_bytes = pk.to_bytes();
                if !self.validator_store.is_signing_enabled(&pk_bytes) {
                    warn!(
                        pubkey = %TruncatedPubkey::new(&duty.pubkey),
                        "Skipping sync committee duty: validator is inside the \
                         post-import doppelganger window (D-3)"
                    );
                    continue;
                }
                matching_duties.push(duty.clone());
                matching_pubkeys.push(pk);
            }
        }

        (matching_duties, matching_pubkeys)
    }
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use async_trait::async_trait;
    use beacon::{
        AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
        BlockRootData, BlockRootResponse, ConfigSpecResponse, DataResponse,
        ExecutionOptimisticResponse, GenesisResponse, ProduceBlockResponse, ProposerDutiesResponse,
        ProposerPreparation, SignedContributionAndProof as BeaconSignedContributionAndProof,
        StateForkResponse, SubmitAttestationResult, SyncCommitteeContributionResponse,
        SyncCommitteeDutiesResponse, SyncCommitteeMessage as BeaconSyncCommitteeMessage,
        SyncingResponse, ValidatorsResponse, VersionedAggregateAttestation, VersionedAttestation,
        VersionedSignedAggregateAndProof,
    };
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use duty_tracker::DutyTracker;
    use eth_types::{
        ForkSchedule, Root, SignedBeaconBlock, SignedBlindedBeaconBlock,
        SignedValidatorRegistration,
    };
    use signer::SignerService;
    use slashing::SlashingDb;
    use validator_store::{ValidatorConfig, ValidatorStore};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

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
        OrchestratorConfig::new([0u8; 32], create_test_fork_schedule())
    }

    // -----------------------------------------------------------------------
    // ToctouBeacon: tracks get_block_root calls and captures submitted messages.
    //
    // Used to prove that neither phase calls get_block_root after the H-5 fix.
    // The mock returns r_from_bn_hex for any get_block_root call, which is
    // intentionally different from the SlotContext's r_captured. If the
    // production code were to call get_block_root, the counter would become
    // non-zero and the submitted messages would contain the wrong root.
    // -----------------------------------------------------------------------
    struct ToctouBeacon {
        /// Total calls to get_block_root — must be 0 after the fix.
        get_block_root_call_count: Arc<AtomicUsize>,
        /// beacon_block_root values from submitted sync committee messages.
        submitted_roots: Arc<Mutex<Vec<Root>>>,
        /// Root the BN would return for head queries (different from SlotContext's root).
        r_from_bn_hex: String,
        /// Pubkey for the duty entry returned from post_sync_committee_duties.
        duty_pubkey: String,
    }

    #[async_trait]
    impl BeaconNodeClient for ToctouBeacon {
        async fn get_block_root(&self, _block_id: &str) -> Result<BlockRootResponse, BeaconError> {
            self.get_block_root_call_count.fetch_add(1, Ordering::SeqCst);
            Ok(DataResponse { data: BlockRootData { root: self.r_from_bn_hex.clone() } })
        }

        async fn post_sync_committee_duties(
            &self,
            _epoch: u64,
            _validator_indices: &[String],
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
        async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
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
            _validator_indices: &[String],
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
        ) -> Result<ProduceBlockResponse, BeaconError> {
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
            _signed_blinded_block: &SignedBlindedBeaconBlock,
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

    // -----------------------------------------------------------------------
    // Setup helper: creates a SyncCommitteeService with a real BLS key and
    // a ToctouBeacon mock with pre-loaded duties.
    // -----------------------------------------------------------------------
    async fn setup_service(
        beacon: Arc<ToctouBeacon>,
        pk_hex: String,
        pk: crypto::PublicKey,
        sk: SecretKey,
    ) -> SyncCommitteeService {
        setup_service_with_store(
            beacon,
            pk_hex,
            pk,
            sk,
            Arc::new(ValidatorStore::new([0u8; 20], 0)),
        )
        .await
    }

    async fn setup_service_with_store(
        beacon: Arc<ToctouBeacon>,
        pk_hex: String,
        pk: crypto::PublicKey,
        sk: SecretKey,
        validator_store: Arc<ValidatorStore>,
    ) -> SyncCommitteeService {
        // D-3 fail-closed: register the loaded validator (enabled) unless the
        // test already tracks it (e.g. as disabled for the doppelganger-window
        // path). Mirrors startup registration so the per-validator gate permits
        // signing for keys the VC actually loaded.
        if !validator_store.has_validator(&pk.to_bytes()) {
            validator_store.add_validator(ValidatorConfig::new(pk.to_bytes()));
        }
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        // Pre-populate sync committee duties for period 0 (epoch 0 / 256 = 0)
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk_hex, pk);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            validator_store,
        )
    }

    // -----------------------------------------------------------------------
    // RED → GREEN: H-5 TOCTOU fix
    //
    // A buggy implementation fetches head_root independently in each phase.
    // When head advances between t=slot/3 and t=2*slot/3 the two phases would
    // sign with different roots. The fix: both phases read from SlotContext.
    //
    // RED: current code calls get_block_root("head") in each phase → counter > 0
    //      and submitted message has r_from_bn, not r_captured.
    // GREEN: fixed code reads ctx.head_root → counter stays 0,
    //        submitted message has r_captured.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_messages_and_contributions_share_head_root() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        // R_captured: the root pinned at slot-start in SlotContext.
        let r_captured: Root = [0xAA; 32];
        // R_from_bn: what the BN would return for head queries — intentionally different.
        let r_from_bn: Root = [0xBB; 32];
        let r_from_bn_hex = format!("0x{}", hex::encode(r_from_bn));

        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));

        let beacon = Arc::new(ToctouBeacon {
            get_block_root_call_count: get_block_root_call_count.clone(),
            submitted_roots: submitted_roots.clone(),
            r_from_bn_hex,
            duty_pubkey: pk_hex.clone(),
        });

        let service = setup_service(beacon, pk_hex, pk, sk).await;

        // SlotContext constructed once at slot start — this is the fix's contract.
        let ctx = SlotContext { slot: 0, epoch: 0, head_root: Some(r_captured) };

        // Run both sync-committee phases with the same context.
        service.maybe_produce_sync_messages(0, 0, &ctx).await;
        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

        // Neither phase must call get_block_root: head_root is sourced from SlotContext.
        assert_eq!(
            get_block_root_call_count.load(Ordering::SeqCst),
            0,
            "H-5: neither sync-committee phase must call get_block_root; \
             head_root must come from SlotContext, not a fresh BN fetch"
        );

        // The messages phase must submit messages with the captured root, not the BN root.
        let roots = submitted_roots.lock().unwrap();
        assert!(
            !roots.is_empty(),
            "Expected sync committee messages to be submitted; \
             check that the test key is in the KeyManager and pubkey_map"
        );
        for root in roots.iter() {
            assert_eq!(
                *root, r_captured,
                "beacon_block_root must equal SlotContext.head_root (r_captured=0xaa…), \
                 not the BN's head root (r_from_bn=0xbb…)"
            );
        }
    }

    // -----------------------------------------------------------------------
    // None head_root: messages phase skips gracefully without any BN call.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_messages_skip_when_head_root_none() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));

        let beacon = Arc::new(ToctouBeacon {
            get_block_root_call_count: get_block_root_call_count.clone(),
            submitted_roots: submitted_roots.clone(),
            r_from_bn_hex: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            duty_pubkey: pk_hex.clone(),
        });

        let service = setup_service(beacon, pk_hex, pk, sk).await;

        // head_root = None simulates a BN failure during SlotContext::capture.
        let ctx = SlotContext { slot: 0, epoch: 0, head_root: None };

        service.maybe_produce_sync_messages(0, 0, &ctx).await;

        assert_eq!(
            get_block_root_call_count.load(Ordering::SeqCst),
            0,
            "messages phase must not fall back to a BN fetch when head_root is None"
        );
        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "no messages must be submitted when head_root is None"
        );
    }

    // -----------------------------------------------------------------------
    // None head_root: contributions phase skips gracefully without any BN call.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_contributions_skip_when_head_root_none() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));
        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));

        let beacon = Arc::new(ToctouBeacon {
            get_block_root_call_count: get_block_root_call_count.clone(),
            submitted_roots: submitted_roots.clone(),
            r_from_bn_hex: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            duty_pubkey: pk_hex.clone(),
        });

        let service = setup_service(beacon, pk_hex, pk, sk).await;

        // head_root = None simulates a BN failure during SlotContext::capture.
        let ctx = SlotContext { slot: 0, epoch: 0, head_root: None };

        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

        assert_eq!(
            get_block_root_call_count.load(Ordering::SeqCst),
            0,
            "contributions phase must not fall back to a BN fetch when head_root is None"
        );
    }

    // -----------------------------------------------------------------------
    // D-3: sync message path skips validators whose is_signing_enabled=false.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_sync_message_skipped_when_validator_disabled() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let pk_bytes: [u8; 48] = pk.to_bytes();

        let submitted_roots = Arc::new(Mutex::new(Vec::<Root>::new()));
        let get_block_root_call_count = Arc::new(AtomicUsize::new(0));

        let beacon = Arc::new(ToctouBeacon {
            get_block_root_call_count: get_block_root_call_count.clone(),
            submitted_roots: submitted_roots.clone(),
            r_from_bn_hex: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            duty_pubkey: pk_hex.clone(),
        });

        // Set up a store where the validator is disabled (doppelganger window).
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut config = ValidatorConfig::new(pk_bytes);
        config.enabled = false;
        store.add_validator(config);

        let service = setup_service_with_store(beacon, pk_hex, pk, sk, store).await;

        let ctx = SlotContext { slot: 0, epoch: 0, head_root: Some([0xAA; 32]) };
        service.maybe_produce_sync_messages(0, 0, &ctx).await;

        // No messages must be submitted for a disabled validator.
        assert!(
            submitted_roots.lock().unwrap().is_empty(),
            "D-3: sync committee message must not be produced when is_signing_enabled=false"
        );
    }

    // -----------------------------------------------------------------------
    // D-3: sync contribution path skips validators whose is_signing_enabled=false.
    //
    // ContribGateBeacon: a beacon that returns a valid contribution and tracks
    // how many times `get_sync_committee_contribution` is called.  If the D-3
    // gate fires correctly (filter_sync_duties skips the disabled validator),
    // the loop body is never entered and the contribution endpoint is never
    // reached.  If the gate is absent (RED state), the loop runs, the selection
    // proof is signed, and — because we arrange for the key to be deterministically
    // selected as a sync committee aggregator — `get_sync_committee_contribution`
    // is called, incrementing the counter.
    // -----------------------------------------------------------------------

    struct ContribGateBeacon {
        /// Counts calls to `get_sync_committee_contribution`.
        /// Must be 0 in GREEN (gate fires); > 0 in RED (validator passes filter
        /// AND is selected as aggregator).
        contrib_fetch_calls: Arc<AtomicUsize>,
        duty_pubkey: String,
    }

    #[async_trait]
    impl BeaconNodeClient for ContribGateBeacon {
        async fn get_block_root(&self, _: &str) -> Result<BlockRootResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }

        async fn post_sync_committee_duties(
            &self,
            _epoch: u64,
            _validator_indices: &[String],
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
            _: &[BeaconSyncCommitteeMessage],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }

        async fn get_sync_committee_contribution(
            &self,
            slot: u64,
            subcommittee_index: u64,
            _beacon_block_root: &str,
        ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
            self.contrib_fetch_calls.fetch_add(1, Ordering::SeqCst);
            // Return a valid (stub) contribution so the signing path continues
            // and we can observe whether `submit_contribution_and_proofs` is reached.
            Ok(DataResponse {
                data: eth_types::SyncCommitteeContribution {
                    slot,
                    beacon_block_root: [0xAA; 32],
                    subcommittee_index,
                    aggregation_bits: vec![0xFF, 0x01],
                    signature: vec![0u8; 96],
                },
            })
        }

        async fn submit_contribution_and_proofs(
            &self,
            _: &[BeaconSignedContributionAndProof],
        ) -> Result<(), BeaconError> {
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
        async fn get_fork(&self, _: &str) -> Result<StateForkResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_validators(&self, _: &[String]) -> Result<ValidatorsResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_attester_duties(
            &self,
            _: u64,
            _: &[String],
        ) -> Result<AttesterDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_proposer_duties(&self, _: u64) -> Result<ProposerDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn produce_block_v3(
            &self,
            _: u64,
            _: &str,
            _: Option<&str>,
            _: Option<u64>,
        ) -> Result<ProduceBlockResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn publish_block(&self, _: &SignedBeaconBlock, _: &str) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn publish_blinded_block(
            &self,
            _: &SignedBlindedBeaconBlock,
            _: &str,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_attestation_data(
            &self,
            _: u64,
            _: u64,
        ) -> Result<AttestationDataResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn submit_attestation(
            &self,
            _: &VersionedAttestation,
        ) -> Result<SubmitAttestationResult, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_aggregate_attestation(
            &self,
            _: u64,
            _: &str,
            _: Option<u64>,
        ) -> Result<VersionedAggregateAttestation, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn submit_aggregate_and_proofs(
            &self,
            _: &VersionedSignedAggregateAndProof,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn prepare_beacon_proposer(
            &self,
            _: &[ProposerPreparation],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn submit_beacon_committee_subscriptions(
            &self,
            _: &[BeaconCommitteeSubscription],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn register_validators(
            &self,
            _: &[SignedValidatorRegistration],
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

    /// Returns a `(SecretKey, PublicKey)` pair that is deterministically
    /// selected as a sync committee aggregator for slot=0 / subcommittee=0
    /// with the test fork schedule (genesis_fork_version=[0,0,0,1],
    /// genesis_validators_root=[0u8;32]).
    ///
    /// The selection criterion is `sha256(bls_sig_bytes)[0..8] as u64 % 8 == 0`.
    /// Expected to terminate in ~8 iterations on average.
    fn find_aggregator_sk() -> (SecretKey, crypto::PublicKey) {
        use eth_types::{
            ForkName, SyncAggregatorSelectionData, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        };

        let fork_schedule = create_test_fork_schedule();
        let genesis_validators_root: eth_types::Root = [0u8; 32];

        // Slot 0 falls in epoch 0, which is Phase0 (altair_fork_epoch = 10).
        let fork_name = ForkName::from_epoch(0, &fork_schedule);
        let fork_version = fork_name.fork_version(&fork_schedule);
        let domain = crypto::compute_domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            fork_version,
            genesis_validators_root,
        );
        let selection_data = SyncAggregatorSelectionData { slot: 0, subcommittee_index: 0 };
        let signing_root = crypto::compute_signing_root(&selection_data, domain);

        loop {
            let sk = SecretKey::generate();
            let pk = sk.public_key();
            // `LocalSigner::sign` calls `sk.sign(signing_root)` internally.
            // Mirror that directly: `SecretKey::sign(&self, message: &[u8])`.
            let sig = sk.sign(&signing_root);
            let sig_bytes = sig.to_bytes();
            if is_sync_committee_aggregator(&sig_bytes) {
                return (sk, pk);
            }
        }
    }

    #[tokio::test]
    async fn test_sync_contribution_skipped_when_validator_disabled() {
        // Find a BLS key that is deterministically selected as a sync committee
        // aggregator for slot=0 / subcommittee=0.  This ensures the test is
        // meaningful in RED state: when the D-3 gate is absent, the selection
        // proof is signed, `is_sync_committee_aggregator` returns true, and
        // `get_sync_committee_contribution` is reached — incrementing the counter.
        let (sk, pk) = find_aggregator_sk();
        let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));
        let pk_bytes: [u8; 48] = pk.to_bytes();

        let contrib_fetch_calls = Arc::new(AtomicUsize::new(0));
        let beacon = Arc::new(ContribGateBeacon {
            contrib_fetch_calls: contrib_fetch_calls.clone(),
            duty_pubkey: pk_hex.clone(),
        });

        // Validator is disabled (inside post-import doppelganger window).
        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        let mut config = ValidatorConfig::new(pk_bytes);
        config.enabled = false;
        store.add_validator(config);

        // Build the service with this beacon and the disabled-validator store.
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let local_signer = LocalSigner::new(key_manager);
        let composite = Arc::new(CompositeSigner::new(local_signer));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

        let mut map = HashMap::new();
        map.insert(pk_hex, pk);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

        let service = SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            pubkey_map,
            create_test_config(),
            store,
        );

        let ctx = SlotContext { slot: 0, epoch: 0, head_root: Some([0xAA; 32]) };
        service.maybe_produce_sync_contributions(0, 0, &ctx).await;

        // In GREEN: filter_sync_duties returns [] because the validator is
        // disabled → the loop body is never entered → get_sync_committee_contribution
        // is NEVER called → count stays 0.
        //
        // In RED (gate removed): the validator passes the filter → selection
        // proof is signed → is_sync_committee_aggregator returns true (the key
        // was chosen to guarantee this) → get_sync_committee_contribution IS called
        // → count > 0 → assertion fails.
        assert_eq!(
            contrib_fetch_calls.load(Ordering::SeqCst),
            0,
            "D-3: get_sync_committee_contribution must not be called for a disabled \
             validator (is_signing_enabled=false)"
        );
    }
}
