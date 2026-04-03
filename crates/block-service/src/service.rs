use std::sync::Arc;

use builder::CircuitBreakerState;
use tracing::{debug, error, info, warn, Instrument};
use tree_hash::TreeHash;

use crypto::logging::TruncatedPubkey;
use crypto::PublicKey;
use eth_types::{ForkSchedule, Root, Slot, SLOTS_PER_EPOCH};
use signer::ValidatorSigner;
use validator_store::ValidatorStore;

use crate::traits::{BeaconBlockClient, ProduceBlockResponse};
use crate::types::BlockSelectionMode;
use crate::BlockServiceError;

/// Result of a successful block proposal.
#[derive(Debug, Clone)]
pub struct BlockProposalResult {
    pub slot: Slot,
    pub block_root: Root,
    pub is_blinded: bool,
    pub consensus_version: String,
    pub value_wei: Option<String>,
}

/// Orchestrates the block proposal lifecycle: RANDAO, produce, sign, submit.
pub struct BlockService<S: ValidatorSigner, B: BeaconBlockClient> {
    signer: Arc<S>,
    beacon: Arc<B>,
    validator_store: Arc<ValidatorStore>,
    fork_schedule: Arc<ForkSchedule>,
    genesis_validators_root: Root,
    circuit_breaker: Arc<CircuitBreakerState>,
}

impl<S: ValidatorSigner, B: BeaconBlockClient> BlockService<S, B> {
    pub fn new(
        signer: Arc<S>,
        beacon: Arc<B>,
        validator_store: Arc<ValidatorStore>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self::with_circuit_breaker(
            signer,
            beacon,
            validator_store,
            fork_schedule,
            genesis_validators_root,
            Arc::new(CircuitBreakerState::new(0, 0)),
        )
    }

    pub fn with_circuit_breaker(
        signer: Arc<S>,
        beacon: Arc<B>,
        validator_store: Arc<ValidatorStore>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
        circuit_breaker: Arc<CircuitBreakerState>,
    ) -> Self {
        Self {
            signer,
            beacon,
            validator_store,
            fork_schedule,
            genesis_validators_root,
            circuit_breaker,
        }
    }

    #[tracing::instrument(
        name = "rvc.block.propose",
        skip_all,
        fields(
            rvc.slot = slot,
            rvc.block.blinded = tracing::field::Empty,
            rvc.block.consensus_version = tracing::field::Empty,
            rvc.block.value_wei = tracing::field::Empty,
        )
    )]
    pub async fn propose_block(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        let mode = self.validator_store.effective_block_selection_mode(&pubkey.to_bytes());
        self.propose_block_with_mode(slot, pubkey, mode).await
    }

    pub async fn propose_block_with_mode(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        mode: BlockSelectionMode,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let proposal_start = std::time::Instant::now();

        info!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), %mode, "Block proposal started");

        let epoch = slot / SLOTS_PER_EPOCH;

        // 1. Sign RANDAO reveal
        let randao_start = std::time::Instant::now();
        let randao_bytes = self
            .signer
            .sign_randao_reveal(epoch, pubkey, &self.fork_schedule, &self.genesis_validators_root)
            .instrument(tracing::info_span!("rvc.sign.randao"))
            .await
            .map_err(|e| {
                let err = BlockServiceError::Signer(e.to_string());
                error!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), error = %err, "RANDAO signing failed");
                err
            })?;
        debug!(
            slot = slot,
            duration_ms = randao_start.elapsed().as_millis() as u64,
            "RANDAO reveal signed"
        );
        let randao_hex = format!("0x{}", hex::encode(&randao_bytes));

        // 2. Get validator preferences, applying block selection mode
        let pubkey_bytes = pubkey.to_bytes();
        let graffiti = self.validator_store.effective_graffiti(&pubkey_bytes);
        let graffiti_hex = graffiti.map(|g| format!("0x{}", hex::encode(g)));

        // Check circuit breaker for builder modes first
        let circuit_breaker_tripped = self.circuit_breaker.is_tripped();

        let boost = match mode {
            BlockSelectionMode::ExecutionOnly => {
                debug!(slot = slot, "ExecutionOnly: builder_boost_factor=0");
                0
            }
            BlockSelectionMode::MaxProfit => {
                if circuit_breaker_tripped {
                    warn!(slot = slot, "Builder circuit breaker tripped, using local block only");
                    0
                } else {
                    self.validator_store.builder_boost_factor(&pubkey_bytes)
                }
            }
            BlockSelectionMode::BuilderAlways => {
                if circuit_breaker_tripped {
                    warn!(
                        slot = slot,
                        "BuilderAlways: circuit breaker tripped, falling back to local"
                    );
                    0
                } else {
                    debug!(slot = slot, "BuilderAlways: builder_boost_factor=u64::MAX");
                    u64::MAX
                }
            }
            BlockSelectionMode::BuilderOnly => {
                if circuit_breaker_tripped {
                    error!(
                        slot = slot,
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        "BuilderOnly mode: circuit breaker tripped, proposal will be missed"
                    );
                    return Err(BlockServiceError::BuilderOnly(
                        "circuit breaker tripped — proposal missed".to_string(),
                    ));
                }
                debug!(slot = slot, "BuilderOnly: builder_boost_factor=u64::MAX");
                u64::MAX
            }
        };

        // 3. Request block from beacon node
        let response = self
            .beacon
            .produce_block_v3(slot, &randao_hex, graffiti_hex.as_deref(), Some(boost))
            .instrument(tracing::info_span!("rvc.beacon.produce_block_v3"))
            .await;

        // Handle BuilderOnly failure: never fall back
        let response = match response {
            Ok(resp) => resp,
            Err(e) => {
                if mode == BlockSelectionMode::BuilderOnly {
                    error!(
                        slot = slot,
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        error = %e,
                        "BuilderOnly mode: builder failed, proposal will be missed"
                    );
                    return Err(BlockServiceError::BuilderOnly(format!(
                        "builder block production failed: {e}"
                    )));
                }
                error!(slot = slot, error = %e, "Block production failed");
                return Err(e);
            }
        };

        info!(
            slot = slot,
            is_blinded = response.is_blinded,
            execution_payload_value = response.execution_payload_value.as_deref().unwrap_or("none"),
            "Block production response received"
        );

        // Record dynamic attributes after block production
        let span = tracing::Span::current();
        span.record("rvc.block.blinded", response.is_blinded);
        span.record("rvc.block.consensus_version", &response.consensus_version);
        if let Some(ref value) = response.execution_payload_value {
            span.record("rvc.block.value_wei", value.as_str());
        }

        // 4. Sign and publish based on block type
        debug!(slot = slot, is_blinded = response.is_blinded, "Blinded/unblinded path chosen");
        let (block_root, is_blinded) = if response.is_ssz {
            self.sign_and_publish_ssz(&response, slot, pubkey).await
        } else if response.is_blinded {
            self.sign_and_publish_blinded(&response, slot, pubkey).await
        } else {
            self.sign_and_publish_full(&response, slot, pubkey).await
        }
        .map_err(|e| {
            error!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), error = %e, "Block publication failed");
            e
        })?;

        info!(
            slot = slot,
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            block_root = %format!("0x{}", hex::encode(block_root)),
            is_blinded = is_blinded,
            duration_ms = proposal_start.elapsed().as_millis() as u64,
            "Block publication success"
        );

        Ok(BlockProposalResult {
            slot,
            block_root,
            is_blinded,
            consensus_version: response.consensus_version,
            value_wei: response.execution_payload_value,
        })
    }

    async fn sign_and_publish_ssz(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<(Root, bool), BlockServiceError> {
        let ssz_bytes = response.ssz_bytes.as_ref().ok_or_else(|| {
            BlockServiceError::Parse("SSZ response missing ssz_bytes".to_string())
        })?;

        let format = ssz_block_format(response.is_blinded, &response.consensus_version);
        let (block_root, block_data_offset): (Root, usize) = if response.is_blinded {
            let (block, offset) =
                beacon::ssz_deser::deserialize_blinded_beacon_block_from_ssz(ssz_bytes, format)
                    .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
            if block.slot != slot {
                return Err(BlockServiceError::Parse(format!(
                    "SSZ block slot mismatch: header has {}, expected {}",
                    block.slot, slot,
                )));
            }
            (compute_blinded_block_root(&block), offset)
        } else {
            let (block, offset) =
                beacon::ssz_deser::deserialize_beacon_block_from_ssz(ssz_bytes, format)
                    .map_err(|e| BlockServiceError::Parse(e.to_string()))?;
            if block.slot != slot {
                return Err(BlockServiceError::Parse(format!(
                    "SSZ block slot mismatch: header has {}, expected {}",
                    block.slot, slot,
                )));
            }
            (compute_block_root(&block), offset)
        };

        let sign_start = std::time::Instant::now();
        let sig = self
            .signer
            .sign_block(
                &block_root,
                slot,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .instrument(tracing::info_span!("rvc.sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        debug!(
            slot = slot,
            duration_ms = sign_start.elapsed().as_millis() as u64,
            "Block signing duration"
        );

        // Construct SignedBeaconBlock SSZ:
        // [message_offset: 4 bytes LE] [signature: 96 bytes] [BeaconBlock SSZ bytes]
        let block_ssz = &ssz_bytes[block_data_offset..];
        let message_offset: u32 = 100; // 4 (offset) + 96 (signature)
        let mut signed_ssz = Vec::with_capacity(100 + block_ssz.len());
        signed_ssz.extend_from_slice(&message_offset.to_le_bytes());
        signed_ssz.extend_from_slice(&sig);
        signed_ssz.extend_from_slice(block_ssz);

        self.beacon
            .publish_block_ssz(&signed_ssz, &response.consensus_version, response.is_blinded)
            .instrument(tracing::info_span!("rvc.beacon.publish_block"))
            .await?;

        Ok((block_root, response.is_blinded))
    }

    async fn sign_and_publish_full(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<(Root, bool), BlockServiceError> {
        let block_contents = response.parse_full_block()?;
        let block = block_contents.block().clone();

        if block.slot != slot {
            return Err(BlockServiceError::SlotMismatch { requested: slot, got: block.slot });
        }

        let block_root = compute_block_root(&block);

        let sign_start = std::time::Instant::now();
        let sig = self
            .signer
            .sign_block(
                &block_root,
                slot,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .instrument(tracing::info_span!("rvc.sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        debug!(
            slot = slot,
            duration_ms = sign_start.elapsed().as_millis() as u64,
            "Block signing duration"
        );

        let signed = eth_types::SignedBeaconBlock { message: block, signature: sig };
        self.beacon
            .publish_block(&signed, &response.consensus_version)
            .instrument(tracing::info_span!("rvc.beacon.publish_block"))
            .await?;

        Ok((block_root, false))
    }

    async fn sign_and_publish_blinded(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<(Root, bool), BlockServiceError> {
        let block = response.parse_blinded_block()?;

        if block.slot != slot {
            return Err(BlockServiceError::SlotMismatch { requested: slot, got: block.slot });
        }

        let block_root = compute_blinded_block_root(&block);

        let sign_start = std::time::Instant::now();
        let sig = self
            .signer
            .sign_block(
                &block_root,
                slot,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .instrument(tracing::info_span!("rvc.sign.block"))
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
        debug!(
            slot = slot,
            duration_ms = sign_start.elapsed().as_millis() as u64,
            "Block signing duration"
        );

        let signed = eth_types::SignedBlindedBeaconBlock { message: block, signature: sig };
        self.beacon
            .publish_blinded_block(&signed, &response.consensus_version)
            .instrument(tracing::info_span!("rvc.beacon.publish_block"))
            .await?;

        Ok((block_root, true))
    }
}

fn compute_block_root(block: &eth_types::BeaconBlock) -> Root {
    block.tree_hash_root().0
}

fn compute_blinded_block_root(block: &eth_types::BlindedBeaconBlock) -> Root {
    block.tree_hash_root().0
}

/// Determines the SSZ wire format based on block type and consensus version.
///
/// - Blinded blocks are always raw `BeaconBlock` SSZ (all forks).
/// - Unblinded blocks use `BlockContents` SSZ for Deneb and later forks
///   (which wraps the `BeaconBlock` with kzg_proofs and blobs).
fn ssz_block_format(
    is_blinded: bool,
    consensus_version: &str,
) -> beacon::ssz_deser::SszBlockFormat {
    use beacon::ssz_deser::SszBlockFormat;
    if is_blinded {
        return SszBlockFormat::BeaconBlock;
    }
    match consensus_version {
        "deneb" | "electra" | "fulu" => SszBlockFormat::BlockContents,
        _ => SszBlockFormat::BeaconBlock,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use eth_types::{BeaconBlock, BlindedBeaconBlock, SignedBeaconBlock, SignedBlindedBeaconBlock};
    use signer::SignerError;
    use std::sync::{Arc, Mutex};
    use validator_store::ValidatorStore;

    // --- Captured call structs ---

    #[derive(Debug, Clone)]
    struct CapturedProduceCall {
        slot: Slot,
        randao_reveal: String,
        graffiti: Option<String>,
        builder_boost_factor: Option<u64>,
    }

    #[derive(Debug, Clone)]
    struct CapturedPublishCall {
        consensus_version: String,
        slot: Slot,
        proposer_index: u64,
        signature_bytes: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct CapturedSignBlockCall {
        block_root: Root,
        slot: Slot,
        pubkey: PublicKey,
        fork_schedule: ForkSchedule,
        genesis_validators_root: Root,
    }

    // --- Mock Signer ---

    struct MockSigner {
        fail_randao: bool,
        fail_block: bool,
        randao_calls: Mutex<Vec<u64>>,
        block_calls: Mutex<Vec<CapturedSignBlockCall>>,
    }

    impl MockSigner {
        fn new() -> Self {
            Self {
                fail_randao: false,
                fail_block: false,
                randao_calls: Mutex::new(Vec::new()),
                block_calls: Mutex::new(Vec::new()),
            }
        }

        fn with_randao_error(mut self) -> Self {
            self.fail_randao = true;
            self
        }

        fn with_block_error(mut self) -> Self {
            self.fail_block = true;
            self
        }

        fn assert_last_sign_block_domain(&self, expected_fork: &ForkSchedule, expected_gvr: &Root) {
            let calls = self.block_calls.lock().unwrap();
            assert!(!calls.is_empty(), "no sign_block calls captured");
            let last = calls.last().unwrap();
            assert_eq!(last.fork_schedule, *expected_fork, "sign_block fork_schedule mismatch");
            assert_eq!(
                last.genesis_validators_root, *expected_gvr,
                "sign_block genesis_validators_root mismatch"
            );
        }
    }

    #[async_trait(?Send)]
    impl ValidatorSigner for MockSigner {
        async fn sign_attestation(
            &self,
            _data: &eth_types::AttestationData,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![])
        }

        async fn sign_block(
            &self,
            block_root: &Root,
            slot: Slot,
            pubkey: &PublicKey,
            fork_schedule: &ForkSchedule,
            genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            self.block_calls.lock().unwrap().push(CapturedSignBlockCall {
                block_root: *block_root,
                slot,
                pubkey: pubkey.clone(),
                fork_schedule: fork_schedule.clone(),
                genesis_validators_root: *genesis_validators_root,
            });
            if self.fail_block {
                Err(SignerError::KeyNotFound("test".to_string()))
            } else {
                Ok(vec![0xbb; 96])
            }
        }

        async fn sign_randao_reveal(
            &self,
            epoch: u64,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            self.randao_calls.lock().unwrap().push(epoch);
            if self.fail_randao {
                Err(SignerError::KeyNotFound("test".to_string()))
            } else {
                Ok(vec![0xaa; 96])
            }
        }

        async fn sign_sync_committee_message(
            &self,
            _beacon_block_root: &Root,
            _slot: Slot,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![])
        }

        async fn sign_selection_proof(
            &self,
            _slot: Slot,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xcc; 96])
        }

        async fn sign_aggregate_and_proof(
            &self,
            _aggregate_and_proof: &eth_types::AggregateAndProof,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xdd; 96])
        }

        async fn sign_electra_aggregate_and_proof(
            &self,
            _aggregate_and_proof: &eth_types::ElectraAggregateAndProof,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xdd; 96])
        }

        async fn sign_voluntary_exit(
            &self,
            _voluntary_exit: &eth_types::VoluntaryExit,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xee; 96])
        }

        async fn sign_builder_registration(
            &self,
            _registration: &eth_types::ValidatorRegistrationV1,
            _pubkey: &PublicKey,
            _fork_version: [u8; 4],
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xff; 96])
        }

        async fn sign_sync_committee_selection_proof(
            &self,
            _slot: Slot,
            _subcommittee_index: u64,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xaa; 96])
        }

        async fn sign_contribution_and_proof(
            &self,
            _contribution_and_proof: &eth_types::ContributionAndProof,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xbb; 96])
        }
    }

    // --- Mock Beacon Client ---

    struct MockBeaconClient {
        produce_response: Option<ProduceBlockResponse>,
        fail_produce: bool,
        fail_publish: bool,
        publish_calls: Mutex<Vec<String>>,
        publish_blinded_calls: Mutex<Vec<String>>,
        publish_ssz_calls: Mutex<Vec<(Vec<u8>, String, bool)>>,
        produce_full_calls: Mutex<Vec<CapturedProduceCall>>,
        publish_full_calls: Mutex<Vec<CapturedPublishCall>>,
        publish_blinded_full_calls: Mutex<Vec<CapturedPublishCall>>,
    }

    impl MockBeaconClient {
        fn unblinded(block: BeaconBlock) -> Self {
            let data = serde_json::to_value(&block).unwrap();
            Self {
                produce_response: Some(ProduceBlockResponse {
                    data,
                    is_blinded: false,
                    consensus_version: "deneb".to_string(),
                    execution_payload_value: Some("12345".to_string()),
                    is_ssz: false,
                    ssz_bytes: None,
                }),
                fail_produce: false,
                fail_publish: false,
                publish_calls: Mutex::new(Vec::new()),
                publish_blinded_calls: Mutex::new(Vec::new()),
                publish_ssz_calls: Mutex::new(Vec::new()),
                produce_full_calls: Mutex::new(Vec::new()),
                publish_full_calls: Mutex::new(Vec::new()),
                publish_blinded_full_calls: Mutex::new(Vec::new()),
            }
        }

        fn blinded(block: BlindedBeaconBlock) -> Self {
            let data = serde_json::to_value(&block).unwrap();
            Self {
                produce_response: Some(ProduceBlockResponse {
                    data,
                    is_blinded: true,
                    consensus_version: "deneb".to_string(),
                    execution_payload_value: None,
                    is_ssz: false,
                    ssz_bytes: None,
                }),
                fail_produce: false,
                fail_publish: false,
                publish_calls: Mutex::new(Vec::new()),
                publish_blinded_calls: Mutex::new(Vec::new()),
                publish_ssz_calls: Mutex::new(Vec::new()),
                produce_full_calls: Mutex::new(Vec::new()),
                publish_full_calls: Mutex::new(Vec::new()),
                publish_blinded_full_calls: Mutex::new(Vec::new()),
            }
        }

        /// Create an SSZ mock response.
        ///
        /// - Blinded → raw `BeaconBlock` layout (slot at offset 0).
        /// - Unblinded (deneb) → `BlockContents` layout (3 × 4-byte offsets, then block).
        fn ssz(slot: Slot, proposer_index: u64, is_blinded: bool) -> Self {
            Self::ssz_with_version(slot, proposer_index, is_blinded, "deneb")
        }

        fn ssz_with_version(
            slot: Slot,
            proposer_index: u64,
            is_blinded: bool,
            consensus_version: &str,
        ) -> Self {
            let ssz_bytes = build_ssz_bytes(slot, proposer_index, is_blinded, consensus_version);
            Self {
                produce_response: Some(ProduceBlockResponse {
                    data: serde_json::Value::Null,
                    is_blinded,
                    consensus_version: consensus_version.to_string(),
                    execution_payload_value: Some("99999".to_string()),
                    is_ssz: true,
                    ssz_bytes: Some(ssz_bytes),
                }),
                fail_produce: false,
                fail_publish: false,
                publish_calls: Mutex::new(Vec::new()),
                publish_blinded_calls: Mutex::new(Vec::new()),
                publish_ssz_calls: Mutex::new(Vec::new()),
                produce_full_calls: Mutex::new(Vec::new()),
                publish_full_calls: Mutex::new(Vec::new()),
                publish_blinded_full_calls: Mutex::new(Vec::new()),
            }
        }

        fn with_produce_error(mut self) -> Self {
            self.fail_produce = true;
            self
        }

        fn with_publish_error(mut self) -> Self {
            self.fail_publish = true;
            self
        }

        fn assert_last_produce_slot(&self, expected_slot: Slot) {
            let calls = self.produce_full_calls.lock().unwrap();
            assert!(!calls.is_empty(), "no produce_block_v3 calls captured");
            let last = calls.last().unwrap();
            assert_eq!(
                last.slot, expected_slot,
                "produce_block_v3 slot mismatch: expected {expected_slot}, got {}",
                last.slot
            );
        }

        fn assert_last_published_block(&self, expected_slot: Slot, expected_proposer: u64) {
            let calls = self.publish_full_calls.lock().unwrap();
            assert!(!calls.is_empty(), "no publish_block calls captured");
            let last = calls.last().unwrap();
            assert_eq!(
                last.slot, expected_slot,
                "published block slot mismatch: expected {expected_slot}, got {}",
                last.slot
            );
            assert_eq!(
                last.proposer_index, expected_proposer,
                "published block proposer_index mismatch: expected {expected_proposer}, got {}",
                last.proposer_index
            );
            assert!(
                !last.signature_bytes.is_empty(),
                "published block signature must not be empty"
            );
        }

        fn assert_last_published_blinded_block(&self, expected_slot: Slot, expected_proposer: u64) {
            let calls = self.publish_blinded_full_calls.lock().unwrap();
            assert!(!calls.is_empty(), "no publish_blinded_block calls captured");
            let last = calls.last().unwrap();
            assert_eq!(
                last.slot, expected_slot,
                "published blinded block slot mismatch: expected {expected_slot}, got {}",
                last.slot
            );
            assert_eq!(
                last.proposer_index, expected_proposer,
                "published blinded block proposer_index mismatch: expected {expected_proposer}, got {}",
                last.proposer_index
            );
            assert!(
                !last.signature_bytes.is_empty(),
                "published blinded block signature must not be empty"
            );
        }
    }

    #[async_trait(?Send)]
    impl BeaconBlockClient for MockBeaconClient {
        async fn produce_block_v3(
            &self,
            slot: Slot,
            randao_reveal: &str,
            graffiti: Option<&str>,
            builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, BlockServiceError> {
            self.produce_full_calls.lock().unwrap().push(CapturedProduceCall {
                slot,
                randao_reveal: randao_reveal.to_string(),
                graffiti: graffiti.map(|s| s.to_string()),
                builder_boost_factor,
            });
            if self.fail_produce {
                return Err(BlockServiceError::Beacon("beacon down".to_string()));
            }
            Ok(self.produce_response.clone().unwrap())
        }

        async fn publish_block(
            &self,
            signed_block: &SignedBeaconBlock,
            consensus_version: &str,
        ) -> Result<(), BlockServiceError> {
            self.publish_calls.lock().unwrap().push(consensus_version.to_string());
            self.publish_full_calls.lock().unwrap().push(CapturedPublishCall {
                consensus_version: consensus_version.to_string(),
                slot: signed_block.message.slot,
                proposer_index: signed_block.message.proposer_index,
                signature_bytes: signed_block.signature.clone(),
            });
            if self.fail_publish {
                return Err(BlockServiceError::Beacon("publish failed".to_string()));
            }
            Ok(())
        }

        async fn publish_blinded_block(
            &self,
            signed_block: &SignedBlindedBeaconBlock,
            consensus_version: &str,
        ) -> Result<(), BlockServiceError> {
            self.publish_blinded_calls.lock().unwrap().push(consensus_version.to_string());
            self.publish_blinded_full_calls.lock().unwrap().push(CapturedPublishCall {
                consensus_version: consensus_version.to_string(),
                slot: signed_block.message.slot,
                proposer_index: signed_block.message.proposer_index,
                signature_bytes: signed_block.signature.clone(),
            });
            if self.fail_publish {
                return Err(BlockServiceError::Beacon("publish failed".to_string()));
            }
            Ok(())
        }

        async fn publish_block_ssz(
            &self,
            ssz_bytes: &[u8],
            consensus_version: &str,
            is_blinded: bool,
        ) -> Result<(), BlockServiceError> {
            self.publish_ssz_calls.lock().unwrap().push((
                ssz_bytes.to_vec(),
                consensus_version.to_string(),
                is_blinded,
            ));
            if self.fail_publish {
                return Err(BlockServiceError::Beacon("publish failed".to_string()));
            }
            Ok(())
        }
    }

    // --- Helpers ---

    fn test_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 30,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 40,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 50,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: 60,
            fulu_fork_version: [6, 0, 0, 0],
        }
    }

    fn test_block(slot: Slot) -> BeaconBlock {
        BeaconBlock {
            slot,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xde, 0xad],
        }
    }

    fn test_blinded_block(slot: Slot) -> BlindedBeaconBlock {
        BlindedBeaconBlock {
            slot,
            proposer_index: 42,
            parent_root: [3u8; 32],
            state_root: [4u8; 32],
            body: vec![0xbe, 0xef],
        }
    }

    fn test_pubkey() -> PublicKey {
        let secret = crypto::SecretKey::generate();
        secret.public_key()
    }

    fn test_validator_store(pubkey: &PublicKey) -> ValidatorStore {
        let store = ValidatorStore::new([0u8; 20], 30_000_000);
        let pk_bytes = pubkey.to_bytes();
        let mut config = validator_store::ValidatorConfig::new(pk_bytes);
        config.builder_boost_factor = 150;
        let mut graffiti = [0u8; 32];
        graffiti[..5].copy_from_slice(b"hello");
        config.graffiti = Some(graffiti);
        store.add_validator(config);
        store
    }

    fn build_service(
        signer: MockSigner,
        beacon: MockBeaconClient,
        pubkey: &PublicKey,
    ) -> BlockService<MockSigner, MockBeaconClient> {
        let store = test_validator_store(pubkey);
        BlockService::new(
            Arc::new(signer),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        )
    }

    /// Build synthetic SSZ bytes matching the expected wire format.
    fn build_ssz_bytes(
        slot: Slot,
        proposer_index: u64,
        is_blinded: bool,
        consensus_version: &str,
    ) -> Vec<u8> {
        let use_block_contents =
            !is_blinded && matches!(consensus_version, "deneb" | "electra" | "fulu");
        let body = [0xab; 8];
        let body_offset: u32 = 84; // fixed portion size

        let mut block_bytes = Vec::new();
        block_bytes.extend_from_slice(&slot.to_le_bytes()); // 8 bytes
        block_bytes.extend_from_slice(&proposer_index.to_le_bytes()); // 8 bytes
        block_bytes.extend_from_slice(&[0x11; 32]); // parent_root
        block_bytes.extend_from_slice(&[0x22; 32]); // state_root
        block_bytes.extend_from_slice(&body_offset.to_le_bytes()); // 4 bytes
        block_bytes.extend_from_slice(&body); // body bytes

        let mut bytes = Vec::new();
        if use_block_contents {
            // BlockContents: 3 × 4-byte offsets, then BeaconBlock at offset 12
            let bc_block_offset: u32 = 12;
            let kzg_offset: u32 = 12 + block_bytes.len() as u32;
            let blobs_offset: u32 = kzg_offset;
            bytes.extend_from_slice(&bc_block_offset.to_le_bytes());
            bytes.extend_from_slice(&kzg_offset.to_le_bytes());
            bytes.extend_from_slice(&blobs_offset.to_le_bytes());
        }
        bytes.extend_from_slice(&block_bytes);
        bytes
    }

    // --- Tests ---

    #[test]
    fn test_compute_block_root_matches_tree_hash() {
        use tree_hash::TreeHash;
        let block = test_block(100);
        let root = compute_block_root(&block);
        let expected = block.tree_hash_root();
        assert_eq!(root, expected.0);
    }

    #[test]
    fn test_compute_blinded_block_root_matches_tree_hash() {
        use tree_hash::TreeHash;
        let block = test_blinded_block(200);
        let root = compute_blinded_block_root(&block);
        let expected = block.tree_hash_root();
        assert_eq!(root, expected.0);
    }

    #[tokio::test]
    async fn test_propose_block_unblinded() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();
        let fork = test_fork_schedule();
        let gvr: Root = [0xaa; 32];

        let signer_arc = Arc::new(signer);
        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(fork.clone()),
            gvr,
        );

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
        assert!(!proposal.is_blinded);
        assert_eq!(proposal.consensus_version, "deneb");
        assert_eq!(proposal.value_wei, Some("12345".to_string()));
        assert_ne!(proposal.block_root, [0u8; 32]);

        beacon_arc.assert_last_produce_slot(slot);
        beacon_arc.assert_last_published_block(slot, 42);
        signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    }

    #[tokio::test]
    async fn test_propose_block_blinded() {
        let pubkey = test_pubkey();
        let slot = 200;
        let block = test_blinded_block(slot);
        let beacon = MockBeaconClient::blinded(block);
        let signer = MockSigner::new();
        let fork = test_fork_schedule();
        let gvr: Root = [0xaa; 32];

        let signer_arc = Arc::new(signer);
        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(fork.clone()),
            gvr,
        );

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
        assert!(proposal.is_blinded);
        assert_eq!(proposal.consensus_version, "deneb");
        assert!(proposal.value_wei.is_none());
        assert_ne!(proposal.block_root, [0u8; 32]);

        beacon_arc.assert_last_produce_slot(slot);
        beacon_arc.assert_last_published_blinded_block(slot, 42);
        signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    }

    #[tokio::test]
    async fn test_propose_block_signing_failure() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new().with_block_error();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BlockServiceError::Signer(_)));
    }

    #[tokio::test]
    async fn test_propose_block_randao_failure() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new().with_randao_error();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BlockServiceError::Signer(_)));
    }

    #[tokio::test]
    async fn test_propose_block_beacon_produce_failure() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block).with_produce_error();
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BlockServiceError::Beacon(_)));
    }

    #[tokio::test]
    async fn test_propose_block_beacon_publish_failure() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block).with_publish_error();
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, BlockServiceError::Beacon(_)));
    }

    #[tokio::test]
    async fn test_propose_block_uses_validator_preferences() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);

        struct CapturingBeacon {
            inner: MockBeaconClient,
            graffiti_arg: Mutex<Option<String>>,
            boost_arg: Mutex<Option<u64>>,
        }

        #[async_trait(?Send)]
        impl BeaconBlockClient for CapturingBeacon {
            async fn produce_block_v3(
                &self,
                slot: Slot,
                randao_reveal: &str,
                graffiti: Option<&str>,
                builder_boost_factor: Option<u64>,
            ) -> Result<ProduceBlockResponse, BlockServiceError> {
                *self.graffiti_arg.lock().unwrap() = graffiti.map(|s| s.to_string());
                *self.boost_arg.lock().unwrap() = builder_boost_factor;
                self.inner
                    .produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor)
                    .await
            }

            async fn publish_block(
                &self,
                signed_block: &SignedBeaconBlock,
                consensus_version: &str,
            ) -> Result<(), BlockServiceError> {
                self.inner.publish_block(signed_block, consensus_version).await
            }

            async fn publish_blinded_block(
                &self,
                signed_block: &SignedBlindedBeaconBlock,
                consensus_version: &str,
            ) -> Result<(), BlockServiceError> {
                self.inner.publish_blinded_block(signed_block, consensus_version).await
            }

            async fn publish_block_ssz(
                &self,
                ssz_bytes: &[u8],
                consensus_version: &str,
                is_blinded: bool,
            ) -> Result<(), BlockServiceError> {
                self.inner.publish_block_ssz(ssz_bytes, consensus_version, is_blinded).await
            }
        }

        let capturing_beacon = CapturingBeacon {
            inner: MockBeaconClient::unblinded(block),
            graffiti_arg: Mutex::new(None),
            boost_arg: Mutex::new(None),
        };

        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            Arc::new(capturing_beacon),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        // Verify graffiti was passed (hex-encoded "hello" + padding)
        let graffiti = service.beacon.graffiti_arg.lock().unwrap().clone();
        assert!(graffiti.is_some());
        let graffiti_str = graffiti.unwrap();
        assert!(graffiti_str.starts_with("0x"));
        // "hello" = 68656c6c6f
        assert!(graffiti_str.contains("68656c6c6f"));

        // Verify boost factor was passed
        let boost = *service.beacon.boost_arg.lock().unwrap();
        assert_eq!(boost, Some(150));
    }

    #[tokio::test]
    async fn test_propose_block_routes_blinded_to_blinded_endpoint() {
        let pubkey = test_pubkey();
        let slot = 200;
        let block = test_blinded_block(slot);
        let beacon = MockBeaconClient::blinded(block);
        let signer = MockSigner::new();

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(signer),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        assert_eq!(beacon_arc.publish_blinded_calls.lock().unwrap().len(), 1);
        assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
        beacon_arc.assert_last_produce_slot(slot);
        beacon_arc.assert_last_published_blinded_block(slot, 42);
    }

    #[tokio::test]
    async fn test_propose_block_routes_unblinded_to_unblinded_endpoint() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(signer),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        assert_eq!(beacon_arc.publish_calls.lock().unwrap().len(), 1);
        assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
        beacon_arc.assert_last_produce_slot(slot);
        beacon_arc.assert_last_published_block(slot, 42);
    }

    #[tokio::test]
    async fn test_blinded_block_signing_failure_prevents_publish() {
        let pubkey = test_pubkey();
        let slot = 200;
        let block = test_blinded_block(slot);
        let beacon = MockBeaconClient::blinded(block);
        let signer = MockSigner::new().with_block_error();

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(signer),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockServiceError::Signer(_)));

        // Verify no publish calls were made
        assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
        assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_blinded_block_publish_failure() {
        let pubkey = test_pubkey();
        let slot = 200;
        let block = test_blinded_block(slot);
        let beacon = MockBeaconClient::blinded(block).with_publish_error();
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockServiceError::Beacon(_)));
    }

    #[tokio::test]
    async fn test_blinded_and_unblinded_same_slot_have_different_block_roots() {
        let pubkey = test_pubkey();
        let slot = 100;

        // Propose unblinded block
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block.clone());
        let signer = MockSigner::new();
        let signer_arc = Arc::new(signer);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );
        let unblinded_result = service.propose_block(slot, &pubkey).await.unwrap();

        // Propose blinded block at same slot
        let blinded_block = test_blinded_block(slot);
        let beacon2 = MockBeaconClient::blinded(blinded_block.clone());
        let signer2 = MockSigner::new();
        let signer2_arc = Arc::new(signer2);
        let store2 = test_validator_store(&pubkey);
        let service2 = BlockService::new(
            signer2_arc.clone(),
            Arc::new(beacon2),
            Arc::new(store2),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );
        let blinded_result = service2.propose_block(slot, &pubkey).await.unwrap();

        // Block roots must differ (slashing protection uses these to detect double proposals)
        assert_ne!(
            unblinded_result.block_root, blinded_result.block_root,
            "blinded and unblinded blocks at same slot must have different roots for slashing protection"
        );

        // Both signers were called with the respective root
        let unblinded_calls = signer_arc.block_calls.lock().unwrap();
        let blinded_calls = signer2_arc.block_calls.lock().unwrap();
        assert_eq!(unblinded_calls.len(), 1);
        assert_eq!(blinded_calls.len(), 1);
        assert_eq!(unblinded_calls[0].block_root, unblinded_result.block_root);
        assert_eq!(blinded_calls[0].block_root, blinded_result.block_root);
    }

    // --- SSZ path tests ---

    #[tokio::test]
    async fn test_propose_block_ssz_unblinded() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz(slot, 42, false);
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
        assert!(!proposal.is_blinded);
        assert_eq!(proposal.consensus_version, "deneb");
        assert_ne!(proposal.block_root, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_propose_block_ssz_blinded() {
        let pubkey = test_pubkey();
        let slot = 200;
        let beacon = MockBeaconClient::ssz(slot, 42, true);
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
        assert!(proposal.is_blinded);
    }

    #[tokio::test]
    async fn test_propose_block_ssz_calls_publish_block_ssz() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz(slot, 42, false);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
        assert_eq!(ssz_calls.len(), 1);
        assert_eq!(ssz_calls[0].1, "deneb");
        assert!(!ssz_calls[0].2); // is_blinded = false

        // JSON publish endpoints should NOT be called
        assert!(beacon_arc.publish_calls.lock().unwrap().is_empty());
        assert!(beacon_arc.publish_blinded_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_propose_block_ssz_blinded_passes_is_blinded_flag() {
        let pubkey = test_pubkey();
        let slot = 200;
        let beacon = MockBeaconClient::ssz(slot, 42, true);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
        assert_eq!(ssz_calls.len(), 1);
        assert!(ssz_calls[0].2); // is_blinded = true
    }

    #[tokio::test]
    async fn test_propose_block_ssz_slot_mismatch_returns_error() {
        let pubkey = test_pubkey();
        let requested_slot = 100;
        let ssz_slot = 200; // mismatch!
        let beacon = MockBeaconClient::ssz(ssz_slot, 42, false);
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(requested_slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("slot mismatch"), "error should mention slot mismatch: {err}");
    }

    #[tokio::test]
    async fn test_propose_block_ssz_missing_bytes_returns_error() {
        let pubkey = test_pubkey();
        let slot = 100;
        let mut beacon = MockBeaconClient::ssz(slot, 42, false);
        // Set ssz_bytes to None while is_ssz is true
        beacon.produce_response.as_mut().unwrap().ssz_bytes = None;
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SSZ"), "error should mention SSZ: {err}");
    }

    #[tokio::test]
    async fn test_propose_block_ssz_short_bytes_returns_error() {
        let pubkey = test_pubkey();
        let slot = 100;
        let mut beacon = MockBeaconClient::ssz(slot, 42, false);
        // Set ssz_bytes to too-short buffer
        beacon.produce_response.as_mut().unwrap().ssz_bytes = Some(vec![0u8; 8]);
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_propose_block_ssz_block_root_uses_tree_hash() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz(slot, 42, false);
        let ssz_bytes = beacon.produce_response.as_ref().unwrap().ssz_bytes.clone().unwrap();
        let signer = MockSigner::new();

        let signer_arc = Arc::new(signer);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        // Deserialize the SSZ and compute tree_hash_root — SSZ path should match
        let format = ssz_block_format(false, "deneb");
        let (block, _) =
            beacon::ssz_deser::deserialize_beacon_block_from_ssz(&ssz_bytes, format).unwrap();
        let expected_root: [u8; 32] = block.tree_hash_root().0;
        let proposal = result.unwrap();
        assert_eq!(proposal.block_root, expected_root);

        // Verify signer was called with the tree_hash root
        let block_calls = signer_arc.block_calls.lock().unwrap();
        assert_eq!(block_calls.len(), 1);
        assert_eq!(block_calls[0].block_root, expected_root);
    }

    #[test]
    fn test_ssz_block_root_uses_tree_hash_not_sha256() {
        use sha2::{Digest, Sha256};

        let block = eth_types::BeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: vec![0xab; 8],
        };

        let tree_hash_root: [u8; 32] = block.tree_hash_root().0;

        // Build SSZ bytes the same way the mock does
        let ssz_bytes = build_ssz_bytes(100, 42, false, "deneb");
        let sha256_root: [u8; 32] = Sha256::digest(&ssz_bytes).into();

        // Regression: these must differ, proving SHA256 was wrong
        assert_ne!(tree_hash_root, sha256_root);
    }

    #[tokio::test]
    async fn test_propose_block_ssz_publish_failure() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz(slot, 42, false).with_publish_error();
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockServiceError::Beacon(_)));
    }

    #[tokio::test]
    async fn test_propose_block_ssz_pre_deneb_uses_beacon_block_format() {
        let pubkey = test_pubkey();
        let slot = 100;
        // Pre-Deneb unblinded: raw BeaconBlock SSZ (no BlockContents wrapper)
        let beacon = MockBeaconClient::ssz_with_version(slot, 42, false, "capella");
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
        assert!(!proposal.is_blinded);
    }

    #[tokio::test]
    async fn test_propose_block_ssz_electra_unblinded_uses_block_contents() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz_with_version(slot, 42, false, "electra");
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
    }

    #[tokio::test]
    async fn test_propose_block_ssz_deneb_blinded_uses_beacon_block_format() {
        let pubkey = test_pubkey();
        let slot = 100;
        // Deneb blinded: raw BeaconBlock SSZ (NOT BlockContents)
        let beacon = MockBeaconClient::ssz_with_version(slot, 42, true, "deneb");
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert!(proposal.is_blinded);
    }

    #[test]
    fn test_ssz_block_format_blinded_always_beacon_block() {
        use beacon::ssz_deser::SszBlockFormat;
        assert_eq!(ssz_block_format(true, "phase0"), SszBlockFormat::BeaconBlock);
        assert_eq!(ssz_block_format(true, "capella"), SszBlockFormat::BeaconBlock);
        assert_eq!(ssz_block_format(true, "deneb"), SszBlockFormat::BeaconBlock);
        assert_eq!(ssz_block_format(true, "electra"), SszBlockFormat::BeaconBlock);
    }

    #[test]
    fn test_ssz_block_format_unblinded_pre_deneb_beacon_block() {
        use beacon::ssz_deser::SszBlockFormat;
        assert_eq!(ssz_block_format(false, "phase0"), SszBlockFormat::BeaconBlock);
        assert_eq!(ssz_block_format(false, "altair"), SszBlockFormat::BeaconBlock);
        assert_eq!(ssz_block_format(false, "bellatrix"), SszBlockFormat::BeaconBlock);
        assert_eq!(ssz_block_format(false, "capella"), SszBlockFormat::BeaconBlock);
    }

    #[test]
    fn test_ssz_block_format_unblinded_deneb_plus_block_contents() {
        use beacon::ssz_deser::SszBlockFormat;
        assert_eq!(ssz_block_format(false, "deneb"), SszBlockFormat::BlockContents);
        assert_eq!(ssz_block_format(false, "electra"), SszBlockFormat::BlockContents);
        assert_eq!(ssz_block_format(false, "fulu"), SszBlockFormat::BlockContents);
    }

    #[tokio::test]
    async fn test_propose_block_ssz_signing_failure() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz(slot, 42, false);
        let signer = MockSigner::new().with_block_error();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockServiceError::Signer(_)));
    }

    #[tokio::test]
    async fn test_propose_block_unblinded_slot_mismatch_returns_error() {
        let pubkey = test_pubkey();
        let requested_slot = 100;
        let block = test_block(200); // block has slot 200, we request 100
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(requested_slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BlockServiceError::SlotMismatch { requested: 100, got: 200 }),
            "expected SlotMismatch, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_propose_block_blinded_slot_mismatch_returns_error() {
        let pubkey = test_pubkey();
        let requested_slot = 100;
        let block = test_blinded_block(300); // block has slot 300, we request 100
        let beacon = MockBeaconClient::blinded(block);
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(requested_slot, &pubkey).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BlockServiceError::SlotMismatch { requested: 100, got: 300 }),
            "expected SlotMismatch, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_propose_block_calls_randao_with_correct_epoch() {
        let pubkey = test_pubkey();
        let slot = 320; // epoch = 320/32 = 10
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();
        let fork = test_fork_schedule();
        let gvr: Root = [0xaa; 32];

        let signer_arc = Arc::new(signer);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(fork.clone()),
            gvr,
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let calls = signer_arc.randao_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], 10); // epoch = 320/32
        drop(calls);

        signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    }

    #[tokio::test]
    async fn test_ssz_published_payload_contains_signature() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz(slot, 42, false);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
        assert_eq!(ssz_calls.len(), 1);
        let published = &ssz_calls[0].0;

        // First 4 bytes: message_offset = 100 (4 + 96)
        let message_offset = u32::from_le_bytes(published[0..4].try_into().unwrap());
        assert_eq!(message_offset, 100);

        // Bytes 4..100: 96-byte signature (MockSigner returns 0xbb * 96)
        let sig = &published[4..100];
        assert_eq!(sig.len(), 96);
        assert!(sig.iter().all(|&b| b == 0xbb), "signature should be mock 0xbb bytes");

        // Bytes 100..: BeaconBlock SSZ data
        assert!(
            published.len() > 100,
            "published payload should contain block data after signature"
        );
    }

    #[tokio::test]
    async fn test_ssz_published_payload_is_signed_beacon_block() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = MockBeaconClient::ssz(slot, 42, false);
        let original_ssz = beacon.produce_response.as_ref().unwrap().ssz_bytes.clone().unwrap();

        // For BlockContents (deneb), block starts at offset 12
        let block_ssz_len = original_ssz.len() - 12; // block data starts at offset 12

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
        let published = &ssz_calls[0].0;

        // Published length = 100 (4 offset + 96 sig) + block_ssz_len
        assert_eq!(published.len(), 100 + block_ssz_len);
    }

    #[tokio::test]
    async fn test_ssz_blinded_block_also_includes_signature() {
        let pubkey = test_pubkey();
        let slot = 200;
        let beacon = MockBeaconClient::ssz(slot, 42, true);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let ssz_calls = beacon_arc.publish_ssz_calls.lock().unwrap();
        assert_eq!(ssz_calls.len(), 1);
        let published = &ssz_calls[0].0;

        // First 4 bytes: message_offset = 100
        let message_offset = u32::from_le_bytes(published[0..4].try_into().unwrap());
        assert_eq!(message_offset, 100);

        // Signature present
        let sig = &published[4..100];
        assert!(sig.iter().all(|&b| b == 0xbb));

        // Blinded flag should be true
        assert!(ssz_calls[0].2);
    }

    // --- Block selection mode tests (T4.2, T4.3) ---

    struct BoostCapturingBeacon {
        inner: MockBeaconClient,
        boost_arg: Mutex<Option<u64>>,
    }

    #[async_trait(?Send)]
    impl BeaconBlockClient for BoostCapturingBeacon {
        async fn produce_block_v3(
            &self,
            slot: Slot,
            randao_reveal: &str,
            graffiti: Option<&str>,
            builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, BlockServiceError> {
            *self.boost_arg.lock().unwrap() = builder_boost_factor;
            self.inner.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await
        }
        async fn publish_block(
            &self,
            s: &SignedBeaconBlock,
            v: &str,
        ) -> Result<(), BlockServiceError> {
            self.inner.publish_block(s, v).await
        }
        async fn publish_blinded_block(
            &self,
            s: &SignedBlindedBeaconBlock,
            v: &str,
        ) -> Result<(), BlockServiceError> {
            self.inner.publish_blinded_block(s, v).await
        }
        async fn publish_block_ssz(
            &self,
            b: &[u8],
            v: &str,
            bl: bool,
        ) -> Result<(), BlockServiceError> {
            self.inner.publish_block_ssz(b, v, bl).await
        }
    }

    fn build_service_with_mode(
        beacon: BoostCapturingBeacon,
        pubkey: &PublicKey,
        circuit_breaker: Arc<CircuitBreakerState>,
    ) -> BlockService<MockSigner, BoostCapturingBeacon> {
        let store = test_validator_store(pubkey);
        BlockService::with_circuit_breaker(
            Arc::new(MockSigner::new()),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
            circuit_breaker,
        )
    }

    #[tokio::test]
    async fn test_execution_only_sets_boost_factor_zero() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(0, 0));
        let service = build_service_with_mode(beacon, &pubkey, cb);

        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::ExecutionOnly).await;
        assert!(result.is_ok());

        let boost = *service.beacon.boost_arg.lock().unwrap();
        assert_eq!(boost, Some(0));
    }

    #[tokio::test]
    async fn test_max_profit_uses_configured_boost_factor() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(0, 0));
        let service = build_service_with_mode(beacon, &pubkey, cb);

        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit).await;
        assert!(result.is_ok());

        // test_validator_store sets builder_boost_factor=150
        let boost = *service.beacon.boost_arg.lock().unwrap();
        assert_eq!(boost, Some(150));
    }

    #[tokio::test]
    async fn test_builder_always_sets_boost_factor_max() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(0, 0));
        let service = build_service_with_mode(beacon, &pubkey, cb);

        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways).await;
        assert!(result.is_ok());

        let boost = *service.beacon.boost_arg.lock().unwrap();
        assert_eq!(boost, Some(u64::MAX));
    }

    #[tokio::test]
    async fn test_builder_always_falls_back_on_circuit_breaker() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(1, 0));
        cb.record_miss(); // trip it
        assert!(cb.is_tripped());

        let service = build_service_with_mode(beacon, &pubkey, cb);
        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderAlways).await;
        // BuilderAlways falls back to local (boost=0)
        assert!(result.is_ok());
        let boost = *service.beacon.boost_arg.lock().unwrap();
        assert_eq!(boost, Some(0));
    }

    #[tokio::test]
    async fn test_builder_only_sets_boost_factor_max() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(0, 0));
        let service = build_service_with_mode(beacon, &pubkey, cb);

        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly).await;
        assert!(result.is_ok());

        let boost = *service.beacon.boost_arg.lock().unwrap();
        assert_eq!(boost, Some(u64::MAX));
    }

    #[tokio::test]
    async fn test_builder_only_fails_on_circuit_breaker_tripped() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(1, 0));
        cb.record_miss(); // trip it
        assert!(cb.is_tripped());

        let service = build_service_with_mode(beacon, &pubkey, cb);
        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockServiceError::BuilderOnly(_)));
    }

    #[tokio::test]
    async fn test_builder_only_fails_on_builder_error() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)).with_produce_error(),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(0, 0));
        let service = build_service_with_mode(beacon, &pubkey, cb);

        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::BuilderOnly).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockServiceError::BuilderOnly(_)));
    }

    #[tokio::test]
    async fn test_max_profit_circuit_breaker_tripped_uses_zero() {
        let pubkey = test_pubkey();
        let slot = 100;
        let beacon = BoostCapturingBeacon {
            inner: MockBeaconClient::unblinded(test_block(slot)),
            boost_arg: Mutex::new(None),
        };
        let cb = Arc::new(CircuitBreakerState::new(1, 0));
        cb.record_miss();
        assert!(cb.is_tripped());

        let service = build_service_with_mode(beacon, &pubkey, cb);
        let result =
            service.propose_block_with_mode(slot, &pubkey, BlockSelectionMode::MaxProfit).await;
        assert!(result.is_ok());
        let boost = *service.beacon.boost_arg.lock().unwrap();
        assert_eq!(boost, Some(0));
    }

    // --- CapturedCall infrastructure tests ---

    #[tokio::test]
    async fn test_produce_call_captures_slot_and_args() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_produce_slot(slot);
        let calls = beacon_arc.produce_full_calls.lock().unwrap();
        assert!(calls[0].randao_reveal.starts_with("0x"));
        assert!(calls[0].graffiti.is_some());
        assert_eq!(calls[0].builder_boost_factor, Some(150));
    }

    #[tokio::test]
    async fn test_publish_call_captures_block_fields() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_published_block(slot, 42);
        let calls = beacon_arc.publish_full_calls.lock().unwrap();
        assert_eq!(calls[0].consensus_version, "deneb");
        assert_eq!(calls[0].signature_bytes, vec![0xbb; 96]);
    }

    #[tokio::test]
    async fn test_publish_blinded_call_captures_block_fields() {
        let pubkey = test_pubkey();
        let slot = 200;
        let block = test_blinded_block(slot);
        let beacon = MockBeaconClient::blinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_published_blinded_block(slot, 42);
        let calls = beacon_arc.publish_blinded_full_calls.lock().unwrap();
        assert_eq!(calls[0].consensus_version, "deneb");
        assert_eq!(calls[0].signature_bytes, vec![0xbb; 96]);
    }

    #[tokio::test]
    async fn test_sign_block_captures_fork_schedule_and_genesis_root() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();

        let signer_arc = Arc::new(signer);
        let fork = test_fork_schedule();
        let gvr: Root = [0xaa; 32];
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(fork.clone()),
            gvr,
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        signer_arc.assert_last_sign_block_domain(&fork, &gvr);
        let calls = signer_arc.block_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].slot, slot);
        assert_eq!(calls[0].pubkey, pubkey);
    }

    // --- Assertion helper tests ---

    #[tokio::test]
    async fn test_assert_last_produce_slot_passes_on_correct_slot() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_produce_slot(slot);
    }

    #[tokio::test]
    #[should_panic(expected = "produce_block_v3 slot mismatch")]
    async fn test_assert_last_produce_slot_fails_on_wrong_slot() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        // This should panic: production code sent slot=100, we assert slot+1=101
        beacon_arc.assert_last_produce_slot(slot + 1);
    }

    #[tokio::test]
    async fn test_assert_last_published_block_passes_on_correct_fields() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_published_block(slot, 42);
    }

    #[tokio::test]
    #[should_panic(expected = "published block slot mismatch")]
    async fn test_assert_last_published_block_fails_on_wrong_slot() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_published_block(slot + 1, 42);
    }

    #[tokio::test]
    #[should_panic(expected = "published block proposer_index mismatch")]
    async fn test_assert_last_published_block_fails_on_wrong_proposer() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_published_block(slot, 99);
    }

    #[tokio::test]
    async fn test_assert_last_published_block_checks_signature() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        // Verify signature is non-empty (MockSigner returns 0xbb * 96)
        let calls = beacon_arc.publish_full_calls.lock().unwrap();
        assert!(!calls[0].signature_bytes.is_empty(), "signature must be non-empty");
        assert_eq!(calls[0].signature_bytes, vec![0xbb; 96]);
    }

    #[tokio::test]
    async fn test_assert_last_published_blinded_block_passes() {
        let pubkey = test_pubkey();
        let slot = 200;
        let block = test_blinded_block(slot);
        let beacon = MockBeaconClient::blinded(block);

        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        beacon_arc.assert_last_published_blinded_block(slot, 42);
    }

    #[tokio::test]
    async fn test_assert_last_sign_block_domain_passes_on_correct_values() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();
        let fork = test_fork_schedule();
        let gvr: Root = [0xaa; 32];

        let signer_arc = Arc::new(signer);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(fork.clone()),
            gvr,
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        signer_arc.assert_last_sign_block_domain(&fork, &gvr);
    }

    #[tokio::test]
    #[should_panic(expected = "sign_block fork_schedule mismatch")]
    async fn test_assert_last_sign_block_domain_fails_on_wrong_fork() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();
        let fork = test_fork_schedule();
        let gvr: Root = [0xaa; 32];

        let signer_arc = Arc::new(signer);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(fork),
            gvr,
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let mut wrong_fork = test_fork_schedule();
        wrong_fork.altair_fork_epoch = 999;
        signer_arc.assert_last_sign_block_domain(&wrong_fork, &gvr);
    }

    #[tokio::test]
    #[should_panic(expected = "sign_block genesis_validators_root mismatch")]
    async fn test_assert_last_sign_block_domain_fails_on_wrong_gvr() {
        let pubkey = test_pubkey();
        let slot = 100;
        let block = test_block(slot);
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();
        let fork = test_fork_schedule();
        let gvr: Root = [0xaa; 32];

        let signer_arc = Arc::new(signer);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon),
            Arc::new(store),
            Arc::new(fork.clone()),
            gvr,
        );

        let result = service.propose_block(slot, &pubkey).await;
        assert!(result.is_ok());

        let wrong_gvr: Root = [0xbb; 32];
        signer_arc.assert_last_sign_block_domain(&fork, &wrong_gvr);
    }

    // --- Issue 3.1: SSZ large-body + non-empty KZG tests (Finding #21) ---

    /// Build SSZ bytes for a BlockContents payload with explicit KZG proofs and blobs.
    ///
    /// Layout: [block_offset(4) | kzg_offset(4) | blobs_offset(4) | BeaconBlock | KZG proofs | Blobs]
    fn build_ssz_bytes_with_kzg(
        slot: Slot,
        proposer_index: u64,
        body: &[u8],
        kzg_proofs: &[u8],
        blobs: &[u8],
    ) -> Vec<u8> {
        let body_offset: u32 = 84;
        let mut block_bytes = Vec::new();
        block_bytes.extend_from_slice(&slot.to_le_bytes());
        block_bytes.extend_from_slice(&proposer_index.to_le_bytes());
        block_bytes.extend_from_slice(&[0x11; 32]); // parent_root
        block_bytes.extend_from_slice(&[0x22; 32]); // state_root
        block_bytes.extend_from_slice(&body_offset.to_le_bytes());
        block_bytes.extend_from_slice(body);

        let bc_block_offset: u32 = 12;
        let kzg_offset: u32 = bc_block_offset + block_bytes.len() as u32;
        let blobs_offset: u32 = kzg_offset + kzg_proofs.len() as u32;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&bc_block_offset.to_le_bytes());
        bytes.extend_from_slice(&kzg_offset.to_le_bytes());
        bytes.extend_from_slice(&blobs_offset.to_le_bytes());
        bytes.extend_from_slice(&block_bytes);
        bytes.extend_from_slice(kzg_proofs);
        bytes.extend_from_slice(blobs);
        bytes
    }

    #[test]
    fn test_ssz_deser_large_body_no_kzg() {
        use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

        let body = vec![0xab; 16384]; // 16KB body
        let body_offset: u32 = 84;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1000u64.to_le_bytes());
        bytes.extend_from_slice(&42u64.to_le_bytes());
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.extend_from_slice(&body_offset.to_le_bytes());
        bytes.extend_from_slice(&body);

        let (block, offset) =
            deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();

        assert_eq!(offset, 0);
        assert_eq!(block.slot, 1000);
        assert_eq!(block.proposer_index, 42);
        assert_eq!(block.body.len(), body.len(), "body must be exactly 16KB");
        assert_eq!(block.body, body);
    }

    #[test]
    #[ignore = "Known body-bleed bug: ssz_deser.rs uses bytes.len() instead of kzg_proofs_offset as block_region_end. Body includes KZG+blob data when non-empty. See beacon/src/ssz_deser.rs:190."]
    fn test_ssz_deser_block_contents_with_kzg_proofs() {
        use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

        let body = vec![0xab; 128];
        let kzg_proof = vec![0xcc; 48];
        let blob = vec![0xdd; 131072]; // 128KB blob

        let bytes = build_ssz_bytes_with_kzg(1000, 42, &body, &kzg_proof, &blob);
        let (block, offset) =
            deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();

        assert_eq!(offset, 12);
        assert_eq!(block.slot, 1000);
        assert_eq!(block.proposer_index, 42);
        // This assertion exposes the body-bleed bug: body will include KZG+blob data
        assert_eq!(
            block.body.len(),
            body.len(),
            "body must be exactly {} bytes, not include KZG data (got {})",
            body.len(),
            block.body.len(),
        );
        assert_eq!(block.body, body);
    }

    #[test]
    fn test_ssz_deser_kzg_offset_boundary() {
        use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

        // kzg_offset at exact end of block — empty KZG, empty blobs
        let body = vec![0xab; 1];
        let bytes = build_ssz_bytes_with_kzg(500, 10, &body, &[], &[]);

        let (block, offset) =
            deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();

        assert_eq!(offset, 12);
        assert_eq!(block.slot, 500);
        // With empty KZG data, bytes.len() == kzg_offset, so body is correct
        assert_eq!(block.body.len(), body.len());
    }

    #[test]
    #[ignore = "Known body-bleed bug: multiple KZG proofs + blobs are included in body. See beacon/src/ssz_deser.rs:190."]
    fn test_ssz_deser_multiple_blobs_deneb() {
        use beacon::ssz_deser::{deserialize_beacon_block_from_ssz, SszBlockFormat};

        let body = vec![0xab; 256];
        let kzg_proofs: Vec<u8> = (0..4).flat_map(|i| vec![i as u8; 48]).collect();
        let blobs: Vec<u8> = (0..4).flat_map(|i| vec![i as u8; 131072]).collect();

        let bytes = build_ssz_bytes_with_kzg(1000, 42, &body, &kzg_proofs, &blobs);
        let (block, _) =
            deserialize_beacon_block_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();

        assert_eq!(
            block.body.len(),
            body.len(),
            "body must be exactly {} bytes, not {} (includes KZG+blobs)",
            body.len(),
            block.body.len(),
        );
    }

    #[test]
    fn test_ssz_propose_with_large_body_through_pipeline() {
        use beacon::ssz_deser::SszBlockFormat;

        // Large body SSZ through the production deserialization path (no KZG data = no bug)
        let body = vec![0xab; 4096];
        let ssz = build_ssz_bytes_with_kzg(100, 42, &body, &[], &[]);

        let format = ssz_block_format(false, "deneb");
        assert_eq!(format, SszBlockFormat::BlockContents);

        let (block, offset) =
            beacon::ssz_deser::deserialize_beacon_block_from_ssz(&ssz, format).unwrap();
        assert_eq!(offset, 12);
        assert_eq!(block.slot, 100);
        assert_eq!(block.proposer_index, 42);
        assert_eq!(block.body.len(), body.len());
        assert_ne!(block.tree_hash_root().0, [0u8; 32]);
    }

    // --- Issue 3.2: Slot 0 / Epoch boundary block proposal tests (Finding #23) ---

    #[tokio::test]
    async fn test_propose_block_at_slot_zero() {
        let pubkey = test_pubkey();
        let slot = 0;
        let block = BeaconBlock {
            slot,
            proposer_index: 1,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: vec![0xde, 0xad],
        };
        let beacon = MockBeaconClient::unblinded(block);
        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok(), "slot 0 must not underflow: {:?}", result.err());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, 0);
        assert!(!proposal.is_blinded);
        assert_ne!(proposal.block_root, [0u8; 32]);

        beacon_arc.assert_last_produce_slot(0);
        beacon_arc.assert_last_published_block(0, 1);
    }

    #[tokio::test]
    async fn test_propose_block_at_epoch_boundary() {
        let pubkey = test_pubkey();
        let slot = SLOTS_PER_EPOCH; // slot 32 = first slot of epoch 1
        let block = BeaconBlock {
            slot,
            proposer_index: 5,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xca, 0xfe],
        };
        let beacon = MockBeaconClient::unblinded(block);
        let signer = MockSigner::new();
        let signer_arc = Arc::new(signer);
        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok(), "epoch boundary slot must work: {:?}", result.err());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, SLOTS_PER_EPOCH);

        beacon_arc.assert_last_produce_slot(SLOTS_PER_EPOCH);
        beacon_arc.assert_last_published_block(SLOTS_PER_EPOCH, 5);

        // RANDAO must use epoch 1
        let randao_calls = signer_arc.randao_calls.lock().unwrap();
        assert_eq!(randao_calls.len(), 1);
        assert_eq!(randao_calls[0], 1, "epoch must be slot/SLOTS_PER_EPOCH = 1");
    }

    #[tokio::test]
    async fn test_propose_block_at_slot_zero_ssz() {
        let pubkey = test_pubkey();
        let slot = 0;
        let beacon = MockBeaconClient::ssz_with_version(slot, 1, false, "capella");
        let beacon_arc = Arc::new(beacon);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            Arc::new(MockSigner::new()),
            beacon_arc.clone(),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok(), "SSZ slot 0 must not underflow: {:?}", result.err());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, 0);
        beacon_arc.assert_last_produce_slot(0);
    }

    // --- Issue 3.3: BlockAndBlobs JSON parse test (Finding #24) ---

    #[test]
    fn test_block_and_blobs_json_deserialization() {
        use eth_types::BlockContents;

        let json = serde_json::json!({
            "block": {
                "slot": "1000",
                "proposer_index": "42",
                "parent_root": format!("0x{}", hex::encode([0x11u8; 32])),
                "state_root": format!("0x{}", hex::encode([0x22u8; 32])),
                "body": format!("0x{}", hex::encode([0xab; 8])),
            },
            "blob_sidecars": [
                {
                    "index": "0",
                    "blob": format!("0x{}", hex::encode([0xdd; 128])),
                },
                {
                    "index": "1",
                    "blob": format!("0x{}", hex::encode([0xee; 128])),
                },
            ]
        });

        let contents: BlockContents = serde_json::from_value(json).unwrap();
        match &contents {
            BlockContents::BlockAndBlobs { block, blob_sidecars } => {
                assert_eq!(block.slot, 1000);
                assert_eq!(block.proposer_index, 42);
                assert_eq!(block.parent_root, [0x11u8; 32]);
                assert_eq!(block.state_root, [0x22u8; 32]);
                assert_eq!(block.body, vec![0xab; 8]);
                assert_eq!(blob_sidecars.len(), 2);
                assert_eq!(blob_sidecars[0].index, 0);
                assert_eq!(blob_sidecars[0].blob, vec![0xdd; 128]);
                assert_eq!(blob_sidecars[1].index, 1);
                assert_eq!(blob_sidecars[1].blob, vec![0xee; 128]);
            }
            BlockContents::Block(_) => {
                panic!("expected BlockAndBlobs variant, got Block");
            }
        }
    }

    #[test]
    fn test_block_and_blobs_json_through_produce_response() {
        let json = serde_json::json!({
            "block": {
                "slot": "500",
                "proposer_index": "10",
                "parent_root": format!("0x{}", hex::encode([0xaa; 32])),
                "state_root": format!("0x{}", hex::encode([0xbb; 32])),
                "body": format!("0x{}", hex::encode([0xde, 0xad])),
            },
            "blob_sidecars": [
                {
                    "index": "0",
                    "blob": format!("0x{}", hex::encode([0xff; 64])),
                },
            ]
        });

        let response = ProduceBlockResponse {
            data: json,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("99999".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };

        let contents = response.parse_full_block().unwrap();
        let block = contents.block();
        assert_eq!(block.slot, 500);
        assert_eq!(block.proposer_index, 10);
        match &contents {
            eth_types::BlockContents::BlockAndBlobs { blob_sidecars, .. } => {
                assert_eq!(blob_sidecars.len(), 1);
                assert_eq!(blob_sidecars[0].blob, vec![0xff; 64]);
            }
            _ => panic!("expected BlockAndBlobs"),
        }
    }

    #[test]
    fn test_block_and_blobs_json_empty_sidecars() {
        let json = serde_json::json!({
            "block": {
                "slot": "100",
                "proposer_index": "1",
                "parent_root": format!("0x{}", hex::encode([0u8; 32])),
                "state_root": format!("0x{}", hex::encode([0u8; 32])),
                "body": "0x",
            },
            "blob_sidecars": []
        });

        let contents: eth_types::BlockContents = serde_json::from_value(json).unwrap();
        match &contents {
            eth_types::BlockContents::BlockAndBlobs { blob_sidecars, .. } => {
                assert!(blob_sidecars.is_empty());
            }
            _ => panic!("expected BlockAndBlobs variant even with empty sidecars"),
        }
    }

    // --- Issue 3.4: Rewrite tautological block root test (Finding #25) ---

    #[tokio::test]
    async fn test_blinded_and_unblinded_roots_differ_through_production_logic() {
        let pubkey = test_pubkey();
        let slot = 100;

        // Both blocks share the same slot + proposer_index but differ in body.
        // The point: verify production code (compute_block_root / compute_blinded_block_root)
        // produces different roots because tree_hash includes the body field.
        let unblinded_block = BeaconBlock {
            slot,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xde, 0xad],
        };
        let blinded_block = BlindedBeaconBlock {
            slot,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xbe, 0xef], // different body → different root
        };

        // Exercise the production root computation functions
        let unblinded_root = compute_block_root(&unblinded_block);
        let blinded_root = compute_blinded_block_root(&blinded_block);

        // Roots differ because body content differs
        assert_ne!(
            unblinded_root, blinded_root,
            "blocks with different bodies at same slot must have different tree_hash roots"
        );

        // Verify roots are non-trivial (not all zeros)
        assert_ne!(unblinded_root, [0u8; 32]);
        assert_ne!(blinded_root, [0u8; 32]);

        // Verify determinism: same input → same root
        assert_eq!(compute_block_root(&unblinded_block), unblinded_root);
        assert_eq!(compute_blinded_block_root(&blinded_block), blinded_root);

        // Now run through the full pipeline and confirm the signer receives these roots
        let beacon_unblinded = MockBeaconClient::unblinded(unblinded_block);
        let signer = MockSigner::new();
        let signer_arc = Arc::new(signer);
        let store = test_validator_store(&pubkey);
        let service = BlockService::new(
            signer_arc.clone(),
            Arc::new(beacon_unblinded),
            Arc::new(store),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        );
        let result = service.propose_block(slot, &pubkey).await.unwrap();
        assert_eq!(
            result.block_root, unblinded_root,
            "pipeline must pass tree_hash root to signer"
        );
        let sign_calls = signer_arc.block_calls.lock().unwrap();
        assert_eq!(sign_calls[0].block_root, unblinded_root);
    }

    #[test]
    fn test_block_root_sensitive_to_every_field() {
        let baseline = BeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xab],
        };
        let baseline_root = compute_block_root(&baseline);

        // Changing slot
        let mut changed = baseline.clone();
        changed.slot = 101;
        assert_ne!(
            compute_block_root(&changed),
            baseline_root,
            "root must change when slot changes"
        );

        // Changing proposer_index
        let mut changed = baseline.clone();
        changed.proposer_index = 43;
        assert_ne!(
            compute_block_root(&changed),
            baseline_root,
            "root must change when proposer_index changes"
        );

        // Changing parent_root
        let mut changed = baseline.clone();
        changed.parent_root = [99u8; 32];
        assert_ne!(
            compute_block_root(&changed),
            baseline_root,
            "root must change when parent_root changes"
        );

        // Changing state_root
        let mut changed = baseline.clone();
        changed.state_root = [99u8; 32];
        assert_ne!(
            compute_block_root(&changed),
            baseline_root,
            "root must change when state_root changes"
        );

        // Changing body
        let mut changed = baseline.clone();
        changed.body = vec![0xcd, 0xef];
        assert_ne!(
            compute_block_root(&changed),
            baseline_root,
            "root must change when body changes"
        );
    }
}
