use std::sync::Arc;

use tracing::{debug, error, info, Instrument};
use tree_hash::TreeHash;

use crypto::logging::TruncatedPubkey;
use crypto::PublicKey;
use eth_types::{ForkSchedule, Root, Slot, SLOTS_PER_EPOCH};
use signer::ValidatorSigner;
use validator_store::ValidatorStore;

use crate::traits::{BeaconBlockClient, ProduceBlockResponse};
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
}

impl<S: ValidatorSigner, B: BeaconBlockClient> BlockService<S, B> {
    pub fn new(
        signer: Arc<S>,
        beacon: Arc<B>,
        validator_store: Arc<ValidatorStore>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self { signer, beacon, validator_store, fork_schedule, genesis_validators_root }
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
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let proposal_start = std::time::Instant::now();

        info!(slot = slot, pubkey = %TruncatedPubkey::new(&pubkey_hex), "Block proposal started");

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
        debug!(slot = slot, duration_ms = randao_start.elapsed().as_millis() as u64, "RANDAO reveal signed");
        let randao_hex = format!("0x{}", hex::encode(&randao_bytes));

        // 2. Get validator preferences
        let pubkey_bytes = pubkey.to_bytes();
        let graffiti = self.validator_store.effective_graffiti(&pubkey_bytes);
        let graffiti_hex = graffiti.map(|g| format!("0x{}", hex::encode(g)));
        let boost = self.validator_store.builder_boost_factor(&pubkey_bytes);

        // 3. Request block from beacon node
        let response = self
            .beacon
            .produce_block_v3(slot, &randao_hex, graffiti_hex.as_deref(), Some(boost))
            .instrument(tracing::info_span!("rvc.beacon.produce_block_v3"))
            .await
            .map_err(|e| {
                error!(slot = slot, error = %e, "Block production failed");
                e
            })?;

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
        debug!(slot = slot, duration_ms = sign_start.elapsed().as_millis() as u64, "Block signing duration");

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
        debug!(slot = slot, duration_ms = sign_start.elapsed().as_millis() as u64, "Block signing duration");

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
        debug!(slot = slot, duration_ms = sign_start.elapsed().as_millis() as u64, "Block signing duration");

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

    // --- Mock Signer ---

    struct MockSigner {
        fail_randao: bool,
        fail_block: bool,
        randao_calls: Mutex<Vec<u64>>,
        block_calls: Mutex<Vec<(Root, Slot)>>,
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
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            self.block_calls.lock().unwrap().push((*block_root, slot));
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
    }

    #[async_trait(?Send)]
    impl BeaconBlockClient for MockBeaconClient {
        async fn produce_block_v3(
            &self,
            _slot: Slot,
            _randao_reveal: &str,
            _graffiti: Option<&str>,
            _builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, BlockServiceError> {
            if self.fail_produce {
                return Err(BlockServiceError::Beacon("beacon down".to_string()));
            }
            Ok(self.produce_response.clone().unwrap())
        }

        async fn publish_block(
            &self,
            _signed_block: &SignedBeaconBlock,
            consensus_version: &str,
        ) -> Result<(), BlockServiceError> {
            self.publish_calls.lock().unwrap().push(consensus_version.to_string());
            if self.fail_publish {
                return Err(BlockServiceError::Beacon("publish failed".to_string()));
            }
            Ok(())
        }

        async fn publish_blinded_block(
            &self,
            _signed_block: &SignedBlindedBeaconBlock,
            consensus_version: &str,
        ) -> Result<(), BlockServiceError> {
            self.publish_blinded_calls.lock().unwrap().push(consensus_version.to_string());
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
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
        assert!(!proposal.is_blinded);
        assert_eq!(proposal.consensus_version, "deneb");
        assert_eq!(proposal.value_wei, Some("12345".to_string()));
        assert_ne!(proposal.block_root, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_propose_block_blinded() {
        let pubkey = test_pubkey();
        let slot = 200;
        let block = test_blinded_block(slot);
        let beacon = MockBeaconClient::blinded(block);
        let signer = MockSigner::new();
        let service = build_service(signer, beacon, &pubkey);

        let result = service.propose_block(slot, &pubkey).await;

        assert!(result.is_ok());
        let proposal = result.unwrap();
        assert_eq!(proposal.slot, slot);
        assert!(proposal.is_blinded);
        assert_eq!(proposal.consensus_version, "deneb");
        assert!(proposal.value_wei.is_none());
        assert_ne!(proposal.block_root, [0u8; 32]);
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
        assert_eq!(unblinded_calls[0].0, unblinded_result.block_root);
        assert_eq!(blinded_calls[0].0, blinded_result.block_root);
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
        assert_eq!(block_calls[0].0, expected_root);
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

        let calls = signer_arc.randao_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], 10); // epoch = 320/32
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
}
