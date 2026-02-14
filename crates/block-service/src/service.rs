use std::sync::Arc;

use tracing::info;
use tree_hash::TreeHash;

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

    pub async fn propose_block(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<BlockProposalResult, BlockServiceError> {
        let epoch = slot / SLOTS_PER_EPOCH;

        // 1. Sign RANDAO reveal
        let randao_bytes = self
            .signer
            .sign_randao_reveal(epoch, pubkey, &self.fork_schedule, &self.genesis_validators_root)
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;
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
            .await?;

        // 4. Sign and publish based on block type
        let (block_root, is_blinded) = if response.is_blinded {
            self.sign_and_publish_blinded(&response, slot, pubkey).await?
        } else {
            self.sign_and_publish_full(&response, slot, pubkey).await?
        };

        let block_type = if is_blinded { "blinded" } else { "unblinded" };
        info!(
            slot,
            block_type,
            consensus_version = %response.consensus_version,
            value_wei = response.execution_payload_value.as_deref().unwrap_or("unknown"),
            "block proposed"
        );

        Ok(BlockProposalResult {
            slot,
            block_root,
            is_blinded,
            consensus_version: response.consensus_version,
            value_wei: response.execution_payload_value,
        })
    }

    async fn sign_and_publish_full(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<(Root, bool), BlockServiceError> {
        let block_contents = response.parse_full_block()?;
        let block = block_contents.block().clone();
        let block_root = compute_block_root(&block);

        let sig = self
            .signer
            .sign_block(
                &block_root,
                slot,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;

        let signed = eth_types::SignedBeaconBlock { message: block, signature: sig };
        self.beacon.publish_block(&signed, &response.consensus_version).await?;

        Ok((block_root, false))
    }

    async fn sign_and_publish_blinded(
        &self,
        response: &ProduceBlockResponse,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<(Root, bool), BlockServiceError> {
        let block = response.parse_blinded_block()?;
        let block_root = compute_blinded_block_root(&block);

        let sig = self
            .signer
            .sign_block(
                &block_root,
                slot,
                pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .await
            .map_err(|e| BlockServiceError::Signer(e.to_string()))?;

        let signed = eth_types::SignedBlindedBeaconBlock { message: block, signature: sig };
        self.beacon.publish_blinded_block(&signed, &response.consensus_version).await?;

        Ok((block_root, true))
    }
}

fn compute_block_root(block: &eth_types::BeaconBlock) -> Root {
    block.tree_hash_root().0
}

fn compute_blinded_block_root(block: &eth_types::BlindedBeaconBlock) -> Root {
    block.tree_hash_root().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use eth_types::{BeaconBlock, BlindedBeaconBlock, SignedBeaconBlock, SignedBlindedBeaconBlock};
    use signer::SignerError;
    use std::cell::RefCell;
    use std::sync::Arc;
    use validator_store::ValidatorStore;

    // --- Mock Signer ---

    struct MockSigner {
        fail_randao: bool,
        fail_block: bool,
        randao_calls: RefCell<Vec<u64>>,
        block_calls: RefCell<Vec<(Root, Slot)>>,
    }

    impl MockSigner {
        fn new() -> Self {
            Self {
                fail_randao: false,
                fail_block: false,
                randao_calls: RefCell::new(Vec::new()),
                block_calls: RefCell::new(Vec::new()),
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
            self.block_calls.borrow_mut().push((*block_root, slot));
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
            self.randao_calls.borrow_mut().push(epoch);
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
        publish_calls: RefCell<Vec<String>>,
        publish_blinded_calls: RefCell<Vec<String>>,
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
                publish_calls: RefCell::new(Vec::new()),
                publish_blinded_calls: RefCell::new(Vec::new()),
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
                publish_calls: RefCell::new(Vec::new()),
                publish_blinded_calls: RefCell::new(Vec::new()),
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
            self.publish_calls.borrow_mut().push(consensus_version.to_string());
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
            self.publish_blinded_calls.borrow_mut().push(consensus_version.to_string());
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
            graffiti_arg: RefCell<Option<String>>,
            boost_arg: RefCell<Option<u64>>,
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
                *self.graffiti_arg.borrow_mut() = graffiti.map(|s| s.to_string());
                *self.boost_arg.borrow_mut() = builder_boost_factor;
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
        }

        let capturing_beacon = CapturingBeacon {
            inner: MockBeaconClient::unblinded(block),
            graffiti_arg: RefCell::new(None),
            boost_arg: RefCell::new(None),
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
        let graffiti = service.beacon.graffiti_arg.borrow().clone();
        assert!(graffiti.is_some());
        let graffiti_str = graffiti.unwrap();
        assert!(graffiti_str.starts_with("0x"));
        // "hello" = 68656c6c6f
        assert!(graffiti_str.contains("68656c6c6f"));

        // Verify boost factor was passed
        let boost = *service.beacon.boost_arg.borrow();
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

        assert_eq!(beacon_arc.publish_blinded_calls.borrow().len(), 1);
        assert!(beacon_arc.publish_calls.borrow().is_empty());
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

        assert_eq!(beacon_arc.publish_calls.borrow().len(), 1);
        assert!(beacon_arc.publish_blinded_calls.borrow().is_empty());
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
        assert!(beacon_arc.publish_blinded_calls.borrow().is_empty());
        assert!(beacon_arc.publish_calls.borrow().is_empty());
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
        let unblinded_calls = signer_arc.block_calls.borrow();
        let blinded_calls = signer2_arc.block_calls.borrow();
        assert_eq!(unblinded_calls.len(), 1);
        assert_eq!(blinded_calls.len(), 1);
        assert_eq!(unblinded_calls[0].0, unblinded_result.block_root);
        assert_eq!(blinded_calls[0].0, blinded_result.block_root);
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

        let calls = signer_arc.randao_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], 10); // epoch = 320/32
    }
}
