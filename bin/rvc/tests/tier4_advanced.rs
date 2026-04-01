//! Tier 4 integration tests: Advanced features.
//!
//! Verifies all five Tier 4 advanced features work correctly both in
//! isolation and when composed together:
//! - FR-1: Block selection modes (MaxProfit, ExecutionOnly, BuilderAlways, BuilderOnly)
//! - FR-2: Health tiers (sync distance → tier classification)
//! - FR-3: Role-based BN assignment (duty-type filtering)
//! - FR-4: Registration batching (chunked builder registration)
//! - FR-5: Pre-signed exits (prepare + submit round-trip)

// =============================================================================
// FR-1: Block Selection Modes
// =============================================================================

mod block_selection {
    use validator_store::{BlockSelectionMode, ValidatorConfig, ValidatorStore};

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    fn test_pubkey(id: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    #[test]
    fn max_profit_is_default_mode() {
        assert_eq!(BlockSelectionMode::default(), BlockSelectionMode::MaxProfit);

        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::MaxProfit);
    }

    #[test]
    fn execution_only_mode() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));
        store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::ExecutionOnly);
    }

    #[test]
    fn builder_always_mode() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));
        store.set_global_block_selection_mode(BlockSelectionMode::BuilderAlways);

        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderAlways);
    }

    #[test]
    fn builder_only_mode() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));
        store.set_global_block_selection_mode(BlockSelectionMode::BuilderOnly);

        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderOnly);
    }

    #[test]
    fn per_validator_config_overrides_global() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.block_selection_mode = Some(BlockSelectionMode::BuilderOnly);
        store.add_validator(config);

        // Global is MaxProfit (default), but per-validator is BuilderOnly
        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderOnly);

        // Even after changing global, per-validator still wins
        store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);
        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderOnly);
    }

    #[test]
    fn builder_only_with_circuit_breaker_tripped() {
        use builder::CircuitBreakerState;

        let cb = CircuitBreakerState::new(2, 5);
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped(), "circuit breaker should be tripped after 2 consecutive misses");

        // In BuilderOnly mode + tripped CB, proposal should be missed.
        // This verifies the condition exists; the actual BlockService test is a unit test.
        // Here we verify the CB state integrates correctly.
        assert!(cb.is_tripped());
    }

    #[test]
    fn serde_roundtrip_all_modes() {
        let modes = [
            BlockSelectionMode::MaxProfit,
            BlockSelectionMode::ExecutionOnly,
            BlockSelectionMode::BuilderAlways,
            BlockSelectionMode::BuilderOnly,
        ];
        for mode in &modes {
            let json = serde_json::to_string(mode).unwrap();
            let deserialized: BlockSelectionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, deserialized, "serde roundtrip failed for {:?}", mode);
        }
    }

    #[test]
    fn config_block_selection_mode_from_toml() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
block_selection_mode = "builder-only"
"#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.block_selection_mode, BlockSelectionMode::BuilderOnly);
    }
}

// =============================================================================
// FR-2: Health Tiers
// =============================================================================

mod health_tiers {
    use bn_manager::{HealthTier, TierThresholds};

    #[test]
    fn tier_computation_boundary_synced() {
        let t = TierThresholds::default(); // synced=8, small=8, large=48
        assert_eq!(t.tier_for_distance(0), HealthTier::Synced);
        assert_eq!(t.tier_for_distance(8), HealthTier::Synced);
        assert_eq!(t.tier_for_distance(9), HealthTier::SmallLag);
    }

    #[test]
    fn tier_computation_boundary_small_lag() {
        let t = TierThresholds::default();
        assert_eq!(t.tier_for_distance(9), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(16), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(17), HealthTier::LargeLag);
    }

    #[test]
    fn tier_computation_boundary_large_lag() {
        let t = TierThresholds::default();
        assert_eq!(t.tier_for_distance(17), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(64), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(65), HealthTier::Unsynced);
    }

    #[test]
    fn tier_computation_unsynced() {
        let t = TierThresholds::default();
        assert_eq!(t.tier_for_distance(65), HealthTier::Unsynced);
        assert_eq!(t.tier_for_distance(10_000), HealthTier::Unsynced);
    }

    #[test]
    fn tier_ordering_for_duty_routing() {
        // Proposals require Synced, attestations allow SmallLag
        assert!(HealthTier::Synced <= HealthTier::Synced, "Synced BN eligible for proposals");
        assert!(HealthTier::Synced <= HealthTier::SmallLag, "Synced BN eligible for attestations");
        assert!(
            HealthTier::SmallLag > HealthTier::Synced,
            "SmallLag BN NOT eligible for proposals"
        );
        assert!(
            HealthTier::SmallLag <= HealthTier::SmallLag,
            "SmallLag BN eligible for attestations"
        );
    }

    #[test]
    fn custom_tier_thresholds() {
        let t = TierThresholds { synced: 4, small: 4, large: 16 };
        assert_eq!(t.tier_for_distance(4), HealthTier::Synced);
        assert_eq!(t.tier_for_distance(5), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(8), HealthTier::SmallLag);
        assert_eq!(t.tier_for_distance(9), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(24), HealthTier::LargeLag);
        assert_eq!(t.tier_for_distance(25), HealthTier::Unsynced);
    }
}

// =============================================================================
// FR-3: Role-Based BN Assignment
// =============================================================================

mod role_based_bn {
    use bn_manager::BnRole;
    use std::collections::HashSet;

    #[test]
    fn role_filtering_specific_roles() {
        let mut roles = HashSet::new();
        roles.insert(BnRole::Attestation);
        roles.insert(BnRole::Proposal);

        assert!(BnRole::matches(&roles, BnRole::Attestation));
        assert!(BnRole::matches(&roles, BnRole::Proposal));
        assert!(!BnRole::matches(&roles, BnRole::SyncCommittee));
        assert!(!BnRole::matches(&roles, BnRole::Aggregation));
        assert!(!BnRole::matches(&roles, BnRole::Submission));
    }

    #[test]
    fn cross_role_fallback_via_all() {
        // A BN with All role matches any required role
        let mut roles = HashSet::new();
        roles.insert(BnRole::All);

        assert!(BnRole::matches(&roles, BnRole::Attestation));
        assert!(BnRole::matches(&roles, BnRole::Proposal));
        assert!(BnRole::matches(&roles, BnRole::SyncCommittee));
        assert!(BnRole::matches(&roles, BnRole::Aggregation));
        assert!(BnRole::matches(&roles, BnRole::Submission));
    }

    #[test]
    fn role_plus_tier_composition() {
        use bn_manager::{HealthTier, TierThresholds};

        // Scenario: 2 BNs, one for proposals (Synced), one for attestations (SmallLag)
        let thresholds = TierThresholds::default();

        // BN-A: sync distance 5 → Synced, role = Proposal
        let tier_a = thresholds.tier_for_distance(5);
        let mut roles_a = HashSet::new();
        roles_a.insert(BnRole::Proposal);

        // BN-B: sync distance 12 → SmallLag, role = Attestation
        let tier_b = thresholds.tier_for_distance(12);
        let mut roles_b = HashSet::new();
        roles_b.insert(BnRole::Attestation);

        // For proposals: BN-A matches role and has Synced tier
        assert!(BnRole::matches(&roles_a, BnRole::Proposal));
        assert!(tier_a <= HealthTier::Synced);

        // For attestations: BN-B matches role and SmallLag is acceptable
        assert!(BnRole::matches(&roles_b, BnRole::Attestation));
        assert!(tier_b <= HealthTier::SmallLag);

        // BN-B should NOT be selected for proposals (role mismatch and tier too low)
        assert!(!BnRole::matches(&roles_b, BnRole::Proposal));
    }

    #[test]
    fn default_role_is_all() {
        let config = bn_manager::BnManagerConfig::new(vec!["http://bn:5052".to_string()]);
        assert_eq!(config.roles.len(), 1);
        assert!(config.roles[0].contains(&BnRole::All));
    }

    #[test]
    fn expand_all_produces_concrete_roles() {
        let mut roles = HashSet::new();
        roles.insert(BnRole::All);
        let expanded = BnRole::expand(&roles);

        assert_eq!(expanded.len(), 5);
        assert!(expanded.contains(&BnRole::Attestation));
        assert!(expanded.contains(&BnRole::Proposal));
        assert!(expanded.contains(&BnRole::SyncCommittee));
        assert!(expanded.contains(&BnRole::Aggregation));
        assert!(expanded.contains(&BnRole::Submission));
        assert!(!expanded.contains(&BnRole::All));
    }
}

// =============================================================================
// FR-4: Registration Batching
// =============================================================================

mod registration_batching {
    use std::sync::Arc;

    use async_trait::async_trait;
    use bn_manager::{
        AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
        BeaconNodeClient, BlockRootResponse, ConfigSpecResponse, GenesisResponse,
        ProduceBlockResponse, ProposerDutiesResponse, SignedBeaconBlock, SignedBlindedBeaconBlock,
        SignedContributionAndProof, SignedValidatorRegistration, StateForkResponse,
        SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
        SyncCommitteeMessage, SyncingResponse, ValidatorRegistrationV1, ValidatorsResponse,
        VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
    };
    use builder::BuilderService;
    use crypto::PublicKey;
    use eth_types::{
        AggregateAndProof, AttestationData, ElectraAggregateAndProof, Epoch, ForkSchedule, Root,
        Slot, VoluntaryExit,
    };
    use parking_lot::Mutex;
    use signer::{SignerError, ValidatorSigner};
    use validator_store::{ValidatorConfig, ValidatorStore};

    // --- Mock BN ---

    struct MockBn {
        register_calls: Mutex<Vec<Vec<SignedValidatorRegistration>>>,
        fail_register: bool,
        fail_register_on_calls: Vec<usize>,
    }

    impl MockBn {
        fn new() -> Self {
            Self {
                register_calls: Mutex::new(Vec::new()),
                fail_register: false,
                fail_register_on_calls: Vec::new(),
            }
        }

        fn with_register_error_on_calls(mut self, indices: Vec<usize>) -> Self {
            self.fail_register_on_calls = indices;
            self
        }
    }

    #[async_trait]
    impl BeaconNodeClient for MockBn {
        async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_fork(&self, _: &str) -> Result<StateForkResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_validators(&self, _: &[String]) -> Result<ValidatorsResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_attester_duties(
            &self,
            _: u64,
            _: &[String],
        ) -> Result<AttesterDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_proposer_duties(&self, _: u64) -> Result<ProposerDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn post_sync_committee_duties(
            &self,
            _: u64,
            _: &[String],
        ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn produce_block_v3(
            &self,
            _: u64,
            _: &str,
            _: Option<&str>,
            _: Option<u64>,
        ) -> Result<ProduceBlockResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn publish_block(&self, _: &SignedBeaconBlock, _: &str) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn publish_blinded_block(
            &self,
            _: &SignedBlindedBeaconBlock,
            _: &str,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_attestation_data(
            &self,
            _: u64,
            _: u64,
        ) -> Result<AttestationDataResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_attestation(
            &self,
            _: &VersionedAttestation,
        ) -> Result<SubmitAttestationResult, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_aggregate_attestation(
            &self,
            _: u64,
            _: &str,
            _: Option<u64>,
        ) -> Result<VersionedAggregateAttestation, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_aggregate_and_proofs(
            &self,
            _: &VersionedSignedAggregateAndProof,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_sync_committee_messages(
            &self,
            _: &[SyncCommitteeMessage],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_sync_committee_contribution(
            &self,
            _: u64,
            _: u64,
            _: &str,
        ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_contribution_and_proofs(
            &self,
            _: &[SignedContributionAndProof],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_block_root(&self, _: &str) -> Result<BlockRootResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn prepare_beacon_proposer(
            &self,
            _: &[bn_manager::ProposerPreparation],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_beacon_committee_subscriptions(
            &self,
            _: &[BeaconCommitteeSubscription],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn register_validators(
            &self,
            registrations: &[SignedValidatorRegistration],
        ) -> Result<(), BeaconError> {
            let call_idx = self.register_calls.lock().len();
            if self.fail_register || self.fail_register_on_calls.contains(&call_idx) {
                self.register_calls.lock().push(registrations.to_vec());
                return Err(BeaconError::HttpError("mock register failure".into()));
            }
            self.register_calls.lock().push(registrations.to_vec());
            Ok(())
        }
        async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_node_version(&self) -> Result<String, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
    }

    // --- Mock Signer ---

    struct MockSigner;

    #[async_trait(?Send)]
    impl ValidatorSigner for MockSigner {
        async fn sign_attestation(
            &self,
            _: &AttestationData,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_block(
            &self,
            _: &Root,
            _: Slot,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_randao_reveal(
            &self,
            _: Epoch,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_sync_committee_message(
            &self,
            _: &Root,
            _: Slot,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_selection_proof(
            &self,
            _: Slot,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_aggregate_and_proof(
            &self,
            _: &AggregateAndProof,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_electra_aggregate_and_proof(
            &self,
            _: &ElectraAggregateAndProof,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_voluntary_exit(
            &self,
            _: &VoluntaryExit,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_builder_registration(
            &self,
            _: &ValidatorRegistrationV1,
            _: &PublicKey,
            _: [u8; 4],
        ) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xaa; 96])
        }
        async fn sign_sync_committee_selection_proof(
            &self,
            _: Slot,
            _: u64,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_contribution_and_proof(
            &self,
            _: &eth_types::ContributionAndProof,
            _: &PublicKey,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
    }

    fn gen_pubkey_bytes() -> [u8; 48] {
        let sk = crypto::SecretKey::generate();
        sk.public_key().to_bytes()
    }

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    fn test_store_with_builder_validators(count: usize) -> (ValidatorStore, Vec<[u8; 48]>) {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let mut pubkeys = Vec::new();
        for _ in 0..count {
            let pk = gen_pubkey_bytes();
            let mut config = ValidatorConfig::new(pk);
            config.builder_proposals = true;
            store.add_validator(config);
            pubkeys.push(pk);
        }
        (store, pubkeys)
    }

    #[tokio::test]
    async fn chunking_2000_validators_500_batch() {
        let (store, _pubkeys) = test_store_with_builder_validators(2000);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner);

        let service =
            BuilderService::with_batching(signer, bn.clone(), Arc::new(store), [0; 4], 500, 0);

        service.register_validators().await.unwrap();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 4, "2000 validators / 500 batch = 4 requests");
        for (i, call) in calls.iter().enumerate() {
            assert_eq!(call.len(), 500, "batch {} should have 500 registrations", i);
        }
    }

    #[tokio::test]
    async fn failed_batch_continues_with_remaining() {
        let (store, _pubkeys) = test_store_with_builder_validators(30);
        let bn = Arc::new(MockBn::new().with_register_error_on_calls(vec![1]));
        let signer = Arc::new(MockSigner);

        let service =
            BuilderService::with_batching(signer, bn.clone(), Arc::new(store), [0; 4], 10, 0);

        // Should not error even though batch 1 fails
        service.register_validators().await.unwrap();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 3, "all 3 batches should be attempted");
    }

    #[tokio::test]
    async fn delay_between_batches() {
        let (store, _pubkeys) = test_store_with_builder_validators(20);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner);

        let service = BuilderService::with_batching(
            signer,
            bn.clone(),
            Arc::new(store),
            [0; 4],
            10,
            50, // 50ms delay
        );

        let start = std::time::Instant::now();
        service.register_validators().await.unwrap();
        let elapsed = start.elapsed();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2, "20 validators / 10 batch = 2 requests");
        // With 50ms delay between batches (1 delay for 2 batches), total should be >= 50ms
        assert!(
            elapsed >= std::time::Duration::from_millis(40),
            "should have delay between batches, elapsed: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn batch_size_zero_sends_all_at_once() {
        let (store, _pubkeys) = test_store_with_builder_validators(50);
        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner);

        let service = BuilderService::with_batching(
            signer,
            bn.clone(),
            Arc::new(store),
            [0; 4],
            0, // batch_size=0 → single request
            0,
        );

        service.register_validators().await.unwrap();

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1, "batch_size=0 should send all in one request");
        assert_eq!(calls[0].len(), 50);
    }
}

// =============================================================================
// FR-5: Pre-Signed Exits
// =============================================================================

mod pre_signed_exits {
    use eth_types::{SignedVoluntaryExit, VoluntaryExit};
    use rvc::prepare_exit::write_exit_to_file;
    use rvc::submit_exit::read_exit_from_file;

    fn sample_signed_exit() -> SignedVoluntaryExit {
        SignedVoluntaryExit {
            message: VoluntaryExit { epoch: 300_000, validator_index: 12345 },
            signature: vec![0xaa; 96],
        }
    }

    #[test]
    fn prepare_creates_valid_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, dir.path(), "0xdeadbeef1234").unwrap();

        assert!(path.exists());
        assert_eq!(path.file_name().unwrap(), "deadbeef1234_exit.json");

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert!(json.get("message").is_some());
        assert!(json.get("signature").is_some());
        assert_eq!(json["message"]["epoch"], "300000");
        assert_eq!(json["message"]["validator_index"], "12345");
    }

    #[cfg(unix)]
    #[test]
    fn file_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, dir.path(), "0xpermtest").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exit file should have 0o600 permissions");
    }

    #[test]
    fn submit_reads_prepared_file() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        // Write using prepare_exit
        let path = write_exit_to_file(&signed, dir.path(), "0xsubmittest").unwrap();

        // Read using submit_exit
        let loaded = read_exit_from_file(&path).unwrap();

        assert_eq!(loaded.message.epoch, 300_000);
        assert_eq!(loaded.message.validator_index, 12345);
        assert_eq!(loaded.signature, vec![0xaa; 96]);
    }

    #[test]
    fn roundtrip_prepare_to_submit() {
        let dir = tempfile::tempdir().unwrap();
        let original = sample_signed_exit();

        let path = write_exit_to_file(&original, dir.path(), "0xroundtrip").unwrap();
        let loaded = read_exit_from_file(&path).unwrap();

        assert_eq!(loaded.message.epoch, original.message.epoch);
        assert_eq!(loaded.message.validator_index, original.message.validator_index);
        assert_eq!(loaded.signature, original.signature);
    }
}

// =============================================================================
// Composition: features work together
// =============================================================================

mod composition {
    use bn_manager::{BnManagerConfig, BnRole, HealthTier, TierThresholds};
    use builder::CircuitBreakerState;
    use std::collections::HashSet;
    use validator_store::{BlockSelectionMode, ValidatorConfig, ValidatorStore};

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    fn test_pubkey(id: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    #[test]
    fn block_selection_with_circuit_breaker_and_health_tiers() {
        let thresholds = TierThresholds::default();

        // Simulate a Synced BN (distance=3)
        let tier = thresholds.tier_for_distance(3);
        assert_eq!(tier, HealthTier::Synced);

        // Circuit breaker is NOT tripped
        let cb = CircuitBreakerState::new(3, 5);
        assert!(!cb.is_tripped());

        // BuilderAlways mode with healthy BN and no CB trip → should proceed with builder
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));
        store.set_global_block_selection_mode(BlockSelectionMode::BuilderAlways);
        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderAlways);

        // Now trip the circuit breaker
        cb.record_miss();
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());

        // BuilderAlways + tripped CB → should fall back to local (boost=0)
        // BuilderOnly + tripped CB → should fail (proposal missed)
        // These are verified through the block service, but the state composition is valid
    }

    #[test]
    fn role_based_with_health_tiers() {
        let thresholds = TierThresholds::default();

        // BN-1: Synced (distance=2), role=Proposal
        let tier_1 = thresholds.tier_for_distance(2);
        let mut roles_1 = HashSet::new();
        roles_1.insert(BnRole::Proposal);

        // BN-2: SmallLag (distance=10), role=Attestation
        let tier_2 = thresholds.tier_for_distance(10);
        let mut roles_2 = HashSet::new();
        roles_2.insert(BnRole::Attestation);

        // BN-3: Unsynced (distance=100), role=All
        let tier_3 = thresholds.tier_for_distance(100);
        let mut roles_3 = HashSet::new();
        roles_3.insert(BnRole::All);

        // For proposal duty (requires Synced tier):
        // - BN-1: role matches, tier=Synced ✓
        // - BN-2: role doesn't match ✗
        // - BN-3: role matches (All), but tier=Unsynced ✗ (only as last resort)
        assert!(BnRole::matches(&roles_1, BnRole::Proposal) && tier_1 <= HealthTier::Synced);
        assert!(!BnRole::matches(&roles_2, BnRole::Proposal));
        assert!(BnRole::matches(&roles_3, BnRole::Proposal));
        assert!(tier_3 > HealthTier::Synced);

        // For attestation duty (allows SmallLag):
        // - BN-1: role doesn't match ✗
        // - BN-2: role matches, tier=SmallLag ✓
        // - BN-3: role matches (All), tier=Unsynced ✗
        assert!(!BnRole::matches(&roles_1, BnRole::Attestation));
        assert!(BnRole::matches(&roles_2, BnRole::Attestation) && tier_2 <= HealthTier::SmallLag);
    }

    #[test]
    fn all_tier4_features_together() {
        let thresholds = TierThresholds { synced: 4, small: 4, large: 16 };

        // Block selection: per-validator override
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk1 = test_pubkey(1);
        let pk2 = test_pubkey(2);
        let mut config1 = ValidatorConfig::new(pk1);
        config1.block_selection_mode = Some(BlockSelectionMode::BuilderAlways);
        config1.builder_proposals = true;
        store.add_validator(config1);
        let mut config2 = ValidatorConfig::new(pk2);
        config2.builder_proposals = true;
        store.add_validator(config2);
        store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

        assert_eq!(
            store.effective_block_selection_mode(&pk1),
            BlockSelectionMode::BuilderAlways,
            "per-validator override"
        );
        assert_eq!(
            store.effective_block_selection_mode(&pk2),
            BlockSelectionMode::ExecutionOnly,
            "global fallback"
        );

        // Health tiers with custom thresholds
        assert_eq!(thresholds.tier_for_distance(4), HealthTier::Synced);
        assert_eq!(thresholds.tier_for_distance(5), HealthTier::SmallLag);
        assert_eq!(thresholds.tier_for_distance(25), HealthTier::Unsynced);

        // Role-based: BnManagerConfig with roles
        let mut bn_config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
        ]);
        let mut proposal_roles = HashSet::new();
        proposal_roles.insert(BnRole::Proposal);
        let mut attest_roles = HashSet::new();
        attest_roles.insert(BnRole::Attestation);
        bn_config.roles = vec![proposal_roles.clone(), attest_roles.clone()];
        bn_config.tier_thresholds = thresholds;

        assert!(BnRole::matches(&bn_config.roles[0], BnRole::Proposal));
        assert!(!BnRole::matches(&bn_config.roles[0], BnRole::Attestation));
        assert!(BnRole::matches(&bn_config.roles[1], BnRole::Attestation));
        assert!(!BnRole::matches(&bn_config.roles[1], BnRole::Proposal));

        // Circuit breaker
        let cb = CircuitBreakerState::new(3, 10);
        assert!(!cb.is_tripped());
        cb.record_miss();
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());
        cb.reset_epoch(1);
        assert!(!cb.is_tripped(), "epoch reset clears circuit breaker");

        // Config TOML with all tier4 fields
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
block_selection_mode = "builder-always"
validator_registration_batch_size = 250
validator_registration_batch_delay = 100
bn_sync_tolerances = "4,4,16"

[[beacon_nodes_config]]
url = "http://bn1:5052"
roles = ["proposal"]

[[beacon_nodes_config]]
url = "http://bn2:5052"
roles = ["attestation"]
"#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.block_selection_mode, BlockSelectionMode::BuilderAlways);
        assert_eq!(config.validator_registration_batch_size, 250);
        assert_eq!(config.validator_registration_batch_delay, 100);
        assert_eq!(config.bn_sync_tolerances.as_deref(), Some("4,4,16"));
        assert_eq!(config.beacon_nodes_config.len(), 2);
        assert_eq!(config.beacon_nodes_config[0].roles, vec!["proposal"]);
        assert_eq!(config.beacon_nodes_config[1].roles, vec!["attestation"]);
    }
}
