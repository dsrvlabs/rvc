use std::time::Duration;

use async_trait::async_trait;

use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
    BlockRootResponse, ConfigSpecResponse, GenesisResponse, ProduceBlockResponse,
    ProposerDutiesResponse, ProposerPreparation, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, SyncingResponse, ValidatorsResponse, VersionedAggregateAttestation,
    VersionedAttestation, VersionedSignedAggregateAndProof,
};
use eth_types::{
    ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedValidatorRegistration,
};

/// Comprehensive trait abstracting all beacon node operations.
///
/// Domain crates depend on this trait instead of `BeaconClient` directly,
/// enabling multi-BN failover, health-based selection, and testability.
#[async_trait]
pub trait BeaconNodeClient: Send + Sync {
    // -- State / Config --

    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError>;

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError>;

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError>;

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError>;

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError>;

    // -- Duties --

    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError>;

    async fn get_proposer_duties(&self, epoch: u64) -> Result<ProposerDutiesResponse, BeaconError>;

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError>;

    // -- Block production --

    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError>;

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError>;

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError>;

    // -- Attestation --

    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError>;

    async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError>;

    // -- Aggregation --

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError>;

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError>;

    // -- Sync committee --

    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError>;

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError>;

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError>;

    // -- Blocks --

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError>;

    // -- Proposer preparation --

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError>;

    // -- Committee subscriptions --

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError>;

    // -- Builder --

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError>;

    // -- Node status --

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError>;

    async fn get_node_version(&self) -> Result<String, BeaconError>;
}

/// Per-operation timeout configuration for beacon node API calls.
#[derive(Debug, Clone)]
pub struct OperationTimeouts {
    pub block_production: Duration,
    pub block_publication: Duration,
    pub attestation_fetch: Duration,
    pub attestation_submit: Duration,
    pub aggregate_fetch: Duration,
    pub aggregate_submit: Duration,
    pub sync_message: Duration,
    pub sync_contribution: Duration,
    pub duty_fetch: Duration,
    pub preparation: Duration,
}

impl Default for OperationTimeouts {
    fn default() -> Self {
        Self {
            block_production: Duration::from_secs(3),
            block_publication: Duration::from_secs(2),
            attestation_fetch: Duration::from_secs(4),
            attestation_submit: Duration::from_secs(2),
            aggregate_fetch: Duration::from_secs(2),
            aggregate_submit: Duration::from_secs(2),
            sync_message: Duration::from_secs(2),
            sync_contribution: Duration::from_secs(2),
            duty_fetch: Duration::from_secs(10),
            preparation: Duration::from_secs(3),
        }
    }
}

/// Strategy for selecting a beacon node when multiple are configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BnSelectionStrategy {
    /// Use the first healthy BN; fail over to the next on error.
    First,
    /// Query all BNs in parallel and pick the best result.
    Best,
}

/// Controls which message types are broadcast to all BNs vs sent to the first healthy BN.
///
/// When a topic is `true`, the corresponding submission is broadcast to all BNs.
/// When `false`, only the first healthy BN receives the message (query_first strategy).
/// Default: all topics enabled (current behavior preserved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastTopics {
    pub attestations: bool,
    pub blocks: bool,
    pub sync_committee: bool,
    pub subscriptions: bool,
}

impl Default for BroadcastTopics {
    fn default() -> Self {
        Self { attestations: true, blocks: true, sync_committee: true, subscriptions: true }
    }
}

/// Configuration for the beacon node manager.
#[derive(Debug, Clone)]
pub struct BnManagerConfig {
    /// Beacon node endpoint URLs.
    pub endpoints: Vec<String>,
    /// Default selection strategy for query operations.
    pub selection_strategy: BnSelectionStrategy,
    /// Per-BN request timeout.
    pub timeout: Duration,
    /// Which submission types are broadcast to all BNs.
    pub broadcast_topics: BroadcastTopics,
    /// Per-BN role assignments (parallel to endpoints). Default: {All} for each.
    pub roles: Vec<std::collections::HashSet<crate::types::BnRole>>,
    /// Health tier thresholds for sync distance classification.
    pub tier_thresholds: crate::types::TierThresholds,
}

impl BnManagerConfig {
    pub fn new(endpoints: Vec<String>) -> Self {
        let count = endpoints.len();
        Self {
            endpoints,
            selection_strategy: BnSelectionStrategy::First,
            timeout: Duration::from_secs(30),
            broadcast_topics: BroadcastTopics::default(),
            roles: vec![
                {
                    let mut s = std::collections::HashSet::new();
                    s.insert(crate::types::BnRole::All);
                    s
                };
                count
            ],
            tier_thresholds: crate::types::TierThresholds::default(),
        }
    }
}

/// Health score for a beacon node, used for selection and failover decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct BnHealthScore {
    /// Endpoint URL of the beacon node.
    pub endpoint: String,
    /// Whether the node is currently reachable.
    pub is_reachable: bool,
    /// Whether the node is fully synced.
    pub is_synced: bool,
    /// Whether the node's execution layer is offline.
    pub is_el_offline: bool,
    /// Latest observed head slot from the node.
    pub head_slot: Option<u64>,
    /// Response latency for the most recent health check.
    pub latency: Option<Duration>,
    /// Exponential moving average latency in milliseconds.
    pub latency_ms: f64,
    /// Error rate as a fraction (0.0 = no errors, 1.0 = all errors).
    pub error_rate: f64,
    /// Composite health score (0.0 = worst, 1.0 = best).
    pub score: f64,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // -- Trait object safety --

    #[test]
    fn test_trait_is_object_safe() {
        // This test verifies that BeaconNodeClient can be used as a trait object.
        // If the trait is not object-safe, this will fail to compile.
        fn _assert_object_safe(_: &dyn BeaconNodeClient) {}
    }

    #[test]
    fn test_trait_can_be_arc_wrapped() {
        // Verifies Arc<dyn BeaconNodeClient> compiles (Send + Sync required).
        fn _assert_arc_dyn(_: Arc<dyn BeaconNodeClient>) {}
    }

    // -- BnSelectionStrategy --

    #[test]
    fn test_selection_strategy_first() {
        let strategy = BnSelectionStrategy::First;
        assert_eq!(strategy, BnSelectionStrategy::First);
    }

    #[test]
    fn test_selection_strategy_best() {
        let strategy = BnSelectionStrategy::Best;
        assert_eq!(strategy, BnSelectionStrategy::Best);
    }

    #[test]
    fn test_selection_strategy_ne() {
        assert_ne!(BnSelectionStrategy::First, BnSelectionStrategy::Best);
    }

    #[test]
    fn test_selection_strategy_clone() {
        let strategy = BnSelectionStrategy::Best;
        let cloned = strategy;
        assert_eq!(cloned, BnSelectionStrategy::Best);
    }

    #[test]
    fn test_selection_strategy_debug() {
        let strategy = BnSelectionStrategy::First;
        let debug = format!("{:?}", strategy);
        assert!(debug.contains("First"));
    }

    // -- BnManagerConfig --

    #[test]
    fn test_config_new_defaults() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.endpoints[0], "http://localhost:5052");
        assert_eq!(config.selection_strategy, BnSelectionStrategy::First);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_multiple_endpoints() {
        let config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
            "http://bn3:5052".to_string(),
        ]);
        assert_eq!(config.endpoints.len(), 3);
    }

    #[test]
    fn test_config_empty_endpoints() {
        let config = BnManagerConfig::new(vec![]);
        assert!(config.endpoints.is_empty());
    }

    #[test]
    fn test_config_clone() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let cloned = config.clone();
        assert_eq!(cloned.endpoints, config.endpoints);
        assert_eq!(cloned.selection_strategy, config.selection_strategy);
        assert_eq!(cloned.timeout, config.timeout);
    }

    #[test]
    fn test_config_debug() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let debug = format!("{:?}", config);
        assert!(debug.contains("BnManagerConfig"));
        assert!(debug.contains("localhost"));
    }

    // -- BnHealthScore --

    #[test]
    fn test_health_score_healthy() {
        let score = BnHealthScore {
            endpoint: "http://localhost:5052".to_string(),
            is_reachable: true,
            is_synced: true,
            is_el_offline: false,
            head_slot: Some(1000),
            latency: Some(Duration::from_millis(50)),
            latency_ms: 50.0,
            error_rate: 0.0,
            score: 0.99,
        };
        assert!(score.is_reachable);
        assert!(score.is_synced);
        assert_eq!(score.head_slot, Some(1000));
        assert!(score.score > 0.9);
    }

    #[test]
    fn test_health_score_unreachable() {
        let score = BnHealthScore {
            endpoint: "http://dead-node:5052".to_string(),
            is_reachable: false,
            is_synced: false,
            is_el_offline: false,
            head_slot: None,
            latency: None,
            latency_ms: 0.0,
            error_rate: 1.0,
            score: 0.0,
        };
        assert!(!score.is_reachable);
        assert!(!score.is_synced);
        assert!(score.head_slot.is_none());
        assert!(score.latency.is_none());
        assert_eq!(score.error_rate, 1.0);
    }

    #[test]
    fn test_health_score_syncing() {
        let score = BnHealthScore {
            endpoint: "http://syncing:5052".to_string(),
            is_reachable: true,
            is_synced: false,
            is_el_offline: false,
            head_slot: Some(500),
            latency: Some(Duration::from_millis(200)),
            latency_ms: 200.0,
            error_rate: 0.1,
            score: 0.8,
        };
        assert!(score.is_reachable);
        assert!(!score.is_synced);
        assert_eq!(score.head_slot, Some(500));
    }

    #[test]
    fn test_health_score_clone() {
        let score = BnHealthScore {
            endpoint: "http://localhost:5052".to_string(),
            is_reachable: true,
            is_synced: true,
            is_el_offline: false,
            head_slot: Some(1000),
            latency: Some(Duration::from_millis(50)),
            latency_ms: 50.0,
            error_rate: 0.0,
            score: 0.99,
        };
        let cloned = score.clone();
        assert_eq!(score, cloned);
    }

    #[test]
    fn test_health_score_debug() {
        let score = BnHealthScore {
            endpoint: "http://localhost:5052".to_string(),
            is_reachable: true,
            is_synced: true,
            is_el_offline: false,
            head_slot: Some(1000),
            latency: Some(Duration::from_millis(50)),
            latency_ms: 50.0,
            error_rate: 0.0,
            score: 0.99,
        };
        let debug = format!("{:?}", score);
        assert!(debug.contains("BnHealthScore"));
        assert!(debug.contains("localhost"));
    }

    // -- OperationTimeouts --

    #[test]
    fn test_operation_timeouts_default_values() {
        let t = OperationTimeouts::default();
        assert_eq!(t.block_production, Duration::from_secs(3));
        assert_eq!(t.block_publication, Duration::from_secs(2));
        assert_eq!(t.attestation_fetch, Duration::from_secs(4));
        assert_eq!(t.attestation_submit, Duration::from_secs(2));
        assert_eq!(t.aggregate_fetch, Duration::from_secs(2));
        assert_eq!(t.aggregate_submit, Duration::from_secs(2));
        assert_eq!(t.sync_message, Duration::from_secs(2));
        assert_eq!(t.sync_contribution, Duration::from_secs(2));
        assert_eq!(t.duty_fetch, Duration::from_secs(10));
        assert_eq!(t.preparation, Duration::from_secs(3));
    }

    #[test]
    fn test_operation_timeouts_clone() {
        let t = OperationTimeouts::default();
        let cloned = t.clone();
        assert_eq!(t.block_production, cloned.block_production);
        assert_eq!(t.duty_fetch, cloned.duty_fetch);
    }

    #[test]
    fn test_operation_timeouts_debug() {
        let t = OperationTimeouts::default();
        let debug = format!("{:?}", t);
        assert!(debug.contains("OperationTimeouts"));
    }

    // -- Mock trait implementation test --

    struct MockBeaconNodeClient;

    #[async_trait]
    impl BeaconNodeClient for MockBeaconNodeClient {
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
        async fn post_sync_committee_duties(
            &self,
            _epoch: u64,
            _validator_indices: &[String],
        ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
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
        async fn submit_sync_committee_messages(
            &self,
            _messages: &[SyncCommitteeMessage],
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
            _proofs: &[SignedContributionAndProof],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_block_root(&self, _block_id: &str) -> Result<BlockRootResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
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

    #[test]
    fn test_mock_implements_trait() {
        let _mock = MockBeaconNodeClient;
    }

    #[test]
    fn test_mock_as_arc_dyn() {
        let mock: Arc<dyn BeaconNodeClient> = Arc::new(MockBeaconNodeClient);
        // Verify it can be cloned as Arc
        let _clone = Arc::clone(&mock);
    }

    #[tokio::test]
    async fn test_mock_returns_error() {
        let mock = MockBeaconNodeClient;
        let result = mock.get_genesis().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_arc_dyn_method_call() {
        let mock: Arc<dyn BeaconNodeClient> = Arc::new(MockBeaconNodeClient);
        let result = mock.get_genesis().await;
        assert!(result.is_err());
    }

    // -- BroadcastTopics --

    #[test]
    fn test_broadcast_topics_default_all_enabled() {
        let topics = BroadcastTopics::default();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn test_broadcast_topics_all_disabled() {
        let topics = BroadcastTopics {
            attestations: false,
            blocks: false,
            sync_committee: false,
            subscriptions: false,
        };
        assert!(!topics.attestations);
        assert!(!topics.blocks);
    }

    #[test]
    fn test_broadcast_topics_partial() {
        let topics = BroadcastTopics {
            attestations: false,
            blocks: true,
            sync_committee: false,
            subscriptions: true,
        };
        assert!(!topics.attestations);
        assert!(topics.blocks);
        assert!(!topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn test_broadcast_topics_clone() {
        let topics = BroadcastTopics {
            attestations: true,
            blocks: false,
            sync_committee: true,
            subscriptions: false,
        };
        let cloned = topics.clone();
        assert_eq!(topics, cloned);
    }

    #[test]
    fn test_broadcast_topics_debug() {
        let topics = BroadcastTopics::default();
        let debug = format!("{:?}", topics);
        assert!(debug.contains("BroadcastTopics"));
    }

    #[test]
    fn test_bn_manager_config_includes_broadcast_topics() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        assert_eq!(config.broadcast_topics, BroadcastTopics::default());
    }
}
