use async_trait::async_trait;
use beacon::{
    AggregateAttestationResponse, Attestation, AttestationDataResponse, AttesterDutiesResponse,
    BeaconClient, BeaconCommitteeSubscription, BeaconError, BlockRootResponse, ConfigSpecResponse,
    GenesisResponse, ProduceBlockResponse, ProposerDutiesResponse, ProposerPreparation,
    SignedAggregateAndProof, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, ValidatorsResponse,
};
use eth_types::{ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock};

use url::Url;

use crate::traits::{BeaconNodeClient, BnManagerConfig};
use crate::BnManagerError;

/// Single beacon node manager that wraps a `BeaconClient` behind the `BeaconNodeClient` trait.
///
/// This initial implementation supports a single BN only, delegating all trait methods
/// to the wrapped `BeaconClient`. Multi-BN failover is added in C-03.
pub struct BnManager {
    client: BeaconClient,
}

impl BnManager {
    /// Creates a new `BnManager` from the given configuration.
    ///
    /// Validates that the endpoints list is non-empty and that the first endpoint
    /// has a valid URL scheme (http:// or https://). Uses the first endpoint only.
    pub fn new(config: BnManagerConfig) -> Result<Self, BnManagerError> {
        if config.endpoints.is_empty() {
            return Err(BnManagerError::NoEndpoints);
        }

        let endpoint = &config.endpoints[0];

        let parsed = Url::parse(endpoint)
            .map_err(|e| BnManagerError::InvalidEndpoint(format!("failed to parse URL: {e}")))?;

        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(BnManagerError::InvalidEndpoint(format!(
                "endpoint must use http or https scheme: {endpoint}"
            )));
        }

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(BnManagerError::InvalidEndpoint(
                "endpoint must not contain credentials".to_string(),
            ));
        }

        if parsed.host_str().is_none() || parsed.host_str() == Some("") {
            return Err(BnManagerError::InvalidEndpoint(
                "endpoint must contain a host".to_string(),
            ));
        }

        let client_config =
            beacon::BeaconClientConfig::new(endpoint.clone()).with_timeout(config.timeout);

        let client = BeaconClient::new(client_config)?;

        Ok(Self { client })
    }
}

#[async_trait]
impl BeaconNodeClient for BnManager {
    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        self.client.get_genesis().await
    }

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.client.get_config_spec().await
    }

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        self.client.get_fork_schedule().await
    }

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        self.client.get_fork(state_id).await
    }

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        self.client.get_validators(pubkeys).await
    }

    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        self.client.get_attester_duties(epoch, validator_indices).await
    }

    async fn get_proposer_duties(&self, epoch: u64) -> Result<ProposerDutiesResponse, BeaconError> {
        self.client.get_proposer_duties(epoch).await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.client.post_sync_committee_duties(epoch, validator_indices).await
    }

    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.client.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.client.publish_block(signed_block, consensus_version).await
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.client.publish_blinded_block(signed_blinded_block, consensus_version).await
    }

    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.client.get_attestation_data(slot, committee_index).await
    }

    async fn submit_attestation(
        &self,
        attestations: &[Attestation],
    ) -> Result<SubmitAttestationResult, BeaconError> {
        self.client.submit_attestation(attestations).await
    }

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
    ) -> Result<AggregateAttestationResponse, BeaconError> {
        self.client.get_aggregate_attestation(slot, attestation_data_root).await
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &[SignedAggregateAndProof],
    ) -> Result<(), BeaconError> {
        self.client.submit_aggregate_and_proofs(proofs).await
    }

    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.client.submit_sync_committee_messages(messages).await
    }

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.client
            .get_sync_committee_contribution(slot, subcommittee_index, beacon_block_root)
            .await
    }

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.client.submit_contribution_and_proofs(proofs).await
    }

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        self.client.get_block_root(block_id).await
    }

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.client.prepare_beacon_proposer(preparations).await
    }

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.client.submit_beacon_committee_subscriptions(subscriptions).await
    }
}

/// Implements `BeaconNodeClient` for `BeaconClient` directly, useful for tests
/// and cases where single-BN behavior without `BnManager` wrapping is desired.
#[async_trait]
impl BeaconNodeClient for BeaconClient {
    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        self.get_genesis().await
    }

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.get_config_spec().await
    }

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        self.get_fork_schedule().await
    }

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        self.get_fork(state_id).await
    }

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        self.get_validators(pubkeys).await
    }

    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        self.get_attester_duties(epoch, validator_indices).await
    }

    async fn get_proposer_duties(&self, epoch: u64) -> Result<ProposerDutiesResponse, BeaconError> {
        self.get_proposer_duties(epoch).await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.post_sync_committee_duties(epoch, validator_indices).await
    }

    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        BeaconClient::publish_block(self, signed_block, consensus_version).await
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        BeaconClient::publish_blinded_block(self, signed_blinded_block, consensus_version).await
    }

    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.get_attestation_data(slot, committee_index).await
    }

    async fn submit_attestation(
        &self,
        attestations: &[Attestation],
    ) -> Result<SubmitAttestationResult, BeaconError> {
        self.submit_attestation(attestations).await
    }

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
    ) -> Result<AggregateAttestationResponse, BeaconError> {
        self.get_aggregate_attestation(slot, attestation_data_root).await
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &[SignedAggregateAndProof],
    ) -> Result<(), BeaconError> {
        self.submit_aggregate_and_proofs(proofs).await
    }

    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.submit_sync_committee_messages(messages).await
    }

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.get_sync_committee_contribution(slot, subcommittee_index, beacon_block_root).await
    }

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.submit_contribution_and_proofs(proofs).await
    }

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        self.get_block_root(block_id).await
    }

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.prepare_beacon_proposer(preparations).await
    }

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.submit_beacon_committee_subscriptions(subscriptions).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    // -- Construction tests --

    #[test]
    fn test_new_with_single_endpoint() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let manager = BnManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_new_with_https_endpoint() {
        let config = BnManagerConfig::new(vec!["https://beacon.example.com".to_string()]);
        let manager = BnManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_new_with_empty_endpoints() {
        let config = BnManagerConfig::new(vec![]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::NoEndpoints));
    }

    #[test]
    fn test_new_with_invalid_scheme() {
        let config = BnManagerConfig::new(vec!["ftp://localhost:5052".to_string()]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_with_no_scheme() {
        let config = BnManagerConfig::new(vec!["localhost:5052".to_string()]);
        let result = BnManager::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_rejects_scheme_only_url() {
        let config = BnManagerConfig::new(vec!["http://".to_string()]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_rejects_url_with_credentials() {
        let config = BnManagerConfig::new(vec!["http://user:pass@localhost:5052".to_string()]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_accepts_valid_urls() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        assert!(BnManager::new(config).is_ok());

        let config = BnManagerConfig::new(vec!["https://beacon.example.com".to_string()]);
        assert!(BnManager::new(config).is_ok());
    }

    #[test]
    fn test_new_uses_first_endpoint() {
        let config = BnManagerConfig::new(vec![
            "http://first:5052".to_string(),
            "http://second:5052".to_string(),
        ]);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.client.endpoint(), "http://first:5052");
    }

    #[test]
    fn test_new_respects_timeout() {
        let mut config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        config.timeout = Duration::from_secs(10);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.client.timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_new_with_trailing_slash() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052/".to_string()]);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.client.endpoint(), "http://localhost:5052");
    }

    // -- Trait object compatibility --

    #[test]
    fn test_bn_manager_as_arc_dyn() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let manager = BnManager::new(config).unwrap();
        let _dyn_client: Arc<dyn BeaconNodeClient> = Arc::new(manager);
    }

    #[test]
    fn test_beacon_client_as_arc_dyn() {
        let config = beacon::BeaconClientConfig::new("http://localhost:5052");
        let client = BeaconClient::new(config).unwrap();
        let _dyn_client: Arc<dyn BeaconNodeClient> = Arc::new(client);
    }

    // -- Helper --

    fn make_manager(endpoint: &str) -> BnManager {
        let config = BnManagerConfig::new(vec![endpoint.to_string()]);
        BnManager::new(config).unwrap()
    }

    // -- BnManager delegation tests --

    #[tokio::test]
    async fn test_get_genesis_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_genesis().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data.genesis_time, "1606824023");
    }

    #[tokio::test]
    async fn test_get_config_spec_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"data":{"SECONDS_PER_SLOT":"12"}}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_config_spec().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data.get("SECONDS_PER_SLOT").unwrap(), "12");
    }

    #[tokio::test]
    async fn test_get_fork_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/fork"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"execution_optimistic":false,"finalized":true,"data":{"previous_version":"0x00000000","current_version":"0x01000000","epoch":"0"}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_fork("head").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_proposer_duties_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"dependent_root":"0xabc","execution_optimistic":false,"data":[]}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_proposer_duties(10).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_attester_duties_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/5"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"dependent_root":"0xdef","execution_optimistic":false,"data":[]}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_attester_duties(5, &["1".to_string(), "2".to_string()]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_block_root_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/blocks/head/root"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"data":{"root":"0xabcdef"}}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_block_root("head").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_attestation_data_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", "100"))
            .and(query_param("committee_index", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"slot":"100","index":"0","beacon_block_root":"0xabc","source":{"epoch":"3","root":"0x01"},"target":{"epoch":"4","root":"0x02"}}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_attestation_data(100, 0).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_sync_committee_messages_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.submit_sync_committee_messages(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_prepare_beacon_proposer_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.prepare_beacon_proposer(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_beacon_committee_subscriptions_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.submit_beacon_committee_subscriptions(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_aggregate_and_proofs_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.submit_aggregate_and_proofs(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_contribution_and_proofs_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/contribution_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.submit_contribution_and_proofs(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_post_sync_committee_duties_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/sync/3"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"execution_optimistic":false,"data":[]}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.post_sync_committee_duties(3, &["1".to_string()]).await;
        assert!(result.is_ok());
    }

    // -- BeaconClient direct trait impl tests --

    #[tokio::test]
    async fn test_beacon_client_get_genesis_via_trait() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = beacon::BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();
        let dyn_client: &dyn BeaconNodeClient = &client;
        let result = dyn_client.get_genesis().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data.genesis_time, "1606824023");
    }

    #[tokio::test]
    async fn test_beacon_client_get_block_root_via_trait() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/blocks/head/root"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"data":{"root":"0xabcdef"}}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = beacon::BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();
        let dyn_client: &dyn BeaconNodeClient = &client;
        let result = dyn_client.get_block_root("head").await;
        assert!(result.is_ok());
    }

    // -- Error propagation --

    #[tokio::test]
    async fn test_error_propagated_from_beacon_client() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let result = manager.get_genesis().await;
        assert!(result.is_err());
    }
}
