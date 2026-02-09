use std::future::Future;
use std::pin::Pin;

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
use futures::future::join_all;
use tracing::{debug, warn};
use url::Url;

use crate::sse::{self, SseConfig, SseEvent};
use crate::traits::{BeaconNodeClient, BnManagerConfig};
use crate::BnManagerError;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, BeaconError>> + Send + 'a>>;
type IndexedResultFut<'a, T> =
    Pin<Box<dyn Future<Output = (usize, String, Result<T, BeaconError>)> + Send + 'a>>;

/// Beacon node manager with multi-BN support, strategy-based selection, and broadcast.
///
/// Supports three operation modes:
/// - **First**: Try BNs in order, fail over on error (used for duty fetching, attestation data)
/// - **Best**: Query all BNs in parallel, pick best result (used for block production)
/// - **Broadcast**: Send to all BNs, return first success (used for all submissions)
pub struct BnManager {
    clients: Vec<BeaconClient>,
}

impl BnManager {
    /// Creates a new `BnManager` from the given configuration.
    ///
    /// Validates that the endpoints list is non-empty and that all endpoints
    /// have valid URL schemes (http:// or https://). Creates a `BeaconClient`
    /// for each endpoint with the configured per-BN timeout.
    pub fn new(config: BnManagerConfig) -> Result<Self, BnManagerError> {
        if config.endpoints.is_empty() {
            return Err(BnManagerError::NoEndpoints);
        }

        let mut clients = Vec::with_capacity(config.endpoints.len());

        for endpoint in &config.endpoints {
            let parsed = Url::parse(endpoint).map_err(|e| {
                BnManagerError::InvalidEndpoint(format!("failed to parse URL: {e}"))
            })?;

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

            let client_config = beacon::BeaconClientConfig::new(endpoint.clone())
                .with_timeout(config.timeout)
                .with_max_retries(0);
            let client = BeaconClient::new(client_config)?;
            clients.push(client);
        }

        Ok(Self { clients })
    }

    /// Returns the endpoint URL of the first (primary) client.
    #[cfg(test)]
    fn primary_endpoint(&self) -> &str {
        self.clients[0].endpoint()
    }

    /// Starts SSE event subscription on the primary beacon node.
    ///
    /// The returned `JoinHandle` runs the SSE loop in a background task.
    /// Send `true` on `shutdown` to stop the subscription.
    pub fn start_sse<F>(
        &self,
        callback: F,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn(SseEvent) + Send + Sync + 'static,
    {
        let config = SseConfig::new(self.clients[0].endpoint().to_string());
        tokio::spawn(async move {
            sse::subscribe_events(config, callback, shutdown).await;
        })
    }

    /// Query using the `First` strategy: try BNs in order, fail over on error.
    async fn query_first<'s, T, F>(&'s self, op_name: &str, op: F) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let mut last_err = None;

        for (i, client) in self.clients.iter().enumerate() {
            match op(client).await {
                Ok(result) => {
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = client.endpoint(),
                        "query succeeded"
                    );
                    return Ok(result);
                }
                Err(e) => {
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = client.endpoint(),
                        error = %e,
                        "BN query failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.expect("at least one client exists"))
    }

    /// Query using the `Best` strategy: query all BNs in parallel, pick best result.
    ///
    /// The `pick_best` function returns `true` if the first argument is better than the second.
    /// Falls back to `First` strategy if only one BN is configured.
    async fn query_best<'s, T, F>(
        &'s self,
        op_name: &str,
        op: F,
        pick_best: fn(&T, &T) -> bool,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        if self.clients.len() == 1 {
            return self.query_first(op_name, op).await;
        }

        let mut futs: Vec<IndexedResultFut<'_, T>> = Vec::with_capacity(self.clients.len());

        for (i, client) in self.clients.iter().enumerate() {
            let endpoint = client.endpoint().to_string();
            let fut = op(client);
            futs.push(Box::pin(async move {
                let result = fut.await;
                (i, endpoint, result)
            }));
        }

        let results = join_all(futs).await;

        let mut best: Option<(usize, T)> = None;

        for (i, endpoint, result) in results {
            match result {
                Ok(value) => {
                    best = Some(match best {
                        None => (i, value),
                        Some((prev_i, prev_value)) => {
                            if pick_best(&value, &prev_value) {
                                (i, value)
                            } else {
                                (prev_i, prev_value)
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = endpoint,
                        error = %e,
                        "BN query failed in best-selection"
                    );
                }
            }
        }

        match best {
            Some((i, value)) => {
                debug!(
                    op = op_name,
                    bn_index = i,
                    endpoint = self.clients[i].endpoint(),
                    "best-selection picked BN"
                );
                Ok(value)
            }
            None => {
                Err(BeaconError::HttpError(format!("{op_name}: all BNs failed in best-selection")))
            }
        }
    }

    /// Broadcast an operation to all BNs. Returns first success.
    /// If all fail, returns the last error.
    async fn broadcast<'s, F>(&'s self, op_name: &str, op: F) -> Result<(), BeaconError>
    where
        F: Fn(&'s BeaconClient) -> BoxFut<'s, ()>,
    {
        let mut futs: Vec<IndexedResultFut<'_, ()>> = Vec::with_capacity(self.clients.len());

        for (i, client) in self.clients.iter().enumerate() {
            let endpoint = client.endpoint().to_string();
            let fut = op(client);
            futs.push(Box::pin(async move {
                let result = fut.await;
                (i, endpoint, result)
            }));
        }

        let results = join_all(futs).await;

        let mut last_err = None;
        for (i, endpoint, result) in results {
            match result {
                Ok(()) => {
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = endpoint,
                        "broadcast succeeded on BN"
                    );
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = endpoint,
                        error = %e,
                        "broadcast failed on BN"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.expect("at least one client exists"))
    }

    /// Broadcast an operation that returns a non-unit result.
    /// Returns first success. If all fail, returns the last error.
    async fn broadcast_with_result<'s, T, F>(
        &'s self,
        op_name: &str,
        op: F,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let mut futs: Vec<IndexedResultFut<'_, T>> = Vec::with_capacity(self.clients.len());

        for (i, client) in self.clients.iter().enumerate() {
            let endpoint = client.endpoint().to_string();
            let fut = op(client);
            futs.push(Box::pin(async move {
                let result = fut.await;
                (i, endpoint, result)
            }));
        }

        let results = join_all(futs).await;

        let mut last_err = None;
        for (i, endpoint, result) in results {
            match result {
                Ok(v) => {
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = endpoint,
                        "broadcast succeeded on BN"
                    );
                    return Ok(v);
                }
                Err(e) => {
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = endpoint,
                        error = %e,
                        "broadcast failed on BN"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.expect("at least one client exists"))
    }
}

/// Compares two `ProduceBlockResponse` values by execution payload value.
/// Returns `true` if `a` is better than `b`.
fn is_better_block(a: &ProduceBlockResponse, b: &ProduceBlockResponse) -> bool {
    let val_a =
        a.execution_payload_value.as_deref().and_then(|v| v.parse::<u128>().ok()).unwrap_or(0);
    let val_b =
        b.execution_payload_value.as_deref().and_then(|v| v.parse::<u128>().ok()).unwrap_or(0);
    val_a > val_b
}

#[async_trait]
impl BeaconNodeClient for BnManager {
    // -- State / Config: query(First) --

    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        self.query_first("get_genesis", |c| Box::pin(c.get_genesis())).await
    }

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.query_first("get_config_spec", |c| Box::pin(c.get_config_spec())).await
    }

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        self.query_first("get_fork_schedule", |c| Box::pin(c.get_fork_schedule())).await
    }

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        self.query_first("get_fork", |c| Box::pin(c.get_fork(state_id))).await
    }

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        self.query_first("get_validators", |c| Box::pin(c.get_validators(pubkeys))).await
    }

    // -- Duties: query(First) --

    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        self.query_first("get_attester_duties", |c| {
            Box::pin(c.get_attester_duties(epoch, validator_indices))
        })
        .await
    }

    async fn get_proposer_duties(&self, epoch: u64) -> Result<ProposerDutiesResponse, BeaconError> {
        self.query_first("get_proposer_duties", |c| Box::pin(c.get_proposer_duties(epoch))).await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.query_first("post_sync_committee_duties", |c| {
            Box::pin(c.post_sync_committee_duties(epoch, validator_indices))
        })
        .await
    }

    // -- Block production: query(Best) --

    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.query_best(
            "produce_block_v3",
            |c| Box::pin(c.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor)),
            is_better_block,
        )
        .await
    }

    // -- Submissions: broadcast --

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.broadcast("publish_block", |c| {
            Box::pin(c.publish_block(signed_block, consensus_version))
        })
        .await
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.broadcast("publish_blinded_block", |c| {
            Box::pin(c.publish_blinded_block(signed_blinded_block, consensus_version))
        })
        .await
    }

    // -- Attestation data: query(First) --

    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.query_first("get_attestation_data", |c| {
            Box::pin(c.get_attestation_data(slot, committee_index))
        })
        .await
    }

    // -- Attestation submission: broadcast --

    async fn submit_attestation(
        &self,
        attestations: &[Attestation],
    ) -> Result<SubmitAttestationResult, BeaconError> {
        self.broadcast_with_result("submit_attestation", |c| {
            Box::pin(c.submit_attestation(attestations))
        })
        .await
    }

    // -- Aggregation: query(First) for fetching, broadcast for submitting --

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
    ) -> Result<AggregateAttestationResponse, BeaconError> {
        self.query_first("get_aggregate_attestation", |c| {
            Box::pin(c.get_aggregate_attestation(slot, attestation_data_root))
        })
        .await
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &[SignedAggregateAndProof],
    ) -> Result<(), BeaconError> {
        self.broadcast("submit_aggregate_and_proofs", |c| {
            Box::pin(c.submit_aggregate_and_proofs(proofs))
        })
        .await
    }

    // -- Sync committee: broadcast for submissions, query(First) for fetching --

    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.broadcast("submit_sync_committee_messages", |c| {
            Box::pin(c.submit_sync_committee_messages(messages))
        })
        .await
    }

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.query_first("get_sync_committee_contribution", |c| {
            Box::pin(c.get_sync_committee_contribution(slot, subcommittee_index, beacon_block_root))
        })
        .await
    }

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.broadcast("submit_contribution_and_proofs", |c| {
            Box::pin(c.submit_contribution_and_proofs(proofs))
        })
        .await
    }

    // -- Blocks --

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        self.query_first("get_block_root", |c| Box::pin(c.get_block_root(block_id))).await
    }

    // -- Proposer preparation: broadcast --

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.broadcast("prepare_beacon_proposer", |c| {
            Box::pin(c.prepare_beacon_proposer(preparations))
        })
        .await
    }

    // -- Committee subscriptions: broadcast --

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.broadcast("submit_beacon_committee_subscriptions", |c| {
            Box::pin(c.submit_beacon_committee_subscriptions(subscriptions))
        })
        .await
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
        assert_eq!(manager.primary_endpoint(), "http://first:5052");
    }

    #[test]
    fn test_new_respects_timeout() {
        let mut config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        config.timeout = Duration::from_secs(10);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.clients[0].timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_new_with_trailing_slash() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052/".to_string()]);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.primary_endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_new_creates_multiple_clients() {
        let config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
            "http://bn3:5052".to_string(),
        ]);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.clients.len(), 3);
        assert_eq!(manager.clients[0].endpoint(), "http://bn1:5052");
        assert_eq!(manager.clients[1].endpoint(), "http://bn2:5052");
        assert_eq!(manager.clients[2].endpoint(), "http://bn3:5052");
    }

    #[test]
    fn test_new_validates_all_endpoints() {
        let config = BnManagerConfig::new(vec![
            "http://good:5052".to_string(),
            "ftp://bad:5052".to_string(),
        ]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_all_clients_use_same_timeout() {
        let mut config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
        ]);
        config.timeout = Duration::from_secs(15);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.clients[0].timeout(), Duration::from_secs(15));
        assert_eq!(manager.clients[1].timeout(), Duration::from_secs(15));
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

    fn make_multi_manager(endpoints: &[&str]) -> BnManager {
        let config = BnManagerConfig::new(endpoints.iter().map(|e| e.to_string()).collect());
        BnManager::new(config).unwrap()
    }

    const GENESIS_RESPONSE: &str = r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}"#;

    // -- Single-BN delegation tests --

    #[tokio::test]
    async fn test_get_genesis_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
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
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
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

    // ===================================================================
    // Multi-BN tests
    // ===================================================================

    // -- First strategy: failover --

    #[tokio::test]
    async fn test_multi_query_first_uses_primary() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&primary)
            .await;

        // Secondary should NOT be called
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(0)
            .mount(&secondary)
            .await;

        let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
        let result = manager.get_genesis().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data.genesis_time, "1606824023");
    }

    #[tokio::test]
    async fn test_multi_query_first_failover_on_error() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        // Primary returns error
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&primary)
            .await;

        // Secondary returns success
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&secondary)
            .await;

        let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
        let result = manager.get_genesis().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data.genesis_time, "1606824023");
    }

    #[tokio::test]
    async fn test_multi_query_first_all_fail() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&primary)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Unavailable"))
            .expect(1)
            .mount(&secondary)
            .await;

        let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
        let result = manager.get_genesis().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multi_query_first_failover_three_bns() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        let bn3 = MockServer::start().await;

        // First two fail
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn2)
            .await;

        // Third succeeds
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&bn3)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri(), &bn3.uri()]);
        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multi_duties_use_first_strategy() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        // Primary fails
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/1"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&primary)
            .await;

        // Secondary succeeds
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"dependent_root":"0xabc","execution_optimistic":false,"data":[]}"#,
            ))
            .expect(1)
            .mount(&secondary)
            .await;

        let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
        let result = manager.get_proposer_duties(1).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multi_attestation_data_uses_first_strategy() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        // Primary fails
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&primary)
            .await;

        // Secondary succeeds
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(query_param("slot", "100"))
            .and(query_param("committee_index", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"slot":"100","index":"0","beacon_block_root":"0xabc","source":{"epoch":"3","root":"0x01"},"target":{"epoch":"4","root":"0x02"}}}"#,
            ))
            .expect(1)
            .mount(&secondary)
            .await;

        let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
        let result = manager.get_attestation_data(100, 0).await;
        assert!(result.is_ok());
    }

    // -- Best strategy: block production --

    #[tokio::test]
    async fn test_multi_best_picks_higher_value_block() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // BN1 returns block with lower value
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "1000")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .expect(1)
            .mount(&bn1)
            .await;

        // BN2 returns block with higher value
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "5000")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
        assert!(result.is_ok());
        let block = result.unwrap();
        assert_eq!(block.execution_payload_value, Some("5000".to_string()));
    }

    #[tokio::test]
    async fn test_multi_best_picks_only_successful_response() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // BN1 fails
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        // BN2 succeeds
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "3000")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().execution_payload_value, Some("3000".to_string()));
    }

    #[tokio::test]
    async fn test_multi_best_all_fail() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Unavailable"))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multi_best_single_bn_falls_back_to_first() {
        let bn = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "2000")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .expect(1)
            .mount(&bn)
            .await;

        let manager = make_manager(&bn.uri());
        let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
        assert!(result.is_ok());
    }

    // -- Broadcast: submissions --

    #[tokio::test]
    async fn test_multi_broadcast_sends_to_all_bns() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.prepare_beacon_proposer(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multi_broadcast_succeeds_if_one_bn_ok() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // BN1 fails
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        // BN2 succeeds
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.prepare_beacon_proposer(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multi_broadcast_fails_if_all_fail() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Unavailable"))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.prepare_beacon_proposer(&[]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multi_broadcast_sync_messages() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.submit_sync_committee_messages(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multi_broadcast_aggregate_proofs() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.submit_aggregate_and_proofs(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multi_broadcast_committee_subscriptions() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.submit_beacon_committee_subscriptions(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multi_broadcast_contribution_proofs() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/contribution_and_proofs"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/contribution_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let result = manager.submit_contribution_and_proofs(&[]).await;
        assert!(result.is_ok());
    }

    // -- is_better_block unit tests --

    #[test]
    fn test_is_better_block_higher_value() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("5000".to_string()),
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
        };
        assert!(is_better_block(&a, &b));
        assert!(!is_better_block(&b, &a));
    }

    #[test]
    fn test_is_better_block_none_vs_some() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
        };
        assert!(!is_better_block(&a, &b));
        assert!(is_better_block(&b, &a));
    }

    #[test]
    fn test_is_better_block_both_none() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
        };
        assert!(!is_better_block(&a, &b));
    }

    #[test]
    fn test_is_better_block_equal_values() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
        };
        assert!(!is_better_block(&a, &b));
    }
}
