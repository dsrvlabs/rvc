use std::time::Duration;

use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, warn, Instrument};
use url::Url;

/// Redact credentials from a URL for safe inclusion in span attributes.
///
/// Replaces username and password with `***` if present, leaving the rest
/// of the URL intact. Returns the original string if parsing fails.
fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        if parsed.password().is_some() || !parsed.username().is_empty() {
            let _ = parsed.set_username("***");
            let _ = parsed.set_password(Some("***"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

use eth_types::{ForkSchedule, SignedValidatorRegistration, SignedVoluntaryExit};

use crate::types::{
    parse_fork_schedule, AggregateAttestationResponse, AttestationDataResponse,
    AttesterDutiesResponse, BeaconCommitteeSubscription, BlockRootResponse, ConfigSpecResponse,
    GenesisResponse, IndexedAttestationError, ProduceBlockResponse, ProposerDutiesResponse,
    ProposerPreparation, SignedContributionAndProof, StateForkResponse, SubmitAttestationResult,
    SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse, SyncCommitteeMessage,
    SyncingResponse, ValidatorLivenessResponse, ValidatorsResponse, VersionedAttestation,
    VersionedSignedAggregateAndProof,
};
use crate::BeaconError;

#[derive(Debug, Deserialize)]
struct AttestationSubmissionError {
    #[serde(default)]
    failures: Vec<IndexedAttestationError>,
}

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_INITIAL_BACKOFF_MS: u64 = 100;

/// Configuration for the beacon node HTTP client.
#[derive(Debug, Clone)]
pub struct BeaconClientConfig {
    pub endpoint: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub initial_backoff: Duration,
}

impl BeaconClientConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff: Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MS),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }
}

/// Async HTTP client wrapper for beacon node communication.
#[derive(Clone)]
pub struct BeaconClient {
    client: Client,
    config: BeaconClientConfig,
}

impl BeaconClient {
    /// Creates a new BeaconClient with the given configuration.
    pub fn new(config: BeaconClientConfig) -> Result<Self, BeaconError> {
        let endpoint = config.endpoint.trim_end_matches('/');
        if endpoint.is_empty() {
            return Err(BeaconError::InvalidUrl("endpoint URL cannot be empty".to_string()));
        }

        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            return Err(BeaconError::InvalidUrl(format!(
                "endpoint must start with http:// or https://: {}",
                endpoint
            )));
        }

        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| BeaconError::HttpError(e.to_string()))?;

        let config = BeaconClientConfig { endpoint: endpoint.to_string(), ..config };

        Ok(Self { client, config })
    }

    /// Returns the configured endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Returns the configured timeout.
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Performs a GET request with retry logic.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, BeaconError> {
        let url = format!("{}{}", self.config.endpoint, path);
        let mut trace_headers = reqwest::header::HeaderMap::new();
        telemetry::inject_trace_context(&mut trace_headers);
        let hdrs = trace_headers.clone();
        self.execute_with_retry("GET", &url, || async {
            let mut req = self.client.get(&url);
            for (name, value) in &hdrs {
                req = req.header(name.clone(), value.clone());
            }
            req.send().await
        })
        .await
    }

    /// Performs a POST request with retry logic.
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, BeaconError> {
        let url = format!("{}{}", self.config.endpoint, path);
        let mut trace_headers = reqwest::header::HeaderMap::new();
        telemetry::inject_trace_context(&mut trace_headers);
        let hdrs = trace_headers.clone();
        self.execute_with_retry("POST", &url, || async {
            let mut req = self.client.post(&url).json(body);
            for (name, value) in &hdrs {
                req = req.header(name.clone(), value.clone());
            }
            req.send().await
        })
        .await
    }

    /// Performs a POST request expecting an empty success response.
    pub async fn post_empty<B: Serialize>(&self, path: &str, body: &B) -> Result<(), BeaconError> {
        self.post_empty_with_headers(path, body, &[]).await
    }

    /// Fetches attester duties for the given epoch and validator indices.
    ///
    /// Returns duties with a dependent root that can be used for cache invalidation.
    /// If the dependent root changes, cached duties should be invalidated.
    pub async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        let path = format!("/eth/v1/validator/duties/attester/{}", epoch);
        self.post(&path, &validator_indices)
            .instrument(tracing::info_span!("rvc.beacon.get_attester_duties", epoch = epoch))
            .await
    }

    /// Resolves public keys to validator data including numeric indices.
    ///
    /// Calls the beacon state validators endpoint with the given public keys
    /// to retrieve their validator indices, status, and other metadata.
    pub async fn get_validators(
        &self,
        pubkeys: &[String],
    ) -> Result<ValidatorsResponse, BeaconError> {
        let ids: String =
            pubkeys.iter().map(|pk| format!("id={}", pk)).collect::<Vec<_>>().join("&");
        let path = format!("/eth/v1/beacon/states/head/validators?{}", ids);
        self.get(&path).instrument(tracing::info_span!("rvc.beacon.get_validators")).await
    }

    /// Fetches attestation data for the given slot and committee index.
    ///
    /// The beacon node will return attestation data that validators can use
    /// to create their attestations for the specified slot and committee.
    ///
    /// Returns an error if the slot is in the past or too far in the future,
    /// or if the beacon node is still syncing.
    pub async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        let path = format!(
            "/eth/v1/validator/attestation_data?slot={}&committee_index={}",
            slot, committee_index
        );
        self.get(&path)
            .instrument(tracing::info_span!("rvc.beacon.get_attestation_data", slot = slot))
            .await
    }

    /// Fetches the chain configuration specification from the beacon node.
    ///
    /// Returns a map of all configuration parameters as string key-value pairs.
    /// Includes fork versions, fork epochs, slot timing, and other consensus parameters.
    #[tracing::instrument(name = "rvc.beacon.get_config_spec", skip_all)]
    pub async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.get("/eth/v1/config/spec").await
    }

    /// Fetches the config spec and parses fork epoch and version fields into a `ForkSchedule`.
    #[tracing::instrument(name = "rvc.beacon.get_fork_schedule", skip_all)]
    pub async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        let spec = self.get_config_spec().await?;
        parse_fork_schedule(&spec.data)
    }

    /// Fetches genesis information from the beacon node.
    ///
    /// Returns the genesis time, genesis validators root, and genesis fork version.
    #[tracing::instrument(name = "rvc.beacon.get_genesis", skip_all)]
    pub async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        self.get("/eth/v1/beacon/genesis").await
    }

    /// Fetches fork information for the given state.
    ///
    /// Returns the previous and current fork versions along with the fork epoch.
    /// Common state_id values: "head", "finalized", "justified", or a specific slot number.
    #[tracing::instrument(name = "rvc.beacon.get_fork", skip_all)]
    pub async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        let path = format!("/eth/v1/beacon/states/{}/fork", state_id);
        self.get(&path).await
    }

    /// Fetches the block root for the given block identifier.
    ///
    /// Common block_id values: "head", "finalized", "justified", or a slot number.
    #[tracing::instrument(name = "rvc.beacon.get_block_root", skip_all)]
    pub async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        let path = format!("/eth/v1/beacon/blocks/{}/root", block_id);
        self.get(&path).await
    }

    /// Fetches proposer duties for the given epoch.
    pub async fn get_proposer_duties(
        &self,
        epoch: u64,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        let path = format!("/eth/v1/validator/duties/proposer/{}", epoch);
        self.get(&path)
            .instrument(tracing::info_span!("rvc.beacon.get_proposer_duties", epoch = epoch))
            .await
    }

    /// SSZ content negotiation Accept header for block production.
    /// Prefers SSZ for ~67% bandwidth savings with JSON as fallback.
    /// The full SSZ pipeline (header extraction, block-service SSZ path,
    /// JSON fallback on failure) is in place.
    const SSZ_ACCEPT_HEADER: &'static str = "application/octet-stream;q=1.0,application/json;q=0.9";

    /// Produces a block for the given slot using the v3 endpoint.
    ///
    /// Requests SSZ-encoded response for reduced network latency on large blocks.
    /// Falls back to JSON if the BN does not support SSZ or responds with JSON
    /// despite the SSZ preference.
    pub async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        let mut query = format!("randao_reveal={}", randao_reveal);
        if let Some(g) = graffiti {
            query.push_str(&format!("&graffiti={}", g));
        }
        if let Some(factor) = builder_boost_factor {
            query.push_str(&format!("&builder_boost_factor={}", factor));
        }
        let url = format!("{}/eth/v3/validator/blocks/{}?{}", self.config.endpoint, slot, query);

        let mut trace_headers = reqwest::header::HeaderMap::new();
        telemetry::inject_trace_context(&mut trace_headers);
        let hdrs = trace_headers.clone();

        let response = self
            .execute_with_retry_raw("GET", &url, || async {
                let mut req =
                    self.client.get(&url).header(reqwest::header::ACCEPT, Self::SSZ_ACCEPT_HEADER);
                for (name, value) in &hdrs {
                    req = req.header(name.clone(), value.clone());
                }
                req.send().await
            })
            .await?;

        let is_blinded = response
            .headers()
            .get("Eth-Execution-Payload-Blinded")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false);

        let consensus_version = response
            .headers()
            .get("Eth-Consensus-Version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let execution_payload_value = response
            .headers()
            .get("Eth-Execution-Payload-Value")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        if content_type.starts_with("application/octet-stream") {
            match Self::try_process_ssz_body(
                response,
                slot,
                is_blinded,
                &consensus_version,
                &execution_payload_value,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(ssz_err) => {
                    warn!(
                        slot = slot,
                        error = %ssz_err,
                        "SSZ block response processing failed, retrying with JSON"
                    );
                    // Single fallback retry with explicit JSON Accept
                    let hdrs2 = trace_headers.clone();
                    let fallback_response = self
                        .execute_with_retry_raw("GET", &url, || async {
                            let mut req = self
                                .client
                                .get(&url)
                                .header(reqwest::header::ACCEPT, "application/json");
                            for (name, value) in &hdrs2 {
                                req = req.header(name.clone(), value.clone());
                            }
                            req.send().await
                        })
                        .await?;
                    return Self::parse_produce_block_json(fallback_response).await;
                }
            }
        }

        Self::parse_produce_block_json(response).await
    }

    /// Attempt to read and validate the SSZ body from an HTTP response.
    async fn try_process_ssz_body(
        response: reqwest::Response,
        slot: u64,
        is_blinded: bool,
        consensus_version: &str,
        execution_payload_value: &Option<String>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        const MAX_SSZ_BLOCK_BYTES: usize = 16 * 1024 * 1024;

        let ssz_bytes = response
            .bytes()
            .await
            .map_err(|e| BeaconError::ParseError(format!("failed to read SSZ bytes: {e}")))?;

        if ssz_bytes.is_empty() {
            return Err(BeaconError::ParseError("received empty SSZ body from beacon node".into()));
        }

        if ssz_bytes.len() > MAX_SSZ_BLOCK_BYTES {
            return Err(BeaconError::ParseError(format!(
                "SSZ response too large: {} bytes (max {})",
                ssz_bytes.len(),
                MAX_SSZ_BLOCK_BYTES
            )));
        }

        let ssz_bytes = ssz_bytes.to_vec();

        debug!(
            slot = slot,
            consensus_version = consensus_version,
            ssz_bytes = ssz_bytes.len(),
            "received SSZ block response"
        );

        Ok(ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded,
            consensus_version: consensus_version.to_string(),
            execution_payload_value: execution_payload_value.clone(),
            is_ssz: true,
            ssz_bytes: Some(ssz_bytes),
        })
    }

    /// Parse a JSON produce-block response (headers + body).
    async fn parse_produce_block_json(
        response: reqwest::Response,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        let is_blinded = response
            .headers()
            .get("Eth-Execution-Payload-Blinded")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false);

        let consensus_version = response
            .headers()
            .get("Eth-Consensus-Version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let execution_payload_value = response
            .headers()
            .get("Eth-Execution-Payload-Value")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        let body: serde_json::Value =
            response.json().await.map_err(|e| BeaconError::ParseError(e.to_string()))?;

        let data = body.get("data").cloned().ok_or_else(|| {
            BeaconError::ParseError("missing 'data' field in produce block response".into())
        })?;

        Ok(ProduceBlockResponse {
            data,
            is_blinded,
            consensus_version,
            execution_payload_value,
            is_ssz: false,
            ssz_bytes: None,
        })
    }

    /// Publishes a signed beacon block to the network.
    pub async fn publish_block<B: Serialize>(
        &self,
        signed_block: &B,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.post_empty_with_headers(
            "/eth/v2/beacon/blocks",
            signed_block,
            &[("Eth-Consensus-Version", consensus_version)],
        )
        .instrument(tracing::info_span!("rvc.beacon.publish_block"))
        .await
    }

    /// Publishes a signed blinded beacon block to the network.
    pub async fn publish_blinded_block<B: Serialize>(
        &self,
        signed_blinded_block: &B,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.post_empty_with_headers(
            "/eth/v1/beacon/blinded_blocks",
            signed_blinded_block,
            &[("Eth-Consensus-Version", consensus_version)],
        )
        .instrument(tracing::info_span!("rvc.beacon.publish_blinded_block"))
        .await
    }

    /// Publishes a block as raw SSZ bytes using `Content-Type: application/octet-stream`.
    ///
    /// Routes to the blinded or unblinded endpoint based on `is_blinded`.
    pub async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BeaconError> {
        let path =
            if is_blinded { "/eth/v1/beacon/blinded_blocks" } else { "/eth/v2/beacon/blocks" };
        let url = format!("{}{}", self.config.endpoint, path);

        let span = tracing::info_span!(
            "rvc.beacon.publish_block_ssz",
            http.method = "POST",
            http.url = %redact_url(&url),
            http.status_code = tracing::field::Empty,
        );

        let mut headers = reqwest::header::HeaderMap::new();
        telemetry::inject_trace_context(&mut headers);

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("Eth-Consensus-Version", consensus_version)
            .body(ssz_bytes.to_vec());
        for (name, value) in &headers {
            request = request.header(name.clone(), value.clone());
        }

        let response = request.send().await.map_err(|e| BeaconError::HttpError(e.to_string()))?;

        let status = response.status();
        span.record("http.status_code", status.as_u16());
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(BeaconError::ApiError { status: status.as_u16(), message: body })
        }
    }

    /// Fetches sync committee duties for the given epoch and validator indices.
    pub async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        let path = format!("/eth/v1/validator/duties/sync/{}", epoch);
        self.post(&path, &validator_indices)
            .instrument(tracing::info_span!("rvc.beacon.get_sync_committee_duties", epoch = epoch))
            .await
    }

    /// Submits sync committee messages to the beacon node pool.
    pub async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/beacon/pool/sync_committees", &messages)
            .instrument(tracing::info_span!("rvc.beacon.submit_sync_committee_messages"))
            .await
    }

    /// Fetches a sync committee contribution for the given slot, subcommittee index, and block root.
    #[tracing::instrument(name = "rvc.beacon.get_sync_committee_contribution", skip_all, fields(rvc.slot = slot))]
    pub async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        let path = format!(
            "/eth/v1/validator/sync_committee_contribution?slot={}&subcommittee_index={}&beacon_block_root={}",
            slot, subcommittee_index, beacon_block_root
        );
        self.get(&path).await
    }

    /// Submits signed contribution and proofs to the beacon node.
    pub async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/contribution_and_proofs", &proofs)
            .instrument(tracing::info_span!("rvc.beacon.submit_contribution_and_proofs"))
            .await
    }

    // Aggregation

    /// Fetches an aggregate attestation for the given slot and attestation data root.
    ///
    /// The `committee_index` parameter is required for Electra and later forks.
    /// Pass `None` for pre-Electra requests.
    #[tracing::instrument(name = "rvc.beacon.get_aggregate_attestation", skip_all, fields(rvc.slot = slot))]
    pub async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<AggregateAttestationResponse, BeaconError> {
        let mut path = format!(
            "/eth/v1/validator/aggregate_attestation?slot={}&attestation_data_root={}",
            slot, attestation_data_root
        );
        if let Some(ci) = committee_index {
            path.push_str(&format!("&committee_index={}", ci));
        }
        self.get(&path).await
    }

    /// Submits signed aggregate and proofs to the beacon node.
    pub async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError> {
        let span = tracing::info_span!("rvc.beacon.submit_aggregate_and_proofs");
        match proofs {
            VersionedSignedAggregateAndProof::PreElectra(ps) => {
                self.post_empty("/eth/v1/validator/aggregate_and_proofs", ps).instrument(span).await
            }
            VersionedSignedAggregateAndProof::Electra(ps)
            | VersionedSignedAggregateAndProof::Fulu(ps) => {
                self.post_empty("/eth/v2/validator/aggregate_and_proofs", ps).instrument(span).await
            }
        }
    }

    /// Sends proposer preparation data to the beacon node.
    ///
    /// Informs the beacon node of each validator's fee recipient address
    /// so that the execution layer can direct transaction fees appropriately.
    pub async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/prepare_beacon_proposer", &preparations)
            .instrument(tracing::info_span!("rvc.beacon.prepare_beacon_proposer"))
            .await
    }

    /// Posts validator indices to check liveness for the given epoch.
    ///
    /// Returns liveness data indicating whether each validator was active
    /// during the specified epoch. Used for doppelganger detection.
    #[tracing::instrument(name = "rvc.beacon.post_validator_liveness", skip_all, fields(rvc.epoch = epoch))]
    pub async fn post_validator_liveness(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        let path = format!("/eth/v1/validator/liveness/{}", epoch);
        self.post(&path, &validator_indices).await
    }

    /// Submits a signed voluntary exit to the beacon node pool.
    ///
    /// Once submitted, the exit is irreversible. The beacon node will propagate
    /// the exit through the network and the validator will be exited from the
    /// active validator set after the exit epoch.
    pub async fn submit_voluntary_exit(
        &self,
        signed_exit: &SignedVoluntaryExit,
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/beacon/pool/voluntary_exits", signed_exit)
            .instrument(tracing::info_span!("rvc.beacon.submit_voluntary_exit"))
            .await
    }

    /// Subscribes validators to beacon committees for attestation subnet management.
    ///
    /// The beacon node uses these subscriptions to join the appropriate
    /// attestation subnets and prepare for aggregation duties.
    pub async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/beacon_committee_subscriptions", &subscriptions)
            .instrument(tracing::info_span!("rvc.beacon.submit_beacon_committee_subscriptions"))
            .await
    }

    // Builder

    pub async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/register_validator", &registrations)
            .instrument(tracing::info_span!("rvc.beacon.register_validators"))
            .await
    }

    /// Fetches the sync status of the beacon node.
    ///
    /// Returns whether the node is syncing, its head slot, sync distance,
    /// and whether the execution layer is offline.
    #[tracing::instrument(name = "rvc.beacon.get_node_syncing", skip_all)]
    pub async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.get("/eth/v1/node/syncing").await
    }

    /// Fetches the node version string from the beacon node.
    #[tracing::instrument(name = "rvc.beacon.get_node_version", skip_all)]
    pub async fn get_node_version(&self) -> Result<String, BeaconError> {
        let response: crate::types::NodeVersionResponse = self.get("/eth/v1/node/version").await?;
        Ok(response.data.version)
    }

    /// Submits signed attestations to the beacon node.
    ///
    /// Accepts a versioned attestation payload and submits to the beacon pool.
    /// Returns success if all attestations were accepted, or partial failure
    /// with details about which attestations failed validation.
    ///
    /// Server errors (5xx) will trigger retry logic with exponential backoff.
    pub async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        let url = format!("{}/eth/v2/beacon/pool/attestations", self.config.endpoint);

        let span = tracing::info_span!(
            "rvc.beacon.submit_attestations",
            http.method = "POST",
            http.url = %redact_url(&url),
            http.status_code = tracing::field::Empty,
        );
        let mut trace_headers = reqwest::header::HeaderMap::new();
        telemetry::inject_trace_context(&mut trace_headers);

        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                let backoff = self.calculate_backoff(attempt - 1);
                debug!(attempt = attempt, backoff_ms = ?backoff.as_millis(), "Retrying request");
                tokio::time::sleep(backoff).await;
            }

            let (consensus_version, attestation_count) = match attestations {
                VersionedAttestation::PreElectra(atts) => ("phase0", atts.len()),
                VersionedAttestation::Electra(atts) => ("electra", atts.len()),
                VersionedAttestation::Fulu(atts) => ("fulu", atts.len()),
            };

            debug!(
                consensus_version = consensus_version,
                attestation_count = attestation_count,
                "Submitting attestations to beacon node"
            );

            let send_result = match attestations {
                VersionedAttestation::PreElectra(atts) => {
                    let mut req = self
                        .client
                        .post(&url)
                        .header("Eth-Consensus-Version", consensus_version)
                        .json(atts);
                    for (name, value) in &trace_headers {
                        req = req.header(name.clone(), value.clone());
                    }
                    req.send().await
                }
                VersionedAttestation::Electra(atts) | VersionedAttestation::Fulu(atts) => {
                    let mut req = self
                        .client
                        .post(&url)
                        .header("Eth-Consensus-Version", consensus_version)
                        .json(atts);
                    for (name, value) in &trace_headers {
                        req = req.header(name.clone(), value.clone());
                    }
                    req.send().await
                }
            };
            match send_result {
                Ok(response) => {
                    let status = response.status();
                    span.record("http.status_code", status.as_u16());

                    if status.is_success() {
                        return Ok(SubmitAttestationResult::Success);
                    }

                    if status.as_u16() == 400 {
                        let body = response.text().await.unwrap_or_default();
                        warn!(
                            response_body = %body,
                            "Attestation submission returned 400"
                        );
                        if let Ok(error_response) =
                            serde_json::from_str::<AttestationSubmissionError>(&body)
                        {
                            if error_response.failures.is_empty() {
                                return Err(BeaconError::ApiError { status: 400, message: body });
                            }
                            return Ok(SubmitAttestationResult::PartialFailure {
                                failures: error_response.failures,
                            });
                        }
                        return Err(BeaconError::ApiError { status: 400, message: body });
                    }

                    if status.is_client_error() {
                        let message = response.text().await.unwrap_or_default();
                        return Err(BeaconError::ApiError { status: status.as_u16(), message });
                    }

                    if status.is_server_error() {
                        let message = response.text().await.unwrap_or_default();
                        last_error =
                            Some(BeaconError::ApiError { status: status.as_u16(), message });
                        warn!(
                            attempt = attempt,
                            status = status.as_u16(),
                            "Server error, will retry"
                        );
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(BeaconError::ApiError { status: status.as_u16(), message });
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(BeaconError::Timeout);
                        warn!(attempt = attempt, "Request timeout, will retry");
                        continue;
                    }

                    if e.is_connect() || e.is_request() {
                        last_error = Some(BeaconError::HttpError(e.to_string()));
                        warn!(attempt = attempt, error = %e, "Connection error, will retry");
                        continue;
                    }

                    return Err(BeaconError::HttpError(e.to_string()));
                }
            }
        }

        let err = last_error.unwrap_or_else(|| BeaconError::HttpError("Unknown error".to_string()));
        span.in_scope(|| tracing::error!(error = %err, "Request failed after retries exhausted"));
        Err(err)
    }

    async fn execute_with_retry<F, Fut, T>(
        &self,
        http_method: &str,
        url: &str,
        request_fn: F,
    ) -> Result<T, BeaconError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
        T: DeserializeOwned,
    {
        let span = tracing::info_span!(
            "rvc.beacon.http",
            http.method = %http_method,
            http.url = %redact_url(url),
            http.status_code = tracing::field::Empty,
        );
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                let backoff = self.calculate_backoff(attempt - 1);
                debug!(attempt = attempt, backoff_ms = ?backoff.as_millis(), "Retrying request");
                tokio::time::sleep(backoff).await;
            }

            match request_fn().await {
                Ok(response) => {
                    let status = response.status();
                    span.record("http.status_code", status.as_u16());

                    if status.is_success() {
                        let body = response.text().await.map_err(|e| {
                            BeaconError::ParseError(format!("failed to read response body: {e}"))
                        })?;
                        return serde_json::from_str::<T>(&body).map_err(|e| {
                            let preview = body.get(..1024).unwrap_or(&body);
                            warn!(
                                error = %e,
                                body_preview = preview,
                                "Failed to parse beacon API response"
                            );
                            BeaconError::ParseError(format!("error decoding response body: {e}"))
                        });
                    }

                    if status.is_client_error() {
                        let message = response.text().await.unwrap_or_default();
                        return Err(BeaconError::ApiError { status: status.as_u16(), message });
                    }

                    if status.is_server_error() {
                        let message = response.text().await.unwrap_or_default();
                        last_error =
                            Some(BeaconError::ApiError { status: status.as_u16(), message });
                        warn!(
                            attempt = attempt,
                            status = status.as_u16(),
                            "Server error, will retry"
                        );
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(BeaconError::ApiError { status: status.as_u16(), message });
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(BeaconError::Timeout);
                        warn!(attempt = attempt, "Request timeout, will retry");
                        continue;
                    }

                    if e.is_connect() || e.is_request() {
                        last_error = Some(BeaconError::HttpError(e.to_string()));
                        warn!(attempt = attempt, error = %e, "Connection error, will retry");
                        continue;
                    }

                    return Err(BeaconError::HttpError(e.to_string()));
                }
            }
        }

        let err = last_error.unwrap_or_else(|| BeaconError::HttpError("Unknown error".to_string()));
        span.in_scope(|| tracing::error!(error = %err, "Request failed after retries exhausted"));
        Err(err)
    }

    /// Performs a POST request with retry logic and optional headers, expecting an empty success response.
    async fn post_empty_with_headers<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        headers: &[(&str, &str)],
    ) -> Result<(), BeaconError> {
        let url = format!("{}{}", self.config.endpoint, path);

        let span = tracing::info_span!(
            "rvc.beacon.http",
            http.method = "POST",
            http.url = %redact_url(&url),
            http.status_code = tracing::field::Empty,
        );
        let mut trace_headers = reqwest::header::HeaderMap::new();
        telemetry::inject_trace_context(&mut trace_headers);

        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                let backoff = self.calculate_backoff(attempt - 1);
                debug!(attempt = attempt, backoff_ms = ?backoff.as_millis(), "Retrying request");
                tokio::time::sleep(backoff).await;
            }

            let mut request = self.client.post(&url).json(body);
            for &(name, value) in headers {
                request = request.header(name, value);
            }
            for (name, value) in &trace_headers {
                request = request.header(name.clone(), value.clone());
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    span.record("http.status_code", status.as_u16());

                    if status.is_success() {
                        return Ok(());
                    }

                    if status.is_client_error() {
                        let message = response.text().await.unwrap_or_default();
                        return Err(BeaconError::ApiError { status: status.as_u16(), message });
                    }

                    if status.is_server_error() {
                        let message = response.text().await.unwrap_or_default();
                        last_error =
                            Some(BeaconError::ApiError { status: status.as_u16(), message });
                        warn!(
                            attempt = attempt,
                            status = status.as_u16(),
                            "Server error, will retry"
                        );
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(BeaconError::ApiError { status: status.as_u16(), message });
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(BeaconError::Timeout);
                        warn!(attempt = attempt, "Request timeout, will retry");
                        continue;
                    }

                    if e.is_connect() || e.is_request() {
                        last_error = Some(BeaconError::HttpError(e.to_string()));
                        warn!(attempt = attempt, error = %e, "Connection error, will retry");
                        continue;
                    }

                    return Err(BeaconError::HttpError(e.to_string()));
                }
            }
        }

        let err = last_error.unwrap_or_else(|| BeaconError::HttpError("Unknown error".to_string()));
        span.in_scope(|| tracing::error!(error = %err, "Request failed after retries exhausted"));
        Err(err)
    }

    /// Executes a request with retry logic and returns the raw response on success.
    async fn execute_with_retry_raw<F, Fut>(
        &self,
        http_method: &str,
        url: &str,
        request_fn: F,
    ) -> Result<reqwest::Response, BeaconError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        let span = tracing::info_span!(
            "rvc.beacon.http",
            http.method = %http_method,
            http.url = %redact_url(url),
            http.status_code = tracing::field::Empty,
        );
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                let backoff = self.calculate_backoff(attempt - 1);
                debug!(attempt = attempt, backoff_ms = ?backoff.as_millis(), "Retrying request");
                tokio::time::sleep(backoff).await;
            }

            match request_fn().await {
                Ok(response) => {
                    let status = response.status();
                    span.record("http.status_code", status.as_u16());

                    if status.is_success() {
                        return Ok(response);
                    }

                    if status.is_client_error() {
                        let message = response.text().await.unwrap_or_default();
                        return Err(BeaconError::ApiError { status: status.as_u16(), message });
                    }

                    if status.is_server_error() {
                        let message = response.text().await.unwrap_or_default();
                        last_error =
                            Some(BeaconError::ApiError { status: status.as_u16(), message });
                        warn!(
                            attempt = attempt,
                            status = status.as_u16(),
                            "Server error, will retry"
                        );
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(BeaconError::ApiError { status: status.as_u16(), message });
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(BeaconError::Timeout);
                        warn!(attempt = attempt, "Request timeout, will retry");
                        continue;
                    }

                    if e.is_connect() || e.is_request() {
                        last_error = Some(BeaconError::HttpError(e.to_string()));
                        warn!(attempt = attempt, error = %e, "Connection error, will retry");
                        continue;
                    }

                    return Err(BeaconError::HttpError(e.to_string()));
                }
            }
        }

        let err = last_error.unwrap_or_else(|| BeaconError::HttpError("Unknown error".to_string()));
        span.in_scope(|| tracing::error!(error = %err, "Request failed after retries exhausted"));
        Err(err)
    }

    fn calculate_backoff(&self, attempt: u32) -> Duration {
        // Cap the exponent to prevent overflow. 2^20 is about 1 million,
        // which when multiplied by a 100ms initial backoff gives ~27 hours max.
        let capped_attempt = attempt.min(20);
        let multiplier = 2u32.saturating_pow(capped_attempt);
        self.config.initial_backoff.saturating_mul(multiplier)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        value: String,
    }

    #[test]
    fn test_config_default_values() {
        let config = BeaconClientConfig::new("http://localhost:5052");
        assert_eq!(config.endpoint, "http://localhost:5052");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_config_builder_pattern() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_timeout(Duration::from_secs(60))
            .with_max_retries(5)
            .with_initial_backoff(Duration::from_millis(200));

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff, Duration::from_millis(200));
    }

    #[test]
    fn test_client_creation_with_valid_url() {
        let config = BeaconClientConfig::new("http://localhost:5052");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_client_creation_strips_trailing_slash() {
        let config = BeaconClientConfig::new("http://localhost:5052/");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_client_creation_with_https() {
        let config = BeaconClientConfig::new("https://beacon.example.com");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "https://beacon.example.com");
    }

    #[test]
    fn test_client_creation_with_empty_url() {
        let config = BeaconClientConfig::new("");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_client_creation_with_invalid_scheme() {
        let config = BeaconClientConfig::new("ftp://localhost:5052");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_client_creation_without_scheme() {
        let config = BeaconClientConfig::new("localhost:5052");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_timeout_accessor() {
        let config =
            BeaconClientConfig::new("http://localhost:5052").with_timeout(Duration::from_secs(60));
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_calculate_backoff() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_initial_backoff(Duration::from_millis(100));
        let client = BeaconClient::new(config).unwrap();

        assert_eq!(client.calculate_backoff(0), Duration::from_millis(100));
        assert_eq!(client.calculate_backoff(1), Duration::from_millis(200));
        assert_eq!(client.calculate_backoff(2), Duration::from_millis(400));
        assert_eq!(client.calculate_backoff(3), Duration::from_millis(800));
    }

    #[test]
    fn test_calculate_backoff_high_attempt_values_no_panic() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_initial_backoff(Duration::from_millis(100));
        let client = BeaconClient::new(config).unwrap();

        // These should not panic - they would overflow with the naive implementation
        let _ = client.calculate_backoff(20);
        let _ = client.calculate_backoff(31);
        let _ = client.calculate_backoff(32);
        let _ = client.calculate_backoff(100);
    }

    #[test]
    fn test_calculate_backoff_capped_at_maximum() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_initial_backoff(Duration::from_millis(100));
        let client = BeaconClient::new(config).unwrap();

        // Max backoff at attempt 20: 100ms * 2^20 = 104,857,600ms (~29 hours)
        let max_backoff = Duration::from_millis(100 * (1 << 20));

        // All attempts >= 20 should return the same maximum backoff
        assert_eq!(client.calculate_backoff(20), max_backoff);
        assert_eq!(client.calculate_backoff(31), max_backoff);
        assert_eq!(client.calculate_backoff(32), max_backoff);
        assert_eq!(client.calculate_backoff(100), max_backoff);
    }

    #[test]
    fn test_calculate_backoff_monotonically_increasing() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_initial_backoff(Duration::from_millis(100));
        let client = BeaconClient::new(config).unwrap();

        // Backoff should be monotonically increasing up to the cap
        let mut prev_backoff = Duration::ZERO;
        for attempt in 0..=25 {
            let backoff = client.calculate_backoff(attempt);
            assert!(
                backoff >= prev_backoff,
                "Backoff should be monotonically increasing: attempt {} gave {:?}, previous was {:?}",
                attempt,
                backoff,
                prev_backoff
            );
            prev_backoff = backoff;
        }
    }

    #[tokio::test]
    async fn test_get_request_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(TestData { value: "success".to_string() }),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: TestData = client.get("/eth/v1/test").await.unwrap();
        assert_eq!(result.value, "success");
    }

    #[tokio::test]
    async fn test_post_request_success() {
        let mock_server = MockServer::start().await;

        let request_body = TestData { value: "request".to_string() };
        let response_body = TestData { value: "response".to_string() };

        Mock::given(method("POST"))
            .and(path("/eth/v1/test"))
            .and(body_json(&request_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: TestData = client.post("/eth/v1/test", &request_body).await.unwrap();
        assert_eq!(result.value, "response");
    }

    #[tokio::test]
    async fn test_client_error_no_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(3);
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 404);
                assert_eq!(message, "Not Found");
            }
            _ => panic!("Expected ApiError with status 404"),
        }
    }

    #[tokio::test]
    async fn test_server_error_triggers_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(4)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        match result {
            Err(BeaconError::ApiError { status, .. }) => {
                assert_eq!(status, 500);
            }
            _ => panic!("Expected ApiError with status 500"),
        }
    }

    #[tokio::test]
    async fn test_retry_success_after_failures() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(2)
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(TestData { value: "recovered".to_string() }),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result: TestData = client.get("/eth/v1/test").await.unwrap();
        assert_eq!(result.value, "recovered");
    }

    #[tokio::test]
    async fn test_parse_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        assert!(matches!(result, Err(BeaconError::ParseError(_))));
    }

    #[tokio::test]
    async fn test_timeout_error_triggers_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .expect(4)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_timeout(Duration::from_millis(50))
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        assert!(matches!(result, Err(BeaconError::Timeout)));
    }

    #[tokio::test]
    async fn test_get_attester_duties_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": false,
            "data": [
                {
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                    "validator_index": "1234",
                    "committee_index": "1",
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "25",
                    "slot": "10000"
                },
                {
                    "pubkey": "0xa1234f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b",
                    "validator_index": "5678",
                    "committee_index": "2",
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "50",
                    "slot": "10001"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .and(body_json(["1234", "5678"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string(), "5678".to_string()];
        let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_eq!(
            result.dependent_root,
            "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
        assert!(!result.execution_optimistic);
        assert_eq!(result.data.len(), 2);
        assert_eq!(result.data[0].validator_index, "1234");
        assert_eq!(result.data[0].slot, "10000");
        assert_eq!(result.data[1].validator_index, "5678");
        assert_eq!(result.data[1].slot, "10001");
    }

    #[tokio::test]
    async fn test_get_attester_duties_empty_indices() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": false,
            "data": []
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .and(body_json::<Vec<String>>(vec![]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices: Vec<String> = vec![];
        let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_eq!(
            result.dependent_root,
            "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
        assert!(result.data.is_empty());
    }

    #[tokio::test]
    async fn test_get_attester_duties_with_execution_optimistic() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": true,
            "data": [
                {
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                    "validator_index": "1234",
                    "committee_index": "1",
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "25",
                    "slot": "10000"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string()];
        let result = client.get_attester_duties(200, &validator_indices).await.unwrap();

        assert!(result.execution_optimistic);
    }

    #[tokio::test]
    async fn test_get_attester_duties_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/999"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string()];
        let result = client.get_attester_duties(999, &validator_indices).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid epoch");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_get_attester_duties_server_error_with_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(2)
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": false,
            "data": []
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let validator_indices: Vec<String> = vec![];
        let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_eq!(
            result.dependent_root,
            "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
    }

    #[tokio::test]
    async fn test_get_attester_duties_dependent_root_changes() {
        let mock_server = MockServer::start().await;

        let response_body_1 = serde_json::json!({
            "dependent_root": "0xroot_a_1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "25",
                "slot": "10000"
            }]
        });

        let response_body_2 = serde_json::json!({
            "dependent_root": "0xroot_b_1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "committee_index": "2",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "30",
                "slot": "10001"
            }]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body_1))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body_2))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string()];

        let result_1 = client.get_attester_duties(100, &validator_indices).await.unwrap();
        let result_2 = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_ne!(result_1.dependent_root, result_2.dependent_root);
        assert_eq!(
            result_1.dependent_root,
            "0xroot_a_1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
        assert_eq!(
            result_2.dependent_root,
            "0xroot_b_1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[tokio::test]
    async fn test_get_attestation_data_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "data": {
                "slot": "1000",
                "index": "1",
                "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "source": {
                    "epoch": "100",
                    "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
                },
                "target": {
                    "epoch": "101",
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(wiremock::matchers::query_param("slot", "1000"))
            .and(wiremock::matchers::query_param("committee_index", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_attestation_data(1000, 1).await.unwrap();

        assert_eq!(result.data.slot, "1000");
        assert_eq!(result.data.index, "1");
        assert_eq!(
            result.data.beacon_block_root,
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
        assert_eq!(result.data.source.epoch, "100");
        assert_eq!(result.data.target.epoch, "101");
    }

    #[tokio::test]
    async fn test_get_attestation_data_different_committee_index() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "data": {
                "slot": "2000",
                "index": "5",
                "beacon_block_root": "0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
                "source": {
                    "epoch": "200",
                    "root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                },
                "target": {
                    "epoch": "201",
                    "root": "0x4444444444444444444444444444444444444444444444444444444444444444"
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .and(wiremock::matchers::query_param("slot", "2000"))
            .and(wiremock::matchers::query_param("committee_index", "5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_attestation_data(2000, 5).await.unwrap();

        assert_eq!(result.data.slot, "2000");
        assert_eq!(result.data.index, "5");
    }

    #[tokio::test]
    async fn test_get_attestation_data_slot_too_early() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("Slot requested is in the future"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_attestation_data(999999999, 0).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert!(message.contains("future"));
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_get_attestation_data_slot_in_past() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Slot is in the past"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_attestation_data(1, 0).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert!(message.contains("past"));
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_get_attestation_data_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_string("Attestation data not available for requested slot"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_attestation_data(500, 0).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 404);
                assert!(message.contains("not available"));
            }
            _ => panic!("Expected ApiError with status 404"),
        }
    }

    #[tokio::test]
    async fn test_get_attestation_data_server_error_with_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(2)
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        let response_body = serde_json::json!({
            "data": {
                "slot": "1000",
                "index": "0",
                "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "source": {
                    "epoch": "100",
                    "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
                },
                "target": {
                    "epoch": "101",
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_attestation_data(1000, 0).await.unwrap();

        assert_eq!(result.data.slot, "1000");
    }

    #[tokio::test]
    async fn test_get_attestation_data_beacon_syncing() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Beacon node is syncing"))
            .expect(4)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_attestation_data(1000, 0).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 503);
                assert!(message.contains("syncing"));
            }
            _ => panic!("Expected ApiError with status 503"),
        }
    }

    #[tokio::test]
    async fn test_submit_attestation_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let attestation = crate::types::SingleAttestation {
            attester_index: 0,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "1".to_string(),
                beacon_block_root:
                    "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                },
            },
            committee_index: 0,
            signature: "0xsignature".to_string(),
        };

        let versioned = crate::types::VersionedAttestation::Electra(vec![attestation]);
        let result = client.submit_attestation(&versioned).await.unwrap();
        assert!(result.is_success());
    }

    #[tokio::test]
    async fn test_submit_attestation_invalid_attestation() {
        let mock_server = MockServer::start().await;

        let error_response = serde_json::json!({
            "code": 400,
            "message": "Invalid attestation",
            "failures": [
                {
                    "index": 0,
                    "message": "Invalid signature"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
            .respond_with(ResponseTemplate::new(400).set_body_json(&error_response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let attestation = crate::types::SingleAttestation {
            attester_index: 0,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "1".to_string(),
                beacon_block_root: "0xabcdef".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222".to_string(),
                },
            },
            committee_index: 0,
            signature: "0xinvalid".to_string(),
        };

        let versioned = crate::types::VersionedAttestation::Electra(vec![attestation]);
        let result = client.submit_attestation(&versioned).await.unwrap();
        assert!(!result.is_success());
        assert_eq!(result.failures().len(), 1);
        assert_eq!(result.failures()[0].index, 0);
        assert!(result.failures()[0].message.contains("Invalid signature"));
    }

    #[tokio::test]
    async fn test_submit_attestation_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(4)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let attestation = crate::types::SingleAttestation {
            attester_index: 0,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "1".to_string(),
                beacon_block_root: "0xabcdef".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222".to_string(),
                },
            },
            committee_index: 0,
            signature: "0xsignature".to_string(),
        };

        let versioned = crate::types::VersionedAttestation::Electra(vec![attestation]);
        let result = client.submit_attestation(&versioned).await;

        match result {
            Err(BeaconError::ApiError { status, .. }) => {
                assert_eq!(status, 500);
            }
            _ => panic!("Expected ApiError with status 500"),
        }
    }

    #[tokio::test]
    async fn test_submit_attestation_multiple_attestations() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let attestation1 = crate::types::SingleAttestation {
            attester_index: 0,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "1".to_string(),
                beacon_block_root: "0xabcdef".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222".to_string(),
                },
            },
            committee_index: 0,
            signature: "0xsignature1".to_string(),
        };

        let attestation2 = crate::types::SingleAttestation {
            attester_index: 1,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "2".to_string(),
                beacon_block_root: "0xabcdef".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222".to_string(),
                },
            },
            committee_index: 0,
            signature: "0xsignature2".to_string(),
        };

        let versioned =
            crate::types::VersionedAttestation::Electra(vec![attestation1, attestation2]);
        let result = client.submit_attestation(&versioned).await.unwrap();
        assert!(result.is_success());
    }

    #[tokio::test]
    async fn test_submit_attestation_partial_failure() {
        let mock_server = MockServer::start().await;

        let error_response = serde_json::json!({
            "code": 400,
            "message": "Some attestations failed validation",
            "failures": [
                {
                    "index": 1,
                    "message": "Invalid signature"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
            .respond_with(ResponseTemplate::new(400).set_body_json(&error_response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let attestation1 = crate::types::SingleAttestation {
            attester_index: 0,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "1".to_string(),
                beacon_block_root: "0xabcdef".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222".to_string(),
                },
            },
            committee_index: 0,
            signature: "0xvalid".to_string(),
        };

        let attestation2 = crate::types::SingleAttestation {
            attester_index: 1,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "2".to_string(),
                beacon_block_root: "0xabcdef".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222".to_string(),
                },
            },
            committee_index: 0,
            signature: "0xinvalid".to_string(),
        };

        let versioned =
            crate::types::VersionedAttestation::Electra(vec![attestation1, attestation2]);
        let result = client.submit_attestation(&versioned).await.unwrap();
        assert!(!result.is_success());
        assert_eq!(result.failures().len(), 1);
        assert_eq!(result.failures()[0].index, 1);
    }

    #[tokio::test]
    async fn test_submit_attestation_400_with_empty_failures() {
        let mock_server = MockServer::start().await;

        let error_response = serde_json::json!({
            "code": 400,
            "message": "Bad request",
            "failures": []
        });

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
            .respond_with(ResponseTemplate::new(400).set_body_json(&error_response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let attestation = crate::types::SingleAttestation {
            attester_index: 0,
            data: crate::types::AttestationData {
                slot: "1000".to_string(),
                index: "1".to_string(),
                beacon_block_root: "0xabcdef".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "100".to_string(),
                    root: "0x1111".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "101".to_string(),
                    root: "0x2222".to_string(),
                },
            },
            committee_index: 0,
            signature: "0xsignature".to_string(),
        };

        let versioned = crate::types::VersionedAttestation::Electra(vec![attestation]);
        let result = client.submit_attestation(&versioned).await;
        match result {
            Err(BeaconError::ApiError { status, .. }) => {
                assert_eq!(status, 400);
            }
            _ => panic!("Expected ApiError for 400 with empty failures"),
        }
    }

    #[tokio::test]
    async fn test_submit_attestation_empty_array() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "electra"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let versioned = crate::types::VersionedAttestation::Electra(vec![]);
        let result = client.submit_attestation(&versioned).await.unwrap();
        assert!(result.is_success());
    }

    #[tokio::test]
    async fn test_get_config_spec_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "data": {
                "GENESIS_FORK_VERSION": "0x00000000",
                "ALTAIR_FORK_EPOCH": "74240",
                "ALTAIR_FORK_VERSION": "0x01000000",
                "BELLATRIX_FORK_EPOCH": "144896",
                "BELLATRIX_FORK_VERSION": "0x02000000",
                "CAPELLA_FORK_EPOCH": "194048",
                "CAPELLA_FORK_VERSION": "0x03000000",
                "DENEB_FORK_EPOCH": "269568",
                "DENEB_FORK_VERSION": "0x04000000",
                "SECONDS_PER_SLOT": "12",
                "SLOTS_PER_EPOCH": "32"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_config_spec().await.unwrap();
        assert_eq!(result.data.get("GENESIS_FORK_VERSION").unwrap(), &json!("0x00000000"));
        assert_eq!(result.data.get("ALTAIR_FORK_EPOCH").unwrap(), &json!("74240"));
        assert_eq!(result.data.get("BELLATRIX_FORK_EPOCH").unwrap(), &json!("144896"));
        assert_eq!(result.data.get("CAPELLA_FORK_EPOCH").unwrap(), &json!("194048"));
        assert_eq!(result.data.get("DENEB_FORK_EPOCH").unwrap(), &json!("269568"));
        assert_eq!(result.data.get("SECONDS_PER_SLOT").unwrap(), &json!("12"));
        assert_eq!(result.data.get("SLOTS_PER_EPOCH").unwrap(), &json!("32"));
        assert_eq!(result.data.len(), 11);
    }

    #[tokio::test]
    async fn test_get_config_spec_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(4)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_config_spec().await;
        match result {
            Err(BeaconError::ApiError { status, .. }) => {
                assert_eq!(status, 500);
            }
            _ => panic!("Expected ApiError with status 500"),
        }
    }

    #[tokio::test]
    async fn test_get_genesis_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "data": {
                "genesis_time": "1606824023",
                "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
                "genesis_fork_version": "0x00000000"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_genesis().await.unwrap();
        assert_eq!(result.data.genesis_time, "1606824023");
        assert_eq!(
            result.data.genesis_validators_root,
            "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        );
        assert_eq!(result.data.genesis_fork_version, "0x00000000");
    }

    #[tokio::test]
    async fn test_get_genesis_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(
                ResponseTemplate::new(404).set_body_string("Chain genesis has not yet occurred"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_genesis().await;
        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 404);
                assert!(message.contains("genesis"));
            }
            _ => panic!("Expected ApiError with status 404"),
        }
    }

    #[tokio::test]
    async fn test_get_genesis_server_error_with_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(2)
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        let response_body = serde_json::json!({
            "data": {
                "genesis_time": "1606824023",
                "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
                "genesis_fork_version": "0x00000000"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_genesis().await.unwrap();
        assert_eq!(result.data.genesis_time, "1606824023");
    }

    #[tokio::test]
    async fn test_get_fork_head_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "execution_optimistic": false,
            "finalized": false,
            "data": {
                "previous_version": "0x03000000",
                "current_version": "0x04000000",
                "epoch": "269568"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/fork"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_fork("head").await.unwrap();
        assert!(!result.execution_optimistic);
        assert!(!result.finalized);
        assert_eq!(result.data.previous_version, "0x03000000");
        assert_eq!(result.data.current_version, "0x04000000");
        assert_eq!(result.data.epoch, "269568");
    }

    #[tokio::test]
    async fn test_get_fork_finalized_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "execution_optimistic": false,
            "finalized": true,
            "data": {
                "previous_version": "0x03000000",
                "current_version": "0x04000000",
                "epoch": "269568"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/finalized/fork"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_fork("finalized").await.unwrap();
        assert!(!result.execution_optimistic);
        assert!(result.finalized);
        assert_eq!(result.data.current_version, "0x04000000");
    }

    #[tokio::test]
    async fn test_get_fork_by_slot() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "execution_optimistic": false,
            "finalized": true,
            "data": {
                "previous_version": "0x00000000",
                "current_version": "0x01000000",
                "epoch": "74240"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/2375680/fork"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_fork("2375680").await.unwrap();
        assert_eq!(result.data.previous_version, "0x00000000");
        assert_eq!(result.data.current_version, "0x01000000");
        assert_eq!(result.data.epoch, "74240");
    }

    #[tokio::test]
    async fn test_get_fork_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/99999999999/fork"))
            .respond_with(ResponseTemplate::new(404).set_body_string("State not found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_fork("99999999999").await;
        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 404);
                assert!(message.contains("not found"));
            }
            _ => panic!("Expected ApiError with status 404"),
        }
    }

    #[tokio::test]
    async fn test_get_fork_execution_optimistic() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "execution_optimistic": true,
            "finalized": false,
            "data": {
                "previous_version": "0x04000000",
                "current_version": "0x05000000",
                "epoch": "364544"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/fork"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_fork("head").await.unwrap();
        assert!(result.execution_optimistic);
        assert!(!result.finalized);
        assert_eq!(result.data.current_version, "0x05000000");
        assert_eq!(result.data.epoch, "364544");
    }

    #[tokio::test]
    async fn test_get_fork_schedule_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "data": {
                "GENESIS_FORK_VERSION": "0x00000000",
                "ALTAIR_FORK_EPOCH": "74240",
                "ALTAIR_FORK_VERSION": "0x01000000",
                "BELLATRIX_FORK_EPOCH": "144896",
                "BELLATRIX_FORK_VERSION": "0x02000000",
                "CAPELLA_FORK_EPOCH": "194048",
                "CAPELLA_FORK_VERSION": "0x03000000",
                "DENEB_FORK_EPOCH": "269568",
                "DENEB_FORK_VERSION": "0x04000000",
                "ELECTRA_FORK_EPOCH": "364544",
                "ELECTRA_FORK_VERSION": "0x05000000",
                "FULU_FORK_EPOCH": "18446744073709551615",
                "FULU_FORK_VERSION": "0x06000000",
                "SECONDS_PER_SLOT": "12",
                "SLOTS_PER_EPOCH": "32"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let schedule = client.get_fork_schedule().await.unwrap();
        assert_eq!(schedule.genesis_fork_version, [0, 0, 0, 0]);
        assert_eq!(schedule.altair_fork_epoch, 74240);
        assert_eq!(schedule.altair_fork_version, [1, 0, 0, 0]);
        assert_eq!(schedule.bellatrix_fork_epoch, 144896);
        assert_eq!(schedule.capella_fork_epoch, 194048);
        assert_eq!(schedule.deneb_fork_epoch, 269568);
        assert_eq!(schedule.deneb_fork_version, [4, 0, 0, 0]);
        assert_eq!(schedule.electra_fork_epoch, 364544);
        assert_eq!(schedule.electra_fork_version, [5, 0, 0, 0]);
        assert_eq!(schedule.fulu_fork_epoch, u64::MAX);
        assert_eq!(schedule.fulu_fork_version, [6, 0, 0, 0]);
    }

    #[tokio::test]
    async fn test_get_fork_schedule_missing_field() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "data": {
                "GENESIS_FORK_VERSION": "0x00000000",
                "ALTAIR_FORK_EPOCH": "74240",
                "ALTAIR_FORK_VERSION": "0x01000000"
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_fork_schedule().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_proposer_duties_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": false,
            "data": [
                {
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                    "validator_index": "1234",
                    "slot": "320000"
                },
                {
                    "pubkey": "0xa1234f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b",
                    "validator_index": "5678",
                    "slot": "320001"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_proposer_duties(10000).await.unwrap();

        assert_eq!(
            result.dependent_root,
            "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
        assert!(!result.execution_optimistic);
        assert_eq!(result.data.len(), 2);
        assert_eq!(result.data[0].validator_index, "1234");
        assert_eq!(result.data[0].slot, "320000");
        assert_eq!(result.data[1].validator_index, "5678");
        assert_eq!(result.data[1].slot, "320001");
    }

    #[tokio::test]
    async fn test_get_proposer_duties_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/999"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_proposer_duties(999).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid epoch");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_produce_block_v3_full_block() {
        let mock_server = MockServer::start().await;

        let block_data = serde_json::json!({
            "slot": "100",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        });
        let envelope = serde_json::json!({
            "version": "deneb",
            "execution_optimistic": false,
            "data": block_data
        });

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/100"))
            .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&envelope)
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Consensus-Version", "deneb")
                    .insert_header("Eth-Execution-Payload-Value", "12345"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(100, "0xrandao", None, None).await.unwrap();

        assert!(!result.is_blinded);
        assert_eq!(result.consensus_version, "deneb");
        assert_eq!(result.execution_payload_value, Some("12345".to_string()));
        assert!(!result.is_ssz);
        assert!(result.ssz_bytes.is_none());

        let block = result.parse_full_block().unwrap();
        assert_eq!(block.block().slot, 100);
        assert_eq!(block.block().proposer_index, 42);
    }

    #[tokio::test]
    async fn test_produce_block_v3_blinded_block() {
        let mock_server = MockServer::start().await;

        let block_data = serde_json::json!({
            "slot": "200",
            "proposer_index": "10",
            "parent_root": format!("0x{}", "03".repeat(32)),
            "state_root": format!("0x{}", "04".repeat(32)),
            "body": "0xbeef"
        });
        let envelope = serde_json::json!({
            "version": "deneb",
            "execution_optimistic": false,
            "data": block_data
        });

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/200"))
            .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&envelope)
                    .insert_header("Eth-Execution-Payload-Blinded", "true")
                    .insert_header("Eth-Consensus-Version", "deneb"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(200, "0xrandao", None, None).await.unwrap();

        assert!(result.is_blinded);
        assert_eq!(result.consensus_version, "deneb");
        assert_eq!(result.execution_payload_value, None);
        assert!(!result.is_ssz);
        assert!(result.ssz_bytes.is_none());

        let block = result.parse_blinded_block().unwrap();
        assert_eq!(block.slot, 200);
        assert_eq!(block.proposer_index, 10);
    }

    #[tokio::test]
    async fn test_produce_block_v3_with_graffiti_and_boost() {
        let mock_server = MockServer::start().await;

        let block_body = serde_json::json!({
            "version": "deneb",
            "data": {}
        });

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/300"))
            .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
            .and(wiremock::matchers::query_param("graffiti", "0xgraf"))
            .and(wiremock::matchers::query_param("builder_boost_factor", "50"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&block_body)
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Consensus-Version", "deneb"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result =
            client.produce_block_v3(300, "0xrandao", Some("0xgraf"), Some(50)).await.unwrap();

        assert!(!result.is_blinded);
        assert_eq!(result.consensus_version, "deneb");
    }

    #[tokio::test]
    async fn test_produce_block_v3_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/999"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Slot in the past"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(999, "0xrandao", None, None).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert!(message.contains("past"));
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_produce_block_v3_ssz_response() {
        let mock_server = MockServer::start().await;

        let ssz_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/500"))
            .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Consensus-Version", "deneb")
                    .insert_header("Eth-Execution-Payload-Value", "99999"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(500, "0xrandao", None, None).await.unwrap();

        assert!(result.is_ssz);
        assert_eq!(result.ssz_bytes, Some(ssz_payload));
        assert_eq!(result.data, serde_json::Value::Null);
        assert!(!result.is_blinded);
        assert_eq!(result.consensus_version, "deneb");
        assert_eq!(result.execution_payload_value, Some("99999".to_string()));
    }

    #[tokio::test]
    async fn test_produce_block_v3_ssz_blinded_response() {
        let mock_server = MockServer::start().await;

        let ssz_payload = vec![0xaa; 256];

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/600"))
            .and(wiremock::matchers::query_param("randao_reveal", "0xrandao"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                    .insert_header("Eth-Execution-Payload-Blinded", "true")
                    .insert_header("Eth-Consensus-Version", "electra"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(600, "0xrandao", None, None).await.unwrap();

        assert!(result.is_ssz);
        assert_eq!(result.ssz_bytes.as_ref().unwrap().len(), 256);
        assert!(result.is_blinded);
        assert_eq!(result.consensus_version, "electra");
        assert_eq!(result.execution_payload_value, None);
    }

    #[tokio::test]
    async fn test_produce_block_v3_sends_accept_header() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/700"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"version": "deneb", "data": {}}))
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Consensus-Version", "deneb"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let _ = client.produce_block_v3(700, "0xrandao", None, None).await.unwrap();

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let accept = requests[0].headers.get("accept").expect("Accept header must be present");
        let accept_str = accept.to_str().unwrap();
        // SSZ preference is disabled until downstream deserialization is implemented.
        // Accept header currently requests JSON only.
        assert!(
            accept_str.contains("application/json"),
            "Accept header must include JSON: {}",
            accept_str
        );
    }

    #[tokio::test]
    async fn test_produce_block_v3_json_fallback_with_charset() {
        let mock_server = MockServer::start().await;

        let block_data = serde_json::json!({
            "slot": "100",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        });
        let envelope = serde_json::json!({
            "version": "deneb",
            "data": block_data
        });

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/800"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&envelope)
                    .insert_header("Content-Type", "application/json; charset=utf-8")
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Consensus-Version", "deneb"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(800, "0xrandao", None, None).await.unwrap();

        assert!(!result.is_ssz);
        assert!(result.ssz_bytes.is_none());
        let block = result.parse_full_block().unwrap();
        assert_eq!(block.block().slot, 100);
    }

    /// Stateful responder: returns `first` on call 0, `second` on all subsequent calls.
    struct SszThenJsonResponder {
        call_count: AtomicUsize,
        first: ResponseTemplate,
        second: ResponseTemplate,
    }

    impl wiremock::Respond for SszThenJsonResponder {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            let n = self.call_count.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                self.first.clone()
            } else {
                self.second.clone()
            }
        }
    }

    #[tokio::test]
    async fn test_produce_block_v3_ssz_empty_body_falls_back_to_json() {
        let mock_server = MockServer::start().await;

        let block_data = serde_json::json!({
            "slot": "900",
            "proposer_index": "42",
            "parent_root": format!("0x{}", "01".repeat(32)),
            "state_root": format!("0x{}", "02".repeat(32)),
            "body": "0xdead"
        });
        let json_envelope = serde_json::json!({ "version": "deneb", "data": block_data });

        let responder = SszThenJsonResponder {
            call_count: AtomicUsize::new(0),
            first: ResponseTemplate::new(200)
                .set_body_raw(vec![], "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
            second: ResponseTemplate::new(200)
                .set_body_json(&json_envelope)
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
        };

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/900"))
            .respond_with(responder)
            .expect(2)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(900, "0xrandao", None, None).await.unwrap();

        // Should have fallen back to JSON
        assert!(!result.is_ssz);
        assert!(result.ssz_bytes.is_none());
        assert_eq!(result.consensus_version, "deneb");
        let block = result.parse_full_block().unwrap();
        assert_eq!(block.block().slot, 900);
    }

    #[tokio::test]
    async fn test_produce_block_v3_ssz_fallback_json_gets_correct_headers() {
        let mock_server = MockServer::start().await;

        let block_data = serde_json::json!({
            "slot": "950",
            "proposer_index": "55",
            "parent_root": format!("0x{}", "03".repeat(32)),
            "state_root": format!("0x{}", "04".repeat(32)),
            "body": "0xbeef"
        });
        let json_envelope = serde_json::json!({ "version": "electra", "data": block_data });

        let responder = SszThenJsonResponder {
            call_count: AtomicUsize::new(0),
            first: ResponseTemplate::new(200)
                .set_body_raw(vec![], "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
            second: ResponseTemplate::new(200)
                .set_body_json(&json_envelope)
                .insert_header("Eth-Execution-Payload-Blinded", "true")
                .insert_header("Eth-Consensus-Version", "electra")
                .insert_header("Eth-Execution-Payload-Value", "77777"),
        };

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/950"))
            .respond_with(responder)
            .expect(2)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(950, "0xrandao", None, None).await.unwrap();

        // Headers come from the JSON fallback response, not the original SSZ response
        assert!(!result.is_ssz);
        assert!(result.is_blinded);
        assert_eq!(result.consensus_version, "electra");
        assert_eq!(result.execution_payload_value, Some("77777".to_string()));
    }

    #[tokio::test]
    async fn test_produce_block_v3_valid_ssz_no_fallback() {
        let mock_server = MockServer::start().await;

        let ssz_payload = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/960"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(ssz_payload.clone(), "application/octet-stream")
                    .insert_header("Eth-Execution-Payload-Blinded", "false")
                    .insert_header("Eth-Consensus-Version", "deneb"),
            )
            // Must be called exactly once — no fallback attempt
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(960, "0xrandao", None, None).await.unwrap();

        assert!(result.is_ssz);
        assert_eq!(result.ssz_bytes, Some(ssz_payload));
    }

    #[tokio::test]
    async fn test_produce_block_v3_ssz_fallback_network_error_propagated() {
        let mock_server = MockServer::start().await;

        // Both calls return SSZ empty body — fallback also gets SSZ, which fails JSON parse
        let responder = SszThenJsonResponder {
            call_count: AtomicUsize::new(0),
            first: ResponseTemplate::new(200)
                .set_body_raw(vec![], "application/octet-stream")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Consensus-Version", "deneb"),
            second: ResponseTemplate::new(500),
        };

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/970"))
            .respond_with(responder)
            .expect(2)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
        let client = BeaconClient::new(config).unwrap();

        let result = client.produce_block_v3(970, "0xrandao", None, None).await;
        // The JSON fallback request gets a 500 server error, which propagates
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_publish_block() {
        let mock_server = MockServer::start().await;

        let signed_block = serde_json::json!({
            "message": {
                "slot": "100",
                "proposer_index": "42",
                "parent_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
                "state_root": "0x0202020202020202020202020202020202020202020202020202020202020202",
                "body": "0xdead"
            },
            "signature": "0xaabbcc"
        });

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .and(body_json(&signed_block))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "deneb"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        client.publish_block(&signed_block, "deneb").await.unwrap();
    }

    #[tokio::test]
    async fn test_publish_block_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid block"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let signed_block = serde_json::json!({"message": {}});
        let result = client.publish_block(&signed_block, "deneb").await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert!(message.contains("Invalid block"));
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_publish_blinded_block() {
        let mock_server = MockServer::start().await;

        let signed_blinded_block = serde_json::json!({
            "message": {
                "slot": "200",
                "proposer_index": "10",
                "parent_root": "0x0101010101010101010101010101010101010101010101010101010101010101",
                "state_root": "0x0202020202020202020202020202020202020202020202020202020202020202",
                "body": "0xbeef"
            },
            "signature": "0xbbccdd"
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/blinded_blocks"))
            .and(body_json(&signed_blinded_block))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "deneb"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        client.publish_blinded_block(&signed_blinded_block, "deneb").await.unwrap();
    }

    #[tokio::test]
    async fn test_publish_blinded_block_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/blinded_blocks"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid blinded block"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let signed_block = serde_json::json!({"message": {}});
        let result = client.publish_blinded_block(&signed_block, "deneb").await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert!(message.contains("Invalid blinded block"));
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_get_proposer_duties_with_dependent_root() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xabc123",
            "execution_optimistic": true,
            "data": [
                {
                    "pubkey": "0xpubkey1",
                    "validator_index": "100",
                    "slot": "64000"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/2000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_proposer_duties(2000).await.unwrap();

        assert_eq!(result.dependent_root, "0xabc123");
        assert!(result.execution_optimistic);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].pubkey, "0xpubkey1");
    }

    #[tokio::test]
    async fn test_publish_block_server_error_with_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(2)
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/blocks"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let signed_block = serde_json::json!({"message": {}});
        client.publish_block(&signed_block, "deneb").await.unwrap();
    }

    #[tokio::test]
    async fn test_post_sync_committee_duties_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "execution_optimistic": false,
            "data": [
                {
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                    "validator_index": "1234",
                    "validator_sync_committee_indices": ["0", "128", "256"]
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/sync/100"))
            .and(body_json(["1234"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let indices = vec!["1234".to_string()];
        let result = client.post_sync_committee_duties(100, &indices).await.unwrap();

        assert!(!result.execution_optimistic);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].validator_index, 1234);
        assert_eq!(result.data[0].validator_sync_committee_indices, vec![0, 128, 256]);
    }

    #[tokio::test]
    async fn test_post_sync_committee_duties_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/sync/999"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let indices = vec!["1234".to_string()];
        let result = client.post_sync_committee_duties(999, &indices).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid epoch");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_submit_sync_committee_messages_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let messages = vec![eth_types::SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [1u8; 32],
            validator_index: 42,
            signature: vec![0xaa; 96],
        }];

        let result = client.submit_sync_committee_messages(&messages).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_sync_committee_messages_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/sync_committees"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid message"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let messages = vec![eth_types::SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [1u8; 32],
            validator_index: 42,
            signature: vec![0xaa; 96],
        }];

        let result = client.submit_sync_committee_messages(&messages).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid message");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_get_sync_committee_contribution_success() {
        let mock_server = MockServer::start().await;

        let contribution = eth_types::SyncCommitteeContribution {
            slot: 100,
            beacon_block_root: [1u8; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xbb; 96],
        };
        let response_body = serde_json::json!({
            "data": serde_json::to_value(&contribution).unwrap()
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/sync_committee_contribution"))
            .and(wiremock::matchers::query_param("slot", "100"))
            .and(wiremock::matchers::query_param("subcommittee_index", "2"))
            .and(wiremock::matchers::query_param("beacon_block_root", "0xbeefbeef"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_sync_committee_contribution(100, 2, "0xbeefbeef").await.unwrap();

        assert_eq!(result.data.slot, 100);
        assert_eq!(result.data.subcommittee_index, 2);
    }

    #[tokio::test]
    async fn test_get_sync_committee_contribution_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/sync_committee_contribution"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Contribution not available"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_sync_committee_contribution(100, 2, "0xbeefbeef").await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 404);
                assert!(message.contains("not available"));
            }
            _ => panic!("Expected ApiError with status 404"),
        }
    }

    #[tokio::test]
    async fn test_submit_contribution_and_proofs_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/contribution_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let proofs = vec![eth_types::SignedContributionAndProof {
            message: eth_types::ContributionAndProof {
                aggregator_index: 42,
                contribution: eth_types::SyncCommitteeContribution {
                    slot: 100,
                    beacon_block_root: [1u8; 32],
                    subcommittee_index: 2,
                    aggregation_bits: vec![0xff; 16],
                    signature: vec![0xbb; 96],
                },
                selection_proof: vec![0xcc; 96],
            },
            signature: vec![0xdd; 96],
        }];

        let result = client.submit_contribution_and_proofs(&proofs).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_contribution_and_proofs_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/contribution_and_proofs"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid proof"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let proofs = vec![eth_types::SignedContributionAndProof {
            message: eth_types::ContributionAndProof {
                aggregator_index: 42,
                contribution: eth_types::SyncCommitteeContribution {
                    slot: 100,
                    beacon_block_root: [1u8; 32],
                    subcommittee_index: 2,
                    aggregation_bits: vec![0xff; 16],
                    signature: vec![0xbb; 96],
                },
                selection_proof: vec![0xcc; 96],
            },
            signature: vec![0xdd; 96],
        }];

        let result = client.submit_contribution_and_proofs(&proofs).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid proof");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    // Aggregation endpoint tests

    #[tokio::test]
    async fn test_get_aggregate_attestation_success() {
        let mock_server = MockServer::start().await;

        let att_data_root = format!("0x{}", "ab".repeat(32));
        let block_root_hex = format!("0x{}", "01".repeat(32));
        let source_root_hex = format!("0x{}", "02".repeat(32));
        let target_root_hex = format!("0x{}", "03".repeat(32));
        let sig_hex = format!("0x{}", "aa".repeat(96));
        let bits_hex = format!("0x{}", "ff".repeat(4));

        let response_body = serde_json::json!({
            "data": {
                "aggregation_bits": bits_hex,
                "data": {
                    "slot": "100",
                    "index": "1",
                    "beacon_block_root": block_root_hex,
                    "source": {
                        "epoch": "3",
                        "root": source_root_hex,
                    },
                    "target": {
                        "epoch": "4",
                        "root": target_root_hex,
                    }
                },
                "signature": sig_hex
            }
        });

        let expected_path = "/eth/v1/validator/aggregate_attestation";

        Mock::given(method("GET"))
            .and(path(expected_path))
            .and(wiremock::matchers::query_param("slot", "100"))
            .and(wiremock::matchers::query_param("attestation_data_root", &att_data_root))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_aggregate_attestation(100, &att_data_root, None).await.unwrap();

        assert_eq!(result.data.data.slot, 100);
        assert_eq!(result.data.data.index, 1);
        assert_eq!(result.data.aggregation_bits, vec![0xff; 4]);
        assert_eq!(result.data.signature, vec![0xaa; 96]);
    }

    #[tokio::test]
    async fn test_get_aggregate_attestation_not_found() {
        let mock_server = MockServer::start().await;

        let att_data_root = format!("0x{}", "ab".repeat(32));

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Attestation not found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_aggregate_attestation(100, &att_data_root, None).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 404);
                assert_eq!(message, "Attestation not found");
            }
            _ => panic!("Expected ApiError with status 404"),
        }
    }

    #[tokio::test]
    async fn test_submit_aggregate_and_proofs_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let proofs = crate::types::VersionedSignedAggregateAndProof::PreElectra(vec![
            eth_types::SignedAggregateAndProof {
                message: eth_types::AggregateAndProof {
                    aggregator_index: 42,
                    aggregate: eth_types::Attestation {
                        aggregation_bits: vec![0xff; 4],
                        data: eth_types::AttestationData {
                            slot: 100,
                            index: 1,
                            beacon_block_root: [1u8; 32],
                            source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                            target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                        },
                        signature: vec![0xaa; 96],
                    },
                    selection_proof: vec![0xbb; 96],
                },
                signature: vec![0xcc; 96],
            },
        ]);

        let result = client.submit_aggregate_and_proofs(&proofs).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_aggregate_and_proofs_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid proof"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let proofs = crate::types::VersionedSignedAggregateAndProof::PreElectra(vec![
            eth_types::SignedAggregateAndProof {
                message: eth_types::AggregateAndProof {
                    aggregator_index: 42,
                    aggregate: eth_types::Attestation {
                        aggregation_bits: vec![0xff; 4],
                        data: eth_types::AttestationData {
                            slot: 100,
                            index: 1,
                            beacon_block_root: [1u8; 32],
                            source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                            target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                        },
                        signature: vec![0xaa; 96],
                    },
                    selection_proof: vec![0xbb; 96],
                },
                signature: vec![0xcc; 96],
            },
        ]);

        let result = client.submit_aggregate_and_proofs(&proofs).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid proof");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_submit_attestation_pre_electra_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/beacon/pool/attestations"))
            .and(wiremock::matchers::header("Eth-Consensus-Version", "phase0"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let legacy = crate::types::LegacyAttestation {
            aggregation_bits: "0xff03".to_string(),
            data: crate::types::AttestationData {
                slot: "100".to_string(),
                index: "1".to_string(),
                beacon_block_root: "0xroot".to_string(),
                source: crate::types::Checkpoint {
                    epoch: "3".to_string(),
                    root: "0xsource".to_string(),
                },
                target: crate::types::Checkpoint {
                    epoch: "4".to_string(),
                    root: "0xtarget".to_string(),
                },
            },
            signature: "0xsig".to_string(),
        };

        let versioned = crate::types::VersionedAttestation::PreElectra(vec![legacy]);
        let result = client.submit_attestation(&versioned).await.unwrap();
        assert!(result.is_success());
    }

    #[tokio::test]
    async fn test_get_aggregate_attestation_with_committee_index() {
        let mock_server = MockServer::start().await;

        let att_data_root = format!("0x{}", "ab".repeat(32));
        let sig_hex = format!("0x{}", "aa".repeat(96));
        let response_body = serde_json::json!({
            "data": {
                "aggregation_bits": format!("0x{}", "ff".repeat(4)),
                "data": {
                    "slot": "100",
                    "index": "1",
                    "beacon_block_root": format!("0x{}", "01".repeat(32)),
                    "source": {
                        "epoch": "3",
                        "root": format!("0x{}", "02".repeat(32))
                    },
                    "target": {
                        "epoch": "4",
                        "root": format!("0x{}", "03".repeat(32))
                    }
                },
                "signature": sig_hex
            }
        });

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/aggregate_attestation"))
            .and(wiremock::matchers::query_param("slot", "100"))
            .and(wiremock::matchers::query_param("attestation_data_root", &att_data_root))
            .and(wiremock::matchers::query_param("committee_index", "5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_aggregate_attestation(100, &att_data_root, Some(5)).await.unwrap();
        assert_eq!(result.data.data.slot, 100);
    }

    #[tokio::test]
    async fn test_submit_aggregate_and_proofs_electra() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v2/validator/aggregate_and_proofs"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let proofs = crate::types::VersionedSignedAggregateAndProof::Electra(vec![
            eth_types::SignedElectraAggregateAndProof {
                message: eth_types::ElectraAggregateAndProof {
                    aggregator_index: 42,
                    aggregate: eth_types::ElectraAttestation {
                        aggregation_bits: vec![0xff; 4],
                        data: eth_types::AttestationData {
                            slot: 100,
                            index: 1,
                            beacon_block_root: [1u8; 32],
                            source: eth_types::Checkpoint { epoch: 3, root: [2u8; 32] },
                            target: eth_types::Checkpoint { epoch: 4, root: [3u8; 32] },
                        },
                        signature: vec![0xaa; 96],
                        committee_bits: vec![0x01; 8],
                    },
                    selection_proof: vec![0xbb; 96],
                },
                signature: vec![0xcc; 96],
            },
        ]);

        let result = client.submit_aggregate_and_proofs(&proofs).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_prepare_beacon_proposer_success() {
        let mock_server = MockServer::start().await;

        let preparations = vec![
            ProposerPreparation {
                validator_index: "1234".to_string(),
                fee_recipient: "0xabcf8e0d4e9587369b2301d0790347320302cc09".to_string(),
            },
            ProposerPreparation {
                validator_index: "5678".to_string(),
                fee_recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            },
        ];

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .and(body_json(&preparations))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.prepare_beacon_proposer(&preparations).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_prepare_beacon_proposer_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid preparation data"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let preparations = vec![ProposerPreparation {
            validator_index: "1234".to_string(),
            fee_recipient: "0xabcf8e0d4e9587369b2301d0790347320302cc09".to_string(),
        }];

        let result = client.prepare_beacon_proposer(&preparations).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid preparation data");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_submit_beacon_committee_subscriptions_success() {
        let mock_server = MockServer::start().await;

        let subscriptions = vec![
            BeaconCommitteeSubscription {
                validator_index: "1234".to_string(),
                committee_index: "1".to_string(),
                committees_at_slot: "64".to_string(),
                slot: "10000".to_string(),
                is_aggregator: true,
            },
            BeaconCommitteeSubscription {
                validator_index: "5678".to_string(),
                committee_index: "2".to_string(),
                committees_at_slot: "64".to_string(),
                slot: "10000".to_string(),
                is_aggregator: false,
            },
        ];

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .and(body_json(&subscriptions))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.submit_beacon_committee_subscriptions(&subscriptions).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_beacon_committee_subscriptions_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid subscription data"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let subscriptions = vec![BeaconCommitteeSubscription {
            validator_index: "1234".to_string(),
            committee_index: "1".to_string(),
            committees_at_slot: "64".to_string(),
            slot: "10000".to_string(),
            is_aggregator: true,
        }];

        let result = client.submit_beacon_committee_subscriptions(&subscriptions).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid subscription data");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_post_validator_liveness_success() {
        let mock_server = MockServer::start().await;

        // Standard spec response: only index + is_live, no epoch.
        let response_body = serde_json::json!({
            "data": [
                {
                    "index": "1234",
                    "is_live": true
                },
                {
                    "index": "5678",
                    "is_live": false
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/liveness/100"))
            .and(body_json(["1234", "5678"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let indices = vec!["1234".to_string(), "5678".to_string()];
        let result = client.post_validator_liveness(100, &indices).await.unwrap();

        assert_eq!(result.data.len(), 2);
        assert_eq!(result.data[0].index, "1234");
        assert!(result.data[0].is_live);
        assert_eq!(result.data[1].index, "5678");
        assert!(!result.data[1].is_live);
    }

    #[tokio::test]
    async fn test_post_validator_liveness_lighthouse_compat() {
        let mock_server = MockServer::start().await;

        // Lighthouse returns an extra `epoch` field; serde ignores it.
        let response_body = serde_json::json!({
            "data": [
                {
                    "index": "1234",
                    "epoch": "100",
                    "is_live": true
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/liveness/100"))
            .and(body_json(["1234"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let indices = vec!["1234".to_string()];
        let result = client.post_validator_liveness(100, &indices).await.unwrap();

        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].index, "1234");
        assert!(result.data[0].is_live);
    }

    #[tokio::test]
    async fn test_post_validator_liveness_empty_indices() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "data": []
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/liveness/100"))
            .and(body_json::<Vec<String>>(vec![]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let indices: Vec<String> = vec![];
        let result = client.post_validator_liveness(100, &indices).await.unwrap();

        assert!(result.data.is_empty());
    }

    #[tokio::test]
    async fn test_post_validator_liveness_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/liveness/999"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let indices = vec!["1234".to_string()];
        let result = client.post_validator_liveness(999, &indices).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid epoch");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    // --- Voluntary exit tests ---

    #[tokio::test]
    async fn test_submit_voluntary_exit_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/voluntary_exits"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let signed_exit = eth_types::SignedVoluntaryExit {
            message: eth_types::VoluntaryExit { epoch: 100, validator_index: 42 },
            signature: vec![0xaa; 96],
        };

        let result = client.submit_voluntary_exit(&signed_exit).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_voluntary_exit_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/pool/voluntary_exits"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid exit"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let signed_exit = eth_types::SignedVoluntaryExit {
            message: eth_types::VoluntaryExit { epoch: 100, validator_index: 42 },
            signature: vec![0xaa; 96],
        };

        let result = client.submit_voluntary_exit(&signed_exit).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid exit");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    // -- get_node_syncing tests --

    #[tokio::test]
    async fn test_get_node_syncing_synced() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_node_syncing().await.unwrap();
        assert_eq!(result.data.head_slot, "1000");
        assert_eq!(result.data.sync_distance, "0");
        assert!(!result.data.is_syncing);
        assert!(!result.data.is_optimistic);
        assert!(!result.data.el_offline);
    }

    #[tokio::test]
    async fn test_get_node_syncing_still_syncing() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"500","sync_distance":"500","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_node_syncing().await.unwrap();
        assert_eq!(result.data.head_slot, "500");
        assert_eq!(result.data.sync_distance, "500");
        assert!(result.data.is_syncing);
    }

    #[tokio::test]
    async fn test_get_node_syncing_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
        let client = BeaconClient::new(config).unwrap();

        let result = client.get_node_syncing().await;
        assert!(result.is_err());
    }

    // -- get_node_version tests --

    #[tokio::test]
    async fn test_get_node_version_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"version":"Lighthouse/v7.1.0-a1b2c3d/x86_64-linux"}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();
        let version = client.get_node_version().await.unwrap();
        assert_eq!(version, "Lighthouse/v7.1.0-a1b2c3d/x86_64-linux");
    }

    #[tokio::test]
    async fn test_get_node_version_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
        let client = BeaconClient::new(config).unwrap();
        let result = client.get_node_version().await;
        assert!(result.is_err());
    }

    // -- Builder registration tests --

    fn sample_signed_registration() -> eth_types::SignedValidatorRegistration {
        eth_types::SignedValidatorRegistration {
            message: eth_types::ValidatorRegistrationV1 {
                fee_recipient: [0xab; 20],
                gas_limit: 30_000_000,
                timestamp: 1_700_000_000,
                pubkey: [0xcd; 48],
            },
            signature: vec![0xee; 96],
        }
    }

    #[tokio::test]
    async fn test_builder_register_validators_success() {
        let mock_server = MockServer::start().await;

        let registrations = vec![sample_signed_registration()];

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/register_validator"))
            .and(body_json(&registrations))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.register_validators(&registrations).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_builder_register_validators_multiple() {
        let mock_server = MockServer::start().await;

        let mut reg2 = sample_signed_registration();
        reg2.message.pubkey = [0xdd; 48];
        reg2.message.fee_recipient = [0xbc; 20];

        let registrations = vec![sample_signed_registration(), reg2];

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/register_validator"))
            .and(body_json(&registrations))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result = client.register_validators(&registrations).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_builder_register_validators_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/register_validator"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid registration data"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let registrations = vec![sample_signed_registration()];
        let result = client.register_validators(&registrations).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid registration data");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_parse_error_includes_body_preview() {
        let mock_server = MockServer::start().await;

        let invalid_body = "this is not valid json at all";

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string(invalid_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        match result {
            Err(BeaconError::ParseError(msg)) => {
                // New format: "error decoding response body: <serde error>"
                // Old format was just "error decoding response body" from reqwest
                assert!(
                    msg.starts_with("error decoding response body: "),
                    "Expected error message to start with 'error decoding response body: ', got: {msg}"
                );
            }
            other => panic!("Expected ParseError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_parse_error_truncates_large_body() {
        let mock_server = MockServer::start().await;

        // Create a body larger than 1024 bytes that is invalid JSON
        let large_body = "x".repeat(2048);

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&large_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        match result {
            Err(BeaconError::ParseError(msg)) => {
                assert!(
                    msg.starts_with("error decoding response body: "),
                    "Expected error message to start with 'error decoding response body: ', got: {msg}"
                );
            }
            other => panic!("Expected ParseError, got: {other:?}"),
        }
    }
}
