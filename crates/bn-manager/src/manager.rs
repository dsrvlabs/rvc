use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconClient, BeaconCommitteeSubscription,
    BeaconError, BlockRootResponse, ConfigSpecResponse, GenesisResponse, ProduceBlockResponse,
    ProposerDutiesResponse, ProposerPreparation, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, SyncingResponse, ValidatorsResponse, VersionedAggregateAttestation,
    VersionedAttestation, VersionedSignedAggregateAndProof,
};
use eth_types::{
    ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedValidatorRegistration,
};
use futures::future::join_all;
use tracing::Instrument;
use tracing::{debug, warn};
use url::Url;

/// Redact credentials from a URL for safe inclusion in tracing spans.
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

use crate::health::{new_shared_health_trackers, SharedHealthTrackers};
use crate::sse::{self, SseConfig, SseEvent};
use crate::sync_status::{
    check_all_sync_statuses, new_shared_sync_statuses, start_sync_monitor, SharedSyncStatuses,
};
use crate::traits::{BeaconNodeClient, BnHealthScore, BnManagerConfig, OperationTimeouts};
use crate::BnManagerError;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, BeaconError>> + Send + 'a>>;
type IndexedTimedResultFut<'a, T> =
    Pin<Box<dyn Future<Output = (usize, String, Result<T, BeaconError>, Duration)> + Send + 'a>>;

/// Default sync check interval: once per epoch (~384 seconds).
const DEFAULT_SYNC_CHECK_INTERVAL: Duration = Duration::from_secs(384);

/// Beacon node manager with multi-BN support, strategy-based selection, and broadcast.
///
/// Supports three operation modes:
/// - **First**: Try synced BNs in order, fail over on error (used for duty fetching, attestation data)
/// - **Best**: Query synced BNs in parallel, pick best result (used for block production)
/// - **Broadcast**: Send to all BNs regardless of sync status, return first success (used for all submissions)
///
/// Tracks per-BN sync status and skips unsynced BNs for query operations.
/// In single-BN mode, logs warnings but continues with the only available BN.
pub struct BnManager {
    clients: Vec<BeaconClient>,
    sync_statuses: SharedSyncStatuses,
    health_trackers: SharedHealthTrackers,
    overall_timeout: Option<Duration>,
    operation_timeouts: Option<OperationTimeouts>,
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

        let sync_statuses = new_shared_sync_statuses(clients.len());
        let endpoints: Vec<String> = clients.iter().map(|c| c.endpoint().to_string()).collect();
        let health_trackers = new_shared_health_trackers(&endpoints);
        Ok(Self {
            clients,
            sync_statuses,
            health_trackers,
            overall_timeout: None,
            operation_timeouts: None,
        })
    }

    /// Returns the shared sync status tracker.
    pub fn sync_statuses(&self) -> &SharedSyncStatuses {
        &self.sync_statuses
    }

    /// Returns the shared health trackers.
    pub fn health_trackers(&self) -> &SharedHealthTrackers {
        &self.health_trackers
    }

    /// Sets an overall deadline for multi-BN operations (`query_best`, `broadcast`).
    ///
    /// When set, the entire operation (including all BN queries and fallbacks)
    /// is wrapped in `tokio::time::timeout`. If the deadline expires before any
    /// BN responds, a timeout error is returned.
    pub fn with_overall_timeout(mut self, timeout: Duration) -> Self {
        self.overall_timeout = Some(timeout);
        self
    }

    /// Sets per-operation timeouts for BN API calls.
    ///
    /// When set, each BN operation is wrapped in `tokio::time::timeout` using the
    /// corresponding field from `OperationTimeouts`. If an operation exceeds its
    /// timeout, `BeaconError::OperationTimeout` is returned.
    pub fn with_operation_timeouts(mut self, timeouts: OperationTimeouts) -> Self {
        self.operation_timeouts = Some(timeouts);
        self
    }

    /// Wraps a future with an optional per-operation timeout.
    async fn with_op_timeout<T>(
        &self,
        op_name: &str,
        timeout: Option<Duration>,
        fut: impl Future<Output = Result<T, BeaconError>>,
    ) -> Result<T, BeaconError> {
        match timeout {
            Some(d) => tokio::time::timeout(d, fut).await.map_err(|_| {
                warn!(op = op_name, timeout_ms = d.as_millis() as u64, "operation timed out");
                BeaconError::OperationTimeout { operation: op_name.to_string(), timeout: d }
            })?,
            None => fut.await,
        }
    }

    /// Returns the per-operation timeout for a given field selector.
    fn op_timeout(&self, f: impl FnOnce(&OperationTimeouts) -> Duration) -> Option<Duration> {
        self.operation_timeouts.as_ref().map(f)
    }

    /// Returns current health scores for all BNs.
    #[tracing::instrument(name = "rvc.bn_manager.health_scores", skip_all)]
    pub async fn health_scores(&self) -> Vec<BnHealthScore> {
        use crate::sync_status::BnSyncStatus;

        let health_guard = self.health_trackers.read().await;
        let sync_guard = self.sync_statuses.read().await;
        health_guard
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let sync_status = sync_guard.get(i).copied().unwrap_or(BnSyncStatus::Unknown);
                BnHealthScore {
                    endpoint: t.endpoint().to_string(),
                    is_reachable: !matches!(sync_status, BnSyncStatus::Unreachable),
                    is_synced: matches!(sync_status, BnSyncStatus::Synced),
                    head_slot: None,
                    latency: t.latency_ema_ms().map(|ms| Duration::from_secs_f64(ms / 1000.0)),
                    latency_ms: t.latency_ema_ms().unwrap_or(0.0),
                    error_rate: t.error_rate(),
                    score: t.score(),
                }
            })
            .collect()
    }

    /// Checks sync status of all configured BNs immediately.
    #[tracing::instrument(name = "rvc.bn_manager.check_sync_status", skip_all)]
    pub async fn check_sync_status(&self) {
        check_all_sync_statuses(&self.clients, &self.sync_statuses).await;
    }

    /// Starts a background task that periodically polls sync status.
    ///
    /// Uses the default interval of one epoch (~384 seconds) if `interval` is None.
    pub fn start_sync_monitor(
        &self,
        interval: Option<Duration>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let interval = interval.unwrap_or(DEFAULT_SYNC_CHECK_INTERVAL);
        start_sync_monitor(self.clients.clone(), self.sync_statuses.clone(), interval, shutdown)
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
        let configs: Vec<SseConfig> =
            self.clients.iter().map(|c| SseConfig::new(c.endpoint().to_string())).collect();
        tokio::spawn(async move {
            sse::subscribe_events(configs, callback, shutdown).await;
        })
    }

    /// Returns indices of synced+healthy BNs, ordered by health score (highest first).
    /// Falls back to all BNs if none are synced (single-BN mode logs a warning).
    #[tracing::instrument(name = "rvc.bn_manager.synced_indices", skip_all)]
    async fn synced_indices(&self) -> Vec<usize> {
        let sync_guard = self.sync_statuses.read().await;
        let health_guard = self.health_trackers.read().await;

        let mut synced: Vec<usize> =
            sync_guard.iter().enumerate().filter(|(_, s)| s.is_usable()).map(|(i, _)| i).collect();

        if synced.is_empty() {
            if self.clients.len() == 1 {
                warn!(
                    endpoint = self.clients[0].endpoint(),
                    "single BN is not synced, continuing with degraded service"
                );
            } else {
                warn!("no synced BNs available, falling back to all BNs");
            }
            synced = (0..self.clients.len()).collect();
        }

        // Filter out unhealthy BNs (unless it would leave none)
        let healthy: Vec<usize> =
            synced.iter().copied().filter(|&i| health_guard[i].is_healthy()).collect();

        let mut result = if healthy.is_empty() {
            warn!("all synced BNs are unhealthy, using all synced BNs");
            synced
        } else {
            healthy
        };

        // Sort by health score descending (highest score first)
        result.sort_by(|&a, &b| {
            health_guard[b]
                .score()
                .partial_cmp(&health_guard[a].score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        result
    }

    /// Query using the `First` strategy: try synced BNs in order, fail over on error.
    async fn query_first<'s, T, F>(&'s self, op_name: &str, op: F) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let strategy_span = tracing::info_span!(
            "rvc.bn.strategy.first",
            rvc.bn.strategy = "first",
            rvc.bn.tried = tracing::field::Empty,
        );
        if let Some(deadline) = self.overall_timeout {
            match tokio::time::timeout(
                deadline,
                self.query_first_inner(op_name, &op).instrument(strategy_span),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(BeaconError::HttpError(format!(
                    "{op_name}: overall deadline of {}s exceeded",
                    deadline.as_secs()
                ))),
            }
        } else {
            self.query_first_inner(op_name, &op).instrument(strategy_span).await
        }
    }

    async fn query_first_inner<'s, T, F>(&'s self, op_name: &str, op: &F) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let indices = self.synced_indices().await;
        let mut last_err = None;
        let mut tried: usize = 0;
        let mut failed_indices: Vec<usize> = Vec::new();

        for i in indices {
            let client = &self.clients[i];
            tried += 1;
            let attempt_span = tracing::info_span!(
                "rvc.bn.attempt",
                rvc.bn.url = %redact_url(client.endpoint()),
            );
            let start = tokio::time::Instant::now();
            match op(client).instrument(attempt_span).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    // Batch update: record success + all prior errors in one lock acquisition
                    {
                        let mut trackers = self.health_trackers.write().await;
                        for fi in &failed_indices {
                            trackers[*fi].record_error();
                        }
                        trackers[i].record_success(elapsed);
                    }
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = client.endpoint(),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded"
                    );
                    tracing::Span::current().record("rvc.bn.tried", tried);
                    return Ok(result);
                }
                Err(e) => {
                    failed_indices.push(i);
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

        // All failed — batch record errors
        if !failed_indices.is_empty() {
            let mut trackers = self.health_trackers.write().await;
            for fi in &failed_indices {
                trackers[*fi].record_error();
            }
        }

        tracing::Span::current().record("rvc.bn.tried", tried);
        Err(last_err.expect("at least one client exists"))
    }

    /// Query using the `Best` strategy: query synced BNs in parallel, pick best result.
    ///
    /// The `pick_best` function returns `true` if the first argument is better than the second.
    /// Falls back to `First` strategy if only one synced BN is available.
    /// When all synced BNs fail, falls back to trying unsynced BNs sequentially.
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
        let strategy_span = tracing::info_span!(
            "rvc.bn.strategy.best",
            rvc.bn.strategy = "best",
            rvc.bn.tried = tracing::field::Empty,
        );
        if let Some(deadline) = self.overall_timeout {
            match tokio::time::timeout(
                deadline,
                self.query_best_inner(op_name, &op, pick_best).instrument(strategy_span),
            )
            .await
            {
                Ok(result) => return result,
                Err(_) => {
                    return Err(BeaconError::HttpError(format!(
                        "{op_name}: overall deadline of {}s exceeded",
                        deadline.as_secs()
                    )))
                }
            }
        }
        self.query_best_inner(op_name, &op, pick_best).instrument(strategy_span).await
    }

    async fn query_best_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        op: &F,
        pick_best: fn(&T, &T) -> bool,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let indices = self.synced_indices().await;
        tracing::Span::current().record("rvc.bn.tried", indices.len());

        if indices.len() == 1 {
            let client = &self.clients[indices[0]];
            let i = indices[0];
            let attempt_span = tracing::info_span!(
                "rvc.bn.attempt",
                rvc.bn.url = %redact_url(client.endpoint()),
            );
            let start = tokio::time::Instant::now();
            match op(client).instrument(attempt_span).await {
                Ok(result) => {
                    self.health_trackers.write().await[i].record_success(start.elapsed());
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = client.endpoint(),
                        "query succeeded (single synced BN)"
                    );
                    return Ok(result);
                }
                Err(e) => {
                    self.health_trackers.write().await[i].record_error();
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = client.endpoint(),
                        error = %e,
                        "BN query failed, trying unsynced BNs"
                    );
                    return self.fallback_unsynced(op_name, &op, &indices).await.ok_or(e);
                }
            }
        }

        let mut futs: Vec<IndexedTimedResultFut<'_, T>> = Vec::with_capacity(indices.len());

        for i in &indices {
            let client = &self.clients[*i];
            let endpoint = client.endpoint().to_string();
            let idx = *i;
            let fut = op(client);
            let attempt_span = tracing::info_span!(
                "rvc.bn.attempt",
                rvc.bn.url = %redact_url(client.endpoint()),
            );
            futs.push(Box::pin(
                async move {
                    let start = tokio::time::Instant::now();
                    let result = fut.await;
                    let elapsed = start.elapsed();
                    (idx, endpoint, result, elapsed)
                }
                .instrument(attempt_span),
            ));
        }

        let results = join_all(futs).await;

        let mut best: Option<(usize, T)> = None;

        for (i, endpoint, result, elapsed) in results {
            match result {
                Ok(value) => {
                    self.health_trackers.write().await[i].record_success(elapsed);
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
                    self.health_trackers.write().await[i].record_error();
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
                if let Some(result) = self.fallback_unsynced(op_name, &op, &indices).await {
                    return Ok(result);
                }
                Err(BeaconError::HttpError(format!("{op_name}: all BNs failed in best-selection")))
            }
        }
    }

    /// Tries unsynced BNs sequentially as a fallback when all synced BNs have failed.
    async fn fallback_unsynced<'s, T, F>(
        &'s self,
        op_name: &str,
        op: &F,
        tried_indices: &[usize],
    ) -> Option<T>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let unsynced: Vec<usize> =
            (0..self.clients.len()).filter(|i| !tried_indices.contains(i)).collect();

        if unsynced.is_empty() {
            return None;
        }

        warn!(op = op_name, "all synced BNs failed, falling back to unsynced BNs");

        for i in unsynced {
            let client = &self.clients[i];
            let start = tokio::time::Instant::now();
            match op(client).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    self.health_trackers.write().await[i].record_success(elapsed);
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = client.endpoint(),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded on unsynced BN (degraded)"
                    );
                    return Some(result);
                }
                Err(e) => {
                    self.health_trackers.write().await[i].record_error();
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = client.endpoint(),
                        error = %e,
                        "unsynced BN fallback also failed"
                    );
                }
            }
        }

        None
    }

    /// Broadcast an operation to all BNs (regardless of sync status). Returns first success.
    /// If all fail, returns the last error.
    async fn broadcast<'s, F>(&'s self, op_name: &str, op: F) -> Result<(), BeaconError>
    where
        F: Fn(&'s BeaconClient) -> BoxFut<'s, ()>,
    {
        let strategy_span = tracing::info_span!(
            "rvc.bn.strategy.broadcast",
            rvc.bn.strategy = "broadcast",
            rvc.bn.tried = self.clients.len(),
        );
        if let Some(deadline) = self.overall_timeout {
            match tokio::time::timeout(
                deadline,
                self.broadcast_inner(op_name, &op).instrument(strategy_span),
            )
            .await
            {
                Ok(result) => return result,
                Err(_) => {
                    return Err(BeaconError::HttpError(format!(
                        "{op_name}: overall deadline of {}s exceeded",
                        deadline.as_secs()
                    )))
                }
            }
        }
        self.broadcast_inner(op_name, &op).instrument(strategy_span).await
    }

    async fn broadcast_inner<'s, F>(&'s self, op_name: &str, op: &F) -> Result<(), BeaconError>
    where
        F: Fn(&'s BeaconClient) -> BoxFut<'s, ()>,
    {
        let mut futs: Vec<IndexedTimedResultFut<'_, ()>> = Vec::with_capacity(self.clients.len());

        for (i, client) in self.clients.iter().enumerate() {
            let endpoint = client.endpoint().to_string();
            let fut = op(client);
            let attempt_span = tracing::info_span!(
                "rvc.bn.attempt",
                rvc.bn.url = %redact_url(client.endpoint()),
            );
            futs.push(Box::pin(
                async move {
                    let start = tokio::time::Instant::now();
                    let result = fut.await;
                    let elapsed = start.elapsed();
                    (i, endpoint, result, elapsed)
                }
                .instrument(attempt_span),
            ));
        }

        let results = join_all(futs).await;

        // Record health for ALL BNs first, then determine the result.
        let mut first_ok = false;
        let mut last_err = None;
        {
            let mut guard = self.health_trackers.write().await;
            for (i, endpoint, result, elapsed) in &results {
                match result {
                    Ok(()) => {
                        guard[*i].record_success(*elapsed);
                        debug!(
                            op = op_name,
                            bn_index = i,
                            endpoint = endpoint,
                            "broadcast succeeded on BN"
                        );
                        first_ok = true;
                    }
                    Err(e) => {
                        guard[*i].record_error();
                        warn!(
                            op = op_name,
                            bn_index = i,
                            endpoint = endpoint,
                            error = %e,
                            "broadcast failed on BN"
                        );
                    }
                }
            }
        }

        if first_ok {
            return Ok(());
        }

        for (_, _, result, _) in results {
            if let Err(e) = result {
                last_err = Some(e);
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
        let strategy_span = tracing::info_span!(
            "rvc.bn.strategy.broadcast",
            rvc.bn.strategy = "broadcast",
            rvc.bn.tried = self.clients.len(),
        );
        if let Some(deadline) = self.overall_timeout {
            match tokio::time::timeout(
                deadline,
                self.broadcast_with_result_inner(op_name, &op).instrument(strategy_span),
            )
            .await
            {
                Ok(result) => return result,
                Err(_) => {
                    return Err(BeaconError::HttpError(format!(
                        "{op_name}: overall deadline of {}s exceeded",
                        deadline.as_secs()
                    )))
                }
            }
        }
        self.broadcast_with_result_inner(op_name, &op).instrument(strategy_span).await
    }

    async fn broadcast_with_result_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        op: &F,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let mut futs: Vec<IndexedTimedResultFut<'_, T>> = Vec::with_capacity(self.clients.len());

        for (i, client) in self.clients.iter().enumerate() {
            let endpoint = client.endpoint().to_string();
            let fut = op(client);
            let attempt_span = tracing::info_span!(
                "rvc.bn.attempt",
                rvc.bn.url = %redact_url(client.endpoint()),
            );
            futs.push(Box::pin(
                async move {
                    let start = tokio::time::Instant::now();
                    let result = fut.await;
                    let elapsed = start.elapsed();
                    (i, endpoint, result, elapsed)
                }
                .instrument(attempt_span),
            ));
        }

        let results = join_all(futs).await;

        // Record health for ALL BNs first.
        {
            let mut guard = self.health_trackers.write().await;
            for (i, endpoint, result, elapsed) in &results {
                match result {
                    Ok(_) => {
                        guard[*i].record_success(*elapsed);
                        debug!(
                            op = op_name,
                            bn_index = i,
                            endpoint = endpoint,
                            "broadcast succeeded on BN"
                        );
                    }
                    Err(e) => {
                        guard[*i].record_error();
                        warn!(
                            op = op_name,
                            bn_index = i,
                            endpoint = endpoint,
                            error = %e,
                            "broadcast failed on BN"
                        );
                    }
                }
            }
        }

        // Return first success or last error.
        let mut last_err = None;
        for (_, _, result, _) in results {
            match result {
                Ok(v) => return Ok(v),
                Err(e) => last_err = Some(e),
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

    // -- Duties: query(First) + duty_fetch timeout --

    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        self.with_op_timeout(
            "get_attester_duties",
            self.op_timeout(|t| t.duty_fetch),
            self.query_first("get_attester_duties", |c| {
                Box::pin(c.get_attester_duties(epoch, validator_indices))
            }),
        )
        .await
    }

    async fn get_proposer_duties(&self, epoch: u64) -> Result<ProposerDutiesResponse, BeaconError> {
        self.with_op_timeout(
            "get_proposer_duties",
            self.op_timeout(|t| t.duty_fetch),
            self.query_first("get_proposer_duties", |c| Box::pin(c.get_proposer_duties(epoch))),
        )
        .await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.with_op_timeout(
            "post_sync_committee_duties",
            self.op_timeout(|t| t.duty_fetch),
            self.query_first("post_sync_committee_duties", |c| {
                Box::pin(c.post_sync_committee_duties(epoch, validator_indices))
            }),
        )
        .await
    }

    // -- Block production: query(Best) + block_production timeout --

    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.with_op_timeout(
            "produce_block_v3",
            self.op_timeout(|t| t.block_production),
            self.query_best(
                "produce_block_v3",
                |c| {
                    Box::pin(c.produce_block_v3(
                        slot,
                        randao_reveal,
                        graffiti,
                        builder_boost_factor,
                    ))
                },
                is_better_block,
            ),
        )
        .await
    }

    // -- Submissions: broadcast + block_publication timeout --

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "publish_block",
            self.op_timeout(|t| t.block_publication),
            self.broadcast("publish_block", |c| {
                Box::pin(c.publish_block(signed_block, consensus_version))
            }),
        )
        .await
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "publish_blinded_block",
            self.op_timeout(|t| t.block_publication),
            self.broadcast("publish_blinded_block", |c| {
                Box::pin(c.publish_blinded_block(signed_blinded_block, consensus_version))
            }),
        )
        .await
    }

    // -- Attestation data: query(First) + attestation_fetch timeout --

    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.with_op_timeout(
            "get_attestation_data",
            self.op_timeout(|t| t.attestation_fetch),
            self.query_first("get_attestation_data", |c| {
                Box::pin(c.get_attestation_data(slot, committee_index))
            }),
        )
        .await
    }

    // -- Attestation submission: broadcast + attestation_submit timeout --

    async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        self.with_op_timeout(
            "submit_attestation",
            self.op_timeout(|t| t.attestation_submit),
            self.broadcast_with_result("submit_attestation", |c| {
                Box::pin(c.submit_attestation(attestations))
            }),
        )
        .await
    }

    // -- Aggregation: query(First) + aggregate_fetch timeout for fetching, broadcast + aggregate_submit timeout for submitting --

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        self.with_op_timeout(
            "get_aggregate_attestation",
            self.op_timeout(|t| t.aggregate_fetch),
            self.query_first("get_aggregate_attestation", |c| {
                Box::pin(c.get_aggregate_attestation(slot, attestation_data_root, committee_index))
            }),
        )
        .await
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "submit_aggregate_and_proofs",
            self.op_timeout(|t| t.aggregate_submit),
            self.broadcast("submit_aggregate_and_proofs", |c| {
                Box::pin(c.submit_aggregate_and_proofs(proofs))
            }),
        )
        .await
    }

    // -- Sync committee: broadcast + sync_message/sync_contribution timeout --

    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "submit_sync_committee_messages",
            self.op_timeout(|t| t.sync_message),
            self.broadcast("submit_sync_committee_messages", |c| {
                Box::pin(c.submit_sync_committee_messages(messages))
            }),
        )
        .await
    }

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.with_op_timeout(
            "get_sync_committee_contribution",
            self.op_timeout(|t| t.sync_contribution),
            self.query_first("get_sync_committee_contribution", |c| {
                Box::pin(c.get_sync_committee_contribution(
                    slot,
                    subcommittee_index,
                    beacon_block_root,
                ))
            }),
        )
        .await
    }

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "submit_contribution_and_proofs",
            self.op_timeout(|t| t.sync_message),
            self.broadcast("submit_contribution_and_proofs", |c| {
                Box::pin(c.submit_contribution_and_proofs(proofs))
            }),
        )
        .await
    }

    // -- Blocks --

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        self.query_first("get_block_root", |c| Box::pin(c.get_block_root(block_id))).await
    }

    // -- Proposer preparation: broadcast + preparation timeout --

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "prepare_beacon_proposer",
            self.op_timeout(|t| t.preparation),
            self.broadcast("prepare_beacon_proposer", |c| {
                Box::pin(c.prepare_beacon_proposer(preparations))
            }),
        )
        .await
    }

    // -- Committee subscriptions: broadcast + preparation timeout --

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "submit_beacon_committee_subscriptions",
            self.op_timeout(|t| t.preparation),
            self.broadcast("submit_beacon_committee_subscriptions", |c| {
                Box::pin(c.submit_beacon_committee_subscriptions(subscriptions))
            }),
        )
        .await
    }

    // -- Builder: broadcast + preparation timeout --

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "register_validators",
            self.op_timeout(|t| t.preparation),
            self.broadcast("register_validators", |c| {
                Box::pin(c.register_validators(registrations))
            }),
        )
        .await
    }

    // -- Node status: query(First) --

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.query_first("get_node_syncing", |c| Box::pin(c.get_node_syncing())).await
    }

    async fn get_node_version(&self) -> Result<String, BeaconError> {
        self.query_first("get_node_version", |c| Box::pin(c.get_node_version())).await
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
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        self.submit_attestation(attestations).await
    }

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        self.get_aggregate_attestation(slot, attestation_data_root, committee_index).await
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
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

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.register_validators(registrations).await
    }

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.get_node_syncing().await
    }

    async fn get_node_version(&self) -> Result<String, BeaconError> {
        self.get_node_version().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::sync_status::BnSyncStatus;

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
        assert_eq!(result.unwrap().data.get("SECONDS_PER_SLOT").unwrap(), &json!("12"));
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
        let proofs = VersionedSignedAggregateAndProof::PreElectra(vec![]);
        let result = manager.submit_aggregate_and_proofs(&proofs).await;
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
        let proofs = VersionedSignedAggregateAndProof::PreElectra(vec![]);
        let result = manager.submit_aggregate_and_proofs(&proofs).await;
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
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
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
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
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
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
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
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };
        assert!(!is_better_block(&a, &b));
    }

    // ===================================================================
    // Sync status integration tests
    // ===================================================================

    const SYNCED_RESPONSE: &str = r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#;
    const SYNCING_SYNCING_RESPONSE: &str = r#"{"data":{"head_slot":"500","sync_distance":"500","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;

    #[tokio::test]
    async fn test_sync_check_sync_status_marks_synced() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());
        manager.check_sync_status().await;

        let guard = manager.sync_statuses().read().await;
        assert_eq!(guard[0], BnSyncStatus::Synced);
    }

    #[tokio::test]
    async fn test_sync_check_sync_status_marks_syncing() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());
        manager.check_sync_status().await;

        let guard = manager.sync_statuses().read().await;
        assert_eq!(guard[0], BnSyncStatus::Syncing);
    }

    #[tokio::test]
    async fn test_sync_check_sync_status_marks_unreachable() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());
        manager.check_sync_status().await;

        let guard = manager.sync_statuses().read().await;
        assert_eq!(guard[0], BnSyncStatus::Unreachable);
    }

    #[tokio::test]
    async fn test_sync_query_first_skips_unsynced_bn() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        // Primary: syncing, has genesis endpoint
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&primary)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(0) // Should NOT be called because primary is syncing
            .mount(&primary)
            .await;

        // Secondary: synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&secondary)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&secondary)
            .await;

        let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
        manager.check_sync_status().await;

        let result = manager.get_genesis().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data.genesis_time, "1606824023");
    }

    #[tokio::test]
    async fn test_sync_query_first_falls_back_when_all_unsynced() {
        let primary = MockServer::start().await;

        // Syncing but still the only BN — should be used with warning
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&primary)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&primary)
            .await;

        let manager = make_manager(&primary.uri());
        manager.check_sync_status().await;

        // Should still work despite syncing status (single-BN fallback)
        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sync_query_best_skips_unsynced_bn() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // BN1: syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "9999")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .expect(0) // Should NOT be called
            .mount(&bn1)
            .await;

        // BN2: synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn2)
            .await;

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
        manager.check_sync_status().await;

        let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().execution_payload_value, Some("5000".to_string()));
    }

    #[tokio::test]
    async fn test_sync_broadcast_sends_to_all_regardless_of_sync_status() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // BN1: syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&bn1)
            .await;

        // BN2: synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn2)
            .await;

        // Both should receive the broadcast
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
        manager.check_sync_status().await;

        let result = manager.prepare_beacon_proposer(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sync_start_sync_monitor() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = manager.start_sync_monitor(Some(Duration::from_millis(50)), shutdown_rx);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let guard = manager.sync_statuses().read().await;
        assert_eq!(guard[0], BnSyncStatus::Synced);
        drop(guard);

        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_sync_multi_bn_all_unsynced_falls_back_to_all() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // Both syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&bn2)
            .await;

        // BN1 fails genesis, BN2 succeeds — tests that fallback tries all
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        manager.check_sync_status().await;

        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sync_query_best_falls_back_to_unsynced_when_synced_fail() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // BN1: synced but block production fails
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .expect(1)
            .mount(&bn1)
            .await;

        // BN2: syncing but block production works
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_SYNCING_RESPONSE))
            .mount(&bn2)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "7000")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        manager.check_sync_status().await;

        // BN1 (synced) fails, should fall back to BN2 (unsynced)
        let result = manager.produce_block_v3(1, "0xrandao", None, None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().execution_payload_value, Some("7000".to_string()));
    }

    #[tokio::test]
    async fn test_sync_initial_status_is_unknown() {
        // Before any sync check, all BNs default to Unknown
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());

        let guard = manager.sync_statuses().read().await;
        assert_eq!(guard[0], BnSyncStatus::Unknown);
        drop(guard);

        // Without calling check_sync_status, BN should still be tried via fallback
        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    // ===================================================================
    // Health scoring tests
    // ===================================================================

    #[tokio::test]
    async fn test_health_scores_tracked_after_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());
        let _ = manager.get_genesis().await.unwrap();

        let scores = manager.health_scores().await;
        assert_eq!(scores.len(), 1);
        assert!(scores[0].latency_ms > 0.0, "latency should be recorded");
        assert_eq!(scores[0].error_rate, 0.0);
        assert!(scores[0].score > 0.5, "score should be high after success");
    }

    #[tokio::test]
    async fn test_health_scores_tracked_after_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());
        let _ = manager.get_genesis().await;

        let scores = manager.health_scores().await;
        assert_eq!(scores[0].error_rate, 1.0);
        assert!(scores[0].score < 0.5, "score should be low after error");
    }

    #[tokio::test]
    async fn test_health_scores_tracked_in_broadcast() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&bn1)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/prepare_beacon_proposer"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let _ = manager.prepare_beacon_proposer(&[]).await;

        let scores = manager.health_scores().await;
        // BN1 succeeded
        assert_eq!(scores[0].error_rate, 0.0);
        // BN2 failed
        assert_eq!(scores[1].error_rate, 1.0);
    }

    #[tokio::test]
    async fn test_health_healthy_bn_preferred_in_failover() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // Both synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        manager.check_sync_status().await;

        // Degrade BN1 health by recording errors
        {
            let mut guard = manager.health_trackers().write().await;
            for _ in 0..50 {
                guard[0].record_error();
            }
            // BN2 is healthy — record successes
            for _ in 0..50 {
                guard[1].record_success(Duration::from_millis(10));
            }
        }

        // BN2 should be tried first (higher score) due to health ordering
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&bn2)
            .await;

        // BN1 should NOT be called (BN2 succeeds first)
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(0)
            .mount(&bn1)
            .await;

        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_unhealthy_bn_excluded() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // Both synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        manager.check_sync_status().await;

        // Make BN1 unhealthy (100% error rate → score=0.2, below 0.2 threshold)
        {
            let mut guard = manager.health_trackers().write().await;
            for _ in 0..100 {
                guard[0].record_error();
            }
            // BN2 is healthy
            for _ in 0..10 {
                guard[1].record_success(Duration::from_millis(50));
            }
        }

        // Only BN2 should be called
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&bn2)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(0)
            .mount(&bn1)
            .await;

        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_recovery_readds_bn() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // Both synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        manager.check_sync_status().await;

        // Make BN1 unhealthy
        {
            let mut guard = manager.health_trackers().write().await;
            for _ in 0..100 {
                guard[0].record_error();
            }
            for _ in 0..10 {
                guard[1].record_success(Duration::from_millis(50));
            }
        }

        // Verify BN1 is excluded
        let guard = manager.health_trackers().read().await;
        assert!(!guard[0].is_healthy());
        drop(guard);

        // Now recover BN1 by adding many successes
        {
            let mut guard = manager.health_trackers().write().await;
            for _ in 0..100 {
                guard[0].record_success(Duration::from_millis(20));
            }
        }

        // BN1 should be healthy again
        let guard = manager.health_trackers().read().await;
        assert!(guard[0].is_healthy());
        drop(guard);

        // BN1 (now recovered & low latency) should have higher score than BN2
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(1)
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .expect(0)
            .mount(&bn2)
            .await;

        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_all_unhealthy_falls_back_to_all() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // Both synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        manager.check_sync_status().await;

        // Make both unhealthy
        {
            let mut guard = manager.health_trackers().write().await;
            for _ in 0..100 {
                guard[0].record_error();
                guard[1].record_error();
            }
        }

        // Should still work despite both being unhealthy (fallback to all)
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .mount(&bn1)
            .await;

        let result = manager.get_genesis().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_scores_accumulate_over_operations() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());

        // Multiple operations should update EMA
        for _ in 0..5 {
            let _ = manager.get_genesis().await.unwrap();
        }

        let scores = manager.health_scores().await;
        assert!(scores[0].latency_ms > 0.0);
        assert_eq!(scores[0].error_rate, 0.0);
        assert!(scores[0].score > 0.9, "should be very healthy after 5 successes");
    }

    #[tokio::test]
    async fn test_health_best_strategy_records_health() {
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;

        // BN1 returns lower value block
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "1000")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .mount(&bn1)
            .await;

        // BN2 returns higher value block
        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(ResponseTemplate::new(200)
                .insert_header("Eth-Consensus-Version", "deneb")
                .insert_header("Eth-Execution-Payload-Blinded", "false")
                .insert_header("Eth-Execution-Payload-Value", "5000")
                .set_body_string(r#"{"data":{"slot":"1","proposer_index":"0","parent_root":"0x00","state_root":"0x00","body":{}}}"#))
            .mount(&bn2)
            .await;

        let manager = make_multi_manager(&[&bn1.uri(), &bn2.uri()]);
        let _ = manager.produce_block_v3(1, "0xrandao", None, None).await.unwrap();

        // Both BNs should have health recorded
        let scores = manager.health_scores().await;
        assert!(scores[0].latency_ms > 0.0, "BN1 latency should be tracked");
        assert!(scores[1].latency_ms > 0.0, "BN2 latency should be tracked");
        assert_eq!(scores[0].error_rate, 0.0);
        assert_eq!(scores[1].error_rate, 0.0);
    }

    // -- get_node_version tests --

    #[tokio::test]
    async fn test_get_node_version_via_trait() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"version":"Lighthouse/v7.1.0-a1b2c3d/x86_64-linux"}}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = beacon::BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();
        let dyn_client: &dyn BeaconNodeClient = &client;
        let version = dyn_client.get_node_version().await.unwrap();
        assert_eq!(version, "Lighthouse/v7.1.0-a1b2c3d/x86_64-linux");
    }

    #[tokio::test]
    async fn test_get_node_version_bn_manager_delegates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"data":{"version":"Prysm/v5.0.0/linux-amd64"}}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let manager = make_manager(&mock_server.uri());
        let version = manager.get_node_version().await.unwrap();
        assert_eq!(version, "Prysm/v5.0.0/linux-amd64");
    }

    #[tokio::test]
    async fn test_get_node_version_failover() {
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&primary)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&secondary)
            .await;

        // Primary fails
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(500).set_body_string("error"))
            .expect(1)
            .mount(&primary)
            .await;

        // Secondary succeeds
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"data":{"version":"Teku/v24.0.0"}}"#),
            )
            .expect(1)
            .mount(&secondary)
            .await;

        let manager = make_multi_manager(&[&primary.uri(), &secondary.uri()]);
        let version = manager.get_node_version().await.unwrap();
        assert_eq!(version, "Teku/v24.0.0");
    }

    #[tokio::test]
    async fn test_overall_deadline_fires_when_all_bns_slow() {
        let server = MockServer::start().await;

        // Both syncing + version respond normally for setup
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "head_slot": "100", "sync_distance": "0", "is_syncing": false, "is_optimistic": false, "el_offline": false }
            })))
            .mount(&server)
            .await;

        // Genesis responds slowly — longer than deadline
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "data": {
                            "genesis_time": "1606824023",
                            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "genesis_fork_version": "0x00000000"
                        }
                    }))
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;

        let config = BnManagerConfig::new(vec![server.uri()]);
        let manager =
            BnManager::new(config).unwrap().with_overall_timeout(Duration::from_millis(200));

        // Mark BN as synced so query_first is used
        {
            let mut statuses = manager.sync_statuses().write().await;
            statuses[0] = BnSyncStatus::Synced;
        }

        let result = manager.get_genesis().await;
        assert!(result.is_err(), "Should timeout when BN is slower than overall deadline");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("deadline") || err_msg.contains("timed out"),
            "Error should mention deadline/timeout, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_no_overall_deadline_by_default() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "head_slot": "100", "sync_distance": "0", "is_syncing": false, "is_optimistic": false, "el_offline": false }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": "1606824023",
                    "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(&server)
            .await;

        let config = BnManagerConfig::new(vec![server.uri()]);
        let manager = BnManager::new(config).unwrap();

        // No overall_timeout set — should default to None
        {
            let mut statuses = manager.sync_statuses().write().await;
            statuses[0] = BnSyncStatus::Synced;
        }

        let result = manager.get_genesis().await;
        assert!(result.is_ok(), "Should succeed without overall deadline");
    }

    #[tokio::test]
    async fn test_health_scores_reflect_sync_status_synced() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());

        // Set sync status to Synced
        {
            let mut statuses = manager.sync_statuses().write().await;
            statuses[0] = BnSyncStatus::Synced;
        }

        let scores = manager.health_scores().await;
        assert_eq!(scores.len(), 1);
        assert!(scores[0].is_reachable);
        assert!(scores[0].is_synced);
    }

    #[tokio::test]
    async fn test_health_scores_reflect_sync_status_syncing() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());

        // Set sync status to Syncing
        {
            let mut statuses = manager.sync_statuses().write().await;
            statuses[0] = BnSyncStatus::Syncing;
        }

        let scores = manager.health_scores().await;
        assert!(scores[0].is_reachable);
        assert!(!scores[0].is_synced);
    }

    #[tokio::test]
    async fn test_health_scores_reflect_sync_status_unreachable() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());

        // Set sync status to Unreachable
        {
            let mut statuses = manager.sync_statuses().write().await;
            statuses[0] = BnSyncStatus::Unreachable;
        }

        let scores = manager.health_scores().await;
        assert!(!scores[0].is_reachable);
        assert!(!scores[0].is_synced);
    }

    #[tokio::test]
    async fn test_health_scores_reflect_sync_status_unknown() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(GENESIS_RESPONSE))
            .mount(&server)
            .await;

        let manager = make_manager(&server.uri());
        // Default is Unknown — don't set anything

        let scores = manager.health_scores().await;
        // Unknown is not unreachable (we don't know), but not synced either
        assert!(scores[0].is_reachable);
        assert!(!scores[0].is_synced);
    }

    // -- Per-operation timeout tests --

    #[tokio::test]
    async fn test_operation_timeout_fires_on_slow_bn() {
        let server = MockServer::start().await;

        // Simulate a slow BN: 10s delay on attestation data endpoint
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"{"data":{"slot":"1","index":"0","beacon_block_root":"0x0000000000000000000000000000000000000000000000000000000000000000","source":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"}}}"#,
                    )
                    .set_delay(Duration::from_secs(10)),
            )
            .mount(&server)
            .await;

        let config = BnManagerConfig::new(vec![server.uri()]);
        let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
            attestation_fetch: Duration::from_millis(100),
            ..OperationTimeouts::default()
        });

        let start = tokio::time::Instant::now();
        let result = manager.get_attestation_data(1, 0).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, BeaconError::OperationTimeout { operation, timeout }
                if operation == "get_attestation_data" && *timeout == Duration::from_millis(100)),
            "expected OperationTimeout, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "should have timed out quickly, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_no_operation_timeout_completes_normally() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/attestation_data"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"{"data":{"slot":"1","index":"0","beacon_block_root":"0x0000000000000000000000000000000000000000000000000000000000000000","source":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},"target":{"epoch":"0","root":"0x0000000000000000000000000000000000000000000000000000000000000000"}}}"#,
                ),
            )
            .mount(&server)
            .await;

        // No operation_timeouts set
        let manager = make_manager(&server.uri());

        let result = manager.get_attestation_data(1, 0).await;
        assert!(result.is_ok(), "should succeed without per-op timeout: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_operation_timeout_on_block_production() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v3/validator/blocks/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"{"version":"deneb","execution_payload_blinded":false,"execution_payload_value":"0","consensus_block_value":"0","data":{}}"#,
                    )
                    .set_delay(Duration::from_secs(10)),
            )
            .mount(&server)
            .await;

        let config = BnManagerConfig::new(vec![server.uri()]);
        let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
            block_production: Duration::from_millis(100),
            ..OperationTimeouts::default()
        });

        let result = manager.produce_block_v3(1, "0xabc", None, None).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), BeaconError::OperationTimeout { operation, .. } if operation == "produce_block_v3"),
        );
    }

    #[tokio::test]
    async fn test_operation_timeout_on_duty_fetch() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"{"dependent_root":"0x0000000000000000000000000000000000000000000000000000000000000000","execution_optimistic":false,"data":[]}"#,
                    )
                    .set_delay(Duration::from_secs(10)),
            )
            .mount(&server)
            .await;

        let config = BnManagerConfig::new(vec![server.uri()]);
        let manager = BnManager::new(config).unwrap().with_operation_timeouts(OperationTimeouts {
            duty_fetch: Duration::from_millis(100),
            ..OperationTimeouts::default()
        });

        let result = manager.get_proposer_duties(1).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), BeaconError::OperationTimeout { operation, .. } if operation == "get_proposer_duties"),
        );
    }
}
