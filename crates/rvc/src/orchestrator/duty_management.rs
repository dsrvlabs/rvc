use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use beacon::{BeaconCommitteeSubscription, ProposerPreparation};
use bn_manager::BeaconNodeClient;
use duty_tracker::DutyTracker;
use metrics::definitions::RVC_DUTY_REORG_DETECTED_TOTAL;
use signer::{is_aggregator, SignerService};
use timing::{SlotClock, SLOTS_PER_EPOCH};

use super::coordinator::{OrchestratorConfig, PubkeyMap};
use super::utils;

/// Number of epochs in a single sync committee period.
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

/// How many epochs before the end of a period to start prefetching next-period duties.
const PREFETCH_LOOKAHEAD: u64 = 2;

pub(crate) struct DutyManagementService<C: SlotClock + 'static> {
    clock: Arc<C>,
    signer: Arc<SignerService>,
    beacon: Arc<dyn BeaconNodeClient>,
    duty_tracker: Arc<DutyTracker>,
    validator_store: Arc<validator_store::ValidatorStore>,
    pubkey_map: PubkeyMap,
    config: OrchestratorConfig,
    /// Tracks which sync committee periods have been prefetched to ensure idempotency.
    prefetched_periods: RwLock<HashSet<u64>>,
}

impl<C: SlotClock + 'static> DutyManagementService<C> {
    pub(crate) fn new(
        clock: Arc<C>,
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        duty_tracker: Arc<DutyTracker>,
        validator_store: Arc<validator_store::ValidatorStore>,
        pubkey_map: PubkeyMap,
        config: OrchestratorConfig,
    ) -> Self {
        Self {
            clock,
            signer,
            beacon,
            duty_tracker,
            validator_store,
            pubkey_map,
            config,
            prefetched_periods: RwLock::new(HashSet::new()),
        }
    }

    #[tracing::instrument(name = "rvc.orchestrator.fetch_epoch_duties", skip_all, fields(rvc.epoch = epoch))]
    pub(crate) async fn fetch_epoch_duties(&self, epoch: u64) {
        // Evict old caches to prevent unbounded growth
        self.duty_tracker.evict_old_caches(epoch).await;

        // Attester duties
        if !self.duty_tracker.is_epoch_cached(epoch).await {
            debug!(epoch, "Fetching attester duties for epoch");
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_duties_for_epoch(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch attester duties"),
                Err(_) => warn!(
                    epoch,
                    "Attester duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        // Proposer duties
        if !self.duty_tracker.is_proposer_epoch_cached(epoch).await {
            debug!(epoch, "Fetching proposer duties for epoch");
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_proposer_duties(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch proposer duties"),
                Err(_) => warn!(
                    epoch,
                    "Proposer duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        // Sync committee duties (at period boundaries)
        if !self.duty_tracker.is_sync_period_cached(epoch).await {
            debug!(epoch, "Fetching sync committee duties");
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.fetch_sync_committee_duties(epoch),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(epoch, error = %e, "Failed to fetch sync committee duties"),
                Err(_) => warn!(
                    epoch,
                    "Sync committee duty fetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                ),
            }
        }

        let (attester_count, proposer_count, sync_count) =
            self.duty_tracker.cached_duty_counts(epoch).await;
        debug!(epoch, attester_count, proposer_count, sync_count, "Duty counts for epoch");

        // Prefetch next-period sync committee duties when approaching period boundary.
        self.maybe_prefetch_next_sync_period(epoch).await;
    }

    /// Prefetches sync committee duties for the next period when within the last
    /// `PREFETCH_LOOKAHEAD` epochs of the current period.
    ///
    /// Uses a `HashSet<Period>` guard to ensure the fetch and subscription submission
    /// happen at most once per period even if called multiple times in the lookahead window.
    async fn maybe_prefetch_next_sync_period(&self, current_epoch: u64) {
        let pos = current_epoch % EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        if pos < EPOCHS_PER_SYNC_COMMITTEE_PERIOD - PREFETCH_LOOKAHEAD {
            return;
        }

        let next_period = current_epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD + 1;
        let next_period_first_epoch = next_period * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

        // Idempotency: skip if this period has already been successfully prefetched.
        {
            let guard = self.prefetched_periods.read().await;
            if guard.contains(&next_period) {
                debug!(
                    current_epoch,
                    next_period, "Sync committee prefetch already done for period"
                );
                return;
            }
        }

        debug!(
            current_epoch,
            next_period, next_period_first_epoch, "Prefetching next-period sync committee duties"
        );

        match tokio::time::timeout(
            self.config.timeouts.duty_fetch,
            self.duty_tracker.fetch_sync_committee_duties(next_period_first_epoch),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(
                    next_period,
                    next_period_first_epoch, "Prefetched sync committee duties for next period"
                );
            }
            Ok(Err(e)) => {
                warn!(
                    next_period,
                    next_period_first_epoch,
                    error = %e,
                    "Failed to prefetch sync committee duties for next period"
                );
                return;
            }
            Err(_) => {
                warn!(
                    next_period,
                    next_period_first_epoch,
                    "Sync committee duty prefetch timed out after {}s",
                    self.config.timeouts.duty_fetch.as_secs()
                );
                return;
            }
        }

        // Submit subnet subscriptions for the first epoch of the next period so the
        // BN subscribes to the correct subnets before the period starts.
        self.submit_committee_subscriptions(next_period_first_epoch).await;

        // Mark as prefetched only after a successful fetch so failures are retried.
        self.prefetched_periods.write().await.insert(next_period);
    }

    #[tracing::instrument(name = "rvc.orchestrator.check_reorg", skip_all, fields(rvc.epoch = current_epoch))]
    pub(crate) async fn check_reorg_at_epoch_boundary(&self, current_epoch: u64) {
        for epoch in [current_epoch, current_epoch + 1] {
            let attester_cached = self.duty_tracker.is_epoch_cached(epoch).await;
            let old_attester_root = self.duty_tracker.get_cached_dependent_root(epoch).await;
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.check_and_refetch_if_root_changed(epoch),
            )
            .await
            {
                Ok(Ok(true)) if attester_cached => {
                    let new_root = self.duty_tracker.get_cached_dependent_root(epoch).await;
                    warn!(
                        epoch,
                        old_head = ?old_attester_root,
                        new_head = ?new_root,
                        "Reorg detected: attester duties refetched"
                    );
                    RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["attester"]).inc();
                }
                Ok(Ok(true)) => {
                    debug!(epoch, "Attester duties fetched (was uncached)");
                }
                Ok(Ok(false)) => {}
                Ok(Err(e)) => {
                    warn!(epoch, error = %e, "Failed to check attester dependent root");
                }
                Err(_) => {
                    warn!(
                        epoch,
                        "Attester reorg check timed out after {}s",
                        self.config.timeouts.duty_fetch.as_secs()
                    );
                }
            }

            let proposer_cached = self.duty_tracker.is_proposer_epoch_cached(epoch).await;
            let old_proposer_root =
                self.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
            match tokio::time::timeout(
                self.config.timeouts.duty_fetch,
                self.duty_tracker.check_and_refetch_proposer_if_root_changed(epoch),
            )
            .await
            {
                Ok(Ok(true)) if proposer_cached => {
                    let new_root =
                        self.duty_tracker.get_cached_proposer_dependent_root(epoch).await;
                    warn!(
                        epoch,
                        old_head = ?old_proposer_root,
                        new_head = ?new_root,
                        "Reorg detected: proposer duties refetched"
                    );
                    RVC_DUTY_REORG_DETECTED_TOTAL.with_label_values(&["proposer"]).inc();
                }
                Ok(Ok(true)) => {
                    debug!(epoch, "Proposer duties fetched (was uncached)");
                }
                Ok(Ok(false)) => {}
                Ok(Err(e)) => {
                    warn!(epoch, error = %e, "Failed to check proposer dependent root");
                }
                Err(_) => {
                    warn!(
                        epoch,
                        "Proposer reorg check timed out after {}s",
                        self.config.timeouts.duty_fetch.as_secs()
                    );
                }
            }
        }
    }

    #[tracing::instrument(name = "rvc.orchestrator.prepare_proposers", skip_all)]
    pub(crate) async fn prepare_proposers(&self) {
        let mut preparations = Vec::new();

        let pubkey_snapshot = self.pubkey_map.read().clone();
        for (pubkey_hex, pubkey) in &pubkey_snapshot {
            let fee_recipient = self.validator_store.effective_fee_recipient(&pubkey.to_bytes());
            let fee_recipient_hex = format!("0x{}", hex::encode(fee_recipient));

            // We need the validator_index. Look it up from cached attester duties.
            // Iterate over current and next epoch slots to find a duty with this pubkey.
            let normalized = utils::normalize_pubkey(pubkey_hex);
            let mut found_index = None;

            if let Ok(current_slot) = self.clock.current_slot() {
                let current_epoch = current_slot / SLOTS_PER_EPOCH;
                for epoch in [current_epoch, current_epoch + 1] {
                    for slot_offset in 0..SLOTS_PER_EPOCH {
                        let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
                        let duties = self.duty_tracker.get_duties_for_slot(slot).await;
                        for duty in &duties {
                            if utils::normalize_pubkey(&duty.pubkey) == normalized {
                                found_index = Some(duty.validator_index.clone());
                                break;
                            }
                        }
                        if found_index.is_some() {
                            break;
                        }
                    }
                    if found_index.is_some() {
                        break;
                    }
                }
            }

            if let Some(validator_index) = found_index {
                preparations.push(ProposerPreparation {
                    validator_index,
                    fee_recipient: fee_recipient_hex,
                });
            } else {
                debug!(pubkey = %pubkey_hex, "No validator index found for proposer preparation");
            }
        }

        if preparations.is_empty() {
            return;
        }

        let count = preparations.len();
        match tokio::time::timeout(
            self.config.timeouts.preparation,
            self.beacon.prepare_beacon_proposer(&preparations),
        )
        .await
        {
            Ok(Ok(_)) => info!(count, "Sent proposer preparations"),
            Ok(Err(e)) => warn!(error = %e, "Failed to send proposer preparations"),
            Err(_) => {
                warn!(
                    "Proposer preparation timed out after {}s",
                    self.config.timeouts.preparation.as_secs()
                )
            }
        }
    }

    #[tracing::instrument(name = "rvc.orchestrator.submit_committee_subscriptions", skip_all, fields(rvc.epoch = epoch))]
    pub(crate) async fn submit_committee_subscriptions(&self, epoch: u64) {
        let mut subscriptions = Vec::new();
        let pubkey_snapshot = self.pubkey_map.read().clone();

        for slot_offset in 0..SLOTS_PER_EPOCH {
            let slot = epoch * SLOTS_PER_EPOCH + slot_offset;
            let duties = self.duty_tracker.get_duties_for_slot(slot).await;

            for duty in &duties {
                // Only subscribe for our own validators
                let normalized = utils::normalize_pubkey(&duty.pubkey);
                let pubkey =
                    pubkey_snapshot.iter().find(|(k, _)| utils::normalize_pubkey(k) == normalized);

                let pubkey = match pubkey {
                    Some((_, pk)) => pk.clone(),
                    None => continue,
                };

                let committee_length: u64 = match duty.committee_length.parse() {
                    Ok(cl) => cl,
                    Err(_) => {
                        warn!(
                            validator_index = %duty.validator_index,
                            "Invalid committee_length in duty: {}",
                            duty.committee_length
                        );
                        continue;
                    }
                };

                // Compute selection proof and determine if aggregator
                let selection_proof = match self
                    .signer
                    .sign_selection_proof(
                        slot,
                        &pubkey,
                        &self.config.fork_schedule,
                        &self.config.genesis_validators_root,
                    )
                    .await
                {
                    Ok(sig) => sig,
                    Err(e) => {
                        warn!(
                            validator_index = %duty.validator_index,
                            slot,
                            error = %e,
                            "Failed to sign selection proof for subscription"
                        );
                        continue;
                    }
                };

                let is_agg = is_aggregator(committee_length, &selection_proof.to_bytes());

                subscriptions.push(BeaconCommitteeSubscription {
                    validator_index: duty.validator_index.clone(),
                    committee_index: duty.committee_index.clone(),
                    committees_at_slot: duty.committees_at_slot.clone(),
                    slot: duty.slot.clone(),
                    is_aggregator: is_agg,
                });
            }
        }

        if subscriptions.is_empty() {
            return;
        }

        let count = subscriptions.len();
        match tokio::time::timeout(
            self.config.timeouts.preparation,
            self.beacon.submit_beacon_committee_subscriptions(&subscriptions),
        )
        .await
        {
            Ok(Ok(_)) => info!(count, epoch, "Sent committee subscriptions"),
            Ok(Err(e)) => warn!(epoch, error = %e, "Failed to send committee subscriptions"),
            Err(_) => warn!(
                epoch,
                "Committee subscription timed out after {}s",
                self.config.timeouts.preparation.as_secs()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use beacon::{BeaconClient, BeaconClientConfig};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use duty_tracker::DutyTracker;
    use eth_types::ForkSchedule;
    use signer::SignerService;
    use slashing::SlashingDb;
    use timing::MockSlotClock;
    use validator_store::ValidatorStore;

    use super::*;
    use crate::orchestrator::coordinator::OrchestratorConfig;

    // EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256.
    // Period 0 spans epochs 0..=255; period 1 spans epochs 256..=511.
    // Lookahead window within period 0: epochs 254 and 255.
    const PERIOD: u64 = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

    fn make_fork_schedule() -> Arc<ForkSchedule> {
        Arc::new(ForkSchedule {
            genesis_fork_version: [0, 0, 0, 1],
            altair_fork_epoch: 0,
            altair_fork_version: [0, 0, 0, 2],
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: [0, 0, 0, 3],
            capella_fork_epoch: 0,
            capella_fork_version: [0, 0, 0, 4],
            deneb_fork_epoch: 0,
            deneb_fork_version: [0, 0, 0, 5],
            electra_fork_epoch: 0,
            electra_fork_version: [0, 0, 0, 6],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [0, 0, 0, 7],
        })
    }

    fn make_config() -> OrchestratorConfig {
        OrchestratorConfig::new([0xaa; 32], make_fork_schedule())
    }

    fn sync_duties_response() -> serde_json::Value {
        serde_json::json!({
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
                "validator_index": 1,
                "validator_sync_committee_indices": ["0"]
            }]
        })
    }

    async fn build_service_no_validators(beacon_url: &str) -> DutyManagementService<MockSlotClock> {
        let beacon_config = BeaconClientConfig::new(beacon_url)
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(1);
        let beacon =
            Arc::new(BeaconClient::new(beacon_config).unwrap()) as Arc<dyn BeaconNodeClient>;
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let clock = Arc::new(MockSlotClock::new(1606824023, Duration::from_secs(12), 0));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        DutyManagementService::new(
            clock,
            signer,
            beacon,
            duty_tracker,
            validator_store,
            pubkey_map,
            make_config(),
        )
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_prefetch_fires_in_last_2_epochs (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// Prefetch fires for epoch PERIOD-2 (pos = 254 = PERIOD - 2).
    #[tokio::test]
    async fn test_prefetch_fires_in_last_2_epochs() {
        let server = MockServer::start().await;
        // Must be called exactly once for the next period's first epoch
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        // epoch PERIOD-2 is the second-to-last epoch of period 0
        service.maybe_prefetch_next_sync_period(PERIOD - 2).await;
        // wiremock asserts expect(1) on drop
    }

    /// Prefetch also fires for epoch PERIOD-1 (pos = 255 = PERIOD - 1).
    #[tokio::test]
    async fn test_prefetch_fires_at_last_epoch_of_period() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
    }

    /// Prefetch does NOT fire when outside the lookahead window (pos < PERIOD - 2).
    #[tokio::test]
    async fn test_prefetch_outside_window_does_not_fire() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(0)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        // epoch PERIOD-3: pos = 253 < 254 → must NOT fire
        service.maybe_prefetch_next_sync_period(PERIOD - 3).await;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_prefetch_retries_on_transient_failure (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// After a transient fetch failure at PERIOD_END-1 the period is NOT marked as
    /// prefetched, so the next call succeeds and duties become available.
    #[tokio::test]
    async fn test_prefetch_retries_on_transient_failure() {
        let server = MockServer::start().await;

        // First call: 500 → failure (up_to_n_times(1) so only the first request fails)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(500).set_body_string("transient"))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Second call: 200 → success
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        // max_retries(0) so the beacon client does NOT auto-retry 5xx; this lets us
        // simulate a transient failure at the DutyManagementService level.
        let beacon_config = BeaconClientConfig::new(server.uri())
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(0);
        let beacon_client =
            Arc::new(BeaconClient::new(beacon_config).unwrap()) as Arc<dyn BeaconNodeClient>;
        let duty_tracker = Arc::new(DutyTracker::new(beacon_client.clone(), vec!["1".to_string()]));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));
        let clock = Arc::new(MockSlotClock::new(1606824023, Duration::from_secs(12), 0));
        let pubkey_map = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));
        let service = DutyManagementService::new(
            clock,
            signer,
            beacon_client,
            duty_tracker.clone(),
            validator_store,
            pubkey_map,
            make_config(),
        );

        // First attempt at PERIOD-1: fails
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
        assert!(
            duty_tracker.get_sync_committee_duties(PERIOD * SLOTS_PER_EPOCH).await.is_empty(),
            "duties must be empty after transient failure"
        );

        // Second attempt: must succeed because period is NOT in prefetched_periods
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
        assert!(
            !duty_tracker.get_sync_committee_duties(PERIOD * SLOTS_PER_EPOCH).await.is_empty(),
            "duties must be present after successful retry"
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_prefetch_idempotent (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// Calling prefetch twice in the window issues the BN request only once.
    #[tokio::test]
    async fn test_prefetch_idempotent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;

        // Two calls in the lookahead window — BN endpoint must only be hit once
        service.maybe_prefetch_next_sync_period(PERIOD - 2).await;
        service.maybe_prefetch_next_sync_period(PERIOD - 1).await;
        // wiremock asserts expect(1) on drop
    }

    // ──────────────────────────────────────────────────────────────────────────
    // test_subnet_subscriptions_submitted_in_window (RED → GREEN)
    // ──────────────────────────────────────────────────────────────────────────

    /// When attester duties for the next period's first epoch are in the cache,
    /// `submit_committee_subscriptions` is invoked as part of the prefetch window.
    #[tokio::test]
    async fn test_subnet_subscriptions_submitted_in_window() {
        let server = MockServer::start().await;

        let validator_index = "42";
        // Use the hex of the real secret key; registered in the pubkey_map below.
        // We generate the secret key first and then set up the mock with its pubkey hex.
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        // Sync committee duties for the next period
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        // Committee subscription endpoint must be called exactly once
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/beacon_committee_subscriptions"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        // Attester duties for the next period's first epoch — pre-populated below
        let first_slot = PERIOD * SLOTS_PER_EPOCH;
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/attester/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": [{
                    "pubkey": pubkey_hex,
                    "validator_index": validator_index,
                    "committee_index": "0",
                    "committee_length": "128",
                    "committees_at_slot": "4",
                    "validator_committee_index": "0",
                    "slot": first_slot.to_string()
                }]
            })))
            .mount(&server)
            .await;

        let beacon_config = BeaconClientConfig::new(server.uri())
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(1);
        let beacon_client = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let beacon: Arc<dyn BeaconNodeClient> = beacon_client.clone();

        let duty_tracker =
            Arc::new(DutyTracker::new(beacon.clone(), vec![validator_index.to_string()]));

        // Pre-populate the attester duty cache for PERIOD (next period's first epoch)
        duty_tracker.fetch_duties_for_epoch(PERIOD).await.unwrap();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(composite, slashing_db));

        let clock = Arc::new(MockSlotClock::new(1606824023, Duration::from_secs(12), 0));

        let mut pubkey_map_inner = HashMap::new();
        pubkey_map_inner.insert(pubkey_hex, pubkey);
        let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));
        let validator_store = Arc::new(ValidatorStore::new([0xffu8; 20], 30_000_000));

        let service = DutyManagementService::new(
            clock,
            signer,
            beacon,
            duty_tracker,
            validator_store,
            pubkey_map,
            make_config(),
        );

        // Trigger prefetch at the second-to-last epoch of period 0
        service.maybe_prefetch_next_sync_period(PERIOD - 2).await;
        // wiremock asserts both expect(1)s on drop
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Integration: fetch_epoch_duties triggers prefetch in window
    // ──────────────────────────────────────────────────────────────────────────

    /// `fetch_epoch_duties` at an epoch in the lookahead window triggers the prefetch,
    /// causing the BN to be queried for the next period's duties.
    #[tokio::test]
    async fn test_fetch_epoch_duties_triggers_prefetch_in_window() {
        let server = MockServer::start().await;
        let current_epoch = PERIOD - 2;

        // Standard duty endpoints for the current epoch (no validators, so no real data needed)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/attester/{}", current_epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/validator/duties/proposer/{}", current_epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&server)
            .await;

        // Sync duties for current period (period 0, epoch 254 → period 0)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", current_epoch)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .mount(&server)
            .await;

        // Prefetch: sync duties for next period (period 1, first epoch = PERIOD = 256)
        Mock::given(method("POST"))
            .and(path(format!("/eth/v1/validator/duties/sync/{}", PERIOD)))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_duties_response()))
            .expect(1)
            .mount(&server)
            .await;

        let service = build_service_no_validators(&server.uri()).await;
        service.fetch_epoch_duties(current_epoch).await;
        // wiremock asserts expect(1) for PERIOD sync duties on drop
    }
}
