use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use bn_manager::{AttesterDuty, BeaconNodeClient, ProposerDuty};
use eth_types::{SyncCommitteeDuty, SLOTS_PER_EPOCH};
use metrics::definitions::RVC_DUTIES_FETCHED_TOTAL;

use crate::error::DutyTrackerError;

/// Epochs per sync committee period (256 epochs ~ 27 hours).
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DutyCacheKey {
    pub slot: u64,
    pub committee_index: u64,
    pub validator_index: u64,
}

#[derive(Debug)]
struct EpochDutyCache {
    duties: HashMap<DutyCacheKey, AttesterDuty>,
    dependent_root: String,
}

impl EpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root }
    }

    fn insert(&mut self, key: DutyCacheKey, duty: AttesterDuty) {
        self.duties.insert(key, duty);
    }

    fn get(&self, key: &DutyCacheKey) -> Option<&AttesterDuty> {
        self.duties.get(key)
    }
}

#[derive(Debug)]
struct ProposerEpochDutyCache {
    duties: HashMap<u64, ProposerDuty>,
    dependent_root: String,
}

impl ProposerEpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root }
    }

    fn insert(&mut self, slot: u64, duty: ProposerDuty) {
        self.duties.insert(slot, duty);
    }

    fn get(&self, slot: &u64) -> Option<&ProposerDuty> {
        self.duties.get(slot)
    }
}

pub struct DutyTracker {
    beacon: Arc<dyn BeaconNodeClient>,
    validator_indices: Vec<String>,
    cache: RwLock<HashMap<u64, EpochDutyCache>>,
    /// Proposer duties keyed by epoch -> ProposerEpochDutyCache.
    proposer_cache: RwLock<HashMap<u64, ProposerEpochDutyCache>>,
    /// Sync committee duties keyed by sync committee period.
    sync_committee_cache: RwLock<HashMap<u64, Vec<SyncCommitteeDuty>>>,
}

impl DutyTracker {
    pub fn new(beacon: Arc<dyn BeaconNodeClient>, validator_indices: Vec<String>) -> Self {
        Self {
            beacon,
            validator_indices,
            cache: RwLock::new(HashMap::new()),
            proposer_cache: RwLock::new(HashMap::new()),
            sync_committee_cache: RwLock::new(HashMap::new()),
        }
    }

    #[tracing::instrument(name = "rvc.duty_tracker.fetch_attester_duties", skip_all, fields(rvc.epoch = epoch))]
    pub async fn fetch_duties_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Vec<AttesterDuty>, DutyTrackerError> {
        debug!(epoch = epoch, "Fetching duties for epoch");

        let response = self
            .beacon
            .get_attester_duties(epoch, &self.validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[] as &[&str]).inc();

        let mut cache = self.cache.write().await;

        if let Some(existing_cache) = cache.get(&epoch) {
            if existing_cache.dependent_root != response.dependent_root {
                warn!(
                    epoch = epoch,
                    old_root = %existing_cache.dependent_root,
                    new_root = %response.dependent_root,
                    "Dependent root changed, invalidating cache"
                );
            }
        }

        let mut epoch_cache = EpochDutyCache::new(response.dependent_root.clone());

        for duty in &response.data {
            let slot: u64 = match duty.slot.parse() {
                Ok(s) => s,
                Err(_) => {
                    warn!(raw_slot = %duty.slot, "Skipping duty with unparseable slot");
                    continue;
                }
            };
            let committee_index: u64 = match duty.committee_index.parse() {
                Ok(c) => c,
                Err(_) => {
                    warn!(raw_committee_index = %duty.committee_index, "Skipping duty with unparseable committee_index");
                    continue;
                }
            };
            let validator_index: u64 = match duty.validator_index.parse() {
                Ok(v) => v,
                Err(_) => {
                    warn!(raw_validator_index = %duty.validator_index, "Skipping duty with unparseable validator_index");
                    continue;
                }
            };

            let key = DutyCacheKey { slot, committee_index, validator_index };
            epoch_cache.insert(key, duty.clone());
        }

        info!(
            epoch = epoch,
            duties_count = response.data.len(),
            dependent_root = %response.dependent_root,
            "Cached duties for epoch"
        );

        cache.insert(epoch, epoch_cache);

        Ok(response.data)
    }

    pub async fn get_duty(
        &self,
        slot: u64,
        committee_index: u64,
        validator_index: u64,
    ) -> Result<AttesterDuty, DutyTrackerError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.cache.read().await;

        let key = DutyCacheKey { slot, committee_index, validator_index };

        if let Some(epoch_cache) = cache.get(&epoch) {
            if let Some(duty) = epoch_cache.get(&key) {
                return Ok(duty.clone());
            }
        }

        Err(DutyTrackerError::DutyNotFound { slot, committee_index, validator_index })
    }

    #[tracing::instrument(name = "rvc.duty_tracker.check_attester_reorg", skip_all, fields(rvc.epoch = epoch))]
    pub async fn check_and_refetch_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let cached_root = {
            let cache = self.cache.read().await;
            cache.get(&epoch).map(|c| c.dependent_root.clone())
        };

        if cached_root.is_none() {
            self.fetch_duties_for_epoch(epoch).await?;
            return Ok(true);
        }

        let response = self
            .beacon
            .get_attester_duties(epoch, &self.validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        if cached_root.as_ref() != Some(&response.dependent_root) {
            info!(
                epoch = epoch,
                old_root = ?cached_root,
                new_root = %response.dependent_root,
                "Dependent root changed, refetching duties"
            );

            let mut cache = self.cache.write().await;
            let mut epoch_cache = EpochDutyCache::new(response.dependent_root.clone());

            for duty in &response.data {
                let slot: u64 = match duty.slot.parse() {
                    Ok(s) => s,
                    Err(_) => {
                        warn!(raw_slot = %duty.slot, "Skipping duty with unparseable slot");
                        continue;
                    }
                };
                let committee_index: u64 = match duty.committee_index.parse() {
                    Ok(c) => c,
                    Err(_) => {
                        warn!(raw_committee_index = %duty.committee_index, "Skipping duty with unparseable committee_index");
                        continue;
                    }
                };
                let validator_index: u64 = match duty.validator_index.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        warn!(raw_validator_index = %duty.validator_index, "Skipping duty with unparseable validator_index");
                        continue;
                    }
                };
                let key = DutyCacheKey { slot, committee_index, validator_index };
                epoch_cache.insert(key, duty.clone());
            }

            cache.insert(epoch, epoch_cache);
            return Ok(true);
        }

        Ok(false)
    }

    #[tracing::instrument(name = "rvc.duty_tracker.evict_old_caches", skip_all, fields(rvc.epoch = current_epoch))]
    pub async fn evict_old_caches(&self, current_epoch: u64) {
        let retain_epoch = current_epoch.saturating_sub(2);

        let mut cache = self.cache.write().await;
        let before = cache.len();
        cache.retain(|&epoch, _| epoch >= retain_epoch);
        let attester_removed = before - cache.len();
        drop(cache);

        let mut pcache = self.proposer_cache.write().await;
        let before = pcache.len();
        pcache.retain(|&epoch, _| epoch >= retain_epoch);
        let proposer_removed = before - pcache.len();
        drop(pcache);

        let current_period = current_epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let retain_period = current_period.saturating_sub(1);
        let mut scache = self.sync_committee_cache.write().await;
        let before = scache.len();
        scache.retain(|&period, _| period >= retain_period);
        let sync_removed = before - scache.len();
        drop(scache);

        if attester_removed > 0 || proposer_removed > 0 || sync_removed > 0 {
            debug!(
                current_epoch,
                attester_removed, proposer_removed, sync_removed, "Evicted old duty caches"
            );
        }
    }

    pub async fn get_duties_for_slot(&self, slot: u64) -> Vec<AttesterDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.cache.read().await;

        let Some(epoch_cache) = cache.get(&epoch) else {
            return Vec::new();
        };

        epoch_cache
            .duties
            .iter()
            .filter(|(key, _)| key.slot == slot)
            .map(|(_, duty)| duty.clone())
            .collect()
    }

    pub async fn clear_epoch_cache(&self, epoch: u64) {
        let mut cache = self.cache.write().await;
        cache.remove(&epoch);
        debug!(epoch = epoch, "Cleared cache for epoch");
    }

    pub async fn is_epoch_cached(&self, epoch: u64) -> bool {
        let cache = self.cache.read().await;
        cache.contains_key(&epoch)
    }

    pub async fn get_cached_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.cache.read().await;
        cache.get(&epoch).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "rvc.duty_tracker.fetch_proposer_duties", skip_all, fields(rvc.epoch = epoch))]
    pub async fn fetch_proposer_duties(
        &self,
        epoch: u64,
    ) -> Result<Vec<ProposerDuty>, DutyTrackerError> {
        debug!(epoch = epoch, "Fetching proposer duties for epoch");

        let response =
            self.beacon.get_proposer_duties(epoch).await.map_err(DutyTrackerError::BeaconError)?;

        let mut epoch_cache = ProposerEpochDutyCache::new(response.dependent_root.clone());
        for duty in &response.data {
            let slot: u64 = match duty.slot.parse() {
                Ok(s) => s,
                Err(_) => {
                    warn!(raw_slot = %duty.slot, "Skipping proposer duty with unparseable slot");
                    continue;
                }
            };
            epoch_cache.insert(slot, duty.clone());
        }

        info!(epoch = epoch, count = response.data.len(), "Cached proposer duties for epoch");

        let mut cache = self.proposer_cache.write().await;
        cache.insert(epoch, epoch_cache);

        Ok(response.data)
    }

    pub async fn get_proposer_duty(&self, slot: u64) -> Option<ProposerDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.proposer_cache.read().await;
        cache.get(&epoch).and_then(|c| c.get(&slot)).cloned()
    }

    pub async fn get_cached_proposer_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.proposer_cache.read().await;
        cache.get(&epoch).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "rvc.duty_tracker.check_proposer_reorg", skip_all, fields(rvc.epoch = epoch))]
    pub async fn check_and_refetch_proposer_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let cached_root = {
            let cache = self.proposer_cache.read().await;
            cache.get(&epoch).map(|c| c.dependent_root.clone())
        };

        if cached_root.is_none() {
            self.fetch_proposer_duties(epoch).await?;
            return Ok(true);
        }

        let response =
            self.beacon.get_proposer_duties(epoch).await.map_err(DutyTrackerError::BeaconError)?;

        if cached_root.as_ref() != Some(&response.dependent_root) {
            info!(
                epoch = epoch,
                old_root = ?cached_root,
                new_root = %response.dependent_root,
                "Proposer dependent root changed, refetching duties"
            );

            let mut epoch_cache = ProposerEpochDutyCache::new(response.dependent_root.clone());
            for duty in &response.data {
                let slot: u64 = match duty.slot.parse() {
                    Ok(s) => s,
                    Err(_) => {
                        warn!(raw_slot = %duty.slot, "Skipping proposer duty with unparseable slot");
                        continue;
                    }
                };
                epoch_cache.insert(slot, duty.clone());
            }

            let mut cache = self.proposer_cache.write().await;
            cache.insert(epoch, epoch_cache);
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn is_proposer_epoch_cached(&self, epoch: u64) -> bool {
        let cache = self.proposer_cache.read().await;
        cache.contains_key(&epoch)
    }

    #[tracing::instrument(name = "rvc.duty_tracker.fetch_sync_committee_duties", skip_all, fields(rvc.epoch = epoch))]
    pub async fn fetch_sync_committee_duties(
        &self,
        epoch: u64,
    ) -> Result<Vec<SyncCommitteeDuty>, DutyTrackerError> {
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        debug!(epoch = epoch, period = period, "Fetching sync committee duties");

        let response = self
            .beacon
            .post_sync_committee_duties(epoch, &self.validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        info!(
            epoch = epoch,
            period = period,
            count = response.data.len(),
            "Cached sync committee duties for period"
        );

        let mut cache = self.sync_committee_cache.write().await;
        cache.insert(period, response.data.clone());

        Ok(response.data)
    }

    pub async fn get_sync_committee_duties(&self, slot: u64) -> Vec<SyncCommitteeDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let cache = self.sync_committee_cache.read().await;
        cache.get(&period).cloned().unwrap_or_default()
    }

    pub async fn is_sync_period_cached(&self, epoch: u64) -> bool {
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let cache = self.sync_committee_cache.read().await;
        cache.contains_key(&period)
    }

    pub fn sync_committee_period(epoch: u64) -> u64 {
        epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
    }

    pub fn is_sync_committee_period_boundary(epoch: u64) -> bool {
        epoch.is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
    }

    pub fn is_epoch_boundary_slot(slot: u64) -> bool {
        slot.is_multiple_of(SLOTS_PER_EPOCH)
    }

    pub fn slot_to_epoch(slot: u64) -> u64 {
        slot / SLOTS_PER_EPOCH
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use beacon::{BeaconClient, BeaconClientConfig};
    use bn_manager::BeaconNodeClient;

    use super::*;

    async fn setup_mock_beacon() -> (MockServer, Arc<dyn BeaconNodeClient>) {
        let mock_server = MockServer::start().await;
        let config = BeaconClientConfig::new(mock_server.uri())
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(1);
        let client = BeaconClient::new(config).unwrap();
        (mock_server, Arc::new(client) as Arc<dyn BeaconNodeClient>)
    }

    fn create_mock_duty_response(
        _epoch: u64,
        duties: Vec<(u64, u64, &str)>,
        dependent_root: &str,
    ) -> serde_json::Value {
        let data: Vec<serde_json::Value> = duties
            .into_iter()
            .map(|(slot, committee_index, validator_index)| {
                serde_json::json!({
                    "pubkey": format!("0xpubkey_{}", validator_index),
                    "validator_index": validator_index,
                    "committee_index": committee_index.to_string(),
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "25",
                    "slot": slot.to_string()
                })
            })
            .collect();

        serde_json::json!({
            "dependent_root": dependent_root,
            "execution_optimistic": false,
            "data": data
        })
    }

    #[tokio::test]
    async fn test_duty_tracker_new() {
        let (_, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        assert!(!tracker.is_epoch_cached(0).await);
    }

    #[tokio::test]
    async fn test_fetch_duties_for_epoch_success() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_duty_response(
            10,
            vec![(320, 1, "1234"), (321, 2, "1234")],
            "0xdeproot_abc123",
        );

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .and(body_json(["1234"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_duties_for_epoch(10).await.unwrap();

        assert_eq!(duties.len(), 2);
        assert_eq!(duties[0].slot, "320");
        assert_eq!(duties[1].slot, "321");
        assert!(tracker.is_epoch_cached(10).await);
    }

    #[tokio::test]
    async fn test_get_duty_from_cache() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_duty_response(10, vec![(320, 1, "1234")], "0xdeproot_abc123");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let duty = tracker.get_duty(320, 1, 1234).await.unwrap();
        assert_eq!(duty.slot, "320");
        assert_eq!(duty.committee_index, "1");
        assert_eq!(duty.validator_index, "1234");
    }

    #[tokio::test]
    async fn test_get_duty_not_found() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_duty_response(10, vec![(320, 1, "1234")], "0xdeproot_abc123");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let result = tracker.get_duty(320, 99, 1234).await;
        assert!(matches!(result, Err(DutyTrackerError::DutyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_get_duty_epoch_not_cached() {
        let (_, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let result = tracker.get_duty(320, 1, 1234).await;
        assert!(matches!(result, Err(DutyTrackerError::DutyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_dependent_root_change_detection() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response1 = create_mock_duty_response(10, vec![(320, 1, "1234")], "0xroot_first");

        let response2 = create_mock_duty_response(10, vec![(320, 2, "1234")], "0xroot_second");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response1))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response2))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_duties_for_epoch(10).await.unwrap();
        let root1 = tracker.get_cached_dependent_root(10).await;
        assert_eq!(root1, Some("0xroot_first".to_string()));

        let changed = tracker.check_and_refetch_if_root_changed(10).await.unwrap();
        assert!(changed);

        let root2 = tracker.get_cached_dependent_root(10).await;
        assert_eq!(root2, Some("0xroot_second".to_string()));
    }

    #[tokio::test]
    async fn test_dependent_root_no_change() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_duty_response(10, vec![(320, 1, "1234")], "0xroot_same");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(2)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let changed = tracker.check_and_refetch_if_root_changed(10).await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn test_clear_epoch_cache() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_duty_response(10, vec![(320, 1, "1234")], "0xdeproot");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        assert!(tracker.is_epoch_cached(10).await);

        tracker.clear_epoch_cache(10).await;

        assert!(!tracker.is_epoch_cached(10).await);
    }

    #[tokio::test]
    async fn test_is_epoch_boundary_slot() {
        assert!(DutyTracker::is_epoch_boundary_slot(0));
        assert!(DutyTracker::is_epoch_boundary_slot(32));
        assert!(DutyTracker::is_epoch_boundary_slot(64));
        assert!(DutyTracker::is_epoch_boundary_slot(320));

        assert!(!DutyTracker::is_epoch_boundary_slot(1));
        assert!(!DutyTracker::is_epoch_boundary_slot(31));
        assert!(!DutyTracker::is_epoch_boundary_slot(33));
    }

    #[tokio::test]
    async fn test_slot_to_epoch() {
        assert_eq!(DutyTracker::slot_to_epoch(0), 0);
        assert_eq!(DutyTracker::slot_to_epoch(31), 0);
        assert_eq!(DutyTracker::slot_to_epoch(32), 1);
        assert_eq!(DutyTracker::slot_to_epoch(64), 2);
        assert_eq!(DutyTracker::slot_to_epoch(320), 10);
    }

    #[tokio::test]
    async fn test_multiple_validators() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let response =
            create_mock_duty_response(10, vec![(320, 1, "1234"), (321, 2, "5678")], "0xdeproot");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .and(body_json(["1234", "5678"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_duties_for_epoch(10).await.unwrap();

        assert_eq!(duties.len(), 2);

        let duty1 = tracker.get_duty(320, 1, 1234).await.unwrap();
        assert_eq!(duty1.validator_index, "1234");

        let duty2 = tracker.get_duty(321, 2, 5678).await.unwrap();
        assert_eq!(duty2.validator_index, "5678");
    }

    #[tokio::test]
    async fn test_fetch_duties_beacon_error() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        let result = tracker.fetch_duties_for_epoch(10).await;

        assert!(matches!(result, Err(DutyTrackerError::BeaconError(_))));
    }

    #[tokio::test]
    async fn test_fetch_next_epoch_while_current_cached() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response10 = create_mock_duty_response(10, vec![(320, 1, "1234")], "0xroot_epoch10");
        let response11 = create_mock_duty_response(11, vec![(352, 2, "1234")], "0xroot_epoch11");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response10))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/11"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response11))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_duties_for_epoch(10).await.unwrap();
        tracker.fetch_duties_for_epoch(11).await.unwrap();

        assert!(tracker.is_epoch_cached(10).await);
        assert!(tracker.is_epoch_cached(11).await);

        let duty10 = tracker.get_duty(320, 1, 1234).await.unwrap();
        assert_eq!(duty10.slot, "320");

        let duty11 = tracker.get_duty(352, 2, 1234).await.unwrap();
        assert_eq!(duty11.slot, "352");
    }

    #[tokio::test]
    async fn test_duty_cache_key_hash_eq() {
        let key1 = DutyCacheKey { slot: 100, committee_index: 1, validator_index: 42 };
        let key2 = DutyCacheKey { slot: 100, committee_index: 1, validator_index: 42 };
        let key3 = DutyCacheKey { slot: 100, committee_index: 2, validator_index: 42 };
        let key4 = DutyCacheKey { slot: 101, committee_index: 1, validator_index: 42 };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);

        let mut map = HashMap::new();
        map.insert(key1.clone(), "value1");
        assert!(map.contains_key(&key2));
        assert!(!map.contains_key(&key3));
    }

    // --- Proposer duty tests ---

    fn create_mock_proposer_response(duties: Vec<(u64, &str, &str)>) -> serde_json::Value {
        let data: Vec<serde_json::Value> = duties
            .into_iter()
            .map(|(slot, validator_index, pubkey)| {
                serde_json::json!({
                    "pubkey": pubkey,
                    "validator_index": validator_index,
                    "slot": slot.to_string()
                })
            })
            .collect();

        serde_json::json!({
            "dependent_root": "0xdeproot",
            "execution_optimistic": false,
            "data": data
        })
    }

    #[tokio::test]
    async fn test_fetch_proposer_duties_success() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_proposer_response(vec![
            (320, "1234", "0xpubkey_1234"),
            (325, "5678", "0xpubkey_5678"),
        ]);

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_proposer_duties(10).await.unwrap();

        assert_eq!(duties.len(), 2);
        assert!(tracker.is_proposer_epoch_cached(10).await);
    }

    #[tokio::test]
    async fn test_get_proposer_duty_found() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_proposer_duties(10).await.unwrap();

        let duty = tracker.get_proposer_duty(320).await;
        assert!(duty.is_some());
        assert_eq!(duty.unwrap().validator_index, "1234");
    }

    #[tokio::test]
    async fn test_get_proposer_duty_not_found() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_proposer_duties(10).await.unwrap();

        let duty = tracker.get_proposer_duty(321).await;
        assert!(duty.is_none());
    }

    #[tokio::test]
    async fn test_get_proposer_duty_epoch_not_cached() {
        let (_, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let duty = tracker.get_proposer_duty(320).await;
        assert!(duty.is_none());
    }

    #[tokio::test]
    async fn test_get_cached_proposer_dependent_root() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_proposer_duties(10).await.unwrap();

        let root = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root, Some("0xdeproot".to_string()));
    }

    #[tokio::test]
    async fn test_get_cached_proposer_dependent_root_not_cached() {
        let (_, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let root = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root, None);
    }

    #[tokio::test]
    async fn test_proposer_dependent_root_changes_with_refetch() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let mut response1 = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);
        response1["dependent_root"] = serde_json::json!("0xfirst_root");

        let mut response2 = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);
        response2["dependent_root"] = serde_json::json!("0xsecond_root");

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response1))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response2))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_proposer_duties(10).await.unwrap();
        let root1 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root1, Some("0xfirst_root".to_string()));

        tracker.fetch_proposer_duties(10).await.unwrap();
        let root2 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root2, Some("0xsecond_root".to_string()));
    }

    #[tokio::test]
    async fn test_check_and_refetch_proposer_if_root_changed_uncached() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);

        let changed = tracker.check_and_refetch_proposer_if_root_changed(10).await.unwrap();
        assert!(changed);
        assert!(tracker.is_proposer_epoch_cached(10).await);
    }

    #[tokio::test]
    async fn test_check_and_refetch_proposer_if_root_changed_detects_change() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let mut response1 = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);
        response1["dependent_root"] = serde_json::json!("0xfirst_root");

        let mut response2 = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);
        response2["dependent_root"] = serde_json::json!("0xsecond_root");

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response1))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response2))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_proposer_duties(10).await.unwrap();
        let root1 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root1, Some("0xfirst_root".to_string()));

        let changed = tracker.check_and_refetch_proposer_if_root_changed(10).await.unwrap();
        assert!(changed);

        let root2 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root2, Some("0xsecond_root".to_string()));
    }

    #[tokio::test]
    async fn test_check_and_refetch_proposer_if_root_unchanged() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response = create_mock_proposer_response(vec![(320, "1234", "0xpubkey_1234")]);

        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/duties/proposer/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(2)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_proposer_duties(10).await.unwrap();

        let changed = tracker.check_and_refetch_proposer_if_root_changed(10).await.unwrap();
        assert!(!changed);
    }

    // --- Sync committee duty tests ---

    fn create_mock_sync_committee_response(
        duties: Vec<(u64, &str, Vec<u64>)>,
    ) -> serde_json::Value {
        let data: Vec<serde_json::Value> = duties
            .into_iter()
            .map(|(validator_index, pubkey, indices)| {
                serde_json::json!({
                    "pubkey": pubkey,
                    "validator_index": validator_index,
                    "validator_sync_committee_indices": indices.iter().map(|i| i.to_string()).collect::<Vec<_>>()
                })
            })
            .collect();

        serde_json::json!({
            "execution_optimistic": false,
            "data": data
        })
    }

    #[tokio::test]
    async fn test_fetch_sync_committee_duties_success() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response =
            create_mock_sync_committee_response(vec![(1234, "0xpubkey_1234", vec![10, 20])]);

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/sync/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_sync_committee_duties(10).await.unwrap();

        assert_eq!(duties.len(), 1);
        assert!(tracker.is_sync_period_cached(10).await);
    }

    #[tokio::test]
    async fn test_get_sync_committee_duties_cached() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let response =
            create_mock_sync_committee_response(vec![(1234, "0xpubkey_1234", vec![10, 20])]);

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/sync/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_sync_committee_duties(10).await.unwrap();

        let duties = tracker.get_sync_committee_duties(320).await; // slot 320 = epoch 10
        assert_eq!(duties.len(), 1);
        assert_eq!(duties[0].validator_index, 1234);
    }

    #[tokio::test]
    async fn test_get_sync_committee_duties_not_cached() {
        let (_, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let duties = tracker.get_sync_committee_duties(320).await;
        assert!(duties.is_empty());
    }

    #[tokio::test]
    async fn test_sync_committee_period_boundary() {
        assert!(DutyTracker::is_sync_committee_period_boundary(0));
        assert!(DutyTracker::is_sync_committee_period_boundary(256));
        assert!(DutyTracker::is_sync_committee_period_boundary(512));
        assert!(!DutyTracker::is_sync_committee_period_boundary(1));
        assert!(!DutyTracker::is_sync_committee_period_boundary(255));
    }

    #[tokio::test]
    async fn test_sync_committee_period() {
        assert_eq!(DutyTracker::sync_committee_period(0), 0);
        assert_eq!(DutyTracker::sync_committee_period(255), 0);
        assert_eq!(DutyTracker::sync_committee_period(256), 1);
        assert_eq!(DutyTracker::sync_committee_period(512), 2);
    }

    #[tokio::test]
    async fn test_get_duties_for_slot() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let response = create_mock_duty_response(
            10,
            vec![(320, 1, "1234"), (320, 2, "5678"), (321, 0, "1234")],
            "0xdeproot",
        );

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let duties_320 = tracker.get_duties_for_slot(320).await;
        assert_eq!(duties_320.len(), 2);

        let duties_321 = tracker.get_duties_for_slot(321).await;
        assert_eq!(duties_321.len(), 1);

        let duties_322 = tracker.get_duties_for_slot(322).await;
        assert!(duties_322.is_empty());
    }

    #[tokio::test]
    async fn test_get_duties_for_slot_uncached_epoch() {
        let (_, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let duties = tracker.get_duties_for_slot(320).await;
        assert!(duties.is_empty());
    }

    #[tokio::test]
    async fn test_evict_old_caches() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        // Set up responses for epochs 5, 6, 7, 8, 9
        for epoch in 5..=9 {
            let slot_base = epoch * 32;
            let response = create_mock_duty_response(
                epoch,
                vec![(slot_base, 0, "1234")],
                &format!("0xroot_{}", epoch),
            );
            Mock::given(method("POST"))
                .and(path(format!("/eth/v1/validator/duties/attester/{}", epoch)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;
        }

        let tracker = DutyTracker::new(beacon, validator_indices);

        for epoch in 5..=9 {
            tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        }
        for epoch in 5..=9 {
            assert!(tracker.is_epoch_cached(epoch).await);
        }

        // Evict with current_epoch=9 should keep epochs >= 7
        tracker.evict_old_caches(9).await;

        assert!(!tracker.is_epoch_cached(5).await);
        assert!(!tracker.is_epoch_cached(6).await);
        assert!(tracker.is_epoch_cached(7).await);
        assert!(tracker.is_epoch_cached(8).await);
        assert!(tracker.is_epoch_cached(9).await);
    }

    #[tokio::test]
    async fn test_evict_old_caches_proposer() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        for epoch in 5..=9 {
            let slot_base = epoch * 32;
            let response =
                create_mock_proposer_response(vec![(slot_base, "1234", "0xpubkey_1234")]);
            Mock::given(method("GET"))
                .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response))
                .mount(&mock_server)
                .await;
        }

        let tracker = DutyTracker::new(beacon, validator_indices);

        for epoch in 5..=9 {
            tracker.fetch_proposer_duties(epoch).await.unwrap();
        }
        for epoch in 5..=9 {
            assert!(tracker.is_proposer_epoch_cached(epoch).await);
        }

        tracker.evict_old_caches(9).await;

        assert!(!tracker.is_proposer_epoch_cached(5).await);
        assert!(!tracker.is_proposer_epoch_cached(6).await);
        assert!(tracker.is_proposer_epoch_cached(7).await);
        assert!(tracker.is_proposer_epoch_cached(8).await);
        assert!(tracker.is_proposer_epoch_cached(9).await);
    }

    #[tokio::test]
    async fn test_fetch_duties_skips_unparseable_slot() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let data = vec![
            serde_json::json!({
                "pubkey": "0xpubkey_1234",
                "validator_index": "1234",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "25",
                "slot": "invalid"
            }),
            serde_json::json!({
                "pubkey": "0xpubkey_1234",
                "validator_index": "1234",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "25",
                "slot": "320"
            }),
        ];

        let response = serde_json::json!({
            "dependent_root": "0xdeproot",
            "execution_optimistic": false,
            "data": data
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_duties_for_epoch(10).await.unwrap();
        // Both returned from API
        assert_eq!(duties.len(), 2);

        // But only the valid one is cached
        let duty = tracker.get_duty(320, 1, 1234).await;
        assert!(duty.is_ok());

        // The invalid slot should not be cached at slot 0 as before
        let duties_at_zero = tracker.get_duties_for_slot(0).await;
        assert!(duties_at_zero.is_empty());
    }

    #[tokio::test]
    async fn test_same_slot_committee_different_validators_both_stored() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["100".to_string(), "200".to_string()];

        // Two validators in the same (slot=320, committee_index=1)
        let response =
            create_mock_duty_response(10, vec![(320, 1, "100"), (320, 1, "200")], "0xdeproot");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let duties = tracker.get_duties_for_slot(320).await;
        assert_eq!(duties.len(), 2, "Both validators should be stored, got {}", duties.len());
    }

    #[tokio::test]
    async fn test_get_duty_with_validator_index() {
        let (mock_server, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["100".to_string(), "200".to_string()];

        let response =
            create_mock_duty_response(10, vec![(320, 1, "100"), (320, 1, "200")], "0xdeproot");

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        // Found with correct validator_index
        let duty = tracker.get_duty(320, 1, 100).await.unwrap();
        assert_eq!(duty.validator_index, "100");

        let duty = tracker.get_duty(320, 1, 200).await.unwrap();
        assert_eq!(duty.validator_index, "200");

        // Not found with wrong validator_index
        let result = tracker.get_duty(320, 1, 999).await;
        assert!(matches!(result, Err(DutyTrackerError::DutyNotFound { .. })));
    }
}
