use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use beacon::{AttesterDuty, BeaconClient};
use eth_types::SLOTS_PER_EPOCH;
use metrics::definitions::RVC_DUTIES_FETCHED_TOTAL;

use super::error::DutyTrackerError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DutyCacheKey {
    pub slot: u64,
    pub committee_index: u64,
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

pub struct DutyTracker {
    beacon: Arc<BeaconClient>,
    validator_indices: Vec<String>,
    cache: RwLock<HashMap<u64, EpochDutyCache>>,
}

impl DutyTracker {
    pub fn new(beacon: Arc<BeaconClient>, validator_indices: Vec<String>) -> Self {
        Self { beacon, validator_indices, cache: RwLock::new(HashMap::new()) }
    }

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

        RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[]).inc();

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
            let slot: u64 = duty.slot.parse().unwrap_or(0);
            let committee_index: u64 = duty.committee_index.parse().unwrap_or(0);

            let key = DutyCacheKey { slot, committee_index };
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
    ) -> Result<AttesterDuty, DutyTrackerError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.cache.read().await;

        let key = DutyCacheKey { slot, committee_index };

        if let Some(epoch_cache) = cache.get(&epoch) {
            if let Some(duty) = epoch_cache.get(&key) {
                return Ok(duty.clone());
            }
        }

        Err(DutyTrackerError::DutyNotFound { slot, committee_index })
    }

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
                let slot: u64 = duty.slot.parse().unwrap_or(0);
                let committee_index: u64 = duty.committee_index.parse().unwrap_or(0);
                let key = DutyCacheKey { slot, committee_index };
                epoch_cache.insert(key, duty.clone());
            }

            cache.insert(epoch, epoch_cache);
            return Ok(true);
        }

        Ok(false)
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

    use beacon::BeaconClientConfig;

    use super::*;

    async fn setup_mock_beacon() -> (MockServer, Arc<BeaconClient>) {
        let mock_server = MockServer::start().await;
        let config = BeaconClientConfig::new(mock_server.uri())
            .with_timeout(Duration::from_secs(5))
            .with_max_retries(1);
        let client = BeaconClient::new(config).unwrap();
        (mock_server, Arc::new(client))
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

        let duty = tracker.get_duty(320, 1).await.unwrap();
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

        let result = tracker.get_duty(320, 99).await;
        assert!(matches!(result, Err(DutyTrackerError::DutyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_get_duty_epoch_not_cached() {
        let (_, beacon) = setup_mock_beacon().await;
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let result = tracker.get_duty(320, 1).await;
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

        let duty1 = tracker.get_duty(320, 1).await.unwrap();
        assert_eq!(duty1.validator_index, "1234");

        let duty2 = tracker.get_duty(321, 2).await.unwrap();
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

        let duty10 = tracker.get_duty(320, 1).await.unwrap();
        assert_eq!(duty10.slot, "320");

        let duty11 = tracker.get_duty(352, 2).await.unwrap();
        assert_eq!(duty11.slot, "352");
    }

    #[tokio::test]
    async fn test_duty_cache_key_hash_eq() {
        let key1 = DutyCacheKey { slot: 100, committee_index: 1 };
        let key2 = DutyCacheKey { slot: 100, committee_index: 1 };
        let key3 = DutyCacheKey { slot: 100, committee_index: 2 };
        let key4 = DutyCacheKey { slot: 101, committee_index: 1 };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);

        let mut map = HashMap::new();
        map.insert(key1.clone(), "value1");
        assert!(map.contains_key(&key2));
        assert!(!map.contains_key(&key3));
    }
}
