//! Doppelganger detection service.

use std::collections::HashMap;
use std::sync::Arc;

use eth_types::Epoch;
use tracing::{info, warn};

use crate::error::DoppelgangerError;
use crate::traits::{LivenessChecker, SlashingDbReader};
use crate::{DoppelgangerResult, DoppelgangerStatus};

const DEFAULT_MONITORING_EPOCHS: u64 = 2;

/// Service for detecting doppelganger validators.
pub struct DoppelgangerService {
    liveness_checker: Arc<dyn LivenessChecker>,
    slashing_db: Arc<dyn SlashingDbReader>,
    monitoring_epochs: u64,
}

impl DoppelgangerService {
    pub fn new(
        liveness_checker: Arc<dyn LivenessChecker>,
        slashing_db: Arc<dyn SlashingDbReader>,
    ) -> Self {
        Self { liveness_checker, slashing_db, monitoring_epochs: DEFAULT_MONITORING_EPOCHS }
    }

    pub fn with_monitoring_epochs(mut self, epochs: u64) -> Self {
        self.monitoring_epochs = epochs;
        self
    }

    /// Check which validators need monitoring vs can be marked safe (restart-aware).
    ///
    /// For each pubkey, queries the slashing DB for the last signed attestation epoch.
    /// If the validator signed within the last `monitoring_epochs` epochs,
    /// it is considered a restart and marked `Safe` immediately.
    /// Otherwise, it needs monitoring.
    pub fn check_validators(
        &self,
        pubkeys: &[String],
        current_epoch: Epoch,
    ) -> Result<Vec<(String, DoppelgangerStatus)>, DoppelgangerError> {
        let mut results = Vec::with_capacity(pubkeys.len());

        for pubkey in pubkeys {
            let last_epoch = self.slashing_db.last_signed_attestation_epoch(pubkey)?;

            let status = match last_epoch {
                Some(epoch) if current_epoch.saturating_sub(epoch) <= self.monitoring_epochs => {
                    info!(
                        pubkey = %pubkey,
                        last_epoch = epoch,
                        current_epoch = current_epoch,
                        "restart detected, skipping doppelganger monitoring"
                    );
                    DoppelgangerStatus::Safe
                }
                _ => {
                    info!(
                        pubkey = %pubkey,
                        last_epoch = ?last_epoch,
                        current_epoch = current_epoch,
                        "validator needs doppelganger monitoring"
                    );
                    DoppelgangerStatus::DetectionInProgress
                }
            };

            results.push((pubkey.clone(), status));
        }

        Ok(results)
    }

    /// Run monitoring for validators that need it.
    ///
    /// Checks liveness for each epoch in the monitoring window.
    /// If any validator shows `is_live: true` and we didn't sign anything
    /// (no slashing DB entry for that epoch), that validator has a doppelganger.
    ///
    /// `validator_indices` maps pubkey -> validator index (as string).
    pub async fn run_monitoring(
        &self,
        pubkeys_to_monitor: &[String],
        validator_indices: &HashMap<String, String>,
        current_epoch: Epoch,
    ) -> Result<DoppelgangerResult, DoppelgangerError> {
        if pubkeys_to_monitor.is_empty() {
            return Ok(DoppelgangerResult { safe_validators: vec![], detected: vec![] });
        }

        let indices: Vec<String> =
            pubkeys_to_monitor.iter().filter_map(|pk| validator_indices.get(pk).cloned()).collect();

        let mut detected: Vec<String> = Vec::new();

        // Check liveness for each epoch in the monitoring window
        for epoch_offset in 0..self.monitoring_epochs {
            let check_epoch = current_epoch.saturating_sub(1).saturating_sub(epoch_offset);

            let liveness_data = self.liveness_checker.check_liveness(check_epoch, &indices).await?;

            // Build index -> pubkey reverse map for this check
            let index_to_pubkey: HashMap<&str, &str> = pubkeys_to_monitor
                .iter()
                .filter_map(|pk| {
                    validator_indices.get(pk.as_str()).map(|idx| (idx.as_str(), pk.as_str()))
                })
                .collect();

            for entry in &liveness_data {
                if entry.is_live {
                    if let Some(&pubkey) = index_to_pubkey.get(entry.index.as_str()) {
                        // Check if we signed anything for this epoch
                        let our_last = self.slashing_db.last_signed_attestation_epoch(pubkey)?;
                        let we_signed = our_last.is_some_and(|e| e >= check_epoch);

                        if !we_signed {
                            warn!(
                                pubkey = %pubkey,
                                epoch = check_epoch,
                                "doppelganger detected: validator is live but we did not sign"
                            );
                            if !detected.contains(&pubkey.to_string()) {
                                detected.push(pubkey.to_string());
                            }
                        }
                    }
                }
            }
        }

        let safe_validators: Vec<String> =
            pubkeys_to_monitor.iter().filter(|pk| !detected.contains(pk)).cloned().collect();

        Ok(DoppelgangerResult { safe_validators, detected })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::traits::{LivenessChecker, SlashingDbReader, ValidatorLivenessData};
    use crate::{DoppelgangerError, DoppelgangerStatus};

    // -- Mock implementations --

    struct MockSlashingDb {
        epochs: HashMap<String, Option<Epoch>>,
    }

    impl MockSlashingDb {
        fn new() -> Self {
            Self { epochs: HashMap::new() }
        }

        fn with_epoch(mut self, pubkey: &str, epoch: Option<Epoch>) -> Self {
            self.epochs.insert(pubkey.to_string(), epoch);
            self
        }
    }

    impl SlashingDbReader for MockSlashingDb {
        fn last_signed_attestation_epoch(
            &self,
            pubkey: &str,
        ) -> Result<Option<Epoch>, DoppelgangerError> {
            Ok(self.epochs.get(pubkey).copied().flatten())
        }
    }

    struct MockLivenessChecker {
        responses: Mutex<Vec<Vec<ValidatorLivenessData>>>,
    }

    impl MockLivenessChecker {
        fn new(responses: Vec<Vec<ValidatorLivenessData>>) -> Self {
            Self { responses: Mutex::new(responses) }
        }
    }

    #[async_trait::async_trait]
    impl LivenessChecker for MockLivenessChecker {
        async fn check_liveness(
            &self,
            _epoch: Epoch,
            _validator_indices: &[String],
        ) -> Result<Vec<ValidatorLivenessData>, DoppelgangerError> {
            let mut responses = self.responses.lock().expect("poisoned");
            if responses.is_empty() {
                Ok(vec![])
            } else {
                Ok(responses.remove(0))
            }
        }
    }

    struct FailingSlashingDb;

    impl SlashingDbReader for FailingSlashingDb {
        fn last_signed_attestation_epoch(
            &self,
            _pubkey: &str,
        ) -> Result<Option<Epoch>, DoppelgangerError> {
            Err(DoppelgangerError::SlashingDbError("db error".to_string()))
        }
    }

    struct FailingLivenessChecker;

    #[async_trait::async_trait]
    impl LivenessChecker for FailingLivenessChecker {
        async fn check_liveness(
            &self,
            _epoch: Epoch,
            _validator_indices: &[String],
        ) -> Result<Vec<ValidatorLivenessData>, DoppelgangerError> {
            Err(DoppelgangerError::LivenessCheckFailed("network error".to_string()))
        }
    }

    fn pk(s: &str) -> String {
        s.to_string()
    }

    // -- Construction tests --

    #[test]
    fn test_new_default_monitoring_epochs() {
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let slashing_db: Arc<dyn SlashingDbReader> = Arc::new(MockSlashingDb::new());
        let service = DoppelgangerService::new(liveness, slashing_db);
        assert_eq!(service.monitoring_epochs, DEFAULT_MONITORING_EPOCHS);
    }

    #[test]
    fn test_with_monitoring_epochs() {
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let slashing_db: Arc<dyn SlashingDbReader> = Arc::new(MockSlashingDb::new());
        let service = DoppelgangerService::new(liveness, slashing_db).with_monitoring_epochs(5);
        assert_eq!(service.monitoring_epochs, 5);
    }

    // -- check_validators tests --

    #[test]
    fn test_check_validators_restart_skip_recent_attestation() {
        // Validator signed at epoch 98, current epoch is 100, window is 2
        // 100 - 98 = 2 <= 2, so should be Safe
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(98)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "0xpk1");
        assert_eq!(result[0].1, DoppelgangerStatus::Safe);
    }

    #[test]
    fn test_check_validators_restart_skip_same_epoch() {
        // Validator signed at epoch 100, current is 100
        // 100 - 100 = 0 <= 2, safe
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(100)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::Safe);
    }

    #[test]
    fn test_check_validators_needs_monitoring_old_attestation() {
        // Validator signed at epoch 95, current is 100, window is 2
        // 100 - 95 = 5 > 2, needs monitoring
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(95)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::DetectionInProgress);
    }

    #[test]
    fn test_check_validators_needs_monitoring_no_attestation() {
        // No attestation history at all — clean start
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::DetectionInProgress);
    }

    #[test]
    fn test_check_validators_mixed_results() {
        // pk1 signed at epoch 99 (safe), pk2 no history (needs monitoring)
        let slashing_db =
            Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(99)).with_epoch("0xpk2", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result =
            service.check_validators(&[pk("0xpk1"), pk("0xpk2")], 100).expect("should succeed");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1, DoppelgangerStatus::Safe);
        assert_eq!(result[1].1, DoppelgangerStatus::DetectionInProgress);
    }

    #[test]
    fn test_check_validators_empty_list() {
        let slashing_db: Arc<dyn SlashingDbReader> = Arc::new(MockSlashingDb::new());
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[], 100).expect("should succeed");
        assert!(result.is_empty());
    }

    #[test]
    fn test_check_validators_boundary_just_outside_window() {
        // monitoring_epochs = 2, signed at 97, current = 100
        // 100 - 97 = 3 > 2, needs monitoring
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(97)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::DetectionInProgress);
    }

    #[test]
    fn test_check_validators_boundary_at_edge_of_window() {
        // monitoring_epochs = 2, signed at 98, current = 100
        // 100 - 98 = 2 <= 2, safe
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(98)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::Safe);
    }

    #[test]
    fn test_check_validators_custom_monitoring_epochs() {
        // Custom window of 5. Signed at 94, current 100.
        // 100 - 94 = 6 > 5, needs monitoring
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(94)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db).with_monitoring_epochs(5);

        let result = service.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::DetectionInProgress);

        // Signed at 95, current 100: 100-95=5 <= 5, safe
        let slashing_db2 = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(95)));
        let liveness2: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service2 = DoppelgangerService::new(liveness2, slashing_db2).with_monitoring_epochs(5);

        let result2 = service2.check_validators(&[pk("0xpk1")], 100).expect("should succeed");
        assert_eq!(result2[0].1, DoppelgangerStatus::Safe);
    }

    #[test]
    fn test_check_validators_slashing_db_error() {
        let slashing_db: Arc<dyn SlashingDbReader> = Arc::new(FailingSlashingDb);
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 100);
        assert!(result.is_err());
    }

    // -- run_monitoring tests --

    #[tokio::test]
    async fn test_run_monitoring_empty_pubkeys() {
        let slashing_db: Arc<dyn SlashingDbReader> = Arc::new(MockSlashingDb::new());
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result =
            service.run_monitoring(&[], &HashMap::new(), 100).await.expect("should succeed");
        assert!(result.safe_validators.is_empty());
        assert!(result.detected.is_empty());
    }

    #[tokio::test]
    async fn test_run_monitoring_no_doppelganger_all_not_live() {
        // Validators are not live on the BN => no doppelganger, all safe
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![
            // epoch current-1
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: false }],
            // epoch current-2
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: false }],
        ]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let mut indices = HashMap::new();
        indices.insert(pk("0xpk1"), "1".to_string());

        let result =
            service.run_monitoring(&[pk("0xpk1")], &indices, 100).await.expect("should succeed");
        assert_eq!(result.safe_validators, vec!["0xpk1"]);
        assert!(result.detected.is_empty());
    }

    #[tokio::test]
    async fn test_run_monitoring_doppelganger_detected() {
        // Validator is live on BN but we didn't sign => doppelganger!
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![
            // epoch 99: validator is live!
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: true }],
            // epoch 98
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: false }],
        ]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let mut indices = HashMap::new();
        indices.insert(pk("0xpk1"), "1".to_string());

        let result =
            service.run_monitoring(&[pk("0xpk1")], &indices, 100).await.expect("should succeed");
        assert!(result.safe_validators.is_empty());
        assert_eq!(result.detected, vec!["0xpk1"]);
    }

    #[tokio::test]
    async fn test_run_monitoring_safe_after_monitoring_no_live() {
        // Two epochs of monitoring, validator never appears live
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![
            vec![ValidatorLivenessData { index: "42".to_string(), is_live: false }],
            vec![ValidatorLivenessData { index: "42".to_string(), is_live: false }],
        ]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let mut indices = HashMap::new();
        indices.insert(pk("0xpk1"), "42".to_string());

        let result =
            service.run_monitoring(&[pk("0xpk1")], &indices, 100).await.expect("should succeed");
        assert_eq!(result.safe_validators, vec!["0xpk1"]);
        assert!(result.detected.is_empty());
    }

    #[tokio::test]
    async fn test_run_monitoring_multiple_validators_mixed() {
        // pk1 has a doppelganger, pk2 is safe
        let slashing_db =
            Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None).with_epoch("0xpk2", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![
            // epoch 99: pk1 live, pk2 not live
            vec![
                ValidatorLivenessData { index: "1".to_string(), is_live: true },
                ValidatorLivenessData { index: "2".to_string(), is_live: false },
            ],
            // epoch 98: both not live
            vec![
                ValidatorLivenessData { index: "1".to_string(), is_live: false },
                ValidatorLivenessData { index: "2".to_string(), is_live: false },
            ],
        ]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let mut indices = HashMap::new();
        indices.insert(pk("0xpk1"), "1".to_string());
        indices.insert(pk("0xpk2"), "2".to_string());

        let result = service
            .run_monitoring(&[pk("0xpk1"), pk("0xpk2")], &indices, 100)
            .await
            .expect("should succeed");
        assert_eq!(result.safe_validators, vec!["0xpk2"]);
        assert_eq!(result.detected, vec!["0xpk1"]);
    }

    #[tokio::test]
    async fn test_run_monitoring_validator_live_but_we_signed() {
        // Validator is live AND we signed at that epoch => not a doppelganger (it's us)
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(99)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![
            // epoch 99: validator live
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: true }],
            // epoch 98
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: false }],
        ]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let mut indices = HashMap::new();
        indices.insert(pk("0xpk1"), "1".to_string());

        let result =
            service.run_monitoring(&[pk("0xpk1")], &indices, 100).await.expect("should succeed");
        assert_eq!(result.safe_validators, vec!["0xpk1"]);
        assert!(result.detected.is_empty());
    }

    #[tokio::test]
    async fn test_run_monitoring_liveness_check_failure() {
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(FailingLivenessChecker);
        let service = DoppelgangerService::new(liveness, slashing_db);

        let mut indices = HashMap::new();
        indices.insert(pk("0xpk1"), "1".to_string());

        let result = service.run_monitoring(&[pk("0xpk1")], &indices, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_run_monitoring_doppelganger_not_duplicated() {
        // If same validator detected in both epochs, should appear only once
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![
            // epoch 99: live
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: true }],
            // epoch 98: also live
            vec![ValidatorLivenessData { index: "1".to_string(), is_live: true }],
        ]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let mut indices = HashMap::new();
        indices.insert(pk("0xpk1"), "1".to_string());

        let result =
            service.run_monitoring(&[pk("0xpk1")], &indices, 100).await.expect("should succeed");
        assert_eq!(result.detected.len(), 1);
        assert_eq!(result.detected[0], "0xpk1");
    }

    #[test]
    fn test_check_validators_epoch_zero_no_underflow() {
        // Current epoch 0, no history
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", None));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 0).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::DetectionInProgress);
    }

    #[test]
    fn test_check_validators_epoch_zero_with_history() {
        // Current epoch 0, signed at epoch 0 => 0-0=0 <= 2, safe
        let slashing_db = Arc::new(MockSlashingDb::new().with_epoch("0xpk1", Some(0)));
        let liveness: Arc<dyn LivenessChecker> = Arc::new(MockLivenessChecker::new(vec![]));
        let service = DoppelgangerService::new(liveness, slashing_db);

        let result = service.check_validators(&[pk("0xpk1")], 0).expect("should succeed");
        assert_eq!(result[0].1, DoppelgangerStatus::Safe);
    }

    // -- DoppelgangerStatus tests --

    #[test]
    fn test_doppelganger_status_eq() {
        assert_eq!(DoppelgangerStatus::Safe, DoppelgangerStatus::Safe);
        assert_eq!(
            DoppelgangerStatus::DetectionInProgress,
            DoppelgangerStatus::DetectionInProgress
        );
        assert_eq!(
            DoppelgangerStatus::DoppelgangerDetected,
            DoppelgangerStatus::DoppelgangerDetected
        );
        assert_ne!(DoppelgangerStatus::Safe, DoppelgangerStatus::DetectionInProgress);
        assert_ne!(DoppelgangerStatus::Safe, DoppelgangerStatus::DoppelgangerDetected);
    }

    #[test]
    fn test_doppelganger_status_debug() {
        let s = format!("{:?}", DoppelgangerStatus::Safe);
        assert!(s.contains("Safe"));
        let s = format!("{:?}", DoppelgangerStatus::DoppelgangerDetected);
        assert!(s.contains("DoppelgangerDetected"));
    }

    #[test]
    fn test_doppelganger_status_clone() {
        let s = DoppelgangerStatus::DetectionInProgress;
        let c = s.clone();
        assert_eq!(s, c);
    }

    // -- DoppelgangerResult tests --

    #[test]
    fn test_doppelganger_result_empty() {
        let r = DoppelgangerResult { safe_validators: vec![], detected: vec![] };
        assert!(r.safe_validators.is_empty());
        assert!(r.detected.is_empty());
    }

    #[test]
    fn test_doppelganger_result_debug() {
        let r = DoppelgangerResult {
            safe_validators: vec!["0xpk1".to_string()],
            detected: vec!["0xpk2".to_string()],
        };
        let s = format!("{:?}", r);
        assert!(s.contains("0xpk1"));
        assert!(s.contains("0xpk2"));
    }

    // -- DoppelgangerError tests --

    #[test]
    fn test_error_liveness_check_failed() {
        let err = DoppelgangerError::LivenessCheckFailed("timeout".to_string());
        let s = format!("{}", err);
        assert!(s.contains("liveness check failed"));
        assert!(s.contains("timeout"));
    }

    #[test]
    fn test_error_slashing_db_error() {
        let err = DoppelgangerError::SlashingDbError("db locked".to_string());
        let s = format!("{}", err);
        assert!(s.contains("slashing DB query failed"));
        assert!(s.contains("db locked"));
    }
}
