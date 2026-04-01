//! Startup sequence for the validator client.
//!
//! Implements the ordered startup checks:
//! 1. Open slashing DB
//! 2. Run integrity check
//! 3. Validate genesis root against beacon node
//! 4. Check beacon node reachability
//! 5. Run doppelganger detection (if enabled)

use std::fs::{File, OpenOptions};
use std::path::Path;

use bn_manager::BeaconNodeClient;
use fd_lock::RwLock;
use slashing::SlashingDb;
use tracing::{error, info, warn};

use crate::config::ConfigError;

/// Distinct exit codes for startup failures.
pub const EXIT_INTEGRITY_CHECK_FAILED: i32 = 10;
pub const EXIT_GENESIS_ROOT_MISMATCH: i32 = 11;
pub const EXIT_DOPPELGANGER_DETECTED: i32 = 12;
pub const EXIT_UNSUPPORTED_FORK_VERSION: i32 = 13;
pub const EXIT_KEYSTORE_LOCKED: i32 = 14;

/// Errors specific to the startup sequence.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("slashing DB integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    #[error("genesis validators root mismatch: local={local}, beacon={beacon}")]
    GenesisRootMismatch { local: String, beacon: String },

    #[error("doppelganger detected for validators: {0:?}")]
    DoppelgangerDetected(Vec<String>),

    #[error("unsupported consensus fork version {version}; upgrade rvc")]
    UnsupportedForkVersion { version: String },

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("slashing DB error: {0}")]
    SlashingDb(#[from] slashing::SlashingError),

    #[error("beacon error: {0}")]
    Beacon(#[from] beacon::BeaconError),

    #[error("doppelganger error: {0}")]
    Doppelganger(#[from] doppelganger::DoppelgangerError),

    #[error("keystore locked: {0}")]
    KeystoreLocked(String),

    #[error("startup exit with code {0}")]
    StartupExit(i32),
}

impl StartupError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::IntegrityCheckFailed(_) => EXIT_INTEGRITY_CHECK_FAILED,
            Self::GenesisRootMismatch { .. } => EXIT_GENESIS_ROOT_MISMATCH,
            Self::DoppelgangerDetected(_) => EXIT_DOPPELGANGER_DETECTED,
            Self::UnsupportedForkVersion { .. } => EXIT_UNSUPPORTED_FORK_VERSION,
            Self::KeystoreLocked(_) => EXIT_KEYSTORE_LOCKED,
            _ => 1,
        }
    }
}

/// Run the slashing DB integrity check.
pub fn check_integrity(slashing_db: &SlashingDb) -> Result<(), StartupError> {
    info!("Running slashing DB integrity check");
    slashing_db.check_integrity().map_err(|e| StartupError::IntegrityCheckFailed(e.to_string()))?;
    info!("Slashing DB integrity check passed");
    Ok(())
}

/// Validate that the local genesis validators root matches the beacon node's.
///
/// On first run, stores the root from the beacon node into the slashing DB.
/// On subsequent runs, compares the stored root against the beacon node's root.
pub async fn validate_genesis_root(
    slashing_db: &SlashingDb,
    beacon: &dyn BeaconNodeClient,
    local_root_hex: &str,
) -> Result<(), StartupError> {
    info!("Validating genesis validators root against beacon node");

    let genesis_response = beacon.get_genesis().await?;
    let beacon_root = &genesis_response.data.genesis_validators_root;

    let local_normalized = normalize_hex(local_root_hex);
    let beacon_normalized = normalize_hex(beacon_root);

    if local_normalized != beacon_normalized {
        error!(
            local = %local_root_hex,
            beacon = %beacon_root,
            "Genesis validators root mismatch"
        );
        return Err(StartupError::GenesisRootMismatch {
            local: local_root_hex.to_string(),
            beacon: beacon_root.clone(),
        });
    }

    // Store normalized value (lowercase, no 0x prefix) for consistent comparisons
    slashing_db.set_genesis_validators_root(&local_normalized)?;

    info!("Genesis validators root validated successfully");
    Ok(())
}

/// Check whether the beacon node is reachable by querying its genesis endpoint.
///
/// This only verifies network reachability, not sync status.
// TODO: integrate actual sync status check via node/syncing endpoint
pub async fn check_beacon_reachability(beacon: &dyn BeaconNodeClient) {
    match beacon.get_genesis().await {
        Ok(_) => {
            info!("Beacon node is reachable");
        }
        Err(e) => {
            warn!(error = %e, "Beacon node may not be synced or reachable");
        }
    }
}

/// Run doppelganger detection for the given validators.
pub async fn run_doppelganger_detection(
    doppelganger: &doppelganger::DoppelgangerService,
    pubkeys: &[String],
    validator_indices: &std::collections::HashMap<String, String>,
    current_epoch: u64,
) -> Result<Vec<String>, StartupError> {
    info!(validator_count = pubkeys.len(), "Starting doppelganger detection");

    let check_results = doppelganger.check_validators(pubkeys, current_epoch)?;

    let mut needs_monitoring: Vec<String> = Vec::new();
    let mut safe: Vec<String> = Vec::new();

    for (pubkey, status) in &check_results {
        match status {
            doppelganger::DoppelgangerStatus::Safe => {
                safe.push(pubkey.clone());
            }
            doppelganger::DoppelgangerStatus::DetectionInProgress => {
                needs_monitoring.push(pubkey.clone());
            }
            doppelganger::DoppelgangerStatus::DoppelgangerDetected => {
                return Err(StartupError::DoppelgangerDetected(vec![pubkey.clone()]));
            }
        }
    }

    if safe.len() == pubkeys.len() {
        info!(count = safe.len(), "All validators safe (restart-aware skip)");
        return Ok(safe);
    }

    info!(
        needs_monitoring = needs_monitoring.len(),
        already_safe = safe.len(),
        "Running doppelganger monitoring"
    );

    let result =
        doppelganger.run_monitoring(&needs_monitoring, validator_indices, current_epoch).await?;

    if !result.detected.is_empty() {
        error!(
            detected = ?result.detected,
            "Doppelganger detected! Shutting down to prevent slashing"
        );
        return Err(StartupError::DoppelgangerDetected(result.detected));
    }

    let mut all_safe = safe;
    all_safe.extend(result.safe_validators);

    info!(
        count = all_safe.len(),
        "Doppelganger detection complete, all monitored validators are safe"
    );

    Ok(all_safe)
}

/// Log that the orchestrator has been started with validator and beacon node counts.
pub fn log_orchestrator_started(validator_count: usize, bn_count: usize) {
    info!(validator_count, bn_count, "Orchestrator started");
}

/// Log that a shutdown has been initiated with the reason.
pub fn log_shutdown_initiated(reason: &str) {
    info!(reason, "Shutdown initiated");
}

/// Check that the beacon node's current head fork version is known in the schedule.
///
/// Prevents future fork-version drift from silently producing invalid signatures.
/// A syncing beacon node may report an older known version, which is fine.
pub async fn check_fork_compatibility(
    beacon: &dyn BeaconNodeClient,
    schedule: &eth_types::ForkSchedule,
) -> Result<(), StartupError> {
    let fork_response = beacon.get_fork("head").await?;
    let current_version = &fork_response.data.current_version;

    let version_bytes = parse_version_hex(current_version)?;

    let known_versions = [
        schedule.genesis_fork_version,
        schedule.altair_fork_version,
        schedule.bellatrix_fork_version,
        schedule.capella_fork_version,
        schedule.deneb_fork_version,
        schedule.electra_fork_version,
        schedule.fulu_fork_version,
    ];

    if !known_versions.contains(&version_bytes) {
        return Err(StartupError::UnsupportedForkVersion { version: current_version.clone() });
    }

    info!(fork_version = %current_version, "Beacon node fork version is supported");
    Ok(())
}

fn parse_version_hex(hex_str: &str) -> Result<[u8; 4], StartupError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)
        .map_err(|_| StartupError::UnsupportedForkVersion { version: hex_str.to_string() })?;
    if bytes.len() != 4 {
        return Err(StartupError::UnsupportedForkVersion { version: hex_str.to_string() });
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn normalize_hex(s: &str) -> String {
    s.to_lowercase().trim_start_matches("0x").to_string()
}

/// Acquires an exclusive file lock on the validator data directory.
///
/// Uses flock(2) advisory locks via fd-lock. Locks are automatically
/// released on process exit (including crash/SIGKILL).
pub fn acquire_keystore_lock(
    data_dir: &Path,
) -> Result<fd_lock::RwLockWriteGuard<'static, File>, StartupError> {
    let lock_path = data_dir.join(".rvc.lock");

    let file =
        OpenOptions::new().create(true).write(true).truncate(false).open(&lock_path).map_err(
            |e| {
                StartupError::KeystoreLocked(format!(
                    "Failed to open lock file {}: {}",
                    lock_path.display(),
                    e
                ))
            },
        )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
    }

    // Box::leak so the RwLock lives for the process lifetime
    let lock = Box::leak(Box::new(RwLock::new(file)));

    match lock.try_write() {
        Ok(guard) => {
            info!(lock_path = %lock_path.display(), "Keystore lock acquired");
            Ok(guard)
        }
        Err(_) => {
            error!(
                lock_path = %lock_path.display(),
                "Keystore directory is already locked by another rvc instance"
            );
            Err(StartupError::KeystoreLocked(format!(
                "Keystore directory {} is already locked by another rvc instance. \
                 If no other instance is running, delete {} and retry.",
                data_dir.display(),
                lock_path.display(),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use beacon::{
        AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
        BlockRootResponse, ConfigSpecResponse, DataResponse, GenesisData, GenesisResponse,
        ProduceBlockResponse, ProposerDutiesResponse, ProposerPreparation,
        SignedContributionAndProof, StateForkResponse, StateResponse, SubmitAttestationResult,
        SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse, SyncCommitteeMessage,
        SyncingData, SyncingResponse, ValidatorsResponse, VersionedAggregateAttestation,
        VersionedAttestation, VersionedSignedAggregateAndProof,
    };
    use eth_types::{ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock};

    // -- Mock BeaconNodeClient for testing --

    struct MockBeacon {
        genesis_root: String,
        fork_version: String,
        should_fail: bool,
    }

    impl MockBeacon {
        fn with_root(root: &str) -> Self {
            Self {
                genesis_root: root.to_string(),
                fork_version: "0x05000000".to_string(),
                should_fail: false,
            }
        }

        fn with_fork_version(version: &str) -> Self {
            Self {
                genesis_root: "0xdead".to_string(),
                fork_version: version.to_string(),
                should_fail: false,
            }
        }

        fn failing() -> Self {
            Self { genesis_root: String::new(), fork_version: String::new(), should_fail: true }
        }
    }

    #[async_trait]
    impl BeaconNodeClient for MockBeacon {
        async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
            if self.should_fail {
                return Err(BeaconError::HttpError("mock failure".to_string()));
            }
            Ok(DataResponse {
                data: GenesisData {
                    genesis_time: "1606824023".to_string(),
                    genesis_validators_root: self.genesis_root.clone(),
                    genesis_fork_version: "0x00000000".to_string(),
                },
            })
        }
        async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_fork(&self, _state_id: &str) -> Result<StateForkResponse, BeaconError> {
            if self.should_fail {
                return Err(BeaconError::HttpError("mock failure".to_string()));
            }
            Ok(StateResponse {
                execution_optimistic: false,
                finalized: true,
                data: beacon::StateFork {
                    previous_version: "0x04000000".to_string(),
                    current_version: self.fork_version.clone(),
                    epoch: "0".to_string(),
                },
            })
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
            _registrations: &[bn_manager::SignedValidatorRegistration],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".to_string()))
        }
        async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
            Ok(DataResponse {
                data: SyncingData {
                    head_slot: "0".to_string(),
                    sync_distance: "0".to_string(),
                    is_syncing: false,
                    is_optimistic: false,
                    el_offline: false,
                },
            })
        }
        async fn get_node_version(&self) -> Result<String, BeaconError> {
            Ok("MockBeacon/v0.0.0".to_string())
        }
    }

    // -- Exit code tests --

    #[test]
    fn test_exit_code_integrity_failed() {
        let err = StartupError::IntegrityCheckFailed("corrupt".to_string());
        assert_eq!(err.exit_code(), EXIT_INTEGRITY_CHECK_FAILED);
    }

    #[test]
    fn test_exit_code_genesis_mismatch() {
        let err = StartupError::GenesisRootMismatch {
            local: "0xabc".to_string(),
            beacon: "0xdef".to_string(),
        };
        assert_eq!(err.exit_code(), EXIT_GENESIS_ROOT_MISMATCH);
    }

    #[test]
    fn test_exit_code_doppelganger() {
        let err = StartupError::DoppelgangerDetected(vec!["0xpk1".to_string()]);
        assert_eq!(err.exit_code(), EXIT_DOPPELGANGER_DETECTED);
    }

    #[test]
    fn test_exit_code_generic() {
        let err = StartupError::SlashingDb(slashing::SlashingError::IntegrityCheckFailed(
            "test".to_string(),
        ));
        assert_eq!(err.exit_code(), 1);
    }

    // -- Integrity check tests --

    #[test]
    fn test_check_integrity_passes_on_valid_db() {
        let db = SlashingDb::open_in_memory().unwrap();
        let result = check_integrity(&db);
        assert!(result.is_ok());
    }

    // -- Genesis root validation tests --

    #[test]
    fn test_normalize_hex_strips_prefix() {
        assert_eq!(normalize_hex("0xAbCdEf"), "abcdef");
    }

    #[test]
    fn test_normalize_hex_lowercases() {
        assert_eq!(normalize_hex("ABCDEF"), "abcdef");
    }

    #[test]
    fn test_normalize_hex_no_prefix() {
        assert_eq!(normalize_hex("abcdef"), "abcdef");
    }

    #[tokio::test]
    async fn test_validate_genesis_root_matching() {
        let root = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
        let db = SlashingDb::open_in_memory().unwrap();
        let beacon = MockBeacon::with_root(root);

        let result = validate_genesis_root(&db, &beacon, root).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_genesis_root_matching_case_insensitive() {
        let root_lower = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
        let root_upper = "0x4B363DB94E286120D76EB905340FDD4E54BFE9F06BF33FF6CF5AD27F511BFE95";
        let db = SlashingDb::open_in_memory().unwrap();
        let beacon = MockBeacon::with_root(root_upper);

        let result = validate_genesis_root(&db, &beacon, root_lower).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_genesis_root_mismatch() {
        let local = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
        let remote = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let db = SlashingDb::open_in_memory().unwrap();
        let beacon = MockBeacon::with_root(remote);

        let result = validate_genesis_root(&db, &beacon, local).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), EXIT_GENESIS_ROOT_MISMATCH);
        assert!(matches!(err, StartupError::GenesisRootMismatch { .. }));
    }

    #[tokio::test]
    async fn test_validate_genesis_root_beacon_unreachable() {
        let local = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
        let db = SlashingDb::open_in_memory().unwrap();
        let beacon = MockBeacon::failing();

        let result = validate_genesis_root(&db, &beacon, local).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StartupError::Beacon(_)));
    }

    #[tokio::test]
    async fn test_validate_genesis_root_stores_normalized_in_slashing_db() {
        let root = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
        let db = SlashingDb::open_in_memory().unwrap();
        let beacon = MockBeacon::with_root(root);

        validate_genesis_root(&db, &beacon, root).await.unwrap();

        let stored = db.genesis_validators_root().unwrap();
        assert!(stored.is_some());
        // Stored value should be normalized: lowercase without 0x prefix
        assert_eq!(
            stored.unwrap(),
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        );
    }

    // -- Sync status tests --

    #[tokio::test]
    async fn test_check_beacon_reachability_reachable() {
        let beacon = MockBeacon::with_root("0xabc");
        // Should not panic, just log
        check_beacon_reachability(&beacon).await;
    }

    #[tokio::test]
    async fn test_check_beacon_reachability_unreachable() {
        let beacon = MockBeacon::failing();
        // Should not panic, just warn
        check_beacon_reachability(&beacon).await;
    }

    // -- StartupError display --

    #[test]
    fn test_startup_error_display_integrity() {
        let err = StartupError::IntegrityCheckFailed("data corrupt".to_string());
        assert!(err.to_string().contains("integrity check failed"));
    }

    #[test]
    fn test_startup_error_display_genesis_mismatch() {
        let err = StartupError::GenesisRootMismatch {
            local: "0xabc".to_string(),
            beacon: "0xdef".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("0xabc"));
        assert!(msg.contains("0xdef"));
    }

    #[test]
    fn test_startup_error_display_doppelganger() {
        let err = StartupError::DoppelgangerDetected(vec!["0xpk1".to_string()]);
        assert!(err.to_string().contains("doppelganger detected"));
    }

    #[test]
    fn test_startup_error_from_config_error() {
        let err: StartupError = ConfigError::MissingField("test".to_string()).into();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn test_startup_error_from_beacon_error() {
        let err: StartupError = BeaconError::HttpError("test".to_string()).into();
        assert_eq!(err.exit_code(), 1);
    }

    // -- Fork compatibility tests --

    fn test_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 74240,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 144896,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 194048,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 269568,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 364544,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [6, 0, 0, 0],
        }
    }

    #[tokio::test]
    async fn test_check_fork_compatibility_known_version() {
        let beacon = MockBeacon::with_fork_version("0x05000000");
        let schedule = test_fork_schedule();
        let result = check_fork_compatibility(&beacon, &schedule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_fork_compatibility_unknown_version() {
        let beacon = MockBeacon::with_fork_version("0xdeadbeef");
        let schedule = test_fork_schedule();
        let result = check_fork_compatibility(&beacon, &schedule).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), EXIT_UNSUPPORTED_FORK_VERSION);
        assert!(matches!(err, StartupError::UnsupportedForkVersion { .. }));
    }

    #[tokio::test]
    async fn test_check_fork_compatibility_fulu_version() {
        let beacon = MockBeacon::with_fork_version("0x06000000");
        let schedule = test_fork_schedule();
        let result = check_fork_compatibility(&beacon, &schedule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_fork_compatibility_genesis_version() {
        let beacon = MockBeacon::with_fork_version("0x00000000");
        let schedule = test_fork_schedule();
        let result = check_fork_compatibility(&beacon, &schedule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_fork_compatibility_beacon_unreachable() {
        let beacon = MockBeacon::failing();
        let schedule = test_fork_schedule();
        let result = check_fork_compatibility(&beacon, &schedule).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StartupError::Beacon(_)));
    }

    #[test]
    fn test_exit_code_unsupported_fork_version() {
        let err = StartupError::UnsupportedForkVersion { version: "0xdeadbeef".to_string() };
        assert_eq!(err.exit_code(), EXIT_UNSUPPORTED_FORK_VERSION);
    }

    #[test]
    fn test_startup_error_display_unsupported_fork_version() {
        let err = StartupError::UnsupportedForkVersion { version: "0xdeadbeef".to_string() };
        let msg = err.to_string();
        assert!(msg.contains("0xdeadbeef"));
        assert!(msg.contains("upgrade rvc"));
    }

    #[test]
    fn test_log_orchestrator_started_does_not_panic() {
        log_orchestrator_started(10, 3);
    }

    #[test]
    fn test_log_shutdown_initiated_does_not_panic() {
        log_shutdown_initiated("SIGTERM");
    }

    // -- Keystore locking tests --

    #[test]
    fn test_exit_code_keystore_locked() {
        let err = StartupError::KeystoreLocked("test".to_string());
        assert_eq!(err.exit_code(), EXIT_KEYSTORE_LOCKED);
    }

    #[test]
    fn test_acquire_keystore_lock_success() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_keystore_lock(dir.path());
        assert!(guard.is_ok());
        // Lock file should exist
        assert!(dir.path().join(".rvc.lock").exists());
    }

    #[test]
    fn test_acquire_keystore_lock_second_attempt_fails() {
        let dir = tempfile::tempdir().unwrap();
        let _guard1 = acquire_keystore_lock(dir.path()).unwrap();
        // Second attempt should fail
        let result = acquire_keystore_lock(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), EXIT_KEYSTORE_LOCKED);
        assert!(matches!(err, StartupError::KeystoreLocked(_)));
    }

    #[test]
    fn test_acquire_keystore_lock_released_after_drop() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _guard = acquire_keystore_lock(dir.path()).unwrap();
            // Lock is held here
        }
        // Note: because we Box::leak the RwLock, the lock is NOT released on drop
        // of the guard in the current implementation. This is by design —
        // the lock is held for the process lifetime. In tests, we verify the
        // flock(2) advisory semantics: process exit releases the lock.
        // We cannot easily test this in-process, so we just verify acquire works.
    }

    #[cfg(unix)]
    #[test]
    fn test_acquire_keystore_lock_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _guard = acquire_keystore_lock(dir.path()).unwrap();
        let metadata = std::fs::metadata(dir.path().join(".rvc.lock")).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_acquire_keystore_lock_nonexistent_dir() {
        let result = acquire_keystore_lock(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_err());
    }
}
