//! Main duty orchestrator implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::signer::SignerService;
use crate::timing::{SlotClock, SLOTS_PER_EPOCH};
use beacon::{Attestation, AttesterDuty, BeaconClient};
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use propagator::{AttestationSubmitter, Propagator};
use eth_types::{Fork, Root, Slot};
use metrics::definitions::{
    attestation_status, orchestrator_result, RVC_ATTESTATIONS_TOTAL,
    RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS, RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL,
    RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL, RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS,
};

use super::error::OrchestratorError;

/// Default timeout for beacon client API calls in seconds.
const BEACON_CALL_TIMEOUT_SECS: u64 = 4;

/// Configuration for the duty orchestrator.
#[derive(Clone)]
pub struct OrchestratorConfig {
    pub genesis_validators_root: Root,
    pub fork: Fork,
    pub shutdown_timeout: Duration,
}

impl OrchestratorConfig {
    pub fn new(genesis_validators_root: Root, fork: Fork) -> Self {
        Self { genesis_validators_root, fork, shutdown_timeout: Duration::from_secs(30) }
    }

    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }
}

/// Handle for controlling the orchestrator.
pub struct OrchestratorHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl OrchestratorHandle {
    /// Signals the orchestrator to shut down gracefully.
    ///
    /// The orchestrator will complete processing of the current slot (if any)
    /// before stopping. The signal is delivered via a watch channel, ensuring
    /// the orchestrator receives it even if waiting for the next slot.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Result of processing a single attestation duty.
#[derive(Debug)]
pub struct AttestationResult {
    pub validator_index: String,
    pub slot: Slot,
    pub success: bool,
    pub error: Option<String>,
}

/// Main orchestrator for coordinating attestation duties.
pub struct DutyOrchestrator<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    clock: Arc<C>,
    duty_tracker: Arc<DutyTracker>,
    signer: Arc<SignerService>,
    propagator: Arc<Propagator<S>>,
    beacon: Arc<BeaconClient>,
    config: OrchestratorConfig,
    pubkey_map: HashMap<String, PublicKey>,
    shutdown_rx: watch::Receiver<bool>,
}

impl<C, S> DutyOrchestrator<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    /// Creates a new DutyOrchestrator with the given dependencies.
    pub fn new(
        clock: Arc<C>,
        duty_tracker: Arc<DutyTracker>,
        signer: Arc<SignerService>,
        propagator: Arc<Propagator<S>>,
        beacon: Arc<BeaconClient>,
        config: OrchestratorConfig,
        pubkey_map: HashMap<String, PublicKey>,
    ) -> (Self, OrchestratorHandle) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let orchestrator = Self {
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
            shutdown_rx,
        };

        let handle = OrchestratorHandle { shutdown_tx };

        (orchestrator, handle)
    }

    /// Runs the orchestrator main loop.
    pub async fn run(&mut self) -> Result<(), OrchestratorError> {
        info!("Starting duty orchestrator");

        loop {
            if *self.shutdown_rx.borrow() {
                info!("Shutdown signal received, stopping orchestrator");
                return Ok(());
            }

            let current_slot = match self.clock.current_slot() {
                Ok(slot) => slot,
                Err(e) => {
                    warn!(error = %e, "Failed to get current slot, waiting...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let current_epoch = current_slot / SLOTS_PER_EPOCH;

            if !self.duty_tracker.is_epoch_cached(current_epoch).await {
                debug!(epoch = current_epoch, "Fetching duties for current epoch");
                if let Err(e) = self.duty_tracker.fetch_duties_for_epoch(current_epoch).await {
                    warn!(epoch = current_epoch, error = %e, "Failed to fetch duties for epoch");
                }
            }

            let next_epoch = current_epoch + 1;
            if !self.duty_tracker.is_epoch_cached(next_epoch).await {
                debug!(epoch = next_epoch, "Prefetching duties for next epoch");
                if let Err(e) = self.duty_tracker.fetch_duties_for_epoch(next_epoch).await {
                    warn!(epoch = next_epoch, error = %e, "Failed to prefetch duties for next epoch");
                }
            }

            let time_until_attestation = self.clock.time_until_attestation(current_slot)?;

            if !time_until_attestation.is_zero() {
                debug!(
                    slot = current_slot,
                    wait_ms = time_until_attestation.as_millis(),
                    "Waiting for attestation time"
                );

                tokio::select! {
                    _ = tokio::time::sleep(time_until_attestation) => {}
                    _ = self.shutdown_rx.changed() => {
                        if *self.shutdown_rx.borrow() {
                            info!("Shutdown signal received during wait");
                            return Ok(());
                        }
                    }
                }
            }

            if *self.shutdown_rx.borrow() {
                info!("Shutdown signal received, stopping orchestrator");
                return Ok(());
            }

            if let Err(e) = self.process_slot(current_slot).await {
                match &e {
                    OrchestratorError::SlotMissed { slot, current_slot } => {
                        warn!(slot = slot, current_slot = current_slot, "Missed slot");
                        RVC_ATTESTATIONS_TOTAL
                            .with_label_values(&[attestation_status::SKIPPED])
                            .inc();
                    }
                    OrchestratorError::NoDutiesForSlot { slot } => {
                        debug!(slot = slot, "No duties for slot");
                    }
                    _ => {
                        error!(slot = current_slot, error = %e, "Error processing slot");
                    }
                }
            }

            let next_slot = current_slot + 1;
            let time_until_next_slot = self.clock.time_until_slot(next_slot)?;

            if !time_until_next_slot.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(time_until_next_slot) => {}
                    _ = self.shutdown_rx.changed() => {
                        if *self.shutdown_rx.borrow() {
                            info!("Shutdown signal received waiting for next slot");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    /// Processes all attestation duties for a given slot.
    ///
    /// Validators are processed sequentially within each slot to work with
    /// the non-Send/Sync `SlashingDb`. For high validator counts, consider
    /// making `SlashingDb` thread-safe with proper locking for concurrent processing.
    pub async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttestationResult>, OrchestratorError> {
        let _timer =
            RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS.with_label_values(&[]).start_timer();

        info!(slot = slot, "Processing attestation duties for slot");

        let current_slot = self.clock.current_slot()?;

        if current_slot > slot {
            RVC_ORCHESTRATOR_MISSED_SLOTS_TOTAL.with_label_values(&[]).inc();
            return Err(OrchestratorError::SlotMissed { slot, current_slot });
        }

        let duties = self.get_duties_for_slot(slot).await?;

        if duties.is_empty() {
            debug!(slot = slot, "No attestation duties for this slot");
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::NO_DUTIES])
                .inc();
            return Err(OrchestratorError::NoDutiesForSlot { slot });
        }

        info!(slot = slot, duty_count = duties.len(), "Found attestation duties");
        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(duties.len() as f64);

        let mut results = Vec::new();

        for duty in duties {
            let result = self.process_attestation_duty(duty).await;

            if result.success {
                info!(
                    validator = %result.validator_index,
                    slot = result.slot,
                    "Attestation completed successfully"
                );
            } else {
                warn!(
                    validator = %result.validator_index,
                    slot = result.slot,
                    error = ?result.error,
                    "Attestation failed"
                );
            }
            results.push(result);
        }

        RVC_ORCHESTRATOR_ACTIVE_ATTESTATIONS.set(0.0);

        let success_count = results.iter().filter(|r| r.success).count();
        let failure_count = results.len() - success_count;

        if failure_count > 0 {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::FAILED])
                .inc();
        } else {
            RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL
                .with_label_values(&[orchestrator_result::SUCCESS])
                .inc();
        }

        info!(
            slot = slot,
            total = results.len(),
            success = success_count,
            failed = failure_count,
            "Slot processing complete"
        );

        Ok(results)
    }

    async fn get_duties_for_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<AttesterDuty>, OrchestratorError> {
        if self.pubkey_map.is_empty() {
            return Ok(Vec::new());
        }

        let epoch = slot / SLOTS_PER_EPOCH;

        if !self.duty_tracker.is_epoch_cached(epoch).await {
            self.duty_tracker.fetch_duties_for_epoch(epoch).await?;
        }

        // Normalize all pubkeys to lowercase without 0x prefix for efficient lookup
        let normalized_pubkeys: std::collections::HashSet<String> =
            self.pubkey_map.keys().map(|k| Self::normalize_pubkey(k)).collect();

        let mut duties = Vec::new();
        // Check a reasonable range of committee indices (typical max is 64 per slot)
        for committee_index in 0..64 {
            if let Ok(duty) = self.duty_tracker.get_duty(slot, committee_index).await {
                let normalized_duty_pubkey = Self::normalize_pubkey(&duty.pubkey);
                if normalized_pubkeys.contains(&normalized_duty_pubkey) {
                    duties.push(duty);
                }
            }
        }

        Ok(duties)
    }

    /// Normalizes a pubkey to lowercase without 0x/0X prefix for comparison.
    fn normalize_pubkey(pubkey: &str) -> String {
        let without_prefix =
            pubkey.strip_prefix("0x").or_else(|| pubkey.strip_prefix("0X")).unwrap_or(pubkey);
        without_prefix.to_lowercase()
    }

    async fn process_attestation_duty(&self, duty: AttesterDuty) -> AttestationResult {
        let validator_index = duty.validator_index.clone();

        let slot: Slot = match duty.slot.parse() {
            Ok(s) => s,
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot: 0,
                    success: false,
                    error: Some(format!("Invalid slot in duty: {}", duty.slot)),
                };
            }
        };

        let committee_index: u64 = match duty.committee_index.parse() {
            Ok(c) => c,
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!(
                        "Invalid committee_index in duty: {}",
                        duty.committee_index
                    )),
                };
            }
        };

        debug!(
            validator = %validator_index,
            slot = slot,
            committee_index = committee_index,
            "Processing attestation duty"
        );

        let pubkey = match self.find_pubkey(&duty.pubkey) {
            Some(pk) => pk,
            None => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Public key not found: {}", duty.pubkey)),
                };
            }
        };

        // Apply timeout to beacon client call to prevent blocking
        let attestation_data_result = tokio::time::timeout(
            Duration::from_secs(BEACON_CALL_TIMEOUT_SECS),
            self.beacon.get_attestation_data(slot, committee_index),
        )
        .await;

        let attestation_data_response = match attestation_data_result {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to get attestation data: {}", e)),
                };
            }
            Err(_) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some("Timeout getting attestation data from beacon node".to_string()),
                };
            }
        };

        let beacon_attestation_data = attestation_data_response.data;

        let crypto_attestation_data = match Self::convert_attestation_data(&beacon_attestation_data)
        {
            Ok(data) => data,
            Err(e) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to convert attestation data: {}", e)),
                };
            }
        };

        let signature = match self.signer.sign_attestation(
            &crypto_attestation_data,
            &pubkey,
            &self.config.fork,
            self.config.genesis_validators_root,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(format!("Failed to sign attestation: {}", e)),
                };
            }
        };

        let attester_index: u64 = match validator_index.parse() {
            Ok(v) => v,
            Err(_) => {
                let error = format!("Invalid validator_index in duty: {}", validator_index);
                return AttestationResult {
                    validator_index,
                    slot,
                    success: false,
                    error: Some(error),
                };
            }
        };

        let attestation = Attestation {
            committee_index,
            attester_index,
            data: beacon_attestation_data,
            signature: format!("0x{}", hex::encode(signature.to_bytes())),
        };

        match self.propagator.propagate(attestation).await {
            Ok(()) => AttestationResult { validator_index, slot, success: true, error: None },
            Err(e) => AttestationResult {
                validator_index,
                slot,
                success: false,
                error: Some(format!("Failed to propagate attestation: {}", e)),
            },
        }
    }

    /// Finds a public key by matching against duty pubkey.
    ///
    /// Pubkeys are matched case-insensitively and with/without "0x" prefix.
    fn find_pubkey(&self, duty_pubkey: &str) -> Option<PublicKey> {
        // Try exact match first
        if let Some(pk) = self.pubkey_map.get(duty_pubkey) {
            return Some(pk.clone());
        }

        // Try with/without 0x prefix
        let normalized_pubkey = if duty_pubkey.starts_with("0x") {
            duty_pubkey.to_string()
        } else {
            format!("0x{}", duty_pubkey)
        };

        if let Some(pk) = self.pubkey_map.get(&normalized_pubkey) {
            return Some(pk.clone());
        }

        // Normalize for case-insensitive matching
        let duty_normalized = Self::normalize_pubkey(duty_pubkey);

        for (key, pk) in &self.pubkey_map {
            if Self::normalize_pubkey(key) == duty_normalized {
                return Some(pk.clone());
            }
        }

        None
    }

    fn convert_attestation_data(
        beacon_data: &beacon::AttestationData,
    ) -> Result<eth_types::AttestationData, OrchestratorError> {
        let slot: u64 = beacon_data
            .slot
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid slot".to_string()))?;

        let index: u64 = beacon_data
            .index
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid index".to_string()))?;

        let beacon_block_root = Self::parse_hex_root(&beacon_data.beacon_block_root)?;

        let source_epoch: u64 = beacon_data
            .source
            .epoch
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid source epoch".to_string()))?;

        let source_root = Self::parse_hex_root(&beacon_data.source.root)?;

        let target_epoch: u64 = beacon_data
            .target
            .epoch
            .parse()
            .map_err(|_| OrchestratorError::ParseError("Invalid target epoch".to_string()))?;

        let target_root = Self::parse_hex_root(&beacon_data.target.root)?;

        Ok(eth_types::AttestationData {
            slot,
            index,
            beacon_block_root,
            source: eth_types::Checkpoint { epoch: source_epoch, root: source_root },
            target: eth_types::Checkpoint { epoch: target_epoch, root: target_root },
        })
    }

    fn parse_hex_root(hex_str: &str) -> Result<Root, OrchestratorError> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        let bytes = hex::decode(hex_str)
            .map_err(|e| OrchestratorError::ParseError(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 32 {
            return Err(OrchestratorError::ParseError(format!(
                "Invalid root length: expected 32, got {}",
                bytes.len()
            )));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Ok(root)
    }
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
mod tests {
    use super::*;
    use crate::timing::MockSlotClock;
    use beacon::BeaconClientConfig;
    use crypto::{KeyManager, SecretKey};
    use slashing::SlashingDb;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_GENESIS_TIME: u64 = 1606824023;

    fn create_test_fork() -> Fork {
        Fork {
            previous_version: [0x00, 0x00, 0x00, 0x01],
            current_version: [0x00, 0x00, 0x00, 0x02],
            epoch: 0,
        }
    }

    fn create_test_config() -> OrchestratorConfig {
        OrchestratorConfig::new([0xaa; 32], create_test_fork())
    }

    struct MockSubmitter {
        call_count: AtomicUsize,
        should_succeed: std::sync::atomic::AtomicBool,
    }

    impl MockSubmitter {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
                should_succeed: std::sync::atomic::AtomicBool::new(true),
            }
        }

        #[allow(dead_code)]
        fn set_should_succeed(&self, value: bool) {
            self.should_succeed.store(value, Ordering::SeqCst);
        }

        #[allow(dead_code)]
        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl AttestationSubmitter for MockSubmitter {
        fn submit_attestation<'a>(
            &'a self,
            _attestations: &'a [Attestation],
        ) -> Pin<
            Box<
                dyn Future<Output = Result<beacon::SubmitAttestationResult, beacon::BeaconError>>
                    + Send
                    + 'a,
            >,
        > {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let should_succeed = self.should_succeed.load(Ordering::SeqCst);
            Box::pin(async move {
                if should_succeed {
                    Ok(beacon::SubmitAttestationResult::Success)
                } else {
                    Err(beacon::BeaconError::Timeout)
                }
            })
        }
    }

    #[test]
    fn test_orchestrator_config_new() {
        let config = OrchestratorConfig::new([0xbb; 32], create_test_fork());
        assert_eq!(config.genesis_validators_root, [0xbb; 32]);
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_orchestrator_config_with_shutdown_timeout() {
        let config = OrchestratorConfig::new([0xcc; 32], create_test_fork())
            .with_shutdown_timeout(Duration::from_secs(60));
        assert_eq!(config.shutdown_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_parse_hex_root_with_prefix() {
        let root = DutyOrchestrator::<MockSlotClock, MockSubmitter>::parse_hex_root(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        assert_eq!(root, [0x11; 32]);
    }

    #[test]
    fn test_parse_hex_root_without_prefix() {
        let root = DutyOrchestrator::<MockSlotClock, MockSubmitter>::parse_hex_root(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        assert_eq!(root, [0x22; 32]);
    }

    #[test]
    fn test_parse_hex_root_invalid_length() {
        let result =
            DutyOrchestrator::<MockSlotClock, MockSubmitter>::parse_hex_root("0x1111111111");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_root_invalid_hex() {
        let result = DutyOrchestrator::<MockSlotClock, MockSubmitter>::parse_hex_root("0xgggggggg");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_attestation_data_success() {
        let beacon_data = beacon::AttestationData {
            slot: "1000".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let crypto_data =
            DutyOrchestrator::<MockSlotClock, MockSubmitter>::convert_attestation_data(
                &beacon_data,
            )
            .unwrap();

        assert_eq!(crypto_data.slot, 1000);
        assert_eq!(crypto_data.index, 5);
        assert_eq!(crypto_data.beacon_block_root, [0x11; 32]);
        assert_eq!(crypto_data.source.epoch, 100);
        assert_eq!(crypto_data.source.root, [0x22; 32]);
        assert_eq!(crypto_data.target.epoch, 101);
        assert_eq!(crypto_data.target.root, [0x33; 32]);
    }

    #[test]
    fn test_convert_attestation_data_invalid_slot() {
        let beacon_data = beacon::AttestationData {
            slot: "invalid".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let result = DutyOrchestrator::<MockSlotClock, MockSubmitter>::convert_attestation_data(
            &beacon_data,
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_orchestrator_handle_shutdown() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (mut orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
        );

        handle.shutdown();

        let result = orchestrator.run().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_orchestrator_no_duties_for_slot() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
        );

        let result = orchestrator.process_slot(100).await;

        assert!(matches!(result, Err(OrchestratorError::NoDutiesForSlot { slot: 100 })));
    }

    #[tokio::test]
    async fn test_orchestrator_slot_missed() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(105);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
        );

        let result = orchestrator.process_slot(100).await;

        assert!(matches!(result, Err(OrchestratorError::SlotMissed { .. })));
    }

    #[test]
    fn test_attestation_result_success() {
        let result = AttestationResult {
            validator_index: "1234".to_string(),
            slot: 100,
            success: true,
            error: None,
        };
        assert!(result.success);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_attestation_result_failure() {
        let result = AttestationResult {
            validator_index: "1234".to_string(),
            slot: 100,
            success: false,
            error: Some("Test error".to_string()),
        };
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("Test error"));
    }

    #[tokio::test]
    async fn test_orchestrator_with_validator_keys() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        clock.set_slot(100);

        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1234".to_string()]));

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let key_manager = Arc::new(key_manager);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(pubkey_hex, pubkey);

        let (_orchestrator, handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
        );

        assert!(!*handle.shutdown_tx.borrow());
        handle.shutdown();
        assert!(*handle.shutdown_tx.borrow());
    }

    #[tokio::test]
    async fn test_find_pubkey_exact_match() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(pubkey_hex.clone(), pubkey.clone());

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
        );

        let found = orchestrator.find_pubkey(&pubkey_hex);
        assert!(found.is_some());
        assert_eq!(found.unwrap().to_bytes(), pubkey.to_bytes());
    }

    #[tokio::test]
    async fn test_find_pubkey_case_insensitive() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let config = create_test_config();
        let mut pubkey_map = HashMap::new();
        pubkey_map.insert(pubkey_hex.to_uppercase(), pubkey.clone());

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
        );

        let found = orchestrator.find_pubkey(&pubkey_hex.to_lowercase());
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn test_find_pubkey_not_found() {
        let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
        let beacon_config = BeaconClientConfig::new("http://localhost:5052");
        let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = Arc::new(SignerService::new(key_manager, slashing_db));

        let submitter = Arc::new(MockSubmitter::new());
        let propagator = Arc::new(Propagator::new(submitter));

        let config = create_test_config();
        let pubkey_map = HashMap::new();

        let (orchestrator, _handle) = DutyOrchestrator::new(
            clock,
            duty_tracker,
            signer,
            propagator,
            beacon,
            config,
            pubkey_map,
        );

        let found = orchestrator.find_pubkey("0x1234567890abcdef");
        assert!(found.is_none());
    }
}
