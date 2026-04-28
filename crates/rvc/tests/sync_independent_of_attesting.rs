//! Integration tests for ISSUE-2.7 (H-7): `sync_enabled` flag is independent
//! of `attesting_enabled`.
//!
//! These tests verify the full orchestrator workflow: the sync-committee
//! messages phase must obey `sync_enabled`, not `attesting_enabled`.  The
//! attestation phase continues to be gated by `attesting_enabled` only.
//!
//! Test strategy:
//! - Build a full `DutyOrchestrator` with a custom mock beacon (`SyncTestBeacon`)
//!   that pre-seeds sync-committee duties and captures submitted sync messages.
//! - Set the mock slot clock to be past the 2/3-slot mark so all phase waits
//!   resolve immediately (zero wait for attestation window and 2/3 window).
//! - Run the orchestrator in a background task.
//! - For the "sync runs" test: wait on a oneshot channel that fires the moment
//!   the first sync-message batch is submitted.
//! - For the "sync disabled" test: sleep briefly, then assert no submissions.
//! - Signal shutdown to interrupt the "wait for next slot" sleep.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription, BeaconError,
    BlockRootData, BlockRootResponse, ConfigSpecResponse, DataResponse,
    ExecutionOptimisticResponse, GenesisResponse, ProduceBlockResponse, ProposerDutiesResponse,
    ProposerPreparation, SignedContributionAndProof as BeaconSignedContributionAndProof,
    StateForkResponse, SubmitAttestationResult, SyncCommitteeContributionResponse,
    SyncCommitteeDutiesResponse, SyncCommitteeMessage as BeaconSyncCommitteeMessage,
    SyncingResponse, ValidatorsResponse, VersionedAggregateAttestation, VersionedAttestation,
    VersionedSignedAggregateAndProof,
};
use block_service::{BeaconBlockClient, BlockServiceError, ProduceBlockResponse as BlockProdResp};
use bn_manager::BeaconNodeClient;
use builder::CircuitBreakerState;
use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
use duty_tracker::DutyTracker;
use eth_types::{
    ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedValidatorRegistration, Slot,
    SyncCommitteeDuty,
};
use propagator::{AttestationSubmitter, Propagator};
use rvc::orchestrator::{DutyOrchestrator, OrchestratorConfig};
use signer::SignerService;
use slashing::SlashingDb;
use timing::MockSlotClock;
use validator_store::ValidatorStore;

// ── constants ────────────────────────────────────────────────────────────────

const TEST_GENESIS_TIME: u64 = 1_606_824_023;

// ── test helpers ─────────────────────────────────────────────────────────────

fn create_test_fork_schedule() -> Arc<ForkSchedule> {
    Arc::new(ForkSchedule {
        genesis_fork_version: [0, 0, 0, 1],
        altair_fork_epoch: 10,
        altair_fork_version: [0, 0, 0, 2],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [0, 0, 0, 3],
        capella_fork_epoch: 30,
        capella_fork_version: [0, 0, 0, 4],
        deneb_fork_epoch: 40,
        deneb_fork_version: [0, 0, 0, 5],
        electra_fork_epoch: 50,
        electra_fork_version: [0, 0, 0, 6],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0, 0, 0, 7],
    })
}

fn create_test_config() -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule())
}

// ── SyncTestBeacon ────────────────────────────────────────────────────────────
//
// A `BeaconNodeClient` mock that:
//   - Returns a valid block root so `SlotContext::capture` succeeds.
//   - Serves sync-committee duties for `duty_pubkey`.
//   - Captures any sync-committee message submissions via an AtomicUsize counter
//     and a oneshot channel (fires on the first submission).
//   - Returns errors for all other endpoints (orchestrator handles gracefully).

struct SyncTestBeacon {
    duty_pubkey: String,
    submitted_count: Arc<AtomicUsize>,
    /// Notified once when the first sync message batch is submitted.
    submitted_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl SyncTestBeacon {
    fn new(
        duty_pubkey: String,
        submitted_count: Arc<AtomicUsize>,
        submitted_tx: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self { duty_pubkey, submitted_count, submitted_tx: Mutex::new(Some(submitted_tx)) }
    }
}

#[async_trait]
impl BeaconNodeClient for SyncTestBeacon {
    async fn get_block_root(&self, _block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        Ok(DataResponse {
            data: BlockRootData {
                root: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            },
        })
    }

    async fn post_sync_committee_duties(
        &self,
        _epoch: u64,
        _indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        Ok(ExecutionOptimisticResponse {
            execution_optimistic: false,
            data: vec![SyncCommitteeDuty {
                pubkey: self.duty_pubkey.clone(),
                validator_index: 1,
                validator_sync_committee_indices: vec![0],
            }],
        })
    }

    async fn submit_sync_committee_messages(
        &self,
        messages: &[BeaconSyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.submitted_count.fetch_add(messages.len(), Ordering::SeqCst);
        // Fire the oneshot on the first submission so the test can proceed
        // without having to poll.
        if let Some(tx) = self.submitted_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Ok(())
    }

    // All other methods return errors; the orchestrator handles them gracefully.
    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_fork(&self, _state_id: &str) -> Result<StateForkResponse, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_validators(&self, _pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_attester_duties(
        &self,
        _epoch: u64,
        _indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_proposer_duties(
        &self,
        _epoch: u64,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
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
        _signed_block: &SignedBlindedBeaconBlock,
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
        _proofs: &[BeaconSignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        Ok(())
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
        _registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn get_node_version(&self) -> Result<String, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
}

// ── NoopBlockBeacon ───────────────────────────────────────────────────────────

struct NoopBlockBeacon;

#[async_trait(?Send)]
impl BeaconBlockClient for NoopBlockBeacon {
    async fn produce_block_v3(
        &self,
        _slot: Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<BlockProdResp, BlockServiceError> {
        Err(BlockServiceError::Beacon("noop".to_string()))
    }
    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
    async fn publish_blinded_block(
        &self,
        _signed_block: &eth_types::SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
    ) -> Result<(), BlockServiceError> {
        Ok(())
    }
}

// ── NoopSubmitter ─────────────────────────────────────────────────────────────

struct NoopSubmitter;

impl AttestationSubmitter for NoopSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        _attestations: &'a VersionedAttestation,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<SubmitAttestationResult, BeaconError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(SubmitAttestationResult::Success) })
    }
}

// ── orchestrator factory ──────────────────────────────────────────────────────

async fn build_integration_orchestrator(
    beacon: Arc<SyncTestBeacon>,
    pk_hex: String,
    pk: crypto::PublicKey,
    sk: SecretKey,
    attesting_enabled: Arc<AtomicBool>,
) -> (
    DutyOrchestrator<MockSlotClock, NoopSubmitter, NoopBlockBeacon>,
    rvc::orchestrator::OrchestratorHandle,
) {
    let mut km = KeyManager::new();
    km.insert(sk);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer = Arc::new(SignerService::new(composite, slashing_db));

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
    // Pre-seed the sync-committee duty cache so the orchestrator doesn't need
    // to reach the BN for it inside run().
    duty_tracker.fetch_sync_committee_duties(0).await.unwrap();

    let mut map = HashMap::new();
    map.insert(pk_hex, pk);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let propagator = Arc::new(Propagator::new(Arc::new(NoopSubmitter)));
    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    let config = create_test_config();

    // Set clock to 2/3 of slot 0 so all phase waits resolve immediately.
    // 12-second slot: attestation @ genesis+4s, 2/3 @ genesis+8s.
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_current_time(TEST_GENESIS_TIME + 8);

    let circuit_breaker = Arc::new(CircuitBreakerState::new(0, 0));

    DutyOrchestrator::new_with_attesting_enabled(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon as Arc<dyn BeaconNodeClient>,
        Arc::new(NoopBlockBeacon),
        None,
        validator_store,
        config,
        pubkey_map,
        circuit_breaker,
        attesting_enabled,
    )
}

// ── test cases ────────────────────────────────────────────────────────────────

/// H-7 integration test — `test_sync_runs_with_attesting_disabled`:
///
/// With `attesting_enabled = false` and `sync_enabled = true` (default),
/// the orchestrator must still produce sync-committee messages.
///
/// RED (before fix): sync messages skipped because they're inside the
///   `if attesting_enabled` guard → `submitted_tx` never fires → timeout.
/// GREEN (after fix): guard is split; `submitted_tx` fires promptly.
///
/// Note: `DutyOrchestrator::run()` is `!Send` because `BeaconBlockClient` uses
/// `#[async_trait(?Send)]`.  We use `tokio::task::LocalSet` to run the future
/// on the current thread without requiring `Send`.
#[tokio::test]
async fn test_sync_runs_with_attesting_disabled() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

    let submitted_count = Arc::new(AtomicUsize::new(0));
    let (submitted_tx, submitted_rx) = tokio::sync::oneshot::channel::<()>();

    let beacon =
        Arc::new(SyncTestBeacon::new(pk_hex.clone(), submitted_count.clone(), submitted_tx));

    // attesting_enabled = false; sync_enabled = true (default)
    let attesting_enabled = Arc::new(AtomicBool::new(false));
    let (mut orchestrator, handle) =
        build_integration_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

    // sync_enabled defaults to true — no explicit call needed, but shown for clarity.

    let local = tokio::task::LocalSet::new();
    let result = local
        .run_until(async move {
            // spawn_local runs on the current thread → no Send requirement.
            let run_task = tokio::task::spawn_local(async move { orchestrator.run().await });

            // Wait for the sync submission notification, or bail after 5 s.
            // With the clock past 2/3 all phase waits are zero, so this fires
            // almost immediately after the task starts.
            let received = tokio::time::timeout(Duration::from_secs(5), submitted_rx).await;

            // Signal shutdown to interrupt the "wait for next slot" sleep.
            handle.shutdown();
            let _ = run_task.await;

            received
        })
        .await;

    assert!(
        result.is_ok(),
        "H-7: sync messages must be produced even when attesting is disabled \
         (sync_enabled defaults to true)"
    );
    assert!(
        submitted_count.load(Ordering::SeqCst) > 0,
        "H-7: at least one sync message must have been submitted to the BN"
    );
}

/// H-7 integration test — `test_sync_disabled_attesting_enabled`:
///
/// With `attesting_enabled = true` and `sync_enabled = false` (explicit),
/// the orchestrator must NOT produce sync-committee messages.
///
/// RED (before fix): sync runs unconditionally → `submitted_count` > 0.
/// GREEN (after fix): `sync_enabled = false` guard prevents the call.
#[tokio::test]
async fn test_sync_disabled_attesting_enabled() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_hex = format!("0x{}", hex::encode(pk.to_bytes()));

    let submitted_count = Arc::new(AtomicUsize::new(0));
    // We don't use the rx side here; the sender is dropped with the beacon.
    let (submitted_tx, _submitted_rx) = tokio::sync::oneshot::channel::<()>();

    let beacon =
        Arc::new(SyncTestBeacon::new(pk_hex.clone(), submitted_count.clone(), submitted_tx));

    // attesting_enabled = true; sync_enabled will be set to false below
    let attesting_enabled = Arc::new(AtomicBool::new(true));
    let (mut orchestrator, handle) =
        build_integration_orchestrator(beacon, pk_hex, pk, sk, attesting_enabled).await;

    // Explicitly disable sync (the flag being tested).
    orchestrator.set_sync_enabled(false);

    let count_after_phases = Arc::new(AtomicUsize::new(0));
    let cap = count_after_phases.clone();

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let run_task = tokio::task::spawn_local(async move { orchestrator.run().await });

            // Give the orchestrator enough time to process the slot phases.
            // All waits are zero because the clock is past 2/3 of slot 0, so
            // 300 ms is more than sufficient for the synchronous mock calls.
            tokio::time::sleep(Duration::from_millis(300)).await;

            // Snapshot the counter before shutdown to avoid a race.
            cap.store(submitted_count.load(Ordering::SeqCst), Ordering::SeqCst);

            // Shutdown interrupts the "wait for next slot" sleep.
            handle.shutdown();
            let _ = run_task.await;
        })
        .await;

    assert_eq!(
        count_after_phases.load(Ordering::SeqCst),
        0,
        "H-7: sync messages must NOT be produced when sync_enabled = false"
    );
}
