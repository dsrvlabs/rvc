//! Pipeline-level slashing protection tests (RF1-02).
//!
//! Guards the wiring `DutyOrchestrator → AttestationService → SignerService →
//! SlashingDb`. A double-vote across two `process_slot` calls must be rejected
//! with **no second signature**, and a slashing-DB error must fail closed.
//!
//! The module-level [`pipeline_fixture`] helper is intentionally reusable —
//! RF1-08 (doppelganger gate / key-import integration) builds on it.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationData as BeaconAttestationData, AttestationDataResponse, AttesterDutiesResponse,
    AttesterDuty, BeaconCommitteeSubscription, BeaconError, BlockRootData, BlockRootResponse,
    Checkpoint as BeaconCheckpoint, ConfigSpecResponse, DataResponse, GenesisResponse,
    ProduceBlockResponse, ProposerDutiesResponse, ProposerPreparation,
    SignedContributionAndProof as BeaconSignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage as BeaconSyncCommitteeMessage, SyncingResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
};
use block_service::{BeaconBlockClient, BlockServiceError, ProduceBlockResponse as BlockProdResp};
use bn_manager::BeaconNodeClient;
use builder::CircuitBreakerState;
use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use duty_tracker::DutyTracker;
use eth_types::{
    ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedValidatorRegistration, Slot,
};
use propagator::{AttestationSubmitter, Propagator};
use rvc::orchestrator::{DutyOrchestrator, OrchestratorConfig, OrchestratorHandle};
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use validator_store::{ValidatorConfig, ValidatorStore};

// ── constants ────────────────────────────────────────────────────────────────

const TEST_GENESIS_TIME: u64 = 1_606_824_023;
const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_INDEX: &str = "1";
const COMMITTEE_INDEX: &str = "0";

/// Slot pair in the same epoch used for the double-vote scenario.
const SLOT_A: Slot = 100; // epoch 3
const SLOT_B: Slot = 101; // epoch 3

// ── shared helpers ───────────────────────────────────────────────────────────

fn create_test_fork_schedule() -> Arc<ForkSchedule> {
    // Electra at epoch 50 so slots 100/101 (epoch 3) stay on the pre-Electra
    // aggregation-bits path (matches other rvc integration tests).
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

fn root_hex(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

/// Build beacon-API attestation data for `slot` with the given vote roots.
///
/// `target.epoch` is derived from `slot / 32` so M-2 validation passes.
fn make_beacon_attestation_data(
    slot: Slot,
    source_epoch: u64,
    source_root: u8,
    target_root: u8,
    head_root: u8,
) -> BeaconAttestationData {
    let target_epoch = slot / SLOTS_PER_EPOCH;
    BeaconAttestationData {
        slot: slot.to_string(),
        index: COMMITTEE_INDEX.to_string(),
        beacon_block_root: root_hex(head_root),
        source: BeaconCheckpoint { epoch: source_epoch.to_string(), root: root_hex(source_root) },
        target: BeaconCheckpoint { epoch: target_epoch.to_string(), root: root_hex(target_root) },
    }
}

fn make_attester_duty(pubkey_hex: &str, slot: Slot) -> AttesterDuty {
    AttesterDuty {
        pubkey: pubkey_hex.to_string(),
        validator_index: VALIDATOR_INDEX.to_string(),
        committee_index: COMMITTEE_INDEX.to_string(),
        committee_length: "4".to_string(),
        committees_at_slot: "1".to_string(),
        validator_committee_index: "0".to_string(),
        slot: slot.to_string(),
    }
}

// ── recording submitter (captures signatures) ────────────────────────────────

/// Counts submitted attestation batches and records how many signed objects
/// were included. Used to assert signature *absence* without relying on logs.
pub struct RecordingSubmitter {
    batch_count: AtomicUsize,
    signature_count: AtomicUsize,
}

impl RecordingSubmitter {
    pub fn new() -> Self {
        Self { batch_count: AtomicUsize::new(0), signature_count: AtomicUsize::new(0) }
    }

    pub fn batch_count(&self) -> usize {
        self.batch_count.load(Ordering::SeqCst)
    }

    pub fn signature_count(&self) -> usize {
        self.signature_count.load(Ordering::SeqCst)
    }
}

impl Default for RecordingSubmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationSubmitter for RecordingSubmitter {
    fn submit_attestation<'a>(
        &'a self,
        attestations: &'a VersionedAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<SubmitAttestationResult, BeaconError>> + Send + 'a>>
    {
        let n = match attestations {
            VersionedAttestation::PreElectra(v) => v.len(),
            VersionedAttestation::Electra(v) => v.len(),
            VersionedAttestation::Fulu(v) => v.len(),
        };
        self.batch_count.fetch_add(1, Ordering::SeqCst);
        self.signature_count.fetch_add(n, Ordering::SeqCst);
        Box::pin(async { Ok(SubmitAttestationResult::Success) })
    }
}

// ── mock block beacon ────────────────────────────────────────────────────────

pub struct NoopBlockBeacon;

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

// ── mock beacon with per-slot attestation data ───────────────────────────────

/// Mock BN that serves attester duties for a fixed pubkey and returns
/// per-slot [`BeaconAttestationData`] from a shared map.
///
/// RF1-08 can mutate `attestation_data_by_slot` between slots (or pre-seed
/// it) without rebuilding the orchestrator.
pub struct PipelineBeacon {
    duty_pubkey: String,
    /// Slots for which `get_attester_duties` should return a duty.
    duty_slots: Vec<Slot>,
    /// Attestation data returned by `get_attestation_data`, keyed by slot.
    attestation_data_by_slot: Mutex<HashMap<Slot, BeaconAttestationData>>,
}

impl PipelineBeacon {
    pub fn new(
        duty_pubkey: String,
        duty_slots: Vec<Slot>,
        attestation_data_by_slot: HashMap<Slot, BeaconAttestationData>,
    ) -> Self {
        Self {
            duty_pubkey,
            duty_slots,
            attestation_data_by_slot: Mutex::new(attestation_data_by_slot),
        }
    }

    /// Replace or insert attestation data for a slot (RF1-08 reuse knob).
    pub fn set_attestation_data(&self, slot: Slot, data: BeaconAttestationData) {
        self.attestation_data_by_slot.lock().unwrap().insert(slot, data);
    }
}

#[async_trait]
impl BeaconNodeClient for PipelineBeacon {
    async fn get_attester_duties(
        &self,
        epoch: u64,
        _indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        let data: Vec<AttesterDuty> = self
            .duty_slots
            .iter()
            .copied()
            .filter(|s| s / SLOTS_PER_EPOCH == epoch)
            .map(|s| make_attester_duty(&self.duty_pubkey, s))
            .collect();
        Ok(beacon::DependentRootResponse {
            dependent_root: root_hex(0xdd),
            execution_optimistic: false,
            data,
        })
    }

    async fn get_attestation_data(
        &self,
        slot: u64,
        _committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        let map = self.attestation_data_by_slot.lock().unwrap();
        let data = map.get(&slot).cloned().ok_or_else(|| {
            BeaconError::HttpError(format!("no attestation data configured for slot {slot}"))
        })?;
        Ok(DataResponse { data })
    }

    async fn get_block_root(&self, _block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        Ok(DataResponse { data: BlockRootData { root: root_hex(0xbb) } })
    }

    // ── unused endpoints ─────────────────────────────────────────────────────

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
    async fn post_sync_committee_duties(
        &self,
        _epoch: u64,
        _indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        Err(BeaconError::HttpError("mock".to_string()))
    }
    async fn submit_sync_committee_messages(
        &self,
        _messages: &[BeaconSyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        Ok(())
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

// ── fixture options + fixture ────────────────────────────────────────────────

/// Knobs for [`pipeline_fixture`].
///
/// RF1-08 reuses these to inject a custom enablement gate and/or a different
/// attestation-data map without re-implementing orchestrator wiring.
pub struct PipelineFixtureOpts {
    /// Attestation data the mock BN returns, keyed by duty slot.
    pub attestation_data_by_slot: HashMap<Slot, BeaconAttestationData>,
    /// Slots for which the mock BN returns attester duties.
    pub duty_slots: Vec<Slot>,
    /// Signing enablement (default: always enabled). RF1-08 plugs
    /// `ForwardWindowMachine` here.
    pub enablement: Arc<dyn SigningEnablement>,
    /// Optional pre-built slashing DB (e.g. a poisoned file-backed DB for the
    /// fail-closed DB-error test). Defaults to a fresh in-memory DB.
    pub slashing_db: Option<Arc<SlashingDb>>,
    /// Initial mock-clock slot. Updated by callers via [`PipelineFixture::set_slot`].
    pub initial_slot: Slot,
}

impl Default for PipelineFixtureOpts {
    fn default() -> Self {
        Self {
            attestation_data_by_slot: HashMap::new(),
            duty_slots: vec![SLOT_A, SLOT_B],
            enablement: always_enabled(),
            slashing_db: None,
            initial_slot: SLOT_A,
        }
    }
}

/// Fully wired pipeline under test.
///
/// Holds the orchestrator plus the shared handles RF1-02/RF1-08 need to drive
/// slots and assert signatures / DB rows.
pub struct PipelineFixture {
    pub orchestrator: DutyOrchestrator<MockSlotClock, RecordingSubmitter, NoopBlockBeacon>,
    pub handle: OrchestratorHandle,
    pub clock: Arc<MockSlotClock>,
    pub slashing_db: Arc<SlashingDb>,
    pub submitter: Arc<RecordingSubmitter>,
    pub beacon: Arc<PipelineBeacon>,
    pub pubkey: PublicKey,
    /// Lowercase hex **without** `0x` — matches `SlashingDb` / signer storage.
    pub pubkey_hex: String,
    /// `0x`-prefixed hex used in duty / pubkey_map keys.
    pub pubkey_hex_0x: String,
}

impl PipelineFixture {
    /// Advance the mock clock to `slot` (required before each `process_slot`).
    pub fn set_slot(&self, slot: Slot) {
        self.clock.set_slot(slot);
    }

    /// Convenience: set clock then call `process_slot`.
    pub async fn process_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<rvc::orchestrator::AttestationResult>, rvc::orchestrator::OrchestratorError>
    {
        self.set_slot(slot);
        self.orchestrator.process_slot(slot).await
    }
}

/// Build a reusable pipeline harness: mock BN + duty tracker + signer with
/// slashing DB + `DutyOrchestrator`.
///
/// This is the RF1-02 / RF1-08 shared fixture contract — keep knobs on
/// [`PipelineFixtureOpts`], not inlined inside individual tests.
pub fn pipeline_fixture(opts: PipelineFixtureOpts) -> PipelineFixture {
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_bytes = pubkey.to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);
    let pubkey_hex_0x = format!("0x{pubkey_hex}");

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

    let slashing_db = opts.slashing_db.unwrap_or_else(|| {
        Arc::new(SlashingDb::open_in_memory().expect("open in-memory slashing db"))
    });
    let signer = Arc::new(
        SignerService::new(composite, Arc::clone(&slashing_db)).with_enablement(opts.enablement),
    );

    let beacon = Arc::new(PipelineBeacon::new(
        pubkey_hex_0x.clone(),
        opts.duty_slots,
        opts.attestation_data_by_slot,
    ));

    let duty_tracker = Arc::new(DutyTracker::new(
        beacon.clone() as Arc<dyn BeaconNodeClient>,
        vec![VALIDATOR_INDEX.to_string()],
    ));

    let submitter = Arc::new(RecordingSubmitter::new());
    let propagator = Arc::new(Propagator::new(Arc::clone(&submitter) as Arc<RecordingSubmitter>));

    let mut map = HashMap::new();
    map.insert(pubkey_hex_0x.clone(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(map));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed: register the validator as signing-enabled so duties
    // are not dropped by the post-import gate.
    validator_store.add_validator(ValidatorConfig::new(pubkey_bytes));

    let clock =
        Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), SLOTS_PER_EPOCH));
    clock.set_slot(opts.initial_slot);

    let config = create_test_config();
    let circuit_breaker = Arc::new(CircuitBreakerState::new(0, 0));
    let attesting_enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let (orchestrator, handle) = DutyOrchestrator::new_with_attesting_enabled(
        Arc::clone(&clock),
        duty_tracker,
        signer,
        propagator,
        beacon.clone() as Arc<dyn BeaconNodeClient>,
        Arc::new(NoopBlockBeacon),
        None,
        validator_store,
        config,
        pubkey_map,
        circuit_breaker,
        attesting_enabled,
    );

    PipelineFixture {
        orchestrator,
        handle,
        clock,
        slashing_db,
        submitter,
        beacon,
        pubkey,
        pubkey_hex,
        pubkey_hex_0x,
    }
}

/// Default double-vote attestation data: same target epoch, different roots.
fn double_vote_attestation_map() -> HashMap<Slot, BeaconAttestationData> {
    let mut map = HashMap::new();
    // First vote: source=2, target=3 (epoch of slot 100), roots A.
    map.insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));
    // Conflicting vote: same target epoch 3, different source + target root.
    map.insert(SLOT_B, make_beacon_attestation_data(SLOT_B, 1, 0x44, 0x55, 0x66));
    map
}

/// Open a file-backed `SlashingDb`, then drop the `attestations` table via a
/// second connection so subsequent stage queries fail with a database error.
fn open_poisoned_slashing_db(path: &std::path::Path) -> Arc<SlashingDb> {
    let db = Arc::new(SlashingDb::open(path).expect("open file-backed slashing db"));
    // Poison while the SlashingDb connection is idle (mutex free). The next
    // stage_* call's SELECT against `attestations`/`watermarks` fails closed.
    {
        let conn = rusqlite::Connection::open(path).expect("second connection for poison");
        conn.execute_batch(
            "DROP TABLE IF EXISTS attestations;
             DROP TABLE IF EXISTS watermarks;
             DROP TABLE IF EXISTS blocks;",
        )
        .expect("drop slashing tables");
    }
    db
}

// ── tests ────────────────────────────────────────────────────────────────────

/// RF1-02: two `process_slot` calls with conflicting AttestationData.
/// First signs; second is rejected by slashing protection — asserted via
/// **absence of a second signature** (not logs).
#[tokio::test]
async fn test_pipeline_rejects_double_vote_across_two_process_slot_calls() {
    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: double_vote_attestation_map(),
        duty_slots: vec![SLOT_A, SLOT_B],
        initial_slot: SLOT_A,
        ..Default::default()
    });

    let results_a = fixture.process_slot(SLOT_A).await.expect("slot A process_slot");
    assert_eq!(results_a.len(), 1, "exactly one duty at slot A");
    assert!(
        results_a[0].success,
        "first attestation must sign successfully; error={:?}",
        results_a[0].error
    );
    assert_eq!(
        fixture.submitter.signature_count(),
        1,
        "first process_slot must emit exactly one signature"
    );

    let results_b = fixture.process_slot(SLOT_B).await.expect("slot B process_slot");
    assert_eq!(results_b.len(), 1, "exactly one duty at slot B");
    assert!(
        !results_b[0].success,
        "conflicting second attestation must be rejected; got success with error={:?}",
        results_b[0].error
    );
    let err = results_b[0].error.as_deref().unwrap_or("");
    assert!(
        err.to_lowercase().contains("sign") || err.to_lowercase().contains("slash"),
        "rejection must surface as a signing/slashing failure, got: {err}"
    );

    // Absence of signature: submitter must still have only the first one.
    assert_eq!(
        fixture.submitter.signature_count(),
        1,
        "second process_slot must not emit a signature (fail-closed double-vote)"
    );
    assert_eq!(fixture.submitter.batch_count(), 1);
}

/// RF1-02: after double-vote rejection the slashing DB holds exactly one
/// attestation row for the pubkey.
#[tokio::test]
async fn test_pipeline_double_vote_leaves_single_db_row() {
    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: double_vote_attestation_map(),
        duty_slots: vec![SLOT_A, SLOT_B],
        initial_slot: SLOT_A,
        ..Default::default()
    });

    let results_a = fixture.process_slot(SLOT_A).await.expect("slot A");
    assert!(results_a[0].success, "first must succeed: {:?}", results_a[0].error);

    let results_b = fixture.process_slot(SLOT_B).await.expect("slot B");
    assert!(!results_b[0].success, "second must fail: {:?}", results_b[0].error);

    let rows = fixture.slashing_db.get_attestations(&fixture.pubkey_hex).expect("get_attestations");
    assert_eq!(
        rows.len(),
        1,
        "after double-vote rejection exactly one attestation row must remain; got {rows:?}"
    );
    assert_eq!(rows[0].target_epoch, SLOT_A / SLOTS_PER_EPOCH);
}

/// RF1-02: a slashing-DB error during `process_slot` fails closed — no signature.
#[tokio::test]
async fn test_pipeline_slashing_db_error_is_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("slashing.sqlite");
    let poisoned = open_poisoned_slashing_db(&db_path);

    let mut att_map = HashMap::new();
    att_map.insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));

    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: att_map,
        duty_slots: vec![SLOT_A],
        slashing_db: Some(poisoned),
        initial_slot: SLOT_A,
        ..Default::default()
    });

    let results = fixture.process_slot(SLOT_A).await.expect("process_slot returns results");
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].success,
        "DB error must fail closed (no successful attestation); error={:?}",
        results[0].error
    );
    let err = results[0].error.as_deref().unwrap_or("");
    assert!(
        err.to_lowercase().contains("sign")
            || err.to_lowercase().contains("slash")
            || err.to_lowercase().contains("database")
            || err.to_lowercase().contains("db"),
        "error should indicate signing/DB failure, got: {err}"
    );

    // Absence of signature is the hard assertion.
    assert_eq!(fixture.submitter.signature_count(), 0, "slashing-DB error must emit no signature");
    assert_eq!(fixture.submitter.batch_count(), 0);
}
