//! Reusable pipeline harness for RF1-02 (slashing) and RF1-08 (key-import /
//! doppelganger gate).
//!
//! Wires: mock BN → duty tracker → SignerService → SlashingDb →
//! DutyOrchestrator, with knobs for attestation data, enablement, key-gen
//! watch channel, and whether a signing key is preloaded.

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
use rvc::orchestrator::{
    DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorHandle, PubkeyMap,
};
use signer::{always_enabled, SignerService};
use slashing::SlashingDb;
use timing::MockSlotClock;
use tokio::sync::watch;
use validator_store::{ValidatorConfig, ValidatorStore};

// ── constants ────────────────────────────────────────────────────────────────

pub const TEST_GENESIS_TIME: u64 = 1_606_824_023;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const VALIDATOR_INDEX: &str = "1";
pub const COMMITTEE_INDEX: &str = "0";

/// Slot pair in the same epoch used for the double-vote / import scenarios.
pub const SLOT_A: Slot = 100; // epoch 3
pub const SLOT_B: Slot = 101; // epoch 3

// ── shared helpers ───────────────────────────────────────────────────────────

pub fn create_test_fork_schedule() -> Arc<ForkSchedule> {
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

pub fn create_test_config() -> OrchestratorConfig {
    OrchestratorConfig::new([0xaa; 32], create_test_fork_schedule())
}

pub fn root_hex(byte: u8) -> String {
    format!("0x{}", hex::encode([byte; 32]))
}

/// Build beacon-API attestation data for `slot` with the given vote roots.
///
/// `target.epoch` is derived from `slot / 32` so M-2 validation passes.
pub fn make_beacon_attestation_data(
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

pub fn make_attester_duty(pubkey_hex: &str, slot: Slot) -> AttesterDuty {
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

/// Mock BN that serves attester duties for a (mutable) duty pubkey and returns
/// per-slot [`BeaconAttestationData`] from a shared map.
///
/// `duty_pubkey` is behind a mutex so RF1-08 can seed a **stale** pre-import
/// duty set, then switch the BN response to the imported identity. That couples
/// duty-cache invalidation to participation: a cached epoch that only has the
/// stale pubkey will not match the imported key until `clear_cache` forces a
/// refetch.
pub struct PipelineBeacon {
    duty_pubkey: Mutex<String>,
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
            duty_pubkey: Mutex::new(duty_pubkey),
            duty_slots,
            attestation_data_by_slot: Mutex::new(attestation_data_by_slot),
        }
    }

    /// Replace or insert attestation data for a slot (RF1-08 reuse knob).
    pub fn set_attestation_data(&self, slot: Slot, data: BeaconAttestationData) {
        self.attestation_data_by_slot.lock().unwrap().insert(slot, data);
    }

    /// Change the pubkey returned by subsequent `get_attester_duties` calls.
    ///
    /// Already-cached epoch entries in `DutyTracker` are **not** updated; a
    /// key-gen cache clear (or other invalidation) is required before the new
    /// identity appears in duty matching. Used by RF1-08 to model a stale
    /// pre-import duty set.
    pub fn set_duty_pubkey(&self, duty_pubkey: String) {
        *self.duty_pubkey.lock().unwrap() = duty_pubkey;
    }
}

#[async_trait]
impl BeaconNodeClient for PipelineBeacon {
    async fn get_attester_duties(
        &self,
        epoch: u64,
        _indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        let duty_pubkey = self.duty_pubkey.lock().unwrap().clone();
        let data: Vec<AttesterDuty> = self
            .duty_slots
            .iter()
            .copied()
            .filter(|s| s / SLOTS_PER_EPOCH == epoch)
            .map(|s| make_attester_duty(&duty_pubkey, s))
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
/// RF1-08 reuses these to inject a custom enablement gate, a real key-gen
/// watch channel, and an empty (import-ready) key set.
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
    /// When `Some`, the orchestrator uses this receiver instead of the discarded
    /// channel from [`OrchestratorDeps::for_test`]. Pair with a sender shared
    /// with `KeystoreManagerAdapter` (RF1-08).
    pub key_gen_rx: Option<watch::Receiver<u64>>,
    /// When `false`, start with an empty `CompositeSigner` + empty `PubkeyMap`
    /// and do not register the identity in `ValidatorStore`. The mock BN still
    /// serves duties for [`Self::duty_identity`]. Default `true` (RF1-02).
    pub preload_signing_key: bool,
    /// Public key identity for mock BN duties / hex fields. When `None`, a
    /// fresh key is generated. RF1-08 passes the key that will be imported.
    pub duty_identity: Option<PublicKey>,
}

impl Default for PipelineFixtureOpts {
    fn default() -> Self {
        Self {
            attestation_data_by_slot: HashMap::new(),
            duty_slots: vec![SLOT_A, SLOT_B],
            enablement: always_enabled(),
            slashing_db: None,
            initial_slot: SLOT_A,
            key_gen_rx: None,
            preload_signing_key: true,
            duty_identity: None,
        }
    }
}

/// Fully wired pipeline under test.
///
/// Holds the orchestrator plus the shared handles RF1-02/RF1-08 need to drive
/// slots and assert signatures / DB rows / duty-cache invalidation.
pub struct PipelineFixture {
    pub orchestrator: DutyOrchestrator<MockSlotClock, RecordingSubmitter, NoopBlockBeacon>,
    pub handle: OrchestratorHandle,
    pub clock: Arc<MockSlotClock>,
    pub slashing_db: Arc<SlashingDb>,
    pub submitter: Arc<RecordingSubmitter>,
    pub beacon: Arc<PipelineBeacon>,
    pub duty_tracker: Arc<DutyTracker>,
    pub pubkey_map: PubkeyMap,
    pub composite_signer: Arc<CompositeSigner>,
    pub validator_store: Arc<ValidatorStore>,
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
    if opts.preload_signing_key {
        // RF1-02 path: generate a local signing key and preload it into the
        // composite signer + pubkey_map + validator_store.
        assert!(
            opts.duty_identity.is_none(),
            "pipeline_fixture: preload_signing_key=true with duty_identity is unsupported \
             (PublicKey alone cannot load a signing key); use preload_signing_key=false \
             and import via KeystoreManagerAdapter"
        );
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let pubkey_hex_0x = format!("0x{pubkey_hex}");

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));

        finish_fixture(opts, composite, pubkey, pubkey_hex, pubkey_hex_0x, true)
    } else {
        // RF1-08 path: empty signer/map; mock BN serves duties for the
        // identity that the test will import.
        let pubkey = opts
            .duty_identity
            .clone()
            .expect("pipeline_fixture: duty_identity is required when preload_signing_key=false");
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let pubkey_hex_0x = format!("0x{pubkey_hex}");
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));

        finish_fixture(opts, composite, pubkey, pubkey_hex, pubkey_hex_0x, false)
    }
}

fn finish_fixture(
    opts: PipelineFixtureOpts,
    composite: Arc<CompositeSigner>,
    pubkey: PublicKey,
    pubkey_hex: String,
    pubkey_hex_0x: String,
    preload: bool,
) -> PipelineFixture {
    let pubkey_bytes = pubkey.to_bytes();

    let slashing_db = opts.slashing_db.unwrap_or_else(|| {
        Arc::new(SlashingDb::open_in_memory().expect("open in-memory slashing db"))
    });
    let signer = Arc::new(
        SignerService::new(Arc::clone(&composite), Arc::clone(&slashing_db))
            .with_enablement(opts.enablement),
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
    if preload {
        map.insert(pubkey_hex_0x.clone(), pubkey.clone());
    }
    let pubkey_map: PubkeyMap = Arc::new(parking_lot::RwLock::new(map));

    let validator_store = Arc::new(ValidatorStore::new([0xaau8; 20], 30_000_000));
    // D-3 fail-closed: register the validator as signing-enabled so duties
    // are not dropped by the post-import store gate (unless import path starts empty).
    if preload {
        validator_store.add_validator(ValidatorConfig::new(pubkey_bytes));
    }

    let clock =
        Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), SLOTS_PER_EPOCH));
    clock.set_slot(opts.initial_slot);

    let config = create_test_config();
    let circuit_breaker = Arc::new(CircuitBreakerState::new(0, 0));
    let attesting_enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let mut deps = OrchestratorDeps::for_test(
        Arc::clone(&clock),
        Arc::clone(&duty_tracker),
        signer,
        propagator,
        beacon.clone() as Arc<dyn BeaconNodeClient>,
        Arc::new(NoopBlockBeacon),
        None,
        Arc::clone(&validator_store),
        config,
        Arc::clone(&pubkey_map),
    );
    if let Some(key_gen_rx) = opts.key_gen_rx {
        deps.key_gen_rx = key_gen_rx;
    }
    deps.circuit_breaker = circuit_breaker;
    deps.attesting_enabled = attesting_enabled;

    let (orchestrator, handle) = DutyOrchestrator::new(deps);

    PipelineFixture {
        orchestrator,
        handle,
        clock,
        slashing_db,
        submitter,
        beacon,
        duty_tracker,
        pubkey_map,
        composite_signer: composite,
        validator_store,
        pubkey,
        pubkey_hex,
        pubkey_hex_0x,
    }
}

/// Default double-vote attestation data: same target epoch, different roots.
pub fn double_vote_attestation_map() -> HashMap<Slot, BeaconAttestationData> {
    let mut map = HashMap::new();
    // First vote: source=2, target=3 (epoch of slot 100), roots A.
    map.insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));
    // Conflicting vote: same target epoch 3, different source + target root.
    map.insert(SLOT_B, make_beacon_attestation_data(SLOT_B, 1, 0x44, 0x55, 0x66));
    map
}

/// Open a file-backed `SlashingDb`, then drop the `attestations` table via a
/// second connection so subsequent stage queries fail with a database error.
pub fn open_poisoned_slashing_db(path: &std::path::Path) -> Arc<SlashingDb> {
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
