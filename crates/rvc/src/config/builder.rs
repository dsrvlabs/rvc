//! Service builder for constructing all services from configuration.

#![allow(clippy::arc_with_non_send_sync)]
#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::beacon_adapter::BeaconBlockAdapter;
use crate::doppelganger_adapter::{BeaconLivenessAdapter, SlashingDbReaderAdapter};
use crate::orchestrator::{DutyOrchestrator, OrchestratorConfig, OrchestratorHandle};
use beacon::{BeaconClient, BeaconClientConfig};
use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};
use builder::BuilderService;
use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey};
use doppelganger::DoppelgangerService;
use duty_tracker::DutyTracker;
use eth_types::{ForkSchedule, Root};
use propagator::{AttestationSubmitter, Propagator};
use signer::SignerService;
use slashing::SlashingDb;
use timing::{SlotClock, SystemSlotClock};
use validator_store::ValidatorStore;

use super::error::ConfigError;
use super::types::Config;

/// Contains all the built services ready for use.
pub struct BuiltServices<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    pub beacon: Arc<dyn BeaconNodeClient>,
    pub beacon_client: Arc<BeaconClient>,
    pub composite_signer: Arc<CompositeSigner>,
    pub slashing_db: Arc<SlashingDb>,
    pub signer: Arc<SignerService>,
    pub propagator: Arc<Propagator<S>>,
    pub duty_tracker: Arc<DutyTracker>,
    pub slot_clock: Arc<C>,
    pub validator_store: Arc<ValidatorStore>,
    pub pubkey_map: HashMap<String, PublicKey>,
    pub genesis_validators_root: Root,
    pub fork_schedule: Arc<ForkSchedule>,
    pub doppelganger_service: Option<DoppelgangerService>,
    pub builder_service: Option<Arc<BuilderService>>,
}

/// Builder for constructing services from configuration.
pub struct ServiceBuilder {
    config: Config,
}

impl ServiceBuilder {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn build_beacon(&self) -> Result<Arc<BeaconClient>, ConfigError> {
        let beacon_config = BeaconClientConfig::new(&self.config.beacon_url)
            .with_timeout(Duration::from_secs(30))
            .with_max_retries(3);

        let client = BeaconClient::new(beacon_config)?;
        info!(url = %self.config.beacon_url, "Created beacon client");
        Ok(Arc::new(client))
    }

    pub fn build_bn_manager(&self) -> Result<Arc<BnManager>, ConfigError> {
        let endpoints = self.config.effective_beacon_nodes();
        let config = BnManagerConfig::new(endpoints.clone());
        let manager = BnManager::new(config).map_err(|e| {
            ConfigError::InvalidBeaconUrl(format!("failed to create BnManager: {}", e))
        })?;
        info!(endpoints = ?endpoints, "Created BnManager with {} beacon nodes", endpoints.len());
        Ok(Arc::new(manager))
    }

    pub fn build_doppelganger_service(
        &self,
        beacon: Arc<BeaconClient>,
        slashing_db: Arc<SlashingDb>,
    ) -> DoppelgangerService {
        let liveness_checker = Arc::new(BeaconLivenessAdapter::new(beacon));
        let slashing_reader = Arc::new(SlashingDbReaderAdapter::new(slashing_db));
        let service = DoppelgangerService::new(liveness_checker, slashing_reader);
        info!("Created doppelganger detection service");
        service
    }

    pub fn build_key_manager(&self) -> Result<Arc<KeyManager>, ConfigError> {
        let passwords = self.config.load_passwords()?;

        if !self.config.keystore_path.exists() {
            return Err(ConfigError::KeystorePathNotFound(self.config.keystore_path.clone()));
        }

        let key_manager = KeyManager::load_from_directory_with_threads(
            &self.config.keystore_path,
            &passwords,
            self.config.key_decrypt_threads,
        )?;
        info!(
            key_count = key_manager.len(),
            path = ?self.config.keystore_path,
            "Loaded validator keys"
        );
        Ok(Arc::new(key_manager))
    }

    pub fn build_slashing_db(&self) -> Result<Arc<SlashingDb>, ConfigError> {
        if let Some(parent) = self.config.slashing_db_path.parent() {
            if !parent.exists() && parent != std::path::Path::new("") {
                return Err(ConfigError::SlashingDbPathInvalid(
                    self.config.slashing_db_path.clone(),
                ));
            }
        }

        let db = SlashingDb::open(&self.config.slashing_db_path)?;
        info!(path = ?self.config.slashing_db_path, "Opened slashing protection database");
        Ok(Arc::new(db))
    }

    pub fn build_signer(
        &self,
        composite_signer: Arc<CompositeSigner>,
        slashing_db: Arc<SlashingDb>,
    ) -> Arc<SignerService> {
        let signer = SignerService::new(composite_signer, slashing_db);
        info!("Created signer service");
        Arc::new(signer)
    }

    pub fn build_propagator<S: AttestationSubmitter>(
        &self,
        submitter: Arc<S>,
    ) -> Arc<Propagator<S>> {
        let propagator = Propagator::new(submitter);
        info!("Created propagator service");
        Arc::new(propagator)
    }

    pub fn build_duty_tracker(
        &self,
        beacon: Arc<dyn BeaconNodeClient>,
        validator_indices: Vec<String>,
    ) -> Arc<DutyTracker> {
        let tracker = DutyTracker::new(beacon, validator_indices);
        info!("Created duty tracker");
        Arc::new(tracker)
    }

    pub fn build_slot_clock(&self) -> Result<Arc<SystemSlotClock>, ConfigError> {
        let genesis_time = self.config.effective_genesis_time()?;
        let slot_duration = Duration::from_secs(self.config.network.seconds_per_slot());
        let slots_per_epoch = self.config.network.slots_per_epoch();

        let clock = SystemSlotClock::new(genesis_time, slot_duration, slots_per_epoch);
        info!(
            genesis_time = genesis_time,
            slot_duration_secs = slot_duration.as_secs(),
            slots_per_epoch = slots_per_epoch,
            "Created slot clock"
        );
        Ok(Arc::new(clock))
    }

    pub fn build_pubkey_map(&self, key_manager: &KeyManager) -> HashMap<String, PublicKey> {
        let mut pubkey_map = HashMap::new();
        for pubkey in key_manager.list_public_keys() {
            let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
            pubkey_map.insert(pubkey_hex, pubkey);
        }
        info!(count = pubkey_map.len(), "Built public key map");
        pubkey_map
    }

    pub fn parse_genesis_validators_root(&self) -> Result<Root, ConfigError> {
        let root_hex = self.config.effective_genesis_validators_root()?;
        let root_hex = root_hex.strip_prefix("0x").unwrap_or(&root_hex);

        let bytes = hex::decode(root_hex).map_err(|_| {
            ConfigError::InvalidNetwork(format!(
                "invalid genesis validators root hex: {}",
                root_hex
            ))
        })?;

        if bytes.len() != 32 {
            return Err(ConfigError::InvalidNetwork(format!(
                "genesis validators root must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Ok(root)
    }

    pub async fn build_fork_schedule(
        &self,
        beacon: &dyn BeaconNodeClient,
    ) -> Result<Arc<ForkSchedule>, ConfigError> {
        info!("Fetching fork schedule from beacon node");
        let schedule = beacon.get_fork_schedule().await?;
        info!(
            genesis_fork = ?schedule.genesis_fork_version,
            "Loaded fork schedule from beacon node"
        );
        Ok(Arc::new(schedule))
    }

    pub fn build_validator_store(&self) -> Arc<ValidatorStore> {
        let store = ValidatorStore::new([0u8; 20], 100);
        info!("Created validator store");
        Arc::new(store)
    }

    pub fn build_builder_service(
        &self,
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        validator_store: Arc<ValidatorStore>,
        genesis_fork_version: [u8; 4],
    ) -> Arc<BuilderService> {
        let service = BuilderService::new(signer, beacon, validator_store, genesis_fork_version);
        info!("Created builder service");
        Arc::new(service)
    }

    pub fn build_orchestrator_config(
        &self,
        genesis_validators_root: Root,
        fork_schedule: Arc<ForkSchedule>,
    ) -> OrchestratorConfig {
        OrchestratorConfig::new(genesis_validators_root, fork_schedule)
            .with_shutdown_timeout(Duration::from_secs(30))
    }

    /// Builds all services and returns them along with the orchestrator handle.
    ///
    /// The `validator_indices` parameter should contain numeric validator indices
    /// resolved from the beacon node. Callers should use `BeaconClient::get_validators`
    /// to resolve public keys to indices before calling this method.
    ///
    /// The `fork_schedule` must be fetched from the beacon node before calling
    /// this method via `build_fork_schedule()`.
    pub fn build_all(
        self,
        validator_indices: Vec<String>,
        fork_schedule: Arc<ForkSchedule>,
    ) -> Result<
        (
            BuiltServices<SystemSlotClock, BeaconClient>,
            impl FnOnce(
                BuiltServices<SystemSlotClock, BeaconClient>,
            ) -> (
                DutyOrchestrator<SystemSlotClock, BeaconClient, BeaconBlockAdapter>,
                OrchestratorHandle,
            ),
        ),
        ConfigError,
    > {
        let beacon_client = self.build_beacon()?;
        let key_manager = self.build_key_manager()?;
        let slashing_db = self.build_slashing_db()?;
        let pubkey_map = self.build_pubkey_map(&key_manager);
        let key_manager_owned = Arc::try_unwrap(key_manager)
            .unwrap_or_else(|_| panic!("single reference to key_manager after pubkey_map build"));
        let composite_signer = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager_owned)));
        let signer = self.build_signer(composite_signer.clone(), slashing_db.clone());
        let propagator = self.build_propagator(beacon_client.clone());
        let slot_clock = self.build_slot_clock()?;
        let validator_store = self.build_validator_store();

        let beacon: Arc<dyn BeaconNodeClient> = beacon_client.clone();
        let duty_tracker = self.build_duty_tracker(beacon.clone(), validator_indices);

        let doppelganger_service = if self.config.doppelganger_detection {
            Some(self.build_doppelganger_service(beacon_client.clone(), slashing_db.clone()))
        } else {
            None
        };

        let genesis_validators_root = self.parse_genesis_validators_root()?;

        let genesis_fork_version = fork_schedule.genesis_fork_version;
        let builder_service = Some(self.build_builder_service(
            signer.clone(),
            beacon.clone(),
            validator_store.clone(),
            genesis_fork_version,
        ));

        let services = BuiltServices {
            beacon,
            beacon_client,
            composite_signer,
            slashing_db,
            signer,
            propagator,
            duty_tracker,
            slot_clock,
            validator_store,
            pubkey_map,
            genesis_validators_root,
            fork_schedule,
            doppelganger_service,
            builder_service,
        };

        let orchestrator_factory = move |services: BuiltServices<SystemSlotClock, BeaconClient>| {
            let config = OrchestratorConfig::new(
                services.genesis_validators_root,
                services.fork_schedule.clone(),
            )
            .with_shutdown_timeout(Duration::from_secs(30));

            let block_beacon = Arc::new(BeaconBlockAdapter(services.beacon_client.clone()));

            DutyOrchestrator::new(
                services.slot_clock,
                services.duty_tracker,
                services.signer,
                services.propagator,
                services.beacon,
                block_beacon,
                services.builder_service,
                services.validator_store,
                config,
                services.pubkey_map,
            )
        };

        Ok((services, orchestrator_factory))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Signer as _;
    use tempfile::TempDir;

    fn create_minimal_config() -> Config {
        Config {
            beacon_url: "http://localhost:5052".to_string(),
            keystore_path: std::path::PathBuf::from("/tmp/nonexistent"),
            slashing_db_path: std::path::PathBuf::from("./test_slashing.db"),
            ..Default::default()
        }
    }

    #[test]
    fn test_service_builder_new() {
        let config = create_minimal_config();
        let _builder = ServiceBuilder::new(config);
    }

    #[test]
    fn test_build_beacon() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_beacon();
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_slashing_db() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("slashing.db");

        let config = Config { slashing_db_path: db_path.clone(), ..create_minimal_config() };

        let builder = ServiceBuilder::new(config);
        let result = builder.build_slashing_db();

        assert!(result.is_ok());
        assert!(db_path.exists());
    }

    #[test]
    fn test_build_slashing_db_invalid_parent() {
        let config = Config {
            slashing_db_path: std::path::PathBuf::from("/nonexistent/path/slashing.db"),
            ..create_minimal_config()
        };

        let builder = ServiceBuilder::new(config);
        let result = builder.build_slashing_db();

        assert!(matches!(result, Err(ConfigError::SlashingDbPathInvalid(_))));
    }

    #[test]
    fn test_build_key_manager_path_not_found() {
        let config = Config {
            keystore_path: std::path::PathBuf::from("/nonexistent/keystores"),
            ..create_minimal_config()
        };

        let builder = ServiceBuilder::new(config);
        let result = builder.build_key_manager();

        assert!(matches!(result, Err(ConfigError::KeystorePathNotFound(_))));
    }

    #[test]
    fn test_build_slot_clock() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_slot_clock();

        assert!(result.is_ok());
        let clock = result.unwrap();
        assert_eq!(clock.genesis_time(), 1606824023);
    }

    #[test]
    fn test_parse_genesis_validators_root() {
        let config = Config {
            genesis_validators_root: Some(
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
            ),
            ..create_minimal_config()
        };

        let builder = ServiceBuilder::new(config);
        let result = builder.parse_genesis_validators_root();

        assert!(result.is_ok());
        let root = result.unwrap();
        assert_eq!(root[0], 0x4b);
    }

    #[test]
    fn test_parse_genesis_validators_root_from_network() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.parse_genesis_validators_root();

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_pubkey_map_empty() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let key_manager = KeyManager::new();
        let pubkey_map = builder.build_pubkey_map(&key_manager);

        assert!(pubkey_map.is_empty());
    }

    #[test]
    fn test_build_signer() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = builder.build_signer(composite, slashing_db);

        assert!(signer.signer().public_keys().is_empty());
    }

    #[test]
    fn test_build_duty_tracker() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let beacon = builder.build_beacon().unwrap();
        let tracker = builder.build_duty_tracker(beacon, vec!["1234".to_string()]);

        assert!(Arc::strong_count(&tracker) > 0);
    }

    #[test]
    fn test_build_orchestrator_config() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let root = [0xaa; 32];
        let fork_schedule = Arc::new(ForkSchedule {
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
        });
        let orch_config = builder.build_orchestrator_config(root, fork_schedule);

        assert_eq!(orch_config.genesis_validators_root, root);
        assert_eq!(orch_config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_build_bn_manager_single_node() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_bn_manager();
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_bn_manager_multi_node() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()],
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let result = builder.build_bn_manager();
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_doppelganger_service() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let beacon = builder.build_beacon().unwrap();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let _service = builder.build_doppelganger_service(beacon, slashing_db);
    }

    #[test]
    fn test_build_builder_service() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let beacon = builder.build_beacon().unwrap();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = builder.build_signer(composite, slashing_db);
        let validator_store = builder.build_validator_store();

        let _builder_service =
            builder.build_builder_service(signer, beacon, validator_store, [0, 0, 0, 0]);
    }
}
