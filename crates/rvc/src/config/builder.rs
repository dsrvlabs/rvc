//! Service builder for constructing all services from configuration.

#![allow(clippy::arc_with_non_send_sync)]
#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crypto::logging::RedactedUrl;

use crate::beacon_adapter::BeaconBlockAdapter;
use crate::doppelganger_adapter::{BeaconLivenessAdapter, SlashingDbReaderAdapter};
use crate::orchestrator::{DutyOrchestrator, OrchestratorConfig, OrchestratorHandle, PubkeyMap};
use beacon::{BeaconClient, BeaconClientConfig};
use bn_manager::{BeaconNodeClient, BnManager, BnManagerConfig};
use builder::BuilderService;
use crypto::{CompositeSigner, KeyManager, LocalSigner};
use doppelganger::DoppelgangerService;
use duty_tracker::DutyTracker;
use eth_types::{ForkSchedule, Root};
use propagator::{AttestationSubmitter, Propagator};
use signer::SignerService;
use slashing::SlashingDb;
use timing::{SlotClock, SystemSlotClock};
use validator_store::ValidatorStore;

use secret_provider::SecretProvider;

use super::error::ConfigError;
use super::types::Config;

fn format_version(v: eth_types::Version) -> String {
    format!("0x{}", hex::encode(v))
}

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
    pub pubkey_map: PubkeyMap,
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

    pub fn log_effective_config(&self) {
        let redacted_bns: Vec<String> = self
            .config
            .effective_beacon_nodes()
            .iter()
            .map(|u| format!("{}", RedactedUrl(u)))
            .collect();

        info!(
            bn_urls = ?redacted_bns,
            key_dir = ?self.config.keystore_path,
            network = %self.config.network,
            features = %format!(
                "doppelganger={}, builder=true, keymanager={}",
                self.config.doppelganger_detection,
                self.config.keymanager_enabled
            ),
            "Effective configuration"
        );

        info!(
            doppelganger_enabled = self.config.doppelganger_detection,
            builder_enabled = true,
            keymanager_enabled = self.config.keymanager_enabled,
            "Feature toggles"
        );
    }

    pub fn build_beacon(&self) -> Result<Arc<BeaconClient>, ConfigError> {
        let beacon_config = BeaconClientConfig::new(&self.config.beacon_url)
            .with_timeout(Duration::from_secs(30))
            .with_max_retries(3)
            .with_max_body_bytes(self.config.beacon_max_body_bytes);

        let client = BeaconClient::new(beacon_config)?;
        info!(
            url = %self.config.beacon_url,
            max_body_bytes = self.config.beacon_max_body_bytes,
            "Created beacon client"
        );
        Ok(Arc::new(client))
    }

    pub fn build_bn_manager(&self) -> Result<Arc<BnManager>, ConfigError> {
        let endpoints = self.config.effective_beacon_nodes();
        let broadcast_topics = self.config.effective_broadcast_topics();
        let mut config = BnManagerConfig::new(endpoints.clone());
        config.broadcast_topics = broadcast_topics.clone();
        let manager = BnManager::new(config)
            .map_err(|e| {
                ConfigError::InvalidBeaconUrl(format!("failed to create BnManager: {}", e))
            })?
            .with_operation_timeouts(bn_manager::OperationTimeouts::default());
        info!(
            endpoints = ?endpoints,
            broadcast_topics = ?broadcast_topics,
            "Created BnManager with {} beacon nodes",
            endpoints.len()
        );
        Ok(Arc::new(manager))
    }

    /// Builds a separate BnManager for proposer nodes if configured.
    ///
    /// Returns `None` if `proposer_nodes` is empty (main pool handles all).
    pub fn build_proposer_bn_manager(&self) -> Result<Option<Arc<BnManager>>, ConfigError> {
        if self.config.proposer_nodes.is_empty() {
            return Ok(None);
        }
        let endpoints = self.config.proposer_nodes.clone();
        let config = BnManagerConfig::new(endpoints.clone());
        let manager = BnManager::new(config)
            .map_err(|e| {
                ConfigError::InvalidBeaconUrl(format!("failed to create proposer BnManager: {}", e))
            })?
            .with_operation_timeouts(bn_manager::OperationTimeouts::default());
        info!(
            endpoints = ?endpoints,
            "Created proposer BnManager with {} proposer nodes",
            endpoints.len()
        );
        Ok(Some(Arc::new(manager)))
    }

    pub fn build_doppelganger_service(
        &self,
        beacon: Arc<BeaconClient>,
        slashing_db: Arc<SlashingDb>,
    ) -> Result<DoppelgangerService, ConfigError> {
        // M-7 (ISSUE-3.6 review): propagate the genesis_time error rather than
        // silently defaulting to 0.  A genesis_time of 0 would compute
        // current_epoch ≈ now_unix / 384 (meaninglessly large) and silently
        // disable doppelganger monitoring for misconfigured custom networks.
        let genesis_time = self.config.effective_genesis_time()?;
        let liveness_checker = Arc::new(BeaconLivenessAdapter::new(beacon));
        let slashing_reader = Arc::new(SlashingDbReaderAdapter::new(slashing_db));
        let service = DoppelgangerService::new(liveness_checker, slashing_reader, genesis_time);
        info!(genesis_time, "Created doppelganger detection service");
        Ok(service)
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

        let clock = SystemSlotClock::new(genesis_time, slot_duration, slots_per_epoch)
            .map_err(|e| ConfigError::MissingField(format!("invalid slot clock: {e}")))?;
        info!(
            genesis_time = genesis_time,
            slot_duration_secs = slot_duration.as_secs(),
            slots_per_epoch = slots_per_epoch,
            "Created slot clock"
        );
        Ok(Arc::new(clock))
    }

    pub fn build_pubkey_map(&self, key_manager: &KeyManager) -> PubkeyMap {
        let mut map = HashMap::new();
        for pubkey in key_manager.list_public_keys() {
            let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
            map.insert(pubkey_hex, pubkey);
        }
        info!(count = map.len(), "Built public key map");
        Arc::new(parking_lot::RwLock::new(map))
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
            genesis_version = %format_version(schedule.genesis_fork_version),
            altair_epoch = schedule.altair_fork_epoch,
            altair_version = %format_version(schedule.altair_fork_version),
            bellatrix_epoch = schedule.bellatrix_fork_epoch,
            bellatrix_version = %format_version(schedule.bellatrix_fork_version),
            capella_epoch = schedule.capella_fork_epoch,
            capella_version = %format_version(schedule.capella_fork_version),
            deneb_epoch = schedule.deneb_fork_epoch,
            deneb_version = %format_version(schedule.deneb_fork_version),
            electra_epoch = schedule.electra_fork_epoch,
            electra_version = %format_version(schedule.electra_fork_version),
            fulu_epoch = schedule.fulu_fork_epoch,
            fulu_version = %format_version(schedule.fulu_fork_version),
            "Loaded fork schedule from beacon node"
        );
        Ok(Arc::new(schedule))
    }

    /// Constructs the [`ValidatorStore`], loading defaults from a TOML file if
    /// one is provided.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ZeroFeeRecipient`] if the effective default fee
    /// recipient is the zero address.  Operators must set a non-zero address in
    /// the validators config file passed via `--validators-config`.
    pub fn build_validator_store(
        &self,
        validators_config: Option<&std::path::Path>,
    ) -> Result<Arc<ValidatorStore>, ConfigError> {
        let store = match validators_config {
            Some(path) => ValidatorStore::load_from_config(path)
                .map_err(|e| ConfigError::ValidatorStoreError(e.to_string()))?,
            None => ValidatorStore::new([0u8; 20], 30_000_000),
        };

        if store.default_fee_recipient() == [0u8; 20] {
            return Err(ConfigError::ZeroFeeRecipient);
        }

        info!("Created validator store");
        Ok(Arc::new(store))
    }

    /// Registers every loaded validator pubkey in the [`ValidatorStore`] so the
    /// per-validator signing gate ([`ValidatorStore::is_signing_enabled`]) treats
    /// keystore-loaded keys as tracked-and-enabled.
    ///
    /// D-3 (Issue 2.11) flipped the unknown-pubkey default to fail-closed
    /// (`false`). The common production deployment supplies no per-validator
    /// `validators_config` TOML — the actual keys are loaded into the
    /// `KeyManager`/`pubkey_map`, not the store — so without this registration
    /// every loaded validator would hit the fail-closed default and be silently
    /// blocked from signing (a catastrophic availability regression).
    ///
    /// Registration is additive and idempotent: a pubkey already tracked by the
    /// store (e.g. set `enabled = false` by the doppelganger window or via the
    /// validators TOML) is left untouched, so the doppelganger flow's ability to
    /// keep a freshly-imported key disabled is preserved.
    pub fn register_loaded_validators(&self, store: &ValidatorStore, pubkey_map: &PubkeyMap) {
        let mut registered = 0usize;
        for pubkey in pubkey_map.read().values() {
            let pk_bytes = pubkey.to_bytes();
            if !store.has_validator(&pk_bytes) {
                store.add_validator(validator_store::ValidatorConfig::new(pk_bytes));
                registered += 1;
            }
        }
        info!(
            registered,
            enabled_total = store.list_enabled_pubkeys().len(),
            "Registered loaded validators in the validator store (D-3 fail-closed)"
        );
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

    pub async fn build_secret_providers(
        &self,
    ) -> Result<Vec<Box<dyn SecretProvider>>, ConfigError> {
        #[allow(unused_mut)]
        let mut providers: Vec<Box<dyn SecretProvider>> = Vec::new();

        #[allow(clippy::never_loop)] // loop continues when gcp-secret feature is enabled
        for provider_name in &self.config.secret_provider.providers {
            match provider_name.as_str() {
                "gcp" => {
                    #[cfg(not(feature = "gcp-secret"))]
                    {
                        return Err(ConfigError::FeatureNotEnabled(
                            "gcp provider requires the `gcp-secret` feature. \
                             Rebuild with: cargo build --features gcp-secret"
                                .to_string(),
                        ));
                    }
                    #[cfg(feature = "gcp-secret")]
                    {
                        use secret_provider::gcp::{GcpSecretProvider, GcpSecretProviderConfig};
                        let gcp_config = GcpSecretProviderConfig {
                            project_id: self
                                .config
                                .secret_provider
                                .gcp
                                .project_id
                                .clone()
                                .ok_or_else(|| {
                                    ConfigError::MissingField(
                                        "gcp_project_id is required for GCP secret provider".into(),
                                    )
                                })?,
                            prefix: self.config.secret_provider.gcp.secret_prefix.clone(),
                            ..Default::default()
                        };
                        let gcp_provider =
                            GcpSecretProvider::new(gcp_config).await.map_err(|e| {
                                ConfigError::SecretProviderError(format!(
                                    "failed to create GCP secret provider: {}",
                                    e
                                ))
                            })?;
                        providers.push(Box::new(gcp_provider));
                        info!("Created GCP secret provider");
                    }
                }
                other => {
                    return Err(ConfigError::SecretProviderError(format!(
                        "unknown secret provider: {}",
                        other
                    )));
                }
            }
        }

        Ok(providers)
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
        self.log_effective_config();

        let beacon_client = self.build_beacon()?;
        let key_manager = self.build_key_manager()?;
        let slashing_db = self.build_slashing_db()?;
        let pubkey_map = self.build_pubkey_map(&key_manager);
        let key_manager_owned = Arc::try_unwrap(key_manager).map_err(|_| {
            ConfigError::MissingField(
                "cannot take ownership of key_manager: outstanding Arc references".to_string(),
            )
        })?;
        let composite_signer = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager_owned)));
        let signer = self.build_signer(composite_signer.clone(), slashing_db.clone());
        let propagator = self.build_propagator(beacon_client.clone());
        let slot_clock = self.build_slot_clock()?;
        let validator_store =
            self.build_validator_store(self.config.validators_config.as_deref())?;

        // D-3 (Issue 2.11): with the fail-closed `is_signing_enabled` default,
        // register every keystore-loaded validator in the store so the
        // per-validator signing gate permits the keys the VC actually loaded.
        self.register_loaded_validators(&validator_store, &pubkey_map);

        let beacon: Arc<dyn BeaconNodeClient> = beacon_client.clone();
        let duty_tracker = self.build_duty_tracker(beacon.clone(), validator_indices);

        let doppelganger_service = if self.config.doppelganger_detection {
            Some(self.build_doppelganger_service(beacon_client.clone(), slashing_db.clone())?)
        } else {
            None
        };

        let genesis_validators_root = self.parse_genesis_validators_root()?;
        info!(
            genesis_validators_root = %format!("0x{}", hex::encode(genesis_validators_root)),
            "Parsed genesis validators root"
        );

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

        assert!(pubkey_map.read().is_empty());
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
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [6, 0, 0, 0],
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
        let _service = builder.build_doppelganger_service(beacon, slashing_db).unwrap();
    }

    #[tokio::test]
    async fn test_build_secret_providers_empty() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_secret_providers().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_build_secret_providers_gcp_without_feature() {
        use super::super::types::{GcpSecretConfig, SecretProviderConfig};
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("my-project".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let result = builder.build_secret_providers().await;
        // Without gcp-secret feature, should return an error
        #[cfg(not(feature = "gcp-secret"))]
        assert!(result.is_err());
        #[cfg(feature = "gcp-secret")]
        {
            // With feature, would attempt GCP client construction (may fail without credentials)
            let _ = result;
        }
    }

    #[tokio::test]
    async fn test_build_secret_providers_unknown_provider() {
        let mut config = create_minimal_config();
        config.secret_provider.providers = vec!["unknown".to_string()];
        let builder = ServiceBuilder::new(config);
        let result = builder.build_secret_providers().await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("unknown secret provider"));
    }

    #[test]
    fn test_build_builder_service() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let beacon = builder.build_beacon().unwrap();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = builder.build_signer(composite, slashing_db);

        // Build a temp validators config with a non-zero fee_recipient to satisfy the guard.
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();
        let validator_store = builder.build_validator_store(Some(&config_path)).unwrap();

        let _builder_service =
            builder.build_builder_service(signer, beacon, validator_store, [0, 0, 0, 0]);
    }

    #[test]
    fn test_log_effective_config_does_not_panic() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        builder.log_effective_config();
    }

    // --- ISSUE-2.1: H-1 fee recipient + gas-limit defaults ---

    /// Zero fee recipient must be refused with a loud, actionable error.
    #[test]
    fn test_zero_fee_recipient_refused() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        // No config file → default fee recipient is [0u8; 20] → must fail
        let result = builder.build_validator_store(None);
        assert!(
            matches!(result, Err(ConfigError::ZeroFeeRecipient)),
            "expected ZeroFeeRecipient, got: {:?}",
            result.err()
        );
    }

    /// When the TOML does not specify gas_limit the store must default to 30_000_000.
    #[test]
    fn test_default_gas_limit_30m() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        // TOML with non-zero fee_recipient but no gas_limit field
        let toml = format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n", fr_hex = fr_hex);
        std::fs::write(&config_path, toml).unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_validator_store(Some(&config_path));
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let store = result.unwrap();
        assert_eq!(store.default_gas_limit(), 30_000_000);
    }

    /// `build_validator_store` must wire `load_from_config` so TOML defaults are reflected.
    #[test]
    fn test_from_toml_paths_wired() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xbbu8; 20]);
        let toml = format!(
            "[defaults]\nfee_recipient = \"{fr_hex}\"\ngas_limit = 50000000\n",
            fr_hex = fr_hex
        );
        std::fs::write(&config_path, toml).unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_validator_store(Some(&config_path));
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let store = result.unwrap();
        assert_eq!(store.default_fee_recipient(), [0xbbu8; 20]);
        assert_eq!(store.default_gas_limit(), 50_000_000);
    }

    // --- D-3 (Issue 2.11): no-availability-regression for fail-closed default ---

    /// Builds an in-memory `KeyManager` populated with `count` freshly generated
    /// keys, returning the manager and the matching `pubkey_map`. Mirrors the
    /// startup path where keystore-loaded keys flow into `build_pubkey_map`.
    fn loaded_key_manager(builder: &ServiceBuilder, count: usize) -> (KeyManager, PubkeyMap) {
        let mut key_manager = KeyManager::new();
        for _ in 0..count {
            key_manager.insert(crypto::SecretKey::generate());
        }
        let pubkey_map = builder.build_pubkey_map(&key_manager);
        (key_manager, pubkey_map)
    }

    /// CRITICAL (D-3 fail-closed safety): after flipping the unknown-pubkey
    /// default to fail-closed, every validator the VC actually loads from
    /// keystores — with NO per-validator `validators_config` TOML entry — must
    /// still be permitted to sign, because startup registers each loaded pubkey
    /// in the `ValidatorStore`. Without `register_loaded_validators`, every
    /// keystore-loaded key would hit the fail-closed default and be silently
    /// blocked (catastrophic availability regression).
    #[test]
    fn test_loaded_validators_registered_so_signing_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xccu8; 20]);
        // Non-zero default fee recipient but NO per-validator entries — the common
        // production case where keys are loaded into the KeyManager, not the store.
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let store = builder.build_validator_store(Some(&config_path)).unwrap();
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 3);

        // Before registration the loaded keys are untracked → fail-closed.
        for pubkey in key_manager.list_public_keys() {
            assert!(
                !store.is_signing_enabled(&pubkey.to_bytes()),
                "untracked loaded key must be fail-closed before registration"
            );
        }

        builder.register_loaded_validators(&store, &pubkey_map);

        // After registration every loaded key is tracked & enabled.
        for pubkey in key_manager.list_public_keys() {
            assert!(
                store.is_signing_enabled(&pubkey.to_bytes()),
                "loaded keystore key must be permitted to sign after startup registration"
            );
        }
    }

    /// `register_loaded_validators` must NOT clobber an existing disabled entry
    /// (e.g. a validator set `enabled = false` by the doppelganger window or via
    /// the validators TOML). Registration only adds keys that are not already
    /// tracked.
    #[test]
    fn test_register_loaded_validators_preserves_disabled_entry() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xddu8; 20]);
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let store = builder.build_validator_store(Some(&config_path)).unwrap();
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 1);
        let pk = key_manager.list_public_keys()[0].to_bytes();

        // Simulate the doppelganger window having disabled this validator before
        // registration runs.
        let mut disabled = validator_store::ValidatorConfig::new(pk);
        disabled.enabled = false;
        store.add_validator(disabled);

        builder.register_loaded_validators(&store, &pubkey_map);

        assert!(
            !store.is_signing_enabled(&pk),
            "registration must not re-enable a validator already tracked as disabled"
        );
    }
}
