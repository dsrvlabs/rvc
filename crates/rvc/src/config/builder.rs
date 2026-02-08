//! Service builder for constructing all services from configuration.

#![allow(clippy::arc_with_non_send_sync)]
#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::orchestrator::{DutyOrchestrator, OrchestratorConfig, OrchestratorHandle};
use crate::signer::SignerService;
use crate::timing::{SlotClock, SystemSlotClock};
use beacon::{BeaconClient, BeaconClientConfig};
use crypto::{KeyManager, PublicKey};
use duty_tracker::DutyTracker;
use eth_types::{Fork, Root};
use propagator::{AttestationSubmitter, Propagator};
use slashing::SlashingDb;

use super::error::ConfigError;
use super::types::Config;

/// Contains all the built services ready for use.
pub struct BuiltServices<C, S>
where
    C: SlotClock + 'static,
    S: AttestationSubmitter + 'static,
{
    pub beacon: Arc<BeaconClient>,
    pub key_manager: Arc<KeyManager>,
    pub slashing_db: Arc<SlashingDb>,
    pub signer: Arc<SignerService>,
    pub propagator: Arc<Propagator<S>>,
    pub duty_tracker: Arc<DutyTracker>,
    pub slot_clock: Arc<C>,
    pub pubkey_map: HashMap<String, PublicKey>,
    pub genesis_validators_root: Root,
    pub fork: Fork,
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

    pub fn build_key_manager(&self) -> Result<Arc<KeyManager>, ConfigError> {
        let passwords = self.config.load_passwords()?;

        if !self.config.keystore_path.exists() {
            return Err(ConfigError::KeystorePathNotFound(self.config.keystore_path.clone()));
        }

        let key_manager = KeyManager::load_from_directory(&self.config.keystore_path, &passwords)?;
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
        key_manager: Arc<KeyManager>,
        slashing_db: Arc<SlashingDb>,
    ) -> Arc<SignerService> {
        let signer = SignerService::new(key_manager, slashing_db);
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
        beacon: Arc<BeaconClient>,
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

    pub fn build_fork(&self) -> Fork {
        // TODO: Implement proper fork version handling
        // Fork versions should be fetched from beacon node or included in network presets
        // (Bellatrix, Capella, Deneb have different fork versions)
        Fork {
            previous_version: [0x00, 0x00, 0x00, 0x00],
            current_version: [0x00, 0x00, 0x00, 0x00],
            epoch: 0,
        }
    }

    pub fn build_orchestrator_config(
        &self,
        genesis_validators_root: Root,
        fork: Fork,
    ) -> OrchestratorConfig {
        OrchestratorConfig::new(genesis_validators_root, fork)
            .with_shutdown_timeout(Duration::from_secs(30))
    }

    /// Builds all services and returns them along with the orchestrator handle.
    ///
    /// The `validator_indices` parameter should contain numeric validator indices
    /// resolved from the beacon node. Callers should use `BeaconClient::get_validators`
    /// to resolve public keys to indices before calling this method.
    pub fn build_all(
        self,
        validator_indices: Vec<String>,
    ) -> Result<
        (
            BuiltServices<SystemSlotClock, BeaconClient>,
            impl FnOnce(
                BuiltServices<SystemSlotClock, BeaconClient>,
            )
                -> (DutyOrchestrator<SystemSlotClock, BeaconClient>, OrchestratorHandle),
        ),
        ConfigError,
    > {
        let beacon = self.build_beacon()?;
        let key_manager = self.build_key_manager()?;
        let slashing_db = self.build_slashing_db()?;
        let signer = self.build_signer(key_manager.clone(), slashing_db.clone());
        let propagator = self.build_propagator(beacon.clone());
        let slot_clock = self.build_slot_clock()?;
        let pubkey_map = self.build_pubkey_map(&key_manager);

        let duty_tracker = self.build_duty_tracker(beacon.clone(), validator_indices);

        let genesis_validators_root = self.parse_genesis_validators_root()?;
        let fork = self.build_fork();

        let services = BuiltServices {
            beacon,
            key_manager,
            slashing_db,
            signer,
            propagator,
            duty_tracker,
            slot_clock,
            pubkey_map,
            genesis_validators_root,
            fork,
        };

        let orchestrator_factory = move |services: BuiltServices<SystemSlotClock, BeaconClient>| {
            let config = OrchestratorConfig::new(services.genesis_validators_root, services.fork)
                .with_shutdown_timeout(Duration::from_secs(30));

            DutyOrchestrator::new(
                services.slot_clock,
                services.duty_tracker,
                services.signer,
                services.propagator,
                services.beacon,
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
    fn test_build_fork() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let fork = builder.build_fork();

        assert_eq!(fork.epoch, 0);
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

        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer = builder.build_signer(key_manager, slashing_db);

        assert!(signer.key_manager().is_empty());
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
        let fork = builder.build_fork();
        let orch_config = builder.build_orchestrator_config(root, fork);

        assert_eq!(orch_config.genesis_validators_root, root);
        assert_eq!(orch_config.shutdown_timeout, Duration::from_secs(30));
    }
}
