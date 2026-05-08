//! Configuration types for the validator client.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use crypto::hex::{strip_prefix_strict, HexError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tracing::warn;

use url::Url;

use beacon::ResponseCaps;

use super::error::ConfigError;
use super::network::Network;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub beacon_url: String,

    #[serde(default)]
    pub beacon_nodes: Vec<String>,

    pub keystore_path: PathBuf,

    pub password_file: Option<PathBuf>,

    pub slashing_db_path: PathBuf,

    pub metrics_address: IpAddr,

    pub metrics_port: u16,

    pub grpc_port: u16,

    pub grpc_address: String,

    pub network: Network,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_time: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_validators_root: Option<String>,

    pub graffiti: Option<String>,

    pub log_level: String,

    pub doppelganger_detection: bool,

    #[serde(default)]
    pub keymanager_enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub keymanager_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub keymanager_token_file: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signer_url: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_allowed_hosts: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_decrypt_threads: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracing_endpoint: Option<String>,

    #[serde(default = "default_tracing_exporter")]
    pub tracing_exporter: String,

    #[serde(default = "default_tracing_sample_rate")]
    pub tracing_sample_rate: f64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracing_max_queue_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracing_max_export_batch_size: Option<usize>,

    #[serde(default)]
    pub secret_provider: SecretProviderConfig,

    #[serde(default)]
    pub allow_insecure_remote_signer: bool,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keymanager_cors_origins: Vec<String>,

    #[serde(default = "default_keymanager_body_limit")]
    pub keymanager_body_limit: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_signer_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_signer_tls_cert: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_signer_tls_key: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_signer_tls_ca_cert: Option<PathBuf>,

    #[serde(default)]
    pub disable_attesting: bool,

    #[serde(default = "default_slashed_validators_action")]
    pub slashed_validators_action: String,

    #[serde(default = "default_circuit_breaker_consecutive_limit")]
    pub builder_circuit_breaker_consecutive_limit: u32,

    #[serde(default = "default_circuit_breaker_epoch_limit")]
    pub builder_circuit_breaker_epoch_limit: u32,

    #[serde(default)]
    pub disable_keystore_locking: bool,

    // --- Monitoring fields (T3.7) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitoring_endpoint: Option<String>,

    #[serde(default = "default_monitoring_interval")]
    pub monitoring_interval: u64,

    #[serde(default)]
    pub monitoring_endpoint_insecure: bool,

    // --- Proposer nodes fields (T3.1/T3.2) ---
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposer_nodes: Vec<String>,

    // --- Broadcast topics fields (T3.3/T3.4) ---
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broadcast: Vec<String>,

    // --- Proposer config URL fields (T3.11/T3.12/T3.13) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposer_config_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposer_config_file: Option<String>,

    #[serde(default = "default_proposer_config_refresh_interval")]
    pub proposer_config_refresh_interval: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposer_config_url_token: Option<String>,

    #[serde(default)]
    pub proposer_config_url_insecure: bool,

    // --- Log rotation fields (T3.8/T3.9/T3.10) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logfile: Option<PathBuf>,

    #[serde(default = "default_logfile_max_size")]
    pub logfile_max_size: u64,

    #[serde(default = "default_logfile_max_number")]
    pub logfile_max_number: usize,

    #[serde(default)]
    pub logfile_compress: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logfile_level: Option<String>,

    // --- Health tier fields (T4.5/T4.8) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bn_sync_tolerances: Option<String>,

    // --- Role-based BN fields (T4.9/T4.11) ---
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub beacon_nodes_config: Vec<BeaconNodeEntry>,

    // --- Block selection mode (T4.1/T4.4) ---
    #[serde(default)]
    pub block_selection_mode: validator_store::BlockSelectionMode,

    // --- Registration batching (T4.12/T4.13) ---
    #[serde(default = "default_validator_registration_batch_size")]
    pub validator_registration_batch_size: usize,

    #[serde(default = "default_validator_registration_batch_delay")]
    pub validator_registration_batch_delay: u64,

    // --- Validator per-validator config (ISSUE-2.1 / H-1) ---
    /// Path to a TOML file containing per-validator and default fee_recipient /
    /// gas_limit overrides.  rvc refuses to start if `default_fee_recipient`
    /// resolves to the zero address (0x000…000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validators_config: Option<PathBuf>,

    // --- BN HTTP caps (ISSUE-2.13 / H-12) ---
    /// Maximum JSON response body size in bytes from the beacon node (H-12).
    ///
    /// Requests whose body (or `Content-Length`) exceeds this value are rejected before
    /// the full body is allocated.  Default: 32 MiB.
    #[serde(default = "default_beacon_max_body_bytes")]
    pub beacon_max_body_bytes: usize,
}

fn default_beacon_max_body_bytes() -> usize {
    ResponseCaps::DEFAULT_MAX_BODY_BYTES
}

fn default_monitoring_interval() -> u64 {
    384
}

fn default_proposer_config_refresh_interval() -> u64 {
    384
}

fn default_logfile_max_size() -> u64 {
    200
}

fn default_logfile_max_number() -> usize {
    5
}

fn default_slashed_validators_action() -> String {
    "disable-only".to_string()
}

/// Per-BN configuration entry for `[[beacon_nodes]]` TOML tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconNodeEntry {
    pub url: String,
    #[serde(default = "default_bn_roles")]
    pub roles: Vec<String>,
}

fn default_bn_roles() -> Vec<String> {
    vec!["all".to_string()]
}

fn default_validator_registration_batch_size() -> usize {
    500
}

fn default_validator_registration_batch_delay() -> u64 {
    500
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretProviderConfig {
    #[serde(default)]
    pub providers: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<u64>,

    #[serde(default)]
    pub gcp: GcpSecretConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GcpSecretConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    #[serde(default = "default_gcp_secret_prefix")]
    pub secret_prefix: String,
}

impl Default for GcpSecretConfig {
    fn default() -> Self {
        Self { project_id: None, secret_prefix: default_gcp_secret_prefix() }
    }
}

fn default_gcp_secret_prefix() -> String {
    "validator-key-".to_string()
}

fn default_keymanager_body_limit() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_circuit_breaker_consecutive_limit() -> u32 {
    3
}

fn default_circuit_breaker_epoch_limit() -> u32 {
    5
}

fn default_tracing_exporter() -> String {
    "otlp".to_string()
}

fn default_tracing_sample_rate() -> f64 {
    0.01
}

impl Default for Config {
    fn default() -> Self {
        Self {
            beacon_url: "http://localhost:5052".to_string(),
            beacon_nodes: Vec::new(),
            keystore_path: PathBuf::from("./keystores"),
            password_file: None,
            slashing_db_path: PathBuf::from("./slashing_protection.sqlite"),
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 8080,
            grpc_port: 50051,
            grpc_address: "127.0.0.1".to_string(),
            network: Network::Mainnet,
            genesis_time: None,
            genesis_validators_root: None,
            graffiti: None,
            log_level: "info".to_string(),
            doppelganger_detection: true,
            keymanager_enabled: false,
            keymanager_address: None,
            keymanager_token_file: None,
            remote_signer_url: None,
            remote_signer_allowed_hosts: None,
            key_decrypt_threads: None,
            tracing_endpoint: None,
            tracing_exporter: default_tracing_exporter(),
            tracing_sample_rate: default_tracing_sample_rate(),
            tracing_max_queue_size: None,
            tracing_max_export_batch_size: None,
            secret_provider: SecretProviderConfig::default(),
            allow_insecure_remote_signer: false,
            keymanager_cors_origins: Vec::new(),
            keymanager_body_limit: default_keymanager_body_limit(),
            grpc_signer_url: None,
            grpc_signer_tls_cert: None,
            grpc_signer_tls_key: None,
            grpc_signer_tls_ca_cert: None,
            disable_attesting: false,
            slashed_validators_action: default_slashed_validators_action(),
            builder_circuit_breaker_consecutive_limit: default_circuit_breaker_consecutive_limit(),
            builder_circuit_breaker_epoch_limit: default_circuit_breaker_epoch_limit(),
            disable_keystore_locking: false,
            proposer_nodes: Vec::new(),
            broadcast: Vec::new(),
            proposer_config_url: None,
            proposer_config_file: None,
            proposer_config_refresh_interval: default_proposer_config_refresh_interval(),
            proposer_config_url_token: None,
            proposer_config_url_insecure: false,
            monitoring_endpoint: None,
            monitoring_interval: default_monitoring_interval(),
            monitoring_endpoint_insecure: false,
            logfile: None,
            logfile_max_size: default_logfile_max_size(),
            logfile_max_number: default_logfile_max_number(),
            logfile_compress: false,
            logfile_level: None,
            bn_sync_tolerances: None,
            beacon_nodes_config: Vec::new(),
            block_selection_mode: validator_store::BlockSelectionMode::default(),
            validator_registration_batch_size: default_validator_registration_batch_size(),
            validator_registration_batch_delay: default_validator_registration_batch_delay(),
            validators_config: None,
            beacon_max_body_bytes: default_beacon_max_body_bytes(),
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }

        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn effective_genesis_time(&self) -> Result<u64, ConfigError> {
        if let Some(genesis_time) = self.genesis_time {
            return Ok(genesis_time);
        }

        self.network
            .genesis_time()
            .ok_or_else(|| ConfigError::MissingField("genesis_time".to_string()))
    }

    pub fn effective_genesis_validators_root(&self) -> Result<String, ConfigError> {
        if let Some(ref root) = self.genesis_validators_root {
            return Ok(root.clone());
        }

        self.network
            .genesis_validators_root()
            .map(|s| s.to_string())
            .ok_or_else(|| ConfigError::MissingField("genesis_validators_root".to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.beacon_url.is_empty() {
            return Err(ConfigError::InvalidBeaconUrl("beacon URL cannot be empty".to_string()));
        }

        if !self.beacon_url.starts_with("http://") && !self.beacon_url.starts_with("https://") {
            return Err(ConfigError::InvalidBeaconUrl(format!(
                "beacon URL must start with http:// or https://: {}",
                self.beacon_url
            )));
        }

        for node_url in &self.beacon_nodes {
            if node_url.is_empty() {
                return Err(ConfigError::InvalidBeaconUrl(
                    "beacon_nodes entry cannot be empty".to_string(),
                ));
            }
            if !node_url.starts_with("http://") && !node_url.starts_with("https://") {
                return Err(ConfigError::InvalidBeaconUrl(format!(
                    "beacon_nodes entry must start with http:// or https://: {}",
                    node_url
                )));
            }
        }

        if self.metrics_port == 0 {
            return Err(ConfigError::InvalidPort(self.metrics_port));
        }

        if self.grpc_port == 0 {
            return Err(ConfigError::InvalidPort(self.grpc_port));
        }

        if let Some(ref graffiti) = self.graffiti {
            if graffiti.len() > 32 {
                return Err(ConfigError::InvalidGraffiti(
                    "graffiti must be 32 bytes or less".to_string(),
                ));
            }
        }

        if self.secret_provider.providers.contains(&"gcp".to_string()) {
            match &self.secret_provider.gcp.project_id {
                None => {
                    return Err(ConfigError::MissingField(
                        "gcp_project_id is required when secret_providers contains 'gcp'"
                            .to_string(),
                    ));
                }
                Some(id) if id.trim().is_empty() => {
                    return Err(ConfigError::MissingField(
                        "gcp_project_id must not be empty or whitespace-only".to_string(),
                    ));
                }
                _ => {}
            }
        }

        self.effective_genesis_time()?;
        self.effective_genesis_validators_root()?;

        if self.allow_insecure_remote_signer {
            self.validate_insecure_env_var()?;
        }

        // Validate proposer_config_url and proposer_config_file mutual exclusivity
        if self.proposer_config_url.is_some() && self.proposer_config_file.is_some() {
            return Err(ConfigError::MissingField(
                "--proposer-config-url and --proposer-config-file are mutually exclusive; use only one".to_string(),
            ));
        }

        // Validate broadcast topics
        for topic in &self.broadcast {
            match topic.as_str() {
                "attestations" | "blocks" | "sync-committee" | "subscriptions" | "none" => {}
                other => {
                    return Err(ConfigError::MissingField(format!(
                        "invalid broadcast topic '{}': must be one of attestations, blocks, sync-committee, subscriptions, none",
                        other
                    )));
                }
            }
        }
        if self.broadcast.contains(&"none".to_string()) && self.broadcast.len() > 1 {
            return Err(ConfigError::MissingField(
                "broadcast topic 'none' cannot be combined with other topics".to_string(),
            ));
        }

        // Validate proposer node URLs
        for node_url in &self.proposer_nodes {
            if node_url.is_empty() {
                return Err(ConfigError::InvalidBeaconUrl(
                    "proposer_nodes entry cannot be empty".to_string(),
                ));
            }
            if !node_url.starts_with("http://") && !node_url.starts_with("https://") {
                return Err(ConfigError::InvalidBeaconUrl(format!(
                    "proposer_nodes entry must start with http:// or https://: {}",
                    node_url
                )));
            }
        }

        match self.slashed_validators_action.as_str() {
            "disable-only" | "shutdown" | "none" => {}
            other => {
                return Err(ConfigError::MissingField(format!(
                    "invalid --slashed-validators-action '{}': must be one of disable-only, shutdown, none",
                    other
                )));
            }
        }

        Ok(())
    }

    fn validate_insecure_env_var(&self) -> Result<(), ConfigError> {
        match std::env::var("RVC_ALLOW_INSECURE") {
            Ok(val) if val == "true" => Ok(()),
            _ => Err(ConfigError::InsecureFlagRequiresEnvVar),
        }
    }

    pub fn load_passwords(&self) -> Result<HashMap<String, SecretString>, ConfigError> {
        let password_file = match &self.password_file {
            Some(path) => path,
            None => return Ok(HashMap::new()),
        };

        if !password_file.exists() {
            return Err(ConfigError::PasswordFileNotFound(password_file.clone()));
        }

        let content = fs::read_to_string(password_file).map_err(|e| {
            ConfigError::PasswordReadError(format!("failed to read password file: {}", e))
        })?;

        let mut passwords = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((pubkey, password)) = line.split_once('=') {
                let pubkey_trimmed = pubkey.trim();
                let pubkey = match strip_prefix_strict(pubkey_trimmed) {
                    Ok(s) => s,
                    Err(HexError::DoubleZeroXPrefix) => {
                        warn!(
                            pubkey = pubkey_trimmed,
                            "skipping password entry: double 0x prefix in pubkey"
                        );
                        continue;
                    }
                };
                let password = password.trim();
                passwords.insert(pubkey.to_string(), SecretString::from(password.to_string()));
            }
        }

        Ok(passwords)
    }

    /// Parses the `broadcast` config field into `BroadcastTopics`.
    ///
    /// If empty, returns default (all enabled). If "none", all disabled.
    /// Otherwise, only listed topics are enabled.
    pub fn effective_broadcast_topics(&self) -> bn_manager::BroadcastTopics {
        if self.broadcast.is_empty() {
            return bn_manager::BroadcastTopics::default();
        }
        if self.broadcast.len() == 1 && self.broadcast[0] == "none" {
            return bn_manager::BroadcastTopics {
                attestations: false,
                blocks: false,
                sync_committee: false,
                subscriptions: false,
            };
        }
        bn_manager::BroadcastTopics {
            attestations: self.broadcast.contains(&"attestations".to_string()),
            blocks: self.broadcast.contains(&"blocks".to_string()),
            sync_committee: self.broadcast.contains(&"sync-committee".to_string()),
            subscriptions: self.broadcast.contains(&"subscriptions".to_string()),
        }
    }

    /// Returns the effective list of beacon node endpoints.
    ///
    /// Prefers `beacon_nodes` if non-empty, otherwise falls back to `beacon_url`.
    pub fn effective_beacon_nodes(&self) -> Vec<String> {
        if !self.beacon_nodes.is_empty() {
            self.beacon_nodes.clone()
        } else {
            vec![self.beacon_url.clone()]
        }
    }

    pub fn merge_with_cli(&mut self, cli: &CliOverrides) {
        if let Some(ref beacon_url) = cli.beacon_url {
            self.beacon_url = beacon_url.clone();
        }

        if let Some(ref beacon_nodes) = cli.beacon_nodes {
            self.beacon_nodes = beacon_nodes.clone();
        }

        if let Some(ref keystore_path) = cli.keystore_path {
            self.keystore_path = keystore_path.clone();
        }

        if let Some(ref password_file) = cli.password_file {
            self.password_file = Some(password_file.clone());
        }

        if let Some(ref slashing_db_path) = cli.slashing_db_path {
            self.slashing_db_path = slashing_db_path.clone();
        }

        if let Some(metrics_address) = cli.metrics_address {
            self.metrics_address = metrics_address;
        }

        if let Some(metrics_port) = cli.metrics_port {
            self.metrics_port = metrics_port;
        }

        if let Some(grpc_port) = cli.grpc_port {
            self.grpc_port = grpc_port;
        }

        if let Some(ref grpc_address) = cli.grpc_address {
            self.grpc_address = grpc_address.clone();
        }

        if let Some(network) = cli.network {
            self.network = network;
        }

        if let Some(genesis_time) = cli.genesis_time {
            self.genesis_time = Some(genesis_time);
        }

        if let Some(ref genesis_validators_root) = cli.genesis_validators_root {
            self.genesis_validators_root = Some(genesis_validators_root.clone());
        }

        if let Some(ref graffiti) = cli.graffiti {
            self.graffiti = Some(graffiti.clone());
        }

        if let Some(ref log_level) = cli.log_level {
            self.log_level = log_level.clone();
        }

        if let Some(doppelganger_detection) = cli.doppelganger_detection {
            self.doppelganger_detection = doppelganger_detection;
        }

        if let Some(keymanager_enabled) = cli.keymanager_enabled {
            self.keymanager_enabled = keymanager_enabled;
        }

        if let Some(ref keymanager_address) = cli.keymanager_address {
            self.keymanager_address = Some(keymanager_address.clone());
        }

        if let Some(ref keymanager_token_file) = cli.keymanager_token_file {
            self.keymanager_token_file = Some(keymanager_token_file.clone());
        }

        if let Some(ref remote_signer_url) = cli.remote_signer_url {
            self.remote_signer_url = Some(remote_signer_url.clone());
        }

        if let Some(ref hosts_csv) = cli.remote_signer_allowed_hosts {
            let hosts: Vec<String> = hosts_csv
                .split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect();
            if !hosts.is_empty() {
                self.remote_signer_allowed_hosts = Some(hosts);
            }
        }

        if let Some(n) = cli.key_decrypt_threads {
            self.key_decrypt_threads = Some(n);
        }

        if let Some(ref tracing_endpoint) = cli.tracing_endpoint {
            self.tracing_endpoint = Some(tracing_endpoint.clone());
        }

        if let Some(ref tracing_exporter) = cli.tracing_exporter {
            self.tracing_exporter = tracing_exporter.clone();
        }

        if let Some(tracing_sample_rate) = cli.tracing_sample_rate {
            self.tracing_sample_rate = tracing_sample_rate;
        }

        if let Some(n) = cli.tracing_max_queue_size {
            self.tracing_max_queue_size = Some(n);
        }

        if let Some(n) = cli.tracing_max_export_batch_size {
            self.tracing_max_export_batch_size = Some(n);
        }

        if let Some(ref provider_csv) = cli.secret_provider {
            let providers: Vec<String> = provider_csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !providers.is_empty() {
                self.secret_provider.providers = providers;
            }
        }

        if let Some(ref gcp_project_id) = cli.gcp_project_id {
            self.secret_provider.gcp.project_id = Some(gcp_project_id.clone());
        }

        if let Some(ref gcp_secret_prefix) = cli.gcp_secret_prefix {
            self.secret_provider.gcp.secret_prefix = gcp_secret_prefix.clone();
        }

        if let Some(interval) = cli.secret_refresh_interval {
            self.secret_provider.refresh_interval = Some(interval);
        }

        if let Some(allow) = cli.allow_insecure_remote_signer {
            self.allow_insecure_remote_signer = allow;
        }

        if let Some(ref origins) = cli.keymanager_cors_origins {
            self.keymanager_cors_origins = origins.clone();
        }

        if let Some(limit) = cli.keymanager_body_limit {
            self.keymanager_body_limit = limit;
        }

        if let Some(ref url) = cli.grpc_signer_url {
            self.grpc_signer_url = Some(url.clone());
        }

        if let Some(ref path) = cli.grpc_signer_tls_cert {
            self.grpc_signer_tls_cert = Some(path.clone());
        }

        if let Some(ref path) = cli.grpc_signer_tls_key {
            self.grpc_signer_tls_key = Some(path.clone());
        }

        if let Some(ref path) = cli.grpc_signer_tls_ca_cert {
            self.grpc_signer_tls_ca_cert = Some(path.clone());
        }

        if let Some(disable_attesting) = cli.disable_attesting {
            self.disable_attesting = disable_attesting;
        }

        if let Some(ref action) = cli.slashed_validators_action {
            self.slashed_validators_action = action.clone();
        }

        if let Some(limit) = cli.builder_circuit_breaker_consecutive_limit {
            self.builder_circuit_breaker_consecutive_limit = limit;
        }

        if let Some(limit) = cli.builder_circuit_breaker_epoch_limit {
            self.builder_circuit_breaker_epoch_limit = limit;
        }

        if let Some(disable) = cli.disable_keystore_locking {
            self.disable_keystore_locking = disable;
        }

        if let Some(ref nodes) = cli.proposer_nodes {
            self.proposer_nodes = nodes.clone();
        }

        if let Some(ref topics) = cli.broadcast {
            self.broadcast = topics.clone();
        }

        if let Some(ref url) = cli.proposer_config_url {
            self.proposer_config_url = Some(url.clone());
        }

        if let Some(ref file) = cli.proposer_config_file {
            self.proposer_config_file = Some(file.clone());
        }

        if let Some(interval) = cli.proposer_config_refresh_interval {
            self.proposer_config_refresh_interval = interval;
        }

        if let Some(ref token) = cli.proposer_config_url_token {
            self.proposer_config_url_token = Some(token.clone());
        }

        if let Some(insecure) = cli.proposer_config_url_insecure {
            self.proposer_config_url_insecure = insecure;
        }

        if let Some(ref endpoint) = cli.monitoring_endpoint {
            self.monitoring_endpoint = Some(endpoint.clone());
        }

        if let Some(interval) = cli.monitoring_interval {
            self.monitoring_interval = interval;
        }

        if let Some(insecure) = cli.monitoring_endpoint_insecure {
            self.monitoring_endpoint_insecure = insecure;
        }

        if let Some(ref logfile) = cli.logfile {
            self.logfile = Some(logfile.clone());
        }

        if let Some(max_size) = cli.logfile_max_size {
            self.logfile_max_size = max_size;
        }

        if let Some(max_number) = cli.logfile_max_number {
            self.logfile_max_number = max_number;
        }

        if let Some(compress) = cli.logfile_compress {
            self.logfile_compress = compress;
        }

        if let Some(ref level) = cli.logfile_level {
            self.logfile_level = Some(level.clone());
        }

        if let Some(mode) = cli.block_selection_mode {
            self.block_selection_mode = mode;
        }

        if let Some(size) = cli.validator_registration_batch_size {
            self.validator_registration_batch_size = size;
        }

        if let Some(delay) = cli.validator_registration_batch_delay {
            self.validator_registration_batch_delay = delay;
        }

        if let Some(ref path) = cli.validators_config {
            self.validators_config = Some(path.clone());
        }

        if let Some(v) = cli.beacon_max_body_bytes {
            self.beacon_max_body_bytes = v;
        }
    }
}

/// Redacts credentials from a URL for safe logging.
///
/// If the URL contains a username, both the username and password are replaced
/// with `***`. Unparseable URLs are returned as-is.
pub fn redact_url(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut parsed) => {
            if !parsed.username().is_empty() {
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        Err(_) => raw.to_string(),
    }
}

#[derive(Debug, Default)]
pub struct CliOverrides {
    pub beacon_url: Option<String>,
    pub beacon_nodes: Option<Vec<String>>,
    pub keystore_path: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub slashing_db_path: Option<PathBuf>,
    pub metrics_address: Option<IpAddr>,
    pub metrics_port: Option<u16>,
    pub grpc_port: Option<u16>,
    pub grpc_address: Option<String>,
    pub network: Option<Network>,
    pub genesis_time: Option<u64>,
    pub genesis_validators_root: Option<String>,
    pub graffiti: Option<String>,
    pub log_level: Option<String>,
    pub doppelganger_detection: Option<bool>,
    pub keymanager_enabled: Option<bool>,
    pub keymanager_address: Option<String>,
    pub keymanager_token_file: Option<PathBuf>,
    pub remote_signer_url: Option<String>,
    pub remote_signer_allowed_hosts: Option<String>,
    pub key_decrypt_threads: Option<usize>,
    pub tracing_endpoint: Option<String>,
    pub tracing_exporter: Option<String>,
    pub tracing_sample_rate: Option<f64>,
    pub tracing_max_queue_size: Option<usize>,
    pub tracing_max_export_batch_size: Option<usize>,
    pub secret_provider: Option<String>,
    pub gcp_project_id: Option<String>,
    pub gcp_secret_prefix: Option<String>,
    pub secret_refresh_interval: Option<u64>,
    pub allow_insecure_remote_signer: Option<bool>,
    pub keymanager_cors_origins: Option<Vec<String>>,
    pub keymanager_body_limit: Option<usize>,
    pub grpc_signer_url: Option<String>,
    pub grpc_signer_tls_cert: Option<PathBuf>,
    pub grpc_signer_tls_key: Option<PathBuf>,
    pub grpc_signer_tls_ca_cert: Option<PathBuf>,
    pub disable_attesting: Option<bool>,
    pub slashed_validators_action: Option<String>,
    pub builder_circuit_breaker_consecutive_limit: Option<u32>,
    pub builder_circuit_breaker_epoch_limit: Option<u32>,
    pub disable_keystore_locking: Option<bool>,
    pub proposer_nodes: Option<Vec<String>>,
    pub broadcast: Option<Vec<String>>,
    pub proposer_config_url: Option<String>,
    pub proposer_config_file: Option<String>,
    pub proposer_config_refresh_interval: Option<u64>,
    pub proposer_config_url_token: Option<String>,
    pub proposer_config_url_insecure: Option<bool>,
    pub monitoring_endpoint: Option<String>,
    pub monitoring_interval: Option<u64>,
    pub monitoring_endpoint_insecure: Option<bool>,
    pub logfile: Option<PathBuf>,
    pub logfile_max_size: Option<u64>,
    pub logfile_max_number: Option<usize>,
    pub logfile_compress: Option<bool>,
    pub logfile_level: Option<String>,
    pub block_selection_mode: Option<validator_store::BlockSelectionMode>,
    pub validator_registration_batch_size: Option<usize>,
    pub validator_registration_batch_delay: Option<u64>,
    pub validators_config: Option<PathBuf>,
    /// Maximum JSON response body size from the BN (H-12).
    pub beacon_max_body_bytes: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.beacon_url, "http://localhost:5052");
        assert_eq!(config.keystore_path, PathBuf::from("./keystores"));
        assert_eq!(config.metrics_port, 8080);
        assert_eq!(config.metrics_address, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(config.grpc_port, 50051);
        assert_eq!(config.grpc_address, "127.0.0.1");
        assert_eq!(config.network, Network::Mainnet);
        assert!(config.genesis_time.is_none());
        assert!(config.genesis_validators_root.is_none());
    }

    #[test]
    fn test_merge_with_cli_metrics_address() {
        let mut config = Config::default();
        let cli = CliOverrides {
            metrics_address: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            ..Default::default()
        };

        config.merge_with_cli(&cli);

        assert_eq!(config.metrics_address, std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_merge_with_cli_metrics_address_none_preserves_default() {
        let mut config = Config::default();
        let cli = CliOverrides::default();

        config.merge_with_cli(&cli);

        assert_eq!(config.metrics_address, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_config_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
metrics_port = 9090
grpc_port = 50052
network = "hoodi"
log_level = "debug"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.beacon_url, "http://beacon:5052");
        assert_eq!(config.keystore_path, PathBuf::from("/data/keystores"));
        assert_eq!(config.slashing_db_path, PathBuf::from("/data/slashing.db"));
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.grpc_port, 50052);
        assert_eq!(config.network, Network::Hoodi);
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_config_file_not_found() {
        let result = Config::from_file("/nonexistent/config.toml");
        assert!(matches!(result, Err(ConfigError::FileNotFound(_))));
    }

    #[test]
    fn test_effective_genesis_time_from_network() {
        let config = Config { network: Network::Mainnet, genesis_time: None, ..Default::default() };
        assert_eq!(config.effective_genesis_time().unwrap(), 1606824023);
    }

    #[test]
    fn test_effective_genesis_time_override() {
        let config =
            Config { network: Network::Mainnet, genesis_time: Some(12345), ..Default::default() };
        assert_eq!(config.effective_genesis_time().unwrap(), 12345);
    }

    #[test]
    fn test_effective_genesis_time_custom_network_requires_explicit() {
        let config = Config { network: Network::Custom, genesis_time: None, ..Default::default() };
        assert!(config.effective_genesis_time().is_err());
    }

    #[test]
    fn test_effective_genesis_validators_root_from_network() {
        let config = Config {
            network: Network::Mainnet,
            genesis_validators_root: None,
            ..Default::default()
        };
        let root = config.effective_genesis_validators_root().unwrap();
        assert!(root.starts_with("0x"));
    }

    #[test]
    fn test_effective_genesis_validators_root_override() {
        let config = Config {
            network: Network::Mainnet,
            genesis_validators_root: Some("0xcustom".to_string()),
            ..Default::default()
        };
        assert_eq!(config.effective_genesis_validators_root().unwrap(), "0xcustom");
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_beacon_url() {
        let config = Config { beacon_url: "".to_string(), ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_invalid_beacon_url_scheme() {
        let config =
            Config { beacon_url: "ftp://localhost:5052".to_string(), ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_invalid_port() {
        let config = Config { metrics_port: 0, ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPort(_))));
    }

    #[test]
    fn test_validate_graffiti_too_long() {
        let config = Config {
            graffiti: Some("a".repeat(33)), // 33 bytes, exceeds 32 byte limit
            ..Default::default()
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidGraffiti(_))));
    }

    #[test]
    fn test_validate_graffiti_valid() {
        let config = Config {
            graffiti: Some("rvc".to_string()), // Valid graffiti
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_passwords() {
        let mut file = NamedTempFile::new().unwrap();
        // Use obviously fake test values to avoid secret detection warnings
        let test_pw_1 = format!("test_value_{}", 1);
        let test_pw_2 = format!("test_value_{}", 2);
        writeln!(file, "# Comment line\nabcd1234 = {}\n0x5678efgh = {}", test_pw_1, test_pw_2)
            .unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 2);
        assert!(passwords.contains_key("abcd1234"));
        assert!(passwords.contains_key("5678efgh"));
    }

    #[test]
    fn test_load_passwords_no_file() {
        let config = Config { password_file: None, ..Default::default() };
        let passwords = config.load_passwords().unwrap();
        assert!(passwords.is_empty());
    }

    #[test]
    fn test_merge_with_cli() {
        let mut config = Config::default();
        let cli = CliOverrides {
            beacon_url: Some("http://custom:5052".to_string()),
            metrics_port: Some(9999),
            network: Some(Network::Hoodi),
            ..Default::default()
        };

        config.merge_with_cli(&cli);

        assert_eq!(config.beacon_url, "http://custom:5052");
        assert_eq!(config.metrics_port, 9999);
        assert_eq!(config.network, Network::Hoodi);
        assert_eq!(config.grpc_port, 50051);
        assert_eq!(config.grpc_address, "127.0.0.1");
    }

    #[test]
    fn test_merge_with_cli_grpc_address() {
        let mut config = Config::default();
        let cli = CliOverrides { grpc_address: Some("0.0.0.0".to_string()), ..Default::default() };

        config.merge_with_cli(&cli);

        assert_eq!(config.grpc_address, "0.0.0.0");
    }

    #[test]
    fn test_config_from_file_with_grpc_address() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
grpc_address = "192.168.1.1"
network = "hoodi"
log_level = "debug"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.grpc_address, "192.168.1.1");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("beacon_url"));
        assert!(toml_str.contains("network"));
    }

    // -- beacon_nodes tests --

    #[test]
    fn test_default_config_beacon_nodes_empty() {
        let config = Config::default();
        assert!(config.beacon_nodes.is_empty());
    }

    #[test]
    fn test_default_config_doppelganger_detection_enabled() {
        let config = Config::default();
        assert!(config.doppelganger_detection);
    }

    #[test]
    fn test_effective_beacon_nodes_falls_back_to_beacon_url() {
        let config = Config { beacon_url: "http://primary:5052".to_string(), ..Default::default() };
        assert_eq!(config.effective_beacon_nodes(), vec!["http://primary:5052"]);
    }

    #[test]
    fn test_effective_beacon_nodes_uses_beacon_nodes_when_set() {
        let config = Config {
            beacon_url: "http://primary:5052".to_string(),
            beacon_nodes: vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()],
            ..Default::default()
        };
        assert_eq!(config.effective_beacon_nodes(), vec!["http://bn1:5052", "http://bn2:5052"]);
    }

    #[test]
    fn test_merge_with_cli_beacon_nodes() {
        let mut config = Config::default();
        let cli = CliOverrides {
            beacon_nodes: Some(vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()]),
            ..Default::default()
        };

        config.merge_with_cli(&cli);
        assert_eq!(config.beacon_nodes.len(), 2);
        assert_eq!(config.beacon_nodes[0], "http://bn1:5052");
    }

    #[test]
    fn test_merge_with_cli_doppelganger_detection() {
        let mut config = Config::default();
        assert!(config.doppelganger_detection);

        let cli = CliOverrides { doppelganger_detection: Some(false), ..Default::default() };
        config.merge_with_cli(&cli);
        assert!(!config.doppelganger_detection);
    }

    #[test]
    fn test_validate_beacon_nodes_invalid_scheme() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "ftp://bn2:5052".to_string()],
            ..Default::default()
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_beacon_nodes_empty_entry() {
        let config = Config { beacon_nodes: vec!["".to_string()], ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_beacon_nodes_valid() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "https://bn2:5052".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_from_file_with_beacon_nodes() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://primary:5052"
beacon_nodes = ["http://bn1:5052", "http://bn2:5052"]
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
doppelganger_detection = false
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.beacon_nodes.len(), 2);
        assert!(!config.doppelganger_detection);
    }

    // -- keymanager config tests --

    #[test]
    fn test_default_config_keymanager_disabled() {
        let config = Config::default();
        assert!(!config.keymanager_enabled);
        assert!(config.keymanager_address.is_none());
        assert!(config.keymanager_token_file.is_none());
        assert!(config.remote_signer_url.is_none());
    }

    #[test]
    fn test_merge_with_cli_keymanager_fields() {
        let mut config = Config::default();
        let cli = CliOverrides {
            keymanager_enabled: Some(true),
            keymanager_address: Some("0.0.0.0:5062".to_string()),
            keymanager_token_file: Some(PathBuf::from("/data/token.txt")),
            remote_signer_url: Some("https://signer.example.com".to_string()),
            ..Default::default()
        };

        config.merge_with_cli(&cli);

        assert!(config.keymanager_enabled);
        assert_eq!(config.keymanager_address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager_token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(config.remote_signer_url.as_deref(), Some("https://signer.example.com"));
    }

    #[test]
    fn test_config_from_file_with_keymanager() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
keymanager_enabled = true
keymanager_address = "0.0.0.0:5062"
keymanager_token_file = "/data/token.txt"
remote_signer_url = "https://signer.example.com"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.keymanager_enabled);
        assert_eq!(config.keymanager_address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager_token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(config.remote_signer_url.as_deref(), Some("https://signer.example.com"));
    }

    #[test]
    fn test_merge_with_cli_keymanager_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();

        config.merge_with_cli(&cli);

        assert!(!config.keymanager_enabled);
        assert!(config.keymanager_address.is_none());
        assert!(config.keymanager_token_file.is_none());
        assert!(config.remote_signer_url.is_none());
    }

    // -- key_decrypt_threads tests --

    #[test]
    fn test_default_config_key_decrypt_threads_none() {
        let config = Config::default();
        assert!(config.key_decrypt_threads.is_none());
    }

    #[test]
    fn test_merge_with_cli_key_decrypt_threads() {
        let mut config = Config::default();
        assert!(config.key_decrypt_threads.is_none());

        let cli = CliOverrides { key_decrypt_threads: Some(4), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.key_decrypt_threads, Some(4));
    }

    #[test]
    fn test_merge_with_cli_key_decrypt_threads_none_preserves_default() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.key_decrypt_threads.is_none());
    }

    #[test]
    fn test_config_from_file_with_key_decrypt_threads() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
key_decrypt_threads = 4
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.key_decrypt_threads, Some(4));
    }

    // -- tracing config tests --

    #[test]
    fn test_default_config_tracing_fields() {
        let config = Config::default();
        assert!(config.tracing_endpoint.is_none());
        assert_eq!(config.tracing_exporter, "otlp");
        assert!((config.tracing_sample_rate - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_merge_with_cli_tracing_endpoint() {
        let mut config = Config::default();
        let cli = CliOverrides {
            tracing_endpoint: Some("http://collector:4318".to_string()),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing_endpoint.as_deref(), Some("http://collector:4318"));
    }

    #[test]
    fn test_merge_with_cli_tracing_exporter() {
        let mut config = Config::default();
        let cli = CliOverrides { tracing_exporter: Some("gcp".to_string()), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing_exporter, "gcp");
    }

    #[test]
    fn test_merge_with_cli_tracing_sample_rate() {
        let mut config = Config::default();
        let cli = CliOverrides { tracing_sample_rate: Some(0.5), ..Default::default() };
        config.merge_with_cli(&cli);
        assert!((config.tracing_sample_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_merge_with_cli_tracing_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.tracing_endpoint.is_none());
        assert_eq!(config.tracing_exporter, "otlp");
        assert!((config.tracing_sample_rate - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_config_from_file_with_tracing() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
tracing_endpoint = "http://otel-collector:4318"
tracing_exporter = "otlp"
tracing_sample_rate = 0.1
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.tracing_endpoint.as_deref(), Some("http://otel-collector:4318"));
        assert_eq!(config.tracing_exporter, "otlp");
        assert!((config.tracing_sample_rate - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_config_from_file_without_tracing_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.tracing_endpoint.is_none());
        assert_eq!(config.tracing_exporter, "otlp");
        assert!((config.tracing_sample_rate - 0.01).abs() < f64::EPSILON);
    }

    // -- tracing batch config tests --

    #[test]
    fn test_default_config_tracing_batch_fields_none() {
        let config = Config::default();
        assert!(config.tracing_max_queue_size.is_none());
        assert!(config.tracing_max_export_batch_size.is_none());
    }

    #[test]
    fn test_merge_with_cli_tracing_max_queue_size() {
        let mut config = Config::default();
        let cli = CliOverrides { tracing_max_queue_size: Some(4096), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing_max_queue_size, Some(4096));
    }

    #[test]
    fn test_merge_with_cli_tracing_max_export_batch_size() {
        let mut config = Config::default();
        let cli = CliOverrides { tracing_max_export_batch_size: Some(1024), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing_max_export_batch_size, Some(1024));
    }

    #[test]
    fn test_merge_with_cli_tracing_batch_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.tracing_max_queue_size.is_none());
        assert!(config.tracing_max_export_batch_size.is_none());
    }

    #[test]
    fn test_config_from_file_with_tracing_batch() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
tracing_max_queue_size = 4096
tracing_max_export_batch_size = 1024
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.tracing_max_queue_size, Some(4096));
        assert_eq!(config.tracing_max_export_batch_size, Some(1024));
    }

    #[test]
    fn test_config_from_file_without_tracing_batch_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.tracing_max_queue_size.is_none());
        assert!(config.tracing_max_export_batch_size.is_none());
    }

    // -- redact_url tests --

    #[test]
    fn test_redact_url_with_credentials() {
        let result = redact_url("http://user:pass@host:5052");
        assert_eq!(result, "http://***:***@host:5052/");
    }

    #[test]
    fn test_redact_url_with_username_only() {
        let result = redact_url("http://user@host:5052");
        assert_eq!(result, "http://***:***@host:5052/");
    }

    #[test]
    fn test_redact_url_without_credentials() {
        let result = redact_url("http://host:5052");
        assert_eq!(result, "http://host:5052/");
    }

    #[test]
    fn test_redact_url_https_without_credentials() {
        let result = redact_url("https://beacon.example.com:5052/eth/v1");
        assert_eq!(result, "https://beacon.example.com:5052/eth/v1");
    }

    #[test]
    fn test_redact_url_invalid_input() {
        let result = redact_url("not-a-url");
        assert_eq!(result, "not-a-url");
    }

    #[test]
    fn test_redact_url_empty_input() {
        let result = redact_url("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_config_from_file_without_key_decrypt_threads() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.key_decrypt_threads.is_none());
    }

    // -- remote_signer_allowed_hosts tests --

    #[test]
    fn test_default_config_remote_signer_allowed_hosts_none() {
        let config = Config::default();
        assert!(config.remote_signer_allowed_hosts.is_none());
    }

    #[test]
    fn test_merge_with_cli_remote_signer_allowed_hosts() {
        let mut config = Config::default();
        let cli = CliOverrides {
            remote_signer_allowed_hosts: Some("host1.com,host2.com".to_string()),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(
            config.remote_signer_allowed_hosts,
            Some(vec!["host1.com".to_string(), "host2.com".to_string()])
        );
    }

    #[test]
    fn test_merge_with_cli_remote_signer_allowed_hosts_with_spaces() {
        let mut config = Config::default();
        let cli = CliOverrides {
            remote_signer_allowed_hosts: Some(" host1.com , host2.com ".to_string()),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(
            config.remote_signer_allowed_hosts,
            Some(vec!["host1.com".to_string(), "host2.com".to_string()])
        );
    }

    #[test]
    fn test_merge_with_cli_remote_signer_allowed_hosts_none_preserves_default() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.remote_signer_allowed_hosts.is_none());
    }

    #[test]
    fn test_config_from_file_with_remote_signer_allowed_hosts() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
remote_signer_allowed_hosts = ["signer1.com", "signer2.com"]
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(
            config.remote_signer_allowed_hosts,
            Some(vec!["signer1.com".to_string(), "signer2.com".to_string()])
        );
    }

    // -- secret provider config tests --

    #[test]
    fn test_default_config_secret_providers_empty() {
        let config = Config::default();
        assert!(config.secret_provider.providers.is_empty());
        assert!(config.secret_provider.gcp.project_id.is_none());
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_merge_with_cli_secret_provider() {
        let mut config = Config::default();
        let cli = CliOverrides {
            secret_provider: Some("gcp".to_string()),
            gcp_project_id: Some("my-project".to_string()),
            gcp_secret_prefix: Some("key-".to_string()),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string()]);
        assert_eq!(config.secret_provider.gcp.project_id, Some("my-project".to_string()));
        assert_eq!(config.secret_provider.gcp.secret_prefix, "key-");
    }

    #[test]
    fn test_merge_with_cli_secret_provider_comma_separated() {
        let mut config = Config::default();
        let cli =
            CliOverrides { secret_provider: Some("gcp,aws".to_string()), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string(), "aws".to_string()]);
    }

    #[test]
    fn test_merge_with_cli_secret_provider_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.secret_provider.providers.is_empty());
        assert!(config.secret_provider.gcp.project_id.is_none());
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_validate_gcp_provider_missing_project_id() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig { project_id: None, ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("gcp_project_id"),
            "error should mention gcp_project_id: {}",
            err
        );
    }

    #[test]
    fn test_validate_gcp_provider_with_project_id_ok() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("my-project".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_no_providers_ok() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_from_file_with_secret_provider() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"

[secret_provider]
providers = ["gcp"]

[secret_provider.gcp]
project_id = "my-gcp-project"
secret_prefix = "val-key-"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string()]);
        assert_eq!(config.secret_provider.gcp.project_id, Some("my-gcp-project".to_string()));
        assert_eq!(config.secret_provider.gcp.secret_prefix, "val-key-");
    }

    #[test]
    fn test_merge_with_cli_no_gcp_secret_prefix_preserves_config_file() {
        let mut config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("my-project".to_string()),
                    secret_prefix: "custom-prefix-".to_string(),
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let cli = CliOverrides { gcp_secret_prefix: None, ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(
            config.secret_provider.gcp.secret_prefix, "custom-prefix-",
            "config file gcp_secret_prefix should be preserved when CLI does not specify it"
        );
    }

    #[test]
    fn test_validate_gcp_provider_empty_project_id() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig { project_id: Some("".to_string()), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err(), "empty gcp_project_id should fail validation");
    }

    #[test]
    fn test_validate_gcp_provider_whitespace_project_id() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig { project_id: Some("   ".to_string()), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err(), "whitespace-only gcp_project_id should fail validation");
    }

    #[test]
    fn test_config_from_file_with_nested_gcp_section() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"

[secret_provider]
providers = ["gcp"]
refresh_interval = 300

[secret_provider.gcp]
project_id = "my-project"
secret_prefix = "validator-key-"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string()]);
        assert_eq!(config.secret_provider.refresh_interval, Some(300));
        assert_eq!(config.secret_provider.gcp.project_id, Some("my-project".to_string()));
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_config_from_file_without_secret_provider_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.secret_provider.providers.is_empty());
        assert!(config.secret_provider.refresh_interval.is_none());
        assert!(config.secret_provider.gcp.project_id.is_none());
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_merge_with_cli_overrides_gcp_project_id() {
        let mut config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("config-project".to_string()),
                    secret_prefix: "config-prefix-".to_string(),
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let cli =
            CliOverrides { gcp_project_id: Some("cli-project".to_string()), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(
            config.secret_provider.gcp.project_id,
            Some("cli-project".to_string()),
            "CLI should override config.toml gcp project_id"
        );
        assert_eq!(
            config.secret_provider.gcp.secret_prefix, "config-prefix-",
            "config.toml secret_prefix should be preserved when CLI does not specify it"
        );
    }

    #[test]
    fn test_default_config_refresh_interval_none() {
        let config = Config::default();
        assert!(config.secret_provider.refresh_interval.is_none());
    }

    #[test]
    fn test_merge_with_cli_secret_refresh_interval() {
        let mut config = Config::default();
        let cli = CliOverrides { secret_refresh_interval: Some(120), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.secret_provider.refresh_interval, Some(120));
    }

    #[test]
    fn test_merge_with_cli_no_secret_refresh_interval_preserves_config() {
        let mut config = Config {
            secret_provider: SecretProviderConfig {
                refresh_interval: Some(300),
                ..Default::default()
            },
            ..Default::default()
        };
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert_eq!(config.secret_provider.refresh_interval, Some(300));
    }

    #[test]
    fn test_insecure_flag_env_var_validation() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        // Case 1: insecure flag false skips env check
        std::env::remove_var("RVC_ALLOW_INSECURE");
        let config = Config::default();
        assert!(!config.allow_insecure_remote_signer);
        assert!(config.validate().is_ok(), "Should pass when insecure flag is false");

        // Case 2: insecure flag true without env var fails
        let config = Config { allow_insecure_remote_signer: true, ..Config::default() };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("RVC_ALLOW_INSECURE"),
            "Error should mention RVC_ALLOW_INSECURE, got: {}",
            err
        );

        // Case 3: insecure flag true with wrong env var value fails
        std::env::set_var("RVC_ALLOW_INSECURE", "yes");
        let config = Config { allow_insecure_remote_signer: true, ..Config::default() };
        assert!(config.validate().is_err(), "Should fail with RVC_ALLOW_INSECURE=yes (not 'true')");

        // Case 4: insecure flag true with correct env var passes
        std::env::set_var("RVC_ALLOW_INSECURE", "true");
        let config = Config { allow_insecure_remote_signer: true, ..Config::default() };
        assert!(config.validate().is_ok(), "Should pass with RVC_ALLOW_INSECURE=true");

        std::env::remove_var("RVC_ALLOW_INSECURE");
    }

    #[test]
    fn test_default_circuit_breaker_limits() {
        let config = Config::default();
        assert_eq!(config.builder_circuit_breaker_consecutive_limit, 3);
        assert_eq!(config.builder_circuit_breaker_epoch_limit, 5);
    }

    #[test]
    fn test_default_keystore_locking_enabled() {
        let config = Config::default();
        assert!(!config.disable_keystore_locking);
    }

    #[test]
    fn test_merge_circuit_breaker_limits() {
        let mut config = Config::default();
        let cli = CliOverrides {
            builder_circuit_breaker_consecutive_limit: Some(10),
            builder_circuit_breaker_epoch_limit: Some(20),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(config.builder_circuit_breaker_consecutive_limit, 10);
        assert_eq!(config.builder_circuit_breaker_epoch_limit, 20);
    }

    #[test]
    fn test_merge_disable_keystore_locking() {
        let mut config = Config::default();
        let cli = CliOverrides { disable_keystore_locking: Some(true), ..Default::default() };
        config.merge_with_cli(&cli);
        assert!(config.disable_keystore_locking);
    }

    #[test]
    fn test_circuit_breaker_toml_parsing() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
builder_circuit_breaker_consecutive_limit = 7
builder_circuit_breaker_epoch_limit = 12
disable_keystore_locking = true
"#
        )
        .unwrap();
        let config = Config::from_file(f.path()).unwrap();
        assert_eq!(config.builder_circuit_breaker_consecutive_limit, 7);
        assert_eq!(config.builder_circuit_breaker_epoch_limit, 12);
        assert!(config.disable_keystore_locking);
    }

    // --- T3.2/T3.4: Proposer nodes and broadcast topics config ---

    #[test]
    fn test_effective_broadcast_topics_default() {
        let config = Config::default();
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn test_effective_broadcast_topics_none() {
        let config = Config { broadcast: vec!["none".to_string()], ..Default::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn test_effective_broadcast_topics_partial() {
        let config = Config {
            broadcast: vec!["blocks".to_string(), "attestations".to_string()],
            ..Default::default()
        };
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn test_validate_invalid_broadcast_topic() {
        let config = Config { broadcast: vec!["invalid-topic".to_string()], ..Default::default() };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_broadcast_none_with_others_fails() {
        let config = Config {
            broadcast: vec!["none".to_string(), "blocks".to_string()],
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_proposer_config_mutual_exclusivity() {
        let config = Config {
            proposer_config_url: Some("https://example.com/config".to_string()),
            proposer_config_file: Some("/path/to/config.json".to_string()),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_proposer_config_url_only() {
        let config = Config {
            proposer_config_url: Some("https://example.com/config".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_proposer_config_file_only() {
        let config = Config {
            proposer_config_file: Some("/path/to/config.json".to_string()),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_default_config_proposer_fields() {
        let config = Config::default();
        assert!(config.proposer_nodes.is_empty());
        assert!(config.broadcast.is_empty());
        assert!(config.proposer_config_url.is_none());
        assert!(config.proposer_config_file.is_none());
        assert_eq!(config.proposer_config_refresh_interval, 384);
        assert!(config.proposer_config_url_token.is_none());
        assert!(!config.proposer_config_url_insecure);
    }

    #[test]
    fn test_proposer_nodes_toml_parsing() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
proposer_nodes = ["http://proposer1:5052", "http://proposer2:5052"]
broadcast = ["blocks", "attestations"]
"#
        )
        .unwrap();
        let config = Config::from_file(f.path()).unwrap();
        assert_eq!(config.proposer_nodes.len(), 2);
        assert_eq!(config.proposer_nodes[0], "http://proposer1:5052");
        assert_eq!(config.broadcast.len(), 2);
    }

    #[test]
    fn test_validate_invalid_proposer_node_url() {
        let config =
            Config { proposer_nodes: vec!["ftp://invalid:5052".to_string()], ..Default::default() };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_with_cli_proposer_fields() {
        let mut config = Config::default();
        let cli = CliOverrides {
            proposer_nodes: Some(vec!["http://p1:5052".to_string()]),
            broadcast: Some(vec!["blocks".to_string()]),
            proposer_config_url: Some("https://example.com/config".to_string()),
            proposer_config_refresh_interval: Some(60),
            proposer_config_url_token: Some("my-token".to_string()),
            proposer_config_url_insecure: Some(true),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(config.proposer_nodes.len(), 1);
        assert_eq!(config.broadcast, vec!["blocks".to_string()]);
        assert_eq!(config.proposer_config_url, Some("https://example.com/config".to_string()));
        assert_eq!(config.proposer_config_refresh_interval, 60);
        assert_eq!(config.proposer_config_url_token, Some("my-token".to_string()));
        assert!(config.proposer_config_url_insecure);
    }

    // -- CQ-2.5: strip_prefix_strict adoption test --

    /// load_passwords must warn and skip a pubkey entry that carries a double 0x prefix.
    #[test]
    #[tracing_test::traced_test]
    fn test_load_passwords_double_0x_prefix_warns_and_skips() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x0xabcd1234 = test_value_1").unwrap();
        // Also write a valid entry so we can confirm only the bad one is skipped
        writeln!(file, "0xdeadbeef = test_value_2").unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1, "only the valid entry should be loaded");
        assert!(!passwords.contains_key("0x0xabcd1234"), "double-0x key must be absent");
        assert!(
            passwords.contains_key("deadbeef"),
            "valid entry must be present (prefix stripped)"
        );
        assert!(logs_contain("double 0x prefix"), "expected warn log about double prefix");
    }
}
