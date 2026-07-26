//! Configuration types for the validator client.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bn_manager::BnRole;
use observability::hex::{strip_prefix_strict, HexError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tracing::warn;

use url::Url;

use beacon::ResponseCaps;

use super::error::ConfigError;
use super::network::Network;

/// Action taken when a managed validator is detected as slashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlashedAction {
    /// Disable the validator in the store and keep running.
    #[default]
    DisableOnly,
    /// Request process shutdown.
    Shutdown,
    /// Do not monitor / take no action.
    None,
}

impl fmt::Display for SlashedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisableOnly => write!(f, "disable-only"),
            Self::Shutdown => write!(f, "shutdown"),
            Self::None => write!(f, "none"),
        }
    }
}

impl FromStr for SlashedAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disable-only" => Ok(Self::DisableOnly),
            "shutdown" => Ok(Self::Shutdown),
            "none" => Ok(Self::None),
            other => Err(format!(
                "invalid slashed-validators-action '{other}': must be one of disable-only, shutdown, none"
            )),
        }
    }
}

/// Message types that may be broadcast to all beacon nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BroadcastTopic {
    Attestations,
    Blocks,
    SyncCommittee,
    Subscriptions,
    /// Disable all broadcast (must appear alone).
    None,
}

impl fmt::Display for BroadcastTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attestations => write!(f, "attestations"),
            Self::Blocks => write!(f, "blocks"),
            Self::SyncCommittee => write!(f, "sync-committee"),
            Self::Subscriptions => write!(f, "subscriptions"),
            Self::None => write!(f, "none"),
        }
    }
}

impl FromStr for BroadcastTopic {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "attestations" => Ok(Self::Attestations),
            "blocks" => Ok(Self::Blocks),
            "sync-committee" => Ok(Self::SyncCommittee),
            "subscriptions" => Ok(Self::Subscriptions),
            "none" => Ok(Self::None),
            other => Err(format!(
                "invalid broadcast topic '{other}': must be one of attestations, blocks, sync-committee, subscriptions, none"
            )),
        }
    }
}

/// OpenTelemetry exporter backend selected in config / CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TracingExporter {
    /// OTLP over HTTP (default).
    #[default]
    Otlp,
    /// Google Cloud Trace (requires the `gcp-trace` feature on the binary).
    Gcp,
}

impl fmt::Display for TracingExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Otlp => write!(f, "otlp"),
            Self::Gcp => write!(f, "gcp"),
        }
    }
}

impl FromStr for TracingExporter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "otlp" => Ok(Self::Otlp),
            "gcp" => Ok(Self::Gcp),
            other => Err(format!("invalid tracing_exporter '{other}': must be one of otlp, gcp")),
        }
    }
}

/// Validator client configuration.
///
/// Related knobs are grouped into nested sub-structs (`logfile`, `tracing`,
/// `keymanager`, `grpc_signer`, `proposer_config`, `monitoring`,
/// `builder_limits`). Existing operator TOML may still use the pre-nesting
/// **flat** keys; both spellings are accepted (see `ConfigWire`).
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct Config {
    pub beacon_url: String,

    #[serde(default)]
    pub beacon_nodes: Vec<String>,

    pub keystore_path: PathBuf,

    pub password_file: Option<PathBuf>,

    pub slashing_db_path: PathBuf,

    /// Allow creating a fresh empty slashing-protection DB when the path is
    /// missing (SEC-3).
    ///
    /// Default `false`: a missing DB aborts startup so a lost volume, path typo,
    /// or ephemeral container storage cannot silently produce zero-history
    /// signing. Set via config `allow_fresh_db = true` or CLI
    /// `--init-slashing-db`. A 0-byte / corrupt-header file is **always** a hard
    /// error regardless of this flag. Never wipes a non-empty DB.
    #[serde(default)]
    pub allow_fresh_db: bool,

    /// Allow startup when the beacon node's current fork version is not in the
    /// client's fork schedule (SEC-9 / M-15).
    ///
    /// Default `false`: an unknown fork aborts startup so the VC cannot produce
    /// invalid signatures after a network upgrade. Set `true` only for testnets
    /// or experimental forks where the schedule is intentionally incomplete.
    #[serde(default)]
    pub allow_unsupported_fork: bool,

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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_decrypt_threads: Option<usize>,

    #[serde(default)]
    pub secret_provider: SecretProviderConfig,

    #[serde(default)]
    pub disable_attesting: bool,

    #[serde(default)]
    pub slashed_validators_action: SlashedAction,

    #[serde(default)]
    pub disable_keystore_locking: bool,

    // --- Nested groups (source of truth for serde + RF5-13 call sites) ---
    #[serde(default)]
    pub logfile: LogfileConfig,

    #[serde(default)]
    pub tracing: TracingConfig,

    #[serde(default)]
    pub keymanager: KeymanagerConfig,

    #[serde(default)]
    pub grpc_signer: GrpcSignerConfig,

    #[serde(default)]
    pub proposer_config: ProposerConfigSource,

    #[serde(default)]
    pub monitoring: MonitoringConfig,

    #[serde(default)]
    pub builder_limits: BuilderLimits,

    // --- Proposer nodes / broadcast (remain flat) ---
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposer_nodes: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broadcast: Vec<BroadcastTopic>,

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

/// Per-BN configuration entry for `[[beacon_nodes]]` TOML tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconNodeEntry {
    pub url: String,
    #[serde(default = "default_bn_roles")]
    pub roles: Vec<BnRole>,
}

fn default_bn_roles() -> Vec<BnRole> {
    vec![BnRole::All]
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

    /// When true, any secret-provider `list_keys` failure aborts startup (SEC-9 / M-9).
    ///
    /// Default `false`: a single flaky provider is logged and skipped so healthy
    /// providers can still load keys. A failure of **all** configured providers
    /// remains fatal regardless of this flag.
    #[serde(default)]
    pub strict: bool,

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

fn default_tracing_sample_rate() -> f64 {
    0.01
}

// ---------------------------------------------------------------------------
// Nested config groups (RF5-12/RF5-13).
// ---------------------------------------------------------------------------

/// Log-file rotation settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogfileConfig {
    /// Path to the log file (`logfile` flat key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Max size in MB before rotation.
    #[serde(default = "default_logfile_max_size")]
    pub max_size: u64,
    /// Max number of rotated files to keep.
    #[serde(default = "default_logfile_max_number")]
    pub max_number: usize,
    /// Compress rotated files.
    #[serde(default)]
    pub compress: bool,
    /// Optional override log level for the file sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
}

impl Default for LogfileConfig {
    fn default() -> Self {
        Self {
            path: None,
            max_size: default_logfile_max_size(),
            max_number: default_logfile_max_number(),
            compress: false,
            level: None,
        }
    }
}

/// Distributed tracing / OpenTelemetry settings.
///
/// `sample_rate` is `Option` end-to-end so an explicit `0.01` is distinguishable
/// from "unset" (RF5-15 / F20). Resolve with [`TracingConfig::resolve_sample_rate`]
/// / [`TracingConfig::resolve_endpoint`] — precedence is CLI > file > `OTEL_*` env >
/// built-in default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TracingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub exporter: TracingExporter,
    /// Head-based sampling ratio when set. `None` means "not configured" so
    /// `OTEL_TRACES_SAMPLER_ARG` and the 0.01 built-in default can apply at
    /// resolution time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queue_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_export_batch_size: Option<usize>,
}

impl TracingConfig {
    /// Resolve the OTLP endpoint: explicit config/CLI > `OTEL_EXPORTER_OTLP_ENDPOINT`.
    ///
    /// Returns `None` when neither source provides a value (tracing stays disabled).
    pub fn resolve_endpoint(&self) -> Option<String> {
        self.endpoint.clone().or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
    }

    /// Resolve the sample rate: explicit config/CLI > `OTEL_TRACES_SAMPLER_ARG` > 0.01.
    ///
    /// Values outside `0.0..=1.0` are clamped with a warning.
    pub fn resolve_sample_rate(&self) -> f64 {
        let mut rate = match self.sample_rate {
            Some(rate) => rate,
            None => match std::env::var("OTEL_TRACES_SAMPLER_ARG") {
                Ok(env_rate) => {
                    env_rate.parse::<f64>().unwrap_or_else(|_| default_tracing_sample_rate())
                }
                Err(_) => default_tracing_sample_rate(),
            },
        };

        if !(0.0..=1.0).contains(&rate) {
            warn!(sample_rate = rate, "tracing_sample_rate out of range 0.0..=1.0, clamping");
            rate = rate.clamp(0.0, 1.0);
        }
        rate
    }
}

/// Keymanager API and remote-signer settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeymanagerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure_remote_signer: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cors_origins: Vec<String>,
    #[serde(default = "default_keymanager_body_limit")]
    pub body_limit: usize,
}

impl Default for KeymanagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: None,
            token_file: None,
            remote_signer_url: None,
            remote_signer_allowed_hosts: None,
            allow_insecure_remote_signer: false,
            cors_origins: Vec::new(),
            body_limit: default_keymanager_body_limit(),
        }
    }
}

/// gRPC remote signer connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GrpcSignerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_cert: Option<PathBuf>,
}

/// Proposer-config URL / file source settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProposerConfigSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default = "default_proposer_config_refresh_interval")]
    pub refresh_interval: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_token: Option<String>,
    #[serde(default)]
    pub url_insecure: bool,
}

impl Default for ProposerConfigSource {
    fn default() -> Self {
        Self {
            url: None,
            file: None,
            refresh_interval: default_proposer_config_refresh_interval(),
            url_token: None,
            url_insecure: false,
        }
    }
}

/// Monitoring push-endpoint settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default = "default_monitoring_interval")]
    pub interval: u64,
    #[serde(default)]
    pub endpoint_insecure: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self { endpoint: None, interval: default_monitoring_interval(), endpoint_insecure: false }
    }
}

/// Builder circuit-breaker limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BuilderLimits {
    #[serde(default = "default_circuit_breaker_consecutive_limit")]
    pub circuit_breaker_consecutive_limit: u32,
    #[serde(default = "default_circuit_breaker_epoch_limit")]
    pub circuit_breaker_epoch_limit: u32,
}

impl Default for BuilderLimits {
    fn default() -> Self {
        Self {
            circuit_breaker_consecutive_limit: default_circuit_breaker_consecutive_limit(),
            circuit_breaker_epoch_limit: default_circuit_breaker_epoch_limit(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            beacon_url: "http://localhost:5052".to_string(),
            beacon_nodes: Vec::new(),
            keystore_path: PathBuf::from("./keystores"),
            password_file: None,
            slashing_db_path: PathBuf::from("./slashing_protection.sqlite"),
            allow_fresh_db: false,
            allow_unsupported_fork: false,
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
            key_decrypt_threads: None,
            secret_provider: SecretProviderConfig::default(),
            disable_attesting: false,
            slashed_validators_action: SlashedAction::default(),
            disable_keystore_locking: false,
            logfile: LogfileConfig::default(),
            tracing: TracingConfig::default(),
            keymanager: KeymanagerConfig::default(),
            grpc_signer: GrpcSignerConfig::default(),
            proposer_config: ProposerConfigSource::default(),
            monitoring: MonitoringConfig::default(),
            builder_limits: BuilderLimits::default(),
            proposer_nodes: Vec::new(),
            broadcast: Vec::new(),
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

/// Intermediate wire format that accepts **both** nested tables and legacy flat
/// keys. Flat keys fill fields that the corresponding nested table left at
/// default; when both spellings set the same logical field, the **flat** key
/// wins (operators with existing files keep working without edits).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConfigWire {
    beacon_url: String,
    beacon_nodes: Vec<String>,
    keystore_path: PathBuf,
    password_file: Option<PathBuf>,
    slashing_db_path: PathBuf,
    allow_fresh_db: bool,
    allow_unsupported_fork: bool,
    metrics_address: Option<IpAddr>,
    metrics_port: Option<u16>,
    grpc_port: Option<u16>,
    grpc_address: Option<String>,
    network: Option<Network>,
    genesis_time: Option<u64>,
    genesis_validators_root: Option<String>,
    graffiti: Option<String>,
    log_level: Option<String>,
    doppelganger_detection: Option<bool>,
    key_decrypt_threads: Option<usize>,
    secret_provider: SecretProviderConfig,
    disable_attesting: bool,
    slashed_validators_action: SlashedAction,
    disable_keystore_locking: bool,
    proposer_nodes: Vec<String>,
    broadcast: Vec<BroadcastTopic>,
    bn_sync_tolerances: Option<String>,
    beacon_nodes_config: Vec<BeaconNodeEntry>,
    block_selection_mode: validator_store::BlockSelectionMode,
    validator_registration_batch_size: Option<usize>,
    validator_registration_batch_delay: Option<u64>,
    validators_config: Option<PathBuf>,
    beacon_max_body_bytes: Option<usize>,

    // Nested tables (new spelling)
    #[serde(default)]
    logfile: LogfileConfig,
    #[serde(default)]
    tracing: TracingConfig,
    #[serde(default)]
    keymanager: KeymanagerConfig,
    #[serde(default)]
    grpc_signer: GrpcSignerConfig,
    #[serde(default)]
    proposer_config: ProposerConfigSource,
    #[serde(default)]
    monitoring: MonitoringConfig,
    #[serde(default)]
    builder_limits: BuilderLimits,

    // Flat legacy keys (old spelling) — Option so we can detect presence
    keymanager_enabled: Option<bool>,
    keymanager_address: Option<String>,
    keymanager_token_file: Option<PathBuf>,
    remote_signer_url: Option<String>,
    remote_signer_allowed_hosts: Option<Vec<String>>,
    allow_insecure_remote_signer: Option<bool>,
    keymanager_cors_origins: Option<Vec<String>>,
    keymanager_body_limit: Option<usize>,
    tracing_endpoint: Option<String>,
    tracing_exporter: Option<TracingExporter>,
    tracing_sample_rate: Option<f64>,
    tracing_max_queue_size: Option<usize>,
    tracing_max_export_batch_size: Option<usize>,
    grpc_signer_url: Option<String>,
    grpc_signer_tls_cert: Option<PathBuf>,
    grpc_signer_tls_key: Option<PathBuf>,
    grpc_signer_tls_ca_cert: Option<PathBuf>,
    builder_circuit_breaker_consecutive_limit: Option<u32>,
    builder_circuit_breaker_epoch_limit: Option<u32>,
    monitoring_endpoint: Option<String>,
    monitoring_interval: Option<u64>,
    monitoring_endpoint_insecure: Option<bool>,
    proposer_config_url: Option<String>,
    proposer_config_file: Option<String>,
    proposer_config_refresh_interval: Option<u64>,
    proposer_config_url_token: Option<String>,
    proposer_config_url_insecure: Option<bool>,
    logfile_max_size: Option<u64>,
    logfile_max_number: Option<usize>,
    logfile_compress: Option<bool>,
    logfile_level: Option<String>,
}

impl From<ConfigWire> for Config {
    fn from(w: ConfigWire) -> Self {
        let mut logfile = w.logfile;
        if let Some(v) = w.logfile_max_size {
            logfile.max_size = v;
        }
        if let Some(v) = w.logfile_max_number {
            logfile.max_number = v;
        }
        if let Some(v) = w.logfile_compress {
            logfile.compress = v;
        }
        if let Some(v) = w.logfile_level {
            logfile.level = Some(v);
        }
        // flat path handled in custom deserialize (toml Value path)

        let mut tracing = w.tracing;
        if let Some(v) = w.tracing_endpoint {
            tracing.endpoint = Some(v);
        }
        if let Some(v) = w.tracing_exporter {
            tracing.exporter = v;
        }
        if let Some(v) = w.tracing_sample_rate {
            tracing.sample_rate = Some(v);
        }
        if let Some(v) = w.tracing_max_queue_size {
            tracing.max_queue_size = Some(v);
        }
        if let Some(v) = w.tracing_max_export_batch_size {
            tracing.max_export_batch_size = Some(v);
        }

        let mut keymanager = w.keymanager;
        if let Some(v) = w.keymanager_enabled {
            keymanager.enabled = v;
        }
        if let Some(v) = w.keymanager_address {
            keymanager.address = Some(v);
        }
        if let Some(v) = w.keymanager_token_file {
            keymanager.token_file = Some(v);
        }
        if let Some(v) = w.remote_signer_url {
            keymanager.remote_signer_url = Some(v);
        }
        if let Some(v) = w.remote_signer_allowed_hosts {
            keymanager.remote_signer_allowed_hosts = Some(v);
        }
        if let Some(v) = w.allow_insecure_remote_signer {
            keymanager.allow_insecure_remote_signer = v;
        }
        if let Some(v) = w.keymanager_cors_origins {
            keymanager.cors_origins = v;
        }
        if let Some(v) = w.keymanager_body_limit {
            keymanager.body_limit = v;
        }

        let mut grpc_signer = w.grpc_signer;
        if let Some(v) = w.grpc_signer_url {
            grpc_signer.url = Some(v);
        }
        if let Some(v) = w.grpc_signer_tls_cert {
            grpc_signer.tls_cert = Some(v);
        }
        if let Some(v) = w.grpc_signer_tls_key {
            grpc_signer.tls_key = Some(v);
        }
        if let Some(v) = w.grpc_signer_tls_ca_cert {
            grpc_signer.tls_ca_cert = Some(v);
        }

        let mut proposer_config = w.proposer_config;
        if let Some(v) = w.proposer_config_url {
            proposer_config.url = Some(v);
        }
        if let Some(v) = w.proposer_config_file {
            proposer_config.file = Some(v);
        }
        if let Some(v) = w.proposer_config_refresh_interval {
            proposer_config.refresh_interval = v;
        }
        if let Some(v) = w.proposer_config_url_token {
            proposer_config.url_token = Some(v);
        }
        if let Some(v) = w.proposer_config_url_insecure {
            proposer_config.url_insecure = v;
        }

        let mut monitoring = w.monitoring;
        if let Some(v) = w.monitoring_endpoint {
            monitoring.endpoint = Some(v);
        }
        if let Some(v) = w.monitoring_interval {
            monitoring.interval = v;
        }
        if let Some(v) = w.monitoring_endpoint_insecure {
            monitoring.endpoint_insecure = v;
        }

        let mut builder_limits = w.builder_limits;
        if let Some(v) = w.builder_circuit_breaker_consecutive_limit {
            builder_limits.circuit_breaker_consecutive_limit = v;
        }
        if let Some(v) = w.builder_circuit_breaker_epoch_limit {
            builder_limits.circuit_breaker_epoch_limit = v;
        }

        let def = Config::default();
        Config {
            beacon_url: if w.beacon_url.is_empty() { def.beacon_url } else { w.beacon_url },
            beacon_nodes: w.beacon_nodes,
            keystore_path: if w.keystore_path.as_os_str().is_empty() {
                def.keystore_path
            } else {
                w.keystore_path
            },
            password_file: w.password_file,
            slashing_db_path: if w.slashing_db_path.as_os_str().is_empty() {
                def.slashing_db_path
            } else {
                w.slashing_db_path
            },
            allow_fresh_db: w.allow_fresh_db,
            allow_unsupported_fork: w.allow_unsupported_fork,
            metrics_address: w.metrics_address.unwrap_or(def.metrics_address),
            metrics_port: w.metrics_port.unwrap_or(def.metrics_port),
            grpc_port: w.grpc_port.unwrap_or(def.grpc_port),
            grpc_address: w.grpc_address.unwrap_or(def.grpc_address),
            network: w.network.unwrap_or(def.network),
            genesis_time: w.genesis_time,
            genesis_validators_root: w.genesis_validators_root,
            graffiti: w.graffiti,
            log_level: w.log_level.unwrap_or(def.log_level),
            doppelganger_detection: w.doppelganger_detection.unwrap_or(def.doppelganger_detection),
            key_decrypt_threads: w.key_decrypt_threads,
            secret_provider: w.secret_provider,
            disable_attesting: w.disable_attesting,
            slashed_validators_action: w.slashed_validators_action,
            disable_keystore_locking: w.disable_keystore_locking,
            logfile,
            tracing,
            keymanager,
            grpc_signer,
            proposer_config,
            monitoring,
            builder_limits,
            proposer_nodes: w.proposer_nodes,
            broadcast: w.broadcast,
            bn_sync_tolerances: w.bn_sync_tolerances,
            beacon_nodes_config: w.beacon_nodes_config,
            block_selection_mode: w.block_selection_mode,
            validator_registration_batch_size: w
                .validator_registration_batch_size
                .unwrap_or(def.validator_registration_batch_size),
            validator_registration_batch_delay: w
                .validator_registration_batch_delay
                .unwrap_or(def.validator_registration_batch_delay),
            validators_config: w.validators_config,
            beacon_max_body_bytes: w.beacon_max_body_bytes.unwrap_or(def.beacon_max_body_bytes),
        }
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Parse as toml-compatible Value first so we can accept both a flat
        // `logfile = "path"` string and a `[logfile]` table (same key, different
        // shapes — not co-representable in one derive struct).
        let value = toml::Value::deserialize(deserializer)?;
        let mut map = match value {
            toml::Value::Table(t) => t,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "config must be a TOML table, got {other:?}"
                )));
            }
        };

        // Pull flat logfile path string before nested table deserialize.
        let flat_logfile_path = match map.remove("logfile") {
            Some(toml::Value::String(s)) => Some(PathBuf::from(s)),
            Some(toml::Value::Table(t)) => {
                // Put nested table back under a private key for ConfigWire
                map.insert("logfile".into(), toml::Value::Table(t));
                None
            }
            Some(other) => {
                return Err(serde::de::Error::custom(format!(
                    "logfile must be a string path or a table, got {other:?}"
                )));
            }
            None => None,
        };

        let wire: ConfigWire =
            ConfigWire::deserialize(toml::Value::Table(map)).map_err(serde::de::Error::custom)?;
        let mut cfg = Config::from(wire);
        if let Some(path) = flat_logfile_path {
            cfg.logfile.path = Some(path);
        }
        Ok(cfg)
    }
}

/// Generate `merge_with_cli` arms from a single field list.
///
/// Exhaustively destructures [`CliOverrides`] so a new override field that is not
/// listed fails to compile. Handlers:
/// - `set` — assign the unwrapped value (CLI `Option<T>` → dest `T`)
/// - `set_some` — wrap in `Some` (CLI `Option<T>` → dest `Option<T>`)
/// - `set_true` — only apply when `Some(true)`
/// - `csv_opt` — comma-separated string → `Option<Vec<String>>`
/// - `csv_vec` — comma-separated string → `Vec<String>`
macro_rules! merge_cli_fields {
    ($self:ident, $cli:ident; $( $field:ident => { $kind:ident : $dst:expr } ),* $(,)?) => {{
        let CliOverrides {
            $($field,)*
        } = $cli;
        $(
            merge_cli_fields!(@arm $kind, $field, $dst);
        )*
    }};

    (@arm set, $field:ident, $dst:expr) => {
        if let Some(v) = $field {
            $dst = v.clone();
        }
    };
    (@arm set_some, $field:ident, $dst:expr) => {
        if let Some(v) = $field {
            $dst = Some(v.clone());
        }
    };
    (@arm set_true, $field:ident, $dst:expr) => {
        if let Some(true) = $field {
            $dst = true;
        }
    };
    (@arm csv_opt, $field:ident, $dst:expr) => {
        if let Some(csv) = $field {
            let items: Vec<String> = csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !items.is_empty() {
                $dst = Some(items);
            }
        }
    };
    (@arm csv_vec, $field:ident, $dst:expr) => {
        if let Some(csv) = $field {
            let items: Vec<String> = csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !items.is_empty() {
                $dst = items;
            }
        }
    };
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

        if self.keymanager.allow_insecure_remote_signer {
            self.validate_insecure_env_var()?;
        }

        // Validate proposer_config_url and proposer_config_file mutual exclusivity
        if self.proposer_config.url.is_some() && self.proposer_config.file.is_some() {
            return Err(ConfigError::MissingField(
                "--proposer-config-url and --proposer-config-file are mutually exclusive; use only one".to_string(),
            ));
        }

        // Broadcast topic values are typed (serde / FromStr). Cross-field rule only:
        // `none` cannot be combined with other topics.
        if self.broadcast.contains(&BroadcastTopic::None) && self.broadcast.len() > 1 {
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
                if pubkey_trimmed == crypto::WILDCARD_KEY {
                    passwords.insert(
                        crypto::WILDCARD_KEY.to_string(),
                        SecretString::from(password.trim().to_string()),
                    );
                    continue;
                }
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
    /// If empty, returns default (all enabled). If `none`, all disabled.
    /// Otherwise, only listed topics are enabled.
    pub fn effective_broadcast_topics(&self) -> bn_manager::BroadcastTopics {
        if self.broadcast.is_empty() {
            return bn_manager::BroadcastTopics::default();
        }
        if self.broadcast.len() == 1 && self.broadcast[0] == BroadcastTopic::None {
            return bn_manager::BroadcastTopics {
                attestations: false,
                blocks: false,
                sync_committee: false,
                subscriptions: false,
            };
        }
        bn_manager::BroadcastTopics {
            attestations: self.broadcast.contains(&BroadcastTopic::Attestations),
            blocks: self.broadcast.contains(&BroadcastTopic::Blocks),
            sync_committee: self.broadcast.contains(&BroadcastTopic::SyncCommittee),
            subscriptions: self.broadcast.contains(&BroadcastTopic::Subscriptions),
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

    /// Merge present CLI overrides into this config.
    ///
    /// Generated from a single field list via [`merge_cli_fields!`]. Adding a
    /// field to [`CliOverrides`] without listing it here fails to compile
    /// (exhaustive destructure).
    pub fn merge_with_cli(&mut self, cli: &CliOverrides) {
        merge_cli_fields! {
            self, cli;
            // top-level
            beacon_url => { set: self.beacon_url },
            beacon_nodes => { set: self.beacon_nodes },
            keystore_path => { set: self.keystore_path },
            password_file => { set_some: self.password_file },
            slashing_db_path => { set: self.slashing_db_path },
            init_slashing_db => { set_true: self.allow_fresh_db },
            allow_unsupported_fork => { set_true: self.allow_unsupported_fork },
            metrics_address => { set: self.metrics_address },
            metrics_port => { set: self.metrics_port },
            grpc_port => { set: self.grpc_port },
            grpc_address => { set: self.grpc_address },
            network => { set: self.network },
            genesis_time => { set_some: self.genesis_time },
            genesis_validators_root => { set_some: self.genesis_validators_root },
            graffiti => { set_some: self.graffiti },
            log_level => { set: self.log_level },
            doppelganger_detection => { set: self.doppelganger_detection },
            key_decrypt_threads => { set_some: self.key_decrypt_threads },
            disable_attesting => { set: self.disable_attesting },
            slashed_validators_action => { set: self.slashed_validators_action },
            disable_keystore_locking => { set: self.disable_keystore_locking },
            proposer_nodes => { set: self.proposer_nodes },
            broadcast => { set: self.broadcast },
            block_selection_mode => { set: self.block_selection_mode },
            validator_registration_batch_size => { set: self.validator_registration_batch_size },
            validator_registration_batch_delay => { set: self.validator_registration_batch_delay },
            validators_config => { set_some: self.validators_config },
            beacon_max_body_bytes => { set: self.beacon_max_body_bytes },
            // keymanager
            keymanager_enabled => { set: self.keymanager.enabled },
            keymanager_address => { set_some: self.keymanager.address },
            keymanager_token_file => { set_some: self.keymanager.token_file },
            remote_signer_url => { set_some: self.keymanager.remote_signer_url },
            remote_signer_allowed_hosts => { csv_opt: self.keymanager.remote_signer_allowed_hosts },
            allow_insecure_remote_signer => { set: self.keymanager.allow_insecure_remote_signer },
            keymanager_cors_origins => { set: self.keymanager.cors_origins },
            keymanager_body_limit => { set: self.keymanager.body_limit },
            // tracing
            tracing_endpoint => { set_some: self.tracing.endpoint },
            tracing_exporter => { set: self.tracing.exporter },
            tracing_sample_rate => { set_some: self.tracing.sample_rate },
            tracing_max_queue_size => { set_some: self.tracing.max_queue_size },
            tracing_max_export_batch_size => { set_some: self.tracing.max_export_batch_size },
            // secret provider
            secret_provider => { csv_vec: self.secret_provider.providers },
            gcp_project_id => { set_some: self.secret_provider.gcp.project_id },
            gcp_secret_prefix => { set: self.secret_provider.gcp.secret_prefix },
            secret_refresh_interval => { set_some: self.secret_provider.refresh_interval },
            secret_provider_strict => { set_true: self.secret_provider.strict },
            // grpc_signer
            grpc_signer_url => { set_some: self.grpc_signer.url },
            grpc_signer_tls_cert => { set_some: self.grpc_signer.tls_cert },
            grpc_signer_tls_key => { set_some: self.grpc_signer.tls_key },
            grpc_signer_tls_ca_cert => { set_some: self.grpc_signer.tls_ca_cert },
            // builder_limits
            builder_circuit_breaker_consecutive_limit => {
                set: self.builder_limits.circuit_breaker_consecutive_limit
            },
            builder_circuit_breaker_epoch_limit => {
                set: self.builder_limits.circuit_breaker_epoch_limit
            },
            // proposer_config
            proposer_config_url => { set_some: self.proposer_config.url },
            proposer_config_file => { set_some: self.proposer_config.file },
            proposer_config_refresh_interval => { set: self.proposer_config.refresh_interval },
            proposer_config_url_token => { set_some: self.proposer_config.url_token },
            proposer_config_url_insecure => { set: self.proposer_config.url_insecure },
            // monitoring
            monitoring_endpoint => { set_some: self.monitoring.endpoint },
            monitoring_interval => { set: self.monitoring.interval },
            monitoring_endpoint_insecure => { set: self.monitoring.endpoint_insecure },
            // logfile
            logfile => { set_some: self.logfile.path },
            logfile_max_size => { set: self.logfile.max_size },
            logfile_max_number => { set: self.logfile.max_number },
            logfile_compress => { set: self.logfile.compress },
            logfile_level => { set_some: self.logfile.level },
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
    /// When `Some(true)`, enables `Config::allow_fresh_db` (SEC-3 / `--init-slashing-db`).
    pub init_slashing_db: Option<bool>,
    /// When `Some(true)`, enables `Config::allow_unsupported_fork` (SEC-9 / M-15).
    pub allow_unsupported_fork: Option<bool>,
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
    pub tracing_exporter: Option<TracingExporter>,
    pub tracing_sample_rate: Option<f64>,
    pub tracing_max_queue_size: Option<usize>,
    pub tracing_max_export_batch_size: Option<usize>,
    pub secret_provider: Option<String>,
    pub gcp_project_id: Option<String>,
    pub gcp_secret_prefix: Option<String>,
    pub secret_refresh_interval: Option<u64>,
    /// When `Some(true)`, enables `SecretProviderConfig::strict` (SEC-9 / M-9).
    pub secret_provider_strict: Option<bool>,
    pub allow_insecure_remote_signer: Option<bool>,
    pub keymanager_cors_origins: Option<Vec<String>>,
    pub keymanager_body_limit: Option<usize>,
    pub grpc_signer_url: Option<String>,
    pub grpc_signer_tls_cert: Option<PathBuf>,
    pub grpc_signer_tls_key: Option<PathBuf>,
    pub grpc_signer_tls_ca_cert: Option<PathBuf>,
    pub disable_attesting: Option<bool>,
    pub slashed_validators_action: Option<SlashedAction>,
    pub builder_circuit_breaker_consecutive_limit: Option<u32>,
    pub builder_circuit_breaker_epoch_limit: Option<u32>,
    pub disable_keystore_locking: Option<bool>,
    pub proposer_nodes: Option<Vec<String>>,
    pub broadcast: Option<Vec<BroadcastTopic>>,
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
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip secret material (passwords) for assertions; not a logging surface
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
        assert!(!config.allow_fresh_db, "SEC-3: allow_fresh_db defaults false");
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.grpc_port, 50052);
        assert_eq!(config.network, Network::Hoodi);
        assert_eq!(config.log_level, "debug");
    }

    /// SEC-3: `allow_fresh_db` parses from TOML and `--init-slashing-db` merges in.
    #[test]
    fn test_allow_fresh_db_toml_and_cli() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
allow_fresh_db = true
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.allow_fresh_db);

        let mut config = Config::default();
        assert!(!config.allow_fresh_db);
        config.merge_with_cli(&CliOverrides { init_slashing_db: Some(true), ..Default::default() });
        assert!(config.allow_fresh_db);
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
        assert_eq!(root, eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex());
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
    fn test_load_passwords_wildcard_only() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        let shared_pw = format!("shared_value_{}", 1);
        writeln!(file, "*={}", shared_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        let entry = passwords.get(crypto::WILDCARD_KEY).unwrap();
        assert_eq!(entry.expose_secret(), shared_pw);
    }

    #[test]
    fn test_load_passwords_wildcard_and_per_key() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        let shared_pw = format!("shared_value_{}", 1);
        let special_pw = format!("special_value_{}", 2);
        writeln!(file, "*={}\n0xabcd1234 = {}", shared_pw, special_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 2);
        assert_eq!(passwords.get(crypto::WILDCARD_KEY).unwrap().expose_secret(), shared_pw);
        assert_eq!(passwords.get("abcd1234").unwrap().expose_secret(), special_pw);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_load_passwords_wildcard_not_hex_validated() {
        use secrecy::ExposeSecret;

        // The wildcard line is never hex-validated: the password VALUE is stored verbatim
        // (even a pathological `0x0x...` value that would trip the double-0x check were it
        // ever passed to `strip_prefix_strict`), and the `*` key never emits the double-0x
        // warning. The verbatim-value assertion is the real teeth here -- the original
        // version of this test asserted no value at all and so proved nothing.
        let mut file = NamedTempFile::new().unwrap();
        let shared_pw = "0x0xdeadbeef";
        writeln!(file, "* = {}", shared_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        let entry = passwords.get(crypto::WILDCARD_KEY).unwrap();
        assert_eq!(entry.expose_secret(), shared_pw, "wildcard value stored verbatim");
        assert!(
            !logs_contain("double 0x prefix"),
            "wildcard line must not trigger the double-0x warn path"
        );
    }

    #[test]
    fn test_load_passwords_wildcard_empty_value() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "*=").unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords.get(crypto::WILDCARD_KEY).unwrap().expose_secret(), "");
    }

    #[test]
    fn test_load_passwords_wildcard_last_wins() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        let first_pw = format!("first_value_{}", 1);
        let second_pw = format!("second_value_{}", 2);
        writeln!(file, "*={}\n*={}", first_pw, second_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords.get(crypto::WILDCARD_KEY).unwrap().expose_secret(), second_pw);
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
        assert!(!config.keymanager.enabled);
        assert!(config.keymanager.address.is_none());
        assert!(config.keymanager.token_file.is_none());
        assert!(config.keymanager.remote_signer_url.is_none());
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

        assert!(config.keymanager.enabled);
        assert_eq!(config.keymanager.address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager.token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(
            config.keymanager.remote_signer_url.as_deref(),
            Some("https://signer.example.com")
        );
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
        assert!(config.keymanager.enabled);
        assert_eq!(config.keymanager.address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager.token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(
            config.keymanager.remote_signer_url.as_deref(),
            Some("https://signer.example.com")
        );
    }

    #[test]
    fn test_merge_with_cli_keymanager_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();

        config.merge_with_cli(&cli);

        assert!(!config.keymanager.enabled);
        assert!(config.keymanager.address.is_none());
        assert!(config.keymanager.token_file.is_none());
        assert!(config.keymanager.remote_signer_url.is_none());
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
        assert!(config.tracing.endpoint.is_none());
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        // Unset end-to-end (RF5-15); resolved default is 0.01.
        assert!(config.tracing.sample_rate.is_none());
        assert!((config.tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_merge_with_cli_tracing_endpoint() {
        let mut config = Config::default();
        let cli = CliOverrides {
            tracing_endpoint: Some("http://collector:4318".to_string()),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing.endpoint.as_deref(), Some("http://collector:4318"));
    }

    #[test]
    fn test_merge_with_cli_tracing_exporter() {
        let mut config = Config::default();
        let cli =
            CliOverrides { tracing_exporter: Some(TracingExporter::Gcp), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing.exporter, TracingExporter::Gcp);
    }

    #[test]
    fn test_merge_with_cli_tracing_sample_rate() {
        let mut config = Config::default();
        let cli = CliOverrides { tracing_sample_rate: Some(0.5), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing.sample_rate, Some(0.5));
    }

    #[test]
    fn test_merge_with_cli_tracing_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.tracing.endpoint.is_none());
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        assert!(config.tracing.sample_rate.is_none());
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
        assert_eq!(config.tracing.endpoint.as_deref(), Some("http://otel-collector:4318"));
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        assert_eq!(config.tracing.sample_rate, Some(0.1));
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
        assert!(config.tracing.endpoint.is_none());
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        assert!(config.tracing.sample_rate.is_none());
        assert!((config.tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
    }

    // -- RF5-15: OTEL precedence + Option sample_rate --

    /// Serialize tests that touch OTEL env vars.
    fn otel_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_explicit_default_sample_rate_survives_env_override() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");
        // Explicit 0.01 (the old "default") must NOT be treated as unset.
        let tracing = TracingConfig { sample_rate: Some(0.01), ..Default::default() };
        assert!((tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_env_sample_rate_applies_when_unset() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");
        let tracing = TracingConfig::default(); // sample_rate: None
        assert!((tracing.resolve_sample_rate() - 0.5).abs() < f64::EPSILON);
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_sample_rate_default_is_0_01_when_unset_everywhere() {
        let _guard = otel_env_lock();
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
        let tracing = TracingConfig::default();
        assert!(tracing.sample_rate.is_none());
        assert!((tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_otlp_endpoint_precedence_cli_over_file_over_env() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env:4318");

        // Env only
        let env_only = TracingConfig::default();
        assert_eq!(env_only.resolve_endpoint().as_deref(), Some("http://env:4318"));

        // File/config beats env
        let from_file =
            TracingConfig { endpoint: Some("http://file:4318".into()), ..Default::default() };
        assert_eq!(from_file.resolve_endpoint().as_deref(), Some("http://file:4318"));

        // CLI merge beats file (and env)
        let mut cfg = Config {
            tracing: TracingConfig {
                endpoint: Some("http://file:4318".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        cfg.merge_with_cli(&CliOverrides {
            tracing_endpoint: Some("http://cli:4318".into()),
            ..Default::default()
        });
        assert_eq!(cfg.tracing.resolve_endpoint().as_deref(), Some("http://cli:4318"));

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_merge_covers_every_cli_override_field() {
        // Compile-time exhaustiveness is enforced by merge_cli_fields!'s
        // destructure of CliOverrides. This runtime smoke check ensures a
        // representative override from each group still lands on Config.
        let mut config = Config::default();
        let cli = CliOverrides {
            beacon_url: Some("http://bn:5052".into()),
            tracing_sample_rate: Some(0.01),
            keymanager_enabled: Some(true),
            logfile: Some(std::path::PathBuf::from("/tmp/rvc.log")),
            monitoring_interval: Some(42),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(config.beacon_url, "http://bn:5052");
        assert_eq!(config.tracing.sample_rate, Some(0.01));
        assert!(config.keymanager.enabled);
        assert_eq!(config.logfile.path.as_deref(), Some(std::path::Path::new("/tmp/rvc.log")));
        assert_eq!(config.monitoring.interval, 42);
    }

    #[test]
    fn test_cli_sample_rate_0_01_survives_merge_and_env() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.9");
        let mut config = Config::default();
        config.merge_with_cli(&CliOverrides {
            tracing_sample_rate: Some(0.01),
            ..Default::default()
        });
        assert_eq!(config.tracing.sample_rate, Some(0.01));
        assert!((config.tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    // -- tracing batch config tests --

    #[test]
    fn test_default_config_tracing_batch_fields_none() {
        let config = Config::default();
        assert!(config.tracing.max_queue_size.is_none());
        assert!(config.tracing.max_export_batch_size.is_none());
    }

    #[test]
    fn test_merge_with_cli_tracing_max_queue_size() {
        let mut config = Config::default();
        let cli = CliOverrides { tracing_max_queue_size: Some(4096), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing.max_queue_size, Some(4096));
    }

    #[test]
    fn test_merge_with_cli_tracing_max_export_batch_size() {
        let mut config = Config::default();
        let cli = CliOverrides { tracing_max_export_batch_size: Some(1024), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.tracing.max_export_batch_size, Some(1024));
    }

    #[test]
    fn test_merge_with_cli_tracing_batch_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.tracing.max_queue_size.is_none());
        assert!(config.tracing.max_export_batch_size.is_none());
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
        assert_eq!(config.tracing.max_queue_size, Some(4096));
        assert_eq!(config.tracing.max_export_batch_size, Some(1024));
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
        assert!(config.tracing.max_queue_size.is_none());
        assert!(config.tracing.max_export_batch_size.is_none());
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
        assert!(config.keymanager.remote_signer_allowed_hosts.is_none());
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
            config.keymanager.remote_signer_allowed_hosts,
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
            config.keymanager.remote_signer_allowed_hosts,
            Some(vec!["host1.com".to_string(), "host2.com".to_string()])
        );
    }

    #[test]
    fn test_merge_with_cli_remote_signer_allowed_hosts_none_preserves_default() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.keymanager.remote_signer_allowed_hosts.is_none());
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
            config.keymanager.remote_signer_allowed_hosts,
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
        assert!(!config.keymanager.allow_insecure_remote_signer);
        assert!(config.validate().is_ok(), "Should pass when insecure flag is false");

        // Case 2: insecure flag true without env var fails
        let config = Config {
            keymanager: KeymanagerConfig {
                allow_insecure_remote_signer: true,
                ..Default::default()
            },
            ..Config::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("RVC_ALLOW_INSECURE"),
            "Error should mention RVC_ALLOW_INSECURE, got: {}",
            err
        );

        // Case 3: insecure flag true with wrong env var value fails
        std::env::set_var("RVC_ALLOW_INSECURE", "yes");
        let config = Config {
            keymanager: KeymanagerConfig {
                allow_insecure_remote_signer: true,
                ..Default::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err(), "Should fail with RVC_ALLOW_INSECURE=yes (not 'true')");

        // Case 4: insecure flag true with correct env var passes
        std::env::set_var("RVC_ALLOW_INSECURE", "true");
        let config = Config {
            keymanager: KeymanagerConfig {
                allow_insecure_remote_signer: true,
                ..Default::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_ok(), "Should pass with RVC_ALLOW_INSECURE=true");

        std::env::remove_var("RVC_ALLOW_INSECURE");
    }

    #[test]
    fn test_default_circuit_breaker_limits() {
        let config = Config::default();
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 3);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 5);
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
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 10);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 20);
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
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 7);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 12);
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 7);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 12);
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
        let config = Config { broadcast: vec![BroadcastTopic::None], ..Default::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn test_effective_broadcast_topics_partial() {
        let config = Config {
            broadcast: vec![BroadcastTopic::Blocks, BroadcastTopic::Attestations],
            ..Default::default()
        };
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn test_invalid_broadcast_topic_fails_at_deserialization() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
broadcast = ["invalid-topic"]
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("broadcast") || err.contains("invalid-topic") || err.contains("unknown"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_broadcast_none_exclusivity_still_enforced_in_validate() {
        let config = Config {
            broadcast: vec![BroadcastTopic::None, BroadcastTopic::Blocks],
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("none"),
            "error should mention none exclusivity"
        );
    }

    #[test]
    fn test_validate_proposer_config_mutual_exclusivity() {
        let config = Config {
            proposer_config: ProposerConfigSource {
                url: Some("https://example.com/config".to_string()),
                file: Some("/path/to/config.json".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_proposer_config_url_only() {
        let config = Config {
            proposer_config: ProposerConfigSource {
                url: Some("https://example.com/config".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_proposer_config_file_only() {
        let config = Config {
            proposer_config: ProposerConfigSource {
                file: Some("/path/to/config.json".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_default_config_proposer_fields() {
        let config = Config::default();
        assert!(config.proposer_nodes.is_empty());
        assert!(config.broadcast.is_empty());
        assert!(config.proposer_config.url.is_none());
        assert!(config.proposer_config.file.is_none());
        assert_eq!(config.proposer_config.refresh_interval, 384);
        assert!(config.proposer_config.url_token.is_none());
        assert!(!config.proposer_config.url_insecure);
        assert!(config.proposer_config.url.is_none());
        assert_eq!(config.proposer_config.refresh_interval, 384);
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
            broadcast: Some(vec![BroadcastTopic::Blocks]),
            proposer_config_url: Some("https://example.com/config".to_string()),
            proposer_config_refresh_interval: Some(60),
            proposer_config_url_token: Some("my-token".to_string()),
            proposer_config_url_insecure: Some(true),
            ..Default::default()
        };
        config.merge_with_cli(&cli);
        assert_eq!(config.proposer_nodes.len(), 1);
        assert_eq!(config.broadcast, vec![BroadcastTopic::Blocks]);
        assert_eq!(config.proposer_config.url, Some("https://example.com/config".to_string()));
        assert_eq!(config.proposer_config.refresh_interval, 60);
        assert_eq!(config.proposer_config.url_token, Some("my-token".to_string()));
        assert!(config.proposer_config.url_insecure);
        assert_eq!(config.proposer_config.url, Some("https://example.com/config".to_string()));
        assert!(config.proposer_config.url_insecure);
    }

    // -- RF5-11: typed config enums (fail-early deserialize) --

    #[test]
    fn test_invalid_slashed_action_fails_at_deserialization_not_validate() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
slashed_validators_action = "not-a-real-action"
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("slashed_validators_action")
                || err.contains("not-a-real-action")
                || err.contains("unknown variant"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_all_previously_accepted_slashed_actions_still_parse() {
        for (literal, expected) in [
            ("disable-only", SlashedAction::DisableOnly),
            ("shutdown", SlashedAction::Shutdown),
            ("none", SlashedAction::None),
        ] {
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
slashed_validators_action = "{literal}"
"#
            );
            let config: Config = toml::from_str(&toml).unwrap_or_else(|e| {
                panic!("accepted slashed action {literal:?} must still parse: {e}")
            });
            assert_eq!(config.slashed_validators_action, expected);
            assert_eq!(literal.parse::<SlashedAction>().unwrap(), expected);
        }
    }

    #[test]
    fn test_all_previously_accepted_broadcast_topics_still_parse() {
        for (literal, expected) in [
            ("attestations", BroadcastTopic::Attestations),
            ("blocks", BroadcastTopic::Blocks),
            ("sync-committee", BroadcastTopic::SyncCommittee),
            ("subscriptions", BroadcastTopic::Subscriptions),
            ("none", BroadcastTopic::None),
        ] {
            assert_eq!(literal.parse::<BroadcastTopic>().unwrap(), expected);
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
broadcast = ["{literal}"]
"#
            );
            let config: Config = toml::from_str(&toml).unwrap_or_else(|e| {
                panic!("accepted broadcast topic {literal:?} must still parse: {e}")
            });
            assert_eq!(config.broadcast, vec![expected]);
        }
    }

    #[test]
    fn test_bn_role_and_tracing_exporter_round_trip() {
        for (literal, expected) in [
            ("attestation", BnRole::Attestation),
            ("proposal", BnRole::Proposal),
            ("sync-committee", BnRole::SyncCommittee),
            ("aggregation", BnRole::Aggregation),
            ("submission", BnRole::Submission),
            ("all", BnRole::All),
        ] {
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"

[[beacon_nodes_config]]
url = "http://bn:5052"
roles = ["{literal}"]
"#
            );
            let config: Config = toml::from_str(&toml)
                .unwrap_or_else(|e| panic!("accepted BnRole {literal:?} must still parse: {e}"));
            assert_eq!(config.beacon_nodes_config[0].roles, vec![expected]);
        }

        for (literal, expected) in [("otlp", TracingExporter::Otlp), ("gcp", TracingExporter::Gcp)]
        {
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
tracing_exporter = "{literal}"
"#
            );
            let config: Config = toml::from_str(&toml).unwrap_or_else(|e| {
                panic!("accepted tracing_exporter {literal:?} must still parse: {e}")
            });
            assert_eq!(config.tracing.exporter, expected);
            assert_eq!(literal.parse::<TracingExporter>().unwrap(), expected);
            let json = serde_json::to_string(&expected).unwrap();
            let back: TracingExporter = serde_json::from_str(&json).unwrap();
            assert_eq!(back, expected);
        }
    }

    #[test]
    fn test_invalid_tracing_exporter_fails_at_deserialization() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
tracing_exporter = "unknown"
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("tracing_exporter") || err.contains("unknown") || err.contains("variant"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_invalid_bn_role_fails_at_deserialization() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"

[[beacon_nodes_config]]
url = "http://bn:5052"
roles = ["not-a-role"]
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("roles") || err.contains("not-a-role") || err.contains("variant"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_validate_no_longer_lists_typed_enum_values() {
        // Typed enums cannot hold invalid variants, so validate only needs
        // cross-field rules. A fully-valid typed config still validates.
        let config = Config {
            slashed_validators_action: SlashedAction::Shutdown,
            tracing: TracingConfig { exporter: TracingExporter::Gcp, ..Default::default() },
            broadcast: vec![BroadcastTopic::Blocks, BroadcastTopic::Attestations],
            beacon_nodes_config: vec![BeaconNodeEntry {
                url: "http://bn:5052".to_string(),
                roles: vec![BnRole::Proposal],
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
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

    // -- RF5-13: nested call sites; flat shims deleted --

    /// Source-level guard: flat field shims must not reappear on `Config`.
    ///
    /// `CliOverrides` / `ConfigWire` still use the historical flat key names for CLI and
    /// serde alias compatibility — only the public `Config` shims are forbidden.
    #[test]
    fn test_no_flat_field_accessors_remain() {
        let full = include_str!("types.rs");
        // Exclude this test module so assertion strings do not self-match.
        let src = full.split("#[cfg(test)]").next().expect("production source before tests");

        assert!(
            !src.contains("removed in RF5-13"),
            "shim markers must be gone from production source"
        );
        assert!(!src.contains("sync_flat_shims"), "sync_flat_shims must be deleted");
        assert!(
            !src.contains("sync_nested_from_flat_shims"),
            "sync_nested_from_flat_shims must be deleted"
        );

        let start = src.find("pub struct Config {").expect("Config struct");
        let after = &src[start..];
        let end = after.find("\nfn default_").expect("end of Config struct region");
        let config_struct = &after[..end];

        for nested in [
            "pub logfile: LogfileConfig",
            "pub tracing: TracingConfig",
            "pub keymanager: KeymanagerConfig",
            "pub grpc_signer: GrpcSignerConfig",
            "pub proposer_config: ProposerConfigSource",
            "pub monitoring: MonitoringConfig",
            "pub builder_limits: BuilderLimits",
        ] {
            assert!(config_struct.contains(nested), "nested group missing from Config: {nested}");
        }

        for field in [
            "keymanager_enabled",
            "keymanager_address",
            "keymanager_token_file",
            "remote_signer_url",
            "remote_signer_allowed_hosts",
            "allow_insecure_remote_signer",
            "keymanager_cors_origins",
            "keymanager_body_limit",
            "tracing_endpoint",
            "tracing_exporter",
            "tracing_sample_rate",
            "tracing_max_queue_size",
            "tracing_max_export_batch_size",
            "grpc_signer_url",
            "grpc_signer_tls_cert",
            "grpc_signer_tls_key",
            "grpc_signer_tls_ca_cert",
            "builder_circuit_breaker_consecutive_limit",
            "builder_circuit_breaker_epoch_limit",
            "monitoring_endpoint",
            "monitoring_interval",
            "monitoring_endpoint_insecure",
            "proposer_config_url",
            "proposer_config_file",
            "proposer_config_refresh_interval",
            "proposer_config_url_token",
            "proposer_config_url_insecure",
            "logfile_max_size",
            "logfile_max_number",
            "logfile_compress",
            "logfile_level",
        ] {
            assert!(
                !config_struct.contains(field),
                "flat Config field shim must be deleted: {field}"
            );
        }

        for method in [
            "fn keymanager_enabled(",
            "fn tracing_sample_rate(",
            "fn logfile_max_size(",
            "fn logfile_path(",
        ] {
            assert!(!src.contains(method), "flat accessor method must be deleted: {method}");
        }
    }
}
