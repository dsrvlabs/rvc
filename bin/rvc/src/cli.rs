//! CLI types and command dispatch for the `rvc` binary.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rvc::config::{CliOverrides, Network};
use tracing::{error, info, warn};

use crate::commands;
use crate::logging::{
    build_file_layer_config, build_tracing_config, init_logging, load_config,
    spawn_log_reload_handler,
};

const DEFAULT_GRPC_ADDRESS: &str = "127.0.0.1";
const DEFAULT_GRPC_PORT: u16 = 50051;
const DEFAULT_METRICS_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_METRICS_PORT: u16 = 8080;

#[derive(Parser)]
#[command(name = "rvc")]
#[command(version)]
#[command(about = "Rust Validator Client - Ethereum consensus layer validator", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Start the validator client
    Start {
        /// Path to the configuration file (TOML format)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Beacon node URL (e.g., http://localhost:5052)
        #[arg(long)]
        beacon_url: Option<String>,

        /// Comma-separated list of beacon node URLs for multi-BN support
        #[arg(long, value_delimiter = ',')]
        beacon_nodes: Option<Vec<String>>,

        /// Path to the keystore directory
        #[arg(long)]
        keystore_path: Option<PathBuf>,

        /// Path to the password file for keystore decryption
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Path to the slashing protection database
        #[arg(long)]
        slashing_db_path: Option<PathBuf>,

        /// Allow creating a fresh empty slashing-protection DB when the path is
        /// missing (SEC-3). DANGEROUS on a previously-active validator: the new
        /// DB has zero signing history and can enable double-signing / slashing.
        /// Use only for genuine first-time deployments. A 0-byte or corrupt DB
        /// is always a hard error regardless of this flag.
        #[arg(long, default_value_t = false)]
        init_slashing_db: bool,

        /// Allow startup when the beacon node's current fork version is not in
        /// the client's schedule (SEC-9 / M-15). For testnets / experimental
        /// forks only; default is fatal on unknown fork.
        #[arg(long, default_value_t = false)]
        allow_unsupported_fork: bool,

        /// Bind address for the metrics HTTP server (default: 127.0.0.1)
        #[arg(long, default_value_t = DEFAULT_METRICS_ADDRESS)]
        metrics_address: IpAddr,

        /// Port for the metrics HTTP server
        #[arg(long, default_value_t = DEFAULT_METRICS_PORT)]
        metrics_port: u16,

        /// Port for the gRPC server
        #[arg(long, default_value_t = DEFAULT_GRPC_PORT)]
        grpc_port: u16,

        /// Bind address for the gRPC server
        #[arg(long, default_value = DEFAULT_GRPC_ADDRESS)]
        grpc_address: String,

        /// Network preset (mainnet, hoodi, holesky, sepolia, custom)
        #[arg(long)]
        network: Option<String>,

        /// Genesis time override (Unix timestamp)
        #[arg(long)]
        genesis_time: Option<u64>,

        /// Genesis validators root override (hex string with 0x prefix)
        #[arg(long)]
        genesis_validators_root: Option<String>,

        /// Graffiti string for blocks
        #[arg(long)]
        graffiti: Option<String>,

        /// Disable doppelganger / forward-window protection (enabled by default).
        ///
        /// When enabled (default), newly loaded and imported keys are withheld from
        /// signing for ~2 epochs (~12.8 min on mainnet) while network liveness is
        /// observed, mitigating double-signing if another live instance holds the
        /// same keys. Opting out removes that safety cost but exposes the process
        /// to the Staked 2021 / SSV-Ankr class of mass-slashing incidents.
        #[arg(long)]
        no_doppelganger_detection: bool,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Console log output format: `pretty` (default, human-readable) or
        /// `json` (one structured object per event, for log-aggregation backends
        /// such as Loki / Elasticsearch / a SIEM). Also settable via the
        /// `RVC_LOG_FORMAT` env var; an explicit flag wins. Applies to the console
        /// stream only — the file appender keeps its own format (issue 5.5).
        #[arg(long, default_value = "pretty")]
        log_format: String,

        /// Enable runtime log-level reload on SIGHUP (opt-in; issue 5.4).
        ///
        /// When set, sending `SIGHUP` to the process re-reads `RUST_LOG` and
        /// swaps the active log filter in place — raising or lowering verbosity
        /// without a restart. Disabled by default so the steady-state log path is
        /// unchanged; the always-on reload *layer* is free on the disabled hot
        /// path either way. Unix only (a no-op on other platforms).
        #[arg(long, default_value_t = false)]
        enable_log_reload: bool,

        /// Enable the Keymanager API server
        #[arg(long)]
        keymanager_enabled: bool,

        /// Disable the Keymanager API server (overrides config file)
        #[arg(long, conflicts_with = "keymanager_enabled")]
        no_keymanager: bool,

        /// Bind address for the Keymanager API server (default: 127.0.0.1:5062)
        #[arg(long)]
        keymanager_address: Option<String>,

        /// Path to the Keymanager API bearer token file
        #[arg(long)]
        keymanager_token_file: Option<std::path::PathBuf>,

        /// Remote signer (Web3Signer) URL
        #[arg(long)]
        remote_signer_url: Option<String>,

        /// Comma-separated list of allowed remote signer hostnames
        #[arg(long)]
        remote_signer_allowed_hosts: Option<String>,

        /// Exit on unsafe slashing DB file permissions (world-readable/writable)
        #[arg(long)]
        strict_permissions: bool,

        /// Reject null-root re-signs as potential double votes (strict EIP-3076 semantics)
        #[arg(long)]
        strict_slashing_semantics: bool,

        /// Block production timeout in seconds (default: 3)
        #[arg(long)]
        block_production_timeout: Option<u64>,

        /// Attestation fetch timeout in seconds (default: 4)
        #[arg(long)]
        attestation_timeout: Option<u64>,

        /// Aggregate fetch timeout in seconds (default: 2)
        #[arg(long)]
        aggregate_timeout: Option<u64>,

        /// Duty fetch timeout in seconds (default: 10)
        #[arg(long)]
        duty_fetch_timeout: Option<u64>,

        /// Number of threads for parallel keystore decryption (default: auto-detect)
        #[arg(long)]
        key_decrypt_threads: Option<usize>,

        /// OTLP exporter endpoint (e.g., http://localhost:4318). Enables tracing when set.
        #[arg(long)]
        tracing_endpoint: Option<String>,

        /// Exporter backend: "otlp" (default) or "gcp"
        #[arg(long, default_value = "otlp")]
        tracing_exporter: String,

        /// Head-based sampling ratio 0.0–1.0 (default: 0.01)
        #[arg(long, default_value_t = 0.01)]
        tracing_sample_rate: f64,

        /// Maximum number of spans queued for export (OTel SDK default: 2048)
        #[arg(long)]
        tracing_max_queue_size: Option<usize>,

        /// Maximum number of spans per export batch (OTel SDK default: 512)
        #[arg(long)]
        tracing_max_export_batch_size: Option<usize>,

        /// Secret provider(s) to use for loading validator keys (e.g., "gcp")
        #[arg(long)]
        secret_provider: Option<String>,

        /// GCP project ID (required when --secret-provider includes "gcp")
        #[arg(long)]
        gcp_project_id: Option<String>,

        /// Prefix for GCP secret names (default: "validator-key-")
        #[arg(long)]
        gcp_secret_prefix: Option<String>,

        /// Interval in seconds to refresh keys from secret providers (0 = disabled)
        #[arg(long)]
        secret_refresh_interval: Option<u64>,

        /// Fail startup if any secret provider fails to list keys (SEC-9 / M-9).
        /// Default is resilient: one flaky provider is skipped; all providers
        /// failing remains fatal regardless of this flag.
        #[arg(long, default_value_t = false)]
        secret_provider_strict: bool,

        // --- Keymanager API hardening flags (SEC-05, SEC-06, SEC-07) ---
        /// Allow HTTP (non-TLS) URLs for remote signer imports
        #[arg(long)]
        allow_insecure_remote_signer: bool,

        /// Comma-separated list of allowed CORS origins for the Keymanager API
        #[arg(long, value_delimiter = ',')]
        keymanager_cors_origins: Option<Vec<String>>,

        /// Maximum request body size in bytes for the Keymanager API (default: 10 MB)
        #[arg(long, default_value_t = keymanager_api::DEFAULT_BODY_LIMIT)]
        keymanager_body_limit: usize,

        // --- BN HTTP cap flags (H-12) ---
        /// Maximum JSON response body size in bytes from the beacon node.
        ///
        /// Requests whose body (or Content-Length) exceeds this value are rejected
        /// before the full body is allocated.  Raise this only if your beacon node
        /// legitimately returns larger responses.
        ///
        /// Default: 33554432 (32 MiB).
        #[arg(long, default_value_t = beacon::ResponseCaps::DEFAULT_MAX_BODY_BYTES)]
        beacon_max_body_bytes: usize,

        // --- gRPC remote signer flags ---
        /// gRPC remote signer URL (e.g., https://signer.example.com:50051)
        #[arg(long)]
        grpc_signer_url: Option<String>,

        /// Path to the client TLS certificate for gRPC signer mTLS
        #[arg(long)]
        grpc_signer_tls_cert: Option<PathBuf>,

        /// Path to the client TLS private key for gRPC signer mTLS
        #[arg(long)]
        grpc_signer_tls_key: Option<PathBuf>,

        /// Path to the CA certificate for gRPC signer mTLS
        #[arg(long)]
        grpc_signer_tls_ca_cert: Option<PathBuf>,

        // --- Safety flags (Tier 2) ---
        /// Disable attestation duties at startup (emergency use only)
        #[arg(long)]
        disable_attesting: bool,

        /// Action when a slashed validator is detected: disable-only, shutdown, none
        #[arg(long, default_value = "disable-only")]
        slashed_validators_action: String,

        /// Builder circuit breaker: consecutive missed slots before fallback to local block (default: 3, 0 to disable)
        #[arg(long)]
        builder_circuit_breaker_consecutive_limit: Option<u32>,

        /// Builder circuit breaker: total epoch missed slots before fallback to local block (default: 5, 0 to disable)
        #[arg(long)]
        builder_circuit_breaker_epoch_limit: Option<u32>,

        /// Disable keystore file locking (for DVT setups with shared key material)
        #[arg(long)]
        disable_keystore_locking: bool,

        // --- Proposer nodes flags (T3.1/T3.2) ---
        /// Comma-separated list of dedicated proposer beacon node URLs for block production
        #[arg(long, value_delimiter = ',')]
        proposer_nodes: Option<Vec<String>>,

        // --- Broadcast topics flags (T3.3/T3.4) ---
        /// Comma-separated list of message types to broadcast to all BNs (attestations,blocks,sync-committee,subscriptions,none)
        #[arg(long, value_delimiter = ',')]
        broadcast: Option<Vec<String>>,

        // --- Proposer config URL flags (T3.11/T3.12/T3.13) ---
        /// Remote URL for proposer configuration (mutually exclusive with --proposer-config-file)
        #[arg(long, conflicts_with = "proposer_config_file")]
        proposer_config_url: Option<String>,

        /// Local file path for proposer configuration (mutually exclusive with --proposer-config-url)
        #[arg(long, conflicts_with = "proposer_config_url")]
        proposer_config_file: Option<String>,

        /// Refresh interval in seconds for proposer config URL (default: 384, i.e., one epoch)
        #[arg(long)]
        proposer_config_refresh_interval: Option<u64>,

        /// Bearer token for proposer config URL authentication
        #[arg(long)]
        proposer_config_url_token: Option<String>,

        /// Allow HTTP (non-HTTPS) proposer config URL
        #[arg(long)]
        proposer_config_url_insecure: bool,

        // --- Monitoring flags (T3.7) ---
        /// Remote monitoring endpoint URL (e.g., https://beaconcha.in/api/v1/client/metrics?apikey=...)
        #[arg(long)]
        monitoring_endpoint: Option<String>,

        /// Monitoring push interval in seconds (default: 384, i.e., one epoch)
        #[arg(long)]
        monitoring_interval: Option<u64>,

        /// Allow HTTP (non-HTTPS) monitoring endpoint
        #[arg(long)]
        monitoring_endpoint_insecure: bool,

        // --- Log rotation flags (T3.8/T3.9/T3.10) ---
        /// Path to the log file (enables file logging alongside stdout)
        #[arg(long)]
        logfile: Option<std::path::PathBuf>,

        /// Maximum log file size in MB before rotation (default: 200)
        #[arg(long)]
        logfile_max_size: Option<u64>,

        /// Maximum number of rotated log files to keep (default: 5)
        #[arg(long)]
        logfile_max_number: Option<usize>,

        /// Enable gzip compression of rotated log files
        #[arg(long)]
        logfile_compress: bool,

        /// Log level for file logging (default: same as --log-level)
        #[arg(long)]
        logfile_level: Option<String>,

        // --- Block selection mode (T4.4) ---
        /// Block selection mode: max-profit (default), execution-only, builder-always, builder-only
        #[arg(long)]
        block_selection_mode: Option<String>,

        // --- Registration batching (T4.12/T4.13) ---
        /// Maximum number of validator registrations per batch (default: 500, 0 = send all at once)
        #[arg(long)]
        validator_registration_batch_size: Option<usize>,

        /// Delay in milliseconds between registration batches (default: 500)
        #[arg(long)]
        validator_registration_batch_delay: Option<u64>,

        // --- Validator config (ISSUE-2.1 / H-1) ---
        /// Path to a TOML file containing per-validator fee_recipient and gas_limit overrides.
        /// rvc refuses to start if default_fee_recipient is the zero address (0x000…000).
        ///
        /// Example file:
        ///   [defaults]
        ///   fee_recipient = "0xYourAddress"
        ///   gas_limit = 30000000
        #[arg(long)]
        validators_config: Option<PathBuf>,
    },

    /// Submit a voluntary exit for a validator
    VoluntaryExit {
        /// Validator public key (hex, with or without 0x prefix)
        #[arg(long)]
        pubkey: String,

        /// Exit epoch (defaults to current epoch if not specified)
        #[arg(long)]
        epoch: Option<u64>,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        confirm: bool,

        /// Beacon node URL (e.g., http://localhost:5052)
        #[arg(long, default_value = "http://localhost:5052")]
        beacon_url: String,

        /// Path to the keystore directory
        #[arg(long)]
        keystore_path: PathBuf,

        /// Path to the password file for keystore decryption
        #[arg(long)]
        password_file: PathBuf,

        /// Path to the slashing protection database
        #[arg(long)]
        slashing_db_path: Option<PathBuf>,

        /// Network preset (mainnet, hoodi, holesky, sepolia, custom)
        #[arg(long)]
        network: Option<String>,

        /// Genesis validators root override (hex string with 0x prefix)
        #[arg(long)]
        genesis_validators_root: Option<String>,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Prepare a pre-signed voluntary exit (sign and save to file, without submitting)
    PrepareExit {
        /// Validator public key (hex, with or without 0x prefix)
        #[arg(long)]
        pubkey: String,

        /// Exit epoch (defaults to current epoch if not specified)
        #[arg(long)]
        epoch: Option<u64>,

        /// Output directory for the signed exit JSON file
        #[arg(long, default_value = ".")]
        output: PathBuf,

        /// Beacon node URL (e.g., http://localhost:5052)
        #[arg(long, default_value = "http://localhost:5052")]
        beacon_url: String,

        /// Path to the keystore directory
        #[arg(long)]
        keystore_path: PathBuf,

        /// Path to the password file for keystore decryption
        #[arg(long)]
        password_file: PathBuf,

        /// Path to the slashing protection database
        #[arg(long)]
        slashing_db_path: Option<PathBuf>,

        /// Network preset (mainnet, hoodi, holesky, sepolia, custom)
        #[arg(long)]
        network: Option<String>,

        /// Genesis validators root override (hex string with 0x prefix)
        #[arg(long)]
        genesis_validators_root: Option<String>,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Submit a pre-signed voluntary exit to the beacon node (no signing keys required)
    SubmitExit {
        /// Path to the signed voluntary exit JSON file
        #[arg(long)]
        file: PathBuf,

        /// Beacon node URL (e.g., http://localhost:5052)
        #[arg(long, default_value = "http://localhost:5052")]
        beacon_url: String,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Slashing-protection maintenance (prune, etc.)
    Slashing {
        #[command(subcommand)]
        command: SlashingCommands,
    },
}

/// Subcommands under `rvc slashing` (RF2-13 / B5). Kept as a small nested enum so
/// Phase 5 F3 can relocate it without redesigning the arg surface.
#[derive(Subcommand)]
pub enum SlashingCommands {
    /// Delete historical slashing-protection rows below per-validator watermarks.
    ///
    /// Destructive and irreversible. Prefer `--dry-run` first; a real prune requires `--yes`.
    /// Refuses to create a fresh empty DB if the path is missing (same class of footgun as
    /// `--init-slashing-db` without opt-in).
    Prune {
        /// Path to an existing slashing protection database
        #[arg(long)]
        slashing_db_path: PathBuf,

        /// Report how many rows would be deleted without deleting them
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Confirm irreversible deletion of rows below watermarks
        #[arg(long, default_value_t = false)]
        yes: bool,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },
}

/// Parse CLI and dispatch to the selected subcommand.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    #[cfg(feature = "gcp-secret")]
    {
        use rustls::crypto::{ring::default_provider, CryptoProvider};
        let _ = CryptoProvider::install_default(default_provider());
    }

    match cli.command {
        Commands::Start {
            config,
            beacon_url,
            beacon_nodes,
            keystore_path,
            password_file,
            slashing_db_path,
            init_slashing_db,
            allow_unsupported_fork,
            metrics_address,
            metrics_port,
            grpc_port,
            grpc_address,
            network,
            genesis_time,
            genesis_validators_root,
            graffiti,
            no_doppelganger_detection,
            log_level,
            log_format,
            enable_log_reload,
            keymanager_enabled,
            no_keymanager,
            keymanager_address,
            keymanager_token_file,
            remote_signer_url,
            remote_signer_allowed_hosts,
            strict_permissions,
            strict_slashing_semantics,
            block_production_timeout,
            attestation_timeout,
            aggregate_timeout,
            duty_fetch_timeout,
            key_decrypt_threads,
            tracing_endpoint,
            tracing_exporter,
            tracing_sample_rate,
            tracing_max_queue_size,
            tracing_max_export_batch_size,
            secret_provider,
            gcp_project_id,
            gcp_secret_prefix,
            secret_refresh_interval,
            secret_provider_strict,
            allow_insecure_remote_signer,
            keymanager_cors_origins,
            keymanager_body_limit,
            grpc_signer_url,
            grpc_signer_tls_cert,
            grpc_signer_tls_key,
            grpc_signer_tls_ca_cert,
            disable_attesting,
            slashed_validators_action,
            builder_circuit_breaker_consecutive_limit,
            builder_circuit_breaker_epoch_limit,
            disable_keystore_locking,
            proposer_nodes,
            broadcast,
            proposer_config_url,
            proposer_config_file,
            proposer_config_refresh_interval,
            proposer_config_url_token,
            proposer_config_url_insecure,
            monitoring_endpoint,
            monitoring_interval,
            monitoring_endpoint_insecure,
            logfile,
            logfile_max_size,
            logfile_max_number,
            logfile_compress,
            logfile_level,
            block_selection_mode,
            validator_registration_batch_size,
            validator_registration_batch_delay,
            validators_config,
            beacon_max_body_bytes,
        } => {
            // Validate gRPC signer flags: if URL is set, all TLS flags are required
            if grpc_signer_url.is_some()
                && (grpc_signer_tls_cert.is_none()
                    || grpc_signer_tls_key.is_none()
                    || grpc_signer_tls_ca_cert.is_none())
            {
                anyhow::bail!(
                    "--grpc-signer-url requires --grpc-signer-tls-cert, \
                     --grpc-signer-tls-key, and --grpc-signer-tls-ca-cert"
                );
            }

            let mut timeouts = bn_manager::OperationTimeouts::default();
            if let Some(secs) = block_production_timeout {
                if secs == 0 {
                    anyhow::bail!("--block-production-timeout must be greater than 0");
                }
                timeouts.block_production = std::time::Duration::from_secs(secs);
            }
            if let Some(secs) = attestation_timeout {
                if secs == 0 {
                    anyhow::bail!("--attestation-timeout must be greater than 0");
                }
                timeouts.attestation_fetch = std::time::Duration::from_secs(secs);
            }
            if let Some(secs) = aggregate_timeout {
                if secs == 0 {
                    anyhow::bail!("--aggregate-timeout must be greater than 0");
                }
                timeouts.aggregate_fetch = std::time::Duration::from_secs(secs);
                timeouts.aggregate_submit = std::time::Duration::from_secs(secs);
            }
            if let Some(secs) = duty_fetch_timeout {
                if secs == 0 {
                    anyhow::bail!("--duty-fetch-timeout must be greater than 0");
                }
                timeouts.duty_fetch = std::time::Duration::from_secs(secs);
            }

            if let Some(n) = key_decrypt_threads {
                if n == 0 {
                    anyhow::bail!("--key-decrypt-threads must be greater than 0");
                }
            }

            let cli_overrides = CliOverrides {
                beacon_url,
                beacon_nodes,
                keystore_path,
                password_file,
                slashing_db_path,
                init_slashing_db: if init_slashing_db { Some(true) } else { None },
                allow_unsupported_fork: if allow_unsupported_fork { Some(true) } else { None },
                metrics_address: Some(metrics_address),
                metrics_port: Some(metrics_port),
                grpc_port: Some(grpc_port),
                grpc_address: Some(grpc_address),
                network: network
                    .map(|n| n.parse::<Network>())
                    .transpose()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                genesis_time,
                genesis_validators_root,
                graffiti,
                log_level: Some(log_level.clone()),
                doppelganger_detection: if no_doppelganger_detection { Some(false) } else { None },
                keymanager_enabled: if no_keymanager {
                    Some(false)
                } else if keymanager_enabled {
                    Some(true)
                } else {
                    None
                },
                keymanager_address,
                keymanager_token_file,
                remote_signer_url,
                remote_signer_allowed_hosts,
                key_decrypt_threads,
                tracing_endpoint,
                tracing_exporter: Some(
                    tracing_exporter
                        .parse::<rvc::config::TracingExporter>()
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                ),
                tracing_sample_rate: Some(tracing_sample_rate),
                tracing_max_queue_size,
                tracing_max_export_batch_size,
                secret_provider,
                gcp_project_id,
                gcp_secret_prefix,
                secret_refresh_interval,
                secret_provider_strict: if secret_provider_strict { Some(true) } else { None },
                allow_insecure_remote_signer: if allow_insecure_remote_signer {
                    Some(true)
                } else {
                    None
                },
                keymanager_cors_origins,
                keymanager_body_limit: Some(keymanager_body_limit),
                grpc_signer_url,
                grpc_signer_tls_cert,
                grpc_signer_tls_key,
                grpc_signer_tls_ca_cert,
                disable_attesting: if disable_attesting { Some(true) } else { None },
                slashed_validators_action: Some(
                    slashed_validators_action
                        .parse::<rvc::config::SlashedAction>()
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                ),
                builder_circuit_breaker_consecutive_limit,
                builder_circuit_breaker_epoch_limit,
                disable_keystore_locking: if disable_keystore_locking { Some(true) } else { None },
                proposer_nodes,
                broadcast: broadcast
                    .map(|topics| {
                        topics
                            .into_iter()
                            .map(|s| s.parse::<rvc::config::BroadcastTopic>())
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                proposer_config_url,
                proposer_config_file,
                proposer_config_refresh_interval,
                proposer_config_url_token,
                proposer_config_url_insecure: if proposer_config_url_insecure {
                    Some(true)
                } else {
                    None
                },
                monitoring_endpoint,
                monitoring_interval,
                monitoring_endpoint_insecure: if monitoring_endpoint_insecure {
                    Some(true)
                } else {
                    None
                },
                logfile,
                logfile_max_size,
                logfile_max_number,
                logfile_compress: if logfile_compress { Some(true) } else { None },
                logfile_level,
                block_selection_mode: block_selection_mode
                    .map(|s| s.parse::<rvc::config::BlockSelectionMode>())
                    .transpose()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                validator_registration_batch_size,
                validator_registration_batch_delay,
                validators_config,
                beacon_max_body_bytes: Some(beacon_max_body_bytes),
            };

            let mut cfg = load_config(config)?;
            cfg.merge_with_cli(&cli_overrides);

            let tracing_config = build_tracing_config(&cfg);
            let file_layer_config = build_file_layer_config(&cfg);
            let log_format = telemetry::LogFormat::resolve(Some(&log_format));
            let logging_guards = init_logging(
                &log_level,
                log_format,
                tracing_config.as_ref(),
                file_layer_config.as_ref(),
            );

            info!(
                version = env!("CARGO_PKG_VERSION"),
                network = %cfg.network,
                commit = option_env!("GIT_COMMIT").unwrap_or("unknown"),
                "rvc starting"
            );

            if let Err(e) = cfg.validate() {
                error!("Configuration validation failed: {}", e);
                return Err(e.into());
            }

            if cfg.keymanager.allow_insecure_remote_signer {
                warn!("INSECURE MODE: HTTP remote signer URLs are allowed. Use only for development/testing.");
            }

            let shutdown_token = tokio_util::sync::CancellationToken::new();
            spawn_log_reload_handler(
                enable_log_reload,
                logging_guards.reload_handle.clone(),
                shutdown_token.clone(),
            );

            let run_result = rvc::bootstrap::run(
                cfg,
                rvc::bootstrap::RunOptions {
                    strict_permissions,
                    strict_slashing_semantics,
                    timeouts,
                },
                shutdown_token,
            )
            .await;

            // Logging guards drop after run returns (flush last).
            let _ = &logging_guards;

            match run_result {
                Err(e) if e.is_keystore_locked() => {
                    // Defensive: run() already process::exits on lock, but keep parity.
                    std::process::exit(e.exit_code());
                }
                Err(e) => return Err(e.into()),
                Ok(()) => {}
            }
        }
        Commands::VoluntaryExit {
            pubkey,
            epoch,
            confirm,
            beacon_url,
            keystore_path,
            password_file,
            slashing_db_path,
            network,
            genesis_validators_root,
            log_level,
        } => {
            // One-shot CLI commands have no `--log-format` flag; honor only the
            // `RVC_LOG_FORMAT` env (default pretty) via `resolve(None)`.
            init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);

            let args = commands::voluntary_exit::VoluntaryExitArgs {
                pubkey,
                epoch,
                confirm,
                beacon_url,
                keystore_path,
                password_file,
                slashing_db_path,
                network,
                genesis_validators_root,
            };

            commands::voluntary_exit::execute(args).await?;
        }
        Commands::PrepareExit {
            pubkey,
            epoch,
            output,
            beacon_url,
            keystore_path,
            password_file,
            slashing_db_path,
            network,
            genesis_validators_root,
            log_level,
        } => {
            init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);

            let args = commands::prepare_exit::PrepareExitArgs {
                pubkey,
                epoch,
                output,
                beacon_url,
                keystore_path,
                password_file,
                slashing_db_path,
                network,
                genesis_validators_root,
            };

            commands::prepare_exit::execute(args).await?;
        }
        Commands::SubmitExit { file, beacon_url, log_level } => {
            init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);

            let args = commands::submit_exit::SubmitExitArgs { file, beacon_url };

            commands::submit_exit::execute(args).await?;
        }
        Commands::Slashing { command } => match command {
            SlashingCommands::Prune { slashing_db_path, dry_run, yes, log_level } => {
                init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);
                // Ensure prune metrics are registered before the handler increments them.
                metrics::definitions::init_metrics();
                commands::slashing::execute_prune(commands::slashing::PruneArgs {
                    slashing_db_path,
                    dry_run,
                    yes,
                })?;
            }
        },
    }

    Ok(())
}
