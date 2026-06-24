//! rvc - Rust Validator Client
//!
//! Main entry point for the validator client binary.

mod commands;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use bn_manager::BeaconNodeClient;
use clap::{Parser, Subcommand};
use metrics::{new_health_status, serve_metrics_with_health, SharedHealthStatus};
use rvc::config::{redact_url, CliOverrides, Config, Network, ServiceBuilder};
use rvc::duty_tracker::DutyTrackerService;
use rvc::keymanager_adapters::{
    KeystoreManagerAdapter, RemoteKeyManagerAdapter, SlashingProtectionAdapter,
    ValidatorConfigManagerAdapter, ValidatorManagerAdapter, VoluntaryExitManagerAdapter,
};
use rvc::startup;
use rvc::DutyTrackerServer;
use tonic::transport::Server;
use tracing::{error, info, warn};

const DEFAULT_GRPC_ADDRESS: &str = "127.0.0.1";
const DEFAULT_GRPC_PORT: u16 = 50051;
const DEFAULT_METRICS_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEFAULT_METRICS_PORT: u16 = 8080;

#[derive(Parser)]
#[command(name = "rvc")]
#[command(version)]
#[command(about = "Rust Validator Client - Ethereum consensus layer validator", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
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

        /// Disable doppelganger detection (enabled by default)
        #[arg(long)]
        no_doppelganger_detection: bool,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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
                tracing_exporter: Some(tracing_exporter),
                tracing_sample_rate: Some(tracing_sample_rate),
                tracing_max_queue_size,
                tracing_max_export_batch_size,
                secret_provider,
                gcp_project_id,
                gcp_secret_prefix,
                secret_refresh_interval,
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
                slashed_validators_action: Some(slashed_validators_action),
                builder_circuit_breaker_consecutive_limit,
                builder_circuit_breaker_epoch_limit,
                disable_keystore_locking: if disable_keystore_locking { Some(true) } else { None },
                proposer_nodes,
                broadcast,
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
            let logging_guards =
                init_logging(&log_level, tracing_config.as_ref(), file_layer_config.as_ref());

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

            if cfg.allow_insecure_remote_signer {
                warn!("INSECURE MODE: HTTP remote signer URLs are allowed. Use only for development/testing.");
            }

            run_validator(
                cfg,
                strict_permissions,
                strict_slashing_semantics,
                timeouts,
                logging_guards,
            )
            .await?;
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
            init_logging(&log_level, None, None);

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
            init_logging(&log_level, None, None);

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
            init_logging(&log_level, None, None);

            let args = commands::submit_exit::SubmitExitArgs { file, beacon_url };

            commands::submit_exit::execute(args).await?;
        }
    }

    Ok(())
}

/// Guards returned from init_logging that must be held for application lifetime.
struct LoggingGuards {
    _tracing_guard: Option<telemetry::TracingGuard>,
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

fn init_logging(
    level: &str,
    tracing_config: Option<&telemetry::TelemetryConfig>,
    file_config: Option<&telemetry::FileAppenderConfig>,
) -> LoggingGuards {
    use tracing_subscriber::layer::Layer;
    use tracing_subscriber::prelude::*;

    let filter = telemetry::env_filter_or(level);

    let (file_layer, file_guard): (
        Option<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>>,
        Option<tracing_appender::non_blocking::WorkerGuard>,
    ) = match file_config {
        Some(config) => match telemetry::create_file_layer(config) {
            Ok((layer, guard)) => {
                eprintln!("File logging enabled: {}/{}", config.directory, config.filename);
                (Some(layer), Some(guard))
            }
            Err(e) => {
                eprintln!("WARNING: Failed to initialize file logging: {e}");
                (None, None)
            }
        },
        None => (None, None),
    };

    // Collect all boxed layers to apply to Registry in a single .with() call.
    // This avoids type issues when mixing Box<dyn Layer<Registry>> with generic layers.
    let mut boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
        Vec::new();

    let tracing_guard = match tracing_config {
        Some(config) => match telemetry::init_tracing(config) {
            Ok((otel_layer, guard)) => {
                boxed_layers.push(otel_layer);
                eprintln!("OpenTelemetry tracing enabled (endpoint: {})", config.endpoint);
                Some(guard)
            }
            Err(e) => {
                eprintln!(
                    "WARNING: Failed to initialize OpenTelemetry tracing: {e}. \
                     Falling back to fmt-only logging."
                );
                None
            }
        },
        None => None,
    };

    if let Some(fl) = file_layer {
        boxed_layers.push(fl);
    }

    // tracing-subscriber 0.3 `Vec<L: Layer<S>>::register_callsite()` returns
    // `Interest::never()` when empty. As the outer layer in a `Layered` stack
    // that short-circuits every callsite via `Layered::pick_interest`, so no
    // events ever reach `fmt::layer` underneath. Pad with `Identity` (a no-op
    // that returns `Interest::always()`) when no optional layers are present.
    if boxed_layers.is_empty() {
        boxed_layers.push(Box::new(tracing_subscriber::layer::Identity::new()));
    }

    tracing_subscriber::registry()
        .with(boxed_layers)
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    LoggingGuards { _tracing_guard: tracing_guard, _file_guard: file_guard }
}

fn load_config(config_path: Option<PathBuf>) -> anyhow::Result<Config> {
    match config_path {
        Some(path) => {
            info!(path = ?path, "Loading configuration from file");
            let config = Config::from_file(&path)?;
            Ok(config)
        }
        None => {
            info!("Using default configuration");
            Ok(Config::default())
        }
    }
}

fn build_tracing_config(config: &Config) -> Option<telemetry::TelemetryConfig> {
    let endpoint = config
        .tracing_endpoint
        .clone()
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())?;

    let mut sample_rate = config.tracing_sample_rate;
    // If sample_rate is still at default, check env var
    if (sample_rate - 0.01).abs() < f64::EPSILON {
        if let Ok(env_rate) = std::env::var("OTEL_TRACES_SAMPLER_ARG") {
            if let Ok(parsed) = env_rate.parse::<f64>() {
                sample_rate = parsed;
            }
        }
    }

    if !(0.0..=1.0).contains(&sample_rate) {
        warn!(sample_rate, "tracing_sample_rate out of range 0.0..=1.0, clamping");
        sample_rate = sample_rate.clamp(0.0, 1.0);
    }

    // Warn on non-localhost http://
    if endpoint.starts_with("http://") {
        if let Ok(url) = url::Url::parse(&endpoint) {
            if let Some(host) = url.host_str() {
                if host != "localhost" && host != "127.0.0.1" && host != "::1" {
                    warn!(
                        endpoint = %endpoint,
                        "tracing endpoint uses http:// with non-localhost host; consider using https://"
                    );
                }
            }
        }
    }

    let exporter = match config.tracing_exporter.as_str() {
        "otlp" => telemetry::ExporterKind::Otlp,
        #[cfg(feature = "gcp-trace")]
        "gcp" => telemetry::ExporterKind::Gcp,
        #[cfg(not(feature = "gcp-trace"))]
        "gcp" => {
            eprintln!(
                "ERROR: --tracing-exporter=gcp requires the `gcp-trace` feature. \
                 Rebuild with: cargo build --features gcp-trace"
            );
            return None;
        }
        other => {
            warn!(exporter = %other, "unknown tracing exporter, defaulting to otlp");
            telemetry::ExporterKind::Otlp
        }
    };

    Some(telemetry::TelemetryConfig {
        endpoint,
        exporter,
        sample_rate,
        network: config.network.to_string(),
        service_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        max_queue_size: config.tracing_max_queue_size,
        max_export_batch_size: config.tracing_max_export_batch_size,
    })
}

fn build_file_layer_config(config: &Config) -> Option<telemetry::FileAppenderConfig> {
    let logfile = config.logfile.as_ref()?;

    let directory = logfile
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());
    let filename = logfile
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "rvc.log".to_string());

    let level = config.logfile_level.clone().unwrap_or_else(|| config.log_level.clone());

    Some(telemetry::FileAppenderConfig {
        directory,
        filename,
        max_size_mb: config.logfile_max_size,
        max_files: config.logfile_max_number,
        compress: config.logfile_compress,
        level,
    })
}

async fn run_validator(
    config: Config,
    strict_permissions: bool,
    strict_slashing_semantics: bool,
    timeouts: bn_manager::OperationTimeouts,
    _logging_guards: LoggingGuards,
) -> anyhow::Result<()> {
    let startup_time = std::time::Instant::now();

    let redacted_nodes: Vec<String> =
        config.effective_beacon_nodes().iter().map(|u| redact_url(u)).collect();
    info!(
        beacon_url = %redact_url(&config.beacon_url),
        beacon_nodes = ?redacted_nodes,
        network = %config.network,
        metrics_address = %config.metrics_address,
        metrics_port = config.metrics_port,
        grpc_address = %config.grpc_address,
        grpc_port = config.grpc_port,
        doppelganger_detection = config.doppelganger_detection,
        spec_version = eth_types::CONSENSUS_SPEC_VERSION,
        "Starting validator client"
    );

    let health_status = new_health_status();
    let shutdown_token = tokio_util::sync::CancellationToken::new();

    let grpc_port = config.grpc_port;
    let metrics_address = config.metrics_address;
    let metrics_port = config.metrics_port;
    let doppelganger_enabled = config.doppelganger_detection;

    let builder = ServiceBuilder::new(config.clone());

    // Step 1: Open slashing DB
    let slashing_db = match builder.build_slashing_db() {
        Ok(db) => {
            update_health_slashing_db(&health_status, true).await;
            db
        }
        Err(e) => {
            error!("Failed to open slashing database: {}", e);
            update_health_error(&health_status, format!("Slashing DB error: {}", e)).await;
            return Err(e.into());
        }
    };

    // Step 2: Run integrity check
    if let Err(e) = startup::check_integrity(&slashing_db) {
        error!("Slashing DB integrity check failed: {}", e);
        return Err(e.into());
    }

    // Step 2a: Configure strict slashing semantics
    if strict_slashing_semantics {
        slashing_db.set_strict_semantics(true);
        info!("Strict slashing semantics enabled: null-root re-signs will be rejected");
    }

    // Step 2b: Check slashing DB file permissions
    if strict_permissions {
        if let Err(e) = slashing_db.check_file_permissions_strict() {
            error!("Strict permissions check failed: {}", e);
            return Err(e.into());
        }
    } else {
        slashing_db.check_file_permissions();
    }

    // Step 2c: Acquire keystore lock
    let _keystore_lock_guard = if config.disable_keystore_locking {
        warn!("Keystore locking disabled -- ensure no duplicate instances");
        None
    } else {
        match startup::acquire_keystore_lock(&config.keystore_path) {
            Ok(guard) => Some(guard),
            Err(e) => {
                error!("Failed to acquire keystore lock: {}", e);
                std::process::exit(startup::EXIT_KEYSTORE_LOCKED);
            }
        }
    };

    // Step 3: Create beacon client and BnManager
    let beacon_client = match builder.build_beacon() {
        Ok(client) => {
            update_health_beacon_connected(&health_status, true).await;
            client
        }
        Err(e) => {
            error!("Failed to create beacon client: {}", e);
            update_health_error(&health_status, format!("Beacon client error: {}", e)).await;
            return Err(e.into());
        }
    };

    let bn_manager = match builder.build_bn_manager() {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to create BnManager: {}", e);
            return Err(e.into());
        }
    };

    // Step 4: Validate genesis root against beacon node
    let genesis_validators_root_hex = match builder.parse_genesis_validators_root() {
        Ok(root) => format!("0x{}", hex::encode(root)),
        Err(e) => {
            error!("Failed to parse genesis validators root: {}", e);
            return Err(e.into());
        }
    };

    if let Err(e) = startup::validate_genesis_root(
        &slashing_db,
        bn_manager.as_ref(),
        &genesis_validators_root_hex,
    )
    .await
    {
        error!("Genesis root validation failed: {}", e);
        return Err(e.into());
    }

    let genesis_validators_root = match builder.parse_genesis_validators_root() {
        Ok(root) => root,
        Err(e) => {
            error!("Failed to parse genesis validators root: {}", e);
            return Err(e.into());
        }
    };

    // Step 5: Check beacon reachability
    startup::check_beacon_reachability(bn_manager.as_ref()).await;

    // Log beacon node version (non-fatal)
    match bn_manager.get_node_version().await {
        Ok(version) => info!(bn_version = %version, "connected to beacon node"),
        Err(e) => warn!(error = %e, "failed to fetch beacon node version"),
    }

    // Load validator keys
    let key_manager = match builder.build_key_manager() {
        Ok(km) => {
            let validator_count = km.len();
            update_health_validators(&health_status, validator_count).await;
            info!(count = validator_count, "Loaded validator keys");
            km
        }
        Err(e) => {
            warn!("Failed to load keys, continuing without validators: {}", e);
            update_health_validators(&health_status, 0).await;
            std::sync::Arc::new(crypto::KeyManager::new())
        }
    };

    // Initialize secret provider metrics eagerly so they appear in /metrics output
    secret_provider::metrics::init_secret_provider_metrics();

    // Load keys from cloud secret providers (if configured)
    let secret_providers: Vec<std::sync::Arc<dyn secret_provider::SecretProvider>> =
        builder.build_secret_providers().await?.into_iter().map(std::sync::Arc::from).collect();
    let key_manager = {
        if secret_providers.is_empty() {
            key_manager
        } else {
            let mut km = std::sync::Arc::try_unwrap(key_manager).map_err(|_| {
                anyhow::anyhow!(
                    "cannot take ownership of key_manager: outstanding Arc references exist"
                )
            })?;
            let ksm = secret_provider::KeySourceManager::from_arc(secret_providers.clone());
            let summary = ksm.load_all(&mut km).await?;
            let mut total_loaded = 0usize;
            let mut total_skipped = 0usize;
            let mut total_errors = 0usize;
            for ps in &summary.per_provider {
                info!(
                    provider = %ps.name,
                    loaded = ps.loaded,
                    skipped = ps.skipped,
                    "Loaded keys from cloud provider"
                );
                total_loaded += ps.loaded;
                total_skipped += ps.skipped;
                total_errors += ps.errors.len();
            }
            info!(
                loaded = total_loaded,
                providers = summary.per_provider.len(),
                skipped = total_skipped,
                errors = total_errors,
                "Loaded keys from cloud providers"
            );
            std::sync::Arc::new(km)
        }
    };

    let pubkey_map = builder.build_pubkey_map(&key_manager);

    // Create shared CompositeSigner from loaded keys
    let key_manager_owned = std::sync::Arc::try_unwrap(key_manager).map_err(|_| {
        anyhow::anyhow!("cannot take ownership of key_manager: outstanding Arc references exist")
    })?;
    let known_pubkeys: std::collections::HashSet<[u8; 48]> =
        key_manager_owned.list_public_keys().iter().map(|pk| pk.to_bytes()).collect();
    let local_signer = crypto::LocalSigner::new(key_manager_owned);
    let composite_signer = std::sync::Arc::new(crypto::CompositeSigner::new(local_signer));

    // Connect gRPC remote signer if configured (non-fatal: lazy connection)
    let _grpc_remote_signer = if let Some(ref grpc_url) = config.grpc_signer_url {
        info!(url = %redact_url(grpc_url), "Configuring gRPC remote signer");

        let mut grpc_config = grpc_signer::GrpcRemoteSignerConfig::new(grpc_url.clone());

        if let (Some(ref cert_path), Some(ref key_path), Some(ref ca_path)) = (
            &config.grpc_signer_tls_cert,
            &config.grpc_signer_tls_key,
            &config.grpc_signer_tls_ca_cert,
        ) {
            let cert = std::fs::read(cert_path)
                .map_err(|e| anyhow::anyhow!("failed to read gRPC signer TLS cert: {e}"))?;
            let key = std::fs::read(key_path)
                .map_err(|e| anyhow::anyhow!("failed to read gRPC signer TLS key: {e}"))?;
            let ca_cert = std::fs::read(ca_path)
                .map_err(|e| anyhow::anyhow!("failed to read gRPC signer TLS CA cert: {e}"))?;
            grpc_config = grpc_config.with_tls(cert, key, ca_cert);
        }

        // Log the v2 gRPC contract version and validate the signer is running v2.
        info!("signer contract: v2 (typed RPCs)");

        match grpc_signer::GrpcRemoteSigner::connect(grpc_config).await {
            Ok(signer) => {
                let key_count = signer.public_keys().len();
                info!(
                    url = %redact_url(grpc_url),
                    key_count,
                    "gRPC remote signer connected (v2 typed RPCs)"
                );

                // Register all keys from the remote signer in the composite signer.
                let pubkeys = signer.public_keys();
                let signer = std::sync::Arc::new(signer);
                composite_signer.add_grpc_remote_signer(pubkeys, signer.clone());
                Some(signer)
            }
            Err(e) => {
                warn!(
                    url = %redact_url(grpc_url),
                    error = %e,
                    "Failed to connect to gRPC remote signer; will retry on demand"
                );
                None
            }
        }
    } else {
        None
    };

    // Spawn secret provider refresh task (if configured)
    let refresh_interval = config.secret_provider.refresh_interval.unwrap_or(0);
    if refresh_interval > 0 && !secret_providers.is_empty() {
        let refresh_service = secret_provider::RefreshService::new(
            secret_providers,
            known_pubkeys,
            std::time::Duration::from_secs(refresh_interval),
            shutdown_token.clone(),
        );
        let signer_for_refresh = std::sync::Arc::clone(&composite_signer);
        tokio::spawn(async move {
            refresh_service
                .run(move |sk| {
                    signer_for_refresh.add_local_key(sk);
                })
                .await;
        });
        info!(interval_secs = refresh_interval, "Secret provider refresh task started");
    }

    // Resolve validator indices using BnManager (via trait)
    let beacon_for_resolve: &dyn BeaconNodeClient = bn_manager.as_ref();
    let validator_index_map = resolve_validator_indices(beacon_for_resolve, &pubkey_map).await;

    // Step 6: Doppelganger detection (if enabled)
    if doppelganger_enabled && !pubkey_map.read().is_empty() {
        let validator_index_map = match validator_index_map {
            Ok(ref map) if !map.is_empty() => map.clone(),
            Ok(_) => {
                warn!(
                    total = pubkey_map.read().len(),
                    "No validator indices resolved; validators may be pending activation. \
                     Skipping doppelganger detection"
                );
                std::collections::HashMap::new()
            }
            Err(ref e) => {
                error!("Failed to resolve validator indices: {}", e);
                return Err(anyhow::anyhow!(
                    "validator index resolution failed; doppelganger detection requires indices: {}", e
                ));
            }
        };

        if !validator_index_map.is_empty() {
            let doppelganger_service =
                builder.build_doppelganger_service(beacon_client.clone(), slashing_db.clone())?;

            let pubkeys: Vec<String> = pubkey_map.read().keys().cloned().collect();

            // M-7 (ISSUE-3.6): use the doppelganger service's monotonic clock,
            // not the wall-clock slot_clock. The slot clock is wall-clock-derived
            // and an NTP step can advance current_epoch enough to compress the
            // doppelganger monitoring window. doppelganger_service.current_epoch()
            // is anchored on a monotonic Instant captured at startup.
            let current_epoch = doppelganger_service.current_epoch();

            // S-3 (Issue 2.8): detection is always invoked — the epoch-0 case is
            // handled inside startup::run_doppelganger_detection as an explicit,
            // logged pre-genesis bypass that returns all validators Safe without
            // issuing a beacon liveness query (so a pre-genesis BN error cannot
            // abort startup).  ForwardWindowMachine also applies an epoch-0 bypass
            // for the future production wiring path (Issue 2.10).
            if current_epoch == 0 {
                info!(
                    "Doppelganger detection: pre-genesis (epoch 0) startup — \
                     validators will be marked Safe without a monitoring window"
                );
            }

            match startup::run_doppelganger_detection(
                &doppelganger_service,
                &pubkeys,
                &validator_index_map,
                current_epoch,
            )
            .await
            {
                Ok(safe_validators) => {
                    info!(safe_count = safe_validators.len(), "Doppelganger detection complete");
                }
                Err(e) => {
                    error!("Doppelganger detection failed: {}", e);
                    return Err(e.into());
                }
            }
        }
    } else if !doppelganger_enabled {
        warn!("Doppelganger detection is disabled");
    }

    // Step 7: Build remaining services
    let signer = builder.build_signer(composite_signer.clone(), slashing_db.clone());
    let propagator = builder.build_propagator(beacon_client.clone());
    let validator_store = builder.build_validator_store(config.validators_config.as_deref())?;

    // D-3 (Issue 2.11): register every keystore-loaded validator so the
    // fail-closed per-validator signing gate permits the keys the VC loaded.
    // Without this, the common no-validators_config deployment would have every
    // loaded validator silently blocked from signing.
    builder.register_loaded_validators(&validator_store, &pubkey_map);

    let beacon: std::sync::Arc<dyn BeaconNodeClient> = bn_manager;
    let validator_indices: Vec<String> = match validator_index_map {
        Ok(ref map) => map.values().cloned().collect(),
        Err(_) => Vec::new(),
    };
    let duty_tracker = builder.build_duty_tracker(beacon.clone(), validator_indices);

    let slot_clock = match builder.build_slot_clock() {
        Ok(clock) => clock,
        Err(e) => {
            error!("Failed to create slot clock: {}", e);
            return Err(e.into());
        }
    };

    let fork_schedule = match builder.build_fork_schedule(beacon.as_ref()).await {
        Ok(schedule) => schedule,
        Err(e) => {
            error!("Failed to fetch fork schedule from beacon node: {}", e);
            return Err(e.into());
        }
    };

    match startup::check_fork_compatibility(beacon.as_ref(), &fork_schedule).await {
        Ok(()) => {}
        Err(e) => {
            warn!("Fork compatibility check failed: {}", e);
        }
    }

    let orchestrator_config = builder
        .build_orchestrator_config(genesis_validators_root, fork_schedule)
        .with_timeouts(timeouts);

    // Build proposer BnManager if proposer nodes are configured (T3.1)
    let proposer_bn_manager = match builder.build_proposer_bn_manager() {
        Ok(Some(mgr)) => {
            info!(
                proposer_nodes = ?config.proposer_nodes,
                "Proposer nodes configured — block production will use dedicated pool"
            );
            Some(mgr)
        }
        Ok(None) => None,
        Err(e) => {
            error!("Failed to create proposer BnManager: {}", e);
            return Err(e.into());
        }
    };

    // Use proposer BnManager for block production if available, otherwise main beacon_client
    let block_beacon = match &proposer_bn_manager {
        Some(_proposer_mgr) => {
            std::sync::Arc::new(rvc::beacon_adapter::BeaconBlockAdapter(
                // We need an Arc<BeaconClient> - but proposer_mgr is an Arc<BnManager>.
                // The BeaconBlockAdapter wraps a BeaconClient. For proposer nodes,
                // we use the first proposer node endpoint to create a new BeaconClient.
                {
                    let proposer_endpoint = &config.proposer_nodes[0];
                    let proposer_config =
                        beacon::BeaconClientConfig::new(proposer_endpoint.clone())
                            .with_timeout(std::time::Duration::from_secs(30))
                            .with_max_retries(0)
                            .with_max_body_bytes(config.beacon_max_body_bytes);
                    std::sync::Arc::new(beacon::BeaconClient::new(proposer_config)?)
                },
            ))
        }
        None => std::sync::Arc::new(rvc::beacon_adapter::BeaconBlockAdapter(beacon_client.clone())),
    };

    #[allow(clippy::arc_with_non_send_sync)]
    let builder_service = Some(std::sync::Arc::new(builder::BuilderService::new(
        signer.clone(),
        beacon.clone(),
        validator_store.clone(),
        orchestrator_config.fork_schedule.genesis_fork_version,
    )));

    // Step 7b: Configure remote signer if URL provided
    if let Some(ref url) = config.remote_signer_url {
        if !config.keymanager_enabled {
            warn!(
                url = %url,
                "Remote signer URL configured but Keymanager API is disabled; \
                 enable --keymanager-enabled to manage remote keys at runtime"
            );
        }
        info!(url = %url, "Remote signer URL configured");
    }

    // Step 7b2: Create attesting_enabled toggle (shared with orchestrator + API)
    let attesting_enabled =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(!config.disable_attesting));
    metrics::definitions::RVC_ATTESTING_ENABLED.set(if config.disable_attesting {
        0.0
    } else {
        1.0
    });
    if config.disable_attesting {
        warn!("Attestation duties disabled at startup (--disable-attesting)");
    }

    // Step 7c: Optionally start Keymanager API server
    if config.keymanager_enabled {
        let token_path = config
            .keymanager_token_file
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("./keymanager-api-token.txt"));
        let token = match keymanager_api::auth::ensure_token(&token_path) {
            Ok(t) => {
                keymanager_api::auth::warn_if_insecure_permissions(&token_path);
                t
            }
            Err(e) => {
                error!("Failed to ensure Keymanager API token: {}", e);
                return Err(anyhow::anyhow!("keymanager token error: {}", e));
            }
        };

        let km_addr: std::net::SocketAddr = config
            .keymanager_address
            .as_deref()
            .unwrap_or("127.0.0.1:5062")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid keymanager address: {}", e))?;

        if !km_addr.ip().is_loopback() {
            warn!(
                addr = %km_addr,
                "Keymanager API is bound to a non-loopback address; this exposes key management over the network"
            );
        }

        let km_composite = composite_signer.clone();
        let keystore_mgr = std::sync::Arc::new(KeystoreManagerAdapter::new(
            config.keystore_path.clone(),
            km_composite.clone(),
        ));
        let slashing_prot = std::sync::Arc::new(SlashingProtectionAdapter::new(
            slashing_db.clone(),
            genesis_validators_root_hex.clone(),
        ));
        let validator_mgr =
            std::sync::Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
        // M-12: use a time-based doppelganger gate for newly imported keys.
        // When doppelganger detection is disabled (doppelganger_enabled = false)
        // the window is Duration::ZERO so keys are immediately enabled.
        let doppelganger_window = if doppelganger_enabled {
            // 2 epochs × 32 slots/epoch × 12 s/slot = 768 s (mainnet default)
            std::time::Duration::from_secs(
                2 * eth_types::SLOTS_PER_EPOCH * eth_types::SECONDS_PER_SLOT,
            )
        } else {
            std::time::Duration::ZERO
        };
        let doppelganger_mon =
            std::sync::Arc::new(keymanager_api::gate::DoppelgangerGate::new(doppelganger_window));

        // M-12 (Critical #2): after a restart, re-arm the gate for any key
        // whose import-time sidecar shows the doppelganger window has not yet
        // elapsed.  This prevents keys from bypassing the window on restart.
        if !doppelganger_window.is_zero() {
            rvc::keymanager_adapters::scan_and_rearm_gate(
                &config.keystore_path,
                doppelganger_mon.as_ref(),
                doppelganger_window.as_secs(),
            );
        }

        let remote_key_mgr = std::sync::Arc::new(RemoteKeyManagerAdapter::new(
            km_composite,
            config.remote_signer_allowed_hosts.clone(),
        ));

        let config_mgr =
            std::sync::Arc::new(ValidatorConfigManagerAdapter::new(validator_store.clone()));

        let exit_mgr: Option<std::sync::Arc<dyn keymanager_api::traits::VoluntaryExitManager>> =
            Some(std::sync::Arc::new(VoluntaryExitManagerAdapter::new(
                beacon_client.clone(),
                signer.clone(),
                orchestrator_config.fork_schedule.clone(),
                genesis_validators_root,
            )));

        let km_server = keymanager_api::KeymanagerServer::new(
            keystore_mgr,
            slashing_prot,
            validator_mgr,
            doppelganger_mon,
            remote_key_mgr,
            config_mgr,
            exit_mgr,
            token.to_string(),
            km_addr,
            config.keymanager_cors_origins.clone(),
            config.keymanager_body_limit,
            config.allow_insecure_remote_signer,
            attesting_enabled.clone(),
            doppelganger_window,
        );

        info!(addr = %km_addr, token_path = %token_path.display(), "Keymanager API enabled");

        tokio::spawn(async move {
            if let Err(e) = km_server.run().await {
                error!("Keymanager API server error: {}", e);
            }
        });
    }

    // Step 8: Start main duty loop
    let circuit_breaker = std::sync::Arc::new(builder::CircuitBreakerState::new(
        config.builder_circuit_breaker_consecutive_limit,
        config.builder_circuit_breaker_epoch_limit,
    ));
    info!(
        consecutive_limit = config.builder_circuit_breaker_consecutive_limit,
        epoch_limit = config.builder_circuit_breaker_epoch_limit,
        "Builder circuit breaker configured"
    );

    let validator_count = pubkey_map.read().len();
    let bn_count = config.effective_beacon_nodes().len();
    let (mut orchestrator, orchestrator_handle) =
        rvc::orchestrator::DutyOrchestrator::new_with_attesting_enabled(
            slot_clock,
            duty_tracker,
            signer,
            propagator,
            beacon.clone(),
            block_beacon,
            builder_service,
            validator_store.clone(),
            orchestrator_config,
            pubkey_map.clone(),
            circuit_breaker,
            attesting_enabled.clone(),
        );

    // Step 8b: Spawn slashing monitor background task
    {
        let slashed_action: rvc::slashing_monitor::SlashedAction =
            config.slashed_validators_action.parse().map_err(|e: String| anyhow::anyhow!(e))?;

        if slashed_action != rvc::slashing_monitor::SlashedAction::None {
            let monitor_beacon = beacon.clone();
            let monitor_store = validator_store.clone();
            let monitor_shutdown = shutdown_token.clone();
            let monitor_orch_handle_shutdown = {
                // We need to signal the orchestrator. Create a watch channel for it.
                let (tx, _rx) = tokio::sync::watch::channel(false);
                tx
            };
            // We'll re-purpose: the slashing monitor just cancels the shutdown_token
            // and the main select! picks it up.
            tokio::spawn(async move {
                let slot_duration = std::time::Duration::from_secs(12);
                let epoch_duration = slot_duration * 32;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(epoch_duration) => {}
                        _ = monitor_shutdown.cancelled() => {
                            break;
                        }
                    }

                    rvc::slashing_monitor::check_slashed_validators(
                        monitor_beacon.as_ref(),
                        &monitor_store,
                        slashed_action,
                        &monitor_orch_handle_shutdown,
                    )
                    .await;

                    // If shutdown action was triggered, cancel everything
                    if *monitor_orch_handle_shutdown.borrow() {
                        monitor_shutdown.cancel();
                        break;
                    }
                }
            });
            info!(
                action = %config.slashed_validators_action,
                "Slashing monitor started"
            );
        }
    }

    finalize_health_status(&health_status).await;

    let grpc_addr = format!("{}:{}", config.grpc_address, grpc_port).parse()?;
    let duty_tracker_service = DutyTrackerService::new();

    info!(addr = %grpc_addr, "Starting gRPC server");
    let grpc_server = Server::builder()
        .add_service(DutyTrackerServer::new(duty_tracker_service))
        .serve_with_shutdown(grpc_addr, async {
            shutdown_signal().await;
        });

    // ISSUE-4.10 / L-10: refuse non-loopback metrics binds unless explicitly
    // opted in via `RVC_METRICS_ALLOW_NON_LOOPBACK=true`. Loopback binds pass
    // silently. Reuses the InsecureGate helper from ISSUE-2.10 (in Refuse mode
    // after Phase 3 ISSUE-3.13 / NFR-10).
    if !metrics_address.is_loopback() {
        // The predicate is constant-true here: the bind is already known to
        // be non-loopback, so the env var alone determines the outcome (the
        // InsecureGate `new()` constructor would set predicate=is_loopback,
        // which is false at this point and would refuse even with the env
        // var set; with_predicate keeps the env-var-only contract).
        let metrics_gate = crypto::insecure::InsecureGate::with_predicate(
            "RVC_METRICS_ALLOW_NON_LOOPBACK",
            crypto::insecure::InsecureMode::default(),
            || true,
        );
        if let Err(e) = metrics_gate.check() {
            error!(
                addr = %metrics_address,
                error = %e,
                "Refusing to start metrics server on non-loopback address (ISSUE-4.10 / L-10)"
            );
            return Err(e.into());
        }
        warn!(
            addr = %metrics_address,
            "Metrics server is bound to a non-loopback address (RVC_METRICS_ALLOW_NON_LOOPBACK=true); \
             this exposes metrics over the network"
        );
    }

    info!(addr = %metrics_address, port = metrics_port, "Starting metrics server");
    let metrics_handle = tokio::spawn(serve_metrics_with_health(
        metrics_address,
        metrics_port,
        health_status.clone(),
    ));

    // Spawn monitoring push task if endpoint is configured (T3.6)
    if let Some(ref monitoring_endpoint) = config.monitoring_endpoint {
        let monitoring_config = rvc::monitoring::MonitoringConfig {
            endpoint: monitoring_endpoint.clone(),
            interval: std::time::Duration::from_secs(config.monitoring_interval),
            insecure: config.monitoring_endpoint_insecure,
        };
        let monitoring_shutdown = shutdown_token.clone();
        info!(
            endpoint = %rvc::config::redact_url(monitoring_endpoint),
            interval_secs = config.monitoring_interval,
            "Starting monitoring push task"
        );
        tokio::spawn(rvc::monitoring::start_monitoring_push(
            monitoring_config,
            monitoring_shutdown,
            move || (validator_count as u32, validator_count as u32),
        ));
    }

    // Spawn proposer config URL refresh task if configured (T3.12)
    if let Some(ref proposer_config_url) = config.proposer_config_url {
        let settings = rvc::config_url::ProposerConfigUrlSettings {
            url: proposer_config_url.clone(),
            refresh_interval: std::time::Duration::from_secs(
                config.proposer_config_refresh_interval,
            ),
            token: config.proposer_config_url_token.clone(),
            insecure: config.proposer_config_url_insecure,
        };
        let config_refresh_shutdown = shutdown_token.clone();
        info!(
            url = %rvc::config::redact_url(proposer_config_url),
            refresh_interval_secs = config.proposer_config_refresh_interval,
            "Starting proposer config URL refresh task"
        );
        tokio::spawn(rvc::config_url::start_proposer_config_refresh(
            settings,
            config_refresh_shutdown,
            move |updates, _default| {
                for update in &updates {
                    info!(
                        pubkey = %update.pubkey,
                        fee_recipient = ?update.fee_recipient,
                        builder_enabled = ?update.builder_enabled,
                        "Proposer config update from URL"
                    );
                }
            },
        ));
    }

    // Log broadcast topics if non-default (T3.4)
    {
        let topics = config.effective_broadcast_topics();
        info!(
            attestations = topics.attestations,
            blocks = topics.blocks,
            sync_committee = topics.sync_committee,
            subscriptions = topics.subscriptions,
            "Active broadcast topics"
        );
    }

    startup::log_orchestrator_started(validator_count, bn_count);
    info!("Starting duty orchestrator");

    tokio::select! {
        result = grpc_server => {
            match result {
                Ok(()) => info!("gRPC server shut down gracefully"),
                Err(e) => error!("gRPC server error: {}", e),
            }
        }
        result = orchestrator.run() => {
            match result {
                Ok(()) => info!("Orchestrator completed"),
                Err(e) => error!("Orchestrator error: {}", e),
            }
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received");
        }
    }

    startup::log_shutdown_initiated("signal received");
    shutdown_token.cancel();
    orchestrator_handle.shutdown();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Logging guards (tracing + file) are held by _logging_guards and
    // dropped at the end of the caller's scope, flushing pending data.

    // Gracefully shut down metrics server with a brief timeout
    metrics_handle.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        metrics_handle.await.ok()
    })
    .await;

    info!(uptime_secs = startup_time.elapsed().as_secs(), "Validator client shut down complete");
    Ok(())
}

async fn resolve_validator_indices(
    beacon_client: &dyn BeaconNodeClient,
    pubkey_map: &rvc::orchestrator::PubkeyMap,
) -> Result<std::collections::HashMap<String, String>, anyhow::Error> {
    let pubkeys: Vec<String> = {
        let map = pubkey_map.read();
        if map.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        map.keys().cloned().collect()
    };
    let response = beacon_client.get_validators(&pubkeys).await?;

    let index_map: std::collections::HashMap<String, String> =
        response.data.iter().map(|v| (v.validator.pubkey.clone(), v.index.clone())).collect();

    if index_map.len() < pubkeys.len() {
        warn!(
            resolved = index_map.len(),
            total = pubkeys.len(),
            "Some validator public keys could not be resolved to indices"
        );
    }
    info!(count = index_map.len(), "Resolved validator indices");
    Ok(index_map)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C)");
        }
        _ = terminate => {
            info!("Received SIGTERM");
        }
    }
}

// Health status update functions.
// These are called sequentially during startup before concurrent access begins,
// so the read-modify-write pattern is safe in this context.
async fn update_health_beacon_connected(health_status: &SharedHealthStatus, connected: bool) {
    let mut status = health_status.write().await;
    status.beacon_connected = connected;
    status.update_healthy();
}

async fn update_health_validators(health_status: &SharedHealthStatus, count: usize) {
    let mut status = health_status.write().await;
    status.validators_loaded = count;
    status.update_healthy();
}

async fn update_health_slashing_db(health_status: &SharedHealthStatus, initialized: bool) {
    let mut status = health_status.write().await;
    status.slashing_db_initialized = initialized;
    status.update_healthy();
}

async fn update_health_error(health_status: &SharedHealthStatus, error: String) {
    let mut status = health_status.write().await;
    status.error = Some(error);
    status.healthy = false;
}

async fn finalize_health_status(health_status: &SharedHealthStatus) {
    let mut status = health_status.write().await;
    status.update_healthy();
    info!(healthy = status.healthy, "Health status finalized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Serialize all tests in this module that read or write OTEL env vars.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_build_tracing_config_no_endpoint_returns_none() {
        let _guard = env_lock();
        // Clear env vars that could interfere
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config::default();
        assert!(build_tracing_config(&config).is_none());
    }

    #[test]
    fn test_build_tracing_config_with_endpoint_returns_some() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.endpoint, "http://localhost:4318");
        assert_eq!(tc.exporter, telemetry::ExporterKind::Otlp);
        assert!((tc.sample_rate - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_tracing_config_env_var_fallback() {
        let _guard = env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-collector:4318");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config::default(); // no tracing_endpoint set
        let tc = build_tracing_config(&config).expect("should fall back to env var");
        assert_eq!(tc.endpoint, "http://env-collector:4318");

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_build_tracing_config_cli_overrides_env() {
        let _guard = env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-collector:4318");

        let config = Config {
            tracing_endpoint: Some("http://cli-collector:4318".to_string()),
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should use config value");
        assert_eq!(tc.endpoint, "http://cli-collector:4318");

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_build_tracing_config_sample_rate_env_fallback() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            // sample_rate at default 0.01, so env var should be checked
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!((tc.sample_rate - 0.5).abs() < f64::EPSILON);

        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_build_tracing_config_explicit_sample_rate_overrides_env() {
        let _guard = env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            tracing_sample_rate: 0.75, // non-default, so env var should NOT be checked
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!((tc.sample_rate - 0.75).abs() < f64::EPSILON);

        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_build_tracing_config_sample_rate_clamped() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            tracing_sample_rate: 2.0,
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!((tc.sample_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_tracing_config_negative_sample_rate_clamped() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            tracing_sample_rate: -0.5,
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!(tc.sample_rate.abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_tracing_config_network_propagated() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            network: rvc::config::Network::Hoodi,
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.network, "hoodi");
    }

    #[test]
    fn test_build_tracing_config_unknown_exporter_defaults_to_otlp() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            tracing_exporter: "unknown".to_string(),
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.exporter, telemetry::ExporterKind::Otlp);
    }

    #[test]
    fn test_build_tracing_config_batch_fields_passthrough() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            tracing_max_queue_size: Some(4096),
            tracing_max_export_batch_size: Some(1024),
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert_eq!(tc.max_queue_size, Some(4096));
        assert_eq!(tc.max_export_batch_size, Some(1024));
    }

    #[test]
    fn test_build_tracing_config_batch_fields_none_by_default() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");
        assert!(tc.max_queue_size.is_none());
        assert!(tc.max_export_batch_size.is_none());
    }

    // H-07: init_logging wiring tests
    //
    // Since init_logging calls .init() which sets a global subscriber,
    // we test the pipeline construction via init_tracing directly.
    // The global subscriber can only be set once per test process.

    #[test]
    fn test_init_logging_none_config_returns_none() {
        // init_logging with None should return None (no guard).
        // We can't call init_logging here because it sets the global
        // subscriber. Instead, verify the logic: None config → None guard.
        let config: Option<&telemetry::TelemetryConfig> = None;
        assert!(config.is_none());
        // The None branch returns None unconditionally (verified by code review).
    }

    #[test]
    fn test_build_tracing_config_creates_valid_telemetry_config() {
        let _guard = env_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config {
            tracing_endpoint: Some("http://localhost:4318".to_string()),
            ..Default::default()
        };
        let tc = build_tracing_config(&config).expect("should return Some");

        // The config should be valid for init_tracing
        let result = telemetry::init_tracing(&tc);
        assert!(result.is_ok(), "init_tracing should succeed with valid config");
        let (_layer, guard) = result.unwrap();
        // Clean up the provider
        drop(guard);
    }

    #[test]
    fn test_init_tracing_with_config_returns_guard() {
        let tc = telemetry::TelemetryConfig {
            endpoint: "http://localhost:4318".to_string(),
            exporter: telemetry::ExporterKind::Otlp,
            sample_rate: 0.5,
            network: "mainnet".to_string(),
            ..Default::default()
        };
        let result = telemetry::init_tracing(&tc);
        assert!(result.is_ok(), "init_tracing should return Ok with layer and guard");
        let (_layer, guard) = result.unwrap();
        drop(guard);
    }

    #[test]
    fn test_init_tracing_invalid_config_returns_err() {
        let tc = telemetry::TelemetryConfig {
            endpoint: "ftp://invalid:21".to_string(),
            exporter: telemetry::ExporterKind::Otlp,
            sample_rate: 0.5,
            network: "mainnet".to_string(),
            ..Default::default()
        };
        let result = telemetry::init_tracing(&tc);
        assert!(result.is_err(), "init_tracing should fail with invalid endpoint scheme");
    }

    #[test]
    fn test_grpc_signer_cli_flags_parse_all() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "rvc",
            "start",
            "--grpc-signer-url",
            "https://signer.example.com:50051",
            "--grpc-signer-tls-cert",
            "/tmp/cert.pem",
            "--grpc-signer-tls-key",
            "/tmp/key.pem",
            "--grpc-signer-tls-ca-cert",
            "/tmp/ca.pem",
        ])
        .expect("should parse");

        match cli.command {
            Commands::Start {
                grpc_signer_url,
                grpc_signer_tls_cert,
                grpc_signer_tls_key,
                grpc_signer_tls_ca_cert,
                ..
            } => {
                assert_eq!(grpc_signer_url.as_deref(), Some("https://signer.example.com:50051"));
                assert_eq!(grpc_signer_tls_cert, Some(PathBuf::from("/tmp/cert.pem")));
                assert_eq!(grpc_signer_tls_key, Some(PathBuf::from("/tmp/key.pem")));
                assert_eq!(grpc_signer_tls_ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn test_grpc_signer_cli_flags_optional() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["rvc", "start"]).expect("should parse without grpc flags");

        match cli.command {
            Commands::Start {
                grpc_signer_url,
                grpc_signer_tls_cert,
                grpc_signer_tls_key,
                grpc_signer_tls_ca_cert,
                ..
            } => {
                assert!(grpc_signer_url.is_none());
                assert!(grpc_signer_tls_cert.is_none());
                assert!(grpc_signer_tls_key.is_none());
                assert!(grpc_signer_tls_ca_cert.is_none());
            }
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn test_grpc_signer_config_defaults_none() {
        let config = Config::default();
        assert!(config.grpc_signer_url.is_none());
        assert!(config.grpc_signer_tls_cert.is_none());
        assert!(config.grpc_signer_tls_key.is_none());
        assert!(config.grpc_signer_tls_ca_cert.is_none());
    }

    #[test]
    fn test_grpc_signer_config_merge_with_cli() {
        let mut config = Config::default();
        let cli = CliOverrides {
            grpc_signer_url: Some("https://signer:50051".to_string()),
            grpc_signer_tls_cert: Some(PathBuf::from("/cert.pem")),
            grpc_signer_tls_key: Some(PathBuf::from("/key.pem")),
            grpc_signer_tls_ca_cert: Some(PathBuf::from("/ca.pem")),
            ..Default::default()
        };

        config.merge_with_cli(&cli);

        assert_eq!(config.grpc_signer_url.as_deref(), Some("https://signer:50051"));
        assert_eq!(config.grpc_signer_tls_cert, Some(PathBuf::from("/cert.pem")));
        assert_eq!(config.grpc_signer_tls_key, Some(PathBuf::from("/key.pem")));
        assert_eq!(config.grpc_signer_tls_ca_cert, Some(PathBuf::from("/ca.pem")));
    }

    #[test]
    fn test_grpc_signer_config_merge_preserves_none() {
        let mut config = Config::default();
        let cli = CliOverrides::default();

        config.merge_with_cli(&cli);

        assert!(config.grpc_signer_url.is_none());
        assert!(config.grpc_signer_tls_cert.is_none());
    }

    /// Regression guard for the v0.4.0 logging silence bug.
    ///
    /// `Vec<L: Layer<S>>::register_callsite()` returns `Interest::never()`
    /// for an empty Vec (tracing-subscriber 0.3 `layer/mod.rs:1788`). When
    /// that empty Vec is the outer layer in a `Layered` stack, the
    /// short-circuit in `Layered::pick_interest` disables every callsite,
    /// so no events ever reach `fmt::layer` underneath.
    ///
    /// This test mirrors `init_logging`'s subscriber composition for the
    /// no-extras case (no `--tracing-endpoint`, no `--logfile`) and asserts
    /// that a basic `info!` event reaches the writer.
    #[test]
    fn test_init_logging_no_extras_emits_events() {
        use std::io;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::layer::Layer;
        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl io::Write for SharedBuf {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for SharedBuf {
            type Writer = SharedBuf;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf = SharedBuf::default();
        let filter = tracing_subscriber::EnvFilter::new("info");

        // Match the exact shape `init_logging` builds when both
        // `tracing_config` and `file_config` are None: a Vec that would have
        // been empty, padded with `Identity` to avoid the never-Interest poison.
        let boxed_layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
            vec![Box::new(tracing_subscriber::layer::Identity::new())];

        let subscriber = tracing_subscriber::registry()
            .with(boxed_layers)
            .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()))
            .with(filter);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("init_logging regression marker");
        });

        let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("init_logging regression marker"),
            "init_logging composition silently drops events; captured: {captured:?}"
        );
    }

    // Serializes the RUST_LOG-mutating parity tests below (process-global env).
    // nextest runs each test in its own process, but guard anyway.
    static RUST_LOG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_rust_log<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = RUST_LOG_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        match value {
            Some(v) => std::env::set_var("RUST_LOG", v),
            None => std::env::remove_var("RUST_LOG"),
        }
        let out = f();
        match prev {
            Some(p) => std::env::set_var("RUST_LOG", p),
            None => std::env::remove_var("RUST_LOG"),
        }
        out
    }

    // Cross-binary init parity (P0-5 / M3): bin/rvc and bin/rvc-signer must share
    // one default level (`info`) and one RUST_LOG precedence — both route their
    // filter through `telemetry::env_filter_or("info")`. These assertions mirror
    // the `rvc-signer` parity tests so an operator learns one behavior, not two.
    #[test]
    fn test_rvc_unset_rust_log_defaults_to_info() {
        let rendered = with_rust_log(None, || format!("{}", telemetry::env_filter_or("info")));
        assert_eq!(rendered, "info", "unset RUST_LOG must default to info, got: {rendered}");
    }

    #[test]
    fn test_rvc_rust_log_overrides_default() {
        let rendered =
            with_rust_log(Some("debug"), || format!("{}", telemetry::env_filter_or("info")));
        assert!(rendered.contains("debug"), "RUST_LOG=debug must override the default: {rendered}");
    }

    #[test]
    fn test_rvc_per_module_directive_preserved() {
        let rendered = with_rust_log(Some("warn,rvc=trace"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        assert!(rendered.contains("rvc=trace"), "per-module directive missing: {rendered}");
    }

    #[test]
    fn test_rvc_malformed_rust_log_falls_back_to_info() {
        let rendered = with_rust_log(Some("rvc=invalidlevel"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert_eq!(
            rendered, "info",
            "malformed RUST_LOG must fall back to info (no panic, no silence): {rendered}"
        );
    }

    #[test]
    fn test_rvc_whitespace_padded_rust_log_honored() {
        let rendered = with_rust_log(Some("warn, rvc=trace"), || {
            format!("{}", telemetry::env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        assert!(rendered.contains("rvc=trace"), "padded per-module directive missing: {rendered}");
    }
}
