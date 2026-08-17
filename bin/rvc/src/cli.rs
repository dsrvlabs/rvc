//! CLI types and command dispatch for the `rvc` binary.

use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use rvc::config::{
    BlockSelectionMode, BroadcastTopic, CliOverrides, GrpcSignerArgs, KeymanagerArgs,
    MonitoringArgs, Network, SlashedAction, TracingArgs,
};
use tracing::{error, info, warn};

use crate::commands;
use crate::logging::{
    build_file_layer_config, build_tracing_config, init_logging, load_config,
    spawn_log_reload_handler,
};

#[derive(Parser)]
#[command(name = "rvc")]
#[command(version)]
#[command(about = "Rust Validator Client - Ethereum consensus layer validator", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the validator client
    Start(Box<StartArgs>),

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

/// Arguments for `rvc start`, composed of flattened clap groups that mirror
/// the nested config sections introduced in RF5-12.
#[derive(Args, Debug)]
pub struct StartArgs {
    /// Path to the configuration file (TOML format)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub beacon: BeaconArgs,

    #[command(flatten)]
    pub keys: KeysArgs,

    #[command(flatten)]
    pub server: ServerArgs,

    #[command(flatten)]
    pub network: NetworkArgs,

    #[command(flatten)]
    pub logging: LoggingArgs,

    #[command(flatten)]
    pub tracing: TracingArgs,

    #[command(flatten)]
    pub keymanager: KeymanagerArgs,

    #[command(flatten)]
    pub grpc_signer: GrpcSignerArgs,

    #[command(flatten)]
    pub safety: SafetyArgs,

    #[command(flatten)]
    pub builder: BuilderArgs,

    #[command(flatten)]
    pub proposer: ProposerArgs,

    #[command(flatten)]
    pub monitoring: MonitoringArgs,

    #[command(flatten)]
    pub slashing: SlashingArgs,
}

/// Beacon-node connection and BN HTTP operation timeouts.
#[derive(Args, Debug)]
pub struct BeaconArgs {
    /// Beacon node URL (e.g., http://localhost:5052)
    #[arg(long)]
    pub beacon_url: Option<String>,

    /// Comma-separated list of beacon node URLs for multi-BN support
    #[arg(long, value_delimiter = ',')]
    pub beacon_nodes: Option<Vec<String>>,

    /// Maximum JSON response body size in bytes from the beacon node.
    ///
    /// Requests whose body (or Content-Length) exceeds this value are rejected
    /// before the full body is allocated.  Raise this only if your beacon node
    /// legitimately returns larger responses.
    ///
    /// Default when unset: 33554432 (32 MiB), from `Config::default()`.
    #[arg(long)]
    pub beacon_max_body_bytes: Option<usize>,

    /// Block production timeout in seconds (default: 3)
    #[arg(long)]
    pub block_production_timeout: Option<u64>,

    /// Attestation fetch timeout in seconds (default: 4)
    #[arg(long)]
    pub attestation_timeout: Option<u64>,

    /// Aggregate fetch timeout in seconds (default: 2)
    #[arg(long)]
    pub aggregate_timeout: Option<u64>,

    /// Duty fetch timeout in seconds (default: 10)
    #[arg(long)]
    pub duty_fetch_timeout: Option<u64>,
}

/// Keystore, secret-provider, and validators-config paths.
#[derive(Args, Debug)]
pub struct KeysArgs {
    /// Path to the keystore directory
    #[arg(long)]
    pub keystore_path: Option<PathBuf>,

    /// Path to the password file for keystore decryption
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Number of threads for parallel keystore decryption (default: auto-detect)
    #[arg(long)]
    pub key_decrypt_threads: Option<usize>,

    /// Disable keystore file locking (for DVT setups with shared key material)
    #[arg(long)]
    pub disable_keystore_locking: bool,

    /// Secret provider(s) to use for loading validator keys (e.g., "gcp")
    #[arg(long)]
    pub secret_provider: Option<String>,

    /// GCP project ID (required when --secret-provider includes "gcp")
    #[arg(long)]
    pub gcp_project_id: Option<String>,

    /// Prefix for GCP secret names (default: "validator-key-")
    #[arg(long)]
    pub gcp_secret_prefix: Option<String>,

    /// Interval in seconds to refresh keys from secret providers (0 = disabled)
    #[arg(long)]
    pub secret_refresh_interval: Option<u64>,

    /// Fail startup if any secret provider fails to list keys (SEC-9 / M-9).
    /// Default is resilient: one flaky provider is skipped; all providers
    /// failing remains fatal regardless of this flag.
    #[arg(long, default_value_t = false)]
    pub secret_provider_strict: bool,

    /// Path to a TOML file containing per-validator fee_recipient and gas_limit overrides.
    /// rvc refuses to start if default_fee_recipient is the zero address (0x000…000).
    ///
    /// Example file:
    ///   [defaults]
    ///   fee_recipient = "0xYourAddress"
    ///   gas_limit = 30000000
    #[arg(long)]
    pub validators_config: Option<PathBuf>,
}

/// Metrics HTTP and local gRPC bind settings.
#[derive(Args, Debug)]
pub struct ServerArgs {
    /// Bind address for the metrics HTTP server (default: 127.0.0.1)
    #[arg(long)]
    pub metrics_address: Option<IpAddr>,

    /// Port for the metrics HTTP server (default: 8080)
    #[arg(long)]
    pub metrics_port: Option<u16>,

    /// Port for the gRPC server (default: 50051)
    #[arg(long)]
    pub grpc_port: Option<u16>,

    /// Bind address for the gRPC server (default: 127.0.0.1)
    #[arg(long)]
    pub grpc_address: Option<String>,
}

/// Network preset and genesis overrides.
#[derive(Args, Debug)]
pub struct NetworkArgs {
    /// Network preset (mainnet, hoodi, holesky, sepolia, custom)
    #[arg(long)]
    pub network: Option<Network>,

    /// Genesis time override (Unix timestamp)
    #[arg(long)]
    pub genesis_time: Option<u64>,

    /// Genesis validators root override (hex string with 0x prefix)
    #[arg(long)]
    pub genesis_validators_root: Option<String>,

    /// Graffiti string for blocks
    #[arg(long)]
    pub graffiti: Option<String>,
}

/// Console logging and logfile rotation settings.
#[derive(Args, Debug)]
pub struct LoggingArgs {
    /// Log level (trace, debug, info, warn, error). Default when unset: info.
    #[arg(long)]
    pub log_level: Option<String>,

    /// Console log output format: `pretty` (default, human-readable) or
    /// `json` (one structured object per event, for log-aggregation backends
    /// such as Loki / Elasticsearch / a SIEM). Also settable via the
    /// `RVC_LOG_FORMAT` env var; an explicit flag wins. Applies to the console
    /// stream only — the file appender keeps its own format (issue 5.5).
    #[arg(long, default_value = "pretty")]
    pub log_format: String,

    /// Enable runtime log-level reload on SIGHUP (opt-in; issue 5.4).
    ///
    /// When set, sending `SIGHUP` to the process re-reads `RUST_LOG` and
    /// swaps the active log filter in place — raising or lowering verbosity
    /// without a restart. Disabled by default so the steady-state log path is
    /// unchanged; the always-on reload *layer* is free on the disabled hot
    /// path either way. Unix only (a no-op on other platforms).
    #[arg(long, default_value_t = false)]
    pub enable_log_reload: bool,

    /// Path to the log file (enables file logging alongside stdout)
    #[arg(long)]
    pub logfile: Option<PathBuf>,

    /// Maximum log file size in MB before rotation (default: 200)
    #[arg(long)]
    pub logfile_max_size: Option<u64>,

    /// Maximum number of rotated log files to keep (default: 5)
    #[arg(long)]
    pub logfile_max_number: Option<usize>,

    /// Enable gzip compression of rotated log files
    #[arg(long)]
    pub logfile_compress: bool,

    /// Log level for file logging (default: same as --log-level)
    #[arg(long)]
    pub logfile_level: Option<String>,
}

/// Startup safety toggles (doppelganger, attesting, slashed action).
#[derive(Args, Debug)]
pub struct SafetyArgs {
    /// Disable doppelganger / forward-window protection (enabled by default).
    ///
    /// When enabled (default), newly loaded and imported keys are withheld from
    /// signing for ~2 epochs (~12.8 min on mainnet) while network liveness is
    /// observed, mitigating double-signing if another live instance holds the
    /// same keys. Opting out removes that safety cost but exposes the process
    /// to the Staked 2021 / SSV-Ankr class of mass-slashing incidents.
    #[arg(long)]
    pub no_doppelganger_detection: bool,

    /// Disable attestation duties at startup (emergency use only)
    #[arg(long)]
    pub disable_attesting: bool,

    /// Action when a slashed validator is detected: disable-only (default), shutdown, none
    #[arg(long)]
    pub slashed_validators_action: Option<SlashedAction>,

    /// Allow startup when the beacon node's current fork version is not in
    /// the client's schedule (SEC-9 / M-15). For testnets / experimental
    /// forks only; default is fatal on unknown fork.
    #[arg(long, default_value_t = false)]
    pub allow_unsupported_fork: bool,
}

/// Builder circuit-breaker and registration batch settings.
#[derive(Args, Debug)]
pub struct BuilderArgs {
    /// Builder circuit breaker: consecutive missed slots before fallback to local block (default: 3, 0 to disable)
    #[arg(long)]
    pub builder_circuit_breaker_consecutive_limit: Option<u32>,

    /// Builder circuit breaker: total epoch missed slots before fallback to local block (default: 5, 0 to disable)
    #[arg(long)]
    pub builder_circuit_breaker_epoch_limit: Option<u32>,

    /// Block selection mode: max-profit (default), execution-only, builder-always, builder-only
    #[arg(long)]
    pub block_selection_mode: Option<BlockSelectionMode>,

    /// Maximum number of validator registrations per batch (default: 500, 0 = send all at once)
    #[arg(long)]
    pub validator_registration_batch_size: Option<usize>,

    /// Delay in milliseconds between registration batches (default: 500)
    #[arg(long)]
    pub validator_registration_batch_delay: Option<u64>,
}

/// Proposer-nodes, broadcast topics, and proposer-config source.
#[derive(Args, Debug)]
pub struct ProposerArgs {
    /// Comma-separated list of dedicated proposer beacon node URLs for block production
    #[arg(long, value_delimiter = ',')]
    pub proposer_nodes: Option<Vec<String>>,

    /// Comma-separated list of message types to broadcast to all BNs (attestations,blocks,sync-committee,subscriptions,none)
    #[arg(long, value_delimiter = ',')]
    pub broadcast: Option<Vec<BroadcastTopic>>,

    /// Remote URL for proposer configuration (mutually exclusive with --proposer-config-file)
    #[arg(long, conflicts_with = "proposer_config_file")]
    pub proposer_config_url: Option<String>,

    /// Local file path for proposer configuration (mutually exclusive with --proposer-config-url)
    #[arg(long, conflicts_with = "proposer_config_url")]
    pub proposer_config_file: Option<String>,

    /// Refresh interval in seconds for proposer config URL (default: 384, i.e., one epoch)
    #[arg(long)]
    pub proposer_config_refresh_interval: Option<u64>,

    /// Bearer token for proposer config URL authentication
    #[arg(long)]
    pub proposer_config_url_token: Option<String>,

    /// Allow HTTP (non-HTTPS) proposer config URL
    #[arg(long)]
    pub proposer_config_url_insecure: bool,
}

/// Slashing-protection database and operator safety flags.
#[derive(Args, Debug)]
pub struct SlashingArgs {
    /// Path to the slashing protection database
    #[arg(long)]
    pub slashing_db_path: Option<PathBuf>,

    /// Allow creating a fresh empty slashing-protection DB when the path is
    /// missing (SEC-3). DANGEROUS on a previously-active validator: the new
    /// DB has zero signing history and can enable double-signing / slashing.
    /// Use only for genuine first-time deployments. A 0-byte or corrupt DB
    /// is always a hard error regardless of this flag.
    #[arg(long, default_value_t = false)]
    pub init_slashing_db: bool,

    /// Exit on unsafe slashing DB file permissions (world-readable/writable)
    #[arg(long)]
    pub strict_permissions: bool,

    /// Reject null-root re-signs as potential double votes (strict EIP-3076 semantics)
    #[arg(long)]
    pub strict_slashing_semantics: bool,
}

/// Convert a present-only CLI boolean into the three-state `Option<bool>`
/// used by [`CliOverrides`]: `true` → `Some(true)`, `false` (absent) → `None`.
fn flag(b: bool) -> Option<bool> {
    if b {
        Some(true)
    } else {
        None
    }
}

impl From<StartArgs> for CliOverrides {
    fn from(args: StartArgs) -> Self {
        let StartArgs {
            config: _,
            beacon,
            keys,
            server,
            network,
            logging,
            tracing,
            keymanager,
            grpc_signer,
            safety,
            builder,
            proposer,
            monitoring,
            slashing,
        } = args;

        Self {
            beacon_url: beacon.beacon_url,
            beacon_nodes: beacon.beacon_nodes,
            keystore_path: keys.keystore_path,
            password_file: keys.password_file,
            slashing_db_path: slashing.slashing_db_path,
            init_slashing_db: flag(slashing.init_slashing_db),
            allow_unsupported_fork: flag(safety.allow_unsupported_fork),
            metrics_address: server.metrics_address,
            metrics_port: server.metrics_port,
            grpc_port: server.grpc_port,
            grpc_address: server.grpc_address,
            network: network.network,
            genesis_time: network.genesis_time,
            genesis_validators_root: network.genesis_validators_root,
            graffiti: network.graffiti,
            log_level: logging.log_level,
            doppelganger_detection: if safety.no_doppelganger_detection {
                Some(false)
            } else {
                None
            },
            keymanager_enabled: if keymanager.no_keymanager {
                Some(false)
            } else if keymanager.enabled == Some(true) {
                Some(true)
            } else {
                None
            },
            keymanager_address: keymanager.address,
            keymanager_token_file: keymanager.token_file,
            remote_signer_url: keymanager.remote_signer_url,
            remote_signer_allowed_hosts: keymanager.remote_signer_allowed_hosts,
            key_decrypt_threads: keys.key_decrypt_threads,
            tracing_endpoint: tracing.endpoint,
            tracing_exporter: tracing.exporter,
            tracing_sample_rate: tracing.sample_rate,
            tracing_max_queue_size: tracing.max_queue_size,
            tracing_max_export_batch_size: tracing.max_export_batch_size,
            secret_provider: keys.secret_provider,
            gcp_project_id: keys.gcp_project_id,
            gcp_secret_prefix: keys.gcp_secret_prefix,
            secret_refresh_interval: keys.secret_refresh_interval,
            secret_provider_strict: flag(keys.secret_provider_strict),
            allow_insecure_remote_signer: keymanager.allow_insecure_remote_signer.filter(|b| *b),
            keymanager_cors_origins: keymanager.cors_origins,
            keymanager_body_limit: keymanager.body_limit,
            grpc_signer_url: grpc_signer.url,
            grpc_signer_tls_cert: grpc_signer.tls_cert,
            grpc_signer_tls_key: grpc_signer.tls_key,
            grpc_signer_tls_ca_cert: grpc_signer.tls_ca_cert,
            disable_attesting: flag(safety.disable_attesting),
            slashed_validators_action: safety.slashed_validators_action,
            builder_circuit_breaker_consecutive_limit: builder
                .builder_circuit_breaker_consecutive_limit,
            builder_circuit_breaker_epoch_limit: builder.builder_circuit_breaker_epoch_limit,
            disable_keystore_locking: flag(keys.disable_keystore_locking),
            proposer_nodes: proposer.proposer_nodes,
            broadcast: proposer.broadcast,
            proposer_config_url: proposer.proposer_config_url,
            proposer_config_file: proposer.proposer_config_file,
            proposer_config_refresh_interval: proposer.proposer_config_refresh_interval,
            proposer_config_url_token: proposer.proposer_config_url_token,
            proposer_config_url_insecure: flag(proposer.proposer_config_url_insecure),
            monitoring_endpoint: monitoring.endpoint,
            monitoring_interval: monitoring.interval,
            monitoring_endpoint_insecure: monitoring.endpoint_insecure.filter(|b| *b),
            logfile: logging.logfile,
            logfile_max_size: logging.logfile_max_size,
            logfile_max_number: logging.logfile_max_number,
            logfile_compress: flag(logging.logfile_compress),
            logfile_level: logging.logfile_level,
            block_selection_mode: builder.block_selection_mode,
            validator_registration_batch_size: builder.validator_registration_batch_size,
            validator_registration_batch_delay: builder.validator_registration_batch_delay,
            validators_config: keys.validators_config,
            beacon_max_body_bytes: beacon.beacon_max_body_bytes,
        }
    }
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
        Commands::Start(args) => {
            let args = *args;
            // Validate gRPC signer flags: if URL is set, all TLS flags are required
            if args.grpc_signer.url.is_some()
                && (args.grpc_signer.tls_cert.is_none()
                    || args.grpc_signer.tls_key.is_none()
                    || args.grpc_signer.tls_ca_cert.is_none())
            {
                anyhow::bail!(
                    "--grpc-signer-url requires --grpc-signer-tls-cert, \
                     --grpc-signer-tls-key, and --grpc-signer-tls-ca-cert"
                );
            }

            let mut timeouts = bn_manager::OperationTimeouts::default();
            if let Some(secs) = args.beacon.block_production_timeout {
                if secs == 0 {
                    anyhow::bail!("--block-production-timeout must be greater than 0");
                }
                timeouts.block_production = std::time::Duration::from_secs(secs);
            }
            if let Some(secs) = args.beacon.attestation_timeout {
                if secs == 0 {
                    anyhow::bail!("--attestation-timeout must be greater than 0");
                }
                timeouts.attestation_fetch = std::time::Duration::from_secs(secs);
            }
            if let Some(secs) = args.beacon.aggregate_timeout {
                if secs == 0 {
                    anyhow::bail!("--aggregate-timeout must be greater than 0");
                }
                timeouts.aggregate_fetch = std::time::Duration::from_secs(secs);
                timeouts.aggregate_submit = std::time::Duration::from_secs(secs);
            }
            if let Some(secs) = args.beacon.duty_fetch_timeout {
                if secs == 0 {
                    anyhow::bail!("--duty-fetch-timeout must be greater than 0");
                }
                timeouts.duty_fetch = std::time::Duration::from_secs(secs);
            }

            if let Some(n) = args.keys.key_decrypt_threads {
                if n == 0 {
                    anyhow::bail!("--key-decrypt-threads must be greater than 0");
                }
            }

            let config_path = args.config.clone();
            let log_format = args.logging.log_format.clone();
            let enable_log_reload = args.logging.enable_log_reload;
            let strict_permissions = args.slashing.strict_permissions;
            let strict_slashing_semantics = args.slashing.strict_slashing_semantics;

            let cli_overrides = CliOverrides::from(args);

            let mut cfg = load_config(config_path)?;
            cfg.merge_with_cli(&cli_overrides);

            let tracing_config = build_tracing_config(&cfg);
            let file_layer_config = build_file_layer_config(&cfg);
            let log_format = telemetry::LogFormat::resolve(Some(&log_format));
            // Use post-merge cfg so a TOML log_level is not clobbered by a clap default.
            let logging_guards = init_logging(
                &cfg.log_level,
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
            // ARCH-2h: keep shutdown_rx so panicking tasks trigger process drain.
            let (executor, shutdown_rx) = rvc::bootstrap::TaskExecutor::new(shutdown_token);
            spawn_log_reload_handler(
                enable_log_reload,
                logging_guards.reload_handle.clone(),
                &executor,
            );

            let run_result = rvc::bootstrap::run(
                cfg,
                rvc::bootstrap::RunOptions {
                    strict_permissions,
                    strict_slashing_semantics,
                    timeouts,
                },
                executor,
                shutdown_rx,
            )
            .await;

            // Logging guards drop after run returns (flush last).
            let _ = &logging_guards;

            // Keystore-lock → EXIT_KEYSTORE_LOCKED is mapped in synchronous main
            // after the runtime drops (ARCH-2i); never hard-exit mid-async here.
            run_result?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use rvc::config::TracingExporter;

    /// Complete long-flag surface for `rvc start` (RF5-14 help snapshot).
    const START_FLAGS: &[&str] = &[
        "--config",
        "--beacon-url",
        "--beacon-nodes",
        "--beacon-max-body-bytes",
        "--block-production-timeout",
        "--attestation-timeout",
        "--aggregate-timeout",
        "--duty-fetch-timeout",
        "--keystore-path",
        "--password-file",
        "--key-decrypt-threads",
        "--disable-keystore-locking",
        "--secret-provider",
        "--gcp-project-id",
        "--gcp-secret-prefix",
        "--secret-refresh-interval",
        "--secret-provider-strict",
        "--validators-config",
        "--metrics-address",
        "--metrics-port",
        "--grpc-port",
        "--grpc-address",
        "--network",
        "--genesis-time",
        "--genesis-validators-root",
        "--graffiti",
        "--log-level",
        "--log-format",
        "--enable-log-reload",
        "--logfile",
        "--logfile-max-size",
        "--logfile-max-number",
        "--logfile-compress",
        "--logfile-level",
        "--tracing-endpoint",
        "--tracing-exporter",
        "--tracing-sample-rate",
        "--tracing-max-queue-size",
        "--tracing-max-export-batch-size",
        "--keymanager-enabled",
        "--no-keymanager",
        "--keymanager-address",
        "--keymanager-token-file",
        "--remote-signer-url",
        "--remote-signer-allowed-hosts",
        "--allow-insecure-remote-signer",
        "--keymanager-cors-origins",
        "--keymanager-body-limit",
        "--grpc-signer-url",
        "--grpc-signer-tls-cert",
        "--grpc-signer-tls-key",
        "--grpc-signer-tls-ca-cert",
        "--no-doppelganger-detection",
        "--disable-attesting",
        "--slashed-validators-action",
        "--allow-unsupported-fork",
        "--builder-circuit-breaker-consecutive-limit",
        "--builder-circuit-breaker-epoch-limit",
        "--block-selection-mode",
        "--validator-registration-batch-size",
        "--validator-registration-batch-delay",
        "--proposer-nodes",
        "--broadcast",
        "--proposer-config-url",
        "--proposer-config-file",
        "--proposer-config-refresh-interval",
        "--proposer-config-url-token",
        "--proposer-config-url-insecure",
        "--monitoring-endpoint",
        "--monitoring-interval",
        "--monitoring-endpoint-insecure",
        "--slashing-db-path",
        "--init-slashing-db",
        "--strict-permissions",
        "--strict-slashing-semantics",
    ];

    #[test]
    fn test_start_help_lists_every_flag() {
        let mut cmd = Cli::command();
        let start = cmd.find_subcommand_mut("start").expect("start subcommand");
        let help = start.render_long_help().to_string();
        for flag in START_FLAGS {
            assert!(help.contains(flag), "start --help missing flag {flag}\n{help}");
        }
        // Short form for --config preserved.
        assert!(help.contains("-c, --config"), "short -c for --config missing:\n{help}");
    }

    #[test]
    fn test_start_args_convert_to_equivalent_cli_overrides() {
        let cli = Cli::try_parse_from([
            "rvc",
            "start",
            "--beacon-url",
            "http://bn:5052",
            "--beacon-nodes",
            "http://a:5052,http://b:5052",
            "--keystore-path",
            "/keys",
            "--password-file",
            "/pw",
            "--slashing-db-path",
            "/slash.db",
            "--init-slashing-db",
            "--allow-unsupported-fork",
            "--metrics-address",
            "0.0.0.0",
            "--metrics-port",
            "9090",
            "--grpc-port",
            "60051",
            "--grpc-address",
            "0.0.0.0",
            "--network",
            "hoodi",
            "--genesis-time",
            "1",
            "--genesis-validators-root",
            "0xabc",
            "--graffiti",
            "rvc",
            "--no-doppelganger-detection",
            "--log-level",
            "debug",
            "--keymanager-enabled",
            "--keymanager-address",
            "127.0.0.1:5062",
            "--keymanager-token-file",
            "/token",
            "--remote-signer-url",
            "https://signer",
            "--remote-signer-allowed-hosts",
            "signer.local",
            "--key-decrypt-threads",
            "4",
            "--tracing-endpoint",
            "http://otel:4318",
            "--tracing-exporter",
            "otlp",
            "--tracing-sample-rate",
            "0.5",
            "--tracing-max-queue-size",
            "100",
            "--tracing-max-export-batch-size",
            "50",
            "--secret-provider",
            "gcp",
            "--gcp-project-id",
            "proj",
            "--gcp-secret-prefix",
            "vk-",
            "--secret-refresh-interval",
            "60",
            "--secret-provider-strict",
            "--allow-insecure-remote-signer",
            "--keymanager-cors-origins",
            "https://a,https://b",
            "--keymanager-body-limit",
            "2048",
            "--grpc-signer-url",
            "https://gs:50051",
            "--grpc-signer-tls-cert",
            "/c.pem",
            "--grpc-signer-tls-key",
            "/k.pem",
            "--grpc-signer-tls-ca-cert",
            "/ca.pem",
            "--disable-attesting",
            "--slashed-validators-action",
            "shutdown",
            "--builder-circuit-breaker-consecutive-limit",
            "2",
            "--builder-circuit-breaker-epoch-limit",
            "4",
            "--disable-keystore-locking",
            "--proposer-nodes",
            "http://p:5052",
            "--broadcast",
            "blocks,attestations",
            "--proposer-config-url",
            "https://pc",
            "--proposer-config-refresh-interval",
            "10",
            "--proposer-config-url-token",
            "tok",
            "--proposer-config-url-insecure",
            "--monitoring-endpoint",
            "https://mon",
            "--monitoring-interval",
            "30",
            "--monitoring-endpoint-insecure",
            "--logfile",
            "/var/log/rvc.log",
            "--logfile-max-size",
            "100",
            "--logfile-max-number",
            "3",
            "--logfile-compress",
            "--logfile-level",
            "warn",
            "--block-selection-mode",
            "builder-only",
            "--validator-registration-batch-size",
            "10",
            "--validator-registration-batch-delay",
            "20",
            "--validators-config",
            "/validators.toml",
            "--beacon-max-body-bytes",
            "1024",
        ])
        .expect("argv should parse");

        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let ov = CliOverrides::from(*args);

        assert_eq!(ov.beacon_url.as_deref(), Some("http://bn:5052"));
        assert_eq!(
            ov.beacon_nodes.as_deref(),
            Some(["http://a:5052".to_string(), "http://b:5052".to_string()].as_slice())
        );
        assert_eq!(ov.keystore_path, Some(PathBuf::from("/keys")));
        assert_eq!(ov.password_file, Some(PathBuf::from("/pw")));
        assert_eq!(ov.slashing_db_path, Some(PathBuf::from("/slash.db")));
        assert_eq!(ov.init_slashing_db, Some(true));
        assert_eq!(ov.allow_unsupported_fork, Some(true));
        assert_eq!(ov.metrics_address, Some("0.0.0.0".parse().unwrap()));
        assert_eq!(ov.metrics_port, Some(9090));
        assert_eq!(ov.grpc_port, Some(60051));
        assert_eq!(ov.grpc_address.as_deref(), Some("0.0.0.0"));
        assert_eq!(ov.network, Some(Network::Hoodi));
        assert_eq!(ov.genesis_time, Some(1));
        assert_eq!(ov.genesis_validators_root.as_deref(), Some("0xabc"));
        assert_eq!(ov.graffiti.as_deref(), Some("rvc"));
        assert_eq!(ov.log_level.as_deref(), Some("debug"));
        assert_eq!(ov.doppelganger_detection, Some(false));
        assert_eq!(ov.keymanager_enabled, Some(true));
        assert_eq!(ov.keymanager_address.as_deref(), Some("127.0.0.1:5062"));
        assert_eq!(ov.keymanager_token_file, Some(PathBuf::from("/token")));
        assert_eq!(ov.remote_signer_url.as_deref(), Some("https://signer"));
        assert_eq!(ov.remote_signer_allowed_hosts.as_deref(), Some("signer.local"));
        assert_eq!(ov.key_decrypt_threads, Some(4));
        assert_eq!(ov.tracing_endpoint.as_deref(), Some("http://otel:4318"));
        assert_eq!(ov.tracing_exporter, Some(TracingExporter::Otlp));
        assert_eq!(ov.tracing_sample_rate, Some(0.5));
        assert_eq!(ov.tracing_max_queue_size, Some(100));
        assert_eq!(ov.tracing_max_export_batch_size, Some(50));
        assert_eq!(ov.secret_provider.as_deref(), Some("gcp"));
        assert_eq!(ov.gcp_project_id.as_deref(), Some("proj"));
        assert_eq!(ov.gcp_secret_prefix.as_deref(), Some("vk-"));
        assert_eq!(ov.secret_refresh_interval, Some(60));
        assert_eq!(ov.secret_provider_strict, Some(true));
        assert_eq!(ov.allow_insecure_remote_signer, Some(true));
        assert_eq!(
            ov.keymanager_cors_origins.as_deref(),
            Some(["https://a".to_string(), "https://b".to_string()].as_slice())
        );
        assert_eq!(ov.keymanager_body_limit, Some(2048));
        assert_eq!(ov.grpc_signer_url.as_deref(), Some("https://gs:50051"));
        assert_eq!(ov.grpc_signer_tls_cert, Some(PathBuf::from("/c.pem")));
        assert_eq!(ov.grpc_signer_tls_key, Some(PathBuf::from("/k.pem")));
        assert_eq!(ov.grpc_signer_tls_ca_cert, Some(PathBuf::from("/ca.pem")));
        assert_eq!(ov.disable_attesting, Some(true));
        assert_eq!(ov.slashed_validators_action, Some(SlashedAction::Shutdown));
        assert_eq!(ov.builder_circuit_breaker_consecutive_limit, Some(2));
        assert_eq!(ov.builder_circuit_breaker_epoch_limit, Some(4));
        assert_eq!(ov.disable_keystore_locking, Some(true));
        assert_eq!(ov.proposer_nodes.as_deref(), Some(["http://p:5052".to_string()].as_slice()));
        assert_eq!(
            ov.broadcast.as_deref(),
            Some([BroadcastTopic::Blocks, BroadcastTopic::Attestations].as_slice())
        );
        assert_eq!(ov.proposer_config_url.as_deref(), Some("https://pc"));
        assert_eq!(ov.proposer_config_refresh_interval, Some(10));
        assert_eq!(ov.proposer_config_url_token.as_deref(), Some("tok"));
        assert_eq!(ov.proposer_config_url_insecure, Some(true));
        assert_eq!(ov.monitoring_endpoint.as_deref(), Some("https://mon"));
        assert_eq!(ov.monitoring_interval, Some(30));
        assert_eq!(ov.monitoring_endpoint_insecure, Some(true));
        assert_eq!(ov.logfile, Some(PathBuf::from("/var/log/rvc.log")));
        assert_eq!(ov.logfile_max_size, Some(100));
        assert_eq!(ov.logfile_max_number, Some(3));
        assert_eq!(ov.logfile_compress, Some(true));
        assert_eq!(ov.logfile_level.as_deref(), Some("warn"));
        assert_eq!(ov.block_selection_mode, Some(BlockSelectionMode::BuilderOnly));
        assert_eq!(ov.validator_registration_batch_size, Some(10));
        assert_eq!(ov.validator_registration_batch_delay, Some(20));
        assert_eq!(ov.validators_config, Some(PathBuf::from("/validators.toml")));
        assert_eq!(ov.beacon_max_body_bytes, Some(1024));
    }

    #[test]
    fn test_boolean_flags_absent_yield_none_not_some_false() {
        let cli = Cli::try_parse_from(["rvc", "start"]).expect("default start should parse");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let ov = CliOverrides::from(*args);

        assert_eq!(ov.init_slashing_db, None);
        assert_eq!(ov.allow_unsupported_fork, None);
        assert_eq!(ov.doppelganger_detection, None);
        assert_eq!(ov.keymanager_enabled, None);
        assert_eq!(ov.secret_provider_strict, None);
        assert_eq!(ov.allow_insecure_remote_signer, None);
        assert_eq!(ov.disable_attesting, None);
        assert_eq!(ov.disable_keystore_locking, None);
        assert_eq!(ov.proposer_config_url_insecure, None);
        assert_eq!(ov.monitoring_endpoint_insecure, None);
        assert_eq!(ov.logfile_compress, None);
        // RF5-15: no default_value_t — absent flag yields None (not Some(0.01)).
        assert_eq!(ov.tracing_sample_rate, None);
        // ADR-009 / ARCH-6b: former clap-default fields are Option; absent → None.
        assert_eq!(ov.metrics_address, None);
        assert_eq!(ov.metrics_port, None);
        assert_eq!(ov.grpc_port, None);
        assert_eq!(ov.grpc_address, None);
        assert_eq!(ov.log_level, None);
        assert_eq!(ov.tracing_exporter, None);
        assert_eq!(ov.keymanager_body_limit, None);
        assert_eq!(ov.slashed_validators_action, None);
        assert_eq!(ov.beacon_max_body_bytes, None);
    }

    /// ADR-009: TOML values must survive when the matching clap flag is absent.
    /// Before ARCH-6b, clap `default_value` + unconditional `Some(...)` forced 8080 over 9090.
    #[test]
    fn a_toml_metrics_port_survives_when_the_flag_is_absent() {
        use rvc::config::Config;
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
metrics_port = 9090
grpc_port = 60051
keymanager_body_limit = 2048
beacon_max_body_bytes = 1024
log_level = "debug"
metrics_address = "0.0.0.0"
grpc_address = "0.0.0.0"
tracing_exporter = "gcp"
slashed_validators_action = "shutdown"
"#
        )
        .unwrap();

        let cli = Cli::try_parse_from(["rvc", "start"]).expect("default start should parse");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let ov = CliOverrides::from(*args);
        let mut cfg = Config::from_file(file.path()).unwrap();
        cfg.merge_with_cli(&ov);

        assert_eq!(
            cfg.metrics_port, 9090,
            "TOML metrics_port must not be clobbered by clap default"
        );
        assert_eq!(cfg.grpc_port, 60051, "TOML grpc_port must not be clobbered by clap default");
        assert_eq!(
            cfg.keymanager.body_limit, 2048,
            "TOML keymanager_body_limit must not be clobbered by clap default"
        );
        assert_eq!(
            cfg.beacon_max_body_bytes, 1024,
            "TOML beacon_max_body_bytes must not be clobbered by clap default"
        );
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(
            cfg.metrics_address,
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            "TOML metrics_address must not be clobbered"
        );
        assert_eq!(cfg.grpc_address, "0.0.0.0");
        assert_eq!(cfg.tracing.exporter, TracingExporter::Gcp);
        assert_eq!(cfg.slashed_validators_action, SlashedAction::Shutdown);
    }

    /// Explicit CLI flags still beat TOML (precedence CLI > file).
    #[test]
    fn an_explicit_flag_still_wins_over_the_toml() {
        use rvc::config::Config;
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
metrics_port = 9090
grpc_port = 60051
"#
        )
        .unwrap();

        let cli =
            Cli::try_parse_from(["rvc", "start", "--metrics-port", "7000", "--grpc-port", "7001"])
                .expect("argv should parse");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let ov = CliOverrides::from(*args);
        let mut cfg = Config::from_file(file.path()).unwrap();
        cfg.merge_with_cli(&ov);

        assert_eq!(cfg.metrics_port, 7000);
        assert_eq!(cfg.grpc_port, 7001);
    }

    #[test]
    fn test_clap_groups_mirror_config_sections() {
        // Each RF5-12 nested config group has a matching clap Args group with
        // the operator-facing flag names (not the nested TOML field names).
        let groups: &[(&str, &[&str])] = &[
            ("LoggingArgs", &["--log-level", "--logfile", "--logfile-max-size"]),
            ("TracingArgs", &["--tracing-endpoint", "--tracing-exporter", "--tracing-sample-rate"]),
            (
                "KeymanagerArgs",
                &["--keymanager-enabled", "--keymanager-address", "--remote-signer-url"],
            ),
            (
                "GrpcSignerArgs",
                &[
                    "--grpc-signer-url",
                    "--grpc-signer-tls-cert",
                    "--grpc-signer-tls-key",
                    "--grpc-signer-tls-ca-cert",
                ],
            ),
            ("ProposerArgs", &["--proposer-nodes", "--proposer-config-url", "--broadcast"]),
            ("MonitoringArgs", &["--monitoring-endpoint", "--monitoring-interval"]),
            (
                "BuilderArgs",
                &[
                    "--builder-circuit-breaker-consecutive-limit",
                    "--builder-circuit-breaker-epoch-limit",
                ],
            ),
            ("SlashingArgs", &["--slashing-db-path", "--init-slashing-db"]),
            ("BeaconArgs", &["--beacon-url", "--beacon-nodes", "--beacon-max-body-bytes"]),
        ];

        let mut cmd = Cli::command();
        let start = cmd.find_subcommand_mut("start").expect("start");
        let help = start.render_long_help().to_string();
        for (group, flags) in groups {
            for flag in *flags {
                assert!(help.contains(flag), "{group} flag {flag} missing from start help");
            }
        }

        // Structural presence: parse with one flag from each group.
        let cli = Cli::try_parse_from([
            "rvc",
            "start",
            "--beacon-url",
            "http://localhost:5052",
            "--logfile",
            "/tmp/rvc.log",
            "--tracing-endpoint",
            "http://localhost:4318",
            "--keymanager-enabled",
            "--grpc-signer-url",
            "https://s:1",
            "--proposer-config-file",
            "/pc.toml",
            "--monitoring-endpoint",
            "https://m",
            "--builder-circuit-breaker-consecutive-limit",
            "1",
            "--slashing-db-path",
            "/s.db",
        ])
        .expect("group flags should parse together");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        assert!(args.beacon.beacon_url.is_some());
        assert!(args.logging.logfile.is_some());
        assert!(args.tracing.endpoint.is_some());
        assert_eq!(args.keymanager.enabled, Some(true));
        assert!(args.grpc_signer.url.is_some());
        assert!(args.proposer.proposer_config_file.is_some());
        assert!(args.monitoring.endpoint.is_some());
        assert!(args.builder.builder_circuit_breaker_consecutive_limit.is_some());
        assert!(args.slashing.slashing_db_path.is_some());
    }

    #[test]
    fn test_no_keymanager_and_keymanager_enabled_conflict() {
        let err = match Cli::try_parse_from([
            "rvc",
            "start",
            "--keymanager-enabled",
            "--no-keymanager",
        ]) {
            Ok(_) => panic!("flags must conflict"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be used with") || msg.contains("conflict"),
            "unexpected conflict message: {msg}"
        );
    }

    #[test]
    fn test_large_enum_variant_allow_removed() {
        // Commands::Start is now a single StartArgs field; the allow attribute
        // must not reappear on the Commands enum definition.
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli.rs"));
        let commands_idx = src.find("pub enum Commands").expect("Commands enum");
        let after = &src[commands_idx..];
        let allow_nearby = src[..commands_idx]
            .lines()
            .rev()
            .take(5)
            .any(|l| l.contains("allow(clippy::large_enum_variant)"));
        assert!(
            !allow_nearby,
            "#[allow(clippy::large_enum_variant)] must be removed from Commands"
        );
        assert!(
            after.contains("Start(Box<StartArgs>)"),
            "Commands::Start must wrap Box<StartArgs> (keeps clippy size clean)"
        );
    }
}
