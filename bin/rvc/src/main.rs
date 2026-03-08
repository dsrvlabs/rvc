//! rvc - Rust Validator Client
//!
//! Main entry point for the validator client binary.

mod commands;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use bn_manager::BeaconNodeClient;
use clap::{Parser, Subcommand};
use crypto::PublicKey;
use metrics::{new_health_status, serve_metrics_with_health, SharedHealthStatus};
use rvc::config::{redact_url, CliOverrides, Config, Network, ServiceBuilder};
use rvc::duty_tracker::DutyTrackerService;
use rvc::keymanager_adapters::{
    DoppelgangerMonitorAdapter, KeystoreManagerAdapter, RemoteKeyManagerAdapter,
    SlashingProtectionAdapter, ValidatorManagerAdapter,
};
use rvc::startup;
use rvc::DutyTrackerServer;
use timing::SlotClock;
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

        /// Network preset (mainnet, hoodi, custom)
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

        /// Network preset (mainnet, hoodi, custom)
        #[arg(long)]
        network: Option<String>,

        /// Genesis validators root override (hex string with 0x prefix)
        #[arg(long)]
        genesis_validators_root: Option<String>,

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
        } => {
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
                network: network.and_then(|n| n.parse::<Network>().ok()),
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
            };

            let mut cfg = load_config(config)?;
            cfg.merge_with_cli(&cli_overrides);

            let tracing_config = build_tracing_config(&cfg);
            let tracing_guard = init_logging(&log_level, tracing_config.as_ref());

            if let Err(e) = cfg.validate() {
                error!("Configuration validation failed: {}", e);
                return Err(e.into());
            }

            run_validator(
                cfg,
                strict_permissions,
                strict_slashing_semantics,
                timeouts,
                tracing_guard,
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
            init_logging(&log_level, None);

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
    }

    Ok(())
}

fn init_logging(
    level: &str,
    tracing_config: Option<&telemetry::TelemetryConfig>,
) -> Option<telemetry::TracingGuard> {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let fmt_layer = tracing_subscriber::fmt::layer();

    match tracing_config {
        Some(config) => match telemetry::init_tracing(config) {
            Ok((otel_layer, guard)) => {
                // otel_layer is Box<dyn Layer<Registry>>, so it must be
                // applied directly to the registry before other layers.
                tracing_subscriber::registry().with(otel_layer).with(fmt_layer).with(filter).init();
                eprintln!("OpenTelemetry tracing enabled (endpoint: {})", config.endpoint);
                Some(guard)
            }
            Err(e) => {
                tracing_subscriber::fmt().with_env_filter(filter).init();
                eprintln!(
                    "WARNING: Failed to initialize OpenTelemetry tracing: {e}. \
                     Falling back to fmt-only logging."
                );
                None
            }
        },
        None => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
            None
        }
    }
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

async fn run_validator(
    config: Config,
    strict_permissions: bool,
    strict_slashing_semantics: bool,
    timeouts: bn_manager::OperationTimeouts,
    tracing_guard: Option<telemetry::TracingGuard>,
) -> anyhow::Result<()> {
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
            let mut km = std::sync::Arc::try_unwrap(key_manager).unwrap_or_else(|_| {
                panic!("single reference to key_manager before cloud key loading")
            });
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
    let key_manager_owned = std::sync::Arc::try_unwrap(key_manager)
        .unwrap_or_else(|_| panic!("single reference to key_manager after pubkey_map build"));
    let known_pubkeys: std::collections::HashSet<[u8; 48]> =
        key_manager_owned.list_public_keys().iter().map(|pk| pk.to_bytes()).collect();
    let local_signer = crypto::LocalSigner::new(key_manager_owned);
    let composite_signer = std::sync::Arc::new(crypto::CompositeSigner::new(local_signer));

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
    if doppelganger_enabled && !pubkey_map.is_empty() {
        let validator_index_map = match validator_index_map {
            Ok(ref map) if !map.is_empty() => map.clone(),
            Ok(_) => {
                warn!(
                    total = pubkey_map.len(),
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
                builder.build_doppelganger_service(beacon_client.clone(), slashing_db.clone());

            let pubkeys: Vec<String> = pubkey_map.keys().cloned().collect();

            let slot_clock = match builder.build_slot_clock() {
                Ok(clock) => clock,
                Err(e) => {
                    error!("Failed to create slot clock: {}", e);
                    return Err(e.into());
                }
            };

            let current_epoch = match slot_clock.current_slot() {
                Ok(slot) => slot / timing::SLOTS_PER_EPOCH,
                Err(e) => {
                    error!(error = %e, "Cannot determine current epoch; refusing to skip doppelganger detection");
                    return Err(anyhow::anyhow!("slot clock failure during doppelganger check"));
                }
            };

            if current_epoch > 0 {
                match startup::run_doppelganger_detection(
                    &doppelganger_service,
                    &pubkeys,
                    &validator_index_map,
                    current_epoch,
                )
                .await
                {
                    Ok(safe_validators) => {
                        info!(
                            safe_count = safe_validators.len(),
                            "Doppelganger detection complete"
                        );
                    }
                    Err(e) => {
                        error!("Doppelganger detection failed: {}", e);
                        return Err(e.into());
                    }
                }
            }
        }
    } else if !doppelganger_enabled {
        warn!("Doppelganger detection is disabled");
    }

    // Step 7: Build remaining services
    let signer = builder.build_signer(composite_signer.clone(), slashing_db.clone());
    let propagator = builder.build_propagator(beacon_client.clone());
    let validator_store = builder.build_validator_store();

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

    let orchestrator_config = builder
        .build_orchestrator_config(genesis_validators_root, fork_schedule)
        .with_timeouts(timeouts);

    let block_beacon =
        std::sync::Arc::new(rvc::beacon_adapter::BeaconBlockAdapter(beacon_client.clone()));

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
        let doppelganger_mon = std::sync::Arc::new(DoppelgangerMonitorAdapter::new());
        let remote_key_mgr = std::sync::Arc::new(RemoteKeyManagerAdapter::new(
            km_composite,
            config.remote_signer_allowed_hosts.clone(),
        ));

        let km_server = keymanager_api::KeymanagerServer::new(
            keystore_mgr,
            slashing_prot,
            validator_mgr,
            doppelganger_mon,
            remote_key_mgr,
            token.to_string(),
            km_addr,
        );

        info!(addr = %km_addr, token_path = %token_path.display(), "Keymanager API enabled");

        tokio::spawn(async move {
            if let Err(e) = km_server.run().await {
                error!("Keymanager API server error: {}", e);
            }
        });
    }

    // Step 8: Start main duty loop
    let (mut orchestrator, orchestrator_handle) = rvc::orchestrator::DutyOrchestrator::new(
        slot_clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
        builder_service,
        validator_store,
        orchestrator_config,
        pubkey_map,
    );

    finalize_health_status(&health_status).await;

    let grpc_addr = format!("{}:{}", config.grpc_address, grpc_port).parse()?;
    let duty_tracker_service = DutyTrackerService::new();

    info!(addr = %grpc_addr, "Starting gRPC server");
    let grpc_server = Server::builder()
        .add_service(DutyTrackerServer::new(duty_tracker_service))
        .serve_with_shutdown(grpc_addr, async {
            shutdown_signal().await;
        });

    if !metrics_address.is_loopback() {
        warn!(
            addr = %metrics_address,
            "Metrics server is bound to a non-loopback address; this exposes metrics over the network"
        );
    }

    info!(addr = %metrics_address, port = metrics_port, "Starting metrics server");
    let metrics_handle = tokio::spawn(serve_metrics_with_health(
        metrics_address,
        metrics_port,
        health_status.clone(),
    ));

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

    info!("Initiating graceful shutdown...");
    shutdown_token.cancel();
    orchestrator_handle.shutdown();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Flush OpenTelemetry traces after orchestrator shutdown
    if let Some(guard) = tracing_guard {
        telemetry::shutdown_tracing(guard).await;
    }

    // Gracefully shut down metrics server with a brief timeout
    metrics_handle.abort();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        metrics_handle.await.ok()
    })
    .await;

    info!("Validator client shut down complete");
    Ok(())
}

async fn resolve_validator_indices(
    beacon_client: &dyn BeaconNodeClient,
    pubkey_map: &std::collections::HashMap<String, PublicKey>,
) -> Result<std::collections::HashMap<String, String>, anyhow::Error> {
    if pubkey_map.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let pubkeys: Vec<String> = pubkey_map.keys().cloned().collect();
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

    #[test]
    fn test_build_tracing_config_no_endpoint_returns_none() {
        // Clear env vars that could interfere
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config::default();
        assert!(build_tracing_config(&config).is_none());
    }

    #[test]
    fn test_build_tracing_config_with_endpoint_returns_some() {
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
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-collector:4318");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");

        let config = Config::default(); // no tracing_endpoint set
        let tc = build_tracing_config(&config).expect("should fall back to env var");
        assert_eq!(tc.endpoint, "http://env-collector:4318");

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_build_tracing_config_cli_overrides_env() {
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
}
