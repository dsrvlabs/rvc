//! rvc - Rust Validator Client
//!
//! Main entry point for the validator client binary.

mod commands;

use std::path::PathBuf;

use bn_manager::BeaconNodeClient;
use clap::{Parser, Subcommand};
use crypto::PublicKey;
use metrics::{new_health_status, serve_metrics_with_health, SharedHealthStatus};
use rvc::config::{CliOverrides, Config, Network, ServiceBuilder};
use rvc::duty_tracker::DutyTrackerService;
use rvc::startup;
use rvc::DutyTrackerServer;
use timing::SlotClock;
use tonic::transport::Server;
use tracing::{error, info, warn};

const DEFAULT_GRPC_ADDRESS: &str = "127.0.0.1";
const DEFAULT_GRPC_PORT: u16 = 50051;
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

        /// Port for the metrics HTTP server
        #[arg(long, default_value_t = DEFAULT_METRICS_PORT)]
        metrics_port: u16,

        /// Port for the gRPC server
        #[arg(long, default_value_t = DEFAULT_GRPC_PORT)]
        grpc_port: u16,

        /// Bind address for the gRPC server
        #[arg(long, default_value = DEFAULT_GRPC_ADDRESS)]
        grpc_address: String,

        /// Network preset (mainnet, goerli, sepolia, holesky, custom)
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

        /// Enable doppelganger detection (default: enabled)
        #[arg(long, default_value_t = true)]
        doppelganger_detection: bool,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
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

        /// Network preset (mainnet, goerli, sepolia, holesky, custom)
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

    match cli.command {
        Commands::Start {
            config,
            beacon_url,
            beacon_nodes,
            keystore_path,
            password_file,
            slashing_db_path,
            metrics_port,
            grpc_port,
            grpc_address,
            network,
            genesis_time,
            genesis_validators_root,
            graffiti,
            doppelganger_detection,
            log_level,
        } => {
            init_logging(&log_level);

            let cli_overrides = CliOverrides {
                beacon_url,
                beacon_nodes,
                keystore_path,
                password_file,
                slashing_db_path,
                metrics_port: Some(metrics_port),
                grpc_port: Some(grpc_port),
                grpc_address: Some(grpc_address),
                network: network.and_then(|n| n.parse::<Network>().ok()),
                genesis_time,
                genesis_validators_root,
                graffiti,
                log_level: Some(log_level),
                doppelganger_detection: Some(doppelganger_detection),
            };

            let mut cfg = load_config(config)?;
            cfg.merge_with_cli(&cli_overrides);

            if let Err(e) = cfg.validate() {
                error!("Configuration validation failed: {}", e);
                return Err(e.into());
            }

            run_validator(cfg).await?;
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
            init_logging(&log_level);

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

fn init_logging(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::fmt().with_env_filter(filter).init();
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

async fn run_validator(config: Config) -> anyhow::Result<()> {
    info!(
        beacon_url = %config.beacon_url,
        beacon_nodes = ?config.effective_beacon_nodes(),
        network = %config.network,
        metrics_port = config.metrics_port,
        grpc_address = %config.grpc_address,
        grpc_port = config.grpc_port,
        doppelganger_detection = config.doppelganger_detection,
        "Starting validator client"
    );

    let health_status = new_health_status();

    let grpc_port = config.grpc_port;
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
        std::process::exit(e.exit_code());
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
        std::process::exit(e.exit_code());
    }

    let genesis_validators_root = match builder.parse_genesis_validators_root() {
        Ok(root) => root,
        Err(e) => {
            error!("Failed to parse genesis validators root: {}", e);
            return Err(e.into());
        }
    };

    // Step 5: Check sync status
    startup::check_sync_status(bn_manager.as_ref()).await;

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

    let pubkey_map = builder.build_pubkey_map(&key_manager);

    // Resolve validator indices using BnManager (via trait)
    let beacon_for_resolve: &dyn BeaconNodeClient = bn_manager.as_ref();
    let validator_indices = resolve_validator_indices(beacon_for_resolve, &pubkey_map).await;

    // Step 6: Doppelganger detection (if enabled)
    if doppelganger_enabled && !pubkey_map.is_empty() {
        let doppelganger_service =
            builder.build_doppelganger_service(beacon_client.clone(), slashing_db.clone());

        let pubkeys: Vec<String> = pubkey_map.keys().cloned().collect();
        let validator_index_map: std::collections::HashMap<String, String> = pubkey_map
            .keys()
            .zip(validator_indices.iter())
            .map(|(pk, idx)| (pk.clone(), idx.clone()))
            .collect();

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
                warn!(error = %e, "Could not determine current epoch for doppelganger detection, skipping");
                0
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
                    info!(safe_count = safe_validators.len(), "Doppelganger detection complete");
                }
                Err(e) => {
                    error!("Doppelganger detection failed: {}", e);
                    std::process::exit(e.exit_code());
                }
            }
        }
    } else if !doppelganger_enabled {
        warn!("Doppelganger detection is disabled");
    }

    // Step 7: Build remaining services
    let signer = builder.build_signer(key_manager.clone(), slashing_db.clone());
    let propagator = builder.build_propagator(beacon_client.clone());
    let validator_store = builder.build_validator_store();

    let beacon: std::sync::Arc<dyn BeaconNodeClient> = bn_manager;
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

    let orchestrator_config =
        builder.build_orchestrator_config(genesis_validators_root, fork_schedule);

    let block_beacon =
        std::sync::Arc::new(rvc::beacon_adapter::BeaconBlockAdapter(beacon_client.clone()));

    // Step 8: Start main duty loop
    let (mut orchestrator, orchestrator_handle) = rvc::orchestrator::DutyOrchestrator::new(
        slot_clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
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

    info!(port = metrics_port, "Starting metrics server");
    let metrics_handle =
        tokio::spawn(serve_metrics_with_health(metrics_port, health_status.clone()));

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
    orchestrator_handle.shutdown();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
) -> Vec<String> {
    if pubkey_map.is_empty() {
        return Vec::new();
    }

    let pubkeys: Vec<String> = pubkey_map.keys().cloned().collect();
    match beacon_client.get_validators(&pubkeys).await {
        Ok(response) => {
            let indices: Vec<String> = response.data.iter().map(|v| v.index.clone()).collect();
            if indices.len() < pubkeys.len() {
                warn!(
                    resolved = indices.len(),
                    total = pubkeys.len(),
                    "Some validator public keys could not be resolved to indices"
                );
            }
            info!(count = indices.len(), "Resolved validator indices");
            indices
        }
        Err(e) => {
            error!("Failed to resolve validator indices from beacon node: {}", e);
            Vec::new()
        }
    }
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
