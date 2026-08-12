//! Full validator-client bootstrap composition.
//!
//! [`run`] is the library entry point for the production Start path: it chains
//! every bootstrap phase, owns the duty-loop `select!`, and performs graceful
//! shutdown (cancel token → orchestrator → metrics drain).

use std::time::Duration;

use bn_manager::OperationTimeouts;
use metrics::{new_health_status, SharedHealthStatus};
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::{error, info, warn};

use super::tasks::{spawn_background_tasks, BackgroundTasks};
use super::{
    build_services, connect_beacon, load_signing_keys, open_slashing_db, wire_signing_enablement,
    BeaconHandles, BootstrapError, EnablementHandles, LoadedKeys, ServiceHandles,
};
use crate::config::{redact_url, Config};
use crate::grpc_health::DutyTrackerService;
use crate::keymanager_adapters::{spawn_keymanager_api, KeymanagerApiDeps};
use crate::startup;
use crate::DutyTrackerServer;

/// Binary-owned flags that are not part of [`Config`].
pub struct RunOptions {
    /// Fail startup on world-readable keystore/password files.
    pub strict_permissions: bool,
    /// Strict slashing-interchange import semantics.
    pub strict_slashing_semantics: bool,
    /// Per-operation BN HTTP timeouts (CLI overrides applied by the binary).
    pub timeouts: OperationTimeouts,
}

/// Compose all bootstrap phases and run until shutdown.
///
/// `shutdown_token` is shared with the binary (e.g. log-reload SIGHUP task) so
/// cancel propagates to every background task. Logging guards stay owned by
/// `main` and drop after this future resolves, flushing pending records last.
///
/// # Errors
///
/// Returns [`BootstrapError`] for phase failures. Keystore-lock contention
/// sets [`BootstrapError::is_keystore_locked`]; the binary maps that to
/// `process::exit` with the startup exit code.
pub async fn run(
    config: Config,
    options: RunOptions,
    shutdown_token: CancellationToken,
) -> Result<(), BootstrapError> {
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

    // Steps 1–2d: open slashing DB, integrity, permissions, keystore lock, denylist.
    let slashing_handles = match open_slashing_db(
        &config,
        options.strict_permissions,
        options.strict_slashing_semantics,
    ) {
        Ok(handles) => {
            update_health_slashing_db(&health_status, true).await;
            handles
        }
        Err(e) if e.is_keystore_locked() => {
            // Match prior binary: hard-exit on lock contention with the startup code.
            std::process::exit(e.exit_code());
        }
        Err(e) => {
            if matches!(e, BootstrapError::Config(_)) {
                update_health_error(&health_status, format!("Slashing DB error: {}", e)).await;
            }
            return Err(e);
        }
    };
    let slashing_db = slashing_handles.db;
    let _keystore_lock_guard = slashing_handles.keystore_lock;
    let deletion_denylist = slashing_handles.denylist;

    // Steps 3–5: beacon client, BnManager, GVR, genesis gate, reachability.
    let beacon_handles =
        match connect_beacon(&config, options.timeouts.clone(), slashing_db.as_ref()).await {
            Ok(handles) => {
                update_health_beacon_connected(&health_status, true).await;
                handles
            }
            Err(e) => {
                if matches!(e, BootstrapError::Config(_)) {
                    update_health_error(&health_status, format!("Beacon client error: {}", e))
                        .await;
                }
                return Err(e);
            }
        };

    // Keystore-dir + secret providers + CompositeSigner + optional gRPC remote.
    let loaded_keys = match load_signing_keys(&config, &deletion_denylist).await {
        Ok(keys) => {
            update_health_validators(&health_status, keys.validator_count).await;
            keys
        }
        Err(e) => {
            if matches!(e, BootstrapError::Config(_)) {
                update_health_error(&health_status, format!("Key load error: {}", e)).await;
            }
            return Err(e);
        }
    };

    // Step 6: SEC-2b/2c enablement + liveness loop + secret-provider refresh.
    let enablement = wire_signing_enablement(
        &config,
        &loaded_keys,
        &beacon_handles,
        std::sync::Arc::clone(&slashing_db),
        std::sync::Arc::clone(&deletion_denylist),
        &shutdown_token,
    )
    .await?;

    // Step 7: remaining services (signer, D-3, fork gate, proposer, toggle).
    let services = build_services(
        &config,
        &loaded_keys,
        &enablement,
        &beacon_handles,
        std::sync::Arc::clone(&slashing_db),
        options.timeouts,
    )
    .await?;

    let BeaconHandles {
        beacon_client,
        bn_manager: _,
        genesis_validators_root,
        genesis_validators_root_hex: _,
        genesis_time: _,
    } = beacon_handles;

    let LoadedKeys {
        composite_signer,
        validator_count: _,
        local_pubkeys: _,
        pubkey_map,
        secret_providers: _,
        grpc_signer: _grpc_remote_signer,
    } = loaded_keys;

    let EnablementHandles {
        signing_enablement: _,
        forward_window_machine,
        epoch_clock,
        pubkey_map: _,
        liveness_task: _liveness_loop_handle,
        pubkey_index,
    } = enablement;

    let ServiceHandles {
        signer,
        validator_store,
        propagator,
        beacon,
        duty_tracker,
        slot_clock,
        orchestrator_config,
        proposer_bn_manager: _,
        block_beacon,
        builder_service,
        attesting_enabled,
    } = services;

    // RF1-06/07: single key-generation watch channel shared by keymanager
    // adapters (tx) and DutyOrchestrator (rx).
    let (key_gen_tx, key_gen_rx) = tokio::sync::watch::channel(0u64);

    // Step 7c: optionally start Keymanager API.
    spawn_keymanager_api(
        &config,
        KeymanagerApiDeps {
            composite_signer: composite_signer.clone(),
            slashing_db: slashing_db.clone(),
            genesis_validators_root,
            validator_store: validator_store.clone(),
            beacon_client: beacon_client.clone(),
            signer: signer.clone(),
            fork_schedule: orchestrator_config.fork_schedule.clone(),
            deletion_denylist: std::sync::Arc::clone(&deletion_denylist),
            attesting_enabled: attesting_enabled.clone(),
            forward_window_machine: forward_window_machine.clone(),
            epoch_clock: std::sync::Arc::clone(&epoch_clock),
            pubkey_map: pubkey_map.clone(),
            key_gen_tx,
        },
    )?;

    // Step 8: duty orchestrator.
    let circuit_breaker = std::sync::Arc::new(signer::CircuitBreakerState::new(
        config.builder_limits.circuit_breaker_consecutive_limit,
        config.builder_limits.circuit_breaker_epoch_limit,
    ));
    info!(
        consecutive_limit = config.builder_limits.circuit_breaker_consecutive_limit,
        epoch_limit = config.builder_limits.circuit_breaker_epoch_limit,
        "Builder circuit breaker configured"
    );

    let validator_count = pubkey_map.read().len();
    let bn_count = config.effective_beacon_nodes().len();
    let (mut orchestrator, orchestrator_handle) =
        crate::orchestrator::DutyOrchestrator::new(crate::orchestrator::OrchestratorDeps {
            clock: slot_clock,
            duty_tracker,
            signer,
            propagator,
            beacon: beacon.clone(),
            block_beacon,
            builder_service,
            validator_store: validator_store.clone(),
            config: orchestrator_config,
            pubkey_map: pubkey_map.clone(),
            pubkey_index,
            key_gen_rx,
            circuit_breaker,
            attesting_enabled: attesting_enabled.clone(),
        });

    // Step 8b: slashing monitor (config already typed — RF5-11).
    {
        let slashed_action = config.slashed_validators_action;

        if slashed_action != crate::slashing_monitor::SlashedAction::None {
            crate::slashing_monitor::spawn(
                beacon.clone(),
                validator_store.clone(),
                slashed_action,
                shutdown_token.clone(),
            );
            info!(action = %slashed_action, "Slashing monitor started");
        }
    }

    finalize_health_status(&health_status).await;

    let grpc_addr = format!("{}:{}", config.grpc_address, config.grpc_port)
        .parse()
        .map_err(|e: std::net::AddrParseError| BootstrapError::InvalidConfig(e.to_string()))?;
    let duty_tracker_service = DutyTrackerService::new();

    info!(addr = %grpc_addr, "Starting gRPC server");
    log_grpc_healthz_deprecation();
    let grpc_server = Server::builder()
        .add_service(DutyTrackerServer::new(duty_tracker_service))
        .serve_with_shutdown(grpc_addr, {
            let token = shutdown_token.clone();
            async move {
                tokio::select! {
                    _ = shutdown_signal() => {}
                    _ = token.cancelled() => {}
                }
            }
        });

    let background: BackgroundTasks =
        spawn_background_tasks(&config, health_status, &shutdown_token, validator_count)?;

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

    // Arm order preserved: gRPC, orchestrator, process signal.
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

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Metrics server drained before returning so logging guards (owned by main)
    // drop last and flush after HTTP work is gone.
    background.shutdown().await;

    info!(uptime_secs = startup_time.elapsed().as_secs(), "Validator client shut down complete");
    Ok(())
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

// Health status update helpers (formerly binary-local). Safe RMW during sequential startup.
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

/// Startup deprecation notice for the gRPC healthz-only server (C8 / ARCH-8).
///
/// Operators should migrate liveness probes to `/livez` and readiness probes to
/// `/readyz` on the metrics HTTP server. Removal is Phase 7 (≥1 release later).
fn log_grpc_healthz_deprecation() {
    warn!(
        "gRPC healthz endpoint is deprecated and will be removed in a future release; \
         migrate liveness probes to /livez and readiness probes to /readyz on the metrics \
         HTTP server (metrics_address / metrics_port)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::duty_tracker::duty_tracker_client::DutyTrackerClient;
    use crate::proto::duty_tracker::HealthzRequest;
    use tokio::net::TcpListener;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn test_startup_warns_that_grpc_healthz_is_deprecated() {
        log_grpc_healthz_deprecation();

        assert!(logs_contain("deprecated"), "expected WARN naming deprecation of gRPC healthz");
        assert!(logs_contain("/livez"), "deprecation WARN must name /livez");
        assert!(logs_contain("/readyz"), "deprecation WARN must name /readyz");
    }

    /// Guard: deprecation must not disable the endpoint it deprecates (C8).
    #[tokio::test]
    async fn test_grpc_healthz_still_serves_after_deprecation_warning() {
        log_grpc_healthz_deprecation();

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");

        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(DutyTrackerServer::new(DutyTrackerService::new()))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .expect("gRPC server");
        });

        let endpoint = format!("http://{addr}");
        let mut client = None;
        for _ in 0..50 {
            match tonic::transport::Endpoint::from_shared(endpoint.clone())
                .expect("endpoint")
                .connect()
                .await
            {
                Ok(channel) => {
                    client = Some(DutyTrackerClient::new(channel));
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let mut client = client.expect("connect to gRPC healthz server");

        let response =
            client.healthz(tonic::Request::new(HealthzRequest {})).await.expect("healthz RPC");
        assert!(response.get_ref().status, "healthz must still report healthy");

        server.abort();
    }
}
