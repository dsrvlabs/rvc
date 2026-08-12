//! Bootstrap phase: metrics, monitoring, and proposer-config background tasks.
//!
//! Extracted from the former `run_validator` tail so the ISSUE-4.10 metrics bind
//! gate and task cancel/drain sequence can be unit-tested without the full
//! startup chain.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use metrics::{serve_metrics_with_health, SharedHealthStatus};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use validator_store::ValidatorStore;

use super::BootstrapError;
use crate::config::{redact_url, Config};
use crate::orchestrator::PubkeyMap;

/// Env var that opts in to non-loopback metrics binds (ISSUE-4.10 / L-10).
pub const METRICS_ALLOW_NON_LOOPBACK_ENV: &str = "RVC_METRICS_ALLOW_NON_LOOPBACK";

/// Timeout used when draining the metrics server after abort on shutdown.
pub const METRICS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Handles for background tasks spawned after services are ready.
///
/// Owned by [`super::run`]; drained in a fixed order on shutdown.
pub struct BackgroundTasks {
    /// Metrics HTTP server task (`serve_metrics_with_health`).
    pub metrics_handle: JoinHandle<Result<(), std::io::Error>>,
}

/// Enforce the ISSUE-4.10 non-loopback metrics bind gate.
///
/// Loopback binds pass silently. Non-loopback binds require
/// `RVC_METRICS_ALLOW_NON_LOOPBACK=true`. Uses `InsecureGate::with_predicate`
/// with a constant-true predicate so the env var alone decides the outcome
/// (see comment preserved from the binary).
pub fn check_metrics_bind_gate(metrics_address: IpAddr) -> Result<(), BootstrapError> {
    if metrics_address.is_loopback() {
        return Ok(());
    }

    // The predicate is constant-true here: the bind is already known to
    // be non-loopback, so the env var alone determines the outcome (the
    // InsecureGate `new()` constructor would set predicate=is_loopback,
    // which is false at this point and would refuse even with the env
    // var set; with_predicate keeps the env-var-only contract).
    let metrics_gate = crypto::insecure::InsecureGate::with_predicate(
        METRICS_ALLOW_NON_LOOPBACK_ENV,
        crypto::insecure::InsecureMode::default(),
        || true,
    );
    if let Err(e) = metrics_gate.check() {
        error!(
            addr = %metrics_address,
            error = %e,
            "Refusing to start metrics server on non-loopback address (ISSUE-4.10 / L-10)"
        );
        return Err(BootstrapError::MetricsBind(e));
    }
    warn!(
        addr = %metrics_address,
        "Metrics server is bound to a non-loopback address (RVC_METRICS_ALLOW_NON_LOOPBACK=true); \
         this exposes metrics over the network"
    );
    Ok(())
}

/// Live validator counts for the monitoring push.
///
/// Returns `(total_loaded, active_enabled)`:
/// - element 0 = keys currently loaded in [`PubkeyMap`]
/// - element 1 = signing-enabled validators in [`ValidatorStore`]
///
/// Reads are sequential (map guard dropped before store access) so the two
/// locks are never held nested. The pair is a **best-effort, non-atomic
/// snapshot**: a monitoring tick can briefly observe `active > total` (e.g.
/// DELETE removes the map entry before the store entry). Operational
/// telemetry only — not a transactional inventory; accepted residual.
fn live_monitoring_counts(pubkey_map: &PubkeyMap, validator_store: &ValidatorStore) -> (u32, u32) {
    let total = pubkey_map.read().len() as u32;
    let active = validator_store.list_enabled_pubkeys().len() as u32;
    (total, active)
}

/// Spawn metrics server, optional monitoring push, and optional proposer-config
/// refresh. Callers must hold [`BackgroundTasks`] until graceful shutdown.
///
/// Tasks that take `shutdown` exit when the token is cancelled. The metrics
/// server is aborted and awaited with [`METRICS_SHUTDOWN_TIMEOUT`] via
/// [`BackgroundTasks::shutdown`].
///
/// `pubkey_map` and `validator_store` are captured by the monitoring push so
/// each interval reports live totals (not a boot-time constant).
pub fn spawn_background_tasks(
    config: &Config,
    health_status: SharedHealthStatus,
    shutdown: &CancellationToken,
    pubkey_map: PubkeyMap,
    validator_store: Arc<ValidatorStore>,
) -> Result<BackgroundTasks, BootstrapError> {
    let metrics_address = config.metrics_address;
    let metrics_port = config.metrics_port;

    check_metrics_bind_gate(metrics_address)?;

    info!(addr = %metrics_address, port = metrics_port, "Starting metrics server");
    let metrics_handle =
        tokio::spawn(serve_metrics_with_health(metrics_address, metrics_port, health_status));

    // Spawn monitoring push task if endpoint is configured (T3.6)
    if let Some(ref monitoring_endpoint) = config.monitoring.endpoint {
        let monitoring_config = crate::background_tasks::monitoring::MonitoringConfig {
            endpoint: monitoring_endpoint.clone(),
            interval: Duration::from_secs(config.monitoring.interval),
            insecure: config.monitoring.endpoint_insecure,
        };
        let monitoring_shutdown = shutdown.clone();
        // Clone so the proposer-config apply path can still own `validator_store`.
        let store_for_monitoring = Arc::clone(&validator_store);
        info!(
            endpoint = %redact_url(monitoring_endpoint),
            interval_secs = config.monitoring.interval,
            "Starting monitoring push task"
        );
        // Element 0 = total loaded; element 1 = active/enabled (see live_monitoring_counts).
        tokio::spawn(crate::background_tasks::monitoring::start_monitoring_push(
            monitoring_config,
            monitoring_shutdown,
            move || live_monitoring_counts(&pubkey_map, &store_for_monitoring),
        ));
    }

    // Spawn proposer config URL refresh task if configured (T3.12)
    if let Some(ref proposer_config_url) = config.proposer_config.url {
        let settings = crate::background_tasks::config_url::ProposerConfigUrlSettings {
            url: proposer_config_url.clone(),
            refresh_interval: Duration::from_secs(config.proposer_config.refresh_interval),
            token: config.proposer_config.url_token.clone(),
            insecure: config.proposer_config.url_insecure,
        };
        let config_refresh_shutdown = shutdown.clone();
        info!(
            url = %redact_url(proposer_config_url),
            refresh_interval_secs = config.proposer_config.refresh_interval,
            "Starting proposer config URL refresh task"
        );
        // ARCH-4b: map URL entries into ValidatorStore (ARCH-4a); malformed → warn + leave previous.
        tokio::spawn(crate::background_tasks::config_url::start_proposer_config_refresh(
            settings,
            config_refresh_shutdown,
            move |updates, default_update| {
                crate::background_tasks::config_url::apply_proposer_config_updates(
                    &validator_store,
                    updates,
                    default_update,
                );
            },
        ));
    }

    Ok(BackgroundTasks { metrics_handle })
}

impl BackgroundTasks {
    /// Abort the metrics server and wait up to [`METRICS_SHUTDOWN_TIMEOUT`].
    pub async fn shutdown(self) {
        self.metrics_handle.abort();
        let _ = tokio::time::timeout(METRICS_SHUTDOWN_TIMEOUT, async {
            self.metrics_handle.await.ok()
        })
        .await;
    }
}

#[cfg(test)]
// RF5-10: env-var contract tests use set_var/remove_var under a lock.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
    use keymanager_api::traits::KeystoreManager;
    use tempfile::TempDir;
    use tokio::sync::watch;
    use validator_store::ValidatorConfig;

    use crate::keymanager_adapters::KeystoreManagerAdapter;

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_env_var<F: FnOnce()>(value: Option<&str>, f: F) {
        let _guard = env_lock();
        let prev = std::env::var(METRICS_ALLOW_NON_LOOPBACK_ENV).ok();
        // SAFETY: env mutations serialized by ENV_LOCK.
        unsafe {
            match value {
                Some(v) => std::env::set_var(METRICS_ALLOW_NON_LOOPBACK_ENV, v),
                None => std::env::remove_var(METRICS_ALLOW_NON_LOOPBACK_ENV),
            }
        }
        f();
        unsafe {
            match prev {
                Some(p) => std::env::set_var(METRICS_ALLOW_NON_LOOPBACK_ENV, p),
                None => std::env::remove_var(METRICS_ALLOW_NON_LOOPBACK_ENV),
            }
        }
    }

    fn empty_pubkey_map() -> PubkeyMap {
        Arc::new(parking_lot::RwLock::new(HashMap::new()))
    }

    fn empty_validator_store() -> Arc<ValidatorStore> {
        Arc::new(ValidatorStore::new([0u8; 20], 30_000_000))
    }

    fn encrypt_test_keystore(sk: &SecretKey) -> String {
        let keystore = crypto::Keystore::encrypt(
            sk,
            b"testpass",
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        serde_json::to_string(&keystore).expect("serialize keystore")
    }

    #[test]
    fn test_spawn_background_tasks_refuses_non_loopback_metrics_bind_without_env_optin() {
        with_env_var(None, || {
            let err = check_metrics_bind_gate(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
                .expect_err("non-loopback without env must refuse");
            let msg = err.to_string();
            assert!(
                msg.contains(METRICS_ALLOW_NON_LOOPBACK_ENV),
                "error must name the opt-in env var, got: {msg}"
            );
        });
    }

    #[test]
    fn test_metrics_bind_gate_allows_loopback_without_env() {
        with_env_var(None, || {
            check_metrics_bind_gate(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .expect("loopback must pass without env opt-in");
        });
    }

    #[test]
    fn test_metrics_bind_gate_allows_non_loopback_with_env_optin() {
        with_env_var(Some("true"), || {
            check_metrics_bind_gate(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
                .expect("non-loopback with env must pass");
        });
    }

    #[tokio::test]
    async fn test_spawn_background_tasks_all_tasks_cancel_on_shutdown() {
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0, // OS-assigned; serve binds ephemeral
            // monitoring / proposer_config left at nested defaults (disabled)
            ..Config::default()
        };
        let health = metrics::new_health_status();
        let shutdown = CancellationToken::new();

        let tasks = spawn_background_tasks(
            &config,
            health,
            &shutdown,
            empty_pubkey_map(),
            empty_validator_store(),
        )
        .expect("loopback metrics spawn");

        // Give the server a moment to start, then shut down.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.cancel();
        tasks.shutdown().await;
        // If we reach here without hang, cancel/drain succeeded.
    }

    #[tokio::test]
    async fn test_shutdown_drains_metrics_server_before_returning() {
        let config = Config {
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 0,
            ..Config::default()
        };
        let health = metrics::new_health_status();
        let shutdown = CancellationToken::new();
        let tasks = spawn_background_tasks(
            &config,
            health,
            &shutdown,
            empty_pubkey_map(),
            empty_validator_store(),
        )
        .expect("spawn");

        let start = std::time::Instant::now();
        tasks.shutdown().await;
        // Drain is bounded by METRICS_SHUTDOWN_TIMEOUT (2s); abort is near-instant.
        assert!(
            start.elapsed() < METRICS_SHUTDOWN_TIMEOUT + Duration::from_millis(500),
            "metrics drain exceeded shutdown bound"
        );
    }

    #[test]
    fn monitoring_count_reflects_a_keymanager_import() {
        let pubkey_map = empty_pubkey_map();
        let validator_store = empty_validator_store();
        let count = || live_monitoring_counts(&pubkey_map, &validator_store);

        assert_eq!(count(), (0, 0));

        let dir = TempDir::new().unwrap();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let (tx, _rx) = watch::channel(0u64);
        let adapter = KeystoreManagerAdapter::new(
            dir.path().to_path_buf(),
            composite,
            pubkey_map.clone(),
            tx,
        );

        let sk = SecretKey::generate();
        let keystore_json = encrypt_test_keystore(&sk);
        adapter.import_keystore(&keystore_json, "testpass").unwrap();

        let (total, _active) = count();
        assert_eq!(total, 1, "keymanager import must bump live total loaded count");
    }

    #[test]
    fn monitoring_count_reflects_a_delete() {
        let pubkey_map = empty_pubkey_map();
        let validator_store = empty_validator_store();
        let count = || live_monitoring_counts(&pubkey_map, &validator_store);

        let dir = TempDir::new().unwrap();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let (tx, _rx) = watch::channel(0u64);
        let adapter = KeystoreManagerAdapter::new(
            dir.path().to_path_buf(),
            composite,
            pubkey_map.clone(),
            tx,
        );

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let keystore_json = encrypt_test_keystore(&sk);
        adapter.import_keystore(&keystore_json, "testpass").unwrap();
        assert_eq!(count().0, 1);

        assert!(adapter.delete_keystore(&pk_bytes).unwrap());
        assert_eq!(count().0, 0, "keymanager delete must drop live total loaded count");
    }

    #[test]
    fn total_and_active_are_distinct_when_a_validator_is_disabled() {
        let pubkey_map = empty_pubkey_map();
        let validator_store = empty_validator_store();

        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk1 = sk1.public_key().to_bytes();
        let pk2 = sk2.public_key().to_bytes();

        pubkey_map.write().insert(pk1, sk1.public_key());
        pubkey_map.write().insert(pk2, sk2.public_key());
        validator_store.add_validator(ValidatorConfig::new(pk1));
        validator_store.add_validator(ValidatorConfig::new(pk2));

        assert_eq!(live_monitoring_counts(&pubkey_map, &validator_store), (2, 2));

        validator_store.set_enabled(&pk1, false);
        assert_eq!(
            live_monitoring_counts(&pubkey_map, &validator_store),
            (2, 1),
            "disabled validator must reduce active without changing total loaded"
        );
    }
}
