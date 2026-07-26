//! Bootstrap phase: wire signing enablement (forward window, liveness, refresh).
//!
//! Extracted from `bin/rvc` startup Step 6 (SEC-2b/2c): constructs the
//! production [`SigningEnablement`] (fail-closed [`ForwardWindowMachine`] or
//! operator opt-out), spawns the per-slot liveness observation loop, and
//! registers secret-provider refresh with import-strict machine registration.

use std::collections::HashMap;
use std::sync::Arc;

use bn_manager::BeaconNodeClient;
use doppelganger::{ForwardWindowMachine, MonotonicEpochClock, SigningEnablement};
use slashing::SlashingDb;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use super::beacon::BeaconHandles;
use super::keys::LoadedKeys;
use super::BootstrapError;
use crate::config::{Config, ServiceBuilder};
use crate::deletion_denylist::DeletionDenylist;
use crate::liveness_loop::{spawn_liveness_loop, LivenessLoopSpawn};
use crate::orchestrator::PubkeyMap;

/// Handles produced by [`wire_signing_enablement`].
///
/// Held as locals by the binary composition root until a future `run()` moves
/// selected fields into [`super::BootstrapCtx`] (at most three named fields per
/// the growth rule).
pub struct EnablementHandles {
    /// Production signing gate (forward-window machine or operator opt-out).
    pub signing_enablement: Arc<dyn SigningEnablement>,
    /// Same machine as enablement when doppelganger is on; `None` on opt-out.
    /// Keymanager import / refresh call `register_for_import` on this handle.
    pub forward_window_machine: Option<Arc<ForwardWindowMachine>>,
    /// Shared monotonic epoch clock (boot register + keymanager import).
    pub epoch_clock: Arc<MonotonicEpochClock>,
    /// Hex-keyed pubkey map (same `Arc` as [`LoadedKeys::pubkey_map`]).
    pub pubkey_map: PubkeyMap,
    /// Spawned SEC-2c liveness loop; `None` when doppelganger is off or there
    /// are no keys/indices to observe.
    pub liveness_task: Option<LivenessLoopSpawn>,
    /// Resolved validator indices (`0x`-pubkey → numeric index string) for the
    /// duty tracker. Empty when unresolved, no keys, or resolution failed with
    /// doppelganger opted out.
    pub validator_index_map: HashMap<String, String>,
}

/// Construct SEC-2b enablement, spawn the SEC-2c liveness loop, and wire
/// secret-provider refresh (import-strict registration).
///
/// # Behaviour preserved from `run_validator`
///
/// - Fail-closed machine when doppelganger is on; unregistered keys cannot sign.
/// - Operator opt-out yields [`doppelganger::DoppelgangerDisabledByOperator`].
/// - Epoch-0 boot register marks keys Safe (pre-genesis bypass).
/// - Restart-aware safe-skip on **boot** `register` only (local slashing history
///   under this GVR). Do **not** copy a live slashing DB to a second VC.
/// - Dynamically added keys use `register_for_import` (always Pending).
/// - Liveness goes through `bn_manager` (multi-BN failover) and re-resolves
///   indices from `pubkey_map` after import.
///
/// Index resolution failure is fatal only when doppelganger is on and keys are
/// present (same as prior binary behaviour).
pub async fn wire_signing_enablement(
    config: &Config,
    keys: &LoadedKeys,
    beacon: &BeaconHandles,
    slashing_db: Arc<SlashingDb>,
    denylist: Arc<DeletionDenylist>,
    shutdown: &CancellationToken,
) -> Result<EnablementHandles, BootstrapError> {
    let builder = ServiceBuilder::new(config.clone());
    let doppelganger_enabled = config.doppelganger_detection;

    // Shared monotonic epoch clock (M-7) for boot register + keymanager import
    // so NTP cannot compress the window and wall-clock alone cannot force epoch 0.
    let epoch_clock = Arc::new(MonotonicEpochClock::new(beacon.genesis_time));
    let enablement_epoch = epoch_clock.current_epoch();

    // Resolve validator indices (also used by duty tracker after this phase).
    let beacon_for_resolve: &dyn BeaconNodeClient = beacon.bn_manager.as_ref();
    let validator_index_map_result =
        resolve_validator_indices(beacon_for_resolve, &keys.pubkey_map).await;

    // Resolve index map for the liveness loop (fail closed if required and missing).
    let resolved_index_map: HashMap<String, String> =
        if doppelganger_enabled && !keys.pubkey_map.read().is_empty() {
            match validator_index_map_result {
                Ok(ref map) if !map.is_empty() => map.clone(),
                Ok(_) => {
                    warn!(
                        total = keys.pubkey_map.read().len(),
                        "No validator indices resolved; validators may be pending activation. \
                         Forward-window liveness loop will not start (gate stays fail-safe closed \
                         for Pending keys)"
                    );
                    HashMap::new()
                }
                Err(ref e) => {
                    error!("Failed to resolve validator indices: {}", e);
                    return Err(BootstrapError::IndexResolution(e.to_string()));
                }
            }
        } else {
            HashMap::new()
        };

    // Duty-tracker map: keep successful resolution even when doppelganger is off;
    // empty on error (prior binary ignored Err for duty indices).
    let validator_index_map: HashMap<String, String> = match &validator_index_map_result {
        Ok(map) => map.clone(),
        Err(_) => HashMap::new(),
    };

    if enablement_epoch == 0 && doppelganger_enabled {
        info!(
            "Doppelganger detection: pre-genesis (epoch 0) startup — \
             validators will be marked Safe without a monitoring window (boot register)"
        );
    } else if !doppelganger_enabled {
        warn!("Doppelganger detection is disabled");
    }

    // SEC-2b: construct enablement (ForwardWindowMachine or operator opt-out)
    // and hand it to the production SignerService.
    //
    // Restart-aware safe-skip (boot register only): if local slashing history
    // shows a recent attestation under this GVR, the key is marked Safe without
    // network observation. Do NOT copy a live slashing DB to a second VC — that
    // would open a dual-instance fail-open. API import uses register_for_import
    // (always Pending).
    let (signing_enablement, forward_window_machine) = builder.build_signing_enablement(
        Arc::clone(&slashing_db),
        beacon.genesis_validators_root,
        enablement_epoch,
        &keys.pubkey_map,
    );

    // SEC-2c: spawn the per-slot liveness observation loop (sole production mechanism).
    // bn_manager is Arc; clone for the loop and keep the original for later duties.
    // Pass pubkey_map so the loop re-resolves indices after keymanager import /
    // delayed activation (review Finding 3).
    let liveness_task = if doppelganger_enabled {
        spawn_liveness_loop(
            forward_window_machine.clone(),
            Arc::clone(&beacon.bn_manager) as Arc<dyn BeaconNodeClient>,
            &resolved_index_map,
            Some(Arc::clone(&keys.pubkey_map)),
            Arc::clone(&epoch_clock),
            shutdown.clone(),
        )
    } else {
        None
    };

    // Secret-provider refresh: after machine is available, register newly
    // discovered local keys (import-strict) so they are not permanently Unmonitored.
    let refresh_interval = config.secret_provider.refresh_interval.unwrap_or(0);
    if refresh_interval > 0 && !keys.secret_providers.is_empty() {
        let denylist_for_refresh = Arc::clone(&denylist);
        let is_denied: secret_provider::DenylistCheck =
            Arc::new(move |pk: &[u8; 48]| denylist_for_refresh.contains(pk));
        let refresh_service = secret_provider::RefreshService::with_denylist(
            keys.secret_providers.clone(),
            keys.local_pubkeys.clone(),
            Some(is_denied),
            std::time::Duration::from_secs(refresh_interval),
            shutdown.clone(),
        );
        let signer_for_refresh = Arc::clone(&keys.composite_signer);
        let denylist_for_callback = Arc::clone(&denylist);
        let machine_for_refresh = forward_window_machine.clone();
        let epoch_clock_for_refresh = Arc::clone(&epoch_clock);
        tokio::spawn(async move {
            refresh_service
                .run(move |sk| {
                    let pk_bytes = sk.public_key().to_bytes();
                    if denylist_for_callback.contains(&pk_bytes) {
                        tracing::info!(
                            pubkey = %observability::logging::TruncatedPubkey::new(&format!(
                                "0x{}",
                                hex::encode(pk_bytes)
                            )),
                            "Skipping denylisted key at refresh callback (DELETE raced refresh)"
                        );
                        return;
                    }
                    let pk = sk.public_key();
                    if let Some(ref machine) = machine_for_refresh {
                        // Import-strict: no restart Safe-skip for dynamically added keys.
                        machine.register_for_import(&pk, epoch_clock_for_refresh.current_epoch());
                    }
                    signer_for_refresh.add_local_key(sk);
                })
                .await;
        });
        info!(interval_secs = refresh_interval, "Secret provider refresh task started");
    }

    Ok(EnablementHandles {
        signing_enablement,
        forward_window_machine,
        epoch_clock,
        pubkey_map: Arc::clone(&keys.pubkey_map),
        liveness_task,
        validator_index_map,
    })
}

/// Resolve validator public keys to numeric beacon indices.
async fn resolve_validator_indices(
    beacon_client: &dyn BeaconNodeClient,
    pubkey_map: &PubkeyMap,
) -> Result<HashMap<String, String>, String> {
    let pubkeys: Vec<String> = {
        let map = pubkey_map.read();
        if map.is_empty() {
            return Ok(HashMap::new());
        }
        map.keys().cloned().collect()
    };
    let response = beacon_client.get_validators(&pubkeys).await.map_err(|e| e.to_string())?;

    let index_map: HashMap<String, String> =
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::deletion_denylist::DeletionDenylist;
    use beacon::BeaconClient;
    use bn_manager::{BnManager, OperationTimeouts};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey, Signer};
    use doppelganger::ForwardWindowStatus;
    use eth_types::{Root, SECONDS_PER_SLOT, SLOTS_PER_EPOCH};
    use slashing::SlashingDbReader;
    use std::collections::HashSet;
    use std::time::Duration;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const GVR: Root = [0x11u8; 32];

    fn empty_loaded_keys() -> LoadedKeys {
        let km = KeyManager::new();
        let local_signer = LocalSigner::new(km);
        LoadedKeys {
            composite_signer: Arc::new(CompositeSigner::new(local_signer)),
            validator_count: 0,
            local_pubkeys: HashSet::new(),
            pubkey_map: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            secret_providers: vec![],
            grpc_signer: None,
        }
    }

    fn loaded_keys_with_pubkey(pk: crypto::PublicKey) -> LoadedKeys {
        let km = KeyManager::new();
        // pubkey_map is authoritative for enablement registration.
        let mut map = HashMap::new();
        let hex = format!("0x{}", hex::encode(pk.to_bytes()));
        map.insert(hex, pk.clone());
        let local_signer = LocalSigner::new(km);
        LoadedKeys {
            composite_signer: Arc::new(CompositeSigner::new(local_signer)),
            validator_count: 1,
            local_pubkeys: HashSet::from([pk.to_bytes()]),
            pubkey_map: Arc::new(parking_lot::RwLock::new(map)),
            secret_providers: vec![],
            grpc_signer: None,
        }
    }

    async fn mock_beacon(genesis_time: u64) -> (MockServer, BeaconHandles) {
        let server = MockServer::start().await;
        // Small pubkey sets use GET; return empty data (pending activation path).
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&server)
            .await;

        let config = Config {
            beacon_url: server.uri(),
            beacon_nodes: vec![server.uri()],
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        };
        let builder = ServiceBuilder::new(config);
        let beacon_client: Arc<BeaconClient> = builder.build_beacon().expect("beacon client");
        let bn_manager: Arc<BnManager> = builder
            .build_bn_manager_with_timeouts(OperationTimeouts::default())
            .expect("bn manager");

        (
            server,
            BeaconHandles {
                beacon_client,
                bn_manager,
                genesis_validators_root: GVR,
                genesis_validators_root_hex: format!("0x{}", hex::encode(GVR)),
                genesis_time,
            },
        )
    }

    fn base_config(doppelganger: bool) -> Config {
        Config {
            doppelganger_detection: doppelganger,
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        }
    }

    fn denylist(dir: &TempDir) -> Arc<DeletionDenylist> {
        Arc::new(DeletionDenylist::empty_at(dir.path().join(".rvc.deleted_keys")))
    }

    /// Default (doppelganger on): machine present, registered key gate-closed.
    #[tokio::test]
    async fn test_wire_signing_enablement_returns_fail_closed_machine_by_default() {
        let dir = TempDir::new().unwrap();
        // genesis_time = 0 → high current epoch (not epoch-0 bypass).
        let (_server, beacon) = mock_beacon(0).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let shutdown = CancellationToken::new();

        let handles = wire_signing_enablement(
            &base_config(true),
            &keys,
            &beacon,
            slashing_db,
            denylist(&dir),
            &shutdown,
        )
        .await
        .expect("phase succeeds with empty index resolution");

        assert!(
            handles.forward_window_machine.is_some(),
            "doppelganger on must construct ForwardWindowMachine"
        );
        assert!(
            !handles.signing_enablement.is_signing_enabled(&pk),
            "registered key at epoch>0 must be fail-closed before liveness window"
        );
        // Unregistered key also closed.
        let other = SecretKey::generate().public_key();
        assert!(
            !handles.signing_enablement.is_signing_enabled(&other),
            "unregistered key must be fail-closed"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_wire_signing_enablement_optout_yields_always_enabled() {
        let dir = TempDir::new().unwrap();
        let (_server, beacon) = mock_beacon(0).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let shutdown = CancellationToken::new();

        let handles = wire_signing_enablement(
            &base_config(false),
            &keys,
            &beacon,
            slashing_db,
            denylist(&dir),
            &shutdown,
        )
        .await
        .expect("opt-out phase succeeds");

        assert!(handles.forward_window_machine.is_none());
        assert!(handles.liveness_task.is_none());
        assert!(handles.signing_enablement.is_signing_enabled(&pk));
        let other = SecretKey::generate().public_key();
        assert!(
            handles.signing_enablement.is_signing_enabled(&other),
            "opt-out enables every pubkey"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_wire_signing_enablement_preserves_epoch0_bypass() {
        let dir = TempDir::new().unwrap();
        // Genesis far in the future → MonotonicEpochClock stays at epoch 0.
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let far_future = now.saturating_add(SECONDS_PER_SLOT * SLOTS_PER_EPOCH * 100);
        let (_server, beacon) = mock_beacon(far_future).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let shutdown = CancellationToken::new();

        let handles = wire_signing_enablement(
            &base_config(true),
            &keys,
            &beacon,
            slashing_db,
            denylist(&dir),
            &shutdown,
        )
        .await
        .expect("epoch-0 phase succeeds");

        assert_eq!(handles.epoch_clock.current_epoch(), 0);
        assert!(
            handles.signing_enablement.is_signing_enabled(&pk),
            "epoch-0 boot register must immediately enable signing (pre-genesis bypass)"
        );
        let machine = handles.forward_window_machine.expect("machine present");
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Safe);
        shutdown.cancel();
    }

    /// Restart safe-skip requires local slashing history under this GVR.
    #[tokio::test]
    async fn test_wire_signing_enablement_restart_safe_skip_requires_local_history() {
        let dir = TempDir::new().unwrap();
        let (_server, beacon) = mock_beacon(0).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = hex::encode(pk.to_bytes());
        let keys = loaded_keys_with_pubkey(pk.clone());
        let shutdown = CancellationToken::new();

        // Without history: Pending (no safe-skip).
        {
            let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
            slashing_db.set_genesis_validators_root(&GVR).unwrap();
            let handles = wire_signing_enablement(
                &base_config(true),
                &keys,
                &beacon,
                slashing_db,
                denylist(&dir),
                &shutdown,
            )
            .await
            .expect("phase");
            assert!(
                !handles.signing_enablement.is_signing_enabled(&pk),
                "no local history → no restart safe-skip"
            );
        }

        // With recent local history: Safe on boot register.
        {
            let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
            slashing_db.set_genesis_validators_root(&GVR).unwrap();
            let epoch = MonotonicEpochClock::new(0).current_epoch();
            assert!(epoch > 2, "test needs epoch > monitoring window");
            let target = epoch - 1;
            slashing_db
                .check_and_record_attestation(&pk_hex, target.saturating_sub(1), target, None, &GVR)
                .expect("seed recent attestation");
            assert_eq!(
                SlashingDbReader::last_signed_attestation(slashing_db.as_ref(), &pk_hex, &GVR),
                Some(target)
            );

            let handles = wire_signing_enablement(
                &base_config(true),
                &keys,
                &beacon,
                slashing_db,
                denylist(&dir),
                &shutdown,
            )
            .await
            .expect("phase with history");
            assert!(
                handles.signing_enablement.is_signing_enabled(&pk),
                "recent local attestation under GVR → restart safe-skip → Safe"
            );
        }
        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_liveness_task_cancels_on_shutdown_token() {
        let dir = TempDir::new().unwrap();
        let (_server, beacon) = mock_beacon(0).await;
        // Non-empty pubkey map so the loop starts (empty indices + pubkeys path).
        let sk = SecretKey::generate();
        let keys = loaded_keys_with_pubkey(sk.public_key());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let shutdown = CancellationToken::new();

        let handles = wire_signing_enablement(
            &base_config(true),
            &keys,
            &beacon,
            slashing_db,
            denylist(&dir),
            &shutdown,
        )
        .await
        .expect("phase");

        let task = handles.liveness_task.expect("liveness loop should spawn with pubkeys");
        shutdown.cancel();
        // Loop must observe cancellation and exit without hanging.
        tokio::time::timeout(Duration::from_secs(5), task.join)
            .await
            .expect("liveness task must terminate on shutdown token")
            .expect("join ok");
    }

    /// Sanity: empty keystore path still produces a usable enablement handle.
    #[tokio::test]
    async fn test_wire_signing_enablement_empty_keys_ok() {
        let dir = TempDir::new().unwrap();
        let (_server, beacon) = mock_beacon(0).await;
        let keys = empty_loaded_keys();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let shutdown = CancellationToken::new();

        let handles = wire_signing_enablement(
            &base_config(true),
            &keys,
            &beacon,
            slashing_db,
            denylist(&dir),
            &shutdown,
        )
        .await
        .expect("empty keys ok");

        assert!(handles.forward_window_machine.is_some());
        assert!(handles.liveness_task.is_none(), "no keys → no liveness loop");
        assert!(handles.validator_index_map.is_empty());
        // Fail-closed for any random key.
        let other = SecretKey::generate().public_key();
        assert!(!handles.signing_enablement.is_signing_enabled(&other));
        // Silence unused import warning paths
        let _ = Signer::public_keys(keys.composite_signer.as_ref());
        shutdown.cancel();
    }
}
