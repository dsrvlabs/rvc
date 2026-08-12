use super::*;

// ── RF5-08: spawn_keymanager_api / build_keymanager_api ─────────────────

use crate::config::Config;
use crate::deletion_denylist::DeletionDenylist;

fn test_fork_schedule() -> Arc<ForkSchedule> {
    Arc::new(ForkSchedule {
        genesis_fork_version: [0, 0, 0, 0],
        altair_fork_epoch: 10,
        altair_fork_version: [1, 0, 0, 0],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [2, 0, 0, 0],
        capella_fork_epoch: 30,
        capella_fork_version: [3, 0, 0, 0],
        deneb_fork_epoch: 40,
        deneb_fork_version: [4, 0, 0, 0],
        electra_fork_epoch: 50,
        electra_fork_version: [5, 0, 0, 0],
        fulu_fork_epoch: 60,
        fulu_fork_version: [6, 0, 0, 0],
    })
}

fn spawn_test_deps(
    keystore_dir: &Path,
    forward_window_machine: Option<Arc<ForwardWindowMachine>>,
) -> KeymanagerApiDeps {
    use crate::key_admission::KeyAdmissionService;

    let composite = create_empty_composite_signer();
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer = Arc::new(
        SignerService::new(composite.clone(), Arc::clone(&slashing_db))
            .with_enablement(always_enabled()),
    );
    let beacon_config = beacon::BeaconClientConfig::new("http://127.0.0.1:9");
    let beacon_client = Arc::new(BeaconClient::new(beacon_config).expect("test beacon client"));
    let (key_gen_tx, _rx) = watch::channel(0u64);
    let pubkey_map = create_pubkey_map();
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 100));
    let deletion_denylist =
        Arc::new(DeletionDenylist::empty_at(keystore_dir.join(".rvc.deleted_keys")));
    let epoch_clock = Arc::new(MonotonicEpochClock::new(0));
    let admissions = Arc::new(KeyAdmissionService::new(
        Arc::clone(&pubkey_map),
        key_gen_tx.clone(),
        Arc::clone(&composite),
        Arc::clone(&validator_store),
        Arc::clone(&deletion_denylist),
        forward_window_machine.clone(),
        Arc::clone(&epoch_clock),
    ));
    KeymanagerApiDeps {
        composite_signer: composite,
        slashing_db,
        genesis_validators_root: [0x11u8; 32],
        validator_store,
        beacon_client,
        signer,
        fork_schedule: test_fork_schedule(),
        deletion_denylist,
        attesting_enabled: Arc::new(AtomicBool::new(true)),
        forward_window_machine,
        epoch_clock,
        pubkey_map,
        key_gen_tx,
        admissions,
    }
}

fn spawn_test_config(dir: &TempDir, enabled: bool, address: &str) -> Config {
    Config {
        keymanager: crate::config::KeymanagerConfig {
            enabled,
            address: Some(address.to_string()),
            token_file: Some(dir.path().join("km-token.txt")),
            ..Default::default()
        },
        keystore_path: dir.path().to_path_buf(),
        doppelganger_detection: true,
        disable_keystore_locking: true,
        allow_fresh_db: true,
        ..Default::default()
    }
}

/// Disabled config must not construct adapters, token file, or re-arm.
#[test]
fn test_spawn_keymanager_api_disabled_constructs_nothing() {
    let dir = TempDir::new().unwrap();
    let config = spawn_test_config(&dir, false, "127.0.0.1:0");
    let deps = spawn_test_deps(dir.path(), None);

    let built = build_keymanager_api(&config, deps).expect("disabled must succeed");
    assert!(built.is_none(), "disabled keymanager must construct nothing");
    assert!(
        !config.keymanager.token_file.as_ref().unwrap().exists(),
        "token file must not be created when disabled"
    );

    // spawn path is also a no-op
    let deps = spawn_test_deps(dir.path(), None);
    let handle = spawn_keymanager_api(&config, deps, &CancellationToken::new())
        .expect("disabled spawn is Ok");
    assert!(handle.is_none(), "disabled spawn must return no JoinHandle");
}

/// Both monitor variants re-arm exactly once (single call site after branch).
#[test]
fn test_spawn_keymanager_api_rearms_gate_exactly_once_for_both_monitors() {
    let dir = TempDir::new().unwrap();
    // Real BLS key: ForwardWindowMonitor validates encoding; the time-based
    // gate accepts any 48-byte array.
    let crypto_pk = SecretKey::generate().public_key();
    let pk: Pubkey = crypto_pk.to_bytes();
    let now_unix =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    std::fs::write(
        import_meta_path(dir.path(), &pk),
        format!("{{\"imported_unix_seconds\":{now_unix}}}"),
    )
    .unwrap();

    // 1) Time-based gate path (no ForwardWindowMachine)
    {
        let config = spawn_test_config(&dir, true, "127.0.0.1:0");
        let deps = spawn_test_deps(dir.path(), None);
        let built = build_keymanager_api(&config, deps).expect("build").expect("enabled");
        assert_eq!(built.monitor_kind, DoppelgangerMonitorKind::TimeBasedGate);
        assert!(!built.doppelganger_window.is_zero());
        assert!(
            !built.doppelganger_monitor.is_doppelganger_safe(&pk),
            "time-based gate must re-arm recent import exactly once"
        );
    }

    // 2) Forward-window path — same sidecar, fresh machine
    {
        struct NoPrior;
        impl slashing::SlashingDbReader for NoPrior {
            fn last_signed_attestation(
                &self,
                _pubkey: &str,
                _gvr: &Root,
            ) -> Option<slashing::TargetEpoch> {
                None
            }
        }
        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPrior);
        let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xefu8; 32]));
        let config = spawn_test_config(&dir, true, "127.0.0.1:0");
        let deps = spawn_test_deps(dir.path(), Some(Arc::clone(&machine)));
        let built = build_keymanager_api(&config, deps).expect("build").expect("enabled");
        assert_eq!(built.monitor_kind, DoppelgangerMonitorKind::ForwardWindow);
        assert!(
            !built.doppelganger_monitor.is_doppelganger_safe(&pk),
            "forward-window monitor must re-arm recent import exactly once"
        );
        // Machine registered the key as Pending (import-strict)
        assert_eq!(machine.status(&crypto_pk), doppelganger::ForwardWindowStatus::Pending);
    }
}

/// Machine present → ForwardWindow monitor is selected.
#[test]
fn test_spawn_keymanager_api_uses_forward_window_monitor_when_machine_present() {
    let dir = TempDir::new().unwrap();
    struct NoPrior;
    impl slashing::SlashingDbReader for NoPrior {
        fn last_signed_attestation(
            &self,
            _pubkey: &str,
            _gvr: &Root,
        ) -> Option<slashing::TargetEpoch> {
            None
        }
    }
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPrior);
    let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xabu8; 32]));
    let config = spawn_test_config(&dir, true, "127.0.0.1:0");
    let deps = spawn_test_deps(dir.path(), Some(machine));
    let built = build_keymanager_api(&config, deps).expect("build").expect("enabled");
    assert_eq!(
        built.monitor_kind,
        DoppelgangerMonitorKind::ForwardWindow,
        "forward_window_machine must select ForwardWindow monitor"
    );
}

/// Non-loopback bind emits the security warning (behavior preserved).
#[test]
#[tracing_test::traced_test]
fn test_spawn_keymanager_api_warns_on_non_loopback_bind() {
    let dir = TempDir::new().unwrap();
    // 0.0.0.0:0 is non-loopback; bind is not attempted by build_keymanager_api.
    let config = spawn_test_config(&dir, true, "0.0.0.0:0");
    let deps = spawn_test_deps(dir.path(), None);
    let built = build_keymanager_api(&config, deps).expect("build").expect("enabled");
    assert!(!built.addr.ip().is_loopback());
    assert!(logs_contain("non-loopback address"), "must warn when Keymanager binds non-loopback");
}

/// Enabled spawn returns a joinable handle that completes after token cancel.
#[tokio::test]
async fn test_spawn_keymanager_api_returns_a_joinable_handle() {
    use std::time::Duration;

    let dir = TempDir::new().unwrap();
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let config = spawn_test_config(&dir, true, &addr);
    let deps = spawn_test_deps(dir.path(), None);
    let token = CancellationToken::new();
    let handle = spawn_keymanager_api(&config, deps, &token)
        .expect("spawn")
        .expect("enabled must return a JoinHandle");

    // Wait until the listener accepts.
    let sock: std::net::SocketAddr = addr.parse().unwrap();
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(sock).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    token.cancel();
    let finished = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("JoinHandle must complete within 2s after cancel");
    finished.expect("server task must not panic");
}
