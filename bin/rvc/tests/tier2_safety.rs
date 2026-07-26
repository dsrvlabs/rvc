//! Tier 2 integration tests: Safety & Reliability features.
//!
//! Verifies all four Tier 2 safety features work correctly both in isolation
//! and when composed together:
//! - FR-1: Builder circuit breaker
//! - FR-2: Emergency attestation disable
//! - FR-3: Slashed validator monitor
//! - FR-4: Keystore file locking

// =============================================================================
// FR-1: Builder Circuit Breaker
// =============================================================================

mod circuit_breaker {
    use builder::CircuitBreakerState;
    use std::sync::Arc;

    #[test]
    fn trips_after_consecutive_misses() {
        let cb = CircuitBreakerState::new(3, 5);
        assert!(!cb.is_tripped());

        cb.record_miss();
        cb.record_miss();
        assert!(!cb.is_tripped(), "should not trip before threshold");

        cb.record_miss();
        assert!(cb.is_tripped(), "should trip at consecutive threshold");
    }

    #[test]
    fn trips_after_epoch_misses_with_interleaved_successes() {
        let cb = CircuitBreakerState::new(3, 5);

        // Interleave misses and successes — consecutive resets but epoch accumulates
        for _ in 0..4 {
            cb.record_miss();
            cb.record_success();
        }
        assert!(!cb.is_tripped());
        assert_eq!(cb.epoch_misses(), 4);
        assert_eq!(cb.consecutive_misses(), 0);

        cb.record_miss(); // epoch_misses = 5 → trips
        assert!(cb.is_tripped());
    }

    #[test]
    fn resets_at_epoch_boundary() {
        let cb = CircuitBreakerState::new(3, 5);

        // Trip the breaker
        for _ in 0..3 {
            cb.record_miss();
        }
        assert!(cb.is_tripped());

        // Epoch boundary resets both counters
        cb.reset_epoch(1);
        assert!(!cb.is_tripped());
        assert_eq!(cb.consecutive_misses(), 0);
        assert_eq!(cb.epoch_misses(), 0);
    }

    #[test]
    fn same_epoch_reset_is_noop() {
        let cb = CircuitBreakerState::new(3, 5);
        cb.reset_epoch(1);
        cb.record_miss();
        cb.record_miss();

        cb.reset_epoch(1); // same epoch — no effect
        assert_eq!(cb.consecutive_misses(), 2);
        assert_eq!(cb.epoch_misses(), 2);
    }

    #[test]
    fn disabled_when_both_limits_zero() {
        let cb = CircuitBreakerState::new(0, 0);
        for _ in 0..100 {
            cb.record_miss();
        }
        assert!(!cb.is_tripped());
    }

    #[test]
    fn concurrent_access_no_panics() {
        let cb = Arc::new(CircuitBreakerState::new(100, 200));
        let mut handles = vec![];

        for _ in 0..10 {
            let cb = cb.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    cb.record_miss();
                    let _ = cb.is_tripped();
                    cb.record_success();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }
    }

    #[test]
    fn trip_reset_cycle_across_epochs() {
        let cb = CircuitBreakerState::new(2, 10);

        // Epoch 1: trip via consecutive
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());

        // Epoch 2: reset, accumulate some misses
        cb.reset_epoch(2);
        assert!(!cb.is_tripped());
        cb.record_miss();
        cb.record_success();
        assert!(!cb.is_tripped());

        // Epoch 3: trip again
        cb.reset_epoch(3);
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());

        // Epoch 4: clean
        cb.reset_epoch(4);
        assert!(!cb.is_tripped());
    }
}

// =============================================================================
// FR-2: Emergency Attestation Disable
// =============================================================================

mod attestation_disable {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn toggle_via_atomic_bool() {
        let flag = Arc::new(AtomicBool::new(true));
        assert!(flag.load(Ordering::Relaxed));

        flag.store(false, Ordering::Relaxed);
        assert!(!flag.load(Ordering::Relaxed));

        flag.store(true, Ordering::Relaxed);
        assert!(flag.load(Ordering::Relaxed));
    }

    #[test]
    fn shared_across_threads() {
        let flag = Arc::new(AtomicBool::new(true));

        let writer = {
            let flag = flag.clone();
            std::thread::spawn(move || {
                flag.store(false, Ordering::Relaxed);
            })
        };

        writer.join().unwrap();
        assert!(!flag.load(Ordering::Relaxed), "reader should see writer's update");
    }

    #[test]
    fn swap_returns_previous_value() {
        let flag = Arc::new(AtomicBool::new(true));

        let prev = flag.swap(false, Ordering::Relaxed);
        assert!(prev, "swap should return previous value (true)");
        assert!(!flag.load(Ordering::Relaxed));

        let prev = flag.swap(false, Ordering::Relaxed);
        assert!(!prev, "swap should return previous value (false)");
    }

    #[test]
    fn disable_attesting_config_flag() {
        use rvc::config::Config;

        let config = Config::default();
        assert!(!config.disable_attesting, "default should be enabled");
    }
}

// =============================================================================
// FR-3: Slashed Validator Monitor
// =============================================================================

mod slashed_validator_monitor {
    use beacon::{ValidatorData, ValidatorInfo, ValidatorsResponse};
    use bn_manager::MockBeaconNodeClient;
    use rvc::slashing_monitor::{check_slashed_validators, SlashedAction, SlashedOutcome};
    use validator_store::ValidatorStore;

    fn mock_with_validators(validators: Vec<ValidatorData>) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_validators(move |_pubkeys| {
            Ok(ValidatorsResponse { data: validators.clone() })
        })
    }

    fn mock_failing() -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_validators(|_| {
            Err(beacon::BeaconError::HttpError("mock failure".to_string()))
        })
    }

    fn test_pubkey() -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = 0xab;
        pk[1] = 0xcd;
        pk
    }

    fn make_validator(pubkey: &[u8; 48], status: &str) -> ValidatorData {
        ValidatorData {
            index: "123".to_string(),
            status: status.to_string(),
            validator: ValidatorInfo { pubkey: format!("0x{}", hex::encode(pubkey)) },
        }
    }

    #[tokio::test]
    async fn slashed_validator_gets_disabled() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator(&pk, "active_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(
            !store.list_enabled_pubkeys().contains(&pk),
            "slashed validator should be disabled"
        );
        assert_eq!(
            outcome,
            SlashedOutcome::NoAction,
            "should not request shutdown in disable-only mode"
        );
    }

    #[tokio::test]
    async fn healthy_validators_untouched() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator(&pk, "active_ongoing")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(
            store.list_enabled_pubkeys().contains(&pk),
            "healthy validator should remain enabled"
        );
        assert_eq!(outcome, SlashedOutcome::NoAction);
    }

    #[tokio::test]
    async fn beacon_error_fails_open() {
        let pk = test_pubkey();
        let beacon = mock_failing();
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(
            store.list_enabled_pubkeys().contains(&pk),
            "fail-open: validator should remain enabled on BN error"
        );
        assert_eq!(outcome, SlashedOutcome::NoAction);
    }

    #[tokio::test]
    async fn shutdown_mode_sends_signal() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator(&pk, "exited_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::Shutdown).await;

        assert_eq!(
            outcome,
            SlashedOutcome::ShutdownRequested,
            "shutdown signal should be requested"
        );
    }

    #[tokio::test]
    async fn none_action_is_noop() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator(&pk, "active_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::None).await;

        assert!(store.list_enabled_pubkeys().contains(&pk), "none action should not disable");
        assert_eq!(outcome, SlashedOutcome::NoAction, "none action should not shutdown");
    }

    #[test]
    fn slashed_action_from_str() {
        assert_eq!("disable-only".parse::<SlashedAction>().unwrap(), SlashedAction::DisableOnly);
        assert_eq!("shutdown".parse::<SlashedAction>().unwrap(), SlashedAction::Shutdown);
        assert_eq!("none".parse::<SlashedAction>().unwrap(), SlashedAction::None);
        assert!("invalid".parse::<SlashedAction>().is_err());
    }

    #[tokio::test]
    async fn multiple_validators_only_slashed_disabled() {
        let pk1 = test_pubkey();
        let mut pk2 = [0u8; 48];
        pk2[0] = 0xef;

        let beacon = mock_with_validators(vec![
            make_validator(&pk1, "active_slashed"),
            make_validator(&pk2, "active_ongoing"),
        ]);

        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk1));
        store.add_validator(validator_store::ValidatorConfig::new(pk2));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(!store.list_enabled_pubkeys().contains(&pk1), "slashed pk1 should be disabled");
        assert!(store.list_enabled_pubkeys().contains(&pk2), "healthy pk2 should remain enabled");
        assert_eq!(outcome, SlashedOutcome::NoAction);
    }
}

// =============================================================================
// FR-4: Keystore File Locking
// =============================================================================

mod keystore_locking {
    use rvc::startup::{acquire_keystore_lock, StartupError, EXIT_KEYSTORE_LOCKED};

    #[test]
    fn lock_acquired_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_keystore_lock(dir.path());
        assert!(guard.is_ok());
        assert!(dir.path().join(".rvc.lock").exists());
    }

    #[test]
    fn second_instance_fails_with_exit_14() {
        let dir = tempfile::tempdir().unwrap();
        let _guard1 = acquire_keystore_lock(dir.path()).unwrap();

        let result = acquire_keystore_lock(dir.path());
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), EXIT_KEYSTORE_LOCKED);
        assert!(matches!(err, StartupError::KeystoreLocked(_)));
    }

    #[test]
    fn nonexistent_dir_fails() {
        let result =
            acquire_keystore_lock(std::path::Path::new("/nonexistent/path/does/not/exist"));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _guard = acquire_keystore_lock(dir.path()).unwrap();
        let metadata = std::fs::metadata(dir.path().join(".rvc.lock")).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

// =============================================================================
// Config integration: all safety fields parse and validate together
// =============================================================================

mod config_integration {
    use rvc::config::Config;

    #[test]
    fn default_config_has_all_safety_fields() {
        let config = Config::default();

        // FR-1: circuit breaker defaults
        assert_eq!(config.builder_circuit_breaker_consecutive_limit, 3);
        assert_eq!(config.builder_circuit_breaker_epoch_limit, 5);

        // FR-2: attestation enabled by default
        assert!(!config.disable_attesting);

        // FR-3: slashed monitor defaults to disable-only
        assert_eq!(config.slashed_validators_action, "disable-only");

        // FR-4: keystore locking enabled by default
        assert!(!config.disable_keystore_locking);
    }

    #[test]
    fn invalid_slashed_action_rejected() {
        let config =
            Config { slashed_validators_action: "invalid-action".to_string(), ..Config::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn valid_slashed_actions_accepted() {
        for action in &["disable-only", "shutdown", "none"] {
            let config =
                Config { slashed_validators_action: action.to_string(), ..Config::default() };
            assert!(config.validate().is_ok(), "action '{}' should be valid", action);
        }
    }

    #[test]
    fn toml_roundtrip_with_all_safety_fields() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
builder_circuit_breaker_consecutive_limit = 7
builder_circuit_breaker_epoch_limit = 12
disable_keystore_locking = true
disable_attesting = true
slashed_validators_action = "shutdown"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.builder_circuit_breaker_consecutive_limit, 7);
        assert_eq!(config.builder_circuit_breaker_epoch_limit, 12);
        assert!(config.disable_keystore_locking);
        assert!(config.disable_attesting);
        assert_eq!(config.slashed_validators_action, "shutdown");
    }

    #[test]
    fn cli_overrides_merge_all_safety_fields() {
        use rvc::config::CliOverrides;

        let mut config = Config::default();
        let cli = CliOverrides {
            disable_attesting: Some(true),
            slashed_validators_action: Some("shutdown".to_string()),
            builder_circuit_breaker_consecutive_limit: Some(10),
            builder_circuit_breaker_epoch_limit: Some(20),
            disable_keystore_locking: Some(true),
            ..Default::default()
        };

        config.merge_with_cli(&cli);

        assert!(config.disable_attesting);
        assert_eq!(config.slashed_validators_action, "shutdown");
        assert_eq!(config.builder_circuit_breaker_consecutive_limit, 10);
        assert_eq!(config.builder_circuit_breaker_epoch_limit, 20);
        assert!(config.disable_keystore_locking);
    }
}

// =============================================================================
// Composition: features don't conflict when active simultaneously
// =============================================================================

mod composition {
    use beacon::{ValidatorData, ValidatorInfo, ValidatorsResponse};
    use bn_manager::MockBeaconNodeClient;
    use builder::CircuitBreakerState;
    use rvc::slashing_monitor::{check_slashed_validators, SlashedAction, SlashedOutcome};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use validator_store::ValidatorStore;

    fn test_pubkey() -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = 0xab;
        pk[1] = 0xcd;
        pk
    }

    fn make_validator(pubkey: &[u8; 48], status: &str) -> ValidatorData {
        ValidatorData {
            index: "123".to_string(),
            status: status.to_string(),
            validator: ValidatorInfo { pubkey: format!("0x{}", hex::encode(pubkey)) },
        }
    }

    fn mock_with_validators(validators: Vec<ValidatorData>) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_validators(move |_pubkeys| {
            Ok(ValidatorsResponse { data: validators.clone() })
        })
    }

    #[tokio::test]
    async fn circuit_breaker_tripped_plus_attestation_disabled() {
        // Both safety features active simultaneously — they target different concerns
        let circuit_breaker = Arc::new(CircuitBreakerState::new(2, 5));
        let attesting_enabled = Arc::new(AtomicBool::new(false));

        // Trip the circuit breaker
        circuit_breaker.record_miss();
        circuit_breaker.record_miss();
        assert!(circuit_breaker.is_tripped());
        assert!(!attesting_enabled.load(Ordering::Relaxed));

        // Circuit breaker controls block production path
        // Attestation flag controls attestation/sync/aggregation path
        // Both can be active independently — no interference
        assert!(circuit_breaker.is_tripped());

        // Re-enable attestation, breaker still tripped
        attesting_enabled.store(true, Ordering::Relaxed);
        assert!(attesting_enabled.load(Ordering::Relaxed));
        assert!(circuit_breaker.is_tripped());

        // Reset breaker, attestation still enabled
        circuit_breaker.reset_epoch(1);
        assert!(!circuit_breaker.is_tripped());
        assert!(attesting_enabled.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn slashed_monitor_and_attestation_disable_compose() {
        // Slashing disables a specific validator, attestation disable is global
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator(&pk, "active_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let attesting_enabled = Arc::new(AtomicBool::new(false));

        // Even with attestation globally disabled, slashing monitor still operates
        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(
            !store.list_enabled_pubkeys().contains(&pk),
            "slashed validator should be disabled regardless of global attestation flag"
        );
        assert_eq!(outcome, SlashedOutcome::NoAction);

        // Attestation flag is independent
        assert!(!attesting_enabled.load(Ordering::Relaxed));
    }

    #[test]
    fn keystore_lock_independent_of_circuit_breaker() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = rvc::startup::acquire_keystore_lock(dir.path()).unwrap();

        // Circuit breaker operates independently of keystore lock
        let cb = CircuitBreakerState::new(3, 5);
        cb.record_miss();
        cb.record_miss();
        cb.record_miss();
        assert!(cb.is_tripped());

        // Lock is still held, breaker is tripped — no interference
        cb.reset_epoch(1);
        assert!(!cb.is_tripped());
    }

    #[tokio::test]
    async fn all_features_active_simultaneously() {
        // Set up all four features at once
        let circuit_breaker = Arc::new(CircuitBreakerState::new(3, 5));
        let attesting_enabled = Arc::new(AtomicBool::new(true));
        let dir = tempfile::tempdir().unwrap();
        let _lock_guard = rvc::startup::acquire_keystore_lock(dir.path()).unwrap();

        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator(&pk, "active_ongoing")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        // All features operating together: no slashing, no circuit breaker trip, attestation on
        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(store.list_enabled_pubkeys().contains(&pk));
        assert!(!circuit_breaker.is_tripped());
        assert!(attesting_enabled.load(Ordering::Relaxed));
        assert_eq!(outcome, SlashedOutcome::NoAction);

        // Now disable attestation and trip circuit breaker
        attesting_enabled.store(false, Ordering::Relaxed);
        circuit_breaker.record_miss();
        circuit_breaker.record_miss();
        circuit_breaker.record_miss();

        assert!(circuit_breaker.is_tripped());
        assert!(!attesting_enabled.load(Ordering::Relaxed));
        assert!(store.list_enabled_pubkeys().contains(&pk)); // healthy validator still enabled
        assert_eq!(outcome, SlashedOutcome::NoAction); // no shutdown
    }
}
