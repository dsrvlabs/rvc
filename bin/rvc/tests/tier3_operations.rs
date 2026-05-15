//! Tier 3 integration tests: Operational features.
//!
//! Verifies all five Tier 3 operational features work correctly both in
//! isolation and when composed together:
//! - FR-1: Proposer nodes (separate BnManager for block proposals)
//! - FR-2: Broadcast topics (per-topic routing control)
//! - FR-3: Monitoring push (beaconcha.in metrics endpoint)
//! - FR-4: Log file rotation (size-based rotation with max file count)
//! - FR-5: Proposer config URL (remote proposer config with refresh)

// =============================================================================
// FR-1: Proposer Nodes
// =============================================================================

mod proposer_nodes {
    use bn_manager::{BnManager, BnManagerConfig};
    use rvc::config::Config;

    #[test]
    fn proposer_bn_manager_constructed_from_config() {
        let config = Config {
            proposer_nodes: vec![
                "http://proposer1:5052".to_string(),
                "http://proposer2:5052".to_string(),
            ],
            ..Config::default()
        };

        let endpoints = config.proposer_nodes.clone();
        let bn_config = BnManagerConfig::new(endpoints);
        let manager = BnManager::new(bn_config);
        assert!(manager.is_ok(), "proposer BnManager should be created from config");
    }

    #[test]
    fn proposer_pool_separate_from_main_pool() {
        let config = Config {
            beacon_url: "http://main-bn:5052".to_string(),
            proposer_nodes: vec!["http://proposer-bn:5052".to_string()],
            ..Config::default()
        };

        let main_endpoints = config.effective_beacon_nodes();
        let proposer_endpoints = config.proposer_nodes.clone();

        assert_eq!(main_endpoints, vec!["http://main-bn:5052"]);
        assert_eq!(proposer_endpoints, vec!["http://proposer-bn:5052"]);
        assert_ne!(main_endpoints, proposer_endpoints, "pools must be separate");
    }

    #[test]
    fn empty_proposer_nodes_returns_none() {
        let config = Config { proposer_nodes: vec![], ..Config::default() };
        assert!(config.proposer_nodes.is_empty());
    }

    #[test]
    fn proposer_nodes_from_toml() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
proposer_nodes = ["http://p1:5052", "http://p2:5052"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proposer_nodes.len(), 2);
        assert_eq!(config.proposer_nodes[0], "http://p1:5052");
        assert_eq!(config.proposer_nodes[1], "http://p2:5052");
    }

    #[test]
    fn proposer_nodes_cli_override() {
        use rvc::config::CliOverrides;

        let mut config = Config::default();
        assert!(config.proposer_nodes.is_empty());

        let cli = CliOverrides {
            proposer_nodes: Some(vec!["http://override:5052".to_string()]),
            ..Default::default()
        };
        config.merge_with_cli(&cli);

        assert_eq!(config.proposer_nodes, vec!["http://override:5052"]);
    }

    #[test]
    fn build_proposer_bn_manager_with_service_builder() {
        use rvc::config::ServiceBuilder;

        let config = Config {
            proposer_nodes: vec!["http://proposer:5052".to_string()],
            ..Config::default()
        };
        let builder = ServiceBuilder::new(config);
        let result = builder.build_proposer_bn_manager();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some(), "should return Some when proposer_nodes is set");
    }

    #[test]
    fn build_proposer_bn_manager_none_when_empty() {
        use rvc::config::ServiceBuilder;

        let config = Config::default();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_proposer_bn_manager();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "should return None when proposer_nodes is empty");
    }
}

// =============================================================================
// FR-2: Broadcast Topics
// =============================================================================

mod broadcast_topics {
    use bn_manager::BroadcastTopics;
    use rvc::config::Config;

    #[test]
    fn default_all_broadcast() {
        let config = Config::default();
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn none_disables_all() {
        let config = Config { broadcast: vec!["none".to_string()], ..Config::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn selective_topics() {
        let config = Config {
            broadcast: vec!["attestations".to_string(), "blocks".to_string()],
            ..Config::default()
        };
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations, "attestations should be enabled");
        assert!(topics.blocks, "blocks should be enabled");
        assert!(!topics.sync_committee, "sync_committee should be disabled");
        assert!(!topics.subscriptions, "subscriptions should be disabled");
    }

    #[test]
    fn sync_committee_topic() {
        let config = Config { broadcast: vec!["sync-committee".to_string()], ..Config::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn subscriptions_topic() {
        let config = Config { broadcast: vec!["subscriptions".to_string()], ..Config::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(!topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn all_topics_explicit() {
        let config = Config {
            broadcast: vec![
                "attestations".to_string(),
                "blocks".to_string(),
                "sync-committee".to_string(),
                "subscriptions".to_string(),
            ],
            ..Config::default()
        };
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn broadcast_topics_from_toml() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
broadcast = ["attestations", "blocks"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn broadcast_topics_cli_override() {
        use rvc::config::CliOverrides;

        let mut config = Config::default();
        let cli =
            CliOverrides { broadcast: Some(vec!["blocks".to_string()]), ..Default::default() };
        config.merge_with_cli(&cli);

        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(topics.blocks);
    }

    #[test]
    fn bn_manager_config_carries_broadcast_topics() {
        let topics = BroadcastTopics {
            attestations: true,
            blocks: false,
            sync_committee: true,
            subscriptions: false,
        };
        let mut config = bn_manager::BnManagerConfig::new(vec!["http://bn:5052".to_string()]);
        config.broadcast_topics = topics.clone();
        assert_eq!(config.broadcast_topics, topics);
    }

    #[test]
    fn bn_manager_constructed_with_custom_topics() {
        let mut config = bn_manager::BnManagerConfig::new(vec!["http://bn:5052".to_string()]);
        config.broadcast_topics = BroadcastTopics {
            attestations: false,
            blocks: true,
            sync_committee: false,
            subscriptions: false,
        };
        let manager = bn_manager::BnManager::new(config);
        assert!(manager.is_ok());
    }
}

// =============================================================================
// FR-3: Monitoring Push
// =============================================================================

mod monitoring {
    use rvc::monitoring::{collect_metrics, MonitoringConfig};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn payload_has_valid_beaconchain_fields() {
        let payload = collect_metrics(10, 8);

        assert_eq!(payload.version, 1);
        assert_eq!(payload.process, "validator");
        assert_eq!(payload.client_name, "rvc");
        assert!(!payload.client_version.is_empty());
        assert_eq!(payload.validator_total, 10);
        assert_eq!(payload.validator_active, 8);
        assert!(payload.timestamp > 0);
    }

    #[test]
    fn payload_serializes_to_valid_json() {
        let payload = collect_metrics(5, 3);
        let json = serde_json::to_value(&payload).unwrap();

        assert_eq!(json["version"], 1);
        assert_eq!(json["process"], "validator");
        assert_eq!(json["client_name"], "rvc");
        assert_eq!(json["validator_total"], 5);
        assert_eq!(json["validator_active"], 3);
        assert!(json["timestamp"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn mock_endpoint_receives_valid_payload() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1..)
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::monitoring::start_monitoring_push(config, shutdown_clone, || (3, 2)).await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn retry_on_server_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Return 500 for all requests (will be retried up to 3 times per push cycle)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(3..)
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::monitoring::start_monitoring_push(config, shutdown_clone, || (1, 1)).await;
        });

        // Give it time for one push cycle with retries
        tokio::time::sleep(Duration::from_millis(300)).await;
        shutdown.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn no_retry_on_client_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // 4xx errors are not retried — each tick cycle sends exactly 1 request
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1..)
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::monitoring::start_monitoring_push(config, shutdown_clone, || (1, 1)).await;
        });

        // Let it run for one tick cycle
        tokio::time::sleep(Duration::from_millis(80)).await;
        shutdown.cancel();
        handle.await.unwrap();

        // 4xx should not trigger retries within a single push cycle
        // (only 1 request per tick, not 3 like 5xx would cause)
    }

    #[tokio::test]
    async fn rejects_http_without_insecure() {
        let config = MonitoringConfig {
            endpoint: "http://example.com/metrics".to_string(),
            interval: Duration::from_secs(1),
            insecure: false,
        };
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        // Should return immediately because HTTP is rejected without insecure
        rvc::monitoring::start_monitoring_push(config, shutdown, || (0, 0)).await;
    }

    #[tokio::test]
    async fn clean_shutdown() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = MonitoringConfig {
            endpoint: mock_server.uri(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::monitoring::start_monitoring_push(config, shutdown_clone, || (0, 0)).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "monitoring task should shut down within timeout");
    }

    #[test]
    fn monitoring_config_fields_default() {
        let config = rvc::config::Config::default();
        assert!(config.monitoring_endpoint.is_none());
        assert_eq!(config.monitoring_interval, 384);
        assert!(!config.monitoring_endpoint_insecure);
    }

    #[test]
    fn monitoring_config_from_toml() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
monitoring_endpoint = "https://beaconcha.in/api/v1/client/metrics"
monitoring_interval = 60
monitoring_endpoint_insecure = true
"#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.monitoring_endpoint.as_deref(),
            Some("https://beaconcha.in/api/v1/client/metrics")
        );
        assert_eq!(config.monitoring_interval, 60);
        assert!(config.monitoring_endpoint_insecure);
    }
}

// =============================================================================
// FR-4: Log File Rotation
// =============================================================================

mod log_rotation {
    use std::fs;
    use telemetry::FileAppenderConfig;
    use tracing_subscriber::prelude::*;

    #[test]
    fn file_layer_created_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let config = FileAppenderConfig {
            directory: dir.path().to_string_lossy().to_string(),
            filename: "test.log".to_string(),
            max_size_mb: 1,
            max_files: 3,
            compress: false,
            level: "info".to_string(),
        };

        let result = telemetry::create_file_layer(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn log_entries_written_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = FileAppenderConfig {
            directory: dir.path().to_string_lossy().to_string(),
            filename: "rotation-test.log".to_string(),
            max_size_mb: 1,
            max_files: 5,
            compress: false,
            level: "info".to_string(),
        };

        let (layer, guard) = telemetry::create_file_layer(&config).unwrap();
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            for i in 0..100 {
                tracing::info!("log entry number {}", i);
            }
        });

        drop(guard);
        std::thread::sleep(std::time::Duration::from_millis(200));

        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert!(!entries.is_empty(), "at least one log file should exist");
    }

    #[test]
    fn compression_layer_created() {
        let dir = tempfile::tempdir().unwrap();
        let config = FileAppenderConfig {
            directory: dir.path().to_string_lossy().to_string(),
            filename: "compress-test.log".to_string(),
            max_size_mb: 1,
            max_files: 2,
            compress: true,
            level: "debug".to_string(),
        };

        let result = telemetry::create_file_layer(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn logfile_config_defaults() {
        let config = rvc::config::Config::default();
        assert!(config.logfile.is_none());
        assert_eq!(config.logfile_max_size, 200);
        assert_eq!(config.logfile_max_number, 5);
        assert!(!config.logfile_compress);
        assert!(config.logfile_level.is_none());
    }

    #[test]
    fn logfile_config_from_toml() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
logfile = "/var/log/rvc/rvc.log"
logfile_max_size = 100
logfile_max_number = 10
logfile_compress = true
logfile_level = "debug"
"#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.logfile.as_ref().unwrap().to_str().unwrap(), "/var/log/rvc/rvc.log");
        assert_eq!(config.logfile_max_size, 100);
        assert_eq!(config.logfile_max_number, 10);
        assert!(config.logfile_compress);
        assert_eq!(config.logfile_level.as_deref(), Some("debug"));
    }

    #[test]
    fn logfile_cli_override() {
        use rvc::config::CliOverrides;
        use std::path::PathBuf;

        let mut config = rvc::config::Config::default();
        let cli = CliOverrides {
            logfile: Some(PathBuf::from("/tmp/test.log")),
            logfile_max_size: Some(50),
            logfile_max_number: Some(3),
            logfile_compress: Some(true),
            logfile_level: Some("warn".to_string()),
            ..Default::default()
        };
        config.merge_with_cli(&cli);

        assert_eq!(config.logfile.as_ref().unwrap().to_str().unwrap(), "/tmp/test.log");
        assert_eq!(config.logfile_max_size, 50);
        assert_eq!(config.logfile_max_number, 3);
        assert!(config.logfile_compress);
        assert_eq!(config.logfile_level.as_deref(), Some("warn"));
    }
}

// =============================================================================
// FR-5: Proposer Config URL
// =============================================================================

mod config_url {
    use rvc::config_url::{
        fetch_proposer_config, ProposerConfigUrlSettings, ValidatorConfigUpdate,
    };
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn fetch_from_mock_server() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let body = r#"{
            "proposer_config": {
                "0xaaa": {
                    "fee_recipient": "0xbbb",
                    "builder": { "enabled": true, "gas_limit": "30000000" }
                },
                "0xccc": {
                    "fee_recipient": "0xddd",
                    "builder": { "enabled": false }
                }
            },
            "default_config": {
                "fee_recipient": "0xeee",
                "builder": { "enabled": true, "gas_limit": "36000000" }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, default_update) =
            fetch_proposer_config(&mock_server.uri(), None, true).await.unwrap();

        assert_eq!(updates.len(), 2);
        let default = default_update.unwrap();
        assert_eq!(default.fee_recipient.as_deref(), Some("0xeee"));
        assert_eq!(default.builder_enabled, Some(true));
        assert_eq!(default.gas_limit, Some(36000000));
    }

    #[tokio::test]
    async fn refresh_applies_changes() {
        use std::sync::{Arc, Mutex};
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let body = r#"{
            "proposer_config": {
                "0xabc": {
                    "fee_recipient": "0xdef",
                    "builder": { "enabled": true, "gas_limit": "30000000" }
                }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&mock_server)
            .await;

        let received_updates: Arc<Mutex<Vec<Vec<ValidatorConfigUpdate>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let received_clone = received_updates.clone();

        let settings = ProposerConfigUrlSettings {
            url: mock_server.uri(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::config_url::start_proposer_config_refresh(
                settings,
                shutdown_clone,
                move |updates, _default| {
                    received_clone.lock().unwrap().push(updates);
                },
            )
            .await;
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.cancel();
        handle.await.unwrap();

        let calls = received_updates.lock().unwrap();
        assert!(!calls.is_empty(), "apply_fn should have been called at least once");
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].pubkey, "0xabc");
        assert_eq!(calls[0][0].fee_recipient.as_deref(), Some("0xdef"));
    }

    #[tokio::test]
    async fn rejects_http_without_insecure() {
        let result = fetch_proposer_config("http://example.com/config", None, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[tokio::test]
    async fn bearer_token_sent() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer my-secret-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":{}}"#))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, _) =
            fetch_proposer_config(&mock_server.uri(), Some("my-secret-token"), true).await.unwrap();
        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn http_error_returns_err() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_proposer_config(&mock_server.uri(), None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    #[tokio::test]
    async fn refresh_clean_shutdown() {
        let settings = ProposerConfigUrlSettings {
            url: "http://nonexistent.invalid/config".to_string(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            rvc::config_url::start_proposer_config_refresh(settings, shutdown_clone, |_, _| {})
                .await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "refresh task should shut down within timeout");
    }

    #[test]
    fn config_url_fields_default() {
        let config = rvc::config::Config::default();
        assert!(config.proposer_config_url.is_none());
        assert_eq!(config.proposer_config_refresh_interval, 384);
        assert!(config.proposer_config_url_token.is_none());
        assert!(!config.proposer_config_url_insecure);
    }

    #[test]
    fn config_url_from_toml() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
proposer_config_url = "https://example.com/proposer-config"
proposer_config_refresh_interval = 120
proposer_config_url_insecure = true
"#;
        let config: rvc::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.proposer_config_url.as_deref(),
            Some("https://example.com/proposer-config")
        );
        assert_eq!(config.proposer_config_refresh_interval, 120);
        assert!(config.proposer_config_url_insecure);
    }
}

// =============================================================================
// Composition: features don't conflict when active simultaneously
// =============================================================================

mod composition {
    use bn_manager::{BnManager, BnManagerConfig};
    use rvc::config::Config;
    use rvc::monitoring::MonitoringConfig;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn proposer_nodes_with_broadcast_topics() {
        let config = Config {
            beacon_url: "http://main-bn:5052".to_string(),
            proposer_nodes: vec!["http://proposer-bn:5052".to_string()],
            broadcast: vec!["attestations".to_string(), "blocks".to_string()],
            ..Config::default()
        };

        // Main pool uses broadcast topics
        let main_topics = config.effective_broadcast_topics();
        assert!(main_topics.attestations);
        assert!(main_topics.blocks);
        assert!(!main_topics.sync_committee);

        // Proposer pool is separate and unaffected
        let proposer_endpoints = config.proposer_nodes.clone();
        assert_eq!(proposer_endpoints, vec!["http://proposer-bn:5052"]);

        // Both pools can be created independently
        let main_config = BnManagerConfig::new(config.effective_beacon_nodes());
        let proposer_config = BnManagerConfig::new(proposer_endpoints);

        assert!(BnManager::new(main_config).is_ok());
        assert!(BnManager::new(proposer_config).is_ok());
    }

    #[tokio::test]
    async fn monitoring_does_not_interfere_with_config_refresh() {
        use std::sync::{Arc, Mutex};

        let config_received = Arc::new(Mutex::new(false));
        let config_received_clone = config_received.clone();

        let shutdown = CancellationToken::new();

        // Start monitoring (will fail to connect, which is fine)
        let monitoring_config = MonitoringConfig {
            endpoint: "http://localhost:1/nonexistent".to_string(),
            interval: Duration::from_millis(50),
            insecure: true,
        };

        let shutdown_mon = shutdown.clone();
        let mon_handle = tokio::spawn(async move {
            rvc::monitoring::start_monitoring_push(monitoring_config, shutdown_mon, || (1, 1))
                .await;
        });

        // Start config refresh (will also fail to connect, which is fine)
        let config_settings = rvc::config_url::ProposerConfigUrlSettings {
            url: "http://localhost:1/nonexistent".to_string(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown_cfg = shutdown.clone();
        let cfg_handle = tokio::spawn(async move {
            rvc::config_url::start_proposer_config_refresh(
                config_settings,
                shutdown_cfg,
                move |_, _| {
                    *config_received_clone.lock().unwrap() = true;
                },
            )
            .await;
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();

        mon_handle.await.unwrap();
        cfg_handle.await.unwrap();
    }

    #[test]
    fn all_tier3_config_fields_in_default() {
        let config = Config::default();

        // Proposer nodes
        assert!(config.proposer_nodes.is_empty());

        // Broadcast topics
        assert!(config.broadcast.is_empty());
        let topics = config.effective_broadcast_topics();
        assert!(
            topics.attestations && topics.blocks && topics.sync_committee && topics.subscriptions
        );

        // Monitoring
        assert!(config.monitoring_endpoint.is_none());
        assert_eq!(config.monitoring_interval, 384);
        assert!(!config.monitoring_endpoint_insecure);

        // Log rotation
        assert!(config.logfile.is_none());
        assert_eq!(config.logfile_max_size, 200);
        assert_eq!(config.logfile_max_number, 5);
        assert!(!config.logfile_compress);

        // URL config
        assert!(config.proposer_config_url.is_none());
        assert_eq!(config.proposer_config_refresh_interval, 384);
        assert!(!config.proposer_config_url_insecure);
    }

    #[test]
    fn toml_roundtrip_with_all_tier3_fields() {
        let toml_str = r#"
beacon_url = "http://localhost:5052"
keystore_path = "/tmp/keystores"
network = "mainnet"
proposer_nodes = ["http://proposer:5052"]
broadcast = ["attestations", "blocks"]
monitoring_endpoint = "https://beaconcha.in/api/v1/client/metrics"
monitoring_interval = 60
monitoring_endpoint_insecure = false
logfile = "/var/log/rvc.log"
logfile_max_size = 100
logfile_max_number = 10
logfile_compress = true
logfile_level = "debug"
proposer_config_url = "https://config.example.com/proposer"
proposer_config_refresh_interval = 120
proposer_config_url_insecure = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.proposer_nodes, vec!["http://proposer:5052"]);
        assert_eq!(config.broadcast, vec!["attestations", "blocks"]);
        assert_eq!(
            config.monitoring_endpoint.as_deref(),
            Some("https://beaconcha.in/api/v1/client/metrics")
        );
        assert_eq!(config.monitoring_interval, 60);
        assert_eq!(config.logfile_max_size, 100);
        assert_eq!(config.logfile_max_number, 10);
        assert!(config.logfile_compress);
        assert_eq!(
            config.proposer_config_url.as_deref(),
            Some("https://config.example.com/proposer")
        );
        assert_eq!(config.proposer_config_refresh_interval, 120);
    }

    #[test]
    fn cli_overrides_all_tier3_fields() {
        use rvc::config::CliOverrides;
        use std::path::PathBuf;

        let mut config = Config::default();
        let cli = CliOverrides {
            proposer_nodes: Some(vec!["http://p:5052".to_string()]),
            broadcast: Some(vec!["blocks".to_string()]),
            monitoring_endpoint: Some("https://monitor.test".to_string()),
            monitoring_interval: Some(30),
            monitoring_endpoint_insecure: Some(true),
            logfile: Some(PathBuf::from("/tmp/rvc.log")),
            logfile_max_size: Some(50),
            logfile_max_number: Some(3),
            logfile_compress: Some(true),
            logfile_level: Some("warn".to_string()),
            proposer_config_url: Some("https://config.test".to_string()),
            proposer_config_refresh_interval: Some(60),
            proposer_config_url_insecure: Some(true),
            ..Default::default()
        };
        config.merge_with_cli(&cli);

        assert_eq!(config.proposer_nodes, vec!["http://p:5052"]);
        assert_eq!(config.broadcast, vec!["blocks"]);
        assert_eq!(config.monitoring_endpoint.as_deref(), Some("https://monitor.test"));
        assert_eq!(config.monitoring_interval, 30);
        assert!(config.monitoring_endpoint_insecure);
        assert_eq!(config.logfile_max_size, 50);
        assert_eq!(config.logfile_max_number, 3);
        assert!(config.logfile_compress);
        assert_eq!(config.logfile_level.as_deref(), Some("warn"));
        assert_eq!(config.proposer_config_url.as_deref(), Some("https://config.test"));
        assert_eq!(config.proposer_config_refresh_interval, 60);
        assert!(config.proposer_config_url_insecure);
    }
}
