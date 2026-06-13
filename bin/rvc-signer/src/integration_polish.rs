#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use crate::backend::basic::BasicSigner;
    use crate::backend::SigningBackend;
    use crate::config::{self, CliOverrides};
    use crate::metrics::SignerMetrics;
    use crate::reload::KeystoreReloader;
    use crate::service::SignerServiceImpl;
    use crate::SignerService;

    // --- Helpers ---

    fn bin_path() -> &'static str {
        static BIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        BIN.get_or_init(|| {
            // Build the binary first via cargo build
            let status = std::process::Command::new("cargo")
                .args(["build", "-p", "rvc-signer-bin"])
                .status()
                .expect("failed to run cargo build");
            assert!(status.success(), "cargo build failed");

            let test_exe = std::env::current_exe().expect("current_exe");
            let dir = test_exe.parent().expect("parent dir");
            let target_dir = if dir.ends_with("deps") { dir.parent().unwrap() } else { dir };
            target_dir.join("rvc-signer").to_string_lossy().to_string()
        })
    }

    fn create_test_keystore(dir: &Path, password: &str) -> [u8; 48] {
        use crypto::{EncryptionKdf, Keystore, SecretKey};
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let ks = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let filename = format!("{}.json", hex::encode(pubkey));
        std::fs::write(dir.join(&filename), ks.to_json().unwrap()).unwrap();
        pubkey
    }

    fn write_toml(dir: &Path, content: &str) -> std::path::PathBuf {
        let path = dir.join("config.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn default_cli_overrides() -> CliOverrides<'static> {
        CliOverrides {
            listen_address: "127.0.0.1:50052",
            listen_address_is_default: true,
            keystore_dir: None,
            password_dir: None,
            password_file: None,
            backend: "basic",
            backend_is_default: true,
            dry_run: false,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            reload_interval: 30,
            reload_interval_is_default: true,
            enable_hot_reload: false,
            dvt_peers: &[],
            dvt_threshold: None,
            dvt_index: None,
            dvt_timeout: 2000,
            dvt_timeout_is_default: true,
        }
    }

    // --- 1. Config.toml E2E: all settings applied ---

    #[test]
    fn test_config_toml_e2e_all_settings_applied() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let pw_path = dir.path().join("password.txt");
        std::fs::write(&pw_path, "test-password").unwrap();

        let config_path = write_toml(
            dir.path(),
            &format!(
                r#"
[signer]
listen_address = "0.0.0.0:9999"
keystore_dir = "{ks}"
password_file = "{pw}"
backend = "basic"
reload_interval_secs = 10
"#,
                ks = ks_dir.display(),
                pw = pw_path.display(),
            ),
        );

        let cfg = config::load_config(&config_path).unwrap();
        let resolved = config::merge_with_cli(cfg, &default_cli_overrides()).unwrap();

        assert_eq!(resolved.listen_address, "0.0.0.0:9999");
        assert_eq!(resolved.keystore_dir, ks_dir);
        assert_eq!(resolved.password_file.unwrap(), pw_path);
        assert_eq!(resolved.backend, "basic");
        assert_eq!(resolved.reload_interval_secs, 10);
        assert!(!resolved.dry_run);
    }

    // --- 2. CLI override: config has address A, CLI overrides to B ---

    #[test]
    fn test_cli_overrides_config_listen_address() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let config_path = write_toml(
            dir.path(),
            &format!(
                r#"
[signer]
listen_address = "0.0.0.0:9000"
keystore_dir = "{}"
"#,
                ks_dir.display(),
            ),
        );

        let cfg = config::load_config(&config_path).unwrap();

        let cli = CliOverrides {
            listen_address: "10.0.0.1:8080",
            listen_address_is_default: false,
            ..default_cli_overrides()
        };

        let resolved = config::merge_with_cli(cfg, &cli).unwrap();
        assert_eq!(
            resolved.listen_address, "10.0.0.1:8080",
            "CLI should override config listen_address"
        );
    }

    #[test]
    fn test_cli_overrides_config_reload_interval() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let config_path = write_toml(
            dir.path(),
            &format!(
                r#"
[signer]
keystore_dir = "{}"
reload_interval_secs = 60
"#,
                ks_dir.display(),
            ),
        );

        let cfg = config::load_config(&config_path).unwrap();

        let cli = CliOverrides {
            reload_interval: 5,
            reload_interval_is_default: false,
            ..default_cli_overrides()
        };

        let resolved = config::merge_with_cli(cfg, &cli).unwrap();
        assert_eq!(resolved.reload_interval_secs, 5, "CLI should override config reload_interval");
    }

    // --- 3. Hot-reload: add keystore file, verify key available ---

    #[tokio::test]
    async fn test_hot_reload_new_key_available() {
        let dir = TempDir::new().unwrap();
        // ISSUE-4.6: tighten test dir to 0o700 so the L-6 perm-check passes.
        #[cfg(unix)]
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let password = Zeroizing::new("test-password".to_string());

        let signer = Arc::new(BasicSigner::load(dir.path(), &password).unwrap());
        assert!(signer.public_keys().is_empty(), "should start with no keys");

        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        // Add a keystore file to the directory
        let pubkey = create_test_keystore(dir.path(), &password);

        // Start reloader with cancellation
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();
        let reloader_handle = tokio::spawn(async move {
            reloader.run(cancel_clone).await;
        });

        // Wait for at least one reload cycle
        tokio::time::sleep(Duration::from_millis(200)).await;

        let keys = signer.public_keys();
        assert_eq!(keys.len(), 1, "hot-reload should detect new keystore");
        assert!(keys.contains(&pubkey));

        // SS-1 (Issue 2.2): v1 list_public_keys returns Unimplemented.
        // Verify availability directly via the backend (already confirmed above).
        let backend_keys = signer.public_keys();
        assert_eq!(backend_keys.len(), 1, "backend reports one key after hot-reload");

        cancel.cancel();
        reloader_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_hot_reload_multiple_keys_added_incrementally() {
        let dir = TempDir::new().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let password = Zeroizing::new("test-password".to_string());

        let signer = Arc::new(BasicSigner::load(dir.path(), &password).unwrap());

        let reloader = KeystoreReloader::new(
            dir.path().to_path_buf(),
            password.clone(),
            Duration::from_millis(50),
            Arc::clone(&signer),
        );

        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();
        let reloader_handle = tokio::spawn(async move {
            reloader.run(cancel_clone).await;
        });

        // Add first key
        let pk1 = create_test_keystore(dir.path(), &password);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(signer.public_keys().len(), 1);

        // Add second key
        let pk2 = create_test_keystore(dir.path(), &password);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let keys = signer.public_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&pk1));
        assert!(keys.contains(&pk2));

        cancel.cancel();
        reloader_handle.await.unwrap();
    }

    // --- 4. Metrics: v1 sign returns Unimplemented without touching counters ---
    // SS-1 (Issue 2.2): v1 sign no longer drives the metrics counters.
    // The metrics system is independently tested; this test confirms v1 calls
    // return Unimplemented immediately and leave counters at zero.

    #[tokio::test]
    async fn test_v1_sign_returns_unimplemented_leaves_counters_at_zero() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);

        let signer = Arc::new(BasicSigner::load(dir.path(), &password).unwrap());
        let metrics = Arc::new(SignerMetrics::new());

        let svc = SignerServiceImpl::new(
            Arc::clone(&signer) as Arc<dyn SigningBackend>,
            "basic".to_string(),
        )
        .with_metrics(Arc::clone(&metrics));

        // v1 sign — must return Unimplemented
        let req = tonic::Request::new(crate::SignRequest {
            signing_root: vec![0u8; 32],
            pubkey: pubkey.to_vec(),
        });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented, "v1 sign must return Unimplemented");

        // v1 sign with unknown key — also Unimplemented (not NotFound)
        let req = tonic::Request::new(crate::SignRequest {
            signing_root: vec![0u8; 32],
            pubkey: vec![0u8; 48],
        });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        // Counters must remain at zero — Unimplemented path does not touch metrics
        assert_eq!(metrics.sign_total.with_label_values(&["basic", "success"]).get(), 0);
        assert_eq!(metrics.sign_total.with_label_values(&["basic", "error"]).get(), 0);
        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(),
            0
        );
        assert_eq!(
            metrics.sign_duration_seconds.with_label_values(&["basic"]).get_sample_count(),
            0,
            "Unimplemented path must not record duration"
        );
    }

    #[tokio::test]
    async fn test_metrics_endpoint_serves_prometheus_text() {
        let metrics = Arc::new(SignerMetrics::new());
        metrics.sign_total.with_label_values(&["basic", "success"]).inc();
        metrics.sign_total.with_label_values(&["basic", "success"]).inc();
        metrics.keys_loaded.with_label_values(&["basic"]).set(3.0);

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (handle, bound_addr) =
            crate::metrics::serve_metrics(addr, Arc::clone(&metrics)).await.unwrap();

        // Scrape the metrics endpoint
        let mut stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut buf = vec![0u8; 16384];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(response.contains("200 OK"));
        assert!(response.contains("rvc_signer_sign_total"));
        assert!(
            response.contains("rvc_signer_keys_loaded"),
            "metrics should include keys_loaded gauge"
        );

        handle.abort();
    }

    // --- 5. Dry-run: valid config → exit 0; invalid cert → exit 1 ---

    #[test]
    fn test_dry_run_valid_config_resolves() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let config_path = write_toml(
            dir.path(),
            &format!(
                r#"
[signer]
keystore_dir = "{}"
dry_run = true
"#,
                ks_dir.display(),
            ),
        );

        let cfg = config::load_config(&config_path).unwrap();
        let resolved = config::merge_with_cli(cfg, &default_cli_overrides()).unwrap();

        assert!(resolved.dry_run, "dry_run should be true from config");
        // Verify the config is valid — no error from load + merge
    }

    #[test]
    fn test_dry_run_cli_flag_overrides_config() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let config_path = write_toml(
            dir.path(),
            &format!(
                r#"
[signer]
keystore_dir = "{}"
"#,
                ks_dir.display(),
            ),
        );

        let cfg = config::load_config(&config_path).unwrap();
        let cli = CliOverrides { dry_run: true, ..default_cli_overrides() };
        let resolved = config::merge_with_cli(cfg, &cli).unwrap();

        assert!(resolved.dry_run, "CLI --dry-run should override config");
    }

    #[test]
    fn test_dry_run_invalid_tls_cert_detected() {
        let dir = TempDir::new().unwrap();

        let tls = crate::tls::TlsConfig::new(
            dir.path().join("nonexistent.pem"),
            dir.path().join("nonexistent.key"),
            dir.path().join("nonexistent-ca.pem"),
        );

        let result = tls.to_server_tls_config();
        assert!(result.is_err(), "missing cert should produce error during dry-run validation");
    }

    #[test]
    #[ignore] // Requires pre-built binary; fails under cargo llvm-cov
    fn test_dry_run_binary_exit_code_valid() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let pw_path = dir.path().join("password.txt");
        std::fs::write(&pw_path, "test-password").unwrap();

        // Build the binary path from CARGO_BIN_EXE
        let binary = bin_path();
        let output = std::process::Command::new(binary)
            .args([
                "serve",
                "--dry-run",
                "--keystore-dir",
                &ks_dir.to_string_lossy(),
                "--password-file",
                &pw_path.to_string_lossy(),
            ])
            .output()
            .expect("failed to execute rvc-signer");

        assert!(
            output.status.success(),
            "dry-run with valid config should exit 0, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Configuration valid"), "should print validation summary");
    }

    #[test]
    #[ignore] // Requires pre-built binary; fails under cargo llvm-cov
    fn test_dry_run_binary_exit_code_invalid_tls() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let pw_path = dir.path().join("password.txt");
        std::fs::write(&pw_path, "test-password").unwrap();

        let binary = bin_path();
        let output = std::process::Command::new(binary)
            .args([
                "serve",
                "--dry-run",
                "--keystore-dir",
                &ks_dir.to_string_lossy(),
                "--password-file",
                &pw_path.to_string_lossy(),
                "--tls-cert",
                "/nonexistent/cert.pem",
                "--tls-key",
                "/nonexistent/key.pem",
                "--tls-ca-cert",
                "/nonexistent/ca.pem",
            ])
            .output()
            .expect("failed to execute rvc-signer");

        assert!(!output.status.success(), "dry-run with invalid TLS certs should exit non-zero");
    }

    // --- 6. Audit log: sign request → audit entry ---

    #[test]
    fn test_audit_entry_fields_populated() {
        let entry = crate::audit::AuditEntry {
            timestamp: crate::audit::now_rfc3339(),
            pubkey_hex: "0x0102030405060708".to_string(),
            client_cn: "validator-client.local".to_string(),
            backend: "basic".to_string(),
            result: "success".to_string(),
            duration_ms: 42,
            rpc: None,
        };

        assert!(!entry.timestamp.is_empty());
        assert!(entry.timestamp.ends_with('Z'));
        assert_eq!(entry.pubkey_hex, "0x0102030405060708");
        assert_eq!(entry.client_cn, "validator-client.local");
        assert_eq!(entry.backend, "basic");
        assert_eq!(entry.result, "success");
        assert_eq!(entry.duration_ms, 42);
    }

    // SS-1 (Issue 2.2): v1 sign is Unimplemented — no audit log is emitted.
    // The test is repurposed to confirm v1 returns Unimplemented immediately.
    // Audit-log coverage for v2 sign paths is in `bin/rvc-signer/tests/audit_log_m5.rs`.
    #[tokio::test]
    async fn test_v1_sign_returns_unimplemented_no_audit_log() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);

        let signer = Arc::new(BasicSigner::load(dir.path(), &password).unwrap());
        let svc = SignerServiceImpl::new(
            Arc::clone(&signer) as Arc<dyn SigningBackend>,
            "basic".to_string(),
        );

        let req = tonic::Request::new(crate::SignRequest {
            signing_root: vec![0u8; 32],
            pubkey: pubkey.to_vec(),
        });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::Unimplemented,
            "v1 sign must return Unimplemented (SS-1 fix)"
        );
    }

    #[test]
    fn test_audit_extract_cn_without_tls_returns_unknown() {
        let request = tonic::Request::new(());
        let cn = crate::audit::extract_client_cn(&request);
        assert_eq!(cn, "unknown");
    }

    #[test]
    fn test_audit_extract_cn_from_der_known_cert() {
        use rcgen::DnType;

        let mut params =
            rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "integration-test-client");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let cn = crate::audit::cn::extract_cn_from_der(cert.der().as_ref());
        assert_eq!(cn, Some("integration-test-client".to_string()));
    }

    // --- Cross-cutting: v1 methods return Unimplemented; metrics/keys_loaded still work ---
    // SS-1 (Issue 2.2): v1 sign and get_status are Unimplemented.
    // This test was previously a full v1 sign round-trip; it now confirms the Unimplemented
    // behavior and that the metrics infrastructure (keys_loaded, encode) is unaffected.

    #[tokio::test]
    async fn test_v1_sign_and_get_status_unimplemented_metrics_infra_intact() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let pubkey = create_test_keystore(dir.path(), &password);

        let signer = Arc::new(BasicSigner::load(dir.path(), &password).unwrap());
        let metrics = Arc::new(SignerMetrics::new());
        metrics.keys_loaded.with_label_values(&["basic"]).set(1.0);

        let svc = SignerServiceImpl::new(
            Arc::clone(&signer) as Arc<dyn SigningBackend>,
            "basic".to_string(),
        )
        .with_metrics(Arc::clone(&metrics));

        // v1 sign — must return Unimplemented (3 calls, all Unimplemented)
        for _ in 0..3 {
            let req = tonic::Request::new(crate::SignRequest {
                signing_root: vec![42u8; 32],
                pubkey: pubkey.to_vec(),
            });
            let err = svc.sign(req).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unimplemented);
        }

        // v1 sign unknown key — also Unimplemented (not NotFound)
        let req = tonic::Request::new(crate::SignRequest {
            signing_root: vec![0u8; 32],
            pubkey: vec![99u8; 48],
        });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        // v1 sign counters must remain at zero
        assert_eq!(metrics.sign_total.with_label_values(&["basic", "success"]).get(), 0);
        assert_eq!(metrics.sign_total.with_label_values(&["basic", "error"]).get(), 0);

        // keys_loaded gauge still works (set above)
        assert_eq!(metrics.keys_loaded.with_label_values(&["basic"]).get(), 1.0);

        // v1 get_status — also Unimplemented
        let err =
            svc.get_status(tonic::Request::new(crate::GetStatusRequest {})).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        // Metrics scrape still encodes correctly (metrics infra not broken)
        let encoded = metrics.encode().unwrap();
        let text = String::from_utf8(encoded).unwrap();
        assert!(text.contains("rvc_signer_keys_loaded"));
    }

    // --- Config.toml with dry_run + reload_interval together ---

    #[test]
    fn test_config_toml_all_phase3_settings() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let config_path = write_toml(
            dir.path(),
            &format!(
                r#"
[signer]
listen_address = "0.0.0.0:50052"
keystore_dir = "{ks}"
backend = "basic"
dry_run = false
reload_interval_secs = 5
"#,
                ks = ks_dir.display(),
            ),
        );

        let cfg = config::load_config(&config_path).unwrap();
        let resolved = config::merge_with_cli(cfg, &default_cli_overrides()).unwrap();

        assert_eq!(resolved.listen_address, "0.0.0.0:50052");
        assert_eq!(resolved.backend, "basic");
        assert!(!resolved.dry_run);
        assert_eq!(resolved.reload_interval_secs, 5);
    }

    // --- Dry-run with config.toml ---

    #[test]
    #[ignore] // Requires pre-built binary; fails under cargo llvm-cov
    fn test_dry_run_binary_with_config_toml() {
        let dir = TempDir::new().unwrap();
        let ks_dir = dir.path().join("keystores");
        std::fs::create_dir(&ks_dir).unwrap();

        let pw_path = dir.path().join("password.txt");
        std::fs::write(&pw_path, "test-password").unwrap();

        // Create a keystore so we can verify key count in dry-run output
        create_test_keystore(&ks_dir, "test-password");

        let config_path = write_toml(
            dir.path(),
            &format!(
                r#"
[signer]
keystore_dir = "{ks}"
password_file = "{pw}"
backend = "basic"
"#,
                ks = ks_dir.display(),
                pw = pw_path.display(),
            ),
        );

        let binary = bin_path();
        let output = std::process::Command::new(binary)
            .args(["serve", "--dry-run", "--config", &config_path.to_string_lossy()])
            .output()
            .expect("failed to execute rvc-signer");

        assert!(
            output.status.success(),
            "dry-run with config.toml should exit 0, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Configuration valid"));
        assert!(stdout.contains("Keys loaded: 1"));
        assert!(stdout.contains("Backend: basic"));
    }
}
