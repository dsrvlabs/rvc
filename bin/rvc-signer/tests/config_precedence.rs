//! In-process config merge, hot-reload, metrics, and audit coverage ported from
//! the former `src/integration_polish.rs` unit suite (RF5-18).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use zeroize::Zeroizing;

use rvc_signer_bin::backend::basic::BasicSigner;
use rvc_signer_bin::backend::SigningBackend;
use rvc_signer_bin::config::{self, Backend, ServeArgs};
use rvc_signer_bin::metrics::SignerMetrics;
use rvc_signer_bin::reload::KeystoreReloader;

mod common;

use common::create_test_keystore;

fn write_toml(dir: &Path, content: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, content).unwrap();
    path
}

fn empty_cli() -> ServeArgs {
    ServeArgs::default()
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
    let resolved = config::merge_with_cli(cfg, &empty_cli()).unwrap();

    assert_eq!(resolved.listen_address, "0.0.0.0:9999");
    assert_eq!(resolved.keystore_dir, ks_dir);
    assert_eq!(resolved.password_file.unwrap(), pw_path);
    assert_eq!(resolved.backend, Backend::Basic);
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

    let cli = ServeArgs { listen_address: Some("10.0.0.1:8080".to_string()), ..empty_cli() };

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

    let cli = ServeArgs { reload_interval: Some(5), ..empty_cli() };

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

    let pubkey = create_test_keystore(dir.path(), &password);

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    let reloader_handle = tokio::spawn(async move {
        reloader.run(cancel_clone).await;
    });

    // Poll until the reloader picks up the new key (avoid fixed sleeps).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let keys = signer.public_keys();
        if keys.len() == 1 && keys.contains(&pubkey) {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("hot-reload did not detect new keystore within timeout");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

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

    let pk1 = create_test_keystore(dir.path(), &password);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while signer.public_keys().len() < 1 {
        if tokio::time::Instant::now() >= deadline {
            panic!("first key not reloaded");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(signer.public_keys().len(), 1);

    let pk2 = create_test_keystore(dir.path(), &password);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while signer.public_keys().len() < 2 {
        if tokio::time::Instant::now() >= deadline {
            panic!("second key not reloaded");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let keys = signer.public_keys();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&pk1));
    assert!(keys.contains(&pk2));

    cancel.cancel();
    reloader_handle.await.unwrap();
}

// --- 4. Metrics endpoint ---

#[tokio::test]
async fn test_metrics_endpoint_serves_prometheus_text() {
    let metrics = Arc::new(SignerMetrics::new());
    metrics.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();
    metrics.sign_total.with_label_values(&["basic", "beacon_block", "success"]).inc();
    metrics.keys_loaded.with_label_values(&["basic"]).set(3.0);

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (handle, bound_addr) =
        rvc_signer_bin::metrics::serve_metrics(addr, Arc::clone(&metrics)).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

    let mut buf = vec![0u8; 16384];
    // Read with a short timeout-ish loop until we see a body.
    let mut n = 0;
    for _ in 0..20 {
        n = stream.read(&mut buf).await.unwrap();
        if n > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let response = String::from_utf8_lossy(&buf[..n]);

    assert!(response.contains("200 OK") || response.contains("HTTP/1.1"), "got: {response}");
    assert!(
        response.contains("rvc_signer_sign_total") || response.contains("rvc_signer_keys_loaded"),
        "metrics body missing expected series; response: {response}"
    );
    assert!(
        response.contains("rvc_signer_keys_loaded"),
        "metrics should include keys_loaded gauge"
    );

    handle.abort();
}

// --- 5. Dry-run: valid config resolves; invalid cert detected in-process ---

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
    let resolved = config::merge_with_cli(cfg, &empty_cli()).unwrap();

    assert!(resolved.dry_run, "dry_run should be true from config");
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
    let cli = ServeArgs { dry_run: true, ..empty_cli() };
    let resolved = config::merge_with_cli(cfg, &cli).unwrap();

    assert!(resolved.dry_run, "CLI --dry-run should override config");
}

#[test]
fn test_dry_run_invalid_tls_cert_detected() {
    let dir = TempDir::new().unwrap();

    let tls = rvc_signer_bin::grpc_tls::TlsConfig::new(
        dir.path().join("nonexistent.pem"),
        dir.path().join("nonexistent.key"),
        dir.path().join("nonexistent-ca.pem"),
    );

    let result = tls.to_server_tls_config();
    assert!(result.is_err(), "missing cert should produce error during dry-run validation");
}

// --- 6. Audit log ---

#[test]
fn test_audit_entry_fields_populated() {
    let entry = rvc_signer_bin::audit::AuditEntry {
        timestamp: rvc_signer_bin::audit::now_rfc3339(),
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

#[test]
fn test_audit_extract_cn_without_tls_returns_unknown() {
    let request = tonic::Request::new(());
    let cn = rvc_signer_bin::audit::extract_client_cn(&request);
    assert_eq!(cn, "unknown");
}

#[test]
fn test_audit_extract_cn_from_der_known_cert() {
    use rcgen::DnType;

    let mut params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, "integration-test-client");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();

    let cn = rvc_signer_bin::audit::cn::extract_cn_from_der(cert.der().as_ref());
    assert_eq!(cn, Some("integration-test-client".to_string()));
}

/// Metrics infrastructure (keys_loaded, encode) still works after RF2-17
/// removed the v1 sign surface that previously exercised counters here.
#[tokio::test]
async fn test_metrics_keys_loaded_and_encode_intact() {
    let metrics = Arc::new(SignerMetrics::new());
    metrics.keys_loaded.with_label_values(&["basic"]).set(1.0);

    assert_eq!(metrics.keys_loaded.with_label_values(&["basic"]).get(), 1.0);

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
    let resolved = config::merge_with_cli(cfg, &empty_cli()).unwrap();

    assert_eq!(resolved.listen_address, "0.0.0.0:50052");
    assert_eq!(resolved.backend, Backend::Basic);
    assert!(!resolved.dry_run);
    assert_eq!(resolved.reload_interval_secs, 5);
}

// --- RF5-23: explicit CLI default-equal wins over file (end-to-end via resolve) ---

#[test]
fn test_explicit_cli_default_equal_listen_address_beats_file() {
    let dir = TempDir::new().unwrap();
    let ks_dir = dir.path().join("keystores");
    std::fs::create_dir(&ks_dir).unwrap();

    let config_path = write_toml(
        dir.path(),
        &format!(
            r#"
[signer]
listen_address = "0.0.0.0:9999"
keystore_dir = "{}"
"#,
            ks_dir.display(),
        ),
    );

    let args = ServeArgs {
        config: Some(config_path),
        listen_address: Some(config::DEFAULT_LISTEN_ADDRESS.to_string()),
        ..empty_cli()
    };
    let resolved = config::resolve_config(&args).unwrap();
    assert_eq!(
        resolved.listen_address,
        config::DEFAULT_LISTEN_ADDRESS,
        "explicit --listen-address equal to built-in default must beat config file"
    );
}
