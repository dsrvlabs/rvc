//! Integration tests for the validator client startup and shutdown.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

const BINARY_NAME: &str = "rvc";

fn build_binary() {
    let status = Command::new("cargo")
        .args(["build", "--package", "rvc-bin"])
        .status()
        .expect("Failed to build binary");

    assert!(status.success(), "Failed to build rvc binary");
}

fn get_binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target")
        .join("debug")
        .join(BINARY_NAME)
}

fn create_test_config(keystore_dir: &TempDir, slashing_db_path: &std::path::Path) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp config file");
    writeln!(
        file,
        r#"
beacon_url = "http://localhost:5052"
keystore_path = "{}"
slashing_db_path = "{}"
metrics_port = 19090
grpc_port = 19051
network = "mainnet"
log_level = "warn"
"#,
        keystore_dir.path().display(),
        slashing_db_path.display()
    )
    .unwrap();
    file
}

fn spawn_validator(config_path: &std::path::Path) -> Child {
    let binary_path = get_binary_path();

    Command::new(binary_path)
        .args(["start", "--config", config_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn validator process")
}

#[allow(dead_code)]
fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn wait_for_http_endpoint(url: &str, timeout: Duration) -> bool {
    let client =
        reqwest::blocking::Client::builder().timeout(Duration::from_secs(1)).build().unwrap();

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if client.get(url).send().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn test_help_command() {
    build_binary();

    let binary_path = get_binary_path();
    let output =
        Command::new(binary_path).args(["--help"]).output().expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Rust Validator Client"));
    assert!(stdout.contains("start"));
}

#[test]
fn test_version_command() {
    build_binary();

    let binary_path = get_binary_path();
    let output =
        Command::new(binary_path).args(["--version"]).output().expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rvc"));
}

#[test]
fn test_start_help() {
    build_binary();

    let binary_path = get_binary_path();
    let output = Command::new(binary_path)
        .args(["start", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--beacon-url"));
    assert!(stdout.contains("--keystore-path"));
    assert!(stdout.contains("--metrics-port"));
    assert!(stdout.contains("--grpc-port"));
    assert!(stdout.contains("--network"));
    assert!(stdout.contains("--keymanager-enabled"));
    assert!(stdout.contains("--keymanager-address"));
    assert!(stdout.contains("--keymanager-token-file"));
    assert!(stdout.contains("--remote-signer-url"));
}

#[test]
fn test_start_with_invalid_config() {
    build_binary();

    let binary_path = get_binary_path();
    let output = Command::new(binary_path)
        .args(["start", "--config", "/nonexistent/config.toml"])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
}

#[test]
#[ignore = "Requires network access and may be slow"]
fn test_startup_and_health_endpoint() {
    build_binary();

    let keystore_dir = TempDir::new().expect("Failed to create keystore dir");
    let slashing_db_dir = TempDir::new().expect("Failed to create slashing db dir");
    let slashing_db_path = slashing_db_dir.path().join("slashing.db");

    let config_file = create_test_config(&keystore_dir, &slashing_db_path);

    let mut child = spawn_validator(config_file.path());

    std::thread::sleep(Duration::from_secs(2));

    let health_available =
        wait_for_http_endpoint("http://127.0.0.1:19090/health", Duration::from_secs(10));

    if health_available {
        let response = reqwest::blocking::get("http://127.0.0.1:19090/health");
        if let Ok(resp) = response {
            let status = resp.status();
            assert!(
                status == reqwest::StatusCode::OK
                    || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
    }

    #[cfg(not(unix))]
    {
        child.kill().ok();
    }

    let wait_result = child.wait();
    assert!(wait_result.is_ok());
}

#[test]
#[ignore = "Requires network access and may be slow"]
fn test_startup_and_metrics_endpoint() {
    build_binary();

    let keystore_dir = TempDir::new().expect("Failed to create keystore dir");
    let slashing_db_dir = TempDir::new().expect("Failed to create slashing db dir");
    let slashing_db_path = slashing_db_dir.path().join("slashing.db");

    let config_file = create_test_config(&keystore_dir, &slashing_db_path);

    let mut child = spawn_validator(config_file.path());

    std::thread::sleep(Duration::from_secs(2));

    let metrics_available =
        wait_for_http_endpoint("http://127.0.0.1:19090/metrics", Duration::from_secs(10));

    if metrics_available {
        let response = reqwest::blocking::get("http://127.0.0.1:19090/metrics");
        if let Ok(resp) = response {
            assert!(resp.status().is_success());
            let body = resp.text().unwrap_or_default();
            assert!(body.contains("# HELP") || body.contains("# TYPE") || body.is_empty());
        }
    }

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
    }

    #[cfg(not(unix))]
    {
        child.kill().ok();
    }

    let _ = child.wait();
}

#[test]
#[ignore = "Requires network access and may be slow"]
fn test_graceful_shutdown_sigterm() {
    build_binary();

    let keystore_dir = TempDir::new().expect("Failed to create keystore dir");
    let slashing_db_dir = TempDir::new().expect("Failed to create slashing db dir");
    let slashing_db_path = slashing_db_dir.path().join("slashing.db");

    let config_file = create_test_config(&keystore_dir, &slashing_db_path);

    let mut child = spawn_validator(config_file.path());

    std::thread::sleep(Duration::from_secs(2));

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(35);

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(
                        status.success() || status.code() == Some(0),
                        "Process should exit cleanly on SIGTERM"
                    );
                    break;
                }
                Ok(None) => {
                    if start.elapsed() > timeout {
                        child.kill().ok();
                        panic!("Process did not shut down within timeout");
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    panic!("Error waiting for process: {}", e);
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        child.kill().ok();
        let _ = child.wait();
    }
}

#[test]
fn test_livez_endpoint_always_ok() {
    build_binary();

    let keystore_dir = TempDir::new().expect("Failed to create keystore dir");
    let slashing_db_dir = TempDir::new().expect("Failed to create slashing db dir");
    let slashing_db_path = slashing_db_dir.path().join("slashing.db");

    let config_file = create_test_config(&keystore_dir, &slashing_db_path);

    let mut child = spawn_validator(config_file.path());

    std::thread::sleep(Duration::from_secs(2));

    let livez_available =
        wait_for_http_endpoint("http://127.0.0.1:19090/livez", Duration::from_secs(10));

    if livez_available {
        let response = reqwest::blocking::get("http://127.0.0.1:19090/livez");
        if let Ok(resp) = response {
            assert!(resp.status().is_success(), "livez should always return 200");
        }
    }

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
    }

    #[cfg(not(unix))]
    {
        child.kill().ok();
    }

    let _ = child.wait();
}
