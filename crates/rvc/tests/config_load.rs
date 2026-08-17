//! ARCH-4i: `Config::load` precedence (defaults < file < CLI).
//!
//! Test names do not end in `_root` (KAT scan / A-4.9).

use std::io::Write;
use std::net::{IpAddr, SocketAddr};

use rvc::config::{Config, ConfigSource, StartArgs};
use tempfile::NamedTempFile;

#[test]
fn config_load_applies_defaults_then_file_then_cli() {
    let defaults = Config::load(None, StartArgs::default()).expect("defaults");
    assert_eq!(defaults.metrics_port, 8080);

    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "metrics_port = 9090").unwrap();
    let file_only = Config::load(Some(file.path()), StartArgs::default()).expect("file");
    assert_eq!(file_only.metrics_port, 9090);

    let mut cli = StartArgs::default();
    cli.server.metrics_port = Some(9100);
    let with_cli = Config::load(Some(file.path()), cli).expect("file+cli");
    assert_eq!(with_cli.metrics_port, 9100);
}

#[test]
fn toml_metrics_port_9090_binds_9090() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
metrics_address = "127.0.0.1"
metrics_port = 9090
"#
    )
    .unwrap();
    let cfg = Config::load(Some(file.path()), StartArgs::default()).expect("load");
    assert_eq!(cfg.metrics_port, 9090, "ADR-009: TOML 9090 must survive absent --metrics-port");
    let addr = SocketAddr::new(cfg.metrics_address, cfg.metrics_port);
    assert_eq!(addr.port(), 9090);
    assert_eq!(addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
}

#[test]
fn config_load_names_file_provenance_on_missing_path() {
    let err = Config::load(Some("/nonexistent/rvc-arch-4i.toml".as_ref()), StartArgs::default())
        .expect_err("missing file");
    let rendered = err.to_string();
    assert!(rendered.contains("config"), "{rendered}");
    assert!(
        rendered.contains("/nonexistent/rvc-arch-4i.toml") || rendered.contains("file"),
        "{rendered}"
    );
    match err {
        rvc::config::ConfigError::Invalid { source_layer, .. } => {
            assert!(matches!(source_layer, ConfigSource::File(_)));
        }
        other => panic!("expected Invalid with File layer, got {other}"),
    }
}

/// Present-only TOML bools must survive an empty CLI overlay (ADR-009).
#[test]
fn toml_safety_flags_survive_empty_cli() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
allow_fresh_db = true
disable_attesting = true
allow_unsupported_fork = true
doppelganger_detection = false
disable_keystore_locking = true
"#
    )
    .unwrap();
    let cfg = Config::load(Some(file.path()), StartArgs::default()).expect("load");
    assert!(cfg.allow_fresh_db);
    assert!(cfg.disable_attesting);
    assert!(cfg.allow_unsupported_fork);
    assert!(!cfg.doppelganger_detection);
    assert!(cfg.disable_keystore_locking);
}
