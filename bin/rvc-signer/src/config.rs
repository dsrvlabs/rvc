use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct SignerConfig {
    pub signer: Option<SignerSection>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SignerSection {
    pub listen_address: Option<String>,
    pub keystore_dir: Option<PathBuf>,
    pub password_dir: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub backend: Option<String>,
    pub dry_run: Option<bool>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca_cert: Option<PathBuf>,
    pub reload_interval_secs: Option<u64>,
    /// ISSUE-4.6 / L-6: keystore hot-reload is opt-in. When unset (or false)
    /// the reloader is not spawned regardless of `reload_interval_secs`.
    pub enable_hot_reload: Option<bool>,
    pub dvt: Option<DvtConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DvtConfig {
    pub peers: Option<Vec<String>>,
    pub threshold: Option<u64>,
    pub index: Option<u64>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug)]
pub struct ResolvedConfig {
    pub listen_address: String,
    pub keystore_dir: PathBuf,
    pub password_dir: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub backend: String,
    pub dry_run: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca_cert: Option<PathBuf>,
    pub reload_interval_secs: u64,
    /// ISSUE-4.6 / L-6: hot-reload is opt-in. The reloader is only spawned
    /// when this is `true` AND `reload_interval_secs > 0`.
    pub enable_hot_reload: bool,
    pub dvt_peers: Vec<String>,
    pub dvt_threshold: Option<u64>,
    pub dvt_index: Option<u64>,
    pub dvt_timeout_ms: u64,
}

pub struct CliOverrides<'a> {
    pub listen_address: &'a str,
    pub listen_address_is_default: bool,
    pub keystore_dir: Option<&'a Path>,
    pub password_dir: Option<&'a Path>,
    pub password_file: Option<&'a Path>,
    pub backend: &'a str,
    pub backend_is_default: bool,
    pub dry_run: bool,
    pub tls_cert: Option<&'a Path>,
    pub tls_key: Option<&'a Path>,
    pub tls_ca_cert: Option<&'a Path>,
    pub reload_interval: u64,
    pub reload_interval_is_default: bool,
    pub enable_hot_reload: bool,
    pub dvt_peers: &'a [String],
    pub dvt_threshold: Option<u64>,
    pub dvt_index: Option<u64>,
    pub dvt_timeout: u64,
    pub dvt_timeout_is_default: bool,
}

pub fn load_config(path: &Path) -> Result<SignerConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file {}: {}", path.display(), e))?;
    let config: SignerConfig =
        toml::from_str(&content).map_err(|e| format!("failed to parse config: {}", e))?;
    Ok(config)
}

pub fn merge_with_cli(
    config: SignerConfig,
    cli: &CliOverrides<'_>,
) -> Result<ResolvedConfig, Box<dyn std::error::Error>> {
    let section = config.signer.unwrap_or_default();
    let dvt = section.dvt.unwrap_or_default();

    let listen_address = if !cli.listen_address_is_default {
        cli.listen_address.to_string()
    } else {
        section.listen_address.unwrap_or_else(|| cli.listen_address.to_string())
    };

    let keystore_dir = cli.keystore_dir.map(PathBuf::from).or(section.keystore_dir).ok_or(
        "keystore_dir is required (set via --keystore-dir or config [signer].keystore_dir)",
    )?;

    let password_dir = cli.password_dir.map(PathBuf::from).or(section.password_dir);
    let password_file = cli.password_file.map(PathBuf::from).or(section.password_file);

    let backend = if !cli.backend_is_default {
        cli.backend.to_string()
    } else {
        section.backend.unwrap_or_else(|| cli.backend.to_string())
    };

    let dry_run = cli.dry_run || section.dry_run.unwrap_or(false);

    let tls_cert = cli.tls_cert.map(PathBuf::from).or(section.tls_cert);
    let tls_key = cli.tls_key.map(PathBuf::from).or(section.tls_key);
    let tls_ca_cert = cli.tls_ca_cert.map(PathBuf::from).or(section.tls_ca_cert);

    let reload_interval_secs = if !cli.reload_interval_is_default {
        cli.reload_interval
    } else {
        section.reload_interval_secs.unwrap_or(cli.reload_interval)
    };

    // ISSUE-4.6 / L-6: hot-reload opt-in.  CLI flag wins; otherwise the TOML
    // setting; otherwise off.  An explicit CLI `--enable-hot-reload` (or
    // future `--no-...`) cannot be cleanly distinguished from the default
    // boolean false in clap, so the policy is "either the CLI flag is set
    // OR the TOML key is set true".
    let enable_hot_reload = cli.enable_hot_reload || section.enable_hot_reload.unwrap_or(false);

    let dvt_peers = if !cli.dvt_peers.is_empty() {
        cli.dvt_peers.to_vec()
    } else {
        dvt.peers.unwrap_or_default()
    };

    let dvt_threshold = cli.dvt_threshold.or(dvt.threshold);
    let dvt_index = cli.dvt_index.or(dvt.index);

    let dvt_timeout_ms = if !cli.dvt_timeout_is_default {
        cli.dvt_timeout
    } else {
        dvt.timeout_ms.unwrap_or(cli.dvt_timeout)
    };

    Ok(ResolvedConfig {
        listen_address,
        keystore_dir,
        password_dir,
        password_file,
        backend,
        dry_run,
        tls_cert,
        tls_key,
        tls_ca_cert,
        reload_interval_secs,
        enable_hot_reload,
        dvt_peers,
        dvt_threshold,
        dvt_index,
        dvt_timeout_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
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

    // --- load_config tests ---

    #[test]
    fn test_load_config_full() {
        let f = write_toml(
            r#"
[signer]
listen_address = "0.0.0.0:9000"
keystore_dir = "/data/keystores"
password_file = "/data/password.txt"
backend = "dvt"
tls_cert = "/tls/cert.pem"
tls_key = "/tls/key.pem"
tls_ca_cert = "/tls/ca.pem"

[signer.dvt]
peers = ["peer1:50052", "peer2:50052"]
threshold = 2
index = 0
timeout_ms = 5000
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let s = cfg.signer.unwrap();
        assert_eq!(s.listen_address.unwrap(), "0.0.0.0:9000");
        assert_eq!(s.keystore_dir.unwrap(), PathBuf::from("/data/keystores"));
        assert_eq!(s.password_file.unwrap(), PathBuf::from("/data/password.txt"));
        assert_eq!(s.backend.unwrap(), "dvt");
        assert_eq!(s.tls_cert.unwrap(), PathBuf::from("/tls/cert.pem"));
        assert_eq!(s.tls_key.unwrap(), PathBuf::from("/tls/key.pem"));
        assert_eq!(s.tls_ca_cert.unwrap(), PathBuf::from("/tls/ca.pem"));

        let dvt = s.dvt.unwrap();
        assert_eq!(dvt.peers.unwrap(), vec!["peer1:50052", "peer2:50052"]);
        assert_eq!(dvt.threshold.unwrap(), 2);
        assert_eq!(dvt.index.unwrap(), 0);
        assert_eq!(dvt.timeout_ms.unwrap(), 5000);
    }

    #[test]
    fn test_load_config_partial() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/data/keystores"
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let s = cfg.signer.unwrap();
        assert_eq!(s.keystore_dir.unwrap(), PathBuf::from("/data/keystores"));
        assert!(s.listen_address.is_none());
        assert!(s.backend.is_none());
        assert!(s.dvt.is_none());
    }

    #[test]
    fn test_load_config_empty_file() {
        let f = write_toml("");
        let cfg = load_config(f.path()).unwrap();
        assert!(cfg.signer.is_none());
    }

    #[test]
    fn test_load_config_nonexistent_file() {
        let result = load_config(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to read config file"));
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let f = write_toml("[invalid toml!!! =");
        let result = load_config(f.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to parse config"));
    }

    #[test]
    fn test_load_config_dvt_section_only() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"

[signer.dvt]
threshold = 3
index = 1
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let dvt = cfg.signer.unwrap().dvt.unwrap();
        assert_eq!(dvt.threshold.unwrap(), 3);
        assert_eq!(dvt.index.unwrap(), 1);
        assert!(dvt.peers.is_none());
        assert!(dvt.timeout_ms.is_none());
    }

    // --- merge_with_cli tests ---

    #[test]
    fn test_merge_defaults_only() {
        let cli = CliOverrides {
            keystore_dir: Some(Path::new("/cli/keystores")),
            ..default_cli_overrides()
        };
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert_eq!(resolved.listen_address, "127.0.0.1:50052");
        assert_eq!(resolved.keystore_dir, PathBuf::from("/cli/keystores"));
        assert_eq!(resolved.backend, "basic");
        assert_eq!(resolved.dvt_timeout_ms, 2000);
        assert!(resolved.dvt_peers.is_empty());
    }

    #[test]
    fn test_merge_config_values_used_when_cli_is_default() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                listen_address: Some("0.0.0.0:9000".to_string()),
                keystore_dir: Some(PathBuf::from("/config/ks")),
                password_file: Some(PathBuf::from("/config/pw.txt")),
                backend: Some("dvt".to_string()),
                tls_cert: Some(PathBuf::from("/config/cert.pem")),
                dvt: Some(DvtConfig {
                    peers: Some(vec!["p1:5000".to_string()]),
                    threshold: Some(2),
                    index: Some(1),
                    timeout_ms: Some(3000),
                }),
                ..Default::default()
            }),
        };

        let resolved = merge_with_cli(config, &default_cli_overrides()).unwrap();

        assert_eq!(resolved.listen_address, "0.0.0.0:9000");
        assert_eq!(resolved.keystore_dir, PathBuf::from("/config/ks"));
        assert_eq!(resolved.password_file.unwrap(), PathBuf::from("/config/pw.txt"));
        assert_eq!(resolved.backend, "dvt");
        assert_eq!(resolved.tls_cert.unwrap(), PathBuf::from("/config/cert.pem"));
        assert_eq!(resolved.dvt_peers, vec!["p1:5000"]);
        assert_eq!(resolved.dvt_threshold.unwrap(), 2);
        assert_eq!(resolved.dvt_index.unwrap(), 1);
        assert_eq!(resolved.dvt_timeout_ms, 3000);
    }

    #[test]
    fn test_merge_cli_overrides_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                listen_address: Some("0.0.0.0:9000".to_string()),
                keystore_dir: Some(PathBuf::from("/config/ks")),
                backend: Some("dvt".to_string()),
                dvt: Some(DvtConfig {
                    peers: Some(vec!["config-peer:5000".to_string()]),
                    threshold: Some(2),
                    index: Some(1),
                    timeout_ms: Some(3000),
                }),
                ..Default::default()
            }),
        };

        let peers = vec!["cli-peer:6000".to_string()];
        let cli = CliOverrides {
            listen_address: "10.0.0.1:8080",
            listen_address_is_default: false,
            keystore_dir: Some(Path::new("/cli/ks")),
            password_file: Some(Path::new("/cli/pw.txt")),
            backend: "basic",
            backend_is_default: false,
            tls_cert: Some(Path::new("/cli/cert.pem")),
            dvt_peers: &peers,
            dvt_threshold: Some(3),
            dvt_index: Some(0),
            dvt_timeout: 5000,
            dvt_timeout_is_default: false,
            ..default_cli_overrides()
        };

        let resolved = merge_with_cli(config, &cli).unwrap();

        assert_eq!(resolved.listen_address, "10.0.0.1:8080");
        assert_eq!(resolved.keystore_dir, PathBuf::from("/cli/ks"));
        assert_eq!(resolved.password_file.unwrap(), PathBuf::from("/cli/pw.txt"));
        assert_eq!(resolved.backend, "basic");
        assert_eq!(resolved.tls_cert.unwrap(), PathBuf::from("/cli/cert.pem"));
        assert_eq!(resolved.dvt_peers, vec!["cli-peer:6000"]);
        assert_eq!(resolved.dvt_threshold.unwrap(), 3);
        assert_eq!(resolved.dvt_index.unwrap(), 0);
        assert_eq!(resolved.dvt_timeout_ms, 5000);
    }

    #[test]
    fn test_load_config_dry_run() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"
dry_run = true
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let s = cfg.signer.unwrap();
        assert_eq!(s.dry_run, Some(true));
    }

    #[test]
    fn test_merge_dry_run_from_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                dry_run: Some(true),
                ..Default::default()
            }),
        };

        let resolved = merge_with_cli(config, &default_cli_overrides()).unwrap();
        assert!(resolved.dry_run);
    }

    #[test]
    fn test_merge_dry_run_cli_overrides_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                dry_run: Some(false),
                ..Default::default()
            }),
        };

        let cli = CliOverrides { dry_run: true, ..default_cli_overrides() };
        let resolved = merge_with_cli(config, &cli).unwrap();
        assert!(resolved.dry_run);
    }

    #[test]
    fn test_merge_dry_run_defaults_false() {
        let cli = CliOverrides { keystore_dir: Some(Path::new("/ks")), ..default_cli_overrides() };
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert!(!resolved.dry_run);
    }

    #[test]
    fn test_merge_missing_keystore_dir_errors() {
        let result = merge_with_cli(SignerConfig::default(), &default_cli_overrides());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("keystore_dir is required"));
    }

    #[test]
    fn test_merge_password_dir_from_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                password_dir: Some(PathBuf::from("/config/pwdir")),
                ..Default::default()
            }),
        };

        let resolved = merge_with_cli(config, &default_cli_overrides()).unwrap();

        assert_eq!(resolved.password_dir.unwrap(), PathBuf::from("/config/pwdir"));
    }

    #[test]
    fn test_merge_cli_password_dir_overrides_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                password_dir: Some(PathBuf::from("/config/pwdir")),
                ..Default::default()
            }),
        };

        let cli =
            CliOverrides { password_dir: Some(Path::new("/cli/pwdir")), ..default_cli_overrides() };

        let resolved = merge_with_cli(config, &cli).unwrap();

        assert_eq!(resolved.password_dir.unwrap(), PathBuf::from("/cli/pwdir"));
    }
}
