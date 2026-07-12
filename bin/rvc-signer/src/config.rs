use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Default HTTP Remote Signing API listen address: **loopback** on the
/// Web3Signer port 9000.
///
/// Secure-by-default: the address is passed verbatim to `TcpListener::bind`
/// (there is no host normalization), so the default must be a concrete bindable
/// host. Loopback works out of the box for a same-host validator client and
/// fails safe (not exposed) for a remote one — an operator with a remote VC must
/// consciously set a routable **private-network** address behind a firewall, and
/// must never bind a public interface (see `docs/web3signer-http-api.md`).
pub const DEFAULT_HTTP_LISTEN_ADDRESS: &str = "127.0.0.1:9000";

/// Default HTTP TLS mode: mutual TLS (the recommended posture, FR-29).
pub const DEFAULT_HTTP_TLS_MODE: &str = "mtls";

#[derive(Debug, Default, Deserialize)]
pub struct SignerConfig {
    pub signer: Option<SignerSection>,
}

/// TLS posture for the HTTP Remote Signing API listener (FR-28/FR-29, ADR-004).
///
/// In both modes the server presents a certificate and the CA stays required;
/// only the *client*-auth requirement differs. Server authentication is never
/// weakened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpTlsMode {
    /// Mutual TLS: client cert required and verified against the configured CA.
    /// Recommended/default posture (Lighthouse).
    Mtls,
    /// Server-TLS-only: server presents a cert; client cert is optional/absent.
    /// Required for Prysm. Only the client-auth requirement is relaxed (opt-in).
    ServerTlsOnly,
}

impl HttpTlsMode {
    /// Parse from the config/CLI string. Accepts `"mtls"` and
    /// `"server-tls-only"`; any other value is a hard resolve error (no silent
    /// fallback).
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "mtls" => Ok(Self::Mtls),
            "server-tls-only" => Ok(Self::ServerTlsOnly),
            other => Err(format!(
                "invalid [signer.http] tls_mode {other:?}: expected \"mtls\" or \"server-tls-only\""
            )),
        }
    }
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
    /// Opt-in Web3Signer HTTP API listener block (FR-25/27/28/30). Absent =
    /// HTTP disabled; gRPC stays default-on.
    pub http: Option<HttpSection>,
}

/// Opt-in `[signer.http]` config block for the Web3Signer HTTP API.
///
/// Parsed/resolved only in this phase — the listener is wired in Phase 3. The
/// HTTP TLS material is independent of the gRPC listener's (FR-30), so gRPC can
/// run mTLS while HTTP runs server-TLS-only.
#[derive(Debug, Default, Deserialize)]
pub struct HttpSection {
    /// Enable the HTTP API. Default `false` (opt-in, FR-27).
    pub enabled: Option<bool>,
    /// Listen address. Default `127.0.0.1:9000` (FR-25); set an explicit
    /// private-network address for a remote validator client.
    pub listen_address: Option<String>,
    /// `"mtls"` (default) or `"server-tls-only"` (FR-28/29).
    pub tls_mode: Option<String>,
    /// Server cert / key / client CA — independent of the gRPC TLS material.
    /// The CA is required in both modes (the requirement is enforced in Phase 3;
    /// here the path is only resolved).
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca_cert: Option<PathBuf>,
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
    /// Web3Signer HTTP API (opt-in; default off). gRPC is unaffected by these.
    pub http_enabled: bool,
    pub http_listen_address: String,
    pub http_tls_mode: HttpTlsMode,
    pub http_tls_cert: Option<PathBuf>,
    pub http_tls_key: Option<PathBuf>,
    pub http_tls_ca_cert: Option<PathBuf>,
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
    // --- Web3Signer HTTP API overrides (FR-25/27/28/30) ---
    /// `--http-enabled`. Combined with the TOML value via OR (mirrors
    /// `enable_hot_reload`): a clap bool can't distinguish explicit-false from
    /// default-false, so the policy is "CLI flag set OR TOML `enabled = true`".
    pub http_enabled: bool,
    pub http_listen_address: &'a str,
    pub http_listen_address_is_default: bool,
    pub http_tls_mode: &'a str,
    pub http_tls_mode_is_default: bool,
    pub http_tls_cert: Option<&'a Path>,
    pub http_tls_key: Option<&'a Path>,
    pub http_tls_ca_cert: Option<&'a Path>,
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

    // --- Web3Signer HTTP API (opt-in; FR-25/27/28/30). Listener not bound this
    // phase; an absent [signer.http] block leaves HTTP disabled and does not
    // affect any gRPC-side resolution. ---
    let http = section.http.unwrap_or_default();

    // Opt-in: CLI flag OR TOML `enabled = true` (mirrors `enable_hot_reload`).
    let http_enabled = cli.http_enabled || http.enabled.unwrap_or(false);

    let http_listen_address = if !cli.http_listen_address_is_default {
        cli.http_listen_address.to_string()
    } else {
        http.listen_address.unwrap_or_else(|| cli.http_listen_address.to_string())
    };

    // CLI > TOML > default; the resolved string is then parsed into the enum,
    // so an invalid value is a hard error rather than a silent fallback.
    let http_tls_mode_str = if !cli.http_tls_mode_is_default {
        cli.http_tls_mode.to_string()
    } else {
        http.tls_mode.unwrap_or_else(|| cli.http_tls_mode.to_string())
    };
    let http_tls_mode = HttpTlsMode::parse(&http_tls_mode_str)?;

    // Independent of the gRPC TLS material (FR-30) — do not alias the gRPC paths.
    let http_tls_cert = cli.http_tls_cert.map(PathBuf::from).or(http.tls_cert);
    let http_tls_key = cli.http_tls_key.map(PathBuf::from).or(http.tls_key);
    let http_tls_ca_cert = cli.http_tls_ca_cert.map(PathBuf::from).or(http.tls_ca_cert);

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
        http_enabled,
        http_listen_address,
        http_tls_mode,
        http_tls_cert,
        http_tls_key,
        http_tls_ca_cert,
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
            http_enabled: false,
            http_listen_address: DEFAULT_HTTP_LISTEN_ADDRESS,
            http_listen_address_is_default: true,
            http_tls_mode: DEFAULT_HTTP_TLS_MODE,
            http_tls_mode_is_default: true,
            http_tls_cert: None,
            http_tls_key: None,
            http_tls_ca_cert: None,
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

    // --- [signer.http] config surface (Issue 1.3, FR-25/27/28/30) ---

    #[test]
    fn test_load_http_section_full() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"

[signer.http]
enabled = true
listen_address = "0.0.0.0:9000"
tls_mode = "server-tls-only"
tls_cert = "/http/cert.pem"
tls_key = "/http/key.pem"
tls_ca_cert = "/http/ca.pem"
"#,
        );
        let cfg = load_config(f.path()).unwrap();
        let http = cfg.signer.unwrap().http.unwrap();
        assert_eq!(http.enabled, Some(true));
        assert_eq!(http.listen_address.unwrap(), "0.0.0.0:9000");
        assert_eq!(http.tls_mode.unwrap(), "server-tls-only");
        assert_eq!(http.tls_cert.unwrap(), PathBuf::from("/http/cert.pem"));
        assert_eq!(http.tls_key.unwrap(), PathBuf::from("/http/key.pem"));
        assert_eq!(http.tls_ca_cert.unwrap(), PathBuf::from("/http/ca.pem"));
    }

    #[test]
    fn test_http_defaults_when_block_absent() {
        // No [signer.http]: HTTP disabled, default address/mode, gRPC untouched.
        let cli = CliOverrides { keystore_dir: Some(Path::new("/ks")), ..default_cli_overrides() };
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert!(!resolved.http_enabled);
        assert_eq!(resolved.http_listen_address, "127.0.0.1:9000");
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::Mtls);
        assert!(resolved.http_tls_cert.is_none());
        assert!(resolved.http_tls_key.is_none());
        assert!(resolved.http_tls_ca_cert.is_none());
        // gRPC-side resolution unchanged by the absent HTTP block.
        assert_eq!(resolved.listen_address, "127.0.0.1:50052");
        assert_eq!(resolved.backend, "basic");
    }

    #[test]
    fn test_http_resolved_from_file() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection {
                    enabled: Some(true),
                    listen_address: Some("0.0.0.0:9000".to_string()),
                    tls_mode: Some("server-tls-only".to_string()),
                    tls_cert: Some(PathBuf::from("/http/cert.pem")),
                    tls_key: Some(PathBuf::from("/http/key.pem")),
                    tls_ca_cert: Some(PathBuf::from("/http/ca.pem")),
                }),
                ..Default::default()
            }),
        };
        let resolved = merge_with_cli(config, &default_cli_overrides()).unwrap();
        assert!(resolved.http_enabled);
        assert_eq!(resolved.http_listen_address, "0.0.0.0:9000");
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::ServerTlsOnly);
        assert_eq!(resolved.http_tls_cert.unwrap(), PathBuf::from("/http/cert.pem"));
        assert_eq!(resolved.http_tls_key.unwrap(), PathBuf::from("/http/key.pem"));
        assert_eq!(resolved.http_tls_ca_cert.unwrap(), PathBuf::from("/http/ca.pem"));
    }

    #[test]
    fn test_http_cli_overrides_file() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection {
                    enabled: Some(false),
                    listen_address: Some("0.0.0.0:9000".to_string()),
                    tls_mode: Some("mtls".to_string()),
                    tls_cert: Some(PathBuf::from("/file/cert.pem")),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let cli = CliOverrides {
            keystore_dir: Some(Path::new("/ks")),
            http_enabled: true, // CLI flag set
            http_listen_address: "127.0.0.1:7000",
            http_listen_address_is_default: false,
            http_tls_mode: "server-tls-only",
            http_tls_mode_is_default: false,
            http_tls_cert: Some(Path::new("/cli/cert.pem")),
            ..default_cli_overrides()
        };
        let resolved = merge_with_cli(config, &cli).unwrap();
        assert!(resolved.http_enabled); // CLI flag OR file → enabled
        assert_eq!(resolved.http_listen_address, "127.0.0.1:7000");
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::ServerTlsOnly);
        assert_eq!(resolved.http_tls_cert.unwrap(), PathBuf::from("/cli/cert.pem"));
    }

    #[test]
    fn test_http_invalid_tls_mode_is_hard_error() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection {
                    tls_mode: Some("none".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let err = merge_with_cli(config, &default_cli_overrides()).unwrap_err().to_string();
        assert!(err.contains("tls_mode"), "error must name the offending field: {err}");
        assert!(err.contains("none"), "error must name the bad value: {err}");
    }

    #[test]
    fn test_http_default_mode_is_mtls_when_enabled_without_mode() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection { enabled: Some(true), ..Default::default() }),
                ..Default::default()
            }),
        };
        let resolved = merge_with_cli(config, &default_cli_overrides()).unwrap();
        assert!(resolved.http_enabled);
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::Mtls);
        assert_eq!(resolved.http_listen_address, "127.0.0.1:9000");
    }
}
