//! Configuration types for the validator client.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use super::network::Network;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub beacon_url: String,

    #[serde(default)]
    pub beacon_nodes: Vec<String>,

    pub keystore_path: PathBuf,

    pub password_file: Option<PathBuf>,

    pub slashing_db_path: PathBuf,

    pub metrics_port: u16,

    pub grpc_port: u16,

    pub grpc_address: String,

    pub network: Network,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_time: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_validators_root: Option<String>,

    pub graffiti: Option<String>,

    pub log_level: String,

    pub doppelganger_detection: bool,

    #[serde(default)]
    pub keymanager_enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub keymanager_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub keymanager_token_file: Option<PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signer_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_decrypt_threads: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            beacon_url: "http://localhost:5052".to_string(),
            beacon_nodes: Vec::new(),
            keystore_path: PathBuf::from("./keystores"),
            password_file: None,
            slashing_db_path: PathBuf::from("./slashing_protection.sqlite"),
            metrics_port: 8080,
            grpc_port: 50051,
            grpc_address: "127.0.0.1".to_string(),
            network: Network::Mainnet,
            genesis_time: None,
            genesis_validators_root: None,
            graffiti: None,
            log_level: "info".to_string(),
            doppelganger_detection: true,
            keymanager_enabled: false,
            keymanager_address: None,
            keymanager_token_file: None,
            remote_signer_url: None,
            key_decrypt_threads: None,
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }

        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn effective_genesis_time(&self) -> Result<u64, ConfigError> {
        if let Some(genesis_time) = self.genesis_time {
            return Ok(genesis_time);
        }

        self.network
            .genesis_time()
            .ok_or_else(|| ConfigError::MissingField("genesis_time".to_string()))
    }

    pub fn effective_genesis_validators_root(&self) -> Result<String, ConfigError> {
        if let Some(ref root) = self.genesis_validators_root {
            return Ok(root.clone());
        }

        self.network
            .genesis_validators_root()
            .map(|s| s.to_string())
            .ok_or_else(|| ConfigError::MissingField("genesis_validators_root".to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.beacon_url.is_empty() {
            return Err(ConfigError::InvalidBeaconUrl("beacon URL cannot be empty".to_string()));
        }

        if !self.beacon_url.starts_with("http://") && !self.beacon_url.starts_with("https://") {
            return Err(ConfigError::InvalidBeaconUrl(format!(
                "beacon URL must start with http:// or https://: {}",
                self.beacon_url
            )));
        }

        for node_url in &self.beacon_nodes {
            if node_url.is_empty() {
                return Err(ConfigError::InvalidBeaconUrl(
                    "beacon_nodes entry cannot be empty".to_string(),
                ));
            }
            if !node_url.starts_with("http://") && !node_url.starts_with("https://") {
                return Err(ConfigError::InvalidBeaconUrl(format!(
                    "beacon_nodes entry must start with http:// or https://: {}",
                    node_url
                )));
            }
        }

        if self.metrics_port == 0 {
            return Err(ConfigError::InvalidPort(self.metrics_port));
        }

        if self.grpc_port == 0 {
            return Err(ConfigError::InvalidPort(self.grpc_port));
        }

        if let Some(ref graffiti) = self.graffiti {
            if graffiti.len() > 32 {
                return Err(ConfigError::InvalidGraffiti(
                    "graffiti must be 32 bytes or less".to_string(),
                ));
            }
        }

        self.effective_genesis_time()?;
        self.effective_genesis_validators_root()?;

        Ok(())
    }

    pub fn load_passwords(&self) -> Result<HashMap<String, SecretString>, ConfigError> {
        let password_file = match &self.password_file {
            Some(path) => path,
            None => return Ok(HashMap::new()),
        };

        if !password_file.exists() {
            return Err(ConfigError::PasswordFileNotFound(password_file.clone()));
        }

        let content = fs::read_to_string(password_file).map_err(|e| {
            ConfigError::PasswordReadError(format!("failed to read password file: {}", e))
        })?;

        let mut passwords = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((pubkey, password)) = line.split_once('=') {
                let pubkey = pubkey.trim().trim_start_matches("0x");
                let password = password.trim();
                passwords.insert(pubkey.to_string(), SecretString::from(password.to_string()));
            }
        }

        Ok(passwords)
    }

    /// Returns the effective list of beacon node endpoints.
    ///
    /// Prefers `beacon_nodes` if non-empty, otherwise falls back to `beacon_url`.
    pub fn effective_beacon_nodes(&self) -> Vec<String> {
        if !self.beacon_nodes.is_empty() {
            self.beacon_nodes.clone()
        } else {
            vec![self.beacon_url.clone()]
        }
    }

    pub fn merge_with_cli(&mut self, cli: &CliOverrides) {
        if let Some(ref beacon_url) = cli.beacon_url {
            self.beacon_url = beacon_url.clone();
        }

        if let Some(ref beacon_nodes) = cli.beacon_nodes {
            self.beacon_nodes = beacon_nodes.clone();
        }

        if let Some(ref keystore_path) = cli.keystore_path {
            self.keystore_path = keystore_path.clone();
        }

        if let Some(ref password_file) = cli.password_file {
            self.password_file = Some(password_file.clone());
        }

        if let Some(ref slashing_db_path) = cli.slashing_db_path {
            self.slashing_db_path = slashing_db_path.clone();
        }

        if let Some(metrics_port) = cli.metrics_port {
            self.metrics_port = metrics_port;
        }

        if let Some(grpc_port) = cli.grpc_port {
            self.grpc_port = grpc_port;
        }

        if let Some(ref grpc_address) = cli.grpc_address {
            self.grpc_address = grpc_address.clone();
        }

        if let Some(network) = cli.network {
            self.network = network;
        }

        if let Some(genesis_time) = cli.genesis_time {
            self.genesis_time = Some(genesis_time);
        }

        if let Some(ref genesis_validators_root) = cli.genesis_validators_root {
            self.genesis_validators_root = Some(genesis_validators_root.clone());
        }

        if let Some(ref graffiti) = cli.graffiti {
            self.graffiti = Some(graffiti.clone());
        }

        if let Some(ref log_level) = cli.log_level {
            self.log_level = log_level.clone();
        }

        if let Some(doppelganger_detection) = cli.doppelganger_detection {
            self.doppelganger_detection = doppelganger_detection;
        }

        if let Some(keymanager_enabled) = cli.keymanager_enabled {
            self.keymanager_enabled = keymanager_enabled;
        }

        if let Some(ref keymanager_address) = cli.keymanager_address {
            self.keymanager_address = Some(keymanager_address.clone());
        }

        if let Some(ref keymanager_token_file) = cli.keymanager_token_file {
            self.keymanager_token_file = Some(keymanager_token_file.clone());
        }

        if let Some(ref remote_signer_url) = cli.remote_signer_url {
            self.remote_signer_url = Some(remote_signer_url.clone());
        }

        if let Some(n) = cli.key_decrypt_threads {
            self.key_decrypt_threads = Some(n);
        }
    }
}

#[derive(Debug, Default)]
pub struct CliOverrides {
    pub beacon_url: Option<String>,
    pub beacon_nodes: Option<Vec<String>>,
    pub keystore_path: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub slashing_db_path: Option<PathBuf>,
    pub metrics_port: Option<u16>,
    pub grpc_port: Option<u16>,
    pub grpc_address: Option<String>,
    pub network: Option<Network>,
    pub genesis_time: Option<u64>,
    pub genesis_validators_root: Option<String>,
    pub graffiti: Option<String>,
    pub log_level: Option<String>,
    pub doppelganger_detection: Option<bool>,
    pub keymanager_enabled: Option<bool>,
    pub keymanager_address: Option<String>,
    pub keymanager_token_file: Option<PathBuf>,
    pub remote_signer_url: Option<String>,
    pub key_decrypt_threads: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.beacon_url, "http://localhost:5052");
        assert_eq!(config.keystore_path, PathBuf::from("./keystores"));
        assert_eq!(config.metrics_port, 8080);
        assert_eq!(config.grpc_port, 50051);
        assert_eq!(config.grpc_address, "127.0.0.1");
        assert_eq!(config.network, Network::Mainnet);
        assert!(config.genesis_time.is_none());
        assert!(config.genesis_validators_root.is_none());
    }

    #[test]
    fn test_config_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
metrics_port = 9090
grpc_port = 50052
network = "hoodi"
log_level = "debug"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.beacon_url, "http://beacon:5052");
        assert_eq!(config.keystore_path, PathBuf::from("/data/keystores"));
        assert_eq!(config.slashing_db_path, PathBuf::from("/data/slashing.db"));
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.grpc_port, 50052);
        assert_eq!(config.network, Network::Hoodi);
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_config_file_not_found() {
        let result = Config::from_file("/nonexistent/config.toml");
        assert!(matches!(result, Err(ConfigError::FileNotFound(_))));
    }

    #[test]
    fn test_effective_genesis_time_from_network() {
        let config = Config { network: Network::Mainnet, genesis_time: None, ..Default::default() };
        assert_eq!(config.effective_genesis_time().unwrap(), 1606824023);
    }

    #[test]
    fn test_effective_genesis_time_override() {
        let config =
            Config { network: Network::Mainnet, genesis_time: Some(12345), ..Default::default() };
        assert_eq!(config.effective_genesis_time().unwrap(), 12345);
    }

    #[test]
    fn test_effective_genesis_time_custom_network_requires_explicit() {
        let config = Config { network: Network::Custom, genesis_time: None, ..Default::default() };
        assert!(config.effective_genesis_time().is_err());
    }

    #[test]
    fn test_effective_genesis_validators_root_from_network() {
        let config = Config {
            network: Network::Mainnet,
            genesis_validators_root: None,
            ..Default::default()
        };
        let root = config.effective_genesis_validators_root().unwrap();
        assert!(root.starts_with("0x"));
    }

    #[test]
    fn test_effective_genesis_validators_root_override() {
        let config = Config {
            network: Network::Mainnet,
            genesis_validators_root: Some("0xcustom".to_string()),
            ..Default::default()
        };
        assert_eq!(config.effective_genesis_validators_root().unwrap(), "0xcustom");
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_beacon_url() {
        let config = Config { beacon_url: "".to_string(), ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_invalid_beacon_url_scheme() {
        let config =
            Config { beacon_url: "ftp://localhost:5052".to_string(), ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_invalid_port() {
        let config = Config { metrics_port: 0, ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPort(_))));
    }

    #[test]
    fn test_validate_graffiti_too_long() {
        let config = Config {
            graffiti: Some("a".repeat(33)), // 33 bytes, exceeds 32 byte limit
            ..Default::default()
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidGraffiti(_))));
    }

    #[test]
    fn test_validate_graffiti_valid() {
        let config = Config {
            graffiti: Some("rvc".to_string()), // Valid graffiti
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_passwords() {
        let mut file = NamedTempFile::new().unwrap();
        // Use obviously fake test values to avoid secret detection warnings
        let test_pw_1 = format!("test_value_{}", 1);
        let test_pw_2 = format!("test_value_{}", 2);
        writeln!(file, "# Comment line\nabcd1234 = {}\n0x5678efgh = {}", test_pw_1, test_pw_2)
            .unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 2);
        assert!(passwords.contains_key("abcd1234"));
        assert!(passwords.contains_key("5678efgh"));
    }

    #[test]
    fn test_load_passwords_no_file() {
        let config = Config { password_file: None, ..Default::default() };
        let passwords = config.load_passwords().unwrap();
        assert!(passwords.is_empty());
    }

    #[test]
    fn test_merge_with_cli() {
        let mut config = Config::default();
        let cli = CliOverrides {
            beacon_url: Some("http://custom:5052".to_string()),
            metrics_port: Some(9999),
            network: Some(Network::Hoodi),
            ..Default::default()
        };

        config.merge_with_cli(&cli);

        assert_eq!(config.beacon_url, "http://custom:5052");
        assert_eq!(config.metrics_port, 9999);
        assert_eq!(config.network, Network::Hoodi);
        assert_eq!(config.grpc_port, 50051);
        assert_eq!(config.grpc_address, "127.0.0.1");
    }

    #[test]
    fn test_merge_with_cli_grpc_address() {
        let mut config = Config::default();
        let cli = CliOverrides { grpc_address: Some("0.0.0.0".to_string()), ..Default::default() };

        config.merge_with_cli(&cli);

        assert_eq!(config.grpc_address, "0.0.0.0");
    }

    #[test]
    fn test_config_from_file_with_grpc_address() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
grpc_address = "192.168.1.1"
network = "hoodi"
log_level = "debug"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.grpc_address, "192.168.1.1");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("beacon_url"));
        assert!(toml_str.contains("network"));
    }

    // -- beacon_nodes tests --

    #[test]
    fn test_default_config_beacon_nodes_empty() {
        let config = Config::default();
        assert!(config.beacon_nodes.is_empty());
    }

    #[test]
    fn test_default_config_doppelganger_detection_enabled() {
        let config = Config::default();
        assert!(config.doppelganger_detection);
    }

    #[test]
    fn test_effective_beacon_nodes_falls_back_to_beacon_url() {
        let config = Config { beacon_url: "http://primary:5052".to_string(), ..Default::default() };
        assert_eq!(config.effective_beacon_nodes(), vec!["http://primary:5052"]);
    }

    #[test]
    fn test_effective_beacon_nodes_uses_beacon_nodes_when_set() {
        let config = Config {
            beacon_url: "http://primary:5052".to_string(),
            beacon_nodes: vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()],
            ..Default::default()
        };
        assert_eq!(config.effective_beacon_nodes(), vec!["http://bn1:5052", "http://bn2:5052"]);
    }

    #[test]
    fn test_merge_with_cli_beacon_nodes() {
        let mut config = Config::default();
        let cli = CliOverrides {
            beacon_nodes: Some(vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()]),
            ..Default::default()
        };

        config.merge_with_cli(&cli);
        assert_eq!(config.beacon_nodes.len(), 2);
        assert_eq!(config.beacon_nodes[0], "http://bn1:5052");
    }

    #[test]
    fn test_merge_with_cli_doppelganger_detection() {
        let mut config = Config::default();
        assert!(config.doppelganger_detection);

        let cli = CliOverrides { doppelganger_detection: Some(false), ..Default::default() };
        config.merge_with_cli(&cli);
        assert!(!config.doppelganger_detection);
    }

    #[test]
    fn test_validate_beacon_nodes_invalid_scheme() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "ftp://bn2:5052".to_string()],
            ..Default::default()
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_beacon_nodes_empty_entry() {
        let config = Config { beacon_nodes: vec!["".to_string()], ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_beacon_nodes_valid() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "https://bn2:5052".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_from_file_with_beacon_nodes() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://primary:5052"
beacon_nodes = ["http://bn1:5052", "http://bn2:5052"]
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
doppelganger_detection = false
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.beacon_nodes.len(), 2);
        assert!(!config.doppelganger_detection);
    }

    // -- keymanager config tests --

    #[test]
    fn test_default_config_keymanager_disabled() {
        let config = Config::default();
        assert!(!config.keymanager_enabled);
        assert!(config.keymanager_address.is_none());
        assert!(config.keymanager_token_file.is_none());
        assert!(config.remote_signer_url.is_none());
    }

    #[test]
    fn test_merge_with_cli_keymanager_fields() {
        let mut config = Config::default();
        let cli = CliOverrides {
            keymanager_enabled: Some(true),
            keymanager_address: Some("0.0.0.0:5062".to_string()),
            keymanager_token_file: Some(PathBuf::from("/data/token.txt")),
            remote_signer_url: Some("https://signer.example.com".to_string()),
            ..Default::default()
        };

        config.merge_with_cli(&cli);

        assert!(config.keymanager_enabled);
        assert_eq!(config.keymanager_address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager_token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(config.remote_signer_url.as_deref(), Some("https://signer.example.com"));
    }

    #[test]
    fn test_config_from_file_with_keymanager() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
keymanager_enabled = true
keymanager_address = "0.0.0.0:5062"
keymanager_token_file = "/data/token.txt"
remote_signer_url = "https://signer.example.com"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.keymanager_enabled);
        assert_eq!(config.keymanager_address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager_token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(config.remote_signer_url.as_deref(), Some("https://signer.example.com"));
    }

    #[test]
    fn test_merge_with_cli_keymanager_none_preserves_defaults() {
        let mut config = Config::default();
        let cli = CliOverrides::default();

        config.merge_with_cli(&cli);

        assert!(!config.keymanager_enabled);
        assert!(config.keymanager_address.is_none());
        assert!(config.keymanager_token_file.is_none());
        assert!(config.remote_signer_url.is_none());
    }

    // -- key_decrypt_threads tests --

    #[test]
    fn test_default_config_key_decrypt_threads_none() {
        let config = Config::default();
        assert!(config.key_decrypt_threads.is_none());
    }

    #[test]
    fn test_merge_with_cli_key_decrypt_threads() {
        let mut config = Config::default();
        assert!(config.key_decrypt_threads.is_none());

        let cli = CliOverrides { key_decrypt_threads: Some(4), ..Default::default() };
        config.merge_with_cli(&cli);
        assert_eq!(config.key_decrypt_threads, Some(4));
    }

    #[test]
    fn test_merge_with_cli_key_decrypt_threads_none_preserves_default() {
        let mut config = Config::default();
        let cli = CliOverrides::default();
        config.merge_with_cli(&cli);
        assert!(config.key_decrypt_threads.is_none());
    }

    #[test]
    fn test_config_from_file_with_key_decrypt_threads() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
key_decrypt_threads = 4
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.key_decrypt_threads, Some(4));
    }

    #[test]
    fn test_config_from_file_without_key_decrypt_threads() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.key_decrypt_threads.is_none());
    }
}
