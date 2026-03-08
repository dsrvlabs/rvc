use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::Deserialize;

use crate::config::{ValidatorConfig, ValidatorConfigUpdate};
use crate::error::ValidatorStoreError;

#[derive(Debug, Deserialize)]
struct TomlConfig {
    #[serde(default)]
    defaults: Option<TomlDefaults>,
    #[serde(default)]
    validators: Vec<TomlValidator>,
}

#[derive(Debug, Deserialize)]
struct TomlDefaults {
    fee_recipient: Option<String>,
    gas_limit: Option<u64>,
    graffiti: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlValidator {
    pubkey: String,
    fee_recipient: Option<String>,
    gas_limit: Option<u64>,
    builder_proposals: Option<bool>,
    builder_boost_factor: Option<u64>,
    graffiti: Option<String>,
    enabled: Option<bool>,
}

fn parse_hex_bytes<const N: usize>(s: &str) -> Result<[u8; N], ValidatorStoreError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| ValidatorStoreError::Config(e.to_string()))?;
    bytes.try_into().map_err(|_| ValidatorStoreError::Config(format!("expected {N} bytes")))
}

pub struct ValidatorStore {
    validators: RwLock<HashMap<[u8; 48], ValidatorConfig>>,
    default_fee_recipient: RwLock<[u8; 20]>,
    default_gas_limit: RwLock<u64>,
    default_graffiti: RwLock<Option<[u8; 32]>>,
    config_path: Option<PathBuf>,
}

impl ValidatorStore {
    pub fn new(default_fee_recipient: [u8; 20], default_gas_limit: u64) -> Self {
        Self {
            validators: RwLock::new(HashMap::new()),
            default_fee_recipient: RwLock::new(default_fee_recipient),
            default_gas_limit: RwLock::new(default_gas_limit),
            default_graffiti: RwLock::new(None),
            config_path: None,
        }
    }

    #[tracing::instrument(name = "rvc.validator_store.load_from_config", skip_all)]
    pub fn load_from_config(path: &Path) -> Result<Self, ValidatorStoreError> {
        let content = std::fs::read_to_string(path)?;
        let toml_config: TomlConfig = toml::from_str(&content)?;

        let mut default_fee_recipient = [0u8; 20];
        let mut default_gas_limit = 30_000_000u64;
        let mut default_graffiti = None;

        if let Some(defaults) = &toml_config.defaults {
            if let Some(ref fr) = defaults.fee_recipient {
                default_fee_recipient = parse_hex_bytes(fr)?;
            }
            if let Some(gl) = defaults.gas_limit {
                default_gas_limit = gl;
            }
            if let Some(ref g) = defaults.graffiti {
                default_graffiti = Some(parse_graffiti(g));
            }
        }

        let mut validators = HashMap::new();
        for v in &toml_config.validators {
            let config = parse_validator(v)?;
            validators.insert(config.pubkey, config);
        }

        Ok(Self {
            validators: RwLock::new(validators),
            default_fee_recipient: RwLock::new(default_fee_recipient),
            default_gas_limit: RwLock::new(default_gas_limit),
            default_graffiti: RwLock::new(default_graffiti),
            config_path: Some(path.to_path_buf()),
        })
    }

    pub fn get_config(&self, pubkey: &[u8; 48]) -> Option<ValidatorConfig> {
        self.validators.read().unwrap().get(pubkey).cloned()
    }

    pub fn effective_fee_recipient(&self, pubkey: &[u8; 48]) -> [u8; 20] {
        self.validators
            .read()
            .unwrap()
            .get(pubkey)
            .and_then(|c| c.fee_recipient)
            .unwrap_or(*self.default_fee_recipient.read().unwrap())
    }

    pub fn effective_gas_limit(&self, pubkey: &[u8; 48]) -> u64 {
        self.validators
            .read()
            .unwrap()
            .get(pubkey)
            .and_then(|c| c.gas_limit)
            .unwrap_or(*self.default_gas_limit.read().unwrap())
    }

    pub fn effective_graffiti(&self, pubkey: &[u8; 48]) -> Option<[u8; 32]> {
        self.validators
            .read()
            .unwrap()
            .get(pubkey)
            .and_then(|c| c.graffiti)
            .or(*self.default_graffiti.read().unwrap())
    }

    pub fn is_builder_enabled(&self, pubkey: &[u8; 48]) -> bool {
        self.validators.read().unwrap().get(pubkey).map(|c| c.builder_proposals).unwrap_or(false)
    }

    pub fn builder_boost_factor(&self, pubkey: &[u8; 48]) -> u64 {
        self.validators.read().unwrap().get(pubkey).map(|c| c.builder_boost_factor).unwrap_or(100)
    }

    #[tracing::instrument(name = "rvc.validator_store.list_enabled_pubkeys", skip_all)]
    pub fn list_enabled_pubkeys(&self) -> Vec<[u8; 48]> {
        self.validators.read().unwrap().values().filter(|c| c.enabled).map(|c| c.pubkey).collect()
    }

    pub fn add_validator(&self, config: ValidatorConfig) {
        self.validators.write().unwrap().insert(config.pubkey, config);
    }

    pub fn remove_validator(&self, pubkey: &[u8; 48]) -> Option<ValidatorConfig> {
        self.validators.write().unwrap().remove(pubkey)
    }

    pub fn set_enabled(&self, pubkey: &[u8; 48], enabled: bool) {
        if let Some(config) = self.validators.write().unwrap().get_mut(pubkey) {
            config.enabled = enabled;
        }
    }

    pub fn update_config(&self, pubkey: &[u8; 48], update: ValidatorConfigUpdate) {
        if let Some(config) = self.validators.write().unwrap().get_mut(pubkey) {
            if let Some(fr) = update.fee_recipient {
                config.fee_recipient = fr;
            }
            if let Some(gl) = update.gas_limit {
                config.gas_limit = gl;
            }
            if let Some(g) = update.graffiti {
                config.graffiti = g;
            }
            if let Some(bp) = update.builder_proposals {
                config.builder_proposals = bp;
            }
            if let Some(bbf) = update.builder_boost_factor {
                config.builder_boost_factor = bbf;
            }
        }
    }

    #[tracing::instrument(name = "rvc.validator_store.reload_config", skip_all)]
    pub fn reload_config(&self) -> Result<(), ValidatorStoreError> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ValidatorStoreError::Config("no config path set for reload".to_string())
        })?;

        let content = std::fs::read_to_string(path)?;
        let toml_config: TomlConfig = toml::from_str(&content)?;

        // Parse-first: compute all new values before any mutation.
        let mut new_fee_recipient = [0u8; 20];
        let mut new_gas_limit = 30_000_000u64;
        let mut new_graffiti = None;

        if let Some(defaults) = &toml_config.defaults {
            if let Some(ref fr) = defaults.fee_recipient {
                new_fee_recipient = parse_hex_bytes(fr)?;
            }
            if let Some(gl) = defaults.gas_limit {
                new_gas_limit = gl;
            }
            if let Some(ref g) = defaults.graffiti {
                new_graffiti = Some(parse_graffiti(g));
            }
        }

        let mut parsed_validators = Vec::with_capacity(toml_config.validators.len());
        for v in &toml_config.validators {
            parsed_validators.push(parse_validator(v)?);
        }

        // Apply-second: all parsing succeeded, now mutate atomically.
        *self.default_fee_recipient.write().unwrap() = new_fee_recipient;
        *self.default_gas_limit.write().unwrap() = new_gas_limit;
        *self.default_graffiti.write().unwrap() = new_graffiti;

        let mut validators = self.validators.write().unwrap();
        for config in parsed_validators {
            validators.insert(config.pubkey, config);
        }

        Ok(())
    }
}

fn parse_validator(v: &TomlValidator) -> Result<ValidatorConfig, ValidatorStoreError> {
    let pubkey: [u8; 48] = parse_hex_bytes(&v.pubkey)?;
    let fee_recipient = v.fee_recipient.as_ref().map(|s| parse_hex_bytes(s)).transpose()?;
    let graffiti = v.graffiti.as_ref().map(|s| parse_graffiti(s));

    Ok(ValidatorConfig {
        pubkey,
        fee_recipient,
        gas_limit: v.gas_limit,
        builder_proposals: v.builder_proposals.unwrap_or(false),
        builder_boost_factor: v.builder_boost_factor.unwrap_or(100),
        graffiti,
        enabled: v.enabled.unwrap_or(true),
    })
}

fn parse_graffiti(s: &str) -> [u8; 32] {
    let mut graffiti = [0u8; 32];
    let bytes = s.as_bytes();
    let len = bytes.len().min(32);
    graffiti[..len].copy_from_slice(&bytes[..len]);
    graffiti
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_pubkey(id: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    #[test]
    fn test_new_empty_store() {
        let fr = test_fee_recipient(1);
        let store = ValidatorStore::new(fr, 30_000_000);

        assert!(store.list_enabled_pubkeys().is_empty());
        assert_eq!(*store.default_fee_recipient.read().unwrap(), fr);
        assert_eq!(*store.default_gas_limit.read().unwrap(), 30_000_000);
        assert!(store.default_graffiti.read().unwrap().is_none());
    }

    #[test]
    fn test_add_and_get_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        let config = ValidatorConfig::new(pk);

        store.add_validator(config.clone());

        let retrieved = store.get_config(&pk).unwrap();
        assert_eq!(retrieved.pubkey, pk);
        assert!(retrieved.enabled);
        assert_eq!(retrieved.builder_boost_factor, 100);
    }

    #[test]
    fn test_get_config_returns_none_for_unknown() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert!(store.get_config(&test_pubkey(99)).is_none());
    }

    #[test]
    fn test_remove_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        let removed = store.remove_validator(&pk);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().pubkey, pk);
        assert!(store.get_config(&pk).is_none());
    }

    #[test]
    fn test_remove_validator_returns_none_for_unknown() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert!(store.remove_validator(&test_pubkey(99)).is_none());
    }

    #[test]
    fn test_effective_fee_recipient_with_override() {
        let default_fr = test_fee_recipient(1);
        let override_fr = test_fee_recipient(2);
        let store = ValidatorStore::new(default_fr, 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.fee_recipient = Some(override_fr);
        store.add_validator(config);

        assert_eq!(store.effective_fee_recipient(&pk), override_fr);
    }

    #[test]
    fn test_effective_fee_recipient_uses_default() {
        let default_fr = test_fee_recipient(1);
        let store = ValidatorStore::new(default_fr, 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert_eq!(store.effective_fee_recipient(&pk), default_fr);
    }

    #[test]
    fn test_effective_fee_recipient_unknown_validator_uses_default() {
        let default_fr = test_fee_recipient(1);
        let store = ValidatorStore::new(default_fr, 30_000_000);

        assert_eq!(store.effective_fee_recipient(&test_pubkey(99)), default_fr);
    }

    #[test]
    fn test_effective_gas_limit_with_override() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.gas_limit = Some(35_000_000);
        store.add_validator(config);

        assert_eq!(store.effective_gas_limit(&pk), 35_000_000);
    }

    #[test]
    fn test_effective_gas_limit_uses_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert_eq!(store.effective_gas_limit(&pk), 30_000_000);
    }

    #[test]
    fn test_effective_graffiti() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut graffiti = [0u8; 32];
        graffiti[..5].copy_from_slice(b"hello");

        let mut config = ValidatorConfig::new(pk);
        config.graffiti = Some(graffiti);
        store.add_validator(config);

        assert_eq!(store.effective_graffiti(&pk), Some(graffiti));
    }

    #[test]
    fn test_effective_graffiti_uses_default() {
        let mut default_graffiti = [0u8; 32];
        default_graffiti[..4].copy_from_slice(b"test");

        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        *store.default_graffiti.write().unwrap() = Some(default_graffiti);

        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert_eq!(store.effective_graffiti(&pk), Some(default_graffiti));
    }

    #[test]
    fn test_effective_graffiti_returns_none() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert!(store.effective_graffiti(&pk).is_none());
    }

    #[test]
    fn test_is_builder_enabled() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        store.add_validator(config);

        assert!(store.is_builder_enabled(&pk));
    }

    #[test]
    fn test_is_builder_disabled_by_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert!(!store.is_builder_enabled(&pk));
    }

    #[test]
    fn test_is_builder_enabled_unknown_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert!(!store.is_builder_enabled(&test_pubkey(99)));
    }

    #[test]
    fn test_builder_boost_factor_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert_eq!(store.builder_boost_factor(&pk), 100);
    }

    #[test]
    fn test_builder_boost_factor_custom() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.builder_boost_factor = 200;
        store.add_validator(config);

        assert_eq!(store.builder_boost_factor(&pk), 200);
    }

    #[test]
    fn test_builder_boost_factor_unknown_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert_eq!(store.builder_boost_factor(&test_pubkey(99)), 100);
    }

    #[test]
    fn test_list_enabled_pubkeys() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);

        let pk1 = test_pubkey(1);
        let pk2 = test_pubkey(2);
        let pk3 = test_pubkey(3);

        store.add_validator(ValidatorConfig::new(pk1));
        store.add_validator(ValidatorConfig::new(pk2));

        let mut disabled = ValidatorConfig::new(pk3);
        disabled.enabled = false;
        store.add_validator(disabled);

        let mut enabled = store.list_enabled_pubkeys();
        enabled.sort();
        assert_eq!(enabled.len(), 2);
        assert!(enabled.contains(&pk1));
        assert!(enabled.contains(&pk2));
        assert!(!enabled.contains(&pk3));
    }

    #[test]
    fn test_set_enabled() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        assert!(store.get_config(&pk).unwrap().enabled);

        store.set_enabled(&pk, false);
        assert!(!store.get_config(&pk).unwrap().enabled);

        store.set_enabled(&pk, true);
        assert!(store.get_config(&pk).unwrap().enabled);
    }

    #[test]
    fn test_set_enabled_unknown_validator_is_noop() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_enabled(&test_pubkey(99), false); // should not panic
    }

    #[test]
    fn test_update_config() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk));

        let new_fr = test_fee_recipient(5);
        let update = ValidatorConfigUpdate {
            fee_recipient: Some(Some(new_fr)),
            gas_limit: Some(Some(50_000_000)),
            builder_proposals: Some(true),
            builder_boost_factor: Some(150),
            graffiti: None, // no change
        };

        store.update_config(&pk, update);

        let config = store.get_config(&pk).unwrap();
        assert_eq!(config.fee_recipient, Some(new_fr));
        assert_eq!(config.gas_limit, Some(50_000_000));
        assert!(config.builder_proposals);
        assert_eq!(config.builder_boost_factor, 150);
        assert!(config.graffiti.is_none()); // unchanged
    }

    #[test]
    fn test_update_config_clear_fields() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.fee_recipient = Some(test_fee_recipient(5));
        config.gas_limit = Some(50_000_000);
        store.add_validator(config);

        let update = ValidatorConfigUpdate {
            fee_recipient: Some(None), // clear
            gas_limit: Some(None),     // clear
            ..Default::default()
        };
        store.update_config(&pk, update);

        let config = store.get_config(&pk).unwrap();
        assert!(config.fee_recipient.is_none());
        assert!(config.gas_limit.is_none());
    }

    #[test]
    fn test_update_config_unknown_validator_is_noop() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.update_config(&test_pubkey(99), ValidatorConfigUpdate::default());
    }

    #[test]
    fn test_load_from_config() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([2u8; 20]);

        let toml_content = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 30000000

[[validators]]
pubkey = "{}"
fee_recipient = "{}"
gas_limit = 35000000
builder_proposals = true
builder_boost_factor = 200
graffiti = "my graffiti"
"#,
            "0x".to_string() + &hex::encode([0xaau8; 20]),
            pubkey_hex,
            fr_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        let pk = [1u8; 48];
        let config = store.get_config(&pk).unwrap();
        assert_eq!(config.fee_recipient, Some([2u8; 20]));
        assert_eq!(config.gas_limit, Some(35_000_000));
        assert!(config.builder_proposals);
        assert_eq!(config.builder_boost_factor, 200);
        assert!(config.graffiti.is_some());
        assert!(config.enabled);

        assert_eq!(*store.default_fee_recipient.read().unwrap(), [0xaau8; 20]);
        assert_eq!(*store.default_gas_limit.read().unwrap(), 30_000_000);
    }

    #[test]
    fn test_load_from_config_with_defaults() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_content = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 25000000
graffiti = "default graffiti"

[[validators]]
pubkey = "{}"
"#,
            "0x".to_string() + &hex::encode([0xbbu8; 20]),
            pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        let pk = [1u8; 48];
        assert_eq!(store.effective_fee_recipient(&pk), [0xbbu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 25_000_000);
        assert!(store.effective_graffiti(&pk).is_some());

        let graffiti = store.effective_graffiti(&pk).unwrap();
        assert_eq!(&graffiti[..16], b"default graffiti");
    }

    #[test]
    fn test_load_from_config_no_defaults_section() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_content = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(*store.default_fee_recipient.read().unwrap(), [0u8; 20]);
        assert_eq!(*store.default_gas_limit.read().unwrap(), 30_000_000);
        assert!(store.default_graffiti.read().unwrap().is_none());
    }

    #[test]
    fn test_load_from_config_invalid_path() {
        let result = ValidatorStore::load_from_config(Path::new("/nonexistent/path.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_config_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("bad.toml");
        std::fs::write(&config_path, "this is not valid toml [[[").unwrap();

        let result = ValidatorStore::load_from_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_config_invalid_hex() {
        let toml_content = r#"
[[validators]]
pubkey = "not-valid-hex"
"#;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("bad_hex.toml");
        std::fs::write(&config_path, toml_content).unwrap();

        let result = ValidatorStore::load_from_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(1), 30_000_000));

        let mut handles = vec![];

        // Spawn writer threads
        for i in 0..5u8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let pk = test_pubkey(i);
                store.add_validator(ValidatorConfig::new(pk));
            }));
        }

        // Spawn reader threads
        for i in 0..5u8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let pk = test_pubkey(i);
                let _ = store.get_config(&pk);
                let _ = store.effective_fee_recipient(&pk);
                let _ = store.effective_gas_limit(&pk);
                let _ = store.list_enabled_pubkeys();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All 5 validators should be present
        assert_eq!(store.list_enabled_pubkeys().len(), 5);
    }

    #[test]
    fn test_parse_hex_bytes_with_prefix() {
        let result: [u8; 4] = parse_hex_bytes("0xdeadbeef").unwrap();
        assert_eq!(result, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_hex_bytes_without_prefix() {
        let result: [u8; 4] = parse_hex_bytes("deadbeef").unwrap();
        assert_eq!(result, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_hex_bytes_wrong_length() {
        let result = parse_hex_bytes::<4>("aabb");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_graffiti_short() {
        let graffiti = parse_graffiti("hello");
        assert_eq!(&graffiti[..5], b"hello");
        assert_eq!(&graffiti[5..], &[0u8; 27]);
    }

    #[test]
    fn test_parse_graffiti_truncates_at_32() {
        let long = "a".repeat(64);
        let graffiti = parse_graffiti(&long);
        assert_eq!(graffiti, [b'a'; 32]);
    }

    #[test]
    fn test_validator_config_new_defaults() {
        let pk = test_pubkey(1);
        let config = ValidatorConfig::new(pk);

        assert_eq!(config.pubkey, pk);
        assert!(config.fee_recipient.is_none());
        assert!(config.gas_limit.is_none());
        assert!(!config.builder_proposals);
        assert_eq!(config.builder_boost_factor, 100);
        assert!(config.graffiti.is_none());
        assert!(config.enabled);
    }

    #[test]
    fn test_reload_config_updates_builder_proposals() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_v1 = format!(
            r#"
[[validators]]
pubkey = "{}"
builder_proposals = false
"#,
            pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        let pk = [1u8; 48];
        assert!(!store.is_builder_enabled(&pk));

        let toml_v2 = format!(
            r#"
[[validators]]
pubkey = "{}"
builder_proposals = true
builder_boost_factor = 250
"#,
            pubkey_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        assert!(store.is_builder_enabled(&pk));
        assert_eq!(store.builder_boost_factor(&pk), 250);
    }

    #[test]
    fn test_reload_config_updates_defaults() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr1_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        let fr2_hex = "0x".to_string() + &hex::encode([0xbbu8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 30000000

[[validators]]
pubkey = "{}"
"#,
            fr1_hex, pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        let pk = [1u8; 48];
        assert_eq!(store.effective_fee_recipient(&pk), [0xaau8; 20]);

        let toml_v2 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 40000000

[[validators]]
pubkey = "{}"
"#,
            fr2_hex, pubkey_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        assert_eq!(store.effective_fee_recipient(&pk), [0xbbu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 40_000_000);
    }

    #[test]
    fn test_reload_config_adds_new_validators() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let pk2_hex = "0x".to_string() + &hex::encode([2u8; 48]);

        let toml_v1 = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(store.list_enabled_pubkeys().len(), 1);

        let toml_v2 = format!(
            r#"
[[validators]]
pubkey = "{}"

[[validators]]
pubkey = "{}"
builder_proposals = true
"#,
            pk1_hex, pk2_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        assert_eq!(store.list_enabled_pubkeys().len(), 2);
        let pk2 = [2u8; 48];
        assert!(store.is_builder_enabled(&pk2));
    }

    #[test]
    fn test_reload_config_preserves_programmatic_validators() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_v1 = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        let pk_extra = [99u8; 48];
        store.add_validator(ValidatorConfig::new(pk_extra));
        assert_eq!(store.list_enabled_pubkeys().len(), 2);

        store.reload_config().unwrap();

        assert!(store.get_config(&pk_extra).is_some());
    }

    #[test]
    fn test_reload_config_no_path_returns_error() {
        let store = ValidatorStore::new([0u8; 20], 30_000_000);
        let result = store.reload_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_reload_config_invalid_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, "[[validators]]\npubkey = \"0x01\"\n").unwrap();

        // Initial load will fail due to wrong length, so create a valid one first
        let pk_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let valid_toml = format!("[[validators]]\npubkey = \"{}\"\n", pk_hex);
        std::fs::write(&config_path, &valid_toml).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        std::fs::write(&config_path, "not valid toml [[[").unwrap();

        let result = store.reload_config();
        assert!(result.is_err());

        // Store should be unchanged after failed reload
        assert!(store.get_config(&[1u8; 48]).is_some());
    }

    #[test]
    fn test_reload_config_partial_validator_failure_no_mutation() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 30000000

[[validators]]
pubkey = "{}"
builder_proposals = false
"#,
            fr_hex, pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        let pk1 = [1u8; 48];
        assert!(!store.is_builder_enabled(&pk1));
        assert_eq!(store.effective_fee_recipient(&pk1), [0xaau8; 20]);
        assert_eq!(store.effective_gas_limit(&pk1), 30_000_000);

        // Write config with one valid validator (changed) + one invalid validator
        let pk2_hex = "0x".to_string() + &hex::encode([2u8; 48]);
        let fr2_hex = "0x".to_string() + &hex::encode([0xbbu8; 20]);
        let toml_v2 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 50000000

[[validators]]
pubkey = "{}"
builder_proposals = true

[[validators]]
pubkey = "invalid-hex-not-48-bytes"
"#,
            fr2_hex, pk2_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        let result = store.reload_config();
        assert!(result.is_err());

        // CRITICAL: Store must be completely unchanged after failed reload
        // Defaults must not have changed
        assert_eq!(*store.default_fee_recipient.read().unwrap(), [0xaau8; 20]);
        assert_eq!(*store.default_gas_limit.read().unwrap(), 30_000_000);

        // No new validators added
        assert!(store.get_config(&[2u8; 48]).is_none());

        // Existing validator unchanged
        assert!(!store.is_builder_enabled(&pk1));
    }

    #[test]
    fn test_reload_config_resets_defaults_when_section_removed() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 50000000
graffiti = "my graffiti"

[[validators]]
pubkey = "{}"
"#,
            fr_hex, pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(*store.default_fee_recipient.read().unwrap(), [0xaau8; 20]);
        assert_eq!(*store.default_gas_limit.read().unwrap(), 50_000_000);
        assert!(store.default_graffiti.read().unwrap().is_some());

        // Remove [defaults] section entirely
        let toml_v2 = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        // Defaults should reset to hardcoded fallbacks
        assert_eq!(*store.default_fee_recipient.read().unwrap(), [0u8; 20]);
        assert_eq!(*store.default_gas_limit.read().unwrap(), 30_000_000);
        assert!(store.default_graffiti.read().unwrap().is_none());
    }

    #[test]
    fn test_reload_config_resets_individual_default_fields() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 50000000
graffiti = "my graffiti"

[[validators]]
pubkey = "{}"
"#,
            fr_hex, pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        // Keep [defaults] but remove some fields
        let toml_v2 = format!(
            r#"
[defaults]
gas_limit = 40000000

[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        // fee_recipient and graffiti should reset to hardcoded fallbacks
        assert_eq!(*store.default_fee_recipient.read().unwrap(), [0u8; 20]);
        assert_eq!(*store.default_gas_limit.read().unwrap(), 40_000_000);
        assert!(store.default_graffiti.read().unwrap().is_none());
    }
}
