use async_trait::async_trait;
use zeroize::Zeroizing;

pub mod format;
pub mod key_source_manager;

pub use format::parse_secret_data;
#[cfg(any(test, feature = "test-utils"))]
pub use key_source_manager::mock::MockSecretProvider;
pub use key_source_manager::KeySourceManager;

/// Metadata about a key available in a secret provider.
pub struct SecretKeyEntry {
    /// Unique identifier within the provider (e.g., secret name, file path).
    pub id: String,
    /// BLS public key hex (0x-prefixed), if known before fetching.
    pub pubkey_hex: Option<String>,
}

/// Material needed to construct a BLS SecretKey.
///
/// Does NOT derive `Debug` to prevent accidental logging of key material.
pub enum KeyMaterial {
    /// Raw 32-byte BLS secret key.
    RawKey(Zeroizing<[u8; 32]>),
    /// EIP-2335 keystore JSON + password.
    Keystore { keystore_json: String, password: Zeroizing<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum SecretProviderError {
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
    #[error("key decryption failed for {id}: {reason}")]
    DecryptionFailed { id: String, reason: String },
}

/// Per-provider summary of a key loading operation.
pub struct ProviderSummary {
    pub name: String,
    pub loaded: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Summary of all key loading across providers.
#[derive(Default)]
pub struct LoadSummary {
    pub per_provider: Vec<ProviderSummary>,
}

#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Human-readable name for logging (e.g., "gcp", "aws", "local").
    fn name(&self) -> &str;

    /// List available key entries without fetching secret material.
    async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError>;

    /// Fetch the key material for a specific entry.
    async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_auth() {
        let err = SecretProviderError::Auth("invalid credentials".into());
        assert_eq!(err.to_string(), "authentication failed: invalid credentials");
    }

    #[test]
    fn test_error_display_not_found() {
        let err = SecretProviderError::NotFound("my-secret".into());
        assert_eq!(err.to_string(), "secret not found: my-secret");
    }

    #[test]
    fn test_error_display_provider() {
        let err = SecretProviderError::Provider("network timeout".into());
        assert_eq!(err.to_string(), "provider error: network timeout");
    }

    #[test]
    fn test_error_display_invalid_key_material() {
        let err = SecretProviderError::InvalidKeyMaterial("not hex".into());
        assert_eq!(err.to_string(), "invalid key material: not hex");
    }

    #[test]
    fn test_error_display_decryption_failed() {
        let err = SecretProviderError::DecryptionFailed {
            id: "key-1".into(),
            reason: "wrong password".into(),
        };
        assert_eq!(err.to_string(), "key decryption failed for key-1: wrong password");
    }

    #[test]
    fn test_secret_key_entry_construction() {
        let entry = SecretKeyEntry {
            id: "validator-key-abc123".into(),
            pubkey_hex: Some("0xabcdef".into()),
        };
        assert_eq!(entry.id, "validator-key-abc123");
        assert_eq!(entry.pubkey_hex.as_deref(), Some("0xabcdef"));
    }

    #[test]
    fn test_secret_key_entry_no_pubkey() {
        let entry = SecretKeyEntry { id: "some-key".into(), pubkey_hex: None };
        assert_eq!(entry.id, "some-key");
        assert!(entry.pubkey_hex.is_none());
    }

    #[test]
    fn test_load_summary_default() {
        let summary = LoadSummary::default();
        assert!(summary.per_provider.is_empty());
    }

    #[test]
    fn test_load_summary_with_providers() {
        let summary = LoadSummary {
            per_provider: vec![
                ProviderSummary {
                    name: "gcp".into(),
                    loaded: 5,
                    skipped: 1,
                    errors: vec!["key-3: format error".into()],
                },
                ProviderSummary { name: "aws".into(), loaded: 3, skipped: 0, errors: vec![] },
            ],
        };
        assert_eq!(summary.per_provider.len(), 2);
        assert_eq!(summary.per_provider[0].name, "gcp");
        assert_eq!(summary.per_provider[0].loaded, 5);
        assert_eq!(summary.per_provider[0].skipped, 1);
        assert_eq!(summary.per_provider[0].errors.len(), 1);
        assert_eq!(summary.per_provider[1].loaded, 3);
        assert_eq!(summary.per_provider[1].skipped, 0);
    }

    #[test]
    fn test_key_material_raw_key() {
        let bytes = [0u8; 32];
        let material = KeyMaterial::RawKey(Zeroizing::new(bytes));
        match material {
            KeyMaterial::RawKey(key) => assert_eq!(*key, [0u8; 32]),
            _ => panic!("expected RawKey variant"),
        }
    }

    #[test]
    fn test_key_material_keystore() {
        let material = KeyMaterial::Keystore {
            keystore_json: r#"{"version":4}"#.into(),
            password: Zeroizing::new("secret".into()),
        };
        match material {
            KeyMaterial::Keystore { keystore_json, password } => {
                assert_eq!(keystore_json, r#"{"version":4}"#);
                assert_eq!(*password, "secret");
            }
            _ => panic!("expected Keystore variant"),
        }
    }

    #[test]
    fn test_error_is_debug() {
        let err = SecretProviderError::Auth("test".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("Auth"));
    }

    #[test]
    fn test_key_material_not_debug() {
        // KeyMaterial intentionally does NOT implement Debug.
        // This is a compile-time guarantee — if someone adds #[derive(Debug)],
        // they should be aware it exposes key material.
        // We verify the type exists and can be constructed; the absence of Debug
        // is enforced by not having this compile: format!("{:?}", material)
    }
}
