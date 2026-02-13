use thiserror::Error;

pub type Pubkey = [u8; 48];

#[derive(Debug, Error)]
pub enum ImportKeystoreError {
    #[error("duplicate key")]
    Duplicate,
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid keystore: {0}")]
    InvalidKeystore(String),
    #[error("I/O error: {0}")]
    Io(String),
}

#[derive(Debug, Error)]
pub enum DeleteKeystoreError {
    #[error("I/O error: {0}")]
    Io(String),
}

/// Manages BLS keystores: decryption, import, removal, and file operations.
pub trait KeystoreManager: Send + Sync {
    fn list_keys(&self) -> Vec<Pubkey>;
    fn has_key(&self, pubkey: &Pubkey) -> bool;
    fn import_keystore(
        &self,
        keystore_json: &str,
        password: &str,
    ) -> Result<Pubkey, ImportKeystoreError>;
    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError>;
}

/// Manages EIP-3076 slashing protection interchange data.
pub trait SlashingProtection: Send + Sync {
    fn import_interchange(&self, interchange_json: &str) -> Result<(), String>;
    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, String>;
}

/// Manages validator configurations (enable/disable).
pub trait ValidatorManager: Send + Sync {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool);
    fn remove_validator(&self, pubkey: &Pubkey) -> bool;
}

/// Triggers doppelganger detection for newly imported keys.
pub trait DoppelgangerMonitor: Send + Sync {
    fn start_monitoring(&self, pubkey: Pubkey);
}
