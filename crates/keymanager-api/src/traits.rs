use async_trait::async_trait;
use thiserror::Error;

use crate::error::ApiError;

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
    /// Flip the attesting-enabled state of an existing validator.
    ///
    /// No-op if `pubkey` is not tracked (e.g. already deleted).
    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool);
}

/// Triggers doppelganger detection for newly imported keys.
pub trait DoppelgangerMonitor: Send + Sync {
    fn start_monitoring(&self, pubkey: Pubkey);
    fn stop_monitoring(&self, pubkey: &Pubkey);
    /// Returns `true` if the doppelganger window for this key has elapsed.
    ///
    /// Keys that are not under active monitoring (e.g. existing keys loaded at
    /// startup) are considered safe and return `true` by default.
    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool;
}

#[derive(Debug, Error)]
pub enum ImportRemoteKeyError {
    #[error("duplicate key")]
    Duplicate,
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum DeleteRemoteKeyError {
    #[error("{0}")]
    Other(String),
}

/// Manages remote signing keys (Web3Signer).
pub trait RemoteKeyManager: Send + Sync {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)>;
    fn has_remote_key(&self, pubkey: &Pubkey) -> bool;
    fn import_remote_key(&self, pubkey: Pubkey, url: String) -> Result<(), ImportRemoteKeyError>;
    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError>;
}

/// Manages per-validator configuration: fee recipient, gas limit, and graffiti.
pub trait ValidatorConfigManager: Send + Sync {
    fn get_fee_recipient(&self, pubkey: &Pubkey) -> Result<[u8; 20], ApiError>;
    fn set_fee_recipient(&self, pubkey: &Pubkey, address: [u8; 20]) -> Result<(), ApiError>;
    fn delete_fee_recipient(&self, pubkey: &Pubkey) -> Result<(), ApiError>;
    fn get_gas_limit(&self, pubkey: &Pubkey) -> Result<u64, ApiError>;
    fn set_gas_limit(&self, pubkey: &Pubkey, limit: u64) -> Result<(), ApiError>;
    fn delete_gas_limit(&self, pubkey: &Pubkey) -> Result<(), ApiError>;
    fn get_graffiti(&self, pubkey: &Pubkey) -> Result<String, ApiError>;
    fn set_graffiti(&self, pubkey: &Pubkey, graffiti: &str) -> Result<(), ApiError>;
    fn delete_graffiti(&self, pubkey: &Pubkey) -> Result<(), ApiError>;
}

/// Manages voluntary exit signing for validators.
#[async_trait]
pub trait VoluntaryExitManager: Send + Sync {
    async fn sign_voluntary_exit(
        &self,
        pubkey: &Pubkey,
        epoch: Option<u64>,
    ) -> Result<eth_types::SignedVoluntaryExit, ApiError>;
}
