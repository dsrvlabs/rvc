pub mod basic;
#[cfg(feature = "dvt")]
pub mod dvt;
pub mod signer_adapter;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningBackendError {
    #[error("key not found: 0x{}", hex::encode(.0))]
    KeyNotFound([u8; 48]),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("keystore load failed: {0}")]
    KeystoreLoadFailed(String),
}

#[async_trait]
pub trait SigningBackend: Send + Sync {
    async fn sign(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<[u8; 96], SigningBackendError>;

    fn public_keys(&self) -> Vec<[u8; 48]>;
}
