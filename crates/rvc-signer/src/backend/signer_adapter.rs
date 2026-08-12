//! Adapter from `SigningBackend` to the `crypto::Signer` trait.
//!
//! `SigningGate::new_with_raw_signer` accepts an `Arc<dyn crypto::Signer>`.
//! The standalone `rvc-signer` binary operates through its own `SigningBackend`
//! abstraction, which has the same raw-root shape but different error and return
//! types.  This adapter bridges the two:
//!
//! - `SigningBackend::sign(&[u8;32], &[u8;48]) -> Result<[u8;96], SigningBackendError>`
//!   maps to
//!   `crypto::Signer::sign(&Root, &[u8;48]) -> Result<Signature, SigningError>`.
//!
//! Error mapping:
//! - `SigningBackendError::KeyNotFound` → `SigningError::KeyNotFound`
//! - `SigningBackendError::SigningFailed` → `SigningError::RemoteSignerError`
//! - `SigningBackendError::KeystoreLoadFailed` → `SigningError::RemoteSignerError`
//!
//! # Why NOT route through `CompositeSigner`
//!
//! `CompositeSigner` is designed for the local VC path and rejects raw-root
//! signing for gRPC remote keys (they require `TypedSigner`).  The `rvc-signer`
//! binary's `SigningBackend` already computes the signing root and delegates to
//! the appropriate backend (basic keystore or DVT).  Wrapping it in the adapter
//! preserves that behaviour while satisfying the `Arc<dyn crypto::Signer>`
//! contract required by `SigningGate::new_with_raw_signer`.

use std::sync::Arc;

use async_trait::async_trait;
use crypto::{Signature, Signer, SigningError};
use eth_types::Root;

use super::{SigningBackend, SigningBackendError};

/// Adapts [`SigningBackend`] to the [`crypto::Signer`] trait.
///
/// The standalone signer does not run doppelganger detection; the calling VC
/// enforces it.  The gate here provides the slashing-protection + per-pubkey-lock
/// layers only.
pub struct SigningBackendAsSigner(pub Arc<dyn SigningBackend>);

#[async_trait]
impl Signer for SigningBackendAsSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        let raw = self.0.sign(signing_root, pubkey).await.map_err(map_backend_err)?;
        Signature::from_bytes(&raw)
            .map_err(|e| SigningError::RemoteSignerError(format!("invalid signature bytes: {e}")))
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.0.public_keys()
    }
}

fn map_backend_err(e: SigningBackendError) -> SigningError {
    match e {
        SigningBackendError::KeyNotFound(pk) => {
            SigningError::KeyNotFound(format!("0x{}", hex::encode(pk)))
        }
        SigningBackendError::SigningFailed(msg) => SigningError::RemoteSignerError(msg),
        SigningBackendError::KeystoreLoadFailed(msg) => SigningError::RemoteSignerError(msg),
    }
}
