//! Error types for `SigningGate` operations.

use slashing::SlashingError;
use thiserror::Error;

/// Errors that can occur during gate-guarded signing operations.
#[derive(Debug, Error)]
pub enum SigningGateError {
    /// The doppelganger gate denied signing for this pubkey.
    ///
    /// Either the validator is not yet cleared through the monitoring window, or
    /// the pubkey is unknown to the enablement implementation (fail-closed).
    #[error("signing blocked by doppelganger gate")]
    BlockedByDoppelganger,

    /// The slashing-protection database rejected the signing request.
    ///
    /// This indicates a potential double-vote or double-block-proposal.
    #[error("signing blocked by slashing-protection database: {0}")]
    BlockedBySlashingDb(#[from] SlashingError),

    /// The BLS signing backend returned an error.
    ///
    /// The staged slashing-DB row was discarded; no phantom row was committed.
    #[error("signing backend failed: {0}")]
    SigningFailed(String),

    /// The signing backend does not have a key for the requested pubkey.
    ///
    /// The staged slashing-DB row was discarded; no phantom row was committed.
    #[error("key not found in signing backend")]
    KeyNotFound,

    /// The pubkey is not registered with the signing enablement implementation.
    ///
    /// Reserved for use by 2.9b (FailClosedDefault routing); in 2.9a a false
    /// from the enablement gate returns `BlockedByDoppelganger`.
    #[error("pubkey not registered with signing gate")]
    UnknownPubkey,
}
