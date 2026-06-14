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
    ///
    /// The slot/epoch was NOT consumed: no slashing-DB row was written.
    #[error("signing blocked by doppelganger gate")]
    BlockedByDoppelganger,

    /// The slashing-protection database rejected the sign request at the *stage*
    /// step — a potential double-vote or double-block-proposal was detected.
    ///
    /// The slot/epoch IS consumed by the EIP-3076 check: retrying with a
    /// **different** signing root for the same slot/epoch is still blocked.
    /// A `BlockedBySlashingDb` from `stage_*` means the signing root has
    /// already been committed (or the current signing root conflicts with an
    /// existing one).  Do NOT retry with a different root; the same root is
    /// still safe on a re-sign path.
    ///
    /// Display intentionally omits the raw `SlashingError` internals (which may
    /// contain SQLite paths or lock messages) so this variant is safe to surface
    /// to API callers.  The underlying error is available via `source()`.
    #[error("signing blocked by slashing protection")]
    BlockedBySlashingDb(#[source] SlashingError),

    /// The slashing-protection database accepted the sign request (stage
    /// succeeded, signing succeeded) but the *commit* step failed with an I/O
    /// error.
    ///
    /// This is the **opposite** of `BlockedBySlashingDb`: nothing was written to
    /// the database, so retrying with the **same** signing root is safe.  The
    /// BLS signature bytes are lost; the caller must obtain a new signature.
    ///
    /// Display intentionally omits raw SQLite internals.  The underlying error
    /// is available via `source()`.
    #[error("slashing-protection commit failed (no row written; same-root retry is safe)")]
    SlashingDbCommitFailed(#[source] SlashingError),

    /// The BLS signing backend returned an error that is not `KeyNotFound`.
    ///
    /// The staged slashing-DB row was discarded; no phantom row was committed.
    /// Same-root retry is safe once the backend recovers.
    #[error("signing backend failed: {0}")]
    SigningFailed(String),

    /// The signing backend has no key for the requested pubkey.
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
