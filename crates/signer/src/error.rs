//! Error types for gate- and service-guarded signing operations.
//!
//! # Signing error taxonomy (D3 / RF4-03)
//!
//! Both [`SigningGateError`] (rvc-signer / external path) and
//! [`crate::SignerError`] (VC / in-process path) distinguish two slashing-related
//! failures with **opposite** retry semantics:
//!
//! | Concept | Variants | DB write | Retry contract |
//! |---|---|---|---|
//! | **SlashingBlocked** | `SigningGateError::SlashingBlocked`, `SignerError::SlashingBlocked` | Slashable/policy stage rejections leave history that consumes slot/epoch semantics; pure stage I/O errors write nothing | **Never** treat as `CommitFailed` same-root advertising. Different-root retry for the same slot/epoch is unsafe after a slashable stage rejection. EIP-3076 same-root re-sign after a prior successful commit is a separate stage path — not what [`SigningGateError::permits_retry_with_root`] / `SignerError::permits_retry_with_root` authorize. |
//! | **CommitFailed** | `SigningGateError::CommitFailed`, `SignerError::CommitFailed` | Nothing written (txn rolled back) | Same-root retry is **safe**. Different-root retry must be refused by the caller (use the carried `signing_root`). |
//!
//! A shared `classify()` mapper over this taxonomy lands in RF4-07; keep the
//! variant names and retry docs aligned so both transports consume one class set.

use eth_types::Root;
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
    /// See module-level **SlashingBlocked** retry contract: do not retry with a
    /// different root for the same slot/epoch.
    ///
    /// Display intentionally omits the raw `SlashingError` internals (which may
    /// contain SQLite paths or lock messages) so this variant is safe to surface
    /// to API callers.  The underlying error is available via `source()`.
    #[error("signing blocked by slashing protection")]
    SlashingBlocked(#[source] SlashingError),

    /// The slashing-protection database accepted the sign request (stage
    /// succeeded, signing succeeded) but the *commit* step failed with an I/O
    /// error.
    ///
    /// See module-level **CommitFailed** retry contract: same-root retry is safe;
    /// `signing_root` is the only root a caller may retry with.  The BLS
    /// signature bytes are lost; the caller must obtain a new signature.
    ///
    /// Display intentionally omits raw SQLite internals.  The underlying error
    /// is available via `source()`.
    #[error("slashing-protection commit failed (no row written; same-root retry is safe)")]
    CommitFailed {
        /// Signing root that was staged (and must be used for any retry).
        signing_root: Root,
        #[source]
        source: SlashingError,
    },

    /// The BLS signing backend failed, timed out, or the blocking task panicked.
    ///
    /// # Staged-row fate (do not assume discard)
    ///
    /// Whether a staged slashing-DB row was discarded depends on **how** this
    /// variant was produced by [`crate::sign_slashable`]:
    ///
    /// | Cause | Typical row fate |
    /// |---|---|
    /// | Unambiguous no-signature (`KeyNotFound`, `LocalRejected`, `UnsupportedSigningType`) | Discarded (ROLLBACK) |
    /// | Sign **timeout** + [`crate::TimeoutPolicy::DiscardStagedRow`] | Discarded |
    /// | Sign **timeout** + [`crate::TimeoutPolicy::RetainStagedRow`] | **Committed** (fail-closed history; slot/epoch consumed) |
    /// | Ambiguous backend error + [`crate::TimeoutPolicy::DiscardStagedRow`] | Discarded |
    /// | Ambiguous backend error + [`crate::TimeoutPolicy::RetainStagedRow`] | **Committed** (remote may have signed) |
    /// | Panic of the blocking task after stage | Unspecified — treat history as possibly written |
    ///
    /// Callers **must not** treat `SigningFailed` as “slot free / different-root
    /// retry safe.” After a retain path, a conflicting different-root retry is
    /// blocked by stage (EIP-3076); only same-root re-sign may apply.
    /// [`SigningGateError::permits_retry_with_root`] does **not** special-case
    /// this variant (it only authorizes `CommitFailed` same-root retry).
    ///
    /// See [`crate::TimeoutPolicy`]: policy applies to timeout **and** ambiguous
    /// non-timeout signer errors (not `KeyNotFound`).
    #[error("signing backend failed: {0}")]
    SigningFailed(String),

    /// The signing backend has no key for the requested pubkey.
    ///
    /// On the slashable core path the staged row is discarded (no signature was
    /// produced for this key). Not used for retain-on-timeout.
    #[error("key not found in signing backend")]
    KeyNotFound,

    /// The pubkey is not registered with the signing enablement implementation.
    ///
    /// Currently **unconstructed** by the gate.  When an unknown pubkey is
    /// presented, `SigningEnablement::is_signing_enabled` returns `false` (the
    /// fail-closed default) and the gate returns `BlockedByDoppelganger` —
    /// it cannot distinguish "unknown pubkey" from "doppelganger-blocked pubkey"
    /// because `is_signing_enabled` exposes only a `bool`, not a status enum.
    ///
    /// This variant is retained for the future path where `SigningEnablement`
    /// is extended to return a richer status (unknown vs. blocked vs. allowed),
    /// at which point the gate can route unknown pubkeys here instead of into
    /// `BlockedByDoppelganger`.
    #[error("pubkey not registered with signing gate")]
    UnknownPubkey,
}

impl SigningGateError {
    /// Taxonomy-level check for **commit-failure same-root retry** only.
    ///
    /// - `CommitFailed` → `true` only when `proposed_root` equals the carried root.
    /// - `SlashingBlocked` → always `false` here (conservative; not an EIP-3076
    ///   same-root re-sign oracle — that is a separate stage check).
    /// - Other variants → `false`.
    ///
    /// Not a general oracle for stage I/O recoverability.
    pub fn permits_retry_with_root(&self, proposed_root: &Root) -> bool {
        match self {
            Self::CommitFailed { signing_root, .. } => signing_root == proposed_root,
            Self::SlashingBlocked(_) => false,
            _ => false,
        }
    }
}
