//! Read-only view over slashing-protection history.
//!
//! This module defines the [`SlashingDbReader`] trait — a deliberately narrow, read-only
//! seam that allows consumers (e.g. `doppelganger`) to query signing history without
//! receiving any staging or commit capability.  The absence of mutation methods is what
//! makes the forbidden `slashing → doppelganger` dependency edge impossible: `doppelganger`
//! depends on this trait, not on `SlashingDb` directly, so `slashing` never needs to know
//! that `doppelganger` exists.

use eth_types::Root;

use crate::SlashingDb;

/// A monotonically-increasing attestation target epoch.
///
/// Alias for now; may become a newtype later if stronger type-safety is needed.
pub type TargetEpoch = u64;

/// Read-only view over slashing-protection history.
///
/// This trait deliberately has NO staging, commit, or mutation methods — that is what
/// makes the `slashing → doppelganger` cycle impossible: `doppelganger` consumes this
/// read-only seam without gaining any ability to write to the slashing DB.
pub trait SlashingDbReader: Send + Sync {
    /// The highest target epoch this validator has attested under the DB's pinned GVR,
    /// or `None` if there is no such record (or the DB's pinned GVR differs from `gvr`).
    fn last_signed_attestation(&self, pubkey: &str, gvr: &Root) -> Option<TargetEpoch>;
}

impl SlashingDbReader for SlashingDb {
    /// Returns the maximum target epoch recorded for `pubkey`, scoped to `gvr`.
    ///
    /// # Fail-closed GVR scoping
    ///
    /// `SignedAttestation` carries no per-row GVR field; GVR scoping is therefore enforced
    /// via the DB's single pinned GVR (stored in `metadata.genesis_validators_root`).
    ///
    /// A `Some(epoch)` answer is consumed downstream as an **unlock** signal — the
    /// doppelganger forward-window's restart-aware safe-skip treats "we already have an
    /// attestation under this chain" as grounds to skip monitoring. An answer derived from
    /// an *unidentified* or *different* chain must therefore never be returned: it would
    /// skip doppelganger protection based on foreign signing history (a slashing-bypass
    /// hazard). This method is fail-closed (PRD §6.3): it returns `Some` **only** when the
    /// DB's pinned GVR exactly matches `gvr`. In every other case — GVR mismatch, no pinned
    /// GVR (chain identity unknown), or any I/O error — it returns `None`, which makes the
    /// caller run the full forward window. Missing a safe-skip optimization is harmless; a
    /// spurious unlock is not.
    ///
    /// Per-row GVR filtering (so legacy / cross-chain rows in a single DB cannot inflate the
    /// answer) lands with the Phase 2 DVT-1/CN-1/GVR-1 schema migration; until then this
    /// method relies on the DB's single-pinned-GVR invariant established at stage time.
    fn last_signed_attestation(&self, pubkey: &str, gvr: &Root) -> Option<TargetEpoch> {
        match self.pinned_gvr() {
            // Pinned GVR matches the requested chain — the only path that may answer `Some`.
            Ok(Some(pinned)) if pinned == *gvr => {}
            Ok(Some(pinned)) => {
                tracing::warn!(
                    requested_gvr = ?gvr,
                    pinned_gvr = ?pinned,
                    "SlashingDbReader: GVR mismatch; returning None (fail-closed)"
                );
                return None;
            }
            Ok(None) => {
                tracing::warn!(
                    "SlashingDbReader: DB has no pinned GVR; returning None \
                     (fail-closed — cannot confirm chain identity for safe-skip)"
                );
                return None;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "SlashingDbReader: pinned_gvr() failed; returning None (fail-closed)"
                );
                return None;
            }
        }

        match self.get_attestations(pubkey) {
            Ok(v) => v.into_iter().map(|a| a.target_epoch).max(),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "SlashingDbReader: get_attestations failed; returning None (fail-closed)"
                );
                None
            }
        }
    }
}
