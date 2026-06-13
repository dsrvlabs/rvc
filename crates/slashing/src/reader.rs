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
pub trait SlashingDbReader {
    /// The highest target epoch this validator has attested under the DB's pinned GVR,
    /// or `None` if there is no such record (or the DB's pinned GVR differs from `gvr`).
    fn last_signed_attestation(&self, pubkey: &str, gvr: &Root) -> Option<TargetEpoch>;
}

impl SlashingDbReader for SlashingDb {
    /// Returns the maximum target epoch recorded for `pubkey`, scoped to `gvr`.
    ///
    /// # GVR scoping
    ///
    /// `SignedAttestation` carries no per-row GVR field; GVR scoping is therefore enforced
    /// via the DB's single pinned GVR (stored in `metadata.genesis_validators_root`).  If
    /// `self.pinned_gvr()` returns `Ok(Some(pinned))` and `pinned != *gvr`, the caller is
    /// asking about a different chain, so we return `None` — there is no relevant prior
    /// attestation under the requested GVR.  If the DB has no pinned GVR yet (`Ok(None)`),
    /// we proceed and return whatever records exist (backward-compat behaviour).
    ///
    /// # Fail-quiet contract
    ///
    /// Any I/O or parse error from `pinned_gvr()` or `get_attestations()` is silently
    /// mapped to `None`.  The trait returns no `Result` by design: this is a best-effort
    /// read used to inform safe-skip decisions; an error means "no usable record".
    fn last_signed_attestation(&self, pubkey: &str, gvr: &Root) -> Option<TargetEpoch> {
        match self.pinned_gvr() {
            Ok(Some(pinned)) if pinned != *gvr => return None,
            Err(_) => return None,
            _ => {}
        }

        self.get_attestations(pubkey).ok().and_then(|v| v.into_iter().map(|a| a.target_epoch).max())
    }
}
