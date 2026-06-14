//! Trait abstractions for doppelganger detection dependencies.

use async_trait::async_trait;
use eth_types::Epoch;

use crate::DoppelgangerError;

/// Liveness data for a single validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorLivenessData {
    pub index: String,
    pub is_live: bool,
}

/// Abstraction for querying validator liveness from a beacon node.
///
/// # Completeness contract (D-2, Issue 2.7)
///
/// A response from `check_liveness` MUST include an entry for every validator
/// index that was requested.  A missing entry is treated as **inconclusive**
/// (fail-closed): `ForwardWindowMachine::observe_liveness` will not record
/// that epoch as observed for the absent validator, preventing a `Safe`
/// transition until a complete response is received.
///
/// Implementors must NOT silently drop entries for validators whose liveness
/// could not be determined.  If the beacon node returns a partial response,
/// the implementor should return `Err(DoppelgangerError::IncompleteLiveness)`
/// rather than an incomplete `Vec`.
#[async_trait]
pub trait LivenessChecker: Send + Sync {
    async fn check_liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[String],
    ) -> Result<Vec<ValidatorLivenessData>, DoppelgangerError>;
}

/// GVR-blind reader used exclusively by [`crate::DoppelgangerService`].
///
/// Returns only the most-recent target epoch (no GVR scoping).  Named
/// `LegacySlashingHistoryReader` to distinguish it from
/// [`slashing::SlashingDbReader`], the GVR-aware reader consumed by
/// [`crate::ForwardWindowMachine`].  Using the wrong reader for the
/// forward-window machine would bypass chain-identity checks.
pub trait LegacySlashingHistoryReader: Send + Sync {
    fn last_signed_attestation_epoch(
        &self,
        pubkey: &str,
    ) -> Result<Option<Epoch>, DoppelgangerError>;
}
