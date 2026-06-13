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
