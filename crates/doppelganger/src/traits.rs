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

/// Abstraction for reading the last signed attestation epoch from the slashing DB.
pub trait SlashingDbReader: Send + Sync {
    fn last_signed_attestation_epoch(
        &self,
        pubkey: &str,
    ) -> Result<Option<Epoch>, DoppelgangerError>;
}
