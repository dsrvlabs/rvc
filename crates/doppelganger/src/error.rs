//! Error types for doppelganger detection.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DoppelgangerError {
    #[error("liveness check failed: {0}")]
    LivenessCheckFailed(String),

    #[error("slashing DB query failed: {0}")]
    SlashingDbError(String),

    #[error("incomplete liveness response: missing entry for one or more requested validators")]
    IncompleteLiveness,
}
