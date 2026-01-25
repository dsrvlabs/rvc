//! Slashing protection error types.

use thiserror::Error;

use crate::crypto::Epoch;

/// Errors that can occur during slashing protection operations.
#[derive(Debug, Error)]
pub enum SlashingError {
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("migration error: {0}")]
    MigrationError(String),

    #[error("attestation slashable: {0}")]
    SlashableAttestation(#[from] AttestationSlashingViolation),

    #[error("genesis validators root mismatch: expected {expected}, got {actual}")]
    GenesisValidatorsRootMismatch { expected: String, actual: String },

    #[error("invalid interchange format: {0}")]
    InvalidInterchangeFormat(String),
}

/// Specific types of attestation slashing violations per EIP-3076.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestationSlashingViolation {
    #[error("double vote: already signed attestation for target epoch {target_epoch}")]
    DoubleVote { target_epoch: Epoch },

    #[error(
        "surrounding vote: new attestation ({new_source}, {new_target}) surrounds existing ({existing_source}, {existing_target})"
    )]
    SurroundingVote {
        new_source: Epoch,
        new_target: Epoch,
        existing_source: Epoch,
        existing_target: Epoch,
    },

    #[error(
        "surrounded vote: new attestation ({new_source}, {new_target}) is surrounded by existing ({existing_source}, {existing_target})"
    )]
    SurroundedVote {
        new_source: Epoch,
        new_target: Epoch,
        existing_source: Epoch,
        existing_target: Epoch,
    },
}
