//! Slashing protection error types.

use thiserror::Error;

use eth_types::{Epoch, Slot};

/// Errors that can occur during slashing protection operations.
#[derive(Debug, Error)]
pub enum SlashingError {
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("migration error: {0}")]
    MigrationError(String),

    #[error("attestation slashable: {0}")]
    SlashableAttestation(#[from] AttestationSlashingViolation),

    #[error("block slashable: {0}")]
    SlashableBlock(#[from] BlockSlashingViolation),

    #[error("genesis validators root mismatch: expected {expected}, got {actual}")]
    GenesisValidatorsRootMismatch { expected: String, actual: String },

    #[error("invalid interchange format: {0}")]
    InvalidInterchangeFormat(String),

    #[error("database integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    #[error("watermark can only be raised: attempted to lower {watermark_type} for {pubkey}")]
    WatermarkLowered { pubkey: String, watermark_type: String },

    #[error("no watermarks set: pruning without watermarks would delete all records")]
    NoWatermarksSet,

    #[error("block at slot {slot} is below watermark slot {watermark_slot}")]
    BelowBlockWatermark { slot: Slot, watermark_slot: Slot },

    #[error("attestation with target epoch {target_epoch} is below watermark target epoch {watermark_target}")]
    BelowAttestationWatermark { target_epoch: Epoch, watermark_target: Epoch },

    #[error("attestation with source epoch {source_epoch} is below watermark source epoch {watermark_source}")]
    BelowAttestationSourceWatermark { source_epoch: Epoch, watermark_source: Epoch },

    #[error("unsafe file permissions on {path} (mode {mode}): group or world accessible")]
    UnsafePermissions { path: String, mode: String },
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

    #[error("target epoch {target_epoch} is below minimum existing target epoch {min_target}")]
    TargetEpochBelowMinimum { target_epoch: Epoch, min_target: Epoch },
}

/// Specific types of block slashing violations per EIP-3076.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlockSlashingViolation {
    #[error("double block proposal: already signed a different block for slot {slot}")]
    DoubleBlockProposal { slot: Slot },

    #[error("slot {slot} is below minimum existing slot {min_slot}")]
    SlotBelowMinimum { slot: Slot, min_slot: Slot },
}
