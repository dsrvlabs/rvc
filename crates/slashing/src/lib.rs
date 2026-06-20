//! Slashing protection module for validator client.
//!
//! This module provides types and functionality for slashing protection
//! as specified in EIP-3076.

mod audit;
mod db;
mod error;
mod migration;
mod reader;
mod scoped;
mod stage;
mod types;

pub use audit::audit_log;
pub use db::SlashingDb;
pub use error::{AttestationSlashingViolation, BlockSlashingViolation, SlashingError};
pub use reader::{SlashingDbReader, TargetEpoch};
pub use scoped::PubkeyScopedDb;
pub use stage::{StagedAttestation, StagedBlock};
pub use types::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata, PruneStats,
    SignedAttestation, SignedBlock, ValidatorRecord,
};
