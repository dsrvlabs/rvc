//! Duty orchestrator for coordinating the full validator workflow.
//!
//! This module provides the [`DutyOrchestrator`] service that coordinates
//! attestation duties, block proposals, and sync committee participation.

pub(crate) mod aggregation;
pub(crate) mod attestation;
pub(crate) mod block_proposal;
mod coordinator;
pub(crate) mod duty_management;
mod error;
pub(crate) mod slot_context;
pub(crate) mod sync_committee;
pub(crate) mod utils;
pub mod validation;

pub use coordinator::{
    AttestationResult, DutyOrchestrator, OrchestratorConfig, OrchestratorDeps, OrchestratorHandle,
    PubkeyMap,
};
pub use error::OrchestratorError;
// Re-export so callers that already depend on `rvc::orchestrator` can reach the
// shared index registry without a second import path.
pub use crate::pubkey_index::{
    parse_pubkey_bytes, pubkey_bytes_to_0x, PubkeyIndexRegistry, SharedPubkeyIndexRegistry,
};
