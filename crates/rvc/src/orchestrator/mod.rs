//! Duty orchestrator for coordinating the full validator workflow.
//!
//! This module provides the [`DutyOrchestrator`] service that coordinates
//! attestation duties, block proposals, and sync committee participation.

pub(crate) mod aggregation;
pub(crate) mod attestation;
mod coordinator;
pub(crate) mod duty_management;
mod error;
pub(crate) mod sync_committee;
pub(crate) mod utils;

pub use coordinator::{
    AttestationResult, DutyOrchestrator, OrchestratorConfig, OrchestratorHandle, PubkeyMap,
};
pub use error::OrchestratorError;
