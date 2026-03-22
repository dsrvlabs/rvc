//! Duty orchestrator for coordinating the full validator workflow.
//!
//! This module provides the [`DutyOrchestrator`] service that coordinates
//! attestation duties, block proposals, and sync committee participation.

pub(crate) mod aggregation;
mod error;
mod service;
pub(crate) mod sync_committee;
pub(crate) mod utils;

pub use error::OrchestratorError;
pub use service::{DutyOrchestrator, OrchestratorConfig, OrchestratorHandle, PubkeyMap};
