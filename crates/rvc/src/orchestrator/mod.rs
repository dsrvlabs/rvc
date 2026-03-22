//! Duty orchestrator for coordinating the full validator workflow.
//!
//! This module provides the [`DutyOrchestrator`] service that coordinates
//! attestation duties, block proposals, and sync committee participation.

mod error;
mod service;
pub(crate) mod utils;

pub use error::OrchestratorError;
pub use service::{DutyOrchestrator, OrchestratorConfig, OrchestratorHandle, PubkeyMap};
