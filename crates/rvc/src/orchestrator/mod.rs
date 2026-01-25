//! Duty orchestrator for coordinating the attestation workflow.
//!
//! This module provides the [`DutyOrchestrator`] service that coordinates
//! the full attestation workflow: duty fetch, slot timing, signing, and propagation.

mod error;
mod service;

pub use error::OrchestratorError;
pub use service::{DutyOrchestrator, OrchestratorConfig, OrchestratorHandle};
