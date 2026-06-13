//! Doppelganger detection for Ethereum validator clients.
//!
//! Detects if another instance is running with the same validator keys.
//! Implements restart-awareness (Lodestar pattern) to avoid false positives
//! when a validator client restarts after recently signing attestations.

mod enablement;
mod error;
mod forward_window;
mod service;
mod state;
mod traits;

pub use enablement::SigningEnablement;
pub use error::DoppelgangerError;
pub use forward_window::ForwardWindowMachine;
pub use service::DoppelgangerService;
pub use state::{DoppelgangerStatus as ForwardStatus, ValidatorState};
pub use traits::{LivenessChecker, SlashingDbReader, ValidatorLivenessData};

/// Status of doppelganger detection for a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoppelgangerStatus {
    /// Validator is safe to sign (restart-aware skip or monitoring complete).
    Safe,
    /// Detection is still in progress.
    DetectionInProgress,
    /// A doppelganger was detected for this validator.
    DoppelgangerDetected,
}

/// Result of a doppelganger check for a set of validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoppelgangerResult {
    /// Validators that are safe to sign.
    pub safe_validators: Vec<String>,
    /// Validators for which a doppelganger was detected.
    pub detected: Vec<String>,
}
