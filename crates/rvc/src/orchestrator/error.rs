//! Error types for the duty orchestrator.

use thiserror::Error;

use crate::propagator::PropagatorError;
use crate::signer::SignerError;
use crate::timing::TimingError;
use beacon::BeaconError;
use duty_tracker::DutyTrackerError;

/// Errors that can occur during duty orchestration.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("Timing error: {0}")]
    Timing(#[from] TimingError),

    #[error("Duty tracker error: {0}")]
    DutyTracker(#[from] DutyTrackerError),

    #[error("Signer error: {0}")]
    Signer(#[from] SignerError),

    #[error("Propagator error: {0}")]
    Propagator(#[from] PropagatorError),

    #[error("Beacon error: {0}")]
    Beacon(#[from] BeaconError),

    #[error("Slot {slot} was missed (current slot is {current_slot})")]
    SlotMissed { slot: u64, current_slot: u64 },

    #[error("Shutdown requested")]
    Shutdown,

    #[error("No duties found for slot {slot}")]
    NoDutiesForSlot { slot: u64 },

    #[error("Failed to parse attestation data: {0}")]
    ParseError(String),

    #[error("Invalid validator pubkey: {0}")]
    InvalidPubkey(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_error_display_timing() {
        let timing_err = TimingError::Cancelled;
        let err = OrchestratorError::Timing(timing_err);
        assert_eq!(err.to_string(), "Timing error: timer cancelled");
    }

    #[test]
    fn test_orchestrator_error_display_slot_missed() {
        let err = OrchestratorError::SlotMissed { slot: 100, current_slot: 105 };
        assert_eq!(err.to_string(), "Slot 100 was missed (current slot is 105)");
    }

    #[test]
    fn test_orchestrator_error_display_shutdown() {
        let err = OrchestratorError::Shutdown;
        assert_eq!(err.to_string(), "Shutdown requested");
    }

    #[test]
    fn test_orchestrator_error_display_no_duties() {
        let err = OrchestratorError::NoDutiesForSlot { slot: 42 };
        assert_eq!(err.to_string(), "No duties found for slot 42");
    }

    #[test]
    fn test_orchestrator_error_display_parse_error() {
        let err = OrchestratorError::ParseError("invalid format".to_string());
        assert_eq!(err.to_string(), "Failed to parse attestation data: invalid format");
    }

    #[test]
    fn test_orchestrator_error_display_invalid_pubkey() {
        let err = OrchestratorError::InvalidPubkey("0xabc".to_string());
        assert_eq!(err.to_string(), "Invalid validator pubkey: 0xabc");
    }

    #[test]
    fn test_from_timing_error() {
        let timing_err = TimingError::BeforeGenesis { current_time: 100, genesis_time: 200 };
        let err: OrchestratorError = timing_err.into();
        assert!(matches!(err, OrchestratorError::Timing(_)));
    }

    #[test]
    fn test_from_beacon_error() {
        let beacon_err = BeaconError::Timeout;
        let err: OrchestratorError = beacon_err.into();
        assert!(matches!(err, OrchestratorError::Beacon(_)));
    }
}
