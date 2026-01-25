//! Error types for the propagator service.

use thiserror::Error;

use beacon_client::BeaconError;

/// Errors that can occur during attestation propagation.
#[derive(Error, Debug)]
pub enum PropagatorError {
    #[error("Beacon client error: {0}")]
    BeaconError(#[from] BeaconError),

    #[error("Partial attestation failure: {success_count} succeeded, {failure_count} failed")]
    PartialFailure { success_count: usize, failure_count: usize },

    #[error("All attestations failed submission")]
    AllAttestationsFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_propagator_error_display_beacon_error() {
        let beacon_err = BeaconError::Timeout;
        let err = PropagatorError::BeaconError(beacon_err);
        assert_eq!(err.to_string(), "Beacon client error: Request timeout");
    }

    #[test]
    fn test_propagator_error_display_partial_failure() {
        let err = PropagatorError::PartialFailure { success_count: 5, failure_count: 2 };
        assert_eq!(err.to_string(), "Partial attestation failure: 5 succeeded, 2 failed");
    }

    #[test]
    fn test_propagator_error_display_all_failed() {
        let err = PropagatorError::AllAttestationsFailed;
        assert_eq!(err.to_string(), "All attestations failed submission");
    }

    #[test]
    fn test_from_beacon_error() {
        let beacon_err = BeaconError::HttpError("connection refused".to_string());
        let err: PropagatorError = beacon_err.into();
        assert!(matches!(err, PropagatorError::BeaconError(_)));
    }
}
