use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncServiceError {
    #[error("signer error: {0}")]
    Signer(String),

    #[error("beacon error: {0}")]
    Beacon(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_error_display() {
        let err = SyncServiceError::Signer("key not found".to_string());
        assert_eq!(err.to_string(), "signer error: key not found");
    }

    #[test]
    fn test_beacon_error_display() {
        let err = SyncServiceError::Beacon("timeout".to_string());
        assert_eq!(err.to_string(), "beacon error: timeout");
    }

    #[test]
    fn test_invalid_input_error_display() {
        let err = SyncServiceError::InvalidInput("mismatched".to_string());
        assert_eq!(err.to_string(), "invalid input: mismatched");
    }
}
