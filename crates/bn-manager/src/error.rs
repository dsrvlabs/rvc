use beacon::BeaconError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BnManagerError {
    #[error("no beacon node endpoints configured")]
    NoEndpoints,

    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error(transparent)]
    Beacon(#[from] BeaconError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_endpoints_display() {
        let err = BnManagerError::NoEndpoints;
        assert_eq!(err.to_string(), "no beacon node endpoints configured");
    }

    #[test]
    fn test_invalid_endpoint_display() {
        let err = BnManagerError::InvalidEndpoint("bad url".to_string());
        assert_eq!(err.to_string(), "invalid endpoint: bad url");
    }

    #[test]
    fn test_beacon_error_conversion() {
        let beacon_err = BeaconError::HttpError("connection refused".to_string());
        let err: BnManagerError = beacon_err.into();
        assert!(matches!(err, BnManagerError::Beacon(_)));
    }
}
