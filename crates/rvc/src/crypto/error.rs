use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlsError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_public_key_display() {
        let err = BlsError::InvalidPublicKey("wrong length".to_string());
        assert_eq!(err.to_string(), "Invalid public key: wrong length");
    }

    #[test]
    fn test_invalid_secret_key_display() {
        let err = BlsError::InvalidSecretKey("invalid bytes".to_string());
        assert_eq!(err.to_string(), "Invalid secret key: invalid bytes");
    }

    #[test]
    fn test_invalid_signature_display() {
        let err = BlsError::InvalidSignature("malformed".to_string());
        assert_eq!(err.to_string(), "Invalid signature: malformed");
    }

    #[test]
    fn test_signature_verification_failed_display() {
        let err = BlsError::SignatureVerificationFailed;
        assert_eq!(err.to_string(), "Signature verification failed");
    }
}
