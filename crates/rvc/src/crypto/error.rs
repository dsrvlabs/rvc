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

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Invalid JSON format: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("Unsupported keystore version: {0}")]
    UnsupportedVersion(u32),

    #[error("Unsupported KDF function: {0}")]
    UnsupportedKdf(String),

    #[error("Unsupported cipher function: {0}")]
    UnsupportedCipher(String),

    #[error("Unsupported checksum function: {0}")]
    UnsupportedChecksum(String),

    #[error("Invalid hex encoding: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("Checksum mismatch: decryption failed")]
    ChecksumMismatch,

    #[error("Invalid scrypt parameters: {0}")]
    InvalidScryptParams(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(#[from] BlsError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
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

    #[test]
    fn test_keystore_unsupported_version() {
        let err = KeystoreError::UnsupportedVersion(3);
        assert_eq!(err.to_string(), "Unsupported keystore version: 3");
    }

    #[test]
    fn test_keystore_unsupported_kdf() {
        let err = KeystoreError::UnsupportedKdf("argon2".to_string());
        assert_eq!(err.to_string(), "Unsupported KDF function: argon2");
    }

    #[test]
    fn test_keystore_checksum_mismatch() {
        let err = KeystoreError::ChecksumMismatch;
        assert_eq!(err.to_string(), "Checksum mismatch: decryption failed");
    }
}
