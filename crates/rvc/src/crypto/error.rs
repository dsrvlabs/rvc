use std::path::PathBuf;

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

    #[error("Rate limit exceeded for keystore decryption: {0}")]
    RateLimitExceeded(String),
}

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Directory not found: {0}")]
    DirectoryNotFound(PathBuf),

    #[error("No keystore files found in directory")]
    NoKeystoreFiles,

    #[error("Failed to load keystore from {path}: {source}")]
    KeystoreLoadFailed {
        path: PathBuf,
        #[source]
        source: KeystoreError,
    },

    #[error("Failed to decrypt keystore from {path}: {source}")]
    DecryptionFailed {
        path: PathBuf,
        #[source]
        source: KeystoreError,
    },

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

    #[test]
    fn test_key_manager_directory_not_found() {
        let err = KeyManagerError::DirectoryNotFound(PathBuf::from("/nonexistent/path"));
        assert_eq!(err.to_string(), "Directory not found: /nonexistent/path");
    }

    #[test]
    fn test_key_manager_no_keystore_files() {
        let err = KeyManagerError::NoKeystoreFiles;
        assert_eq!(err.to_string(), "No keystore files found in directory");
    }

    #[test]
    fn test_keystore_rate_limit_exceeded() {
        let err = KeystoreError::RateLimitExceeded("abc123".to_string());
        assert_eq!(err.to_string(), "Rate limit exceeded for keystore decryption: abc123");
    }
}
