use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum ShareError {
    #[error("failed to read directory: {0}")]
    ReadDir(String),

    #[error("failed to read file: {0}")]
    ReadFile(String),

    #[error("failed to parse keystore: {0}")]
    ParseKeystore(String),

    #[error("failed to decrypt keystore: {0}")]
    DecryptKeystore(String),

    #[error("missing share metadata sidecar for keystore: {0}")]
    MissingMetadata(String),

    #[error("failed to parse share metadata: {0}")]
    ParseMetadata(String),

    #[error("invalid share: scalar bytes length mismatch")]
    InvalidScalar,

    #[error("invalid aggregate pubkey in keystore: {0}")]
    InvalidPubkey(String),
}

/// Metadata sidecar for a Shamir share keystore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMetadata {
    pub threshold: u64,
    pub total: u64,
    pub index: u64,
}

/// A loaded Shamir secret share with its associated metadata.
///
/// `Clone` is derived so shares can be extracted from a `HashMap` by value.
/// The scalar bytes are wrapped in `Zeroizing` to ensure they are zeroed on
/// drop even after cloning.
#[derive(Debug, Clone)]
pub struct ShareInfo {
    pub index: u64,
    pub threshold: u64,
    pub total: u64,
    pub scalar_bytes: Zeroizing<[u8; 32]>,
    pub aggregate_pubkey: [u8; 48],
}

const SHARE_DESCRIPTION_MARKER: &str = "shamir-share";

/// Load Shamir secret shares from a directory of EIP-2335 keystores.
///
/// Each share keystore must have `description: "shamir-share"` and a companion
/// `share-meta.json` sidecar in the same directory with `threshold`, `total`, and `index`.
pub fn load_shares(dir: &Path, password: &Zeroizing<String>) -> Result<Vec<ShareInfo>, ShareError> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| ShareError::ReadDir(format!("{}: {}", dir.display(), e)))?;

    let mut shares = Vec::new();

    for entry in entries {
        let entry =
            entry.map_err(|e| ShareError::ReadDir(format!("failed to read entry: {}", e)))?;

        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let extension = path.extension().and_then(|e| e.to_str());
        if extension != Some("json") {
            continue;
        }

        // Skip metadata sidecar files
        if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n == "share-meta.json") {
            continue;
        }

        let keystore = crypto::Keystore::from_file(&path)
            .map_err(|e| ShareError::ParseKeystore(format!("{}: {}", path.display(), e)))?;

        // Only process keystores marked as Shamir shares
        let is_share = keystore.description.as_ref().is_some_and(|d| d == SHARE_DESCRIPTION_MARKER);
        if !is_share {
            continue;
        }

        // Load companion share-meta.json sidecar
        let meta_path = path.with_file_name("share-meta.json");
        let meta_json = std::fs::read_to_string(&meta_path)
            .map_err(|e| ShareError::MissingMetadata(format!("{}: {}", meta_path.display(), e)))?;
        let metadata: ShareMetadata = serde_json::from_str(&meta_json)
            .map_err(|e| ShareError::ParseMetadata(format!("{}: {}", meta_path.display(), e)))?;

        // Decrypt keystore to get the 32-byte scalar
        let secret_key = keystore
            .decrypt(password.as_bytes())
            .map_err(|e| ShareError::DecryptKeystore(format!("{}: {}", path.display(), e)))?;

        // Gate 1: DVT share-split needs the decrypted scalar bytes (kept in Zeroizing, never logged).
        #[allow(clippy::disallowed_methods)]
        let scalar_bytes = Zeroizing::new(secret_key.to_bytes());

        // Extract aggregate pubkey from keystore pubkey field
        let aggregate_pubkey = keystore
            .pubkey
            .as_ref()
            .and_then(|hex_str| {
                let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
                hex::decode(stripped).ok()
            })
            .and_then(|bytes| <[u8; 48]>::try_from(bytes).ok())
            .ok_or_else(|| {
                ShareError::InvalidPubkey(format!(
                    "{}: missing or invalid pubkey field",
                    path.display()
                ))
            })?;

        shares.push(ShareInfo {
            index: metadata.index,
            threshold: metadata.threshold,
            total: metadata.total,
            scalar_bytes,
            aggregate_pubkey,
        });
    }

    Ok(shares)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;
    use crypto::{EncryptionKdf, Keystore, SecretKey};
    use std::fs;
    use tempfile::TempDir;

    fn create_share_keystore(
        dir: &Path,
        sk: &SecretKey,
        password: &str,
        metadata: &ShareMetadata,
    ) -> String {
        let mut keystore = Keystore::encrypt(sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2)
            .expect("encryption should succeed");
        keystore.description = Some(SHARE_DESCRIPTION_MARKER.to_string());

        // Set the aggregate pubkey (for shares, this is the combined key, but for
        // testing we use the individual key's pubkey)
        keystore.pubkey = Some(hex::encode(sk.public_key().to_bytes()));

        let json = keystore.to_json().expect("serialize");
        let filename = format!("share-{}.json", metadata.index);
        fs::write(dir.join(&filename), json).expect("write keystore");

        // Write metadata sidecar
        let meta = serde_json::json!({
            "threshold": metadata.threshold,
            "total": metadata.total,
            "index": metadata.index,
        });
        fs::write(dir.join("share-meta.json"), meta.to_string()).expect("write metadata");

        filename
    }

    #[test]
    fn test_load_shares_empty_dir() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let shares = load_shares(dir.path(), &password).unwrap();
        assert!(shares.is_empty());
    }

    #[test]
    fn test_load_shares_single_share() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let sk = SecretKey::generate();

        let metadata = ShareMetadata { threshold: 2, total: 3, index: 1 };
        create_share_keystore(dir.path(), &sk, &password, &metadata);

        let shares = load_shares(dir.path(), &password).unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].index, 1);
        assert_eq!(shares[0].threshold, 2);
        assert_eq!(shares[0].total, 3);
        assert_eq!(*shares[0].scalar_bytes, sk.to_bytes());
    }

    #[test]
    fn test_load_shares_skips_non_share_keystores() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        // Create a regular keystore (no shamir-share description)
        let sk = SecretKey::generate();
        let keystore =
            Keystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2).unwrap();
        let json = keystore.to_json().unwrap();
        fs::write(dir.path().join("regular.json"), json).unwrap();

        let shares = load_shares(dir.path(), &password).unwrap();
        assert!(shares.is_empty());
    }

    #[test]
    fn test_load_shares_missing_metadata_fails() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let sk = SecretKey::generate();

        // Create keystore with share marker but no metadata sidecar
        let mut keystore =
            Keystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2).unwrap();
        keystore.description = Some(SHARE_DESCRIPTION_MARKER.to_string());
        keystore.pubkey = Some(hex::encode(sk.public_key().to_bytes()));

        let json = keystore.to_json().unwrap();
        fs::write(dir.path().join("share-1.json"), json).unwrap();

        let result = load_shares(dir.path(), &password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShareError::MissingMetadata(_)));
    }

    #[test]
    fn test_load_shares_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let correct_pw = Zeroizing::new("correct".to_string());
        let wrong_pw = Zeroizing::new("wrong".to_string());
        let sk = SecretKey::generate();

        let metadata = ShareMetadata { threshold: 2, total: 3, index: 1 };
        create_share_keystore(dir.path(), &sk, &correct_pw, &metadata);

        let result = load_shares(dir.path(), &wrong_pw);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShareError::DecryptKeystore(_)));
    }

    #[test]
    fn test_load_shares_nonexistent_dir_fails() {
        let password = Zeroizing::new("test".to_string());
        let result = load_shares(Path::new("/nonexistent"), &password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShareError::ReadDir(_)));
    }

    #[test]
    fn test_share_metadata_deserialize() {
        let json = r#"{"threshold": 2, "total": 3, "index": 1}"#;
        let meta: ShareMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.threshold, 2);
        assert_eq!(meta.total, 3);
        assert_eq!(meta.index, 1);
    }

    #[test]
    fn test_load_shares_skips_non_json_files() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());

        fs::write(dir.path().join("readme.txt"), "not a keystore").unwrap();
        fs::write(dir.path().join("data.bin"), b"\x00\x01\x02").unwrap();

        let shares = load_shares(dir.path(), &password).unwrap();
        assert!(shares.is_empty());
    }

    #[test]
    fn test_load_shares_invalid_metadata_json_fails() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let sk = SecretKey::generate();

        let mut keystore =
            Keystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2).unwrap();
        keystore.description = Some(SHARE_DESCRIPTION_MARKER.to_string());
        keystore.pubkey = Some(hex::encode(sk.public_key().to_bytes()));
        let json = keystore.to_json().unwrap();
        fs::write(dir.path().join("share-1.json"), json).unwrap();

        // Write invalid metadata
        fs::write(dir.path().join("share-meta.json"), "not valid json").unwrap();

        let result = load_shares(dir.path(), &password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShareError::ParseMetadata(_)));
    }

    #[test]
    fn test_load_shares_missing_pubkey_fails() {
        let dir = TempDir::new().unwrap();
        let password = Zeroizing::new("test-password".to_string());
        let sk = SecretKey::generate();

        let mut keystore =
            Keystore::encrypt(&sk, password.as_bytes(), "", EncryptionKdf::Pbkdf2).unwrap();
        keystore.description = Some(SHARE_DESCRIPTION_MARKER.to_string());
        keystore.pubkey = None; // No pubkey
        let json = keystore.to_json().unwrap();
        fs::write(dir.path().join("share-1.json"), json).unwrap();

        let meta = serde_json::json!({"threshold": 2, "total": 3, "index": 1});
        fs::write(dir.path().join("share-meta.json"), meta.to_string()).unwrap();

        let result = load_shares(dir.path(), &password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShareError::InvalidPubkey(_)));
    }
}
