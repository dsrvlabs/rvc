use std::fs;
use std::path::PathBuf;

use bls12_381_plus::Scalar;
use rand::rngs::OsRng;
use thiserror::Error;
use tracing::info;
use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField, Share};
use zeroize::Zeroizing;

use crate::dvt::bridge::{blst_sk_to_scalar, scalar_to_blst_sk};
use crate::dvt::types::ShareMetadata;

type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

#[derive(Error, Debug)]
pub enum SplitKeyError {
    #[error("failed to read keystore: {0}")]
    ReadKeystore(String),

    #[error("failed to decrypt keystore: {0}")]
    DecryptKeystore(String),

    #[error("failed to convert secret key to scalar: {0}")]
    ScalarConversion(String),

    #[error("failed to split secret: {0}")]
    SplitFailed(String),

    #[error("failed to convert share back to secret key: {0}")]
    ShareConversion(String),

    #[error("failed to encrypt share keystore: {0}")]
    EncryptShare(String),

    #[error("failed to write output: {0}")]
    WriteOutput(String),

    #[error("validation error: {0}")]
    Validation(String),
}

pub struct SplitKeyArgs {
    pub keystore: PathBuf,
    pub password: Zeroizing<String>,
    pub threshold: u64,
    pub shares: u64,
    pub output_dir: PathBuf,
    pub output_password: Zeroizing<String>,
}

pub fn execute(args: SplitKeyArgs) -> Result<(), SplitKeyError> {
    validate_args(&args)?;

    let keystore = crypto::Keystore::from_file(&args.keystore)
        .map_err(|e| SplitKeyError::ReadKeystore(e.to_string()))?;

    let secret_key = keystore
        .decrypt(args.password.as_bytes())
        .map_err(|e| SplitKeyError::DecryptKeystore(e.to_string()))?;

    let aggregate_pubkey = secret_key.public_key();
    let aggregate_pubkey_hex = hex::encode(aggregate_pubkey.to_bytes());

    info!(
        pubkey = %aggregate_pubkey_hex,
        threshold = args.threshold,
        shares = args.shares,
        "Splitting key"
    );

    // Gate 1: key-splitting needs the raw SK bytes to build the blst scalar; never logged.
    #[allow(clippy::disallowed_methods)]
    let blst_sk = blst::min_pk::SecretKey::from_bytes(&secret_key.to_bytes())
        .map_err(|_| SplitKeyError::ScalarConversion("invalid blst key bytes".to_string()))?;
    let secret_scalar =
        blst_sk_to_scalar(&blst_sk).map_err(|e| SplitKeyError::ScalarConversion(e.to_string()))?;

    let share_scalars: Vec<BlsShare> = shamir::split_secret::<BlsShare>(
        args.threshold as usize,
        args.shares as usize,
        &IdentifierPrimeField(secret_scalar),
        OsRng,
    )
    .map_err(|e| SplitKeyError::SplitFailed(format!("{:?}", e)))?;

    fs::create_dir_all(&args.output_dir)
        .map_err(|e| SplitKeyError::WriteOutput(format!("{}: {}", args.output_dir.display(), e)))?;

    for share in &share_scalars {
        let id: &IdentifierPrimeField<Scalar> = share.identifier();
        let id_bytes = id.0.to_be_bytes();
        // vsss_rs identifiers fit in the low 8 bytes of the 32-byte scalar
        let share_index = u64::from_be_bytes(id_bytes[24..32].try_into().unwrap());
        let share_scalar: &IdentifierPrimeField<Scalar> = share.value();
        let scalar_val = share_scalar.0;

        let share_blst_sk = scalar_to_blst_sk(&scalar_val)
            .map_err(|e| SplitKeyError::ShareConversion(format!("share {}: {}", share_index, e)))?;

        let share_sk = crypto::SecretKey::from_bytes(&share_blst_sk.to_bytes())
            .map_err(|e| SplitKeyError::ShareConversion(format!("share {}: {}", share_index, e)))?;

        let mut share_keystore = crypto::Keystore::encrypt(
            &share_sk,
            args.output_password.as_bytes(),
            "",
            crypto::EncryptionKdf::Pbkdf2,
        )
        .map_err(|e| SplitKeyError::EncryptShare(format!("share {}: {}", share_index, e)))?;

        share_keystore.description = Some("shamir-share".to_string());
        share_keystore.pubkey = Some(aggregate_pubkey_hex.clone());

        let share_dir = args.output_dir.join(format!("share-{}", share_index));
        fs::create_dir_all(&share_dir)
            .map_err(|e| SplitKeyError::WriteOutput(format!("{}: {}", share_dir.display(), e)))?;

        let keystore_json = share_keystore.to_json().map_err(|e| {
            SplitKeyError::WriteOutput(format!("serialize share {}: {}", share_index, e))
        })?;
        fs::write(share_dir.join("keystore.json"), keystore_json).map_err(|e| {
            SplitKeyError::WriteOutput(format!("write share {}: {}", share_index, e))
        })?;

        let metadata =
            ShareMetadata { threshold: args.threshold, total: args.shares, index: share_index };
        let meta_json = serde_json::to_string_pretty(&metadata).map_err(|e| {
            SplitKeyError::WriteOutput(format!("serialize meta {}: {}", share_index, e))
        })?;
        fs::write(share_dir.join("share-meta.json"), meta_json).map_err(|e| {
            SplitKeyError::WriteOutput(format!("write meta {}: {}", share_index, e))
        })?;

        info!(share_index, dir = %share_dir.display(), "Wrote share");
    }

    info!(
        output_dir = %args.output_dir.display(),
        shares = args.shares,
        threshold = args.threshold,
        "Key split complete"
    );

    Ok(())
}

fn validate_args(args: &SplitKeyArgs) -> Result<(), SplitKeyError> {
    if args.threshold == 0 {
        return Err(SplitKeyError::Validation("threshold must be > 0".to_string()));
    }
    if args.shares < 2 {
        return Err(SplitKeyError::Validation("shares must be >= 2".to_string()));
    }
    if args.threshold > args.shares {
        return Err(SplitKeyError::Validation(format!(
            "threshold ({}) must be <= shares ({})",
            args.threshold, args.shares
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;
    use crypto::SecretKey;
    use tempfile::TempDir;
    use vsss_rs::ReadableShareSet;

    fn create_test_keystore(dir: &std::path::Path, password: &str) -> (PathBuf, SecretKey) {
        let sk = SecretKey::generate();
        let keystore =
            crypto::Keystore::encrypt(&sk, password.as_bytes(), "", crypto::EncryptionKdf::Pbkdf2)
                .unwrap();
        let path = dir.join("source-keystore.json");
        fs::write(&path, keystore.to_json().unwrap()).unwrap();
        (path, sk)
    }

    #[test]
    fn test_validate_threshold_zero() {
        let args = SplitKeyArgs {
            keystore: PathBuf::from("/tmp/ks.json"),
            password: Zeroizing::new("pw".to_string()),
            threshold: 0,
            shares: 3,
            output_dir: PathBuf::from("/tmp/out"),
            output_password: Zeroizing::new("pw".to_string()),
        };
        let err = validate_args(&args).unwrap_err();
        assert!(matches!(err, SplitKeyError::Validation(_)));
    }

    #[test]
    fn test_validate_shares_less_than_two() {
        let args = SplitKeyArgs {
            keystore: PathBuf::from("/tmp/ks.json"),
            password: Zeroizing::new("pw".to_string()),
            threshold: 1,
            shares: 1,
            output_dir: PathBuf::from("/tmp/out"),
            output_password: Zeroizing::new("pw".to_string()),
        };
        let err = validate_args(&args).unwrap_err();
        assert!(matches!(err, SplitKeyError::Validation(_)));
    }

    #[test]
    fn test_validate_threshold_exceeds_shares() {
        let args = SplitKeyArgs {
            keystore: PathBuf::from("/tmp/ks.json"),
            password: Zeroizing::new("pw".to_string()),
            threshold: 4,
            shares: 3,
            output_dir: PathBuf::from("/tmp/out"),
            output_password: Zeroizing::new("pw".to_string()),
        };
        let err = validate_args(&args).unwrap_err();
        assert!(matches!(err, SplitKeyError::Validation(_)));
    }

    #[test]
    fn test_validate_valid_args() {
        let args = SplitKeyArgs {
            keystore: PathBuf::from("/tmp/ks.json"),
            password: Zeroizing::new("pw".to_string()),
            threshold: 2,
            shares: 3,
            output_dir: PathBuf::from("/tmp/out"),
            output_password: Zeroizing::new("pw".to_string()),
        };
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn test_split_key_2_of_3() {
        let tmp = TempDir::new().unwrap();
        let password = "test-password";
        let (keystore_path, original_sk) = create_test_keystore(tmp.path(), password);

        let output_dir = tmp.path().join("shares");
        let args = SplitKeyArgs {
            keystore: keystore_path,
            password: Zeroizing::new(password.to_string()),
            threshold: 2,
            shares: 3,
            output_dir: output_dir.clone(),
            output_password: Zeroizing::new("share-pw".to_string()),
        };

        execute(args).unwrap();

        // Verify output structure
        for i in 1..=3 {
            let share_dir = output_dir.join(format!("share-{}", i));
            assert!(share_dir.join("keystore.json").exists());
            assert!(share_dir.join("share-meta.json").exists());

            // Check metadata
            let meta: ShareMetadata = serde_json::from_str(
                &fs::read_to_string(share_dir.join("share-meta.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(meta.threshold, 2);
            assert_eq!(meta.total, 3);
            assert_eq!(meta.index, i);

            // Check keystore description and pubkey
            let ks = crypto::Keystore::from_file(share_dir.join("keystore.json")).unwrap();
            assert_eq!(ks.description.as_deref(), Some("shamir-share"));
            assert_eq!(
                ks.pubkey.as_deref(),
                Some(hex::encode(original_sk.public_key().to_bytes()).as_str())
            );
        }
    }

    #[test]
    fn test_split_key_shares_reconstruct() {
        let tmp = TempDir::new().unwrap();
        let password = "test-password";
        let share_password = "share-pw";
        let (keystore_path, original_sk) = create_test_keystore(tmp.path(), password);

        let output_dir = tmp.path().join("shares");
        let args = SplitKeyArgs {
            keystore: keystore_path,
            password: Zeroizing::new(password.to_string()),
            threshold: 2,
            shares: 3,
            output_dir: output_dir.clone(),
            output_password: Zeroizing::new(share_password.to_string()),
        };

        execute(args).unwrap();

        // Decrypt first 2 shares and reconstruct
        let mut share_scalars: Vec<BlsShare> = Vec::new();
        for i in 1..=2 {
            let share_dir = output_dir.join(format!("share-{}", i));
            let ks = crypto::Keystore::from_file(share_dir.join("keystore.json")).unwrap();
            let share_sk = ks.decrypt(share_password.as_bytes()).unwrap();

            let blst_sk = blst::min_pk::SecretKey::from_bytes(&share_sk.to_bytes()).unwrap();
            let scalar = blst_sk_to_scalar(&blst_sk).unwrap();

            // Read metadata to get index
            let meta: ShareMetadata = serde_json::from_str(
                &fs::read_to_string(share_dir.join("share-meta.json")).unwrap(),
            )
            .unwrap();

            let share = DefaultShare {
                identifier: IdentifierPrimeField(Scalar::from(meta.index)),
                value: IdentifierPrimeField(scalar),
            };
            share_scalars.push(share);
        }

        let reconstructed: IdentifierPrimeField<Scalar> =
            share_scalars.combine().expect("combine should succeed");
        let recovered_blst = scalar_to_blst_sk(&reconstructed.0).unwrap();
        let recovered_sk = crypto::SecretKey::from_bytes(&recovered_blst.to_bytes()).unwrap();

        assert_eq!(recovered_sk.public_key().to_bytes(), original_sk.public_key().to_bytes());
    }

    #[test]
    fn test_split_key_invalid_keystore_path() {
        let tmp = TempDir::new().unwrap();
        let args = SplitKeyArgs {
            keystore: PathBuf::from("/nonexistent/keystore.json"),
            password: Zeroizing::new("pw".to_string()),
            threshold: 2,
            shares: 3,
            output_dir: tmp.path().join("out"),
            output_password: Zeroizing::new("pw".to_string()),
        };
        let err = execute(args).unwrap_err();
        assert!(matches!(err, SplitKeyError::ReadKeystore(_)));
    }

    #[test]
    fn test_split_key_wrong_password() {
        let tmp = TempDir::new().unwrap();
        let (keystore_path, _) = create_test_keystore(tmp.path(), "correct-pw");

        let args = SplitKeyArgs {
            keystore: keystore_path,
            password: Zeroizing::new("wrong-pw".to_string()),
            threshold: 2,
            shares: 3,
            output_dir: tmp.path().join("out"),
            output_password: Zeroizing::new("pw".to_string()),
        };
        let err = execute(args).unwrap_err();
        assert!(matches!(err, SplitKeyError::DecryptKeystore(_)));
    }

    #[test]
    fn test_split_key_3_of_5_all_subsets() {
        let tmp = TempDir::new().unwrap();
        let password = "pw";
        let share_password = "share-pw";
        let (keystore_path, original_sk) = create_test_keystore(tmp.path(), password);

        let output_dir = tmp.path().join("shares");
        execute(SplitKeyArgs {
            keystore: keystore_path,
            password: Zeroizing::new(password.to_string()),
            threshold: 3,
            shares: 5,
            output_dir: output_dir.clone(),
            output_password: Zeroizing::new(share_password.to_string()),
        })
        .unwrap();

        // Load all 5 shares
        let mut all_shares: Vec<BlsShare> = Vec::new();
        for i in 1..=5 {
            let share_dir = output_dir.join(format!("share-{}", i));
            let ks = crypto::Keystore::from_file(share_dir.join("keystore.json")).unwrap();
            let share_sk = ks.decrypt(share_password.as_bytes()).unwrap();
            let blst_sk = blst::min_pk::SecretKey::from_bytes(&share_sk.to_bytes()).unwrap();
            let scalar = blst_sk_to_scalar(&blst_sk).unwrap();

            let meta: ShareMetadata = serde_json::from_str(
                &fs::read_to_string(share_dir.join("share-meta.json")).unwrap(),
            )
            .unwrap();
            all_shares.push(DefaultShare {
                identifier: IdentifierPrimeField(Scalar::from(meta.index)),
                value: IdentifierPrimeField(scalar),
            });
        }

        // Try all 3-element subsets (10 subsets for 5 choose 3)
        let subsets: Vec<Vec<usize>> = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for subset_idx in &subsets {
            let subset: Vec<BlsShare> = subset_idx.iter().map(|&i| all_shares[i]).collect();
            let reconstructed: IdentifierPrimeField<Scalar> =
                subset.combine().expect("combine should succeed");
            let recovered_blst = scalar_to_blst_sk(&reconstructed.0).unwrap();
            let recovered_sk = crypto::SecretKey::from_bytes(&recovered_blst.to_bytes()).unwrap();
            assert_eq!(
                recovered_sk.public_key().to_bytes(),
                original_sk.public_key().to_bytes(),
                "subset {:?} should reconstruct the same key",
                subset_idx
            );
        }
    }
}
