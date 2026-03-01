use std::path::Path;

use anyhow::{bail, Context, Result};

use crypto::Keystore;

/// Verifies a keystore file by reading it from disk and decrypting with the given password.
/// Returns the public key hex string on success.
pub fn verify_keystore(keystore_path: &Path, password: &[u8]) -> Result<String> {
    let keystore = Keystore::from_file(keystore_path)
        .with_context(|| format!("Failed to read keystore: {}", keystore_path.display()))?;

    let decrypted = keystore
        .decrypt(password)
        .with_context(|| format!("Failed to decrypt keystore: {}", keystore_path.display()))?;

    let pubkey_hex = hex::encode(decrypted.public_key().to_bytes());

    // Verify pubkey in keystore metadata matches the decrypted key
    if let Some(ref stored_pubkey) = keystore.pubkey {
        if *stored_pubkey != pubkey_hex {
            bail!("Keystore pubkey mismatch: stored={}, derived={}", stored_pubkey, pubkey_hex);
        }
    }

    Ok(pubkey_hex)
}

/// Prints a summary table of generated validators to stderr.
pub fn print_summary(validators: &[ValidatorSummary], network_name: &str, output_dir: &Path) {
    eprintln!();
    eprintln!("Successfully generated {} validator key(s) for {}.", validators.len(), network_name);
    eprintln!();
    eprintln!("{:<7} {:<98} Status", "Index", "Public Key");
    eprintln!("{}", "-".repeat(116));

    for v in validators {
        eprintln!("{:<7} {:<98} {}", v.index, v.pubkey, v.status);
    }

    eprintln!();
    eprintln!("Output directory: {}", output_dir.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Back up your mnemonic phrase securely");
    eprintln!("  2. Upload deposit_data JSON to the Ethereum Launchpad");
    eprintln!("  3. Import keystores into your validator client:");
    eprintln!("     rvc --datadir <DIR> validator import --directory {}", output_dir.display());
}

/// Summary information for a single generated validator.
pub struct ValidatorSummary {
    pub index: u32,
    pub pubkey: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{EncryptionKdf, Keystore};

    const TEST_PASSWORD: &str = "testpassword123";
    const TEST_SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn generate_test_keystore(dir: &Path) -> std::path::PathBuf {
        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_SEED).unwrap();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let key =
            crypto::eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0/0").unwrap();

        let keystore = Keystore::encrypt(
            &key,
            TEST_PASSWORD.as_bytes(),
            "m/12381/3600/0/0/0",
            EncryptionKdf::Pbkdf2,
        )
        .unwrap();

        let path = dir.join("keystore-test.json");
        keystore.to_file(&path).unwrap();
        path
    }

    #[test]
    fn test_verify_keystore_success() {
        let dir = tempfile::tempdir().unwrap();
        let keystore_path = generate_test_keystore(dir.path());

        let pubkey = verify_keystore(&keystore_path, TEST_PASSWORD.as_bytes()).unwrap();
        assert_eq!(pubkey.len(), 96); // 48 bytes = 96 hex chars
    }

    #[test]
    fn test_verify_keystore_returns_correct_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let keystore_path = generate_test_keystore(dir.path());

        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_SEED).unwrap();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let key =
            crypto::eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0/0").unwrap();
        let expected_pubkey = hex::encode(key.public_key().to_bytes());

        let pubkey = verify_keystore(&keystore_path, TEST_PASSWORD.as_bytes()).unwrap();
        assert_eq!(pubkey, expected_pubkey);
    }

    #[test]
    fn test_verify_keystore_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let keystore_path = generate_test_keystore(dir.path());

        let result = verify_keystore(&keystore_path, b"wrongpassword!");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_keystore_missing_file() {
        let result = verify_keystore(Path::new("/nonexistent/keystore.json"), b"password");
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_summary_fields() {
        let summary = ValidatorSummary {
            index: 42,
            pubkey: "abcd1234".to_string(),
            status: "Verified".to_string(),
        };
        assert_eq!(summary.index, 42);
        assert_eq!(summary.pubkey, "abcd1234");
        assert_eq!(summary.status, "Verified");
    }
}
