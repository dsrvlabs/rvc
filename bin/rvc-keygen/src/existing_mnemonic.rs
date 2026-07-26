use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::network;
use crate::new_mnemonic::{self, GenerateArgs};
use crate::password;

/// Runs the existing-mnemonic subcommand with all resolved inputs.
///
/// Shares [`GenerateArgs`] with `new_mnemonic` so both subcommands use one
/// generation parameter bag (and the same `EncryptionKdf` field).
pub fn run(
    args: &GenerateArgs,
    mnemonic_passphrase: &str,
    keystore_password: &Zeroizing<String>,
) -> Result<()> {
    // Fail-fast validation before prompting for the mnemonic.
    let _ = network::from_name(&args.network)?;
    if let Some(addr) = &args.withdrawal_address {
        password::validate_address(addr)?;
    }

    let phrase = prompt_mnemonic()?;
    let mnemonic =
        crypto::mnemonic::validate_mnemonic(&phrase).context("Invalid mnemonic phrase")?;

    let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, mnemonic_passphrase);

    new_mnemonic::generate_from_seed(seed.as_ref(), args, keystore_password)
}

/// Prompts the user for a mnemonic phrase via stderr.
fn prompt_mnemonic() -> Result<Zeroizing<String>> {
    eprintln!("Enter your mnemonic phrase (space-separated words):");
    let phrase =
        Zeroizing::new(rpassword::prompt_password_stderr("").context("Failed to read mnemonic")?);
    Ok(phrase)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use std::path::Path;

    use super::*;
    use crypto::EncryptionKdf;
    use new_mnemonic::GenerateArgs;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const TEST_PASSWORD: &str = "testpassword123";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(TEST_PASSWORD.to_string())
    }

    fn base_args(output_dir: &Path) -> GenerateArgs {
        GenerateArgs {
            network: "mainnet".into(),
            output_dir: output_dir.to_path_buf(),
            num_validators: 1,
            start_index: 0,
            withdrawal_address: None,
            kdf: EncryptionKdf::Pbkdf2,
            dry_run: false,
        }
    }

    fn fixed_seed() -> impl AsRef<[u8]> {
        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        crypto::mnemonic::mnemonic_to_seed(&mnemonic, "")
    }

    /// Both subcommands construct the same [`GenerateArgs`] type for generation.
    #[test]
    fn test_existing_mnemonic_shares_generate_args() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let seed = fixed_seed();
        let args = base_args(dir.path());

        // Type identity: existing_mnemonic consumers use new_mnemonic::GenerateArgs.
        let _: &GenerateArgs = &args;
        new_mnemonic::generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        let ks = find_keystore(dir.path());
        assert_eq!(ks.crypto.kdf.function, "pbkdf2");
        assert!(ks.decrypt(TEST_PASSWORD.as_bytes()).is_ok());
    }

    #[test]
    fn test_existing_mnemonic_generates_same_keys_as_new_mnemonic() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let password = password();
        let seed = fixed_seed();

        new_mnemonic::generate_from_seed(seed.as_ref(), &base_args(dir1.path()), &password)
            .unwrap();
        new_mnemonic::generate_from_seed(seed.as_ref(), &base_args(dir2.path()), &password)
            .unwrap();

        let key1 = find_keystore(dir1.path()).decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        let key2 = find_keystore(dir2.path()).decrypt(TEST_PASSWORD.as_bytes()).unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_existing_mnemonic_different_passphrase_different_keys() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let password = password();

        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed1 = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let seed2 = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "different");

        new_mnemonic::generate_from_seed(seed1.as_ref(), &base_args(dir1.path()), &password)
            .unwrap();
        new_mnemonic::generate_from_seed(seed2.as_ref(), &base_args(dir2.path()), &password)
            .unwrap();

        let key1 = find_keystore(dir1.path()).decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        let key2 = find_keystore(dir2.path()).decrypt(TEST_PASSWORD.as_bytes()).unwrap();

        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_existing_mnemonic_start_index_offset() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let password = password();
        let seed = fixed_seed();

        let mut args_three = base_args(dir1.path());
        args_three.num_validators = 3;
        new_mnemonic::generate_from_seed(seed.as_ref(), &args_three, &password).unwrap();

        let mut args_offset = base_args(dir2.path());
        args_offset.start_index = 2;
        new_mnemonic::generate_from_seed(seed.as_ref(), &args_offset, &password).unwrap();

        let keystores1 = find_all_keystores(dir1.path());
        let ks3 = &keystores1[2];
        let ks_single = find_keystore(dir2.path());

        let key3 = ks3.decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        let key_single = ks_single.decrypt(TEST_PASSWORD.as_bytes()).unwrap();

        assert_eq!(key3.to_bytes(), key_single.to_bytes());
    }

    #[test]
    fn test_existing_mnemonic_with_withdrawal_address() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let seed = fixed_seed();

        let mut args = base_args(dir.path());
        args.withdrawal_address = Some("0x71C7656EC7ab88b098defB751B7401B5f6d8976F".into());
        new_mnemonic::generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        let deposit_file = find_deposit_data(dir.path());
        let content = std::fs::read_to_string(&deposit_file).unwrap();
        assert!(content.contains("\"withdrawal_credentials\": \"01"));
    }

    #[test]
    fn test_existing_mnemonic_hoodi_network() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let seed = fixed_seed();

        let mut args = base_args(dir.path());
        args.network = "hoodi".into();
        new_mnemonic::generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        let deposit_file = find_deposit_data(dir.path());
        let content = std::fs::read_to_string(&deposit_file).unwrap();
        assert!(content.contains("\"network_name\": \"hoodi\""));
    }

    fn find_keystore(dir: &Path) -> crypto::Keystore {
        let mut keystores = find_all_keystores(dir);
        assert!(!keystores.is_empty(), "No keystore files found in {:?}", dir);
        keystores.remove(0)
    }

    fn find_all_keystores(dir: &Path) -> Vec<crypto::Keystore> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("keystore-m_"))
            .collect();
        entries.sort_by_key(|e| e.file_name());

        entries.into_iter().map(|e| crypto::Keystore::from_file(e.path()).unwrap()).collect()
    }

    fn find_deposit_data(dir: &Path) -> std::path::PathBuf {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .map(|e| e.path())
            .expect("No deposit data file found")
    }
}
