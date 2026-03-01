use std::path::Path;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::network;
use crate::new_mnemonic;
use crate::password;

/// Runs the existing-mnemonic subcommand with all resolved inputs.
#[allow(clippy::too_many_arguments)]
pub fn run(
    network_name: &str,
    output_dir: &Path,
    num_validators: u32,
    start_index: u32,
    withdrawal_address: Option<&str>,
    mnemonic_passphrase: &str,
    pbkdf2: bool,
    keystore_password: &Zeroizing<String>,
    dry_run: bool,
) -> Result<()> {
    let net = network::from_name(network_name)?;

    let withdrawal_addr_bytes = match withdrawal_address {
        Some(addr) => Some(password::validate_address(addr)?),
        None => None,
    };

    let phrase = prompt_mnemonic()?;
    let mnemonic =
        crypto::mnemonic::validate_mnemonic(&phrase).context("Invalid mnemonic phrase")?;

    let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, mnemonic_passphrase);

    new_mnemonic::generate_from_seed(
        seed.as_ref(),
        net,
        output_dir,
        num_validators,
        start_index,
        withdrawal_addr_bytes.as_ref(),
        pbkdf2,
        keystore_password,
        dry_run,
    )
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
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const TEST_PASSWORD: &str = "testpassword123";

    #[test]
    fn test_existing_mnemonic_generates_same_keys_as_new_mnemonic() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let password = Zeroizing::new(TEST_PASSWORD.to_string());

        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let net = network::from_name("mainnet").unwrap();

        // Generate via generate_from_seed twice — should produce identical keystores
        new_mnemonic::generate_from_seed(
            seed.as_ref(),
            net,
            dir1.path(),
            1,
            0,
            None,
            true,
            &password,
            false,
        )
        .unwrap();

        new_mnemonic::generate_from_seed(
            seed.as_ref(),
            net,
            dir2.path(),
            1,
            0,
            None,
            true,
            &password,
            false,
        )
        .unwrap();

        // Both should decrypt to the same key
        let ks1 = find_keystore(dir1.path());
        let ks2 = find_keystore(dir2.path());

        let key1 = ks1.decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        let key2 = ks2.decrypt(TEST_PASSWORD.as_bytes()).unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_existing_mnemonic_different_passphrase_different_keys() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let password = Zeroizing::new(TEST_PASSWORD.to_string());

        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed1 = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let seed2 = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "different");
        let net = network::from_name("mainnet").unwrap();

        new_mnemonic::generate_from_seed(
            seed1.as_ref(),
            net,
            dir1.path(),
            1,
            0,
            None,
            true,
            &password,
            false,
        )
        .unwrap();

        new_mnemonic::generate_from_seed(
            seed2.as_ref(),
            net,
            dir2.path(),
            1,
            0,
            None,
            true,
            &password,
            false,
        )
        .unwrap();

        let ks1 = find_keystore(dir1.path());
        let ks2 = find_keystore(dir2.path());

        let key1 = ks1.decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        let key2 = ks2.decrypt(TEST_PASSWORD.as_bytes()).unwrap();

        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_existing_mnemonic_start_index_offset() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let password = Zeroizing::new(TEST_PASSWORD.to_string());

        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let net = network::from_name("mainnet").unwrap();

        // Generate 3 validators starting at index 0
        new_mnemonic::generate_from_seed(
            seed.as_ref(),
            net,
            dir1.path(),
            3,
            0,
            None,
            true,
            &password,
            false,
        )
        .unwrap();

        // Generate 1 validator starting at index 2 — should match the 3rd key from above
        new_mnemonic::generate_from_seed(
            seed.as_ref(),
            net,
            dir2.path(),
            1,
            2,
            None,
            true,
            &password,
            false,
        )
        .unwrap();

        let keystores1 = find_all_keystores(dir1.path());
        let ks3 = &keystores1[2]; // Third key (index 2)
        let ks_single = find_keystore(dir2.path());

        let key3 = ks3.decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        let key_single = ks_single.decrypt(TEST_PASSWORD.as_bytes()).unwrap();

        assert_eq!(key3.to_bytes(), key_single.to_bytes());
    }

    #[test]
    fn test_existing_mnemonic_with_withdrawal_address() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new(TEST_PASSWORD.to_string());

        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let net = network::from_name("mainnet").unwrap();
        let addr =
            password::validate_address("0x71C7656EC7ab88b098defB751B7401B5f6d8976F").unwrap();

        new_mnemonic::generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&addr),
            true,
            &password,
            false,
        )
        .unwrap();

        // Verify deposit data file exists and contains the address
        let deposit_file = find_deposit_data(dir.path());
        let content = std::fs::read_to_string(&deposit_file).unwrap();
        // The withdrawal credentials should start with "01" (eth1 prefix, pretty-printed JSON)
        assert!(content.contains("\"withdrawal_credentials\": \"01"));
    }

    #[test]
    fn test_existing_mnemonic_hoodi_network() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new(TEST_PASSWORD.to_string());

        let mnemonic = crypto::mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");
        let net = network::from_name("hoodi").unwrap();

        new_mnemonic::generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            None,
            true,
            &password,
            false,
        )
        .unwrap();

        let deposit_file = find_deposit_data(dir.path());
        let content = std::fs::read_to_string(&deposit_file).unwrap();
        assert!(content.contains("\"network_name\": \"hoodi\""));
    }

    // Helper: find the first keystore JSON in a directory
    fn find_keystore(dir: &Path) -> crypto::Keystore {
        let mut keystores = find_all_keystores(dir);
        assert!(!keystores.is_empty(), "No keystore files found in {:?}", dir);
        keystores.remove(0)
    }

    // Helper: find all keystores sorted by filename
    fn find_all_keystores(dir: &Path) -> Vec<crypto::Keystore> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("keystore-m_"))
            .collect();
        entries.sort_by_key(|e| e.file_name());

        entries.into_iter().map(|e| crypto::Keystore::from_file(e.path()).unwrap()).collect()
    }

    // Helper: find the deposit data JSON file
    fn find_deposit_data(dir: &Path) -> std::path::PathBuf {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .map(|e| e.path())
            .expect("No deposit data file found")
    }
}
