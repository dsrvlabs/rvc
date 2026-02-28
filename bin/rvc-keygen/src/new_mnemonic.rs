use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crypto::{EncryptionKdf, Keystore};

use crate::deposit;
use crate::network;
use crate::password;

/// Runs the new-mnemonic subcommand with all resolved inputs.
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
) -> Result<()> {
    let net = network::from_name(network_name)?;

    let withdrawal_addr_bytes = match withdrawal_address {
        Some(addr) => Some(password::validate_address(addr)?),
        None => None,
    };

    let mnemonic = crypto::mnemonic::generate_mnemonic();

    eprintln!("\nIMPORTANT: Write down this mnemonic and store it safely.");
    eprintln!("It is the ONLY way to recover your keys.\n");
    eprintln!("{}\n", mnemonic);

    let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, mnemonic_passphrase);

    generate_from_seed(
        seed.as_ref(),
        net,
        output_dir,
        num_validators,
        start_index,
        withdrawal_addr_bytes.as_ref(),
        pbkdf2,
        keystore_password,
    )
}

/// Core generation logic shared between new-mnemonic and existing-mnemonic.
#[allow(clippy::too_many_arguments)]
pub fn generate_from_seed(
    seed: &[u8],
    net: &network::KeygenNetwork,
    output_dir: &Path,
    num_validators: u32,
    start_index: u32,
    withdrawal_addr_bytes: Option<&[u8; 20]>,
    pbkdf2: bool,
    keystore_password: &Zeroizing<String>,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock before UNIX epoch")?
        .as_secs();

    let kdf = if pbkdf2 { EncryptionKdf::Pbkdf2 } else { EncryptionKdf::Scrypt };

    let mut deposits = Vec::with_capacity(num_validators as usize);

    for i in start_index..start_index + num_validators {
        let signing_path = format!("m/12381/3600/{}/0/0", i);
        let signing_key = crypto::eip2333::derive_key_from_path(seed, &signing_path)
            .with_context(|| format!("Failed to derive signing key at {}", signing_path))?;

        let withdrawal_credentials = match withdrawal_addr_bytes {
            Some(addr) => deposit::eth1_withdrawal_credentials(addr),
            None => {
                let withdrawal_path = format!("m/12381/3600/{}/0", i);
                let withdrawal_key = crypto::eip2333::derive_key_from_path(seed, &withdrawal_path)
                    .with_context(|| {
                        format!("Failed to derive withdrawal key at {}", withdrawal_path)
                    })?;
                deposit::bls_withdrawal_credentials(&withdrawal_key.public_key())
            }
        };

        let deposit_data =
            deposit::sign_deposit(&signing_key, withdrawal_credentials, net.genesis_fork_version);
        deposits.push(deposit_data);

        let keystore =
            Keystore::encrypt(&signing_key, keystore_password.as_bytes(), &signing_path, kdf)
                .with_context(|| format!("Failed to encrypt keystore for {}", signing_path))?;

        let keystore_filename = keystore_filename(i, timestamp);
        let keystore_path = output_dir.join(&keystore_filename);
        keystore
            .to_file(&keystore_path)
            .with_context(|| format!("Failed to write keystore: {}", keystore_path.display()))?;

        eprintln!(
            "Generated validator {} (pubkey: {})",
            i,
            hex::encode(signing_key.public_key().to_bytes())
        );
    }

    let deposit_json = deposit::to_launchpad_json(&deposits, net.genesis_fork_version, net.name)?;
    let deposit_path = output_dir.join(deposit_data_filename(timestamp));
    write_with_permissions(&deposit_path, deposit_json.as_bytes())?;

    eprintln!("\nDeposit data written to: {}", deposit_path.display());
    Ok(())
}

fn keystore_filename(index: u32, timestamp: u64) -> String {
    format!("keystore-m_12381_3600_{}_0_0-{}.json", index, timestamp)
}

fn deposit_data_filename(timestamp: u64) -> String {
    format!("deposit_data-{}.json", timestamp)
}

fn write_with_permissions(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create file: {}", path.display()))?;
        file.write_all(data)?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write file: {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_filename_format() {
        let name = keystore_filename(0, 1708800000);
        assert_eq!(name, "keystore-m_12381_3600_0_0_0-1708800000.json");
    }

    #[test]
    fn test_keystore_filename_with_index() {
        let name = keystore_filename(5, 1708800000);
        assert_eq!(name, "keystore-m_12381_3600_5_0_0-1708800000.json");
    }

    #[test]
    fn test_deposit_data_filename_format() {
        let name = deposit_data_filename(1708800000);
        assert_eq!(name, "deposit_data-1708800000.json");
    }

    #[test]
    fn test_generate_single_validator_with_eth1_withdrawal() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&[0xAB; 20]),
            true, // Use PBKDF2 for speed
            &password,
        )
        .unwrap();

        // Verify keystore file exists
        let entries: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();

        let keystore_files: Vec<_> = entries
            .iter()
            .filter(|e| e.file_name().to_string_lossy().starts_with("keystore-m_12381_3600_0"))
            .collect();
        assert_eq!(keystore_files.len(), 1);

        let deposit_files: Vec<_> = entries
            .iter()
            .filter(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .collect();
        assert_eq!(deposit_files.len(), 1);
    }

    #[test]
    fn test_generate_single_validator_keystore_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
        )
        .unwrap();

        // Find and load keystore
        let keystore_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("keystore-m_12381_3600_0"))
            .unwrap();

        let keystore = Keystore::from_file(keystore_file.path()).unwrap();
        let decrypted = keystore.decrypt(password.as_bytes()).unwrap();

        // Verify the decrypted key matches the derived key
        let expected_key =
            crypto::eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0/0").unwrap();
        assert_eq!(decrypted.to_bytes(), expected_key.to_bytes());
    }

    #[test]
    fn test_generate_deposit_data_has_eth1_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
        )
        .unwrap();

        // Read and parse deposit data
        let deposit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .unwrap();

        let deposit_json = std::fs::read_to_string(deposit_file.path()).unwrap();
        let deposits: Vec<serde_json::Value> = serde_json::from_str(&deposit_json).unwrap();

        assert_eq!(deposits.len(), 1);

        let wc = deposits[0]["withdrawal_credentials"].as_str().unwrap();
        assert!(wc.starts_with("01"), "0x01 withdrawal credentials expected");
    }

    #[test]
    fn test_generate_deposit_data_has_bls_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            None, // No withdrawal address → BLS credentials
            true,
            &password,
        )
        .unwrap();

        let deposit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .unwrap();

        let deposit_json = std::fs::read_to_string(deposit_file.path()).unwrap();
        let deposits: Vec<serde_json::Value> = serde_json::from_str(&deposit_json).unwrap();

        let wc = deposits[0]["withdrawal_credentials"].as_str().unwrap();
        assert!(wc.starts_with("00"), "0x00 BLS withdrawal credentials expected");
    }

    #[test]
    fn test_generate_multiple_validators_with_start_index() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("hoodi").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            3,
            5,
            Some(&[0xAB; 20]),
            true,
            &password,
        )
        .unwrap();

        let entries: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();

        // Should have 3 keystore files + 1 deposit data file
        let keystore_files: Vec<_> = entries
            .iter()
            .filter(|e| e.file_name().to_string_lossy().starts_with("keystore-"))
            .collect();
        assert_eq!(keystore_files.len(), 3);

        // Verify indices 5, 6, 7
        for i in 5..8u32 {
            let pattern = format!("keystore-m_12381_3600_{}_0_0-", i);
            let found =
                entries.iter().any(|e| e.file_name().to_string_lossy().starts_with(&pattern));
            assert!(found, "Expected keystore for index {}", i);
        }

        // Deposit data should have 3 entries
        let deposit_file = entries
            .iter()
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .unwrap();

        let deposit_json = std::fs::read_to_string(deposit_file.path()).unwrap();
        let deposits: Vec<serde_json::Value> = serde_json::from_str(&deposit_json).unwrap();
        assert_eq!(deposits.len(), 3);
    }

    #[test]
    fn test_generate_keystore_has_correct_path_field() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            5,
            Some(&[0xAB; 20]),
            true,
            &password,
        )
        .unwrap();

        let keystore_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("keystore-"))
            .unwrap();

        let keystore = Keystore::from_file(keystore_file.path()).unwrap();
        assert_eq!(keystore.path, "m/12381/3600/5/0/0");
    }

    #[test]
    fn test_generate_deposit_pubkey_matches_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
        )
        .unwrap();

        // Get pubkey from keystore
        let keystore_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("keystore-"))
            .unwrap();
        let keystore = Keystore::from_file(keystore_file.path()).unwrap();
        let keystore_pubkey = keystore.pubkey.unwrap();

        // Get pubkey from deposit data
        let deposit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .unwrap();
        let deposit_json = std::fs::read_to_string(deposit_file.path()).unwrap();
        let deposits: Vec<serde_json::Value> = serde_json::from_str(&deposit_json).unwrap();
        let deposit_pubkey = deposits[0]["pubkey"].as_str().unwrap();

        assert_eq!(keystore_pubkey, deposit_pubkey);
    }

    #[test]
    fn test_generate_creates_output_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deeply/nested/output");
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(seed.as_ref(), net, &nested, 1, 0, Some(&[0xAB; 20]), true, &password)
            .unwrap();

        assert!(nested.exists());
        assert!(nested.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn test_generate_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
        )
        .unwrap();

        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let perms = entry.metadata().unwrap().permissions();
            assert_eq!(
                perms.mode() & 0o777,
                0o600,
                "File {} should have 0o600 permissions",
                entry.file_name().to_string_lossy()
            );
        }
    }

    #[test]
    fn test_generate_hoodi_fork_version_in_deposit() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("hoodi").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
        )
        .unwrap();

        let deposit_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .unwrap();

        let deposit_json = std::fs::read_to_string(deposit_file.path()).unwrap();
        let deposits: Vec<serde_json::Value> = serde_json::from_str(&deposit_json).unwrap();

        assert_eq!(deposits[0]["fork_version"], "10000910");
        assert_eq!(deposits[0]["network_name"], "hoodi");
    }
}
