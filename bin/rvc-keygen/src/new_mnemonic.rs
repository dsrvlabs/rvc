use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crypto::{EncryptionKdf, Keystore};

use crate::deposit;
use crate::network;
use crate::password;
use crate::verify;

/// Writes the mnemonic to a backup file with restrictive permissions (0o600).
/// Returns the SHA-256 hex checksum of the mnemonic string.
pub fn write_mnemonic_backup(path: &Path, mnemonic: &str) -> Result<String> {
    let checksum = mnemonic_checksum(mnemonic);

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| {
                format!("Failed to create mnemonic backup (already exists?): {}", path.display())
            })?;
        file.write_all(mnemonic.as_bytes())?;
        file.write_all(b"\n")?;
    }

    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut file =
            OpenOptions::new().write(true).create_new(true).open(path).with_context(|| {
                format!("Failed to create mnemonic backup (already exists?): {}", path.display())
            })?;
        file.write_all(mnemonic.as_bytes())?;
        file.write_all(b"\n")?;
    }

    Ok(checksum)
}

fn mnemonic_checksum(mnemonic: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(mnemonic.as_bytes());
    hex::encode(hasher.finalize())
}

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
    dry_run: bool,
    backup_file: Option<&Path>,
) -> Result<()> {
    let net = network::from_name(network_name)?;

    let withdrawal_addr_bytes = match withdrawal_address {
        Some(addr) => Some(password::validate_address(addr)?),
        None => None,
    };

    let mnemonic = crypto::mnemonic::generate_mnemonic();

    if let Some(path) = backup_file {
        let mnemonic_str = mnemonic.to_string();
        let checksum = write_mnemonic_backup(path, &mnemonic_str)?;
        eprintln!("\nMnemonic backed up to: {}", path.display());
        eprintln!("SHA-256 checksum: {}\n", checksum);
    } else {
        eprintln!(
            "\nWARNING: No --backup-file specified. The mnemonic will only be shown on screen."
        );
        eprintln!("IMPORTANT: Write down this mnemonic and store it safely.");
        eprintln!("It is the ONLY way to recover your keys.\n");
        eprintln!("{}\n", mnemonic);
    }

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
        dry_run,
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
    dry_run: bool,
) -> Result<()> {
    if !dry_run {
        std::fs::create_dir_all(output_dir).with_context(|| {
            format!("Failed to create output directory: {}", output_dir.display())
        })?;
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock before UNIX epoch")?
        .as_secs();

    let kdf = if pbkdf2 { EncryptionKdf::Pbkdf2 } else { EncryptionKdf::Scrypt };

    let end_index = start_index.checked_add(num_validators).ok_or_else(|| {
        anyhow::anyhow!(
            "start_index ({}) + num_validators ({}) overflows u32",
            start_index,
            num_validators
        )
    })?;

    let mut deposits = Vec::with_capacity(num_validators as usize);
    let mut summaries = Vec::with_capacity(num_validators as usize);

    for i in start_index..end_index {
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

        if dry_run {
            eprintln!("[DRY RUN] Would write keystore: {}", keystore_path.display());
            summaries.push(verify::ValidatorSummary {
                index: i,
                pubkey: hex::encode(signing_key.public_key().to_bytes()),
                status: "Dry run".to_string(),
            });
        } else {
            keystore.to_file(&keystore_path).with_context(|| {
                format!("Failed to write keystore: {}", keystore_path.display())
            })?;

            let status = match verify::verify_keystore(&keystore_path, keystore_password.as_bytes())
            {
                Ok(pubkey) => {
                    let expected_pubkey = hex::encode(signing_key.public_key().to_bytes());
                    if pubkey == expected_pubkey {
                        "Verified".to_string()
                    } else {
                        format!("MISMATCH (expected {}, got {})", expected_pubkey, pubkey)
                    }
                }
                Err(e) => format!("FAILED: {}", e),
            };

            summaries.push(verify::ValidatorSummary {
                index: i,
                pubkey: hex::encode(signing_key.public_key().to_bytes()),
                status,
            });
        }
    }

    let deposit_json = deposit::to_launchpad_json(&deposits, net.genesis_fork_version, net.name)?;
    let deposit_path = output_dir.join(deposit_data_filename(timestamp));

    if dry_run {
        eprintln!("[DRY RUN] Would write deposit data: {}", deposit_path.display());
        println!("{}", deposit_json);
    } else {
        write_with_permissions(&deposit_path, deposit_json.as_bytes())?;
    }

    verify::print_summary(&summaries, net.name, output_dir);

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
        let mut file =
            OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).with_context(
                || format!("Failed to create file (already exists?): {}", path.display()),
            )?;
        file.write_all(data)?;
    }

    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut file =
            OpenOptions::new().write(true).create_new(true).open(path).with_context(|| {
                format!("Failed to create file (already exists?): {}", path.display())
            })?;
        file.write_all(data)?;
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
        generate_from_seed(
            seed.as_ref(),
            net,
            &nested,
            1,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
            false,
        )
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
            false,
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
            false,
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

    #[test]
    fn test_dry_run_creates_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("dry_run_output");
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        generate_from_seed(
            seed.as_ref(),
            net,
            &output,
            2,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
            true,
        )
        .unwrap();

        // Output directory should NOT be created in dry-run mode
        assert!(!output.exists(), "Output directory should not exist in dry-run mode");
    }

    #[test]
    fn test_dry_run_still_derives_keys() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        // Should succeed without error — derivation runs, just no file I/O
        let result = generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            1,
            0,
            Some(&[0xAB; 20]),
            true,
            &password,
            true,
        );
        assert!(result.is_ok());
    }

    // LOW-22: Integer overflow guard
    #[test]
    fn test_generate_overflow_start_index_plus_num_validators() {
        let dir = tempfile::tempdir().unwrap();
        let password = Zeroizing::new("testpassword123".to_string());

        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let net = network::from_name("mainnet").unwrap();
        let result = generate_from_seed(
            seed.as_ref(),
            net,
            dir.path(),
            u32::MAX,
            1,
            Some(&[0xAB; 20]),
            true,
            &password,
            true,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overflows"));
    }

    // LOW-24: Atomic file creation rejects existing file
    #[test]
    fn test_write_with_permissions_rejects_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.json");
        std::fs::write(&path, "existing content").unwrap();

        let result = write_with_permissions(&path, b"new content");
        assert!(result.is_err());
    }

    #[test]
    fn test_write_mnemonic_backup_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnemonic.txt");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let checksum = write_mnemonic_backup(&path, mnemonic).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, format!("{}\n", mnemonic));
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_write_mnemonic_backup_checksum_deterministic() {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        let c1 = mnemonic_checksum(mnemonic);
        let c2 = mnemonic_checksum(mnemonic);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_write_mnemonic_backup_different_mnemonics_different_checksums() {
        let c1 = mnemonic_checksum("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let c2 = mnemonic_checksum("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
        assert_ne!(c1, c2);
    }

    #[cfg(unix)]
    #[test]
    fn test_write_mnemonic_backup_has_0o600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mnemonic_perms.txt");
        write_mnemonic_backup(&path, "test mnemonic words").unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_write_mnemonic_backup_rejects_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing_backup.txt");
        std::fs::write(&path, "old").unwrap();

        let result = write_mnemonic_backup(&path, "new mnemonic");
        assert!(result.is_err());
    }
}
