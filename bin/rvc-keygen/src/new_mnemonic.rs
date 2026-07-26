use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tracing::{debug, info};
use zeroize::Zeroizing;

use crypto::{EncryptionKdf, Keystore};
use observability::logging::TruncatedPubkey;

use crate::deposit;
use crate::network;
use crate::password;
use crate::verify;

/// Shared key-generation parameters for `new-mnemonic` and `existing-mnemonic`.
///
/// Matches the Args-struct convention used by `ExitArgs` / `BlsToExecutionArgs`.
/// The CLI `--pbkdf2` flag maps to [`EncryptionKdf`] at the binary edge via
/// [`kdf_from_pbkdf2_flag`]; the core path never sees a bare bool.
pub struct GenerateArgs {
    pub network: String,
    pub output_dir: PathBuf,
    pub num_validators: u32,
    pub start_index: u32,
    pub withdrawal_address: Option<String>,
    pub kdf: EncryptionKdf,
    pub dry_run: bool,
}

/// Maps the historical `--pbkdf2` CLI flag onto [`EncryptionKdf`].
///
/// `true` → [`EncryptionKdf::Pbkdf2`], `false` → [`EncryptionKdf::Scrypt`].
/// Production defaults are unchanged for both arms.
pub fn kdf_from_pbkdf2_flag(pbkdf2: bool) -> EncryptionKdf {
    if pbkdf2 {
        EncryptionKdf::Pbkdf2
    } else {
        EncryptionKdf::Scrypt
    }
}

/// Writes the mnemonic to a backup file with restrictive permissions (0o600).
/// Returns the SHA-256 hex checksum of the mnemonic string.
pub fn write_mnemonic_backup(path: &Path, mnemonic: &str) -> Result<String> {
    let checksum = mnemonic_checksum(mnemonic);
    let mut data = mnemonic.as_bytes().to_vec();
    data.push(b'\n');
    crate::fs_util::write_new_0600(path, &data)
        .with_context(|| format!("Failed to create mnemonic backup: {}", path.display()))?;
    Ok(checksum)
}

fn mnemonic_checksum(mnemonic: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(mnemonic.as_bytes());
    hex::encode(hasher.finalize())
}

/// Runs the new-mnemonic subcommand with all resolved inputs.
pub fn run(
    args: &GenerateArgs,
    mnemonic_passphrase: &str,
    keystore_password: &Zeroizing<String>,
    backup_file: Option<&Path>,
) -> Result<()> {
    // Fail-fast validation before generating a mnemonic the operator must store.
    let net = network::from_name(&args.network)?;
    if let Some(addr) = &args.withdrawal_address {
        password::validate_address(addr)?;
    }

    let mnemonic = crypto::mnemonic::generate_mnemonic();
    // Milestone only — the mnemonic value, its length, and the seed are never logged.
    info!(network = net.name, "generated new mnemonic");

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

    generate_from_seed(seed.as_ref(), args, keystore_password)
}

/// Core generation logic shared between new-mnemonic and existing-mnemonic.
pub fn generate_from_seed(
    seed: &[u8],
    args: &GenerateArgs,
    keystore_password: &Zeroizing<String>,
) -> Result<()> {
    let net = network::from_name(&args.network)?;
    let withdrawal_addr_bytes = match &args.withdrawal_address {
        Some(addr) => Some(password::validate_address(addr)?),
        None => None,
    };

    if !args.dry_run {
        std::fs::create_dir_all(&args.output_dir).with_context(|| {
            format!("Failed to create output directory: {}", args.output_dir.display())
        })?;
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock before UNIX epoch")?
        .as_secs();

    let end_index = args.start_index.checked_add(args.num_validators).ok_or_else(|| {
        anyhow::anyhow!(
            "start_index ({}) + num_validators ({}) overflows u32",
            args.start_index,
            args.num_validators
        )
    })?;

    let mut deposits = Vec::with_capacity(args.num_validators as usize);
    let mut summaries = Vec::with_capacity(args.num_validators as usize);

    info!(
        count = args.num_validators,
        start_index = args.start_index,
        network = net.name,
        dry_run = args.dry_run,
        "generating validator keystores"
    );

    for i in args.start_index..end_index {
        let signing_path = format!("m/12381/3600/{}/0/0", i);
        let signing_key = crypto::eip2333::derive_key_from_path(seed, &signing_path)
            .with_context(|| format!("Failed to derive signing key at {}", signing_path))?;

        // Non-secret: only the derived public key (truncated). The seed and signing_key
        // (secret material) are never passed to a logging macro.
        let pubkey_hex = hex::encode(signing_key.public_key().to_bytes());
        debug!(
            validator_index = i,
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            "derived validator signing key"
        );

        let withdrawal_credentials = match withdrawal_addr_bytes.as_ref() {
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
            Keystore::encrypt(&signing_key, keystore_password.as_bytes(), &signing_path, args.kdf)
                .with_context(|| format!("Failed to encrypt keystore for {}", signing_path))?;

        let keystore_filename = keystore_filename(i, timestamp);
        let keystore_path = args.output_dir.join(&keystore_filename);

        if args.dry_run {
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
    let deposit_path = args.output_dir.join(deposit_data_filename(timestamp));

    if args.dry_run {
        eprintln!("[DRY RUN] Would write deposit data: {}", deposit_path.display());
        println!("{}", deposit_json);
    } else {
        crate::fs_util::write_new_0600(&deposit_path, deposit_json.as_bytes())?;
    }

    verify::print_summary(&summaries, net.name, &args.output_dir);

    info!(
        count = args.num_validators,
        output_dir = %args.output_dir.display(),
        "validator keystores generated"
    );

    Ok(())
}

fn keystore_filename(index: u32, timestamp: u64) -> String {
    format!("keystore-m_12381_3600_{}_0_0-{}.json", index, timestamp)
}

fn deposit_data_filename(timestamp: u64) -> String {
    format!("deposit_data-{}.json", timestamp)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;

    /// All-lowercase eth1 address (20 × 0xab) — skips mixed-case EIP-55 checks.
    const TEST_ETH1_ADDR: &str = "0xabababababababababababababababababababab";
    const TEST_PASSWORD: &str = "testpassword123";
    const FIXED_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(TEST_PASSWORD.to_string())
    }

    fn base_args(output_dir: &Path) -> GenerateArgs {
        GenerateArgs {
            network: "mainnet".into(),
            output_dir: output_dir.to_path_buf(),
            num_validators: 1,
            start_index: 0,
            withdrawal_address: Some(TEST_ETH1_ADDR.into()),
            kdf: EncryptionKdf::Pbkdf2,
            dry_run: false,
        }
    }

    fn fixed_seed() -> Zeroizing<[u8; 64]> {
        let mnemonic = crypto::mnemonic::validate_mnemonic(FIXED_MNEMONIC).unwrap();
        crypto::mnemonic::mnemonic_to_seed(&mnemonic, "")
    }

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

    /// Pins the historical `--pbkdf2` bool → [`EncryptionKdf`] mapping in both directions,
    /// and asserts the produced keystore KDF function string is unchanged for each arm.
    #[test]
    fn test_generate_args_kdf_enum_selects_same_kdf_as_bool() {
        assert!(matches!(kdf_from_pbkdf2_flag(true), EncryptionKdf::Pbkdf2));
        assert!(matches!(kdf_from_pbkdf2_flag(false), EncryptionKdf::Scrypt));

        let seed = fixed_seed();
        let password = password();

        for (flag, expected_fn) in [(true, "pbkdf2"), (false, "scrypt")] {
            let dir = tempfile::tempdir().unwrap();
            let mut args = base_args(dir.path());
            args.kdf = kdf_from_pbkdf2_flag(flag);
            generate_from_seed(seed.as_ref(), &args, &password).unwrap();

            let keystore_file = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .find(|e| e.file_name().to_string_lossy().starts_with("keystore-"))
                .unwrap();
            let keystore = Keystore::from_file(keystore_file.path()).unwrap();
            assert_eq!(
                keystore.crypto.kdf.function, expected_fn,
                "flag {flag} must select KDF function {expected_fn}"
            );
        }
    }

    /// Fixed seed → identical deposit data and decrypted signing keys across two runs.
    /// (Keystore ciphertext differs: EIP-2335 salts are random.)
    #[test]
    fn test_new_mnemonic_output_unchanged_for_fixed_seed() {
        let seed = fixed_seed();
        let password = password();
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        generate_from_seed(seed.as_ref(), &base_args(dir1.path()), &password).unwrap();
        generate_from_seed(seed.as_ref(), &base_args(dir2.path()), &password).unwrap();

        let deposit1 = read_deposit_json(dir1.path());
        let deposit2 = read_deposit_json(dir2.path());
        assert_eq!(deposit1, deposit2, "deposit data must be byte-identical for fixed seed");

        let key1 = find_keystore(dir1.path()).decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        let key2 = find_keystore(dir2.path()).decrypt(TEST_PASSWORD.as_bytes()).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        let expected =
            crypto::eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0/0").unwrap();
        assert_eq!(key1.to_bytes(), expected.to_bytes());
    }

    #[test]
    fn test_dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("dry_run_output");
        let password = password();
        let seed = fixed_seed();

        let mut args = base_args(&output);
        args.num_validators = 2;
        args.dry_run = true;

        generate_from_seed(seed.as_ref(), &args, &password).unwrap();
        assert!(!output.exists(), "Output directory should not exist in dry-run mode");
    }

    /// Gate 3 (high-risk redaction): driving the real key-generation core under a
    /// subscriber that captures every level must NOT emit the mnemonic phrase, any
    /// constituent word, or the seed hex — not at any level.
    #[test]
    fn generate_from_seed_never_logs_mnemonic_or_seed() {
        use std::sync::{Arc, Mutex};

        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;

        #[derive(Clone, Default)]
        struct Cap(Arc<Mutex<String>>);
        struct V<'a>(&'a mut String);
        impl Visit for V<'_> {
            fn record_debug(&mut self, f: &Field, val: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={:?}", f.name(), val);
            }
        }
        impl<S: tracing::Subscriber> Layer<S> for Cap {
            fn on_event(&self, e: &tracing::Event<'_>, _: Context<'_, S>) {
                if let Ok(mut buf) = self.0.lock() {
                    e.record(&mut V(&mut buf));
                    buf.push('\n');
                }
            }
        }

        let cap = Cap::default();
        // No per-layer filter → the capture sees every level (debug/trace included).
        let subscriber = tracing_subscriber::registry().with(cap.clone());

        let seed = fixed_seed();
        let seed_hex = hex::encode(seed.as_ref());
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mut args = base_args(dir.path());
        args.num_validators = 2;
        args.withdrawal_address = None;
        args.kdf = EncryptionKdf::Scrypt;
        args.dry_run = true;

        tracing::subscriber::with_default(subscriber, || {
            generate_from_seed(seed.as_ref(), &args, &password).unwrap();
        });

        let logs = cap.0.lock().unwrap();
        assert!(!logs.contains(FIXED_MNEMONIC), "full mnemonic phrase leaked into logs");
        assert!(!logs.contains("abandon"), "a mnemonic word leaked into logs: {}", *logs);
        assert!(!logs.contains(&seed_hex), "seed hex leaked into logs");
        // Sanity: the breadth WAS captured, so the absence assertions are meaningful.
        assert!(
            logs.contains("derived validator signing key"),
            "expected debug breadth not captured; harness may be inert: {}",
            *logs
        );
    }

    #[test]
    fn test_generate_single_validator_with_eth1_withdrawal() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        generate_from_seed(seed.as_ref(), &base_args(dir.path()), &password).unwrap();

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
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        generate_from_seed(seed.as_ref(), &base_args(dir.path()), &password).unwrap();

        let keystore = find_keystore(dir.path());
        let decrypted = keystore.decrypt(password.as_bytes()).unwrap();

        let expected_key =
            crypto::eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0/0").unwrap();
        assert_eq!(decrypted.to_bytes(), expected_key.to_bytes());
    }

    #[test]
    fn test_generate_deposit_data_has_eth1_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        generate_from_seed(seed.as_ref(), &base_args(dir.path()), &password).unwrap();

        let deposits = read_deposit_json(dir.path());
        assert_eq!(deposits.len(), 1);

        let wc = deposits[0]["withdrawal_credentials"].as_str().unwrap();
        assert!(wc.starts_with("01"), "0x01 withdrawal credentials expected");
    }

    #[test]
    fn test_generate_deposit_data_has_bls_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let mut args = base_args(dir.path());
        args.withdrawal_address = None; // BLS credentials
        generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        let deposits = read_deposit_json(dir.path());
        let wc = deposits[0]["withdrawal_credentials"].as_str().unwrap();
        assert!(wc.starts_with("00"), "0x00 BLS withdrawal credentials expected");
    }

    #[test]
    fn test_generate_multiple_validators_with_start_index() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let mut args = base_args(dir.path());
        args.network = "hoodi".into();
        args.num_validators = 3;
        args.start_index = 5;
        generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        let entries: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();

        let keystore_files: Vec<_> = entries
            .iter()
            .filter(|e| e.file_name().to_string_lossy().starts_with("keystore-"))
            .collect();
        assert_eq!(keystore_files.len(), 3);

        for i in 5..8u32 {
            let pattern = format!("keystore-m_12381_3600_{}_0_0-", i);
            let found =
                entries.iter().any(|e| e.file_name().to_string_lossy().starts_with(&pattern));
            assert!(found, "Expected keystore for index {}", i);
        }

        let deposits = read_deposit_json(dir.path());
        assert_eq!(deposits.len(), 3);
    }

    #[test]
    fn test_generate_keystore_has_correct_path_field() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let mut args = base_args(dir.path());
        args.start_index = 5;
        generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        let keystore = find_keystore(dir.path());
        assert_eq!(keystore.path, "m/12381/3600/5/0/0");
    }

    #[test]
    fn test_generate_deposit_pubkey_matches_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        generate_from_seed(seed.as_ref(), &base_args(dir.path()), &password).unwrap();

        let keystore = find_keystore(dir.path());
        let keystore_pubkey = keystore.pubkey.unwrap();

        let deposits = read_deposit_json(dir.path());
        let deposit_pubkey = deposits[0]["pubkey"].as_str().unwrap();

        assert_eq!(keystore_pubkey, deposit_pubkey);
    }

    #[test]
    fn test_generate_creates_output_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deeply/nested/output");
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        generate_from_seed(seed.as_ref(), &base_args(&nested), &password).unwrap();

        assert!(nested.exists());
        assert!(nested.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn test_generate_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        generate_from_seed(seed.as_ref(), &base_args(dir.path()), &password).unwrap();

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
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let mut args = base_args(dir.path());
        args.network = "hoodi".into();
        generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        let deposits = read_deposit_json(dir.path());
        assert_eq!(deposits[0]["fork_version"], "10000910");
        assert_eq!(deposits[0]["network_name"], "hoodi");
    }

    #[test]
    fn test_dry_run_creates_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("dry_run_output");
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let mut args = base_args(&output);
        args.num_validators = 2;
        args.dry_run = true;
        generate_from_seed(seed.as_ref(), &args, &password).unwrap();

        assert!(!output.exists(), "Output directory should not exist in dry-run mode");
    }

    #[test]
    fn test_dry_run_still_derives_keys() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let mut args = base_args(dir.path());
        args.dry_run = true;
        let result = generate_from_seed(seed.as_ref(), &args, &password);
        assert!(result.is_ok());
    }

    // LOW-22: Integer overflow guard
    #[test]
    fn test_generate_overflow_start_index_plus_num_validators() {
        let dir = tempfile::tempdir().unwrap();
        let password = password();
        let mnemonic = crypto::mnemonic::generate_mnemonic();
        let seed = crypto::mnemonic::mnemonic_to_seed(&mnemonic, "");

        let mut args = base_args(dir.path());
        args.num_validators = u32::MAX;
        args.start_index = 1;
        args.dry_run = true;
        let result = generate_from_seed(seed.as_ref(), &args, &password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overflows"));
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

    /// Gate 3 (rvc-keygen): the BIP-39 mnemonic is an absolute sink. Driving the
    /// new-mnemonic generation path under a capturing subscriber must never emit
    /// the mnemonic phrase — nor even its length — through `tracing` at any level.
    /// The phrase reaches the operator via the backup file / `eprintln!` only; it
    /// must never enter the structured-logging layer where a collector could ship
    /// it off-box.
    #[test]
    #[tracing_test::traced_test]
    fn run_new_mnemonic_never_logs_mnemonic_through_tracing() {
        let out = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        let backup_path = backup.path().join("mnemonic.txt");
        let password = password();

        // Probe: prove the subscriber is live, so the absence assertions below
        // cannot pass merely because nothing was captured.
        tracing::info!("keygen conformance probe");

        let mut args = base_args(out.path());
        args.withdrawal_address = None;
        args.dry_run = true;
        run(&args, "", &password, Some(&backup_path))
            .expect("new-mnemonic generation should succeed");

        // The randomly generated phrase is only knowable via the backup file.
        let phrase = std::fs::read_to_string(&backup_path).unwrap();
        let phrase = phrase.trim();
        assert!(!phrase.is_empty(), "backup file must hold the generated mnemonic");
        assert!(logs_contain("keygen conformance probe"), "subscriber must be capturing");

        // The phrase — and a recognisable leading fragment — must never appear.
        assert!(!logs_contain(phrase), "mnemonic phrase leaked into a log line");
        let head = phrase.split_whitespace().take(4).collect::<Vec<_>>().join(" ");
        assert!(!logs_contain(&head), "leading words of the mnemonic leaked into a log line");

        // Not even the length: guard the realistic "N-word" / "N chars" phrasings.
        let word_count = phrase.split_whitespace().count();
        assert!(!logs_contain(&format!("{word_count}-word")), "mnemonic word count leaked");
        assert!(!logs_contain(&format!("{word_count} word")), "mnemonic word count leaked");
        assert!(!logs_contain(&format!("{} char", phrase.len())), "mnemonic char length leaked");
    }

    fn find_keystore(dir: &Path) -> Keystore {
        let entry = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("keystore-"))
            .expect("No keystore file found");
        Keystore::from_file(entry.path()).unwrap()
    }

    fn read_deposit_json(dir: &Path) -> Vec<serde_json::Value> {
        let deposit_file = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with("deposit_data-"))
            .expect("No deposit data file found");
        let deposit_json = std::fs::read_to_string(deposit_file.path()).unwrap();
        serde_json::from_str(&deposit_json).unwrap()
    }
}
