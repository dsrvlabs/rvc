use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crypto::{compute_domain, compute_signing_root, eip2333, mnemonic};
use eth_types::{BLSToExecutionChange, SignedBLSToExecutionChange, DOMAIN_BLS_TO_EXECUTION_CHANGE};

use crate::network;
use crate::password;

pub struct BlsToExecutionArgs {
    pub network: String,
    pub output_dir: PathBuf,
    pub validator_index: u64,
    pub execution_address: String,
    pub bls_withdrawal_index: u32,
}

pub fn run(args: BlsToExecutionArgs) -> Result<()> {
    let network = network::from_name(&args.network)?;

    let execution_address = password::validate_address(&args.execution_address)?;

    let mnemonic_phrase = Zeroizing::new(
        rpassword::prompt_password_stderr("Enter your mnemonic: ")
            .context("Failed to read mnemonic")?,
    );

    let mnemonic =
        mnemonic::validate_mnemonic(mnemonic_phrase.trim()).context("Invalid mnemonic phrase")?;

    let seed = mnemonic::mnemonic_to_seed(&mnemonic, "");

    // Withdrawal key path: m/12381/3600/{bls_withdrawal_index}/0
    let withdrawal_path = format!("m/12381/3600/{}/0", args.bls_withdrawal_index);
    let withdrawal_key = eip2333::derive_key_from_path(seed.as_ref(), &withdrawal_path)
        .context("Failed to derive withdrawal key")?;

    let withdrawal_pubkey = withdrawal_key.public_key();

    let change = BLSToExecutionChange {
        validator_index: args.validator_index,
        from_bls_pubkey: withdrawal_pubkey.to_bytes(),
        to_execution_address: execution_address,
    };

    // Domain: DOMAIN_BLS_TO_EXECUTION_CHANGE with Capella fork version and actual genesis_validators_root
    let domain = compute_domain(
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
        network.capella_fork_version,
        network.genesis_validators_root,
    );

    let signing_root = compute_signing_root(&change, domain);
    let signature = withdrawal_key.sign(&signing_root);

    let signed =
        SignedBLSToExecutionChange { message: change, signature: signature.to_bytes().to_vec() };

    let json = serde_json::to_string_pretty(&signed)
        .context("Failed to serialize signed BLS-to-execution change")?;

    fs::create_dir_all(&args.output_dir).with_context(|| {
        format!("Failed to create output directory: {}", args.output_dir.display())
    })?;

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let filename = format!("bls_to_execution-{}-{}.json", timestamp, args.validator_index);
    let output_path = args.output_dir.join(filename);

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;

        file.write_all(json.as_bytes())
            .with_context(|| format!("Failed to write output file: {}", output_path.display()))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&output_path, &json)
            .with_context(|| format!("Failed to write output file: {}", output_path.display()))?;
    }

    eprintln!("BLS-to-execution change written to: {}", output_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{compute_domain, compute_signing_root, eip2333, mnemonic};
    use eth_types::DOMAIN_BLS_TO_EXECUTION_CHANGE;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_withdrawal_key(index: u32) -> (crypto::SecretKey, crypto::PublicKey) {
        let mnemonic = mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = mnemonic::mnemonic_to_seed(&mnemonic, "");
        let path = format!("m/12381/3600/{}/0", index);
        let sk = eip2333::derive_key_from_path(seed.as_ref(), &path).unwrap();
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn test_bls_to_execution_sign_and_verify() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0x71; 20],
        };

        let network = network::from_name("mainnet").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        assert!(signature.verify(&withdrawal_pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_bls_to_execution_uses_capella_fork_version() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0x71; 20],
        };

        let network = network::from_name("mainnet").unwrap();

        // Sign with Capella fork version (correct)
        let capella_domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let capella_root = compute_signing_root(&change, capella_domain);
        let signature = withdrawal_key.sign(&capella_root);

        // Verify with Capella succeeds
        assert!(signature.verify(&withdrawal_pubkey, &capella_root).is_ok());

        // Verify with genesis fork version fails (proves we use Capella)
        let genesis_domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let genesis_root = compute_signing_root(&change, genesis_domain);
        assert!(signature.verify(&withdrawal_pubkey, &genesis_root).is_err());
    }

    #[test]
    fn test_bls_to_execution_uses_actual_genesis_root() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0x71; 20],
        };

        let network = network::from_name("mainnet").unwrap();

        // Sign with actual genesis_validators_root (correct)
        let correct_domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let correct_root = compute_signing_root(&change, correct_domain);
        let signature = withdrawal_key.sign(&correct_root);

        // Verify with zeroed root fails (proves we use actual root)
        let zeroed_domain =
            compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, network.capella_fork_version, [0u8; 32]);
        let zeroed_root = compute_signing_root(&change, zeroed_domain);
        assert!(signature.verify(&withdrawal_pubkey, &zeroed_root).is_err());
    }

    #[test]
    fn test_bls_to_execution_withdrawal_path_not_signing_path() {
        let mnemonic = mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = mnemonic::mnemonic_to_seed(&mnemonic, "");

        // Withdrawal path: m/12381/3600/0/0 (4 levels)
        let withdrawal_key =
            eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0").unwrap();

        // Signing path: m/12381/3600/0/0/0 (5 levels)
        let signing_key =
            eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0/0").unwrap();

        // They must be different keys
        assert_ne!(withdrawal_key.to_bytes(), signing_key.to_bytes());
        assert_ne!(withdrawal_key.public_key().to_bytes(), signing_key.public_key().to_bytes());
    }

    #[test]
    fn test_bls_to_execution_output_json_structure() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);
        let exec_addr = [0xAB; 20];

        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: exec_addr,
        };

        let network = network::from_name("mainnet").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        let signed = SignedBLSToExecutionChange {
            message: change,
            signature: signature.to_bytes().to_vec(),
        };

        let json = serde_json::to_string_pretty(&signed).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("message").is_some());
        assert!(parsed.get("signature").is_some());
        assert_eq!(parsed["message"]["validator_index"], "42");

        // from_bls_pubkey should be 0x-prefixed 48-byte hex (98 chars)
        let pubkey_str = parsed["message"]["from_bls_pubkey"].as_str().unwrap();
        assert!(pubkey_str.starts_with("0x"));
        assert_eq!(pubkey_str.len(), 98);

        // to_execution_address should be 0x-prefixed 20-byte hex (42 chars)
        let addr_str = parsed["message"]["to_execution_address"].as_str().unwrap();
        assert!(addr_str.starts_with("0x"));
        assert_eq!(addr_str.len(), 42);

        // signature should be 0x-prefixed 96-byte hex (194 chars)
        let sig_str = parsed["signature"].as_str().unwrap();
        assert!(sig_str.starts_with("0x"));
        assert_eq!(sig_str.len(), 194);
    }

    #[cfg(unix)]
    #[test]
    fn test_bls_to_execution_output_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 1,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0x01; 20],
        };

        let network = network::from_name("mainnet").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        let signed = SignedBLSToExecutionChange {
            message: change,
            signature: signature.to_bytes().to_vec(),
        };

        let json = serde_json::to_string_pretty(&signed).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let output_path = dir.path().join("test_bls.json");

        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&output_path)
                .unwrap();

            file.write_all(json.as_bytes()).unwrap();
        }

        let metadata = fs::metadata(&output_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let content = fs::read_to_string(&output_path).unwrap();
        let parsed: SignedBLSToExecutionChange = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.message.validator_index, 1);
    }

    #[test]
    fn test_bls_to_execution_hoodi_network() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 99,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0xCC; 20],
        };

        let network = network::from_name("hoodi").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        assert!(signature.verify(&withdrawal_pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_bls_to_execution_different_withdrawal_indices() {
        let (_, pk0) = test_withdrawal_key(0);
        let (_, pk1) = test_withdrawal_key(1);

        // Different withdrawal indices produce different keys
        assert_ne!(pk0.to_bytes(), pk1.to_bytes());
    }

    #[test]
    fn test_bls_to_execution_invalid_address() {
        // Missing 0x prefix
        assert!(password::validate_address("71C7656EC7ab88b098defB751B7401B5f6d8976F").is_err());
        // Too short
        assert!(password::validate_address("0x71C7").is_err());
        // Invalid hex
        assert!(password::validate_address("0xZZC7656EC7ab88b098defB751B7401B5f6d8976F").is_err());
    }
}
