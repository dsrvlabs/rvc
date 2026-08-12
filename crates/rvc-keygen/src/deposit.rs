use crypto::{compute_domain, compute_signing_root, PublicKey, SecretKey};
use eth_types::{DepositData, DepositMessage, Version, DOMAIN_DEPOSIT};
use sha2::{Digest, Sha256};
use tree_hash::TreeHash;

const DEPOSIT_AMOUNT: u64 = 32_000_000_000;

/// Computes 0x01 withdrawal credentials from an Ethereum execution address.
/// Format: 0x01 || 0x00 * 11 || address (20 bytes)
pub fn eth1_withdrawal_credentials(address: &[u8; 20]) -> [u8; 32] {
    let mut creds = [0u8; 32];
    creds[0] = 0x01;
    creds[12..32].copy_from_slice(address);
    creds
}

/// Computes 0x00 withdrawal credentials from a BLS withdrawal public key.
/// Format: 0x00 || SHA-256(pubkey)[1..32]
pub fn bls_withdrawal_credentials(withdrawal_pubkey: &PublicKey) -> [u8; 32] {
    let hash = Sha256::digest(withdrawal_pubkey.to_bytes());
    let mut creds = [0u8; 32];
    creds[0] = 0x00;
    creds[1..32].copy_from_slice(&hash[1..32]);
    creds
}

/// Signs a deposit message and returns the complete DepositData.
/// Uses DOMAIN_DEPOSIT with zeroed genesis_validators_root.
pub fn sign_deposit(
    signing_key: &SecretKey,
    withdrawal_credentials: [u8; 32],
    genesis_fork_version: Version,
) -> DepositData {
    let pubkey = signing_key.public_key().to_bytes();

    let deposit_message = DepositMessage { pubkey, withdrawal_credentials, amount: DEPOSIT_AMOUNT };

    let domain = compute_domain(DOMAIN_DEPOSIT, genesis_fork_version, [0u8; 32]);
    let signing_root = compute_signing_root(&deposit_message, domain);
    let signature = signing_key.sign(&signing_root);

    DepositData {
        pubkey,
        withdrawal_credentials,
        amount: DEPOSIT_AMOUNT,
        signature: signature.to_bytes(),
    }
}

/// Launchpad-compatible deposit entry with bare hex (no 0x prefix).
#[derive(serde::Serialize)]
struct LaunchpadDepositEntry {
    pubkey: String,
    withdrawal_credentials: String,
    amount: u64,
    signature: String,
    deposit_message_root: String,
    deposit_data_root: String,
    fork_version: String,
    network_name: String,
    deposit_cli_version: String,
}

fn bare_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Serializes deposit data entries to Launchpad-compatible JSON.
/// All hex values are bare hex (no 0x prefix) per Launchpad format.
pub fn to_launchpad_json(
    deposits: &[DepositData],
    genesis_fork_version: Version,
    network_name: &str,
) -> Result<String, serde_json::Error> {
    let entries: Vec<LaunchpadDepositEntry> = deposits
        .iter()
        .map(|d| {
            let deposit_message = DepositMessage {
                pubkey: d.pubkey,
                withdrawal_credentials: d.withdrawal_credentials,
                amount: d.amount,
            };

            LaunchpadDepositEntry {
                pubkey: bare_hex(&d.pubkey),
                withdrawal_credentials: bare_hex(&d.withdrawal_credentials),
                amount: d.amount,
                signature: bare_hex(&d.signature),
                deposit_message_root: bare_hex(&deposit_message.tree_hash_root().0),
                deposit_data_root: bare_hex(&d.tree_hash_root().0),
                fork_version: bare_hex(&genesis_fork_version),
                network_name: network_name.to_string(),
                deposit_cli_version: "rvc-keygen-0.1.0".to_string(),
            }
        })
        .collect();

    serde_json::to_string_pretty(&entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth1_withdrawal_credentials_prefix() {
        let address = [0xAB; 20];
        let creds = eth1_withdrawal_credentials(&address);
        assert_eq!(creds[0], 0x01);
    }

    #[test]
    fn test_eth1_withdrawal_credentials_padding() {
        let address = [0xAB; 20];
        let creds = eth1_withdrawal_credentials(&address);
        assert_eq!(&creds[1..12], &[0u8; 11]);
    }

    #[test]
    fn test_eth1_withdrawal_credentials_address() {
        let address = [0xAB; 20];
        let creds = eth1_withdrawal_credentials(&address);
        assert_eq!(&creds[12..32], &address);
    }

    #[test]
    fn test_eth1_withdrawal_credentials_known_address() {
        let mut address = [0u8; 20];
        address[19] = 0x01;
        let creds = eth1_withdrawal_credentials(&address);
        assert_eq!(creds[0], 0x01);
        assert_eq!(&creds[1..12], &[0u8; 11]);
        assert_eq!(&creds[12..31], &[0u8; 19]);
        assert_eq!(creds[31], 0x01);
    }

    #[test]
    fn test_bls_withdrawal_credentials_prefix() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let creds = bls_withdrawal_credentials(&pk);
        assert_eq!(creds[0], 0x00);
    }

    #[test]
    fn test_bls_withdrawal_credentials_hash() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let creds = bls_withdrawal_credentials(&pk);

        let expected_hash = Sha256::digest(pk.to_bytes());
        assert_eq!(&creds[1..32], &expected_hash[1..32]);
    }

    #[test]
    fn test_bls_withdrawal_credentials_deterministic() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let creds1 = bls_withdrawal_credentials(&pk);
        let creds2 = bls_withdrawal_credentials(&pk);
        assert_eq!(creds1, creds2);
    }

    #[test]
    fn test_sign_deposit_pubkey() {
        let sk = SecretKey::generate();
        let expected_pubkey = sk.public_key().to_bytes();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(deposit.pubkey, expected_pubkey);
    }

    #[test]
    fn test_sign_deposit_amount() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(deposit.amount, 32_000_000_000);
    }

    #[test]
    fn test_sign_deposit_withdrawal_credentials() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(deposit.withdrawal_credentials, creds);
    }

    #[test]
    fn test_sign_deposit_signature_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let fork_version = [0x00, 0x00, 0x00, 0x00];
        let deposit = sign_deposit(&sk, creds, fork_version);

        let deposit_message = DepositMessage {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
        };

        let domain = compute_domain(DOMAIN_DEPOSIT, fork_version, [0u8; 32]);
        let signing_root = compute_signing_root(&deposit_message, domain);
        let sig = crypto::Signature::from_bytes(&deposit.signature).unwrap();
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_deposit_uses_zeroed_genesis_root() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let fork_version = [0x00, 0x00, 0x00, 0x00];
        let deposit = sign_deposit(&sk, creds, fork_version);

        let deposit_message = DepositMessage {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
        };

        // Verify with zeroed root (correct)
        let domain = compute_domain(DOMAIN_DEPOSIT, fork_version, [0u8; 32]);
        let signing_root = compute_signing_root(&deposit_message, domain);
        let sig = crypto::Signature::from_bytes(&deposit.signature).unwrap();
        assert!(sig.verify(&pk, &signing_root).is_ok());

        // Verify with non-zeroed root (should fail)
        let wrong_domain = compute_domain(DOMAIN_DEPOSIT, fork_version, [0xAA; 32]);
        let wrong_root = compute_signing_root(&deposit_message, wrong_domain);
        assert!(sig.verify(&pk, &wrong_root).is_err());
    }

    #[test]
    fn test_sign_deposit_hoodi_fork_version() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let fork_version = [0x10, 0x00, 0x09, 0x10]; // Hoodi genesis
        let deposit = sign_deposit(&sk, creds, fork_version);

        let deposit_message = DepositMessage {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
        };

        let domain = compute_domain(DOMAIN_DEPOSIT, fork_version, [0u8; 32]);
        let signing_root = compute_signing_root(&deposit_message, domain);
        let sig = crypto::Signature::from_bytes(&deposit.signature).unwrap();
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    #[test]
    fn test_bare_hex_no_prefix() {
        assert_eq!(bare_hex(&[0x01, 0x02, 0x03]), "010203");
        assert!(!bare_hex(&[0xFF]).starts_with("0x"));
    }

    #[test]
    fn test_to_launchpad_json_structure() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.len(), 1);
        let entry = &parsed[0];

        assert!(entry["pubkey"].is_string());
        assert!(entry["withdrawal_credentials"].is_string());
        assert!(entry["amount"].is_number());
        assert!(entry["signature"].is_string());
        assert!(entry["deposit_message_root"].is_string());
        assert!(entry["deposit_data_root"].is_string());
        assert!(entry["fork_version"].is_string());
        assert!(entry["network_name"].is_string());
        assert!(entry["deposit_cli_version"].is_string());
    }

    #[test]
    fn test_to_launchpad_json_no_hex_prefix() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let entry = &parsed[0];

        let hex_fields = [
            "pubkey",
            "withdrawal_credentials",
            "signature",
            "deposit_message_root",
            "deposit_data_root",
            "fork_version",
        ];
        for field in &hex_fields {
            let val = entry[field].as_str().unwrap();
            assert!(
                !val.starts_with("0x"),
                "Field '{}' should not have 0x prefix, got: {}",
                field,
                val
            );
        }
    }

    #[test]
    fn test_to_launchpad_json_amount_is_integer() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0]["amount"], 32_000_000_000u64);
    }

    #[test]
    fn test_to_launchpad_json_network_name() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0]["network_name"], "mainnet");
    }

    #[test]
    fn test_to_launchpad_json_fork_version() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0]["fork_version"], "00000000");
    }

    #[test]
    fn test_to_launchpad_json_cli_version() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0]["deposit_cli_version"], "rvc-keygen-0.1.0");
    }

    #[test]
    fn test_to_launchpad_json_deposit_message_root() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let deposit_message = DepositMessage {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
        };
        let expected_root = bare_hex(&deposit_message.tree_hash_root().0);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0]["deposit_message_root"], expected_root);
    }

    #[test]
    fn test_to_launchpad_json_deposit_data_root() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let expected_root = bare_hex(&deposit.tree_hash_root().0);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0]["deposit_data_root"], expected_root);
    }

    #[test]
    fn test_to_launchpad_json_pubkey_length() {
        let sk = SecretKey::generate();
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);
        let deposit = sign_deposit(&sk, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[deposit], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        // 48 bytes = 96 hex chars
        assert_eq!(parsed[0]["pubkey"].as_str().unwrap().len(), 96);
        // 32 bytes = 64 hex chars
        assert_eq!(parsed[0]["withdrawal_credentials"].as_str().unwrap().len(), 64);
        // 96 bytes = 192 hex chars
        assert_eq!(parsed[0]["signature"].as_str().unwrap().len(), 192);
        // 32 bytes = 64 hex chars
        assert_eq!(parsed[0]["deposit_message_root"].as_str().unwrap().len(), 64);
        assert_eq!(parsed[0]["deposit_data_root"].as_str().unwrap().len(), 64);
        // 4 bytes = 8 hex chars
        assert_eq!(parsed[0]["fork_version"].as_str().unwrap().len(), 8);
    }

    #[test]
    fn test_to_launchpad_json_multiple_deposits() {
        let creds = eth1_withdrawal_credentials(&[0xAB; 20]);

        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let d1 = sign_deposit(&sk1, creds, [0x00, 0x00, 0x00, 0x00]);
        let d2 = sign_deposit(&sk2, creds, [0x00, 0x00, 0x00, 0x00]);

        let json = to_launchpad_json(&[d1, d2], [0x00, 0x00, 0x00, 0x00], "mainnet").unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_ne!(parsed[0]["pubkey"], parsed[1]["pubkey"]);
    }
}
