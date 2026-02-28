//! Integration tests for parallel keystore loading.
//!
//! These tests create real PBKDF2-encrypted keystores and verify that
//! `load_from_directory_with_threads` correctly loads, decrypts, and
//! handles mixed success/failure scenarios.

use std::collections::HashMap;

use rvc_crypto::{EncryptionKdf, KeyManager, Keystore, PublicKey, SecretKey};
use secrecy::SecretString;
use tempfile::TempDir;

const TEST_PASSWORD: &[u8] = b"integration-test-pw";

fn password_map(pubkey_hex: &str) -> HashMap<String, SecretString> {
    let mut map = HashMap::new();
    map.insert(
        pubkey_hex.to_string(),
        SecretString::from(String::from_utf8(TEST_PASSWORD.to_vec()).unwrap()),
    );
    map
}

fn create_keystore(dir: &TempDir, index: usize, password: &[u8]) -> (SecretKey, String) {
    let sk = SecretKey::generate();
    let pubkey_hex = hex::encode(sk.public_key().to_bytes());
    let path = format!("m/12381/3600/{}/0/0", index);
    let keystore = Keystore::encrypt(&sk, password, &path, EncryptionKdf::Pbkdf2)
        .expect("encryption should succeed");
    let filename = format!("keystore-{}.json", index);
    keystore.to_file(dir.path().join(&filename)).expect("write should succeed");
    (sk, pubkey_hex)
}

#[test]
fn test_parallel_load_multiple_keystores() {
    let dir = TempDir::new().unwrap();

    // Create 3 keystores with the same password
    let (sk0, pub0) = create_keystore(&dir, 0, TEST_PASSWORD);
    let (sk1, pub1) = create_keystore(&dir, 1, TEST_PASSWORD);
    let (sk2, pub2) = create_keystore(&dir, 2, TEST_PASSWORD);

    // Build password map for all 3
    let mut passwords = HashMap::new();
    let pw = String::from_utf8(TEST_PASSWORD.to_vec()).unwrap();
    for pubkey in [&pub0, &pub1, &pub2] {
        passwords.insert(pubkey.clone(), SecretString::from(pw.clone()));
    }

    // Load with 2 threads
    let manager =
        KeyManager::load_from_directory_with_threads(dir.path(), &passwords, Some(2)).unwrap();

    // Verify correct key count
    assert_eq!(manager.len(), 3);

    // Verify each key can sign and verify
    let message = b"hello parallel decryption";
    let keys: Vec<(&SecretKey, &str)> = vec![(&sk0, &pub0), (&sk1, &pub1), (&sk2, &pub2)];
    for (sk, pubkey_hex) in keys {
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();

        let loaded_sk = manager.get_secret_key(&pubkey);
        assert!(loaded_sk.is_some(), "key {} should be loaded", pubkey_hex);

        let loaded_sk = loaded_sk.unwrap();
        assert_eq!(
            loaded_sk.public_key().to_bytes(),
            sk.public_key().to_bytes(),
            "loaded key should match original for {}",
            pubkey_hex,
        );

        let sig = loaded_sk.sign(message);
        assert!(sig.verify(&pubkey, message).is_ok(), "signature should verify for {}", pubkey_hex,);
    }
}

#[test]
fn test_parallel_load_wrong_password_skipped() {
    let dir = TempDir::new().unwrap();

    // Create 3 keystores: 2 with correct password, 1 with different password
    let (_sk0, pub0) = create_keystore(&dir, 0, TEST_PASSWORD);
    let (_sk1, pub1) = create_keystore(&dir, 1, TEST_PASSWORD);
    let (_sk_wrong, pub_wrong) = create_keystore(&dir, 2, b"wrong-password");

    // Password map has the shared password for all 3 pubkeys,
    // but keystore #2 was encrypted with a different password
    let mut passwords = HashMap::new();
    let pw = String::from_utf8(TEST_PASSWORD.to_vec()).unwrap();
    for pubkey in [&pub0, &pub1, &pub_wrong] {
        passwords.insert(pubkey.clone(), SecretString::from(pw.clone()));
    }

    // Load with 2 threads — wrong-password keystore should be skipped
    let manager =
        KeyManager::load_from_directory_with_threads(dir.path(), &passwords, Some(2)).unwrap();

    // Only 2 keys should load successfully
    assert_eq!(manager.len(), 2);

    // The correctly-encrypted keys should be present
    let pub0_bytes = hex::decode(&pub0).unwrap();
    let pub1_bytes = hex::decode(&pub1).unwrap();
    assert!(manager.get_secret_key(&PublicKey::from_bytes(&pub0_bytes).unwrap()).is_some());
    assert!(manager.get_secret_key(&PublicKey::from_bytes(&pub1_bytes).unwrap()).is_some());

    // The wrong-password key should NOT be present
    let pub_wrong_bytes = hex::decode(&pub_wrong).unwrap();
    assert!(manager.get_secret_key(&PublicKey::from_bytes(&pub_wrong_bytes).unwrap()).is_none());
}

#[test]
fn test_parallel_load_with_auto_threads() {
    let dir = TempDir::new().unwrap();

    let (_sk, pubkey_hex) = create_keystore(&dir, 0, TEST_PASSWORD);
    let passwords = password_map(&pubkey_hex);

    // None = auto-detect thread count
    let manager =
        KeyManager::load_from_directory_with_threads(dir.path(), &passwords, None).unwrap();
    assert_eq!(manager.len(), 1);
}

#[test]
fn test_parallel_load_single_thread() {
    let dir = TempDir::new().unwrap();

    let (_sk0, pub0) = create_keystore(&dir, 0, TEST_PASSWORD);
    let (_sk1, pub1) = create_keystore(&dir, 1, TEST_PASSWORD);

    let mut passwords = HashMap::new();
    let pw = String::from_utf8(TEST_PASSWORD.to_vec()).unwrap();
    for pubkey in [&pub0, &pub1] {
        passwords.insert(pubkey.clone(), SecretString::from(pw.clone()));
    }

    // Single thread should still work correctly
    let manager =
        KeyManager::load_from_directory_with_threads(dir.path(), &passwords, Some(1)).unwrap();
    assert_eq!(manager.len(), 2);
}
