use crypto::{KeyManager, LocalSigner, SecretKey, Signer as _};
use rvc_secret_provider::{
    KeyMaterial, KeySourceManager, MockSecretProvider, SecretKeyEntry, SecretProviderError,
};
use zeroize::Zeroizing;

fn make_raw_key_entry(
    id: &str,
    sk: &SecretKey,
) -> (SecretKeyEntry, Result<KeyMaterial, SecretProviderError>) {
    let bytes: [u8; 32] = sk.to_bytes();
    (
        SecretKeyEntry { id: id.to_string(), pubkey_hex: None },
        Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
    )
}

#[tokio::test]
async fn test_mock_provider_keys_visible_in_key_manager_and_signable() {
    let sk = SecretKey::generate();
    let pubkey_bytes = sk.public_key().to_bytes();

    let provider = MockSecretProvider {
        name: "mock-cloud".to_string(),
        keys: vec![make_raw_key_entry("cloud-key-1", &sk)],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let mut km = KeyManager::new();
    let summary = ksm.load_all(&mut km).await.expect("load_all should succeed");

    assert_eq!(summary.per_provider.len(), 1);
    assert_eq!(summary.per_provider[0].loaded, 1);
    assert_eq!(km.len(), 1);

    let signer = LocalSigner::new(km);
    let signing_root = [0xABu8; 32];
    let signature = signer.sign(&signing_root, &pubkey_bytes).await;
    assert!(signature.is_ok(), "should be able to sign with cloud-loaded key");
}

#[tokio::test]
async fn test_mixed_filesystem_and_cloud_keys_coexist() {
    let fs_sk = SecretKey::generate();
    let fs_pubkey_bytes = fs_sk.public_key().to_bytes();
    let mut km = KeyManager::new();
    km.insert(fs_sk);
    assert_eq!(km.len(), 1);

    let cloud_sk = SecretKey::generate();
    let cloud_pubkey_bytes = cloud_sk.public_key().to_bytes();

    let provider = MockSecretProvider {
        name: "mock-cloud".to_string(),
        keys: vec![make_raw_key_entry("cloud-key-1", &cloud_sk)],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let summary = ksm.load_all(&mut km).await.expect("load_all should succeed");

    assert_eq!(summary.per_provider[0].loaded, 1);
    assert_eq!(km.len(), 2);

    let signer = LocalSigner::new(km);
    let signing_root = [0xCDu8; 32];

    let fs_sig = signer.sign(&signing_root, &fs_pubkey_bytes).await;
    assert!(fs_sig.is_ok(), "filesystem key should be signable");

    let cloud_sig = signer.sign(&signing_root, &cloud_pubkey_bytes).await;
    assert!(cloud_sig.is_ok(), "cloud key should be signable");
}

#[tokio::test]
async fn test_partial_failures_load_successful_keys_skip_failed() {
    let good_sk = SecretKey::generate();
    let good_pubkey_bytes = good_sk.public_key().to_bytes();

    let provider = MockSecretProvider {
        name: "partial-fail".to_string(),
        keys: vec![
            make_raw_key_entry("good-key", &good_sk),
            (
                SecretKeyEntry { id: "bad-key".to_string(), pubkey_hex: None },
                Err(SecretProviderError::Provider("network timeout".into())),
            ),
        ],
        list_error: None,
    };

    let ksm = KeySourceManager::new(vec![Box::new(provider)]);
    let mut km = KeyManager::new();
    let summary =
        ksm.load_all(&mut km).await.expect("load_all should succeed despite partial failure");

    assert_eq!(summary.per_provider[0].loaded, 1);
    assert_eq!(summary.per_provider[0].skipped, 1);
    assert_eq!(summary.per_provider[0].errors.len(), 1);
    assert_eq!(km.len(), 1);

    let signer = LocalSigner::new(km);
    let signing_root = [0xEFu8; 32];
    let sig = signer.sign(&signing_root, &good_pubkey_bytes).await;
    assert!(sig.is_ok(), "good key should be signable after partial failure");
}
