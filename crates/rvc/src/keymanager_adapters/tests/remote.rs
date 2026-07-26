use super::*;

// --- RemoteKeyManagerAdapter tests ---

#[test]
fn test_remote_key_adapter_empty_list() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    assert!(adapter.list_remote_keys().is_empty());
}

#[test]
fn test_remote_key_adapter_has_key_false() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    assert!(!adapter.has_remote_key(&test_pubkey(1)));
}

#[test]
fn test_remote_key_adapter_import_and_list() {
    let composite = create_empty_composite_signer();
    let (adapter, _, _) = test_remote_adapter(composite.clone(), None);

    let pk = test_pubkey(1);
    let url = "https://signer.example.com".to_string();
    adapter.import_remote_key(pk, url.clone()).unwrap();

    let keys = adapter.list_remote_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, pk);
    assert_eq!(keys[0].1, url);
    assert!(adapter.has_remote_key(&pk));

    assert!(composite.public_keys().contains(&pk));
}

#[test]
fn test_remote_key_adapter_import_duplicate() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);
    adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
    let result = adapter.import_remote_key(pk, "https://signer.example.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)));
}

#[test]
fn test_remote_key_adapter_delete() {
    let composite = create_empty_composite_signer();
    let (adapter, _, _) = test_remote_adapter(composite.clone(), None);

    let pk = test_pubkey(1);
    adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
    assert!(adapter.has_remote_key(&pk));

    let deleted = adapter.delete_remote_key(&pk).unwrap();
    assert!(deleted);
    assert!(!adapter.has_remote_key(&pk));
    assert!(!composite.public_keys().contains(&pk));
}

#[test]
fn test_remote_key_adapter_delete_nonexistent() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    assert!(!adapter.delete_remote_key(&test_pubkey(99)).unwrap());
}

#[test]
fn test_remote_key_adapter_import_rejects_invalid_url_scheme() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);

    // file:// scheme — SSRF risk
    let result = adapter.import_remote_key(pk, "file:///etc/passwd".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));

    // ftp:// scheme
    let result = adapter.import_remote_key(pk, "ftp://evil.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));

    // No scheme
    let result = adapter.import_remote_key(pk, "signer.example.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));

    // Valid schemes should be accepted
    let pk2 = test_pubkey(2);
    let result = adapter.import_remote_key(pk2, "https://signer.example.com".to_string());
    assert!(result.is_ok());
}

// --- Remote signer host allowlist tests ---

#[test]
fn test_import_remote_key_allowed_host_accepted() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["signer.example.com".to_string()]),
    );
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "https://signer.example.com/api".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_import_remote_key_blocked_host_rejected() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["trusted.host".to_string()]),
    );
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "https://evil.attacker.com/api".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::HostNotAllowed(_))));
}

#[test]
fn test_import_remote_key_no_allowlist_allows_all() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "https://any.host.com".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_import_remote_key_allowlist_multiple_hosts() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["signer1.example.com".to_string(), "signer2.example.com".to_string()]),
    );
    let pk1 = test_pubkey(1);
    assert!(adapter.import_remote_key(pk1, "https://signer1.example.com".to_string()).is_ok());

    let pk2 = test_pubkey(2);
    assert!(adapter.import_remote_key(pk2, "https://signer2.example.com".to_string()).is_ok());

    let pk3 = test_pubkey(3);
    let result = adapter.import_remote_key(pk3, "https://signer3.example.com".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::HostNotAllowed(_))));
}

#[test]
fn test_import_remote_key_invalid_url_parse_error() {
    let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
    let pk = test_pubkey(1);
    let result = adapter.import_remote_key(pk, "not a valid url".to_string());
    assert!(matches!(result, Err(ImportRemoteKeyError::InvalidUrl(_))));
}

#[test]
fn test_import_remote_key_allowlist_with_port() {
    let (adapter, _, _) = test_remote_adapter(
        create_empty_composite_signer(),
        Some(vec!["signer.example.com".to_string()]),
    );
    let pk = test_pubkey(1);
    // host_str() returns the host without port
    let result =
        adapter.import_remote_key(pk, "https://signer.example.com:9000/api".to_string());
    assert!(result.is_ok());
}

