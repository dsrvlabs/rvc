use rvc_eth_types::canonical::{
    gvr_hex::{eq_gvr, parse_gvr_hex, GvrHex},
    pubkey_hex::{parse_pubkey_hex, PubkeyHex},
    signing_root_hex::{parse_signing_root_hex, SigningRootHex},
    ParseError,
};

// ─── PubkeyHex ──────────────────────────────────────────────────────────────

#[test]
fn test_pubkey_hex_happy_path_with_prefix() {
    let hex_str = format!("0x{}", "ab".repeat(48));
    let pk = parse_pubkey_hex(&hex_str).expect("valid prefixed pubkey hex");
    assert_eq!(pk.as_bytes(), &[0xabu8; 48]);
}

#[test]
fn test_pubkey_hex_happy_path_no_prefix() {
    let hex_str = "ab".repeat(48);
    let pk = parse_pubkey_hex(&hex_str).expect("valid bare pubkey hex");
    assert_eq!(pk.as_bytes(), &[0xabu8; 48]);
}

#[test]
fn test_pubkey_hex_mixed_case_accepted() {
    // Build a valid 48-byte pubkey using mixed-case hex
    let mut hex_str = String::from("0x");
    hex_str.push_str(&"aAbB".repeat(24)); // 96 hex chars = 48 bytes
    let pk = parse_pubkey_hex(&hex_str).expect("mixed-case hex is valid");
    let expected = hex::decode("aabb".repeat(24)).unwrap();
    assert_eq!(pk.as_bytes(), expected.as_slice());
}

#[test]
fn test_pubkey_hex_rejects_double_prefix() {
    let hex_str = format!("0x0x{}", "ab".repeat(48));
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

#[test]
fn test_pubkey_hex_rejects_odd_length() {
    // bare hex with odd length (no prefix)
    let hex_str = format!("0x{}", "abc"); // 3 hex chars = odd
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

#[test]
fn test_pubkey_hex_rejects_non_hex_char() {
    let hex_str = format!("0x{}", "zz".repeat(48));
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

#[test]
fn test_pubkey_hex_rejects_wrong_length() {
    // valid hex but 32 bytes instead of 48
    let hex_str = format!("0x{}", "ab".repeat(32));
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { .. }));
}

#[test]
fn test_pubkey_hex_derives_clone_eq_hash() {
    let hex_str = format!("0x{}", "cd".repeat(48));
    let pk1: PubkeyHex = parse_pubkey_hex(&hex_str).unwrap();
    let pk2 = pk1.clone();
    assert_eq!(pk1, pk2);

    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(pk1);
    set.insert(pk2);
    assert_eq!(set.len(), 1);
}

// ─── GvrHex ─────────────────────────────────────────────────────────────────

#[test]
fn test_gvr_hex_happy_path_with_prefix() {
    let hex_str = format!("0x{}", "cd".repeat(32));
    let root = parse_gvr_hex(&hex_str).expect("valid prefixed GVR hex");
    assert_eq!(root, [0xcdu8; 32]);
}

#[test]
fn test_gvr_hex_happy_path_no_prefix() {
    let hex_str = "cd".repeat(32);
    let root = parse_gvr_hex(&hex_str).expect("valid bare GVR hex");
    assert_eq!(root, [0xcdu8; 32]);
}

#[test]
fn test_gvr_hex_rejects_double_prefix() {
    let hex_str = format!("0x0x{}", "cd".repeat(32));
    let err = parse_gvr_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

#[test]
fn test_gvr_hex_rejects_odd_length() {
    let hex_str = "0xabc"; // 3 hex chars = odd
    let err = parse_gvr_hex(hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

#[test]
fn test_gvr_hex_rejects_non_hex_char() {
    let hex_str = format!("0x{}", "zz".repeat(32));
    let err = parse_gvr_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

#[test]
fn test_gvr_hex_rejects_wrong_length() {
    let hex_str = format!("0x{}", "ab".repeat(16)); // 16 bytes, not 32
    let err = parse_gvr_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { .. }));
}

#[test]
fn test_gvr_hex_as_bytes() {
    let hex_str = format!("0x{}", "ef".repeat(32));
    let root = parse_gvr_hex(&hex_str).unwrap();
    let gvr = GvrHex::from_root(root);
    assert_eq!(gvr.as_bytes(), &[0xefu8; 32]);
}

#[test]
fn test_gvr_hex_as_normalised_hex_is_lowercase() {
    // Input mixed-case, normalised should be lowercase
    let mut hex_str = String::from("0x");
    hex_str.push_str(&"ABCD".repeat(16)); // 64 chars = 32 bytes
    let root = parse_gvr_hex(&hex_str).unwrap();
    let gvr = GvrHex::from_root(root);
    let normalised = gvr.as_normalised_hex();
    assert!(normalised.chars().all(|c| !c.is_ascii_uppercase()));
    assert!(normalised.starts_with("0x"));
}

#[test]
fn test_gvr_hex_derives_clone_eq_hash() {
    let hex_str = format!("0x{}", "12".repeat(32));
    let root = parse_gvr_hex(&hex_str).unwrap();
    let g1 = GvrHex::from_root(root);
    let g2 = g1.clone();
    assert_eq!(g1, g2);

    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(g1);
    set.insert(g2);
    assert_eq!(set.len(), 1);
}

// ─── eq_gvr ─────────────────────────────────────────────────────────────────

#[test]
fn test_eq_gvr_true_exact_lowercase() {
    let bytes = [0xabu8; 32];
    let hex_str = format!("0x{}", hex::encode(bytes));
    assert!(eq_gvr(&hex_str, &bytes));
}

#[test]
fn test_eq_gvr_true_mixed_case() {
    // Mixed-case hex should still match the same bytes
    let bytes = [0xabu8; 32];
    let upper = format!("0x{}", "AB".repeat(32));
    assert!(eq_gvr(&upper, &bytes));
}

#[test]
fn test_eq_gvr_false_when_bytes_differ() {
    let bytes = [0xabu8; 32];
    let other_hex = format!("0x{}", "cd".repeat(32));
    assert!(!eq_gvr(&other_hex, &bytes));
}

#[test]
fn test_eq_gvr_false_on_invalid_hex() {
    let bytes = [0xabu8; 32];
    assert!(!eq_gvr("not-hex-at-all", &bytes));
}

#[test]
fn test_eq_gvr_false_on_double_prefix() {
    let bytes = [0xabu8; 32];
    let double = format!("0x0x{}", "ab".repeat(32));
    assert!(!eq_gvr(&double, &bytes));
}

// ─── SigningRootHex ──────────────────────────────────────────────────────────

#[test]
fn test_signing_root_hex_happy_path_with_prefix() {
    let hex_str = format!("0x{}", "de".repeat(32));
    let sr = parse_signing_root_hex(&hex_str).expect("valid prefixed signing root hex");
    assert_eq!(sr.as_bytes(), &[0xdeu8; 32]);
}

#[test]
fn test_signing_root_hex_happy_path_no_prefix() {
    let hex_str = "de".repeat(32);
    let sr = parse_signing_root_hex(&hex_str).expect("valid bare signing root hex");
    assert_eq!(sr.as_bytes(), &[0xdeu8; 32]);
}

#[test]
fn test_signing_root_hex_rejects_double_prefix() {
    let hex_str = format!("0x0x{}", "de".repeat(32));
    let err = parse_signing_root_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

#[test]
fn test_signing_root_hex_rejects_odd_length() {
    let hex_str = "0xabc"; // 3 hex chars = odd
    let err = parse_signing_root_hex(hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

#[test]
fn test_signing_root_hex_rejects_non_hex_char() {
    let hex_str = format!("0x{}", "zz".repeat(32));
    let err = parse_signing_root_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

#[test]
fn test_signing_root_hex_rejects_wrong_length() {
    let hex_str = format!("0x{}", "ab".repeat(16)); // 16 bytes, not 32
    let err = parse_signing_root_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { .. }));
}

#[test]
fn test_signing_root_hex_derives_clone_eq_hash() {
    let hex_str = format!("0x{}", "56".repeat(32));
    let sr1: SigningRootHex = parse_signing_root_hex(&hex_str).unwrap();
    let sr2 = sr1.clone();
    assert_eq!(sr1, sr2);

    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(sr1);
    set.insert(sr2);
    assert_eq!(set.len(), 1);
}
