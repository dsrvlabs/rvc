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
    // "0x0x…" is the canonical double-prefix case.
    let hex_str = format!("0x0x{}", "ab".repeat(48));
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// "0x0X…" (mixed-case second prefix) must also be DoublePrefix.
#[test]
fn test_pubkey_hex_rejects_double_prefix_mixed_second_0x_upper() {
    let hex_str = format!("0x0X{}", "ab".repeat(48));
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// RF3-13: outer "0X" is a recognised prefix; "0X0x…" is DoublePrefix.
#[test]
fn test_pubkey_hex_outer_upper_x_double_prefix_rejected() {
    let hex_str = format!("0X0x{}", "ab".repeat(48));
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// RF3-13: "0X0X…" → DoublePrefix.
#[test]
fn test_pubkey_hex_both_upper_x_prefixes_rejected() {
    let hex_str = format!("0X0X{}", "ab".repeat(48));
    let err = parse_pubkey_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// Item 2: true bare unprefixed odd-length hex → InvalidHex.
#[test]
fn test_pubkey_hex_rejects_bare_odd_length() {
    // "abc" has 3 chars — odd, no prefix at all
    let err = parse_pubkey_hex("abc").unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

// Item 2 (fixed comment): prefixed odd-length hex → InvalidHex.
#[test]
fn test_pubkey_hex_rejects_prefixed_odd_length() {
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

// Item 3: empty string → InvalidLength { got: 0 }.
#[test]
fn test_pubkey_hex_rejects_empty_string() {
    let err = parse_pubkey_hex("").unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { got: 0, .. }));
}

// Item 3: lone "0x" → InvalidLength { got: 0 }.
#[test]
fn test_pubkey_hex_rejects_lone_0x() {
    let err = parse_pubkey_hex("0x").unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { got: 0, .. }));
}

// RF3-13: uppercase-X single prefix "0X…" is accepted (widened strip_prefix).
#[test]
fn test_canonical_accepts_uppercase_0x_prefix() {
    let hex_str = format!("0X{}", "ab".repeat(48));
    let pk = parse_pubkey_hex(&hex_str).expect("0X-prefixed pubkey must parse");
    assert_eq!(pk.as_bytes(), &[0xabu8; 48]);
}

// RF3-13: all doubled-prefix case combinations rejected.
#[test]
fn test_double_prefix_still_rejected_both_cases() {
    for prefix in ["0x0x", "0x0X", "0X0x", "0X0X"] {
        let hex_str = format!("{prefix}{}", "ab".repeat(48));
        let err = parse_pubkey_hex(&hex_str).unwrap_err();
        assert!(
            matches!(err, ParseError::DoublePrefix),
            "expected DoublePrefix for {prefix}…, got {err:?}"
        );
    }
}

// RF3-13: error messages never echo the raw offending character.
#[test]
fn test_error_messages_contain_no_raw_input_characters() {
    let err = parse_pubkey_hex(&format!("0x{}", "zz".repeat(48))).unwrap_err();
    let msg = err.to_string();
    assert!(!msg.contains('z'), "error must not echo raw non-hex char: {msg}");
    assert!(matches!(err, ParseError::InvalidHex(_)));
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

// "0x0X…" must also be DoublePrefix.
#[test]
fn test_gvr_hex_rejects_double_prefix_mixed_second_0x_upper() {
    let hex_str = format!("0x0X{}", "cd".repeat(32));
    let err = parse_gvr_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// RF3-13: outer "0X" is recognised; "0X0x…" is DoublePrefix.
#[test]
fn test_gvr_hex_outer_upper_x_double_prefix_rejected() {
    let hex_str = format!("0X0x{}", "cd".repeat(32));
    let err = parse_gvr_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// RF3-13: "0X0X…" → DoublePrefix.
#[test]
fn test_gvr_hex_both_upper_x_prefixes_rejected() {
    let hex_str = format!("0X0X{}", "cd".repeat(32));
    let err = parse_gvr_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// Item 2 (fixed comment): prefixed odd-length hex → InvalidHex.
#[test]
fn test_gvr_hex_rejects_prefixed_odd_length() {
    let hex_str = "0xabc"; // 3 hex chars = odd, with 0x prefix
    let err = parse_gvr_hex(hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

// Item 2: true bare unprefixed odd-length hex → InvalidHex.
#[test]
fn test_gvr_hex_rejects_bare_odd_length() {
    let err = parse_gvr_hex("abc").unwrap_err();
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

// Item 3: empty string → InvalidLength { got: 0 }.
#[test]
fn test_gvr_hex_rejects_empty_string() {
    let err = parse_gvr_hex("").unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { got: 0, .. }));
}

// Item 3: lone "0x" → InvalidLength { got: 0 }.
#[test]
fn test_gvr_hex_rejects_lone_0x() {
    let err = parse_gvr_hex("0x").unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { got: 0, .. }));
}

// RF3-13: uppercase-X single prefix "0X…" is accepted.
#[test]
fn test_gvr_hex_accepts_uppercase_0x_prefix() {
    let hex_str = format!("0X{}", "cd".repeat(32));
    let root = parse_gvr_hex(&hex_str).expect("0X-prefixed GVR must parse");
    assert_eq!(root, [0xcdu8; 32]);
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

// Item 3: eq_gvr("", …) → false (parse fails with InvalidLength, not a match).
#[test]
fn test_eq_gvr_false_on_empty_string() {
    assert!(!eq_gvr("", &[0u8; 32]));
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

// "0x0X…" must also be DoublePrefix.
#[test]
fn test_signing_root_hex_rejects_double_prefix_mixed_second_0x_upper() {
    let hex_str = format!("0x0X{}", "de".repeat(32));
    let err = parse_signing_root_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// RF3-13: outer "0X" is recognised; "0X0x…" is DoublePrefix.
#[test]
fn test_signing_root_hex_outer_upper_x_double_prefix_rejected() {
    let hex_str = format!("0X0x{}", "de".repeat(32));
    let err = parse_signing_root_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// RF3-13: "0X0X…" → DoublePrefix.
#[test]
fn test_signing_root_hex_both_upper_x_prefixes_rejected() {
    let hex_str = format!("0X0X{}", "de".repeat(32));
    let err = parse_signing_root_hex(&hex_str).unwrap_err();
    assert!(matches!(err, ParseError::DoublePrefix));
}

// Item 2 (fixed comment): prefixed odd-length hex → InvalidHex.
#[test]
fn test_signing_root_hex_rejects_prefixed_odd_length() {
    let hex_str = "0xabc"; // 3 hex chars = odd, with 0x prefix
    let err = parse_signing_root_hex(hex_str).unwrap_err();
    assert!(matches!(err, ParseError::InvalidHex(_)));
}

// Item 2: true bare unprefixed odd-length hex → InvalidHex.
#[test]
fn test_signing_root_hex_rejects_bare_odd_length() {
    let err = parse_signing_root_hex("abc").unwrap_err();
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

// Item 3: empty string → InvalidLength { got: 0 }.
#[test]
fn test_signing_root_hex_rejects_empty_string() {
    let err = parse_signing_root_hex("").unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { got: 0, .. }));
}

// Item 3: lone "0x" → InvalidLength { got: 0 }.
#[test]
fn test_signing_root_hex_rejects_lone_0x() {
    let err = parse_signing_root_hex("0x").unwrap_err();
    assert!(matches!(err, ParseError::InvalidLength { got: 0, .. }));
}

// RF3-13: uppercase-X single prefix "0X…" is accepted.
#[test]
fn test_signing_root_hex_accepts_uppercase_0x_prefix() {
    let hex_str = format!("0X{}", "de".repeat(32));
    let sr = parse_signing_root_hex(&hex_str).expect("0X-prefixed signing root must parse");
    assert_eq!(sr.as_bytes(), &[0xdeu8; 32]);
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
