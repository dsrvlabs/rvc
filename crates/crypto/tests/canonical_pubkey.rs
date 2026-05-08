// RED test for ISSUE-CQ-2.4 (C1).
//
//! Cross-crate integration tests for [`rvc_crypto::pubkey::CanonicalPubkey`].
//!
//! This file is the publicly-facing test fixture that confirms the helper
//! collapses every input representation into the single canonical form:
//! **`0x`-prefixed lowercase hex**.
//!
//! At least six distinct input shapes are exercised so that both the `slashing`
//! and `orchestrator` crates can rely on the same normalisation contract without
//! independent re-implementation.

use rvc_crypto::pubkey::CanonicalPubkey;

// ── helpers ───────────────────────────────────────────────────────────────────

fn parse(s: &str) -> CanonicalPubkey {
    s.parse().expect("CanonicalPubkey::from_str is infallible")
}

/// Assert `input` collapses to `expected` canonical string.
fn assert_canonical(input: &str, expected: &str) {
    let got = parse(input).to_string();
    assert_eq!(got, expected, "input={input:?} → got={got:?}, want={expected:?}");
}

// ── shape 1: already canonical (0x + lowercase) ───────────────────────────────

#[test]
fn test_canonical_prefixed_lowercase_unchanged() {
    assert_canonical("0xabcdef0123456789", "0xabcdef0123456789");
}

// ── shape 2: 0x-prefixed, uppercase hex digits ───────────────────────────────

#[test]
fn test_canonical_prefixed_uppercase_lowercased() {
    assert_canonical("0xABCDEF0123456789", "0xabcdef0123456789");
}

// ── shape 3: bare lowercase (no prefix) ──────────────────────────────────────

#[test]
fn test_canonical_bare_lowercase_gets_prefix() {
    assert_canonical("abcdef0123456789", "0xabcdef0123456789");
}

// ── shape 4: bare uppercase (no prefix) ──────────────────────────────────────

#[test]
fn test_canonical_bare_uppercase_lowercased_and_prefixed() {
    assert_canonical("ABCDEF0123456789", "0xabcdef0123456789");
}

// ── shape 5: uppercase 0X prefix ─────────────────────────────────────────────

#[test]
fn test_canonical_uppercase_0x_prefix() {
    assert_canonical("0XABCDEF0123456789", "0xabcdef0123456789");
}

// ── shape 6: mixed-case hex digits with 0x prefix ────────────────────────────

#[test]
fn test_canonical_prefixed_mixed_case_lowercased() {
    assert_canonical("0xAbCdEf0123456789", "0xabcdef0123456789");
}

// ── shape 7: mixed-case hex digits with 0X prefix ────────────────────────────

#[test]
fn test_canonical_uppercase_prefix_mixed_case() {
    assert_canonical("0XaBcDeF0123456789", "0xabcdef0123456789");
}

// ── shape 8: bare mixed-case (no prefix) ─────────────────────────────────────

#[test]
fn test_canonical_bare_mixed_case_lowercased_and_prefixed() {
    assert_canonical("DeAdBeEf01234567", "0xdeadbeef01234567");
}

// ── parity: all representations of the same key are equal ────────────────────

#[test]
fn test_canonical_all_forms_equal() {
    let hex = "deadbeef0123456789abcdef01234567deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567deadbeef0102";
    let forms = [
        format!("0x{hex}"),
        format!("0X{hex}"),
        hex.to_uppercase(),
        format!("0x{}", hex.to_uppercase()),
        hex.to_string(),
    ];
    let canonical: Vec<CanonicalPubkey> = forms.iter().map(|s| parse(s)).collect();
    let expected = format!("0x{hex}");
    for (i, c) in canonical.iter().enumerate() {
        assert_eq!(
            c.to_string(),
            expected,
            "form[{i}] = {:?} did not canonicalise to {expected:?}",
            forms[i]
        );
    }
}

// ── full BLS-length key (96 hex chars = 48 bytes) ────────────────────────────

const BLS_LOWER: &str =
    "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";
const BLS_UPPER: &str =
    "0xA491D1B0ECD9BB917989F0E74F0DEA0422EAC4A873E5E2644F368DFFB9A6E20FD6E10C1B77654D067C0618F6E5A7F79A";
const BLS_BARE: &str =
    "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a";

#[test]
fn test_canonical_full_bls_prefixed_lowercase() {
    assert_canonical(BLS_LOWER, BLS_LOWER);
}

#[test]
fn test_canonical_full_bls_prefixed_uppercase() {
    assert_canonical(BLS_UPPER, BLS_LOWER);
}

#[test]
fn test_canonical_full_bls_bare() {
    assert_canonical(BLS_BARE, BLS_LOWER);
}

// ── idempotence: applying twice must equal applying once ─────────────────────

#[test]
fn test_canonical_idempotent() {
    let inputs = ["0xABCDEF", "0Xabcdef", "ABCDEF", "abcdef", "0xAbCdEf"];
    for input in inputs {
        let once = parse(input).to_string();
        let twice = parse(&once).to_string();
        assert_eq!(once, twice, "idempotence failed for input={input:?}");
    }
}

// ── Display and AsRef round-trip ─────────────────────────────────────────────

#[test]
fn test_canonical_display_matches_as_ref() {
    let pk = parse("0xDeAdBeEf");
    assert_eq!(pk.to_string(), pk.as_ref());
}
