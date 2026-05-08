// RED test for ISSUE-CQ-2.4 (C1).
//
//! Cross-crate pubkey-normalization parity tests.
//!
//! ## Purpose
//!
//! CQ-2.3 (RED phase): This file pins the *divergence* between the two
//! `normalize_pubkey` implementations that existed before CQ-2.4:
//!
//! - **Slashing style** (`crates/slashing/src/db.rs` pre-fix): returns
//!   `0x`-prefixed lowercase.
//! - **Orchestrator style** (`crates/rvc/src/orchestrator/utils.rs` pre-fix):
//!   returns *bare* lowercase (no `0x` prefix).
//!
//! Both functions are `pub(crate)` and cannot be imported here directly.
//! Instead, their pre-fix logic is inlined as reference implementations so the
//! test is self-contained.  The divergence test asserts that the two styles
//! produce *different* strings for the same input — this proves the bug is real
//! and pins it for reviewers.
//!
//! CQ-2.4 (GREEN phase): The divergence test is replaced with a parity test
//! asserting that `crypto::CanonicalPubkey` (the single source of truth both
//! crates now delegate to) produces the expected `0x`-prefixed lowercase form
//! for every input.  After CQ-2.4 this file stays GREEN forever.

use crypto::pubkey::CanonicalPubkey;

// ── reference implementations (inlined from pre-fix source) ──────────────────

/// Pre-fix `slashing::db::normalize_pubkey` logic.
/// Returns `0x`-prefixed lowercase.
fn slashing_normalize_pre_fix(pubkey: &str) -> String {
    let stripped = pubkey.strip_prefix("0x").unwrap_or(pubkey);
    format!("0x{}", stripped.to_lowercase())
}

/// Pre-fix `orchestrator::utils::normalize_pubkey` logic.
/// Returns *bare* lowercase — the C1 bug.
fn orchestrator_normalize_pre_fix(pubkey: &str) -> String {
    let without_prefix =
        pubkey.strip_prefix("0x").or_else(|| pubkey.strip_prefix("0X")).unwrap_or(pubkey);
    without_prefix.to_lowercase()
}

// ── parametrised test inputs ──────────────────────────────────────────────────

const CASES: &[&str] = &[
    "0xABCDEF0123456789",
    "0Xabcdef0123456789",
    "ABCDEF0123456789",
    "abcdef0123456789",
    "0xAbCdEf0123456789",
    "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
    "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
    "0xDEADBEEF",
    "deadbeef",
];

// ── CQ-2.3 divergence proof (pre-fix) ────────────────────────────────────────
//
// These tests prove that the two pre-fix implementations diverge: the
// orchestrator-style output lacks the `0x` prefix that the slashing-style
// output carries.  They pass on develop HEAD before CQ-2.4 lands.

#[test]
fn test_pre_fix_divergence_proof() {
    for &input in CASES {
        let slashing_out = slashing_normalize_pre_fix(input);
        let orchestrator_out = orchestrator_normalize_pre_fix(input);

        assert_ne!(
            slashing_out, orchestrator_out,
            "expected divergence for input={input:?}: \
             slashing={slashing_out:?} orchestrator={orchestrator_out:?} \
             — if this fails the pre-fix logic changed unexpectedly"
        );

        // Slashing form must be 0x-prefixed.
        assert!(
            slashing_out.starts_with("0x"),
            "slashing pre-fix output must start with '0x': {slashing_out:?}"
        );

        // Orchestrator form must NOT be 0x-prefixed (bare — this is the bug).
        assert!(
            !orchestrator_out.starts_with("0x"),
            "orchestrator pre-fix output must be bare (no '0x'): {orchestrator_out:?}"
        );
    }
}

// ── CQ-2.4 parity via CanonicalPubkey (post-fix) ─────────────────────────────
//
// After CQ-2.4 both `normalize_pubkey` functions delegate to
// `CanonicalPubkey`.  These tests assert the canonical form is `0x`-prefixed
// lowercase and that every input collapses to the same value regardless of the
// normalisation path.  They are GREEN on develop after CQ-2.4 lands and serve
// as the permanent regression guard.

#[test]
fn test_canonical_pubkey_produces_0x_prefixed_lowercase() {
    for &input in CASES {
        let canonical = input.parse::<CanonicalPubkey>().unwrap().to_string();
        assert!(
            canonical.starts_with("0x"),
            "CanonicalPubkey output must start with '0x': input={input:?} got={canonical:?}"
        );
        // All hex characters after the prefix must be lowercase.
        let hex_part = &canonical[2..];
        assert_eq!(
            hex_part,
            hex_part.to_lowercase(),
            "hex digits must be lowercase: input={input:?} got={canonical:?}"
        );
    }
}

#[test]
fn test_canonical_pubkey_matches_slashing_pre_fix_for_prefixed_inputs() {
    // For inputs that already carry a `0x` prefix, the slashing pre-fix logic
    // and CanonicalPubkey should agree (both output 0x + lowercase).
    let prefixed_cases: &[&str] = &[
        "0xABCDEF0123456789",
        "0xAbCdEf0123456789",
        "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        "0xDEADBEEF",
    ];
    for &input in prefixed_cases {
        let slashing_out = slashing_normalize_pre_fix(input);
        let canonical_out = input.parse::<CanonicalPubkey>().unwrap().to_string();
        assert_eq!(
            slashing_out, canonical_out,
            "slashing pre-fix and CanonicalPubkey must agree for prefixed input={input:?}"
        );
    }
}

#[test]
fn test_canonical_equals_expected_0x_prefixed_lower() {
    let cases: &[(&str, &str)] = &[
        ("0xABCDEF0123456789", "0xabcdef0123456789"),
        ("0Xabcdef0123456789", "0xabcdef0123456789"),
        ("ABCDEF0123456789", "0xabcdef0123456789"),
        ("abcdef0123456789", "0xabcdef0123456789"),
        ("0xAbCdEf0123456789", "0xabcdef0123456789"),
        (
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        ),
        (
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        ),
        ("0xDEADBEEF", "0xdeadbeef"),
        ("deadbeef", "0xdeadbeef"),
    ];
    for &(input, expected) in cases {
        let got = input.parse::<CanonicalPubkey>().unwrap().to_string();
        assert_eq!(got, expected, "input={input:?}");
    }
}
