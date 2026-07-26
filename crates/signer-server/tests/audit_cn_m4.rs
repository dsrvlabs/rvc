//! Regression tests for M-4 (ISSUE-3.4): x509-parser-based CN extraction.
//!
//! # What M-4 fixes
//!
//! The legacy hand-rolled DER scanner returned the **last** CN OID match.
//! A crafted certificate with `Subject: CN=peer-A, CN=admin` would be logged
//! as `admin` — allowing a client to spoof the audit-log CN.
//!
//! The new `x509-parser`-based implementation returns the **first** CN match
//! per RDN rules, which is the standard-compliant behaviour.

use rvc_test_support::{
    self_signed_der_with_cn, self_signed_der_with_two_cns, self_signed_der_without_cn,
};
use signer_server::audit::cn::extract_cn_from_der;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a self-signed certificate whose Subject contains exactly one CN entry.
fn cert_with_single_cn(cn: &str) -> Vec<u8> {
    self_signed_der_with_cn(cn)
}

/// Build a self-signed certificate whose Subject contains **two** CN entries:
/// the first is `first_cn` and the second is `second_cn`.
///
/// See `rvc_test_support::self_signed_der_with_two_cns` for the CustomDnType
/// workaround (rcgen IndexMap would otherwise collapse two CommonName pushes).
fn cert_with_two_cns(first_cn: &str, second_cn: &str) -> Vec<u8> {
    self_signed_der_with_two_cns(first_cn, second_cn)
}

/// Build a self-signed certificate with no CN in the Subject.
fn cert_with_no_cn() -> Vec<u8> {
    self_signed_der_without_cn()
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// M-4: A certificate carrying two CN RDN entries must return the **first**
/// one.  Before the fix the hand-rolled scanner returned the last one.
#[test]
fn test_first_cn_returned_per_rdn() {
    let der = cert_with_two_cns("peer-A", "admin");
    let cn = extract_cn_from_der(&der);
    assert_eq!(cn.as_deref(), Some("peer-A"), "expected first CN 'peer-A', got {:?}", cn);
}

/// M-4: When the Subject contains no CN OID the function must return `None`
/// (callers map `None` to the documented default `"unknown"`).
#[test]
fn test_no_cn_returns_none() {
    let der = cert_with_no_cn();
    let cn = extract_cn_from_der(&der);
    assert_eq!(cn, None, "expected None for cert without CN, got {:?}", cn);
}

/// Regression: a normal single-CN certificate continues to work after the
/// rewrite.
#[test]
fn test_single_cn_still_works() {
    let der = cert_with_single_cn("my-validator-client");
    let cn = extract_cn_from_der(&der);
    assert_eq!(cn.as_deref(), Some("my-validator-client"));
}

/// Edge case: empty DER bytes must not panic and must return `None`.
#[test]
fn test_empty_der_returns_none() {
    assert_eq!(extract_cn_from_der(&[]), None);
}

/// Edge case: garbage bytes must not panic and must return `None`.
#[test]
fn test_garbage_der_returns_none() {
    assert_eq!(extract_cn_from_der(&[0xFFu8; 64]), None);
}
