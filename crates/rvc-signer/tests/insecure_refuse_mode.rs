//! Regression test for ISSUE-3.13: `InsecureMode::Refuse` is the GA default.
//!
//! Per NFR-10, at the Mainnet GA tag (Phase 3 ISSUE-3.13) the default insecure
//! mode flips from `Warn` (Phase 2) to `Refuse`.  This file pins that contract.

use crypto::InsecureMode;

/// GA regression guard: `InsecureMode::default()` must return `Refuse`.
///
/// If this test breaks, the GA gate has been accidentally rolled back to Warn,
/// which would allow insecure connections without explicit operator opt-in.
#[test]
fn test_default_mode_refuses() {
    assert_eq!(
        InsecureMode::default(),
        InsecureMode::Refuse,
        "InsecureMode default must be Refuse at GA (ISSUE-3.13 / NFR-10)"
    );
}
