//! DVT-1 / CN-1 regression tests: cross-CN double-sign detection (Issue 2.4).
//!
//! # Why these tests FAIL on develop (v2 schema)
//!
//! The v2 schema uses `(client_cn, pubkey, slot)` / `(client_cn, pubkey, target_epoch)` as
//! uniqueness keys for slashing checks.  Two different CNs therefore operate in independent
//! namespaces, allowing cn-B to commit a conflicting signing root for the same
//! (pubkey, slot) that cn-A already signed — a cross-CN double-block-proposal.
//!
//! # What must pass after GREEN
//!
//! After the v3 migration the WHERE clauses drop `client_cn`, so the check
//! becomes `(pubkey, slot)` / `(pubkey, target_epoch)` scoped.  Cross-CN
//! conflicting-root signs for the same pubkey MUST be rejected.

use rvc_slashing::{BlockSlashingViolation, AttestationSlashingViolation, SlashingDb, SlashingError};

/// A validator pubkey shared by both CNs in all tests below.
const PUBKEY: &str =
    "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";

/// A realistic non-zero GVR (all-zero is rejected by the parser when pinned).
const GVR: &[u8; 32] = &[7u8; 32];

// ── Block: cross-CN double-proposal ──────────────────────────────────────────

/// cn-A signs (pubkey, slot=100) with root1.  cn-B then attempts (pubkey, slot=100)
/// with root2 ≠ root1.  The second attempt MUST be rejected as DoubleBlockProposal.
///
/// On develop this test FAILS because cn-B's `stage_block` returns `Ok` (the v2
/// check is restricted to `WHERE client_cn = 'cn-B'`, which finds no row).
#[test]
fn test_cross_cn_double_block_proposal_rejected() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    // cn-A commits slot 100 with root-1.
    db.stage_block("cn-A", PUBKEY, 100, Some("0xroot_1".into()), GVR)
        .expect("cn-A stage_block must succeed")
        .commit()
        .expect("cn-A commit must succeed");

    // cn-B attempts slot 100 with a DIFFERENT root — must be rejected.
    let result = db.stage_block("cn-B", PUBKEY, 100, Some("0xroot_2".into()), GVR);

    match result {
        Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
            slot,
        })) => {
            assert_eq!(slot, 100, "violation slot must match");
        }
        Err(other) => panic!("expected DoubleBlockProposal, got: {other:?}"),
        Ok(_) => panic!(
            "cn-B stage_block returned Ok — cross-CN double-block accepted (DVT-1 / CN-1 bug)"
        ),
    }
}

/// Sanity: same root from a different CN is treated as a re-sign (not a violation).
#[test]
fn test_cross_cn_same_root_is_resign_not_violation() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    db.stage_block("cn-A", PUBKEY, 200, Some("0xresign_root".into()), GVR)
        .expect("cn-A stage")
        .commit()
        .expect("cn-A commit");

    // Same root from cn-B must succeed (idempotent resign).
    db.stage_block("cn-B", PUBKEY, 200, Some("0xresign_root".into()), GVR)
        .expect("cn-B resign must not be rejected")
        .commit()
        .expect("cn-B resign commit must succeed");
}

// ── Attestation: cross-CN double-vote ────────────────────────────────────────

/// cn-A signs (pubkey, target=50) with att-root-1.  cn-B then attempts
/// (pubkey, target=50) with att-root-2 ≠ att-root-1.  Must be rejected as DoubleVote.
///
/// On develop this test FAILS because the check is CN-scoped.
#[test]
fn test_cross_cn_double_vote_rejected() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    // cn-A commits target_epoch=50 with att-root-1.
    db.stage_attestation("cn-A", PUBKEY, 40, 50, Some("0xatt_root_1".into()), GVR)
        .expect("cn-A stage_attestation must succeed")
        .commit()
        .expect("cn-A commit must succeed");

    // cn-B attempts the same target_epoch with a different root.
    let result = db.stage_attestation("cn-B", PUBKEY, 40, 50, Some("0xatt_root_2".into()), GVR);

    match result {
        Err(SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
            target_epoch,
        })) => {
            assert_eq!(target_epoch, 50, "violation target_epoch must match");
        }
        Err(other) => panic!("expected DoubleVote, got: {other:?}"),
        Ok(_) => panic!(
            "cn-B stage_attestation returned Ok — cross-CN double-vote accepted (DVT-1 / CN-1 bug)"
        ),
    }
}

/// Sanity: same root from a different CN on the same target_epoch is a re-sign.
#[test]
fn test_cross_cn_same_att_root_is_resign() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    db.stage_attestation("cn-A", PUBKEY, 60, 70, Some("0xresign_att".into()), GVR)
        .expect("cn-A stage")
        .commit()
        .expect("cn-A commit");

    db.stage_attestation("cn-B", PUBKEY, 60, 70, Some("0xresign_att".into()), GVR)
        .expect("cn-B same-root attestation resign must not be rejected")
        .commit()
        .expect("cn-B resign commit");
}
