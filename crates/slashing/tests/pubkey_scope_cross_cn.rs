//! DVT-1 / CN-1 regression tests: pubkey-scoped double-sign detection (Issue 2.4 / 2.5).
//!
//! After Issue 2.5 the `stage_block` / `stage_attestation` signatures no longer accept
//! a `client_cn` parameter — the CN is audit-only and flows through `audit_log` inside
//! `PubkeyScopedDb`.  The test scenario that previously used two different CNs ("cn-A"
//! and "cn-B") collapses to: two stage calls for the same pubkey/slot with different
//! roots.  The second call must be rejected, proving pubkey-scoped enforcement.
//!
//! # What these tests prove
//!
//! - Cross-CN double-block: the first stage commits root-1; the second stage
//!   (which would have been from a different CN) attempts root-2 and is rejected.
//! - Cross-CN re-sign: same root on a second call → idempotent resign (not a violation).
//! - Cross-CN double-vote: same structure for attestations.

use rvc_slashing::{
    AttestationSlashingViolation, BlockSlashingViolation, SlashingDb, SlashingError,
};

/// A validator pubkey used in all tests below.
const PUBKEY: &str =
    "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";

/// A realistic non-zero GVR (all-zero is rejected by the parser when pinned).
const GVR: &[u8; 32] = &[7u8; 32];

// ── Block: pubkey-scoped double-proposal ─────────────────────────────────────

/// First call commits (pubkey, slot=100) with root-1.  A second call for the same
/// (pubkey, slot=100) with root-2 ≠ root-1 MUST be rejected as DoubleBlockProposal.
///
/// This replaces the cross-CN scenario from Issue 2.4: because `stage_block` no longer
/// accepts a CN, "two different CNs" is expressed as "two stage calls with different
/// roots."  The uniqueness scope is now purely pubkey+slot, which is what the test verifies.
#[test]
fn test_cross_cn_double_block_proposal_rejected() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    // First call commits slot 100 with root-1.
    db.stage_block(PUBKEY, 100, Some("0xroot_1".into()), GVR)
        .expect("first stage_block must succeed")
        .commit()
        .expect("first commit must succeed");

    // Second call — same slot, different root — must be rejected.
    let result = db.stage_block(PUBKEY, 100, Some("0xroot_2".into()), GVR);

    match result {
        Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
            slot,
        })) => {
            assert_eq!(slot, 100, "violation slot must match");
        }
        Err(other) => panic!("expected DoubleBlockProposal, got: {other:?}"),
        Ok(_) => panic!(
            "second stage_block returned Ok — pubkey-scoped double-block accepted (DVT-1 / CN-1 bug)"
        ),
    }
}

/// Same root on a second call is treated as a re-sign (not a violation).
#[test]
fn test_cross_cn_same_root_is_resign_not_violation() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    db.stage_block(PUBKEY, 200, Some("0xresign_root".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // Same root — idempotent resign, must not be rejected.
    db.stage_block(PUBKEY, 200, Some("0xresign_root".into()), GVR)
        .expect("same-root re-sign must not be rejected")
        .commit()
        .expect("re-sign commit must succeed");
}

// ── Attestation: pubkey-scoped double-vote ───────────────────────────────────

/// First call commits (pubkey, target=50) with att-root-1.  A second call for the same
/// (pubkey, target=50) with att-root-2 ≠ att-root-1 MUST be rejected as DoubleVote.
#[test]
fn test_cross_cn_double_vote_rejected() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    // First call commits target_epoch=50 with att-root-1.
    db.stage_attestation(PUBKEY, 40, 50, Some("0xatt_root_1".into()), GVR)
        .expect("first stage_attestation must succeed")
        .commit()
        .expect("first commit must succeed");

    // Second call — same target, different root — must be rejected.
    let result = db.stage_attestation(PUBKEY, 40, 50, Some("0xatt_root_2".into()), GVR);

    match result {
        Err(SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
            target_epoch,
        })) => {
            assert_eq!(target_epoch, 50, "violation target_epoch must match");
        }
        Err(other) => panic!("expected DoubleVote, got: {other:?}"),
        Ok(_) => panic!(
            "second stage_attestation returned Ok — pubkey-scoped double-vote accepted (DVT-1 / CN-1 bug)"
        ),
    }
}

/// Same root on a second attestation call is a re-sign (not a violation).
#[test]
fn test_cross_cn_same_att_root_is_resign() {
    let db = SlashingDb::open_in_memory().expect("open in-memory db");

    db.stage_attestation(PUBKEY, 60, 70, Some("0xresign_att".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    db.stage_attestation(PUBKEY, 60, 70, Some("0xresign_att".into()), GVR)
        .expect("same-root attestation re-sign must not be rejected")
        .commit()
        .expect("re-sign commit");
}
