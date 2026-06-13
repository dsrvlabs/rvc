/// Integration tests for the stage/commit ordering API (ISSUE-1.4 / A15).
///
/// These tests verify the RAII guard semantics:
/// - `discard()` rolls back so no row is committed.
/// - `commit()` persists the row; a conflicting re-stage is then rejected.
/// - Bare `drop` without calling `commit()` or `discard()` also rolls back.
/// - Symmetric behaviour for `StagedAttestation`.
/// - The existing `check_and_record_*` API still works on the same DB.
use rvc_slashing::{
    AttestationSlashingViolation, BlockSlashingViolation, SlashingDb, SlashingError,
};

const CN: &str = "test-cn";
const PUBKEY: &str = "0xdeadbeef01";
const PUBKEY2: &str = "0xdeadbeef02";
const GVR: &[u8; 32] = &[0u8; 32];

// ── StagedBlock tests ─────────────────────────────────────────────────────────

/// Stage a block, call `discard()`, and assert the row is absent in `blocks`.
#[test]
fn test_stage_block_discard_no_row_committed() {
    let db = SlashingDb::open_in_memory().expect("open");
    let staged = db.stage_block(CN, PUBKEY, 42, Some("0xroot_a".into()), GVR).expect("stage");
    staged.discard();

    // The row must NOT appear in the database.
    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert!(blocks.is_empty(), "discard must not commit any row; got: {blocks:?}");
}

/// Stage + commit a block; then attempt to stage the same (cn, pubkey, slot) with a
/// different signing root — the second stage must return `DoubleBlockProposal`.
#[test]
fn test_stage_block_commit_then_conflicting_stage_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");

    // First stage + commit.
    db.stage_block(CN, PUBKEY, 100, Some("0xroot_1".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // One row should be in the DB.
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);

    // Second stage with a different root must be rejected immediately.
    let err = db
        .stage_block(CN, PUBKEY, 100, Some("0xroot_2".into()), GVR)
        .expect_err("second stage must fail");

    match err {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(slot, 100);
        }
        other => panic!("expected DoubleBlockProposal, got: {other:?}"),
    }
}

/// Stage a block and drop the guard without calling `commit()` or `discard()`.
/// The row must not appear in the database (drop rolls back).
#[test]
fn test_stage_block_drop_without_commit_rolls_back() {
    let db = SlashingDb::open_in_memory().expect("open");

    {
        let _guard =
            db.stage_block(CN, PUBKEY, 77, Some("0xroot_drop".into()), GVR).expect("stage");
        // _guard is dropped here without calling commit() or discard()
    }

    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert!(blocks.is_empty(), "bare drop must roll back; got: {blocks:?}");
}

/// Verify that `commit()` actually persists the row.
#[test]
fn test_stage_block_commit_persists_row() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block(CN, PUBKEY, 55, Some("0xroot_persist".into()), GVR)
        .expect("stage")
        .commit()
        .expect("commit");

    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 1, "commit must persist exactly one row");
    assert_eq!(blocks[0].slot, 55);
}

// ── StagedAttestation tests ───────────────────────────────────────────────────

/// Stage an attestation, call `discard()`, and assert the row is absent.
#[test]
fn test_stage_attestation_discard_no_row_committed() {
    let db = SlashingDb::open_in_memory().expect("open");
    let staged =
        db.stage_attestation(CN, PUBKEY, 1, 5, Some("0xatt_root_a".into()), GVR).expect("stage");
    staged.discard();

    let atts = db.get_attestations(PUBKEY).expect("get");
    assert!(atts.is_empty(), "discard must not commit any row; got: {atts:?}");
}

/// Stage + commit an attestation; then attempt a double vote — second stage must return
/// `DoubleVote`.
#[test]
fn test_stage_attestation_commit_then_double_vote_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");

    // First stage + commit.
    db.stage_attestation(CN, PUBKEY, 3, 10, Some("0xatt_root_1".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // Second stage: same target_epoch (double vote) with a different root.
    let err = db
        .stage_attestation(CN, PUBKEY, 3, 10, Some("0xatt_root_2".into()), GVR)
        .expect_err("second stage must fail");

    match err {
        SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
            target_epoch,
        }) => {
            assert_eq!(target_epoch, 10);
        }
        other => panic!("expected DoubleVote, got: {other:?}"),
    }
}

/// Stage an attestation and drop without `commit()` — must roll back.
#[test]
fn test_stage_attestation_drop_without_commit_rolls_back() {
    let db = SlashingDb::open_in_memory().expect("open");

    {
        let _guard = db
            .stage_attestation(CN, PUBKEY, 2, 8, Some("0xatt_root_drop".into()), GVR)
            .expect("stage");
        // dropped without commit
    }

    let atts = db.get_attestations(PUBKEY).expect("get");
    assert!(atts.is_empty(), "bare drop must roll back; got: {atts:?}");
}

/// Stage a surrounding vote; must be rejected at stage time (before commit).
#[test]
fn test_stage_attestation_commit_then_surround_vote_rejected() {
    let db = SlashingDb::open_in_memory().expect("open");

    // Commit a narrow attestation: source=3, target=7.
    db.stage_attestation(CN, PUBKEY, 3, 7, Some("0xnarrow".into()), GVR)
        .expect("narrow stage")
        .commit()
        .expect("narrow commit");

    // Attempt a surrounding attestation: source=1, target=10 surrounds (3,7).
    let err = db
        .stage_attestation(CN, PUBKEY, 1, 10, Some("0xsurrounding".into()), GVR)
        .expect_err("surrounding vote must be rejected at stage");

    match err {
        SlashingError::SlashableAttestation(AttestationSlashingViolation::SurroundingVote {
            ..
        }) => {}
        other => panic!("expected SurroundingVote, got: {other:?}"),
    }
}

// ── Backwards-compatibility test ─────────────────────────────────────────────

/// `check_and_record_block` must still work on the same DB that has staged records.
#[test]
fn test_stage_block_keeps_existing_check_and_record_unchanged() {
    let db = SlashingDb::open_in_memory().expect("open");

    // Use check_and_record for the first block.
    db.check_and_record_block(CN, PUBKEY, 200, Some("0xcheck_root".into()), GVR)
        .expect("check_and_record_block");

    // Stage a different slot — should work fine.
    db.stage_block(CN, PUBKEY, 201, Some("0xstage_root".into()), GVR)
        .expect("stage")
        .commit()
        .expect("commit");

    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 2, "both records must be present");

    // Attempting to check_and_record at slot 200 with a different root must fail.
    let err = db
        .check_and_record_block(CN, PUBKEY, 200, Some("0xdifferent".into()), GVR)
        .expect_err("double proposal must be rejected by check_and_record");
    assert!(
        matches!(
            err,
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { .. })
        ),
        "expected DoubleBlockProposal, got: {err:?}"
    );
}

/// `check_and_record_attestation` must still work on the same DB.
#[test]
fn test_stage_attestation_keeps_existing_check_and_record_unchanged() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.check_and_record_attestation(CN, PUBKEY2, 5, 15, Some("0xatt_check".into()), GVR)
        .expect("check_and_record_attestation");

    // Stage a non-conflicting attestation.
    db.stage_attestation(CN, PUBKEY2, 16, 20, Some("0xatt_stage".into()), GVR)
        .expect("stage")
        .commit()
        .expect("commit");

    let atts = db.get_attestations(PUBKEY2).expect("get");
    assert_eq!(atts.len(), 2);

    // Attempt a double vote via check_and_record — must be rejected.
    let err = db
        .check_and_record_attestation(CN, PUBKEY2, 5, 15, Some("0xatt_conflict".into()), GVR)
        .expect_err("double vote must be rejected");
    assert!(
        matches!(
            err,
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote { .. })
        ),
        "expected DoubleVote, got: {err:?}"
    );
}

// ── v3 pubkey-scoped test ─────────────────────────────────────────────────────

/// After the v3 migration, cross-CN conflicting blocks for the same (pubkey, slot)
/// MUST be rejected (DVT-1 / CN-1 fix).  The CN is audit-only; pubkey+slot is
/// the uniqueness scope.
///
/// This test replaces the v2 "different CNs are independent" test.
/// Updated in Issue 2.4: CN-scoped independence is removed.
#[test]
fn test_stage_block_cn_scoped_different_cns_independent() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block("cn-alpha", PUBKEY, 300, Some("0xroot_alpha".into()), GVR)
        .expect("stage cn-alpha")
        .commit()
        .expect("commit cn-alpha");

    // Different CN, same (pubkey, slot) but DIFFERENT root — must be rejected in v3.
    let result = db.stage_block("cn-beta", PUBKEY, 300, Some("0xroot_beta".into()), GVR);
    assert!(
        matches!(
            result,
            Err(SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal {
                slot: 300
            }))
        ),
        "cross-CN conflicting block must be rejected in v3 pubkey-scoped schema: {result:?}"
    );

    // Same root from a different CN is a re-sign (not a violation).
    db.stage_block("cn-beta", PUBKEY, 300, Some("0xroot_alpha".into()), GVR)
        .expect("same-root re-sign from different CN must be allowed")
        .commit()
        .expect("commit cn-beta resign");

    // Only one row (the cn-alpha row); the cn-beta re-sign didn't insert a new row.
    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 1, "re-sign must not produce a duplicate row");
}

// ── Re-sign (idempotent) tests ────────────────────────────────────────────────

/// Staging the same (cn, pubkey, slot, root) twice is an idempotent re-sign.
/// The second stage+commit must succeed and must not produce a duplicate row.
#[test]
fn test_stage_block_resign_is_idempotent() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block(CN, PUBKEY, 400, Some("0xresign_root".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    // Same signing root — should be treated as an idempotent re-sign.
    db.stage_block(CN, PUBKEY, 400, Some("0xresign_root".into()), GVR)
        .expect("second stage (re-sign) should succeed")
        .commit()
        .expect("second commit");

    // Still only one row.
    let blocks = db.get_blocks(PUBKEY).expect("get");
    assert_eq!(blocks.len(), 1, "re-sign must not create a duplicate row");
}

/// Staging the same (cn, pubkey, target, root) twice is an idempotent re-sign
/// for attestations.
#[test]
fn test_stage_attestation_resign_is_idempotent() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_attestation(CN, PUBKEY, 5, 20, Some("0xresign_att".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    db.stage_attestation(CN, PUBKEY, 5, 20, Some("0xresign_att".into()), GVR)
        .expect("second stage (re-sign)")
        .commit()
        .expect("second commit");

    let atts = db.get_attestations(PUBKEY).expect("get");
    assert_eq!(atts.len(), 1, "re-sign must not create a duplicate attestation row");
}

/// Discarding (or dropping) a re-sign stage must NOT delete the existing
/// committed row.  The transaction was effectively read-only on the resign
/// path, so ROLLBACK is a data no-op — but a future refactor could break
/// this if e.g. the resign path started doing speculative writes.
#[test]
fn test_stage_block_resign_discard_keeps_existing_row() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_block(CN, PUBKEY, 500, Some("0xresign_keep".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    let before = db.get_blocks(PUBKEY).expect("get before");
    assert_eq!(before.len(), 1);

    // Same signing root — resign path.  Discard instead of commit.
    db.stage_block(CN, PUBKEY, 500, Some("0xresign_keep".into()), GVR)
        .expect("resign stage")
        .discard();

    let after = db.get_blocks(PUBKEY).expect("get after");
    assert_eq!(after.len(), 1, "resign+discard must not delete the existing row");
    assert_eq!(after[0].slot, 500);
    assert_eq!(after[0].signing_root.as_deref(), Some("0xresign_keep"));

    // Bare drop (no explicit commit/discard) on a resign must also be safe.
    {
        let _staged = db
            .stage_block(CN, PUBKEY, 500, Some("0xresign_keep".into()), GVR)
            .expect("resign stage 2");
        // _staged is dropped here without commit/discard.
    }

    let final_rows = db.get_blocks(PUBKEY).expect("get final");
    assert_eq!(final_rows.len(), 1, "resign+drop must not delete the existing row");
}

/// Same property for attestations: a duplicate stage that is discarded must
/// leave the previously committed attestation row intact.
#[test]
fn test_stage_attestation_duplicate_discard_keeps_existing_row() {
    let db = SlashingDb::open_in_memory().expect("open");

    db.stage_attestation(CN, PUBKEY, 7, 30, Some("0xdup_keep".into()), GVR)
        .expect("first stage")
        .commit()
        .expect("first commit");

    let before = db.get_attestations(PUBKEY).expect("get before");
    assert_eq!(before.len(), 1);

    db.stage_attestation(CN, PUBKEY, 7, 30, Some("0xdup_keep".into()), GVR)
        .expect("duplicate stage")
        .discard();

    let after = db.get_attestations(PUBKEY).expect("get after");
    assert_eq!(after.len(), 1, "duplicate+discard must not delete the existing attestation");
    assert_eq!(after[0].source_epoch, 7);
    assert_eq!(after[0].target_epoch, 30);
}
