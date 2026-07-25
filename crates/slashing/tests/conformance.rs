//! EIP-3076 conformance tests.
//!
//! Integrates all 38 test cases from the official
//! `eth-clients/slashing-protection-interchange-tests` repository.
//!
//! # Runner → strategy mapping
//!
//! - **`complete`** — full-history EIP-3076 strategy. Interchange is imported into
//!   the history tables via [`SlashingDb::import`]; every block/attestation verdict
//!   comes from the production `stage_* → commit()/discard()` path.
//! - **`minimal_conservative`** — watermark (minified) EIP-3076 strategy. Interchange
//!   maxima are projected onto the real `set_block_watermark` /
//!   `set_attestation_watermark` API (harness-side projection only); every verdict
//!   comes from the same production `stage_* → commit()/discard()` path. After a
//!   successful stage commit the harness raises the corresponding watermark so later
//!   steps see the post-sign high-water mark (production signing does not yet auto-
//!   raise watermarks — that remains history-table driven on the complete path).
//!
//! Both runners therefore certify the **production decision path**. They still diverge
//! on strategy-sensitive fixtures (`*_iff_minified`, `*_fail_iff_imported`, resign /
//! gap cases, etc.) because the *import* side differs (full history vs watermark
//! maxima).
//!
//! # B5 handoff (Phase 2)
//!
//! Moving the interchange → watermark *projection* from this harness into production
//! import code is Phase 2 issue **B5** ("Interchange import sets watermarks from
//! interchange maxima"). RF1-04 deliberately leaves projection in the test so B5 has
//! a single, explicit place to absorb it.

use serde::Deserialize;

use rvc_slashing::{InterchangeFormat, SlashingDb, SlashingError};

/// Zero GVR used by signing-path checks in the complete runner (matches the
/// historical `check_and_record_*` harness; import pins the test-case GVR).
const SIGN_GVR: &[u8; 32] = &[0u8; 32];

// ---------------------------------------------------------------------------
// Stage-path harness helpers (RF1-03)
// ---------------------------------------------------------------------------

/// Stage a block via the production path and commit on success.
///
/// On rejection, `stage_block` rolls back before returning `Err` (no guard is
/// handed out). On accept, the guard is committed so the row is durable for
/// subsequent checks in the same runner.
fn stage_and_commit_block(
    db: &SlashingDb,
    pubkey: &str,
    slot: u64,
    signing_root: Option<String>,
    gvr: &[u8; 32],
) -> Result<(), SlashingError> {
    let staged = db.stage_block(pubkey, slot, signing_root, gvr)?;
    staged.commit()
}

/// Stage an attestation via the production path and commit on success.
///
/// See [`stage_and_commit_block`] for success/rejection semantics.
fn stage_and_commit_attestation(
    db: &SlashingDb,
    pubkey: &str,
    source_epoch: u64,
    target_epoch: u64,
    signing_root: Option<String>,
    gvr: &[u8; 32],
) -> Result<(), SlashingError> {
    let staged = db.stage_attestation(pubkey, source_epoch, target_epoch, signing_root, gvr)?;
    staged.commit()
}

// ---------------------------------------------------------------------------
// Test fixture types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TestCase {
    name: String,
    genesis_validators_root: String,
    steps: Vec<TestStep>,
}

#[derive(Debug, Deserialize)]
struct TestStep {
    should_succeed: bool,
    contains_slashable_data: bool,
    interchange: InterchangeFormat,
    blocks: Vec<TestBlock>,
    attestations: Vec<TestAttestation>,
}

#[derive(Debug, Deserialize)]
struct TestBlock {
    pubkey: String,
    slot: String,
    signing_root: Option<String>,
    should_succeed: bool,
    should_succeed_complete: bool,
}

#[derive(Debug, Deserialize)]
struct TestAttestation {
    pubkey: String,
    source_epoch: String,
    target_epoch: String,
    signing_root: Option<String>,
    should_succeed: bool,
    should_succeed_complete: bool,
}

// ---------------------------------------------------------------------------
// Test loaders
// ---------------------------------------------------------------------------

fn load_test_case(name: &str) -> TestCase {
    let path = format!("{}/tests/conformance/{}.json", env!("CARGO_MANIFEST_DIR"), name);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read test file {path}: {e}"));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse test file {path}: {e}"))
}

// ---------------------------------------------------------------------------
// Complete strategy runner (production stage_* → commit/discard path)
// ---------------------------------------------------------------------------

fn run_complete(test: &TestCase) {
    let db = SlashingDb::open_in_memory().expect("failed to open db");
    let gvr = &test.genesis_validators_root;

    for (step_idx, step) in test.steps.iter().enumerate() {
        let import_result = db.import(&step.interchange, gvr);

        if !step.should_succeed {
            if !step.contains_slashable_data {
                // Must fail (e.g. GVR mismatch)
                assert!(
                    import_result.is_err(),
                    "[complete] {}: step {step_idx}: import should have failed",
                    test.name
                );
                continue;
            }
            // Contains slashable data — implementation MAY accept or reject.
            // Our implementation accepts (INSERT OR IGNORE), so we continue
            // with signing checks regardless.
            if import_result.is_err() {
                continue;
            }
        } else {
            assert!(
                import_result.is_ok(),
                "[complete] {}: step {step_idx}: import should have succeeded but got: {:?}",
                test.name,
                import_result.err()
            );
        }

        // Run block checks via production stage path
        for (i, block) in step.blocks.iter().enumerate() {
            let slot: u64 = block.slot.parse().unwrap();
            let result = stage_and_commit_block(
                &db,
                &block.pubkey,
                slot,
                block.signing_root.clone(),
                SIGN_GVR,
            );

            if block.should_succeed_complete {
                assert!(
                    result.is_ok(),
                    "[complete] {}: step {step_idx}, block {i} (slot={slot}): \
                     expected success but got: {:?}",
                    test.name,
                    result.err()
                );
            } else {
                assert!(
                    result.is_err(),
                    "[complete] {}: step {step_idx}, block {i} (slot={slot}): \
                     expected failure but succeeded",
                    test.name
                );
            }
        }

        // Run attestation checks via production stage path
        for (i, att) in step.attestations.iter().enumerate() {
            let source: u64 = att.source_epoch.parse().unwrap();
            let target: u64 = att.target_epoch.parse().unwrap();
            let result = stage_and_commit_attestation(
                &db,
                &att.pubkey,
                source,
                target,
                att.signing_root.clone(),
                SIGN_GVR,
            );

            if att.should_succeed_complete {
                assert!(
                    result.is_ok(),
                    "[complete] {}: step {step_idx}, attestation {i} \
                     (src={source}, tgt={target}): expected success but got: {:?}",
                    test.name,
                    result.err()
                );
            } else {
                assert!(
                    result.is_err(),
                    "[complete] {}: step {step_idx}, attestation {i} \
                     (src={source}, tgt={target}): expected failure but succeeded",
                    test.name
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal / watermark strategy: project interchange maxima, decide via stage_*
// ---------------------------------------------------------------------------

/// Project interchange block/attestation maxima onto real watermark storage.
///
/// Harness-only until Phase 2 B5 moves this into production import.
fn project_interchange_maxima_to_watermarks(db: &SlashingDb, interchange: &InterchangeFormat) {
    for validator in &interchange.data {
        let max_slot = validator.signed_blocks.iter().map(|b| b.slot.parse::<u64>().unwrap()).max();
        if let Some(slot) = max_slot {
            let current = db.get_block_watermark(&validator.pubkey).unwrap().unwrap_or(0);
            db.set_block_watermark(&validator.pubkey, slot.max(current)).unwrap();
        }

        let max_source = validator
            .signed_attestations
            .iter()
            .map(|a| a.source_epoch.parse::<u64>().unwrap())
            .max();
        let max_target = validator
            .signed_attestations
            .iter()
            .map(|a| a.target_epoch.parse::<u64>().unwrap())
            .max();
        if let (Some(source), Some(target)) = (max_source, max_target) {
            let (cur_source, cur_target) =
                db.get_attestation_watermark(&validator.pubkey).unwrap().unwrap_or((0, 0));
            db.set_attestation_watermark(
                &validator.pubkey,
                source.max(cur_source),
                target.max(cur_target),
            )
            .unwrap();
        }
    }
}

/// Raise block watermark after a successful stage commit (min strategy high-water).
fn raise_block_watermark_after_sign(db: &SlashingDb, pubkey: &str, slot: u64) {
    let current = db.get_block_watermark(pubkey).unwrap().unwrap_or(0);
    db.set_block_watermark(pubkey, slot.max(current)).unwrap();
}

/// Raise attestation watermarks after a successful stage commit.
fn raise_attestation_watermark_after_sign(db: &SlashingDb, pubkey: &str, source: u64, target: u64) {
    let (cur_source, cur_target) = db.get_attestation_watermark(pubkey).unwrap().unwrap_or((0, 0));
    db.set_attestation_watermark(pubkey, source.max(cur_source), target.max(cur_target)).unwrap();
}

fn run_minimal_conservative(test: &TestCase) {
    let db = SlashingDb::open_in_memory().expect("failed to open db");
    let gvr = &test.genesis_validators_root;

    for (step_idx, step) in test.steps.iter().enumerate() {
        // GVR mismatch: min strategy does not call import; reject at the harness.
        if step.interchange.metadata.genesis_validators_root != *gvr {
            assert!(
                !step.should_succeed,
                "[minimal] {}: step {step_idx}: GVR mismatch but should_succeed is true",
                test.name
            );
            continue;
        }

        // Min import: project interchange maxima onto real watermarks (B5 handoff).
        project_interchange_maxima_to_watermarks(&db, &step.interchange);

        // Block checks via production stage path (verdict only — no inline wm compares).
        for (i, block) in step.blocks.iter().enumerate() {
            let slot: u64 = block.slot.parse().unwrap();
            let result = stage_and_commit_block(
                &db,
                &block.pubkey,
                slot,
                block.signing_root.clone(),
                SIGN_GVR,
            );

            if result.is_ok() {
                raise_block_watermark_after_sign(&db, &block.pubkey, slot);
            }

            let success = result.is_ok();
            assert_eq!(
                success, block.should_succeed,
                "[minimal] {}: step {step_idx}, block {i} (slot={slot}): \
                 expected should_succeed={}, got {success} ({result:?})",
                test.name, block.should_succeed
            );
        }

        // Attestation checks via production stage path.
        for (i, att) in step.attestations.iter().enumerate() {
            let source: u64 = att.source_epoch.parse().unwrap();
            let target: u64 = att.target_epoch.parse().unwrap();
            let result = stage_and_commit_attestation(
                &db,
                &att.pubkey,
                source,
                target,
                att.signing_root.clone(),
                SIGN_GVR,
            );

            if result.is_ok() {
                raise_attestation_watermark_after_sign(&db, &att.pubkey, source, target);
            }

            let success = result.is_ok();
            assert_eq!(
                success, att.should_succeed,
                "[minimal] {}: step {step_idx}, attestation {i} \
                 (src={source}, tgt={target}): expected should_succeed={}, got {success} ({result:?})",
                test.name, att.should_succeed
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Macro to generate test functions for all 38 test cases × 2 runners
// ---------------------------------------------------------------------------

macro_rules! conformance_test {
    ($name:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn complete() {
                let test = load_test_case(stringify!($name));
                run_complete(&test);
            }

            #[test]
            fn minimal_conservative() {
                let test = load_test_case(stringify!($name));
                run_minimal_conservative(&test);
            }
        }
    };
}

// ---------------------------------------------------------------------------
// All 38 EIP-3076 conformance tests
// ---------------------------------------------------------------------------

// Duplicate pubkey tests (3)
conformance_test!(duplicate_pubkey_not_slashable);
conformance_test!(duplicate_pubkey_slashable_attestation);
conformance_test!(duplicate_pubkey_slashable_block);

// Multiple interchange tests (10)
conformance_test!(multiple_interchanges_multiple_validators_repeat_idem);
conformance_test!(multiple_interchanges_overlapping_validators_merge_stale);
conformance_test!(multiple_interchanges_overlapping_validators_repeat_idem);
conformance_test!(multiple_interchanges_single_validator_fail_iff_imported);
conformance_test!(multiple_interchanges_single_validator_first_surrounds_second);
conformance_test!(multiple_interchanges_single_validator_multiple_blocks_out_of_order);
conformance_test!(multiple_interchanges_single_validator_second_surrounds_first);
conformance_test!(multiple_interchanges_single_validator_single_att_out_of_order);
conformance_test!(multiple_interchanges_single_validator_single_block_out_of_order);
conformance_test!(multiple_interchanges_single_validator_single_message_gap);

// Multiple validator tests (2)
conformance_test!(multiple_validators_multiple_blocks_and_attestations);
conformance_test!(multiple_validators_same_slot_blocks);

// Single validator basic tests (8)
conformance_test!(single_validator_genesis_attestation);
conformance_test!(single_validator_import_only);
conformance_test!(single_validator_multiple_block_attempts);
conformance_test!(single_validator_multiple_blocks_and_attestations);
conformance_test!(single_validator_out_of_order_attestations);
conformance_test!(single_validator_out_of_order_blocks);
conformance_test!(single_validator_single_attestation);
conformance_test!(single_validator_single_block);

// Single block+attestation tests (2)
conformance_test!(single_validator_single_block_and_attestation);
conformance_test!(single_validator_single_block_and_attestation_signing_root);

// Re-signing tests (2)
conformance_test!(single_validator_resign_attestation);
conformance_test!(single_validator_resign_block);

// Slashable data tests (5)
conformance_test!(single_validator_slashable_attestations_double_vote);
conformance_test!(single_validator_slashable_attestations_surrounded_by_existing);
conformance_test!(single_validator_slashable_attestations_surrounds_existing);
conformance_test!(single_validator_slashable_blocks);
conformance_test!(single_validator_slashable_blocks_no_root);

// Source > target edge cases (4)
conformance_test!(single_validator_source_greater_than_target);
conformance_test!(single_validator_source_greater_than_target_sensible_iff_minified);
conformance_test!(single_validator_source_greater_than_target_surrounded);
conformance_test!(single_validator_source_greater_than_target_surrounding);

// Two blocks no signing root (1)
conformance_test!(single_validator_two_blocks_no_signing_root);

// Wrong genesis validators root (1)
conformance_test!(wrong_genesis_validators_root);

// ---------------------------------------------------------------------------
// check_and_record_* smoke (Phase 2 B4 handoff)
// ---------------------------------------------------------------------------
//
// RF1-03 retargeted the complete conformance runner at stage_* → commit/discard.
// This single smoke test keeps the legacy check_and_record_* API exercised so
// Phase 2 issue B4 (decide fate of check_and_record_*) has an explicit target
// to delete or repoint rather than discovering silent coverage loss.
//
// Do not expand this into a second conformance suite.

/// Thin residual coverage for `check_and_record_*` until Phase 2 B4.
#[test]
fn check_and_record_smoke_for_phase2_b4() {
    let db = SlashingDb::open_in_memory().expect("open db");
    let pubkey = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // Accept a block, then reject a conflicting double proposal at the same slot.
    db.check_and_record_block("local-vc", pubkey, 100, Some("0xroot_a".into()), SIGN_GVR)
        .expect("first block must succeed");
    let blocked =
        db.check_and_record_block("local-vc", pubkey, 100, Some("0xroot_b".into()), SIGN_GVR);
    assert!(blocked.is_err(), "conflicting block at same slot must be rejected");

    // Accept an attestation, then reject a double vote at the same target.
    db.check_and_record_attestation("local-vc", pubkey, 1, 2, Some("0xatt_a".into()), SIGN_GVR)
        .expect("first attestation must succeed");
    let blocked =
        db.check_and_record_attestation("local-vc", pubkey, 1, 2, Some("0xatt_b".into()), SIGN_GVR);
    assert!(blocked.is_err(), "double vote at same target must be rejected");
}
