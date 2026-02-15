//! EIP-3076 conformance tests.
//!
//! Integrates all 38 test cases from the official
//! `eth-clients/slashing-protection-interchange-tests` repository.
//! Tests both "complete" and "minimal" import strategies.

use std::collections::HashMap;

use serde::Deserialize;

use rvc_slashing::{InterchangeFormat, SlashingDb};

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
// Complete strategy runner
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

        // Run block checks
        for (i, block) in step.blocks.iter().enumerate() {
            let slot: u64 = block.slot.parse().unwrap();
            let result = db.check_and_record_block(&block.pubkey, slot, block.signing_root.clone());

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

        // Run attestation checks
        for (i, att) in step.attestations.iter().enumerate() {
            let source: u64 = att.source_epoch.parse().unwrap();
            let target: u64 = att.target_epoch.parse().unwrap();
            let result = db.check_and_record_attestation(
                &att.pubkey,
                source,
                target,
                att.signing_root.clone(),
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
// Minimal strategy runner (watermark-based)
// ---------------------------------------------------------------------------

fn run_minimal(test: &TestCase) {
    let gvr = &test.genesis_validators_root;

    // Track per-validator watermarks
    let mut block_wm: HashMap<String, u64> = HashMap::new();
    let mut att_source_wm: HashMap<String, u64> = HashMap::new();
    let mut att_target_wm: HashMap<String, u64> = HashMap::new();

    for (step_idx, step) in test.steps.iter().enumerate() {
        // GVR mismatch check
        if step.interchange.metadata.genesis_validators_root != *gvr {
            assert!(
                !step.should_succeed,
                "[minimal] {}: step {step_idx}: GVR mismatch but should_succeed is true",
                test.name
            );
            continue;
        }

        // Minimal import: update watermarks from interchange data
        for validator in &step.interchange.data {
            for block in &validator.signed_blocks {
                let slot: u64 = block.slot.parse().unwrap();
                let entry = block_wm.entry(validator.pubkey.clone()).or_insert(0);
                if slot > *entry {
                    *entry = slot;
                }
            }
            for att in &validator.signed_attestations {
                let source: u64 = att.source_epoch.parse().unwrap();
                let target: u64 = att.target_epoch.parse().unwrap();
                let se = att_source_wm.entry(validator.pubkey.clone()).or_insert(0);
                if source > *se {
                    *se = source;
                }
                let te = att_target_wm.entry(validator.pubkey.clone()).or_insert(0);
                if target > *te {
                    *te = target;
                }
            }
        }

        // Run block checks using watermark logic
        for (i, block) in step.blocks.iter().enumerate() {
            let slot: u64 = block.slot.parse().unwrap();
            let success = match block_wm.get(&block.pubkey) {
                Some(&max_slot) => slot > max_slot,
                None => true, // No previous blocks, any slot is fine
            };

            if success {
                // Record successful signing → update watermark
                let entry = block_wm.entry(block.pubkey.clone()).or_insert(0);
                if slot > *entry {
                    *entry = slot;
                }
            }

            assert_eq!(
                success, block.should_succeed,
                "[minimal] {}: step {step_idx}, block {i} (slot={slot}): \
                 expected should_succeed={}, got {success}",
                test.name, block.should_succeed
            );
        }

        // Run attestation checks using watermark logic
        for (i, att) in step.attestations.iter().enumerate() {
            let source: u64 = att.source_epoch.parse().unwrap();
            let target: u64 = att.target_epoch.parse().unwrap();

            let success = match (att_source_wm.get(&att.pubkey), att_target_wm.get(&att.pubkey)) {
                (Some(&max_source), Some(&max_target)) => {
                    source >= max_source && target > max_target
                }
                _ => true, // No previous attestations
            };

            if success {
                let se = att_source_wm.entry(att.pubkey.clone()).or_insert(0);
                if source > *se {
                    *se = source;
                }
                let te = att_target_wm.entry(att.pubkey.clone()).or_insert(0);
                if target > *te {
                    *te = target;
                }
            }

            assert_eq!(
                success, att.should_succeed,
                "[minimal] {}: step {step_idx}, attestation {i} \
                 (src={source}, tgt={target}): expected should_succeed={}, got {success}",
                test.name, att.should_succeed
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Macro to generate test functions for all 38 test cases
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
            fn minimal() {
                let test = load_test_case(stringify!($name));
                run_minimal(&test);
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
