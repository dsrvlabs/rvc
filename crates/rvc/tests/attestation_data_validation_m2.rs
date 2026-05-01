//! Regression tests for ISSUE-3.2 (M-2): local AttestationData sanity check.
//!
//! The validator must reject AttestationData received from the BN when:
//! - `target.epoch != data.slot / SLOTS_PER_EPOCH` (epoch inconsistency)
//! - `source.epoch > target.epoch` (impossible epoch ordering)
//! - `data.slot` is more than 2 slots away from the local clock slot (clock skew)
//!
//! RED phase: these tests fail until the production implementation lands.
//! GREEN phase: passing after the validation module is added to `attestation.rs`.

use eth_types::{AttestationData, Checkpoint, SLOTS_PER_EPOCH};
use rvc::orchestrator::validation::attestation_data::{
    validate_attestation_data, AttestationServiceError,
};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build an `AttestationData` that passes all sanity checks when using `slot`
/// as both the duty slot and the clock slot.
fn valid_data(slot: u64) -> AttestationData {
    let target_epoch = slot / SLOTS_PER_EPOCH;
    let source_epoch = if target_epoch > 0 { target_epoch - 1 } else { 0 };
    AttestationData {
        slot,
        index: 0,
        beacon_block_root: [0u8; 32],
        source: Checkpoint { epoch: source_epoch, root: [0u8; 32] },
        target: Checkpoint { epoch: target_epoch, root: [1u8; 32] },
    }
}

// ── RED tests (ISSUE-3.2 M-2) ─────────────────────────────────────────────────

/// target.epoch does not match slot / SLOTS_PER_EPOCH → must be rejected.
///
/// Example: slot 64 is in epoch 2 (64 / 32 = 2), but BN returns target.epoch = 5.
#[test]
fn test_target_epoch_mismatch_rejected() {
    let slot: u64 = 64; // epoch 2
    let mut data = valid_data(slot);
    data.target.epoch = 5; // wrong — should be 2

    let result = validate_attestation_data(&data, slot, slot);
    assert!(
        matches!(result, Err(AttestationServiceError::TargetEpochMismatch { .. })),
        "expected TargetEpochMismatch, got: {result:?}",
    );
}

/// source.epoch > target.epoch → must be rejected.
///
/// A source checkpoint cannot be in a later epoch than the target.
#[test]
fn test_source_after_target_rejected() {
    let slot: u64 = 96; // epoch 3
    let mut data = valid_data(slot);
    data.source.epoch = data.target.epoch + 1; // source after target

    let result = validate_attestation_data(&data, slot, slot);
    assert!(
        matches!(result, Err(AttestationServiceError::SourceAfterTarget { .. })),
        "expected SourceAfterTarget, got: {result:?}",
    );
}

/// data.slot is 100 slots ahead of the local clock → must be rejected.
///
/// The ±2 slot window protects against a confused/malicious BN returning
/// attestation data for a future slot.
#[test]
fn test_slot_far_from_clock_rejected() {
    let current_clock_slot: u64 = 100;
    let far_slot: u64 = current_clock_slot + 100;
    let data = valid_data(far_slot); // slot=200, target_epoch=6, source_epoch=5

    let result = validate_attestation_data(&data, far_slot, current_clock_slot);
    assert!(
        matches!(result, Err(AttestationServiceError::SlotOutOfWindow { .. })),
        "expected SlotOutOfWindow, got: {result:?}",
    );
}

/// Happy path: all checks pass.
#[test]
fn test_valid_data_passes() {
    let slot: u64 = 128; // epoch 4
    let data = valid_data(slot);
    let result = validate_attestation_data(&data, slot, slot);
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}
