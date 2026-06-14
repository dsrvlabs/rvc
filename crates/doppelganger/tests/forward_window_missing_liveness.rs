//! Tests for D-2: `ForwardWindowMachine` fails CLOSED on missing/incomplete liveness data.
//!
//! A validator must be marked `Safe` ONLY after EVERY epoch in its monitoring
//! window has a COMPLETE liveness observation (i.e. the validator's index is
//! present in the beacon-node response for that epoch).  An epoch whose response
//! omits a requested validator does NOT count as "observed" — the validator stays
//! `Pending` through the satisfaction boundary.

use std::sync::Arc;

use rvc_doppelganger::{
    DoppelgangerError, ForwardWindowMachine, SigningEnablement, ValidatorLivenessData,
};

use crypto::SecretKey;
use eth_types::{Epoch, Root, SLOTS_PER_EPOCH};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct NoPriorAttestation;

impl slashing::SlashingDbReader for NoPriorAttestation {
    fn last_signed_attestation(&self, _pubkey: &str, _gvr: &Root) -> Option<slashing::TargetEpoch> {
        None
    }
}

fn gvr() -> Root {
    [0xbb; 32]
}

fn new_pubkey() -> crypto::PublicKey {
    SecretKey::generate().public_key()
}

fn machine() -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPriorAttestation);
    ForwardWindowMachine::new(reader, 1, gvr())
}

fn machine_n(monitoring_epochs: u64) -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPriorAttestation);
    ForwardWindowMachine::new(reader, monitoring_epochs, gvr())
}

// ---------------------------------------------------------------------------
// D-2: missing entry in response → Err(IncompleteLiveness)
// ---------------------------------------------------------------------------

/// When `observe_liveness` is called for an epoch with an empty sample slice,
/// any Pending in-window validator is absent → must return `Err(IncompleteLiveness)`.
#[test]
fn test_observe_liveness_empty_samples_returns_incomplete_liveness_error() {
    let machine = machine();
    let pubkey = new_pubkey();
    let start_epoch: Epoch = 10;
    machine.register(&pubkey, start_epoch);

    // Empty slice — validator is absent.
    let result = machine.observe_liveness(start_epoch, &[]);
    assert!(
        matches!(result, Err(DoppelgangerError::IncompleteLiveness)),
        "empty samples for in-window Pending validator must return Err(IncompleteLiveness), got: {:?}",
        result
    );
}

/// When the response contains an entry for a DIFFERENT validator but not for
/// our validator, the result must be `Err(IncompleteLiveness)`.
#[test]
fn test_observe_liveness_missing_validator_in_partial_response_returns_error() {
    let machine = machine();
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let start_epoch: Epoch = 20;
    machine.register(&pubkey, start_epoch);

    // Response contains a *different* index — our validator is missing.
    let other_index = "deadbeef".to_string();
    assert_ne!(other_index, pubkey_hex, "test setup: indices must differ");
    let samples = vec![ValidatorLivenessData { index: other_index, is_live: false }];
    let result = machine.observe_liveness(start_epoch, &samples);
    assert!(
        matches!(result, Err(DoppelgangerError::IncompleteLiveness)),
        "response missing our validator's index must return Err(IncompleteLiveness)"
    );
}

// ---------------------------------------------------------------------------
// D-2: missing-entry epoch → validator stays Pending through boundary (fail-closed)
// ---------------------------------------------------------------------------

/// Negative path: a validator with a missing-entry epoch CANNOT transition to
/// Safe at the satisfaction boundary — it must remain Pending (fail-closed).
#[test]
fn test_missing_entry_epoch_keeps_validator_pending_through_boundary() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 30;
    let end_epoch = start_epoch + monitoring_epochs; // 31

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Call observe_liveness with empty samples for epoch start_epoch.
    // This is an incomplete response — the validator is absent.
    let _ = machine.observe_liveness(start_epoch, &[]);
    // (We intentionally ignore the error here; we are testing tick's behavior.)

    // Tick to the satisfaction boundary.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "validator with incomplete liveness observation must NOT become Safe at the boundary \
         (fail-closed D-2)"
    );
}

/// Tick FAR past end_epoch: incomplete observation must still prevent Safe.
#[test]
fn test_missing_entry_keeps_pending_even_far_past_boundary() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 40;
    let end_epoch = start_epoch + monitoring_epochs; // 41

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Incomplete observation — only start_epoch observed, but end_epoch is missing.
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let not_live = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
    machine.observe_liveness(start_epoch, &not_live).expect("start_epoch observation must succeed");

    // end_epoch NOT observed at all — tick far past the boundary.
    machine.tick(end_epoch + 50, 0);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "validator with end_epoch observation missing must NOT become Safe even far past boundary"
    );
}

// ---------------------------------------------------------------------------
// D-2: complete observation → Safe at boundary (positive path unchanged)
// ---------------------------------------------------------------------------

/// Positive path: a validator with COMPLETE (present, not-live) observations for
/// EVERY epoch in the window transitions to Safe at the satisfaction boundary.
#[test]
fn test_complete_observation_yields_safe_at_boundary() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 50;
    let end_epoch = start_epoch + monitoring_epochs; // 51

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Observe completely (present, not-live) for EVERY epoch in [start, end].
    for epoch in start_epoch..=end_epoch {
        let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
        machine.observe_liveness(epoch, &samples).expect("complete observation must succeed");
    }

    // Tick to the satisfaction boundary.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);

    assert!(
        machine.is_signing_enabled(&pubkey),
        "validator with complete not-live observation across the window must be Safe at boundary"
    );
}

/// Complete observation for monitoring_epochs = 2 (window is [start, start+2]).
#[test]
fn test_complete_observation_monitoring_epochs_2_yields_safe() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 100;
    let end_epoch = start_epoch + monitoring_epochs; // 102

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Complete observation for all 3 epochs in the inclusive window.
    for epoch in start_epoch..=end_epoch {
        let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
        machine.observe_liveness(epoch, &samples).expect("complete observation must succeed");
    }

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "monitoring_epochs=2: all 3 epochs observed completely → Safe at boundary"
    );
}

/// Partial observation (only start_epoch, missing end_epoch) → stays Pending.
#[test]
fn test_partial_observation_only_start_epoch_stays_pending() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 200;
    let end_epoch = start_epoch + monitoring_epochs; // 202

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Observe ONLY start_epoch — middle and end_epoch are missing.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
    machine.observe_liveness(start_epoch, &samples).expect("start_epoch must succeed");

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "only start_epoch observed (missing middle and end_epoch) → must stay Pending"
    );
}

// ---------------------------------------------------------------------------
// D-2: is_live in any observed epoch → Detected (unchanged from D-1)
// ---------------------------------------------------------------------------

/// An is_live=true in a complete response still transitions to Detected (D-1 preserved).
#[test]
fn test_complete_observation_with_live_transitions_to_detected() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 70;

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Present AND is_live=true → must Detect.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    machine
        .observe_liveness(start_epoch, &samples)
        .expect("observe_liveness must succeed when index is present");

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "is_live=true in complete response → Detected; signing denied"
    );
}

/// Present + is_live=true does NOT return Err (the index is present; the error is about absence).
#[test]
fn test_live_validator_present_does_not_return_error() {
    let machine = machine();
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let start_epoch: Epoch = 80;
    machine.register(&pubkey, start_epoch);

    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    let result = machine.observe_liveness(start_epoch, &samples);
    assert!(
        result.is_ok(),
        "is_live=true but index is PRESENT in response → must be Ok (no IncompleteLiveness)"
    );
}

// ---------------------------------------------------------------------------
// D-2: out-of-window observations still ignored (D-1 preserved)
// ---------------------------------------------------------------------------

/// An is_live observation before start_epoch: ignored (not counted as observed,
/// not detected, does not affect IncompleteLiveness for that epoch).
#[test]
fn test_out_of_window_before_start_ignored_completely() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 90;
    let end_epoch = start_epoch + monitoring_epochs; // 91

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Call observe_liveness for an epoch BEFORE the window.
    // The validator IS in the response, but the epoch is out-of-window.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    let result = machine.observe_liveness(start_epoch - 1, &samples);
    // No in-window Pending validator was expected for this epoch → Ok (no IncompleteLiveness).
    assert!(result.is_ok(), "out-of-window epoch: no in-window validator expected → must be Ok");

    // Confirm the validator is still Pending (not Detected) — out-of-window is_live ignored.
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "out-of-window is_live must not Detect the validator"
    );

    // Now provide complete observation for in-window epochs and confirm Safe.
    for epoch in start_epoch..=end_epoch {
        let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
        machine.observe_liveness(epoch, &samples).expect("in-window observation must succeed");
    }
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "complete in-window observation after out-of-window ignore → Safe"
    );
}

/// observe_liveness returns Ok when no Pending in-window validators are expected
/// (e.g. all registered validators are already Safe or Detected).
#[test]
fn test_observe_liveness_returns_ok_when_no_pending_in_window_validators() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 5;
    let end_epoch = start_epoch + monitoring_epochs; // 6

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Observe completely to reach Safe.
    for epoch in start_epoch..=end_epoch {
        let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
        machine.observe_liveness(epoch, &samples).expect("complete observation must succeed");
    }
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pubkey), "must be Safe");

    // Now call observe_liveness for another epoch with empty samples.
    // The only validator is Safe (not Pending) — no expected in-window validator → Ok.
    let result = machine.observe_liveness(end_epoch + 1, &[]);
    assert!(
        result.is_ok(),
        "no Pending in-window validators → empty samples must be Ok (no IncompleteLiveness)"
    );
}
