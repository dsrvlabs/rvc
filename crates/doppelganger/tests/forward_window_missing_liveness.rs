//! Tests for D-2: `ForwardWindowMachine` fails CLOSED on missing/incomplete liveness data.
//!
//! A validator must be marked `Safe` ONLY after EVERY epoch in its monitoring
//! window has a COMPLETE liveness observation (i.e. the validator's pubkey-hex
//! index is present in the beacon-node response for that epoch).  An epoch
//! whose response omits a requested validator does NOT count as "observed" —
//! the validator stays `Pending` through the satisfaction boundary.

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

/// Observe EVERY epoch in `[start_epoch, end_epoch]` as complete and not-live.
///
/// Panics if any call returns an error (which would indicate the response is
/// missing the validator's index — a test-setup bug).
fn observe_complete_window(
    machine: &ForwardWindowMachine,
    pubkey: &crypto::PublicKey,
    start_epoch: Epoch,
    end_epoch: Epoch,
) {
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    for epoch in start_epoch..=end_epoch {
        let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
        machine.observe_liveness(epoch, &samples).expect("complete observation must succeed");
    }
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
        matches!(result, Err(DoppelgangerError::IncompleteLiveness { missing_count: 1, .. })),
        "empty samples for in-window Pending validator must return Err(IncompleteLiveness \
         {{ missing_count: 1, .. }}), got: {:?}",
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
        matches!(
            result,
            Err(DoppelgangerError::IncompleteLiveness { epoch: 20, missing_count: 1 })
        ),
        "response missing our validator's index must return Err(IncompleteLiveness)"
    );
}

/// IncompleteLiveness carries the correct epoch and missing_count.
#[test]
fn test_incomplete_liveness_error_carries_epoch_and_count() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 77;

    let machine = machine_n(monitoring_epochs);
    let _pk_a = new_pubkey();
    let _pk_b = new_pubkey();

    // Register two validators.
    machine.register(&_pk_a, start_epoch);
    machine.register(&_pk_b, start_epoch);

    // Respond with empty samples — both validators are absent.
    let result = machine.observe_liveness(start_epoch, &[]);
    match result {
        Err(DoppelgangerError::IncompleteLiveness { epoch, missing_count }) => {
            assert_eq!(epoch, start_epoch, "epoch in error must match the queried epoch");
            assert_eq!(missing_count, 2, "both validators absent → missing_count must be 2");
        }
        other => panic!("expected IncompleteLiveness, got {:?}", other),
    }
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

    // Call observe_liveness with empty samples for start_epoch.
    // This is an incomplete response — the validator is absent.
    // We assert the error is returned (must_use: errors must not be silently dropped).
    assert!(
        matches!(
            machine.observe_liveness(start_epoch, &[]),
            Err(DoppelgangerError::IncompleteLiveness { .. })
        ),
        "empty samples must return IncompleteLiveness"
    );

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

/// Start_epoch absent + end_epoch present: the most realistic transient-BN-omission case.
/// The BN happened to include the validator for end_epoch but omitted it for start_epoch.
/// The window is not complete → validator must stay Pending.
#[test]
fn test_start_epoch_absent_end_epoch_present_stays_pending() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 55;
    let end_epoch = start_epoch + monitoring_epochs; // 56

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // start_epoch: missing (BN transient omission).
    assert!(
        matches!(
            machine.observe_liveness(start_epoch, &[]),
            Err(DoppelgangerError::IncompleteLiveness { .. })
        ),
        "missing start_epoch must return IncompleteLiveness"
    );

    // end_epoch: present, not-live.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
    machine.observe_liveness(end_epoch, &samples).expect("end_epoch observation must succeed");

    // Tick to boundary — start_epoch was never recorded → window incomplete → stays Pending.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "start_epoch absent + end_epoch present must NOT satisfy the window (fail-closed)"
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
    machine.register(&pubkey, start_epoch);

    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);

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
    machine.register(&pubkey, start_epoch);

    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "monitoring_epochs=2: all 3 epochs observed completely → Safe at boundary"
    );
}

/// Partial observation (only start_epoch, missing middle and end_epoch) → stays Pending.
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

/// Detected is TERMINAL: tick past end_epoch must NOT resurrect to Safe.
#[test]
fn test_detected_is_terminal_tick_past_boundary_still_denied() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 71;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Detect the validator.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    machine.observe_liveness(start_epoch, &samples).expect("must not fail");
    assert!(!machine.is_signing_enabled(&pubkey), "Detected → signing denied");

    // Tick far past end_epoch.
    machine.tick(end_epoch + 10, 0);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "Detected is terminal: tick past end_epoch must NOT resurrect to Safe"
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
// SEC-008: duplicate-sample OR semantics
// ---------------------------------------------------------------------------

/// If a pubkey appears twice in samples with is_live=false then is_live=true,
/// the OR-fold must detect it (true wins over false).
#[test]
fn test_duplicate_sample_or_semantics_true_wins() {
    let machine = machine();
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let start_epoch: Epoch = 85;
    machine.register(&pubkey, start_epoch);

    // (pk, false) then (pk, true) — last-wins naive collect would keep false; OR-fold must detect.
    let samples = vec![
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false },
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true },
    ];
    machine.observe_liveness(start_epoch, &samples).expect("must succeed (index present)");

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "OR-fold: (false, true) → is_live=true must win → Detected"
    );
}

/// If a pubkey appears twice both not-live, OR-fold keeps false → stays Pending.
#[test]
fn test_duplicate_sample_or_semantics_both_false_stays_pending() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 86;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_n(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    machine.register(&pubkey, start_epoch);

    // Both not-live — OR-fold keeps false.
    let samples = vec![
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false },
        ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false },
    ];
    machine.observe_liveness(start_epoch, &samples).expect("must succeed (index present)");

    // Observe end_epoch too, then tick.
    let samples2 = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
    machine.observe_liveness(end_epoch, &samples2).expect("end_epoch must succeed");

    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "OR-fold: (false, false) → is_live=false → Safe after complete window"
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
    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);
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
    machine.register(&pubkey, start_epoch);

    // Observe completely to reach Safe.
    observe_complete_window(&machine, &pubkey, start_epoch, end_epoch);
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

// ---------------------------------------------------------------------------
// Multi-validator partial response (new — review item 6a)
// ---------------------------------------------------------------------------

/// Multi-validator: A present, B absent in the same epoch.
/// - returns Err(IncompleteLiveness, missing_count=1)
/// - A's epoch is recorded; B's is not
/// - After retry with a complete response for B, both reach Safe.
#[test]
fn test_multi_validator_partial_response_a_present_b_absent() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 300;
    let end_epoch = start_epoch + monitoring_epochs; // 301

    let machine = machine_n(monitoring_epochs);
    let pk_a = new_pubkey();
    let pk_b = new_pubkey();
    let hex_a = hex::encode(pk_a.to_bytes());
    let hex_b = hex::encode(pk_b.to_bytes());

    machine.register(&pk_a, start_epoch);
    machine.register(&pk_b, start_epoch);

    // start_epoch: A is present, B is absent.
    let samples = vec![ValidatorLivenessData { index: hex_a.clone(), is_live: false }];
    let result = machine.observe_liveness(start_epoch, &samples);
    assert!(
        matches!(
            result,
            Err(DoppelgangerError::IncompleteLiveness { epoch: 300, missing_count: 1 })
        ),
        "A present, B absent → must be IncompleteLiveness(missing=1), got: {:?}",
        result
    );

    // Both are still Pending; A has start_epoch recorded, B does not.
    assert!(!machine.is_signing_enabled(&pk_a), "A must still be Pending");
    assert!(!machine.is_signing_enabled(&pk_b), "B must still be Pending");

    // Retry B for start_epoch with a complete response (A already recorded, B missing).
    // We send BOTH to avoid triggering IncompleteLiveness for A again.
    let retry = vec![
        ValidatorLivenessData { index: hex_a.clone(), is_live: false },
        ValidatorLivenessData { index: hex_b.clone(), is_live: false },
    ];
    machine.observe_liveness(start_epoch, &retry).expect("retry must succeed");

    // Observe end_epoch for both.
    let end_samples = vec![
        ValidatorLivenessData { index: hex_a.clone(), is_live: false },
        ValidatorLivenessData { index: hex_b.clone(), is_live: false },
    ];
    machine.observe_liveness(end_epoch, &end_samples).expect("end_epoch must succeed");

    // Tick to boundary — both should now be Safe.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pk_a), "A must be Safe after complete observation");
    assert!(machine.is_signing_enabled(&pk_b), "B must be Safe after retry + complete observation");
}

/// Multi-validator: A present, B absent — B is NEVER retried.
/// After ticking to boundary: A is Safe, B stays Pending (fail-closed).
#[test]
fn test_multi_validator_b_never_retried_stays_pending() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 310;
    let end_epoch = start_epoch + monitoring_epochs; // 311

    let machine = machine_n(monitoring_epochs);
    let pk_a = new_pubkey();
    let pk_b = new_pubkey();
    let hex_a = hex::encode(pk_a.to_bytes());
    // hex_b deliberately not used: B is never included in any response.
    let _ = hex::encode(pk_b.to_bytes());

    machine.register(&pk_a, start_epoch);
    machine.register(&pk_b, start_epoch);

    // start_epoch: A present, B absent (never retried).
    let samples_start = vec![ValidatorLivenessData { index: hex_a.clone(), is_live: false }];
    let _err = machine.observe_liveness(start_epoch, &samples_start);
    // Error is intentionally checked only for the must_use; result already asserted above.
    assert!(matches!(_err, Err(DoppelgangerError::IncompleteLiveness { .. })));

    // end_epoch: A present (complete), B still absent.
    let samples_end = vec![ValidatorLivenessData { index: hex_a.clone(), is_live: false }];
    let _err2 = machine.observe_liveness(end_epoch, &samples_end);
    assert!(matches!(_err2, Err(DoppelgangerError::IncompleteLiveness { .. })));

    // Tick to boundary.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);

    // A has both start_epoch and end_epoch recorded → Safe.
    assert!(machine.is_signing_enabled(&pk_a), "A (fully observed) must be Safe");
    // B has neither epoch recorded → window incomplete → stays Pending.
    assert!(
        !machine.is_signing_enabled(&pk_b),
        "B (never retried) must stay Pending (fail-closed)"
    );
}
