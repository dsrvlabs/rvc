//! Tests for D-1: `ForwardWindowMachine` withholds signing for a forward window.
//!
//! Covers:
//! - `is_signing_enabled` returns `false` while Pending
//! - Safe transition fires only at-or-after the last slot of the satisfaction epoch
//! - Missed-tick recovery: tick past end_epoch still satisfies
//! - Restart-aware safe-skip: recent attestation → immediate Safe; stale → Pending
//! - `register` is idempotent (Pending/Safe/Detected all preserved)
//! - `observe_liveness` with `is_live = true` → Detected (terminal — no recovery)
//! - In-window liveness guard: out-of-window observations are ignored
//! - `cancel` removes the validator; next `register` starts fresh

use std::sync::Arc;

use rvc_doppelganger::{ForwardWindowMachine, SigningEnablement, ValidatorLivenessData};

use crypto::SecretKey;
use eth_types::{Epoch, Root, SLOTS_PER_EPOCH};

// ---------------------------------------------------------------------------
// Mock SlashingDbReader (slashing crate's GVR-aware reader)
// ---------------------------------------------------------------------------

struct NoPriorAttestation;

impl slashing::SlashingDbReader for NoPriorAttestation {
    fn last_signed_attestation(&self, _pubkey: &str, _gvr: &Root) -> Option<slashing::TargetEpoch> {
        None
    }
}

struct PriorAttestationAt {
    target_epoch: slashing::TargetEpoch,
}

impl slashing::SlashingDbReader for PriorAttestationAt {
    fn last_signed_attestation(&self, _pubkey: &str, _gvr: &Root) -> Option<slashing::TargetEpoch> {
        Some(self.target_epoch)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gvr() -> Root {
    [0xaa; 32]
}

fn new_pubkey() -> crypto::PublicKey {
    SecretKey::generate().public_key()
}

fn machine_no_prior(monitoring_epochs: u64) -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPriorAttestation);
    ForwardWindowMachine::new(reader, monitoring_epochs, gvr())
}

fn machine_with_prior(monitoring_epochs: u64, target_epoch: Epoch) -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(PriorAttestationAt { target_epoch });
    ForwardWindowMachine::new(reader, monitoring_epochs, gvr())
}

// ---------------------------------------------------------------------------
// Core: signing is withheld while Pending
// ---------------------------------------------------------------------------

#[test]
fn test_signing_disabled_immediately_after_register() {
    let machine = machine_no_prior(1);
    let pubkey = new_pubkey();
    machine.register(&pubkey, 10);
    assert!(!machine.is_signing_enabled(&pubkey), "must be false immediately after register");
}

#[test]
fn test_signing_disabled_for_unmonitored_pubkey() {
    let machine = machine_no_prior(1);
    let pubkey = new_pubkey();
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "unmonitored pubkey must return false (fail-closed)"
    );
}

// ---------------------------------------------------------------------------
// Satisfaction edge: Safe fires at-or-after last slot of end_epoch
// ---------------------------------------------------------------------------

/// monitoring_epochs = 1, start_epoch = E → end_epoch = E + 1.
/// Safe only at tick(end_epoch, SLOTS_PER_EPOCH - 1); all earlier slots stay Pending.
#[test]
fn test_safe_transition_fires_only_on_last_slot_of_satisfaction_epoch() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 5;
    let end_epoch = start_epoch + monitoring_epochs; // 6

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // All slots of start_epoch (epoch 5) — still Pending.
    for slot in 0..SLOTS_PER_EPOCH {
        machine.tick(start_epoch, slot);
        assert!(
            !machine.is_signing_enabled(&pubkey),
            "slot {slot} of epoch {start_epoch}: must still be false (not yet end_epoch)"
        );
    }

    // All slots of end_epoch EXCEPT the last — still Pending.
    for slot in 0..(SLOTS_PER_EPOCH - 1) {
        machine.tick(end_epoch, slot);
        assert!(
            !machine.is_signing_enabled(&pubkey),
            "slot {slot} of end_epoch {end_epoch}: must still be false (not the last slot)"
        );
    }

    // The last slot of end_epoch — transitions to Safe.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "must be true only after tick(end_epoch={end_epoch}, last_slot={})",
        SLOTS_PER_EPOCH - 1
    );
}

/// Per-slot off-by-one: tick at (end_epoch - 1, SLOTS_PER_EPOCH - 1) must NOT satisfy.
#[test]
fn test_off_by_one_previous_epoch_last_slot_does_not_satisfy() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 10;
    let end_epoch = start_epoch + monitoring_epochs; // 12

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Last slot of end_epoch - 1 (epoch 11) — must NOT satisfy.
    machine.tick(end_epoch - 1, SLOTS_PER_EPOCH - 1);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "last slot of epoch {} must NOT satisfy (end_epoch is {})",
        end_epoch - 1,
        end_epoch
    );

    // First slot of end_epoch — must NOT satisfy.
    machine.tick(end_epoch, 0);
    assert!(!machine.is_signing_enabled(&pubkey), "first slot of end_epoch must NOT satisfy");

    // Second-to-last slot of end_epoch — must NOT satisfy.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 2);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "second-to-last slot of end_epoch must NOT satisfy"
    );

    // Last slot of end_epoch — NOW satisfies.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pubkey), "last slot of end_epoch must satisfy");
}

/// Full slot-by-slot walk with monitoring_epochs = 2.
#[test]
fn test_full_slot_walk_monitoring_epochs_2() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 100;
    let end_epoch = start_epoch + monitoring_epochs; // 102

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Walk every slot of epochs 100 and 101 — all must be false.
    for epoch in start_epoch..end_epoch {
        for slot in 0..SLOTS_PER_EPOCH {
            machine.tick(epoch, slot);
            assert!(
                !machine.is_signing_enabled(&pubkey),
                "epoch {epoch}, slot {slot}: must be false before end_epoch={end_epoch}"
            );
        }
    }

    // Walk slots 0..=SLOTS_PER_EPOCH-2 of end_epoch (102) — still false.
    for slot in 0..(SLOTS_PER_EPOCH - 1) {
        machine.tick(end_epoch, slot);
        assert!(
            !machine.is_signing_enabled(&pubkey),
            "epoch {end_epoch}, slot {slot}: must be false (not last slot)"
        );
    }

    // Last slot of end_epoch — must flip to true.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pubkey), "must become true at last slot of end_epoch");
}

// ---------------------------------------------------------------------------
// Missed-tick recovery (should-fix #3)
// ---------------------------------------------------------------------------

/// A restart that skips the exact last slot of end_epoch must still resolve to Safe.
/// tick(end_epoch, SLOTS_PER_EPOCH-2) stays Pending; tick(end_epoch+1, 0) → Safe.
#[test]
fn test_missed_tick_resolves_to_safe_on_next_epoch() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 20;
    let end_epoch = start_epoch + monitoring_epochs; // 21

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Tick to one-before-last slot — still Pending.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 2);
    assert!(!machine.is_signing_enabled(&pubkey), "second-to-last slot must be Pending");

    // Miss the exact boundary; tick with first slot of end_epoch+1 → must resolve Safe.
    machine.tick(end_epoch + 1, 0);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "missed-tick recovery: tick past end_epoch must still become Safe"
    );
}

/// tick with current_epoch >> end_epoch also resolves to Safe.
#[test]
fn test_tick_far_past_end_epoch_resolves_to_safe() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 50;
    let end_epoch = start_epoch + monitoring_epochs; // 52

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Jump many epochs ahead.
    machine.tick(end_epoch + 100, 0);
    assert!(machine.is_signing_enabled(&pubkey), "tick far past end_epoch must resolve to Safe");
}

// ---------------------------------------------------------------------------
// Restart-aware safe-skip — recency check (Critical 1)
// ---------------------------------------------------------------------------

/// REGRESSION: prior attestation at epoch 0 with current_epoch=10_000 and
/// monitoring_epochs=2 must NOT trigger the safe-skip (goes Pending instead).
#[test]
fn test_restart_safe_skip_stale_attestation_goes_pending() {
    let monitoring_epochs: u64 = 2;
    let current_epoch: Epoch = 10_000;
    let stale_target: Epoch = 0; // 10_000 - 0 = 10_000 >> 2

    let machine = machine_with_prior(monitoring_epochs, stale_target);
    let pubkey = new_pubkey();
    machine.register(&pubkey, current_epoch);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "stale prior attestation (epoch {stale_target}) at current_epoch={current_epoch} \
         must NOT trigger safe-skip; must be Pending"
    );
}

/// Recent attestation within the monitoring window → immediate Safe on register.
#[test]
fn test_restart_safe_skip_recent_attestation_gives_immediate_safe() {
    let monitoring_epochs: u64 = 2;
    let current_epoch: Epoch = 100;
    // target = current - 1 → distance=1 ≤ monitoring_epochs=2 → skip
    let recent_target: Epoch = current_epoch - 1;

    let machine = machine_with_prior(monitoring_epochs, recent_target);
    let pubkey = new_pubkey();
    machine.register(&pubkey, current_epoch);

    assert!(
        machine.is_signing_enabled(&pubkey),
        "recent prior attestation (epoch {recent_target}) within window → immediate Safe"
    );
}

/// Attestation exactly at the window edge (distance == monitoring_epochs) → Safe.
#[test]
fn test_restart_safe_skip_edge_of_window_gives_safe() {
    let monitoring_epochs: u64 = 2;
    let current_epoch: Epoch = 100;
    let edge_target: Epoch = current_epoch - monitoring_epochs; // distance == 2 == monitoring_epochs

    let machine = machine_with_prior(monitoring_epochs, edge_target);
    let pubkey = new_pubkey();
    machine.register(&pubkey, current_epoch);

    assert!(
        machine.is_signing_enabled(&pubkey),
        "attestation at distance exactly == monitoring_epochs must trigger safe-skip"
    );
}

/// Attestation one beyond the window edge (distance == monitoring_epochs+1) → Pending.
#[test]
fn test_restart_safe_skip_just_outside_window_goes_pending() {
    let monitoring_epochs: u64 = 2;
    let current_epoch: Epoch = 100;
    let outside_target: Epoch = current_epoch - monitoring_epochs - 1; // distance=3 > 2

    let machine = machine_with_prior(monitoring_epochs, outside_target);
    let pubkey = new_pubkey();
    machine.register(&pubkey, current_epoch);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "attestation at distance > monitoring_epochs must NOT trigger safe-skip"
    );
}

/// When `last_signed_attestation` returns `None`, no safe-skip occurs.
#[test]
fn test_no_restart_skip_when_no_prior_attestation() {
    let machine = machine_no_prior(1);
    let pubkey = new_pubkey();
    machine.register(&pubkey, 10);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "no prior attestation → must be Pending (no safe-skip)"
    );
}

/// Pre-genesis-skew guard: current_epoch <= monitoring_epochs must NOT safe-skip.
/// (Same guard as DoppelgangerService M-7 fix.)
#[test]
fn test_restart_safe_skip_blocked_at_low_epoch() {
    let monitoring_epochs: u64 = 2;
    let current_epoch: Epoch = 1; // current_epoch (1) > monitoring_epochs (2)? No → guard fires
    let recent_target: Epoch = 1;

    let machine = machine_with_prior(monitoring_epochs, recent_target);
    let pubkey = new_pubkey();
    machine.register(&pubkey, current_epoch);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "current_epoch <= monitoring_epochs must block safe-skip (pre-genesis guard)"
    );
}

// ---------------------------------------------------------------------------
// Idempotency (extended — should-fix #5)
// ---------------------------------------------------------------------------

#[test]
fn test_register_idempotent_does_not_reset_after_safe() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 7;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Tick to Safe.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pubkey));

    // Register again — must NOT reset to Pending.
    machine.register(&pubkey, start_epoch);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "re-register while Safe must be idempotent — state stays Safe"
    );
}

/// Second register while Pending must NOT extend end_epoch.
#[test]
fn test_register_idempotent_while_pending_does_not_extend_window() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 10;
    let end_epoch = start_epoch + monitoring_epochs; // 11

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Attempt to re-register with a later epoch — must not extend the window.
    let later_epoch: Epoch = 50;
    machine.register(&pubkey, later_epoch);

    // Original end_epoch (11) still applies; tick at last slot of epoch 11 → Safe.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "re-register while Pending must not extend end_epoch; must be Safe at original end_epoch"
    );
}

/// Second register while Detected must NOT reset state to Pending.
#[test]
fn test_register_idempotent_while_detected_does_not_reset() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 30;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    machine.register(&pubkey, start_epoch);

    // Detect the validator as live.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    machine.observe_liveness(start_epoch, &samples).expect("must not fail");
    assert!(!machine.is_signing_enabled(&pubkey), "Detected → must deny signing");

    // Re-register — must NOT reset to Pending.
    machine.register(&pubkey, start_epoch);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "re-register while Detected must be idempotent — state stays Detected"
    );
}

// ---------------------------------------------------------------------------
// Liveness detection → Detected is TERMINAL (should-fix #4)
// ---------------------------------------------------------------------------

#[test]
fn test_observe_liveness_live_validator_transitions_to_detected() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 50;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    machine.register(&pubkey, start_epoch);

    // Observe the validator as live in epoch 50.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    machine.observe_liveness(start_epoch, &samples).expect("observe_liveness must not fail");

    assert!(!machine.is_signing_enabled(&pubkey), "Detected state must deny signing (fail-closed)");
}

/// Detected is terminal: tick past end_epoch must NOT resurrect the validator to Safe.
#[test]
fn test_detected_is_terminal_tick_does_not_resurrect() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 40;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    machine.register(&pubkey, start_epoch);

    // Detect: mark live.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    machine.observe_liveness(start_epoch, &samples).expect("must not fail");
    assert!(!machine.is_signing_enabled(&pubkey), "Detected → signing denied");

    // Tick past end_epoch — must STILL be denied (Detected is terminal).
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "Detected is terminal: tick past end_epoch must NOT resurrect to Safe"
    );

    // Tick even further.
    machine.tick(end_epoch + 10, 0);
    assert!(!machine.is_signing_enabled(&pubkey), "Detected is terminal even many epochs later");
}

#[test]
fn test_observe_liveness_not_live_does_not_detect() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 30;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    machine.register(&pubkey, start_epoch);

    let samples = vec![ValidatorLivenessData { index: pubkey_hex, is_live: false }];
    machine.observe_liveness(start_epoch, &samples).expect("must not fail");

    // Tick to end — if not Detected, should still become Safe at last slot.
    let end_epoch = start_epoch + monitoring_epochs;
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "not-live observation must not block Safe transition"
    );
}

// ---------------------------------------------------------------------------
// In-window liveness guard (should-fix #9)
// ---------------------------------------------------------------------------

/// An is_live observation BEFORE start_epoch must be ignored.
#[test]
fn test_observe_liveness_before_window_is_ignored() {
    let monitoring_epochs: u64 = 2;
    let start_epoch: Epoch = 60;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    machine.register(&pubkey, start_epoch);

    // Observation at epoch before the window.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    machine.observe_liveness(start_epoch - 1, &samples).expect("must not fail");

    // Must still be Pending, not Detected.
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "before-window observation must be ignored — still Pending"
    );

    // Tick to Safe — confirms not Detected.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "before-window observation must not Detect; Safe at end_epoch"
    );
}

/// An is_live observation AFTER end_epoch must be ignored.
#[test]
fn test_observe_liveness_after_window_is_ignored() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 70;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    machine.register(&pubkey, start_epoch);

    // Observation at epoch after the window.
    let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: true }];
    machine.observe_liveness(end_epoch + 1, &samples).expect("must not fail");

    // Must still be Pending.
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "after-window observation must be ignored — still Pending"
    );

    // Tick to Safe — confirms not Detected.
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "after-window observation must not Detect; Safe at end_epoch"
    );
}

// ---------------------------------------------------------------------------
// cancel
// ---------------------------------------------------------------------------

#[test]
fn test_cancel_removes_validator_state() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 9;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    machine.cancel(&pubkey);

    // After cancel, should be Unmonitored → fail-closed.
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "after cancel, pubkey must be Unmonitored → false"
    );
}

#[test]
fn test_cancel_then_reregister_starts_fresh() {
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 9;
    let end_epoch = start_epoch + monitoring_epochs;

    let machine = machine_no_prior(monitoring_epochs);
    let pubkey = new_pubkey();

    // Tick to Safe.
    machine.register(&pubkey, start_epoch);
    machine.tick(end_epoch, SLOTS_PER_EPOCH - 1);
    assert!(machine.is_signing_enabled(&pubkey));

    // Cancel, then re-register → Pending again.
    machine.cancel(&pubkey);
    machine.register(&pubkey, start_epoch);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "after cancel + re-register, must be Pending again"
    );
}
