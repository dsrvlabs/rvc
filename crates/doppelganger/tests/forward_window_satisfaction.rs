//! RED tests for D-1: `ForwardWindowMachine` withholds signing for a forward window.
//!
//! These tests verify the Lighthouse-pattern forward-window state machine:
//! - `is_signing_enabled` returns `false` while Pending
//! - Safe transition fires ONLY on the LAST slot of the satisfaction epoch
//! - Restart-aware safe-skip: `last_signed_attestation` returning `Some` → immediate Safe
//! - `register` is idempotent (second call does NOT reset state)
//! - `observe_liveness` with `is_live = true` → Detected
//! - `cancel` removes the validator; next `register` starts fresh
//!
//! The test file references `ForwardWindowMachine` and `SigningEnablement`
//! from `rvc_doppelganger`, which do NOT exist yet — this causes a compile
//! failure that is the RED state.

use std::sync::Arc;

use rvc_doppelganger::{ForwardWindowMachine, SigningEnablement, ValidatorLivenessData};

use crypto::SecretKey;
use eth_types::{Epoch, Root, SLOTS_PER_EPOCH};

// ---------------------------------------------------------------------------
// Mock SlashingDbReader
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
// Satisfaction edge: Safe fires ONLY on the last slot of end_epoch
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
// Restart-aware safe-skip (Layer 4)
// ---------------------------------------------------------------------------

/// When `last_signed_attestation` returns `Some(_)`, register goes straight to Safe.
#[test]
fn test_restart_safe_skip_prior_attestation_gives_immediate_safe() {
    // Prior attestation at end_epoch — within window → straight to Safe on register.
    let monitoring_epochs: u64 = 1;
    let start_epoch: Epoch = 20;
    let end_epoch = start_epoch + monitoring_epochs; // 21

    let machine = machine_with_prior(monitoring_epochs, end_epoch);
    let pubkey = new_pubkey();
    machine.register(&pubkey, start_epoch);

    // Should be Safe immediately — no tick needed.
    assert!(
        machine.is_signing_enabled(&pubkey),
        "restart safe-skip: prior attestation within window → immediate Safe"
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

// ---------------------------------------------------------------------------
// Idempotency
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

    // Register again with the same pubkey and epoch — must NOT reset to Pending.
    machine.register(&pubkey, start_epoch);
    assert!(
        machine.is_signing_enabled(&pubkey),
        "re-register same pubkey/epoch must be idempotent — state stays Safe"
    );
}

// ---------------------------------------------------------------------------
// Liveness detection → Detected state
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

    // State must be Detected → signing still denied.
    assert!(!machine.is_signing_enabled(&pubkey), "Detected state must deny signing (fail-closed)");
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
