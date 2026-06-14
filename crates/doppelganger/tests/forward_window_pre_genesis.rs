//! S-3: Startup doppelganger detection must ALWAYS be invoked — pre-genesis epoch-0 bypass.
//!
//! At epoch 0 (genesis / pre-genesis), no slots have occurred yet so liveness-based
//! detection is not meaningful.  `ForwardWindowMachine::register` must immediately
//! mark the validator `Safe` and emit an explicit `info!` log documenting the bypass
//! decision (rather than silently skipping).
//!
//! # RED phase (Issue 2.8)
//!
//! On current code `register(pubkey, 0)` goes to `Pending`, so the assertions
//! that check for `Safe` immediately after register will FAIL.

use std::sync::Arc;

use rvc_doppelganger::{ForwardWindowMachine, SigningEnablement};

use crypto::SecretKey;
use eth_types::Root;

// ---------------------------------------------------------------------------
// Mock SlashingDbReader (no prior attestation — exercises the new epoch-0 path)
// ---------------------------------------------------------------------------

struct NoPriorAttestation;

impl slashing::SlashingDbReader for NoPriorAttestation {
    fn last_signed_attestation(&self, _pubkey: &str, _gvr: &Root) -> Option<slashing::TargetEpoch> {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gvr() -> Root {
    [0xcc; 32]
}

fn new_pubkey() -> crypto::PublicKey {
    SecretKey::generate().public_key()
}

fn machine(monitoring_epochs: u64) -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPriorAttestation);
    ForwardWindowMachine::new(reader, monitoring_epochs, gvr())
}

// ---------------------------------------------------------------------------
// S-3: epoch-0 pre-genesis bypass → immediate Safe, no tick needed
// ---------------------------------------------------------------------------

/// S-3 core: `register(pubkey, 0)` must produce an immediate `Safe` state.
///
/// At genesis epoch 0, no slots have occurred so liveness detection is not
/// meaningful.  The documented Lighthouse tradeoff is to mark the validator
/// `Safe` immediately (remaining_epochs = 0) with an explicit log.
///
/// On current code this test is RED: `register(pubkey, 0)` goes to `Pending`
/// and `is_signing_enabled` returns `false`.
#[test]
fn test_register_at_epoch_0_is_immediately_safe() {
    let machine = machine(2);
    let pubkey = new_pubkey();

    machine.register(&pubkey, 0);

    assert!(
        machine.is_signing_enabled(&pubkey),
        "register at epoch 0 (pre-genesis) must immediately mark the validator Safe; \
         no tick should be required"
    );
}

/// S-3: the epoch-0 bypass is epoch-0-ONLY.
///
/// A validator registered at `current_epoch = 5` must be `Pending`
/// (signing disabled) — the bypass must not apply to any epoch > 0.
#[test]
fn test_register_at_epoch_5_is_still_pending() {
    let machine = machine(2);
    let pubkey = new_pubkey();

    machine.register(&pubkey, 5);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "register at epoch 5 must leave the validator Pending; \
         the pre-genesis bypass must only fire at epoch 0"
    );
}

/// S-3: idempotency guard wins over the epoch-0 bypass.
///
/// If the validator is already in a non-Unmonitored state (e.g. Pending from
/// a prior register call at epoch > 0), a second register at epoch 0 must be
/// a no-op — the existing state must be preserved.
#[test]
fn test_epoch_0_bypass_does_not_override_existing_state() {
    let machine = machine(2);
    let pubkey = new_pubkey();

    // First register at epoch 5 → Pending.
    machine.register(&pubkey, 5);
    assert!(!machine.is_signing_enabled(&pubkey), "first register at epoch 5 must be Pending");

    // Second register at epoch 0 — idempotency guard must win; state stays Pending.
    machine.register(&pubkey, 0);
    assert!(
        !machine.is_signing_enabled(&pubkey),
        "re-register at epoch 0 must not override existing Pending state (idempotency guard wins)"
    );
}

/// S-3 + log: `register(pubkey, 0)` must emit an info! log containing the
/// pre-genesis bypass decision.
#[test]
#[tracing_test::traced_test]
fn test_register_at_epoch_0_emits_pre_genesis_bypass_log() {
    let machine = machine(1);
    let pubkey = new_pubkey();

    machine.register(&pubkey, 0);

    // The validator must be Safe immediately (same assertion as the core test).
    assert!(
        machine.is_signing_enabled(&pubkey),
        "epoch-0 bypass must mark validator Safe immediately"
    );

    // The implementation must emit an info! log documenting the bypass decision.
    assert!(
        logs_contain("pre-genesis"),
        "register at epoch 0 must emit a log containing 'pre-genesis' to document the bypass"
    );
}
