//! PRD M6 — doppelganger window enforced at every signing entry point (Issue 2.13).
//!
//! # What M6 requires
//!
//! > The doppelganger window is enforced at EVERY signing entry point.
//!
//! When the gate's `SigningEnablement` returns `false` — which happens both when
//! a validator is inside its active doppelganger forward window AND when the
//! pubkey is unknown (the fail-closed default,
//! `<bool as FailClosedDefault>::default_when_unknown()` = `false`) — then NONE
//! of the six `SigningGate::sign_*` paths may produce a signature.
//!
//! # The six paths
//!
//! 1. `sign_block`                    (slashable)
//! 2. `sign_attestation`              (slashable)
//! 3. `sign_sync_committee_message`   (non-slashable)
//! 4. `sign_contribution_and_proof`   (non-slashable — sync-committee contribution)
//! 5. `sign_aggregate_and_proof`      (non-slashable)
//! 6. `sign_selection_proof`          (non-slashable)
//!
//! Each must return `SigningGateError::BlockedByDoppelganger`, and the two
//! slashable paths must additionally leave the slashing DB untouched (no
//! phantom row — the gate refuses BEFORE staging).
//!
//! This is the M1 milestone artifact for PRD M6; the per-path unit RED tests
//! from Issues 2.9a/2.9b (`gate_*_doppelganger_blocked.rs`) cover the same
//! methods individually — this file is the single auditor-facing "every entry
//! point, gate off" assertion.

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb;

const GVR: Root = [0xd3; 32];

/// `SigningEnablement` that denies every pubkey — models both an active
/// doppelganger forward window and an unknown pubkey (fail-closed default).
struct GateOff;
impl SigningEnablement for GateOff {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

/// Build a `SigningGate` whose BLS backend genuinely holds the key (so the only
/// thing standing between the caller and a signature is the gate decision) and
/// whose enablement denies everything.
fn make_gate_off(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(km)));
    let gate = SigningGate::new(
        Arc::clone(&db),
        Arc::new(GateOff),
        Arc::clone(&signer),
        Arc::new(ValidatorLockMap::new()),
    );
    (pubkey, gate)
}

fn assert_blocked(label: &str, result: Result<Vec<u8>, SigningGateError>) {
    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "{label}: gate off must yield BlockedByDoppelganger (no signature); got: {result:?}"
    );
}

// ── Path 1: block (slashable) — blocked AND no slashing row ──────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_block_path_refuses_and_writes_no_row() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_off(sk, Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let result = gate.sign_block(&pubkey, 42, [0xb1; 32], GVR, "test").await;
    assert_blocked("sign_block", result);

    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(
        blocks.is_empty(),
        "block path must not stage any slashing row when the gate is off; found: {blocks:?}"
    );
}

// ── Path 2: attestation (slashable) — blocked AND no slashing row ────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_attestation_path_refuses_and_writes_no_row() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_off(sk, Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let result = gate.sign_attestation(&pubkey, 3, 4, [0xa7; 32], GVR, "test").await;
    assert_blocked("sign_attestation", result);

    let atts = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        atts.is_empty(),
        "attestation path must not stage any slashing row when the gate is off; found: {atts:?}"
    );
}

// ── Path 3: sync-committee message (non-slashable) ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_sync_committee_message_path_refuses() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_off(sk, db);

    let result = gate.sign_sync_committee_message(&pubkey, [0x33; 32]).await;
    assert_blocked("sign_sync_committee_message", result);
}

// ── Path 4: sync-committee contribution (non-slashable) ──────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_sync_contribution_path_refuses() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_off(sk, db);

    let result = gate.sign_contribution_and_proof(&pubkey, [0x44; 32]).await;
    assert_blocked("sign_contribution_and_proof", result);
}

// ── Path 5: aggregate-and-proof (non-slashable) ──────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_aggregate_and_proof_path_refuses() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_off(sk, db);

    let result = gate.sign_aggregate_and_proof(&pubkey, [0x55; 32]).await;
    assert_blocked("sign_aggregate_and_proof", result);
}

// ── Path 6: selection-proof (non-slashable) ──────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_selection_proof_path_refuses() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_off(sk, db);

    let result = gate.sign_selection_proof(&pubkey, [0x66; 32]).await;
    assert_blocked("sign_selection_proof", result);
}

// ── All six in one runtime: the doppelganger gate is enforced uniformly ──────

/// A single end-to-end assertion that ALL SIX entry points refuse with the same
/// `BlockedByDoppelganger` error under one gate-off configuration — the
/// auditor-facing M6 "every signing entry point" statement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_all_six_paths_refuse_under_one_gate_off() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_off(sk, Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    assert_blocked("block", gate.sign_block(&pubkey, 1, [0x01; 32], GVR, "t").await);
    assert_blocked("attestation", gate.sign_attestation(&pubkey, 1, 2, [0x02; 32], GVR, "t").await);
    assert_blocked("sync_message", gate.sign_sync_committee_message(&pubkey, [0x03; 32]).await);
    assert_blocked("sync_contribution", gate.sign_contribution_and_proof(&pubkey, [0x04; 32]).await);
    assert_blocked("aggregate", gate.sign_aggregate_and_proof(&pubkey, [0x05; 32]).await);
    assert_blocked("selection", gate.sign_selection_proof(&pubkey, [0x06; 32]).await);

    // The two slashable paths must have left the DB pristine.
    assert!(
        db.get_blocks(&pubkey_hex).expect("get_blocks").is_empty(),
        "no block slashing row may be written with the gate off"
    );
    assert!(
        db.get_attestations(&pubkey_hex).expect("get_attestations").is_empty(),
        "no attestation slashing row may be written with the gate off"
    );
}
