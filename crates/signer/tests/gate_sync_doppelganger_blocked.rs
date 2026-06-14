//! RED test: non-slashable gate methods return BlockedByDoppelganger when
//! `is_signing_enabled` returns `false`.
//!
//! All 7 non-slashable methods delegate to `sign_nonslashable`, which calls
//! `gate_decision` before attempting any sign.  This test pins the routing for
//! each method: gate denied → BlockedByDoppelganger, no slashing DB touched.

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb;

struct AlwaysDenied;
impl SigningEnablement for AlwaysDenied {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

fn make_gate(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(km)));
    let gate = SigningGate::new(
        Arc::clone(&db),
        Arc::new(AlwaysDenied),
        Arc::clone(&signer),
        Arc::new(ValidatorLockMap::new()),
    );
    (pubkey, gate)
}

/// `sign_sync_committee_message` must return `BlockedByDoppelganger` when the
/// doppelganger gate returns `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_sync_committee_message_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));

    let signing_root: Root = [0x11; 32];
    let result = gate.sign_sync_committee_message(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

/// `sign_contribution_and_proof` must return `BlockedByDoppelganger` when the
/// doppelganger gate returns `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_contribution_and_proof_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));

    let signing_root: Root = [0x22; 32];
    let result = gate.sign_contribution_and_proof(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

/// `sign_aggregate_and_proof` must return `BlockedByDoppelganger` when the
/// doppelganger gate returns `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_aggregate_and_proof_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));

    let signing_root: Root = [0x33; 32];
    let result = gate.sign_aggregate_and_proof(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

/// `sign_selection_proof` must return `BlockedByDoppelganger` when the
/// doppelganger gate returns `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_selection_proof_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));

    let signing_root: Root = [0x44; 32];
    let result = gate.sign_selection_proof(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

/// `sign_randao_reveal` must return `BlockedByDoppelganger` when the
/// doppelganger gate returns `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_randao_reveal_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));

    let signing_root: Root = [0x55; 32];
    let result = gate.sign_randao_reveal(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

/// `sign_voluntary_exit` must return `BlockedByDoppelganger` when the
/// doppelganger gate returns `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_voluntary_exit_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));

    let signing_root: Root = [0x66; 32];
    let result = gate.sign_voluntary_exit(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}

/// `sign_builder_registration` must return `BlockedByDoppelganger` when the
/// doppelganger gate returns `false`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_builder_registration_blocked_by_doppelganger() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));

    let signing_root: Root = [0x77; 32];
    let result = gate.sign_builder_registration(&pubkey, signing_root).await;

    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );
}
