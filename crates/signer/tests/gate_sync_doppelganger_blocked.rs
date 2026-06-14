//! RED test: non-slashable gate methods return BlockedByDoppelganger when
//! `is_signing_enabled` returns `false`.
//!
//! Covered: `sign_sync_committee_message` and `sign_contribution_and_proof`.
//! Neither method should call the slashing DB; the gate must fail closed as soon
//! as the doppelganger check returns false.

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
