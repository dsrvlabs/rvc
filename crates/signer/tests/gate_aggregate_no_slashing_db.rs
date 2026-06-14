//! RED test: `sign_aggregate_and_proof` must NOT commit any slashing-DB row.
//!
//! SS-2/SS-3 invariant: An `AggregateAndProof` is NOT itself slashable; the
//! inner `Attestation` is.  Therefore the aggregate-signing path must NOT touch
//! the slashing DB at all.  This test asserts that the DB remains empty after
//! a successful `sign_aggregate_and_proof` call, pinning the invariant.

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, ValidatorLockMap};
use slashing::SlashingDb;

struct AlwaysAllowed;
impl SigningEnablement for AlwaysAllowed {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

fn make_gate(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(km)));
    let gate = SigningGate::new(
        Arc::clone(&db),
        Arc::new(AlwaysAllowed),
        Arc::clone(&signer),
        Arc::new(ValidatorLockMap::new()),
    );
    (pubkey, gate)
}

/// SS-2/SS-3 invariant: a successful `sign_aggregate_and_proof` must return a
/// 96-byte signature AND leave BOTH the attestation table and the block table
/// in the slashing DB completely empty.
///
/// Any staging of an attestation (or block) row by the aggregate path would be
/// a violation of the chain-of-custody invariant; this test catches regressions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_aggregate_and_proof_no_slashing_row_committed() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate(sk, Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let signing_root: Root = [0xaa; 32];
    let result = gate.sign_aggregate_and_proof(&pubkey, signing_root).await;

    // Must succeed with a 96-byte BLS signature.
    let sig = result.expect("sign_aggregate_and_proof must succeed");
    assert_eq!(sig.len(), 96, "BLS signature must be 96 bytes; got {} bytes", sig.len());

    // SS-2/SS-3 invariant: no attestation row must have been staged/committed.
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations must not fail");
    assert!(
        attestations.is_empty(),
        "sign_aggregate_and_proof must NOT commit any attestation row; found: {attestations:?}"
    );

    // No block row either.
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks must not fail");
    assert!(
        blocks.is_empty(),
        "sign_aggregate_and_proof must NOT commit any block row; found: {blocks:?}"
    );
}
