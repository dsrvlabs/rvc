//! Item-5 tests for `SigningGate::sign_attestation`:
//!
//! (a) Happy path — enablement=true → 96-byte signature returned, attestation
//!     row committed, a subsequent conflicting attestation is rejected.
//!
//! (b) Signer failure (key not found) → Err(KeyNotFound) returned and NO
//!     slashing-DB row committed (phantom-row guarantee for the attestation path).

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb;

const GVR: Root = [0xd3; 32];

struct AlwaysAllowed;
impl SigningEnablement for AlwaysAllowed {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

fn make_gate_with_key(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
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

fn make_gate_empty_signer(db: Arc<SlashingDb>) -> SigningGate {
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    SigningGate::new(
        Arc::clone(&db),
        Arc::new(AlwaysAllowed),
        Arc::clone(&signer),
        Arc::new(ValidatorLockMap::new()),
    )
}

// ── (a) Happy path ─────────────────────────────────────────────────────────────

/// `sign_attestation` must return 96 bytes, commit the row, and block a
/// subsequent conflicting attestation for the same target epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_attestation_happy_path_commits_row_and_blocks_conflict() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_with_key(SecretKey::generate(), Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let signing_root: Root = [0xaa; 32];

    // First sign: must succeed.
    let result = gate.sign_attestation(&pubkey, 10, 11, signing_root, GVR, "test").await;
    assert!(result.is_ok(), "first sign_attestation must succeed; err: {:?}", result.err());

    // Must be 96 bytes.
    let sig_bytes = result.unwrap();
    assert_eq!(
        sig_bytes.len(),
        96,
        "BLS signature must be 96 bytes; got {} bytes",
        sig_bytes.len()
    );

    // Exactly one attestation row must be committed.
    let rows = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert_eq!(rows.len(), 1, "exactly one row must be committed; rows: {rows:?}");
    assert_eq!(rows[0].source_epoch, 10);
    assert_eq!(rows[0].target_epoch, 11);

    // Second sign with a different signing_root at the same target epoch must
    // be rejected as a DoubleVote by the slashing-protection check.
    let conflict_root: Root = [0xbb; 32];
    let conflict = gate.sign_attestation(&pubkey, 10, 11, conflict_root, GVR, "test").await;
    assert!(
        matches!(conflict, Err(SigningGateError::BlockedBySlashingDb(_))),
        "conflicting attestation must return BlockedBySlashingDb; got: {conflict:?}"
    );

    // Still exactly one row — the conflict was rejected before any write.
    let rows_after = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert_eq!(rows_after.len(), 1, "conflict must not write a second row; rows: {rows_after:?}");
}

// ── (b) Signer failure leaves no row ───────────────────────────────────────────

/// When the signing backend has no key, `sign_attestation` must return
/// `Err(KeyNotFound)` and leave the slashing DB empty (no phantom row).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_attestation_signer_failure_no_phantom_row() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let gate = make_gate_empty_signer(Arc::clone(&db));

    // Generate a pubkey that is NOT in the signer.
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let signing_root: Root = [0xcc; 32];
    let result = gate.sign_attestation(&pubkey, 20, 21, signing_root, GVR, "test").await;

    assert!(
        matches!(result, Err(SigningGateError::KeyNotFound)),
        "missing key must return KeyNotFound; got: {result:?}"
    );

    // Phantom-row guarantee: no row must be committed when signing fails.
    let rows = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        rows.is_empty(),
        "signer failure must not commit a phantom attestation row; found: {rows:?}"
    );
}
