//! Integration test: block-proposal signing routes through `SigningGate`.
//!
//! Issue 2.10a acceptance criterion 4: assert that a block-proposal sign goes
//! through `SigningGate::sign_block`, proving that the gate is in the signing path.
//!
//! # Test strategy
//!
//! Two properties prove gate routing:
//!
//! (a) **Slashing protection is enforced**: A double-proposal (same slot, different
//!     signing root) is blocked with `BlockedBySlashingDb`.  If the gate were not
//!     in the path, the slashing check would be skipped and both signs would succeed.
//!
//! (b) **Doppelganger gate is enforced**: When the gate is built with `AlwaysEnabled`
//!     (default) signing succeeds.  When it is built with a custom `NeverEnabled`
//!     enablement, `sign_block` returns `BlockedByDoppelganger` immediately —
//!     without staging any slashing-DB row.  This can ONLY happen if the doppelganger
//!     check is actually evaluated on the signing path.
//!
//! Both tests use `SigningGate` directly (the `rvc-signer` crate's central seam).
//! The bin's `SignerServiceImpl` is tested separately in
//! `bin/rvc-signer/tests/sign_beacon_block_v2.rs`.

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb;

const GVR: Root = [0xd3; 32];

// ── Enablement stubs ──────────────────────────────────────────────────────────

struct AlwaysEnabled;
impl SigningEnablement for AlwaysEnabled {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

struct NeverEnabled;
impl SigningEnablement for NeverEnabled {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_gate_with_key(
    sk: SecretKey,
    db: Arc<SlashingDb>,
    enablement: Arc<dyn SigningEnablement>,
) -> (PublicKey, SigningGate) {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(km)));
    let gate = SigningGate::new(db, enablement, signer, Arc::new(ValidatorLockMap::new()));
    (pubkey, gate)
}

// ── (a) Slashing protection enforced via gate ─────────────────────────────────

/// A double-proposal for the same slot with a different signing root must be
/// blocked by `SigningGate::sign_block`.  If the gate were not in the path,
/// there would be no slashing DB check and both signs would succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_block_routing_slashing_protection_enforced_by_gate() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_with_key(sk, Arc::clone(&db), Arc::new(AlwaysEnabled));

    let slot = 42u64;
    let signing_root_a: Root = [0xaa; 32];
    let signing_root_b: Root = [0xbb; 32];

    // First sign: must succeed and commit a slashing-DB row.
    let first = gate.sign_block(&pubkey, slot, signing_root_a, GVR).await;
    assert!(first.is_ok(), "first sign_block must succeed; err: {:?}", first.err());

    // Row must be committed.
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let rows = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(rows.len(), 1, "slashing row must be committed after first sign");

    // Second sign — same slot, different root — must be blocked.
    let second = gate.sign_block(&pubkey, slot, signing_root_b, GVR).await;
    assert!(
        matches!(second, Err(SigningGateError::BlockedBySlashingDb(_))),
        "double-proposal must return BlockedBySlashingDb; got: {second:?}"
    );

    // Still exactly one row (the second was rejected before any write).
    let rows_after = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(rows_after.len(), 1, "double-proposal must not commit a second row");
}

// ── (b) Doppelganger gate enforced, no slashing row on denial ────────────────

/// When the gate is built with `NeverEnabled`, `sign_block` must return
/// `BlockedByDoppelganger` without writing any slashing-DB row.
///
/// If signing bypassed the gate, the doppelganger check would not be evaluated
/// and the sign would either succeed or fail with a key-not-found error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_block_routing_doppelganger_gate_blocks_and_no_phantom_row() {
    let sk = SecretKey::generate();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let (pubkey, gate) = make_gate_with_key(sk, Arc::clone(&db), Arc::new(NeverEnabled));

    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let signing_root: Root = [0xcc; 32];

    let result = gate.sign_block(&pubkey, 100, signing_root, GVR).await;

    // Must be blocked by the doppelganger gate.
    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "sign_block with NeverEnabled must return BlockedByDoppelganger; got: {result:?}"
    );

    // No phantom row: doppelganger denial must not stage or commit any slashing row.
    let rows = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(
        rows.is_empty(),
        "doppelganger block must not commit any slashing-DB row; found: {rows:?}"
    );
}
