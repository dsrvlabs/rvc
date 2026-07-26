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
//!     signing root) is blocked with `SlashingBlocked`.  If the gate were not
//!     in the path, the slashing check would be skipped and both signs would succeed.
//!
//! (b) **Doppelganger gate is enforced**: When the gate is built with
//!     [`common::AlwaysAllowed`] signing succeeds.  When it is built with
//!     [`common::AlwaysDenied`], `sign_block` returns `BlockedByDoppelganger`
//!     immediately — without staging any slashing-DB row.  This can ONLY happen if
//!     the doppelganger check is actually evaluated on the signing path.
//!
//! Both tests use `SigningGate` directly (the `rvc-signer` crate's central seam).
//! The bin's `SignerServiceImpl` is tested separately in
//! `bin/rvc-signer/tests/sign_beacon_block_v2.rs`.

mod common;

use std::sync::Arc;

use crypto::SecretKey;
use eth_types::Root;
use rvc_signer::SigningGateError;

const GVR: Root = [0xd3; 32];

// ── (a) Slashing protection enforced via gate ─────────────────────────────────

/// A double-proposal for the same slot with a different signing root must be
/// blocked by `SigningGate::sign_block`.  If the gate were not in the path,
/// there would be no slashing DB check and both signs would succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_block_routing_slashing_protection_enforced_by_gate() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_allowed(sk, Arc::clone(&db));

    let slot = 42u64;
    let signing_root_a: Root = [0xaa; 32];
    let signing_root_b: Root = [0xbb; 32];

    // First sign: must succeed and commit a slashing-DB row.
    let first = gate.sign_block(&pubkey, slot, signing_root_a, GVR, "test").await;
    assert!(first.is_ok(), "first sign_block must succeed; err: {:?}", first.err());

    // Row must be committed.
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let rows = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(rows.len(), 1, "slashing row must be committed after first sign");

    // Second sign — same slot, different root — must be blocked.
    let second = gate.sign_block(&pubkey, slot, signing_root_b, GVR, "test").await;
    assert!(
        matches!(second, Err(SigningGateError::SlashingBlocked(_))),
        "double-proposal must return SlashingBlocked; got: {second:?}"
    );

    // Still exactly one row (the second was rejected before any write).
    let rows_after = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(rows_after.len(), 1, "double-proposal must not commit a second row");
}

// ── (b) Doppelganger gate enforced, no slashing row on denial ────────────────

/// When the gate is built with `AlwaysDenied`, `sign_block` must return
/// `BlockedByDoppelganger` without writing any slashing-DB row.
///
/// If signing bypassed the gate, the doppelganger check would not be evaluated
/// and the sign would either succeed or fail with a key-not-found error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_block_routing_doppelganger_gate_blocks_and_no_phantom_row() {
    let sk = SecretKey::generate();
    let db = common::open_db();
    let (pubkey, gate) = common::gate_denied(sk, Arc::clone(&db));

    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let signing_root: Root = [0xcc; 32];

    let result = gate.sign_block(&pubkey, 100, signing_root, GVR, "test").await;

    // Must be blocked by the doppelganger gate.
    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "sign_block with AlwaysDenied must return BlockedByDoppelganger; got: {result:?}"
    );

    // No phantom row: doppelganger denial must not stage or commit any slashing row.
    let rows = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(
        rows.is_empty(),
        "doppelganger block must not commit any slashing-DB row; found: {rows:?}"
    );
}
