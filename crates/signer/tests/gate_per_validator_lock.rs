//! Test: concurrent sign_block calls for the same pubkey are serialized safely.
//!
//! Two concurrent sign_block calls for the SAME pubkey at the SAME slot with the
//! SAME signing root (an idempotent re-sign) must BOTH succeed and commit EXACTLY
//! ONE row — regardless of which task acquires the per-pubkey lock first.
//!
//! Why same-slot/same-root (not two different slots): EIP-3076 block protection
//! rejects a block at a slot below the highest already-signed slot. Two concurrent
//! signs at distinct slots (e.g. 100 and 101) have an order-dependent outcome —
//! if slot 101 commits first, the slot-100 sign is *correctly* rejected as
//! below-watermark. That is correct gate behavior, not a serialization failure,
//! so it cannot be asserted as "both succeed". The same-slot/same-root re-sign is
//! order-INDEPENDENT: whichever task wins, the other observes the committed row as
//! an idempotent re-sign. This deterministically exercises the serialization
//! invariant (no race-induced UNIQUE violation, no double row, no lost write)
//! under concurrency, including under heavy parallel `cargo test --workspace` load.

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, ValidatorLockMap};
use slashing::SlashingDb;

const GVR: Root = [0xd3; 32];

struct AlwaysAllowed;
impl SigningEnablement for AlwaysAllowed {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

fn make_signer_with_key(sk: SecretKey) -> Arc<crypto::CompositeSigner> {
    let mut km = KeyManager::new();
    km.insert(sk);
    Arc::new(crypto::CompositeSigner::new(LocalSigner::new(km)))
}

/// Both concurrent sign_block calls must complete successfully and each commit
/// exactly one row.  The per-validator lock ensures they serialize so that the
/// slashing DB never sees a concurrent write for the same pubkey.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sign_block_per_validator_lock_serializes_concurrent_calls() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let signer = make_signer_with_key(sk);
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let lock_map = Arc::new(ValidatorLockMap::new());

    // Build two gate references sharing the same underlying resources.
    // Use a generous sign timeout: this test exercises serialization, not the
    // timeout. Under heavy parallel `cargo test --workspace` load the
    // spawn_blocking + block_on(sign) thread can be starved, and the default 4s
    // timeout could spuriously fire and turn a sign into SigningFailed (causing
    // a flaky <2-rows assertion). 60s removes that timing dependency.
    let gate = Arc::new(
        SigningGate::new(
            Arc::clone(&db),
            Arc::new(AlwaysAllowed),
            Arc::clone(&signer),
            Arc::clone(&lock_map),
        )
        .with_sign_timeout(std::time::Duration::from_secs(60)),
    );

    // Same slot, same signing root → an idempotent re-sign. Order-independent:
    // whichever task commits first, the other observes the committed row as a
    // re-sign of the identical root and also succeeds, leaving exactly one row.
    const SLOT: u64 = 100;
    let signing_root: Root = [0xaa; 32];

    let pubkey_a = pubkey.clone();
    let pubkey_b = pubkey.clone();
    let gate_a = Arc::clone(&gate);
    let gate_b = Arc::clone(&gate);

    // Launch two concurrent sign_block calls for the SAME pubkey/slot/root.
    let task_a =
        tokio::spawn(async move { gate_a.sign_block(&pubkey_a, SLOT, signing_root, GVR).await });
    let task_b =
        tokio::spawn(async move { gate_b.sign_block(&pubkey_b, SLOT, signing_root, GVR).await });

    let result_a = task_a.await.expect("task_a did not panic");
    let result_b = task_b.await.expect("task_b did not panic");

    // Both must succeed: the first stages+commits, the second is an idempotent
    // re-sign of the same root. A serialization failure would surface here as a
    // UNIQUE-index violation on the second commit.
    assert!(result_a.is_ok(), "concurrent re-sign A must succeed; err: {:?}", result_a.err());
    assert!(result_b.is_ok(), "concurrent re-sign B must succeed; err: {:?}", result_b.err());

    // Exactly ONE row: the re-sign must not double-insert under concurrency.
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks must not fail");
    assert_eq!(
        blocks.len(),
        1,
        "concurrent same-slot/same-root re-sign must commit exactly one row; found: {blocks:?}"
    );
    assert_eq!(blocks[0].slot, SLOT, "the single committed row must be at the signed slot");
}
