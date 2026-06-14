//! RED test: per-validator lock serializes concurrent sign_block calls for the same pubkey.
//!
//! Two concurrent sign_block calls for the SAME pubkey at DIFFERENT slots must
//! complete without any slashing-DB race or inconsistency.  Both calls must
//! succeed and exactly two rows must be committed.
//!
//! This exercises the ValidatorLockMap: calls for the same pubkey are serialized,
//! while the test shows both operations complete successfully (no data race).

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
    let gate = Arc::new(SigningGate::new(
        Arc::clone(&db),
        Arc::new(AlwaysAllowed),
        Arc::clone(&signer),
        Arc::clone(&lock_map),
    ));

    let signing_root_a: Root = [0xaa; 32];
    let signing_root_b: Root = [0xbb; 32];

    let pubkey_a = pubkey.clone();
    let pubkey_b = pubkey.clone();
    let gate_a = Arc::clone(&gate);
    let gate_b = Arc::clone(&gate);

    // Launch two concurrent sign_block calls for different slots.
    let task_a =
        tokio::spawn(async move { gate_a.sign_block(&pubkey_a, 100, signing_root_a, GVR).await });
    let task_b =
        tokio::spawn(async move { gate_b.sign_block(&pubkey_b, 101, signing_root_b, GVR).await });

    let result_a = task_a.await.expect("task_a did not panic");
    let result_b = task_b.await.expect("task_b did not panic");

    // Both must succeed (different slots, no slashing conflict).
    assert!(result_a.is_ok(), "sign_block slot 100 must succeed; err: {:?}", result_a.err());
    assert!(result_b.is_ok(), "sign_block slot 101 must succeed; err: {:?}", result_b.err());

    // Exactly two rows must be committed — serialization ensures no lost writes.
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks must not fail");
    assert_eq!(
        blocks.len(),
        2,
        "both sign_block calls must have committed exactly one row each; found: {blocks:?}"
    );

    let slots: Vec<u64> = blocks.iter().map(|b| b.slot).collect();
    assert!(slots.contains(&100), "slot 100 row must be present; blocks: {blocks:?}");
    assert!(slots.contains(&101), "slot 101 row must be present; blocks: {blocks:?}");
}
