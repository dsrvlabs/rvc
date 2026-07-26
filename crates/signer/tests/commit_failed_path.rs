//! RF4-03 path-level tests: `SigningGate` commit arms produce `CommitFailed`.
//!
//! Arms `SlashingDb::fail_next_commits` so `Staged*::commit` fails after a
//! successful BLS sign; asserts the gate returns `CommitFailed` with the
//! caller-supplied signing root (not `SlashingBlocked`).

mod common;

use std::sync::Arc;

use crypto::SecretKey;
use eth_types::Root;
use rvc_signer::SigningGateError;

const GVR: Root = [0xd3; 32];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gate_sign_block_commit_failure_is_commit_failed() {
    let db = common::open_db();
    let (pubkey, gate) = common::gate_allowed(SecretKey::generate(), Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let signing_root: Root = [0xaa; 32];
    let slot = 42u64;

    db.fail_next_commits(1);
    let err = gate
        .sign_block(&pubkey, slot, signing_root, GVR, "test")
        .await
        .expect_err("injected commit failure must surface");

    match &err {
        SigningGateError::CommitFailed { signing_root: r, source } => {
            assert_eq!(*r, signing_root);
            assert!(
                source.to_string().contains("injected commit failure"),
                "source should be inject: {source}"
            );
        }
        SigningGateError::SlashingBlocked(_) => {
            panic!("commit failure must NOT be SlashingBlocked")
        }
        other => panic!("expected CommitFailed, got: {other:?}"),
    }
    assert!(err.permits_retry_with_root(&signing_root));
    assert!(!err.permits_retry_with_root(&[0xbb; 32]));
    assert!(
        db.get_blocks(&pubkey_hex).expect("query").is_empty(),
        "failed commit must leave no block row"
    );

    // Same-root retry after inject exhausted succeeds.
    gate.sign_block(&pubkey, slot, signing_root, GVR, "test")
        .await
        .expect("same-root retry after CommitFailed");
    assert_eq!(db.get_blocks(&pubkey_hex).expect("query").len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gate_sign_attestation_commit_failure_is_commit_failed() {
    let db = common::open_db();
    let (pubkey, gate) = common::gate_allowed(SecretKey::generate(), Arc::clone(&db));
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let signing_root: Root = [0xcc; 32];

    db.fail_next_commits(1);
    let err = gate
        .sign_attestation(&pubkey, 10, 11, signing_root, GVR, "test")
        .await
        .expect_err("injected commit failure must surface");

    match &err {
        SigningGateError::CommitFailed { signing_root: r, .. } => {
            assert_eq!(*r, signing_root);
        }
        SigningGateError::SlashingBlocked(_) => {
            panic!("commit failure must NOT be SlashingBlocked")
        }
        other => panic!("expected CommitFailed, got: {other:?}"),
    }
    assert!(err.permits_retry_with_root(&signing_root));
    assert!(!err.permits_retry_with_root(&[0xdd; 32]));
    assert!(db.get_attestations(&pubkey_hex).expect("query").is_empty());

    gate.sign_attestation(&pubkey, 10, 11, signing_root, GVR, "test")
        .await
        .expect("same-root retry after CommitFailed");
    assert_eq!(db.get_attestations(&pubkey_hex).expect("query").len(), 1);
}
