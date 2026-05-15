//! Integration tests for the typed `sign_attestation_data` v2 RPC.

use tonic::Request;

mod helpers;
use helpers::{
    make_service_with_db, make_service_with_db_unknown_key, sample_fork_info, KNOWN_PUBKEY_BYTES,
};

use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// ── helpers ───────────────────────────────────────────────────────────────────

fn sample_attestation_data(source_epoch: u64, target_epoch: u64) -> sv2::AttestationData {
    sv2::AttestationData {
        slot: target_epoch * 32, // slot = target_epoch * SLOTS_PER_EPOCH
        index: 0,                // EIP-7549: client must zero for Electra+
        beacon_block_root: vec![0x33u8; 32],
        source: Some(sv2::Checkpoint { epoch: source_epoch, root: vec![0x44u8; 32] }),
        target: Some(sv2::Checkpoint { epoch: target_epoch, root: vec![0x55u8; 32] }),
    }
}

// --------------------------------------------------------------------------
// Test 1: happy path — signature returned + row committed in DB
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_attestation_typed_rpc_happy_path() {
    let (svc, db_path) = make_service_with_db();

    let req = Request::new(sv2::SignAttestationDataRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(sample_attestation_data(9, 10)),
        fork_id: 4,
    });

    let resp = svc.sign_attestation_data(req).await.expect("sign_attestation_data succeeded");
    assert_eq!(resp.into_inner().signature.len(), 96, "signature must be 96 bytes");

    // Row must be committed in the DB
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert_eq!(attestations.len(), 1, "attestation row must be committed after successful sign");
    assert_eq!(attestations[0].source_epoch, 9);
    assert_eq!(attestations[0].target_epoch, 10);
}

// --------------------------------------------------------------------------
// Test 2: double vote rejected — same (cn, pubkey, target_epoch), different roots
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_attestation_double_vote_rejected() {
    let (svc, db_path) = make_service_with_db();

    // First request — succeeds
    let req1 = Request::new(sv2::SignAttestationDataRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(sample_attestation_data(9, 10)),
        fork_id: 4,
    });
    svc.sign_attestation_data(req1).await.expect("first sign succeeded");

    // Second request — same target_epoch (10) but different beacon_block_root → different signing root
    let mut different_data = sample_attestation_data(9, 10);
    different_data.beacon_block_root = vec![0xFFu8; 32]; // mutated root → different signing root
    let req2 = Request::new(sv2::SignAttestationDataRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(different_data),
        fork_id: 4,
    });
    let err = svc.sign_attestation_data(req2).await.expect_err("double vote must be rejected");

    assert!(
        err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
        "expected FailedPrecondition or Aborted for double vote, got {:?}",
        err.code()
    );

    // DB must still have exactly one row for target_epoch=10
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    let epoch_10_count = attestations.iter().filter(|a| a.target_epoch == 10).count();
    assert_eq!(epoch_10_count, 1, "DB must have exactly one row for target_epoch=10");
}

// --------------------------------------------------------------------------
// Test 3: surround vote rejected — new (source, target) surrounds existing
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_attestation_surround_vote_rejected() {
    let (svc, db_path) = make_service_with_db();

    // First request: source=5, target=10
    let req1 = Request::new(sv2::SignAttestationDataRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(sample_attestation_data(5, 10)),
        fork_id: 4,
    });
    svc.sign_attestation_data(req1).await.expect("first sign succeeded");

    // Second request: source=3 (< 5) and target=12 (> 10) — surrounds the first
    let surrounding_data = sample_attestation_data(3, 12);
    let req2 = Request::new(sv2::SignAttestationDataRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(surrounding_data),
        fork_id: 4,
    });
    let err = svc.sign_attestation_data(req2).await.expect_err("surrounding vote must be rejected");

    assert!(
        err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
        "expected FailedPrecondition or Aborted for surround vote, got {:?}",
        err.code()
    );

    // Only the first row must be in DB
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert_eq!(attestations.len(), 1, "DB must have exactly one row (surround rejected)");
    assert_eq!(attestations[0].target_epoch, 10);
}

// --------------------------------------------------------------------------
// Test 4: signer failure does NOT persist a row (A15 stage→sign→commit)
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_attestation_signer_failure_does_not_persist_row() {
    let (svc, db_path) = make_service_with_db_unknown_key();

    let req = Request::new(sv2::SignAttestationDataRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(sample_attestation_data(9, 10)),
        fork_id: 4,
    });

    let err = svc.sign_attestation_data(req).await.expect_err("sign should fail for unknown key");
    assert_eq!(err.code(), tonic::Code::NotFound, "unknown key must return NotFound");

    // Critical: the slashing row must NOT be committed when the signer fails.
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        attestations.is_empty(),
        "signer failure must not commit a slashing row — no phantom row (A15 stage→sign→commit)"
    );
}
