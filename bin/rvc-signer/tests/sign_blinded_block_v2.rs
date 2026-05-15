//! Integration tests for the typed `sign_blinded_beacon_block` v2 RPC.

use tonic::Request;

mod helpers;
use helpers::{
    make_service_with_db, sample_blinded_block_ssz, sample_fork_info, KNOWN_PUBKEY_BYTES,
};

use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// --------------------------------------------------------------------------
// Test 1: happy path
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_blinded_block_typed_rpc_happy_path() {
    let (svc, db_path) = make_service_with_db();

    let req = Request::new(sv2::SignBlindedBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_blinded_block_ssz(200),
        fork_id: 4,
    });

    let resp =
        svc.sign_blinded_beacon_block(req).await.expect("sign_blinded_beacon_block succeeded");
    assert_eq!(resp.into_inner().signature.len(), 96);

    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(blocks.len(), 1, "block row must be committed");
    assert_eq!(blocks[0].slot, 200);
}

// --------------------------------------------------------------------------
// Test 2: double proposal rejected
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_blinded_block_double_proposal_rejected() {
    let (svc, db_path) = make_service_with_db();

    let req1 = Request::new(sv2::SignBlindedBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_blinded_block_ssz(300),
        fork_id: 4,
    });
    svc.sign_blinded_beacon_block(req1).await.expect("first sign succeeded");

    let mut different_body = sample_blinded_block_ssz(300);
    for b in &mut different_body[16..48] {
        *b ^= 0xFF;
    }
    let req2 = Request::new(sv2::SignBlindedBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: different_body,
        fork_id: 4,
    });
    let err =
        svc.sign_blinded_beacon_block(req2).await.expect_err("double proposal must be rejected");

    assert!(
        err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
        "expected FailedPrecondition or Aborted, got {:?}",
        err.code()
    );

    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    let slot_300_count = blocks.iter().filter(|b| b.slot == 300).count();
    assert_eq!(slot_300_count, 1, "DB must have exactly one row for slot 300");
}

// --------------------------------------------------------------------------
// Test 3: signer failure does NOT persist a row (A15 stage→sign→commit)
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_blinded_block_signer_failure_does_not_persist_row() {
    use helpers::make_service_with_db_unknown_key;

    let (svc, db_path) = make_service_with_db_unknown_key();

    let req = Request::new(sv2::SignBlindedBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_blinded_block_ssz(400),
        fork_id: 4,
    });

    let err =
        svc.sign_blinded_beacon_block(req).await.expect_err("sign should fail for unknown key");
    assert_eq!(err.code(), tonic::Code::NotFound);

    // Critical: no phantom row on signer failure (A15 guarantee).
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(
        blocks.is_empty(),
        "signer failure must not commit a slashing row — no phantom row (A15 stage→sign→commit)"
    );
}
