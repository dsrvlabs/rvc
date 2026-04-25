//! Integration tests for the typed `sign_beacon_block` v2 RPC.

use tonic::Request;

mod helpers;
use helpers::{make_service_with_db, sample_block_ssz, sample_fork_info, KNOWN_PUBKEY_BYTES};

use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// --------------------------------------------------------------------------
// Test 1: happy path — signature returned, row committed in DB
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_block_typed_rpc_happy_path() {
    let (svc, db_path) = make_service_with_db();

    let req = Request::new(sv2::SignBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(42),
        fork_id: 4,
    });

    let resp = svc.sign_beacon_block(req).await.expect("sign_beacon_block succeeded");
    assert_eq!(resp.into_inner().signature.len(), 96, "signature must be 96 bytes");

    // Row must be committed in the DB
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(blocks.len(), 1, "block row must be committed after successful sign");
    assert_eq!(blocks[0].slot, 42);
}

// --------------------------------------------------------------------------
// Test 2: double proposal rejected
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_block_double_proposal_rejected() {
    let (svc, db_path) = make_service_with_db();

    // First request — succeeds
    let req1 = Request::new(sv2::SignBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(100),
        fork_id: 4,
    });
    svc.sign_beacon_block(req1).await.expect("first sign succeeded");

    // Second request — same slot 100, different block body (different signing root)
    let mut different_body = sample_block_ssz(100);
    for b in &mut different_body[16..48] {
        *b ^= 0xFF;
    }
    let req2 = Request::new(sv2::SignBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: different_body,
        fork_id: 4,
    });
    let err = svc.sign_beacon_block(req2).await.expect_err("double proposal must be rejected");

    assert!(
        err.code() == tonic::Code::FailedPrecondition || err.code() == tonic::Code::Aborted,
        "expected FailedPrecondition or Aborted, got {:?}",
        err.code()
    );

    // DB must still have exactly one row for slot 100
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    let slot_100_count = blocks.iter().filter(|b| b.slot == 100).count();
    assert_eq!(slot_100_count, 1, "DB must have exactly one row for slot 100");
}

// --------------------------------------------------------------------------
// Test 3: signer failure returns NotFound; slashing row is pre-committed
//
// DESIGN NOTE: This implementation uses "commit-before-sign" to avoid holding
// the !Send parking_lot::MutexGuard across the async sign call.  The slashing
// row is committed before the sign; a signer failure leaves the row in the DB
// (preventing slashable replay), which is the safe conservative behavior.
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_block_signer_failure_returns_not_found() {
    use helpers::make_service_with_db_unknown_key;

    let (svc, db_path) = make_service_with_db_unknown_key();

    let req = Request::new(sv2::SignBeaconBlockRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        block_ssz: sample_block_ssz(77),
        fork_id: 4,
    });

    let err = svc.sign_beacon_block(req).await.expect_err("sign should fail for unknown key");
    assert_eq!(err.code(), tonic::Code::NotFound, "unknown key must return NotFound");

    // Row IS committed (conservative design) — prevents slashable replay
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert_eq!(blocks.len(), 1, "slashing row is committed before sign (conservative design)");
    assert_eq!(blocks[0].slot, 77);
}
