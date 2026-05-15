//! Integration tests for the typed `sign_randao_reveal` v2 RPC.
//!
//! RANDAO is unslashable per FR-P0-3 — two requests for the same epoch succeed.

use tonic::Request;

mod helpers;
use helpers::{make_service_with_db, sample_fork_info, KNOWN_PUBKEY_BYTES};

use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// --------------------------------------------------------------------------
// Test: two randao requests for same epoch both succeed (no slashing check)
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_randao_no_slashing_check() {
    let (svc, _db_path) = make_service_with_db();

    let req1 = Request::new(sv2::SignRandaoRevealRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        epoch: 50,
        fork_id: 4,
    });
    let resp1 = svc.sign_randao_reveal(req1).await.expect("first randao succeeded");
    assert_eq!(resp1.into_inner().signature.len(), 96);

    // Second request for the same epoch — must also succeed (RANDAO is unslashable)
    let req2 = Request::new(sv2::SignRandaoRevealRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        epoch: 50,
        fork_id: 4,
    });
    let resp2 = svc.sign_randao_reveal(req2).await.expect("second randao also succeeded");
    assert_eq!(resp2.into_inner().signature.len(), 96);
}
