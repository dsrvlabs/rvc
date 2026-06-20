//! Integration tests for the typed `sign_aggregate_and_proof` v2 RPC.
//!
//! # SS-2/SS-3 fix (Issue 2.10a)
//!
//! The previous handler erroneously called `stage_attestation` for the aggregate
//! path, effectively treating `DOMAIN_AGGREGATE_AND_PROOF` signing roots as
//! attestation slashing watermarks.  This constituted:
//!
//! - SS-2: double-staging the inner attestation (the VC had already committed it
//!   via `sign_attestation`).
//! - SS-3: re-interpreting an `AggregateAndProof` signing root as an attestation
//!   epoch watermark, mis-attributing `DOMAIN_AGGREGATE_AND_PROOF` roots to the
//!   attestation slot column.
//!
//! The fix (D-3, Issue 2.10a) routes this handler through
//! `SigningGate::sign_aggregate_and_proof`, which is explicitly non-slashable:
//! no `stage_attestation` call is made.
//!
//! Test 1 (`test_aggregate_typed_rpc_happy_path`) now asserts that:
//! - A valid signature is returned.
//! - **NO attestation row is committed** (the SS-2/SS-3 invariant).
//!
//! Test 2 (`test_aggregate_signer_failure_does_not_persist_row`) remains
//! unchanged: signer failure still leaves no row (no regression on M-1).

use tonic::Request;

mod helpers;
use helpers::{
    make_service_with_db, make_service_with_db_unknown_key, sample_fork_info, KNOWN_PUBKEY_BYTES,
};

use eth_types::{encode_attestation_ssz, Attestation, AttestationData, Checkpoint};
use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal SSZ-encoded `Attestation` for the given source/target epochs.
fn sample_aggregate_ssz(source_epoch: u64, target_epoch: u64) -> Vec<u8> {
    let att = Attestation {
        aggregation_bits: vec![0xff, 0x01],
        data: AttestationData {
            slot: target_epoch * 32,
            index: 0, // EIP-7549 zeroed
            beacon_block_root: [0x33u8; 32],
            source: Checkpoint { epoch: source_epoch, root: [0x44u8; 32] },
            target: Checkpoint { epoch: target_epoch, root: [0x55u8; 32] },
        },
        signature: vec![0xaa; 96],
    };
    encode_attestation_ssz(&att, 4)
}

fn make_aggregate_req(source_epoch: u64, target_epoch: u64) -> sv2::SignAggregateAndProofRequest {
    sv2::SignAggregateAndProofRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        aggregator_index: 42,
        aggregate_ssz: sample_aggregate_ssz(source_epoch, target_epoch),
        selection_proof: vec![0xbb; 96],
        fork_id: 4,
    }
}

// --------------------------------------------------------------------------
// Test 1: happy path — signature returned, NO attestation row committed (SS-2/SS-3)
// --------------------------------------------------------------------------

/// SS-2/SS-3 invariant: `sign_aggregate_and_proof` must NOT commit any
/// attestation row to the slashing DB.  The `AggregateAndProof` is signed over
/// `DOMAIN_AGGREGATE_AND_PROOF` — it is NOT slashable; its inner attestation's
/// watermark was already committed by `sign_attestation`.
///
/// The previous implementation (pre-2.10a) erroneously called `stage_attestation`
/// here.  After routing through `SigningGate::sign_aggregate_and_proof` (which is
/// explicitly non-slashable), no attestation row may be committed.
#[tokio::test]
async fn test_aggregate_typed_rpc_happy_path() {
    let (svc, db_path) = make_service_with_db();

    let req = Request::new(make_aggregate_req(9, 10));

    let resp = svc.sign_aggregate_and_proof(req).await.expect("sign_aggregate_and_proof succeeded");
    assert_eq!(resp.into_inner().signature.len(), 96, "signature must be 96 bytes");

    // SS-2/SS-3 fix: NO attestation row must be committed by the aggregate path.
    // (Previously the test asserted rows.len() == 1 — that assertion was the
    //  evidence of the bug.  Flip it to assert rows.is_empty().)
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        attestations.is_empty(),
        "sign_aggregate_and_proof must NOT commit any attestation row (SS-2/SS-3); \
         found {} row(s): {:?}",
        attestations.len(),
        attestations,
    );
}

// --------------------------------------------------------------------------
// Test 2: signer failure does NOT persist a row (A15 stage→sign→commit)
// --------------------------------------------------------------------------

#[tokio::test]
async fn test_aggregate_signer_failure_does_not_persist_row() {
    let (svc, db_path) = make_service_with_db_unknown_key();

    let req = Request::new(make_aggregate_req(9, 10));

    let err =
        svc.sign_aggregate_and_proof(req).await.expect_err("sign should fail for unknown key");
    assert_eq!(err.code(), tonic::Code::NotFound, "unknown key must return NotFound");

    // No row regardless (gate is non-slashable for aggregate).
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        attestations.is_empty(),
        "sign_aggregate_and_proof failure must not commit any attestation row"
    );
}
