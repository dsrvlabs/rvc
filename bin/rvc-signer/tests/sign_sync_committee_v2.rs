//! Integration tests for the typed sync-committee v2 RPCs:
//! `sign_sync_committee_message`, `sign_sync_aggregator_selection_data`,
//! `sign_contribution_and_proof`.
//!
//! Per FR-P0-3 and NFR-1 these RPCs are NOT slashable — no staging, no DB write.

use tonic::Request;

mod helpers;
use helpers::{
    make_service_with_db, make_service_with_db_unknown_key, sample_fork_info, KNOWN_PUBKEY_BYTES,
};

use crypto::{compute_domain, compute_signing_root};
use eth_types::{
    encode_sync_committee_contribution_ssz, ContributionAndProof, SyncAggregatorSelectionData,
    SyncCommitteeContribution, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
};
use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// ── helpers ───────────────────────────────────────────────────────────────────

fn sample_beacon_block_root() -> Vec<u8> {
    vec![0xBBu8; 32]
}

fn sample_contribution_ssz(slot: u64) -> Vec<u8> {
    let contrib = SyncCommitteeContribution {
        slot,
        beacon_block_root: [0xBB; 32],
        subcommittee_index: 2,
        aggregation_bits: vec![0xff; 16],
        signature: vec![0xcc; 96],
    };
    encode_sync_committee_contribution_ssz(&contrib, 4)
}

// ── Test 1: sign_sync_committee_message happy path ────────────────────────────

#[tokio::test]
async fn test_sync_message_typed_rpc_happy_path() {
    let (svc, _db_path) = make_service_with_db();

    let slot: u64 = 500;
    let beacon_block_root = sample_beacon_block_root();

    let req = Request::new(sv2::SignSyncCommitteeMessageRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        slot,
        beacon_block_root: beacon_block_root.clone(),
        fork_id: 4,
    });

    let resp =
        svc.sign_sync_committee_message(req).await.expect("sign_sync_committee_message succeeded");
    let sig = resp.into_inner().signature;
    assert_eq!(sig.len(), 96, "signature must be 96 bytes");

    // Verify the signature against the expected signing root.
    // The service uses current_version from fork_info directly (same pattern as randao).
    let fork_info = sample_fork_info();
    let current_version: [u8; 4] = fork_info.current_version.try_into().unwrap();
    let gvr: [u8; 32] = fork_info.genesis_validators_root.try_into().unwrap();
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, current_version, gvr);
    let bbr: [u8; 32] = beacon_block_root.try_into().unwrap();
    let signing_root = compute_signing_root(&bbr, domain);

    let pubkey = crypto::PublicKey::from_bytes(&*KNOWN_PUBKEY_BYTES).unwrap();
    let bls_sig = crypto::Signature::from_bytes(&sig).unwrap();
    assert!(
        bls_sig.verify(&pubkey, &signing_root).is_ok(),
        "signature must verify against DOMAIN_SYNC_COMMITTEE signing root"
    );
}

// ── Test 2: two requests for same (pubkey, slot) both succeed (unslashable) ───

#[tokio::test]
async fn test_sync_message_no_slashing_replay_allowed() {
    let (svc, db_path) = make_service_with_db();

    let slot: u64 = 777;
    let beacon_block_root = sample_beacon_block_root();

    for _ in 0..2 {
        let req = Request::new(sv2::SignSyncCommitteeMessageRequest {
            pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
            fork_info: Some(sample_fork_info()),
            slot,
            beacon_block_root: beacon_block_root.clone(),
            fork_id: 4,
        });
        svc.sign_sync_committee_message(req)
            .await
            .expect("both requests for same (pubkey, slot) must succeed — sync is unslashable");
    }

    // Confirm no slashing DB writes occurred (the DB must be empty for this key).
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        blocks.is_empty() && attestations.is_empty(),
        "sync messages must not write to slashing DB"
    );
}

// ── Test 3: sign_sync_aggregator_selection_data happy path ────────────────────

#[tokio::test]
async fn test_sync_aggregator_selection_happy_path() {
    let (svc, _db_path) = make_service_with_db();

    let slot: u64 = 600;
    let subcommittee_index: u64 = 3;

    let req = Request::new(sv2::SignSyncAggregatorSelectionDataRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        slot,
        subcommittee_index,
        fork_id: 4,
    });

    let resp = svc
        .sign_sync_aggregator_selection_data(req)
        .await
        .expect("sign_sync_aggregator_selection_data succeeded");
    let sig = resp.into_inner().signature;
    assert_eq!(sig.len(), 96, "signature must be 96 bytes");

    // Verify the signature.
    let fork_info = sample_fork_info();
    let current_version: [u8; 4] = fork_info.current_version.try_into().unwrap();
    let gvr: [u8; 32] = fork_info.genesis_validators_root.try_into().unwrap();
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, current_version, gvr);
    let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
    let signing_root = compute_signing_root(&selection_data, domain);

    let pubkey = crypto::PublicKey::from_bytes(&*KNOWN_PUBKEY_BYTES).unwrap();
    let bls_sig = crypto::Signature::from_bytes(&sig).unwrap();
    assert!(
        bls_sig.verify(&pubkey, &signing_root).is_ok(),
        "signature must verify against DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF signing root"
    );
}

// ── Test 4: sign_contribution_and_proof happy path ────────────────────────────

#[tokio::test]
async fn test_contribution_and_proof_happy_path() {
    let (svc, _db_path) = make_service_with_db();

    let slot: u64 = 700;
    let aggregator_index: u64 = 42;
    let subcommittee_index: u64 = 2;
    let contribution_ssz = sample_contribution_ssz(slot);
    let selection_proof = vec![0xcc; 96];

    let req = Request::new(sv2::SignContributionAndProofRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        aggregator_index,
        contribution_ssz: contribution_ssz.clone(),
        selection_proof: selection_proof.clone(),
        fork_id: 4,
    });

    let resp =
        svc.sign_contribution_and_proof(req).await.expect("sign_contribution_and_proof succeeded");
    let sig = resp.into_inner().signature;
    assert_eq!(sig.len(), 96, "signature must be 96 bytes");

    // Verify the signature against the expected signing root.
    let fork_info = sample_fork_info();
    let current_version: [u8; 4] = fork_info.current_version.try_into().unwrap();
    let gvr: [u8; 32] = fork_info.genesis_validators_root.try_into().unwrap();
    let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, current_version, gvr);

    let contribution = SyncCommitteeContribution {
        slot,
        beacon_block_root: [0xBB; 32],
        subcommittee_index,
        aggregation_bits: vec![0xff; 16],
        signature: vec![0xcc; 96],
    };
    let cap = ContributionAndProof { aggregator_index, contribution, selection_proof };
    let signing_root = compute_signing_root(&cap, domain);

    let pubkey = crypto::PublicKey::from_bytes(&*KNOWN_PUBKEY_BYTES).unwrap();
    let bls_sig = crypto::Signature::from_bytes(&sig).unwrap();
    assert!(
        bls_sig.verify(&pubkey, &signing_root).is_ok(),
        "signature must verify against DOMAIN_CONTRIBUTION_AND_PROOF signing root"
    );
}

// ── Test 5: backend KeyNotFound → NotFound status, DB unchanged ───────────────

#[tokio::test]
async fn test_sync_message_signer_failure_returns_err() {
    let (svc, db_path) = make_service_with_db_unknown_key();

    let req = Request::new(sv2::SignSyncCommitteeMessageRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sample_fork_info()),
        slot: 999,
        beacon_block_root: sample_beacon_block_root(),
        fork_id: 4,
    });

    let err = svc.sign_sync_committee_message(req).await.expect_err("unknown key must fail");
    assert_eq!(err.code(), tonic::Code::NotFound, "unknown key must return NotFound");

    // DB must remain completely empty — sync handlers never write to it.
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        blocks.is_empty() && attestations.is_empty(),
        "signer failure on sync message must not write to slashing DB"
    );
}
