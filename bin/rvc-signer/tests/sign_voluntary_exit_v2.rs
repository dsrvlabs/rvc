//! Integration tests for the typed voluntary-exit v2 RPC: `sign_voluntary_exit`.
//!
//! Domain: DOMAIN_VOLUNTARY_EXIT + fork_info.current_version.
//! EIP-7044: the caller is responsible for passing the Capella-capped
//! `current_version` for post-Capella exits.  The server signs as-given.
//! Neither voluntary exits nor RANDAO are slashable.

use tonic::Request;

mod helpers;
use helpers::{make_service_with_db, make_service_with_db_unknown_key, KNOWN_PUBKEY_BYTES};

use crypto::{compute_domain, compute_signing_root};
use eth_types::{VoluntaryExit, DOMAIN_VOLUNTARY_EXIT};
use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// ── helpers ───────────────────────────────────────────────────────────────────

/// A ForkInfo for voluntary exits using Capella fork version (EIP-7044 cap).
fn capella_fork_info() -> sv2::ForkInfo {
    sv2::ForkInfo {
        previous_version: vec![0x02, 0x00, 0x00, 0x00],
        current_version: vec![0x03, 0x00, 0x00, 0x00], // Capella
        epoch: 0,
        genesis_validators_root: vec![0xaa; 32],
    }
}

/// Compute the expected signing root for a voluntary exit.
fn expected_signing_root(
    exit: &VoluntaryExit,
    current_version: [u8; 4],
    gvr: [u8; 32],
) -> [u8; 32] {
    let domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, current_version, gvr);
    compute_signing_root(exit, domain)
}

// ── Test 1: happy path — signature verifies against pubkey ───────────────────

#[tokio::test]
async fn test_voluntary_exit_happy_path() {
    let (svc, _db_path) = make_service_with_db();

    let epoch: u64 = 200;
    let validator_index: u64 = 99;
    let fork_info = capella_fork_info();

    let req = Request::new(sv2::SignVoluntaryExitRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(fork_info.clone()),
        epoch,
        validator_index,
        fork_id: 3, // Capella
    });

    let resp = svc
        .sign_voluntary_exit(req)
        .await
        .expect("sign_voluntary_exit must succeed with known key");
    let sig_bytes = resp.into_inner().signature;
    assert_eq!(sig_bytes.len(), 96, "signature must be 96 bytes");

    // Verify the signature against the expected signing root.
    let current_version: [u8; 4] = fork_info.current_version.try_into().unwrap();
    let gvr: [u8; 32] = fork_info.genesis_validators_root.try_into().unwrap();
    let exit = VoluntaryExit { epoch, validator_index };
    let signing_root = expected_signing_root(&exit, current_version, gvr);

    let pubkey = crypto::PublicKey::from_bytes(&*KNOWN_PUBKEY_BYTES).unwrap();
    let bls_sig = crypto::Signature::from_bytes(&sig_bytes).unwrap();
    assert!(
        bls_sig.verify(&pubkey, &signing_root).is_ok(),
        "signature must verify against DOMAIN_VOLUNTARY_EXIT + current_version signing root"
    );
}

// ── Test 2: missing fork_info → invalid_argument ──────────────────────────────

#[tokio::test]
async fn test_voluntary_exit_missing_fork_info_rejected() {
    let (svc, _db_path) = make_service_with_db();

    let req = Request::new(sv2::SignVoluntaryExitRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: None,
        epoch: 100,
        validator_index: 42,
        fork_id: 3,
    });

    let err = svc.sign_voluntary_exit(req).await.expect_err("missing fork_info must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ── Test 3: wrong pubkey length → invalid_argument ────────────────────────────

#[tokio::test]
async fn test_voluntary_exit_bad_pubkey_length_rejected() {
    let (svc, _db_path) = make_service_with_db();

    let req = Request::new(sv2::SignVoluntaryExitRequest {
        pubkey: vec![0x01u8; 32], // wrong length
        fork_info: Some(capella_fork_info()),
        epoch: 100,
        validator_index: 42,
        fork_id: 3,
    });

    let err = svc.sign_voluntary_exit(req).await.expect_err("wrong-length pubkey must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ── Test 4: unknown key returns NotFound ──────────────────────────────────────

#[tokio::test]
async fn test_voluntary_exit_unknown_key_returns_not_found() {
    let (svc, _db_path) = make_service_with_db_unknown_key();

    let req = Request::new(sv2::SignVoluntaryExitRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(capella_fork_info()),
        epoch: 100,
        validator_index: 42,
        fork_id: 3,
    });

    let err = svc.sign_voluntary_exit(req).await.expect_err("unknown key must return error");
    assert_eq!(err.code(), tonic::Code::NotFound);
}

// ── Test 5: voluntary exit is NOT slashable — two identical requests succeed ──

#[tokio::test]
async fn test_voluntary_exit_not_slashable_replay_ok() {
    let (svc, db_path) = make_service_with_db();

    for _ in 0..2 {
        let req = Request::new(sv2::SignVoluntaryExitRequest {
            pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
            fork_info: Some(capella_fork_info()),
            epoch: 200,
            validator_index: 99,
            fork_id: 3,
        });
        svc.sign_voluntary_exit(req).await.expect("voluntary exit must succeed — not slashable");
    }

    // DB must remain empty: voluntary exits never write to slashing DB.
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        blocks.is_empty() && attestations.is_empty(),
        "voluntary exit must not write to slashing DB"
    );
}

// ── Test 6: EIP-7044 — different fork versions produce different signatures ───

#[tokio::test]
async fn test_voluntary_exit_fork_version_affects_signature() {
    let (svc, _db_path) = make_service_with_db();

    // Capella fork version
    let req_capella = Request::new(sv2::SignVoluntaryExitRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sv2::ForkInfo {
            previous_version: vec![0x02, 0x00, 0x00, 0x00],
            current_version: vec![0x03, 0x00, 0x00, 0x00], // Capella
            epoch: 0,
            genesis_validators_root: vec![0xaa; 32],
        }),
        epoch: 200,
        validator_index: 99,
        fork_id: 3,
    });

    // Bellatrix fork version (pre-Capella)
    let req_bellatrix = Request::new(sv2::SignVoluntaryExitRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fork_info: Some(sv2::ForkInfo {
            previous_version: vec![0x01, 0x00, 0x00, 0x00],
            current_version: vec![0x02, 0x00, 0x00, 0x00], // Bellatrix
            epoch: 0,
            genesis_validators_root: vec![0xaa; 32],
        }),
        epoch: 200,
        validator_index: 99,
        fork_id: 2,
    });

    let sig_capella = svc.sign_voluntary_exit(req_capella).await.unwrap().into_inner().signature;
    let sig_bellatrix =
        svc.sign_voluntary_exit(req_bellatrix).await.unwrap().into_inner().signature;

    assert_ne!(
        sig_capella, sig_bellatrix,
        "different fork versions must produce different signatures (EIP-7044 sensitivity)"
    );
}
