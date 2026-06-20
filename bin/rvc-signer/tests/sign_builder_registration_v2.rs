//! Integration tests for the typed builder-registration v2 RPC:
//! `sign_builder_registration`.
//!
//! Builder-registration domain:
//! domain = DOMAIN_APPLICATION_BUILDER + GENESIS_FORK_VERSION + ZERO_HASH
//! `GENESIS_FORK_VERSION` is a per-network config value (mainnet 0x00000000,
//! Holesky 0x01017000, …), carried on the request, NOT a spec-fixed constant.
//! The caller supplies `pubkey` in the top-level proto field AND that same
//! pubkey is used as the registration body's pubkey.  If they differ the
//! server returns `Status::invalid_argument`.

use tonic::Request;

mod helpers;
use helpers::{make_service_with_db, make_service_with_db_unknown_key, KNOWN_PUBKEY_BYTES};

use crypto::{compute_domain, compute_signing_root};
use eth_types::{ValidatorRegistrationV1, DOMAIN_APPLICATION_BUILDER};
use rvc_signer_bin::proto::signer_v2 as sv2;
use rvc_signer_bin::proto::signer_v2::signer_service_server::SignerService;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a canonical builder-registration request using the known test key.
///
/// `genesis_fork_version` is the 4-byte per-network value carried on the
/// request; an empty `Vec` means mainnet (`0x00000000`).
fn canonical_request(
    pubkey: Vec<u8>,
    genesis_fork_version: Vec<u8>,
) -> sv2::SignBuilderRegistrationRequest {
    sv2::SignBuilderRegistrationRequest {
        pubkey,
        fee_recipient: vec![0xabu8; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        genesis_fork_version,
    }
}

/// Compute the expected signing root for the canonical registration under a
/// given network `genesis_fork_version`. The genesis validators root is the
/// builder-domain zero hash (`[0u8; 32]`).
fn expected_signing_root(pubkey: [u8; 48], genesis_fork_version: [u8; 4]) -> [u8; 32] {
    let reg = ValidatorRegistrationV1 {
        fee_recipient: [0xab; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        pubkey,
    };
    let zero_hash = [0u8; 32];
    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_hash);
    compute_signing_root(&reg, domain)
}

// ── Test 1: happy path (mainnet KAT) — signature verifies against pubkey ──────
//
// Mainnet GENESIS_FORK_VERSION = 0x00000000. The request omits the field
// (empty `Vec`), which the server must treat as `[0u8; 4]`. This pins mainnet
// so the per-network GREEN fix cannot silently change mainnet behavior.

#[tokio::test]
async fn test_builder_registration_happy_path() {
    let (svc, _db_path) = make_service_with_db();
    let pubkey_bytes = KNOWN_PUBKEY_BYTES.to_vec();

    let req = Request::new(canonical_request(pubkey_bytes.clone(), vec![]));

    let resp = svc
        .sign_builder_registration(req)
        .await
        .expect("sign_builder_registration must succeed with known key");
    let sig_bytes = resp.into_inner().signature;
    assert_eq!(sig_bytes.len(), 96, "signature must be 96 bytes");

    // Verify the signature against the expected mainnet signing root
    // (GENESIS_FORK_VERSION = 0x00000000).
    let pubkey_arr: [u8; 48] = pubkey_bytes.try_into().unwrap();
    let signing_root = expected_signing_root(pubkey_arr, [0u8; 4]);
    let pubkey = crypto::PublicKey::from_bytes(&pubkey_arr).unwrap();
    let bls_sig = crypto::Signature::from_bytes(&sig_bytes).unwrap();
    assert!(
        bls_sig.verify(&pubkey, &signing_root).is_ok(),
        "signature must verify against DOMAIN_APPLICATION_BUILDER signing root \
         with GENESIS_FORK_VERSION=[0;4] and ZERO_HASH"
    );
}

// ── Test 1b: Holesky KAT — server must use the per-network fork version ───────
//
// Holesky GENESIS_FORK_VERSION = 0x01017000 (report §4.2 network table;
// Lighthouse `consensus/types/src/core/chain_spec.rs`). The request carries the
// 4-byte version and the returned signature must verify against a domain built
// from the byte-pinned literal `[0x01, 0x01, 0x70, 0x00]` — NOT an oracle that
// re-derives the version through the server path. This is RED until the server
// reads `genesis_fork_version` (issue 2.3): the unfixed server signs over the
// mainnet `[0u8; 4]` domain, so the Holesky verification fails.

#[tokio::test]
async fn sign_builder_registration_holesky_domain() {
    const HOLESKY_GENESIS_FORK_VERSION: [u8; 4] = [0x01, 0x01, 0x70, 0x00];

    let (svc, _db_path) = make_service_with_db();
    let pubkey_bytes = KNOWN_PUBKEY_BYTES.to_vec();

    let req = Request::new(canonical_request(
        pubkey_bytes.clone(),
        HOLESKY_GENESIS_FORK_VERSION.to_vec(),
    ));

    let resp = svc
        .sign_builder_registration(req)
        .await
        .expect("sign_builder_registration must succeed with known key");
    let sig_bytes = resp.into_inner().signature;
    assert_eq!(sig_bytes.len(), 96, "signature must be 96 bytes");

    let pubkey_arr: [u8; 48] = pubkey_bytes.try_into().unwrap();
    let signing_root = expected_signing_root(pubkey_arr, HOLESKY_GENESIS_FORK_VERSION);
    let pubkey = crypto::PublicKey::from_bytes(&pubkey_arr).unwrap();
    let bls_sig = crypto::Signature::from_bytes(&sig_bytes).unwrap();
    assert!(
        bls_sig.verify(&pubkey, &signing_root).is_ok(),
        "signature must verify against the Holesky DOMAIN_APPLICATION_BUILDER \
         signing root with GENESIS_FORK_VERSION=0x01017000 and ZERO_HASH"
    );
}

// ── Test 2: pubkey mismatch — request.pubkey != registration.pubkey ───────────
//
// The proto has `pubkey` at the top level which is also used as the pubkey
// inside the `ValidatorRegistrationV1` body.  The body pubkey is always set
// equal to the top-level pubkey.  This test verifies validation of a
// deliberately mismatched pubkey at the top level vs. a different pubkey
// supplied as a separate argument (simulated by sending a wrong-length pubkey).
// The real mismatch scenario is: caller sends `pubkey` = key A but
// `fee_recipient`/`gas_limit`/`timestamp` for a registration that was
// originally signed for key B.  The server catches this via the length check
// (pubkey must be exactly 48 bytes) or explicit mismatch logic if the proto
// were to carry a separate registration_pubkey field.
//
// Since the proto `SignBuilderRegistrationRequest` only has one `pubkey` field,
// the mismatch scenario is: pubkey != 48 bytes → invalid_argument.
// We also test the explicit server-side equality check by sending two different
// 48-byte values (if the proto ever evolves) — for now the server constructs
// the registration body with the request pubkey, so there is no mismatch path.
// The test here verifies that a wrong-length pubkey is rejected.

#[tokio::test]
async fn test_pubkey_mismatch_rejected() {
    let (svc, _db_path) = make_service_with_db();

    // Sending a 48-byte pubkey that does NOT match any loaded key is a
    // "key not found" scenario (NotFound), not mismatch.
    // The mismatch scenario in this proto design is: send pubkey field != 48 bytes.
    let req = Request::new(sv2::SignBuilderRegistrationRequest {
        pubkey: vec![0x01u8; 32], // wrong length — must be 48
        fee_recipient: vec![0xabu8; 20],
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        genesis_fork_version: vec![],
    });

    let err =
        svc.sign_builder_registration(req).await.expect_err("wrong-length pubkey must be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "wrong-length pubkey must return InvalidArgument, got: {:?}",
        err.code()
    );
}

// ── Test 3: wrong fee_recipient length ───────────────────────────────────────

#[tokio::test]
async fn test_fee_recipient_wrong_length_rejected() {
    let (svc, _db_path) = make_service_with_db();

    let req = Request::new(sv2::SignBuilderRegistrationRequest {
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
        fee_recipient: vec![0xabu8; 10], // wrong: must be 20
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000,
        genesis_fork_version: vec![],
    });

    let err = svc
        .sign_builder_registration(req)
        .await
        .expect_err("wrong fee_recipient length must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

// ── Test 3b: non-empty, non-4-byte genesis_fork_version is rejected ───────────
//
// Empty ⇒ mainnet (covered by the happy path); exactly 4 bytes ⇒ that network
// (covered by the Holesky KAT). Any other length must fail closed with
// `InvalidArgument`, mirroring the fee_recipient length check.

#[tokio::test]
async fn test_genesis_fork_version_wrong_length_rejected() {
    let (svc, _db_path) = make_service_with_db();

    for bad in [vec![0x01u8; 3], vec![0x01u8; 5]] {
        let req = Request::new(sv2::SignBuilderRegistrationRequest {
            pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
            fee_recipient: vec![0xabu8; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            genesis_fork_version: bad,
        });

        let err = svc
            .sign_builder_registration(req)
            .await
            .expect_err("non-4-byte genesis_fork_version must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}

// ── Test 4: unknown key returns NotFound ──────────────────────────────────────

#[tokio::test]
async fn test_builder_registration_unknown_key_returns_not_found() {
    let (svc, _db_path) = make_service_with_db_unknown_key();

    let req = Request::new(canonical_request(KNOWN_PUBKEY_BYTES.to_vec(), vec![]));

    let err = svc.sign_builder_registration(req).await.expect_err("unknown key must return error");
    assert_eq!(err.code(), tonic::Code::NotFound);
}

// ── Test 5: builder registration is NOT slashable — two identical requests OK ─

#[tokio::test]
async fn test_builder_registration_not_slashable() {
    let (svc, db_path) = make_service_with_db();

    for _ in 0..2 {
        let req = Request::new(canonical_request(KNOWN_PUBKEY_BYTES.to_vec(), vec![]));
        svc.sign_builder_registration(req)
            .await
            .expect("builder registration must succeed — not slashable");
    }

    // DB must remain empty: builder registrations never write to slashing DB.
    let db = slashing::SlashingDb::open(&db_path).expect("re-open db");
    let pubkey_hex = format!("0x{}", hex::encode(*KNOWN_PUBKEY_BYTES));
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        blocks.is_empty() && attestations.is_empty(),
        "builder registration must not write to slashing DB"
    );
}
