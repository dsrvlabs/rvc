//! SS-1 regression test: v1 raw-root `sign` bypass.
//!
//! # What this test reproduces
//!
//! The v1 `sign(SignRequest { signing_root, pubkey })` RPC signs the
//! caller-supplied 32-byte `signing_root` directly via
//! `backend.sign(&signing_root, &pubkey)` with **zero** EIP-3076 /
//! slashing-protection consultation (see `service.rs:236–311` on `develop`).
//! `main.rs:507` registers this v1 service on the live listener.
//!
//! Because there is no slashing guard, two v1 sign requests for the same
//! pubkey with **different** 32-byte roots both succeed on the buggy
//! `develop` — each returns `Ok(signature)`.  This is the SS-1 double-sign
//! bypass.
//!
//! # What the test asserts (spec-correct / fixed behavior)
//!
//! After Issue 2.2 removes the v1 raw-root path, every v1 method must return
//! `tonic::Status::unimplemented(...)`.  The test asserts that **both** sign
//! calls return `Err` with `Code::Unimplemented`.
//!
//! | Phase      | Test result |
//! |------------|-------------|
//! | develop    | **RED** — both `svc.sign(...)` calls return `Ok(signature)` |
//! | Issue 2.2  | **GREEN** — both calls return `Unimplemented`               |

use tonic::Request;

mod helpers;
use helpers::{make_service_with_db, KNOWN_PUBKEY_BYTES};

use rvc_signer_bin::proto::signer::signer_service_server::SignerService;
use rvc_signer_bin::proto::signer::SignRequest;

/// Two v1 `sign` calls for the same pubkey with conflicting 32-byte roots
/// must each return `Unimplemented`.
///
/// On the buggy `develop` both calls currently return `Ok(signature)` — the
/// SS-1 bypass.  This test encodes the spec-correct expectation so it is RED
/// on `develop` and GREEN after Issue 2.2 removes the v1 raw-root path.
#[tokio::test]
async fn test_v1_sign_conflicting_roots_returns_unimplemented() {
    let (svc, _db_path) = make_service_with_db();

    // First request: signing_root = 0xAA…AA, same pubkey
    let req_a = Request::new(SignRequest {
        signing_root: vec![0xAAu8; 32],
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
    });

    // Second request: signing_root = 0xBB…BB — a conflicting root for the
    // same pubkey, which would constitute a double-sign if both succeed.
    let req_b = Request::new(SignRequest {
        signing_root: vec![0xBBu8; 32],
        pubkey: KNOWN_PUBKEY_BYTES.to_vec(),
    });

    let err_a = svc
        .sign(req_a)
        .await
        .expect_err("v1 sign must be removed (Unimplemented); got Ok on first conflicting root");

    assert_eq!(
        err_a.code(),
        tonic::Code::Unimplemented,
        "first v1 sign call must return Unimplemented, got {:?}: {}",
        err_a.code(),
        err_a.message()
    );

    let err_b = svc
        .sign(req_b)
        .await
        .expect_err("v1 sign must be removed (Unimplemented); got Ok on second conflicting root");

    assert_eq!(
        err_b.code(),
        tonic::Code::Unimplemented,
        "second v1 sign call must return Unimplemented, got {:?}: {}",
        err_b.code(),
        err_b.message()
    );
}
