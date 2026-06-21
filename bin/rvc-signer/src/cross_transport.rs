//! Cross-transport slashing-serialization test (Issue 3.7).
//!
//! Proves the gate-hoist payoff (FR-26, ADR-003, R2): the ONE shared
//! `Arc<SigningGate>` — reached via BOTH the gRPC service and the HTTP route —
//! serializes slashing protection. A block signed through one transport slashes
//! a conflicting block at the same slot through the other, because both share
//! the same slashing DB (and the same in-memory `ValidatorLockMap`).
//!
//! A two-gates-over-one-DB design would still share the SQLite DB but split the
//! in-memory lock; this test is the regression backstop that the realized
//! single-shared-`Arc` design holds. It deliberately builds the gate exactly
//! once (as `run_serve` does, 1.2/3.5) and hands the SAME `Arc` to both
//! transports — it would fail if the gate were constructed per-transport.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::backend::SigningBackend;
use crate::http_api::test_support::{test_keypair, RealSigningBackend};
use crate::http_api::{router, AuditCfg, Web3SignerState};
use crate::proto::signer_v2::signer_service_server::SignerService as SignerServiceV2;
use crate::proto::signer_v2::{ForkInfo, SignBeaconBlockRequest};
use crate::service::SignerServiceImpl;

/// The single slot both transports propose at (the conflict).
const SLOT: u64 = 7_000_000;
/// The shared genesis validators root. The slashing check is pubkey+gvr-scoped,
/// so BOTH transports must use the same gvr to land in one slashing namespace.
const GVR: [u8; 32] = [0u8; 32];
const CURRENT_VERSION: &str = "0x04000000";

/// Build the shared `(backend, gate, pubkey)` exactly as `run_serve` does:
/// one backend, one in-memory slashing DB, one `Arc<SigningGate>`.
fn shared() -> (Arc<dyn SigningBackend>, Arc<signer::SigningGate>, [u8; 48]) {
    let (sk, pubkey) = test_keypair();
    let backend: Arc<dyn SigningBackend> = Arc::new(RealSigningBackend::with_key(sk));
    let db = Arc::new(slashing::SlashingDb::open_in_memory().expect("in-memory slashing DB"));
    let gate = Arc::new(SignerServiceImpl::build_gate(Arc::clone(&backend), db));
    (backend, gate, pubkey)
}

/// gRPC `sign_beacon_block` over the SAME shared gate (a full BeaconBlock at `SLOT`).
async fn grpc_sign_block(
    backend: &Arc<dyn SigningBackend>,
    gate: &Arc<signer::SigningGate>,
    pubkey: &[u8; 48],
) -> Result<(), tonic::Code> {
    use eth_types::{encode_beacon_block_ssz, BeaconBlock};
    let block = BeaconBlock {
        slot: SLOT,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: vec![0xde, 0xad],
    };
    let svc = SignerServiceImpl::new_v2_with_gate(
        Arc::clone(backend),
        "basic".to_string(),
        Arc::clone(gate),
    );
    let req = tonic::Request::new(SignBeaconBlockRequest {
        pubkey: pubkey.to_vec(),
        fork_info: Some(ForkInfo {
            previous_version: vec![0x04, 0x00, 0x00, 0x00],
            current_version: vec![0x04, 0x00, 0x00, 0x00],
            epoch: 0,
            genesis_validators_root: GVR.to_vec(),
        }),
        block_ssz: encode_beacon_block_ssz(&block, 4),
        fork_id: 4,
    });
    SignerServiceV2::sign_beacon_block(&svc, req).await.map(|_| ()).map_err(|s| s.code())
}

/// HTTP `BLOCK_V2` over the SAME shared gate (a BeaconBlockHeader at `SLOT`).
/// Its signing root differs from the gRPC full-block root, so at the same slot
/// the two are a double block proposal.
async fn http_sign_block(
    backend: &Arc<dyn SigningBackend>,
    gate: &Arc<signer::SigningGate>,
    pubkey: &[u8; 48],
) -> StatusCode {
    let state = Web3SignerState {
        gate: Arc::clone(gate),
        backend: Arc::clone(backend),
        audit: AuditCfg::default(),
    };
    let id = format!("0x{}", hex::encode(pubkey));
    let body = format!(
        r#"{{ "type": "BLOCK_V2",
              "fork_info": {{ "fork": {{ "previous_version": "0x04000000",
                                         "current_version": "{cv}", "epoch": "0" }},
                              "genesis_validators_root": "0x{gvr}" }},
              "beacon_block": {{ "version": "DENEB",
                                 "block_header": {{ "slot": "{SLOT}", "proposer_index": "1",
                                                    "parent_root": "0x{r1}",
                                                    "state_root": "0x{r2}",
                                                    "body_root": "0x{r3}" }} }} }}"#,
        cv = CURRENT_VERSION,
        gvr = hex::encode(GVR),
        r1 = "11".repeat(32),
        r2 = "22".repeat(32),
        r3 = "33".repeat(32),
    );
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/eth2/sign/{id}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    router(state).oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn grpc_block_then_conflicting_http_block_is_slashed() {
    let (backend, gate, pubkey) = shared();

    // gRPC signs a block at SLOT — commits the proposal watermark.
    assert!(grpc_sign_block(&backend, &gate, &pubkey).await.is_ok(), "first gRPC block signs");

    // HTTP signs a DIFFERENT block at the SAME slot over the SAME gate → 412.
    assert_eq!(
        http_sign_block(&backend, &gate, &pubkey).await,
        StatusCode::PRECONDITION_FAILED,
        "the shared gate must slash the conflicting HTTP block (one slashing DB)"
    );
}

#[tokio::test]
async fn http_block_then_conflicting_grpc_block_is_slashed() {
    let (backend, gate, pubkey) = shared();

    // HTTP signs a block at SLOT — commits the watermark.
    assert_eq!(
        http_sign_block(&backend, &gate, &pubkey).await,
        StatusCode::OK,
        "first HTTP block signs"
    );

    // gRPC signs a DIFFERENT block at the SAME slot over the SAME gate → slashed.
    assert_eq!(
        grpc_sign_block(&backend, &gate, &pubkey).await,
        Err(tonic::Code::FailedPrecondition),
        "the shared gate must slash the conflicting gRPC block (one slashing DB)"
    );
}
