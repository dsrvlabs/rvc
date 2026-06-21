//! Axum handlers for the Web3Signer HTTP API.
//!
//! `GET /upcheck`, `GET /api/v1/eth2/publicKeys`, and the live
//! `POST /api/v1/eth2/sign/{identifier}` sign route.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::ACCEPT;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};

use super::dispatch::{plan_sign, Slashing};
use super::pubkey::{resolve_identifier, PubkeyError};
use super::request::{SignPayload, SignRequest};
use super::response::{sign_response, HttpSignError};
use super::tls::{audit_cn, PeerCert};
use super::Web3SignerState;

/// `GET /upcheck` — liveness probe (FR-1).
///
/// Returns `200 OK` with the body `OK`. It takes no state and never calls the
/// gate, so orchestration health-checks succeed even while the signing path is
/// busy or erroring.
#[tracing::instrument(skip_all)]
pub(super) async fn upcheck() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// `GET /api/v1/eth2/publicKeys` (FR-2).
///
/// Returns `200` with a JSON array of `0x`-prefixed lowercase BLS public keys
/// for every key currently loaded in the backend — the same key set the gRPC
/// `list_public_keys` handler serves (one source of truth, both transports). An
/// empty backend returns `[]` (still `200`, not `404`). No gate call.
#[tracing::instrument(skip_all)]
pub(super) async fn public_keys(State(state): State<Web3SignerState>) -> Json<Vec<String>> {
    let keys =
        state.backend.public_keys().iter().map(|pk| format!("0x{}", hex::encode(pk))).collect();
    Json(keys)
}

/// `POST /api/v1/eth2/sign/{identifier}` (FR-3..FR-24).
///
/// Resolves `{identifier}` to a loaded key (`400`/`404`), decodes the request,
/// computes the signing root via the dispatcher, routes the matching
/// `SigningGate.sign_*` call (the single signing authority — slashing + lock +
/// timeout), and shapes the body per `Accept`. The gate result maps to the exact
/// HTTP status (`200/400/404/412/500`) via [`HttpSignError`].
#[tracing::instrument(skip_all)]
pub(super) async fn sign(
    State(state): State<Web3SignerState>,
    Path(identifier): Path<String>,
    peer: Option<Extension<PeerCert>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let accept = headers.get(ACCEPT).and_then(|v| v.to_str().ok());
    // Derive the audit CN from the TLS peer cert (Phase 3). `None` extension
    // (socket-free tests / no-TLS) or no client cert (Prysm / server-TLS-only)
    // both degrade to the configured default (`AUDIT_CN_DEFAULT`). The CN is
    // NEVER an authorization gate — a missing CN still signs.
    let cn = audit_cn(peer.as_ref().map(|Extension(p)| p), &state.audit.default_cn);
    match sign_inner(&state, &identifier, accept, &cn, body.as_ref()).await {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

/// The fallible core of [`sign`], split out so every failure renders through the
/// single [`HttpSignError`] → status mapping.
async fn sign_inner(
    state: &Web3SignerState,
    identifier: &str,
    accept: Option<&str>,
    cn: &str,
    body: &[u8],
) -> Result<Response, HttpSignError> {
    // 1. Resolve {identifier} to a loaded key: malformed → 400, unloaded → 404.
    //    The pre-check runs before any decode/gate work.
    let pubkey = resolve_identifier(identifier, state.backend.as_ref()).map_err(|e| match e {
        PubkeyError::Malformed => {
            HttpSignError::BadRequest("malformed public key identifier".to_string())
        }
        PubkeyError::NotLoaded => HttpSignError::UnknownKey,
    })?;

    // 2. Decode the body. A serde decode failure maps to a FIXED 400 — the
    //    decoder message can echo request bytes / field text and is NEVER
    //    surfaced to the client (SEC-INFO-01).
    let req: SignRequest = serde_json::from_slice(body)
        .map_err(|_| HttpSignError::BadRequest("invalid sign request body".to_string()))?;

    // 3. Compute the signing root + slashing inputs; enforce the signingRoot /
    //    fork_info policy (the dispatcher owns the domain).
    let plan = plan_sign(&req)?;
    let root = plan.signing_root;

    // 4. Route to the matching gate method. `cn` is the TLS peer-cert audit CN
    //    derived by the caller (Phase 3), or the audit default.
    let sig = match plan.slashing {
        Slashing::Block { slot, gvr } => state.gate.sign_block(&pubkey, slot, root, gvr, cn).await,
        Slashing::Attestation { source_epoch, target_epoch, gvr } => {
            state.gate.sign_attestation(&pubkey, source_epoch, target_epoch, root, gvr, cn).await
        }
        Slashing::NonSlashable => match &req.payload {
            SignPayload::RandaoReveal { .. } => state.gate.sign_randao_reveal(&pubkey, root).await,
            SignPayload::AggregationSlot { .. } => {
                state.gate.sign_selection_proof(&pubkey, root).await
            }
            // BLOCK_V2 / ATTESTATION are slashable and never yield NonSlashable;
            // a no-`_` match keeps a future payload variant a compile error.
            SignPayload::BlockV2 { .. } | SignPayload::Attestation { .. } => {
                return Err(HttpSignError::BadRequest("internal dispatch mismatch".to_string()))
            }
        },
    }
    .map_err(HttpSignError::Gate)?;

    // 5. Shape the success body per Accept (FR-17).
    Ok(sign_response(accept, &sig))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::Response;
    use tower::ServiceExt; // oneshot

    use crate::http_api::router;
    use crate::http_api::test_support::{
        test_keypair, test_state, MockBackend, RealSigningBackend,
    };

    use crypto::{compute_domain, compute_signing_root};
    // Import BeaconBlockHeader EXPLICITLY from eth_types: an unrelated all-String
    // `rvc-beacon::BeaconBlockHeader` DTO exists and would compute a garbage root.
    use eth_types::{
        AttestationData, BeaconBlockHeader, Checkpoint, Root, DOMAIN_BEACON_ATTESTER,
        DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
    };

    const CURRENT_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

    fn fork_info_json() -> &'static str {
        r#""fork_info": { "fork": { "previous_version": "0x03000000",
                                    "current_version": "0x04000000",
                                    "epoch": "100" },
             "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }"#
    }

    fn expected_gvr() -> Root {
        let half = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ];
        let mut g = [0u8; 32];
        g[..16].copy_from_slice(&half);
        g[16..].copy_from_slice(&half);
        g
    }

    /// The canonical attestation used by the happy-path tests, matching
    /// `attestation_body`.
    fn sample_attestation() -> AttestationData {
        AttestationData {
            slot: 5,
            index: 0,
            beacon_block_root: [0u8; 32],
            source: Checkpoint { epoch: 1, root: [0u8; 32] },
            target: Checkpoint { epoch: 2, root: [0u8; 32] },
        }
    }

    fn attestation_body(extra_signing_root: Option<&str>) -> String {
        let sr =
            extra_signing_root.map(|r| format!(r#""signingRoot": "{r}","#)).unwrap_or_default();
        format!(
            r#"{{ "type": "ATTESTATION", {fi}, {sr}
                  "attestation": {{ "slot": "5", "index": "0",
                                    "beacon_block_root": "0x{z}",
                                    "source": {{ "epoch": "1", "root": "0x{z}" }},
                                    "target": {{ "epoch": "2", "root": "0x{z}" }} }} }}"#,
            fi = fork_info_json(),
            z = "00".repeat(32),
        )
    }

    /// An ATTESTATION body with the same source/target epochs (1/2) as
    /// `attestation_body` but a caller-chosen `beacon_block_root`, so two calls
    /// with different bytes produce two DISTINCT attestations sharing a target
    /// epoch — a double vote (Issue 2.8b slashing harness, reused by 2.9).
    fn attestation_body_with_block_root(block_root_byte: u8) -> String {
        let br = format!("{block_root_byte:02x}").repeat(32);
        format!(
            r#"{{ "type": "ATTESTATION", {fi},
                  "attestation": {{ "slot": "5", "index": "0",
                                    "beacon_block_root": "0x{br}",
                                    "source": {{ "epoch": "1", "root": "0x{z}" }},
                                    "target": {{ "epoch": "2", "root": "0x{z}" }} }} }}"#,
            fi = fork_info_json(),
            z = "00".repeat(32),
        )
    }

    /// A `BeaconBlockHeader` (slot 3_000_000) with a caller-chosen `state_root`,
    /// so two headers at the same slot with different bytes are two DISTINCT
    /// blocks — a double block proposal. Matches `block_v2_body`.
    fn sample_block_header(state_root_byte: u8) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: 3_000_000,
            proposer_index: 12_345,
            parent_root: [0xaa; 32],
            state_root: [state_root_byte; 32],
            body_root: [0xcc; 32],
        }
    }

    fn block_v2_body(state_root_byte: u8) -> String {
        format!(
            r#"{{ "type": "BLOCK_V2", {fi},
                  "beacon_block": {{ "version": "DENEB",
                                     "block_header": {{ "slot": "3000000",
                                                        "proposer_index": "12345",
                                                        "parent_root": "0x{aa}",
                                                        "state_root": "0x{sr}",
                                                        "body_root": "0x{cc}" }} }} }}"#,
            fi = fork_info_json(),
            aa = "aa".repeat(32),
            sr = format!("{state_root_byte:02x}").repeat(32),
            cc = "cc".repeat(32),
        )
    }

    fn randao_body(epoch: u64) -> String {
        format!(
            r#"{{ "type": "RANDAO_REVEAL", {fi}, "randao_reveal": {{ "epoch": "{epoch}" }} }}"#,
            fi = fork_info_json(),
        )
    }

    fn aggregation_slot_body(slot: u64) -> String {
        format!(
            r#"{{ "type": "AGGREGATION_SLOT", {fi}, "aggregation_slot": {{ "slot": "{slot}" }} }}"#,
            fi = fork_info_json(),
        )
    }

    async fn post_sign(
        state: crate::http_api::Web3SignerState,
        identifier: &str,
        accept: Option<&str>,
        body: String,
    ) -> Response {
        let mut rb = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/eth2/sign/{identifier}"))
            .header("content-type", "application/json");
        if let Some(a) = accept {
            rb = rb.header("accept", a);
        }
        router(state).oneshot(rb.body(Body::from(body)).unwrap()).await.unwrap()
    }

    async fn body_bytes(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()
    }

    // ── Real-gate 412 slashing harness (Issue 2.8b, reused by 2.9) ───────────

    #[tokio::test]
    async fn conflicting_attestation_same_target_epoch_returns_412() {
        let (sk, pk_bytes) = test_keypair();
        // One real gate over one in-memory slashing DB shared across both POSTs.
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        // First attestation (target epoch 2) stages + commits → 200.
        let first =
            post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x00)).await;
        assert_eq!(first.status(), StatusCode::OK, "first attestation signs");

        // A DISTINCT attestation with the SAME target epoch (different
        // beacon_block_root → different signing root) is a double vote → 412.
        let second =
            post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x11)).await;
        assert_eq!(
            second.status(),
            StatusCode::PRECONDITION_FAILED,
            "double vote must be rejected by the gate as 412"
        );
        // The 412 body must not leak slashing-DB internals (paths/rusqlite).
        let body = String::from_utf8(body_bytes(second).await).unwrap();
        assert!(
            !body.contains(".db") && !body.to_lowercase().contains("sqlite"),
            "no DB internals: {body}"
        );
    }

    // ── RANDAO_REVEAL + AGGREGATION_SLOT (Issue 2.10): non-slashable KATs ─────

    /// Sign `body` with a fresh real-key gate and return the raw 96-byte sig.
    async fn sign_ok(body: String) -> Vec<u8> {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        let resp = post_sign(state, &id, Some("application/json"), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let hexsig = v["signature"].as_str().unwrap().strip_prefix("0x").unwrap().to_string();
        hex::decode(hexsig).unwrap()
    }

    #[tokio::test]
    async fn randao_reveal_kat_signs_epoch_under_randao_domain() {
        let (sk, _) = test_keypair();
        let domain = compute_domain(DOMAIN_RANDAO, CURRENT_VERSION, expected_gvr());
        let expected = sk.sign(&compute_signing_root(&42u64, domain)).to_bytes();
        assert_eq!(sign_ok(randao_body(42)).await, expected.to_vec());
    }

    #[tokio::test]
    async fn aggregation_slot_kat_signs_slot_under_selection_proof_domain() {
        let (sk, _) = test_keypair();
        let domain = compute_domain(DOMAIN_SELECTION_PROOF, CURRENT_VERSION, expected_gvr());
        let expected = sk.sign(&compute_signing_root(&77u64, domain)).to_bytes();
        assert_eq!(sign_ok(aggregation_slot_body(77)).await, expected.to_vec());
    }

    /// RANDAO and AGGREGATION_SLOT share neither domain nor gate method; the same
    /// scalar must NOT collide (0x02 RANDAO vs 0x05 SELECTION_PROOF).
    #[tokio::test]
    async fn randao_and_aggregation_slot_domains_do_not_collide() {
        assert_ne!(sign_ok(randao_body(7)).await, sign_ok(aggregation_slot_body(7)).await);
    }

    /// Non-slashable: re-signing the same RANDAO succeeds (no slashing-DB row).
    #[tokio::test]
    async fn randao_reveal_is_non_slashable_resign_ok() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        for _ in 0..2 {
            let resp = post_sign(state.clone(), &id, None, randao_body(9)).await;
            assert_eq!(resp.status(), StatusCode::OK, "randao is non-slashable");
        }
    }

    // ── BLOCK_V2 (Issue 2.9): KAT over the block header + double-proposal 412 ─

    #[tokio::test]
    async fn block_v2_happy_path_signs_the_block_header_root() {
        // BLOCK_V2 signs the `block_header` (a BeaconBlockHeader), never a
        // reconstructed block, under DOMAIN_BEACON_PROPOSER.
        let header = sample_block_header(0xbb);
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_VERSION, expected_gvr());
        let expected_root = compute_signing_root(&header, domain);

        let (sk, pk_bytes) = test_keypair();
        let expected_sig = sk.sign(&expected_root).to_bytes();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        let resp = post_sign(state, &id, Some("application/json"), block_v2_body(0xbb)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let got = v["signature"].as_str().unwrap().strip_prefix("0x").unwrap();
        assert_eq!(hex::decode(got).unwrap(), expected_sig.to_vec(), "route signs the header root");
    }

    #[tokio::test]
    async fn conflicting_block_same_slot_returns_412() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        // First block at slot 3_000_000 stages + commits → 200.
        let first = post_sign(state.clone(), &id, None, block_v2_body(0xaa)).await;
        assert_eq!(first.status(), StatusCode::OK, "first block signs");

        // A DISTINCT block at the SAME slot (different state_root → different
        // signing root) is a double block proposal → 412.
        let second = post_sign(state.clone(), &id, None, block_v2_body(0xbb)).await;
        assert_eq!(second.status(), StatusCode::PRECONDITION_FAILED, "double proposal → 412");

        // Safe-body check (2.8b review polish): the 412 surfaces only the safe
        // slashing-violation detail, never the signature or DB internals.
        let body = String::from_utf8(body_bytes(second).await).unwrap();
        assert!(body.contains("slashing protection violation"), "safe violation message: {body}");
        assert!(!body.contains("0x") && !body.contains(".db"), "no signature/DB internals: {body}");
    }

    // ── ATTESTATION happy path — KAT: the route signs the correct root ───────

    #[tokio::test]
    async fn attestation_happy_path_signs_the_expected_root() {
        let att = sample_attestation();
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, CURRENT_VERSION, expected_gvr());
        let expected_root = compute_signing_root(&att, domain);

        let (sk, pk_bytes) = test_keypair();
        let expected_sig = sk.sign(&expected_root).to_bytes();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        let resp = post_sign(state, &id, Some("application/json"), attestation_body(None)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let v: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let got = v["signature"].as_str().unwrap().strip_prefix("0x").unwrap();
        let got_sig = hex::decode(got).unwrap();
        assert_eq!(got_sig, expected_sig.to_vec(), "route must sign the dispatcher-computed root");
    }

    #[tokio::test]
    async fn attestation_text_plain_returns_bare_hex_signature() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        let resp = post_sign(state, &id, Some("text/plain"), attestation_body(None)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(body.starts_with("0x") && !body.contains('{'), "bare 0x.. body: {body}");
        assert_eq!(body.len(), 2 + 192, "0x + 96-byte sig hex");
    }

    // ── Request hardening (Issue 2.11) ───────────────────────────────────────

    #[tokio::test]
    async fn oversized_body_returns_413() {
        // Empty backend: were the body cap missing, the route would resolve the
        // (unloaded) key and return 404 — so a 413 strictly proves the cap fired
        // at extraction, before any handler/gate work.
        let state = test_state(Arc::new(MockBackend::empty()));
        let id = format!("0x{}", "ab".repeat(48));
        let oversized = "x".repeat((1 << 20) + 1); // 1 MiB + 1 byte
        let resp = post_sign(state, &id, None, oversized).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ── Pre-gate error paths ─────────────────────────────────────────────────

    #[tokio::test]
    async fn unloaded_key_returns_404() {
        let state = test_state(Arc::new(MockBackend::empty()));
        // A well-formed 48-byte hex key that is simply not loaded.
        let id = format!("0x{}", "ab".repeat(48));
        let resp = post_sign(state, &id, None, attestation_body(None)).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_identifier_returns_400() {
        let state = test_state(Arc::new(MockBackend::empty()));
        let resp = post_sign(state, "0xdeadbeef", None, attestation_body(None)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_body_returns_400_without_decoder_detail() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        let resp = post_sign(state, &id, None, "{ this is not json".to_string()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        // SEC-INFO-01: a fixed body, no serde decoder text (no line/column/"expected").
        assert_eq!(body, "invalid sign request body");
        assert!(
            !body.contains("column") && !body.contains("expected"),
            "no decoder detail: {body}"
        );
    }

    #[tokio::test]
    async fn signing_root_mismatch_returns_400() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        let bad = format!("0x{}", "ff".repeat(32));
        let resp = post_sign(state, &id, None, attestation_body(Some(&bad))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn missing_fork_info_returns_400() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        let body = format!(
            r#"{{ "type": "ATTESTATION",
                  "attestation": {{ "slot": "5", "index": "0",
                                    "beacon_block_root": "0x{z}",
                                    "source": {{ "epoch": "1", "root": "0x{z}" }},
                                    "target": {{ "epoch": "2", "root": "0x{z}" }} }} }}"#,
            z = "00".repeat(32),
        );
        let resp = post_sign(state, &id, None, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
