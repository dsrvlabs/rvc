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
use crate::audit;

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

    // Audit posture (Issue 4.4): emit exactly one structured entry per request —
    // success at `info`, every rejection at `warn` — carrying only metadata
    // (pubkey identifier, Web3Signer `type`, outcome, peer CN, backend, latency).
    // NEVER the request body, signing root, or signature. `rpc_type` is filled by
    // `sign_inner` once the payload parses, so a pre-parse 400 audits with no
    // `type` rather than a wrong one.
    let started = std::time::Instant::now();
    let mut rpc_type: Option<&'static str> = None;
    let (response, result_label) =
        match sign_inner(&state, &identifier, accept, &cn, body.as_ref(), &mut rpc_type).await {
            Ok(resp) => (resp, "success"),
            Err(e) => {
                let label = e.audit_label();
                (e.into_response(), label)
            }
        };
    audit::log_audit(&audit::AuditEntry {
        timestamp: audit::now_rfc3339(),
        pubkey_hex: identifier,
        client_cn: cn,
        backend: state.audit.backend_name.clone(),
        result: result_label.to_string(),
        duration_ms: started.elapsed().as_millis() as u64,
        rpc: rpc_type.map(str::to_string),
    });
    response
}

/// The fallible core of [`sign`], split out so every failure renders through the
/// single [`HttpSignError`] → status mapping. `rpc_type` is an out-param set to
/// the Web3Signer `type` as soon as the body parses, so the caller can audit the
/// type even on a post-parse failure (slashing/gate error).
async fn sign_inner(
    state: &Web3SignerState,
    identifier: &str,
    accept: Option<&str>,
    cn: &str,
    body: &[u8],
    rpc_type: &mut Option<&'static str>,
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
    // Record the type for the audit entry now that the payload is known, so a
    // later slashing/gate rejection still audits the correct `type` (Issue 4.4).
    *rpc_type = Some(req.payload.type_name());

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
            SignPayload::AggregateAndProof { .. } => {
                state.gate.sign_aggregate_and_proof(&pubkey, root).await
            }
            SignPayload::SyncCommitteeMessage { .. } => {
                state.gate.sign_sync_committee_message(&pubkey, root).await
            }
            SignPayload::SyncCommitteeContributionAndProof { .. } => {
                state.gate.sign_contribution_and_proof(&pubkey, root).await
            }
            // Same gate method as AGGREGATION_SLOT; the dispatcher already applied
            // the DISTINCT 0x08 domain, so the gate just signs the root.
            SignPayload::SyncCommitteeSelectionProof { .. } => {
                state.gate.sign_selection_proof(&pubkey, root).await
            }
            SignPayload::ValidatorRegistration { .. } => {
                state.gate.sign_builder_registration(&pubkey, root).await
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
    use crate::http_api::tls::PeerCert;

    use crypto::{compute_domain, compute_signing_root};
    // Import BeaconBlockHeader EXPLICITLY from eth_types: an unrelated all-String
    // `rvc-beacon::BeaconBlockHeader` DTO exists and would compute a garbage root.
    use eth_types::{
        AggregateAndProof, Attestation, AttestationData, BeaconBlockHeader, Checkpoint,
        ContributionAndProof, Root, SyncAggregatorSelectionData, SyncCommitteeContribution,
        SyncCommitteeMessage, ValidatorRegistrationV1, DOMAIN_AGGREGATE_AND_PROOF,
        DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
        DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
        DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
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

    // ── P1 aggregation + sync-committee arms (Issue 4.1) ─────────────────────

    fn dummy_sig() -> Vec<u8> {
        vec![0xAB; 96]
    }

    /// A valid (small, in-limit) pre-Electra aggregation bitlist: `0x01` is a
    /// 0-data-bit bitlist (just the length delimiter).
    fn valid_agg_bits() -> Vec<u8> {
        vec![0x01]
    }

    fn sample_aggregate_and_proof() -> AggregateAndProof {
        AggregateAndProof {
            aggregator_index: 1,
            aggregate: Attestation {
                aggregation_bits: valid_agg_bits(),
                data: sample_attestation(),
                signature: dummy_sig(),
            },
            selection_proof: vec![0xCD; 96],
        }
    }

    fn sample_contribution_and_proof() -> ContributionAndProof {
        ContributionAndProof {
            aggregator_index: 1,
            contribution: SyncCommitteeContribution {
                slot: 5,
                beacon_block_root: [0x11; 32],
                subcommittee_index: 0,
                aggregation_bits: vec![0u8; 16],
                signature: dummy_sig(),
            },
            selection_proof: vec![0xCD; 96],
        }
    }

    /// Wrap a serialized payload object in the sign envelope with `fork_info`.
    fn p1_body(type_name: &str, payload_key: &str, payload_json: String) -> String {
        format!(
            r#"{{ "type": "{type_name}", {fi}, "{payload_key}": {payload_json} }}"#,
            fi = fork_info_json(),
        )
    }

    #[tokio::test]
    async fn aggregate_and_proof_kat() {
        let agg = sample_aggregate_and_proof();
        let domain = compute_domain(DOMAIN_AGGREGATE_AND_PROOF, CURRENT_VERSION, expected_gvr());
        let object_root = agg.try_tree_hash_root().unwrap().0;
        let (sk, _) = test_keypair();
        let expected = sk.sign(&compute_signing_root(&object_root, domain)).to_bytes();
        let body = p1_body(
            "AGGREGATE_AND_PROOF",
            "aggregate_and_proof",
            serde_json::to_string(&agg).unwrap(),
        );
        assert_eq!(sign_ok(body).await, expected.to_vec());
    }

    #[tokio::test]
    async fn sync_committee_message_kat_signs_the_block_root() {
        let msg = SyncCommitteeMessage {
            slot: 5,
            beacon_block_root: [0x22; 32],
            validator_index: 0,
            signature: dummy_sig(),
        };
        let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, CURRENT_VERSION, expected_gvr());
        // The signed object is the block ROOT, not the message container.
        let (sk, _) = test_keypair();
        let expected = sk.sign(&compute_signing_root(&msg.beacon_block_root, domain)).to_bytes();
        let body = p1_body(
            "SYNC_COMMITTEE_MESSAGE",
            "sync_committee_message",
            serde_json::to_string(&msg).unwrap(),
        );
        assert_eq!(sign_ok(body).await, expected.to_vec());
    }

    #[tokio::test]
    async fn sync_committee_contribution_and_proof_kat() {
        let cap = sample_contribution_and_proof();
        let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, CURRENT_VERSION, expected_gvr());
        let (sk, _) = test_keypair();
        let expected = sk.sign(&compute_signing_root(&cap, domain)).to_bytes();
        let body = p1_body(
            "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
            "contribution_and_proof",
            serde_json::to_string(&cap).unwrap(),
        );
        assert_eq!(sign_ok(body).await, expected.to_vec());
    }

    #[tokio::test]
    async fn aggregate_and_proof_malformed_bits_is_400_not_panic() {
        // An over-length aggregation_bits bitlist must surface as 400 via
        // try_tree_hash_root, never a panic (the liveness-DoS class).
        let mut agg = sample_aggregate_and_proof();
        agg.aggregate.aggregation_bits = vec![0xff; 4096]; // far past the committee limit
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        let body = p1_body(
            "AGGREGATE_AND_PROOF",
            "aggregate_and_proof",
            serde_json::to_string(&agg).unwrap(),
        );
        let resp = post_sign(state, &id, None, body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "malformed bits → 400, not panic");
    }

    /// 4.1-review polish: lock the no-panic property at the ROUTE layer for the
    /// contribution arm — a multi-KB `aggregation_bits` signs cleanly (200), not
    /// a panic (`SyncCommitteeContribution` hashes the bits via a self-sizing
    /// `vec_u8_tree_hash_root`, so any length is safe).
    #[tokio::test]
    async fn sync_committee_contribution_large_bits_is_200() {
        let mut cap = sample_contribution_and_proof();
        cap.contribution.aggregation_bits = vec![0xff; 4096];
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));
        let body = p1_body(
            "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
            "contribution_and_proof",
            serde_json::to_string(&cap).unwrap(),
        );
        let resp = post_sign(state, &id, Some("application/json"), body).await;
        assert_eq!(resp.status(), StatusCode::OK, "large contribution bits sign cleanly, no panic");
    }

    // ── SYNC_COMMITTEE_SELECTION_PROOF (Issue 4.2): the 0x08 disambiguation ───

    fn sync_selection_body(slot: u64, subcommittee_index: u64) -> String {
        format!(
            r#"{{ "type": "SYNC_COMMITTEE_SELECTION_PROOF", {fi},
                  "sync_aggregator_selection_data": {{ "slot": "{slot}",
                                                       "subcommittee_index": "{subcommittee_index}" }} }}"#,
            fi = fork_info_json(),
        )
    }

    #[tokio::test]
    async fn sync_committee_selection_proof_kat() {
        let sasd = SyncAggregatorSelectionData { slot: 7, subcommittee_index: 3 };
        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, CURRENT_VERSION, expected_gvr());
        let (sk, _) = test_keypair();
        let expected = sk.sign(&compute_signing_root(&sasd, domain)).to_bytes();
        assert_eq!(sign_ok(sync_selection_body(7, 3)).await, expected.to_vec());
    }

    /// The load-bearing test: `SYNC_COMMITTEE_SELECTION_PROOF` (0x08 over the
    /// `SyncAggregatorSelectionData` struct) must NOT collide with
    /// `AGGREGATION_SLOT` (0x05 over a bare slot) for the same slot — a
    /// regression pointing this arm at `DOMAIN_SELECTION_PROOF` would pass every
    /// other check but fail here.
    #[tokio::test]
    async fn sync_selection_and_aggregation_slot_domains_do_not_collide() {
        assert_ne!(
            sign_ok(aggregation_slot_body(7)).await,
            sign_ok(sync_selection_body(7, 0)).await,
            "0x08 sync-selection must not equal 0x05 aggregation-slot for the same slot"
        );
    }

    // ── VALIDATOR_REGISTRATION (Issue 4.3): no fork_info, fixed builder domain ─

    fn sample_registration() -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: [0x11; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: test_keypair().1,
        }
    }

    fn registration_body(reg: &ValidatorRegistrationV1, with_fork_info: bool) -> String {
        let reg_json = serde_json::to_string(reg).unwrap();
        if with_fork_info {
            format!(
                r#"{{ "type": "VALIDATOR_REGISTRATION", {fi}, "validator_registration": {reg_json} }}"#,
                fi = fork_info_json(),
            )
        } else {
            format!(
                r#"{{ "type": "VALIDATOR_REGISTRATION", "validator_registration": {reg_json} }}"#
            )
        }
    }

    /// Independently compute the builder signing root: fixed builder fork version
    /// `0x00000000` + a ZERO genesis validators root (ADR-008), NOT a fork_info gvr.
    fn expected_registration_sig(reg: &ValidatorRegistrationV1) -> Vec<u8> {
        let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, [0, 0, 0, 0], [0u8; 32]);
        let (sk, _) = test_keypair();
        sk.sign(&compute_signing_root(reg, domain)).to_bytes().to_vec()
    }

    #[tokio::test]
    async fn validator_registration_without_fork_info_signs_kat() {
        // A body that OMITS fork_info must parse + sign (not 400), and sign the
        // builder root (zero gvr, fixed builder fork version).
        let reg = sample_registration();
        assert_eq!(
            sign_ok(registration_body(&reg, false)).await,
            expected_registration_sig(&reg),
            "VALIDATOR_REGISTRATION omitting fork_info signs the builder root"
        );
    }

    #[tokio::test]
    async fn validator_registration_with_fork_info_is_ignored_not_rejected() {
        // A body that DOES include fork_info still signs and produces the SAME
        // signature — fork_info is ignored for this type, not rejected.
        let reg = sample_registration();
        assert_eq!(
            sign_ok(registration_body(&reg, true)).await,
            expected_registration_sig(&reg),
            "fork_info is ignored for VALIDATOR_REGISTRATION (same builder root)"
        );
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

    // ── Issue 4.4: HTTP audit logging ────────────────────────────────────────
    //
    // Every sign request emits exactly one structured audit entry (success at
    // `info`, every rejection at `warn` via `log_audit`) carrying only
    // metadata — pubkey identifier, Web3Signer `type`, outcome, peer CN,
    // backend, latency — NEVER the body, signing root, or signature. These tests
    // capture the emitted tracing events with `tracing-test` and assert the
    // field set plus the absence of secrets.

    use tracing_test::traced_test;

    /// Mint a self-signed leaf whose subject CN is `cn`. Only the CN is read by
    /// the audit extractor and no chain validation happens at the audit layer, so
    /// a self-signed cert suffices to drive the cert-bearing CN path.
    fn peer_cert_with_cn(cn: &str) -> PeerCert {
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        PeerCert(Some(cert.der().clone()))
    }

    /// `post_sign` with a Phase-3 `PeerCert` request extension injected, so the
    /// handler derives the audit CN from a (test) client cert instead of the
    /// default.
    async fn post_sign_with_peer(
        state: crate::http_api::Web3SignerState,
        identifier: &str,
        body: String,
        peer: PeerCert,
    ) -> Response {
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/eth2/sign/{identifier}"))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(peer);
        router(state).oneshot(req).await.unwrap()
    }

    /// Pull the `0x`-prefixed signature out of a JSON `{"signature":"0x.."}` body.
    fn signature_hex(json_body: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(json_body).unwrap();
        v["signature"].as_str().unwrap().to_string()
    }

    #[traced_test]
    #[tokio::test]
    async fn audit_success_records_type_default_cn_and_omits_signature() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        let resp = post_sign(state, &id, None, attestation_body(None)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(resp).await).unwrap();
        let sig = signature_hex(&body);

        // One audit line: success, with the Web3Signer type and the default CN
        // (no client cert on the socket-free path → AUDIT_CN_DEFAULT).
        assert!(logs_contain("sign request audit"));
        assert!(logs_contain("result=success"));
        assert!(logs_contain("rpc=ATTESTATION"));
        assert!(logs_contain("client_cn=signing-gate"));
        // The signature (hence no key material) must NOT appear in any log line.
        assert!(!logs_contain(&sig), "audit log leaked the signature");
    }

    #[traced_test]
    #[tokio::test]
    async fn audit_rejection_412_logged_with_slashing_outcome_and_type() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        // Commit, then a conflicting same-target-epoch attestation → 412.
        let first =
            post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x00)).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second =
            post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x11)).await;
        assert_eq!(second.status(), StatusCode::PRECONDITION_FAILED);

        // The rejection is audited (at `warn` per `log_audit`) with the gate
        // outcome label and the still-known type.
        assert!(logs_contain("result=slashing"));
        assert!(logs_contain("rpc=ATTESTATION"));
    }

    #[traced_test]
    #[tokio::test]
    async fn audit_unknown_key_404_logged_with_key_not_found() {
        let state = test_state(Arc::new(MockBackend::empty()));
        let id = format!("0x{}", "ab".repeat(48)); // well-formed, not loaded
        let resp = post_sign(state, &id, None, attestation_body(None)).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Resolved before the body parses → outcome label set, no `type` recorded.
        assert!(logs_contain("result=key_not_found"));
    }

    #[traced_test]
    #[tokio::test]
    async fn audit_records_client_cert_leaf_cn() {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let id = format!("0x{}", hex::encode(pk_bytes));

        let resp = post_sign_with_peer(
            state,
            &id,
            attestation_body(None),
            peer_cert_with_cn("lighthouse-vc"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // mTLS path: the audit CN is the leaf cert's first CN, not the default.
        assert!(logs_contain("client_cn=lighthouse-vc"));
        assert!(!logs_contain("client_cn=signing-gate"));
    }
}
