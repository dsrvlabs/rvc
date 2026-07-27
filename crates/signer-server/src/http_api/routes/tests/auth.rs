//! CN allow-list, structured audit log, and HTTP sign metrics.

use super::*;
use tracing_test::traced_test;

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

/// SEC-4 residual F1: HTTP path shares the primary CN allow-list with gRPC.
/// Socket-free requests use `AUDIT_CN_DEFAULT` (`signing-gate`); a list that
/// does not include it must reject with 401 before any signature.
#[traced_test]
#[tokio::test]
async fn test_http_non_allowlisted_cn_rejected_before_sign() {
    let (sk, pk_bytes) = test_keypair();
    let mut state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    state.client_cn_allow_list =
        Some(Arc::new(crate::audit::ClientCnAllowList::from_cns(["vc-A"])));
    let id = format!("0x{}", hex::encode(pk_bytes));

    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "non-allow-listed CN must not obtain a signature over HTTP"
    );
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.contains("not on the allow-list"), "body: {body}");
    assert!(logs_contain("client_cn_not_allowed") || logs_contain("sign request audit"));
}

/// SEC-4: allow-listed default CN still signs over HTTP.
#[tokio::test]
async fn test_http_allowlisted_cn_succeeds() {
    let (sk, pk_bytes) = test_keypair();
    let mut state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    // Socket-free path degrades to AUDIT_CN_DEFAULT ("signing-gate").
    state.client_cn_allow_list =
        Some(Arc::new(crate::audit::ClientCnAllowList::from_cns(["signing-gate"])));
    let id = format!("0x{}", hex::encode(pk_bytes));

    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await).unwrap();
    assert!(body.contains("signature"), "body: {body}");
}

#[traced_test]
#[tokio::test]
async fn audit_rejection_412_logged_with_slashing_outcome_and_type() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let id = format!("0x{}", hex::encode(pk_bytes));

    // Commit, then a conflicting same-target-epoch attestation → 412.
    let first = post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x00)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = post_sign(state.clone(), &id, None, attestation_body_with_block_root(0x11)).await;
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

    let resp =
        post_sign_with_peer(state, &id, attestation_body(None), peer_cert_with_cn("lighthouse-vc"))
            .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // mTLS path: the audit CN is the leaf cert's first CN, not the default.
    assert!(logs_contain("client_cn=lighthouse-vc"));
    assert!(!logs_contain("client_cn=signing-gate"));
}

// ── Issue 4.5: HTTP metrics ──────────────────────────────────────────────

/// A successful HTTP sign increments `http_sign_total{type,result}` for the
/// exact type×outcome and records one latency-histogram sample.
#[tokio::test]
async fn http_sign_records_type_outcome_counter_and_latency() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let metrics = Arc::clone(&state.metrics);
    let id = format!("0x{}", hex::encode(pk_bytes));

    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(
        metrics.http_sign_total.with_label_values(&["ATTESTATION", "success"]).get(),
        1,
        "one ATTESTATION/success request counted"
    );
    assert_eq!(
        metrics.http_sign_duration_seconds.with_label_values(&[] as &[&str]).get_sample_count(),
        1,
        "one latency sample recorded"
    );
}

/// A rejection is counted under its outcome label, not `success`.
#[tokio::test]
async fn http_sign_counts_rejection_outcome() {
    let state = test_state(Arc::new(MockBackend::empty()));
    let metrics = Arc::clone(&state.metrics);
    let id = format!("0x{}", "ab".repeat(48)); // well-formed, not loaded → 404

    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // Resolved before the body parses → type "unknown", outcome key_not_found.
    assert_eq!(metrics.http_sign_total.with_label_values(&["unknown", "key_not_found"]).get(), 1);
}

/// AC: a single `:9101` scrape spans BOTH transports — after a real HTTP
/// sign (via shared `dispatch_sign`), the encoded output carries both the
/// A7 `rvc_signer_sign_total` series (type×outcome) and the HTTP-only
/// `rvc_signer_http_sign_total` series.
#[tokio::test]
async fn single_scrape_spans_grpc_and_http_series() {
    let (sk, pk_bytes) = test_keypair();
    let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
    let metrics = Arc::clone(&state.metrics);
    let id = format!("0x{}", hex::encode(pk_bytes));

    // Real HTTP sign — shared dispatcher also records A7 sign_* labels.
    let resp = post_sign(state, &id, None, attestation_body(None)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(
        metrics.sign_total.with_label_values(&["basic", "attestation_data", "success"]).get(),
        1,
        "HTTP path must record A7 sign_total via dispatch_sign"
    );
    assert_eq!(
        metrics
            .sign_duration_seconds
            .with_label_values(&["basic", "attestation_data"])
            .get_sample_count(),
        1
    );
    assert_eq!(
        metrics.http_sign_total.with_label_values(&["ATTESTATION", "success"]).get(),
        1,
        "Issue 4.5 HTTP-only series still recorded"
    );

    let scrape = String::from_utf8(metrics.encode().unwrap()).unwrap();
    assert!(scrape.contains("rvc_signer_sign_total"), "A7 series present");
    assert!(scrape.contains("rvc_signer_http_sign_total"), "HTTP series present");
    assert!(scrape.contains("attestation_data"), "A7 type label from HTTP dispatch");
}

/// The P2 arms inherit Phase-4 audit + metrics automatically: each emits an
/// audit line (type + success) and increments the per-type success counter,
/// matching FR-33/FR-34.
#[traced_test]
#[tokio::test]
async fn p2_types_emit_audit_and_metrics() {
    for (type_name, body) in [
        ("VOLUNTARY_EXIT", voluntary_exit_body(7, 1)),
        ("AGGREGATE_AND_PROOF_V2", electra_v2_frozen_fixture()),
    ] {
        let (sk, pk_bytes) = test_keypair();
        let state = test_state(Arc::new(RealSigningBackend::with_key(sk)));
        let metrics = Arc::clone(&state.metrics);
        let id = format!("0x{}", hex::encode(pk_bytes));

        let resp = post_sign(state, &id, None, body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(
            metrics.http_sign_total.with_label_values(&[type_name, "success"]).get(),
            1,
            "{type_name} success metric fired"
        );
        assert!(logs_contain(&format!("rpc={type_name}")), "{type_name} audited");
        assert!(logs_contain("result=success"));
    }
}
