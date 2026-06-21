//! HTTP status mapping for `POST /sign/{identifier}` (FR-20..FR-24).
//!
//! This is a *fresh* `SigningGateError -> (StatusCode, body)` translation for
//! the HTTP edge — NOT a literal reuse of the gRPC `tonic::Status` table. It
//! reuses the error *categories* and *sanitization rules* (so both transports
//! agree on what is surfaced vs. logged) and emits HTTP statuses + safe bodies.
//!
//! Only slashing-violation slot/epoch detail (already deemed safe on the gRPC
//! path) is surfaced; SQLite paths, rusqlite internals, and lock messages are
//! logged server-side and replaced with a generic message.
//!
//! The success / `Accept`-negotiated half (`sign_response`) shapes the body per
//! the request `Accept` header (FR-17). Both halves are consumed by the live
//! `routes::sign` handler (Issue 2.8).

use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use signer::SigningGateError;
use slashing::SlashingError;

/// An error from the HTTP sign path, mapped to an exact HTTP status.
#[derive(Debug)]
pub enum HttpSignError {
    /// Pre-gate failure that never reaches the gate: parse error, unsupported
    /// `type`, missing `fork_info`, or a `signingRoot` mismatch. → `400`.
    BadRequest(String),
    /// Unknown / unloaded public key (pre-gate resolution). → `404`.
    UnknownKey,
    /// A `SigningGate` result error, mapped per [`gate_err_to_http`].
    Gate(SigningGateError),
}

impl HttpSignError {
    /// Map to `(status, safe-body)`. The body never contains SQLite paths, lock
    /// messages, or backend internals — only the slashing-violation slot/epoch
    /// detail, which is safe to surface.
    pub fn status_and_body(&self) -> (StatusCode, String) {
        match self {
            HttpSignError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            HttpSignError::UnknownKey => (StatusCode::NOT_FOUND, "unknown public key".to_string()),
            HttpSignError::Gate(e) => gate_err_to_http(e),
        }
    }
}

/// Map a gate result error to `(status, safe-body)` (FR-20..FR-24), mirroring
/// the gRPC `gate_err_to_status` categories.
fn gate_err_to_http(e: &SigningGateError) -> (StatusCode, String) {
    match e {
        SigningGateError::BlockedByDoppelganger => {
            (StatusCode::PRECONDITION_FAILED, "signing blocked by doppelganger gate".to_string())
        }
        SigningGateError::BlockedBySlashingDb(inner) => match inner {
            // Slashing-violation detail (slot/epoch numbers) is safe to surface.
            SlashingError::SlashableBlock(_) | SlashingError::SlashableAttestation(_) => {
                (StatusCode::PRECONDITION_FAILED, format!("slashing protection violation: {inner}"))
            }
            // Other DB errors may contain rusqlite internals / file paths — log
            // server-side, return a generic message.
            other => {
                tracing::error!(error = %other, "slashing DB error during staging");
                (StatusCode::PRECONDITION_FAILED, "slashing protection error".to_string())
            }
        },
        SigningGateError::SlashingDbCommitFailed(inner) => {
            tracing::error!(error = %inner, "slashing DB commit failed after successful sign");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "slashing DB commit failed; same-root retry is safe".to_string(),
            )
        }
        SigningGateError::KeyNotFound | SigningGateError::UnknownPubkey => {
            (StatusCode::NOT_FOUND, "unknown public key".to_string())
        }
        SigningGateError::SigningFailed(msg) => {
            tracing::error!(error = %msg, "signing backend error");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal signing error".to_string())
        }
    }
}

impl IntoResponse for HttpSignError {
    fn into_response(self) -> Response {
        let (status, body) = self.status_and_body();
        (status, body).into_response()
    }
}

// ── Success response shaping (Issue 2.7, FR-17) ──────────────────────────────

/// JSON success body: `{"signature":"0x.."}`.
#[derive(Debug, Serialize)]
pub(super) struct SignatureResponse {
    pub signature: String,
}

/// Shape a successful `POST /sign/{identifier}` response per the `Accept` header
/// (FR-17). `Accept: text/plain` → a bare `0x<hex>` body with a `text/plain`
/// content type; everything else (JSON, `*/*`, or absent) → `{"signature":
/// "0x.."}`. `signature` is the raw gate output (96 bytes) as `0x`+lowercase hex.
///
/// The live sign route (Issue 2.8) calls this with the gate's signature; the
/// shaper is driven directly by unit tests here, so no socket/gate is needed.
pub(super) fn sign_response(accept: Option<&str>, signature: &[u8]) -> Response {
    let hex = format!("0x{}", hex::encode(signature));
    if wants_text_plain(accept) {
        ([(CONTENT_TYPE, "text/plain")], hex).into_response()
    } else {
        Json(SignatureResponse { signature: hex }).into_response()
    }
}

/// `true` only when the client explicitly accepts `text/plain`. An absent,
/// wildcard (`*/*`), or `application/json` Accept defaults to JSON (Web3Signer
/// mirrors the content type, defaulting to JSON).
///
/// Media-type matching is case-insensitive and ignores `;`-parameters
/// (`q`/`charset`) per RFC 9110, and scans every comma-separated member so a
/// multi-value `Accept` that lists `text/plain` is honored (2.7 review).
fn wants_text_plain(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| {
        a.split(',').any(|member| {
            member.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/plain")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use slashing::{AttestationSlashingViolation, BlockSlashingViolation};

    // ── Success response shaping (Issue 2.7, FR-17) ──────────────────────────

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn content_type(resp: &Response) -> String {
        resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
    }

    #[test]
    fn wants_text_plain_is_case_insensitive_param_aware_and_multi_value() {
        assert!(wants_text_plain(Some("text/plain")));
        assert!(wants_text_plain(Some("Text/Plain")), "media types are case-insensitive");
        assert!(wants_text_plain(Some("text/plain; q=0.9")), ";-params ignored");
        assert!(wants_text_plain(Some("application/json, text/plain")), "multi-value scanned");
        assert!(!wants_text_plain(Some("application/json")));
        assert!(!wants_text_plain(Some("*/*")));
        assert!(!wants_text_plain(Some("text/plainish")), "exact media type, not a prefix");
        assert!(!wants_text_plain(None));
    }

    #[tokio::test]
    async fn text_plain_accept_returns_bare_hex_with_text_content_type() {
        let resp = sign_response(Some("text/plain"), &[0xABu8; 96]);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("text/plain"), "ct={}", content_type(&resp));
        let body = body_string(resp).await;
        assert_eq!(body, format!("0x{}", "ab".repeat(96)));
        assert!(!body.contains('{'), "text/plain must be a bare body, not JSON: {body}");
    }

    #[tokio::test]
    async fn json_accept_returns_signature_object() {
        let resp = sign_response(Some("application/json"), &[0xABu8; 96]);
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("application/json"), "ct={}", content_type(&resp));
        let v: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(v["signature"], format!("0x{}", "ab".repeat(96)));
    }

    #[tokio::test]
    async fn absent_and_wildcard_accept_default_to_json() {
        for accept in [None, Some("*/*"), Some("application/json")] {
            let resp = sign_response(accept, &[0x01u8; 96]);
            assert!(
                content_type(&resp).starts_with("application/json"),
                "accept={accept:?} must default to JSON"
            );
            assert!(body_string(resp).await.starts_with("{\"signature\""));
        }
    }

    #[tokio::test]
    async fn signature_is_0x_lowercase_hex_of_raw_bytes() {
        // Distinct per-byte values catch a wrong/transposed encoding.
        let mut sig = [0u8; 96];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = i as u8;
        }
        let body = body_string(sign_response(Some("text/plain"), &sig)).await;
        let expected: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(body, format!("0x{expected}"));
        assert_eq!(body, body.to_lowercase(), "hex must be lowercase");
    }

    #[test]
    fn doppelganger_block_is_412() {
        let (status, _) =
            HttpSignError::Gate(SigningGateError::BlockedByDoppelganger).status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn slashable_block_is_412_with_safe_slot_detail() {
        let err = HttpSignError::Gate(SigningGateError::BlockedBySlashingDb(
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot: 42 }),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert!(body.contains("42"), "safe slot detail must be surfaced: {body}");
    }

    #[test]
    fn slashable_attestation_is_412_with_safe_epoch_detail() {
        let err = HttpSignError::Gate(SigningGateError::BlockedBySlashingDb(
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch: 7,
            }),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert!(body.contains('7'), "safe epoch detail must be surfaced: {body}");
    }

    #[test]
    fn generic_db_error_is_412_without_leaking_internals() {
        let secret = "/var/lib/rvc/slashing.db lock contention";
        let err = HttpSignError::Gate(SigningGateError::BlockedBySlashingDb(
            SlashingError::MigrationError(secret.to_string()),
        ));
        let (status, body) = err.status_and_body();
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert!(!body.contains(secret), "generic DB error must NOT leak internals: {body}");
        assert!(!body.contains(".db"), "no path internals: {body}");
    }

    #[test]
    fn commit_failed_is_500_generic() {
        let secret = "/var/lib/rvc/slashing.db disk full";
        let (status, body) = HttpSignError::Gate(SigningGateError::SlashingDbCommitFailed(
            SlashingError::MigrationError(secret.to_string()),
        ))
        .status_and_body();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains(secret), "commit-failed body must not leak: {body}");
    }

    #[test]
    fn signing_failed_is_500_generic() {
        let (status, body) =
            HttpSignError::Gate(SigningGateError::SigningFailed("blst internal x0042".to_string()))
                .status_and_body();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("x0042"), "signing-failed body must not leak detail: {body}");
    }

    #[test]
    fn key_not_found_and_unknown_pubkey_are_404() {
        for e in [SigningGateError::KeyNotFound, SigningGateError::UnknownPubkey] {
            let (status, body) = HttpSignError::Gate(e).status_and_body();
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(body, "unknown public key");
        }
    }

    #[test]
    fn pre_gate_bad_request_is_400_and_unknown_key_is_404() {
        let (status, body) =
            HttpSignError::BadRequest("unsupported type".to_string()).status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "unsupported type");

        let (status, _) = HttpSignError::UnknownKey.status_and_body();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
