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
//! The success / `Accept`-negotiated half is added in Issue 2.7.
//!
//! NOTE: landed ahead of its consumer — the sign handler (Issues 2.6/2.7)
//! returns `HttpSignError`. Until then it is exercised only by this module's
//! tests, hence the transitional `allow(dead_code)`; remove it in 2.6.
#![allow(dead_code)]

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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

#[cfg(test)]
mod tests {
    use super::*;
    use slashing::{AttestationSlashingViolation, BlockSlashingViolation};

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
