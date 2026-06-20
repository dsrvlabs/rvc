//! Axum handlers for the Web3Signer HTTP API.
//!
//! Phase 2 lands `GET /upcheck`; `GET /publicKeys` and `POST /sign/{identifier}`
//! arrive in the following issues.

use axum::http::StatusCode;
use axum::response::IntoResponse;

/// `GET /upcheck` — liveness probe (FR-1).
///
/// Returns `200 OK` with the body `OK`. It takes no state and never calls the
/// gate, so orchestration health-checks succeed even while the signing path is
/// busy or erroring.
#[tracing::instrument(skip_all)]
pub(super) async fn upcheck() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}
