//! Axum handlers for the Web3Signer HTTP API.
//!
//! Phase 2 lands `GET /upcheck` and `GET /api/v1/eth2/publicKeys`;
//! `POST /sign/{identifier}` arrives in the following issues.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

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
