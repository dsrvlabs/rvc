# Research: Axum Patterns for New Endpoints

## Summary

rvc uses Axum 0.7 with a clean trait-based architecture. The existing patterns for route registration, state injection, error handling, auth middleware, and response formatting are well-established. The new endpoints should follow these same patterns with minor extensions: path parameter extraction for `:pubkey`, query parameter extraction for voluntary exit `epoch`, new trait objects in `AppState`, and a `NotFound` error variant.

## Existing Architecture

### Axum Version

```toml
# Cargo.toml (workspace)
axum = "0.7"

# crates/keymanager-api/Cargo.toml
axum = { workspace = true, features = ["macros"] }
```

Axum 0.7 uses `axum::extract::State` with `Arc<AppState>` — this is the current pattern in rvc.

### Route Registration (`server.rs`)

Routes are registered in `KeymanagerServer::router()`:

```rust
let api = Router::new()
    .route(
        "/eth/v1/keystores",
        get(handlers::list_keystores)
            .post(handlers::import_keystores)
            .delete(handlers::delete_keystores),
    )
    .route(
        "/eth/v1/remotekeys",
        get(handlers::list_remote_keys)
            .post(handlers::import_remote_keys)
            .delete(handlers::delete_remote_keys),
    )
    .layer(DefaultBodyLimit::max(self.body_limit))
    .with_state(self.state.clone());

auth::with_auth(api, self.token.clone()).layer(cors)
```

**Pattern:** All routes are under the same `Router`, share the same `AppState`, and go through the auth middleware.

### State Injection (`handlers.rs`)

The `AppState` struct holds trait objects:

```rust
pub struct AppState {
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
    pub remote_key_manager: Arc<dyn RemoteKeyManager>,
    pub allow_insecure_remote_signer: bool,
}
```

Handlers extract state via `State(state): State<Arc<AppState>>`.

### Error Handling (`error.rs`)

```rust
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };
        let body = serde_json::json!({ "message": message });
        (status, axum::Json(body)).into_response()
    }
}
```

**Consistent with spec:** The error response format `{ "message": "..." }` matches the Keymanager API `ErrorResponse` schema.

### Auth Middleware (`auth.rs`)

Bearer token authentication via Axum middleware:

```rust
pub fn with_auth(router: axum::Router, token: Arc<Zeroizing<String>>) -> axum::Router {
    router.layer(middleware::from_fn_with_state(token, bearer_auth))
}
```

Uses constant-time comparison (`subtle::ConstantTimeEq`). Returns 401 Unauthorized for invalid/missing tokens.

### Response Formatting

Handlers return `Json<ResponseType>` for success. The keymanager spec wraps data in `{ "data": ... }`, which the response types already handle.

---

## Proposed Patterns for New Endpoints

### 1. Path Parameter Extraction (`:pubkey`)

Axum 0.7 provides `axum::extract::Path` for path parameters:

```rust
use axum::extract::Path;

pub async fn get_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<FeeRecipientResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    // ...
}
```

The `pubkey` comes in as a hex string (e.g., `"0x9324..."`) and must be parsed/validated to `[u8; 48]`. A shared `parse_pubkey()` function should:
1. Strip `0x` prefix
2. Validate hex format (pattern: `^0x[a-fA-F0-9]{96}$`)
3. Decode to `[u8; 48]`
4. Return `Err(ApiError::BadRequest(...))` on invalid format

Note: An existing `parse_pubkey()` function is already in `handlers.rs` — reuse it.

### 2. Query Parameter Extraction (voluntary exit `epoch`)

```rust
use axum::extract::Query;

#[derive(Deserialize)]
pub struct VoluntaryExitQuery {
    pub epoch: Option<String>,  // Uint64 is a string in the spec
}

pub async fn submit_voluntary_exit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Query(query): Query<VoluntaryExitQuery>,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    let epoch = query.epoch
        .map(|e| e.parse::<u64>())
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid epoch".into()))?;
    // ...
}
```

### 3. Extending AppState with New Traits

Add the new trait objects to `AppState`:

```rust
pub struct AppState {
    // Existing
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
    pub remote_key_manager: Arc<dyn RemoteKeyManager>,
    pub allow_insecure_remote_signer: bool,
    // New
    pub config_manager: Arc<dyn ValidatorConfigManager>,
    pub exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
}
```

**`exit_manager` is `Option`** because:
- The PRD notes that voluntary exit requires beacon node access, which may not always be available
- Making it optional allows the server to start without exit capability and return 500 with a descriptive error when the endpoint is called without a configured beacon client

### 4. Adding New Routes

```rust
let api = Router::new()
    // Existing routes
    .route("/eth/v1/keystores", ...)
    .route("/eth/v1/remotekeys", ...)
    // New routes
    .route(
        "/eth/v1/validator/:pubkey/feerecipient",
        get(handlers::get_fee_recipient)
            .post(handlers::set_fee_recipient)
            .delete(handlers::delete_fee_recipient),
    )
    .route(
        "/eth/v1/validator/:pubkey/gas_limit",
        get(handlers::get_gas_limit)
            .post(handlers::set_gas_limit)
            .delete(handlers::delete_gas_limit),
    )
    .route(
        "/eth/v1/validator/:pubkey/graffiti",
        get(handlers::get_graffiti)
            .post(handlers::set_graffiti)
            .delete(handlers::delete_graffiti),
    )
    .route(
        "/eth/v1/validator/:pubkey/voluntary_exit",
        post(handlers::submit_voluntary_exit),
    )
    .layer(DefaultBodyLimit::max(self.body_limit))
    .with_state(self.state.clone());
```

**Note:** Axum 0.7 uses `:pubkey` syntax for path parameters (not `{pubkey}` as in the spec URL).

### 5. Adding `NotFound` Error Variant

The existing `ApiError` only has `BadRequest` and `Internal`. Add `NotFound` for unknown validators:

```rust
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };
        let body = serde_json::json!({ "message": message });
        (status, axum::Json(body)).into_response()
    }
}
```

### 6. Handler Return Types for Different Status Codes

Axum handlers return different status codes based on the operation:

**GET (200 with body):**
```rust
pub async fn get_fee_recipient(...) -> Result<Json<FeeRecipientResponse>, ApiError> {
    Ok(Json(response))
}
```

**POST (202 no body):**
```rust
pub async fn set_fee_recipient(...) -> Result<StatusCode, ApiError> {
    // ... set fee recipient ...
    Ok(StatusCode::ACCEPTED)
}
```

**DELETE (204 no body):**
```rust
pub async fn delete_fee_recipient(...) -> Result<StatusCode, ApiError> {
    // ... delete fee recipient ...
    Ok(StatusCode::NO_CONTENT)
}
```

**Voluntary exit POST (200 with body):**
```rust
pub async fn submit_voluntary_exit(...) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    Ok(Json(response))
}
```

### 7. Request Body Types

Define serde types for POST request bodies:

```rust
#[derive(Deserialize)]
pub struct SetFeeRecipientRequest {
    pub ethaddress: String,
}

#[derive(Deserialize)]
pub struct SetGasLimitRequest {
    pub gas_limit: String,  // Uint64 = string
}

#[derive(Deserialize)]
pub struct SetGraffitiRequest {
    pub graffiti: String,
}
```

### 8. Response Body Types

```rust
#[derive(Serialize)]
pub struct FeeRecipientData {
    pub pubkey: String,
    pub ethaddress: String,
}

#[derive(Serialize)]
pub struct FeeRecipientResponse {
    pub data: FeeRecipientData,
}

#[derive(Serialize)]
pub struct GasLimitData {
    pub pubkey: String,
    pub gas_limit: String,  // String, not number
}

#[derive(Serialize)]
pub struct GasLimitResponse {
    pub data: GasLimitData,
}

#[derive(Serialize)]
pub struct GraffitiData {
    pub pubkey: String,
    pub graffiti: String,
}

#[derive(Serialize)]
pub struct GraffitiResponse {
    pub data: GraffitiData,
}

#[derive(Serialize)]
pub struct VoluntaryExitMessage {
    pub epoch: String,
    pub validator_index: String,
}

#[derive(Serialize)]
pub struct SignedVoluntaryExitData {
    pub message: VoluntaryExitMessage,
    pub signature: String,
}

#[derive(Serialize)]
pub struct VoluntaryExitResponse {
    pub data: SignedVoluntaryExitData,
}
```

---

## Handler Template

Here is the recommended handler template, combining all patterns:

```rust
pub async fn get_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<FeeRecipientResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;

    let ethaddress = state.config_manager
        .get_fee_recipient(&pubkey)
        .map_err(|e| match e {
            ConfigError::NotFound => ApiError::NotFound(
                format!("no validator found with pubkey {pubkey_hex}")
            ),
            _ => ApiError::Internal(e.to_string()),
        })?;

    Ok(Json(FeeRecipientResponse {
        data: FeeRecipientData {
            pubkey: pubkey_hex,
            ethaddress: format!("0x{}", hex::encode(ethaddress)),
        },
    }))
}
```

## Axum 0.7 Considerations

- **No breaking changes expected** — Axum 0.7 is the current stable release and rvc is already on it.
- `Path`, `Query`, `State`, and `Json` extractors all work as documented.
- The `with_state()` pattern is correct for sharing `Arc<AppState>`.
- The auth middleware layering pattern (`auth::with_auth(api, token).layer(cors)`) correctly applies auth inside CORS, which is the right order for preflight OPTIONS handling.
