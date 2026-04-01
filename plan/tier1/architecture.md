# Software Architecture: Tier 1 — Standards Compliance

## Overview

This architecture extends rvc's existing 4-layer crate structure to implement 10 missing Keymanager API endpoints and add Holesky/Sepolia testnet support. The design follows the established trait-based abstraction pattern: new `ValidatorConfigManager` and `VoluntaryExitManager` traits are defined in `keymanager-api`, implemented as adapter structs in the `rvc` crate, and wired into the Axum `AppState` alongside existing trait objects. Config mutations are persisted atomically via `tempfile` + rename on the `ValidatorStore`. Network support is extended by adding enum variants and hardcoded genesis constants.

The guiding principle is **minimal surface area**: no new crates, no new external dependencies, no new architectural patterns. Every change follows an existing pattern in the codebase.

## Architecture Principles

- **Trait-boundary isolation** — Handlers depend on traits, never on `ValidatorStore` or `BeaconClient` directly. This preserves testability and avoids coupling the HTTP layer to domain internals.
- **Read-fast, write-safe** — GET operations are in-memory lookups (sub-millisecond). POST/DELETE operations serialize writes through the existing `RwLock` and flush to disk atomically.
- **Optional capabilities** — `VoluntaryExitManager` is `Option<Arc<dyn ...>>` in `AppState`. The server starts without exit capability if no beacon client is available, returning 500 with a descriptive error.
- **Spec-first types** — API request/response types match the Keymanager API OpenAPI spec exactly. `gas_limit` is a string. `epoch` is a query parameter. Pubkeys are `0x`-prefixed lowercase hex.

## System Context Diagram

```text
                         ┌──────────────┐
                         │ Staking Tool │
                         │  (ethdo,     │
                         │  dashboard)  │
                         └──────┬───────┘
                                │ HTTP (Bearer auth)
                                ▼
┌────────────────────────────────────────────────────────────┐
│                      rvc Validator Client                  │
│                                                            │
│  ┌────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Keymanager │  │ Orchestrator │  │   Signer Service  │  │
│  │    API     │──│  (duties)    │──│ (CompositeSigner) │  │
│  │  (Axum)    │  └──────┬───────┘  └───────────────────┘  │
│  └─────┬──────┘         │                                  │
│        │                ▼                                  │
│  ┌─────▼──────┐  ┌──────────────┐                          │
│  │ Validator  │  │ Beacon       │                          │
│  │   Store    │  │  Client(s)   │                          │
│  └─────┬──────┘  └──────┬───────┘                          │
│        │                │                                  │
└────────┼────────────────┼──────────────────────────────────┘
         │                │
         ▼                ▼
  ┌──────────┐    ┌──────────────┐
  │ TOML     │    │ Beacon Node  │
  │ Config   │    │ (CL client)  │
  └──────────┘    └──────────────┘
```

## Module Overview

| Module | Responsibility | Owns Data | Depends On | Communication |
|--------|---------------|-----------|------------|---------------|
| `keymanager-api` | HTTP handlers, traits, route registration | — (stateless) | traits only | sync (Axum state) |
| `validator-store` | Validator config CRUD + TOML persistence | validators, defaults | — | sync (direct calls) |
| `rvc` (adapters) | Bridge traits to concrete impls | — | validator-store, beacon, signer, crypto | sync |
| `rvc` (config) | Network enum, genesis constants | — | — | — |
| `bin/rvc` (main) | DI wiring, server startup | — | all crates | startup |
| `bin/rvc-keygen` | Key generation, BLS-to-exec-change | — | eth-types | CLI |

## Crate Modification Map

```text
Binary Layer          ┌─ bin/rvc/src/main.rs .............. inject new adapters into KeymanagerServer
                      └─ bin/rvc-keygen/src/network.rs .... add HOLESKY, SEPOLIA constants

Orchestrator Layer    (no changes)

Domain Layer          ┌─ crates/keymanager-api/src/traits.rs ...... new traits
                      ├─ crates/keymanager-api/src/handlers.rs .... new handler functions
                      ├─ crates/keymanager-api/src/types.rs ....... new request/response types
                      ├─ crates/keymanager-api/src/error.rs ....... add NotFound variant
                      ├─ crates/keymanager-api/src/server.rs ...... new routes + constructor params
                      └─ crates/rvc/src/keymanager_adapters.rs .... new adapter structs

Foundation Layer      ├─ crates/validator-store/src/store.rs ...... save_config(), has_validator()
                      ├─ crates/validator-store/src/error.rs ...... (no changes needed)
                      └─ crates/rvc/src/config/network.rs ......... add Holesky, Sepolia variants
```

### New Files vs Modified Files

**New files:** None. All changes go into existing files.

**Modified files (10):**

| File | Type of Change |
|------|---------------|
| `crates/keymanager-api/src/traits.rs` | Add 2 new traits + 1 error enum |
| `crates/keymanager-api/src/handlers.rs` | Add 10 handler functions |
| `crates/keymanager-api/src/types.rs` | Add request/response structs |
| `crates/keymanager-api/src/error.rs` | Add `NotFound` variant |
| `crates/keymanager-api/src/server.rs` | Add routes, extend constructor |
| `crates/rvc/src/keymanager_adapters.rs` | Add 2 adapter structs |
| `crates/validator-store/src/store.rs` | Add `save_config()`, `has_validator()` |
| `crates/rvc/src/config/network.rs` | Add `Holesky`, `Sepolia` variants |
| `bin/rvc/src/main.rs` | Wire new adapters into server |
| `bin/rvc-keygen/src/network.rs` | Add `HOLESKY`, `SEPOLIA` constants |

---

## Module Details

### 1. Trait Design

#### `ValidatorConfigManager` trait

Defined in `crates/keymanager-api/src/traits.rs`. Nine synchronous methods following the existing trait pattern (`Send + Sync`, no `async`). Config lookups and mutations on `ValidatorStore` are all synchronous (behind `parking_lot::RwLock`), so `async` is unnecessary.

```rust
use crate::error::ApiError;

pub trait ValidatorConfigManager: Send + Sync {
    fn get_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<[u8; 20], ApiError>;
    fn set_fee_recipient(&self, pubkey: &[u8; 48], address: [u8; 20]) -> Result<(), ApiError>;
    fn delete_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<(), ApiError>;

    fn get_gas_limit(&self, pubkey: &[u8; 48]) -> Result<u64, ApiError>;
    fn set_gas_limit(&self, pubkey: &[u8; 48], gas_limit: u64) -> Result<(), ApiError>;
    fn delete_gas_limit(&self, pubkey: &[u8; 48]) -> Result<(), ApiError>;

    fn get_graffiti(&self, pubkey: &[u8; 48]) -> Result<String, ApiError>;
    fn set_graffiti(&self, pubkey: &[u8; 48], graffiti: &str) -> Result<(), ApiError>;
    fn delete_graffiti(&self, pubkey: &[u8; 48]) -> Result<(), ApiError>;
}
```

**Design decisions:**

- `get_fee_recipient` returns the **effective** value (per-validator override OR default). Never returns an error for "no override set" — there is always a fallback. Maps to `ValidatorStore::effective_fee_recipient()`.
- `set_*` methods update in-memory state AND persist to TOML. The adapter calls `update_config()` then `save_config()`.
- `delete_*` methods remove the per-validator override (set to `None`), reverting to the default. Same persistence path.
- `get_graffiti` returns `String` (not `[u8; 32]`) because the API works with UTF-8 strings. The adapter handles byte-to-string conversion.
- All methods return `ApiError` directly. The handler maps `ApiError::NotFound` to 404, `ApiError::Internal` to 500.

#### `VoluntaryExitManager` trait

```rust
use async_trait::async_trait;
use eth_types::SignedVoluntaryExit;

use crate::error::ApiError;

#[async_trait]
pub trait VoluntaryExitManager: Send + Sync {
    async fn sign_voluntary_exit(
        &self,
        pubkey: &[u8; 48],
        epoch: Option<u64>,
    ) -> Result<SignedVoluntaryExit, ApiError>;
}
```

**Design decisions:**

- `async` because it makes network calls to the beacon node (resolve validator index, get genesis/fork data).
- Returns `SignedVoluntaryExit` from `eth_types` — the existing type already has correct serde attributes with `quoted_u64` for epoch/validator_index and hex-encoded signature.
- The trait does NOT submit to the beacon node. It only returns the signed message. This matches Lighthouse's behavior and the spec's `signVoluntaryExit` operation ID. **Decision: do not submit.** The caller (or another tool) can submit it via the beacon API if desired.
- `epoch: Option<u64>` — `None` means "use current epoch from beacon node."

#### Integration with existing traits

The two new traits join the existing five in `traits.rs`. They follow the same pattern: no `async_trait` for synchronous traits, `async_trait` only for `VoluntaryExitManager`. The `Pubkey` type alias (`[u8; 48]`) already exists in `traits.rs` and is reused.

```rust
// traits.rs — after the existing traits:
pub type Pubkey = [u8; 48];  // already exists

// Existing: KeystoreManager, SlashingProtection, ValidatorManager,
//           DoppelgangerMonitor, RemoteKeyManager

// New:
pub trait ValidatorConfigManager: Send + Sync { /* ... */ }

#[async_trait]
pub trait VoluntaryExitManager: Send + Sync { /* ... */ }
```

The `keymanager-api` crate's `Cargo.toml` already has `async_trait` transitively available (it's used via `tokio`), but we need to add `async-trait` as a direct dependency since the existing traits don't use it. Alternatively, we can use the native Rust async-in-traits (RPITIT) since the project uses Rust edition 2021+ with a sufficiently recent MSRV. Given that the existing signer traits use `async_trait`, we follow the same pattern for consistency.

**Dependency addition to `crates/keymanager-api/Cargo.toml`:**
```toml
async-trait.workspace = true
eth-types.workspace = true
```

`eth-types` is needed for `SignedVoluntaryExit` in the trait return type.

---

### 2. Error Type Extension

Add `NotFound` variant to `crates/keymanager-api/src/error.rs`:

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

This is consistent with the Keymanager API `ErrorResponse` schema (`{ "message": "..." }`).

---

### 3. Handler Design

All 10 new handlers are added to `crates/keymanager-api/src/handlers.rs`.

#### AppState Extension

```rust
pub struct AppState {
    // Existing fields (unchanged)
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
    pub remote_key_manager: Arc<dyn RemoteKeyManager>,
    pub allow_insecure_remote_signer: bool,
    // New fields
    pub config_manager: Arc<dyn ValidatorConfigManager>,
    pub exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
}
```

`exit_manager` is `Option` — if the beacon client is unavailable, the server starts without exit capability and returns a descriptive 500 error.

#### Request/Response Types

Added to `crates/keymanager-api/src/types.rs`:

```rust
// --- Fee Recipient ---

#[derive(Serialize)]
pub struct FeeRecipientData {
    pub pubkey: String,
    pub ethaddress: String,
}

#[derive(Serialize)]
pub struct FeeRecipientResponse {
    pub data: FeeRecipientData,
}

#[derive(Deserialize)]
pub struct SetFeeRecipientRequest {
    pub ethaddress: String,
}

// --- Gas Limit ---

#[derive(Serialize)]
pub struct GasLimitData {
    pub pubkey: String,
    pub gas_limit: String,  // Uint64 = string per spec
}

#[derive(Serialize)]
pub struct GasLimitResponse {
    pub data: GasLimitData,
}

#[derive(Deserialize)]
pub struct SetGasLimitRequest {
    pub gas_limit: String,  // Uint64 = string per spec
}

// --- Graffiti ---

#[derive(Serialize)]
pub struct GraffitiData {
    pub pubkey: String,
    pub graffiti: String,
}

#[derive(Serialize)]
pub struct GraffitiResponse {
    pub data: GraffitiData,
}

#[derive(Deserialize)]
pub struct SetGraffitiRequest {
    pub graffiti: String,
}

// --- Voluntary Exit ---

#[derive(Deserialize)]
pub struct VoluntaryExitQuery {
    pub epoch: Option<String>,  // Uint64 = string per spec
}

#[derive(Serialize)]
pub struct VoluntaryExitResponse {
    pub data: SignedVoluntaryExitData,
}

#[derive(Serialize)]
pub struct SignedVoluntaryExitData {
    pub message: VoluntaryExitMessageData,
    pub signature: String,
}

#[derive(Serialize)]
pub struct VoluntaryExitMessageData {
    pub epoch: String,
    pub validator_index: String,
}
```

**Note:** The voluntary exit response does NOT reuse `eth_types::SignedVoluntaryExit` directly for the HTTP response because the API serialization format must use `{ "data": { ... } }` wrapping and string-encoded fields. The handler converts from `eth_types::SignedVoluntaryExit` (which already has `quoted_u64` serde) into the response types.

Actually, since `eth_types::SignedVoluntaryExit` already serializes with `quoted_u64` and hex signature, we can simplify:

```rust
#[derive(Serialize)]
pub struct VoluntaryExitResponse {
    pub data: eth_types::SignedVoluntaryExit,
}
```

This works because `SignedVoluntaryExit` already serializes `epoch` and `validator_index` as strings (via `serde_utils::quoted_u64`) and `signature` as `0x`-prefixed hex (via `crate::serde_signature`). The `{ "data": { "message": { ... }, "signature": "0x..." } }` structure matches the spec exactly.

#### Handler Signatures

```rust
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

// --- Fee Recipient ---

pub async fn get_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<FeeRecipientResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    let address = state.config_manager.get_fee_recipient(&pubkey)
        .map_err(map_not_found)?;
    Ok(Json(FeeRecipientResponse {
        data: FeeRecipientData {
            pubkey: format_pubkey(&pubkey),
            ethaddress: format!("0x{}", hex::encode(address)),
        },
    }))
}

pub async fn set_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetFeeRecipientRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    let address = parse_eth_address(&request.ethaddress)?;
    // Reject 0x0000...0000 per spec
    if address == [0u8; 20] {
        return Err(ApiError::BadRequest(
            "cannot set fee recipient to zero address".into(),
        ));
    }
    state.config_manager.set_fee_recipient(&pubkey, address)?;
    Ok(StatusCode::ACCEPTED)  // 202
}

pub async fn delete_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    state.config_manager.delete_fee_recipient(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)  // 204
}

// --- Gas Limit ---

pub async fn get_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<GasLimitResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    let gas_limit = state.config_manager.get_gas_limit(&pubkey)?;
    Ok(Json(GasLimitResponse {
        data: GasLimitData {
            pubkey: format_pubkey(&pubkey),
            gas_limit: gas_limit.to_string(),  // String, not number
        },
    }))
}

pub async fn set_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetGasLimitRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    let gas_limit: u64 = request.gas_limit.parse()
        .map_err(|_| ApiError::BadRequest("invalid gas_limit: must be a numeric string".into()))?;
    state.config_manager.set_gas_limit(&pubkey, gas_limit)?;
    Ok(StatusCode::ACCEPTED)  // 202
}

pub async fn delete_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    state.config_manager.delete_gas_limit(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)  // 204
}

// --- Graffiti ---

pub async fn get_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<GraffitiResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    let graffiti = state.config_manager.get_graffiti(&pubkey)?;
    Ok(Json(GraffitiResponse {
        data: GraffitiData {
            pubkey: format_pubkey(&pubkey),
            graffiti,
        },
    }))
}

pub async fn set_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetGraffitiRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    if request.graffiti.len() > 32 {
        return Err(ApiError::BadRequest(
            "graffiti must be at most 32 bytes".into(),
        ));
    }
    state.config_manager.set_graffiti(&pubkey, &request.graffiti)?;
    Ok(StatusCode::ACCEPTED)  // 202
}

pub async fn delete_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    state.config_manager.delete_graffiti(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)  // 204
}

// --- Voluntary Exit ---

pub async fn sign_voluntary_exit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Query(query): Query<VoluntaryExitQuery>,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex)?;
    let epoch = query.epoch
        .map(|e| e.parse::<u64>())
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid epoch: must be a numeric string".into()))?;

    let exit_manager = state.exit_manager.as_ref().ok_or_else(|| {
        ApiError::Internal("voluntary exit not available: beacon node not configured".into())
    })?;

    tracing::warn!(
        pubkey = %pubkey_hex,
        epoch = ?epoch,
        "Voluntary exit requested — THIS IS IRREVERSIBLE"
    );

    let signed_exit = exit_manager.sign_voluntary_exit(&pubkey, epoch).await?;

    Ok(Json(VoluntaryExitResponse { data: signed_exit }))
}
```

#### Helper Functions

```rust
// Already exists in handlers.rs — reused for new handlers:
fn parse_pubkey(s: &str) -> Result<Pubkey, String> { /* ... */ }

// New helpers:
fn parse_eth_address(s: &str) -> Result<[u8; 20], ApiError> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid eth address hex: {e}")))?;
    if bytes.len() != 20 {
        return Err(ApiError::BadRequest(
            format!("invalid eth address length: expected 20 bytes, got {}", bytes.len()),
        ));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn format_pubkey(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}
```

The existing `parse_pubkey` returns `Result<Pubkey, String>`. The handlers need to convert this `String` error to `ApiError::BadRequest`. This is done at the call site:

```rust
let pubkey = parse_pubkey(&pubkey_hex)
    .map_err(|e| ApiError::BadRequest(e))?;
```

---

### 4. Config Persistence Design

#### `save_config()` on `ValidatorStore`

Added to `crates/validator-store/src/store.rs`:

```rust
use std::io::Write;
use tempfile::NamedTempFile;

impl ValidatorStore {
    pub fn has_validator(&self, pubkey: &[u8; 48]) -> bool {
        self.validators.read().contains_key(pubkey)
    }

    pub fn save_config(&self) -> Result<(), ValidatorStoreError> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ValidatorStoreError::Config("no config path set for save".to_string())
        })?;

        let parent = path.parent().unwrap_or(std::path::Path::new("."));

        // Serialize current state while holding read locks
        let toml_content = {
            let defaults = self.defaults.read();
            let validators = self.validators.read();
            self.serialize_to_toml(&defaults, &validators)?
        };

        // Atomic write: temp file in same directory → sync → rename
        let mut tmp = NamedTempFile::new_in(parent)
            .map_err(ValidatorStoreError::Io)?;
        tmp.write_all(toml_content.as_bytes())
            .map_err(ValidatorStoreError::Io)?;
        tmp.as_file().sync_all()
            .map_err(ValidatorStoreError::Io)?;
        tmp.persist(path)
            .map_err(|e| ValidatorStoreError::Io(e.error))?;

        Ok(())
    }

    fn serialize_to_toml(
        &self,
        defaults: &ValidatorDefaults,
        validators: &HashMap<[u8; 48], ValidatorConfig>,
    ) -> Result<String, ValidatorStoreError> {
        // Build TOML document preserving the same structure as load_from_config expects
        // [defaults] section + [[validators]] array
        // ... (serialization logic)
    }
}
```

#### Write Serialization Strategy

Concurrent writes are serialized by the existing `parking_lot::RwLock` on `validators`. The pattern is:

1. **API handler** calls `config_manager.set_fee_recipient(&pubkey, addr)`
2. **Adapter** calls `validator_store.update_config(pubkey, update)` — acquires write lock, mutates, releases
3. **Adapter** calls `validator_store.save_config()` — acquires read locks, serializes, writes temp file, renames

**Race window:** Between step 2 and step 3, another request could mutate the store. This is acceptable because `save_config()` captures the latest snapshot. The final state on disk always matches the final state in memory.

**If `save_config()` fails:** The in-memory state has the update but disk is stale. On restart, the change is lost. The adapter logs a warning. For the initial implementation, this trade-off is acceptable — config changes are infrequent, human-initiated operations.

#### How POST/DELETE Handlers Trigger Persistence

The adapter's `set_*` and `delete_*` methods handle the full cycle:

```text
Handler → adapter.set_fee_recipient()
            → store.update_config()    // in-memory update
            → store.save_config()      // atomic disk write
```

This is a two-step operation, not a combined atomic operation. The write lock is NOT held across the entire I/O — this is intentional to avoid blocking reads during disk I/O. Config updates are infrequent enough that the race window is negligible.

---

### 5. Adapter Design

Both adapters are added to `crates/rvc/src/keymanager_adapters.rs`.

#### `ValidatorConfigManagerAdapter`

```rust
use std::sync::Arc;
use keymanager_api::error::ApiError;
use keymanager_api::traits::ValidatorConfigManager;
use validator_store::ValidatorStore;

pub struct ValidatorConfigManagerAdapter {
    validator_store: Arc<ValidatorStore>,
}

impl ValidatorConfigManagerAdapter {
    pub fn new(validator_store: Arc<ValidatorStore>) -> Self {
        Self { validator_store }
    }

    fn ensure_validator_exists(&self, pubkey: &[u8; 48]) -> Result<(), ApiError> {
        if !self.validator_store.has_validator(pubkey) {
            return Err(ApiError::NotFound(format!(
                "no validator found with pubkey 0x{}",
                hex::encode(pubkey)
            )));
        }
        Ok(())
    }

    fn update_and_save(
        &self,
        pubkey: &[u8; 48],
        update: validator_store::ValidatorConfigUpdate,
    ) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.validator_store.update_config(pubkey, update);
        self.validator_store.save_config().map_err(|e| {
            tracing::error!(error = %e, "failed to persist config to disk");
            ApiError::Internal(format!("failed to persist config: {e}"))
        })?;
        Ok(())
    }
}

impl ValidatorConfigManager for ValidatorConfigManagerAdapter {
    fn get_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<[u8; 20], ApiError> {
        self.ensure_validator_exists(pubkey)?;
        Ok(self.validator_store.effective_fee_recipient(pubkey))
    }

    fn set_fee_recipient(&self, pubkey: &[u8; 48], address: [u8; 20]) -> Result<(), ApiError> {
        self.update_and_save(pubkey, validator_store::ValidatorConfigUpdate {
            fee_recipient: Some(Some(address)),
            ..Default::default()
        })
    }

    fn delete_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<(), ApiError> {
        self.update_and_save(pubkey, validator_store::ValidatorConfigUpdate {
            fee_recipient: Some(None),  // Some(None) = delete override
            ..Default::default()
        })
    }

    fn get_gas_limit(&self, pubkey: &[u8; 48]) -> Result<u64, ApiError> {
        self.ensure_validator_exists(pubkey)?;
        Ok(self.validator_store.effective_gas_limit(pubkey))
    }

    fn set_gas_limit(&self, pubkey: &[u8; 48], gas_limit: u64) -> Result<(), ApiError> {
        self.update_and_save(pubkey, validator_store::ValidatorConfigUpdate {
            gas_limit: Some(Some(gas_limit)),
            ..Default::default()
        })
    }

    fn delete_gas_limit(&self, pubkey: &[u8; 48]) -> Result<(), ApiError> {
        self.update_and_save(pubkey, validator_store::ValidatorConfigUpdate {
            gas_limit: Some(None),
            ..Default::default()
        })
    }

    fn get_graffiti(&self, pubkey: &[u8; 48]) -> Result<String, ApiError> {
        self.ensure_validator_exists(pubkey)?;
        let graffiti_bytes = self.validator_store.effective_graffiti(pubkey);
        match graffiti_bytes {
            Some(bytes) => {
                let s = std::str::from_utf8(&bytes)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                Ok(s.to_string())
            }
            None => Ok(String::new()),
        }
    }

    fn set_graffiti(&self, pubkey: &[u8; 48], graffiti: &str) -> Result<(), ApiError> {
        let mut bytes = [0u8; 32];
        let len = graffiti.len().min(32);
        bytes[..len].copy_from_slice(&graffiti.as_bytes()[..len]);
        self.update_and_save(pubkey, validator_store::ValidatorConfigUpdate {
            graffiti: Some(Some(bytes)),
            ..Default::default()
        })
    }

    fn delete_graffiti(&self, pubkey: &[u8; 48]) -> Result<(), ApiError> {
        self.update_and_save(pubkey, validator_store::ValidatorConfigUpdate {
            graffiti: Some(None),
            ..Default::default()
        })
    }
}
```

**Key patterns:**
- `ensure_validator_exists()` checks before every operation — consistent 404 for unknown pubkeys.
- `update_and_save()` centralizes the two-step update + persist pattern.
- Uses the existing `ValidatorConfigUpdate` `Option<Option<T>>` pattern: `Some(Some(v))` = set, `Some(None)` = delete.

#### `VoluntaryExitManagerAdapter`

```rust
use std::sync::Arc;
use async_trait::async_trait;
use beacon::BeaconClient;
use crypto::CompositeSigner;
use eth_types::{ForkSchedule, Root, SignedVoluntaryExit, VoluntaryExit, SECONDS_PER_SLOT, SLOTS_PER_EPOCH};
use keymanager_api::error::ApiError;
use keymanager_api::traits::VoluntaryExitManager;
use signer::SignerService;

pub struct VoluntaryExitManagerAdapter {
    beacon_client: Arc<BeaconClient>,
    signer: Arc<SignerService>,
    fork_schedule: Arc<ForkSchedule>,
    genesis_validators_root: Root,
}

impl VoluntaryExitManagerAdapter {
    pub fn new(
        beacon_client: Arc<BeaconClient>,
        signer: Arc<SignerService>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self {
            beacon_client,
            signer,
            fork_schedule,
            genesis_validators_root,
        }
    }
}

#[async_trait]
impl VoluntaryExitManager for VoluntaryExitManagerAdapter {
    async fn sign_voluntary_exit(
        &self,
        pubkey: &[u8; 48],
        epoch: Option<u64>,
    ) -> Result<SignedVoluntaryExit, ApiError> {
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));

        // 1. Resolve validator index from beacon node
        let validators_response = self.beacon_client
            .get_validators(std::slice::from_ref(&pubkey_hex))
            .await
            .map_err(|e| ApiError::Internal(format!("beacon node error: {e}")))?;

        let validator = validators_response.data.first()
            .ok_or_else(|| ApiError::NotFound(format!(
                "validator not found on beacon node: {pubkey_hex}"
            )))?;

        let validator_index: u64 = validator.index.parse()
            .map_err(|e| ApiError::Internal(format!("invalid validator index: {e}")))?;

        // 2. Determine epoch
        let exit_epoch = match epoch {
            Some(e) => e,
            None => {
                let genesis = self.beacon_client.get_genesis().await
                    .map_err(|e| ApiError::Internal(format!("failed to get genesis: {e}")))?;
                let genesis_time: u64 = genesis.data.genesis_time.parse()
                    .map_err(|e| ApiError::Internal(format!("invalid genesis time: {e}")))?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time before UNIX epoch")
                    .as_secs();
                let current_slot = now.saturating_sub(genesis_time) / SECONDS_PER_SLOT;
                current_slot / SLOTS_PER_EPOCH
            }
        };

        // 3. Construct the VoluntaryExit message
        let voluntary_exit = VoluntaryExit {
            epoch: exit_epoch,
            validator_index,
        };

        // 4. Sign using the signer service
        let crypto_pubkey = crypto::PublicKey::from_bytes(pubkey)
            .map_err(|e| ApiError::Internal(format!("invalid public key: {e:?}")))?;

        let signature = self.signer
            .sign_voluntary_exit(
                &voluntary_exit,
                &crypto_pubkey,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("signing failed: {e}")))?;

        Ok(SignedVoluntaryExit {
            message: voluntary_exit,
            signature,
        })
    }
}
```

**How the adapter gets its dependencies:**

All dependencies are pre-constructed and injected via `Arc` from `main.rs`:

| Dependency | Source in `main.rs` | Already exists? |
|-----------|-------------------|-----------------|
| `BeaconClient` | `beacon_client` variable (created in step 2) | Yes |
| `SignerService` | `signer` variable (created in step 5) | Yes |
| `ForkSchedule` | `fork_schedule` variable (fetched in step 3) | Yes |
| `genesis_validators_root` | `genesis_validators_root` (parsed in step 3) | Yes |

Unlike the CLI's `voluntary_exit.rs` which constructs its own signer from scratch, the API adapter reuses the existing pre-constructed instances from the server's dependency injection.

---

### 6. Network Extension Design

#### Network Enum Changes

`crates/rvc/src/config/network.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Hoodi,
    Holesky,
    Sepolia,
    Custom,
}

impl Network {
    pub fn genesis_time(&self) -> Option<u64> {
        match self {
            Network::Mainnet => Some(1_606_824_023),
            Network::Hoodi => Some(1_742_213_400),
            Network::Holesky => Some(1_695_902_400),
            Network::Sepolia => Some(1_655_733_600),
            Network::Custom => None,
        }
    }

    pub fn genesis_validators_root(&self) -> Option<&'static str> {
        match self {
            Network::Mainnet => Some("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
            Network::Hoodi => Some("0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"),
            Network::Holesky => Some("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"),
            Network::Sepolia => Some("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"),
            Network::Custom => None,
        }
    }

    // seconds_per_slot() and slots_per_epoch() unchanged — both testnets use mainnet values
}
```

Update `FromStr` and `Display` to include `"holesky"` and `"sepolia"`.

#### Keygen Tool Changes

`bin/rvc-keygen/src/network.rs`:

```rust
pub const HOLESKY: KeygenNetwork = KeygenNetwork {
    name: "holesky",
    genesis_fork_version: [0x01, 0x01, 0x70, 0x00],
    genesis_validators_root: [
        0x91, 0x43, 0xaa, 0x7c, 0x61, 0x5a, 0x7f, 0x71, 0x15, 0xe2, 0xb6, 0xaa, 0xc3, 0x19, 0xc0, 0x35,
        0x29, 0xdf, 0x82, 0x42, 0xae, 0x70, 0x5f, 0xba, 0x9d, 0xf3, 0x9b, 0x79, 0xc5, 0x9f, 0xa8, 0xb1,
    ],
    capella_fork_version: [0x04, 0x01, 0x70, 0x00],
};

pub const SEPOLIA: KeygenNetwork = KeygenNetwork {
    name: "sepolia",
    genesis_fork_version: [0x90, 0x00, 0x00, 0x69],
    genesis_validators_root: [
        0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a,
        0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78,
    ],
    capella_fork_version: [0x90, 0x00, 0x00, 0x72],
};

pub fn from_name(name: &str) -> Result<&'static KeygenNetwork> {
    match name.to_lowercase().as_str() {
        "mainnet" => Ok(&MAINNET),
        "hoodi" => Ok(&HOODI),
        "holesky" => Ok(&HOLESKY),
        "sepolia" => Ok(&SEPOLIA),
        other => bail!("Unknown network: '{}'. Supported: mainnet, hoodi, holesky, sepolia", other),
    }
}
```

#### Test Changes

In `crates/rvc/src/config/network.rs`:

```rust
#[test]
fn test_network_from_str_deprecated_networks_rejected() {
    assert!("goerli".parse::<Network>().is_err());
    // Holesky and Sepolia removed from this test
}

#[test]
fn test_network_from_str_testnets_accepted() {
    assert_eq!("holesky".parse::<Network>().unwrap(), Network::Holesky);
    assert_eq!("sepolia".parse::<Network>().unwrap(), Network::Sepolia);
    assert_eq!("HOLESKY".parse::<Network>().unwrap(), Network::Holesky);
    assert_eq!("SEPOLIA".parse::<Network>().unwrap(), Network::Sepolia);
}

#[test]
fn test_network_serde_deprecated_networks_rejected() {
    assert!(serde_json::from_str::<Network>("\"goerli\"").is_err());
    // Holesky and Sepolia removed from this test
}

#[test]
fn test_network_serde_testnets() {
    let holesky = Network::Holesky;
    assert_eq!(serde_json::to_string(&holesky).unwrap(), "\"holesky\"");
    assert_eq!(serde_json::from_str::<Network>("\"holesky\"").unwrap(), Network::Holesky);

    let sepolia = Network::Sepolia;
    assert_eq!(serde_json::to_string(&sepolia).unwrap(), "\"sepolia\"");
    assert_eq!(serde_json::from_str::<Network>("\"sepolia\"").unwrap(), Network::Sepolia);
}

#[test]
fn test_network_genesis_constants_holesky() {
    assert_eq!(Network::Holesky.genesis_time(), Some(1_695_902_400));
    assert_eq!(
        Network::Holesky.genesis_validators_root(),
        Some("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1")
    );
}

#[test]
fn test_network_genesis_constants_sepolia() {
    assert_eq!(Network::Sepolia.genesis_time(), Some(1_655_733_600));
    assert_eq!(
        Network::Sepolia.genesis_validators_root(),
        Some("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
    );
}
```

---

### 7. Server Wiring

#### Changes to `KeymanagerServer::new()`

`crates/keymanager-api/src/server.rs`:

```rust
use crate::traits::{
    DoppelgangerMonitor, KeystoreManager, RemoteKeyManager, SlashingProtection,
    ValidatorConfigManager, ValidatorManager, VoluntaryExitManager,
};

impl KeymanagerServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keystore_manager: Arc<dyn KeystoreManager>,
        slashing_protection: Arc<dyn SlashingProtection>,
        validator_manager: Arc<dyn ValidatorManager>,
        doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
        remote_key_manager: Arc<dyn RemoteKeyManager>,
        config_manager: Arc<dyn ValidatorConfigManager>,             // NEW
        exit_manager: Option<Arc<dyn VoluntaryExitManager>>,         // NEW
        token: String,
        addr: SocketAddr,
        cors_origins: Vec<String>,
        body_limit: usize,
        allow_insecure_remote_signer: bool,
    ) -> Self {
        Self {
            state: Arc::new(AppState {
                keystore_manager,
                slashing_protection,
                validator_manager,
                doppelganger_monitor,
                remote_key_manager,
                allow_insecure_remote_signer,
                config_manager,      // NEW
                exit_manager,        // NEW
            }),
            // ... rest unchanged
        }
    }
}
```

#### Route Registration Additions

In `KeymanagerServer::router()`:

```rust
let api = Router::new()
    // Existing routes (unchanged)
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
        post(handlers::sign_voluntary_exit),
    )
    .layer(DefaultBodyLimit::max(self.body_limit))
    .with_state(self.state.clone());
```

All new routes go through the same auth middleware and CORS layer as existing routes.

#### Changes to `main.rs`

In `bin/rvc/src/main.rs`, after the existing adapter construction:

```rust
// Existing adapters (unchanged)
let keystore_mgr = Arc::new(KeystoreManagerAdapter::new(/* ... */));
let slashing_prot = Arc::new(SlashingProtectionAdapter::new(/* ... */));
let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
let doppelganger_mon = Arc::new(DoppelgangerMonitorAdapter::new());
let remote_key_mgr = Arc::new(RemoteKeyManagerAdapter::new(/* ... */));

// NEW: Config manager adapter
let config_mgr = Arc::new(ValidatorConfigManagerAdapter::new(validator_store.clone()));

// NEW: Voluntary exit adapter (optional — requires beacon client and signer)
let exit_mgr: Option<Arc<dyn VoluntaryExitManager>> = Some(Arc::new(
    VoluntaryExitManagerAdapter::new(
        beacon_client.clone(),
        signer.clone(),
        fork_schedule.clone(),
        genesis_validators_root,
    ),
));

// Updated server construction
let km_server = keymanager_api::KeymanagerServer::new(
    keystore_mgr,
    slashing_prot,
    validator_mgr,
    doppelganger_mon,
    remote_key_mgr,
    config_mgr,    // NEW
    exit_mgr,      // NEW
    token.to_string(),
    km_addr,
    config.keymanager_cors_origins.clone(),
    config.keymanager_body_limit,
    config.allow_insecure_remote_signer,
);
```

The `beacon_client`, `signer`, `fork_schedule`, and `genesis_validators_root` are all already constructed earlier in the main function. No additional setup is needed.

---

### 8. Data Flow Diagrams

#### POST fee recipient

```text
Client ──POST /eth/v1/validator/:pubkey/feerecipient──▶ Axum router
  │                                                         │
  │  Authorization: Bearer <token>                          │ bearer_auth middleware
  │  { "ethaddress": "0xabc..." }                           │
  │                                                         ▼
  │                                              handlers::set_fee_recipient()
  │                                                  │
  │                                                  ├─ parse_pubkey() → [u8; 48]
  │                                                  ├─ parse_eth_address() → [u8; 20]
  │                                                  ├─ reject 0x00 address → 400
  │                                                  │
  │                                                  ▼
  │                                     config_manager.set_fee_recipient()
  │                                                  │
  │                                                  ▼
  │                                ValidatorConfigManagerAdapter
  │                                    │
  │                                    ├─ ensure_validator_exists() ─── 404 if not found
  │                                    ├─ store.update_config(pubkey, {
  │                                    │      fee_recipient: Some(Some(addr))
  │                                    │  })
  │                                    │      └─ acquires write lock, mutates, releases
  │                                    │
  │                                    └─ store.save_config()
  │                                           ├─ acquire read locks
  │                                           ├─ serialize to TOML string
  │                                           ├─ write to NamedTempFile in same dir
  │                                           ├─ sync_all()
  │                                           └─ persist() (atomic rename)
  │
  ◀──────────── 202 Accepted (no body) ────────────
```

#### GET fee recipient

```text
Client ──GET /eth/v1/validator/:pubkey/feerecipient──▶ Axum router
  │                                                        │
  │  Authorization: Bearer <token>                         │ bearer_auth middleware
  │                                                        ▼
  │                                             handlers::get_fee_recipient()
  │                                                  │
  │                                                  ├─ parse_pubkey()
  │                                                  ▼
  │                                     config_manager.get_fee_recipient()
  │                                                  │
  │                                                  ▼
  │                                ValidatorConfigManagerAdapter
  │                                    │
  │                                    ├─ ensure_validator_exists() ─── 404 if not found
  │                                    └─ store.effective_fee_recipient(pubkey)
  │                                           └─ read lock → override or default → release
  │
  ◀──────────── 200 OK ────────────
                { "data": { "pubkey": "0x...", "ethaddress": "0x..." } }

  NOTE: No disk I/O on read path. Sub-millisecond response.
```

#### POST voluntary exit

```text
Client ──POST /eth/v1/validator/:pubkey/voluntary_exit?epoch=300000──▶ Axum router
  │                                                                        │
  │  Authorization: Bearer <token>                                         │
  │                                                                        ▼
  │                                                         handlers::sign_voluntary_exit()
  │                                                              │
  │                                                              ├─ parse_pubkey()
  │                                                              ├─ parse epoch from query (optional)
  │                                                              ├─ check exit_manager is Some ── 500 if None
  │                                                              ├─ WARN log: "Voluntary exit requested"
  │                                                              │
  │                                                              ▼
  │                                                 exit_manager.sign_voluntary_exit()
  │                                                              │
  │                                                              ▼
  │                                              VoluntaryExitManagerAdapter
  │                                                  │
  │                                                  ├─ beacon_client.get_validators([pubkey])
  │                                                  │      └──HTTP──▶ Beacon Node
  │                                                  │                 GET /eth/v1/beacon/states/head/validators?id=0x...
  │                                                  │      ◀─────── { validator_index: "12345" }
  │                                                  │
  │                                                  ├─ (if epoch=None) beacon_client.get_genesis()
  │                                                  │      └──HTTP──▶ Beacon Node
  │                                                  │      ◀─────── { genesis_time: "..." }
  │                                                  │      └─ compute current_slot / SLOTS_PER_EPOCH
  │                                                  │
  │                                                  ├─ construct VoluntaryExit { epoch, validator_index }
  │                                                  │
  │                                                  └─ signer.sign_voluntary_exit(exit, pubkey, fork_schedule, root)
  │                                                         └─ CompositeSigner → BLS signature
  │
  ◀──────────── 200 OK ────────────
                { "data": {
                    "message": { "epoch": "300000", "validator_index": "12345" },
                    "signature": "0x..."
                }}
```

---

## Cross-Cutting Concerns

### Authentication & Authorization

All 10 new endpoints share the existing Bearer token auth middleware (`auth::with_auth`). No changes needed — routes are registered inside the same `Router` that gets wrapped with the auth layer. The constant-time comparison in `bearer_auth` protects against timing attacks.

### Logging & Observability

- **GET handlers:** `trace!` level for config lookups (existing pattern in `ValidatorStore`)
- **POST/DELETE handlers:** `info!` level for config changes (existing pattern in `update_config()`)
- **Voluntary exit:** `warn!` level — irreversible operation. Logs pubkey and epoch.
- **Save failures:** `error!` level — config persistence failed, in-memory and disk diverged.

### Error Handling

All errors flow through `ApiError` → `IntoResponse`:

| Condition | ApiError variant | HTTP Status |
|-----------|-----------------|-------------|
| Malformed pubkey hex | `BadRequest` | 400 |
| Invalid eth address | `BadRequest` | 400 |
| Zero fee recipient | `BadRequest` | 400 |
| Non-numeric gas_limit | `BadRequest` | 400 |
| Graffiti > 32 bytes | `BadRequest` | 400 |
| Invalid epoch | `BadRequest` | 400 |
| Missing auth token | (auth middleware) | 401 |
| Unknown validator pubkey | `NotFound` | 404 |
| Beacon node unreachable | `Internal` | 500 |
| Config persistence failure | `Internal` | 500 |
| Exit manager not configured | `Internal` | 500 |
| Signing failure | `Internal` | 500 |

### Configuration

No new configuration knobs are introduced. The existing `--keymanager-address`, `--keymanager-cors-origins`, and `--keymanager-body-limit` flags govern the server. The new endpoints are automatically available when the Keymanager API server is enabled.

---

## Infrastructure & Deployment

### Deployment Model

No changes to the deployment model. rvc remains a single binary. The new endpoints are part of the existing Keymanager API server (same port, same auth).

### Dependency Additions

**`crates/keymanager-api/Cargo.toml`:**
```toml
[dependencies]
# Add:
async-trait.workspace = true
eth-types.workspace = true
```

These are already workspace dependencies used by other crates. No new external crates.

**`crates/validator-store/Cargo.toml`:**
```toml
[dependencies]
# Add (move from dev-dependencies if needed):
tempfile.workspace = true
```

`tempfile` is already a workspace dependency (used in test code). It needs to be a regular dependency for `save_config()`.

---

## Technology Choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| HTTP framework | Axum 0.7 (existing) | Already in use, clean extractor model |
| Serialization | serde + serde_json (existing) | Standard Rust ecosystem |
| Config format | TOML (existing) | Already used for validator config |
| Atomic writes | `tempfile` crate (existing workspace dep) | Battle-tested, handles cleanup on error |
| Synchronization | `parking_lot::RwLock` (existing) | Already used in `ValidatorStore` |
| Async traits | `async-trait` crate | Consistent with signer traits |

---

## ADRs (Architecture Decision Records)

### ADR-001: Voluntary Exit Does Not Submit to Beacon Node

- **Status:** Accepted
- **Context:** The PRD (FR-7) says "Submit the signed exit to the beacon node." However, the official spec's operationId is `signVoluntaryExit` (not "submit"), and Lighthouse's implementation only returns the signed message without submitting.
- **Decision:** The API endpoint signs and returns the `SignedVoluntaryExit` but does NOT submit it to the beacon node. The caller can submit it themselves via `POST /eth/v1/beacon/pool/voluntary_exits` on the beacon node.
- **Alternatives Considered:** (1) Submit and return — adds beacon node write dependency, couples signing with submission. (2) Submit-only — doesn't return the signed message, less useful.
- **Consequences:** Matches reference implementations. Simpler error handling. The operator must take an extra step to submit, but this is consistent with the "sign, then review, then submit" workflow for irreversible operations.

### ADR-002: epoch as Query Parameter (Not Request Body)

- **Status:** Accepted
- **Context:** The PRD specified `epoch` as a JSON request body field. The official OpenAPI spec defines it as an optional query parameter with no request body.
- **Decision:** Follow the spec. `epoch` is an optional query parameter: `POST /eth/v1/validator/:pubkey/voluntary_exit?epoch=300000`.
- **Alternatives Considered:** Request body as in the PRD draft — would break compatibility with standard tooling.
- **Consequences:** Full spec compliance. Tools built against the standard Keymanager API work without modification.

### ADR-003: exit_manager is Option in AppState

- **Status:** Accepted
- **Context:** The voluntary exit endpoint requires a beacon client, signer, and fork schedule. In some deployment topologies, the Keymanager API server may not have access to a beacon client.
- **Decision:** `exit_manager` is `Option<Arc<dyn VoluntaryExitManager>>`. If `None`, the voluntary exit endpoint returns HTTP 500 with "voluntary exit not available: beacon node not configured."
- **Alternatives Considered:** (1) Require beacon client — breaks server startup when beacon is unavailable. (2) Skip route registration — harder to diagnose, tools get 404 instead of a descriptive error.
- **Consequences:** The server starts successfully even without exit capability. Other 9 endpoints work normally. Descriptive error message helps operators diagnose the issue.

### ADR-004: Two-Step Update + Save (Not Combined Atomic)

- **Status:** Accepted
- **Context:** Config mutations involve an in-memory update (under write lock) and a disk write (temp file + rename). These could be a single atomic operation holding the write lock across I/O, or two separate steps.
- **Decision:** Two separate steps: `update_config()` releases the write lock, then `save_config()` acquires read locks for serialization. The write lock is NOT held during I/O.
- **Alternatives Considered:** Hold write lock across both operations — serializes all reads behind I/O, adds latency to GET requests.
- **Consequences:** GET requests are never blocked by disk I/O. Tiny race window between update and save is acceptable: if two concurrent POSTs interleave, both in-memory updates are applied and the last `save_config()` captures both. If save fails, in-memory and disk diverge — logged at `error` level.

### ADR-005: Reuse eth_types::SignedVoluntaryExit for Response

- **Status:** Accepted
- **Context:** The voluntary exit response needs `{ "data": { "message": { "epoch": "...", "validator_index": "..." }, "signature": "0x..." } }`. The existing `eth_types::SignedVoluntaryExit` already serializes with `quoted_u64` (string-encoded numbers) and hex signature.
- **Decision:** Wrap `eth_types::SignedVoluntaryExit` in `VoluntaryExitResponse { data: SignedVoluntaryExit }` rather than defining custom response types.
- **Alternatives Considered:** Custom `VoluntaryExitMessageData` and `SignedVoluntaryExitData` structs — duplicates existing serde logic.
- **Consequences:** Less code, guaranteed consistency with the consensus types. If `eth_types` changes serde attributes, the API response changes too (desired behavior).

---

## Architecture Quality Checklist

- [x] **No circular dependencies** — keymanager-api depends on traits only; adapters depend on domain crates; domain crates don't depend on HTTP layer
- [x] **Each module has a single, clear responsibility** — traits.rs defines contracts, handlers.rs handles HTTP, adapters bridge to implementations
- [x] **No shared databases** — ValidatorStore is the single owner of config data; accessed only through traits
- [x] **All inter-module communication goes through defined interfaces** — handlers never import `ValidatorStore` directly
- [x] **Every module can be tested in isolation** — mock `ValidatorConfigManager` and `VoluntaryExitManager` for handler tests; mock `ValidatorStore` for adapter tests
- [x] **Cross-cutting concerns are standardized** — auth middleware, error format, logging levels
- [x] **Failure modes are defined** — beacon node down → 500; save fails → error log; exit_manager absent → descriptive 500
- [x] **Data flow is traceable** — diagrams above cover all three major flows
- [x] **Module count is justified** — no new crates or files; changes spread across existing modules

---

## Open Questions

None. All architectural decisions have been made based on the PRD, spec research, and reference implementations.

## Risks

| Risk | Mitigation |
|------|-----------|
| Genesis constants are wrong | Verified against 3 independent sources (see testnet-constants.md). Unit tests assert exact values. |
| Concurrent save_config corrupts TOML | Atomic write via tempfile+rename. Only temp file can be partial; rename is atomic on all target filesystems. |
| Voluntary exit accidentally triggered | WARN-level log on every exit request. API only signs, does not submit. Operator must take explicit action to broadcast. |
| Existing endpoints regress | No existing handler code is modified. AppState gains new fields (additive). All existing tests continue to pass. |
| keymanager-api Cargo.toml breaks | Only 2 new workspace deps added (async-trait, eth-types) — both already used by other crates in the workspace. |
