# Phase 2: Config Endpoints — Fee Recipient, Gas Limit, Graffiti

## Phase Overview

- **Goal:** Implement all 9 config management endpoints (GET/POST/DELETE for fee_recipient, gas_limit, graffiti) with persistence, following the Keymanager API spec exactly.
- **Issue count:** 7 issues, 14 total points
- **Estimated duration:** 4 days (with 2 parallel streams)
- **Entry criteria:** Phase 1 Stream A tasks (1.1, 1.2, 1.3) complete. `ValidatorConfigManager` trait, `ApiError::NotFound`, and `save_config()` all available.
- **Exit criteria:**
  - All 9 config handlers respond with correct status codes (200/202/204/400/404)
  - `gas_limit` is string-encoded in JSON responses (not a JSON number)
  - Fee recipient POST rejects `0x00...00` with 400
  - Graffiti POST rejects > 32 bytes with 400
  - Config changes persist to TOML and survive simulated restart
  - All handlers require Bearer auth (401 without token)
  - `cargo test` passes

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | Blocks | New Files | Modified Files |
|-------|-------|--------|--------|------------|--------|-----------|----------------|
| 2.1 | Add request/response types and helpers | 2 | A | 1.2 | 2.3, 2.4, 2.5 | — | `types.rs`, `handlers.rs` |
| 2.2 | Implement ValidatorConfigManagerAdapter | 3 | A | 1.1, 1.3 | 2.7, 4.4 | — | `keymanager_adapters.rs` |
| 2.3 | Implement fee recipient handlers | 2 | A | 2.1 | 2.6 | — | `handlers.rs` |
| 2.4 | Implement gas limit handlers | 2 | A | 2.1 | 2.6 | — | `handlers.rs` |
| 2.5 | Implement graffiti handlers | 2 | A | 2.1 | 2.6 | — | `handlers.rs` |
| 2.6 | Register config routes and extend AppState | 2 | A | 2.3, 2.4, 2.5 | 2.7, 3.4 | — | `handlers.rs`, `server.rs` |
| 2.7 | Wire config adapter into main.rs | 1 | A | 2.2, 2.6 | 4.1, 4.2 | — | `main.rs` |

## Phase Parallel Plan

| Day | Stream A (Dev A) | Stream B (Dev B) |
|-----|-----------------|-----------------|
| 4 (offset from Phase 1) | 2.1 Types (2pts, started day 2) | 2.2 Config adapter (3pts) |
| 5 | 2.3 Fee handlers (2pts) | 2.2 cont. |
| 6 | 2.4 Gas handlers (2pts) | (available for 2.5 or Phase 3 pull-ahead) |
| 7 | 2.5 Graffiti handlers (2pts) + 2.6 Routes (2pts) | — |
| 8 | 2.7 Wire config (1pt) | — |

> Dev B completes 2.2 (adapter) while Dev A iterates through handlers. Dev A then handles route registration (2.6) and wiring (2.7) since these are sequential and small.

---

## Issues

### Issue 2.1: Add request/response types and helpers

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 1.2 (NotFound variant — needed for error mapping in helpers)
- **Blocks:** 2.3, 2.4, 2.5
- **Scope:** 1 day

**Description:**

Add all serde structs for the 9 config endpoints to `crates/keymanager-api/src/types.rs`, and add `parse_eth_address()` and `format_pubkey()` helper functions to `crates/keymanager-api/src/handlers.rs`. These types and helpers are shared by all config handler issues.

**Implementation Notes:**

- Files modified: `crates/keymanager-api/src/types.rs`, `crates/keymanager-api/src/handlers.rs`
- Types to add in `types.rs` (per architecture doc section 3):

  ```rust
  // Fee recipient
  FeeRecipientData { pubkey: String, ethaddress: String }           // Serialize
  FeeRecipientResponse { data: FeeRecipientData }                   // Serialize
  SetFeeRecipientRequest { ethaddress: String }                     // Deserialize

  // Gas limit
  GasLimitData { pubkey: String, gas_limit: String }                // Serialize — gas_limit is STRING per spec
  GasLimitResponse { data: GasLimitData }                           // Serialize
  SetGasLimitRequest { gas_limit: String }                          // Deserialize — string per spec

  // Graffiti
  GraffitiData { pubkey: String, graffiti: String }                 // Serialize
  GraffitiResponse { data: GraffitiData }                           // Serialize
  SetGraffitiRequest { graffiti: String }                           // Deserialize
  ```

- Helpers to add in `handlers.rs`:
  - `parse_eth_address(s: &str) -> Result<[u8; 20], ApiError>` — strip `0x`, hex decode, validate 20 bytes
  - `format_pubkey(pubkey: &[u8; 48]) -> String` — `format!("0x{}", hex::encode(pubkey))`
- The existing `parse_pubkey()` in handlers.rs returns `Result<Pubkey, String>`. Callers will `.map_err(ApiError::BadRequest)`.
- Add `use axum::extract::{Path, Query};` and `use axum::http::StatusCode;` imports (needed by handler issues)
- Conflict note: `handlers.rs` is touched by 2.3–2.6 and 3.3. Each issue appends to a different section. Helpers go at the bottom, before the `#[cfg(test)]` module.
- Files NOT to modify: `server.rs`, `keymanager_adapters.rs`, `main.rs`

**Acceptance Criteria:**

- [ ] All 9 serde structs compile and derive correct traits (Serialize/Deserialize)
- [ ] `parse_eth_address("0xAbcF8e0d4e9587369b2301D0790347320302cc09")` returns correct 20-byte array
- [ ] `parse_eth_address("invalid")` returns `ApiError::BadRequest`
- [ ] `format_pubkey()` returns `0x`-prefixed lowercase hex
- [ ] `cargo check -p keymanager-api` passes

**Testing Requirements:**

- [ ] Unit test: `parse_eth_address` with valid address, invalid hex, wrong length
- [ ] Unit test: `format_pubkey` round-trip with `parse_pubkey`

---

### Issue 2.2: Implement ValidatorConfigManagerAdapter

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 1.1 (trait definition), 1.3 (`save_config()` and `has_validator()`)
- **Blocks:** 2.7, 4.4
- **Scope:** 1.5 days

**Description:**

Add `ValidatorConfigManagerAdapter` struct to `crates/rvc/src/keymanager_adapters.rs` that implements the `ValidatorConfigManager` trait by delegating to `ValidatorStore`. This adapter bridges the keymanager-api trait layer to the concrete validator-store implementation.

**Implementation Notes:**

- File modified: `crates/rvc/src/keymanager_adapters.rs`
- Add struct with `validator_store: Arc<ValidatorStore>` field
- Implement all 9 trait methods per architecture doc section 5:
  - `ensure_validator_exists()` private helper — calls `validator_store.has_validator()`, returns `ApiError::NotFound` if not found
  - `update_and_save()` private helper — calls `update_config()` then `save_config()`, logs error on save failure
  - `get_fee_recipient` → `ensure_validator_exists` → `validator_store.effective_fee_recipient()`
  - `set_fee_recipient` → `update_and_save` with `ValidatorConfigUpdate { fee_recipient: Some(Some(addr)), ..Default::default() }`
  - `delete_fee_recipient` → `update_and_save` with `ValidatorConfigUpdate { fee_recipient: Some(None), ..Default::default() }`
  - Same pattern for gas_limit and graffiti
- Graffiti conversion: `get_graffiti` converts `Option<[u8; 32]>` to `String` (trim null bytes). `set_graffiti` converts `&str` to `[u8; 32]` (pad with zeros).
- Add required imports: `keymanager_api::traits::ValidatorConfigManager`, `keymanager_api::error::ApiError`, `validator_store::{ValidatorStore, ValidatorConfigUpdate}`
- Conflict note: `keymanager_adapters.rs` is also touched by 3.2 (exit adapter). Append the config adapter struct before the `#[cfg(test)]` module. 3.2 will append below it.
- Files NOT to modify: `traits.rs`, `handlers.rs`, `server.rs`

**Acceptance Criteria:**

- [ ] `ValidatorConfigManagerAdapter` compiles and implements `ValidatorConfigManager`
- [ ] `get_fee_recipient` returns effective value (per-validator override or default)
- [ ] `set_fee_recipient` updates in-memory AND persists to disk
- [ ] `delete_fee_recipient` removes override AND persists
- [ ] Unknown pubkey returns `ApiError::NotFound` for all 9 methods
- [ ] Same behavior for gas_limit and graffiti methods
- [ ] `cargo test` passes

**Testing Requirements:**

- [ ] Unit test: create `ValidatorStore` with test config, construct adapter, test all 9 methods
- [ ] Unit test: get returns effective value (override > default fallback)
- [ ] Unit test: set then get returns updated value
- [ ] Unit test: delete then get returns default value
- [ ] Unit test: unknown pubkey returns NotFound error
- [ ] Unit test: save_config is called after set/delete (verify file on disk changes)

---

### Issue 2.3: Implement fee recipient handlers (GET/POST/DELETE)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.1 (types and helpers)
- **Blocks:** 2.6
- **Scope:** 1 day

**Description:**

Add 3 Axum handler functions for fee recipient management to `crates/keymanager-api/src/handlers.rs`:

- `get_fee_recipient` — GET, returns 200 with `FeeRecipientResponse`
- `set_fee_recipient` — POST, returns 202 (no body)
- `delete_fee_recipient` — DELETE, returns 204 (no body)

**Implementation Notes:**

- File modified: `crates/keymanager-api/src/handlers.rs`
- Handler signatures per architecture doc section 3:
  ```rust
  pub async fn get_fee_recipient(
      State(state): State<Arc<AppState>>,
      Path(pubkey_hex): Path<String>,
  ) -> Result<Json<FeeRecipientResponse>, ApiError>
  ```
- POST handler:
  1. Parse pubkey from path with `parse_pubkey()`, map error to `BadRequest`
  2. Parse `SetFeeRecipientRequest` from JSON body
  3. Parse ethaddress with `parse_eth_address()`
  4. **Reject zero address** (`[0u8; 20]`) with `ApiError::BadRequest` — per Keymanager API spec
  5. Call `state.config_manager.set_fee_recipient()`
  6. Return `StatusCode::ACCEPTED` (202)
- DELETE handler returns `StatusCode::NO_CONTENT` (204)
- GET handler returns `Json(FeeRecipientResponse { data: ... })`
- Note: `AppState` doesn't have `config_manager` field yet — that's added in 2.6. Handlers compile against the trait interface. Unit tests use mock `ValidatorConfigManager`.
- Conflict note: handlers.rs is touched sequentially by 2.3 → 2.4 → 2.5 → 2.6. Add fee recipient handlers in a clearly labeled section: `// --- Fee Recipient ---`
- Files NOT to modify: `server.rs` (routes registered in 2.6), `main.rs` (wired in 2.7)

**Acceptance Criteria:**

- [ ] GET returns 200 with `{ "data": { "pubkey": "0x...", "ethaddress": "0x..." } }`
- [ ] POST returns 202 with no body
- [ ] DELETE returns 204 with no body
- [ ] POST with zero address (`0x0000000000000000000000000000000000000000`) returns 400
- [ ] POST with invalid hex address returns 400
- [ ] Unknown pubkey returns 404 for all three methods
- [ ] Invalid pubkey format returns 400

**Testing Requirements:**

- [ ] Unit test with mock `ValidatorConfigManager`: GET valid pubkey returns correct response
- [ ] Unit test: GET unknown pubkey returns 404
- [ ] Unit test: POST valid address returns 202
- [ ] Unit test: POST zero address returns 400
- [ ] Unit test: POST invalid address returns 400
- [ ] Unit test: DELETE valid pubkey returns 204
- [ ] Unit test: DELETE unknown pubkey returns 404

---

### Issue 2.4: Implement gas limit handlers (GET/POST/DELETE)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.1 (types and helpers)
- **Blocks:** 2.6
- **Scope:** 1 day

**Description:**

Add 3 Axum handler functions for gas limit management to `crates/keymanager-api/src/handlers.rs`. Key spec requirement: `gas_limit` is a **string** (Uint64) in both requests and responses, not a JSON number.

**Implementation Notes:**

- File modified: `crates/keymanager-api/src/handlers.rs`
- POST handler:
  1. Parse pubkey
  2. Parse `SetGasLimitRequest` from JSON body — `gas_limit` is a string
  3. Parse `gas_limit` string to `u64`: `request.gas_limit.parse::<u64>().map_err(|_| ApiError::BadRequest(...))`
  4. Call `state.config_manager.set_gas_limit()`
  5. Return 202
- GET handler:
  1. Get gas limit as `u64` from trait
  2. Convert to string for response: `gas_limit.to_string()`
  3. Return `GasLimitResponse` with string-encoded gas_limit
- The `gas_limit` string encoding is critical for spec compliance — reference `research/keymanager-api-spec.md` Uint64 schema: `"^(0|[1-9][0-9]{0,19})$"`
- Section label: `// --- Gas Limit ---`
- Files NOT to modify: `server.rs`, `main.rs`, `keymanager_adapters.rs`

**Acceptance Criteria:**

- [ ] GET returns 200 with `{ "data": { "pubkey": "0x...", "gas_limit": "30000000" } }` — note string, not number
- [ ] POST with valid numeric string returns 202
- [ ] POST with non-numeric string (e.g., `"abc"`) returns 400
- [ ] DELETE returns 204
- [ ] Unknown pubkey returns 404 for all three
- [ ] Default gas limit is `"30000000"` (from ValidatorStore default)

**Testing Requirements:**

- [ ] Unit test with mock: GET returns string-encoded gas limit
- [ ] Unit test: POST valid gas limit, GET returns updated value
- [ ] Unit test: POST non-numeric string returns 400
- [ ] Unit test: DELETE resets to default (30000000)
- [ ] Unit test: unknown pubkey → 404

---

### Issue 2.5: Implement graffiti handlers (GET/POST/DELETE)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.1 (types and helpers)
- **Blocks:** 2.6
- **Scope:** 1 day

**Description:**

Add 3 Axum handler functions for graffiti management to `crates/keymanager-api/src/handlers.rs`. Key constraint: graffiti must be <= 32 bytes (consensus layer limit).

**Implementation Notes:**

- File modified: `crates/keymanager-api/src/handlers.rs`
- POST handler:
  1. Parse pubkey
  2. Parse `SetGraffitiRequest` from JSON body
  3. Validate `request.graffiti.len() <= 32` — return 400 if exceeded
  4. Call `state.config_manager.set_graffiti()`
  5. Return 202
- GET handler returns graffiti as a plain string. If no graffiti is set (neither per-validator nor default), return empty string.
- Section label: `// --- Graffiti ---`
- Files NOT to modify: `server.rs`, `main.rs`, `keymanager_adapters.rs`

**Acceptance Criteria:**

- [ ] GET returns 200 with `{ "data": { "pubkey": "0x...", "graffiti": "my-graffiti" } }`
- [ ] POST with valid graffiti (<= 32 bytes) returns 202
- [ ] POST with > 32 bytes returns 400
- [ ] DELETE returns 204
- [ ] GET after DELETE returns empty string (or default graffiti)
- [ ] Unknown pubkey returns 404

**Testing Requirements:**

- [ ] Unit test with mock: GET returns correct graffiti
- [ ] Unit test: POST valid graffiti, GET returns it
- [ ] Unit test: POST 33-byte graffiti returns 400
- [ ] Unit test: POST exactly 32-byte graffiti succeeds
- [ ] Unit test: DELETE resets graffiti
- [ ] Unit test: unknown pubkey → 404

---

### Issue 2.6: Register config routes and extend AppState/constructor

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.3, 2.4, 2.5 (handler functions must exist)
- **Blocks:** 2.7, 3.4
- **Scope:** 1 day

**Description:**

Extend `AppState` with the `config_manager` field, update `KeymanagerServer::new()` to accept it as a parameter, and register 3 new route groups (fee recipient, gas limit, graffiti — 9 handlers total).

**Implementation Notes:**

- Files modified: `crates/keymanager-api/src/handlers.rs` (AppState), `crates/keymanager-api/src/server.rs` (routes + constructor)
- In `handlers.rs` — add to `AppState`:
  ```rust
  pub config_manager: Arc<dyn ValidatorConfigManager>,
  ```
  Add import: `use crate::traits::ValidatorConfigManager;`
- In `server.rs` — add `config_manager: Arc<dyn ValidatorConfigManager>` parameter to `KeymanagerServer::new()`
- In `server.rs` — add to `router()`:
  ```rust
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
  ```
- Update `use crate::traits::{...}` import in `server.rs` to include `ValidatorConfigManager`
- **Note:** This changes the `KeymanagerServer::new()` signature. The only call site is in `bin/rvc/src/main.rs`, which is updated in Issue 2.7. Between 2.6 and 2.7, the binary crate won't compile — this is expected and acceptable since they merge in sequence.
- Conflict note: `server.rs` is also modified by 3.4 (exit route). 2.6 must merge first. 3.4 adds the exit route and `exit_manager` field.
- Files NOT to modify: `main.rs` (that's 2.7), `keymanager_adapters.rs`

**Acceptance Criteria:**

- [ ] `AppState` has `config_manager: Arc<dyn ValidatorConfigManager>` field
- [ ] `KeymanagerServer::new()` accepts `config_manager` parameter
- [ ] Routes registered for `/eth/v1/validator/:pubkey/feerecipient`, `.../gas_limit`, `.../graffiti`
- [ ] Each route has GET, POST, DELETE methods
- [ ] `cargo check -p keymanager-api` passes
- [ ] Existing routes (`/eth/v1/keystores`, `/eth/v1/remotekeys`) unchanged

**Testing Requirements:**

- [ ] Existing server tests still pass
- [ ] Route registration tested via integration tests in Phase 4 (Issue 4.1, 4.2)

---

### Issue 2.7: Wire config adapter into main.rs

- **Points:** 1
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.2 (adapter implementation), 2.6 (constructor change)
- **Blocks:** 4.1, 4.2
- **Scope:** half day

**Description:**

Update `bin/rvc/src/main.rs` to construct `ValidatorConfigManagerAdapter` from the existing `ValidatorStore` and pass it to `KeymanagerServer::new()`.

**Implementation Notes:**

- File modified: `bin/rvc/src/main.rs`
- Construct adapter:
  ```rust
  let config_manager = Arc::new(ValidatorConfigManagerAdapter::new(
      validator_store.clone(),
  ));
  ```
- Pass to `KeymanagerServer::new()` as the new parameter
- Add import: `use rvc::keymanager_adapters::ValidatorConfigManagerAdapter;`
- This is a simple wiring change — no logic, just DI plumbing
- Conflict note: `main.rs` is also modified by 3.4 (exit adapter wiring). 2.7 must merge first.
- Files NOT to modify: `keymanager_adapters.rs`, `server.rs`, `handlers.rs`

**Acceptance Criteria:**

- [ ] `cargo build -p rvc` compiles
- [ ] `cargo test` passes
- [ ] The 9 new config endpoints are accessible when the server starts (tested in Phase 4)

**Testing Requirements:**

- [ ] Compilation test — the binary builds
- [ ] Functional testing deferred to integration tests (Issues 4.1, 4.2)
