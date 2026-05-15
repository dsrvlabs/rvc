# Phase 3: Voluntary Exit Endpoint

## Phase Overview

- **Goal:** Implement the voluntary exit signing endpoint with beacon node integration. The endpoint signs a `VoluntaryExit` message and returns the `SignedVoluntaryExit` — it does NOT submit to the beacon node (ADR-001).
- **Issue count:** 4 issues, 7 total points
- **Estimated duration:** 3 days (with 2 parallel streams)
- **Entry criteria:** Phase 1 Stream A tasks (1.1, 1.2) complete. Phase 2 task 2.6 complete (AppState extended, routes can be registered).
- **Exit criteria:**
  - `POST /eth/v1/validator/:pubkey/voluntary_exit` returns 200 with valid `SignedVoluntaryExit`
  - `?epoch=300000` accepted as query parameter
  - Omitting epoch defaults to current epoch from beacon node
  - WARN-level log emitted on every exit request
  - Returns 500 when `exit_manager` is `None`
  - Unknown pubkey returns 404
  - Bearer auth required (401 without token)
  - `cargo test` passes

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | Blocks | New Files | Modified Files |
|-------|-------|--------|--------|------------|--------|-----------|----------------|
| 3.1 | Add voluntary exit types | 1 | A | 1.1 | 3.3 | — | `types.rs` |
| 3.2 | Implement VoluntaryExitManagerAdapter | 3 | A | 1.1 | 3.4 | — | `keymanager_adapters.rs` |
| 3.3 | Implement voluntary exit handler | 2 | A | 3.1, 1.2 | 3.4 | — | `handlers.rs` |
| 3.4 | Register exit route and wire into main.rs | 1 | A | 3.2, 3.3, 2.6 | 4.3 | — | `server.rs`, `main.rs` |

## Phase Parallel Plan

| Day | Stream A (Dev A) | Stream B (Dev B) |
|-----|-----------------|-----------------|
| 6 (offset) | (finishing 2.6 Routes) | 3.1 Exit types (1pt) + 3.2 Exit adapter start (3pts) |
| 7 | 2.7 Wire config (1pt) | 3.2 cont. |
| 8 | 3.3 Exit handler (2pts) | 4.4 Persistence integ (2pts) |
| 9 | 3.4 Wire exit (1pt) | 4.5 Smoke tests (1pt) |

> Dev B starts the exit adapter (3.2) while Dev A finishes config endpoint wiring. Dev A then implements the handler (3.3) and does final wiring (3.4).

---

## Issues

### Issue 3.1: Add voluntary exit types

- **Points:** 1
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 1.1 (trait definition — `SignedVoluntaryExit` from `eth_types`)
- **Blocks:** 3.3
- **Scope:** half day

**Description:**

Add request query and response types for the voluntary exit endpoint to `crates/keymanager-api/src/types.rs`.

**Implementation Notes:**

- File modified: `crates/keymanager-api/src/types.rs`
- Types to add (per architecture doc section 3):
  ```rust
  // Query parameter for optional epoch
  #[derive(Deserialize)]
  pub struct VoluntaryExitQuery {
      pub epoch: Option<String>,  // Uint64 = string per spec
  }

  // Response wrapping eth_types::SignedVoluntaryExit
  #[derive(Serialize)]
  pub struct VoluntaryExitResponse {
      pub data: eth_types::SignedVoluntaryExit,
  }
  ```
- **Design decision (ADR-005):** The response wraps `eth_types::SignedVoluntaryExit` directly. This type already serializes with `quoted_u64` for epoch/validator_index and hex-encoded signature, matching the Keymanager API spec format:
  ```json
  { "data": { "message": { "epoch": "300000", "validator_index": "12345" }, "signature": "0x..." } }
  ```
- If `eth_types::SignedVoluntaryExit` serde doesn't match the spec format exactly, fall back to custom types (architecture doc has both options). Verify with a test.
- Add `eth-types` import to `types.rs` if not already present
- Conflict note: `types.rs` was last modified by 2.1 (config types). 3.1 appends exit types in a new section: `// --- Voluntary Exit ---`
- Files NOT to modify: `handlers.rs`, `server.rs`, `keymanager_adapters.rs`

**Acceptance Criteria:**

- [ ] `VoluntaryExitQuery` deserializes from `?epoch=300000` (Some) and empty query string (None)
- [ ] `VoluntaryExitResponse` serializes to the correct JSON structure matching the spec
- [ ] `cargo check -p keymanager-api` passes

**Testing Requirements:**

- [ ] Unit test: serialize `VoluntaryExitResponse` and verify JSON structure matches spec (epoch and validator_index as strings, signature as 0x-hex)
- [ ] Unit test: deserialize `VoluntaryExitQuery` with and without epoch

---

### Issue 3.2: Implement VoluntaryExitManagerAdapter

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 1.1 (trait definition)
- **Blocks:** 3.4
- **Scope:** 1.5 days

**Description:**

Add `VoluntaryExitManagerAdapter` struct to `crates/rvc/src/keymanager_adapters.rs` that implements the `VoluntaryExitManager` trait. This adapter ports the signing logic from `bin/rvc/src/commands/voluntary_exit.rs`, using pre-constructed `BeaconClient`, `SignerService`, `ForkSchedule`, and `genesis_validators_root` from DI rather than building them from scratch.

**Implementation Notes:**

- File modified: `crates/rvc/src/keymanager_adapters.rs`
- Struct fields (per architecture doc section 5):
  ```rust
  pub struct VoluntaryExitManagerAdapter {
      beacon_client: Arc<BeaconClient>,
      signer: Arc<SignerService>,
      fork_schedule: Arc<ForkSchedule>,
      genesis_validators_root: Root,
  }
  ```
- Implementation of `sign_voluntary_exit(&self, pubkey, epoch)`:
  1. **Resolve validator index:** Call `beacon_client.get_validators(&[pubkey_hex])` — same pattern as `bin/rvc/src/commands/voluntary_exit.rs:35-43`
  2. **Determine epoch:** If `epoch` is `Some`, use it. If `None`, calculate current epoch from genesis time and system clock — same as `voluntary_exit.rs:51-69`
  3. **Sign:** Construct `VoluntaryExit { epoch, validator_index }`, sign via `signer.sign_voluntary_exit()` — same as `voluntary_exit.rs:137-142`
  4. **Return:** Construct `SignedVoluntaryExit { message, signature }` — same as `voluntary_exit.rs:144-145`
  5. **Do NOT submit to beacon node** (ADR-001) — unlike the CLI which calls `beacon_client.submit_voluntary_exit()`
- Error mapping:
  - Beacon node unreachable → `ApiError::Internal("beacon node error: ...")`
  - Validator not found on beacon node → `ApiError::NotFound("validator not found on beacon node: ...")`
  - Invalid validator index parse → `ApiError::Internal`
  - Signing failure → `ApiError::Internal`
- Key differences from CLI:
  - No interactive confirmation prompt (the API call IS the confirmation)
  - Uses pre-constructed signer/beacon client (not built from config)
  - Returns `SignedVoluntaryExit` instead of submitting it
- Conflict note: `keymanager_adapters.rs` was last modified by 2.2. 3.2 appends the exit adapter struct below the config adapter.
- Files NOT to modify: `handlers.rs`, `server.rs`, `voluntary_exit.rs` (CLI stays unchanged)

**Acceptance Criteria:**

- [ ] `VoluntaryExitManagerAdapter` compiles and implements `VoluntaryExitManager`
- [ ] `sign_voluntary_exit` resolves validator index from beacon node
- [ ] Explicit epoch is used when provided
- [ ] Current epoch is calculated from genesis time when epoch is `None`
- [ ] Returns correctly signed `SignedVoluntaryExit`
- [ ] Does NOT submit to beacon node
- [ ] Unknown pubkey on beacon node returns `NotFound`
- [ ] Beacon node failure returns `Internal` error

**Testing Requirements:**

- [ ] Unit test with mock beacon client: valid exit with explicit epoch
- [ ] Unit test: valid exit with auto-detected epoch (mock genesis time)
- [ ] Unit test: unknown pubkey → NotFound
- [ ] Unit test: beacon node error → Internal error
- [ ] Unit test: verify returned `SignedVoluntaryExit` has correct epoch and validator_index

---

### Issue 3.3: Implement voluntary exit handler

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 3.1 (types), 1.2 (NotFound variant)
- **Blocks:** 3.4
- **Scope:** 1 day

**Description:**

Add `sign_voluntary_exit` handler function to `crates/keymanager-api/src/handlers.rs`. This handler accepts `epoch` as an optional **query parameter** (not request body — per spec and ADR-002), delegates to `VoluntaryExitManager`, and returns the signed exit message.

**Implementation Notes:**

- File modified: `crates/keymanager-api/src/handlers.rs`
- Handler signature per architecture doc section 3:
  ```rust
  pub async fn sign_voluntary_exit(
      State(state): State<Arc<AppState>>,
      Path(pubkey_hex): Path<String>,
      Query(query): Query<VoluntaryExitQuery>,
  ) -> Result<Json<VoluntaryExitResponse>, ApiError>
  ```
- Implementation steps:
  1. Parse pubkey from path
  2. Parse epoch from query param — `query.epoch.map(|e| e.parse::<u64>()).transpose().map_err(...)` for invalid epoch → 400
  3. Check `state.exit_manager.as_ref()` — if `None`, return `ApiError::Internal("voluntary exit not available: beacon node not configured")`
  4. **WARN log** (NFR-6, irreversible operation):
     ```rust
     tracing::warn!(pubkey = %pubkey_hex, epoch = ?epoch, "Voluntary exit requested — THIS IS IRREVERSIBLE");
     ```
  5. Call `exit_manager.sign_voluntary_exit(&pubkey, epoch).await?`
  6. Return `Json(VoluntaryExitResponse { data: signed_exit })`
- Section label: `// --- Voluntary Exit ---`
- Note: `AppState` doesn't have `exit_manager` field yet — added in 3.4. Unit tests use a mock.
- Files NOT to modify: `server.rs`, `main.rs`, `keymanager_adapters.rs`

**Acceptance Criteria:**

- [ ] POST with explicit `?epoch=300000` signs exit at that epoch and returns 200
- [ ] POST without `?epoch` auto-detects current epoch
- [ ] POST with invalid epoch (e.g., `?epoch=abc`) returns 400
- [ ] Unknown pubkey returns 404
- [ ] `exit_manager` is `None` → returns 500 with descriptive message
- [ ] WARN-level log emitted on every exit request with pubkey and epoch
- [ ] Response body: `{ "data": { "message": { "epoch": "...", "validator_index": "..." }, "signature": "0x..." } }`

**Testing Requirements:**

- [ ] Unit test with mock `VoluntaryExitManager`: valid exit with explicit epoch
- [ ] Unit test: valid exit without epoch (auto-detect)
- [ ] Unit test: invalid epoch query param → 400
- [ ] Unit test: unknown pubkey → 404
- [ ] Unit test: `exit_manager` is `None` → 500
- [ ] Unit test: verify WARN log is emitted (use `tracing_test` or assert log output)

---

### Issue 3.4: Register voluntary exit route and wire into main.rs

- **Points:** 1
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 3.2 (adapter), 3.3 (handler), 2.6 (AppState extension)
- **Blocks:** 4.3
- **Scope:** half day

**Description:**

Add `exit_manager: Option<Arc<dyn VoluntaryExitManager>>` to `AppState`, register the voluntary exit route in `server.rs`, and construct `VoluntaryExitManagerAdapter` in `main.rs`.

**Implementation Notes:**

- Files modified: `crates/keymanager-api/src/server.rs`, `crates/keymanager-api/src/handlers.rs` (AppState), `bin/rvc/src/main.rs`
- In `handlers.rs` — add to `AppState`:
  ```rust
  pub exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
  ```
- In `server.rs` — add `exit_manager: Option<Arc<dyn VoluntaryExitManager>>` parameter to `KeymanagerServer::new()`, add route:
  ```rust
  .route(
      "/eth/v1/validator/:pubkey/voluntary_exit",
      post(handlers::sign_voluntary_exit),
  )
  ```
- In `main.rs` — construct exit adapter:
  ```rust
  let exit_manager: Option<Arc<dyn VoluntaryExitManager>> = Some(Arc::new(
      VoluntaryExitManagerAdapter::new(
          beacon_client.clone(),
          signer.clone(),
          fork_schedule.clone(),
          genesis_validators_root,
      )
  ));
  ```
  Pass to `KeymanagerServer::new()`.
- The exit_manager is `Option` (ADR-003) — if beacon client is unavailable at startup, pass `None`. The handler returns 500 with a descriptive error.
- Conflict note: both `server.rs` and `main.rs` were last modified by 2.6/2.7. This issue appends the exit-specific additions.
- Files NOT to modify: `keymanager_adapters.rs` (adapter already exists from 3.2)

**Acceptance Criteria:**

- [ ] `AppState` has `exit_manager: Option<Arc<dyn VoluntaryExitManager>>` field
- [ ] Route `POST /eth/v1/validator/:pubkey/voluntary_exit` registered
- [ ] `KeymanagerServer::new()` accepts `exit_manager` parameter
- [ ] `VoluntaryExitManagerAdapter` constructed in `main.rs` with correct dependencies
- [ ] `cargo build -p rvc` compiles
- [ ] `cargo test` passes
- [ ] All 10 new endpoints are accessible when server starts

**Testing Requirements:**

- [ ] Compilation test — binary builds
- [ ] Functional testing deferred to integration tests (Issue 4.3)
