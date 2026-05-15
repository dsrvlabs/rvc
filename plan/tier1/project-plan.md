# Project Plan: Tier 1 — Standards Compliance

## Summary

This plan delivers full Keymanager API spec compliance (10 new endpoints) and Holesky/Sepolia testnet support for rvc. Work is organized into 4 phases over 2 parallel streams: **Stream A** (API infrastructure + endpoints) and **Stream B** (testnet support + keygen). Stream B is fully independent of Stream A and can be developed concurrently. The critical path runs through Stream A: foundation traits → config endpoints → voluntary exit → integration testing.

## Prerequisites

- [ ] PRD, architecture, and research documents reviewed and approved
- [ ] `develop` branch up to date with `main`
- [ ] `cargo check && cargo test` passes on current `develop`
- [ ] Developer(s) have read the architecture doc (especially ADRs 001–005)

---

## Phase 1: Foundation — Traits, Error Types, and Persistence

**Goal:** Establish the trait interfaces, error handling, and persistence layer that all subsequent work depends on.

**Entry Criteria:** Prerequisites complete.

**Parallel Streams:** All tasks in this phase can be worked by two developers simultaneously — Stream A (1.1–1.4) and Stream B (1.5–1.7) are independent.

### Stream A — API Foundation

- [ ] **1.1 — Define `ValidatorConfigManager` trait**
  - Add 9-method trait (`get/set/delete` for fee_recipient, gas_limit, graffiti) to `crates/keymanager-api/src/traits.rs`
  - Add `async-trait` and `eth-types` to `crates/keymanager-api/Cargo.toml`
  - Dependencies: none
  - Files: `crates/keymanager-api/src/traits.rs`, `crates/keymanager-api/Cargo.toml`
  - Size: **S**

- [ ] **1.2 — Define `VoluntaryExitManager` trait**
  - Add async trait with `sign_voluntary_exit(pubkey, epoch) -> SignedVoluntaryExit` to `crates/keymanager-api/src/traits.rs`
  - Dependencies: 1.1 (same file, can be done together)
  - Files: `crates/keymanager-api/src/traits.rs`
  - Size: **S**

- [ ] **1.3 — Add `ApiError::NotFound` variant**
  - Extend `ApiError` enum with `NotFound(String)` mapping to HTTP 404
  - Update `IntoResponse` impl
  - Dependencies: none
  - Files: `crates/keymanager-api/src/error.rs`
  - Size: **S**

- [ ] **1.4 — Implement `save_config()` and `has_validator()` on `ValidatorStore`**
  - Add `has_validator(&self, pubkey) -> bool` method
  - Add `save_config(&self) -> Result<()>` with atomic write (tempfile + sync_all + persist)
  - Add `serialize_to_toml()` helper
  - Move `tempfile` from dev-dependencies to dependencies in `crates/validator-store/Cargo.toml`
  - Write unit tests: round-trip (load → save → load), atomic write on concurrent calls, save with no config path returns error
  - Dependencies: none
  - Files: `crates/validator-store/src/store.rs`, `crates/validator-store/Cargo.toml`
  - Size: **M**

### Stream B — Testnet Foundation

- [ ] **1.5 — Add `Holesky` variant to `Network` enum**
  - Add `Holesky` to enum, `FromStr`, `Display`, serde, `genesis_time()`, `genesis_validators_root()`
  - Constants: `genesis_time = 1695902400`, `genesis_validators_root = 0x9143aa...a8b1`
  - Update deprecation test to only assert Goerli; add `test_network_from_str_testnets_accepted`, `test_network_genesis_constants_holesky`, `test_network_serde_testnets`
  - Dependencies: none
  - Files: `crates/rvc/src/config/network.rs`
  - Size: **S**

- [ ] **1.6 — Add `Sepolia` variant to `Network` enum**
  - Same pattern as Holesky. Constants: `genesis_time = 1655733600`, `genesis_validators_root = 0xd8ea...8078`
  - Add `test_network_genesis_constants_sepolia` test
  - Dependencies: none (can be combined with 1.5)
  - Files: `crates/rvc/src/config/network.rs`
  - Size: **S**

- [ ] **1.7 — Add Holesky and Sepolia to `rvc-keygen`**
  - Add `HOLESKY` and `SEPOLIA` `KeygenNetwork` constants with genesis fork versions and Capella fork versions
  - Update `from_name()` to accept `"holesky"` and `"sepolia"`
  - Add unit tests for the new constants
  - Holesky: genesis_fork `[0x01, 0x01, 0x70, 0x00]`, capella_fork `[0x04, 0x01, 0x70, 0x00]`
  - Sepolia: genesis_fork `[0x90, 0x00, 0x00, 0x69]`, capella_fork `[0x90, 0x00, 0x00, 0x72]`
  - Dependencies: none
  - Files: `bin/rvc-keygen/src/network.rs`
  - Size: **S**

### Phase 1 Exit Criteria

- `ValidatorConfigManager` and `VoluntaryExitManager` traits compile with `Send + Sync` bounds
- `ApiError::NotFound` returns HTTP 404 with `{ "message": "..." }` body
- `save_config()` round-trip test passes (load → mutate → save → reload → verify)
- `"holesky".parse::<Network>()` and `"sepolia".parse::<Network>()` succeed with correct constants
- `from_name("holesky")` and `from_name("sepolia")` return correct `KeygenNetwork` structs
- All existing tests pass (`cargo test`)

---

## Phase 2: Config Endpoints — Fee Recipient, Gas Limit, Graffiti

**Goal:** Implement all 9 config management endpoints with persistence, following the spec exactly.

**Entry Criteria:** Phase 1 Stream A tasks (1.1–1.4) complete.

### Tasks

- [ ] **2.1 — Add request/response types**
  - Add all serde structs to `crates/keymanager-api/src/types.rs`: `FeeRecipientData`, `FeeRecipientResponse`, `SetFeeRecipientRequest`, `GasLimitData`, `GasLimitResponse`, `SetGasLimitRequest`, `GraffitiData`, `GraffitiResponse`, `SetGraffitiRequest`
  - Add `parse_eth_address()` and `format_pubkey()` helpers to `crates/keymanager-api/src/handlers.rs`
  - Dependencies: 1.3 (NotFound variant)
  - Files: `crates/keymanager-api/src/types.rs`, `crates/keymanager-api/src/handlers.rs`
  - Size: **S**

- [ ] **2.2 — Implement `ValidatorConfigManagerAdapter`**
  - Add adapter struct to `crates/rvc/src/keymanager_adapters.rs`
  - Implement all 9 trait methods delegating to `ValidatorStore`
  - `ensure_validator_exists()` + `update_and_save()` helper pattern
  - Uses `ValidatorConfigUpdate` `Option<Option<T>>` semantics
  - Unit tests with a real `ValidatorStore` (not mocks — test the integration)
  - Dependencies: 1.1, 1.4
  - Files: `crates/rvc/src/keymanager_adapters.rs`
  - Size: **M**

- [ ] **2.3 — Implement fee recipient handlers (GET/POST/DELETE)**
  - Add 3 handler functions to `crates/keymanager-api/src/handlers.rs`
  - POST rejects zero address (`0x00...00`) with 400
  - POST returns 202, DELETE returns 204, GET returns 200
  - Unit tests with mock `ValidatorConfigManager`: valid pubkey, unknown pubkey (404), invalid address (400), zero address (400)
  - Dependencies: 2.1, 1.3
  - Files: `crates/keymanager-api/src/handlers.rs`
  - Size: **M**

- [ ] **2.4 — Implement gas limit handlers (GET/POST/DELETE)**
  - Add 3 handler functions
  - `gas_limit` is string-encoded in request and response (Uint64 per spec)
  - POST validates numeric string, returns 400 on non-numeric
  - Unit tests with mock: valid, unknown pubkey, non-numeric gas_limit
  - Dependencies: 2.1, 1.3
  - Files: `crates/keymanager-api/src/handlers.rs`
  - Size: **M**

- [ ] **2.5 — Implement graffiti handlers (GET/POST/DELETE)**
  - Add 3 handler functions
  - POST validates <= 32 bytes, returns 400 if exceeded
  - Unit tests with mock: valid, unknown pubkey, oversized graffiti
  - Dependencies: 2.1, 1.3
  - Files: `crates/keymanager-api/src/handlers.rs`
  - Size: **M**

- [ ] **2.6 — Register config routes and extend `AppState`/constructor**
  - Add `config_manager: Arc<dyn ValidatorConfigManager>` to `AppState`
  - Extend `KeymanagerServer::new()` to accept `config_manager` parameter
  - Register 3 new routes (`/eth/v1/validator/:pubkey/feerecipient`, `.../gas_limit`, `.../graffiti`)
  - Dependencies: 2.3, 2.4, 2.5
  - Files: `crates/keymanager-api/src/handlers.rs` (AppState), `crates/keymanager-api/src/server.rs`
  - Size: **S**

- [ ] **2.7 — Wire config adapter into `main.rs`**
  - Construct `ValidatorConfigManagerAdapter` and pass to `KeymanagerServer::new()`
  - Dependencies: 2.2, 2.6
  - Files: `bin/rvc/src/main.rs`
  - Size: **S**

### Phase 2 Exit Criteria

- All 9 config handlers respond with correct status codes (200/202/204/400/404)
- `gas_limit` is string-encoded in JSON responses
- Fee recipient POST rejects `0x00...00` with 400
- Graffiti POST rejects > 32 bytes with 400
- Config changes persist to TOML and survive simulated restart (load → POST → save → reload → GET)
- All handlers require Bearer auth (401 without token)
- `cargo test` passes

---

## Phase 3: Voluntary Exit Endpoint

**Goal:** Implement the voluntary exit signing endpoint with beacon node integration.

**Entry Criteria:** Phase 1 Stream A tasks (1.1–1.3) complete. Phase 2 task 2.6 complete (AppState extended).

### Tasks

- [ ] **3.1 — Add voluntary exit types**
  - Add `VoluntaryExitQuery` (with `epoch: Option<String>`) and `VoluntaryExitResponse` (wrapping `eth_types::SignedVoluntaryExit`) to `crates/keymanager-api/src/types.rs`
  - Dependencies: 1.2
  - Files: `crates/keymanager-api/src/types.rs`
  - Size: **S**

- [ ] **3.2 — Implement `VoluntaryExitManagerAdapter`**
  - Add adapter struct to `crates/rvc/src/keymanager_adapters.rs`
  - Port signing logic from `bin/rvc/src/commands/voluntary_exit.rs` — reuse pre-constructed `BeaconClient`, `SignerService`, `ForkSchedule`, `genesis_validators_root`
  - Steps: resolve validator index from beacon node → determine epoch (explicit or current) → sign VoluntaryExit → return SignedVoluntaryExit
  - Does NOT submit to beacon node (ADR-001)
  - Unit test with mock beacon client and signer
  - Dependencies: 1.2
  - Files: `crates/rvc/src/keymanager_adapters.rs`
  - Size: **L**

- [ ] **3.3 — Implement voluntary exit handler**
  - Add `sign_voluntary_exit` handler to `crates/keymanager-api/src/handlers.rs`
  - `epoch` as optional query parameter (ADR-002)
  - WARN-level log on every exit request
  - Returns 500 if `exit_manager` is `None` (ADR-003)
  - Unit tests with mock: valid exit, missing epoch (auto-detect), invalid epoch (400), unknown pubkey (404), no exit_manager (500)
  - Dependencies: 3.1, 1.3
  - Files: `crates/keymanager-api/src/handlers.rs`
  - Size: **M**

- [ ] **3.4 — Register voluntary exit route and wire into `main.rs`**
  - Add `exit_manager: Option<Arc<dyn VoluntaryExitManager>>` to `AppState`
  - Register route: `POST /eth/v1/validator/:pubkey/voluntary_exit`
  - Construct `VoluntaryExitManagerAdapter` in `main.rs` using existing `beacon_client`, `signer`, `fork_schedule`, `genesis_validators_root`
  - Dependencies: 3.2, 3.3, 2.6
  - Files: `crates/keymanager-api/src/server.rs`, `bin/rvc/src/main.rs`
  - Size: **S**

### Phase 3 Exit Criteria

- `POST /eth/v1/validator/:pubkey/voluntary_exit` returns 200 with valid `SignedVoluntaryExit`
- `?epoch=300000` is accepted as query parameter
- Omitting epoch defaults to current epoch
- WARN log emitted on every exit request
- Returns 500 with descriptive message when `exit_manager` is `None`
- Unknown pubkey returns 404
- Bearer auth required (401 without token)
- `cargo test` passes

---

## Phase 4: Integration Testing and Polish

**Goal:** Full HTTP round-trip integration tests for all 10 endpoints. Verify spec conformance. Documentation updates.

**Entry Criteria:** Phases 1, 2, and 3 complete.

### Tasks

- [ ] **4.1 — Integration tests for config endpoints (fee recipient)**
  - Full HTTP round-trip: start test server with mock traits → POST fee recipient → GET → verify → DELETE → GET → verify default
  - Test auth (401 without token)
  - Test 404 for unknown pubkey
  - Test 400 for invalid address, zero address
  - Dependencies: 2.7
  - Files: `crates/keymanager-api/src/handlers.rs` (or `tests/` directory)
  - Size: **M**

- [ ] **4.2 — Integration tests for config endpoints (gas limit + graffiti)**
  - Same round-trip pattern for gas limit and graffiti
  - Verify `gas_limit` is string-encoded in response
  - Verify graffiti > 32 bytes rejected
  - Dependencies: 2.7
  - Files: `crates/keymanager-api/src/handlers.rs` (or `tests/` directory)
  - Size: **M**

- [ ] **4.3 — Integration tests for voluntary exit endpoint**
  - Full HTTP round-trip with mock `VoluntaryExitManager`
  - Test with explicit epoch, without epoch
  - Test 404, 500 (no exit manager), 400 (bad epoch)
  - Verify response schema matches spec: `{ "data": { "message": { "epoch": "...", "validator_index": "..." }, "signature": "0x..." } }`
  - Dependencies: 3.4
  - Files: `crates/keymanager-api/src/handlers.rs` (or `tests/` directory)
  - Size: **M**

- [ ] **4.4 — Config persistence integration test**
  - End-to-end: create `ValidatorStore` from TOML → POST via adapter → `save_config()` → construct new `ValidatorStore` from same TOML path → GET → verify values match
  - Test concurrent POST requests don't corrupt
  - Dependencies: 2.2
  - Files: `crates/validator-store/src/store.rs` or `crates/rvc/` tests
  - Size: **M**

- [ ] **4.5 — Testnet smoke tests**
  - Verify `rvc --network holesky` and `rvc --network sepolia` parse correctly (unit test level; live beacon node test is manual)
  - Verify `rvc-keygen --network holesky` and `rvc-keygen --network sepolia` produce valid output
  - Dependencies: 1.5, 1.6, 1.7
  - Files: `crates/rvc/src/config/network.rs`, `bin/rvc-keygen/src/network.rs`
  - Size: **S**

- [ ] **4.6 — Regression test suite**
  - Run full existing test suite, verify no regressions
  - Verify existing 6 Keymanager API endpoints still work (keystores + remotekeys)
  - `cargo clippy` clean, `cargo fmt` clean
  - Dependencies: all prior tasks
  - Files: none (test run only)
  - Size: **S**

- [ ] **4.7 — Documentation updates (P2)**
  - Update `config.example.toml` to list all 5 networks
  - Update CLI `--help` text for `--network` flag
  - Dependencies: 1.5, 1.6
  - Files: `config.example.toml`, CLI help strings
  - Size: **S**

### Phase 4 Exit Criteria

- All 16 Keymanager API endpoints respond correctly (6 existing + 10 new)
- Full HTTP round-trip integration tests pass for all 10 new endpoints
- Config persistence survives simulated restart
- `cargo test` passes with no regressions
- `cargo clippy` and `cargo fmt` clean
- Holesky and Sepolia parse and serialize correctly

---

## Dependency Graph

```text
Phase 1 (Foundation)                Phase 2 (Config)              Phase 3 (Exit)         Phase 4 (Integration)
─────────────────────               ────────────────              ──────────────         ─────────────────────

Stream A:
┌─────┐  ┌─────┐  ┌─────┐
│ 1.1 │  │ 1.3 │  │ 1.4 │
│Trait │  │Error│  │Save │
│Config│  │ 404 │  │Cfg  │
└──┬──┘  └──┬──┘  └──┬──┘
   │        │        │
┌──┴──┐     │        │         ┌─────┐                           ┌─────┐
│ 1.2 │     │        │    ┌───▶│ 2.2 │──────────────┐           │ 4.4 │
│Trait │     │        │    │   │Adapt│              │           │Persi│
│Exit  │     │        │    │   └─────┘              │           │stenc│
└──┬──┘     │        │    │                        ▼           └─────┘
   │        │        │    │   ┌─────┐          ┌─────┐
   │        ▼        ▼    │   │ 2.1 │    ┌────▶│ 2.7 │──────────┐
   │     ┌────────────────┘   │Types│    │    │Wire │          │
   │     │                    └──┬──┘    │    └─────┘          ▼
   │     │                       │       │                 ┌─────┐  ┌─────┐
   │     │      ┌────────────────┤       │                 │ 4.1 │  │ 4.2 │
   │     │      │       │        │       │                 │FeeRe│  │Gas/ │
   │     │      ▼       ▼        ▼       │                 │cipIT│  │Graf │
   │     │  ┌─────┐ ┌─────┐ ┌─────┐     │                 └─────┘  └─────┘
   │     │  │ 2.3 │ │ 2.4 │ │ 2.5 │     │
   │     │  │FeeRe│ │Gas  │ │Graf │     │
   │     │  │cipHd│ │Hdlrs│ │Hdlrs│     │
   │     │  └──┬──┘ └──┬──┘ └──┬──┘     │
   │     │     │       │       │        │
   │     │     └───────┴───────┘        │
   │     │             │                │
   │     │             ▼                │
   │     │         ┌─────┐              │
   │     │         │ 2.6 │◀─────────────┘
   │     │         │Route│
   │     │         │Regis│
   │     │         └──┬──┘
   │     │            │
   ▼     ▼            │
┌─────┐  ┌─────┐     │                                    ┌─────┐
│ 3.1 │  │ 3.2 │     │                                    │ 4.3 │
│Types│  │Adapt│     │                                    │ExitI│
│Exit │  │Exit │     │                                    │ntTst│
└──┬──┘  └──┬──┘     │                                    └─────┘
   │        │        │                                        ▲
   ▼        │        │                                        │
┌─────┐     │        │                                        │
│ 3.3 │     │        │                                        │
│Hdlr │     │        │                                        │
│Exit │     │        │                                        │
└──┬──┘     │        │                                        │
   │        │        │                                        │
   └────┬───┘        │                                        │
        ▼            │                                        │
    ┌─────┐          │                                        │
    │ 3.4 │◀─────────┘                                        │
    │Wire │───────────────────────────────────────────────────┘
    │Exit │
    └─────┘

Stream B (independent):
┌─────┐  ┌─────┐  ┌─────┐                                 ┌─────┐
│ 1.5 │  │ 1.6 │  │ 1.7 │────────────────────────────────▶│ 4.5 │
│Holes│  │Sepol│  │Keyge│                                  │Smoke│
│ky   │  │ia   │  │n    │                                  │Tests│
└─────┘  └─────┘  └─────┘                                 └─────┘

Final gate:
    All ──────────────────────────────────────────────────▶┌─────┐  ┌─────┐
                                                           │ 4.6 │  │ 4.7 │
                                                           │Regre│  │Docs │
                                                           │ssion│  │     │
                                                           └─────┘  └─────┘
```

### Critical Path

```
1.1 → 1.2 → 3.2 → 3.4 → 4.3 → 4.6
         ↘
1.4 → 2.2 → 2.7 → 4.1 → 4.6
         ↘
1.3 → 2.1 → 2.3/2.4/2.5 → 2.6 → 2.7
```

The longest path is through the config endpoints: **1.1 → 2.1 → 2.3 → 2.6 → 2.7 → 4.1 → 4.6**.

### Parallelization Opportunities

| Developer A | Developer B |
|------------|------------|
| 1.1 + 1.2 (traits) | 1.5 + 1.6 + 1.7 (testnet) |
| 1.3 (NotFound error) | 1.4 (save_config) |
| 2.1 (types) | 2.2 (adapter) |
| 2.3 (fee recipient handlers) | 2.4 + 2.5 (gas limit + graffiti handlers) |
| 2.6 + 2.7 (route wiring) | 3.1 + 3.2 (exit types + adapter) |
| 3.3 + 3.4 (exit handler + wiring) | 4.4 (persistence integration test) |
| 4.1 (fee recipient integration) | 4.2 (gas limit + graffiti integration) |
| 4.3 (exit integration) | 4.5 (testnet smoke tests) |
| 4.6 (regression) | 4.7 (docs) |

---

## Milestones

### M1: Foundation Complete
**Criteria:**
- [x] `ValidatorConfigManager` and `VoluntaryExitManager` traits defined and compile
- [x] `ApiError::NotFound` variant added
- [x] `save_config()` implemented with atomic write and passing round-trip test
- [x] Holesky and Sepolia network variants added with verified genesis constants
- [x] Keygen tool supports Holesky and Sepolia
- [x] All existing tests pass

**Corresponds to:** Phase 1 exit criteria

### M2: All Config Endpoints Working
**Criteria:**
- [x] 9 config endpoints respond correctly (GET/POST/DELETE for fee_recipient, gas_limit, graffiti)
- [x] Correct HTTP status codes (200, 202, 204, 400, 404)
- [x] Config changes persist to TOML via atomic write
- [x] `gas_limit` is string-encoded in responses
- [x] Zero fee recipient address rejected with 400
- [x] Bearer auth enforced

**Corresponds to:** Phase 2 exit criteria

### M3: Voluntary Exit Endpoint Working
**Criteria:**
- [x] Voluntary exit endpoint signs and returns `SignedVoluntaryExit`
- [x] `epoch` accepted as optional query parameter
- [x] WARN-level log on every exit request
- [x] Graceful degradation when beacon node unavailable

**Corresponds to:** Phase 3 exit criteria

### M4: Full Integration Tested and Spec-Conformant
**Criteria:**
- [x] All 16 Keymanager API endpoints pass HTTP round-trip integration tests
- [x] Config persistence survives simulated restart
- [x] Response schemas validated against OpenAPI spec
- [x] No regressions in existing endpoints
- [x] `cargo clippy` and `cargo fmt` clean
- [x] Testnet support verified

**Corresponds to:** Phase 4 exit criteria

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| **`save_config()` serialization doesn't round-trip** — TOML output doesn't match expected input format, breaking `load_from_config()` | High | Medium | Write round-trip test in Phase 1 (task 1.4) before any endpoint work. If serialization is harder than expected, address it before Phase 2 starts. |
| **AppState constructor change breaks existing wiring** — Adding `config_manager` and `exit_manager` params to `KeymanagerServer::new()` requires updating all call sites | Medium | Low | Only one call site exists (`main.rs`). Task 2.7 handles this. Keep the change additive — never remove existing parameters. |
| **Voluntary exit adapter integration complexity** — Porting signing logic from CLI to adapter involves multiple beacon node calls and crypto operations | Medium | Medium | Task 3.2 is sized L. Port logic incrementally from existing `voluntary_exit.rs`. Mock beacon client for unit tests. |
| **Phase 2/3 merge conflicts** — Two developers working on `handlers.rs` simultaneously could create merge conflicts | Low | Medium | Stream B (testnet) is in completely different files. Within Stream A, tasks 2.3/2.4/2.5 can be done sequentially or with clear file-section ownership. |
| **Beacon node unavailable for voluntary exit testing** — Integration tests for voluntary exit require beacon node responses | Medium | Low | Use mock `VoluntaryExitManager` for HTTP integration tests (task 4.3). Live beacon node testing is manual and out of scope for CI. |
| **`eth_types::SignedVoluntaryExit` serde doesn't match spec** — The `quoted_u64` / hex signature format might not match the Keymanager API OpenAPI schema exactly | Medium | Low | Verify in task 3.1 by writing a test that serializes `SignedVoluntaryExit` and checks the JSON structure. If mismatch, use custom response types (architecture doc has both options). |
| **Existing tests assert Holesky/Sepolia rejection** — Current tests may explicitly verify these networks are rejected | High | High | Task 1.5/1.6 updates these tests. Identified in PRD (FR-11). Run `cargo test` after network changes to catch any missed assertions. |

## Technical Spikes / Open Questions

| Item | Status | Notes |
|------|--------|-------|
| Voluntary exit: sign-only vs sign+submit | **Resolved** | ADR-001: sign-only, matching Lighthouse and spec |
| Epoch: query param vs request body | **Resolved** | ADR-002: query parameter per spec |
| `exit_manager` optionality | **Resolved** | ADR-003: `Option` in AppState, 500 if None |
| Write lock scope during save | **Resolved** | ADR-004: two-step (update then save), not combined atomic |
| Response type reuse for voluntary exit | **Resolved** | ADR-005: wrap `eth_types::SignedVoluntaryExit` |
| `serialize_to_toml` compatibility with `load_from_config` | **Open** | Must verify in task 1.4. The TOML structure must match what the loader expects. |

## Decision Log

| Decision | Rationale | Date |
|----------|-----------|------|
| Follow spec for epoch as query parameter | PRD had it as body field, but OpenAPI spec and Lighthouse both use query param | Pre-planning |
| Sign-only for voluntary exit (no BN submission) | Spec says `signVoluntaryExit`, Lighthouse doesn't submit, safer for irreversible operation | Pre-planning |
| No new crate dependencies | All needed functionality available via existing workspace deps | Pre-planning |
| Two parallel work streams | Testnet support (Stream B) has zero dependency on API work (Stream A) | Planning |
| `exit_manager` as `Option` | Allows server to start without beacon node; returns descriptive 500 | Pre-planning |
| Phase ordering: foundation → config → exit → integration | Config endpoints are simpler and can be tested without beacon node; builds up infrastructure incrementally | Planning |
