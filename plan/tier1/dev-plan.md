# Tier 1 — Development Plan

> Standards Compliance: Extended Keymanager API + Testnet Support

## Overview

| Metric | Value |
|--------|-------|
| Total issues | 17 |
| Total story points | 36 SP |
| Epics | 4 |
| Phases | 3 |
| Critical path | Phase 1 → Phase 2 → Phase 3 |

**Goal:** Bring rvc to parity with ecosystem standards so it can integrate with standard tooling (staking dashboards, Rocket Pool, etc.) and be tested on public testnets before mainnet deployment.

---

## Epics

| Epic | Issues | SP | Description |
|------|--------|----|-------------|
| **A — Testnet Support** | 3 | 4 | Add Holesky + Sepolia network support |
| **B — Keymanager Foundation** | 4 | 9 | Traits, adapters, config persistence, pubkey parsing |
| **C — Config Endpoints** | 4 | 11 | Fee recipient, gas limit, graffiti GET/POST/DELETE |
| **D — Voluntary Exit Endpoint** | 3 | 7 | Sign + submit exit via API |
| **E — Integration & Validation** | 3 | 5 | E2E tests, spec conformance, docs |

---

## Dependency Graph

```
Phase 1 (parallel)          Phase 2 (parallel)              Phase 3
─────────────────          ──────────────────              ─────────
A.1 ─→ A.2 ─→ A.3
                            C.1 ─→ C.2 ─┐
B.1 ─→ B.2 ─┐              D.1 ─→ D.2 ─┼─→ E.1 ─→ E.2 ─→ E.3
             ├─→ B.3 ─→ B.4             │
             │              D.3 ─→ D.4 ─┘
             │
             └──────────────────────────────→ (blocks Phase 2)
```

- **Epic A** is fully independent — can be done in parallel with everything else
- **Epic B** (foundation) must complete before Epics C and D can start
- **Epic C** config endpoints (fee recipient, gas limit, graffiti) can be done in parallel
- **Epic D** (voluntary exit) can be done in parallel with Epic C
- **Epic E** (integration) depends on C + D completion

---

## Phase 1 — Foundation

> Testnet support + Keymanager API infrastructure. No new HTTP endpoints yet.

### A.1 — Add Holesky & Sepolia to Network enum

| Field | Value |
|-------|-------|
| SP | 1 |
| Depends on | — |
| Files | `crates/rvc/src/config/network.rs` |

**Scope:**
- Add `Holesky` and `Sepolia` variants to `Network` enum
- Implement `FromStr`, `Display`, serde support
- Add `genesis_time()` and `genesis_validators_root()` match arms
- Holesky: genesis_time=`1695902400`, root=`0x9143aa7c...`
- Sepolia: genesis_time=`1655733600`, root=`0xd8ea171f...`

**Acceptance criteria:**
- [ ] `"holesky".parse::<Network>()` returns `Ok(Network::Holesky)`
- [ ] `"sepolia".parse::<Network>()` returns `Ok(Network::Sepolia)`
- [ ] `"goerli".parse::<Network>()` still returns `Err`
- [ ] `Network::Holesky.genesis_time()` returns `Some(1695902400)`
- [ ] `Network::Sepolia.genesis_time()` returns `Some(1655733600)`
- [ ] Serde round-trips correctly for both networks
- [ ] `cargo test` passes (existing rejection tests updated)

---

### A.2 — Add keygen tool testnet constants

| Field | Value |
|-------|-------|
| SP | 1 |
| Depends on | A.1 |
| Files | `bin/rvc-keygen/src/network.rs` |

**Scope:**
- Add `HOLESKY` and `SEPOLIA` static `KeygenNetwork` constants with genesis fork version, genesis validators root, and Capella fork version
- Update `from_name()` to accept `"holesky"` and `"sepolia"`

**Acceptance criteria:**
- [ ] `from_name("holesky")` returns `Ok(&HOLESKY)`
- [ ] `from_name("sepolia")` returns `Ok(&SEPOLIA)`
- [ ] `exit_fork_schedule(&HOLESKY)` returns valid fork schedule with Capella fork version
- [ ] `exit_fork_schedule(&SEPOLIA)` returns valid fork schedule with Capella fork version
- [ ] Keygen commands work with `--network holesky` and `--network sepolia`

---

### A.3 — Update testnet tests and documentation

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | A.2 |
| Files | `crates/rvc/src/config/network.rs`, `config.example.toml`, CLI help text |

**Scope:**
- Update rejection tests: remove Holesky/Sepolia from "deprecated" tests, add acceptance tests
- Add tests for genesis constants correctness (hardcode expected values)
- Update `config.example.toml` to document all supported networks
- Update `--network` CLI help text

**Acceptance criteria:**
- [ ] `test_network_from_str_deprecated_networks_rejected` only asserts Goerli
- [ ] New `test_network_from_str_testnets_accepted` passes for Holesky/Sepolia
- [ ] New `test_network_genesis_constants` verifies all genesis times and roots
- [ ] `config.example.toml` lists `mainnet`, `hoodi`, `holesky`, `sepolia`, `custom`
- [ ] `cargo test` — all network tests pass
- [ ] `cargo clippy` — no warnings

---

### B.1 — Add ValidatorConfigManager and VoluntaryExitManager traits

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | — |
| Files | `crates/keymanager-api/src/traits.rs`, `crates/keymanager-api/src/error.rs` |

**Scope:**
- Define `ValidatorConfigManager` trait with 9 methods (get/set/delete for fee_recipient, gas_limit, graffiti)
- Define `VoluntaryExitManager` trait with `submit_voluntary_exit(pubkey, epoch) -> SignedVoluntaryExit`
- Add `ApiError::NotFound` variant if not present (for unknown pubkey 404 responses)
- Add request/response types: `FeeRecipientResponse`, `GasLimitResponse`, `GraffitiResponse`, `VoluntaryExitRequest`, `VoluntaryExitResponse`

**Acceptance criteria:**
- [ ] Both traits compile with `Send + Sync` bounds
- [ ] Response types implement `Serialize`; request types implement `Deserialize`
- [ ] Response JSON format matches [keymanager-APIs spec](https://github.com/ethereum/keymanager-APIs)
- [ ] `ApiError::NotFound` maps to HTTP 404

---

### B.2 — Add config persistence (save_config) to ValidatorStore

| Field | Value |
|-------|-------|
| SP | 3 |
| Depends on | — |
| Files | `crates/validator-store/src/store.rs` |

**Scope:**
- Add `save_config(&self) -> Result<()>` method that serializes current in-memory state to TOML and writes to the config file path
- Use write lock to prevent concurrent writes (store already uses `RwLock`)
- Write to temp file + atomic rename to prevent corruption
- Ensure `update_config()` calls `save_config()` after in-memory update

**Acceptance criteria:**
- [ ] `save_config()` writes valid TOML that `load_from_config()` can read back
- [ ] Round-trip test: load → update → save → load → verify values match
- [ ] Atomic write: partial write failure does not corrupt existing config
- [ ] Concurrent update test: two threads calling `update_config` don't clobber each other
- [ ] File permissions preserved after save

---

### B.3 — Implement ValidatorConfigManager adapter

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | B.1, B.2 |
| Files | `crates/rvc/src/keymanager_adapters.rs` |

**Scope:**
- Implement `ValidatorConfigManager` for a new adapter struct wrapping `Arc<ValidatorStore>`
- `get_*` methods delegate to `effective_*()` — return 404 if pubkey unknown
- `set_*` methods delegate to `update_config()` — persist to disk
- `delete_*` methods call `update_config()` with `None` — persist to disk
- Pubkey validation: check pubkey exists in store before any operation

**Acceptance criteria:**
- [ ] All 9 trait methods implemented and compile
- [ ] Unknown pubkey returns `ApiError::NotFound`
- [ ] Set then get returns the set value
- [ ] Delete then get returns the default value
- [ ] Changes persist to TOML after set/delete

---

### B.4 — Implement VoluntaryExitManager adapter

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | B.1 |
| Files | `crates/rvc/src/keymanager_adapters.rs` |

**Scope:**
- Implement `VoluntaryExitManager` for a new adapter struct wrapping beacon client, signer, fork schedule, and genesis validators root
- Port signing logic from `bin/rvc/src/commands/voluntary_exit.rs`
- If epoch is None, fetch current epoch from beacon node
- Resolve validator index from beacon node via pubkey
- Sign and submit voluntary exit, return `SignedVoluntaryExit`
- Log at WARN level (irreversible operation)

**Acceptance criteria:**
- [ ] Compiles with all required dependencies injected
- [ ] Unknown pubkey returns 404
- [ ] Epoch resolution works (explicit and auto-detect)
- [ ] Signed exit signature is valid
- [ ] Exit is submitted to beacon node
- [ ] WARN log emitted on every exit request

---

## Phase 2 — Endpoints

> HTTP handlers and route registration. All 10 new endpoints.

### C.1 — Fee recipient endpoints (GET/POST/DELETE)

| Field | Value |
|-------|-------|
| SP | 3 |
| Depends on | B.3 |
| Files | `crates/keymanager-api/src/handlers.rs`, `crates/keymanager-api/src/server.rs` |

**Scope:**
- Add `get_fee_recipient`, `set_fee_recipient`, `delete_fee_recipient` handlers
- Parse `{pubkey}` path parameter (hex with or without `0x` prefix)
- POST body: `{ "ethaddress": "0x..." }` — validate 20-byte hex address
- GET response: `{ "data": { "pubkey": "0x...", "ethaddress": "0x..." } }`
- DELETE response: 204 No Content
- Register route: `/eth/v1/validator/:pubkey/feerecipient`

**Acceptance criteria:**
- [ ] GET returns current effective fee recipient (per-validator or default)
- [ ] POST with valid address updates fee recipient, returns 202
- [ ] POST with invalid address returns 400
- [ ] DELETE resets to default, returns 204
- [ ] Unknown pubkey returns 404 for all three methods
- [ ] Bearer token required for all three methods

---

### C.2 — Fee recipient endpoint tests

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | C.1 |
| Files | `crates/keymanager-api/src/handlers.rs` (test module) |

**Scope:**
- Unit tests with mock `ValidatorConfigManager`
- Test: GET returns default when no override set
- Test: POST → GET round-trip
- Test: DELETE resets to default
- Test: 404 for unknown pubkey
- Test: 400 for malformed address
- Test: 401 for missing/invalid bearer token

**Acceptance criteria:**
- [ ] All test cases pass
- [ ] Response JSON format matches spec exactly
- [ ] HTTP status codes match spec (200, 202, 204, 400, 401, 404)

---

### C.3 — Gas limit endpoints (GET/POST/DELETE)

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | B.3 |
| Files | `crates/keymanager-api/src/handlers.rs`, `crates/keymanager-api/src/server.rs` |

**Scope:**
- Add `get_gas_limit`, `set_gas_limit`, `delete_gas_limit` handlers
- POST body: `{ "gas_limit": "35000000" }` — string-encoded u64
- GET response: `{ "data": { "pubkey": "0x...", "gas_limit": "30000000" } }`
- Register route: `/eth/v1/validator/:pubkey/gas_limit`

**Acceptance criteria:**
- [ ] GET returns effective gas limit (default 30M)
- [ ] POST updates gas limit, returns 202
- [ ] POST with non-numeric string returns 400
- [ ] DELETE resets to default (30M), returns 204
- [ ] Unknown pubkey returns 404

---

### C.4 — Graffiti endpoints (GET/POST/DELETE)

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | B.3 |
| Files | `crates/keymanager-api/src/handlers.rs`, `crates/keymanager-api/src/server.rs` |

**Scope:**
- Add `get_graffiti`, `set_graffiti`, `delete_graffiti` handlers
- POST body: `{ "graffiti": "my-graffiti" }` — ASCII string, max 32 bytes
- GET response: `{ "data": { "pubkey": "0x...", "graffiti": "my-graffiti" } }`
- Validate graffiti length (reject > 32 bytes with 400)
- Register route: `/eth/v1/validator/:pubkey/graffiti`

**Acceptance criteria:**
- [ ] GET returns effective graffiti (or empty string if none set)
- [ ] POST updates graffiti, returns 202
- [ ] POST with > 32 bytes returns 400
- [ ] DELETE resets graffiti, returns 204
- [ ] Unknown pubkey returns 404

---

### D.1 — Voluntary exit endpoint (POST)

| Field | Value |
|-------|-------|
| SP | 3 |
| Depends on | B.4 |
| Files | `crates/keymanager-api/src/handlers.rs`, `crates/keymanager-api/src/server.rs` |

**Scope:**
- Add `submit_voluntary_exit` handler
- POST body: `{ "epoch": "300000" }` — epoch is optional
- Response: `{ "data": { "message": { "epoch": "...", "validator_index": "..." }, "signature": "0x..." } }`
- Register route: `/eth/v1/validator/:pubkey/voluntary_exit`

**Acceptance criteria:**
- [ ] POST with explicit epoch signs exit at that epoch
- [ ] POST without epoch uses current epoch from beacon node
- [ ] Response contains valid `SignedVoluntaryExit` with correct fields
- [ ] Unknown pubkey returns 404
- [ ] Beacon node unreachable returns 500 with descriptive message
- [ ] WARN-level log emitted for every exit request

---

### D.2 — Wire new dependencies into KeymanagerServer

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | B.3, B.4 |
| Files | `crates/keymanager-api/src/server.rs`, `bin/rvc/src/main.rs` |

**Scope:**
- Extend `KeymanagerServer::new()` to accept `ValidatorConfigManager` and `VoluntaryExitManager`
- Add both to Axum state (via `Extension` or `State`)
- Wire adapters in `main.rs` where `KeymanagerServer` is constructed
- Inject: `Arc<ValidatorStore>` (for config), beacon client + signer + fork schedule (for exit)

**Acceptance criteria:**
- [ ] `KeymanagerServer` compiles with new dependencies
- [ ] `main.rs` constructs and injects both adapters
- [ ] All existing keystores/remotekeys endpoints still work (regression)
- [ ] `cargo build` succeeds for `rvc` binary

---

### D.3 — Voluntary exit and gas limit/graffiti endpoint tests

| Field | Value |
|-------|-------|
| SP | 2 |
| Depends on | C.3, C.4, D.1 |
| Files | `crates/keymanager-api/src/handlers.rs` (test module) |

**Scope:**
- Unit tests for gas limit endpoints (same pattern as C.2)
- Unit tests for graffiti endpoints (same pattern as C.2, plus length validation)
- Unit tests for voluntary exit endpoint (mock VoluntaryExitManager)
- Test: exit with explicit epoch
- Test: exit with auto-detected epoch
- Test: 404 for unknown pubkey
- Test: 500 when beacon node unreachable

**Acceptance criteria:**
- [ ] All test cases pass
- [ ] Gas limit response uses string-encoded numbers per spec
- [ ] Graffiti validates 32-byte max
- [ ] Voluntary exit response matches spec format
- [ ] `cargo test -p keymanager-api` — all pass

---

## Phase 3 — Integration & Validation

> End-to-end testing, spec conformance, and documentation.

### E.1 — End-to-end integration tests

| Field | Value |
|-------|-------|
| SP | 3 |
| Depends on | D.2, D.3 |
| Files | `crates/keymanager-api/tests/` (new integration test files) |

**Scope:**
- Full HTTP round-trip tests using `axum::test` or an actual TCP server
- Test flow: import keystore → set fee recipient → get fee recipient → delete → verify default
- Test flow: set gas limit → get → delete → verify 30M default
- Test flow: set graffiti → get → delete → verify empty
- Test all endpoints with valid bearer token
- Test all endpoints with missing/invalid bearer token (401)
- Test CORS headers present in responses

**Acceptance criteria:**
- [ ] All round-trip flows pass
- [ ] Auth rejection works for all 10 new endpoints
- [ ] CORS headers present
- [ ] No regressions on existing 6 endpoints
- [ ] Tests are independent (no shared state between tests)

---

### E.2 — Spec conformance validation

| Field | Value |
|-------|-------|
| SP | 1 |
| Depends on | E.1 |
| Files | — (manual verification) |

**Scope:**
- Verify all request/response bodies against [ethereum/keymanager-APIs](https://github.com/ethereum/keymanager-APIs) OpenAPI spec
- Verify HTTP status codes: 200 (GET), 202 (POST set), 204 (DELETE), 400 (bad input), 401 (auth), 404 (not found), 500 (server error)
- Verify Content-Type headers (`application/json`)
- Verify pubkey format in responses (0x-prefixed, lowercase hex)
- Verify gas_limit is string-encoded in JSON (not number)

**Acceptance criteria:**
- [ ] All response schemas match OpenAPI spec
- [ ] All status codes match spec
- [ ] No deviations documented or justified

---

### E.3 — Documentation updates

| Field | Value |
|-------|-------|
| SP | 1 |
| Depends on | E.2 |
| Files | `config.example.toml`, CLI help, `VALIDATOR_CLIENT_COMPARISON.md` |

**Scope:**
- Update `config.example.toml` with network options and gas limit documentation
- Update `VALIDATOR_CLIENT_COMPARISON.md` to reflect completed Tier 1 items
- Verify `--help` output for new `--network` options

**Acceptance criteria:**
- [ ] Config example documents all 5 networks
- [ ] Comparison matrix updated (Keymanager API rows, Network rows)
- [ ] CLI help text accurate

---

## Issue Summary

| ID | Title | SP | Depends on | Phase |
|----|-------|----|------------|-------|
| A.1 | Add Holesky & Sepolia to Network enum | 1 | — | 1 |
| A.2 | Add keygen tool testnet constants | 1 | A.1 | 1 |
| A.3 | Update testnet tests and documentation | 2 | A.2 | 1 |
| B.1 | Add ValidatorConfigManager and VoluntaryExitManager traits | 2 | — | 1 |
| B.2 | Add config persistence (save_config) to ValidatorStore | 3 | — | 1 |
| B.3 | Implement ValidatorConfigManager adapter | 2 | B.1, B.2 | 1 |
| B.4 | Implement VoluntaryExitManager adapter | 2 | B.1 | 1 |
| C.1 | Fee recipient endpoints (GET/POST/DELETE) | 3 | B.3 | 2 |
| C.2 | Fee recipient endpoint tests | 2 | C.1 | 2 |
| C.3 | Gas limit endpoints (GET/POST/DELETE) | 2 | B.3 | 2 |
| C.4 | Graffiti endpoints (GET/POST/DELETE) | 2 | B.3 | 2 |
| D.1 | Voluntary exit endpoint (POST) | 3 | B.4 | 2 |
| D.2 | Wire new dependencies into KeymanagerServer | 2 | B.3, B.4 | 2 |
| D.3 | Voluntary exit and config endpoint tests | 2 | C.3, C.4, D.1 | 2 |
| E.1 | End-to-end integration tests | 3 | D.2, D.3 | 3 |
| E.2 | Spec conformance validation | 1 | E.1 | 3 |
| E.3 | Documentation updates | 1 | E.2 | 3 |

---

## Branch Strategy

```
main
 └─ develop
     └─ feature/tier1-testnet-support      (A.1 → A.2 → A.3)
     └─ feature/tier1-keymanager-foundation (B.1 → B.2 → B.3 → B.4)
     └─ feature/tier1-config-endpoints      (C.1 → C.2 → C.3 → C.4)
     └─ feature/tier1-voluntary-exit        (D.1 → D.2 → D.3)
     └─ feature/tier1-integration           (E.1 → E.2 → E.3)
```

- Each feature branch merges into `develop` via PR when its issues are complete
- `feature/tier1-testnet-support` can merge independently (no dependencies on other branches)
- `feature/tier1-config-endpoints` and `feature/tier1-voluntary-exit` both depend on `feature/tier1-keymanager-foundation`
- `feature/tier1-integration` merges last after all others are in `develop`

---

## Parallelization Opportunities

**Phase 1** — maximum parallelism:
- Epic A (testnet) and Epic B (foundation) are fully independent
- B.1 and B.2 are independent of each other
- B.4 only depends on B.1 (not B.2), so it can start before B.2 finishes

**Phase 2** — moderate parallelism:
- C.1, C.3, C.4 can all start simultaneously once B.3 lands
- D.1 can start once B.4 lands (independent of C.*)
- D.2 must wait for both B.3 and B.4

**Phase 3** — mostly sequential:
- E.1 needs all endpoints working
- E.2 and E.3 are sequential after E.1

---

## Definition of Done

An issue is complete when:
1. Code compiles (`cargo build`)
2. Lints pass (`cargo clippy` — no warnings)
3. Formatting correct (`cargo fmt -- --check`)
4. All tests pass (`cargo test`)
5. Acceptance criteria are met
6. PR reviewed and merged to `develop`

Tier 1 is complete when:
1. All 17 issues are Done
2. `develop` branch builds and all tests pass
3. Keymanager API serves all 16 endpoints (6 existing + 10 new)
4. `--network holesky` and `--network sepolia` work end-to-end
5. `feature/tier1-integration` PR merged
