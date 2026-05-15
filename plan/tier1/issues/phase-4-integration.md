# Phase 4: Integration Testing and Polish

## Phase Overview

- **Goal:** Full HTTP round-trip integration tests for all 10 new endpoints. Verify spec conformance, config persistence across restarts, testnet support, and zero regressions.
- **Issue count:** 7 issues, 11 total points
- **Estimated duration:** 3 days (with 2 parallel streams)
- **Entry criteria:** Phases 1, 2, and 3 complete. All 10 new endpoints functional and unit-tested.
- **Exit criteria:**
  - All 16 Keymanager API endpoints respond correctly (6 existing + 10 new)
  - Full HTTP round-trip integration tests pass for all 10 new endpoints
  - Config persistence survives simulated restart
  - `cargo test` passes with no regressions
  - `cargo clippy` and `cargo fmt` clean
  - Holesky and Sepolia parse and serialize correctly

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | Blocks | New Files | Modified Files |
|-------|-------|--------|--------|------------|--------|-----------|----------------|
| 4.1 | Integration tests: fee recipient endpoints | 2 | A | 2.7 | 4.6 | — | `handlers.rs` (tests) |
| 4.2 | Integration tests: gas limit + graffiti endpoints | 2 | A | 2.7 | 4.6 | — | `handlers.rs` (tests) |
| 4.3 | Integration tests: voluntary exit endpoint | 2 | A | 3.4 | 4.6 | — | `handlers.rs` (tests) |
| 4.4 | Config persistence integration test | 2 | A | 2.2 | 4.6 | — | `store.rs` (tests) or `keymanager_adapters.rs` (tests) |
| 4.5 | Testnet smoke tests | 1 | B | 1.4, 1.5 | 4.6 | — | `network.rs` (tests) |
| 4.6 | Regression test suite | 1 | both | all prior | — | — | — (test run only) |
| 4.7 | Documentation updates | 1 | B | 1.4 | — | — | `config.example.toml`, CLI help |

## Phase Parallel Plan

| Day | Stream A (Dev A) | Stream B (Dev B) |
|-----|-----------------|-----------------|
| 9 (offset) | 3.4 Wire exit (1pt) + 4.1 Fee integ (2pts) | 4.5 Smoke tests (1pt) + 4.2 Gas/Graffiti integ (2pts) |
| 10 | 4.3 Exit integ (2pts) | 4.4 Persistence integ (2pts) |
| 11 | 4.6 Regression (1pt) | 4.7 Docs (1pt) + 4.6 Regression (1pt) |

---

## Issues

### Issue 4.1: Integration tests for fee recipient endpoints

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.7 (config endpoints fully wired)
- **Blocks:** 4.6
- **Scope:** 1 day

**Description:**

Write full HTTP round-trip integration tests for the fee recipient GET/POST/DELETE endpoints. Tests start a real Axum test server with mock trait implementations, make HTTP requests, and verify responses match the Keymanager API spec.

**Implementation Notes:**

- File modified: `crates/keymanager-api/src/handlers.rs` (add tests in `#[cfg(test)]` module) or `crates/keymanager-api/tests/` directory if integration test isolation is preferred
- Test setup pattern:
  1. Create mock implementations of all traits (use existing mock pattern from the crate's tests)
  2. Construct `AppState` with mocks
  3. Build router via `KeymanagerServer::router()` (or directly from `Router` if the server struct is cumbersome for tests)
  4. Use `axum::body::Body` + `tower::ServiceExt::oneshot()` to send requests without binding a port
- Test the full lifecycle: POST → GET → verify → DELETE → GET → verify default
- Verify Bearer auth: request without `Authorization` header → 401
- Verify 404 for unknown pubkey on all three methods
- Verify 400 for invalid address and zero address on POST
- Verify response JSON structure matches spec exactly:
  ```json
  { "data": { "pubkey": "0x...", "ethaddress": "0x..." } }
  ```
- Files NOT to modify: production code files — tests only

**Acceptance Criteria:**

- [ ] POST → GET → DELETE lifecycle test passes
- [ ] POST returns 202, GET returns 200, DELETE returns 204
- [ ] 401 without Bearer token
- [ ] 404 for unknown pubkey
- [ ] 400 for invalid address format
- [ ] 400 for zero address (`0x0000000000000000000000000000000000000000`)
- [ ] Response JSON matches spec structure

**Testing Requirements:**

- [ ] Integration test: `test_fee_recipient_lifecycle` — POST → GET → verify → DELETE → GET → verify default
- [ ] Integration test: `test_fee_recipient_auth_required` — 401 without token
- [ ] Integration test: `test_fee_recipient_unknown_pubkey` — 404
- [ ] Integration test: `test_fee_recipient_invalid_address` — 400
- [ ] Integration test: `test_fee_recipient_zero_address` — 400

---

### Issue 4.2: Integration tests for gas limit + graffiti endpoints

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.7 (config endpoints fully wired)
- **Blocks:** 4.6
- **Scope:** 1 day

**Description:**

Write full HTTP round-trip integration tests for gas limit and graffiti endpoints. Same pattern as 4.1 — test server with mocks, full lifecycle, spec conformance.

**Implementation Notes:**

- File modified: same test location as 4.1
- Gas limit tests:
  - Verify `gas_limit` is **string-encoded** in JSON response (`"30000000"`, not `30000000`)
  - POST with non-numeric string → 400
  - Default gas limit is `"30000000"`
- Graffiti tests:
  - POST with > 32 bytes → 400
  - POST with exactly 32 bytes → 202
  - Empty graffiti after DELETE
- Both: lifecycle, auth, 404, 400 validation
- Files NOT to modify: production code

**Acceptance Criteria:**

- [ ] Gas limit: `gas_limit` field is a JSON string (not number) in GET response
- [ ] Gas limit: POST → GET → DELETE lifecycle passes
- [ ] Gas limit: non-numeric gas_limit → 400
- [ ] Graffiti: POST → GET → DELETE lifecycle passes
- [ ] Graffiti: > 32 bytes → 400
- [ ] Both: 401 without auth, 404 unknown pubkey

**Testing Requirements:**

- [ ] Integration test: `test_gas_limit_lifecycle`
- [ ] Integration test: `test_gas_limit_string_encoding` — verify string, not number
- [ ] Integration test: `test_gas_limit_invalid_value` — non-numeric → 400
- [ ] Integration test: `test_graffiti_lifecycle`
- [ ] Integration test: `test_graffiti_max_length` — 33 bytes → 400, 32 bytes → 202
- [ ] Integration test: `test_graffiti_auth_required`

---

### Issue 4.3: Integration tests for voluntary exit endpoint

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 3.4 (exit endpoint fully wired)
- **Blocks:** 4.6
- **Scope:** 1 day

**Description:**

Write full HTTP round-trip integration tests for the voluntary exit endpoint. Use a mock `VoluntaryExitManager` to control beacon node responses.

**Implementation Notes:**

- File modified: same test location as 4.1
- Tests:
  - POST with explicit `?epoch=300000` → 200 with `SignedVoluntaryExit`
  - POST without epoch → 200 (auto-detect)
  - POST with `?epoch=abc` → 400
  - Unknown pubkey → 404
  - `exit_manager` is `None` → 500 with descriptive error
  - 401 without auth
- Verify response schema matches spec exactly:
  ```json
  {
    "data": {
      "message": { "epoch": "300000", "validator_index": "12345" },
      "signature": "0x..."
    }
  }
  ```
- Verify `epoch` and `validator_index` are string-encoded (Uint64 per spec)
- Verify `signature` is 0x-prefixed hex
- Files NOT to modify: production code

**Acceptance Criteria:**

- [ ] POST with explicit epoch → 200 with correct `SignedVoluntaryExit`
- [ ] POST without epoch → 200 (auto-detect works)
- [ ] Invalid epoch → 400
- [ ] Unknown pubkey → 404
- [ ] No exit_manager → 500 with message "voluntary exit not available"
- [ ] 401 without auth
- [ ] Response JSON matches Keymanager API spec schema

**Testing Requirements:**

- [ ] Integration test: `test_voluntary_exit_with_epoch`
- [ ] Integration test: `test_voluntary_exit_auto_epoch`
- [ ] Integration test: `test_voluntary_exit_invalid_epoch` — 400
- [ ] Integration test: `test_voluntary_exit_unknown_pubkey` — 404
- [ ] Integration test: `test_voluntary_exit_no_manager` — 500
- [ ] Integration test: `test_voluntary_exit_auth_required` — 401
- [ ] Integration test: `test_voluntary_exit_response_schema` — verify JSON structure

---

### Issue 4.4: Config persistence integration test

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** 2.2 (adapter implementation)
- **Blocks:** 4.6
- **Scope:** 1 day

**Description:**

Write an end-to-end persistence test that verifies config changes survive a simulated restart. This tests the full path: adapter → ValidatorStore → save_config() → reload from TOML → verify values match.

**Implementation Notes:**

- File modified: `crates/validator-store/src/store.rs` (tests) or `crates/rvc/src/keymanager_adapters.rs` (tests)
- Test flow:
  1. Create a temp TOML config file with a known validator
  2. `ValidatorStore::load_from_config(&temp_path)`
  3. Construct `ValidatorConfigManagerAdapter`
  4. POST fee_recipient, gas_limit, graffiti via adapter methods
  5. Call `save_config()` (already called by adapter)
  6. Create a NEW `ValidatorStore::load_from_config(&temp_path)` — simulates restart
  7. Verify: `effective_fee_recipient()`, `effective_gas_limit()`, `effective_graffiti()` match posted values
- Additional test: concurrent POST requests don't corrupt the config file
  - Spawn multiple threads, each updating different validators
  - After all complete, reload and verify all values are correct
- Use `tempfile::tempdir()` for test isolation
- Files NOT to modify: production code

**Acceptance Criteria:**

- [ ] Fee recipient persists across simulated restart
- [ ] Gas limit persists across simulated restart
- [ ] Graffiti persists across simulated restart
- [ ] DELETE reverts to default, and default persists
- [ ] Concurrent writes don't corrupt the file
- [ ] Round-trip preserves all config fields (including builder_proposals, builder_boost_factor, enabled)

**Testing Requirements:**

- [ ] Integration test: `test_config_persistence_fee_recipient` — set → save → reload → verify
- [ ] Integration test: `test_config_persistence_gas_limit` — same
- [ ] Integration test: `test_config_persistence_graffiti` — same
- [ ] Integration test: `test_config_persistence_delete_reverts` — delete → save → reload → verify default
- [ ] Integration test: `test_config_persistence_concurrent_writes` — multi-threaded updates, no corruption

---

### Issue 4.5: Testnet smoke tests

- **Points:** 1
- **Type:** chore
- **Priority:** P1
- **Stream:** B
- **Blocked by:** 1.4 (network enum), 1.5 (keygen constants)
- **Blocks:** 4.6
- **Scope:** half day

**Description:**

Verify Holesky and Sepolia support works end-to-end at the unit test level. Live beacon node testing is manual and out of scope for CI.

**Implementation Notes:**

- Files modified: `crates/rvc/src/config/network.rs` (tests), `bin/rvc-keygen/src/network.rs` (tests)
- Tests to add:
  - `rvc --network holesky` parses correctly (test at the config/CLI arg parsing level)
  - `rvc --network sepolia` parses correctly
  - `rvc-keygen --network holesky` produces valid `KeygenNetwork`
  - `rvc-keygen --network sepolia` produces valid `KeygenNetwork`
  - Verify `exit_fork_schedule()` for both networks returns schedule that caps at Capella
- These are mostly redundant with Phase 1 tests but serve as a final verification
- Files NOT to modify: production code

**Acceptance Criteria:**

- [ ] `"holesky"` and `"sepolia"` parse as `Network` enum variants
- [ ] Genesis constants match verified values
- [ ] Keygen tool supports both networks with correct fork versions
- [ ] `exit_fork_schedule` caps at Capella for both networks

**Testing Requirements:**

- [ ] Smoke test: parse "holesky" and "sepolia" as Network
- [ ] Smoke test: keygen from_name for both networks
- [ ] Smoke test: exit_fork_schedule for both networks

---

### Issue 4.6: Regression test suite

- **Points:** 1
- **Type:** chore
- **Priority:** P0
- **Stream:** both
- **Blocked by:** all prior tasks
- **Blocks:** None (final gate)
- **Scope:** half day

**Description:**

Run the full test suite, linting, and formatting checks to ensure zero regressions. Verify existing 6 Keymanager API endpoints still work alongside the 10 new ones.

**Implementation Notes:**

- Files modified: None — this is a test run and verification task
- Commands to run:
  ```bash
  cargo test                    # All tests pass
  cargo clippy                  # No warnings
  cargo fmt -- --check          # Properly formatted
  ```
- Verify existing endpoints:
  - `GET /eth/v1/keystores` still lists keys
  - `POST /eth/v1/keystores` still imports keystores
  - `DELETE /eth/v1/keystores` still deletes keystores
  - `GET /eth/v1/remotekeys` still lists remote keys
  - `POST /eth/v1/remotekeys` still imports remote keys
  - `DELETE /eth/v1/remotekeys` still deletes remote keys
- This should be run by both developers as a final gate before merging to `develop`

**Acceptance Criteria:**

- [ ] `cargo test` — all tests pass (existing + new)
- [ ] `cargo clippy` — no warnings
- [ ] `cargo fmt -- --check` — no formatting issues
- [ ] Existing 6 Keymanager API endpoints function correctly
- [ ] No compilation warnings

**Testing Requirements:**

- [ ] Run full `cargo test` suite
- [ ] Run `cargo clippy` with no warnings
- [ ] Run `cargo fmt -- --check`
- [ ] Manually verify existing endpoint tests still pass

---

### Issue 4.7: Documentation updates (P2)

- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Stream:** B
- **Blocked by:** 1.4 (network enum — must know all 5 networks)
- **Blocks:** None
- **Scope:** half day

**Description:**

Update configuration documentation and CLI help text to reflect all 5 supported networks.

**Implementation Notes:**

- Files modified: `config.example.toml` (if it exists), CLI `--help` text for `--network` flag
- Update network list in config example to: `mainnet`, `hoodi`, `holesky`, `sepolia`, `custom`
- Update CLI help text (likely in `bin/rvc/src/main.rs` or a clap derive struct) to list all 5 networks
- Check if `config.example.toml` exists — if not, this may be a new file or the task may be N/A
- Low priority (P2) — can be deferred if the team is behind schedule

**Acceptance Criteria:**

- [ ] Config example lists all 5 supported networks
- [ ] CLI `--help` for `--network` flag lists all 5 networks
- [ ] `cargo build` passes after any help text changes

**Testing Requirements:**

- [ ] Manual verification: `rvc --help` shows all networks
- [ ] No automated tests needed for documentation
