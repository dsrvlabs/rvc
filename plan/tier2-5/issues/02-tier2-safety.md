# Tier 2: Safety & Reliability

## Tier Overview
- **Goal:** Protect validators from financial loss due to builder failures, slashing, duplicate signing, and operational errors
- **Issue count:** 11 issues, 24 total points
- **Estimated duration:** ~7 days (with 2 parallel streams)
- **Entry criteria:** Tier 1 (Standards Compliance) is merged to develop
- **Exit criteria:** All 4 safety features pass integration tests; circuit breaker trips/resets correctly; keystore lock prevents second instance; attestation disable toggles within 1 slot; slashed validator auto-disables

## Tier Summary

| Issue | Title | Points | Stream | Blocked by | New Files | Shared File Edits |
|-------|-------|--------|--------|------------|-----------|-------------------|
| T2.1 | Circuit breaker types + state | 2 | A | — | `crates/builder/src/circuit_breaker.rs` | `crates/builder/src/lib.rs` (export) |
| T2.2 | Circuit breaker integration into block production | 3 | A | T2.1 | — | `crates/block-service/src/service.rs`, `coordinator.rs` |
| T2.3 | Circuit breaker CLI + config + metrics | 2 | A | T2.1 | — | `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs` |
| T2.4 | Emergency attestation disable: AtomicBool + coordinator | 2 | B | — | — | `coordinator.rs`, `crates/rvc/src/config/types.rs` |
| T2.5 | Emergency attestation disable: API endpoint + metric | 2 | B | T2.4 | — | `crates/keymanager-api/src/server.rs`, `handlers.rs` |
| T2.6 | Slashed validator monitor: background task | 3 | B | — | `crates/rvc/src/slashing_monitor.rs` | `coordinator.rs`, `crates/rvc/src/config/types.rs` |
| T2.7 | Slashed validator monitor: metrics + action modes | 1 | B | T2.6 | — | `crates/metrics/src/definitions.rs` |
| T2.8 | Keystore file locking: acquire + release | 2 | A | — | — | `crates/rvc/src/startup.rs` |
| T2.9 | Keystore file locking: CLI flag + error handling | 1 | A | T2.8 | — | `crates/rvc/src/config/types.rs` |
| T2.10 | Keystore locking: fd-lock dependency + tests | 2 | A | T2.8 | — | `crates/rvc/Cargo.toml` |
| T2.11 | Tier 2 integration tests | 4 | both | T2.2, T2.5, T2.7, T2.10 | `tests/tier2_safety.rs` | — |

## Tier Parallel Plan

| Day | Stream A | Stream B |
|-----|----------|----------|
| 1 | T2.1 Circuit breaker types (2pts) | T2.4 Attestation disable AtomicBool (2pts) |
| 2 | T2.8 Keystore locking acquire (2pts) | T2.6 Slashed monitor task (3pts) |
| 3 | T2.2 Circuit breaker block integration (3pts) | T2.6 cont. |
| 4 | T2.2 cont. | T2.5 Attestation disable API (2pts) |
| 5 | T2.3 Circuit breaker CLI/config (2pts) + T2.9 Lock CLI (1pt) | T2.7 Slashed metrics (1pt) + T2.10 Lock tests (2pts) |
| 6-7 | T2.11 Integration tests (4pts) | T2.11 Integration tests (4pts) |

---

## Issues

### Issue T2.1: Builder circuit breaker state type

**Feature:** FR-1 Builder Circuit Breakers
**Story Points:** 2
**Priority:** P0
**Depends On:** None
**Blocks:** T2.2, T2.3
**Files Modified:**
- `crates/builder/src/circuit_breaker.rs` — new file: `CircuitBreakerState` with `AtomicU32` counters
- `crates/builder/src/lib.rs` — export `circuit_breaker` module

**Description:**
Implement the `CircuitBreakerState` struct using lock-free atomics. The state tracks consecutive missed builder slots and total epoch misses. Either condition exceeding its threshold trips the breaker. The struct provides `is_tripped()`, `record_miss()`, `record_success()`, and `reset_epoch()` methods.

**Implementation Notes:**
- Use `AtomicU32` for miss counters, `AtomicU64` for current epoch tracking
- `is_tripped()` must be < 1μs (two atomic loads with `Ordering::Relaxed`)
- `reset_epoch()` zeroes both counters only when the epoch actually changes (compare-and-swap on `current_epoch`)
- Feature disabled when both limits are 0
- See architecture doc `CircuitBreakerState` code sketch for exact implementation

**Acceptance Criteria:**
- [ ] `CircuitBreakerState::new(3, 5)` creates a breaker with consecutive=3, epoch=5 limits
- [ ] `is_tripped()` returns false initially
- [ ] After 3 `record_miss()` calls, `is_tripped()` returns true
- [ ] `record_success()` resets consecutive counter but not epoch counter
- [ ] `reset_epoch(new_epoch)` zeroes both counters
- [ ] `CircuitBreakerState::new(0, 0)` — `is_tripped()` always returns false (disabled)

**Testing Requirements:**
- [ ] Unit tests for all state transitions
- [ ] Test concurrent access with multiple threads (no data races)
- [ ] Test disabled mode (limits=0)

---

### Issue T2.2: Integrate circuit breaker into block production path

**Feature:** FR-1 Builder Circuit Breakers
**Story Points:** 3
**Priority:** P0
**Depends On:** T2.1
**Blocks:** T2.11
**Files Modified:**
- `crates/block-service/src/service.rs` — check `circuit_breaker.is_tripped()` before `produce_block_v3()`, set `builder_boost_factor=0` when tripped
- `crates/rvc/src/orchestrator/coordinator.rs` — call `record_miss()`/`record_success()` after block proposal result; call `reset_epoch()` at epoch boundary
- `bin/rvc/src/main.rs` — construct `CircuitBreakerState` and pass to `BlockService`/coordinator

**Description:**
Wire the circuit breaker into the block production flow. When tripped, force local block by setting `builder_boost_factor=0`. After each proposal attempt, record success/miss. At epoch boundaries, reset the breaker.

**Implementation Notes:**
- `BlockService` needs an `Arc<CircuitBreakerState>` field — inject via constructor
- In `propose_block()` (~line 55): before calling `produce_block_v3()`, check `is_tripped()`. If true, override `builder_boost_factor` to 0 and log at WARN
- In coordinator `maybe_propose_block()` (~line 307): after the result, call `record_miss()` on builder failure or `record_success()` on success
- In coordinator epoch boundary (~line 274): call `reset_epoch(current_epoch)`
- Log WARN when breaker trips, INFO when it resets at epoch boundary

**Acceptance Criteria:**
- [ ] After 3 consecutive builder failures, next proposal uses local block (boost_factor=0)
- [ ] After 5 total epoch misses, remaining proposals use local block
- [ ] Successful builder proposal resets consecutive counter
- [ ] Epoch boundary resets both counters
- [ ] WARN log emitted when circuit breaker trips
- [ ] INFO log emitted when circuit breaker resets

**Testing Requirements:**
- [ ] Unit test: propose_block with tripped breaker uses local block
- [ ] Unit test: miss counting triggers breaker at threshold
- [ ] Unit test: epoch reset clears counters

---

### Issue T2.3: Circuit breaker CLI flags, config, and metrics

**Feature:** FR-1 Builder Circuit Breakers
**Story Points:** 2
**Priority:** P0
**Depends On:** T2.1
**Blocks:** T2.11
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `builder_circuit_breaker_consecutive_limit: u32`, `builder_circuit_breaker_epoch_limit: u32`
- `crates/metrics/src/definitions.rs` — add `rvc_builder_circuit_breaker_trips_total`, `rvc_builder_consecutive_misses`, `rvc_builder_epoch_misses`
- TOML config example update

**Description:**
Add CLI flags and TOML config fields for circuit breaker thresholds. Add Prometheus metrics for observability. Wire config values into `CircuitBreakerState` construction.

**Implementation Notes:**
- Defaults: consecutive=3, epoch=5 (matching Prysm)
- Setting either to 0 disables that check; both 0 disables the feature entirely
- `rvc_builder_circuit_breaker_trips_total` is a counter, incremented each time `is_tripped()` transitions from false to true
- `rvc_builder_consecutive_misses` and `rvc_builder_epoch_misses` are gauges updated after each `record_miss()`/`record_success()`/`reset_epoch()`

**Acceptance Criteria:**
- [ ] `--builder-circuit-breaker-consecutive-limit=3` sets the consecutive limit
- [ ] `--builder-circuit-breaker-epoch-limit=5` sets the epoch limit
- [ ] TOML config `builder_circuit_breaker_consecutive_limit = 3` works
- [ ] Metrics update correctly on trip/reset
- [ ] Setting limit to 0 disables that check

**Testing Requirements:**
- [ ] Config parsing test for both CLI and TOML
- [ ] Metrics increment correctly in unit tests

---

### Issue T2.4: Emergency attestation disable — AtomicBool + coordinator integration

**Feature:** FR-2 Emergency Attestation Disable
**Story Points:** 2
**Priority:** P0
**Depends On:** None
**Blocks:** T2.5, T2.11
**Files Modified:**
- `crates/rvc/src/orchestrator/coordinator.rs` — add `attesting_enabled: Arc<AtomicBool>` to `DutyOrchestrator`, check before attestation/sync-committee/aggregation duties
- `crates/rvc/src/config/types.rs` — add `disable_attesting: bool`
- `bin/rvc/src/main.rs` — construct `AtomicBool` from config, pass to orchestrator

**Description:**
Add a runtime toggle for attestation duties. When disabled, the orchestrator skips attestation production, sync committee messages, and aggregation duties. Block proposals, builder registrations, and metrics continue normally.

**Implementation Notes:**
- Create `Arc<AtomicBool>` initialized from `!config.disable_attesting`
- In coordinator `run()` loop (~line 362): before `attestation_service.process_slot()`, check `attesting_enabled.load(Ordering::Relaxed)`. If false, skip.
- Same check before `sync_committee_service.maybe_produce_sync_messages()` (~line 385)
- Same check before aggregation duties (~line 429)
- Log at DEBUG level every slot when skipping ("Attestation duties skipped (disabled)")
- The `Arc<AtomicBool>` is shared with the API server (T2.5)

**Acceptance Criteria:**
- [ ] `--disable-attesting` starts with attestation duties disabled from slot 1
- [ ] Block proposals continue normally while attestation is disabled
- [ ] Sync committee messages are also skipped when disabled
- [ ] Aggregation duties are skipped when disabled
- [ ] DEBUG log emitted each slot when disabled

**Testing Requirements:**
- [ ] Unit test: orchestrator skips attestation when flag is false
- [ ] Unit test: orchestrator runs attestation when flag is true
- [ ] Unit test: block proposals unaffected by flag state

---

### Issue T2.5: Emergency attestation disable — API endpoint + metric

**Feature:** FR-2 Emergency Attestation Disable
**Story Points:** 2
**Priority:** P0
**Depends On:** T2.4
**Blocks:** T2.11
**Files Modified:**
- `crates/keymanager-api/src/server.rs` — add `POST /rvc/v1/attesting` route, add `attesting_enabled: Arc<AtomicBool>` to `AppState`
- `crates/keymanager-api/src/handlers.rs` — add `set_attesting_enabled()` handler + request/response types
- `crates/metrics/src/definitions.rs` — add `rvc_attesting_enabled` gauge

**Description:**
Add an HTTP API endpoint to toggle attestation duties at runtime. The endpoint requires Bearer token auth (same as Keymanager API). Also add a Prometheus gauge for the current state.

**Implementation Notes:**
- `POST /rvc/v1/attesting` with body `{"enabled": true|false}`, returns `{"enabled": true|false}`
- Use `AtomicBool::swap()` to toggle atomically
- Log at WARN when disabled via API, INFO when re-enabled
- `rvc_attesting_enabled` gauge: 1 = enabled, 0 = disabled — update on every toggle
- Bearer token auth reuses existing Keymanager API auth middleware

**Acceptance Criteria:**
- [ ] `POST /rvc/v1/attesting {"enabled": false}` disables attestation within current slot
- [ ] `POST /rvc/v1/attesting {"enabled": true}` re-enables from next slot
- [ ] Endpoint requires Bearer token (401 without)
- [ ] Metric `rvc_attesting_enabled` reflects current state
- [ ] WARN log when disabled, INFO log when re-enabled

**Testing Requirements:**
- [ ] Integration test: API toggle changes orchestrator behavior
- [ ] Test: endpoint returns 401 without auth token
- [ ] Test: metric updates on toggle

---

### Issue T2.6: Slashed validator monitor background task

**Feature:** FR-3 Slashed Validator Auto-Shutdown
**Story Points:** 3
**Priority:** P0
**Depends On:** None
**Blocks:** T2.7, T2.11
**Files Modified:**
- `crates/rvc/src/slashing_monitor.rs` — new file: `SlashedAction` enum, `check_slashed_validators()` async function, periodic task
- `crates/rvc/src/orchestrator/coordinator.rs` — spawn slashing monitor at epoch boundaries
- `crates/rvc/src/config/types.rs` — add `slashed_validators_action: String`

**Description:**
Implement a background task that runs once per epoch. It queries the beacon node for statuses of all managed validators. If any validator has `status` containing "slashed", it either disables that validator or shuts down the entire client, depending on the configured action.

**Implementation Notes:**
- Use existing `beacon.get_validators()` from `BeaconNodeClient` trait
- Use existing `validator_store.set_enabled(pubkey, false)` to disable validators
- `SlashedAction` enum: `DisableOnly` (default), `Shutdown`, `None`
- In `DisableOnly` mode: disable only the slashed validator, others continue
- In `Shutdown` mode: send `true` via `shutdown_tx` watch channel
- Fail-open: if BN request fails, log WARN and continue (don't disable on network error)
- Persist disabled state via `validator_store.save_config()`
- Log at ERROR when slashing detected

**Acceptance Criteria:**
- [ ] Slashed validator detected within 1 epoch of slashing event
- [ ] `disable-only`: slashed validator disabled, others continue
- [ ] `shutdown`: entire VC shuts down within 12 seconds of detection
- [ ] `none`: no action taken (feature disabled)
- [ ] BN unreachable: WARN log, no validators disabled
- [ ] Disabled state persists across restarts

**Testing Requirements:**
- [ ] Unit test: mock BN returns slashed status → validator disabled
- [ ] Unit test: mock BN returns healthy status → no action
- [ ] Unit test: mock BN returns error → warn, no action
- [ ] Unit test: shutdown mode sends shutdown signal

---

### Issue T2.7: Slashed validator monitor metrics and action mode config

**Feature:** FR-3 Slashed Validator Auto-Shutdown
**Story Points:** 1
**Priority:** P0
**Depends On:** T2.6
**Blocks:** T2.11
**Files Modified:**
- `crates/metrics/src/definitions.rs` — add `rvc_validators_slashed_total` counter
- Config validation: `--slashed-validators-action` must be one of `disable-only|shutdown|none`

**Description:**
Add Prometheus metrics and CLI flag for the slashing monitor. Wire the action mode config value into the monitor task.

**Implementation Notes:**
- `rvc_validators_slashed_total` counter incremented each time a slashed validator is detected
- CLI flag: `--slashed-validators-action=disable-only` (default)
- Invalid values produce a startup error listing valid options

**Acceptance Criteria:**
- [ ] `--slashed-validators-action=disable-only` is the default
- [ ] `--slashed-validators-action=none` disables the feature
- [ ] Invalid action value produces startup error
- [ ] Metric increments on each slashing detection

**Testing Requirements:**
- [ ] Config parsing test for valid/invalid action values
- [ ] Metric increment test

---

### Issue T2.8: Keystore file locking — acquire and release

**Feature:** FR-4 Keystore File Locking
**Story Points:** 2
**Priority:** P0
**Depends On:** None
**Blocks:** T2.9, T2.10, T2.11
**Files Modified:**
- `crates/rvc/src/startup.rs` — add `acquire_keystore_lock()` function, `EXIT_KEYSTORE_LOCKED` exit code (14)

**Description:**
Implement exclusive file locking on the validator data directory using `fd-lock`. The lock file is `<data-dir>/.rvc.lock`. If the lock is already held, the process exits with code 14 and a descriptive error. The lock is held for the process lifetime and automatically released on exit (including crash).

**Implementation Notes:**
- Lock file: `<validator-data-dir>/.rvc.lock`
- Use `fd_lock::RwLock::try_write()` for non-blocking lock attempt
- Set file permissions to `0o600` on Unix
- `Box::leak` the `RwLock` to get a `'static` guard that lives for the process
- Insert in startup sequence: after integrity check, before genesis validation
- On lock failure: ERROR log with locked path, exit with code 14

**Acceptance Criteria:**
- [ ] First instance starts normally and acquires lock
- [ ] Second instance with same data dir fails with code 14 and descriptive error
- [ ] After first instance exits, second can start
- [ ] Lock file permissions are 0o600
- [ ] Process crash releases lock (advisory `flock` semantics)

**Testing Requirements:**
- [ ] Unit test: lock acquired successfully
- [ ] Unit test: second lock attempt fails with correct error
- [ ] Test: lock released after drop

---

### Issue T2.9: Keystore file locking — CLI flag and error handling

**Feature:** FR-4 Keystore File Locking
**Story Points:** 1
**Priority:** P0
**Depends On:** T2.8
**Blocks:** T2.11
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `disable_keystore_locking: bool`
- `crates/rvc/src/startup.rs` — conditional lock based on config

**Description:**
Add the `--disable-keystore-locking` CLI flag for DVT setups where multiple signers legitimately share key material. When the flag is set, skip lock acquisition entirely.

**Implementation Notes:**
- `--disable-keystore-locking` defaults to false (locking enabled by default)
- When true, skip `acquire_keystore_lock()` call and log at WARN ("Keystore locking disabled — ensure no duplicate instances")
- TOML: `disable_keystore_locking = false`

**Acceptance Criteria:**
- [ ] Default: locking is enabled
- [ ] `--disable-keystore-locking`: lock acquisition skipped with WARN log
- [ ] Flag documented in help text

**Testing Requirements:**
- [ ] Config parsing test

---

### Issue T2.10: Keystore locking — fd-lock dependency and integration tests

**Feature:** FR-4 Keystore File Locking
**Story Points:** 2
**Priority:** P0
**Depends On:** T2.8
**Blocks:** T2.11
**Files Modified:**
- `crates/rvc/Cargo.toml` — add `fd-lock = "4"` dependency
- Integration tests for lock behavior

**Description:**
Add the `fd-lock` crate dependency and write integration tests verifying lock behavior across multiple processes.

**Implementation Notes:**
- `fd-lock` provides RAII-based file locking with `flock(2)` on Unix
- Actively maintained (yoshuawuyts), no `libc` dependency (uses `rustix`)
- Test with `tempfile` for isolated test directories
- Test: spawn child process attempting same lock — verify it fails

**Acceptance Criteria:**
- [ ] `fd-lock = "4"` added to `crates/rvc/Cargo.toml`
- [ ] `cargo build` succeeds with new dependency
- [ ] Integration test: two processes contend for same lock
- [ ] Integration test: `kill -9` first process → second can acquire

**Testing Requirements:**
- [ ] Multi-process lock contention test
- [ ] Crash recovery test (kill -9 → lock released)

---

### Issue T2.11: Tier 2 integration tests

**Feature:** All Tier 2 features (FR-1 through FR-4)
**Story Points:** 4
**Priority:** P0
**Depends On:** T2.2, T2.5, T2.7, T2.10
**Blocks:** None
**Files Modified:**
- `tests/tier2_safety.rs` — new integration test file

**Description:**
End-to-end integration tests covering all four Tier 2 safety features working together. These tests verify the features compose correctly in a realistic scenario.

**Implementation Notes:**
- Test circuit breaker: simulate N builder failures → verify local block used
- Test attestation disable: toggle via API → verify attestation skipped next slot
- Test slashing monitor: mock BN returns slashed → verify validator disabled
- Test keystore lock: start two instances → verify second fails
- Test composition: circuit breaker tripped + attestation disabled → block proposals still work

**Acceptance Criteria:**
- [ ] Circuit breaker trips and resets correctly in integration test
- [ ] Attestation disable API toggles take effect within 1 slot
- [ ] Slashed validator auto-disables in integration test
- [ ] Keystore lock prevents second instance
- [ ] All features compose without interference

**Testing Requirements:**
- [ ] Full integration test suite for all Tier 2 features
- [ ] Composition tests verifying features don't conflict
