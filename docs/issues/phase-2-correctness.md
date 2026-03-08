# Phase 2: Correctness & Reliability (P1)

## Phase Overview
- **Goal:** Fix logic errors, concurrency issues, and timing bugs across correctness, concurrency, and other categories
- **Issue count:** 20 issues + 1 integration verification, 39 total points
- **Estimated duration:** 8 days (with 2 parallel streams)
- **Entry criteria:** Phase 1 complete, all SEC/DB issues merged
- **Exit criteria:** All COR/CON/OTH issues merged, per-validator signing mutex active, dynamic pubkey_map, builder registration non-blocking, health scores accurate

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | New Files | Shared File Edits |
|-------|-------|--------|--------|------------|-----------|-------------------|
| COR-01 | Per-validator signing mutex (TOCTOU prevention) | 3 | A | — | none | `signer/lib.rs` |
| COR-02 | Add --mnemonic-passphrase to bls-to-execution | 1 | A | — | none | `rvc-keygen/bls_to_execution.rs` |
| COR-03 | reload_config removes deleted validators | 2 | A | — | none | `validator-store/store.rs` |
| COR-04 | Atomic reload_config | 2 | A | COR-03 | none | `validator-store/store.rs` |
| COR-05 | list_keystores excludes remote keys | 2 | A | — | none | `keymanager-api/handlers.rs`, `rvc/keymanager_adapters.rs` |
| COR-06 | Slot validation on JSON block path | 1 | A | — | none | `block-service/service.rs` |
| COR-07 | health_scores uses actual BN status | 2 | A | — | none | `bn-manager/manager.rs` |
| COR-08 | Retry 429 responses | 2 | A | — | none | `beacon/client.rs` |
| COR-09 | POST for large validator sets | 2 | A | — | none | `beacon/client.rs` |
| OTH-01 | Sub-second attestation delay metric | 1 | B | — | none | `timing/timer.rs` |
| OTH-02 | Division-by-zero guard in slot clock | 1 | B | — | none | `timing/clock.rs` |
| OTH-04 | Deduplicate format detection logic | 1 | B | — | none | `secret-provider/gcp.rs`, `secret-provider/format.rs` |
| OTH-05 | TOCTOU in dependent root change detection | 2 | B | — | none | `duty-tracker/tracker.rs` |
| CON-04 | Reduce write lock scope in query_first | 2 | B | — | none | `bn-manager/manager.rs` |
| CON-05 | Record health for fallback attempts | 1 | B | — | none | `bn-manager/manager.rs` |
| CON-06 | SSE counter reset with BN health verification | 2 | B | — | none | `bn-manager/sse.rs` |
| CON-01 | Spawn builder registration off main loop | 2 | B | — | none | `rvc/service.rs` |
| CON-02 | Use SlotClock for phase 3 timing | 1 | B | — | none | `rvc/service.rs` |
| CON-03 | Dynamic pubkey_map + graceful Arc unwrap | 3 | B | COR-05 | none | `bin/rvc/main.rs`, `rvc/service.rs`, `rvc/keymanager_adapters.rs` |
| OTH-03 | Handle Arc::try_unwrap failure gracefully | — | B | — | — | (solved by CON-03) |
| II-JOINT | Phase 2 integration verification | 3 | both | all above | none | none |

## Phase Parallel Plan

| Day | Stream A (Correctness) | Stream B (Concurrency & Other) |
|-----|-----|-----|
| 1 | COR-01 (3pt) | OTH-01 (1pt), OTH-02 (1pt), OTH-04 (1pt) |
| 2 | COR-01 cont., COR-02 (1pt) | OTH-05 (2pt), CON-05 (1pt) |
| 3 | COR-03 (2pt), COR-04 (2pt) | CON-04 (2pt), CON-06 (2pt) |
| 4 | COR-06 (1pt), COR-07 (2pt) | CON-01 (2pt), CON-02 (1pt) |
| 5 | COR-08 (2pt), COR-09 (2pt) | CON-03 (3pt) |
| 6 | COR-05 (2pt) | CON-03 cont. |
| 7 | (buffer / pull-ahead) | (buffer / pull-ahead) |
| 8 | II-JOINT | II-JOINT |

---

## Issues

### Issue COR-01: Per-validator signing mutex (TOCTOU prevention)
- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 2 days

**Description:**
The current record-then-sign order is **correct per Ethereum consensus spec** (research finding #4). The fix adds a per-validator mutex to prevent two concurrent sign requests from both passing the slashing check before either records. COR-01 is reframed from the original PRD: do NOT reorder to sign-then-record.

**Implementation Notes:**
- Files likely affected: `crates/signer/src/lib.rs` (lines 116-146)
- Approach:
  1. Add `ValidatorLockMap` struct:
     ```rust
     pub struct ValidatorLockMap {
         locks: std::sync::Mutex<HashMap<[u8; 48], Arc<tokio::sync::Mutex<()>>>>,
     }
     impl ValidatorLockMap {
         pub fn get(&self, pubkey: &[u8; 48]) -> Arc<tokio::sync::Mutex<()>> {
             self.locks.lock().expect("lock map poisoned")
                 .entry(*pubkey).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
         }
     }
     ```
  2. Add `validator_locks: ValidatorLockMap` field to `SignerService`
  3. In `sign_attestation` and `sign_block`, acquire per-validator lock BEFORE `check_and_record`:
     ```rust
     let lock = self.validator_locks.get(&pubkey_bytes);
     let _guard = lock.lock().await;
     // check_and_record → sign (serialized per validator)
     ```
  4. Add doc comment: `// Record-then-sign order is mandated by Ethereum consensus spec (phase0/validator.md)`
  5. Log WARN if signing fails after recording: phantom entry is safe per spec
- Watch out for: Mutex is never held across `.await` of another mutex — single lock per sign operation
- New files to create: none
- Files NOT to modify: anything outside `signer` crate

**Acceptance Criteria:**
- [ ] Per-validator `tokio::sync::Mutex` prevents concurrent check-and-record for same validator
- [ ] Different validators are NOT blocked by each other
- [ ] Record-then-sign order preserved (not changed to sign-then-record)
- [ ] Doc comment references Ethereum consensus spec
- [ ] WARN log on sign failure after recording (phantom entry)
- [ ] Test: concurrent signing for same validator is serialized
- [ ] Test: concurrent signing for different validators executes in parallel
- [ ] Test: signing failure after recording logs WARN and does not corrupt slashing DB

**Testing Notes:**
- Concurrency test: spawn 2 tasks signing attestation for same validator simultaneously → verify they execute sequentially (no double entry)
- Parallel test: spawn 2 tasks for different validators → verify they run concurrently
- Use `tokio::test` with multi-threaded runtime

---

### Issue COR-02: Add --mnemonic-passphrase to bls-to-execution
- **Points:** 1
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
The `bls-to-execution` subcommand does not accept `--mnemonic-passphrase`, making it impossible to derive correct keys for users who set a passphrase during mnemonic generation.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/bls_to_execution.rs` (line ~35)
- Approach:
  1. Add `--mnemonic-passphrase` to the clap CLI args (same pattern as `new-mnemonic` and `existing-mnemonic` subcommands)
  2. Thread passphrase into `mnemonic_to_seed()` call
  3. Default to empty string if not provided (BIP-39 standard behavior)
- New files to create: none

**Acceptance Criteria:**
- [ ] `--mnemonic-passphrase` flag accepted by `bls-to-execution` subcommand
- [ ] Passphrase used in key derivation via `mnemonic_to_seed()`
- [ ] Default (no passphrase) produces same keys as before (backward compatible)
- [ ] Test: derive with passphrase matches expected BLS key (known test vector)

**Testing Notes:**
- Unit test: derive key with known mnemonic + passphrase, compare to expected output
- Unit test: derive key without passphrase, verify matches existing behavior

---

### Issue COR-03: reload_config removes deleted validators
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** COR-04 (same file)
- **Scope:** 1 day

**Description:**
`reload_config` adds new validators and updates existing ones but never removes validators that were deleted from the config file.

**Implementation Notes:**
- Files likely affected: `crates/validator-store/src/store.rs` (lines 206-217)
- Approach:
  1. After parsing new config, collect new validator keys into a `HashSet`
  2. Compute stale keys: `current_keys.difference(&new_keys)`
  3. Remove stale entries from the validators map
  4. Log at INFO for each removed validator
- New files to create: none
- Files NOT to modify: anything outside `validator-store`

**Acceptance Criteria:**
- [ ] Validators removed from config are removed from in-memory store on reload
- [ ] Validators still in config are preserved (not affected by removal logic)
- [ ] New validators in config are added
- [ ] Test: start with 3 validators, reload with 2, verify 3rd removed
- [ ] Test: start with 2 validators, reload with 3, verify 3rd added and original 2 preserved

**Testing Notes:**
- Unit test: create store with validators A, B, C → reload with A, B → verify C removed
- Unit test: reload with A, B, D → verify C removed, D added

---

### Issue COR-04: Atomic reload_config
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** COR-03 (same file, implement together)
- **Blocks:** none
- **Scope:** 1 day

**Description:**
`reload_config` acquires and releases multiple locks non-atomically; a concurrent reader can observe a partially-updated state.

**Implementation Notes:**
- Files likely affected: `crates/validator-store/src/store.rs` (lines 207-214)
- Approach:
  1. Introduce `ValidatorStoreState` struct wrapping all mutable state:
     ```rust
     struct ValidatorStoreState {
         validators: HashMap<[u8; 48], ValidatorConfig>,
         default_fee_recipient: Option<[u8; 20]>,
         default_gas_limit: Option<u64>,
         default_graffiti: Option<[u8; 32]>,
     }
     ```
  2. Replace separate `RwLock`s with single `RwLock<ValidatorStoreState>`
  3. Parse new config fully → build `ValidatorStoreState` → swap under single write lock
  4. All readers see either old state or new state, never partial
- Watch out for: This is a refactor of internal state management. All methods reading individual fields must be updated to go through the single `RwLock`.
- New files to create: none
- Files NOT to modify: anything outside `validator-store`

**Acceptance Criteria:**
- [ ] Reload is atomic from readers' perspective (single `RwLock` swap)
- [ ] No partial state observable during reload
- [ ] All existing `ValidatorStore` methods work correctly with new internal layout
- [ ] Test: concurrent read during reload sees consistent state (all fields from same version)
- [ ] All existing tests pass

**Testing Notes:**
- Concurrency test: spawn reader thread + reload on main thread → verify reader never sees mixed old/new state
- Verify all `ValidatorStore` public methods compile and pass existing tests

---

### Issue COR-05: list_keystores excludes remote keys
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** CON-03 (keymanager trait may change)
- **Scope:** 1 day

**Description:**
`GET /eth/v1/keystores` returns remote keys mixed with local keys. The Keymanager API spec defines this endpoint for local keystores only.

**Implementation Notes:**
- Files likely affected:
  - `crates/keymanager-api/src/handlers.rs` (lines 27-48, `list_keystores`)
  - `crates/keymanager-api/src/traits.rs` (may need `list_local_keys()` method)
  - `crates/rvc/src/keymanager_adapters.rs` (adapter implementation)
- Approach:
  1. Check if `KeystoreManager` trait already distinguishes local vs remote
  2. If not: add `list_local_keys()` to the trait (or add a `source: KeySource` field to the return type)
  3. Update `list_keystores` handler to use the filtered method
  4. Verify `list_remote_keys` handler already correctly returns only remote keys
  5. Update adapter in `keymanager_adapters.rs` to implement the new trait method
- Conflict risk: `keymanager_adapters.rs` is shared with CON-03 — COR-05 adds a new trait method implementation, CON-03 adds pubkey_map wiring. Different methods, low conflict risk.
- New files to create: none

**Acceptance Criteria:**
- [ ] `GET /eth/v1/keystores` returns only local keys
- [ ] `GET /eth/v1/remotekeys` returns only remote keys
- [ ] Test: import both local and remote keys, verify `/keystores` returns only local
- [ ] Test: verify `/remotekeys` returns only remote

**Testing Notes:**
- Integration test: import 2 local keystores + 1 remote key → GET `/keystores` → assert 2 results (local only)
- Integration test: GET `/remotekeys` → assert 1 result (remote only)

---

### Issue COR-06: Slot validation on JSON block path
- **Points:** 1
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
The SSZ block path validates the returned block's slot matches the requested slot, but the JSON path does not.

**Implementation Notes:**
- Files likely affected: `crates/block-service/src/service.rs` (lines 175-205)
- Approach:
  1. Add slot validation to JSON path:
     ```rust
     if block.slot() != requested_slot {
         error!(requested = requested_slot, got = block.slot(), "Block slot mismatch (JSON path)");
         return Err(BlockServiceError::SlotMismatch { requested: requested_slot, got: block.slot() });
     }
     ```
  2. Add `SlotMismatch { requested: u64, got: u64 }` variant to `BlockServiceError`
- New files to create: none

**Acceptance Criteria:**
- [ ] JSON block with mismatched slot is rejected with error log
- [ ] Correct-slot JSON blocks proceed normally
- [ ] `BlockServiceError::SlotMismatch` error variant added
- [ ] Test: mock beacon returns wrong-slot block via JSON, verify rejection

**Testing Notes:**
- Unit test: mock beacon returns block for slot 100 when slot 99 requested → assert `SlotMismatch` error

---

### Issue COR-07: health_scores uses actual reachability/sync status
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
`health_scores()` hardcodes `is_reachable: true, is_synced: true` instead of using actual beacon node status.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/manager.rs` (lines 145-146)
- Approach:
  1. Read actual status from `sync_statuses` (already tracked in `BnManager`):
     ```rust
     let sync_guard = self.sync_statuses.read().await;
     // ... for each BN:
     is_reachable: sync_status.map_or(false, |s| s.is_reachable),
     is_synced: sync_status.map_or(false, |s| !s.is_syncing),
     ```
  2. May need to verify what fields are available on `sync_statuses` entries
- New files to create: none

**Acceptance Criteria:**
- [ ] Health scores reflect actual BN reachability (not hardcoded true)
- [ ] Health scores reflect actual BN sync status (not hardcoded true)
- [ ] Unreachable BN shows `is_reachable: false`
- [ ] Syncing BN shows `is_synced: false`
- [ ] Test: simulate unreachable BN, verify `is_reachable: false`
- [ ] Test: simulate syncing BN, verify `is_synced: false`

**Testing Notes:**
- Unit test: create `BnManager` with mock sync status showing unreachable → assert health score reflects it
- Unit test: create `BnManager` with mock sync status showing syncing → assert `is_synced: false`

---

### Issue COR-08: Retry 429 responses
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
HTTP 429 (rate limited) is classified as a non-retryable client error. It should be retried with backoff, respecting the `Retry-After` header.

**Implementation Notes:**
- Files likely affected: `crates/beacon/src/client.rs` (line ~912)
- Approach:
  1. Move 429 check BEFORE the generic `is_client_error()` branch:
     ```rust
     if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
         let retry_after = response.headers()
             .get("retry-after")
             .and_then(|v| v.to_str().ok())
             .and_then(|v| v.parse::<u64>().ok())
             .map(|s| Duration::from_secs(s.min(120)));
         let backoff = retry_after.unwrap_or_else(|| self.calculate_backoff(attempt));
         warn!(attempt, backoff_ms = backoff.as_millis(), "Rate limited (429), retrying");
         tokio::time::sleep(backoff).await;
         continue;
     }
     // Then: existing is_client_error() branch
     ```
  2. Cap `Retry-After` at 120 seconds to prevent abuse
  3. Apply to both `execute_with_retry` and `execute_with_retry_raw`
- New files to create: none

**Acceptance Criteria:**
- [ ] 429 responses trigger retry with backoff
- [ ] `Retry-After` header respected when present (seconds format)
- [ ] `Retry-After` capped at 120 seconds
- [ ] Without `Retry-After`, uses existing exponential backoff
- [ ] Other 4xx errors still non-retryable
- [ ] Test: mock 429 → 429 → 200, verify retry succeeds on 3rd attempt
- [ ] Test: mock 429 with `Retry-After: 5`, verify 5s backoff used

**Testing Notes:**
- Unit test: mock server returns 429, then 200 → assert success after retry
- Unit test: mock server returns 429 with `Retry-After: 5` → assert backoff duration >= 5s
- Unit test: mock server returns 429 with `Retry-After: 999` → assert capped to 120s

---

### Issue COR-09: POST for large validator sets
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
`get_validators` uses GET with pubkeys as query parameters. Large validator sets (100+) can exceed URL length limits (~8KB).

**Implementation Notes:**
- Files likely affected: `crates/beacon/src/client.rs` (lines 184-191)
- Approach:
  1. Threshold: if pubkeys.len() > 50, use POST with JSON body instead of GET with query params
  2. The Beacon API spec supports POST for `/eth/v1/beacon/states/{state_id}/validators`
  3. Small sets (≤ 50) continue using GET for backward compatibility
  4. POST body: `{ "ids": ["0x...", ...] }`
- New files to create: none

**Acceptance Criteria:**
- [ ] ≤ 50 validators: uses GET with query parameters (backward compatible)
- [ ] > 50 validators: uses POST with JSON body
- [ ] Both paths return the same data format
- [ ] Test: 10 validators → verify GET used
- [ ] Test: 100 validators → verify POST used
- [ ] Test: POST path correctly deserializes response

**Testing Notes:**
- Unit test: mock server expects GET for 10 validators → assert success
- Unit test: mock server expects POST for 100 validators → assert success
- Check `reqwest` request method in test assertions

---

### Issue OTH-01: Sub-second attestation delay metric
- **Points:** 1
- **Type:** bug
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
Attestation delay metric truncates to whole seconds via `.as_secs()`, losing sub-second precision critical for monitoring attestation timeliness.

**Implementation Notes:**
- Files likely affected: `crates/timing/src/timer.rs` (lines 136-143)
- Approach: Replace `.as_secs()` with `.as_secs_f64()` for the metric recording
- New files to create: none

**Acceptance Criteria:**
- [ ] Metric captures sub-second precision (e.g., 0.5 for 500ms)
- [ ] Test: 500ms delay recorded as ~0.5, not 0

**Testing Notes:**
- Unit test: simulate 500ms delay → assert metric value is approximately 0.5

---

### Issue OTH-02: Division-by-zero guard in slot clock
- **Points:** 1
- **Type:** bug
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
Division by `slot_duration` panics if duration is zero (misconfiguration).

**Implementation Notes:**
- Files likely affected: `crates/timing/src/clock.rs` (line ~61)
- Approach:
  1. Validate `slot_duration >= 1` in `SlotClock::new()`
  2. Return `Err(TimingError::InvalidSlotDuration)` instead of allowing the panic
  3. Add `InvalidSlotDuration` variant to `TimingError`
- New files to create: none

**Acceptance Criteria:**
- [ ] `SlotClock::new` with zero duration returns `Err`
- [ ] Non-zero durations work as before
- [ ] Test: `SlotClock::new(genesis, Duration::ZERO)` returns error

**Testing Notes:**
- Unit test: construct with `Duration::ZERO` → assert `Err(TimingError::InvalidSlotDuration)`
- Unit test: construct with `Duration::from_secs(12)` → assert `Ok`

---

### Issue OTH-04: Deduplicate format detection logic
- **Points:** 1
- **Type:** chore
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
Key format detection logic is duplicated between `gcp.rs` and `format.rs` in the `secret-provider` crate.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/gcp.rs` (lines 92-103), `crates/secret-provider/src/format.rs`
- Approach:
  1. Ensure all format detection logic lives in `format.rs`
  2. Replace inline logic in `gcp.rs` with a call to `format::detect_key_format()` or `format::parse_secret_data()`
  3. Remove duplicated logic from `gcp.rs`
- New files to create: none

**Acceptance Criteria:**
- [ ] Single format detection implementation in `format.rs`
- [ ] `gcp.rs` calls `format.rs` function instead of inline logic
- [ ] No logic duplication between files
- [ ] All existing tests pass

**Testing Notes:**
- Existing tests in `format.rs` cover all format detection scenarios
- Run `cargo test -p secret-provider`

---

### Issue OTH-05: TOCTOU in dependent root change detection
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
Time-of-check to time-of-use race between reading the dependent root and acting on it. A concurrent update can be missed.

**Implementation Notes:**
- Files likely affected: `crates/duty-tracker/src/tracker.rs` (lines 169-219)
- Approach: Use compare-and-swap pattern:
  1. Fetch from BN first (no lock held)
  2. Acquire write lock
  3. Compare cached root with fetched root under the lock
  4. If changed: update cache under same lock
  5. Trade-off: always fetches from BN even if unchanged — acceptable since duty checks happen once per epoch (~6.4 min)
- New files to create: none

**Acceptance Criteria:**
- [ ] Root check and update are atomic (under single write lock)
- [ ] No window for concurrent update to be missed
- [ ] Test: concurrent root updates don't cause missed duty refreshes

**Testing Notes:**
- Concurrency test: simulate 2 concurrent root change detections → verify both are handled correctly

---

### Issue CON-04: Reduce write lock scope in query_first
- **Points:** 2
- **Type:** performance
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
A write lock is acquired per-BN attempt in `query_first`, the hottest path. This serializes all concurrent beacon node queries.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/manager.rs` (lines 291, 303)
- Approach:
  1. Collect `(index, result, elapsed)` tuples without holding write lock
  2. After the loop, acquire write lock once to batch-update health scores:
     ```rust
     let mut trackers = self.health_trackers.write().await;
     for (i, elapsed) in successes { trackers[i].record_success(elapsed); }
     for i in failures { trackers[i].record_error(); }
     ```
  3. Only one BN succeeds in `query_first`, so pattern is: 1 success + N-1 errors in single lock
- New files to create: none

**Acceptance Criteria:**
- [ ] Write lock acquired at most once per `query_first` call (not per BN)
- [ ] Concurrent queries are not serialized by write lock
- [ ] Health scores still correctly updated
- [ ] Test: concurrent `query_first` calls don't deadlock

**Testing Notes:**
- Concurrency test: spawn multiple `query_first` calls in parallel → verify no deadlock
- Verify health scores update correctly via existing tests

---

### Issue CON-05: Record health for fallback attempts
- **Points:** 1
- **Type:** bug
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
`fallback_unsynced` does not update health scores for fallback beacon node attempts, skewing the health-based ranking.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/manager.rs` (lines 498-520)
- Approach: Add health recording for fallback attempts using the same pattern as `query_first`:
  - Record success latency on successful fallback
  - Record error on failed fallback
- New files to create: none

**Acceptance Criteria:**
- [ ] Fallback BN health scores update on success (latency recorded)
- [ ] Fallback BN health scores update on failure (error recorded)
- [ ] Test: fallback attempt updates health metrics

**Testing Notes:**
- Unit test: trigger fallback, verify health tracker recorded the attempt

---

### Issue CON-06: SSE counter reset with BN health verification
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
SSE reconnection counter resets without verifying the beacon node has actually recovered, enabling infinite rapid reconnection loops.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/sse.rs` (line ~159)
- Approach:
  1. Add `events_since_reconnect: u64` counter to the SSE subscriber state
  2. Increment on each valid SSE event received
  3. Reset `reconnect_count` only when `events_since_reconnect > 0`
  4. Reset `events_since_reconnect` to 0 on each reconnection
- New files to create: none

**Acceptance Criteria:**
- [ ] Counter resets only after receiving at least one valid event post-reconnect
- [ ] Rapid reconnection without events does NOT reset counter
- [ ] Test: reconnect without receiving events → counter not reset
- [ ] Test: reconnect, receive event, then reconnect → counter reset

**Testing Notes:**
- Unit test: simulate reconnect → no events → verify counter incremented (not reset)
- Unit test: simulate reconnect → 1 event → verify counter reset

---

### Issue CON-01: Spawn builder registration off main loop
- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** CON-03
- **Scope:** 1 day

**Description:**
Builder registration runs synchronously in the main slot loop, blocking for up to 40 seconds at epoch boundaries.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/orchestrator/service.rs` (lines 350-352)
- Approach:
  1. Replace `self.register_builders().await` with:
     ```rust
     let builder = self.builder_service.clone();
     tokio::spawn(async move {
         if let Err(e) = builder.register_builders().await {
             warn!(error = %e, "Builder registration failed");
         }
     });
     ```
  2. Builder registration has its own internal timeout
  3. The spawned task runs independently; main loop continues to next slot
- New files to create: none

**Acceptance Criteria:**
- [ ] Builder registration runs in background tokio task
- [ ] Main loop slot processing is not blocked during registration
- [ ] Registration errors are logged but don't crash the orchestrator
- [ ] Test: verify slot processing proceeds while registration runs

**Testing Notes:**
- Integration test: mock slow builder registration (2s delay) → verify next slot processed without waiting

---

### Issue CON-02: Use SlotClock for phase 3 timing
- **Points:** 1
- **Type:** bug
- **Priority:** P1
- **Stream:** B
- **Blocked by:** none
- **Blocks:** CON-03
- **Scope:** < 1 day

**Description:**
Phase 3 timing uses `SystemTime::now()` directly instead of the `SlotClock` abstraction. Clock skew or mock clocks in tests won't be respected.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/orchestrator/service.rs` (lines 313-319)
- Approach: Replace `SystemTime::now()` with `self.clock.now()` or equivalent slot clock method
- New files to create: none

**Acceptance Criteria:**
- [ ] Phase 3 timing uses `SlotClock` instead of `SystemTime::now()`
- [ ] Mock clocks work correctly for phase 3 in tests
- [ ] All existing tests pass

**Testing Notes:**
- Verify existing orchestrator tests that use mock clocks still pass
- Add test: mock clock with skew → verify phase 3 timing follows clock

---

### Issue CON-03: Dynamic pubkey_map + graceful Arc::try_unwrap (includes OTH-03)
- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Stream:** B
- **Blocked by:** COR-05 (keymanager trait changes)
- **Blocks:** none
- **Scope:** 2 days

**Description:**
`pubkey_map` is built once at startup and never updated. Keys added via keymanager API at runtime are invisible to the orchestrator. Also fixes `Arc::try_unwrap().unwrap()` panics (OTH-03).

**Implementation Notes:**
- Files likely affected:
  - `bin/rvc/src/main.rs` (lines 681, 711, 714)
  - `crates/rvc/src/orchestrator/service.rs` (read pubkey_map each slot)
  - `crates/rvc/src/keymanager_adapters.rs` (write pubkey_map on import/delete)
- Approach:
  1. Replace `HashMap<[u8;48], usize>` with `type PubkeyMap = Arc<tokio::sync::RwLock<HashMap<[u8;48], usize>>>`
  2. Pass same `Arc` to orchestrator and keymanager API adapters
  3. Add `tokio::sync::watch<u64>` generation counter for change notification:
     - Keymanager import/delete: increment generation after map update
     - Orchestrator: check `key_gen_rx.has_changed()` each slot, trigger duty refresh on change
  4. On key import: call `get_validators` for validator index, insert into map, increment generation
  5. On key delete: remove from map, increment generation
  6. **OTH-03:** Remove `Arc::try_unwrap().unwrap()` from `main.rs:681,714`. Either:
     - Use `Arc::try_unwrap().unwrap_or_else(|arc| (*arc).clone())` if the value needs to be consumed
     - Or restructure to avoid the unwrap entirely (preferred)
- Conflict risk: `main.rs` shared with Phase 1 CLI flags (SEC-05/06/07) — append-only CLI section, low conflict
- Conflict risk: `keymanager_adapters.rs` shared with COR-05 — COR-05 adds new trait method, CON-03 adds pubkey_map wiring. Different methods.
- New files to create: none

**Acceptance Criteria:**
- [ ] Dynamically imported keys appear in `pubkey_map`
- [ ] Deleted keys are removed from `pubkey_map`
- [ ] Generation counter triggers duty refresh on key change
- [ ] Orchestrator reads `pubkey_map` without blocking key import
- [ ] `Arc::try_unwrap().unwrap()` panics removed from main.rs
- [ ] Shutdown with outstanding references completes cleanly (OTH-03)
- [ ] Test: import key via keymanager API, verify it appears in pubkey_map
- [ ] Test: delete key, verify removed from pubkey_map
- [ ] Test: generation counter increments on key change

**Testing Notes:**
- Integration test: import key → read pubkey_map → assert new key present
- Integration test: delete key → read pubkey_map → assert key removed
- Unit test: verify generation counter increments on insert/remove
- Shutdown test: create multiple Arc references → shutdown → no panic

---

### Issue II-JOINT: Phase 2 integration verification
- **Points:** 3
- **Type:** chore
- **Priority:** P1
- **Stream:** both
- **Blocked by:** all Phase 2 issues
- **Blocks:** Phase 3
- **Scope:** 1 day

**Description:**
Verify all Phase 2 changes integrate correctly.

**Implementation Notes:**
- No code changes — verification only
- Run: `cargo test` (all tests must pass)
- Run: `cargo clippy` (must be clean)
- Run: `cargo fmt --check` (must be clean)
- Manual verification:
  1. Dynamic key import triggers duty refresh
  2. Builder registration doesn't block slot processing
  3. 429 retry works with mock beacon
  4. Health scores reflect actual BN status
  5. `bls-to-execution --mnemonic-passphrase` works

**Acceptance Criteria:**
- [ ] All tests pass (0 failures)
- [ ] `cargo clippy` clean
- [ ] `cargo fmt --check` clean
- [ ] ~25 new tests added across Phase 2
- [ ] No `SystemTime::now()` in orchestrator (all via SlotClock)
- [ ] No `Arc::try_unwrap().unwrap()` in main.rs
