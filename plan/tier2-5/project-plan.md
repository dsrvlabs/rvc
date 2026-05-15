# Project Plan: Tiers 2–5 — Safety, Operations, Advanced & Experimental

## Summary

This plan delivers 18 features across 6 phases, taking rvc from "spec-compliant" to "production-hardened, operator-preferred, and forward-looking." Phase 1 tackles all P0 safety features (circuit breakers, attestation disable, slashed auto-shutdown, keystore locking) — 4 independent features that can run in full parallel. Phase 2 builds shared BnManager infrastructure (health tiers, broadcast topics, proposer nodes). Phase 3 delivers operational quality-of-life (monitoring, log rotation, proposer config URL). Phase 4 extends the builder/block-selection path. Phase 5 adds advanced BN routing and pre-signed exits. Phase 6 tackles experimental features (Gnosis, native relay, verifying signer, SSE logs). The critical dependency chain runs FR-1 → FR-10 → FR-16 (builder path) and FR-14 → FR-11 (BnManager path).

## Prerequisites

- [ ] Tier 1 (Standards Compliance) fully merged to `develop` and all tests passing
- [ ] PRD, architecture, and research documents reviewed and approved
- [ ] `cargo check && cargo test` passes on current `develop`
- [ ] Developer(s) have read the architecture doc (especially shared infrastructure clusters and dependency graph)
- [ ] `fd-lock` crate evaluated and approved for keystore locking (FR-4)
- [ ] `logroller` or equivalent crate evaluated for size-based log rotation (FR-8)

---

## Phase 1: Safety — Tier 2 P0 Features

**Goal:** Eliminate the four highest-risk gaps: financial loss from builder failures, inability to respond to incidents without full restart, slashing cascade damage, and duplicate-instance slashing risk.

**Entry Criteria:** Prerequisites complete. Tier 1 merged and green.

**Duration Estimate:** Medium

### Parallel Streams

All 4 features touch different crates with zero overlap. Full parallelization is possible.

| Stream | Feature | Primary Crates |
|--------|---------|----------------|
| A | FR-1: Builder Circuit Breakers | `crates/builder/`, `crates/block-service/`, coordinator |
| B | FR-2: Emergency Attestation Disable | coordinator, `crates/keymanager-api/` |
| C | FR-3: Slashed Validator Auto-Shutdown | coordinator, `crates/validator-store/` |
| D | FR-4: Keystore File Locking | `crates/rvc/src/startup.rs` |

### Work Items

#### Stream A — Builder Circuit Breakers (FR-1)

- [ ] **1.1 — Add `CircuitBreakerState` struct**
  - New file `crates/builder/src/circuit_breaker.rs` with lock-free `AtomicU32` counters
  - Methods: `new()`, `is_tripped()`, `record_miss()`, `record_success()`, `reset_epoch()`
  - Unit tests: trip on consecutive limit, trip on epoch limit, reset at epoch boundary, disabled when limits=0
  - Dependencies: none
  - Complexity: **S**

- [ ] **1.2 — Add circuit breaker config and CLI flags**
  - Add `builder_circuit_breaker_consecutive_limit` and `builder_circuit_breaker_epoch_limit` to `Config`
  - CLI flags: `--builder-circuit-breaker-consecutive-limit=3`, `--builder-circuit-breaker-epoch-limit=5`
  - Dependencies: none
  - Complexity: **S**

- [ ] **1.3 — Integrate circuit breaker into BlockService**
  - In `BlockService::propose_block()`, check `circuit_breaker.is_tripped()` before requesting builder block
  - If tripped, set `builder_boost_factor=0` to force local block
  - After proposal result, call `record_miss()` or `record_success()`
  - Dependencies: 1.1
  - Complexity: **M**

- [ ] **1.4 — Add epoch reset and metrics**
  - Call `circuit_breaker.reset_epoch()` at epoch boundary in coordinator
  - Add Prometheus metrics: `rvc_builder_circuit_breaker_trips_total`, `rvc_builder_consecutive_misses`, `rvc_builder_epoch_misses`
  - WARN log on trip, INFO log on reset
  - Dependencies: 1.3
  - Complexity: **S**

- [ ] **1.5 — Integration tests for circuit breaker**
  - End-to-end: mock builder failures → verify local block fallback after N misses
  - Verify epoch reset re-enables builder
  - Verify `limit=0` disables feature
  - Dependencies: 1.4
  - Complexity: **M**

#### Stream B — Emergency Attestation Disable (FR-2)

- [ ] **1.6 — Add `AttestingEnabled` shared state and coordinator check**
  - Add `attesting_enabled: Arc<AtomicBool>` to `DutyOrchestrator`
  - Before `attestation_service.process_slot()`, check `attesting_enabled.load(Relaxed)` — skip if false
  - Same check before sync committee and aggregation duties
  - Block proposals, builder registration, SSE, and metrics continue unaffected
  - Dependencies: none
  - Complexity: **S**

- [ ] **1.7 — Add attestation toggle API endpoint**
  - `POST /rvc/v1/attesting` with `{"enabled": true|false}` request body
  - Bearer token auth required
  - WARN log on disable, INFO log on re-enable
  - Dependencies: 1.6
  - Complexity: **S**

- [ ] **1.8 — Add `--disable-attesting` CLI flag and metric**
  - CLI flag sets initial `AtomicBool` to `false`
  - Prometheus gauge: `rvc_attesting_enabled` (1=enabled, 0=disabled)
  - Wire `Arc<AtomicBool>` from coordinator into `AppState` for API access
  - Dependencies: 1.6, 1.7
  - Complexity: **S**

- [ ] **1.9 — Integration tests for attestation disable**
  - Toggle via API → verify attestations stop → re-enable → verify attestations resume
  - Verify block proposals continue while attestation is disabled
  - Verify `--disable-attesting` starts with duties skipped
  - Dependencies: 1.8
  - Complexity: **M**

#### Stream C — Slashed Validator Auto-Shutdown (FR-3)

- [ ] **1.10 — Add `SlashedAction` enum and config**
  - New `SlashedAction` enum: `DisableOnly`, `Shutdown`, `None`
  - CLI flag: `--slashed-validators-action=disable-only|shutdown|none` (default: `disable-only`)
  - Config field: `slashed_validators_action`
  - Dependencies: none
  - Complexity: **S**

- [ ] **1.11 — Implement slashing monitor background task**
  - New file `crates/rvc/src/slashing_monitor.rs`
  - Runs once per epoch: query BN `get_validators()` for managed pubkeys, check for `"slashed"` in status
  - On detection: call `validator_store.set_enabled(pubkey, false)` + `save_config()`
  - In `Shutdown` mode: trigger shutdown via `watch::Sender<bool>`
  - Fail-open: if BN unreachable, log WARN and continue (don't disable validators)
  - Dependencies: 1.10
  - Complexity: **M**

- [ ] **1.12 — Add metrics and integration tests**
  - Prometheus counter: `rvc_validators_slashed_total`
  - ERROR log with pubkey and status on detection
  - Test: mock BN returns slashed status → verify validator disabled
  - Test: mock BN unreachable → verify validators continue
  - Test: `Shutdown` mode triggers shutdown
  - Dependencies: 1.11
  - Complexity: **M**

#### Stream D — Keystore File Locking (FR-4)

- [ ] **1.13 — Add `fd-lock` dependency and `acquire_keystore_lock()`**
  - Add `fd-lock = "4"` to `crates/rvc/Cargo.toml`
  - New function `acquire_keystore_lock(data_dir: &Path)` in `startup.rs`
  - Creates `.rvc.lock` file, acquires exclusive `flock()` via `fd-lock`
  - On failure: ERROR log with locked path, exit with code 14
  - Lock file permissions: `0o600`
  - Dependencies: none
  - Complexity: **S**

- [ ] **1.14 — Integrate into startup sequence and add CLI flag**
  - Insert lock acquisition after integrity check, before genesis validation
  - CLI flag: `--disable-keystore-locking` bypasses lock
  - Config field: `disable_keystore_locking: bool`
  - Dependencies: 1.13
  - Complexity: **S**

- [ ] **1.15 — Integration tests for keystore locking**
  - First instance acquires lock successfully
  - Second instance with overlapping keys fails with descriptive error
  - After first instance exits, second instance starts successfully
  - `--disable-keystore-locking` bypasses check
  - Dependencies: 1.14
  - Complexity: **M**

### Phase 1 Exit Criteria

- Circuit breaker trips after configured consecutive/epoch misses; proposals fall back to local block
- Circuit breaker resets at epoch boundary; metrics accurate
- Attestation duties can be disabled/re-enabled via API within one slot, without affecting block proposals
- Slashed validators detected within 1 epoch; duties disabled automatically
- Second rvc instance with overlapping keys fails to start with clear error
- All new features have Prometheus metrics and appropriate log levels
- `cargo test` passes with no regressions
- `cargo clippy` and `cargo fmt` clean

---

## Phase 2: BN Infrastructure — Shared BnManager Foundation

**Goal:** Build the shared BnManager infrastructure that FR-11 (Role-Based BN) will later compose with: health-based tier selection, configurable broadcast topics, and dedicated proposer nodes.

**Entry Criteria:** Phase 1 complete (specifically FR-1, since the block production path is now stable).

### Ordering Within Phase

FR-14 (Health Tiers) must be implemented first — it changes the core `synced_indices()` method that FR-6 and FR-5 also touch. FR-6 and FR-5 are then independent of each other and can be parallelized.

```
FR-14 (Health Tiers)
  ├──→ FR-6 (Broadcast Topics)    [parallel]
  └──→ FR-5 (Proposer Nodes)      [parallel]
```

**Duration Estimate:** Medium-Large

### Work Items

#### Sub-Phase 2A — Health Tiers (FR-14) — Sequential

- [ ] **2.1 — Add `HealthTier`, `BnCapabilities`, and `TierThresholds` types**
  - New types in `crates/bn-manager/src/types.rs`
  - `HealthTier` enum: `Synced`, `SmallLag`, `LargeLag`, `Unsynced` with `PartialOrd`
  - Configurable thresholds (default: 8/8/48 slot distances)
  - Dependencies: none
  - Complexity: **S**

- [ ] **2.2 — Refactor `BnSyncStatus` to include sync distance**
  - Extend `BnSyncStatus` struct with `sync_distance: Option<u64>` and `head_slot: Option<u64>`
  - `check_single_sync_status()` already parses these — store them instead of discarding
  - Add `compute_tier(sync_distance, thresholds) -> HealthTier` method
  - Backwards compatible: existing `is_usable()` unchanged
  - Dependencies: 2.1
  - Complexity: **M**

- [ ] **2.3 — Refactor `synced_indices()` with tier-based filtering**
  - Add `min_tier: HealthTier` parameter to `synced_indices()`
  - Filter BNs by tier eligibility: proposals require `Synced`, attestations `SmallLag`, submissions `LargeLag`
  - Fallback to all BNs with WARN if no eligible BNs at required tier
  - Maintain backwards compatibility: callers that don't specify tier get current behavior
  - Per-BN Prometheus gauge: `rvc_bn_health_tier`
  - Dependencies: 2.2
  - Complexity: **M**

- [ ] **2.4 — Add tier threshold config and integration tests**
  - TOML config for tier thresholds (synced, small, large)
  - Test: BN 2 slots behind → Tier 2 → used for attestations, skipped for proposals
  - Test: BN 20 slots behind → Tier 3 → used for submissions only
  - Test: fallback to lower tier with WARN when no higher-tier BNs available
  - Dependencies: 2.3
  - Complexity: **M**

#### Sub-Phase 2B — Broadcast Topics & Proposer Nodes (parallel after 2A)

- [ ] **2.5 — Add `BroadcastTopics` config and routing (FR-6)**
  - Add `broadcast_topics: BroadcastTopics` field to `BnManager`
  - Each submission method checks topic: if topic not in set, use `query_first()` instead of `broadcast_to_all()`
  - CLI flag: `--broadcast attestations,blocks,sync-committee,subscriptions` (default: all)
  - `none` disables broadcast entirely
  - Validate topic names at startup; reject invalid topics with error
  - INFO log of active broadcast topics at startup
  - Dependencies: 2.3 (uses refactored BnManager)
  - Complexity: **M**

- [ ] **2.6 — Integration tests for broadcast topics (FR-6)**
  - `--broadcast blocks` → only block submissions are broadcast; attestations use First strategy
  - `--broadcast none` → all messages use First strategy
  - Default behavior unchanged
  - Invalid topic name → startup error
  - Dependencies: 2.5
  - Complexity: **S**

- [ ] **2.7 — Add dedicated proposer BnManager instance (FR-5)**
  - CLI flag: `--proposer-nodes <URL1>,<URL2>,...`
  - Create second `BnManager` instance from proposer node endpoints
  - Pass to `BlockService` as `block_beacon` (architecture already separates this)
  - Proposer BnManager has independent health tracking, sync monitoring, and failover
  - Fallback to main BN pool if all proposer nodes are down (WARN log)
  - Dependencies: 2.3 (uses refactored BnManager with tier support)
  - Complexity: **M**

- [ ] **2.8 — Add proposer node metrics and integration tests (FR-5)**
  - Separate metrics: `rvc_proposer_bn_health_score`, `rvc_proposer_bn_latency_ms` (with `pool="proposer"` label)
  - Test: with `--proposer-nodes`, block production goes to proposer nodes
  - Test: proposer nodes unreachable → falls back to main pool with WARN
  - Test: without `--proposer-nodes`, behavior unchanged
  - Dependencies: 2.7
  - Complexity: **M**

### Phase 2 Exit Criteria

- BN health assessed on 4-tier model based on sync distance
- Proposals route only through Synced-tier BNs; attestations through Synced + SmallLag
- Broadcast topics configurable; non-broadcast topics use First strategy
- Dedicated proposer nodes handle block production separately from main BN pool
- Proposer node failure falls back to main pool gracefully
- All features backwards compatible (defaults match current behavior)
- `cargo test` passes; `cargo clippy` clean

---

## Phase 3: Operations — Tier 3 Quality-of-Life

**Goal:** Deliver operational features that reduce manual effort: remote monitoring, log management, and remote proposer configuration.

**Entry Criteria:** Phase 1 complete. (Phase 2 is NOT required — these features are independent of BnManager work.)

**Duration Estimate:** Medium

### Parallel Streams

All 3 features are fully independent — different crates, no shared state.

| Stream | Feature | Primary Crates |
|--------|---------|----------------|
| A | FR-7: Remote Monitoring | new `crates/rvc/src/monitoring.rs` |
| B | FR-8: Log Rotation | `crates/telemetry/` |
| C | FR-9: Proposer Config URL | new `crates/rvc/src/config_url.rs`, `crates/validator-store/` |

### Work Items

#### Stream A — Remote Monitoring (FR-7)

- [ ] **3.1 — Implement monitoring push service**
  - New file `crates/rvc/src/monitoring.rs`
  - `MonitoringPayload` struct matching beaconcha.in v1 schema
  - Background task: collect metrics → POST to configured endpoint every epoch
  - Retry with exponential backoff (max 3 retries per push)
  - Push failures do NOT block validator duties
  - Dependencies: none
  - Complexity: **M**

- [ ] **3.2 — Add monitoring config, CLI flags, and tests**
  - CLI flags: `--monitoring-endpoint <URL>`, `--monitoring-interval <seconds>` (default: 384), `--monitoring-endpoint-insecure`
  - HTTPS enforced by default
  - DEBUG log on successful push, WARN on failure
  - Prometheus counters: monitoring push success/failure
  - Test: mock endpoint receives correct payload; failures don't affect duties
  - Dependencies: 3.1
  - Complexity: **M**

#### Stream B — Log Rotation (FR-8)

- [ ] **3.3 — Add size-based file appender with rotation**
  - New file `crates/telemetry/src/file_appender.rs`
  - Add `logroller` (or custom `MakeWriter`) and `flate2` dependencies
  - Size-based rotation (not time-based per PRD requirement)
  - Gzip compression for rotated files when enabled
  - Non-blocking I/O via `tracing_appender::non_blocking`
  - Dependencies: none
  - Complexity: **M**

- [ ] **3.4 — Integrate file appender into tracing subscriber stack**
  - Extend `init_tracing()` to optionally add file appender layer
  - File logging runs alongside stdout logging
  - CLI flags: `--logfile <path>`, `--logfile-max-size <MB>` (default: 200), `--logfile-max-number <N>` (default: 5), `--logfile-compress`, `--logfile-level <level>`
  - Test: log file rotates at size limit; old files deleted at max count; compressed files valid gzip
  - Dependencies: 3.3
  - Complexity: **M**

#### Stream C — Proposer Config URL (FR-9)

- [ ] **3.5 — Implement URL fetcher and config parser**
  - New file `crates/rvc/src/config_url.rs`
  - Parse Prysm/Teku JSON schema into `ValidatorConfigUpdate` structs
  - Background task: fetch URL → apply changes via `validator_store.update_config()`
  - On failure: retain existing config, WARN log, retry next interval
  - Bearer token auth support via `--proposer-config-url-token`
  - Dependencies: none
  - Complexity: **M**

- [ ] **3.6 — Add config, mutual exclusivity check, and tests**
  - CLI flags: `--proposer-config-url <URL>`, `--proposer-config-refresh-interval <seconds>` (default: 384), `--proposer-config-url-token`, `--proposer-config-url-insecure`
  - Startup rejects `--proposer-config-url` + `--proposer-config-file` together
  - HTTPS enforced by default
  - Test: config loaded from URL at startup; changes picked up on refresh; fetch failure retains current config
  - Dependencies: 3.5
  - Complexity: **M**

### Phase 3 Exit Criteria

- Monitoring metrics pushed to configured endpoint every epoch; failures don't affect duties
- Log files rotate at configured size; old files cleaned up; compressed files valid gzip
- File I/O does not block attestation signing hot path
- Proposer config loaded from URL; changes applied within one refresh interval
- Fetch failures retain last-known-good config
- `--proposer-config-url` and `--proposer-config-file` mutual exclusivity enforced
- `cargo test` passes; `cargo clippy` clean

---

## Phase 4: Block Selection & Builder Enhancements

**Goal:** Extend the builder and block production path with multi-strategy selection and registration batching for large validator sets.

**Entry Criteria:** Phase 1 complete (FR-1 circuit breakers required for FR-10's `builderonly` interaction).

**Duration Estimate:** Medium

### Parallel Streams

FR-10 and FR-12 modify different parts of the builder path and can be parallelized.

| Stream | Feature | Primary Crates |
|--------|---------|----------------|
| A | FR-10: Multi-Strategy Block Selection | `crates/block-service/`, `crates/validator-store/` |
| B | FR-12: Registration Batching | `crates/builder/src/service.rs` |

### Work Items

#### Stream A — Block Selection Modes (FR-10)

- [ ] **4.1 — Add `BlockSelectionMode` enum and per-validator config**
  - New enum in `crates/block-service/src/types.rs`: `MaxProfit`, `BuilderOnly`, `ExecutionOnly`, `BuilderAlways`
  - Add `block_selection_mode` field to `ValidatorConfig` and TOML parsing
  - Add `effective_block_selection_mode()` to `ValidatorStore` (per-validator overrides global)
  - CLI flag: `--block-selection-mode <mode>` (default: `maxprofit`)
  - Dependencies: none
  - Complexity: **S**

- [ ] **4.2 — Integrate block selection into `propose_block()`**
  - Match on selection mode in `BlockService::propose_block()`:
    - `ExecutionOnly`: set `builder_boost_factor=0`
    - `BuilderOnly`: set max boost + verify response is blinded block; ERROR if circuit breaker tripped
    - `BuilderAlways`: set max boost (BN handles fallback)
    - `MaxProfit`: use existing `builder_boost_factor` from ValidatorStore
  - Metric: `rvc_block_selection_mode` (label per mode)
  - Dependencies: 4.1, FR-1 (circuit breaker for `builderonly` interaction)
  - Complexity: **M**

- [ ] **4.3 — Integration tests for block selection**
  - `executiononly` → never requests builder; `builderonly` → fails if builder down; `builderalways` → falls back to local
  - `builderonly` + circuit breaker tripped → ERROR log, proposal fails
  - Per-validator mode overrides global
  - Default behavior unchanged
  - Dependencies: 4.2
  - Complexity: **M**

#### Stream B — Registration Batching (FR-12)

- [ ] **4.4 — Implement chunked registration submission**
  - In `BuilderService::register_validators()`, replace single submission with `.chunks(batch_size)` loop
  - Configurable delay between batches
  - Per-batch error handling: log WARN on failure, continue with remaining batches
  - `batch_size=0` means single batch (current behavior)
  - CLI flags: `--validator-registration-batch-size <N>` (default: 500), `--validator-registration-batch-delay <ms>` (default: 500)
  - Dependencies: none
  - Complexity: **S**

- [ ] **4.5 — Add batching metrics and tests**
  - Prometheus counters: `rvc_builder_registration_batches_total`, `rvc_builder_registration_batches_failed`
  - Test: 2000 validators, batch size 500 → 4 sequential registrations
  - Test: failed batch doesn't prevent remaining batches
  - Dependencies: 4.4
  - Complexity: **S**

### Phase 4 Exit Criteria

- All 4 block selection modes work correctly (`maxprofit`, `builderonly`, `executiononly`, `builderalways`)
- `builderonly` + circuit breaker tripped → fails loudly (ERROR log)
- Per-validator mode overrides global; default behavior unchanged
- Registration batching completes within 2 epochs for 10,000 validators
- Failed batches don't block remaining batches
- `cargo test` passes; `cargo clippy` clean

---

## Phase 5: Advanced — Role-Based BN & Pre-Signed Exits

**Goal:** Enable sentry-node architectures via role-based BN assignment and cold-key custody workflows via pre-signed exit storage.

**Entry Criteria:** Phase 2 complete (FR-14 health tiers and FR-5 proposer nodes required for FR-11).

**Duration Estimate:** Medium

### Parallel Streams

FR-11 and FR-13 are independent.

| Stream | Feature | Primary Crates |
|--------|---------|----------------|
| A | FR-11: Role-Based BN Assignment | `crates/bn-manager/` |
| B | FR-13: Pre-Signed Voluntary Exit Storage | `bin/rvc/`, `crates/keymanager-api/` |

### Work Items

#### Stream A — Role-Based BN Assignment (FR-11)

- [ ] **5.1 — Add `BnRole` enum and per-BN role config**
  - `BnRole` enum: `Attestation`, `Proposal`, `SyncCommittee`, `Aggregation`, `Submission`, `All`
  - TOML config: `[[beacon_nodes]]` with `roles = [...]` field (default: `["all"]`)
  - Add `bn_roles: Vec<HashSet<BnRole>>` to `BnManager`
  - Dependencies: FR-14 (2.3 — refactored `synced_indices()`)
  - Complexity: **S**

- [ ] **5.2 — Implement role-aware `eligible_indices()` and caller updates**
  - Extend `synced_indices()` → `eligible_indices(role, min_tier)`: filter by role first, then by tier
  - Update all callers (attestation data, block production, sync committee, submissions) to pass appropriate role
  - FR-5 becomes a config shorthand for `roles = ["proposal"]`
  - Cross-role fallback as last resort when no BNs match role+tier (WARN log)
  - Dependencies: 5.1
  - Complexity: **M**

- [ ] **5.3 — Integration tests for role-based routing**
  - BNs with `proposal` role receive only block production requests
  - BNs with `attestation` role receive only attestation data requests
  - Cross-role fallback when all role-matched BNs are down
  - Default `roles = ["all"]` behaves identically to current implementation
  - Dependencies: 5.2
  - Complexity: **M**

#### Stream B — Pre-Signed Voluntary Exit Storage (FR-13)

- [ ] **5.4 — Add `prepare-exit` CLI subcommand**
  - Signs voluntary exit for specified validator using existing signing logic
  - Stores `SignedVoluntaryExit` as JSON in output directory (`<pubkey>_exit.json`)
  - File permissions: `0o600`
  - EIP-7044 guarantees exits are perpetually valid from Capella onward
  - Dependencies: none (uses existing `VoluntaryExitManagerAdapter` signing logic)
  - Complexity: **M**

- [ ] **5.5 — Add `submit-exit` CLI subcommand**
  - Reads stored `SignedVoluntaryExit` JSON file
  - POSTs to BN `/eth/v1/beacon/pool/voluntary_exits`
  - Does NOT require signing keys
  - Dependencies: none
  - Complexity: **S**

- [ ] **5.6 — Add `prepare_exit` API endpoint and tests**
  - `POST /rvc/v1/validator/{pubkey}/prepare_exit` — returns `SignedVoluntaryExit` without submitting
  - Bearer token auth required
  - Tests: prepare → store → submit roundtrip; stored exits valid after simulated fork
  - Dependencies: 5.4
  - Complexity: **S**

### Phase 5 Exit Criteria

- BNs route duties based on assigned roles; role-unassigned BNs default to `all`
- Cross-role fallback works when role-matched BNs are unavailable
- `prepare-exit` produces valid JSON; `submit-exit` submits without signing keys
- API endpoint returns signed exits without submission
- `cargo test` passes; `cargo clippy` clean

---

## Phase 6: Experimental — Tier 5 Features

**Goal:** Deliver forward-looking capabilities: expanded network support, native relay integration, remote signer verification, and real-time log streaming.

**Entry Criteria:** Phase 1 complete (FR-1 required for FR-16). Other phases not strictly required.

**Duration Estimate:** Large

### Ordering Constraints

- FR-16 (Native Relay) depends on FR-1 (Circuit Breakers) — relay path must respect circuit breakers
- FR-17 (Gnosis) is high-risk and should include a dedicated spike for slot-time audit
- FR-15 (Verifying Signer) is high-risk due to trait signature changes — feature-gated
- FR-18 (SSE Logs) is independent and low-risk

### Work Items

#### FR-17: Gnosis Chain Support

- [ ] **6.1 — Audit slot-time assumptions across codebase**
  - Technical spike: grep for `SECONDS_PER_SLOT`, `SLOTS_PER_EPOCH`, hardcoded `12`, `32` across all crates
  - Document every location that assumes Ethereum's 12-second slots
  - Key locations: `crates/timing/`, coordinator deadline calculations, `BnManager::DEFAULT_SYNC_CHECK_INTERVAL`, builder jitter
  - Produce list of required changes before implementation
  - Dependencies: none
  - Complexity: **M**

- [ ] **6.2 — Parameterize slot duration from network config**
  - Make `seconds_per_slot()` return network-specific values (5s for Gnosis, 12s for Ethereum)
  - Replace all hardcoded slot-time constants with `network.seconds_per_slot()` calls
  - Dependencies: 6.1
  - Complexity: **L**

- [ ] **6.3 — Add `Gnosis` and `Chiado` network variants**
  - Add to `Network` enum with genesis constants, fork schedule, deposit contract
  - Add to `rvc-keygen` with correct fork versions
  - Test: `--network gnosis` parses; `--network chiado` parses
  - Dependencies: 6.2
  - Complexity: **M**

#### FR-16: Native Relay Integration

- [ ] **6.4 — Create `crates/relay-client/` crate**
  - Implement MEV-Boost relay API client: header requests, blinded block submissions, validator registration
  - Multi-relay support: query all relays in parallel, select best bid
  - BLS signing for relay authentication
  - Timeout and retry configuration per-relay
  - Dependencies: none
  - Complexity: **L**

- [ ] **6.5 — Integrate relay client into builder/block paths**
  - Alternative path in `BuilderService` for direct relay registration
  - Alternative path in `BlockService` for relay header + unblinding flow
  - Must respect circuit breakers (FR-1)
  - Mutual exclusivity with `--builder-endpoint` (mev-boost)
  - CLI flags: `--relay-endpoints <URLs>`, `--relay-secret-key`
  - Dependencies: 6.4, FR-1
  - Complexity: **L**

- [ ] **6.6 — Native relay integration tests**
  - Mock relay: header request → bid selection → unblinding
  - Multi-relay: select highest-value bid
  - Relay failure → local block fallback (respects circuit breakers)
  - `--relay-endpoints` + `--builder-endpoint` → startup error
  - Dependencies: 6.5
  - Complexity: **M**

#### FR-15: Verifying Web3Signer

- [ ] **6.7 — Add execution payload Merkle proof verification types**
  - Add Merkle proof verification for fee recipient/gas limit within execution payload
  - Add verification types to `crates/eth-types/`
  - Feature-gated: `--features verifying-signer`
  - Dependencies: none
  - Complexity: **M**

- [ ] **6.8 — Extend rvc-signer with block verification**
  - Add `sign_block_with_verification()` method to `ValidatorSigner` trait (default impl falls back to `sign_block()`)
  - gRPC protocol extension: optional verification fields (expected fee recipient, gas limit, Merkle proof)
  - Reject signing when proof invalid or fee recipient mismatches
  - Dependencies: 6.7
  - Complexity: **L**

- [ ] **6.9 — Verifying signer integration tests**
  - Valid proof → sign succeeds
  - Invalid proof → sign rejected with ERROR
  - Missing proof (feature off) → unchanged behavior
  - Dependencies: 6.8
  - Complexity: **M**

#### FR-18: SSE Log Streaming API

- [ ] **6.10 — Add tracing broadcast layer**
  - Custom `tracing::Layer` that captures log events into a `tokio::sync::broadcast` channel
  - Bounded channel (drop oldest on overflow) to avoid slow client backpressure
  - `LogEvent` type: timestamp, level, target, message, fields
  - Dependencies: none
  - Complexity: **M**

- [ ] **6.11 — Add SSE endpoint and connection management**
  - `GET /rvc/v1/logs` returning `text/event-stream`
  - Query parameters: `level=<info|warn|error>`, `target=<module_path>`
  - Bearer token auth required
  - Max concurrent connections: 10 (configurable), reject 11th with 429
  - `AtomicU32` connection counter
  - Dependencies: 6.10
  - Complexity: **M**

- [ ] **6.12 — SSE integration tests**
  - Verify live log events stream as JSON SSE
  - `level=error` filters correctly
  - Slow client dropped (bounded channel) without affecting others
  - Connection limit enforced
  - Dependencies: 6.11
  - Complexity: **S**

### Phase 6 Exit Criteria

- `rvc --network gnosis` starts with correct 5-second slot timing
- All slot-time-dependent calculations parameterized from network config
- Native relay path produces blocks without mev-boost; respects circuit breakers
- Verifying signer rejects signing on proof mismatch (when feature-gated enabled)
- SSE log stream delivers events to connected clients within 100ms
- All features are opt-in and do not affect default behavior
- `cargo test` passes; `cargo clippy` clean

---

## Dependency Graph

```text
Phase 1 (Safety)                  Phase 2 (BN Infra)         Phase 3 (Ops)          Phase 4 (Block)       Phase 5 (Advanced)     Phase 6 (Experimental)
════════════════                  ═══════════════════         ═════════════          ════════════════      ══════════════════     ═════════════════════

┌────────────┐                    ┌────────────┐             ┌───────────┐          ┌────────────┐        ┌────────────┐         ┌────────────┐
│ FR-1       │───────────────────▶│ FR-14      │             │ FR-7      │          │ FR-10      │        │ FR-11      │         │ FR-17      │
│ Circuit    │─────────┐         │ Health     │             │ Monitor   │     ┌───▶│ Block Sel  │   ┌───▶│ Role BN    │         │ Gnosis     │
│ Breakers   │─────┐   │         │ Tiers      │             └───────────┘     │    └────────────┘   │    └────────────┘         └────────────┘
└────────────┘     │   │         └─────┬──────┘                               │                     │
                   │   │               │                     ┌───────────┐     │    ┌────────────┐   │    ┌────────────┐         ┌────────────┐
┌────────────┐     │   │         ┌─────▼──────┐             │ FR-8      │     │    │ FR-12      │   │    │ FR-13      │         │ FR-16      │
│ FR-2       │     │   │         │ FR-6       │             │ Log Rot   │     │    │ Reg Batch  │   │    │ Pre-Exits  │    ┌───▶│ Nat Relay  │
│ Att Disable│     │   │         │ Broadcast  │             └───────────┘     │    └────────────┘   │    └────────────┘    │    └────────────┘
└────────────┘     │   │         └────────────┘                               │                     │                      │
                   │   │                                     ┌───────────┐     │                     │                      │    ┌────────────┐
┌────────────┐     │   │         ┌────────────┐             │ FR-9      │     │                     │                      │    │ FR-15      │
│ FR-3       │     │   │         │ FR-5       │             │ Config URL│     │                     │                      │    │ Verify Sign│
│ Slash Shut │     │   │         │ Proposer   │─────────────┼───────────┼─────┘                     │                      │    └────────────┘
└────────────┘     │   │         │ Nodes      │──────────────────────────────────────────────────────┘
                   │   │         └────────────┘                                                                             │    ┌────────────┐
┌────────────┐     │   │                                                                                                    │    │ FR-18      │
│ FR-4       │     │   └────────────────────────────────────────────────────────────────────────────────────────────────────┘    │ SSE Logs   │
│ Key Lock   │     │             dep: FR-1 → FR-10                                                                              └────────────┘
└────────────┘     │             dep: FR-1 → FR-16
                   │             dep: FR-14 → FR-11
                   └──────────────dep: FR-5 → FR-11
                                  dep: FR-14 → FR-6, FR-5

Legend: ──▶ = depends on (must complete before)
```

### Critical Paths

```
Path 1 (Builder):    FR-1 → FR-10 → [done]
                     FR-1 → FR-16 → [done]

Path 2 (BnManager):  FR-14 → FR-5 → FR-11 → [done]
                      FR-14 → FR-6 → [done]

Path 3 (Gnosis):     6.1 spike → 6.2 parameterize → 6.3 variants → [done]
```

The longest path is through BnManager: **FR-14 → FR-5 → FR-11**.

---

## Milestones

### M1: Safety Complete (Phase 1)

**Criteria:**
- [ ] Circuit breakers prevent financial loss from relay failures
- [ ] Attestation duties can be disabled/re-enabled at runtime without process restart
- [ ] Slashed validators detected and duties halted within 1 epoch
- [ ] Duplicate rvc instances prevented via keystore locking
- [ ] All 4 features have metrics, logging, and integration tests

### M2: BN Infrastructure Complete (Phase 2)

**Criteria:**
- [ ] Health-based 4-tier BN selection operational
- [ ] Broadcast topics configurable per message type
- [ ] Dedicated proposer nodes handle block production independently
- [ ] All features backwards compatible with current defaults

### M3: Operations Complete (Phase 3)

**Criteria:**
- [ ] Remote monitoring pushes to beaconcha.in-compatible endpoint
- [ ] Log files self-rotate by size with optional compression
- [ ] Proposer config loadable from URL with auto-refresh

### M4: Builder Enhancements Complete (Phase 4)

**Criteria:**
- [ ] All 4 block selection strategies functional (maxprofit, builderonly, executiononly, builderalways)
- [ ] Registration batching handles 10,000+ validators without BN timeout
- [ ] Circuit breaker + builderonly interaction tested and documented

### M5: Advanced Features Complete (Phase 5)

**Criteria:**
- [ ] Role-based BN assignment enables sentry-node architectures
- [ ] Pre-signed exits support cold-key custody workflows
- [ ] All features compose correctly with Phase 2 BnManager infrastructure

### M6: Experimental Features Complete (Phase 6)

**Criteria:**
- [ ] Gnosis Chain operational with 5-second slot timing
- [ ] Native relay integration eliminates mev-boost dependency
- [ ] Verifying signer validates block properties before signing
- [ ] SSE log streaming delivers events within 100ms

---

## Risk Register

| Risk | Impact | Likelihood | Phase | Mitigation |
|------|--------|------------|-------|------------|
| **Circuit breaker mis-calibration** — defaults too aggressive or too lenient | Missed proposals or continued exposure | Medium | 1 | Match Prysm defaults (3/5); make fully configurable; log all trips for operator tuning |
| **Keystore locking incompatible with DVT** — DVT runs multiple signers with overlapping keys | DVT users locked out | Medium | 1 | `--disable-keystore-locking` flag; document DVT exception |
| **Slashing detection false positive** — stale BN validator status | Healthy validator disabled | Low | 1 | Fail-open on BN error; consider requiring 2 consecutive slashed statuses |
| **Health tier refactor breaks BN selection** — `synced_indices()` is core to all operations | All duties disrupted | Medium | 2 | Incremental refactor; maintain backwards compatibility at every step; extensive testing |
| **Log rotation blocks hot path** — synchronous file I/O during attestation signing | Missed attestation deadlines | Medium | 3 | Non-blocking writer via `tracing_appender::non_blocking`; verify with load test |
| **Proposer config URL single point of failure** — URL unreachable = stale config | Incorrect fee recipients | Medium | 3 | Retain last-known-good config; WARN on consecutive failures; max staleness cap |
| **`builderonly` + circuit breaker** — proposal fails when builder is broken | Missed proposals (by design) | Low | 4 | Document explicitly; ERROR-level logging; operators choose this mode knowingly |
| **Gnosis slot-time assumptions** — 5-second slots break calculations across codebase | Incorrect timing for all duties | High | 6 | Mandatory spike (6.1) before implementation; audit every hardcoded constant |
| **Native relay API drift** — relay spec is evolving | Implementation becomes stale | Medium | 6 | Feature-gate behind `--features native-relay`; pin to relay spec v1 |
| **Verifying signer trait change** — modifying `ValidatorSigner` trait breaks all implementors | Build breakage across crates | High | 6 | Add new method with default impl; feature-gate; don't modify existing `sign_block()` |

---

## Resource Planning

### 1-Developer Execution

If working solo, execute phases sequentially. Within each phase, work streams sequentially (pick the highest-dependency stream first):

| Phase | Focus | Est. Relative Size |
|-------|-------|-------------------|
| 1 | Safety (FR-1 → FR-2 → FR-3 → FR-4) | Large |
| 2 | BN Infrastructure (FR-14 → FR-6 → FR-5) | Medium-Large |
| 3 | Operations (FR-7 → FR-8 → FR-9) | Medium |
| 4 | Block Selection (FR-10 → FR-12) | Medium |
| 5 | Advanced (FR-11 → FR-13) | Medium |
| 6 | Experimental (FR-18 → FR-17 → FR-16 → FR-15) | Large |

**Note:** Phases 3 and 4 have no dependency between them and can be interleaved based on priority.

### 2-Developer Execution

With 2 developers, parallelize within phases:

| Phase | Developer A | Developer B |
|-------|-----------|-----------|
| 1 | FR-1 (Circuit Breakers) + FR-3 (Slash Shutdown) | FR-2 (Att Disable) + FR-4 (Key Lock) |
| 2 | FR-14 (Health Tiers) → FR-5 (Proposer Nodes) | [Phase 3: FR-7 or FR-8 or FR-9] then FR-6 (Broadcast Topics) |
| 3 | FR-7 (Monitoring) | FR-8 (Log Rotation) or FR-9 (Config URL) |
| 4 | FR-10 (Block Selection) | FR-12 (Reg Batching) |
| 5 | FR-11 (Role-Based BN) | FR-13 (Pre-Signed Exits) |
| 6 | FR-17 (Gnosis) + FR-16 (Relay) | FR-18 (SSE Logs) + FR-15 (Verifying Signer) |

**Key insight:** With 2 developers, Phase 3 can be started in parallel with Phase 2 (by Developer B), since Phase 3 has no dependency on Phase 2. This significantly compresses the overall timeline.

### Where Parallel Streams Exist

| Phase | Independent Streams | Bottleneck |
|-------|-------------------|------------|
| 1 | 4 streams (FR-1, FR-2, FR-3, FR-4) | None — full parallel |
| 2 | 2 streams after sub-phase 2A (FR-6 ∥ FR-5) | FR-14 must be first |
| 3 | 3 streams (FR-7, FR-8, FR-9) | None — full parallel |
| 4 | 2 streams (FR-10 ∥ FR-12) | None — full parallel |
| 5 | 2 streams (FR-11 ∥ FR-13) | None — full parallel |
| 6 | 4 features, but FR-17 spike is a bottleneck | FR-17 spike before Gnosis impl |

---

## Technical Spikes / Open Questions

| Item | Phase | Status | Notes |
|------|-------|--------|-------|
| `logroller` vs custom `MakeWriter` for size-based rotation | 3 | Open | `tracing-appender` only supports time-based rotation; need to evaluate `logroller` crate maturity |
| Gnosis `SLOTS_PER_EPOCH` — is it 16 or 32 after recent updates? | 6 | Open | Verify against current Gnosis Chain spec before implementation |
| Relay spec v1 stability — is the MEV-Boost relay API stable enough? | 6 | Open | Check Flashbots relay spec for breaking changes; consider pinning to specific version |
| beaconcha.in monitoring API v1 schema — is the spec public and stable? | 3 | Open | Need to verify payload schema matches current beaconcha.in expectations |
| `fd-lock` vs `fs2` for cross-platform locking | 1 | Open | Architecture recommends `fd-lock`; verify it handles SIGKILL lock release correctly |
| Circuit breaker: should `record_miss()` trigger on empty builder response or only on error? | 1 | Open | PRD says "failed or returned empty/invalid block"; need to define "empty" precisely |

## Decision Log

| Decision | Rationale | Date |
|----------|-----------|------|
| Phase 1 is all-safety, all-parallel | P0 features have zero code overlap; maximum risk reduction earliest | 2026-04-01 |
| FR-14 (Health Tiers) before FR-5/FR-6 in Phase 2 | FR-14 refactors `synced_indices()` which FR-5/FR-6/FR-11 all depend on; doing it first avoids rework | 2026-04-01 |
| Phase 3 independent of Phase 2 | FR-7/FR-8/FR-9 touch telemetry, validator-store, and monitoring — no overlap with BnManager work | 2026-04-01 |
| FR-10 in Phase 4 (after FR-1) | `builderonly` mode must interact with circuit breakers; implementing FR-10 without FR-1 would require mocking the interaction | 2026-04-01 |
| FR-11 in Phase 5 (after FR-14 + FR-5) | FR-11 generalizes FR-5 and composes with FR-14 tier filtering; building it before those features would mean rework | 2026-04-01 |
| Gnosis spike mandatory before implementation | Slot-time assumptions are spread across the entire codebase; implementing without audit risks correctness bugs in all duty paths | 2026-04-01 |
| All Tier 5 features are opt-in / feature-gated | Experimental features should not affect default builds or existing operator workflows | 2026-04-01 |
| 2-dev plan overlaps Phase 2 + Phase 3 | Phase 3 features are fully independent of BnManager work; Developer B can start Phase 3 while Developer A builds BnManager infrastructure | 2026-04-01 |
