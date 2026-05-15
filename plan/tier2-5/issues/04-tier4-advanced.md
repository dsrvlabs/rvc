# Tier 4: Advanced / Differentiating

## Tier Overview
- **Goal:** Support specialized operator profiles — DVT clusters, sentry architectures, large-scale registrations, cold-key custody, and intelligent BN health selection
- **Issue count:** 16 issues, 36 total points
- **Estimated duration:** ~10 days (with 2 parallel streams)
- **Entry criteria:** Tier 2 safety features merged (especially FR-1 circuit breakers for FR-10); Tier 3 proposer nodes merged (for FR-11 to subsume FR-5)
- **Exit criteria:** All 5 advanced features functional; block selection modes route correctly; role-based BN filtering composes with health tiers; registration batching handles 10k+ validators; pre-signed exits stored and submitted successfully

## Tier Summary

| Issue | Title | Points | Stream | Blocked by | New Files | Shared File Edits |
|-------|-------|--------|--------|------------|-----------|-------------------|
| T4.1 | Block selection mode enum + type | 1 | A | — | `crates/block-service/src/types.rs` | — |
| T4.2 | Block selection: ExecutionOnly + MaxProfit | 2 | A | T4.1 | — | `crates/block-service/src/service.rs` |
| T4.3 | Block selection: BuilderOnly + BuilderAlways | 3 | A | T4.1, T2.2 (circuit breaker) | — | `crates/block-service/src/service.rs` |
| T4.4 | Block selection: per-validator config + CLI | 2 | A | T4.1 | — | `crates/validator-store/src/store.rs`, `crates/rvc/src/config/types.rs` |
| T4.5 | Health tier types + threshold config | 2 | B | — | — | `crates/bn-manager/src/sync_status.rs`, `crates/bn-manager/src/types.rs` |
| T4.6 | Health tier: synced_indices refactor | 3 | B | T4.5 | — | `crates/bn-manager/src/manager.rs` |
| T4.7 | Health tier: duty-aware routing | 2 | B | T4.6 | — | `crates/bn-manager/src/manager.rs` |
| T4.8 | Health tier: CLI + metrics | 1 | B | T4.5 | — | `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs` |
| T4.9 | Role-based BN: role enum + annotation | 2 | B | T4.6 | — | `crates/bn-manager/src/manager.rs`, `crates/bn-manager/src/traits.rs` |
| T4.10 | Role-based BN: role-aware filtering | 3 | B | T4.9 | — | `crates/bn-manager/src/manager.rs` |
| T4.11 | Role-based BN: TOML config + CLI | 1 | B | T4.9 | — | `crates/rvc/src/config/types.rs` |
| T4.12 | Registration batching: chunked submission | 2 | A | — | — | `crates/builder/src/service.rs` |
| T4.13 | Registration batching: CLI + metrics | 1 | A | T4.12 | — | `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs` |
| T4.14 | Pre-signed exits: prepare-exit command | 3 | A | — | `crates/rvc/src/prepare_exit.rs` | `crates/keymanager-api/src/handlers.rs` |
| T4.15 | Pre-signed exits: submit-exit command | 2 | A | T4.14 | `crates/rvc/src/submit_exit.rs` | — |
| T4.16 | Tier 4 integration tests | 6 | both | T4.3, T4.7, T4.10, T4.13, T4.15 | `tests/tier4_advanced.rs` | — |

## Tier Parallel Plan

| Day | Stream A | Stream B |
|-----|----------|----------|
| 1 | T4.1 Block selection types (1pt) + T4.12 Reg batching (2pts) | T4.5 Health tier types (2pts) |
| 2 | T4.2 ExecOnly + MaxProfit (2pts) | T4.6 synced_indices refactor (3pts) |
| 3 | T4.3 BuilderOnly + BuilderAlways (3pts) | T4.6 cont. |
| 4 | T4.3 cont. | T4.7 Duty-aware routing (2pts) |
| 5 | T4.4 Block sel per-validator (2pts) + T4.13 Reg CLI (1pt) | T4.9 Role enum + annotation (2pts) |
| 6 | T4.14 Pre-signed exits prepare (3pts) | T4.10 Role-aware filtering (3pts) |
| 7 | T4.14 cont. | T4.10 cont. |
| 8 | T4.15 Submit exit (2pts) | T4.8 Health CLI (1pt) + T4.11 Role CLI (1pt) |
| 9-10 | T4.16 Integration tests (6pts) | T4.16 Integration tests (6pts) |

---

## Issues

### Issue T4.1: Block selection mode enum and type definitions

**Feature:** FR-10 Multi-Strategy Block Selection
**Story Points:** 1
**Priority:** P1
**Depends On:** None
**Blocks:** T4.2, T4.3, T4.4
**Files Modified:**
- `crates/block-service/src/types.rs` — new file: `BlockSelectionMode` enum

**Description:**
Define the `BlockSelectionMode` enum with four variants: `MaxProfit` (default), `BuilderOnly`, `ExecutionOnly`, `BuilderAlways`. Include serde support for TOML/JSON config.

**Implementation Notes:**
- `MaxProfit`: request both sources, select highest value (current behavior)
- `ExecutionOnly`: never request builder blocks (set `builder_boost_factor=0`)
- `BuilderAlways`: prefer builder, fall back to local on failure
- `BuilderOnly`: always use builder, fail if builder fails (for DVT)
- `Default` impl returns `MaxProfit`

**Acceptance Criteria:**
- [ ] Enum with 4 variants defined
- [ ] Serializes/deserializes correctly (kebab-case for TOML)
- [ ] Default is MaxProfit

**Testing Requirements:**
- [ ] Serde round-trip test

---

### Issue T4.2: Block selection — ExecutionOnly and MaxProfit modes

**Feature:** FR-10 Multi-Strategy Block Selection
**Story Points:** 2
**Priority:** P1
**Depends On:** T4.1
**Blocks:** T4.16
**Files Modified:**
- `crates/block-service/src/service.rs` — add mode check in `propose_block()`

**Description:**
Implement `ExecutionOnly` and `MaxProfit` modes in the block production path. `ExecutionOnly` sets `builder_boost_factor=0`, forcing the BN to use local blocks. `MaxProfit` preserves current behavior (uses configured boost factor).

**Implementation Notes:**
- In `propose_block()` (~line 55): match on `BlockSelectionMode`
- `ExecutionOnly`: always pass `builder_boost_factor=Some(0)` to `produce_block_v3()`
- `MaxProfit`: pass configured `builder_boost_factor` (current behavior)
- `BlockService` needs a `mode: BlockSelectionMode` field or receives it per-proposal from validator config

**Acceptance Criteria:**
- [ ] `ExecutionOnly` never sends builder requests (boost_factor=0)
- [ ] `MaxProfit` uses configured boost factor (current behavior unchanged)
- [ ] Mode logged at DEBUG level per proposal

**Testing Requirements:**
- [ ] Unit test: ExecutionOnly passes boost_factor=0
- [ ] Unit test: MaxProfit passes configured boost_factor

---

### Issue T4.3: Block selection — BuilderOnly and BuilderAlways modes

**Feature:** FR-10 Multi-Strategy Block Selection
**Story Points:** 3
**Priority:** P1
**Depends On:** T4.1, T2.2 (circuit breaker integration)
**Blocks:** T4.16
**Files Modified:**
- `crates/block-service/src/service.rs` — add BuilderOnly/BuilderAlways logic

**Description:**
Implement `BuilderOnly` and `BuilderAlways` modes. `BuilderAlways` prefers builder but falls back to local on failure. `BuilderOnly` never falls back — if builder fails, the proposal fails (with ERROR log). `BuilderOnly` interacts critically with the circuit breaker.

**Implementation Notes:**
- `BuilderAlways`: set `builder_boost_factor=u64::MAX` to strongly prefer builder; if builder fails, fall back to local
- `BuilderOnly`: if circuit breaker is tripped, log ERROR and skip proposal (don't fall back to local); if builder returns empty/error, fail the proposal
- Critical interaction: `BuilderOnly` + circuit breaker tripped = missed proposal (this is by design for DVT where all cluster members must propose the same block)
- Log at ERROR when `BuilderOnly` proposal fails

**Acceptance Criteria:**
- [ ] `BuilderAlways` uses builder when available, local as fallback
- [ ] `BuilderOnly` never falls back to local
- [ ] `BuilderOnly` + circuit breaker tripped = missed proposal with ERROR log
- [ ] `BuilderOnly` + builder error = missed proposal with ERROR log

**Testing Requirements:**
- [ ] Unit test: BuilderAlways falls back on builder failure
- [ ] Unit test: BuilderOnly fails on builder failure
- [ ] Unit test: BuilderOnly + circuit breaker = missed proposal

---

### Issue T4.4: Block selection — per-validator config and CLI

**Feature:** FR-10 Multi-Strategy Block Selection
**Story Points:** 2
**Priority:** P1
**Depends On:** T4.1
**Blocks:** T4.16
**Files Modified:**
- `crates/validator-store/src/store.rs` — add `block_selection_mode: Option<BlockSelectionMode>` per validator
- `crates/validator-store/src/config.rs` — TOML field
- `crates/rvc/src/config/types.rs` — global `block_selection_mode` CLI flag
- `crates/metrics/src/definitions.rs` — `rvc_block_selection_mode` gauge

**Description:**
Add per-validator and global configuration for block selection mode. Per-validator overrides global. The block service reads the effective mode from the validator store when producing a block.

**Implementation Notes:**
- `ValidatorConfig` gets `block_selection_mode: Option<BlockSelectionMode>`
- `ValidatorStore::effective_block_selection_mode(pubkey)` returns per-validator if set, else global
- Global CLI: `--block-selection-mode maxprofit` (default)
- Per-validator TOML: `block_selection_mode = "builderonly"`

**Acceptance Criteria:**
- [ ] Global CLI flag sets default mode
- [ ] Per-validator TOML overrides global
- [ ] `effective_block_selection_mode()` returns correct priority
- [ ] Metric labels per mode

**Testing Requirements:**
- [ ] Config parsing: global and per-validator
- [ ] Priority resolution test

---

### Issue T4.5: Health tier types and threshold configuration

**Feature:** FR-14 Health-Based BN Tier Selection
**Story Points:** 2
**Priority:** P2
**Depends On:** None
**Blocks:** T4.6, T4.8
**Files Modified:**
- `crates/bn-manager/src/sync_status.rs` — extend `BnSyncStatus` with `sync_distance` and `head_slot` fields
- `crates/bn-manager/src/types.rs` — new file or extend: `HealthTier`, `TierThresholds`

**Description:**
Define the 4-tier health model and configurable thresholds. Extend `BnSyncStatus` to store sync distance for tier calculation.

**Implementation Notes:**
- `HealthTier`: `Synced`, `SmallLag`, `LargeLag`, `Unsynced` (architecture doc has the enum)
- `TierThresholds`: configurable widths (default: synced=8, small=8, large=48)
- Extend `BnSyncStatus` with `sync_distance: Option<u64>`, `head_slot: Option<u64>` — these are already parsed in `check_single_sync_status()` but only used for logging
- Add `tier(&self, thresholds: &TierThresholds) -> HealthTier` method to `BnSyncStatus`

**Acceptance Criteria:**
- [ ] 4-tier enum defined with correct ordering
- [ ] Threshold config with defaults matching Lighthouse (8,8,48)
- [ ] `BnSyncStatus` stores sync distance
- [ ] `tier()` method computes correct tier from distance and thresholds

**Testing Requirements:**
- [ ] Unit test: tier computation for each boundary value
- [ ] Unit test: custom thresholds

---

### Issue T4.6: Health tier — synced_indices refactor

**Feature:** FR-14 Health-Based BN Tier Selection
**Story Points:** 3
**Priority:** P2
**Depends On:** T4.5
**Blocks:** T4.7, T4.9
**Files Modified:**
- `crates/bn-manager/src/manager.rs` — refactor `synced_indices()` to filter by tier instead of binary synced/not-synced

**Description:**
Replace the binary `is_usable()` check in `synced_indices()` with tier-based filtering. The method now accepts a minimum tier requirement and returns indices of BNs meeting that tier.

**Implementation Notes:**
- Current `synced_indices()` (~line 222-287) checks `is_usable()` (binary)
- New: `synced_indices(min_tier: HealthTier)` — returns indices where BN tier >= min_tier
- Within same tier: preserve user-specified ordering (current behavior)
- EL offline detection: treat as `Unsynced` tier
- Optimistic sync: deprioritize within same tier
- Backwards compatible: existing callers pass `HealthTier::Synced` for current behavior

**Acceptance Criteria:**
- [ ] `synced_indices(Synced)` returns only fully-synced BNs
- [ ] `synced_indices(SmallLag)` returns Synced + SmallLag BNs
- [ ] User ordering preserved within same tier
- [ ] EL offline BNs classified as Unsynced
- [ ] Existing behavior unchanged for default callers

**Testing Requirements:**
- [ ] Unit test: tier-based filtering with multiple BNs at different tiers
- [ ] Unit test: ordering within same tier
- [ ] Unit test: EL offline handling

---

### Issue T4.7: Health tier — duty-aware routing

**Feature:** FR-14 Health-Based BN Tier Selection
**Story Points:** 2
**Priority:** P2
**Depends On:** T4.6
**Blocks:** T4.16
**Files Modified:**
- `crates/bn-manager/src/manager.rs` — duty methods call `synced_indices()` with appropriate tier requirement

**Description:**
Wire tier requirements into duty-specific BnManager methods. Proposals require Synced tier, attestations accept SmallLag, submissions accept LargeLag.

**Implementation Notes:**
- Proposals (`produce_block_v3`, `publish_block`): `synced_indices(HealthTier::Synced)`
- Attestation data, sync committee: `synced_indices(HealthTier::SmallLag)`
- Submissions (attestation submit, block publish): `synced_indices(HealthTier::LargeLag)`
- If no BNs at required tier, fall back to next lower tier with WARN log
- Per-slot health checks already exist; tier computation is just additional classification

**Acceptance Criteria:**
- [ ] Proposals use Synced-tier BNs only (fallback with WARN if none)
- [ ] Attestations use Synced + SmallLag BNs
- [ ] Submissions use Synced + SmallLag + LargeLag BNs
- [ ] Tier fallback logged at WARN

**Testing Requirements:**
- [ ] Unit test: proposal routing with mixed-tier BNs
- [ ] Unit test: attestation routing accepts SmallLag
- [ ] Unit test: fallback to lower tier with warning

---

### Issue T4.8: Health tier — CLI flags and metrics

**Feature:** FR-14 Health-Based BN Tier Selection
**Story Points:** 1
**Priority:** P2
**Depends On:** T4.5
**Blocks:** T4.16
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add tier threshold config
- `crates/metrics/src/definitions.rs` — add `rvc_bn_health_tier` gauge per BN

**Description:**
Add CLI flag for tier thresholds and per-BN tier metrics.

**Implementation Notes:**
- `--bn-sync-tolerances 8,8,48` (matching Lighthouse format)
- TOML: `bn_sync_tolerances = [8, 8, 48]`
- `rvc_bn_health_tier` gauge with BN endpoint label: value 1-4

**Acceptance Criteria:**
- [ ] CLI flag parses three comma-separated values
- [ ] Per-BN tier metric updates on health check
- [ ] Default tolerances: 8,8,48

**Testing Requirements:**
- [ ] Config parsing test
- [ ] Metric update test

---

### Issue T4.9: Role-based BN — role enum and per-BN annotation

**Feature:** FR-11 Role-Based BN Assignment
**Story Points:** 2
**Priority:** P2
**Depends On:** T4.6 (synced_indices refactor)
**Blocks:** T4.10, T4.11
**Files Modified:**
- `crates/bn-manager/src/traits.rs` — add `BnRole` enum
- `crates/bn-manager/src/manager.rs` — add `roles: Vec<HashSet<BnRole>>` parallel to `clients`

**Description:**
Define the role enum and add per-BN role annotations to `BnManager`. Each BN has a set of roles; default is `{All}`.

**Implementation Notes:**
- `BnRole` enum: `Attestation`, `Proposal`, `SyncCommittee`, `Aggregation`, `Submission`, `All` (architecture doc has the type)
- `BnManager` gets `roles: Vec<HashSet<BnRole>>` (one set per client, parallel to `clients`)
- Default: `{All}` for each BN (backwards compatible)
- `All` expands to all other roles
- Parsed from config during `BnManager::new()`

**Acceptance Criteria:**
- [ ] Role enum with 6 variants defined
- [ ] Each BN annotated with role set in BnManager
- [ ] Default role is `{All}` (backwards compatible)
- [ ] `All` expands to all concrete roles

**Testing Requirements:**
- [ ] Role set construction from config
- [ ] Default role expansion

---

### Issue T4.10: Role-based BN — role-aware filtering in synced_indices

**Feature:** FR-11 Role-Based BN Assignment
**Story Points:** 3
**Priority:** P2
**Depends On:** T4.9
**Blocks:** T4.16
**Files Modified:**
- `crates/bn-manager/src/manager.rs` — `synced_indices()` filters by role, then by tier

**Description:**
Extend `synced_indices()` to accept a role parameter. First filter by role, then by tier. This composes with the health tier work from T4.6.

**Implementation Notes:**
- `synced_indices(role: BnRole, min_tier: HealthTier)` — filter by role first, then tier
- Cross-role fallback as last resort: if no BNs for the requested role, fall back to `All` BNs with WARN
- FR-5 (Proposer Nodes) becomes a config shorthand: a proposer node is a BN with `roles = ["proposal"]`
- Within same role+tier, user ordering is tie-breaker

**Acceptance Criteria:**
- [ ] BNs with `proposal` role only receive block production requests
- [ ] BNs with `attestation` role only receive attestation requests
- [ ] If all BNs for a role are down, cross-role fallback occurs with WARN
- [ ] Default config (`All` role) behaves identically to current implementation

**Testing Requirements:**
- [ ] Unit test: role-based filtering
- [ ] Unit test: cross-role fallback
- [ ] Unit test: role + tier composition

---

### Issue T4.11: Role-based BN — TOML config and CLI

**Feature:** FR-11 Role-Based BN Assignment
**Story Points:** 1
**Priority:** P2
**Depends On:** T4.9
**Blocks:** T4.16
**Files Modified:**
- `crates/rvc/src/config/types.rs` — TOML config for `[[beacon_nodes]]` with `roles` field

**Description:**
Add TOML config format for per-BN role assignment.

**Implementation Notes:**
- TOML format: `[[beacon_nodes]]` table with `url` and `roles` fields
- `roles` is an array of strings: `["attestation", "sync-committee"]`
- Default: `["all"]`
- Invalid role names → startup error
- Log at INFO which roles are assigned to which BNs

**Acceptance Criteria:**
- [ ] TOML config parsed correctly
- [ ] Invalid roles → startup error
- [ ] Default roles = ["all"]
- [ ] INFO log showing BN-role assignments

**Testing Requirements:**
- [ ] Config parsing: valid roles
- [ ] Config parsing: invalid roles → error

---

### Issue T4.12: Registration batching — chunked submission

**Feature:** FR-12 Validator Registration Batching
**Story Points:** 2
**Priority:** P1
**Depends On:** None
**Blocks:** T4.13, T4.16
**Files Modified:**
- `crates/builder/src/service.rs` — chunk `register_validators()` into batches

**Description:**
Split the single `register_validators()` call into batches. Currently it collects all registrations and submits in one request. Add chunking with configurable batch size and delay.

**Implementation Notes:**
- Current: single `self.bn.register_validators(&registrations)` call (~line 139-157)
- New: `registrations.chunks(batch_size)` → sequential submission
- Delay between batches: configurable (default 500ms)
- On batch failure: log WARN, continue with remaining batches (don't abort)
- Batch size 0 = send all at once (current behavior)
- Registration failures should NOT mark a BN as offline (following Lighthouse PR #3488)

**Acceptance Criteria:**
- [ ] 2,000 validators with batch size 500 → 4 sequential requests
- [ ] Failed batch doesn't prevent remaining batches
- [ ] Delay between batches configurable
- [ ] Batch size 0 → current behavior (single request)

**Testing Requirements:**
- [ ] Unit test: chunking produces correct batch count
- [ ] Unit test: batch failure doesn't abort remaining
- [ ] Unit test: delay applied between batches

---

### Issue T4.13: Registration batching — CLI flags and metrics

**Feature:** FR-12 Validator Registration Batching
**Story Points:** 1
**Priority:** P1
**Depends On:** T4.12
**Blocks:** T4.16
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `validator_registration_batch_size`, `validator_registration_batch_delay_ms`
- `crates/metrics/src/definitions.rs` — add `rvc_builder_registration_batches_total`, `rvc_builder_registration_batches_failed`

**Description:**
Add CLI flags, config, and metrics for registration batching.

**Implementation Notes:**
- `--validator-registration-batch-size <N>` (default: 500)
- `--validator-registration-batch-delay <ms>` (default: 500)
- Metrics: total batches sent, failed batches

**Acceptance Criteria:**
- [ ] CLI flags parse correctly
- [ ] Default batch size is 500
- [ ] Metrics track batch success/failure

**Testing Requirements:**
- [ ] Config parsing test

---

### Issue T4.14: Pre-signed exits — prepare-exit command and API

**Feature:** FR-13 Pre-Signed Voluntary Exit Storage
**Story Points:** 3
**Priority:** P2
**Depends On:** None
**Blocks:** T4.15, T4.16
**Files Modified:**
- `crates/rvc/src/prepare_exit.rs` — new file: CLI subcommand + API handler
- `crates/keymanager-api/src/handlers.rs` — add `POST /rvc/v1/validator/{pubkey}/prepare_exit` handler
- `crates/keymanager-api/src/server.rs` — register route

**Description:**
Implement the `prepare-exit` CLI subcommand and API endpoint. Signs a voluntary exit for a validator and returns/stores the `SignedVoluntaryExit` JSON without submitting it to the beacon node.

**Implementation Notes:**
- CLI: `rvc prepare-exit --pubkey <pubkey> --output <dir>`
- API: `POST /rvc/v1/validator/{pubkey}/prepare_exit` returns `SignedVoluntaryExit` JSON
- Uses existing signing logic from `VoluntaryExitManagerAdapter` — extract the signing portion
- EIP-7044: domain fixed to `CAPELLA_FORK_VERSION` → exits valid forever
- File name: `<pubkey>_exit.json`
- File permissions: `0o600`
- BN endpoint required at sign-time (to get validator index and network params)
- The API endpoint does NOT submit the exit

**Acceptance Criteria:**
- [ ] CLI produces valid `SignedVoluntaryExit` JSON file
- [ ] API returns `SignedVoluntaryExit` without submitting
- [ ] Exit uses Capella domain (EIP-7044)
- [ ] File permissions are 0o600
- [ ] Valid JSON matching Beacon API schema

**Testing Requirements:**
- [ ] Unit test: exit message signed with correct domain
- [ ] Unit test: JSON output matches schema
- [ ] Test: file created with correct permissions

---

### Issue T4.15: Pre-signed exits — submit-exit command

**Feature:** FR-13 Pre-Signed Voluntary Exit Storage
**Story Points:** 2
**Priority:** P2
**Depends On:** T4.14
**Blocks:** T4.16
**Files Modified:**
- `crates/rvc/src/submit_exit.rs` — new file: `submit-exit` CLI subcommand

**Description:**
Implement the `submit-exit` CLI subcommand that reads a stored `SignedVoluntaryExit` JSON file and submits it to the beacon node. Does NOT require signing keys.

**Implementation Notes:**
- CLI: `rvc submit-exit --file <path> --beacon-node <URL>`
- Read JSON file, deserialize `SignedVoluntaryExit`
- POST to `<beacon-node>/eth/v1/beacon/pool/voluntary_exits`
- Any BN can accept the submission (standard Beacon API)
- Report success/failure to stdout
- No signing keys needed — only the stored exit file and a BN endpoint

**Acceptance Criteria:**
- [ ] Reads stored exit file and submits to BN
- [ ] Works without signing keys
- [ ] Reports success/failure clearly
- [ ] Accepts any beacon node URL

**Testing Requirements:**
- [ ] Unit test: deserialize stored exit
- [ ] Integration test: mock BN accepts submission

---

### Issue T4.16: Tier 4 integration tests

**Feature:** All Tier 4 features (FR-10 through FR-14)
**Story Points:** 6
**Priority:** P1
**Depends On:** T4.3, T4.7, T4.10, T4.13, T4.15
**Blocks:** None
**Files Modified:**
- `tests/tier4_advanced.rs` — new integration test file

**Description:**
End-to-end integration tests for all five Tier 4 advanced features.

**Implementation Notes:**
- Block selection: test each mode with mock BN/builder
- Health tiers: test duty routing with BNs at different sync distances
- Role-based BN: test role filtering + tier composition
- Registration batching: test with large validator set
- Pre-signed exits: full prepare → store → submit lifecycle
- Composition: block selection + circuit breaker + health tiers

**Acceptance Criteria:**
- [ ] All 4 block selection modes route correctly
- [ ] Health tiers affect duty routing appropriately
- [ ] Role-based filtering composes with tier selection
- [ ] Registration batching handles 2000+ validators
- [ ] Pre-signed exit lifecycle works end-to-end
- [ ] All features compose without interference

**Testing Requirements:**
- [ ] Full integration test suite for all Tier 4 features
- [ ] Cross-feature composition tests
