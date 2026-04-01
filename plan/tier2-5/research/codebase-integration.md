# Research: Codebase Integration Map — Tiers 2–5

## Summary

This document maps each of the 18 Tier 2–5 features to the specific rvc crates, files, and methods that need modification. The goal is to provide the architecture and project planning phases with precise integration points, shared infrastructure opportunities, and dependency ordering.

## Codebase Architecture Recap

rvc follows a 4-layer crate architecture:

```
Binary Layer        → crates/rvc/          (orchestrator, config, startup, keymanager adapters)
Orchestrator Layer  → crates/rvc/src/orchestrator/  (coordinator, attestation, aggregation, sync_committee, duty_management)
Domain Layer        → crates/builder/      (BuilderService, validator registration)
                      crates/block-service/ (BlockService, block proposal lifecycle)
                      crates/signer/       (SignerService, slashing-protected signing)
                      crates/bn-manager/   (BnManager, health, sync status, broadcast, SSE)
                      crates/validator-store/ (ValidatorStore, per-validator config, TOML persistence)
                      crates/keymanager-api/ (Axum server, handlers, traits, auth)
Foundation Layer    → crates/crypto/       (BLS, CompositeSigner)
                      crates/slashing/     (SlashingDb, EIP-3076)
                      crates/telemetry/    (OpenTelemetry, tracing init)
                      crates/timing/       (SlotClock)
                      crates/eth-types/    (SSZ types, fork types, domains)
                      crates/metrics/      (Prometheus definitions)
```

## Feature Integration Map

---

### FR-1: Builder Circuit Breakers [Tier 2]

**Primary crate:** `crates/builder/src/service.rs`
**Secondary:** `crates/rvc/src/orchestrator/coordinator.rs`, `crates/block-service/src/service.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/builder/src/service.rs` | Add `CircuitBreakerState` struct with `AtomicU32` counters for consecutive misses and epoch misses. Add `is_circuit_broken()` method. |
| `crates/builder/src/lib.rs` | Export `CircuitBreakerState` |
| `crates/block-service/src/service.rs:55-100` | `propose_block()` currently calls `produce_block_v3()` with `builder_boost_factor`. Add a check: if circuit breaker is tripped, pass `builder_boost_factor=0` (or skip builder entirely). |
| `crates/rvc/src/orchestrator/coordinator.rs:307-311` | `maybe_propose_block()` — after block proposal result, call `circuit_breaker.record_miss()` or `circuit_breaker.record_success()` |
| `crates/rvc/src/orchestrator/coordinator.rs:274` | At epoch boundary, call `circuit_breaker.reset()` |
| `crates/rvc/src/config/types.rs` | Add `builder_circuit_breaker_consecutive_limit: u32` and `builder_circuit_breaker_epoch_limit: u32` to `Config` |
| `crates/metrics/src/definitions.rs` | Add `rvc_builder_circuit_breaker_trips_total`, `rvc_builder_consecutive_misses`, `rvc_builder_epoch_misses` |

**Key design note:** The `CircuitBreakerState` should use atomics (`AtomicU32`) since it's checked in the hot block-production path and the PRD requires <1μs overhead (NFR-1). It should be injected into `BlockService` or passed as a shared `Arc<CircuitBreakerState>` from the orchestrator.

**Current block production flow:**
```
DutyOrchestrator::maybe_propose_block()
  → BlockService::propose_block() [block-service/src/service.rs:55]
    → beacon.produce_block_v3(slot, randao, graffiti, builder_boost_factor)
    → signer.sign_block()
    → beacon.publish_block() or publish_blinded_block()
```

The circuit breaker intercepts at the `produce_block_v3` call — either by zeroing `builder_boost_factor` or by introducing a pre-check.

---

### FR-2: Emergency Attestation Disable [Tier 2]

**Primary crate:** `crates/rvc/src/orchestrator/coordinator.rs`
**Secondary:** `crates/keymanager-api/src/server.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/rvc/src/orchestrator/coordinator.rs:94-112` | Add `attesting_enabled: Arc<AtomicBool>` field to `DutyOrchestrator` |
| `crates/rvc/src/orchestrator/coordinator.rs:362-383` | Before `attestation_service.process_slot()`, check `attesting_enabled.load(Ordering::Relaxed)`. If false, skip. |
| `crates/rvc/src/orchestrator/coordinator.rs:385-388` | Before `sync_committee_service.maybe_produce_sync_messages()`, same check. |
| `crates/rvc/src/orchestrator/coordinator.rs:429+` | Before aggregation duties, same check. |
| `crates/keymanager-api/src/server.rs` | Add `POST /rvc/v1/attesting` route with `Arc<AtomicBool>` in `AppState` |
| `crates/keymanager-api/src/handlers.rs` | Add handler `set_attesting_enabled()` — toggles the `AtomicBool` |
| `crates/rvc/src/config/types.rs` | Add `disable_attesting: bool` to `Config` |
| `crates/metrics/src/definitions.rs` | Add `rvc_attesting_enabled` gauge |

**Key design note:** `Arc<AtomicBool>` is the correct primitive. The orchestrator already uses `watch::Receiver<bool>` for shutdown; attesting disable follows the same pattern but uses `AtomicBool` for lower overhead since it's checked every slot. The `AtomicBool` is shared between the orchestrator and the Keymanager API server.

**Current attestation flow:**
```
DutyOrchestrator::run() [coordinator.rs:362]
  → attestation_service.process_slot(current_slot)
    → utils::get_duties_for_slot()
    → for each duty: sign_attestation(), propagator.submit()
```

The disable check is a single `if !attesting_enabled.load(Relaxed)` before the `process_slot` call.

---

### FR-3: Slashed Validator Auto-Shutdown [Tier 2]

**Primary crate:** `crates/rvc/src/orchestrator/coordinator.rs`
**Secondary:** `crates/validator-store/src/store.rs`, `crates/bn-manager/`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/rvc/src/orchestrator/coordinator.rs:274-305` | Add a periodic slashing check at epoch boundary (alongside duty fetch). Call `beacon.get_validators()` for managed pubkeys, check `status` field. |
| `crates/validator-store/src/store.rs:182-192` | `set_enabled()` already exists and is the correct method to disable slashed validators. |
| `crates/rvc/src/orchestrator/coordinator.rs:94-112` | Add `slashed_action: SlashedAction` enum field (`DisableOnly`, `Shutdown`, `None`) |
| `crates/rvc/src/config/types.rs` | Add `slashed_validators_action: String` to `Config` |
| `crates/metrics/src/definitions.rs` | Add `rvc_validators_slashed_total` counter |
| `crates/bn-manager/src/traits.rs:33` | `get_validators()` already exists in `BeaconNodeClient` trait — returns `ValidatorsResponse` |

**Key design note:** The existing `ValidatorStore.set_enabled(pubkey, false)` already disables a validator from producing duties. The `list_enabled_pubkeys()` method filters out disabled validators, so all duty paths automatically exclude them. The slashing check is a background task that runs once per epoch.

**Validator status check flow:**
```
Every epoch boundary:
  → beacon.get_validators(managed_pubkeys)
  → for each response: check if status contains "slashed"
  → if slashed: validator_store.set_enabled(pubkey, false)
  → if shutdown mode: orchestrator_handle.shutdown()
```

---

### FR-4: Keystore File Locking [Tier 2]

**Primary crate:** `crates/rvc/src/startup.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/rvc/src/startup.rs` | Add `acquire_keystore_locks()` function, called after `check_integrity()` but before validator activation. Creates `.rvc.lock` file and acquires `flock()`. |
| `crates/rvc/src/startup.rs:16-20` | Add `EXIT_KEYSTORE_LOCKED: i32 = 14` exit code |
| `crates/rvc/src/config/types.rs` | Add `disable_keystore_locking: bool` to `Config` |
| `Cargo.toml` (rvc crate) | Add `fs2` (or `fd-lock`) dependency |

**Key design note:** The startup sequence in `startup.rs` is well-structured with distinct phases. Locking fits naturally after integrity check (step 2) and before genesis validation (step 3). The lock file should be `<keystore_path>/.rvc.lock`. On Unix, `flock()` advisory locks are automatically released on process crash, which is exactly the behavior needed.

**Current startup sequence:**
```
1. Open slashing DB
2. Run integrity check           ← keystore locking fits after here
3. Validate genesis root
4. Check beacon node reachability
5. Run doppelganger detection
```

---

### FR-5: Dedicated Proposer Nodes [Tier 3]

**Primary crate:** `crates/bn-manager/src/manager.rs`
**Secondary:** `crates/rvc/src/orchestrator/coordinator.rs`, `crates/block-service/`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/bn-manager/src/manager.rs` | Create a second `BnManager` instance for proposer nodes (reuses exact same struct, different endpoints). Or add `proposer_clients: Option<Vec<BeaconClient>>` field. |
| `crates/bn-manager/src/traits.rs:53-60` | `produce_block_v3()`, `publish_block()`, `publish_blinded_block()` — these are the methods that should route through proposer nodes. |
| `crates/rvc/src/orchestrator/coordinator.rs:100-112` | Add `proposer_beacon: Option<Arc<dyn BeaconNodeClient>>` to `DutyOrchestrator`. Pass to `BlockService` instead of the main beacon. |
| `crates/block-service/src/service.rs:34-42` | `BlockService::new()` already takes a separate `beacon: Arc<B>`. Just pass the proposer BnManager when available. |
| `crates/rvc/src/config/types.rs` | Add `proposer_nodes: Vec<String>` to `Config` |

**Key design note:** The current architecture already separates `beacon` (general BN) from `block_beacon` (block-producing BN) in the orchestrator constructor (`coordinator.rs:128`). This separation is ideal — the proposer nodes feature simply provides a different `BnManager` instance as `block_beacon`. This is the cleanest integration point in the entire feature set.

---

### FR-6: Configurable Broadcast Topics [Tier 3]

**Primary crate:** `crates/bn-manager/src/manager.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/bn-manager/src/manager.rs` | Add `broadcast_topics: BroadcastTopics` field (a bitfield or HashSet). In each `broadcast_*()` method, check if the topic is in the set. If not, use `query_first()` instead. |
| `crates/bn-manager/src/broadcast.rs` | The `BroadcastResult` type stays the same. The routing decision happens in the manager. |
| `crates/bn-manager/src/traits.rs` | The `BeaconNodeClient` trait methods (`submit_attestation`, `publish_block`, etc.) don't change — the BnManager decides whether to broadcast or first-strategy. |
| `crates/rvc/src/config/types.rs` | Add `broadcast: Vec<String>` to `Config` |

**Key design note:** The current BnManager has two strategies visible to callers: `query_first()` and `broadcast_to_all()`. Configurable topics would add a decision layer: `submit_attestation()` checks if `attestations` is in the broadcast set; if yes, use broadcast; if no, use first. This is a config-driven branch in each submission method.

**Current submission methods in BnManager that would be affected:**
- `submit_attestation()` — topic: `attestations`
- `publish_block()` / `publish_blinded_block()` — topic: `blocks`
- `submit_sync_committee_messages()` — topic: `sync-committee`
- `submit_beacon_committee_subscriptions()` — topic: `subscriptions`

---

### FR-7: Remote Monitoring Endpoint [Tier 3]

**Primary crate:** new module in `crates/rvc/src/` (e.g., `monitoring.rs`)

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/rvc/src/monitoring.rs` (new) | Background task that periodically POSTs metrics to beaconcha.in-compatible endpoint. Uses `reqwest` (already in deps). |
| `crates/rvc/src/orchestrator/coordinator.rs` | Needs to expose duty performance data (attestation results, proposal results) to the monitoring module. Could use a `watch::Sender<MonitoringData>` or `Arc<Mutex<MonitoringState>>`. |
| `crates/rvc/src/config/types.rs` | Add `monitoring_endpoint: Option<String>`, `monitoring_interval: Option<u64>` |
| `crates/metrics/src/definitions.rs` | Monitoring push success/failure counters |

**Key design note:** This is a fully independent background task that reads from existing metrics and validator state. It should NOT modify any duty execution path. The main integration challenge is collecting duty performance data (attestation effectiveness, proposal history) from the orchestrator into a format the monitoring endpoint expects.

---

### FR-8: Log File Rotation & Compression [Tier 3]

**Primary crate:** `crates/telemetry/src/init.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/telemetry/src/init.rs:27-53` | `init_tracing()` currently returns only an OpenTelemetry layer. Extend to optionally return a file appender layer as well. |
| `crates/telemetry/src/config.rs` | Add `logfile: Option<PathBuf>`, `logfile_max_size_mb: u64`, `logfile_max_number: usize`, `logfile_compress: bool`, `logfile_level: Option<String>` to `TelemetryConfig`. |
| `crates/telemetry/Cargo.toml` | Add `tracing-appender` dependency. For size-based rotation (not supported by `tracing-appender` natively), may need a custom implementation or `tracing-rolling-file`. For gzip, add `flate2`. |

**Key design note:** `tracing-appender` only supports time-based rotation (hourly/daily/minutely/never), NOT size-based. The PRD requires size-based rotation. Options:
1. Use `tracing-appender::non_blocking` for the writer but implement custom size-based rotation logic
2. Use a crate like `tracing-rolling-file` that supports size-based rotation
3. Implement a custom `MakeWriter` that rotates on size threshold

The telemetry crate currently has a clean initialization pattern (`init_tracing()` returns a layer + guard). The file appender would be composed as an additional layer in the subscriber stack using `tracing_subscriber::Layer::with_filter()`.

---

### FR-9: Proposer Config from URL [Tier 3]

**Primary crate:** `crates/validator-store/src/store.rs`
**Secondary:** `crates/rvc/src/` (background task)

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/validator-store/src/store.rs:194-236` | `update_config()` already exists and handles per-validator config updates atomically. URL-fetched config flows through this method. |
| `crates/rvc/src/config_url.rs` (new) | Background task: fetch URL → parse JSON → for each validator, call `validator_store.update_config()`. Runs every epoch. |
| `crates/rvc/src/config/types.rs` | Add `proposer_config_url: Option<String>`, `proposer_config_refresh_interval: Option<u64>`, `proposer_config_url_token: Option<String>` |

**Key design note:** The `ValidatorStore.update_config()` method already handles partial updates via `ValidatorConfigUpdate` (fee_recipient, gas_limit, graffiti, builder_proposals, builder_boost_factor — all optional). The URL fetcher just needs to parse the Prysm/Teku JSON schema into `ValidatorConfigUpdate` structs and call `update_config()` for each validator.

**Mutual exclusivity check:** At startup, validate that `proposer_config_url` and the existing TOML `proposer_config_file` path (via `validator-store` crate) are not both set.

---

### FR-10: Multi-Strategy Block Selection [Tier 4]

**Primary crate:** `crates/block-service/src/service.rs`
**Secondary:** `crates/builder/`, `crates/validator-store/`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/block-service/src/service.rs:55-100` | `propose_block()` currently always calls `produce_block_v3()` which lets the BN decide between builder and local. New strategies need to override this: `executiononly` sets `builder_boost_factor=0`, `builderonly` needs builder-specific error handling, `maxprofit` and `builderalways` need comparative logic. |
| `crates/block-service/src/traits.rs:14-21` | `BeaconBlockClient` trait may need a separate `produce_builder_block()` method for `maxprofit` (request both concurrently). |
| `crates/validator-store/src/store.rs` | Add `block_selection_mode: Option<BlockSelectionMode>` per validator. Add `effective_block_selection_mode()` method. |
| `crates/validator-store/src/config.rs` | Add `block_selection_mode` field to `ValidatorConfig` and TOML parsing. |
| `crates/rvc/src/config/types.rs` | Add global `block_selection_mode: String` to `Config` |

**Key design note:** The current `produce_block_v3()` API uses `builder_boost_factor` to influence the BN's builder/local decision. For `executiononly`, setting `builder_boost_factor=0` suffices. For `builderonly`, the client needs to explicitly fail if the returned block is not blinded (indicating builder block). For `maxprofit`, the BN already handles this if `builder_boost_factor` is set high. The main implementation work is in `BlockService.propose_block()` which needs a match on the selection mode.

**Interaction with FR-1 (Circuit Breakers):** When `builderonly` mode is active and the circuit breaker trips, the proposal must fail (log ERROR). This is a critical interaction that needs careful testing.

---

### FR-11: Role-Based BN Assignment [Tier 4]

**Primary crate:** `crates/bn-manager/src/manager.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/bn-manager/src/manager.rs:51-56` | `BnManager` struct needs per-BN role annotations. Add `roles: Vec<Vec<BnRole>>` parallel to `clients`. |
| `crates/bn-manager/src/manager.rs:222-287` | `synced_indices()` needs a `role: BnRole` parameter to filter by assigned role. |
| `crates/bn-manager/src/manager.rs:290+` | `query_first()` and `broadcast_to_all()` need role-aware index selection. |
| `crates/bn-manager/src/traits.rs` | Add `BnRole` enum: `Attestation`, `Proposal`, `SyncCommittee`, `Aggregation`, `Submission`, `All` |
| `crates/rvc/src/config/types.rs` | TOML config for BN roles |

**Key design note:** This feature and FR-5 (Dedicated Proposer Nodes) overlap significantly. FR-5 is the simpler case (proposal-only nodes) while FR-11 generalizes to all duty types. Implementation strategy: implement FR-5 first as a separate BnManager instance, then FR-11 subsumes it by adding role filtering to the main BnManager. Alternatively, implement FR-11 directly and FR-5 becomes a config shorthand.

**Shared infrastructure with FR-14 (Health-Based BN Tiers):** Both FR-11 and FR-14 modify `synced_indices()` to add filtering criteria. They should be designed together to avoid conflicting refactors.

---

### FR-12: Validator Registration Batching [Tier 4]

**Primary crate:** `crates/builder/src/service.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/builder/src/service.rs:56-174` | `register_validators()` currently collects all registrations and submits in one batch (`self.bn.register_validators(&registrations)`). Change to chunk into batches of `batch_size` and submit sequentially with configurable delay. |
| `crates/builder/src/service.rs:139-157` | The single `self.bn.register_validators(&registrations)` call becomes a loop over chunks. |
| `crates/rvc/src/config/types.rs` | Add `validator_registration_batch_size: usize`, `validator_registration_batch_delay_ms: u64` |
| `crates/metrics/src/definitions.rs` | Add `rvc_builder_registration_batches_total`, `rvc_builder_registration_batches_failed` |

**Key design note:** This is a straightforward change. The current `register_validators()` already collects all registrations into a `Vec`. Simply add `.chunks(batch_size)` and iterate. The existing cache mechanism (checking if config changed before re-signing) already reduces the number of registrations per call, so batching primarily helps the initial registration or after config changes affecting many validators.

---

### FR-13: Pre-Signed Voluntary Exit Storage [Tier 4]

**Primary crate:** `crates/rvc/` (CLI commands)
**Secondary:** `crates/keymanager-api/`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/rvc/src/` (new module) | `prepare_exit` CLI subcommand: sign voluntary exit, serialize to JSON file. |
| `crates/rvc/src/` (new module) | `submit_exit` CLI subcommand: read JSON file, POST to beacon node. |
| `crates/keymanager-api/src/server.rs` | Add `POST /rvc/v1/validator/{pubkey}/prepare_exit` route |
| `crates/keymanager-api/src/handlers.rs` | Handler returns `SignedVoluntaryExit` JSON without submitting |
| `crates/keymanager-api/src/traits.rs` | `VoluntaryExitManager` trait already exists (line ~80+). May need a `prepare_exit()` method that returns the signed exit without submitting. |
| `crates/rvc/src/keymanager_adapters.rs` | Adapt the existing `VoluntaryExitManager` implementation. The current `VoluntaryExitManagerAdapter` already has signing logic — extract the signing portion for prepare-exit. |

**Key design note:** EIP-7044 (activated at Capella) makes voluntary exit signatures perpetually valid — the domain is fixed to the Capella fork version regardless of the current fork. This means a signed exit today is valid indefinitely. The signing logic in `keymanager_adapters.rs` already handles domain computation. The `prepare-exit` command just needs to serialize the `SignedVoluntaryExit` to JSON instead of submitting it.

---

### FR-14: Health-Based BN Tier Selection [Tier 4]

**Primary crate:** `crates/bn-manager/src/sync_status.rs`
**Secondary:** `crates/bn-manager/src/manager.rs`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/bn-manager/src/sync_status.rs:12-23` | Replace `BnSyncStatus` enum with a tier-aware version. Current: `Unknown`, `Synced`, `Syncing`, `ElOffline`, `Unreachable`. New: add `head_slot: Option<u64>` and `sync_distance: Option<u64>` to enable tier calculation. |
| `crates/bn-manager/src/sync_status.rs:46-80` | `check_all_sync_statuses()` already extracts `head_slot` and `sync_distance` from the syncing response. Currently these are only used for logging. Store them in the status for tier computation. |
| `crates/bn-manager/src/manager.rs:222-287` | `synced_indices()` currently checks `is_usable()` (binary). Replace with tier-based filtering: accept a `min_tier: BnTier` parameter. Proposals require Tier 1, attestations Tier 1+2, submissions Tier 1+2+3. |
| `crates/bn-manager/src/health.rs` | May need to incorporate tier into the composite health score. |
| `crates/metrics/src/definitions.rs` | Add `rvc_bn_health_tier` gauge per BN |

**Key design note:** The current `BnSyncStatus` enum is the right abstraction to extend. The `check_single_sync_status()` function already parses `head_slot` and `sync_distance` from the BN's `/eth/v1/node/syncing` response. The tier thresholds (1 slot, 16 slots, 64 slots) would be configurable in `BnManagerConfig`.

**Shared infrastructure with FR-11 (Role-Based BN):** Both features filter `synced_indices()`. Design them to compose: first filter by role, then filter by tier eligibility for the duty type.

---

### FR-15: Verifying Web3Signer [Tier 5]

**Primary crate:** `crates/signer/src/lib.rs` (rvc-signer binary)
**Secondary:** `crates/eth-types/`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/signer/src/lib.rs` | The `SignerService` wraps `CompositeSigner` and `SlashingDb`. For verifying signer, the block signing path needs to accept and verify Merkle proofs before signing. |
| `crates/signer/src/traits.rs:28-36` | `sign_block()` currently takes `block_root`, `slot`, `pubkey`, etc. For verification, it needs additional parameters: expected fee recipient, expected gas limit, and the Merkle proof. |
| `crates/eth-types/` | Need execution payload tree hash support for Merkle proof verification. |
| The rvc-signer gRPC service | The gRPC protocol definition needs new optional fields for verification data. |

**Key design note:** This is the most invasive Tier 5 feature. The `ValidatorSigner` trait is `#[async_trait(?Send)]` and is implemented by both the local `SignerService` and the remote gRPC signer. Adding verification fields to `sign_block()` would break the trait signature. Better approach: add a separate `sign_block_with_verification()` method with default implementation that falls back to `sign_block()`, and feature-gate behind `--features verifying-signer`.

---

### FR-16: Native Relay Integration [Tier 5]

**Primary crate:** new `crates/relay-client/`
**Secondary:** `crates/builder/`, `crates/block-service/`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/relay-client/` (new crate) | Implements MEV-Boost relay API client: header requests, blinded block submissions, validator registration. |
| `crates/builder/src/service.rs` | `register_validators()` currently registers via the BN. With native relay, registration goes directly to relays. |
| `crates/block-service/src/service.rs` | `propose_block()` needs a path for relay header + unblinding flow (separate from BN's `produce_block_v3`). |
| `crates/block-service/src/traits.rs` | May need a `RelayClient` trait for relay operations. |
| `crates/rvc/src/config/types.rs` | Add `relay_endpoints: Vec<String>`, `relay_secret_key: Option<String>` |

**Key design note:** This is a large feature that warrants its own crate. The relay client is architecturally distinct from the beacon client — it uses different endpoints, different authentication (BLS signing), and different response types. The current `BuilderService` and `BlockService` would need an alternative path when native relay is configured.

**Mutual exclusivity:** `relay_endpoints` and `builder_endpoint` (mev-boost) cannot both be set.

---

### FR-17: Gnosis Chain Support [Tier 5]

**Primary crate:** `crates/rvc/src/config/network.rs`
**Secondary:** Many crates that assume 12-second slots

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/rvc/src/config/network.rs:7-14` | Add `Gnosis` and `Chiado` variants to `Network` enum. |
| `crates/rvc/src/config/network.rs:45-48` | `seconds_per_slot()` currently returns hardcoded `12`. Must return `5` for Gnosis/Chiado. |
| `crates/rvc/src/config/network.rs:17-43` | Add genesis_time and genesis_validators_root for Gnosis and Chiado. |
| `crates/timing/` | `SlotClock` implementations — verify they use `seconds_per_slot` from config, not hardcoded values. |
| `crates/eth-types/` | `SECONDS_PER_SLOT` constant is used across the codebase. Must become a config parameter, not a constant. |

**Key design note:** This is the highest-risk Tier 5 feature. A grep for `SECONDS_PER_SLOT` and `SLOTS_PER_EPOCH` across the codebase reveals hardcoded constants. All of these need to be parameterized. The `seconds_per_slot()` method on `Network` already exists (line 45-48) but returns hardcoded `12` for all networks. Gnosis also uses different `SLOTS_PER_EPOCH` (16 instead of 32) — though this may have been standardized to 32 in recent Gnosis updates.

**Files to audit for slot-time assumptions (non-exhaustive):**
- `crates/timing/` — SlotClock calculations
- `crates/rvc/src/orchestrator/coordinator.rs:349-356` — attestation deadline calculation uses `slot_duration.as_secs() / 3`
- `crates/rvc/src/orchestrator/coordinator.rs:399-401` — 2/3 slot offset
- `crates/bn-manager/src/manager.rs:39` — `DEFAULT_SYNC_CHECK_INTERVAL` hardcoded to 384s (32 slots × 12s)
- `crates/builder/src/service.rs:216-219` — `jitter_seconds()` range 0..30

---

### FR-18: SSE Log Streaming API [Tier 5]

**Primary crate:** `crates/keymanager-api/src/server.rs`
**Secondary:** `crates/telemetry/src/`

**Integration points:**

| File | What Changes |
|------|-------------|
| `crates/keymanager-api/src/server.rs` | Add `GET /rvc/v1/logs` route returning `text/event-stream` |
| `crates/keymanager-api/src/handlers.rs` | SSE handler using `axum::response::sse::Sse` and `tokio::sync::broadcast` |
| `crates/telemetry/src/init.rs` | Add a custom `tracing::Layer` that captures events and sends them to a `broadcast::Sender<LogEvent>` |
| `crates/telemetry/src/lib.rs` | Export the SSE broadcast layer and `LogEvent` type |

**Key design note:** Axum has native SSE support via `axum::response::sse::Sse<S>` where `S: Stream<Item = Result<Event, _>>`. The tracing layer would use `tokio::sync::broadcast` (bounded channel) — each SSE connection creates a `broadcast::Receiver`. The bounded channel ensures slow clients are dropped (they receive `RecvError::Lagged`). Max connections enforced via an `AtomicU32` counter in the handler.

---

## Shared Infrastructure Opportunities

### 1. BnManager Refactoring (FR-5 + FR-6 + FR-11 + FR-14)

Four features modify BnManager's node selection and routing:
- FR-5: Dedicated proposer nodes (separate BnManager instance)
- FR-6: Broadcast topic filtering
- FR-11: Role-based BN assignment
- FR-14: Health-based tier selection

**Recommendation:** Implement in this order:
1. FR-14 (tiers) — foundational: changes how `synced_indices()` works
2. FR-6 (broadcast topics) — config-driven routing change
3. FR-5 (proposer nodes) — separate BnManager instance
4. FR-11 (role-based) — generalizes FR-5, depends on FR-14

### 2. Builder Path Refactoring (FR-1 + FR-10 + FR-12)

Three features modify the builder/block production path:
- FR-1: Circuit breakers (intercepts block production)
- FR-10: Block selection modes (changes how builder/local is chosen)
- FR-12: Registration batching (changes how registrations are submitted)

**Recommendation:** Implement in this order:
1. FR-1 (circuit breakers) — safety-critical, standalone
2. FR-12 (batching) — simple chunking, standalone
3. FR-10 (block selection) — depends on FR-1 for `builderonly` interaction

### 3. Config Infrastructure (FR-9 + FR-10 + FR-11)

Three features add new per-validator configuration fields:
- FR-9: Proposer config from URL
- FR-10: Per-validator block selection mode
- FR-11: Per-BN role assignment (TOML-based)

All flow through `ValidatorStore.update_config()` which already handles partial updates.

### 4. API Server Extensions (FR-2 + FR-13 + FR-18)

Three features add new endpoints to the Keymanager API server:
- FR-2: `POST /rvc/v1/attesting`
- FR-13: `POST /rvc/v1/validator/{pubkey}/prepare_exit`
- FR-18: `GET /rvc/v1/logs`

All use the existing Axum server with Bearer token auth.

## Dependency Graph

```
FR-1 (Circuit Breakers)  ← FR-10 (Block Selection: builderonly interaction)
                          ← FR-16 (Native Relay: respects circuit breakers)

FR-5 (Proposer Nodes)   ← FR-11 (Role-Based BN: generalizes FR-5)

FR-14 (Health Tiers)     ← FR-11 (Role-Based BN: composes with tiers)

FR-4 (Keystore Locking)  — standalone

FR-2 (Attestation Disable) — standalone

FR-3 (Slashed Auto-Shutdown) — standalone

FR-6 (Broadcast Topics) — standalone

FR-7 (Remote Monitoring) — standalone

FR-8 (Log Rotation) — standalone

FR-9 (Proposer Config URL) — standalone

FR-12 (Registration Batching) — standalone

FR-13 (Pre-Signed Exits) — standalone

FR-15 (Verifying Signer) — standalone (feature-gated)

FR-17 (Gnosis Chain) — standalone (but high-risk due to slot-time assumptions)

FR-18 (SSE Logs) — standalone
```

## Risk Assessment

| Feature | Integration Risk | Reason |
|---------|-----------------|--------|
| FR-17 (Gnosis) | **High** | Slot-time assumptions are spread across the entire codebase |
| FR-15 (Verifying Signer) | **High** | Changes `ValidatorSigner` trait used everywhere |
| FR-16 (Native Relay) | **High** | New crate + alternative block production path |
| FR-14 (Health Tiers) | **Medium** | Refactors core `synced_indices()` used by all BN operations |
| FR-11 (Role-Based BN) | **Medium** | Deep BnManager changes, interacts with FR-14 |
| FR-10 (Block Selection) | **Medium** | Changes block production path, interacts with FR-1 |
| FR-1 (Circuit Breakers) | **Low** | Localized to builder path, uses atomics |
| FR-2 (Attestation Disable) | **Low** | Single `AtomicBool` check |
| FR-3 (Slashed Auto-Shutdown) | **Low** | Uses existing `set_enabled()` |
| FR-4 (Keystore Locking) | **Low** | Startup-only, no runtime impact |
| FR-5 (Proposer Nodes) | **Low** | Architecture already separates block_beacon |
| FR-6 (Broadcast Topics) | **Low** | Config-driven routing change |
| FR-7 (Monitoring) | **Low** | Fully independent background task |
| FR-8 (Log Rotation) | **Low** | Additive tracing layer |
| FR-9 (Proposer Config URL) | **Low** | Uses existing update_config() |
| FR-12 (Registration Batching) | **Low** | Simple chunking of existing code |
| FR-13 (Pre-Signed Exits) | **Low** | CLI commands + existing signing logic |
| FR-18 (SSE Logs) | **Low** | Additive: new layer + new endpoint |
