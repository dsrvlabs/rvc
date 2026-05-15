# Tier 3: Operational Excellence

## Tier Overview
- **Goal:** Reduce operational friction for validator operators — dedicated proposer nodes, broadcast control, remote monitoring, log management, and URL-based proposer config
- **Issue count:** 14 issues, 29 total points
- **Estimated duration:** ~8 days (with 2 parallel streams)
- **Entry criteria:** Tier 2 safety features merged; BnManager and coordinator stable
- **Exit criteria:** All 5 operational features functional; proposer nodes route block production correctly; log rotation handles size limits; monitoring pushes to beaconcha.in-compatible endpoint; URL config refreshes per epoch

## Tier Summary

| Issue | Title | Points | Stream | Blocked by | New Files | Shared File Edits |
|-------|-------|--------|--------|------------|-----------|-------------------|
| T3.1 | Proposer nodes: second BnManager instance | 3 | A | — | — | `crates/bn-manager/src/manager.rs`, `bin/rvc/src/main.rs` |
| T3.2 | Proposer nodes: CLI + config + metrics | 1 | A | T3.1 | — | `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs` |
| T3.3 | Broadcast topics: BnManager routing | 2 | A | — | — | `crates/bn-manager/src/manager.rs` |
| T3.4 | Broadcast topics: CLI + config + parsing | 1 | A | T3.3 | — | `crates/rvc/src/config/types.rs` |
| T3.5 | Monitoring endpoint: payload types + collector | 2 | B | — | `crates/rvc/src/monitoring.rs` | — |
| T3.6 | Monitoring endpoint: push task + retry | 2 | B | T3.5 | — | `crates/rvc/src/monitoring.rs` |
| T3.7 | Monitoring endpoint: CLI + config + metrics | 1 | B | T3.5 | — | `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs` |
| T3.8 | Log rotation: size-based rotation layer | 3 | B | — | `crates/telemetry/src/file_appender.rs` | `crates/telemetry/Cargo.toml`, `crates/telemetry/src/init.rs` |
| T3.9 | Log rotation: compression + max files | 2 | B | T3.8 | — | `crates/telemetry/src/file_appender.rs` |
| T3.10 | Log rotation: CLI flags + config | 1 | A | T3.8 | — | `crates/rvc/src/config/types.rs` |
| T3.11 | Proposer config URL: schema + fetch | 2 | A | — | `crates/rvc/src/config_url.rs` | — |
| T3.12 | Proposer config URL: refresh task + wiring | 3 | A | T3.11 | — | `crates/rvc/src/config_url.rs`, `bin/rvc/src/main.rs` |
| T3.13 | Proposer config URL: CLI + mutual exclusivity | 1 | A | T3.11 | — | `crates/rvc/src/config/types.rs` |
| T3.14 | Tier 3 integration tests | 5 | both | T3.2, T3.4, T3.7, T3.9, T3.13 | `tests/tier3_operations.rs` | — |

## Tier Parallel Plan

| Day | Stream A | Stream B |
|-----|----------|----------|
| 1 | T3.1 Proposer nodes BnManager (3pts) | T3.5 Monitoring payload types (2pts) |
| 2 | T3.1 cont. | T3.8 Log rotation layer (3pts) |
| 3 | T3.3 Broadcast routing (2pts) | T3.8 cont. |
| 4 | T3.11 URL config schema (2pts) | T3.6 Monitoring push task (2pts) |
| 5 | T3.12 URL config refresh (3pts) | T3.9 Log compression (2pts) |
| 6 | T3.12 cont. + T3.2 Proposer CLI (1pt) | T3.7 Monitoring CLI (1pt) + T3.10 Log CLI (1pt) |
| 7 | T3.4 Broadcast CLI (1pt) + T3.13 URL CLI (1pt) | T3.14 Integration tests start |
| 8 | T3.14 Integration tests | T3.14 Integration tests |

---

## Issues

### Issue T3.1: Dedicated proposer nodes — second BnManager instance

**Feature:** FR-5 Dedicated Proposer Nodes
**Story Points:** 3
**Priority:** P1
**Depends On:** None
**Blocks:** T3.2, T3.14
**Files Modified:**
- `crates/bn-manager/src/manager.rs` — no structural changes; reuse existing `BnManager::new()`
- `bin/rvc/src/main.rs` — construct second `BnManager` for proposer nodes, pass as `block_beacon` to orchestrator

**Description:**
Create a separate `BnManager` instance for proposer-only beacon nodes. The existing architecture already separates `beacon` (general BN) from `block_beacon` (block production) in the orchestrator constructor. This feature simply provides a different `BnManager` instance as `block_beacon` when `--proposer-nodes` is configured.

**Implementation Notes:**
- Architecture already supports this: `DutyOrchestrator::new()` takes separate `beacon` and `block_beacon` parameters (~line 128 coordinator.rs)
- Construct second `BnManager` from `config.proposer_nodes` endpoints
- Start sync monitoring for proposer nodes (separate from main pool)
- If `proposer_nodes` is empty, use main BnManager for block_beacon (current behavior)
- Proposer BnManager gets its own health tracking and sync status checks

**Acceptance Criteria:**
- [ ] With `--proposer-nodes` set, block production uses proposer BnManager
- [ ] Without `--proposer-nodes`, behavior unchanged (main pool handles all)
- [ ] Proposer nodes have independent sync status checks
- [ ] Proposer nodes can overlap with main pool (same URL in both)

**Testing Requirements:**
- [ ] Unit test: proposer BnManager constructed from config
- [ ] Unit test: block service receives proposer BnManager
- [ ] Test: fallback to main pool when no proposer nodes configured

---

### Issue T3.2: Dedicated proposer nodes — CLI, config, and metrics

**Feature:** FR-5 Dedicated Proposer Nodes
**Story Points:** 1
**Priority:** P1
**Depends On:** T3.1
**Blocks:** T3.14
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `proposer_nodes: Vec<String>`
- `crates/metrics/src/definitions.rs` — add `rvc_proposer_bn_health_score`, `rvc_proposer_bn_latency_ms` with `pool="proposer"` label

**Description:**
Add CLI flag and config for proposer node endpoints. Add separate metrics for proposer BN health.

**Implementation Notes:**
- `--proposer-nodes http://bn1:5052,http://bn2:5052` (comma-separated list)
- TOML: `proposer_nodes = ["http://bn1:5052", "http://bn2:5052"]`
- Metrics use `pool="proposer"` label to distinguish from main pool

**Acceptance Criteria:**
- [ ] CLI flag parses comma-separated URLs
- [ ] TOML config array format works
- [ ] Proposer BN metrics have `pool="proposer"` label

**Testing Requirements:**
- [ ] Config parsing test

---

### Issue T3.3: Configurable broadcast topics — BnManager routing

**Feature:** FR-6 Configurable Broadcast Topics
**Story Points:** 2
**Priority:** P1
**Depends On:** None
**Blocks:** T3.4, T3.14
**Files Modified:**
- `crates/bn-manager/src/manager.rs` — add `broadcast_topics: BroadcastTopics` field; each submission method checks topic before choosing broadcast vs first strategy

**Description:**
Add topic-based routing to BnManager submission methods. For each message type (attestations, blocks, sync-committee, subscriptions), check if the topic is in the broadcast set. If yes, use `broadcast_to_all()`; if no, use `query_first()`.

**Implementation Notes:**
- `BroadcastTopics` struct with four boolean fields (architecture doc has the type)
- Default: all true (current behavior — broadcast everything)
- Modify `submit_attestation()`, `publish_block()`/`publish_blinded_block()`, `submit_sync_committee_messages()`, `submit_beacon_committee_subscriptions()`
- Each method: `if self.broadcast_topics.<topic> { broadcast } else { query_first }`
- `BnManager::new()` takes `BroadcastTopics` in config

**Acceptance Criteria:**
- [ ] `broadcast_topics.attestations = false` → attestations use first strategy
- [ ] `broadcast_topics.blocks = true` → blocks use broadcast strategy
- [ ] Default (all true) → current behavior unchanged
- [ ] All four submission types respect their topic flag

**Testing Requirements:**
- [ ] Unit test: each topic routed correctly
- [ ] Unit test: default config broadcasts everything

---

### Issue T3.4: Configurable broadcast topics — CLI and config

**Feature:** FR-6 Configurable Broadcast Topics
**Story Points:** 1
**Priority:** P1
**Depends On:** T3.3
**Blocks:** T3.14
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `broadcast: Vec<String>`

**Description:**
Add CLI flag for broadcast topic selection. Parse comma-separated list into `BroadcastTopics`.

**Implementation Notes:**
- `--broadcast attestations,blocks,sync-committee,subscriptions` (default: all)
- `--broadcast none` → all topics disabled
- `none` only effective when specified alone; mixed with other topics → startup error
- Invalid topic name → startup error listing valid topics
- Log at INFO which topics are active at startup

**Acceptance Criteria:**
- [ ] `--broadcast blocks` → only blocks broadcast
- [ ] `--broadcast none` → all use first strategy
- [ ] Invalid topic → startup error
- [ ] Default → all topics broadcast
- [ ] INFO log listing active broadcast topics

**Testing Requirements:**
- [ ] Config parsing: valid topics
- [ ] Config parsing: `none`
- [ ] Config parsing: invalid topic → error

---

### Issue T3.5: Remote monitoring — payload types and metrics collector

**Feature:** FR-7 Remote Monitoring Endpoint
**Story Points:** 2
**Priority:** P1
**Depends On:** None
**Blocks:** T3.6, T3.7, T3.14
**Files Modified:**
- `crates/rvc/src/monitoring.rs` — new file: `MonitoringPayload` struct, `collect_metrics()` function

**Description:**
Implement the beaconcha.in monitoring API v1 payload type and a function that collects current metrics from the validator store and BN manager.

**Implementation Notes:**
- `MonitoringPayload` struct with all fields from the beaconcha.in spec (version 1)
- `collect_metrics()` reads from `ValidatorStore` (total/active counts), process metrics (CPU, memory via `sysinfo` or `/proc/self/stat`), and BN manager (fallback status)
- `client_name = "rvc"`, `process = "validator"`
- Use `serde::Serialize` for JSON serialization
- CPU/memory: use `std::process` or a lightweight system info approach

**Acceptance Criteria:**
- [ ] `MonitoringPayload` serializes to beaconcha.in-compatible JSON
- [ ] `collect_metrics()` returns current validator counts
- [ ] CPU and memory metrics are populated
- [ ] `client_version` and `client_build` are correct

**Testing Requirements:**
- [ ] Unit test: payload serialization matches expected schema
- [ ] Unit test: collect_metrics returns valid data

---

### Issue T3.6: Remote monitoring — push task with retry

**Feature:** FR-7 Remote Monitoring Endpoint
**Story Points:** 2
**Priority:** P1
**Depends On:** T3.5
**Blocks:** T3.14
**Files Modified:**
- `crates/rvc/src/monitoring.rs` — add `start_monitoring_push()` background task
- `bin/rvc/src/main.rs` — spawn monitoring task when endpoint configured

**Description:**
Implement the background task that periodically POSTs metrics to the configured monitoring endpoint. Includes retry with exponential backoff.

**Implementation Notes:**
- Use `reqwest::Client` (already a dependency) for HTTP POST
- Default interval: 384 seconds (1 epoch)
- Retry: max 3 attempts with exponential backoff (1s, 2s, 4s)
- On failure: log at WARN, do not block validator duties
- On success: log at DEBUG
- Use `tokio::select!` with shutdown channel for clean teardown
- HTTPS enforcement by default; `--monitoring-endpoint-insecure` allows HTTP

**Acceptance Criteria:**
- [ ] Metrics pushed to endpoint at configured interval
- [ ] Push failures do not affect validator operation
- [ ] Retry on transient failure (up to 3 times)
- [ ] Clean shutdown on VC termination
- [ ] HTTPS required by default

**Testing Requirements:**
- [ ] Unit test: push task sends correct payload
- [ ] Test: retry on failure
- [ ] Test: no retry on non-transient error (4xx)

---

### Issue T3.7: Remote monitoring — CLI, config, and metrics

**Feature:** FR-7 Remote Monitoring Endpoint
**Story Points:** 1
**Priority:** P1
**Depends On:** T3.5
**Blocks:** T3.14
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `monitoring_endpoint: Option<String>`, `monitoring_interval: Option<u64>`, `monitoring_endpoint_insecure: bool`
- `crates/metrics/src/definitions.rs` — add `rvc_monitoring_push_success_total`, `rvc_monitoring_push_failures_total`

**Description:**
Add CLI flags, config, and Prometheus metrics for the monitoring push service.

**Implementation Notes:**
- `--monitoring-endpoint <URL>` (default: none — feature disabled)
- `--monitoring-interval <seconds>` (default: 384)
- `--monitoring-endpoint-insecure` (default: false)
- Without `--monitoring-endpoint`, no monitoring task is spawned

**Acceptance Criteria:**
- [ ] `--monitoring-endpoint` enables the feature
- [ ] Without the flag, no monitoring task runs
- [ ] Metrics track success/failure counts

**Testing Requirements:**
- [ ] Config parsing test

---

### Issue T3.8: Log rotation — size-based rotation layer

**Feature:** FR-8 Log File Rotation & Compression
**Story Points:** 3
**Priority:** P1
**Depends On:** None
**Blocks:** T3.9, T3.10, T3.14
**Files Modified:**
- `crates/telemetry/src/file_appender.rs` — new file: `FileAppenderConfig`, `create_file_layer()` function
- `crates/telemetry/Cargo.toml` — add `logroller` and `tracing-appender` dependencies
- `crates/telemetry/src/init.rs` — compose file layer into subscriber stack

**Description:**
Implement size-based log rotation using `logroller`. The file logging layer runs alongside stdout logging. Use `tracing-appender::non_blocking` for async I/O to avoid blocking the validator hot path.

**Implementation Notes:**
- `tracing-appender` only supports time-based rotation → use `logroller` for size-based
- `logroller` supports size rotation + max file count + gzip compression
- Wrap `logroller` output with `tracing_appender::non_blocking()` for async writes
- Compose as an additional `tracing::Layer` in the subscriber stack
- The `WorkerGuard` must be held for the application lifetime (return from init)
- Default: no file logging (stdout only). Only activated with `--logfile`

**Acceptance Criteria:**
- [ ] File rotates when reaching configured size limit
- [ ] Non-blocking I/O — no attestation latency impact
- [ ] File logging alongside stdout (not replacing)
- [ ] Without `--logfile`, behavior unchanged

**Testing Requirements:**
- [ ] Unit test: file created when configured
- [ ] Unit test: rotation occurs at size threshold
- [ ] Test: non-blocking write doesn't block caller

---

### Issue T3.9: Log rotation — compression and max file cleanup

**Feature:** FR-8 Log File Rotation & Compression
**Story Points:** 2
**Priority:** P1
**Depends On:** T3.8
**Blocks:** T3.14
**Files Modified:**
- `crates/telemetry/src/file_appender.rs` — wire compression and max_files into `logroller` builder

**Description:**
Add gzip compression for rotated log files and automatic cleanup of old files beyond the max count.

**Implementation Notes:**
- `logroller::Compression::Gzip` when `--logfile-compress` is set
- `max_keep_files(n)` for automatic cleanup
- Compressed files: `.gz` extension
- Verify compressed files are valid gzip
- Default: no compression, keep 5 files

**Acceptance Criteria:**
- [ ] `--logfile-compress` produces `.gz` rotated files
- [ ] Files beyond `--logfile-max-number` are deleted
- [ ] Compressed files are valid gzip
- [ ] Default: no compression, 5 max files

**Testing Requirements:**
- [ ] Test: compressed files are valid gzip
- [ ] Test: old files cleaned up when exceeding max count

---

### Issue T3.10: Log rotation — CLI flags and config

**Feature:** FR-8 Log File Rotation & Compression
**Story Points:** 1
**Priority:** P1
**Depends On:** T3.8
**Blocks:** T3.14
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `logfile`, `logfile_max_size`, `logfile_max_number`, `logfile_compress`, `logfile_level`

**Description:**
Add all CLI flags for log file configuration.

**Implementation Notes:**
- `--logfile <path>`: enable file logging
- `--logfile-max-size <MB>`: default 200
- `--logfile-max-number <N>`: default 5
- `--logfile-compress`: default false
- `--logfile-level <level>`: default same as `--log-level`

**Acceptance Criteria:**
- [ ] All 5 CLI flags parse correctly
- [ ] TOML config equivalent works
- [ ] Defaults match PRD values

**Testing Requirements:**
- [ ] Config parsing test for all flags

---

### Issue T3.11: Proposer config URL — schema parsing and initial fetch

**Feature:** FR-9 Proposer Config from URL with Auto-Refresh
**Story Points:** 2
**Priority:** P1
**Depends On:** None
**Blocks:** T3.12, T3.13, T3.14
**Files Modified:**
- `crates/rvc/src/config_url.rs` — new file: `ProposerConfigResponse`, `ProposerEntry`, `BuilderEntry` types; `fetch_proposer_config()` function

**Description:**
Define the Prysm/Teku-compatible JSON schema for proposer configuration and implement the initial fetch function that parses the response into `ValidatorConfigUpdate` structs.

**Implementation Notes:**
- JSON schema with `proposer_config` (per-validator) and `default_config` (fallback)
- Each entry has `fee_recipient`, `builder.enabled`, `builder.gas_limit`
- Parse into existing `ValidatorConfigUpdate` type from `validator-store`
- Use `reqwest` for HTTP GET (already a dependency)
- Support Bearer token via `--proposer-config-url-token`
- HTTPS required by default; `--proposer-config-url-insecure` allows HTTP

**Acceptance Criteria:**
- [ ] Parses Prysm-compatible JSON schema
- [ ] Parses Teku-compatible JSON schema
- [ ] Converts entries into `ValidatorConfigUpdate` structs
- [ ] Bearer token sent when configured
- [ ] HTTP rejected unless `--proposer-config-url-insecure`

**Testing Requirements:**
- [ ] Unit test: parse valid Prysm JSON
- [ ] Unit test: parse valid Teku JSON
- [ ] Unit test: conversion to ValidatorConfigUpdate

---

### Issue T3.12: Proposer config URL — auto-refresh task and wiring

**Feature:** FR-9 Proposer Config from URL with Auto-Refresh
**Story Points:** 3
**Priority:** P1
**Depends On:** T3.11
**Blocks:** T3.14
**Files Modified:**
- `crates/rvc/src/config_url.rs` — add `start_proposer_config_refresh()` background task
- `bin/rvc/src/main.rs` — spawn refresh task when URL configured

**Description:**
Implement the background task that re-fetches proposer config every epoch and applies changes to the validator store via `update_config()`.

**Implementation Notes:**
- Default refresh interval: 384 seconds (1 epoch)
- On success: apply changes to `ValidatorStore.update_config()` for each validator
- Log changed validators at INFO level
- On failure: retain existing config, log WARN, retry next interval
- Use `tokio::select!` with shutdown channel
- `ValidatorStore.update_config()` already handles partial updates atomically

**Acceptance Criteria:**
- [ ] Config loaded from URL at startup
- [ ] Changes at URL picked up within one refresh interval
- [ ] Fetch failures retain existing config
- [ ] Changed validators logged at INFO
- [ ] Clean shutdown on VC termination

**Testing Requirements:**
- [ ] Unit test: refresh applies changes
- [ ] Unit test: refresh failure retains old config
- [ ] Test: changed validators detected and logged

---

### Issue T3.13: Proposer config URL — CLI flags and mutual exclusivity

**Feature:** FR-9 Proposer Config from URL with Auto-Refresh
**Story Points:** 1
**Priority:** P1
**Depends On:** T3.11
**Blocks:** T3.14
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `proposer_config_url`, `proposer_config_refresh_interval`, `proposer_config_url_token`, `proposer_config_url_insecure`

**Description:**
Add CLI flags and enforce mutual exclusivity with `--proposer-config-file`.

**Implementation Notes:**
- `--proposer-config-url <URL>` and `--proposer-config-file` cannot both be set
- Startup validation: if both are set → error with descriptive message
- `--proposer-config-refresh-interval <seconds>` (default: 384)
- `--proposer-config-url-token <token>` for Bearer auth
- `--proposer-config-url-insecure` for testing with HTTP

**Acceptance Criteria:**
- [ ] Both URL and file set → startup error
- [ ] URL alone → works
- [ ] File alone → works (existing behavior)
- [ ] Neither → works (existing behavior)

**Testing Requirements:**
- [ ] Config validation: mutual exclusivity
- [ ] Config parsing: all flags

---

### Issue T3.14: Tier 3 integration tests

**Feature:** All Tier 3 features (FR-5 through FR-9)
**Story Points:** 5
**Priority:** P1
**Depends On:** T3.2, T3.4, T3.7, T3.9, T3.13
**Blocks:** None
**Files Modified:**
- `tests/tier3_operations.rs` — new integration test file

**Description:**
End-to-end integration tests for all five Tier 3 operational features.

**Implementation Notes:**
- Test proposer nodes: block production routed through proposer BnManager
- Test broadcast: verify topic-based routing (first vs broadcast)
- Test monitoring: mock HTTP endpoint receives valid payload
- Test log rotation: write enough logs to trigger rotation, verify file count
- Test URL config: mock HTTP server serves config, verify refresh applies changes
- Test composition: proposer nodes + broadcast topics work together

**Acceptance Criteria:**
- [ ] Proposer nodes route block production correctly
- [ ] Broadcast topics control routing per message type
- [ ] Monitoring payload matches beaconcha.in schema
- [ ] Log rotation triggers at size threshold
- [ ] URL config refresh applies changes
- [ ] All features compose without interference

**Testing Requirements:**
- [ ] Full integration test suite for all Tier 3 features
