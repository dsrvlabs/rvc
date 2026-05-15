# Software Architecture: Tiers 2–5 — Safety, Operational, Advanced & Experimental

## Overview

This architecture extends rvc's 4-layer crate structure to implement 18 features across Tiers 2–5. The design groups features into four shared infrastructure clusters — BnManager enhancements, Builder/Block-service modifications, Config infrastructure, and API server extensions — to minimize redundant refactoring and maximize code reuse. No new architectural layers are introduced. One new crate (`crates/relay-client/`) is added for Tier 5 native relay integration. All other features fit within existing crates.

Key architectural decisions: health-based BN selection replaces binary sync status with a 4-tier model that composes with role-based filtering; builder circuit breakers use lock-free atomics for zero-overhead safety; attestation disable uses `Arc<AtomicBool>` for sub-microsecond runtime toggling; and file locking uses `fd-lock` RAII guards for automatic cleanup on crash.

## Architecture Principles

- **Additive, not breaking** — Every feature is opt-in or has backwards-compatible defaults. No existing CLI flag, config field, or API endpoint changes behavior.
- **Lock-free hot paths** — Safety features on the critical path (circuit breaker check, attestation disable check) use atomics, never mutexes.
- **Shared infrastructure, independent features** — Features that touch the same crate are co-designed to compose cleanly, but each feature can be implemented and tested independently.
- **Fail-open for liveness** — When safety features encounter ambiguous state (e.g., BN unreachable during slashing check), they preserve current behavior rather than disabling duties.

## System Context Diagram

```text
                                    ┌─────────────────┐
                                    │   Operator CLI   │
                                    │  (clap commands) │
                                    └────────┬────────┘
                                             │
                   ┌─────────────────────────┼─────────────────────────┐
                   │                         │                         │
                   │    ┌───────────────┐    │    ┌───────────────┐    │
                   │    │  Keymanager   │◀───┘    │  Monitoring   │────┼──▶ beaconcha.in
                   │    │  API (Axum)   │         │  Push Service │    │
                   │    └───────┬───────┘         └───────────────┘    │
                   │            │                                      │
                   │    ┌───────▼─────────────────────────────────┐    │
                   │    │           DutyOrchestrator               │    │
                   │    │  ┌─────────┐ ┌──────────┐ ┌──────────┐ │    │
                   │    │  │Attesting│ │ Circuit  │ │ Slashing │ │    │
                   │    │  │ Toggle  │ │ Breaker  │ │ Monitor  │ │    │
                   │    │  └─────────┘ └──────────┘ └──────────┘ │    │
                   │    └──────┬──────────────┬───────────────────┘    │
                   │           │              │                        │
                   │    ┌──────▼──────┐ ┌─────▼──────┐                │
                   │    │ BlockService│ │  Builder   │                │
                   │    │ (selection  │ │  Service   │                │
                   │    │  modes)     │ │ (batching) │                │
                   │    └──────┬──────┘ └─────┬──────┘                │
                   │           │              │                        │
                   │    ┌──────▼──────────────▼──────┐                │
                   │    │         BnManager           │                │
                   │    │  ┌────────┐ ┌────────────┐ │                │
                   │    │  │ Health │ │   Role     │ │                │
                   │    │  │ Tiers  │ │  Routing   │ │                │
                   │    │  └────────┘ └────────────┘ │                │
                   │    └──────┬────────────┬────────┘                │
                   │           │            │                          │
                   └───────────┼────────────┼──────────────────────────┘
                               │            │
                    ┌──────────▼──┐  ┌──────▼──────────┐
                    │ Beacon Node │  │ Proposer-Only BN │
                    │  (general)  │  │  (--proposer-    │
                    │             │  │    nodes)        │
                    └─────────────┘  └─────────────────┘
```

## Feature Interaction Matrix

```text
                FR1  FR2  FR3  FR4  FR5  FR6  FR7  FR8  FR9  FR10 FR11 FR12 FR13 FR14 FR15 FR16 FR17 FR18
FR1  CircBreak   ·    ·    ·    ·    ·    ·    ·    ·    ·    dep   ·    ·    ·    ·    ·   dep   ·    ·
FR2  AttDisable  ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR3  SlashShut   ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR4  KeyLock     ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR5  PropNodes   ·    ·    ·    ·    ·    ·    ·    ·    ·    ·    sub   ·    ·   co    ·    ·    ·    ·
FR6  Broadcast   ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR7  Monitor     ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR8  LogRotate   ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR9  ConfigURL   ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR10 BlockSel    dep  ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR11 RoleBN      ·    ·    ·    ·   sub   ·    ·    ·    ·    ·     ·    ·    ·   co    ·    ·    ·    ·
FR12 RegBatch    ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR13 PreExits    ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR14 HealthTier  ·    ·    ·    ·   co    ·    ·    ·    ·    ·    co    ·    ·    ·    ·    ·    ·    ·
FR15 VerifSign   ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR16 NatRelay    dep  ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR17 Gnosis      ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·
FR18 SSELogs     ·    ·    ·    ·    ·    ·    ·    ·    ·    ·     ·    ·    ·    ·    ·    ·    ·    ·

Legend: dep = depends on, sub = subsumed by, co = co-design required
```

### Ordering Constraints

1. **FR-14 (Health Tiers)** before **FR-11 (Role-Based BN)** — FR-11 composes with tier filtering in `synced_indices()`
2. **FR-1 (Circuit Breakers)** before **FR-10 (Block Selection)** — `builderonly` mode interacts with circuit breaker state
3. **FR-1 (Circuit Breakers)** before **FR-16 (Native Relay)** — relay path must respect circuit breakers
4. **FR-5 (Proposer Nodes)** before **FR-11 (Role-Based BN)** — FR-11 generalizes FR-5

### Independent Features (no ordering constraints)

FR-2, FR-3, FR-4, FR-6, FR-7, FR-8, FR-9, FR-12, FR-13, FR-15, FR-17, FR-18

---

## Shared Infrastructure

### 1. BnManager Cluster (FR-5 + FR-6 + FR-11 + FR-14)

All four features modify how BnManager selects and routes to beacon nodes. Implementation order:

1. **FR-14 (Health Tiers)** — Replace `BnSyncStatus` binary with 4-tier model. Changes `synced_indices()` to accept tier requirements per duty type.
2. **FR-6 (Broadcast Topics)** — Add `BroadcastTopics` bitfield. Submission methods check topic set before choosing broadcast vs. first strategy.
3. **FR-5 (Proposer Nodes)** — Create second `BnManager` instance for proposer nodes. The orchestrator passes it to `BlockService` as `block_beacon`.
4. **FR-11 (Role-Based BN)** — Add per-BN role annotations. `synced_indices()` filters by role, then by tier. FR-5 becomes a config shorthand for `roles = ["proposal"]`.

**Shared type: `BnCapabilities`**

```rust
// crates/bn-manager/src/types.rs

use std::collections::HashSet;

/// Health tier based on sync distance from chain head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HealthTier {
    /// Head within threshold_synced slots of wall clock. Eligible for all duties.
    Synced = 1,
    /// Small lag (threshold_synced..threshold_small). Eligible for attestations, sync committee.
    SmallLag = 2,
    /// Large lag (threshold_small..threshold_large). Eligible for submissions only.
    LargeLag = 3,
    /// Beyond threshold_large or unreachable. Not eligible for any duty.
    Unsynced = 4,
}

/// Duty-type roles assignable to each BN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BnRole {
    Attestation,
    Proposal,
    SyncCommittee,
    Aggregation,
    Submission,
    All,
}

/// Per-BN capabilities combining role assignment and health tier.
#[derive(Debug, Clone)]
pub struct BnCapabilities {
    pub roles: HashSet<BnRole>,
    pub tier: HealthTier,
    pub sync_distance: Option<u64>,
    pub el_offline: bool,
    pub is_optimistic: bool,
}

/// Broadcast topic selection.
#[derive(Debug, Clone)]
pub struct BroadcastTopics {
    pub attestations: bool,
    pub blocks: bool,
    pub sync_committee: bool,
    pub subscriptions: bool,
}

impl Default for BroadcastTopics {
    fn default() -> Self {
        Self { attestations: true, blocks: true, sync_committee: true, subscriptions: true }
    }
}

/// Tier threshold configuration.
#[derive(Debug, Clone)]
pub struct TierThresholds {
    /// Max sync distance for Synced tier (default: 8)
    pub synced: u64,
    /// Width of SmallLag tier (default: 8, so SmallLag = 9..16)
    pub small: u64,
    /// Width of LargeLag tier (default: 48, so LargeLag = 17..64)
    pub large: u64,
}

impl Default for TierThresholds {
    fn default() -> Self {
        Self { synced: 8, small: 8, large: 48 }
    }
}
```

### 2. Builder/Block-Service Cluster (FR-1 + FR-10 + FR-12)

Three features modify the builder and block production path. Implementation order:

1. **FR-1 (Circuit Breakers)** — Add `CircuitBreakerState` to `BuilderService`, queried by `BlockService` before requesting builder blocks.
2. **FR-12 (Registration Batching)** — Chunk `register_validators()` with configurable batch size and delay.
3. **FR-10 (Block Selection Modes)** — Add `BlockSelectionMode` enum that controls how `propose_block()` uses builder_boost_factor and handles builder failures.

**Shared type: `BlockSelectionMode`**

```rust
// crates/block-service/src/types.rs

/// Block selection strategy determining builder vs. local execution preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockSelectionMode {
    /// Request both sources, select highest value (default). Uses builder_boost_factor.
    MaxProfit,
    /// Always use builder; fail proposal if builder fails. For DVT clusters.
    BuilderOnly,
    /// Never request builder blocks; local execution only.
    ExecutionOnly,
    /// Prefer builder, fall back to local on failure.
    BuilderAlways,
}

impl Default for BlockSelectionMode {
    fn default() -> Self {
        Self::MaxProfit
    }
}
```

### 3. Config Infrastructure Cluster (FR-9 + FR-10 + FR-11)

All three add new per-validator or global configuration fields, flowing through `ValidatorStore.update_config()`.

### 4. API Server Cluster (FR-2 + FR-13 + FR-18)

Three features add new endpoints to the Keymanager API server, all using existing Axum infrastructure with Bearer token auth.

---

## Per-Feature Architecture

### FR-1: Builder Circuit Breakers [Tier 2]

**Crates modified:** `crates/builder/src/service.rs`, `crates/block-service/src/service.rs`, `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs`

**New types:**

```rust
// crates/builder/src/circuit_breaker.rs (new file)

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Lock-free circuit breaker for builder block production.
///
/// Uses atomics for zero-overhead checking on the block production hot path.
/// The breaker tracks two independent conditions:
/// - Consecutive missed builder slots
/// - Total missed builder slots in the current epoch
///
/// Either condition exceeding its threshold trips the breaker.
pub struct CircuitBreakerState {
    consecutive_misses: AtomicU32,
    epoch_misses: AtomicU32,
    current_epoch: AtomicU64,
    consecutive_limit: u32,
    epoch_limit: u32,
}

impl CircuitBreakerState {
    pub fn new(consecutive_limit: u32, epoch_limit: u32) -> Self {
        Self {
            consecutive_misses: AtomicU32::new(0),
            epoch_misses: AtomicU32::new(0),
            current_epoch: AtomicU64::new(0),
            consecutive_limit,
            epoch_limit,
        }
    }

    /// Returns true if builder should be bypassed for this slot.
    /// Cost: two atomic loads (~1ns on x86).
    pub fn is_tripped(&self) -> bool {
        if self.consecutive_limit == 0 && self.epoch_limit == 0 {
            return false; // Feature disabled
        }
        let consec = self.consecutive_misses.load(Ordering::Relaxed);
        let epoch = self.epoch_misses.load(Ordering::Relaxed);
        (self.consecutive_limit > 0 && consec >= self.consecutive_limit)
            || (self.epoch_limit > 0 && epoch >= self.epoch_limit)
    }

    /// Record a builder miss (failed or empty response).
    pub fn record_miss(&self) {
        self.consecutive_misses.fetch_add(1, Ordering::Relaxed);
        self.epoch_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a builder success. Resets consecutive counter only.
    pub fn record_success(&self) {
        self.consecutive_misses.store(0, Ordering::Relaxed);
    }

    /// Reset at epoch boundary. Zeroes both counters.
    pub fn reset_epoch(&self, new_epoch: u64) {
        let prev = self.current_epoch.swap(new_epoch, Ordering::Relaxed);
        if new_epoch != prev {
            self.consecutive_misses.store(0, Ordering::Relaxed);
            self.epoch_misses.store(0, Ordering::Relaxed);
        }
    }
}
```

**Integration into BlockService:**

```rust
// In BlockService::propose_block(), before requesting block from BN:

let boost = if circuit_breaker.is_tripped() {
    warn!(slot = slot, "Builder circuit breaker tripped, using local block only");
    Some(0) // builder_boost_factor=0 forces local block
} else {
    Some(self.validator_store.builder_boost_factor(&pubkey_bytes))
};
```

**Configuration:**

```toml
# rvc.toml
builder_circuit_breaker_consecutive_limit = 3  # default
builder_circuit_breaker_epoch_limit = 5         # default
# Set to 0 to disable
```

**CLI flags:** `--builder-circuit-breaker-consecutive-limit`, `--builder-circuit-breaker-epoch-limit`

**Metrics:** `rvc_builder_circuit_breaker_trips_total` (counter), `rvc_builder_consecutive_misses` (gauge), `rvc_builder_epoch_misses` (gauge)

---

### FR-2: Emergency Attestation Disable [Tier 2]

**Crates modified:** `crates/rvc/src/orchestrator/coordinator.rs`, `crates/keymanager-api/src/server.rs`, `crates/keymanager-api/src/handlers.rs`, `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs`

**New types:**

```rust
// Shared state — injected into both DutyOrchestrator and Keymanager API AppState
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Runtime toggle for attestation/sync-committee duties.
/// Shared between the orchestrator (reader) and API server (writer).
pub type AttestingEnabled = Arc<AtomicBool>;
```

**Integration into coordinator:**

```rust
// In DutyOrchestrator, before attestation duties:
if !self.attesting_enabled.load(Ordering::Relaxed) {
    debug!(slot = current_slot, "Attestation duties skipped (disabled)");
    // Skip: attestation_service.process_slot()
    // Skip: sync_committee_service.maybe_produce_sync_messages()
    // Skip: aggregation duties
    // Continue: block proposals, builder registration, SSE, metrics
}
```

**API endpoint:**

```rust
// POST /rvc/v1/attesting
// Request:  { "enabled": true | false }
// Response: { "enabled": true | false }

pub async fn set_attesting_enabled(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SetAttestingRequest>,
) -> Result<Json<AttestingStatusResponse>, ApiError> {
    let prev = state.attesting_enabled.swap(request.enabled, Ordering::Relaxed);
    if prev != request.enabled {
        if request.enabled {
            info!("Attestation duties re-enabled via API");
        } else {
            warn!("Attestation duties disabled via API");
        }
    }
    Ok(Json(AttestingStatusResponse { enabled: request.enabled }))
}
```

**CLI flag:** `--disable-attesting` (sets initial value to `false`)

**Metric:** `rvc_attesting_enabled` (gauge: 1 = enabled, 0 = disabled)

---

### FR-3: Slashed Validator Auto-Shutdown [Tier 2]

**Crates modified:** `crates/rvc/src/orchestrator/coordinator.rs`, `crates/validator-store/src/store.rs`, `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs`

**New types:**

```rust
// crates/rvc/src/slashing_monitor.rs (new file)

/// Action to take when a managed validator is detected as slashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlashedAction {
    /// Disable duties for slashed validator(s), continue operating others.
    DisableOnly,
    /// Shut down the entire validator client.
    Shutdown,
    /// No action (feature disabled).
    None,
}

impl Default for SlashedAction {
    fn default() -> Self {
        Self::DisableOnly
    }
}
```

**Background task:**

```rust
/// Runs once per epoch. Checks validator statuses via BN API.
async fn check_slashed_validators(
    beacon: &dyn BeaconNodeClient,
    validator_store: &ValidatorStore,
    action: SlashedAction,
    shutdown_tx: &watch::Sender<bool>,
) {
    let pubkeys = validator_store.list_enabled_pubkeys();
    if pubkeys.is_empty() {
        return;
    }

    // Query BN for validator statuses
    let response = match beacon.get_validators(&pubkeys).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Failed to check validator statuses for slashing");
            return; // Fail-open: don't disable on BN error
        }
    };

    for validator in &response.data {
        if validator.status.contains("slashed") {
            let pubkey = &validator.pubkey;
            error!(
                pubkey = %pubkey,
                status = %validator.status,
                "Managed validator detected as slashed!"
            );
            metrics::RVC_VALIDATORS_SLASHED_TOTAL.inc();

            match action {
                SlashedAction::DisableOnly => {
                    validator_store.set_enabled(pubkey, false);
                    // Persist disabled state
                    let _ = validator_store.save_config();
                }
                SlashedAction::Shutdown => {
                    error!("Shutting down due to slashed validator");
                    let _ = shutdown_tx.send(true);
                    return;
                }
                SlashedAction::None => {}
            }
        }
    }
}
```

**CLI flag:** `--slashed-validators-action=disable-only|shutdown|none`

**Metric:** `rvc_validators_slashed_total` (counter)

---

### FR-4: Keystore File Locking [Tier 2]

**Crates modified:** `crates/rvc/src/startup.rs`, `crates/rvc/src/config/types.rs`

**New dependency:** `fd-lock = "4"` in `crates/rvc/Cargo.toml`

**Implementation:**

```rust
// crates/rvc/src/startup.rs

use fd_lock::RwLock;
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Exit code when keystore is already locked by another process.
pub const EXIT_KEYSTORE_LOCKED: i32 = 14;

/// Acquires an exclusive file lock on the validator data directory.
/// Returns the lock guard which must be held for the process lifetime.
///
/// Uses flock(2) advisory locks via fd-lock. Locks are automatically
/// released on process exit (including crash/SIGKILL).
pub fn acquire_keystore_lock(
    data_dir: &Path,
) -> Result<fd_lock::RwLockWriteGuard<'static, File>, String> {
    let lock_path = data_dir.join(".rvc.lock");

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("Failed to open lock file {}: {}", lock_path.display(), e))?;

    // Set permissions to 0o600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600));
    }

    // Leak the file into a 'static RwLock so the guard can be returned
    let lock = Box::leak(Box::new(RwLock::new(file)));

    match lock.try_write() {
        Ok(guard) => Ok(guard),
        Err(_) => Err(format!(
            "Keystore directory {} is already locked by another rvc instance. \
             If no other instance is running, delete {} and retry.",
            data_dir.display(),
            lock_path.display(),
        )),
    }
}
```

**Startup sequence insertion:**

```text
1. Open slashing DB
2. Run integrity check
3. Acquire keystore lock   ← NEW (FR-4)
4. Validate genesis root
5. Check beacon node reachability
6. Run doppelganger detection
```

**CLI flag:** `--disable-keystore-locking` (for DVT setups)

---

### FR-5: Dedicated Proposer Nodes [Tier 3]

**Crates modified:** `crates/bn-manager/src/manager.rs`, `crates/rvc/src/config/types.rs`, `bin/rvc/src/main.rs`

**Design:** Create a second `BnManager` instance from `--proposer-nodes` endpoints. The orchestrator passes it to `BlockService` as the `beacon` parameter. The existing architecture already separates `beacon` (general) from `block_beacon` (for block production) — this feature simply provides a different `BnManager` instance for `block_beacon`.

```rust
// In main.rs, during service construction:

let proposer_bn: Arc<dyn BeaconNodeClient> = if !config.proposer_nodes.is_empty() {
    let proposer_config = BnManagerConfig {
        endpoints: config.proposer_nodes.clone(),
        timeout: config.bn_timeout,
    };
    let proposer_manager = BnManager::new(proposer_config)?;
    proposer_manager.start_sync_monitor(None, shutdown_rx.clone());
    Arc::new(proposer_manager)
} else {
    bn_manager.clone() // Use main pool for proposals
};

let block_service = BlockService::new(
    signer.clone(),
    proposer_bn,  // Proposer nodes for block production
    validator_store.clone(),
    fork_schedule.clone(),
    genesis_validators_root,
);
```

**Fallback:** If all proposer nodes fail, `BnManager`'s existing fallback logic (try all BNs when none are synced) handles it. A future enhancement could add cross-pool fallback.

**CLI flag:** `--proposer-nodes http://proposer-bn1:5052,http://proposer-bn2:5052`

**Metrics:** `rvc_proposer_bn_health_score`, `rvc_proposer_bn_latency_ms` (same metrics as main pool but with `pool="proposer"` label)

---

### FR-6: Configurable Broadcast Topics [Tier 3]

**Crates modified:** `crates/bn-manager/src/manager.rs`, `crates/rvc/src/config/types.rs`

**Integration into BnManager:**

```rust
// In BnManager, add broadcast_topics field:
pub struct BnManager {
    clients: Vec<BeaconClient>,
    sync_statuses: SharedSyncStatuses,
    health_trackers: SharedHealthTrackers,
    operation_timeouts: Option<OperationTimeouts>,
    broadcast_topics: BroadcastTopics,  // NEW
}

// Each submission method checks the topic:
impl BnManager {
    pub async fn submit_attestation(&self, ...) -> ... {
        if self.broadcast_topics.attestations {
            self.broadcast_to_all("submit_attestation", ...).await
        } else {
            self.query_first("submit_attestation", ...).await
        }
    }

    pub async fn publish_block(&self, ...) -> ... {
        if self.broadcast_topics.blocks {
            self.broadcast_to_all("publish_block", ...).await
        } else {
            self.query_first("publish_block", ...).await
        }
    }
    // ... same pattern for sync_committee and subscriptions
}
```

**CLI flag:** `--broadcast attestations,blocks,sync-committee,subscriptions` (default: all enabled)

**Parsing:** `none` disables all; any comma-separated subset enables only those topics.

---

### FR-7: Remote Monitoring Endpoint [Tier 3]

**Crates modified:** `crates/rvc/src/monitoring.rs` (new file), `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs`

**New types:**

```rust
// crates/rvc/src/monitoring.rs

use serde::Serialize;

/// beaconcha.in monitoring API v1 payload for validator process.
#[derive(Debug, Serialize)]
pub struct MonitoringPayload {
    pub version: u32, // Always 1
    pub timestamp: u64, // Unix millis
    pub process: String, // "validator"
    pub cpu_process_seconds_total: u64,
    pub memory_process_bytes: u64,
    pub client_name: String, // "rvc"
    pub client_version: String,
    pub client_build: u32,
    pub sync_eth2_fallback_configured: bool,
    pub sync_eth2_fallback_connected: bool,
    pub validator_total: u32,
    pub validator_active: u32,
}
```

**Background task:**

```rust
/// Spawns a background task that pushes metrics every `interval`.
pub fn start_monitoring_push(
    endpoint: String,
    interval: Duration,
    validator_store: Arc<ValidatorStore>,
    bn_manager: Arc<BnManager>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        loop {
            let payload = collect_metrics(&validator_store, &bn_manager);
            match client.post(&endpoint).json(&payload).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!("Monitoring push succeeded");
                }
                Ok(resp) => {
                    warn!(status = %resp.status(), "Monitoring push rejected");
                }
                Err(e) => {
                    warn!(error = %e, "Monitoring push failed");
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => break,
            }
        }
    })
}
```

**CLI flags:** `--monitoring-endpoint <URL>`, `--monitoring-interval <seconds>` (default: 384 = 1 epoch), `--monitoring-endpoint-insecure`

---

### FR-8: Log File Rotation & Compression [Tier 3]

**Crates modified:** `crates/telemetry/src/init.rs`, `crates/telemetry/src/config.rs`, `crates/telemetry/Cargo.toml`

**New dependencies:** `logroller = "0.1"` (size-based rotation + gzip compression), `tracing-appender` (non-blocking writer)

**Design decision:** Use `logroller` instead of `tracing-appender` because the PRD requires size-based rotation, which `tracing-appender` does not support.

```rust
// crates/telemetry/src/file_appender.rs (new file)

use logroller::LogRollerBuilder;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::Registry;

pub struct FileAppenderConfig {
    pub path: std::path::PathBuf,
    pub max_size_mb: u64,
    pub max_files: usize,
    pub compress: bool,
    pub level: tracing::Level,
}

/// Creates a file logging layer with size-based rotation.
///
/// Returns the layer and a guard. The guard MUST be held for the
/// application lifetime — dropping it flushes and stops the writer.
pub fn create_file_layer(
    config: &FileAppenderConfig,
) -> anyhow::Result<(Box<dyn Layer<Registry> + Send + Sync>, WorkerGuard)> {
    let dir = config.path.parent().unwrap_or(std::path::Path::new("."));
    let filename = config.path.file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("rvc.log");

    let mut builder = LogRollerBuilder::new()
        .directory(dir)
        .filename(filename)
        .rotation_size(logroller::RotationSize::MB(config.max_size_mb as u32))
        .max_keep_files(config.max_files as u32);

    if config.compress {
        builder = builder.compression(logroller::Compression::Gzip);
    }

    let roller = builder.build()?;
    let (non_blocking, guard) = tracing_appender::non_blocking(roller);

    let layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_filter(tracing_subscriber::filter::LevelFilter::from_level(config.level))
        .boxed();

    Ok((layer, guard))
}
```

**CLI flags:** `--logfile <path>`, `--logfile-max-size <MB>` (default: 200), `--logfile-max-number <N>` (default: 5), `--logfile-compress`, `--logfile-level <level>`

---

### FR-9: Proposer Config from URL with Auto-Refresh [Tier 3]

**Crates modified:** `crates/rvc/src/config_url.rs` (new file), `crates/validator-store/src/store.rs`, `crates/rvc/src/config/types.rs`

**URL config schema (matches Prysm/Teku):**

```rust
// crates/rvc/src/config_url.rs

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct ProposerConfigResponse {
    pub proposer_config: Option<HashMap<String, ProposerEntry>>,
    pub default_config: Option<ProposerEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ProposerEntry {
    pub fee_recipient: Option<String>,
    pub builder: Option<BuilderEntry>,
}

#[derive(Debug, Deserialize)]
pub struct BuilderEntry {
    pub enabled: Option<bool>,
    pub gas_limit: Option<String>, // String per spec
}
```

**Background refresh task:**

```rust
pub async fn start_proposer_config_refresh(
    url: String,
    token: Option<String>,
    interval: Duration,
    validator_store: Arc<ValidatorStore>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        loop {
            match fetch_and_apply(&client, &url, token.as_deref(), &validator_store).await {
                Ok(changed) => {
                    if changed > 0 {
                        info!(changed_validators = changed, "Proposer config updated from URL");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Proposer config URL fetch failed, retaining current config");
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => break,
            }
        }
    })
}

async fn fetch_and_apply(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    store: &ValidatorStore,
) -> Result<usize, anyhow::Error> {
    let mut req = client.get(url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await?.error_for_status()?;
    let config: ProposerConfigResponse = resp.json().await?;

    let mut changed = 0;
    if let Some(proposer_config) = config.proposer_config {
        for (pubkey_hex, entry) in proposer_config {
            let pubkey = parse_hex_pubkey(&pubkey_hex)?;
            let update = entry_to_config_update(&entry);
            store.update_config(&pubkey, update);
            changed += 1;
        }
    }
    Ok(changed)
}
```

**CLI flags:** `--proposer-config-url <URL>`, `--proposer-config-refresh-interval <seconds>` (default: 384), `--proposer-config-url-token <token>`, `--proposer-config-url-insecure`

**Mutual exclusivity:** Startup validation rejects `--proposer-config-url` + `--proposer-config-file` together.

---

### FR-10: Multi-Strategy Block Selection [Tier 4]

**Crates modified:** `crates/block-service/src/service.rs`, `crates/validator-store/src/store.rs`, `crates/validator-store/src/config.rs`, `crates/rvc/src/config/types.rs`

**Integration into BlockService:**

```rust
// In BlockService::propose_block():

let pubkey_bytes = pubkey.to_bytes();
let mode = self.validator_store
    .block_selection_mode(&pubkey_bytes)
    .unwrap_or(self.default_block_selection_mode);

let boost = match mode {
    BlockSelectionMode::ExecutionOnly => Some(0), // Force local block
    BlockSelectionMode::BuilderOnly => {
        if circuit_breaker.is_tripped() {
            error!(
                slot = slot,
                "BuilderOnly mode active but circuit breaker tripped — proposal will fail"
            );
            // Still attempt with max boost; BN may reject if builder is truly down
        }
        Some(u64::MAX) // Maximum builder preference
    }
    BlockSelectionMode::BuilderAlways => Some(u64::MAX), // Prefer builder, but BN handles fallback
    BlockSelectionMode::MaxProfit => {
        Some(self.validator_store.builder_boost_factor(&pubkey_bytes))
    }
};

// For BuilderOnly, verify the response was actually a builder block
if mode == BlockSelectionMode::BuilderOnly && !response.is_blinded {
    return Err(BlockServiceError::BuilderRequired(
        "BuilderOnly mode: BN returned local block instead of builder block".into(),
    ));
}
```

**Per-validator config:**

```toml
[[validators]]
pubkey = "0xabc..."
block_selection_mode = "builderonly"  # Overrides global default
```

**CLI flag:** `--block-selection-mode <maxprofit|builderonly|executiononly|builderalways>` (default: `maxprofit`)

---

### FR-11: Role-Based BN Assignment [Tier 4]

**Crates modified:** `crates/bn-manager/src/manager.rs`, `crates/bn-manager/src/types.rs`, `crates/rvc/src/config/types.rs`

**Refactored `synced_indices()`:**

```rust
/// Returns indices of BNs eligible for the given duty type and minimum health tier.
///
/// Filtering pipeline:
/// 1. Filter by role assignment (BnRole)
/// 2. Filter by health tier (HealthTier)
/// 3. Sort by health score descending
/// 4. Fall back to all BNs if no eligible BNs remain
async fn eligible_indices(
    &self,
    role: BnRole,
    min_tier: HealthTier,
) -> Vec<usize> {
    let sync_guard = self.sync_statuses.read().await;
    let health_guard = self.health_trackers.read().await;

    let mut candidates: Vec<usize> = (0..self.clients.len())
        .filter(|&i| {
            // Step 1: Role filter
            let roles = &self.bn_roles[i];
            roles.contains(&BnRole::All) || roles.contains(&role)
        })
        .filter(|&i| {
            // Step 2: Tier filter
            self.capabilities[i].tier <= min_tier
        })
        .collect();

    if candidates.is_empty() {
        warn!(
            role = ?role,
            min_tier = ?min_tier,
            "No BNs eligible for role+tier, falling back to all BNs"
        );
        candidates = (0..self.clients.len()).collect();
    }

    // Step 3: Sort by health score
    candidates.sort_by(|&a, &b| {
        health_guard[b].score().partial_cmp(&health_guard[a].score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    candidates
}
```

**TOML configuration:**

```toml
[[beacon_nodes]]
url = "http://bn1:5052"
roles = ["attestation", "sync-committee", "aggregation"]

[[beacon_nodes]]
url = "http://bn2:5052"
roles = ["proposal"]

[[beacon_nodes]]
url = "http://bn3:5052"
# roles defaults to ["all"]
```

**Tier requirements per duty type:**

| Duty | Required Role | Minimum Tier |
|------|--------------|--------------|
| Block production | `Proposal` | `Synced` |
| Attestation data | `Attestation` | `SmallLag` |
| Sync committee | `SyncCommittee` | `SmallLag` |
| Aggregation | `Aggregation` | `SmallLag` |
| All submissions | `Submission` | `LargeLag` |

---

### FR-12: Validator Registration Batching [Tier 4]

**Crates modified:** `crates/builder/src/service.rs`, `crates/rvc/src/config/types.rs`, `crates/metrics/src/definitions.rs`

**Modified `register_validators()`:**

```rust
// In BuilderService::register_validators(), replace single submission with batching:

let batch_size = self.registration_batch_size;
let batch_delay = self.registration_batch_delay;

if batch_size == 0 || registrations.len() <= batch_size {
    // Single batch (current behavior)
    self.bn.register_validators(&registrations).await?;
} else {
    // Chunked batching
    let total_batches = (registrations.len() + batch_size - 1) / batch_size;
    for (batch_idx, chunk) in registrations.chunks(batch_size).enumerate() {
        debug!(
            batch = batch_idx + 1,
            total_batches = total_batches,
            batch_size = chunk.len(),
            "Submitting registration batch"
        );
        match self.bn.register_validators(chunk).await {
            Ok(()) => {
                metrics::RVC_BUILDER_REGISTRATION_BATCHES_TOTAL.inc();
            }
            Err(e) => {
                warn!(
                    batch = batch_idx + 1,
                    error = %e,
                    "Registration batch failed, continuing with remaining batches"
                );
                metrics::RVC_BUILDER_REGISTRATION_BATCHES_FAILED.inc();
            }
        }
        if batch_idx + 1 < total_batches {
            tokio::time::sleep(batch_delay).await;
        }
    }
}
```

**CLI flags:** `--validator-registration-batch-size <N>` (default: 500), `--validator-registration-batch-delay <ms>` (default: 500)

---

### FR-13: Pre-Signed Voluntary Exit Storage [Tier 4]

**Crates modified:** `bin/rvc/src/main.rs` (new subcommands), `crates/keymanager-api/src/handlers.rs`, `crates/keymanager-api/src/server.rs`

**CLI subcommands:**

```rust
// bin/rvc/src/main.rs — new Commands variants

/// Prepare a signed voluntary exit without submitting it
PrepareExit {
    /// Validator public key (0x-prefixed hex)
    #[arg(long)]
    pubkey: String,

    /// Output directory for the signed exit JSON file
    #[arg(long)]
    output: PathBuf,

    /// Beacon node URL (needed for validator index lookup)
    #[arg(long)]
    beacon_url: String,

    // Config, keystore, password args for signing
    #[arg(short, long)]
    config: Option<PathBuf>,
},

/// Submit a previously-prepared signed voluntary exit
SubmitExit {
    /// Path to the signed exit JSON file
    #[arg(long)]
    file: PathBuf,

    /// Beacon node URL
    #[arg(long)]
    beacon_url: String,
},
```

**File format (standard `SignedVoluntaryExit`):**

```json
{
  "message": {
    "epoch": "123456",
    "validator_index": "789012"
  },
  "signature": "0xabcd..."
}
```

**API endpoint:**

```rust
// POST /rvc/v1/validator/{pubkey}/prepare_exit
// Returns: { "data": { "message": { "epoch": "...", "validator_index": "..." }, "signature": "0x..." } }
// Does NOT submit to beacon node.

pub async fn prepare_exit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    let exit_manager = state.exit_manager.as_ref()
        .ok_or(ApiError::Internal("Exit manager not available".into()))?;
    let pubkey = parse_pubkey(&pubkey_hex)?;
    let signed_exit = exit_manager.sign_voluntary_exit(&pubkey, None).await?;
    Ok(Json(VoluntaryExitResponse { data: signed_exit }))
}
```

---

### FR-14: Health-Based BN Tier Selection [Tier 4]

**Crates modified:** `crates/bn-manager/src/sync_status.rs`, `crates/bn-manager/src/manager.rs`, `crates/bn-manager/src/types.rs`, `crates/metrics/src/definitions.rs`

**Refactored `BnSyncStatus`:**

```rust
// crates/bn-manager/src/sync_status.rs

/// Extended sync status with quantitative sync distance for tier computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BnSyncStatus {
    pub state: BnSyncState,
    pub sync_distance: Option<u64>,
    pub head_slot: Option<u64>,
}

/// Qualitative sync state (backwards compatible with old enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BnSyncState {
    Unknown,
    Synced,
    Syncing,
    ElOffline,
    Unreachable,
}

impl BnSyncStatus {
    /// Compute health tier from sync distance and thresholds.
    pub fn tier(&self, thresholds: &TierThresholds) -> HealthTier {
        match self.state {
            BnSyncState::Unreachable | BnSyncState::Unknown => HealthTier::Unsynced,
            BnSyncState::ElOffline => HealthTier::Unsynced, // EL offline = can't produce blocks
            BnSyncState::Syncing | BnSyncState::Synced => {
                match self.sync_distance {
                    Some(d) if d <= thresholds.synced => HealthTier::Synced,
                    Some(d) if d <= thresholds.synced + thresholds.small => HealthTier::SmallLag,
                    Some(d) if d <= thresholds.synced + thresholds.small + thresholds.large => {
                        HealthTier::LargeLag
                    }
                    _ => HealthTier::Unsynced,
                }
            }
        }
    }

    /// Backwards-compatible: returns true if fully synced (tier == Synced).
    pub fn is_usable(&self) -> bool {
        self.state == BnSyncState::Synced
    }
}
```

**Backwards compatibility:** The `is_usable()` method returns the same result as before. Code that only checks `is_usable()` sees no behavior change. The tier system is activated when `--beacon-nodes-sync-tolerances` is set or when features like FR-11 reference tiers.

**CLI flag:** `--beacon-nodes-sync-tolerances <synced_width>,<small_width>,<large_width>` (default: `8,8,48`)

**Metric:** `rvc_bn_health_tier{endpoint="..."}` (gauge: 1-4)

---

### FR-15: Verifying Web3Signer [Tier 5]

**Crates modified:** `crates/signer/src/traits.rs`, `crates/signer/src/lib.rs`, `crates/eth-types/`

**Feature-gated:** `--features verifying-signer` (Cargo feature flag, off by default)

**Extended signing trait:**

```rust
// crates/signer/src/traits.rs

/// Optional verification data for block signing.
/// Only used when the verifying-signer feature is enabled.
#[cfg(feature = "verifying-signer")]
#[derive(Debug, Clone)]
pub struct BlockVerificationData {
    /// Expected fee recipient address.
    pub expected_fee_recipient: [u8; 20],
    /// Expected gas limit.
    pub expected_gas_limit: Option<u64>,
    /// Merkle proof for fee_recipient within ExecutionPayload.
    pub fee_recipient_proof: Vec<[u8; 32]>,
    /// Generalized index of fee_recipient in the block body tree.
    pub fee_recipient_gindex: u64,
    /// Block body root to verify against.
    pub block_body_root: [u8; 32],
}

#[async_trait(?Send)]
pub trait ValidatorSigner: Send + Sync {
    // Existing method (unchanged):
    async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError>;

    /// Sign a block with verification data. Default implementation ignores
    /// verification and delegates to sign_block().
    #[cfg(feature = "verifying-signer")]
    async fn sign_block_with_verification(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
        verification: &BlockVerificationData,
    ) -> Result<Signature, SignerError> {
        // Default: ignore verification, sign normally
        self.sign_block(block_root, slot, pubkey, fork_schedule, genesis_validators_root).await
    }
}
```

**Merkle proof verification (signer side):**

```rust
/// Verify a Merkle proof for a leaf against a root.
/// Uses the standard `is_valid_merkle_branch` from the consensus spec.
fn verify_merkle_proof(
    leaf: [u8; 32],
    proof: &[[u8; 32]],
    depth: usize,
    index: u64,
    root: [u8; 32],
) -> bool {
    let mut value = leaf;
    for i in 0..depth {
        if (index >> i) & 1 == 1 {
            value = hash_concat(&proof[i], &value);
        } else {
            value = hash_concat(&value, &proof[i]);
        }
    }
    value == root
}
```

---

### FR-16: Native Relay Integration [Tier 5]

**New crate:** `crates/relay-client/`

**Crate structure:**

```
crates/relay-client/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Public API, RelayClient trait
│   ├── client.rs        # HTTP relay client implementation
│   ├── types.rs         # Builder API types (SignedBuilderBid, etc.)
│   ├── bid_selector.rs  # Multi-relay bid selection strategies
│   └── error.rs         # Relay-specific errors
```

**Key trait:**

```rust
// crates/relay-client/src/lib.rs

#[async_trait]
pub trait RelayClient: Send + Sync {
    /// Register validators with relay.
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), RelayError>;

    /// Request a builder bid (execution payload header).
    async fn get_header(
        &self,
        slot: u64,
        parent_hash: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<Option<SignedBuilderBid>, RelayError>;

    /// Submit a signed blinded block and receive the full execution payload.
    async fn submit_blinded_block(
        &self,
        block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<ExecutionPayloadResponse, RelayError>;

    /// Check relay health.
    async fn status(&self) -> Result<(), RelayError>;
}
```

**Multi-relay orchestrator:**

```rust
// crates/relay-client/src/bid_selector.rs

pub struct MultiRelayClient {
    relays: Vec<Box<dyn RelayClient>>,
    timeout: Duration,
}

impl MultiRelayClient {
    /// Query all relays in parallel, return the highest-value valid bid.
    pub async fn best_bid(
        &self,
        slot: u64,
        parent_hash: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<Option<(usize, SignedBuilderBid)>, RelayError> {
        let futs: Vec<_> = self.relays.iter().enumerate().map(|(i, relay)| {
            let ph = *parent_hash;
            let pk = *pubkey;
            async move {
                match tokio::time::timeout(self.timeout, relay.get_header(slot, &ph, &pk)).await {
                    Ok(Ok(Some(bid))) => Some((i, bid)),
                    _ => None,
                }
            }
        }).collect();

        let results = futures::future::join_all(futs).await;
        Ok(results.into_iter()
            .flatten()
            .max_by_key(|(_, bid)| bid.message.value.clone()))
    }
}
```

**Integration with BlockService:** When `--relay-endpoints` is configured, `BlockService` gets a `RelayClient` alongside (or instead of) the `BeaconBlockClient`. The block production path forks:

```text
Normal path:  BlockService → BN.produce_block_v3() → sign → BN.publish()
Relay path:   BlockService → RelayClient.get_header() → sign blinded → RelayClient.submit_blinded_block()
```

**CLI flags:** `--relay-endpoints <URL1>,<URL2>,...`, `--relay-secret-key <hex>`

**Mutual exclusivity:** `--relay-endpoints` and `--builder-endpoint` cannot both be set.

---

### FR-17: Gnosis Chain Support [Tier 5]

**Crates modified:** `crates/rvc/src/config/network.rs`, `crates/timing/`, `crates/eth-types/`, `bin/rvc-keygen/`

**Network enum extension:**

```rust
// crates/rvc/src/config/network.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Hoodi,
    Holesky,
    Sepolia,
    Gnosis,
    Chiado,
    Custom,
}

impl Network {
    pub fn genesis_time(&self) -> Option<u64> {
        match self {
            Network::Mainnet => Some(1606824023),
            Network::Hoodi => Some(1742213400),
            Network::Holesky => Some(1695902400),
            Network::Sepolia => Some(1655733600),
            Network::Gnosis => Some(1638993340),
            Network::Chiado => Some(1665396300),
            Network::Custom => None,
        }
    }

    pub fn seconds_per_slot(&self) -> u64 {
        match self {
            Network::Gnosis | Network::Chiado => 5,
            _ => 12,
        }
    }

    pub fn slots_per_epoch(&self) -> u64 {
        match self {
            Network::Gnosis | Network::Chiado => 16,
            _ => 32,
        }
    }

    pub fn genesis_validators_root(&self) -> Option<&'static str> {
        match self {
            Network::Mainnet => Some("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
            Network::Hoodi => Some("0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"),
            Network::Holesky => Some("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"),
            Network::Sepolia => Some("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"),
            Network::Gnosis => Some("0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"),
            Network::Chiado => Some("0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1c"),
            Network::Custom => None,
        }
    }
}
```

**Slot-time audit — files requiring parameterization:**

| File | Current Assumption | Change Required |
|------|-------------------|-----------------|
| `crates/timing/` (SlotClock) | Uses `seconds_per_slot` from config | Verify it's not hardcoded |
| `crates/rvc/src/orchestrator/coordinator.rs:349-356` | `slot_duration.as_secs() / 3` | Already parameterized via `slot_duration` |
| `crates/bn-manager/src/manager.rs:39` | `DEFAULT_SYNC_CHECK_INTERVAL = 384s` (32×12) | Must use `slots_per_epoch * seconds_per_slot` |
| `crates/builder/src/service.rs:216-219` | `jitter_seconds()` range 0..30 | Should scale with epoch duration |
| `crates/block-service/src/service.rs:65` | `SLOTS_PER_EPOCH` constant | Must come from config |
| `crates/eth-types/` | `SLOTS_PER_EPOCH = 32` constant | Must be parameterizable |

**Risk mitigation:** Full `grep` audit of `SECONDS_PER_SLOT`, `SLOTS_PER_EPOCH`, `12` (literal slot duration), and `32` (literal epoch size) across the codebase.

---

### FR-18: SSE Log Streaming API [Tier 5]

**Crates modified:** `crates/telemetry/src/sse_layer.rs` (new file), `crates/keymanager-api/src/server.rs`, `crates/keymanager-api/src/handlers.rs`

**Tracing layer for SSE broadcast:**

```rust
// crates/telemetry/src/sse_layer.rs

use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Maximum SSE broadcast channel capacity.
const CHANNEL_CAPACITY: usize = 2048;

/// Maximum concurrent SSE connections.
const MAX_CONNECTIONS: u32 = 10;

/// JSON log event sent to SSE subscribers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEvent {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// Tracing layer that broadcasts log events to SSE subscribers.
pub struct SseBroadcastLayer {
    sender: broadcast::Sender<LogEvent>,
    connection_count: AtomicU32,
    max_connections: u32,
}

impl SseBroadcastLayer {
    pub fn new() -> (Self, broadcast::Sender<LogEvent>) {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        let sender_clone = sender.clone();
        (
            Self {
                sender,
                connection_count: AtomicU32::new(0),
                max_connections: MAX_CONNECTIONS,
            },
            sender_clone,
        )
    }

    /// Try to acquire a connection slot. Returns None if at max.
    pub fn try_subscribe(&self) -> Option<broadcast::Receiver<LogEvent>> {
        let current = self.connection_count.load(Ordering::Relaxed);
        if current >= self.max_connections {
            return None;
        }
        self.connection_count.fetch_add(1, Ordering::Relaxed);
        Some(self.sender.subscribe())
    }

    pub fn release_connection(&self) {
        self.connection_count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<S: Subscriber> Layer<S> for SseBroadcastLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Only broadcast if there are active subscribers
        if self.sender.receiver_count() == 0 {
            return;
        }

        let metadata = event.metadata();
        let mut visitor = FieldCollector::new();
        event.record(&mut visitor);

        let log_event = LogEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: metadata.level().to_string(),
            target: metadata.target().to_string(),
            message: visitor.message,
            fields: visitor.fields,
        };

        // Non-blocking send. If channel is full, old events are dropped for slow receivers.
        let _ = self.sender.send(log_event);
    }
}
```

**SSE endpoint:**

```rust
// In keymanager-api handlers:

use axum::response::sse::{Event, Sse};
use tokio_stream::wrappers::BroadcastStream;

pub async fn logs_stream(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogStreamParams>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let receiver = state.sse_layer.try_subscribe()
        .ok_or(ApiError::TooManyRequests("Max SSE connections reached".into()))?;

    let min_level = params.level.unwrap_or("info".into());
    let target_filter = params.target.clone();

    let stream = BroadcastStream::new(receiver)
        .filter_map(move |result| {
            match result {
                Ok(event) => {
                    if should_include(&event, &min_level, target_filter.as_deref()) {
                        let json = serde_json::to_string(&event).ok()?;
                        Some(Ok(Event::default().data(json)))
                    } else {
                        None
                    }
                }
                Err(_) => None, // Lagged: skip gaps silently
            }
        });

    Ok(Sse::new(stream))
}
```

**CLI flag:** `--sse-logging` (enables the SSE endpoint and tracing layer)

**Route:** `GET /rvc/v1/logs?level=info&target=rvc` (Bearer token required)

---

## New Crates

### `crates/relay-client/` [Tier 5, FR-16]

| Field | Value |
|-------|-------|
| Purpose | Native MEV relay communication (builder API client) |
| Dependencies | `reqwest`, `serde`, `serde_json`, `blst`, `tokio`, `async-trait`, `thiserror` |
| Size estimate | ~2,000 LOC |
| Justification | Distinct API surface, authentication model (BLS signing), and error types from the beacon client. Relay protocol evolves independently of the beacon API. Isolation prevents relay complexity from leaking into the beacon crate. |

---

## Dependency Changes

| Crate | Feature | Purpose | Version Constraint |
|-------|---------|---------|-------------------|
| `fd-lock` | FR-4 (Keystore locking) | RAII file locking via flock(2) | `^4.0` |
| `logroller` | FR-8 (Log rotation) | Size-based rotation + gzip compression | `^0.1` |
| `tracing-appender` | FR-8 (Log rotation) | Non-blocking writer wrapper | `^0.2` |
| `chrono` | FR-18 (SSE logs) | RFC 3339 timestamps for log events | `^0.4` |
| `tokio-stream` | FR-18 (SSE logs) | `BroadcastStream` wrapper for SSE | `^0.1` |

All other features use existing dependencies (`axum`, `reqwest`, `tokio`, `serde`, `prometheus`, `tracing`, `blst`).

---

## Cross-Cutting Concerns

### Authentication & Authorization

All new API endpoints (`POST /rvc/v1/attesting`, `POST /rvc/v1/validator/{pubkey}/prepare_exit`, `GET /rvc/v1/logs`) use the existing Bearer token authentication from the Keymanager API. No new auth mechanism is introduced.

### Logging & Observability

- All state transitions logged at WARN+ (`rvc.<crate>.<operation>` naming convention)
- Circuit breaker trip/reset: WARN
- Attestation enable/disable: WARN
- Slashing detection: ERROR
- New spans follow existing pattern: `rvc.builder.circuit_breaker`, `rvc.monitoring.push`, etc.
- All features expose Prometheus metrics (listed per feature)

### Error Handling

- Safety features (FR-1 through FR-4) **fail-open** when facing ambiguity — never disable duties based on a failed health check or unreachable BN
- Operational features (FR-5 through FR-9) **gracefully degrade** — monitoring push failure doesn't affect duties; proposer config URL failure retains last-known-good config
- Advanced features (FR-10 through FR-14) **fail explicitly** — `builderonly` mode fails the proposal loudly rather than silently falling back

### Configuration

**Precedence order:**

```
CLI flag (highest) > Environment variable > URL config > TOML file > Default (lowest)
```

All new config fields are `Option<T>` with documented defaults. No existing field changes meaning.

---

## Data Flow Diagrams

### Block Proposal with Circuit Breaker + Selection Mode

```text
DutyOrchestrator::maybe_propose_block(slot, pubkey)
  │
  ├── resolve BlockSelectionMode (per-validator or global)
  │
  ├── check CircuitBreakerState.is_tripped()
  │     ├── tripped + mode=MaxProfit → boost=0 (force local)
  │     ├── tripped + mode=BuilderOnly → ERROR, fail proposal
  │     ├── tripped + mode=ExecutionOnly → no effect (already local)
  │     └── not tripped → use mode-specific boost
  │
  ├── BlockService.propose_block(slot, pubkey, boost)
  │     ├── sign RANDAO
  │     ├── BN.produce_block_v3(slot, randao, graffiti, boost)
  │     ├── sign block
  │     └── BN.publish_block() or BN.publish_blinded_block()
  │
  ├── on success → CircuitBreaker.record_success()
  └── on failure → CircuitBreaker.record_miss()
```

### Multi-BN Duty Routing with Tiers + Roles

```text
Attestation duty for slot N:
  │
  ├── BnManager.eligible_indices(role=Attestation, min_tier=SmallLag)
  │     ├── filter BNs with role ∈ {Attestation, All}
  │     ├── filter BNs with tier ≤ SmallLag
  │     └── sort by health score
  │
  ├── query_first(eligible_indices) → get attestation data
  │
  ├── sign attestation
  │
  └── if broadcast_topics.attestations:
        broadcast_to_all(attestation) → all BNs with Submission role
      else:
        query_first(submission_indices) → single BN
```

### Slashing Detection Flow

```text
Every epoch boundary:
  │
  ├── beacon.get_validators(managed_pubkeys)
  │
  ├── for each validator in response:
  │     └── if status contains "slashed":
  │           ├── log ERROR with pubkey, status
  │           ├── metrics: rvc_validators_slashed_total.inc()
  │           │
  │           └── match slashed_action:
  │                 ├── DisableOnly → validator_store.set_enabled(pubkey, false)
  │                 │                  validator_store.save_config()
  │                 ├── Shutdown → shutdown_tx.send(true)
  │                 └── None → (no action)
```

---

## Infrastructure & Deployment

### Deployment Model

- **Monorepo with modular crate structure** — all 23+ crates in a single repository
- **Single binary** (`rvc`) for the validator client, **separate binary** (`rvc-signer`) for the signing service
- **New crate** (`relay-client`) is a library crate consumed by the `rvc` binary, not a separate service
- **Feature flags** for experimental features: `verifying-signer`, `native-relay`, `gnosis`

### Service Extraction Path

| Module | Extraction Readiness |
|--------|---------------------|
| `relay-client` | **Ready now** — own crate, own types, no shared state |
| `monitoring` | **Ready now** — background task, reads only from shared metrics |
| `slashing-monitor` | **Needs work** — tightly coupled to `ValidatorStore` and coordinator lifecycle |
| `bn-manager` (with tiers + roles) | **Keep together** — core coordination logic, no benefit to splitting |

---

## Technology Choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| File locking | `fd-lock` v4 | RAII guards, no raw libc, actively maintained, auto-release on crash |
| Log rotation | `logroller` + `tracing-appender` | Size-based rotation (PRD requirement), gzip compression, non-blocking I/O |
| SSE streaming | `axum::response::sse` + `tokio::sync::broadcast` | Native Axum support, bounded channel prevents slow-consumer blocking |
| Relay HTTP client | `reqwest` (existing dep) | Already in dependency tree, connection pooling, TLS support |
| Circuit breaker atomics | `std::sync::atomic` | Zero-cost on hot path, no external dependency |
| Monitoring push | `reqwest` (existing dep) | beaconcha.in API is simple HTTP POST |
| Merkle proofs | `tree_hash` (existing dep) | Already used for block root computation |

---

## ADRs (Architecture Decision Records)

### ADR-001: Health Tier vs. Binary Sync Status

- **Status:** Accepted
- **Context:** The current `BnSyncStatus` enum uses binary classification (Synced vs. not). Lighthouse introduced a 4-tier model in v6.0.0 that enables more nuanced BN selection. FR-14 requires tier-based selection, and FR-11 requires role-based filtering that composes with tiers.
- **Decision:** Replace `BnSyncStatus` enum variants with a struct containing `BnSyncState` + `sync_distance`. Add a `tier()` method that computes the tier from sync distance and configurable thresholds. Maintain `is_usable()` for backwards compatibility.
- **Alternatives Considered:**
  - Keep binary status + add a separate tier field: Rejected because it duplicates state and risks inconsistency.
  - Use Lighthouse's exact tier boundaries as constants: Rejected because operators need to tune thresholds for their infrastructure.
- **Consequences:** The `synced_indices()` method changes signature to accept tier requirements. All callers must be updated. The default thresholds (8, 8, 48) match Lighthouse's proven values. Operators who don't configure tiers see no behavior change because `is_usable()` still returns the same result.

### ADR-002: AtomicBool vs. Config-Based Attestation Disable

- **Status:** Accepted
- **Context:** FR-2 requires runtime attestation toggling within a single slot (~12s). Two approaches: (1) `Arc<AtomicBool>` shared between orchestrator and API server, or (2) `ValidatorStore` config field updated via API.
- **Decision:** Use `Arc<AtomicBool>`. The attestation check runs every slot on the hot path. `AtomicBool::load(Relaxed)` costs ~1ns. A config-based approach would require `RwLock` acquisition (~50ns) on every slot, which is acceptable but unnecessary overhead. The `AtomicBool` also avoids persisting transient operational state to the config file.
- **Alternatives Considered:**
  - `tokio::sync::watch` channel: More idiomatic for async, but `AtomicBool` is simpler and the check doesn't need `await`. The `watch` pattern is better for change-notification scenarios; here we just need a flag check.
  - Per-validator disable via `set_enabled()`: This exists but disables all duties, not just attestation. A separate flag is needed for attestation-only disable.
- **Consequences:** The flag is ephemeral — a restart re-enables attestation (or uses `--disable-attesting`). This is intentional: emergency disables should not persist silently.

### ADR-003: fd-lock for File Locking

- **Status:** Accepted
- **Context:** FR-4 needs to prevent two rvc instances from running on the same keystore. Options: `fd-lock`, `fs4`, `fs2`, or sentinel `.lock` files (Teku approach).
- **Decision:** Use `fd-lock` for RAII-based exclusive file locking via `flock(2)`.
- **Alternatives Considered:**
  - `fs2`: Unmaintained since ~2017. Rejected.
  - `fs4`: Active fork of `fs2` with async support. Viable but `fd-lock`'s RAII guards are a better fit for our use case (lock held for process lifetime, auto-release on drop).
  - Sentinel `.lock` files (Teku approach): Creates a file at startup, deletes on shutdown. Problem: crash leaves stale files requiring manual cleanup. OS-level `flock` automatically releases on process exit, including SIGKILL.
  - SQLite exclusive mode (Lighthouse approach): Our slashing DB already uses SQLite, but locking the keystore directory is a separate concern. Adding SQLite locking to the keystore path adds unnecessary complexity.
- **Consequences:** Lock is advisory (cooperative). Only rvc instances respect it. Other VC implementations (Lighthouse, Teku) will not check for `.rvc.lock`. This is acceptable because the goal is preventing accidental duplicate rvc instances.

### ADR-004: logroller for Log Rotation

- **Status:** Accepted
- **Context:** FR-8 requires size-based log rotation with optional gzip compression. `tracing-appender` (official tokio crate) only supports time-based rotation and has no compression. Size-based rotation has been requested (Issue #1940) but not merged.
- **Decision:** Use `logroller` for the file writer (size rotation + gzip), wrapped in `tracing-appender::non_blocking` for async I/O.
- **Alternatives Considered:**
  - `tracing-appender` with daily rotation: Doesn't meet PRD requirement for size-based rotation.
  - `tracing-rolling-file`: Supports size rotation but no compression.
  - Custom `MakeWriter` implementation: More control but significant engineering effort for a solved problem.
- **Consequences:** Adds `logroller` (~2K LOC) as a dependency. The crate is moderately maintained but the feature set is stable. If `tracing-appender` adds size-based rotation in the future, migration is straightforward.

### ADR-005: Gnosis Slot Time — Config vs. Constant

- **Status:** Accepted
- **Context:** Gnosis Chain uses 5-second slots (vs Ethereum's 12s). The codebase has `SECONDS_PER_SLOT` and `SLOTS_PER_EPOCH` as constants in `eth-types`. FR-17 requires these to be parameterized.
- **Decision:** The `Network` enum's `seconds_per_slot()` and `slots_per_epoch()` methods already exist and return the correct values. The constants in `eth-types` (`SECONDS_PER_SLOT = 12`, `SLOTS_PER_EPOCH = 32`) must be replaced by config parameters passed through the system. The `SlotClock` already accepts `seconds_per_slot` from config. Remaining hardcoded references (BnManager's `DEFAULT_SYNC_CHECK_INTERVAL`, builder jitter range) must be computed from network config.
- **Alternatives Considered:**
  - Feature-flag Gnosis as a compile-time selection: Rejected because operators should be able to switch networks at runtime via `--network gnosis`.
  - Keep `SLOTS_PER_EPOCH` as a const and only parameterize slot time: Rejected because Gnosis uses 16 slots/epoch, not 32.
- **Consequences:** High-risk change. Every file that references `SECONDS_PER_SLOT`, `SLOTS_PER_EPOCH`, or hardcodes `12` or `32` must be audited. The `epoch = slot / SLOTS_PER_EPOCH` pattern in `block-service/src/service.rs:65` uses the `SLOTS_PER_EPOCH` constant and must be updated.

---

## Open Questions

1. **Cross-pool fallback for proposer nodes** — Should FR-5 fall back to the main BN pool if all proposer nodes fail, or should proposal fail? Current design: fallback. Operators wanting strict separation can use FR-11 (role-based) with `no_cross_role_fallback = true`.

2. **Slashing detection granularity** — FR-3 checks validator status once per epoch. Should it also subscribe to SSE `proposer_slashing` / `attester_slashing` events for faster detection? The BnManager already supports SSE subscriptions.

3. **Native relay + circuit breaker interaction** — When FR-16 (native relay) is active and the circuit breaker trips, should the relay client be bypassed entirely, or should the circuit breaker only affect the bid selection (fall back to local block)?

4. **Gnosis `SLOTS_PER_EPOCH`** — Some sources suggest Gnosis standardized to 32 slots/epoch in recent updates. This needs verification against the latest `gnosischain/configs` before implementation.

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| BnManager refactoring (tiers + roles) introduces regressions in BN selection | High | Implement FR-14 (tiers) first with backwards-compatible defaults. Extensive integration tests with wiremock. |
| Circuit breaker defaults too aggressive on low-activity networks | Medium | Make limits configurable. Log all trips for operator tuning. Default 3/5 matches Prysm's battle-tested values. |
| Gnosis slot-time audit misses hardcoded values | High | Automated grep scan for `12`, `32`, `SECONDS_PER_SLOT`, `SLOTS_PER_EPOCH`. CI test with Gnosis config values. |
| Native relay protocol drift | Medium | Feature-gate behind `--features native-relay`. Pin builder-specs version. Monitor ethereum/builder-specs for breaking changes. |
| Log rotation with gzip blocks during high-throughput events | Low | `logroller` compression runs on a separate thread. Non-blocking writer ensures the validator's hot path is never blocked. |
| Too many new CLI flags overwhelm operators | Medium | Group related flags under TOML config sections. CLI flags are for the most common options; advanced settings go in TOML only. |

---

## Architecture Quality Checklist

- [x] **No circular dependencies** between modules — relay-client depends on eth-types only; no crate depends on relay-client except rvc binary
- [x] **Each module has a single, clear responsibility** — CircuitBreakerState: track builder misses; MonitoringPush: push metrics; RelayClient: talk to relays
- [x] **No shared databases** — each module owns its data (circuit breaker: atomics; monitoring: ephemeral; relay: stateless client)
- [x] **All inter-module communication goes through defined interfaces** — traits (`BeaconNodeClient`, `RelayClient`, `ValidatorSigner`) mediate all cross-crate calls
- [x] **Every module can be tested in isolation** — CircuitBreakerState is pure logic (no I/O); BnManager uses wiremock; BlockService uses mock BeaconBlockClient
- [x] **Cross-cutting concerns are standardized** — Bearer auth shared across all API endpoints; Prometheus metrics follow `rvc_*` convention; tracing spans follow `rvc.<crate>.<op>`
- [x] **Failure modes are defined** — each feature section documents what happens on failure
- [x] **Service extraction path is clear** — relay-client and monitoring are ready for extraction
- [x] **Data flow is traceable** — three data flow diagrams cover the critical paths
- [x] **Module count is justified** — only one new crate (relay-client) with clear isolation rationale
