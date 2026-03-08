# Software Architecture: Code Review Remediation (MEDIUM & LOW)

## Overview

This document defines the architecture for remediating ~30 MEDIUM and ~32 LOW findings from the RVC code review. All changes fit within existing crate boundaries — no new crates are introduced. The work is organized into three phases (Security & Data Integrity → Correctness & Reliability → Code Quality & Hardening), with explicit dependency ordering between crates to enable parallel development streams.

The guiding principles are: (1) defense-in-depth for key material and slashing protection, (2) spec compliance over optimization, (3) minimal blast radius per change, and (4) backward-compatible CLI/API surface.

## Architecture Principles

- **Record-then-sign is correct** — The Ethereum consensus spec mandates saving slashing records BEFORE signing. COR-01 is reframed as adding a per-validator mutex to prevent TOCTOU races, NOT reordering operations.
- **Zeroize at every layer** — Wrap all intermediate key material in `Zeroizing<T>`. Trust blst's own `#[zeroize(drop)]` but document the reliance.
- **Fail closed** — SSRF validation rejects by default; CORS allows nothing by default; body limits enforce by default.
- **No shared mutable state without synchronization** — Replace `Arc::try_unwrap` panics with graceful fallbacks; use `tokio::sync::RwLock` in async contexts.

## Crate Dependency Graph (Affected Crates Only)

```text
                          ┌──────────────┐
                          │  bin/rvc     │  (main binary)
                          │  main.rs     │
                          └──────┬───────┘
                                 │ depends on
                          ┌──────▼───────┐
                          │  crates/rvc  │  (orchestrator)
                          │  service.rs  │
                          └──────┬───────┘
                    ┌────────────┼────────────┬────────────┐
                    ▼            ▼            ▼            ▼
             ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
             │  signer  │ │ block-   │ │ builder  │ │ duty-    │
             │          │ │ service  │ │          │ │ tracker  │
             └────┬─────┘ └────┬─────┘ └──────────┘ └──────────┘
                  │            │
           ┌──────┤        ┌───┘
           ▼      ▼        ▼
     ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────────┐
     │ slashing │ │ beacon   │ │ keymanager-  │ │ validator-   │
     │          │ │          │ │ api          │ │ store        │
     └──────────┘ └──────────┘ └──────────────┘ └──────────────┘
                                      │
     ┌──────────┐ ┌──────────┐ ┌──────┘    ┌──────────────┐
     │ crypto   │ │ timing   │ │           │ secret-      │
     │          │ │          │ │           │ provider     │
     └──────────┘ └──────────┘ │           └──────────────┘
                          ┌────▼─────┐
                          │ bn-      │
                          │ manager  │
                          └──────────┘
```

## Phase 1: Security & Data Integrity (P0)

### Change Map by Crate

#### 1.1 `crypto` — Zeroization & Path Safety (SEC-01, SEC-02, SEC-03)

**Files changed:** `bls.rs`, `keystore.rs`, `key_manager.rs`

**SEC-01: Document BlstSecretKey zeroization (M-1)**
- Research confirmed blst >= 0.3.11 implements `#[zeroize(drop)]` on `SecretKey`
- **Action:** Add doc comment to `SecretKey` struct explaining blst handles inner key zeroization. Consider removing the redundant `raw_bytes` field (key material in two places doubles zeroization surface). If removed, `raw_bytes()` returns `self.inner.to_bytes()` (stack-allocated, dropped immediately).
- **No behavioral change** — verification + documentation only

**SEC-02: Zeroize keystore intermediates (M-2, M-3)**
- `keystore.rs:155-161` (decrypt path): wrap derived key in `Zeroizing<[u8; 32]>`
- `keystore.rs:371-375` (encrypt path): wrap plaintext secret key bytes in `Zeroizing<Vec<u8>>`
- Pattern: `let derived_key = Zeroizing::new(derive_key(...))`
- All intermediate `Vec<u8>` holding secret material → `Zeroizing<Vec<u8>>`
- **Dependencies:** None (leaf crate)

**SEC-03: Path traversal check (M-4)**
- `key_manager.rs:307` — `load_from_directory_with_tracker`
- New helper function in `key_manager.rs`:

```rust
fn validate_key_path(base: &Path, candidate: &Path) -> Result<PathBuf, KeyManagerError> {
    let canonical_base = base.canonicalize()?;
    let canonical_path = candidate.canonicalize()?;
    if !canonical_path.starts_with(&canonical_base) {
        return Err(KeyManagerError::PathTraversal {
            path: candidate.to_path_buf(),
            base: canonical_base,
        });
    }
    Ok(canonical_path)
}
```
- Add `PathTraversal` variant to `KeyManagerError`
- Reject symlinks pointing outside base directory with WARN log
- **Dependencies:** None

#### 1.2 `keymanager-api` — API Hardening (SEC-04, SEC-05, SEC-06, SEC-07)

**Files changed:** `types.rs`, `handlers.rs`, `server.rs`
**New file:** `url_validator.rs` (module within crate)

**SEC-04: Redact passwords in Debug (M-5)**
- `types.rs:16-22` — Replace `#[derive(Debug)]` with manual `Debug` impl
- Print `passwords: [REDACTED; N]` where N is the count

```rust
impl std::fmt::Debug for ImportKeystoresRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportKeystoresRequest")
            .field("keystores", &self.keystores)
            .field("passwords", &format_args!("[REDACTED; {}]", self.passwords.len()))
            .field("slashing_protection", &self.slashing_protection)
            .finish()
    }
}
```

**SEC-05: URL validation for remote keys (M-6)**
- New module `url_validator.rs` with:

```rust
pub fn validate_remote_signer_url(
    url_str: &str,
    allow_insecure: bool,
) -> Result<url::Url, String>
```

- Validates: scheme (https required, http with flag), IP literals against private/loopback/link-local/CGNAT ranges, IPv4-mapped IPv6
- Called from `handlers.rs:199-202` in `import_remote_keys`
- New `--allow-insecure-remote-signer` CLI flag (bin/rvc main.rs)
- Thread `allow_insecure` through `AppState`
- **Dependencies:** `url` crate (already in workspace)

**SEC-06: CORS configuration (M-7)**
- `server.rs` — Add `CorsLayer` from `tower-http`
- Default: `CorsLayer::new()` (no CORS headers = same-origin only)
- With `--keymanager-cors-origins`: explicit allowlist
- New fields on `KeymanagerServer`: `cors_origins: Vec<HeaderValue>`
- Methods: GET, POST, DELETE, OPTIONS
- Headers: Content-Type, Authorization
- **New dependency:** `tower-http` with `cors` feature (likely already present)

**SEC-07: Request body size limit (M-8)**
- `server.rs` — Add `DefaultBodyLimit::max(self.body_limit)` layer
- Default: 10 MB
- New `--keymanager-body-limit` CLI flag
- New field on `KeymanagerServer`: `body_limit: usize`

**Server constructor change:**

```rust
pub fn new(
    /* existing params */
    cors_origins: Vec<HeaderValue>,
    body_limit: usize,
    allow_insecure_remote_signer: bool,
) -> Self
```

**Router change:**

```rust
pub fn router(&self) -> Router {
    let cors = if self.cors_origins.is_empty() {
        CorsLayer::new()
    } else {
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(self.cors_origins.clone()))
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    };

    let api = Router::new()
        .route("/eth/v1/keystores", get(...).post(...).delete(...))
        .route("/eth/v1/remotekeys", get(...).post(...).delete(...))
        .layer(DefaultBodyLimit::max(self.body_limit))
        .layer(cors)
        .with_state(self.state.clone());

    auth::with_auth(api, self.token.clone())
}
```

**Dependencies:** `tower-http` (cors feature), `axum` (DefaultBodyLimit)

#### 1.3 `signer` — Remote Signature Verification (SEC-08)

**Files changed:** `remote_signer.rs` (in `crypto` crate — the `RemoteSigner` lives here)

**SEC-08: Verify remote signer signature (M-9)**
- After receiving signature bytes from Web3Signer, verify against expected pubkey and signing root
- Add verification step in `sign()` method:

```rust
// After receiving signature_bytes from remote signer
let signature = Signature::from_bytes(&signature_bytes)?;
if !signature.verify(&pubkey, &signing_root) {
    tracing::error!(pubkey = %hex::encode(pubkey), "Remote signer returned invalid signature");
    return Err(CryptoError::InvalidRemoteSignature);
}
```

- New error variant: `CryptoError::InvalidRemoteSignature`
- **Dependencies:** None (uses existing BLS verify)

#### 1.4 `slashing` — Database Durability (DB-01, DB-02, DB-03)

**Files changed:** `db.rs`

**DB-01: SQLite WAL + synchronous=FULL (M-24)**
- Add PRAGMAs in `open()` after `Connection::open()`:

```rust
let mode: String = conn.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
if mode != "wal" {
    return Err(SlashingError::DatabaseError("Failed to enable WAL mode".into()));
}
conn.pragma_update(None, "synchronous", "FULL")?;
```

- Also add to `open_in_memory()` for consistency (WAL is no-op for in-memory but `synchronous=FULL` isn't harmful)
- Log at INFO level: "Slashing DB: journal_mode=WAL, synchronous=FULL"

**DB-02: Transactional EIP-3076 import (M-25)**
- Wrap the entire `import_interchange` method body in a single IMMEDIATE transaction
- Currently iterates over validators/attestations/blocks inserting individually
- Change: `conn.transaction_with_behavior(TransactionBehavior::Immediate)` → iterate → `tx.commit()`
- On any error: transaction auto-rolls back (rusqlite `Transaction` Drop)

**DB-03: Reconcile check logic (M-26)**
- Standalone `is_safe_to_sign` / `is_safe_to_propose` have subtly different logic from `check_and_record_*`
- **Option A (preferred):** Extract shared `check_attestation_safety(conn, pubkey, source, target, signing_root) -> Result<(), SlashingError>` called by both standalone and atomic variants
- **Option B:** Remove standalone variants if unused
- Audit callers first — if only `check_and_record_*` is used externally, make standalone `pub(crate)`

**Dependencies:** None (leaf crate)

---

## Phase 2: Correctness & Reliability (P1)

### Correctness

#### 2.1 `signer` — Per-Validator Signing Mutex (COR-01)

**Files changed:** `lib.rs`

**COR-01: Per-validator mutex for TOCTOU prevention (M-10)**

The current record-then-sign order is **correct per Ethereum consensus spec**. The fix adds a per-validator mutex to prevent two concurrent sign requests from both passing the slashing check before either records.

**New abstraction — `ValidatorLockMap`:**

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct ValidatorLockMap {
    locks: std::sync::Mutex<HashMap<[u8; 48], Arc<Mutex<()>>>>,
}

impl ValidatorLockMap {
    pub fn new() -> Self {
        Self { locks: std::sync::Mutex::new(HashMap::new()) }
    }

    pub fn get(&self, pubkey: &[u8; 48]) -> Arc<Mutex<()>> {
        let mut map = self.locks.lock().expect("lock map poisoned");
        map.entry(*pubkey).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    }
}
```

- Add `validator_locks: ValidatorLockMap` field to `SignerService`
- In `sign_attestation` and `sign_block`, acquire the per-validator lock BEFORE check-and-record:

```rust
let lock = self.validator_locks.get(&pubkey_bytes);
let _guard = lock.lock().await;
// Now: check_and_record → sign (serialized per validator)
```

- Add doc comment explaining record-then-sign is spec-mandated, with reference to phase0/validator.md
- Log WARN if signing fails after recording (phantom entry — safe per spec)
- **Dependencies:** None

#### 2.2 `rvc-keygen` — Mnemonic Passphrase (COR-02)

**Files changed:** `bin/rvc-keygen/src/bls_to_execution.rs`

- Add `--mnemonic-passphrase` CLI argument (same pattern as `new-mnemonic` and `existing-mnemonic`)
- Thread passphrase into `mnemonic_to_seed()` call
- **Dependencies:** None

#### 2.3 `validator-store` — Atomic Reload (COR-03, COR-04)

**Files changed:** `store.rs`

**COR-03: Remove deleted validators on reload (M-12)**
- After parsing new config, compute stale keys: `current_keys.difference(&new_keys)`
- Remove stale entries from validators map

**COR-04: Atomic reload (M-13)**
- Current code acquires/releases multiple `RwLock`s non-atomically
- Fix: build entire new state (defaults + validators map), then swap all under a single write lock
- Pattern: use a single `RwLock<ValidatorStoreState>` wrapping all mutable state instead of separate locks

```rust
struct ValidatorStoreState {
    validators: HashMap<[u8; 48], ValidatorConfig>,
    default_fee_recipient: Option<[u8; 20]>,
    default_gas_limit: Option<u64>,
    default_graffiti: Option<[u8; 32]>,
}
```

- Parse fully → `let new_state = ValidatorStoreState { ... }` → `*self.state.write().unwrap() = new_state`
- **Dependencies:** None

#### 2.4 `keymanager-api` — Spec Compliance (COR-05)

**Files changed:** `handlers.rs`

**COR-05: Filter local vs remote keys (M-14)**
- `list_keystores` must exclude remote keys
- Requires the `KeystoreManager` trait to expose a method to distinguish local vs remote, or filter by source
- If `KeystoreManager::list_public_keys()` returns all keys, add `KeystoreManager::list_local_keys()` or add a `source: KeySource` field to the return type
- The keymanager adapter in `crates/rvc/src/keymanager_adapters.rs` must implement the filtering
- **Dependencies:** May require trait change in `keymanager-api/traits.rs` + adapter change in `crates/rvc`

#### 2.5 `block-service` — JSON Slot Validation (COR-06)

**Files changed:** `service.rs`

- Add slot validation to the JSON block path matching the SSZ path:

```rust
if block.slot() != requested_slot {
    tracing::error!(requested = requested_slot, got = block.slot(), "Block slot mismatch");
    return Err(BlockServiceError::SlotMismatch { requested: requested_slot, got: block.slot() });
}
```

- New error variant: `BlockServiceError::SlotMismatch`
- **Dependencies:** None

#### 2.6 `bn-manager` — Health & Lock Fixes (COR-07, CON-04, CON-05, CON-06)

**Files changed:** `manager.rs`, `sse.rs`

**COR-07: Actual health scores (M-16)**
- Replace hardcoded `is_reachable: true, is_synced: true` with actual values
- Read from `sync_statuses` (already tracked in `BnManager`):

```rust
pub async fn health_scores(&self) -> Vec<BnHealthScore> {
    let guard = self.health_trackers.read().await;
    let sync_guard = self.sync_statuses.read().await;
    guard.iter().enumerate().map(|(i, t)| {
        let sync = sync_guard.get(i);
        BnHealthScore {
            is_reachable: sync.map_or(false, |s| s.is_reachable),
            is_synced: sync.map_or(false, |s| !s.is_syncing),
            // ... rest unchanged
        }
    }).collect()
}
```

**CON-04: Reduce write lock scope in query_first (M-21)**
- Current: `self.health_trackers.write().await[i].record_success(elapsed)` called inside the per-BN loop
- Fix: collect `(index, result, elapsed)` tuples, then acquire write lock once after loop:

```rust
// After loop:
let mut trackers = self.health_trackers.write().await;
for (i, elapsed) in successes {
    trackers[i].record_success(elapsed);
}
for i in failures {
    trackers[i].record_error();
}
```

- Note: only one BN succeeds in `query_first`, so the pattern is: record the one success + all prior errors in a single lock acquisition

**CON-05: Fallback health recording (M-22)**
- `fallback_unsynced` currently doesn't record health — add same pattern as `query_first`

**CON-06: SSE counter reset (M-23)**
- `sse.rs:159` — only reset reconnection counter after receiving at least one valid event
- Add `events_since_reconnect: u64` counter; reset `reconnect_count` only when `events_since_reconnect > 0`

**Dependencies:** None

#### 2.7 `beacon` — Retry & POST (COR-08, COR-09)

**Files changed:** `client.rs`

**COR-08: 429 retry (M-31)**
- Move 429 check BEFORE the generic `is_client_error()` branch
- Parse `Retry-After` header (seconds format), cap at 120s
- Use parsed value or fall back to `calculate_backoff(attempt)`

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
```

**COR-09: POST for large validator sets (M-32)**
- Threshold: 50 pubkeys → switch from GET with query params to POST with JSON body
- Both Lighthouse and the Beacon API spec support POST for `/eth/v1/beacon/states/{state_id}/validators`

**Dependencies:** None

### Concurrency & Timing

#### 2.8 `rvc` (orchestrator) — Spawn & Clock (CON-01, CON-02, CON-03)

**Files changed:** `orchestrator/service.rs`, `bin/rvc/src/main.rs`

**CON-01: Spawn builder registration (M-17)**
- Replace `self.register_builders().await` with:

```rust
if current_slot % SLOTS_PER_EPOCH == 0 {
    let builder = self.builder_service.clone();
    tokio::spawn(async move {
        if let Err(e) = builder.register_builders().await {
            warn!(error = %e, "Builder registration failed");
        }
    });
}
```

- Builder registration has its own internal timeout; spawning prevents blocking slot processing

**CON-02: SlotClock for phase 3 timing (M-18)**
- Replace `SystemTime::now()` at line 316-319 with `self.clock.now()`:

```rust
let now = self.clock.now();
if now < two_thirds_time {
    let wait_duration = Duration::from_secs(two_thirds_time - now);
    // ...
}
```

- Ensures mock clocks work in tests and clock skew is handled consistently

**CON-03: Dynamic pubkey_map (M-19)**
- Replace `HashMap<[u8; 48], usize>` with shared mutable type:

```rust
pub type PubkeyMap = Arc<tokio::sync::RwLock<HashMap<[u8; 48], usize>>>;
```

- Pass same `Arc` to orchestrator and keymanager API adapters
- Add `tokio::sync::watch<u64>` generation counter for change notification:
  - Keymanager import/delete: increment generation
  - Orchestrator: check generation each slot, trigger duty refresh on change

- `main.rs:711` — change `builder.build_pubkey_map(...)` to return `Arc<tokio::sync::RwLock<...>>`
- `main.rs:714` — remove `Arc::try_unwrap().unwrap()` panic (OTH-03 solved simultaneously)

**OTH-03: Graceful Arc::try_unwrap (M-30)**
- Solved by CON-03: with shared `PubkeyMap`, the `Arc::try_unwrap` on `key_manager` is no longer needed
- If still needed for `key_manager`, use `Arc::try_unwrap(km).unwrap_or_else(|arc| (*arc).clone())` — KeyManager is Clone-able or extract owned data before wrapping in Arc

**Dependencies:** Changes in `main.rs` depend on `keymanager-api` and `crates/rvc` adapter changes

#### 2.9 `duty-tracker` — Atomic Root Check (OTH-05)

**Files changed:** `tracker.rs`

**OTH-05: TOCTOU in dependent root (M-20)**
- Current: read lock to get cached root → drop lock → API call → write lock to update
- Between drop and re-acquire, another task could update
- Fix: use compare-and-swap pattern:

```rust
pub async fn check_and_refetch_if_root_changed(&self, epoch: u64) -> Result<bool, DutyTrackerError> {
    // Fetch from BN first (no lock held)
    let response = self.beacon.get_attester_duties(epoch, &self.validator_indices).await?;

    // Now acquire write lock and compare
    let mut cache = self.cache.write().await;
    let cached_root = cache.get(&epoch).map(|c| c.dependent_root.clone());

    if cached_root.as_ref() == Some(&response.dependent_root) {
        return Ok(false); // No change
    }

    // Root changed (or first fetch) — update under write lock
    let mut epoch_cache = EpochDutyCache::new(response.dependent_root.clone());
    // ... populate from response ...
    cache.insert(epoch, epoch_cache);
    Ok(true)
}
```

- Trade-off: always fetches from BN even if unchanged. Acceptable because duty checks happen once per epoch (~6.4 min).

#### 2.10 `timing` — Metric Precision & Safety (OTH-01, OTH-02)

**Files changed:** `timer.rs`, `clock.rs`

**OTH-01: Sub-second attestation delay (M-28)**
- `timer.rs:136-143` — Replace `.as_secs()` with `.as_secs_f64()`

**OTH-02: Division-by-zero guard (M-29)**
- `clock.rs` — Validate `slot_duration >= 1` in `SlotClock::new()`, return `Err(TimingError::InvalidSlotDuration)` instead of panicking
- New error variant: `TimingError::InvalidSlotDuration`

#### 2.11 `secret-provider` — Dedup Format Detection (OTH-04)

**Files changed:** `gcp.rs`, `format.rs`

- Move all format detection logic into `format.rs`
- `gcp.rs:92-103` calls `format::detect_key_format()` instead of inline logic
- **Dependencies:** None

---

## Phase 3: Code Quality & Hardening (P2)

### 3.1 `eth-types` — Type Safety (LOW-01, LOW-02, LOW-03, LOW-04)

**LOW-01:** Validate signature byte length (96) at deserialization boundaries
**LOW-02:** Extract `vec_u8_tree_hash_root` into a shared utility in `eth-types`
**LOW-03:** Change `ProposerDuty.pubkey` from `String` to typed `[u8; 48]` (serde with hex)
**LOW-04:** Replace untagged `BlockContents` enum with explicit variant tagging or better error context

### 3.2 `crypto` — Zeroization & Robustness (LOW-05, LOW-06, LOW-07, LOW-08)

**LOW-05:** Best-effort zeroize of `num-bigint` intermediates in `eip2333.rs` (BigInt::zeroize not available — document limitation)
**LOW-06:** Log WARN when remote signer URL uses `http://` without `--allow-insecure-remote-signer` (covered by SEC-05)
**LOW-07:** Replace `.unwrap()` on `RwLock::read()/write()` with `.expect("context")` in `CompositeSigner`
**LOW-08:** Replace `String` passwords with `secrecy::SecretString` in `load_from_directory_with_tracker`

### 3.3 `keymanager-api` — Token Hardening (LOW-09, LOW-10)

**LOW-09:** Replace `Arc<String>` token with `Arc<Zeroizing<String>>`
**LOW-10:** Replace `create(true).truncate(true)` with `create_new(true)` + atomic rename for token file

### 3.4 `signer` — Interface Cleanup (LOW-11, LOW-12)

**LOW-11:** Align `sign_attestation` to take `ForkSchedule` like all other signing methods (breaking internal API)
**LOW-12:** Sanitize remote signer error responses — strip server-provided error details before logging

### 3.5 `slashing` — Edge Cases (LOW-13 through LOW-17)

**LOW-13:** Validate `interchange_format_version == "5"` per EIP-3076 on import
**LOW-14:** Normalize pubkeys (lowercase + 0x-prefix) on insert and query
**LOW-15:** Wrap `set_block_watermark` in a transaction
**LOW-16:** Make `insert_attestation` / `insert_block` `pub(crate)` to prevent bypass
**LOW-17:** Set `0o600` permissions at DB creation time (not just post-check)

### 3.6 `secret-provider` — Cleanup (LOW-18 through LOW-21)

**LOW-18:** Remove unused `concurrency_limit` field or wire it
**LOW-19:** Wrap hex-decoded bytes in `Zeroizing<Vec<u8>>` in `format.rs`
**LOW-20:** Wrap `fetch_companion_password` copy in `Zeroizing`
**LOW-21:** Add per-key-fetch timeout (default 30s) to `RefreshService`

### 3.7 `rvc-keygen` — Edge Cases (LOW-22 through LOW-24)

**LOW-22:** Guard `start_index + num_validators` against integer overflow (`.checked_add()`)
**LOW-23:** EIP-55 checksum validation on withdrawal address (mixed-case)
**LOW-24:** Use `create_new` instead of `truncate(true)` for deposit files

### 3.8 Async Span Fixes (LOW-25)

**Crates affected:** `doppelganger`, `rvc` (orchestrator), `keymanager-api`

Replace `span.enter()` / `.entered()` in async code with correct patterns:

| File | Current | Fix |
|------|---------|-----|
| `doppelganger/service.rs:134` | `epoch_span.enter()` | `.instrument(epoch_span)` on the async block |
| `rvc/orchestrator/service.rs:233,242,251,261,311` | `.entered()` on phase spans | These are correct IF no `.await` inside the span scope. Audit each: block/attestation/aggregation phases DO contain `.await` → must change to `.instrument()` |
| `keymanager-api/handlers.rs:59,113,195,243` | `.entered()` | Handlers are async fns — change to `#[tracing::instrument]` or `.instrument()` |

**Audit results from grep:**
- `signer/lib.rs:117,180` — `.entered()` around sync `check_and_record` — **CORRECT** (no .await inside scope)
- `doppelganger/service.rs:134` — `.enter()` in async loop — **BUG** (spans .await inside)
- `orchestrator/service.rs` phase spans — `.entered()` wrapping code blocks with `.await` calls — **BUG**
- `keymanager-api/handlers.rs` — `.entered()` in async handlers — **BUG** (handlers are async)

### 3.9 `builder` — Async RwLock (LOW-26)

**Files changed:** `service.rs`

- Replace `std::sync::RwLock<HashMap<[u8; 48], CachedRegistration>>` with `tokio::sync::RwLock`
- Current usage at line 36 and 51 — straightforward swap

### 3.10 `sync-service` — Graceful Batch Failure (LOW-27)

**Files changed:** `lib.rs`

- When one validator's signing fails, continue with remaining validators
- Collect errors, log per-validator failures, return partial results

### 3.11 `beacon` — Backoff Jitter (LOW-28)

**Files changed:** `client.rs`

- Add ±25% jitter to `calculate_backoff`:

```rust
fn calculate_backoff(&self, attempt: u32) -> Duration {
    let base = /* existing calculation */;
    let jitter_range = base.as_millis() as u64 / 4;
    if jitter_range > 0 {
        let offset = rand::thread_rng().gen_range(0..=jitter_range * 2);
        base.checked_add(Duration::from_millis(offset))
            .map(|d| d - Duration::from_millis(jitter_range))
            .unwrap_or(base)
    } else {
        base
    }
}
```

### 3.12 `rvc` (main) — Config Validation (LOW-29, LOW-30)

**LOW-29:** Return error on invalid network string instead of silent `None` fallback
**LOW-30:** Guard against `committee_length=0` in `make_aggregation_bits` — return error instead of panic

### 3.13 `bn-manager` — SSE Failover & Metrics (LOW-31, LOW-32)

**LOW-31:** Subscribe to SSE from backup BNs when primary disconnects
**LOW-32:** Remove unused metrics definitions

---

## Cross-Cutting Concerns

### Zeroization Pattern (SEC-01, SEC-02, LOW-05, LOW-08, LOW-09, LOW-19, LOW-20)

All crates handling key material follow this pattern:

```rust
use zeroize::Zeroizing;

// Intermediate key bytes
let derived_key = Zeroizing::new(derive_key_bytes(...));

// Passwords
let password = secrecy::SecretString::new(raw_password);

// Token storage
let token: Arc<Zeroizing<String>> = Arc::new(Zeroizing::new(token_string));
```

**Crates affected:** `crypto`, `keymanager-api`, `secret-provider`
**Already available:** `zeroize` and `secrecy` are workspace dependencies

### Async Span Correction (LOW-25)

**Crates affected:** `doppelganger`, `rvc` (orchestrator), `keymanager-api`

**Rule:** Never use `span.enter()` or `.entered()` in scopes containing `.await`. Use:
- `#[tracing::instrument(...)]` on async functions
- `.instrument(span)` on futures
- `span.in_scope(|| sync_code())` for sync code within async

### CLI Flag Additions

New CLI flags across phases (all in `bin/rvc/src/main.rs`):

| Flag | Default | Phase | Issue |
|------|---------|-------|-------|
| `--allow-insecure-remote-signer` | false | 1 | SEC-05 |
| `--keymanager-cors-origins` | (none) | 1 | SEC-06 |
| `--keymanager-body-limit` | 10485760 | 1 | SEC-07 |

These are additive (backward-compatible). No existing flags change.

---

## Data Flow: Key Import with New Validation

```text
Client ──POST /eth/v1/remotekeys──▶ keymanager-api
  │
  ├─ auth::verify_token (constant-time compare)
  ├─ DefaultBodyLimit (reject > 10MB)
  ├─ CORS check (if configured)
  │
  ▼
handlers::import_remote_keys
  │
  ├─ url_validator::validate_remote_signer_url(url, allow_insecure)
  │   ├─ Scheme: https required (http with flag)
  │   ├─ IP: reject private/loopback/link-local
  │   └─ Reject non-HTTP(S) schemes
  │
  ├─ remote_key_manager.add_remote_key(pubkey, validated_url)
  │
  ├─ pubkey_map.write().insert(pubkey, index)
  ├─ key_generation_tx.send_modify(|gen| *gen += 1)
  │
  └─ Return 200 OK
```

## Data Flow: Attestation Signing with Per-Validator Mutex

```text
orchestrator ──sign_attestation──▶ SignerService
  │
  ├─ Compute domain, signing_root
  │
  ├─ validator_locks.get(&pubkey) → Arc<Mutex<()>>
  ├─ lock.lock().await  ◄── Serializes per-validator
  │   │
  │   ├─ slashing_db.check_and_record_attestation()  ◄── Record FIRST (spec-mandated)
  │   │   └─ IMMEDIATE transaction: check surround + record
  │   │
  │   ├─ signer.sign(&signing_root, &pubkey).await
  │   │   └─ If remote: verify returned signature against pubkey
  │   │
  │   └─ On sign failure: WARN log (phantom entry is safe per spec)
  │
  └─ Return signature
```

## Data Flow: Dynamic Key Change Notification

```text
keymanager-api                     orchestrator
     │                                  │
     ├─ import_keystores()              │
     │   └─ pubkey_map.write()          │
     │       .insert(pk, idx)           │
     │                                  │
     ├─ key_gen_tx.send_modify(+1)      │
     │                      ─────────▶  │
     │                                  ├─ key_gen_rx.has_changed()?
     │                                  │   └─ true → refresh_duties()
     │                                  │
     └─────────────────────────────────────────────────────────────
```

---

## Dependency Order (Build Sequence)

Changes must land in this order to maintain compilability:

### Wave 1 — Leaf crates (no internal dependencies among them)

These can all be developed and merged in parallel:

| Crate | Issues |
|-------|--------|
| `crypto` | SEC-01, SEC-02, SEC-03, SEC-08 |
| `slashing` | DB-01, DB-02, DB-03, LOW-13–LOW-17 |
| `timing` | OTH-01, OTH-02 |
| `eth-types` | LOW-01, LOW-02, LOW-03, LOW-04 |
| `secret-provider` | OTH-04, LOW-18–LOW-21 |
| `rvc-keygen` | COR-02, LOW-22–LOW-24 |
| `beacon` | COR-08, COR-09, LOW-28 |

### Wave 2 — Mid-level crates (depend on Wave 1)

| Crate | Issues | Depends On |
|-------|--------|------------|
| `signer` | COR-01, LOW-11, LOW-12 | crypto, slashing |
| `bn-manager` | COR-07, CON-04, CON-05, CON-06, LOW-31, LOW-32 | beacon |
| `validator-store` | COR-03, COR-04, LOW-07 (shared pattern) | — |
| `block-service` | COR-06 | beacon |
| `keymanager-api` | SEC-04–SEC-07, COR-05, LOW-09, LOW-10, LOW-25 (handlers) | crypto (for URL validation types) |
| `builder` | LOW-26 | — |
| `sync-service` | LOW-27 | — |
| `duty-tracker` | OTH-05 | — |
| `doppelganger` | LOW-25 (async spans) | — |

### Wave 3 — Top-level integration

| Crate | Issues | Depends On |
|-------|--------|------------|
| `rvc` (orchestrator) | CON-01, CON-02, LOW-25, LOW-29, LOW-30 | All Wave 2 |
| `bin/rvc` (main) | CON-03, OTH-03, CLI flags | orchestrator, keymanager-api |

---

## New Abstractions Summary

| Abstraction | Location | Purpose |
|------------|----------|---------|
| `ValidatorLockMap` | `signer/lib.rs` | Per-validator tokio::sync::Mutex map for serializing check-record-sign |
| `validate_remote_signer_url()` | `keymanager-api/url_validator.rs` | SSRF prevention: scheme + IP validation |
| `validate_ip()` | `keymanager-api/url_validator.rs` | Private/loopback/link-local IP rejection |
| `validate_key_path()` | `crypto/key_manager.rs` | Path traversal check for key directory loading |
| `PubkeyMap` type alias | `bin/rvc/src/main.rs` | `Arc<tokio::sync::RwLock<HashMap<[u8;48], usize>>>` |
| `ValidatorStoreState` | `validator-store/store.rs` | Single struct for atomic reload swap |
| `check_attestation_safety()` | `slashing/db.rs` | Shared core logic for standalone + atomic check variants |

---

## Technology Additions

| Concern | Addition | Rationale |
|---------|----------|-----------|
| CORS | `tower-http` `cors` feature | Standard Axum CORS middleware |
| Body limit | `axum::extract::DefaultBodyLimit` | Built-in Axum body limit |
| URL parsing | `url` crate (already in workspace) | SSRF URL validation |

No new external crates are required. All dependencies are already in the workspace.

---

## ADRs

### ADR-001: Keep Record-Then-Sign Order

- **Status:** Accepted
- **Context:** Code review (M-10) suggested reordering to sign-then-record to avoid phantom entries in slashing DB.
- **Decision:** Keep the current record-then-sign order. Add per-validator mutex instead.
- **Alternatives:** Sign-then-record (violates Ethereum consensus spec); global signing mutex (too coarse, serializes all validators)
- **Consequences:** Phantom entries remain possible on signing failure — this is the spec-intended safety tradeoff. Missing a single duty is negligible compared to the risk of double-signing.

### ADR-002: Per-Validator Mutex (Not Global)

- **Status:** Accepted
- **Context:** Need to prevent TOCTOU between slashing check and record for the same validator.
- **Decision:** Use a `HashMap<[u8;48], Arc<tokio::sync::Mutex<()>>>` keyed by validator pubkey.
- **Alternatives:** Global mutex (serializes all signing, unacceptable latency for multi-validator setups); sharded locks (complexity without benefit, pubkey is already natural shard key)
- **Consequences:** Memory: one Mutex per active validator (negligible). No contention between different validators. Slight overhead for single-validator setups (one uncontended lock acquisition).

### ADR-003: Shared PubkeyMap with Generation Counter

- **Status:** Accepted
- **Context:** Keys added via keymanager API are invisible to the orchestrator until restart.
- **Decision:** `Arc<tokio::sync::RwLock<HashMap>>` shared between orchestrator and keymanager adapters, with `tokio::sync::watch` generation counter for change notification.
- **Alternatives:** Channel-based key change events (more complex, harder to reason about); epoch-boundary-only refresh (up to 6.4 min latency for new keys)
- **Consequences:** Read lock acquired every slot (cheap, uncontended in happy path). Write lock acquired only on key import/delete (rare). Generation counter avoids unnecessary duty refreshes.

### ADR-004: blst Zeroization Is Sufficient

- **Status:** Accepted
- **Context:** Code review (M-1) flagged `BlstSecretKey` inner field not zeroized.
- **Decision:** Document that blst >= 0.3.11 implements `#[zeroize(drop)]` on `SecretKey`. Consider removing the redundant `raw_bytes` field.
- **Alternatives:** Wrap blst SecretKey in custom zeroization layer (unnecessary complexity, blst already handles it); keep raw_bytes as backup (duplicates key material in memory)
- **Consequences:** Reliance on upstream crate's zeroization. Verified in blst source code. Document with version constraint.

---

## Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| COR-01 per-validator mutex introduces deadlock | HIGH | LOW | Mutex is never held across .await of another mutex; single lock per sign operation |
| CON-03 dynamic pubkey_map race with duty polling | MEDIUM | MEDIUM | Write lock is short-lived (insert only); generation counter prevents stale reads |
| DB-01 WAL migration on existing installations | LOW | LOW | WAL mode is safe to enable; backward-compatible; tested migration path |
| LOW-03 ProposerDuty.pubkey type change | MEDIUM | LOW | Internal type only; grep all callers; update serde |
| COR-04 ValidatorStoreState refactor breaks concurrent readers | MEDIUM | LOW | Single RwLock swap is atomic from readers' perspective by design |
| Phase 3 scope creep (32 LOW items) | MEDIUM | MEDIUM | P2 items can be deferred; each is independent and small |

---

## Architecture Quality Checklist

- [x] **No circular dependencies** — all changes flow downward through the crate DAG
- [x] **Each change has a single, clear purpose** — one issue per change unit
- [x] **No shared databases** — slashing DB ownership stays in `slashing` crate
- [x] **All inter-module communication through defined interfaces** — new `ValidatorLockMap` and `PubkeyMap` are explicit shared types
- [x] **Every module testable in isolation** — no new cross-crate test dependencies
- [x] **Cross-cutting concerns standardized** — zeroization pattern, async span rules, CLI flag conventions
- [x] **Failure modes defined** — phantom entries documented, SSRF rejected, body limits enforced
- [x] **No new crates** — all changes within existing boundaries
- [x] **Data flow traceable** — key import, signing, and notification flows documented
- [x] **Dependency order explicit** — 3-wave build sequence defined
