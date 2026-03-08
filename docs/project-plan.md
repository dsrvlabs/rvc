# Project Plan: Code Review Remediation (MEDIUM & LOW)

## Summary

This plan remediates ~30 MEDIUM and ~32 LOW findings from the RVC code review, organized into three phases: Security & Data Integrity (P0), Correctness & Reliability (P1), and Code Quality & Hardening (P2). All CRITICAL/HIGH findings are already fixed. Each phase uses two parallel development streams aligned with the crate dependency graph (leaf crates first, then mid-level, then top-level). Total scope: ~55 issues, ~80 story points.

**Key technical decisions from research:**
- **COR-01:** Keep record-then-sign order (spec-compliant). Reframe as per-validator mutex for TOCTOU prevention.
- **SEC-01:** blst >= 0.3.11 already implements `#[zeroize(drop)]`. Document + consider removing redundant `raw_bytes`.
- **DB-01:** WAL + `synchronous=FULL` is mandatory for slashing safety. Performance impact negligible at 1-2 writes/slot.
- **SEC-05:** SSRF prevention via scheme + IP validation. HTTPS required by default.

## Prerequisites

- All CRITICAL/HIGH findings fixed (bugfix sprint complete, develop HEAD: `e5dfa55`)
- 1,876 tests passing, 0 failures, 6 ignored
- `cargo clippy` clean, `cargo fmt` clean
- Workspace dependencies available: `zeroize`, `secrecy`, `tower-http`, `url`

---

## Phase I: Security & Data Integrity (P0)

**Goal:** Close all security-sensitive gaps in key material handling, API hardening, and database durability.
**Size:** 11 issues, ~22 story points

### Stream A — Crypto & Slashing (Wave 1 leaf crates)

Issues targeting `crypto` and `slashing` — no cross-crate dependencies.

- [ ] **SEC-01** — Document BlstSecretKey zeroization _(1 pt)_
  - Crate: `crypto` | File: `bls.rs:53-105`
  - Verify blst version >= 0.3.11 in Cargo.lock
  - Add doc comment explaining blst handles inner key zeroization via `#[zeroize(drop)]`
  - Consider removing redundant `raw_bytes` field (doubles zeroization surface)
  - Dependencies: none
  - Complexity: low

- [ ] **SEC-02** — Zeroize keystore intermediates _(2 pts)_
  - Crate: `crypto` | File: `keystore.rs:155-161, 371-375`
  - Wrap derived key in `Zeroizing<[u8; 32]>` (decrypt path)
  - Wrap plaintext secret key bytes in `Zeroizing<Vec<u8>>` (encrypt path)
  - Ensure no raw `Vec<u8>` holds secret key material
  - Dependencies: none
  - Complexity: low

- [ ] **SEC-03** — Path traversal check in key directory loading _(2 pts)_
  - Crate: `crypto` | File: `key_manager.rs:307`
  - Add `validate_key_path()` helper: canonicalize base, verify each resolved file starts with canonical base
  - Add `PathTraversal` variant to `KeyManagerError`
  - Reject symlinks pointing outside base directory with WARN log
  - Test: create symlink outside dir, verify rejection
  - Dependencies: none
  - Complexity: medium

- [ ] **SEC-08** — Verify remote signer returned signature _(2 pts)_
  - Crate: `crypto` | File: `remote_signer.rs:103-134`
  - After receiving signature bytes, verify against expected pubkey and signing root
  - Add `CryptoError::InvalidRemoteSignature` error variant
  - Test: mock signer returns wrong signature, verify rejection
  - Dependencies: none
  - Complexity: medium

- [ ] **DB-01** — SQLite WAL + synchronous=FULL _(2 pts)_
  - Crate: `slashing` | File: `db.rs:27-36`
  - Add PRAGMAs in `open()`: `journal_mode=WAL`, `synchronous=FULL`
  - Verify `journal_mode` return value equals "wal"
  - Log at INFO level on mode transition
  - Test: open DB, query both PRAGMAs, verify values
  - Dependencies: none
  - Complexity: low

- [ ] **DB-02** — Transactional EIP-3076 import _(2 pts)_
  - Crate: `slashing` | File: `db.rs:362-409`
  - Wrap entire `import_interchange` in `IMMEDIATE` transaction
  - On any error: transaction auto-rolls back (rusqlite `Transaction` Drop)
  - Test: import with intentional mid-import error, verify no partial records
  - Dependencies: none
  - Complexity: medium

- [ ] **DB-03** — Reconcile slashing check logic _(2 pts)_
  - Crate: `slashing` | File: `db.rs:202-302`
  - Extract shared `check_attestation_safety()` / `check_proposal_safety()` called by both standalone and atomic variants
  - Audit callers: if standalone variants unused externally, make `pub(crate)`
  - Test: both paths produce identical results for same inputs
  - Dependencies: none
  - Complexity: medium

### Stream B — Keymanager API Hardening (Wave 1-2)

Issues targeting `keymanager-api` — independent of Stream A.

- [ ] **SEC-04** — Redact passwords in ImportKeystoresRequest Debug _(1 pt)_
  - Crate: `keymanager-api` | File: `types.rs:16-22`
  - Replace `#[derive(Debug)]` with manual `Debug` impl printing `[REDACTED; N]`
  - Test: format with `{:?}` and assert no password substring
  - Dependencies: none
  - Complexity: low

- [ ] **SEC-05** — URL validation for remote key imports _(3 pts)_
  - Crate: `keymanager-api` | New file: `url_validator.rs`
  - Validate scheme (https required, http with `--allow-insecure-remote-signer` flag)
  - Reject private/loopback/link-local/CGNAT IP literals
  - Handle IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
  - Add `--allow-insecure-remote-signer` CLI flag in `bin/rvc/src/main.rs`
  - Test: various URL schemes (ftp, file, data) rejected; private IPs rejected
  - Dependencies: `url` crate (already in workspace)
  - Complexity: high

- [ ] **SEC-06** — CORS configuration on keymanager API _(2 pts)_
  - Crate: `keymanager-api` | File: `server.rs:45-61`
  - Add `CorsLayer` from `tower-http` (default: no CORS headers = same-origin only)
  - Add `--keymanager-cors-origins` CLI flag for explicit allowlist
  - Allow methods: GET, POST, DELETE, OPTIONS; headers: Content-Type, Authorization
  - Test: preflight OPTIONS handled correctly
  - Dependencies: `tower-http` cors feature
  - Complexity: medium

- [ ] **SEC-07** — Request body size limit _(1 pt)_
  - Crate: `keymanager-api` | File: `server.rs:45-61`
  - Add `DefaultBodyLimit::max(self.body_limit)` layer (default 10 MB)
  - Add `--keymanager-body-limit` CLI flag
  - Test: oversized payload returns 413 Payload Too Large
  - Dependencies: none (axum built-in)
  - Complexity: low

### Phase I Joint — Integration Verification

- [ ] **I-JOINT** — Phase I integration verification _(2 pts)_
  - All Phase I issues merged to develop
  - Run full test suite: all 1,876+ tests pass, 0 failures
  - `cargo clippy` clean, `cargo fmt` clean
  - Manual verification: keymanager API with CORS/body limit/URL validation
  - Verify slashing DB opens with WAL mode on fresh and existing databases
  - Dependencies: all Phase I issues

### Phase I Exit Criteria

- All SEC-01 through SEC-08 and DB-01 through DB-03 merged
- No secret key material in raw `Vec<u8>` in keystore paths
- Keymanager API: CORS defaults to same-origin, body limit enforced, URLs validated
- Slashing DB: `journal_mode=WAL`, `synchronous=FULL` on every connection
- Remote signer signatures verified against expected pubkey
- All existing tests pass + new tests for each fix (~15 new tests)
- Three new CLI flags: `--allow-insecure-remote-signer`, `--keymanager-cors-origins`, `--keymanager-body-limit`

---

## Phase II: Correctness & Reliability (P1)

**Goal:** Fix logic errors, concurrency issues, and timing bugs across correctness, concurrency, and other categories.
**Size:** 20 issues, ~35 story points

### Stream A — Correctness Fixes (Wave 1-2 crates)

- [ ] **COR-01** — Per-validator signing mutex (TOCTOU prevention) _(3 pts)_
  - Crate: `signer` | File: `lib.rs:116-146`
  - **Keep record-then-sign order** (spec-mandated, per research finding #4)
  - Add `ValidatorLockMap` (HashMap of per-validator `Arc<tokio::sync::Mutex<()>>`)
  - Acquire per-validator lock BEFORE check-and-record in `sign_attestation` and `sign_block`
  - Add doc comment referencing consensus spec (phase0/validator.md)
  - Log WARN on sign failure after recording (phantom entry — safe per spec)
  - Test: concurrent signing for same validator is serialized; different validators not blocked
  - Dependencies: none
  - Complexity: high

- [ ] **COR-02** — Add --mnemonic-passphrase to bls-to-execution _(1 pt)_
  - Crate: `rvc-keygen` | File: `bls_to_execution.rs:35`
  - Add `--mnemonic-passphrase` CLI argument (same pattern as `new-mnemonic`)
  - Thread passphrase into `mnemonic_to_seed()` call
  - Test: derive with passphrase matches expected BLS key
  - Dependencies: none
  - Complexity: low

- [ ] **COR-03** — reload_config removes deleted validators _(2 pts)_
  - Crate: `validator-store` | File: `store.rs:206-217`
  - Compute set difference: `current_keys - new_config_keys`
  - Remove stale entries from validators map
  - Test: reload with fewer validators, verify removal
  - Dependencies: none
  - Complexity: low

- [ ] **COR-04** — Atomic reload_config _(2 pts)_
  - Crate: `validator-store` | File: `store.rs:207-214`
  - Introduce `ValidatorStoreState` struct wrapping all mutable state
  - Use single `RwLock<ValidatorStoreState>` instead of separate locks
  - Parse fully → build new state → swap under single write lock
  - Test: concurrent read during reload sees consistent state
  - Dependencies: COR-03 (same file, implement together)
  - Complexity: medium

- [ ] **COR-05** — list_keystores excludes remote keys _(2 pts)_
  - Crate: `keymanager-api` | File: `handlers.rs:27-48`
  - Filter `GET /eth/v1/keystores` to local keys only
  - May require adding `list_local_keys()` to `KeystoreManager` trait
  - Update adapter in `crates/rvc/src/keymanager_adapters.rs`
  - Test: import both types, verify correct endpoint filtering
  - Dependencies: none
  - Complexity: medium

- [ ] **COR-06** — Slot validation on JSON block path _(1 pt)_
  - Crate: `block-service` | File: `service.rs:175-205`
  - Add slot validation matching SSZ path: `block.slot() != requested_slot` → error
  - Add `BlockServiceError::SlotMismatch` error variant
  - Test: mock beacon returns wrong-slot block, verify rejection
  - Dependencies: none
  - Complexity: low

- [ ] **COR-07** — health_scores uses actual reachability/sync status _(2 pts)_
  - Crate: `bn-manager` | File: `manager.rs:145-146`
  - Replace hardcoded `is_reachable: true, is_synced: true` with values from `sync_statuses`
  - Test: simulate unreachable BN, verify health score reflects it
  - Dependencies: none
  - Complexity: low

- [ ] **COR-08** — Retry 429 responses _(2 pts)_
  - Crate: `beacon` | File: `client.rs:912`
  - Move 429 check BEFORE generic `is_client_error()` branch
  - Parse `Retry-After` header (seconds format), cap at 120s
  - Fall back to `calculate_backoff(attempt)` if no header
  - Test: mock 429 then 200, verify retry succeeds
  - Dependencies: none
  - Complexity: medium

- [ ] **COR-09** — POST for large validator sets _(2 pts)_
  - Crate: `beacon` | File: `client.rs:184-191`
  - Threshold: 50 pubkeys → switch from GET query params to POST JSON body
  - Small sets continue using GET (backward compatible)
  - Test: 100+ validators uses POST path
  - Dependencies: none
  - Complexity: medium

### Stream B — Concurrency, Timing & Other (Wave 1-3 crates)

- [ ] **OTH-01** — Sub-second attestation delay metric _(1 pt)_
  - Crate: `timing` | File: `timer.rs:136-143`
  - Replace `.as_secs()` with `.as_secs_f64()`
  - Test: 500ms delay recorded as 0.5, not 0
  - Dependencies: none
  - Complexity: low

- [ ] **OTH-02** — Division-by-zero guard in slot clock _(1 pt)_
  - Crate: `timing` | File: `clock.rs:61`
  - Validate `slot_duration >= 1` in `SlotClock::new()`, return `Err(TimingError::InvalidSlotDuration)`
  - Test: zero duration construction fails gracefully
  - Dependencies: none
  - Complexity: low

- [ ] **OTH-04** — Deduplicate format detection logic _(1 pt)_
  - Crate: `secret-provider` | File: `gcp.rs:92-103`, `format.rs`
  - Consolidate into `format.rs`, call from `gcp.rs`
  - Dependencies: none
  - Complexity: low

- [ ] **OTH-05** — TOCTOU in dependent root change detection _(2 pts)_
  - Crate: `duty-tracker` | File: `tracker.rs:169-219`
  - Use compare-and-swap pattern: fetch from BN first (no lock), then write-lock to compare-and-update
  - Test: concurrent root updates don't cause missed duty refreshes
  - Dependencies: none
  - Complexity: medium

- [ ] **CON-04** — Reduce write lock scope in query_first _(2 pts)_
  - Crate: `bn-manager` | File: `manager.rs:291,303`
  - Collect `(index, result, elapsed)` tuples, acquire write lock once after loop
  - Test: concurrent query_first calls don't deadlock
  - Dependencies: none
  - Complexity: medium

- [ ] **CON-05** — Record health for fallback attempts _(1 pt)_
  - Crate: `bn-manager` | File: `manager.rs:498-520`
  - Add health recording for fallback attempts (same pattern as primary)
  - Test: fallback attempt updates health metrics
  - Dependencies: none
  - Complexity: low

- [ ] **CON-06** — SSE counter reset with BN health verification _(2 pts)_
  - Crate: `bn-manager` | File: `sse.rs:159`
  - Add `events_since_reconnect` counter; reset `reconnect_count` only when counter > 0
  - Test: reconnect without events does not reset counter
  - Dependencies: none
  - Complexity: medium

- [ ] **CON-01** — Spawn builder registration off main loop _(2 pts)_
  - Crate: `rvc` (orchestrator) | File: `service.rs:350-352`
  - Replace `self.register_builders().await` with `tokio::spawn`
  - Builder registration has internal timeout; spawning prevents blocking slot processing
  - Test: verify slot processing proceeds while registration runs
  - Dependencies: none (Wave 3, but no code deps on other Phase II items)
  - Complexity: medium

- [ ] **CON-02** — Use SlotClock for phase 3 timing _(1 pt)_
  - Crate: `rvc` (orchestrator) | File: `service.rs:313-319`
  - Replace `SystemTime::now()` with `self.clock.now()`
  - Test: mock clock works for phase 3
  - Dependencies: none
  - Complexity: low

- [ ] **CON-03 + OTH-03** — Dynamic pubkey_map + graceful Arc::try_unwrap _(3 pts)_
  - Crate: `rvc` (main) | File: `main.rs:711,681,714`
  - Type: `Arc<tokio::sync::RwLock<HashMap<[u8; 48], usize>>>`
  - Pass same Arc to orchestrator and keymanager API adapters
  - Add `tokio::sync::watch<u64>` generation counter for change notification
  - Keymanager: increment generation on import/delete
  - Orchestrator: check generation each slot, trigger duty refresh on change
  - Remove `Arc::try_unwrap().unwrap()` panic (OTH-03 solved simultaneously)
  - Test: import key via API, verify it appears in duties
  - Dependencies: COR-05 (keymanager trait changes), CON-01/CON-02 (orchestrator changes)
  - Complexity: high

### Phase II Joint — Integration Verification

- [ ] **II-JOINT** — Phase II integration verification _(2 pts)_
  - All Phase II issues merged to develop
  - Run full test suite: all tests pass, 0 failures
  - `cargo clippy` clean, `cargo fmt` clean
  - Verify: dynamic key import triggers duty refresh
  - Verify: builder registration doesn't block slot processing
  - Verify: 429 retry works with mock beacon
  - Dependencies: all Phase II issues

### Phase II Exit Criteria

- All COR-01 through COR-09, CON-01 through CON-06, OTH-01 through OTH-05 merged
- Per-validator signing mutex prevents TOCTOU (record-then-sign order preserved)
- Dynamic pubkey_map enables runtime key management end-to-end
- Builder registration runs in background (no slot blocking)
- SlotClock used consistently (no raw SystemTime)
- 429 responses retried with backoff; large validator sets use POST
- Health scores reflect actual BN status
- All existing tests pass + new tests for each fix (~25 new tests)

---

## Phase III: Code Quality & Hardening (P2)

**Goal:** Address all LOW findings for edge case handling, code quality, async correctness, and defensive programming.
**Size:** 32 issues, ~32 story points

### Stream A — Type Safety, Zeroization & Slashing Edge Cases (Wave 1 crates)

- [ ] **LOW-01** — Signature Vec<u8> length validation _(1 pt)_
  - Crate: `eth-types` — Validate 96 bytes at deserialization boundaries
  - Complexity: low

- [ ] **LOW-02** — Deduplicate vec_u8_tree_hash_root _(1 pt)_
  - Crate: `eth-types` — Extract shared utility, remove copies from 3 files
  - Complexity: low

- [ ] **LOW-03** — ProposerDuty.pubkey typed as [u8; 48] _(2 pts)_
  - Crate: `eth-types` — Replace `String` with `[u8; 48]` + hex serde
  - Complexity: medium (grep all callers)

- [ ] **LOW-04** — BlockContents serde error context _(1 pt)_
  - Crate: `eth-types` — Replace untagged enum with explicit variant tagging or error wrapping
  - Complexity: low

- [ ] **LOW-05** — Zeroize num-bigint intermediates in EIP-2333 _(1 pt)_
  - Crate: `crypto` — Best-effort; document limitation if BigInt doesn't support zeroize
  - Complexity: low

- [ ] **LOW-07** — Handle RwLock poisoning gracefully _(1 pt)_
  - Crates: `crypto` (CompositeSigner), `validator-store`
  - Replace `.unwrap()` with `.expect("context")` or recovery logic
  - Complexity: low

- [ ] **LOW-08** — SecretString for directory password loading _(1 pt)_
  - Crate: `crypto` — Replace `String` passwords with `secrecy::SecretString`
  - Complexity: low

- [ ] **LOW-13** — Validate interchange_format_version on import _(1 pt)_
  - Crate: `slashing` — Check `interchange_format_version == "5"` per EIP-3076
  - Complexity: low

- [ ] **LOW-14** — Normalize pubkeys in slashing DB _(1 pt)_
  - Crate: `slashing` — Lowercase + 0x-prefix on insert/query
  - Complexity: low

- [ ] **LOW-15** — Transactional set_block_watermark _(1 pt)_
  - Crate: `slashing` — Wrap watermark update in a transaction
  - Complexity: low

- [ ] **LOW-16** — Make insert_attestation/insert_block non-public _(1 pt)_
  - Crate: `slashing` — Restrict to `pub(crate)` to prevent bypassing slashing checks
  - Complexity: low

- [ ] **LOW-17** — Set file permissions on DB creation _(1 pt)_
  - Crate: `slashing` — Set `0o600` at creation time, not just post-check
  - Complexity: low

- [ ] **LOW-22** — Integer overflow guard in keygen _(1 pt)_
  - Crate: `rvc-keygen` — `start_index.checked_add(num_validators)` with error
  - Complexity: low

- [ ] **LOW-23** — EIP-55 checksum validation on withdrawal address _(1 pt)_
  - Crate: `rvc-keygen` — Validate mixed-case addresses against EIP-55 checksum
  - Complexity: low

- [ ] **LOW-24** — Atomic deposit file creation _(1 pt)_
  - Crate: `rvc-keygen` — Use `create_new` instead of `truncate(true)`
  - Complexity: low

### Stream B — Async, Concurrency & API Hardening (Wave 1-3 crates)

- [ ] **LOW-06** — Warn on plaintext HTTP for remote signer _(1 pt)_
  - Crate: `crypto` — Log WARN when URL uses `http://` (covered by SEC-05 flag)
  - Complexity: low
  - Note: may already be handled by SEC-05; verify and add if not

- [ ] **LOW-09** — Zeroize keymanager token _(1 pt)_
  - Crate: `keymanager-api` — Replace `Arc<String>` with `Arc<Zeroizing<String>>`
  - Complexity: low

- [ ] **LOW-10** — Atomic token file creation _(1 pt)_
  - Crate: `keymanager-api` — Use `create_new(true)` + rename pattern
  - Complexity: low

- [ ] **LOW-11** — Consistent Fork/ForkSchedule parameter _(1 pt)_
  - Crate: `signer` — Align `sign_attestation` to take `ForkSchedule`
  - Complexity: low (internal API only)

- [ ] **LOW-12** — Sanitize remote signer error responses _(1 pt)_
  - Crate: `signer` — Strip server error details before logging
  - Complexity: low

- [ ] **LOW-18** — Remove unused concurrency_limit field _(1 pt)_
  - Crate: `secret-provider` — Delete field or wire to actual concurrency control
  - Complexity: low

- [ ] **LOW-19** — Zeroize hex-decoded intermediate in format.rs _(1 pt)_
  - Crate: `secret-provider` — Wrap in `Zeroizing<Vec<u8>>`
  - Complexity: low

- [ ] **LOW-20** — Zeroize fetch_companion_password copy _(1 pt)_
  - Crate: `secret-provider` — Wrap `.to_vec()` copy in `Zeroizing`
  - Complexity: low

- [ ] **LOW-21** — Per-fetch timeout in RefreshService _(1 pt)_
  - Crate: `secret-provider` — Add 30s per-key-fetch timeout
  - Complexity: low

- [ ] **LOW-25** — Fix span.enter() in async code _(2 pts)_
  - Crates: `doppelganger`, `rvc` (orchestrator), `keymanager-api`
  - Replace `.entered()` / `span.enter()` with `.instrument(span)` in async code
  - Confirmed bugs: doppelganger `service.rs:134`, orchestrator phase spans, keymanager handlers
  - Leave sync scopes (signer `lib.rs:117,180`) as-is — they are correct
  - Complexity: medium

- [ ] **LOW-26** — Use tokio::sync::RwLock in BuilderService _(1 pt)_
  - Crate: `builder` — Replace `std::sync::RwLock` with `tokio::sync::RwLock`
  - Complexity: low

- [ ] **LOW-27** — Graceful batch signing failure in sync-service _(1 pt)_
  - Crate: `sync-service` — Continue producing sync messages for other validators on single failure
  - Complexity: low

- [ ] **LOW-28** — Add jitter to retry backoff _(1 pt)_
  - Crate: `beacon` — Add ±25% jitter to `calculate_backoff`
  - Complexity: low

- [ ] **LOW-29** — Reject invalid network values _(1 pt)_
  - Crate: `rvc` (main) — Return error instead of silent `None` fallback
  - Complexity: low

- [ ] **LOW-30** — Guard against committee_length=0 _(1 pt)_
  - Crate: `rvc` (orchestrator) — Return error instead of panicking
  - Complexity: low

- [ ] **LOW-31** — SSE failover to secondary BN _(2 pts)_
  - Crate: `bn-manager` — Subscribe to SSE from backup BNs on primary disconnect
  - Complexity: medium

- [ ] **LOW-32** — Remove unused metrics _(1 pt)_
  - Crate: `bn-manager` — Delete metrics defined but never recorded
  - Complexity: low

### Phase III Joint — Integration Verification

- [ ] **III-JOINT** — Phase III integration verification _(2 pts)_
  - All Phase III issues merged to develop
  - Run full test suite: all tests pass, 0 failures
  - `cargo clippy` clean, `cargo fmt` clean
  - Grep audit: no `span.enter()` / `.entered()` in async code with `.await`
  - Grep audit: no raw `Vec<u8>` holding secret key material
  - Grep audit: no `.unwrap()` on `RwLock::read()/write()` without context
  - Dependencies: all Phase III issues

### Phase III Exit Criteria

- All LOW-01 through LOW-32 merged
- No async span bugs (`span.enter()` across `.await` points)
- All `RwLock` poisoning handled gracefully
- All intermediate key material wrapped in `Zeroizing<T>` or `SecretString`
- Slashing DB: pubkeys normalized, visibility restricted, permissions set at creation
- All existing tests pass + new tests (~15 new tests)
- Total test count: 1,950+ tests

---

## Dependency Graph

```text
Phase I (P0)                     Phase II (P1)                    Phase III (P2)
─────────────                    ──────────────                   ───────────────

Stream A:                        Stream A:                        Stream A:
┌─────────┐                      ┌─────────┐                      ┌─────────────┐
│ SEC-01  │─┐                    │ COR-01  │ (signer)             │ LOW-01..04  │ (eth-types)
│ SEC-02  │ │                    │ COR-02  │ (rvc-keygen)         │ LOW-05,07,08│ (crypto)
│ SEC-03  │ ├── Wave 1           │ COR-03  │─┐                   │ LOW-13..17  │ (slashing)
│ SEC-08  │ │   (crypto)         │ COR-04  │─┘ (validator-store)  │ LOW-22..24  │ (rvc-keygen)
│ DB-01   │ │                    │ COR-05  │ (keymanager-api)     └─────────────┘
│ DB-02   │ │                    │ COR-06  │ (block-service)
│ DB-03   │─┘                    │ COR-07  │ (bn-manager)        Stream B:
                                 │ COR-08  │ (beacon)            ┌─────────────┐
Stream B:                        │ COR-09  │ (beacon)            │ LOW-06      │ (crypto)
┌─────────┐                      └─────────┘                      │ LOW-09,10   │ (keymanager)
│ SEC-04  │─┐                                                     │ LOW-11,12   │ (signer)
│ SEC-05  │ ├── Wave 1-2         Stream B:                        │ LOW-18..21  │ (secret-prov)
│ SEC-06  │ │   (keymanager)     ┌─────────┐                      │ LOW-25      │ (async spans)
│ SEC-07  │─┘                    │ OTH-01  │ (timing)             │ LOW-26      │ (builder)
                                 │ OTH-02  │ (timing)             │ LOW-27      │ (sync-svc)
Joint:                           │ OTH-04  │ (secret-provider)    │ LOW-28      │ (beacon)
┌─────────┐                      │ OTH-05  │ (duty-tracker)       │ LOW-29,30   │ (rvc)
│ I-JOINT │                      │ CON-04  │─┐                    │ LOW-31,32   │ (bn-manager)
└─────────┘                      │ CON-05  │ ├── (bn-manager)     └─────────────┘
                                 │ CON-06  │─┘
                                 │ CON-01  │─┐                    Joint:
                                 │ CON-02  │ ├── (orchestrator)   ┌─────────────┐
                                 │ CON-03  │─┘ + main.rs          │ III-JOINT   │
                                 │ OTH-03  │  (solved by CON-03)  └─────────────┘
                                 └─────────┘

                                 Joint:
                                 ┌─────────┐
                                 │ II-JOINT│
                                 └─────────┘
```

**Wave ordering within phases:**

| Wave | Crates | Can Start |
|------|--------|-----------|
| 1 | crypto, slashing, timing, eth-types, secret-provider, rvc-keygen, beacon | Immediately |
| 2 | signer, bn-manager, validator-store, block-service, keymanager-api, builder, sync-service, duty-tracker, doppelganger | After Wave 1 deps |
| 3 | rvc (orchestrator), bin/rvc (main) | After Wave 2 deps |

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| COR-01 per-validator mutex deadlock | HIGH | LOW | Mutex never held across .await of another mutex; single lock per sign op |
| CON-03 dynamic pubkey_map race with duty polling | MEDIUM | MEDIUM | Short-lived write lock (insert only); generation counter prevents stale reads |
| COR-04 ValidatorStoreState refactor breaks readers | MEDIUM | LOW | Single RwLock swap is atomic from readers' perspective |
| DB-01 WAL migration on existing installations | LOW | LOW | WAL mode is safe to enable; backward-compatible |
| SEC-01 blst upstream changes zeroization behavior | LOW | LOW | Pin blst version; document reliance on `#[zeroize(drop)]` |
| Phase III scope (32 LOW items) | MEDIUM | MEDIUM | All P2 items independent; can defer without impact |
| LOW-03 ProposerDuty.pubkey type change ripple | MEDIUM | LOW | Internal type only; grep all callers before changing |

---

## Technical Spikes / Open Questions

1. **SEC-01 (raw_bytes removal):** Should we remove the redundant `raw_bytes` field from `SecretKey`? Reduces zeroization surface but changes the `raw_bytes()` API. Investigate callers first.

2. **COR-01 (mutex granularity):** The `ValidatorLockMap` HashMap itself uses `std::sync::Mutex`. Is this acceptable or should it use a concurrent hashmap? For typical validator counts (1-1000), `std::sync::Mutex` on HashMap is fine — the critical section is just a HashMap lookup/insert.

3. **CON-03 (duty refresh timing):** Should dynamic key changes trigger immediate duty re-poll or wait for next slot? Research recommends immediate via `watch` channel. Confirm orchestrator can handle mid-slot duty refresh without side effects.

4. **LOW-25 (async span audit scope):** The architecture identifies specific bug locations, but a full grep for `.entered()` in async contexts should be done to catch any missed instances.

5. **LOW-31 (SSE failover):** Multi-BN SSE subscription adds complexity. Should we subscribe to all BNs simultaneously or only failover on disconnect? Failover-only is simpler and sufficient.

---

## Decision Log

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Keep record-then-sign order (COR-01) | Ethereum consensus spec mandates save-before-sign. All major VCs follow this. Phantom entries are the intended safety tradeoff. |
| 2 | Per-validator mutex, not global (COR-01) | Global mutex serializes all validators. Per-validator is natural shard key with no cross-validator contention. |
| 3 | blst zeroization is sufficient (SEC-01) | Research confirmed blst >= 0.3.11 implements `#[zeroize(drop)]`. Document reliance rather than reimplementing. |
| 4 | HTTPS required by default (SEC-05) | Fail-closed security posture. HTTP allowed only with explicit `--allow-insecure-remote-signer` flag. |
| 5 | `tokio::sync::RwLock` for pubkey_map (CON-03) | Read-heavy workload (every slot) with rare writes (key import). tokio RwLock required since lock held across .await. |
| 6 | Generation counter for key change notification (CON-03) | Simpler than channel-based events. Avoids unnecessary duty refreshes when no keys changed. |
| 7 | `synchronous=FULL` not NORMAL (DB-01) | For slashing protection, data loss = potential double-signing. 1-2 writes/slot makes performance irrelevant. |
| 8 | 3 phases matching priority (P0/P1/P2) | Delivers security fixes first, then correctness, then polish. P2 can be deferred without risk. |
