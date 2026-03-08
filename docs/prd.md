# PRD: Code Review Findings Remediation (MEDIUM & LOW)

## Overview

This PRD covers remediation of ~30 MEDIUM and ~33 LOW findings from the comprehensive RVC code review conducted on 2026-03-08. All CRITICAL (C-1 through C-3) and HIGH (H-1 through H-4) findings have already been fixed in the previous bugfix sprint. This effort hardens the validator client across security, correctness, concurrency, data integrity, and code quality dimensions.

## Problem Statement

The RVC code review identified multiple MEDIUM-severity gaps in key zeroization, slashing DB durability, concurrency safety, and API hardening, alongside LOW-severity issues in edge case handling, code quality, and defensive programming. While the validator client is functionally correct after the CRITICAL/HIGH fixes, these remaining findings represent residual risk in production operation — particularly for multi-validator and multi-beacon-node deployments.

## Goals & Success Metrics

- **Primary goal:** Resolve all MEDIUM findings and high-impact LOW findings to production-ready quality
- **Success metrics:**
  - All P0/P1 items pass code review with no regressions
  - All existing tests pass (1,876+ tests, 0 failures)
  - New tests cover each fix (target: 50+ new tests across all issues)
  - `cargo clippy` clean, `cargo fmt` clean
  - No new `unsafe` blocks introduced

## Target Users

- Ethereum solo stakers running RVC with 1-100 validators
- Institutional operators running RVC with 100+ validators across multiple beacon nodes
- RVC developers maintaining and extending the codebase

## Functional Requirements

### P0 — Security-Sensitive (Must Have)

#### SEC-01: Zeroize BlstSecretKey on drop (M-1)
- **Crate:** `crypto` | **File:** `bls.rs:53-105`
- **Problem:** `BlstSecretKey` inner field is not zeroized on drop; secret key material persists in memory after use.
- **Fix:** Implement `Drop` for the wrapper type that zeroizes the inner `blst::SecretKey` bytes. If `blst` does not expose mutable access to the key bytes, wrap in `Zeroizing<[u8; 32]>` and reconstruct on use, or document the limitation with a code comment referencing the upstream constraint.
- **Acceptance criteria:**
  - `Drop` impl exists and is tested (allocate, drop, verify memory pattern)
  - If upstream limitation: doc comment + tracking issue

#### SEC-02: Zeroize derived key after keystore decrypt/encrypt (M-2, M-3)
- **Crate:** `crypto` | **File:** `keystore.rs:155-161, 371-375`
- **Problem:** Derived key bytes and plaintext secret key bytes are not wrapped in `Zeroizing<T>` in the decrypt and encrypt paths.
- **Fix:** Wrap all intermediate key material in `Zeroizing<Vec<u8>>` or `Zeroizing<[u8; 32]>`.
- **Acceptance criteria:**
  - All intermediate key variables use `Zeroizing<T>`
  - No raw `Vec<u8>` holds secret key material in keystore.rs

#### SEC-03: Path traversal check in key directory loading (M-4)
- **Crate:** `crypto` | **File:** `key_manager.rs:307`
- **Problem:** `load_from_directory_with_tracker` does not check for symlinks or path traversal (`../`), allowing reads outside the intended key directory.
- **Fix:** Canonicalize the base directory path and verify each resolved file path starts with the canonical base. Reject symlinks pointing outside the base directory.
- **Acceptance criteria:**
  - Symlinks pointing outside key directory are rejected with a warning log
  - Path traversal attempts (`../`) are rejected
  - Test: create symlink outside dir, verify rejection

#### SEC-04: Redact passwords in ImportKeystoresRequest Debug (M-5)
- **Crate:** `keymanager-api` | **File:** `types.rs:16-22`
- **Problem:** `ImportKeystoresRequest` derives `Debug`, which would print passwords to logs.
- **Fix:** Implement `Debug` manually, printing `[REDACTED]` for the `passwords` field.
- **Acceptance criteria:**
  - `Debug` output for `ImportKeystoresRequest` does not contain password values
  - Test: format with `{:?}` and assert no password substring

#### SEC-05: URL validation for remote key imports (M-6)
- **Crate:** `keymanager-api` | **File:** `handlers.rs:199-202`
- **Problem:** Remote key import accepts arbitrary URLs without validation, enabling SSRF against internal services.
- **Fix:** Validate that imported URLs use `https://` scheme (or `http://` only with an explicit `--allow-insecure-remote-signer` flag). Reject private/loopback IPs unless explicitly allowed.
- **Acceptance criteria:**
  - Non-HTTP(S) schemes rejected with 400 error
  - HTTP without flag rejected with descriptive error
  - Test: various URL schemes (ftp, file, data) rejected

#### SEC-06: CORS configuration on keymanager API (M-7)
- **Crate:** `keymanager-api` | **File:** `server.rs:45-61`
- **Problem:** No CORS headers set, allowing any origin to call the keymanager API from a browser context.
- **Fix:** Add `tower-http` CORS layer. Default to no allowed origins (localhost only). Add `--keymanager-cors-origins` CLI flag for explicit allowlist.
- **Acceptance criteria:**
  - Default: no `Access-Control-Allow-Origin` header (same-origin only)
  - With flag: only specified origins allowed
  - Preflight OPTIONS requests handled correctly

#### SEC-07: Request body size limit on keymanager endpoints (M-8)
- **Crate:** `keymanager-api` | **File:** `server.rs:45-61`
- **Problem:** No body size limit allows memory exhaustion via large POST payloads.
- **Fix:** Add `tower-http::limit::RequestBodyLimitLayer` with a default of 10 MB (configurable via `--keymanager-body-limit`).
- **Acceptance criteria:**
  - Payloads exceeding limit return 413 Payload Too Large
  - Default limit is 10 MB
  - Test: oversized payload rejected

#### SEC-08: Verify remote signer returned signature (M-9)
- **Crate:** `signer` | **File:** `remote_signer.rs:103-134`
- **Problem:** The remote signer accepts the returned signature without verifying it was produced by the expected public key. A compromised signer could return an invalid or malicious signature.
- **Fix:** After receiving the signature, verify it against the expected pubkey and signing root before returning. Log a warning and return an error on verification failure.
- **Acceptance criteria:**
  - Invalid signatures from remote signer are rejected with error log
  - Valid signatures pass through unchanged
  - Test: mock signer returns wrong signature, verify rejection

### P1 — Correctness & Reliability (Should Have)

#### COR-01: Record slashing DB after signing, not before (M-10)
- **Crate:** `signer` | **File:** `lib.rs:116-146`
- **Problem:** Slashing DB records the attestation/block before signing. If signing fails, a phantom record remains that can falsely prevent future signing.
- **Fix:** Reorder to: (1) check slashing DB, (2) sign, (3) record in slashing DB. Use a transaction or mutex to prevent TOCTOU between check and record.
- **Acceptance criteria:**
  - Failed signing does not leave phantom slashing records
  - Concurrent signing for same validator is serialized
  - Test: simulate signing failure, verify no slashing record created

#### COR-02: Add --mnemonic-passphrase to bls-to-execution (M-11)
- **Crate:** `rvc-keygen` | **File:** `bls_to_execution.rs:35`
- **Problem:** `bls-to-execution` subcommand does not accept `--mnemonic-passphrase`, making it impossible to derive correct keys for users who set a passphrase during mnemonic generation.
- **Fix:** Add `--mnemonic-passphrase` CLI argument (same as `new-mnemonic` and `existing-mnemonic`).
- **Acceptance criteria:**
  - `--mnemonic-passphrase` flag accepted and used in key derivation
  - Test: derive with passphrase matches expected BLS key

#### COR-03: reload_config removes deleted validators (M-12)
- **Crate:** `validator-store` | **File:** `store.rs:206-217`
- **Problem:** `reload_config` adds new validators and updates existing ones but never removes validators that were deleted from the config file.
- **Fix:** Compute the set difference (current keys minus new config keys) and remove stale entries.
- **Acceptance criteria:**
  - Validators removed from config are removed from in-memory store on reload
  - Test: reload with fewer validators, verify removal

#### COR-04: Atomic reload_config (M-13)
- **Crate:** `validator-store` | **File:** `store.rs:207-214`
- **Problem:** `reload_config` acquires and releases multiple locks non-atomically; a concurrent reader can observe a partially-updated state.
- **Fix:** Parse new config fully, then apply all changes under a single write lock (or use a swap pattern).
- **Acceptance criteria:**
  - Reload is atomic from readers' perspective
  - Test: concurrent read during reload sees consistent state

#### COR-05: list_keystores excludes remote keys (M-14)
- **Crate:** `keymanager-api` | **File:** `handlers.rs:27-48`
- **Problem:** `GET /eth/v1/keystores` returns remote keys mixed with local keys. The Keymanager API spec defines this endpoint for local keystores only.
- **Fix:** Filter to only locally-managed keystores. Remote keys are served via `GET /eth/v1/remotekeys`.
- **Acceptance criteria:**
  - `/eth/v1/keystores` returns only local keys
  - `/eth/v1/remotekeys` returns only remote keys
  - Test: import both types, verify correct endpoint filtering

#### COR-06: Slot validation on JSON block path (M-15)
- **Crate:** `block-service` | **File:** `service.rs:175-205`
- **Problem:** The SSZ block path validates the returned block's slot matches the requested slot, but the JSON path does not.
- **Fix:** Add the same slot validation check to the JSON path.
- **Acceptance criteria:**
  - JSON block with mismatched slot is rejected with error log
  - Test: mock beacon returns wrong-slot block, verify rejection

#### COR-07: health_scores uses actual reachability/sync status (M-16)
- **Crate:** `bn-manager` | **File:** `manager.rs:145-146`
- **Problem:** `health_scores()` hardcodes `is_reachable: true, is_synced: true` instead of using actual beacon node status.
- **Fix:** Read actual reachability and sync status from the BN health tracking state.
- **Acceptance criteria:**
  - Health scores reflect actual BN reachability and sync status
  - Test: simulate unreachable BN, verify health score reflects it

#### COR-08: Retry 429 responses (M-31)
- **Crate:** `beacon` | **File:** `client.rs:912`
- **Problem:** HTTP 429 (rate limited) is classified as a non-retryable client error. It should be retried with backoff.
- **Fix:** Add 429 to the retryable status codes, using `Retry-After` header if present.
- **Acceptance criteria:**
  - 429 responses trigger retry with backoff
  - `Retry-After` header respected when present
  - Test: mock 429 then 200, verify retry succeeds

#### COR-09: POST for large validator sets (M-32)
- **Crate:** `beacon` | **File:** `client.rs:184-191`
- **Problem:** `get_validators` uses GET with pubkeys as query parameters. Large validator sets can exceed URL length limits (~8KB).
- **Fix:** Switch to POST body when the number of validators exceeds a threshold (e.g., 50 pubkeys).
- **Acceptance criteria:**
  - Small validator sets use GET (backward compatible)
  - Large validator sets use POST
  - Test: 100+ validators uses POST path

### P1 — Concurrency & Timing

#### CON-01: Spawn builder registration off main loop (M-17)
- **Crate:** `rvc` (orchestrator) | **File:** `service.rs:350-352`
- **Problem:** Builder registration runs synchronously in the main slot loop, blocking for up to 40 seconds at epoch boundaries.
- **Fix:** Spawn builder registration as a background task with its own timeout. Do not block slot processing.
- **Acceptance criteria:**
  - Builder registration runs in background tokio task
  - Main loop slot processing is not blocked
  - Test: verify slot processing proceeds while registration runs

#### CON-02: Use SlotClock for phase 3 timing (M-18)
- **Crate:** `rvc` (orchestrator) | **File:** `service.rs:313-319`
- **Problem:** Phase 3 timing uses `SystemTime::now()` directly instead of the `SlotClock` abstraction. Clock skew or mock clocks in tests won't be respected.
- **Fix:** Replace `SystemTime::now()` with `slot_clock.now()` or equivalent.
- **Acceptance criteria:**
  - Phase 3 timing uses SlotClock
  - Test: mock clock works for phase 3

#### CON-03: Make pubkey_map dynamic (M-19)
- **Crate:** `rvc` (main) | **File:** `main.rs:711`
- **Problem:** `pubkey_map` is built once at startup and never updated. Keys added via keymanager API at runtime are invisible to the orchestrator.
- **Fix:** Replace with a shared `Arc<RwLock<HashMap>>` that is updated when keys are added/removed via keymanager API.
- **Acceptance criteria:**
  - Dynamically imported keys appear in pubkey_map
  - Deleted keys are removed from pubkey_map
  - Test: import key via API, verify it appears in duties

#### CON-04: Reduce write lock scope in query_first (M-21)
- **Crate:** `bn-manager` | **File:** `manager.rs:291,303`
- **Problem:** A write lock is acquired per-BN attempt in `query_first`, the hottest path. This serializes all concurrent beacon node queries.
- **Fix:** Collect results, then acquire write lock once to update health scores.
- **Acceptance criteria:**
  - Write lock acquired at most once per `query_first` call
  - Concurrent queries are not serialized
  - Test: concurrent query_first calls don't deadlock

#### CON-05: Record health for fallback attempts (M-22)
- **Crate:** `bn-manager` | **File:** `manager.rs:498-520`
- **Problem:** `fallback_unsynced` does not update health scores for fallback beacon node attempts, skewing the health-based ranking.
- **Fix:** Record success/failure health data for fallback attempts same as primary attempts.
- **Acceptance criteria:**
  - Fallback BN health scores update on success/failure
  - Test: fallback attempt updates health metrics

#### CON-06: SSE counter reset with BN health verification (M-23)
- **Crate:** `bn-manager` | **File:** `sse.rs:159`
- **Problem:** SSE reconnection counter resets without verifying the beacon node has actually recovered, enabling infinite rapid reconnection loops.
- **Fix:** Only reset counter after receiving at least one valid SSE event post-reconnect.
- **Acceptance criteria:**
  - Counter resets only after successful event reception
  - Test: reconnect without events does not reset counter

### P1 — Database & Data Integrity

#### DB-01: SQLite durability settings (M-24)
- **Crate:** `slashing` | **File:** `db.rs:27-36`
- **Problem:** Missing `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=FULL`. Default journal mode risks corruption on power loss; default synchronous level may lose committed transactions.
- **Fix:** Set pragmas on connection open: `journal_mode=WAL`, `synchronous=FULL`.
- **Acceptance criteria:**
  - Pragmas set on every DB connection
  - Test: open DB, query pragmas, verify values

#### DB-02: Transactional EIP-3076 import (M-25)
- **Crate:** `slashing` | **File:** `db.rs:362-409`
- **Problem:** EIP-3076 interchange import is not wrapped in a single transaction. Partial imports on failure leave the DB in an inconsistent state.
- **Fix:** Wrap the entire import in a single SQLite transaction. Rollback on any error.
- **Acceptance criteria:**
  - Partial import failure rolls back all changes
  - Successful import commits atomically
  - Test: import with intentional mid-import error, verify no partial records

#### DB-03: Reconcile is_safe_to_sign/propose with atomic variants (M-26)
- **Crate:** `slashing` | **File:** `db.rs:202-302`
- **Problem:** Standalone `is_safe_to_sign` and `is_safe_to_propose` have subtly different logic from their atomic `check_and_record_*` counterparts, leading to potential inconsistencies.
- **Fix:** Either remove the standalone variants (if unused) or refactor both pairs to share the same core check logic.
- **Acceptance criteria:**
  - Single source of truth for slashing check logic
  - Test: both paths produce identical results for same inputs

### P1 — Other

#### OTH-01: Sub-second attestation delay metric (M-28)
- **Crate:** `timing` | **File:** `timer.rs:136-143`
- **Problem:** Attestation delay metric truncates to whole seconds, losing sub-second precision critical for monitoring attestation timeliness.
- **Fix:** Use `.as_secs_f64()` or `.as_millis()` instead of `.as_secs()`.
- **Acceptance criteria:**
  - Metric captures sub-second precision
  - Test: 500ms delay recorded as 0.5, not 0

#### OTH-02: Guard against division-by-zero in slot clock (M-29)
- **Crate:** `timing` | **File:** `clock.rs:61`
- **Problem:** Division by `slot_duration` panics if duration is zero (misconfiguration).
- **Fix:** Validate `slot_duration >= 1` at construction time, return error instead of panic.
- **Acceptance criteria:**
  - `SlotClock::new` with zero duration returns `Err`
  - Test: zero duration construction fails gracefully

#### OTH-03: Handle Arc::try_unwrap failure gracefully (M-30)
- **Crate:** `rvc` (main) | **File:** `main.rs:681,714`
- **Problem:** `Arc::try_unwrap().unwrap()` panics if other references exist during shutdown.
- **Fix:** Use `Arc::try_unwrap().unwrap_or_else(|arc| (*arc).clone())` or restructure to ensure unique ownership at shutdown.
- **Acceptance criteria:**
  - Shutdown does not panic on multi-reference Arc
  - Test: shutdown with outstanding references completes cleanly

#### OTH-04: Deduplicate format detection logic (M-27)
- **Crate:** `secret-provider` | **File:** `gcp.rs:92-103`
- **Problem:** Key format detection logic is duplicated between `gcp.rs` and `format.rs`.
- **Fix:** Consolidate into `format.rs` and call from `gcp.rs`.
- **Acceptance criteria:**
  - Single format detection implementation
  - No logic duplication between files

#### OTH-05: TOCTOU in dependent root change detection (M-20)
- **Crate:** `duty-tracker` | **File:** `tracker.rs:169-219`
- **Problem:** Time-of-check to time-of-use race between reading the dependent root and acting on it. A concurrent update can be missed.
- **Fix:** Use compare-and-swap or hold the lock through the check-and-update sequence.
- **Acceptance criteria:**
  - Root check and update are atomic
  - Test: concurrent root updates don't cause missed duty refreshes

### P2 — Code Quality & Hardening (Nice to Have)

#### LOW-01: Signature Vec<u8> length validation (L-1)
- Validate signature byte length (96 bytes) at deserialization boundaries.

#### LOW-02: Deduplicate vec_u8_tree_hash_root (L-2)
- Extract shared utility function, remove copies from 3 files.

#### LOW-03: ProposerDuty.pubkey typed as [u8; 48] (L-3)
- Replace `String` with `[u8; 48]` for type-safe pubkey handling.

#### LOW-04: BlockContents serde error context (L-4)
- Replace untagged enum with explicit variant tagging or error wrapping.

#### LOW-05: Zeroize num-bigint intermediates in EIP-2333 (L-5)
- Wrap BigInt intermediates or clear after use (best-effort, BigInt may not support zeroize).

#### LOW-06: Warn on plaintext HTTP for remote signer (L-6)
- Log warning when remote signer URL uses `http://` without `--allow-insecure-remote-signer`.

#### LOW-07: Handle RwLock poisoning gracefully (L-7, L-22)
- Replace `.unwrap()` on `RwLock::read()/write()` with `.expect("context")` or recovery logic in CompositeSigner and ValidatorStore.

#### LOW-08: SecretString for directory password loading (L-8)
- Replace `String` passwords with `secrecy::SecretString` in `load_from_directory_with_tracker`.

#### LOW-09: Zeroize keymanager token (L-9)
- Replace `Arc<String>` with `Arc<Zeroizing<String>>` for bearer token storage.

#### LOW-10: Atomic token file creation (L-10)
- Replace `create(true).truncate(true)` with `create_new(true)` + rename pattern to avoid TOCTOU.

#### LOW-11: Consistent Fork/ForkSchedule parameter (L-11)
- Align `sign_attestation` to take `ForkSchedule` like all other signing methods.

#### LOW-12: Sanitize remote signer error responses (L-12)
- Strip or redact server error details before logging to prevent information leakage.

#### LOW-13: Validate interchange_format_version on import (L-13)
- Check `interchange_format_version == "5"` per EIP-3076.

#### LOW-14: Normalize pubkeys in slashing DB (L-14)
- Lowercase and 0x-prefix all pubkeys on insert/query to prevent case-sensitivity bypass.

#### LOW-15: Transactional set_block_watermark (L-15)
- Wrap watermark update in a transaction.

#### LOW-16: Make insert_attestation/insert_block non-public (L-16)
- Restrict visibility to `pub(crate)` to prevent bypassing slashing checks.

#### LOW-17: Set file permissions on DB creation (L-17)
- Set `0o600` permissions at creation time, not just checked after.

#### LOW-18: Remove unused concurrency_limit field (L-18)
- Delete the field or wire it to actual concurrency control.

#### LOW-19: Zeroize hex-decoded intermediate in format.rs (L-19)
- Wrap decoded bytes in `Zeroizing<Vec<u8>>`.

#### LOW-20: Zeroize fetch_companion_password copy (L-20)
- Avoid `.to_vec()` copy or wrap in `Zeroizing`.

#### LOW-21: Per-fetch timeout in RefreshService (L-21)
- Add per-key-fetch timeout (default 30s) to prevent hung refresh cycles.

#### LOW-22: Integer overflow guard in keygen (L-23)
- Check `start_index + num_validators` for overflow before iteration.

#### LOW-23: EIP-55 checksum validation on withdrawal address (L-24)
- Validate mixed-case addresses against EIP-55 checksum.

#### LOW-24: Atomic deposit file creation (L-25)
- Use `create_new` instead of `truncate(true)` to prevent overwriting existing deposits.

#### LOW-25: Fix span.enter() in async code (L-26)
- Replace `span.enter()` with `.instrument(span)` in doppelganger and orchestrator async code.

#### LOW-26: Use tokio::sync::RwLock in BuilderService (L-27)
- Replace `std::sync::RwLock` with `tokio::sync::RwLock` in async context.

#### LOW-27: Graceful batch signing failure in sync-service (L-28)
- Continue producing sync messages for other validators when one signing fails.

#### LOW-28: Add jitter to retry backoff (L-29)
- Add randomized jitter to prevent synchronized retry storms across validators.

#### LOW-29: Reject invalid network values (L-30)
- Return error instead of silent `None` fallback on invalid network string.

#### LOW-30: Guard against committee_length=0 (L-31)
- Return error instead of panicking when `committee_length` is 0.

#### LOW-31: SSE failover to secondary BN (L-32)
- Subscribe to SSE from backup beacon nodes when primary disconnects.

#### LOW-32: Remove unused metrics (L-33)
- Delete metrics that are defined but never recorded.

## Non-Functional Requirements

- **Performance:** No regression in slot processing latency (< 100ms per slot cycle)
- **Backward compatibility:** No breaking changes to CLI flags, config format, or keymanager API
- **Test coverage:** Each fix must include at least one targeted test
- **Code quality:** `cargo clippy` clean, `cargo fmt` clean, no new warnings

## Technical Considerations

- **Zeroization (SEC-01/02):** `blst` crate may not expose mutable access to secret key internals. If so, document the limitation and track upstream.
- **Slashing DB ordering (COR-01):** Reordering sign-then-record requires careful concurrency handling to prevent double-signing between check and record.
- **pubkey_map (CON-03):** Making this dynamic has implications for the orchestrator's duty assignment flow; ensure no race between key addition and duty poll.
- **SQLite WAL mode (DB-01):** WAL mode changes are persistent per database file. Existing installations will be migrated on first connection.

## Out of Scope

- CRITICAL findings C-1 through C-3 (already fixed)
- HIGH findings H-1 through H-4 (already fixed)
- Architectural refactoring or crate restructuring
- New feature development
- Performance optimization beyond fixing identified issues
- UI/UX changes (RVC is a CLI tool)

## Open Questions

1. **SEC-01 (BlstSecretKey zeroization):** Does the `blst` crate provide any mechanism to access/clear the inner key bytes? If not, what is the acceptable documentation-only resolution?
2. **COR-01 (Sign-then-record ordering):** Should we use a per-validator mutex or a broader serialization strategy for the check-sign-record sequence?
3. **CON-03 (Dynamic pubkey_map):** Should dynamic key changes trigger an immediate duty re-poll, or wait for the next natural epoch boundary?

## Milestones & Phases

### Phase 1: Security & Data Integrity (P0)
- SEC-01 through SEC-08 (9 issues)
- DB-01 through DB-03 (3 issues)
- **Target:** ~30 story points

### Phase 2: Correctness & Reliability (P1)
- COR-01 through COR-09 (9 issues)
- CON-01 through CON-06 (6 issues)
- OTH-01 through OTH-05 (5 issues)
- **Target:** ~35 story points

### Phase 3: Code Quality & Hardening (P2)
- LOW-01 through LOW-32 (32 issues)
- **Target:** ~30 story points

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| COR-01 sign-then-record introduces TOCTOU for double-sign | HIGH | MEDIUM | Use per-validator mutex; extensive concurrent signing tests |
| SEC-01 blst upstream doesn't support zeroization | MEDIUM | HIGH | Document limitation; open upstream issue; defense-in-depth with process memory protections |
| CON-03 dynamic pubkey_map race with duty polling | MEDIUM | MEDIUM | Use RwLock with duty-refresh trigger on key change |
| DB-01 WAL migration on existing installations | LOW | LOW | WAL mode is safe to enable; test migration path |
| Large scope (~95 story points) causes timeline slip | MEDIUM | MEDIUM | Strict phasing; P2 items can be deferred without impact |
