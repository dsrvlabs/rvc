# Phase 3: Code Quality & Hardening (P2)

## Phase Overview
- **Goal:** Address all LOW findings for edge case handling, code quality, async correctness, and defensive programming
- **Issue count:** 32 issues + 1 integration verification, 37 total points
- **Estimated duration:** 7 days (with 2 parallel streams)
- **Entry criteria:** Phase 2 complete, all COR/CON/OTH issues merged
- **Exit criteria:** All LOW-01–LOW-32 merged, no async span bugs, all RwLock poisoning handled, all intermediate key material zeroized

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | Crate |
|-------|-------|--------|--------|------------|-------|
| LOW-01 | Signature Vec<u8> length validation | 1 | A | — | eth-types |
| LOW-02 | Deduplicate vec_u8_tree_hash_root | 1 | A | — | eth-types |
| LOW-03 | ProposerDuty.pubkey typed as [u8; 48] | 2 | A | — | eth-types |
| LOW-04 | BlockContents serde error context | 1 | A | — | eth-types |
| LOW-05 | Zeroize num-bigint intermediates in EIP-2333 | 1 | A | — | crypto |
| LOW-07 | Handle RwLock poisoning gracefully | 1 | A | — | crypto, validator-store |
| LOW-08 | SecretString for directory password loading | 1 | A | — | crypto |
| LOW-13 | Validate interchange_format_version on import | 1 | A | — | slashing |
| LOW-14 | Normalize pubkeys in slashing DB | 1 | A | — | slashing |
| LOW-15 | Transactional set_block_watermark | 1 | A | — | slashing |
| LOW-16 | Make insert_attestation/insert_block non-public | 1 | A | — | slashing |
| LOW-17 | Set file permissions on DB creation | 1 | A | — | slashing |
| LOW-22 | Integer overflow guard in keygen | 1 | A | — | rvc-keygen |
| LOW-23 | EIP-55 checksum validation on withdrawal address | 1 | A | — | rvc-keygen |
| LOW-24 | Atomic deposit file creation | 1 | A | — | rvc-keygen |
| LOW-06 | Warn on plaintext HTTP for remote signer | 1 | B | — | crypto |
| LOW-09 | Zeroize keymanager token | 1 | B | — | keymanager-api |
| LOW-10 | Atomic token file creation | 1 | B | — | keymanager-api |
| LOW-11 | Consistent Fork/ForkSchedule parameter | 1 | B | — | signer |
| LOW-12 | Sanitize remote signer error responses | 1 | B | — | signer |
| LOW-18 | Remove unused concurrency_limit field | 1 | B | — | secret-provider |
| LOW-19 | Zeroize hex-decoded intermediate in format.rs | 1 | B | — | secret-provider |
| LOW-20 | Zeroize fetch_companion_password copy | 1 | B | — | secret-provider |
| LOW-21 | Per-fetch timeout in RefreshService | 1 | B | — | secret-provider |
| LOW-25 | Fix span.enter() in async code | 2 | B | — | doppelganger, rvc, keymanager-api |
| LOW-26 | Use tokio::sync::RwLock in BuilderService | 1 | B | — | builder |
| LOW-27 | Graceful batch signing failure in sync-service | 1 | B | — | sync-service |
| LOW-28 | Add jitter to retry backoff | 1 | B | — | beacon |
| LOW-29 | Reject invalid network values | 1 | B | — | rvc (main) |
| LOW-30 | Guard against committee_length=0 | 1 | B | — | rvc (orchestrator) |
| LOW-31 | SSE failover to secondary BN | 2 | B | — | bn-manager |
| LOW-32 | Remove unused metrics | 1 | B | — | bn-manager |
| III-JOINT | Phase 3 integration verification | 2 | both | all above | — |

## Phase Parallel Plan

| Day | Stream A (Types, Zeroization, Slashing, Keygen) | Stream B (Async, Concurrency, API) |
|-----|-----|-----|
| 1 | LOW-01 (1), LOW-02 (1), LOW-04 (1) | LOW-06 (1), LOW-09 (1), LOW-10 (1) |
| 2 | LOW-03 (2), LOW-05 (1) | LOW-11 (1), LOW-12 (1), LOW-18 (1) |
| 3 | LOW-07 (1), LOW-08 (1), LOW-13 (1) | LOW-19 (1), LOW-20 (1), LOW-21 (1) |
| 4 | LOW-14 (1), LOW-15 (1), LOW-16 (1), LOW-17 (1) | LOW-25 (2), LOW-26 (1) |
| 5 | LOW-22 (1), LOW-23 (1), LOW-24 (1) | LOW-27 (1), LOW-28 (1), LOW-29 (1) |
| 6 | (buffer) | LOW-30 (1), LOW-31 (2), LOW-32 (1) |
| 7 | III-JOINT | III-JOINT |

---

## Issues

### Issue LOW-01: Signature Vec<u8> length validation
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Validate signature byte length (96 bytes) at deserialization boundaries to catch malformed data early.

**Implementation Notes:**
- Files likely affected: `crates/eth-types/src/` — signature deserialization points
- Add length check: `if bytes.len() != 96 { return Err(...) }`
- Check serde deserializer for `Signature` type

**Acceptance Criteria:**
- [ ] Signature bytes validated as 96 bytes at deserialization
- [ ] Invalid length returns descriptive error
- [ ] Test: 95-byte and 97-byte signatures rejected

---

### Issue LOW-02: Deduplicate vec_u8_tree_hash_root
- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
`vec_u8_tree_hash_root` utility function is duplicated across 3 files.

**Implementation Notes:**
- Extract shared utility into `crates/eth-types/src/` (e.g., `tree_hash_utils.rs`)
- Replace copies in all 3 files with imports

**Acceptance Criteria:**
- [ ] Single implementation of `vec_u8_tree_hash_root`
- [ ] All 3 files import from shared location
- [ ] All existing tree hash tests pass

---

### Issue LOW-03: ProposerDuty.pubkey typed as [u8; 48]
- **Points:** 2
- **Type:** chore
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Replace `String` with `[u8; 48]` for type-safe pubkey handling in `ProposerDuty`.

**Implementation Notes:**
- Files likely affected: `crates/eth-types/src/` — `ProposerDuty` definition
- Grep all callers of `ProposerDuty.pubkey` before changing
- Add hex serde for `[u8; 48]` (may already exist via existing serde helpers)
- Higher points due to potential ripple effect across multiple crates

**Acceptance Criteria:**
- [ ] `ProposerDuty.pubkey` is `[u8; 48]` not `String`
- [ ] Hex serde serialization/deserialization works correctly
- [ ] All callers updated
- [ ] All existing tests pass

---

### Issue LOW-04: BlockContents serde error context
- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
`BlockContents` untagged enum loses error context during serde deserialization.

**Implementation Notes:**
- Replace untagged enum with explicit variant tagging or add error wrapping with context

**Acceptance Criteria:**
- [ ] Serde errors for `BlockContents` include variant-specific context
- [ ] Deserialization still works for all variants
- [ ] Test: invalid JSON produces descriptive error message

---

### Issue LOW-05: Zeroize num-bigint intermediates in EIP-2333
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Best-effort zeroization of `num-bigint` `BigInt` intermediates in EIP-2333 key derivation.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/eip2333.rs`
- `BigInt` may not implement `Zeroize` — if so, document the limitation with a comment
- Where possible, use fixed-size arrays instead of BigInt for intermediate values

**Acceptance Criteria:**
- [ ] BigInt intermediates zeroized where supported, or limitation documented
- [ ] Doc comment explaining upstream constraint if zeroization not possible
- [ ] All existing EIP-2333 tests pass

---

### Issue LOW-07: Handle RwLock poisoning gracefully
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Replace `.unwrap()` on `RwLock::read()/write()` with `.expect("context")` or recovery logic.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/` (CompositeSigner), `crates/validator-store/src/store.rs`
- Replace all `.unwrap()` on lock acquisitions with `.expect("descriptive context")`
- Grep for `.read().unwrap()` and `.write().unwrap()` across both crates

**Acceptance Criteria:**
- [ ] All `RwLock::read().unwrap()` replaced with `.expect("context")`
- [ ] All `RwLock::write().unwrap()` replaced with `.expect("context")`
- [ ] Context messages describe which lock and operation

---

### Issue LOW-08: SecretString for directory password loading
- **Points:** 1
- **Type:** security
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Replace `String` passwords with `secrecy::SecretString` in `load_from_directory_with_tracker`.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/key_manager.rs`
- `secrecy` is already a workspace dependency
- Replace `String` → `SecretString` for password variables
- Use `.expose_secret()` only where the raw string is needed

**Acceptance Criteria:**
- [ ] Password variables use `SecretString` not `String`
- [ ] `SecretString` zeroized on drop (automatic via secrecy crate)
- [ ] All existing tests pass

---

### Issue LOW-13: Validate interchange_format_version on import
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Check `interchange_format_version == "5"` per EIP-3076 specification on import.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (import method)
- Add check at the start of import: `if version != "5" { return Err(...) }`

**Acceptance Criteria:**
- [ ] Version "5" accepted
- [ ] Other versions (e.g., "4", "6") rejected with descriptive error
- [ ] Test: import with version "4" returns error

---

### Issue LOW-14: Normalize pubkeys in slashing DB
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Lowercase and 0x-prefix all pubkeys on insert and query to prevent case-sensitivity bypass.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs`
- Add normalization helper: `fn normalize_pubkey(pk: &str) -> String`
- Call on all insert and query paths

**Acceptance Criteria:**
- [ ] Pubkeys normalized to lowercase + 0x-prefix on insert
- [ ] Queries use normalized pubkeys
- [ ] Test: insert with uppercase, query with lowercase → found
- [ ] Test: insert without 0x prefix, query with 0x prefix → found

---

### Issue LOW-15: Transactional set_block_watermark
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Wrap `set_block_watermark` update in a transaction for consistency.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs`
- Wrap in `conn.transaction_with_behavior(TransactionBehavior::Immediate)`

**Acceptance Criteria:**
- [ ] Watermark update is transactional
- [ ] All existing tests pass

---

### Issue LOW-16: Make insert_attestation/insert_block non-public
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Restrict `insert_attestation` and `insert_block` visibility to `pub(crate)` to prevent external callers from bypassing slashing checks.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs`
- Change `pub fn insert_attestation` → `pub(crate) fn insert_attestation`
- Change `pub fn insert_block` → `pub(crate) fn insert_block`
- Verify no external callers exist (grep across workspace)

**Acceptance Criteria:**
- [ ] Both methods are `pub(crate)`
- [ ] No external callers broken (compile check)
- [ ] All existing tests pass (tests within crate still have access)

---

### Issue LOW-17: Set file permissions on DB creation
- **Points:** 1
- **Type:** security
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Set `0o600` permissions at DB creation time, not just checked after.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs`
- After `Connection::open()`, set file permissions immediately
- Use `std::fs::set_permissions` with `Permissions::from_mode(0o600)`

**Acceptance Criteria:**
- [ ] DB file created with `0o600` permissions
- [ ] Test: create DB, verify file permissions are 0o600

---

### Issue LOW-22: Integer overflow guard in keygen
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Check `start_index + num_validators` for overflow before iteration.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/` (relevant subcommand)
- Use `.checked_add()` and return error on overflow

**Acceptance Criteria:**
- [ ] `start_index.checked_add(num_validators)` used
- [ ] Overflow returns descriptive error
- [ ] Test: `u32::MAX - 1 + 5` returns error

---

### Issue LOW-23: EIP-55 checksum validation on withdrawal address
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Validate mixed-case Ethereum addresses against EIP-55 checksum.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/` (withdrawal address parsing)
- Implement EIP-55 checksum validation (keccak256 of lowercase hex → check case against hash)
- Accept lowercase-only addresses without checksum validation

**Acceptance Criteria:**
- [ ] Mixed-case addresses validated against EIP-55
- [ ] Invalid checksum rejected with descriptive error
- [ ] Lowercase addresses accepted (no checksum applied)
- [ ] Test: valid EIP-55 address accepted
- [ ] Test: invalid EIP-55 address rejected

---

### Issue LOW-24: Atomic deposit file creation
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none

**Description:**
Use `create_new` instead of `truncate(true)` to prevent overwriting existing deposit files.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/` (deposit file writing)
- Replace `OpenOptions::new().create(true).truncate(true)` with `.create_new(true)`
- `create_new` fails if file exists, preventing accidental overwrite

**Acceptance Criteria:**
- [ ] New deposits create file with `create_new`
- [ ] Existing file causes error (not silent overwrite)
- [ ] Test: create deposit, attempt again → error

---

### Issue LOW-06: Warn on plaintext HTTP for remote signer
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Log warning when remote signer URL uses `http://` without `--allow-insecure-remote-signer`.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/remote_signer.rs`
- May already be handled by SEC-05 URL validation; verify and add if not
- Add `warn!("Remote signer URL uses plaintext HTTP — consider using HTTPS")` at construction time

**Acceptance Criteria:**
- [ ] WARN log emitted when HTTP URL used for remote signer
- [ ] No warning for HTTPS URLs
- [ ] Test: construct with HTTP URL → verify WARN logged

---

### Issue LOW-09: Zeroize keymanager token
- **Points:** 1
- **Type:** security
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Replace `Arc<String>` with `Arc<Zeroizing<String>>` for bearer token storage.

**Implementation Notes:**
- Files likely affected: `crates/keymanager-api/src/` (token storage, auth module)
- `zeroize` is already a workspace dependency
- Update all token references to use `Zeroizing<String>`

**Acceptance Criteria:**
- [ ] Token stored in `Arc<Zeroizing<String>>`
- [ ] Token zeroized on drop
- [ ] Constant-time comparison still works with `Zeroizing` wrapper
- [ ] All existing auth tests pass

---

### Issue LOW-10: Atomic token file creation
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Replace `create(true).truncate(true)` with `create_new(true)` + rename pattern for TOCTOU-safe token file creation.

**Implementation Notes:**
- Files likely affected: `crates/keymanager-api/src/` (token file writing)
- Pattern: write to temp file → `fs::rename` to final path (atomic on same filesystem)

**Acceptance Criteria:**
- [ ] Token file creation is atomic (write-then-rename)
- [ ] No TOCTOU window between check and write
- [ ] Test: concurrent token file creation doesn't corrupt

---

### Issue LOW-11: Consistent Fork/ForkSchedule parameter
- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Align `sign_attestation` to take `ForkSchedule` like all other signing methods.

**Implementation Notes:**
- Files likely affected: `crates/signer/src/lib.rs`
- Change `sign_attestation(fork: Fork, ...)` to `sign_attestation(fork_schedule: &ForkSchedule, ...)`
- Internal API only — update all callers

**Acceptance Criteria:**
- [ ] `sign_attestation` takes `ForkSchedule` parameter
- [ ] All callers updated
- [ ] All existing tests pass

---

### Issue LOW-12: Sanitize remote signer error responses
- **Points:** 1
- **Type:** security
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Strip or redact server error details from remote signer responses before logging to prevent information leakage.

**Implementation Notes:**
- Files likely affected: `crates/signer/src/` or `crates/crypto/src/remote_signer.rs`
- Truncate error body to max 200 chars, strip any HTML/stack traces

**Acceptance Criteria:**
- [ ] Server error details truncated/redacted in logs
- [ ] Error type (status code) still visible
- [ ] Test: long error response truncated in log output

---

### Issue LOW-18: Remove unused concurrency_limit field
- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Delete the unused `concurrency_limit` config field from `secret-provider` or wire it to actual concurrency control.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/` (config struct)
- Grep for usage — if unused, delete; if partially wired, complete the wiring

**Acceptance Criteria:**
- [ ] Field removed (if unused) or wired to actual concurrency control
- [ ] No dead code

---

### Issue LOW-19: Zeroize hex-decoded intermediate in format.rs
- **Points:** 1
- **Type:** security
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Wrap hex-decoded bytes in `Zeroizing<Vec<u8>>` in `format.rs`.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/format.rs`
- Wrap: `let decoded = Zeroizing::new(hex::decode(...)?)`

**Acceptance Criteria:**
- [ ] Hex-decoded intermediate wrapped in `Zeroizing<Vec<u8>>`
- [ ] All existing format tests pass

---

### Issue LOW-20: Zeroize fetch_companion_password copy
- **Points:** 1
- **Type:** security
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Avoid `.to_vec()` copy of password or wrap in `Zeroizing`.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/` (password fetching)
- Wrap the copy in `Zeroizing::new(password.to_vec())`

**Acceptance Criteria:**
- [ ] Password copy wrapped in `Zeroizing`
- [ ] All existing tests pass

---

### Issue LOW-21: Per-fetch timeout in RefreshService
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Add per-key-fetch timeout (default 30s) to prevent hung refresh cycles.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/` (RefreshService)
- Wrap each key fetch in `tokio::time::timeout(Duration::from_secs(30), ...)`

**Acceptance Criteria:**
- [ ] Each key fetch has 30s timeout
- [ ] Timeout produces WARN log, continues with next key
- [ ] Test: mock slow provider, verify timeout triggers

---

### Issue LOW-25: Fix span.enter() in async code
- **Points:** 2
- **Type:** bug
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Replace `span.enter()` / `.entered()` with `.instrument(span)` in async code. Using `span.enter()` across `.await` points produces incorrect traces.

**Implementation Notes:**
- Files likely affected:
  - `crates/doppelganger/src/service.rs` (line ~134) — `.enter()` in async loop → **BUG**
  - `crates/rvc/src/orchestrator/service.rs` (lines ~233, 242, 251, 261, 311) — `.entered()` wrapping code with `.await` → **BUG**
  - `crates/keymanager-api/src/handlers.rs` (lines ~59, 113, 195, 243) — `.entered()` in async handlers → **BUG**
- Leave correct usages alone:
  - `crates/signer/src/lib.rs:117,180` — `.entered()` around sync `check_and_record` (no `.await` inside) — **CORRECT**
- Replacement patterns:
  - `#[tracing::instrument]` on async functions
  - `.instrument(span)` on futures
  - `span.in_scope(|| sync_code())` for sync closures in async

**Acceptance Criteria:**
- [ ] No `span.enter()` or `.entered()` in scopes containing `.await`
- [ ] All async spans use `.instrument()` or `#[tracing::instrument]`
- [ ] Sync-only scopes (signer lib.rs) left unchanged (they are correct)
- [ ] Test: grep confirms no `.entered()` in async code with `.await`
- [ ] All existing tracing tests pass

---

### Issue LOW-26: Use tokio::sync::RwLock in BuilderService
- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Replace `std::sync::RwLock` with `tokio::sync::RwLock` in async `BuilderService` context.

**Implementation Notes:**
- Files likely affected: `crates/builder/src/service.rs` (line ~36 and ~51)
- Straightforward swap of lock type
- Change `.read().unwrap()` → `.read().await` and `.write().unwrap()` → `.write().await`

**Acceptance Criteria:**
- [ ] `tokio::sync::RwLock` used instead of `std::sync::RwLock`
- [ ] All lock acquisitions use `.await`
- [ ] All existing builder tests pass

---

### Issue LOW-27: Graceful batch signing failure in sync-service
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Continue producing sync committee messages for other validators when one signing fails.

**Implementation Notes:**
- Files likely affected: `crates/sync-service/src/lib.rs`
- Collect errors per-validator, log each, return partial results instead of failing entire batch

**Acceptance Criteria:**
- [ ] Single validator signing failure does not stop other validators
- [ ] Per-validator errors logged at WARN
- [ ] Successfully signed messages are still submitted
- [ ] Test: 3 validators, middle one fails → 2 messages produced

---

### Issue LOW-28: Add jitter to retry backoff
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Add randomized jitter to prevent synchronized retry storms across validators.

**Implementation Notes:**
- Files likely affected: `crates/beacon/src/client.rs` (`calculate_backoff` function, line ~1118-1124)
- Add ±25% jitter:
  ```rust
  let jitter_range = base.as_millis() as u64 / 4;
  // Add random offset in [0, jitter_range*2], then subtract jitter_range
  ```
- Requires `rand` crate (likely already available)

**Acceptance Criteria:**
- [ ] Backoff includes random jitter (±25% of base delay)
- [ ] Jitter is non-negative after application (floor at 0)
- [ ] Test: multiple calls to `calculate_backoff` with same attempt produce different durations

---

### Issue LOW-29: Reject invalid network values
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Return error instead of silent `None` fallback on invalid network string.

**Implementation Notes:**
- Files likely affected: `bin/rvc/src/main.rs` or network config parsing
- Replace silent fallback with explicit error message listing valid networks

**Acceptance Criteria:**
- [ ] Invalid network string returns descriptive error
- [ ] Error lists valid network values
- [ ] Test: invalid network → error with list of valid options

---

### Issue LOW-30: Guard against committee_length=0
- **Points:** 1
- **Type:** hardening
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Return error instead of panicking when `committee_length` is 0 in `make_aggregation_bits`.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/orchestrator/` or `crates/eth-types/`
- Add check: `if committee_length == 0 { return Err(...) }`

**Acceptance Criteria:**
- [ ] `committee_length=0` returns error instead of panic
- [ ] Test: `make_aggregation_bits` with `committee_length=0` → error

---

### Issue LOW-31: SSE failover to secondary BN
- **Points:** 2
- **Type:** feature
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Subscribe to SSE from backup beacon nodes when primary disconnects.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/sse.rs`
- On primary disconnect (max consecutive failures), attempt SSE subscription to next BN in health-sorted order
- Failover-only (not simultaneous multi-BN subscription)
- Return to primary when it recovers

**Acceptance Criteria:**
- [ ] Primary disconnect triggers SSE subscription to next-best BN
- [ ] Returns to primary when it recovers
- [ ] Test: primary disconnects → SSE moves to secondary

---

### Issue LOW-32: Remove unused metrics
- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none

**Description:**
Delete metrics that are defined but never recorded.

**Implementation Notes:**
- Grep for metric definitions, cross-reference with recording calls
- Delete any metrics that are defined but never incremented/observed
- May span multiple crates

**Acceptance Criteria:**
- [ ] No metrics defined but never recorded
- [ ] All remaining metrics have at least one recording site
- [ ] `cargo build` succeeds (no unused import warnings)

---

### Issue III-JOINT: Phase 3 integration verification
- **Points:** 2
- **Type:** chore
- **Priority:** P2
- **Stream:** both
- **Blocked by:** all Phase 3 issues
- **Blocks:** none
- **Scope:** 1 day

**Description:**
Verify all Phase 3 changes integrate correctly.

**Implementation Notes:**
- Run: `cargo test` (all tests must pass)
- Run: `cargo clippy` (must be clean)
- Run: `cargo fmt --check` (must be clean)
- Grep audits:
  1. No `span.enter()` / `.entered()` in async code with `.await`
  2. No raw `Vec<u8>` holding secret key material (should be `Zeroizing<Vec<u8>>`)
  3. No `.unwrap()` on `RwLock::read()/write()` without context
  4. No `pub fn insert_attestation` / `pub fn insert_block` (should be `pub(crate)`)

**Acceptance Criteria:**
- [ ] All tests pass (0 failures)
- [ ] `cargo clippy` clean
- [ ] `cargo fmt --check` clean
- [ ] All grep audits pass
- [ ] ~15 new tests added across Phase 3
- [ ] Total test count: 1,950+ tests
