# Phase 1: Security & Data Integrity (P0)

## Phase Overview
- **Goal:** Close all security-sensitive gaps in key material handling, API hardening, and database durability
- **Issue count:** 11 issues + 1 integration verification, 24 total points
- **Estimated duration:** 5 days (with 2 parallel streams)
- **Entry criteria:** All CRITICAL/HIGH findings fixed (develop HEAD: `e5dfa55`), 1,876 tests passing
- **Exit criteria:** All SEC-01–SEC-08 and DB-01–DB-03 merged, no raw `Vec<u8>` holds secret key material, keymanager API hardened, slashing DB durable

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | New Files | Shared File Edits |
|-------|-------|--------|--------|------------|-----------|-------------------|
| SEC-01 | Document BlstSecretKey zeroization | 1 | A | — | none | `crypto/bls.rs` (doc comment) |
| SEC-02 | Zeroize keystore intermediates | 2 | A | — | none | `crypto/keystore.rs` |
| SEC-03 | Path traversal check in key directory loading | 2 | A | — | none | `crypto/key_manager.rs` |
| SEC-08 | Verify remote signer returned signature | 2 | A | — | none | `crypto/remote_signer.rs` |
| DB-01 | SQLite WAL + synchronous=FULL | 2 | A | — | none | `slashing/db.rs` |
| DB-02 | Transactional EIP-3076 import | 2 | A | DB-01 | none | `slashing/db.rs` |
| DB-03 | Reconcile slashing check logic | 3 | A | — | none | `slashing/db.rs` |
| SEC-04 | Redact passwords in ImportKeystoresRequest Debug | 1 | B | — | none | `keymanager-api/types.rs` |
| SEC-05 | URL validation for remote key imports | 3 | B | — | `keymanager-api/url_validator.rs` | `keymanager-api/handlers.rs`, `bin/rvc/main.rs` (CLI flag) |
| SEC-06 | CORS configuration on keymanager API | 2 | B | — | none | `keymanager-api/server.rs`, `bin/rvc/main.rs` (CLI flag) |
| SEC-07 | Request body size limit | 1 | B | — | none | `keymanager-api/server.rs`, `bin/rvc/main.rs` (CLI flag) |
| I-JOINT | Phase 1 integration verification | 3 | both | all above | none | none |

## Phase Parallel Plan

| Day | Stream A (crypto + slashing) | Stream B (keymanager-api) |
|-----|-----|-----|
| 1 | SEC-01 (1pt), SEC-02 (2pt) | SEC-04 (1pt), SEC-07 (1pt) |
| 2 | SEC-03 (2pt), SEC-08 (2pt) | SEC-05 (3pt) |
| 3 | DB-01 (2pt), DB-02 (2pt) | SEC-05 cont., SEC-06 (2pt) |
| 4 | DB-03 (3pt) | SEC-06 cont. |
| 5 | I-JOINT | I-JOINT |

---

## Issues

### Issue SEC-01: Document BlstSecretKey zeroization
- **Points:** 1
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
Research confirmed that blst >= 0.3.11 implements `#[zeroize(drop)]` on `SecretKey`. The `inner: BlstSecretKey` field is already zeroized by blst's own `Drop` impl. The `raw_bytes` field is already zeroized in RVC's `Drop` impl. This issue verifies the blst version and adds documentation.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/bls.rs` (lines 53-105)
- Approach:
  1. Verify blst version >= 0.3.11 in `Cargo.lock`
  2. Add doc comment to `SecretKey` struct: `/// blst::SecretKey implements Zeroize + Drop via #[zeroize(drop)] (blst >= 0.3.11)`
  3. Consider removing redundant `raw_bytes` field — key material lives in two places, doubling zeroization surface. If removed, change `raw_bytes()` method to return `self.inner.to_bytes()` (stack-allocated, short-lived). Grep all callers of `raw_bytes()` first.
- New files to create: none
- Files NOT to modify: anything outside `crypto` crate (owned by Stream B)

**Acceptance Criteria:**
- [ ] blst version >= 0.3.11 confirmed in Cargo.lock
- [ ] Doc comment on `SecretKey` struct explains blst handles inner key zeroization
- [ ] If `raw_bytes` removed: `raw_bytes()` returns `self.inner.to_bytes()`, all callers updated
- [ ] If `raw_bytes` NOT removed: doc comment explains why both fields exist
- [ ] All existing tests pass

**Testing Notes:**
- No new tests needed (verification + documentation only)
- Run `cargo test -p crypto` to ensure no regressions

---

### Issue SEC-02: Zeroize keystore intermediates
- **Points:** 2
- **Type:** security
- **Priority:** P0
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
Derived key bytes and plaintext secret key bytes in the keystore decrypt and encrypt paths are not wrapped in `Zeroizing<T>`. Secret key material persists in memory after use.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/keystore.rs` (lines 155-161 decrypt, lines 371-375 encrypt)
- Approach:
  1. **Decrypt path (line ~155):** Wrap `derived_key` in `Zeroizing::new(derive_key(...))` → `Zeroizing<[u8; 32]>` or `Zeroizing<Vec<u8>>`
  2. **Encrypt path (line ~371):** Wrap plaintext secret key bytes in `Zeroizing::new(secret_key.to_bytes())` → `Zeroizing<Vec<u8>>`
  3. Verify no other intermediate `Vec<u8>` holds secret key material in the file
  4. `zeroize` crate is already a workspace dependency
- New files to create: none
- Files NOT to modify: anything outside `crypto` crate

**Acceptance Criteria:**
- [ ] All intermediate key variables in decrypt path use `Zeroizing<T>`
- [ ] All intermediate key variables in encrypt path use `Zeroizing<T>`
- [ ] No raw `Vec<u8>` holds secret key material in `keystore.rs`
- [ ] All existing tests pass (`cargo test -p crypto`)

**Testing Notes:**
- Existing keystore tests cover encrypt/decrypt correctness
- No new test needed (zeroization is a compile-time type guarantee via `Zeroizing<T>`)

---

### Issue SEC-03: Path traversal check in key directory loading
- **Points:** 2
- **Type:** security
- **Priority:** P0
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
`load_from_directory_with_tracker` does not check for symlinks or path traversal (`../`), allowing reads outside the intended key directory.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/key_manager.rs` (line ~307)
- Approach:
  1. Add `validate_key_path(base: &Path, candidate: &Path) -> Result<PathBuf, KeyManagerError>` helper
  2. Canonicalize base directory and each candidate file path
  3. Verify `canonical_path.starts_with(&canonical_base)`
  4. Add `PathTraversal { path: PathBuf, base: PathBuf }` variant to `KeyManagerError`
  5. Reject symlinks pointing outside base with `warn!` log
  6. Call `validate_key_path` in the directory iteration loop before reading each file
- New files to create: none
- Files NOT to modify: anything outside `crypto` crate

**Acceptance Criteria:**
- [ ] `validate_key_path` helper rejects paths resolving outside base directory
- [ ] `PathTraversal` error variant added to `KeyManagerError`
- [ ] Symlinks pointing outside key directory are rejected with WARN log
- [ ] Path traversal attempts (`../`) are rejected
- [ ] Test: create symlink outside dir, verify rejection
- [ ] Test: normal keystore files inside dir load successfully

**Testing Notes:**
- Unit test: create temp dir with valid keystore + symlink to `/tmp/evil`, verify symlink rejected
- Unit test: create temp dir with `../` in filename, verify rejected
- May need `#[cfg(unix)]` for symlink tests (Windows symlinks differ)

---

### Issue SEC-08: Verify remote signer returned signature
- **Points:** 2
- **Type:** security
- **Priority:** P0
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
The remote signer accepts the returned signature without verifying it was produced by the expected public key. A compromised or misconfigured remote signer could return an invalid signature.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/remote_signer.rs` (line ~103-134, the `sign` method)
- Approach:
  1. After receiving `signature_bytes` from the HTTP response, construct a `Signature` from the bytes
  2. Verify the signature against the expected `pubkey` and `signing_root` using BLS verify
  3. If verification fails: `error!(pubkey = %hex::encode(pubkey), "Remote signer returned invalid signature")` and return `Err(CryptoError::InvalidRemoteSignature)`
  4. Add `InvalidRemoteSignature` variant to `CryptoError`
  5. The existing `RemoteSigner` already has the pubkey available in the `sign()` method
- Watch out for: BLS verify is ~1ms; acceptable overhead for the security guarantee
- New files to create: none
- Files NOT to modify: anything outside `crypto` crate

**Acceptance Criteria:**
- [ ] Invalid signatures from remote signer are rejected with error log
- [ ] Valid signatures pass through unchanged (no behavioral change for correct signers)
- [ ] `CryptoError::InvalidRemoteSignature` error variant added
- [ ] Test: mock Web3Signer returns wrong signature (different key), verify rejection
- [ ] Test: mock Web3Signer returns correct signature, verify acceptance
- [ ] Test: mock Web3Signer returns garbage bytes, verify rejection

**Testing Notes:**
- Use existing `wiremock` test infrastructure in `remote_signer.rs` tests
- Generate a valid signing root and correct signature with one key, then verify rejection when presented with a different key's pubkey

---

### Issue DB-01: SQLite WAL + synchronous=FULL
- **Points:** 2
- **Type:** security
- **Priority:** P0
- **Stream:** A
- **Blocked by:** none
- **Blocks:** DB-02
- **Scope:** 1 day

**Description:**
The slashing DB lacks `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=FULL`. Default journal mode risks corruption on power loss; for slashing protection, data loss = potential double-signing.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (lines 27-36, the `open()` method)
- Approach:
  1. In `open()`, after `Connection::open(path)`:
     ```rust
     let mode: String = conn.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
     if mode != "wal" {
         return Err(SlashingError::DatabaseError("Failed to enable WAL mode".into()));
     }
     conn.pragma_update(None, "synchronous", "FULL")?;
     ```
  2. Log at INFO: `"Slashing DB: journal_mode=WAL, synchronous=FULL"`
  3. Also add to `open_in_memory()` for consistency (WAL is no-op for in-memory but harmless)
  4. WAL mode persists per-database file — existing installations auto-migrate on first connection
- New files to create: none
- Files NOT to modify: anything outside `slashing` crate

**Acceptance Criteria:**
- [ ] `PRAGMA journal_mode=WAL` set on every DB connection open
- [ ] `PRAGMA synchronous=FULL` set on every DB connection open
- [ ] `open()` returns error if WAL mode fails to enable
- [ ] INFO log emitted on successful pragma setup
- [ ] Test: open DB, query both PRAGMAs, verify `journal_mode=wal` and `synchronous=2` (FULL)
- [ ] Test: existing DB file migrates to WAL on open (no data loss)

**Testing Notes:**
- Unit test: `open()` → query `PRAGMA journal_mode` → assert "wal"
- Unit test: `open()` → query `PRAGMA synchronous` → assert 2 (FULL)
- Integration test: create DB with default mode, reopen with new code, verify WAL migration

---

### Issue DB-02: Transactional EIP-3076 import
- **Points:** 2
- **Type:** security
- **Priority:** P0
- **Stream:** A
- **Blocked by:** DB-01 (same file, pragmas must be set first)
- **Blocks:** none
- **Scope:** 1 day

**Description:**
EIP-3076 interchange import is not wrapped in a single transaction. Partial imports on failure leave the DB in an inconsistent state.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (lines 362-409, `import_interchange` or equivalent)
- Approach:
  1. Wrap the entire import method body in `conn.transaction_with_behavior(TransactionBehavior::Immediate)`
  2. All individual inserts (validators, attestations, blocks) happen within the transaction
  3. On any error: `Transaction` Drop auto-rolls back (rusqlite behavior)
  4. On success: `tx.commit()`
  5. The current code likely iterates over validators inserting individually — keep the iteration but within the transaction scope
- Watch out for: The `Mutex<Connection>` is already held during import, so no concurrent access concerns
- Conflict risk: Same file as DB-01 — implement DB-01 first, DB-02 touches different methods
- New files to create: none
- Files NOT to modify: anything outside `slashing` crate

**Acceptance Criteria:**
- [ ] Entire EIP-3076 import wrapped in single `IMMEDIATE` transaction
- [ ] Partial import failure rolls back all changes (no partial records)
- [ ] Successful import commits atomically
- [ ] Test: import with intentional mid-import error (e.g., invalid data after valid entries), verify DB has no partial records
- [ ] Test: successful import commits all records
- [ ] All existing EIP-3076 tests pass

**Testing Notes:**
- Unit test: create interchange data with 5 validators, corrupt the 3rd entry, import → verify 0 records in DB
- Unit test: import valid interchange data → verify all records present
- Existing EIP-3076 conformance tests (76 tests) must all pass

---

### Issue DB-03: Reconcile slashing check logic
- **Points:** 3
- **Type:** chore
- **Priority:** P0
- **Stream:** A
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1-2 days

**Description:**
Standalone `is_safe_to_sign` and `is_safe_to_propose` have subtly different logic from their atomic `check_and_record_*` counterparts, leading to potential inconsistencies.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (lines 202-302)
- Approach:
  1. Audit all callers of `is_safe_to_sign`, `is_safe_to_propose`, `check_and_record_attestation`, `check_and_record_block`
  2. **Option A (preferred):** Extract shared core logic:
     - `check_attestation_safety(conn, pubkey, source, target, signing_root) -> Result<(), SlashingViolation>`
     - `check_proposal_safety(conn, pubkey, slot, signing_root) -> Result<(), SlashingViolation>`
     - Both standalone and atomic variants call the same core function
  3. **Option B:** If standalone variants are unused externally, make them `pub(crate)` (overlaps with LOW-16)
  4. Verify both paths produce identical results via comprehensive test matrix
- Watch out for: Subtle differences in watermark handling, surround vote checks, or signing_root comparisons between the two code paths
- New files to create: none
- Files NOT to modify: anything outside `slashing` crate

**Acceptance Criteria:**
- [ ] Single source of truth for attestation safety check logic
- [ ] Single source of truth for proposal safety check logic
- [ ] Test: both standalone and atomic paths produce identical results for same inputs (parameterized test matrix)
- [ ] Test: watermark edge cases produce identical results in both paths
- [ ] Test: surround vote detection identical in both paths
- [ ] All existing EIP-3076 conformance tests pass (76 tests)
- [ ] All existing proptest properties pass (9 properties)

**Testing Notes:**
- Create a parameterized test that runs the same attestation/block scenarios through both code paths and asserts identical outcomes
- Cover: normal attestation, double vote, surrounding vote, surrounded vote, watermark boundary

---

### Issue SEC-04: Redact passwords in ImportKeystoresRequest Debug
- **Points:** 1
- **Type:** security
- **Priority:** P0
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
`ImportKeystoresRequest` derives `Debug`, which would print passwords to logs if the struct is debug-formatted.

**Implementation Notes:**
- Files likely affected: `crates/keymanager-api/src/types.rs` (lines 16-22)
- Approach:
  1. Remove `Debug` from the `#[derive(...)]` attribute
  2. Implement `Debug` manually:
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
- New files to create: none
- Files NOT to modify: anything outside `keymanager-api` crate

**Acceptance Criteria:**
- [ ] `Debug` output for `ImportKeystoresRequest` does not contain password values
- [ ] `Debug` output shows `[REDACTED; N]` for passwords field
- [ ] Test: format with `{:?}`, assert output contains "REDACTED" and does NOT contain the actual password string

**Testing Notes:**
- Unit test: construct `ImportKeystoresRequest` with known password, format with `{:?}`, assert `!output.contains("my_password")` and `output.contains("REDACTED")`

---

### Issue SEC-05: URL validation for remote key imports
- **Points:** 3
- **Type:** security
- **Priority:** P0
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 2 days

**Description:**
Remote key import accepts arbitrary URLs without validation, enabling SSRF against internal services. Must validate URL scheme and reject private/loopback IPs.

**Implementation Notes:**
- Files likely affected:
  - `crates/keymanager-api/src/handlers.rs` (lines 199-202, `import_remote_keys`)
  - New file: `crates/keymanager-api/src/url_validator.rs`
  - `crates/keymanager-api/src/lib.rs` (add `mod url_validator`)
  - `bin/rvc/src/main.rs` (CLI flag `--allow-insecure-remote-signer`)
  - `crates/keymanager-api/src/server.rs` (thread `allow_insecure` through `AppState`)
- Approach:
  1. Create `url_validator.rs` with `validate_remote_signer_url(url_str, allow_insecure) -> Result<Url, String>`
  2. Validate scheme: `https://` required, `http://` only with `--allow-insecure-remote-signer` flag
  3. Check IP literals against private (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16), CGNAT (100.64/10), broadcast, unspecified
  4. Handle IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
  5. Reject non-HTTP(S) schemes (file, ftp, data, etc.)
  6. Call from `import_remote_keys` handler before adding the key
  7. Add `allow_insecure_remote_signer: bool` to `AppState` or handler context
  8. Add CLI flag in `main.rs`
- Conflict risk: `bin/rvc/main.rs` is shared — SEC-06 and SEC-07 also add CLI flags. Use append-only sections.
- New files to create: `crates/keymanager-api/src/url_validator.rs`
- Files NOT to modify: `crypto/`, `slashing/` (owned by Stream A)

**Acceptance Criteria:**
- [ ] Non-HTTP(S) schemes rejected with 400 error (file, ftp, data, gopher, etc.)
- [ ] `http://` without `--allow-insecure-remote-signer` rejected with descriptive error
- [ ] `http://` with `--allow-insecure-remote-signer` accepted with WARN log
- [ ] `https://` always accepted
- [ ] Private IP literals (127.0.0.1, 10.0.0.1, 192.168.1.1, 172.16.0.1) rejected
- [ ] Link-local (169.254.x.x) rejected
- [ ] CGNAT (100.64.x.x) rejected
- [ ] IPv6 loopback (::1) rejected
- [ ] IPv4-mapped IPv6 (::ffff:127.0.0.1) rejected
- [ ] Public IPs accepted
- [ ] Hostname-based URLs accepted (DNS resolution check is future work)
- [ ] Test: at least 10 URL validation test cases covering all categories

**Testing Notes:**
- Unit tests in `url_validator.rs` for each URL category
- Integration test: attempt to import remote key with `http://` URL, verify 400 response
- Integration test: attempt to import with `file:///etc/passwd`, verify 400 response

---

### Issue SEC-06: CORS configuration on keymanager API
- **Points:** 2
- **Type:** security
- **Priority:** P0
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** 1 day

**Description:**
No CORS headers are set on the keymanager API, allowing any origin to call it from a browser context.

**Implementation Notes:**
- Files likely affected:
  - `crates/keymanager-api/src/server.rs` (lines 45-61, `router()` method)
  - `bin/rvc/src/main.rs` (CLI flag `--keymanager-cors-origins`)
  - `crates/keymanager-api/Cargo.toml` (add `tower-http` cors feature if not present)
- Approach:
  1. Add `cors_origins: Vec<HeaderValue>` field to `KeymanagerServer`
  2. In `router()`:
     ```rust
     let cors = if self.cors_origins.is_empty() {
         CorsLayer::new()  // No CORS headers = same-origin only
     } else {
         CorsLayer::new()
             .allow_origin(AllowOrigin::list(self.cors_origins.clone()))
             .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
             .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
     };
     ```
  3. Add `.layer(cors)` to the router
  4. Add CLI flag `--keymanager-cors-origins` (comma-separated list)
- Dependency: `tower-http` with `cors` feature. Check if already in workspace deps; add if not.
- Conflict risk: `server.rs` also edited by SEC-07. SEC-06 adds cors layer, SEC-07 adds body limit layer — both are `.layer()` calls on the router, touching different lines. Implement SEC-06 first.
- Conflict risk: `bin/rvc/main.rs` shared with SEC-05, SEC-07 — each adds a different CLI flag in the keymanager section.
- New files to create: none
- Files NOT to modify: `crypto/`, `slashing/` (owned by Stream A)

**Acceptance Criteria:**
- [ ] Default (no flag): no `Access-Control-Allow-Origin` header (same-origin only)
- [ ] With `--keymanager-cors-origins "http://localhost:3000"`: only specified origin allowed
- [ ] Preflight OPTIONS requests handled correctly (returns 200 with CORS headers)
- [ ] Allowed methods: GET, POST, DELETE, OPTIONS
- [ ] Allowed headers: Content-Type, Authorization
- [ ] Test: request without CORS origin → no CORS headers in response
- [ ] Test: request with allowed origin → correct CORS headers
- [ ] Test: preflight OPTIONS → correct response

**Testing Notes:**
- Integration test: send request with `Origin: http://evil.com`, verify no CORS headers
- Integration test: configure allowed origin, send request, verify `Access-Control-Allow-Origin` header
- Test preflight: send OPTIONS with `Access-Control-Request-Method: POST`, verify response

---

### Issue SEC-07: Request body size limit
- **Points:** 1
- **Type:** security
- **Priority:** P0
- **Stream:** B
- **Blocked by:** none
- **Blocks:** none
- **Scope:** < 1 day

**Description:**
No body size limit on keymanager endpoints allows memory exhaustion via large POST payloads.

**Implementation Notes:**
- Files likely affected:
  - `crates/keymanager-api/src/server.rs` (lines 45-61)
  - `bin/rvc/src/main.rs` (CLI flag `--keymanager-body-limit`)
- Approach:
  1. Add `body_limit: usize` field to `KeymanagerServer` (default: `10 * 1024 * 1024` = 10 MB)
  2. Add `.layer(DefaultBodyLimit::max(self.body_limit))` in `router()`
  3. Axum returns 413 Payload Too Large automatically when exceeded
  4. Add `--keymanager-body-limit` CLI flag (bytes, default 10485760)
- Conflict risk: `server.rs` also edited by SEC-06 — both add `.layer()` calls. Implement after SEC-06.
- New files to create: none
- Files NOT to modify: `crypto/`, `slashing/` (owned by Stream A)

**Acceptance Criteria:**
- [ ] Default limit is 10 MB
- [ ] Payloads exceeding limit return 413 Payload Too Large
- [ ] `--keymanager-body-limit` flag allows customization
- [ ] Test: send payload > 10 MB, verify 413 response
- [ ] Test: send payload < 10 MB, verify normal processing

**Testing Notes:**
- Integration test: POST to `/eth/v1/keystores` with body > 10 MB → assert 413
- Integration test: POST with normal-sized body → assert 200

---

### Issue I-JOINT: Phase 1 integration verification
- **Points:** 3
- **Type:** chore
- **Priority:** P0
- **Stream:** both
- **Blocked by:** all Phase 1 issues
- **Blocks:** Phase 2
- **Scope:** 1 day

**Description:**
Verify all Phase 1 changes integrate correctly. Run full test suite, verify no regressions, and manually verify key behaviors.

**Implementation Notes:**
- No code changes — verification only
- Run: `cargo test` (all 1,876+ tests must pass)
- Run: `cargo clippy` (must be clean)
- Run: `cargo fmt --check` (must be clean)
- Manual verification checklist:
  1. Keymanager API with CORS: start server, verify no CORS headers by default
  2. Keymanager API body limit: send oversized POST, verify 413
  3. URL validation: attempt remote key import with `http://` URL, verify rejection
  4. Slashing DB: open fresh DB, verify WAL mode via `PRAGMA journal_mode`
  5. Slashing DB: open existing DB, verify WAL migration
  6. EIP-3076 import: import test interchange file, verify transactional behavior

**Acceptance Criteria:**
- [ ] All tests pass (0 failures)
- [ ] `cargo clippy` clean (0 warnings)
- [ ] `cargo fmt --check` clean
- [ ] No new `unsafe` blocks
- [ ] 3 new CLI flags functional: `--allow-insecure-remote-signer`, `--keymanager-cors-origins`, `--keymanager-body-limit`
- [ ] ~15 new tests added across all Phase 1 issues
