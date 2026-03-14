# RVC Comprehensive Code Review Report

**Date:** 2026-03-08
**Scope:** All 21 workspace crates (~57,400 lines of Rust)
**Reviewers:** 14 parallel specialized agents (bug-hunter + security-auditor)

---

## Executive Summary

The RVC codebase is well-structured with solid architecture, comprehensive test coverage (1,800+ tests), and good security practices overall. However, the review uncovered **5 CRITICAL/HIGH findings** that could cause missed validator duties or incorrect signatures, **~30 MEDIUM findings** spanning security gaps, logic errors, and concurrency issues, and **~40 LOW/INFO findings** for code quality and hardening improvements.

### Finding Distribution

| Severity | Count | Key Themes |
|----------|-------|------------|
| CRITICAL | 3 | SSZ block signing broken (2), ElectraAttestation tree hash order wrong (1) |
| HIGH | 4 | Duty cache key collision, missing fork check, no URL encoding, no SSZ retry |
| MEDIUM | ~30 | Zeroization gaps, race conditions, timing issues, API validation |
| LOW | ~25 | Edge cases, code quality, dead code, config validation |
| INFO | ~15 | Modernization opportunities, documentation |

---

## CRITICAL Findings

### C-1. SSZ block root computed incorrectly (SHA-256 of raw bytes, not tree-hash)
- **Crate:** `block-service`
- **File:** `service.rs:152`
- **Impact:** SSZ-path blocks are signed with the wrong root. Beacon nodes reject these blocks; validators miss proposals.
- **Detail:** `Sha256::digest(ssz_bytes)` produces a flat hash, not the SSZ Merkle tree-hash root required by the consensus spec. The JSON path correctly uses `block.tree_hash_root()`.
- **Fix:** Deserialize SSZ bytes into `BeaconBlock` and call `tree_hash_root()`, or implement tree-hash on raw SSZ.

### C-2. SSZ signature never included in published payload
- **Crate:** `block-service`
- **File:** `service.rs:154-170`
- **Impact:** The SSZ publish path sends an unsigned `BeaconBlock` instead of `SignedBeaconBlock`. Beacon nodes reject it.
- **Detail:** Signature is computed but assigned to `_sig` (unused). The original unsigned SSZ bytes are published directly. The JSON path correctly wraps the block in `SignedBeaconBlock`.
- **Fix:** Append the 96-byte BLS signature to the SSZ bytes before publishing (SSZ `SignedBeaconBlock` = `BeaconBlock` bytes + signature bytes).

### C-3. ElectraAttestation tree hash field order violates EIP-7549
- **Crate:** `eth-types`
- **File:** `aggregation.rs:99-106`
- **Impact:** All Electra aggregate attestation signatures will be rejected -- `committee_bits` and `signature` are swapped in the hash.
- **Detail:** Spec order: `aggregation_bits, data, committee_bits, signature`. Code order: `aggregation_bits, data, signature, committee_bits`. The tree hash root is wrong, producing invalid signing roots.
- **Fix:** Swap lines 103-104 so `committee_bits` is hashed before `signature`.

---

## HIGH Findings

### H-1. Attester duty cache key collision (missing validator_index)
- **Crate:** `duty-tracker`
- **File:** `tracker.rs:17-20, 129`
- **Impact:** When two validators share the same `(slot, committee_index)`, the second overwrites the first. One validator silently misses attestations.
- **Fix:** Add `validator_index` to `DutyCacheKey`.

### H-2. `check_fork_compatibility` never called during startup
- **Crate:** `rvc` (main binary)
- **File:** `bin/rvc/src/main.rs`
- **Impact:** After an unknown hard fork, the validator client produces invalid signatures with wrong fork domain parameters. No warning is emitted.
- **Fix:** Wire `startup::check_fork_compatibility()` into `run_validator()` after beacon reachability check.

### H-3. No URL-encoding of query parameters (graffiti injection)
- **Crate:** `beacon`
- **File:** `client.rs:187-189, 287-293`
- **Impact:** User-supplied graffiti containing `&` or `=` corrupts the query string, causing truncated or malformed requests.
- **Fix:** Use `reqwest::Url::query_pairs_mut()` or `urlencoding::encode()` for all interpolated values.

### H-4. `publish_block_ssz` has no retry logic
- **Crate:** `beacon`
- **File:** `client.rs:497-537`
- **Impact:** A transient 503 or timeout during SSZ block publication causes the block to be silently lost. Every other endpoint retries.
- **Fix:** Add `execute_with_retry_raw` or a retry loop matching other endpoints.

---

## MEDIUM Findings

### Security / Cryptography

| # | Finding | Crate | File |
|---|---------|-------|------|
| M-1 | `BlstSecretKey` inner field not zeroized on drop | crypto | bls.rs:53-105 |
| M-2 | Derived key not zeroized after keystore decrypt/encrypt | crypto | keystore.rs:155-161 |
| M-3 | Plaintext secret key bytes not zeroized in encrypt path | crypto | keystore.rs:371-375 |
| M-4 | Missing symlink/path traversal check in `load_from_directory_with_tracker` | crypto | key_manager.rs:307 |
| M-5 | `ImportKeystoresRequest` derives `Debug`, exposing passwords in logs | keymanager-api | types.rs:16-22 |
| M-6 | No URL validation for remote key imports (SSRF risk) | keymanager-api | handlers.rs:199-202 |
| M-7 | No CORS configuration on keymanager API | keymanager-api | server.rs:45-61 |
| M-8 | No request body size limit on keymanager endpoints | keymanager-api | server.rs:45-61 |
| M-9 | Remote signer does not verify returned signature against pubkey | signer | remote_signer.rs:103-134 |

### Correctness / Logic

| # | Finding | Crate | File |
|---|---------|-------|------|
| M-10 | Slashing DB records before signing; phantom entries on sign failure | signer | lib.rs:116-146 |
| M-11 | Missing `--mnemonic-passphrase` on bls-to-execution (functional bug) | rvc-keygen | bls_to_execution.rs:35 |
| M-12 | `reload_config` does not remove validators deleted from config | validator-store | store.rs:206-217 |
| M-13 | Non-atomic multi-lock writes in `reload_config` | validator-store | store.rs:207-214 |
| M-14 | `list_keystores` includes remote keys (spec says local only) | keymanager-api | handlers.rs:27-48 |
| M-15 | No slot validation on JSON block path (SSZ path validates) | block-service | service.rs:175-205 |
| M-16 | `health_scores()` hardcodes `is_reachable: true, is_synced: true` | bn-manager | manager.rs:145-146 |

### Concurrency / Timing

| # | Finding | Crate | File |
|---|---------|-------|------|
| M-17 | Builder registration blocks main loop up to 40s | rvc orchestrator | service.rs:350-352 |
| M-18 | Phase 3 timing uses `SystemTime` directly, bypasses `SlotClock` | rvc orchestrator | service.rs:313-319 |
| M-19 | `pubkey_map` immutable after startup; dynamic keys invisible | rvc main | main.rs:711 |
| M-20 | TOCTOU race in dependent root change detection | duty-tracker | tracker.rs:169-219 |
| M-21 | Write lock acquired per-BN attempt in `query_first` hot path | bn-manager | manager.rs:291,303 |
| M-22 | `fallback_unsynced` does not record health for fallback attempts | bn-manager | manager.rs:498-520 |
| M-23 | SSE counter reset without verifying BN recovery | bn-manager | sse.rs:159 |

### Database / Data Integrity

| # | Finding | Crate | File |
|---|---------|-------|------|
| M-24 | Missing SQLite durability settings (WAL mode, synchronous=FULL) | slashing | db.rs:27-36 |
| M-25 | Import is not transactional -- partial import on failure | slashing | db.rs:362-409 |
| M-26 | `is_safe_to_sign`/`is_safe_to_propose` diverge from atomic variants | slashing | db.rs:202-302 |
| M-27 | Duplicate format detection logic (gcp.rs vs format.rs) | secret-provider | gcp.rs:92-103 |

### Other

| # | Finding | Crate | File |
|---|---------|-------|------|
| M-28 | Attestation delay metric at second granularity (sub-second lost) | timing | timer.rs:136-143 |
| M-29 | Division-by-zero panic if `slot_duration < 1 second` | timing | clock.rs:61 |
| M-30 | `Arc::try_unwrap` panics on multi-reference in main startup | rvc main | main.rs:681,714 |
| M-31 | 429 (rate limit) treated as non-retryable client error | beacon | client.rs:912 |
| M-32 | `get_validators` GET query may exceed URL length limits | beacon | client.rs:184-191 |

---

## LOW Findings (Summary)

| # | Finding | Crate |
|---|---------|-------|
| L-1 | Signature type `Vec<u8>` has no length validation | eth-types |
| L-2 | Duplicated `vec_u8_tree_hash_root` across 3 files | eth-types |
| L-3 | `ProposerDuty.pubkey` is `String` instead of `[u8; 48]` | eth-types |
| L-4 | `BlockContents` untagged serde loses error context | eth-types |
| L-5 | `num-bigint` intermediates in EIP-2333 not zeroized | crypto |
| L-6 | Remote signer allows plaintext HTTP without warning | crypto |
| L-7 | `CompositeSigner` RwLock poisoning causes panic | crypto |
| L-8 | `load_from_directory_with_tracker` uses `String` passwords (not `SecretString`) | crypto |
| L-9 | Token stored in non-zeroized `Arc<String>` | keymanager-api |
| L-10 | `write_token_file` uses `create(true).truncate(true)` (TOCTOU) | keymanager-api |
| L-11 | `sign_attestation` takes `Fork` while all others take `ForkSchedule` | signer |
| L-12 | Remote signer error responses may leak server internals | signer |
| L-13 | No validation of `interchange_format_version` on import | slashing |
| L-14 | No pubkey format normalization in slashing DB | slashing |
| L-15 | `set_block_watermark` not transactional | slashing |
| L-16 | `insert_attestation`/`insert_block` public but bypass slashing checks | slashing |
| L-17 | File permissions not set on DB creation, only checked after | slashing |
| L-18 | `concurrency_limit` config field unused | secret-provider |
| L-19 | Hex-decoded intermediate not zeroized in `format.rs` | secret-provider |
| L-20 | `fetch_companion_password` creates unzeroized copy via `.to_vec()` | secret-provider |
| L-21 | `RefreshService` has no per-fetch timeout | secret-provider |
| L-22 | `RwLock::read().unwrap()` panics on poisoned locks | validator-store |
| L-23 | Integer overflow in `start_index + num_validators` | rvc-keygen |
| L-24 | No EIP-55 checksum validation on withdrawal address | rvc-keygen |
| L-25 | Deposit file uses `truncate(true)` instead of `create_new` | rvc-keygen |
| L-26 | `span.enter()` used in async code (doppelganger + orchestrator) | doppelganger, rvc |
| L-27 | `std::sync::RwLock` in async `BuilderService` | builder |
| L-28 | `produce_sync_messages` fails entire batch on single signing failure | sync-service |
| L-29 | Backoff has no jitter -- retry storms possible | beacon |
| L-30 | Network parse silently falls back to None on invalid value | rvc main |
| L-31 | `make_aggregation_bits` panics on `committee_length = 0` | rvc orchestrator |
| L-32 | SSE only subscribes to primary BN; no failover | bn-manager |
| L-33 | Multiple metrics defined but never used | metrics |

---

## Positive Observations

Across the entire codebase, reviewers consistently noted strong practices:

1. **Comprehensive test coverage** -- 1,800+ tests including EIP-3076 conformance, proptest properties, wiremock integration, and concurrency tests
2. **Correct domain separation** -- All 12+ domain types match the Ethereum consensus spec; EIP-7044 Capella cap correctly implemented (with defense-in-depth)
3. **Slashing protection fundamentals** -- Atomic check-and-record using `IMMEDIATE` transactions; parameterized SQL queries (no injection)
4. **Key material protection** -- `Zeroizing<T>` used extensively; `SecretKey::Debug` prints `[REDACTED]`; keystore files written with `0o600`
5. **Constant-time token comparison** -- `subtle::ConstantTimeEq` used in keymanager auth
6. **Good async patterns** -- `.instrument()` for async spans; lock release before `.await`; `CancellationToken` for shutdown
7. **Defensive URL validation** -- Credential redaction in tracing; non-HTTP scheme rejection
8. **Clean trait-based architecture** -- Dependency injection enables testability without leaking mocks into production

---

## Priority Recommendations

### Immediate (CRITICAL/HIGH -- blocks correctness)

1. **Fix SSZ block signing** (C-1, C-2) -- The entire SSZ block path is non-functional. Until fixed, the JSON fallback masks this.
2. **Fix ElectraAttestation tree hash** (C-3) -- Will break all Electra aggregate attestations.
3. **Fix duty cache key collision** (H-1) -- Multi-validator operators will miss attestations.
4. **Wire fork compatibility check** (H-2) -- Prevents silent failure after unknown hard forks.
5. **Add URL encoding** (H-3) -- Graffiti with special characters corrupts requests.
6. **Add SSZ publish retry** (H-4) -- Block publication is too critical for single-attempt.

### Short-term (MEDIUM -- security & reliability)

7. **Zeroization gaps** (M-1 through M-3) -- Document BlstSecretKey limitation; wrap derived keys in `Zeroizing`.
8. **Slashing DB durability** (M-24) -- Add `PRAGMA journal_mode=WAL; synchronous=FULL`.
9. **Transactional import** (M-25) -- Wrap EIP-3076 import in single SQLite transaction.
10. **Spawn builder registration** (M-17) -- Prevent 40s epoch-boundary blocking.
11. **Make pubkey_map dynamic** (M-19) -- Enable runtime key management to work end-to-end.
12. **Keymanager API hardening** (M-5 through M-8) -- CORS, body limits, password redaction, URL validation.

### Medium-term (LOW -- hardening)

13. **Sub-second attestation delay metrics** (M-28) -- Use `.as_secs_f64()`.
14. **Normalize pubkeys in slashing DB** (L-14) -- Prevent case-sensitivity bypass.
15. **Add retry for 429 responses** (M-31) -- Handle rate limiting correctly.
16. **Switch GET to POST for large validator sets** (M-32) -- Prevent URL length issues.
17. **Add jitter to backoff** (L-29) -- Prevent synchronized retry storms.

---

*Report generated by 14 parallel review agents analyzing 21 workspace crates.*
