# Phase 2: Fail-Open → Fail-Closed (audit #4, #5, #6)

> The three fail-open paths behind the incident-class findings: a slashing DB that silently creates
> itself and signs with zero history (#4), a primary signer that authenticates any CA-issued cert for
> any key (#5), and a keystore-decrypt panic reachable from startup and the import endpoint (#6, DoS).
> Milestone **M2**.
>
> Authoritative inputs: [`../prd.md`](../prd.md), [`../project-plan.md`](../project-plan.md), the audit.
> All file:line references verified against HEAD `develop` v0.6.0 (`ffdb49b`). SEC-4 and SEC-5 were both
> **reviewer-reported and independently re-verified — both CONFIRMED.**

## Phase Overview

- **Goal:** Make each of the three paths fail closed: refuse to sign on a missing/0-byte slashing DB
  without an explicit opt-in; enforce a client-CN allow-list on the primary signer; turn the IV-length
  panic into a typed error.
- **Issue count:** 3 issues, 7 points.
- **Estimated duration:** ~4–6 days single-stream; ~3 days with 2 developers (Stream A does SEC-3,
  Stream B does SEC-4 + SEC-5, in parallel).
- **Entry criteria:** Phase 1 merged and green (soft — SEC-3/4/5 are independent of Phase 1 files and can
  overlap Phase 1's tail).
- **Exit criteria (M2):**
  - [ ] Missing/0-byte slashing DB aborts startup without opt-in; opt-in path logs loudly and never
        wipes a non-empty DB.
  - [ ] A non-allow-listed client CN is rejected before any signing logic on the primary path.
  - [ ] A wrong-length keystore IV returns `Err`; keymanager import surfaces it as a per-item failure.
  - [ ] Workspace green on the standing invariant.

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| SEC-3 | Slashing DB fails CLOSED on missing / 0-byte file | 3 | bugfix | — | A |
| SEC-4 | Primary `SignerService` client-CN allow-list | 2 | feature | — | B |
| SEC-5 | Keystore decrypt IV-length panic → typed error | 2 | bugfix | — | B |

**Total: 3 issues, 7 points.** All three are mutually independent; slot any time.

---

## Issues

### Issue SEC-3: Slashing DB fails CLOSED on missing / 0-byte file

- **Points:** 3
- **Type:** bugfix
- **Priority:** P1
- **Audit source:** #4 [MEDIUM] (CONFIRMED)
- **Blocked by:** none
- **Scope:** 1.5–2 days
- **Stream:** A

**Description:**
`build_slashing_db` checks only the parent directory; `Connection::open` silently creates a fresh empty
DB when the file is absent, and a 0-byte truncated file is indistinguishable from a fresh init — so a
lost volume, ephemeral container storage, a path typo, or partial-write corruption all look like "new
validator" and the process signs with **zero history**. Make a missing DB require an explicit operator
opt-in (with a loud warning), and make a 0-byte/corrupt-header DB *always* a hard error (that is
corruption, never a legitimate fresh init). The fresh-init path must still work for genuine new
deployments, and the opt-in must never wipe a non-empty DB.

**Files to touch (verified):**
- `crates/rvc/src/config/builder.rs` — `build_slashing_db` `:192-204`; the parent-dir-only check is at
  `:193-199`, the `ConfigError::SlashingDbPathInvalid` variant already exists at `:195`. Add: existence
  + non-empty check before open; gate the create-fresh path behind an opt-in.
- `crates/slashing/src/db.rs` — `SlashingDb::open` `:83-130` calls `Connection::open` at `:85` with
  default `READWRITE|CREATE` flags and `migrate()` at `:107`. Surface a "created fresh" signal (or open
  with `OpenFlags` that don't auto-create, and let the caller decide) so the builder can distinguish
  fresh-create from open-existing; a 0-byte file must be rejected before `migrate()` populates it.
- `crates/rvc/src/config/types.rs` — add the opt-in flag (`slashing.allow_fresh_db` / `--init-slashing-db`),
  mirroring the existing `slashing_db_path` field `:32` and CLI plumbing `:638-639`.
- `bin/rvc/src/main.rs` — startup gating of the opt-in (hotspot — distinct step).

**Implementation outline:**
1. **RED:** three tests — (a) missing DB file without opt-in → startup aborts with a clear error;
   (b) missing DB file with opt-in → DB created, loud warning logged, VC starts; (c) 0-byte DB file
   (with and without opt-in) → startup aborts.
2. Add the existence/non-empty check in `build_slashing_db` before open. Add the opt-in flag.
3. Make `SlashingDb::open` distinguish fresh-create from open-existing (a `created_fresh` bool or a
   non-auto-create open) and reject a 0-byte / bad-header file as corruption.
4. Loud, unambiguous log line on the fresh-init path stating a NEW slashing DB is being created and why
   that is dangerous on a previously-active validator.
5. **GREEN/REFACTOR:** the opt-in never wipes or overwrites a non-empty DB (assert in a test);
   existing DB open/migration tests pass.

**Test plan:**
- `test_missing_db_without_optin_aborts_startup` (in `crates/rvc/src/config/builder.rs` tests)
- `test_missing_db_with_optin_creates_and_warns`
- `test_zero_byte_db_always_aborts` (with and without opt-in)
- `test_optin_never_wipes_nonempty_db`
- existing `crates/slashing/src/db.rs` open/migration tests still pass.

**Acceptance criteria:**
- [x] Missing DB without opt-in aborts with a clear error; with opt-in creates + warns.
- [x] 0-byte/corrupt-header DB always aborts, opt-in or not.
- [x] Opt-in never wipes an existing non-empty DB.
- [x] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo nextest run --workspace` green.

**Risks / unknowns:**
- SQLite treats a 0-byte file as a valid empty DB, so the "corrupt vs fresh" distinction must be made in
  the builder *before* `Connection::open`/`migrate` (stat the file: absent → opt-in-gated fresh;
  present-and-0-byte → hard error; present-and-nonempty → normal open). Straightforward, budgeted.

---

### Issue SEC-4: Primary `SignerService` client-CN allow-list

- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Audit source:** #5 [MEDIUM] — reviewer-reported, **independently re-verified: CONFIRMED**
- **Blocked by:** none
- **Scope:** ~1 day
- **Stream:** B

**Description:**
The primary (non-DVT) signer, `SignerServiceImpl` in `bin/rvc-signer`, extracts the caller cert CN via
`audit::cn::extract_client_cn` and uses it **only as an audit label** — any holder of a CA-issued mTLS
cert can request signatures for any loaded pubkey. The DVT path *does* enforce a CN allow-list
(`authenticate_peer` → `allow_list.lookup_by_cn`). Add an optional client-CN allow-list to the primary
path, mirroring the DVT mechanism: when configured, reject requests whose CN is not listed *before* any
signing logic; when not configured, log a startup warning and accept (backward compatible). mTLS stays
mandatory — this is an additional authorization check, not a replacement.

*Verification note:* CONFIRMED against HEAD. The primary `SignerServiceImpl` struct has no allow-list
field; every V2 handler extracts the CN and passes it to the gate purely as a label (per
`docs/web3signer-http-api.md:134`, "the CN is an audit label only"). No verification spike needed.

**Files to touch (verified):**
- `bin/rvc-signer/src/service.rs`
  - `SignerServiceImpl` struct `:120-136` — add an optional allow-list field.
  - each V2 handler's CN-extraction site (`:454`, `:501`, `:543`, `:589`, `:684`, `:750`, `:810`,
    `:867`) — enforce the allow-list (reject before signing) when configured.
- `bin/rvc-signer/src/audit/cn.rs` — `extract_client_cn` `:22` (returns `"unknown"` on missing cert;
  a configured allow-list must reject `"unknown"`).
- `bin/rvc-signer/src/dvt/allow_list.rs` + `dvt/peer_service.rs:171-177` — the DVT allow-list pattern to
  reuse (reuse the type/helper if possible).
- `bin/rvc-signer/src/main.rs` `:402-404` — where the DVT allow-list is loaded; add the primary allow-list
  wiring + the startup warning when unset.

**Implementation outline:**
1. **RED:** test that a request with a non-allow-listed CN is rejected (no signature, audit-log entry);
   an allow-listed CN succeeds; no allow-list configured → request succeeds + a startup warning was
   emitted.
2. Add the optional allow-list field to `SignerServiceImpl` (reuse the DVT `allow_list` type/config
   shape).
3. In each V2 handler, after `extract_client_cn`, reject the request if the allow-list is configured and
   the CN is not listed (including `"unknown"`).
4. Wire the config + the startup warning in `main.rs`.
5. **GREEN/REFACTOR:** DVT path behavior unchanged; mTLS still mandatory.

**Test plan (in `bin/rvc-signer/src/service.rs` tests):**
- `test_non_allowlisted_cn_rejected_no_signature`
- `test_allowlisted_cn_succeeds`
- `test_no_allowlist_configured_succeeds_with_startup_warning`
- `test_dvt_path_unchanged`

**Acceptance criteria:**
- [x] Non-allow-listed CN → rejected before signing, no signature, audit-log entry.
- [x] Allow-listed CN → succeeds. No allow-list → succeeds + startup warning.
- [x] mTLS remains mandatory; DVT path unchanged.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- Eight handler enforcement sites is the main surface; because the DVT allow-list type is reusable, this
  stays 2 pts. If the allow-list must be per-key (not per-service), it could rise to 3 — the audit
  describes a per-service allow-list, so 2 pts holds.

---

### Issue SEC-5: Keystore decrypt IV-length panic → typed error

- **Points:** 2
- **Type:** bugfix
- **Priority:** P1
- **Audit source:** #6 [MEDIUM/DoS] = repo H-5 — reviewer-reproduced, **independently re-verified: CONFIRMED**
- **Blocked by:** none
- **Scope:** ~1 day
- **Stream:** B

**Description:**
`decrypt_ciphertext` converts a keystore IV into a fixed-size `GenericArray` with no length check →
**panics** (not `Err`) on any non-16-byte IV, reachable via startup key loading and the keymanager
import endpoint with a correctly-passworded but IV-corrupted keystore. Validate the IV length and return
the crate's typed `KeystoreError`. The sweep the audit asked for is **already done** (see verification
note): line 321 is the sole attacker-reachable panic; this issue confirms that quickly and does not
chase open-ended work.

*Verification note:* CONFIRMED. `keystore.rs:321` `Aes128Ctr::new(aes_key.into(), iv.as_slice().into())`
— `iv` = `hex::decode(params.iv)` (`:318`), attacker-controlled length, `GenericArray::from_slice`
panics if `len != 16`. Sweep result: the encrypt-side IV (`:415`) is internally generated (safe), the
AES-key slice is fixed-length by construction (safe), and the salt/checksum paths (`ct_eq`) do not panic
on length mismatch (safe). So the fix is a single length guard + a quick regression that the other paths
stay `Err`/non-panicking.

**Files to touch (verified):**
- `crates/crypto/src/keystore.rs` — `decrypt_ciphertext` `:313-326`; add `iv.len() == 16` validation
  before `:321`, returning `KeystoreError`. Keep the constant-time checksum verification ordering
  (checksum before decrypt) intact.
- `crates/crypto/src/error.rs` — `KeystoreError` enum `:21`; add a variant (e.g. `InvalidIvLength`) or
  reuse `DecryptionFailed(String)` (`:52-53`).
- Reachability confirmation (read-only): callers at
  `crates/secret-provider/src/key_source_manager.rs:179`, `crates/crypto/src/key_manager.rs:220`,`:413`,
  `crates/rvc/src/keymanager_adapters.rs:189`, `bin/rvc-signer/src/backend/basic.rs:66`,`:159`.

**Implementation outline:**
1. **RED:** a unit test with a valid-password keystore whose `cipherparams.iv` is 8 bytes → confirm the
   panic on HEAD, then a test asserting `Err` after the fix (shorter and longer than 16).
2. Add the length guard + typed error.
3. Add a keymanager-import test: importing an IV-corrupted keystore returns a per-item error status
   (HTTP 4xx item status), not a process crash.
4. Quick sweep-confirmation test that the encrypt-side IV and salt/checksum paths remain
   `Err`/non-panicking (documents the sweep result).
5. **GREEN/REFACTOR:** existing scrypt + PBKDF2 decrypt vector tests still pass.

**Test plan (in `crates/crypto/src/keystore.rs` tests + a keymanager-api handler test):**
- `test_decrypt_wrong_length_iv_returns_err_not_panic` (8-byte and 24-byte IV)
- `test_keymanager_import_iv_corrupted_keystore_returns_item_error` (service keeps running)
- `test_decrypt_valid_scrypt_vector_still_passes`
- `test_decrypt_valid_pbkdf2_vector_still_passes`

**Acceptance criteria:**
- [ ] Wrong-length IV (shorter and longer than 16) → `Err`, no panic.
- [ ] Keymanager import of an IV-corrupted keystore → error status for that item, service keeps running.
- [ ] Constant-time checksum-before-decrypt ordering intact; existing decrypt vector tests pass.
- [ ] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- None material — the sweep is done and the fix is a single guard + error variant. If the keymanager
  import path already catches the panic at a task boundary (rayon), step 3 simply asserts the cleaner
  typed error; either way ≤ 2 pts.
