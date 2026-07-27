# Phase 4: Remaining Correctness + Hygiene (audit #8, #9, #10 + process)

> The remaining correctness fixes (BLS-to-execution genesis fork #8, Web3Signer client body #9), the
> low-severity correctness batch (#10), and the process/hygiene items (dependency audit, CI gate, footgun
> docs). Milestone **M4**.
>
> Authoritative inputs: [`../prd.md`](../prd.md), [`../project-plan.md`](../project-plan.md), the audit.
> All file:line references verified against HEAD `develop` v0.6.0 (`ffdb49b`).

## Phase Overview

- **Goal:** Sign BLS-to-execution with the genesis fork version (#8); send a Web3Signer-compliant client
  body (#9); make fork-mismatch fatal, provider-load resilient, and the watermark comparison `<=` (#10);
  and close the hygiene gaps (webpki bump, `cargo audit` CI, refreshed report, footgun docs).
- **Issue count:** 4 issues, 10 points.
- **Estimated duration:** ~5–8 days single-stream; ~4 days with 2 developers (Stream A: SEC-9, SEC-10;
  Stream B: SEC-8, SEC-7).
- **Entry criteria:** Phases 1–3 merged and green (soft — these are independent of the earlier files
  except the `bin/rvc/src/main.rs` hotspot, which SEC-9 touches).
- **Exit criteria (M4):**
  - [ ] BLS-to-execution domain uses the genesis fork version; the Capella-asserting test is inverted.
  - [ ] The Web3Signer client body matches the contract for every signing type the client dispatches.
  - [ ] Fork mismatch is fatal at startup (with opt-out); one failing provider does not abort startup;
        watermark equality is blocked.
  - [ ] `cargo audit` runs in CI; `rustls-webpki >= 0.103.13`; report regenerated; footguns documented.
  - [ ] Workspace green on the standing invariant.

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| SEC-7 | BLS-to-execution signs with the genesis fork version | 1 | bugfix | — | B |
| SEC-8 | Web3Signer HTTP client request body per contract | 3 | bugfix | — | B |
| SEC-9 | Correctness batch: M-15 fatal fork-compat, M-9 provider resilience, M-1 watermark `<=` | 3 | bugfix | — | A |
| SEC-10 | Hygiene: webpki bump, `cargo audit` CI, regenerate report, footgun docs | 3 | chore | — | A |

**Total: 4 issues, 10 points.** All mutually independent.

---

## Issues

### Issue SEC-7: BLS-to-execution signs with the genesis fork version

- **Points:** 1
- **Type:** bugfix
- **Priority:** P2
- **Audit source:** #8 [HIGH] = repo H-9 (CONFIRMED)
- **Blocked by:** none
- **Scope:** ~0.5 day
- **Stream:** B

**Description:**
`bin/rvc-keygen/src/bls_to_execution.rs` computes the `DOMAIN_BLS_TO_EXECUTION_CHANGE` domain with
`network.capella_fork_version` instead of the genesis fork version. Per the consensus spec (EIP-7044 /
Capella `process_bls_to_execution_change`), this domain uses `GENESIS_FORK_VERSION` (with the genesis
validators root, which is already correct). The result is rejected on-chain on any network where genesis
≠ capella fork version. Reachable only via the keygen tool, not the Keymanager API. A test even asserts
the wrong behavior; invert it.

**Files to touch (verified):**
- `bin/rvc-keygen/src/bls_to_execution.rs`
  - `:55` — change `network.capella_fork_version` → `network.genesis_fork_version` in the `compute_domain`
    call (`:52-57`). `network.genesis_validators_root` stays.
  - `:52` — the misleading comment.
  - `:152-179` — `test_bls_to_execution_uses_capella_fork_version` (asserts the bug; line `:175` comment
    "proves we use Capella") and the sibling test at `:140-143`: invert to assert the genesis fork
    version, ideally validated against a known-good external `SignedBLSToExecutionChange` vector.
- `network.genesis_fork_version` availability confirmed at `crates/rvc/src/startup.rs:238`
  (`schedule.genesis_fork_version`) and referenced in the existing test at `:178`.

**Implementation outline:**
1. **RED:** invert the test to assert the domain is computed from the genesis fork version (currently
   fails).
2. Change the one line + comment.
3. **GREEN/REFACTOR:** the new test passes; ideally add a known-good external-vector assertion.

**Test plan (in `bin/rvc-keygen/src/bls_to_execution.rs` tests):**
- `test_bls_to_execution_uses_genesis_fork_version` (replaces the Capella-asserting test)
- (optional) `test_bls_to_execution_matches_known_good_vector`

**Acceptance criteria:**
- [x] Domain computed from the genesis fork version + genesis validators root.
- [x] The old Capella-asserting test is inverted/replaced; the new test passes.
- [x] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo nextest run --workspace` green.

**Risks / unknowns:** none — one-line fix + test inversion.

---

### Issue SEC-8: Web3Signer HTTP client request body per contract

- **Points:** 3
- **Type:** bugfix
- **Priority:** P2
- **Audit source:** #9 [HIGH] = repo H-4 (CONFIRMED)
- **Blocked by:** none
- **Scope:** 1.5–2 days
- **Stream:** B

**Description:**
The HTTP Web3Signer **client** sends a bare `{"signing_root":"0x…"}` body (snake_case, **no `type`
discriminator**, no `fork_info`, no typed payload) — incompatible with the real Web3Signer contract
(`POST /api/v1/eth2/sign/{identifier}` expects a `type`-tagged, camelCase `signingRoot` plus type-specific
payload). It fails safe (no signature) — a liveness bug. Send a Web3Signer-compliant body: `type`
discriminator, camelCase `signingRoot`, and the required per-type payload for every signing type the
client dispatches; return a typed error for unsupported types rather than a malformed body. The in-repo
**server-side** implementation is the correct-contract reference — do not touch it.

*Verification note:* CONFIRMED. Client body struct `crates/crypto/src/remote_signer.rs:121-124`
(`struct SignRequest { signing_root: String }`), built at `:160-161`, POSTed to
`{url}/api/v1/eth2/sign/{identifier}` at `:143`. The client `sign()` (`:133-206`) is generic over message
type and can never emit a typed request. The correct shape lives in
`bin/rvc-signer/src/http_api/request.rs:79-178` (the `#[serde(tag = "type")]` `SignPayload` at `:79-133`,
camelCase `signingRoot` with a `signing_root` alias at `:172`). Docs: `docs/web3signer-http-api.md`
(ethereum remote-signing-api v1.3.0).

**Files to touch (verified):**
- `crates/crypto/src/remote_signer.rs`
  - `SignRequest` struct `:121-124` — replace with the typed, `type`-tagged, camelCase body.
  - `sign()` `:133-206` — thread the signing type + per-type payload so the client can emit the correct
    request; keep the local re-verify against `signingRoot` (`:194`).
- Reference (read-only, do not change): `bin/rvc-signer/src/http_api/request.rs:79-178` (correct shape),
  `bin/rvc-signer/src/http_api/dispatch.rs`, `docs/web3signer-http-api.md`.
- Callers of the client `sign()` — thread the message type through (grep the `RemoteSigner` construction
  in `crates/rvc/src/keymanager_adapters.rs:9` and `bin/rvc/src/main.rs`).

**Implementation outline:**
1. **RED:** contract tests asserting the exact serialized JSON body for each signing type the client
   dispatches (block, attestation, aggregation, etc.), compared against the server-side `request.rs`
   shape as the cross-check.
2. Replace the bare body with the typed, `type`-tagged, camelCase body; supply the per-type payload
   (fork_info + block/attestation data as applicable).
3. For any type the client dispatches that lacks a full payload implementation, return a typed error —
   never a malformed body.
4. Keep the local slashing-stage-before-dispatch ordering unchanged (SEC-8 is client-body only).
5. **GREEN/REFACTOR:** the server-side feature is untouched.

**Test plan (in `crates/crypto/src/remote_signer.rs` tests):**
- `test_web3signer_client_block_body_matches_contract` (exact-JSON assertion)
- `test_web3signer_client_attestation_body_matches_contract`
- `test_web3signer_client_unsupported_type_returns_error_not_malformed_body`
- `test_local_slashing_stage_ordering_unchanged`

**Acceptance criteria:**
- [x] Serialized request bodies match the Web3Signer contract for every signing type the client
      dispatches (exact JSON in tests).
- [x] Unsupported types return a typed error, never a malformed body.
- [x] The local slashing-stage-before-dispatch ordering is unchanged; the server-side feature untouched.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- The client `sign()` being generic over message type is the main lift — threading the concrete type +
  payload through the call sites. If the set of dispatched types is larger than block/attestation, this
  sits at the top of the 3-pt band; if only block/attestation, it's comfortably 2–3.

---

### Issue SEC-9: Correctness batch — fatal fork-compat, provider resilience, watermark `<=`

- **Points:** 3
- **Type:** bugfix
- **Priority:** P3
- **Audit source:** #10 [LOW–MED] = repo M-15, M-9, M-1
- **Blocked by:** none
- **Scope:** ~2 days
- **Stream:** A

**Description:**
Three small, independent open items from the repo's own audit, landing as one issue (three clearly
separated changes + tests, one commit):

1. **M-15 — fork-compat is warn-only.** *Verification delta:* `check_fork_compatibility`
   (`crates/rvc/src/startup.rs:228-253`) already returns `Err(StartupError::UnsupportedForkVersion)` at
   `:248` — the audit's implication that the *function* only warns is stale. The warn-only, non-fatal
   behavior is at the **caller** (`bin/rvc/src/main.rs:1395-1400`), which logs and continues. Make the
   caller fatal by default (mirroring the fatal GVR chain-swap gate at `main.rs:1123-1132`), with a
   config opt-out for testnets. **Do not change the function.**
2. **M-9 — one provider aborts the whole VC startup.** `KeySourceManager::load_all`
   (`crates/secret-provider/src/key_source_manager.rs:31-58`) does `return Err(err)` at `:56` when any
   provider's `list_keys` fails — one flaky provider takes down all validators from all sources. Log
   loudly + continue by default; add a strict mode (config) that preserves today's fail-fast; a failure
   of **all** sources (zero keys loaded) remains fatal.
3. **M-1 — watermark comparison uses `<` where `<=` is required.** *(Latent — no production writers
   today, but must be fixed before any pruning/minimal-DB feature writes watermarks.)* The
   strictly-increasing block/attestation-target watermark checks use `<`:
   `crates/slashing/src/db.rs:1188` and `:1288` (block), `:882` and `:1492` (attestation target). Change
   to `<=`. **Do not touch** the attestation-source watermark (`:866`,`:1468`, correctly `<`) or the
   surround/`*BelowMinimum` checks.

**Files to touch (verified):**
- M-15: `bin/rvc/src/main.rs:1395-1400` (make the `Err` arm fatal, mirror `:1123-1132`); a config opt-out
  flag in `crates/rvc/src/config/`. Function `crates/rvc/src/startup.rs:228-253` — **unchanged**.
- M-9: `crates/secret-provider/src/key_source_manager.rs:46-57` (log+skip instead of `return Err`);
  strict-mode config; the startup caller at `bin/rvc/src/main.rs:1182` (`.await?`).
- M-1: `crates/slashing/src/db.rs:1188`,`:1288`,`:882`,`:1492` (`<` → `<=`).

**Implementation outline:**
1. **RED (M-15):** test that a fork mismatch aborts startup (and that the opt-out lets it continue).
2. **RED (M-9):** test that one failing provider + one healthy source → VC starts with the healthy keys,
   error logged; strict mode → aborts; all sources failing → aborts.
3. **RED (M-1):** unit test pinning the equality boundary (equal watermark must be rejected per
   EIP-3076) at each of the four sites.
4. Implement the three changes in separated modules/tests.
5. **GREEN/REFACTOR.**

**Test plan:**
- `test_fork_mismatch_aborts_startup_and_optout_allows` (bin/rvc)
- `test_one_failing_provider_starts_with_healthy_keys` / `test_strict_mode_aborts_on_provider_failure` /
  `test_all_sources_failing_aborts` (secret-provider)
- `test_block_watermark_equal_is_rejected` / `test_attestation_target_watermark_equal_is_rejected`
  (slashing)

**Acceptance criteria:**
- [x] Fork mismatch → startup aborts; opt-out works; the `check_fork_compatibility` function is unchanged.
- [x] One failing provider + one healthy source → VC starts; strict mode → aborts; all sources failing →
      aborts.
- [x] Watermark equality is blocked at the four block/attestation-target sites; the source-watermark and
      surround checks are untouched.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- M-1 is latent (no production watermark writers), so its tests pin behavior for a future feature; keep
  the change minimal and localized to the four confirmed sites.

---

### Issue SEC-10: Hygiene — webpki bump, `cargo audit` CI, regenerate report, footgun docs

- **Points:** 3
- **Type:** chore
- **Priority:** P3
- **Audit source:** Process/hygiene + #3 hardening notes
- **Blocked by:** none
- **Scope:** 1.5–2 days
- **Stream:** A

**Description:**
Close the dependency-hygiene and documentation gaps. Bump `rustls-webpki` past the three current CRL/
name-constraint advisories; regenerate the stale committed `cargo_audit.json`; add a `cargo audit` step
to the **existing** CI (`.github/workflows/ci.yml`); and document the two operator footguns the audit
flagged (the `RVC_ALLOW_NON_WAL_SLASHING_DB` escape hatch and the independently-settable
`keystore_path`/`slashing_db_path` that can hide a copied-data-dir deployment). Scope is the single
webpki bump only — `tonic`/`rustls-pemfile` are known-blocked.

*Verification note:* `rustls-webpki` is pinned at **0.103.10** in `Cargo.lock` (below the audit's
`>= 0.103.13` fix). `cargo_audit.json` last committed **2026-04-01** (~3.5 months stale). CI is
`ci.yml` with `check`/`secret-scan`/`coverage` jobs and **no `cargo audit` step** → SEC-10 **extends**
existing CI. `RVC_ALLOW_NON_WAL_SLASHING_DB` is read at `crates/slashing/src/db.rs:193` (gates whether a
non-WAL journal mode is fatal, `:196-205`) and documented only in a release note, not the operator docs.
`keystore_path` (`config/types.rs:28`) and `slashing_db_path` (`:32`) are independently settable with no
divergence warning.

**Files to touch (verified):**
- `Cargo.lock` — bump `rustls-webpki` to `>= 0.103.13` (via `cargo update -p rustls-webpki`); verify the
  build + tests.
- `cargo_audit.json` (repo root) — regenerate from a fresh `cargo audit` run.
- `.github/workflows/ci.yml` — add a `cargo audit` step/job (the `check` job is the natural home;
  install `cargo-audit`). If a policy-ignore for the known-blocked advisories (`rustls-pemfile`
  unmaintained, blocked on tonic 0.13) is needed to keep the gate green, add an `audit.toml` ignore with
  a justification comment.
- Operator docs: `docs/running-guide.md` (or `docs/validators-config.md`) — document
  `RVC_ALLOW_NON_WAL_SLASHING_DB` (what it disables and the same-key-two-places risk on shared storage)
  and the `keystore_path`/`slashing_db_path` divergence warning (copied-data-dir deployments). Optional
  cheap add: a startup log line when the two paths are on different filesystems
  (`crates/rvc/src/config/` / `bin/rvc/src/main.rs`).

**Implementation outline:**
1. `cargo update -p rustls-webpki` to `>= 0.103.13`; `cargo build` + `cargo nextest run --workspace`.
2. Run `cargo audit`; regenerate `cargo_audit.json`; confirm the three rustls-webpki advisories are
   cleared; list remaining accepted advisories with justification in the summary.
3. Add the `cargo audit` CI step to `ci.yml` (+ an `audit.toml` ignore for the known-blocked ones if
   required to keep it green).
4. Write the two footgun docs; optionally add the different-filesystem startup log line.
5. Verify CI green.

**Test plan:**
- CI dry-run of the `cargo audit` step (locally: `cargo audit` clean of the three webpki advisories).
- `cargo build` + `cargo nextest run --workspace` after the bump.
- (if the log line is added) `test_warn_when_keystore_and_slashing_paths_differ_fs`.

**Acceptance criteria:**
- [x] `rustls-webpki >= 0.103.13`; `cargo build` + `cargo nextest run --workspace` pass after the bump.
- [x] `cargo audit` clean of the three rustls-webpki advisories; remaining accepted advisories listed
      with justification; `cargo_audit.json` regenerated and consistent with the lockfile.
- [x] A `cargo audit` step runs in CI (`ci.yml`).
- [x] `RVC_ALLOW_NON_WAL_SLASHING_DB` and the `keystore_path`/`slashing_db_path` divergence are
      documented in the operator docs.
- [x] `cargo fmt`/`clippy -D warnings` clean.

**Risks / unknowns:**
- `tonic`/`rustls-pemfile` must **not** be bumped (known-blocked); the webpki bump is scoped to not pull
  them. If `cargo update -p rustls-webpki` forces a transitive bump, pin narrowly and note it. The
  `rustls-pemfile` unmaintained advisory stays accepted (documented) until tonic 0.13.
