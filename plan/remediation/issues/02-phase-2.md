# Phase 2: M1 Fixes — Slashing-Safety Floor

## Phase Overview

- **Goal:** Close all 9 M1 findings (SS-1, KM-1, DVT-1+CN-1, D-1, D-2, D-3, KM-2, S-3). After this phase: no signing path on `rvc-signer` bypasses EIP-3076; doppelganger forward window is enforced at every signing entry point; DVT and non-DVT slashing namespacing scoped pubkey-only. Satisfies PRD M4 + M6.
- **Issue count:** 15 issues, 36 total points
- **Estimated duration:** 18 days (single-stream)
- **Entry criteria:**
  - Phase 1 (M1 Shared Pre-Work) complete on `develop`: `eth-types::canonical` module, `eth-types::insecure::InsecureGate`, `signer::SigningEnablement` + `FailClosedDefault` traits, `slashing::SlashingDbReader` trait, `signer → doppelganger` Cargo dep edge, `tests/architecture_no_cycles.rs` standing gate, `signer-registry` dev-only crate skeleton — all landed with zero behavior change.
  - PRD Q3 resolved: either confirmation that no production on-disk slashing DBs exist (tracked) or an anonymised pre-migration `slashing.sqlite` fixture committed at `crates/slashing/tests/fixtures/migration_v1.sqlite` with provenance.
  - Tracker `plan/remediation/tracker.md` updated; each M1 finding row notes consumed seam/trait.
  - `develop` four-gate CI green (`cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`).
- **Exit criteria:**
  - All 9 M1 findings closed; each tracker row has a RED commit hash + GREEN commit hash + test file path + finding-ID-referencing commit messages.
  - PRD M4 verified: `bin/rvc-signer/tests/signing_path_enumeration.rs` green; SS-1 v1 raw-root regression test green (two conflicting-root requests both fail closed).
  - PRD M6 verified: doppelganger gate consulted at every signing entry point (per-path tests for block, attestation, sync-message, sync-contribution, aggregate-and-proof, selection-proof all assert fail-closed when gate is off).
  - DVT-1/CN-1 schema migration regression test green against the captured pre-migration fixture (or Q3-resolution synthetic fixture).
  - `tests/architecture_no_cycles.rs` and `bin/rvc-signer/tests/signing_path_enumeration.rs` both green as standing CI gates.
  - All M1 fix branches merged FF-only to `develop`; four-gate CI suite green.

### Assumptions recorded for this phase

1. **Phase 1 pre-work is fully landed** — the four traits (`SigningEnablement`, `FailClosedDefault`, `SlashingDbReader`, plus `eth-types::canonical` newtypes and `eth-types::insecure::InsecureGate`) compile with zero consumers and the `signer → doppelganger` dep edge is acyclic. If any pre-work is missing, that issue blocks before Phase 2 begins.
2. **PRD Q3 outcome.** This phase plans for the "captured fixture path." If Q3 resolves as "no production DBs," Issue 2.4 (DVT-1+CN-1 schema migration) ships against a synthetic fixture and the points stay the same.
3. **Branch policy** — one finding per branch unless PRD §7.1 explicitly clusters (DVT-1+CN-1 here). All branches FF-only merged to `develop` per `CLAUDE.md` + persisted memory.
4. **TDD discipline (PRD §6.1).** Each finding lands in at least two commits: a RED test reproducing the defect (`test(<crate>): <ID> — RED test ...`) and a GREEN fix (`fix(<crate>): <ID> — ...`). A REFACTOR commit is optional. The reviewer at the pre-merge gate verifies the RED commit existed and failed before GREEN.
5. **Fail-closed discipline (PRD §6.3).** Every M1 fix that touches a slashing-protection or key-confidentiality boundary must default to fail-closed on error.
6. **No new external dependencies (PRD §2).** Every fix uses existing workspace deps.
7. **`is_attesting_enabled` rename to `is_signing_enabled`** (PRD Assumption #7) lands as part of D-3 (Issue 2.11). The gate-side fail-closed semantic for unknown pubkeys (the `FailClosedDefault` trait) is landed by Issue 2.9b; Issue 2.11 propagates the rename through validator-store + orchestrator call sites.
8. **D-3 centralization in `crates/signer`** (PRD Q4 / ADR-001) is the decided default. The orchestrator does not hold direct `crypto::sign_*` handles.
9. **Single-stream execution.** Issues are sequenced for one code-writer; dependencies are explicit. No stream-A/B planning.
10. **Single-day issues are 1 point; ~1-2 days are 2; ~2-3 days (review/integration heavy) are 3; the DVT-1+CN-1 schema-migration cluster is 5 by its cross-file and on-disk-state risk — kept atomic at the review gate because splitting the slashing-schema migration leaves an inconsistent on-disk intermediate that cannot pass its own RED test (the cross-CN double-sign rejection requires both index drop AND the new index in place). The D-3 SigningGate work and the call-site wiring are each split into letter-suffixed issues (2.9a/2.9b, 2.10a/2.10b) to keep individual diffs reviewable.**
11. **Acceptance criteria default to passing the per-issue RED test, cargo test, clippy -D warnings, fmt --check, and (for P0) explicit reviewer Approve.** These are listed once here and not repeated under every issue.

## Phase Summary

| Issue | Title | Points | Blocked by | Scope | Files |
|-------|-------|--------|------------|-------|-------|
| 2.1 | SS-1 RED — v1 raw-root sign bypasses EIP-3076 | 2 | — | 1-2 days | `bin/rvc-signer/tests/v1_raw_root_bypass.rs` (new) |
| 2.2 | SS-1 GREEN — unregister v1 raw-root from live listener + signer-registry enumeration | 3 | 2.1, Phase 1 Task 1.7 | 2 days | `bin/rvc-signer/src/{main,service,lib}.rs`, `crates/signer-registry/src/lib.rs`, `bin/rvc-signer/tests/signing_path_enumeration.rs` (new) |
| 2.3 | KM-1 — atomic export contract + DELETE fail-closed | 3 | — | 2 days | `crates/slashing/src/db.rs`, `crates/keymanager-api/src/handlers.rs`, tests |
| 2.4 | DVT-1 + CN-1 cluster — pubkey-scoped slashing schema migration v1→v2 | 5 | 2.3 | 3 days (cluster; on-disk state) | `crates/slashing/src/{db,stage,scoped,migration,audit}.rs`, `bin/rvc-signer/src/dvt/peer_service.rs`, `bin/rvc-signer/src/slashing/scope.rs`, captured fixture |
| 2.5 | DVT-1 + CN-1 call-site rekey — drop `client_cn` from staging signatures | 2 | 2.4 | 1-2 days | `crates/slashing/src/stage.rs`, `bin/rvc-signer/src/{service,dvt/peer_service,slashing/scope}.rs` |
| 2.6 | D-1 — `ForwardWindowMachine` state machine + restart-aware safe-skip | 3 | — | 2 days | `crates/doppelganger/src/{forward_window,state,traits}.rs`, tests |
| 2.7 | D-2 — fail-closed on missing liveness entries | 1 | 2.6 | 1 day | `crates/doppelganger/src/{forward_window,traits}.rs`, tests |
| 2.8 | S-3 — pre-genesis / epoch-0 doppelganger registration always called | 1 | 2.6 | 1 day | `crates/doppelganger/src/forward_window.rs`, `bin/rvc/src/main.rs` |
| 2.9a | D-3 — `SigningGate` skeleton: slashable paths + per-pubkey async `ValidatorLockMap` | 3 | 2.4, 2.5, 2.6 | 2 days | `crates/signer/src/{gate,locks,error}.rs` (new), tests for block + attestation doppelganger-blocked |
| 2.9b | D-3 — non-slashable paths + aggregate chain-of-custody skeleton + `FailClosedDefault` | 2 | 2.9a | 1-2 days | `crates/signer/src/{gate,fail_closed}.rs` (extends 2.9a), `gate_unknown_pubkey_fails_closed.rs` (new) |
| 2.10a | D-3 — signer-side wrapper + every typed handler in `rvc-signer/src/service.rs` through gate | 3 | 2.9b | 2 days | `crates/signer/src/{slashable,non_slashable}.rs`, `bin/rvc-signer/src/service.rs` |
| 2.10b | D-3 — validator-store + orchestrator call sites; grep-gate asserting no direct `CompositeSigner::sign` outside `crates/signer` | 2 | 2.10a | 1-2 days | `crates/validator-store/src/store.rs`, `crates/rvc/src/orchestrator/{coordinator,sync_committee,aggregation}.rs` |
| 2.11 | D-3 — rename `is_attesting_enabled` → `is_signing_enabled` + flip unknown-pubkey default to `false` | 2 | 2.10b | 1-2 days | `crates/signer/src/enablement.rs`, `crates/validator-store/src/store.rs`, orchestrator call sites |
| 2.12 | KM-2 — replace cancel-token map with `ForwardWindowMachine::cancel` (race-impossible) | 2 | 2.6, 2.10b | 1-2 days | `crates/keymanager-api/src/handlers.rs`, `crates/doppelganger/src/forward_window.rs` |
| 2.13 | M1 phase-exit integration — PRD M4/M6 verification suite + enumeration gate flip | 2 | 2.1-2.12 | 1-2 days | new `bin/rvc-signer/tests/m4_enumeration.rs`, `crates/signer/tests/m6_gate_per_path.rs` |

**Totals: 15 issues, 36 points.**

## Phase Execution Plan

Single code-writer, sequential. Each day-slot represents ~1 day of focused work (coding + review + integration). Multi-point issues continue across days.

| Day | Issue | Notes |
|-----|-------|-------|
| 1 | 2.1 SS-1 RED (2pts) | Reproduce v1 raw-root bypass; no fix yet |
| 2 | 2.1 cont. + 2.2 SS-1 GREEN (3pts) start | Land RED test; begin unregistration; consumes Phase 1 Task 1.7 signer-registry skeleton |
| 3 | 2.2 cont. | signer-registry populated; enumeration test |
| 4 | 2.2 finish + 2.3 KM-1 (3pts) start | SS-1 PR review; start KM-1 (atomic export contract) |
| 5 | 2.3 cont. + 2.3 finish | KM-1 GREEN; 2.3 either ships schema-agnostic acceptance or blocks 2.4 with re-verify criterion |
| 6 | 2.4 DVT-1+CN-1 cluster (5pts) start | Schema migration v1→v2; row-pair resolution; atomic per review decision (no split) |
| 7 | 2.4 cont. | Migration tests against captured fixture |
| 8 | 2.4 finish | DVT-1+CN-1 GREEN; merge cluster |
| 9 | 2.5 DVT-1+CN-1 call-site rekey (2pts) | Drop `client_cn` from staging signatures |
| 10 | 2.6 D-1 ForwardWindowMachine (3pts) | State machine implementation |
| 11 | 2.6 cont. | Restart-aware safe-skip via SlashingDbReader |
| 12 | 2.7 D-2 (1pt) + 2.8 S-3 (1pt) | Fail-closed liveness + epoch-0 path |
| 13 | 2.9a SigningGate skeleton — slashable (3pts) | Struct skeleton + block/attestation paths + per-pubkey lock; RED tests for block + attestation doppelganger-blocked |
| 14 | 2.9a cont. + 2.9b non-slashable (2pts) start | Slashable RED tests pass; begin non-slashable paths + aggregate chain-of-custody + `FailClosedDefault` |
| 15 | 2.9b finish + 2.10a wrapper + rvc-signer handlers (3pts) start | unknown-pubkey fail-closed RED test passes; begin signer-side wrapper + every typed handler in `rvc-signer/src/service.rs` |
| 16 | 2.10a cont. + 2.10b validator-store + orchestrator (2pts) start | Finish rvc-signer routing; begin validator-store + orchestrator call sites + grep-gate |
| 17 | 2.10b finish + 2.11 enablement rename (2pts) | grep-gate asserts no direct `CompositeSigner::sign` outside `crates/signer`; rename + flip default |
| 18 | 2.12 KM-2 (2pts) + 2.13 M1 phase-exit (2pts) | KM-2 consumes `ForwardWindowMachine::cancel`/`register`; flip standing CI gates |

> Day 18 closes the phase. Issues 2.11 and 2.12 are independent of each other but both block on 2.10b (2.12 additionally blocks on 2.6 for `ForwardWindowMachine` API consumption); they can be interleaved by the same code-writer.

---

## Issues

### Issue 2.1: SS-1 RED — failing regression test reproducing v1 raw-root sign bypass

- **Points:** 2
- **Type:** test (RED-first per PRD §6.1)
- **Priority:** P0
- **Blocked by:** none (Phase 1 pre-work landed)
- **Blocks:** 2.2
- **Scope:** 1-2 days

**Description:**
Write the RED regression test demanded by PRD acceptance criterion SS-1(c): two v1 `sign(signing_root, pubkey)` requests with conflicting roots for one slot must both fail closed. On `develop` today, the test fails because `bin/rvc-signer/src/service.rs:234-312` registers the v1 raw-root sign handler on the live listener with zero EIP-3076 consultation; both conflicting-root requests succeed and produce signatures. The RED commit lands the test alone; the GREEN commit in Issue 2.2 unregisters the handler.

**Implementation Notes:**
- New file: `bin/rvc-signer/tests/v1_raw_root_bypass.rs`.
- Files referenced (read-only): `bin/rvc-signer/src/service.rs:234-312` (the SignerServiceServer v1 handler), `bin/rvc-signer/src/main.rs:439,507` (the `add_service` registration).
- Approach: spin up `rvc-signer` against an in-process gRPC client (use the existing `bin/rvc-signer/tests/sign_aggregate_v2.rs` harness as the pattern). Issue two v1 raw-root `sign(signing_root, pubkey)` RPCs for the same `(pubkey, slot)` but different signing roots. Assert: at least one succeeded today (proving the bypass), and the test would assert both fail closed (which is the spec-correct behavior). To make this a *failing* test on current `develop`, structure the assertion as "both requests must return `Status::unimplemented` OR the v1 service must not be registered." This will fail on current `develop` because both signatures succeed.
- Watch out for: the test harness must bind the live listener (not a separate insecure-gated listener) — that is the bypass surface SS-1 is closing.
- Existing in-tree pattern: `bin/rvc-signer/tests/sign_aggregate_v2.rs` already runs a real `SignerService` instance for an integration test; reuse its server-bring-up scaffolding.

**Acceptance Criteria:**
- [ ] New test file `bin/rvc-signer/tests/v1_raw_root_bypass.rs` compiles.
- [ ] Test asserts: "the live listener does not accept a v1 `sign(signing_root, pubkey)` RPC, OR if accepted it returns `Status::unimplemented`."
- [ ] Test FAILS on current `develop` (run `cargo test -p rvc-signer --test v1_raw_root_bypass` to confirm).
- [ ] Commit message: `test(rvc-signer): SS-1 — RED test reproduces v1 raw-root bypass on live listener`.
- [ ] `cargo build`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.

**Testing Notes:**
- The test must fail "for the right reason" — i.e. the bypass actually executes and produces two conflicting signatures.
- Use a deterministic test pubkey loaded from an in-tree test keystore (see `bin/rvc-signer/tests/sign_aggregate_v2.rs` for the pattern).

---

### Issue 2.2: SS-1 GREEN — unregister v1 raw-root from live listener + signer-registry enumeration

- **Points:** 3
- **Type:** fix
- **Priority:** P0
- **Blocked by:** 2.1, **Phase 1 Task 1.7** (cross-phase — signer-registry dev-only crate skeleton; this issue populates the metadata)
- **Blocks:** 2.13, **Phase 6 Task 6.8 (DVT-2)** (cross-phase handoff — the SS-1 unregistration pattern established here is reused verbatim by DVT-2 to delete the v1 raw-root PartialSign service and `lib.rs` export)
- **Scope:** 2 days

**Description:**
Close PRD acceptance criteria SS-1(a)+(b)+(d). Unregister the v1 raw-root `SignerServiceServer` from the live `add_service` call. Keep the handler code compiled (per ADR-010) but make every method return `Status::unimplemented` regardless of arguments. Populate the Phase 1-skeleton `crates/signer-registry` crate with compile-time metadata for every gRPC method, then add `bin/rvc-signer/tests/signing_path_enumeration.rs` (the PRD M4 enumeration test) that asserts every registered gRPC method on the live listener is either (a) a non-slashable message type, or (b) routed through `crates/signer::SigningGate`. The enumeration test becomes a standing CI gate alongside `tests/architecture_no_cycles.rs`.

**Implementation Notes:**
- Files modified: `bin/rvc-signer/src/main.rs` (lines ~439, ~507: remove `add_service(SignerServiceServer::new(...))`); `bin/rvc-signer/src/service.rs:234-312` (every v1 method body returns `Status::unimplemented`); `bin/rvc-signer/src/lib.rs` (drop v1 export if no longer referenced); `crates/signer-registry/src/lib.rs` (populate with method metadata: name, message class, slashable Y/N).
- New file: `bin/rvc-signer/tests/signing_path_enumeration.rs` — uses `signer-registry` static metadata to assert every method is either non-slashable or routed through the gate. Since `SigningGate` lands in Issue 2.9, the enumeration test in this issue can assert the weaker invariant ("every method is non-slashable OR is registered as routing through the gate-trait") and the final tightening flip is in Issue 2.13.
- Approach: per ADR-010, the v1 handler stays compiled to preserve the gRPC proto types in-tree for future legacy-bind opt-in; only the `add_service` registration on the live listener is removed.
- Consumes: `crates/eth-types::insecure::InsecureGate` (Phase 1 Task 1.2) — the doc-comment notes a future separately-bound insecure listener may be added but is not implemented in this issue.
- The signer-registry test running enumeration on the live listener — to bring up an actual `tonic::transport::Server` and reflect its registered services — should use the same harness as Issue 2.1.

**Acceptance Criteria:**
- [ ] Issue 2.1's RED test passes (`cargo test -p rvc-signer --test v1_raw_root_bypass` green).
- [ ] `bin/rvc-signer/src/main.rs` no longer calls `add_service(SignerServiceServer::new(...))` on the live listener.
- [ ] Every v1 method body returns `tonic::Status::unimplemented("v1 raw-root signing has been removed; use the v2 typed RPCs.")`.
- [ ] `crates/signer-registry/src/lib.rs` contains a `pub const SIGNING_METHODS: &[MethodMeta]` (or equivalent) with one entry per live-listener method, each tagged `slashable: bool` and `routes_through_gate: bool`.
- [ ] `bin/rvc-signer/tests/signing_path_enumeration.rs` asserts the enumeration invariant and passes.
- [ ] Commit messages: `fix(rvc-signer): SS-1 — unregister v1 raw-root sign service from live listener` (the GREEN), and a follow-up `chore(signer-registry): SS-1/M4 — enumerate live-listener methods for PRD M4 gate`.
- [ ] No new external dependencies.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve recorded for the P0 GREEN PR.

**Testing Notes:**
- The enumeration test is a standing CI gate from this issue forward; future contributors adding a gRPC method without a `signer-registry` entry will see CI fail.
- The legacy-opt-in path (separately-bound listener under `InsecureGate::Allow`) is documented in the SS-1 fix comments but not implemented this issue; if a downstream integrator surfaces, the design hook is in place.
- **Cross-phase handoff (Phase 6 Task 6.8 / DVT-2):** the exact unregistration pattern landed here (drop `add_service`, keep handler compiled returning `Status::unimplemented`, populate `signer-registry` metadata as `slashable: false, routes_through_gate: false, status: unimplemented`) is reused verbatim by 6.8 to delete the DVT v1 raw-root PartialSign server impl and `lib.rs` export. The 6.8 issue should reference this issue's commit hash in its Implementation Notes as the pattern source.

---

### Issue 2.3: KM-1 — atomic export contract + DELETE `/eth/v1/keystores` fail-closed

- **Points:** 3
- **Type:** fix
- **Priority:** P0
- **Blocked by:** none (Phase 1 pre-work landed)
- **Blocks:** 2.4 (the 2.4 schema migration adds the audit-only `client_cn` column to the slashing DB; 2.4 must re-verify the atomic-export contract from this issue still holds across the v1→v2 schema). Re-verify criterion is recorded on Issue 2.4.
- **Scope:** 2 days

**Description:**
Close PRD acceptance criteria KM-1(a)+(b)+(c). Strengthen `crates/slashing::SlashingDb::export_interchange` to the atomic contract from ADR-008: either every requested pubkey is exported into the returned interchange OR the call returns `Err` with no partial output. Rewrite `crates/keymanager-api/src/handlers.rs:244-313` DELETE handler so an `export_interchange` error aborts the entire request with 500: no keystores deleted, no empty interchange returned to the client. Remove the `unwrap_or_else(|e| empty_interchange())` permissive fallback. Frame the fix per Research R4: "fail-closed, consistent with `local_keystores.yaml` + EIP-3076 spirit of DELETE semantics," not as a literal MUST from the flows README.

**Implementation Notes:**
- RED commit first: add `crates/keymanager-api/tests/delete_export_error_fail_closed.rs` that mocks an `export_interchange` failure (inject a poisoned `SlashingDb` handle or a test-double) and asserts (a) the DELETE response is 500, (b) no keystore is deleted, (c) the response body is NOT an empty interchange.
- Files modified: `crates/slashing/src/db.rs` (strengthen `export_interchange` to atomic: collect all rows in a single transaction, return `Err` on any per-pubkey failure); `crates/keymanager-api/src/handlers.rs:244-313` (rewrite DELETE handler: on export err, return `(StatusCode::INTERNAL_SERVER_ERROR, ...)` without touching keystores).
- Approach: the atomic contract makes the DELETE handler trivially fail-closed — no per-key error-handling logic needed.
- Watch out for: existing call sites of `export_interchange` may rely on the old per-pubkey-success behavior. Grep all callers; the only known caller is the DELETE handler.
- Per PRD Assumption #9 + Research R4: prefer the atomic abort, not per-key marking.

**Acceptance Criteria:**
- [ ] RED test `crates/keymanager-api/tests/delete_export_error_fail_closed.rs` fails on current `develop` (the `unwrap_or_else(empty_interchange)` path executes and deletions proceed).
- [ ] `SlashingDb::export_interchange` returns `Err` on any per-pubkey failure; no partial output is ever returned.
- [ ] **Schema-agnostic acceptance assertion:** the RED + GREEN test exercises `export_interchange` purely through its public type signature (pubkey set in, `Result<Interchange, _>` out) without inspecting the on-disk row layout, so the v1 schema (current) and v2 schema (post-Issue 2.4 migration that adds the audit-only `client_cn` column) both satisfy the same assertion. The test must NOT hard-code `SELECT client_cn FROM ...` or any column the v1→v2 migration changes.
- [ ] DELETE handler returns `INTERNAL_SERVER_ERROR` on export failure with no keystores deleted and no empty interchange.
- [ ] The `unwrap_or_else(|e| empty_interchange())` line is removed.
- [ ] RED test now passes (after the GREEN commit).
- [ ] Commit messages: `test(keymanager-api): KM-1 — RED test asserts DELETE export error aborts without deletion`, `fix(slashing,keymanager-api): KM-1 — atomic export_interchange contract; DELETE fails closed on export error`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for P0.

**Testing Notes:**
- The injected export failure must be deterministic; use a `MockSlashingDb` or a `cfg(test)` hook that flips `export_interchange` to return `Err` on the second call.
- Document in the fix's commit message: framed per Research R4 as "fail-closed, consistent with `local_keystores.yaml` + EIP-3076."

---

### Issue 2.4: DVT-1 + CN-1 cluster — pubkey-scoped slashing schema + migration v1→v2

- **Points:** 5
- **Type:** fix (PRD §7.1 cluster; on-disk schema change)
- **Priority:** P0 + P1
- **Blocked by:** 2.3 (KM-1 atomic export contract must land first so its assertions can be re-verified against the v2 schema), Phase 1 Task 1.8 (captured fixture if Q3=yes; pre-work landed)
- **Blocks:** 2.5, 2.9a (SigningGate composes `PubkeyScopedDb`; see 2.9a Blocked-by note)
- **Scope:** 3 days — **kept atomic at 5 points (above the 3-point soft cap) by review-gate decision**: the change is one atomic schema migration touching SQLite UNIQUE indices, in-flight stage signatures, the DVT peer-service call sites, and the captured-fixture regression test. Splitting the slashing-schema migration leaves an inconsistent on-disk intermediate that cannot pass its own RED test (cross-CN double-sign requires both index drop AND the new index in place; a partial state would either still accept the bug OR fail every signing path). PRD §7.1 cluster rationale + adversarial sizing review confirmed.

**Description:**
Close PRD acceptance criteria DVT-1(a)+(b)+(c) and CN-1(a)+(b) atomically. Re-key the slashing SQLite schema from `(client_cn, pubkey, gvr, slot)` / `(client_cn, pubkey, gvr, target_epoch)` to `(pubkey, gvr, slot)` / `(pubkey, gvr, target_epoch)` UNIQUE indices with `client_cn` preserved as an audit-only column. Implement `crates/slashing::scoped::PubkeyScopedDb` to replace `bin/rvc-signer/src/slashing/scope.rs::ScopedSlashingDb`. Ship the one-way idempotent transactional migration v1→v2 with the row-pair resolution table from the architecture (Module: `slashing`). Regression test against the Phase 1 Task 1.8 captured pre-migration fixture (or a synthetic fixture if Q3=no production DBs).

**Implementation Notes:**
- RED commit first: `crates/slashing/tests/pubkey_scope_cross_cn.rs` — two distinct allow-listed peer CNs request block sign for the same pubkey/slot/different roots; the second must be rejected as DoubleProposal. Test fails on `develop` (both succeed because `client_cn` is in the WHERE clause).
- Files modified: `crates/slashing/src/db.rs` (drop CN-in-WHERE-clause uses; add new UNIQUE indices; keep `client_cn` column for audit); `crates/slashing/src/scoped.rs` (new — `PubkeyScopedDb<'a>` thin view); `crates/slashing/src/migration.rs` (new — v1→v2 idempotent transactional migration with row-pair resolution per architecture's migration table); `crates/slashing/src/audit.rs` (new — `audit_log(client_cn, pubkey, outcome)` for retained per-CN visibility); `crates/slashing/src/reader.rs` (extend `SlashingDbReader` trait if needed for migration introspection).
- Migration row-pair resolution table is reproduced from the architecture document; implement exactly the five cases listed there. Property guaranteed: post-migration DB rejects every message the pre-migration DB rejected, plus every cross-CN double-sign the pre-migration DB silently accepted.
- Captured fixture loads from `crates/slashing/tests/fixtures/migration_v1.sqlite`; new regression test `crates/slashing/tests/migration_v1_to_v2.rs` exercises each row-pair case. If Q3 resolves "no production DBs," generate a synthetic fixture via a small helper in the test harness.
- The `stage_block` / `stage_attestation` signature *change* (dropping the `client_cn` parameter) is deliberately deferred to Issue 2.5; this issue keeps the signatures intact (passing `client_cn` is allowed but ignored at the WHERE-clause level) so the schema change can merge with no in-flight signature breakage.
- Watch out for: the migration must be idempotent (gated on `metadata.migration_v2_applied_at`); a re-run on an already-migrated DB must be a no-op. Add a regression test for this.
- ADR refs: ADR-004, ADR-007, ADR-008 (atomic export).

**Acceptance Criteria:**
- [ ] RED test `crates/slashing/tests/pubkey_scope_cross_cn.rs` fails on current `develop`.
- [ ] After GREEN: cross-CN double-sign attempt is rejected with `DoubleProposal` (DVT-1 acceptance criterion c).
- [ ] Schema migration v1→v2 is idempotent and transactional; re-running on a migrated DB is a no-op.
- [ ] Row-pair resolution per architecture's migration table implemented exactly for all five cases; each case has a unit test.
- [ ] `crates/slashing/tests/migration_v1_to_v2.rs` green against captured-fixture pre-migration DB.
- [ ] `client_cn` is preserved on disk as audit column; `audit_log(client_cn, pubkey, outcome)` writes per-CN audit rows.
- [ ] `PubkeyScopedDb` exists in `crates/slashing/src/scoped.rs`; old `bin/rvc-signer/src/slashing/scope.rs::ScopedSlashingDb` left in place but un-used (deleted in Issue 2.5).
- [ ] **Re-verify Issue 2.3 (KM-1) acceptance:** re-run `crates/keymanager-api/tests/delete_export_error_fail_closed.rs` against the v2 schema (post-migration); the schema-agnostic assertion from Issue 2.3 must still hold (the audit-only `client_cn` column does not change the public `export_interchange` contract). Document the re-verification in the GREEN commit message body.
- [ ] Commit messages: `test(slashing): DVT-1 — RED test reproduces cross-CN double-sign acceptance`, `fix(slashing): DVT-1 + CN-1 — pubkey-scoped slashing schema migration v1→v2 with audit-only client_cn column`.
- [ ] No new external dependencies.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for P0.

**Testing Notes:**
- This is the highest-risk fix in M1 because it touches on-disk state.
- The migration property invariant ("rejects every message the pre-migration DB rejected") is asserted by replaying the pre-migration fixture's accepted-row set against the migrated DB.
- The captured-fixture test is the canonical evidence for PRD M8 closeout of DVT-1+CN-1.

---

### Issue 2.5: DVT-1 + CN-1 call-site rekey — drop `client_cn` from `stage_block` / `stage_attestation`

- **Points:** 2
- **Type:** refactor (post-schema GREEN cleanup)
- **Priority:** P0 (follow-on)
- **Blocked by:** 2.4
- **Blocks:** 2.9
- **Scope:** 1-2 days

**Description:**
Close the API-surface side of DVT-1+CN-1. Drop the `client_cn` parameter from `crates/slashing::SlashingDb::stage_block` and `stage_attestation`. Update the DVT peer-service and main signer call sites. Delete the now-unused `bin/rvc-signer/src/slashing/scope.rs::ScopedSlashingDb` (replaced by `crates/slashing::PubkeyScopedDb` from Issue 2.4). Audit-side per-CN logging stays via `audit_log` from Issue 2.4.

**Implementation Notes:**
- Files modified: `crates/slashing/src/stage.rs` (drop `client_cn` from signatures; staging types lose the field); `bin/rvc-signer/src/service.rs` (call sites); `bin/rvc-signer/src/dvt/peer_service.rs:244,377` (call sites — see PRD §5 P0 table); `bin/rvc-signer/src/slashing/scope.rs` (delete file or shrink to an empty re-export of `crates/slashing::PubkeyScopedDb`).
- This is a mechanical refactor riding on top of Issue 2.4's behavioral fix; no new behavior, no new tests beyond `cargo test` keeping the cluster's RED tests green.
- Watch out for: any call site relying on the audit-side per-CN visibility must call `audit_log` explicitly (otherwise audit data goes missing).

**Acceptance Criteria:**
- [ ] `stage_block` and `stage_attestation` signatures no longer accept `client_cn`.
- [ ] All call sites compile and pass tests.
- [ ] `bin/rvc-signer/src/slashing/scope.rs::ScopedSlashingDb` deleted or replaced by a re-export shim.
- [ ] Issue 2.4's `pubkey_scope_cross_cn` test still green.
- [ ] `audit_log` is called at each pre-`stage_*` site to preserve per-CN visibility.
- [ ] Commit message: `refactor(slashing,rvc-signer): DVT-1 + CN-1 — drop client_cn from stage_* signatures; audit-only via audit_log`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.

**Testing Notes:**
- No new tests beyond regression coverage from Issue 2.4.
- Verify with `cargo grep client_cn` that no `WHERE`-clause use remains.

---

### Issue 2.6: D-1 — `ForwardWindowMachine` state machine + restart-aware safe-skip

- **Points:** 3
- **Type:** feature (new module per architecture)
- **Priority:** P0
- **Blocked by:** none (Phase 1 traits landed)
- **Blocks:** 2.7, 2.8, 2.9
- **Scope:** 2 days

**Description:**
Close PRD acceptance criteria D-1(a)+(b)+(c) by implementing `crates/doppelganger::forward_window::ForwardWindowMachine` per Research R8 and ADR-001. The Lighthouse v5.3.0 `doppelganger_service.rs` state machine is the reference (forward window: a validator marked safe only after the last slot of `e+1` with no unexplained `is_live`). Restart-aware safe-skip via `crates/slashing::SlashingDbReader::last_signed_attestation`: if the validator already signed in this window, mark Safe immediately (Lodestar pattern, existing in `crates/doppelganger/src/service.rs:122-150`).

**Implementation Notes:**
- RED commit first: `crates/doppelganger/tests/forward_window_satisfaction.rs` — assert that `is_signing_enabled(pubkey)` returns `false` during a registered forward window and `true` only after the last slot of `e+1` advances with no `is_live` observation. Test fails on current `develop` because `service.rs:166-258` observes only past epochs.
- New files: `crates/doppelganger/src/forward_window.rs`, `crates/doppelganger/src/state.rs` (per-validator `ValidatorState` enum: `Unmonitored | Pending { start_epoch, end_epoch, observed } | Safe | Detected`).
- Extend `crates/doppelganger/src/traits.rs` with the existing `LivenessChecker` and the new `SigningEnablement` trait (already declared in Phase 1).
- `ForwardWindowMachine` impls `SigningEnablement` (`is_signing_enabled(&self, pubkey) -> bool`).
- Public API per architecture: `register`, `is_signing_enabled`, `tick`, `observe_liveness`, `cancel`, `status`.
- Restart-aware safe-skip uses `SlashingDbReader::last_signed_attestation(pubkey, gvr)` — if present within this window, transition straight to `Safe` (consistent with Lodestar pattern).
- Pre-genesis branch (S-3 hook) is reserved here but landed in Issue 2.8.
- Watch out for: state must persist across the slot-loop tick boundary; protect with `parking_lot::Mutex<HashMap<Pubkey, ValidatorState>>` per architecture.

**Acceptance Criteria:**
- [ ] RED test `crates/doppelganger/tests/forward_window_satisfaction.rs` fails on `develop`, passes after GREEN.
- [ ] `ForwardWindowMachine::register` is idempotent; calling twice for the same `(pubkey, current_epoch)` does not reset state.
- [ ] State machine transitions exactly as in the architecture's state diagram (Unmonitored → Pending → Safe / Detected).
- [ ] Restart-aware safe-skip transitions to `Safe` when `SlashingDbReader::last_signed_attestation` returns `Some(target)` within the window.
- [ ] D-1 acceptance criterion (a)+(b)+(c) all asserted in tests.
- [ ] Commit messages: `test(doppelganger): D-1 — RED forward-window withholds signing for next monitoring_epochs`, `fix(doppelganger): D-1 — ForwardWindowMachine state machine with restart-aware safe-skip via SlashingDbReader`.
- [ ] No new external dependencies.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for P0.

**Testing Notes:**
- The "last slot of `e+1`" satisfaction edge is the easiest place to introduce an off-by-one. Add a unit test for `tick(epoch, slot_in_epoch)` at every slot of the satisfaction epoch to assert the transition only fires on the last slot.
- Use Lighthouse v5.3.0 `doppelganger_service.rs` as the live reference (Research R8); do not work from a summary.

---

### Issue 2.7: D-2 — fail-closed on missing liveness entries

- **Points:** 1
- **Type:** fix (co-located with D-1 cluster per PRD §7.1)
- **Priority:** P2 → escalated into M1 per architecture cluster (clusters with D-1+D-3+S-3)
- **Blocked by:** 2.6
- **Blocks:** —
- **Scope:** 1 day

**Description:**
Close PRD acceptance criterion D-2. `LivenessChecker` responses missing an entry for any requested validator index leave that validator in `Pending` (no `Safe` transition). On `develop` today, `crates/doppelganger/src/service.rs:207-242` silently treats absent indices as "not live," which is fail-open.

**Implementation Notes:**
- RED commit first: `crates/doppelganger/tests/forward_window_missing_liveness.rs` — `LivenessChecker` mock returns a response missing one requested index; assert that validator remains `Pending`, no `Safe` transition emitted. Test fails on `develop`.
- Files modified: `crates/doppelganger/src/forward_window.rs` (`observe_liveness` returns `DoppelgangerError::IncompleteLiveness` if any requested index is absent; no Safe transition for missing entries); `crates/doppelganger/src/traits.rs` (extend `LivenessChecker` contract with the response-completeness invariant in the doc-comment); `crates/doppelganger/src/error.rs` (`IncompleteLiveness` variant).
- Watch out for: must work in conjunction with Issue 2.6's tick-driven satisfaction logic — missing-entry epochs are not "observations" and do not contribute to the satisfaction count.
- Research R8 / Lighthouse pattern: CRITICAL log on missing entries; rs-vc's analog is the `DoppelgangerError::IncompleteLiveness` + warn-level log (no need to upgrade to CRITICAL in this issue).

**Acceptance Criteria:**
- [ ] RED test `crates/doppelganger/tests/forward_window_missing_liveness.rs` fails on `develop`, passes after GREEN.
- [ ] `observe_liveness` returns `Err(DoppelgangerError::IncompleteLiveness)` when any requested index is absent.
- [ ] D-2 acceptance criterion asserted: missing-index validator remains `Pending`.
- [ ] Commit messages: `test(doppelganger): D-2 — RED missing-liveness fails open`, `fix(doppelganger): D-2 — fail-closed on missing liveness entries`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.

**Testing Notes:**
- The test fixture is a simple `LivenessChecker` mock returning a partial response; reuse the harness from Issue 2.6.

---

### Issue 2.8: S-3 — pre-genesis / epoch-0 doppelganger registration always called

- **Points:** 1
- **Type:** fix (co-located with D-1 cluster per PRD §7.1)
- **Priority:** P2 → escalated into M1 per architecture cluster
- **Blocked by:** 2.6
- **Blocks:** —
- **Scope:** 1 day

**Description:**
Close PRD acceptance criterion S-3. On `develop` today, `bin/rvc/src/main.rs:1264-1287` fully skips startup doppelganger detection when `current_epoch == 0`. Always call `ForwardWindowMachine::register` (the state machine handles epoch 0 conservatively per Research R8 / Lighthouse pattern: pre-genesis bypass to `remaining_epochs = 0`). Pre-genesis bypass is logged explicitly with a clear decision message.

**Implementation Notes:**
- RED commit first: `crates/doppelganger/tests/forward_window_pre_genesis.rs` — assert that calling `register(pubkey, 0)` either marks the validator `Safe` immediately (pre-genesis bypass) or `Pending` with an explicit log line; either way, the registration path is invoked. Test the `bin/rvc/src/main.rs` flow via a small harness or unit-test the pre-genesis branch directly. Currently `develop`'s `if current_epoch > 0` guard skips this entirely.
- Files modified: `bin/rvc/src/main.rs:1264-1287` (drop the `current_epoch > 0` guard; always call `run_doppelganger_detection`); `crates/doppelganger/src/forward_window.rs` (pre-genesis branch: if `current_epoch == 0`, mark `Safe` with an explicit `info!` log per Research R8 "pre-genesis bypass to remaining_epochs = 0").
- Watch out for: the pre-genesis bypass is a defined behavior, not an oversight; log it clearly so operators see the decision in logs.

**Acceptance Criteria:**
- [ ] RED test `crates/doppelganger/tests/forward_window_pre_genesis.rs` fails on `develop` (the path is skipped).
- [ ] After GREEN: pre-genesis registration always invoked; explicit `info!` log records the bypass decision.
- [ ] S-3 acceptance criterion asserted: epoch 0 path invokes detection.
- [ ] Commit messages: `test(doppelganger): S-3 — RED pre-genesis path skips detection`, `fix(doppelganger,rvc): S-3 — always invoke ForwardWindowMachine::register; pre-genesis bypass logged`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.

**Testing Notes:**
- Verifying the `bin/rvc/src/main.rs` flow may need a thin integration shim; alternatively, unit-test the pre-genesis branch in `forward_window.rs` and assert the call-site change with a `grep` test.

---

### Issue 2.9a: D-3 — `SigningGate` skeleton: slashable paths + per-pubkey async `ValidatorLockMap`

- **Points:** 3
- **Type:** feature (the central seam per architecture P1+P4; slashable half of the split)
- **Priority:** P0
- **Blocked by:** 2.4 (`PubkeyScopedDb`), 2.5 (`stage_block`/`stage_attestation` signatures drop `client_cn` — `SigningGate` calls these signatures and would otherwise compile against the wrong arity), 2.6 (`ForwardWindowMachine` for `SigningEnablement` impl)
- **Blocks:** 2.9b, 2.10a
- **Scope:** 2 days

**Description:**
Land the first half of `crates/signer::SigningGate` per architecture Module: `signer`: the struct skeleton, the slashable signing paths (block, attestation), and the per-pubkey async lock map. Issue 2.9b extends the same struct with non-slashable paths, the aggregate-and-proof chain-of-custody skeleton, and `FailClosedDefault`. Issues 2.10a/2.10b wire every signing call site through the completed gate.

The gate composes `Arc<SlashingDb>` / `PubkeyScopedDb`, `Arc<dyn SigningEnablement>` (concrete: `ForwardWindowMachine` from 2.6), `Arc<CompositeSigner>` (BLS backend), and `Arc<ValidatorLockMap>` (per-pubkey async mutex for TOCTOU). This issue lands the skeleton struct, the slashable-message methods, the lock map, and the error enum; 2.9b adds the non-slashable methods + `FailClosedDefault` trait.

**Implementation Notes:**
- RED commits this issue: `crates/signer/tests/gate_block_doppelganger_blocked.rs`, `crates/signer/tests/gate_attestation_doppelganger_blocked.rs`, `crates/signer/tests/gate_per_validator_lock.rs`. Each asserts the gate refuses to sign in the relevant scenario; tests pass after this issue lands the GREEN code.
- New files: `crates/signer/src/gate.rs` (the `SigningGate` struct + `sign_block`, `sign_attestation`); `crates/signer/src/locks.rs` (`ValidatorLockMap`); `crates/signer/src/error.rs` (`SigningGateError` variants per architecture: `BlockedByDoppelganger | BlockedBySlashingDb | SigningFailed | KeyNotFound | UnknownPubkey`).
- Public API delivered this issue: `SigningGate::sign_attestation`, `SigningGate::sign_block`. The non-slashable methods (`sign_sync_committee_message`, `sign_aggregate_and_proof`, `sign_contribution_and_proof`, `sign_selection_proof`, `sign_randao_reveal`, `sign_voluntary_exit`, `sign_builder_registration`) are stubbed `todo!()` and filled in by 2.9b.
- Defense-in-depth per slashable message (delivered here): (1) per-pubkey lock acquire from `ValidatorLockMap`, (2) `SigningEnablement::is_signing_enabled` check (the default-`false` semantics from `FailClosedDefault` arrive in 2.9b; this issue uses an explicit `match` returning `Err(UnknownPubkey)` until 2.9b lands), (3) `PubkeyScopedDb::stage_*` (consumes the 2.5 signatures), (4) SQLite UNIQUE index as storage layer, (5) call backend, (6) commit on success / discard on failure.
- Watch out for: `ValidatorLockMap` must be async-Mutex (e.g. `tokio::sync::Mutex`) since signing is async; cleanup of stale entries can be deferred (HashMap not unbounded in practice — capped by registered-validator count).
- Watch out for: 2.5 dropped `client_cn` from the staging signatures; this issue's `SigningGate::sign_block`/`sign_attestation` MUST NOT pass `client_cn` to `stage_block`/`stage_attestation` (compile-error guard is now structural).
- Watch out for: temporarily explicit `Err(UnknownPubkey)` is fine because 2.9b will replace it with a `FailClosedDefault`-driven path; do not invent a different default semantic here that 2.9b would then have to undo.

**Acceptance Criteria:**
- [ ] `crates/signer/src/gate.rs` compiles with `SigningGate::sign_block` + `sign_attestation` implementations; remaining methods stubbed `todo!()`.
- [ ] `crates/signer/src/locks.rs` exposes `ValidatorLockMap` backed by `tokio::sync::Mutex`.
- [ ] `crates/signer/src/error.rs` exposes `SigningGateError` with the five variants per architecture.
- [ ] RED test `crates/signer/tests/gate_block_doppelganger_blocked.rs` fails before GREEN and passes after.
- [ ] RED test `crates/signer/tests/gate_attestation_doppelganger_blocked.rs` fails before GREEN and passes after.
- [ ] Per-pubkey lock asserted via `crates/signer/tests/gate_per_validator_lock.rs` (two concurrent signs for the same pubkey serialize).
- [ ] No direct `stage_block(_, client_cn, ...)` / `stage_attestation(_, client_cn, ...)` call (2.5 dropped the parameter; `grep client_cn` inside `crates/signer/src/gate.rs` returns empty).
- [ ] Commit messages: `test(signer): D-3 — RED gate block/attestation fail closed`, `fix(signer): D-3 — SigningGate slashable skeleton + ValidatorLockMap`.
- [ ] No new external dependencies.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for P0.

**Testing Notes:**
- Mocks: a `MockSigningEnablement` (returns configured `bool` per pubkey), a `MockBlsSigner` (returns a dummy signature), and a real `SlashingDb` against an in-memory SQLite.
- The integration with real `ForwardWindowMachine` and `PubkeyScopedDb` is exercised in Issue 2.10a/2.10b's call-site rewiring.
- Non-slashable RED tests land in 2.9b alongside the implementations they cover.

---

### Issue 2.9b: D-3 — `SigningGate` non-slashable paths + aggregate chain-of-custody skeleton + `FailClosedDefault`

- **Points:** 2
- **Type:** feature (non-slashable half of the SigningGate split)
- **Priority:** P0
- **Blocked by:** 2.9a (extends the same `SigningGate` struct + replaces 2.9a's explicit `UnknownPubkey` path with `FailClosedDefault`)
- **Blocks:** 2.10a, 2.11, 2.13
- **Scope:** 1-2 days

**Description:**
Complete `crates/signer::SigningGate` by filling in the non-slashable methods (randao, sync committee message, sync contribution, aggregate-and-proof, voluntary exit, builder registration, selection proof) and the `FailClosedDefault` trait. Land the SS-2/SS-3 chain-of-custody skeleton on `sign_aggregate_and_proof` (skeleton method + invariant doc-comment; the final GREEN ride-along closing `bin/rvc-signer/src/service.rs:698-740` lands in Phase 4 Issue 4.5). Land the unknown-pubkey fail-closed semantics that Issue 2.11's rename relies on.

**Implementation Notes:**
- RED commits this issue: `crates/signer/tests/gate_sync_doppelganger_blocked.rs`, `crates/signer/tests/gate_aggregate_no_slashing_db.rs`, `crates/signer/tests/gate_unknown_pubkey_fails_closed.rs` (the unknown-pubkey RED test asset that Phase 2 Issue 2.11 also references — see Issue 2.11 Implementation Notes for the content-dependency callout).
- Files extended: `crates/signer/src/gate.rs` (replace `todo!()` stubs for `sign_sync_committee_message`, `sign_aggregate_and_proof`, `sign_contribution_and_proof`, `sign_selection_proof`, `sign_randao_reveal`, `sign_voluntary_exit`, `sign_builder_registration`).
- New file: `crates/signer/src/fail_closed.rs` (`FailClosedDefault` trait + `impl FailClosedDefault for bool { fn default_when_unknown() -> bool { false } }`).
- 2.9a's explicit `Err(UnknownPubkey)` path is replaced by a `FailClosedDefault`-driven default that returns `false` for `is_signing_enabled` on unknown pubkeys; same observable behavior, now via the codified trait.
- Defense-in-depth per non-slashable message: (1) `is_signing_enabled` check (now via `FailClosedDefault` for unknown pubkeys), (2) sign — no DB stage.
- `SigningGate::sign_aggregate_and_proof` does NOT call slashing DB (Research R5 + SS-2/SS-3 chain-of-custody invariant): pre-condition that the inner `Attestation` was signed via `sign_attestation` first. Add a doc-comment block explicitly stating this invariant. The final SS-2/SS-3 GREEN ride-along (closing the bug at `bin/rvc-signer/src/service.rs:698-740`) happens in Phase 4 Issue 4.5; this issue lands only the skeleton method + doc-comment.
- Watch out for: `crates/signer/tests/gate_unknown_pubkey_fails_closed.rs` is referenced by 2.11 as the canonical gate-side semantic test — its assertions must hold after the rename in 2.11.

**Acceptance Criteria:**
- [ ] `crates/signer/src/gate.rs` has no remaining `todo!()` stubs; all nine public-API methods implemented.
- [ ] `crates/signer/src/fail_closed.rs` defines `FailClosedDefault` with the `bool → false` impl (codifies PRD §6.3 / Assumption #7).
- [ ] `SigningGate::sign_aggregate_and_proof` skeleton landed; explicit doc-comment block states the SS-2/SS-3 chain-of-custody invariant ("caller must have signed the inner Attestation via `sign_attestation` first; the final closing of `service.rs:698-740` is Issue 4.5").
- [ ] RED test `crates/signer/tests/gate_sync_doppelganger_blocked.rs` fails before GREEN and passes after.
- [ ] RED test `crates/signer/tests/gate_aggregate_no_slashing_db.rs` fails before GREEN and passes after; specifically asserts no `stage_attestation` row is committed by the aggregate path.
- [ ] RED test `crates/signer/tests/gate_unknown_pubkey_fails_closed.rs` fails before GREEN and passes after — gate refuses to sign for an unknown pubkey via the `FailClosedDefault` path.
- [ ] 2.9a's earlier `Err(UnknownPubkey)` path is replaced by the `FailClosedDefault` semantic; the change is observable only through the trait (the test asserts behavior, not the path).
- [ ] Commit messages: `test(signer): D-3 — RED gate non-slashable + unknown-pubkey fail closed`, `fix(signer): D-3 — SigningGate non-slashable paths + aggregate chain-of-custody skeleton + FailClosedDefault`.
- [ ] No new external dependencies.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for P0.

**Testing Notes:**
- Reuse the mocks from 2.9a (`MockSigningEnablement`, `MockBlsSigner`, in-memory SQLite `SlashingDb`).
- The `gate_unknown_pubkey_fails_closed.rs` test asset is reused by Issue 2.11 (rename + flip default); see 2.11 Implementation Notes for the content-dependency callout.

---

### Issue 2.10a: D-3 — signer-side wrapper + every typed handler in `bin/rvc-signer/src/service.rs` routed through `SigningGate`

- **Points:** 3
- **Type:** fix (broad refactor — narrow per call site; signer-side half of the split)
- **Priority:** P0
- **Blocked by:** 2.9b (full `SigningGate` API including non-slashable methods must exist before handlers can route through it)
- **Blocks:** 2.10b
- **Scope:** 2 days

**Description:**
Close the signer-side half of PRD acceptance criterion D-3(a): every typed handler in `bin/rvc-signer/src/service.rs` routes through `SigningGate::sign_*`. Land the `crates/signer::slashable` and `crates/signer::non_slashable` wrapper modules. Issue 2.10b extends the wiring to `crates/validator-store/src/store.rs` and the orchestrator call sites; the grep-gate acceptance test lives there.

**Implementation Notes:**
- RED tests already landed in 2.9a/2.9b; this issue makes the `rvc-signer`-side integration paths route through the gate. Add `crates/signer/tests/integration_block_routed_through_gate.rs` asserting block proposal on the standalone signer calls `SigningGate::sign_block`.
- New files: `crates/signer/src/slashable.rs` (block+attestation wrapper paths), `crates/signer/src/non_slashable.rs` (randao, sync, agg, exit, builder, selection wrapper paths).
- Files modified: `crates/signer/src/lib.rs` (existing `SignerService` wraps `SigningGate`); `bin/rvc-signer/src/service.rs` (every typed handler shrinks to: deserialize → fork validate → `gate.sign_*` → serialize).
- The `validator-store`/orchestrator wiring is deferred to 2.10b so this issue can ship a focused, reviewable `rvc-signer`-only PR.
- Watch out for: `bin/rvc-signer/src/service.rs` may contain branches that bypass `SignerService` (e.g. the v1 raw-root paths). 2.1/2.2 already unregistered the v1 listener; any remaining bypass would be a CI failure on the enumeration test landed in 2.2.

**Acceptance Criteria:**
- [ ] Every slashable + non-slashable typed handler in `bin/rvc-signer/src/service.rs` routes through `SigningGate::sign_*`.
- [ ] `crates/signer/src/slashable.rs` and `crates/signer/src/non_slashable.rs` compile with the wrapper API.
- [ ] `crates/signer/tests/integration_block_routed_through_gate.rs` passes (exercises the standalone-signer block proposal end-to-end).
- [ ] Issue 2.9a + 2.9b unit tests still green.
- [ ] Commit message: `fix(signer,rvc-signer): D-3 — signer-side wrapper + every rvc-signer typed handler routes through SigningGate`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for P0.

**Testing Notes:**
- The `signer-registry`-driven enumeration test from Issue 2.2 is the structural check; the integration test here is the behavioral check. Both stay green.
- 2.10b adds the cross-crate grep-gate that asserts no direct `CompositeSigner::sign` calls remain anywhere outside `crates/signer`.

---

### Issue 2.10b: D-3 — `validator-store` + orchestrator call sites; grep-gate asserting no direct `CompositeSigner::sign` outside `crates/signer`

- **Points:** 2
- **Type:** fix (orchestrator/validator-store half of the split)
- **Priority:** P0
- **Blocked by:** 2.10a (signer-side wrapper must exist before orchestrator can consume it)
- **Blocks:** 2.11, 2.12, 2.13
- **Scope:** 1-2 days

**Description:**
Close the orchestrator-side half of PRD acceptance criterion D-3(a): every signing call site in `crates/validator-store` and `crates/rvc/src/orchestrator` consults `is_signing_enabled` via the gate (or its trait). Land the grep-gate acceptance criterion asserting **no direct `CompositeSigner::sign` calls remain outside `crates/signer`** — this is the type-level structural enforcement per architecture P4.

**Implementation Notes:**
- Files modified: `crates/validator-store/src/store.rs:218-220` (consult `is_signing_enabled` via gate); orchestrator call sites in `crates/rvc/src/orchestrator/coordinator.rs:591-618`, `crates/rvc/src/orchestrator/sync_committee.rs:54,137,294`, `crates/rvc/src/orchestrator/aggregation.rs`.
- Per ADR-012's two-layer defense, both the orchestrator fast-path (consults same `Arc<dyn SigningEnablement>`) and the signer-side gate (the storage-layer defense from 2.10a) consult the same trait method so the two layers cannot diverge.
- Grep-gate test: `crates/signer/tests/no_direct_composite_signer_outside_signer.rs` runs `cargo metadata` to enumerate workspace crates, then for each crate ≠ `signer` greps source files for `CompositeSigner::sign` / `crypto::sign_*` / `Signer::sign` call patterns. Any match outside `crates/signer` fails the test. This is the standing CI enforcement for architecture P4.
- Issue 2.2's enumeration test (`signing_path_enumeration.rs`) is flipped to assert the stronger invariant (every method routes through `SigningGate`) in Issue 2.13.
- Watch out for: the orchestrator fast-path is the early-skip that avoids unnecessary BLS work when the gate is off; keep it as a perf optimization, but the gate is the source of truth.
- Watch out for: test files (`crates/*/tests/`) and dev-fixtures are excluded from the grep-gate's allow-list — those may legitimately call `CompositeSigner::sign` for setup.

**Acceptance Criteria:**
- [ ] `crates/validator-store/src/store.rs:218-220` consults `is_signing_enabled` via the gate (or its trait).
- [ ] Orchestrator call sites in `crates/rvc/src/orchestrator/{coordinator,sync_committee,aggregation}.rs` consult `is_signing_enabled` via the gate; no direct `CompositeSigner::sign` calls remain in production source.
- [ ] **Grep-gate test `crates/signer/tests/no_direct_composite_signer_outside_signer.rs` passes:** asserts via `cargo metadata` enumeration that no source file outside `crates/signer/src/**` calls `CompositeSigner::sign` / `crypto::sign_*` / `Signer::sign` directly in production code paths. Test/dev paths excluded with explicit allow-list.
- [ ] D-3 acceptance criterion (a) satisfied end-to-end: per-path tests (block, attestation, sync, aggregate, contribution, selection) all show the gate is consulted at every entry point.
- [ ] Issue 2.10a's `integration_block_routed_through_gate.rs` and Issue 2.9a/2.9b unit tests still green.
- [ ] Commit message: `fix(validator-store,rvc,signer): D-3 — orchestrator + validator-store consult gate; grep-gate asserts no direct CompositeSigner::sign outside crates/signer`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for P0.

**Testing Notes:**
- The grep-gate becomes a standing CI gate from this issue forward, alongside `tests/architecture_no_cycles.rs` (Phase 1 Task 1.6) and `bin/rvc-signer/tests/signing_path_enumeration.rs` (Issue 2.2).
- Together, the three standing gates structurally enforce: (1) the level-graded DAG, (2) the enumeration invariant on the live listener, (3) the type-level absence of `CompositeSigner::sign` outside `crates/signer`.

---

### Issue 2.11: D-3 — rename `is_attesting_enabled` → `is_signing_enabled` + flip unknown-pubkey default to `false`

- **Points:** 2
- **Type:** refactor (PRD Assumption #7)
- **Priority:** P0 (follow-on to D-3)
- **Blocked by:** 2.10b
- **Blocks:** 2.13
- **Scope:** 1-2 days

**Description:**
Close PRD acceptance criterion D-3(b): `is_attesting_enabled` (or a renamed `is_signing_enabled`) for an unknown pubkey returns `false` (fail-closed). On `develop` today `crates/validator-store/src/store.rs:218-220` returns `unwrap_or(true)` for unknown pubkeys (fail-open). Rename to `is_signing_enabled` everywhere (PRD Assumption #7) and flip the default for unknown pubkeys to `false`. The gate-side semantic was already established by Issue 2.9b's `FailClosedDefault`; this issue propagates the rename through the validator-store + orchestrator call sites.

**Implementation Notes:**
- **Content dependency on Issue 2.9b:** the RED test asset `crates/signer/tests/gate_unknown_pubkey_fails_closed.rs` is authored and landed by Issue 2.9b (not this issue). This issue's gate-side semantics are already exercised by that test; this issue adds the validator-store-side counterpart `crates/validator-store/tests/unknown_pubkey_fail_closed.rs` and verifies the 2.9b test still holds after the rename.
- Files modified: `crates/signer/src/enablement.rs` (the `SigningEnablement` trait method name; default impl uses `FailClosedDefault` from 2.9b); `crates/validator-store/src/store.rs:218-220` (rename + flip default); call sites across `crates/rvc/src/orchestrator/{coordinator.rs:591-618, sync_committee.rs:54,137,294, aggregation.rs}` — see PRD §5 P0 table.
- This rename is mechanical but cross-crate; use `cargo grep is_attesting_enabled` then change-all.
- Watch out for: any caller that relied on the fail-open default (e.g. tests asserting "unknown pubkey signs") needs updating to register the pubkey explicitly. Document in commit message.

**Acceptance Criteria:**
- [ ] `is_attesting_enabled` no longer exists in the codebase (`grep` returns empty).
- [ ] `is_signing_enabled` returns `false` for unknown pubkeys.
- [ ] `crates/validator-store/tests/unknown_pubkey_fail_closed.rs` passes (new in this issue).
- [ ] Issue 2.9b's `crates/signer/tests/gate_unknown_pubkey_fails_closed.rs` (content dependency) still passes after the rename — the test asset is owned by 2.9b but its assertions exercise the semantic landed jointly by 2.9b + this issue.
- [ ] All existing tests still pass; any test that relied on fail-open default is updated.
- [ ] Commit message: `refactor(validator-store,signer,rvc): D-3 — rename is_attesting_enabled → is_signing_enabled; flip unknown-pubkey default to false (fail-closed)`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.

**Testing Notes:**
- The rename touches the full signer-call-site set; a `cargo grep is_signing_enabled` should match exactly the renamed call sites.

---

### Issue 2.12: KM-2 — replace cancel-token map with `ForwardWindowMachine::cancel` (race-impossible)

- **Points:** 2
- **Type:** fix (PRD §7.1 cluster with D-3 + KM-1)
- **Priority:** P1 (escalated into M1 per architecture cluster + ADR-005)
- **Blocked by:** 2.6 (directly consumes `ForwardWindowMachine::cancel` / `register` API surface authored in 2.6), 2.10b (orchestrator-side gate must be centralised first so the keymanager handler can route its cancel/re-register through the single `ForwardWindowMachine` instance held by the orchestrator)
- **Blocks:** 2.13
- **Scope:** 1-2 days

**Description:**
Close PRD acceptance criteria KM-2(a)+(b)+(c)+(d). The current `crates/keymanager-api/src/handlers.rs:160-195,259-272` doppelganger cancel-token map can be overwritten without cancelling the displaced token in a concurrent delete+re-import race. Per ADR-005, replace with `ForwardWindowMachine::cancel` as the single implementation; the race becomes structurally impossible because there is no `insert` API that returns an un-cancelled old token.

**Implementation Notes:**
- RED test first: `crates/doppelganger/tests/forward_window_km2_race.rs` (per architecture file structure) — simulate concurrent delete+re-import; assert the displaced monitoring is cancelled and the new monitoring window starts fresh from the import's `current_epoch`.
- Files modified: `crates/keymanager-api/src/handlers.rs` (drop the cancel-token map; consume `doppelganger::ForwardWindowMachine::cancel(pubkey)` on delete and `register(pubkey, current_epoch)` on import); `crates/doppelganger/src/forward_window.rs` (`cancel(pubkey)` implementation: removes the validator from the state map; the next `register` starts fresh).
- Per architecture Module: `doppelganger` Failure Modes: "delete cancels pending monitoring; re-import re-registers fresh."
- Watch out for: the keymanager handler must hold a single lock across the delete's keystore-removal and the cancel call; otherwise the race window reopens. The single-lock invariant is enforceable via the keymanager's existing handler-state mutex.

**Acceptance Criteria:**
- [ ] RED test `crates/doppelganger/tests/forward_window_km2_race.rs` fails on `develop` and passes after GREEN.
- [ ] `crates/keymanager-api/src/handlers.rs` no longer references a per-pubkey cancel-token map; consumes `ForwardWindowMachine::cancel`.
- [ ] KM-2 acceptance criteria (a)+(b)+(c)+(d) all asserted in tests.
- [ ] Commit messages: `test(doppelganger): KM-2 — RED concurrent delete+re-import race`, `fix(keymanager-api,doppelganger): KM-2 — cancel-token race closed via ForwardWindowMachine::cancel`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.

**Testing Notes:**
- The race test needs a Tokio runtime spawning two concurrent tasks; serialise via the structural single-implementation (no token map exists, so the race window collapses).

---

### Issue 2.13: M1 phase-exit integration — PRD M4/M6 verification suite + flip enumeration gate to strict

- **Points:** 2
- **Type:** test + standing-gate flip
- **Priority:** P0 (closes PRD M4 + M6)
- **Blocked by:** 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9a, 2.9b, 2.10a, 2.10b, 2.11, 2.12
- **Blocks:** Phase 3 entry
- **Scope:** 1-2 days

**Description:**
Close PRD M4 (no signing path on `rvc-signer` can produce a signature without EIP-3076 consultation for slashable message types) and M6 (doppelganger window enforced at every signing entry point). Land the integration tests that exercise the full M1 surface end-to-end, then flip `bin/rvc-signer/tests/signing_path_enumeration.rs` (from Issue 2.2) to assert the stronger invariant — every registered handler routes through `SigningGate`. This is the gate-flip that locks M1 into place.

**Implementation Notes:**
- New tests: `bin/rvc-signer/tests/m4_enumeration.rs` (the PRD M4 enumeration test; uses `signer-registry` static metadata + a `cfg(test)` introspection of the live listener); `crates/signer/tests/m6_gate_per_path.rs` (per-path test: gate off → block / attestation / sync / aggregate / contribution / selection all refuse to produce a signature).
- Flip Issue 2.2's enumeration assertion from "every method is non-slashable OR registered as routing through the gate-trait" to "every method is non-slashable OR confirmed via `signer-registry` to invoke `SigningGate::sign_*`."
- Update tracker: every M1 finding row gets its commit hashes (RED + GREEN) + test file paths.
- Watch out for: the M4 enumeration must include the v1 raw-root handlers from Issue 2.2 — they are present (compiled) but return `Unimplemented`; they are "registered" only on the legacy off-by-default listener (which is documented but not implemented this milestone), so the enumeration on the live listener must show zero v1 entries.

**Acceptance Criteria:**
- [ ] `bin/rvc-signer/tests/m4_enumeration.rs` is the canonical PRD M4 test and passes.
- [ ] `crates/signer/tests/m6_gate_per_path.rs` covers all six paths (block, attestation, sync-message, sync-contribution, aggregate-and-proof, selection-proof) and passes.
- [ ] Issue 2.2's `signing_path_enumeration.rs` strict assertion is flipped on.
- [ ] PRD §6.6 tracker `plan/remediation/tracker.md` shows every M1 finding row complete with commit hashes + test file paths.
- [ ] PRD M4 and M6 marked Verified in the tracker.
- [ ] Commit message: `test(rvc-signer,signer): M1 — PRD M4 + M6 verification suite + flip enumeration gate to strict`.
- [ ] `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Reviewer Approve for the phase-exit PR.

**Testing Notes:**
- This issue is the M1 closing milestone. After this lands, Phase 3 (M2 shared pre-work) can begin.
