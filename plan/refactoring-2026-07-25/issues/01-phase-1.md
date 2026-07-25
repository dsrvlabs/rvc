# Refactoring Phase 1: Correctness Fixes & Safety Nets (Theme A)

> The plan's first phase: fix the one live EIP-3076 rule divergence on the production signing path,
> then install the tests that make Phases 2–6 safe to attempt. Source: [`plan/refactoring-2026-07-25/refactoring-plan.md`](../refactoring-plan.md)
> §3 Theme A, §4 Phase 1, §6 Validation Strategy; evidence in [`plan/refactoring-2026-07-25/refactoring-findings.json`](../refactoring-findings.json)
> (F1, F29, F30, F48, F50, F100, F124, F126, F127).
>
> All file:line references below were re-verified against HEAD `develop` (`a7f8cdf`) while estimating.
> Where a plan or findings citation had drifted, the corrected reference is given and the drift is
> called out under **Citation check**.

## Phase Overview

- **Goal:** the production `stage_*` slashing path matches EIP-3076 (including watermark equality);
  the certified conformance/property artillery runs against that production path instead of a
  path with zero production callers; a pipeline-level double-vote test guards the
  orchestrator → signer → slashing wiring; the runtime key-import path actually reaches the
  orchestrator; three smaller correctness/dead-code defects (unsafe test downcast, `--password-dir`,
  gRPC sign metrics) are closed.
- **Issue count:** 12 issues, 26 points.
- **Estimated duration:** ~26 days single-stream; ~14 days with 2 developers on the two streams below.
- **Entry criteria:** working tree on `develop`, green on the standing invariant
  (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo nextest run --workspace`).
- **Exit criteria (phase gate):**
  - [ ] `crates/slashing/src/stage.rs` block-slot and attestation-target watermark comparisons use
        `<=`; stage-path watermark-equality tests prove equality is blocked.
  - [ ] The EIP-3076 conformance suite is green **on the stage path** (`stage_* → commit()/discard()`),
        and the property tests drive the same path.
  - [ ] A pipeline double-vote test rejects the second of two conflicting `process_slot` calls; the
        slashing-DB-error path is asserted fail-closed unconditionally.
  - [ ] `KeystoreManagerAdapter` / `RemoteKeyManagerAdapter` cannot be constructed without the
        `PubkeyMap` + `key_gen_tx` pair; `DutyOrchestrator` has exactly one constructor; an
        integration test proves an API-imported key clears the duty cache, and a doppelganger gate
        test proves it produces no attestations until its window clears.
  - [ ] No `unsafe` in `crates/builder`; workspace `unsafe_code` lint active with an explicit allow-list.
  - [ ] `--password-dir` is gone from CLI, config, and docs; a missing password source is a startup error.
  - [ ] All 10 rvc-signer gRPC v2 sign handlers record sign metrics through one shared helper; a scrape
        test asserts non-zero series after a sign.
  - [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
        `cargo nextest run --workspace`, and `crates/architecture-tests` green.

## Assumptions (verified against HEAD `a7f8cdf`)

- **P1 — The A1 divergence is exactly two comparisons.** `stage.rs:356` is `if (slot as i64) < wm`
  and `stage.rs:506` is `if (target_epoch as i64) < wt`, while the equivalents in `db.rs` (`:1276`,
  `:1377`, `:969`, `:1582`) all read `<=` with `SEC-9 / M-1` comments. The **source** watermark stays
  `<` on both paths (`stage.rs:490` vs `db.rs:947-955`) — EIP-3076 blocks equality on the block-slot
  and attestation-target watermarks only. A1 must not "fix" the source comparison.
- **P2 — Nothing currently asserts the old `<` behavior through the stage path.** Every
  `set_block_watermark` / `set_attestation_watermark` caller in the workspace is either inside
  `crates/slashing/src/db.rs`'s own test module (which asserts through `is_safe_to_sign` /
  `check_and_record_*`) or in `crates/slashing/tests/conformance.rs:291-352` (the `real_watermarks`
  runner, which never calls `stage_*`). So A1 adds tests; it does not have to renegotiate existing ones.
- **P3 — The two APIs are drop-in comparable.** `check_and_record_attestation(_client_cn, pubkey,
  source, target, root, gvr)` (`db.rs:1523`) and `stage_attestation(pubkey, source, target, root, gvr)`
  (`stage.rs:452`) differ only by the ignored `_client_cn` and the staged-guard return; both perform the
  same GVR-pinning check, watermark checks, double-vote, surround and surrounded checks, and both read
  the same `strict_semantics` flag off the shared `SlashingDb` (`db.rs:59`, `stage.rs:340`).
- **P4 — The SEC-1/SEC-2 security phase has already landed.** Commits `0200aab`, `dee059b`, `16ba7fb`,
  `6d77dad` wired the doppelganger enablement gate into `SignerService`
  (`SignerService::new(..).with_enablement(..)`), constructed `ForwardWindowMachine` in
  `bin/rvc/src/main.rs:1401`, added the liveness loop (`crates/rvc/src/liveness_loop.rs`), and added the
  deletion denylist. A4's doppelganger gate test is therefore testable end-to-end today and does **not**
  need to build enablement machinery.
- **P5 — F1's core claim still holds.** `with_pubkey_map` exists on both adapters
  (`keymanager_adapters.rs:73` and `:775`) and has zero callers outside the defining file; `main.rs:1626`
  builds `KeystoreManagerAdapter::new(..).with_denylist(..)` with no `pubkey_map`; both `DutyOrchestrator::new`
  (`coordinator.rs:150`) and `new_with_attesting_enabled` (`coordinator.rs:186`) still do
  `let (_key_gen_tx, key_gen_rx) = watch::channel(0u64)`, so `key_gen_rx.has_changed()` at
  `coordinator.rs:322` is permanently false.

## Citation check (drift found while grounding the estimates)

| Item | Plan/finding says | HEAD reality | Effect on estimate |
|---|---|---|---|
| A1 | `stage.rs:356`, `stage.rs:506` | Exact match | none |
| A2 | "76 conformance cases"; conformance drives `check_and_record_*` | **38** cases × **3** runners (`complete`, `minimal_conservative`, `real_watermarks`) = 114 test fns. A third runner `run_with_real_watermarks` (`conformance.rs:270`) was added after the finding was written and already uses the real `set_/get_*_watermark` API | A2 is partly started; "76" reconciles with the 2-runner end state this phase targets |
| A2/F126 | "conformance runner re-implements watermarks in test-local HashMaps" | Still true of `run_minimal_conservative` (`:167-264`); `run_with_real_watermarks` uses real storage but still re-implements the **decision** in the test (`slot > wm`, `target > wm_target` at `:321`,`:345`) | A2 scope sharpened: move the *decision*, keep the interchange→watermark *projection* in the harness until B5 |
| A3/F124 | "the concurrent same-validator signer test uses identical data so it passes even with the mutex removed" | **Stale.** `test_concurrent_signing_same_validator_serialized` (`crates/signer/src/lib.rs:2636`) uses source=59 vs source=58 against the same target=60 — genuinely conflicting, and asserts exactly one success / one failure | A3 shrinks; that sub-item is dropped |
| A3/F124 | "no fail-closed test for DB errors" | **Partly stale but not done.** A corrupted-DB test exists (`lib.rs:~2760-2795`) but its only assertion is inside `if let Ok(db) { … }`, so it passes vacuously when `SlashingDb::open` errors | A3 keeps a hardening sub-item |
| A4 | ctor churn "across bin/rvc + tests" | 30 `DutyOrchestrator::new(` call sites + 6 `new_with_attesting_enabled` + 51 `KeystoreManagerAdapter::new`/`RemoteKeyManagerAdapter::new` call sites | A4 cannot be one issue; split into three |
| A5 | "consider `unsafe_code = "deny"` workspace lint" | No `[workspace.lints]` table exists and no member crate has `[lints]`; 25 members; legitimate `unsafe` lives in `crates/signer/tests/zero_alloc.rs` (GlobalAlloc) and `crates/crypto/tests/*.rs` (`env::set_var`) | Split: delete the unsafe block (1) + install the lint with allow-list (1) |
| A6 | `main.rs:82`, `:1031`, `config.rs:58` | Exact match; plumbing spans 10 sites incl. `config.rs:109`,`:137`,`:192`,`:266`,`:305`, two config tests at `:587`,`:602`, and `integration_polish.rs:64` | none |
| A7 | `routes.rs:167-176` for the HTTP precedent | File moved: `bin/rvc-signer/src/http_api/routes.rs:163-177` | none |
| A7 | "type×outcome labels" | Existing gRPC collectors are `sign_total{backend,result}`, `sign_duration_seconds{backend}`, `sign_errors_total{backend,error_type}` (`metrics.rs:46-75`) — not type×outcome | Label-shape decision recorded in RF1-09; arity change breaks the scrape test at `http_api/routes.rs:1286` |

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| RF1-01 | Stage-path watermark equality: `<` → `<=` + stage watermark tests | 2 | bugfix | — | A |
| RF1-02 | Pipeline double-vote test + unconditional fail-closed DB-error assertion | 3 | test | — | A |
| RF1-03 | Retarget the conformance `complete` runner at `stage_* → commit/discard` | 3 | test | RF1-01 | A |
| RF1-04 | Move the conformance watermark **decision** into production code; retire the duplicate runner | 2 | test | RF1-03 | A |
| RF1-05 | Retarget the slashing property tests at the stage path | 2 | test | RF1-03 | A |
| RF1-06 | Adapters require `PubkeyMap` + `key_gen_tx` at construction | 3 | refactor | — | B |
| RF1-07 | Collapse the three `DutyOrchestrator` constructors into one `OrchestratorDeps` ctor | 3 | refactor | RF1-06 | B |
| RF1-08 | Key-import → duty-cache integration test + doppelganger gate test | 2 | test | RF1-07, RF1-02 | B |
| RF1-09 | Record gRPC sign metrics via one shared helper in all 10 v2 handlers | 2 | bugfix | — | B |
| RF1-10 | Remove `--password-dir`; make a missing password source a startup error | 2 | bugfix | — | B |
| RF1-11 | Delete the unsafe pointer downcast in the builder test | 1 | bugfix | — | B |
| RF1-12 | Workspace `unsafe_code` lint with an explicit allow-list | 1 | chore | RF1-11 | B |

**Total: 12 issues, 26 points. Stream A = 12 points, Stream B = 14 points.**

## Execution Plan

Two streams, chosen so the file sets are disjoint:

- **Stream A — `crates/slashing/**` plus one new integration-test file under `crates/rvc/tests/`.**
  Order: `RF1-01 → RF1-02 → RF1-03 → RF1-04`, with `RF1-05` after `RF1-03` (it can also be picked up
  by whoever is free). RF1-02 is scheduled second, not last, because RF1-08 in Stream B depends on the
  fixture it builds.
- **Stream B — `crates/rvc/src/keymanager_adapters.rs` + `orchestrator/coordinator.rs` + `bin/rvc`,
  then `bin/rvc-signer` and `crates/builder`.** Order: `RF1-06 → RF1-07 → RF1-08`, then the four
  independent small items `RF1-09`, `RF1-10`, `RF1-11 → RF1-12` in any order.

Indicative 2-dev schedule (~1 point ≈ 0.5–1 working day):

| Day | Stream A | Stream B |
|-----|----------|----------|
| 1–2 | RF1-01 | RF1-06 |
| 3–5 | RF1-02 | RF1-06 → RF1-07 |
| 6–8 | RF1-03 | RF1-07 → RF1-08 |
| 9–10 | RF1-04 | RF1-09 |
| 11–12 | RF1-05 | RF1-10 |
| 13–14 | (slack / triage buffer for RF1-03) | RF1-11, RF1-12 |

**The one cross-stream contract:** RF1-02 must land its pipeline harness as a *reusable fixture*
(a `pub(crate)`/module-level helper in `crates/rvc/tests/pipeline_slashing.rs`), not inline inside a
single `#[test]` fn, because RF1-08's doppelganger gate test builds on it. Agree the fixture signature
at kickoff.

## Dependency Map

```text
Stream A:  RF1-01 ──▶ RF1-03 ──┬─▶ RF1-04
                               └─▶ RF1-05
           RF1-02 ───────────────────────────────┐
                                                 │ (fixture)
Stream B:  RF1-06 ──▶ RF1-07 ──▶ RF1-08 ◀────────┘
           RF1-09     RF1-10     RF1-11 ──▶ RF1-12
```

Longest dependency chain (critical path): **RF1-06 → RF1-07 → RF1-08 = 8 points.** The A1/A2 chain
(RF1-01 → RF1-03 → RF1-04) is 7 points. RF1-01 is the highest-*priority* item in the plan, but it is
not the longest chain — schedule Stream B's start on day 1 accordingly.

## Phase Risk Flags

- **RF1-03 triage is the phase's main unknown.** Pointing 38 conformance cases at a second, independently
  written rule implementation will surface divergences. Per the plan: *a failing case is signal, not
  noise* — each divergence gets triaged and written up before any production code changes. The 3 points
  include a triage allowance; a systemic divergence (rather than one or two cases) is the scenario that
  would push this to 5, and is the flag to raise at standup rather than absorb silently.
- **`crates/rvc/src/orchestrator/coordinator.rs` is a hotspot.** RF1-07 rewrites 30+ constructor call
  sites inside its `#[cfg(test)]` module. Nothing else in the phase may edit that file — which is why
  RF1-02's test goes in a new `crates/rvc/tests/` file.
- **RF1-01 is an intentional behavior change on the live signing path.** A validator whose block-slot
  watermark equals the slot it is about to propose will now be refused. This is the EIP-3076-correct
  outcome and matches `db.rs`, but it needs a release note.
- **RF1-10 is deployment-visible.** Removing a documented CLI flag breaks any startup script that passes
  it, and the new startup error breaks any deployment that was relying on the silent empty-password
  fallback. Release-note both.
- **RF1-09's helper is D4's future prey.** Phase 4's D4 rewrites the v2 handlers into a `SignPlan`
  dispatcher. The helper must be free-standing so D4 absorbs it rather than reimplementing it, and the
  scrape test must stay green through that unification.

---

## Issues

### Issue RF1-01: Stage-path watermark equality (`<` → `<=`) + stage watermark tests

- **Points:** 2
- **Days:** ~1–1.5
- **Type:** bugfix
- **Priority:** P0 — highest-priority item in the whole refactoring plan
- **Source plan item:** A1
- **Findings:** F48 (partial), F127
- **Blocked by:** none
- **Blocks:** RF1-03
- **Stream:** A

**What / why:**
Commit `40b6c1e` ("watermark equality… use `<=` per EIP-3076 equality blocking") applied the fix to
`crates/slashing/src/db.rs` only. The production signing path does **not** go through `db.rs` — every
production caller reaches `stage_block`/`stage_attestation` (`crates/signer/src/gate.rs:275`,`:410`;
`crates/signer/src/lib.rs:351`,`:529`; `bin/rvc-signer/src/dvt/peer_service.rs:261`,`:394`). So the fix
landed everywhere except where it matters, and `crates/slashing/tests/stage.rs` has no watermark test to
catch it. Concretely: with a block watermark of 1000, `stage_block(pubkey, 1000, …)` succeeds today and
must not.

**Files (verified at HEAD):**
- `crates/slashing/src/stage.rs:356` — `if (slot as i64) < wm` → `<=`
- `crates/slashing/src/stage.rs:506` — `if (target_epoch as i64) < wt` → `<=`
- `crates/slashing/src/stage.rs:490` — `if (source_epoch as i64) < ws` — **leave as `<`** (matches
  `db.rs:947-955`; EIP-3076 blocks equality on block-slot and att-target only)
- `crates/slashing/tests/stage.rs` — new watermark test section (file currently has 18 tests, none
  touching watermarks)
- Reference only: `crates/slashing/src/db.rs:969`,`:1276`,`:1377`,`:1582` (the already-correct `<=` sites
  with their `SEC-9 / M-1` comments)
- **Not** a third site: `PubkeyScopedDb::stage_block` / `stage_attestation`
  (`crates/slashing/src/scoped.rs:62`,`:88`) are thin delegators to `SlashingDb::stage_*` with the GVR
  pinned; they carry no watermark comparison of their own (verified). Two comparisons change, no more.

**Implementation sketch:**
1. Add the failing tests to `crates/slashing/tests/stage.rs` first (see TDD plan) using
   `SlashingDb::open_in_memory()` + `set_block_watermark` / `set_attestation_watermark`.
2. Flip the two comparisons. Carry the `SEC-9 / M-1` comment convention from `db.rs` across so the
   invariant is visible at both sites and the next rule fix is greppable.
3. Confirm the strictly-greater case still passes and the source-watermark equality case still succeeds.
4. Re-run the full slashing suite plus `crates/signer` (the stage callers) to confirm no test encoded the
   old behavior — per assumption **P2**, none does.

**Acceptance criteria:**
- [x] `stage.rs:356` and `stage.rs:506` use `<=`; `stage.rs:490` (source) still uses `<`.
- [x] Stage-path tests prove: block slot **equal** to the block watermark is rejected with
      `SlashingError::BelowBlockWatermark`; attestation target **equal** to the target watermark is
      rejected with `SlashingError::BelowAttestationWatermark`.
- [x] Stage and `check_and_record_*` return the same verdict for the same watermark inputs (a direct
      parity assertion, so the two paths cannot drift again before Phase 4's E1 unifies them).
- [x] A rejected stage leaves no row committed (the guard rolls back).
- [x] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo nextest run --workspace` green.
- [x] Release note drafted: equality-at-watermark is now refused on the live signing path.

**TDD test plan** (new, in `crates/slashing/tests/stage.rs`):
1. **RED first:** `test_stage_block_at_block_watermark_is_rejected` — set watermark 1000, `stage_block`
   at slot 1000, expect `Err(BelowBlockWatermark)`. Fails today (returns a staged guard).
2. `test_stage_attestation_at_target_watermark_is_rejected` — set (source, target) watermark (100, 200),
   stage (100, 200), expect `Err(BelowAttestationWatermark)`. Fails today.
3. `test_stage_block_above_block_watermark_succeeds` — slot 1001 with watermark 1000 still commits.
4. `test_stage_attestation_at_source_watermark_succeeds` — source **equal** to the source watermark with
   a target above the target watermark is accepted (guards against over-applying the fix).
5. `test_stage_below_watermark_commits_no_row` — after a rejection, `get_blocks`/`get_attestations` empty.
6. `test_stage_and_check_and_record_agree_on_watermark_equality` — parity assertion across both paths.

**Risks:** the behavior change is intentional and deployment-visible; a validator restoring from an
interchange whose maxima equal its next duty will now be refused (correct per EIP-3076, but it is the
kind of thing that generates a support ticket). Mitigation: release note, and the parity test makes the
new semantics explicit.

---

### Issue RF1-02: Pipeline double-vote test + unconditional fail-closed DB-error assertion

- **Points:** 3
- **Days:** ~1.5–2
- **Type:** test
- **Priority:** P0
- **Source plan item:** A3
- **Findings:** F124
- **Blocked by:** none
- **Blocks:** RF1-08 (consumes the fixture)
- **Stream:** A

**What / why:**
No test drives two `process_slot` calls with conflicting `AttestationData`, so a refactor that severs the
`AttestationService → SignerService → SlashingDb` wiring passes every existing test. Every coordinator
test builds a fresh in-memory `SlashingDb` and processes a single slot. This test is named in the plan's
§6 validation strategy as the guard for Phases 4–5 — it is the reason the orchestrator consolidation can
be attempted at all.

Two of F124's three sub-items are **stale** and are explicitly out of scope (see Citation check): the
concurrent same-validator test at `crates/signer/src/lib.rs:2636` already uses conflicting data
(source 59 vs 58, same target 60). The third sub-item survives in weakened form: the corrupted-DB test
around `crates/signer/src/lib.rs:2760-2795` wraps its only assertion in `if let Ok(db) { … }`, so it
asserts nothing when `SlashingDb::open` fails — that is not a fail-closed test.

**Files:**
- **New:** `crates/rvc/tests/pipeline_slashing.rs` — integration test + the reusable fixture. A new file
  rather than the `coordinator.rs` test module, so RF1-07's 30-call-site sweep does not collide.
- `crates/rvc/src/orchestrator/coordinator.rs:706` — `process_slot` (read-only; delegates to
  `attestation_service.process_slot`)
- `crates/signer/src/lib.rs` (~`:2760-2795`) — harden the corrupted-DB assertion
- Reference: existing coordinator fixtures around `coordinator.rs:1198-1260` for how mock beacon /
  composite signer / `SignerService::new(..).with_enablement(always_enabled())` are assembled

**Implementation sketch:**
1. Build `fn pipeline_fixture(...)` in the new file: slot clock, duty tracker, mock beacon returning
   attestation duties for a known pubkey, propagator, `SignerService` over a shared `SlashingDb`,
   `DutyOrchestrator`. Expose knobs for (a) the `AttestationData` the mock beacon returns per slot and
   (b) the enablement, so RF1-08 can reuse it for the doppelganger gate test.
2. Test 1: process slot N (attestation accepted, row committed), then process a second slot whose
   `AttestationData` conflicts (same target epoch, different source/root). Assert the second produces no
   signature and the slashing DB still holds exactly one attestation row.
3. Test 2: same fixture with a `SlashingDb` that errors on query; assert the orchestrator surfaces the
   error and emits no signature.
4. Harden the signer-level corrupted-DB test: assert in **both** branches — if `SlashingDb::open` errors,
   assert that explicitly; if it opens, assert the sign attempt errors. No vacuous pass.

**Acceptance criteria:**
- [x] Two `process_slot` calls with conflicting `AttestationData`: the first signs, the second is
      rejected by slashing protection; assertion is on the *absence of a signature*, not just on a log.
- [x] After the rejection the slashing DB contains exactly one attestation row for the pubkey.
- [x] A slashing-DB error during `process_slot` propagates fail-closed (no signature emitted).
- [x] The corrupted-DB test in `crates/signer/src/lib.rs` asserts unconditionally in both branches.
- [x] The fixture is a reusable module-level helper, not inline in one test fn (RF1-08 contract).
- [x] Additive only: no production code changes in this issue.
- [x] Standing invariant green.

**TDD test plan** (new, in `crates/rvc/tests/pipeline_slashing.rs`):
1. **RED first:** `test_pipeline_rejects_double_vote_across_two_process_slot_calls` — written before the
   fixture is generalized; it fails initially because no fixture exists that can vary attestation data
   across slots.
2. `test_pipeline_double_vote_leaves_single_db_row`
3. `test_pipeline_slashing_db_error_is_fail_closed`
4. `test_corrupted_slashing_db_refuses_to_sign` (hardened in place in `crates/signer/src/lib.rs`)

**Dependencies / coordination:** none inbound. Outbound: RF1-08 consumes the fixture — agree its
signature at kickoff. RF1-07 will later update the `DutyOrchestrator` construction inside this fixture
(one call site); that sweep is RF1-07's responsibility.

**Risks:** the mock beacon may not currently support returning different `AttestationData` for the same
validator across slots; extending it is the likely time sink and is budgeted here. If the mock turns out
to be a bigger lift than the tests themselves, split the mock extension into its own issue rather than
letting this exceed 3.

---

### Issue RF1-03: Retarget the conformance `complete` runner at `stage_* → commit/discard`

- **Points:** 3
- **Days:** ~1.5–2
- **Type:** test
- **Priority:** P0
- **Source plan item:** A2
- **Findings:** F50
- **Blocked by:** RF1-01
- **Blocks:** RF1-04, RF1-05
- **Stream:** A

**What / why:**
The official EIP-3076 conformance suite is the project's master oracle for every later slashing change —
and it currently certifies `check_and_record_*`, an API with **zero production callers**. This is exactly
why the watermark regression in RF1-01 went unnoticed. Retargeting the `complete` runner at
`stage_* → commit()/discard()` moves the certification onto the code that actually ships.

**Files:**
- `crates/slashing/tests/conformance.rs:69-165` — `run_complete`; the two call sites to swap are
  `db.check_and_record_block(…)` at `:104` and `db.check_and_record_attestation(…)` at `:134`
- Reference: `crates/slashing/src/stage.rs:315` (`stage_block`), `:452` (`stage_attestation`),
  `:161` (`StagedBlock::commit`), `:188` (`discard`), `:235`/`:260` (attestation equivalents)

**Implementation sketch:**
1. Add two small harness helpers, `stage_and_commit_block(&db, …) -> Result<(), SlashingError>` and the
   attestation equivalent, so the assertion bodies stay unchanged and the diff is legible. Signature
   delta to absorb: `stage_*` drops the leading `_client_cn` argument and takes `gvr: &Root`.
2. Point `run_complete` at the helpers.
3. **Triage every failure individually.** Both paths implement the same rule set over the same tables and
   share `strict_semantics` (assumption **P3**), so a divergence means a real behavioral difference
   between the two implementations. For each: record the case name, both verdicts, and which path EIP-3076
   supports. A stage-path bug is fixed here (that is the point of the issue); a `db.rs`-path bug is
   recorded and handed to Phase 4's E1 rule-core extraction, since `db.rs` is not the production path.
4. Keep exactly one thin `check_and_record_*` smoke test alive so Phase 2's B4 (which decides that API's
   fate) has an explicit thing to delete or repoint rather than discovering silent coverage loss.

**Acceptance criteria:**
- [ ] `run_complete` drives `stage_* → commit()` on success paths and `discard()` (or guard drop) on
      rejection paths; no `check_and_record_*` call remains in `run_complete`.
- [ ] All 38 conformance cases pass on the stage path under the `complete` runner. *(The plan's
      "76 conformance cases" refers to 38 cases × 2 runners; the file today generates 38 × 3 = 114 test
      functions. RF1-04 retires the redundant runner, landing the phase at 38 × 2 = 76.)*
- [ ] Every divergence found during retargeting is written into the PR description with its EIP-3076
      adjudication; none is silently absorbed by loosening an assertion.
- [ ] One thin `check_and_record_*` smoke test remains, annotated with a pointer to Phase 2 B4.
- [ ] Standing invariant green.

**TDD test plan:** this issue *is* test work, so RED is the retarget itself.
1. **RED first:** flip one representative case — `single_validator_slashable_attestations_double_vote` —
   to the stage helpers and confirm it passes before converting the rest. If it fails, that is the first
   triage item and it is diagnosed before any further conversion.
2. Convert the remaining 37 cases; run the full suite.
3. Confirm rejection paths commit no row (`discard`/drop semantics) — the equivalent of `check_and_record`'s
   rollback.
4. Re-run `crates/slashing` + `crates/signer` suites.

**Dependencies:** RF1-01 must land first — the `real_watermarks` runner already encodes `<=` semantics
(`conformance.rs:321`,`:345`), so retargeting onto an unfixed stage path would produce watermark failures
that are RF1-01's bug, not conformance signal.

**Risks:** triage depth is the unknown. Two or three divergences are the expected case and are inside the
3 points; a systemic divergence (many cases, one root cause) is the escalation trigger — flag it rather
than absorbing it, because it would mean the two rule implementations differ structurally, which is
Phase 4 E1 information.

---

### Issue RF1-04: Move the conformance watermark decision into production code; retire the duplicate runner

- **Points:** 2
- **Days:** ~1
- **Type:** test
- **Priority:** P1
- **Source plan item:** A2
- **Findings:** F126, F50
- **Blocked by:** RF1-03
- **Blocks:** none
- **Stream:** A

**What / why:**
Two of the three conformance runners re-implement watermark logic in the test. `run_minimal_conservative`
(`conformance.rs:167-264`) tracks watermarks in test-local `HashMap`s. `run_with_real_watermarks`
(`:270-368`) improved on that by using the real `set_/get_*_watermark` storage API — but it still decides
the outcome in the test (`slot > wm` at `:321`, `source >= wm_source && target > wm_target` at `:345`).
So the *decision* the suite certifies is still the test's opinion, not production's. Once the decision
comes from `stage_*`, the two runners collapse into near-duplicates and one must go, or the suite ends up
worse organized than it started.

**Target end state (decide once, here):**
- `complete` — full-history strategy on `stage_* → commit/discard` (delivered by RF1-03).
- `minimal_conservative` — watermark strategy: interchange maxima are projected onto watermarks via the
  real `set_block_watermark` / `set_attestation_watermark` API, and every verdict comes from `stage_*`.
- `real_watermarks` — **deleted**, now redundant with `minimal_conservative`.
- Result: 38 cases × 2 runners = 76 conformance test functions.

**Scope fence:** the interchange → watermark *projection* stays in the test harness in this phase. Moving
it into production import code is Phase 2's **B5** ("Interchange import sets watermarks from interchange
maxima"). Only the *decision* moves to production code here. Do not pull B5 forward.

**Files:**
- `crates/slashing/tests/conformance.rs:167-264` (`run_minimal_conservative`), `:270-368`
  (`run_with_real_watermarks`), `:374-398` (the `conformance_test!` macro — drop the third generated fn)
- Reference: `crates/slashing/src/db.rs:1832` (`set_block_watermark`), `:1882`
  (`set_attestation_watermark`)

**Implementation sketch:**
1. Rewrite `run_minimal_conservative` to: project interchange maxima onto watermarks with the real setters
   (lift the projection from `run_with_real_watermarks:286-314`), then take every block/attestation verdict
   from `stage_* → commit/discard` — deleting the `HashMap`s and the inline comparisons.
2. Delete `run_with_real_watermarks` and its generated `real_watermarks` test fn.
3. Confirm the surviving runner still distinguishes the minimal strategy from the complete strategy on the
   cases that differ between them (the `*_iff_minified` / `*_fail_iff_imported` cases are the ones that
   prove the two strategies are not the same test twice).
4. Record in the file's module doc which runner certifies which EIP-3076 strategy, and note the B5 handoff
   for the projection.

**Acceptance criteria:**
- [ ] No test-local `HashMap` watermark tracking and no test-local watermark comparison remains in
      `conformance.rs`.
- [ ] Every conformance verdict — both runners — comes from the production `stage_*` path.
- [ ] `real_watermarks` is deleted; the suite generates 38 × 2 = 76 test functions, all green.
- [ ] The minimal and complete runners still diverge on the cases that are strategy-sensitive (proving the
      collapse did not turn one runner into a copy of the other).
- [ ] A module-doc comment records the runner→strategy mapping and the B5 handoff for the projection.
- [ ] Standing invariant green.

**TDD test plan:**
1. **RED first:** `single_validator_source_greater_than_target_sensible_iff_minified::minimal_conservative`
   — convert this case first; it is strategy-sensitive, so it fails loudly if the rewrite accidentally
   makes the minimal runner behave like the complete runner.
2. Convert the remaining cases; full suite green.
3. Deliberate-regression check: temporarily revert `stage.rs:356` to `<` and confirm the minimal runner now
   fails — proof that the suite exercises the production watermark decision. Revert the revert; do not commit it.
4. Delete `run_with_real_watermarks`; confirm the test count drops by exactly 38.

**Risks:** low. The main trap is the collapse producing two runners that test the same thing — acceptance
criterion 4 and the RED case are specifically aimed at that.

---

### Issue RF1-05: Retarget the slashing property tests at the stage path

- **Points:** 2
- **Days:** ~1
- **Type:** test
- **Priority:** P1
- **Source plan item:** A2
- **Findings:** F50
- **Blocked by:** RF1-03 (reuses its stage helpers)
- **Blocks:** none
- **Stream:** A

**What / why:**
`crates/slashing/tests/proptest_slashing.rs` runs 256 cases per property against `check_and_record_*` —
the same non-production path as the conformance suite. The invariants it checks (no double proposals, no
double votes, no surround votes) are exactly the invariants a Phase 4 rule-core extraction could break, so
they need to hold on the shipping path.

**Files:**
- `crates/slashing/tests/proptest_slashing.rs:49` (`proptest_no_double_proposals`), `:78`
  (`proptest_no_double_votes`), `:110` (`proptest_no_surround_votes`), and the remaining properties
  through `:315`
- Reuses the stage helpers introduced by RF1-03 (promote them to a shared test-support module if that
  reads better than duplicating; a small `tests/common/` module is acceptable)

**Implementation sketch:**
1. Swap each `db.check_and_record_*` call for the stage helper (`stage_* → commit()` on the accept path).
2. Keep the post-hoc invariant queries (`db.get_attestations(&pk)`) unchanged — they read committed state
   and are path-agnostic, which is what makes them good invariants.
3. Keep `PROPTEST_CASES = 256`; if the stage path's `BEGIN IMMEDIATE` + guard makes the suite materially
   slower, report the wall-clock delta in the PR rather than silently reducing the case count.
4. Add one property that the current suite lacks and that the phase's headline fix motivates: a watermark
   monotonicity property.

**Acceptance criteria:**
- [ ] All existing properties drive `stage_* → commit/discard`; no `check_and_record_*` call remains in
      the file.
- [ ] Existing invariants still hold at 256 cases per property.
- [ ] New property: for any watermark W and candidate slot/target T, `stage_*` accepts **iff** `T > W`
      (block slot and attestation target), pinning RF1-01's semantics under random input.
- [ ] Suite runtime reported in the PR; no silent case-count reduction.
- [ ] Standing invariant green.

**TDD test plan:**
1. **RED first:** `proptest_watermark_blocks_at_or_below` — the new property, written against the stage
   path. On an unfixed `stage.rs` it fails at `T == W`; after RF1-01 it passes. (If RF1-01 is already
   merged, assert the RED by locally reverting the `<=`, exactly as in RF1-04.)
2. Convert `proptest_no_double_proposals`, then `proptest_no_double_votes`, then
   `proptest_no_surround_votes`, then the remainder — one at a time, running between each.
3. Full slashing suite green.

**Risks:** the staged guard holds the connection mutex for its lifetime; a property that stages twice
without committing or dropping the first guard will deadlock rather than fail. Structure each property to
resolve one guard before opening the next, and note it in a comment — a deadlocked proptest is a confusing
CI hang for whoever hits it next.

---

### Issue RF1-06: Adapters require `PubkeyMap` + `key_gen_tx` at construction

- **Points:** 3
- **Days:** ~1.5–2
- **Type:** refactor
- **Priority:** P0
- **Source plan item:** A4
- **Findings:** F1
- **Blocked by:** none
- **Blocks:** RF1-07
- **Stream:** B

**What / why:**
`KeystoreManagerAdapter` and `RemoteKeyManagerAdapter` update the shared `PubkeyMap` and fire
`key_gen_tx` only when `with_pubkey_map(…)` was called — and it is called nowhere outside the defining
file. `bin/rvc/src/main.rs:1626` builds the adapter with `new(..).with_denylist(..)` only. The consequence
is a silent production defect: a key imported through the Keymanager API is added to `CompositeSigner`
but never to the orchestrator's `pubkey_map`, so duty matching for that key only starts working after a
restart. Making the pair a required constructor parameter converts a silent misconfiguration into a
compile error.

**Files (verified at HEAD):**
- `crates/rvc/src/keymanager_adapters.rs`
  - `KeystoreManagerAdapter` fields `:55-56`, `new` `:60-71`, `with_pubkey_map` `:73-81` (delete),
    `notify_key_change` `:89-93`, import-path use `:400`, delete-path use `:485`
  - `RemoteKeyManagerAdapter` fields `:759-760`, `new` (through `:773`), `with_pubkey_map` `:775-783`
    (delete), its `notify_key_change`
- `bin/rvc/src/main.rs:1626` (`KeystoreManagerAdapter::new(..).with_denylist(..)`) and the
  `RemoteKeyManagerAdapter::new(..)` at `:1681`
- ~51 `KeystoreManagerAdapter::new` / `RemoteKeyManagerAdapter::new` call sites workspace-wide, the large
  majority in `keymanager_adapters.rs`'s own test module (`:1076`+)

**Implementation sketch:**
1. Change both `new` signatures to take `pubkey_map: PubkeyMap` and `key_gen_tx: watch::Sender<u64>`;
   change the fields from `Option<…>` to the concrete types; delete both `with_pubkey_map` methods.
2. Simplify `notify_key_change` and the two `if let Some(ref map) = self.pubkey_map` blocks (`:400`,
   `:485`) to unconditional operations — this is where the dormant behavior wakes up.
3. Fix `main.rs`: construct the `watch::channel` **once** in startup, pass the sender to both adapters and
   the receiver onward (RF1-07 consumes it; until then `main.rs` may hold it). Note that `main.rs:1280`
   already builds `pubkey_map` and `main.rs:1746` already passes it to the orchestrator, so the map is in
   scope at both points.
4. Sweep the test call sites with a shared test helper (`fn test_adapter(dir, signer) -> (Adapter,
   watch::Receiver<u64>)`) so ~50 sites become a one-line change each rather than five.
5. Keep `with_denylist` as-is — the denylist is genuinely optional (SEC-1b, `None` disables persistence
   for tests); only the pubkey_map/key_gen pair becomes required.

**Acceptance criteria:**
- [x] `with_pubkey_map` does not exist on either adapter; `pubkey_map` and `key_gen_tx` are non-`Option`
      fields set at construction.
- [x] `main.rs` constructs both adapters with the real `pubkey_map` and a real `key_gen_tx` sourced from a
      single startup channel.
- [x] Importing a key through the adapter updates the shared `PubkeyMap` and increments the watch value —
      asserted by a unit test, unconditionally (no `if let Some`).
- [x] Deleting a key through the adapter removes it from the shared `PubkeyMap` and increments the watch value.
- [x] SEC-1a/SEC-1b behavior is unchanged: `local_public_keys`-based list/has/delete and the deletion
      denylist still pass their existing tests.
- [x] Standing invariant green.

**TDD test plan** (in `crates/rvc/src/keymanager_adapters.rs`'s `#[cfg(test)]` module):
1. **RED first:** `test_import_updates_shared_pubkey_map_and_notifies` — construct the adapter with a real
   map + channel, import, assert the map contains the pubkey **and** `rx.has_changed()` is true. Written
   against the new required-parameter signature, so it does not compile before the change — the intended
   RED.
2. `test_delete_removes_from_shared_pubkey_map_and_notifies`
3. `test_remote_adapter_import_notifies_key_change`
4. Existing tests (`test_concurrent_delete_same_key` `:1924`, `test_concurrent_import_same_key` `:1981`,
   the SEC-1a/1b suites) all still pass.

**Dependencies / coordination:** touches `bin/rvc/src/main.rs`, which is also a hotspot for Phase 5's
composition-root work — land Phase 1's edits first. No overlap with Stream A's files.

**Risks:** the ~50 test call sites are mechanical but tedious; the shared test helper is what keeps this at
3 points rather than 5. If the helper cannot be made to fit some call sites (e.g. tests that deliberately
construct an adapter without a notifier), convert those to an explicitly-named `no_notify` helper rather
than reintroducing the `Option`.

---

### Issue RF1-07: Collapse the three `DutyOrchestrator` constructors into one `OrchestratorDeps` ctor

- **Points:** 3
- **Days:** ~1.5–2
- **Type:** refactor
- **Priority:** P0
- **Source plan item:** A4
- **Findings:** F1
- **Blocked by:** RF1-06
- **Blocks:** RF1-08
- **Stream:** B

**What / why:**
`DutyOrchestrator::new` (`coordinator.rs:150`) and `new_with_attesting_enabled` (`:186`) each fabricate a
watch channel and immediately drop the sender — `let (_key_gen_tx, key_gen_rx) = watch::channel(0u64)` —
so `key_gen_rx.has_changed()` at `:322` is permanently false and the "Key set changed, clearing duty
cache" path is unreachable. `new_with_key_gen` (`:203`), the only constructor that accepts a real
receiver, has zero production callers. Three stacked constructors of 10–13 arguments each, all carrying
`#[allow(clippy::too_many_arguments)]`, are what made it possible to add a fourth-from-last parameter and
never notice it was inert. One constructor taking a deps struct makes the omission impossible.

**Files:**
- `crates/rvc/src/orchestrator/coordinator.rs` — `new` `:~139-167`, `new_with_attesting_enabled`
  `:~169-199`, `new_with_key_gen` `:203`, the `key_gen_rx.has_changed()` consumer `:322`, plus ~28 test
  call sites in the `#[cfg(test)]` module from `:1208` onward
- `bin/rvc/src/main.rs:1736` — the production `new_with_attesting_enabled` call
- `crates/rvc/src/config/builder.rs:802` — a `DutyOrchestrator::new` call
- `crates/rvc/tests/sync_independent_of_attesting.rs:370` — a `new_with_attesting_enabled` call
- `crates/rvc/tests/pipeline_slashing.rs` — RF1-02's fixture (one call site; sweep it here)

**Implementation sketch:**
1. Define `pub struct OrchestratorDeps<C, S, B> { clock, duty_tracker, signer, propagator, beacon,
   block_beacon, builder_service, validator_store, config, pubkey_map, key_gen_rx, circuit_breaker,
   attesting_enabled }` next to the orchestrator, with doc comments on the two fields whose omission was
   previously silent (`key_gen_rx`, `attesting_enabled`).
2. Replace all three constructors with one `pub fn new(deps: OrchestratorDeps<…>) -> (Self,
   OrchestratorHandle)`. Remove every `#[allow(clippy::too_many_arguments)]` on them in the same PR (the
   plan calls this out explicitly).
3. Add a `Default`-ish test builder — `OrchestratorDeps::for_test(...)` with sensible defaults — so the
   ~28 test sites become short struct-literal updates instead of 13-argument reshuffles.
4. Update `main.rs:1736` to pass the **real** receiver from the channel RF1-06 created, closing the loop:
   adapter fires `key_gen_tx` → orchestrator sees `has_changed()` → duty cache cleared.
5. Leave `key_gen_rx.has_changed()` logic at `:322` untouched; it becomes reachable rather than rewritten.

**Acceptance criteria:**
- [ ] Exactly one `DutyOrchestrator` constructor exists; `new_with_attesting_enabled` and
      `new_with_key_gen` are gone.
- [ ] No `watch::channel` is fabricated inside any constructor; the receiver always comes from the caller.
- [ ] No `#[allow(clippy::too_many_arguments)]` remains on orchestrator construction.
- [ ] `main.rs` passes the receiver paired with the sender RF1-06 gave the adapters (same channel).
- [ ] All ~30 call sites compile and pass; the call-site inventory is listed in the PR description.
- [ ] `crates/architecture-tests` green (constructor churn must not alter crate edges).
- [ ] Standing invariant green.

**TDD test plan:**
1. **RED first:** `test_key_gen_notification_clears_duty_cache` — build the orchestrator with a real
   receiver, send on the paired sender, drive one iteration, assert the duty cache was cleared. Fails
   today because production constructors drop the sender.
2. `test_orchestrator_deps_requires_key_gen_receiver` — compile-level: there is no constructor path that
   omits it (assert by construction/API shape, documented in the test).
3. All existing coordinator tests pass unchanged in behavior after the mechanical call-site sweep.

**Dependencies / coordination:** RF1-06 must land first (the sender must exist before the receiver can be
paired). This PR is a large mechanical diff in `coordinator.rs` — no other Phase 1 issue may edit that
file concurrently, which is why RF1-02's test lives in `crates/rvc/tests/`. Sweep RF1-02's fixture call
site as part of this PR.

**Risks:** merge-conflict blast radius. Land it as a single PR, promptly, and rebase rather than
long-lived-branch it. The generic parameters `<C, S, B>` on the deps struct are the fiddly part; if the
generics fight back, an alternative is a non-generic deps struct holding trait objects — but only if it
does not change the orchestrator's existing monomorphization, which is a behavior-adjacent decision worth
a note in the PR.

---

### Issue RF1-08: Key-import → duty-cache integration test + doppelganger gate test

- **Points:** 2
- **Days:** ~1
- **Type:** test
- **Priority:** P0
- **Source plan item:** A4 (test half)
- **Findings:** F1
- **Blocked by:** RF1-07, RF1-02 (fixture)
- **Blocks:** none
- **Stream:** B
- **Cross-plan coordination:** SEC-2 (already landed — see below)

**What / why:**
RF1-06 and RF1-07 make the import→orchestrator path *possible*; this issue proves it *works*, end to end,
and adds the interim safety net the plan asks for. Per the plan's A4 row: A4 lands four phases before the
`DoppelgangerLifecycle` consolidation (F5/E8c in Phase 4), so the gate test is what guards the newly-live
import path in the meantime — a newly imported key must produce **no attestations** until its doppelganger
window / enablement gate clears.

The SEC-2 machinery this test exercises is already in production (assumption **P4**): commits `dee059b`
and `16ba7fb` construct `ForwardWindowMachine` at `bin/rvc/src/main.rs:1401`, wire it as the
`SignerService` enablement, and drive it from `crates/rvc/src/liveness_loop.rs`. `main.rs:1647-1665`
already registers keymanager imports with the machine via `ForwardWindowMonitor`. So this issue writes
tests against existing behavior — it does not build enablement.

**Files:**
- `crates/rvc/tests/pipeline_slashing.rs` (RF1-02's fixture) or a sibling
  `crates/rvc/tests/key_import_pipeline.rs` — prefer a sibling file importing the shared fixture, so the
  slashing and key-import concerns stay separable
- Reference: `crates/rvc/src/keymanager_adapters.rs` (import path, `notify_key_change`),
  `crates/rvc/src/orchestrator/coordinator.rs:322` (cache-clear consumer),
  `crates/doppelganger/src/forward_window.rs` (`ForwardWindowMachine`),
  `crates/rvc/src/liveness_loop.rs:909-910` (the enablement→`SignerService` wiring pattern to mirror)

**Implementation sketch:**
1. Build on RF1-02's fixture with an added `KeystoreManagerAdapter` sharing the same `PubkeyMap` and
   `key_gen_tx` as the orchestrator's receiver.
2. Test A: import a keystore via the adapter; drive one orchestrator iteration; assert the duty cache was
   cleared and the new pubkey participates in duty matching without a restart.
3. Test B (the gate test): construct the fixture with a `ForwardWindowMachine` enablement, import a key,
   register it with the machine as a new import, and assert that across the window the orchestrator emits
   **zero** attestation signatures for that pubkey; then advance past the window and assert it signs.
4. Assert on the absence of a *signature*, not on log output or an internal flag — the failure mode this
   guards is a real double-sign.

**Acceptance criteria:**
- [ ] Importing a key via the keymanager adapter clears the orchestrator duty cache (`key_gen_rx` fires) —
      asserted end-to-end, no restart.
- [ ] A newly imported key produces no attestation signatures until its doppelganger window / enablement
      gate clears; after it clears, it signs.
- [ ] The gate assertion is on emitted signatures, not on logs or internal state flags.
- [ ] Test lives in `crates/rvc/tests/`, reusing RF1-02's fixture rather than duplicating it.
- [ ] Standing invariant green.

**TDD test plan:**
1. **RED first:** `test_imported_key_clears_duty_cache_without_restart` — on pre-RF1-06/07 code this fails
   (the notification never fires); it is the acceptance proof for the whole A4 chain.
2. `test_imported_key_produces_no_attestations_during_doppelganger_window`
3. `test_imported_key_signs_after_doppelganger_window_clears`

**Dependencies / coordination:** RF1-07 (real receiver wired) and RF1-02 (fixture) — the latter is the
phase's only cross-stream dependency. If RF1-02 slips, this issue can start against a locally-stubbed
fixture and rebase, but that duplicates work; prefer holding.

**Risks:** driving a time-based window deterministically in a test. Use the injectable epoch clock the
machine already takes (`MonotonicEpochClock` / the `epoch_provider` closure pattern at `main.rs:1650-1653`)
rather than sleeping — a wall-clock-dependent test here would be flaky in CI and worse than no test.

---

### Issue RF1-09: Record gRPC sign metrics via one shared helper in all 10 v2 handlers

- **Points:** 2
- **Days:** ~1
- **Type:** bugfix
- **Priority:** P1
- **Source plan item:** A7
- **Findings:** F29
- **Blocked by:** none
- **Blocks:** none (but Phase 4 **D4** absorbs the helper)
- **Stream:** B

**What / why:**
`SignerMetrics.sign_total`, `sign_duration_seconds` and `sign_errors_total` (`metrics.rs:20-22`, created
and registered at `:46-75`) are never incremented in production — the v2 handler migration dropped all
per-RPC recording on the gRPC path. `SignerServiceImpl.metrics` (`service.rs:123`) is written by
`with_metrics` (`:210`) and never read; `classify_error` (`metrics.rs:193`) is referenced only by its own
unit tests. Operators scraping `:9101` see permanently-zero gRPC series next to live HTTP series. The
plan chose *record*, not delete.

**Files:**
- `bin/rvc-signer/src/metrics.rs` — collectors `:20-22`, construction/labels `:46-75`, `classify_error`
  `:193`; add the shared recording helper here (free-standing `pub fn`, **not** a method on
  `SignerServiceImpl`)
- `bin/rvc-signer/src/service.rs` — `metrics` field `:123`, `with_metrics` `:210`, and the 10 v2 sign
  handlers: `sign_beacon_block` `:490`, `sign_blinded_beacon_block` `:542`, `sign_randao_reveal` `:589`,
  `sign_attestation_data` `:636`, `sign_aggregate_and_proof` `:732`, `sign_sync_committee_message` `:799`,
  `sign_sync_aggregator_selection_data` `:860`, `sign_contribution_and_proof` `:918`,
  `sign_builder_registration` `:982`, `sign_voluntary_exit` `:1053`
- Precedent to mirror: `bin/rvc-signer/src/http_api/routes.rs:163-177` (the HTTP type×outcome recording),
  and the scrape test at `:1276-1293`

**Label decision (record it in the PR):** the existing gRPC collectors are `sign_total{backend,result}`,
`sign_duration_seconds{backend}`, `sign_errors_total{backend,error_type}` — not the type×outcome shape the
plan's acceptance line describes. Recommendation: extend to `sign_total{backend,type,result}` and
`sign_duration_seconds{backend,type}`, keeping `sign_errors_total{backend,error_type}` fed by
`classify_error`. This satisfies "type × outcome" while preserving the backend dimension. Because these
series have **never been emitted**, no operator dashboard can depend on them, so the arity change is safe —
but it does break the existing scrape test at `http_api/routes.rs:1286`, which must be updated in the
same PR. Keep the `type` label values a bounded, code-derived set (never request-derived), matching the
low-cardinality reasoning already documented at `http_api/routes.rs:165-167`.

**Implementation sketch:**
1. Add `pub fn record_sign(metrics: Option<&SignerMetrics>, backend: &str, rpc_type: &str, started:
   Instant, outcome: Result<&T, &SigningBackendError>)` (or an equivalent shape) in `metrics.rs` —
   free-standing, no-ops when `metrics` is `None`, and routes errors through `classify_error` into
   `sign_errors_total`.
2. Call it from all 10 v2 handlers on both the success and error paths. If the handlers share a common
   helper (`sign_via_backend` at `service.rs:302`), prefer recording there once — but only if every one of
   the 10 routes through it; otherwise call the helper per handler and note why.
3. Update the label arity and the scrape test.
4. Leave `with_metrics` in place — the field stops being dead once the helper reads it.

**Acceptance criteria:**
- [x] All 10 v2 sign handlers record `sign_total`, `sign_duration_seconds`, and (on error)
      `sign_errors_total` through **one shared free-standing helper** — no per-handler inline recording.
- [x] The helper is not a method on `SignerServiceImpl`, so Phase 4's D4 `SignPlan` dispatcher can absorb
      it unchanged.
- [x] The helper no-ops safely when `metrics` is `None`.
- [x] `classify_error` is wired into `sign_errors_total` and is no longer test-only.
- [x] A scrape test asserts non-zero `rvc_signer_sign_total` after a successful gRPC sign, and a non-zero
      `rvc_signer_sign_errors_total` after a failing one.
- [x] `type` label values come from a bounded code-derived set.
- [x] Standing invariant green.

**TDD test plan** (in `bin/rvc-signer/src/service.rs` tests + the metrics scrape test):
1. **RED first:** `test_v2_sign_beacon_block_records_sign_total` — sign through the v2 handler with metrics
   attached, assert `sign_total{…,"success"}` is 1. Fails today (permanently zero).
2. `test_v2_sign_unknown_key_records_sign_error` — asserts `sign_errors_total{…,"key_not_found"}` via
   `classify_error`.
3. `test_sign_recording_helper_no_ops_without_metrics` — helper called with `None` does not panic.
4. `test_all_v2_handlers_record_sign_total` — table-driven across all 10 RPCs, so a future handler added
   without recording fails the test.
5. Existing scrape test (`http_api/routes.rs:1276`) updated for the new arity and still green.

**Risks:** the label-arity change breaks the existing scrape test — expected and handled above. The
table-driven test (item 4) is what makes D4's later rewrite safe, so do not drop it for brevity.

---

### Issue RF1-10: Remove `--password-dir`; make a missing password source a startup error

- **Points:** 2
- **Days:** ~1
- **Type:** bugfix
- **Priority:** P1
- **Source plan item:** A6
- **Findings:** F30
- **Blocked by:** none
- **Blocks:** none
- **Stream:** B

**What / why:**
`--password-dir` is documented as "Path to the directory containing per-keystore password files"
(`main.rs:81-83`) and is plumbed through `SignerSection` → `CliOverrides` → `ResolvedConfig`, but its only
consumer does `std::fs::read_to_string(dir)` on the directory path (`main.rs:1034`), which fails with
EISDIR on Unix. No per-keystore-password logic exists anywhere — `BasicSigner::load` takes one password for
all keystores. Separately, when neither source is set, `load_serve_password` silently returns an empty
password (`main.rs:1042-1043`) despite a comment promising a prompt, so a misconfigured deployment starts
and then fails later with confusing per-keystore decrypt errors.

**Decision: delete the flag.** The discriminating fact is that no correctly-used deployment can depend on
it — passing a directory has always failed. Per-keystore passwords are a feature request, not refactoring
debt, and implementing them would mean changing `BasicSigner::load`'s contract, which is out of Theme A's
scope.

**Files:**
- `bin/rvc-signer/src/main.rs` — CLI arg `:81-83` (including the `group = "password_source"` clap group,
  which becomes single-membered and should be simplified), `CliOverrides` construction `:1002`,
  `load_serve_password` `:1031-1044`
- `bin/rvc-signer/src/config.rs` — `SignerSection.password_dir` `:58`, `ResolvedConfig` `:109`,
  `CliOverrides` `:137`, merge logic `:192`, struct literal `:266`, default `:305`, and the two tests
  `test_merge_password_dir_from_config` `:587` and `test_merge_cli_password_dir_overrides_config` `:602`
  (delete both — they test plumbing for a removed field)
- `bin/rvc-signer/src/integration_polish.rs:64`
- Docs mentioning the flag (`docs/running-guide.md` and any rvc-signer config sample) — grep and update
- Release notes under `docs/releases/`

**Implementation sketch:**
1. Delete the CLI arg, the config field, and every plumbing site; simplify the clap `password_source`
   group now that only `--password-file` remains.
2. Replace the empty-password fallback with an explicit startup error naming `--password-file` /
   `signer.password_file` as the fix. Route it through the binary's existing error type so the exit code
   and message format match other startup failures.
3. Delete the two now-meaningless config merge tests; add the startup-error test.
4. Release note: `--password-dir` removed (it never worked); an operator who happened to pass a *file*
   path to `--password-dir` was working by accident and must switch to `--password-file`. Also note that
   a missing password source is now a startup failure rather than a silent empty password.

**Acceptance criteria:**
- [x] No occurrence of `password_dir` / `--password-dir` remains in `bin/rvc-signer`, its config parsing,
      its tests, or the docs.
- [x] Starting with a keystore dir and no password source fails at startup with an actionable message
      naming `--password-file`; it does not proceed with an empty password.
- [x] `--password-file` behavior (including the trailing-newline trim at `main.rs:1039`) is unchanged.
- [x] Config files that still contain `signer.password_dir` are handled per the crate's existing
      unknown-field policy; whichever way that falls (ignore vs error), it is asserted by a test and stated
      in the release note.
- [x] Release note drafted covering both the removal and the new startup error.
- [x] Standing invariant green.

**TDD test plan** (in `bin/rvc-signer/src/config.rs` tests + a startup test):
1. **RED first:** `test_missing_password_source_is_startup_error` — resolve a config with a keystore dir
   and no password source, assert an error. Fails today (returns `Ok("")`).
2. `test_password_file_still_resolves` — regression guard on the surviving path.
3. `test_config_with_legacy_password_dir_key` — pins the decided behavior for old config files.
4. Deleted: `test_merge_password_dir_from_config`, `test_merge_cli_password_dir_overrides_config`. The
   test-count drop is explained in the PR (per the plan's deletion-hygiene convention).

**Risks:** deployment-visible. Mitigated by the release note and by the fact that the removed path could
never have worked as documented.

---

### Issue RF1-11: Delete the unsafe pointer downcast in the builder test

- **Points:** 1
- **Days:** ~0.5
- **Type:** bugfix
- **Priority:** P2
- **Source plan item:** A5
- **Findings:** F100
- **Blocked by:** none
- **Blocks:** RF1-12
- **Stream:** B

**What / why:**
`test_register_validators_no_builder_enabled` (`crates/builder/src/service.rs:660-672`) reaches its mock
through `let bn = service.bn.as_ref() as *const dyn BeaconNodeClient as *const MockBn; let calls = unsafe
{ &*bn }.register_calls.lock();`. That is undefined behavior the moment the field stops holding a
`MockBn` — and it is gratuitous: every other test in the same file keeps an `Arc<MockBn>` clone before
constructing the service (e.g. `:693-705`) and asserts through it.

**Files:**
- `crates/builder/src/service.rs:660-672` (the test), with `:693-705` as the in-file pattern to copy

**Implementation sketch:**
1. Hold `let bn = Arc::new(MockBn::new());` and pass `bn.clone()` into the service constructor
   (`build_service`), matching the surrounding tests.
2. Assert through the retained `Arc`; delete the `unsafe` block and the raw-pointer casts.
3. If `build_service` does not currently accept an `Arc`, add the small variant the neighboring tests
   already imply rather than reshaping the helper for everyone.

**Acceptance criteria:**
- [x] No `unsafe` remains anywhere in `crates/builder`.
- [x] The test still asserts that no registration call was made when no validator has the builder enabled
      (same assertion, sound access path).
- [x] The test matches the `Arc<MockBn>`-clone idiom used by its neighbors.
- [x] Standing invariant green.

**TDD test plan:** this is a test rewrite, so the RED is a mutation check rather than a new failing test.
1. **RED first:** `test_register_validators_no_builder_enabled` — after the rewrite, temporarily make
   `register_validators` call `register` unconditionally and confirm the test **fails**. This proves the
   new access path actually observes the mock (the old unsafe read did; a botched rewrite might assert on a
   fresh, always-empty mock and pass vacuously). Revert the mutation; do not commit it.
2. Full `crates/builder` suite green.

**Risks:** none of substance. The only trap is the vacuous-pass failure mode that step 1 exists to catch.

---

### Issue RF1-12: Workspace `unsafe_code` lint with an explicit allow-list

- **Points:** 1
- **Days:** ~0.5
- **Type:** chore
- **Priority:** P2
- **Source plan item:** A5 ("consider `unsafe_code = "deny"` workspace lint")
- **Findings:** F100
- **Blocked by:** RF1-11
- **Blocks:** none
- **Stream:** B

**What / why:**
Nothing structurally prevents the next `unsafe` block from landing where RF1-11's was. The workspace has
no `[workspace.lints]` table at all and no member crate declares `[lints]`, so this installs the guard
rather than tightening one. Split from RF1-11 because it touches 25 `Cargo.toml` files while RF1-11
touches one `.rs` file — different review shapes, and the split keeps both inside the point cap.

**Files:**
- `Cargo.toml` — add `[workspace.lints.rust] unsafe_code = "deny"` (the `[workspace]` block is at `:1-4`;
  25 members listed at `:2`)
- All 25 member `Cargo.toml`s — add `[lints] workspace = true`
- Allow-list (genuine, reviewed uses):
  - `crates/signer/tests/zero_alloc.rs:53-65` — `unsafe impl GlobalAlloc` for the allocation-counting test
    allocator; cannot be written safely
  - `crates/crypto/tests/insecure_gate.rs` and `crates/crypto/tests/remote_signer_h10.rs` —
    `unsafe { std::env::set_var / remove_var }`
  Each gets a file-level `#![allow(unsafe_code)]` with a one-line justification comment.

**Implementation sketch:**
1. Add the workspace lint table; add `[lints] workspace = true` to all 25 members.
2. Build `--workspace --all-targets` to enumerate every violation; annotate exactly the files listed above.
3. Use `deny` rather than `forbid` so the file-level allows are possible at all (`forbid` cannot be
   overridden) — record that reasoning in a comment next to the lint so the next person does not "upgrade"
   it to `forbid` and break the test suite.
4. Confirm no production (non-test) crate needs an allow. If one does, that is a finding worth surfacing,
   not silently allowing.

**Acceptance criteria:**
- [ ] `[workspace.lints.rust] unsafe_code = "deny"` present; all 25 members opt in via `[lints] workspace = true`.
- [ ] The only `#![allow(unsafe_code)]` annotations are the three test files listed above, each with a
      justification comment.
- [ ] No production crate requires an allow.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` green.
- [ ] Standing invariant green.

**TDD test plan:** lint configuration, so the verification is a deliberate-violation check.
1. **RED first:** add a throwaway `unsafe { }` block to a production crate (e.g. `crates/builder/src/service.rs`)
   and confirm the build **fails** with `unsafe_code`. Remove it; do not commit.
2. Confirm `cargo nextest run --workspace` still passes with the allow-listed test files intact.

**Risks:** low, but two traps. `[lints]` inheritance requires each member to opt in — missing one silently
leaves that crate unguarded, so the deliberate-violation check should be run in a second crate too.
And an edition bump later (2024 makes `env::set_var` unsafe more broadly) could add allow-list entries;
the justification comments are what will make that diff reviewable.

---

## Notes for the phase lead

1. **The plan's Phase 1 row for A2 says "all 76 conformance cases green."** The file today has 38 cases ×
   3 runners = 114 test functions. RF1-03 + RF1-04 land the phase at 38 × 2 = 76, which reconciles the two
   readings — but a developer comparing the plan text to the file will stall unless told. It is stated in
   RF1-03's acceptance criteria.
2. **F124 is partly stale.** The concurrent same-validator signer test already uses conflicting data;
   only the pipeline double-vote test and the fail-closed hardening remain. A3 shrank from M to roughly S–M
   (3 points) as a result.
3. **SEC-1/SEC-2 have landed.** The doppelganger `ForwardWindowMachine` is constructed and wired in
   production, the liveness loop exists, and the deletion denylist is persistent. RF1-08's gate test
   therefore tests existing behavior instead of building machinery — which is what keeps it at 2 points.
   The plan's A4 row ("coordinate with SEC-2") should be read as *already coordinated*.
4. **RF1-03's triage is the phase's schedule risk.** Everything else is well-bounded. The day 13–14 slack
   in the schedule table is deliberately reserved for it.
5. **One cross-stream dependency only:** RF1-08 (Stream B) needs RF1-02's fixture (Stream A). RF1-02 is
   scheduled second in Stream A specifically to clear it early.
