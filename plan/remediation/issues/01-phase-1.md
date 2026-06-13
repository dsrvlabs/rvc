# Phase 1: M1 Shared Pre-Work — Slashing-Safety Seams & Traits

## Phase Overview

- **Goal:** Land the traits, dependency edges, skeleton modules, and standing test gates
  that every Milestone-1 (slashing-safety) per-finding fix consumes, with **zero observable
  behavior change** on `develop`. Resolve the two M1-gating open questions (PRD Q3 — do
  production on-disk slashing DBs exist; Q7 — is B-1/T-1 partially landed) before any
  per-finding fix begins.
- **Issue count:** 12 issues, 22 total points.
- **Estimated duration:** ~13-14 working days (single-stream).
- **Branch:** `prep/M1-shared` (all issues here land FF-only on this prep branch, which
  then FF-merges to `develop`).
- **Entry criteria:**
  - PRD (`plan/remediation/prd.md`), architecture (`plan/remediation/architecture.md`), and
    research overview (`plan/remediation/research/00-overview.md`) are merged on `develop`
    (or the active feature branch).
  - `develop` is green on the four-gate suite: `cargo build`, `cargo test`,
    `cargo clippy -- -D warnings`, `cargo fmt --check`.
  - Branch-naming convention agreed: `prep/M1-shared` for this phase; per-finding fix
    branches `fix/<ID>-<short-slug>` from Phase 2 onward.
  - FF-only merge policy to `develop` confirmed (rebase onto `develop`, then
    `git merge --ff-only`).
  - Reviewer Approve workflow agreed for P0 PRs (PRD §6.5).
- **Exit criteria:**
  - `prep/M1-shared` merged FF-only to `develop`; CI four-gate suite green.
  - `tests/architecture_no_cycles.rs` is a standing CI gate (asserts the level-graded DAG
    from `cargo metadata`, forbidding `slashing → doppelganger`, `signer → keymanager-api`,
    and `eth-types → anything`).
  - All four new traits / module skeletons compile with **zero call-site consumers**, and
    no behavior change is observable in any existing test on `develop`.
  - Q3 resolved in the tracker (either confirmed "no production DBs" or a captured
    pre-migration `slashing.sqlite` fixture is committed under
    `crates/slashing/tests/fixtures/`).
  - Q7 resolved in the tracker (current B-1/T-1 / L-9 state from running
    `cargo test -- --ignored` on `develop` is documented).
  - The remediation tracker `plan/remediation/tracker.md` is created with one row per
    finding (state `Open`) and each row annotated with which seam/trait it will consume.

### Phase Assumptions (recorded — no user input requested)

1. **Output directory.** Issue files live under `plan/remediation/issues/` (sibling to the
   existing `plan/remediation/{prd,architecture,project-plan}.md`); created fresh in this
   phase since no prior issues directory exists.
2. **Single-stream execution.** Per the user's explicit instruction, no
   Stream A / Stream B planning, no file-ownership map, no scaffold issues. One
   code-writer works issues sequentially in the order below.
3. **Point scale.** 1 = trivial (a few hours), 2 = small (~1 day), 3 = medium (~1.5-2
   days), 5 = large (rare; must be justified). No issue exceeds 3 points in this phase.
4. **Tracker file is a Phase-1 deliverable.** PRD §6.6 requires it; the project plan's
   "Prerequisites" lists it as a precondition, but the file does not exist on disk today
   (`plan/remediation/tracker.md` not present per `Glob`), so we create it here as Issue
   1.0 rather than treating it as already-done pre-work.
5. **No new external dependencies in Phase 1.** All new modules use existing workspace
   deps. The `tests/architecture_no_cycles.rs` parser uses the existing `cargo metadata`
   JSON via `std::process::Command` (no `cargo_metadata` crate added) to stay consistent
   with the architecture's P6.
6. **Test ordering convention.** Pre-work skeletons land with at least one smoke test
   per new module (`compiles + empty constructor returns`) so CI exercises them; full
   RED tests for findings live in Phase 2 branches.
7. **`SignerService` already wraps `slashing` + `CompositeSigner`** (verified by reading
   `crates/signer/src/lib.rs` lines 99-114); the SigningEnablement / FailClosedDefault
   traits in Issue 1.3 are new additions that the eventual `SigningGate` (Phase 2 Task
   2.6) will compose. Issue 1.3 does not yet wire them in.
8. **Pre-migration fixture provenance.** If Q3 resolves "yes, production DBs exist," the
   captured fixture is anonymised (validator pubkeys zeroed or remapped) before commit;
   provenance recorded in `crates/slashing/tests/fixtures/README.md`.
9. **Phase 1 is purely additive.** No existing file deletes, no existing public API
   changes. Any test that fails on `develop` after Phase 1 is a regression and the change
   must be reverted before the prep branch merges.

---

## Phase Summary

| Issue | Title | Points | Blocked by | Scope | Files |
|-------|-------|--------|------------|-------|-------|
| 1.0 | Create remediation tracker artifact | 1 | — | Few hours | `plan/remediation/tracker.md` |
| 1.1 | Add `eth-types::canonical` module skeleton | 2 | 1.0 | 1 day | `crates/eth-types/src/canonical/{mod,pubkey_hex,gvr_hex,signing_root_hex}.rs`, `crates/eth-types/src/lib.rs`, `crates/eth-types/tests/canonical_skeleton.rs` |
| 1.2 | Add `eth-types::insecure::InsecureGate` module | 2 | 1.0, 1.1 | 1 day | `crates/eth-types/src/insecure.rs`, `crates/eth-types/src/lib.rs`, `crates/eth-types/tests/insecure_gate.rs` |
| 1.3 | Add `signer::SigningEnablement` + `FailClosedDefault` traits | 2 | 1.0 | 1 day | `crates/signer/src/{enablement,fail_closed}.rs`, `crates/signer/src/lib.rs`, `crates/signer/tests/trait_skeletons.rs` |
| 1.4 | Add `slashing::SlashingDbReader` read-only trait | 2 | 1.0 | 1 day | `crates/slashing/src/reader.rs`, `crates/slashing/src/lib.rs`, `crates/slashing/src/db.rs`, `crates/slashing/tests/reader_skeleton.rs` |
| 1.5 | Add `signer → doppelganger` Cargo dep edge | 1 | 1.0 | Few hours | `crates/signer/Cargo.toml` |
| 1.6 | Author `tests/architecture_no_cycles.rs` standing CI gate | 3 | 1.0, 1.5 | 2 days | `tests/architecture_no_cycles.rs`, `Cargo.toml` (workspace test binary), workspace root |
| 1.7 | Add `crates/signer-registry` (dev-only) skeleton | 2 | 1.0, 1.6 | 1 day | `crates/signer-registry/{Cargo.toml, src/lib.rs}`, root `Cargo.toml` workspace members |
| 1.8a | Q3 determination spike (operator poll) | 1 | 1.0 | 1 day | `plan/remediation/tracker.md` |
| 1.8b | Anonymized pre-migration fixture capture (conditional on Outcome B) | 2 | 1.0, 1.8a | 1-2 days | `crates/slashing/tests/fixtures/migration_v1.sqlite`, `crates/slashing/tests/fixtures/README.md`, `crates/slashing/tests/fixtures_smoke.rs` |
| 1.9 | Resolve PRD Q7 (B-1/T-1 actual landed state) | 2 | 1.0 | 1 day | `plan/remediation/tracker.md` |
| 1.10 | Phase exit gate — FF-merge `prep/M1-shared` to `develop` | 2 | 1.0-1.9, 1.8a, 1.8b | 1 day | (merge + tracker annotations) |

**Totals:** 12 issues / 22 points / ~13-14 days single-stream.

> **Note on 1.8a / 1.8b conditional skip.** 1.8b is conditional on Outcome B (production DBs exist). If 1.8a determines Outcome A (no production DBs), 1.8b is skipped entirely and Phase 2 Task 2.3 uses a synthetic fixture generated inline in Rust. In the Outcome A path the phase totals are 11 issues / 20 points / ~12-13 days; in the Outcome B path the totals are 12 issues / 22 points / ~13-14 days. The table above lists the upper-bound (Outcome B) plan.

---

## Phase Execution Plan

Sequential, single-stream. Each day-slot is one working day for one code-writer.

| Day | Issue | Notes |
|-----|-------|-------|
| 1 | 1.0 Tracker artifact (1pt) + start 1.8a Q3 operator-poll spike | Tracker file lands first so each subsequent issue can annotate. 1.8a's operator poll has a 2-day SLA, so kick it off in parallel as a pure-async work item the moment the tracker exists. |
| 2 | 1.1 canonical skeleton (2pt) | Land all four newtypes + parsers + smoke tests. 1.8a continues asynchronously (no code-writer time after the initial Slack/email kickoff). |
| 3 | 1.1 cont. + 1.2 InsecureGate kickoff | 1.2 is independent of 1.1 logically but the implementation note orders `pub mod insecure;` after `pub mod canonical;` in `lib.rs`, so 1.1 must land first. |
| 4 | 1.2 InsecureGate (2pt cont.) | Decision/Refuse/Warn/Allow enum + from_env + traced_test for warn! emission. |
| 5 | 1.3 SigningEnablement + FailClosedDefault (2pt) | Pure trait skeletons in `crates/signer`. |
| 6 | 1.4 SlashingDbReader (2pt) | Adds trait + makes existing `SlashingDb` implement it. |
| 7 | 1.5 signer→doppelganger dep edge (1pt) + start 1.6 architecture_no_cycles.rs | Dep edge is a `Cargo.toml` one-liner; immediately unblocks 1.6. |
| 8 | 1.6 architecture_no_cycles.rs (3pt cont.) | Parses `cargo metadata`, asserts the level-graded DAG. Must encode the expected zero out-edges for `signer-registry` (Level DEV-ONLY) so 1.7 lands without re-editing the test. |
| 9 | 1.6 architecture_no_cycles.rs (cont.) | Forbidden-edge assertions; flake-proofing. |
| 10 | 1.7 signer-registry skeleton (2pt) | New dev-only crate; updates workspace members. 1.6 must already encode signer-registry's expected zero out-edges so 1.7 lands without re-touching 1.6. |
| 11 | 1.8a decision close-out + 1.9 Q7 resolution (2pt) | Land the Outcome A/B decision in tracker; immediately run `cargo test -- --ignored` for Q7. If 1.8a returns Outcome A: skip 1.8b, slot 1.10 onto day 13. If Outcome B: proceed to 1.8b on day 12. |
| 12 | 1.8b fixture capture (2pt; Outcome B only) | Anonymisation script + commit + smoke test + provenance README. Skipped in Outcome A. |
| 13 | 1.8b cont. (Outcome B) **or** 1.10 phase exit gate (Outcome A) | Outcome B: finish 1.8b; Outcome A: rebase `prep/M1-shared` onto `develop`, full CI green, FF-merge, annotate tracker. |
| 14 | 1.10 Phase exit gate (Outcome B only) | Rebase, CI, FF-merge, annotate tracker. |

> **1.8a polling SLA.** 1.8a's "spike" content is a 2-day operator-response SLA. If no
> operators respond by end of day 3 (≈ end of business day 2 after kickoff on day 1),
> 1.8a's escalation path is: recommend "proceed under Outcome A (no production DBs)" with
> the rationale documented in the tracker. This prevents the open question from
> degenerating into a perpetual blocker on the rest of the phase.
>
> **Day budget.** Outcome A path: 13 days; Outcome B path: 14 days. The execution plan
> above shows the upper bound (Outcome B). Update day-13/day-14 row binding once 1.8a
> resolves.

---

## Issues

### Issue 1.0: Create remediation tracker artifact

- **Points:** 1
- **Type:** chore
- **Priority:** P0
- **Blocked by:** none
- **Blocks:** every subsequent issue annotates this file
- **Scope:** Few hours

**Description:**
Create `plan/remediation/tracker.md` per PRD §6.6 / Assumption #12. This is the single
auditor-facing artifact that lists every finding ID, current state (`Open` /
`RED-landed` / `GREEN-landed` / `Verified` / `Shipped`), commit hashes, and the test
file/name. Populated initially with all 46 findings in `Open` state. Subsequent Phase 1
issues will annotate each row with the seam/trait it will consume.

**Implementation Notes:**
- Files to create: `plan/remediation/tracker.md`.
- Approach: Markdown table with columns `ID | Priority | Crate | One-line problem | State | RED commit | GREEN commit | Test file | Seam/trait consumed | Notes`.
- Source the 46 finding IDs from PRD §5 P0/P1/P2 tables verbatim. Initial state =
  `Open`; commit/test columns blank.
- Add a "Phase-1 pre-work" subsection at the top listing the four traits/modules and the
  two question-resolutions (Q3, Q7) with their owning issue numbers.
- Watch out for: do not omit any finding ID. PRD §5 totals are 46 (1 Critical + 13 High +
  13 Medium + 14 Low + 5 Info). Cross-check the count at the bottom of the table.

**Acceptance Criteria:**
- [ ] `plan/remediation/tracker.md` exists and lists all 46 finding IDs from PRD §5.
- [ ] Each row has columns `ID | Priority | Crate | One-line problem | State | RED commit | GREEN commit | Test file | Seam/trait consumed | Notes`.
- [ ] Every row's `State` column is `Open` at this commit.
- [ ] A row count footer asserts `Total: 46 findings (1 Critical + 13 High + 13 Medium + 14 Low + 5 Info)`.
- [ ] A top-of-file "Phase-1 pre-work" subsection lists the issues 1.1-1.7, 1.8a,
      1.8b, 1.9 with their target deliverables (1.8b explicitly noted as conditional
      on Outcome B).
- [ ] File is referenced from `plan/remediation/project-plan.md` Prerequisites section
      (no rewrite — a one-line link is enough; or note in tracker that the project-plan
      already references it by path).

**Testing Notes:**
- No automated test; the artifact is reviewed by hand at PR time.
- Reviewer checks: 46 row count, every PRD §5 ID present, no duplicates.

---

### Issue 1.1: Add `eth-types::canonical` module skeleton

- **Points:** 2
- **Type:** feature (additive seam)
- **Priority:** P0
- **Blocked by:** 1.0 (acceptance criteria require annotating `plan/remediation/tracker.md`, which 1.0 creates)
- **Blocks:** 1.2 (its implementation note orders `pub mod insecure;` after `pub mod canonical;` in `eth-types/src/lib.rs`), 3.5 (Phase 3 canonical promotion), 4.11 (GVR-1 + IMP-1), 4.13 (EXIT-1), 6.5 (L-2)
- **Scope:** 1 day

**Description:**
Add the `canonical` submodule to `crates/eth-types` containing the `PubkeyHex`,
`GvrHex`, and `SigningRootHex` newtypes plus their `parse_*` constructors and the
`eq_gvr` comparison helper. This is the single source of truth that every later fix
collapsing duplicated hex/GVR parsing onto one implementation will use. **No call sites
migrate in this issue** — the module ships with zero consumers and is exercised only by
its own unit tests.

**Implementation Notes:**
- Files to create:
  - `crates/eth-types/src/canonical/mod.rs` — re-exports.
  - `crates/eth-types/src/canonical/pubkey_hex.rs` — `PubkeyHex` newtype around `[u8; 48]` with `parse_pubkey_hex(&str) -> Result<PubkeyHex, ParseError>`. Validates ASCII hex, even length, strict single `0x` prefix (architecture lines 257-258, addresses L-2).
  - `crates/eth-types/src/canonical/gvr_hex.rs` — `GvrHex` newtype with lowercase-normalised string view; `parse_gvr_hex(&str) -> Result<Root, ParseError>` and `eq_gvr(&str, &Root) -> bool` (architecture lines 258, 273, addresses GVR-1).
  - `crates/eth-types/src/canonical/signing_root_hex.rs` — `SigningRootHex` newtype around `[u8; 32]` with the same strict-hex pattern.
- Files to modify:
  - `crates/eth-types/src/lib.rs` — add `pub mod canonical;` (after existing `pub mod ssz_helpers;` line).
- Files to create (tests):
  - `crates/eth-types/tests/canonical_skeleton.rs` — smoke tests for each newtype's
    `parse_*` happy path + at least three error cases per parser (double-0x, odd-length,
    non-hex char). Property test stub using existing `proptest` workspace dep is optional
    and not required for this issue.
- Approach: Pure additive. Define a single `ParseError` enum in `canonical/mod.rs`
  (`#[derive(Debug, Error)]` via `thiserror`) with `InvalidHex`, `InvalidLength`,
  `DoublePrefix` variants. Each parser returns `Result<_, ParseError>`.
- Key decisions:
  - Newtypes are `#[derive(Clone, PartialEq, Eq, Hash)]`; no `Copy` (consistent with
    existing `Root` usage).
  - `PubkeyHex` stores `[u8; 48]` not a `String`, so call sites needing bytes get them
    without re-parsing.
  - `GvrHex` exposes both `as_bytes() -> &Root` and `as_normalised_hex() -> &str` so
    downstream comparisons can pick either side.
- Watch out for:
  - Do not add `serde` derives to the newtypes yet — that's a downstream concern and
    avoiding it keeps the seam minimal.
  - The strict single-`0x` prefix matters: `0x0xABCD...` must be rejected (PRD L-2
    finding).
- New files to create: per above. No existing files are deleted.

**Acceptance Criteria:**
- [ ] `cargo build -p rvc-eth-types` succeeds.
- [ ] `cargo test -p rvc-eth-types --test canonical_skeleton` is green and covers:
      happy-path parse for all three newtypes; rejection of `0x0xABCD...` style double
      prefix; rejection of odd-length hex; rejection of non-hex character; `eq_gvr`
      true when string and bytes match (mixed case in string), false when they differ.
- [ ] `cargo clippy -- -D warnings` is green for `rvc-eth-types`.
- [ ] No existing test in any other crate is touched (verified by `git status`).
- [ ] The new module has zero callers outside its own tests (`grep -r 'eth_types::canonical' crates/ bin/` returns only the test file).
- [ ] Tracker row for L-2 annotated with "Will consume `eth-types::canonical::parse_pubkey_hex` in Phase 6 Task 6.5"; rows for GVR-1, IMP-1, EXIT-1 annotated likewise for `eq_gvr`.

**Testing Notes:**
- Tests live in `crates/eth-types/tests/canonical_skeleton.rs` (integration test
  location, since the module is `pub`).
- Use the existing `hex` workspace dep for golden-value construction inside tests.
- No mocks needed — pure functions.

---

### Issue 1.2: Add `eth-types::insecure::InsecureGate` module

- **Points:** 2
- **Type:** feature (additive seam)
- **Priority:** P0
- **Blocked by:** 1.0 (AC annotates the tracker created by 1.0); 1.1 (implementation note orders `pub mod insecure;` after `pub mod canonical;` in `eth-types/src/lib.rs`, so 1.1's `pub mod canonical;` line must already exist)
- **Blocks:** 2.1 (SS-1), 6.1 (KM-3), 6.13 (SIG-1), 6.3 (L-1 portion via shared gate)
- **Scope:** 1 day

**Description:**
Add `eth-types::insecure::InsecureGate { Refuse, Warn, Allow }` and the
`from_env(var: &str, default: Self) -> Self` + `Decision::evaluate(gate, condition_is_insecure)`
helpers per the architecture's ADR-003 (InsecureGate inlined into `eth-types` rather
than a separate crate). Used by SS-1 to gate the legacy v1 raw-root signer, by KM-3 for
non-loopback keymanager bind, by L-1 for HTTPS-mode handling, and by SIG-1 for the
`--password-dir` fail-closed path. **No call sites migrate in this issue.**

**Implementation Notes:**
- Files to create:
  - `crates/eth-types/src/insecure.rs` — the enum + helpers.
- Files to modify:
  - `crates/eth-types/src/lib.rs` — add `pub mod insecure;` after `pub mod canonical;`.
- Files to create (tests):
  - `crates/eth-types/tests/insecure_gate.rs` — covers each `InsecureGate` arm's
    decision semantics: `Refuse` returns a `Decision::Abort`; `Warn` returns
    `Decision::ProceedWithWarning` and emits a `tracing::warn!`; `Allow` returns
    `Decision::Proceed`. `from_env` reads a process env var and maps `"true"` →
    `Allow`, `"false"` → `Refuse`, unset → the supplied default.
- Approach:
  - `InsecureGate` is a small `pub enum InsecureGate { Refuse, Warn, Allow }` with
    `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`.
  - `Decision` is a sibling enum `pub enum Decision { Proceed, ProceedWithWarning { reason: &'static str }, Abort { reason: &'static str } }`.
  - `pub fn evaluate(gate: InsecureGate, condition_is_insecure: bool, reason: &'static str) -> Decision` — returns `Proceed` when the condition is **not** insecure; otherwise dispatches on the gate variant.
  - `pub fn from_env(var: &str, default: InsecureGate) -> InsecureGate` — `std::env::var`; lowercase compare.
- Key decisions:
  - The reason string is `&'static str` to avoid allocations on the hot bind path.
  - `tracing::warn!` is emitted inside `evaluate` for the `Warn` arm so consumers do
    not have to remember to log; consumers only check `matches!(d, Decision::Abort{..})`.
- Watch out for:
  - Don't conflate this with the SS-1 v1 raw-root removal itself — this module is the
    decision primitive; SS-1 (Phase 2) is the consumer.
  - Env-var tests must not mutate process-global state in a way that races other tests.
    Use a per-test unique var name (e.g. `RVC_INSECURE_GATE_TEST_<n>`) so parallel
    `cargo test` does not flake. (PRD Info-5 calls out the broader env-mutation issue;
    this issue avoids the trap by construction.)

**Acceptance Criteria:**
- [ ] `cargo build -p rvc-eth-types` succeeds.
- [ ] `cargo test -p rvc-eth-types --test insecure_gate` is green and covers:
      `Refuse + insecure=true → Abort`; `Warn + insecure=true → ProceedWithWarning` and
      asserts the warn! was emitted (via `tracing-test`'s `traced_test`); `Allow +
      insecure=true → Proceed`; all three gates with `insecure=false → Proceed`;
      `from_env(unset) → default`; `from_env("true") → Allow`; `from_env("false") →
      Refuse`; case-insensitive parsing.
- [ ] `cargo clippy -- -D warnings` green for `rvc-eth-types`.
- [ ] Zero callers outside the test module
      (`grep -r 'eth_types::insecure' crates/ bin/` returns only the test file).
- [ ] Tracker rows for SS-1, KM-3, SIG-1, L-1 annotated with "Will consume
      `eth-types::insecure::InsecureGate` in Phase 2/6."

**Testing Notes:**
- The `tracing-test` workspace dev-dep is already available (`tracing-test = "0.2"` in
  the workspace `Cargo.toml`). Use `#[traced_test]` to assert `warn!` emission.
- Use unique env var names per test, never `unsafe { std::env::set_var }` of a shared
  name (architecture ADR-009 / Info-5 lesson).

---

### Issue 1.3: Add `signer::SigningEnablement` + `FailClosedDefault` traits

- **Points:** 2
- **Type:** feature (additive seam)
- **Priority:** P0
- **Blocked by:** 1.0 (AC annotates the tracker created by 1.0)
- **Blocks:** 2.4 (D-1 implements `SigningEnablement`), 2.6 (D-3 consumes both traits)
- **Scope:** 1 day

> **Sequencing note (vs Issue 1.5).** Earlier drafts marked 1.5 as "Blocked by 1.3" on
> the rationale that the dep edge "needs the trait to exist." That is not strictly true:
> 1.5 is a pure `doppelganger.workspace = true` Cargo edge that imports no symbol from
> 1.3. 1.5 has been softened to a sequencing note (it should not artificially inflate
> the critical path) and 1.5's actual hard prerequisite is 1.0 only. The traits added
> here in 1.3 must still exist before Phase 2's consumers (2.4, 2.6) compile, but that
> ordering is in-phase and does not bind 1.5.

**Description:**
Add two new traits to `crates/signer`:
1. `SigningEnablement` — single-method trait `fn is_signing_enabled(&self, pubkey: &PublicKey) -> bool`. The eventual `SigningGate` (Phase 2 Task 2.6) consults this before every sign; `ForwardWindowMachine` (Phase 2 Task 2.4) implements it. **No implementors land in this issue.**
2. `FailClosedDefault<T>` — single-method trait `fn default_when_unknown() -> T` codifying PRD §6.3 fail-closed defaults for boundary booleans. Default impl for `bool` returns `false`. Replaces the `unwrap_or(true)` pattern that PRD §6.3 calls out.

Both traits ship with smoke tests but zero call-site consumers. The existing
`SignerService` is not modified.

**Implementation Notes:**
- Files to create:
  - `crates/signer/src/enablement.rs` — defines `pub trait SigningEnablement { fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool; }`. Document the fail-closed default: unknown pubkey → `false`.
  - `crates/signer/src/fail_closed.rs` — defines `pub trait FailClosedDefault { type Out; fn default_when_unknown() -> Self::Out; }` with a default impl `impl FailClosedDefault for bool { type Out = bool; fn default_when_unknown() -> bool { false } }`.
- Files to modify:
  - `crates/signer/src/lib.rs` — add `mod enablement;` + `mod fail_closed;` then
    `pub use enablement::SigningEnablement;` and `pub use fail_closed::FailClosedDefault;`.
- Files to create (tests):
  - `crates/signer/tests/trait_skeletons.rs` — defines an in-test mock implementor
    `struct DenyAll;` for `SigningEnablement` that always returns `false`; asserts the
    trait is `dyn`-compatible (`let _: &dyn SigningEnablement = &DenyAll;`); asserts
    `<bool as FailClosedDefault>::default_when_unknown() == false`.
- Approach:
  - `SigningEnablement` does NOT take `async` — `is_signing_enabled` is a synchronous
    in-memory lookup against the `ForwardWindowMachine`'s `HashMap<PublicKey, State>`
    (architecture line 446). Keeping it sync avoids forcing `async-trait` on the
    consumer site and avoids the `Send + Sync` bounds that complicate Phase 2's
    `SigningGate` composition.
  - `FailClosedDefault` uses an associated type rather than a generic so future
    non-bool implementors (e.g. `Decision`) can plug in without breaking the bool
    consumer.
- Key decisions:
  - The trait takes `&crypto::PublicKey` (not `&[u8; 48]`) to match the existing
    `signer` crate's API surface (`crates/signer/src/lib.rs` lines 20, 131, 336).
  - The trait does not return `Result` — fail-closed is encoded as `false`, not as `Err`.
- Watch out for:
  - Adding `async-trait` here would force every implementor and every call site to be
    `async`. The architecture explicitly designs the gate as a sync trait (architecture
    line 446-449).
  - Do not pre-add the `signer → doppelganger` dep edge here — that is Issue 1.5,
    sequenced after this issue.

**Acceptance Criteria:**
- [ ] `cargo build -p rvc-signer` succeeds.
- [ ] `cargo test -p rvc-signer --test trait_skeletons` green; covers: a mock
      `DenyAll` implementor returns `false` for any pubkey; `&dyn SigningEnablement`
      type-coerces (object-safety); `<bool as FailClosedDefault>::default_when_unknown()
      == false`.
- [ ] `cargo clippy -- -D warnings` green for `rvc-signer`.
- [ ] The existing `SignerService` is **not** modified (verified by `git diff --stat
      crates/signer/src/lib.rs` showing only the new `mod` / `pub use` lines added).
- [ ] No existing `crates/signer` test (the 2300-line `lib.rs` test module) regresses.
- [ ] Zero non-test consumers: `grep -r 'SigningEnablement\|FailClosedDefault' crates/ bin/ | grep -v 'tests/'` returns only the new files.
- [ ] Tracker rows for D-1, D-3 annotated with "Will implement `SigningEnablement` in
      Phase 2 Tasks 2.4 / 2.6"; rows for L-3, D-2, D-3 annotated with
      `FailClosedDefault` consumption.

**Testing Notes:**
- The smoke test only needs `&dyn SigningEnablement = &DenyAll;` to verify object
  safety; no async runtime required.
- Use `crypto::SecretKey::generate().public_key()` (already pattern-used in
  `crates/signer/src/lib.rs:1218`) to obtain a `PublicKey` for the mock call.

---

### Issue 1.4: Add `slashing::SlashingDbReader` read-only trait

- **Points:** 2
- **Type:** feature (additive seam)
- **Priority:** P0
- **Blocked by:** 1.0 (AC annotates the tracker created by 1.0)
- **Blocks:** 2.4 (D-1 restart-aware safe-skip needs this)
- **Scope:** 1 day

**Description:**
Add a read-only trait `SlashingDbReader` in `crates/slashing` with at minimum
`fn last_signed_attestation(&self, pubkey: &str, gvr: &Root) -> Option<TargetEpoch>` and
make the existing `SlashingDb` struct implement it. This breaks the architectural
forbidden edge `slashing → doppelganger` (architecture lines 216-220): instead of
`doppelganger` reaching into `SlashingDb`, `doppelganger` consumes a read-only trait
that `slashing` exposes and `doppelganger` imports. `slashing` does not know
`doppelganger` exists.

**Implementation Notes:**
- Files to create:
  - `crates/slashing/src/reader.rs` — the trait and a blanket
    `impl SlashingDbReader for SlashingDb` that delegates to existing
    `SlashingDb::get_attestations` (visible in `crates/signer/src/lib.rs:1244` already).
- Files to modify:
  - `crates/slashing/src/lib.rs` — add `mod reader;` + `pub use reader::SlashingDbReader;`.
  - `crates/slashing/src/db.rs` — no behavior change; the existing
    `get_attestations(&self, pubkey: &str) -> Result<Vec<SignedAttestation>>` (per
    `signer/src/lib.rs:1244` callsite) is the building block. If a `gvr` filter is not
    already supported, the trait method filters in Rust over the returned `Vec`.
- Files to create (tests):
  - `crates/slashing/tests/reader_skeleton.rs` — opens an in-memory DB (use
    `SlashingDb::open_in_memory` already exercised at `signer/src/lib.rs:1209`),
    stages and commits one attestation row, then asserts
    `(&db as &dyn SlashingDbReader).last_signed_attestation(pubkey_hex, &gvr) == Some(target_epoch)`. Also asserts `None` for an unknown pubkey.
- Approach:
  - The trait takes `&str` pubkey (matching the existing `get_attestations(&str)` API)
    and `&Root` gvr.
  - Return type is `Option<TargetEpoch>` (an alias for `u64`) — `None` means "no prior
    attestation for this validator under this GVR." Define `TargetEpoch` as `u64` for
    now; can be a newtype later.
- Key decisions:
  - Read-only by design: the trait has **no** `stage_*` / `commit` methods. This is
    what makes the `slashing → doppelganger` cycle impossible.
  - Trait stays in `crates/slashing` (not in `eth-types`) because the data shape
    (`SignedAttestation`, GVR semantics) belongs to slashing.
- Watch out for:
  - The signature must accept `&Root` (alias for `[u8; 32]` from `eth-types`), not a
    new GVR type from Issue 1.1. Issue 1.1's `GvrHex` is a string-comparison helper;
    this trait works with bytes.
  - If `SlashingDb::get_attestations` does not currently filter by GVR (most likely
    not), document this and filter in the trait impl rather than changing the DB API.

**Acceptance Criteria:**
- [ ] `cargo build -p rvc-slashing` succeeds.
- [ ] `cargo test -p rvc-slashing --test reader_skeleton` green.
- [ ] `cargo clippy -- -D warnings` green for `rvc-slashing`.
- [ ] `SlashingDb` implements `SlashingDbReader` (proven by the trait-object cast in
      the test).
- [ ] All existing `crates/slashing` tests still pass (`cargo test -p rvc-slashing`).
- [ ] Tracker row for D-1 annotated with "Will consume `SlashingDbReader` for
      restart-aware safe-skip (Phase 2 Task 2.4)."

**Testing Notes:**
- `SlashingDb::open_in_memory()` is the test constructor used throughout
  `crates/signer/src/lib.rs` tests.
- For the stage+commit setup, mirror the pattern at `signer/src/lib.rs:1210-1248`
  (stage_attestation → commit → get_attestations).

---

### Issue 1.5: Add `signer → doppelganger` Cargo dep edge

- **Points:** 1
- **Type:** chore
- **Priority:** P0
- **Blocked by:** 1.0 (tracker AC). **Not blocked by 1.3** — a pure `doppelganger.workspace = true` Cargo edge imports no symbol from 1.3's traits, so 1.3 is **not** a hard prerequisite. See sequencing note below.
- **Blocks:** 1.6 (architecture_no_cycles.rs must observe this edge), 2.6 (D-3 needs it)
- **Scope:** Few hours

**Description:**
Add `doppelganger.workspace = true` to `crates/signer/Cargo.toml` `[dependencies]`. Per
the architecture's level-graded DAG (lines 186-189), `signer` (Level 6) consults
`doppelganger` (Level 5) via the `SigningEnablement` trait. The edge is mandatory
before Phase 2 Task 2.6 ships the `SigningGate`. Adding it now lets the
`tests/architecture_no_cycles.rs` gate (Issue 1.6) observe and assert it.

> **Sequencing note (vs Issue 1.3).** An earlier draft listed 1.5 as "Blocked by 1.3"
> on the theory that the dep edge "needs the trait to exist." That is not strictly
> true: 1.5 is a pure `Cargo.toml` one-liner that adds `doppelganger.workspace = true`
> to `[dependencies]`; no `use doppelganger::SigningEnablement;` line lands in
> `crates/signer/src/` until Phase 2 Task 2.6. The Cargo dep edge compiles fine against
> a `doppelganger` crate that does not yet contain the trait. Removing the false 1.3 →
> 1.5 hard-blocker shortens the critical path and lets 1.5 sit anywhere after 1.0 (and
> before 1.6). For diff/PR locality the execution plan still places 1.5 on day 7, after
> 1.3 / 1.4 — but that is convenience, not a hard dependency.

**Implementation Notes:**
- Files to modify:
  - `crates/signer/Cargo.toml` — add `doppelganger.workspace = true` to
    `[dependencies]`.
- No source-code changes; nothing in `crates/signer/src/` imports `doppelganger::*`
  yet. Phase 2 Task 2.6 adds the first import.
- Approach: One-line Cargo.toml edit, run `cargo check -p rvc-signer` to confirm.
- Watch out for: This edge cannot be removed later — it is the canonical seam direction.
  If the build fails because `doppelganger` itself transitively depends on something
  `signer` already depends on with conflicting features, that is a deeper architectural
  bug to surface; current architecture (line 134) shows `doppelganger` depends only on
  `eth-types`, `crypto`, `slashing`, none of which create a cycle.

**Acceptance Criteria:**
- [ ] `crates/signer/Cargo.toml` lists `doppelganger.workspace = true` under
      `[dependencies]`.
- [ ] `cargo check -p rvc-signer` is green.
- [ ] `cargo test -p rvc-signer` (existing tests) all pass — no behavior change.
- [ ] No new `use doppelganger::...` lines in `crates/signer/src/` (verified by
      `git diff --stat crates/signer/src/`).
- [ ] Tracker note added: "M1 dep edge `signer → doppelganger` is live."

**Testing Notes:**
- No new tests; the existing CI four-gate suite is the proof.
- Issue 1.6's standing gate then asserts this edge programmatically.

---

### Issue 1.6: Author `tests/architecture_no_cycles.rs` standing CI gate

- **Points:** 3
- **Type:** feature (CI gate)
- **Priority:** P0
- **Blocked by:** 1.0 (tracker AC), 1.5 (the edge must exist before the test asserts it)
- **Blocks:** 1.7 (signer-registry's AC requires `architecture_no_cycles.rs` to stay green after adding the new workspace member; 1.6 must encode the expected zero out-edges from day one), standing gate from this point onwards
- **Scope:** 2 days

> **Sequencing note (vs Issue 1.7).** 1.7 adds a new workspace crate
> (`crates/signer-registry`) and its AC requires that `tests/architecture_no_cycles.rs`
> stays green after the addition. To avoid 1.7 re-editing 1.6's test file, 1.6 should
> encode the expected DAG node for `signer-registry` as a **dev-only / Level
> DEV-ONLY** entry with zero production out-edges from the moment 1.6 lands. The
> `const FORBIDDEN: &[(&str, &str)]` list and the cycle-detection seed should both
> already know about `signer-registry` even though the crate itself doesn't exist
> yet in 1.6 — the test treats a missing-crate name as "skip the assertion for that
> crate" rather than "fail." That way 1.7 lands as a pure-additive `Cargo.toml` +
> `crates/signer-registry/` diff with no test churn.

**Description:**
Author a workspace-level integration test, `tests/architecture_no_cycles.rs`, that
parses `cargo metadata --format-version=1` and enforces:
1. The dependency graph among workspace members is acyclic (no `cargo metadata` cycle).
2. Every documented forbidden edge from the architecture (lines 216-222) is absent:
   `slashing → doppelganger`, `signer → keymanager-api`, `eth-types → any other
   workspace crate`.
3. The expected edge `signer → doppelganger` (Issue 1.5) is present.

This is a **standing CI gate** that runs as part of every fix branch's `cargo test` from
this point onwards.

**Implementation Notes:**
- Files to create:
  - `tests/architecture_no_cycles.rs` — workspace integration test. Per the
    architecture's P6 ("no new external deps"), do **not** add the `cargo_metadata`
    crate; instead use `std::process::Command::new("cargo").args(["metadata",
    "--format-version=1", "--no-deps"])` and parse the JSON with `serde_json` (already
    a workspace dep).
- Files to modify:
  - Root `Cargo.toml` — confirm a top-level `[[test]]` section is not needed; Rust
    integration tests in `tests/` are auto-discovered by `cargo test` when run from the
    workspace root only if a top-level package owns the `tests/` directory. **Decision
    point during implementation:** if the workspace root has no package, host this
    test inside an existing crate (e.g. add `crates/architecture-tests/` as a tiny
    test-only crate, similar to the `signer-registry` pattern in Issue 1.7), or attach
    a top-level dummy package. Pick whichever requires the fewer workspace-member
    additions; both are valid.
- Approach:
  1. Shell out to `cargo metadata --format-version=1 --no-deps`.
  2. Parse the JSON into `serde_json::Value`.
  3. Walk `packages[].dependencies[]`, filter to `kind != "dev"` (the production graph)
     and `kind != "build"`, and to `path` deps only (workspace-internal).
  4. Build a `HashMap<crate_name, Vec<crate_name>>` of edges.
  5. Run a cycle-detection DFS; assert no cycle.
  6. Assert each forbidden edge is absent: `assert!(!edges["slashing"].contains("doppelganger"), ...)` and similarly for the other two.
  7. Assert `signer → doppelganger` is present (proves Issue 1.5 took effect).
- Key decisions:
  - Use `--no-deps` to scope to workspace members only — keeps the parse small and
    deterministic across registry changes.
  - Forbidden edges are encoded as a `const FORBIDDEN: &[(&str, &str)]` at top of file
    so future architects can extend without restructuring.
  - The test name pattern `architecture_no_cycles` makes the CI failure self-documenting.
- Watch out for:
  - `cargo metadata` output is not stable across versions; check `metadata_version`
    field and assert `>= 1`.
  - The test must run from any directory; use `cargo`'s automatic `CARGO_MANIFEST_DIR`
    or `current_dir()` resolution rather than hardcoding paths.
  - In CI, `cargo` itself must be on the PATH — the test fails loudly if not
    (`Command::new("cargo").spawn()` returns a clear error).
  - Crate names in `cargo metadata` are the package names (`rvc-signer`, `rvc-eth-types`,
    `rvc-doppelganger`), not the workspace.dependencies keys. Map carefully.

**Acceptance Criteria:**
- [ ] `tests/architecture_no_cycles.rs` exists and `cargo test --test architecture_no_cycles` is green.
- [ ] The test asserts no cycle among workspace members.
- [ ] The test asserts `slashing` does NOT depend on `doppelganger`.
- [ ] The test asserts `signer` does NOT depend on `keymanager-api`.
- [ ] The test asserts `eth-types` does NOT depend on any other workspace member.
- [ ] The test asserts `signer` DOES depend on `doppelganger` (proving Issue 1.5
      survived).
- [ ] A deliberate test-only injection (commented-out, or behind a feature flag) of a
      forbidden edge causes the test to fail with a clear assertion message — verified
      by hand once and documented in the test's header comment.
- [ ] `cargo clippy -- -D warnings` green for the new test file.
- [ ] The test runs in <10 seconds locally (so it stays cheap in CI).
- [ ] Tracker note added: "Standing gate `tests/architecture_no_cycles.rs` live from
      this commit onwards."

**Testing Notes:**
- Manual sanity check during development: temporarily add a forbidden edge in a
  scratch branch and confirm the test fails with the expected message; revert before
  merge.
- The test is a pure-Rust shellout; no network, no DB, no async runtime.

---

### Issue 1.7: Add `crates/signer-registry` (dev-only) skeleton

- **Points:** 2
- **Type:** feature (test infrastructure)
- **Priority:** P0
- **Blocked by:** 1.0 (tracker AC), 1.6 (the standing `tests/architecture_no_cycles.rs` gate must already exist and have been authored to know `signer-registry` as a dev-only / zero-production-out-edges node; adding the workspace member must keep that test green)
- **Blocks:** 2.1 (SS-1 populates the registry with v1/v2 signing-method metadata)
- **Scope:** 1 day

**Description:**
Add a new workspace member `crates/signer-registry` that holds static, compile-time
metadata describing every gRPC signing entry point on `rvc-signer`. Per architecture
ADR-010, this crate is **dev-dependency-only** — no production code links it. The
metadata is consumed by the PRD M4 enumeration test
(`bin/rvc-signer/tests/signing_path_enumeration.rs`, landed in Phase 2 Task 2.1) which
asserts that every registered handler either (a) is a non-slashable message type, or
(b) routes through `SigningGate::stage_* + commit`. In this issue the skeleton ships
with empty metadata; Phase 2 Task 2.1 populates it.

**Implementation Notes:**
- Files to create:
  - `crates/signer-registry/Cargo.toml` — `package.name = "rvc-signer-registry"`,
    `package.publish = false`, no external deps initially.
  - `crates/signer-registry/src/lib.rs` — defines `pub struct SigningMethod { pub
    service: &'static str, pub method: &'static str, pub message_kind: MessageKind, pub
    routes_through_gate: bool }`, `pub enum MessageKind { Block, Attestation,
    Aggregate, SyncMessage, SyncContribution, RandaoReveal, VoluntaryExit,
    BuilderRegistration, Selection, V1RawRoot }`, and `pub const REGISTERED_METHODS:
    &[SigningMethod] = &[];` (empty array; populated in Phase 2 Task 2.1).
- Files to modify:
  - Root `Cargo.toml` — add `"crates/signer-registry"` to `[workspace] members` and add
    `signer-registry = { path = "crates/signer-registry", package = "rvc-signer-registry" }` to `[workspace.dependencies]`.
- Files to create (tests):
  - `crates/signer-registry/tests/skeleton.rs` — asserts `REGISTERED_METHODS.is_empty()`
    today (so the test will fail-loud when Phase 2 populates it — that is intentional;
    Phase 2 Task 2.1 inverts this assertion to "not empty" as part of its work).
- Approach:
  - Pure `const`/`static` data; no runtime allocation, no async, no I/O.
  - All fields are `&'static str` so the data is link-time-known.
- Key decisions:
  - `routes_through_gate: bool` for now; Phase 2 may upgrade to an enum if more
    nuanced routing semantics emerge.
  - Crate is `publish = false` so it cannot leak to crates.io.
  - No production consumer ever depends on this crate. Architecture line 211 makes
    this explicit ("DEV-ONLY (no production edges)").
- Watch out for:
  - Adding it as a `[workspace.dependencies]` entry does NOT make it a production dep
    of any other crate. It only becomes a `dev-dependency` when a `[dev-dependencies]`
    section lists it. Issue 2.1 is the place where `bin/rvc-signer/Cargo.toml`'s
    `[dev-dependencies]` will reference `signer-registry`. Verify nothing in this
    issue accidentally adds it under `[dependencies]`.

**Acceptance Criteria:**
- [ ] `crates/signer-registry/Cargo.toml` and `crates/signer-registry/src/lib.rs` exist.
- [ ] Root `Cargo.toml` lists `crates/signer-registry` in `[workspace] members`.
- [ ] Root `Cargo.toml` `[workspace.dependencies]` has a `signer-registry` entry.
- [ ] `cargo build -p rvc-signer-registry` is green.
- [ ] `cargo test -p rvc-signer-registry --test skeleton` is green
      (asserts `REGISTERED_METHODS.is_empty()`).
- [ ] `cargo clippy -- -D warnings` green for the new crate.
- [ ] Issue 1.6's `tests/architecture_no_cycles.rs` is still green after the new crate
      is added (no cycle introduced).
- [ ] No production crate has `signer-registry` in its `[dependencies]` (verified by
      grep across all `Cargo.toml` files).
- [ ] Tracker row for SS-1 annotated with "Will populate `signer-registry::REGISTERED_METHODS` in Phase 2 Task 2.1."

**Testing Notes:**
- The current `is_empty()` assertion is intentionally a tripwire: when Phase 2 Task
  2.1 populates the array, the test fails until that PR also updates the assertion to
  `!is_empty()` + per-method checks.

---

### Issue 1.8a: Q3 determination spike (operator poll)

- **Points:** 1
- **Type:** spike
- **Priority:** P0
- **Blocked by:** 1.0 (AC annotates the tracker created by 1.0)
- **Blocks:** 1.8b (conditional — only if Outcome B), 2.3 (DVT-1 + CN-1 migration regression test path selection)
- **Scope:** 1 day (operator-response SLA bound: 2 days from kickoff before escalation)

**Description:**
Resolve PRD Open Question Q3 ("are there existing on-disk slashing DBs in production?")
**at the binary-decision level only**: produce an Outcome A vs Outcome B determination
and record it in `plan/remediation/tracker.md`. This is a pure spike — no fixture
capture, no code change. The fixture work, if needed, is Issue 1.8b.

Two outcomes are acceptable:
- **Outcome A — no production DBs.** Record in the tracker. Phase 2 Task 2.3's
  migration regression test runs against a synthetic fixture generated inline in Rust.
  Issue 1.8b is **skipped entirely**.
- **Outcome B — production DBs exist.** Record in the tracker, hand off to Issue 1.8b
  for the anonymised fixture capture.

The split exists because the operator-coordination time sink (polling, awaiting
responses, escalation) is independent of the technical work of capturing /
anonymising a fixture. Bundling them into one 3pt issue, as in earlier drafts, masked
this and gave the 2pt fixture-capture work no separate visibility.

**Implementation Notes:**
- Owning artifacts (modify):
  - `plan/remediation/tracker.md` — Q3 resolution recorded in the "Phase-1 pre-work"
    subsection from Issue 1.0. Entry must include: outcome (A or B), operators
    consulted (names/teams), dates of outreach and response, and any caveats.
- Approach:
  1. Poll the rs-vc operator owners / deployment configs (Slack, email, ops runbook,
     deployment-repo Helm/Compose values) to determine whether production
     deployments carry a populated `slashing.sqlite`.
  2. Inspect known production deployment configs (search the deployment repo / IaC
     for `slashing-db-path`, `--slashing-db`, `SLASHING_DB_PATH` env vars, persistent
     volume mounts for `*.sqlite`) as an independent secondary signal.
  3. **SLA:** 2 working days from initial operator outreach. If no operators have
     responded by end of business day 2, escalate to the project owner **with a
     recommendation to proceed under Outcome A** (synthetic fixture). The
     recommendation is not silent: it lands in the tracker with the rationale ("no
     operator response within SLA; deployment-config inspection found no populated
     `slashing.sqlite` path; proceeding synthetic"). This prevents the open
     question from degenerating into a perpetual blocker.
  4. If Outcome B (production DBs exist): hand off to 1.8b. No code change in this
     issue.
  5. If Outcome A (none): tracker entry calls out the synthetic-fixture path for
     Phase 2 Task 2.3 and names the operators whose negative responses confirm the
     outcome (or the escalation rationale if SLA-driven).
- Key decisions:
  - "No production DBs" is a valid outcome and is not a deferral; it just changes
    the Phase 2 test surface (synthetic in-Rust fixture instead of disk fixture).
  - The 2-day SLA is binding. Past the SLA, the recommendation defaults to Outcome A
    so the rest of Phase 1 does not stall.
- Watch out for:
  - Do NOT capture or commit any fixture file in this issue. That is 1.8b. Mixing
    the two re-bundles what the split was designed to separate.
  - Make sure the tracker entry distinguishes "operators positively confirmed no
    DBs" from "no operator response within SLA, defaulting to A" — they have
    different residual-risk profiles for Phase 2.

**Acceptance Criteria:**
- [ ] `plan/remediation/tracker.md` has a "Q3 resolution" entry naming:
      - the outcome (A or B);
      - the operators consulted (names / teams);
      - the dates of outreach and (where applicable) response;
      - any deployment-config inspection findings (e.g. "grep on the deployment repo
        found no `slashing-db-path` mount in any prod cluster");
      - whether the resolution came from a positive operator confirmation, an
        operator-confirmed disclosure of an on-disk DB, or an SLA-driven escalation
        default.
- [ ] If the SLA was breached, the tracker entry explicitly notes the escalation
      rationale and the recommendation to proceed under Outcome A.
- [ ] No code change to `crates/slashing/src/` or to `crates/slashing/tests/` in this
      issue (the spike is the deliverable; the fixture, if any, lands in 1.8b).
- [ ] Issue 1.8b is opened only if outcome is B; if outcome is A, 1.8b is closed as
      not-needed with the tracker entry as justification.
- [ ] Phase 2 Task 2.3's branch can reference the resolved Q3 state via the tracker
      and pick the right migration-test fixture shape (synthetic vs disk).

**Testing Notes:**
- No automated test. The deliverable is the tracker entry plus the binary outcome.

---

### Issue 1.8b: Anonymized pre-migration fixture capture (conditional on Outcome B)

- **Points:** 2
- **Type:** chore (test data)
- **Priority:** P0 (only if Outcome B; otherwise this issue is skipped)
- **Blocked by:** 1.0 (tracker AC), 1.8a (Q3 outcome decided)
- **Blocks:** 2.3 (DVT-1 + CN-1 migration regression test needs the fixture)
- **Scope:** 1-2 days
- **Skip condition:** **If 1.8a resolves Outcome A (no production DBs), this issue is
  skipped entirely.** The Phase 2 Task 2.3 migration test runs against a synthetic
  fixture generated inline in Rust. The tracker entry from 1.8a is the justification
  for closing this issue as not-needed.

**Description:**
Under Outcome B (1.8a confirmed production on-disk slashing DBs exist), capture an
**anonymised** snapshot of a real pre-migration `slashing.sqlite` and commit it to
`crates/slashing/tests/fixtures/migration_v1.sqlite`. Phase 2 Task 2.3's migration
regression test runs against this real fixture, giving the schema migration the
highest-stakes change in M1) coverage against actual on-disk data shapes operators
have generated in production.

The anonymisation pipeline is **deterministic sha256-based pubkey remap with
signing_root columns zeroed**, leaving slot/epoch/source/target intact (those are
the data the migration test needs to assert that the row-pair resolution table in
the architecture is honoured).

**Implementation Notes:**
- Files to create:
  - `crates/slashing/tests/fixtures/migration_v1.sqlite` — anonymised real snapshot.
  - `crates/slashing/tests/fixtures/README.md` — provenance: who captured it, when,
    what operator/cluster (anonymised label), and the exact anonymisation transform
    applied. Includes the deterministic remap formula
    (`sha256(operator_secret_seed || index)[..48]`) so a reviewer can verify the
    transform is reproducible.
  - `crates/slashing/tests/fixtures_smoke.rs` — smoke test that opens the fixture via
    `SlashingDb::open_at_path`, reads at least one block + one attestation row, and
    asserts the read succeeds without panic.
- Files to modify:
  - `plan/remediation/tracker.md` — append fixture provenance entry referencing the
    commit hash and the smoke test name.
- Anonymisation transform (the deterministic remap):
  1. Generate a one-time `operator_secret_seed: [u8; 32]` (random; stays on the
     anonymising operator's machine; **never committed**).
  2. For each distinct `validator_pubkey` row, compute
     `remapped = sha256(operator_secret_seed || index_in_db)[..48]`. The index is
     the row's stable ordinal in the source DB so the remap is deterministic *for
     the captured snapshot* (a re-capture by the same operator with the same seed
     gives the same fixture; without the seed nothing is reproducible).
  3. Zero every `signing_root` column (both block and attestation tables).
  4. Leave `slot`, `source_epoch`, `target_epoch`, `genesis_validators_root`,
     `client_cn` (audit column), and any other non-key columns **intact** — the
     migration test asserts row-pair resolution behaviour on these.
  5. Optionally remap `client_cn` to `cn-1`, `cn-2`, ... if production CN strings
     leak operator identity.
- Verification before commit:
  1. Re-open the anonymised fixture with the current `develop`'s
     `SlashingDb::open_at_path`; confirm it opens without error.
  2. Manually inspect a sample of rows: every `validator_pubkey` is 48 bytes of
     non-deterministic-looking hex; every `signing_root` is 32 zero bytes; slots
     and epochs match the source distribution.
  3. Run the smoke test in `fixtures_smoke.rs`.
- Key decisions:
  - Anonymisation is mandatory before commit, even if operators sign off — production
    pubkeys are operationally sensitive even when not tied to a name.
  - The `operator_secret_seed` is **never committed** — only the remapped output
    lands in the fixture. The README documents the *formula* without the *seed*.
  - The smoke test is the standing in-repo verification that the fixture remains
    valid as the slashing schema evolves; if a future schema change breaks
    open_at_path on the fixture, the smoke test catches it.
- Watch out for:
  - Do NOT commit a non-anonymised fixture under any circumstances. The
    pre-commit checklist in the README explicitly calls out "zero `signing_root`"
    and "no real pubkey appears in the fixture."
  - Do NOT commit the `operator_secret_seed`. If anonymisation is repeated, generate
    a fresh seed.
  - `SlashingDb::open_at_path` may run migrations on first open against modern code;
    capture the fixture by copying the file at the SQLite layer (not via
    `SlashingDb::export_interchange`) so the pre-migration schema is preserved
    bit-for-bit. The migration v1→v2 in Phase 2 Task 2.3 is exactly what we want to
    test *against this snapshot.*

**Acceptance Criteria:**
- [ ] `crates/slashing/tests/fixtures/migration_v1.sqlite` exists in the repo.
- [ ] `crates/slashing/tests/fixtures/README.md` documents:
      - provenance (anonymised operator label, capture date);
      - the deterministic remap formula
        (`sha256(operator_secret_seed || index)[..48]`);
      - the `signing_root` zeroing step;
      - the list of intact columns (`slot`, `source_epoch`, `target_epoch`,
        `genesis_validators_root`, audit `client_cn`);
      - the pre-commit anonymisation checklist (no real pubkey, no seed committed).
- [ ] `cargo test -p rvc-slashing --test fixtures_smoke` is green: the fixture opens
      via `SlashingDb::open_at_path` and at least one block + one attestation row are
      readable without panic.
- [ ] No real pubkey appears in the fixture (verified by grep against any known
      production pubkey prefix list available to the anonymising operator; the README
      records that this check was performed).
- [ ] The `operator_secret_seed` is **not** present in any committed file (verified
      by `git log -p` review).
- [ ] Tracker `plan/remediation/tracker.md` has a fixture-provenance entry referencing
      the commit hash for `migration_v1.sqlite` and naming the smoke test.
- [ ] Phase 2 Task 2.3's branch can reference this fixture for its migration
      regression test.
- [ ] No code change to `crates/slashing/src/` (the fixture is data only; the smoke
      test is the only Rust addition).

**Testing Notes:**
- The smoke test in `fixtures_smoke.rs` is the only automated test introduced by this
  issue. It is intentionally minimal — its job is to detect "the fixture has gone
  stale relative to current `SlashingDb` schema reading," not to test migration
  behaviour (that is Phase 2 Task 2.3's job).
- If Outcome A was the 1.8a result, this entire issue is skipped, the synthetic
  fixture used by Phase 2 Task 2.3 is generated inline in Rust, and no fixture file
  lands in the repo.

---

### Issue 1.9: Resolve PRD Q7 (B-1/T-1 actual landed state)

- **Points:** 2
- **Type:** spike
- **Priority:** P0
- **Blocked by:** 1.0 (AC annotates the tracker created by 1.0)
- **Blocks:** 4.3 (Phase 4 Task B-1 / T-1 / L-9 RED test)
- **Scope:** 1 day

**Description:**
Resolve PRD Open Question Q7 (Research R2) per project-plan Decision DL-9. The research
overview (line 25-32) reports that the SSZ block-publish fix infrastructure (B-1 / T-1
/ L-9) appears **partially landed** on `develop`: `ssz_deser.rs:190` already documents
the correct "kzg_proofs offset for BlockContents, bytes.len() for raw BeaconBlock"
semantics, but either one call site still uses `bytes.len()` or the `#[ignore]` tests
were never re-enabled. Writing a Phase 4 RED test against an already-green state wastes
a cycle and pollutes the tracker.

Run `cargo test -- --ignored` on the current `develop`, inspect the L-9-flagged tests
(`block-service/src/service.rs:2597-2622, 2641-2661`), and document the actual landed
state in the tracker so the Phase 4 Task 4.3 RED test is written against reality (e.g.
inverts a bug-pinning test per Research R3 KG-1 pattern).

**Implementation Notes:**
- Owning artifacts (modify):
  - `plan/remediation/tracker.md` — Q7 resolution recorded.
- Approach:
  1. Check out `develop` clean.
  2. Run `cargo test --workspace -- --ignored` and capture output.
  3. Run `cargo test -p rvc-block-service --test '*' -- --ignored` for narrowness.
  4. Inspect `crates/block-service/src/service.rs` around lines 2597-2622 and
     2641-2661 (per PRD §5 L-9 row) for the `#[ignore]` annotations and their stated
     reasons.
  5. Inspect `crates/beacon/src/ssz_deser.rs` around line 190 (per Research R2) for
     the `resolve_block_region_end` docstring and its call sites.
  6. Categorise the state as one of:
     - **State X1:** Bug fully unfixed; `#[ignore]` tests still fail when run.
     - **State X2:** Bug partially fixed; one call site uses correct offset, another
       still uses `bytes.len()`. `#[ignore]` tests may pass or fail depending.
     - **State X3:** Bug fully fixed; `#[ignore]` tests pass when un-ignored; comments
       are stale.
  7. Record the state + supporting line numbers + the `cargo test --ignored` output
     digest in the tracker.
  8. For Phase 4 Task 4.3: state X1 → ordinary RED test; state X2 → narrow RED test
     against the specific broken call site; state X3 → RED test inverts a bug-pinning
     test per Research R3 (test that *currently asserts the wrong behavior* gets
     flipped).
- Key decisions:
  - Resolution is **observational**, not a fix. No code change in this issue.
  - Tracker entry must include the exact `cargo test --ignored` command output (or a
    digest), so Phase 4 reviewer can reproduce.
- Watch out for:
  - `cargo test -- --ignored` runs ONLY ignored tests by default. Use the variant
    `cargo test -- --include-ignored` if all-tests-including-ignored is needed for
    cross-validation.
  - Do not edit the `#[ignore]` annotations in this issue — that is Phase 4's GREEN.

**Acceptance Criteria:**
- [ ] Tracker `plan/remediation/tracker.md` has a "Q7 resolution" entry naming the
      state (X1 / X2 / X3), the file:line evidence, and the `cargo test --ignored`
      result summary.
- [ ] No source-code file under `crates/` or `bin/` is modified.
- [ ] Phase 4 Task 4.3's branch can reference the resolved Q7 state via the tracker
      and pick the right RED-test shape from it.

**Testing Notes:**
- No new automated tests; the spike is the deliverable.

---

### Issue 1.10: Phase exit gate — FF-merge `prep/M1-shared` to `develop`

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Blocked by:** 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8a, 1.8b (1.8b only under Outcome B; under Outcome A it is closed as not-needed and not a blocker), 1.9
- **Blocks:** Phase 2 entry
- **Scope:** 1 day

**Description:**
Close Phase 1 by FF-merging the `prep/M1-shared` branch to `develop` per the project's
fast-forward-only policy. Validate all exit criteria, run the full four-gate suite plus
the two new standing gates, update the tracker.

**Implementation Notes:**
- Approach:
  1. Rebase `prep/M1-shared` onto the current `develop` tip.
  2. Run the full local validation:
     - `cargo build`
     - `cargo test --workspace` (all phases' new tests included)
     - `cargo test --test architecture_no_cycles` (standing gate)
     - `cargo clippy -- -D warnings`
     - `cargo fmt --check`
  3. Open a PR for reviewer Approve (PRD §6.5).
  4. Once approved, perform the merge: `git checkout develop && git merge --ff-only prep/M1-shared`.
  5. Push `develop` (this is the fast-forward update).
  6. Update tracker.md with the merge commit hash and flip per-issue tracker rows from
     `Open` to `Pre-work-landed`.
- Watch out for:
  - If the FF-merge fails because `develop` advanced (e.g. an unrelated hotfix), rebase
    and retry; never substitute `--no-ff` (CLAUDE.md memory: "Merges to develop must be
    fast-forward only").
  - The tracker is part of the merge commit — update it on the prep branch before
    the FF, not after.
- Key decisions:
  - Phase 1 is purely additive; if any existing test fails after the rebase, revert the
    offending Phase 1 commit rather than patching `develop`.

**Acceptance Criteria:**
- [ ] `prep/M1-shared` rebased onto current `develop` tip; no conflict markers remain.
- [ ] `cargo build`, `cargo test --workspace`, `cargo clippy -- -D warnings`, and
      `cargo fmt --check` all green on the rebased branch.
- [ ] `cargo test --test architecture_no_cycles` green.
- [ ] PR opened and a reviewer Approve recorded (PRD §6.5).
- [ ] `git merge --ff-only prep/M1-shared` succeeds on the local `develop` checkout
      (no merge commit produced).
- [ ] `develop` advances by the prep-branch commits; `git log --oneline develop`
      shows them.
- [ ] Tracker updated with the merge commit hash and each Phase-1 row flipped from
      `Open` to `Pre-work-landed`.
- [ ] All Phase 1 exit criteria from the Phase Overview section above are satisfied
      (cross-checked against the bullet list).
- [ ] Phase 2 entry can begin (the four traits + dep edge + architecture-no-cycles
      gate + signer-registry skeleton + Q3 resolution from 1.8a (+ optional 1.8b
      fixture under Outcome B) + Q7 resolution are all on `develop`).

**Testing Notes:**
- No new test code; this issue's deliverable is the verified merge.
- If CI is slower than the 30-minute assumption (project-plan §Assumptions #5), batch
  the standing-gate run as part of the four-gate suite rather than as a separate job to
  keep latency manageable.
