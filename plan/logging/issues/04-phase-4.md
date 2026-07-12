# Phase 4: Breadth — Gap Crates, Remaining Spans, Normalization

> Self-contained issue breakdown for **Phase 4 (Breadth)** of the rs-vc Structured Logging &
> Observability initiative. Maps to architecture rollout **Phase 3**; PRD scope **P1-1** (gap crates),
> **P1-2** (remaining span instrumentation), **P1-3** (normalize already-covered crates). A code-writer
> should be able to work entirely from this file plus `STANDARD.md`, the `crypto::logging` kit, and the
> existing `crypto/src/logging.rs:119` captured-subscriber test as the proven model.

## Phase Overview

- **Goal:** Bring the near-silent crates up to the landed standard, extend `#[instrument]` to the
  remaining hot-path entry points not covered in Phase 2, and normalize the already-well-covered crates
  for level/field/redaction conformance. Crucially, **eliminate every `rvc.`-prefixed span/field key
  workspace-wide** so OTLP dashboards group on the canonical keys (`slot`, not `rvc.slot`). This is
  mechanical, kit-backed, low-risk breadth measured against the rubric that landed in Phase 1.
- **Issue count:** 16 issues, 34 total points.
- **Estimated duration:** ~17 working days (single-stream default; one code-writer, sequenced by
  dependency).
- **Entry criteria:**
  - Phases 1–3 merged on `develop`. Specifically: `STANDARD.md` merged and referenced from `telemetry`
    `//!`; the `crypto::logging` kit (`TruncatedRoot`, `fields::*` consts, `Duty`, `new_request_id`,
    `record_display`/`record_debug`) merged and exported; Gates 1/2/3/4/6 live; both bins on
    `release_max_level_debug`; `crypto` and `signer` `rvc.`-prefixed sites already normalized in Phase 2.
  - Working tree green: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
    warnings`, `cargo nextest run --workspace`.
- **Exit criteria:**
  - [ ] Each gap crate has `info` milestones + `debug` internal state (+ `trace` where a hot path
        exists) — the PRD's near-silent-crate metric hits 100% (with the documented exceptions in the
        Assumptions below).
  - [ ] **No `rvc.`-prefixed field or span keys remain anywhere in the workspace** (verified by a
        repo-wide grep gate tightened in Issue 4.12b); `slot` (not `rvc.slot`) is the emitted attribute
        key everywhere.
  - [ ] `error`-vs-`warn` miscategorizations and duplicate log-and-return lines on the audited crates
        are fixed, with **no change** to `Result`/error-type/`?` control flow (Non-Goal).
  - [ ] Gate 5 (canonical-field-name conformance) wired as a captured-subscriber test in **advisory**
        mode, green over a curated hot-path event set; non-canonical keys flagged (not failing).
  - [ ] `rvc-keygen` mnemonic redaction remains proven (Gate 3) after its breadth additions — not even
        mnemonic length is logged.
  - [ ] Workspace fully green: `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets --
        -D warnings` + `cargo nextest run --workspace`. (**Never** `cargo test --workspace` — it
        deadlocks; `nextest` is the runner of record.)

### Standing invariant (every issue, at merge)

`cargo fmt --all -- --check` clean, `cargo clippy --workspace --all-targets -- -D warnings` green,
`cargo nextest run --workspace` green. TDD per CLAUDE.md (RED → GREEN → REFACTOR): for each logging
change, first write/extend the captured-subscriber test asserting the intended level + intended
canonical fields (and, on secret-adjacent crates, raw-secret-absent), watch it fail, then add the log
statement, then refactor. No change to runtime behavior, public APIs, `Result`/`thiserror`/`?` flow, or
the Prometheus/`:9101` metrics surface.

### Assumptions recorded for Phase 4 (verified against the tree at `develop`; task forbids asking)

The Phase 4 scope in the plan/architecture is written against the PRD's original "near-silent crate"
census. Code inspection at `develop` shows that census has **drifted** — several crates the PRD lists as
near-silent have since gained logging (often with `rvc.`-prefixed keys). Phase 4 is therefore
**more normalization and less greenfield** than the plan implies. The issues below reflect the verified
state. Specific corrections, each load-bearing:

1. **`doppelganger` is NOT greenfield** — `crates/doppelganger/src/service.rs` already has
   `info`/`debug`/`warn`/`error`, three `#[instrument]` spans, an `info_span!`, a `Span::current().record(...)`,
   and uses `TruncatedPubkey`. It carries `rvc.`-prefixed keys (`rvc.operation`,
   `rvc.doppelganger.validator_count`, `rvc.doppelganger.detected_count`, `rvc.epoch`, spans
   `rvc.doppelganger.check_validators` / `rvc.doppelganger.monitor` / `rvc.doppelganger.epoch_check`).
   → Treated as a **normalization** issue (4.7), not greenfield.
2. **`validator-store` and `propagator` are NOT greenfield** — both already have
   `info`/`debug`/`warn`/`error`/`trace`, `#[instrument]` spans (`rvc.validator_store.*`,
   `rvc.propagator.propagate`), and use `TruncatedPubkey`. They carry `rvc.`-prefixed keys
   (`rvc.count`, etc.). → Treated as **normalization + thin-spot fill** (4.6, 4.9), not greenfield.
3. **`timing` is light-but-present** — `crates/timing/src/timer.rs` already has `trace!` with good
   fields (`phase`, `slot`, `epoch`, `drift_ms`) and a hot path (`run_slot_loop`). It needs `info`
   milestones + a conformance pass, not from-scratch instrumentation (4.8).
4. **`signer-registry` has no meaningful logging surface** — it is a **dev-only** crate (ADR-010,
   pinned to zero production out-edges by Gate 6) consisting solely of compile-time `const` tables
   consumed by enumeration tests. There is no runtime/hot path to instrument. → Issue 4.5 documents this
   disposition (a `//!` standard reference only); we do **not** invent `info`/`debug` for a const table.
   This is an honest deviation from the PRD's "100% of near-silent crates get `info`+`debug`" metric and
   is flagged as such.
5. **`eth-types` is zero-out-edge constrained** — pinned to zero workspace-internal out-edges by Gate 6,
   so it **cannot** import `crypto`'s kit (`TruncatedRoot`/`fields`). Its instrumentation must use bare
   `tracing` field literals (`slot`, etc., typed directly) and the existing `tracing`/`tracing-test`
   deps it already has. It is mostly pure SSZ/data types with one `warn!` (`insecure.rs:70`); its
   breadth is narrow (4.4).
6. **The namespace normalization is workspace-wide and large** — `rvc.`-prefixed keys appear in **~30+
   files** beyond the `signer`/`crypto` sites Phase 2 already fixed: the orchestrator (`crates/rvc`,
   ~42 in `coordinator.rs` alone), `beacon` (~29 in `client.rs`), `grpc-signer` (~31), `bn-manager`
   (~26), `slashing` (~17), plus the gap crates' own prefixes. Phase 4 owns all of these. They are
   split into per-crate normalization issues (4.6–4.11, with the high-risk tier as 4.10a/b/c and the
   orchestrator/bins as 4.12a/4.12b) so each is a focused, reviewable diff, with a final repo-wide grep
   gate (4.12b) proving zero remain.
7. **Gate 5 stays advisory** in Phase 4 (escalates to blocking in Phase 5) — wiring it before the
   `rvc.`-prefixed sites are normalized would fail the workspace on the very sites this phase fixes.
   Sequenced as the last code issue (4.12b normalization gate → 4.13 Gate 5 advisory).
8. **`grpc-signer` is added to the normalization set.** The plan's P1-3 list does not name it, but it
   carries ~31 `rvc.`-prefixed occurrences and the exit criterion is "no `rvc.` anywhere." Folded into
   the orchestrator-adjacent normalization (4.11) so the zero-`rvc.` invariant is actually achievable.
9. **`secret-provider` `rvc.` sites** (`gcp.rs`, `key_source_manager.rs`) are the high-risk
   normalization issue 4.10c and re-run under Gate 3 (it is a high-risk crate). Phase 2 signed off its
   *redaction*; Phase 4 normalizes its *field names*.

---

## Phase Summary

| Issue | Title | Points | Blocked by | Scope | Files |
|-------|-------|--------|------------|-------|-------|
| 4.1 | Gate 5 conformance helper (advisory infra, no wiring) | 2 | — | 1-2 days | `crates/crypto/src/logging.rs` (or `fields.rs`), `crypto/src/logging/conformance.rs` (new) |
| 4.2 | Curated canonical-field event set + namespace-grep tooling | 2 | 4.1 | 1-2 days | `crates/architecture-tests/tests/field_name_conformance.rs` (new), `tests/no_rvc_prefix.rs` (new) |
| 4.3 | `rvc-keygen` breadth (`info`/`debug`) preserving mnemonic redaction | 3 | — | 2 days | `bin/rvc-keygen/src/{new_mnemonic,existing_mnemonic,deposit,verify,main}.rs`, `bin/rvc-keygen/Cargo.toml` |
| 4.4 | `eth-types` breadth (zero-out-edge constrained) | 1 | — | 1 day | `crates/eth-types/src/{insecure,domains,fork}.rs` |
| 4.5 | `signer-registry` disposition (dev-only, documented N/A) | 1 | — | 0.5 day | `crates/signer-registry/src/lib.rs` |
| 4.6 | `validator-store` normalize + thin-spot `debug` | 2 | 4.2 | 1-2 days | `crates/validator-store/src/store.rs` |
| 4.7 | `doppelganger` namespace normalize + `record_*` helpers | 3 | 4.2 | 2 days | `crates/doppelganger/src/service.rs` |
| 4.8 | `timing` `info` milestones + conformance | 2 | 4.2 | 1-2 days | `crates/timing/src/{timer,clock}.rs` |
| 4.9 | `propagator` + `metrics` breadth/normalize | 2 | 4.2 | 1-2 days | `crates/propagator/src/lib.rs`, `crates/metrics/src/server.rs` |
| 4.10a | High-risk normalize: `bn-manager` | 2 | 4.2 | 1-2 days | `crates/bn-manager/src/manager.rs` |
| 4.10b | High-risk normalize: `slashing` | 2 | 4.2 | 1-2 days | `crates/slashing/src/{db,audit}.rs` |
| 4.10c | High-risk normalize: `secret-provider` | 2 | 4.2 | 1-2 days | `crates/secret-provider/src/{gcp,key_source_manager}.rs` |
| 4.11 | `beacon` + `grpc-signer` namespace normalize | 3 | 4.2 | 2 days | `crates/beacon/src/client.rs`, `crates/grpc-signer/src/client.rs` |
| 4.12a | Orchestrator (`crates/rvc`) namespace normalize + test blocks | 3 | 4.6–4.11 | 2 days | `crates/rvc/src/orchestrator/*.rs`, `crates/rvc/src/startup.rs`, `crates/rvc/src/orchestrator/coordinator.rs` test block (`:3729+`) |
| 4.12b | Bins normalize + tighten zero-`rvc.` grep gate to empty | 2 | 4.12a | 1-2 days | `bin/rvc/src/main.rs`, `bin/rvc-signer/src/*.rs`, `crates/architecture-tests/tests/no_rvc_prefix.rs` |
| 4.13 | Wire Gate 5 advisory + remaining hot `#[instrument]` sweep | 2 | 4.2, 4.10a/b/c, 4.11, 4.12a, 4.12b | 1-2 days | `crates/architecture-tests/tests/field_name_conformance.rs`, remaining hot-path entry points |
| **Total** | | **34** | | | |

## Phase Execution Plan

Single-stream: one code-writer, issues in dependency order; each day-slot is one day of work. 4.1→4.2
build the advisory/grep tooling first so every normalization issue can self-check. 4.3/4.4/4.5 are
independent greenfield/disposition work that can be slotted any time (shown early to front-load the
low-risk, no-dependency items). The normalization issues (4.6–4.11, including the high-risk tier
4.10a/b/c) all depend on 4.2's grep tooling and curated set; 4.12a normalizes the orchestrator and
4.12b normalizes the bins and tightens the workspace-wide grep gate to empty (the load-bearing exit
criterion), so both depend on all prior normalization; 4.13 wires Gate 5 last (after the field set is
normalized and the gate is green).

| Day | Issue |
|-----|-------|
| 1 | 4.1 Gate 5 conformance helper |
| 2 | 4.2 Curated event set + grep tooling |
| 3 | 4.3 `rvc-keygen` breadth |
| 4 | 4.3 cont. |
| 5 | 4.4 `eth-types` breadth + 4.5 `signer-registry` disposition |
| 6 | 4.6 `validator-store` |
| 7 | 4.7 `doppelganger` normalize |
| 8 | 4.7 cont. |
| 9 | 4.8 `timing` milestones |
| 10 | 4.9 `propagator` + `metrics` |
| 11 | 4.10a high-risk normalize (`bn-manager`) |
| 12 | 4.10b high-risk normalize (`slashing`) |
| 13 | 4.10c high-risk normalize (`secret-provider`) |
| 14 | 4.11 `beacon` + `grpc-signer` |
| 15 | 4.12a orchestrator (`crates/rvc`) + test blocks |
| 16 | 4.12b bins + tighten grep gate to empty |
| 17 | 4.13 Gate 5 advisory + hot-`#[instrument]` sweep |

---

## Issues

### Issue 4.1: Gate 5 conformance helper (advisory infrastructure, no wiring yet)

- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** none (consumes the Phase 1 `crypto::logging::fields` consts)
- **Blocks:** 4.2, 4.13
- **Scope:** 1-2 days

**Description:**
Build the reusable helper that Gate 5 (canonical-field-name conformance) uses: given a captured set of
emitted field keys, return the set of keys that are **not** present in the canonical
`crypto::logging::fields` registry. This is the engine; wiring it to a curated event set is 4.2/4.13.
Keep it a pure function so it is unit-testable without a subscriber.

**Implementation Notes:**
- Files likely affected: new `crates/crypto/src/logging/conformance.rs` (or a `conformance` submodule in
  the existing `crypto/src/logging.rs`), exported from `crypto::logging`.
- Approach: expose `pub fn non_canonical_keys<'a>(observed: impl IntoIterator<Item = &'a str>) ->
  Vec<&'a str>` that diffs against a `const CANONICAL: &[&str]` derived from the Phase 1 `fields::*`
  consts (`SLOT`, `EPOCH`, `VALIDATOR_INDEX`, `PUBKEY`, `DUTY`, `REQUEST_ID`, `COMMITTEE_INDEX`,
  `SUBCOMMITTEE_INDEX`, `BN_URL`, `HEAD`, `BLOCK_ROOT`, `TIME_INTO_SLOT`). Build `CANONICAL` from the
  consts so it cannot drift from the registry.
- Allow a small set of legitimately-non-registry keys that the standard permits on events
  (e.g. `count`, `error`, `phase`, `otel.kind`, the `http.*` OTel-semantic names beacon uses); model
  these as an explicit, documented `ADVISORY_ALLOW` list so the diff is meaningful rather than noisy.
- This is library code (advisory), not a gate yet — it must not fail any build on its own.
- Watch out for: R1 — this is pure data, no `Display`/formatting work; no `#[instrument]` here.

**Acceptance Criteria:**
- [ ] `non_canonical_keys(["slot","epoch"])` returns empty; `non_canonical_keys(["rvc.slot","val_idx"])`
      returns both, in input order.
- [ ] `CANONICAL` is built from the `fields::*` consts (a unit test asserts every `fields::*` const is
      contained in `CANONICAL`, so adding a const automatically covers it).
- [ ] The `ADVISORY_ALLOW` list is documented inline with a one-line rationale per entry.
- [ ] Unit tests cover: all-canonical, all-non-canonical, mixed, and allow-listed (`count` → not
      flagged) cases.
- [ ] `cargo nextest run -p crypto` green; workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- Pure unit tests in a `#[cfg(test)]` module; no subscriber needed. RED first: write the diff assertions
  against a not-yet-existing function.

---

### Issue 4.2: Curated canonical-field event set + workspace `rvc.`-prefix grep tooling

- **Points:** 2
- **Type:** feature / chore
- **Priority:** P1
- **Blocked by:** 4.1
- **Blocks:** 4.6, 4.7, 4.8, 4.9, 4.10a, 4.10b, 4.10c, 4.11, 4.12a (every normalization issue self-checks against this)
- **Scope:** 1-2 days

**Description:**
Create the two pieces of tooling the rest of the phase is measured by: (a) a placeholder/seed
captured-subscriber conformance test harness in `architecture-tests` that runs `non_canonical_keys`
over a curated set of representative hot-path events (initially small; grown per normalization issue),
and (b) a workspace-wide grep gate test asserting **no `rvc.`-prefixed span/field keys remain** in
production source. Both ride `nextest`. The grep gate starts **allow-listed** to the not-yet-normalized
crates and is tightened to zero by Issue 4.12.

**Implementation Notes:**
- Files likely affected: new `crates/architecture-tests/tests/field_name_conformance.rs` (advisory) and
  new `crates/architecture-tests/tests/no_rvc_prefix.rs` (the grep gate).
- Approach for the grep gate: walk `crates/*/src/**.rs` + `bin/*/src/**.rs` (exclude `#[cfg(test)]`
  blocks and `tests/` where the prefix appears only in assertions; simplest robust approach is to scan
  source files and ignore lines inside test modules, or scan only non-test files). Match the regex
  `rvc\.[a-z_][a-z0-9_.]*` used as a `tracing` span name or field key. Maintain an explicit
  `KNOWN_REMAINING: &[&str]` allow-list of files still carrying the prefix (every crate not yet
  normalized) so the gate is green now and tightening it is a visible diff per issue.
- Approach for the advisory conformance test: capture events with `tracing-test` (already a dev-dep) or
  a small captured-subscriber `Layer`, collect field keys, call `non_canonical_keys`, and `eprintln!`
  (advisory — **do not** `assert!`) any flagged keys. 4.13 grows the curated set and keeps it advisory.
- Watch out for: the prefix also appears in `Cargo.toml`-style `rvc.workspace` matches and in test
  assertion strings — the gate must scope to production `*.rs` source and not trip on those.

**Acceptance Criteria:**
- [ ] `no_rvc_prefix.rs` passes today with `KNOWN_REMAINING` listing exactly the files that currently
      carry `rvc.`-prefixed keys (enumerated, not a blanket skip).
- [ ] Removing a file from `KNOWN_REMAINING` while it still contains an `rvc.` key makes the test
      **fail** (proven by a temporary local check in review).
- [ ] `field_name_conformance.rs` runs, emits advisory output for any flagged key, and never fails the
      build (advisory mode).
- [ ] Both tests run under `cargo nextest run -p architecture-tests`; workspace green.

**Testing Notes:**
- The grep gate is itself the test. Verify the regex against `crates/rvc/src/orchestrator/coordinator.rs`
  (~42 hits) and confirm test-assertion lines (e.g. `coordinator.rs:3729+`) are excluded.

---

### Issue 4.3: `rvc-keygen` breadth (`info`/`debug`) preserving mnemonic redaction

- **Points:** 3
- **Type:** feature
- **Priority:** P1 (high-risk crate — mnemonic rule)
- **Blocked by:** none (Phase 2 already proved its redaction via Gate 3)
- **Blocks:** —
- **Scope:** 2 days

**Description:**
`rvc-keygen` has **0 log statements** today. Add operator-facing `info` milestones (mnemonic generated,
keystore written, deposit data produced, verification passed/failed) and developer `debug` internal
state across the keygen subcommands — **without ever logging the mnemonic, seed, or any secret, not even
its length**. This is the breadth half of `rvc-keygen`; its high-risk redaction sign-off was pulled
forward into Phase 2 and must remain intact.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/new_mnemonic.rs`, `existing_mnemonic.rs`, `deposit.rs`,
  `verify.rs`, `main.rs` (all touch mnemonics — verified). Add `tracing` to `bin/rvc-keygen/Cargo.toml`
  if not already a dep, and `tracing-test` as a dev-dep for the Gate 3 test.
- Approach: `info!` at completed milestones with non-secret fields only (counts, output paths via
  `%path.display()`, derived `pubkey` via `crypto::logging::TruncatedPubkey`). `debug!` for step
  boundaries (derivation index, network selected). The bare `bip39::Mnemonic` type **is a sink** (it
  `Display`s to the phrase) — never pass it, a reference to it, or its word count to a macro.
- Key decisions: no `#[instrument]` that auto-captures a `Mnemonic`/seed arg — use `skip_all` + explicit
  non-secret `fields(...)` if instrumenting a fn that takes secret material. Pubkeys truncated even at
  `debug`/`trace`.
- Watch out for: `verify.rs` may format derived keys — ensure only truncated pubkeys reach a macro.

**Acceptance Criteria:**
- [ ] Each keygen subcommand emits at least one `info` milestone on success and a `warn`/`error` on the
      relevant failure, fields canonical (`pubkey` truncated, paths via `%display`).
- [ ] **Gate 3:** a `#[tracing_test::traced_test]` test runs mnemonic generation + keystore write at
      `trace` and asserts the emitted output does **NOT** contain the mnemonic phrase, any constituent
      word, or the seed hex — and contains only the truncated pubkey / metadata. (Model:
      `crypto/src/logging.rs:119`.)
- [ ] No `#[instrument]` auto-captures a `Mnemonic`/`SecretKey`/seed argument (`skip_all` enforced;
      Gate 1 clippy sinks stay green).
- [ ] Mnemonic length / word count is **never** logged at any level.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- This is the one breadth issue where the captured-subscriber redaction test is the *primary*
  deliverable, not a nicety. Reuse the Phase 2 high-risk-crate test pattern.

---

### Issue 4.4: `eth-types` breadth (zero-out-edge constrained)

- **Points:** 1
- **Type:** feature
- **Priority:** P2
- **Blocked by:** none
- **Blocks:** —
- **Scope:** 1 day

**Description:**
`eth-types` has a single `warn!` (`insecure.rs:70`) and is otherwise silent. It is pinned to **zero
workspace-internal out-edges** by Gate 6, so it **cannot** use `crypto`'s kit. Add the few `debug`/`trace`
statements that have operator/developer value on the data-construction paths (domain computation, fork
selection) using bare `tracing` field literals only. This crate is mostly pure SSZ/serde types with no
async hot path, so its breadth is deliberately narrow — this is an honest, bounded pass, not a forced
`info` heartbeat.

**Implementation Notes:**
- Files likely affected: `crates/eth-types/src/insecure.rs` (review the existing `warn!` for canonical
  shape), `domains.rs`, `fork.rs` (the two computation paths with diagnostic value).
- Approach: `trace!(slot, epoch, "computed domain")`-style lines with **literal** canonical field idents
  (`slot`, `epoch`) — the macro requires idents anyway, and `eth-types` cannot import `fields::*`. No
  `TruncatedRoot` available here; if a root must appear, log nothing rather than the full root (it
  cannot truncate without `crypto`).
- Key decisions: do **not** add a `crypto`/`telemetry`/`uuid` dependency — Gate 6 forbids it and would
  fail. `tracing` + `tracing-test` are already present (verified in `eth-types/Cargo.toml`).
- Watch out for: adding any internal dep here breaks the `ZERO_OUT_EDGE_IF_PRESENT` pin — Gate 6 fails.

**Acceptance Criteria:**
- [ ] At least the domain/fork computation paths carry a `debug`/`trace` line with canonical literal
      field keys (`slot`/`epoch`/`fork_version`), no full roots emitted.
- [ ] **Gate 6 green:** `cargo nextest run -p architecture-tests` confirms `rvc-eth-types` still has zero
      production out-edges (no new dep added).
- [ ] The existing `insecure.rs` `warn!` conforms to the standard (level appropriate, message stable).
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- A `#[tracing_test::traced_test]` test (the crate already has the dev-dep) asserting one `trace` line
  fires at the intended level with the intended field is sufficient.

---

### Issue 4.5: `signer-registry` disposition (dev-only crate — documented N/A)

- **Points:** 1
- **Type:** chore
- **Priority:** P2
- **Blocked by:** none
- **Blocks:** —
- **Scope:** 0.5 day

**Description:**
The PRD lists `signer-registry` among the near-silent crates to bring up to standard. Inspection shows
it is a **dev-only** crate (ADR-010, pinned to zero production out-edges by Gate 6) containing only
compile-time `const` tables (`REGISTERED_METHODS`, `SIGNING_GATE_METHODS`) consumed by enumeration
tests. There is **no runtime or hot path to instrument** — adding `info`/`debug` to a const table would
be noise. This issue records that disposition explicitly (so the deviation from the PRD's 100% metric is
deliberate and reviewable) and adds only a `//!` reference to `STANDARD.md` noting why this crate is out
of the logging-breadth scope.

**Implementation Notes:**
- Files likely affected: `crates/signer-registry/src/lib.rs` (module doc only).
- Approach: extend the existing `//!` header with a one-paragraph note: "DEV-ONLY const registry; no
  runtime logging surface; intentionally excluded from logging-breadth per Phase 4 disposition. See
  `plan/logging/STANDARD.md`." Do **not** add a `tracing` dependency.
- Key decisions: this is the honest "the metric does not literally apply here" call the architecture
  flags as the one under-enforced area; documenting it is the deliverable.
- Watch out for: do not add any dependency — the crate must stay dependency-free (Gate 6 pin).

**Acceptance Criteria:**
- [ ] `signer-registry/src/lib.rs` `//!` doc references `STANDARD.md` and states the dev-only / no-runtime
      disposition.
- [ ] No new dependency added; **Gate 6 green** (`rvc-signer-registry` still zero out-edges).
- [ ] The Phase 4 summary (and `00-summary.md` if present) notes `signer-registry` as a documented
      exception to the "100% of near-silent crates" metric.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- No runtime test; the deliverable is documentation + the Gate 6 pin staying green.

---

### Issue 4.6: `validator-store` normalize + thin-spot `debug`

- **Points:** 2
- **Type:** chore / feature
- **Priority:** P1
- **Blocked by:** 4.2
- **Blocks:** 4.12a (its file leaves `KNOWN_REMAINING`)
- **Scope:** 1-2 days

**Description:**
`validator-store/src/store.rs` already logs well (`info`/`warn`/`trace`, `TruncatedPubkey`) but carries
`rvc.`-prefixed span names (`rvc.validator_store.load_from_config`/`list_enabled_pubkeys`/`save_config`/
`reload_config`) and a `rvc.count`-style field. Normalize the span names to the canonical convention
(drop the `rvc.` prefix; keep a stable greppable `name`), rename non-canonical field keys to the
registry, and fill the one or two `debug` decision points that are currently thin (e.g. effective-config
resolution).

**Implementation Notes:**
- Files likely affected: `crates/validator-store/src/store.rs` (the `#[instrument(name="rvc.validator_store.*")]`
  at `:87`, `:206`, `:298`, `:354`; `info!`/`warn!`/`trace!` sites at `:114`, `:164`, `:182`, `:237`,
  `:239`, `:286`, `:350`, `:361`, `:365`, `:405`).
- Approach: rename `name = "rvc.validator_store.X"` → `name = "validator_store.X"` (or the unprefixed
  form `STANDARD.md` settles on — match whatever Phase 2 used for `signer`'s renamed spans). Replace any
  `rvc.`-prefixed field key (e.g. `rvc.count`) with the canonical `count`/registry key. Pubkeys already
  truncated — keep.
- Key decisions: span *names* are not in the field registry, but the exit criterion is "no `rvc.`
  anywhere"; mirror the Phase 2 `signer` rename convention exactly so the workspace is internally
  consistent.
- Watch out for: do not change `Result`/error flow; the `warn!` on parse error (`:361`/`:365`) stays
  `warn` (it degrades-but-progresses by keeping the old config).

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed span name or field key remains in `store.rs`; its entry is removed from
      `no_rvc_prefix.rs` `KNOWN_REMAINING` and the gate stays green.
- [ ] Captured-subscriber test asserts the (renamed) `load_from_config` span and the `validator enabled`/
      `validator disabled` events fire at intended levels with canonical fields (`pubkey` truncated).
- [ ] The thin `debug` decision point (effective-config resolution) is added with canonical fields.
- [ ] No change to `Result`/error-type/`?` flow.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- `tracing-test` is not yet a dev-dep here — add it (`tracing-test = { workspace = true, features = ["no-env-filter"] }`)
  to write the Gate-3-style assertion.

---

### Issue 4.7: `doppelganger` namespace normalize + `record_*` helper adoption

- **Points:** 3
- **Type:** chore / feature
- **Priority:** P1
- **Blocked by:** 4.2
- **Blocks:** 4.12a
- **Scope:** 2 days

**Description:**
`doppelganger/src/service.rs` is well-instrumented but entirely `rvc.`-prefixed: spans
`rvc.doppelganger.check_validators` (`:105`), `rvc.doppelganger.monitor` (`:165`),
`rvc.doppelganger.epoch_check` (`:205`); fields `rvc.operation`, `rvc.doppelganger.validator_count`,
`rvc.doppelganger.detected_count`, `rvc.epoch`; and a raw `Span::current().record("rvc.doppelganger.detected_count", …)`
(`:255`). Normalize all of these to the canonical registry, replace the raw `record()` with the Phase 1
`crypto::logging::record_display`/`record_debug` helper (and declare the late-bound field `field::Empty`
at span creation so it cannot vanish), and confirm levels.

**Implementation Notes:**
- Files likely affected: `crates/doppelganger/src/service.rs` only (verified — `forward_window.rs` has a
  single unrelated `tracing` import).
- Approach: rename spans to the unprefixed convention; map `rvc.epoch` → `epoch`,
  `rvc.doppelganger.validator_count`/`detected_count` → a canonical `count`/registry key or a
  documented domain-specific event field (not a `rvc.`-prefixed one). The `:255`
  `Span::current().record("rvc.doppelganger.detected_count", detected.len() as u64)` becomes
  `record_display`/`record_debug` against a field declared `Empty` in the `#[instrument(fields(...))]`
  on `run_monitoring`. Keep `TruncatedPubkey` on every `pubkey`.
- Key decisions: this is the canonical demonstration of the late-bound-field foot-gun the kit exists to
  fix — declare `Empty` + use the helper, not a raw `record()`.
- Watch out for: R1 — `fields(rvc.doppelganger.validator_count = pubkeys.len())` is an eager `len()`
  call on a `#[instrument]` field; `len()` is a cheap `usize` so it is R1-safe, but keep it a scalar
  (no formatting) when renaming.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed span/field key remains in `service.rs`; its entry leaves `KNOWN_REMAINING`,
      gate green.
- [ ] The late-bound detected-count field is declared `field::Empty` at span creation and filled via
      `crypto::logging::record_display`/`record_debug` (not a raw `Span::record`).
- [ ] **Gate 3:** captured-subscriber test asserts the late-bound count field **is present** on the
      emitted `monitor` span (proving the helper + `Empty` declaration work), and that `check_validators`
      events carry canonical `pubkey` (truncated) + `epoch`.
- [ ] The `doppelganger detected` line stays `error` (an intended safety action — detection — fired);
      `warn` for the no-index skip; conforms to the `error`-iff-intended-action-incomplete rule.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green (`doppelganger` already has `tracing-test`).

**Testing Notes:**
- The existing 30+ unit tests in `service.rs` must stay green; add the captured-subscriber assertions as
  new `#[tracing_test::traced_test]` tests.

---

### Issue 4.8: `timing` `info` milestones + conformance pass

- **Points:** 2
- **Type:** feature / chore
- **Priority:** P1
- **Blocked by:** 4.2
- **Blocks:** 4.12a
- **Scope:** 1-2 days

**Description:**
`timing/src/timer.rs` already has good `trace!` on the hot `run_slot_loop`/`wait_*` paths (`phase`,
`slot`, `epoch`, `drift_ms`). It lacks `info` milestones and is not measured against the standard. Add
the operator-facing milestone(s) appropriate to a timing crate (e.g. a once-per-slot liveness/`time_into_slot`
signal at `info`, per the architecture's heartbeat shape), confirm the existing `trace` fields are
canonical, and ensure the hot `run_slot_loop` stays zero-cost when verbose is disabled (no eager work in
the loop's `trace!` field expressions).

**Implementation Notes:**
- Files likely affected: `crates/timing/src/timer.rs` (the `run_slot_loop` at `:100`, the `trace!` sites
  at `:70`, `:86`, `:94`, `:116`; the `record_attestation_delay`/`update_slot_metrics` helpers), and
  `clock.rs` (2 existing tracing references) for conformance.
- Approach: add an `info!(slot, time_into_slot = …, "slot tick")`-style milestone gated to once per slot
  (the architecture explicitly lists an optional once-per-slot tick under `info`). The `time_into_slot`
  field is in the registry. Keep the per-tick `trace!` as-is (it is already correct). `timing` has no
  `crypto` dep (and adding one is undesirable — it is a low crate), so use literal canonical field idents.
- Key decisions: do **not** touch the Prometheus gauges/histograms or the `metrics::REGISTRY` wiring —
  that is a Non-Goal; this is log events only. The `info` tick must be genuinely once-per-slot, not
  per-poll (it scales with slots, which is bounded, not with validator count).
- Watch out for: R1/P0-6 — the loop's `trace!(slot, epoch, "slot loop tick")` fields are `Copy` scalars,
  already safe; keep them scalar. Do not introduce a `format!` in the loop.

**Acceptance Criteria:**
- [ ] `run_slot_loop` emits an `info` once-per-slot milestone carrying `slot` (+ `time_into_slot` where
      computable) — bounded volume, not per-poll.
- [ ] Existing `trace!` fields confirmed canonical (`slot`/`epoch`/`phase`); any `rvc.`-prefixed key (if
      present) removed and the file leaves `KNOWN_REMAINING`.
- [ ] Captured-subscriber test asserts the `info` tick fires at `info` with `slot`, and a hot-loop
      `trace` fires at `trace` with `slot`/`epoch`.
- [ ] No change to the Prometheus metrics surface (`:9101`/`REGISTRY` untouched).
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- Add `tracing-test` as a dev-dep to `timing` (not currently present). Use `MockSlotClock` (already in
  `clock.rs` tests) to drive a deterministic slot.

---

### Issue 4.9: `propagator` + `metrics` breadth/normalize

- **Points:** 2
- **Type:** feature / chore
- **Priority:** P1
- **Blocked by:** 4.2
- **Blocks:** 4.12a
- **Scope:** 1-2 days

**Description:**
Two small crates in one focused issue (logically related: both are thin service/utility crates with a
handful of sites). `propagator/src/lib.rs` already has `info`/`debug`/`warn`/`error` + an
`#[instrument(name="rvc.propagator.propagate", fields(rvc.count))]` — normalize the span name and the
`rvc.count` field, and confirm the partial-success/`warn` vs complete-failure/`error` categorization.
`metrics/src/server.rs` has 3 tracing references — bring the metrics-server lifecycle (listening,
serving error) to `info`/`error` milestones with canonical fields. **Neither touches the Prometheus
counters/registry or the `:9101` endpoint behavior** — log events only (Non-Goal guard).

**Implementation Notes:**
- Files likely affected: `crates/propagator/src/lib.rs` (`#[instrument]` at `:89`, sites at `:105`,
  `:109`, `:115`, `:132`, `:145`, `:161`, `:169`); `crates/metrics/src/server.rs` (3 existing tracing
  refs).
- Approach (propagator): rename `name = "rvc.propagator.propagate"` → unprefixed; `fields(rvc.count)` →
  `fields(count = …)` (or declare `Empty` + record). `batch_slot` already logged with `slot = %batch_slot`
  — confirm `slot` is the canonical key. Categorization: complete failure → `error`; partial success →
  `warn`; full success → `info` (already roughly there).
- Approach (metrics): `info!` when the metrics server binds/listens (a milestone), `error!` on bind/serve
  failure (an intended action did not complete). Do not log per-scrape.
- Key decisions: `propagator` and `metrics` both lack a `crypto` dep; `propagator` depends on
  `bn-manager`/`metrics` only, `metrics` on `axum`/`prometheus` only — use literal canonical field idents,
  do not add `crypto`.
- Watch out for: the metrics crate's whole point is the Prometheus surface — be surgical, only the
  server *lifecycle* gets log events; counters are untouched.

**Acceptance Criteria:**
- [ ] `propagator`: span renamed, `rvc.count` → canonical `count`; file leaves `KNOWN_REMAINING`;
      partial-vs-complete failure categorization confirmed (`warn` vs `error`).
- [ ] `metrics`: server bind/listen `info` milestone + bind/serve-failure `error`; no per-scrape logging;
      no `rvc.` keys.
- [ ] Captured-subscriber test in `propagator` asserts the `propagate` span fires with canonical
      `count`/`slot`; a `metrics` test asserts the listen milestone at `info`.
- [ ] Prometheus registry / `:9101` behavior unchanged (no metrics added/removed).
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- `propagator` has no `tracing-test` dev-dep — add it. `metrics` has `tower` as a dev-dep already; add
  `tracing-test` for the lifecycle assertion.

---

### Issue 4.10a: High-risk normalize — `bn-manager`

- **Points:** 2
- **Type:** chore
- **Priority:** P0-adjacent (high-risk crate; redaction must stay proven)
- **Blocked by:** 4.2
- **Blocks:** 4.12a, 4.13
- **Scope:** 1-2 days

**Description:**
Normalize the `rvc.`-prefixed field/span keys in `bn-manager/src/manager.rs` (~26 `rvc.` hits — endpoint
selection, failover) to the canonical registry, keeping `bn_url` redacted. This is one of three
independently-shippable high-risk normalization issues (split from the former bundled 4.10 so each crate
carries its own `tracing-test` setup and its own Gate 3 redaction re-proof). No secret material in any
new or renamed line.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/manager.rs`.
- Approach: rename all `rvc.`-prefixed span names and field keys to the canonical registry
  (`slot`/`epoch`/`pubkey`/`validator_index`/`bn_url`/`request_id`). Failover stays `warn` with
  `bn_url = %RedactedUrl(...)`; all-nodes-unreachable is the `error`-iff-intended-action-did-not-complete
  case — confirm `error`/`warn` per the rule without touching `Result` flow.
- Key decisions: confirm `bn-manager` depends on `crypto` (it logs `bn_url`); if so use `RedactedUrl` and
  the `fields::*` consts.
- Watch out for: any URL with credentials must go through `RedactedUrl` — never log a raw `user:pass@`
  endpoint at any level.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed keys remain in `manager.rs`; its entry leaves `KNOWN_REMAINING`; gate green.
- [ ] **Gate 3 green:** a captured-subscriber test asserts `bn-manager` failover logs `bn_url` redacted
      (no `user:pass@`) with canonical fields.
- [ ] All-nodes-unreachable categorized `error`; transient retry/failover `warn` — no `Result`/`?`/
      error-type changes.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green; existing bn-manager tests green.

**Testing Notes:**
- Add `tracing-test` as a dev-dep to `bn-manager` if absent. RED first: assert the redacted `bn_url`
  against the renamed key before the rename lands.

---

### Issue 4.10b: High-risk normalize — `slashing`

- **Points:** 2
- **Type:** chore
- **Priority:** P0-adjacent (high-risk crate; redaction must stay proven)
- **Blocked by:** 4.2
- **Blocks:** 4.12a, 4.13
- **Scope:** 1-2 days

**Description:**
Normalize the `rvc.`-prefixed field/span keys in `slashing/src/db.rs` (~17) + `audit.rs` (1) — the
slashing check/decision/DB paths — to the canonical registry, and re-run the high-risk redaction proof
(Gate 3) so normalization does not regress secret handling. Independently shippable (split from the
former bundled 4.10). No secret material in any new or renamed line.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs`, `crates/slashing/src/audit.rs`.
- Approach: rename all `rvc.`-prefixed span names and field keys to the canonical registry
  (`slot`/`epoch`/`pubkey`/`validator_index`). Check inputs/decision stay `debug`; a slashing **veto**
  (intended sign blocked) is the canonical `error`-iff-intended-action-did-not-complete case — confirm
  it is `error`/`warn` per the rule without touching `Result` flow.
- Key decisions: `slashing` depends on `crypto` (verified) → use the `fields::*` consts / `TruncatedPubkey`
  where applicable.
- Watch out for: keep `expose_secret`/`raw_bytes`/`to_bytes` out of any log macro (Gate 1); the check
  inputs are non-secret (slot/epoch/root metadata) but the decision path is security-sensitive.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed keys remain in `db.rs`, `audit.rs`; their entries leave `KNOWN_REMAINING`; gate
      green.
- [ ] **Gate 1 green** (clippy `disallowed-methods`): no new secret-getter reaches a log macro.
- [ ] **Gate 3 green:** a captured-subscriber test asserts `slashing` decision events carry canonical
      `pubkey`/`slot`/`epoch` and no secret.
- [ ] `slashing` veto categorized `error`; transient/skip cases `warn` — no `Result`/`?`/error-type
      changes.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green; existing slashing tests green.

**Testing Notes:**
- Add `tracing-test` as a dev-dep to `slashing` if absent. Reuse the Phase 2 high-risk-crate captured-
  subscriber pattern.

---

### Issue 4.10c: High-risk normalize — `secret-provider`

- **Points:** 2
- **Type:** chore
- **Priority:** P0-adjacent (high-risk crate; a careless rename could re-expose a secret)
- **Blocked by:** 4.2
- **Blocks:** 4.12a, 4.13
- **Scope:** 1-2 days

**Description:**
Normalize the `rvc.`-prefixed field/span keys in `secret-provider/src/gcp.rs` (2) +
`key_source_manager.rs` (13) to the canonical registry. This is the highest-risk of the three high-risk
normalization issues: a careless field rename in `gcp.rs` could re-expose a secret, so re-running the
Phase 2 Gate 3 redaction tests for this crate is a hard acceptance criterion. Independently shippable
(split from the former bundled 4.10). Phase 2 signed off this crate's *redaction*; Phase 4 normalizes its
*field names* only.

**Implementation Notes:**
- Files likely affected: `crates/secret-provider/src/gcp.rs`, `crates/secret-provider/src/key_source_manager.rs`.
- Approach: rename all `rvc.`-prefixed span names and field keys to the canonical registry
  (`slot`/`epoch`/`pubkey`/`request_id`/`bn_url` as applicable). Every renamed line must keep
  `expose_secret`/`raw_bytes`/`to_bytes` out of the macro (Gate 1) — the rename must not change which
  values reach a log macro, only their key names.
- Key decisions: `secret-provider` depends on `crypto` (verified) → use the `fields::*` consts /
  `RedactedUrl` / `TruncatedPubkey` where applicable.
- Watch out for: this is the issue where a careless rename could re-expose a secret in `gcp.rs` — re-run
  the Phase 2 Gate 3 redaction tests for this crate and add any missing assertion before the rename
  lands.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed keys remain in `gcp.rs`, `key_source_manager.rs`; their entries leave
      `KNOWN_REMAINING`; gate green.
- [ ] **Gate 1 green** (clippy `disallowed-methods`): no new `expose_secret`/`raw_bytes`/`to_bytes`
      reaches a log macro in `secret-provider`.
- [ ] **Gate 3 green:** the Phase 2 `secret-provider` redaction tests are re-run against the renamed keys
      and assert no raw key/password material is emitted at any level.
- [ ] No `Result`/`?`/error-type changes.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green; existing secret-provider tests green.

**Testing Notes:**
- `secret-provider` already has `tests/tracing_hierarchy.rs` (7 `rvc.` hits in tests — update the
  assertions to the renamed keys in the same atomic commit). The Gate 3 redaction re-proof is the
  primary deliverable, not a nicety.

---

### Issue 4.11: `beacon` + `grpc-signer` namespace normalize

- **Points:** 3
- **Type:** chore
- **Priority:** P1
- **Blocked by:** 4.2
- **Blocks:** 4.12a
- **Scope:** 2 days

**Description:**
Two HTTP/RPC client crates with the highest `rvc.`-prefixed span density outside the orchestrator:
`beacon/src/client.rs` (~29 — one `rvc.beacon.<method>` span per beacon-node HTTP call, plus `rvc.slot`/
`rvc.epoch` fields and an `rvc.beacon.http` span) and `grpc-signer/src/client.rs` (~31 — the gRPC signer
client spans). Normalize all span names and field keys to the canonical registry. `beacon` is a
ready-now crate that already mixes `rvc.`-prefixed names with OTel-semantic `http.*` names — keep the
`http.*` semantic names (they are intentional OTel conventions, allow-listed in 4.1), normalize only the
`rvc.`-prefixed ones.

**Implementation Notes:**
- Files likely affected: `crates/beacon/src/client.rs` (span names at `:187`–`:911`, `rvc.slot`/`rvc.epoch`
  fields), `crates/grpc-signer/src/client.rs` (~31 sites).
- Approach: `name = "rvc.beacon.get_attester_duties"` → unprefixed `name = "beacon.get_attester_duties"`
  (matching the Phase 2 `signer` convention); `rvc.slot`/`rvc.epoch` fields → `slot`/`epoch`. Preserve the
  existing `enabled!(Level::TRACE)` guard at `client.rs:149` (the verified zero-cost pattern) and the
  `http.status_code = Empty` late-bound pattern (the canonical late-bind model) — these are correct, do
  not disturb them.
- Key decisions: `beacon` depends on both `crypto` and `telemetry` (verified) → may use `fields::*`/
  `RedactedUrl`. Keep `bn_url` redacted. Keep OTel `http.*` semantic names (do not rename to registry —
  they are deliberately OTel-semantic and on the advisory allow-list).
- Watch out for: `client.rs` is large; the diff is mechanical but wide. Confirm via the grep gate, not by
  eyeballing all 29 sites.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed span/field key remains in `beacon/src/client.rs` or `grpc-signer/src/client.rs`;
      their entries leave `KNOWN_REMAINING`; gate green.
- [ ] The `enabled!(Level::TRACE)` guard (`client.rs:149`) and the `http.status_code = Empty` late-bind
      pattern are preserved unchanged.
- [ ] OTel-semantic `http.*` field names are retained (not flagged by the advisory conformance set).
- [ ] Captured-subscriber test asserts a representative `beacon` request span fires with canonical
      `slot`/`epoch` and redacted `bn_url`.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green; existing beacon/grpc-signer tests green.

**Testing Notes:**
- These crates are heavily tested already; the normalization must keep all existing tests green. Any test
  asserting an `rvc.`-prefixed key must be updated to the canonical key (search the test files too).

---

### Issue 4.12a: Orchestrator (`crates/rvc`) namespace normalize + test blocks

- **Points:** 3
- **Type:** chore
- **Priority:** P1
- **Blocked by:** 4.6, 4.7, 4.8, 4.9, 4.10a, 4.10b, 4.10c, 4.11 (the orchestrator normalizes after every library crate)
- **Blocks:** 4.12b, 4.13
- **Scope:** 2 days

**Description:**
Normalize the largest single concentration of `rvc.`-prefixed keys — the orchestrator (`crates/rvc`:
`coordinator.rs` ~42, `attestation.rs` ~7, `aggregation.rs` ~14, `duty_management.rs` ~4,
`sync_committee.rs` ~2, `startup.rs` ~3). Spans like `rvc.slot.process`,
`rvc.slot.phase.{block,attestation,aggregation}`, `rvc.epoch.boundary`, `rvc.orchestrator.*`,
`rvc.aggregation.submit` and the `rvc.slot`/`rvc.epoch` fields all become canonical. The
`coordinator.rs` test block (`:3729+`) asserts exact `rvc.`-prefixed span names and **must** be updated
in the same atomic commit so `nextest` stays green. Split from the former bundled 4.12 so the wide
orchestrator rename and the load-bearing gate-tighten (now 4.12b) are reviewed separately.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/orchestrator/coordinator.rs`, `attestation.rs`, `aggregation.rs`,
  `duty_management.rs`, `sync_committee.rs`; `crates/rvc/src/startup.rs`. Plus the `coordinator.rs` test
  block at `:3729+` that asserts the old keys (update in the same commit).
- Approach: mechanical rename to the unprefixed convention; `rvc.slot`→`slot`, `rvc.epoch`→`epoch`. The
  orchestrator is the spans-first showcase — confirm `slot`/`epoch`/`duty` live on the per-slot/per-phase
  spans and child events inherit them (do not duplicate per event). Keep coarse spans (one per phase, not
  per inner await) per the architecture's poll-cost rule.
- Key decisions: `crates/rvc` is a ready-now crate (depends on `crypto`/`telemetry`) → use `fields::*`/
  `Duty::as_str()`. Update test assertions in the same commit so the rename is atomic and `nextest` stays
  green.
- Watch out for: the `coordinator.rs` test blocks (`:3729+`) assert exact span/field names and **will**
  break if not updated together. Do not tighten the grep gate here — that is 4.12b, after the bins are
  also done.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed span/field key remains anywhere under `crates/rvc/src`; the orchestrator file
      entries leave `KNOWN_REMAINING`; gate stays green (still allow-listing the bins).
- [ ] Orchestrator per-slot/per-phase spans carry canonical `slot`/`epoch`/`duty`; child events do not
      duplicate them; coarse-span granularity preserved.
- [ ] The `coordinator.rs` test block (`:3729+`) is updated to canonical keys in the same atomic commit
      and `cargo nextest run -p rvc` is green.
- [ ] No change to `Result`/error-type/`?` flow or runtime behavior.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- Run `cargo nextest run -p rvc` specifically after the rename to confirm the `:3729+` assertions track
  the renamed spans.

---

### Issue 4.12b: Bins normalize + tighten the zero-`rvc.` grep gate to empty

- **Points:** 2
- **Type:** chore
- **Priority:** P1
- **Blocked by:** 4.12a (and, transitively, the rest of the normalization tier 4.6–4.11)
- **Blocks:** 4.13
- **Scope:** 1-2 days

**Description:**
Normalize the remaining `rvc.`-prefixed keys in the binaries (`bin/rvc/src/main.rs`,
`bin/rvc-signer/src/*.rs`), then **tighten `no_rvc_prefix.rs` to an empty `KNOWN_REMAINING`** — the
workspace-wide exit-criterion gate. This is the phase's **load-bearing exit criterion**: once
`KNOWN_REMAINING` is empty and the whole-workspace zero-`rvc.` invariant is green, any `rvc.`-prefixed
production key now fails CI. Split from the former bundled 4.12 so the gate-tighten lands as its own
reviewable, dependency-gated step.

**Implementation Notes:**
- Files likely affected: `bin/rvc/src/main.rs`; `bin/rvc-signer/src/{service.rs,dvt/peer_service.rs,backend/dvt.rs}`;
  `crates/architecture-tests/tests/no_rvc_prefix.rs`. Plus the bin integration test files that assert on
  the old keys (`bin/rvc/tests/tier3_operations.rs`, `tier2_safety.rs`).
- Approach: mechanical rename of the bin sites to the unprefixed convention; update any bin integration
  test that asserts an `rvc.`-prefixed key in the same commit. Only **after** every other crate's
  `KNOWN_REMAINING` entry is already gone (4.6–4.11, 4.12a), empty the list so the gate covers the whole
  workspace.
- Key decisions: tightening `KNOWN_REMAINING` to empty is the single most load-bearing assertion in the
  phase — do it last, in this issue, after the orchestrator (4.12a) and every library crate have left the
  list.
- Watch out for: a reintroduced `rvc.` key in any production file must fail the gate once the list is
  empty — verify by a temporary local reintroduction in review.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed span/field key remains anywhere under `bin/*/src`.
- [ ] `no_rvc_prefix.rs` `KNOWN_REMAINING` is **empty** and the gate is green over the whole workspace —
      a reintroduced `rvc.` key in any production file now fails `cargo nextest run -p architecture-tests`.
- [ ] All existing bin integration tests updated to canonical keys and green.
- [ ] No change to `Result`/error-type/`?` flow or runtime behavior.
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- Run the `bin/rvc` integration tiers specifically after the rename. The exit-criterion gate (empty
  `KNOWN_REMAINING`) is the single most important assertion in the phase — prove it fails on a
  reintroduced key during review.

---

### Issue 4.13: Wire Gate 5 advisory + remaining hot-`#[instrument]` sweep (P1-2)

- **Points:** 2
- **Type:** feature / chore
- **Priority:** P1
- **Blocked by:** 4.2 (the harness); **and the full normalization set** — 4.10a, 4.10b, 4.10c, 4.11,
  4.12a, and 4.12b (the empty-`KNOWN_REMAINING` state). The curated conformance set grows from the beacon
  (4.11) and high-risk (4.10a/b/c) paths and asserts "advisory output empty", which fails on any
  un-normalized `rvc.` key — so 4.13 depends **directly** on every crate that contributes events to the
  set being normalized, not merely transitively via 4.12b.
- **Blocks:** — (Gate 5 → blocking is Phase 5)
- **Scope:** 1-2 days

**Description:**
Two closing tasks. (a) Grow the curated conformance set in `field_name_conformance.rs` to a
representative slice of hot-path events across the now-normalized crates and confirm Gate 5 runs
**advisory** (flags non-canonical keys, does not fail) — completing the architecture's "Gate 5 wired
advisory in Phase 4" deliverable. (b) A final P1-2 sweep: identify any remaining hot-path public async
entry point not yet carrying a standardized `#[instrument]` span (after Phase 2's hot-path pass and the
Phase 4 normalization), and add `#[instrument(level="debug", skip_all, fields(...))]` with canonical
correlation fields, completing the 100% span-coverage metric.

**Implementation Notes:**
- Files likely affected: `crates/architecture-tests/tests/field_name_conformance.rs` (grow the curated
  set); any hot-path entry point surfaced by a grep for `pub async fn` on the duty/attestation/block/
  signing/beacon paths that lacks `#[instrument]`.
- Approach: for (a), add captured events from the normalized orchestrator/beacon/signer/doppelganger
  paths to the curated set; assert advisory output is empty for the canonical ones (proving normalization
  worked) and that an intentionally-bad key would be flagged (a negative test). Keep it advisory — no
  `assert!` that fails the build on a flagged key (that is Phase 5).
- For (b), apply `skip_all` + scalar `fields(...)` (R1: no eager formatting in instrument fields); declare
  late-bound fields `Empty` and fill via `record_display`/`record_debug`.
- Key decisions: Gate 5 escalation to blocking is explicitly **out of scope** here (Phase 5, Open Q4) —
  this issue only lands the advisory form.
- Watch out for: do not add `#[instrument]` to a fn taking a secret/large arg without `skip_all` (Gate 1).

**Acceptance Criteria:**
- [ ] `field_name_conformance.rs` covers a curated multi-crate hot-path event set; advisory output is
      empty for the canonical events (proving Phase 4 normalization); a negative test confirms a
      non-canonical key **would** be flagged (advisory).
- [ ] Gate 5 is **advisory** (runs under `nextest`, never fails the build on a flagged key).
- [ ] Any remaining hot-path async entry point lacking a span now carries
      `#[instrument(level=…, skip_all, fields(…))]` with canonical fields and `skip_all`; the P0-4/P1-2
      100%-span-coverage metric holds.
- [ ] Gate 1 green (no new bare `#[instrument]` on a secret-taking fn).
- [ ] Workspace `fmt` + `clippy -D warnings` + `nextest` green.

**Testing Notes:**
- The advisory harness is the test for (a). For (b), a captured-subscriber test asserting each newly-added
  span fires at its intended level with canonical fields. The "remaining sites" set should be small after
  Phase 2 — if it is large, that signals Phase 2 under-delivered and the surplus should be raised with the
  Phase 2 owner rather than silently absorbed here.

---

## Dependency Map

```text
4.1 (Gate5 helper) ──▶ 4.2 (curated set + grep tooling)
                              │
        ┌─────────────────────┼─────────────────────────────┐
        ▼                     ▼                              ▼
   4.6 validator-store   4.7 doppelganger   4.8 timing   4.9 propagator+metrics
   4.10a bn-manager      4.11 beacon+grpc                (all depend on 4.2)
   4.10b slashing
   4.10c secret-provider
        └─────────────────────┴──────────────┬───────────────┘
                                              ▼
                                  4.12a orchestrator (crates/rvc) + test blocks
                                              ▼
                                  4.12b bins + tighten grep gate to empty
                                              │
        ┌─────────────────────────────────────┘
        ▼  (also directly blocked-by 4.10a/b/c, 4.11, 4.12a)
   4.13 Gate 5 advisory + hot-#[instrument] sweep

   4.3 rvc-keygen ─┐
   4.4 eth-types   ├── independent (no dependency; greenfield/disposition); slot any time
   4.5 signer-reg ─┘
```

## Risk Flags

| Issue | Risk | Mitigation |
|-------|------|------------|
| 4.12a/4.12b | Largest diff; the orchestrator test blocks (`coordinator.rs:3729+`) assert exact `rvc.`-prefixed names and break on rename. Easy to leave a key behind across ~70 sites. | **Split applied (4.12a orchestrator + test blocks, 4.12b bins + final gate-tighten).** The `no_rvc_prefix.rs` grep gate (4.2) is the safety net — tighten `KNOWN_REMAINING` to empty only when green (in 4.12b). Update tests in the same atomic commit as each rename. |
| 4.10a/4.10b/4.10c | High-risk crates — a careless field rename in `secret-provider`/`gcp.rs` could re-expose a secret. | **Split applied (4.10a `bn-manager`, 4.10b `slashing`, 4.10c `secret-provider`)** so each carries its own `tracing-test` setup and Gate 3 re-proof. Re-run Phase 2 Gate 3 redaction tests for each crate as an acceptance criterion; Gate 1 clippy sinks stay green. |
| 4.3 | Mnemonic re-leak via a breadth addition (`bip39::Mnemonic` `Display`s to the phrase). | The bare type is treated as a sink; the Gate 3 captured-subscriber test (raw phrase absent at `trace`) is the *primary* deliverable; never log length. |
| 4.5 | Documented N/A for `signer-registry` deviates from the PRD's literal "100% of near-silent crates" metric. | Flagged honestly in this file and to be noted in `00-summary.md`; the crate genuinely has no runtime surface (dev-only const table, Gate-6-pinned). |
| 4.4 | Temptation to add `crypto` to `eth-types` for `TruncatedRoot`/`fields`. | Gate 6 forbids it (zero-out-edge pin) and would fail CI; use literal field idents; log nothing rather than a full root. |
| 4.7 | The raw `Span::current().record("rvc.…", …)` will silently no-op if the renamed field isn't declared `Empty` at span creation. | Acceptance criterion requires the `field::Empty` declaration + `record_display`/`record_debug` helper, with Gate 3 asserting the field is present on the emitted span. |
| 4.13 | Over-absorbing missed Phase 2 work into "remaining hot sites." | If the remaining-sites set is large, escalate to the Phase 2 owner rather than silently absorbing scope; Gate 5 stays advisory (not blocking) here. |

## Census drift note (for `00-summary.md` and stakeholders)

The PRD's near-silent census predates current `develop`. Verified at `develop`: of the eight crates the
PRD lists as near-silent, only **`eth-types`** (1 statement, constrained) and **`metrics`** (3,
lifecycle-only) are genuinely greenfield; **`rvc-keygen`** is greenfield-but-high-risk (0 statements,
mnemonic rule); **`doppelganger`**, **`validator-store`**, **`propagator`**, and **`timing`** already log
and are normalization targets; **`signer-registry`** is a dev-only const table with no runtime surface
(documented exception). The bulk of Phase 4's actual effort is therefore the **workspace-wide `rvc.`
namespace normalization** (~300+ occurrences across ~30 files), which the architecture spot-checked only
on `signer`/`crypto`. This is reflected in the point distribution (the high-risk and orchestrator/bins
normalization issues — 4.10a/b/c, 4.11, 4.12a, 4.12b — carry 14 of the 34 points).
