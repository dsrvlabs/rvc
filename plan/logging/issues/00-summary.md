# rs-vc Structured Logging & Observability — Cross-Phase Summary

> Engineering-lead roll-up across all five phase breakdowns of the rs-vc structured-logging /
> observability initiative. Each phase file is self-contained; this summary is the planning index —
> total scope, the single-stream execution order, the cross-phase dependency map, and the risk flags
> that span more than one phase. Authoritative inputs are the per-phase files plus `plan/logging/prd.md`,
> `plan/logging/architecture.md`, and `plan/logging/project-plan.md`.
>
> Phase files:
> [Phase 1](01-phase-1.md) · [Phase 2](02-phase-2.md) · [Phase 3](03-phase-3.md) ·
> [Phase 4](04-phase-4.md) · [Phase 5](05-phase-5.md)

## Estimation Approach

- **Unit = relative story points**, calibrated to this workspace (Rust, `nextest` runner of record,
  TDD RED→GREEN→REFACTOR per CLAUDE.md). The rough day-rate is ~1 point ≈ 0.5–1 working day for the
  single code-writer; the day tables in each phase show the assumed cadence. Points are the planning
  currency; the day estimates are derived, not independent.
- **Scale:** 1 pt = a focused single-file change with a unit/captured-subscriber test; 2 pt = a small
  multi-site change or a gate stand-up; 3 pt = a load-bearing feature, a wide rename + test-fallout, or
  a proof harness. The former 5-pt cross-crate normalization sweeps have been **split** so no Phase 4
  issue exceeds 3 pt: the high-risk tier into 4.10a/4.10b/4.10c and the orchestrator+bins sweep into
  4.12a/4.12b.
- **Verified-against-`develop`, not planned-on-paper.** Every phase recorded an Assumptions block from
  reading the actual tree (file:line citations throughout). The most consequential finding is the
  **Phase 4 census drift**: several crates the PRD called "near-silent" already log (often with
  `rvc.`-prefixed keys), so Phase 4 is **more normalization, less greenfield** than the PRD implies —
  ~300+ `rvc.`-prefixed occurrences across ~30 files, concentrated in the orchestrator. This reshaped
  Phase 4's point distribution (the bulk of its 34 points sits in the per-crate normalization issues
  4.6–4.11 — including the high-risk tier 4.10a/b/c — plus the orchestrator/bins sweep 4.12a/4.12b).
- **Gate-driven.** Six fail-closed CI gates are the spine: Gate 1 (clippy `disallowed-methods` secret
  sinks), Gate 2 (gitleaks source + emitted-log sample), Gate 3 (captured-subscriber redaction/level/
  field conformance), Gate 4 (counting-allocator zero-alloc), Gate 5 (canonical-field-name conformance,
  advisory in P4 → blocking in P5), Gate 6 (DAG / `architecture-tests`). Gates land in Phase 1–2, are
  exercised through Phase 4, and Gate 5 is escalated in Phase 5.
- **No-ask constraint.** All Open Questions were resolved to the architecture's stricter ADR defaults
  and recorded as per-phase assumptions rather than escalated to the user.

## Phase Table

| Phase | File | Theme | Issues | Points | Est. duration | Milestone / PRD scope |
|-------|------|-------|-------:|-------:|---------------|-----------------------|
| 1 | [01-phase-1.md](01-phase-1.md) | Standard + Primitives + Gate Skeleton | 8 | 17 | ~10 days | M1 · P0-1 (+ substrate for P0-2/3/4/6) |
| 2 | [02-phase-2.md](02-phase-2.md) | Hot Paths + Safety (core observability) | 13 | 30 | ~21 days | M2 · P0-2 / P0-3 / P0-4 / P0-6 |
| 3 | [03-phase-3.md](03-phase-3.md) | Init Consistency — Operator Parity | 5 | 10 | ~6 days | M3 · P0-5 |
| 4 | [04-phase-4.md](04-phase-4.md) | Breadth — Gap Crates, Spans, Normalization | 16 | 34 | ~17-18 days | M4 · P1-1 / P1-2 / P1-3 |
| 5 | [05-phase-5.md](05-phase-5.md) | Docs & Polish — Operability and P2 | 7 | 16 | ~11 days | M5 · P1-4 + P2-1..P2-4 |
| **Total** | | | **49** | **107** | **~66 days** | P0-1..P0-6, P1-1..P1-4, P2-1..P2-4 |

> **The P0 commitment closes at the end of Phase 3** (M3). **P0+P1 closes after Phase 5 issues 5.1 + 5.2.**
> Phase 5 issues 5.3–5.6 are P2 ("as capacity allows"), deferred-not-dropped via 5.7.

## Single-Stream Execution Plan

One code-writer works every issue in dependency order; there is **no Stream A/B split** anywhere in the
initiative (the architecture's plan is single-stream by default; the kit *is* the scaffold, so there are
no scaffold issues). Phases run in number order because each phase's entry criteria require the prior
phase merged and green on `develop`. Within a phase, issues run in the order the phase file's day table
specifies. The macro order:

1. **Phase 1 (M1):** Land the rubric (`STANDARD.md` first — it is the review rubric for everything that
   follows), then the `crypto::logging` light-primitive kit (`TruncatedRoot`, `fields`/`Duty`,
   `new_request_id`, `record_*`), the inbound trace extractor in `telemetry`, and the gate skeleton
   (Gates 1, 6, then 2 — 2 is sequenced last because it scans the emitted-log output of 1.2/1.4).
2. **Phase 2 (M2):** Front-load the load-bearing signer/`:9000` correlation spine (2.1 rename → 2.2
   `spawn_blocking` re-entry + `TruncatedRoot` / 2.3 the `:9000` bridge), run the mutually-independent
   kit-consuming crates in the middle (2.4–2.10, crypto-first so the high-risk crate is done early),
   then land the proof gates last (2.11 Gate 3, 2.12 Gate 4, 2.13 the criterion bench companion) once
   their subjects exist.
3. **Phase 3 (M3):** Keystone helper first (3.1 `telemetry::env_filter_or`), then rewire both bins
   through it (3.2 `bin/rvc`, 3.3 `bin/rvc-signer` + the `→ telemetry` edge if Phase 2 has not added
   it), then the cross-binary parity assertions (3.4). 3.5 (file-more-verbose) is an optional, hard-
   capped P2 tail with a documented fallback.
4. **Phase 4 (M4):** Build the advisory/grep tooling first (4.1 Gate 5 helper → 4.2 curated set + the
   `no_rvc_prefix` grep gate) so every normalization issue self-checks; slot the independent
   greenfield/disposition work (4.3 keygen, 4.4 eth-types, 4.5 signer-registry) any time; run the
   per-crate normalization tier (4.6–4.9, the high-risk tier 4.10a/b/c, 4.11); then close the
   workspace-wide zero-`rvc.` invariant (4.12a normalizes the orchestrator → 4.12b normalizes the bins
   and tightens `KNOWN_REMAINING` to empty, last) and wire Gate 5 advisory (4.13).
5. **Phase 5 (M5):** Operator guide (5.1) then flip Gate 5 advisory→blocking (5.2) — **P0+P1 complete
   here.** Then the P2 nice-to-haves as capacity allows (5.3 sampling, 5.4 reload, 5.5 JSON, 5.6 dylint
   spike), and 5.7 closes out with deferral tracking + the final full-workspace green gate.

**Standing invariant at every merge (all phases):** `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`. **Never**
`cargo test --workspace` — it deadlocks in this workspace; `nextest` is the runner of record. Each issue
merges ff-only after review.

## Dependency Map

### Cross-phase spine

```text
Phase 1 (M1) ──▶ Phase 2 (M2) ──▶ Phase 3 (M3) ──▶ Phase 4 (M4) ──▶ Phase 5 (M5)
  rubric+kit       hot paths        init parity       breadth          docs+blocking
  +gates 1,2,6     +gates 3,4       (P0 closes)       +gate 5 advisory  +gate 5 blocking
```

Each phase is **hard-blocked** on the prior phase being merged and green (entry criteria). The
load-bearing cross-phase edges (each named in the phase files):

- **Kit (Phase 1) → everything.** `TruncatedRoot`, `fields::*`/`Duty`, `new_request_id`, `record_*`,
  and `STANDARD.md` are consumed by every Phase 2/4 logging change and by Gates 3/4/5. A missing Phase 1
  primitive at any later kickoff is a blocker to report upward, **not** a reason to inline a copy.
- **`set_parent_from_headers` (1.5) → the `:9000` bridge (2.3).** Phase 1 lands and unit-tests the
  function; Phase 2 wires it into the live handler. This is the cross-process trace-continuity edge.
- **The single new production edge `rvc-signer-bin → rvc-telemetry`.** Gate 6 policy is pre-extended to
  accept it in Phase 1 (1.7); the edge is physically introduced in Phase 2 (2.3). If Phase 2 has not
  landed it when Phase 3 starts, **Phase 3 issue 3.3 adds it** (a provably-acyclic leaf attachment).
  It must land exactly once.
- **`crypto::logging::fields` (1.3) → Gate 5 (4.1 helper → 4.2 curated set → 4.13 advisory → 5.2
  blocking).** The const registry is the single source of truth the conformance gate diffs emitted keys
  against, across three phases.
- **`release_max_level_debug` + Gate 4 zero-alloc (Phase 2) → P2 sampling (5.3).** Phase 5 sampling
  must re-run Gate 4 to prove it did not reintroduce the R1 eager-alloc trap.
- **Reconciled `init_logging` / `env_filter_or` (Phase 3) → reload (5.4) + JSON profile (5.5) +
  operator guide (5.1).** Phase 5's P2 layers compose onto the Phase-3 reconciled init and must
  preserve the `Identity`-padding short-circuit and the init parity tests.
- **`rvc.`-prefix normalization (Phase 2 signer/crypto → Phase 4 workspace-wide) → Gate 5 blocking
  (5.2).** Gate 5 cannot block until every `rvc.`-prefixed site is normalized (4.12b's empty
  `KNOWN_REMAINING`); blocking it earlier would fail the workspace on the very sites Phase 4 fixes.

### Intra-phase (per phase file)

- **Phase 1:** `1.1 → 1.3`; `{1.2, 1.4} → 1.8`; `1.5 / 1.6 / 1.7` independent.
- **Phase 2:** serial spine `2.1 → {2.2, 2.3, 2.9}`; independent kit-consumer tier `2.4–2.8`;
  `2.4 → 2.10`; gates `{2.2, 2.3, 2.4} → 2.11`, `{2.2, 2.4} → 2.12 → 2.13`.
- **Phase 3:** `3.1 → {3.2, 3.3} → 3.4`; `3.3 → 3.5` (optional).
- **Phase 4:** `4.1 → 4.2 → {4.6, 4.7, 4.8, 4.9, 4.10a, 4.10b, 4.10c, 4.11} → 4.12a → 4.12b → 4.13`;
  `4.3 / 4.4 / 4.5` independent (slot any time).
- **Phase 5:** `5.1 → 5.2 → {5.3, 5.4, 5.6}`; `5.4 → 5.5` (soft, shared `init_logging`);
  `{5.1, 5.2, +landed P2} → 5.7`.

## Risk Flags

Cross-phase and high-impact risks (each phase file carries its full local risk table):

- **[P1 → P2 → P3] The `rvc-signer-bin → rvc-telemetry` edge could land twice or not at all.** Gate 6
  policy is pre-set in Phase 1, the edge is introduced in Phase 2, and Phase 3 is a fallback adder.
  *Mitigation:* Phase 3's 3.3 explicitly reuses-or-adds; the DAG gate stays green either way (leaf
  attachment to a zero-internal-dep crate).
- **[P1] Open Q1 — `telemetry` naming `http::HeaderMap` (1.5) could force a new dep.** *Mitigation:*
  `reqwest` re-export is the primary path; a direct `http` leaf-dep is the documented fallback (no
  internal edge, no cycle). Confirmed empirically during Phase 1; could be 2× if the re-export proves
  insufficient.
- **[P1] Gate 1 over-banning legitimate `expose_secret`/`to_bytes` (1.6) turns the workspace clippy-red.**
  *Mitigation:* scope-don't-ban — reviewed `#[allow(clippy::disallowed_methods)]` at each enumerated
  site; ban only `SecretKey` paths, never `PublicKey::to_bytes`. Stated limitation: named-path match
  only (cannot see a value laundered into a `String`) — accepted; Gates 2/3 cover the runtime result.
- **[P1] Gate 2 gitleaks false positives block PRs (1.8).** *Mitigation:* `.gitleaks.toml` allow-lists
  intentional test fixtures; the emitted-log-sample step (the load-bearing novel part) reuses 1.2/1.4
  test output and may need harness iteration; cannot fully self-verify offline (Action runs in CI).
- **[P2] Zero-alloc proof (2.12) under `nextest`'s per-process model.** A process-global
  `#[global_allocator]` must isolate + warm up the measured region. *Mitigation:* sign once untimed,
  then measure; the test must demonstrably go RED if an eager `hex::encode`/heavy `#[instrument(fields)]`
  is reintroduced on the sign path.
- **[P3] Init reconciliation silently changes `bin/rvc-signer` default verbosity (named P0-5 risk).**
  The change is intentional and operator-visible (it currently has *no* `info` default).
  *Mitigation:* ADR-003 pins precedence; 3.4 asserts unset→`info`, env override, per-module directive,
  malformed→fallback in **both** bins, plus the `Identity`-padding emission marker.
- **[P3] ADR-004 (file-more-verbose) scope-creeps into an appender redesign (3.5).** *Mitigation:*
  quarantined in the optional, hard-capped P2 issue with an explicit "document the fallback (file ==
  console) and stop" branch; not required for M3.
- **[P4] The orchestrator+bins normalization is the largest diff** — the orchestrator test blocks
  (`coordinator.rs:3729+`) assert exact `rvc.`-prefixed names and break on rename; easy to leave a key
  behind across ~70 sites. The former bundled 4.12 is now **split into 4.12a** (orchestrator `crates/rvc`
  + its test blocks) **and 4.12b** (bins + the final `no_rvc_prefix` grep-gate tighten to empty) so the
  wide rename and the load-bearing gate-tighten are reviewed separately. *Mitigation:* the
  `no_rvc_prefix.rs` grep gate (4.2) is the safety net (4.12b tightens `KNOWN_REMAINING` to empty only
  when green); update tests in the same atomic commit as each rename.
- **[P4] High-risk-crate normalization** — a careless field rename in `secret-provider`/`gcp.rs` could
  re-expose a secret. The former bundled 4.10 is now **split into 4.10a** (`bn-manager`), **4.10b**
  (`slashing`), and **4.10c** (`secret-provider`) so each carries its own `tracing-test` setup and its
  own Gate 3 redaction re-proof, and each is independently shippable. *Mitigation:* re-run Phase 2 Gate 3
  redaction tests as an acceptance criterion on each (4.10c, the highest-risk, makes it a hard gate);
  Gate 1 clippy sinks stay green.
- **[P4] 4.3 mnemonic re-leak** — `bip39::Mnemonic` `Display`s to the phrase. *Mitigation:* treat the
  bare type as a sink; the Gate 3 captured-subscriber test (raw phrase absent at `trace`) is the
  *primary* deliverable; never log length.
- **[P4 — documented deviation] `signer-registry` (4.5) is a documented N/A**, deviating from the PRD's
  literal "100% of near-silent crates" metric. It is a dev-only const table with no runtime surface
  (Gate-6-pinned to zero out-edges). Flagged honestly here per the phase file's request.
- **[P5 — the main estimate risk] Gate 5 advisory test may not exist at phase start (5.2).** 5.2 is
  sized at 2 pts *assuming* Phase 4 shipped the advisory harness (4.13). If Phase 4 slipped it, 5.2
  absorbs authoring it and rises to ~5 pts / must split into 5.2a (author) + 5.2b (flip). *Mitigation:*
  confirm the advisory test is present and green as 5.2's first action; re-estimate before starting.
- **[P5] P2 sampling re-introduces an eager allocation (5.3).** *Mitigation:* the sampling decision must
  sit behind the level/`enabled!` check; 5.3 re-runs Gate 4 as an explicit acceptance criterion.
- **[P5] Dynamic reload breaks `Identity`-padding / init parity (5.4).** *Mitigation:* the reload
  layer's *initial* value is the reconciled `env_filter_or(level)`; re-run the init parity tests and the
  `init_logging` regression marker as acceptance criteria.
- **[P5] dylint adds a mandatory nightly toolchain (5.6) — hard Non-Goal.** *Mitigation:* land (if at
  all) only as a separate, non-blocking, allow-to-fail CI lane; the stable invariant is never gated on
  it. Strongly bias toward "spike + defer".
- **[P5] P2 scope creep delays closing the initiative (5.3–5.6).** *Mitigation:* P0/P1 is complete after
  5.2; 5.7 makes deferral first-class (tracked, not dropped); each P2 item is independently shippable
  and must not block the others.

## Census-Drift Note (carried up from Phase 4)

The PRD's "near-silent crate" census predates current `develop`. Verified: of the eight crates the PRD
lists as near-silent, only **`eth-types`** (1 statement, zero-out-edge constrained) and **`metrics`**
(3, lifecycle-only) are genuinely greenfield; **`rvc-keygen`** is greenfield-but-high-risk (0
statements, mnemonic rule); **`doppelganger`**, **`validator-store`**, **`propagator`**, **`timing`**
already log and are normalization targets; **`signer-registry`** is a documented exception (dev-only
const table). The bulk of the initiative's mid-game effort is therefore the **workspace-wide `rvc.`
namespace normalization** (~300+ occurrences across ~30 files), which the architecture spot-checked only
on `signer`/`crypto`.
