# Phase 3: Init Consistency — Operator Parity

> Self-contained issue breakdown for **Phase 3** of the rs-vc Structured Logging & Observability
> initiative. Authoritative inputs: [`prd.md`](../prd.md) (P0-5), [`architecture.md`](../architecture.md)
> (ADR-003, ADR-004; the *Subscriber-init reconciliation* module), [`project-plan.md`](../project-plan.md)
> (Phase 3 / Milestone M3), and the research overview [`research/00-overview.md`](../research/00-overview.md)
> (§G file-more-verbose-than-console familiarity). A code-writer should need only this file plus the
> cited source sites.

## Phase Overview

- **Goal:** Give both long-running binaries **one** default level (`info`), **one** `EnvFilter`
  precedence (env `RUST_LOG` overrides the config/flag default), and a shared output-format selection —
  **without** touching the OTLP layer, file appender, sampler, or the `TracingGuard`/shutdown contract.
  This is P0-5, the last must-have; the P0 commitment closes at the end of this phase (Milestone M3).
- **PRD scope:** P0-5 (subscriber-init consistency). **Maps to** architecture rollout Phase 2 and
  decision **ADR-003** (one precedence) + **ADR-004** (file-more-verbose-than-console, contingent).
- **Issue count:** 5 issues, **10 total points**.
- **Estimated duration:** ~6 days (single-stream default; one code-writer working issues in order).
- **Entry criteria:**
  - Phase 1 landed: the `crypto::logging` kit and (relevant here) `telemetry` is the agreed home for
    shared init helpers. The `architecture-tests` DAG gate does **not** have a policy-table entry for
    `rvc-signer-bin → rvc-telemetry` (its `FORBIDDEN` / `ZERO_OUT_EDGE_IF_PRESENT` / `REQUIRED_EDGE`
    tables contain no such entry; the architecture only *recommends* adding one). The gate stays green
    for this edge **because the edge touches none of those policy tables** — it is a leaf attachment to
    a zero-internal-dep crate — not because the tables were extended. Adding an explicit
    allow/`REQUIRED_EDGE` entry to lock the boundary is an **optional** hardening that Issue 3.3 (or a
    sub-task of it) may do; it is **not** a Phase-1 precondition.
  - The single new production edge `rvc-signer-bin → rvc-telemetry` does **not** exist on `develop`
    today (`bin/rvc-signer/Cargo.toml` has no `telemetry`/`tracing-opentelemetry` dependency), and the
    helpers it would call (`telemetry::env_filter_or`, `set_parent_from_headers`) are built earlier in
    the plan (Phase 1 / Phase 2). In practice **Issue 3.3 owns introducing the edge** — reusing it only
    if Phase 2's :9000 bridge has already added it (to call `set_parent_from_headers`). It is a leaf
    attachment to a zero-internal-dep crate — provably acyclic; the DAG gate stays green either way.
    Sequencing after Phase 2 keeps the edge landing once; this phase does not depend on Phase 2's
    hot-path edits otherwise.
  - Working tree on `develop`, green on the standing invariant (below).
- **Exit criteria (phase-level):**
  - [ ] Both bins share the same default level (`info`): init parity tests assert unset `RUST_LOG` →
        effective level `info` in **both** binaries.
  - [ ] Both bins share the same precedence: `RUST_LOG=debug` overrides; a per-module directive
        (e.g. `rvc_signer_bin::http_api=trace`) raises **only** that target — asserted by tests in both.
  - [ ] The `bin/rvc` empty-layer `Identity`-padding still emits events (the existing
        `test_init_logging_no_extras_emits_events` regression marker stays green and is mirrored in
        rvc-signer).
  - [ ] Malformed `RUST_LOG` falls back to the configured default — never panics, never goes silent.
  - [ ] OTLP layer, file appender, sampler, and `TracingGuard`/shutdown contracts unchanged; their
        existing `telemetry` tests still green. The reconciliation does **not** add OTLP/file layers to
        `bin/rvc-signer` as part of the core scope (Issue 3.5 is an explicitly-bounded, optional add).
  - [ ] **Standing invariant green** (see below).

### Standing invariant (every issue must hold this at merge)

`cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean
(Gate 1 `disallowed-methods` is active workspace-wide as of Phase 1 — new code must not trip it);
`cargo nextest run --workspace` green. **Do NOT use `cargo test --workspace`** — it can deadlock in this
workspace; `nextest` is the runner of record. TDD per CLAUDE.md: **RED → GREEN → REFACTOR** (write the
failing test first, confirm it fails for the right reason, then minimal code, then refactor green).

### Assumptions recorded for this phase (no user was asked, per task constraints)

1. **(verified)** `telemetry` is the correct home for `env_filter_or` — it owns the OTel/`EnvFilter`
   surface, depends on **no** workspace crate (a leaf sink), and `bin/rvc` already depends on it.
   `bin/rvc-signer` gains a single additive `→ telemetry` edge — introduced by Issue 3.3 (or reused
   from Phase 2's :9000 bridge if it landed first) — which is acyclic (leaf attachment). The
   `architecture-tests` DAG gate has **no** policy-table entry for this edge; it stays green because
   the edge touches none of the `FORBIDDEN`/`ZERO_OUT_EDGE_IF_PRESENT`/`REQUIRED_EDGE` tables, not
   because they were pre-extended. (ADR-003; architecture *Module Dependency Graph*.)
2. **(verified)** The divergence is real and as the architecture states:
   - `bin/rvc` `init_logging` (`bin/rvc/src/main.rs:774`) builds the filter at `:783` as
     `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))` — config default
     `info` with `RUST_LOG` override — and pads an empty layer `Vec` with `Identity` at `:834-836`
     before `registry().with(boxed_layers).with(fmt::layer()).with(filter).init()` (`:838-842`).
   - `bin/rvc-signer` inits **inline in `main()`** at `bin/rvc-signer/src/main.rs:234-236`:
     `tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init()` — **no** fallback,
     so unset `RUST_LOG` yields the bare default (effectively `ERROR`), **not** `info`; no `info`
     default, no `Identity` padding, no config plumbing.
3. **(verified)** `bin/rvc-signer/src/main.rs` has **no** `mod tests` and **no** init test today; the
   model to mirror is `bin/rvc`'s `test_init_logging_no_extras_emits_events`
   (`bin/rvc/src/main.rs:2202-2251`), which reconstructs the exact layer composition with a captured
   `MakeWriter` and asserts an `info!` event reaches the writer.
4. **(verified)** The independent **file** level (file `debug`, console `info`, ADR-004) exists **only**
   in `bin/rvc` today — `build_file_layer_config` (`bin/rvc/src/main.rs:925-947`) threads
   `config.logfile_level` (falling back to `log_level`) into `telemetry::FileAppenderConfig.level`
   (`:937`). `bin/rvc-signer` has **no** file-appender path at all (no `create_file_layer` /
   `FileAppenderConfig` / `logfile` references in `bin/rvc-signer/src`, and `ResolvedConfig`
   — `bin/rvc-signer/src/config.rs:106` — has no `log_level`/`logfile_level` field). Therefore ADR-004
   for rvc-signer means **adding a file-appender path**, which is broader than init-consistency. It is
   isolated to the **optional** Issue 3.5 with a documented fallback (file == console) so the core P0-5
   work (Issues 3.1–3.4) cannot balloon. (Architecture Open Q2 / project-plan Phase 3 spike: "confirm
   the `logroller`/non-blocking path honors an independent file level for `bin/rvc-signer`; if not, fall
   back to file == console — documented, not assumed.")
5. **(verified)** `bin/rvc` calls `init_logging(&log_level, ...)` from **four** sites (`:673`, `:712`,
   `:740`, `:757`); `log_level` originates from a clap `String` arg whose default is `info`. The
   reconciliation must preserve all four call paths' behavior.
6. The reconciliation **unifies default level + precedence + format selection only**. It deliberately
   does **not** add OTLP/file layers to `bin/rvc-signer` as core scope (that would be a telemetry change,
   out of P0-5); each binary keeps its own thin binary-local init wrapper — we do **not** introduce a
   shared init *crate* for two call sites (ADR-009: the documented contract + the one tested helper is
   cheaper).

---

## Phase Summary

| Issue | Title | Points | Type | Priority | Blocked by | Scope | Files |
|-------|-------|--------|------|----------|------------|-------|-------|
| 3.1 | `telemetry::env_filter_or` shared precedence helper (TDD) | 2 | feature | P0 | — | 1-2 days | `crates/telemetry/src/init.rs` (or `lib.rs`), `crates/telemetry/src/lib.rs` (re-export) |
| 3.2 | Route `bin/rvc` init through the helper; preserve `Identity` padding | 2 | chore | P0 | 3.1 | 1 day | `bin/rvc/src/main.rs` (`:783`, `:834-842`, helper call) |
| 3.3 | Reconcile `bin/rvc-signer` init + add test scaffold (+ introduce the `→ telemetry` edge) | 3 | feature | P0 | 3.1 | 2 days | `bin/rvc-signer/src/main.rs` (`:234-236`), `bin/rvc-signer/Cargo.toml` |
| 3.4 | Cross-binary init parity assertions (precedence / per-module / malformed / silent-default) | 2 | feature | P0 | 3.2, 3.3 | 1-2 days | `bin/rvc/src/main.rs` (tests), `bin/rvc-signer/src/main.rs` (tests) |
| 3.5 | (Optional, bounded) File-more-verbose-than-console for `bin/rvc-signer`, or documented fallback | 1 | feature | P2 | 3.3 | 1 day | `bin/rvc-signer/src/main.rs`, `bin/rvc-signer/src/config.rs` |
| **Total** | | **10** | | | | | |

## Phase Execution Plan

Single-stream: one code-writer works the issues in dependency order; each day-slot is ~1 day of work.

| Day | Issue | Notes |
|-----|-------|-------|
| 1 | 3.1 `env_filter_or` helper (RED → GREEN) | No deps; the keystone every other issue calls. |
| 2 | 3.1 cont. / 3.2 `bin/rvc` rewire | 3.2 starts once 3.1 is green. Pure refactor + regression-marker stays green. |
| 3 | 3.3 `bin/rvc-signer` reconcile | Replace inline init; add `mod tests` scaffold; introduce the `→ telemetry` edge (reuse Phase 2's only if it landed it first). |
| 4 | 3.3 cont. | Mirror the `bin/rvc` captured-writer regression marker. |
| 5 | 3.4 parity assertions (both bins) | Depends on 3.2 + 3.3; the cross-binary "operators learn one thing" proof. |
| 6 | 3.5 optional file-level (or document fallback) | P2; if the appender can't filter independently, ship the documented fallback and stop. |

> **Single-stream note.** Per the project plan's decision log, Phase 3 is technically independent of
> Phase 2's hot-path edits but shares the `telemetry` helper work and the new `bin/rvc-signer →
> telemetry` edge, so it is sequenced after Phase 2 to land that edge once. No stream/ownership split is
> used.

## Dependency Map

```text
3.1 (env_filter_or helper) ──┬──▶ 3.2 (bin/rvc rewire) ──┐
                             │                            ├──▶ 3.4 (cross-binary parity tests)
                             └──▶ 3.3 (bin/rvc-signer) ───┘
                                        │
                                        └──▶ 3.5 (optional rvc-signer file level / fallback)
```

## Risk Flags (phase-local)

- **Init reconciliation silently changes rvc-signer default verbosity/format** (the named P0-5 risk).
  *Mitigation:* ADR-003 pins the precedence/default explicitly; Issue 3.4 asserts unset-`RUST_LOG`→`info`,
  the `RUST_LOG=debug` override, a per-module directive, and the `Identity`-padding emission in **both**
  bins. The change to rvc-signer is intentional and visible (it currently has *no* `info` default).
- **Touching the telemetry stack by accident.** *Mitigation:* `env_filter_or` is a pure, additive free
  function over `std::env` + `EnvFilter`; it constructs no layers and touches no OTLP/file/sampler/guard
  code. Issues 3.2/3.3 only swap the filter-construction expression; existing `telemetry` tests are the
  backstop and must stay green (phase exit criterion).
- **ADR-004 (file-more-verbose) scope-creeps into a telemetry/appender redesign.** *Mitigation:* it is
  quarantined in the optional P2 Issue 3.5 with an explicit "document the fallback (file == console) and
  stop" branch; it is **not** required for the P0-5 commitment (M3 closes at Issue 3.4).
- **`EnvFilter` "default" semantics are subtle** — `EnvFilter::new("info")` sets the *global* default
  directive, which is the intended P0-5 behavior, but a stray per-target directive in `RUST_LOG` can
  still raise a noisy target. *Mitigation:* the helper's contract is documented as "env wins entirely
  when set"; Issue 3.4's per-module-directive test pins exactly this.

---

## Issues

### Issue 3.1: `telemetry::env_filter_or` shared precedence helper (TDD)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** none
- **Blocks:** 3.2, 3.3
- **Scope:** 1-2 days

**Description:**
Promote `bin/rvc`'s in-line filter-precedence logic to a single, named, tested helper in the `telemetry`
crate so both binaries share one implementation. The helper encodes the **documented precedence**
(ADR-003): *if `RUST_LOG` is set, use it; otherwise fall back to the configured default level.* This is
exactly `bin/rvc`'s current `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))`
(`bin/rvc/src/main.rs:783`), extracted and given a name + tests. This is the keystone of the phase —
nothing else can route through a shared helper until it exists.

**Implementation Notes:**
- New files to create: none. Edit `crates/telemetry/src/init.rs` (preferred home — it already owns the
  `tracing-subscriber`/`EnvFilter` surface) and re-export from `crates/telemetry/src/lib.rs` next to the
  existing `pub use init::init_tracing;` (`lib.rs:14`).
- Proposed signature (match the in-tree style; `EnvFilter` is `tracing_subscriber::EnvFilter`):
  `pub fn env_filter_or(default_level: &str) -> tracing_subscriber::EnvFilter`.
- Body is the promoted one-liner: `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level))`.
  `try_from_default_env()` returns `Err` when `RUST_LOG` is **unset or malformed**, so the
  `unwrap_or_else` branch covers both the unset case (→ `default_level`) and the malformed case
  (→ `default_level`, never a panic, never silent). Document this in the `///` doc comment with an
  example, per CLAUDE.md (public API gets `///` + an example).
- Watch out for: `EnvFilter::new(level)` panics if `level` is itself an invalid directive string — but
  callers pass a static `"info"`, so this is not a runtime risk; do **not** add fallible handling for the
  caller-supplied default (keep it a thin promotion of the existing behavior). The unit tests below use
  valid level strings only.
- Do **not** touch `init_tracing`, `create_file_layer`, `shutdown_tracing`, the sampler, or
  `TracingGuard` — this is an additive free function only (the architecture's "compose, never rebuild"
  rule; phase exit criterion).
- Tests must control the `RUST_LOG` env var. Because env vars are process-global, **serialize** the
  env-mutating tests (the workspace uses `nextest`, which runs tests in separate processes by default,
  but guard anyway): use a `std::sync::Mutex` static or set/remove `RUST_LOG` and restore it within each
  test. Assert on the filter via `format!("{filter}")` (the `EnvFilter` `Display` renders its directives)
  rather than reaching into private internals.

**Acceptance Criteria:**
- [ ] **RED first:** a failing test `env_filter_or("info")` (with `RUST_LOG` unset) is written before the
      function exists / before its body is filled, and is confirmed to fail for the right reason.
- [ ] `env_filter_or("info")` with `RUST_LOG` **unset** yields a filter whose effective default level is
      `info` (assert the rendered directive contains `info`).
- [ ] `env_filter_or("info")` with `RUST_LOG=debug` yields a filter reflecting `debug` (env wins).
- [ ] `env_filter_or("info")` with a **malformed** `RUST_LOG` (e.g. `"not a directive!!"`) falls back to
      the `info` default — the call returns a usable filter and does **not** panic.
- [ ] `env_filter_or("info")` with a per-module directive `RUST_LOG=warn,rvc_signer_bin::http_api=trace`
      preserves the per-target directive (env used verbatim).
- [ ] The helper is re-exported from `telemetry::lib` (`pub use init::env_filter_or;`) and is callable as
      `telemetry::env_filter_or(...)`.
- [ ] `///` doc comment present with a usage example.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`); existing `telemetry` tests
      (config/init/propagation/shutdown/file_appender) unaffected.

**Testing Notes:**
- Place tests in a `#[cfg(test)] mod tests` at the bottom of `init.rs` (CLAUDE.md test organization).
- Env-var mutation pattern: capture the prior value, `std::env::set_var`/`remove_var`, run the assertion,
  restore. Hold a module-static `Mutex` lock across the body so two env-mutating tests never interleave
  even if a future runner threads them.
- `EnvFilter`'s `Display` is the public, stable way to inspect directives — prefer it over any internal
  field access.

---

### Issue 3.2: Route `bin/rvc` init through the helper; preserve `Identity` padding

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Blocked by:** 3.1
- **Blocks:** 3.4
- **Scope:** 1 day

**Description:**
Replace `bin/rvc`'s in-line filter construction with a call to `telemetry::env_filter_or`, with **no
behavior change** for `bin/rvc` (it already implements the canonical precedence — this is the
single-source-of-truth refactor so the two binaries cannot drift again). All of `bin/rvc`'s existing
init structure — the boxed-layer composition, the OTLP/file layers, and especially the empty-`Vec`
`Identity` padding — must be preserved exactly.

**Implementation Notes:**
- File: `bin/rvc/src/main.rs`. Change the filter line at `:783` from
  `let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));`
  to `let filter = telemetry::env_filter_or(level);`.
- Remove the now-unused `use tracing_subscriber::EnvFilter;` import inside `init_logging` (`:781`) **only
  if** nothing else in the function references `EnvFilter` after the change (clippy `-D warnings` will
  flag an unused import — resolve it). The `Layer` and `prelude` imports stay.
- **Do not touch** the `Identity`-padding block (`:834-836`) or the final
  `registry().with(boxed_layers).with(fmt::layer()).with(filter).init()` (`:838-842`) — the comment at
  `:829-833` explains the empty-`Vec` never-Interest poison this padding fixes; the regression marker
  test guards it.
- All four `init_logging(&log_level, ...)` call sites (`:673`, `:712`, `:740`, `:757`) are unchanged —
  they pass `log_level` (default `info`) into the same helper, preserving behavior.
- `bin/rvc` already depends on `telemetry` (verified — existing OTLP/file usage), so **no new edge** and
  no `Cargo.toml` change.

**Acceptance Criteria:**
- [ ] `bin/rvc`'s `init_logging` constructs its `EnvFilter` via `telemetry::env_filter_or(level)`; the
      hand-rolled `try_from_default_env().unwrap_or_else(...)` expression is gone from `main.rs`.
- [ ] The existing regression-marker test `test_init_logging_no_extras_emits_events`
      (`bin/rvc/src/main.rs:2202-2251`) still passes unchanged — the `Identity`-padded empty-layer
      composition still emits an `info!` event to the writer.
- [ ] No `bin/rvc` behavior change: unset `RUST_LOG` → `info`; `RUST_LOG=debug` overrides (existing
      behavior preserved, re-asserted comprehensively in Issue 3.4).
- [ ] No new dependency edge added (`bin/rvc → telemetry` already exists); `bin/rvc/Cargo.toml`
      unchanged.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`) — including no unused-import
      warning from the removed `EnvFilter` use.

**Testing Notes:**
- This is a behavior-preserving refactor, so the *existing* regression marker is the primary guard; do
  not weaken it. New cross-binary assertions live in Issue 3.4 (kept together so both bins are asserted
  with one harness shape).
- Sanity-check the four call sites compile and that `level` is still threaded (no accidental hardcoding
  of `"info"` at the helper call — pass the caller's `level`).

---

### Issue 3.3: Reconcile `bin/rvc-signer` init + add test scaffold (+ introduce the `→ telemetry` edge)

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 3.1
- **Blocks:** 3.4
- **Scope:** 2 days

**Description:**
Make `bin/rvc-signer` use the shared precedence helper so it gains the canonical `info` default and the
`RUST_LOG`-overrides-default behavior it lacks today (currently `EnvFilter::from_default_env()` →
effectively silent when `RUST_LOG` is unset). Because `bin/rvc-signer` has **no** `mod tests` and **no**
init test today, this issue also lands the test scaffold (a captured-`MakeWriter` harness mirroring
`bin/rvc`'s regression marker) so Issue 3.4 can assert parity. The change is intentional and operator-
visible: unset `RUST_LOG` will now produce an `info` heartbeat instead of near-silence.

**Implementation Notes:**
- File: `bin/rvc-signer/src/main.rs`. Replace the inline init at `:234-236`:
  ```rust
  tracing_subscriber::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
      .init();
  ```
  with the helper-backed form, defaulting to `info`:
  ```rust
  tracing_subscriber::fmt()
      .with_env_filter(telemetry::env_filter_or("info"))
      .init();
  ```
  Keep it as the `fmt()` builder (rvc-signer's format selection); the **only** change is the filter
  source and the `info` default. Do **not** add OTLP or file layers here (out of P0-5 scope; Issue 3.5
  handles the optional file path).
- **Dependency edge — this issue owns introducing it.** `bin/rvc-signer` does **not** depend on
  `telemetry` on `develop` today (verified: `bin/rvc-signer/Cargo.toml` has no
  `telemetry`/`tracing-opentelemetry` dependency). If Phase 2's :9000 bridge already added
  `bin/rvc-signer → telemetry` (for `set_parent_from_headers`), reuse it; **otherwise this issue adds
  it.** Add `telemetry` to `bin/rvc-signer/Cargo.toml` `[dependencies]` using the workspace dependency
  form (match how other crates reference it, e.g. `telemetry = { workspace = true }` / `rvc-telemetry`
  workspace alias — verify the exact crate name used elsewhere in the workspace). This is a leaf
  attachment to a zero-internal-dep crate → **provably acyclic**. The `architecture-tests` DAG gate
  (`crates/architecture-tests/tests/architecture_no_cycles.rs`) stays green **because this edge touches
  none of its policy tables** (`FORBIDDEN`/`ZERO_OUT_EDGE_IF_PRESENT`/`REQUIRED_EDGE` contain no entry
  for it) — *not* because the tables were pre-extended. Run the DAG gate test to confirm it stays green
  with the edge present.
- **Optional hardening (may be done here or as a sub-task):** add an explicit `REQUIRED_EDGE` (or
  allow) entry for `rvc-signer-bin → rvc-telemetry` to
  `crates/architecture-tests/tests/architecture_no_cycles.rs` to *lock* the boundary, as the
  architecture recommends. This is optional and not required for P0-5; the gate already stays green
  without it.
- Extracting rvc-signer's init into a small binary-local `fn init_logging()` (mirroring `bin/rvc`) is
  encouraged for testability and symmetry, but **not required** — the helper call is the load-bearing
  change. If you extract it, keep it binary-local (ADR-009: no shared init crate for two call sites).
- Add a `#[cfg(test)] mod tests` to `bin/rvc-signer/src/main.rs` (it has none today). Mirror the
  `bin/rvc` `SharedBuf`/`MakeWriter` pattern from `bin/rvc/src/main.rs:2202-2251` to capture output and
  assert an `info!` event is emitted under the reconciled init.

**Acceptance Criteria:**
- [ ] **RED first:** a failing test asserting "unset `RUST_LOG` → an `info!` event is captured from
      rvc-signer's init" is written before the init change lands (it fails today because
      `from_default_env()` filters `info` out when `RUST_LOG` is unset).
- [ ] `bin/rvc-signer`'s init constructs its filter via `telemetry::env_filter_or("info")`; the bare
      `EnvFilter::from_default_env()` is gone.
- [ ] With `RUST_LOG` **unset**, an `info!` event emitted under the reconciled init **is** captured
      (parity with `bin/rvc`'s default `info`) — proving rvc-signer is no longer silent-by-default.
- [ ] `bin/rvc-signer/src/main.rs` has a `#[cfg(test)] mod tests` with a captured-`MakeWriter`
      regression marker mirroring `bin/rvc`'s `test_init_logging_no_extras_emits_events`.
- [ ] `bin/rvc-signer → telemetry` edge present (reused from Phase 2 or added here); and
      `crates/architecture-tests/tests/architecture_no_cycles.rs` stays green with the new
      `rvc-signer-bin → rvc-telemetry` edge present (production graph still acyclic), with
      `rvc-eth-types` still at zero out-edges.
- [ ] No OTLP/file layer added to `bin/rvc-signer` in this issue; the `fmt()` format selection is
      preserved.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`); the existing rvc-signer
      shutdown/SIGTERM behavior (project-history note: a prior reviewer caught a SIGTERM shutdown stall)
      is unaffected — init reconciliation does not touch the run/shutdown path.

**Testing Notes:**
- Reuse the `SharedBuf` `MakeWriter` shape verbatim from `bin/rvc`; assert
  `captured.contains("<marker>")`. Build the same `registry().with(...).with(fmt::layer().with_writer(buf)).with(filter)`
  shape rvc-signer ends up with so the test exercises the real composition.
- Serialize any `RUST_LOG`-mutating test with a module-static `Mutex` and restore the prior value
  (same pattern as Issue 3.1).
- Confirm the exact workspace crate name/alias for `telemetry` before editing `Cargo.toml` (grep an
  existing consumer such as `bin/rvc/Cargo.toml` or `crates/beacon/Cargo.toml`).

---

### Issue 3.4: Cross-binary init parity assertions (precedence / per-module / malformed / silent-default)

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 3.2, 3.3
- **Scope:** 1-2 days

**Description:**
Land the init **parity** tests in **both** binaries that prove an operator learns one behavior, not two
(the PRD's "same default level, `RUST_LOG` behavior, and output format across both binaries" user
story). These assertions close the phase's exit criteria and the named P0-5 risk (a silent default-level
change). They cover the four behaviors ADR-003 specifies: unset→`info`, env override, per-module
directive, and malformed→fallback (no panic, no silence).

**Implementation Notes:**
- Files: add/extend `#[cfg(test)] mod tests` in `bin/rvc/src/main.rs` and `bin/rvc-signer/src/main.rs`.
- Assert through the **shared helper** where possible (`telemetry::env_filter_or` rendered via
  `format!("{filter}")`) so both bins' tests share one assertion shape — this is the cheapest way to
  prove parity and avoids fragile end-to-end subscriber plumbing for the precedence cases. Keep the
  captured-`MakeWriter` test (Issues 3.2/3.3) for the *emission*/`Identity`-padding case; use the helper
  rendering for the *precedence/directive/malformed* cases.
- The per-module directive case must use a target string each binary actually emits under (e.g.
  `rvc_signer_bin::http_api=trace` for rvc-signer); assert the rendered filter contains both the global
  directive and the per-target directive.
- The malformed case asserts the call returns (no panic) and renders the `info` default.
- Serialize all `RUST_LOG`-mutating tests (module-static `Mutex`, restore prior value) — these are
  process-global mutations.

**Acceptance Criteria:**
- [ ] **Both** binaries have a test asserting unset `RUST_LOG` → effective default level `info`.
- [ ] **Both** binaries have a test asserting `RUST_LOG=debug` overrides the default (env wins).
- [ ] **Both** binaries have a test asserting a per-module directive (e.g.
      `RUST_LOG=warn,rvc_signer_bin::http_api=trace`) raises **only** that target and leaves the global
      at `warn` — i.e. the directive is preserved verbatim.
- [ ] **Both** binaries have a test asserting a malformed `RUST_LOG` falls back to `info` and does
      **not** panic and does **not** go silent.
- [ ] `bin/rvc`'s `Identity`-padding emission test (`test_init_logging_no_extras_emits_events`) remains
      green, and the rvc-signer mirror (from Issue 3.3) remains green — the "empty optional-layer Vec
      still emits events" guarantee holds in both.
- [ ] OTLP/file/sampler/`TracingGuard`/shutdown contracts demonstrably untouched: the existing
      `telemetry` crate tests (config/init/propagation/shutdown/file_appender) and any existing rvc-signer
      tests still pass with no edits to those modules.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- Prefer asserting on `format!("{}", telemetry::env_filter_or(...))` for the precedence/directive/
  malformed cases — `EnvFilter`'s `Display` is the stable, public surface and avoids needing a live
  subscriber per case.
- Keep one emission-level test per binary (the captured `MakeWriter`) so the `Identity`-padding +
  `fmt::layer` composition is exercised end-to-end, not just the filter in isolation.
- These tests are the M3 acceptance evidence — name them descriptively
  (`test_<bin>_unset_rust_log_defaults_to_info`, `test_<bin>_rust_log_overrides_default`,
  `test_<bin>_per_module_directive_preserved`, `test_<bin>_malformed_rust_log_falls_back_to_info`).

---

### Issue 3.5: (Optional, bounded) File-more-verbose-than-console for `bin/rvc-signer`, or documented fallback

- **Points:** 1
- **Type:** feature
- **Priority:** P2
- **Blocked by:** 3.3
- **Scope:** 1 day (hard-capped — do not exceed; fall back and stop)
- **Status:** Optional / capacity-permitting. **Not required for the P0-5 / M3 commitment** (that closes
  at Issue 3.4). Included so the architecture's ADR-004 file-more-verbose default is either delivered for
  rvc-signer or its non-delivery is an explicit, documented decision rather than a silent gap.

**Description:**
`bin/rvc` already supports an independent file level (file `debug`, console `info`) via
`logfile_level` → `FileAppenderConfig.level` (`bin/rvc/src/main.rs:937`). `bin/rvc-signer` has **no
file-appender path at all**. This issue investigates whether the existing `telemetry` file appender
(`logroller` + non-blocking writer, `create_file_layer`/`FileAppenderConfig`) can be wired into
rvc-signer with an **independent** file level, and either (a) delivers that, or (b) records the
documented fallback (file == console, no independent level) without any appender redesign. **Either
outcome is acceptable;** redesigning the appender or the `telemetry` crate is explicitly out of scope
(PRD Non-Goal; architecture Open Q2).

**Implementation Notes:**
- First, the spike (architecture Open Q2 / project-plan Phase 3 spike): confirm whether
  `telemetry::create_file_layer(&FileAppenderConfig)` honors `FileAppenderConfig.level` as an
  **independent** filter for the file layer in the rvc-signer composition (it does for `bin/rvc`). Read
  `crates/telemetry/src/file_appender.rs` to confirm the `level` field gates the file layer
  independently of the console `EnvFilter`.
- If feasible: add an optional `logfile`/`logfile_level` to rvc-signer's config surface
  (`bin/rvc-signer/src/config.rs` `ResolvedConfig` at `:106`, which today has **no** log-level field),
  build a `FileAppenderConfig` (mirroring `bin/rvc`'s `build_file_layer_config` at
  `bin/rvc/src/main.rs:925-947`, defaulting `logfile_level` to `debug` when a logfile is configured and
  console stays `info`), and compose the file layer into rvc-signer's subscriber. Reuse `bin/rvc`'s
  `Identity`-padding discipline for the boxed-layer `Vec` if you adopt the boxed-layer composition.
- If **not** feasible (the file layer cannot filter independently of the console in rvc-signer's
  configuration): **stop**, do not redesign anything, and record the fallback (file == console) as a
  documented decision — a code comment at the rvc-signer init site plus a one-line note for the Phase 5
  `OPERATOR_GUIDE.md` so the operator doc states the rvc-signer file/console relationship explicitly.
- This issue must **not** change the OTLP/sampler/`TracingGuard` contracts and must **not** alter the
  console default established in Issue 3.3.

**Acceptance Criteria:**
- [ ] The spike conclusion is recorded (feasible / not feasible) with the specific `file_appender.rs`
      evidence for the independent-level capability.
- [ ] **If feasible:** rvc-signer accepts an optional logfile with an independent file level; a test
      asserts console default `info` while the file level can be set to `debug` (file ≥ console), and the
      console behavior from Issue 3.3 is unchanged. The new file path reuses `telemetry`'s existing
      appender (no appender/telemetry redesign).
- [ ] **If not feasible:** the fallback (file == console) is documented at the init site and queued for
      the Phase 5 operator guide; no partial/broken file path is left in the code.
- [ ] No regression to `bin/rvc`'s file-level behavior or to any existing `telemetry`/rvc-signer test.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- If delivering the file path, the test can construct a `FileAppenderConfig { level: "debug", .. }` with
  a temp directory and assert (via the file layer in a captured composition, or by reading the existing
  `bin/rvc` file-level test `tier3_operations.rs:545` as the model) that the file layer admits `debug`
  while the console `EnvFilter` stays at `info`.
- If documenting the fallback, no new runtime test is required beyond confirming Issue 3.3's console
  behavior is intact.
