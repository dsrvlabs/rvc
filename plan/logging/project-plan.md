# Project Plan: rs-vc Structured Logging & Observability

> Phased, dependency-ordered execution plan for the cross-cutting logging/observability
> initiative on the rs-vc Cargo workspace (23 crates + 3 binaries: `bin/rvc`,
> `bin/rvc-keygen`, `bin/rvc-signer`).
>
> **Authoritative inputs:** PRD [`prd.md`](./prd.md), research overview
> [`research/00-overview.md`](./research/00-overview.md) (authoritative over the per-angle
> docs), and architecture [`architecture.md`](./architecture.md). The architecture's
> decisions — spans-first; light primitives in `crypto::logging`; the OTel-coupled extractor
> + init helper in `telemetry`; the single new edge `rvc-signer-bin → telemetry`;
> `release_max_level_debug`; `uuid` `request_id` + `x-request-id`; the six CI gates; the 9 ADRs
> — are **authoritative and not re-opened here**. This plan turns the architecture's Phase 0–4
> rollout (renumbered Phase 1–5 below) into milestones, dependencies, exit criteria, and
> sequencing rationale. It does **not** decompose phases into individual issues — that is the
> next stage's job.

---

## Overview & Objectives

This is an **enforcement-led, primitive-first** rollout. The work composes into the existing
`tracing` / `tracing-subscriber` / OpenTelemetry stack and the `telemetry` crate; it does **not**
rebuild any of them. The defining sequencing decision: **the standard, the shared primitives, and
the CI gates land first (Phase 1)**, so every later code change is measured against a landed rubric,
is checked by a fail-closed gate, and merely *calls* shared code rather than reinventing it. This is
why the order below is enforcement-and-primitive-first, not "highest-volume crate first."

The initiative ties directly to the PRD success metrics:

| PRD success metric | Where this plan delivers it |
|---|---|
| Documented logging standard committed under `plan/logging/`, referenced from code | Phase 1 (`STANDARD.md` + `telemetry` `//!` ref) |
| `trace!` raised from 19 to full hot-path-step coverage | Phase 2 (hot paths), extended in Phase 4 (breadth) |
| 100% of hot-path async entry points carry a standardized `#[instrument]` span with canonical correlation fields | Phase 2 (hot paths), completed in Phase 4 (remaining sites) |
| Near-silent crates raised to standard (`rvc-keygen`, `signer-registry`, `eth-types`, `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`) | Phase 4 |
| Secret-leak audit passes in CI, 0 findings | Phase 1 (gate skeleton) → Phase 2 (high-risk crates pass it) → enforced thereafter |
| No measurable latency regression at `info`; disabled `debug`/`trace` do no alloc/format/hash | Phase 2 (counting-allocator gate + `release_max_level_debug` + criterion bench) |
| Both binaries share default level / `RUST_LOG` semantics / format | Phase 3 (init consistency) |
| `cargo fmt` clean, `cargo clippy -D warnings`, `cargo nextest run --workspace` green | Every phase's exit criteria; the standing invariant |
| Operator-facing log documentation | Phase 5 (`OPERATOR_GUIDE.md`) |

**Objectives, in priority order:**

1. **Establish one enforceable standard** (taxonomy + canonical `snake_case` spans-first field
   registry + secret-redaction policy), documented *and* machine-checked.
2. **Make the runtime hot paths fully observable** at `debug`/`trace` with standardized correlation,
   continuous across the :9000 Web3Signer boundary, with **zero secret leakage** and **zero overhead
   when verbose is disabled**.
3. **Reconcile the two binaries' subscriber init.**
4. **Bring the near-silent and inconsistent crates up to standard** (breadth + normalization).
5. **Document operations and land P2 polish** as capacity allows.

**Standing invariants (every phase must hold these at merge):**

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and
  `cargo nextest run --workspace` all green. (`cargo test --workspace` can deadlock — **do not** use
  it; `nextest` is the runner of record.)
- TDD per CLAUDE.md (RED → GREEN → REFACTOR).
- No change to runtime behavior, public APIs, or signing/slashing logic. The only new wire behavior
  is inbound trace-context extraction at :9000 plus an additive `x-request-id` header (Phase 2).
- The `architecture-tests` DAG gate (no cycles) stays green.
- No regression to the existing `telemetry`/OTLP/file-appender/propagation/shutdown tests.

---

## Prerequisites

These must be true before Phase 1 work begins. All are already satisfied or are confirmation steps,
not build work:

- **Three upstream artifacts approved** — PRD, research overview, architecture (all present and
  approved; this plan is downstream of them).
- **Working tree at `develop`**, green on `cargo nextest run --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --all -- --check`. The
  initiative is purely additive on top of a green tree.
- **CI write access** to add one new `gitleaks` job to `.github/workflows/ci.yml` and to extend
  `clippy.toml` and the `architecture-tests` policy tables.
- **Gate-forwarded decisions confirmed (or accepted as the recommended defaults) at the Phase 1
  kickoff.** The architecture forwards eight implementation-gate questions; none blocks starting, all
  have a recommended default. The two with the broadest downstream impact and their recommended
  resolutions:
  - Static cap = `release_max_level_debug` (ADR-001), not `_info` — so operators can escalate to
    `debug` in prod via `RUST_LOG` without a rebuild while `trace!` is compiled out.
  - `request_id` source = fresh `uuid::Uuid::new_v4()` + `x-request-id` header (ADR-002), matching the
    in-tree `keymanager-api` precedent.
  - The remaining six (file-independent level confirmation; `telemetry` naming `http::HeaderMap`
    without a new dep; Gate 5 escalation timing; gitleaks emitted-sample harness shape; coarse-span
    granularity; pretty-vs-JSON default) are carried into the relevant phase below and do not gate the
    start.
- **No new mandatory toolchain.** Nightly / `dylint` / `--cfg tracing_unstable` are P2 escalations, not
  P0 blockers (the gates ride the existing `clippy`/`fmt`/`nextest` steps).

---

## Phase 1: Standard + Primitives + Gate Skeleton — Foundation

**Goal:** Land the normative contract, the thin shared-primitive surface, and the enforcement skeleton
so that every subsequent code change is measured against a landed rubric, checked by a fail-closed
gate, and only *calls* shared code. This is the foundation that makes the rest safe and measurable.

**Maps to architecture rollout:** Phase 0. **PRD scope:** P0-1 (documented standard), plus the
shared-code and gate substrate that P0-2/3/4/6 depend on.

**Scope (crates / surfaces):**
- `plan/logging/STANDARD.md` — the normative taxonomy + canonical field registry + redaction policy +
  copy-paste examples + `info`-heartbeat shape. Referenced from a `//!` module doc in `telemetry`.
- `crypto::logging` — the light primitives kit: `TruncatedRoot` (new, zero-alloc `Display`, `&[u8]`),
  `fields` const module + `Duty` enum, `new_request_id()`, `record_display`/`record_debug` span
  helpers. (`TruncatedPubkey`/`RedactedUrl` already exist — unchanged.)
- `telemetry::propagation` — the inbound `HeaderExtractor` + `set_parent_from_headers` (the inverse of
  the existing `inject_trace_context`). **Lands the function; wiring it into the :9000 handler is
  Phase 2.**
- `clippy.toml` — extended with `disallowed-methods` for the secret-laundering sinks
  (`expose_secret`/`raw_bytes`/`to_bytes`) + a reviewed, greppable `#[allow(...)]` allow-list at the
  legitimate decrypt/sign call sites.
- `.github/workflows/ci.yml` — the single net-new `gitleaks` PR job (source + emitted-log sample),
  with test-fixture allow-listing.
- `crates/architecture-tests` policy tables — extended to lock the new boundary (allow
  `rvc-signer-bin → rvc-telemetry`; keep `rvc-eth-types` at zero out-edges).

**Key deliverables:**
- `STANDARD.md` reviewed and merged — the rubric reviewers and gates code against.
- The `crypto::logging` kit, each primitive covered by captured-subscriber / unit tests (the existing
  `test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` is the proven model).
- `set_parent_from_headers` + `HeaderExtractor`, with a unit test asserting a synthetic inbound
  `traceparent` produces a **non-zero parent** on the span.
- Gate 1 (clippy `disallowed-methods`) live on the existing `-D warnings` step.
- Gate 2 (gitleaks) live as a PR job.
- Gate 6 (DAG) policy tables extended; the new edge confirmed acyclic.

**Exit criteria (measurable):**
- [ ] `STANDARD.md` exists, is reviewed, and is merged; `telemetry` carries a `//!` reference to it.
- [ ] `cargo nextest run --workspace` green including new kit tests; `TruncatedRoot` renders a real
      32-byte root truncated (`0x{10hex}...{8hex}`) and its full hex is **absent** from output.
- [ ] `set_parent_from_headers` unit test passes: synthetic inbound `traceparent` → **non-zero span
      parent** (trace continues); absent/garbled header → root span, no panic.
- [ ] Gate 1 green: `cargo clippy --workspace --all-targets -- -D warnings` passes with
      `disallowed-methods` active and the allow-list scoped to existing legitimate sites.
- [ ] Gate 2 green: gitleaks PR job runs over source + an emitted `trace`-level sample, 0 findings,
      test fixtures allow-listed.
- [ ] Gate 6 green with the extended policy tables: production graph acyclic; the
      `rvc-signer-bin → rvc-telemetry` edge accepted; `rvc-eth-types` pinned to zero out-edges.
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`).

**Phase risks & how the gates de-risk them:**
- *A wrong primitive shape bakes in an eager allocation (the R1 trap).* — Mitigated by `TruncatedRoot`
  taking `&[u8]` and rendering inside `Display::fmt` (ADR-005), and by `record_display`/`record_debug`
  removing the sigil-at-`record()` and undeclared-`field::Empty` foot-guns by construction. The Phase 2
  counting-allocator gate will later prove no eager alloc on the hot path.
- *gitleaks false positives block PRs.* — Tune the config to allow-list test fixtures; keep
  `trufflehog` verification-first as a scheduled deep sweep, not the blocking gate.
- *Gate 1 over-bans legitimate `expose_secret` at decrypt sites.* — Scope, don't ban: a small reviewed
  `#[allow(clippy::disallowed_methods)]` allow-list at the known sites; the lint then flags only *new*
  uses. Stated limitation: it matches named paths only (a value laundered into a `String` is invisible)
  — accepted because the type layer makes the implicit path impossible and Phase 2's runtime tests
  (Gate 3) cover the emitted result.

---

## Phase 2: Hot Paths + Safety — Core Observability

**Goal:** Make the runtime hot paths fully observable at `debug`/`trace` with standardized
spans-first correlation, prove the trace is continuous across the :9000 boundary, guarantee zero
secret leakage on the high-risk crates, and prove zero overhead when verbose is disabled. This is the
phase that delivers the PRD's central operability promise.

**Maps to architecture rollout:** Phase 1. **PRD scope:** P0-2 (field convention applied), P0-3
(redaction applied + enforced on high-risk crates), P0-4 (`trace`/`debug` hot-path coverage), P0-6
(zero-overhead-when-disabled).

**Scope (crates / surfaces — the hot path and the high-risk crates):**
- `crypto`, `signer` — apply canonical fields; **rename the `rvc.`-prefixed spans/fields to the
  registry** (`rvc.sign.*`, `rvc.operation`, `rvc.slashing.result`, span `rvc.slashing.check`) **and**
  apply the `spawn_blocking` span re-entry fix (ADR-008) at the **same** verified `crates/signer/src/lib.rs`
  sites (`:126`/`:209`, `:330`/`:372`) — done together so re-instrumentation does not re-introduce the
  prefixed keys.
- `bin/rvc-signer` :9000 path — wire `set_parent_from_headers` **first** in the `sign` handler, mint /
  read `request_id`, echo `x-request-id`, fill late-bound span fields (`slot`/`duty`/`pubkey` via
  `record_display` after body parse). This is the **bridge** that ends the cross-process trace break.
  This is also where `bin/rvc-signer` gains its single new production edge `→ telemetry`.
- `beacon`, `bn-manager` — endpoint selection (`debug`), request/response framing (`trace`), failover
  (`warn`); redacted `bn_url`.
- `slashing` — check inputs (non-secret, `debug`), decision (`debug`), DB interaction.
- `duty-tracker`, `builder`, orchestrator (`rvc` `duty_management`/`attestation`/`aggregation`/
  `block-service`) — fetch / cache hit-miss / dependent-root / epoch boundaries; selection / build
  steps / publish.
- `release_max_level_debug` added to `bin/rvc/Cargo.toml` and `bin/rvc-signer/Cargo.toml`.
- Net-new verification harness: a dependency-free counting-`#[global_allocator]` zero-alloc test
  (`crypto`/`signer`) and a `criterion` sign-path bench (`crates/signer/benches/sign_path.rs`).

**Key deliverables:**
- Hot-path async entry points carrying a standardized `#[instrument(level = "debug"/"trace", skip_all,
  fields(...))]` span with canonical correlation fields; `info` milestones / `debug` decisions /
  `trace` steps applied per the taxonomy.
- The :9000 trace continuity bridge wired and proven end to end.
- Gate 3 (captured-subscriber conformance) tests in `crypto`, `signer`, `bin/rvc-signer`, and
  `rvc-keygen` (treated as high-risk for the mnemonic rule even though the PRD lists it under P1
  breadth) — asserting redaction (raw secret **absent**, truncated/redacted form **present**),
  intended level, and intended fields, including late-bound `record()` fields landing on the span.
- Gate 4 (counting-allocator zero-alloc test) asserting `allocs_when_disabled == baseline` on the
  `sign_attestation` / `sign_block` paths and around one coordinator/per-slot phase.
- `release_max_level_debug` compiled into both binaries.

**Exit criteria (measurable):**
- [ ] Every identified hot-path step has `trace`; no hot-path step lacks it. Hot-path async entry
      points carry a standardized `#[instrument]` span with canonical correlation fields (100% of the
      P0-4 surface).
- [ ] **Trace continuous across :9000**, proven by the non-zero-parent test on the live `sign` handler
      (the span is a child of the caller's trace, not a fresh root); `request_id` and `x-request-id`
      present on both sides.
- [ ] The `rvc.`-prefixed sites in `signer` are normalized to the unprefixed registry **and** the
      `spawn_blocking` closures re-enter the span (Gate 3 asserts blocking-section events carry the
      span's `request_id`/`slot`).
- [ ] **0 secret findings**: Gate 1 + Gate 2 + Gate 3 all green on the high-risk crates (`crypto`,
      `secret-provider`, `signer`, the :9000 path, `rvc-keygen` mnemonics); no added statement widens
      secret exposure; pubkeys truncated even at `trace`, roots/signatures truncated via `TruncatedRoot`.
- [ ] **Zero-alloc assertion passes** (Gate 4): `allocs_when_disabled == baseline` on the sign and
      per-slot paths; the eager `hex::encode` locals on the sign path are replaced by `TruncatedRoot`.
- [ ] `release_max_level_debug` present in both bins' `Cargo.toml`; `trace!` physically absent from the
      `--release` build (and `debug!` still runtime-switchable via `RUST_LOG`); `criterion` sign-path
      bench shows `info ≈ no_subscriber` within noise.
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`); existing `telemetry`/OTLP tests
      still green.

**Phase risks & how the gates de-risk them:**
- *Secret leakage via a new statement on a high-risk crate.* — Defense-in-depth: type layer + Gate 1
  (clippy sinks) + Gate 3 (runtime absent) + Gate 2 (emitted scan) + explicit high-risk-crate sign-off.
  Fail-closed at 0 findings.
- *Hot-path latency regression / a reintroduced eager `hex::encode` (R1 trap).* — Gate 4 counting
  allocator is the *precise* gate (a ~1 ns span is below `criterion`'s floor next to a BLS sign);
  `release_max_level_debug` removes `trace`; house rule "scalars-only in instrument `fields`, redaction
  wrappers on event macros / `record()`"; `criterion` bench as the latency sanity companion.
- *The R3 fix or namespace rename applied at the wrong site (e.g. `gate.rs` instead of `lib.rs`).* —
  ADR-008 pins the verified `lib.rs` sites and binds the blocking-section fix to the namespace
  normalization at those same sites; Gate 3 asserts events carry the span's correlation fields.
- *Vanishing late-bound attribute (`record()` on an undeclared field).* — The
  `record_display`/`record_debug` helpers + the house rule "declare every late-bound field
  `field::Empty` at creation"; Gate 3 asserts recorded fields are present on the emitted span.

---

## Phase 3: Init Consistency — Operator Parity

**Goal:** Give both long-running binaries one default level (`info`), one `EnvFilter` precedence (env
`RUST_LOG` overrides the config/flag default), and a shared output-format selection — without touching
the OTLP layer, file appender, sampler, or `TracingGuard` contract.

**Maps to architecture rollout:** Phase 2. **PRD scope:** P0-5 (subscriber-init consistency).

**Scope (crates / surfaces):**
- `telemetry` — extract a small, tested helper (e.g. `env_filter_or(level)`) encoding the documented
  precedence (`bin/rvc`'s current `try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))`
  logic, promoted to a named, tested function). Optionally extend the file-more-verbose-than-console
  default (`logfile_level` `debug`, console `info`) to `bin/rvc-signer`, contingent on confirming the
  `logroller`/non-blocking path honors an independent file level for `bin/rvc-signer`.
- `bin/rvc` — call the shared helper; preserve existing behavior including the `Identity`-padding
  correctness for the empty-`Vec<Layer>` short-circuit.
- `bin/rvc-signer` — call the shared helper, thereby gaining a config default (unset `RUST_LOG` →
  `info`, identical to `bin/rvc`).

**Key deliverables:**
- The shared `env_filter_or` helper in `telemetry`, tested.
- Init parity tests in **both** binaries.
- (If confirmed feasible) `bin/rvc-signer` gains the independent file-level option; documented as the
  sanctioned recipe (the doc itself lands in Phase 5).

**Exit criteria (measurable):**
- [ ] **Both bins share the same default level** (`info`): init parity tests assert unset `RUST_LOG` →
      effective level `info` in both.
- [ ] Both bins share the same precedence: `RUST_LOG=debug` overrides; a per-module directive
      (e.g. `rvc_signer_bin::http_api=trace`) raises only that target — asserted by tests in both.
- [ ] The `bin/rvc` empty-layer `Identity`-padding still emits events (mirror the existing
      `init_logging regression marker` test in `rvc-signer`).
- [ ] OTLP layer, file appender, sampler, and `TracingGuard`/shutdown contracts unchanged; their tests
      still green. (The reconciliation deliberately does **not** add OTLP/file layers to
      `bin/rvc-signer` — that would be out of scope.)
- [ ] Malformed `RUST_LOG` falls back to the configured default (never panics, never goes silent).
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`).

**Phase risks & how the gates de-risk them:**
- *Init reconciliation silently changes default verbosity/format for `bin/rvc-signer`.* — ADR-003
  documents the precedence/default explicitly; init parity tests in both bins assert
  unset-`RUST_LOG`→`info`, the override, the per-module directive, and `Identity`-padding emission.
- *The file-independent-level default is assumed where the appender can't support it.* — Confirm
  against the existing `bin/rvc-signer` `logroller`/non-blocking path; if it cannot filter
  independently, fall back to file == console (documented, not assumed) — no appender redesign.

---

## Phase 4: Breadth — Gap Crates, Remaining Spans, Normalization

**Goal:** Bring the near-silent crates up to the standard, extend `#[instrument]` to the remaining
hot-path entry points not covered in Phase 2, and normalize the already-well-covered crates for
level/field/redaction conformance. This is mechanical, kit-backed, low-risk breadth measured against
the landed standard.

**Maps to architecture rollout:** Phase 3. **PRD scope:** P1-1 (gap crates), P1-2 (remaining span
instrumentation), P1-3 (normalize well-covered crates).

**Scope (crates / surfaces):**
- **Greenfield gap crates (add to standard):** `rvc-keygen` (mnemonic — high-risk; its redaction
  conformance was already proven in Phase 2, breadth completes here), `signer-registry`, `eth-types`,
  `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`. Each gains `info` milestones,
  `debug` internal state, and `trace` where a hot path exists. (`metrics` may gain log statements; this
  does **not** touch the Prometheus counters / `:9101` endpoint — that is a Non-Goal.)
- **Remaining hot `#[instrument]` sites** not covered in Phase 2.
- **Normalize the already-covered crates** (`crates/rvc`, `bin/rvc`, `bin/rvc-signer`, `signer`,
  `bn-manager`, `slashing`, `crypto`): fix level/field/redaction divergences, conservative
  `error`-vs-`warn` re-categorization (`error` iff an intended action did not complete), and remove
  duplicate log-and-return lines — **without** touching `Result`/`thiserror`/`?` control flow
  (Non-Goal).
- Gate 5 (canonical-field-name conformance) wired as a captured-subscriber test in **advisory** mode.

**Key deliverables:**
- Every gap crate raised to the standard (the PRD's 100%-of-near-silent-crates metric).
- Remaining hot-path entry points carrying standardized spans (completes the 100% span-coverage metric
  begun in Phase 2).
- A normalization pass over the well-covered crates; `rvc.`-prefixed sites eliminated workspace-wide.
- Gate 5 advisory conformance test over a curated hot-path event set.

**Exit criteria (measurable):**
- [ ] Each gap crate has `info` milestones + `debug` internal state (+ `trace` where a hot path
      exists) — the PRD's near-silent-crate metric hits 100%.
- [ ] No `rvc.`-prefixed field/span keys remain in the workspace (namespace normalized to the canonical
      registry); `slot` (not `rvc.slot`) is the emitted attribute key everywhere.
- [ ] `error`-vs-`warn` miscategorizations and duplicate log-and-return lines on the audited crates are
      fixed, with no change to `Result`/error-type/`?` control flow.
- [ ] Gate 5 advisory conformance test green over the curated set; non-canonical field names flagged.
      (Honestly flagged: field-name conformance for the full 23-crate breadth is the one normative rule
      under-enforced in P0 — the curated set is not exhaustive; `STANDARD.md` is the backstop review
      rubric.)
- [ ] `rvc-keygen` mnemonic redaction remains proven (Gate 3) after its breadth additions — not even
      mnemonic length is logged.
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`).

**Phase risks & how the gates de-risk them:**
- *Adoption drift / non-canonical field names creep into breadth crates.* — Gate 5 (advisory here) +
  the `crypto::logging::fields` consts as the greppable, refactor-safe source of truth + `STANDARD.md`
  as the review rubric.
- *A breadth edit on `rvc-keygen` re-introduces a mnemonic leak.* — `rvc-keygen` carries the
  Phase 2 high-risk redaction sign-off and Gate 3 captured-subscriber tests; the bare `bip39::Mnemonic`
  type is treated as a sink.
- *Re-categorizing `error`/`warn` drifts into rewriting control flow (a Non-Goal).* — Conservative rule
  (`error` iff an intended action did not complete); the pass touches log statements only, not
  `Result` flow.

---

## Phase 5: Docs & Polish — Operability and P2

**Goal:** Ship the operator-facing documentation, escalate the field-name conformance gate to blocking
now that the field set is stable, and land the P2 nice-to-haves as capacity allows.

**Maps to architecture rollout:** Phase 4. **PRD scope:** P1-4 (operator documentation); then P2-1
(sampling), P2-2 (dynamic reload), P2-3 (JSON profile), P2-4 (conformance lint beyond the secret gate).

**Scope (crates / surfaces):**
- `plan/logging/OPERATOR_GUIDE.md` (or `docs/`) — default levels, `RUST_LOG` recipes (per-module
  filters), pretty-vs-JSON output, how to read the canonical fields and follow a `request_id`, and the
  file-more-verbose-than-console recipe (ADR-004).
- Gate 5 escalated from advisory to **blocking** (now that Phase 4 normalized the `rvc.`-prefixed sites
  and the field set has stabilized).
- P2, prioritized and as capacity allows:
  - P2-1 log sampling for the highest-volume `trace`/`debug` sites (the volume backstop under large
    validator counts).
  - P2-2 dynamic level reload (`tracing_subscriber::reload`), coordinated with the existing reload
    machinery in `bin/rvc-signer`.
  - P2-3 a documented JSON output profile as a first-class production/aggregation mode.
  - P2-4 a per-crate conformance lint beyond the secret gate (`dylint` dataflow is the P2 nightly
    escalation; not a P0 requirement).

**Key deliverables:**
- `OPERATOR_GUIDE.md` merged.
- Gate 5 blocking.
- P2 items as capacity allows (each independently shippable; none blocks closing the initiative's P0/P1
  commitment).

**Exit criteria (measurable):**
- [ ] `OPERATOR_GUIDE.md` exists, is reviewed, and is merged; covers default levels, `RUST_LOG`
      recipes, pretty-vs-JSON, reading canonical fields, following a `request_id`, and the
      file-vs-console recipe.
- [ ] Gate 5 escalated to blocking: a non-canonical field key on the covered surface now fails CI.
- [ ] Any P2 item that is landed leaves the workspace green and is independently shippable; P2 items
      not yet landed are explicitly tracked as deferred, not silently dropped.
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`).

**Phase risks & how the gates de-risk them:**
- *Gate 5 escalated to blocking before the field set is truly stable, blocking unrelated PRs.* — Escalate
  only after Phase 4 normalization lands; the curated set is the contract; `STANDARD.md` documents the
  canonical keys so authors can self-check.
- *P2 scope creep delays closing the initiative.* — P2 is explicitly "as capacity allows"; the P0/P1
  commitment is complete at the end of Phase 4 + the P1-4 doc. P2 items are independent and deferrable.

---

## Milestones

Each phase maps to a milestone with a single, stakeholder-evaluable "done" definition. Milestones are
sequential; each leaves the workspace green and is independently shippable.

| Milestone | Phase | "Done" definition (stakeholder-evaluable) |
|---|---|---|
| **M1 — Standard & Enforcement Substrate** | Phase 1 | `STANDARD.md` merged and referenced from `telemetry`; the `crypto::logging` kit + `telemetry` extractor merged and tested; Gates 1, 2, 6 green. The rubric and the safety net exist *before* any hot-path code changes. |
| **M2 — Hot Paths Observable & Safe** | Phase 2 | Every hot-path step has `trace`; spans carry canonical correlation fields; the :9000 trace is continuous (non-zero-parent test); 0 secret findings on the high-risk crates; the zero-alloc assertion passes; `release_max_level_debug` on both bins. This is the PRD's central operability promise, delivered and proven. |
| **M3 — Operator Parity Across Binaries** | Phase 3 | `bin/rvc` and `bin/rvc-signer` share default level, `RUST_LOG` precedence, and format selection; init parity tests pass in both; OTLP/file/guard contracts unchanged. |
| **M4 — Whole-Workspace Coverage** | Phase 4 | All near-silent crates raised to standard; remaining hot spans instrumented; well-covered crates normalized; no `rvc.`-prefixed keys remain; Gate 5 advisory green. The PRD's breadth metrics hit 100%. |
| **M5 — Operability Documented & Polished** | Phase 5 | `OPERATOR_GUIDE.md` merged; Gate 5 blocking; P2 items landed as capacity allows (or explicitly deferred). The initiative's P0+P1 commitment is fully delivered. |

The **P0 commitment** (the must-haves) is complete at **M3** (P0-1 in M1; P0-2/3/4/6 in M2; P0-5 in
M3). The **P1 commitment** is complete at **M4** plus the M5 operator guide. **P2** is M5 best-effort.

---

## Dependency Graph

### Phase-level dependencies

```text
Phase 1 (Standard + primitives + gates)
   │   ├── STANDARD.md ............ the rubric all later phases are reviewed against
   │   ├── crypto::logging kit .... TruncatedRoot / fields / new_request_id / record_*
   │   ├── set_parent_from_headers  (lands the fn; wiring is Phase 2)
   │   └── Gates 1/2/6 ............ fail-closed enforcement live before any code change
   │
   ├─────────────▼ (HARD: primitives + gates + standard must land first)
   │
Phase 2 (Hot paths + safety)
   │   ├── consumes the kit (redaction, fields, request_id) — no reinvented code
   │   ├── WIRES set_parent_from_headers into the :9000 handler  ◀── the bridge
   │   ├── adds rvc-signer-bin → telemetry (the one new edge; Gate 6 already green)
   │   ├── Gate 3 (captured-subscriber) + Gate 4 (zero-alloc) land here
   │   └── release_max_level_debug on both bins
   │
   ├─────────────▼ (SOFT: Phase 3 is independent of Phase 2's hot-path edits, but
   │                      shares the telemetry-helper work and the new bin→telemetry edge,
   │                      so it is cleaner to sequence after Phase 2)
   │
Phase 3 (Init consistency)
   │   └── env_filter_or helper in telemetry + init parity tests in both bins
   │
   ├─────────────▼ (HARD on Phase 1 standard + kit; SOFT on Phase 2 — breadth crates
   │                      adopt the same kit and are normalized against the same standard)
   │
Phase 4 (Breadth + normalization)
   │   ├── gap crates call the Phase 1 kit; measured against STANDARD.md
   │   ├── completes the namespace normalization begun in Phase 2 (no rvc.* anywhere)
   │   └── Gate 5 wired ADVISORY (curated hot-path event set)
   │
   ├─────────────▼ (HARD: Gate 5 → blocking only after Phase 4 stabilizes the field set)
   │
Phase 5 (Docs & polish)
       ├── OPERATOR_GUIDE.md
       ├── Gate 5 → BLOCKING
       └── P2 (sampling / reload / JSON profile / conformance lint) — best-effort
```

### The load-bearing cross-phase dependencies (call these out explicitly)

1. **Phase 1's primitives + gates must land before Phase 2's hot-path adoption.** Every Phase 2 change
   *calls* `TruncatedRoot`/`fields`/`new_request_id`/`record_*` and is measured by Gates 1/3/4. Adopting
   hot-path logging before the kit exists would force per-crate reinvention and unmeasured changes —
   the exact drift the enforcement-first sequencing prevents.
2. **`set_parent_from_headers` (the inbound extractor) blocks the :9000 end-to-end correlation.** The
   function lands in Phase 1; it is *wired* into the `bin/rvc-signer` `sign` handler in Phase 2. Until
   wired, the :9000 `sign` span starts a fresh root trace and the duty trace breaks at the boundary. The
   non-zero-parent test is the proof that the bridge is in place.
3. **Gate 5 escalation (advisory → blocking) depends on Phase 4 namespace normalization.** Making
   field-name conformance blocking before the `rvc.`-prefixed sites are normalized would fail the
   workspace on the very sites Phase 4 fixes. Hence Gate 5 is advisory in Phase 4 and blocking in
   Phase 5.
4. **The single new production edge `rvc-signer-bin → telemetry` is introduced in Phase 2** (to call
   the extractor and the init helper). Its acyclicity is guaranteed by `telemetry` being a
   zero-internal-dep leaf, and the DAG gate's policy tables are pre-extended in Phase 1 to lock it.

### Per-crate readiness tiers (from the architecture — drives intra-phase ordering)

- **Ready now (just call the kit + normalize):** `crates/rvc`, `bin/rvc`, `bin/rvc-signer`, `signer`,
  `bn-manager`, `slashing`, `crypto`. These already depend on `crypto`/`telemetry`; no new edge to
  adopt. They are the bulk of Phase 2 (hot-path) and the normalization half of Phase 4.
- **Bridge-blocked:** the :9000 correlation cannot be end-to-end until `set_parent_from_headers` lands
  (Phase 1) **and** is wired (Phase 2); the `signer` gate correlation depends on the same bridge. This
  is the dependency that forces the extractor to land before the :9000 adoption.
- **Greenfield (near-silent, add to standard):** `rvc-keygen`, `signer-registry`, `eth-types`,
  `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`. Mechanical, low-risk,
  kit-backed — the breadth half of Phase 4. (`rvc-keygen` is greenfield for breadth but **high-risk**
  for the mnemonic redaction rule, so its redaction conformance is pulled forward into Phase 2's
  high-risk-crate sign-off.)

---

## Risk Register (cross-phase)

Phase-local risks are listed under each phase. The cross-cutting risks below span the initiative:

| Risk | Impact | Likelihood | Mitigation (and which gate owns it) |
|---|---|---|---|
| Secret leakage via a new log statement (esp. `crypto`/`secret-provider`/`signer`/:9000/`rvc-keygen`) | High (security incident) | Medium | Defense-in-depth: type layer + Gate 1 (clippy sinks) + Gate 3 (runtime absent) + Gate 2 (emitted scan) + high-risk-crate sign-off; fail-closed at 0 findings (Phase 1 substrate, Phase 2 proof) |
| `disallowed-methods` blind spot (value laundered into a `String`) | Medium (a bypass the lint can't see) | Low | Type layer makes the implicit path impossible; Gate 3 tests the runtime result; Gate 2 scans emitted output; stated as a known limitation; P2 `dylint` is the dataflow upgrade |
| Hot-path latency regression / reintroduced eager `hex::encode` (R1 trap) | High (missed duties / slashing-deadline pressure) | Medium | Gate 4 counting-allocator zero-alloc test (precise); `TruncatedRoot(&[u8])` replaces the eager encode; `release_max_level_debug`; `enabled!` guards + `Display` wrappers; `criterion` sanity bench |
| `#[instrument(fields(...))]` eager evaluation (R1) sneaks in expensive work | Medium (silent per-call cost even when span disabled) | Medium | House rule: scalars-only in instrument `fields`, redaction wrappers on event macros / `record()`; Gate 4 catches sign/slot paths; reviewer rule + Gate 5 |
| R3 fix or namespace rename applied at the wrong site (`gate.rs` vs `lib.rs`) | Medium (blocking-section events stay detached; dashboards split on `rvc.slot` vs `slot`) | Medium | ADR-008 pins the verified `lib.rs` sites and binds the R3 fix to the namespace normalization at the same sites; Gate 3 asserts events carry the span's correlation fields |
| Vanishing late-bound attribute (`record()` on an undeclared field) | Medium (missing correlation in traces) | Medium | `record_display`/`record_debug` helpers + house rule "declare every late-bound field `field::Empty`"; Gate 3 asserts recorded fields present |
| Field-name conformance is advisory in P0 (the one under-enforced rule) | Low–Medium (style/key drift on crates outside the curated set) | Medium | Honestly flagged (not sold as a guarantee); `STANDARD.md` is the review rubric; Gate 5 escalates to blocking in Phase 5; `fields` consts make keys greppable |
| A future edit adds a dependency cycle (e.g. `eth-types → uuid`/`telemetry`) | High (build break / inverted layering) | Low | Gate 6 (`architecture-tests`) pins `rvc-eth-types` to zero out-edges and the graph acyclic; policy tables locked in Phase 1; primitives live in `crypto::logging`, removing the temptation |
| Init reconciliation silently changes default verbosity/format for `bin/rvc-signer` | Medium (operator surprise) | Medium | ADR-003 documents precedence/default; init parity tests in both bins (Phase 3) |
| `gitleaks` false positives block PRs | Low (CI friction) | Medium | Tune gitleaks config (allow-list test fixtures); `trufflehog` verification-first as a scheduled deep sweep, not the blocking gate |
| Breaking the existing OTLP/file/propagation stack | High (lost telemetry) | Low | Non-Goal to redesign `telemetry`; only additive (`set_parent_from_headers`, `env_filter_or`); `TracingGuard`/shutdown/sampler/exporters untouched; existing tests stay green |
| `cargo test --workspace` deadlock masks results | Medium (false confidence) | Medium (if the wrong runner is used) | `cargo nextest run --workspace` is the runner of record (project history); standing invariant in every phase |

---

## Technical Spikes / Open Questions

The architecture forwards eight implementation-gate questions; none blocks Phase 1, and each has a
recommended default. They are folded into the phase that resolves them:

- **Phase 1 spike — `telemetry` naming `http::HeaderMap` without a new dep** (architecture Open Q1):
  confirm `telemetry` can write the `Extractor` over `&http::HeaderMap` (re-exported by both `axum` and
  `reqwest`) without a direct `axum`/`http` dependency. If a direct `http` dep is needed, it is a
  leaf-internal external dep (no internal edge, no cycle) — acceptable. *Resolve while building the
  extractor.*
- **Phase 1/2 confirmation — static cap `release_max_level_debug` vs `_info`** (architecture Open Q3,
  ADR-001): recommended `_debug` (operators escalate to `debug` in prod via `RUST_LOG` without a
  rebuild). *Confirm at the Phase 2 bench.*
- **Phase 2 confirmation — `request_id` carrier** (architecture Open Q6, ADR-002): `x-request-id` header
  (recommended) vs deriving from the OTel trace/span id; confirm the operators' tooling reads the
  header. *Recommended default accepted unless an operator constraint surfaces.*
- **Phase 2 decision — gitleaks emitted-sample harness shape** (architecture Open Q5): reuse the
  captured-subscriber tests for the emitted sample, or a dedicated tiny `trace`-level dump harness?
  Recommended: reuse first, add a harness only if coverage gaps appear.
- **Phase 2/3 spike — coarse-span granularity on the hottest async fns** (architecture Open Q7): confirm
  phase boundaries with the orchestrator owners (one span per phase, not per inner `.await`) to bound
  the *enabled* per-poll enter/exit cost under large validator counts.
- **Phase 3 confirmation — file-independent level for `bin/rvc-signer`** (architecture Open Q2, ADR-004):
  confirm the `logroller`/non-blocking path honors an independent file level for `bin/rvc-signer` before
  defaulting `logfile_level` to `debug`; if not, fall back to file == console (documented, not assumed).
- **Phase 4 decision — Gate 5 escalation timing** (architecture Open Q4): advisory in Phase 4, blocking
  in Phase 5 after the `rvc.`-prefixed sites are normalized and the field set stabilizes.
- **Phase 5 confirmation — production output default** (PRD Open Q4 / architecture Open Q8): keep pretty
  as the production default, document JSON as the sanctioned aggregation profile (P2-3); confirm with
  operators.

The PRD's six Open Questions stand and are resolved-to-stricter per the architecture (pubkeys truncated
even at `trace`; full roots/signatures truncated/omitted by default via `TruncatedRoot`; spans-first
with the flat-backend `request_id`-on-terminal-event mitigation held in reserve).

---

## Decision Log (planning-level)

These are the *planning* decisions made in turning the architecture into this phased plan. The
*technical* decisions are the architecture's nine ADRs (ADR-001…ADR-009), which are authoritative and
not re-litigated here.

| Decision | Rationale |
|---|---|
| **Enforcement-and-primitive-first sequencing** (standard + kit + gates as Phase 1, before any hot-path code) | Every later change is then measured against a landed rubric, checked by a fail-closed gate, and merely *calls* shared code — preventing per-crate reinvention and unmeasured drift. This is the architecture's explicit rollout stance, adopted as the plan's spine. |
| **Map architecture Phase 0–4 to plan Phase 1–5 one-to-one** (no re-decomposition) | The architecture's rollout is already dependency-ordered and each phase is independently shippable and green. Re-inventing the phasing would discard verified work and risk diverging from the gate-to-rule traceability. |
| **Pull `rvc-keygen` redaction conformance forward into Phase 2** (high-risk), while its breadth lands in Phase 4 | The architecture treats `rvc-keygen` (mnemonic/`bip39`) as a high-risk redaction boundary even though the PRD lists it under P1 breadth. Its redaction sign-off belongs with the other high-risk crates in Phase 2; the rest of its `info`/`debug`/`trace` breadth is mechanical and fits Phase 4. |
| **Phase 3 (init consistency) sequenced after Phase 2, not before** | Phase 3 is technically independent of Phase 2's hot-path edits, but it shares the `telemetry`-helper work and the new `bin/rvc-signer → telemetry` edge that Phase 2 introduces; sequencing it after keeps that edge and the helper landing once. (It could be parallelized in a multi-stream model; this plan assumes single-stream by default.) |
| **Gate 5 advisory in Phase 4, blocking in Phase 5** | Making field-name conformance blocking before Phase 4 normalizes the `rvc.`-prefixed sites would fail the workspace on the very sites Phase 4 fixes. Advisory-then-blocking is the only safe ordering. |
| **No time estimates; relative phase sizing only** | Per the planning brief and repo conventions, sizing is relative. Indicative sizing: Phase 1 medium (docs + kit + gate wiring), Phase 2 **large** (the hot-path bulk + the bridge + two net-new test harnesses), Phase 3 small–medium, Phase 4 **large** (breadth across ~8 gap crates + normalization), Phase 5 small–medium + best-effort P2. |
| **P0 done at M3, P1 done at M4 + the M5 operator guide, P2 best-effort** | Makes the "what must ship" boundary explicit for stakeholders: the must-haves (P0) close at the end of Phase 3; the should-haves (P1) close with Phase 4 + P1-4; the nice-to-haves (P2) are deferrable. |
| **Single-stream execution by default** | Per the task constraints. The dependency graph identifies where parallelism *could* be introduced (Phase 3 vs Phase 2; the greenfield vs ready-now tiers within Phase 4) if a multi-stream model is later chosen. |

---

## Assumptions

Carried verbatim-in-spirit from the architecture's verified assumptions and the research's consolidated
assumptions (the architecture marked graph/file facts **verified** against the tree at `develop`; this
plan re-confirmed the workspace shape — 23 crates + 3 binaries — and the bare `clippy.toml`
`msrv = "1.92"`). Items this plan additionally assumes are marked **(plan)**.

1. The existing `telemetry` stack (init, config, `file_appender`, `propagation`, `shutdown`, the
   `ParentBased(TraceIdRatioBased)` sampler, `TracingGuard`) is correct and stays the foundation; this
   composes into it. Versions: `tracing` 0.1 / `tracing-subscriber` 0.3 / `tracing-opentelemetry` 0.32 /
   `opentelemetry*` 0.31.
2. The PRD's settled decisions are authoritative and not re-opened: `snake_case`, spans-first, the
   5-level taxonomy, `TruncatedPubkey = 0x{first10}...{last8}`, `info` = production default,
   `RUST_LOG`/`EnvFilter` env-overrides-config.
3. **(verified)** `crypto::logging` is the correct home for the light primitives — `crypto` already
   hosts `TruncatedPubkey`/`RedactedUrl`, carries `uuid`/`hex`/`url`/`reqwest`/`eth-types`, has no
   `telemetry`/OTel edge, and is depended on by every signing-adjacent crate.
4. **(verified)** `telemetry::propagation` is the correct home for the inbound extractor and the
   `env_filter_or` helper — it owns the outbound `inject_trace_context` and the OTel deps and depends on
   no workspace crate. `bin/rvc-signer` gains a single additive `→ telemetry` production edge, which is
   acyclic (leaf attachment).
5. **(verified)** The `architecture-tests` DAG gate exists and rides CI, pins `rvc-eth-types` /
   `rvc-signer-registry` to zero out-edges, and stays green for the new edge. `clippy.toml` is bare
   `msrv = "1.92"`, so Gate 1 rides the existing `-D warnings` step.
6. `release_max_level_debug` is the chosen static cap (ADR-001): `trace` compiled out of release,
   `debug` runtime-switchable. Confirm vs `release_max_level_info` at the Phase 2 gate.
7. Pubkeys are truncated even at `trace`; full signing roots/signatures are truncated/omitted by default
   (PRD Open Qs 1 & 2 resolved-to-stricter), with `TruncatedRoot(&[u8])` as the primitive. `network`
   stays a resource attribute, never duplicated per event.
8. **(verified)** `x-request-id` is an acceptable additive carrier alongside W3C `traceparent`; the
   `keymanager-api` precedent mints `Uuid::new_v4()` and logs `request_id = %req_id`.
9. `cargo nextest run --workspace` is the runner of record (`cargo test --workspace` can deadlock). No
   new mandatory toolchain (nightly/`dylint`/`--cfg tracing_unstable`) for P0; those are P2 escalations.
10. The four high-risk crates (`crypto`, `secret-provider`, `signer`, the `bin/rvc-signer` :9000 path)
    plus `rvc-keygen` (mnemonic/`bip39`) are the correct redaction review boundary.
11. **(verified)** The instrumented `sign_*` methods and their `spawn_blocking` closures both live in
    `crates/signer/src/lib.rs` (`:126`/`:209`, `:330`/`:372`); the `rvc.`-prefixed spans/fields are live
    there; the :9000 `sign` handler is already `#[instrument(skip_all)]` and takes
    `axum::http::HeaderMap`; `bin/rvc` already plumbs `logfile_level` into `FileAppenderConfig`.
12. This effort changes only logging/observability — no runtime behavior, public-API, or
    signing/slashing-logic change. The only new wire behavior is inbound trace-context extraction at
    :9000 plus an additive `x-request-id` header.
13. **(plan)** Single-stream execution by default; the phasing is sequential. Where the dependency
    graph permits parallelism (Phase 3 vs Phase 2; greenfield vs ready-now tiers within Phase 4), it is
    noted but not assumed.
14. **(plan)** Each phase is independently shippable and leaves the workspace green; a phase is "done"
    only when its exit criteria — including the standing `fmt`/`clippy -D warnings`/`nextest`
    invariants — are met.
