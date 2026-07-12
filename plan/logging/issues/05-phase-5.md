# Phase 5: Docs & Polish — Operability and P2

> Self-contained issue breakdown for **Phase 5** of the rs-vc structured
> logging & observability initiative. Estimated by an engineering lead against
> the tree at `develop`. A code-writer should be able to work this phase from
> this file alone. Sources: [`project-plan.md`](../project-plan.md) §"Phase 5"
> + Milestone **M5** + the Phase 5 dependency-graph node;
> [`prd.md`](../prd.md) P1-4 and P2-1..P2-4 + Open Q4; [`architecture.md`](../architecture.md)
> Gate 5, ADR-001/004/006, the Enforcement Architecture, and the
> `OPERATOR_GUIDE.md` module row;
> [`research/00-overview.md`](../research/00-overview.md) §D, §G, R8, and the
> Consolidated Assumptions (`valuable`/`dylint` are P2 escalations).

## Phase Overview

- **Goal:** Close the initiative's operability and polish commitments on top of
  the now-stable field set: (1) ship the operator-facing log documentation
  (P1-4 — the last **P1** deliverable), (2) escalate the canonical-field-name
  conformance gate (Gate 5) from advisory to **blocking** now that Phase 4 has
  normalized the `rvc.`-prefixed sites and the field set has stabilized, and
  (3) land the **P2** nice-to-haves — log sampling, dynamic level reload, a
  documented JSON output profile, and a conformance lint beyond the secret gate
  — as capacity allows, each independently shippable.
- **Maps to:** architecture rollout **Phase 4**; PRD **P1-4** then **P2-1..P2-4**.
- **Priority:** **P1** for 5.1 (operator guide) and 5.2 (Gate 5 blocking — the
  enforcement promise that closes M5's stated bar); **P2** for 5.3–5.6
  (sampling / reload / JSON / extra lint); 5.7 is the closing **chore**.
- **Issue count:** 7 issues, **16 total points**.
- **Estimated duration:** ~11 days, single-stream (one code-writer working in
  order). 5.1, 5.3, and 5.4 are the multi-day issues. **The P0+P1 commitment is
  complete after 5.1 + 5.2;** 5.3–5.6 are explicitly "as capacity allows" and
  any not landed are deferred-not-dropped by 5.7.
- **Entry criteria (all must hold before this phase starts):**
  - **Phase 4 is complete and green (Milestone M4).** Specifically: every gap
    crate is at the standard; remaining hot `#[instrument]` sites are
    instrumented; the well-covered crates are normalized; **no `rvc.`-prefixed
    field/span keys remain anywhere in the workspace** (`slot`, not `rvc.slot`,
    is the emitted attribute key everywhere); and **Gate 5 is wired as an
    advisory captured-subscriber test over a curated hot-path event set** (the
    test exists and is green — Phase 5 only flips its severity and locks its
    coverage). These are the hard preconditions for 5.2.
  - `crypto::logging::fields` (the canonical `snake_case` const registry +
    `Duty` enum) exists and is the single source of truth Gate 5 diffs emitted
    keys against (landed in Phase 1, used through Phases 2–4).
  - `STANDARD.md` is merged and is the human-readable rubric the operator guide
    cross-references; the reconciled subscriber init (Phase 3, ADR-003) is in
    place in **both** binaries (one default level `info`, one `EnvFilter`
    precedence, shared format selection) — the operator guide documents *that*
    reconciled behavior, and the JSON profile (5.5) extends *that* shared format
    selection.
  - Workspace green on the standing invariant: `cargo fmt --all -- --check`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo nextest run --workspace` (**not** `cargo test --workspace`, which can
    deadlock — `nextest` is the runner of record).
- **Exit criteria (all test- or review-backed — these gate phase completion = Milestone M5):**
  1. `OPERATOR_GUIDE.md` exists, is reviewed, and is merged; it covers default
     levels, `RUST_LOG`/per-module filter recipes, pretty-vs-JSON output, how to
     read the canonical fields and follow a `request_id` end to end (including
     across the :9000 hop), and the file-more-verbose-than-console recipe
     (ADR-004). It is discoverable from `docs/running-guide.md`.
  2. **Gate 5 is blocking:** a non-canonical field key on the covered (curated)
     surface now **fails CI** under `cargo nextest run --workspace`; the prior
     advisory escape hatch is removed; the limitation (the curated set is not
     exhaustive for the full 23-crate breadth) is stated in-code and in the doc.
  3. Any **P2** item that is landed leaves the workspace green and is
     independently shippable; **P2 items not landed are explicitly tracked as
     deferred** (in `OPERATOR_GUIDE.md` and/or a tracking note), **not silently
     dropped** (5.7).
  4. The standing invariant holds (`fmt` + `clippy -D warnings` + `nextest`);
     the OTLP / file-appender / sampler / propagation / shutdown / `TracingGuard`
     contracts remain unchanged and their existing tests stay green (this phase
     is documentation + an enforcement-severity flip + additive, opt-in P2
     layers — it changes no runtime signing behavior, no public API, no
     telemetry foundation).

### Assumptions recorded (not blocking; re-check if any changed)

These materially shaped the estimates and the issue boundaries below. They were
verified against the tree at `develop` on the estimation date; the task forbids
asking the user, so they are recorded here.

1. **Phase 4 already shipped Gate 5 as an advisory test** (project-plan Phase 4
   exit criterion + architecture Gate 5: "Land the test form as **advisory** in
   Phase 3 [renumbered Phase 4], escalate to blocking … in Phase 5"). Therefore
   5.2 is a **severity flip + coverage lock**, not authoring the conformance
   harness from scratch — which is why it is 2 points, not 5. If, at phase
   start, the advisory test does **not** exist (Phase 4 slipped it), 5.2 absorbs
   authoring it and rises to ~5 points / should be split; this is called out in
   5.2's Risk note.
2. **No JSON `fmt` profile and no `reload` layer exist today** (verified): both
   binaries build their console layer with `tracing_subscriber::fmt::layer()`
   with no `.json()` and no `reload::Layer` — `bin/rvc/src/main.rs:774`
   (`init_logging`, layer at `:840`, with the `Identity`-padding workaround at
   `:832`/`:840` and its regression-marker test at `:2229`) and
   `bin/rvc-signer/src/main.rs:234`
   (`tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env())`).
   So **P2-3 (JSON) and P2-2 (reload) are net-new, additive layers composed into
   the binaries' `init_logging`** — *not* changes to `crates/telemetry`'s OTLP
   layer (`init.rs`), which stays untouched (PRD/architecture Non-Goal).
3. **`bin/rvc-signer`'s "reload machinery" is a KEYSTORE reloader, not a
   subscriber reloader** (verified): `bin/rvc-signer/src/reload.rs` is
   `KeystoreReloader` (file-watching for key material, opt-in via
   `--enable-hot-reload`), gated behind ISSUE-4.6/L-6 directory-permission
   checks. The project plan's phrase "coordinate with the existing reload
   machinery in `bin/rvc-signer`" (P2-2) therefore means **reuse its opt-in
   flag + `CancellationToken` lifecycle conventions** for a *new* log-level
   reload control, **not** repurpose the keystore reloader. 5.4 builds a
   `tracing_subscriber::reload::Layer` over the `EnvFilter`; it does not touch
   `reload.rs`.
4. **The sampler is `ParentBased(TraceIdRatioBased(config.sample_rate))` with
   `sample_rate` default 1.0** (verified `crates/telemetry/src/init.rs:45`,
   `config.rs:63`). P2-1 (log **sampling**) is about bounding **log-event**
   volume for the highest-volume `trace`/`debug` sites under large validator
   counts — it is **distinct** from this OTLP **trace** sampler, which stays
   exactly as-is (architecture: sampler untouched). 5.3 must not be confused
   with, or alter, the trace sampler.
5. **`docs/running-guide.md` already documents `--log-level`, `RUST_LOG`
   examples (incl. `RUST_LOG=rvc=trace,bn_manager=debug`), and the
   `--tracing-*` OTLP flags** (verified `:79`, `:163`, `:323`–`:326`,
   `:127`–`:135`). `OPERATOR_GUIDE.md` therefore **deepens and cross-references**
   that file (canonical fields, `request_id`-following, pretty-vs-JSON,
   file-vs-console) rather than duplicating the flag tables; 5.1 adds a link
   from `docs/running-guide.md` to the guide so it is discoverable from code's
   existing docs.
6. **P2-4 = `dylint` is a P2 *nightly* escalation, not a P0/P1 requirement**
   (research Consolidated Assumption 8; architecture Gate 5: "A `dylint`
   dataflow lint (nightly) is **P2 only**", "Nightly/`dylint`/`--cfg
   tracing_unstable` are **P2**, never P0 blockers"). 5.6 is therefore scoped as
   a **spike + optional landing behind a non-blocking, non-default CI lane** —
   it must **not** add a mandatory nightly toolchain to the existing `check`
   job. It is the single most deferrable issue in the phase.
7. **JSON output default stays "pretty"; JSON is a sanctioned, documented
   aggregation profile, not the default** (PRD Open Q4 / architecture Open Q8 /
   project-plan: "keep pretty as the production default, document JSON as the
   sanctioned aggregation profile (P2-3)"). 5.5 therefore adds an **opt-in**
   selector (flag/config/env), not a default change.
8. **Gate 5 is the one normative rule honestly flagged as under-enforced for the
   full 23-crate breadth** (architecture Gate 5; project-plan Phase 4 exit
   criterion). Escalating it to blocking does **not** make it exhaustive — it
   makes the **curated** set enforced. 5.2's acceptance criteria reflect this
   bounded promise rather than overclaiming workspace-wide coverage.

## Phase Summary

| Issue | Title | Points | Type | Blocked by | Scope | Files |
|-------|-------|--------|------|------------|-------|-------|
| 5.1 | `OPERATOR_GUIDE.md` operator-facing log documentation (P1-4) | 3 | docs | — (Phase 4 / M4) | 2 days | `plan/logging/OPERATOR_GUIDE.md` (new), `docs/running-guide.md` (cross-ref) |
| 5.2 | Escalate Gate 5 (field-name conformance) advisory → **blocking** | 2 | chore | 5.1 (soft) | 1-2 days | Gate 5 conformance test (Phase-4 site, e.g. `crates/architecture-tests/tests/` or per-crate), `crypto::logging::fields` (read-only) |
| 5.3 | P2-1 log sampling for highest-volume `trace`/`debug` sites | 3 | feature | 5.2 | 2 days | hot-loop sites in `crates/rvc` (per-validator inner loops), `crates/signer`, `crypto::logging` (sampling helper) |
| 5.4 | P2-2 dynamic level reload (`tracing_subscriber::reload`) | 3 | feature | 5.2 | 2 days | `bin/rvc/src/main.rs` (`init_logging`), `bin/rvc-signer/src/main.rs` (`init_logging`), `crates/telemetry/src/init.rs` (helper, optional) |
| 5.5 | P2-3 documented JSON output profile (opt-in) | 2 | feature | 5.4 (soft, shares `init_logging`) | 1-2 days | `bin/rvc/src/main.rs` (`init_logging`), `bin/rvc-signer/src/main.rs`, `OPERATOR_GUIDE.md` |
| 5.6 | P2-4 conformance lint beyond the secret gate (dylint spike) | 2 | spike | 5.2 | 1-2 days | `lint/` (new, optional dylint crate), `.github/workflows/ci.yml` (non-blocking lane) |
| 5.7 | Phase close-out: deferral tracking + full-workspace green gate | 1 | chore | 5.1, 5.2 (+ whichever of 5.3–5.6 landed) | 1 day | `OPERATOR_GUIDE.md` (deferred-items section), workspace-wide gate |

**Total: 7 issues, 16 points.** Every issue is ≤ 3 points (1-2 day scope); none
needs splitting. (5.2 is held at 2 only under Assumption 1 — see its Risk note.)

## Phase Execution Plan

Single-stream: one code-writer works the issues in order. Each day-slot is one
day of work. The **P1 commitment closes at Day 4** (end of 5.2); 5.3–5.6 run as
capacity allows, and 5.7 closes whatever landed.

| Day | Issue |
|-----|-------|
| 1 | 5.1 `OPERATOR_GUIDE.md` — default levels, `RUST_LOG`/per-module recipes, canonical-field reference |
| 2 | 5.1 cont. — `request_id`-following walkthrough (incl. :9000), pretty-vs-JSON, file-vs-console; cross-ref from `docs/running-guide.md` |
| 3 | 5.2 — flip the Phase-4 advisory conformance test to blocking; lock the curated event set; add a RED test (a deliberate `val_idx` key fails CI) |
| 4 | 5.2 cont. — state the bounded-coverage limitation in-code + doc; workspace green (**P1 commitment complete here**) |
| 5 | 5.3 P2-1 sampling — add the per-N / rate sampling helper; apply to the curated highest-volume `trace`/`debug` loop sites |
| 6 | 5.3 cont. — prove zero-cost-when-disabled is preserved (Gate 4 still green); bounded-volume test |
| 7 | 5.4 P2-2 reload — `reload::Layer` over `EnvFilter` in both bins' `init_logging`; opt-in trigger reusing the rvc-signer opt-in/lifecycle conventions |
| 8 | 5.4 cont. — reload-applies test (raise a target's level at runtime, assert effect); preserve `Identity`-padding + init parity |
| 9 | 5.5 P2-3 JSON — opt-in `.json()` fmt profile selector in both bins; document in `OPERATOR_GUIDE.md` |
| 10 | 5.6 P2-4 dylint spike — evaluate feasibility; land behind a **non-blocking** nightly CI lane or file a deferral |
| 11 | 5.7 — deferral tracking for any unland P2; final full-workspace green gate |

## Dependency Map

```text
(Phase 4 / M4 complete: no rvc.* keys remain; Gate 5 ADVISORY test green; fields registry stable)
        │
        ▼
   Issue 5.1 (OPERATOR_GUIDE.md, P1-4)
        │
        ▼
   Issue 5.2 (Gate 5 → BLOCKING, P1)      ◀── HARD on M4 (rvc.* normalized) + advisory test existing
        │   └── P0+P1 commitment COMPLETE here
        ├───────────────┬───────────────┬───────────────┐
        ▼               ▼               ▼               ▼
   Issue 5.3        Issue 5.4        Issue 5.6      (5.5 depends on 5.4: shares init_logging)
   (P2-1            (P2-2 reload)    (P2-4 dylint        │
    sampling)            │            spike)             ▼
        │               └───────────────────────▶  Issue 5.5 (P2-3 JSON profile)
        │                                               │
        └───────────────┬───────────────────────────────┘
                        ▼
                   Issue 5.7 (deferral tracking + full-workspace green gate)
                   (gates whatever of 5.3–5.6 actually landed; deferred items tracked, not dropped)
```

`5.1 → 5.2` is a **soft** ordering (the doc is the rubric authors self-check
against once Gate 5 blocks; landing the doc first is cleaner, but the two are
technically independent). `5.2 → {5.3, 5.4, 5.6}` is **soft** sequencing only
(P2 work should land on a workspace where conformance is already enforced).
`5.4 → 5.5` is a **soft** real coupling: both edit the same `init_logging`
format-selection code in both binaries, so sequencing them avoids a merge
collision on those functions. `5.7` is **hard** on 5.1 + 5.2 and gates whichever
P2 issues landed.

## Risk Flags (phase-local)

- **Gate 5 advisory test may not actually exist at phase start (5.2) — MEDIUM,
  the main estimate risk.** 5.2 is sized at 2 points *assuming* Phase 4 shipped
  the advisory captured-subscriber conformance test (Assumption 1 / project-plan
  Phase 4 exit criterion). If Phase 4 deferred it, 5.2 must author the harness +
  the curated event set + the field-diff logic from scratch and rises to ~5
  points — at which point split it into "5.2a author advisory test" and "5.2b
  flip to blocking". **Mitigation:** confirm the advisory test is present and
  green as the first action of 5.2; if absent, re-estimate before starting.
- **Escalating Gate 5 to blocking surfaces a stray non-canonical key on the
  curated surface (5.2) — LOW–MEDIUM.** The flip can fail CI on a real key that
  slipped Phase 4 normalization. This is the gate working as intended, but it
  can block the phase. **Mitigation:** run the conformance test in blocking mode
  locally first; fix any flagged key (it is a one-line rename to the
  `crypto::logging::fields` canonical key) before pushing; the limitation note
  documents that only the *curated* set is enforced, so an out-of-set key is not
  a phase blocker.
- **P2 sampling silently re-introduces an eager allocation / breaks the
  zero-cost-when-disabled invariant (5.3) — MEDIUM.** A naive per-N counter or a
  sampling wrapper computed *into a local* before the level check would
  re-introduce exactly the R1 trap Phase 2's Gate 4 (counting-allocator
  zero-alloc test) exists to catch. **Mitigation:** the sampling decision must
  sit behind the level/`enabled!` check (so a disabled site never samples), and
  5.3 must re-run Gate 4 to prove `allocs_when_disabled == baseline` is still
  true after the sampling sites land. This is an explicit acceptance criterion.
- **Dynamic reload changes default verbosity or breaks the `Identity`-padding /
  init parity (5.4) — MEDIUM.** Wrapping the `EnvFilter` in a `reload::Layer`
  must not change the unset-`RUST_LOG`→`info` default or the empty-`Vec<Layer>`
  `Identity`-padding short-circuit that `bin/rvc`'s `init_logging` relies on
  (`main.rs:832`), nor regress the Phase-3 init parity tests. **Mitigation:**
  preserve the reconciled `env_filter_or(level)` precedence as the reload
  layer's *initial* value; re-run the init parity tests (both bins) and the
  `init_logging regression marker` test (`main.rs:2229`) as acceptance criteria.
- **P2 scope creep delays closing the initiative (5.3–5.6) — MEDIUM, by design
  bounded.** P2 is explicitly "as capacity allows"; the P0/P1 commitment is
  complete after 5.2. **Mitigation:** 5.7 makes deferral first-class — any P2
  item not landed is tracked as deferred (not dropped), and the phase can close
  on 5.1 + 5.2 + 5.7 alone with 5.3–5.6 deferred. Do **not** let any P2 item
  block the others; each is independently shippable.
- **dylint adds a mandatory nightly toolchain (5.6) — LOW but a hard Non-Goal if
  it happens.** P2-4 must not make nightly/`dylint`/`--cfg tracing_unstable` a
  P0 blocker on the existing `check` job. **Mitigation:** 5.6 lands (if at all)
  only as a separate, non-blocking, allow-to-fail CI lane; the stable
  `fmt`/`clippy -D warnings`/`nextest` invariant is never gated on it.

---

## Issues

### Issue 5.1: `OPERATOR_GUIDE.md` — operator-facing log documentation (P1-4)

- **Points:** 3
- **Type:** docs
- **Priority:** P1 (the last P1 deliverable; required for Milestone M5)
- **Blocked by:** none (needs Phase 4 / M4 complete so the documented fields and
  the normalized `slot`-not-`rvc.slot` keys are final)
- **Blocks:** Issue 5.7 (and soft-blocks 5.2; 5.5 appends to it)
- **Scope:** 2 days

**Description:**
Author the operator-facing log documentation the PRD requires (P1-4) and the
architecture homes at `plan/logging/OPERATOR_GUIDE.md`. It is the SRE/operator
counterpart to `STANDARD.md` (which is the author/reviewer rubric): it teaches an
operator how to read the rs-vc log stream and OTLP traces, set verbosity, and
follow a single duty/request end to end. It must document the **reconciled**
(Phase 3 / ADR-003) behavior — one default level (`info`), one `EnvFilter`
precedence (env `RUST_LOG` overrides the config/flag default), shared format
selection across both binaries — and the file-more-verbose-than-console recipe
(ADR-004). It deepens, and cross-references, the existing `docs/running-guide.md`
(which already lists the `--log-level`/`RUST_LOG`/`--tracing-*` flags) rather
than duplicating its flag tables.

**Implementation Notes:**
- Files likely affected:
  - `plan/logging/OPERATOR_GUIDE.md` (new) — the guide. Required sections:
    1. **Default levels & precedence** — `info` is the production default; env
       `RUST_LOG` overrides the configured default; both binaries behave
       identically (cite the Phase-3 reconciliation / ADR-003). Note that
       `trace!` is compiled out of `--release` (`release_max_level_debug`,
       ADR-001) so escalating to `trace` in prod requires a debug/test build,
       while `debug` stays runtime-switchable via `RUST_LOG`.
    2. **`RUST_LOG` recipes** — per-module filters with concrete rs-vc targets
       (e.g. `RUST_LOG=rvc=debug`, `RUST_LOG=rvc=trace,bn_manager=debug`,
       `RUST_LOG=rvc_signer_bin::http_api=trace`), matching the directive style
       already shown in `docs/running-guide.md:323`–`:326`.
    3. **Canonical fields reference** — reproduce the canonical field registry
       (slot/epoch/validator_index/committee_index/subcommittee_index/pubkey/
       duty/request_id/bn_url/head/block_root/time_into_slot; `network` is a
       resource attribute) from `STANDARD.md`, explaining what each means to an
       operator and that pubkeys are **always truncated** (`0x{first10}...{last8}`)
       and URLs **always redacted** — even at `trace`.
    4. **Following a `request_id`** — a worked walkthrough of grepping one
       signing/API request end to end, including **across the :9000 Web3Signer
       boundary** (the `x-request-id` header echo + the W3C `traceparent`
       continuity from the Phase-2 bridge), and the equivalent in an OTLP
       backend (filter by `request_id` span attribute / trace id).
    5. **The `info` heartbeat** — what a healthy client's `info` stream looks
       like (the milestone narrative from `STANDARD.md` §G: validators loaded,
       BN connected, epoch boundary, attestation/aggregate published, block
       proposed, sync-committee message/contribution, validator registration,
       optional per-slot tick), so an operator can alert on its absence.
    6. **Pretty vs JSON output** — pretty is the default; JSON is the sanctioned
       aggregation profile (forward-reference 5.5 / P2-3; if 5.5 has not landed
       yet, document it as "planned" and have 5.5 fill it in).
    7. **File-more-verbose-than-console recipe (ADR-004)** — how to set the file
       layer to `debug` while the console stays `info` via the existing
       `logfile_level` plumbing (`bin/rvc` already supports it; note the
       `bin/rvc-signer` status per Phase 3's confirmation).
  - `docs/running-guide.md` — add a short pointer (a one-line link near the
    `--log-level`/`RUST_LOG` section at `:79`/`:323`) to `OPERATOR_GUIDE.md` so
    the guide is discoverable from the existing user docs (PRD P1-4 "referenced"
    / discoverability).
- Keep it **short and example-driven** (the same product framing as
  `STANDARD.md`): copy-paste `RUST_LOG` lines and a real (redacted) log excerpt
  beat prose. Do not restate the full taxonomy — link to `STANDARD.md`.
- This is documentation only: **no code change** beyond the one cross-reference
  link, so the standing invariant cannot regress here (only `fmt`/markdown).

**Acceptance Criteria:**
- [ ] `plan/logging/OPERATOR_GUIDE.md` exists and contains all seven sections
      above (default levels & precedence, `RUST_LOG` recipes, canonical-field
      reference, following a `request_id` incl. :9000, the `info` heartbeat,
      pretty-vs-JSON, file-vs-console).
- [ ] The documented default level (`info`), `RUST_LOG` precedence (env overrides
      config default), and shared cross-binary behavior **match the actual
      reconciled Phase-3 init** (verify against `bin/rvc`/`bin/rvc-signer`
      `init_logging` after Phase 3; no documented behavior that the code does not
      exhibit).
- [ ] Every `RUST_LOG` recipe and field name in the guide is **consistent with
      `crypto::logging::fields` and `STANDARD.md`** — no `rvc.`-prefixed keys, no
      synonyms (`val_idx`/`validator`), pubkeys shown truncated, URLs redacted.
- [ ] The `request_id`-following walkthrough explicitly shows the :9000 hop
      (`x-request-id` + `traceparent`) and an OTLP-backend equivalent.
- [ ] `docs/running-guide.md` links to `OPERATOR_GUIDE.md` (discoverable from the
      existing user docs).
- [ ] The pretty-vs-JSON section is consistent with 5.5 (or marks JSON "planned"
      with a forward reference if 5.5 has not yet landed).
- [ ] Workspace stays green (`fmt` + `clippy -D warnings` + `nextest`); no code
      behavior change.

**Testing Notes:**
- No automated test (documentation). Verification is review against the live
  `init_logging` behavior and against `STANDARD.md`/`crypto::logging::fields` for
  field/recipe accuracy.
- Sanity-check the `request_id` walkthrough by actually running a `trace`-level
  build, issuing one signing request through :9000, and confirming the same
  `request_id` appears on both sides (the Phase-2 bridge guarantees this) — paste
  the (redacted) excerpt into the guide as the worked example.

---

### Issue 5.2: Escalate Gate 5 (canonical-field-name conformance) advisory → **blocking**

- **Points:** 2
- **Type:** chore
- **Priority:** P1 (closes M5's "Gate 5 blocking" bar; the enforcement promise)
- **Blocked by:** Issue 5.1 (soft — land the operator/author rubric first so a
  flagged key has a documented canonical target); **hard-depends** on Phase 4
  having normalized all `rvc.`-prefixed keys and shipped the advisory test
- **Blocks:** Issues 5.3, 5.4, 5.6 (soft sequencing), Issue 5.7
- **Scope:** 1-2 days

**Description:**
Flip the Phase-4 **advisory** canonical-field-name conformance check (Gate 5) to
**blocking**, now that Phase 4 has normalized the `rvc.`-prefixed sites and the
field set has stabilized (architecture Gate 5; project-plan dependency #3:
"Making field-name conformance blocking before the `rvc.`-prefixed sites are
normalized would fail the workspace on the very sites Phase 4 fixes"). A
non-canonical field key on the curated hot-path event set must now **fail CI**
under `cargo nextest run --workspace`. This is a severity flip plus locking the
curated coverage set — **not** authoring the harness (which Phase 4 shipped, per
Assumption 1).

**Implementation Notes:**
- Files likely affected:
  - The Phase-4 Gate 5 conformance test (confirm its exact location at phase
    start — per the architecture it is a captured-subscriber/`tracing_test` test
    that "rides `nextest`"; it may live alongside the other architecture gates in
    `crates/architecture-tests/tests/` or as a per-crate conformance test). Flip
    it from advisory (e.g. logging/`eprintln!`-warn on a non-canonical key, or a
    `#[ignore]`/soft-assert) to a **hard `assert!`** that fails the test.
  - `crypto::logging::fields` — **read-only** here: it is the canonical key
    source the test diffs emitted field names against. Do not add keys in this
    issue (any genuinely-new canonical key is a `STANDARD.md` + registry change,
    out of scope for the severity flip).
- **Lock the curated set:** make the set of hot-path events the test asserts
  over explicit and stable (a named list/table in the test), so "blocking"
  has a well-defined surface. Add a comment naming each covered event family
  (e.g. the duty span, the sign span, the published-attestation event, the
  failover warn) so a reviewer can see exactly what is enforced.
- **State the limitation in-code and in the doc:** Gate 5 enforces the **curated**
  set, **not** the full 23-crate breadth — this is the one normative rule
  honestly flagged as under-enforced for breadth (architecture). Put a short
  doc-comment to that effect at the top of the test and a one-liner in
  `OPERATOR_GUIDE.md`/`STANDARD.md` so the blocking gate is not mistaken for an
  exhaustive guarantee.
- TDD (RED → GREEN): add a **RED** case first — a deliberately non-canonical key
  (e.g. emit `val_idx = …` on a covered event in a test-only fixture) and assert
  the conformance test **fails** on it; then confirm all real curated events use
  only canonical keys so the gate is **GREEN** on the actual tree.
- Do **not** introduce a new toolchain — Gate 5's blocking form rides the
  existing `nextest` coverage job (the `dylint` dataflow upgrade is 5.6 / P2-4,
  explicitly separate).

**Acceptance Criteria:**
- [ ] The Phase-4 advisory conformance test is now **blocking**: it fails (a hard
      assertion, surfaced under `cargo nextest run --workspace`) when a covered
      event emits a field key not present in `crypto::logging::fields`.
- [ ] **RED proof:** a test-only fixture emitting a non-canonical key (e.g.
      `val_idx`) causes the conformance test to fail; removing it makes it pass
      (demonstrates the gate actually bites).
- [ ] **GREEN on the real tree:** with no synthetic violation, the conformance
      test passes — i.e. every event in the curated set uses only canonical keys
      (this confirms Phase 4's normalization held).
- [ ] The curated covered-event set is explicit and named in the test (a
      reviewer can enumerate exactly what is enforced).
- [ ] The bounded-coverage limitation (curated, not exhaustive for all 23 crates)
      is stated in a doc-comment in the test and referenced in
      `OPERATOR_GUIDE.md`/`STANDARD.md`.
- [ ] No new mandatory toolchain; the gate rides the existing `nextest` job.
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`); the other
      five CI gates (1/2/3/4/6) are unaffected.

**Testing Notes:**
- **First action:** confirm the advisory test exists and is green (Assumption 1).
  If it does not exist, stop and re-estimate — this issue then absorbs authoring
  it and should be split (see phase Risk Flags); do not silently expand it to
  5 points inline.
- Run the test in blocking mode locally before pushing to catch any stray
  non-canonical key on the curated surface (the gate working as intended); fix
  any flagged key by renaming to the `crypto::logging::fields` canonical key.

---

### Issue 5.3: P2-1 — log sampling for the highest-volume `trace`/`debug` sites

- **Points:** 3
- **Type:** feature
- **Priority:** P2 (as capacity allows)
- **Blocked by:** Issue 5.2 (soft — land P2 on an enforced-conformance tree)
- **Blocks:** Issue 5.7
- **Scope:** 2 days

**Description:**
Bound log-event volume for the highest-volume `trace`/`debug` sites (the
per-validator inner loops) so that enabling verbose levels under a large
validator count does not flood the log stream (PRD P2-1; the volume backstop in
the architecture and research Assumption 3). This is **log-event sampling** —
emit 1-in-N (or rate-limited) for a designated high-volume site — and is
**distinct from** the OTLP **trace** sampler in `crates/telemetry`, which is
untouched (Assumption 4).

**Implementation Notes:**
- Files likely affected:
  - `crypto::logging` — a tiny, dependency-light sampling helper (e.g. a
    per-call-site `AtomicU64` counter behind a `sample_every(n)` /
    `should_log_sampled()` predicate, or a documented use of an existing
    `tracing` sampling pattern). Place it next to the kit so the highest-volume
    sites can call it without a new edge (consistent with ADR-007 — light
    primitives live in `crypto::logging`).
  - The curated highest-volume loop sites — per-validator inner loops in the
    orchestrator (`crates/rvc`) and any per-item `trace` loop in `crates/signer`
    flagged during Phases 2/4 as the volume hotspots. Apply sampling **only** to
    those designated sites; do not blanket-sample milestones (`info`).
- **Zero-cost-when-disabled is the hard constraint:** the sampling decision MUST
  sit **behind** the level/`enabled!` check so a disabled `trace!`/`debug!` site
  never even evaluates the sampler (no counter bump, no allocation). Do not
  precompute a sampling decision into a local before the macro — that is the R1
  trap Gate 4 forbids.
- Keep it opt-in per site and documented: a sampled site should be obvious in the
  source (a clear helper call) so an operator reading `OPERATOR_GUIDE.md` knows a
  given high-volume line is sampled, not dropped by accident.
- TDD: write a test asserting that with the level enabled, N calls to a sampled
  site produce ~N/rate emitted events (captured-subscriber count), and a test
  asserting that with the level **disabled** the sampler is never consulted
  (counter unchanged) — i.e. the zero-cost property is preserved.

**Acceptance Criteria:**
- [ ] A sampling helper exists in `crypto::logging` (dependency-light, no new
      crate edge) with a clear, greppable call shape.
- [ ] The designated highest-volume `trace`/`debug` loop sites use it; `info`
      milestones are **not** sampled (the heartbeat stays complete).
- [ ] **Volume bound proven:** a captured-subscriber test shows a sampled site at
      an enabled level emits the expected fraction (≈1-in-N) of events.
- [ ] **Zero-cost-when-disabled preserved:** with the site's level disabled, the
      sampler is not consulted (counter/allocation unchanged); **Gate 4
      (counting-allocator zero-alloc test on the sign + per-slot paths) is
      re-run and still passes** (`allocs_when_disabled == baseline`).
- [ ] The OTLP trace sampler (`crates/telemetry/src/init.rs`,
      `ParentBased(TraceIdRatioBased)`) is **unchanged** — this issue adds no
      change there.
- [ ] Sampled sites are documented in `OPERATOR_GUIDE.md` (so a sampled line is
      not mistaken for a dropped one).
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- Re-running Gate 4 is non-negotiable here — sampling is the most likely P2 item
  to reintroduce an eager allocation; the counting-allocator assertion is the
  precise guard (a ~1 ns sampler branch is below `criterion`'s floor).
- If no single site is hot enough to justify sampling after Phase 2/4
  measurement, this issue may reduce to "document that sampling is available and
  where it would attach" — record that outcome rather than force-fitting a
  sampler; it remains independently shippable / deferrable.

---

### Issue 5.4: P2-2 — dynamic level reload (`tracing_subscriber::reload`)

- **Points:** 3
- **Type:** feature
- **Priority:** P2 (as capacity allows)
- **Blocked by:** Issue 5.2 (soft)
- **Blocks:** Issue 5.5 (soft — shares `init_logging`), Issue 5.7
- **Scope:** 2 days

**Description:**
Let an operator raise (or lower) log verbosity at runtime without restarting the
process (PRD P2-2), by wrapping the `EnvFilter` in a `tracing_subscriber::reload::Layer`
in both binaries' subscriber init and exposing an opt-in trigger to swap the
filter. Per Assumption 3, "coordinate with the existing reload machinery in
`bin/rvc-signer`" means reuse that crate's opt-in-flag + `CancellationToken`
lifecycle conventions for the new control — **not** repurpose the keystore
`KeystoreReloader` (`reload.rs`), which stays untouched.

**Implementation Notes:**
- Files likely affected:
  - `bin/rvc/src/main.rs` (`init_logging`, `:774`) and `bin/rvc-signer/src/main.rs`
    (`init_logging`, `:234`) — wrap the reconciled `EnvFilter` (the Phase-3
    `env_filter_or(level)` value) in `reload::Layer::new(...)`, keep the returned
    `reload::Handle`, and store it so the trigger can call `handle.reload(...)`.
  - Optionally a small helper in `crates/telemetry/src/init.rs` to construct the
    reload layer + hand back the handle (keeps the two binaries' wiring
    identical; consistent with the Phase-3 shared-helper approach). The OTLP
    layer and `TracingGuard` are **not** changed.
  - The trigger surface — the **simplest** opt-in mechanism consistent with the
    repo: e.g. honor a `SIGHUP`/signal or an admin call that re-reads `RUST_LOG`
    and calls `handle.reload`, gated behind an opt-in flag mirroring
    `bin/rvc-signer`'s `--enable-hot-reload`/`reload_interval` opt-in style
    (`main.rs:153`–`:167`). Do **not** add a new network endpoint to the :9000
    surface (that would widen the API — out of scope).
- **Must not regress Phase-3 init:** the reload layer's **initial** value is the
  reconciled `env_filter_or(level)` (unset `RUST_LOG` → `info`, env overrides);
  the empty-`Vec<Layer>` `Identity`-padding short-circuit in `bin/rvc`
  (`main.rs:832`) and the init parity tests must still hold.
- `reload::Layer` has a small always-on cost (an `RwLock` read on the filter);
  confirm this does not violate P0-6 at the default `info` level — if there is
  any measurable effect, gate reload behind the opt-in flag so the default build
  path is unchanged.
- TDD: write a test that initializes with `info`, then calls the reload handle to
  raise a target (e.g. `my_target=debug`) and asserts a `debug!` on that target
  now emits (captured-subscriber), while a non-targeted `debug!` still does not.

**Acceptance Criteria:**
- [ ] Both binaries build their `EnvFilter` inside a `reload::Layer`; a stored
      reload handle can swap the active filter at runtime.
- [ ] **Reload-applies test:** starting at effective `info`, a runtime reload to
      raise a specific target makes that target's `debug!` emit, asserted via a
      captured subscriber; an unrelated target is unaffected.
- [ ] The opt-in trigger reuses `bin/rvc-signer`'s opt-in-flag +
      `CancellationToken` lifecycle conventions; the keystore `reload.rs` is
      **not** modified; no new :9000 endpoint is added.
- [ ] **Phase-3 init parity preserved:** unset `RUST_LOG` still yields `info` in
      both bins; the `bin/rvc` empty-layer `Identity`-padding still emits events
      (the `init_logging regression marker` test, `main.rs:2229`, still passes);
      the Phase-3 init parity tests still pass.
- [ ] The OTLP layer, file appender, sampler, and `TracingGuard`/shutdown
      contracts are unchanged; their tests stay green.
- [ ] If `reload::Layer`'s always-on cost is measurable at `info`, it is gated
      behind the opt-in flag so the default path is unaffected (documented).
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- Keep the trigger minimal and non-networked; a signal handler or a test-only
  direct `handle.reload(...)` call is sufficient to prove the mechanism — the
  operator ergonomics can be documented in `OPERATOR_GUIDE.md` without a heavy
  control plane.
- This is a known-deferrable P2: if the reload-layer cost or the trigger
  ergonomics prove fiddly, defer via 5.7 rather than expanding scope.

---

### Issue 5.5: P2-3 — documented JSON output profile (opt-in)

- **Points:** 2
- **Type:** feature
- **Priority:** P2 (as capacity allows)
- **Blocked by:** Issue 5.4 (soft — both edit `init_logging` format selection;
  sequence to avoid a merge collision)
- **Blocks:** Issue 5.7
- **Scope:** 1-2 days

**Description:**
Promote JSON console output to a first-class, **opt-in**, documented production
aggregation profile (PRD P2-3). The `fmt` layer already supports JSON via
`.json()`; today both binaries build a plain (pretty/full) `fmt::layer()`
(verified — Assumption 2). Add an opt-in selector so an operator can choose JSON
for log-aggregation backends, while **pretty stays the default** (PRD Open Q4 /
ADR — Assumption 7).

**Implementation Notes:**
- Files likely affected:
  - `bin/rvc/src/main.rs` (`init_logging`) and `bin/rvc-signer/src/main.rs`
    (`init_logging`) — branch the `fmt` layer construction on a format selector:
    pretty (default, current `fmt::layer()`) vs JSON (`fmt::layer().json()`,
    optionally `.flatten_event(true)`/`.with_current_span(true)` so span fields
    land as JSON keys for aggregation). The selector is the shared
    format-selection that Phase 3 reconciled across the two bins — extend it,
    keep both bins identical.
  - The selector source — reuse the existing config/flag plumbing (e.g. a
    `--log-format pretty|json` flag / config key / `RVC_LOG_FORMAT` env),
    matching how `--log-level` is already exposed (`docs/running-guide.md:79`).
    Default = pretty.
  - `OPERATOR_GUIDE.md` (5.1) — fill in / finalize the pretty-vs-JSON section:
    when to use JSON, the exact flag/env, and that span fields (the canonical
    correlation fields) appear as JSON keys so `request_id`/`slot` are
    machine-filterable.
- Do **not** change the default (pretty), do **not** touch the OTLP layer or the
  file appender's own format, and do **not** enable `--cfg tracing_unstable` /
  `valuable` (research notes `valuable` structured redaction is a *future* JSON
  enhancement needing the unstable cfg — out of scope here).
- TDD: a test that, with the JSON profile selected, the captured output parses as
  JSON and a known event's canonical fields (e.g. `slot`, `request_id`) are
  present as JSON keys; and a test that the default selection is still pretty.

**Acceptance Criteria:**
- [ ] Both binaries support an **opt-in** JSON output profile via a shared
      format selector; **pretty remains the default** when the selector is
      unset.
- [ ] With JSON selected, emitted output is valid JSON and a representative
      event's canonical correlation fields (e.g. `slot`, `request_id`, `pubkey`
      truncated) appear as JSON keys/values (captured-subscriber/parse test).
- [ ] The default (unset selector) output is unchanged from today's pretty
      format (a test or review confirms no default-behavior change).
- [ ] The OTLP layer, the file appender, and the trace sampler are unchanged; no
      `--cfg tracing_unstable`/`valuable` dependency is introduced.
- [ ] `OPERATOR_GUIDE.md`'s pretty-vs-JSON section documents the selector and the
      JSON-keys-for-aggregation behavior (no longer "planned").
- [ ] Phase-3 init parity and the `Identity`-padding behavior are preserved for
      both profiles.
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- Assert the JSON profile preserves **redaction**: a pubkey field in JSON is the
  truncated form, a URL is redacted — JSON output must not become a redaction
  bypass. (Reuse the Gate-3 captured-subscriber redaction assertions against the
  JSON layer for one high-risk event.)
- If sequencing puts 5.5 before 5.4, that is fine — they only share the
  `init_logging` format-selection code; just rebase to avoid a textual conflict.

---

### Issue 5.6: P2-4 — conformance lint beyond the secret gate (dylint spike)

- **Points:** 2
- **Type:** spike
- **Priority:** P2 (most deferrable item in the phase)
- **Blocked by:** Issue 5.2 (the captured-subscriber Gate 5 is the no-new-toolchain
  baseline this would *augment*, not replace)
- **Blocks:** Issue 5.7
- **Scope:** 1-2 days

**Description:**
Evaluate, and (only if cheaply feasible) land behind a **non-blocking** CI lane, a
per-crate conformance lint that catches non-canonical field names (and similar
on-standard drift) across the **full** workspace — beyond the curated
captured-subscriber Gate 5 and beyond the secret-sink `disallowed-methods` gate
(PRD P2-4). The architecture pins this as a `dylint` **dataflow** lint that needs
a **nightly** toolchain and is therefore **P2 only** (Assumptions 6/8): it must
**not** become a mandatory part of the existing stable `check` job.

**Implementation Notes:**
- This is primarily a **spike**: determine whether a `dylint` lint that flags
  non-`crypto::logging::fields` keys workspace-wide is worth the nightly-toolchain
  cost, and if so, scaffold it minimally.
- Files likely affected (only if landing, not just spiking):
  - `lint/` (new optional `dylint` lint crate, out of the default workspace
    build) — a lint that reads field idents against the canonical
    `crypto::logging::fields` set.
  - `.github/workflows/ci.yml` — a **separate, non-blocking, allow-failure**
    job/lane (its own nightly toolchain), distinct from the stable `check` and
    `coverage` jobs. It must never gate the `fmt`/`clippy -D warnings`/`nextest`
    invariant.
- Hard constraints: no nightly/`dylint`/`--cfg tracing_unstable` on the existing
  mandatory jobs; the stable invariant is untouched. If the spike concludes the
  cost outweighs the benefit (likely, given Gate 5 + `STANDARD.md` already cover
  the curated surface and the review rubric), **document the conclusion and defer
  via 5.7** — a written "not worth it / here's what it would take" outcome is a
  valid, complete result for this issue.
- If landing: keep the lint advisory (informational), since exhaustive field-name
  conformance is explicitly the under-enforced-for-breadth rule the team accepted
  (architecture Gate 5).

**Acceptance Criteria:**
- [ ] A written feasibility conclusion for a workspace-wide `dylint` field-name
      conformance lint (cost of the nightly lane vs. the marginal coverage beyond
      curated Gate 5), recorded in `OPERATOR_GUIDE.md` or a Phase-5 note.
- [ ] **If landed:** the lint lives in an optional `lint/` crate outside the
      default workspace build, runs only in a **separate non-blocking
      allow-failure** CI lane with its own nightly toolchain, and flags a
      non-canonical key in a fixture.
- [ ] **The existing mandatory CI is unchanged:** the stable `check`
      (`cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt`) and
      `coverage` (`nextest`) jobs do **not** depend on nightly/`dylint`; no new
      mandatory toolchain.
- [ ] **If deferred:** the deferral and its rationale are recorded by 5.7 (tracked,
      not dropped).
- [ ] Workspace fully green (`fmt` + `clippy -D warnings` + `nextest`) regardless
      of the spike outcome.

**Testing Notes:**
- The default `cargo nextest run --workspace` / `cargo clippy` runs must not pick
  up the optional `lint/` crate or require nightly — verify by running the
  standing invariant commands on stable and confirming they are unaffected.
- Strongly bias toward "spike + defer": this is the lowest-value, highest-friction
  P2 item; closing it as a documented deferral is the expected outcome unless the
  lint is trivially cheap.

---

### Issue 5.7: Phase close-out — deferral tracking + full-workspace green gate

- **Points:** 1
- **Type:** chore
- **Priority:** P2 (closes Milestone M5)
- **Blocked by:** Issues 5.1, 5.2 (hard) plus whichever of 5.3–5.6 landed
- **Blocks:** none (phase/initiative close)
- **Scope:** 1 day

**Description:**
Close Phase 5 (and the initiative's P0+P1+P2 commitment) by recording the final
state: which P2 items (5.3 sampling / 5.4 reload / 5.5 JSON / 5.6 dylint) landed
and which are **deferred** (explicitly tracked, with rationale — not silently
dropped, per the project plan's Phase 5 exit criterion and the P2 scope-creep
mitigation), and run the final full-workspace green gate confirming the standing
invariant and all six CI gates hold.

**Implementation Notes:**
- Files likely affected:
  - `OPERATOR_GUIDE.md` — a short "Logging roadmap / deferred items" section
    listing each P2 item's status (landed | deferred + why + what it would take),
    so deferral is first-class and discoverable.
  - No source change expected; this is a status + verification gate.
- Confirm the **P0+P1 commitment is fully delivered**: P0-1 (Phase 1), P0-2/3/4/6
  (Phase 2), P0-5 (Phase 3), P1-1/2/3 (Phase 4), P1-4 (5.1) all merged; Gate 5
  blocking (5.2). State this explicitly in the close-out so stakeholders can see
  M5's bar met.
- Run the full standing invariant as the closing gate:
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, `cargo nextest run --workspace` (**not** `cargo test --workspace`).
- Confirm the six CI gates are all green / present: Gate 1 (clippy sinks),
  Gate 2 (gitleaks), Gate 3 (captured-subscriber), Gate 4 (zero-alloc), **Gate 5
  now blocking** (5.2), Gate 6 (DAG).

**Acceptance Criteria:**
- [ ] `OPERATOR_GUIDE.md` has a deferred-items section recording each P2 item
      (5.3/5.4/5.5/5.6) as **landed** or **deferred-with-rationale**; no P2 item
      is silently dropped.
- [ ] A close-out statement confirms the P0+P1 commitment is fully delivered
      (P0-1..P0-6, P1-1..P1-4) and Gate 5 is blocking — i.e. Milestone M5's bar
      is met (P2 best-effort).
- [ ] The full standing invariant passes: `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo nextest run --workspace` all green.
- [ ] All six CI gates are present and green, with **Gate 5 now blocking**; the
      OTLP/file/sampler/propagation/shutdown/`TracingGuard` contracts and their
      tests are unchanged.
- [ ] Any landed P2 item is independently shippable and left the workspace green;
      any deferred item is tracked with a clear "what it would take" note.

**Testing Notes:**
- This issue ships no behavior; verification is the green standing invariant plus
  a review that the deferred-items section is accurate against what actually
  landed in 5.3–5.6.
- If the phase closes on 5.1 + 5.2 + 5.7 alone (all of 5.3–5.6 deferred), that is
  a **valid** completion of the P0+P1 commitment — record the four deferrals and
  close.
