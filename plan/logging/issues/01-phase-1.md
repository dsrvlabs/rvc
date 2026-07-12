# Phase 1: Standard + Primitives + Gate Skeleton

> Foundation phase of the rs-vc structured-logging / observability initiative. Lands the normative
> contract (`STANDARD.md`), the thin shared-primitive surface in `crypto::logging` + `telemetry`, and
> the enforcement skeleton (Gates 1, 2, 6) so every later phase is measured against a landed rubric,
> checked by a fail-closed gate, and merely *calls* shared code.
>
> Authoritative inputs: [`prd.md`](../prd.md), [`architecture.md`](../architecture.md),
> [`project-plan.md`](../project-plan.md). The architecture's nine ADRs are authoritative and not
> re-opened. This phase maps to architecture rollout **Phase 0** and PRD scope **P0-1** plus the
> shared-code + gate substrate that P0-2/3/4/6 depend on. Milestone **M1**.

## Phase Overview

- **Goal:** Land the normative `STANDARD.md`, the `crypto::logging` light-primitive kit
  (`TruncatedRoot`, `fields`/`Duty`, `new_request_id`, `record_display`/`record_debug`), the
  OTel-coupled inbound trace extractor in `telemetry`, and the three fail-closed CI gates that can be
  stood up before any hot-path code changes (Gate 1 clippy `disallowed-methods`, Gate 2 gitleaks,
  Gate 6 DAG policy). This is the substrate the rest of the initiative builds on.
- **Issue count:** 8 issues, 17 total points.
- **Estimated duration:** ~10 days (single-stream default; one code-writer working sequentially).
- **Entry criteria:**
  - PRD, research overview, and architecture approved (all present; this phase is downstream of them).
  - Working tree on `develop`, green on the standing invariant:
    `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and
    `cargo nextest run --workspace`. (`cargo test --workspace` can deadlock — **never** use it.)
  - CI write access to extend `clippy.toml`, `.github/workflows/ci.yml`, and the
    `crates/architecture-tests` policy tables.
- **Exit criteria:**
  - [ ] `STANDARD.md` exists under `plan/logging/`, is reviewed and merged, and `telemetry` carries a
        `//!` module-doc reference to it (PRD P0-1 "referenced from the codebase").
  - [ ] `cargo nextest run --workspace` green including the new `crypto::logging` kit tests;
        `TruncatedRoot` renders a real 32-byte root truncated (`0x{10hex}...{8hex}`) and its full hex
        is **absent** from the rendered output (captured-subscriber test).
  - [ ] `telemetry::propagation::set_parent_from_headers` unit test passes: a synthetic inbound
        `traceparent` produces a **non-zero span parent** (trace continues); an absent/garbled header
        yields a root span with no panic.
  - [ ] Gate 1 green: `cargo clippy --workspace --all-targets -- -D warnings` passes with
        `disallowed-methods` active for the secret-laundering sinks and a scoped, greppable
        `#[allow(clippy::disallowed_methods)]` allow-list at the existing legitimate decrypt/sign sites.
  - [ ] Gate 2 green: a new `gitleaks` PR job runs over the source tree **and** an emitted
        `trace`-level log sample, 0 findings, with test fixtures allow-listed.
  - [ ] Gate 6 green with extended policy tables: production graph acyclic; `rvc-signer-bin →
        rvc-telemetry` accepted as an allowed/expected edge; `rvc-eth-types` and `rvc-signer-registry`
        pinned to zero out-edges.
  - [ ] Workspace fully green on the standing invariant (`fmt` + `clippy -D warnings` + `nextest`).
- **Assumptions recorded for this phase (the task forbids asking the user; defaults accepted per the
  architecture's ADRs and Open Questions):**
  - **A1 — Single-stream execution.** One code-writer works these issues in dependency order. No
    stream-ownership map or scaffold issues (the architecture's plan is single-stream by default;
    decision log).
  - **A2 — `crypto::logging` is the home for the light primitives** (`TruncatedRoot`, `fields`,
    `new_request_id`, `record_*`). Verified: `crypto` already hosts `TruncatedPubkey`/`RedactedUrl`
    (`crates/crypto/src/logging.rs:5`,`:40`), the module is `pub mod logging`
    (`crates/crypto/src/lib.rs:15`), and `crypto` carries `uuid` v4, `hex`, `url`, `tracing` deps
    (`crates/crypto/Cargo.toml:32`,`:15`,`:29`,`:28`) with no `telemetry`/OTel edge (ADR-007).
  - **A3 — `telemetry::propagation` is the home for the inbound extractor.** It owns the outbound
    `inject_trace_context` (`crates/telemetry/src/propagation.rs:25`) and the OTel deps
    (`crates/telemetry/Cargo.toml:14-17`) and depends on no workspace crate. The extractor is written
    against `http::HeaderMap` (re-exported by `reqwest`, already a `telemetry` dep at
    `Cargo.toml:18`) to avoid pulling `axum` into `telemetry` (Open Q1). If a direct `http` dep is
    needed it is a leaf-internal external dep (no internal edge, no cycle) — acceptable.
  - **A4 — `request_id` = `uuid::Uuid::new_v4()`** (ADR-002), matching the in-tree precedent at
    `crates/keymanager-api/src/handlers.rs:348` (`Uuid::new_v4()` logged as `request_id = %req_id`).
  - **A5 — `TruncatedRoot` takes `&[u8]` and hex-renders inside `Display::fmt`** (ADR-005) — never a
    `&str` (which would force an eager `hex::encode`). Glyph `...`, format `0x{10hex}...{8hex}`,
    matching `TruncatedPubkey` (R9).
  - **A6 — This phase lands the extractor function only; wiring it into the :9000 `sign` handler is
    Phase 2.** Likewise `release_max_level_debug`, the counting-allocator zero-alloc test (Gate 4),
    and the captured-subscriber hot-path level/field tests (Gate 3) are Phase 2 — out of scope here.
  - **A7 — Gate-1 secret-sink paths are taken from ADR-001/Gate-1 of the architecture**
    (`secrecy::ExposeSecret::expose_secret`, `rvc_crypto::bls::SecretKey::raw_bytes`,
    `rvc_crypto::bls::SecretKey::to_bytes`). The implementing issue must confirm the exact paths
    against the tree before banning, and `#[allow]` exactly the existing legitimate call sites so the
    workspace stays clippy-green.
  - **A8 — CI shape (verified `.github/workflows/ci.yml`).** A `check` job runs `cargo fmt --all --
    --check` and `cargo clippy --workspace --all-targets -- -D warnings`; a `coverage` job runs
    `cargo llvm-cov nextest --workspace` (installs `cargo-nextest`). Gate 1 rides the `check` job's
    clippy step (no new step); Gate 3/4 conformance + zero-alloc tests (Phase 2) ride the `coverage`
    job's nextest; the gitleaks job (Gate 2) is the single net-new CI job.
  - **A9 — `tracing-test` and `uuid` (v4) are already workspace deps** (`Cargo.toml:125`,`:84`); the
    captured-subscriber model is the in-tree `test_truncated_pubkey_double_0x_prefix_warns_and_falls_back`
    at `crates/crypto/src/logging.rs:119`. No new mandatory toolchain for P0.

## Phase Summary

| Issue | Title | Points | Type | Blocked by | Scope | Files |
|-------|-------|--------|------|------------|-------|-------|
| 1.1 | `STANDARD.md` — normative standard doc + `telemetry` `//!` reference | 3 | feature | — | 1-2 days | `plan/logging/STANDARD.md`, `crates/telemetry/src/lib.rs` |
| 1.2 | `crypto::logging::TruncatedRoot` — zero-alloc `&[u8]` root/sig wrapper | 2 | feature | — | 1 day | `crates/crypto/src/logging.rs` |
| 1.3 | `crypto::logging::fields` — canonical field-key consts + `Duty` enum | 2 | feature | 1.1 | 1 day | `crates/crypto/src/logging.rs` (new `fields` submodule), `crates/crypto/src/lib.rs` |
| 1.4 | `crypto::logging` correlation kit — `new_request_id` + `record_display`/`record_debug` | 2 | feature | — | 1 day | `crates/crypto/src/logging.rs`, `crates/crypto/Cargo.toml` (dev-dep) |
| 1.5 | `telemetry::propagation::set_parent_from_headers` + `HeaderExtractor` | 3 | feature | — | 2 days | `crates/telemetry/src/propagation.rs`, `crates/telemetry/src/lib.rs`, `crates/telemetry/Cargo.toml` |
| 1.6 | Gate 1 — `clippy.toml` `disallowed-methods` secret sinks + allow-list | 2 | chore | — | 1 day | `clippy.toml`, decrypt/sign call sites across `crypto`/`signer`/`secret-provider` |
| 1.7 | Gate 6 — extend `architecture-tests` policy tables for the new edge | 2 | chore | — | 1 day | `crates/architecture-tests/tests/architecture_no_cycles.rs` |
| 1.8 | Gate 2 — `gitleaks` PR job (source + emitted log sample) | 3 | chore | 1.2, 1.4 | 1-2 days | `.github/workflows/ci.yml`, `.gitleaks.toml` (new) |

**Total: 8 issues, 17 points.**

## Phase Execution Plan

Single-stream: one code-writer works the issues in order; each day-slot is one day of work. 1.1
(the rubric) is sequenced first because 1.3 references its field registry and reviewers use it as the
rubric for the rest. 1.2 / 1.4 / 1.5 / 1.6 / 1.7 are mutually independent. 1.8 is sequenced last
because its emitted-log sample harness reuses the `TruncatedRoot` (1.2) and `new_request_id` (1.4)
tests as the trace-level dump it scans (architecture Open Q5: "reuse first").

| Day | Issue |
|-----|-------|
| 1 | 1.1 `STANDARD.md` + `telemetry` `//!` reference |
| 2 | 1.1 cont. |
| 3 | 1.2 `TruncatedRoot` |
| 4 | 1.3 `fields` consts + `Duty` enum |
| 5 | 1.4 correlation kit (`new_request_id` + `record_*`) |
| 6 | 1.5 inbound trace extractor |
| 7 | 1.5 cont. |
| 8 | 1.6 Gate 1 clippy `disallowed-methods` |
| 9 | 1.7 Gate 6 DAG policy tables |
| 10 | 1.8 Gate 2 gitleaks job |

## Dependency Map

```text
1.1 STANDARD.md ───────▶ 1.3 fields/Duty   (registry table is the source of truth for the consts)

1.2 TruncatedRoot  ──┐
                     ├──▶ 1.8 gitleaks      (emitted-log sample harness reuses these tests' output)
1.4 correlation kit ─┘

1.5 extractor        (independent — lands the fn; Phase 2 wires it)
1.6 Gate 1 clippy    (independent)
1.7 Gate 6 DAG       (independent)
```

## Phase Risk Flags

- **1.5 (extractor) carries the only Open Question that could change its shape** (Open Q1: can
  `telemetry` name `http::HeaderMap` without a new dep?). Mitigation: `reqwest` (a `telemetry` dep)
  re-exports `http`; the issue resolves this empirically while building, and a direct `http` leaf-dep
  is the documented fallback. Could be 2x if `reqwest`'s re-export proves insufficient and a new
  external dep + Gate-6 confirmation is needed — flagged.
- **1.6 (Gate 1) risks over-banning legitimate `expose_secret`/`to_bytes` at decrypt/sign sites,
  turning the workspace clippy-red.** Mitigation: scope, don't ban — a small reviewed
  `#[allow(clippy::disallowed_methods)]` at each known site; the lint then flags only *new* uses. The
  issue must enumerate every existing call site (the count is unknown until grepped) — if there are
  many, this can slip toward 3 points; flagged. Stated limitation (in the policy comment): the lint
  matches **named paths only** and cannot see a value laundered into a `String` — accepted because the
  type layer makes the implicit path impossible and Phase 2's Gate 3 covers the emitted result.
- **1.8 (gitleaks) risks false positives blocking PRs.** Mitigation: tune `.gitleaks.toml` to
  allow-list test fixtures (the workspace contains intentional test keystores/keys); keep `trufflehog`
  verification-first as a *scheduled* deep sweep, not the blocking gate. The emitted-log-sample step
  is the load-bearing novel part (proves no secret reached a sink) and may need iteration on the
  harness shape — flagged.

---

## Issues

### Issue 1.1: `STANDARD.md` — normative standard doc + `telemetry` `//!` reference

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** none
- **Blocks:** 1.3 (the `fields` consts mirror this registry); it is the review rubric for every later
  issue/phase.
- **Scope:** 1-2 days

**Description:**
Author the single normative logging standard for the workspace under `plan/logging/STANDARD.md` and
reference it from a `//!` module doc in `telemetry` so it is discoverable from code (PRD P0-1
"referenced from the codebase"). This is the artifact every later change is measured against — it must
be unambiguous, example-driven, and short enough to be read end to end. It is documentation only; no
runtime code changes beyond the `//!` comment.

**Implementation Notes:**
- New file: `plan/logging/STANDARD.md`. Reproduce, as normative sections:
  1. **Level taxonomy** — the 5-level table (`error`/`warn`/`info`/`debug`/`trace`) verbatim from the
     PRD ("Level Taxonomy (Normative)") and architecture ("Level taxonomy + span-instrumentation
     strategy"). Anchor it on the `tracing::Level` docs as the rs-vc *house standard*, not an upstream
     mandate (research R8). Load-bearing rule: *anything that scales with validator count or fires
     per-loop is `debug`/`trace`, never `info`.* Include the cross-cutting `error`-vs-`warn` rule and
     "one event, one level" and "no secrets at any level including `trace`".
  2. **Canonical field registry** — the exact `snake_case` keys with type, where each lives (span vs
     event vs resource attr), and rule, from the architecture's registry table: `slot`, `epoch`,
     `validator_index`, `committee_index`, `subcommittee_index`, `pubkey`, `duty`, `request_id`,
     `bn_url`, `head`, `block_root`, `time_into_slot`, `network` (resource attr). Forbid synonyms
     (`val_idx`, `validator`, `rvc.slot`). Presented as a house standard (SHOULD-level per research R2).
  3. **Secret-redaction policy** — the MUST/MUST-NOT list (BLS private keys / Shamir shares, keystore
     passwords, mnemonics, full signing payloads/signatures, raw credentials in URLs — forbidden at
     **every** level including `trace`) and the mandated primitives (`TruncatedPubkey`, `RedactedUrl`,
     `TruncatedRoot`, `telemetry::config::redact_endpoint`). Name the high-risk crates (`crypto`,
     `secret-provider`, `signer`, the :9000 path, plus `rvc-keygen` mnemonics).
  4. **`#[instrument]` idioms** — the eager-`fields()` rule (research R1: `fields(...)` evaluate on
     every call regardless of span level → scalars only in instrument `fields`, redaction wrappers on
     event macros / `record()`), `skip_all`-first on secret/large-arg fns, `level = "debug"` on hot
     fns, async-correctness (never hold `Span::enter()` across `.await`), `err`-once.
  5. **Worked examples** — a duty span, a sign span, an `enabled!`-guarded trace dump, the
     `field::Empty` + `record()` late-bind pattern. Copy-paste ready.
  6. **`info` heartbeat shape** — the milestone set and the Lodestar-style `Signed`(debug) /
     `Published`(info) split with a `time_into_slot` timing field (architecture data-flow §B).
- `telemetry` `//!` reference: add a line to the crate-level doc in `crates/telemetry/src/lib.rs`
  pointing to `plan/logging/STANDARD.md` as the normative logging contract. Keep it a doc comment
  only — do not add code or a dependency.
- Resolve the PRD Open Questions to the architecture's stricter defaults in the doc: pubkeys truncated
  even at `trace` (Open Q2); full roots/signatures truncated/omitted via `TruncatedRoot` (Open Q1);
  spans-first (Open Q5).

**Acceptance Criteria:**
- [ ] `plan/logging/STANDARD.md` exists and contains all six normative sections above, each labelled
      normative, with at least one copy-paste worked example per section.
- [ ] The level taxonomy and the canonical field registry match the PRD/architecture tables exactly
      (no invented levels or field keys); synonyms are explicitly forbidden with examples.
- [ ] The redaction policy lists every forbidden secret category and the mandated primitives, and
      names the high-risk crates.
- [ ] The `#[instrument]` idioms section states the R1 eager-`fields()` rule and the "scalars in
      instrument `fields`, redaction wrappers on event macros / `record()`" house rule.
- [ ] `crates/telemetry/src/lib.rs` carries a `//!` line referencing `plan/logging/STANDARD.md`;
      `cargo doc -p rvc-telemetry --no-deps` builds without warnings.
- [ ] Standing invariant green: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
      -- -D warnings`, `cargo nextest run --workspace` (the doc-only `//!` change must not regress any
      test).

**Testing Notes:**
- No automated test for a Markdown doc; the gate is review against the PRD/architecture as the source
  of truth. The only compiled change is the `//!` line — covered by the standing `clippy`/`doc` build.

---

### Issue 1.2: `crypto::logging::TruncatedRoot` — zero-alloc `&[u8]` root/signature wrapper

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** none
- **Blocks:** 1.8 (its captured-subscriber test output feeds the gitleaks emitted-log sample).
- **Scope:** 1 day

**Description:**
Add a new `TruncatedRoot<'a>(pub &'a [u8])` zero-allocation `Display` wrapper to `crypto::logging`,
the only sanctioned way to render a 32-byte block/head/signing root, hash, or signature in a log line
(ADR-005). It must take `&[u8]` — **not** `&str` — and hex-render the first/last bytes *inside*
`Display::fmt` so that under the `%` specifier it allocates nothing and only runs when the level is
enabled. This is the primitive that replaces the eager `hex::encode(...)` locals on the sign path
(`crates/signer/src/lib.rs:170`,`:359` and the `%format!("0x{}", hex::encode(...))` fields at
`:161-174`) in Phase 2 — but this issue only adds the wrapper and its tests, it does not touch the
sign path. Follows the existing `TruncatedPubkey`/`RedactedUrl` pattern in the same file.

**Implementation Notes:**
- File: `crates/crypto/src/logging.rs` (already `pub mod logging` at `crates/crypto/src/lib.rs:15`).
- Shape: `pub struct TruncatedRoot<'a>(pub &'a [u8]);` with `pub fn new(bytes: &'a [u8]) -> Self` and
  `impl std::fmt::Display`. Render `0x{first-5-bytes-hex}...{last-4-bytes-hex}` so a 32-byte root reads
  `0x{10hex}...{8hex}` (10 leading + 8 trailing hex chars), matching `TruncatedPubkey`'s shape and the
  `...` glyph (R9, ADR-005).
- Zero-alloc: write hex directly into the `Formatter` byte-by-byte (e.g. `write!(f, "{:02x}", b)` over
  the chosen slices) — do **not** call `hex::encode` (which allocates a `String`). The `Display` body
  only runs under `%` on an enabled event, so the whole thing is lazy and free when the level is off.
- Short-input branch (mirror `TruncatedPubkey`): for `< 9` bytes, render the full lower-hex
  (`0x{all-bytes}`) rather than slicing out of bounds; never panic.
- No `Display` is ever added to a secret type — `TruncatedRoot` wraps a non-secret root/signature only;
  this is documented on the type.
- Add a `///` doc comment matching the style of `TruncatedPubkey` (note the zero-alloc, level-gated
  behavior).

**Acceptance Criteria:**
- [ ] `TruncatedRoot::new(&[u8; 32])` rendered via `Display` produces `0x{10hex}...{8hex}` for a
      32-byte input, and the rendered string is exactly 22 characters (`0x` + 10 + `...` + 8).
- [ ] For a real 32-byte root, the **full** hex encoding of the root is **absent** from the rendered
      output (proven by a `#[tracing_test::traced_test]` test that logs `root = %TruncatedRoot::new(&r)`
      at `trace` and asserts `logs_contain` the truncated form and `!logs_contain` the full hex) — this
      is the Gate-3-style redaction assertion required by the phase exit criteria.
- [ ] Inputs `< 9` bytes render full lower-hex and do not panic (unit tests for empty, 1-byte, 8-byte).
- [ ] No heap allocation is performed by `Display::fmt` (verified by inspection: byte-wise `write!`,
      no `hex::encode`/`format!`/`to_string` in the body). A code comment records this.
- [ ] `TruncatedRoot` is exported the same way `TruncatedPubkey`/`RedactedUrl` are
      (`crypto::logging::TruncatedRoot` is reachable from dependent crates).
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- TDD (RED → GREEN → REFACTOR): write the failing `assert_eq!(TruncatedRoot::new(&[0xab;32]).to_string(), "0xababababab...abababab")`
  first. Reuse the existing `#[tracing_test::traced_test]` model at `crates/crypto/src/logging.rs:119`
  for the redaction assertion. `tracing-test` is already a `crypto` dev-dep (`crates/crypto/Cargo.toml:48`).
- Run `cargo nextest run -p rvc-crypto` for the fast inner loop; full `cargo nextest run --workspace`
  before merge.

---

### Issue 1.3: `crypto::logging::fields` — canonical field-key consts + `Duty` enum

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 1.1 (the consts are a compile-checked mirror of `STANDARD.md`'s registry)
- **Blocks:** none in this phase (used by Gate 5 in Phase 4 and by `record_*` call sites in Phase 2)
- **Scope:** 1 day

**Description:**
Add a `fields` submodule to `crypto::logging` providing one `&'static str` const per canonical field
key in the `STANDARD.md` registry, plus a `Duty` enum with `as_str()` returning the normative `duty`
value strings. This is the single compile-time, greppable, refactor-safe source of truth for field
keys so no crate can invent a synonym (`val_idx`, `validator`, `rvc.slot`). It is the artifact Gate 5
(Phase 4/5) diffs emitted field names against; landing it now lets Phase 2 use the `Duty` values.

**Implementation Notes:**
- File: `crates/crypto/src/logging.rs` — add `pub mod fields { ... }` (or a sibling file
  `crates/crypto/src/logging/fields.rs` if the module is split; keep it under `crypto::logging`).
  Update `crates/crypto/src/lib.rs` only if a new path needs re-export (the module is already
  `pub mod logging`).
- Consts (exactly the registry keys, names normative): `pub const SLOT: &str = "slot";` and likewise
  `EPOCH`, `VALIDATOR_INDEX`, `PUBKEY`, `DUTY`, `REQUEST_ID`, `COMMITTEE_INDEX`, `SUBCOMMITTEE_INDEX`,
  `BN_URL`, `HEAD`, `BLOCK_ROOT`, `TIME_INTO_SLOT`. (`network` is a resource attribute, not a per-event
  key — document that it is intentionally **not** a const here.)
- `pub enum Duty { Attestation, Block, Aggregate, SyncCommittee, SyncContribution,
  ValidatorRegistration, VoluntaryExit }` with `pub fn as_str(&self) -> &'static str` returning the
  normative spellings (`"attestation"`, `"block"`, `"aggregate"`, `"sync_committee"`,
  `"sync_contribution"`, `"validator_registration"`, `"voluntary_exit"` — research §G: `sync_committee`,
  **not** Prysm/Lodestar spellings). `as_str()` returns `&'static str` so it is `Copy`-cheap and
  R1-safe on `#[instrument(fields(duty = %Duty::…))]`.
- These are consts (not an enum-of-keys) deliberately: `#[instrument(fields(slot = …))]` needs the
  literal `slot` ident, which the macro requires anyway; the consts back `record()` call sites and the
  Gate 5 conformance diff. Document this rationale in the module `//!`.
- Add a `//!` doc on the `fields` module that points back to `STANDARD.md` as the normative source and
  states that the consts must stay in lockstep with the registry table.

**Acceptance Criteria:**
- [ ] Every field key in the `STANDARD.md` registry (except the `network` resource attr) has a
      corresponding `pub const` whose value equals the canonical string (e.g. `fields::SLOT == "slot"`,
      `fields::COMMITTEE_INDEX == "committee_index"`, `fields::SUBCOMMITTEE_INDEX == "subcommittee_index"`).
- [ ] `Duty::as_str()` returns the normative value string for every variant, asserted by a unit test
      (`assert_eq!(Duty::SyncCommittee.as_str(), "sync_committee")` etc.); the test pins all 7 variants.
- [ ] `network` is documented as intentionally absent (resource attribute), with a comment.
- [ ] `crypto::logging::fields::SLOT` and `crypto::logging::fields::Duty` are reachable from a
      dependent crate (visibility verified by a compile-time use in the test).
- [ ] The module `//!` references `STANDARD.md` and states the lockstep requirement.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- TDD: write the failing `assert_eq!`s for the const values and the `Duty::as_str()` mapping first.
  Pure-data module → unit tests only; no subscriber needed.
- The const-value test doubles as the Gate-5 contract anchor; keep all keys in one test so a future
  rename is caught in one place.

---

### Issue 1.4: `crypto::logging` correlation kit — `new_request_id` + `record_display`/`record_debug`

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** none (soft-after 1.3 — `fields::REQUEST_ID`; falls back to the `"request_id"` literal, see Testing Notes)
- **Blocks:** 1.8 (the `new_request_id` test output feeds the gitleaks emitted-log sample)
- **Scope:** 1 day

**Description:**
Add the correlation primitives to `crypto::logging`: `new_request_id() -> uuid::Uuid` (mints the
`request_id` that follows a single signing/API request end to end, including across the :9000 hop) and
`record_display`/`record_debug` thin helpers for filling deferred (`field::Empty`) span fields
correctly. These remove the two recurring foot-guns by construction: the `%`/`?` sigils are macro
sugar and do **not** work at a `record()` call site (research §A), and `record()` on a field **not
declared at span creation is silently dropped** (the #1 "vanishing attribute" bug). This issue lands
the primitives; Phase 2 wires them into the :9000 path and the sign spans.

**Implementation Notes:**
- File: `crates/crypto/src/logging.rs`.
- `pub fn new_request_id() -> uuid::Uuid { uuid::Uuid::new_v4() }` — returns a `Uuid`, **not** a
  pre-built `String`, so callers render with `%` and pay nothing when the span level is disabled
  (ADR-002). `uuid` is already a `crypto` dep with the `v4` feature (`crates/crypto/Cargo.toml:32`;
  workspace `Cargo.toml:84` enables `v4`). Matches the in-tree precedent at
  `crates/keymanager-api/src/handlers.rs:348`.
- `pub fn record_display(span: &tracing::Span, key: &'static str, val: impl std::fmt::Display)` →
  `span.record(key, tracing::field::display(val));`
- `pub fn record_debug(span: &tracing::Span, key: &'static str, val: impl std::fmt::Debug)` →
  `span.record(key, tracing::field::debug(val));`
- Doc comments must state the contract: the target field MUST have been declared (e.g.
  `slot = tracing::field::Empty`) at span creation or the record is a silent no-op (mirror
  `beacon::client`'s `http.status_code = Empty` pattern), and that these helpers exist because the
  `%`/`?` sigils are unavailable at a `record()` site.
- No new dependency required (`tracing` and `uuid` are already present).

**Acceptance Criteria:**
- [ ] `new_request_id()` returns a v4 `Uuid` (`uuid.get_version() == Some(Version::Random)`), and two
      successive calls return distinct values (unit test).
- [ ] `record_display` fills a span field **declared `field::Empty` at creation**: a
      `#[tracing_test::traced_test]` test creates a span with `request_id = tracing::field::Empty`,
      calls `record_display(&span, fields::REQUEST_ID, some_uuid)` inside the span, emits a child event,
      and asserts `logs_contain` the uuid value (the field landed on the span and inherited to the
      event).
- [ ] A negative test confirms that `record_display` to a field **not** declared at creation is a
      silent no-op (documents the foot-gun the helper guards against), and is called out in the doc
      comment.
- [ ] `record_debug` behaves identically for a `Debug` value (one test).
- [ ] `crypto::logging::{new_request_id, record_display, record_debug}` are reachable from a dependent
      crate.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- TDD: the span-record test is the key one — declare the field `Empty`, record via the helper, assert
  the value appears on a child event under a captured subscriber (`tracing-test`, already a `crypto`
  dev-dep). This is the exact mechanism Phase 2's :9000 late-bind relies on, so prove it here.
- Use `crypto::logging::fields::REQUEST_ID` from 1.3 as the key if 1.3 has merged; otherwise the
  literal `"request_id"` (the helper takes any `&'static str`). Either keeps this issue unblocked.

---

### Issue 1.5: `telemetry::propagation::set_parent_from_headers` + `HeaderExtractor`

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** none
- **Blocks:** Phase 2 (the :9000 trace-continuity bridge wires this fn; not a Phase 1 dependency)
- **Scope:** 2 days

**Description:**
Add the inbound W3C trace-context extractor to `telemetry::propagation` — the exact inverse of the
existing `inject_trace_context` (`crates/telemetry/src/propagation.rs:25`). It reads
`traceparent`/`tracestate` from an inbound `http::HeaderMap` and sets a `tracing::Span`'s OpenTelemetry
parent, so that once Phase 2 wires it into the :9000 `sign` handler a duty trace is all-or-nothing end
to end under the existing `ParentBased(TraceIdRatioBased)` sampler. **This issue lands and unit-tests
the function only; wiring it into `bin/rvc-signer` (and the one new `rvc-signer-bin → telemetry` edge)
is Phase 2** (ADR-008, project-plan §"load-bearing cross-phase dependencies" item 2). The sampler,
exporters, and `inject_trace_context` are untouched.

**Implementation Notes:**
- File: `crates/telemetry/src/propagation.rs`; re-export from `crates/telemetry/src/lib.rs` next to
  `inject_trace_context`.
- `struct HeaderExtractor<'a>(&'a http::HeaderMap)` implementing
  `opentelemetry::propagation::Extractor` (`get(&self, key: &str) -> Option<&str>` and `keys(&self) ->
  Vec<&str>`) — the mirror of the existing `HeaderInjector` at `propagation.rs:6`.
- `pub fn set_parent_from_headers(span: &tracing::Span, headers: &http::HeaderMap)` — read the inbound
  context via `opentelemetry::global::get_text_map_propagator(|p| p.extract(&HeaderExtractor(headers)))`
  and set the span's parent with `tracing_opentelemetry::OpenTelemetrySpanExt::set_parent` (the
  `OpenTelemetrySpanExt` trait is already imported in this module at `propagation.rs:3`).
- **Header type = `http::HeaderMap`, not `reqwest::header::HeaderMap`** (architecture R3 / Open Q1).
  The inbound :9000 handler holds `axum::http::HeaderMap`; both `axum` and `reqwest` re-export the same
  `http` crate's `HeaderMap`, so a single `&http::HeaderMap` extractor serves the server side while the
  existing `reqwest`-typed `HeaderInjector` stays as-is. **Resolve Open Q1 while building:** confirm
  `telemetry` can name `http::HeaderMap` via `reqwest`'s re-export (`reqwest` is a `telemetry` dep,
  `crates/telemetry/Cargo.toml:18`). If it cannot, add a direct `http` dependency to
  `crates/telemetry/Cargo.toml` — this is a leaf-internal external dep with **no** workspace-internal
  edge and **no** cycle (the DAG gate is unaffected); record which path was taken in the doc/PR.
- Failure behavior: absent/garbled `traceparent` → empty context → the span stays a root (no worse
  than today, mirrors `inject_trace_context`'s no-op-without-OTel behavior). Never panic; no
  signing-behavior change.
- Reject `axum-tracing-opentelemetry` (pre-1.0; `telemetry` already owns init/propagation) — the
  ~20-line in-repo extractor is additive and keeps sampler/propagator ownership in one place.

**Acceptance Criteria:**
- [ ] `set_parent_from_headers` is implemented in `telemetry::propagation` and re-exported from
      `telemetry::lib` alongside `inject_trace_context`.
- [ ] **Non-zero-parent test:** with an active OTel layer (reuse `init_tracing(&TelemetryConfig::default())`
      as the existing propagation tests do at `propagation.rs:55-77`), build a synthetic inbound
      `traceparent` header (e.g. `00-<32 hex>-<16 hex>-01`), call `set_parent_from_headers` on a fresh
      span, and assert the span's resulting OTel context has a **non-zero / valid trace id** matching
      the injected one (i.e. it is a child of the caller's trace, not a fresh root). This is the
      phase exit-criteria proof.
- [ ] **Absent-header test:** calling `set_parent_from_headers` with an empty `HeaderMap` leaves the
      span as a root and does **not** panic.
- [ ] **Garbled-header test:** a malformed `traceparent` value yields a root span, no panic.
- [ ] `HeaderExtractor` correctly returns header values via `get`/`keys` (mirror of the injector's
      invalid-name/value tests where applicable).
- [ ] Open Q1 resolved and documented: the PR states whether `http::HeaderMap` was named via
      `reqwest`'s re-export or via a new direct `http` leaf-dep; if a dep was added, the DAG gate
      (1.7 / existing) is confirmed still green.
- [ ] Existing `telemetry`/OTLP/propagation tests still green (no regression to `inject_trace_context`
      or the sampler).
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- TDD: write the failing non-zero-parent test first (synthetic `traceparent` in, assert non-zero trace
  id on the span's context out). The existing `test_inject_with_otel_layer`
  (`crates/telemetry/src/propagation.rs:54`) is the model for standing up an OTel layer in a test and
  for the trace-id-not-zero assertion idiom (`!value.contains("0000…0000")`).
- Remember to `guard.provider.shutdown().ok()` at the end of any test that calls `init_tracing`, as the
  existing tests do (`propagation.rs:76`).
- Run `cargo nextest run -p rvc-telemetry` for the inner loop.

---

### Issue 1.6: Gate 1 — `clippy.toml` `disallowed-methods` secret sinks + scoped allow-list

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Blocked by:** none
- **Blocks:** none in this phase (it is the standing secret-sink lint Phase 2 relies on)
- **Scope:** 1 day

**Description:**
Stand up Gate 1: extend `clippy.toml` (today only `msrv = "1.92"`, verified) with `disallowed-methods`
for the secret-laundering sinks so that any code passing raw secret bytes toward a logging macro fails
`cargo clippy --workspace --all-targets -- -D warnings` (the existing `check` CI job). Because these
methods are legitimately needed at decrypt/sign call sites, scope — don't ban — by annotating exactly
those existing sites with a small, reviewed, greppable `#[allow(clippy::disallowed_methods)]`; the lint
then flags only **new** uses elsewhere. The workspace must stay clippy-green at merge.

**Implementation Notes:**
- File: `clippy.toml`. Add (confirming exact paths against the tree first — A7):
  ```toml
  msrv = "1.92"

  disallowed-methods = [
    { path = "secrecy::ExposeSecret::expose_secret",
      reason = "expose_secret() output must never reach a log macro; decrypt at the call site only" },
    { path = "rvc_crypto::bls::SecretKey::raw_bytes",
      reason = "raw key bytes escape the redacted newtype; do not log or format" },
    { path = "rvc_crypto::bls::SecretKey::to_bytes",
      reason = "raw key bytes escape the redacted newtype; do not log or format" },
  ]
  ```
- **Confirm the paths exist before banning** (A7): grep for `expose_secret`, `SecretKey::raw_bytes`,
  `SecretKey::to_bytes` (and confirm the `SecretKey` type path is `rvc_crypto::bls::SecretKey`). Note
  `sign_attestation` already calls `pubkey.to_bytes()` at `crates/signer/src/lib.rs:136` — that is
  `PublicKey::to_bytes`, **not** `SecretKey::to_bytes`, so the public-key path must **not** be banned;
  ban only the `SecretKey` method paths. If the real method names differ, use the actual paths and
  record them in the PR.
- Enumerate every existing legitimate call site of the banned methods and add a one-line, reviewed
  `#[allow(clippy::disallowed_methods)]` immediately above each (decrypt in `crypto`/`secret-provider`,
  sign in `crypto`/`signer`). Keep the allow-list greppable (the literal attribute string).
- Add a comment in `clippy.toml` recording the **stated limitation**: `disallowed-methods` matches
  named paths only — it cannot see a value already laundered into a `String`/`&str`; this is accepted
  because the type layer makes the implicit path impossible and Gates 3/2 (Phase 2) test the runtime
  result. P2 `dylint` is the dataflow upgrade if ever needed.
- No CI-file change: Gate 1 rides the existing `check` job's `cargo clippy … -D warnings` step
  (`.github/workflows/ci.yml:43-44`).

**Acceptance Criteria:**
- [ ] `clippy.toml` contains the `disallowed-methods` array with the three (confirmed) secret-sink
      paths and a `reason` on each, plus the stated-limitation comment.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes (green) — i.e. every existing
      legitimate call site is covered by a scoped `#[allow(clippy::disallowed_methods)]`; no public-key
      method (`PublicKey::to_bytes`) is banned.
- [ ] A demonstration (in the PR description, not committed) that adding a **new** call to a banned
      method outside the allow-list makes clippy fail — proving the gate is live (mirror the
      architecture's "forbidden-edge injection verified once then reverted" practice for the DAG gate).
- [ ] The allow-list is greppable: `rg "allow\(clippy::disallowed_methods\)"` returns exactly the
      enumerated legitimate sites (no stray suppressions).
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- The gate *is* the test (clippy fail-closed). Verify the live behavior locally by temporarily adding a
  banned call in a scratch location, confirming clippy errors, then removing it.
- This issue does not add or change logging statements — it only constrains future ones.

---

### Issue 1.7: Gate 6 — extend `architecture-tests` policy tables for the new edge

- **Points:** 2
- **Type:** chore
- **Priority:** P0
- **Blocked by:** none
- **Blocks:** none (locks the boundary Phase 2's new edge will use)
- **Scope:** 1 day

**Description:**
Lock the dependency-graph boundary for the initiative in the existing DAG gate
(`crates/architecture-tests/tests/architecture_no_cycles.rs`). The single new production edge the whole
initiative introduces — `rvc-signer-bin → rvc-telemetry` (added in Phase 2 to call the extractor +
init helper) — is already acyclic because `telemetry` is a zero-internal-dep leaf, and the gate stays
green for it **without** edits (verified by reading the test). This issue *proactively extends the
policy tables* so the boundary is explicit and a future contributor cannot "fix" a field-constant
import by adding a `uuid`/`telemetry` edge to `eth-types` (architecture Gate 6 recommendation,
project-plan Phase 1 scope).

**Implementation Notes:**
- File: `crates/architecture-tests/tests/architecture_no_cycles.rs`.
- The gate already pins `ZERO_OUT_EDGE_IF_PRESENT = ["rvc-eth-types", "rvc-signer-registry"]`
  (line 47), enforces `FORBIDDEN` edges (line 39), and requires `rvc-signer → rvc-doppelganger`
  (line 50). Confirm `rvc-eth-types` stays in `ZERO_OUT_EDGE_IF_PRESENT` (it is the temptation target
  for a field-constant import — keeping it at zero out-edges is what blocks an `eth-types → uuid`/
  `telemetry` "fix").
- Add an explicit allowed/expected entry for `rvc-signer-bin → rvc-telemetry` so the boundary is
  documented and locked. Implementation choice (pick one, document it): either add it as a new
  `REQUIRED_EDGE`-style assertion (a regression guard that the edge, once Phase 2 adds it, stays
  present) **or** — since the edge does not exist until Phase 2 — add it to a new "expected/allowed"
  comment-documented list and assert only that it is **not** forbidden and introduces no cycle. Prefer
  the latter for Phase 1 (the edge is not present yet), with a clear `// Phase 2 will add this edge`
  note, so the test stays green now and after Phase 2.
- Confirm the actual package names against `cargo metadata` (`rvc-signer-bin` vs the bin crate's real
  package name; `rvc-telemetry` is confirmed by `crates/telemetry/Cargo.toml:2`). Use the real names.
- Do **not** weaken any existing assertion. The cycle check, `FORBIDDEN`, the zero-out-edge pins, and
  the `rvc-signer → rvc-doppelganger` requirement must all remain.

**Acceptance Criteria:**
- [ ] `architecture-tests` still passes today (the `rvc-signer-bin → rvc-telemetry` edge does not yet
      exist; the graph is acyclic): `cargo nextest run -p rvc-architecture-tests` green.
- [ ] `rvc-eth-types` (and `rvc-signer-registry`) remain pinned to zero workspace-internal production
      out-edges; a comment documents that this is what blocks an `eth-types → uuid`/`telemetry` "fix".
- [ ] The new boundary `rvc-signer-bin → rvc-telemetry` is documented in the policy (as an
      expected/allowed edge), and the test asserts it is not in `FORBIDDEN` and introduces no cycle.
- [ ] The package names used match `cargo metadata --no-deps` output (verified, not guessed).
- [ ] No existing assertion is weakened or removed; the forbidden edges and the required
      `rvc-signer → rvc-doppelganger` edge still hold.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`).

**Testing Notes:**
- The test runs `cargo metadata --format-version=1 --no-deps`; run it via
  `cargo nextest run -p rvc-architecture-tests`.
- To sanity-check the lock works, temporarily add `telemetry.workspace = true` to the signer-bin
  `Cargo.toml` and confirm the gate stays green (acyclic leaf attachment) — then revert; and
  temporarily add a `uuid` dep to `eth-types` and confirm the zero-out-edge assertion fails — then
  revert (mirror the gate's own "verified once then reverted" doc practice at the top of the file).

---

### Issue 1.8: Gate 2 — `gitleaks` PR job (source + emitted log sample)

- **Points:** 3
- **Type:** chore
- **Priority:** P0
- **Blocked by:** 1.2 (`TruncatedRoot` tests), 1.4 (`new_request_id`/`record_*` tests) — their
  `trace`-level output is the emitted sample the job scans (architecture Open Q5: "reuse first")
- **Blocks:** none (it is the standing secret-scan gate)
- **Scope:** 1-2 days

**Description:**
Stand up Gate 2: add the single net-new CI job — a `gitleaks` PR job — to
`.github/workflows/ci.yml`. It must (a) run `gitleaks` over the **source tree** and (b) **emit a
representative `trace`-level log sample** (by running the captured-subscriber conformance tests, or a
tiny dump harness) and run `gitleaks` over **that emitted output**. Scanning the *emitted* log, not
just source, is the load-bearing part — it is what actually verifies "no secret reached a logging
macro" (the part most designs miss, and the one that proves a BLS key never reached a sink). It is
fail-closed at 0 findings, with test fixtures allow-listed to control false positives.

**Implementation Notes:**
- File: `.github/workflows/ci.yml` — add a new top-level job (e.g. `secret-scan`) alongside the
  existing `check` and `coverage` jobs (verified structure: `check` at line 13, `coverage` at line 46).
  Mirror their `runs-on: ubuntu-latest`, checkout, and (if compiling the sample) the Rust toolchain +
  protoc + nextest install steps from the `coverage` job (`ci.yml:54-81`).
- Source scan: use the `gitleaks` GitHub Action (rule + entropy, SARIF, blocking) over the repo. Add a
  `.gitleaks.toml` at the repo root with allow-list rules for the workspace's intentional test
  fixtures (test keystores, hard-coded test pubkeys/roots, the BLS test vectors in `crypto` tests) so
  legitimate fixtures do not trip the gate (false-positive control). The pubkey/root test constants in
  `crates/crypto/src/logging.rs` tests are examples of fixtures to allow-list.
- Emitted-log sample (Open Q5 — **reuse first**): run the captured-subscriber tests that exercise the
  redaction wrappers at `trace` level and capture their stdout/stderr to a file, then run `gitleaks`
  over that file. Concretely: run the `crypto` logging tests (e.g.
  `cargo nextest run -p rvc-crypto logging -- --nocapture` redirected to a file, or the existing
  `tracing-test`-based tests) so the emitted lines include `TruncatedRoot`/`TruncatedPubkey`/
  `new_request_id` output, and assert `gitleaks` finds 0 secrets in that captured output. Only add a
  dedicated tiny `trace`-level dump harness if reuse leaves a coverage gap (Open Q5 fallback).
- Keep `trufflehog` verification-first mode as a **scheduled** full sweep (not part of this blocking PR
  job) — out of scope for this issue beyond a note; do not add it to the PR-blocking path.
- Do not modify the `check` or `coverage` jobs; this is purely additive (the one net-new CI job).

**Acceptance Criteria:**
- [ ] `.github/workflows/ci.yml` has a new `gitleaks`/`secret-scan` job that runs on `pull_request`
      (same triggers as `check`/`coverage`).
- [ ] The job runs `gitleaks` over the **source tree** and fails the PR on any finding (fail-closed,
      blocking, SARIF or non-zero exit).
- [ ] The job **emits a `trace`-level log sample** (from the reused captured-subscriber tests) to a
      file and runs `gitleaks` over that emitted output, also fail-closed at 0 findings.
- [ ] `.gitleaks.toml` exists at the repo root and allow-lists the workspace's intentional test
      fixtures so the job passes with 0 findings on the current tree (no false positives from test
      keystores / test pubkeys / test roots).
- [ ] On the current `develop` tree the job reports **0 findings** for both the source scan and the
      emitted-sample scan.
- [ ] The `check` and `coverage` jobs are unchanged.
- [ ] Standing invariant green (`fmt` + `clippy -D warnings` + `nextest`) — the workspace itself is
      unaffected by the CI addition.

**Testing Notes:**
- The natural inner loop is to run `gitleaks` locally (`gitleaks detect --config .gitleaks.toml`) over
  the tree and over a locally captured `trace`-level log file before pushing, iterating on the
  allow-list until 0 findings.
- The emitted-sample step depends on 1.2 and 1.4 having merged so there is real redaction-wrapper
  output to scan; sequence this issue after them (see the execution plan).
- This issue cannot fully self-verify offline (the gitleaks Action runs in GitHub CI); the local
  `gitleaks` CLI run is the proxy. Note this in the PR.
