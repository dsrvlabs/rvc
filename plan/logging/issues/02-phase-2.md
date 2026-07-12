# Phase 2: Hot Paths + Safety

> Self-contained issue breakdown for **Phase 2** of the rs-vc structured-logging / observability
> initiative. Maps to the project plan's *Phase 2: Hot Paths + Safety — Core Observability*
> (architecture rollout "Phase 1"; PRD scope **P0-2 / P0-3 / P0-4 / P0-6**). A code-writer should be
> able to execute this phase from this file alone, consulting `plan/logging/STANDARD.md` (the rubric
> from Phase 1) for level/field/redaction rules and `plan/logging/architecture.md` for the ADRs.

## Phase Overview

- **Goal:** Make the runtime hot paths fully observable at `debug`/`trace` with standardized,
  spans-first correlation; prove the trace is continuous across the :9000 Web3Signer boundary;
  guarantee zero secret leakage on the high-risk crates; and prove zero hot-path overhead when
  verbose levels are disabled. This is the PRD's central operability promise, delivered and proven.
- **Issue count:** 13 issues, **30 total points**.
- **Estimated duration:** ~21 working days (single-stream default; one code-writer working issues in
  order).
- **PRD requirements delivered:** P0-2 (canonical field convention applied), P0-3 (redaction applied
  + enforced on the high-risk crates), P0-4 (`trace`/`debug` hot-path coverage with standardized
  spans), P0-6 (zero-overhead-when-disabled, proven).
- **Entry criteria (Phase 1 must be merged on `develop`):**
  - `plan/logging/STANDARD.md` merged and is the review rubric.
  - The `crypto::logging` kit exists and is tested: `TruncatedRoot<'a>(&'a [u8])` (zero-alloc
    `Display`, `0x{10hex}...{8hex}`), the `crypto::logging::fields` const module (`SLOT`, `EPOCH`,
    `VALIDATOR_INDEX`, `PUBKEY`, `DUTY`, `REQUEST_ID`, `COMMITTEE_INDEX`, `SUBCOMMITTEE_INDEX`,
    `BN_URL`, `HEAD`, `BLOCK_ROOT`, `TIME_INTO_SLOT`) + `Duty` enum with `as_str()`,
    `new_request_id() -> uuid::Uuid`, and `record_display`/`record_debug` span helpers.
    (`TruncatedPubkey`/`RedactedUrl` already exist in `crates/crypto/src/logging.rs`.)
  - `telemetry::propagation::set_parent_from_headers(&tracing::Span, &http::HeaderMap)` +
    `HeaderExtractor` exist and are unit-tested (synthetic inbound `traceparent` → non-zero parent),
    re-exported from `telemetry::lib` next to `inject_trace_context`. **Phase 1 lands the function;
    this phase wires it.**
  - Gate 1 (`clippy.toml` `disallowed-methods` on `expose_secret`/`raw_bytes`/`to_bytes` + scoped
    allow-list) is live on the existing `cargo clippy --workspace --all-targets -- -D warnings` step.
  - Gate 2 (`gitleaks` PR job over source + emitted sample) is live in `.github/workflows/ci.yml`.
  - Gate 6 (`crates/architecture-tests` DAG gate) policy tables already accept the
    `rvc-signer-bin -> rvc-telemetry` edge and keep `rvc-eth-types` at zero out-edges.
- **Exit criteria (the phase is complete when all hold):**
  - Every identified hot-path step has `trace`; every hot-path async entry point carries a
    standardized `#[instrument(level = "debug"|"trace", skip_all, fields(...))]` span with canonical
    correlation fields (100% of the P0-4 surface listed in the issues below).
  - **Trace continuous across :9000**: the non-zero-parent test passes on the *live* `sign` handler
    (the span is a child of the caller's trace, not a fresh root); `request_id` and the
    `x-request-id` header are present on both sides.
  - No `rvc.`-prefixed field/span keys remain in `crates/signer/src/lib.rs` **or**
    `crates/rvc/src/orchestrator/` (normalized to the unprefixed canonical registry); `slot` (not
    `rvc.slot`) is the emitted attribute key.
  - The `spawn_blocking` closures in `crates/signer/src/lib.rs` re-enter the span, so
    blocking-section `crypto`/`slashing` events carry the span's `request_id`/`slot` (Gate 3 asserts).
  - **0 secret findings** across Gates 1 + 2 + 3 on `crypto`, `secret-provider`, `signer`, the :9000
    path, and `rvc-keygen` mnemonics; pubkeys truncated even at `trace`; roots/signatures truncated
    via `TruncatedRoot`.
  - **Zero-alloc assertion passes** (Gate 4): `allocs_when_disabled == baseline` on the
    `sign_attestation` / `sign_block` paths and around one coordinator/per-slot phase; the eager
    `let signing_root_hex = hex::encode(...)` / `%format!("0x{}", hex::encode(...))` locals on the
    sign path are replaced by `TruncatedRoot`.
  - `release_max_level_debug` present on `tracing` in both `bin/rvc/Cargo.toml` and
    `bin/rvc-signer/Cargo.toml`; `trace!` physically absent from `--release`, `debug!` still
    `RUST_LOG`-switchable; the `criterion` sign-path bench shows `info ≈ no_subscriber` within noise.
  - **Standing invariant green at every merge:** `cargo fmt --all -- --check`,
    `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo nextest run --workspace`.
    **Do NOT run `cargo test --workspace`** — it deadlocks in this workspace; `nextest` is the runner
    of record.

### Assumptions recorded for this phase (no user input was sought)

1. **Phase 1 is merged and green** on `develop` before issue 2.1 starts. The kit primitives and
   `set_parent_from_headers` are treated as existing dependencies, not re-implemented here. If any
   Phase 1 primitive is missing at kickoff, that is a blocker to report upward — not a reason to
   inline a copy.
2. **Single-stream execution.** One code-writer works the issues in dependency order. No stream
   assignments, file-ownership maps, or scaffold issues (the kit is the scaffold, and it is Phase 1).
3. **Verified sites are current** (checked against `develop` this pass): `crates/signer/src/lib.rs`
   `sign_attestation` `#[instrument(name="rvc.sign.attestation", …)]` at `:126` with `spawn_blocking`
   at `:209` and the eager `hex::encode` at `:170` (`%format!` fields `:161-174`); `sign_block`
   `#[instrument(name="rvc.sign.block", …)]` at `:330` with `spawn_blocking` at `:372` and eager
   `hex::encode` at `:359`; `rvc.slashing.result` records at `:306`/`:311` (and the block arm),
   `info_span!("rvc.slashing.check")` at `:189`. The :9000 `sign` handler is already
   `#[tracing::instrument(skip_all)]` at `bin/rvc-signer/src/http_api/routes.rs:51` and already takes
   `headers: axum::http::HeaderMap` at `:56`. `bin/rvc-signer` does **not** depend on `telemetry`
   today; `bin/rvc` does. The orchestrator carries live `rvc.`-prefixed spans/fields in
   `crates/rvc/src/orchestrator/coordinator.rs` (`rvc.slot.process` `:320`, `rvc.epoch.boundary`
   `:345`, `rvc.slot.phase.{block,attestation,aggregation}` `:381`/`:391`/`:477`,
   `rvc.orchestrator.maybe_propose_block` `:602`) **with tests asserting those exact span names**
   (`:3729-3739`), so any rename must update those test assertions in the same issue.
4. **Forwarded gate decisions accepted as the architecture's recommended defaults** (none blocks
   this phase): static cap = `release_max_level_debug` (ADR-001); `request_id` carrier = fresh
   `uuid::Uuid::new_v4()` + `x-request-id` header (ADR-002); `gitleaks` emitted-sample harness reuses
   the captured-subscriber tests first (Gate 2); coarse spans = one span per phase, not per inner
   `.await` (research §C/§D). `telemetry` can name `http::HeaderMap` without a new `axum` dep
   (re-exported by `reqwest`, already a `telemetry` dep) — confirmed during Phase 1.
5. **No behavior change.** This phase changes only logging/observability plus the single additive
   wire behavior at :9000 (inbound trace-context extraction + an additive `x-request-id` header). No
   public API, signing, or slashing-logic change. The single new production edge
   `rvc-signer-bin -> rvc-telemetry` is introduced in issue 2.3 (Gate 6 already accepts it).
6. **`rvc-keygen` is pulled into this phase for its mnemonic-redaction sign-off only** (high-risk for
   the mnemonic rule per research §9), even though its `info`/`debug`/`trace` breadth lands in
   Phase 4. Issue 2.11 covers the redaction conformance, not the breadth.

---

## Phase Summary

| Issue | Title | Points | Type | Priority | Blocked by | Scope | Files |
|-------|-------|--------|------|----------|------------|-------|-------|
| 2.1 | `signer`: rename `rvc.*` spans/fields to registry + update span-name tests | 3 | chore | P0 | — (Phase 1 kit) | 1-2 days | `crates/signer/src/lib.rs` |
| 2.2 | `signer`: `spawn_blocking` span re-entry + `TruncatedRoot` adoption (zero-alloc) | 3 | feature | P0 | 2.1 | 2 days | `crates/signer/src/lib.rs` |
| 2.3 | `bin/rvc-signer` :9000: wire `set_parent_from_headers` + `request_id` + `x-request-id` (the bridge) | 3 | feature | P0 | Phase 1 kit (1.3/1.4/1.5) + 2.1 | 2 days | `bin/rvc-signer/src/http_api/routes.rs`, `Cargo.toml` |
| 2.4 | `crypto`: canonical fields + `TruncatedRoot` on sign/domain/root paths | 2 | feature | P0 | — (Phase 1 kit) | 1-2 days | `crates/crypto/src/**` |
| 2.5 | `beacon`: endpoint selection (debug) + request/response framing (trace) + `RedactedUrl` | 2 | feature | P1 | — (Phase 1 kit) | 1-2 days | `crates/beacon/src/client.rs` |
| 2.6 | `bn-manager`: selection (debug), failover (warn), `bn_url` redacted | 2 | feature | P1 | — (Phase 1 kit) | 1-2 days | `crates/bn-manager/src/{manager,health,broadcast}.rs` |
| 2.7 | `slashing`: check inputs (debug), decision (debug), DB interaction | 2 | feature | P1 | — (Phase 1 kit) | 1-2 days | `crates/slashing/src/**` |
| 2.8 | `duty-tracker`: fetch / cache hit-miss / dependent-root / epoch boundary | 2 | feature | P1 | — (Phase 1 kit) | 1-2 days | `crates/duty-tracker/src/**` |
| 2.9 | orchestrator: rename `rvc.*` slot/phase spans + duty/attestation/aggregation debug+trace | 3 | feature | P0 | 2.1 | 2 days | `crates/rvc/src/orchestrator/{coordinator,attestation,aggregation,duty_management}.rs` |
| 2.10 | `builder` + `block-service`: block build steps (trace), publish milestone (info), `block_root` | 2 | feature | P1 | 2.4 | 1-2 days | `crates/builder/src/**`, `crates/block-service/src/**` |
| 2.11 | Gate 3 captured-subscriber conformance tests (crypto, signer, :9000, rvc-keygen) | 3 | feature | P0 | 2.2, 2.3, 2.4 | 2 days | test modules in 4 crates |
| 2.12 | Gate 4 counting-allocator zero-alloc test + `release_max_level_debug` on both bins | 3 | feature | P0 | 2.2, 2.4 | 2 days | `crates/signer/{src,tests}`, `bin/*/Cargo.toml` |
| 2.13 | `criterion` sign-path + per-slot bench (latency sanity companion) | 2 | feature | P2 | 2.12 | 1-2 days | `crates/signer/benches/sign_path.rs`, `Cargo.toml` |

**Total: 13 issues, 30 points.**

---

## Phase Execution Plan

Single-stream: one code-writer works in order. Each row is one day of work; multi-point issues span
multiple rows. The ordering front-loads the load-bearing signer/`:9000` correlation work (2.1-2.3),
runs the independent kit-consuming crates in the middle (2.4-2.10), then lands the proof gates
(2.11-2.13) once their subjects exist.

| Day | Issue | Notes |
|-----|-------|-------|
| 1-2 | 2.1 (3 pts) | Namespace rename in `signer`; unblocks 2.2/2.3/2.9. Touch the span-name test assertions. |
| 3-4 | 2.2 (3 pts) | `spawn_blocking` re-entry + `TruncatedRoot`; depends on the 2.1 rename landing first. |
| 5-6 | 2.3 (3 pts) | The :9000 bridge; introduces `rvc-signer-bin -> telemetry`. Depends on 2.1's canonical names. |
| 7-8 | 2.4 (2 pts) | `crypto` sign/domain/root paths; independent of 2.1-2.3, sequenced here so 2.11/2.12 have it. |
| 9-10 | 2.5 (2 pts) | `beacon` framing; independent. |
| 11-12 | 2.6 (2 pts) | `bn-manager` selection/failover; independent. |
| 13-14 | 2.7 (2 pts) | `slashing`; independent. |
| 15-16 | 2.8 (2 pts) | `duty-tracker`; independent. |
| 17-18 | 2.9 (3 pts) | orchestrator rename + duty/att/agg coverage; depends on 2.1's registry being settled. |
| 19 | 2.10 (2 pts) | `builder`/`block-service`; depends on 2.4's `TruncatedRoot` adoption pattern. |
| 20-21 | 2.11 (3 pts) | Gate 3 conformance tests; runs after its subjects (2.2/2.3/2.4) exist. |
| 22-23 | 2.12 (3 pts) | Gate 4 zero-alloc + `release_max_level_debug`; runs after sign-path edits (2.2/2.4). |
| 24 | 2.13 (2 pts) | `criterion` bench; non-blocking companion to 2.12. |

> Sequencing note: 2.4-2.8 are mutually independent kit-consumers and could be reordered freely; they
> are listed crypto-first so the high-risk crate is done early and the Gate-3/Gate-4 subjects (2.11,
> 2.12) have everything they assert against. If a multi-stream model is ever adopted, 2.4-2.8 are the
> natural parallel tier and 2.1->2.2/2.3 is the serial spine.

---

## Issues

### Issue 2.1: `signer` — rename `rvc.*` spans/fields to the canonical registry (+ update span-name tests)
- **Points:** 3
- **Type:** chore (namespace normalization)
- **Priority:** P0
- **Blocked by:** none (consumes the Phase 1 `crypto::logging::fields` registry)
- **Blocks:** 2.2, 2.3, 2.9
- **Scope:** 1-2 days

**Description:**
The `SigningGate.sign_*` methods carry `rvc.`-prefixed span names and fields that produce *different*
OTLP attribute keys than the canonical registry (`rvc.slot` and `slot` are distinct attributes, so a
dashboard grouping by `slot` silently misses these spans). Normalize them to the unprefixed registry
**before** the `spawn_blocking`/bridge work (2.2/2.3) so re-instrumentation does not re-introduce the
prefixed keys (ADR-008 binds these together). This issue is the rename only; the blocking-section fix
and `TruncatedRoot` adoption are 2.2.

**Implementation Notes:**
- Files: `crates/signer/src/lib.rs` only.
- Verified sites to rename:
  - `:126` `#[instrument(name = "rvc.sign.attestation", skip_all, fields(rvc.operation = "attestation", rvc.slashing.result))]`
    -> name `rvc.sign.attestation` is a stable greppable span name; per STANDARD.md keep a stable
    `name` but move correlation to canonical `fields`. Replace `rvc.operation` with `duty =
    %fields::Duty::Attestation.as_str()` (or the canonical `DUTY` key) and rename the late-bound
    `rvc.slashing.result` field to an unprefixed key (e.g. `slashing_result`, declared at span
    creation so `record()` lands — see record discipline below).
  - `:330` the `sign_block` equivalent (`rvc.operation = "block"`, `rvc.slashing.result`).
  - `:189` `info_span!("rvc.slashing.check")` -> unprefixed span name per STANDARD.md.
  - `:306`/`:311` (attestation) and the block arm's `Span::current().record("rvc.slashing.result", …)`
    -> the renamed unprefixed key. **The recorded key MUST match the key declared in the
    `#[instrument(fields(...))]` list, or the `record()` is silently dropped** (use `record_display`
    from the kit, and declare the field at span creation).
  - Apply to every instrumented `sign_*` arm (attestation, block, randao, sync, aggregate, exit,
    registration, contribution) — grep `rvc\.` across the file to find them all.
- Keep `skip_all` on every arm (it is the redaction + perf control; bare `#[instrument]` on a sign fn
  is forbidden by STANDARD.md and flagged by Gate 1).
- **R1 rule:** `fields(...)` on `#[instrument]` evaluates eagerly on every call — keep only `Copy`
  scalars / `&'static str` (`duty = %Duty::…::as_str()` is a `&'static str`, fine). No `hex::encode`
  or formatting in instrument `fields` (that is 2.2's `TruncatedRoot` work on event macros).
- **Watch out for:** there are tests that assert the *old* span names. Grep the workspace for
  `rvc.sign.`, `rvc.slashing.`, and any `span_names.contains` assertions and update them in this same
  issue (the orchestrator has the same pattern at `coordinator.rs:3729-3739`, but those belong to 2.9;
  here, fix only the signer/slashing span-name assertions).

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed span name or field key remains in `crates/signer/src/lib.rs` (grep `rvc\.`
      returns 0 logging hits).
- [ ] Each instrumented `sign_*` arm uses the canonical `duty` value string from `fields::Duty` and
      keeps `skip_all`.
- [ ] The renamed late-bound slashing-result field is declared at span creation and recorded via the
      kit's `record_display`/`record_debug` so it lands on the span (not silently dropped).
- [ ] Any test asserting the old `rvc.sign.*` / `rvc.slashing.*` span names is updated to the new
      names and passes.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and
      `cargo nextest run --workspace` all green. (TDD: first update/observe the failing span-name
      assertion, then rename to green.)

**Testing Notes:**
- The captured-subscriber span-name assertions are the RED step — update them to the new names first,
  watch them fail against the old code, then rename. Gate 3's deeper field/level assertions land in
  2.11; here it is sufficient that the existing signer tests pass with the new names.

---

### Issue 2.2: `signer` — `spawn_blocking` span re-entry + `TruncatedRoot` adoption (zero-alloc)
- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 2.1 (rename must land first so re-entry uses canonical names)
- **Blocks:** 2.11, 2.12
- **Scope:** 2 days

**Description:**
Two coupled correctness fixes on the sign path. (1) The BLS sign + slashing-DB work runs inside a
`spawn_blocking` closure on an OS thread that does **not** re-enter the parent `sign` span, so
`crypto`/`slashing` events emitted there are detached from the duty trace (ADR-008). Capture
`Span::current()` before `spawn_blocking` and `let _e = span.enter()` *inside* the closure (safe —
there is no `.await` there). (2) The sign path eagerly allocates hex strings for roots/domains even
when the level is disabled (the R1 trap); replace those with the zero-alloc `TruncatedRoot(&[u8])`
wrapper on the `debug!`/`trace!` event macros.

**Implementation Notes:**
- Files: `crates/signer/src/lib.rs` only.
- **Span re-entry (verified sites):** `sign_attestation` `spawn_blocking` at `:209`; `sign_block`
  `spawn_blocking` at `:372`. Before each, `let span = tracing::Span::current();`; as the first line
  inside the closure, `let _e = span.enter();`. Do the same for any other instrumented `sign_*` arm
  that uses `spawn_blocking`. (Do **not** touch `crates/signer/src/gate.rs:270/:405` — those
  `spawn_blocking` closures belong to `SigningGate` methods that are *not* `#[instrument]`-annotated,
  so re-entering there would attach to no span; ADR-008.)
- **`TruncatedRoot` adoption (verified eager-alloc sites):**
  - `:170` `let signing_root_hex = hex::encode(signing_root);` and `:174`
    `signing_root = %format!("0x{}", &signing_root_hex)` -> emit `signing_root = %TruncatedRoot::new(signing_root.as_ref())`
    directly on the `debug!`/`trace!` macro (no local, no `format!`). Note the `signing_root_hex`
    *string* is also reused for the slashing DB `stage_*` call at `:217` — that DB use is NOT a log
    and must keep the full hex; only the **logging** field changes. Keep the DB string; drop only the
    `%format!` logging usage. (Verify whether the local can be dropped or must stay for the DB call;
    if it must stay for the DB, the log field still switches to `%TruncatedRoot` so no *extra*
    allocation happens for logging.)
  - `:161-163` `fork_version_used`/`genesis_validators_root`/`domain` `%format!("0x{}", hex::encode(...))`
    fields -> `%TruncatedRoot::new(&fork_version)` etc. on the event macro (these are non-secret
    domain bytes; truncated is fine and zero-alloc when disabled).
  - `:359` the `sign_block` `let signing_root_hex = hex::encode(signing_root);` — same treatment.
- **Per STANDARD.md / R1:** roots/signatures are truncated even at `trace`; the redaction wrapper goes
  on the event macro (`debug!`/`trace!`), never in an ungated `#[instrument(fields(...))]`.
- **Watch out for:** the eager `pubkey_hex = hex::encode(pubkey_bytes)` at `:137`/`:341` is currently
  unconditional and reused across several `debug!` lines; it is non-secret (a pubkey) and feeds
  `TruncatedPubkey`. Leave the existing `%TruncatedPubkey::new(&pubkey_hex)` pattern; the zero-alloc
  goal here is specifically the *root/domain* `format!`+`hex::encode` locals, which 2.12's allocator
  test will assert against. (A follow-on micro-optimization of the pubkey hex is out of scope.)

**Acceptance Criteria:**
- [ ] Both verified `spawn_blocking` closures (`:209`, `:372`, plus any other instrumented arm)
      capture `Span::current()` and `let _e = span.enter()` as the first line inside the closure.
- [ ] No `%format!("0x{}", hex::encode(...))` logging field remains on the sign path; root/domain log
      fields use `%TruncatedRoot::new(&bytes)` on `debug!`/`trace!` macros.
- [ ] Signing behavior is unchanged: the slashing DB `stage_*` calls still receive the full
      `signing_root_hex` string; no signature/root value is altered.
- [ ] A captured-subscriber test (can be the seed of Gate 3 / 2.11) shows an event emitted from
      *inside* the blocking section carries the span's correlation fields (e.g. `slot`).
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- TDD: write a `#[tracing_test::traced_test]` test that signs an attestation under a capturing
  subscriber and asserts a known blocking-section event line carries `slot` (RED before the
  `span.enter()` fix, GREEN after). The zero-alloc proof itself is 2.12.

---

### Issue 2.3: `bin/rvc-signer` :9000 — wire `set_parent_from_headers` + `request_id` + `x-request-id` (the bridge)
- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** the Phase 1 kit (1.3 `fields`/`Duty`, 1.4 `new_request_id` + `record_*` helpers,
  1.5 `set_parent_from_headers`) plus 2.1. This issue *consumes* the Phase-1 kit (`new_request_id`,
  `record_display`, `fields::{SLOT,PUBKEY,DUTY}`, `telemetry::propagation::set_parent_from_headers`),
  which 2.1 — a signer-internal rename — does not produce; 2.1 is required only so the late-bound
  field names are already canonical. The kit is a phase-wide entry criterion, made explicit here.
- **Blocks:** 2.11
- **Scope:** 2 days

**Description:**
The :9000 `sign` handler currently starts a fresh root trace, so a duty trace breaks at the
Web3Signer boundary. Wire the Phase-1 `telemetry::set_parent_from_headers` as the **first** action in
the handler span so it becomes a child of the caller's trace (honoring the existing
`ParentBased(TraceIdRatioBased)` sampler), mint/read a `request_id`, echo it via an additive
`x-request-id` response header, and fill the late-bound span fields (`slot`/`duty`/`pubkey`) via
`record_display` after the body parses. This is the bridge that ends the cross-process trace break and
introduces the single new production edge `rvc-signer-bin -> rvc-telemetry`.

**Implementation Notes:**
- Files: `bin/rvc-signer/src/http_api/routes.rs` (the `sign` handler at `:51`, already
  `#[tracing::instrument(skip_all)]`, already takes `headers: axum::http::HeaderMap` at `:56`) and
  `bin/rvc-signer/Cargo.toml` (add `telemetry.workspace = true` — the **one new edge**; Gate 6 already
  accepts it).
- Declare the late-bound fields on the handler's `#[instrument]`: add
  `fields(otel.kind = "server", request_id = tracing::field::Empty, slot = tracing::field::Empty,
  duty = tracing::field::Empty, pubkey = tracing::field::Empty)`. (`record()` on an undeclared field
  is silently dropped — declare them `Empty`, mirroring `beacon::client`'s `http.status_code = Empty`
  pattern.)
- First line of the handler body: `telemetry::set_parent_from_headers(&tracing::Span::current(),
  &headers);`.
- `request_id`: read `x-request-id` from `headers`; if present, record it; else
  `crypto::logging::new_request_id()` (a `Uuid`) and record with `%`. Echo it back as an
  `x-request-id` response header on the `Response` (additive; does not change signing). This matches
  the `keymanager-api` precedent (`Uuid::new_v4()` + `request_id = %req_id`).
- After the body parses (inside or just after `sign_inner` resolves the pubkey/type/slot), fill the
  span via `record_display(&span, fields::SLOT, slot)`, `record_display(&span, fields::PUBKEY,
  TruncatedPubkey::new(&pubkey_hex))`, `record_display(&span, fields::DUTY, Duty::…::as_str())`. **No
  secrets**: pubkey via `TruncatedPubkey`, never the body/root/signature.
- The existing one-line metadata-only audit log (success=`info`, rejection=`warn`, `:99`) stays; add
  the `request_id`/`x-request-id` to it so both sides log the same correlator. Do NOT fold the audit
  log into the trace (cross-cutting concern: it stays a separate metadata-only line).
- **Watch out for:** `sign_inner` is a separate fn (`:115`) that resolves the pubkey; the late-bind
  `record()` must happen on the *handler* span (`Span::current()` inside `sign`), so either thread the
  resolved values back out (there is already a `rpc_type` out-param at `:73`/`:121` — mirror that) or
  record inside `sign_inner` using `Span::current()` (which is the handler's instrument span because
  `sign_inner` is called without its own `#[instrument]`). Confirm which and keep it consistent.

**Acceptance Criteria:**
- [ ] `bin/rvc-signer/Cargo.toml` declares `telemetry.workspace = true`; Gate 6
      (`cargo nextest -p rvc-architecture-tests`) stays green with the `rvc-signer-bin -> rvc-telemetry`
      edge.
- [ ] `set_parent_from_headers` is the first action in the `sign` handler body.
- [ ] A test feeding a synthetic inbound `traceparent` to the live handler asserts the resulting
      `sign` span has a **non-zero OTel parent** (continues the caller's trace); a request with no
      `traceparent` yields a root span and does not panic.
- [ ] `request_id` is present on the span and echoed as an `x-request-id` response header; when the
      caller sends `x-request-id`, the same value is used (not a fresh one).
- [ ] The late-bound `slot`/`duty`/`pubkey` fields land on the span (asserted present), `pubkey`
      truncated.
- [ ] No request body, signing root, or signature appears in any log line on the path (re-asserted by
      Gate 3 in 2.11).
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green; existing
      `bin/rvc-signer` http_api tests still pass.

**Testing Notes:**
- The handler is already exercised in-memory via the `tower` oneshot pattern (a dev-dep). Build the
  inbound-`traceparent` test on that harness with an active OTel layer (mirror
  `telemetry/src/propagation.rs::test_inject_with_otel_layer`). Assert non-zero parent and the
  `x-request-id` response header.

---

### Issue 2.4: `crypto` — canonical fields + `TruncatedRoot` on sign/domain/root paths
- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Blocked by:** none (consumes the Phase 1 kit)
- **Blocks:** 2.10, 2.11, 2.12
- **Scope:** 1-2 days

**Description:**
Apply the canonical fields and `TruncatedRoot` redaction to `crypto`'s own logging on the
signing-root / domain / signature computation paths, and ensure `crypto`'s `debug`/`trace` lines on
the hot path are zero-alloc when disabled. `crypto` is a high-risk crate (it touches BLS keys), so
every added/changed statement is reviewed under the redaction policy: no raw key bytes, pubkeys via
`TruncatedPubkey`, roots/signatures via `TruncatedRoot`.

**Implementation Notes:**
- Files: under `crates/crypto/src/**` (the BLS sign, `compute_domain`, `compute_signing_root`, and
  any existing `debug!`/`trace!`/`#[instrument]` sites). `crypto::logging` already hosts the wrappers
  (`crates/crypto/src/logging.rs`); `crypto::logging::fields`/`TruncatedRoot` arrive from Phase 1.
- Add `trace` step coverage where the signing payload is built (non-secret intermediate
  roots/domains) using `%TruncatedRoot::new(&bytes)` on the event macro. Add `debug` for decision
  points. Use canonical field keys from `crypto::logging::fields`.
- **Gate 1 interplay:** any legitimate `to_bytes()`/`raw_bytes()`/`expose_secret` call on a sign path
  is already on the scoped `#[allow(clippy::disallowed_methods)]` allow-list from Phase 1; do NOT add
  new unscoped uses, and never pass their output to a logging macro. `skip_all` on any `#[instrument]`
  taking a `&SecretKey`/payload.
- **R1 rule:** redaction wrappers go on event-family macros, not in `#[instrument(fields(...))]`.

**Acceptance Criteria:**
- [ ] `crypto` sign/domain/root paths have `debug` decision points and `trace` step coverage using
      canonical field keys and `TruncatedRoot`/`TruncatedPubkey`; no raw key bytes, full root, or full
      signature is logged at any level.
- [ ] Every `#[instrument]` on a fn taking a secret/large arg uses `skip_all`.
- [ ] No new unscoped `expose_secret`/`raw_bytes`/`to_bytes` usage (Gate 1:
      `cargo clippy --workspace --all-targets -- -D warnings` green).
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- Seed the Gate-3 captured-subscriber tests here (formalized in 2.11): fire a representative
  signing-root `trace!` and assert the truncated form is present and the full 32-byte hex is absent.

---

### Issue 2.5: `beacon` — endpoint selection (debug) + request/response framing (trace) + `RedactedUrl`
- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** none (consumes the Phase 1 kit)
- **Blocks:** —
- **Scope:** 1-2 days

**Description:**
Add `trace` wire-level request/response framing and `debug` endpoint-selection coverage to the beacon
HTTP client, with the `bn_url` always redacted. `beacon` already depends on `telemetry` and already
has the `enabled!(Level::TRACE)`-guarded body-size `trace!` at `client.rs:149` — extend that pattern
rather than introduce eager formatting.

**Implementation Notes:**
- Files: `crates/beacon/src/client.rs` (the `post`/`get` request paths; the existing guarded `trace!`
  at `:149`, the `inject_trace_context` call at `:159`). Other modules under `crates/beacon/src/` as
  needed.
- Add `trace` framing for both request and response (method, path, status, body size) — reuse the
  `if tracing::enabled!(tracing::Level::TRACE) { … }` guard for any multi-statement / serialize work
  (this is the proven zero-cost pattern, research §D).
- Any URL/endpoint in a log line uses `%RedactedUrl::new(&url)` (canonical `bn_url` key) — never raw
  credentials.
- Keep correlation spans-first: if a request fn is `#[instrument]`, put `bn_url` on the event (it is
  an event-level field per the registry), not duplicated per line.

**Acceptance Criteria:**
- [ ] Request and response framing logged at `trace` behind an `enabled!` guard (no eager serialize
      when trace is disabled).
- [ ] Endpoint selection logged at `debug`.
- [ ] Every URL/endpoint log field uses `RedactedUrl` and the canonical `bn_url` key; no raw
      `user:pass@` reaches a log macro.
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green; existing beacon
      tests (incl. `wiremock`-based) still pass.

**Testing Notes:**
- A captured-subscriber test asserting a credentialed URL renders redacted (`***`) in the emitted
  `debug`/`trace` line; reuse the `RedactedUrl` model tests in `crypto`.

---

### Issue 2.6: `bn-manager` — selection (debug), failover (warn), `bn_url` redacted
- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** none (consumes the Phase 1 kit)
- **Blocks:** —
- **Scope:** 1-2 days

**Description:**
`bn-manager` is near-silent on the operational hot path. Add `debug` for which beacon node was
selected and why, and `warn` for failover events (per the taxonomy: failover is handled/degraded ->
`warn`, not `error`), with `bn_url` redacted everywhere.

**Implementation Notes:**
- Files: `crates/bn-manager/src/manager.rs`, `health.rs`, `broadcast.rs` (selection / health
  transitions / broadcast fan-out). `bn-manager` depends on `crypto`, so `RedactedUrl`/`fields` are
  reachable with no new edge.
- Failover / health-state transitions -> `warn` with `%RedactedUrl` and the reason. Endpoint
  selection -> `debug`. Per-item broadcast loops -> `trace`.
- **Taxonomy gotcha:** "all beacon nodes unreachable" (an intended action cannot complete) is `error`;
  a single-node failover that still progresses is `warn`. Be deliberate.

**Acceptance Criteria:**
- [ ] Endpoint selection at `debug`; failover at `warn`; total-outage (no node usable) at `error`.
- [ ] Every URL log field uses `RedactedUrl` + the canonical `bn_url` key.
- [ ] Per-broadcast-item loops are `trace`, not `info`/`debug` (volume scales with node count).
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- Captured-subscriber test asserting a failover fires at `warn` with a redacted `bn_url`.

---

### Issue 2.7: `slashing` — check inputs (debug), decision (debug), DB interaction
- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** none (consumes the Phase 1 kit)
- **Blocks:** —
- **Scope:** 1-2 days

**Description:**
Make the slashing-protection decision reconstructable from logs: log the (non-secret) check inputs,
the decision (safe/blocked), and the DB interaction at `debug`, with a terminal `error` only when a
sign is actually rejected (which is the intended-action-failed case). Pair with the `signer`-side
`slashing_result` span field from 2.1 so the decision correlates to the duty.

**Implementation Notes:**
- Files: under `crates/slashing/src/**` (the `rvc-slashing` crate). The signer already emits the
  `rvc.slashing.check` span (renamed in 2.1) and records the result; this issue covers the slashing
  crate's *own* internal logging.
- Check inputs (source/target epoch, slot, signing root via `TruncatedRoot`, `pubkey` via
  `TruncatedPubkey`) -> `debug`. Decision -> `debug`. DB row stage/commit/discard -> `debug`/`trace`.
- A rejection that blocks a sign is the terminal failure -> `error` (logged once, at the layer that
  decides it is terminal — the existing signer-side `error!("Slashing protection rejected …")` at
  `signer/src/lib.rs:221`/`:378` is that layer; do not duplicate the same `error` inside slashing —
  return the `Result` per CLAUDE.md "log once").
- Canonical field keys; no full signing root in any line (truncate via `TruncatedRoot`).

**Acceptance Criteria:**
- [ ] Slashing check inputs and decision are logged at `debug` with canonical fields and truncated
      roots/pubkeys.
- [ ] DB stage/commit/discard logged at `debug`/`trace`.
- [ ] No duplicate `error` line for a rejection that the signer layer already logs as terminal (one
      event, one level, one layer).
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- Captured-subscriber test asserting a "blocked" decision logs at `debug` (not `error`) inside
  slashing, and the full signing root is absent.

---

### Issue 2.8: `duty-tracker` — fetch / cache hit-miss / dependent-root / epoch boundary
- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** none (consumes the Phase 1 kit)
- **Blocks:** —
- **Scope:** 1-2 days

**Description:**
Make duty management observable: log duty fetches, cache hit/miss and contents, dependent-root
handling, and epoch boundaries at `debug` (decision/internal state), with `trace` for per-duty loop
detail. `duty-tracker` (`rvc-duty-tracker`) already has `#[instrument]` sites (it is in the existing
72); extend their fields to the canonical registry and set `level="debug"` where they are per-slot.

**Implementation Notes:**
- Files: under `crates/duty-tracker/src/**`.
- Cache hit/miss + contents -> `debug`; dependent-root handling -> `debug`; epoch boundary -> `info`
  milestone (one line, low volume) or `debug` depending on volume (per STANDARD.md: epoch boundary is
  an `info` milestone). Per-duty iteration -> `trace`.
- Put `slot`/`epoch`/`validator_index` on the existing `#[instrument]` spans (spans-first);
  `level="debug"` on any per-slot/per-validator instrumented fn (the default INFO would flood the
  heartbeat — the single most common mis-use to audit for, research rule 3).
- **R1:** scalars only in instrument `fields`.

**Acceptance Criteria:**
- [ ] Duty fetch, cache hit/miss + contents, and dependent-root handling logged at `debug` with
      canonical `slot`/`epoch`/`validator_index` keys.
- [ ] Epoch-boundary milestone at `info`; per-duty loop detail at `trace`.
- [ ] Any per-slot/per-validator `#[instrument]` is `level = "debug"` (or `"trace"`), not the default
      INFO.
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- Captured-subscriber test asserting a cache hit logs at `debug` and a per-validator loop line logs at
  `trace`.

---

### Issue 2.9: orchestrator — rename `rvc.*` slot/phase spans + duty/attestation/aggregation debug+trace
- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** 2.1 (registry/field naming settled)
- **Blocks:** —
- **Scope:** 2 days

**Description:**
The orchestrator carries the per-slot heartbeat and the `rvc.`-prefixed slot/phase spans. Normalize
those span/field names to the canonical registry (so dashboards group on `slot`, not `rvc.slot`), add
`debug` decision points and `trace` step coverage to the attestation/aggregation/duty-management
paths, and shape the `info` heartbeat per STANDARD.md (milestone per completed duty carrying `slot`;
build/sign at `debug`, publish at `info`). This is the largest single-crate surface in the phase.

**Implementation Notes:**
- Files: `crates/rvc/src/orchestrator/coordinator.rs`, `attestation.rs`, `aggregation.rs`,
  `duty_management.rs` (the verified module set). `sync_committee.rs` may also carry `rvc.`-prefixed
  fields — grep and include it if so.
- **Verified `rvc.`-prefixed sites to rename in `coordinator.rs`:** `info_span!("rvc.slot.process",
  rvc.slot = …, rvc.epoch = …)` `:320`; `info_span!(… "rvc.epoch.boundary", rvc.epoch = …)` `:345`;
  `info_span!(… "rvc.slot.phase.block")` `:381`; `"rvc.slot.phase.attestation"` `:391`;
  `"rvc.slot.phase.aggregation"` `:477`; `#[tracing::instrument(name = "rvc.orchestrator.maybe_propose_block",
  skip_all, fields(rvc.slot = slot, rvc.epoch = epoch))]` `:602`. Replace `rvc.slot`/`rvc.epoch` field
  keys with the canonical `slot`/`epoch` (`fields::SLOT`/`EPOCH`); keep stable span `name=`s but
  unprefixed (e.g. `slot.process`) per STANDARD.md.
- **Test fallout (verified):** `coordinator.rs:3729-3739` asserts `span_names.contains("rvc.slot.process")`,
  `"rvc.slot.phase.block"`, `"rvc.slot.phase.attestation"` — update these assertions to the new names
  in this same issue. Grep the whole `crates/rvc` tree for `rvc.slot`, `rvc.epoch`, `rvc.orchestrator`,
  `rvc.slot.phase` to find every assertion.
- **Heartbeat per STANDARD.md / research §G:** keep `info` to milestones (validators loaded, BN
  connected, epoch boundary, attestation/aggregate published, block proposed, sync message/contribution,
  validator registration); demote `Signed…`, duty cache hit/miss, BN selection to `debug`; per-item
  loops to `trace`. Use `head` (attested head root, `TruncatedRoot`) and `committee_index` on the
  attestation line. The existing per-slot `debug!`/`info_span!` calls (`:396`, `:452`, `:460`, `:492`,
  `:524`, `:542`) already lean `debug` — conform their field keys and confirm levels.
- **`level="debug"`** on any per-slot/per-validator `#[instrument]` (research rule 3).
- **R1:** scalars only in instrument `fields`; `TruncatedRoot`/`TruncatedPubkey` go on event macros.

**Acceptance Criteria:**
- [ ] No `rvc.`-prefixed span name or field key remains anywhere under `crates/rvc/src/orchestrator/`
      (grep `rvc\.` returns 0 logging hits); `slot`/`epoch` are the emitted attribute keys.
- [ ] All `rvc.`-prefixed span-name assertions under `crates/rvc` are updated to the canonical
      registry names and pass — including (but grep the whole tree to confirm) `coordinator.rs`
      `rvc.orchestrator.produce_aggregations` (:3889, :3949), the negative `rvc.aggregation.submit`
      assertion (:3955), `rvc.epoch.boundary` (:3797), and the parent-child checks (:4013-4030).
- [ ] `info` is milestones-only (one line per completed duty with `slot`); duty cache hit/miss, BN
      selection, and `Signed…` are at `debug`; per-item loops at `trace`.
- [ ] Attestation `info` line carries `head = %TruncatedRoot` and `committee_index`; block line carries
      `block_root = %TruncatedRoot`.
- [ ] Any per-slot/per-validator `#[instrument]` is `level="debug"`/`"trace"`, not default INFO.
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- Update the existing span-name assertions first (RED), rename to GREEN. Add a captured-subscriber
  test asserting the per-slot heartbeat emits one `info` "published" line with `slot` and that cache
  hit/miss is `debug`.

---

### Issue 2.10: `builder` + `block-service` — block build steps (trace), publish milestone (info), `block_root`
- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** 2.4 (reuse the `crypto` `TruncatedRoot` adoption pattern)
- **Blocks:** —
- **Scope:** 1-2 days

**Description:**
Make block production observable: `trace` for the build steps, `debug` for selection/decision points,
and an `info` "block proposed" milestone carrying `slot` and a truncated `block_root`. Covers both the
`rvc-builder` and `rvc-block-service` crates.

**Implementation Notes:**
- Files: under `crates/builder/src/**` and `crates/block-service/src/**`.
- Build steps (assembling the block, local-vs-builder selection) -> `trace`/`debug`; the final
  publish -> `info` "block proposed" with `slot` + `block_root = %TruncatedRoot::new(root.as_ref())`.
- Spans-first: `slot`/`validator_index` on the existing `#[instrument]` spans; `level="debug"` on
  per-slot fns.
- Reuse the exact `TruncatedRoot` usage established in 2.4 (event-macro, zero-alloc, truncated even at
  `trace`).

**Acceptance Criteria:**
- [ ] Block build steps at `trace`, selection at `debug`, publish at `info` with `slot` and
      `block_root = %TruncatedRoot`.
- [ ] No full block root or payload logged at any level; `block_root` truncated.
- [ ] Per-slot `#[instrument]` is `level="debug"`/`"trace"`.
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- Captured-subscriber test asserting the publish line is `info` with a truncated `block_root` and the
  full root hex is absent.

---

### Issue 2.11: Gate 3 — captured-subscriber conformance tests (crypto, signer, :9000, rvc-keygen)
- **Points:** 3
- **Type:** feature (test harness; the P0-3 enforcement proof)
- **Priority:** P0
- **Blocked by:** 2.2, 2.3, 2.4 (the high-risk-crate logging must exist to assert against)
- **Blocks:** —
- **Scope:** 2 days

**Description:**
Land the Gate 3 captured-subscriber / `tracing_test` conformance tests that prove, at runtime, that
the high-risk crates redact correctly, fire at the intended level, carry the intended canonical
fields, and that late-bound `record()` fields land on the span. This is the runtime half of the
defense-in-depth secret gate (the other halves are Gate 1 clippy sinks and Gate 2 gitleaks, both from
Phase 1). The emitted-log sample these tests produce is also what Gate 2 scans (architecture Open Q5:
reuse the captured-subscriber tests for the emitted sample).

**Implementation Notes:**
- Crates: `crypto`, `signer`, `bin/rvc-signer` (`rvc_signer_bin`), and `rvc-keygen` — each gets
  `#[tracing_test::traced_test]` tests in a `#[cfg(test)]` module. `tracing-test` is already a
  workspace dev-dep (verified in `bin/rvc-signer/Cargo.toml:109`); add it to any of the four that
  lacks it.
- The proven in-tree model is `test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` at
  `crates/crypto/src/logging.rs:119` (uses `logs_contain(...)`).
- **Per high-risk crate, assert (the redaction half):** fire each high-risk log line and assert the
  output **contains** the truncated/redacted form (`0x…...…`, `***`) and **does NOT** contain the raw
  secret (full key hex, full root, full signature, password, mnemonic, raw `user:pass@`). Pubkeys
  truncated **even at `trace`**.
- **Assert (the conformance half):** representative hot-path events fire at the **intended level**
  (e.g. "published" at `info`, "Signed"/cache hit/miss at `debug`, wire framing at `trace`) and carry
  the **intended canonical fields**; and that late-bound `record()` fields from 2.3 (`slot`/`duty`/
  `pubkey`) and 2.1 (`slashing_result`) are **present on the emitted span** (the vanishing-attribute
  guard).
- **`rvc-keygen` specifics:** treat the bare `bip39::Mnemonic` as a sink (it `Display`s to the
  phrase). Assert no mnemonic phrase — **and not even its length** — appears at any level. This is the
  Phase-2 high-risk sign-off pulled forward from Phase 4 breadth.
- **:9000 specifics:** assert the body/root/signature never appears in the handler or audit line, and
  that the `pubkey` on the exported span attributes is truncated.

**Acceptance Criteria:**
- [ ] Each of `crypto`, `signer`, `bin/rvc-signer`, `rvc-keygen` has captured-subscriber tests
      asserting raw secret **absent** and truncated/redacted form **present** for every high-risk line.
- [ ] Tests assert intended level and intended canonical fields for representative hot-path events,
      including blocking-section events (from 2.2) carrying the span's `slot`/`request_id`.
- [ ] Late-bound `record()` fields (:9000 `slot`/`duty`/`pubkey`; signer `slashing_result`) are
      asserted present on the emitted span.
- [ ] `rvc-keygen`: no mnemonic phrase and no mnemonic length at any level.
- [ ] The tests run under `cargo nextest run --workspace` (Gate 3 rides the existing coverage job) and
      are 0-findings green.
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- These are the formalization of the seed tests written in 2.2/2.4. Keep each assertion explicit about
  *which* raw value must be absent, so a future regression names the leak. The emitted sample for Gate
  2 is captured from these same tests at `trace` level.

---

### Issue 2.12: Gate 4 — counting-allocator zero-alloc test + `release_max_level_debug` on both bins
- **Points:** 3
- **Type:** feature (the precise P0-6 gate)
- **Priority:** P0
- **Blocked by:** 2.2, 2.4 (the sign-path `TruncatedRoot` adoption must be in place)
- **Blocks:** 2.13
- **Scope:** 2 days

**Description:**
Turn "disabled `debug!`/`trace!` perform no allocation/formatting/hashing" from a claim into a tested
invariant, and physically remove `trace!` from the release binaries. Add a dependency-free
counting-`#[global_allocator]` test that asserts zero incremental allocations across a
`sign_attestation`/`sign_block` call and one coordinator/per-slot phase under an `info`-level
subscriber (trace/debug OFF), and add `release_max_level_debug` to `tracing` in both binaries' Cargo
manifests. This is the **precise** P0-6 gate (a ~1 ns span is below `criterion`'s measurement floor
next to a BLS sign).

**Implementation Notes:**
- **Counting allocator:** a small struct wrapping `std::alloc::System` that bumps an `AtomicUsize` on
  `alloc`/`realloc`, installed via `#[global_allocator]` in the signer test target (no external dep —
  not `dhat`). Read the counter before/after, `assert_eq!(allocs_after, allocs_before)`.
- **Test location:** `crates/signer/tests/` (an integration test) or a `#[cfg(test)]` module in
  `crates/signer/src/lib.rs` — wherever the `sign_attestation`/`sign_block` call can be driven under a
  capturing `info`-level subscriber with `debug`/`trace` disabled.
- **What it must catch:** the test must **fail** if someone reintroduces the eager
  `let signing_root_hex = hex::encode(...)` on the sign path (the R1 trap 2.2 fixed at
  `lib.rs:170/359`) or a `fields(... = %heavy)` on a hot `#[instrument]`. Add one assertion around a
  coordinator/per-slot phase too (the orchestrator's `process_slot` path, exercised in
  `crates/rvc/src/orchestrator/coordinator.rs` tests) — this may live in `crates/rvc/tests/` instead
  if the signer crate can't reach the coordinator.
- **`release_max_level_debug`:** in `bin/rvc/Cargo.toml` and `bin/rvc-signer/Cargo.toml`, change the
  `tracing` dependency to `tracing = { workspace = true, features = ["release_max_level_debug"] }`. In
  `--release`, `trace!` (and below-cap spans) compile to nothing; `debug!` stays `RUST_LOG`-switchable.
  **Do NOT enable tracing's `log` bridge feature** (re-introduces cost under a static cap; ADR-001).
- **Watch out for:** `nextest` runs tests in separate processes; a `#[global_allocator]` is
  process-global, so the counting allocator must be installed in the test *binary* and the assertion
  must isolate the measured region (warm up first to avoid one-time lazy allocations skewing the
  count — sign once untimed, then measure the second call).

**Acceptance Criteria:**
- [ ] A dependency-free counting `#[global_allocator]` test asserts `allocs_when_disabled == baseline`
      across `sign_attestation` and `sign_block` under an `info`-level subscriber (debug/trace off).
- [ ] The same assertion holds around one coordinator/per-slot phase.
- [ ] The test demonstrably fails if an eager `hex::encode` / heavy `#[instrument(fields)]` is
      reintroduced on the sign path (verify by temporarily reverting one and observing RED).
- [ ] `bin/rvc/Cargo.toml` and `bin/rvc-signer/Cargo.toml` enable `tracing`'s `release_max_level_debug`
      feature; the `log` bridge feature is NOT enabled.
- [ ] A `--release` build has no `trace!` output even with `RUST_LOG=trace`, while `RUST_LOG=debug`
      still produces `debug` output (spot-check / documented in the test or PR).
- [ ] The asserting test runs under `cargo nextest run --workspace`; `cargo fmt`,
      `cargo clippy -D warnings`, `cargo nextest run --workspace` green.

**Testing Notes:**
- The allocator counter is the precise gate; the `criterion` latency bench (2.13) is the non-blocking
  companion. Keep this test's measured region tiny and warmed-up so it is robust under `nextest`'s
  per-process execution.

---

### Issue 2.13: `criterion` sign-path + per-slot bench (latency sanity companion)
- **Points:** 2
- **Type:** feature (non-blocking regression guard)
- **Priority:** P2 (companion to the precise Gate 4; not a blocking PR gate)
- **Blocked by:** 2.12
- **Scope:** 1-2 days

**Description:**
Add a `criterion` sign-path bench comparing `no_subscriber` / `subscriber_info` (debug spans disabled)
/ `subscriber_trace` regimes, plus a per-slot-loop bench around one coordinator phase. It passes if
`info ≈ no_subscriber` within noise. This is the latency sanity companion to the precise zero-alloc
gate; it is run via `cargo bench`, not as a blocking PR gate (a ~1 ns span is below criterion's floor
next to a BLS sign, which is exactly why 2.12's allocator test is the precise gate).

**Implementation Notes:**
- Files: `crates/signer/benches/sign_path.rs` (new) + a `[[bench]]` entry and `criterion` dev-dep in
  `crates/signer/Cargo.toml`. No bench infra exists in the workspace today (research §H) — this
  establishes it.
- Three regimes: no subscriber; an `info`-level subscriber (debug/trace disabled); a `trace`-level
  subscriber. Assert/observe `info ≈ no_subscriber`.
- Add a per-slot-loop bench around one coordinator phase (may live in `crates/rvc/benches/` if it
  needs the orchestrator).
- This does NOT run under `nextest` or block CI; it is a `cargo bench` regression guard. Document that
  in the PR.

**Acceptance Criteria:**
- [ ] `crates/signer/benches/sign_path.rs` exists with the three regimes and builds under
      `cargo bench` (and `cargo build --benches`).
- [ ] The `info` regime is within noise of `no_subscriber` (recorded in the PR description as the
      baseline).
- [ ] A per-slot-loop bench around one coordinator phase exists.
- [ ] The bench is excluded from the blocking gates (does not affect `nextest`); `cargo fmt`,
      `cargo clippy -D warnings`, `cargo nextest run --workspace` still green (benches compile under
      `--all-targets`, so clippy must stay clean on the bench file too).

**Testing Notes:**
- Benches compile under `cargo clippy --workspace --all-targets`, so the bench file must be
  clippy-clean even though it is not run in CI. Keep the harness minimal.

---

## Phase Exit Checklist (roll-up)

- [ ] 2.1-2.13 merged to `develop`, each ff-only after review, each leaving the workspace green.
- [ ] No `rvc.`-prefixed logging keys remain in `crates/signer/src/lib.rs` or
      `crates/rvc/src/orchestrator/`.
- [ ] :9000 trace continuity proven on the live handler (non-zero parent); `request_id` +
      `x-request-id` on both sides.
- [ ] Gates 1 + 2 + 3 green with 0 secret findings on `crypto`, `secret-provider`, `signer`, the :9000
      path, and `rvc-keygen` mnemonics.
- [ ] Gate 4 zero-alloc assertion green on the sign and per-slot paths; eager `hex::encode` locals
      replaced by `TruncatedRoot`.
- [ ] `release_max_level_debug` on both binaries; `trace!` absent from `--release`, `debug!` still
      `RUST_LOG`-switchable; `criterion` bench shows `info ≈ no_subscriber`.
- [ ] Existing `telemetry`/OTLP/file-appender/propagation/shutdown tests still green (no regression).
- [ ] Standing invariant green: `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`
      (never `cargo test --workspace`).
