# PRD: Logging & Tracing Enhancement Initiative

## Overview

rs-vc already emits OpenTelemetry traces and uses `tracing` for structured logs, but coverage,
field conventions, and redaction discipline are inconsistent across the 23-crate workspace. This
initiative codifies existing conventions, retrofits the full workspace to them, and raises
observability to a level where an oncall engineer can debug a production duty failure end-to-end
from logs alone, and a developer can diagnose a failing `cargo test` without re-running with custom
`RUST_LOG` flags.

The scope is tuning, enforcement, and coverage — not a rewrite. We keep `tracing`,
`tracing-subscriber`, `tracing-opentelemetry`, `tracing-appender`, `logroller`, and the existing
`crates/telemetry` home.

## Problem Statement

Current state (empirical):

- ~74 `#[instrument]` attributes across 28 files, ~633 log calls across 61 files — heavy on
  `crates/beacon`, `crates/signer`, `crates/duty-tracker`, `crates/rvc/orchestrator`; near-zero on
  `crates/eth-types` (fine), but also thin on `bin/rvc-keygen`, parts of `bin/rvc-signer/dvt/`,
  `crates/block-service` helpers, `crates/builder`, `crates/timing`, `crates/keymanager-api`
  handlers, and `crates/validator-store` reload paths.
- Span-name and field-key conventions exist in practice (`rvc.{domain}.{operation}` names,
  `rvc.slot`, `rvc.epoch`, `rvc.operation`, `rvc.slashing.result`) but are not written down. New
  code invents new shapes.
- Redaction helpers (`TruncatedPubkey`, `RedactedUrl`) live in `crates/crypto/src/logging.rs` and
  are used inconsistently. Nothing prevents a contributor from logging a full 96-hex-char pubkey, a
  full BLS signature, a `SecretKey`, a mnemonic, or a `Zeroizing<_>` body via `{:?}` today.
- The duty-lifecycle span hierarchy is partial. `rvc.orchestrator.process_slot` and
  `rvc.attestation.produce` exist, but not all duty families wrap their phase handlers in a
  root-per-duty span, and field sets are heterogeneous.
- Tests emit whatever `tracing` output happens to reach a global subscriber, or nothing.
  `crates/secret-provider/tests/tracing_hierarchy.rs` is the only test that captures spans; most
  failing tests force the developer to re-run with `RUST_LOG=debug -- --nocapture`.
- Log sinks (`tracing-appender` + `logroller`) are wired but retention, rotation, and level
  policies for prod have not been reviewed against the intended deployment shape.

Consequences: oncall reconstructs duty failures by correlating metrics with partial logs and the
source. Developers pay a second test run every time a flake surfaces.

## Target Users & Scenarios

**Oncall engineer (prod debug).** "Validator `0x93247f...11df74a` missed the attestation in slot
7531200. Why?" Walks from slot log entry, to duty fetch, to signing attempt, to slashing check, to
propagation result, following one trace-id across crates, in under 5 minutes, without opening a
debugger or re-deploying with higher verbosity. All correlation keys (`rvc.slot`, `rvc.pubkey`
short-form, `rvc.validator_index`) are present on every span.

**Developer (test debug).** "Integration test `test_aggregation_submits_on_schedule` failed in CI."
Opens the test output, sees the captured span tree printed on failure — including every child span
and the fields on each — and identifies the root cause from the default output. No re-run, no
custom env vars.

## Goals & Success Metrics

**Primary goal (equal weight).** Deliver value for both prod debug and test debug.

**Acceptance metrics, measured on merge:**

1. Given a slot number and a validator pubkey, an oncall can reconstruct the full duty lifecycle
   (duty fetch → signing → slashing DB write → propagation → BN response) from the logs of a
   single trace id, within 5 minutes, using only a log viewer (Kibana / `jq` on file sink). Tested
   by a runbook walkthrough on a synthetic failure in the integration test rig.
2. A developer running `cargo test -p duty-tracker` or `cargo test -p rvc` on a failing test sees,
   in the default test output, the span tree and fields for the failing code path sufficient to
   identify the root cause without re-running. Tested by at least two "synthesize a failure, read
   output" exercises during review.
3. `cargo clippy --workspace --all-targets -- -D warnings` passes after the retrofit.
4. Workspace-wide `#[instrument]` coverage on public async fns on the duty hot path reaches 100%
   on the explicit list in P0-4 below. All spans on that list carry the mandatory field set from
   the conventions doc.
5. A regression test (`tests/forbidden_log_patterns.rs` or `cargo xtask lint-logs`) fails the build
   if any banned pattern (see P0-2) is introduced.
6. No new `ERROR`/`WARN` events fire under a clean `cargo test --workspace` run aside from tests
   that explicitly exercise error paths.

## Scope

**In scope.** All workspace crates under `crates/` and all binaries under `bin/` (`bin/rvc`,
`bin/rvc-keygen`, `bin/rvc-signer`). This is literal: not the hot path only.

**Out of scope.** See Non-Goals.

## Functional Requirements

### Must Have (P0)

**P0-1. Conventions doc (`docs/observability.md`).**

- Codifies existing `rvc.{domain}.{operation}` span-name scheme.
- Standard field keys: `rvc.slot` (u64), `rvc.epoch` (u64), `rvc.validator_index` (u64),
  `rvc.pubkey` (short-form string from `TruncatedPubkey`), `rvc.operation` (static str),
  `rvc.outcome` (`success|rejected|error|timeout`), `rvc.duration_ms` (u64 where applicable),
  `rvc.bn_endpoint` (redacted), `rvc.slashing.result` (`safe|double_vote|surrounding|surrounded|
  double_proposal|db_error`).
- Mandatory fields per duty type table (attestation/block/sync/aggregation/contribution/
  builder-registration/voluntary-exit/RANDAO).
- Level policy: `error!` = duty failed or data loss risk (slashing DB write fail, signature
  rejected for reasons other than slashing protection); `warn!` = retryable degraded path (BN
  failover, transient HTTP 5xx, slashing check rejected a request); `info!` = successful duty
  milestones and state transitions (one per duty lifecycle phase); `debug!` = inputs and
  intermediate computations; `trace!` = loops, per-pubkey iteration detail.
- Error-logging style: always attach `error = %e` (Display), never `error = ?e` (Debug) for
  thiserror/anyhow roots; include the `rvc.operation` and at least one correlation key.
- `#[instrument]` style: always `skip_all`, always an explicit `name = "rvc...."`, fields
  allowlisted to the standard keys above.
- Acceptance: doc committed; reviewed by architect; referenced from `CLAUDE.md`.

**P0-2. Redaction helpers and forbidden-pattern enforcement.**

- Promote `TruncatedPubkey` and `RedactedUrl` from `crates/crypto/src/logging.rs` to
  `crates/telemetry` (canonical home) with a backward-compatible re-export from `crypto` during
  the transition.
- Add `TruncatedSignature` (first 8 + last 8 hex of a BLS signature), `RedactedKeystore`
  (metadata only), `RedactedSecret` (unconditional `<redacted>`).
- Forbidden patterns (enforced by a workspace-level test, not a clippy lint, because it needs to
  match attribute arguments and format-string contents):
  - Any `tracing::{info,debug,warn,error,trace}!` whose format string or field value contains:
    `{secret`, `{sk`, `{private_key`, `{mnemonic`, `{passphrase`, `{password`, literal
    `Zeroizing`, or a variable bound to `SecretKey` / `SecretString` / `Zeroizing<_>`.
  - Any `fields(...)` inside `#[tracing::instrument]` that references a field named `secret`,
    `sk`, `private_key`, `mnemonic`, `passphrase`, `password`, `signature` (unless wrapped in
    `TruncatedSignature`), or a 96-hex-char pubkey literal.
  - Any `instrument` macro missing `skip_all` on a fn whose signature mentions `SecretKey`,
    `SecretString`, `Zeroizing`, `Mnemonic`, `SignRequest`, or `SigningRequest` (the tonic-
    generated protobuf type).
- Mechanism: `tests/forbidden_log_patterns.rs` at the workspace root that `glob`s all `.rs`
  sources and regex-matches. Violations are named file+line. Runs under `cargo test` and in CI.
  Allowlist supported via a top-of-file comment `// observability: allow <reason>`.
- Acceptance: test fails on seeded violations; passes on the retrofitted tree.

**P0-3. Duty-lifecycle span hierarchy.**

- One root span per duty attempt, tied to `(rvc.slot, rvc.pubkey, rvc.operation)`. Names:
  `rvc.attestation.produce`, `rvc.block.propose`, `rvc.sync.message`, `rvc.sync.contribution`,
  `rvc.aggregation.produce`, `rvc.builder.register`, `rvc.voluntary_exit.submit`,
  `rvc.randao.sign`.
- Existing slot-scoped `rvc.orchestrator.process_slot` remains the parent; per-duty spans are
  children; downstream spans (signer, slashing, beacon, propagator) chain under the duty span via
  `.instrument(span)` or `#[instrument]`.
- Where loops iterate validators, each iteration is its own child span with
  `rvc.validator_index` and `rvc.pubkey` set.
- Acceptance: a unit/integration test emits a full duty attempt, captures the span tree via a
  recording layer (pattern from `crates/secret-provider/tests/tracing_hierarchy.rs`), and asserts
  the parent/child relationships and required fields.

**P0-4. `#[instrument]` coverage on duty hot path.**

All public async fns below are instrumented with `skip_all`, a `rvc.*` name, and the mandatory
fields from P0-1:

- `crates/rvc/src/orchestrator/{attestation,aggregation,sync_committee,duty_management,
  coordinator,utils}.rs` — all non-trivial `pub(crate) async fn`.
- `crates/block-service/src/service.rs` — all `pub async fn` on `BlockService`.
- `crates/sync-service/src/lib.rs` — all `pub async fn` on `SyncService`.
- `crates/builder/src/service.rs` — `register_validators`, `prepare_proposers`, any retry helper.
- `crates/signer/src/lib.rs` — all `sign_*` (most already done; verify and fill gaps).
- `crates/duty-tracker/src/tracker.rs` — all `fetch_*`, `check_and_refetch_*`, `evict_*` (most
  already done; verify).
- `crates/propagator/src/lib.rs` — all submit paths.

(Doppelganger monitoring is a pre-activation safety gate, not hot-path; it is covered in P0-6.)

Constraint: retrofit MUST NOT cause source-breaking changes to public signatures. Adding
`#[tracing::instrument]` to async trait methods is allowed where it doesn't change the `Send`
bound of the returned future or introduce pinning differences; where it would, wrap the body in
`.instrument(span)` instead.

Acceptance: grep-based check lists all `pub async fn` on the above files and asserts every one
has `#[tracing::instrument]` or a `#[cfg(test)]` / internal marker exemption.

**P0-5. External I/O client instrumentation.**

Every outbound request gets one span (request) with: target identity (`rvc.bn_endpoint` or
`rvc.signer_endpoint`, redacted), HTTP method/route or RPC name, status/result, `rvc.duration_ms`,
retry attempt number if retrying, and a short error string on failure.

- `crates/beacon/src/client.rs`: mostly done; verify every endpoint method has an
  `rvc.beacon.*` span with `rvc.duration_ms` and `http.status`; add redacted endpoint field.
- `crates/bn-manager/src/manager.rs`, `sse.rs`, `health.rs`, `sync_status.rs`: failover attempts,
  SSE reconnects, health probe outcomes all emit a span with outcome + endpoint.
- `crates/grpc-signer/src/client.rs`: every RPC instrumented with `rvc.signer.*` name, latency,
  outcome.
- `crates/crypto/src/remote_signer.rs` (Web3Signer HTTP): request/response timing, outcome.
- `crates/secret-provider/src/gcp.rs`: every GCP call.
- `crates/keymanager-api/src/handlers.rs`: every handler has a span with request id, caller kind
  (keystore vs remotekey), outcome.
- W3C trace-context injection already in place for beacon HTTP via `inject_trace_context`. Extend
  to: remote Web3Signer HTTP calls, and GCP client calls where feasible. gRPC propagation to
  `bin/rvc-signer` is **in scope** (resolved at PRD gate, see §Resolved at PRD Gate item 4) — add
  tonic client interceptor on rvc side and server interceptor on rvc-signer side to carry W3C
  `traceparent` via metadata.

Acceptance: for every client-shaped crate above, a test exercises one success and one failure
path and asserts the span is emitted with the mandatory outcome/duration fields.

**P0-6. Storage/safety layer instrumentation.**

- `crates/slashing/src/db.rs`: every `check_and_record_*` logs at `info!` with outcome
  (`rvc.slashing.result`) and, on reject, the before/after watermarks relevant to the rule
  (source/target epoch for attestations, slot+signing root for blocks). Pruning operations emit
  `rvc.duration_ms` and row counts. Integrity check emits `info!` on pass, `error!` on fail with
  specifics.
- `crates/validator-store/src/store.rs`: config load, reload (parse-first/apply-second),
  per-validator override application all logged with `info!` and the validator short-form
  pubkey.
- `crates/doppelganger/src/service.rs`: each epoch of monitoring emits a child span with per-pubkey
  liveness outcomes; a detection event logs at `error!` with the short-form pubkey and exit-code
  note.

Acceptance: integration test triggers a double-vote rejection and asserts the log contains
`rvc.slashing.result = "double_vote"`, the validator short-form pubkey, and the source/target
epochs that triggered the rule.

**P0-7. Test-harness integration.**

- Add a `crates/telemetry/src/test_capture.rs` helper: a `TestTracingGuard` that installs a
  per-test subscriber capturing spans + events into a thread-local `Vec`, and on drop during a
  failing test, prints the captured tree via `println!` (captured by `cargo test` and shown on
  failure). Pattern inspired by the existing `crates/secret-provider/tests/tracing_hierarchy.rs`.
- Provide `#[rvc_test]` macro or a doc snippet instructing `let _g = telemetry::test_capture();`
  as the standard test preamble.
- Update at least the integration tests under `crates/rvc`, `crates/signer`, `crates/block-
  service`, `crates/sync-service`, `crates/propagator`, `crates/duty-tracker`, `crates/slashing`
  to use it.
- No dependency on `tracing-test` crate unless we conclude at Open Question review that we want
  it; prefer a handrolled layer for zero dependency churn.

Acceptance: at least one intentionally failing test demonstrates the span tree appearing in the
default `cargo test` output with no extra flags.

**P0-8. Prod log sink review.**

- Review `FileAppenderConfig` defaults (`max_size_mb`, `max_files`, `compress`, `level`)
  against target deployment: single-instance VC writing one rotating file. Document the
  recommended values in `docs/observability.md`.
- Confirm size-based rotation is sufficient, or surface "add time-based retention" in Open
  Questions (see below).
- Ensure structured (JSON) output is available as a config-selectable formatter for prod; human
  format remains default for dev/test. Add a `FileAppenderConfig.format: text|json` field.
- Acceptance: integration test writes ~3 MB of logs, confirms rotation and compression behaviour
  on a 1 MB cap.

### Should Have (P1)

**P1-1. Error type -> log style consistency.** Every `thiserror` variant in a public error enum
includes enough context in `Display` that `error = %e` is actionable without needing `Debug`.
Audit `crates/*/src/error.rs`, add missing context where display is terse.

**P1-2. Metrics cross-reference.** Where a metric exists for an event (e.g. `slashing_checks_
total`), the log line mentions the metric name so a reader can jump to dashboards. One-line
annotation in the conventions doc; no runtime change required.

**P1-3. OTel resource attribute cleanup.** Current resource has `service.name`, `service.version`,
`network.name`. Add `service.instance.id` (hostname or config-provided id) and `deployment.
environment` (from config).

**P1-4. Span event for slot clock tick.** One `info!` per slot boundary at the top of the
orchestrator loop with `rvc.slot`, `rvc.epoch`, `rvc.wall_clock_drift_ms`, so a log-only reader can
establish the slot timeline without needing metric timestamps.

### Nice to Have (P2)

**P2-1. Log-based SLO assertions in CI.** A post-test step greps for `ERROR` events in test logs
and fails if any appear outside allowlisted error-path tests.

**P2-2. Correlation ID header on keymanager-api.** Accept an incoming `x-request-id` and surface
it as `rvc.request_id` on the root handler span.

**P2-3. `tracing` documentation examples in `///` doc comments** for the top three public API
surfaces (`DutyOrchestrator`, `SignerService`, `BnManager`).

## Non-Functional Requirements

- **Performance.** Instrumentation must not regress per-slot latency budgets. `skip_all` is
  mandatory; `%` Display formatting (vs `?` Debug) for large objects; never format pubkeys
  unconditionally — use `TruncatedPubkey` which is zero-alloc when the log level is disabled.
  Target: <1% CPU delta on a 100-validator load-test relative to baseline.
- **Security.** See P0-2. No private key material, no full signatures, no mnemonics, no raw
  signing request bodies ever hit the log stream, at any level, via any formatter.
- **Compatibility.** Public API source compatibility preserved. `#[instrument]` additions to
  async trait methods evaluated case-by-case to preserve `Send` bounds.
- **Observability of observability.** The telemetry pipeline itself logs (once) on startup the
  effective sample rate, exporter kind, endpoint, and whether file sink is active.

## Technical Considerations

- Home for new helpers is `crates/telemetry` (redaction formatters, span builders, test capture).
  `crates/crypto/src/logging.rs` becomes a thin re-export during transition, then is removed.
- The forbidden-pattern enforcer is a workspace-level integration test (`tests/forbidden_log_
  patterns.rs` at workspace root), not a clippy lint, because it inspects macro arguments and
  format-string contents that clippy does not expose.
- The test-capture subscriber must use `tracing::subscriber::set_default` (thread-local
  `DefaultGuard` RAII) rather than `set_global_default` so parallel `cargo test` threads don't
  collide. Note: `with_default` is closure-scoped and doesn't match the drop-guard design — see
  `research/test-capture-design.md` and the precedent at
  `crates/secret-provider/tests/tracing_hierarchy.rs`.
- W3C propagation extension to gRPC requires adding `tonic` interceptors — list in Open
  Questions; may defer to a follow-up.
- Async trait instrumentation: prefer `.instrument(info_span!(...))` inside the body over
  `#[instrument]` on the trait method, to avoid `Send`-bound surprises.

## UX / Design Notes

A good log line in prod looks like:

```
2026-04-18T09:12:03.421Z  INFO rvc.attestation.produce{rvc.slot=7531200 rvc.epoch=235350
  rvc.pubkey=0x93247f2209...611df74a rvc.validator_index=42} attestation signed and queued
  rvc.duration_ms=34 rvc.outcome=success
```

A good test failure output looks like (spans printed on drop when the test panics):

```
SPAN rvc.attestation.produce { rvc.slot=32, rvc.pubkey=0xabc...def }
  EVENT fetched attester duty { rvc.validator_index=0 }
  SPAN rvc.sign.attestation { rvc.operation=attestation, rvc.slashing.result=safe }
    EVENT signature computed { rvc.duration_ms=2 }
  SPAN rvc.propagator.submit_attestations { rvc.outcome=error }
    EVENT beacon responded { http.status=500, error="connection refused" }
```

## Out of Scope (Non-Goals)

- Building a new telemetry crate or swapping `tracing` for a different framework.
- Adding new Prometheus metrics, dashboards, or alert rules. That is the metrics team's scope and
  this PRD only references existing metrics where it helps a log reader.
- Runtime log-level reconfiguration API (filed as a separate initiative).
- Shipping logs to a cloud vendor by default (only OTel traces are shipped; file sink is local).
- Changes to the OTel trace-exporter wiring beyond resource attribute tweaks in P1-3.
- Sampling policy changes beyond what is specified in §Resolved at PRD Gate (parent-based +
  always-sample errors). Any further sampling work is a follow-up.

## Constraints

- No new top-level dependencies unless strongly justified and called out in review. `tracing-
  test` is an example where we explicitly chose to reimplement in-tree instead.
- `cargo fmt` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean after
  retrofit.
- Retrofit must not introduce source-breaking changes to any `pub` signature. Adding
  `#[instrument]` to a trait method is only permitted where it preserves the `Send` bound and
  pinning behaviour of the returned future; otherwise use `.instrument(span)` inside the body.
- TDD cycle (RED -> GREEN -> REFACTOR) applies to new helpers (test capture, forbidden-pattern
  test, redaction formatters).
- Each retrofit PR stays under ~500 LOC diff where possible; group by crate.

## Resolved at PRD Gate

The team lead ran the PRD gate with the user. Resolutions below are CONSTRAINTS for downstream
agents.

1. **Prod sampling — parent-based + tail-sampling for errors in the collector.** rs-vc side
   keeps the plain `ParentBased(TraceIdRatioBased)` base sampler. The "always export rvc.outcome=
   error" rule is implemented in the OTel Collector via the `tail_sampling` processor, because
   error outcome is only known at span close and a head-based `ShouldSample` cannot retroactively
   flip a NotSampled decision. Architect writes: (a) the rvc-side sampler config (unchanged), and
   (b) the recommended collector tail-sampling policy (match on `rvc.outcome = error` OR span
   `status = Error`) in `architecture.md`. See `research/summary.md` contradictions #2 for the
   reasoning.
2. **File sink retention — size + count only.** No time-based retention in this initiative. Stick
   with the existing `logroller` size+count rotation. Not a follow-up item.
3. **Test capture — handrolled, in-tree, zero new dependency.** Build `TestTracingGuard` in
   `crates/telemetry/src/test_capture.rs` following the `secret-provider/tests/tracing_hierarchy.rs`
   precedent. Do not pull in `tracing-test`.
4. **W3C propagation to `bin/rvc-signer` over gRPC — INCLUDED in scope.** Add tonic client
   interceptor on the rvc side and server interceptor on the rvc-signer side, extracting/injecting
   W3C `traceparent` via metadata. Elevate to a P0 deliverable under the External I/O & Safety
   phase. Completes the distributed trace story end-to-end. Architect sizes the interceptor work;
   estimator cuts issues.
5. **JSON vs text formatter — recommendation ratified.** JSON is the default for the prod file
   sink; text is the default for tests and local dev (controlled by env + feature flag, architect
   specifies the exact knob).
6. **Conventions doc lives at `docs/observability.md`.** Confirmed. Single canonical location.

## Open Technical Decisions (forwarded to architect)

These are scoped design decisions the architect should resolve in `architecture.md`, not user
decisions:

- **Long-running task span shape.** 2-epoch doppelganger monitor and SSE event stream: pick
  between one long-lived parent with per-iteration children vs fresh root per iteration.
  Recommendation leans toward fresh root per iteration (bounded trace size, easier ingest) with
  a correlation field linking iterations — but architect has final call.

## Milestones & Phases

1. **Phase 1 — Conventions and guardrails (P0-1, P0-2).** Doc, redaction helpers moved, forbidden-
   pattern test green on current tree. Exit: estimator can scope Phase 2.
2. **Phase 2 — Duty hot path retrofit (P0-3, P0-4).** Root spans unified, all listed public async
   fns instrumented. Exit: runbook walkthrough succeeds on synthetic failure.
3. **Phase 3 — External I/O and safety layer (P0-5, P0-6).** All client crates and safety-critical
   write paths carry outcome/duration/endpoint. Exit: integration tests demonstrate.
4. **Phase 4 — Test harness and prod sink (P0-7, P0-8).** Test-capture adopted in listed
   integration tests; file sink defaults reviewed; JSON formatter available. Exit: failing test
   prints span tree without re-run.
5. **Phase 5 — P1 polish.** Error display audit, metrics cross-references, resource attributes,
   slot-tick event.

## Risks & Mitigations

- **Risk: retrofit breaks a public API signature.** Mitigation: CI check for ABI diff on `pub`
  signatures; prefer `.instrument(span)` over `#[instrument]` on trait methods.
- **Risk: forbidden-pattern test becomes a source of false positives and gets muted.**
  Mitigation: narrow patterns; explicit allowlist-comment mechanism with mandatory reason;
  review-required to add entries.
- **Risk: test capture changes subscriber semantics and breaks existing tests.** Mitigation: use
  `tracing::subscriber::set_default` (thread-local, RAII `DefaultGuard`) only; never call
  `set_global_default` in the helper; gate the helper behind an opt-in.
- **Risk: instrumentation introduces a perf regression.** Mitigation: 100-validator load-test
  before/after P0-4 and P0-5 merges; fail the phase if delta >1% CPU or >5ms p99 slot latency.
- **Risk: scope creep (the team starts rewriting telemetry).** Mitigation: out-of-scope list is
  explicit; architect reviews PRs against it.
