# Project Plan: Logging & Tracing Enhancement Initiative

## Deviations From Architect's §7 Rollout

This plan uses the 8-phase shape the team lead prescribed. It deviates from the 8-step sequence in
`architecture.md` §7 in two concrete ways, both deliberate:

1. **Plan Phase 5 merges architect's §7 steps 5 and 6** (external I/O + storage/safety layer) into
   a single external-surface phase. Justification: both groups share the dual-attribution pattern
   (`rvc.*` + OTel semconv `rpc.*`/`http.*`/`server.*`) and the success+failure test shape; packing
   them together amortizes the test-harness scaffolding. gRPC propagation (architect §1.5, §2.4) is
   co-located in this phase because the tonic interceptor work sits on the same surface.
2. **Plan Phase 6 is net-new beyond §7**: it catches crates/bins not covered in the hot path or the
   external surface (`bin/rvc`, `bin/rvc-keygen`, `bin/rvc-signer` self-instrumentation beyond the
   interceptor, `metrics`, `timing`, `eth-types` sanity pass, `telemetry` self-instrumentation).
   This is the "mop-up" the architect §1.5 retrofit matrix implies but §7 does not call out.

Numbering inside this document otherwise matches §7 one-to-one.

---

## One-Page Overview

| Item | Value |
|---|---|
| Total phases | 8 |
| Estimated working days (single stream) | ~37–45 days |
| Critical path | Phase 1 → 2 → 3 → 4 → 7 → 8 |
| Parallelizable after Phase 3 | Phases 5 and 6 can fork; Phase 7 needs only Phase 1 helpers |
| Acceptance metrics (PRD §Goals) | All 6 gated across Phases 3, 4, 5, 7, 8 |

**Plan thesis.** Land observability helpers first as additive, zero-risk code (Phase 1). Promote
redaction and close the `bls.rs` Debug leak (Phase 2). Install the forbidden-pattern ratchet with
an allowlist seeded against the current tree (Phase 3) — from that point on, no new violations
enter the codebase. Apply the span/field standard to the duty hot path (Phase 4) to hit the
runbook-walkthrough acceptance. Cover external I/O + safety layer + gRPC propagation (Phase 5).
Mop up the long tail (Phase 6). Retrofit tests to use the capture guard and publish the conventions
doc (Phase 7). Finish P1 polish (Phase 8).

**Parallelism note.** The default is single-stream. If the user opts into parallel execution after
Phase 3 lands, Phases 5 and 6 are independent (disjoint crate sets per architecture §1.5), and
Phase 7 depends only on Phase 1's `test_capture.rs` — it can run in parallel with Phases 4–6.
Phase 8 sits at the end regardless (slot-tick event and resource attribute tweaks touch Phase 4/6
surfaces).

---

## Phase Overview Table

| # | Name | Crates touched | Rough days |
|---|---|---|---|
| 1 | Telemetry foundation | `crates/telemetry` | 5–6 |
| 2 | Redaction promotion + `bls.rs` Debug fix | `crates/crypto`, importers | 2–3 |
| 3 | Forbidden-pattern test (ratchet) | workspace-root `tests/` | 2–3 |
| 4 | Duty hot-path retrofit | 8 files across 7 crates | 9–11 |
| 5 | External I/O + safety + gRPC propagation | 9 crates + `bin/rvc-signer` | 9–11 |
| 6 | Remaining crates + bins | 6 crates/bins | 4–5 |
| 7 | Test-harness adoption + conventions doc | 7 integration-test suites | 4–5 |
| 8 | P1 polish | orchestrator, telemetry | 2–3 |
| | **Total** | | **~37–45** |

---

## Milestones Table

Each milestone maps a phase exit to a user-visible checkpoint. PRD §Goals acceptance metrics (#1–#6)
are called out by number.

| Phase exit | User-visible checkpoint | PRD goal |
|---|---|---|
| Phase 1 exit | `cargo test -p telemetry` green; `TruncatedSignature`, `TestTracingGuard`, `TraceContextInterceptor` importable from `telemetry::` | — |
| Phase 2 exit | `PublicKey`/`Signature` Debug output is short-form on any intentional `?sig` call; `crypto::logging` compiles as a re-export | — |
| Phase 3 exit | `cargo test --test forbidden_log_patterns` green on current tree; a seeded-violation fixture confirms detection; CI job fails on a planted violation | #5 |
| Phase 4 exit | Runbook walkthrough on a synthetic duty failure reconstructs slot → signing → slashing → propagation from a single trace id in under 5 minutes | #1, #4 |
| Phase 5 exit | Integration tests demonstrate success + failure path spans for beacon, bn-manager failover, grpc-signer, Web3Signer, GCP, keymanager, slashing; tonic traceparent round-trip asserted between `bin/rvc` and `bin/rvc-signer`; slashing double-vote rejection surfaces `rvc.slashing.result = "double_vote"` with source/target epochs | — |
| Phase 6 exit | Every crate in architecture §1.5 retrofit matrix is at its target state; `cargo clippy --workspace --all-targets -- -D warnings` green | #3 |
| Phase 7 exit | A deliberately failing test in `crates/duty-tracker` prints the span tree in default `cargo test` output with no re-run and no `RUST_LOG`; `docs/observability.md` exists and is referenced from `CLAUDE.md`; doc examples compile via `cargo test --doc` | #2 |
| Phase 8 exit | `cargo test --workspace` run produces zero `ERROR`/`WARN` events outside explicit error-path tests; `service.instance.id` and `deployment.environment` present on exported resources; one `info!` slot-tick per slot with `rvc.wall_clock_drift_ms` | #6 |

---

## Phase Dependency Graph

```
                  Phase 1 (telemetry foundation)
                         |
                         v
                  Phase 2 (redaction promotion + bls.rs Debug fix)
                         |
                         v
                  Phase 3 (forbidden-pattern ratchet)
                         |
            +------------+-------------+----------+
            v            v             v          v
        Phase 4       Phase 5       Phase 6    Phase 7
      (hot path)  (external I/O) (long tail)  (tests + doc)
            \           |              /          /
             \          |             /          /
              +---------+------------+----------+
                         |
                         v
                  Phase 8 (P1 polish)
```

**Critical path** (single stream, default): 1 → 2 → 3 → 4 → 7 → 8. Phases 5 and 6 slot anywhere
after Phase 3 in single-stream mode; for the default ordering we place them between 4 and 7 so the
runbook walkthrough in Phase 4 doesn't depend on Phase 5 plumbing.

**Parallelism** (opt-in after Phase 3): Phase 4, Phase 5, Phase 6, and Phase 7 can run concurrently
with no crate overlap (architecture §1.5 matrix enforces disjoint file sets). Phase 8 must follow.

---

## Phase 1 — Telemetry Foundation

**Goal.** Land new telemetry helpers as purely additive code. No existing call-site changes.

**Scope (files, per architecture §1.1, §1.4).**

- `crates/telemetry/src/redact.rs` (new) — `TruncatedPubkey`, `TruncatedPubkeyBytes`,
  `TruncatedSignature`, `RedactedUrl`, `RedactedKeystore`, `RedactedSecret`.
- `crates/telemetry/src/test_capture.rs` (new) — `TestTracingGuard`, `CaptureLayer`,
  `SpanTreeFormatter`, `test_capture()`.
- `crates/telemetry/src/propagation.rs` (updated) — `MetadataInjector`, `MetadataExtractor`,
  `inject_trace_context_grpc`, `extract_trace_context_grpc`, `attach_server_parent`,
  `TraceContextInterceptor`.
- `crates/telemetry/src/init.rs` (updated) — `service.instance.id`, `deployment.environment`
  resource attrs; startup `info!` banner; sampler unchanged (`ParentBased(TraceIdRatioBased)`).
- `crates/telemetry/src/file_appender.rs` (updated) — `LogFormat::{Text, Json}` field on
  `FileAppenderConfig`; `fmt::layer().json()` path enabled by the `"json"` feature.
- `crates/telemetry/src/lib.rs` (updated) — exact re-export block from architecture §1.1.
- `crates/telemetry/Cargo.toml` — enable `tracing-subscriber`'s `"json"` feature.
- Workspace `Cargo.toml` — add `walkdir = "2"` and `regex = "1"` under `[workspace.dev-dependencies]`
  (consumed in Phase 3, landed here so Phase 3 has the deps ready).

**Dependencies.** None.

**Exit criteria.**

- `cargo test -p telemetry` passes.
- Unit tests exist for every redaction formatter: `TruncatedPubkey` (string input), `TruncatedPubkeyBytes`
  (`&[u8]` input), `TruncatedSignature::from_bytes`, `RedactedUrl` (userinfo strip), `RedactedKeystore`,
  `RedactedSecret`; assertions against the exact outputs in architecture §2.1 table.
- Round-trip unit test: `inject_trace_context_grpc(&mut req)` followed by `extract_trace_context_grpc(&req)`
  recovers the `traceparent`.
- `TestTracingGuard` has at least one unit test that captures a span with a recorded field and
  asserts `field_on_span` / `spans_named` / `assert_child_of` behave per architecture §2.2 contract.
- `cargo fmt` and `cargo clippy -p telemetry -- -D warnings` clean.
- `telemetry::TestTracingGuard`, `telemetry::test_capture`, `telemetry::TruncatedSignature`, and
  `telemetry::TraceContextInterceptor` are visible via the re-export block in `lib.rs`.
- `grep -n 'tracing-subscriber' Cargo.toml` in the workspace root shows `features = [..., "json"]`
  (or in the telemetry crate manifest, whichever is canonical).

**Duration.** 5–6 days. `TestTracingGuard` pretty-printer ~2d; redaction formatters + unit tests
~1d; tonic metadata helpers + round-trip test ~1.5d; init/file_appender changes ~1d.

**Phase-specific risks.** `tracing-subscriber` `"json"` feature flip is additive (no call-site
churn). Tonic injector/extractor: pin to hand-rolled ~20-LOC impl per research; no
`opentelemetry-tonic` dep.

**Rollback plan.** Additive; revert the telemetry crate commit. Rest of workspace unaffected.

---

## Phase 2 — Redaction Promotion + `bls.rs` Debug Fix

**Goal.** Canonicalize redaction helpers in `crates/telemetry` and close the `bls.rs` Debug leak so
the forbidden-pattern test can go green without false negatives.

**Scope (files, per architecture §1.2, §1.5).**

- `crates/crypto/src/logging.rs` — shrink to `pub use telemetry::{RedactedUrl, TruncatedPubkey};`
  with `#[deprecated(note = "import from telemetry directly")]` at module level.
- `crates/crypto/src/bls.rs` — replace `impl Debug for PublicKey` to use `TruncatedPubkeyBytes`
  (short-form); replace `impl Debug for Signature` to use `TruncatedSignature::from_bytes`. `Display`
  impls unchanged.
- `crates/crypto/Cargo.toml` — add `telemetry` as a normal dependency (architecture §1.2 verifies
  no cycle: `telemetry` does not depend on `crypto`).
- All crates that currently import from `crypto::logging::{TruncatedPubkey, RedactedUrl}` — update
  to `telemetry::`. The deprecated re-export stays in place through Phase 6 as a grace period.

**Dependencies.** Phase 1 (telemetry helpers must exist before crypto imports them).

**Exit criteria.**

- `cargo build --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Unit tests in `crates/crypto/src/bls.rs` assert `format!("{:?}", pubkey)` matches the short-form
  regex `^PublicKey\(0x[0-9a-f]{10}\.\.\.[0-9a-f]{8}\)$` and `format!("{:?}", signature)` matches
  `^Signature\(0x[0-9a-f]{8}\.\.\.[0-9a-f]{8}\)$`.
- `grep -rn "crypto::logging::" crates/ bin/` returns only the re-export module itself plus any
  intentional import sites (allowed during grace period) — no accidental fresh imports.
- `cargo test -p crypto` passes.

**Duration.** 2–3 days. Debug impls ~0.5d (~50 LOC + tests); importer sweep and cycle verify ~1.5d.

**Phase-specific risks.** Adding `telemetry` as a `crypto` dep could cycle; architecture §1.2
pre-verified clean, `cargo check --workspace` is the gate.

**Rollback plan.** Revert `bls.rs` Debug change; keep `crypto::logging` re-export as grace period
(architecture §1.2 prescribes).

---

## Phase 3 — Forbidden-Pattern Test (Ratchet)

**Goal.** Land `tests/forbidden_log_patterns.rs` green on the current tree. The allowlist is seeded
with every pre-existing violation; from this phase forward, no new violation enters the codebase.

**Scope (files, per architecture §1.3, §2.3).**

- `tests/forbidden_log_patterns.rs` (new, workspace root) — walkdir + regex + allowlist parser per
  architecture §2.3. Regex set verbatim from the §2.3 table (BAD_FIELD, BAD_FMT, BAD_ZEROIZING,
  BAD_SIG_DEBUG, INSTRUMENT_NO_SKIPALL, BAD_GLOBAL_DEFAULT).
- Allowlist entries as top-of-line comments `// observability: allow <reason>` at each pre-existing
  violation site. Every entry must have a non-empty reason.
- `tests/fixtures/forbidden_log_patterns/` (new) — seeded-violation fixture files for the
  detection self-test.

**Dependencies.** Phase 1 (`walkdir`, `regex` dev-deps) and Phase 2 (`bls.rs` Debug fix eliminates
the primary BAD_SIG_DEBUG leak without needing an allowlist entry).

**Exit criteria.**

- `cargo test --test forbidden_log_patterns` passes on the current tree.
- Seeded-violation fixture test (inside the same file) demonstrates each rule fires on a planted
  example file under `tests/fixtures/forbidden_log_patterns/`.
- The test prints file+line for any violation, asserted by the fixture test output.
- Every allowlist comment in the tree matches the form `// observability: allow <non-empty reason>`;
  a fixture test confirms empty-reason allowlists do NOT suppress detection.
- CI job runs `cargo test --test forbidden_log_patterns` alongside the regular test suite.
- Test runtime on the current tree is under 5 seconds (baseline from research: ~500 ms).

**Duration.** 2–3 days. Scanner + allowlist parser ~1d (~200 LOC per research); allowlist seeding
against current tree ~0.5–1d; fixture tests ~0.5d.

**Phase-specific risks.** Regex false-positives under generated proto files — mitigated by
exclusion list in architecture §2.3 (`target/`, `tests/conformance/`, `plan/`, `docs/`, `OUT_DIR`,
test file itself).

**Rollback plan.** If noisy or blocks merges, `#[ignore]` the test body with a tracked follow-up;
do NOT expand the allowlist as a shortcut.

---

## Phase 4 — Duty Hot-Path Retrofit

**Goal.** Apply the span hierarchy (architecture §3 table) and field standard to every duty-path
file. Oncall runbook walkthrough succeeds on a synthetic duty failure.

**Scope (files, per PRD P0-4, architecture §1.5, §3).**

File-level scope (note these are modules inside `crates/rvc/src/orchestrator/`, not separate crates):

- `crates/rvc/src/orchestrator/attestation.rs`
- `crates/rvc/src/orchestrator/aggregation.rs`
- `crates/rvc/src/orchestrator/sync_committee.rs`
- `crates/rvc/src/orchestrator/duty_management.rs`
- `crates/rvc/src/orchestrator/coordinator.rs`
- `crates/rvc/src/orchestrator/utils.rs`
- `crates/block-service/src/service.rs` — root span `rvc.block.propose`; children
  `rvc.block.{sign_randao,produce_block,sign_block,publish}`.
- `crates/sync-service/src/lib.rs` — verify/fill `produce_sync_messages`, `produce_contributions`,
  `compute_selection_proof`; add `rvc.sync.subnet`.
- `crates/builder/src/service.rs` — `register_validators`, `prepare_proposers`, retry helper.
- `crates/signer/src/lib.rs` — 11 existing `#[instrument]` sites; verify `skip_all`; record
  `rvc.outcome` / `rvc.duration_ms` via `Span::record`; `rvc.slashing.result` after slashing check.
- `crates/duty-tracker/src/tracker.rs` — verify and fill gaps on `fetch_*`, `check_and_refetch_*`,
  `evict_*`; all carry `rvc.epoch` / `rvc.committee_period`.
- `crates/propagator/src/lib.rs` — `submit_attestations`, `submit_aggregate_attestations`;
  `rvc.propagator.*` root span per submit call.
- `crates/crypto/src/signing.rs`, `block_signing.rs`, `sync_signing.rs`, `aggregation_signing.rs`,
  `voluntary_exit_signing.rs`, `builder_signing.rs` — verify `skip_all` on existing ~11 sites.

Root-span names and field sets come from architecture §3 per-duty-family table (no deviation).

**Dependencies.** Phase 3 (so no new violations are introduced during the retrofit).

**Exit criteria.**

- `cargo clippy --workspace --all-targets -- -D warnings` passes after each touched file.
- For each file above, a grep-based verification shows every `pub async fn` (or `pub(crate) async
  fn` for the orchestrator) has either `#[tracing::instrument(skip_all, name = "rvc....", fields(...))]`
  or an in-body `.instrument(info_span!(...))` with equivalent field set.
- Integration tests exist under `crates/rvc/tests/`, `crates/signer/tests/`, `crates/block-service/tests/`,
  `crates/propagator/tests/` that emit a complete duty attempt and assert (via `TestTracingGuard`):
  - parent-child span relationships match architecture §3 (e.g. `rvc.attestation.produce` →
    `rvc.sign.attestation` → `rvc.propagator.submit_attestations`);
  - mandatory fields are present on each root span (`rvc.slot`, `rvc.validator_index`, `rvc.pubkey`,
    `rvc.operation`);
  - `rvc.outcome=success` on the happy path and `rvc.outcome=error` on a planted failure.
- A runbook walkthrough (documented in Phase 7's `docs/observability.md`, sketched here) succeeds
  against a synthetic failure in the integration-test rig in <5 minutes (PRD acceptance #1).
- No `#[instrument]` site carries `err` or `ret`; all sites carry `skip_all`.

**Duration.** 9–11 days. ~1d per crate × 7 crates + 6 orchestrator module files; async-trait
fallback budget for trait methods that break `Send` (architecture §8: case-by-case, not universal).

**Phase-specific risks.** Async-trait `#[instrument]` can break `Send` bounds — fall back to
`.instrument(info_span!(...))` in body; escalate if fallbacks exceed ~20% of touched trait methods.
100-validator load-test is the perf gate (>1% CPU or >5ms p99 slot latency → fail).

**Rollback plan.** Per-crate commits; revert any commit that fails the perf gate without touching
neighbors.

---

## Phase 5 — External I/O + Safety Layer + gRPC Propagation

**Goal.** Every outbound I/O crate carries dual-attribution (`rvc.*` + OTel semconv) on success and
failure paths. Safety-layer writes (slashing, validator-store, doppelganger) log watermarks and
outcomes. W3C traceparent propagates end-to-end across the gRPC link to `bin/rvc-signer`.

**Scope (files, per architecture §1.5, §2.4, §3).**

External I/O crates:

- `crates/beacon/src/client.rs` — 10 existing `#[instrument]` sites; audit each endpoint wrapper
  for dual-attribution (`rvc.bn_endpoint`, `rvc.beacon.endpoint_name`, `http.request.method`,
  `http.response.status_code`, `url.full=%RedactedUrl`, `rvc.outcome`, `rvc.duration_ms`).
- `crates/bn-manager/src/{manager,sse,health,sync_status}.rs` — failover attempts, SSE reconnects
  (fresh root per event per architecture §6 decision), health probes, sync-status. Each
  failover/reconnect carries `rvc.bn_endpoint`, `rvc.outcome`; SSE events carry `rvc.sse.stream_id`
  and `rvc.sse.event_type`.
- `crates/grpc-signer/src/client.rs` — add `TraceContextInterceptor` to the channel per
  architecture §2.4; instrument `GrpcRemoteSigner::sign_*` with `rvc.signer.*` root span,
  `rpc.system.name="grpc"`, `rpc.method`, `server.address`, `server.port`, `rpc.response.status_code`.
- `crates/crypto/src/remote_signer.rs` — Web3Signer HTTP; `rvc.signer.operation`, `http.*`,
  `server.*` fields.
- `crates/secret-provider/src/gcp.rs` — every GCP call: `rvc.secret_provider.*` span; fresh root
  per BN connection for any streaming listeners.
- `crates/keymanager-api/src/handlers.rs` — 8+ handlers; root span `rvc.keymanager.{handler}`,
  `rvc.keymanager.caller_kind`, `rvc.outcome`, count fields.

gRPC propagation (one-time wiring):

- `bin/rvc-signer` (tonic server) — install a tower `Layer` on `Server::builder().layer(...)` OR
  call `attach_server_parent(&req)` at the top of each handler per architecture §2.4. Instrument
  `backend::basic::sign`, `backend::dvt::sign`, `service::SignerService::{sign,list_public_keys,get_status}`
  as server-side root spans.
- `bin/rvc-signer` audit-log fields — `signing_root` as `%TruncatedPubkeyBytes`, `pubkey` as
  `%TruncatedPubkey`, any BLS-sig-shaped response as `%TruncatedSignature::from_bytes`.

Safety layer:

- `crates/slashing/src/db.rs` — 5 existing `#[instrument]` sites; add `rvc.slashing.result`,
  source/target epochs (attestations), slot+signing_root (blocks), row counts on prune,
  `rvc.duration_ms`. Integrity check → `info!` pass / `error!` fail.
- `crates/validator-store/src/store.rs` — 4 existing sites; extend `reload_config` to log
  parse-first then apply-second; per-validator override application logs short-form pubkey.
- `crates/doppelganger/src/service.rs` — rewrite to fresh-root-per-epoch pattern (architecture §6):
  `rvc.doppelganger.check_epoch` parent-less root, `rvc.monitor.instance_id` UUID, per-iteration
  `add_link` to previous iteration's `SpanContext`; per-pubkey debug child span.

**Dependencies.** Phase 3 (ratchet is live so retrofit edits don't regress). Phase 4 recommended
to precede so acceptance test fixtures are shared, but not strictly required.

**Exit criteria.**

- For every external-I/O crate, one success-path integration test and one failure-path test assert
  the span is emitted with the mandatory fields (outcome, duration, endpoint).
- End-to-end test exercises a gRPC call from a fake client channel through
  `TraceContextInterceptor` into `bin/rvc-signer`'s handler and asserts the resulting span on the
  server side has `parent_span_id` matching the client-side span and the same `trace_id`.
- Slashing integration test: triggers a double-vote rejection against `crates/slashing/tests/` and
  asserts the captured log line contains `rvc.slashing.result = "double_vote"`, the validator
  short-form pubkey, and the source/target epochs that triggered the rule (PRD acceptance for P0-6).
- Doppelganger multi-iteration test: runs two epochs of monitoring against a mock BN and asserts
  two distinct root spans exist, both carry the same `rvc.monitor.instance_id`, and the second
  span has an `add_link` to the first's `SpanContext`.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.

**Duration.** 9–11 days. Beacon audit ~1.5d; bn-manager (manager/sse/health/sync_status) ~2d
(SSE fresh-root is the dominant subtask); grpc-signer + rvc-signer tonic + round-trip ~1.5d;
`crypto::remote_signer` + `secret-provider::gcp` ~2d; keymanager-api 8 handlers ~1.5d;
slashing + validator-store + doppelganger ~2d (doppelganger rewrite dominates).

**Phase-specific risks.** SSE fresh-root-per-event could flood the trace backend — drops managed
by collector tail-sampling (architecture §5). Dual-attribution doubles field count on hot paths —
`skip_all` keeps them zero-alloc when disabled; load-test before merge.

**Rollback plan.** Per-crate commits; revert the offending commit. gRPC interceptor is a one-line
channel-builder change if propagation breaks.

---

## Phase 6 — Remaining Crates + Bins

**Goal.** Close the retrofit matrix (architecture §1.5) on crates/bins not already covered.

**Scope (files, per architecture §1.5).**

- `bin/rvc` — init telemetry with new resource attrs (Phase 8 finalizes slot-tick event); add CLI
  flag for `RVC_LOG_FORMAT=json|text`; verify `process_slot` root span is the slot-scoped parent
  for duty children from Phase 4.
- `bin/rvc-keygen` — `#[instrument]` on subcommand entries: `new_mnemonic::run`,
  `existing_mnemonic::run`, `bls_to_execution::run`, `exit::run`. Add `rvc.keygen.operation` field.
- `bin/rvc-signer` — self-instrumentation beyond the gRPC interceptor already landed in Phase 5
  (any helper functions, startup logs).
- `crates/metrics` — minimal: one startup `info!` on `MetricsServer`; skip `/metrics` and `/healthz`
  handler spans per architecture §1.5 (noisy, low-value).
- `crates/timing` — no change; call out in the matrix verification for completeness.
- `crates/telemetry` — self-instrumentation for the crate itself (e.g. startup banner is already
  in Phase 1; confirm no gaps).
- `crates/eth-types` — sanity pass only; architecture §1.5 marks this as no-change. Verify no drive-by
  violations surfaced.

**Dependencies.** Phase 1 (helpers). Phase 3 (ratchet). Phase 4 preferred so duty path is stable.

**Exit criteria.**

- `cargo clippy --workspace --all-targets -- -D warnings` clean (PRD acceptance #3).
- Each crate in architecture §1.5 retrofit matrix matches its target state, verified by grep
  (e.g. `grep -n '#\[tracing::instrument' bin/rvc-keygen/src/**/*.rs` shows a site on each
  subcommand entry).
- `bin/rvc --log-format json` produces JSON log output on stdout/file sink; `bin/rvc` without the
  flag remains human-readable text.
- `RVC_LOG_FORMAT=json` env var is honored; CLI flag takes precedence when both are set.

**Duration.** 4–5 days. `bin/rvc` CLI + env wiring ~1d; `bin/rvc-keygen` ~1d; `bin/rvc-signer`
~0.5d; matrix verification pass ~1d.

**Phase-specific risks.** JSON formatter changes log shape for downstream consumers — opt-in by
flag/env per PRD Gate resolution #5; text remains default for dev/test.

**Rollback plan.** Per-crate commits; revert individually. `--log-format` is additive.

---

## Phase 7 — Test-Harness Adoption + Conventions Doc

**Goal.** Retrofit integration tests to use `TestTracingGuard`. Publish `docs/observability.md`.
Failing tests print the span tree by default.

**Scope.**

- `crates/rvc/tests/*.rs`, `crates/signer/tests/*.rs`, `crates/block-service/tests/*.rs`,
  `crates/sync-service/tests/*.rs`, `crates/propagator/tests/*.rs`, `crates/duty-tracker/tests/*.rs`,
  `crates/slashing/tests/*.rs` — add `let _g = telemetry::test_capture();` at the top of each test
  body.
- `docs/observability.md` (new) — conventions doc per PRD P0-1. Content:
  - Span-name scheme `rvc.{domain}.{operation}`.
  - Field-key table from PRD P0-1 + architecture §3.
  - Mandatory fields per duty type table (from architecture §3).
  - Level policy (architecture §4).
  - `#[instrument]` style (always `skip_all`, always explicit `name`, fields allowlisted).
  - Error-logging style (`error = %e`, never `error = ?e`).
  - Redaction helpers reference + forbidden-pattern rules (from architecture §2.3).
  - gRPC propagation flow (architecture §2.4).
  - Runbook snippet: "given a slot and validator pubkey, reconstruct the duty lifecycle".
  - FileAppender defaults + `RVC_LOG_FORMAT` behavior (from architecture §2.6).
  - Doc examples compile as `///` doc tests where applicable.
- `CLAUDE.md` — add a reference line pointing to `docs/observability.md`.
- One intentionally failing test (in `crates/duty-tracker/tests/` or a dedicated
  `crates/telemetry/tests/`) demonstrates the span-tree-on-panic output.

**Dependencies.** Phase 1 (`TestTracingGuard`). Phase 4 (so retrofitted tests have spans to
capture). Phase 5 preferred so cross-crate trace context works in tests.

**Exit criteria.**

- `cargo test --workspace` completes; intentionally failing demo test produces a span tree on
  stderr/stdout (captured by `cargo test`) that matches the shape in PRD §UX/Design Notes.
- No retrofitted integration test requires `RUST_LOG` or `--nocapture` to be readable.
- `docs/observability.md` exists, content matches the scope bullet list above, and `CLAUDE.md`
  contains a reference to it.
- `cargo test --doc -p telemetry` passes (doc examples in `test_capture.rs`, `redact.rs` compile).
- PRD acceptance #2 satisfied: at least two "synthesize a failure, read output" exercises pass
  during review.

**Duration.** 4–5 days. Per-crate test retrofit ~0.5d × 7 = ~3.5d; doc drafting ~1d; demo failing
test + review exercises ~0.5d.

**Phase-specific risks.** `TestTracingGuard` could interfere with tests that install their own
subscribers (e.g. `secret-provider/tests/tracing_hierarchy.rs`) — guard is thread-local RAII,
retrofit test-by-test, not blanket.

**Rollback plan.** `test_capture` is opt-in per test; revert per-test adoption if a test regresses.

---

## Phase 8 — P1 Polish

**Goal.** Complete PRD P1 items: error-display audit, metrics cross-references, resource attribute
tweaks, slot-tick event.

**Scope (per PRD §Should Have).**

- **P1-1 error-display audit** — walk every `thiserror`-derived enum in `crates/*/src/error.rs`;
  ensure `Display` carries enough context that `error = %e` is actionable without `Debug`. Add
  missing context (e.g. include endpoint name, validator pubkey short form where relevant).
- **P1-2 metrics cross-reference** — at sites where a metric exists for an event (e.g.
  `slashing_checks_total`), add a one-line comment annotation referencing the metric name. Document
  the convention in `docs/observability.md` (added as a patch to Phase 7's doc).
- **P1-3 resource attributes** — `service.instance.id` and `deployment.environment` already added
  to `TelemetryConfig` in Phase 1's `init.rs`; Phase 8 wires `bin/rvc` to populate them from config
  or hostname (fallback to `hostname::get()` if config-provided id is absent).
- **P1-4 slot-tick event** — one `info!` per slot boundary at the top of the orchestrator loop in
  `crates/rvc/src/orchestrator/coordinator.rs` (or wherever the slot iteration sits) with
  `rvc.slot`, `rvc.epoch`, `rvc.wall_clock_drift_ms`.

**Dependencies.** Phase 1 (TelemetryConfig fields). Phase 4 (orchestrator hot path is stable).
Phase 7 (doc exists to patch).

**Exit criteria.**

- `cargo test --workspace` run produces zero `ERROR`/`WARN` events outside allowlisted error-path
  tests (PRD acceptance #6). Verified by a post-test grep of the captured log output.
- `service.instance.id` and `deployment.environment` appear on every exported OTel resource; unit
  test in `crates/telemetry` asserts they are set when `TelemetryConfig` provides values.
- One `info!` event per slot fires at the top of the orchestrator loop with the required fields;
  integration test in `crates/rvc/tests/` asserts the event count matches slot iteration count.
- Error-display audit complete: grep for `thiserror` derives under `crates/*/src/error.rs` is
  documented; every variant has a `Display` that includes at least one correlation key where one
  is available.
- `docs/observability.md` has the metrics cross-reference convention section.

**Duration.** 2–3 days. Slot-tick event ~0.5d; resource attribute wiring ~0.5d; error-display
audit ~1d (sweep across `crates/*/src/error.rs`); metrics cross-ref doc + annotations ~0.5d.

**Phase-specific risks.** Error-display audit could surface broader refactor needs — scope to
adding context to existing variants; defer variant restructuring to a follow-up.

**Rollback plan.** P1 items are independent; each revertable alone.

---

## Risk Register (cross-phase)

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Retrofit breaks public API signature | High | Low | `cargo check --workspace` each commit; prefer `.instrument(span)` in body over `#[instrument]` on trait methods (architecture §8) |
| Forbidden-pattern test becomes a source of false positives | Medium | Medium | Narrow regex per architecture §2.3; explicit allowlist-comment with mandatory reason; reviewer gate |
| `TestTracingGuard` changes subscriber semantics and breaks existing tests | Medium | Low | Thread-local RAII via `set_default`; never `set_global_default`; per-test opt-in |
| Instrumentation perf regression | High | Low–Medium | 100-validator load test before Phases 4 and 5 merges; fail phase if delta >1% CPU or >5ms p99 slot latency |
| Scope creep into telemetry rewrite | High | Low | PRD out-of-scope list explicit; architect reviews PRs against it |
| gRPC trace context propagation silently drops | Medium | Low | Round-trip test in Phase 1 (unit) + Phase 5 (end-to-end) asserts `trace_id` continuity |
| Deprecation re-export `crypto::logging` retained past Phase 6 | Low | Medium | Exit checklist for Phase 6 explicitly removes the re-export after importer sweep |

---

## Open Questions

See architecture §8 for carried-over open items (SSE `stream_id` lifetime, collector tail-sampling
config as ops artifact, startup banner ordering). No new open items raised by this plan.
