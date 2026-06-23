# Issue Estimates Index

See per-phase files for issue content. This index lists totals, critical path, and pointers.

## Estimation Approach

- Point scale: 1 / 2 / 3 / 5 Fibonacci. 1 = trivial, 2 = half day, 3 = 1 day, 5 = 1.5-2 days.
  No issue above 3 points in this breakdown.
- Every issue is completable in 1-2 working days by a single code-writer.
- Execution model: single-stream by default. Code-writer works top-to-bottom inside each phase.
- Velocity assumption: ~2 points/day, sum of issue points ~= sum of day estimates from
  `plan/observability/project-plan.md`.

## Totals

- Total issues: 48
- Total points: 90
- Estimated duration (single stream, ~2 pts/day): ~37-45 working days.

## Per-Phase Breakdown

| File | Phase | Issues | Points | Est. days |
|------|-------|--------|--------|-----------|
| [phase-1-telemetry-foundation.md](./phase-1-telemetry-foundation.md) | Phase 1 - Telemetry Foundation | 7 | 13 | 5-6 |
| [phase-2-redaction-promotion.md](./phase-2-redaction-promotion.md) | Phase 2 - Redaction Promotion + bls.rs Debug Fix | 3 | 5 | 2-3 |
| [phase-3-forbidden-pattern-test.md](./phase-3-forbidden-pattern-test.md) | Phase 3 - Forbidden-Pattern Test (Ratchet) | 3 | 5 | 2-3 |
| [phase-4-duty-hot-path.md](./phase-4-duty-hot-path.md) | Phase 4 - Duty Hot-Path Retrofit | 11 | 21 | 9-11 |
| [phase-5-io-safety-grpc.md](./phase-5-io-safety-grpc.md) | Phase 5 - External I/O + Safety + gRPC | 11 | 23 | 9-11 |
| [phase-6-mop-up.md](./phase-6-mop-up.md) | Phase 6 - Remaining Crates + Bins | 5 | 9 | 4-5 |
| [phase-7-test-harness-docs.md](./phase-7-test-harness-docs.md) | Phase 7 - Test-Harness + Conventions Doc | 5 | 9 | 4-5 |
| [phase-8-p1-polish.md](./phase-8-p1-polish.md) | Phase 8 - P1 Polish | 3 | 5 | 2-3 |
| Total | | 48 | 90 | ~37-45 |

## Critical Path

Single-stream default: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8.

Issue-level longest chain:

```
1.1 (redact) -> 1.2 (TestTracingGuard) -> 1.3 (tonic prop) -> 1.4 (init) -> 1.5 (file format)
  -> 1.7 (gate)
2.1 (logging re-export) -> 2.2 (bls Debug) -> 2.3 (importer sweep)
3.1 (scanner) -> 3.2 (fixtures) -> 3.3 (seed + CI)
4.1 (attestation) -> 4.2 (agg+sync) -> 4.3 (coordinator+utils) ->
  {4.4 block-service, 4.5 sync-service, 4.6 builder, 4.7 signer audit,
   4.8 propagator, 4.9 duty-tracker, 4.10 crypto signing audit} -> 4.11 (runbook gate)
5.1 (beacon) -> 5.2 (bn-manager) -> 5.3 (grpc client) -> 5.4 (rvc-signer server) -> 5.5 (round-trip)
  then: 5.6 web3signer, 5.7 gcp, 5.8 keymanager, 5.9 slashing, 5.10 validator-store, 5.11 doppelganger
6.1 (bin/rvc) -> 6.2 (rvc-keygen) -> 6.3 (rvc-signer mop-up + metrics) ->
  6.4 (remove crypto::logging) -> 6.5 (matrix verify)
7.1 (guard adoption - duty crates) -> 7.2 (guard adoption - prop/duty-tracker/slashing) ->
  7.3 (docs/observability.md) -> 7.4 (demo failing test) -> 7.5 (acceptance #2 review)
8.1 (error-display + metrics xref) -> 8.2 (resource attrs wire-up) -> 8.3 (slot-tick event)
```

## Parallelizable Branches (opt-in)

Default is single-stream. If the user opts into parallel execution after Phase 3 lands, the
following branches are independent (disjoint crate sets per architecture §1.5):

- Branch A (duty hot path): 4.1 -> 4.3 -> 4.11 is the spine. 4.4 / 4.5 / 4.6 / 4.7 / 4.8 /
  4.9 / 4.10 fan out after 4.3.
- Branch B (external I/O): 5.1 / 5.2 / 5.6 / 5.7 / 5.8 independent per crate; 5.3 + 5.4 + 5.5
  joined sub-chain; 5.9 / 5.10 / 5.11 independent safety items.
- Branch C (mop-up): 6.1 / 6.2 / 6.3 independent; 6.4 depends only on 2.3; 6.5 merges.
- Branch D (test harness + docs): 7.1 / 7.2 after Phase 1; 7.3 / 7.4 / 7.5 after 4.11.
- Branch E (P1 polish): Phase 8 always terminal.

Multi-stream plans additionally require file-ownership map / merge-conflict hotspots tables -
not produced here per single-stream default. If the user opts in, regenerate using
architecture §1.5 as the ownership baseline.

## Phase File Pointers

- [Phase 1 - Telemetry Foundation](./phase-1-telemetry-foundation.md) - redact.rs,
  test_capture.rs, tonic propagation, init resource attrs, file-appender format selector,
  dev-deps, gate.
- [Phase 2 - Redaction Promotion + bls.rs Debug Fix](./phase-2-redaction-promotion.md) -
  crypto/src/logging.rs thin re-export, bls.rs Debug fix, workspace importer sweep.
- [Phase 3 - Forbidden-Pattern Test (Ratchet)](./phase-3-forbidden-pattern-test.md) - scanner +
  allowlist parser, seeded fixtures + self-test, seed allowlist on current tree + CI wiring.
- [Phase 4 - Duty Hot-Path Retrofit](./phase-4-duty-hot-path.md) - orchestrator (3 issues),
  block-service, sync-service, builder, signer, propagator, duty-tracker, crypto signing
  audit, runbook integration gate.
- [Phase 5 - External I/O + Safety + gRPC](./phase-5-io-safety-grpc.md) - beacon, bn-manager,
  grpc-signer client, rvc-signer server, round-trip, web3signer, gcp, keymanager, slashing,
  validator-store, doppelganger.
- [Phase 6 - Remaining Crates + Bins](./phase-6-mop-up.md) - bin/rvc CLI + env, bin/rvc-keygen,
  bin/rvc-signer mop-up + metrics, remove crypto::logging, retrofit-matrix verification.
- [Phase 7 - Test-Harness + Conventions Doc](./phase-7-test-harness-docs.md) - TestTracingGuard
  adoption (2 batches), docs/observability.md publication, demo failing test, acceptance #2
  review exercise.
- [Phase 8 - P1 Polish](./phase-8-p1-polish.md) - error-display audit + metrics xref, resource
  attrs wire-up, slot-tick event.

## PRD Acceptance Metric Coverage

Per `plan/observability/prd.md` Goals & Success Metrics:

| # | Metric | Gated by |
|---|--------|----------|
| 1 | Oncall reconstructs duty lifecycle in <= 5 min from one trace id | Phase 4 Issue 4.11 + Phase 7 Issue 7.3 runbook |
| 2 | Developer reads span tree from default cargo test output on failure | Phase 7 Issues 7.4, 7.5 |
| 3 | cargo clippy --workspace --all-targets -- -D warnings passes | Phase 6 Issue 6.5 |
| 4 | 100% #[instrument] coverage on PRD-P0-4 hot path | Phase 4 Issues 4.1-4.10 |
| 5 | Forbidden-pattern regression test fails on banned pattern | Phase 3 Issues 3.1-3.3 |
| 6 | Zero new ERROR/WARN on clean cargo test --workspace | Phase 8 Issue 8.3 (plus Phase 4 failure-path classifiers) |

## Issues Blocked by Unresolved Design

None. All architectural open items from the PRD Gate and research contradictions were resolved
in `plan/observability/architecture.md`:

- Sampling head vs tail: resolved to head-parent-based + collector tail-sampling (§2.5, §5).
- File sink retention: resolved to size+count (PRD Gate item 2).
- Test capture API: resolved to tracing::subscriber::set_default (research contradiction #1
  corrected in architecture §2.2).
- gRPC propagation scope: resolved in scope (PRD Gate item 4; architecture §2.4).
- JSON vs text formatter: resolved JSON default for prod, text default for dev/test (PRD Gate
  item 5; architecture §2.6).
- docs/observability.md location: confirmed (PRD Gate item 6).
- Long-running span shape: resolved fresh-root-per-iteration with rvc.monitor.instance_id +
  optional add_link (architecture §6).

Architecture §8 Risks & Open Items lists three residual items - all operational, not
architectural, and none block any issue:

1. Async-trait #[instrument] Send-bound escape hatch - handled per-issue by the fallback
   pattern in Phase 4 / 5 tests.
2. Collector tail-sampling yaml is an ops artifact, not a rs-vc artifact.
3. rvc.sse.stream_id per-connection lifetime confirmed per-connection; any alternate lifetime
   is a follow-up.

## Risk Flags (cross-phase)

| Risk | Phase(s) exposed | Mitigation in issues |
|------|-------------------|----------------------|
| Retrofit breaks a public trait signature on async-trait + #[instrument] | Phase 4, 5 | Every Phase 4/5 issue lists the `.instrument(info_span!(...))` fallback; acceptance criteria require public signatures unchanged. |
| Forbidden-pattern test produces false positives and gets muted | Phase 3 | Issue 3.1 pins regex set verbatim from architecture §2.3; Issue 3.3 requires mandatory reason on every allowlist entry; Issue 3.2 self-test protects the allowlist parser. |
| Perf regression from new instrumentation | Phase 4, Phase 5 | Issue 4.11 has a loose runtime bound. Full 100-validator load test is an infra task (PRD Risks) to schedule outside this scope before merging Phase 4 / 5. |
| JSON formatter changes prod log shape for downstream consumers | Phase 6 (Issue 6.1) | `--log-format` is additive; text remains default for dev/test. PRD Gate item 5 ratifies the choice. |
| Scope creep into telemetry rewrite | All phases | PRD Out of Scope is the gate. No new workspace runtime deps; two dev-deps (walkdir, regex) called out in Issue 1.6. |
| SSE fresh-root-per-event floods trace backend | Phase 5 (Issue 5.2) | Architecture §5 tail-sampling at collector drops non-error traces; documented in Phase 7 Issue 7.3. |
