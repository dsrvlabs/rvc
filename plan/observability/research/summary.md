# summary
## Key findings (what architect/estimator must know first)

1. **Tonic trace propagation: hand-roll, don't depend on `opentelemetry-tonic`.** The crate is at 0.1.0 with unclear compat for our pinned `opentelemetry = 0.31` / `tonic = 0.12`. A hand-rolled `MetadataInjector`/`MetadataExtractor` (~20 LOC each, shown in `otel-semantic-conventions.md`) uses only `opentelemetry::propagation::{Injector, Extractor}` and `tonic::metadata::MetadataMap`. Lives in `crates/telemetry/src/propagation.rs`. No new workspace dep. Estimator: scope this as ~half a day, including client+server interceptor wiring tests.

2. **Dual-attribution is required for OTel backend usability.** rs-vc `rvc.*` fields give us business-level correlation; OTel semconv `rpc.*`, `http.*`, `server.*`, `url.*`, `error.type` fields give us Jaeger/Tempo compatibility for filter/search. Architect: document both in `docs/observability.md` conventions tables and list them per span family.

3. **Version pins are compatible; no upgrades needed.** `tracing-opentelemetry 0.32` depends on `opentelemetry ^0.31.0` — exact match. `tracing 0.1` + `tracing-subscriber 0.3` + `tracing-appender 0.2` + `logroller 0.1` + `tonic 0.12` all work together. No PRD-violating upgrade required.

4. **`#[instrument]` on `#[async_trait]` methods can break `Send` bounds** — the PRD already calls this out. Concrete recommendation: for all `async_trait` impl methods, use `.instrument(info_span!(...))` inside the method body, NOT `#[instrument]` on the method signature. Matches the pattern already used by some rs-vc code.

5. **Test-capture design works; PRD has an API-name mistake.** The design sketch in `test-capture-design.md` uses `tracing::subscriber::set_default` (thread-local, returns `DefaultGuard`, RAII drop) — exactly what the existing `secret-provider/tests/tracing_hierarchy.rs` uses. See contradiction #1 below.

## Surprises

- **`opentelemetry-tonic` crate is effectively unmaintained** (0.1.0, sparse metadata). Don't adopt.
- **Jaeger UI has known multi-year-old bugs rendering `FOLLOWS_FROM` and multi-parent spans** — this influences the long-running-span recommendation toward `rvc.monitor.instance_id` field over pure `SpanLink` reliance.
- **BatchSpanProcessor only exports on span end.** A long-lived parent span crashes lose the whole trace. This is the hard technical reason to prefer fresh-root-per-iteration for doppelganger + SSE monitoring.
- **gRPC `rpc.grpc.*` namespace doesn't exist** in OTel semconv — gRPC uses the generic `rpc.*` with `rpc.system.name = "grpc"`. Many blog posts get this wrong.

## Contradictions with the PRD (need user / architect attention)

1. **PRD Risks & Mitigations section: `with_default` is the wrong API name.**
   - PRD text (Risks): "use `with_default` (scoped) only; never call `set_global_default`".
   - Reality: `tracing::subscriber::with_default(sub, f: FnOnce)` is **closure-scoped** — it doesn't match the Guard-on-drop design described in P0-7. The existing precedent `secret-provider/tests/tracing_hierarchy.rs:59` correctly uses `tracing::subscriber::set_default` (returns `DefaultGuard`, thread-local RAII).
   - Action: architect should update the PRD Risks wording from `with_default` to `set_default` before estimation.

2. **PRD Resolved at Gate item 1: "always-sample errors" is not straightforwardly implementable as a head-based sampler.**
   - `rvc.outcome = error` is only knowable at span *close*, not at span *start*. A `ParentBased(TraceIdRatioBased)` head sampler decides at creation; late `Span::record` cannot retroactively flip a `NotSampled` decision to `Sampled`.
   - Two viable implementations, both scoped:
     - (a) Custom `ShouldSample` impl that inspects fields present at creation. Works only if the error determination (e.g. `rvc.outcome = error`) can be predicted at entry — usually false for duty operations.
     - (b) OTel Collector tail-sampling processor (configured at collector, not in rs-vc). Moves the "always-sample errors" rule outside the binary entirely.
   - Action: architect should pick (a) or (b) and update `architecture.md`. If this is a hard constraint in the PRD, option (b) is the low-risk path but requires the collector side to be configured.

3. **P0-4 "source compatibility constraint" is at mild tension with async-trait method `#[instrument]`.**
   - PRD says: retrofit MUST NOT cause source-breaking changes to public signatures. Adding `#[instrument]` to async trait methods is allowed where it doesn't change the `Send` bound.
   - In practice, because `#[instrument]` on an async fn rewrites the return type to an anonymous `Instrumented<_>`, on a trait method that returns `BoxFuture<'_, T>` via `#[async_trait]`, the rewrite can alter the concrete type produced by the macro expansion. Experimental finding (outside this research, cross-check during retrofit): most `async_trait` + `#[instrument]` stacks work because `#[async_trait]` runs first and boxes the result, swallowing the `Instrumented` type. But for certain shapes it inserts a `Send` bound mismatch.
   - Not a PRD bug — just a flag that the retrofit PRs must test compilation on every trait method touched and fall back to `.instrument(info_span!(...))` inside the body when `#[instrument]` breaks. The PRD does say this; estimator should plan for both paths when touching `async_trait` impls.

## Things the estimator must scope correctly

- **Redaction Debug-impl fixes are a concrete chunk of work** already visible: update `crates/crypto/src/bls.rs` `Debug` impls for `Signature` and `PublicKey` to use the promoted `TruncatedPubkey` / new `TruncatedSignature` helpers. Keep `Display` unchanged. ~50 LOC + tests. Blocker for enforcing the forbidden-pattern test without false-negatives.
- **Forbidden-pattern test** at workspace root (`tests/forbidden_log_patterns.rs`): ~200 LOC (walkdir + regex + allowlist parser), plus seed-and-verify fixture tests. Regex-over-source beats `syn` per analysis.
- **Tonic interceptor wiring**: two sides (rvc client, rvc-signer server) + one integration test exercising `traceparent` round-trip. Estimate: 1–1.5 days.
- **Doppelganger / SSE span retrofit**: "fresh root per iteration" pattern — small code delta, main work is test coverage for the multi-iteration correlation.
- **TestTracingGuard** + retrofit of listed integration tests: per-test adoption is ~1 line; the guard itself is ~300 LOC including span-tree pretty-printer. Estimate: 2 days for guard + 1 day per crate for retrofit coverage.

---

## Final 4-part report

### (1) Files written

All 7 research files are in `/Users/joonkyo.kim/git/dsrv/rvc/plan/observability/research/`:
`tracing-patterns.md`, `otel-semantic-conventions.md`, `redaction-and-secret-hygiene.md`,
`test-capture-design.md`, `prior-art.md`, `long-running-spans.md`, `summary.md`.

### (2) 5-line summary of findings

- **Version compat is clean** at our pins (`tracing-opentelemetry 0.32` → `opentelemetry 0.31` → works with `tonic 0.12`); hand-roll a ~20-LOC tonic `MetadataInjector`/`MetadataExtractor` rather than depend on the unmaintained `opentelemetry-tonic` crate.
- **`rvc.*` fields must be paired with OTel semconv `rpc.*`/`http.*`/`server.*`/`error.type`** for Jaeger/Tempo search and filter to work; note gRPC has no `rpc.grpc.*` namespace.
- **Test-capture design** via `tracing::subscriber::set_default` (thread-local `DefaultGuard` RAII) + `std::thread::panicking()` print-on-drop works; the PRD's reference to `with_default` is an API-name slip (see contradictions).
- **Active redaction gap exists today:** `crates/crypto/src/bls.rs` Debug impls for `Signature` and `PublicKey` leak the full hex — must be fixed as part of P0-2.
- **`#[instrument]` + `err`/`ret` hurt more than help** (Debug-formatted errors, unbounded return logging); stick to `skip_all` + explicit `fields(...)` + `Span::record` for deferred outcome/duration attachment.

### (3) Contradictions with the PRD needing user attention

1. **PRD "Risks & Mitigations": use `with_default` is wrong.** The API that matches the PRD's drop-guard test design (P0-7) is `tracing::subscriber::set_default`, which returns a thread-local `DefaultGuard`. `with_default` is closure-scoped and incompatible with a guard-on-drop pattern. Existing `secret-provider/tests/tracing_hierarchy.rs` already uses `set_default` correctly. Architect should correct the PRD text.

2. **PRD "Resolved at Gate" item 1 ("always-sample errors") can't be a pure head sampler.** Error outcome is only known at span close; a head-based `ShouldSample` at span start can't retroactively flip sampling. Architect must pick: (a) predict-at-entry via a computable field, or (b) OTel Collector tail-sampling outside rs-vc. This is an architectural decision not a PRD retraction, but it's a concrete scoped decision the architect owes.

3. **PRD P0-4 async-trait `#[instrument]` constraint is real but narrow.** Most `#[async_trait]` + `#[instrument]` stacks compile fine; some shapes produce `Send`-bound mismatches. Estimator should allow retrofit PRs to fall back to `.instrument(info_span!(...))` inside method bodies on any trait method where the macro approach fails to compile. PRD already permits this — flagging as "estimator budget this as a case-by-case overhead, not a universal overhead".

### (4) 1-sentence long-running-span recommendation

Use **fresh root span per iteration** for both the 2-epoch doppelganger monitor and the SSE event stream, correlated across iterations via an `rvc.monitor.instance_id` field (primary, log-readable) and optionally enhanced with `tracing_opentelemetry::OpenTelemetrySpanExt::add_link` to the previous iteration's `SpanContext` (secondary, trace-backend-readable) — this bounds trace size, survives process restarts cleanly, matches `BatchSpanProcessor` export-on-close semantics, and avoids Jaeger UI's historical `FOLLOWS_FROM`/multi-parent rendering quirks.

---

**Sources (aggregated):**

- [`tracing` crate — `#[instrument]`](https://docs.rs/tracing/0.1/tracing/attr.instrument.html)
- [`tracing::Span`](https://docs.rs/tracing/0.1/tracing/struct.Span.html)
- [`tracing::dispatcher::set_default`](https://docs.rs/tracing/0.1/tracing/dispatcher/fn.set_default.html)
- [`tracing_subscriber::fmt::TestWriter`](https://docs.rs/tracing-subscriber/0.3/tracing_subscriber/fmt/struct.TestWriter.html)
- [`tracing-opentelemetry 0.32` OpenTelemetrySpanExt](https://docs.rs/tracing-opentelemetry/0.32/tracing_opentelemetry/trait.OpenTelemetrySpanExt.html)
- [`opentelemetry 0.31` SpanKind](https://docs.rs/opentelemetry/0.31/opentelemetry/trace/enum.SpanKind.html)
- [`opentelemetry 0.31` Link](https://docs.rs/opentelemetry/0.31/opentelemetry/trace/struct.Link.html)
- [`opentelemetry_sdk 0.31` BatchSpanProcessor](https://docs.rs/opentelemetry_sdk/0.31/opentelemetry_sdk/trace/struct.BatchSpanProcessor.html)
- [`tonic 0.12` Interceptor](https://docs.rs/tonic/0.12/tonic/service/trait.Interceptor.html)
- [OTel semconv — RPC spans](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/rpc/rpc-spans.md)
- [OTel semconv — gRPC](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/rpc/grpc.md)
- [OTel semconv — HTTP spans](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/http/http-spans.md)
- [Lighthouse attestation_service.rs](https://raw.githubusercontent.com/sigp/lighthouse/stable/validator_client/validator_services/src/attestation_service.rs)
- [Lighthouse common/logging](https://raw.githubusercontent.com/sigp/lighthouse/stable/common/logging/src/lib.rs)
- [Prysm validator/client/attest.go](https://raw.githubusercontent.com/prysmaticlabs/prysm/develop/validator/client/attest.go)
- [Lodestar attestation.ts](https://raw.githubusercontent.com/ChainSafe/lodestar/unstable/packages/validator/src/services/attestation.ts)
- [Teku docs — validator-client](https://docs.teku.consensys.io/reference/cli/subcommands/validator-client)
- [Vouch configuration](https://github.com/attestantio/vouch/blob/master/docs/configuration.md)
- [Tempo architecture](https://grafana.com/docs/tempo/latest/introduction/architecture/)
- [Jaeger UI FOLLOWS_FROM rendering issue](https://github.com/jaegertracing/jaeger-ui/issues/115)
- [std::thread::panicking](https://doc.rust-lang.org/std/thread/fn.panicking.html)agentId: a3524cdeb51f556b0 (use SendMessage with to: 'a3524cdeb51f556b0' to continue this agent)
<usage>total_tokens: 287367
tool_uses: 77
duration_ms: 798517</usage>
