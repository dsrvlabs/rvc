# Research: tracing → OpenTelemetry correlation across async tasks and the rvc ↔ rvc-signer :9000 boundary

## Summary

The `telemetry` crate already wires the whole pipeline: `tracing` spans → `tracing-opentelemetry`'s
`OpenTelemetryLayer` → batched OTLP/HTTP export, with a `ParentBased(TraceIdRatioBased)` sampler and
a W3C `TraceContextPropagator`. `tracing` span fields become OTel span **attributes**, and events
(`info!`/`debug!`/…) inside a span become OTel **span events** whose fields become event attributes
[1][9]. Correlation of one logical duty therefore reduces to three disciplines layered onto that
existing stack: (a) put the correlation identifiers (`slot`, `epoch`, `pubkey`, `duty`,
`request_id`, …) on the **span** (not just events) so they attach to every child and every
descendant span; (b) keep the span actually *entered across `.await`* by using `#[instrument]` /
`.instrument()` instead of `span.enter()`, and re-attach the span when crossing `tokio::spawn`; and
(c) make the trace **continuous across the :9000 HTTP hop** by injecting W3C context on the rvc
(client) side — already done in `beacon::client` via `telemetry::inject_trace_context` — **and
extracting it on the rvc-signer (server) side**, which today is the single missing piece: the
`POST /api/v1/eth2/sign/{id}` handler starts a fresh root trace instead of continuing the caller's.

The biggest *correctness* gaps in the current tree, all fixable by composing into the existing
`telemetry` module rather than rebuilding it:

1. **No inbound extraction at :9000.** `telemetry::propagation` has `inject_trace_context` (outbound)
   but no `extract_trace_context` (inbound), so `rvc-signer`'s `sign` handler
   (`bin/rvc-signer/src/http_api/routes.rs:51`) is a `#[tracing::instrument(skip_all)]` root — the
   trace breaks at the boundary even though the sampler is built to preserve it.
2. **No `request_id` on the signing path.** `request_id` exists only in `keymanager-api`
   (via `uuid::Uuid::new_v4()`); the Web3Signer sign path and `signer::SigningGate` carry none.
3. **Field-name namespace drift.** Orchestrator `#[instrument]` sites use a `rvc.`-prefix
   (`fields(rvc.slot = slot)`, span name `rvc.orchestrator.process_slot`) while `beacon::client`
   uses OTel semantic-convention names (`http.method`, `http.status_code`). The PRD's canonical
   registry (unprefixed `snake_case`: `slot`, `epoch`, `pubkey`, `duty`, `request_id`) must be the
   one source of truth, and the existing sites normalized to it.

## Key Concepts

### How `tracing` spans/fields map to OTel spans/attributes

`OpenTelemetryLayer` (constructed in `telemetry::init::init_tracing` as
`OpenTelemetryLayer::new(tracer)`) is a `tracing_subscriber::Layer` that, for every `tracing` span,
starts a corresponding OTel span and copies the span's fields onto it as attributes [1]. Mechanics
that matter for correlation:

- **Span fields → span attributes.** Any field set on a `tracing` span — at creation
  (`info_span!("…", slot = 42)`), via `#[instrument(fields(...))]`, or late via `span.record(...)` —
  is exported as an attribute on the OTel span [1]. Field names are passed through essentially
  verbatim, so dotted names like `http.method` become the OTel attribute `http.method` [1] (this is
  why `beacon::client` can follow OTel HTTP semantic conventions just by naming fields that way).
- **Events → span events.** A `tracing` event emitted while a span is entered is recorded as an OTel
  `Event` on the enclosing span, and the event's fields become attributes on that span event [9].
  Consequence for the PRD: identifiers placed on the **span** are visible on every child event
  automatically; identifiers placed only on the **event** are *not* inherited by sibling/child
  events. This is the mechanical reason the PRD's "spans-first" convention is the right default.
- **Reserved `otel.*` fields.** `otel.name` overrides the exported span name (useful for
  non-static names), `otel.kind` sets span kind (`"server"`/`"client"`/…), and
  `otel.status_code`/`otel.status_description` set span status [1]. `otel.kind = "server"` is the
  correct marker for the inbound :9000 span; `"client"` for the outbound beacon/signer calls.
- **Error → exception semantics.** `OpenTelemetryLayer` has opt-in config
  (`with_error_fields_to_exceptions`, `with_error_events_to_exceptions`, `with_error_events_to_status`)
  that maps error-valued event fields to OTel `exception.*` attributes and span status [9]. Not
  currently enabled in `init.rs`; optional future polish, out of scope for correlation.

### Declaring fields up-front with `field::Empty` and late-binding via `record()`

A span's fields are part of its **statically-constructed metadata** and *cannot be added after
creation* [2][3]. Therefore any field whose value is not known at span creation **must be declared
up front** with `tracing::field::Empty`, and filled in later with `span.record("field", value)`
[2][3]. The hard pitfall: **`record()` on a field that was not declared at creation is silently
dropped — no error, no effect** [2]. This is the single most common reason a correlation field
"vanishes" from traces.

This pattern is already used correctly in-repo: `beacon::client` declares
`http.status_code = tracing::field::Empty` on its request span and records the real code after the
response (`crates/beacon/src/client.rs:766`, `:1044`). The same idiom is the right way to attach
`slot`/`pubkey`/`duty`/`request_id` at the rvc-signer boundary, where some identifiers (e.g. `slot`,
`duty`, `pubkey`) are only known *after* the request body is parsed, not at handler entry.

With `#[instrument]`, declare the placeholder in the macro and record inside the body:

```rust
#[tracing::instrument(
    name = "rvc.signer.sign",
    skip_all,
    fields(request_id = %request_id, duty = tracing::field::Empty,
           slot = tracing::field::Empty, pubkey = tracing::field::Empty),
)]
async fn sign(/* … */) {
    // … parse body …
    let span = tracing::Span::current();
    span.record("duty", duty_label);                 // e.g. "block" / "attestation"
    span.record("slot", slot);
    span.record("pubkey", tracing::field::display(TruncatedPubkey::new(&pubkey_hex)));
}
```

Field names declared in `#[instrument(fields(...))]` *without a value* are equivalent to `Empty`
and may be recorded later in the body [2][4]. Note that to record a `Display`/`Debug` value you must
wrap it with `tracing::field::display(...)` / `tracing::field::debug(...)` at the `record()` call
site (the `%`/`?` sigils are only sugar inside the macros).

### W3C trace-context propagation across the HTTP boundary

`telemetry::init::init_tracing` installs `TraceContextPropagator` as the global text-map propagator
(`global::set_text_map_propagator`), which serializes/parses the W3C `traceparent`/`tracestate`
headers [4][8]. Propagation is two halves:

- **Inject (client side — exists).** `telemetry::inject_trace_context(headers)` takes
  `tracing::Span::current().context()` (the `OpenTelemetrySpanExt::context()` bridge that turns the
  current `tracing` span into an OTel `Context`) and calls `propagator.inject_context(...)` through a
  `HeaderInjector` adapter over `reqwest::HeaderMap` (`crates/telemetry/src/propagation.rs:25`).
  `beacon::client` already calls this on every GET/POST so beacon-node calls continue the trace.
- **Extract (server side — MISSING).** The inverse: implement an `opentelemetry::propagation::Extractor`
  over the inbound header map, call `global::get_text_map_propagator(|p| p.extract(&extractor))` to
  get the remote parent `Context`, then attach it to the request span with
  `OpenTelemetrySpanExt::set_parent(parent_cx)` [4][5][7]. Canonical shape, mirroring the existing
  `HeaderInjector`:

```rust
// add to crates/telemetry/src/propagation.rs (composes into the existing module)
use opentelemetry::propagation::Extractor;

struct HeaderExtractor<'a>(&'a http::HeaderMap);
impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Make `span` a child of the W3C trace context carried on `headers`, if any.
pub fn set_parent_from_headers(span: &tracing::Span, headers: &http::HeaderMap) {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let parent_cx = opentelemetry::global::get_text_map_propagator(|prop| {
        prop.extract(&HeaderExtractor(headers))
    });
    span.set_parent(parent_cx);
}
```

In the `sign` handler, call `telemetry::set_parent_from_headers(&tracing::Span::current(), &headers)`
as the first line so the handler span continues the caller's trace [5][7]. If no `traceparent` is
present (Prysm/Lighthouse may not send one), `extract` yields an empty context and the span stays a
root — graceful degradation, identical in spirit to the existing inject no-op [4].

> Note: the in-repo `crate` named `propagator` (`crates/propagator`) is the **attestation submission
> service**, unrelated to trace propagation; trace-context code lives only in
> `crates/telemetry/src/propagation.rs`. Don't conflate them.

### How the `ParentBased(TraceIdRatioBased)` sampler interacts with correlation

`init.rs` builds `Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(sample_rate)))`. This is
exactly the configuration that *preserves whole-trace correlation under sampling* [6][10]:

- **`TraceIdRatioBased(r)`** is a deterministic head sampler: the keep/drop decision is a hash of the
  `TraceId`, so the same trace ID yields the same decision regardless of service, language, or time
  [6]. The spec requires it to **ignore the parent sampled flag** on its own [10] — which is why it
  must be wrapped.
- **`ParentBased(root = …)`** is a decorator: if the span **has a parent**, it honors the parent's
  sampled flag (remote-parent-sampled → keep, remote-parent-not-sampled → drop, and likewise for
  local parents); only for a **root** span (no parent) does it delegate to the `TraceIdRatioBased`
  root sampler [6][10]. The sampled bit travels in the W3C `traceparent` flags, so a downstream
  service that *extracts* the context inherits the upstream decision verbatim [6][10].

Correlation consequence: a duty trace is sampled **all-or-nothing** end to end — if the rvc-side root
span is kept, every descendant (including the rvc-signer-side span and the beacon-node-side span) is
kept too, because each respects the propagated flag. **But this guarantee only holds if the boundary
is bridged.** If rvc-signer does *not* extract the inbound context (today's state), its handler span
is a fresh **root**, the ratio sampler re-rolls independently, and you get a fragmented, possibly
half-sampled view of one logical operation. Inbound extraction is therefore not just a "nice
parent-child link" — it is what makes the existing sampler honor the upstream decision. (`sample_rate`
defaults to `1.0`, so this is latent today but will bite the moment an operator lowers the rate.)

## How It Works (end-to-end correlation flow)

1. **rvc** enters a duty span (e.g. `rvc.orchestrator.process_slot`, already instrumented at
   `crates/rvc/src/orchestrator/attestation.rs:123`) carrying `slot`/`epoch`. The
   `ParentBased(TraceIdRatio)` root sampler decides keep/drop from the new trace ID.
2. All downstream work on that task inherits the span **because** the orchestrator fns are
   `#[instrument]`'d (the span is entered across every `.await`, not via `span.enter()`).
3. At a signing call, rvc opens a `client`-kind child span (`request_id` minted here as a
   `Uuid::new_v4()`), and `telemetry::inject_trace_context` writes `traceparent` (carrying the
   trace ID + sampled flag) into the outbound :9000 request headers.
4. **rvc-signer** `sign` handler runs `set_parent_from_headers(...)` first → its `server`-kind span
   becomes a child of rvc's span in the *same* trace; the sampler sees a sampled parent and keeps it.
   It echoes `request_id` (read from a header, or freshly minted if absent) and, after parsing,
   `record()`s `slot`/`duty`/`pubkey` (declared `Empty`).
5. `SigningGate.sign_*` (`crates/signer/src/gate.rs`) runs under that span; today it has *no*
   `#[instrument]`, so adding one (or `.instrument(Span::current())` on any spawned/blocking work)
   keeps `slashing`/`crypto` events correlated. Note `sign_block` already uses `spawn_blocking`
   internally (see the cancellation note at `gate.rs:243`) — blocking closures do **not** inherit
   the current span, so the span must be captured and re-entered inside the closure.
6. Every `info!`/`debug!`/`trace!` emitted anywhere in steps 1–5 is an OTel span event attached to
   the nearest enclosing span [9], so it inherits `slot`/`pubkey`/`duty`/`request_id` from the span
   without repeating them per-event.

## Code Examples (the canonical correlation-field set, end to end)

The PRD's normative registry maps onto OTel cleanly. Recommended canonical set, declared on **spans**
(unprefixed `snake_case` per the PRD; reconcile the existing `rvc.*` sites to these names):

| Field | Where declared | When valued | Notes |
|---|---|---|---|
| `request_id` | sign/API + duty span | at creation (mint `Uuid::new_v4()` or read inbound header) | the human-followable correlator across the :9000 hop |
| `slot` | duty/att/block/sign span | at creation if known, else `Empty`→`record` after parse | `u64` |
| `epoch` | duty span | at creation | `u64` |
| `duty` | duty/sign span | `Empty`→`record` once type known | `attestation`/`block`/`aggregate`/`sync_committee`/… |
| `pubkey` | sign/att/block span | `Empty`→`record` after identifier resolves | **always** `TruncatedPubkey` via `field::display(...)`; never the full key |
| `validator_index` | duty/att span | at creation if known | `u64` |
| `committee_index` | att span | at creation if known | `u64` |
| `otel.kind` | boundary spans | at creation | `"server"` inbound :9000 / beacon-server; `"client"` outbound |
| `network` | resource attr (already set in `init.rs`) | once | do **not** repeat per span/event |

```rust
// rvc side: mint request_id, open a client span, inject, call :9000
let request_id = uuid::Uuid::new_v4();
let span = tracing::info_span!(
    "rvc.signer.request",
    otel.kind = "client",
    request_id = %request_id,
    slot,
    duty = %duty,                              // known here
    pubkey = %TruncatedPubkey::new(&pubkey_hex),
);
async move {
    let mut headers = reqwest::header::HeaderMap::new();
    // carry request_id explicitly so the signer logs the same value even if
    // it re-roots; traceparent carries the trace itself.
    headers.insert("x-request-id", request_id.to_string().parse().unwrap());
    telemetry::inject_trace_context(&mut headers);
    // … POST to :9000 …
}
.instrument(span)                              // entered across .await, not span.enter()
.await
```

```rust
// rvc-signer side: continue the trace, echo request_id, late-bind slot/duty/pubkey
#[tracing::instrument(
    name = "rvc.signer.sign", skip_all,
    fields(otel.kind = "server", request_id = tracing::field::Empty,
           slot = tracing::field::Empty, duty = tracing::field::Empty,
           pubkey = tracing::field::Empty),
)]
async fn sign(headers: HeaderMap, /* … */) -> Response {
    let span = tracing::Span::current();
    telemetry::set_parent_from_headers(&span, &headers);   // <-- the missing bridge
    let request_id = headers.get("x-request-id")
        .and_then(|v| v.to_str().ok()).map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    span.record("request_id", tracing::field::display(&request_id));
    // … parse body, resolve identifier …
    span.record("duty", duty_label);
    span.record("slot", slot);
    span.record("pubkey", tracing::field::display(TruncatedPubkey::new(&pubkey_hex)));
    // every info!/warn! below now inherits all of the above on its span event
}
```

```rust
// crossing tokio::spawn / spawn_blocking: capture and re-enter the span
let span = tracing::Span::current();
tokio::task::spawn_blocking(move || {
    let _e = span.enter();   // OK here: NO .await inside a blocking closure
    // … sign …
});
// or, for async tasks, prefer:  tokio::spawn(work().instrument(tracing::Span::current()))
//                          or:  tokio::spawn(work().in_current_span())
```

## Common Pitfalls

- **Undeclared field silently dropped.** `span.record("slot", n)` does nothing unless `slot` was
  declared at creation (value or `field::Empty`) [2]. Declare every late-bound correlation field in
  the `#[instrument(fields(...))]` list or the `info_span!` call. This is the #1 cause of missing
  attributes.
- **`span.enter()` held across `.await`.** Holding the `Entered` guard across an await yields
  **incorrect traces**: the runtime can switch tasks while the span is still entered, so unrelated
  work is attributed to it [2][3]. Use `#[instrument]` (async-aware), `.instrument(span)`, or confine
  `span.enter()` to synchronous blocks via `Span::in_scope` [2]. `cargo clippy` has a lint for this.
- **`tokio::spawn` does not inherit the current span.** A spawned task starts with no parent unless
  you attach one; fields/correlation are lost across the spawn boundary [Discussion 6008]. Use
  `work().instrument(Span::current())`, `work().in_current_span()`, or `Span::or_current()` (preferred
  when the span may be disabled) [Instrument docs]. `spawn_blocking` closures likewise need an
  explicit `let _e = span.enter()` (safe there — no `.await` inside).
- **Boundary not bridged → fragmented trace + re-rolled sampling.** Without inbound `extract` at
  :9000, the signer span is a new root and the `ParentBased` sampler re-decides independently [6][10];
  the duty appears as two disconnected traces. Extraction is the fix, and it is currently absent.
- **Per-event vs per-span duplication.** Putting `slot`/`pubkey` only on events forces every event to
  repeat them and breaks "follow one span"; putting them on the span makes them inherit to all child
  events [9]. Spans-first is correct (the PRD's decision). Only flatten-to-event if a backend can't
  show span attributes.
- **Namespace drift.** `rvc.slot` (orchestrator) vs `slot` (PRD registry) are *different attribute
  keys* in the OTLP output — dashboards/queries that group by `slot` miss the `rvc.slot` spans.
  Normalize existing `#[instrument]` sites to the registry names.
- **Secret leakage via attributes.** Span attributes are exported to the collector just like log
  fields. `pubkey` must always be `TruncatedPubkey` (via `field::display`), URLs `RedactedUrl`, and
  signing roots/signatures/private material must never be a span field — the PRD redaction policy
  applies to OTel attributes identically. Use `skip`/`skip_all` on `#[instrument]` so large/sensitive
  args are never `Debug`-formatted into attributes.
- **Sampler footgun if reconfigured.** Replacing the wrapped sampler with a bare
  `TraceIdRatioBased` would make it ignore the parent flag [10] and shatter cross-service correlation.
  Keep the `ParentBased(...)` wrapper exactly as in `init.rs`.

## Concrete guidance: canonical correlation-field set carried end to end

1. **Adopt the PRD registry verbatim as span fields, spans-first.** `request_id`, `slot`, `epoch`,
   `duty`, `pubkey` (truncated), `validator_index`, `committee_index`. `network` stays a *resource*
   attribute (already set in `init.rs`); never duplicate it per span/event.
2. **Mint `request_id` once per logical operation** with `uuid::Uuid::new_v4()` (the in-repo
   `keymanager-api` precedent), put it on the rvc-side duty/sign span, propagate it across :9000 both
   implicitly (W3C `traceparent` → trace ID) and explicitly (an `x-request-id` header the signer
   echoes) so it appears identically on both sides' logs even if a request arrives without a
   `traceparent`.
3. **Add the inbound extractor to `telemetry::propagation`** (the `HeaderExtractor` +
   `set_parent_from_headers` shown above) and call it as the first line of the rvc-signer `sign`
   handler. This is the one change that actually closes the trace across the boundary and lets the
   existing `ParentBased` sampler do its job. Compose into the existing module; do not add a new crate
   (`axum-tracing-opentelemetry` is viable but is opinionated about init, which `telemetry` already
   owns, and has no published releases [crate analysis]).
4. **Declare late-bound fields as `field::Empty`** on every boundary/sign span (`slot`, `duty`,
   `pubkey` are only known after parse) and `record()` them once resolved — mirroring the existing
   `http.status_code = Empty` pattern in `beacon::client`.
5. **Instrument the signing authority.** Put `#[instrument(name="rvc.signer.gate.sign_*", skip_all,
   fields(slot, pubkey=%TruncatedPubkey…, request_id))]` on the `SigningGate.sign_*` methods
   (`crates/signer/src/gate.rs`), and re-enter the captured span inside the `spawn_blocking` closures
   so `crypto`/`slashing` events stay correlated.
6. **Normalize names.** Reconcile orchestrator `rvc.slot`/`rvc.epoch` to `slot`/`epoch` (or, if a
   namespace is desired, apply it uniformly and update the registry) so OTLP attribute keys match the
   registry across every crate.
7. **Keep the sampler as `ParentBased(TraceIdRatioBased(rate))`** unchanged — it is the mechanism
   that makes a sampled duty all-or-nothing across services *once the boundary is bridged*.
8. **Test with captured-subscriber/`tracing_test`** (PRD approach) asserting the boundary span has a
   non-zero parent (continues the trace) and that `pubkey` is truncated in the exported attributes.

## Assumptions

- The exact crate versions are those pinned in the workspace `Cargo.toml`:
  `tracing 0.1`, `tracing-subscriber 0.3`, `tracing-opentelemetry 0.32`, and `opentelemetry`
  / `opentelemetry_sdk` / `opentelemetry-otlp` `0.31`. Some linked docs pages render "latest";
  the `0.31`/`0.32` line behaves as described (the `OpenTelemetrySpanExt`, `field::Empty`/`record`,
  and `ParentBased`/`TraceIdRatioBased` semantics are stable across these versions).
- The correlation target is the duty/signing path the PRD names (orchestrator → signer/crypto →
  beacon, plus the Web3Signer :9000 hop). gRPC-signer / DVT peer paths are out of scope for this
  angle except to note they would need the same inject/extract discipline if correlation across them
  is later desired.
- An explicit `x-request-id`/`X-Request-Id` header is an acceptable, additive carrier for the
  human-readable `request_id` alongside W3C `traceparent`; it does not change signing behavior and is
  ignored by clients that don't send it. (If the team prefers deriving `request_id` from the OTel
  span/trace ID instead of a separate UUID, that is a viable alternative and avoids the extra header —
  flagged for the gate.)
- `inject_trace_context` is `reqwest`-typed today; the inbound `HeaderExtractor` is shown over
  `http::HeaderMap` (what axum hands the handler). Both `reqwest` and `axum` re-export the `http`
  crate's `HeaderMap`, so a single `http::HeaderMap`-based extractor serves the server side; the
  existing reqwest-based injector can stay as-is. This is a minor type detail to confirm at
  implementation time.
- `sample_rate` is effectively `1.0` in current deployments (the config default), so the
  fragmentation-from-missing-extraction problem is latent rather than currently observed; it becomes
  a real correlation bug as soon as the rate is lowered.
- This work is observability-only and composes into the existing `telemetry` stack (init, sampler,
  propagation, guard, OTLP/GCP exporters); it does not alter signing/slashing logic or public APIs,
  consistent with the PRD's Non-Goals.

## Sources

[1] [`tracing_opentelemetry` crate docs (OpenTelemetryLayer, field→attribute mapping, reserved `otel.*` fields)](https://docs.rs/tracing-opentelemetry/0.32.0/tracing_opentelemetry/) — docs.rs, accessed 2026-06-22. How span fields become OTel attributes; `otel.name`/`otel.kind`/`otel.status_code`; dotted field passthrough; `OpenTelemetrySpanExt` overview.
[2] [`tracing::Span` docs (`record`, field metadata is static, `enter` async warning)](https://docs.rs/tracing/latest/tracing/struct.Span.html) — docs.rs, accessed 2026-06-22. Fields must be declared at creation; recording an undeclared field is silently ignored; `field::Empty` for unknown values; holding `enter()` across `.await` is incorrect.
[3] [`tracing::span::Span` docs](https://docs.rs/tracing/latest/tracing/span/struct.Span.html) — docs.rs, accessed 2026-06-22. Same `record`/metadata semantics; `Future::instrument` as the async-correct alternative to `enter()`.
[4] [`tracing::instrument` attribute macro docs](https://docs.rs/tracing/latest/tracing/attr.instrument.html) — docs.rs, accessed 2026-06-22. Args→fields; `skip`/`skip_all`; `fields(...)` including value-less (Empty) fields recorded later; `parent`/`follows_from`; async-aware instrumentation.
[5] [`OpenTelemetrySpanExt` docs (`set_parent`, `context`, `add_link`, extract-then-set_parent example)](https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/trait.OpenTelemetrySpanExt.html) — docs.rs, accessed 2026-06-22. Canonical extract-remote-context-and-`set_parent` pattern.
[6] [Sampling concepts / ParentBased + TraceIdRatioBased behavior](https://opentelemetry.io/docs/languages/js/sampling/) — OpenTelemetry docs, accessed 2026-06-22. TraceIdRatioBased determinism; parent-based whole-trace consistency via the W3C sampled flag.
[7] [How to Instrument Rust Axum Applications with OpenTelemetry](https://oneuptime.com/blog/post/2026-02-06-instrument-rust-axum-opentelemetry/view) — OneUptime, 2026-02-06. Concrete `HeaderExtractor` over `http::HeaderMap`, `global::get_text_map_propagator(|p| p.extract(&ext))`, `set_parent` in an axum handler; adding custom attributes.
[8] [Context propagation](https://opentelemetry.io/docs/concepts/context-propagation/) — OpenTelemetry docs, accessed 2026-06-22. Propagators, W3C TraceContext, inject/extract across service boundaries.
[9] [`OpenTelemetryLayer` docs (events → span events; error/exception + inactivity config)](https://docs.rs/tracing-opentelemetry/0.32.0/tracing_opentelemetry/struct.OpenTelemetryLayer.html) — docs.rs, accessed 2026-06-22. `tracing` events recorded as OTel span events with field attributes; `with_error_*`, `with_tracked_inactivity`, `with_location`.
[10] [OpenTelemetry Trace SDK spec — Sampling (ParentBased decorator, TraceIdRatioBased MUST ignore parent flag)](https://opentelemetry.io/docs/specs/otel/trace/sdk/#parentbased) — OpenTelemetry specification, accessed 2026-06-22. The five parent cases ParentBased distinguishes; TraceIdRatioBased determinism/monotonicity and the requirement to wrap it in ParentBased to respect the parent sampled flag.
[Discussion 6008] [Do tasks inherit tracing spans? — tokio-rs/tokio Discussion #6008](https://github.com/tokio-rs/tokio/discussions/6008) — GitHub, accessed 2026-06-22. `tokio::spawn` does not inherit the current span; use `.instrument(Span::current())` / `.in_current_span()`.
[Instrument docs] [`tracing::Instrument` trait (`instrument`, `in_current_span`, `or_current`)](https://docs.rs/tracing/latest/tracing/trait.Instrument.html) — docs.rs, accessed 2026-06-22. Attaching a span to a future so it is entered across `.await`; `or_current` preferred over nesting.
[crate analysis] [playbookengineering/axum-tracing-opentelemetry](https://github.com/playbookengineering/axum-tracing-opentelemetry) — GitHub, accessed 2026-06-22. Middleware that extracts inbound traceparent and roots a child span; opinionated init helpers; pre-1.0, no published releases — supports composing a small in-repo extractor rather than adopting the crate.

## In-repo references (grounding)

- `crates/telemetry/src/init.rs` — pipeline init: `OpenTelemetryLayer::new(tracer)`,
  `set_text_map_propagator(TraceContextPropagator::new())`,
  `Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(sample_rate)))`, `network.name` resource attr.
- `crates/telemetry/src/propagation.rs` — existing `inject_trace_context` + `HeaderInjector`
  (outbound only); the inbound `HeaderExtractor`/`set_parent_from_headers` is the missing inverse.
- `crates/beacon/src/client.rs:766`,`:1044` — in-repo precedent for `field::Empty` + late `record`
  (`http.status_code`) and per-request `inject_trace_context`.
- `bin/rvc-signer/src/http_api/routes.rs:51` — `sign` handler is `#[instrument(skip_all)]` with **no**
  inbound extraction and **no** `request_id`: the boundary correlation gap.
- `crates/signer/src/gate.rs:225` (`sign_block`, `spawn_blocking` at `:243`) — signing authority with
  **no** `#[instrument]`; blocking closures need an explicit captured-span re-enter.
- `crates/rvc/src/orchestrator/{attestation,duty_management,aggregation,sync_committee,coordinator}.rs`
  — existing 9+ `#[instrument]` sites using the `rvc.`-prefixed field namespace
  (`fields(rvc.slot = slot)`), which diverges from the PRD's unprefixed registry and should be
  normalized.
- `crates/keymanager-api/src/handlers.rs:800` — in-repo `request_id = Uuid::new_v4()` precedent to
  reuse on the signing path.
