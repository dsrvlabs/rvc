# Research: Production-Grade Structured Logging with the Rust `tracing` Ecosystem — Best Practices

> Angle for the rs-vc logging initiative (PRD: `plan/logging/prd.md`). Scope: opinionated,
> workspace-wide conventions for `tracing` + `tracing-subscriber`, grounded in the existing rs-vc
> stack (`telemetry` crate, OTLP, `crypto::logging` redaction primitives). Template D
> (Best Practices).

## Recommended Approach

Adopt a **spans-first, `snake_case`, instrument-the-async-entry-points** model:

- Put correlation identifiers (`slot`, `epoch`, `pubkey`, `duty`, `request_id`, …) on
  `#[tracing::instrument]` **spans** so they attach to every child event for free and propagate
  across `.await`, spawned tasks, and crate boundaries; reserve per-event fields for data unique to
  that one event. The `tracing` span model makes a field set on a span automatically apply to every
  event emitted while that span is active [1][9], and the OTLP layer turns those span fields into
  span attributes [12], so spans-first is the lowest-friction way to feed the existing pipeline.
- Treat the five levels as a strict, audience-keyed taxonomy (error/warn = operator-actionable,
  info = low-volume operator heartbeat, debug = developer decision points, trace = wire-level
  step-by-step) [3][4][16]. This matches the PRD's normative table exactly, so this research
  ratifies it rather than proposing an alternative.
- Lean on `tracing`'s **interest caching and static-max-level elision** for zero-cost-when-disabled,
  rather than hand-rolled guards: disabled events never construct the event and never evaluate their
  field-value expressions [5][8], and levels above `STATIC_MAX_LEVEL` are removed from the binary at
  compile time [6][8]. Use `Display` wrappers (rs-vc already has `TruncatedPubkey`/`RedactedUrl`)
  instead of `format!()` so no string is built when the level is off [2 §fields][PRD].
- Instrument **async** correctly: never hold a `Span::enter()` guard across `.await`; use
  `#[instrument]` (which rewrites the body to do the right thing), `.instrument(span)` on raw
  futures, `.in_current_span()` on spawned tasks, and `Span::in_scope()` for synchronous closures
  inside async code [7][10][11].

This is intentionally close to the PRD's stated decision; the research below is the evidence and the
**precise idioms** that make it correct and cheap, ending with a concrete convention list rs-vc can
paste into its standard doc.

## Approach Overview

### Option 1: [Recommended] — Spans-first correlation, events for point data

**How it works:** Correlation IDs live once on the span created by `#[instrument]` (or a manual
`info_span!`). Because a span's fields are inherited by every event recorded while the span is
entered [1][9], a single `#[instrument(fields(slot, %pubkey, duty = "attestation"))]` on the duty
entry point makes every downstream `debug!`/`trace!` — including ones in `crypto`/`signer` called
across crate boundaries — carry `slot`/`pubkey`/`duty` without repeating them. The OTLP layer records
those span fields as span attributes [12], so the same data drives both the text log and the trace.

**Why this one:** It is the convention the existing OTLP pipeline is built for; it eliminates the "ad
hoc correlation" problem the PRD calls out; and it keeps individual `info!`/`debug!` call sites short
and consistent. It also degrades gracefully — even a flattened/JSON backend that does not understand
span nesting still receives `trace_id`/`span_id` for correlation [12][13].

**Trade-offs:** Backends that *flatten* spans and drop span fields will lose the correlation keys
unless the fmt/JSON layer is configured to render current-span fields onto each event (this is the
PRD's Open Question #5). Mitigation: keep the option of also stamping the one or two most important
keys (e.g. `request_id`) on the terminal event of each operation.

### Option 2: [Alternative] — Per-event fields on every call site (no span inheritance)

**How it works:** Every `info!`/`debug!`/`trace!` repeats `slot = …, pubkey = %…, duty = …` inline.

**When to prefer this:** Only if the aggregation backend cannot carry span context at all and you are
not running the OTLP layer — i.e. pure flat-line JSON with no trace pipeline.

**Trade-offs:** Verbose, error-prone, and drifts (the exact failure mode — synonyms like `val_idx`
vs `validator_index` — the PRD is trying to kill). Rejected as the default; allowed as a *targeted*
supplement (stamp `request_id` on terminal events) per Option 1's mitigation.

### Option 3: [Alternative] — `log`-crate-style flat events, no spans

**How it works:** Use only leveled macros, treat `tracing` as a structured `log`.

**When to prefer this:** Tiny binaries with no async fan-out. Not applicable to rs-vc, which has deep
async call chains and a cross-process Web3Signer boundary where span/trace propagation is the whole
point.

**Trade-offs:** Throws away the single biggest reason to be on `tracing` (span-based correlation and
OTLP). Rejected.

## Level Taxonomy — what concretely belongs where

`tracing`'s own level docs define the intent: ERROR = very serious errors, WARN = hazardous
situations, INFO = useful information, DEBUG = lower-priority info, TRACE = very low-priority, often
extremely verbose [3]. The widely-cited community/operational refinement [4][16] maps that onto
production behavior, and matches the PRD's normative table:

| Level | Production default | Concretely contains | rs-vc examples (from PRD hot paths) |
|---|---|---|---|
| `error` | on | An intended action did **not** complete and needs a human. | Sign rejected by slashing protection; all BNs unreachable; keystore decrypt failed. |
| `warn` | on | Unexpected but handled; degraded-but-progressing. | BN failover; remote-signer retry/slow; duty fetched late; malformed API input rejected. |
| `info` | **on (the heartbeat)** | Operator-facing **milestones only**. Low, bounded volume. | Startup/config summary; epoch processed; attestation published for slot N; block proposed; validator set loaded; BN connected; `:9000` signer listening. |
| `debug` | off | Developer **decision points / internal state**. | Duty cache hit/miss + contents; selected BN and why; slashing-protection inputs/outcome; orchestrator state transitions. |
| `trace` | off | **Step-by-step / wire-level**, highest volume. | Each signing-payload build step; BN HTTP and `:9000` request/response framing; per-item loop iterations; computed roots/domains (non-secret). |

Operational guidance backing this: TRACE is for function entry/exit, loop iterations, and verbose
diagnostics and is usually disabled in production; DEBUG is variable values / decision branches and
usually disabled in production; INFO is general operational events (request handling, business
events, startup/shutdown) and is enabled in production [16]. Note: `#[instrument]` defaults its span
to **INFO** [2][14] — for hot-path functions that fire per-slot/per-validator this is too loud, so
rs-vc must set `level = "debug"` (or `"trace"`) on those spans (see conventions).

**Keeping `info` low-volume (production default).** The lever is the taxonomy itself plus filtering:
- Anything that scales with validator count or fires every loop iteration is `debug`/`trace`, never
  `info`. `info` is reserved for *milestones* that an operator would want as a liveness signal [16].
- A function instrumented at INFO emits an enter/exit pair per call; for hot functions, drop the
  **span** level to `debug`/`trace` so the span exists for correlation only when verbose is on
  [2][14]. The span and its child events are then elided entirely when the level is disabled [5][6].
- `RUST_LOG`/`EnvFilter` is the runtime control. A bare level sets the max for everything not matched
  by a more specific directive [15]; per-module directives (`rvc_signer::http_api=trace`) raise just
  one area without flooding the rest [15].

## `#[tracing::instrument]` idioms (the core mechanic)

Defaults (quote-exact): "Unless overridden, a span with the INFO level will be generated"; "The
generated span's name will be the name of the function"; "By default, all arguments to the function
are included as fields on the span" [2]. Primitive args implementing `Value` are recorded as their
type; everything else is recorded via `fmt::Debug` [2].

| Arg | What it does | rs-vc usage rule |
|---|---|---|
| `skip(a, b)` / `skip_all` | Omit named args / all args from the span. Skipped args need not implement `Debug` [2][14]. | **Mandatory** for `self`, keystores, secret material, large buffers (`Vec<u8>`, full payloads). `skip_all` + explicit `fields(...)` is the safest default on sensitive fns. |
| `fields(k = expr, %k, ?k)` | Add explicit key/value pairs; any Rust expression is allowed; combine with `skip_all` to record only chosen fields [2][14]. | Where the canonical correlation keys are stamped. Use `%` for `Display` (e.g. `pubkey = %TruncatedPubkey(hex)`), `?` for `Debug`, plain for `Copy` numerics (`slot`). |
| `level = "debug"` (or 1–5 / `Level::DEBUG`) | Override span level [2][14]. | **Required** on per-slot/per-validator hot fns so the default INFO does not flood. |
| `name = "..."` | Override span name (default = fn name) [2][14]. | Use a stable, greppable name on public entry points (e.g. `name = "sign_request"`) so renames don't break dashboards. |
| `target = "..."` | Override span target (module path kept separately) [2][14]. | Use to group cross-crate hot paths under one filterable target (e.g. `target = "rvc::hotpath"`) when per-module filtering is too coarse. |
| `ret` | Emit an event with the return value on return; for `Result<T,E>` records **only `Ok`** [2]. Event level = span level (default TRACE for the value event) [14]. | Allow on non-secret, small returns at `debug`/`trace`; **forbid** where the return contains a signature/payload/secret. Pair with `ret(Display)` to control formatting. |
| `err` | Emit an event when `Result::Err` is returned; default formats via `Display`, `err(Debug)` for `Debug`; defaults to **ERROR** level [2]. | Useful, but watch the PRD's "log once" rule — do not `err` at every layer; reserve for the layer that decides the error is terminal, else it double-logs. |

Idiomatic rs-vc skeleton for a hot async entry point:

```rust
#[tracing::instrument(
    level = "debug",                  // not the default INFO — this is hot
    name = "sign_request",            // stable, greppable
    skip_all,                         // never auto-Debug args (secrets!)
    fields(slot, %pubkey, duty = %duty, request_id = %req_id),
    err                               // log terminal error here, once
)]
async fn handle_sign(/* … */) -> Result<Signature, SignError> { /* … */ }
```

`#[instrument]` works on `async fn` and `#[async_trait]` methods; it rewrites the body so the span is
correctly entered/exited around await points (see next section). `const fn` cannot be instrumented
[2].

A field declared empty in `fields()` can be filled later with `Span::current().record("k", v)` once
the value is known [2][12] — useful for stamping `request_id` or a result count discovered mid-fn.

## Async span propagation (the part that's easy to get wrong)

**Why a bare `Span::enter()` across `.await` is a bug.** From the official docs:
> "In asynchronous code that uses async/await syntax, `Span::enter` may produce incorrect traces if
> the returned drop guard is held across an await point." [9]

Mechanism: when a future yields at `.await`, the scope is exited but its locals are **not** dropped,
so the `EnteredSpan` guard stays alive; the executor then polls a *different* task while your span is
still entered, producing overlapping/incorrect spans [9][11]. clippy flags this
(`clippy::await_holding_span_guard`-style lints exist for exactly this) [11].

**The correct idioms:**

1. **`#[tracing::instrument]`** on the `async fn` — preferred; the macro generates the right
   enter/exit-on-poll behavior for you [2][10].
2. **`Future::instrument(span)`** on a raw future/async block: "The attached Span will be entered
   every time the instrumented Future is polled or Dropped" — entered on each poll, exited on each
   yield [10]:
   ```rust
   use tracing::Instrument;
   some_future().instrument(tracing::debug_span!("build_attestation", slot)).await;
   ```
3. **`.in_current_span()`** when handing a future to `tokio::spawn`, so the spawned task keeps the
   *current* span as parent across the task boundary [10]:
   ```rust
   let span = tracing::info_span!("publish", slot);
   let _e = span.enter();
   tokio::spawn(async { /* inherits `publish` */ }.in_current_span());
   ```
   (Note the guard `_e` is fine here because it is **not** held across an `.await` — the spawn is
   synchronous; the future itself carries the span via `in_current_span`.)
4. **`Span::in_scope(|| { … })`** to enter a span for a *synchronous* block inside async code: it
   takes a sync closure and exits the span before the closure returns, so the span is always exited
   before the next await point [9][11].

**Across crate boundaries / spawned tasks / the `:9000` Web3Signer process boundary.** In-process,
spans propagate automatically through the call stack and (with the idioms above) across `.await` and
`tokio::spawn`. Across the *process* boundary to the remote signer, the `telemetry` crate's W3C
trace-context propagation (`inject_trace_context`, `TraceContextPropagator`) carries the trace into
the HTTP request so the signer's spans join the same trace [PRD][12] — i.e. correlation survives the
`:9000` hop via standard OTLP context propagation, not via the log text.

## Zero-cost-when-disabled (P0-6) — what actually makes it free

Three layers, in order of strength:

1. **Runtime interest cache (always on).** "For performance reasons, if no currently active
   subscribers express interest in a given set of metadata by returning true, then the corresponding
   Span or Event will never be constructed." And critically, when disabled, "argument expressions are
   not evaluated" [5][8]. So `trace!(root = %compute_root(...))` does **not** call `compute_root`
   when `trace` is off — provided the work is *inside* the macro's field expression, not computed
   into a local beforehand.
2. **Compile-time static-max-level elision.** `STATIC_MAX_LEVEL` is "the statically configured
   maximum trace level"; "the instrumentation macros check this value before recording an event or
   constructing a span", and instrumentation at disabled levels "will not even be present in the
   resulting binary" [6][8]. Controlled via cargo features `max_level_*` (debug builds) and
   `release_max_level_*` (release builds) [6]. For rs-vc, a release build can keep all levels
   compiled in (so operators can dynamically enable `trace`), or set
   `release_max_level_debug`/`info` if the team decides `trace` should be physically absent in prod.
3. **`enabled!` for unavoidably-expensive setup.** When a value is too expensive to compute even as a
   deferred field expression and is needed across several statements, gate it:
   ```rust
   use tracing::{enabled, Level};
   if enabled!(Level::TRACE) {
       let dump = expensive_wire_dump();        // only runs when TRACE is live
       tracing::trace!(?dump, "bn request frame");
   }
   ```
   `enabled!` "checks whether a span or event is enabled based on the provided metadata" [5][8].

**Practical rules for rs-vc** (these are what make the above true in the hot path):
- Put the cost **inside** the field expression or behind `enabled!`; never compute a String/hash into
  a local and then pass it to `debug!`/`trace!` — that always runs (PRD P0-6).
- Prefer the existing zero-alloc `Display` wrappers (`TruncatedPubkey`, `RedactedUrl`) over
  `format!()`. Their `Display::fmt` is only invoked when the level is enabled (the wrapper's own
  doc-comment states "When tracing level is disabled, `Display::fmt` is never called.")
  [crypto/src/logging.rs][2 §fields].
- Use `#[instrument(skip_all, fields(...))]` so the macro does not `Debug`-format heavy/secret args
  on every call [2][14].
- `%`/`?` sigils select `Display`/`Debug` recording [5][8]; choose `%` (cheaper, controlled) for
  anything that has a purpose-built `Display`.

## Field naming conventions

- **`snake_case`, canonical keys, no synonyms.** This aligns with OpenTelemetry semantic-convention
  naming, which mandates `snake_case` for multi-word components ("words should be separated by
  underscores", e.g. `http.response.status_code`) and identical meaning for identical names across
  Span/Log/Metric signals [17][18]. Because the OTLP layer maps span fields → span attributes [12],
  matching OTel naming keeps rs-vc logs and traces queryable with one vocabulary.
- **Use the PRD's canonical registry verbatim** (`slot`, `epoch`, `validator_index`, `pubkey`,
  `duty`, `request_id`, `bn_url`, `committee_index`, `network`). Forbid drift (`val_idx`,
  `validator`, `node`) — drift is precisely what breaks `RUST_LOG` field filters and dashboards [PRD].
- **Namespacing (dots) vs underscores.** OTel: prefer dot-namespacing to avoid clashes, but "use
  underscore only when using dot does not make sense or changes the semantic meaning" (e.g.
  `rate_limiting`, not `rate.limiting`) [17]. rs-vc's flat keys (`slot`, `bn_url`) are fine; if a
  namespace is ever introduced, follow `domain.subkey` (e.g. `bn.url`) consistently — but the PRD
  registry's flat names are the standard, so do not retrofit dots onto existing keys without updating
  the registry. (`EnvFilter` field-matching works on the flat key name regardless [15].)
- **`network` is a resource attribute, not a per-event field.** `telemetry::init` already sets
  `network.name` (and `service.version`) on the OTLP `Resource` [telemetry/src/init.rs] — do **not**
  duplicate it on every event [PRD].
- Numeric IDs (`slot`, `epoch`, `*_index`) are `u64` and recorded as native values (cheap, typed);
  `pubkey`/`bn_url` go through redaction wrappers with `%`.

## `target=` usage and per-module filtering

- By default an event's/span's **target is the module path** (crate + module), and a crate's dash
  becomes an underscore (`rvc-signer` → target root `rvc_signer`) [15]. So `RUST_LOG`
  per-module directives work out of the box: `rvc_signer::http_api=trace`,
  `rvc_beacon=debug`, `warn,rvc_slashing=trace` [15].
- `EnvFilter` directive grammar is `target[span{field=value}]=level`; a bare level is the global max
  for anything not matched by a more specific directive [15]. This is the lever for "verbose one area
  without flooding the rest."
- Override `target = "..."` on `#[instrument]`/macros only when you want a **cross-crate logical
  channel** that module-path filtering can't express (e.g. tag all hot-path spin under
  `target = "rvc::hotpath"` so an operator can do `RUST_LOG=info,rvc::hotpath=trace`). Use sparingly;
  default to module-path targets so filters stay predictable.
- Field-level filtering (`[sign_request{duty="block"}]=trace`) is available for surgical debugging
  [15] — worth documenting in the P1-4 operator guide, but not something code must do.

## Implementation Guidelines (rs-vc, opinionated — adopt these)

1. **Spans-first.** Stamp canonical correlation fields (`slot`, `epoch`, `validator_index`,
   `%pubkey`, `duty`, `request_id`) on the `#[instrument]` span at each hot-path async entry point;
   let child events inherit them. Per-event fields carry only event-specific data
   (`count`, `%bn_url`, `result`).
2. **Instrument hot fns at the right level.** `#[instrument]` defaults to INFO [2]; set
   `level = "debug"` (or `"trace"`) on anything that fires per-slot/per-validator/per-loop so `info`
   stays a milestone-only heartbeat.
3. **Always `skip`/`skip_all` sensitive & heavy args**, then re-add chosen fields via `fields(...)`.
   `self`, keystores, secret-key bytes, full payloads, large `Vec<u8>` must never be auto-`Debug`ed
   [2][14]. This is also a redaction control, not just performance.
4. **Redaction via the sanctioned `Display` wrappers only.** `pubkey = %TruncatedPubkey(hex)` and
   `bn_url = %RedactedUrl(url)` — never the raw value, never `format!()`. These are zero-alloc when
   the level is off [crypto/src/logging.rs]. Forbidden at *every* level (incl. `trace`): private
   keys, keystore passwords, mnemonics, full signing payloads/signatures, raw URL credentials [PRD].
5. **Async correctness is mandatory.** Never hold `Span::enter()` across `.await`. Prefer
   `#[instrument]`; use `.instrument(span)` for raw futures, `.in_current_span()` for `tokio::spawn`,
   `Span::in_scope()` for sync closures in async code [9][10][11]. Add the clippy lint for
   await-holding-span-guards to CI if available.
6. **Cost stays inside the macro.** Put expensive computations in the field expression or behind
   `enabled!(Level::TRACE)`; never precompute into a local and pass it in [5][8].
7. **Canonical `snake_case` keys, no synonyms.** Use the PRD registry's exact names; align with OTel
   naming so logs and traces share one vocabulary [17][18]. `network` stays a resource attribute.
8. **Default to module-path targets**; reserve `target = "..."` for deliberate cross-crate channels.
   Document `RUST_LOG` recipes (`rvc_signer::http_api=trace`, etc.) for operators [15].
9. **`err` once, not per layer.** Use `#[instrument(err)]`/`error!` at the layer that decides an error
   is terminal; lower layers return the `Result` (matches CLAUDE.md "log once" + PRD dedup) [2][PRD].
10. **`ret` only on non-secret, small returns** at `debug`/`trace`; never where the return is a
    signature/payload/secret [2].
11. **Reconcile subscriber init** (P0-5): both binaries on `info` default with `RUST_LOG`/`EnvFilter`
    env-overrides-config precedence and identical format selection; compose into the existing OTLP
    layer/file appender/`TracingGuard` — do not rebuild them [PRD][telemetry/src/init.rs].

## Common Pitfalls

- **Holding `Span::enter()` across `.await`** → overlapping, wrong spans. The single most common
  `tracing` async bug [9][11]. Fix with `#[instrument]` / `.instrument()` / `in_scope`.
- **Precomputing a `format!()`/hash into a local, then logging it** → the cost runs even when the
  level is disabled, defeating zero-cost. Keep it in the field expression or behind `enabled!`
  [5][8].
- **Leaving `#[instrument]` at the default INFO on a hot fn** → an enter/exit pair per call floods
  `info`. Drop the span level [2][14].
- **Letting all args auto-record** (no `skip`) on a fn taking secrets/`self`/big buffers → secret
  leak and/or expensive `Debug`. Use `skip_all` + explicit `fields` [2][14].
- **Field-name drift** (`val_idx` vs `validator_index`) → `RUST_LOG` field filters and dashboards
  silently miss data [PRD][15].
- **Duplicating `network` per event** when it is already a resource attribute → noise and cost [PRD].
- **`err` at every layer** → the same error logged N times up the stack [2][PRD].
- **Assuming spans survive a *flattened* JSON backend** → if the backend drops span fields, correlation
  keys vanish; either render current-span fields onto events or stamp `request_id` on terminal events
  (PRD Open Q #5).
- **Crate-name dash confusion in `RUST_LOG`** → operators must use the underscore form
  (`rvc_signer`, not `rvc-signer`) [15]; document it.

## Real-World Examples

- **Tokio (mini-redis)** instruments its connection handler with exactly the recommended shape —
  `#[instrument(name = "Handler::run", skip(self), fields(peer_addr = %…))]` — and emits point
  events with structured fields (`warn!{ %cause, "failed to parse command from frame" }`), explicitly
  noting "tracing provides structured logging, so information is logged as key-value pairs" [14].
- **rustc** uses `tracing` with per-module `RUST_LOG` filtering as its standard instrumentation
  mechanism, demonstrating target-based filtering at scale [4].
- **OpenTelemetry semantic conventions** are the cross-industry source for `snake_case` attribute
  naming and one-vocabulary-across-signals, which the OTLP layer makes directly applicable to
  `tracing` span fields [17][18][12].
- **rs-vc itself** already ships the right redaction primitive shape: `TruncatedPubkey`/`RedactedUrl`
  are zero-alloc `Display` wrappers whose `fmt` is skipped when the level is disabled, and
  `telemetry::init` puts `network.name`/`service.version` on the OTLP resource — this research
  ratifies extending those, not redesigning them [crypto/src/logging.rs][telemetry/src/init.rs][PRD].

## Assumptions

- The PRD's normative level taxonomy and canonical field registry are authoritative; this research's
  job is to validate them against `tracing` ecosystem practice and supply precise idioms — so the
  conventions above deliberately ratify (not contradict) the PRD.
- rs-vc stays on the current `tracing` 0.1.x / `tracing-subscriber` 0.3.x line and the existing
  `telemetry` OTLP stack; no framework swap (per PRD Non-Goals). The macro/feature behaviors cited
  (`STATIC_MAX_LEVEL`, `max_level_*`, `Instrument`, `instrument` args) are stable across that line.
- Release builds keep all levels compiled in (so operators can dynamically enable `trace` via
  `RUST_LOG`); if the team instead wants `trace` physically absent in prod, that is a
  `release_max_level_*` cargo-feature decision flagged here for the gate, not assumed.
- Spans-first is acceptable to the operators' backend (OTLP collector carries span context). If a
  flat backend that drops span fields is in play, the Option-1 mitigation (render current-span fields
  onto events, or stamp `request_id` on terminal events) applies — this maps to PRD Open Question #5.
- "Per-slot/per-validator/per-loop" functions are the ones whose `#[instrument]` span level should be
  lowered to `debug`/`trace`; the exact list comes from the PRD's P0-4 hot-path enumeration.
- The clippy lint for await-holding-span-guards is available/enableable in this toolchain; if not,
  the rule is enforced by reviewer checklist instead.

## Sources

[1] [tracing — crate root docs (spans, events, structured fields)](https://docs.rs/tracing) — tokio-rs, docs.rs (current). Spans have begin/end and nest; events are point-in-time; both record typed fields + messages.
[2] [`#[tracing::instrument]` attribute macro](https://docs.rs/tracing/latest/tracing/attr.instrument.html) — tokio-rs, docs.rs (current). Default INFO span; default name = fn name; all args become fields; `skip`/`skip_all`, `fields`, `level`, `name`, `target`, `ret` (Ok-only), `err` (default ERROR) semantics; async/`async-trait` support; `const fn` unsupported.
[3] [`tracing::Level` docs](https://docs.rs/tracing/latest/tracing/struct.Level.html) — tokio-rs, docs.rs (current). Canonical definitions of ERROR/WARN/INFO/DEBUG/TRACE.
[4] [Using the tracing/logging instrumentation — Rust Compiler Dev Guide](https://rustc-dev-guide.rust-lang.org/tracing.html) — rust-lang (current). Real-world per-module `RUST_LOG` filtering; level-usage guidance.
[5] [tracing crate root — overhead, interest caching, `enabled!`, `%`/`?` sigils](https://docs.rs/tracing/latest/tracing/index.html) — tokio-rs, docs.rs (current). "If no currently active subscribers express interest … the corresponding Span or Event will never be constructed"; disabled → "argument expressions are not evaluated"; `enabled!`; Display/Debug sigils.
[6] [`tracing::level_filters` — `STATIC_MAX_LEVEL` and compile-time elision](https://docs.rs/tracing/latest/tracing/level_filters/index.html) — tokio-rs, docs.rs (current). `STATIC_MAX_LEVEL`; `max_level_*`/`release_max_level_*` cargo features; macros check it; disabled levels "will not even be present in the resulting binary".
[7] [`tracing::span` module docs (async warning)](https://docs.rs/tracing/latest/tracing/span/index.html) — tokio-rs, docs.rs (current). Why holding `Span::enter` across `.await` is wrong; `in_scope` mention.
[8] [tracing crate root (overhead/elision, secondary read)](https://docs.rs/tracing/latest/tracing/) — tokio-rs, docs.rs (current). Corroborates [5][6] on zero-cost-when-disabled and field-expression non-evaluation.
[9] [`tracing::span::Span` docs — `enter`/`EnteredSpan` async warning](https://docs.rs/tracing/latest/tracing/span/struct.Span.html) — tokio-rs, docs.rs (current). Exact warning: `Span::enter` "may produce incorrect traces if the returned drop guard is held across an await point"; recommends `in_scope`/`Instrument`.
[10] [`tracing::Instrument` trait](https://docs.rs/tracing/latest/tracing/trait.Instrument.html) — tokio-rs, docs.rs (current). `.instrument(span)` and `.in_current_span()`; "attached Span will be entered every time the instrumented Future is polled or Dropped"; spawn example.
[11] [clippy issue: await in tracing span / await-holding-span-guard](https://github.com/rust-lang/rust-clippy/issues/8722) — rust-lang/rust-clippy (2022). Mechanism of overlapping spans across `.await`; `in_scope` vs `Future::instrument` fixes.
[12] [How to Structure Logs Properly in Rust with tracing and OpenTelemetry](https://oneuptime.com/blog/post/2026-01-07-rust-tracing-structured-logs/view) — OneUptime, 2026-01-07. Span fields → attributes; `trace_id`/`span_id` embedded; `.instrument()` for spawned tasks; `Span::current().record(...)`; `%` Display; redaction wrapper types; level table; "never concatenate values into message strings".
[13] [How to Create Structured JSON Logs with tracing in Rust](https://oneuptime.com/blog/post/2026-01-25-structured-json-logs-tracing-rust/view) — OneUptime, 2026-01-25. JSON fmt layer; structured key-value output for aggregation backends.
[14] [Getting started with Tracing — Tokio topics](https://tokio.rs/tokio/topics/tracing) — Tokio project (current). Official `#[instrument]` usage incl. `name`/`skip`/`fields(%…)`; `warn!{ %cause, … }`; "structured logging, so information is logged as key-value pairs".
[15] [`tracing_subscriber::filter::EnvFilter` docs](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) — tokio-rs, docs.rs (current). `RUST_LOG` grammar `target[span{field=value}]=level`; target = module path; dash→underscore; bare level = global max; per-module + field directives.
[16] [How to Structure Logs Properly in Rust with tracing (level-usage table)](https://oneuptime.com/blog/post/2026-01-07-rust-tracing-structured-logs/view) — OneUptime, 2026-01-07. Concrete per-level production guidance (TRACE/DEBUG dev-only & off in prod; INFO+ on; WARN/ERROR alerting).
[17] [Attribute Naming — OpenTelemetry semantic conventions (general)](https://opentelemetry.io/docs/specs/semconv/general/naming/) — OpenTelemetry (current). `snake_case` for multi-word components; namespacing via dots; "underscore only when dot doesn't make sense"; lowercase/alnum/`_`/`.` constraints.
[18] [Semantic Conventions overview — OpenTelemetry](https://opentelemetry.io/docs/concepts/semantic-conventions/) — OpenTelemetry (current). Identical namespaces/names across Resource/Span/Log/Metric MUST have identical meaning — one vocabulary across signals.
[PRD] rs-vc logging PRD (`plan/logging/prd.md`) and in-repo code: `crates/crypto/src/logging.rs` (`TruncatedPubkey`/`RedactedUrl`, zero-alloc `Display`), `crates/telemetry/src/init.rs` (OTLP layer, `network.name`/`service.version` resource attrs, `TracingGuard`). Source of the normative taxonomy, canonical field registry, redaction policy, and subscriber-init divergence.
