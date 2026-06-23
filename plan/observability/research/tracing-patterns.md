# tracing-patterns
## Summary
rs-vc already uses `tracing = 0.1` + `tracing-subscriber = 0.3` + `tracing-opentelemetry = 0.32` correctly on the duty hot path. Retrofit discipline centers on: always `skip_all`, always explicit `name = "rvc.*"`, deferred fields via `Span::record`, and preferring `.instrument(span)` over `#[instrument]` on async-trait methods to avoid `Send` bound surprises.

## `#[instrument]` attribute — exhaustive options (tracing 0.1)

| Option | Semantics | Use in rs-vc |
|---|---|---|
| `name = "rvc.xxx"` | Overrides span name (default = fn name). | **MANDATORY.** PRD P0-1 requires explicit `rvc.{domain}.{operation}`. |
| `skip(arg1, arg2)` | Excludes specific args from Debug-recording. | Use when one or two args are expensive/unsafe to Debug. |
| `skip_all` | Excludes *every* arg; pair with explicit `fields(...)`. | **MANDATORY** per PRD P0-1. Prevents accidental leaks and zero-alloc when level disabled. |
| `fields(k = v, k2 = %expr, k3 = ?expr, empty_field)` | Adds fields at entry. Expressions evaluated at call time. Empty fields are recorded later via `Span::record`. | Primary mechanism for `rvc.slot`, `rvc.epoch`, etc. |
| `level = Level::DEBUG` or `level = "debug"` | Span level. Default INFO. | Default INFO is correct for duty roots; lower to DEBUG for internal helpers. |
| `target = "rvc::module"` | Overrides span target. | Avoid — default is fine. |
| `parent = <span_ref>` / `parent = None` | Overrides implicit current-span parent. | Use `parent = None` only for root spans in long-running loops; see `long-running-spans.md`. |
| `follows_from = <id>` | Non-hierarchical causal link. | Not needed; use `OpenTelemetrySpanExt::add_link` when correlating long-running iterations. |
| `err` / `err(Display)` / `err(level = Level::WARN)` | Auto-emit an error event when `Result::Err`. Defaults to Debug formatting, ERROR level. | **Hurts more than helps.** Defaults to Debug formatting — violates PRD's "always `error = %e` not `?e`" rule. Avoid; manually log errors so `%e` / `Display` is used. |
| `ret` / `ret(Display)` | Emit event on successful return with the value. | Avoid — duty return types (Signatures, Blocks) should never be logged. |

## When `#[instrument]` vs manual span

**Use `#[instrument]`** when:
- Regular `async fn` on a struct, not a trait method.
- All fields known at entry or declared empty for later `Span::record`.
- The fn signature doesn't mention `SecretKey`/`SigningRequest` (else `skip_all` is mandatory and harder to audit via macro).

**Use `tracing::info_span!("rvc.xxx", ...)` + `.instrument(fut)` or `.entered()`** when:
- The span spans only a region inside a larger function (e.g. a signing call inside an attestation producer).
- Implementing an `async_trait` method where `#[instrument]` can alter the `Send` bound of the returned future (instrumented future type may differ from the trait's BoxFuture).
- Need a root span with `parent = None` in a long-running loop (clearer in code than `#[instrument(parent = None)]` on a helper fn).

Concrete rule: **on `#[async_trait]` trait impl methods, prefer `.instrument(info_span!(...))` inside the body**. The PRD already states this in Technical Considerations.

## `Span::record` for deferred fields

Canonical pattern for attaching `rvc.outcome` and `rvc.duration_ms` at the end:

```rust
#[tracing::instrument(
    name = "rvc.attestation.produce",
    skip_all,
    fields(rvc.slot = slot, rvc.validator_index, rvc.outcome, rvc.duration_ms)
)]
async fn produce(&self, slot: Slot, validator_index: u64) -> Result<...> {
    let start = std::time::Instant::now();
    tracing::Span::current().record("rvc.validator_index", validator_index);

    let outcome = match self.inner(slot).await {
        Ok(_) => "success",
        Err(e) if e.is_timeout() => "timeout",
        Err(_) => "error",
    };

    let span = tracing::Span::current();
    span.record("rvc.outcome", outcome);
    span.record("rvc.duration_ms", start.elapsed().as_millis() as u64);
    // ...
}
```

Declare every field you may `record` later as an empty field in `fields(...)` at macro time. `Span::record` cannot add new fields after span creation.

## `.in_current_span()` vs `.instrument(span)`

- `.in_current_span()` — returns `Instrumented<F>` wrapping the future with the current thread's active span. Use when spawning a `tokio::spawn` task that should continue under the caller's span (else the task would lose context).
- `.instrument(span)` — wraps the future with a specific span. Use to wrap a region inside a function with an explicit new span.

rs-vc already uses `.in_current_span()` correctly in a handful of places; the retrofit mainly needs more `.instrument(info_span!(...))` on signer/slashing regions.

## `enter()` / `entered()` — async danger

`Span::enter` and `entered()` return drop-guards that exit on drop. **Holding across `.await` produces wrong traces** because the span stays "current" while the task is parked on another thread. `.instrument(fut)` handles this correctly by entering the span on each poll and exiting on yield.

**Rule:** never call `.enter()` in async code. Use `.instrument()` or `#[instrument]`. Inside sync blocks inside an async fn, `Span::in_scope(|| { ... })` is OK.

## Anti-patterns to flag during retrofit

Grep targets (regex, workspace-wide):

1. `\.enter\(\)` in an `async fn` body — wrong for traces spanning await.
2. `#[tracing::instrument\]` (no parens) or `#[tracing::instrument()]` without `skip_all` — violates PRD P0-1.
3. `fields\([^)]*(?:signature|sk\b|secret|mnemonic|password)` — P0-2 forbidden.
4. `tracing::(info|debug|warn|error|trace)!.*\?.*err\b` or `error = ?e` — PRD mandates `%e`.
5. `?pubkey\b` where `pubkey` is a `[u8;48]` or `PublicKey` — use `%TruncatedPubkey::new(&hex)` instead.
6. Inconsistent `name =` — a span named e.g. `name = "attestation_produce"` instead of `name = "rvc.attestation.produce"`.

## Sources

- [`tracing` crate — `#[instrument]` attribute macro](https://docs.rs/tracing/0.1/tracing/attr.instrument.html) — tokio-rs, current docs for pinned `tracing = 0.1`.
- [`tracing::Span` methods](https://docs.rs/tracing/0.1/tracing/struct.Span.html) — `enter`, `entered`, `record`, `in_scope`, `instrument`.
- [`tracing::dispatcher::set_default`](https://docs.rs/tracing/0.1/tracing/dispatcher/fn.set_default.html) — returns `DefaultGuard`; thread-local RAII.

---
