# long-running-spans
## Verdict
**Fresh root span per iteration.** Correlate iterations via `rvc.monitor.instance_id` field (always-present, log-readable). Optionally enhance with `tracing_opentelemetry::OpenTelemetrySpanExt::add_link` to the previous iteration's `SpanContext` for trace-backend linking. This bounds trace size, survives restarts cleanly, matches BatchSpanProcessor export semantics, and is the industry-standard shape for long-running periodic work.

## Trade-offs — concrete

### Option A: one long-lived parent span

`rvc.doppelganger.monitor` wraps the entire 2-epoch (~12.8 min) monitoring loop; each epoch-check is a child span.

- **BatchSpanProcessor cost.** Spans are only exported **when they end**. The parent stays open for 12.8 min. If the process crashes at t=10min, the parent's partial trace — and every child under it — is lost. `opentelemetry_sdk::trace::BatchSpanProcessor` holds the span in memory on the dedicated background thread queue; children are independently held until export, but the parent-child relationship can only be assembled by the backend after the parent closes.
- **Memory.** Per-span memory cost is small (~KB), but queue pressure accumulates: default `max_queue_size = 2048`, so 2048 open-child spans would start dropping new ones.
- **Jaeger/Tempo rendering.** Both can ingest spans arbitrarily — **Tempo explicitly has no "end of trace" concept** and accumulates. BUT the UI rendering assumes a sensible trace duration; a 12.8-min trace shows a very compressed timeline, and child events are hard to locate. Jaeger defaults its search UI to a 2-hour window — usable; a 12.8-min trace is within that.
- **Restart case.** On crash, the parent span is lost (never closed, never exported) AND its children are orphaned — backend tries to render them under an unknown parent. This is the ugliest failure mode.

### Option B: one root span per iteration

Each epoch-check of doppelganger detection starts a new root span `rvc.doppelganger.check_epoch` with no parent. A shared field `rvc.monitor.instance_id = uuid::Uuid::new_v4()` (created once at monitor startup) links them for log-readers. For trace-readers, use `OpenTelemetrySpanExt::add_link(prev_ctx)` to attach a SpanLink to the previous iteration's SpanContext.

- **BatchSpanProcessor cost.** Each iteration span is short (~few ms to a few hundred ms), exports cleanly on end. Queue pressure is trivial.
- **Restart case.** Each iteration's span either exports before crash (if it finished) or is lost (if mid-flight). No orphaned children; each trace is self-contained.
- **Correlation for log-only readers.** `rvc.monitor.instance_id` appears on every log line; `grep instance_id=abc123` retrieves the full monitor run across iterations.
- **Correlation for trace-backend readers.** SpanLink attached via `OpenTelemetrySpanExt::add_link(prev_span_context)` lets Jaeger/Tempo navigate "previous iteration". Jaeger UI has known quirks rendering non-parent-child links — `FOLLOWS_FROM` rendering issues exist historically (jaeger-ui #115, #1802). Tempo handles SpanLinks more cleanly via TraceQL. **Bias: for rock-solid correlation, `rvc.monitor.instance_id` field alone is the minimum safe; SpanLinks are enhancement.**
- **Attribution.** Each root iteration span is a fresh root in sampling terms — `ParentBased(TraceIdRatioBased)` decides independently per iteration. With the PRD's "always-sample errors on root" rule, this is actually a benefit: failures of any iteration are sampled regardless of ratio, without holding a 12.8-min root open.

### SSE event stream (the other long-running case)

`crates/bn-manager/src/sse.rs` consumes a continuous Server-Sent Events stream from the beacon node. This is **structurally different** from doppelganger monitoring:
- SSE can run for hours/days — long-lived-span approach is even more catastrophic.
- Each SSE event is an independent work unit (head, reorg, finalized checkpoint, block notification).
- Recommendation: fresh root span **per event** with `rvc.sse.event_type` field. No attempt to link events — the BN-side trace chain stops at "event emitted"; rvc's job is to process each one. Reconnection attempts get their own `rvc.bn_manager.sse_reconnect` span.

## Concrete recommendation

Doppelganger monitor:
```rust
async fn monitor(&self) -> Result<()> {
    let instance_id = uuid::Uuid::new_v4().to_string();
    let mut prev_span_cx: Option<opentelemetry::trace::SpanContext> = None;

    for epoch in 0..2 {  // 2-epoch window
        let span = tracing::info_span!(
            parent: None,
            "rvc.doppelganger.check_epoch",
            rvc.monitor.instance_id = %instance_id,
            rvc.epoch = epoch,
            rvc.outcome = tracing::field::Empty,
        );
        if let Some(cx) = &prev_span_cx {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            span.add_link(cx.clone());
        }

        let check_result = async {
            // ... check liveness for each pubkey ...
        }.instrument(span.clone()).await;

        span.record("rvc.outcome", outcome_str(&check_result));
        prev_span_cx = Some(span.context().span().span_context().clone());
    }
    Ok(())
}
```

SSE event stream: fresh span per event, no linking, just the `rvc.sse.stream_id` field connecting events to a reconnection instance.

## Sources

- [`opentelemetry_sdk 0.31` BatchSpanProcessor](https://docs.rs/opentelemetry_sdk/0.31/opentelemetry_sdk/trace/struct.BatchSpanProcessor.html) — export on span end, queue size 2048 default.
- [`tracing-opentelemetry 0.32` OpenTelemetrySpanExt](https://docs.rs/tracing-opentelemetry/0.32/tracing_opentelemetry/trait.OpenTelemetrySpanExt.html) — `add_link`, `add_link_with_attributes`.
- [`opentelemetry 0.31` Link type](https://docs.rs/opentelemetry/0.31/opentelemetry/trace/struct.Link.html) — cross-trace link with attributes.
- [Grafana Tempo — no end of trace](https://grafana.com/docs/tempo/latest/introduction/architecture/) — spans accumulate; no trace completion concept.
- [Jaeger UI — FOLLOWS_FROM rendering quirks](https://github.com/jaegertracing/jaeger-ui/issues/115), [multi-parent rendering](https://github.com/jaegertracing/jaeger-ui/issues/467), [CHILD_OF vs FOLLOWS_FROM](https://github.com/jaegertracing/jaeger-ui/issues/1802).

---
