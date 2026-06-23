# otel-semantic-conventions
## Summary
OTel semconv mandates dual attribution: rs-vc's own `rvc.*` keys for business-level correlation PLUS OTel `rpc.*`/`http.*`/`server.*` keys for backend-agnostic tooling (Jaeger query, Tempo TraceQL, Grafana attribute filters). For tonic trace propagation, hand-roll ~20 LOC of `MetadataInjector`/`MetadataExtractor`; do not add `opentelemetry-tonic` as a dep (version pinning unclear).

## OTel namespace vs `rvc.*` namespace

| Namespace | Ownership | Role |
|---|---|---|
| `rvc.*` | Our own | Business correlation: `rvc.slot`, `rvc.epoch`, `rvc.validator_index`, `rvc.pubkey`, `rvc.operation`, `rvc.outcome`, `rvc.slashing.result`, `rvc.duration_ms`. |
| `rpc.*` | OTel semconv stable | gRPC client/server spans — dual-attribute alongside `rvc.signer.*`. |
| `http.*` / `url.*` | OTel semconv stable | Beacon HTTP client spans — dual-attribute alongside `rvc.beacon.*`. |
| `server.*` / `network.*` | OTel semconv stable | Endpoint identity — redacted form. |
| `error.type` | OTel semconv stable | Short error class on failure (e.g. `timeout`, `connection_refused`). |
| `service.*` / `deployment.*` | OTel Resource | Set once on TracerProvider init (already covered in P1-3). |
| `otel.*` | `tracing-opentelemetry` reserved | `otel.status_code`, `otel.kind`, `otel.name` — set via magic field names. |

## Beacon HTTP client spans — required attributes

For `crates/beacon/src/client.rs` and each beacon endpoint wrapper:

| Key | Value | Required level |
|---|---|---|
| `http.request.method` | `"GET"` / `"POST"` | Required |
| `url.full` | `%RedactedUrl(full_url)` | Required (redact creds in URL) |
| `server.address` | host from URL | Required |
| `server.port` | port from URL | Conditionally required |
| `http.response.status_code` | u16 | Conditionally required (if received) |
| `http.request.resend_count` | retry attempt index | Recommended |
| `error.type` | short classifier on failure | Conditionally required |
| `rvc.beacon.endpoint_name` | endpoint route like `"/eth/v1/validator/duties/attester/{epoch}"` | rs-vc specific |
| `rvc.bn_endpoint` | redacted target BN base URL | rs-vc specific |
| `rvc.duration_ms` | u64 | rs-vc specific |
| `rvc.outcome` | `success|rejected|error|timeout` | rs-vc specific |

Span kind: `otel.kind = "client"`. Span name pattern: `rvc.beacon.{method_verb}` (e.g. `rvc.beacon.get_attester_duties`) — note: OTel semconv suggests span name = `{http.request.method}`, but rs-vc's `rvc.{domain}.{op}` convention takes precedence since the PRD locks it. Keep the verb-scoped rs-vc name; add the `http.*` attributes as dual-attribution.

## Tonic gRPC signer spans — required attributes

For `crates/grpc-signer/src/client.rs` (client side) and `bin/rvc-signer` (server side):

| Key | Value | Required level |
|---|---|---|
| `rpc.system.name` | `"grpc"` | Required |
| `rpc.method` | `"signer.v1.SignerService/Sign"` | Conditionally required |
| `rpc.response.status_code` | gRPC status string e.g. `"OK"`, `"DEADLINE_EXCEEDED"` | Conditionally required |
| `server.address` | signer host | Conditionally required |
| `server.port` | signer port | Conditionally required |
| `error.type` | short class on failure | Conditionally required |
| `rvc.signer.operation` | `"sign_attestation"` / `"sign_block"` / etc. | rs-vc specific |
| `rvc.signer_endpoint` | redacted signer target | rs-vc specific |
| `rvc.duration_ms` | u64 | rs-vc specific |
| `rvc.outcome` | as above | rs-vc specific |

Note: OTel semconv has **no `rpc.grpc.*` namespace** — gRPC uses the generic `rpc.*` keys with `rpc.system.name = "grpc"` and `rpc.response.status_code` as a string (`"OK"`, `"DEADLINE_EXCEEDED"`, etc., not the numeric code). Span kind: `otel.kind = "client"` for rvc side, `otel.kind = "server"` for rvc-signer side.

## W3C `traceparent` / `tracestate`

- Header / metadata key: `traceparent` (lowercase, canonical). Optional: `tracestate`.
- `traceparent` format: `00-<32-hex trace-id>-<16-hex span-id>-<2-hex flags>` (version 00 mandated).
- Existing beacon HTTP path already injects via `telemetry::inject_trace_context(&mut headers)` — verified in `crates/beacon/src/client.rs:117`.
- For tonic: gRPC metadata IS HTTP/2 headers; the same `traceparent`/`tracestate` keys work, but tonic needs its own `Injector`/`Extractor` types because `opentelemetry-http::HeaderInjector` targets `reqwest::HeaderMap`, not `tonic::metadata::MetadataMap`.

## Tonic interceptor — recommended hand-rolled implementation

Do NOT add the `opentelemetry-tonic` crate. Its version is 0.1.0 with sparse metadata and no confirmed compatibility with our pins (`opentelemetry = 0.31`, `tonic = 0.12`). Hand-rolled code is ~20 lines, stays on pinned versions, and lives cleanly in `crates/telemetry/src/propagation.rs` alongside the existing reqwest injector.

**`tonic = 0.12` Interceptor trait:**
```rust
pub trait Interceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status>;
}
// Blanket impl for any FnMut(Request<()>) -> Result<Request<()>, Status>.
```

**Client-side injector sketch (pseudocode — architect to finalize):**
```rust
use opentelemetry::global;
use opentelemetry::propagation::Injector;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::{Request, Status};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub struct MetadataInjector<'a>(pub &'a mut tonic::metadata::MetadataMap);

impl Injector for MetadataInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(k), Ok(v)) = (
            MetadataKey::from_bytes(key.as_bytes()),
            MetadataValue::try_from(value.as_str()),
        ) {
            self.0.insert(k, v);
        }
    }
}

pub fn inject_trace_context_grpc(req: &mut Request<()>) {
    let cx = tracing::Span::current().context();
    global::get_text_map_propagator(|prop| {
        prop.inject_context(&cx, &mut MetadataInjector(req.metadata_mut()));
    });
}
```

**Server-side extractor sketch:**
```rust
use opentelemetry::propagation::Extractor;

pub struct MetadataExtractor<'a>(pub &'a tonic::metadata::MetadataMap);

impl Extractor for MetadataExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().filter_map(|k| match k {
            tonic::metadata::KeyRef::Ascii(k) => Some(k.as_str()),
            _ => None,
        }).collect()
    }
}

// In the server handler, extract and attach as parent:
let parent_cx = global::get_text_map_propagator(|p| {
    p.extract(&MetadataExtractor(request.metadata()))
});
let span = tracing::info_span!("rvc.signer.sign", ...);
span.set_parent(parent_cx);
```

Install as a tonic interceptor layer on both sides (tower `ServiceBuilder::layer(interceptor(...))` client; `Server::builder().layer(...)` server). Both sides already use mTLS; trace context rides inside the established channel.

## Error outcome — exact API in pinned versions

To mark a span as failed (tracing-opentelemetry 0.32 on opentelemetry 0.31):

**Option A: magic reserved field (set at entry or via Span::record).**
```rust
tracing::info_span!("rvc.attestation.produce", otel.status_code = tracing::field::Empty);
// ... on error:
span.record("otel.status_code", "ERROR");
```

**Option B: `OpenTelemetrySpanExt::set_status`.**
```rust
use tracing_opentelemetry::OpenTelemetrySpanExt;
use opentelemetry::trace::Status;
tracing::Span::current().set_status(Status::error("signing rejected: double_vote"));
```

For PRD's "always-sample-errors" head sampler, the critical thing is that `rvc.outcome = "error"` must be recorded on the **root** span (not just a descendant). The sampler runs when the root span is created, so one of two shapes works:

1. Set `rvc.outcome = tracing::field::Empty` at root-span creation, then `Span::record("rvc.outcome", "error")` before the span closes. BatchSpanProcessor will export the span on close. But a head-based sampler can only decide at creation; late `record` doesn't retroactively flip `NotSampled` → `Sampled`. So this doesn't do what the PRD wants.
2. **Architect alert:** To actually "always sample error roots", implement a **tail-ish head sampler**: a custom `ShouldSample` impl that inspects attributes present at span-start. If the PRD wants error outcomes sampled that aren't known at span start, we need either (a) a custom processor that re-tags on close and re-routes, or (b) OTel Collector tail sampling. This is a scoped architectural question — **flag in summary contradictions**.

## Sources

- [OTel semconv — RPC spans](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/rpc/rpc-spans.md) — open-telemetry/semantic-conventions, current. Defines `rpc.*`, `server.*`.
- [OTel semconv — gRPC](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/rpc/grpc.md) — confirms gRPC uses generic `rpc.*` (no `rpc.grpc.*` namespace).
- [OTel semconv — HTTP spans](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/http/http-spans.md) — defines `http.request.method`, `url.full`, etc.
- [`tonic 0.12` `Interceptor` trait](https://docs.rs/tonic/0.12/tonic/service/trait.Interceptor.html) — signature `fn call(&mut self, Request<()>) -> Result<Request<()>, Status>`.
- [`tracing-opentelemetry 0.32` — OpenTelemetrySpanExt](https://docs.rs/tracing-opentelemetry/0.32/tracing_opentelemetry/trait.OpenTelemetrySpanExt.html) — `set_parent`, `set_status`, `add_link`, `context`.
- [`opentelemetry 0.31` — SpanKind](https://docs.rs/opentelemetry/0.31/opentelemetry/trace/enum.SpanKind.html) — Client/Server/Internal.

---
