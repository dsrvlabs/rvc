# Phase 1: Telemetry Foundation

**Goal:** Land new telemetry helpers as purely additive code with no existing call-site changes.
**Total points:** 13
**Total issues:** 7
**Depends on:** none
**Unblocks:** Phase 2, Phase 3, Phase 4, Phase 5, Phase 6, Phase 7, Phase 8

Scope is the `crates/telemetry` crate only. All helpers land first so every downstream phase has a
stable import surface. Conventions / per-span field sets referenced throughout this phase live in
`plan/observability/architecture.md` §2 (public APIs) and §3 (span hierarchy table).

---

## Issue 1.1: Add redaction formatters in `crates/telemetry/src/redact.rs`

- **Points:** 2
- **Depends on:** none
- **Files touched:**
  - `crates/telemetry/src/redact.rs` (new)
  - `crates/telemetry/src/lib.rs` (add `pub mod redact;` and re-export block — architecture §1.1)
  - `crates/telemetry/Cargo.toml` (add `hex`, `url` dependencies if not already declared)
- **Summary:** Create the canonical redaction module with `TruncatedPubkey`, `TruncatedPubkeyBytes`,
  `TruncatedSignature`, `RedactedUrl`, `RedactedKeystore`, `RedactedSecret`. Formatters land first so
  Phase 2 can cut over `crypto::bls` Debug impls without waiting on additional plumbing.
- **Acceptance criteria:**
  - [ ] `crates/telemetry/src/redact.rs` exists with public types and signatures exactly as in
        architecture §2.1.
  - [ ] `TruncatedPubkey::new(hex: &str)`, `TruncatedPubkeyBytes(&[u8])`,
        `TruncatedSignature::from_bytes(&[u8])`, `RedactedUrl(&str)`,
        `RedactedKeystore { version, kdf, uuid, pubkey_hex }`, and `RedactedSecret` unit struct all
        implement `Display` and delegate `Debug` to `Display`.
  - [ ] `TruncatedPubkey` keeps the existing behavior from `crates/crypto/src/logging.rs` (input
        may omit the `0x` prefix; strings <= 18 hex chars pass through unchanged).
  - [ ] `TruncatedSignature::from_bytes(bytes)` produces `0x{first8_hex}...{last8_hex}` for any
        byte slice (docstring notes the expected 96-byte BLS signature length but the formatter is
        length-agnostic).
  - [ ] `RedactedUrl` replaces both username and password with `***` when either is set; path,
        query, and fragment are preserved verbatim; unparseable input falls through to the raw
        string.
  - [ ] `RedactedSecret` always prints `<redacted>`, zero allocation.
  - [ ] `crates/telemetry/src/lib.rs` adds `pub mod redact;` plus the re-export block from
        architecture §1.1 (`pub use redact::{RedactedKeystore, RedactedSecret, RedactedUrl,
        TruncatedPubkey, TruncatedPubkeyBytes, TruncatedSignature};`).
- **Tests:**
  - `crates/telemetry/src/redact.rs::tests::truncated_pubkey_long_with_prefix` —
    `TruncatedPubkey::new("0x93247f2209abcacf...611df74a").to_string()` returns exactly
    `0x93247f2209...611df74a`.
  - `crates/telemetry/src/redact.rs::tests::truncated_pubkey_short_passthrough` —
    <= 18 hex chars flow through unchanged (mirrors existing `crypto::logging` test).
  - `crates/telemetry/src/redact.rs::tests::truncated_pubkey_bytes_from_48_bytes` — 48-byte BLS
    pubkey bytes produce `0x{first10}...{last8}`.
  - `crates/telemetry/src/redact.rs::tests::truncated_signature_from_96_bytes` — produces
    `0x{first8}...{last8}`.
  - `crates/telemetry/src/redact.rs::tests::redacted_url_userinfo_strip` —
    `RedactedUrl("http://user:pass@host:4318/p?q=1")` produces exactly
    `http://***:***@host:4318/p?q=1`.
  - `crates/telemetry/src/redact.rs::tests::redacted_url_invalid_passes_through` — non-URL input
    reaches `Display` as-is.
  - `crates/telemetry/src/redact.rs::tests::redacted_keystore_shape` — asserts output of the form
    `Keystore{ver=4, kdf=scrypt, uuid=..., pubkey=0x9324...df74a}`.
  - `crates/telemetry/src/redact.rs::tests::redacted_secret_output` — `format!("{}",
    RedactedSecret)` equals `<redacted>`.
- **Non-goals:**
  - Query-parameter scrubbing in `RedactedUrl` (architecture §8 bullet on RedactedUrl).
  - Replacing any existing call sites with the new helpers (that's Phase 2 / retrofit phases).
  - Removing `crates/crypto/src/logging.rs` (kept as thin re-export during transition; removed in
    Phase 6).

---

## Issue 1.2: Implement `TestTracingGuard` + `CaptureLayer` + `SpanTreeFormatter`

- **Points:** 3
- **Depends on:** 1.1 (lib.rs re-export scaffolding lands with redact.rs)
- **Files touched:**
  - `crates/telemetry/src/test_capture.rs` (new)
  - `crates/telemetry/src/lib.rs` (add `pub mod test_capture;` + `pub use test_capture::{
    test_capture, TestTracingGuard};`)
- **Summary:** Handrolled test-capture guard following the precedent at
  `crates/secret-provider/tests/tracing_hierarchy.rs`. Thread-local RAII via
  `tracing::subscriber::set_default` (not `set_global_default`, not the closure-scoped
  `with_default` — see `research/summary.md` contradictions #1), prints span tree on drop when
  `std::thread::panicking()`.
- **Acceptance criteria:**
  - [ ] Public `TestTracingGuard` matches the contract in architecture §2.2:
        `spans_named(&self, &str) -> Vec<CapturedSpan>`,
        `events_at(&self, Level) -> Vec<CapturedEvent>`,
        `assert_child_of(&self, child, parent)`,
        `field_on_span(&self, span_name, field) -> Option<String>`,
        `dump(&self)`.
  - [ ] Public `test_capture() -> TestTracingGuard` convenience constructor exists.
  - [ ] Constructor uses `tracing::subscriber::set_default(Registry::default().with(CaptureLayer::
        new(buf)))` so parallel `cargo test` threads do not collide. Test asserts two guards on
        different threads capture independent buffers.
  - [ ] `CaptureLayer` implements `tracing_subscriber::Layer<S>`: `on_new_span` pushes a
        `CapturedSpan` with `parent_id` taken from `ctx.lookup_current()`, `on_record` updates the
        same entry (so `Span::record(...)` of deferred `rvc.outcome` / `rvc.duration_ms` fields is
        visible), `on_event` pushes a `CapturedEvent`, `on_close` is a no-op.
  - [ ] `Drop` impl prints the span tree via `println!` only when `std::thread::panicking()` is
        true; a non-panicking drop is silent. (Architecture §2.2 "drop-printing-on-panic".)
  - [ ] `SpanTreeFormatter` walks the parent-id graph and emits indented output matching the
        shape in PRD §UX/Design Notes (SPAN / EVENT / nested SPAN).
  - [ ] `field_on_span` clones out of the internal `Mutex<CaptureBuffer>` (cannot return a borrow
        that outlives the lock).
  - [ ] `#[must_use]` attribute on the guard struct.
- **Tests:**
  - `crates/telemetry/src/test_capture.rs::tests::captures_span_with_recorded_field` — create a
    guard, open `info_span!("rvc.test.op", rvc.outcome = Empty)`, record
    `rvc.outcome = "success"`, assert `field_on_span("rvc.test.op", "rvc.outcome") ==
    Some("success")`.
  - `crates/telemetry/src/test_capture.rs::tests::captures_parent_child_relationship` —
    parent `info_span!("parent")` with child `info_span!("child")`, assert
    `guard.assert_child_of("child", "parent")` does not panic.
  - `crates/telemetry/src/test_capture.rs::tests::captures_events_at_level` — fire one `info!`
    and one `warn!`, assert `events_at(Level::WARN).len() == 1`.
  - `crates/telemetry/src/test_capture.rs::tests::prints_tree_on_panic` — spawn a thread that
    creates a guard, records spans, then panics; parent thread captures stdout via
    `std::io::set_output_capture` (or a child-process harness) and asserts the panic output
    contains `SPAN` and recorded span names. (If stdout capture is impractical, assert via a
    `Drop`-side flag that drop detected `panicking()`.)
  - `crates/telemetry/src/test_capture.rs::tests::silent_on_normal_drop` — guard dropped without
    a panic writes nothing to stdout.
  - `crates/telemetry/src/test_capture.rs::tests::two_threads_independent_buffers` — two threads
    each take a guard; neither sees the other's spans.
- **Non-goals:**
  - Adopting the guard in downstream integration tests (Phase 7 does the rollout).
  - `tracing-test` crate dependency — PRD §Resolved at Gate item 3 forbids.
  - Global subscriber installation (`set_global_default`). PRD risks explicitly rules it out.

---

## Issue 1.3: Add tonic trace-context propagation helpers

- **Points:** 2
- **Depends on:** 1.1
- **Files touched:**
  - `crates/telemetry/src/propagation.rs` (extend — existing reqwest `inject_trace_context` stays)
  - `crates/telemetry/src/lib.rs` (add re-exports from architecture §1.1:
    `attach_server_parent, extract_trace_context_grpc, inject_trace_context,
    inject_trace_context_grpc, TraceContextInterceptor`)
  - `crates/telemetry/Cargo.toml` (ensure `tonic` dep is present in this crate; use workspace
    `tonic = "0.12"`)
- **Summary:** Extend propagation with gRPC helpers. Hand-rolled
  `MetadataInjector` / `MetadataExtractor` (~10 LOC each, `research/summary.md` finding #1
  justifies avoiding the unmaintained `opentelemetry-tonic` crate), plus `inject_trace_context_grpc`
  / `extract_trace_context_grpc`, `attach_server_parent`, and the client-side
  `TraceContextInterceptor`.
- **Acceptance criteria:**
  - [ ] `MetadataInjector<'a>(pub &'a mut MetadataMap)` implements
        `opentelemetry::propagation::Injector`.
  - [ ] `MetadataExtractor<'a>(pub &'a MetadataMap)` implements
        `opentelemetry::propagation::Extractor`.
  - [ ] `pub fn inject_trace_context_grpc<T>(req: &mut tonic::Request<T>)` writes `traceparent` /
        `tracestate` into metadata via `global::get_text_map_propagator`.
  - [ ] `pub fn extract_trace_context_grpc<T>(req: &tonic::Request<T>) ->
        opentelemetry::Context` parses incoming metadata back into an OTel `Context`.
  - [ ] `pub fn attach_server_parent<T>(req: &tonic::Request<T>)` attaches the extracted parent
        context to `tracing::Span::current()` via `OpenTelemetrySpanExt::set_parent`.
  - [ ] `#[derive(Clone, Default)] pub struct TraceContextInterceptor` implements
        `tonic::service::Interceptor::call` by calling `inject_trace_context_grpc`.
  - [ ] Documentation notes that the **server side is NOT an `Interceptor`** (architecture §2.4
        paragraph after the code block); pick option (a) per-handler `attach_server_parent` in
        Phase 5.
  - [ ] Existing `inject_trace_context` for `reqwest::header::HeaderMap` is unchanged and still
        exported.
- **Tests:**
  - `crates/telemetry/src/propagation.rs::tests::round_trip_grpc_traceparent` — RED→GREEN→REFACTOR:
    start with a failing assertion that `extract_trace_context_grpc` after
    `inject_trace_context_grpc` recovers the same `TraceId`/`SpanId`. Use `init_tracing` (existing
    helper) + a `set_default` subscriber, open a span, inject into a fresh
    `tonic::Request<()>`, extract, and assert the extracted `SpanContext.trace_id()` equals the
    originating span's trace id.
  - `crates/telemetry/src/propagation.rs::tests::interceptor_injects_on_call` — build a
    `TraceContextInterceptor`, call `interceptor.call(Request::new(()))`, assert the returned
    request has a `traceparent` metadata entry starting with `00-`.
  - `crates/telemetry/src/propagation.rs::tests::metadata_injector_rejects_invalid_key` — invalid
    metadata key (spaces) does not panic and does not corrupt the map.
- **Non-goals:**
  - Server-side tower `Layer` — architecture §2.4 option (a) is per-handler; option (b) is
    deferred.
  - `opentelemetry-tonic` crate dependency.
  - Wiring these into `crates/grpc-signer` or `bin/rvc-signer` (Phase 5 issues).

---

## Issue 1.4: Extend `init.rs` with resource attrs and startup banner

- **Points:** 2
- **Depends on:** 1.1 (for `RedactedUrl` inside the banner formatting)
- **Files touched:**
  - `crates/telemetry/src/init.rs`
  - `crates/telemetry/src/config.rs` (add `instance_id: String`, `deployment_env: String`,
    `file_sink_enabled: bool` fields to `TelemetryConfig`, with documented defaults)
- **Summary:** Add `service.instance.id` and `deployment.environment` OTel resource attributes
  (PRD P1-3) and emit a one-shot `info!` startup banner ("telemetry pipeline initialized") on
  successful init (PRD §Non-Functional "Observability of observability"). Sampler stays
  `ParentBased(TraceIdRatioBased)` per architecture §2.5.
- **Acceptance criteria:**
  - [ ] `TelemetryConfig` gains `instance_id: String`, `deployment_env: String`,
        `file_sink_enabled: bool`, each with a default (`instance_id` defaults to empty, populated
        by the binary from `hostname::get` fallback; `deployment_env` defaults to `"dev"`;
        `file_sink_enabled` defaults to `false`).
  - [ ] `init_tracing` builds the `Resource` with:
        `service.name=rvc`, `service.version`, `network.name`, `service.instance.id`,
        `deployment.environment`.
  - [ ] Sampler construction unchanged:
        `Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sample_rate)))`.
  - [ ] At the end of `init_tracing`, a single `tracing::info!(target: "telemetry.init", ...)`
        fires with fields: `sample_rate`, `exporter = ?config.exporter`,
        `endpoint = %RedactedUrl(&config.endpoint)`, `file_sink_active = config.file_sink_enabled`,
        message `"telemetry pipeline initialized"`.
  - [ ] Architecture §2.5 pseudocode is realized line-for-line.
- **Tests:**
  - `crates/telemetry/src/init.rs::tests::resource_contains_instance_id_and_env` — build a
    provider with populated `instance_id` / `deployment_env`, query the `Resource`, assert both
    keys are present with the provided values. (Use
    `SdkTracerProvider::resource` via whatever public accessor is available; if only the
    builder-side is introspectable, wire a unit that asserts the `KeyValue` list passed into
    `Resource::builder` includes both keys.)
  - `crates/telemetry/src/init.rs::tests::emits_startup_banner` — install a `TestTracingGuard`,
    call `init_tracing` with an endpoint containing user-info
    (`http://user:pass@host:4318`); assert one event at level `info!` with target
    `telemetry.init` whose `endpoint` field renders as `http://***:***@host:4318`.
  - `crates/telemetry/src/init.rs::tests::sampler_remains_parent_based` — existing valid-config
    test extended to assert the sampler type chain is ParentBased(TraceIdRatioBased). May require
    introspection via exposing a `built_sampler_kind()` helper if the SDK doesn't expose sampler
    identity directly; otherwise rely on a smoke test that sampling behavior matches ratio.
- **Non-goals:**
  - Wiring `bin/rvc` to populate `instance_id` from `hostname::get` (Phase 8 issue).
  - Changing the head sampler to anything other than `ParentBased(TraceIdRatioBased)`. The
    "always export errors" rule lives in the OTel Collector tail-sampling (architecture §5), not
    here.

---

## Issue 1.5: Add `LogFormat::{Text, Json}` field to `FileAppenderConfig`

- **Points:** 2
- **Depends on:** none (independent from 1.1–1.4)
- **Files touched:**
  - `crates/telemetry/src/file_appender.rs` (assumed — if the file lives in a differently named
    module today, use whichever module owns `FileAppenderConfig` in `crates/telemetry/src/`)
  - `crates/telemetry/Cargo.toml` (enable `tracing-subscriber` `"json"` feature — architecture
    §1.4 calls this an already-present dep gaining a feature, not a new dep)
- **Summary:** Add a `format: LogFormat` selector on `FileAppenderConfig`. `LogFormat::Text` stays
  default for dev/test; `LogFormat::Json` is opt-in. `create_file_layer` picks
  `fmt::layer().json()` when Json is selected. Supports the PRD Gate §5 "JSON default for prod
  file sink" decision; `bin/rvc` wires the env/CLI knob in Phase 6.
- **Acceptance criteria:**
  - [ ] Public `pub enum LogFormat { Text, Json }` with
        `#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]`.
  - [ ] `FileAppenderConfig` gains `pub format: LogFormat` with a default of `LogFormat::Text`.
  - [ ] `create_file_layer` uses `fmt::layer().json()` (with `with_ansi(false)` retained) when
        `format == Json`; otherwise the existing text layer is returned untouched.
  - [ ] `tracing-subscriber` feature `"json"` is enabled in `crates/telemetry/Cargo.toml` (or the
        workspace root — whichever spot the dep is defined).
  - [ ] Public API is source-compatible: callers who do not set `format` still compile
        (via `Default`).
- **Tests:**
  - `crates/telemetry/src/file_appender.rs::tests::default_format_is_text` — default config has
    `format == LogFormat::Text`.
  - `crates/telemetry/src/file_appender.rs::tests::json_format_selects_json_layer` — write a
    temp-file appender with `LogFormat::Json`, emit one `info!` with fields, read the file back,
    assert the line parses as JSON (`serde_json::from_str::<Value>(line).is_ok()`) and contains
    the expected field keys.
  - `crates/telemetry/src/file_appender.rs::tests::text_format_remains_human_readable` —
    mirror test for `LogFormat::Text` asserts the line parses as plain text (does not start with
    `{`).
- **Non-goals:**
  - `RVC_LOG_FORMAT` env variable or `--log-format` CLI flag in `bin/rvc` (Phase 6 issue).
  - Feature-gating the `LogFormat::Json` variant behind a cargo feature — it rides on the
    `tracing-subscriber` feature flip, not a new one.

---

## Issue 1.6: Add workspace dev-deps (`walkdir`, `regex`) for Phase 3 ratchet

- **Points:** 1
- **Depends on:** none
- **Files touched:**
  - `Cargo.toml` (workspace root — add `walkdir = "2"` and `regex = "1"` under
    `[workspace.dev-dependencies]` — architecture §1.4 justifies these as dev-only)
- **Summary:** Land the two dev-deps that Phase 3's forbidden-pattern test needs, so Phase 3 can
  start without a dep-bump PR. Both are dev-only; runtime crates gain nothing.
- **Acceptance criteria:**
  - [ ] `[workspace.dev-dependencies]` (or `[workspace.dependencies]` with `dev = true` pattern
        matching the existing layout) includes `walkdir = "2"` and `regex = "1"`.
  - [ ] `cargo tree -e dev -i walkdir` and `cargo tree -e dev -i regex` both show only
        `tests/forbidden_log_patterns.rs`-reachable paths (or nothing until Phase 3 lands).
  - [ ] `cargo build --workspace` and `cargo check --workspace` still succeed.
  - [ ] `cargo build --workspace --release` has no change in the runtime dep graph (check with
        `cargo tree -e no-dev -i walkdir`: empty).
- **Tests:**
  - No test of its own. Phase 3 Issue 3.1 consumes these deps and gates green.
- **Non-goals:**
  - Writing the forbidden-pattern test itself (Phase 3).
  - Any other new workspace deps. PRD forbids casual dep additions.

---

## Issue 1.7: Verify `cargo test -p telemetry` and re-export surface

- **Points:** 1
- **Depends on:** 1.1, 1.2, 1.3, 1.4, 1.5
- **Files touched:**
  - `crates/telemetry/src/lib.rs` (final re-export block — copy architecture §1.1 verbatim and
    assert no missing exports)
- **Summary:** Close-out verification so downstream phases have a known-green baseline. No new
  logic; this issue exists to gate the phase exit criteria.
- **Acceptance criteria:**
  - [ ] `cargo test -p telemetry` passes on `cargo test -p telemetry --all-targets`.
  - [ ] `cargo fmt --check` and `cargo clippy -p telemetry -- -D warnings` are clean.
  - [ ] `cargo doc -p telemetry --no-deps` builds without warnings.
  - [ ] The following symbols all resolve from an external consumer (quick grep in
        `crates/telemetry/src/lib.rs` — no new file needed):
        `telemetry::TruncatedPubkey`, `telemetry::TruncatedPubkeyBytes`,
        `telemetry::TruncatedSignature`, `telemetry::RedactedUrl`, `telemetry::RedactedKeystore`,
        `telemetry::RedactedSecret`, `telemetry::TestTracingGuard`, `telemetry::test_capture`,
        `telemetry::TraceContextInterceptor`, `telemetry::inject_trace_context`,
        `telemetry::inject_trace_context_grpc`, `telemetry::extract_trace_context_grpc`,
        `telemetry::attach_server_parent`.
- **Tests:**
  - `crates/telemetry/tests/reexports.rs` (new) — a smoke integration test with one `use
    telemetry::{...};` line per symbol listed above. If any re-export is missing, the test file
    fails to compile.
- **Non-goals:**
  - Any new behavior. This is a gate.
