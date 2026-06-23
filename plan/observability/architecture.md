# Software Architecture: Logging & Tracing Enhancement Initiative

## Overview

This architecture retrofits the rs-vc workspace (23 crates, 3 binaries) to a uniform observability
standard built on the existing `tracing` / `tracing-opentelemetry` / `tracing-appender` /
`logroller` stack. No framework swap; no new workspace top-level deps (one dev-dep pair called
out). All new helpers land in `crates/telemetry`; `crates/crypto/src/logging.rs` becomes a thin
re-export during transition, and `bls.rs` Debug impls are fixed to stop leaking full-hex
`Signature` / `PublicKey`. rs-vc stays on `ParentBased(TraceIdRatioBased)` head sampling; the
"always export errors" rule moves to the OTel Collector tail-sampling processor.

Guiding principles: single canonical home for redaction and test helpers; dual attribution
(`rvc.*` for business-level correlation + OTel semconv for backend search); deferred-field pattern
(`Span::record`) for outcome/duration; `skip_all` mandatory; fresh root per iteration for
long-running loops.

## Architecture Principles

- **Single canonical home** — all redaction, test-capture, and propagation helpers live in
  `crates/telemetry`. `crypto::logging` re-exports during transition, then the file is removed.
- **Dual attribution on every external I/O span** — `rvc.*` for domain search + OTel semconv
  (`rpc.*`, `http.*`, `server.*`, `error.type`) for backend compat (Jaeger / Tempo / Grafana).
- **Deferred fields via `Span::record`** — `rvc.outcome`, `rvc.duration_ms` declared as empty at
  entry, recorded at close. No `err` / `ret` on `#[instrument]` — they force Debug formatting and
  return-value logging.
- **`skip_all` is mandatory** — every `#[instrument]` uses `skip_all` + explicit `fields(...)`.
  Zero-alloc when the level is disabled.
- **Fresh root per iteration** for long-running loops (doppelganger 2-epoch monitor, SSE stream).
  BatchSpanProcessor only exports on span close; a long-lived parent loses the whole trace on
  crash.
- **No secrets in logs, ever** — enforced at source by a regex-based workspace integration test
  with an opt-in allowlist comment.

---

## 1. Module Topology

### 1.1 New / changed modules in `crates/telemetry/src/`

| Path | Status | Purpose |
|---|---|---|
| `redact.rs` | **new** | Canonical home for `TruncatedPubkey`, `TruncatedSignature`, `RedactedUrl`, `RedactedKeystore`, `RedactedSecret`. Formatters with custom `Display` + `Debug` impls. |
| `test_capture.rs` | **new** | `TestTracingGuard` + `CaptureLayer` + `SpanTreeFormatter`. Thread-local subscriber via `tracing::subscriber::set_default`. Print-on-drop only when `std::thread::panicking()`. |
| `propagation.rs` | **updated** | Keep existing `inject_trace_context` (reqwest). Add `MetadataInjector`, `MetadataExtractor`, `inject_trace_context_grpc`, `extract_trace_context_grpc`, plus a `TraceContextInterceptor` (tonic client) and an `attach_server_parent` helper (server-side extraction — NOT an `Interceptor`; see §2.4). |
| `init.rs` | **updated** | Add `service.instance.id`, `deployment.environment` resource attributes (P1-3). Sampler stays `ParentBased(TraceIdRatioBased)`. Log once on startup: sampler ratio, exporter kind, endpoint, file-sink status (P0-8 observability-of-observability). |
| `file_appender.rs` | **updated** | Add `format: TextOrJson` field to `FileAppenderConfig`. JSON default for prod; text for tests/dev. Env knob: `RVC_LOG_FORMAT=json|text` (CLI flag wins). |
| `lib.rs` | **updated** | Re-exports block below. |

**Exact `lib.rs` re-export block** (add below existing re-exports):

```rust
pub mod redact;
pub mod test_capture;

pub use redact::{
    RedactedKeystore, RedactedSecret, RedactedUrl, TruncatedPubkey, TruncatedPubkeyBytes,
    TruncatedSignature,
};
pub use test_capture::{test_capture, TestTracingGuard};
pub use propagation::{
    attach_server_parent, extract_trace_context_grpc, inject_trace_context,
    inject_trace_context_grpc, TraceContextInterceptor,
};
```

### 1.2 Changes to `crates/crypto/`

- `crates/crypto/src/logging.rs` — **shrink to re-exports** during transition:
  ```rust
  pub use telemetry::{RedactedUrl, TruncatedPubkey};
  ```
  File is marked `#[deprecated(note = "import from telemetry directly")]` at the module level and
  removed in Phase 5.
- `crates/crypto/src/bls.rs` — **Debug impl fixes (security bug)**:
  - `impl fmt::Debug for PublicKey` → prints `PublicKey({})` using `TruncatedPubkey::new(&hex)`.
  - `impl fmt::Debug for Signature` → prints `Signature({})` using
    `TruncatedSignature::from_bytes(&self.to_bytes())`.
  - `Display` impls unchanged (explicit full-hex remains available via `%`; accidental `?` no
    longer leaks full material).
- `crates/crypto/Cargo.toml` — `telemetry` added as a normal dependency (already a tree-neighbour
  via eth-types; check cycle is clean — `telemetry` depends on nothing in `crypto`, so OK).

### 1.3 New files at workspace root

- `tests/forbidden_log_patterns.rs` — integration test; walkdir + regex + allowlist parser.
- `docs/observability.md` — conventions document (P0-1). Single canonical location.

### 1.4 New workspace dev-dependencies (explicit, justified)

Called out because PRD bars casual deps:

- `walkdir = "2"` — dev-dep for `tests/forbidden_log_patterns.rs`. ~300 LOC std-only equivalent
  would be brittle across symlinks and hidden dirs. Dev-dep only; no runtime impact.
- `regex = "1"` — dev-dep for the same test. Regex-over-source is the researcher-recommended
  approach (~100 LOC vs ~400 LOC for `syn`; 50× faster per run). Dev-dep only.

Both pinned to the workspace `dev-dependencies` section; no runtime crates gain them.

One runtime-adjacent dep change: `tracing-subscriber` must gain the `"json"` feature (currently
featureless in workspace Cargo.toml). Required by `fmt::layer().json()` inside the updated
`file_appender.rs`. This is a feature flip on an already-present dep — not a new dep — and is the
minimum change to satisfy the PRD-Gate-ratified "JSON default for prod file sink" decision.

### 1.5 Per-crate retrofit matrix

Covers every entry in the workspace `members` list. Column "Retrofit" is the mechanical change set
the estimator turns into issues. "No change" means nothing to do in this initiative.

| Crate | Retrofit scope |
|---|---|
| `bin/rvc` | Init telemetry with new resource attrs (P1-3); add CLI flag for `RVC_LOG_FORMAT`; log startup observability status (§init.rs bullet). Verify `process_slot` root span already exists; adopt slot-tick event (P1-4). |
| `bin/rvc-keygen` | `#[instrument]` on each subcommand entry (`new_mnemonic::run`, `existing_mnemonic::run`, `bls_to_execution::run`, `exit::run`). Add `rvc.keygen.operation` field. Thin logging; not hot-path. |
| `bin/rvc-signer` | Tonic server: add tower `Layer` on `Server::builder().layer(...)` that calls `attach_server_parent` inside each handler (see §2.4). Instrument `backend::basic::sign`, `backend::dvt::sign`, `service::SignerService::sign/list_public_keys/get_status` as server-side root spans. Audit log fields: drop `signing_root` full-hex → short-form via `%TruncatedPubkeyBytes(&req.signing_root)` (it's a 32-byte hash, not a BLS sig); use `TruncatedPubkey` for `pubkey`; `TruncatedSignature::from_bytes` on any 96-byte BLS response bytes. |
| `crates/rvc` | `#[instrument]` on all `pub(crate) async fn` in `orchestrator/{attestation,aggregation,sync_committee,duty_management,coordinator,utils}.rs` per P0-4. Unify duty root span names to §3 table. Fresh-root pattern for doppelganger driver in `doppelganger_adapter.rs`. |
| `crates/beacon` | Client already has 10 `#[instrument]` sites; audit each endpoint wrapper for the `http.*` + `server.*` dual-attribution fields (§3). Add `rvc.beacon.endpoint_name`, `rvc.bn_endpoint` (redacted), `rvc.outcome`, `rvc.duration_ms`. |
| `crates/bn-manager` | Add spans in `manager.rs` (failover attempt), `sse.rs` (one fresh root per SSE event + `rvc.sse.stream_id`), `health.rs` (probe outcomes), `sync_status.rs`. All failover attempts carry `rvc.bn_endpoint`, `rvc.outcome`. |
| `crates/builder` | `#[instrument]` on `register_validators`, `prepare_proposers`, and any retry helper. Jitter sleep is a sibling span. |
| `crates/doppelganger` | Rewrite `service.rs` monitor loop to fresh-root-per-epoch pattern (§6). `rvc.doppelganger.check_epoch` root span + `rvc.monitor.instance_id` field. |
| `crates/eth-types` | **No change.** Pure data crate; PRD explicitly exempts. |
| `crates/crypto` | Debug-impl fixes (§1.2). Logging re-exports. `remote_signer.rs`: instrument HTTP call with `http.*` fields + `rvc.signer.operation` for Web3Signer. `signing.rs` / `block_signing.rs` / `sync_signing.rs` / `aggregation_signing.rs` / `voluntary_exit_signing.rs` / `builder_signing.rs`: already instrumented (~11 sites); verify `skip_all` on every one. |
| `crates/grpc-signer` | Client: add `TraceContextInterceptor` to the channel (§2.4). Instrument `GrpcRemoteSigner::sign_*` calls with dual-attribution `rpc.*` fields. Server handlers live in `bin/rvc-signer`. |
| `crates/keymanager-api` | Instrument every handler in `handlers.rs` (8+ handlers: import/list/delete keystores + remotekeys + slashing protection export). Root span name `rvc.keymanager.{handler}`. Add request id (P2-2 backlog). |
| `crates/metrics` | **No change beyond a single line** in the `/metrics` and `/healthz` handlers if they need a span at all — they're low-value and noisy. Skip instrumentation here; only the MetricsServer startup line logs once at `info`. |
| `crates/propagator` | `#[instrument]` on `submit_attestations`, `submit_aggregate_attestations`. `rvc.propagator.*` root span per submit call. `rvc.outcome` recorded at close. |
| `crates/secret-provider` | `gcp.rs`: already has 2 `#[instrument]` sites; verify and add `rvc.secret_provider.*` on list/fetch. `key_source_manager.rs`: retain the existing hierarchical span pattern (tests cover it). `format.rs`: no change. |
| `crates/signer` | `lib.rs`: 11 `#[instrument]` sites exist; verify all use `skip_all` and record `rvc.outcome` / `rvc.duration_ms`. `rvc.sign.{attestation,block,sync,aggregation,randao,voluntary_exit,builder}` root span names. `rvc.slashing.result` recorded after `check_and_record_*`. |
| `crates/slashing` | `db.rs`: 5 `#[instrument]` sites exist; add `rvc.slashing.result` + relevant watermark fields (source/target epoch on attestation reject; slot+signing_root on block reject). Pruning span records `rvc.duration_ms` + row counts. Integrity check → `info!` on pass, `error!` on fail. |
| `crates/sync-service` | `lib.rs` has 2 `#[instrument]` sites. Confirm coverage on `produce_sync_messages`, `produce_contributions`, `compute_selection_proof`. Add `rvc.sync.subnet` field where applicable. |
| `crates/block-service` | `service.rs` has 1 `#[instrument]` site — expand to all `pub async fn` on `BlockService`. Root span `rvc.block.propose`; child `rvc.block.{sign_randao,produce_block,sign_block,publish}`. |
| `crates/duty-tracker` | `tracker.rs` has 6 `#[instrument]` sites; verify and fill gaps on `fetch_*`, `check_and_refetch_*`, `evict_*`. All carry `rvc.epoch` / `rvc.committee_period`. |
| `crates/validator-store` | `store.rs` has 4 `#[instrument]` sites; extend to `reload_config` with parse-first/apply-second `info!` per stage. Override-application logs carry the validator short-form pubkey. |
| `crates/timing` | **No change.** Pure slot-clock; no logging surface. (Slot-tick event P1-4 fires in the orchestrator loop, not here.) |
| `crates/telemetry` | The helper work itself (§1.1). |

---

## 2. Public API Surface of New Helpers

### 2.1 `crates/telemetry/src/redact.rs`

```rust
//! Redaction formatters. All types implement `Display` (zero-alloc when tracing
//! level is disabled) and `Debug` (same output). No `Copy`; `Clone` on the
//! non-borrowing newtypes only.

/// `0x{first10}...{last8}` when the hex body is longer than 18 chars; otherwise
/// prints the raw hex with a `0x` prefix. Input may be with or without `0x`.
/// (Unchanged format from the existing `crypto::logging::TruncatedPubkey`.)
pub struct TruncatedPubkey<'a>(pub &'a str);
impl<'a> TruncatedPubkey<'a> {
    pub fn new(hex: &'a str) -> Self;
}
impl std::fmt::Display for TruncatedPubkey<'_> { /* ... */ }
impl std::fmt::Debug for TruncatedPubkey<'_> { /* delegate to Display */ }

/// Byte-array convenience: accepts a `&[u8]` (e.g. BLS pubkey bytes) and
/// hex-encodes on the fly. Used by `bls.rs` Debug impl.
pub struct TruncatedPubkeyBytes<'a>(pub &'a [u8]);
impl std::fmt::Display for TruncatedPubkeyBytes<'_> { /* 0x{first10}...{last8} */ }

/// `0x{first8}...{last8}` of a BLS signature (192 hex chars → 0x + 8 + ... + 8).
/// Constructor accepts either a 96-byte `&[u8]` or a hex string. Produces
/// the same output shape either way.
pub struct TruncatedSignature<'a>(&'a [u8]);
impl<'a> TruncatedSignature<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self;
}
impl std::fmt::Display for TruncatedSignature<'_> { /* ... */ }
impl std::fmt::Debug for TruncatedSignature<'_> { /* delegate */ }

/// URL with userinfo (user + password) replaced by `***:***@`. Path and
/// query are left intact. If parsing fails, displays the raw string.
/// (Unchanged from existing `crypto::logging::RedactedUrl`; scope pinned here
/// explicitly: userinfo-only — no query-param scrubbing in this initiative.)
pub struct RedactedUrl<'a>(pub &'a str);
impl std::fmt::Display for RedactedUrl<'_> { /* ... */ }
impl std::fmt::Debug for RedactedUrl<'_> { /* delegate */ }

/// EIP-2335 keystore summary: prints `Keystore{version, crypto.kdf.function,
/// uuid, pubkey=TruncatedPubkey}`. Never prints ciphertext bytes.
pub struct RedactedKeystore<'a> {
    pub version: u32,
    pub kdf: &'a str,           // e.g. "scrypt", "pbkdf2"
    pub uuid: &'a str,
    pub pubkey_hex: &'a str,
}
impl std::fmt::Display for RedactedKeystore<'_> { /* ... */ }
impl std::fmt::Debug for RedactedKeystore<'_> { /* delegate */ }

/// Unconditional `"<redacted>"`. Zero-alloc. For any field that must never
/// appear in logs regardless of shape (e.g. bearer token, decrypted key bytes).
pub struct RedactedSecret;
impl std::fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}
impl std::fmt::Debug for RedactedSecret { /* same output */ }
```

Formatting rules table:

| Helper | Exact output (input → output) |
|---|---|
| `TruncatedPubkey` | `0x93247f2209abcacf...611df74a` → `0x93247f2209...611df74a` |
| `TruncatedSignature::from_bytes(&[..])` | 96-byte BLS sig → `0x{first8_hex}...{last8_hex}` |
| `RedactedUrl` | `http://user:pass@host:4318/p?q=1` → `http://***:***@host:4318/p?q=1` |
| `RedactedKeystore` | `Keystore{ver=4, kdf=scrypt, uuid=abc-..., pubkey=0x9324...df74a}` |
| `RedactedSecret` | always `<redacted>` |

### 2.2 `crates/telemetry/src/test_capture.rs`

```rust
use std::sync::{Arc, Mutex};
use tracing::subscriber::DefaultGuard;
use tracing::{Level, Metadata};

/// Captured snapshot of a span as observed by the CaptureLayer.
pub struct CapturedSpan {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub name: &'static str,
    pub target: &'static str,
    pub level: Level,
    pub fields: Vec<(&'static str, String)>, // recorded values including deferred Span::record
}

/// Captured snapshot of an event.
pub struct CapturedEvent {
    pub span_id: Option<u64>,
    pub level: Level,
    pub message: String,
    pub fields: Vec<(&'static str, String)>,
}

/// Thread-local RAII guard holding a capturing subscriber.
/// On drop during `std::thread::panicking()`, pretty-prints the captured
/// span tree via `println!` so cargo test surfaces it with the failure.
#[must_use = "dropping TestTracingGuard ends capture"]
pub struct TestTracingGuard {
    buffer: Arc<Mutex<CaptureBuffer>>,
    _default: DefaultGuard,
}

impl TestTracingGuard {
    /// Query helpers for assertions in tests.
    pub fn spans_named(&self, name: &str) -> Vec<CapturedSpan>;
    pub fn events_at(&self, level: Level) -> Vec<CapturedEvent>;
    pub fn assert_child_of(&self, child_name: &str, parent_name: &str);
    /// Returns the recorded value of a named field on the first span matching
    /// `span_name`, or `None`. Clones out of the internal `Mutex<...>`; do not
    /// try to borrow — the lock cannot outlive the call.
    pub fn field_on_span(&self, span_name: &str, field: &str) -> Option<String>;
    /// Pretty-print the span tree unconditionally (used by debug-on-demand,
    /// not on panic).
    pub fn dump(&self);
}

impl Drop for TestTracingGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            /* format via SpanTreeFormatter and println! */
        }
    }
}

/// Convenience constructor; preferred at the top of any test body.
/// ```
/// #[tokio::test]
/// async fn test_x() {
///     let _guard = telemetry::test_capture();
///     // ...
/// }
/// ```
pub fn test_capture() -> TestTracingGuard;
```

Implementation notes:
- Uses `tracing::subscriber::set_default(Registry::default().with(CaptureLayer::new(buf)))`.
  Thread-local, RAII — parallel `cargo test` threads do not collide.
- `CaptureLayer` implements `tracing_subscriber::Layer<S>`: `on_new_span` pushes a `CapturedSpan`
  with parent id taken from `ctx.lookup_current()`; `on_record` updates the same entry; `on_event`
  pushes a `CapturedEvent`; `on_close` is a no-op (retain span for drop-time dump).
- `SpanTreeFormatter` walks the parent-id graph and emits indented output in the shape shown in
  the PRD "Good test failure output" example.
- Zero new workspace deps. All internal.

### 2.3 Forbidden-pattern test — `tests/forbidden_log_patterns.rs`

```rust
// Single #[test] entrypoint. No subtests — the test prints all violations and
// fails once if any remain.
#[test]
fn forbidden_log_patterns_workspace_clean() {
    let violations = scan_workspace();
    if !violations.is_empty() {
        for v in &violations {
            eprintln!("{}:{}: {}", v.file.display(), v.line, v.rule);
        }
        panic!("{} forbidden log pattern(s) detected", violations.len());
    }
}

struct Violation {
    file: std::path::PathBuf,
    line: usize,
    rule: &'static str, // rule name (e.g. "BAD_FIELD", "BAD_SIG_DEBUG")
}

fn scan_workspace() -> Vec<Violation>;
fn is_allowlisted(source: &str, match_offset: usize) -> bool;
```

Regex set (verbatim, from research — do not modify without review):

| Name | Pattern |
|---|---|
| `BAD_FIELD` | `(?m)^[^/]*\btracing::(?:info\|debug\|warn\|error\|trace)!\([^)]*\b(?:secret\|sk\|private_key\|mnemonic\|passphrase\|password)\b` |
| `BAD_FMT` | `(?m)tracing::(?:info\|debug\|warn\|error\|trace)!\([^)]*\{(?:secret\|sk\|private_key\|mnemonic\|passphrase\|password)(?:[:?][^}]*)?\}` |
| `BAD_ZEROIZING` | `(?m)tracing::(?:info\|debug\|warn\|error\|trace)!\([^)]*\bZeroizing\b` |
| `BAD_SIG_DEBUG` | `(?m)tracing::(?:info\|debug\|warn\|error\|trace)!\([^)]*\?(?:sig\|signature)\b` |
| `INSTRUMENT_NO_SKIPALL` | `(?m)#\[tracing::instrument\([^)]*\)\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[a-zA-Z_0-9]+\s*(?:<[^>]*>)?\s*\([^)]*\b(?:SecretKey\|SecretString\|Zeroizing\|Mnemonic\|SignRequest\|SigningRequest)\b` (fails if match exists AND the attribute body does NOT contain `skip_all`) |
| `BAD_GLOBAL_DEFAULT` | `(?m)tracing::subscriber::set_global_default` under `#[cfg(test)]` or `tests/` paths |

Allowlist syntax (line directly above the offending line):
```
// observability: allow <free-text reason>
tracing::debug!("exercising error path: {secret}");
```
The scanner requires a non-empty reason after the marker; absent, the allowlist doesn't apply.

Exclusions: `target/`, `tests/conformance/`, `plan/`, `docs/`, generated proto files (`OUT_DIR`),
and the pattern regex literals inside this test file itself (test file is explicitly skipped).

### 2.4 `crates/telemetry/src/propagation.rs` (tonic additions)

```rust
use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::service::Interceptor;
use tonic::{Request, Status};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub struct MetadataInjector<'a>(pub &'a mut MetadataMap);
impl Injector for MetadataInjector<'_> { /* ~10 LOC, research spec */ }

pub struct MetadataExtractor<'a>(pub &'a MetadataMap);
impl Extractor for MetadataExtractor<'_> { /* ~10 LOC, research spec */ }

/// Client-side injector callable from a handler body.
pub fn inject_trace_context_grpc<T>(req: &mut Request<T>);

/// Server-side extractor: call at the top of every tonic service method
/// BEFORE creating the handler span, then `span.set_parent(ctx)` on the
/// span that will wrap the handler body.
pub fn extract_trace_context_grpc<T>(req: &Request<T>) -> opentelemetry::Context;

/// Convenience for server handlers that already have a `tracing::Span` open:
/// attach the incoming parent (if any) to the current span.
pub fn attach_server_parent<T>(req: &Request<T>);

/// Tonic client interceptor. Install via
/// `tonic::service::interceptor(TraceContextInterceptor::default())` on the
/// channel or via `InterceptedService::new(channel, TraceContextInterceptor)`.
#[derive(Clone, Default)]
pub struct TraceContextInterceptor;
impl Interceptor for TraceContextInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        inject_trace_context_grpc(&mut req);
        Ok(req)
    }
}
```

**Server side is NOT an `Interceptor`.** `tonic::service::Interceptor` is for mutating outgoing
client requests. On the server, either (a) call `attach_server_parent(&request)` inside each
handler method right after entering the method-level span, or (b) add a tower `Layer` on
`Server::builder().layer(...)` that wraps the service with an extractor. Option (a) is simpler,
matches the research sketch, and is what `bin/rvc-signer` will adopt per §1.5.

### 2.5 `crates/telemetry/src/init.rs` updates (pseudocode)

```rust
let resource = Resource::builder()
    .with_service_name(SERVICE_NAME)
    .with_attributes([
        KeyValue::new("service.version", version),
        KeyValue::new("network.name", config.network.clone()),
        // NEW (P1-3):
        KeyValue::new("service.instance.id", config.instance_id.clone()),       // hostname or configured
        KeyValue::new("deployment.environment", config.deployment_env.clone()), // "prod"/"staging"/"dev"
    ])
    .build();

// Sampler UNCHANGED — head-based parent-ratio:
let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sample_rate)));
// Error always-sampling is implemented in the OTel Collector — see §5.

// Observability-of-observability (one info! on startup):
tracing::info!(
    target: "telemetry.init",
    sample_rate = config.sample_rate,
    exporter = ?config.exporter,
    endpoint = %RedactedUrl(&config.endpoint),
    file_sink_active = config.file_sink_enabled,
    "telemetry pipeline initialized"
);
```

`TelemetryConfig` gains `instance_id: String`, `deployment_env: String`, and a bool that reflects
whether the file sink is wired (set by the binary after calling `create_file_layer`).

### 2.6 `FileAppenderConfig` format selector

```rust
pub enum LogFormat { Text, Json }
// default: Text for dev/test, Json set by binary from env:RVC_LOG_FORMAT or CLI --log-format.

pub struct FileAppenderConfig {
    pub directory: String,
    pub filename: String,
    pub max_size_mb: u64,
    pub max_files: usize,
    pub compress: bool,
    pub level: String,
    pub format: LogFormat, // NEW
}
```

`create_file_layer` selects `fmt::layer().json()` when `format == Json`, else the existing text
layer. `with_ansi(false)` remains on text-file output.

---

## 3. Span Hierarchy & Field Standard

Every root span sets the entry fields at creation via `fields(...)`; deferred fields (`rvc.outcome`,
`rvc.duration_ms`, `error.type`) are declared empty and populated via `Span::current().record(...)`
at close. Every root span is `info` level unless noted. All spans use `skip_all`. Sub-operation
spans (signing internals, single-validator iteration) are `debug` level. Child spans inherit the
parent unless the parent is the slot-root (`rvc.orchestrator.process_slot`).

| Duty family | Root span | Entry fields | Deferred fields | Expected children | Level | OTel co-attach |
|---|---|---|---|---|---|---|
| Attestation | `rvc.attestation.produce` | `rvc.slot`, `rvc.validator_index`, `rvc.pubkey`, `rvc.operation="attestation"` | `rvc.outcome`, `rvc.duration_ms`, `rvc.slashing.result`, `error.type` | `rvc.sign.attestation`, `rvc.propagator.submit_attestations` | `info` | `otel.kind="internal"` |
| Block proposal | `rvc.block.propose` | `rvc.slot`, `rvc.validator_index`, `rvc.pubkey`, `rvc.block.blinded` (bool), `rvc.operation="block"` | `rvc.outcome`, `rvc.duration_ms`, `rvc.block.slot`, `rvc.slashing.result`, `error.type` | `rvc.sign.randao`, `rvc.beacon.produce_block`, `rvc.sign.block`, `rvc.beacon.publish_block` | `info` | `otel.kind="internal"` |
| Sync committee msg | `rvc.sync.message` | `rvc.slot`, `rvc.validator_index`, `rvc.pubkey`, `rvc.operation="sync_message"` | `rvc.outcome`, `rvc.duration_ms`, `error.type` | `rvc.sign.sync_message`, `rvc.beacon.submit_sync_messages` | `info` | — |
| Sync contribution | `rvc.sync.contribution` | `rvc.slot`, `rvc.validator_index`, `rvc.pubkey`, `rvc.sync.subnet`, `rvc.operation="sync_contribution"` | `rvc.outcome`, `rvc.duration_ms`, `error.type` | `rvc.sign.selection_proof`, `rvc.sign.contribution`, `rvc.beacon.submit_contributions` | `info` | — |
| Aggregation | `rvc.aggregation.produce` | `rvc.slot`, `rvc.validator_index`, `rvc.pubkey`, `rvc.committee_index`, `rvc.operation="aggregate"` | `rvc.outcome`, `rvc.duration_ms`, `error.type` | `rvc.sign.selection_proof`, `rvc.sign.aggregate`, `rvc.propagator.submit_aggregate` | `info` | — |
| Propagation | `rvc.propagator.submit_attestations` (+ `..submit_aggregate_attestations`) | `rvc.slot`, `rvc.count` (attestations submitted) | `rvc.outcome`, `rvc.duration_ms`, `rvc.bn_endpoint`, `error.type` | one child `rvc.beacon.submit_*` per BN attempt | `info` | `otel.kind="internal"` |
| Duty fetch | `rvc.duty.fetch_attester` / `rvc.duty.fetch_proposer` / `rvc.duty.fetch_sync` | `rvc.epoch` (or `rvc.committee_period`), `rvc.operation` | `rvc.outcome`, `rvc.duration_ms`, `rvc.count`, `rvc.duty.dependent_root` (trunc), `error.type` | `rvc.beacon.get_*_duties` | `info` | `otel.kind="client"` on child |
| Doppelganger monitor | `rvc.doppelganger.check_epoch` (fresh root per epoch — §6) | `rvc.monitor.instance_id`, `rvc.epoch`, `rvc.operation="doppelganger_check"` (parent: None) | `rvc.outcome`, `rvc.duration_ms`, `rvc.doppelganger.detected` (bool), `error.type` | per-pubkey debug child span | `info` | `otel.kind="internal"` |
| SSE event stream | `rvc.bn_manager.sse_event` (fresh root per event — §6) | `rvc.sse.event_type`, `rvc.sse.stream_id`, `rvc.bn_endpoint` (parent: None) | `rvc.outcome`, `rvc.duration_ms`, `error.type` | `rvc.bn_manager.handle_head` / `..handle_reorg` / `..handle_finalized` / `..handle_block` | `info` | `otel.kind="consumer"` |
| Signer request (gRPC client) | `rvc.signer.sign_{attestation\|block\|sync\|...}` | `rvc.signer.operation`, `rvc.signer_endpoint` (redacted), `rvc.pubkey` | `rvc.outcome`, `rvc.duration_ms`, `rpc.response.status_code`, `error.type` | — | `info` | `otel.kind="client"`, `rpc.system.name="grpc"`, `rpc.method`, `server.address`, `server.port` |
| Beacon client request | `rvc.beacon.{verb}` (e.g. `rvc.beacon.get_attester_duties`) | `rvc.beacon.endpoint_name`, `rvc.bn_endpoint` (redacted) | `rvc.outcome`, `rvc.duration_ms`, `http.response.status_code`, `http.request.resend_count`, `error.type` | — | `debug` (root for isolated probes; `info` elevated on failover attempts) | `otel.kind="client"`, `http.request.method`, `url.full=%RedactedUrl`, `server.address`, `server.port` |
| Keymanager-API request | `rvc.keymanager.{handler}` (e.g. `rvc.keymanager.import_keystores`) | `rvc.keymanager.caller_kind` (`"keystore"` or `"remotekey"`), `rvc.keymanager.request_id` (if provided via `x-request-id`) | `rvc.outcome`, `rvc.duration_ms`, `rvc.keymanager.count_accepted`, `rvc.keymanager.count_rejected`, `error.type` | Sub-calls into signer/slashing emit their own children | `info` | `otel.kind="server"`, `http.request.method`, `http.route` |
| Slashing DB write | `rvc.slashing.check_attestation` / `..check_block` | `rvc.validator_index`, `rvc.pubkey`, for attestations: `rvc.slashing.source_epoch`, `rvc.slashing.target_epoch`; for blocks: `rvc.slot`, `rvc.slashing.signing_root` (trunc) | `rvc.outcome`, `rvc.duration_ms`, `rvc.slashing.result` | — | `info` | `db.system="sqlite"` |

Notes:
- `rvc.pubkey` is always `%TruncatedPubkey::new(&hex)` (short-form string).
- Any signature in a log line is always `%TruncatedSignature::from_bytes(&bytes)`.
- Any URL field is always `%RedactedUrl(&s)`.
- `error.type` is a short classifier (e.g. `"timeout"`, `"connection_refused"`, `"double_vote"`),
  NOT the full error message. The full error message goes in the log line text with
  `error = %e` (Display).
- `rvc.outcome` values are one of: `"success"`, `"rejected"`, `"error"`, `"timeout"`.

---

## 4. Level Policy (rs-vc-specific)

| Level | Emit when | Examples |
|---|---|---|
| `error!` | Duty outcome is `error` AND `rvc.outcome` records it; OR a data-loss risk is imminent (slashing DB write fail, integrity check fail, doppelganger detection → exit). Every `error!` MUST carry a correlation key (`rvc.pubkey`, `rvc.slot`, or `rvc.validator_index`) and `error = %e`. | slashing DB write fail; BLS sign produced unexpected bytes; doppelganger detected; all BN failover attempts exhausted. |
| `warn!` | Recoverable anomaly with retries engaged OR a policy-rejected request that is not a slashing fault. | BN failover from primary to secondary; HTTP 5xx with retry; slashing rejected a request (expected behavior — info on first-rule match, warn only if the request was unusual in shape); hot-reload parse succeeded but apply skipped validator overrides. |
| `info!` | Successful duty milestones (root-span close with `rvc.outcome=success`); state transitions (startup steps, keystore import success, doppelganger safe); one slot-tick per slot (P1-4). | `attestation signed and queued`, `block published`, `genesis validated`, `keystore imported`. |
| `debug!` | Sub-operation details: per-pubkey iteration when looping, signing request/response framing summaries, duty cache hit/miss. | `looking up validator index for pubkey=0x93...`, `cache hit for epoch=235350`, `partial signature received from peer index=2`. |
| `trace!` | Byte-level framing, decrypted-keystore hashing internals, per-iteration of aggregate bitfield. Reserved for the lowest-volume development-time diagnostics. Any `trace!` should be inert in prod (`RUST_LOG` never includes `trace` by default). | `ssz body length=4096 bytes`, `bitfield participation count=256`. |

Hard rules:
- `error = %e` (Display), never `error = ?e`.
- Never `?pubkey` / `?sig` / `?signature` — use the redaction helpers.
- `#[instrument]` never uses `err` or `ret` (Debug format + unbounded return logging).
- Spans at root level use `info`; sub-operation spans use `debug`. Exception: `rvc.beacon.*`
  child probes default to `debug` because one per HTTP call is noisy; failover attempts use `info`.
- No `ERROR` or `WARN` event may fire under a clean `cargo test --workspace` run (acceptance
  metric #6).

---

## 5. Collector Tail-Sampling Policy

`tail_sampling` runs in the OTel Collector (downstream of rs-vc) and evaluates trace sampling
decisions after spans have closed. rs-vc ships every span to the collector (subject to its head
sampler); the collector drops non-error traces according to ratio but always retains error-bearing
traces. `decision_wait` buffers spans long enough for typical duty operations to close (<10s
including sub-operation batches).

```yaml
# otel-collector-config.yaml excerpt — rs-vc recommended baseline.
processors:
  tail_sampling:
    # Wait up to 15s for all spans in a trace to arrive before deciding. Duty
    # operations commonly close in under 5s; 15s absorbs slow propagator paths.
    decision_wait: 15s
    num_traces: 50000
    expected_new_traces_per_sec: 500
    policies:
      # (1) Always keep traces with at least one error-outcome span.
      - name: rvc-outcome-error
        type: string_attribute
        string_attribute:
          key: rvc.outcome
          values: [error, timeout]
      # (2) Always keep traces where any span has status=Error.
      - name: span-status-error
        type: status_code
        status_code:
          status_codes: [ERROR]
      # (3) Probabilistic fallback for everything else. Ratio should mirror
      # the rs-vc head sampler (e.g. 0.10 if the VC head ratio is 1.0 and
      # we want 10% persisted; set to 1.0 if keeping everything).
      - name: probabilistic-baseline
        type: probabilistic
        probabilistic:
          sampling_percentage: 10
```

Sources:
- [OTel Collector Contrib — `tailsamplingprocessor`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor)
  — defines `status_code`, `string_attribute`, `probabilistic` policies.

---

## 6. Long-Running Span Shape — Decision

**Decision: fresh root span per iteration for both the 2-epoch doppelganger monitor and the SSE
event stream.** Iterations are correlated by an `rvc.monitor.instance_id` (doppelganger) /
`rvc.sse.stream_id` (SSE) UUID field that is the same across all iterations of one run, and are
secondarily linked via `tracing_opentelemetry::OpenTelemetrySpanExt::add_link` to the previous
iteration's `SpanContext` for trace-backend navigability.

Rationale (endorsing the researcher): `BatchSpanProcessor` exports spans only on close; a
long-lived parent span loses its entire trace on crash, and its children become orphans in the
backend. A fresh root per iteration exports cleanly on close, bounds trace size, survives restarts
without orphan spans, and interacts correctly with `ParentBased(TraceIdRatioBased)` sampling
(each iteration's sampling decision is independent). `FOLLOWS_FROM`/multi-parent rendering has
long-standing UI quirks in Jaeger that make SpanLinks a weaker correlation mechanism than a
filterable field — so `rvc.monitor.instance_id` is the primary log-reader correlation key;
SpanLinks are a secondary enhancement.

Concrete implementation shape for doppelganger:

```rust
// crates/doppelganger/src/service.rs
pub struct DoppelgangerService { /* ... */ instance_id: String }

impl DoppelgangerService {
    pub fn new(/* ... */) -> Self {
        Self { /* ... */, instance_id: uuid::Uuid::new_v4().to_string() }
    }

    async fn monitor(&self) -> Result<()> {
        let mut prev_ctx: Option<opentelemetry::trace::SpanContext> = None;
        for epoch in 0..2 {
            let span = tracing::info_span!(
                parent: None,
                "rvc.doppelganger.check_epoch",
                rvc.monitor.instance_id = %self.instance_id,
                rvc.epoch = epoch,
                rvc.operation = "doppelganger_check",
                rvc.outcome = tracing::field::Empty,
                rvc.duration_ms = tracing::field::Empty,
                rvc.doppelganger.detected = tracing::field::Empty,
            );
            if let Some(cx) = &prev_ctx {
                use tracing_opentelemetry::OpenTelemetrySpanExt;
                span.add_link(cx.clone());
            }

            let start = std::time::Instant::now();
            let result = async { /* liveness probes per pubkey */ }
                .instrument(span.clone())
                .await;

            let outcome = match &result { Ok(_) => "success", Err(_) => "error" };
            span.record("rvc.outcome", outcome);
            span.record("rvc.duration_ms", start.elapsed().as_millis() as u64);

            use tracing_opentelemetry::OpenTelemetrySpanExt;
            prev_ctx = Some(span.context().span().span_context().clone());
        }
        Ok(())
    }
}
```

SSE stream follows the same shape:
- `stream_id: String` is set once per BN connection (regenerated on reconnect).
- Each incoming SSE event opens a fresh root span `rvc.bn_manager.sse_event` with
  `parent: None`, `rvc.sse.event_type`, `rvc.sse.stream_id`, and dispatches to a child handler
  span (`rvc.bn_manager.handle_head`, etc.).
- Reconnection is its own fresh root span `rvc.bn_manager.sse_reconnect` recording
  `rvc.bn_endpoint`, `rvc.outcome`, `rvc.duration_ms`.

No `add_link` on SSE (events are independent work items; BN-side causal chain ends at emit).

---

## 7. Rollout Sequence (for the project-planner)

Each step produces a merge-able, green-on-CI unit. Steps are listed in the required dependency
order.

1. **Telemetry helpers land first.** `crates/telemetry/src/redact.rs`, `test_capture.rs`,
   updated `propagation.rs` (tonic additions), updated `init.rs` (new resource attrs + startup
   info log), updated `file_appender.rs` (format selector). New re-exports in `lib.rs`.
   Exit: `cargo test -p telemetry` green; unit tests for every formatter; round-trip test for
   `inject_trace_context_grpc` + `extract_trace_context_grpc`.
2. **Redaction promotion + crypto Debug fix.** `crates/crypto/src/logging.rs` becomes a
   re-export; `bls.rs` Debug impls switched to `TruncatedPubkey` / `TruncatedSignature`; audit all
   crates importing `crypto::logging` and flip to `telemetry::` (leave the re-export as a grace
   period). Exit: `cargo clippy --workspace` green; unit tests on Debug impls assert short-form
   output.
3. **Forbidden-pattern test lands green.** `tests/forbidden_log_patterns.rs` + dev-deps
   (`walkdir`, `regex`). Run against current tree — any real violation that surfaces is either
   fixed in the same PR or allowlisted with a reason. Exit: `cargo test forbidden` green;
   seeded-violation fixture test confirms detection.
4. **Hot-path `#[instrument]` retrofit + field standard.** Apply §3 to the P0-4 file list
   (`crates/rvc/src/orchestrator/*`, `block-service`, `sync-service`, `builder`, `signer`,
   `duty-tracker`, `propagator`). Async-trait methods fall back to `.instrument(info_span!(...))`
   inside the body when `#[instrument]` breaks `Send`. Exit: runbook walkthrough succeeds on a
   synthetic failure (PRD acceptance #1); tests assert root-span existence and mandatory fields.
5. **External I/O instrumentation + tonic interceptors.** Beacon client (`crates/beacon`),
   bn-manager (failover + SSE + health + sync_status), grpc-signer client + `bin/rvc-signer`
   server (tower `Layer` or per-handler `attach_server_parent`), `crypto::remote_signer`
   (Web3Signer HTTP), `secret-provider::gcp`, `keymanager-api::handlers`. All gain dual-
   attribution fields. End-to-end test exercises a traceparent round-trip through the gRPC link.
   Exit: for every client crate, one success test + one failure test assert the mandatory fields.
6. **Storage/safety-layer instrumentation.** `slashing::db` (watermark fields on reject,
   row-count on prune, integrity-check transition), `validator-store::store` (parse-first /
   apply-second), `doppelganger::service` (fresh-root-per-iteration rewrite + `instance_id`).
   Exit: slashing test suite asserts `rvc.slashing.result = "double_vote"` + source/target epochs
   surface in logs (PRD acceptance #P0-6).
7. **Test-harness retrofit.** Adopt `let _g = telemetry::test_capture();` in integration tests
   under `crates/rvc`, `crates/signer`, `crates/block-service`, `crates/sync-service`,
   `crates/propagator`, `crates/duty-tracker`, `crates/slashing`. One intentionally failing test
   demonstrates the span tree printed on panic. Exit: PRD acceptance #2 satisfied; no tests
   require `RUST_LOG` or `--nocapture` to be readable.
8. **Prod sink defaults + conventions doc publication + P1 polish.**
   `FileAppenderConfig` defaults reviewed and documented; `RVC_LOG_FORMAT` env + CLI flag wired
   in `bin/rvc`. `docs/observability.md` published and referenced from `CLAUDE.md`. Error-display
   audit (`P1-1`), metrics cross-reference notes (`P1-2`), resource attrs (`P1-3`), slot-tick
   event (`P1-4`). Exit: 3 MB log-write integration test confirms rotation+compression on a 1 MB
   cap; PRD acceptance #3 + #5 + #6 all green.

---

## 8. Risks & Open Items

- **Async-trait + `#[instrument]` Send-bound regressions** (PRD-acknowledged). The retrofit
  path tolerates per-method fallback to `.instrument(info_span!(...))`; estimator budgets this
  as a case-by-case overhead on each trait-method touched, not a universal overhead. If the
  percentage of fallbacks exceeds ~20% of touched methods, escalate — may indicate a pattern that
  justifies a macro wrapper, which is out of scope here.
- **Dev-dep introduction (`walkdir`, `regex`).** Called out explicitly to respect the PRD's
  no-casual-dep rule. Both are dev-only. Alternative (`syn` / hand-rolled walk) was rejected by
  the researcher on cost and speed grounds. If the gate reviewer disagrees, the fallback is a
  hand-rolled walker (~200 LOC) and a hand-rolled regex-lite that only handles anchored literals —
  doable but strictly worse per the research.
- **Tail-sampling collector config is an ops artifact, not a rs-vc artifact.** The yaml above is
  recommended baseline; actual deployment may tune `decision_wait` and `probabilistic.sampling_
  percentage` per environment. rs-vc's guarantee ends at "we ship every span with faithful
  `rvc.outcome` on the root"; the "always keep errors" property lives in the collector.
- **RedactedUrl query-param scrubbing is out of scope.** Existing helper strips userinfo only; we
  keep that surface. Any credential-bearing query param (`?token=...`, `?api_key=...`) must be
  avoided at the URL-construction site, not by the redaction helper. Flag if a production endpoint
  is found to do this.
- **Workspace-level integration test run cost.** `tests/forbidden_log_patterns.rs` scans every
  `.rs` file in `crates/` and `bin/` once per `cargo test`. Estimated <500 ms on current tree
  size; will grow linearly. Mitigation: `cargo test --workspace` already parallelizes; if the
  test becomes a CI bottleneck, gate it behind a `lint-logs` feature or an `xtask`. Not expected
  in this initiative.
- **`rvc.sse.stream_id` correlation depends on stream lifetime.** A naive implementation
  regenerates the id on every BN reconnect; a deliberate design decision the estimator should
  capture — in this architecture the id is **per-connection**, so two reconnects produce two
  ids. If operator feedback wants one id per BN target across reconnects, reopen — it's a small
  field-definition change.
- **Startup info-log of telemetry config runs BEFORE the file sink is installed.** The message
  goes to whatever subscriber is active at that moment (typically stdout/fmt). Document in
  `docs/observability.md` that the startup banner appears on stdout even when the file sink is
  configured.
