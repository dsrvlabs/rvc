# Phase 5: External I/O + Safety Layer + gRPC Propagation

**Goal:** Every outbound I/O crate carries dual-attribution (`rvc.*` + OTel semconv) on success
and failure paths. Safety-layer writes (slashing, validator-store, doppelganger) log watermarks
and outcomes. W3C `traceparent` propagates end-to-end across the gRPC link to `bin/rvc-signer`.
**Total points:** 23
**Total issues:** 11
**Depends on:** Phase 3 (ratchet live); Phase 4 recommended but not strictly required for crates
5.1, 5.2, 5.6, 5.7, 5.8, 5.9, 5.10 (shared test fixtures benefit from Phase 4 landing first)
**Unblocks:** Phase 7 (cross-crate trace-id continuity in integration tests)

Dual-attribution constraint (architecture §3 + research summary finding #2): every external-I/O
span carries BOTH `rvc.*` fields (business correlation) AND OTel semconv fields (`rpc.*`,
`http.*`, `server.*`, `url.*`, `error.type`). The OTel keys are what Jaeger / Tempo use for
filter/search.

---

## Issue 5.1: Retrofit `crates/beacon/src/client.rs` — audit 10 sites for dual attribution

- **Points:** 2
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/beacon/src/client.rs`
- **Summary:** Architecture §1.5 reports ~10 existing `#[instrument]` sites. Audit each endpoint
  wrapper for the dual-attribution field set from architecture §3 "Beacon client request":
  `rvc.beacon.endpoint_name`, `rvc.bn_endpoint = %RedactedUrl(&url)`, `rvc.outcome`,
  `rvc.duration_ms`, `http.request.method`, `http.response.status_code`,
  `http.request.resend_count` (for retries), `url.full = %RedactedUrl(&full_url)`,
  `server.address`, `server.port`, `error.type`. Root level `debug` per architecture §4 (HTTP
  probes are noisy); failover attempts elevated to `info!` (owned by `bn-manager` in Issue 5.2).
- **Acceptance criteria:**
  - [ ] Every `pub async fn` returning an HTTP-backed Beacon call has
        `#[tracing::instrument(skip_all, level = "debug", name = "rvc.beacon.<endpoint_name>",
        fields(rvc.beacon.endpoint_name = "<endpoint_name>", rvc.bn_endpoint = Empty,
        rvc.outcome = Empty, rvc.duration_ms = Empty, http.request.method = "<GET|POST>",
        http.response.status_code = Empty, http.request.resend_count = Empty, url.full = Empty,
        server.address = Empty, server.port = Empty, error.type = Empty))]`.
  - [ ] `rvc.bn_endpoint` and `url.full` both populated via `%RedactedUrl(&url)` (userinfo
        stripped).
  - [ ] `inject_trace_context(&mut request.headers_mut())` already called before dispatching
        (existing pattern — verify in at least one site).
  - [ ] All 10 audit sites confirmed via grep.
- **Tests:**
  - `crates/beacon/tests/beacon_span.rs::test_get_attester_duties_success_fields` — `wiremock`
    stub returns 200 with valid payload; `TestTracingGuard` asserts `rvc.outcome = "success"`,
    `http.response.status_code = 200`, `rvc.bn_endpoint` is the redacted URL, `server.address`
    is the mock host.
  - `crates/beacon/tests/beacon_span.rs::test_get_attester_duties_5xx_records_error_type` —
    wiremock returns 500; assert `rvc.outcome = "error"`, `error.type = "http_5xx"` (or
    classifier), `http.response.status_code = 500`.
  - `crates/beacon/tests/beacon_span.rs::test_timeout_records_timeout_classifier` — wiremock
    delays past timeout; assert `rvc.outcome = "timeout"`, `error.type = "timeout"`.
- **Non-goals:**
  - Adding new endpoint wrappers.
  - Changing retry policy.
  - Instrumenting `bn-manager` failover (Issue 5.2).

---

## Issue 5.2: Retrofit `crates/bn-manager/` — failover, SSE fresh-root, health, sync-status

- **Points:** 3
- **Depends on:** 5.1 (shares beacon endpoint fields), 1.2 (TestTracingGuard)
- **Files touched:**
  - `crates/bn-manager/src/manager.rs` — failover attempt spans
  - `crates/bn-manager/src/sse.rs` — fresh-root-per-event per architecture §6
  - `crates/bn-manager/src/health.rs` — probe outcomes
  - `crates/bn-manager/src/sync_status.rs` — sync status probe
- **Summary:** Four files, unified into one issue because they share the failover / endpoint
  field set. `sse.rs` is the dominant subtask (fresh-root pattern per architecture §6). Each file
  gains outcome+endpoint fields; SSE additionally gets `rvc.sse.stream_id` (per-connection UUID
  regenerated on reconnect — architecture §8 open item confirmed per-connection lifetime).
- **Acceptance criteria:**
  - [ ] `manager.rs` failover path emits `info!` at failover with fields `rvc.bn_endpoint`
        (failing), `rvc.bn_endpoint.next` (new target), `rvc.outcome = "rejected"` on the old
        endpoint's attempt span, `rvc.attempt` counter.
  - [ ] `sse.rs` opens a fresh root span `rvc.bn_manager.sse_event` with `parent: None` per
        incoming event per architecture §6; fields `rvc.sse.event_type`, `rvc.sse.stream_id`,
        `rvc.bn_endpoint = %RedactedUrl(...)`; deferred `rvc.outcome`, `rvc.duration_ms`,
        `error.type`. Handler dispatches to child `rvc.bn_manager.handle_{head|reorg|finalized|
        block}` spans.
  - [ ] SSE reconnect emits `rvc.bn_manager.sse_reconnect` fresh root with `rvc.bn_endpoint`,
        `rvc.outcome`, `rvc.duration_ms`. Regenerates `stream_id` for subsequent events.
  - [ ] `health.rs` probe emits `rvc.bn_manager.health_probe` span with `rvc.bn_endpoint`,
        `rvc.outcome`, `rvc.duration_ms`, `http.response.status_code`.
  - [ ] `sync_status.rs` emits `rvc.bn_manager.sync_status` span with `rvc.bn_endpoint`,
        `rvc.outcome`, `rvc.is_synced` (bool), `rvc.head_slot`.
  - [ ] No `err` / `ret` attributes anywhere.
- **Tests:**
  - `crates/bn-manager/tests/failover_span.rs::test_failover_records_old_and_new_endpoints` —
    fake primary returns 500, secondary returns 200; assert sequence of spans with `rvc.attempt =
    0,1`.
  - `crates/bn-manager/tests/sse_span.rs::test_sse_event_is_fresh_root` — drive one SSE
    `head` event; `TestTracingGuard` asserts the `rvc.bn_manager.sse_event` span has `parent_id =
    None`, carries `rvc.sse.stream_id`, and has a child `rvc.bn_manager.handle_head`.
  - `crates/bn-manager/tests/sse_span.rs::test_sse_reconnect_regenerates_stream_id` — reconnect
    mid-stream; assert first-event and second-event stream ids differ.
  - `crates/bn-manager/tests/health_span.rs::test_health_probe_5xx_records_error_type` —
    assertion per 5.1 analog.
  - `crates/bn-manager/tests/sync_status_span.rs::test_sync_status_reports_slot` — assert
    `rvc.head_slot` populated.
- **Non-goals:**
  - Changing failover semantics.
  - Adding sampling-aware SSE drop logic (architecture §5 tail-sampling owns this).

---

## Issue 5.3: Install `TraceContextInterceptor` on `crates/grpc-signer/src/client.rs`

- **Points:** 2
- **Depends on:** 1.3 (interceptor impl lands), Phase 3 complete
- **Files touched:**
  - `crates/grpc-signer/src/client.rs`
  - `crates/grpc-signer/src/lib.rs` (channel builder / exposed client factory)
  - `crates/grpc-signer/Cargo.toml` (add `telemetry = { workspace = true }` if not present)
- **Summary:** Wrap the tonic channel with `TraceContextInterceptor` per architecture §2.4 so
  outgoing gRPC requests carry `traceparent` in metadata. Instrument each `GrpcRemoteSigner::
  sign_*` client call with the Signer-request field set from architecture §3: root span
  `rvc.signer.sign_<operation>`, dual-attribution (`rpc.system.name = "grpc"`, `rpc.method`,
  `server.address`, `server.port`, `rpc.response.status_code`), deferred `rvc.outcome`,
  `rvc.duration_ms`, `error.type`.
- **Acceptance criteria:**
  - [ ] Channel / client builder wraps with
        `InterceptedService::new(channel, TraceContextInterceptor::default())` (or equivalent
        `tonic::service::interceptor` call).
  - [ ] Every `sign_*` client method has `#[tracing::instrument(skip_all, name =
        "rvc.signer.sign_<op>", fields(rvc.signer.operation = "<op>", rvc.signer_endpoint =
        Empty, rvc.pubkey = Empty, rpc.system.name = "grpc", rpc.method = "<method>",
        server.address = Empty, server.port = Empty, rvc.outcome = Empty, rvc.duration_ms =
        Empty, rpc.response.status_code = Empty, error.type = Empty))]`.
  - [ ] `rvc.signer_endpoint` uses `%RedactedUrl`.
  - [ ] `rvc.pubkey` uses `%TruncatedPubkey`.
  - [ ] Any returned BLS signature logged in a debug event uses `%TruncatedSignature::from_bytes`.
- **Tests:**
  - `crates/grpc-signer/tests/client_span.rs::test_sign_attestation_injects_traceparent` —
    spin up a mock tonic server that echoes incoming metadata; assert the client request carries
    a valid `traceparent` starting with `00-`.
  - `crates/grpc-signer/tests/client_span.rs::test_sign_records_outcome_and_duration` — on
    success, `rvc.outcome = "success"`; on server returning an RPC error, `rvc.outcome = "error"`
    and `error.type` classifier.
- **Non-goals:**
  - Server-side extraction (Issue 5.4).
  - Round-trip integration test (Issue 5.5).

---

## Issue 5.4: Wire `attach_server_parent` + audit-log redaction in `bin/rvc-signer`

- **Points:** 3
- **Depends on:** 1.3 (helpers land), 5.3 recommended (shared fixture if available)
- **Files touched:**
  - `bin/rvc-signer/src/service.rs` (tonic `SignerService` handlers — `sign`, `list_public_keys`,
    `get_status`)
  - `bin/rvc-signer/src/backend/basic.rs`
  - `bin/rvc-signer/src/backend/dvt.rs`
  - `bin/rvc-signer/src/audit.rs` (audit-log field sanitization — `signing_root` →
    `%TruncatedPubkeyBytes`, `pubkey` → `%TruncatedPubkey`, any BLS sig → `%TruncatedSignature`)
  - `bin/rvc-signer/Cargo.toml` (add `telemetry = { workspace = true }` if absent)
- **Summary:** Option (a) from architecture §2.4: call `attach_server_parent(&request)` at the
  top of each tonic handler before opening the handler's tracing span. Every handler becomes a
  server-side root span with the extracted parent context. Audit-log field types swapped to
  redaction helpers so a future `{:?}` does not leak raw material. `#[instrument(skip_all)]` on
  all three handler methods plus both backend sign methods.
- **Acceptance criteria:**
  - [ ] `service.rs::SignerService::sign`, `list_public_keys`, `get_status` each call
        `attach_server_parent(&request)` first thing inside the method.
  - [ ] Each has `#[tracing::instrument(skip_all, name = "rvc.signer.server.<method>",
        fields(rvc.signer.operation = "<method>", rvc.pubkey = Empty, rvc.outcome = Empty,
        rvc.duration_ms = Empty, error.type = Empty, otel.kind = "server",
        rpc.system.name = "grpc", rpc.method = "<method>"))]`.
  - [ ] `backend::basic::sign` and `backend::dvt::sign` are instrumented at `debug` level as
        child sub-operations of the server root.
  - [ ] `audit.rs` logs `signing_root` via `%TruncatedPubkeyBytes(&req.signing_root)`, `pubkey`
        via `%TruncatedPubkey::new(&hex)`, any response BLS sig bytes via
        `%TruncatedSignature::from_bytes(&bytes)`. No `?req` or `?resp` anywhere in this file.
  - [ ] `#[instrument]` macros on any fn whose signature mentions `SignRequest` / `SigningRequest`
        have `skip_all` — architecturally required (Phase 3 rule
        `INSTRUMENT_NO_SKIPALL` catches).
- **Tests:**
  - `bin/rvc-signer/tests/server_span.rs::test_sign_handler_attaches_parent_from_metadata` —
    construct a `tonic::Request` with a handcrafted `traceparent` metadata entry, call the
    handler, assert the resulting root span has a matching trace id under `TestTracingGuard`.
  - `bin/rvc-signer/tests/server_span.rs::test_audit_log_uses_truncated_fields` — drive one
    sign; assert no captured event contains a 96-hex signature string or a 32-byte signing-root
    full hex. (`let _g = telemetry::test_capture()` with drop-on-panic behavior visible.)
  - `bin/rvc-signer/tests/server_span.rs::test_sign_records_outcome_error_on_failure` — backend
    returns error; assert `rvc.outcome = "error"`, `error.type` populated.
- **Non-goals:**
  - Deploying a tower `Layer` (option (b) in architecture §2.4) — explicitly chose option (a).
  - DVT peer-service instrumentation beyond what's needed for the sign handler (Phase 6 mop-up
    if needed).

---

## Issue 5.5: gRPC traceparent round-trip integration test

- **Points:** 2
- **Depends on:** 5.3, 5.4
- **Files touched:**
  - `crates/grpc-signer/tests/round_trip.rs` (new) OR `bin/rvc-signer/tests/round_trip.rs` —
    pick the crate that can own both a real client and a real server process
- **Summary:** End-to-end test: a `crates/grpc-signer` client with the interceptor installed
  makes a sign RPC against an in-process tonic server using `bin/rvc-signer`'s handler with
  `attach_server_parent`. Capture the span tree on both sides (two independent
  `TestTracingGuard`s are impractical since they're thread-local; use one guard in the server and
  assert the server span's trace id matches the known client-side trace id via injected metadata
  inspection).
- **Acceptance criteria:**
  - [ ] Test spins up an in-process tonic server on a random port, client connects, issues one
        sign call.
  - [ ] Server-side captured span `rvc.signer.server.sign` has `trace_id` equal to the
        client-side originating span's `trace_id`.
  - [ ] Server-side span's `parent_span_id` equals the client-side `sign_*` span's `span_id`.
  - [ ] Both spans carry `rvc.outcome = "success"`.
  - [ ] Test runtime < 2 seconds.
- **Tests:**
  - `*/tests/round_trip.rs::test_traceparent_client_to_server` — per acceptance.
- **Non-goals:**
  - Multi-hop propagation (just one client ↔ one server in this initiative).
  - Load testing.

---

## Issue 5.6: Retrofit `crates/crypto/src/remote_signer.rs` — Web3Signer HTTP

- **Points:** 2
- **Depends on:** Phase 3 complete, 1.1
- **Files touched:**
  - `crates/crypto/src/remote_signer.rs`
- **Summary:** Web3Signer HTTP calls gain dual attribution: `rvc.signer.operation`, `rvc.
  signer_endpoint = %RedactedUrl`, `http.request.method`, `http.response.status_code`,
  `url.full = %RedactedUrl`, `server.address`, `server.port`, `rvc.outcome`, `rvc.duration_ms`,
  `error.type`. `inject_trace_context(&mut request.headers_mut())` is called before dispatch
  (already present for beacon — architecture §1.5 lists Web3Signer as a new W3C-extension
  target).
- **Acceptance criteria:**
  - [ ] Every `pub async fn` that hits the Web3Signer endpoint has
        `#[tracing::instrument(skip_all, name = "rvc.signer.web3_<op>", fields(...))]` with the
        dual-attribution field list above.
  - [ ] `inject_trace_context(headers)` is called before every outgoing request.
  - [ ] `rvc.pubkey = %TruncatedPubkey::new(&hex)` wherever pubkey is logged.
  - [ ] Response bodies containing BLS signatures are logged via `%TruncatedSignature::from_bytes`
        only in `debug!` events.
- **Tests:**
  - `crates/crypto/tests/remote_signer_span.rs::test_sign_attestation_records_http_status` —
    wiremock stubs, assert `http.response.status_code = 200` on success.
  - `crates/crypto/tests/remote_signer_span.rs::test_web3_error_records_error_type` — 500
    response; assert `rvc.outcome = "error"`, `error.type = "web3_5xx"` (classifier).
  - `crates/crypto/tests/remote_signer_span.rs::test_traceparent_injected` — assert outgoing
    request headers contain a valid `traceparent` when called under an active span.
- **Non-goals:**
  - Changing the signing request body shape.

---

## Issue 5.7: Retrofit `crates/secret-provider/src/gcp.rs` — GCP calls

- **Points:** 2
- **Depends on:** Phase 3 complete, 1.1
- **Files touched:**
  - `crates/secret-provider/src/gcp.rs`
- **Summary:** Architecture §1.5 says 2 `#[instrument]` sites exist; add any missing on list /
  fetch / auth methods. Every GCP call becomes `rvc.secret_provider.{list|fetch|auth}` with
  `rvc.outcome`, `rvc.duration_ms`, `error.type`. W3C propagation to GCP calls is
  best-effort (architecture §P0-5 notes "where feasible"); inject if the GCP client exposes a
  header-map hook, otherwise skip and document.
- **Acceptance criteria:**
  - [ ] Every `pub async fn` that talks to GCP has
        `#[tracing::instrument(skip_all, name = "rvc.secret_provider.<op>",
        fields(rvc.secret_provider.operation = "<op>", rvc.outcome = Empty, rvc.duration_ms =
        Empty, error.type = Empty))]`.
  - [ ] `rvc.secret_provider.resource_id` (the secret resource name) logged on fetch — but
        redacted to the resource short-form (final path segment) because full resource paths may
        include project ids that are sensitive.
  - [ ] No raw secret bytes appear in any log line / captured span (Phase 3 ratchet enforces).
- **Tests:**
  - `crates/secret-provider/tests/gcp_span.rs::test_fetch_success_records_outcome` —
    mock GCP client, happy path.
  - `crates/secret-provider/tests/gcp_span.rs::test_fetch_error_records_error_type` — GCP
    returns NotFound; assert `error.type = "gcp_not_found"`.
- **Non-goals:**
  - Switching GCP SDK.
  - Changing the existing `key_source_manager.rs` hierarchical span pattern (architecture §1.5
    notes tests cover it — preserve).

---

## Issue 5.8: Retrofit `crates/keymanager-api/src/handlers.rs` — all 8+ handlers

- **Points:** 2
- **Depends on:** Phase 3 complete, 1.1
- **Files touched:**
  - `crates/keymanager-api/src/handlers.rs`
- **Summary:** Every handler (import / list / delete keystores, import / list / delete
  remotekeys, slashing-protection export / import, plus any status/info handlers) becomes a
  root span `rvc.keymanager.<handler>` with the architecture §3 "Keymanager-API request" field
  set: `rvc.keymanager.caller_kind` (`"keystore"` or `"remotekey"`), `rvc.keymanager.request_id`
  (if `x-request-id` header provided — P2-2 backlog, but land the field as `Empty` now),
  `rvc.outcome`, `rvc.duration_ms`, `rvc.keymanager.count_accepted`,
  `rvc.keymanager.count_rejected`, `http.request.method`, `http.route`, `error.type`.
- **Acceptance criteria:**
  - [ ] Every handler `pub async fn` has `#[tracing::instrument(skip_all, name =
        "rvc.keymanager.<handler>", fields(...))]` per architecture §3.
  - [ ] `rvc.keymanager.count_accepted` / `count_rejected` recorded at close for bulk-op
        handlers (import / delete); unused handlers leave them `Empty`.
  - [ ] Any logged pubkey uses `%TruncatedPubkey`; keystore bodies are never logged.
  - [ ] Error responses log at `error!` with `error = %e` and `error.type` classifier.
- **Tests:**
  - `crates/keymanager-api/tests/handlers_span.rs::test_import_keystores_success_fields` —
    drive import of 2 keystores, assert `rvc.keymanager.count_accepted = 2`,
    `rvc.outcome = "success"`.
  - `crates/keymanager-api/tests/handlers_span.rs::test_import_keystores_partial_failure` —
    one invalid keystore; assert `count_accepted = 1`, `count_rejected = 1`,
    `rvc.outcome = "rejected"`.
  - `crates/keymanager-api/tests/handlers_span.rs::test_list_keystores_error` — DB-backed
    failure path; `rvc.outcome = "error"`, `error.type` populated.
- **Non-goals:**
  - Implementing the `x-request-id` intake logic — field is declared `Empty`; intake is P2-2
    and lives in Phase 8 or later.
  - Auth/session work.

---

## Issue 5.9: Retrofit `crates/slashing/src/db.rs` — watermark fields + prune row counts

- **Points:** 2
- **Depends on:** Phase 3 complete, Phase 4 Issue 4.7 (signer records `rvc.slashing.result`)
- **Files touched:**
  - `crates/slashing/src/db.rs`
- **Summary:** Architecture §1.5 reports 5 existing `#[instrument]` sites. Add the fields called
  out in architecture §3 "Slashing DB write" row. Attestation reject: record
  `rvc.slashing.source_epoch`, `rvc.slashing.target_epoch`. Block reject: record `rvc.slot`,
  `rvc.slashing.signing_root = %TruncatedPubkeyBytes(&root.0)`. Pruning spans record
  `rvc.duration_ms` + row counts (`rvc.slashing.pruned_rows`). Integrity check: `info!` on pass,
  `error!` on fail with specifics.
- **Acceptance criteria:**
  - [ ] `check_and_record_attestation` has `#[tracing::instrument(skip_all, name =
        "rvc.slashing.check_attestation", fields(rvc.validator_index, rvc.pubkey,
        rvc.slashing.source_epoch = Empty, rvc.slashing.target_epoch = Empty, rvc.outcome =
        Empty, rvc.duration_ms = Empty, rvc.slashing.result = Empty, db.system = "sqlite"))]`.
        Source/target epoch fields populated on reject per architecture §3.
  - [ ] `check_and_record_block` has analog with `rvc.slot` and `rvc.slashing.signing_root =
        %TruncatedPubkeyBytes(&root)`.
  - [ ] Pruning span (`rvc.slashing.prune_*`) records `rvc.slashing.pruned_rows` (u64) and
        `rvc.duration_ms` at close.
  - [ ] Integrity-check span: `info!` ("integrity check passed") on success,
        `error!(error = %e, error.type = "integrity_fail", ...)` on failure.
  - [ ] Every `rvc.slashing.result` record uses one of
        `safe|double_vote|surrounding|surrounded|double_proposal|db_error`.
- **Tests:**
  - `crates/slashing/tests/slashing_span.rs::test_double_vote_records_result_and_epochs` — PRD
    P0-6 acceptance: trigger a double-vote rejection, `TestTracingGuard` asserts the log
    contains `rvc.slashing.result = "double_vote"`, the validator short-form pubkey, and the
    source/target epochs that triggered the rule.
  - `crates/slashing/tests/slashing_span.rs::test_block_double_proposal_records_slot_and_root`
    — trigger a double-proposal, assert `rvc.slot` and `rvc.slashing.signing_root` short-form
    are on the span.
  - `crates/slashing/tests/slashing_span.rs::test_prune_records_row_count` — trigger pruning
    with N rows; assert `rvc.slashing.pruned_rows = N`.
  - `crates/slashing/tests/slashing_span.rs::test_integrity_check_pass_emits_info` — normal
    DB; assert one `info!` event.
- **Non-goals:**
  - Changing slashing-DB schema.
  - Watermark change detection alerting (metrics team).

---

## Issue 5.10: Retrofit `crates/validator-store/src/store.rs` — parse-first/apply-second reload

- **Points:** 1
- **Depends on:** Phase 3 complete
- **Files touched:**
  - `crates/validator-store/src/store.rs`
- **Summary:** Architecture §1.5 reports 4 existing sites. Extend `reload_config` so parse and
  apply are two separate `info!` stages with explicit fields (`rvc.validator_store.parsed_count`,
  `rvc.validator_store.applied_count`, `rvc.validator_store.skipped_count`). Every per-validator
  override application emits a `debug!` event with the validator short-form pubkey.
- **Acceptance criteria:**
  - [ ] `reload_config` instrumented with `#[tracing::instrument(skip_all, name =
        "rvc.validator_store.reload", fields(rvc.outcome = Empty, rvc.duration_ms = Empty,
        rvc.validator_store.parsed_count = Empty, rvc.validator_store.applied_count = Empty,
        rvc.validator_store.skipped_count = Empty, error.type = Empty))]`.
  - [ ] Two distinct `info!` events inside the method: one on parse-complete
        (`parsed_count` recorded), one on apply-complete (`applied_count` /
        `skipped_count` recorded).
  - [ ] Per-validator override application emits one `debug!` event with `rvc.pubkey =
        %TruncatedPubkey`.
- **Tests:**
  - `crates/validator-store/tests/reload_span.rs::test_reload_parse_then_apply_stages` — load
    a config with N overrides; `TestTracingGuard` asserts two `info!` events and the counts.
  - `crates/validator-store/tests/reload_span.rs::test_reload_parse_error_records_error_type`
    — malformed config; assert `rvc.outcome = "error"`, `error.type = "parse"`.
- **Non-goals:**
  - Changing reload semantics.

---

## Issue 5.11: Rewrite `crates/doppelganger/src/service.rs` — fresh-root-per-epoch

- **Points:** 2
- **Depends on:** Phase 3 complete, 1.1
- **Files touched:**
  - `crates/doppelganger/src/service.rs`
  - `crates/rvc/src/doppelganger_adapter.rs` (if the adapter drives the monitor loop —
    propagate `instance_id` through)
  - `crates/doppelganger/Cargo.toml` (add `uuid = { workspace = true, features = ["v4"] }` if
    absent — workspace already pins)
- **Summary:** Implement architecture §6 concrete shape verbatim. Each epoch gets a fresh root
  span `rvc.doppelganger.check_epoch` with `parent: None`, `rvc.monitor.instance_id` (per-run
  UUID), `rvc.epoch`, `rvc.operation = "doppelganger_check"`, deferred outcome / duration /
  detection flag. Iterations are linked via
  `tracing_opentelemetry::OpenTelemetrySpanExt::add_link` to the previous iteration's
  `SpanContext`. Per-pubkey liveness probe spans are `debug`-level children of the epoch root.
  On detection, `error!` with the short-form pubkey (PRD P0-6).
- **Acceptance criteria:**
  - [ ] `DoppelgangerService::new` stores an `instance_id: String` (UUID v4).
  - [ ] Monitor loop creates a fresh root span per epoch with `parent: None` and the
        architecture §3 / §6 field set.
  - [ ] `prev_ctx` threading: each iteration after the first calls
        `span.add_link(prev_ctx.clone())` (unhidden `OpenTelemetrySpanExt` import).
  - [ ] Per-pubkey liveness is a `debug_span!("rvc.doppelganger.probe", rvc.pubkey =
        %TruncatedPubkey::new(&hex))` child.
  - [ ] On detection, `error!(rvc.pubkey = %TruncatedPubkey::new(&hex), rvc.validator_index,
        "doppelganger detected")` fires AND `rvc.doppelganger.detected = true` is recorded on
        the epoch root span.
  - [ ] On clean epoch, `rvc.doppelganger.detected = false` and `rvc.outcome = "success"`.
- **Tests:**
  - `crates/doppelganger/tests/doppelganger_span.rs::test_two_epochs_share_instance_id` — run
    two epochs against a mock BN, assert both root spans have the same
    `rvc.monitor.instance_id` and distinct `rvc.epoch`.
  - `crates/doppelganger/tests/doppelganger_span.rs::test_second_epoch_links_to_first` —
    assert the second root span has a `SpanLink` referencing the first span's
    `SpanContext`.
  - `crates/doppelganger/tests/doppelganger_span.rs::test_detection_emits_error_event` — mock
    liveness reports the validator as active; assert `rvc.doppelganger.detected = true` AND
    one `error!` event with the short-form pubkey.
  - `crates/doppelganger/tests/doppelganger_span.rs::test_no_detection_emits_success` — clean
    epoch; assert `rvc.outcome = "success"`, `rvc.doppelganger.detected = false`.
- **Non-goals:**
  - Changing detection algorithm.
  - Cross-restart correlation (architecture §8 carries this as open item; not in this
    initiative).
