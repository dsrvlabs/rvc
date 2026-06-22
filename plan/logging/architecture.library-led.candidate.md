# Software Architecture: rs-vc Structured Logging & Observability — Candidate **library-led**

> Candidate for the rs-vc logging initiative (PRD: [`plan/logging/prd.md`](./prd.md);
> research: [`plan/logging/research/00-overview.md`](./research/00-overview.md), which is **authoritative**
> over the per-angle docs and whose reconciliations R1–R9 are honored throughout).
>
> **This is a cross-cutting observability initiative, not a new system.** Nothing here rebuilds the
> runtime, the `telemetry` crate, the OTLP/GCP exporters, the `logroller` file appender, the
> `ParentBased(TraceIdRatioBased)` sampler, or the `TracingGuard` contract. Every component below
> **composes into** the existing `tracing` + `tracing-subscriber` + OpenTelemetry stack.

## Overview

rs-vc is a 23-crate / 3-binary Cargo workspace (an Ethereum validator client) already running on
`tracing` + `tracing-subscriber` with a dedicated `telemetry` crate (OTLP/HTTP + optional GCP Cloud
Trace, W3C trace-context injection, size-rotated non-blocking file logging, a sampler, and a lifetime
guard). Logging today is *uneven*: only 19 `trace!` sites, whole crates near-silent, no documented
standard, ad-hoc correlation, and redaction-by-convention rather than by-construction. The PRD wants
**one** standard (5-level taxonomy, canonical `snake_case` spans-first field registry, hard secret
redaction), the runtime hot paths fully observable at `debug`/`trace`, zero secret leakage, zero
hot-path overhead when verbose is disabled, and reconciled subscriber init across both binaries.

This candidate optimizes for the **library-led** strategy: rather than asking 23 crates to each apply
the standard *by judgment*, we centralize correctness into **shared observability primitives that
crates merely call**, so the guarantee is baked into code, not into reviewer discipline. The load-bearing
architectural decision is the **placement of those primitives in the crate graph** such that no cycle is
introduced across the 23 crates. We split the primitives along their *dependency cost*:

1. **A new `crypto::logging` sub-surface (the "fields kit")** — pure-data, dependency-light primitives
   (the canonical field-key constants, the `TruncatedRoot` wrapper joining the existing
   `TruncatedPubkey`/`RedactedUrl`, `request_id` minting, and small ergonomic span helpers/macros). It
   lives in `crypto`, the lowest universally-reachable crate that `signer`, `secret-provider`,
   `block-service`, `bn-manager`, `beacon`, and the orchestrator already depend on. It pulls **no** OTel
   weight. This is where "the four high-risk crates plus rvc-keygen mnemonics merely call shared code"
   actually happens.
2. **An extension of `telemetry::propagation` (the "wire kit")** — the OTel-coupled primitive: an
   **inbound** W3C `traceparent`/`tracestate` extractor (`set_parent_from_headers`, the exact inverse of
   the existing `inject_trace_context`) for the :9000 Web3Signer boundary. It lives in `telemetry`
   because it needs `opentelemetry`/`tracing-opentelemetry`, which `telemetry` already owns, and only the
   binaries (and `beacon`) — which already depend on `telemetry` — need it.

This split is what keeps the graph acyclic (the heavy OTel primitive stays in the leaf crate `telemetry`,
which has **zero** internal dependencies; the light primitives stay in `crypto`, which never gains an OTel
or `telemetry` edge). "More shared code, stronger by-construction guarantees" — each guarantee (truncation,
redaction, canonical field names, correlation-id presence, zero-cost-when-disabled) is delivered by a
primitive a crate calls, plus a CI/test gate that proves the primitive was used.

## Architecture Principles

- **Library-led correctness** — Bake each rule into a callable primitive, then prove it with a gate. A
  crate should be *unable* to spell a non-canonical field name or a non-redacted secret without tripping
  the type system, a clippy lint, or a captured-subscriber test. Minimize per-crate judgment.
- **Primitives placed by dependency cost, never by theme** — Dependency-light primitives sink to the
  lowest universally-reachable crate (`crypto`); OTel-coupled primitives stay in the OTel-owning leaf
  (`telemetry`). This is the rule that prevents cycles across 23 crates (see Module Dependency Graph).
- **Compose, never rebuild** — The `telemetry` init/config/file_appender/propagation/shutdown surface,
  the OTLP/GCP exporters, the sampler, and `TracingGuard` are inputs, not redesign targets (PRD
  Non-Goals). New code is additive: new free functions, new `Display` wrappers, new const modules, new
  layers added to an existing `Registry` builder.
- **Spans-first correlation** — Canonical IDs (`slot`, `epoch`, `validator_index`, `pubkey`, `duty`,
  `request_id`, `committee_index`/`subcommittee_index`) live **once** on `#[instrument]` spans; child
  events inherit them and the OTLP layer turns them into span attributes (research R-recommendation 2).
- **Redaction is defense-in-depth, not a single wrapper** — Type layer (secret types don't `Display`),
  + CI lint gate (`disallowed-methods` on `expose_secret`/`raw_bytes`/`to_bytes`), + runtime
  captured-subscriber proof. No layer alone is sufficient (research §E).
- **Zero-cost-when-disabled is verified, not asserted** — `level` + `skip_all` on every hot-path
  `#[instrument]`; expensive fields gated by `enabled!` or wrapped in a zero-alloc `Display`;
  `release_max_level_debug` compiled into both binaries; proven by a criterion bench + a
  counting-`#[global_allocator]` zero-alloc test (research §D, §H; PRD P0-6).
- **`#[instrument(fields(...))]` evaluates EAGERLY** — (research R1, the most important correction.) Field
  expressions on `#[instrument]` run on *every call regardless of span level*. So `fields(...)` carries
  only `Copy` scalars / pre-resolved cheap values; all real formatting (hex, truncation Display, JSON) goes
  on an event-family macro (`debug!`/`trace!`) or behind `enabled!`. The primitives are designed so the
  cheap thing is the easy thing.

## System Context Diagram

```text
                         RUST_LOG / EnvFilter (env overrides config default)
                                          │
  ┌──────────────┐   W3C traceparent   ┌──┴───────────────────────────┐   OTLP/HTTP   ┌──────────────┐
  │ Lighthouse / │ ──+ x-request-id──▶ │        rs-vc workspace        │ ────spans───▶ │ OTel Collector│
  │ Prysm (VC)   │ ◀─── signature ──── │  bin/rvc · bin/rvc-signer:9000 │               │ (+ GCP Trace) │
  └──────────────┘                     │  bin/rvc-keygen · 23 crates    │               └──────────────┘
                                       └───────┬───────────────┬───────┘
   ┌──────────────┐  redacted bn_url           │ console (fmt) │ file (logroller, non-blocking)
   │ Beacon Nodes │ ◀── HTTP + traceparent ────┘  info default │ debug default (file ≥ console)
   └──────────────┘                                            ▼
                                                       operator / SRE log stream
```

The observability primitives are *internal* to the workspace; the external surfaces (OTLP collector,
beacon nodes, upstream VC clients on :9000) are unchanged. The only new external-facing behavior is
**reading** an inbound `traceparent`/`x-request-id` on :9000 (additive; ignored if absent).

## Module Overview

"Module" here = a logical observability component, each homed in an existing crate (no new crate is
created — that is the point of library-led: extend, don't proliferate). The table shows where each
primitive lives and the dependency direction it imposes.

| Module (component) | Responsibility | Home crate | Owns | Depends on | Comms |
|---|---|---|---|---|---|
| **Field Registry** | Canonical `snake_case` field-key constants + the normative names (`slot`, `epoch`, `validator_index`, `pubkey`, `duty`, `request_id`, `committee_index`, `subcommittee_index`, `bn_url`, `head`, `block_root`, `time_into_slot`) | `crypto::logging::fields` | the vocabulary (single source of truth) | `tracing` only | compile-time consts |
| **Redaction Kit** | `TruncatedPubkey`, `RedactedUrl` (existing) + **`TruncatedRoot`** (new, zero-alloc `Display`) | `crypto::logging` | the only sanctioned way to render a pubkey / URL / 32-byte root | `tracing`, `url`, crate-internal `hex` | `Display` (lazy via `%`) |
| **Correlation Kit** | `request_id` minting (`uuid::Uuid::new_v4()` → `RequestId` wrapper) + span-field helpers (`record_display`, `record_debug` to fill `field::Empty`) | `crypto::logging::correlation` | `request_id` lifecycle | `tracing`, `uuid` | function calls / span `record` |
| **Span Conventions** | The `#[instrument]` house style as small opt-in macros / documented attribute templates (`#[hot_instrument]`-style guidance) + `skip_all`+`fields` discipline | `crypto::logging` (macros) + standard doc | the convention | `tracing` | macro / doc |
| **Inbound Trace Extractor** | `set_parent_from_headers` (inverse of `inject_trace_context`) for :9000 + `x-request-id` echo | `telemetry::propagation` | the W3C-context boundary bridge | `opentelemetry`, `tracing-opentelemetry` (already present) | function call in the :9000 handler |
| **Subscriber Init Facade** | One shared init helper that both binaries call: default level `info`, `EnvFilter` precedence (env overrides config), console+file layer assembly, `release_max_level_debug` honored | `telemetry::init` (new `build_subscriber` fn) | the init contract | existing telemetry layers, `tracing-subscriber` env-filter | called once at startup |
| **Redaction Gate (CI)** | `clippy.toml` `disallowed-methods` + `gitleaks` job + captured-subscriber tests | repo root + 4 high-risk crates' tests | the enforcement | clippy, gitleaks, `tracing-test` | CI |
| **Zero-Overhead Harness** | criterion sign-path/per-slot benches + counting-`#[global_allocator]` zero-alloc test | new `crates/crypto` (or `signer`) bench + test | the P0-6 proof | `criterion`, `tracing`, `tracing-subscriber` | `cargo bench` / `cargo nextest` |

**Why no new crate?** A new `obs`/`logging` crate would have to be depended on by `crypto` (so `crypto`
can truncate) *and* would want OTel (for the extractor) — re-creating the exact coupling we are avoiding.
`crypto` is already a universal dependency and already hosts `TruncatedPubkey`/`RedactedUrl`; `telemetry`
already hosts `inject_trace_context` and the OTel deps. Extending these two is the minimal, acyclic move.

## Module Dependency Graph

Relevant existing edges (verified from Cargo.toml files):

```text
eth-types ──────────────▶ (no internal deps; only serde/ssz/tracing/tree_hash/hex)

crypto ────────────────▶ eth-types                         (crypto has NO telemetry edge)

signer ────────────────▶ crypto, eth-types                 (signer has NO telemetry edge)
secret-provider ───────▶ crypto, metrics                   (NO telemetry edge)
bn-manager / block-service / builder / duty-tracker / orchestrator(rvc) ─▶ crypto (+others)

beacon ────────────────▶ crypto, eth-types, telemetry      (only crate besides bins → telemetry)

telemetry ─────────────▶ (NO internal deps — leaf; only opentelemetry*/tracing*/reqwest/logroller)

bin/rvc ───────────────▶ telemetry, crypto, rvc, …
bin/rvc-signer ────────▶ telemetry, crypto, …              (already takes HeaderMap in /sign)
bin/rvc-keygen ────────▶ crypto, …
```

Where the new primitives land (▲ = primitive added here; arrows show *call direction*, never a new
crate edge unless noted):

```text
                              ┌──────────────────────────────┐
   ▲ Field Registry           │            crypto             │  ← already depended on by signer,
   ▲ Redaction Kit (+Root)  ──┤  crypto::logging  (the kit)   │     secret-provider, beacon, bn-manager,
   ▲ Correlation Kit          │  deps: tracing, url, uuid,    │     block-service, builder, duty-tracker,
   ▲ Span macros              │        eth-types (internal)   │     orchestrator(rvc), bins
                              └───────────────┬──────────────┘
   signer / secret-provider / orchestrator / bn-manager / beacon / keygen
        ──────────── call ────────────────────┘   (NO new edge: they already depend on crypto)

                              ┌──────────────────────────────┐
   ▲ Inbound Extractor        │           telemetry           │  ← leaf, ZERO internal deps; stays a leaf
   ▲ Subscriber Init Facade ──┤  propagation:: + init::       │
                              │  deps: opentelemetry*, etc.   │
                              └───────────────┬──────────────┘
   bin/rvc, bin/rvc-signer, beacon  ── call ──┘   (NO new edge: all three already depend on telemetry)
```

**Cycle analysis (the load-bearing guarantee).** Two candidate cycles are conceivable; both are avoided
by construction:

1. *Would `crypto → telemetry` cycle?* `crypto` does **not** depend on `telemetry` today, and we do **not**
   add that edge: the light primitives live in `crypto` itself and need no OTel. Even if one *wanted*
   `crypto → telemetry`, it would be acyclic (telemetry is a leaf), but it would (a) force the heavy OTel
   tree onto `crypto` and every crate below it, and (b) is unnecessary. **Rejected.**
2. *Would `telemetry → crypto` cycle?* The inbound extractor needs nothing from `crypto`
   (it operates on `axum`/`http` headers + `opentelemetry`), so `telemetry` stays a leaf with **zero**
   internal deps. We do **not** move `TruncatedPubkey` into `telemetry` (that would create
   `telemetry → crypto` and, since `beacon → telemetry` and `beacon → crypto`, would be a needless
   widening of the leaf). **Rejected.**

Result: **no new crate-to-crate edge is introduced anywhere.** All consumers already depend on the home
crate of the primitive they call. The architecture-tests crate (`crates/architecture-tests`) is the
natural place to add a guard test asserting `crypto` has no `telemetry`/`opentelemetry` dependency and
`telemetry` has no internal dependency, so the no-cycle invariant is itself library-enforced.

Verify: **No circular dependencies.** ✔ (light primitives in `crypto`, heavy primitive in leaf
`telemetry`; no edges added.)

---

## Module Details

### Module: Field Registry (`crypto::logging::fields`)

**Responsibility:** Be the single compile-time source of truth for canonical `snake_case` field keys so
no crate can invent a synonym (`val_idx`, `validator`, `rvc.slot`).

**Domain entities:**
- `pub const SLOT: &str = "slot"` … one `const` per canonical key in the PRD registry.
- Grouped re-export `pub mod keys { … }` so call sites can write `fields::keys::SLOT`.

**Data store:** none (consts).

**Public API (interface to other crates):**

| Item | Signature | Description |
|---|---|---|
| `fields::SLOT … fields::REQUEST_ID` | `&'static str` consts | Canonical keys: `slot`, `epoch`, `validator_index`, `pubkey`, `duty`, `request_id`, `committee_index`, `subcommittee_index`, `bn_url`, `head`, `block_root`, `time_into_slot` |
| `fields::Duty` | `enum { Attestation, Block, Aggregate, SyncCommittee, SyncContribution, ValidatorRegistration, VoluntaryExit }` with `as_str()` | Normative `duty` value strings (research §G: `committee_index` not `CommitteeIndex`) |

**Events published / consumed:** n/a (vocabulary only).

**Internal structure:**
```text
crypto/src/logging/
├── mod.rs        # re-exports TruncatedPubkey, RedactedUrl, TruncatedRoot, fields, correlation
├── fields.rs     # canonical key consts + Duty enum
├── redact.rs     # TruncatedPubkey (moved), RedactedUrl (moved), TruncatedRoot (new)
└── correlation.rs# RequestId, record_display/record_debug helpers
```
(The existing single-file `crypto/src/logging.rs` is split into a `logging/` module folder; this is an
internal refactor of `crypto`, no API break — the public re-exports stay at `crypto::logging::*`.)

**Key design decisions:**
- Consts, not an enum-of-keys, so `#[instrument(fields(slot = …))]` can still use the literal `slot`
  ident (the macro needs an ident, not a `&str`); the consts exist for *event-family* macros and for the
  conformance lint to diff against. The standard doc lists the literal idents; the consts back the lint.
- `Duty::as_str()` returns `&'static str` so it is a `Copy`-cheap span field (R1-safe on `#[instrument]`).

**Failure modes:** none (pure data). A typo'd key is caught by the P2-4 conformance lint diffing source
field names against this registry, not at runtime.

---

### Module: Redaction Kit (`crypto::logging` — `TruncatedPubkey`, `RedactedUrl`, **`TruncatedRoot`**)

**Responsibility:** Provide the *only* sanctioned, zero-allocation way to render a pubkey, a URL, or a
32-byte root/hash in a log line — safe at every level including `trace`.

**Domain entities:**
- `TruncatedPubkey<'a>(pub &'a str)` — existing; `0x{first10}...{last8}`, warns+falls-back on double-`0x`.
- `RedactedUrl<'a>(pub &'a str)` — existing; strips `user:pass@` via `url::Url`.
- **`TruncatedRoot<'a>(pub &'a [u8])`** — new; `Display` renders `0x{first8hex}...{last8hex}` for a
  `&[u8; 32]`/`&[u8]` block/head/signing root or hash, zero-alloc, mirroring `TruncatedPubkey`.

**Data store:** none.

**Public API:**

| Item | Signature | Output | Description |
|---|---|---|---|
| `TruncatedRoot::new` | `(bytes: &[u8]) -> Self` | — | Wrap a root/hash for `%`-rendering |
| `impl Display for TruncatedRoot` | — | `0x{8hex}...{8hex}` | Renders first 4 + last 4 bytes as hex; for `len < 8` bytes renders full hex; chooses one glyph `...` (research R9: be glyph-consistent) |

**Events published:** none.

**Internal structure:** `crypto/src/logging/redact.rs`.

**Key design decisions:**
- **`TruncatedRoot` takes `&[u8]`, not `&str`** — roots arrive as `Root`/`[u8;32]` on the hot path;
  forcing the caller to `hex::encode` first would *allocate even when the level is disabled* (R1 trap).
  Rendering bytes directly inside `Display::fmt` keeps it zero-alloc and lazy (only runs under `%` on an
  enabled event). This is the single most important shape choice for P0-6 on the sign path, where
  `signer/src/lib.rs:359` currently does `hex::encode(signing_root)` eagerly — see ADR-005.
- **Glyph:** use `...` (three ASCII dots), matching the settled `TruncatedPubkey` format, so all three
  wrappers read consistently (research R9). Drop the unverifiable "Lighthouse truncates roots" precedent
  (research R6) — this is an rs-vc house choice for readability + safety, not an imitation.
- **No `Display` is ever added to a secret type.** `TruncatedRoot` wraps a *non-secret* root; secret
  bytes (BLS key, password, mnemonic, full signature) have **no** wrapper and **no** `Display` — they are
  simply never passed to a logging macro (enforced by the gate, below).

**Failure modes:** malformed/short input renders the available bytes as full hex rather than panicking
(mirrors `TruncatedPubkey`'s short-input branch). A captured-subscriber test asserts a real 32-byte root
renders truncated and that the full hex is **absent** from output.

---

### Module: Correlation Kit (`crypto::logging::correlation`)

**Responsibility:** Mint and carry the `request_id` that follows a single signing/API request end to end
(including across the :9000 hop), and provide the helpers to fill deferred span fields correctly.

**Domain entities:**
- `RequestId(Uuid)` with `new() -> Self` (`Uuid::new_v4()`), `Display` (hyphenated), and `as_header_value()`.
- `record_display(span, key, value)` / `record_debug(span, key, value)` thin wrappers over
  `span.record(key, tracing::field::display(value))` — because the `%`/`?` sigils are macro sugar and do
  **not** work at a `record()` call site (research §A), and because `record()` on a field **not declared
  at span creation is silently dropped** (the #1 "vanishing attribute" bug).

**Data store:** none.

**Public API:**

| Item | Signature | Description |
|---|---|---|
| `RequestId::new` | `() -> RequestId` | Fresh v4 uuid per logical operation |
| `RequestId::as_header_value` | `(&self) -> http::HeaderValue` *(behind a tiny `http` types dep already transitively present)* | For the `x-request-id` echo across :9000 |
| `correlation::record_display` | `(span: &Span, key: &'static str, val: impl Display)` | Fill a `field::Empty` span field, lazily |

**Events published / consumed:** n/a.

**Internal structure:** `crypto/src/logging/correlation.rs`.

**Key design decisions:**
- **`request_id` source = fresh `Uuid::new_v4()` + `x-request-id` header** (ADR-002), matching the
  existing `keymanager-api` precedent (research, Consolidated Assumption 7). Deriving it from the OTel
  trace/span id is the rejected alternative (it couples the human-readable id to sampling/trace presence).
- **The deferred-field pattern is a first-class primitive**, not left to per-crate memory: a span on the
  :9000 path is created with `slot = tracing::field::Empty`, `duty = Empty`, `pubkey = Empty`, then filled
  via `record_display` after the body is parsed (mirrors the existing `http.status_code = Empty` pattern in
  `beacon::client`). Shipping `record_display`/`record_debug` removes the two foot-guns (sigil-at-record,
  undeclared-field) by construction.

**Failure modes:** if a field was not declared `Empty` at creation, `record_*` is a silent no-op — caught
by a captured-subscriber test asserting the field is present on the emitted span, not at runtime.

---

### Module: Span Conventions (macros + standard doc)

**Responsibility:** Make the correct `#[instrument]` the easy default on hot paths, encoding research R1
(eager fields), rule 3 (`level=`), rule 4 (`skip_all`), and the async rules (§C).

**Public API (opt-in ergonomics, not mandatory):**
- A documented **attribute template** in the standard (P0-1) that every hot-path fn copies:
  `#[tracing::instrument(level = "debug", skip_all, fields(slot, duty = %Duty::…, request_id = %rid))]`
  with the rule that `fields(...)` holds only `Copy`/`&'static str`/already-resolved cheap values.
- *(Optional)* a small declarative macro `hot_span!{ name=…, level=…, slot, duty }` in
  `crypto::logging` that expands to a correctly-shaped `info_span!`/`debug_span!` with `field::Empty`
  placeholders, for sites that build a span manually rather than via `#[instrument]`. Macro, not proc-macro
  — no `syn`/`quote` dependency added.

**Key design decisions:**
- **We do not ship a custom `#[instrument]` replacement proc-macro.** It would (a) add a proc-macro crate
  to `crypto`'s dependency tree and (b) fight the well-tested upstream macro. Instead the *guarantee* that
  hot-path instrument sites are shaped right is delivered by the **P2-4 conformance lint** (flagging bare
  `#[instrument]` on functions whose name matches the hot-path/sign/decrypt allow-list) + reviewer rubric,
  not by a bespoke macro. This keeps "library-led" without over-engineering.
- **`err`/`ret` discipline:** `err` only at the layer that decides an error is terminal (CLAUDE.md "log
  once"); `ret` only on small non-secret returns at `debug`/`trace`. Encoded in the template + lint.

**Failure modes:** a mis-leveled span (default INFO on a per-slot fn) floods the heartbeat — caught by
the conformance lint (P2-4) and the `info`-volume review, not at runtime. This is research's single
most-common mis-use to audit for (recommendation 3).

---

### Module: Inbound Trace Extractor (`telemetry::propagation::set_parent_from_headers`)

**Responsibility:** Bridge the W3C trace context **into** the :9000 `sign` span so a duty trace is
all-or-nothing end to end under the existing `ParentBased(TraceIdRatioBased)` sampler — the exact inverse
of the existing `inject_trace_context`.

**Domain entities:**
- `HeaderExtractor<'a>(&'a http_like_headers)` implementing `opentelemetry::propagation::Extractor`
  (mirror of the existing `HeaderInjector`).
- `set_parent_from_headers(span: &tracing::Span, headers: &HeaderMap)` — reads `traceparent`/`tracestate`
  via the global `TextMapPropagator` and sets the span's OTel parent context.

**Data store:** none.

**Public API:**

| Item | Signature | Description |
|---|---|---|
| `set_parent_from_headers` | `(&tracing::Span, &axum::http::HeaderMap)` | Set the inbound span's parent from W3C headers; no-op if absent/invalid (matches `inject`'s no-op-without-OTel behavior) |

**Events published / consumed:** n/a (context plumbing).

**Internal structure:** appended to `crates/telemetry/src/propagation.rs`, beside `inject_trace_context`,
sharing the module's existing `tracing_opentelemetry::OpenTelemetrySpanExt` import.

**Key design decisions (research §F, R3):**
- **Lives in `telemetry`, not `crypto`** — it needs `opentelemetry`/`tracing-opentelemetry`, already in
  `telemetry`; `bin/rvc-signer` already depends on `telemetry`. No new edge; the leaf stays a leaf.
- **Header type:** the existing injector uses `reqwest::header::HeaderMap` (outbound, client side). The
  inbound :9000 handler holds `axum::http::HeaderMap` (see `routes.rs:56`). `axum` re-exports the `http`
  crate's `HeaderMap`, and `reqwest` re-exports the same `http` types — so a single `&http::HeaderMap`
  generic (or a tiny `Extractor` impl over `http::HeaderMap`) serves both. The extractor is written
  against `http::HeaderMap` to avoid pulling `axum` into `telemetry` (open item flagged at the gate:
  confirm `telemetry` can name `http::HeaderMap` without a new dep — `reqwest` already re-exports it).
- **`x-request-id` is read alongside `traceparent`** (additive carrier, Assumption 7): the handler mints a
  `RequestId` if the header is absent, or adopts the inbound one, and echoes it on the response.
- **Sampler untouched** — bridging the boundary is exactly what makes the existing
  `ParentBased(TraceIdRatioBased(rate))` keep a duty trace whole once `rate < 1.0`; today the fragmentation
  is latent because `sample_rate` defaults to `1.0` (research §F).

**Failure modes:** absent/garbled `traceparent` → fresh root span (no worse than today); the captured
test asserts that *with* a valid inbound `traceparent`, the :9000 span's trace id equals the inbound one.

**Call site (bin/rvc-signer, not a telemetry concern):** the `sign` handler at
`bin/rvc-signer/src/http_api/routes.rs:51` (already `#[instrument(skip_all)]`, already takes `headers`)
calls `set_parent_from_headers(&Span::current(), &headers)` **first**, then records `request_id`,
`pubkey`, `slot`, `duty` (filled via `record_display` after body parse). R3's blocking-section fix lives
in `crates/signer/src/lib.rs` (capture `Span::current()` and `let _e = span.enter()` *inside* the
`spawn_blocking` closure at `lib.rs:372` so events from the BLS sign reattach to the `rvc.sign.*` span).

---

### Module: Subscriber Init Facade (`telemetry::init::build_subscriber`)

**Responsibility:** Give both binaries **one** init path so they share a default level, `EnvFilter`
precedence, and format selection (PRD P0-5), while leaving the OTLP layer, file appender, and
`TracingGuard` contracts byte-for-byte intact.

**Current divergence (verified):**
- `bin/rvc` (`main.rs:783`): `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))`
  — config default with `RUST_LOG` override — then assembles `registry().with(boxed_layers).with(fmt).with(filter)`,
  padding with `Identity` when no optional layers exist (the documented never-`Interest` poison fix).
- `bin/rvc-signer` (`main.rs:234`): `tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init()`
  — `RUST_LOG`-only, **no** config default, no OTel/file layer, no `Identity` padding.

**Public API:**

| Item | Signature | Description |
|---|---|---|
| `telemetry::build_subscriber` | `(cfg: &SubscriberConfig) -> (impl-into-init layers, guards)` | Assembles `EnvFilter` (env overrides `cfg.default_level`, default `info`), the `fmt` console layer, optional OTLP layer (via existing `init_tracing`), optional file layer (via existing `create_file_layer`), with the `Identity` padding rule; returns the same guard types both bins already hold |
| `SubscriberConfig` | `{ default_level: Level (=info), otlp: Option<TelemetryConfig>, file: Option<FileAppenderConfig>, format: ConsoleFormat }` | One shape both bins fill |

**Key design decisions:**
- **One `EnvFilter` precedence everywhere:** `try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default))`,
  default = `info` (ADR-003). `bin/rvc-signer` thereby *gains* a config default and the `Identity` padding
  correctness it lacks today; `bin/rvc`'s behavior is preserved.
- **Compose, don't rebuild:** `build_subscriber` *calls* the existing `init_tracing` and `create_file_layer`
  — it is an assembly helper, not a re-implementation. The `TracingGuard`/file-guard lifetimes are returned
  unchanged (Compatibility NFR).
- **File-more-verbose-than-console** (file `debug`, console `info`) is offered via `SubscriberConfig`
  *iff* the existing `logroller`/non-blocking layer supports an independent per-layer `EnvFilter`
  (research open item) — gated, not assumed; if unsupported, both share one filter (no regression).
- **`release_max_level_debug`** is set in **both** binaries' `Cargo.toml` (ADR-001), so `trace!` is
  compiled out of release while `debug!` stays `RUST_LOG`-switchable. The init facade does not change this
  (it is a compile-time feature on `tracing`), but the facade's doc references it as the companion knob.

**Failure modes:** an init regression that silently changes default verbosity/format is the named P0-5
risk — covered by init tests in **both** bins asserting (a) default level is `info`, (b) `RUST_LOG=debug`
overrides it, (c) the empty-layer `Identity` padding still emits events (the existing
`init_logging regression marker` test in `bin/rvc/src/main.rs:2242` is the model to mirror in rvc-signer).

---

### Module: Redaction Gate (CI + tests)

**Responsibility:** Prove, automatically, that no raw secret reaches a logging macro in the four
high-risk crates (`crypto`, `secret-provider`, `signer`, the `bin/rvc-signer` :9000 path) plus
`rvc-keygen` mnemonics — defense-in-depth, three layers (research §E; PRD P0-3).

**The three layers (all net-new enforcement except the type layer):**

1. **Type layer (exists; standardize + close gaps).** Every secret already lives in a type that redacts
   `Debug` and does **not** `Display`: `SecretKey([REDACTED])`, `secrecy::SecretString`,
   `SecretDataFormat → <redacted>`, `Zeroizing`. **Keep `secrecy`'s default no-`Serialize`/no-`Display`**;
   never add `SerializableSecret` or a `Display` "for convenience" (research §E.1, R4). `bip39::Mnemonic`
   *does* `Display` to the phrase — treat the bare type as a sink (never log it, not even length).
2. **CI lint gate (net-new — does NOT exist today; research R5).** Add to the repo-root `clippy.toml`
   (currently only `msrv = "1.92"`):
   ```toml
   disallowed-methods = [
     { path = "secrecy::ExposeSecret::expose_secret", reason = "log-adjacent secret exposure; scope with a reviewed #[allow] at decrypt sites only" },
     # BLS secret-byte laundering paths (the highest-risk):
     { path = "<bls SecretKey>::to_bytes", reason = "raw key bytes must never reach a log" },
     { path = "<bls SecretKey>::raw_bytes", reason = "raw key bytes must never reach a log" },
   ]
   ```
   riding the existing `cargo clippy --workspace --all-targets -- -D warnings` step (zero new infra).
   `expose_secret` is legitimately needed at decrypt call sites → a small, greppable, reviewed
   `#[allow(clippy::disallowed_methods)]` allow-list scopes it, so the lint flags any **new** use
   elsewhere. *Stated limitation:* `disallowed-methods` matches **named paths only** — it cannot see a
   value already laundered into a `String`/`&str`; acceptable because the type layer makes the implicit
   path impossible and the runtime tests cover the result.
3. **Runtime proof (net-new tests, existing harness).** `#[tracing_test::traced_test]` tests in
   `crypto`/`signer`/`bin/rvc-signer` that fire each high-risk log line and assert the output **contains**
   the truncated/redacted form and **does NOT contain** the raw secret. The existing
   `test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` (`crypto/src/logging.rs:119`) is the
   proven model. Plus a `gitleaks` PR job over **source** *and* over a **captured sample of emitted
   `trace`-level output**.

**Mandated handling per secret (from the standard doc):** BLS key → never log, gate `raw_bytes`/`to_bytes`;
password → `SecretString`, ban `expose_secret` outside decrypt; mnemonic → never log (bare `bip39::Mnemonic`
is a sink); full payload/root/signature → truncate at `trace` via `TruncatedRoot`, full value only on
return values; pubkey → **always** `TruncatedPubkey` + `%`, even at `trace` (PRD Open Q2 resolved-stricter);
URL → **always** `RedactedUrl`/`redact_endpoint`.

**Fallback (PRD Open Q3, research §E):** if a robust automated *source* regex scan proves impractical,
drop only the brittle regex scan and keep Layers 1+2 (both automated), the captured-subscriber tests, the
`gitleaks` source+emitted scan, and a documented reviewer checklist for the four crates — *stronger* than
the PRD's stated minimum, so P0-3 is met either way.

**Failure modes:** a new `expose_secret().into()` → `info!` bypass → caught by the lint (named path) *or*
the captured test (runtime absence) *or* gitleaks (emitted-output scan). Three independent nets.

---

### Module: Zero-Overhead Harness (`crypto`/`signer` bench + test)

**Responsibility:** Turn P0-6 from an assertion into a proof (research §H; no bench infra exists today).

**Components:**
- **criterion sign-path bench** comparing three regimes: `no_subscriber` / `subscriber_info` (debug spans
  disabled) / `subscriber_trace`. **Pass = `subscriber_info ≈ no_subscriber` within noise.**
- **per-slot-loop bench** around one coordinator phase (same three regimes).
- **counting-`#[global_allocator]` zero-alloc test** (dependency-free) asserting
  `assert_eq!(allocs_when_disabled, baseline)` on the sign path and per-slot path. **This allocation
  assertion — not the latency bench — is the precise gate**, because a ~1 ns disabled span is below
  criterion's measurement floor next to a BLS sign.

**Internal structure:** `crates/signer/benches/sign_path.rs` (+ `crates/crypto` or coordinator bench),
and a `#[cfg(test)]` counting-allocator module. Benches run via `cargo bench`; the asserting test runs
under `cargo nextest run --workspace` (the runner of record; `cargo test --workspace` can deadlock).

**Key design decisions:**
- The harness exists to validate the **primitives' shape**: it will *fail* if someone reintroduces an
  eager `hex::encode` on the sign path (the R1 trap) or a `fields(... = %heavy)` on a hot `#[instrument]`,
  giving the library-led guarantee a regression tripwire.
- `release_max_level_debug` is exercised by a release-profile build assertion that `trace!` callsites
  are compiled out (the strongest P0-6 form).

**Failure modes:** the harness *is* the failure detector; if `allocs_when_disabled != baseline` the build
fails before merge.

---

## Cross-Cutting Concerns

### Authentication & Authorization
Unchanged. The :9000 path's existing client-CN/mTLS audit logging (`bin/rvc-signer/src/audit`) is
preserved; the only addition is `request_id` correlation and inbound `traceparent` parsing, neither of
which gates access. No secret enters the audit or the trace.

### Logging & Observability (the subject of this doc)
Standardized by construction: canonical fields from `crypto::logging::fields`, correlation via
`RequestId` + spans-first, redaction via the Redaction Kit, init via the Subscriber Init Facade,
OTLP unchanged. The standard doc (P0-1) is the human-readable contract; the primitives + gates are the
machine-enforced one.

### Error Handling
Per CLAUDE.md "log once": `error` only at the terminal-decision layer (`err` on `#[instrument]` only
there); lower layers return the `Result`. The normalize pass (P1-3) removes duplicate log-and-return
lines and fixes `error`-vs-`warn` miscategorization **without** touching `Result`/`thiserror`/`?` control
flow (PRD Non-Goal). `error`-vs-`warn` breadth is bounded by the rule "`error` iff an intended action did
not complete" (PRD Open Q6 → conservative).

### Configuration
`RUST_LOG`/`EnvFilter` is the runtime knob (env overrides config default `info`). `release_max_level_debug`
is the compile-time cap. `SubscriberConfig` carries OTLP/file/format choices. No feature flags added beyond
the existing `gcp-trace` and the static-cap feature.

---

## Data Flow Diagrams

```text
Inbound Web3Signer sign (the correlation-critical path, P0-2/P0-4):
  VC client  ──POST /sign + traceparent + x-request-id──▶ bin/rvc-signer http_api::sign  [#instrument span]
  sign       ── telemetry::set_parent_from_headers(&Span, &headers) ──▶ span.parent = inbound trace
  sign       ── RequestId::new() OR adopt x-request-id ──▶ record_display(span, request_id)
  sign       ── parse body ──▶ record_display(span, slot/duty/pubkey via Empty fields)  [no secrets]
  sign       ── crypto/signer build steps ──▶ trace! framing w/ TruncatedRoot(signing_root)  [lazy]
  signer.sign_* (crates/signer/lib.rs) ── spawn_blocking { let _e = span.enter(); BLS sign } ─▶ events reattach
  sign       ── info! "signed" {slot, duty, request_id} ──▶ response + x-request-id echo
  OTLP layer ── span fields → span attributes; events → span events ──▶ collector (one whole trace)
```

```text
Per-slot duty (heartbeat shape, research §G):
  coordinator ── debug! duty cache hit/miss {slot, validator_index} ──▶ (off in prod)
  attestation ── trace! build steps {slot} ──▶ (off in prod)
  attestation ── info! "attestation published" {slot, head=%TruncatedRoot, committee_index} ──▶ heartbeat
  bn-manager  ── warn! "failover" {bn_url=%RedactedUrl} ──▶ operator
```

---

## Infrastructure & Deployment

### Deployment Model
Unchanged: a Cargo workspace producing `bin/rvc`, `bin/rvc-keygen`, `bin/rvc-signer`. Both long-running
binaries gain `release_max_level_debug` in their `Cargo.toml`. No container/PaaS/serverless change.

### Scaling Strategy
Not applicable to logging primitives (they are libraries). The relevant "scaling" axis is **log volume
under large validator counts**: `info` stays ≈ one line per assigned duty (Assumption 3); per-validator
inner loops are `debug`/`trace`; P2-1 sampling is the backstop for the highest-volume `trace`/`debug`
sites.

### Adoption / Rollout Path (replaces "service extraction")

This is a cross-cutting initiative across 23 crates; the rollout is **primitive-first, then breadth**,
so every later crate change is measured against a landed rubric and merely *calls* shared code.

| Phase | Scope (PRD) | Crates / sites | Library-led leverage |
|---|---|---|---|
| **P0 — Standard + primitives** | P0-1 + the kit | `crypto::logging` (fields, `TruncatedRoot`, `RequestId`, `record_*`); `telemetry::propagation` (inbound extractor); `telemetry::init` (facade); standard doc under `plan/logging/` | Land the callable primitives + the doc *before* any crate adoption, so the rubric and the tools exist first. |
| **P0 — Hot paths + safety** | P0-2/3/4/6 | `crypto`, `signer`, `secret-provider`, `bin/rvc-signer` :9000, `bn-manager`, `beacon`, `slashing`, `duty-tracker`, orchestrator (`rvc`) | Hot paths adopt `#[instrument(level, skip_all, fields)]` + the kit; land the Redaction Gate (clippy + gitleaks + captured tests) and the Zero-Overhead Harness. The four high-risk crates + `rvc-keygen` mnemonics reviewed under the policy. |
| **P0 — Init consistency** | P0-5 | `bin/rvc`, `bin/rvc-signer` | Both call `telemetry::build_subscriber`; init tests in both. |
| **P1 — Breadth** | P1-1/2/3 | gap crates (`rvc-keygen`, `signer-registry`, `eth-types`, `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`); remaining hot `#[instrument]` sites; normalize already-covered crates (`crates/rvc`, bins, `signer`, `bn-manager`, `slashing`, `crypto`) incl. the `rvc.`-prefix → bare `snake_case` migration (research §F namespace drift) | Each crate *calls* `fields::*`/the kit; the conformance lint (P2-4) keeps them on-standard. |
| **P1 — Docs** | P1-4 | `plan/logging/` or `docs/` | Operator guide: default levels, `RUST_LOG` recipes, pretty-vs-JSON, reading canonical fields / following `request_id`. |
| **P2 — Polish** | P2-1/2/3/4 | workspace | Sampling, dynamic `reload` (coordinate with rvc-signer's existing reload), JSON profile, conformance lint. |

**Per-crate "readiness to adopt" (analogue of extraction readiness):**
- **Ready now (just call the kit):** `signer`, `crypto`, `secret-provider`, `bn-manager`, `beacon`,
  `slashing`, orchestrator — already depend on `crypto`/`telemetry`; no new edge to adopt the primitives.
- **Needs the namespace migration first:** orchestrator `rvc.`-prefixed sites must move to bare
  `snake_case` (`rvc.slot` and `slot` are *different* OTLP keys) before dashboards unify.
- **Gap crates:** add `info`/`debug`/`trace` per the standard; mechanical, low-risk, kit-backed.

---

## Technology Choices

| Concern | Choice | Rationale |
|---|---|---|
| Framework | `tracing` + `tracing-subscriber` (existing) | PRD Non-Goal to swap; compose in. |
| Tracing export | OpenTelemetry OTLP/HTTP + optional GCP (existing `telemetry`) | Already wired; unchanged. |
| Field convention | `snake_case`, spans-first, canonical registry | PRD-settled; SHOULD-level house standard (research R2, not an OTel MUST). |
| Pubkey/URL/root redaction | `TruncatedPubkey`/`RedactedUrl` (existing) + `TruncatedRoot` (new), zero-alloc `Display` | Settled format `0x{first10}...{last8}`; new root wrapper mirrors it (R9 glyph-consistent). |
| `request_id` | `uuid::Uuid::new_v4()` + `x-request-id` header | `keymanager-api` precedent; decoupled from sampling (ADR-002). |
| Secret types | `secrecy` 0.10 (`SecretString`/`SecretBox`), `Zeroizing`, redacted `Debug` | Existing; keep no-`Display`/no-`Serialize` (R4). |
| CI lint | `clippy.toml` `disallowed-methods` + `gitleaks` | Net-new (R5); rides existing `-D warnings`, zero new infra. |
| Bench | `criterion` + counting-`#[global_allocator]` | Net-new (§H); alloc assertion is the precise P0-6 gate. |
| Static cap | `release_max_level_debug` (both bins) | `debug` stays `RUST_LOG`-switchable in prod; `trace` compiled out (ADR-001). |
| Test runner | `cargo nextest run --workspace` | Runner of record; `cargo test --workspace` can deadlock. |
| New crate? | **No** | Extend `crypto`/`telemetry`; a new crate would re-create the coupling we avoid. |

---

## ADRs (Architecture Decision Records)

### ADR-001: Static level cap = `release_max_level_debug` (not `_info`)
- **Status:** Accepted (forwarded to gate per research Open Questions).
- **Context:** P0-6 wants `trace` to cost nothing in release, but operators must be able to escalate to
  `debug` in prod via `RUST_LOG` without a separate build.
- **Decision:** Compile `release_max_level_debug` into `bin/rvc` and `bin/rvc-signer`. `trace!` is
  physically removed from the release binary; `debug!` remains runtime-switchable.
- **Alternatives:** `release_max_level_info` (would force a special build to ever see `debug` in prod —
  contradicts the PRD operator story); no static cap (leaves residual `EnvFilter` dynamic-directive cost).
- **Consequences:** Strongest P0-6 form for `trace`; `debug` cost is gated by the runtime interest cache.
  Must **not** enable tracing's `log`-bridge feature (re-introduces cost under a static cap, research §D2).

### ADR-002: `request_id` = fresh `uuid::v4` + `x-request-id` header
- **Status:** Accepted.
- **Context:** A single signing/API request must be followable end to end incl. the :9000 hop; spans-first
  needs one carried id.
- **Decision:** Mint `RequestId(Uuid::new_v4())` per logical operation in `crypto::logging::correlation`;
  carry on the span; echo across :9000 via `x-request-id`; adopt an inbound `x-request-id` if present.
- **Alternatives:** Derive `request_id` from the OTel trace/span id (one fewer header, but couples the
  human-readable id to trace presence/sampling and is empty when no OTel layer is active).
- **Consequences:** Matches the `keymanager-api` precedent; works even with OTLP disabled; additive header
  ignored by clients that don't send it (Assumption 7).

### ADR-003: One subscriber-init precedence — env overrides config default `info`
- **Status:** Accepted (P0-5).
- **Context:** `bin/rvc` uses config-default-with-`RUST_LOG`-override + `Identity` padding;
  `bin/rvc-signer` uses `RUST_LOG`-only with no default and no padding — operators must learn each.
- **Decision:** Both binaries call `telemetry::build_subscriber`, which uses
  `try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))` and the `Identity`-padding rule.
- **Alternatives:** Standardize on `from_default_env()` (drops the config default rvc relies on); leave
  divergent (the status quo the PRD rejects).
- **Consequences:** `bin/rvc-signer` gains a config default + padding correctness; `bin/rvc` behavior
  preserved; covered by init tests in both. OTLP/file/guard contracts unchanged.

### ADR-004: File default more verbose than console (file `debug`, console `info`) — conditional
- **Status:** Accepted *iff* the appender supports an independent per-layer filter; else deferred.
- **Context:** Lighthouse/Lodestar default the file to `debug` for richer post-mortems; familiarity for
  migrating operators (research §G).
- **Decision:** Offer it via `SubscriberConfig` only if the existing `logroller`/non-blocking layer
  accepts its own `EnvFilter`; otherwise both share one filter (no regression). Confirm at the gate; do
  not redesign the appender.
- **Alternatives:** Force file=console level (simpler, less useful); redesign the appender (PRD Non-Goal).
- **Consequences:** Better incident forensics when supported; zero risk when not (falls back to today's
  single-filter behavior).

### ADR-005: `TruncatedRoot` takes `&[u8]` and renders inside `Display` (no eager `hex::encode`)
- **Status:** Accepted.
- **Context:** Roots are `[u8;32]` on the hot path; the sign path today does eager `hex::encode(signing_root)`
  (`signer/src/lib.rs:359`), which allocates even when the level is disabled (the R1 trap).
- **Decision:** `TruncatedRoot(&[u8])` hex-renders the first/last bytes *inside* `Display::fmt`, so under
  `%` on an event-family macro it is zero-alloc and only runs when the level is enabled.
- **Alternatives:** `TruncatedRoot(&str)` (forces a caller `hex::encode` that allocates eagerly); a
  `format!`-based helper (allocates unconditionally).
- **Consequences:** Zero-alloc-when-disabled for root logging; the Zero-Overhead Harness will catch any
  reintroduced eager encode. Pairs with rule R1 (keep heavy work off `#[instrument(fields)]`).

### ADR-006: Spans-first; correlation NOT repeated on every event (PRD Open Q5)
- **Status:** Accepted (default), with a flat-backend mitigation.
- **Context:** Spans-first makes child events inherit IDs and the OTLP layer turns them into span
  attributes; repeating IDs on every event is redundant and verbose.
- **Decision:** Correlation IDs live on `#[instrument]` spans only. **Exception/mitigation:** stamp
  `request_id` on the **terminal** event of the :9000/sign path so a backend that flattens spans still
  correlates the request (Assumption 5).
- **Alternatives:** Repeat all IDs on every event (verbose, defeats spans-first); never repeat (breaks
  flat backends entirely).
- **Consequences:** Clean OTLP attributes; one pragmatic redundancy at the terminal event for flat
  backends. Confirm the operators' backend at the gate.

### ADR-007: Primitives placed by dependency cost — light in `crypto`, OTel in `telemetry`; no new crate
- **Status:** Accepted (the load-bearing decision of this candidate).
- **Context:** Library-led means many crates call shared primitives; the 23-crate graph must stay acyclic.
  `crypto` is a universal low dependency with no `telemetry`/OTel edge; `telemetry` is a leaf with zero
  internal deps and owns the OTel stack.
- **Decision:** Pure-data primitives (fields, `TruncatedRoot`, `RequestId`, span helpers/macros) extend
  `crypto::logging`; the OTel-coupled inbound extractor extends `telemetry::propagation`; the init facade
  extends `telemetry::init`. **No new crate; no new crate-to-crate edge.**
- **Alternatives:** (a) a new `obs` crate — would need to be a `crypto` dependency *and* want OTel,
  re-creating the coupling; (b) put everything in `telemetry` — forces `crypto → telemetry` (heavy OTel
  onto every crate below `crypto`) or `telemetry → crypto` (widens the leaf, risks a cycle with
  `beacon`); (c) put the extractor in `crypto` — forces OTel into `crypto`.
- **Consequences:** Minimal, acyclic, no dependency widening; every consumer already depends on the home
  crate of the primitive it calls. An `architecture-tests` guard asserts `crypto` has no `telemetry`/OTel
  dep and `telemetry` has no internal dep, making the invariant self-enforcing.

### ADR-008: Conformance enforced by lint + captured tests, not a bespoke `#[instrument]` proc-macro
- **Status:** Accepted.
- **Context:** Library-led tempts a custom proc-macro that bakes `level`/`skip_all`/canonical fields into
  one attribute.
- **Decision:** Keep the upstream `#[tracing::instrument]`; deliver the guarantee via a documented
  attribute template + the P2-4 conformance lint (flag bare `#[instrument]` on hot/sign/decrypt fns,
  flag non-canonical field names against `fields::*`) + the Redaction Gate + reviewer rubric. Optionally
  a small declarative (non-proc) `hot_span!` macro for manual spans.
- **Alternatives:** A bespoke proc-macro (adds `syn`/`quote` to `crypto`, fights well-tested upstream,
  high maintenance).
- **Consequences:** Strong by-construction guarantees without a proc-macro dependency or NIH risk; the
  lint is the regression tripwire.

---

## Open Questions

These are forwarded to the implementation gate (PRD's six Open Questions stand; these are the
architecture-specific ones; several mirror research's "forwarded to the gate"):

1. **`telemetry` naming `http::HeaderMap`** for the inbound extractor without a new dep — `reqwest`
   re-exports `http` types today; confirm `telemetry` can write the `Extractor` over `&http::HeaderMap`
   (used by both `axum` and `reqwest`) without adding an `axum`/`http` direct dependency. If a direct
   `http` dep is needed, it is a leaf-internal external dep (no internal edge, no cycle) — acceptable.
2. **File-independent level (ADR-004)** — does the existing `logroller`/non-blocking `create_file_layer`
   accept its own `EnvFilter`? If not, ADR-004 defers to single-filter (no regression).
3. **Static-cap confirmation (ADR-001)** — confirm `release_max_level_debug` vs `_info` against the
   operator "escalate to `debug` in prod" requirement (recommended: `_debug`).
4. **Conformance-lint scope (P2-4)** — is matching field names against `fields::*` feasible with
   `disallowed-*`/a simple source scan, or does it need the P2 `dylint` dataflow lint? (P2, not a P0
   blocker.)
5. **Coarse-span granularity** on the hottest async fns (one span per phase, not per inner `.await`) to
   bound the *enabled* per-poll enter/exit cost under large validator counts (research §D caveat).
6. **`request_id` carrier confirmation** — `x-request-id` vs deriving from OTel id (ADR-002 chooses the
   header; confirm the operators' tooling reads it).

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| A new crate edge sneaks in (e.g. someone adds `telemetry` to `crypto` to "reach the extractor"). | Cycle / heavy-dep widening across 23 crates. | ADR-007 split + an `architecture-tests` guard asserting `crypto` has no `telemetry`/OTel dep and `telemetry` has no internal dep. |
| `#[instrument(fields = %heavy)]` reintroduces eager work (R1 trap). | Hot-path latency / alloc when disabled. | Template forbids it; Zero-Overhead Harness alloc-assertion fails the build; conformance lint flags it. |
| Secret leak via `expose_secret().into()` → `info!`. | Security incident. | Three independent nets: clippy `disallowed-methods`, captured-subscriber absence test, gitleaks emitted-output scan. |
| Init reconciliation silently changes verbosity/format. | Operator surprise. | ADR-003 + init tests in **both** bins (default `info`, `RUST_LOG` override, `Identity` padding emits). |
| `TruncatedRoot` `&str` shape chosen by mistake → eager `hex::encode`. | Alloc when disabled. | ADR-005 fixes the shape to `&[u8]`; harness catches a regression. |
| Namespace drift (`rvc.slot` vs `slot`) left un-migrated. | Dashboards miss spans. | P1 migration to bare `snake_case`; conformance lint diffs against `fields::*`. |
| Spans-first breaks a flat OTLP backend. | Lost correlation. | ADR-006 stamps `request_id` on terminal events; confirm backend at gate. |
| Custom proc-macro NIH. | Maintenance burden / fights upstream. | ADR-008: lint + tests + declarative macro only; keep upstream `#[instrument]`. |

## Assumptions

(Carried from the PRD + research §Consolidated Assumptions; recorded here because the task forbids
asking the user.)

1. The existing `telemetry` stack (init, config, `file_appender`, `propagation`, `shutdown`, sampler,
   `TracingGuard`) is correct and stays the foundation; this composes into it. Versions: `tracing` 0.1 /
   `tracing-subscriber` 0.3 / `tracing-opentelemetry` 0.32 / `opentelemetry*` 0.31.
2. The PRD's settled decisions are authoritative and not re-opened: `snake_case`, spans-first, 5-level
   taxonomy, `TruncatedPubkey = 0x{first10}...{last8}`, `info` = production default, `RUST_LOG`/`EnvFilter`
   env-overrides-config.
3. `info` stays ≈ one line per assigned duty per validator; anything scaling with validator count or
   per-loop is `debug`/`trace`. P2-1 sampling is the backstop.
4. Release builds keep `debug` runtime-switchable but compile `trace` out (`release_max_level_debug`),
   confirmed at the gate vs `_info`.
5. Pubkeys are truncated even at `trace`; full signing roots/signatures are truncated/omitted by default
   (PRD Open Qs 1 & 2, resolved-stricter). `network` stays a resource attribute, never per-event.
6. The four high-risk crates (`crypto`, `secret-provider`, `signer`, the `bin/rvc-signer` :9000 path) are
   the review boundary; `rvc-keygen` (mnemonic/`bip39`) is treated as equally high-risk for the mnemonic
   rule even though the PRD lists it under P1 breadth.
7. `cargo nextest run --workspace` is the runner of record. No new mandatory toolchain (nightly/dylint)
   for P0; `dylint`/`valuable` are P2 escalations held in reserve.
8. The crate graph facts used for the no-cycle argument are current (verified this pass from Cargo.toml):
   `crypto → eth-types` only; `signer/secret-provider → crypto` (no `telemetry`); `beacon → crypto +
   telemetry`; `telemetry` has **zero** internal deps; both binaries already depend on `telemetry` and
   `crypto`; the `bin/rvc-signer` `/sign` handler already receives `axum::http::HeaderMap`.
9. `axum`'s and `reqwest`'s `HeaderMap` are both the `http` crate's type, so one `Extractor` over
   `http::HeaderMap` serves the inbound :9000 path without pulling `axum` into `telemetry` (confirm at the
   gate, Open Question 1).

---

## Architecture Quality Checklist

- [x] **No circular dependencies** — light primitives in `crypto`, OTel primitive in leaf `telemetry`;
  **no new crate-to-crate edge** (ADR-007); `architecture-tests` guard enforces it.
- [x] **Each module has a single, clear responsibility** — one sentence each (see Module Overview).
- [x] **No shared databases** — n/a (libraries); each primitive owns its data (vocabulary / wrappers / id).
- [x] **All inter-module communication through defined interfaces** — `fields::*` consts, `Display`
  wrappers, free functions (`set_parent_from_headers`, `build_subscriber`); no backdoor imports.
- [x] **Every module testable in isolation** — captured-subscriber tests per primitive; init tests per
  binary; bench/alloc test for P0-6.
- [x] **Cross-cutting concerns standardized** — fields/redaction/correlation/init are *the* shared code,
  not reimplemented per crate.
- [x] **Failure modes defined** — per-module above; the gates (lint/tests/harness) are the runtime nets.
- [x] **Adoption path is clear** — primitive-first, then hot paths, then breadth (replaces extraction
  path); per-crate readiness listed.
- [x] **Data flow traceable** — inbound :9000 sign and per-slot duty flows traced end to end.
- [x] **Module count justified** — no new crate; primitives grouped by dependency cost into exactly two
  existing homes (`crypto`, `telemetry`) — neither over-split nor a monolithic blob.
