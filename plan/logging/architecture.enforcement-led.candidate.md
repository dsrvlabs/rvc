# Software Architecture: rs-vc Structured Logging & Observability — **Enforcement-Led** Candidate

> Candidate logging/observability architecture for the existing `rs-vc` Cargo workspace
> (23 crates + 3 binaries, already on `tracing` + `tracing-subscriber` + OpenTelemetry/OTLP with a
> dedicated `telemetry` crate). This is a **cross-cutting observability initiative, not a new
> system**: it **composes into** the existing telemetry/OTLP/file-appender stack; it does not
> redesign the runtime or rebuild telemetry.
>
> **Sources of truth:** PRD [`plan/logging/prd.md`](./prd.md) and research
> [`plan/logging/research/00-overview.md`](./research/00-overview.md) (authoritative over the
> per-angle docs; honors reconciliations R1–R9). This candidate optimizes the **enforcement-led**
> axis: every rule in the standard is backed by an automated, machine-checked guarantee that keeps
> the standard from drifting, riding the **existing** CI with **no new mandatory toolchain for P0**.

---

## Overview

rs-vc is an Ethereum validator client that signs and broadcasts attestations and blocks on a strict
per-slot deadline; an unobservable incident costs rewards, and a leaked secret is a security
incident. The logging stack already exists (`tracing`/`tracing-subscriber`/`tracing-opentelemetry`,
the `telemetry` crate, `crypto::logging` redaction wrappers, 72 `#[instrument]` sites). What is
missing is **one standard** and, above all, **enforcement that the standard cannot silently drift**.

This candidate treats the logging standard as a **self-policing contract**. Each normative rule —
canonical field names, level taxonomy, secret redaction, zero-overhead-when-disabled, subscriber-init
parity — is paired with a concrete gate: a `clippy.toml` `disallowed-methods` lint riding the
existing `cargo clippy --workspace --all-targets -- -D warnings` step; a `gitleaks` PR job over
source **and** a captured sample of emitted logs; `#[tracing_test::traced_test]` captured-subscriber
conformance tests asserting redaction and the intended level/fields; a dependency-free
counting-`#[global_allocator]` zero-alloc test (P0-6); and an optional canonical-field-name
conformance lint. The guiding stance: **prefer a machine-checked guarantee over a documented
convention, even at the cost of more CI/test infra** — because a convention a reviewer can forget is
not a guarantee.

The architecture is deliberately **additive and acyclic**. Shared logging primitives have exactly
one home each, chosen so the 23-crate dependency DAG (already machine-enforced by the
`rvc-architecture-tests` standing gate) gains **zero cycles**: redaction wrappers + canonical-field
constants + `request_id` minting live in `crypto::logging` (the low-level crate every signing-adjacent
crate already depends on, which already owns `TruncatedPubkey`/`RedactedUrl` and the `uuid` dep); the
inbound W3C trace-context **extractor** (inverse of the existing `telemetry::propagation::
inject_trace_context`) lives in `telemetry::propagation` (the only crate with the OTel deps). No new
crate is required.

---

## Architecture Principles

- **Enforcement over convention (the defining principle).** Every normative rule ships with an
  automated gate. If a rule cannot be machine-checked, it is downgraded to "advisory" and explicitly
  flagged — it is never presented as a guarantee. Drift is a CI failure, not a code-review judgment
  call.
- **Ride the existing CI; no new mandatory toolchain for P0.** Gates attach to the steps that already
  exist (`cargo clippy … -D warnings`, `cargo fmt --all -- --check`, `cargo llvm-cov nextest
  --workspace`). The only net-new CI job is a single `gitleaks` action; everything else is config or
  tests. Nightly/dylint/`--cfg tracing_unstable` are explicitly **P2**, never P0 blockers.
- **Compose into the telemetry stack, never rebuild it.** `init`, `config`, `file_appender`,
  `propagation`, `shutdown`, the `ParentBased(TraceIdRatioBased)` sampler, and the `TracingGuard`
  contract are foundations. New work is layered on, not forked.
- **One canonical home per primitive, acyclic by construction.** A primitive lives in the lowest crate
  that can host it without inverting an existing edge. This is verified, not asserted, by the
  `rvc-architecture-tests` DAG gate.
- **Spans-first correlation.** Canonical correlation identifiers live once on `#[instrument]` spans and
  inherit to every child event and across crate/process boundaries; events carry only event-specific
  data. (Ratified by all five research angles.)
- **Defense in depth for secrets.** No single layer is sufficient: type-level redaction + a CI lint
  gate + runtime captured-subscriber tests, applied with explicit sign-off to the four high-risk
  crates plus `rvc-keygen` mnemonics.
- **Zero-cost-when-disabled is a tested property, not a hope.** A counting allocator asserts
  `allocs_when_disabled == baseline` on the sign and per-slot paths; `release_max_level_debug`
  physically removes `trace!` from release binaries.

---

## System Context Diagram

```text
                         RUST_LOG / EnvFilter (env overrides config default)
                                          │
   ┌──────────┐  duty/sign spans          ▼                      ┌─────────────────────┐
   │ Operator │ ◀──── info heartbeat ─── bin/rvc  ──(W3C tp)────▶ │ OTLP collector /     │
   │  / SRE   │ ◀──── debug/trace ─────  bin/rvc-signer (:9000)   │ GCP Cloud Trace      │
   └──────────┘            │ logs+spans       │                   └─────────────────────┘
                           │                  │ inbound traceparent EXTRACT (new)
                           ▼                  ▼                   ┌─────────────────────┐
                   console (fmt) + file (logroller)               │ Beacon Node(s) HTTP │
                   non-blocking writer                ──(W3C tp)──▶│ (trace continues)   │
                                                                   └─────────────────────┘
   ┌───────────────────────────── CI (self-policing gates) ─────────────────────────────┐
   │  cargo fmt ──  cargo clippy -D warnings (+ clippy.toml disallowed-methods)          │
   │  cargo llvm-cov nextest --workspace (captured-subscriber + zero-alloc tests)        │
   │  gitleaks PR job (source + emitted-log sample)    rvc-architecture-tests DAG gate   │
   └────────────────────────────────────────────────────────────────────────────────────┘
```

The system boundary is unchanged from today. The only **new** wire-level behavior is inbound W3C
trace-context extraction at `:9000` (closing the trace-continuity gap) and an additive `x-request-id`
header; signing behavior, public APIs, and the OTLP export path are untouched.

---

## Module Overview

This is an observability layer, so "modules" are **logical observability components** mapped onto
existing crates, plus the CI gates that police them. The table lists where each shared primitive lives
and what enforces its correct use.

| Module (logical) | Responsibility | Home crate (canonical) | Depends on | Enforced by |
|---|---|---|---|---|
| **Redaction primitives** | `TruncatedPubkey`, `RedactedUrl`, **new** `TruncatedRoot` — zero-alloc `Display` wrappers | `crypto::logging` | `crypto` (existing) | clippy `disallowed-methods` + captured-subscriber tests |
| **Canonical field registry** | Normative `snake_case` field names as constants + doc | `crypto::logging::fields` (new submodule) + standard doc | `crypto` (existing) | optional field-name conformance lint (P2-4); doc is the review rubric |
| **request_id minting** | `new_request_id()` → `uuid::Uuid::new_v4()`; `%`-renderable | `crypto::logging` | `crypto` (already has `uuid`) | captured-subscriber test asserts presence on sign/API spans |
| **Inbound trace-context extractor** | `HeaderExtractor` + `set_parent_from_headers` (inverse of `inject_trace_context`) | `telemetry::propagation` | `telemetry` (has OTel deps) | unit test asserts boundary span has non-zero parent |
| **Subscriber init (reconciled)** | one default level + EnvFilter precedence, shared by both bins | `telemetry` (helper) + each `bin/*/main.rs` | `telemetry` | init parity tests in both binaries |
| **Level taxonomy + span strategy** | `#[instrument]` `level=`/`skip_all`/`fields` conventions on hot paths | per-crate (applied) | — | captured-subscriber level/field tests; clippy `skip_all` discipline |
| **Zero-overhead harness (P0-6)** | counting `#[global_allocator]` test + criterion sign bench | `crypto` benches/tests + `release_max_level_debug` on bins | `crypto`, both bins | nextest zero-alloc assertion (the precise gate) |
| **Secret-leak CI gate** | clippy `disallowed-methods` + gitleaks (source + emitted) | `clippy.toml` + `.github/workflows/ci.yml` | — | the gates themselves (fail-closed, 0 findings) |
| **DAG invariant gate** | new edges introduce no cycles | `rvc-architecture-tests` (existing) | — | `cargo metadata` parse, already in CI |

**Why `crypto::logging` is the canonical home for redaction + fields + request_id** (the load-bearing
boundary decision): `crypto` already exports `pub mod logging` with `TruncatedPubkey`/`RedactedUrl`,
already depends on `uuid`, `hex`, and `tracing`, and is depended on by **every** signing-adjacent
crate (`signer`, `secret-provider`, `beacon`, `bn-manager`, `block-service`, both bins…). Placing the
new `TruncatedRoot`, the field constants, and `new_request_id()` here means downstream code gets all
logging primitives from **one import** with **no new edges**. The truly-lowest crate `rvc-eth-types`
is excluded because the `rvc-architecture-tests` gate pins it to **zero out-edges** and it lacks
`uuid`; `telemetry` is excluded because most signing crates do not (and should not) depend on it.

---

## Module Dependency Graph

Relevant slice of the 23-crate workspace, showing the **observability** edges. `→` = production
dependency (already present unless marked **NEW**).

```text
eth-types  ─────────────────────▶ (zero out-edges; pinned by arch-tests)
   ▲
   │
crypto (owns crypto::logging: TruncatedPubkey, RedactedUrl, TruncatedRoot[NEW],
   ▲   ▲   ▲   fields[NEW], new_request_id[NEW])  ── deps: eth-types, uuid, hex, tracing, url
   │   │   │
   │   │   └──────────── secret-provider ─▶ crypto, metrics
   │   │
   │   └────── signer ─▶ crypto, slashing, doppelganger, metrics, eth-types
   │                         (gate.rs spawn_blocking: re-enter captured span [NEW behavior])
   │
   └── beacon ─▶ crypto, eth-types, telemetry   (already calls inject_trace_context)

telemetry (owns propagation: inject_trace_context, set_parent_from_headers[NEW])
   ▲   ▲      deps: opentelemetry*, tracing-opentelemetry, tracing-subscriber, logroller
   │   │      (depends on NOTHING workspace-internal — it is a near-leaf sink)
   │   │
   │   └──────────── bin/rvc        ─▶ … telemetry (existing)
   │
   └──── bin/rvc-signer  ─▶ telemetry [NEW edge], signer, crypto, slashing
                              (:9000 sign handler calls set_parent_from_headers)
```

**Cycle check (verified against `cargo metadata` semantics):**

- `crypto::logging` additions (`TruncatedRoot`, `fields`, `new_request_id`) need only deps `crypto`
  already has (`core::fmt`, `hex`, `uuid`, `tracing`). **No new edge. No cycle.**
- `telemetry::propagation::set_parent_from_headers` needs only `opentelemetry` + `tracing-opentelemetry`,
  which `telemetry` already has. **No new edge. No cycle.**
- The **single new production edge** is `bin/rvc-signer → telemetry`. `telemetry` depends on **no
  workspace crate**, so an edge *into* it from a binary is a leaf attachment — **provably acyclic**.
  `beacon` and `bin/rvc` already depend on `telemetry`, so this is the established direction.

**Verify (machine-checked):** the existing `crates/architecture-tests/tests/architecture_no_cycles.rs`
gate parses `cargo metadata --no-deps`, asserts the production graph is acyclic, enforces `FORBIDDEN`
edges, and pins `ZERO_OUT_EDGE_IF_PRESENT = ["rvc-eth-types", …]`. This candidate **rides that gate**:
adding `bin/rvc-signer → rvc-telemetry` keeps it green (no cycle, eth-types untouched). The candidate
also recommends extending that test's policy tables to lock the new boundary (see *Enforcement
Architecture → Gate 6*).

---

## Module Details

### Module: `crypto::logging` (redaction primitives + canonical fields + request_id)

**Responsibility:** Be the single, low-level, dependency-light home for every reusable logging
primitive that downstream crates need — redaction wrappers, canonical field-name constants, and
`request_id` minting — so the standard is consumed from one import with no new dependency edges.

**Domain entities (logical):**
- `TruncatedPubkey<'a>` — existing; renders `0x{first10}...{last8}`, zero-alloc `Display`, warns+falls
  back on double-`0x`. **Unchanged** (settled format, PRD).
- `RedactedUrl<'a>` — existing; strips `user:pass@` via `url::Url`, falls back to raw on parse failure.
  **Unchanged.**
- `TruncatedRoot<'a>` — **NEW**; zero-alloc `Display` wrapper for 32-byte signing roots / block roots /
  head roots / signatures at `trace`, mirroring `TruncatedPubkey`'s shape and laziness. Resolves PRD
  Open Q1 ("truncate, don't omit") by giving it a primitive.
- `fields` (**NEW submodule**) — `pub const` string constants for the canonical registry
  (`SLOT = "slot"`, `EPOCH = "epoch"`, `VALIDATOR_INDEX = "validator_index"`, `PUBKEY = "pubkey"`,
  `DUTY = "duty"`, `REQUEST_ID = "request_id"`, `BN_URL = "bn_url"`, `COMMITTEE_INDEX = "committee_index"`,
  `SUBCOMMITTEE_INDEX = "subcommittee_index"`, `HEAD = "head"`, `BLOCK_ROOT = "block_root"`). These make
  field names greppable, refactor-safe, and lint-checkable.
- `new_request_id()` (**NEW**) — `uuid::Uuid::new_v4()`, matching the `keymanager-api` precedent
  (`handlers.rs:348/800`); returned as a `Uuid` so callers render it with `%` (zero-alloc when
  disabled).

**Data store:** none. Pure functions / value types.

**Public API (interface to other modules):**

| Item | Signature | Output | Description |
|---|---|---|---|
| `TruncatedPubkey::new` | `(hex: &str) -> Self` | `Display` | Truncated pubkey, `%`-renderable (existing) |
| `RedactedUrl` | `(&str)` tuple-struct | `Display` | Credential-stripped URL (existing) |
| `TruncatedRoot::new` | `(bytes: &[u8]) -> Self` | `Display` | `0x{first10}…{last8}` of a root/sig, `%`-renderable (NEW) |
| `fields::*` | `pub const &str` | name | Canonical field-name constants (NEW) |
| `new_request_id` | `() -> uuid::Uuid` | `Uuid` | Mint one correlation id per logical op (NEW) |

**`TruncatedRoot` design (concrete):**

```rust
/// Displays a 32-byte root/signature as `0x{first10}...{last8}` for `trace`-level use.
/// Zero-allocation Display: when the tracing level is disabled, `fmt` is never called.
/// Glyph: ASCII `...` (matches the settled `TruncatedPubkey` format; honors R9 — one glyph).
pub struct TruncatedRoot<'a>(pub &'a [u8]);
impl std::fmt::Display for TruncatedRoot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // hex-encode lazily into the formatter; 32 bytes → 64 hex chars → first10/last8.
        // For short/odd inputs, fall back to the full lower-hex (never panic).
        // (Impl mirrors TruncatedPubkey: no String allocation on the hot path.)
        ...
    }
}
```

**Events published / consumed:** none (these are sinks-of-values used *by* other modules' events).
`TruncatedPubkey` itself emits one `warn!` on a malformed double-`0x` input (existing, retained).

**Internal structure (within `crates/crypto/src/`):**
```text
logging.rs            # TruncatedPubkey, RedactedUrl, TruncatedRoot (one file, existing + NEW)
logging/fields.rs     # OR `mod fields { … }` inside logging.rs — canonical name constants (NEW)
# new_request_id() lives in logging.rs (uuid already a crypto dep)
```

**Key design decisions:**
- **Co-locate to avoid edges.** Everything goes in `crypto::logging` because `crypto` is the lowest
  crate that already (a) hosts the wrappers, (b) has `uuid`/`hex`, and (c) is depended on by all
  signing-adjacent crates. Splitting into a new `obs` crate would add 23 potential new edges for zero
  benefit and risk a cycle with `crypto`.
- **Constants, not an enum, for field names.** `pub const &str` keeps them usable directly as
  `tracing` field keys and lets the optional conformance lint compare emitted keys against the set.
- **Return `Uuid`, not `String`, from `new_request_id`.** Rendering with `%` stays zero-alloc when the
  span level is disabled; a pre-built `String` would allocate unconditionally.

**Failure modes:** all wrappers are infallible `Display` impls that fall back to the raw/full value
rather than panic (a garbled log line is acceptable; a panic on the sign path is not). `TruncatedRoot`
on a non-32-byte input renders full lower-hex.

---

### Module: `telemetry::propagation` (inbound trace-context extractor)

**Responsibility:** Provide the inbound W3C trace-context **extractor** so the `:9000` sign handler
continues the caller's trace instead of starting a fresh root — the inverse of the existing
`inject_trace_context`.

**Domain entities:**
- `HeaderExtractor<'a>` — **NEW**; implements `opentelemetry::propagation::Extractor` over
  `http::HeaderMap` (what axum hands the handler). Mirror of the existing `HeaderInjector`.
- `set_parent_from_headers(span, headers)` — **NEW**; extracts the remote context via the global
  `TraceContextPropagator` and attaches it with `OpenTelemetrySpanExt::set_parent`.

**Data store:** none.

**Public API:**

| Item | Signature | Description |
|---|---|---|
| `set_parent_from_headers` | `(span: &tracing::Span, headers: &http::HeaderMap)` | Make `span` a child of the W3C context on `headers`, if any; no-op if absent (graceful degradation) |

**Internal structure (within `crates/telemetry/src/propagation.rs`):** add `HeaderExtractor` +
`set_parent_from_headers` next to the existing `HeaderInjector`/`inject_trace_context`; re-export from
`telemetry::lib` (`pub use propagation::{inject_trace_context, set_parent_from_headers}`).

**Key design decisions:**
- **Compose into the existing module; do not add a crate.** Research evaluated
  `axum-tracing-opentelemetry` and rejected it (pre-1.0, opinionated init that `telemetry` already
  owns). The 20-line extractor is additive and keeps the sampler/propagator ownership in one place.
- **`http::HeaderMap`, not `reqwest::header::HeaderMap`.** axum hands the handler `http::HeaderMap`;
  both `reqwest` and `axum` re-export the same `http` crate, so the inbound extractor uses `http`
  while the existing outbound injector stays `reqwest`-typed.
- **Keep the sampler exactly as-is.** `ParentBased(TraceIdRatioBased(rate))` makes a duty trace
  all-or-nothing *once the boundary is bridged*; bridging is the only change needed.

**Failure modes:** if no `traceparent` is present (Prysm/Lighthouse may not send one), `extract`
yields an empty context and the span stays a root — identical in spirit to the existing inject no-op.
No panic, no behavior change to signing.

**Enforcement:** a unit test asserts that, given a synthetic `traceparent`, the handler span's OTel
parent is non-zero (continues the trace); and that `pubkey` recorded on that span is truncated in the
exported attributes (captured-subscriber).

---

### Module: Subscriber-init reconciliation (`bin/rvc` ⟷ `bin/rvc-signer`)

**Responsibility:** Give both binaries **one** default level (`info`), **one** EnvFilter precedence
(env `RUST_LOG` overrides the config/flag default), and a shared output-format selection — without
touching the OTLP layer, file appender, or non-blocking-writer contracts.

**Current divergence (verified in-tree):**

| Aspect | `bin/rvc` (`main.rs:774` `init_logging`) | `bin/rvc-signer` (`main.rs:234`) |
|---|---|---|
| Filter | `EnvFilter::try_from_default_env().unwrap_or_else(\|_\| EnvFilter::new(level))` (config default `info`, `RUST_LOG` overrides) | `EnvFilter::from_default_env()` (no fallback → unset `RUST_LOG` yields the bare default, **not** `info`) |
| Layers | OTLP + file + `fmt` + `Identity`-padding workaround | bare `tracing_subscriber::fmt()…init()` — no OTLP, no file |
| Default level | `info` (via flag default) | effectively undefined when `RUST_LOG` unset |

**Reconciled design:**
- Extract a shared helper — recommended location `telemetry` (the crate both bins already can depend
  on; `bin/rvc-signer` gains the `→ telemetry` edge anyway for the extractor) — that builds the
  `EnvFilter` with the **documented precedence**: *if `RUST_LOG` is set, use it; else use the
  configured default level (`info`)*. This is exactly `bin/rvc`'s current `try_from_default_env().
  unwrap_or_else(|_| EnvFilter::new(level))` logic, promoted to a named, tested helper, e.g.
  `telemetry::env_filter_or(level)`.
- Both binaries call the helper with `info` as the default. `bin/rvc-signer` keeps its `fmt()`-only
  output for now (no OTLP/file is in scope to *add* to it, only the level/precedence parity), but uses
  the same filter-construction path so unset `RUST_LOG` means `info`, identically to `bin/rvc`.
- Output-format selection (pretty default; JSON as the sanctioned P2-3 profile) is centralized in the
  helper's documentation; no functional change to the existing `fmt` layer.

**Key design decisions / ADR pointers:** see **ADR-004** (one default level + precedence) and
**ADR-005** (file-vs-console level). The reconciliation deliberately does **not** add OTLP/file
layers to `bin/rvc-signer` (out of scope — that would be a telemetry change, not an init-consistency
change); it only unifies *default level + precedence + format selection*.

**Failure modes:** if `RUST_LOG` is malformed, the helper falls back to the configured default (never
panics, never goes silent). Init tests in both binaries assert: (a) unset `RUST_LOG` → effective level
`info`; (b) `RUST_LOG=debug` overrides to `debug`; (c) per-module directive
(`rvc_signer_bin::http_api=trace`) raises only that target.

---

### Module: Level taxonomy + span-instrumentation strategy (applied across crates)

**Responsibility:** Make the 5-level taxonomy and spans-first correlation a concrete,
machine-checkable house style on the hot paths, honoring research **R1** (instrument `fields(...)`
evaluate **eagerly**).

**The taxonomy (rs-vc house standard; primary anchor = `tracing::Level` docs, per R8):**

| Level | Audience | Contains | Static cap in release |
|---|---|---|---|
| `error` | operator | intended action did not complete | present |
| `warn` | operator | handled / degraded-but-progressing | present |
| `info` | operator | **milestones only** — the heartbeat (low, bounded volume) | present, runtime-on |
| `debug` | developer | decision points / internal state | present, runtime-gated by `RUST_LOG` |
| `trace` | developer | wire-level / per-item, highest volume | **compiled out** (`release_max_level_debug`) |

**Span conventions (concrete, the R1-correct version):**

1. **`level=` on every hot-path `#[instrument]`.** The attribute defaults to **INFO**; on
   per-slot/per-validator fns that floods the heartbeat. Hot-path spans are `level = "debug"` (or
   `"trace"`). *This is the single most common mis-use to audit for* (research rule 3).
2. **`skip_all` is the default on any secret- or large-arg fn**, then re-add only chosen fields via
   `fields(...)`. `skip_all` is both a redaction control (no auto-`Debug` of `&SecretKey`/
   `&BeaconBlock`/payloads) and a perf control. **Bare `#[instrument]` on a sign/decrypt fn is
   forbidden** and lint-flagged.
3. **`fields(...)` carries only `Copy` scalars / cheap values (R1).** Because `#[instrument]`
   evaluates `fields(...)` **eagerly on every call regardless of whether the span level is enabled**,
   expensive Display/Debug (a `hex::encode`, a `serde_json`, a hashing of a root) must **not** go in a
   `fields(...)` expression. Put such work in an `event!`-family macro field (which *is* gated by the
   level check) or behind `tracing::enabled!`. A `%TruncatedPubkey`/`%TruncatedRoot` in
   `#[instrument(fields(...))]` runs its `Display` on every call — fine for the cheap pubkey case, but
   the rule is "scalars in instrument fields; redaction wrappers on event macros / `record()`."
4. **Spans-first.** Stamp `slot`/`epoch`/`validator_index`/`pubkey`/`duty`/`request_id`/`committee_index`
   on the span once; child events inherit them. `network` stays a resource attribute (already set in
   `telemetry::init`); never duplicated per event.
5. **Late-bound fields via `field::Empty` + `record()`.** Identifiers only known after a body parses
   (`:9000` `slot`/`duty`/`pubkey`) are declared `Empty` at span creation and filled with
   `span.record(...)`. **`record()` on an undeclared field is silently dropped** — the #1 cause of a
   vanishing attribute (mirror the existing `http.status_code = Empty` pattern in `beacon::client`).
6. **Async correctness.** Never hold `Span::enter()` across `.await`; prefer `#[instrument]`,
   `.instrument(span)`, `.in_current_span()`/`Span::or_current()` for `tokio::spawn`, and
   `Span::in_scope()` for sync closures. For the `SigningGate.sign_*` **`spawn_blocking`** closures
   (`crates/signer/src/gate.rs:270`), capture `Span::current()` and `let _e = span.enter()` **inside**
   the closure (safe — no `.await` there) so `crypto`/`slashing` events emitted in the blocking section
   stay correlated. This is the accurate R3 fix (the `sign_*` methods **are** already instrumented; the
   gap is the detached blocking section).
7. **Coarse spans on the hottest async fns** (one span per phase, not per inner await): an *enabled*
   `#[instrument]` async fn enters/exits its span on **every poll**, so coarse granularity bounds the
   per-poll cost when `debug`/`trace` is on under large validator counts.
8. **Namespace normalization.** Reconcile the orchestrator's `rvc.`-prefixed fields/spans
   (`rvc.slot`, `rvc.orchestrator.process_slot`) to the unprefixed canonical registry (`slot`) — in
   OTLP, `rvc.slot` and `slot` are *different* attribute keys, so dashboards grouping by `slot` miss
   the prefixed spans.

**`info` heartbeat shape (operator familiarity, Lighthouse-like):** one milestone per completed duty
carrying `slot`; build/sign at `debug`, publish at `info` (the Lodestar `Signed`=debug /
`Published`=info split); a once-per-slot liveness tick; a `time_into_slot`/`delay` timing field
(Nimbus's most useful operator signal). Milestone set at `info`: validators loaded, BN connected,
epoch boundary, attestation/aggregate published, block proposed, sync-committee message/contribution,
validator registration. Use field `head` for the attested head, `block_root` for a proposed block,
`committee_index`/`subcommittee_index` (Lighthouse-compatible; the primary migration source).

**Enforcement:** captured-subscriber tests assert representative hot-path events fire at the **intended
level** with the **intended fields**; clippy enforces `skip_all` on the secret-taking fns (via the
disallowed-methods gate catching the laundering sinks); the optional P2-4 conformance lint flags
non-canonical field names against `crypto::logging::fields`.

---

### Module: Zero-overhead-when-disabled harness (P0-6)

**Responsibility:** Turn "disabled `debug!`/`trace!` perform no allocation/formatting/hashing" from a
claim into a **tested invariant**, and physically remove `trace!` from release binaries.

**Two mechanisms + a verification harness:**

1. **Compile-time static cap (`release_max_level_debug`) on both binaries.** Add
   `tracing = { workspace = true, features = ["release_max_level_debug"] }` to `bin/rvc/Cargo.toml`
   and `bin/rvc-signer/Cargo.toml`. In `--release`, `trace!` (and below-cap spans) compile to
   **nothing**, while `debug!` stays runtime-switchable via `RUST_LOG` (PRD: operators escalate to
   `debug` in prod without a separate build). This is the **strongest** form of P0-6 and also
   neutralizes any residual `EnvFilter` dynamic-directive cost (nothing left to be called on). **Do
   not** enable tracing's `log` bridge feature (it can re-introduce cost under a static cap). See
   **ADR-001**.
2. **Runtime interest cache + `enabled!` guards + zero-alloc `Display` wrappers.** Disabled
   events/spans are a cached-integer load + branch; field expressions are not evaluated *provided the
   work is inside the macro field expression*, not precomputed into a local. Any field doing real work
   (`hex::encode`, `serde_json`, hashing) is gated behind `tracing::enabled!(Level::TRACE)` (the
   existing `beacon::client:149` pattern) or expressed as a zero-alloc `Display` wrapper
   (`TruncatedPubkey`/`TruncatedRoot`).

**Verification harness (net-new; no bench infra exists today):**
- **Counting-`#[global_allocator]` zero-alloc test (the *precise* gate).** A dependency-free allocator
  wrapping `std::alloc::System` bumps an `AtomicUsize`; a `#[test]` under an `info`-level subscriber
  (trace/debug OFF) asserts `assert_eq!(allocs_after, allocs_before)` across a `sign_attestation` /
  `sign_block` call and around one coordinator/per-slot phase. This is the precise gate because a ~1 ns
  span is below `criterion`'s measurement floor next to a BLS sign. Runs under `cargo nextest run
  --workspace`. See **ADR-006**.
- **`criterion` sign-path bench (latency sanity).** Compare `no_subscriber` / `subscriber_info`
  (debug spans disabled) / `subscriber_trace` regimes; pass if `info ≈ no_subscriber` within noise.
  Lives in `crates/crypto/benches/sign_path.rs`; run via `cargo bench` (not a blocking PR gate — it is
  a regression guard).

**Failure modes:** if a future contributor adds an unguarded expensive field, the zero-alloc test
fails on the sign/slot paths specifically. The criterion bench catches a gross latency regression.

---

## Cross-Cutting Concerns

### Authentication & Authorization

Unchanged by this initiative. The one intersection: the `:9000` audit log already emits exactly one
structured entry per request (success=`info`, rejection=`warn`) carrying **metadata only** (pubkey
identifier, Web3Signer `type`, outcome, peer CN, backend, latency) and **never** the body/root/
signature (`bin/rvc-signer/src/http_api/routes.rs`). The redaction policy formalizes that this audit
line, and any new log on the path, stays metadata-only. The CN is never an authorization gate.

### Logging & Observability (the subject of this document)

- **Correlation** is spans-first; `request_id` (minted via `crypto::logging::new_request_id`) plus W3C
  `traceparent` follow a signing/API request end to end, **including across the `:9000` hop** once
  `set_parent_from_headers` is wired. An additive `x-request-id` header echoes the human-readable id so
  both sides log the same value even when a request arrives without a `traceparent`.
- **OTLP mapping** is unchanged: span fields → span attributes, events → span events; `otel.kind =
  "server"` on the inbound `:9000` span, `"client"` on outbound beacon/signer calls.
- **Resource attributes** (`network.name`, `service.version`) stay in `telemetry::init`; never
  duplicated per event.

### Error Handling

- **`error` only when an intended action did not complete**; recoverable/degraded → `warn`. **Log once**
  at the layer that decides terminal (CLAUDE.md); lower layers return the `Result`. `#[instrument(err)]`
  is used only at that terminal layer, never at every layer (else it double-logs). Rewriting
  error-handling control flow is a **non-goal**; this is a level-categorization + dedup pass only.

### Configuration

- Level/format are controlled by `RUST_LOG`/`EnvFilter` with **env-overrides-config** precedence,
  reconciled across both binaries (see the subscriber-init module). The static cap
  (`release_max_level_debug`) is a Cargo-feature decision baked into the binaries, documented in the
  standard. No runtime config change to the OTLP/file/sampler stack.

---

## Data Flow Diagrams

### Signing request across the `:9000` Web3Signer boundary (the correlation showcase)

```text
bin/rvc (client side)
  orchestrator duty span  ── slot/epoch on span (ParentBased root sampler decides keep/drop)
  mint request_id         ── crypto::logging::new_request_id()  → Uuid
  open client span        ── otel.kind="client", request_id=%id, slot, duty=%duty,
                              pubkey=%TruncatedPubkey
  inject_trace_context()  ── writes W3C traceparent (trace id + sampled flag) into headers
  + x-request-id header   ── echoes the human-readable id
       │  POST /api/v1/eth2/sign/{id}
       ▼
bin/rvc-signer (server side, :9000)
  sign handler span       ── #[instrument(skip_all, fields(otel.kind="server",
                              request_id=Empty, slot=Empty, duty=Empty, pubkey=Empty))]
  set_parent_from_headers ── <<< THE BRIDGE: span becomes child of caller's trace;
                              ParentBased sampler honors the upstream keep/drop
  read x-request-id       ── span.record("request_id", …)  (or mint if absent)
  parse body → resolve    ── span.record("slot"/"duty"/"pubkey"=%TruncatedPubkey)
  SigningGate.sign_*      ── already #[instrument(name="rvc.sign.*", skip_all, fields(…))]
    spawn_blocking {      ── capture Span::current(); let _e = span.enter();   <<< R3 fix
      stage (slashing) → BLS sign (no secret in any field) → commit
    }
  audit log (info/warn)   ── metadata only: pubkey id, type, outcome, CN, backend, latency
  every event in handler+gate inherits slot/pubkey/duty/request_id from the span (no repeat)
```

### Operator `info` heartbeat (healthy client, low volume)

```text
startup     ── info  "rvc starting" {version, network, commit}
validators  ── info  "Loaded validator keys" {count}
BN connect  ── info  "connected to beacon node" {bn_version}
per epoch   ── info  "epoch boundary processed" {epoch}
per duty    ── debug "Signed attestation" {slot, duty} ; info "published attestation" {slot, head}
per slot    ── info  once-per-slot liveness tick {slot, time_into_slot}
            (duty cache hit/miss, BN selection, slashing inputs → debug ; wire framing → trace)
```

---

## Infrastructure & Deployment

### Deployment Model

Modular monorepo (existing Cargo workspace); no change to deployable units. The two production
binaries (`bin/rvc`, `bin/rvc-signer`) gain the `release_max_level_debug` feature and the reconciled
init helper. No new runtime services; no new ports beyond the unchanged `:9000` / `:9101` / metrics.

### Scaling Strategy

Unchanged. The only scaling-relevant logging decision is keeping `info` low-volume (milestones only)
so it is safe as a production default at large validator counts, with P2-1 sampling as the backstop
for high-volume `trace`/`debug` sites if verbose is ever enabled under load.

### Adoption / Rollout Path (replaces "service extraction"; phased across the 23 crates)

The standard rolls out enforcement-first, so each phase ships its **gate** alongside its code.

| Phase | Scope (PRD mapping) | Crates touched | Gate landed in this phase |
|---|---|---|---|
| **0 — Standard + primitives + gates skeleton** | P0-1; add `TruncatedRoot`, `fields`, `new_request_id`; `set_parent_from_headers` | `crypto`, `telemetry` | `clippy.toml` `disallowed-methods` seeded; gitleaks PR job added; arch-tests policy tables extended; standard doc committed under `plan/logging/` |
| **1 — Hot paths + safety** | P0-2/3/4/6 | `crypto`, `signer`, `bin/rvc-signer` (:9000), `beacon`, `bn-manager`, `slashing`, orchestrator (`crates/rvc`), `duty-tracker`, `builder` | captured-subscriber redaction + level/field tests in the 4 high-risk crates; **counting-allocator zero-alloc test**; `release_max_level_debug` on both bins |
| **2 — Init consistency** | P0-5 | `telemetry` (helper), `bin/rvc`, `bin/rvc-signer` | init parity tests in both binaries (default level + precedence + per-module directive) |
| **3 — Breadth** | P1-1/2/3 | gap crates: `rvc-keygen` (mnemonic — treat as high-risk), `signer-registry`, `eth-types`, `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`; normalize `crates/rvc`/`bin/rvc`/`bin/rvc-signer`/`signer`/`bn-manager`/`slashing`/`crypto` | optional field-name conformance lint (P2-4) wired as advisory; namespace-normalization captured-subscriber checks |
| **4 — Docs & polish** | P1-4; then P2 | docs | operator guide; P2 sampling / dynamic reload / JSON profile as capacity allows |

**Per-crate readiness note (the "extraction-path" analogue):** each crate is rated for standard
conformance — **conformant** (well-covered: `crates/rvc`, `bin/rvc`, `bin/rvc-signer`, `signer`,
`bn-manager`, `slashing`, `crypto` — needs only normalization in Phase 3); **gap** (near-silent:
`rvc-keygen`, `signer-registry`, `eth-types`, `propagator`, `validator-store`, `doppelganger`,
`timing`, `metrics` — Phase 3 brings to standard); **bridge-blocked** (the `:9000` correlation can't be
end-to-end until `set_parent_from_headers` lands in Phase 0 and is wired in Phase 1).

---

## Enforcement Architecture (the differentiator — how each gate rides the existing CI)

This is the heart of the enforcement-led candidate. Six gates, each attached to a step that **already
exists** (except one tiny new gitleaks job), fail-closed at **0 findings**, with **no new mandatory
toolchain for P0**.

### Gate 1 — `clippy.toml` `disallowed-methods` (secret sinks) — rides `cargo clippy … -D warnings`

`clippy.toml` today contains only `msrv = "1.92"`. Extend it (the existing `check` job already runs
`cargo clippy --workspace --all-targets -- -D warnings`, which fails on any warning):

```toml
msrv = "1.92"

disallowed-methods = [
  { path = "secrecy::ExposeSecret::expose_secret",
    reason = "expose_secret() output must never reach a log macro; decrypt at the call site only" },
  { path = "rvc_crypto::bls::SecretKey::raw_bytes",
    reason = "raw key bytes escape the redacted newtype; do not log or format" },
  { path = "rvc_crypto::bls::SecretKey::to_bytes",
    reason = "raw key bytes escape the redacted newtype; do not log or format" },
]
```

- **Scope, don't ban, the legitimate uses.** `expose_secret`/`to_bytes`/`raw_bytes` are needed at
  decrypt/sign call sites → annotate exactly those lines with a small, reviewed, greppable
  `#[allow(clippy::disallowed_methods)]`. The lint then flags any **new** use elsewhere.
- **Stated limitation (in the policy):** `disallowed-methods` matches **named paths only** — it cannot
  see a value already laundered into a `String`/`&str`. Acceptable because the **type layer** makes the
  implicit path impossible and **Gate 3/4** test the runtime result.
- **No new toolchain.** Pure config; runs on the existing clippy step.

### Gate 2 — `gitleaks` PR job (source + emitted log sample) — one small new CI job

Add a job to `.github/workflows/ci.yml` (the only net-new CI infra). It (a) runs `gitleaks` (rule +
entropy, fast, SARIF, blocking) over the **source tree**, and (b) **emits a representative log
sample** — runs the captured-subscriber conformance tests (or a tiny harness) at `trace` level,
captures stdout to a file, and runs `gitleaks` over **that emitted output**. Scanning the *emitted*
log, not just source, is what actually verifies "no secret reached a sink." `trufflehog`
verification-first mode is reserved as a **scheduled** full sweep (not the blocking gate).

### Gate 3 — Captured-subscriber / `tracing_test` conformance tests — ride `nextest`

`#[tracing_test::traced_test]` tests in `crypto`, `signer`, `bin/rvc-signer`, and `rvc-keygen` that
fire each high-risk log line and assert, via `logs_contain(...)`, that the output **contains** the
truncated/redacted form and **does NOT** contain the raw secret (the existing
`test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` is the proven model). The same harness
asserts **intended level** and **intended fields** for representative hot-path events. `tracing-test`
is already a workspace dev-dependency; these run under the existing `cargo llvm-cov nextest
--workspace` coverage job.

### Gate 4 — Counting-`#[global_allocator]` zero-alloc test (P0-6) — rides `nextest`

The dependency-free counting allocator + `assert_eq!(allocs_when_disabled, baseline)` on the sign and
per-slot paths (detailed in the *Zero-overhead* module). This is the **precise** P0-6 gate. Runs under
`nextest`; the `criterion` bench is the non-blocking latency companion.

### Gate 5 — Optional canonical-field-name conformance lint (P2-4) — advisory first

A conformance check that flags emitted field keys not present in `crypto::logging::fields`. Two viable
forms: (a) a captured-subscriber test that asserts a curated set of hot-path events use only canonical
keys (no new toolchain — preferred for P0/P1, rides `nextest`); (b) a dylint dataflow lint (nightly —
**P2 only**, never a P0 blocker). Land form (a) as advisory in Phase 3, escalate to blocking once the
field set stabilizes.

### Gate 6 — `rvc-architecture-tests` DAG gate (no cycles) — already in CI

The existing `crates/architecture-tests/tests/architecture_no_cycles.rs` already asserts the
production graph is acyclic, enforces `FORBIDDEN` edges, and pins `ZERO_OUT_EDGE_IF_PRESENT`
(including `rvc-eth-types`). This candidate **rides it unchanged** for the no-cycle guarantee, and
recommends extending its policy tables to **lock the new boundary**: add `rvc-signer-bin →
rvc-telemetry` as an expected/allowed edge and keep `rvc-eth-types` at zero out-edges (so a future
contributor cannot "fix" a field-constant import by adding a `uuid`/`telemetry` edge to `eth-types`).

**Gate-to-rule traceability (every normative rule has an automated owner):**

| Normative rule | Primary gate | Backstop |
|---|---|---|
| No raw secret at any level | Gate 1 (clippy sinks) | Gate 3 (runtime absent) + Gate 2 (emitted scan) |
| Pubkeys/URLs/roots only via wrappers | Gate 3 (captured-subscriber) | reviewer checklist (4 crates) |
| `skip_all` on secret-taking fns | Gate 1 (laundering sinks) | reviewer checklist |
| Canonical `snake_case` field names | Gate 5 (advisory→blocking) | standard doc (review rubric) |
| Intended level per event | Gate 3 (level assertions) | — |
| Zero alloc when disabled | Gate 4 (counting allocator) | criterion bench |
| `trace` absent in release | `release_max_level_debug` (compile) | Gate 4 |
| No circular dependency | Gate 6 (DAG) | — |

---

## Technology Choices

| Concern | Choice | Rationale |
|---|---|---|
| Tracing framework | `tracing` 0.1 / `tracing-subscriber` 0.3 (existing) | PRD Non-Goal to swap; compose in |
| Export | `tracing-opentelemetry` 0.32 / OTLP 0.31 (existing) | Existing pipeline; span fields → attributes |
| Redaction primitives | `crypto::logging` zero-alloc `Display` wrappers (extend with `TruncatedRoot`) | Settled format; zero-alloc when disabled; one home, no new edge |
| `request_id` | `uuid::Uuid::new_v4()` via `crypto::logging::new_request_id` + `x-request-id` header | Matches `keymanager-api` precedent; `uuid` already a `crypto` dep |
| Secret sink lint | `clippy.toml` `disallowed-methods` | Rides existing `-D warnings`; no new toolchain |
| Secret scan | `gitleaks` (blocking PR), `trufflehog` (scheduled) | gitleaks is the standard blocking gate; emitted-log scan proves runtime |
| Conformance tests | `tracing-test` captured subscriber (existing dev-dep) | Proven in-tree model; runs under `nextest` |
| Zero-alloc proof | dependency-free counting `#[global_allocator]` | Precise gate below criterion's floor; no heavy dep (vs `dhat`) |
| Static cap | `release_max_level_debug` on both bins | `trace` compiled out; `debug` stays `RUST_LOG`-switchable in prod |
| DAG enforcement | existing `rvc-architecture-tests` (`cargo metadata` parse) | Already in CI; no new dep (P6 rule: no new external dep there) |

---

## ADRs (Architecture Decision Records)

### ADR-001: Static level cap = `release_max_level_debug` (not `_info`)
- **Status:** Accepted
- **Context:** P0-6 requires disabled verbose logging to be free; the PRD also requires operators to
  escalate to `debug` in prod via `RUST_LOG` without a separate build.
- **Decision:** Compile `tracing` with `release_max_level_debug` on **both** binaries. `trace!` (and
  below-cap spans) are physically removed from `--release`; `debug!` stays runtime-gated.
- **Alternatives considered:** `release_max_level_info` (removes `debug` too, but then `RUST_LOG=debug`
  does nothing in prod — contradicts the escalation requirement); no static cap (keeps all levels,
  loses the strongest P0-6 guarantee and leaves residual `EnvFilter` cost).
- **Consequences:** Strongest zero-cost form; neutralizes dynamic-`EnvFilter` cost; `trace` in prod
  requires a debug/test build (acceptable — `trace` is "never on in prod"). Must **not** enable
  tracing's `log` bridge (re-introduces cost under a cap). Verified by Gate 4.

### ADR-002: `request_id` source = fresh `uuid::Uuid::new_v4()` + `x-request-id` header
- **Status:** Accepted
- **Context:** A single human-followable correlator must survive the `:9000` hop, including when a
  caller sends no `traceparent`.
- **Decision:** Mint `request_id` with `uuid::Uuid::new_v4()` (via `crypto::logging::new_request_id`),
  carry it on the span, and echo it across `:9000` via an additive `x-request-id` header; the signer
  reads it (or mints one if absent).
- **Alternatives considered:** Derive `request_id` from the OTel trace/span id (one fewer header, but
  not human-friendly and absent when no trace context flows); no explicit id (relies solely on
  `traceparent`, which breaks for clients that don't send one).
- **Consequences:** Matches the in-tree `keymanager-api` precedent; `uuid` already a `crypto` dep; one
  extra header, ignored by clients that don't send it; both sides log the same value. W3C `traceparent`
  still carries the trace itself.

### ADR-003: Redaction primitives + canonical fields + `request_id` live in `crypto::logging`
- **Status:** Accepted
- **Context:** Shared primitives need one home that introduces no dependency cycle across 23 crates.
- **Decision:** Host `TruncatedPubkey`/`RedactedUrl`/`TruncatedRoot`, the `fields` name constants, and
  `new_request_id()` in `crypto::logging`. Host the inbound trace-context extractor in
  `telemetry::propagation` (the only crate with OTel deps).
- **Alternatives considered:** A new bottom `obs`/`logging` crate (adds up to 23 new edges, risks a
  cycle with `crypto`, zero benefit); `eth-types` (pinned to zero out-edges by the arch-tests gate and
  lacks `uuid`); `telemetry` (most signing crates neither do nor should depend on it).
- **Consequences:** Downstream gets all primitives from one import with **no new edge**; the single new
  production edge in the whole initiative is `bin/rvc-signer → telemetry`, which is provably acyclic
  (`telemetry` has no workspace deps). Verified by Gate 6.

### ADR-004: One default level (`info`) + EnvFilter precedence (env overrides config)
- **Status:** Accepted
- **Context:** `bin/rvc` and `bin/rvc-signer` diverge: `try_from_default_env().unwrap_or_else(|_|
  EnvFilter::new(level))` vs bare `from_default_env()` (no fallback → unset `RUST_LOG` is not `info`).
- **Decision:** Promote `bin/rvc`'s logic to a shared, tested helper in `telemetry`
  (`env_filter_or(level)`): if `RUST_LOG` is set use it, else default to `info`. Both binaries use it.
- **Alternatives considered:** Standardize on bare `from_default_env()` (surprises operators with a
  silent/odd default when `RUST_LOG` is unset); duplicate the logic per-binary (drifts again).
- **Consequences:** Identical default + precedence + format selection across both binaries; init parity
  tests assert it (Gate via `nextest`). Does **not** add OTLP/file layers to `bin/rvc-signer` (out of
  scope). No change to the OTLP/file/sampler contracts.

### ADR-005: File can be more verbose than console (file `debug`, console `info`) — contingent
- **Status:** Accepted (contingent on the existing appender supporting an independent level)
- **Context:** Lighthouse/Lodestar default the file to `debug` and the console to `info`; operators
  expect a richer on-disk record. `bin/rvc` already plumbs a separate `logfile_level`
  (`build_file_layer_config`, default = console level).
- **Decision:** Adopt file-more-verbose-than-console as the documented default *where the existing
  `logroller`/non-blocking-writer file layer supports an independent level filter* — which `bin/rvc`
  already exposes via `logfile_level`. Default `logfile_level` to `debug` when a logfile is configured;
  console stays `info`.
- **Alternatives considered:** Force file == console (simpler, but loses the familiar richer file);
  redesign the appender for independent levels (a telemetry redesign — out of scope).
- **Consequences:** Familiar to migrating operators; **no appender redesign** (uses the existing
  `level` field on `FileAppenderConfig`); documented in the operator guide (P1-4). If a future appender
  path cannot filter independently, fall back to file == console (documented, not assumed).

### ADR-006: Spans-first (correlation on spans), not per-event repetition
- **Status:** Accepted
- **Context:** Correlation must follow a duty across `.await`, `tokio::spawn`, crate boundaries, and the
  `:9000` hop, and feed the OTLP pipeline (span fields → attributes).
- **Decision:** Stamp canonical identifiers once on `#[instrument]` spans; child events inherit them;
  events carry only event-specific data. Late-bound identifiers use `field::Empty` + `record()`.
- **Alternatives considered:** Per-event fields on every call site (verbose, drift-prone — the exact
  `val_idx` vs `validator_index` failure the PRD kills; only justified for a flat backend that drops
  span fields); log-style flat events with no spans (throws away the main reason to be on `tracing`).
- **Consequences:** Lowest-friction for the existing OTLP pipeline; degrades gracefully (a flat backend
  still gets `trace_id`/`span_id`). Mitigation for a span-dropping backend: also stamp `request_id` on
  terminal events (PRD Open Q5). **Honors R1:** correlation scalars on instrument `fields(...)` are
  cheap; expensive redaction wrappers go on event macros / `record()`, not ungated instrument fields.

### ADR-007: Add `TruncatedRoot` rather than omit roots at `trace` (PRD Open Q1)
- **Status:** Accepted
- **Context:** Deep debugging wants the signing root / block root at `trace`, but the full value is
  noisy and the policy default is "omit or truncate."
- **Decision:** Add a zero-alloc `TruncatedRoot` (`0x{first10}…{last8}`, ASCII `...` glyph per R9)
  mirroring `TruncatedPubkey`; log roots/signatures **truncated** at `trace`, full value only on
  return values, never in a macro.
- **Alternatives considered:** Omit roots entirely (loses debugging signal); allow full roots at
  `trace` (noisy; R6 notes Lighthouse logs full roots inconsistently — not a precedent to copy).
- **Consequences:** Gives Open Q1's "truncate, don't omit" a primitive; zero-alloc when disabled;
  pubkeys stay truncated even at `trace` (Open Q2). Enforced by Gate 3 (captured-subscriber asserts the
  truncated form, raw root absent).

### ADR-008: Fix the `SigningGate` blocking-section span detachment (not a missing `#[instrument]`)
- **Status:** Accepted
- **Context:** Research R3 corrected the gap inventory: `SigningGate.sign_*` **are** instrumented; the
  real gap is the `spawn_blocking` closure (`gate.rs:270`) running on an OS thread that does not
  re-enter the parent `rvc.sign.*` span, detaching `crypto`/`slashing` events.
- **Decision:** Capture `Span::current()` before `spawn_blocking` and `let _e = span.enter()` **inside**
  the closure (safe — no `.await` there). No new `#[instrument]` is added to the gate methods.
- **Alternatives considered:** Add `#[instrument]` to gate methods (false fix — they already have it);
  `.instrument()` the closure (doesn't apply to a sync `spawn_blocking` closure).
- **Consequences:** Blocking-section events rejoin the duty/sign span; correlation is continuous. A
  correctness-of-correlation fix, not a cost fix; no signing-behavior change.

---

## Open Questions

These are forwarded to the implementation gate (the PRD's six Open Questions stand; the research
overview's gate questions are folded into the ADRs above where decided).

1. **Conformance-lint escalation timing.** When does Gate 5 (field-name conformance) move from advisory
   to blocking? Proposed: after Phase 3 normalizes existing `rvc.`-prefixed sites, so the field set is
   stable. Until then, advisory to avoid blocking unrelated PRs.
2. **gitleaks emitted-sample harness shape.** Should the emitted-log sample be produced by the existing
   captured-subscriber tests (reuse) or a dedicated tiny harness binary? Reuse is cheaper; a dedicated
   harness gives a more representative `trace`-level dump. Proposed: reuse first, add a harness only if
   coverage gaps appear.
3. **`telemetry` as the home for the shared init helper.** `env_filter_or` is proposed in `telemetry`
   so both bins share it; confirm `telemetry` is the right home vs a thin helper in each `main.rs`
   (the latter avoids the `bin/rvc-signer → telemetry` edge being load-bearing for *init*, but that
   edge is added anyway for the extractor).
4. **`x-request-id` vs OTel-derived id (ADR-002).** Confirmed as a header for human-readability; flag
   remains if the team prefers deriving from the span id to avoid the header.
5. **File-level default (ADR-005).** Confirm the `logroller` path honors an independent `level` for the
   file layer in all configurations before defaulting `logfile_level` to `debug`.

---

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Secret leakage via a new log statement** (esp. `crypto`/`secret-provider`/`signer`/`:9000`/`rvc-keygen`). | Security incident. | Defense-in-depth: type layer + Gate 1 (clippy sinks) + Gate 3 (runtime absent) + Gate 2 (emitted scan) + explicit 4-crate-plus-mnemonic sign-off. Fail-closed at 0 findings. |
| **`disallowed-methods` blind spot** (value laundered into `String`). | A bypass the lint can't see. | The **type layer** makes the implicit path impossible; Gate 3 tests the runtime result; Gate 2 scans emitted output. Stated as a known limitation in the policy. P2 dylint is the dataflow upgrade if ever needed. |
| **Hot-path latency regression** from new logging. | Missed duties / slashing-deadline pressure. | Gate 4 counting-allocator zero-alloc test (precise); `release_max_level_debug` removes `trace`; `enabled!` guards + `Display` wrappers; criterion sanity bench. |
| **`#[instrument(fields(...))]` eager evaluation (R1) sneaks in expensive work.** | Silent per-call cost even when span disabled. | House rule: scalars-only in instrument `fields`; redaction wrappers on event macros / `record()`. Gate 4 catches the sign/slot paths; reviewer rule + (P2-4) lint. |
| **Vanishing late-bound attribute** (`record()` on an undeclared field). | Missing correlation in traces. | House rule: declare every late-bound field as `field::Empty`; mirror the proven `http.status_code = Empty` pattern; boundary-span test asserts non-zero parent + recorded fields. |
| **A future edit adds a dependency cycle** (e.g. `eth-types → uuid`/`telemetry` to "import field constants"). | Build break / inverted layering. | Gate 6 (`rvc-architecture-tests`) pins `rvc-eth-types` to zero out-edges and the graph to acyclic; extend its tables to lock `bin/rvc-signer → telemetry`. Primitives live in `crypto::logging`, removing the temptation. |
| **Subscriber-init reconciliation changes default verbosity/format.** | Operator surprise. | ADR-004 documents precedence/default explicitly; init parity tests in both binaries assert unset-`RUST_LOG`→`info`, override, and per-module directive. |
| **`gitleaks` false positives block PRs.** | CI friction. | Tune `gitleaks` config (allow-list test fixtures); keep `trufflehog` verification-first as the scheduled deep sweep, not the blocking gate. |
| **Breaking the existing OTLP/file/propagation stack.** | Lost telemetry. | Non-Goal to redesign `telemetry`; only additive (`set_parent_from_headers`, `env_filter_or`); `TracingGuard`/shutdown/sampler contracts untouched; existing `telemetry` tests stay green. |

---

## Assumptions

1. **The existing stack stays and is composed into, not rebuilt:** `tracing` 0.1 / `tracing-subscriber`
   0.3 / `tracing-opentelemetry` 0.32 / `opentelemetry*` 0.31; the `telemetry` crate
   (`init`/`config`/`file_appender`/`propagation`/`shutdown`, `ParentBased(TraceIdRatioBased)` sampler,
   `TracingGuard`). No framework swap; no telemetry redesign (PRD Non-Goals).
2. **The PRD's settled decisions are authoritative and not re-opened:** `snake_case`, spans-first, the
   5-level taxonomy, `TruncatedPubkey = 0x{first10}...{last8}`, `info` = production default,
   `RUST_LOG`/`EnvFilter` env-overrides-config. This candidate supplies the enforcement and the precise
   homes/idioms.
3. **`crypto::logging` is the correct home** for redaction wrappers, canonical field constants, and
   `new_request_id`, because `crypto` already hosts the wrappers, already has `uuid`/`hex`/`tracing`,
   and is depended on by every signing-adjacent crate. Verified against `cargo metadata` and the
   `rvc-architecture-tests` zero-out-edge pin on `rvc-eth-types`.
4. **`telemetry::propagation` is the correct home** for the inbound extractor (only crate with OTel
   deps); `bin/rvc-signer` gains a single additive `→ telemetry` production edge, which is acyclic
   because `telemetry` depends on no workspace crate.
5. **CI rides existing steps:** the `check` job's `cargo clippy --workspace --all-targets -- -D
   warnings` carries Gate 1; the `coverage` job's `cargo llvm-cov nextest --workspace` carries
   Gates 3/4; the `rvc-architecture-tests` DAG test (already in the workspace) carries Gate 6. The
   **only** net-new CI infra is one `gitleaks` job (Gate 2). **No new mandatory toolchain for P0**
   (nightly/dylint/`--cfg tracing_unstable` are P2).
6. **`release_max_level_debug`** is the chosen static cap (ADR-001): `trace` compiled out of release,
   `debug` runtime-switchable via `RUST_LOG`. Confirm vs `release_max_level_info` at the gate.
7. **Pubkeys are truncated even at `trace`; full signing roots/signatures are truncated/omitted by
   default** (PRD Open Qs 1 & 2 taken as resolved-to-stricter), with `TruncatedRoot` as the primitive.
   `network` stays a resource attribute, never duplicated per event.
8. **`x-request-id` is an acceptable additive carrier** for the human-readable `request_id` alongside
   W3C `traceparent`; it does not change signing behavior and is ignored by clients that don't send it.
9. **`cargo nextest run --workspace` is the runner of record** (`cargo test --workspace` can deadlock,
   per project history); the asserting conformance/zero-alloc tests run under it, `criterion` benches
   via `cargo bench`.
10. **The four high-risk crates** (`crypto`, `secret-provider`, `signer`, the `bin/rvc-signer` `:9000`
    path) plus **`rvc-keygen` (mnemonic/`bip39`)** are the correct review boundary for the
    secret-redaction sign-off, even though the PRD lists `rvc-keygen` under P1 breadth.
11. **This effort changes only logging/observability** — no runtime behavior, public-API, or
    signing/slashing-logic change. The single new wire behavior is inbound trace-context extraction at
    `:9000` plus an additive `x-request-id` header.
