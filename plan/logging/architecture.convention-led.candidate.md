# Software Architecture: rs-vc Structured Logging & Observability — **Convention-Led Candidate**

> Candidate optimizing for **convention-led** delivery: a crisp, documented standard plus the
> *thinnest possible* shared-helper layer. The normative standard doc (level taxonomy + canonical
> field registry + redaction policy) is the **primary artifact**; the 23 crates **self-apply** it;
> net-new code/infra is deliberately minimized. Correctness rests on the documented standard +
> code review, backstopped by a small, automated, fail-closed safety net.
>
> Scope note: this is a **cross-cutting observability initiative on an existing system**, not a new
> build. It **composes into** the in-place `tracing` + `tracing-subscriber` + OpenTelemetry/OTLP
> stack and the dedicated `telemetry` crate; it does **not** redesign the runtime, the
> telemetry/OTLP/file-appender pipeline, the sampler, or the propagation/shutdown machinery.
> Authoritative inputs: PRD `plan/logging/prd.md` and research `plan/logging/research/`
> (`00-overview.md` is authoritative over the per-angle docs; its reconciliations **R1–R9** and the
> Consolidated Assumptions are honored throughout).

---

## Overview

rs-vc already runs a complete `tracing` → `tracing-opentelemetry` → batched OTLP/HTTP pipeline with a
`ParentBased(TraceIdRatioBased)` sampler, a W3C `TraceContextPropagator`, size-rotated file logging,
and a `TracingGuard` lifetime contract — all owned by `crates/telemetry`. The gap is **not** machinery;
it is **consistency and policy**: `trace` is near-absent (19 sites), whole crates are silent, levels
and field names drift by author, correlation IDs are not standardized onto spans, redaction is by
convention only, and the two binaries initialize the subscriber differently.

This candidate treats the **documented standard as the product**. The load-bearing artifact is
`plan/logging/STANDARD.md` (the level taxonomy, the canonical `snake_case` field registry, and the
secret-redaction policy, with copy-paste examples), referenced from a module doc in `telemetry`.
Crates then self-apply it with the macros and `#[instrument]` idioms they already use. The shared-code
footprint is held to **exactly four small, unavoidable primitives** — three of which already exist —
placed so they introduce **no new edge** in the 23-crate dependency DAG that the
`architecture-tests` cycle gate already enforces:

1. `crypto::logging::TruncatedRoot` — one net-new zero-alloc `Display` wrapper (mirrors the existing
   `TruncatedPubkey`) for signing roots / block roots / signatures at `trace`.
2. `telemetry::propagation::{HeaderExtractor, set_parent_from_headers}` — the inbound inverse of the
   existing `inject_trace_context`, closing the :9000 trace-continuity gap.
3. `crypto::logging` field-name **constants** (`field` submodule) — optional, compile-checked spelling
   of the registry keys; convention is the rule, the constants are a cheap typo-guard.
4. (already present) `crypto::logging::{TruncatedPubkey, RedactedUrl}` and
   `telemetry::config::redact_endpoint` — standardized on, not redesigned.

Everything else — which level an event gets, which fields a span carries, whether a secret is logged —
is **convention enforced by the standard doc + reviewer checklist**, with a thin automated safety net
(clippy `disallowed-methods`, captured-subscriber tests, a `gitleaks` source+emitted scan, and a
zero-allocation harness) that fails **closed** so drift and leaks cannot land silently.

The guiding trade-off, stated plainly: **lowest friction, highest reliance on people.** A convention-led
design ships fastest and adds the least to compile/maintain, but its correctness lives in a document and
in reviewers' attention. We therefore spend the small shared-code budget exactly where convention is
**unsafe** (secret redaction, cross-process trace continuity, zero-cost-when-disabled) and nowhere else.

---

## Architecture Principles

- **The standard doc is the primary deliverable.** `STANDARD.md` is normative; code conforms to it.
  Every later PR is measured against it. (PRD P0-1.) — *A convention-led approach is only as good as
  the document that defines the convention.*
- **Minimize net-new code; prefer convention to abstraction.** No logging facade, no wrapper macros,
  no per-crate logging module. Crates call `tracing` directly and follow the doc. — *Friction and
  maintenance scale with shared surface area; we keep it near-zero.*
- **Spend shared code only where convention is unsafe.** Three places justify code:
  secret-redaction primitives (a doc can't stop a `Debug`), the inbound trace extractor (a missing
  inverse is a real bug, not a style choice), and the zero-cost-when-disabled mechanics (a guarantee,
  not a guideline). — *Justify every line that isn't convention.*
- **Compose into `telemetry`; never rebuild it.** The OTLP layer, file appender, sampler,
  propagation, and `TracingGuard` are correct and stay. (PRD Non-Goals; Assumption 1.) — *This is an
  uplift of an existing stack.*
- **Spans-first correlation.** Canonical IDs live once on `#[instrument]` spans and inherit to child
  events and OTLP span attributes; events carry only event-specific data. (PRD P0-2; R-overview §2.)
- **No secret at any level, including `trace`.** Type layer + lint gate + runtime captured-subscriber
  tests; the existing redaction primitives are the *only* sanctioned sink for pubkeys/URLs/roots.
  (PRD P0-3; overview §E.)
- **Free when off.** Disabled `debug!`/`trace!` allocate/format/hash nothing; `release_max_level_debug`
  compiles `trace!` out of release; a counting-allocator test is the precise gate. (PRD P0-6;
  overview §D/§H.)
- **No new edge in the dependency DAG.** Shared primitives live where they create **zero** new
  workspace-internal production edges and **no** cycle; the `architecture-tests` gate stays green
  without edits to its policy tables.
- **One operator experience across both binaries.** Same default level, same `EnvFilter` precedence,
  same format selection for `bin/rvc` and `bin/rvc-signer`. (PRD P0-5.)

---

## System Context Diagram

```text
                       RUST_LOG / EnvFilter (env overrides config default)
                                         │
   ┌───────────┐  W3C traceparent  ┌─────┴───────────┐   OTLP/HTTP   ┌──────────────────┐
   │ Lighthouse│ ───────────────▶  │   bin/rvc       │ ────spans────▶│  OTel Collector  │
   │ / Prysm   │  POST :9000 sign  │   bin/rvc-signer │               │  (+ GCP Trace)   │
   └───────────┘ ◀───────────────  └─────┬───────────┘ ◀── (none) ───└──────────────────┘
        ▲           x-request-id         │
        │                                ├─ console (fmt layer, default `info`)
        │  (rvc is also the CLIENT       ├─ file   (logroller, rotated; level configurable)
        │   calling :9000 — inject)      ▼
   ┌────┴───────┐   HTTP (beacon)   ┌─────────────────┐
   │ Beacon Node│ ◀───────────────  │  crates/* (23)  │  self-apply STANDARD.md:
   │ (eth2 API) │ ───────────────▶  │  tracing macros │  level taxonomy · field registry · redaction
   └────────────┘                   └─────────────────┘
```

The shaded boxes that change are **policy + a handful of helpers**, not the pipeline. The collector,
exporters, sampler, file appender, and `TracingGuard` are untouched.

---

## Component / Module Overview

This is a cross-cutting initiative, so the "modules" below are **(a) the standard artifact**,
**(b) the thin shared-primitive surface**, and **(c) the 23 crates as self-applying consumers**. The
table makes the shared-vs-convention split explicit — the central decision of this candidate.

| Component | Kind | Responsibility | Net-new? | Lives in | Depends on (new edge?) |
|---|---|---|---|---|---|
| `STANDARD.md` | Doc (primary) | Normative taxonomy + field registry + redaction policy + examples | **New doc** | `plan/logging/` (+ ref'd by `telemetry` module doc) | none |
| `OPERATOR_GUIDE.md` | Doc | `RUST_LOG` recipes, pretty-vs-JSON, follow a `request_id` (P1-4) | New doc | `plan/logging/` | none |
| `crypto::logging::TruncatedRoot` | Shared code | Zero-alloc `Display` truncation for roots/sigs at `trace` | **New (small)** | `crates/crypto/src/logging.rs` | none (crypto already depended on everywhere needed) |
| `crypto::logging::field` consts | Shared code | Compile-checked registry key spellings (optional adoption) | **New (tiny)** | `crates/crypto/src/logging.rs` | none |
| `crypto::logging::{TruncatedPubkey,RedactedUrl}` | Shared code | Pubkey/URL redaction sinks | exists | `crates/crypto/src/logging.rs` | none |
| `telemetry::propagation::set_parent_from_headers` | Shared code | Inbound W3C extractor (inverse of `inject_trace_context`) | **New (small)** | `crates/telemetry/src/propagation.rs` | none |
| `telemetry::config::redact_endpoint` | Shared code | Endpoint redaction | exists | `crates/telemetry` | none |
| `request_id` minting | Convention | `uuid::Uuid::new_v4()` at the operation boundary; carried on the span + `x-request-id` | convention (uuid already a dep) | call sites (`signer`, `bin/rvc-signer`, orchestrator) | none |
| Subscriber init (`bin/rvc`) | Existing code | `init_logging(level, otlp, file)` — keep, lightly reconcile | exists | `bin/rvc/src/main.rs` | none |
| Subscriber init (`bin/rvc-signer`) | Code change | Replace bare `fmt().with_env_filter(from_default_env())` with shared precedence | change | `bin/rvc-signer/src/main.rs` | **new edge: `rvc-signer-bin → telemetry`** (see ADR-002) |
| Secret-leak gate (clippy + tests + gitleaks) | Safety net | Fail-closed enforcement of the redaction policy | New (additive) | `clippy.toml`, `ci.yml`, high-risk crates | none |
| Zero-overhead harness | Safety net | criterion sign bench + counting-allocator test + `release_max_level_debug` | New (additive) | `crates/crypto/benches/`, `bin/*/Cargo.toml` | dev-dep only |
| 23 crates + 3 bins | Consumers | Self-apply `STANDARD.md` with `tracing` macros / `#[instrument]` | per-crate edits | each crate | none |

**The only new production graph edge introduced by this entire candidate is
`rvc-signer-bin → rvc-telemetry`** (so the :9000 handler can call the inbound extractor and share
init). It is acyclic and is analyzed in the Dependency Graph section and ADR-002.

---

## Module Dependency Graph

The shared logging primitives sit at the **bottom** of the graph so every consumer can reach them
without creating a back-edge. Two existing leaf-ish crates host all shared code: **`crypto`** (already
a dependency of everything that signs or handles keys) and **`telemetry`** (an isolated observability
crate that nothing in the domain layer depends on).

```text
eth-types  ─────────────────────────────────▶ (workspace leaf; zero prod out-edges, gate-enforced)
   ▲
   │ (crypto depends on eth-types)
crypto  ── hosts ──▶  logging::{TruncatedPubkey, RedactedUrl, TruncatedRoot(NEW), field consts(NEW)}
   ▲   ▲   ▲   ▲   ▲   ▲   ▲   ▲   ▲   ▲   ▲   (12 consumers: signer, secret-provider, slashing,
   │   │   │   │   │   │   │   │   │   │   │    validator-store, builder, block-service,
   │   │   │   │   │   │   │   │   │   │   │    keymanager-api, grpc-signer, rvc, bin/rvc,
   │   │   │   │   │   │   │   │   │   │   │    bin/rvc-signer, bin/rvc-keygen)
   │
signer ──▶ crypto, slashing, doppelganger, eth-types, metrics   (sign_* spans live here)

telemetry  ── hosts ──▶  propagation::{inject_trace_context, set_parent_from_headers(NEW)}
   ▲                                          (telemetry depends on tracing/otel/reqwest only —
   │                                           NOT on crypto, NOT on eth-types, NOT on any domain crate)
   ├── bin/rvc                (existing edge)
   └── bin/rvc-signer         ◀── NEW EDGE (ADR-002): rvc-signer-bin → telemetry

bin/rvc          ──▶ rvc, telemetry, crypto, signer, beacon, bn-manager, … (existing)
bin/rvc-signer   ──▶ signer, crypto, eth-types, slashing, telemetry(NEW), …
```

**Why this is acyclic and adds no policy churn:**

- `TruncatedRoot` + `field` consts go in **`crypto::logging`**. `crypto` is *below* every crate that
  needs to log a root or use a canonical field name, and *above* only `eth-types` (which it already
  depends on). No consumer needs a new dependency — they already depend on `crypto`. **Zero new
  edges.**
- The inbound extractor goes in **`telemetry::propagation`**, next to its existing inverse. `telemetry`
  depends on nothing in the domain layer, so hosting code there can never form a cycle. The single
  consumer that gains an edge is `bin/rvc-signer` (`→ telemetry`), and a binary depending on
  `telemetry` is the same shape `bin/rvc` already has.
- `request_id` minting uses `uuid` (already a workspace dependency reached transitively) at call
  sites — **no shared module, no edge.**
- The `architecture-tests` cycle gate (`crates/architecture-tests/tests/architecture_no_cycles.rs`)
  re-runs `cargo metadata` and asserts acyclicity + forbidden-edge absence + the `eth-types` /
  `signer-registry` zero-out-edge invariant. The `rvc-signer-bin → telemetry` edge touches **none** of
  its policy tables (`FORBIDDEN`, `ZERO_OUT_EDGE_IF_PRESENT`, `REQUIRED_EDGE`), so the gate stays green
  **with no edits**.

**Verify:** No circular dependencies. `crypto` and `telemetry` never depend on each other or on any
consumer; the one new edge is binary→`telemetry`, a sink.

---

## Module Details

### Module: `STANDARD.md` — the normative standard (PRIMARY ARTIFACT, P0-1)

**Responsibility:** Be the single source of truth a reviewer and an author consult to answer "what
level, what fields, redacted how?" — so that placement is never a judgment call.

**Why it is the centerpiece of *this* candidate:** In a convention-led design, the document *is* the
mechanism. The shared-code candidates exist to make the few unsafe cases safe; the document carries
everything else. It must therefore be unambiguous, example-driven, and short enough to be read.

**Contents (each section is normative):**

1. **Level taxonomy** (reproduces the PRD table verbatim). House standard (R8): anchored on
   `tracing::Level` docs, *not* presented as an upstream mandate. Load-bearing rule: *anything that
   scales with validator count or fires per-loop is `debug`/`trace`, never `info`.*
2. **Canonical field registry** — the exact `snake_case` keys, types, and **where each lives (span vs
   event)**. Presented as an rs-vc **house standard (SHOULD-level)** per R2 (OTel `snake_case` is a
   SHOULD; the within-namespace uniqueness rule is the real constraint). No synonyms
   (`val_idx`/`validator`/`node` are forbidden).

   | Field | Type | Lives on | Source / rule |
   |---|---|---|---|
   | `slot` | `u64` | span | duty/att/block/sign spans |
   | `epoch` | `u64` | span | duty span |
   | `validator_index` | `u64` | span/event | |
   | `committee_index` | `u64` | span/event | matches Lighthouse (migration source); not `index`/`CommitteeIndex` |
   | `subcommittee_index` | `u64` | span/event | sync-committee contribution lines only |
   | `pubkey` | truncated `0x{first10}...{last8}` | span/event | **always** `crypto::logging::TruncatedPubkey` + `%`; never the full key, even at `trace` |
   | `duty` | enum string (`attestation`/`block`/`aggregate`/`sync_committee`/…) | span | |
   | `request_id` | string/uuid | span | one per signing/API request, incl. :9000 |
   | `bn_url` | redacted URL | event | **always** `crypto::logging::RedactedUrl` |
   | `head` | truncated root | event | attested head root (`TruncatedRoot`) |
   | `block_root` | truncated root | event | proposed block root (`TruncatedRoot`) |
   | `network` | string | **resource attr** | set once in `telemetry::init`; never per-event |

3. **Redaction policy** (the six MUST/MUST-NOT rules; see the redaction module below).
4. **`#[instrument]` idioms** — the eager-`fields()` rule (R1), `skip_all`-first, `level="debug"` on
   hot fns, async-correctness rules, `err`-once.
5. **Worked examples** — a duty span, a sign span, an `enabled!`-guarded trace dump, the `field::Empty`
   + `record()` late-bind pattern. Copy-paste ready.
6. **`info` heartbeat shape** (overview §G) — the milestone set, Lodestar-style `Signed`(debug) /
   `Published`(info) split, `time_into_slot`/`delay` timing field.

**Data store:** none (a Markdown file). **Public API:** the field registry and rules are the
"interface" every crate codes against.

**Key design decisions:**
- The registry table is the **normative artifact**; the `crypto::logging::field` consts are an
  *optional* compile-checked mirror, not a required import (keeps friction low — a crate may type
  `slot` as a literal and still be conformant).
- The doc is referenced from a `//!` module doc in `telemetry` so it's discoverable from code (PRD
  P0-1 "referenced from the codebase").

**Failure modes:** the doc going stale is the main risk — mitigated by P2-4 conformance lint (future)
and the reviewer checklist making the doc the review rubric.

---

### Module: `crypto::logging` — shared redaction & field primitives (THIN shared code)

**Responsibility:** Provide the *only* sanctioned sinks for secret-adjacent values and the canonical
field-key spellings, as zero-allocation `Display` wrappers + `const` strings — nothing more.

**Why `crypto` (dependency-direction justification):** `crypto::logging` already hosts
`TruncatedPubkey`/`RedactedUrl`; `crypto` already sits below every crate that signs, handles keys, or
talks to a BN; and `crypto` depends only on `eth-types` upward. Adding `TruncatedRoot` and the `field`
consts here reaches all 12 consumers with **zero new edges** and **no cycle**. Placing them anywhere
higher (e.g. a new `logging` crate) would force new edges from `crypto`/`signer`/`slashing` down`,`
and a new node the cycle gate must learn about — strictly more friction for no benefit. (See ADR-003.)

**Existing (standardized on, not redesigned):**
- `TruncatedPubkey(&str)` → `0x{first10}...{last8}`, zero-alloc `Display`, warns+falls-back on a
  double-`0x` prefix. (`crates/crypto/src/logging.rs:5`.)
- `RedactedUrl(&str)` → strips `user:pass@` via `url::Url`, raw fallback on parse failure.
  (`:40`.)

**Net-new — `TruncatedRoot` (the one unavoidable new wrapper):**
- Mirrors `TruncatedPubkey`: a zero-alloc `Display` wrapper over a 32-byte root / signature hex (or
  `&[u8]`), rendering `0x{first10}...{last8}` so the truncate-don't-omit resolution of PRD Open-Q1 has
  a primitive. Pick **one** glyph (`...`, matching `TruncatedPubkey`) and be consistent (R9).
- Used **only** at `trace` and **only** via `%`; the *full* root/signature appears only on return
  values, never in a macro. (overview §E mandated-handling.)

**Net-new — `field` consts submodule (optional, tiny):**
```rust
pub mod field {                         // compile-checked spelling of the registry keys
    pub const SLOT: &str = "slot";
    pub const EPOCH: &str = "epoch";
    pub const VALIDATOR_INDEX: &str = "validator_index";
    pub const COMMITTEE_INDEX: &str = "committee_index";
    pub const PUBKEY: &str = "pubkey";
    pub const DUTY: &str = "duty";
    pub const REQUEST_ID: &str = "request_id";
    pub const BN_URL: &str = "bn_url";
    // … head, block_root, subcommittee_index …
}
```
These exist so a crate *can* write `crypto::logging::field::SLOT` and get a typo caught at compile
time, but the **convention is the rule** — the registry table — and the consts are a cheap guard, not a
mandated import. (Deliberately low-friction: no macro, no wrapper around `tracing`.)

**Data store:** none. **Events published/consumed:** none (these are formatting/constant helpers).

**Public API (interface to other modules):**

| Item | Signature | Use |
|---|---|---|
| `TruncatedPubkey<'a>` | `Display` | `pubkey = %TruncatedPubkey::new(hex)` |
| `RedactedUrl<'a>` | `Display` | `bn_url = %RedactedUrl(url)` |
| `TruncatedRoot<'a>` | `Display` | `head = %TruncatedRoot::new(root_hex)` at `trace` |
| `field::*` | `&'static str` | optional compile-checked key spelling |

**Internal structure:** one file, `crates/crypto/src/logging.rs` (already exists; extended, not
restructured).

**Key design decisions:**
- **No `Display` on secret types ever.** Mnemonics/keys/passwords have no wrapper here — they are
  *never* logged, so giving them a `Display` would be an anti-feature (overview §E layer 1).
- Zero-alloc `Display` is the P0-6 mechanic: the wrapper's `fmt` runs only when the level is enabled
  (and only on an **event** macro or a `skip`/`enabled!`-protected path — R1).

**Failure modes:** a malformed input (double-`0x`, non-ASCII) falls back to raw display + a `warn!`
rather than panicking — the existing `TruncatedPubkey` behavior, replicated in `TruncatedRoot`. There
is no runtime dependency to be "down".

---

### Module: `telemetry::propagation` — inbound trace-context extractor (THIN shared code)

**Responsibility:** Continue an upstream W3C trace across the inbound :9000 boundary — the exact
inverse of the existing `inject_trace_context`.

**Why `telemetry` (dependency-direction justification):** the outbound injector already lives in
`crates/telemetry/src/propagation.rs`; `telemetry` depends only on `tracing`/`opentelemetry`/`reqwest`
(no domain crate), so hosting the inverse there can never create a cycle. The research's explicit
guidance: *compose into the existing module; do not add a crate* (overview §F; otel-correlation §3).

**Net-new (the one unavoidable new function):**
```rust
// crates/telemetry/src/propagation.rs — alongside inject_trace_context
use opentelemetry::propagation::Extractor;

struct HeaderExtractor<'a>(&'a http::HeaderMap);
impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> { self.0.get(key).and_then(|v| v.to_str().ok()) }
    fn keys(&self) -> Vec<&str> { self.0.keys().map(|k| k.as_str()).collect() }
}

/// Make `span` a child of the W3C trace context on `headers`, if any. No-op (root) if absent.
pub fn set_parent_from_headers(span: &tracing::Span, headers: &http::HeaderMap) {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let parent_cx = opentelemetry::global::get_text_map_propagator(|p| p.extract(&HeaderExtractor(headers)));
    span.set_parent(parent_cx);
}
```
Both `reqwest` and `axum` re-export `http::HeaderMap`, so a single `http`-typed extractor serves the
server side while the existing `reqwest`-typed injector stays as-is (otel-correlation Assumptions).

**Public API:** `pub fn set_parent_from_headers(span: &tracing::Span, headers: &http::HeaderMap)`; re-export from `telemetry::lib` next to `inject_trace_context`.

**Events:** none. **Data store:** none.

**Key design decisions:**
- **Graceful degradation:** if no `traceparent` is present (Prysm/Lighthouse may not send one),
  `extract` yields an empty context and the span stays a root — identical in spirit to the existing
  inject no-op. (otel-correlation §W3C.)
- **Sampler untouched:** keep `ParentBased(TraceIdRatioBased(rate))` exactly as in `init.rs`. The
  extractor is what makes the sampler honor the upstream decision all-or-nothing — replacing the
  sampler would shatter correlation (otel-correlation §sampler; PRD Non-Goals).

**Failure modes:** a malformed `traceparent` parses to an empty context (root span) — no panic, no
broken request. If the OTel layer is inactive, the global propagator is a no-op and the call is free.

---

### Module: Subscriber initialization (`bin/rvc` and `bin/rvc-signer`) — P0-5 reconciliation

**Responsibility:** Give both binaries one default level, one `EnvFilter` precedence (env overrides
config default), and one format-selection path — without touching the OTLP layer, file appender, or
`TracingGuard` contract.

**Current divergence (verified):**
- `bin/rvc` (`src/main.rs:783`): `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))`
  — config default `info` with `RUST_LOG` override — then assembles boxed OTLP + file layers and pads
  with `Identity` so the empty-`Vec<Layer>` short-circuit doesn't suppress `fmt`. This is the **correct
  precedence** and the richer init.
- `bin/rvc-signer` (`src/main.rs:234`): `tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init()`
  — `from_default_env()` defaults to **everything off** when `RUST_LOG` is unset (no `info` default),
  diverging on default level *and* format and offering no OTLP/file path.

**Design (convention-led: standardize the precedence rule, reuse the existing helper):**

- **Reconcile on `bin/rvc`'s precedence rule**, documented in `STANDARD.md`:
  > `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))` — `RUST_LOG`
  > overrides; absent it, the default is `info`.
- **Make `bin/rvc-signer` adopt the same rule and the same layer assembly.** Because the signer now
  takes a `telemetry` dependency (ADR-002), its `main` calls the same shape of init: an `EnvFilter`
  with the shared precedence, the `fmt` layer for console, and — when configured — the existing
  `telemetry::init_tracing` OTLP layer and `telemetry::create_file_layer` file layer, returning the
  `TracingGuard`. The signer keeps its own thin `init_logging` wrapper (a binary-local function); we do
  **not** introduce a shared init crate (that would be net-new infra for two call sites — convention +
  a documented snippet is cheaper). (See ADR-002 and ADR-004.)
- **File-vs-console level** (overview §G, Open-Q forwarded): the file layer may be more verbose than
  the console (file `debug`, console `info`) **iff** the existing `logroller`/non-blocking appender
  supports an independent level. `bin/rvc` already threads a `logfile_level` (`main.rs:937`) into
  `FileAppenderConfig`, so this is **already supported** — `STANDARD.md` documents it as the sanctioned
  recipe; `bin/rvc-signer` gains the same option. (ADR-005.)

**Public API:** each binary keeps a local `init_logging(level, otlp_cfg, file_cfg) -> Guards`; the
**contract** (precedence, default, format) is the shared, documented standard — not shared code.

**Key design decisions:**
- **Keep `bin/rvc`'s `Identity`-padding** for the empty-layer short-circuit (`main.rs:834`); it's a
  correct, already-tested workaround for the 0.3 `Vec<Layer>::register_callsite()` returning
  `Interest::never()`.
- **No change to `TracingGuard`/shutdown** — both binaries hold the guard for process lifetime exactly
  as today.

**Failure modes:** if OTLP init fails, both binaries fall back to fmt-only with a warning (already
`bin/rvc`'s behavior at `main.rs:814`); the signer adopts the same fallback.

---

### Module: the 23 crates as self-applying consumers (the bulk of the work, convention-driven)

**Responsibility:** Each crate raises its own logging to `STANDARD.md` using the macros and
`#[instrument]` idioms it already uses — no shared logging layer to call, no facade to learn.

**How "self-apply" works in practice (per crate):**
- Add `info` milestones, `debug` decision points, `trace` step/wire detail per the taxonomy.
- Put canonical correlation fields on the crate's existing `#[instrument]` spans; set `level="debug"`
  on hot fns; `skip_all` on anything secret/large; redact via the `crypto::logging` wrappers.
- Normalize the namespace drift the research found: orchestrator and `signer` gate sites use the
  `rvc.`-prefix (`fields(rvc.slot = slot)`, span `rvc.orchestrator.process_slot`; and
  `crates/signer/src/lib.rs` `sign_*` use `fields(rvc.operation = …, rvc.slashing.result)`) which is a
  **different OTLP attribute key** than the registry's `slot`/`duty` — rename to the unprefixed
  registry. (overview §F namespace-drift; R3.)
- Fix the `SigningGate` blocking-section detachment: `crates/signer/src/lib.rs` runs the BLS sign in a
  `spawn_blocking` closure (`:209`, `:372`) that does **not** re-enter the `rvc.sign.*` span — capture
  `Span::current()` and `let _e = span.enter()` **inside** the closure so `crypto`/`slashing` events
  stay correlated. (R3; overview §C.)

**Data ownership:** each crate owns its own log statements; there is no shared logging state. This is
the property that makes a convention-led approach viable — there is nothing to centralize.

**Key design decisions:**
- **No per-crate logging module, no wrapper macros.** Crates call `tracing::{info,debug,trace,warn,error}!`
  and `#[tracing::instrument]` directly. The standard is the only shared thing. (Principle 2.)
- **The four high-risk crates** (`crypto`, `secret-provider`, `signer`, the `bin/rvc-signer` :9000
  path) — plus `rvc-keygen` for mnemonics (overview Assumption 9) — get the redaction tests + reviewer
  sign-off (see redaction module).

**Failure modes:** the risk here is *adoption drift*, not runtime failure — addressed by the safety net
and the rollout phasing.

---

## Cross-Cutting Concerns

### Authentication & Authorization
Out of scope for logging changes. The :9000 path keeps its existing TLS/CN audit posture
(`bin/rvc-signer/src/http_api/routes.rs:64`); the CN is logged as metadata only and is **never** an
authz gate. The redaction policy guarantees no auth material (passwords, keys) appears in any log line.

### Logging & Observability (this initiative)
- **Standard:** `STANDARD.md` is the rubric (taxonomy + registry + redaction). (P0-1.)
- **Correlation:** spans-first; canonical IDs on `#[instrument]` spans → OTLP span attributes; events
  inherit. `request_id` minted once per operation, carried on the span and across :9000 via
  `x-request-id` + W3C `traceparent`. (P0-2/§F.)
- **OTLP:** untouched. `tracing` events → OTel span events; span fields → span attributes;
  `otel.kind = "server"` on the inbound :9000 span, `"client"` on outbound beacon/signer calls.
- **The existing audit log stays separate.** `bin/rvc-signer` already emits one structured audit entry
  per sign request (success=`info`, rejection=`warn`, metadata-only — `routes.rs:99`). This initiative
  does **not** fold it into the trace; it ensures the audit entry's fields conform to the registry and
  carry `request_id`.

### Error Handling
- **`error` only when an intended action did not complete**; recover/degrade → `warn`. (Taxonomy.)
- **Log once** — `err`/`error!` at the layer that decides terminality; lower layers return the
  `Result` (CLAUDE.md). The P1-3 normalize pass removes duplicate log-and-return lines and fixes
  `error`-vs-`warn` miscategorization **without** touching `Result` flow / error types (PRD Non-Goal;
  R6 re-categorization breadth is conservative).

### Configuration
- **Level:** `RUST_LOG`/`EnvFilter`, env overrides config default `info` (both binaries, P0-5).
- **Static cap:** `release_max_level_debug` on both production binaries — `trace!` compiled out of
  release; `debug!` runtime-switchable via `RUST_LOG`. (ADR-001; overview Assumption 4.)
- **Format/file:** existing config (`logfile`, `logfile_level`, OTLP endpoint/sample-rate) — unchanged
  contracts; documented in `OPERATOR_GUIDE.md`.

### Secret Redaction — defense in depth (P0-3; overview §E)
**No single layer suffices** — a type wrapper makes a leak *harder*, not *impossible*
(`expose_secret() → info!()` always compiles). The design layers three controls, scoped to the four
high-risk crates + `rvc-keygen` mnemonics:

**Layer 1 — Type level (reduces accidents; already largely present):** every secret lives behind a
type that redacts `Debug` and does **not** implement `Display` — `SecretKey([REDACTED])`,
`secrecy::SecretString`, `SecretDataFormat → <redacted>`, `Zeroizing`, `bip39` behind a redacted
newtype. The policy **standardizes and closes gaps**; it does **not** add `Display`/`Serialize`
(`secrecy`'s default no-`Serialize` is kept deliberately, R4). Mandatory `#[instrument(skip_all)]` on
every fn taking a secret arg.

**Layer 2 — CI lint gate (catches obvious bypasses; NET-NEW, R5):** extend `clippy.toml` (today only
`msrv = "1.92"`) with `disallowed-methods` banning the known unsafe sinks
(`secrecy::ExposeSecret::expose_secret`, `SecretKey::to_bytes`/`raw_bytes`, raw `bip39::Mnemonic`
formatting), riding the existing `cargo clippy --workspace --all-targets -- -D warnings` step.
`expose_secret` is legitimately needed at decrypt call sites → scope with a small, reviewed,
greppable `#[allow(clippy::disallowed_methods)]` allow-list so the lint flags any *new* use. Limitation
stated in the policy: `disallowed-methods` matches **named paths only** — it cannot see a value already
laundered into a `String`; acceptable because Layer 1 makes the implicit path impossible and Layer 3
tests the runtime result.

**Layer 3 — Runtime captured-subscriber tests + emitted scan (proves it):**
`#[tracing_test::traced_test]` tests in `crypto`/`signer`/`bin/rvc-signer` (and `rvc-keygen`) that fire
each high-risk log line and assert the output **does** contain the truncated/redacted form and **does
NOT** contain the raw secret — the existing
`test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` (`crates/crypto/src/logging.rs:119`) is
the proven model. Plus a `gitleaks` PR job over **source and a captured `trace`-level emitted sample**
(scanning emitted output is what actually verifies "no secret reached a sink").

**The four high-risk surfaces and their mandated handling** (overview §E):

| Surface | Secret | Rule |
|---|---|---|
| `crypto` | BLS key | never log; gate `raw_bytes`/`to_bytes` (the laundering path) |
| `secret-provider` | provider material | never log payloads; metadata only |
| `signer` (+ :9000) | full payload / root / signature | truncate at `trace` via `TruncatedRoot`; full only on return |
| `bin/rvc-signer` :9000 | request body | `skip_all` on handlers (already done, `routes.rs:51`); body never logged |
| `rvc-keygen` | mnemonic / seed | never log, not even length; `bip39::Mnemonic` is a sink (it `Display`s the phrase) |

**Fallback (PRD Open-Q3, overview §E):** if a robust automated *source* scan proves impractical, drop
only the brittle regex source scan; keep Layers 1+2 (both automated), the captured-subscriber tests,
the `gitleaks` source+emitted scan, and the reviewer checklist. This is **stronger** than the PRD's
stated minimum.

### Zero-Overhead-When-Disabled (P0-6; overview §D/§H)
Three rules + a verification harness:
1. `level="debug"` (or `trace`) **and** `skip_all` on every hot-path `#[instrument]` — disabled at prod
   `info` → ~0.7 ns no-op span; `skip_all` stops auto-`Debug` of `&SecretKey`/`&BeaconBlock`/payloads.
2. Gate any field doing real work (`hex::encode`, `serde_json`, hashing, `format!`) behind
   `tracing::enabled!` or a zero-alloc `Display` wrapper. **R1 caveat:** a `%TruncatedPubkey` is lazy
   **only** on an event-family macro or a `skip`/`enabled!`-protected path — in
   `#[instrument(fields(pk = %…))]` it runs eagerly on every call, so `#[instrument(fields(...))]` is
   restricted to `Copy` scalars / cheap values. The in-repo `enabled!`-guard at
   `crates/beacon/src/client.rs:149` is the model.
3. Compile `release_max_level_debug` into both binaries (ADR-001) — `trace!` physically removed from
   release; also neutralizes residual `EnvFilter` dynamic-directive cost. Do **not** enable tracing's
   `log` bridge feature.

**Harness (net-new; no bench infra exists today):** a `criterion` sign-path bench comparing
`no_subscriber` / `subscriber_info` (debug spans off) / `subscriber_trace`; a per-slot-loop bench
around one coordinator phase; and a dependency-free **counting-`#[global_allocator]` test** asserting
`assert_eq!(allocs_when_disabled, baseline)` on the sign and per-slot paths. The allocation assertion —
not the latency bench — is the **precise** gate (a ~1 ns span is below criterion's floor next to a BLS
sign). Asserting tests run under `cargo nextest run --workspace`; benches via `cargo bench`. (ADR-006
spans-first; ADR-001 static cap.)

---

## Data Flow Diagrams

**A. One signing request across the :9000 boundary (the correlation flow this candidate completes):**
```text
rvc (client side, orchestrator duty span: slot, epoch on span)
  ├─ mint request_id = Uuid::new_v4()                       ─┐ (convention; uuid already a dep)
  ├─ open client span: otel.kind="client", request_id, slot, duty, %pubkey(TruncatedPubkey)
  ├─ telemetry::inject_trace_context(&mut headers)          ─┘ (existing)
  ├─ headers.insert("x-request-id", request_id)              (convention; explicit carrier)
  └─ POST :9000  ───────────────────────────────────────────▶ rvc-signer sign handler
                                                                 ├─ telemetry::set_parent_from_headers(  NEW
                                                                 │     &Span::current(), &headers)  ── joins trace
                                                                 ├─ read x-request-id (or mint) → record on span
                                                                 ├─ parse body → record slot/duty/%pubkey (field::Empty→record)
                                                                 ├─ SigningGate.sign_* span (rename rvc.* → registry)
                                                                 │     └─ spawn_blocking { let _e=span.enter(); BLS sign }  R3 fix
                                                                 │           ├─ slashing check  (debug: inputs/decision)
                                                                 │           └─ crypto sign     (trace: payload steps, no secrets)
                                                                 └─ audit log (info/warn, metadata only) + x-request-id echo
  every info!/debug!/trace! in this chain inherits {request_id, slot, duty, pubkey} from its span.
```

**B. A healthy `info` heartbeat (operator liveness, low volume):**
```text
startup        → info  "rvc starting" {version, network, commit}
validators load→ info  "Loaded validator keys" {count}
BN connect     → info  "connected to beacon node" {bn_version}
epoch boundary → info  "epoch processed" {epoch}
attestation    → debug "Signed attestation" {slot,%pubkey}  ; info "published attestation" {slot,count}
block proposed → info  "block proposed" {slot, block_root=%TruncatedRoot}
slot tick      → info  (optional once-per-slot) {slot, time_into_slot}
```
(Demote duty cache hit/miss, BN selection, slashing inputs to `debug`; wire framing + per-item loops to
`trace`. overview §G.)

**C. Secret-redaction enforcement at PR time (the safety net):**
```text
PR ──▶ cargo clippy -D warnings  ──▶ disallowed-methods (expose_secret/raw_bytes/…) ─┐
PR ──▶ cargo nextest --workspace ──▶ captured-subscriber tests (raw secret ABSENT)  ─┤─ all must pass,
PR ──▶ gitleaks (source + emitted trace sample)                                     ─┤   fail-closed
PR ──▶ reviewer checklist on {crypto, secret-provider, signer, :9000, rvc-keygen}   ─┘
```

---

## Infrastructure & Deployment

### Deployment Model
Unchanged. `bin/rvc`, `bin/rvc-signer`, `bin/rvc-keygen` build and ship exactly as today. The only
build-graph change is `bin/rvc-signer` gaining a `telemetry` dependency (already a transitively-present
crate). No new runtime services, sidecars, or collector config (operator territory — `OPERATOR_GUIDE.md`
documents recipes only, PRD Non-Goals).

### Scaling Strategy
This candidate does not change scaling. The relevant performance property is **volume control under
verbose levels**: `info` stays low-volume by taxonomy; P2-1 per-validator sampling is the documented
backstop; coarse spans (one per phase, not per inner await) bound per-poll enter/exit cost when
`debug`/`trace` is enabled under large validator counts (overview §D caveat).

### Adoption / Rollout Path across the 23 crates (replaces "service extraction")

Phased to land the rubric first, then the unsafe-by-convention pieces, then breadth. Each phase is
independently shippable and leaves the workspace green (`cargo fmt`, `cargo clippy -D warnings`,
`cargo nextest run --workspace`).

| Phase | Scope | Crates / surfaces touched | Net-new code | Exit criterion |
|---|---|---|---|---|
| **0 — Standard** | P0-1 | `plan/logging/STANDARD.md`; `//!` ref in `telemetry` | docs only | Doc reviewed + merged; it is the review rubric |
| **1 — Safety primitives** | P0-3 layer 1+2 prep; P0-6 mechanics | `crypto::logging` (`TruncatedRoot` + `field` consts); `clippy.toml` disallowed-methods + allow-list; counting-allocator harness skeleton | `TruncatedRoot`, consts, clippy cfg, bench crate | clippy gate green; `TruncatedRoot` tested; allocator test compiles |
| **2 — Correlation bridge** | P0-2/P0-4 boundary | `telemetry::propagation::set_parent_from_headers`; wire it + `request_id` + `x-request-id` into `bin/rvc-signer` sign handler and the rvc client span; **`rvc-signer-bin → telemetry` edge** | extractor fn + wiring | trace continuous across :9000 (captured-subscriber test: non-zero parent); cycle gate green |
| **3 — Hot paths + redaction tests** | P0-4/P0-3 layer 3/P0-6 | `crypto`, `signer` (rename `rvc.*`→registry; `spawn_blocking` re-enter), `slashing`, `beacon`/`bn-manager`, orchestrator duty/att/block; captured-subscriber redaction tests on the 4 high-risk crates + `rvc-keygen`; `release_max_level_debug` on both bins | per-crate edits; static-cap features; gitleaks job | hot-path steps have `trace`; spans carry registry fields; 0 secret findings; allocation assertion passes |
| **4 — Init reconciliation** | P0-5 | `bin/rvc-signer` init adopts shared precedence/format/file-level; `bin/rvc` light touch-up | binary-local init change | both bins: same default `info`, same `EnvFilter` precedence, same format selection (init tests) |
| **5 — Breadth (gap crates)** | P1-1/P1-2 | `rvc-keygen`, `signer-registry`, `eth-types`, `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`; remaining `#[instrument]` sites | per-crate edits | each gap crate has `info`/`debug` (+`trace` where a hot path exists) |
| **6 — Normalize + docs + P2** | P1-3/P1-4/P2 | audit well-covered crates for level/field/redaction; `OPERATOR_GUIDE.md`; then P2 (sampling, dynamic reload, JSON profile, conformance lint) as capacity allows | docs + targeted fixes | divergences fixed; operator guide merged |

**Per-crate "readiness" framing (analogue of extraction-readiness):**
- **Ready to self-apply now** (well-covered, only normalize): `crates/rvc`, `bin/rvc`,
  `bin/rvc-signer`, `signer`, `bn-manager`, `slashing`, `crypto`.
- **Needs the bridge first** (correlation depends on Phase 2): the :9000 path and `signer` gate
  correlation.
- **Greenfield** (near-silent, add from scratch to standard): `rvc-keygen`, `signer-registry`,
  `eth-types`, `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`.

---

## Technology Choices

| Concern | Choice | Rationale |
|---|---|---|
| Tracing framework | `tracing` 0.1 / `tracing-subscriber` 0.3 (existing) | PRD Non-Goal to swap; compose in |
| Trace export | `tracing-opentelemetry` 0.32 / `opentelemetry*` 0.31, OTLP/HTTP (existing) | already wired; untouched |
| Sampler | `ParentBased(TraceIdRatioBased(rate))` (existing) | preserves whole-trace correlation once boundary bridged |
| Redaction sinks | `crypto::logging::{TruncatedPubkey, RedactedUrl, TruncatedRoot}`, `telemetry::config::redact_endpoint` | zero-alloc `Display`; settled format; one new wrapper |
| Field convention | `snake_case`, spans-first, canonical registry (house standard) | OTel `snake_case` is SHOULD (R2); registry kills synonym drift |
| `request_id` | `uuid::Uuid::new_v4()` + `x-request-id` header | matches `keymanager-api` precedent (`handlers.rs`); already a dep |
| Inbound extractor | in-repo `telemetry::propagation` fn (not a crate) | compose into existing module; no opinionated 3rd-party init crate |
| Secret-leak gate | `clippy.toml` `disallowed-methods` + `tracing_test` + `gitleaks` | rides existing `-D warnings` + `nextest`; no nightly/dylint for P0 |
| Static level cap | `release_max_level_debug` (both bins) | `trace` compiled out of release; `debug` runtime-switchable (PRD wants prod escalation) |
| Bench harness | `criterion` (dev-dep) + counting `#[global_allocator]` test | allocation assertion is the precise P0-6 gate |
| Test runner | `cargo nextest run --workspace` | `cargo test --workspace` can deadlock (project history) |

---

## ADRs (Architecture Decision Records)

### ADR-001: Static level cap — `release_max_level_debug` on both binaries
- **Status:** Accepted (forwarded to gate to confirm vs `release_max_level_info`).
- **Context:** P0-6 requires `trace!` to add zero binary cost in production; operators must still be
  able to escalate to `debug` via `RUST_LOG` without a separate build (PRD user story; overview
  Assumption 4 / Open Q).
- **Decision:** Compile `tracing = { features = ["release_max_level_debug"] }` into `bin/rvc` and
  `bin/rvc-signer`. `trace!` and below-cap spans are physically removed from `--release`; `debug!`
  stays runtime-gated by `EnvFilter`.
- **Alternatives considered:** (a) `release_max_level_info` — removes `debug` too, but then
  `RUST_LOG=debug` does nothing in prod and an operator needs a separate build; rejected against the
  PRD requirement. (b) keep all levels compiled in — leaves residual `EnvFilter` dynamic-directive cost
  and `trace!` binary weight; weaker P0-6.
- **Consequences:** Strongest practical P0-6; also neutralizes the per-callsite `enabled()` cost for
  below-cap sites (nothing left to call). Cost: a release build cannot emit `trace` without rebuild —
  acceptable (taxonomy says `trace` is never on in prod). Must **not** enable tracing's `log` feature
  (re-introduces cost under a static cap).

### ADR-002: `request_id` source and the inbound :9000 extractor (and its one new edge)
- **Status:** Accepted (`request_id` source forwarded to gate as overview notes).
- **Context:** The :9000 `sign` handler starts a fresh root trace (no inbound extraction) and carries no
  `request_id`; the duty appears as two disconnected traces and the `ParentBased` sampler re-rolls
  independently (otel-correlation §1–2; latent today because `sample_rate` defaults to 1.0).
- **Decision:** (1) Add `telemetry::propagation::set_parent_from_headers` (inbound inverse of
  `inject_trace_context`) and call it first in the sign handler. (2) Mint `request_id` as
  `uuid::Uuid::new_v4()` once per operation on the rvc side, carry it on the span and across the hop via
  both W3C `traceparent` and an explicit `x-request-id` header the signer echoes. (3) This requires the
  single new production edge **`rvc-signer-bin → rvc-telemetry`**.
- **Alternatives considered:** (a) derive `request_id` from the OTel trace/span ID — one fewer header,
  but less human-followable and absent when no `traceparent` is sent; kept as a gate option. (b) adopt
  `axum-tracing-opentelemetry` — opinionated about init (which `telemetry` already owns) and has no
  published releases; rejected. (c) put the extractor in a new crate — needless node + edge.
- **Consequences:** Trace is continuous across :9000; sampler honors the upstream decision
  all-or-nothing. The new edge is acyclic and touches no `architecture-tests` policy table, so the
  cycle gate stays green without edits. `x-request-id` is additive and ignored by clients that don't
  send it.

### ADR-003: Shared logging primitives live in `crypto::logging` + `telemetry::propagation`, not a new crate
- **Status:** Accepted.
- **Context:** The candidate needs four shared primitives (`TruncatedPubkey`/`RedactedUrl` exist;
  `TruncatedRoot` + `field` consts new) and one new function (inbound extractor). A convention-led
  design must add the **fewest** nodes/edges and create **no** cycle in the 23-crate DAG.
- **Decision:** Host the redaction wrappers + field consts in **`crypto::logging`** (already there;
  `crypto` is below all 12 consumers, above only `eth-types`). Host the inbound extractor in
  **`telemetry::propagation`** (next to its inverse; `telemetry` depends on no domain crate). Mint
  `request_id` at call sites with `uuid` (no module).
- **Alternatives considered:** (a) a new `rvc-logging` crate aggregating all primitives — adds a node
  the cycle gate must learn, forces new edges from `crypto`/`signer`/`slashing`/binaries downward, and
  buys nothing because `crypto` is already a universal dependency; rejected as pure friction. (b) put
  field consts in `eth-types` — `eth-types` is a gate-enforced zero-out-edge leaf and carries no
  logging concepts; wrong home. (c) put the extractor in `crypto` — `crypto` doesn't depend on
  `tracing-opentelemetry` and shouldn't; wrong layer.
- **Consequences:** **Zero new edges** for the redaction/field surface; **one** acyclic edge
  (`rvc-signer-bin → telemetry`) for the extractor. No `architecture-tests` policy edits. Maximally
  low-friction placement consistent with the existing graph.

### ADR-004: Convention over a shared logging facade/macro layer
- **Status:** Accepted.
- **Context:** An alternative candidate could ship a shared logging crate with wrapper macros
  (`log_duty!`, a `LogContext` builder, a re-export of `tracing` with house defaults) so correctness is
  enforced by code rather than a document. This candidate is explicitly the **convention-led** one.
- **Decision:** Ship **no** facade and **no** wrapper macros. Crates call `tracing` directly and follow
  `STANDARD.md`. The only shared code is the four redaction/field primitives and the one extractor —
  each justified because convention there is *unsafe* (a doc can't stop a `Debug`, a missing extractor
  is a real bug, a guarantee needs mechanics), not merely *inconsistent*.
- **Alternatives considered:** wrapper-macro / typed-context layer — gives compile-time enforcement of
  field names and levels, but adds a node, an edge from every crate, a learning surface, and ongoing
  maintenance, and tends to ossify call sites; it is the *opposite* of low-friction. Rejected for this
  candidate (it is the natural shape of a *different*, "enforced-helper" candidate).
- **Consequences:** Lowest friction and least net-new code/maintenance; fastest adoption. The cost is
  that field-name/level correctness rests on the doc + reviewer + the (future, P2-4) conformance lint,
  not the compiler. The redaction safety net (clippy + tests + gitleaks) covers the one class of
  mistakes that must never ship (secret leaks); style drift is caught in review.

### ADR-005: File log may be more verbose than console (file `debug`, console `info`)
- **Status:** Accepted (contingent confirmation per overview Open Q).
- **Context:** Lighthouse/Lodestar default the file to `debug` while the console stays `info`; migrating
  operators expect this. It is only viable if the existing `logroller`/non-blocking appender supports an
  independent level.
- **Decision:** Document file-more-verbose-than-console as the **sanctioned recipe** in
  `STANDARD.md`/`OPERATOR_GUIDE.md`. `bin/rvc` already threads `logfile_level` into
  `FileAppenderConfig` (`main.rs:937`), so it is supported today; `bin/rvc-signer` gains the same
  option in Phase 4.
- **Alternatives considered:** force file == console level — simpler but loses the operator-familiar
  "quiet console, rich file" pattern and a post-incident detail source. Rejected.
- **Consequences:** No appender redesign (the level field already exists). Console stays a clean `info`
  heartbeat; the file retains `debug` detail for forensics.

### ADR-006: Spans-first correlation (canonical IDs on spans, not repeated per event)
- **Status:** Accepted.
- **Context:** Correlating one duty across crates and the :9000 hop requires the same
  `slot`/`pubkey`/`duty`/`request_id` on every related line. Two shapes: stamp them on the span (inherit
  to children) or repeat them on every event.
- **Decision:** **Spans-first.** Canonical IDs live once on the `#[instrument]` span; the OTLP layer
  maps span fields → span attributes and events → span events that inherit them; per-event fields carry
  only event-specific data. Honor R1: `#[instrument(fields(...))]` evaluates eagerly, so keep its
  fields to `Copy` scalars / cheap values and move costly/`%`-formatted work to event-family macros or
  behind `enabled!`.
- **Alternatives considered:** (a) per-event fields on every call — verbose, drift-prone (the
  `val_idx`/`validator` synonym problem the PRD kills); allowed only as a *targeted* supplement (stamp
  `request_id` on terminal events) for flat backends that drop span fields (PRD Open Q5). (b) flat
  `log`-style events, no spans — throws away the main reason to be on `tracing`; rejected.
- **Consequences:** Lowest per-call-site friction (short `info!`/`debug!` lines), best OTLP fit, and the
  property that makes a convention-led approach scannable. Mitigation for span-flattening backends is
  documented but not implemented by default.

---

## Open Questions

1. **Static cap:** confirm `release_max_level_debug` over `release_max_level_info` (PRD's "escalate to
   `debug` in prod via `RUST_LOG`" points to `debug`). (ADR-001.)
2. **`request_id` source:** fresh `uuid::Uuid::new_v4()` + `x-request-id` (recommended) vs derive from
   the OTel trace/span ID (one fewer header). (ADR-002; overview Open Q.)
3. **Secret-leak gate mechanism (PRD Open Q3):** is the clippy + captured-subscriber + `gitleaks`
   (+ reviewer checklist) stack acceptable as P0 if the brittle regex *source* scan is dropped? (This
   candidate assumes yes — it is stronger than the PRD minimum.)
4. **Output default (PRD Open Q4):** keep pretty as the default, document JSON as the sanctioned
   aggregation profile (P2-3)? Confirm.
5. **Spans-first strictness (PRD Open Q5):** confirm we do **not** also repeat correlation fields on
   every event (only `request_id` on terminal events as a flat-backend mitigation).
6. **File-vs-console independent level (overview Open Q):** confirm the `logroller`/non-blocking
   appender honors a file level independent of console for `bin/rvc-signer` (already true for `bin/rvc`
   via `logfile_level`). (ADR-005.)
7. **`error`-vs-`warn` re-categorization breadth (PRD Open Q6):** how aggressive should the P1-3
   normalize pass be, given the Non-Goal of not touching error-handling control flow? (Default:
   conservative — only clear miscategorizations and duplicate log-and-return lines.)
8. **Coarse-span granularity:** one span per phase (not per inner await) on the hottest async fns to
   bound per-poll enter/exit cost when verbose is on. Confirm the phase boundaries with the orchestrator
   owners.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Convention drift** (the core risk of a convention-led design): authors apply the standard unevenly over time | Goal not met; dashboards/filters degrade | `STANDARD.md` as the review rubric (P0-1); reviewer checklist on high-risk crates; P2-4 conformance lint; the normalize pass (P1-3). The redaction safety net covers the one drift class that must never ship. |
| **Secret leakage** via a new log statement in `crypto`/`secret-provider`/`signer`/:9000/`rvc-keygen` | Security incident | Defense-in-depth: type layer + clippy `disallowed-methods` + captured-subscriber "raw secret absent" tests + `gitleaks` source+emitted scan + reviewer sign-off (P0-3, §E). Fails closed. |
| **Hot-path latency regression** from new logging | Missed duties / slashing-deadline pressure | `level`+`skip_all`, `enabled!`/`Display` guards, `release_max_level_debug`; criterion bench + counting-allocator assertion on sign + per-slot paths (P0-6, §D/§H). |
| **R1 eager-`fields()` foot-gun:** someone puts `%`-formatted or costly work in `#[instrument(fields(...))]` | Cost runs even when span disabled | Standard rule: `#[instrument(fields(...))]` limited to `Copy`/cheap values; costly/`%` work goes on event macros or behind `enabled!`; allocation test catches sign/slot paths. |
| **Trace fragmentation at :9000** if extractor not wired before the sampler rate is lowered | Half-sampled, disconnected duty traces | Phase 2 lands `set_parent_from_headers` + keeps `ParentBased(TraceIdRatioBased)`; captured-subscriber test asserts non-zero parent on the boundary span (§F). |
| **New `rvc-signer-bin → telemetry` edge** introduces a cycle or trips the gate | Build/CI breakage | Edge is binary→sink; `telemetry` depends on no domain crate; touches no `architecture-tests` policy table — gate green without edits (Dependency Graph, ADR-003). |
| **Breaking the existing OTLP/file/propagation stack** | Lost telemetry | Non-Goal to redesign `telemetry`; compose into existing layers; keep `TracingGuard`/shutdown and the sampler exactly; rely on existing `telemetry` tests staying green. |
| **`cargo test --workspace` deadlock** masks results | False confidence | Use `cargo nextest run --workspace` (runner of record). |
| **Subscriber-init reconciliation** subtly changes default verbosity/format for `bin/rvc-signer` | Operator surprise | Documented precedence + default in `STANDARD.md`; init tests in both binaries assert default `info` + env-override + format (P0-5). |

## Assumptions

(These are *this candidate's* assumptions; the PRD's and overview's Consolidated Assumptions are
inherited.)

1. **The existing `telemetry`/OTLP/file/propagation/sampler/`TracingGuard` stack is correct and stays**
   — composed into, never rebuilt (PRD Non-Goals; overview Assumption 1).
2. **`crypto::logging` is the right home for shared redaction/field primitives** — `crypto` is a
   universal lower-layer dependency (12 consumers), already hosts `TruncatedPubkey`/`RedactedUrl`, and
   depends only on `eth-types` upward, so adding `TruncatedRoot` + `field` consts there creates no new
   edge and no cycle. (Verified against `Cargo.toml` graph + the `architecture-tests` gate.)
3. **`telemetry::propagation` is the right home for the inbound extractor** — it already hosts the
   outbound inverse and depends on no domain crate. The single new edge `rvc-signer-bin → telemetry`
   is acyclic and policy-table-neutral.
4. **`bin/rvc-signer` taking a `telemetry` dependency is acceptable** (it is the same shape `bin/rvc`
   already has) and is the cleanest way to (a) call the extractor and (b) reconcile subscriber init.
   The alternative (duplicate the extractor inline in the binary) is rejected as code duplication.
5. **A convention-led approach is acceptable for everything except secret redaction, cross-process
   trace continuity, and zero-cost-when-disabled**, where this candidate spends its entire shared-code
   budget. Field-name/level correctness rests on the doc + review + (future) conformance lint.
6. **The clippy `disallowed-methods` gate + captured-subscriber tests + `gitleaks` (source+emitted) +
   reviewer checklist** satisfy P0-3, with the brittle regex *source* scan optional (overview §E
   fallback; PRD Open Q3). No nightly/dylint toolchain is required for P0.
7. **`release_max_level_debug`** is the chosen static cap (forwarded to gate vs `info`).
8. **Pubkeys are truncated even at `trace`; full roots/signatures are truncated/omitted by default;
   `network` stays a resource attribute** (PRD Open Qs 1&2 resolved-to-stricter; overview Assumption 6).
9. **`rvc-keygen` is treated as high-risk for the mnemonic rule** even though the PRD lists it under P1
   breadth (overview Assumption 9) — its redaction tests land in Phase 3, its broader logging in Phase 5.
10. **`uuid` is reachable at the call sites that mint `request_id`** (it is a workspace dependency used
    by `keymanager-api` already); no new dependency is needed for `request_id`.
11. **The `architecture-tests` cycle gate remains the dependency-direction enforcer**; this candidate is
    designed so it needs **no** edits to its `FORBIDDEN` / `ZERO_OUT_EDGE_IF_PRESENT` / `REQUIRED_EDGE`
    tables.
```
