# Software Architecture: rs-vc Structured Logging & Observability

> **Final architecture** for the rs-vc logging initiative. Authoritative inputs: the PRD
> [`plan/logging/prd.md`](./prd.md) and the research overview
> [`plan/logging/research/00-overview.md`](./research/00-overview.md) (which is authoritative over
> the per-angle docs; its reconciliations **R1–R9** and Consolidated Assumptions are honored
> throughout).
>
> **This is a cross-cutting observability initiative on an existing system, not a new build.** Nothing
> here rebuilds the runtime, the `telemetry` crate, the OTLP/GCP exporters, the `logroller` file
> appender, the `ParentBased(TraceIdRatioBased)` sampler, or the `TracingGuard` contract. Every
> component **composes into** the existing `tracing` + `tracing-subscriber` + OpenTelemetry stack
> (PRD Non-Goals; Assumption 1).
>
> This document is a **blend** of three candidate designs, taking the *enforcement-led* spine (every
> normative rule is paired with an automated, machine-checked gate — proportionate to the threat that
> a leaked BLS key is a security incident), grafting the *library-led* dependency-graph placement
> proof and zero-alloc primitive shapes, and adopting the *convention-led* `STANDARD.md`-as-product
> framing so the standard is both **documented** (a human-readable contract) and **enforced** (a CI
> gate). All load-bearing file/graph claims below were verified against the tree at `develop`.

---

## Overview

rs-vc is a 23-crate / 3-binary Cargo workspace (an Ethereum validator client) that signs and
broadcasts attestations and blocks on a strict per-slot deadline. An unobservable incident costs
rewards; a leaked secret is a security incident. The logging machinery already exists
(`tracing` 0.1 / `tracing-subscriber` 0.3 / `tracing-opentelemetry` 0.32 / `opentelemetry*` 0.31,
the `telemetry` crate, the `crypto::logging` redaction wrappers, 72 `#[instrument]` sites). What is
missing is **one standard**, the **runtime hot paths fully observable** at `debug`/`trace`, **zero
secret leakage**, **zero hot-path overhead when verbose is disabled**, reconciled subscriber init
across both binaries — and, above all, **enforcement that the standard cannot silently drift**.

The architecture rests on three pillars working together:

1. **A normative standard document (`STANDARD.md`)** — the level taxonomy, the canonical `snake_case`
   spans-first field registry, and the secret-redaction policy, with copy-paste examples. This is the
   human-readable contract every PR is measured against (PRD P0-1), referenced from a module doc in
   `telemetry`.

2. **A thin shared-primitives layer placed by dependency cost** — dependency-light primitives
   (`TruncatedRoot`, canonical field-name constants, `request_id` minting, span-record helpers) sink
   into `crypto::logging`, the lowest universally-reachable crate, which already hosts
   `TruncatedPubkey`/`RedactedUrl` and already carries `uuid`/`hex`. The one OTel-coupled primitive
   (the inbound W3C trace-context extractor for the :9000 boundary) extends `telemetry::propagation`,
   the only crate with the OTel deps. This split is what keeps the 23-crate graph acyclic: **no new
   crate; only one new production edge in the whole initiative** (`rvc-signer-bin → telemetry`), which
   is provably acyclic because `telemetry` has zero workspace-internal dependencies.

3. **An automated enforcement layer that rides the existing CI** — each normative rule is paired with
   a machine-checked gate at near-zero new infrastructure: a `clippy.toml` `disallowed-methods` lint on
   the secret-laundering sinks (rides the existing `-D warnings` step); captured-subscriber
   conformance tests asserting redaction, levels, and fields (ride `nextest`); a dependency-free
   counting-`#[global_allocator]` zero-alloc test (the precise P0-6 gate); a single new `gitleaks` PR
   job scanning source **and** emitted log output; and the **existing** `architecture-tests` DAG gate
   for the no-cycle invariant. **The guiding stance: prefer a machine-checked guarantee over a
   documented convention. If a rule cannot be machine-checked, it is downgraded to advisory and
   flagged — never presented as a guarantee.** The shared-code budget is spent where convention is
   *unsafe* (secret redaction, cross-process trace continuity, zero-cost-when-disabled) and the doc
   carries everything else.

---

## Architecture Principles

- **Document the standard, enforce the standard.** `STANDARD.md` is the normative contract (the
  fastest, lowest-friction way to align 23 crates); every rule that *can* be machine-checked ships with
  a gate so drift is a CI failure, not a reviewer judgment call. Advisory-only rules are explicitly
  labelled. *(Blends convention-led's "doc is the product" with enforcement-led's "convention a
  reviewer can forget is not a guarantee.")*
- **Ride the existing CI; no new mandatory toolchain for P0.** Gates attach to steps that already
  exist (`cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`,
  `cargo nextest run --workspace` / the coverage job, the standing `architecture-tests` DAG gate). The
  only net-new CI job is one `gitleaks` action. Nightly/`dylint`/`--cfg tracing_unstable` are **P2**,
  never P0 blockers.
- **Compose into the telemetry stack, never rebuild it.** `init`, `config`, `file_appender`,
  `propagation`, `shutdown`, the sampler, and `TracingGuard` are foundations; new work is additive
  (new free functions, new `Display` wrappers, new const modules, layers added to an existing
  `Registry` builder).
- **Place primitives by dependency cost, never by theme.** Dependency-light primitives sink to the
  lowest universally-reachable crate (`crypto`); the OTel-coupled primitive stays in the OTel-owning
  leaf (`telemetry`). This is the rule that prevents cycles across 23 crates and is **verified, not
  asserted**, by the `architecture-tests` gate (ADR-007).
- **Spend shared code only where convention is unsafe.** Three places justify net-new code: secret
  redaction (a doc cannot stop a `Debug`), the inbound trace extractor (a missing inverse is a real
  bug, not a style choice), and zero-cost-when-disabled mechanics (a guarantee needs mechanism).
  No facade, no wrapper-macro layer, no per-crate logging module (ADR-009).
- **Spans-first correlation.** Canonical IDs (`slot`, `epoch`, `validator_index`, `pubkey`, `duty`,
  `request_id`, `committee_index`/`subcommittee_index`) live **once** on `#[instrument]` spans; child
  events inherit them and the OTLP layer turns them into span attributes. `network` stays a resource
  attribute (research recommendation 2; ADR-006).
- **Defense in depth for secrets.** No single layer suffices: type-level redaction (secrets do not
  `Display`) + a CI lint gate (`disallowed-methods` on `expose_secret`/`raw_bytes`/`to_bytes`) +
  runtime captured-subscriber proof + a `gitleaks` scan over *emitted* output, applied with explicit
  sign-off to the four high-risk crates plus `rvc-keygen` mnemonics (research §E).
- **Zero-cost-when-disabled is a tested property, not a hope.** `level` + `skip_all` on every hot-path
  `#[instrument]`; expensive fields gated by `enabled!` or wrapped in a zero-alloc `Display`;
  `release_max_level_debug` compiled into both binaries; proven by a counting-`#[global_allocator]`
  zero-alloc test (the precise gate) plus a `criterion` latency sanity bench (research §D, §H).
- **`#[instrument(fields(...))]` evaluates EAGERLY (research R1 — the most important correction).**
  Field expressions on `#[instrument]` run on *every call regardless of span level*. So `fields(...)`
  carries only `Copy` scalars / pre-resolved cheap values; all real formatting (hex, truncation
  `Display`, JSON) goes on an event-family macro (`debug!`/`trace!`) or behind `enabled!`. The
  primitives are shaped so the cheap thing is the easy thing.

---

## System Context Diagram

```text
                       RUST_LOG / EnvFilter (env overrides config default = info)
                                          │
  ┌──────────────┐  W3C traceparent    ┌──┴────────────────────────────┐  OTLP/HTTP   ┌──────────────┐
  │ Lighthouse / │ ──+ x-request-id──▶ │        rs-vc workspace         │ ───spans───▶ │ OTel Collector│
  │ Prysm (VC)   │ ◀─── signature ──── │ bin/rvc · bin/rvc-signer:9000  │              │ (+ GCP Trace) │
  └──────────────┘                     │ bin/rvc-keygen · 23 crates     │              └──────────────┘
                                       └───────┬───────────────┬────────┘
  ┌──────────────┐  redacted bn_url            │ console (fmt) │ file (logroller, non-blocking)
  │ Beacon Nodes │ ◀── HTTP + traceparent ─────┘  info default │ debug default (file ≥ console)
  └──────────────┘                                             ▼
                                                       operator / SRE log stream
  ┌────────────────────────────── CI (self-policing gates) ──────────────────────────────────────┐
  │ cargo fmt ── cargo clippy -D warnings (+ clippy.toml disallowed-methods)                       │
  │ cargo nextest run --workspace (captured-subscriber + zero-alloc tests)                         │
  │ gitleaks PR job (source + emitted-log sample)        architecture-tests DAG gate (no cycles)   │
  └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

The system boundary is unchanged. The only **new** wire-level behavior is **reading** an inbound
`traceparent` / `x-request-id` on :9000 (additive; ignored if absent) plus an additive `x-request-id`
on outbound calls. Signing behavior, public APIs, and the OTLP export path are untouched.

---

## Component / Module Overview

This is an observability layer, so "modules" are **(a) the standard artifact**, **(b) the thin
shared-primitive surface homed in existing crates**, **(c) the 23 crates as self-applying consumers**,
and **(d) the CI gates that police them**. No new crate is created — that is the point of placing
primitives by dependency cost. The table makes the shared-vs-convention-vs-enforced split explicit.

| Component | Kind | Responsibility | Net-new? | Home | New edge? | Enforced by |
|---|---|---|---|---|---|---|
| `STANDARD.md` | Doc (primary) | Normative taxonomy + field registry + redaction policy + examples | **New doc** | `plan/logging/` (ref'd from `telemetry` `//!`) | — | review rubric + Gates below |
| `OPERATOR_GUIDE.md` | Doc | `RUST_LOG` recipes, pretty-vs-JSON, following a `request_id` (P1-4) | New doc | `plan/logging/` | — | — |
| Redaction Kit | Shared code | `TruncatedPubkey`, `RedactedUrl` (exist) + **`TruncatedRoot`** (new, zero-alloc `Display`) | new (small) | `crypto::logging` | no | Gate 3 (captured-subscriber) |
| Field Registry | Shared code | Canonical `snake_case` field-key `const`s + `Duty` value strings | new (tiny) | `crypto::logging::fields` | no | Gate 5 (advisory→blocking) |
| Correlation Kit | Shared code | `new_request_id()` (`Uuid::new_v4`) + `record_display`/`record_debug` span helpers | new (small) | `crypto::logging` | no | Gate 3 (presence test) |
| Inbound Trace Extractor | Shared code | `HeaderExtractor` + `set_parent_from_headers` (inverse of `inject_trace_context`) | new (small) | `telemetry::propagation` | **`rvc-signer-bin → telemetry`** | unit test (non-zero parent) |
| Subscriber-init reconciliation | Code change | One default level + EnvFilter precedence + format, both bins | change | `telemetry` helper + each `main.rs` | (same edge) | init parity tests both bins |
| Span/level strategy | Convention (applied) | `#[instrument]` `level=`/`skip_all`/`fields` idioms on hot paths | per-crate edits | each crate | no | Gate 3 + Gate 1 (`skip_all` via sinks) |
| Zero-overhead harness | Safety net | counting-`#[global_allocator]` test + `criterion` sign bench + `release_max_level_debug` | new (additive) | `crypto`/`signer` bench+test, both bins' Cargo.toml | dev-dep only | Gate 4 (the precise P0-6 gate) |
| Secret-leak CI gate | Safety net | `clippy.toml` `disallowed-methods` + `gitleaks` (source + emitted) | new (additive) | `clippy.toml`, `ci.yml`, 4+1 crates | no | the gates themselves (fail-closed) |
| DAG invariant gate | Safety net | new edges introduce no cycle | exists | `architecture-tests` | no | `cargo metadata` parse, already in CI |
| 23 crates + 3 bins | Consumers | Self-apply `STANDARD.md` via `tracing` macros / `#[instrument]` | per-crate edits | each crate | no | Gates 1/3/5 + review |

**Why no new crate, and why `crypto::logging` is the canonical home for the light primitives** (the
load-bearing boundary decision): a new `obs`/`logging` crate would have to be a dependency of `crypto`
(so `crypto` can truncate) *and* would want OTel (for the extractor), re-creating the exact coupling
we are avoiding — and it would add a node the DAG gate must learn plus up to ~23 new edges for zero
benefit. `crypto` is already a universal dependency, already hosts `TruncatedPubkey`/`RedactedUrl`,
and already carries `uuid`, `hex`, `tracing`, `url`, `eth-types` (verified in
`crates/crypto/Cargo.toml`). The truly-lowest crate `rvc-eth-types` is excluded because the DAG gate
pins it to **zero out-edges** and it lacks `uuid`; `telemetry` is excluded for the light primitives
because most signing crates neither do nor should depend on it (ADR-007).

---

## Module Dependency Graph

Relevant existing edges (verified from the in-tree `Cargo.toml` files this pass):

```text
eth-types ──────────────▶ (zero out-edges; PINNED by architecture-tests ZERO_OUT_EDGE_IF_PRESENT)

crypto ────────────────▶ eth-types        (deps: eth-types, hex, uuid, url, reqwest, tracing — NO telemetry/OTel edge)

signer ────────────────▶ crypto, slashing, doppelganger, eth-types, metrics   (the instrumented rvc.sign.* spans live here)
secret-provider ───────▶ crypto, metrics                                       (NO telemetry edge)
bn-manager / block-service / builder / duty-tracker / orchestrator(rvc) ─▶ crypto (+others)

beacon ────────────────▶ crypto, eth-types, telemetry   (only crate besides bins → telemetry today)

telemetry ─────────────▶ (ZERO workspace-internal deps — a leaf sink; only opentelemetry*/tracing*/reqwest/logroller)

bin/rvc ───────────────▶ telemetry, crypto, rvc, signer, beacon, bn-manager, …
bin/rvc-signer ────────▶ signer, crypto, eth-types, slashing, …   (does NOT depend on telemetry today)
bin/rvc-keygen ────────▶ crypto, …
```

Where the new primitives land (▲ = primitive added here; arrows show *call direction*, never a new
crate edge unless marked **NEW EDGE**):

```text
                              ┌──────────────────────────────┐
   ▲ Field Registry           │            crypto             │  ← already depended on by signer,
   ▲ Redaction Kit (+Root)  ──┤  crypto::logging  (the kit)   │     secret-provider, beacon, bn-manager,
   ▲ Correlation Kit          │  deps: eth-types, hex, uuid,  │     block-service, builder, duty-tracker,
   ▲ (record_* helpers)       │        url, tracing           │     orchestrator(rvc), all 3 bins
                              └───────────────┬──────────────┘
   signer / secret-provider / orchestrator / bn-manager / beacon / keygen
        ──────────── call ────────────────────┘   (NO new edge: they already depend on crypto)

                              ┌──────────────────────────────┐
   ▲ Inbound Extractor        │           telemetry           │  ← leaf, ZERO internal deps; stays a leaf
   ▲ (init helper)          ──┤  propagation:: + init::       │
                              │  deps: opentelemetry*, etc.   │
                              └───────────────┬──────────────┘
   bin/rvc, beacon  ── call ───────────────────┤   (existing edges)
   bin/rvc-signer   ── call ──── NEW EDGE ──────┘   rvc-signer-bin → telemetry  (the ONE new edge)
```

**Cycle analysis (the load-bearing guarantee).** Two candidate cycles are conceivable; both are
avoided by construction:

1. *Would `crypto → telemetry` cycle?* `crypto` does **not** depend on `telemetry` today, and we do
   **not** add that edge: the light primitives live in `crypto` itself and need no OTel. (Even if one
   *wanted* it, it would be acyclic because `telemetry` is a leaf — but it would force the heavy OTel
   tree onto `crypto` and every crate below it, and is unnecessary.) **Rejected.**
2. *Would `telemetry → crypto` cycle?* The inbound extractor needs nothing from `crypto` (it operates
   on `http`/`axum` headers + `opentelemetry`), so `telemetry` stays a leaf with **zero** internal
   deps. We do **not** move `TruncatedPubkey` into `telemetry` (that would create `telemetry → crypto`
   and, since `beacon → telemetry` and `beacon → crypto`, needlessly widen the leaf). **Rejected.**

The **single new production edge in the entire initiative is `rvc-signer-bin → telemetry`**.
`telemetry` depends on no workspace crate, so an edge *into* it from a binary is a leaf attachment —
**provably acyclic**. `beacon` and `bin/rvc` already depend on `telemetry`, so this is the established
direction.

**Verify (machine-checked):** the existing
`crates/architecture-tests/tests/architecture_no_cycles.rs` gate parses `cargo metadata --no-deps`
(via `serde_json` — no new external dep), asserts the production graph is acyclic via a 3-colour DFS,
enforces `FORBIDDEN` edges, and pins `ZERO_OUT_EDGE_IF_PRESENT = ["rvc-eth-types",
"rvc-signer-registry"]`. The `rvc-signer-bin → rvc-telemetry` edge touches **none** of its policy
tables (`FORBIDDEN`, `ZERO_OUT_EDGE_IF_PRESENT`, `REQUIRED_EDGE`), so **the gate stays green with no
edits** (verified by reading the test). This architecture additionally *recommends* extending the
policy tables to lock the new boundary (see *Enforcement Architecture → Gate 6*), so a future
contributor cannot "fix" a field-constant import by adding a `uuid`/`telemetry` edge to `eth-types`.

**Verify: No circular dependencies.** Confirmed — light primitives in `crypto`, OTel primitive in leaf
`telemetry`; exactly one new edge, into the leaf.

---

## Module Details

### Module: `STANDARD.md` — the normative standard (PRIMARY ARTIFACT, P0-1)

**Responsibility:** Be the single source of truth a reviewer and an author consult to answer "what
level, what fields, redacted how?" — so placement is never a judgment call.

**Why it is a centerpiece:** the document is the lowest-friction mechanism to align 23 crates, and it
is the rubric the gates and reviewers code against. It must be unambiguous, example-driven, and short
enough to be read.

**Contents (each section is normative):**

1. **Level taxonomy** (reproduces the PRD table verbatim). Presented as the **rs-vc house standard**
   anchored on the `tracing::Level` docs, *not* an upstream mandate (research R8). Load-bearing rule:
   *anything that scales with validator count or fires per-loop is `debug`/`trace`, never `info`.*
2. **Canonical field registry** — the exact `snake_case` keys, types, and **where each lives (span vs
   event)**. Presented as a **house standard (SHOULD-level)** per research R2 (OTel `snake_case` is a
   SHOULD; the real constraint is within-namespace uniqueness). No synonyms (`val_idx`/`validator` are
   forbidden).

   | Field | Type / format | Lives on | Rule |
   |---|---|---|---|
   | `slot` | `u64` | span | duty/att/block/sign spans |
   | `epoch` | `u64` | span | duty span |
   | `validator_index` | `u64` | span/event | |
   | `committee_index` | `u64` | span/event | matches Lighthouse (migration source); not `index`/`CommitteeIndex` |
   | `subcommittee_index` | `u64` | span/event | sync-committee contribution lines only |
   | `pubkey` | truncated `0x{first10}...{last8}` | span/event | **always** `crypto::logging::TruncatedPubkey` + `%`; never the full key, even at `trace` |
   | `duty` | enum string (`attestation`/`block`/`aggregate`/`sync_committee`/…) | span | from `fields::Duty::as_str()` |
   | `request_id` | uuid string | span | one per signing/API request, incl. :9000 |
   | `bn_url` | redacted URL | event | **always** `crypto::logging::RedactedUrl` |
   | `head` | truncated root | event | attested head root (`TruncatedRoot`) |
   | `block_root` | truncated root | event | proposed block root (`TruncatedRoot`) |
   | `time_into_slot` | duration/ms | event | Nimbus-style operator timing signal |
   | `network` | string | **resource attr** | set once in `telemetry::init`; never per-event |

3. **Redaction policy** (the MUST/MUST-NOT rules; see the Redaction module).
4. **`#[instrument]` idioms** — the eager-`fields()` rule (R1), `skip_all`-first, `level="debug"` on
   hot fns, the async-correctness rules, `err`-once.
5. **Worked examples** — a duty span, a sign span, an `enabled!`-guarded trace dump, the
   `field::Empty` + `record()` late-bind pattern. Copy-paste ready.
6. **`info` heartbeat shape** (research §G) — the milestone set, the Lodestar-style `Signed`(debug) /
   `Published`(info) split, the `time_into_slot`/`delay` timing field.

**Data store:** none (a Markdown file). **Public API:** the field registry and rules are the
"interface" every crate codes against.

**Key design decisions:**
- The registry table is the **normative artifact**; the `crypto::logging::fields` consts are an
  *optional* compile-checked mirror, not a mandated import (keeps friction low — a crate may type the
  literal `slot` ident in `#[instrument(fields(slot = …))]`, which the macro requires anyway, and
  still be conformant). The consts back the event-family macros and the Gate 5 conformance lint.
- Referenced from a `//!` module doc in `telemetry` so it is discoverable from code (PRD P0-1
  "referenced from the codebase").

**Failure modes:** the doc going stale is the main risk — mitigated by Gate 5 (field-name
conformance, advisory→blocking) and by the doc being the review rubric.

---

### Module: Redaction Kit (`crypto::logging` — `TruncatedPubkey`, `RedactedUrl`, **`TruncatedRoot`**)

**Responsibility:** Provide the *only* sanctioned, zero-allocation way to render a pubkey, a URL, or a
32-byte root/hash/signature in a log line — safe at every level including `trace`.

**Domain entities:**
- `TruncatedPubkey<'a>(pub &'a str)` — **existing, unchanged**; renders `0x{first10}...{last8}`,
  zero-alloc `Display`, warns + falls back on a double-`0x` prefix (`crypto/src/logging.rs:5`,
  verified).
- `RedactedUrl<'a>(pub &'a str)` — **existing, unchanged**; strips `user:pass@` via `url::Url`, raw
  fallback on parse failure (`crypto/src/logging.rs:40`, verified).
- **`TruncatedRoot<'a>(pub &'a [u8])`** — **new**; `Display` renders `0x{first10}...{last8}` (matching
  `TruncatedPubkey`'s 10-leading/8-trailing hex-char shape and glyph) for a `&[u8; 32]`/`&[u8]`
  block/head/signing root, hash, or signature, zero-alloc, hex-rendered lazily inside `fmt`.

**Public API:**

| Item | Signature | Output | Description |
|---|---|---|---|
| `TruncatedRoot::new` | `(bytes: &[u8]) -> Self` | — | Wrap a root/hash/signature for `%`-rendering |
| `impl Display for TruncatedRoot` | — | `0x{10hex}...{8hex}` | Hex-renders first 5 + last 4 bytes; for `< 9` bytes renders full lower-hex; never panics |

**Key design decisions:**
- **`TruncatedRoot` takes `&[u8]`, not `&str` (ADR-005).** Roots arrive as `Root`/`[u8; 32]` on the
  hot path; forcing the caller to `hex::encode` first would *allocate even when the level is disabled*
  (the R1 trap). Rendering bytes directly inside `Display::fmt` keeps it zero-alloc and lazy (only runs
  under `%` on an enabled event). This is the single most important shape choice for P0-6 on the sign
  path: `crates/signer/src/lib.rs:170` and `:359` currently do `let signing_root_hex =
  hex::encode(signing_root)` **eagerly into a local** and `:161-174` build `%format!("0x{}",
  hex::encode(...))` fields — exactly the unconditional allocation `TruncatedRoot(&[u8])` exists to
  replace (all verified in-tree).
- **Glyph:** `...` (three ASCII dots), matching the settled `TruncatedPubkey` format so all three
  wrappers read consistently (research R9). Drop the unverifiable "Lighthouse truncates roots"
  precedent (research R6) — this is an rs-vc house choice for readability + safety, not an imitation.
- **No `Display` is ever added to a secret type.** `TruncatedRoot` wraps a *non-secret* root; secret
  bytes (BLS key, password, mnemonic, full signature material) have **no** wrapper and **no**
  `Display` — they are simply never passed to a logging macro (enforced by Gates 1/3/2).

**Failure modes:** malformed/short input renders the available bytes as full lower-hex rather than
panicking (mirrors `TruncatedPubkey`'s short-input branch). Gate 3 asserts a real 32-byte root renders
truncated and that the full hex is **absent** from output. There is no runtime dependency to be "down".

---

### Module: Field Registry (`crypto::logging::fields`)

**Responsibility:** Be the single compile-time source of truth for canonical `snake_case` field keys
so no crate can invent a synonym (`val_idx`, `validator`, `rvc.slot`).

**Domain entities:**
- `pub const SLOT: &str = "slot"` … one `&'static str` const per canonical key in the registry
  (`SLOT`, `EPOCH`, `VALIDATOR_INDEX`, `PUBKEY`, `DUTY`, `REQUEST_ID`, `COMMITTEE_INDEX`,
  `SUBCOMMITTEE_INDEX`, `BN_URL`, `HEAD`, `BLOCK_ROOT`, `TIME_INTO_SLOT`).
- `pub enum Duty { Attestation, Block, Aggregate, SyncCommittee, SyncContribution,
  ValidatorRegistration, VoluntaryExit }` with `as_str() -> &'static str` returning the normative
  `duty` value strings (research §G: `sync_committee`, not Prysm/Lodestar spellings).

**Key design decisions:**
- **Consts, not an enum-of-keys**, so `#[instrument(fields(slot = …))]` can still use the literal
  `slot` ident (the macro needs an ident, not a `&str`). The consts exist for *event-family* macros
  (`debug!(fields::SLOT = slot, …)` is not how `tracing` keys work — they back `record()` call sites
  and the Gate 5 conformance diff) and as the refactor-safe, greppable source of truth.
- `Duty::as_str()` returns `&'static str` so it is a `Copy`-cheap span field (R1-safe on
  `#[instrument(fields(duty = %Duty::…))]`).

**Failure modes:** none (pure data). A typo'd key is caught by Gate 5 diffing emitted/source field
names against this registry, not at runtime.

---

### Module: Correlation Kit (`crypto::logging` — `request_id` + span helpers)

**Responsibility:** Mint and carry the `request_id` that follows a single signing/API request end to
end (including across the :9000 hop), and provide the helpers to fill deferred span fields correctly.

**Domain entities:**
- `new_request_id() -> uuid::Uuid` — `Uuid::new_v4()`, matching the `keymanager-api` precedent
  (`crates/keymanager-api/src/handlers.rs:348` mints `Uuid::new_v4()` and logs `request_id = %req_id`,
  verified). Returns a `Uuid` so callers render with `%` (zero-alloc when the span level is disabled;
  a pre-built `String` would allocate unconditionally).
- `record_display(span: &Span, key: &'static str, val: impl Display)` /
  `record_debug(span, key, val: impl Debug)` — thin wrappers over `span.record(key,
  tracing::field::display(val))` / `…::debug(val)`, because the `%`/`?` sigils are macro sugar and do
  **not** work at a `record()` call site (research §A), and because `record()` on a field **not
  declared at span creation is silently dropped** (the #1 "vanishing attribute" bug).

**Public API:**

| Item | Signature | Description |
|---|---|---|
| `new_request_id` | `() -> uuid::Uuid` | Fresh v4 uuid per logical operation |
| `record_display` | `(&Span, &'static str, impl Display)` | Fill a `field::Empty` span field, lazily |
| `record_debug` | `(&Span, &'static str, impl Debug)` | Fill a `field::Empty` span field, lazily |

**Key design decisions:**
- **`request_id` source = fresh `Uuid::new_v4()` + `x-request-id` header (ADR-002)**, matching the
  in-tree `keymanager-api` precedent (research Assumption 7). Deriving it from the OTel trace/span id
  is the rejected alternative (it couples the human-readable id to sampling/trace presence and is empty
  when no OTel layer is active).
- **The deferred-field pattern is a first-class primitive**, not left to per-crate memory: a span on
  the :9000 path is created with `slot = tracing::field::Empty`, `duty = Empty`, `pubkey = Empty`,
  `request_id = Empty`, then filled via `record_display` after the body is parsed (mirrors the existing
  `http.status_code = Empty` pattern in `beacon::client`). Shipping `record_display`/`record_debug`
  removes the two foot-guns (sigil-at-record, undeclared-field) by construction.

**Failure modes:** if a field was not declared `Empty` at creation, `record_*` is a silent no-op —
caught by Gate 3 asserting the field is present on the emitted span, not at runtime. `request_id`
minting is infallible.

---

### Module: Inbound Trace Extractor (`telemetry::propagation::set_parent_from_headers`)

**Responsibility:** Bridge the W3C trace context **into** the :9000 `sign` span so a duty trace is
all-or-nothing end to end under the existing `ParentBased(TraceIdRatioBased)` sampler — the exact
inverse of the existing `inject_trace_context` (`telemetry/src/propagation.rs:25`, verified).

**Domain entities:**
- `HeaderExtractor<'a>(&'a http::HeaderMap)` implementing `opentelemetry::propagation::Extractor`
  (mirror of the existing `HeaderInjector` at `propagation.rs:6`).
- `set_parent_from_headers(span: &tracing::Span, headers: &http::HeaderMap)` — reads
  `traceparent`/`tracestate` via the global `TextMapPropagator` and sets the span's OTel parent via
  `OpenTelemetrySpanExt::set_parent` (the trait is already imported in this module).

**Public API:**

| Item | Signature | Description |
|---|---|---|
| `set_parent_from_headers` | `(&tracing::Span, &http::HeaderMap)` | Set the inbound span's parent from W3C headers; no-op (root) if absent/invalid — identical in spirit to the existing inject no-op |

Re-exported from `telemetry::lib` next to `inject_trace_context`.

**Key design decisions (research §F, R3):**
- **Lives in `telemetry`, not `crypto`** — it needs `opentelemetry`/`tracing-opentelemetry`, already
  in `telemetry` (verified in `telemetry/Cargo.toml`). `bin/rvc-signer` gains the `→ telemetry` edge
  (the one new edge) to call it; that edge is acyclic. No leaf widening.
- **Header type = `http::HeaderMap`, not `reqwest::header::HeaderMap`.** The inbound :9000 handler
  holds `axum::http::HeaderMap` (verified: `routes.rs:56` — `headers: axum::http::HeaderMap`). Both
  `axum` and `reqwest` re-export the same `http` crate's `HeaderMap`, so a single `&http::HeaderMap`
  extractor serves the server side while the existing `reqwest`-typed injector stays as-is. The
  extractor is written against `http::HeaderMap` to avoid pulling `axum` into `telemetry` (Open Q1:
  confirm `telemetry` can name `http::HeaderMap` without a new dep — `reqwest` already re-exports it; a
  direct `http` dep, if needed, is a leaf-internal external dep with no internal edge).
- **Reject `axum-tracing-opentelemetry`.** Research evaluated it and rejected it (pre-1.0, opinionated
  init that `telemetry` already owns). The ~20-line extractor is additive and keeps
  sampler/propagator ownership in one place.
- **Sampler untouched** — bridging the boundary is exactly what makes the existing
  `ParentBased(TraceIdRatioBased(rate))` keep a duty trace whole once `rate < 1.0`; today the
  fragmentation is latent because `sample_rate` defaults to `1.0` (research §F).

**Failure modes:** absent/garbled `traceparent` (Prysm/Lighthouse may not send one) → empty context →
the span stays a root (no worse than today). No panic, no signing-behavior change. A unit test asserts
that *with* a synthetic inbound `traceparent`, the :9000 span's OTel parent is non-zero (continues the
trace), and Gate 3 asserts `pubkey` on that span is truncated in the exported attributes.

**Call site (in `bin/rvc-signer`, not a telemetry concern):** the `sign` handler at
`bin/rvc-signer/src/http_api/routes.rs:52` (already `#[tracing::instrument(skip_all)]` at `:51`,
already takes `headers: axum::http::HeaderMap` at `:56` — both verified) calls
`set_parent_from_headers(&Span::current(), &headers)` **first**, then records `request_id`, `pubkey`,
`slot`, `duty` (filled via `record_display` after body parse, declared `Empty` at the span).

---

### Module: Subscriber-init reconciliation (`bin/rvc` ⟷ `bin/rvc-signer`, P0-5)

**Responsibility:** Give both binaries **one** default level (`info`), **one** `EnvFilter` precedence
(env `RUST_LOG` overrides the config/flag default), and a shared output-format selection — without
touching the OTLP layer, file appender, or `TracingGuard` contracts.

**Current divergence (verified in-tree):**

| Aspect | `bin/rvc` (`main.rs:783`, `init_logging`) | `bin/rvc-signer` (`main.rs:235`) |
|---|---|---|
| Filter | `EnvFilter::try_from_default_env().unwrap_or_else(\|_\| EnvFilter::new(level))` — config default `info`, `RUST_LOG` overrides | `EnvFilter::from_default_env()` — no fallback → unset `RUST_LOG` yields the bare default, **not** `info` |
| Layers | OTLP + file + `fmt` + `Identity`-padding workaround (`main.rs:835`) | bare `tracing_subscriber::fmt()…init()` — no OTLP, no file |
| Default level | `info` (via flag default) | effectively undefined when `RUST_LOG` unset |

**Reconciled design (standardize the precedence rule; reuse a tested helper, not a new crate):**
- Extract a small, tested helper in `telemetry` (the crate both bins can depend on; `bin/rvc-signer`
  gains the `→ telemetry` edge anyway for the extractor), e.g. `telemetry::env_filter_or(level:
  &str) -> EnvFilter`, encoding the **documented precedence**: *if `RUST_LOG` is set, use it; else use
  the configured default level (`info`)* — exactly `bin/rvc`'s current
  `try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))` logic, promoted to a named, tested
  function.
- Both binaries call the helper with `info` as the default. `bin/rvc-signer` thereby *gains* a config
  default (unset `RUST_LOG` → `info`, identically to `bin/rvc`); `bin/rvc`'s behavior is preserved,
  including its `Identity`-padding correctness for the empty-`Vec<Layer>` short-circuit.
- The reconciliation deliberately does **not** add OTLP/file layers to `bin/rvc-signer` (that would be
  a telemetry change, not an init-consistency change, and is out of scope). It unifies *default level
  + precedence + format selection* only. Each binary keeps its own thin `init_logging(...)` wrapper
  (binary-local); we do **not** introduce a shared init crate for two call sites — the documented
  contract + the helper is cheaper (ADR-009).

**Key design decisions:**
- **One `EnvFilter` precedence everywhere** (ADR-004), default `info`. Covered by init parity tests in
  **both** bins.
- **File can be more verbose than console** (file `debug`, console `info`) is supported **today** in
  `bin/rvc`: it already threads `logfile_level` into `telemetry::FileAppenderConfig`
  (`main.rs:937`, with tests at `tier3_operations.rs:545`, verified). `bin/rvc-signer` gains the same
  option; `STANDARD.md`/`OPERATOR_GUIDE.md` document it as the sanctioned recipe (ADR-005). No appender
  redesign. If a future appender path cannot filter independently, fall back to file == console
  (documented, not assumed).
- **`TracingGuard`/shutdown unchanged** — both binaries hold the guard for process lifetime exactly as
  today.

**Failure modes:** the named P0-5 risk is an init regression that silently changes default
verbosity/format — covered by init tests in both bins asserting (a) unset `RUST_LOG` → effective level
`info`, (b) `RUST_LOG=debug` overrides, (c) a per-module directive
(`rvc_signer_bin::http_api=trace`) raises only that target, (d) the empty-layer `Identity` padding
still emits events (the existing `init_logging regression marker` test at `bin/rvc/src/main.rs:2229`
is the model to mirror in rvc-signer). If `RUST_LOG` is malformed, the helper falls back to the
configured default (never panics, never goes silent). If OTLP init fails, both binaries fall back to
fmt-only with a warning (already `bin/rvc`'s behavior).

---

### Module: Level taxonomy + span-instrumentation strategy (applied across crates)

**Responsibility:** Make the 5-level taxonomy and spans-first correlation a concrete, machine-checkable
house style on the hot paths, honoring research **R1** (instrument `fields(...)` evaluate **eagerly**).

**The taxonomy (rs-vc house standard; primary anchor = `tracing::Level` docs, per R8):**

| Level | Audience | Contains | In release |
|---|---|---|---|
| `error` | operator | an intended action did not complete | present |
| `warn` | operator | handled / degraded-but-progressing | present |
| `info` | operator | **milestones only** — the heartbeat (low, bounded volume) | present, runtime-on |
| `debug` | developer | decision points / internal state | present, runtime-gated by `RUST_LOG` |
| `trace` | developer | wire-level / per-item, highest volume | **compiled out** (`release_max_level_debug`) |

**Span conventions (the R1-correct version):**

1. **`level=` on every hot-path `#[instrument]`.** The attribute defaults to **INFO**; on
   per-slot/per-validator fns that floods the heartbeat. Hot-path spans are `level = "debug"` (or
   `"trace"`). *This is the single most common mis-use to audit for* (research rule 3).
2. **`skip_all` is the default on any secret- or large-arg fn**, then re-add only chosen fields via
   `fields(...)`. `skip_all` is both a redaction control (no auto-`Debug` of
   `&SecretKey`/`&BeaconBlock`/payloads) and a perf control. **Bare `#[instrument]` on a sign/decrypt
   fn is forbidden** (Gate 1 catches the laundering sinks; reviewer checklist backstops).
3. **`fields(...)` carries only `Copy` scalars / cheap values (R1).** Because `#[instrument]`
   evaluates `fields(...)` **eagerly on every call regardless of whether the span level is enabled**,
   expensive Display/Debug (a `hex::encode`, a `serde_json`, hashing a root) must **not** go in a
   `fields(...)` expression — put such work on an `event!`-family macro field (gated by the level
   check) or behind `tracing::enabled!`. A `%TruncatedPubkey`/`%TruncatedRoot` placed in
   `#[instrument(fields(...))]` runs its `Display` on every call (fine for the cheap pubkey scalar
   case, but the house rule is: **scalars in instrument `fields`; redaction wrappers on event macros /
   `record()`**).
4. **Spans-first.** Stamp `slot`/`epoch`/`validator_index`/`pubkey`/`duty`/`request_id`/`committee_index`
   on the span once; child events inherit them. `network` stays a resource attribute.
5. **Late-bound fields via `field::Empty` + `record()`** (through `record_display`/`record_debug`).
   `record()` on an undeclared field is silently dropped — declare every late-bound field `Empty` at
   span creation (mirror `beacon::client`'s `http.status_code = Empty`).
6. **Async correctness.** Never hold `Span::enter()` across `.await`; prefer `#[instrument]`,
   `.instrument(span)`, `.in_current_span()`/`Span::or_current()` for `tokio::spawn`, and
   `Span::in_scope()` for sync closures. **For the instrumented `sign_*` methods' `spawn_blocking`
   closures, capture `Span::current()` and `let _e = span.enter()` *inside* the closure** (safe — no
   `.await` there) so `crypto`/`slashing` events emitted in the blocking section stay correlated. See
   ADR-008 for the exact, verified site list.
7. **Coarse spans on the hottest async fns** (one span per phase, not per inner await): an *enabled*
   `#[instrument]` async fn enters/exits its span on **every poll**, so coarse granularity bounds the
   per-poll cost when `debug`/`trace` is on under large validator counts.
8. **Namespace normalization.** Reconcile the orchestrator's and signer's `rvc.`-prefixed
   fields/spans to the unprefixed canonical registry. Verified live divergence in
   `crates/signer/src/lib.rs`: spans named `rvc.sign.*` (`:126`, `:330`, …) with `fields(rvc.operation
   = …)`, plus `rvc.slashing.result` (`:306`, `:311`, `:450`, `:455`) and span `rvc.slashing.check`
   (`:189`). In OTLP, `rvc.slot` and `slot` are *different* attribute keys, so dashboards grouping by
   `slot` miss the prefixed spans. **The R3 blocking-section fix (item 6) and this namespace
   normalization touch the same sites** — do them together so re-instrumentation does not re-introduce
   the prefixed keys (a connection both top candidates left implicit).

**`info` heartbeat shape (operator familiarity, Lighthouse-like):** one milestone per completed duty
carrying `slot`; build/sign at `debug`, publish at `info` (the Lodestar `Signed`=debug /
`Published`=info split); a once-per-slot liveness tick; a `time_into_slot`/`delay` field. Milestone
set at `info`: validators loaded, BN connected, epoch boundary, attestation/aggregate published, block
proposed, sync-committee message/contribution, validator registration. Use `head` for the attested
head, `block_root` for a proposed block, `committee_index`/`subcommittee_index` (Lighthouse-compatible).

**Enforcement:** Gate 3 captured-subscriber tests assert representative hot-path events fire at the
**intended level** with the **intended fields**; Gate 1 enforces `skip_all` on secret-taking fns via
the disallowed-sink lint; Gate 5 (advisory→blocking) flags non-canonical field names against
`crypto::logging::fields`.

---

### Module: Zero-overhead-when-disabled harness (P0-6)

**Responsibility:** Turn "disabled `debug!`/`trace!` perform no allocation/formatting/hashing" from a
claim into a **tested invariant**, and physically remove `trace!` from release binaries (no bench
infra exists today — research §H).

**Two mechanisms + a verification harness:**

1. **Compile-time static cap (`release_max_level_debug`) on both binaries (ADR-001).** Add
   `tracing = { workspace = true, features = ["release_max_level_debug"] }` to `bin/rvc/Cargo.toml` and
   `bin/rvc-signer/Cargo.toml`. In `--release`, `trace!` (and below-cap spans) compile to **nothing**,
   while `debug!` stays runtime-switchable via `RUST_LOG` (PRD: operators escalate to `debug` in prod
   without a separate build). Strongest P0-6 form; also neutralizes residual `EnvFilter`
   dynamic-directive cost. **Do not** enable tracing's `log` bridge feature (re-introduces cost under a
   static cap).
2. **Runtime interest cache + `enabled!` guards + zero-alloc `Display` wrappers.** Disabled
   events/spans are a cached-integer load + branch; field expressions are not evaluated *provided the
   work is inside the macro field expression*, not precomputed into a local. Any field doing real work
   (`hex::encode`, `serde_json`, hashing) is gated behind `tracing::enabled!(Level::TRACE)` (the
   existing `crates/beacon/src/client.rs:149` pattern) or expressed as a zero-alloc `Display` wrapper
   (`TruncatedPubkey`/`TruncatedRoot`).

**Verification harness (net-new):**
- **Counting-`#[global_allocator]` zero-alloc test — the *precise* gate (Gate 4).** A dependency-free
  allocator wrapping `std::alloc::System` bumps an `AtomicUsize`; a `#[test]` under an `info`-level
  subscriber (trace/debug OFF) asserts `assert_eq!(allocs_after, allocs_before)` across a
  `sign_attestation` / `sign_block` call and around one coordinator/per-slot phase. This is the precise
  gate because a ~1 ns span is below `criterion`'s measurement floor next to a BLS sign. Crucially, the
  harness is tied to the primitives' shape: it **fails** if someone reintroduces an eager
  `hex::encode` on the sign path (the R1 trap at `lib.rs:170/359`) or a `fields(... = %heavy)` on a hot
  `#[instrument]`. Runs under `cargo nextest run --workspace`.
- **`criterion` sign-path bench (latency sanity).** Compare `no_subscriber` / `subscriber_info` (debug
  spans disabled) / `subscriber_trace`; pass if `info ≈ no_subscriber` within noise. Lives in
  `crates/signer/benches/sign_path.rs` (+ a per-slot-loop bench around one coordinator phase); run via
  `cargo bench` — a regression guard, not a blocking PR gate.

**Failure modes:** the harness *is* the failure detector — if `allocs_when_disabled != baseline` the
build fails before merge; the `criterion` bench catches a gross latency regression.

---

### Module: the 23 crates as self-applying consumers

**Responsibility:** Each crate raises its own logging to `STANDARD.md` using the `tracing` macros and
`#[instrument]` idioms it already uses — calling the shared kit for redaction/fields/correlation, with
no facade to learn (ADR-009).

**How "self-apply" works per crate:** add `info` milestones, `debug` decision points, `trace`
step/wire detail per the taxonomy; put canonical correlation fields on the crate's existing
`#[instrument]` spans; `level="debug"` on hot fns; `skip_all` on anything secret/large; redact via the
`crypto::logging` wrappers; mint/record `request_id`; normalize `rvc.`-prefixed sites and apply the
R3 blocking-section fix together (strategy items 6 & 8).

**Data ownership:** each crate owns its own log statements; there is no shared logging *state* (only
shared *primitives*). This is the property that keeps the approach viable — there is nothing to
centralize beyond the kit.

**Failure modes:** the risk here is *adoption drift*, not runtime failure — addressed by the gates and
the rollout phasing.

---

## Cross-Cutting Concerns

### Authentication & Authorization
Unchanged. The :9000 path's existing TLS/CN audit logging (`bin/rvc-signer/src/http_api`) emits exactly
one structured entry per request (success=`info`, rejection=`warn`) carrying **metadata only** (pubkey
identifier, Web3Signer `type`, outcome, peer CN, backend, latency) and **never** the body/root/
signature. The redaction policy formalizes that this audit line, and any new log on the path, stays
metadata-only and carries `request_id`. The CN is never an authorization gate. This initiative does
**not** fold the audit log into the trace; it only conforms its fields to the registry.

### Logging & Observability (the subject of this document)
Standardized by `STANDARD.md` (the human-readable contract) and by the kit + gates (the machine-checked
one): canonical fields from `crypto::logging::fields`, correlation via `new_request_id` + spans-first,
redaction via the Redaction Kit, init via the reconciled helper, OTLP/sampler/exporters unchanged.
`request_id` plus W3C `traceparent` follow a signing/API request end to end including across :9000 once
`set_parent_from_headers` is wired; an additive `x-request-id` header echoes the human-readable id so
both sides log the same value even when a request arrives without a `traceparent`. OTLP mapping is
unchanged: span fields → span attributes, events → span events; `otel.kind = "server"` on the inbound
:9000 span, `"client"` on outbound beacon/signer calls.

### Error Handling
Per CLAUDE.md "log once": `error` only at the terminal-decision layer (`#[instrument(err)]` only
there); lower layers return the `Result`. `error` only when an intended action did not complete;
recover/degrade → `warn`. The P1-3 normalize pass removes duplicate log-and-return lines and fixes
`error`-vs-`warn` miscategorization **without** touching `Result`/`thiserror`/`?` control flow (PRD
Non-Goal); re-categorization breadth is conservative — `error` iff an intended action did not complete
(PRD Open Q6).

### Configuration
`RUST_LOG`/`EnvFilter` is the runtime knob (env overrides config default `info`), reconciled across
both binaries. `release_max_level_debug` is the compile-time cap (a Cargo feature baked into the
binaries). The file layer may be more verbose than the console via the existing `logfile_level`
plumbing. No feature flags added beyond the existing `gcp-trace` and the static-cap feature; no runtime
config change to the OTLP/file/sampler stack.

---

## Data Flow Diagrams

### A. Signing request across the :9000 Web3Signer boundary (the correlation showcase, P0-2/P0-4)

```text
bin/rvc (client side)
  orchestrator duty span  ── slot/epoch on span (ParentBased root sampler decides keep/drop)
  mint request_id         ── crypto::logging::new_request_id()  → Uuid
  open client span        ── otel.kind="client", request_id=%id, slot, duty=%Duty::…, pubkey=%TruncatedPubkey
  inject_trace_context()  ── writes W3C traceparent (trace id + sampled flag) into headers   [existing]
  + x-request-id header   ── echoes the human-readable id
       │  POST :9000 /api/v1/eth2/sign/{id}
       ▼
bin/rvc-signer (server side, :9000)
  sign handler span       ── #[instrument(skip_all)] (routes.rs:51), headers: http::HeaderMap (routes.rs:56)
                              fields(otel.kind="server", request_id=Empty, slot=Empty, duty=Empty, pubkey=Empty)
  set_parent_from_headers ── <<< THE BRIDGE: span becomes child of caller's trace;
                              ParentBased sampler honors the upstream keep/drop                [NEW]
  read x-request-id       ── record_display(span, request_id, …)   (or mint if absent)
  parse body → resolve    ── record_display(span, slot/duty/pubkey=%TruncatedPubkey)   [no secrets]
  SigningGate.sign_*       ── (crates/signer/src/lib.rs) already #[instrument(name="rvc.sign.*", skip_all, …)]
    spawn_blocking {       ── capture Span::current(); let _e = span.enter();   <<< R3 fix (lib.rs:209/372)
      slashing check (debug: inputs/decision) → BLS sign (trace: payload steps via TruncatedRoot, no secrets) → commit
    }
  audit log (info/warn)   ── metadata only: pubkey id, type, outcome, CN, backend, latency + x-request-id echo
  every event in handler+gate inherits {request_id, slot, duty, pubkey} from the span (no repeat)
  OTLP layer              ── span fields → span attributes; events → span events ──▶ collector (one whole trace)
```

### B. Per-slot duty / `info` heartbeat (operator liveness, low volume — research §G)

```text
startup        → info  "rvc starting" {version, network, commit}
validators load→ info  "Loaded validator keys" {count}
BN connect     → info  "connected to beacon node" {bn_version}
epoch boundary → info  "epoch processed" {epoch}
attestation    → debug "Signed attestation" {slot, %pubkey} ; info "published attestation" {slot, head=%TruncatedRoot, committee_index}
block proposed → info  "block proposed" {slot, block_root=%TruncatedRoot}
slot tick      → info  (optional once-per-slot) {slot, time_into_slot}
bn-manager     → warn  "failover" {bn_url=%RedactedUrl}
               (duty cache hit/miss, BN selection, slashing inputs → debug ; wire framing + per-item loops → trace)
```

### C. Secret-redaction enforcement at PR time (the safety net)

```text
PR ──▶ cargo clippy -D warnings  ──▶ disallowed-methods (expose_secret/raw_bytes/to_bytes)  ─┐
PR ──▶ cargo nextest --workspace ──▶ captured-subscriber tests (raw secret ABSENT)          ─┤─ all must pass,
PR ──▶ gitleaks (source + emitted trace-level sample)                                       ─┤   fail-closed
PR ──▶ reviewer checklist on {crypto, secret-provider, signer, :9000, rvc-keygen}           ─┘   (0 findings)
```

---

## Infrastructure & Deployment

### Deployment Model
Unchanged: a Cargo workspace producing `bin/rvc`, `bin/rvc-keygen`, `bin/rvc-signer`. Both long-running
binaries gain `release_max_level_debug` in their `Cargo.toml` and the reconciled init helper. The only
build-graph change is `bin/rvc-signer` gaining a `telemetry` dependency (the one new edge — same shape
`bin/rvc` already has). No container/PaaS/serverless change; no new runtime services; no new ports
beyond the unchanged :9000 / :9101.

### Scaling Strategy
Not applicable to the logging primitives (they are libraries). The relevant axis is **log volume under
large validator counts**: `info` stays ≈ one line per assigned duty (Assumption 3); per-validator
inner loops are `debug`/`trace`; P2-1 sampling is the backstop; coarse spans (one per phase) bound
per-poll enter/exit cost when verbose is enabled under load.

### Adoption / Rollout Path (replaces "service extraction"; phased across the 23 crates)

Enforcement-first and primitive-first: each phase ships its **gate** and **primitive** alongside its
code, so every later crate change is measured against a landed rubric and merely *calls* shared code.
Each phase is independently shippable and leaves the workspace green (`cargo fmt`, `cargo clippy -D
warnings`, `cargo nextest run --workspace`).

| Phase | Scope (PRD) | Crates / surfaces touched | Net-new code / gate landed | Exit criterion |
|---|---|---|---|---|
| **0 — Standard + primitives + gate skeleton** | P0-1 | `plan/logging/STANDARD.md`; `crypto::logging` (`TruncatedRoot`, `fields`, `new_request_id`, `record_*`); `telemetry::propagation` (extractor); standard ref'd from `telemetry` `//!` | docs + the kit; `clippy.toml` `disallowed-methods` seeded + allow-list; gitleaks PR job added; arch-tests policy tables extended | doc reviewed + merged (the rubric); kit tested; clippy gate green; cycle gate green |
| **1 — Hot paths + safety** | P0-2/3/4/6 | `crypto`, `signer` (rename `rvc.*`→registry + `spawn_blocking` re-enter, lib.rs), `bin/rvc-signer` :9000 (wire extractor + `request_id` + `x-request-id`), `beacon`, `bn-manager`, `slashing`, `duty-tracker`, `builder`, orchestrator (`rvc`) | hot-path `#[instrument(level, skip_all, fields)]` + the kit; captured-subscriber redaction + level/field tests (4 high-risk crates + `rvc-keygen`); **counting-allocator zero-alloc test**; `release_max_level_debug` on both bins | hot-path steps have `trace`; spans carry registry fields; trace continuous across :9000 (non-zero-parent test); 0 secret findings; allocation assertion passes |
| **2 — Init consistency** | P0-5 | `telemetry` (helper), `bin/rvc`, `bin/rvc-signer` | shared `env_filter_or` helper; init parity tests in both bins | both bins: same default `info`, same precedence, same format selection |
| **3 — Breadth** | P1-1/2/3 | gap crates (`rvc-keygen` [mnemonic — high-risk], `signer-registry`, `eth-types`, `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`); remaining hot `#[instrument]` sites; normalize already-covered crates (`crates/rvc`, both bins, `signer`, `bn-manager`, `slashing`, `crypto`) | per-crate edits; Gate 5 (field-name conformance) wired as **advisory** | each gap crate has `info`/`debug` (+`trace` where a hot path exists); namespace normalized |
| **4 — Docs & polish** | P1-4; then P2 | `OPERATOR_GUIDE.md`; then P2 (sampling, dynamic reload, JSON profile); escalate Gate 5 to blocking once the field set is stable | docs + targeted fixes | operator guide merged; P2 as capacity allows |

**Per-crate "readiness to adopt" (analogue of extraction readiness):**
- **Ready now (just call the kit + normalize):** `crates/rvc`, `bin/rvc`, `bin/rvc-signer`, `signer`,
  `bn-manager`, `slashing`, `crypto` — already depend on `crypto`/`telemetry`; no new edge to adopt.
- **Bridge-blocked:** the :9000 correlation cannot be end-to-end until `set_parent_from_headers` lands
  (Phase 0) and is wired (Phase 1); `signer` gate correlation depends on the same.
- **Greenfield (near-silent, add to standard):** `rvc-keygen`, `signer-registry`, `eth-types`,
  `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics` — mechanical, low-risk,
  kit-backed.

---

## Enforcement Architecture (the differentiator — how each gate rides the existing CI)

Six gates, each attached to a step that **already exists** (except one tiny new `gitleaks` job),
fail-closed at **0 findings**, with **no new mandatory toolchain for P0**.

### Gate 1 — `clippy.toml` `disallowed-methods` (secret sinks) — rides `cargo clippy … -D warnings`

`clippy.toml` today contains only `msrv = "1.92"` (verified). Extend it (the existing `check` job runs
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
  implicit path impossible and **Gates 3/2** test the runtime result. P2 `dylint` is the dataflow
  upgrade if ever needed.
- **No new toolchain.** Pure config on the existing clippy step.

### Gate 2 — `gitleaks` PR job (source + emitted log sample) — one small new CI job

Add a job to `.github/workflows/ci.yml` (the only net-new CI infra). It (a) runs `gitleaks` (rule +
entropy, fast, SARIF, blocking) over the **source tree**, and (b) **emits a representative log
sample** — runs the captured-subscriber conformance tests (or a tiny harness) at `trace` level,
captures output to a file, and runs `gitleaks` over **that emitted output**. Scanning the *emitted*
log, not just source, is what actually verifies "no secret reached a sink" — the part most designs
miss and the one that proves a BLS key never reached a logging macro. `trufflehog`
verification-first mode is reserved as a **scheduled** full sweep, not the blocking gate. Tune the
`gitleaks` config to allow-list test fixtures (false-positive control).

### Gate 3 — Captured-subscriber / `tracing_test` conformance tests — ride `nextest`

`#[tracing_test::traced_test]` tests in `crypto`, `signer`, `bin/rvc-signer`, and `rvc-keygen` that
fire each high-risk log line and assert, via `logs_contain(...)`, that the output **contains** the
truncated/redacted form and **does NOT** contain the raw secret (the existing
`test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` at `crypto/src/logging.rs:119` is the
proven, in-tree model). The same harness asserts **intended level** and **intended fields** for
representative hot-path events, and that late-bound `record()` fields land on the span. `tracing-test`
is already a workspace dev-dependency; these run under the existing `nextest` coverage job.

### Gate 4 — Counting-`#[global_allocator]` zero-alloc test (P0-6) — rides `nextest`

The dependency-free counting allocator + `assert_eq!(allocs_when_disabled, baseline)` on the sign and
per-slot paths (detailed in the *Zero-overhead* module). The **precise** P0-6 gate (a ~1 ns span is
below `criterion`'s floor next to a BLS sign). Runs under `nextest`; the `criterion` bench is the
non-blocking latency companion.

### Gate 5 — Canonical-field-name conformance — advisory first, then blocking

A conformance check that flags emitted field keys not present in `crypto::logging::fields`. Preferred
P0/P1 form (no new toolchain): a captured-subscriber test asserting a curated set of hot-path events
use only canonical keys, rides `nextest`. A `dylint` dataflow lint (nightly) is **P2 only**. Land the
test form as **advisory** in Phase 3, escalate to blocking once Phase 3 normalizes the `rvc.`-prefixed
sites and the field set stabilizes. **This is the one normative rule that is genuinely under-enforced
for the full 23-crate breadth in P0** (the captured set is curated, not exhaustive) — flagged honestly
rather than presented as a guarantee, and backstopped by `STANDARD.md` as the review rubric.

### Gate 6 — `architecture-tests` DAG gate (no cycles) — already in CI

The existing `crates/architecture-tests/tests/architecture_no_cycles.rs` already asserts the production
graph is acyclic (3-colour DFS over `cargo metadata --no-deps`), enforces `FORBIDDEN` edges, and pins
`ZERO_OUT_EDGE_IF_PRESENT` (incl. `rvc-eth-types`, `rvc-signer-registry`). This architecture **rides it
unchanged** for the no-cycle guarantee (the new `rvc-signer-bin → rvc-telemetry` edge keeps it green —
verified) and **recommends extending its policy tables** to lock the new boundary: add
`rvc-signer-bin → rvc-telemetry` as an expected/allowed edge and keep `rvc-eth-types` at zero
out-edges, so a future contributor cannot "fix" a field-constant import by adding a `uuid`/`telemetry`
edge to `eth-types`.

**Gate-to-rule traceability (every normative rule has an automated owner or is flagged advisory):**

| Normative rule | Primary gate | Backstop |
|---|---|---|
| No raw secret at any level | Gate 1 (clippy sinks) | Gate 3 (runtime absent) + Gate 2 (emitted scan) |
| Pubkeys/URLs/roots only via wrappers | Gate 3 (captured-subscriber) | reviewer checklist (4+1 crates) |
| `skip_all` on secret-taking fns | Gate 1 (laundering sinks) | reviewer checklist |
| Canonical `snake_case` field names | Gate 5 (advisory→blocking) | `STANDARD.md` (review rubric) |
| Intended level per event | Gate 3 (level assertions) | — |
| Zero alloc when disabled | Gate 4 (counting allocator) | `criterion` bench |
| `trace` absent in release | `release_max_level_debug` (compile) | Gate 4 |
| No circular dependency | Gate 6 (DAG) | — |

---

## Technology Choices

| Concern | Choice | Rationale |
|---|---|---|
| Tracing framework | `tracing` 0.1 / `tracing-subscriber` 0.3 (existing) | PRD Non-Goal to swap; compose in |
| Trace export | `tracing-opentelemetry` 0.32 / `opentelemetry*` 0.31, OTLP/HTTP (existing) | already wired; span fields → attributes; untouched |
| Sampler | `ParentBased(TraceIdRatioBased(rate))` (existing) | preserves whole-trace correlation once boundary bridged |
| Redaction sinks | `crypto::logging::{TruncatedPubkey, RedactedUrl}` (exist) + `TruncatedRoot` (new), zero-alloc `Display` | settled `0x{first10}...{last8}` format; one new wrapper; glyph-consistent (R9) |
| Field convention | `snake_case`, spans-first, canonical registry (house standard) | OTel `snake_case` is SHOULD (R2); registry kills synonym drift |
| `request_id` | `uuid::Uuid::new_v4()` via `crypto::logging::new_request_id` + `x-request-id` header | matches `keymanager-api` precedent; `uuid` already a `crypto` dep |
| Inbound extractor | in-repo `telemetry::propagation` fn (not a 3rd-party crate) | compose into existing module; reject pre-1.0 `axum-tracing-opentelemetry` |
| Secret sink lint | `clippy.toml` `disallowed-methods` | rides existing `-D warnings`; no new toolchain |
| Secret scan | `gitleaks` (blocking PR, source + emitted), `trufflehog` (scheduled) | emitted-log scan proves runtime absence |
| Conformance tests | `tracing-test` captured subscriber (existing dev-dep) | proven in-tree model; runs under `nextest` |
| Zero-alloc proof | dependency-free counting `#[global_allocator]` | precise gate below `criterion`'s floor; no heavy dep (vs `dhat`) |
| Static cap | `release_max_level_debug` (both bins) | `trace` compiled out; `debug` stays `RUST_LOG`-switchable in prod |
| DAG enforcement | existing `architecture-tests` (`cargo metadata` parse via `serde_json`) | already in CI; no new external dep |
| Test runner | `cargo nextest run --workspace` | `cargo test --workspace` can deadlock (project history) |
| New crate? | **No** | extend `crypto`/`telemetry`; a new crate re-creates the coupling we avoid |

---

## ADRs (Architecture Decision Records)

### ADR-001: Static level cap = `release_max_level_debug` (not `_info`)
- **Status:** Accepted (forwarded to gate to confirm vs `release_max_level_info`).
- **Context:** P0-6 requires disabled verbose logging to be free; the PRD also requires operators to
  escalate to `debug` in prod via `RUST_LOG` without a separate build.
- **Decision:** Compile `tracing` with `release_max_level_debug` on **both** binaries. `trace!` (and
  below-cap spans) are physically removed from `--release`; `debug!` stays runtime-gated.
- **Alternatives:** `release_max_level_info` (removes `debug` too — then `RUST_LOG=debug` does nothing
  in prod, contradicting the escalation requirement); no static cap (keeps all levels, loses the
  strongest P0-6 form and leaves residual `EnvFilter` cost).
- **Consequences:** Strongest zero-cost form; neutralizes dynamic-`EnvFilter` cost; `trace` in prod
  requires a debug/test build (acceptable — `trace` is "never on in prod"). Must **not** enable
  tracing's `log` bridge. Verified by Gate 4.

### ADR-002: `request_id` source = fresh `uuid::Uuid::new_v4()` + `x-request-id` header
- **Status:** Accepted.
- **Context:** A single human-followable correlator must survive the :9000 hop, including when a caller
  sends no `traceparent`.
- **Decision:** Mint `request_id` with `uuid::Uuid::new_v4()` (via `crypto::logging::new_request_id`),
  carry it on the span, echo it across :9000 via an additive `x-request-id` header; the signer reads it
  (or mints one if absent). W3C `traceparent` still carries the trace itself.
- **Alternatives:** Derive `request_id` from the OTel trace/span id (one fewer header, but not
  human-friendly and absent when no trace context flows); no explicit id (relies solely on
  `traceparent`, which breaks for clients that don't send one).
- **Consequences:** Matches the in-tree `keymanager-api` precedent (`handlers.rs:348`); `uuid` already
  a `crypto` dep; one extra header, ignored by clients that don't send it; both sides log the same value.

### ADR-003: One subscriber-init precedence — env overrides config default `info`
- **Status:** Accepted (P0-5).
- **Context:** `bin/rvc` uses `try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))` (config
  default + `RUST_LOG` override) + `Identity` padding; `bin/rvc-signer` uses bare `from_default_env()`
  (no fallback → unset `RUST_LOG` is not `info`). Operators must learn each (verified divergence).
- **Decision:** Promote `bin/rvc`'s logic to a shared, tested helper in `telemetry`
  (`env_filter_or(level)`): if `RUST_LOG` is set use it, else default to `info`. Both binaries use it.
- **Alternatives:** Standardize on bare `from_default_env()` (surprises operators with an odd default
  when `RUST_LOG` is unset); duplicate the logic per-binary (drifts again).
- **Consequences:** `bin/rvc-signer` gains a config default + the `Identity`-padding correctness it
  lacks; `bin/rvc` behavior preserved; init parity tests assert it. Does **not** add OTLP/file layers to
  `bin/rvc-signer` (out of scope). OTLP/file/guard/sampler contracts unchanged.

### ADR-004: File can be more verbose than console (file `debug`, console `info`) — already supported
- **Status:** Accepted (contingent on the appender supporting an independent level — confirmed for
  `bin/rvc`).
- **Context:** Lighthouse/Lodestar default the file to `debug` and the console to `info`; operators
  expect a richer on-disk record. `bin/rvc` already plumbs a separate `logfile_level` into
  `telemetry::FileAppenderConfig` (`main.rs:937`, tests at `tier3_operations.rs:545` — verified).
- **Decision:** Adopt file-more-verbose-than-console as the documented default *where the existing
  `logroller`/non-blocking file layer supports an independent level filter* — which `bin/rvc` already
  exposes. Default `logfile_level` to `debug` when a logfile is configured; console stays `info`.
  `bin/rvc-signer` gains the same option in Phase 2.
- **Alternatives:** Force file == console (simpler, loses the familiar richer file); redesign the
  appender for independent levels (a telemetry redesign — out of scope).
- **Consequences:** Familiar to migrating operators; **no appender redesign** (uses the existing `level`
  field). If a future appender path cannot filter independently, fall back to file == console
  (documented, not assumed). Documented in `OPERATOR_GUIDE.md` (P1-4).

### ADR-005: `TruncatedRoot` takes `&[u8]` and renders inside `Display` (no eager `hex::encode`)
- **Status:** Accepted.
- **Context:** Roots are `[u8; 32]` on the hot path; the sign path today does eager `let
  signing_root_hex = hex::encode(signing_root)` into a local (`signer/src/lib.rs:170`, `:359`) and
  `%format!("0x{}", hex::encode(...))` fields (`:161-174`), which allocate even when the level is
  disabled (the R1 trap — all verified in-tree).
- **Decision:** `TruncatedRoot(&[u8])` hex-renders the first/last bytes *inside* `Display::fmt`, so
  under `%` on an event-family macro it is zero-alloc and only runs when the level is enabled. Roots /
  signatures are **truncated** at `trace`; the full value appears only on return values, never in a
  macro (resolves PRD Open Q1 "truncate, don't omit" with a primitive).
- **Alternatives:** `TruncatedRoot(&str)` (forces a caller `hex::encode` that allocates eagerly); a
  `format!`-based helper (allocates unconditionally); omit roots entirely (loses debugging signal).
- **Consequences:** Zero-alloc-when-disabled for root logging; pubkeys stay truncated even at `trace`
  (PRD Open Q2); the Zero-Overhead Harness (Gate 4) catches any reintroduced eager encode. Glyph `...`
  (R9). Enforced by Gate 3 (truncated form present, raw root absent).

### ADR-006: Spans-first correlation (canonical IDs on spans, not repeated per event)
- **Status:** Accepted (default), with a flat-backend mitigation.
- **Context:** Correlating one duty across crates, `.await`, `tokio::spawn`, and the :9000 hop requires
  the same `slot`/`pubkey`/`duty`/`request_id` on every related line, and must feed the OTLP pipeline
  (span fields → attributes).
- **Decision:** Stamp canonical identifiers once on `#[instrument]` spans; child events inherit them;
  events carry only event-specific data. Late-bound identifiers use `field::Empty` + `record()`.
- **Alternatives:** Per-event fields on every call (verbose, drift-prone — the exact `val_idx` vs
  `validator_index` failure the PRD kills; justified only for a flat backend that drops span fields);
  flat `log`-style events with no spans (throws away the main reason to be on `tracing`).
- **Consequences:** Lowest friction for the existing OTLP pipeline; degrades gracefully (a flat backend
  still gets `trace_id`/`span_id`). Mitigation for a span-dropping backend: also stamp `request_id` on
  the **terminal** event of the :9000/sign path (PRD Open Q5). **Honors R1:** correlation scalars on
  instrument `fields(...)` are cheap; expensive redaction wrappers go on event macros / `record()`, not
  ungated instrument fields. Confirm the operators' backend at the gate.

### ADR-007: Primitives placed by dependency cost — light in `crypto`, OTel in `telemetry`; no new crate
- **Status:** Accepted (the load-bearing graph decision).
- **Context:** The standard needs shared primitives many crates call; the 23-crate graph must stay
  acyclic. `crypto` is a universal low dependency with no `telemetry`/OTel edge and already carries
  `uuid`/`hex`; `telemetry` is a leaf with zero internal deps and owns the OTel stack (all verified).
- **Decision:** Pure-data primitives (`TruncatedRoot`, `fields`, `new_request_id`, `record_*`) extend
  `crypto::logging`; the OTel-coupled inbound extractor + the init helper extend `telemetry`. **No new
  crate; no new crate-to-crate edge except the single `rvc-signer-bin → telemetry` leaf attachment.**
- **Alternatives:** (a) a new `obs`/`logging` crate — would need to be a `crypto` dependency *and* want
  OTel, re-creating the coupling, adding a DAG node and up to ~23 edges for zero benefit; (b) put
  everything in `telemetry` — forces `crypto → telemetry` (heavy OTel onto every crate below `crypto`)
  or `telemetry → crypto` (widens the leaf, risks a `beacon` cycle); (c) `eth-types` for the consts —
  pinned to zero out-edges by Gate 6 and lacks `uuid`; (d) the extractor in `crypto` — `crypto` does
  not (and should not) depend on `tracing-opentelemetry`.
- **Consequences:** Minimal, acyclic, no dependency widening; every consumer already depends on the
  home crate of the primitive it calls (except the one new leaf edge). Gate 6 makes the invariant
  self-enforcing (extend its tables to lock the boundary).

### ADR-008: Fix the instrumented `sign_*` blocking-section span detachment (not a missing `#[instrument]`)
- **Status:** Accepted.
- **Context:** Research R3 corrected the gap inventory: the `sign_*` methods **are** instrumented; the
  real gap is the `spawn_blocking` closure running on an OS thread that does not re-enter the parent
  `rvc.sign.*` span, detaching `crypto`/`slashing` events. **Verified site list:** the instrumented
  methods and their `spawn_blocking` closures both live in `crates/signer/src/lib.rs` —
  `sign_attestation` `#[instrument(name="rvc.sign.attestation", …)]` at `:126` with `spawn_blocking` at
  `:209`; `sign_block` `#[instrument(name="rvc.sign.block", …)]` at `:330` with `spawn_blocking` at
  `:372`. (NOT `gate.rs`: the `SigningGate` in `crates/signer/src/gate.rs` also has `spawn_blocking` at
  `:270`/`:405`, but its `sign_*` methods are **not** `#[instrument]`-annotated — so the earlier
  "gate.rs:270" pointer would under-fix the problem.)
- **Decision:** Capture `Span::current()` before `spawn_blocking` and `let _e = span.enter()` **inside**
  the closure (safe — no `.await` there) at the `lib.rs` sites. No new `#[instrument]` is added. Apply
  this **together with** the `rvc.`→registry namespace normalization at the same sites (`rvc.operation`,
  `rvc.slashing.result` `:306/:311/:450/:455`, span `rvc.slashing.check` `:189`), so the re-instrumented
  events use canonical keys.
- **Alternatives:** Add `#[instrument]` to the methods (false fix — they already have it); `.instrument()`
  the closure (does not apply to a sync `spawn_blocking` closure); point at `gate.rs:270` (wrong type —
  not instrumented).
- **Consequences:** Blocking-section events rejoin the duty/sign span; correlation is continuous. A
  correctness-of-correlation fix, not a cost fix; no signing-behavior change. Verified by Gate 3.

### ADR-009: Convention + kit, enforced by gates — no logging facade or wrapper-macro layer
- **Status:** Accepted.
- **Context:** A "more shared code" temptation is a logging facade / wrapper macros (`log_duty!`, a
  `LogContext` builder, a custom `#[instrument]` proc-macro that bakes in `level`/`skip_all`/canonical
  fields) so field-name/level correctness is compiler-enforced.
- **Decision:** Ship **no** facade and **no** wrapper macros and **no** bespoke proc-macro. Crates call
  `tracing` directly, call the thin `crypto::logging` kit for redaction/fields/correlation, and follow
  `STANDARD.md`. Deliver the *guarantee* via the documented standard + the gates (1/3/5 + reviewer
  rubric), not a NIH macro. The only shared code is the kit + the extractor — each justified because
  convention there is *unsafe*, not merely inconsistent.
- **Alternatives:** A wrapper-macro / typed-context layer (compile-time field/level enforcement, but
  adds a node, an edge from every crate, a learning surface, ongoing maintenance, and tends to ossify
  call sites — the opposite of low-friction, and it fights the well-tested upstream `#[instrument]`).
- **Consequences:** Lowest friction and least net-new code/maintenance; fastest adoption. The cost is
  that field-name/level correctness rests on the doc + reviewer + the (Phase 3, advisory→blocking)
  Gate 5, not the compiler — accepted because the one mistake class that must never ship (secret leaks)
  is covered by Gates 1/2/3 fail-closed, and style drift is caught in review. This is the deliberate
  proportioning of the shared-code budget to the BLS-key threat model.

---

## Open Questions

The PRD's six Open Questions stand. The research overview's gate questions are folded into the ADRs
above where decided; the remainder are forwarded to the implementation gate:

1. **`telemetry` naming `http::HeaderMap`** for the inbound extractor without a new dep — `reqwest`
   (a `telemetry` dep, verified) re-exports `http` types; confirm `telemetry` can write the `Extractor`
   over `&http::HeaderMap` (used by both `axum` and `reqwest`) without a direct `axum`/`http`
   dependency. If a direct `http` dep is needed, it is a leaf-internal external dep (no internal edge,
   no cycle) — acceptable.
2. **File-independent level (ADR-004)** — confirmed supported in `bin/rvc` via `logfile_level`; confirm
   the same `logroller`/non-blocking path honors an independent file level for `bin/rvc-signer` in all
   configurations before defaulting `logfile_level` to `debug`. If not, fall back to file == console.
3. **Static-cap confirmation (ADR-001)** — confirm `release_max_level_debug` vs `_info` against the
   operator "escalate to `debug` in prod" requirement (recommended: `_debug`).
4. **Gate 5 escalation timing** — when does field-name conformance move from advisory to blocking?
   Proposed: after Phase 3 normalizes the `rvc.`-prefixed sites and the field set stabilizes. Until
   then, advisory to avoid blocking unrelated PRs.
5. **`gitleaks` emitted-sample harness shape (Gate 2)** — reuse the captured-subscriber tests or a
   dedicated tiny `trace`-level dump harness? Proposed: reuse first, add a harness only if coverage
   gaps appear.
6. **`request_id` carrier confirmation (ADR-002)** — `x-request-id` header (recommended) vs deriving
   from the OTel trace/span id; confirm the operators' tooling reads the header.
7. **Coarse-span granularity** on the hottest async fns (one span per phase, not per inner `.await`) —
   confirm phase boundaries with the orchestrator owners to bound the *enabled* per-poll enter/exit cost.
8. **Output default (PRD Open Q4)** — keep pretty as the production default, document JSON as the
   sanctioned aggregation profile (P2-3); confirm.

---

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Secret leakage** via a new log statement (esp. `crypto`/`secret-provider`/`signer`/:9000/`rvc-keygen`). | Security incident. | Defense-in-depth: type layer + Gate 1 (clippy sinks) + Gate 3 (runtime absent) + Gate 2 (emitted scan) + explicit 4-crate-plus-mnemonic sign-off. Fail-closed at 0 findings. |
| **`disallowed-methods` blind spot** (value laundered into a `String`). | A bypass the lint can't see. | The type layer makes the implicit path impossible; Gate 3 tests the runtime result; Gate 2 scans emitted output. Stated as a known limitation in the policy; P2 `dylint` is the dataflow upgrade. |
| **Hot-path latency regression** from new logging. | Missed duties / slashing-deadline pressure. | Gate 4 counting-allocator zero-alloc test (precise); `release_max_level_debug` removes `trace`; `enabled!` guards + `Display` wrappers; `criterion` sanity bench. |
| **`#[instrument(fields(...))]` eager evaluation (R1)** sneaks in expensive work (e.g. a reintroduced `hex::encode` like `lib.rs:170/359`). | Silent per-call cost even when the span is disabled. | House rule: scalars-only in instrument `fields`; redaction wrappers on event macros / `record()`; `TruncatedRoot(&[u8])` replaces the eager encode; Gate 4 catches the sign/slot paths; reviewer rule + Gate 5. |
| **Vanishing late-bound attribute** (`record()` on an undeclared field). | Missing correlation in traces. | `record_display`/`record_debug` helpers + house rule: declare every late-bound field `field::Empty`; mirror `beacon::client`'s `http.status_code = Empty`; Gate 3 asserts recorded fields present. |
| **R3 fix or namespace rename applied at the wrong site** (e.g. `gate.rs` instead of the instrumented `lib.rs` methods). | Blocking-section events stay detached; dashboards still split on `rvc.slot` vs `slot`. | ADR-008 pins the verified `lib.rs` sites (`:126/:209`, `:330/:372`) and binds the R3 fix to the namespace normalization at the same sites; Gate 3 captured-subscriber asserts events carry the span's `request_id`/`slot`. |
| **Field-name conformance is advisory in P0** (the one under-enforced rule). | Style/key drift on crates outside the curated test set. | Honestly flagged (not sold as a guarantee); `STANDARD.md` is the review rubric; Gate 5 escalates to blocking in Phase 3+; the consts make keys greppable/refactor-safe. |
| **A future edit adds a dependency cycle** (e.g. `eth-types → uuid`/`telemetry` to "import field constants"). | Build break / inverted layering. | Gate 6 (`architecture-tests`) pins `rvc-eth-types` to zero out-edges and the graph to acyclic; extend its tables to lock `rvc-signer-bin → telemetry`; primitives live in `crypto::logging`, removing the temptation. |
| **Init reconciliation** silently changes default verbosity/format for `bin/rvc-signer`. | Operator surprise. | ADR-003 documents precedence/default explicitly; init parity tests in both bins assert unset-`RUST_LOG`→`info`, override, per-module directive, and `Identity`-padding emits. |
| **`gitleaks` false positives** block PRs. | CI friction. | Tune `gitleaks` config (allow-list test fixtures); keep `trufflehog` verification-first as the scheduled deep sweep, not the blocking gate. |
| **Breaking the existing OTLP/file/propagation stack.** | Lost telemetry. | Non-Goal to redesign `telemetry`; only additive (`set_parent_from_headers`, `env_filter_or`); `TracingGuard`/shutdown/sampler/exporters untouched; existing `telemetry` tests stay green. |
| **`cargo test --workspace` deadlock** masks results. | False confidence. | `cargo nextest run --workspace` is the runner of record (project history). |

---

## Assumptions

(Carried from the PRD + research §Consolidated Assumptions; recorded here because the task forbids
asking the user. Graph/file facts marked **verified** were checked against the tree at `develop`.)

1. The existing `telemetry` stack (init, config, `file_appender`, `propagation`, `shutdown`, sampler,
   `TracingGuard`) is correct and stays the foundation; this composes into it. Versions: `tracing` 0.1 /
   `tracing-subscriber` 0.3 / `tracing-opentelemetry` 0.32 / `opentelemetry*` 0.31.
2. The PRD's settled decisions are authoritative and not re-opened: `snake_case`, spans-first, the
   5-level taxonomy, `TruncatedPubkey = 0x{first10}...{last8}`, `info` = production default,
   `RUST_LOG`/`EnvFilter` env-overrides-config. This work supplies the standard, the precise homes/idioms,
   and the enforcement.
3. **(verified)** `crypto::logging` is the correct home for redaction wrappers, canonical field
   constants, and `request_id` — `crypto` already hosts `TruncatedPubkey`/`RedactedUrl`
   (`crypto/src/logging.rs:5`,`:40`), already carries `uuid`/`hex`/`url`/`reqwest`/`eth-types`
   (`crypto/Cargo.toml`), has no `telemetry`/OTel edge, and is depended on by every signing-adjacent
   crate.
4. **(verified)** `telemetry::propagation` is the correct home for the inbound extractor — it owns the
   outbound `inject_trace_context` (`propagation.rs:25`) and the OTel deps (`telemetry/Cargo.toml`),
   and depends on no workspace crate. `bin/rvc-signer` gains a single additive `→ telemetry` production
   edge (it does **not** depend on `telemetry` today), which is acyclic.
5. **(verified)** The `architecture-tests` DAG gate exists and rides CI
   (`crates/architecture-tests/tests/architecture_no_cycles.rs`), pins `rvc-eth-types` /
   `rvc-signer-registry` to zero out-edges, and stays green for the new edge without policy edits.
   `clippy.toml` is bare `msrv = "1.92"` (verified), so Gate 1 rides the existing `-D warnings` step.
6. `release_max_level_debug` is the chosen static cap (ADR-001): `trace` compiled out of release,
   `debug` runtime-switchable. Confirm vs `release_max_level_info` at the gate.
7. Pubkeys are truncated even at `trace`; full signing roots/signatures are truncated/omitted by
   default (PRD Open Qs 1 & 2 resolved-to-stricter), with `TruncatedRoot(&[u8])` as the primitive.
   `network` stays a resource attribute, never duplicated per event.
8. `x-request-id` is an acceptable additive carrier for the human-readable `request_id` alongside W3C
   `traceparent`; it does not change signing behavior and is ignored by clients that don't send it.
   **(verified)** the `keymanager-api` precedent mints `Uuid::new_v4()` and logs `request_id = %req_id`
   (`handlers.rs:348`).
9. `cargo nextest run --workspace` is the runner of record. No new mandatory toolchain
   (nightly/`dylint`/`--cfg tracing_unstable`) for P0; `dylint`/`valuable` are P2 escalations in reserve.
10. The four high-risk crates (`crypto`, `secret-provider`, `signer`, the `bin/rvc-signer` :9000 path)
    plus `rvc-keygen` (mnemonic/`bip39`) are the correct redaction review boundary, even though the PRD
    lists `rvc-keygen` under P1 breadth.
11. **(verified)** The instrumented `sign_*` methods and their `spawn_blocking` closures both live in
    `crates/signer/src/lib.rs` (`:126/:209`, `:330/:372`); the `rvc.`-prefixed spans/fields are live
    there (`rvc.sign.*`, `rvc.operation`, `rvc.slashing.result`, span `rvc.slashing.check`); the :9000
    `sign` handler is already `#[instrument(skip_all)]` and already takes `axum::http::HeaderMap`
    (`routes.rs:51`,`:56`); `bin/rvc` already plumbs `logfile_level` into `FileAppenderConfig`
    (`main.rs:937`). These ground ADR-004, ADR-005, ADR-008 and the call-site claims.
12. This effort changes only logging/observability — no runtime behavior, public-API, or
    signing/slashing-logic change. The single new wire behavior is inbound trace-context extraction at
    :9000 plus an additive `x-request-id` header.

---

## Architecture Quality Checklist

- [x] **No circular dependencies** — light primitives in `crypto`, OTel primitive in leaf `telemetry`;
  exactly one new edge (`rvc-signer-bin → telemetry`, into the zero-internal-dep leaf), verified
  acyclic against the in-tree DAG gate, which stays green without policy edits (ADR-007; Gate 6).
- [x] **Each module has a single, clear responsibility** — one sentence each (see Module Overview).
- [x] **No shared databases** — n/a (libraries); each primitive owns its data (vocabulary / wrappers /
  id); each crate owns its own log statements, no shared logging state.
- [x] **All inter-module communication through defined interfaces** — `fields::*` consts, `Display`
  wrappers, free functions (`new_request_id`, `record_*`, `set_parent_from_headers`, `env_filter_or`);
  no backdoor imports.
- [x] **Every module testable in isolation** — captured-subscriber tests per primitive; init parity
  tests per binary; counting-allocator + `criterion` for P0-6; unit test for the extractor.
- [x] **Cross-cutting concerns standardized** — fields/redaction/correlation/init are *the* shared code
  (the kit), not reimplemented per crate; the rest is the documented standard + gates.
- [x] **Failure modes defined** — per-module above; the gates (lint/tests/harness/DAG) are the runtime
  and CI nets, each mapped to a rule in the traceability matrix.
- [x] **Adoption path is clear** — primitive-and-gate-first, then hot paths, then breadth (replaces
  extraction path); per-crate readiness listed (ready-now / bridge-blocked / greenfield).
- [x] **Data flow traceable** — inbound :9000 sign and per-slot heartbeat traced end to end, with the
  R3 fix and namespace normalization pinned to verified sites.
- [x] **Module count justified** — no new crate; primitives grouped by dependency cost into exactly two
  existing homes (`crypto`, `telemetry`); neither over-split (no tiny per-rule crates) nor a monolithic
  blob.
- [x] **Every normative rule has an automated owner or is flagged advisory** — gate-to-rule
  traceability matrix; the single advisory-for-now rule (field-name conformance, Gate 5) is honestly
  labelled and on a path to blocking, not sold as a guarantee.
- [x] **Proportionate to the threat model** — shared-code budget and fail-closed enforcement spent on
  the secret path (leaking a BLS key is a security incident); facade/proc-macro and nightly tooling
  declined as over-engineering (ADR-009; P2 deferrals).
