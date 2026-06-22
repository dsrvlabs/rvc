# PRD: Comprehensive Structured Logging & Observability for rs-vc

## Overview

A cross-cutting initiative to level up logging across the entire `rs-vc` Cargo workspace
(23 crates + 3 binaries) by establishing **one** logging standard and applying `info`/`debug`/`trace`
consistently everywhere — including crates that already log well. The codebase already runs on
`tracing` + `tracing-subscriber` with a dedicated `telemetry` crate and OpenTelemetry/OTLP wired up;
this work **levels up that existing stack**, it does not introduce one. The emphasis is **production
observability and operability**: structured `key=value` fields, spans carrying correlation IDs,
OTLP-ready events, and strict secret redaction.

This is an observability initiative, **not** a feature. No user-facing functionality changes.

## Problem Statement

`rs-vc` is an Ethereum Validator Client — software that signs and broadcasts attestations and blocks
on a strict per-slot deadline, where a missed duty costs rewards and a double-sign can cause a
slashing. When something goes wrong in production (a missed attestation, a beacon-node failover, a
remote-signer timeout, a slashing-protection veto), operators need to reconstruct *what the client
decided and why* from logs. Today they often cannot, because logging is **inconsistent and uneven**:

- **`trace` is effectively absent** and `debug` is thin in many crates. Current workspace macro
  usage: 271 `warn!`, 231 `info!`, 136 `debug!`, 129 `error!`, but only **19 `trace!`**. Step-by-step
  and wire-level detail needed to debug a live incident mostly does not exist.
- **Whole crates are near-silent**, including ones on or adjacent to the runtime hot path:
  `rvc-keygen` (0 log statements), `signer-registry` (0), `eth-types` (~4), and `propagator`,
  `validator-store`, `doppelganger`, `timing`, `metrics`. By contrast `crates/rvc` (201), `bin/rvc`
  (81), `bin/rvc-signer` (75), `signer`, `bn-manager`, `slashing`, and `crypto` are well covered.
  Coverage is a function of which author touched a crate, not of operational importance.
- **No documented standard exists** for what belongs at each level, which structured fields to attach,
  or how to name them. Levels are applied by individual judgment, so the same kind of event is logged
  at different levels (and with different field names, or no fields) across crates. This makes
  `RUST_LOG` filtering and log-based dashboards unreliable.
- **Correlation is ad hoc.** `#[tracing::instrument]` spans already exist at 72 sites across 25 files,
  but coverage is partial and the fields carried on spans are not standardized, so it is not always
  possible to follow a single duty (by `slot` / `validator pubkey` / `duty type` / `request_id`) end
  to end across crate boundaries.
- **Redaction is not enforced as policy.** Good redaction primitives already exist
  (`crypto::logging::{TruncatedPubkey, RedactedUrl}`, `telemetry::config::redact_endpoint`), but their
  use is by convention. In a system that handles BLS private keys, keystore passwords, and mnemonics,
  an accidental secret in a log line is a security incident, and nothing today structurally prevents
  one.
- **Subscriber initialization differs between the two binaries** (`bin/rvc` vs `bin/rvc-signer`),
  creating subtle differences in default level, `RUST_LOG` handling, and output format that operators
  must learn per-binary.

The result: incidents are slow to diagnose, logs are hard to filter and aggregate, and there is a
latent risk of leaking secrets.

## Goals & Success Metrics

### Goals

1. Publish a **single, documented logging standard** — a level taxonomy, a canonical structured-field
   convention, and a secret-redaction policy — that every crate follows.
2. Make the **runtime hot paths fully observable** at `debug`/`trace`, so an operator can reconstruct
   any duty decision from logs without a debugger.
3. Bring the **near-silent and inconsistent crates up to the standard**.
4. Guarantee **zero secret leakage** and **zero hot-path overhead when verbose levels are disabled**.
5. Stay **fully backward compatible** with the existing `telemetry`/OTLP/file-appender stack.

### Success Metrics

| Metric | Target |
|---|---|
| Documented logging standard committed under `plan/logging/` and referenced from code/docs | Exists, reviewed, merged |
| `trace!` call sites in the workspace | From 19 to a level that covers every identified hot-path step (see P0 hot-path list); no hot-path step lacks `trace` |
| Hot-path async entry points (duty tracking, attestation/block production, signing incl. Web3Signer :9000, beacon-node interaction, slashing protection) carrying a standardized `#[instrument]` span with canonical correlation fields | 100% |
| Near-silent crates (`rvc-keygen`, `signer-registry`, `eth-types`, `propagator`, `validator-store`, `doppelganger`, `timing`, `metrics`) raised to the standard | 100% have `info` milestones + `debug` internal-state + `trace` where a hot path exists |
| Secret-leak audit: automated check that no raw private key / keystore password / mnemonic / full signing payload pattern is emitted at any level | Passes in CI; 0 findings |
| Added latency on the signing/attestation path at the default (`info`) level | No measurable regression vs. pre-change baseline |
| Disabled `debug!`/`trace!` perform no allocation/formatting/hashing (verified by inspection + targeted bench/test on the per-slot loop and sign path) | Confirmed |
| `cargo fmt` clean, `cargo clippy` warning-free, `cargo nextest run --workspace` green | Yes |

## Target Users

1. **Node operators / SREs (primary).** Run `bin/rvc` and `bin/rvc-signer` in production. They read
   `info` to confirm the client is healthy and hitting its duties, escalate to `debug`/`trace` (or
   inspect OTLP traces in their collector) to diagnose an incident, and rely on consistent fields to
   build dashboards and alerts. They must never see a secret in a log line.
2. **rs-vc developers (primary).** Read `debug`/`trace` to understand internal state machines while
   building and debugging, and author new log statements. They need the standard to be unambiguous so
   that "where does this go and what fields does it get" is not a judgment call.
3. **On-call incident responders (secondary).** May be operator or developer; need to correlate a
   single duty across crate boundaries by `slot` / `pubkey` / `duty` / `request_id`, in logs and in
   OTLP traces.

## Level Taxonomy (Normative)

This is the load-bearing decision of the initiative. Every log statement added or changed must fit
this taxonomy.

| Level | Audience | Meaning | Examples |
|---|---|---|---|
| `error` | Operator | An operation failed and the client could not complete an intended action; needs attention. | Sign request rejected by slashing protection; all beacon nodes unreachable; keystore decrypt failed. |
| `warn` | Operator | Unexpected but handled; degraded but progressing. | Beacon-node failover triggered; remote signer slow/retried; duty fetched late; malformed input rejected at an API boundary. |
| `info` | Operator | Operator-facing **milestones** — the normal heartbeat of a healthy client. Low volume; safe as a production default. | Startup/config summary; epoch boundary processed; attestation published for slot N; block proposed; validator set loaded; BN connected; signer server listening. |
| `debug` | Developer | Developer-facing **internal state** and decision points. Off in production by default. | Duty cache hit/miss and contents; selected target BN and why; slashing-protection check inputs/outcome; state transitions in the orchestrator. |
| `trace` | Developer | **Fine-grained, step-by-step / wire-level** detail. Highest volume; never on in production. | Each step of building a signing payload; request/response framing on the :9000 Web3Signer path and beacon-node HTTP calls; per-item loop iterations; computed roots/domains (non-secret). |

Cross-cutting rules while we are touching every crate:

- **`error` vs `warn`:** `error` only when an intended action did not complete; if the client recovers
  or degrades-but-progresses, it is `warn`. Do not log-and-return the same error at multiple layers —
  log once at the layer that decides it is terminal; lower layers return the `Result` (per
  CLAUDE.md). This dedup pass is in scope where it is causing duplicate error lines, but **rewriting
  error-handling control flow is a non-goal** (see Non-Goals).
- **One event, one level.** The same logical event is logged at the same level everywhere.
- **No secrets at any level** (see Redaction Policy) — `trace` is *not* an exception.

## Canonical Structured-Field Convention (Normative)

**Decision (recommended default; see Open Questions for the one item left open):**
`snake_case` keys, **spans-first**. Correlation identifiers live on `#[tracing::instrument]` **spans**
so they automatically attach to every child event and propagate across `.await` points and crate
boundaries; per-event fields carry only data specific to that event. This is the convention best
suited to the existing OTLP pipeline (span fields become span attributes).

Canonical field registry — names are normative; use these exact keys (do not invent synonyms like
`val_idx` or `validator`):

| Field | Type / format | Where it lives | Notes |
|---|---|---|---|
| `slot` | `u64` | span (duty/attestation/block/sign spans) | |
| `epoch` | `u64` | span | |
| `validator_index` | `u64` | span/event | |
| `pubkey` | truncated `0x{first10}...{last8}` | span/event | **Always** via `crypto::logging::TruncatedPubkey` + `%`. Never the full key. |
| `duty` | enum-ish string (`attestation`/`block`/`aggregate`/`sync_committee`/…) | span | |
| `request_id` | string/uuid | span | Correlates a single signing/API request, incl. the :9000 Web3Signer path. |
| `bn_url` | redacted URL | event | **Always** via `crypto::logging::RedactedUrl`. Never raw credentials. |
| `validator_index` / `committee_index` | `u64` | span/event | |
| `network` | string | resource attr (already set in `telemetry::init`) | Do not duplicate per event. |

Mechanics:

- Hot-path async fns get `#[tracing::instrument]` with the relevant correlation fields, and
  `skip(...)` for large/sensitive arguments (so the macro does not `Debug`-format them).
- Per-event fields use the `field = value` form (e.g. `info!(slot, count, "published attestation")`);
  use the `%` (Display) and `?` (Debug) specifiers deliberately and only on non-secret values.
- Prefer `Display` wrappers (e.g. `TruncatedPubkey`, `RedactedUrl`) over `format!()` so that **no
  string is built when the level is disabled**.

The field registry table above is the normative artifact; the PRD-linked standard doc (P0) reproduces
and maintains it.

## Secret Redaction Policy (Normative, P0)

**Decision (recommended default):** standardize on the existing primitives, **hard-forbid** raw
secrets at every level, and add an **automated CI gate**.

Forbidden from logs entirely, at **every** level including `trace`:

- BLS **private keys** / secret-key bytes / Shamir shares.
- **Keystore passwords** and any decryption password material.
- **Mnemonics** / seed phrases.
- **Full signing payloads** and **full signatures** (the complete signing root or signature may appear
  only where already deemed safe; default is to omit or truncate — see Open Questions).
- Raw credentials inside URLs / endpoints.

Mandated primitives (the *only* sanctioned way to log these values):

- Public keys → `crypto::logging::TruncatedPubkey` (`0x{first10}...{last8}`), rendered with `%`.
- URLs/endpoints → `crypto::logging::RedactedUrl` (strips `user:pass@`) / `telemetry::config::redact_endpoint`.

High-risk crates that get explicit review under this policy: `crypto`, `secret-provider`, `signer`
(and the `bin/rvc-signer` :9000 path). These crates may add logging, but **no** added statement may
widen secret exposure.

Enforcement:

- A CI/test check (e.g. a `grep`/lint over source for raw secret-bearing patterns reaching a logging
  macro, plus targeted `tracing_test`/captured-subscriber tests in `crypto`/`signer` asserting
  truncated/redacted output) must pass with **0 findings**. If a fully robust automated gate proves
  impractical, the fallback is a documented reviewer checklist plus the captured-subscriber tests
  (this fallback choice is an Open Question).

## User Stories / Use Cases

- As an **operator**, I want a healthy client to emit a low-volume `info` heartbeat (epoch processed,
  attestation published for slot N, block proposed, BN connected) so I can confirm liveness at a
  glance and alert on its absence.
- As an **operator**, I want to set `RUST_LOG=debug` (or a per-module filter) and immediately see *why*
  a duty was skipped, *which* beacon node was chosen, and *what* the slashing-protection check decided,
  using consistent field names I can grep and dashboard on.
- As an **incident responder**, I want every log line and OTLP span for one duty to carry the same
  `slot` / `pubkey` (truncated) / `duty` / `request_id`, so I can follow a single signing request from
  the orchestrator through `crypto`/`signer` to the beacon node — including across the :9000
  Web3Signer boundary.
- As a **developer**, I want `trace` to walk me through building a signing payload step by step and show
  the wire-level beacon-node/Web3Signer request framing, so I can debug without attaching a debugger.
- As an **operator handling keys**, I want a guarantee that no log at any level ever contains a private
  key, keystore password, mnemonic, or full payload — only truncated pubkeys and redacted URLs.
- As an **operator running both binaries**, I want `bin/rvc` and `bin/rvc-signer` to share the same
  default level, `RUST_LOG` behavior, and output format so I do not have to learn each separately.
- As a **developer**, I want enabling `trace` in production-like load to be safe-by-construction:
  disabled verbose logging must add no allocation or formatting cost to the per-slot loop or sign path.

## Functional Requirements

### Must Have (P0)

- **P0-1 — Documented logging standard.** Author a normative standard under `plan/logging/` containing:
  the level taxonomy (above), the canonical structured-field registry (above), and the secret-redaction
  policy (above), with examples. This is the artifact every later change is measured against, and it is
  referenced from the codebase (e.g. a module doc in `telemetry`).
- **P0-2 — Structured-field convention applied.** Adopt the `snake_case`, spans-first convention with
  the canonical field registry across all in-scope logging. Correlation IDs (`slot`, `pubkey`, `duty`,
  `request_id`, …) live on spans and propagate to child events.
- **P0-3 — Secret-redaction policy applied + enforced.** Standardize on `TruncatedPubkey` /
  `RedactedUrl` / `redact_endpoint`; forbid the listed secrets at every level; land the automated
  secret-leak check (or the documented fallback) so it passes with 0 findings. Explicit review of
  `crypto`, `secret-provider`, `signer`, and the :9000 path.
- **P0-4 — `trace`/`debug` coverage of the runtime hot paths.** Add `debug` (decision points / internal
  state) and `trace` (step-by-step / wire-level) coverage, with standardized fields, across:
  - **Duty tracking** (`duty-tracker`, orchestrator `duty_management`) — fetch, cache hit/miss,
    dependent-root handling, epoch boundaries.
  - **Attestation & block production** (orchestrator `attestation`/`aggregation`/`block-service`,
    `builder`) — selection, build steps, publish.
  - **Signing**, including the **Web3Signer :9000 path** (`crypto`, `signer`, `bin/rvc-signer`
    `http_api`) — request received, payload build steps (no secrets), backend call, result; carry
    `request_id`.
  - **Beacon-node interaction** (`beacon`, `bn-manager`) — endpoint selection, request/response framing
    at `trace`, failover at `warn`.
  - **Slashing protection** (`slashing`) — check inputs (non-secret), decision, DB interaction.
- **P0-5 — Subscriber-init consistency.** Reconcile `bin/rvc` and `bin/rvc-signer` so they share a
  default level (`info`), `RUST_LOG`/`EnvFilter` precedence (env overrides config default), and output
  format selection. No change to the existing OTLP layer, file appender, or non-blocking writer
  contracts.
- **P0-6 — Hot-path zero-overhead-when-disabled.** Disabled `debug!`/`trace!` must perform no
  allocation, formatting, or hashing; guard expensive arguments; use `Display` wrappers and
  `#[instrument(skip(...))]` for heavy/sensitive args. No measurable latency added to the
  signing/attestation path at the default `info` level.

### Should Have (P1)

- **P1-1 — Bring gap crates up to standard.** Raise `rvc-keygen`, `signer-registry`, `eth-types`,
  `propagator`, `validator-store`, `doppelganger`, `timing`, and `metrics` to the standard: `info`
  milestones, `debug` internal state, and `trace` where a hot path exists.
- **P1-2 — Span instrumentation on remaining hot async fns.** Extend `#[tracing::instrument]` (with
  canonical fields and `skip` discipline) to hot-path public entry points not already covered by the
  existing 72 sites, so every hot-path entry point carries a standardized span.
- **P1-3 — Normalize existing well-covered crates.** Audit `crates/rvc`, `bin/rvc`, `bin/rvc-signer`,
  `signer`, `bn-manager`, `slashing`, `crypto` for level/field/redaction conformance and fix
  divergences (including any `error`-vs-`warn` miscategorization and duplicate error logging).
- **P1-4 — Operator-facing log documentation.** A short operator guide (under `plan/logging/` or
  `docs/`) covering default levels, `RUST_LOG` recipes (per-module filters), pretty-vs-JSON output, and
  how to read the canonical fields / follow a `request_id`.

### Nice to Have (P2)

- **P2-1 — Log sampling** for the highest-volume `trace`/`debug` sites (e.g. per-validator inner loops)
  to bound volume when verbose levels are enabled under large validator counts.
- **P2-2 — Dynamic level reload** at runtime (e.g. `tracing_subscriber::reload`) so operators can raise
  verbosity without restarting; coordinate with the existing reload machinery in `bin/rvc-signer`.
- **P2-3 — JSON output profile** as a first-class, documented production mode if not already the default
  for aggregation backends (the `fmt` layer exists; this is about a sanctioned, documented profile).
- **P2-4 — Per-crate logging conformance lint/CI** beyond the secret gate (e.g. flag non-canonical field
  names) to keep new code on-standard over time.

## Non-Functional Requirements

- **Performance.** Verbose levels are zero-cost when disabled (P0-6). `trace`/`debug` are never expected
  to be on in production. The per-slot loop and the signing/attestation path must show no measurable
  latency regression at the default `info` level vs. the pre-change baseline.
- **Security / privacy.** No secret material in logs at any level (P0-3). Truncated pubkeys and redacted
  URLs only. The high-risk crates carry explicit sign-off.
- **Compatibility.** Fully backward compatible with the existing `telemetry` crate (init, config,
  file_appender, propagation, shutdown), the OTLP/GCP exporters, trace-context propagation, and the
  `TracingGuard` lifetime contract. No regression to existing tests.
- **Operability.** Consistent default level and `RUST_LOG`/`EnvFilter` semantics across both binaries;
  documented filter recipes; output usable by standard aggregation tooling.
- **Maintainability / conventions.** `cargo fmt` clean, `cargo clippy` warning-free, follows the repo's
  naming and error-handling conventions and the RED→GREEN→REFACTOR TDD cycle in CLAUDE.md.
- **Volume.** `info` stays low-volume enough to run as a production default without flooding.

## Technical Considerations

- **Stack is already in place.** `tracing` + `tracing-subscriber`; dedicated `telemetry` crate
  (`config.rs`, `init.rs`, `file_appender.rs`, `propagation.rs`, `shutdown.rs`, `lib.rs`) with
  OpenTelemetry/OTLP (HTTP) and optional GCP Cloud Trace, W3C trace-context injection
  (`inject_trace_context`), size-rotated file logging via `logroller` + non-blocking writer, and a
  `ParentBased(TraceIdRatioBased)` sampler. **Do not rebuild any of this**; compose into it.
- **Existing redaction primitives to standardize on:** `crypto::logging::TruncatedPubkey`
  (`0x{first10}...{last8}`, zero-alloc `Display`, warns+falls-back on a double-`0x` prefix),
  `crypto::logging::RedactedUrl` (strips `user:pass@` via `url::Url`), and
  `telemetry::config::redact_endpoint`. The pubkey truncation format (10 leading / 8 trailing hex chars)
  is therefore a settled decision.
- **Existing span coverage:** 72 `#[tracing::instrument]` sites across 25 files (incl. `duty-tracker`,
  `beacon`, `slashing`, `crypto`, orchestrator modules). P1-2 extends, not introduces, this.
- **Subscriber-init divergence to fix (P0-5):** `bin/rvc` uses
  `EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))` (config default with
  `RUST_LOG` override) and pads layers with `Identity`; `bin/rvc-signer` uses
  `EnvFilter::from_default_env()`. These should converge on one documented precedence and default.
- **Hot-path mechanics:** use `#[instrument(skip(...))]` to avoid `Debug`-formatting large/sensitive
  args; pass `Display` wrappers (`TruncatedPubkey`/`RedactedUrl`) rather than pre-formatted strings;
  rely on `tracing`'s level check so disabled events never run their argument expressions.
- **Testing approach:** TDD per CLAUDE.md. Use captured-subscriber / `tracing_test::traced_test` tests
  to assert that specific events fire at the intended level with the intended fields and **redacted**
  values — the `crypto::logging` tests are the model. Validate workspace with
  `cargo nextest run --workspace`.
- **Integration test runner note (from project history):** `cargo test --workspace` can deadlock; use
  `cargo nextest run --workspace`.

## UX / Design Notes

This has no GUI. The "UX" is the operator/developer experience of the log stream and OTLP traces:

- **Scannable `info` heartbeat** that reads as a clear narrative of a healthy client.
- **Consistent field keys** so `RUST_LOG` filters, grep, and dashboards are reliable across crates.
- **One `request_id`** to follow a signing/API request end to end (including the :9000 path).
- **Truncated pubkeys** everywhere keep lines readable *and* safe.
- **Same look & feel** across both binaries (default level, `RUST_LOG`, format).

## Assumptions

- The existing `telemetry` stack (OTLP/GCP, file appender, propagation, shutdown, sampler, guard) is
  correct and stays as the foundation; this work composes into it.
- The pubkey truncation format `0x{first10}...{last8}` and the `TruncatedPubkey`/`RedactedUrl` helpers
  are the accepted redaction primitives and are extended/standardized, not redesigned.
- `info` is the production default level; `debug`/`trace` are diagnostic and off in production.
- `RUST_LOG`/`EnvFilter` is the level-control mechanism; env overrides the config default.
- Existing tests pass on `develop` and `cargo nextest run --workspace` is the runner of record.
- The 23-crate / 3-binary workspace shape (`bin/rvc`, `bin/rvc-keygen`, `bin/rvc-signer` on :9000) is
  current.
- This effort changes only logging/observability; it does not alter runtime behavior, public APIs, or
  signing/slashing logic.

## Out of Scope / Non-Goals

- **Not** introducing a new logging or tracing framework — `tracing`/`tracing-subscriber`/OTLP stay.
- **Not** redesigning the `telemetry` crate, the OTLP/GCP exporters, the file appender, the sampler, or
  the propagation/shutdown machinery (beyond the P0-5 init-consistency reconciliation).
- **Not** changing metrics. The `metrics` crate's Prometheus counters/registry and the `:9101` metrics
  endpoint are separate; this is about log events, not metrics (the `metrics` crate may still gain log
  statements under P1-1).
- **Not** rewriting error-handling control flow. We may fix `error`-vs-`warn` miscategorization and
  remove duplicate log-and-return error lines, but `Result` flow, error types (`thiserror`/`anyhow`),
  and `?` propagation are unchanged.
- **Not** adding logging to test code or test helpers, except the captured-subscriber tests that verify
  level/field/redaction behavior.
- **Not** altering validator behavior, signing logic, slashing protection decisions, or any public API.
- **Not** building log dashboards, alerts, or collector/back-end configuration (operator territory;
  P1-4 documents recipes only).
- **Not** redefining the pubkey truncation format or building new redaction primitives unless an
  existing helper is missing for a needed type.

## Open Questions

1. **Full signing root / signature at `trace`.** Default policy is to omit or truncate. Is the
   *complete* (non-secret) signing root or signature ever acceptable at `trace` for deep debugging, or
   should it always be truncated/omitted? (Resolved as truncate/omit unless explicitly approved.)
2. **Pubkey at `trace`.** Confirm pubkeys are truncated even at `trace` (current default), or whether a
   full pubkey is permitted at `trace` only. Private keys/passwords/mnemonics remain forbidden
   regardless.
3. **Secret-leak gate mechanism.** Preferred enforcement is an automated CI grep/lint plus
   captured-subscriber tests. If a robust automated source-scan proves impractical, is the documented
   reviewer-checklist + tests fallback acceptable for P0?
4. **Output default for production.** Pretty vs. JSON as the *default* production format (the `fmt` layer
   supports both). Proposed: keep current default, document JSON as the sanctioned aggregation profile
   (P2-3); confirm.
5. **Per-event-vs-span strictness.** Spans-first is the recommended default; confirm we do not also want
   correlation fields *repeated* on each event for environments that flatten spans.
6. **`error`-vs-`warn` re-categorization breadth.** How aggressively should the normalize pass (P1-3)
   reclassify existing `error!`/`warn!` calls, given the Non-Goal of not touching error-handling
   control flow?

## Milestones & Phases

- **Phase 0 — Standard.** Land P0-1 (taxonomy + field registry + redaction policy) under
  `plan/logging/`. Unblocks everything; gives reviewers the rubric.
- **Phase 1 — Hot paths + safety.** P0-2/P0-3/P0-4/P0-6: apply fields, redaction, and `debug`/`trace`
  coverage to the runtime hot paths with zero-overhead-when-disabled, plus the secret-leak gate.
- **Phase 2 — Init consistency.** P0-5: reconcile the two binaries' subscriber init.
- **Phase 3 — Breadth.** P1-1/P1-2/P1-3: gap crates, remaining span instrumentation, and normalization
  of already-covered crates.
- **Phase 4 — Docs & polish.** P1-4 operator guide; then P2 items (sampling, dynamic reload, JSON
  profile, conformance lint) as capacity allows.

## Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **Secret leakage** via a new log statement (esp. `crypto`/`secret-provider`/`signer`/:9000). | Security incident. | Hard-forbid list + mandated redaction helpers + automated secret-leak gate + explicit high-risk-crate review (P0-3); captured-subscriber tests assert redacted output. |
| **Hot-path latency regression** from logging in per-slot/sign code. | Missed duties / slashing-deadline pressure. | Zero-cost-when-disabled rules (P0-6): guard args, `Display` wrappers, `instrument(skip)`; bench/test the per-slot loop and sign path; verbose off in prod. |
| **`info` floods** production logs. | Operators tune it out / cost. | Strict taxonomy: `info` = milestones only; high-volume detail is `debug`/`trace`; P2-1 sampling as backstop. |
| **Inconsistent adoption** leaves drift. | Goal not met; future regressions. | Standard doc as the review rubric (P0-1); normalization pass (P1-3); optional conformance lint (P2-4); reviewers check field/level/redaction. |
| **Breaking the existing OTLP/file/propagation stack.** | Lost telemetry. | Non-Goal to redesign `telemetry`; compose into existing layers; keep `TracingGuard`/shutdown contracts; rely on existing `telemetry` tests staying green. |
| **`cargo test --workspace` deadlock** masks results. | False confidence. | Use `cargo nextest run --workspace` (project-history runner of record). |
| **Subscriber-init reconciliation** subtly changes default verbosity/format. | Operator surprise. | P0-5 documents the precedence/default explicitly; covered by init tests in both binaries. |
