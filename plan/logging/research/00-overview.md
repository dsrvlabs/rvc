# Research Overview: Structured Logging & Observability for rs-vc

> Lead consolidation of a five-angle investigation for the rs-vc logging initiative
> (PRD: [`plan/logging/prd.md`](../prd.md)). This doc **leads with the recommendations**, reconciles
> conflicts between angles, drops or caveats claims that adversarial verification refuted, and surfaces
> the consolidated assumptions. Per-angle detail lives in the linked docs.

## Per-Angle Docs

| Angle | Doc | Scope |
|---|---|---|
| Tracing best practices | [`tracing-best-practices.md`](./tracing-best-practices.md) | Spans-first conventions, `#[instrument]` idioms, async correctness, zero-cost mechanics, field naming. |
| Secret redaction | [`secret-redaction.md`](./secret-redaction.md) | Structurally preventing key/password/mnemonic/payload leakage across `crypto`/`secret-provider`/`signer`/:9000. |
| OTel correlation | [`otel-correlation.md`](./otel-correlation.md) | `tracing` → OTLP attribute mapping, W3C context across the :9000 hop, sampler interaction, `request_id`. |
| VC logging landscape | [`vc-logging-landscape.md`](./vc-logging-landscape.md) | What operators expect from Lighthouse/Prysm/Teku/Nimbus/Lodestar; the familiar `info` heartbeat. |
| Hot-path performance | [`hot-path-performance.md`](./hot-path-performance.md) | Whether `tracing` adds measurable overhead; how to GUARANTEE P0-6; the verification harness. |

---

## TL;DR Recommendations (lead with these)

1. **Ratify the PRD's spans-first, `snake_case`, 5-level taxonomy as-is.** All five angles independently
   converged on it; none proposes an alternative. The research's job is the *precise idioms*, not a
   re-decision.

2. **Stamp the canonical correlation fields on `#[instrument]` spans, not events**
   (`slot`, `epoch`, `validator_index`, `pubkey`, `duty`, `request_id`, `committee_index`/
   `subcommittee_index`; `network` stays a resource attribute). Child events inherit them for free, and
   the OTLP layer turns span fields into span attributes.

3. **Set `level = "debug"` (or `"trace"`) on every hot-path `#[instrument]`.** The attribute defaults
   to **INFO**, which floods the `info` heartbeat on per-slot/per-validator functions. This is the
   single most common mis-use to audit for.

4. **Make `skip_all` the default on every secret- or large-arg function**, then re-add only chosen
   fields via `fields(...)`. `skip_all` is both a redaction control and a performance control (it stops
   auto-`Debug` of `&SecretKey`/`&BeaconBlock`/payloads). Bare `#[instrument]` on a sign/decrypt fn is
   forbidden.

5. **Close the :9000 correlation gap.** Add an inbound `HeaderExtractor` + `set_parent_from_headers`
   to `telemetry::propagation` (the inverse of the existing `inject_trace_context`) and call it first in
   the rvc-signer `sign` handler. Mint one `request_id` (`uuid::Uuid::new_v4()`) per logical operation,
   carry it on the span, and echo it across the hop via an `x-request-id` header. This is the one change
   that actually makes the existing `ParentBased(TraceIdRatioBased)` sampler keep a duty trace
   all-or-nothing end to end.

6. **Guarantee P0-6 with three rules + a bench:** (a) `level` + `skip_all` on every hot-path
   `#[instrument]`; (b) gate any field that does real work (`hex::encode`, `serde_json`, hashing,
   `format!`) behind `tracing::enabled!` or a zero-alloc `Display` wrapper; (c) compile
   `release_max_level_debug` into both production binaries so `trace!` is physically removed from the
   release build while `debug!` stays runtime-switchable via `RUST_LOG`. Verify with a `criterion`
   sign-path bench + a counting-`#[global_allocator]` test asserting **zero** incremental allocations
   when verbose is disabled.

7. **Shape the `info` heartbeat like Lighthouse** (familiarity for migrating operators): one milestone
   per completed duty with `slot`, the build/sign step at `debug` and the publish step at `info`
   (the Lodestar `Signed`=debug / `Published`=info split), a once-per-slot "still alive / here's the
   head" tick, and a `time_into_slot`/`delay` timing field (Nimbus's most useful operator signal).

8. **Add the missing redaction primitive and CI gate.** Add a `TruncatedRoot`/`TruncatedHash`
   zero-alloc `Display` wrapper (mirroring `TruncatedPubkey`) for block/head roots and signing roots at
   `trace`. Land the enforcement that does **not yet exist**: a `clippy.toml` `disallowed-methods` gate
   (banning `expose_secret`/`raw_bytes`/`to_bytes` from log-adjacent code) + a `gitleaks` PR job +
   captured-subscriber tests asserting the raw secret is **absent** from emitted output.

---

## Consolidated Implementation Guidance

### A. Spans-first correlation (P0-2)

- Canonical correlation IDs live **once** on the `#[instrument]` span; per-event fields carry only
  event-specific data (`count`, `%bn_url`, `result`).
- Declare any field whose value isn't known at span creation as `tracing::field::Empty`, then fill it
  with `span.record("field", value)` after the value resolves (e.g. `slot`/`duty`/`pubkey` after the
  :9000 body is parsed). **`record()` on a field that was not declared at creation is silently
  dropped** — this is the #1 cause of a "vanishing" attribute. (Mirror the existing
  `http.status_code = Empty` pattern in `beacon::client`.)
- To `record()` a `Display`/`Debug` value, wrap with `tracing::field::display(...)` /
  `tracing::field::debug(...)` — the `%`/`?` sigils are macro sugar only and don't work at a `record()`
  call site.

### B. `#[instrument]` idioms

- Defaults: span level **INFO**, span name = fn name, **all args auto-captured** (via `Value` or
  `Debug`). Override deliberately:
  - `level = "debug"` on hot fns (rule 3 above).
  - `skip_all` + explicit `fields(...)` on anything taking a secret or large arg (rule 4).
  - `name = "..."` for a stable, greppable name on public entry points.
  - `err` only at the layer that decides an error is terminal — **not** at every layer (CLAUDE.md
    "log once"); `ret` only on small non-secret returns at `debug`/`trace`.
- `#[instrument(fields(...))]` expressions are evaluated **eagerly at the start of the function body,
  on every call**, regardless of whether the span level is enabled (see Reconciliation §R1). So do
  **not** put expensive Debug/Display computation in `fields(...)`; move it into an `event!`/`debug!`
  field (which is gated by the level check) or behind `enabled!`.

### C. Async correctness (mandatory)

- **Never hold a `Span::enter()` guard across `.await`** — the executor can poll a different task while
  your span is still entered, producing overlapping/wrong traces. Prefer `#[instrument]` (rewrites the
  body correctly); use `.instrument(span)` on raw futures, `.in_current_span()` / `Span::or_current()`
  when handing a future to `tokio::spawn`, and `Span::in_scope(|| …)` for synchronous closures inside
  async code.
- `tokio::spawn` does **not** inherit the current span; attach it explicitly.
- `spawn_blocking` closures don't inherit the span either; capture `Span::current()` and
  `let _e = span.enter()` **inside** the closure (safe there — no `.await`). This is the concrete fix
  for the `SigningGate.sign_*` blocking-section detachment (see Reconciliation §R3).

### D. Zero-cost-when-disabled (P0-6)

1. **Runtime interest cache (always on):** a disabled event/span is a cached integer load + branch;
   the Span/Event is never constructed and the macro's field expressions aren't evaluated — *provided
   the work is inside the macro field expression*, not precomputed into a local.
2. **Compile-time static cap:** `release_max_level_debug` on both binaries removes `trace!` (and
   below-cap spans) from the release binary entirely — the strongest form of P0-6, and it also
   neutralizes the residual `EnvFilter` dynamic-directive cost (there's nothing left to be called on).
   Do **not** enable tracing's `log` bridge feature (it can re-introduce cost under a static cap).
3. **`enabled!` guard** for unavoidably-expensive multi-statement setup
   (`if enabled!(Level::TRACE) { let dump = …; trace!(?dump, …) }`).
- Quantitative anchor: an upstream `no_subscriber` span costs ~0.7 ns to construct / ~0.5 ns to enter —
  ~6 orders of magnitude below a BLS sign. (Note: those are *no-dispatcher* numbers, an upper bound for
  the static-cap case; the disabled-by-`EnvFilter` in-process number is **not** published upstream,
  which is exactly why rs-vc must measure its own — see §H.)
- Caveat on async spans: an **enabled** `#[instrument]` async fn enters/exits its span on **every
  poll**, so cost scales with poll count when on. Prefer **coarse spans** (one per phase, not one per
  inner await) on the hottest async paths. This is the *enabled* cost (out of P0-6's "when disabled"
  scope) but operationally real under verbose-in-prod.

### E. Secret redaction (P0-3) — defense in depth, three layers

No single layer is sufficient: a type wrapper makes a secret *harder* to leak but **cannot make it
impossible** — `expose_secret()` → `info!()` always works. So combine:

1. **Type-level (reduces accidents):** every secret lives in a type that redacts `Debug` and does
   **not** implement `Display`. rs-vc already does this (`SecretKey([REDACTED])`, `secrecy::SecretString`,
   `SecretDataFormat` → `<redacted>`, `Zeroizing`). The policy *standardizes and closes gaps*, it does
   not redesign. **Keep** `secrecy`'s default no-`Serialize`/no-`Display` — never add `SerializableSecret`
   or a `Display` impl "for convenience."
2. **CI lint gate (catches obvious bypasses) — NET-NEW, NOT YET PRESENT:** a `clippy.toml`
   `disallowed-methods` config banning the known unsafe sinks (`secrecy::ExposeSecret::expose_secret`,
   `SecretKey::to_bytes`/`raw_bytes`, raw `bip39::Mnemonic` formatting), riding the existing
   `cargo clippy --workspace --all-targets -- -D warnings` step. `expose_secret` is legitimately needed
   at decrypt call sites → scope it with a small, reviewed, greppable
   `#[allow(clippy::disallowed_methods)]` allow-list so the lint flags any *new* use elsewhere.
   *Limitation (state in the policy):* `disallowed-methods` matches **named paths only** — it cannot
   see a value already laundered into a `String`/`&str`. That's acceptable because the type layer makes
   the implicit path impossible and the tests cover the runtime result.
3. **Runtime proof:** `#[tracing_test::traced_test]` tests in `crypto`/`signer`/`bin/rvc-signer` that
   fire each high-risk log line and assert the output **does** contain the truncated/redacted form and
   **does NOT** contain the raw secret (the existing
   `test_truncated_pubkey_double_0x_prefix_warns_and_falls_back` test is the proven model), plus a
   `gitleaks` pass over source **and** a captured sample of emitted `trace`-level log output.

**Mandated handling per secret** (from `secret-redaction.md`): BLS key → never log, gate
`raw_bytes()`/`to_bytes()` (the highest-risk laundering path); password → `SecretString`, ban
`expose_secret` outside decrypt; mnemonic → never log, not even length (`bip39::Mnemonic` *does*
`Display` to the phrase — treat the bare type as a sink); full payload/root/signature → truncate at
`trace` via the new `TruncatedRoot` wrapper, full value only on return values; pubkey → **always**
`TruncatedPubkey` + `%`, even at `trace`; URL → **always** `RedactedUrl`/`redact_endpoint`.

**Fallback (PRD Open Q3):** if a robust automated *source* scan proves impractical, drop only the
brittle regex source scan and keep Layers 1+2 (both automated), the captured-subscriber tests, the
`gitleaks` source+emitted scan, and a documented reviewer checklist for the four high-risk crates.
This is *stronger* than the PRD's stated minimum.

### F. OTel correlation across the :9000 boundary (P0-2/P0-4)

- `tracing` span fields → OTel span **attributes**; events inside a span → OTel **span events** whose
  fields become event attributes. Dotted names pass through verbatim (`http.method` → `http.method`).
- Use `otel.kind = "server"` on the inbound :9000 span, `"client"` on outbound beacon/signer calls.
- **The gap to close:** `telemetry::propagation` has `inject_trace_context` (outbound) but **no**
  inbound extractor, so the :9000 `sign` handler starts a fresh root trace — the trace breaks at the
  boundary. Add the `HeaderExtractor`/`set_parent_from_headers` inverse (compose into the existing
  module; do not add a crate). Keep the `ParentBased(TraceIdRatioBased(rate))` sampler exactly as-is —
  it makes a duty trace all-or-nothing *once the boundary is bridged*; `sample_rate` defaults to `1.0`
  so the fragmentation is latent today but bites the moment the rate is lowered.
- **Namespace drift to fix:** orchestrator `#[instrument]` sites use an `rvc.`-prefix
  (`rvc.slot`, span `rvc.orchestrator.process_slot`) while `beacon::client` uses OTel HTTP semantic
  names. The PRD's unprefixed `snake_case` registry must be the single source of truth; normalize the
  existing sites to it (`rvc.slot` and `slot` are *different* OTLP attribute keys — dashboards grouping
  by `slot` miss the `rvc.slot` spans).

### G. Operator-facing `info` heartbeat (familiarity)

Convergence across all five major clients: default level **`info`**, a low-volume `info` heartbeat
anchored on "I did my duty for slot N", `slot` on every duty line, truncated roots/pubkeys, human-
readable console default with opt-in JSON for aggregation, and the **file often more verbose than the
console** (Lighthouse/Lodestar default the file to `debug`). Recommended milestone set at `info`:
validators loaded, BN connected, epoch boundary, attestation/aggregate published, block proposed,
sync-committee message/contribution, validator registration, and an optional once-per-slot tick.
Demote `Signed…`, duty cache hit/miss, BN selection, and slashing inputs/decision to `debug`; demote
wire framing and per-item loops to `trace`. Use field name `head` for the attested head, `block_root`
for a proposed block. Keep `committee_index`/`subcommittee_index` (not Prysm's `CommitteeIndex` or
Lodestar's bare `index`) — `committee_index` matches Lighthouse, the primary migration source.

### H. Verification harness (P0-6, net-new)

No bench infra exists in the workspace today. Add: a `criterion` sign-path bench comparing
`no_subscriber` / `subscriber_info` (debug spans disabled) / `subscriber_trace` regimes (pass if
info ≈ no_subscriber within noise); a per-slot-loop bench around one coordinator phase; and a
dependency-free counting-`#[global_allocator]` test asserting `assert_eq!(allocs_when_disabled,
baseline)` on the sign and per-slot paths. The allocation assertion — not the latency bench — is the
**precise** gate, because a ~1 ns span is below `criterion`'s measurement floor next to a BLS sign.
Run the asserting tests under `cargo nextest run --workspace`; benches via `cargo bench`.

---

## Reconciliation of Conflicts & Corrections

These are the points where adversarial verification overturned, narrowed, or re-sourced a per-angle
claim. **Treat the versions below as authoritative**, overriding the raw per-angle text.

### R1 — `#[instrument(fields(...))]` evaluates EAGERLY, not lazily (the most important correction)

The best-practices doc's "keep expensive work INSIDE the macro field expression" advice is correct for
the **`event!`/`span!`/`debug!`/`trace!` family** (their field expressions are skipped when the level
is disabled) but **backwards for `#[instrument]`**: per the `#[instrument]` docs, `fields(...)`
expressions *"will be evaluated at the beginning of the function's body"* — **eagerly, on every call,
regardless of whether the span level is enabled.**

- **Authoritative rule for rs-vc:** Do **not** compute expensive Debug/Display values in
  `#[instrument(fields(...))]`. Use `skip_all`, gate with `tracing::enabled!`, or move the cost into an
  `event!`-family field where the enabled check gates evaluation.
- **Knock-on for redaction:** a `TruncatedPubkey`/`RedactedUrl` passed with `%` is lazy-skipped **only**
  on an event-family macro (or a `skip`/`enabled!`-protected path). Placed in
  `#[instrument(fields(pk = %...))]`, its `Display` **runs on every call**. So "pass with `%` rather
  than `format!()`" is necessary but **not sufficient** — the `%` must be on an event macro, not on an
  ungated `#[instrument]` field. (The cheapness is still fine for `Copy` scalars like `slot`; the
  caveat is about anything that does real formatting work.)

This affects the codebase's own house style — e.g. the `crypto` sign fns carry
`#[instrument(level="debug", skip_all, fields(...))]`; the `fields(...)` there must stay limited to
`Copy` scalars / cheap values, not costly computations.

### R2 — OTel naming is SHOULD, not MUST; the reuse rule is narrower than stated

`tracing-best-practices.md` claims OTel semconv "mandates `snake_case`" and "requires identical names
across Resource/Span/Log/Metric / forbids synonyms." Verification narrows this:

- `snake_case` is a **SHOULD**, not a MUST ("separate the words by underscores").
- The actual rule is *"two attributes, two metrics, or two events MUST NOT share the same name"* while
  *"different entities (attribute and metric, metric and event) MAY share the same name."* A name is
  unique-in-meaning **within the attribute namespace** (which Resource/Span/Log attributes share), but
  the spec **permits** the same string across different entity types.
- **Net:** the downstream advice — one shared `snake_case` vocabulary, the canonical registry, no
  `val_idx`/`validator` synonyms — **survives as a sound house rule**, but present it in the standard
  as a **house standard (SHOULD-level)**, not as an OTel-mandated MUST.

### R3 — `SigningGate.sign_*` ARE instrumented; the real gap is the blocking section

`otel-correlation.md`'s in-repo gap list says "`SigningGate.sign_*` … has no `#[instrument]`." **This is
false** — every `sign_*` method on the gate is `#[tracing::instrument(name="rvc.sign.…", skip_all,
fields(…))]` (e.g. `sign_block` at `crates/signer/src/lib.rs:330`, plus `sign_attestation`,
`sign_randao`, sync/aggregate/exit/registration/contribution arms). The **accurate** gap: the BLS sign
runs inside a `spawn_blocking` closure (via `handle.block_on`, `lib.rs:372`) that does **not** re-enter
the parent `rvc.sign.*` span, so events emitted from inside the blocking section are detached from the
span. The fix is the captured-span `let _e = span.enter()` inside the closure (§C), not adding a missing
`#[instrument]`. (Also: the evidence lives in `crates/signer/src/lib.rs`, not
`bin/rvc-signer/src/http_api/routes.rs` as the angle's source pointer claimed.) The rest of the
correlation gap inventory — no inbound `traceparent` extraction at /sign, no `request_id` on the sign
path, `rvc.`-prefixed namespace divergence, `request_id` only in `keymanager-api` — is **verified**.

### R4 — `secrecy` 0.10 REMOVED `Secret<T>` + newtyped `SecretBox` (not a "rename")

`secret-redaction.md` says 0.10 "renamed `Secret<T>` → `SecretBox`." More precisely: 0.10.0 **removed**
`Secret<T>` ("instead use `SecretBox<T>`") and made `SecretBox<T>` a **newtype** rather than a type
alias of `Secret<Box<T>>`. Downstream guidance (use `SecretBox`/`SecretString` on the 0.10 line rs-vc
pins, read via `ExposeSecret::expose_secret`) is unaffected.

### R5 — The clippy `disallowed-*` gate and the gitleaks job DO NOT EXIST YET

`secret-redaction.md` describes the `clippy.toml` `disallowed-methods` gate and a secret-scan job as
the enforcement mechanism. **rs-vc's `clippy.toml` today contains only `msrv = "1.92"`** — no
`disallowed-*` entries — and `ci.yml` has **no** secret-scan job. Write these as **"to be added"**
recommended additive work, not as current state. The mechanism is sound and rides the existing
`-D warnings` step at zero new infra; the in-tree primitives
(`SecretKey`/`SecretDataFormat` redaction, `TruncatedPubkey`, `skip_all` on the :9000 routes, the
metadata-only audit log, `tracing-test`) are already present to make it testable.

### R6 — Drop/soften the "Lighthouse truncates roots" precedent; keep the verified contrast

`secret-redaction.md`'s "Lighthouse truncates block roots/hashes" precedent could not be verified and
is **contradicted** by Lighthouse emitting full-length `0x` block roots in some log lines. **Soften or
drop it.** The load-bearing facts survive: rs-vc's `TruncatedPubkey` = `0x{first10}...{last8}` zero-alloc;
and Lighthouse logs the **full** `voting_pubkey` at enable-time — a choice rs-vc deliberately does
**not** copy (rs-vc truncates pubkeys at every level incl. `trace`, PRD Open Q2). The recommendation
(consistent always-truncated pubkeys) stands.

### R7 — Citation hygiene in `vc-logging-landscape.md` (content sound, sources to fix)

The angle's *log-line substance* is verified, but five citations are mis-attributed and must be fixed
before this is treated as finished:

1. Lodestar debug/info split: drop issue #2909 (wrong topic — orphaned attestations); keep CoinCashew
   for the `info: Published attestations` line, find a real source for the `debug: Signed attestation`
   line.
2. Nimbus sync-message + `delay` line: re-source to nimbus-eth2 issue #5324, not
   `validator-monitor.html`.
3. Prysm `Submitted new block`/`sync message`: re-source to actual log captures; move
   `subcommitteeIndex` onto the `sync contribution and proof` line (it's not on the plain sync-message
   line).
4. Lighthouse per-slot line: present **both** observed shapes (older `Slot timer, sync_state: Synced …`
   and current `INFO Synced …`, issue #4747) — don't imply one canonical field set.
5. Soften the Prysm `--log-format text/json/fluentd/journald` flag claims (consistent with logrus but
   not re-confirmed from a primary Prysm doc this pass).

Also: the recommendation §11 originally grounded itself in "`plan/logging/prd.md` decisions" that the
researcher could not find at the time — **that PRD now exists** (it's the artifact this overview sits
under), so that grounding is resolved; the "`request_id` survives the :9000 hop" and "OTLP traces none
of the five offer" differentiators are forward-looking **design opinion**, plausible and consistent
with the Web3Signer frontend, not facts checkable against the five clients' docs.

### R8 — Level-taxonomy table is a house standard, not upstream-normative

The taxonomy's external corroboration is a single third-party blog (oneuptime.com), not a primary
source. The taxonomy is conventional and consistent with tracing's own `Level` docs and the Tokio
examples, and the load-bearing rule ("anything scaling with validator count or per-loop is
`debug`/`trace`, never `info`") is good practice — but present it as the **rs-vc house standard**, with
the tracing `Level` enum docs as the primary anchor, not as an upstream mandate.

### R9 — Truncation-glyph nit (only if a format is copied byte-for-byte)

Lighthouse/Lodestar use the single-char ellipsis `…`; Teku/Prysm/Nimbus short forms use two ASCII dots
`..` or none. The angle docs mix `…` and `..` loosely. rs-vc's `TruncatedPubkey` is the settled format
(`0x{first10}...{last8}`); the new `TruncatedRoot` wrapper should pick one glyph and be consistent.

### Claims that survived verification cleanly (cite with confidence)

- **hot-path-performance**: no claims refuted; all eight substantially supported by primary docs, the
  upstream PR #1974 benchmark, and a byte-exact check of the in-repo `enabled!` guard at
  `crates/beacon/src/client.rs:149`. Minor precision flags only (e.g. "integer load, comparison and
  jump" is the `log` crate's phrasing, attributed correctly; `~696/466 ps` are no-dispatcher numbers).
- **tracing-best-practices** claims 1,2,4,5,6,8: every sub-clause matched primary
  tracing/tracing-subscriber docs and the Tokio page verbatim — safe to cite as normative.
- **otel-correlation** claims 1–10: high confidence, each on a re-fetched primary source (rustdoc or
  the OTel SDK spec) plus direct file reads; only the gap-inventory item (R3) carried an error.

---

## Consolidated Assumptions

These hold across the angles and underpin every recommendation above. They should be carried into the
standard doc (P0-1) and flagged at the implementation gate.

1. **The existing stack stays and is composed into, not rebuilt.** `tracing` 0.1 / `tracing-subscriber`
   0.3 / `tracing-opentelemetry` 0.32 / `opentelemetry*` 0.31; the `telemetry` crate (init, config,
   file appender, propagation, shutdown, `ParentBased(TraceIdRatioBased)` sampler, `TracingGuard`).
   No framework swap; no telemetry redesign (PRD Non-Goals).
2. **The PRD's settled decisions are authoritative and not re-opened:** `snake_case`, spans-first,
   the 5-level taxonomy, `TruncatedPubkey = 0x{first10}...{last8}`, `info` = production default,
   `RUST_LOG`/`EnvFilter` env-overrides-config. The research ratifies and supplies idioms.
3. **`info` stays low-volume** (≈ one line per assigned duty per validator); anything scaling with
   validator count or per-loop is `debug`/`trace`. P2-1 sampling is the backstop.
4. **Release builds keep `debug` runtime-switchable but compile `trace` out**
   (`release_max_level_debug`), so operators can escalate to `debug` via `RUST_LOG` in prod without a
   separate build, while `trace!` adds zero binary cost. (Confirm at the gate vs `release_max_level_info`.)
5. **Spans-first is acceptable to the operators' OTLP backend.** If a flat backend that drops span
   fields is in play, stamp `request_id` on terminal events as a mitigation (PRD Open Q5).
6. **Pubkeys are truncated even at `trace`; full signing roots/signatures are truncated/omitted by
   default** (PRD Open Qs 1 & 2, taken as resolved-to-stricter). `network` stays a resource attribute,
   never duplicated per event.
7. **`x-request-id` is an acceptable additive carrier** for the human-readable `request_id` alongside
   W3C `traceparent`; it doesn't change signing behavior and is ignored by clients that don't send it.
   (Deriving `request_id` from the OTel trace/span ID is a viable alternative — flagged for the gate.)
8. **`cargo nextest run --workspace` is the runner of record** (`cargo test --workspace` can deadlock,
   per project history). No new mandatory toolchain (nightly/dylint) for P0; the dylint dataflow-aware
   lint is a P2 escalation, not a P0 blocker. `valuable`-based structured redaction stays in reserve
   for the future JSON profile (it needs the unstable `--cfg tracing_unstable`).
9. **The four high-risk crates** (`crypto`, `secret-provider`, `signer`, the `bin/rvc-signer` :9000
   path) are the correct review boundary; treat `rvc-keygen` (mnemonic/`bip39`) as equally high-risk
   for the mnemonic rule even though the PRD lists it under P1 breadth.

---

## Open Questions Forwarded to the Gate

(Beyond the PRD's six Open Questions, which stand.)

- **Static cap choice:** `release_max_level_debug` (recommended) vs `release_max_level_info`. The PRD's
  "operators escalate to `debug` via `RUST_LOG` in prod" requirement points to `debug`.
- **`request_id` source:** fresh `uuid::Uuid::new_v4()` + `x-request-id` header (recommended, matches
  the `keymanager-api` precedent) vs deriving it from the OTel trace/span ID (one fewer header).
- **File-more-verbose-than-console default** (file at `debug`, console at `info`) — recommended for
  Lighthouse/Lodestar familiarity, **contingent** on the existing `logroller`/non-blocking-writer
  appender supporting an independent level; confirm against the `telemetry` crate, do not assume a
  redesign.
- **Coarse-span granularity** on the hottest async fns (one span per phase) to bound the per-poll
  enter/exit cost when `debug`/`trace` is enabled under large validator counts.
