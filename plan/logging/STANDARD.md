# rs-vc Logging & Observability Standard (Normative)

> **This is the normative logging contract for the entire rs-vc workspace.** Every log statement
> added or changed — in any crate or binary — must conform to it. It is the review rubric for the
> structured-logging / observability initiative and is referenced from a `//!` module doc in the
> `telemetry` crate so it is discoverable from code.
>
> Authoritative sources reproduced here: the **level taxonomy (§1)** is verbatim from
> `plan/logging/prd.md` ("Level Taxonomy"); the **canonical field registry (§2)** follows the registry
> table in `plan/logging/architecture.md` (~lines 267–281, the declared normative artifact — a
> superset of the PRD's field table, adding `committee_index`/`subcommittee_index`/`head`/`block_root`/
> `time_into_slot`); the **redaction policy (§3)** reproduces `plan/logging/prd.md` ("Secret Redaction
> Policy"); the `#[instrument]` rules (§4) come from `plan/logging/research/` (rules R1–R9) and the
> ADRs. Where this document and a phase issue disagree, **this document wins** for
> level/field/redaction questions.
>
> Conformance keywords (**MUST**, **MUST NOT**, **SHOULD**, **MAY**) are used in the RFC 2119 sense.
> The field-naming rules are a **house standard** (SHOULD-level per research R2); the redaction rules
> are **hard MUST/MUST NOT** (P0).

---

## 1. Level Taxonomy (Normative)

This is the load-bearing decision of the initiative. Every log statement added or changed **MUST**
fit this taxonomy. Anchored on the `tracing::Level` docs as the **rs-vc house standard**, not an
upstream mandate (research R8).

| Level | Audience | Meaning | Examples |
|---|---|---|---|
| `error` | Operator | An operation failed and the client could not complete an intended action; needs attention. | Sign request rejected by slashing protection; all beacon nodes unreachable; keystore decrypt failed. |
| `warn` | Operator | Unexpected but handled; degraded but progressing. | Beacon-node failover triggered; remote signer slow/retried; duty fetched late; malformed input rejected at an API boundary. |
| `info` | Operator | Operator-facing **milestones** — the normal heartbeat of a healthy client. Low volume; safe as a production default. | Startup/config summary; epoch boundary processed; attestation published for slot N; block proposed; validator set loaded; BN connected; signer server listening. |
| `debug` | Developer | Developer-facing **internal state** and decision points. Off in production by default. | Duty cache hit/miss and contents; selected target BN and why; slashing-protection check inputs/outcome; state transitions in the orchestrator. |
| `trace` | Developer | **Fine-grained, step-by-step / wire-level** detail. Highest volume; never on in production. | Each step of building a signing payload; request/response framing on the :9000 Web3Signer path and beacon-node HTTP calls; per-item loop iterations; computed roots/domains (non-secret). |

**Load-bearing rule:** *anything that scales with validator count or fires per-loop / per-slot is
`debug` or `trace`, **never** `info`.* The `info` stream is the operator heartbeat — it MUST stay
low-volume and constant regardless of how many validators are loaded.

### Cross-cutting rules

- **`error` vs `warn`.** Use `error` **only** when an intended action did not complete. If the client
  recovers or degrades-but-progresses, it is `warn`. (Total beacon-node outage = `error`; a
  single-node failover that still progresses = `warn`.)
- **Log once.** Do **not** log-and-return the same error at multiple layers. Log once, at the layer
  that decides the failure is terminal; lower layers return the `Result` (per CLAUDE.md). Rewriting
  error-handling control flow is a non-goal — only collapse genuine duplicate error lines.
- **One event, one level.** The same logical event is logged at the same level everywhere.
- **No secrets at any level.** `trace` is **not** an exception. See §3.

---

## 2. Canonical Structured-Field Registry (Normative)

**`snake_case` keys, spans-first.** Correlation identifiers live **once** on a
`#[tracing::instrument]` span so they automatically attach to every child event, propagate across
`.await` points and crate boundaries, and become span attributes in the OTLP pipeline. Per-event
fields carry only data specific to that one event.

Use these **exact** keys. Synonyms are **forbidden** — never `val_idx`, `validator`, `index`,
`CommitteeIndex`, and never an `rvc.`-prefixed variant (`rvc.slot` and `slot` are *distinct* OTLP
attributes, so a dashboard grouping by `slot` silently drops the prefixed spans).

| Field | Type / format | Lives on | Rule |
|---|---|---|---|
| `slot` | `u64` | span | duty / attestation / block / sign spans |
| `epoch` | `u64` | span | duty span |
| `validator_index` | `u64` | span/event | not `val_idx`, not `validator` |
| `committee_index` | `u64` | span/event | matches Lighthouse (migration source); not `index` / `CommitteeIndex` |
| `subcommittee_index` | `u64` | span/event | sync-committee contribution lines only |
| `pubkey` | truncated `0x{first10}...{last8}` | span/event | **always** `crypto::logging::TruncatedPubkey` + `%`; never the full key, **even at `trace`** |
| `duty` | enum string (`attestation` / `block` / `aggregate` / `sync_committee` / …) | span | from `crypto::logging::fields::Duty::as_str()` |
| `request_id` | uuid string | span | one per signing / API request, including the :9000 Web3Signer hop |
| `bn_url` | redacted URL | event | **always** `crypto::logging::RedactedUrl` (or `telemetry::config::redact_endpoint`); never raw credentials |
| `head` | truncated root | event | attested head root, via `crypto::logging::TruncatedRoot` |
| `block_root` | truncated root | event | proposed block root, via `crypto::logging::TruncatedRoot` |
| `time_into_slot` | duration / ms | event | Nimbus-style operator timing signal |
| `network` | string | **resource attr** | set **once** in `telemetry::init`; **never** duplicated per event |

### Field rules

- **Spans-first.** Stamp `slot` / `epoch` / `validator_index` / `pubkey` / `duty` / `request_id` /
  `committee_index` on the span once; child events inherit them — do **not** repeat them per event.
- **`network` is a resource attribute**, set once at init. It is intentionally **not** a per-event
  field and **not** a `fields` const.
- **Compile-checked mirror.** `crypto::logging::fields` provides one `&'static str` const per key
  above (plus the `Duty` enum). Using the consts at `record()` / event-macro call sites is **SHOULD**
  (it makes Gate 5 conformance and renames refactor-safe). A `#[instrument(fields(slot = …))]` may
  type the literal `slot` ident — the macro requires a literal there anyway — and still be conformant.
- Per-event fields use `field = value` (e.g. `info!(slot, count, "published attestation")`). Use the
  `%` (Display) and `?` (Debug) specifiers **deliberately and only on non-secret values**.

---

## 3. Secret Redaction Policy (Normative, P0)

Standardize on the existing redaction primitives, **hard-forbid** raw secrets at **every** level
(including `trace`), and enforce it with automated CI gates (§7).

**Forbidden from logs entirely, at every level including `trace` — MUST NOT:**

- BLS **private keys** / secret-key bytes / Shamir shares — concretely the `secret-provider` raw
  key/password carriers (`Zeroizing<[u8; 32]>` / `Zeroizing<String>` in `crates/secret-provider`) and
  the DVT share scalar `ShareInfo.scalar_bytes` (`bin/rvc-signer/src/dvt/types.rs`, which **derives
  `Debug`** — so a `?share` prints the raw bytes; it MUST be `skip`-ped and **never** `?`-formatted).
- **Keystore passwords** and any decryption-password material.
- **Mnemonics** / seed phrases — and **not even their length** (`rvc-keygen`; `bip39::Mnemonic`
  `Display`s to the phrase, so treat the bare type as a sink).
- **Full signing payloads** and **full signatures**; full signing roots. Default is to **omit or
  truncate** via `TruncatedRoot`.
- Raw credentials inside URLs / endpoints.

**Mandated primitives — the *only* sanctioned way to log these values (MUST):**

| Value | Primitive | Renders |
|---|---|---|
| Public key (hex string) | `crypto::logging::TruncatedPubkey` + `%` | `0x{first10}...{last8}` |
| 32-byte root / signature / hash (`&[u8]`) | `crypto::logging::TruncatedRoot` + `%` | `0x{first10hex}...{last8hex}` |
| URL / endpoint (`bn_url`) | `crypto::logging::RedactedUrl` + `%` (the workspace-wide mandate) | `***:***@host` (strips `user:pass@`) |

> `telemetry`'s init-time endpoint redactor `redact_endpoint` renders `***@host` (no `:***`) and is
> telemetry-internal; for the `bn_url` event field use `RedactedUrl`. **Caveat on `TruncatedPubkey`:**
> it is best-effort — on malformed input it emits the value **un-truncated** (a double `0x` prefix
> additionally logs a `warn`; non-ASCII or ≤18-hex inputs fall back silently), so it MUST only ever
> receive canonical public-key hex, never secret material.

**High-risk crates** that get explicit review under this policy: `crypto`, `secret-provider`,
`signer`, the `bin/rvc-signer` :9000 path, and `rvc-keygen` (mnemonics). These crates **MAY** add
logging, but **no** added statement may widen secret exposure.

---

## 4. `#[instrument]` Idioms (Normative)

### R1 — `fields(...)` evaluates **eagerly**, on every call (the most important rule)

Per the `#[instrument]` docs, `fields(...)` expressions are evaluated **at the start of the function
body, on every call, regardless of whether the span's level is enabled.** This is the inverse of the
event macros (`debug!`/`trace!`), whose arguments are lazy and only run when the level is on.

- **MUST NOT** put expensive `Display`/`Debug`/`hex::encode`/`format!` computation in
  `#[instrument(fields(...))]`. A `fields(root = %TruncatedRoot::new(&bytes))` there runs its
  `Display` on **every** call even when the span is disabled.
- **MUST** keep instrument `fields(...)` limited to `Copy` scalars and `&'static str`
  (`duty = %Duty::Attestation.as_str()` is a `&'static str` — fine).
- Put redaction wrappers (`TruncatedRoot`, `TruncatedPubkey`, `RedactedUrl`) on **event-family
  macros** (`debug!`/`trace!`/`info!`), never in an ungated `#[instrument(fields(...))]`.

### Other idioms

- **`skip_all` first.** Any fn taking a secret or a large argument **MUST** use `skip_all` (or
  `skip(...)` the offending args) so the macro never `Debug`-formats them. A bare `#[instrument]` on a
  sign fn is forbidden (Gate 1 / review).
- **`level = "debug"` (or `"trace"`) on hot fns.** Any per-slot / per-validator / per-loop
  instrumented fn **MUST** set an explicit `level` — the default `INFO` would flood the heartbeat
  (the single most common mis-use to audit for, research rule 3).
- **Async correctness.** Never hold a `Span::enter()` guard across an `.await`. Prefer
  `#[instrument]` (or `.instrument(span)`) for async fns. It **is** safe to
  `let _e = span.enter();` inside a `spawn_blocking` closure (no `.await` there) to re-enter the
  parent span on the blocking thread.
- **`enabled!`-guard multi-statement trace work.** Wrap any multi-statement / serialize-to-log work in
  `if tracing::enabled!(tracing::Level::TRACE) { … }` so nothing runs when the level is off (research §D).
- **`err` once.** Use `#[instrument(err)]` to record an error return at most once; do not also log it
  manually at the same layer.
- **Late-bound fields.** A field filled later via `span.record(key, …)` **MUST** be declared at span
  creation (e.g. `slot = tracing::field::Empty`), or the `record()` is **silently dropped** (the #1
  "vanishing attribute" bug). The `%`/`?` sigils do **not** work at a `record()` site — use
  `crypto::logging::record_display` / `record_debug`.

---

## 5. Worked Examples (copy-paste ready)

> The primitives below — `TruncatedRoot`, `crypto::logging::fields`/`Duty`, `new_request_id`,
> `record_display`/`record_debug`, and `telemetry::set_parent_from_headers` — are introduced by issues
> 1.2–1.5 of this initiative (this standard lands first, as the rubric). Until they exist, do **not**
> reach for `hex::encode(full_root)` or a raw `format!` as a stopgap.

### A duty span (spans-first correlation)

```rust
use crypto::logging::fields::{self, Duty};

#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(slot, epoch, validator_index, duty = %Duty::Attestation.as_str())
)]
async fn process_attestation(slot: u64, epoch: u64, validator_index: u64) {
    // every event below inherits slot/epoch/validator_index/duty from the span
    tracing::debug!("evaluating attestation duty");
    // ...
    // `head_root: &[u8]` is the (non-secret) attested head root computed earlier in the duty
    tracing::info!(committee_index, head = %crypto::logging::TruncatedRoot::new(head_root),
        "published attestation");
}
```

### A sign span (secrets skipped; root truncated on the event, not the instrument)

```rust
#[tracing::instrument(level = "debug", name = "sign.attestation", skip_all, fields(slot))]
async fn sign_attestation(&self, secret: &SecretKey, signing_root: &[u8]) -> Signature {
    // signing_root truncated, on the event macro (lazy, zero-alloc when trace is off)
    tracing::trace!(signing_root = %crypto::logging::TruncatedRoot::new(signing_root),
        "computed signing root");
    // ... never log `secret`
}
```

### An `enabled!`-guarded trace dump

```rust
if tracing::enabled!(tracing::Level::TRACE) {
    let framed = serialize_for_log(&response); // only runs when trace is on
    tracing::trace!(bytes = framed.len(), "beacon response framing");
}
```

### The `field::Empty` + `record()` late-bind pattern (the :9000 bridge shape)

```rust
#[tracing::instrument(skip_all, fields(
    otel.kind = "server",
    request_id = tracing::field::Empty,
    slot = tracing::field::Empty,
    pubkey = tracing::field::Empty,
))]
async fn sign(headers: http::HeaderMap, body: SignRequest) -> Response {
    let span = tracing::Span::current();
    telemetry::set_parent_from_headers(&span, &headers); // continue the caller's trace
    let req_id = crypto::logging::new_request_id();
    crypto::logging::record_display(&span, fields::REQUEST_ID, req_id);
    // ... after the body parses:
    crypto::logging::record_display(&span, fields::SLOT, slot);
    crypto::logging::record_display(&span, fields::PUBKEY,
        crypto::logging::TruncatedPubkey::new(&pubkey_hex));
}
```

---

## 6. `info` Heartbeat Shape (Normative)

The `info` stream is the operator liveness signal — **milestones only**, low and constant volume
(research §G). The Lodestar-style split applies: **`Signed…` is `debug`, `Published…` is `info`.**

```text
startup        → info  "rvc starting"                  {version, network, commit}
validators load→ info  "Loaded validator keys"          {count}
BN connect     → info  "connected to beacon node"       {bn_version}
epoch boundary → info  "epoch processed"                 {epoch}
attestation    → debug "Signed attestation"             {slot, pubkey = %TruncatedPubkey}
               → info  "published attestation"           {slot, head = %TruncatedRoot, committee_index}
block proposed → info  "block proposed"                  {slot, block_root = %TruncatedRoot}
slot tick      → info  (optional, once-per-slot)         {slot, time_into_slot}
bn-manager     → warn  "failover"                        {bn_url = %RedactedUrl}

   (duty cache hit/miss, BN selection, slashing inputs → debug ; wire framing + per-item loops → trace)
```

Every milestone line carries `slot` (or `epoch`) so it correlates to the duty trace. `time_into_slot`
is the Nimbus-style timing signal on the slot tick / publish lines.

---

## 7. Enforcement (the safety net)

Conformance is enforced by fail-closed CI gates (introduced across this initiative — until each lands,
the rule is review-enforced); secret redaction is defense-in-depth across three of them. A PR **MUST**
be green on all that apply:

```text
Gate 1  cargo clippy -D warnings  → disallowed-methods bans the PATH-QUALIFIED secret sinks
                                     (secrecy::ExposeSecret::expose_secret, SecretKey::raw_bytes,
                                      SecretKey::to_bytes) — never the public-key / SSZ `to_bytes`
Gate 2  gitleaks                  → source tree + an emitted trace-level log sample, 0 findings
Gate 3  cargo nextest             → captured-subscriber tests: raw secret ABSENT, truncated/redacted form PRESENT,
                                     events fire at the intended level with the canonical fields, late-bound record() lands
Gate 4  cargo nextest             → counting-allocator: a disabled debug!/trace! performs zero incremental allocation
Gate 5  cargo nextest             → emitted field keys conform to the §2 registry (BLOCKING as of issue 5.2)
                                     — enforced over a CURATED 16-event hot-path set, NOT full 23-crate breadth
Gate 6  cargo nextest             → architecture DAG stays acyclic; the one new edge rvc-signer-bin → rvc-telemetry is allowed
```

Standing invariant at every merge: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`. **Never**
`cargo test --workspace` (it deadlocks in this workspace; `nextest` is the runner of record).
