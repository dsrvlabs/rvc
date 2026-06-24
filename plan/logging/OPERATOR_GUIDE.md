# rs-vc Operator Guide — Reading the Log Stream & OTLP Traces

> **Audience: SREs / operators running `rvc` (the validator client) and `rvc-signer`
> (the remote signer).** This is the operator-facing counterpart to
> [`STANDARD.md`](./STANDARD.md) (the author/reviewer rubric). It teaches you to read the
> rs-vc log stream, dial verbosity, follow one duty or signing request end to end, and
> alert on the absence of the healthy `info` heartbeat.
>
> For the field taxonomy / level rules themselves, this guide **links to**
> [`STANDARD.md`](./STANDARD.md) rather than restating it. For the CLI flags that turn
> these knobs on, see [`docs/running-guide.md`](../../docs/running-guide.md); this guide
> deepens that material, it does not duplicate the flag tables.

---

## 1. Default levels & precedence

Both binaries default to **`info`** and share **one** filter implementation, so they
**cannot drift** on default level or precedence: each routes its subscriber init through
`telemetry::env_filter_or("info")` (`crates/telemetry/src/init.rs:147`, ADR-003;
`bin/rvc/src/main.rs:782`, `bin/rvc-signer/src/main.rs:250`). This is the reconciliation
that landed in Phase 3.

**`info` is the production default and is safe to leave on.** It is the operator
heartbeat — low, constant volume regardless of how many validators are loaded (see §5).

**Precedence — `RUST_LOG` always wins over the configured default / `--log-level`:**

| Source | Effect |
|---|---|
| `RUST_LOG` set to ≥1 valid directive | **Wins entirely.** Overrides `--log-level` / `log_level` config / the `info` default. |
| `RUST_LOG` unset, empty (`""`, `","`, whitespace), or malformed (`rvc=notalevel`) | Falls back to the default (`info` in production) — logging **never goes dark** on a `RUST_LOG=` style misconfig in a Dockerfile/k8s manifest. |
| `RUST_LOG=off` (explicit) | Honored — you asked for silence. Only *accidental*-empty falls back. |

The fallback behavior is deliberate and tested (`crates/telemetry/src/init.rs:113-164`):
an accidental "verbose off" never means "silent."

**Compile-time level floor (ADR-001).** The release build is compiled with
`release_max_level_debug`: **`trace!` statements are compiled OUT of `--release` binaries.**
Consequences for an operator:

- `debug` is **runtime-switchable** in a normal release build — `RUST_LOG=...=debug`
  works on the binary you already deployed.
- `trace` requires a **debug/test build** (`cargo build` without `--release`). Setting
  `RUST_LOG=...=trace` on a release binary raises the *filter* to trace, but the release
  binary contains no `trace!` callsites to emit, so you see nothing new. To get wire-level
  detail, run a debug build in a controlled environment — never in production (trace is the
  highest-volume level; see [`STANDARD.md` §1](./STANDARD.md#1-level-taxonomy-normative)).

---

## 2. `RUST_LOG` recipes (copy-paste)

`RUST_LOG` directives are `target=level` pairs, comma-separated. A bare level
(`RUST_LOG=debug`) sets the global floor. The `target` is the **compiled crate name**
(hyphens become underscores) optionally followed by a `::module::path`. Whitespace after
commas is tolerated (`warn, rvc=trace` is honored).

> **Target-name reference** (verify against `cargo tree`): the `rvc` binary *and* the
> orchestrator crate both compile as target **`rvc`** (so `rvc=debug` covers both); the
> multi-BN layer is **`rvc_bn_manager`** (package `rvc-bn-manager`); the intra-slot timing
> crate is **`rvc_timing`** (package `rvc-timing`); the signer's HTTP frontend module is
> **`rvc_signer_bin::http_api`**.

```bash
# Everything the rvc binary + orchestrator emit, at debug (per-duty decision points).
RUST_LOG=rvc=debug rvc start

# Quiet globally, but trace the orchestrator while debugging the beacon-node failover layer.
# (trace requires a DEBUG build — see §1. On a release build use =debug for rvc_bn_manager.)
RUST_LOG=rvc=trace,rvc_bn_manager=debug rvc start

# Slot-timing investigation: see the per-slot timing milestones at debug, rest at info.
RUST_LOG=info,rvc_timing=debug rvc start

# rvc-signer: trace the :9000 Web3Signer HTTP path (request framing, dispatch) only.
# Run a DEBUG build of rvc-signer for trace; =debug works on a release build.
RUST_LOG=warn,rvc_signer_bin::http_api=trace rvc-signer serve ...

# Two directives, hand-typed with a space after the comma (tolerated, not discarded):
RUST_LOG=warn, rvc=debug rvc start
```

These match the directive style already in
[`docs/running-guide.md:319-327`](../../docs/running-guide.md). `RUST_LOG` overrides
`--log-level` (§1).

---

## 3. Canonical fields reference

Every structured field rs-vc emits comes from the **canonical registry** —
`crypto::logging::fields` (`crates/crypto/src/logging.rs:110-149`), the compile-checked
mirror of [`STANDARD.md` §2](./STANDARD.md#2-canonical-structured-field-registry-normative).
**`snake_case`, no `rvc.` prefix, no synonyms** (never `val_idx`, `validator`, `index`).
Correlation ids (`slot` / `epoch` / `validator_index` / `pubkey` / `duty` / `request_id` /
`committee_index`) live **once** on the duty/request span and inherit into every child
event — so you grep one of them and get the whole trace.

| Field | Operator meaning |
|---|---|
| `slot` | The beacon slot the line pertains to. Your primary correlation key. |
| `epoch` | The epoch (duty span). |
| `validator_index` | The validator a duty/sign line is for. |
| `committee_index` | Attestation committee index (matches Lighthouse). |
| `subcommittee_index` | Sync-committee contribution lines only. |
| `pubkey` | Validator public key — **always truncated** `0x{first10}...{last8}`. |
| `duty` | What kind of duty: `attestation` / `block` / `aggregate` / `sync_committee` / `sync_contribution` / `validator_registration` / `voluntary_exit`. |
| `request_id` | UUID correlating one signing / API request end to end, **including the :9000 hop** (§4). |
| `bn_url` | Beacon-node URL — **always redacted** (`***:***@host`, credentials stripped). |
| `head` | Attested head root — truncated `0x{first10hex}...{last8hex}`. |
| `block_root` | Proposed block root — truncated, same form. |
| `time_into_slot` | Nimbus-style timing signal (ms into the slot) on publish / slot-tick lines. |
| `network` | The chain (`mainnet`/`hoodi`/…). A **resource attribute** set once at init — it is **not** a per-event field, so don't grep events for it; in OTLP it is `network.name` on the resource. |

**Redaction is unconditional — even at `trace`** ([`STANDARD.md` §3](./STANDARD.md#3-secret-redaction-policy-normative-p0)):

- **`pubkey` is always truncated** to `0x{first10}...{last8}` (via
  `crypto::logging::TruncatedPubkey`). The full key never appears.
- **`bn_url` and any endpoint are always redacted** — `user:pass@` becomes `***:***@`
  (via `crypto::logging::RedactedUrl`). Raw credentials never appear in a log line.
- **Roots / signatures are truncated** to `0x{first10hex}...{last8hex}` (via
  `TruncatedRoot`); a full signing root or signature is never logged.
- **Secret keys, keystore passwords, mnemonics, full signing payloads** are forbidden at
  every level. If you ever see one, it is a bug — file it against the redaction gates.

So raising verbosity to `debug`/`trace` to chase an issue **never** exposes a key or a
credential. That is a hard P0 invariant, enforced by CI gates
([`STANDARD.md` §7](./STANDARD.md#7-enforcement-the-safety-net)).

> **What's enforced (and what isn't).** Field-name conformance to this registry is a
> **blocking** CI gate (Gate 5, issue 5.2) — but only over a **curated 16-event hot-path
> set** (the attestation/block/sign/duty lines you actually grep), **not** every log line in
> all 23 crates. So a green build guarantees the *covered* hot-path events use the canonical
> spellings above; it is **not** an exhaustive promise that no crate anywhere ever emits a
> stray key. If you spot a non-canonical key on some rarely-hit line, it is a normalization
> gap to file, not a contract violation — the covered set is the enforced floor, widening it
> to full breadth is future work.

---

## 4. Following a `request_id` (end to end, including the :9000 hop)

Every signing / API request to `rvc-signer`'s `:9000` Web3Signer HTTP frontend gets a
`request_id` that follows it from the calling client (Lighthouse / Prysm), through the
signer's handler, onto the audit line. Two mechanisms carry it across the boundary
(`bin/rvc-signer/src/http_api/routes.rs:56-110`):

1. **`x-request-id` header.** If the caller sends an `x-request-id` (bounded: non-empty,
   ≤128 ASCII-graphic chars), the signer **reuses** it as the `request_id`; otherwise it
   mints a fresh UUID v4 (`crypto::logging::new_request_id`). Either way the signer
   **echoes `x-request-id` back** on the response, so the caller can stitch both sides.
2. **W3C `traceparent`.** The handler span is parented from the inbound `traceparent`
   header (`telemetry::set_parent_from_headers`,
   `crates/telemetry/src/propagation.rs:66`) **before** it is entered, so the signer's
   spans join the **same OTLP trace** as the calling client. A missing/malformed
   `traceparent` degrades gracefully to a root span (no panic).

### Grepping the log stream

The `request_id` is a span field on the `sign` span, so it inherits onto the audit line
emitted per request (`bin/rvc-signer/src/audit/log.rs:32` — success at `info`, every
rejection at `warn`). Grep one id to get that request's lines:

```bash
# Pull every line for one request across the signer logs.
grep 'request_id=2f8e1c40-9a7b-4c1e-8d2a-1b3c4d5e6f70' rvc-signer.stdout.log
```

A representative **redacted** success excerpt (pretty format; pubkey truncated, no root /
signature / payload anywhere):

```text
2026-06-25T14:02:11Z  INFO sign{request_id=2f8e1c40-9a7b-4c1e-8d2a-1b3c4d5e6f70 slot=7806432 duty=attestation pubkey=0x93247f2209...611df74a}: rvc_signer_bin::http_api: sign request audit audit=true rpc=sign_attestation result=success backend=basic duration_ms=3 client_cn=lighthouse-vc-1
```

Read it as: span `sign` carries the correlation fields (`request_id`, `slot`, `duty`,
`pubkey` — all inherited); the event is the one-per-request **audit** line carrying only
metadata (`rpc` type, `result`, `backend`, `duration_ms`, peer `client_cn`). A rejection
looks identical but at `WARN` with `result=double_proposal` (or another reason). The
caller (Lighthouse/Prysm) logs the same id because the signer echoed `x-request-id`.

### OTLP-backend equivalent

In your tracing backend (Jaeger / Tempo / Grafana / Cloud Trace) you don't grep — you
**filter by attribute** or open the trace:

- Filter spans by the `request_id` span attribute
  (`request_id = 2f8e1c40-9a7b-4c1e-8d2a-1b3c4d5e6f70`) to find the signer's `sign` span.
- Because of `traceparent` continuity, the caller's span and the signer's `sign` span
  share **one trace id** — open that trace to see both sides of the `:9000` hop as a
  single waterfall. Filter the whole view to one chain with the `network.name` resource
  attribute (§3).

---

## 5. The `info` heartbeat — what healthy looks like

The `info` stream is the **operator liveness signal: milestones only**, low and constant
volume no matter how many validators are loaded. Anything that scales with validator count
or fires per-loop is `debug`/`trace`, never `info`
([`STANDARD.md` §1](./STANDARD.md#1-level-taxonomy-normative)). The Lodestar-style split
applies: **`Signed…` is `debug`, `Published…` is `info`** — so you alert on the
*published* milestones, the proof a duty actually went out.

A healthy `rvc` `info` stream is a recurring narrative
([`STANDARD.md` §6](./STANDARD.md#6-info-heartbeat-shape-normative)):

```text
info  "rvc starting"                {version, network, commit}     ← once, at startup
info  "Loaded validator keys"       {count}                        ← once
info  "connected to beacon node"    {bn_version}                   ← once / on reconnect
info  "epoch processed"             {epoch}                        ← every epoch boundary
info  "published attestation"       {slot, head, committee_index}  ← every assigned slot
info  "block proposed"              {slot, block_root}             ← on a proposer duty
info  (sync-committee msg / contribution)  {slot, subcommittee_index}
info  "validator registration"                                     ← builder registration
info  (optional per-slot tick)      {slot, time_into_slot}
warn  "failover"                    {bn_url}                       ← degraded but progressing
```

**Alert on ABSENCE, not just on errors.** The actionable signals are:

- No `"epoch processed"` for more than one epoch (~6.4 min on mainnet) → the orchestrator
  is stuck.
- An assigned slot with no `"published attestation"` → a missed attestation.
- `"connected to beacon node"` not re-appearing after a `warn "failover"` → no healthy BN.

Recurring `warn "failover"` means the multi-BN layer is degrading-but-progressing — worth
investigating, not yet an outage. `error` means an intended action did **not** complete
(all BNs unreachable; sign rejected by slashing protection; keystore decrypt failed) — page
on it.

To enrich the heartbeat with the per-duty *why* without flooding it, raise just one target
to `debug` (§2), e.g. `RUST_LOG=info,rvc_bn_manager=debug` to see BN-selection decisions
while the rest stays at the milestone level.

---

## 6. Pretty vs JSON output

**Pretty (human-readable) is the default** for both binaries — the `tracing_subscriber`
`fmt` layer renders the colorized, span-scoped lines shown in §4 and §5. This is what you
get on stdout/stderr with no extra configuration, and it is the right choice for
interactive debugging and `grep`.

**JSON is the sanctioned profile for log aggregation** (shipping to Loki / Elasticsearch /
a SIEM, where a structured parser beats a regex). One JSON object per event, with the
canonical fields (§3) as keys — ideal for indexing by `request_id`, `slot`, or
`validator_index`.

> **Status: JSON output is _planned_, not yet shipped.** The JSON aggregation profile is
> issue **5.5 (P2-3)** of this initiative and has **not landed**. Until it does, both
> binaries emit pretty output only; for machine ingestion today, parse the pretty stream or
> rely on the OTLP trace pipeline (§4). **This section will be filled in by 5.5** with the
> flag/config to select JSON and a sample object.

---

## 7. File logging more verbose than the console (ADR-004)

A common operator setup: keep the **console at `info`** (clean heartbeat for humans / your
log shipper) while writing a **more verbose `debug` file** to disk for post-incident
forensics. ADR-004 supports this for `rvc`.

**`rvc` (validator client) — supported.** The file appender filters with its **own** level,
independent of the console. Set the file level via `logfile_level` (config) — it defaults to
`log_level` if omitted (`bin/rvc/src/main.rs:936`). Point `logfile` at a path to enable the
appender (`build_file_layer_config`, `bin/rvc/src/main.rs:924`).

```toml
# config.toml — console stays info; the on-disk file captures debug.
log_level      = "info"     # console / RUST_LOG default
logfile        = "/var/log/rvc/rvc.log"
logfile_level  = "debug"    # the file layer's independent level
```

The console keeps its low-volume `info` heartbeat; `/var/log/rvc/rvc.log` carries the
`debug` decision points for when you need them. (`RUST_LOG`, if set, still governs the
console filter per §1.)

**`rvc-signer` (remote signer) — console-only; file == console.** rvc-signer is
intentionally **console-only**: it does **not** wire the file appender, so it has **no
independent file level** — there is nothing to set more verbose than the console
(`bin/rvc-signer/src/main.rs:234-250`). Collect rvc-signer logs from the process's standard
streams (e.g. via your container runtime / `journald`) and set verbosity with `RUST_LOG`
(§2). This is the documented Phase-3 (issue 3.5) status: the appender is *capable* of an
independent file level, but exposing it for the signer is deferred rather than rushed into a
security-sensitive binary. ADR-004's "file more verbose than console" therefore applies to
`rvc`, not `rvc-signer`.

---

## See also

- [`STANDARD.md`](./STANDARD.md) — the normative level taxonomy, canonical field registry,
  redaction policy, and `#[instrument]` idioms (the author/reviewer rubric this guide
  mirrors for operators).
- [`docs/running-guide.md`](../../docs/running-guide.md) — the `--log-level`, `RUST_LOG`,
  and `--tracing-*` CLI flags and example invocations.
