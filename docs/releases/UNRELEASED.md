# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## Deprecations

### gRPC healthz endpoint deprecated — migrate probes to metrics `/livez` and `/readyz`

The gRPC **healthz** RPC on `{grpc_address}:{grpc_port}` (the healthz-only
DutyTracker tonic server) is **deprecated** and will be **removed in a future
release** (at least one release after this note ships).

**This release starts the deprecation window** for that removal.

**Probe mapping (do not swap these):**

| Probe kind | Endpoint | Semantics |
|------------|----------|-----------|
| **Liveness** | `GET /livez` on the metrics HTTP server | Always process-up (`200 ok`) — closest match to legacy gRPC healthz |
| **Readiness** | `GET /readyz` on the metrics HTTP server | Real readiness: fails (`503 not ready`) until beacon is connected, at least one validator is loaded, and the slashing DB is initialized |

**Do not use `/readyz` as a liveness probe** — readiness can fail during BN blips or early startup and would restart the pod in a loop. gRPC healthz was always `status: true` (process-up only); `/livez` is the replacement for that behavior.

`/health` remains available (JSON status) but is not the Kubernetes liveness/readiness pair; prefer `/livez` + `/readyz`. Prefer those over `/health` for probes (they return plain text only).

**Metrics bind defaults (probe reachability):**

- Default bind is **loopback** (`metrics_address` = `127.0.0.1`, `metrics_port` = `8080`).
- Probes from outside the process namespace (typical Kubernetes kubelet) need a bind the probe source can reach (often pod IP / `0.0.0.0` with appropriate network policy).
- Non-loopback metrics binds require the existing opt-in env var
  `RVC_METRICS_ALLOW_NON_LOOPBACK=true`; the same listener also serves
  `/metrics` and `/health` — restrict scrape/probe sources accordingly.

**Copy-pasteable Kubernetes probes** (set `port` to your `metrics_port`; default `8080`):

```yaml
livenessProbe:
  httpGet:
    path: /livez
    port: 8080   # metrics_port — must reach metrics_address from the probe source
  initialDelaySeconds: 10
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /readyz
    port: 8080   # metrics_port
  initialDelaySeconds: 5
  periodSeconds: 5
```

**Probe-migration checklist (operators):**

- [ ] Does any Kubernetes `livenessProbe` / `readinessProbe` target the **gRPC**
      port (`grpc_port`, default 50051) or the gRPC Healthz RPC?
- [ ] Does any external monitor, blackbox exporter, or load-balancer health check
      hit the gRPC port instead of the metrics HTTP port?
- [ ] Do any Docker / Compose `healthcheck` commands call the gRPC surface?
- [ ] After migrating: **liveness → `/livez`**, **readiness → `/readyz`**, both on
      **metrics** `port` (not gRPC). Never put `/readyz` on the liveness probe.
- [ ] Is the metrics bind reachable from the probe source? Default is loopback
      only; non-loopback needs `RVC_METRICS_ALLOW_NON_LOOPBACK=true` and should
      be network-restricted (opening the port also exposes `/metrics` and `/health`).

**Note:** No probe dependency on the gRPC healthz endpoint has been verified
from inside this repository. Whether production deployments target it is
unknown here; the deprecation window is the discovery mechanism. If you rely
on gRPC healthz, migrate before the removal release.

**Unchanged this release:** `grpc_address` and `grpc_port` still work; the
endpoint still answers. Disposal of those knobs is deferred to the removal
release.

---

## Config: `--help` presentation (defaults unchanged)

On **promoted / section knobs** — the ADR-009 fields that lost clap
`default_value` (e.g. `--metrics-port`) — `rvc start --help` no longer
prints clap's `[default: 8080]` annotation. The numeric and string
defaults themselves are **unchanged**; they now live in the flag doc
comments (and in `Config::default()`), so clap treats an absent flag as
"not supplied" rather than as the default value.

**CLI-only flags are not in that set.** `--log-format` has no
config-file knob and still prints clap's `[default: pretty]`. The other
three CLI-only args (`--enable-log-reload`, `--strict-permissions`,
`--strict-slashing-semantics`) stay CLI-only too; they do not print a
clap `[default:]` block. Do not assume every `[default: …]` line is
gone from `--help`.

**Before** (clap invented the default and printed it on Config knobs):

```text
      --metrics-port <METRICS_PORT>
          Port for the metrics HTTP server

          [default: 8080]
```

**After** (same default, now in the doc comment; clap prints no `[default:]`
on this flag):

```text
      --metrics-port <METRICS_PORT>
          Port for the metrics HTTP server (default: 8080)
```

`--flag` strings are unchanged. The `--help` move is presentation only.

**vs v0.7.0 (ADR-009, already shipped):** an absent flag **used to**
clobber the file. With `metrics_port = 9090` and no `--metrics-port`,
v0.7.0 bound **8080** (clap's invented default). ADR-009 already fixed
that precedence; this phase did not change it. A TOML
`metrics_port = 9090` with no `--metrics-port` still binds **9090**.

---

## Config: TOML section tables (flat spelling still accepted)

The validator-client config file now has section tables — the existing groups
(`[keymanager]`, `[tracing]`, `[grpc_signer]`, `[builder_limits]`,
`[monitoring]`, `[proposer_config]`, `[logfile]`) plus the newly documented
`[beacon]`, `[server]`, `[network]`, `[safety]`, `[slashing]`, and `[keys]`.

**The flat spelling still works and is not being removed.** Existing operator
files need no rewrite. Nested tables are the documented form going forward;
both spellings are valid and will stay valid.

**Before** — flat keys (corpus fixture
`crates/rvc/tests/fixtures/config/flat_legacy_full.toml`):

```toml
tracing_endpoint = "http://wire-otel:4318"
tracing_exporter = "gcp"
tracing_sample_rate = 0.37
tracing_max_queue_size = 3333
tracing_max_export_batch_size = 444
```

**After** — the same knobs as a section table (corpus fixture
`crates/rvc/tests/fixtures/config/nested_full.toml`):

```toml
[tracing]
endpoint = "http://wire-otel:4318"
exporter = "gcp"
sample_rate = 0.37
max_queue_size = 3333
max_export_batch_size = 444
```

Those two fixtures parse to the same `Config`
(`nested_tables_match_flat_legacy_snapshot` in
`crates/rvc/tests/config_wire_parity.rs`).

### Collision rule: **flat-wins**

If a file sets **both** spellings of the same logical field to *different*
values, the **flat** key wins. That rule has been in force since the first
nested-group migration (v0.7.0) and is preserved. Corpus fixture
`crates/rvc/tests/fixtures/config/collision.toml` pins it:

```toml
tracing_endpoint = "http://flat-otel:4318"

[tracing]
endpoint = "http://nested-otel:4318"
```

The loaded config uses `http://flat-otel:4318`
(`flat_key_wins_over_nested_table` in
`crates/rvc/tests/config_wire_parity.rs`). Operators with existing flat files
keep working even if an example snippet later adds a nested table beside them.

---

## Config: no knob removed, renamed, or re-defaulted

**No operator knob was removed, renamed, or given a new default.** The
collapse is one declaration per knob, not a schema break.

Evidence is the parity harness `crates/rvc/tests/config_wire_parity.rs`:
`every_knob_appears_in_the_parity_corpus` asserts the full 69-knob set, and
`flat_legacy_keys_still_parse` / `nested_tables_match_flat_legacy_snapshot`
require the pre-migration snapshots to stay byte-identical. If a knob had
been dropped, renamed, or re-defaulted, that suite would fail.

---

## Config: four BN timeouts now settable from the file

`--block-production-timeout`, `--attestation-timeout`, `--aggregate-timeout`,
and `--duty-fetch-timeout` were CLI-only. They now also load from the config
file (CLI still wins). Defaults are unchanged: they still come from
`bn_manager::OperationTimeouts::default()` (3s / 4s / 2s / 10s).
`--aggregate-timeout` still sets both aggregate fetch and aggregate submit.

Corpus fixture `crates/rvc/tests/fixtures/config/beacon_timeouts.toml` (the
values are non-default on purpose — it is a parse/round-trip fixture, not a
recommended production config):

```toml
[beacon]
block_production_timeout = 11
attestation_timeout = 12
aggregate_timeout = 13
duty_fetch_timeout = 14
```

The same four keys also parse as top-level flat keys (`block_production_timeout`,
…). A value of `0` is rejected from both the file and the CLI.

---

## Slashing: ADR-005 does not deliver G6 on the VC path

ARCH-P1-5 (`reserve_then_sign`) shortens the slashing-DB critical section on
the **signer-server** path. It does **not** make slashable signing scale to
the target validator count on the validator-client path. Attestation in
`crates/rvc/src/orchestrator/attestation.rs` is still a sequential
`for duty in duties { … .await }` loop; 200 keys × 200 ms remote-sign
latency is **40 s (ten mainnet slots) with a free slashing DB**. VC-path
attestation concurrency is a separate, unscheduled requirement. Do not read
this cycle as delivering G6.
