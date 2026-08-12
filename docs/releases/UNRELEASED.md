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
- ADR-009: clap defaults no longer clobber TOML when flags are absent (nine fields become Option).
