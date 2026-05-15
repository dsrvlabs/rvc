# Issue Estimates: Tiers 2–5 — Safety, Operations, Advanced & Experimental

## Estimation Approach

- **Point scale:** 1 (half day) / 2 (one day) / 3 (one and a half days) / 5 (two+ days — must be justified)
- **Target scope:** Every issue completable in 1–2 days by a single code-writer
- Points reflect relative effort including coding, testing, review, and integration
- Two parallel workstreams: **Stream A** and **Stream B**
- Each tier has its own parallel plan; tiers are executed sequentially

## Tier Files

| File | Tier | Issue Count | Total Points |
|------|------|-------------|-------------|
| [02-tier2-safety.md](./02-tier2-safety.md) | Tier 2: Safety & Reliability | 11 | 24 |
| [03-tier3-operations.md](./03-tier3-operations.md) | Tier 3: Operational Excellence | 14 | 29 |
| [04-tier4-advanced.md](./04-tier4-advanced.md) | Tier 4: Advanced / Differentiating | 16 | 36 |
| [05-tier5-experimental.md](./05-tier5-experimental.md) | Tier 5: Future / Experimental | 15 | 39 |
| **Total** | | **56** | **128** |

## Feature-to-Issue Mapping

| Feature | FR# | Tier | Issues | Points |
|---------|-----|------|--------|--------|
| Builder Circuit Breakers | FR-1 | 2 | T2.1, T2.2, T2.3 | 7 |
| Emergency Attestation Disable | FR-2 | 2 | T2.4, T2.5 | 4 |
| Slashed Validator Auto-Shutdown | FR-3 | 2 | T2.6, T2.7 | 4 |
| Keystore File Locking | FR-4 | 2 | T2.8, T2.9, T2.10 | 5 |
| Tier 2 Integration Tests | — | 2 | T2.11 | 4 |
| Dedicated Proposer Nodes | FR-5 | 3 | T3.1, T3.2 | 4 |
| Configurable Broadcast Topics | FR-6 | 3 | T3.3, T3.4 | 3 |
| Remote Monitoring Endpoint | FR-7 | 3 | T3.5, T3.6, T3.7 | 5 |
| Log File Rotation & Compression | FR-8 | 3 | T3.8, T3.9, T3.10 | 6 |
| Proposer Config from URL | FR-9 | 3 | T3.11, T3.12, T3.13 | 6 |
| Tier 3 Integration Tests | — | 3 | T3.14 | 5 |
| Multi-Strategy Block Selection | FR-10 | 4 | T4.1, T4.2, T4.3, T4.4 | 8 |
| Role-Based BN Assignment | FR-11 | 4 | T4.9, T4.10, T4.11 | 6 |
| Validator Registration Batching | FR-12 | 4 | T4.12, T4.13 | 3 |
| Pre-Signed Voluntary Exit Storage | FR-13 | 4 | T4.14, T4.15 | 5 |
| Health-Based BN Tier Selection | FR-14 | 4 | T4.5, T4.6, T4.7, T4.8 | 8 |
| Tier 4 Integration Tests | — | 4 | T4.16 | 6 |
| Verifying Web3Signer | FR-15 | 5 | T5.1, T5.2, T5.3, T5.4 | 9 |
| Native Relay Integration | FR-16 | 5 | T5.5, T5.6, T5.7, T5.8, T5.9 | 12 |
| Gnosis Chain Support | FR-17 | 5 | T5.10, T5.11 | 5 |
| SSE Log Streaming API | FR-18 | 5 | T5.12, T5.13, T5.14 | 5 |
| Tier 5 Integration Tests | — | 5 | T5.15 | 8 |

## Cross-Tier Parallel Execution Plan

Each tier runs with 2 parallel streams. Tiers are sequential (Tier 2 completes before Tier 3 starts, etc.).

| Tier | Duration (2 devs) | Points | Issues |
|------|-------------------|--------|--------|
| Tier 2: Safety | ~7 days | 24 | 11 |
| Tier 3: Operations | ~8 days | 29 | 14 |
| Tier 4: Advanced | ~10 days | 36 | 16 |
| Tier 5: Experimental | ~11 days | 39 | 15 |
| **Total** | **~36 days** | **128** | **56** |

## Cross-Tier Dependency Map

```text
Tier 2                          Tier 3                    Tier 4                        Tier 5
──────                          ──────                    ──────                        ──────

T2.1 CircBreaker types
 ├──▶ T2.2 Block integration ──────────────────────────▶ T4.3 BuilderOnly mode ──────▶ T5.8 Relay integration
 └──▶ T2.3 CLI/config/metrics

T2.4 AttDisable AtomicBool
 └──▶ T2.5 API endpoint

T2.6 Slashed monitor
 └──▶ T2.7 Metrics/config

T2.8 Keystore lock
 ├──▶ T2.9 CLI flag
 └──▶ T2.10 Tests

T2.11 Tier 2 integration ═══╗
                              ║
                         T3.1 Proposer nodes ───────────▶ T4.9 Role-based BN (subsumes)
                         T3.3 Broadcast topics
                         T3.5 Monitoring types
                          └──▶ T3.6 Push task
                         T3.8 Log rotation
                          └──▶ T3.9 Compression
                         T3.11 URL config schema
                          └──▶ T3.12 Refresh task
                         T3.14 Tier 3 integration ═══╗
                                                      ║
                                                 T4.5 Health tiers
                                                  └──▶ T4.6 synced_indices ──▶ T4.9 Role BN
                                                       └──▶ T4.7 Duty routing
                                                 T4.1 Block sel types
                                                  ├──▶ T4.2 ExecOnly/MaxProfit
                                                  └──▶ T4.3 BuilderOnly/Always (needs T2.2)
                                                 T4.12 Reg batching
                                                 T4.14 Prepare exit
                                                  └──▶ T4.15 Submit exit
                                                 T4.16 Tier 4 integration ═══╗
                                                                              ║
                                                                         T5.1 Merkle types
                                                                          ├──▶ T5.2 Proof gen
                                                                          └──▶ T5.3 Proof verify
                                                                         T5.5 Relay crate
                                                                          └──▶ T5.6 Reg/header
                                                                               └──▶ T5.7 Blinded blocks
                                                                                    └──▶ T5.8 Integration (needs T2.2)
                                                                         T5.10 Gnosis enum
                                                                          └──▶ T5.11 Slot audit
                                                                         T5.12 SSE layer
                                                                          └──▶ T5.13 SSE endpoint
                                                                         T5.15 Tier 5 integration
```

### Critical Cross-Tier Dependencies

| Source | Target | Reason |
|--------|--------|--------|
| T2.2 (Circuit breaker integration) | T4.3 (BuilderOnly mode) | `builderonly` must interact with circuit breaker state |
| T2.2 (Circuit breaker integration) | T5.8 (Native relay integration) | Relay path must respect circuit breakers |
| T3.1 (Proposer nodes) | T4.9 (Role-based BN) | FR-11 subsumes FR-5; role-based BN generalizes proposer nodes |
| T4.6 (synced_indices refactor) | T4.9 (Role-based BN) | Role filtering composes with tier-based filtering in synced_indices |

### Sync Points

- **End of Tier 2** (Day 7): All safety features pass integration tests. Verify `cargo test` passes.
- **End of Tier 3** (Day 15): All operational features functional. Verify proposer nodes, broadcast, monitoring, log rotation, URL config.
- **End of Tier 4** (Day 25): All advanced features functional. Verify block selection modes, health tiers, roles, batching, pre-signed exits.
- **End of Tier 5** (Day 36): All experimental features functional behind feature gates. Full regression suite.

## Risk Flags

| Issue | Risk | Mitigation |
|-------|------|------------|
| T2.2 Circuit breaker integration | Modifying the block production hot path — must not add latency | Atomic-only checks (< 1ns on x86). Profile before/after. |
| T3.8 Log rotation (size-based) | `tracing-appender` doesn't support size-based rotation — using `logroller` instead | `logroller` is lower-adoption. Wrap with `non_blocking` for safety. Fallback: custom `MakeWriter`. |
| T4.3 BuilderOnly + circuit breaker | Critical interaction: DVT missed proposal is by design but must be clearly communicated | Comprehensive error logging. Document DVT implications in operator guide. |
| T4.6 synced_indices refactor | Core BnManager method used by all duty paths — regression risk | Backwards-compatible default (existing callers pass Synced). Extensive unit tests before integration. |
| T5.8 Native relay integration | New block production path alongside existing — complexity risk | Feature-gated. Mutual exclusivity with mev-boost. Share circuit breaker code. |
| T5.11 Gnosis slot time audit | Hardcoded 12s assumptions across 5+ crates — high grep/fix surface | Systematic audit: grep for `SECONDS_PER_SLOT`, `12`, `384`, `32`. Parameterized tests. |
| T5.3 Verifying signer | Changes `ValidatorSigner` trait — affects all signing paths | Add `sign_block_with_verification()` with default fallback. Feature-gated. |

## File Ownership Map

### Stream A — Tiers 2-5

| Directory / Module | Notes |
|--------------------|-------|
| `crates/builder/src/circuit_breaker.rs` | New file — circuit breaker state |
| `crates/block-service/src/` | Block selection modes, circuit breaker integration |
| `crates/rvc/src/config/types.rs` | CLI flags and config for all features (both streams share, append-only) |
| `crates/metrics/src/definitions.rs` | Prometheus metrics for all features (both streams share, append-only) |
| `crates/rvc/src/prepare_exit.rs` | Pre-signed exit CLI |
| `crates/rvc/src/submit_exit.rs` | Submit exit CLI |
| `crates/rvc/src/config_url.rs` | URL config fetcher |
| `crates/validator-store/src/` | Per-validator config fields |
| `crates/signer/src/verification.rs` | Verifying signer types |
| `crates/rvc/src/config/network.rs` | Gnosis network support |

### Stream B — Tiers 2-5

| Directory / Module | Notes |
|--------------------|-------|
| `crates/rvc/src/orchestrator/coordinator.rs` | Attestation disable, slashing monitor (Stream A also touches for circuit breaker — sequential in Tier 2) |
| `crates/keymanager-api/src/` | API endpoints (attestation disable, SSE logs, pre-signed exit) |
| `crates/rvc/src/slashing_monitor.rs` | New file — slashing monitor |
| `crates/rvc/src/monitoring.rs` | New file — beaconcha.in push |
| `crates/telemetry/src/` | Log rotation, SSE layer |
| `crates/bn-manager/src/` | Health tiers, role-based routing, broadcast topics |
| `crates/relay-client/` | New crate — native relay |

## Merge Conflict Hotspots

| File | Touched by | Strategy | Merge Order |
|------|-----------|----------|-------------|
| `crates/rvc/src/config/types.rs` | Almost all issues | Append-only: each issue adds new fields in a dedicated section | Sequential within tier |
| `crates/metrics/src/definitions.rs` | T2.3, T2.5, T2.7, T3.2, T3.7, T4.4, T4.8, T4.13 | Append-only: each issue adds new metrics at end of file | Sequential within tier |
| `crates/rvc/src/orchestrator/coordinator.rs` | T2.2, T2.4, T2.6 | Strict ordering within Tier 2: T2.4 (attestation disable) first, T2.6 (slashing) next, T2.2 (circuit breaker at epoch boundary) last | T2.4 → T2.6 → T2.2 |
| `crates/bn-manager/src/manager.rs` | T3.1, T3.3, T4.6, T4.7, T4.9, T4.10 | Strict ordering: T3.3 (broadcast) → T3.1 (proposer, separate instance) → T4.6 (synced_indices refactor) → T4.7 (duty routing) → T4.9 (roles) → T4.10 (role filtering) | Sequential across Tier 3 → Tier 4 |
| `crates/block-service/src/service.rs` | T2.2, T4.2, T4.3, T5.2, T5.8 | Strict ordering across tiers: circuit breaker first, then block selection modes, then verifying signer, then relay | T2.2 → T4.2 → T4.3 → T5.2 → T5.8 |
| `crates/keymanager-api/src/server.rs` | T2.5, T4.14, T5.13 | Append-only: each adds a new route to the router | Sequential within tier |
| `crates/builder/src/service.rs` | T4.12, T5.8 | Sequential: batching in Tier 4, relay path in Tier 5 | T4.12 → T5.8 |
| `bin/rvc/src/main.rs` | T2.2, T3.1, T3.12 | Strict ordering: each adds construction code in the startup section | T2.2 → T3.1 → T3.12 |

### Conflict Avoidance Patterns

1. **Append-only sections** — Config types and metrics definitions are append-only. Each issue adds fields at the end of the file with a comment marking the feature.
2. **New files preferred** — Most features create new files (circuit_breaker.rs, slashing_monitor.rs, monitoring.rs, config_url.rs, file_appender.rs, sse_layer.rs, verification.rs, relay-client crate). New files cannot conflict.
3. **Strict ordering within shared files** — When multiple issues touch the same method (e.g., `synced_indices()`), they are ordered within the same stream to prevent conflicts.
4. **Tier boundaries as sync points** — Each tier completes before the next starts, ensuring all shared file modifications from the previous tier are merged.
