# Validator Client Comparison: rvc vs. Industry

> Generated: 2026-03-31
> Clients analyzed: Lighthouse (Rust), Prysm (Go), Teku (Java), Nimbus (Nim), Lodestar (TypeScript), Vouch (Go)

---

## Table of Contents

- [Current rvc Feature Coverage](#current-rvc-feature-coverage)
- [Cross-Client Feature Matrix](#cross-client-feature-matrix)
- [Feature Gap Analysis](#feature-gap-analysis)
  - [Tier 1 — Standards Compliance](#tier-1--standards-compliance)
  - [Tier 2 — Safety & Reliability](#tier-2--safety--reliability)
  - [Tier 3 — Operational Excellence](#tier-3--operational-excellence)
  - [Tier 4 — Advanced / Differentiating](#tier-4--advanced--differentiating)
  - [Tier 5 — Future / Experimental](#tier-5--future--experimental)
- [Where rvc Already Leads](#where-rvc-already-leads)
- [Recommended Roadmap](#recommended-roadmap)

---

## Current rvc Feature Coverage

rvc is a production-grade validator client (~73k LOC, 23 crates, 3 binaries) with strong coverage:

| Category | rvc Status | Details |
|----------|-----------|---------|
| Block proposals | Yes | Full 3-phase slot processing |
| Attestations | Yes | With aggregation duties |
| Sync committees | Yes | Messages + contributions |
| Multi-BN failover | Yes | Health scoring (EMA latency + error rate), First/Best/Broadcast strategies |
| BLS signing | Yes | `blst` library, 3-tier CompositeSigner routing |
| Web3Signer | Yes | HTTP remote signing |
| gRPC remote signing | Yes | mTLS via rvc-signer binary |
| Slashing protection | Yes | SQLite, EIP-3076 import/export, 76 conformance tests |
| Doppelganger detection | Yes | 2-epoch monitoring, restart-aware |
| MEV/Builder | Yes | Validator registration, blinded blocks, per-validator boost factor |
| Keymanager API | Yes | Full spec: keystores, remotekeys, fee recipient, gas limit, graffiti, voluntary exit (16 endpoints) |
| Key generation | Yes | rvc-keygen: mnemonic, derive, deposit data, BLS-to-execution, exit |
| DVT | Yes | Shamir Secret Sharing (feature-gated) |
| Per-validator config | Yes | Graffiti, fee recipient, boost factor (TOML, hot-reload) |
| Voluntary exit | Yes | CLI command (`rvc voluntary-exit`) |
| Prometheus metrics | Yes | Port 8080, `/metrics`, `/healthz`, `/livez`, `/readyz` |
| Distributed tracing | Yes | OpenTelemetry (OTLP/HTTP + GCP Cloud Trace), W3C propagation |
| Cloud secrets | Yes | GCP Secret Manager (feature-gated) |
| Networks | Yes | Mainnet, Hoodi, Holesky, Sepolia, Custom |
| Forks | Yes | Phase0, Altair, Bellatrix, Capella, Deneb, Electra, Fulu |
| Docker | Yes | Multi-stage builds, 3 runtime images (rvc, rvc-signer, rvc-keygen) |

---

## Cross-Client Feature Matrix

| Feature | rvc | Lighthouse | Prysm | Teku | Nimbus | Lodestar | Vouch |
|---------|-----|-----------|-------|------|--------|----------|-------|
| **Language** | Rust | Rust | Go | Java | Nim | TypeScript | Go |
| **Block proposals** | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Attestations** | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Sync committees** | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Aggregation** | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Multi-BN failover** | Yes | Yes | Yes | Yes | Yes | Yes | Yes (best-data) |
| **BN health scoring** | EMA | 4-tier | Max checks | Yes | Role-based | Failover | Strategy-based |
| **Dedicated proposer nodes** | No | Yes | No | No | No | No | Yes |
| **Web3Signer** | Yes | Yes | Yes | Yes | Yes | Yes | No (uses Dirk) |
| **gRPC remote signing** | Yes (mTLS) | No | Deprecated | No | No | No | Yes (Dirk) |
| **Slashing protection** | SQLite | SQLite | BoltDB | YAML files | SQLite | Built-in | Delegated to Dirk |
| **EIP-3076 import/export** | Yes | Yes | Yes | Yes | Yes | Yes | No (Dirk) |
| **Doppelganger detection** | Yes | Yes (off) | Yes (off) | Yes (off) | Yes (on) | Yes (off) | No |
| **Builder API / MEV** | Yes | Yes | Yes | Yes | Yes | Yes | Yes (native relay) |
| **Builder boost factor** | Per-validator | Per-validator | Global | Percentage | Percentage | 6 strategies | Per-builder scoring |
| **Builder circuit breakers** | No | Chain health | Yes | No | No | No | No |
| **Keymanager API (keystores)** | Yes | Yes | Yes | Yes | Yes | Yes | No |
| **Keymanager API (remotekeys)** | Yes | Yes | Yes | Yes | Yes | Yes | No |
| **Keymanager API (fee recipient)** | Yes | Yes | Yes | Yes | Yes | Yes | No |
| **Keymanager API (gas limit)** | Yes | Yes | Yes | Yes | No | Yes | No |
| **Keymanager API (graffiti)** | Yes | Yes | No | No | No | Yes | No |
| **Keymanager API (voluntary exit)** | Yes | Yes | No | No | No | No | No |
| **Per-validator graffiti** | TOML + API | YAML + API | File modes | Config + file | CLI flag | YAML + API | Config |
| **Per-validator fee recipient** | TOML + API | YAML + API | JSON/URL | JSON config | API | YAML + API | JSON config |
| **Voluntary exit** | CLI + API | CLI + API | CLI (prysmctl) | CLI | CLI | CLI | No |
| **DVT** | SSS (native) | Obol compatible | Obol compatible | Config overrides | Experimental | Obol compatible | Dirk threshold |
| **Cloud secret management** | GCP | No | No | No | No | No | AWS/GCP (Majordomo) |
| **Prometheus metrics** | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **OpenTelemetry tracing** | OTLP/HTTP + GCP | gRPC | No | No | No | No | Yes |
| **Remote monitoring endpoint** | No | Yes | No | No | No | Yes | No |
| **Log file rotation** | No | Yes | Yes | No | No | No | No |
| **Emergency attestation disable** | No | Yes | No | No | No | No | No |
| **Slashed auto-shutdown** | No | No | No | Yes | No | No | No |
| **Keystore locking** | No | DB lock | No | File lock | No | No | N/A |
| **Broadcast topic control** | No | Yes | No | No | No | No | No |
| **Proposer config from URL** | No | No | Yes | Yes | No | No | No |
| **Pre-signed voluntary exits** | No | No | No | Yes | No | No | No |
| **Role-based BN assignment** | No | No | No | No | Yes | No | No |
| **Verifying Web3Signer** | No | No | No | No | Experimental | No | No |
| **Networks** | 4 + custom | 6 | 5+ | 5+ | 5+ | 5+ | Any |
| **Testnets (Holesky/Sepolia)** | Yes | Yes | Yes | Yes | Yes | Yes | Yes |

---

## Feature Gap Analysis

### Tier 1 — Standards Compliance

> High impact, expected by the ecosystem. Should be prioritized.

#### 1. Extended Keymanager API

**Who has it:** All major clients (Lighthouse, Prysm, Teku, Nimbus, Lodestar)

**What's missing:** rvc only implements `/eth/v1/keystores` and `/eth/v1/remotekeys`. The standard Keymanager API also defines:

| Endpoint | Purpose |
|----------|---------|
| `GET /eth/v1/validator/{pubkey}/feerecipient` | Get fee recipient for a validator |
| `POST /eth/v1/validator/{pubkey}/feerecipient` | Set fee recipient |
| `DELETE /eth/v1/validator/{pubkey}/feerecipient` | Reset fee recipient to default |
| `GET /eth/v1/validator/{pubkey}/gas_limit` | Get gas limit for a validator |
| `POST /eth/v1/validator/{pubkey}/gas_limit` | Set gas limit |
| `DELETE /eth/v1/validator/{pubkey}/gas_limit` | Reset gas limit to default |
| `GET /eth/v1/validator/{pubkey}/graffiti` | Get graffiti for a validator |
| `POST /eth/v1/validator/{pubkey}/graffiti` | Set graffiti |
| `DELETE /eth/v1/validator/{pubkey}/graffiti` | Reset graffiti to default |
| `POST /eth/v1/validator/{pubkey}/voluntary_exit` | Submit voluntary exit |

**Why it matters:** All ecosystem tooling (staking dashboards, automation platforms, Rocket Pool, etc.) expects these endpoints. Without them, rvc cannot be used with standard validator management tooling.

**Implementation note:** rvc already has per-validator fee recipient, graffiti, and boost factor in the `validator-store` crate with hot-reload support. The Keymanager API endpoints would be thin wrappers over existing functionality.

#### 2. Additional Testnet Support

**Who has it:** Lighthouse (mainnet, gnosis, chiado, sepolia, holesky, hoodi), Prysm, Teku, Nimbus, Lodestar

**What's missing:** rvc only supports Mainnet and Hoodi. The code in `network.rs` explicitly rejects Sepolia and Holesky (`assert!("sepolia".parse::<Network>().is_err())`).

**Why it matters:** Holesky is the primary Ethereum testnet for validator testing. Without it, operators cannot test rvc before deploying to mainnet. This is a significant barrier to adoption.

**Implementation note:** Requires adding genesis time, genesis validators root, and fork schedule for each network to the `Network` enum.

---

### Tier 2 — Safety & Reliability

> Protects validators from financial loss. High priority for production use.

#### 3. Builder Circuit Breakers

**Who has it:** Prysm (`--max-builder-consecutive-missed-slots=3`, `--max-builder-epoch-missed-slots=5`), Lighthouse (chain health fallback)

**What's missing:** If a builder/relay fails repeatedly, rvc continues requesting builder blocks. There is no automatic fallback to local block production after consecutive failures.

**Why it matters:** When a relay goes down, every failed builder request = a missed block proposal = lost rewards (~0.05 ETH per missed proposal). Circuit breakers automatically switch to local execution client blocks after N consecutive failures.

**Suggested implementation:**
- Track consecutive missed builder slots per epoch
- After N consecutive misses (default: 3), disable builder for remainder of epoch
- After M total misses in an epoch (default: 5), disable builder for remainder of epoch
- Auto-reset at epoch boundary

#### 4. Emergency Attestation Disable

**Who has it:** Lighthouse (`--disable-attesting`)

**What's missing:** No runtime flag to stop attestation/sync committee duties without stopping the process.

**Why it matters:** During incident response (e.g., suspected slashing bug, chain fork issues), operators need to quickly disable attestation duties while keeping the process running for monitoring and block proposals. Currently the only option is to stop the entire validator client.

#### 5. Slashed Validator Auto-Shutdown

**Who has it:** Teku (`--shut-down-when-validator-slashed-enabled`)

**What's missing:** If a managed validator is detected as slashed on-chain, rvc continues operating.

**Why it matters:** Once slashed, a validator enters a ~36-day exit queue. Continuing to attest incorrectly during this period increases penalties. Auto-shutdown prevents additional inactivity leak penalties.

#### 6. Keystore Locking

**Who has it:** Teku (file-level lock, default ON), Lighthouse (SQLite exclusive lock)

**What's missing:** No mechanism to prevent two rvc instances from signing with the same keys simultaneously.

**Why it matters:** Running duplicate validator instances is the most common cause of slashing. While doppelganger detection helps, it has a 2-epoch delay. File-level keystore locking provides immediate prevention at the filesystem level.

---

### Tier 3 — Operational Excellence

> Production quality-of-life features for professional operators.

#### 7. Dedicated Proposer Nodes

**Who has it:** Lighthouse (`--proposer-nodes`), Vouch (per-operation node assignment)

**What's missing:** All BN operations use the same node selection strategy. No way to designate high-quality nodes specifically for block proposals.

**Why it matters:** Block proposals are the highest-value duty (~10x attestation reward). A dedicated, well-peered, low-latency BN for proposals reduces missed proposal risk. For institutional operators managing many validators, this is a significant optimization.

#### 8. Configurable Broadcast Topics

**Who has it:** Lighthouse (`--broadcast attestations,blocks,sync-committee,subscriptions,none`)

**What's missing:** rvc broadcasts all submissions to all BNs unconditionally.

**Why it matters:** For operators with many BNs, broadcasting every message type to every node increases bandwidth and can overwhelm slower nodes. Being able to selectively broadcast only high-value messages (blocks) while sending others to a single node reduces load.

#### 9. Remote Monitoring Endpoint

**Who has it:** Lighthouse (`--monitoring-endpoint`), Lodestar (`--monitoring.endpoint`)

**What's missing:** No push-based metrics endpoint for external monitoring services.

**Why it matters:** Services like beaconcha.in offer validator monitoring dashboards. Push-based metrics avoid exposing Prometheus ports to the internet, which is especially important for home stakers without reverse proxy setups.

#### 10. Log File Rotation & Compression

**Who has it:** Lighthouse (`--logfile-max-size=200MB`, `--logfile-max-number=10`, `--logfile-compress`)

**What's missing:** No built-in log file management. Operators must configure external log rotation (logrotate).

**Why it matters:** Unmanaged log files can fill disks and crash validator clients. Built-in rotation with compression is table-stakes for production software.

#### 11. Proposer Config from URL with Auto-Refresh

**Who has it:** Prysm (`--proposer-settings-url`), Teku (`--validators-proposer-config`, auto-refresh per epoch)

**What's missing:** Per-validator proposer settings can only be loaded from local TOML files.

**Why it matters:** Institutional staking platforms manage hundreds of validators with centralized configuration. Loading proposer settings from a URL allows dynamic management without file deployment. Auto-refresh per epoch means changes take effect within ~6.4 minutes.

---

### Tier 4 — Advanced / Differentiating

> Features that expand rvc's capabilities for specialized use cases.

#### 12. Multi-Strategy Block Selection

**Who has it:** Lodestar (6 strategies), Vouch (multi-source evaluation)

**What's missing:** rvc has Best (evaluate quality) and First (lowest latency) strategies. Missing specialized modes:

| Strategy | Use Case |
|----------|----------|
| `builderonly` | DVT setups where builder blocks are mandatory |
| `executiononly` | Operators who want to avoid MEV entirely |
| `maxprofit` | Always select highest-value block regardless of source |
| `builderalways` | Prefer builder blocks even when local is slightly better |

**Why it matters:** Different operator profiles have different block selection needs. DVT clusters often require `builderonly` mode. Privacy-focused operators want `executiononly`.

#### 13. Role-Based BN Assignment

**Who has it:** Nimbus (per-BN role assignment)

**What's missing:** Cannot assign specific duty types to specific beacon nodes.

**Why it matters:** Enables sentry-node architectures where block-proposal traffic is routed through a dedicated node to hide the validator's IP address. Also enables geographic optimization (attest via local node, propose via well-peered node).

#### 14. Validator Registration Batching

**Who has it:** Lighthouse (`--validator-registration-batch-size=500`)

**What's missing:** Builder registration for large validator sets may overwhelm beacon nodes.

**Why it matters:** Operators with hundreds or thousands of validators need batched registration to avoid BN timeouts and rate limits during epoch-boundary registration.

#### 15. Pre-Signed Voluntary Exit Storage

**Who has it:** Teku (`--save-exits-path`)

**What's missing:** Voluntary exits can only be generated and submitted in one step.

**Why it matters:** For custody workflows, signing keys may be in cold storage. Pre-signing exit messages that remain valid across future hard forks (EIP-7044) allows operators to prepare exits without having signing keys online.

#### 16. Health-Based BN Tier Selection

**Who has it:** Lighthouse (4 tiers with configurable sync distance thresholds)

**What's missing:** rvc's health scoring is binary (synced/not synced with EMA weighting). No tiered approach.

**Why it matters:** A BN that is 2 slots behind is still perfectly useful for attestations but risky for proposals. Tiered selection allows using partially-synced nodes for lower-criticality duties while reserving fully-synced nodes for proposals.

---

### Tier 5 — Future / Experimental

> Emerging features that may become important.

#### 17. Verifying Web3Signer

**Who has it:** Nimbus (experimental)

Remote signer verifies block properties (fee recipient, gas limit) via Merkle proofs before signing. Prevents a compromised beacon node from tricking the signer into signing malicious blocks.

#### 18. Native Relay Integration

**Who has it:** Vouch

Talk directly to MEV relays without the mev-boost sidecar. Reduces infrastructure complexity and latency.

#### 19. Gnosis Chain Support

**Who has it:** Lighthouse

Expands validator client to non-Ethereum-mainnet chains. Gnosis Chain uses GNO for staking with lower requirements (1 GNO vs. 32 ETH).

#### 20. SSE Log Streaming API

**Who has it:** Lighthouse (`GET /lighthouse/logs`)

Real-time Server-Sent Events log subscription for monitoring dashboards and alerting systems.

---

## Where rvc Already Leads

rvc has several features that match or exceed the competition:

| Feature | rvc Advantage |
|---------|--------------|
| **gRPC remote signing with mTLS** | Most clients only support Web3Signer HTTP. rvc's native gRPC signer with mutual TLS is unique and offers lower latency + stronger auth. |
| **Cloud secret management (GCP)** | Only rvc has native cloud KMS integration. Other clients rely on external tooling or manual key loading. |
| **OpenTelemetry with W3C propagation** | More advanced distributed tracing than most clients. Lighthouse only recently added basic OTel (gRPC only). rvc supports OTLP/HTTP + GCP Cloud Trace. |
| **DVT via Shamir Secret Sharing** | Native threshold signing without external middleware like Obol Charon or SSV. rvc-signer handles SSS directly. |
| **TOML-based hot-reloadable config** | Clean, file-based per-validator configuration with automatic reload. No restart required for config changes. |
| **4-layer crate architecture** | Binary -> Orchestrator -> Domain -> Foundation separation provides excellent modularity and testability. |
| **Audit logging in signer** | Structured audit trail for all remote signing requests. Important for compliance. |

---

## Recommended Roadmap

### Phase 1 — Standards & Safety

> Unblocks adoption and prevents validator losses.

1. Extended Keymanager API (fee recipient, gas limit, graffiti, voluntary exit endpoints)
2. Holesky + Sepolia testnet support
3. Builder circuit breakers (consecutive + per-epoch miss limits)
4. Emergency attestation disable flag

### Phase 2 — Production Hardening

> Makes rvc ready for institutional operators.

5. Keystore file locking
6. Slashed validator auto-shutdown
7. Dedicated proposer nodes (`--proposer-nodes`)
8. Log file rotation and compression
9. Validator registration batching

### Phase 3 — Operational Excellence

> Quality-of-life for large-scale operations.

10. Proposer config from URL with auto-refresh
11. Configurable broadcast topics
12. Remote monitoring endpoint (beaconcha.in compatible)
13. Health-based BN tier selection (4-tier sync distance)

### Phase 4 — Differentiation

> Advanced features for specialized use cases.

14. Multi-strategy block selection modes (builderonly, executiononly, maxprofit)
15. Role-based BN assignment
16. Pre-signed voluntary exit storage

---

## Client Summaries

### Lighthouse (Sigma Prime)
- **Language:** Rust | **License:** Apache 2.0
- **Architecture:** Separate BN + VC processes, 80+ crates
- **Strengths:** Most feature-complete VC API, 4-tier BN health, dedicated proposer nodes, comprehensive log management, mature Rust codebase
- **Networks:** mainnet, gnosis, chiado, sepolia, holesky, hoodi

### Prysm (Offchain Labs)
- **Language:** Go | **License:** GPL-3.0
- **Architecture:** Separate BN + VC, migrating from gRPC to REST
- **Strengths:** Builder circuit breakers, rich proposer settings (file + URL), graffiti file modes (specific/ordered/random), DVT support, largest market share
- **Networks:** mainnet, sepolia, holesky, hoodi, prater

### Teku (ConsenSys)
- **Language:** Java | **License:** Apache 2.0
- **Architecture:** Combined or separate BN + VC modes
- **Strengths:** Enterprise focus, rich proposer config with auto-refresh, pre-signed exits, keystore locking, slashed auto-shutdown, Swagger API docs
- **Networks:** mainnet, sepolia, holesky, hoodi, gnosis, chiado

### Nimbus (Status/IFT)
- **Language:** Nim | **License:** Apache 2.0 / MIT
- **Architecture:** Combined or separate, ultra-lightweight (~1 GiB RAM)
- **Strengths:** Role-based BN assignment, sentry node architecture, doppelganger ON by default, verifying Web3Signer, era files, minimal resource usage
- **Networks:** mainnet, sepolia, holesky, hoodi, gnosis

### Lodestar (ChainSafe)
- **Language:** TypeScript/Zig | **License:** LGPL-3.0
- **Architecture:** Monorepo with separate packages
- **Strengths:** 6 block selection strategies, light client implementation, slashing protection always-on, restart-aware doppelganger, JS ecosystem
- **Networks:** mainnet, sepolia, holesky, hoodi, gnosis, chiado

### Vouch (Attestant/Bitwise)
- **Language:** Go | **License:** Apache 2.0
- **Architecture:** Middleware between BN(s) and signer(s) (Dirk)
- **Strengths:** Multi-BN best-data selection (unique depth), native relay integration, multi-instance support, strategy-based per-operation node selection, client diversity support
- **Networks:** Any (beacon-node independent)

---

## References

- [Ethereum Keymanager APIs](https://github.com/ethereum/keymanager-APIs)
- [EIP-3076: Slashing Protection Interchange Format](https://eips.ethereum.org/EIPS/eip-3076)
- [Ethereum Builder Specs](https://github.com/ethereum/builder-specs)
- [Ethereum Beacon APIs](https://github.com/ethereum/beacon-APIs)
- [Ethereum Distributed Validator Specs](https://github.com/ethereum/distributed-validator-specs)
- [Lighthouse Book](https://lighthouse-book.sigmaprime.io/)
- [Prysm Documentation](https://prysm.offchainlabs.com/docs/)
- [Teku Documentation](https://docs.teku.consensys.io/)
- [Nimbus Guide](https://nimbus.guide/)
- [Lodestar Documentation](https://chainsafe.github.io/lodestar/)
- [Vouch GitHub](https://github.com/attestantio/vouch)
- [Obol Charon](https://github.com/ObolNetwork/charon)
- [SSV Network](https://docs.ssv.network/)
