# Research: Existing Ethereum Validator Client Implementations

## Recommendation

Build a standalone Rust VC using Lighthouse's service-per-duty architecture as a starting point, but adopt Vouch's strategy-based multi-BN selection and Lodestar's restart-aware doppelganger detection. Decouple completely from any beacon node codebase — zero shared crates.

## Context

- **Goal:** Understand the architecture, strengths, and weaknesses of existing VCs to inform design of a new standalone Rust VC.
- **Evaluated:** Lighthouse (Rust), Vouch (Go), Lodestar (TypeScript), Prysm (Go), Teku (Java), Nimbus (Nim)
- **Market share (2025):** Teku ~53.9%, Prysm ~21.2%, Lighthouse ~20.6%, Nimbus ~3.1%, Grandine ~0.7%, Lodestar ~0.5% [1]

## Comparison

| Criteria | Lighthouse | Vouch | Lodestar | Prysm | Teku | Nimbus |
|----------|-----------|-------|----------|-------|------|--------|
| Language | Rust | Go | TypeScript | Go | Java | Nim |
| Standalone VC | Yes (but coupled codebase) | Yes (purpose-built) | Yes (monorepo package) | Yes | Yes (combined + standalone) | Yes (integrated + standalone) |
| Multi-BN | Ordered failover + broadcast | Strategy-based (best/first/majority) | Basic multi-BN | Health-check failover | Primary + warm failover | Role-based assignment |
| Slashing DB | SQLite (ACID) | Delegated to Dirk | Local DB | BoltDB | Per-validator YAML | SQLite (Lighthouse-modeled) |
| Key Management | EIP-2335 + Web3Signer + Keymanager API | Dirk (proprietary) | EIP-2335 + Keymanager API | EIP-2335 + Web3Signer + Keymanager API | EIP-2335 + Web3Signer + Keymanager API | EIP-2335 + Web3Signer |
| Doppelganger | Opt-in, 2-3 epochs | N/A | Restart-aware | Opt-in, conflicts w/ failover | Opt-in, shuts down entire VC | On by default, 2 epochs |
| License | Apache-2.0 | Apache-2.0 | Apache-2.0 | GPL-3.0 | Apache-2.0 | Apache-2.0 |

## Detailed Analysis

### 1. Lighthouse VC (Rust) — Primary Reference

**Repository:** [sigp/lighthouse](https://github.com/sigp/lighthouse) [2]

**Architecture:**
Lighthouse uses a service-per-duty architecture within the `validator_client/src/` directory [3]:
- `duties_service.rs` — Polls beacon node for attester/proposer duties each epoch (~906 lines) [3]
- `attestation_service.rs` — Produces and submits attestations at correct slot offsets
- `block_service.rs` — Block proposal when selected as proposer
- `sync_committee_service.rs` — Sync committee contributions (~620 lines) [5]
- `preparation_service.rs` — Proposer preparation and validator registration [6]
- `check_synced.rs` — BN sync status verification [7]

**Duty Scheduling:**
- Fetches attester duties at the start of each epoch via `/eth/v1/validator/duties/attester/{epoch}`
- Fetches proposer duties similarly; pre-fetches next epoch duties
- Attestation production triggered at 1/3 into the slot (4 seconds) [4]
- Uses a `DutiesService` that maintains a cache of upcoming duties

**Key Management:**
- EIP-2335 keystores with `validator_definitions.yml` for configuration [9]
- Web3Signer remote signing support [9]
- Standard Keymanager API for runtime management [10]
- Per-validator builder and fee recipient configuration

**Slashing Protection:**
- SQLite database with WAL mode and exclusive locking [11]
- Schema-enforced uniqueness constraints prevent double proposals at the DB level
- Full EIP-3076 interchange support (import/export) [11]
- v1.6.0+ uses "import by minification" to handle large interchange files efficiently

**Multi-BN Support:**
- `--beacon-nodes` accepts comma-separated URLs [12]
- Ordered failover: tries first BN, falls back to next on failure
- `--broadcast` flag (v4.6.0+) sends signed messages to all BNs simultaneously [13]
- BN health checking via sync status endpoint [14]

**Known Issues:**
- Post-merge attestation miss rate increased due to execution payload timing [15]
- Doppelganger detection adds 12-20 min startup delay on every restart [16]
- Historical race condition in duty scheduling (Issue #918) [17]
- BN health detection can report "available" when not fully ready (Issue #5044) [18]
- VC is tightly coupled to Lighthouse BN codebase — shares many internal crates

**What to Replicate:**
- Service-per-duty architecture — clean separation, independent lifecycles
- SQLite slashing protection with schema-enforced constraints
- EIP-3076 import/export
- `--broadcast` flag for multi-BN message dissemination

**What to Improve:**
- Zero shared code with any BN — pure Beacon API client
- Strategy-based multi-BN selection instead of ordered failover
- Restart-aware doppelganger detection to avoid startup penalties
- BN health scoring using latency + sync status + error rate

---

### 2. Vouch (Go) — Architecture Exemplar

**Repository:** [attestantio/vouch](https://github.com/attestantio/vouch) [19]

**Architecture:**
Vouch is the only purpose-built standalone VC. Its architecture features [20]:
- **Controller** — Manages scheduler and services
- **Scheduler** — Epoch-based duty triggering
- **Strategy system** — Configurable per-operation selection strategies
- **Service modules** — Independent services for each duty type, metrics, graffiti, etc.

**Duty Scheduling:**
- Epoch-based: at the start of each epoch, fetches duties and schedules them
- Proposer, attester, and sync committee duties are handled by separate service modules
- Uses go-eth2-client library for beacon API communication

**Key Management:**
- Uses [Dirk](https://github.com/attestantio/dirk) — a proprietary distributed remote key manager [24]
- Supports threshold signing (e.g., 2-of-3 signers across hosts)
- Authentication via TLS certificates
- **Lock-in risk:** Vouch essentially requires Dirk; no local keystore support [26]

**Multi-BN Support — The Differentiator:**
Vouch pioneered strategy-based multi-BN selection [23][25]:
- **Best strategy:** Query all BNs, use the response with the highest reward value
- **First strategy:** Use the first successful response (lowest latency)
- **Majority strategy:** Wait for majority of BNs to respond, use the most common answer
- Strategies are configurable **per-operation** (different strategy for proposals vs attestations)
- Per-operation BN lists allow connecting different duties to different client implementations [25]

**Known Issues:**
- Small adoption (~22.6% of Lido CM validators use it [27])
- Dirk lock-in limits accessibility for solo stakers
- No local keystore support
- Complex configuration for simple setups

**What to Replicate:**
- Strategy-based multi-BN selection (best/first/majority)
- Per-operation BN configuration for client diversity
- Clean standalone architecture with no BN coupling

**What to Improve:**
- Support local keystores and Web3Signer — not just Dirk
- Simplify configuration for solo stakers
- Implement in Rust for performance and safety guarantees

---

### 3. Lodestar VC (TypeScript)

**Repository:** [ChainSafe/lodestar](https://github.com/ChainSafe/lodestar) (`packages/validator/`) [28][29]

**Architecture:**
- Monorepo package at `packages/validator/` [29]
- Main entry point: `packages/validator/src/validator.ts` [30]
- Service-based with `AttestationService`, `BlockProposingService`, `SyncCommitteeService`
- Shares types with the BN through the monorepo but communicates via REST API

**Key Innovation — Restart-Aware Doppelganger Detection:**
Lodestar's restart-aware doppelganger (Issue #5856 [34]) is best-in-class:
- On startup, checks slashing DB for last signed attestation epoch
- If recently active (within 1-2 epochs), skips doppelganger detection
- Only runs full DP for validators that have been offline longer
- Eliminates the 12-20 minute startup penalty on routine restarts

**Known Issues:**
- TypeScript performance limitations for compute-heavy operations [36]
- Attestation and sync committee services occasionally stop working (Issue #2727) [31]
- Cross-client BN compatibility issues (e.g., Nimbus VC incompatibility, Issue #6634) [35]
- Smallest market share (~0.5%) means fewer battle-tested scenarios

**What to Replicate:**
- Restart-aware doppelganger detection
- SSZ wire format support (added as opt-in via `--http.requestWireFormat ssz`) [36]

**What to Improve:**
- Performance: Rust eliminates TypeScript's overhead
- Cross-client testing must be a first-class CI concern

---

### 4. Prysm (Go) — Cautionary Reference

**Repository:** [prysmaticlabs/prysm](https://github.com/prysmaticlabs/prysm) [37]

**Architecture:**
- VC in `validator/client/` directory with `attest.go`, `propose.go`, etc. [38]
- Three-tier keymanager abstraction: local, derived, remote (Web3Signer) [39]
- Historically used gRPC for BN-VC communication; migrated to REST API (gRPC gateway removed in v5.1.1) [41]
- Slashing protection via BoltDB (key-value store) [40]

**Critical Incidents:**
- **Medalla testnet (Aug 2020):** Time server bug + Docker volume misconfiguration caused mass slashing. Slashing DBs recreated on container restart [44]
- **Staked incident (Feb 2021):** 75 validators slashed because operator disabled slashing DB persistence due to I/O overhead [17][18]
- **December 2025 Fusaka incident:** Resource exhaustion bug caused 18.5% missed slot rate and ~382 ETH in losses [48]

**Known Issues:**
- Fixed 12-second attestation deadline becomes insufficient at scale (Issue #9596) [42]
- Doppelganger + failover are incompatible in certain configs (Issue #15296) [47]
- Late proposals when attesting on the same slot (Issue #8346) [49]

**What to Replicate:**
- Three-tier keymanager abstraction (local, derived, remote)
- Separate safety check and commit operations for slashing protection
- Health-check-based BN failover

**What to Improve:**
- Use REST API exclusively from day one
- Parallelize attestation production to avoid deadline issues at scale
- Make DB persistence validation a startup requirement
- Ensure doppelganger and failover are compatible by design

---

### 5. Teku (Java) — Institutional Reference

**Repository:** [Consensys/teku](https://github.com/Consensys/teku) [50]

**Architecture:**
- Combined mode (BN+VC in single JVM) and standalone mode [51]
- REST-only BN communication from inception [51]
- Per-validator YAML files for slashing protection [53]
- Warm failover with preemptive subnet subscriptions [54]

**What to Replicate:**
- Warm failover BNs via preemptive subnet subscriptions
- Keystore file locking to prevent concurrent use
- Clean REST-only BN interface

**What to Improve:**
- Use SQLite instead of per-validator YAML (no ACID guarantees)
- Doppelganger should disable individual validators, not shut down entire VC

---

### 6. Nimbus (Nim) — Lightweight Reference

**Repository:** [status-im/nimbus-eth2](https://github.com/status-im/nimbus-eth2) [58]

**Architecture:**
- Integrated mode (default), standalone VC, and split mode [59]
- Role-based multi-BN assignment supporting sentry node architectures [60]
- SQLite slashing protection modeled after Lighthouse [11]
- Strict file permission enforcement on key files [60]

**What to Replicate:**
- Role-based multi-BN assignment (sentry node support)
- Strict file permission validation on key files
- Low resource usage as a design goal

**What to Improve:**
- A standalone VC should never have an "integrated" mode that risks key confusion
- Provide clearer startup checks to prevent accidental key duplication

---

## Cross-Cutting Recommendations

### Slashing Protection
Use SQLite with schema-enforced uniqueness constraints (Lighthouse/Nimbus pattern). Add startup integrity check; refuse to start if DB is corrupted.

### Doppelganger Detection
Implement Lodestar's restart-aware approach: skip DP for recently-active validators, only run full 2-epoch monitoring for validators offline longer than 2 epochs.

### Multi-BN Support
Combine Vouch's strategy-based selection with Nimbus's role-based assignment:
1. Per-operation BN lists (proposals, attestations, sync committees)
2. Configurable strategies per operation (best, first, majority)
3. Broadcast signed messages to all BNs
4. BN health scoring (latency + sync status + error rate)

### What to Replicate vs Improve

| Replicate | Source | Improve | Source |
|-----------|--------|---------|--------|
| Service-per-duty architecture | Lighthouse | Zero BN coupling | Lighthouse |
| SQLite slashing with schema constraints | Lighthouse/Nimbus | Strategy-based multi-BN | Vouch → all |
| Strategy-based multi-BN selection | Vouch | Restart-aware doppelganger | Lodestar → all |
| Per-operation BN configuration | Vouch/Nimbus | Parallel attestation production | Prysm lesson |
| EIP-3076 interchange support | All | Compatible doppelganger + failover | Prysm lesson |
| Standard Keymanager API | All (except Vouch) | Per-validator doppelganger (not whole-VC) | Teku lesson |
| Warm failover BN subscriptions | Teku | Standard interfaces only (no Dirk lock-in) | Vouch lesson |

## Sources

[1] [Client Diversity](https://clientdiversity.org/) — Market share data for consensus clients.
[2] [sigp/lighthouse](https://github.com/sigp/lighthouse) — Sigma Prime. Ethereum consensus client in Rust.
[3] [lighthouse/duties_service.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/src/duties_service.rs) — Duty scheduling implementation.
[4] [Missed Attestations Analysis](https://blog.sigmaprime.io/attestation-analysis.html) — Sigma Prime Blog.
[5] [lighthouse/sync_committee_service.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/src/sync_committee_service.rs) — Sync committee service.
[6] [lighthouse/preparation_service.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/src/preparation_service.rs) — Proposer preparation.
[7] [lighthouse/check_synced.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/src/check_synced.rs) — BN sync verification.
[9] [Remote Signing with Web3Signer](https://lighthouse-book.sigmaprime.io/advanced_web3signer.html) — Sigma Prime.
[10] [Validator Client API](https://lighthouse-book.sigmaprime.io/api-vc.html) — Sigma Prime.
[11] [Slashing Protection](https://lighthouse-book.sigmaprime.io/slashing-protection.html) — Sigma Prime.
[12] [Redundancy](https://lighthouse-book.sigmaprime.io/redundancy.html) — Sigma Prime.
[13] [Release v4.6.0](https://github.com/sigp/lighthouse/releases/tag/v4.6.0) — Introduction of --broadcast flag.
[14] [Improve BN failover — Issue #3613](https://github.com/sigp/lighthouse/issues/3613) — Sigma Prime.
[15] [Post-merge attestation issues — Issue #3579](https://github.com/sigp/lighthouse/issues/3579) — Sigma Prime.
[16] [Doppelganger Protection](https://lighthouse-book.sigmaprime.io/validator-doppelganger.html) — Sigma Prime.
[17] [Race condition — Issue #918](https://github.com/sigp/lighthouse/issues/918) — Sigma Prime.
[18] [BN health detection — Issue #5044](https://github.com/sigp/lighthouse/issues/5044) — Sigma Prime.
[19] [attestantio/vouch](https://github.com/attestantio/vouch) — Attestant. Multi-node VC.
[20] [Vouch architecture — DeepWiki](https://deepwiki.com/attestantio/vouch) — Architecture analysis.
[23] [Introducing Vouch](https://www.attestant.io/posts/introducing-vouch/) — Attestant Blog.
[24] [Introducing Dirk](https://www.attestant.io/posts/introducing-dirk/) — Attestant Blog.
[25] [Helping Client Diversity](https://www.attestant.io/posts/helping-client-diversity/) — Attestant Blog.
[26] [Improving client diversity with Vero](https://serenita.io/blog/2024/improving-client-diversity-with-vero) — Serenita Blog, 2024.
[27] [Lido Validator Metrics Q3 2025](https://blog.lido.fi/lido-validator-and-node-operator-metrics-q3-2025/) — Lido Finance.
[28] [ChainSafe/lodestar](https://github.com/ChainSafe/lodestar) — ChainSafe Systems.
[29] [lodestar/packages/validator](https://github.com/ChainSafe/lodestar/tree/unstable/packages/validator) — Validator package.
[30] [lodestar validator.ts](https://github.com/ChainSafe/lodestar/blob/unstable/packages/validator/src/validator.ts) — Main entry.
[31] [Services stop working — Issue #2727](https://github.com/ChainSafe/lodestar/issues/2727) — ChainSafe.
[34] [Restart-aware doppelganger — Issue #5856](https://github.com/ChainSafe/lodestar/issues/5856) — ChainSafe.
[35] [Nimbus VC incompatibility — Issue #6634](https://github.com/ChainSafe/lodestar/issues/6634) — ChainSafe.
[36] [A Lodestar for Consensus 2024](https://blog.chainsafe.io/a-lodestar-for-consensus-2024/) — ChainSafe Blog.
[37] [prysmaticlabs/prysm](https://github.com/prysmaticlabs/prysm) — Offchain Labs.
[38] [prysm/validator/client/attest.go](https://github.com/prysmaticlabs/prysm/blob/develop/validator/client/attest.go) — Attestation production.
[39] [Keymanager package](https://pkg.go.dev/github.com/prysmaticlabs/prysm/v5/validator/keymanager) — Keymanager abstraction.
[40] [Slashing protection package](https://pkg.go.dev/github.com/prysmaticlabs/prysm/validator/slashing-protection) — BoltDB backend.
[41] [Prysm APIs](https://hackmd.io/@prysmaticlabs/prysm-api) — gRPC vs REST documentation.
[42] [Attestations missed — Issue #9596](https://github.com/prysmaticlabs/prysm/issues/9596) — Fixed deadline issue.
[44] [Validators slashed with local protection — Issue #7076](https://github.com/prysmaticlabs/prysm/issues/7076) — Medalla incident.
[47] [Doppelganger prevents failover — Issue #15296](https://github.com/OffchainLabs/prysm/issues/15296) — Compatibility conflict.
[48] [Prysm client issue — BanklessTimes](https://www.banklesstimes.com/articles/2025/12/04/ethereum-foundation-alerts-users-about-prysm-client-issue/) — Fusaka incident.
[49] [Late proposals — Issue #8346](https://github.com/OffchainLabs/prysm/issues/8346) — Scheduling conflict.
[50] [Consensys/teku](https://github.com/Consensys/teku) — Java consensus client.
[51] [Teku Architecture](https://docs.teku.consensys.io/concepts/architecture) — Combined vs standalone.
[53] [Teku Slashing Protection](https://docs.teku.consensys.io/concepts/slashing-protection) — YAML-based approach.
[54] [Teku CLI Reference](https://docs.teku.consensys.io/reference/cli/subcommands/validator-client) — Multi-BN failover.
[58] [status-im/nimbus-eth2](https://github.com/status-im/nimbus-eth2) — Nim consensus client.
[59] [Nimbus Validator Client Options](https://nimbus.guide/validator-client-options.html) — Deployment modes.
[60] [Nimbus Standalone VC](https://nimbus.guide/validator-client.html) — Multi-BN, sentry nodes, key management.
