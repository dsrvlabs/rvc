# PRD: Tiers 2–5 — Safety, Operational Excellence, Advanced Features & Experimental

## Overview

With Tier 1 (Standards Compliance) complete — full Keymanager API and Holesky/Sepolia testnet support — rvc needs to close the remaining feature gaps identified in the [cross-client comparison](../VALIDATOR_CLIENT_COMPARISON.md). This PRD defines 18 features across four tiers that take rvc from "spec-compliant" to "production-hardened, operator-preferred, and forward-looking." The tiers progress from safety-critical protections (Tier 2) through operational quality-of-life (Tier 3), advanced differentiation (Tier 4), and experimental capabilities (Tier 5).

## Problem Statement

rvc is architecturally sound (~153k LOC, 23 crates, 2,433 tests, clean 4-layer design) and now spec-complete on the Keymanager API. However, production operators — especially institutional stakers managing hundreds of validators — face risks and operational friction that competing clients have already solved:

- **Financial risk**: No builder circuit breakers means a failing relay causes missed proposals (~0.05 ETH each). No keystore locking means duplicate instances can cause slashing (~1+ ETH penalty). No auto-shutdown on slashing means extended inactivity leak penalties.
- **Incident response**: No emergency attestation disable forces full process shutdown during incidents, losing monitoring and block proposal capability.
- **Operational friction**: No dedicated proposer nodes, no configurable broadcast, no log rotation, no remote monitoring endpoint, no URL-based proposer config. Operators must rely on external tooling or accept suboptimal setups.
- **Specialized use cases**: No multi-strategy block selection (DVT clusters need `builderonly`), no role-based BN assignment (sentry node architectures), no pre-signed exit storage (cold-key custody workflows).

Lighthouse, Prysm, Teku, and Nimbus each address subsets of these gaps. No single client covers all 18 features, giving rvc an opportunity to become the most complete validator client through systematic implementation.

## Goals & Success Metrics

### Tier 2 — Safety & Reliability

| Goal | Success Metric |
|------|---------------|
| Prevent financial loss from builder failures | Zero missed proposals due to relay downtime when circuit breakers are active |
| Enable safe incident response | Attestation duties can be disabled/re-enabled within 1 slot (~12s) without process restart |
| Limit slashing damage | Slashed validator detected and duties halted within 1 epoch (~6.4 min) |
| Prevent duplicate signing | Second rvc instance with overlapping keys fails to start (exits with clear error) |

### Tier 3 — Operational Excellence

| Goal | Success Metric |
|------|---------------|
| Maximize proposal success rate | Dedicated proposer nodes reduce missed proposals vs. shared-node baseline |
| Reduce operational overhead | Log files self-manage without external logrotate; proposer config updates without file deployment |
| Enable external monitoring | beaconcha.in-compatible monitoring endpoint pushes metrics without exposing Prometheus ports |
| Optimize multi-BN bandwidth | Operators can reduce broadcast traffic by 60-80% by limiting broadcast topics |

### Tier 4 — Advanced / Differentiating

| Goal | Success Metric |
|------|---------------|
| Support all operator profiles | DVT, MEV-averse, and max-profit operators each have appropriate block selection strategies |
| Enable sentry architectures | Block proposals routed through dedicated BN to hide validator IP |
| Scale to 10,000+ validators | Builder registration completes within BN timeout window via batching |
| Support cold-key custody | Pre-signed exits can be stored and submitted without signing keys online |

### Tier 5 — Future / Experimental

| Goal | Success Metric |
|------|---------------|
| Reduce trust in beacon node | Verifying Web3Signer validates block properties before signing |
| Simplify MEV infrastructure | Native relay integration eliminates mev-boost sidecar |
| Expand network support | rvc runs on Gnosis Chain with correct fork parameters |
| Enable real-time monitoring | SSE log streaming delivers events to dashboards within 100ms |

## Target Users

### Solo Staker (1–100 validators)
Runs rvc on personal hardware. Values safety features (circuit breakers, keystore locking, auto-shutdown) and zero-maintenance operations (log rotation). Uses remote monitoring to avoid exposing Prometheus. Limited multi-BN setups.

### Institutional Operator (100–10,000+ validators)
Manages large validator fleets across infrastructure. Requires dedicated proposer nodes, configurable broadcast, URL-based proposer config, registration batching, and role-based BN assignment. Incident response features (emergency attestation disable) are critical for SLA compliance.

### Staking Pool / Protocol (Rocket Pool, Lido, SSV)
Integrates rvc into automated pipelines. Needs pre-signed exit storage for custody workflows, multi-strategy block selection for DVT clusters, and programmatic control over all operational parameters.

### MEV-Focused Operator
Maximizes execution-layer rewards. Requires builder circuit breakers (to avoid missed proposals when relays fail), multi-strategy block selection (`maxprofit`, `builderalways`), and eventually native relay integration to reduce latency.

### Privacy-Focused Operator
Wants to minimize MEV extraction or hide validator identity. Needs `executiononly` block selection and role-based BN assignment for sentry node architectures.

## User Stories

### Tier 2
- As a **validator operator**, I want rvc to automatically fall back to local block production when the builder relay fails, so that I don't miss proposals and lose rewards.
- As an **incident responder**, I want to disable attestation duties without stopping the process, so that I can investigate issues while maintaining monitoring and block proposals.
- As a **solo staker**, I want rvc to automatically stop duties if my validator is slashed, so that I don't accumulate additional inactivity penalties during the exit queue.
- As a **validator operator**, I want rvc to prevent a second instance from signing with the same keys, so that I don't get slashed from accidental duplicate operation.

### Tier 3
- As an **institutional operator**, I want to designate specific beacon nodes for block proposals, so that my highest-value duties use the most reliable infrastructure.
- As a **multi-BN operator**, I want to control which message types are broadcast to all nodes, so that I can reduce bandwidth without sacrificing reliability for high-value messages.
- As a **solo staker**, I want rvc to push metrics to beaconcha.in, so that I can monitor my validators without exposing Prometheus to the internet.
- As a **validator operator**, I want rvc to manage its own log files, so that uncontrolled log growth doesn't crash my validator.
- As a **staking platform**, I want to load proposer configuration from a URL that auto-refreshes, so that I can manage per-validator settings centrally.

### Tier 4
- As a **DVT cluster operator**, I want to force builder-only block selection, so that all cluster members propose the same block.
- As a **privacy-focused operator**, I want to route block proposals through a dedicated sentry node, so that my validator's IP address is hidden.
- As an **institutional operator** with 5,000 validators, I want builder registrations to be batched, so that I don't overwhelm my beacon node at epoch boundaries.
- As a **custody provider**, I want to pre-sign voluntary exits and store them for later submission, so that I can prepare exits without keeping signing keys online.
- As a **multi-BN operator**, I want rvc to use partially-synced nodes for attestations while reserving fully-synced nodes for proposals, so that I maximize resource utilization.

### Tier 5
- As a **security-conscious operator**, I want my remote signer to verify block properties before signing, so that a compromised beacon node cannot trick me into signing malicious blocks.
- As an **infrastructure operator**, I want rvc to talk directly to MEV relays without mev-boost, so that I can reduce latency and infrastructure complexity.
- As a **Gnosis Chain validator**, I want to use rvc on Gnosis Chain, so that I can benefit from its architecture on a lower-capital network.
- As a **monitoring engineer**, I want to subscribe to rvc's log stream via SSE, so that I can build real-time alerting dashboards.

## Functional Requirements

### Tier 2 — Safety & Reliability

#### FR-1: Builder Circuit Breakers [P0]

**Description:** Automatically disable builder block requests after repeated failures, falling back to local execution client block production.

**Reference implementations:** Prysm (`--max-builder-consecutive-missed-slots`, `--max-builder-epoch-missed-slots`), Lighthouse (chain health fallback)

**Requirements:**
- Track consecutive missed builder slots (builder request failed or returned empty/invalid block)
- After `N` consecutive misses (configurable, default: 3), disable builder for the remainder of the epoch
- Track total missed builder slots per epoch
- After `M` total misses in an epoch (configurable, default: 5), disable builder for the remainder of the epoch
- Auto-reset counters at each epoch boundary
- When builder is circuit-broken, request local execution client blocks only
- Log at WARN level when circuit breaker trips, including miss count and epoch
- Log at INFO level when circuit breaker resets at epoch boundary
- Expose Prometheus metrics: `rvc_builder_circuit_breaker_trips_total`, `rvc_builder_consecutive_misses`, `rvc_builder_epoch_misses`
- CLI flags: `--builder-circuit-breaker-consecutive-limit=3`, `--builder-circuit-breaker-epoch-limit=5`

**Acceptance criteria:**
- After 3 consecutive builder failures, next proposal uses local block without attempting builder
- After 5 total builder failures in an epoch, remaining proposals use local block
- Counters reset at epoch boundary and builder is re-enabled
- Circuit breaker state is per-epoch, not global (different epochs are independent)
- Metrics accurately reflect circuit breaker state
- Feature can be disabled via `--builder-circuit-breaker-consecutive-limit=0`

**Dependencies:** None. Modifies `crates/builder/src/service.rs` and block production path in coordinator.

---

#### FR-2: Emergency Attestation Disable [P0]

**Description:** Runtime flag to stop attestation and sync committee duties without stopping the process.

**Reference implementations:** Lighthouse (`--disable-attesting`)

**Requirements:**
- Accept `--disable-attesting` CLI flag at startup (default: false)
- Support runtime toggle via HTTP API endpoint: `POST /rvc/v1/attesting` with `{"enabled": true|false}`
- When disabled: skip attestation production, skip sync committee messages, skip aggregation duties
- When disabled: continue block proposals, doppelganger detection, builder registrations, SSE subscription, metrics serving
- Store state in `Arc<AtomicBool>` accessible to the coordinator
- Log at WARN level when attestation is disabled (both at startup and via API)
- Log at INFO level when attestation is re-enabled via API
- Expose Prometheus gauge: `rvc_attesting_enabled` (1 = enabled, 0 = disabled)
- The HTTP endpoint must require Bearer token authentication (same as Keymanager API)

**Acceptance criteria:**
- `--disable-attesting` starts rvc with attestation duties skipped from the first slot
- `POST /rvc/v1/attesting {"enabled": false}` disables attestation within the current slot
- Block proposals continue normally while attestation is disabled
- Re-enabling attestation resumes duties from the next slot
- Metrics endpoint reflects current state

**Dependencies:** None. Adds a conditional check in the coordinator's attestation/sync-committee paths.

---

#### FR-3: Slashed Validator Auto-Shutdown [P0]

**Description:** Automatically disable duties for validators detected as slashed on-chain.

**Reference implementations:** Teku (`--shut-down-when-validator-slashed-enabled`)

**Requirements:**
- Periodically check validator statuses via beacon node API (`/eth/v1/beacon/states/head/validators`)
- If any managed validator has `status: "active_slashed"` or `status: "exited_slashed"`:
  - Disable all duties for that validator immediately
  - Log at ERROR level with validator pubkey and slashing details
  - Emit alert metric: `rvc_validators_slashed_total`
- Configurable behavior on slash detection:
  - `--slashed-validators-action=disable-only` (default): disable duties for slashed validator(s), continue operating other validators
  - `--slashed-validators-action=shutdown`: shut down the entire validator client (matches Teku behavior)
- Status check interval: once per epoch (configurable via `--slashed-check-interval`)
- Feature enabled by default (opt-out via `--slashed-validators-action=none`)

**Acceptance criteria:**
- Slashed validator detected within 1 epoch of slashing event
- Disabled validator produces no attestations or proposals after detection
- Non-slashed validators continue normal operation in `disable-only` mode
- Full shutdown occurs within 12 seconds of detection in `shutdown` mode
- Validator status persists across restarts (slashed validators remain disabled)

**Dependencies:** Requires beacon node validator status API. Uses existing `ValidatorStore.set_enabled()`.

---

#### FR-4: Keystore File Locking [P0]

**Description:** Prevent multiple rvc instances from operating on the same validator keys simultaneously.

**Reference implementations:** Teku (file-level lock, default ON), Lighthouse (SQLite exclusive lock)

**Requirements:**
- At startup, acquire an exclusive file lock on each keystore directory (or a dedicated lock file per validator)
- Lock file path: `<validator-data-dir>/.rvc.lock`
- Use `flock(2)` / `fcntl(2)` advisory locks (Unix) for process-level mutual exclusion
- If lock acquisition fails (another process holds the lock):
  - Log at ERROR level with the locked keystore path
  - Exit with non-zero status and descriptive error message
  - Do NOT start any validator duties
- Release locks on clean shutdown
- Locks are automatically released on process crash (OS reclaims advisory locks)
- CLI flag: `--disable-keystore-locking` to opt out (for advanced use cases like DVT)
- Feature enabled by default

**Acceptance criteria:**
- First rvc instance starts normally and acquires locks
- Second rvc instance with overlapping keys fails to start with clear error message naming the locked keys
- After first instance exits, second instance can start successfully
- `--disable-keystore-locking` bypasses lock checks
- Lock files are cleaned up on normal shutdown
- Process crash releases locks (verified by starting a new instance after `kill -9`)

**Dependencies:** None. Added to startup sequence before validator activation.

---

### Tier 3 — Operational Excellence

#### FR-5: Dedicated Proposer Nodes [P1]

**Description:** Designate specific beacon nodes for block proposals, separate from the general-purpose BN pool.

**Reference implementations:** Lighthouse (`--proposer-nodes`), Vouch (per-operation node assignment)

**Requirements:**
- New CLI flag: `--proposer-nodes <URL1>,<URL2>,...`
- When configured, block proposals (blinded and unblinded) use proposer nodes exclusively
- Proposer nodes have their own health tracking, sync monitoring, and failover (same First/Best strategies)
- Attestation data, duty fetching, and submissions continue using the main BN pool (`--beacon-nodes`)
- Proposer nodes can overlap with main nodes (same URL in both lists is valid)
- If all proposer nodes are down, fall back to the main BN pool (log at WARN)
- Expose separate health scores for proposer nodes: `rvc_proposer_bn_*` metrics

**Acceptance criteria:**
- With `--proposer-nodes` set, block production requests go exclusively to proposer nodes
- If proposer nodes are unreachable, proposals fall back to main BN pool with WARN log
- Health scores for proposer nodes are independent of main pool scores
- Without `--proposer-nodes`, behavior is unchanged (main pool handles all operations)

**Dependencies:** Extends `BnManager` to support a second node pool. Modifies block production path in coordinator.

---

#### FR-6: Configurable Broadcast Topics [P1]

**Description:** Allow operators to control which message types are broadcast to all beacon nodes.

**Reference implementations:** Lighthouse (`--broadcast attestations,blocks,sync-committee,subscriptions,none`)

**Requirements:**
- New CLI flag: `--broadcast <topics>` where topics is a comma-separated list
- Valid topics: `attestations`, `blocks`, `sync-committee`, `subscriptions`, `none`
- Default: `attestations,blocks,sync-committee,subscriptions` (current behavior — broadcast everything)
- `none` disables broadcast entirely (send to single best BN only)
- For topics NOT in the broadcast list, use First strategy (single BN) instead of Broadcast
- `blocks` should almost always be included (highest-value message)
- Log at INFO level which broadcast topics are active at startup

**Acceptance criteria:**
- `--broadcast blocks` only broadcasts block submissions; attestations use First strategy
- `--broadcast none` sends all messages to single BN only
- Default behavior (no flag) is unchanged
- Invalid topic names produce a startup error with list of valid topics

**Dependencies:** Modifies `BnManager` submission methods to check broadcast config.

---

#### FR-7: Remote Monitoring Endpoint [P1]

**Description:** Push-based metrics endpoint compatible with beaconcha.in's validator monitoring API.

**Reference implementations:** Lighthouse (`--monitoring-endpoint`), Lodestar (`--monitoring.endpoint`)

**Requirements:**
- New CLI flag: `--monitoring-endpoint <URL>`
- When configured, periodically POST validator metrics to the specified URL
- Push interval: every epoch (~6.4 minutes), configurable via `--monitoring-interval`
- Payload format: beaconcha.in monitoring API v1 schema (JSON)
- Include: validator pubkeys, attestation effectiveness, proposal history, sync committee participation, client version, network
- Use HTTPS with TLS verification (allow `--monitoring-endpoint-insecure` for testing)
- Retry with exponential backoff on transient failures (max 3 retries per push)
- Do NOT block validator duties if monitoring push fails
- Log at DEBUG level on successful push, WARN on failure

**Acceptance criteria:**
- Metrics are pushed to the configured endpoint every epoch
- Push failures do not affect validator operation
- Payload validates against beaconcha.in's monitoring API schema
- HTTPS is enforced by default; `--monitoring-endpoint-insecure` allows HTTP

**Dependencies:** Requires access to duty performance data from the coordinator.

---

#### FR-8: Log File Rotation & Compression [P1]

**Description:** Built-in log file management with size-based rotation and optional compression.

**Reference implementations:** Lighthouse (`--logfile`, `--logfile-max-size`, `--logfile-max-number`, `--logfile-compress`)

**Requirements:**
- New CLI flags:
  - `--logfile <path>`: enable file logging (default: disabled, stdout only)
  - `--logfile-max-size <MB>`: maximum size before rotation (default: 200 MB)
  - `--logfile-max-number <N>`: maximum number of rotated files to keep (default: 5)
  - `--logfile-compress`: compress rotated files with gzip (default: false)
  - `--logfile-level <level>`: log level for file output, independent of stdout (default: same as `--log-level`)
- Rotation is size-based (not time-based)
- Rotated files named: `rvc.log.1`, `rvc.log.2`, ... (or `.gz` if compressed)
- File logging runs alongside stdout logging (not instead of)
- Use `tracing-appender` or equivalent for non-blocking file I/O

**Acceptance criteria:**
- Log file rotates when it reaches `--logfile-max-size`
- Old files beyond `--logfile-max-number` are deleted
- Compressed files are valid gzip
- File I/O does not block the validator's hot path (attestation signing)
- Without `--logfile`, behavior is unchanged (stdout only)

**Dependencies:** None. Modifies telemetry initialization.

---

#### FR-9: Proposer Config from URL with Auto-Refresh [P1]

**Description:** Load per-validator proposer configuration from a remote URL with periodic refresh.

**Reference implementations:** Prysm (`--proposer-settings-url`), Teku (`--validators-proposer-config` with auto-refresh per epoch)

**Requirements:**
- New CLI flag: `--proposer-config-url <URL>`
- Fetches proposer config (JSON, matching Prysm/Teku schema) from the URL at startup
- Auto-refresh: re-fetch every epoch (~6.4 minutes), configurable via `--proposer-config-refresh-interval`
- Config schema supports per-validator and default fee recipient, gas limit, builder settings
- On refresh:
  - Apply changes to `ValidatorStore` in-memory
  - Log changed validators at INFO level
  - On fetch failure: retain existing config, log at WARN, retry next interval
- Mutual exclusivity with `--proposer-config-file` (cannot use both)
- Support Bearer token auth: `--proposer-config-url-token <token>`
- HTTPS required by default; `--proposer-config-url-insecure` for testing

**Acceptance criteria:**
- Proposer config loaded from URL at startup
- Changes at the URL are picked up within one refresh interval
- Fetch failures do not disrupt current validator operation
- Config changes are reflected in builder registrations within 1 epoch
- Both `--proposer-config-url` and `--proposer-config-file` produces a startup error

**Dependencies:** Uses existing `ValidatorStore.update_config()`. Requires HTTP client (reuse `reqwest` from beacon crate).

---

### Tier 4 — Advanced / Differentiating

#### FR-10: Multi-Strategy Block Selection [P1]

**Description:** Expand block selection strategies beyond First and Best to support specialized operator profiles.

**Reference implementations:** Lodestar (6 strategies), Vouch (multi-source evaluation)

**Requirements:**
- Add new block selection strategies to `BnSelectionStrategy` or a new `BlockSelectionMode`:
  - `builderonly`: Always use builder blocks; fail proposal if builder fails (for DVT clusters)
  - `executiononly`: Never request builder blocks; use local execution client only
  - `maxprofit`: Request both builder and local blocks, select highest value
  - `builderalways`: Prefer builder blocks unless builder fails, then fall back to local
- CLI flag: `--block-selection-mode <mode>` (default: current behavior, equivalent to `maxprofit`)
- Per-validator override via TOML config: `block_selection_mode = "builderonly"`
- `builderonly` mode must interact correctly with circuit breakers (circuit-broken builder = missed proposal, log at ERROR)
- Expose metric: `rvc_block_selection_mode` (label per validator or global)

**Acceptance criteria:**
- `builderonly` never falls back to local blocks (fails loudly if builder unavailable)
- `executiononly` never requests builder blocks
- `maxprofit` selects the higher-value block between builder and local
- `builderalways` uses builder when available, local as fallback
- Default behavior is unchanged from current implementation
- Per-validator mode overrides global mode

**Dependencies:** Depends on FR-1 (circuit breakers) for `builderonly` interaction.

---

#### FR-11: Role-Based BN Assignment [P2]

**Description:** Assign specific beacon nodes to specific duty types for sentry-node architectures and geographic optimization.

**Reference implementations:** Nimbus (per-BN role assignment)

**Requirements:**
- TOML config for BN role assignment:
  ```toml
  [[beacon_nodes]]
  url = "http://bn1:5052"
  roles = ["attestation", "sync-committee"]

  [[beacon_nodes]]
  url = "http://bn2:5052"
  roles = ["proposal"]

  [[beacon_nodes]]
  url = "http://bn3:5052"
  roles = ["all"]  # default
  ```
- Valid roles: `attestation`, `proposal`, `sync-committee`, `aggregation`, `submission`, `all`
- Default role: `all` (backwards compatible)
- Each duty type queries/submits only through BNs assigned to its role
- Failover within role group; cross-role failover as last resort (configurable)
- Health tracking is per-BN, not per-role

**Acceptance criteria:**
- BNs with `proposal` role receive block production requests only
- BNs with `attestation` role receive attestation data requests only
- If all BNs for a role are down, cross-role fallback occurs (with WARN log)
- Default config (`roles = ["all"]`) behaves identically to current implementation

**Dependencies:** Extends `BnManager` architecture. Should be designed alongside FR-5 (Dedicated Proposer Nodes).

---

#### FR-12: Validator Registration Batching [P1]

**Description:** Batch builder validator registrations to avoid overwhelming beacon nodes.

**Reference implementations:** Lighthouse (`--validator-registration-batch-size=500`)

**Requirements:**
- New CLI flag: `--validator-registration-batch-size <N>` (default: 500)
- Split registration list into batches of size N
- Submit batches sequentially with configurable delay between batches: `--validator-registration-batch-delay <ms>` (default: 500ms)
- Per-batch timeout: use existing BN operation timeout
- On batch failure: log at WARN, continue with remaining batches
- Track batch progress via metrics: `rvc_builder_registration_batches_total`, `rvc_builder_registration_batches_failed`

**Acceptance criteria:**
- 2,000 validators with batch size 500 produces 4 sequential registration requests
- Failed batch does not prevent remaining batches from being submitted
- Batch delay prevents BN overload (configurable)
- Batch size of 0 means "send all at once" (current behavior)

**Dependencies:** Modifies `crates/builder/src/service.rs`.

---

#### FR-13: Pre-Signed Voluntary Exit Storage [P2]

**Description:** Generate and store signed voluntary exit messages for later submission without signing keys.

**Reference implementations:** Teku (`--save-exits-path`)

**Requirements:**
- New CLI command: `rvc prepare-exit --pubkey <pubkey> --output <dir>`
  - Signs a voluntary exit message for the specified validator
  - Stores the `SignedVoluntaryExit` as JSON in the output directory
  - File name: `<pubkey>_exit.json`
  - Exit message uses current epoch (EIP-7044 guarantees validity across future forks)
- New CLI command: `rvc submit-exit --file <path>`
  - Reads a stored `SignedVoluntaryExit` JSON file
  - Submits to the beacon node via `/eth/v1/beacon/pool/voluntary_exits`
  - Does NOT require signing keys
- Keymanager API integration: `POST /rvc/v1/validator/{pubkey}/prepare_exit`
  - Returns the `SignedVoluntaryExit` without submitting it
  - Allows programmatic exit preparation

**Acceptance criteria:**
- `prepare-exit` produces a valid JSON file containing a `SignedVoluntaryExit`
- `submit-exit` submits the stored exit without access to signing keys
- Stored exits remain valid after hard forks (EIP-7044)
- API endpoint returns the signed exit without submitting to beacon node

**Dependencies:** Extends existing voluntary exit infrastructure in CLI and Keymanager API.

---

#### FR-14: Health-Based BN Tier Selection [P2]

**Description:** Replace binary synced/not-synced BN classification with a tiered system based on sync distance.

**Reference implementations:** Lighthouse (4 tiers with configurable sync distance thresholds)

**Requirements:**
- Define 4 health tiers:
  - **Tier 1 — Synced**: head slot within 1 slot of wall clock (eligible for all duties)
  - **Tier 2 — Small lag**: 2-16 slots behind (eligible for attestations and sync committee, not proposals)
  - **Tier 3 — Large lag**: 17-64 slots behind (eligible for submissions only)
  - **Tier 4 — Unsynced**: >64 slots behind or unreachable (not eligible for any duty)
- Tier thresholds configurable via TOML config
- Duty routing respects tier eligibility:
  - Proposals: Tier 1 only
  - Attestation data / sync committee: Tier 1 + Tier 2
  - Submissions (broadcast): Tier 1 + Tier 2 + Tier 3
- Fall back to lower tiers if no BNs available at required tier (with WARN log)
- Expose per-BN tier as Prometheus metric: `rvc_bn_health_tier`

**Acceptance criteria:**
- BN 2 slots behind is Tier 2 (used for attestations, not proposals)
- BN 20 slots behind is Tier 3 (used for submissions only)
- If only Tier 2 BNs are available and a proposal is needed, Tier 2 is used with WARN log
- Tier transitions are logged at DEBUG level
- Current binary sync check behavior is equivalent to Tier 1 + Tier 4 only (backwards compatible default)

**Dependencies:** Refactors `BnSyncStatus` in `crates/bn-manager/src/sync_status.rs`. Should be designed alongside FR-11 (Role-Based BN Assignment).

---

### Tier 5 — Future / Experimental

#### FR-15: Verifying Web3Signer [P2]

**Description:** Remote signer verifies block properties (fee recipient, gas limit) via Merkle proofs before signing.

**Reference implementations:** Nimbus (experimental)

**Requirements:**
- Extend the rvc-signer gRPC signing protocol with optional block verification fields:
  - Expected fee recipient (from validator config)
  - Expected gas limit (from validator config)
  - Merkle proof for fee recipient within the execution payload
- rvc-signer verifies the proof before signing the block
- If verification fails: reject signing request with descriptive error, log at ERROR
- Feature-gated: `--features verifying-signer` (off by default)
- Backwards compatible: verification fields are optional; existing signing protocol unchanged

**Acceptance criteria:**
- rvc-signer rejects block signing when fee recipient doesn't match expected value
- rvc-signer accepts block signing when fee recipient matches via Merkle proof
- Without the feature flag, signing behavior is unchanged
- Invalid Merkle proofs are rejected

**Dependencies:** Requires changes to both rvc (to send proofs) and rvc-signer (to verify). Depends on execution payload tree hash support in `eth-types`.

---

#### FR-16: Native Relay Integration [P2]

**Description:** Communicate directly with MEV relays without the mev-boost middleware.

**Reference implementations:** Vouch (native relay integration)

**Requirements:**
- Implement the MEV-Boost relay API client (relay spec v1):
  - `GET /relay/v1/data/validator_registration`
  - `POST /relay/v1/builder/validators`
  - `GET /relay/v1/data/bidtraces/...`
  - `GET /eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}`
  - `POST /eth/v1/builder/blinded_blocks`
- New CLI flag: `--relay-endpoints <URL1>,<URL2>,...`
- Mutual exclusivity with mev-boost (`--builder-endpoint`): cannot use both
- Multi-relay support: query all relays in parallel, select best bid
- Relay authentication via `--relay-secret-key` (BLS signing for relay registration)
- Timeout and retry configuration per-relay

**Acceptance criteria:**
- Block proposals use relay bids without mev-boost running
- Multi-relay queries select the highest-value bid
- Relay failures fall back to local block production (respects circuit breakers)
- Both `--relay-endpoints` and `--builder-endpoint` produces startup error

**Dependencies:** Depends on FR-1 (circuit breakers). New crate: `crates/relay-client/`.

---

#### FR-17: Gnosis Chain Support [P2]

**Description:** Add Gnosis Chain as a supported network.

**Reference implementations:** Lighthouse, Teku, Nimbus, Lodestar

**Requirements:**
- Add `Gnosis` variant to the `Network` enum with correct genesis constants:
  - Genesis time, genesis validators root, fork schedule
  - Gnosis-specific slot time (5 seconds vs Ethereum's 12 seconds)
  - Gnosis deposit contract address
- Add `Chiado` variant (Gnosis testnet)
- Support Gnosis-specific consensus parameters:
  - Different epochs per sync committee period
  - Different base rewards
  - GNO token denomination
- Extend rvc-keygen with Gnosis Chain support (deposit data, BLS-to-exec-change)

**Acceptance criteria:**
- `rvc --network gnosis` starts and connects to a Gnosis Chain beacon node
- Attestation timing uses 5-second slots
- rvc-keygen generates correct deposit data for Gnosis Chain
- Chiado testnet works for pre-production testing

**Dependencies:** Requires audit of all slot-time assumptions across the codebase (many calculations assume 12-second slots).

---

#### FR-18: SSE Log Streaming API [P2]

**Description:** Real-time Server-Sent Events endpoint for log streaming.

**Reference implementations:** Lighthouse (`GET /lighthouse/logs`)

**Requirements:**
- New HTTP endpoint: `GET /rvc/v1/logs`
- Returns a `text/event-stream` (SSE) response
- Each log event is a JSON object: `{"timestamp": "...", "level": "...", "target": "...", "message": "...", "fields": {...}}`
- Support query parameters:
  - `level=<info|warn|error>`: minimum log level filter (default: info)
  - `target=<module_path>`: filter by tracing target
- Bearer token authentication required
- Connection-scoped: each client gets its own stream; disconnection is clean
- Use a bounded broadcast channel (drop oldest on overflow) to avoid slow clients blocking the logger
- Maximum concurrent SSE connections: 10 (configurable)

**Acceptance criteria:**
- `curl -N -H "Authorization: Bearer <token>" http://localhost:5062/rvc/v1/logs` streams live logs
- Log events are valid JSON with correct fields
- `level=error` only streams ERROR and above
- Slow clients are dropped (bounded channel) without affecting other clients or the validator
- 11th concurrent connection is rejected with 429

**Dependencies:** Requires a custom `tracing::Layer` that broadcasts events to SSE subscribers. Added to Keymanager API server.

---

## Non-Functional Requirements

### Performance

| ID | Requirement |
|----|-------------|
| NFR-1 | Builder circuit breaker state check must add < 1μs to the block production path (atomic load) |
| NFR-2 | Emergency attestation disable toggle must take effect within the current slot (< 12 seconds) |
| NFR-3 | Keystore lock acquisition at startup must complete within 1 second per validator |
| NFR-4 | Log file rotation must not block the validator's hot path; use async/buffered I/O |
| NFR-5 | Proposer config URL refresh must not block duty execution; run in background task |
| NFR-6 | Validator registration batching must complete all batches within 2 epochs |
| NFR-7 | SSE log streaming must not add measurable latency (> 1ms) to the tracing pipeline |

### Security

| ID | Requirement |
|----|-------------|
| NFR-8 | Emergency attestation disable API endpoint must require Bearer token authentication |
| NFR-9 | Keystore lock files must have `0o600` permissions (owner-only read/write) |
| NFR-10 | Proposer config URL fetch must validate TLS certificates by default |
| NFR-11 | Remote monitoring endpoint must use HTTPS by default |
| NFR-12 | Pre-signed exit files must have `0o600` permissions |
| NFR-13 | SSE log stream must not leak sensitive data (signing keys, tokens, passwords) — rely on existing `RedactedUrl`, `TruncatedPubkey`, `SecretKey([REDACTED])` patterns |
| NFR-14 | Native relay integration must use BLS signing for relay authentication |
| NFR-15 | Verifying Web3Signer must reject signing if Merkle proof is invalid or absent (when enabled) |

### Backwards Compatibility

| ID | Requirement |
|----|-------------|
| NFR-16 | All new features must be opt-in or have backwards-compatible defaults |
| NFR-17 | Existing CLI flags, config files, and API endpoints must not change behavior |
| NFR-18 | BnManager's current First/Best/Broadcast strategies must remain the default |
| NFR-19 | Validator config TOML format must remain backwards compatible (new fields are optional) |
| NFR-20 | Feature-gated items (verifying signer, Gnosis) must not affect default build |

### Observability

| ID | Requirement |
|----|-------------|
| NFR-21 | Each new feature must expose relevant Prometheus metrics (documented in feature requirements) |
| NFR-22 | All state transitions (circuit breaker trip/reset, attestation enable/disable, slashed detection) must be logged at WARN or higher |
| NFR-23 | New OpenTelemetry spans must follow existing naming convention: `rvc.<crate>.<operation>` |

## Technical Considerations

### Architecture Impact

The 4-layer crate architecture (Binary → Orchestrator → Domain → Foundation) accommodates all Tier 2-4 features without new layers. Key integration points:

| Feature | Primary Crate(s) | Pattern |
|---------|-----------------|---------|
| Builder circuit breakers | `builder`, coordinator | New `CircuitBreaker` struct in `builder`, queried by coordinator during block production |
| Emergency attestation disable | `rvc` (coordinator) | `Arc<AtomicBool>` injected into coordinator, checked before each attestation duty |
| Slashed auto-shutdown | `rvc` (coordinator), `validator-store` | Background task polls BN; calls `ValidatorStore.set_enabled(false)` on detection |
| Keystore locking | `rvc` (startup) | `flock` at startup before validator activation |
| Dedicated proposer nodes | `bn-manager` | Second `BnManager` instance for proposals |
| Broadcast topics | `bn-manager` | Config-driven branch: broadcast vs. First strategy per message type |
| Remote monitoring | new module in `rvc` | Background task, independent of duty execution |
| Log rotation | `telemetry` | `tracing-appender::rolling` integrated into subscriber stack |
| Proposer config URL | `validator-store`, `rvc` | Background task fetches URL, calls `update_config()` |
| Block selection modes | `builder`, coordinator | Enum-driven block source selection in production path |
| Role-based BN | `bn-manager` | Per-role BN subsets within existing manager |
| Registration batching | `builder` | Chunk iterator over registration list |
| Pre-signed exits | `rvc` (CLI + API) | Serialize `SignedVoluntaryExit` to JSON file |
| Health-based BN tiers | `bn-manager` | Replace `BnSyncStatus` binary with 4-tier enum |

### New Crates

| Crate | Tier | Justification |
|-------|------|---------------|
| `crates/relay-client` | 5 | Native relay integration has distinct API surface and auth model; warrants isolation from `beacon` crate |

All other features fit within existing crates.

### Dependencies (Estimated New)

| Crate | Feature | Purpose |
|-------|---------|---------|
| `tracing-appender` | FR-8 (log rotation) | Non-blocking file appender with rotation |
| `flate2` | FR-8 (log compression) | gzip compression for rotated logs |
| `fs2` or `file-lock` | FR-4 (keystore locking) | Cross-platform file locking |

All other features use existing dependencies (`axum`, `reqwest`, `tokio`, `serde`, `prometheus`, `tracing`).

### Configuration Precedence

For features with multiple configuration sources (TOML, CLI, URL):

```
CLI flag (highest) > URL config > TOML file > Default (lowest)
```

This matches Prysm and Teku precedence models.

## Out of Scope

The following are explicitly **not** included in this PRD:

- **Obol Charon / SSV middleware integration** — rvc already has native DVT via Shamir Secret Sharing; middleware compatibility is a separate initiative
- **EIP-3076 slashing protection improvements** — existing implementation passes all 76 conformance tests and is sufficient
- **AWS/Azure secret management** — GCP Secret Manager is already supported; other cloud providers are a separate effort
- **GUI / web dashboard** — rvc is a CLI tool; dashboards are built by ecosystem tooling on top of the Keymanager API
- **Beacon node implementation** — rvc is a validator client only; it does not implement the beacon chain
- **Keymanager API v2** — no breaking changes to existing endpoint contracts
- **Backwards-incompatible config changes** — all TOML/CLI changes are additive
- **Windows support** — advisory file locking uses Unix `flock`; Windows support is a future consideration
- **Rate limiting on Keymanager API** — not required by the spec; can be added by reverse proxy
- **Multi-process validator splitting** — running different validators in different processes; use separate rvc instances

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| **Circuit breaker mis-calibration** — defaults too aggressive (disable builder unnecessarily) or too lenient (don't protect fast enough) | Missed proposals or continued exposure to relay failures | Medium | Default values match Prysm (3 consecutive, 5 per epoch); make configurable; log all trips for operator tuning |
| **Keystore locking incompatible with DVT** — DVT setups legitimately run multiple signers with overlapping key material | DVT users locked out | Medium | Provide `--disable-keystore-locking` flag; document DVT exception in operator guide |
| **Slashing detection false positive** — beacon node returns stale validator status | Healthy validator disabled unnecessarily | Low | Require 2 consecutive slashed statuses before action; allow manual re-enable via API |
| **Log rotation data loss** — rotation during crash loses buffered but unflushed data | Missing log data for incident investigation | Medium | Use `tracing-appender` non-blocking writer with flush-on-shutdown hook; accept small window of loss on hard crash |
| **Proposer config URL becomes single point of failure** — URL unreachable means stale config | Incorrect fee recipients or builder settings | Medium | Retain last-known-good config on fetch failure; alert on consecutive failures; cap max staleness |
| **Native relay integration duplicates mev-boost** — relay API surface is complex and evolving | Maintenance burden, spec drift | High | Feature-gate behind `--features native-relay`; ensure circuit breakers work identically for both paths; consider as experimental until relay spec stabilizes |
| **Gnosis Chain slot time assumption** — 5-second slots may break code that assumes 12-second slots | Incorrect timing for all duties | High | Audit all slot-time calculations; parameterize slot duration from network config; extensive testnet validation |
| **SSE log stream memory pressure** — many slow clients with large buffer | OOM or degraded performance | Low | Bounded broadcast channel (drop oldest); max concurrent connections (default: 10); per-connection timeout |
| **Health-based tier thresholds not portable** — optimal thresholds differ across networks and BN implementations | Sub-optimal BN selection | Medium | Make thresholds configurable; start with Lighthouse's proven defaults; document tuning guidance |

## References

- [Ethereum Builder Specifications](https://github.com/ethereum/builder-specs) — MEV-Boost relay API
- [Ethereum Beacon APIs](https://github.com/ethereum/beacon-APIs) — Beacon node API specification
- [EIP-7044: Perpetually Valid Signed Voluntary Exits](https://eips.ethereum.org/EIPS/eip-7044) — Enables pre-signed exit storage
- [Lighthouse Book: BN Management](https://lighthouse-book.sigmaprime.io/advanced-datadir.html) — Dedicated proposer nodes, broadcast topics, health tiers
- [Prysm Documentation: Builder Configuration](https://prysm.offchainlabs.com/docs/) — Circuit breaker flags, proposer settings URL
- [Teku Documentation: Validator Configuration](https://docs.teku.consensys.io/) — Slashed auto-shutdown, keystore locking, proposer config refresh
- [Nimbus Guide: Multi-BN Setup](https://nimbus.guide/) — Role-based BN assignment, verifying Web3Signer
- [Lodestar Documentation: Block Selection](https://chainsafe.github.io/lodestar/) — 6 block selection strategies
- [Vouch GitHub: Strategy Configuration](https://github.com/attestantio/vouch) — Native relay integration, per-operation node assignment
- [beaconcha.in Monitoring API](https://beaconcha.in/api/v1/docs) — Remote monitoring endpoint specification
- [Gnosis Chain Documentation](https://docs.gnosischain.com/) — Gnosis-specific consensus parameters
- [MEV-Boost Relay Specification](https://flashbots.notion.site/Relay-API-Spec) — Native relay API reference
- `plan/VALIDATOR_CLIENT_COMPARISON.md` — Cross-client feature comparison (source of gap analysis)
- `plan/tier1/prd.md` — Tier 1 PRD (format reference and completed work)
- `plan/tier1/architecture.md` — Tier 1 architecture (existing patterns)
- `REVIEW.md` — Current codebase review with remaining findings
