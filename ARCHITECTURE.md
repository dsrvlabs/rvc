# Architecture

RVC is a Rust-based Ethereum Validator Client built as a modular workspace of 18 crates. It handles the full validator lifecycle: block proposals, attestations, sync committee participation, aggregation duties, slashing protection, multi-BN failover, doppelganger detection, MEV/builder integration, and runtime key management via the Keymanager API.

## System Overview

```mermaid
graph TB
    subgraph External
        BN[Beacon Nodes]
        KS[Keystore Files<br/>EIP-2335]
        W3S[Web3Signer]
        DB[(SQLite<br/>Slashing DB)]
        PROM[Prometheus]
    end

    subgraph RVC["RVC Validator Client"]
        BIN[bin/rvc<br/>CLI & Bootstrap]
        ORCH[DutyOrchestrator]
        BNM[BnManager<br/>Multi-BN Failover]
        KMA[Keymanager API<br/>:5062]
        MS[Metrics Server<br/>:8080]

        BIN -->|builds| ORCH
        ORCH -->|queries/submits| BNM
    end

    BNM <-->|HTTP API| BN
    KS -->|load keys| BIN
    W3S <-->|HTTP signing| RVC
    DB <-->|read/write| ORCH
    KMA <-->|key mgmt| RVC
    MS -->|expose| PROM
```

## Crate Dependency Graph

```mermaid
graph TD
    BIN["bin/rvc<br/><i>CLI entry point</i>"]
    RVC["rvc<br/><i>orchestrator</i>"]
    BEACON["beacon<br/><i>HTTP client</i>"]
    BNM["bn-manager<br/><i>multi-BN</i>"]
    CRYPTO["crypto<br/><i>BLS, signing, Web3Signer</i>"]
    SIGNER["signer<br/><i>safe signing</i>"]
    SLASHING["slashing<br/><i>EIP-3076</i>"]
    DUTY["duty-tracker<br/><i>duty cache</i>"]
    PROP["propagator<br/><i>message submit</i>"]
    TIMING["timing<br/><i>slot clock</i>"]
    METRICS["metrics<br/><i>prometheus</i>"]
    ETH["eth-types<br/><i>consensus types</i>"]
    BLOCK["block-service<br/><i>block proposals</i>"]
    SYNC["sync-service<br/><i>sync committees</i>"]
    DOPP["doppelganger<br/><i>duplicate detection</i>"]
    BUILD["builder<br/><i>MEV registration</i>"]
    VSTORE["validator-store<br/><i>validator config</i>"]
    KMA["keymanager-api<br/><i>key mgmt REST</i>"]

    BIN --> RVC
    BIN --> BNM
    BIN --> CRYPTO
    BIN --> METRICS
    BIN --> KMA
    BIN --> SLASHING

    RVC --> SIGNER
    RVC --> DUTY
    RVC --> PROP
    RVC --> TIMING
    RVC --> BNM
    RVC --> CRYPTO
    RVC --> SLASHING
    RVC --> METRICS
    RVC --> ETH
    RVC --> BLOCK
    RVC --> SYNC
    RVC --> DOPP
    RVC --> BUILD
    RVC --> VSTORE

    BLOCK --> CRYPTO
    BLOCK --> SIGNER
    BLOCK --> VSTORE
    BLOCK --> ETH

    SYNC --> ETH

    BUILD --> BNM
    BUILD --> CRYPTO
    BUILD --> SIGNER
    BUILD --> VSTORE
    BUILD --> ETH

    DOPP --> ETH

    SIGNER --> CRYPTO
    SIGNER --> SLASHING
    SIGNER --> METRICS
    SIGNER --> ETH

    DUTY --> BNM
    DUTY --> METRICS
    DUTY --> ETH

    PROP --> BNM
    PROP --> METRICS

    BNM --> BEACON
    BNM --> ETH

    TIMING --> ETH

    CRYPTO --> ETH
    SLASHING --> ETH
    SLASHING --> METRICS

    style BIN fill:#4a9eff,color:#fff
    style RVC fill:#ff6b6b,color:#fff
    style ETH fill:#51cf66,color:#fff
    style METRICS fill:#51cf66,color:#fff
    style BEACON fill:#51cf66,color:#fff
    style BNM fill:#51cf66,color:#fff
    style KMA fill:#51cf66,color:#fff
    style VSTORE fill:#51cf66,color:#fff
    style SIGNER fill:#ffd43b,color:#333
    style CRYPTO fill:#ffd43b,color:#333
    style SLASHING fill:#ffd43b,color:#333
    style DUTY fill:#ffd43b,color:#333
    style PROP fill:#ffd43b,color:#333
    style TIMING fill:#ffd43b,color:#333
    style BLOCK fill:#ffd43b,color:#333
    style SYNC fill:#ffd43b,color:#333
    style DOPP fill:#ffd43b,color:#333
    style BUILD fill:#ffd43b,color:#333
```

**Layer colors:**
- **Blue** — Binary entry point
- **Red** — Core orchestrator (depends on all internal crates)
- **Yellow** — Domain crates (duty-specific logic)
- **Green** — Foundation crates (infrastructure, no domain logic)

## Crate Layer Diagram

```mermaid
block-beta
    columns 7

    block:binary:7
        BIN["bin/rvc"]
    end

    space:7

    block:orchestrator:7
        RVC["rvc (orchestrator)"]
    end

    space:7

    block:domain:7
        SIGNER["signer"]
        DUTY["duty-tracker"]
        PROP["propagator"]
        TIMING["timing"]
        BLOCK["block-service"]
        SYNC["sync-service"]
        BUILD["builder"]
    end

    space:7

    block:foundation:7
        CRYPTO["crypto"]
        SLASHING["slashing"]
        BNM["bn-manager"]
        BEACON["beacon"]
        METRICS["metrics"]
        ETH["eth-types"]
        KMA["keymanager-api"]
    end

    BIN --> RVC
    RVC --> SIGNER
    RVC --> DUTY
    RVC --> PROP
    RVC --> TIMING
    RVC --> BLOCK
    RVC --> BUILD
    SIGNER --> CRYPTO
    SIGNER --> SLASHING
    DUTY --> BNM
    PROP --> BNM
    BNM --> BEACON

    style binary fill:#4a9eff,color:#fff
    style orchestrator fill:#ff6b6b,color:#fff
    style domain fill:#ffd43b,color:#333
    style foundation fill:#51cf66,color:#fff
```

## Slot Processing — 3-Phase Architecture

```mermaid
sequenceDiagram
    participant Clock as SlotClock
    participant Orch as DutyOrchestrator
    participant DT as DutyTracker
    participant BNM as BnManager
    participant Block as BlockService
    participant Sync as SyncService
    participant Signer as SignerService
    participant Prop as Propagator
    participant Builder as BuilderService

    Note over Clock,Builder: Epoch boundary (once per 32 slots)
    Orch->>DT: fetch attester + proposer + sync committee duties
    Orch->>BNM: prepare_beacon_proposer (fee recipients)
    Orch->>BNM: submit committee subscriptions

    Note over Clock,Builder: Phase 1 — t=0 (slot start)
    alt Validator is proposer
        Orch->>Block: propose_block(slot, pubkey, fork)
        Block->>Signer: sign_randao_reveal(epoch)
        Block->>BNM: produce_block_v3(slot, randao, graffiti)
        Block->>Signer: sign_block(root, pubkey)
        Block->>BNM: publish_block / publish_blinded_block
    end

    Note over Clock,Builder: Phase 2 — t=slot/3 (4s)
    Orch->>Signer: sign_attestation(data, pubkey)
    Orch->>Prop: submit_attestations(signed)
    Orch->>Sync: produce_sync_messages(slot, duties, head_root)
    Sync->>BNM: submit_sync_committee_messages(msgs)

    Note over Clock,Builder: Phase 3 — t=2*slot/3 (8s)
    Orch->>Prop: submit aggregate attestations
    Orch->>Sync: produce_contributions(slot, duties, head_root)
    Sync->>BNM: submit_contribution_and_proofs(proofs)

    Note over Clock,Builder: Post-duty (epoch boundary only)
    Orch->>Builder: register_validators (with jitter)
```

## Block Proposal Lifecycle

```mermaid
flowchart TD
    A[Slot start, validator is proposer] --> B[Sign RANDAO reveal<br/>DOMAIN_RANDAO]
    B --> C[produce_block_v3<br/>graffiti, builder_boost_factor]
    C --> D{Blinded?}
    D -->|Yes| E[SlashingDb<br/>is_safe_to_propose]
    D -->|No| E
    E -->|Slashable| X1[REJECT: DoubleProposal]
    E -->|Safe| F[Sign block<br/>DOMAIN_BEACON_PROPOSER]
    F --> G[Record block in SlashingDb]
    G --> H{Blinded?}
    H -->|Yes| I[publish_blinded_block<br/>broadcast to all BNs]
    H -->|No| J[publish_block<br/>broadcast to all BNs]

    style X1 fill:#ff6b6b,color:#fff
    style I fill:#51cf66,color:#fff
    style J fill:#51cf66,color:#fff
```

## Signing Flow

```mermaid
flowchart TD
    A[Signing Request] --> B{Message Type}
    B -->|Attestation| C{SlashingDb<br/>check_and_record_attestation}
    B -->|Block| D{SlashingDb<br/>check_and_record_block}
    B -->|Sync Committee| E[No slashing check]
    B -->|Builder Registration| F[No slashing check<br/>zeroed genesis root]

    C -->|Double Vote| X1[REJECT]
    C -->|Surround Vote| X2[REJECT]
    C -->|Safe| G[CompositeSigner]
    D -->|Double Proposal| X3[REJECT]
    D -->|Safe| G
    E --> G
    F --> G

    G -->|Remote key| H[Web3Signer<br/>POST /api/v1/eth2/sign]
    G -->|Local key| I[BLS sign<br/>blst library]
    G -->|Not found| X4[REJECT: KeyNotFound]

    H --> J[Return Signature]
    I --> J

    style X1 fill:#ff6b6b,color:#fff
    style X2 fill:#ff6b6b,color:#fff
    style X3 fill:#ff6b6b,color:#fff
    style X4 fill:#ff6b6b,color:#fff
    style J fill:#51cf66,color:#fff
```

## Startup Sequence

```mermaid
flowchart TD
    A[Parse CLI + Config] --> B[Open SlashingDb]
    B --> C[Integrity check<br/>PRAGMA integrity_check]
    C -->|Fail| X1[Refuse to start]
    C -->|Pass| D[Create BnManager]
    D --> E[Validate genesis_validators_root<br/>against beacon node]
    E -->|Mismatch| X2[Refuse to start]
    E -->|Match| F[Check beacon node sync status]
    F --> G[Load validator keys<br/>→ CompositeSigner]
    G --> H{Doppelganger<br/>enabled?}
    H -->|Yes| I[Run 2-epoch monitoring]
    I -->|Detected| X3[Exit code 2]
    I -->|Safe| J[Build services]
    H -->|No| J
    J --> K[Start DutyOrchestrator]
    J --> L[Start Metrics Server :8080]
    J --> M[Start Keymanager API :5062]

    style X1 fill:#ff6b6b,color:#fff
    style X2 fill:#ff6b6b,color:#fff
    style X3 fill:#ff6b6b,color:#fff
```

## Service Construction

```mermaid
flowchart LR
    CONFIG[Config / CLI Args] --> BIN[bin/rvc]

    BIN --> BNM[BnManager<br/>multi-BN failover]
    BIN --> CS[CompositeSigner<br/>local + remote keys]
    BIN --> SDB[SlashingDb]
    BIN --> SC[SystemSlotClock]
    BIN --> VS[ValidatorStore]

    BNM --> DT[DutyTracker]
    BNM --> PROP[Propagator]
    BNM --> BUILD[BuilderService]

    CS --> SS[SignerService]
    SDB --> SS

    SS --> BLOCK[BlockService]
    VS --> BLOCK

    DT --> ORCH[DutyOrchestrator]
    PROP --> ORCH
    SS --> ORCH
    SC --> ORCH
    BLOCK --> ORCH
    BUILD --> ORCH

    BIN --> MS[MetricsServer<br/>:8080]
    BIN --> KMA[Keymanager API<br/>:5062]
    BIN --> GRPC[gRPC Server<br/>:50051]

    style CONFIG fill:#e9ecef,color:#333
    style BIN fill:#4a9eff,color:#fff
    style ORCH fill:#ff6b6b,color:#fff
```

## Workspace Crates

### `bin/rvc` — CLI Entry Point

Binary crate. Parses CLI arguments (via `clap`), loads TOML configuration, initializes logging, runs the startup sequence (slashing integrity → genesis validation → BN sync check → doppelganger detection), builds all services, and runs the `DutyOrchestrator`. Manages graceful shutdown on SIGTERM/SIGINT. Optionally starts the Keymanager API server and configures remote signing.

### `crates/rvc` — Core Orchestrator

Central coordination crate. Contains:

- **`DutyOrchestrator<C, S, B>`** — Main loop with 3-phase slot processing: t=0 block proposals, t=slot/3 attestations + sync messages, t=2*slot/3 aggregations + contributions. Generic over `SlotClock`, `AttestationSubmitter`, and `BeaconBlockClient` for testability.
- **`Config`** / **`Network`** — Configuration types with network presets (Mainnet, Hoodi, Custom).
- **`OrchestratorConfig`** — Fork schedule, genesis root, shutdown timeout.
- **Adapter modules** — `beacon_adapter`, `doppelganger_adapter`, `keymanager_adapters` bridge domain traits to concrete services.
- **gRPC DutyTracker service** — Exposes a `Healthz` RPC via tonic.

### `crates/bn-manager` — Multi-BN Management

Manages connections to one or more Beacon Nodes with strategy-based selection, health scoring, failover, sync status monitoring, and SSE event subscription.

- **`BeaconNodeClient` trait** — Unified async interface for all BN operations. All domain crates depend on this trait, not on `BeaconClient` directly.
- **`BnManager`** — Wraps multiple `BeaconClient` instances. Selection strategies: `First` (lowest latency), `Best` (highest-value response for block production), `Broadcast` (submit to all BNs).
- **Health scoring** — EMA latency (α=0.3), sliding window error rate, composite score (0.4×latency + 0.6×error).
- **SSE events** — Head, ChainReorg, FinalizedCheckpoint, Block.
- **Sync checking** — Monitors `el_offline`, `is_optimistic`, `sync_distance`.

### `crates/block-service` — Block Proposals

Orchestrates the block proposal lifecycle: RANDAO reveal → block production → slashing check → signing → publication.

- **`BlockService<S, B>`** — Generic over `Signer` trait and `BeaconBlockClient`.
- **`BeaconBlockClient` trait** — `produce_block`, `publish_block`, `publish_blinded_block`.
- Handles both full and blinded (MEV) blocks via `Eth-Execution-Payload-Blinded` header.

### `crates/sync-service` — Sync Committees

Produces and submits sync committee messages (at t=slot/3) and contributions (at t=2*slot/3).

- **`SyncService<S, B>`** — Generic over `SyncSigner` and `SyncBeaconClient`.
- **Aggregator selection** — Computes selection proof, checks against `TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE`.
- **Constants** — `SYNC_COMMITTEE_SIZE = 512`, `SYNC_COMMITTEE_SUBNET_COUNT = 4`.

### `crates/builder` — MEV & Builder Integration

Builder registration management and proposer preparation.

- **`BuilderService`** — Batch-signs `ValidatorRegistrationV1` with `DOMAIN_APPLICATION_BUILDER` (zeroed genesis root), submits via `register_validator` endpoint.
- **`prepare_proposers`** — Sends fee recipients to BN at epoch start.
- **Jitter** — Random 0–30s delay before registration to spread load.
- Registration runs at epoch boundary AFTER all duty phases.

### `crates/doppelganger` — Doppelganger Detection

Detects duplicate validator instances before activating signing (Lodestar pattern).

- **`DoppelgangerService`** — 2-epoch monitoring via `post_validator_liveness` endpoint.
- **Restart-aware** — Validators with recent slashing DB entries skip detection.
- **`DoppelgangerStatus`** — `Safe`, `DetectionInProgress`, `DoppelgangerDetected`.

### `crates/beacon` — Beacon Node HTTP Client

Low-level async HTTP client for the Ethereum Beacon Node API. Provides methods for all standard endpoints: duties, block production, attestations, sync committees, voluntary exits, validator liveness. Includes configurable retry logic with exponential backoff.

Used internally by `bn-manager`; domain crates depend on `BeaconNodeClient` trait instead.

### `crates/eth-types` — Ethereum Consensus Types

Pure data types with SSZ encoding/decoding and tree hashing. Defines all consensus types: `Slot`, `Epoch`, `Root`, `ForkName`, `ForkSchedule`, `AttestationData`, `BeaconBlock`, `BlindedBeaconBlock`, `SyncCommitteeMessage`, `SyncCommitteeContribution`, `ValidatorRegistrationV1`, `VoluntaryExit`, and all domain constants.

Quoted-integer serde via `ethereum_serde_utils` for API compatibility. No business logic. No internal dependencies.

### `crates/crypto` — BLS Cryptography & Signing

Wraps the `blst` library for BLS12-381 operations:

- **`Signer` trait** — Async, object-safe (`dyn Signer`), `Send + Sync`. Abstracts local vs remote signing.
- **`LocalSigner`** — In-memory key manager wrapping `KeyManager`.
- **`RemoteSigner`** — Web3Signer HTTP client (`POST /api/v1/eth2/sign/{identifier}`).
- **`CompositeSigner`** — Routes: remote → dynamic local → base local. Supports runtime key add/remove.
- **`KeyManager`** — Loads EIP-2335 keystores, stores keys in `HashMap<pubkey_hex, SecretKey>`.
- **Signing functions** — `sign_attestation`, `sign_block`, `sign_randao_reveal`, `sign_sync_committee_message`, `sign_contribution_and_proof`, `sign_aggregate_and_proof`, `sign_selection_proof`, `sign_voluntary_exit`, `sign_builder_registration`.
- **`Zeroize` on drop**, `SecretString` for passwords, `DecryptionAttemptTracker` for brute-force protection.

### `crates/signer` — Safe Signing with Slashing Protection

Combines `crypto` and `slashing` into a safe signing workflow:

- **`SignerService`** — Implements `ValidatorSigner` trait. Every signing operation: slashing check → retrieve key → compute domain → sign → record in DB → update metrics.
- **`ValidatorSigner` trait** — Methods for all message types: attestations, blocks, sync committee, aggregation, RANDAO, voluntary exits, builder registrations.
- **Fail-closed** — Any slashing DB error refuses to sign.

### `crates/slashing` — Slashing Protection (EIP-3076)

SQLite-backed slashing protection for attestations and blocks:

- **Attestation rules** — Double vote, surrounding vote, surrounded vote.
- **Block rule** — Double proposal (same slot, different signing root).
- **`check_and_record_attestation`** / **`check_and_record_block`** — Atomic check-and-record.
- **Integrity checks** — `PRAGMA integrity_check` at startup, genesis root validation.
- **Pruning** — Watermark-based pruning for source epoch, target epoch, and block slot.
- **EIP-3076 interchange** — Import/export for keystore migration.
- **Conformance** — 76 EIP-3076 tests (38 complete + 38 minimal strategy).

### `crates/keymanager-api` — Keymanager REST API

HTTP server for runtime key management per the Ethereum Keymanager API standard:

- **Endpoints** — `GET/POST/DELETE /eth/v1/keystores`, `GET/POST/DELETE /eth/v1/remotekeys`.
- **Authentication** — Bearer token (256-bit CSPRNG, hex-encoded, `0o400` file permissions, constant-time comparison via `subtle`, `Zeroizing<String>`).
- **Traits** — `KeystoreManager`, `RemoteKeyManager`, `SlashingProtectionExporter`, `ValidatorManager`, `DoppelgangerMonitor`.
- **Key import** — Imports keystore → adds to `CompositeSigner` → imports slashing protection → triggers doppelganger detection.

### `crates/validator-store` — Per-Validator Configuration

Stores per-validator preferences: fee recipient, graffiti, builder settings.

- **`ValidatorStore`** — TOML-backed config with hot-reload (`reload_config` with parse-first/apply-second atomicity).
- **Queries** — `effective_fee_recipient`, `effective_graffiti`.

### `crates/duty-tracker` — Validator Duty Caching

Fetches and caches attester, proposer, and sync committee duties from the beacon node.

- **Attester duties** — Per-epoch cache with dependent root tracking.
- **Proposer duties** — Per-epoch cache, prefetched at epoch start.
- **Sync committee duties** — Per-sync-committee-period cache (~256 epochs).
- Depends on `BnManager` via `BeaconNodeClient` trait.

### `crates/propagator` — Message Propagation

Submits signed messages to beacon node(s). Uses `AttestationSubmitter` trait for dependency injection. Supports attestations and aggregate attestation proofs. Depends on `BnManager` for multi-BN broadcast.

### `crates/timing` — Slot Clock

Slot timing abstraction:

- **`SlotClock` trait** — `current_slot()`, `time_until_slot()`, `time_until_attestation()`, epoch/slot conversions.
- **`SystemSlotClock`** — Production implementation using system time relative to genesis.
- **`MockSlotClock`** — Test implementation with configurable time.

### `crates/metrics` — Prometheus Metrics & Health

Global Prometheus metrics registry. Runs an Axum HTTP server exposing `/metrics` and `/healthz` endpoints. Metrics cover slot processing, attestations, blocks, sync committees, aggregation, slashing protection, BN health, builder registrations, keymanager requests, and DB pruning.

## Key Design Patterns

- **3-phase slot processing** — t=0 blocks, t=slot/3 attestations + sync messages, t=2*slot/3 aggregations + contributions.
- **Trait-based injection** — `BeaconNodeClient`, `SlotClock`, `AttestationSubmitter`, `Signer`, `ValidatorSigner` allow swapping implementations for testing.
- **Composite pattern** — `CompositeSigner` routes local/dynamic/remote keys. `BnManager` routes across multiple BNs.
- **Adapter pattern** — 5 adapters in the orchestrator bridge keymanager-api traits to concrete services.
- **Arc-wrapped services** — All long-lived services are `Arc<T>` for cheap cloning across async tasks.
- **Fail-closed signing** — Any error in the slashing protection path refuses to sign.
- **Downward-only dependencies** — Binary → Orchestrator → Domain → Foundation. Never upward.
- **Graceful shutdown** — `tokio::watch` channel signals completion of current slot before exiting.

## Consensus Protocol Parameters

| Parameter | Value |
|---|---|
| Slot duration | 12 seconds |
| Slots per epoch | 32 |
| Epoch duration | 6.4 minutes |
| Block proposal timing | slot start (t=0) |
| Attestation timing | slot_start + slot_duration / 3 (4s) |
| Aggregation timing | slot_start + 2 * slot_duration / 3 (8s) |
| BLS scheme | BLS12-381, min-pk variant |
| Slashing protection | EIP-3076 (conservative) |
| Keystore format | EIP-2335 |
| Keymanager API | Standard Ethereum Keymanager API |
| Supported forks | Phase0, Altair, Bellatrix, Capella, Deneb, Electra |

## Configuration & Deployment

The validator client is configured via a TOML file or CLI flags:

- Beacon node endpoint(s) (multi-BN supported)
- Keystore directory path and password file
- Slashing DB path
- Fee recipient (default + per-validator overrides)
- Graffiti (default + per-validator overrides)
- Builder preferences (enabled, boost factor)
- Doppelganger detection (`--no-doppelganger` to disable)
- Keymanager API (`--keymanager-enabled`, address, token file)
- Remote signer URL (`--remote-signer-url`)
- Metrics port (default 8080) with `/metrics` and `/healthz`
- gRPC port (default 50051) with `Healthz` RPC
- Network preset or custom genesis parameters
