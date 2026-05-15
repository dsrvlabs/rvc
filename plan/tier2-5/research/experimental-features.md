# Experimental/Future Features Research

**Date**: 2026-04-01
**Scope**: Research on experimental and future features for rvc (Rust Validator Client)
**Topics**: Verifying Web3Signer, Native Relay Integration, Gnosis Chain, SSE Log Streaming, MEV-Boost Relay API

---

## Table of Contents

1. [Nimbus Verifying Web3Signer](#1-nimbus-verifying-web3signer)
2. [Vouch Native Relay Integration](#2-vouch-native-relay-integration)
3. [Gnosis Chain Support Requirements](#3-gnosis-chain-support-requirements)
4. [Lighthouse SSE Log Streaming](#4-lighthouse-sse-log-streaming)
5. [MEV-Boost Relay API Specification](#5-mev-boost-relay-api-specification)

---

## 1. Nimbus Verifying Web3Signer

### Status

**Experimental. Not recommended for production use.** The Nimbus documentation explicitly states: "this functionality is not currently recommended for production use, and all details are subject to change after a planned security audit of the implementation." The remote keystore format version was bumped to **v3** to accommodate this feature.

### Overview

The verifying Web3Signer is an extension to the standard Web3Signer protocol. It allows a remote signer to **verify specific block properties via Merkle proofs** before creating a BLS signature. This addresses a key trust concern: when using a remote signer, the validator client asks the signer to sign a block, but the signer has no way to verify that the block contains the expected fee recipient, gas limit, or graffiti. A malicious or compromised validator client could submit a block with a different fee recipient, stealing rewards.

### Merkle Proof Mechanism

The `BLOCK_V2` request type on the `/api/v1/eth2/sign/{identifier}` endpoint is extended with an additional `proofs` array field. Each proof object contains:

| Field   | Description |
|---------|-------------|
| `index` | A generalized index of any property nested under the block body |
| `proof` | The corresponding Merkle proof against the block body root included in the request |
| `value` | Optional; included only when the SSZ hash does not match the raw field value |

The remote signer verifies each incoming Merkle proof using the standardized `is_valid_merkle_branch` function (from the Ethereum consensus spec). This function takes the leaf value, the proof branch, the depth, the generalized index, and the root, and confirms the leaf is part of the tree.

### Verifiable Block Properties

Properties are configured by **path notation** rather than raw generalized indices, because generalized indices change between hard forks as the BeaconBlockBody SSZ container evolves:

- `.execution_payload.fee_recipient` -- ensures block rewards go to the correct address
- `.graffiti` -- verifies the graffiti field matches expectations

Gas limit verification is not explicitly documented in the current Nimbus implementation, though the mechanism is general enough to support any SSZ field path under the block body.

### Configuration

**Remote keystore file** (placed in the validators directory):

```json
{
  "version": 3,
  "type": "verifying-web3signer",
  "pubkey": "0x8107ff...",
  "remote": "http://127.0.0.1:15052",
  "proven_block_properties": [
    { "path": ".execution_payload.fee_recipient" },
    { "path": ".graffiti" }
  ]
}
```

**Command-line flags** (alternative to keystore files):

- `--verifying-web3-signer` -- enable the verifying protocol
- `--proven-block-property=.execution_payload.fee_recipient` -- can be specified multiple times

### Implementation Details for rvc

To implement this in rvc, the following would be needed:

1. **SSZ Merkle proof generation**: Compute the generalized index for a given field path at the current fork. Use `tree_hash` (already a dependency) to generate inclusion proofs against the `BeaconBlockBody` root.
2. **Fork-aware index mapping**: The generalized index for `.execution_payload.fee_recipient` differs between Capella, Deneb, and Electra because the `BeaconBlockBody` SSZ container adds/removes fields at each fork. The index must be recomputed per fork.
3. **Extended signing request**: Add the `proofs` array to the Web3Signer `BLOCK_V2` request payload.
4. **Signer-side verification**: If rvc-signer is the target, add Merkle proof verification using `is_valid_merkle_branch`.

### Gotchas

- Generalized indices change with every hard fork. Any hardcoded index table must be updated.
- The `value` field in the proof is only needed when the SSZ hash of the field does not equal the field itself (i.e., for variable-length fields or nested containers). For `fee_recipient` (a fixed 20-byte value), the SSZ leaf is the value itself zero-padded to 32 bytes.
- This is a Nimbus-specific extension. No other client implements it yet. There is no EIP or consensus spec standardizing it.
- A security audit is pending. The protocol may change.

### Sources

- [Nimbus Web3Signer Guide](https://nimbus.guide/web3signer.html)
- [Nimbus CLI Options](https://nimbus.guide/options.html)
- [Nimbus v23.5.0 Release (introduced verifying web3signer)](https://github.com/status-im/nimbus-eth2/releases/tag/v23.5.0)
- [Nimbus v22.11.1 Release (initial work)](https://github.com/status-im/nimbus-eth2/releases/tag/v22.11.1)

---

## 2. Vouch Native Relay Integration

### Status

**Production.** Vouch is actively used by institutional staking operators (Attestant's own infrastructure and clients). The relay integration is a core feature, not experimental.

### Overview

Vouch (by Attestant) is a Go-based multi-node validator client middleware. Unlike standard validator clients that delegate MEV to an external `mev-boost` sidecar process, Vouch **acts as its own MEV-boost server**, communicating directly with MEV relays and presenting the standard builder API to beacon nodes. Beacon nodes connect to Vouch's built-in MEV-boost service (default port `18550`) instead of an external mev-boost instance.

### Architecture

```
Standard flow:    Beacon Node --> mev-boost --> Relay(s)
Vouch flow:       Beacon Node --> Vouch (built-in relay client) --> Relay(s)
```

Vouch uses the [go-builder-client](https://pkg.go.dev/github.com/attestantio/go-builder-client/api) library for relay communication. This library implements versioned types for all builder API interactions across Bellatrix, Capella, Deneb, Electra, and Fulu forks.

### Relay Communication

Vouch communicates with MEV relays for three operations:

| Operation | Default Timeout | Description |
|-----------|----------------|-------------|
| Validator registration | 10s | Periodic registration with relays (every epoch) |
| Bid fetching (auction) | 5s | Request execution payload headers from relays |
| Block unblinding | 5s | Submit signed blinded block, receive full payload |

### Multi-Relay Bid Selection

Vouch supports two bid selection strategies:

**1. `best` strategy**: Queries all configured relays once, selects the highest-value bid.

```yaml
strategies:
  builderbid:
    style: 'best'
    best:
      timeout: '2s'
```

**2. `deadline` strategy**: Repeatedly queries relays until a deadline expires, capturing better bids that arrive over time.

```yaml
strategies:
  builderbid:
    style: 'deadline'
    deadline:
      deadline: '1s'
      bid-gap: '100ms'
```

The `bid-gap` parameter controls the minimum interval between re-queries.

### Per-Validator Relay Configuration

Vouch supports a three-tier configuration hierarchy:

1. **Validator-specific** (`proposer_config` entries) -- highest priority
2. **Default configuration** (`default_config`) -- secondary
3. **Fallback values** (Vouch config) -- lowest priority

Each validator can have different relays, fee recipients, and gas limits:

```yaml
blockrelay:
  fallback-fee-recipient: '0x0123...cdef'
  fallback-gas-limit: 30000000
  config:
    url: 'file:///home/vouch/config.json'
```

The execution config file is **refreshed every epoch**, enabling live adjustments without restart.

### Bid Verification and Builder Scoring

- Relays can include a **public key** in the URL's username section. If present, Vouch verifies BLS signatures on bids before considering them. Otherwise, bids are trusted.
- Builder-specific scoring adjustments are supported:

```yaml
builder-configs:
  '0xaaaa...':
    category: 'privileged'
    factor: 1000000000    # strongly prefer this builder
  '0xbbbb...':
    category: 'excluded'
    factor: 0             # ignore this builder
```

Final bid score = `(base_value + offset) * (factor / 100)`

### Builder-Boost Factor

The `builder-boost-factor` setting (default: `91`) controls the preference for builder payloads vs locally-produced blocks. A value of 91 means the builder bid must be at least ~10% more valuable than the local block to be selected.

### Key Go Types (go-builder-client)

```go
// Bid request options
type BuilderBidOpts struct {
    Slot       phase0.Slot
    ParentHash phase0.Hash32
    PubKey     phase0.BLSPubKey
}

// Validator registration
type SubmitValidatorRegistrationsOpts struct {
    Registrations []*VersionedSignedValidatorRegistration
}

// Blinded block submission
type UnblindProposalOpts struct {
    Proposal *consensusapi.VersionedSignedBlindedProposal
}

// Versioned responses span Bellatrix through Fulu
type VersionedSubmitBlindedBlockResponse struct {
    Version   consensusspec.DataVersion
    Bellatrix *bellatrix.ExecutionPayload
    Capella   *capella.ExecutionPayload
    Deneb     *deneb.ExecutionPayloadAndBlobsBundle
    Electra   *deneb.ExecutionPayloadAndBlobsBundle
    Fulu      *fulu.ExecutionPayloadAndBlobsBundle
}
```

### Auction Logging

Enabling `log-results: true` generates structured logs per auction showing:
- Each relay's bid value
- Delta from the winning bid
- Whether the bid was selected

### Gotchas

- Vouch is Go-only. There is no Rust crate. A Rust implementation would need to reimplement the relay client from scratch using the builder API spec.
- The bid scoring formula with `factor` and `offset` is Vouch-specific. Other implementations just pick the highest value.
- The `deadline` strategy adds latency but may capture higher-value bids that arrive late in the slot.
- Relay URL format with embedded pubkey: `https://<relay_pubkey>@relay.example.com/`

### Sources

- [Vouch Execution Layer Docs](https://github.com/attestantio/vouch/blob/master/docs/execlayer.md)
- [Vouch Configuration Docs](https://github.com/attestantio/vouch/blob/master/docs/configuration.md)
- [go-builder-client API Package](https://pkg.go.dev/github.com/attestantio/go-builder-client/api)
- [go-relay-client Repository](https://github.com/attestantio/go-relay-client)
- [Vouch Block Relay v2 Package](https://pkg.go.dev/github.com/attestantio/vouch/services/blockrelay/v2)
- [Introducing Vouch (Attestant blog)](https://www.attestant.io/posts/introducing-vouch/)
- [Exploring the Impact of MEV Relays (Attestant blog)](https://www.attestant.io/posts/exploring-the-impact-of-mev-relays/)

---

## 3. Gnosis Chain Support Requirements

### Status

**Production network.** Gnosis Chain is a fully operational PoS network with its own validator set. Four consensus clients support it: Lighthouse, Lodestar, Nimbus, and Teku.

### Key Differences from Ethereum Mainnet

| Parameter | Ethereum Mainnet | Gnosis Mainnet | Impact on VC |
|-----------|-----------------|----------------|--------------|
| `SECONDS_PER_SLOT` | 12 | **5** | All slot-based timers must use config, not hardcoded 12s |
| `SLOTS_PER_EPOCH` | 32 | **16** | Epoch boundary logic changes |
| Epoch duration | 6.4 min | **80 seconds** | More frequent duty rotations |
| Finalization time | ~12.8 min | **~2.7 min** | Faster finality |
| Staking amount | 32 ETH | **1 GNO (32 mGNO)** | Different deposit amount validation |
| `EJECTION_BALANCE` | 16 ETH | **16 mGNO (16 GNO gwei)** | Different ejection threshold |
| `DEPOSIT_CHAIN_ID` | 1 | **100** | Network identification |
| `PRESET_BASE` | mainnet | **gnosis** | Different SSZ presets |
| `MAX_BLOBS_PER_BLOCK` | 6 | **2** | Fewer blobs per block |
| `SECONDS_PER_ETH1_BLOCK` | 14 | **6** | Faster EL block times |
| `ETH1_FOLLOW_DISTANCE` | 2048 | **1024** | Different deposit processing lag |

### Fork Versions (Gnosis Mainnet)

| Fork | Version | Epoch |
|------|---------|-------|
| Genesis (Phase0) | `0x00000064` | 0 |
| Altair | `0x01000064` | 512 |
| Bellatrix | `0x02000064` | 385,536 |
| Capella | `0x03000064` | 648,704 |
| Deneb | `0x04000064` | 889,856 |
| Electra | `0x05000064` | 1,337,856 |
| Fulu | `0x06000064` | 1,714,688 |

Pattern: Gnosis uses `0x0N000064` where `N` is the fork number and `0x64` (100 decimal) is the Gnosis "area code" matching Chain ID 100.

### Chiado Testnet

| Parameter | Value |
|-----------|-------|
| `CONFIG_NAME` | `chiado` |
| `PRESET_BASE` | `gnosis` |
| `GENESIS_FORK_VERSION` | `0x0000006f` |
| `ALTAIR_FORK_VERSION` | `0x0100006f` |
| `BELLATRIX_FORK_VERSION` | `0x0200006f` |
| `CAPELLA_FORK_VERSION` | `0x0300006f` |
| `DENEB_FORK_VERSION` | `0x0400006f` |
| `ELECTRA_FORK_VERSION` | `0x0500006f` |
| `FULU_FORK_VERSION` | `0x0600006f` |
| `DEPOSIT_CONTRACT_ADDRESS` | `0xb97036A26259B7147018913bD58a774cf91acf25` |
| `DEPOSIT_CHAIN_ID` | 10200 |
| `DEPOSIT_NETWORK_ID` | 10200 |
| `SECONDS_PER_SLOT` | 5 |
| `MIN_GENESIS_TIME` | 1665396000 (Oct 10, 2022) |
| `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT` | 6000 |

Chiado uses `0x0N00006f` where `0x6f` (111 decimal) distinguishes it from mainnet. Chiado has a semi-permissioned validator set, similar to Ethereum's Sepolia.

### Deposit Contract

| Network | Deposit Contract |
|---------|-----------------|
| Gnosis Mainnet | `0x0B98057eA310F4d31F2a452B414647007d1645d9` |
| Chiado Testnet | `0xb97036A26259B7147018913bD58a774cf91acf25` |

There is also a GNO-to-mGNO converter contract at `0x647507A70Ff598F386CB96ae5046486389368C66` (mainnet only). Validators deposit 1 GNO which is internally converted to 32 mGNO (milliGNO).

### Supported Clients

**Execution Layer** (Gnosis only supports these two):
- Nethermind
- Erigon

**Consensus Layer** (all four supported):
- Lighthouse
- Lodestar
- Nimbus
- Teku

**Not Supported**: Prysm (consensus), Geth/Besu/Reth (execution)

### Implementation Requirements for rvc

1. **Parameterize all timing constants**: `SECONDS_PER_SLOT` and `SLOTS_PER_EPOCH` must come from configuration, not hardcoded values. This affects:
   - Slot timer intervals
   - Attestation deadline calculations (1/3 into the slot)
   - Aggregation deadline calculations (2/3 into the slot)
   - Epoch boundary detection

2. **Add `gnosis` preset**: The `PRESET_BASE: gnosis` uses different SSZ container sizes than `mainnet`. This affects committee sizes and validator counts per slot.

3. **Fork version configuration**: Add Gnosis mainnet and Chiado fork versions and epochs to the network configuration. The pattern (`0x0N000064` / `0x0N00006f`) should be stored in config, not computed.

4. **Deposit contract addresses**: Add the Gnosis deposit contract address for any deposit-related functionality.

5. **Genesis constants**: Add `MIN_GENESIS_TIME` and `GENESIS_VALIDATORS_ROOT` for both Gnosis mainnet and Chiado (similar to existing Holesky/Sepolia support).

6. **Domain separation**: Fork versions determine BLS signing domains. Using the wrong fork version would produce invalid signatures. The validator client must use the correct fork version from the beacon node's `/eth/v1/config/spec` response.

### Gotchas

- The 5-second slot time means the validator client has much less time to complete attestation and block proposal duties. Any latency issues that are tolerable on Ethereum (12s slots) become critical on Gnosis.
- The `gnosis` preset has different `MAX_VALIDATORS_PER_COMMITTEE` and other committee parameters. SSZ containers that include these as fixed-size lists will have different sizes.
- Gnosis has `MAX_BLOBS_PER_BLOCK: 2` vs Ethereum's 6, which affects blob sidecar handling.
- The canonical configuration source is the [gnosischain/configs](https://github.com/gnosischain/configs) repository, not the Ethereum consensus specs.

### Sources

- [Gnosis Chain Specs (Contracts, Addresses, Parameters)](https://docs.gnosischain.com/about/specs/gbc/)
- [Gnosis Mainnet Config](https://github.com/gnosischain/configs/blob/main/mainnet/config.yaml)
- [Gnosis Chiado Config](https://github.com/gnosischain/configs/blob/main/chiado/config.yaml)
- [Chiado Testnet Docs](https://docs.gnosischain.com/about/networks/chiado)
- [Gnosis Node Guide (supported clients)](https://docs.gnosischain.com/node/)
- [Gnosis Mainnet Network Page](https://docs.gnosischain.com/about/networks/mainnet)
- [Gnosis Dencun Hard Fork Announcement](https://www.gnosis.io/blog/gnosis-chain-cancun-deneb-dencun-hard-fork-announcement)

---

## 4. Lighthouse SSE Log Streaming

### Status

**Production.** Available since Lighthouse v4.2.0 (for the VC API) and present in the BN API for longer. Requires the `--gui` flag to enable.

### Overview

Lighthouse exposes a `GET /lighthouse/logs` SSE (Server-Sent Events) endpoint that streams log messages in real-time over HTTP. This is a Lighthouse-specific extension (not part of the Eth Beacon API standard). It enables external GUIs and monitoring tools to consume logs without parsing stdout/stderr.

### Enabling the Endpoint

The `--gui` flag enables SSE logging. It implicitly also enables:
- `--http` (the HTTP API)
- `--validator-monitor-auto` (automatic validator monitoring)

Without `--gui`, the `/lighthouse/logs` endpoint is not available.

### Event Format

Each SSE event is a JSON object with the following fields:

```json
{
  "time": "Mar 13 15:28:41",
  "level": "INFO",
  "msg": "Syncing",
  "service": "slot_notifier",
  "est_time": "3 hrs",
  "speed": "5.33 slots/sec",
  "distance": "41052",
  "peers": "50"
}
```

Standard fields:
- `time` -- Human-readable timestamp (local time for text format, RFC 3339 UTC for JSON format)
- `level` -- Log level: `INFO`, `WARN`, `ERRO`, `CRIT` (and higher)
- `msg` -- The log message
- `service` -- The originating service/module (e.g., `slot_notifier`, `beacon`)

Additional fields vary by log event and include contextual key-value pairs like `speed`, `distance`, `peers`, etc.

### Log Levels

The SSE endpoint currently exposes **INFO and higher** level logs. DEBUG and TRACE are not streamed. The overall log level can be controlled with the `--debug-level` CLI flag, but the SSE endpoint filters to INFO+.

### Implementation Architecture

Lighthouse's logging uses the `tracing` crate ecosystem:

1. **`LoggingLayer`** (in `common/logging/src/tracing_logging_layer.rs`): A custom `tracing::Layer` implementation that intercepts log events. It supports dual output:
   - **Text format**: Human-readable with local timestamps
   - **JSON format**: Structured with UTC RFC 3339 timestamps, fields for `msg`, `level`, `ts`, `module`

2. **Field handling**: A `FieldVisitor` extracts message content, strings, numbers, booleans, and debug values. Events inherit field data from parent spans, with event-level fields taking precedence over span-level fields on collision.

3. **Broadcast channel**: The SSE streaming uses a `tokio::sync::broadcast` channel pattern. The logging layer sends events to a broadcast sender, and each SSE client connection receives events via a broadcast receiver. This allows multiple concurrent SSE clients.

4. **Channel capacity**: Lighthouse historically had issues with logging channel overflow (Issue [#1464](https://github.com/sigp/lighthouse/issues/1464)). The capacity was increased from 128 to **2048** messages to prevent log drops, especially for operators running large validator sets (1000+ validators). Memory overhead: ~400 KB (2048 x ~200 bytes per message).

### Backpressure Handling

When the broadcast channel is full (slow consumers), the `tokio::sync::broadcast` channel's behavior is:
- **Lagged receivers**: Slow consumers that fall behind receive a `RecvError::Lagged(n)` error, indicating `n` messages were skipped. They automatically resume from the latest message.
- **No sender blocking**: The sender (logging layer) never blocks. It always succeeds in sending, but old messages are overwritten for slow receivers.
- This means the validator client's logging performance is never degraded by slow SSE consumers, at the cost of consumers potentially missing messages.

### Implementation for rvc

To implement SSE log streaming in rvc:

1. **Tracing layer**: Create a custom `tracing::Layer` that serializes log events to JSON and sends them to a `tokio::sync::broadcast::Sender<String>`.

2. **SSE endpoint**: Add `GET /rvc/logs` (or similar) to the HTTP API using axum's SSE support:

```rust
use axum::response::sse::{Event, Sse};
use tokio_stream::wrappers::BroadcastStream;

async fn logs_handler(
    State(log_sender): State<broadcast::Sender<String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receiver = log_sender.subscribe();
    let stream = BroadcastStream::new(receiver)
        .filter_map(|result| match result {
            Ok(msg) => Some(Ok(Event::default().data(msg))),
            Err(BroadcastStreamRecvError::Lagged(_)) => None,  // skip gaps
        });
    Sse::new(stream)
}
```

3. **Capacity**: Use a broadcast channel capacity of 2048+ based on Lighthouse's experience.

4. **Feature gate**: Gate behind a CLI flag (e.g., `--gui` or `--sse-logging`) since it adds overhead.

### Gotchas

- The SSE endpoint streams continuously. Clients must handle reconnection (standard SSE behavior).
- Lighthouse only exposes INFO+. Streaming DEBUG/TRACE would be very high volume.
- The `tokio::sync::broadcast` channel drops old messages for slow consumers rather than applying backpressure. This is the correct behavior for logging (never block the producer), but clients should handle gaps.
- JSON log format changed in Lighthouse v7.1.0 when they migrated from `slog` to `tracing`. Any parser should target the tracing-based format.
- This is a Lighthouse-specific API. Other clients do not implement it. There is no standard for it.

### Sources

- [Lighthouse API Documentation (includes /lighthouse/logs)](https://lighthouse-book.sigmaprime.io/api-lighthouse.html)
- [Lighthouse Beacon Node API](https://lighthouse-book.sigmaprime.io/api-bn.html)
- [Lighthouse Logging Channel Capacity Issue #1464](https://github.com/sigp/lighthouse/issues/1464)
- [Lighthouse Tracing Logging Layer Source](https://github.com/sigp/lighthouse/blob/stable/common/logging/src/tracing_logging_layer.rs)
- [Lighthouse v4.2.0 Release (VC SSE logging)](https://newreleases.io/project/github/sigp/lighthouse/release/v4.2.0)
- [Lighthouse v7.1.0 Release (tracing migration)](https://github.com/sigp/lighthouse/releases/tag/v7.1.0)

---

## 5. MEV-Boost Relay API Specification

### Status

**Production standard.** The Builder API is defined by the Ethereum Foundation in [ethereum/builder-specs](https://github.com/ethereum/builder-specs). The Relay API extends it with data endpoints and is defined by Flashbots in [flashbots/relay-specs](https://github.com/flashbots/relay-specs). Both are actively used by all major relays (Flashbots, bloXroute, Ultra Sound, Aestus, Agnostic Gnosis, etc.).

### API Overview

There are two complementary specs:

1. **Builder API** (ethereum/builder-specs) -- Validator/BN-facing endpoints for block building
2. **Relay API** (flashbots/relay-specs) -- Builder-facing and data query endpoints

### Builder API Endpoints (Validator-Facing)

These are the endpoints that mev-boost (or a native relay client) calls on relays:

#### `GET /eth/v1/builder/status`

Health check endpoint. Returns 200 if the relay is operational.

#### `POST /eth/v1/builder/validators`

Register validators with the relay. Must be called periodically (every `EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION` = 1 epoch).

**Request body**: Array of `SignedValidatorRegistration`:

```json
[
  {
    "message": {
      "fee_recipient": "0x...",
      "gas_limit": "30000000",
      "timestamp": "1234567890",
      "pubkey": "0x..."
    },
    "signature": "0x..."
  }
]
```

The `ValidatorRegistrationV1` message fields:
- `fee_recipient`: Execution layer address for rewards
- `gas_limit`: Preferred block gas limit
- `timestamp`: Anti-DoS timestamp (must be recent, monotonically increasing)
- `pubkey`: Validator BLS public key

The signature uses BLS with `DOMAIN_APPLICATION_BUILDER` (domain type `0x00000001`).

#### `GET /eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}`

Request an execution payload header (bid) from the relay.

**Parameters**:
- `slot`: The slot being proposed
- `parent_hash`: Hash of the parent execution block (from `state.latest_execution_payload_header.block_hash`)
- `pubkey`: Proposer's BLS public key

**Response**: `SignedBuilderBid` containing:

```json
{
  "version": "deneb",
  "data": {
    "message": {
      "header": { /* ExecutionPayloadHeader */ },
      "blob_kzg_commitments": ["0x..."],
      "value": "1234567890",
      "pubkey": "0x..."
    },
    "signature": "0x..."
  }
}
```

The `value` is the bid amount in wei. The validator must verify:
- `header.parent_hash == expected_parent_hash`
- `header.fee_recipient == registered_fee_recipient`
- The BLS signature is valid against the relay's public key using `DOMAIN_APPLICATION_BUILDER`

#### `POST /eth/v1/builder/blinded_blocks` (v1)
#### `POST /eth/v2/builder/blinded_blocks` (v2)

Submit a signed blinded block and receive the full execution payload.

**Request body**: `SignedBlindedBeaconBlock` -- the beacon block with `ExecutionPayloadHeader` instead of full `ExecutionPayload`.

**Response**: The full `ExecutionPayload` (and `BlobsBundle` for Deneb+).

The response type varies by fork:
- Bellatrix: `ExecutionPayload`
- Capella: `ExecutionPayload`
- Deneb/Electra: `ExecutionPayloadAndBlobsBundle`
- Fulu: `ExecutionPayloadAndBlobsBundle` (with updated BlobsBundle)

### Relay API Endpoints (Builder-Facing and Data)

These are Flashbots relay-specific extensions (v3.0.3):

#### `GET /relay/v1/builder/validators`

Returns the list of registered validators for the current and next epoch. Builders use this to know which validators are registered and their fee recipient preferences.

#### `POST /relay/v1/builder/blocks`

Submit a new block to the relay. Fork-versioned request schemas:
- `Bellatrix.SubmitBlockRequest`
- `Capella.SubmitBlockRequest`
- `Deneb.SubmitBlockRequest`
- `Electra.SubmitBlockRequest`
- `Fulu.SubmitBlockRequest`

#### `GET /relay/v1/data/bidtraces/proposer_payload_delivered`

Query historical records of delivered payloads. Useful for analytics.

#### `GET /relay/v1/data/bidtraces/builder_blocks_received`

Query historical records of blocks received from builders.

#### `GET /relay/v1/data/validator_registration`

Query validator registration history.

### Authentication

There is **no explicit authentication mechanism** in the relay API spec. Security relies on:

1. **BLS signatures**: Validator registrations are signed. Bids from relays are signed. Blinded blocks are signed by the proposer.
2. **Relay public keys**: The relay's BLS public key is embedded in the relay URL (`https://<pubkey>@relay.example.com/`). Clients verify bid signatures against this key.
3. **HTTPS**: Transport security via TLS.
4. **Rate limiting**: Relays implement their own rate limiting (not standardized).

### Block Proposal Safety Requirements

The builder spec mandates these safety measures:

1. **Parallel local building**: Validators MUST run local block building as a fallback. Never depend solely on external builders.
2. **Timeout**: Allow builders `BUILDER_PROPOSAL_DELAY_TOLERANCE` (1 second) before aborting.
3. **No double signing**: Once committed to either external or local block via signature, cancel the other. Signing two distinct blocks in the same slot is a slashable offense.
4. **Circuit breaker**: Disable builder usage during chain instability (e.g., missed finality).

### Fork Versioning

All builder API types are versioned per consensus fork. The `version` field in responses indicates which schema to deserialize:
- `"bellatrix"`, `"capella"`, `"deneb"`, `"electra"`, `"fulu"`

The v2 blinded blocks endpoint uses a `Content-Type` header or `Eth-Consensus-Version` header to indicate the fork version, avoiding the need for response sniffing.

### Implementation for rvc (Native Relay Client)

To implement direct relay communication (like Vouch does), rvc would need:

1. **Relay client**: HTTP client that implements all four builder API endpoints. Use `reqwest` with connection pooling and timeouts.

2. **Multi-relay orchestration**: Query multiple relays in parallel, select the best bid. Handle relay failures gracefully.

3. **BLS verification**: Verify relay bid signatures against the relay's public key. Use `blst` (already a dependency).

4. **Validator registration**: Periodically (every epoch) sign and submit `ValidatorRegistrationV1` for all active validators.

5. **Blinded block handling**: After selecting a bid, construct a `BlindedBeaconBlock`, sign it, submit to the winning relay, receive the full payload.

6. **Fork-aware deserialization**: Handle all fork versions in request/response types. SSZ and JSON support needed.

7. **Circuit breaker**: Implement liveness-based circuit breaking. If the chain has not finalized in N epochs, fall back to local block building only.

### Gotchas

- The bid `value` is in wei and can be zero. A zero-value bid is valid but means no MEV was extracted.
- Relays may return different bid values for the same slot over time. The `deadline` strategy (like Vouch) can capture late-arriving higher bids.
- The relay may fail to return the full payload after you submit the blinded block (relay down, network issue). This is why local fallback is mandatory.
- Different relays have different latency characteristics. Timeout tuning per relay may be necessary.
- The `Eth-Consensus-Version` header is required for v2 endpoints.
- Blobs handling (Deneb+) adds significant complexity. The response includes `ExecutionPayload` + `BlobsBundle` (commitments, proofs, blobs).
- There is no standardized relay discovery. Relay URLs are configured manually.

### Sources

- [Ethereum Builder Specs (official)](https://github.com/ethereum/builder-specs)
- [Builder API Interactive Docs](https://ethereum.github.io/builder-specs/)
- [Builder Spec - Validator Interaction (Bellatrix)](https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/validator.md)
- [Builder API OpenAPI Spec](https://github.com/ethereum/builder-specs/blob/main/builder-oapi.yaml)
- [Flashbots Relay Specs](https://github.com/flashbots/relay-specs)
- [Flashbots Relay API Interactive Docs](https://flashbots.github.io/relay-specs/)
- [Flashbots Relay Fundamentals](https://docs.flashbots.net/flashbots-mev-boost/relay)
- [Flashbots mev-boost-relay Implementation](https://github.com/flashbots/mev-boost-relay)
- [MEV-Boost in a Nutshell](https://boost.flashbots.net/)
