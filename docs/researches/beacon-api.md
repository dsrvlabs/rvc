# Research: Beacon Node API Compatibility

## Summary

The Ethereum Beacon API is the standard REST interface between Validator Clients and Beacon Nodes, defined in the [ethereum/beacon-APIs](https://github.com/ethereum/beacon-APIs) repository [1]. While the spec is well-defined, real-world implementations have subtle differences in response formats, SSZ support, error handling, and timing behavior. A new VC must be tested against all five major BN implementations and implement defensive parsing throughout.

## Key Concepts

### API Versioning

The Beacon API uses path-based versioning (`/eth/v1/`, `/eth/v2/`, `/eth/v3/`) [1]:
- **v1**: Original endpoints, still used for most operations
- **v2**: Fork-aware endpoints that include `Eth-Consensus-Version` header (e.g., block retrieval)
- **v3**: Unified endpoints (e.g., block production combining blinded and unblinded flows)

### Content Negotiation

Responses can be JSON (default) or SSZ [1][2]:
- **JSON**: `Accept: application/json` (default if no Accept header)
- **SSZ**: `Accept: application/octet-stream`
- SSZ responses include `Eth-Consensus-Version` header for deserialization context [1]
- Not all endpoints support SSZ — primarily block and state endpoints

## How It Works — VC-Required Endpoints

### Duty Fetching

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/validator/duties/attester/{epoch}` | POST | Get attester duties | Body: list of validator indices |
| `/eth/v1/validator/duties/proposer/{epoch}` | GET | Get proposer duties | Returns all proposers for epoch |
| `/eth/v1/validator/duties/sync/{epoch}` | POST | Get sync committee duties | Body: list of validator indices |

### Block Production

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v3/validator/blocks/{slot}` | GET | Produce block (blinded or unblinded) | Preferred unified endpoint [3] |
| `/eth/v2/validator/blocks/{slot}` | GET | Produce unblinded block | Legacy; still supported |
| `/eth/v1/validator/blinded_blocks/{slot}` | GET | Produce blinded block | Legacy builder flow |

The v3 endpoint returns:
- `Eth-Execution-Payload-Blinded: true/false` header to indicate block type
- `Eth-Execution-Payload-Value` header with block value in wei
- `Eth-Consensus-Version` header for fork context

### Attestation

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/validator/attestation_data` | GET | Get attestation data | Params: slot, committee_index |
| `/eth/v1/beacon/pool/attestations` | POST | Submit attestation | Body: list of attestations |
| `/eth/v1/validator/aggregate_attestation` | GET | Get aggregate attestation | Params: slot, attestation_data_root |
| `/eth/v1/validator/aggregate_and_proofs` | POST | Submit aggregates | Body: list of signed aggregates |

### Sync Committee

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/beacon/pool/sync_committees` | POST | Submit sync committee messages | Body: list of messages |
| `/eth/v1/validator/sync_committee_contribution` | GET | Get contribution | Params: slot, subcommittee_index, beacon_block_root |
| `/eth/v1/validator/contribution_and_proofs` | POST | Submit contributions | Body: list of signed contributions |

### State and Config

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/config/spec` | GET | Get chain config | Fork epochs, fork versions, constants [4] |
| `/eth/v1/beacon/states/head/fork` | GET | Get current fork | Returns current fork version |
| `/eth/v1/beacon/genesis` | GET | Get genesis info | Genesis time, validators root |
| `/eth/v1/node/syncing` | GET | Check sync status | Is syncing, head slot, sync distance |
| `/eth/v1/node/version` | GET | Get BN version | Useful for logging/debugging |

### Builder / MEV

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/validator/register_validator` | POST | Register validators with builders | Body: list of signed registrations |
| `/eth/v1/validator/liveness/{epoch}` | POST | Check validator liveness | For doppelganger detection [5] |

### Key Management (Keymanager API)

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/keystores` | GET/POST/DELETE | Manage validator keystores | Standard Keymanager API [6] |
| `/eth/v1/remotekeys` | GET/POST/DELETE | Manage remote signing keys | Web3Signer integration |

### Events (SSE)

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/events` | GET (SSE) | Subscribe to events | Topics: head, block, attestation, finalized_checkpoint, etc. |

Supported topics for VC: `head`, `block`, `finalized_checkpoint`, `chain_reorg`, `contribution_and_proof`, `payload_attributes` [7]

### Other VC Operations

| Endpoint | Method | Purpose | Notes |
|----------|--------|---------|-------|
| `/eth/v1/beacon/pool/voluntary_exits` | POST | Submit voluntary exit | Signed exit message |
| `/eth/v1/beacon/blocks` | POST | Publish signed block | v2 is fork-aware |
| `/eth/v1/beacon/blinded_blocks` | POST | Publish signed blinded block | For builder flow |
| `/eth/v1/validator/prepare_beacon_proposer` | POST | Prepare proposer | Fee recipient, per-validator |
| `/eth/v2/validator/beacon_committee_subscriptions` | POST | Subscribe to committees | For subnet attestation aggregation |

## Known Inconsistencies Between Implementations

### JSON Serialization Quirks

- **Quoted integers**: The Beacon API spec requires all integer fields to be serialized as quoted strings (e.g., `"slot": "12345"`, not `"slot": 12345`) [1]. Most BNs comply, but edge cases exist in error responses and non-standard extensions.
- **Optional fields**: Some BNs omit optional fields entirely; others include them as `null`. Deserializers must handle both with `#[serde(default)]` and `Option<T>`.
- **Enum encoding**: SSZ and JSON encode enums differently. Do not share a single serde configuration for both.

### Prysm API History

- Prysm historically used **gRPC** as its primary BN-VC interface with a gRPC-gateway for REST [8]
- The gRPC gateway was removed in v5.1.1, completing migration to the standard REST API [8]
- Some Prysm-specific behaviors persist in edge cases
- Prysm operators using older versions may have non-standard API behavior

### SSZ Support Variance

SSZ response support varies significantly across BNs [2]:

| Endpoint Category | Lighthouse | Prysm | Teku | Nimbus | Lodestar |
|-------------------|-----------|-------|------|--------|----------|
| Block production | SSZ supported | SSZ supported | SSZ supported | SSZ supported | SSZ opt-in [9] |
| State queries | SSZ supported | Limited | SSZ supported | SSZ supported | Limited |
| Duties (attester/proposer) | JSON only | JSON only | JSON only | JSON only | JSON only |
| Attestation submission | JSON only | JSON only | JSON only | JSON only | JSON only |

**Recommendation**: Start with JSON for all endpoints. Add SSZ for block production in Phase 4 for performance (200-250ms savings on large blocks [10]).

### Event Stream (SSE) Differences

- **`payload_attributes` event**: Requires Lighthouse `--always-prepare-payload` and `--suggested-fee-recipient` flags [7]. Prysm v4.0.6+ supports it.
- **Reconnection behavior**: SSE auto-reconnect behavior differs. Use `reqwest-eventsource` which handles reconnection [11].
- **Event format**: Generally consistent, but test payload structures against each BN.

### Fork-Specific API Changes

| Fork | API Impact |
|------|-----------|
| Altair | Added sync committee endpoints |
| Bellatrix | Added execution payload to blocks; v2 block endpoints |
| Capella | Added BLS-to-execution-change endpoints; withdrawal fields |
| Deneb | Added blob sidecar endpoints; `BlockContents` wraps block + blobs [12] |
| Electra | Deterministic proposer lookahead (EIP-7917) [13]; `proposer_lookahead` in beacon state |

**Deneb block production**: After Deneb, the produce block endpoint returns `BlockContents` containing both the block and blob sidecars. The publish endpoint also broadcasts blobs [12].

**Electra proposer lookahead** (EIP-7917): A deterministic `proposer_lookahead` is pre-calculated and stored in the beacon state [13]. This may change how VCs fetch proposer duties in the future.

## Connection Management Best Practices

### Multi-BN Setup

1. **Connection pooling**: Reuse HTTP connections via `reqwest::Client` (automatic with client reuse)
2. **Per-BN timeouts**: Use shorter timeouts for time-sensitive operations (attestation: 2s, block proposal: 4s) and longer for general queries (30s)
3. **Health checking**: Poll `/eth/v1/node/syncing` periodically; weight BNs by latency + sync status + error rate
4. **Broadcast on submit**: Send signed attestations/blocks to ALL configured BNs for maximum propagation
5. **Failover on query**: Use primary BN for duty queries; failover to secondary on failure

### Timeout Strategy

| Operation | Suggested Timeout | Rationale |
|-----------|------------------|-----------|
| Duty queries | 5s | Not time-critical; runs at epoch boundaries |
| Attestation data | 2s | Must complete within slot timing window |
| Block production | 4s | Time-sensitive; includes BN-builder negotiation |
| Block/attestation submission | 5s | Should succeed quickly; retry on secondary BN |
| State queries | 30s | Large responses; not time-critical |
| SSE connection | No timeout (keep-alive) | Long-lived; reconnect on drop |

### Rate Limiting

- BNs generally don't rate-limit VC traffic, but avoid unnecessary polling
- Fetch duties once per epoch, not per slot
- Cache BN config/spec (fetch once at startup, refresh on fork transitions)
- Use SSE events for head tracking instead of polling

## Common Pitfalls

- **Assuming all BNs return SSZ for all endpoints.** They do not. Always implement JSON fallback [2].
- **Forgetting the `Eth-Consensus-Version` header.** Required for SSZ deserialization and fork-aware endpoints [1].
- **Not handling quoted integers.** The Beacon API quotes all integers as strings. Use `ethereum_serde_utils::quoted_u64` [14].
- **Ignoring BN sync status.** A syncing BN returns stale data. Check `/eth/v1/node/syncing` before relying on responses.
- **Hardcoding fork epochs.** Always load from `/eth/v1/config/spec`. Different networks have different schedules.
- **Not testing against all five BN implementations.** Subtle differences will cause production failures.

## Further Reading

- [Ethereum Beacon APIs Specification](https://ethereum.github.io/beacon-APIs/) — Interactive API docs [1]
- [ethereum/beacon-APIs GitHub](https://github.com/ethereum/beacon-APIs) — Source of truth for the spec [1]
- [EIP-7917: Deterministic Proposer Lookahead](https://eips.ethereum.org/EIPS/eip-7917) — Upcoming API changes [13]
- [Lighthouse Beacon Node API](https://lighthouse-book.sigmaprime.io/api-bn.html) — Lighthouse-specific docs
- [Prysm Beacon Node API](https://prysm.offchainlabs.com/docs/apis/ethereum-public-api/) — Prysm REST API docs

## Sources

[1] [Ethereum Beacon APIs Specification](https://ethereum.github.io/beacon-APIs/) — Ethereum Foundation. Official rendered specification.
[2] [Provide first-class SSZ support — Issue #250](https://github.com/ethereum/beacon-APIs/issues/250) — Beacon APIs. SSZ performance (40-50x faster, 67% size reduction) and endpoint coverage discussion.
[3] [Consolidating blinded/unblinded flow — Issue #309](https://github.com/ethereum/beacon-APIs/issues/309) — v3 produce_block endpoint design.
[4] [/eth/v1/config/spec documentation](https://www.quicknode.com/docs/ethereum/eth-v1-config-spec) — QuickNode. Config/spec response format.
[5] [Add liveness endpoint — PR #131](https://github.com/ethereum/beacon-APIs/pull/131) — Paul Hauner. Doppelganger liveness API.
[6] [Ethereum Keymanager APIs](https://github.com/ethereum/keymanager-APIs) — Ethereum Foundation. Key management standard.
[7] [SSE subscription for payload_attributes — Issue #244](https://github.com/ethereum/beacon-APIs/issues/244) — Event stream discussion.
[8] [Prysm APIs](https://hackmd.io/@prysmaticlabs/prysm-api) — Prysmatic Labs. gRPC to REST migration.
[9] [A Lodestar for Consensus 2024](https://blog.chainsafe.io/a-lodestar-for-consensus-2024/) — ChainSafe. SSZ wire format opt-in.
[10] [Add SSZ for block production — Issue #4531](https://github.com/sigp/lighthouse/issues/4531) — Lighthouse. 200-250ms savings.
[11] [reqwest-eventsource](https://lib.rs/crates/reqwest-eventsource) — SSE client with auto-reconnect.
[12] [Blob Signing APIs — Issue #300](https://github.com/ethereum/beacon-APIs/issues/300) — Deneb block+blob production.
[13] [EIP-7917: Deterministic Proposer Lookahead](https://eips.ethereum.org/EIPS/eip-7917) — Ethereum Improvement Proposals.
[14] [ethereum_serde_utils](https://github.com/sigp/ethereum_serde_utils) — Sigma Prime. Hex encoding, quoted integers for Beacon API JSON.
