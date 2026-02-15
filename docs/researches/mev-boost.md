# Research: MEV-Boost / Builder API Integration

## Summary

MEV-Boost is a sidecar for the beacon node that outsources block building to external builders via relays [1]. The VC's role is limited: register validators with builder preferences, request blocks (which may be blinded or unblinded), and sign/submit them. All builder complexity lives in the BN and MEV-Boost — the VC should NOT communicate with builders or relays directly. ePBS (EIP-7732) will eventually enshrine PBS into the protocol, making the current relay-based system obsolete [2].

## Key Concepts

### Architecture Stack

```
Validator Client ←→ Beacon Node ←→ MEV-Boost ←→ Relays ←→ Builders
     (you)            (BN)         (sidecar)     (trusted)  (block builders)
```

The VC interacts only with the Beacon Node via the standard Beacon API. The BN handles all relay/builder communication [1][3].

### Two Separate APIs

1. **Beacon API** (VC ↔ BN): Standard endpoints the VC uses — `/eth/v1/validator/register_validator`, `/eth/v3/validator/blocks/{slot}`, etc. [4]
2. **Builder API** (BN ↔ Relay): Endpoints the BN uses to talk to MEV-Boost/relays — `/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}`, `/eth/v1/builder/blinded_blocks`, etc. [5]

The VC only uses the Beacon API. The Builder API is the BN's responsibility.

### Spec Versioning

Builder API spec (ethereum/builder-specs) [5]:
- v0.4.0 — Deneb support (blob KZG commitments in bids)
- v0.5.0 — Electra support
- v0.6.0 — Fulu support (POST v2/blinded_blocks; relay broadcasts directly)
- v0.6.1 — Current stable (October 2025) [6]

## Builder Registration Flow

### What the VC Does

The VC builds and signs `ValidatorRegistrationV1` messages, then submits them to the BN via `POST /eth/v1/validator/register_validator` [4][7].

**Registration message structure:**
```json
{
  "message": {
    "fee_recipient": "0xabcdef1234567890abcdef1234567890abcdef12",
    "gas_limit": "30000000",
    "timestamp": "1234567890",
    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc..."
  },
  "signature": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e..."
}
```

**Signing domain:** `DOMAIN_APPLICATION_BUILDER` (0x00000001) with **zeroed** `genesis_validators_root` and `fork_version` [8][9]. This is different from other validator signatures that use chain-specific values.

**Registration frequency:**
- The spec suggests once per epoch (EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION = 1) [7]
- Prysm registers at startup + mid-epoch [10]
- Add random jitter to avoid thundering herd at epoch boundaries [11]
- Re-register when fee_recipient or gas_limit changes

**Gas limit:** Builders MUST respect the validator's gas limit preference [12]. The validator sets their preferred gas limit; the builder must build blocks within that limit.

### What the BN Does

The BN forwards registration messages to MEV-Boost, which forwards them to configured relays. The relays store the registration for future block building.

## Blinded Block Flow

### Step-by-Step Sequence

1. **VC signs registration** with proposer settings (fee_recipient, gas_limit)
2. **VC submits registration** via `POST /eth/v1/validator/register_validator`; BN forwards to builder
3. **Validator selected as proposer** for slot N
4. **BN checks builder config** and chain health (circuit breaker)
5. **BN requests header** from relay via Builder API (`GET /eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}`)
6. **BN compares bids** — builder bid vs local block value
7. **BN returns block to VC** — either blinded (builder) or unblinded (local)
8. **VC signs the block** (after slashing protection check)
9. **VC submits signed block** to BN; if blinded, BN submits to relay for unblinding and broadcast

### Using the v3 Block Production Endpoint

The preferred endpoint is `GET /eth/v3/validator/blocks/{slot}` [13]:

```
GET /eth/v3/validator/blocks/{slot}?randao_reveal=0x...&builder_boost_factor=100
```

**Response headers:**
- `Eth-Execution-Payload-Blinded: true|false` — Indicates block type
- `Eth-Execution-Payload-Value: <wei>` — Block value
- `Eth-Consensus-Version: deneb|electra` — Fork version

The VC MUST check the `Eth-Execution-Payload-Blinded` header and handle both paths.

### Block Value Comparison

**`builder_boost_factor` (Lighthouse)** [14]:
```
use_builder = builder_bid_value * builder_boost_factor / 100 > local_block_value
```
- Factor 100 = pure profit maximization (equal comparison)
- Factor > 100 = prefer builder (e.g., 150 = builder gets 50% advantage)
- Factor 0 = always use local

**`local_block_value_boost` (Prysm)** [10][15]:
```
use_builder = builder_bid_value * 100 > local_block_value * (local_block_value_boost + 100)
```
- Default boost: 10 (local gets 10% advantage since v5.0.2)

### Minimum Bid Threshold

Configurable at multiple levels:
- **MEV-Boost:** `-min-bid <ETH>` flag — relays with bids below this are filtered [16]
- **BN/VC:** Per-validator `min_bid_eth` configuration
- When all builder bids are below threshold, MEV-Boost returns 204 (no bid), and BN falls back to local block

### Critical Safety Constraint

**Once a validator signs a blinded block for a slot, it MUST NOT sign any other block for that slot.** Doing so is a slashing offense. The slashing protection DB must record the signing regardless of block type [7].

## Known Issues and Edge Cases

### Timing

| Phase | Time | Notes |
|-------|------|-------|
| Slot start | t=0 | Block should be proposed |
| Attestation deadline | t=4s | Validators vote for head |
| Aggregate deadline | t=8s | Aggregated attestations |
| Slot end | t=12s | Next slot begins |

**MEV-Boost timeout defaults [17]:**
- `getHeader`: 950ms (configurable via `-request-timeout-getheader`)
- `getPayload`: 4000ms
- `registerValidator`: 3000ms
- Lighthouse BN hard timeout: ~1 second [18]

### Builder Failure Modes

| Failure | Behavior |
|---------|----------|
| MEV-Boost unreachable | BN returns local block |
| All relays return 204 (no bid) | BN returns local block |
| Builder bid below min-bid | MEV-Boost returns 204; BN uses local |
| Relay returns invalid header | BN discards bid, uses local |
| Relay timeout (>950ms) | BN uses local block |
| **Relay fails on getPayload** | **Slot may be missed (liveness risk)** |

The most dangerous failure is getPayload failure after signing a blinded block. The validator has committed and cannot sign an alternative without risking slashing [19].

### Circuit Breaker Patterns

Circuit breakers are implemented at the **BN level** (not the VC) [20]:

**Lighthouse [14]:**
- `--builder-fallback-skips <N>`: Consecutive skip slots
- `--builder-fallback-skips-per-epoch <N>`: Skips within epoch
- `--builder-fallback-epochs-since-finalization <N>`: Finality lag

**Prysm [10]:**
- `--max-builder-consecutive-missed-slots` (default: 3)
- `--max-builder-epoch-missed-slots` (default: 5)
- Auto-recovers when conditions clear

**VC implication:** The VC does not need its own circuit breaker. When the BN's circuit breaker is active, it returns unblinded blocks. The VC handles both blinded and unblinded gracefully.

### Relay Trust Assumptions

Relays are "doubly-trusted" [19][21]:
- **By builders:** To fairly route submissions and not steal MEV
- **By proposers:** To provide valid blocks, accurate bid values, and data availability

Risks: fraudulent bids, payload withholding, bid manipulation, censorship. Mitigations: multiple relays, relay monitoring, `min-bid` for some local production, future ePBS [2].

## Upcoming Spec Changes

### ePBS (EIP-7732)

Enshrined Proposer-Builder Separation eliminates trusted relays [2][22]:
- Builders become staked beacon chain entities (min 1 ETH)
- Proposer includes builder's `SignedExecutionPayloadBid` in beacon block (no full payload)
- Payload Timeliness Committee (512 validators) attests to builder behavior
- Payment guaranteed from builder's staked balance
- **Timeline:** Testing on `epbs-devnet-0` as of Q1 2026. Glamsterdam hard fork scope freeze end of Feb 2026 [23].

**Impact on VC:** Current Builder API becomes obsolete. The VC won't handle blinded blocks — PBS is protocol-native. Design registration and block handling behind abstractions for easy replacement.

### Post-Fulu Changes

Builder-specs v0.6.0 [24]:
- `POST /eth/v2/builder/blinded_blocks`: Relays don't return payload in response
- Relay takes responsibility for direct block broadcast
- Builder default gas limit raised from 45M to 60M [25]

### Design for Forward Compatibility

1. **Abstract the builder interface** behind a trait that can swap between current and ePBS
2. **Handle both blinded and unblinded blocks** generically via v3 endpoint
3. **Don't hardcode relay logic in the VC** — all builder complexity lives in the BN
4. **Version the registration flow** for when ePBS changes it
5. **Make builder preference configurable per-validator**

## How Other VCs Implement It

| Pattern | Lighthouse | Prysm |
|---------|-----------|-------|
| Builder config | BN `--builder <URL>` + VC `--builder-proposals` | BN `--http-mev-relay <URL>` + VC `--enable-builder` |
| Per-validator toggle | `validator_definitions.yml` [26] | `proposer-settings-file` JSON |
| Registration frequency | Every epoch | Startup + mid-epoch |
| Block comparison | `builder_boost_factor / 100` | `local_block_value_boost + 100` |
| Default local preference | None (100 = equal) | 10% local boost |
| Circuit breaker | BN-level, multiple flags | BN-level, auto-recovery |
| Builder connection | Single (use MEV-Boost for multi-relay) | Single |

## Common Pitfalls

1. **Signing both blinded and unblinded blocks for the same slot** — slashing offense
2. **Ignoring `Eth-Execution-Payload-Blinded` header** — must handle both block types
3. **Registering with incorrect `fee_recipient`** — payments go to wrong address
4. **Not building locally in parallel** — BN should always have a local fallback
5. **Treating registration as fire-and-forget** — log success/failure, retry on failure
6. **Hardcoding builder API version assumptions** — API evolves with each fork

## Sources

[1] [MEV-Boost GitHub](https://github.com/flashbots/mev-boost) — Flashbots. MEV-Boost sidecar.
[2] [EIP-7732: Enshrined PBS](https://eips.ethereum.org/EIPS/eip-7732) — Ethereum Foundation.
[3] [MEV-Boost in a Nutshell](https://boost.flashbots.net/) — Flashbots. Architecture overview.
[4] [Beacon APIs](https://ethereum.github.io/beacon-APIs/) — Ethereum Foundation.
[5] [Builder API Specification](https://ethereum.github.io/builder-specs/) — Ethereum Foundation. Current v0.6.1.
[6] [Builder-Specs Releases](https://github.com/ethereum/builder-specs/releases) — Release history.
[7] [Builder-Specs Bellatrix Validator Spec](https://github.com/ethereum/builder-specs/blob/main/specs/bellatrix/validator.md) — Core specification.
[8] [Clarify signing routines — Issue #14](https://github.com/ethereum/builder-specs/issues/14) — Signing domain discussion.
[9] [Clarify fork_version — PR #33](https://github.com/ethereum/builder-specs/pull/33) — Zeroed genesis root.
[10] [Prysm Configure MEV Builder](https://prysm.offchainlabs.com/docs/advanced/builder) — Prysm builder integration.
[11] [Registration frequency — Issue #24](https://github.com/ethereum/builder-specs/issues/24) — Frequency optimization.
[12] [Gas Limit in Register Validator — Issue #17](https://github.com/ethereum/builder-specs/issues/17) — Gas limit semantics.
[13] [Consolidating blinded/unblinded flow — Issue #309](https://github.com/ethereum/beacon-APIs/issues/309) — v3 endpoint.
[14] [Lighthouse MEV Documentation](https://lighthouse-book.sigmaprime.io/advanced_builders.html) — Sigma Prime.
[15] [Prysm v5.0.2 Release](https://github.com/prysmaticlabs/prysm/releases/tag/v5.0.2) — Local boost default changed.
[16] [MEV-Boost v1.4.0 Release](https://github.com/flashbots/mev-boost/releases/tag/v1.4.0) — min-bid flag.
[17] [MEV-Boost Usage](https://docs.flashbots.net/flashbots-mev-boost/getting-started/usage) — Default timeouts.
[18] [mev-boost timeout — Issue #4709](https://github.com/sigp/lighthouse/issues/4709) — Lighthouse hard timeout.
[19] [MEV-Boost Risks](https://docs.flashbots.net/flashbots-mev-boost/architecture-overview/risks) — Comprehensive risk analysis.
[20] [MEV-Boost Circuit Breaker Proposal](https://hackmd.io/@ralexstokes/BJn9N6Thc) — Alex Stokes. Original design.
[21] [Relay Fundamentals](https://docs.flashbots.net/flashbots-mev-boost/relay) — Relay trust model.
[22] [EIP-7732 Technical Spec](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7732.md) — Detailed spec.
[23] [Checkpoint #8: Jan 2026](https://blog.ethereum.org/en/2026/01/20/checkpoint-8) — Glamsterdam timeline.
[24] [Builder-Specs v0.6.0](https://github.com/ethereum/builder-specs/releases/tag/v0.6.0) — Fulu changes.
[25] [Prysm v7.0.0 Release](https://github.com/OffchainLabs/prysm/releases/tag/v7.0.0) — Gas limit increase.
[26] [Lighthouse Validator Management](https://lighthouse-book.sigmaprime.io/validator-management.html) — Per-validator config.
