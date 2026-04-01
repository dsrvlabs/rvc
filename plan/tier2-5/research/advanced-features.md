# Advanced Validator Client Features: Cross-Client Research

Research findings on advanced features from other Ethereum validator clients (Lodestar, Nimbus, Lighthouse, Teku) relevant to rvc design.

---

## 1. Lodestar Block Selection Strategies

Lodestar (TypeScript) provides 6 block selection strategies via the `--builder.selection` flag, controlling how the validator chooses between local execution blocks and builder (MEV) blocks.

### All 6 Strategies

| Strategy | `builder.boostFactor` | Behavior |
|---|---|---|
| `default` | `90` | ~10% local block boost. Builder blocks must be >~10% more profitable to be selected. |
| `maxprofit` | `100` | Always picks the more profitable block (no boost either way). |
| `executionalways` | `0` | Always selects local execution block, unless local production fails (then falls back to builder). |
| `executiononly` | N/A | BN only produces local execution block even if builder relays are configured. Errors if local block fails. No builder fallback. |
| `builderalways` | `18446744073709551615` (2^64 - 1) | Always selects builder block, unless builder fails (then falls back to local). |
| `builderonly` | N/A | Only builder blocks. No local execution block production triggered. Fails entirely if builder unavailable. Primarily for DVT setups. |

### How `builder.boostFactor` Works

- The boost factor is a **percentage multiplier** applied to the builder block value when comparing against the local execution block value.
- A value of `100` means 1:1 comparison (maxprofit).
- A value `<100` dampens builder block value (favors local blocks).
- A value `>100` boosts builder block value (favors builder blocks).
- The **calculation happens on the beacon node**, not the validator client. The VC passes the boost factor to the BN via the `produceBlockV3` API (introduced with Deneb).

### Custom Boost Factor Formula

To compute a custom boost factor based on what premium you require from the builder:

```
boostFactor = 100 * 100 / (100 + percentage_premium)
```

Example: To require builder blocks to be 25% more profitable than local:
`10000 / 125 = 80` --> `--builder.boostFactor=80`

### CLI Defaults

- `--builder.selection` default: `"executiononly"` (on the validator CLI page)
- `--builder.boostFactor` default: `"100"` (on the validator CLI page)
- When using the **vc-configuration** (recommended) defaults, the `default` strategy applies `boostFactor=90`

### Key Implementation Details

- The builder/execution race logic was moved from the validator to the beacon node in Lodestar v1.12.0. Both VC and BN must be upgraded together.
- `builderonly` and `executiononly` are "hard" modes -- they error rather than falling back.
- `builderalways` and `executionalways` are "soft" modes -- they prefer one source but fall back to the other on failure.
- The `boostFactor` is ignored if `--builder.selection` is set to anything other than `maxprofit` (or `default` which uses it implicitly).
- `boostFactor` must be an integer; decimal values cause errors.

### Sources

- [Lodestar Validator Configuration](https://chainsafe.github.io/lodestar/run/validator-management/vc-configuration/)
- [Lodestar Validator CLI Reference](https://chainsafe.github.io/lodestar/run/validator-management/validator-cli/)
- [Lodestar v1.12.0 Release Notes](https://github.com/ChainSafe/lodestar/releases/tag/v1.12.0)
- [Lodestar MEV/Builder Integration](https://chainsafe.github.io/lodestar/run/beacon-management/mev-and-builder-integration/)

---

## 2. Nimbus Role-Based Beacon Node Assignment

Nimbus (Nim) supports assigning **specific roles** to each beacon node, enabling fine-grained control over which BN handles which validator duty.

### Configuration Syntax

Roles are configured via **URL fragment anchors** using `#roles=`:

```
--beacon-node=http://127.0.0.1:5052/#roles=attestation-data,attestation-publish
--beacon-node=http://192.168.1.10:5052/#roles=block
```

The `#roles=` fragment is stripped from the URL before it is used for API calls. Without a `#roles=` anchor, the default role is `all`.

### 9 Atomic Roles

| Role | API Calls |
|---|---|
| `attestation-data` | `produceAttestationData()` |
| `attestation-publish` | `submitPoolAttestations()` |
| `aggregated-data` | `getAggregatedAttestation()` |
| `aggregated-publish` | `publishAggregateAndProofs()` |
| `block-data` | `produceBlockV2()` |
| `block-publish` | `publishBlock()` |
| `sync-data` | `getBlockRoot()`, `produceSyncCommitteeContribution()` |
| `sync-publish` | `publishContributionAndProofs()`, `submitPoolSyncCommitteeSignatures()` |
| `duties` | 9 duty-related API calls (attester/proposer/sync committee duties, subnet subscriptions, validator config) |

### 7 Composite Roles

| Composite | Expands To |
|---|---|
| `attestation` | `attestation-data`, `attestation-publish` |
| `aggregated` | `aggregated-data`, `aggregated-publish` |
| `block` | `block-data`, `block-publish` |
| `sync` | `sync-data`, `sync-publish` |
| `publish` | All 4 `*-publish` roles |
| `data` | All 4 `*-data` roles |
| `all` | `attestation`, `aggregated`, `block`, `sync`, `duties` (everything) |

### Failover Behavior

- **Within same role**: When multiple BNs share the same role, Nimbus provides full redundancy. If one BN goes offline, the others with the same role take over.
- **No cross-role failover**: A BN assigned only `attestation` will never handle `block` duties, even if all `block` BNs fail. This is by design for isolation.
- **Order matters**: For same-role BNs, the first listed BN is preferred (user-specified order is the tie-breaker).

### Sentry Node Architecture

The sentry node pattern separates block production from attestation traffic to enhance privacy:

```
# Node A: handles all traffic except block production (public-facing)
--beacon-node=http://public-bn:5052/#roles=attestation,aggregated,sync,duties

# Node B: handles only block production (isolated IP)
--beacon-node=http://private-bn:5052/#roles=block
```

**Motivation**: The block proposer is known ~12 minutes before they propose. Since each validator attests every ~6 minutes, an attacker can map a validator pubkey to its BN IP by monitoring attestation traffic. By separating block production onto a different IP, the proposer's network identity is obscured.

### Configuration via TOML

All CLI options work in TOML config files:

```toml
beacon-node = [
  "http://127.0.0.1:5052/#roles=attestation,aggregated,sync,duties",
  "http://192.168.1.10:5052/#roles=block"
]
```

### Sources

- [Nimbus Validator Client Options](https://nimbus.guide/validator-client-options.html)
- [Nimbus Validator Client Setup](https://nimbus.guide/validator-client.html)
- [Nimbus CLI Reference](https://nimbus.guide/options.html)

---

## 3. Lighthouse Validator Registration Batch Size

Lighthouse (Rust) batches validator registration requests to MEV-Boost builder relays to avoid timeouts.

### Flag

```
--validator-registration-batch-size <INTEGER>
```

### Default Value

**500** validators per batch.

### How It Works

- When `--builder-proposals` is enabled, the VC periodically sends `POST /eth/v1/validator/register_validator` requests to each connected BN.
- With many validators (e.g., 10,000+), a single request with all validators can timeout at the builder relay.
- The batch size splits validators into chunks. For 10,000 validators with batch size 500: 20 sequential requests of 500 validators each.

### Timing

- Registration happens once per epoch (every ~6.4 minutes).
- Batches are sent **sequentially** to avoid overwhelming the BN/relay.
- No configurable delay between batches -- they fire as fast as the previous one completes.
- If timeouts still occur with the default, operators should reduce the batch size (e.g., `--validator-registration-batch-size 100`).

### Gotchas

- **Only active/pending validators should be registered.** There was a bug (Issue #3465) where exited validators were being sent to MEV-Boost. Lighthouse fixed this to only register validators that are active or pending.
- **All connected BNs receive registrations.** Per Issue #3614, the VC publishes proposer preparation and validator registrations to all connected BNs, not just the primary.
- **File descriptor limits.** With very large validator sets, batch registration can hit OS file descriptor limits (Issue #3468). Reducing batch size helps.
- **Registration failures are not fatal.** Since PR #3488, registration request failures do not cause the VC to mark a BN as offline, preventing cascading failures.

### Source Code Location

- CLI definition: `validator_client/src/cli.rs`
- Registration logic: `validator_client/src/` (registration service module)

### Sources

- [Lighthouse VC CLI Reference](https://lighthouse-book.sigmaprime.io/help_vc.html)
- [Lighthouse v4.3.0 Release Notes](https://github.com/sigp/lighthouse/releases/tag/v4.3.0)
- [Lighthouse MEV Documentation](https://lighthouse-book.sigmaprime.io/advanced_builders.html)
- [Registration failure handling PR #3488](https://github.com/sigp/lighthouse/pull/3488)
- [CLI source: cli.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/src/cli.rs)

---

## 4. Teku Pre-Signed Exits (`--save-exits-path`)

Teku (Java) allows generating and saving signed voluntary exit messages without broadcasting them, for use at a future time.

### Flag

```
teku voluntary-exit --save-exits-path=<PATH> \
  --beacon-node-api-endpoint=http://127.0.0.1:5051 \
  --validator-keys=validator/keys/validator_1e9f2a.json:validator/passwords/validator_1e9f2a.txt
```

### Configuration Options

| Option | Description |
|---|---|
| CLI: `--save-exits-path=<PATH>` | Directory to save JSON exit files |
| Env: `TEKU_SAVE_EXITS_PATH` | Same, via environment variable |
| Config: `save-exits-path: "path"` | Same, via TOML/YAML config file |

### Behavior

When `--save-exits-path` is provided:

1. **Creates** a signed voluntary exit message for each specified validator
2. **Does NOT submit** the exit to the beacon node
3. **Does NOT validate** the exit epoch
4. **Does NOT publish** the exit to the network
5. **Saves** a JSON file per validator to the specified directory

A BN endpoint is still **required** because the tool:
- Verifies the validator status (must be active)
- Retrieves network parameters needed to generate a valid message

### JSON File Format

The saved file conforms to the Ethereum Beacon API `SignedVoluntaryExit` schema:

```json
{
  "message": {
    "epoch": "0",
    "validator_index": "111075"
  },
  "signature": "0x90321cc3fef91133b96fcbd5620907219dd15db5a33c306cce1a30d5c53dbeb2171e0f6e00bd66ef6cfb550a71fb84d006461398c729d17e45d648180ae75b388efc1a0b36eedb63c433339ddc0851dbf0c49386a00a5a60f46f822a8ae28114"
}
```

### Submitting a Pre-Signed Exit

```bash
curl -X POST "http://127.0.0.1:5051/eth/v1/beacon/pool/voluntary_exits" \
  -H "Content-Type: application/json" \
  -d @saved_exit.json
```

Any beacon node (even a different client) can accept the submission via the standard Beacon API.

### How EIP-7044 Enables This

**Before EIP-7044** (pre-Deneb): Signed voluntary exits were only valid for 2 fork versions (current + previous). This meant pre-signed exits could become invalid after a hard fork, requiring re-signing.

**After EIP-7044** (Deneb onwards): The signing domain for voluntary exits is permanently locked to `CAPELLA_FORK_VERSION`.

Key specification change:
- `process_voluntary_exit` now computes the signing domain and root **fixed on `CAPELLA_FORK_VERSION`**, regardless of the current fork.
- This means exits signed today will be valid forever, through any future hard fork.
- The trade-off: fork-based replay protection is removed, but this is considered safe because replaying a voluntary exit has no impact on funds or chain security.

**Practical impact for pre-signed exits**: Staking operations where the key operator differs from the fund owner can now exchange pre-signed exits once, rather than re-signing after every hard fork. This is critical for liquid staking protocols and institutional staking setups.

### Gotchas

- The epoch field in the saved message does not need to match the current epoch when submitted -- it just needs to be <= current epoch.
- The validator must still be in an active state when the exit is eventually submitted.
- If the validator was not yet active at sign-time, the exit message is still valid -- it just cannot be processed until the validator is active and the epoch has been reached.
- For exits signed **before Deneb** using a non-Capella domain: these are now invalid. Only Capella-domain signatures are perpetually valid.

### Sources

- [Teku: Voluntarily Exit a Validator](https://docs.teku.consensys.io/how-to/voluntarily-exit)
- [Teku: voluntary-exit CLI Reference](https://docs.teku.consensys.io/development/reference/cli/subcommands/voluntary-exit)
- [EIP-7044: Perpetually Valid Signed Voluntary Exits](https://eips.ethereum.org/EIPS/eip-7044)
- [Consensys Blog: EIP-7044 & EIP-7045](https://consensys.io/blog/ethereum-evolved-dencun-upgrade-part-2-eip-7044-eip-7045)
- [Teku GitHub: Tooling Issue #2461](https://github.com/Consensys/teku/issues/2461)

---

## 5. Lighthouse 4-Tier Beacon Node Health System

Lighthouse (Rust) introduced a health-based beacon node selection system in v6.0.0, replacing the previous binary synced/unsynced approach.

### The 4 Sync Distance Tiers

| Tier | Default Range (slots) | Description |
|---|---|---|
| **Synced** | 0..=8 | Fully synced, head is within 8 slots of current slot |
| **Small** | 9..=16 | Slightly behind, minor lag |
| **Medium** | 17..=64 | Moderately behind, noticeable lag |
| **Large** | 65+ | Significantly behind, likely syncing or stalled |

### Configuration

```
--beacon-nodes-sync-tolerances 8,8,48
```

The flag takes a **comma-separated list of 3 values** representing the **width** of each range:

- 1st value (`8`): Width of the **Synced** range (0 to 8)
- 2nd value (`8`): Width of the **Small** range (9 to 16)
- 3rd value (`48`): Width of the **Medium** range (17 to 64)
- Everything beyond is **Large** (65+)

Default: `8,8,48`

### Health Scoring Algorithm

Each BN is scored based on three dimensions (in priority order):

1. **Sync distance tier** (Synced > Small > Medium > Large)
2. **Execution layer health** (EL online and not erroring > EL offline)
3. **Optimistic sync status** (Not optimistic > Optimistic)

The scoring works as a **composite ordering**:
- A Synced node with a healthy EL is preferred over a Small node regardless of other factors.
- Within the same tier + EL status + optimistic status, **user-specified order** (from `--beacon-nodes`) is the tie-breaker. The primary BN is always prioritized among equals.

### How Duty Routing Changes Based on Tier

| Scenario | Behavior |
|---|---|
| Primary BN is Synced | All duties route to primary BN (normal operation) |
| Primary BN is Small, fallback is Synced | Duties switch to the Synced fallback BN |
| All BNs are in the same tier | Primary BN is preferred (user order tie-break) |
| Primary BN has EL offline | Fallback with healthy EL is preferred, even if in same sync tier |
| Primary BN is optimistic | Non-optimistic fallback preferred |

The VC checks health **every slot** and can switch BNs aggressively between slots. This is a significant change from pre-v6.0.0 behavior where the VC would stick with a BN until it was fully offline.

### Health Check Mechanism

Every slot, the VC queries each connected BN's `/eth/v1/node/syncing` endpoint, which returns:

```json
{
  "data": {
    "head_slot": "12345678",
    "sync_distance": "0",
    "is_syncing": false,
    "is_optimistic": false,
    "el_offline": false
  }
}
```

These fields directly map to the health scoring dimensions.

### Monitoring

The `/lighthouse/beacon/health` API endpoint on the VC exposes health information for all connected BNs, useful for monitoring dashboards.

### Gotchas

- **Faulty majority client risk**: If a majority CL client has a bug, the faulty chain may appear "healthier" (more nodes synced to the faulty head). Mitigation: run some VCs connected to minority clients.
- **Aggressive switching**: The new system switches BNs much more frequently than before. Operators who relied on sticky BN selection may see different behavior.
- **EL offline detection**: Pre-v6.0.0, BNs would self-report as synced even when the EL was offline, causing missed attestations. The new system detects `el_offline: true` and routes away.
- **Eight-epoch delayed sync reporting**: BNs may report synced status for up to 8 epochs after internal sync transitions. The sync distance tier system mitigates this by using quantitative distance rather than binary state.
- **Backwards incompatible**: The v6.0.0 health system requires upgrading from v5.x; it is not a minor version change.

### Sources

- [Lighthouse Redundancy Documentation](https://lighthouse-book.sigmaprime.io/advanced_redundancy.html)
- [Lighthouse VC CLI Reference](https://lighthouse-book.sigmaprime.io/help_vc.html)
- [Lighthouse v6.0.0 Release Notes](https://github.com/sigp/lighthouse/releases/tag/v6.0.0)
- [Lighthouse Failover Tracking Issue #3613](https://github.com/sigp/lighthouse/issues/3613)
- [Lighthouse CLI Source: cli.rs](https://github.com/sigp/lighthouse/blob/stable/validator_client/src/cli.rs)

---

## Cross-Cutting Design Implications for rvc

### Block Selection (from Lodestar)
- Consider supporting at least 3 modes: `maxprofit`, `executiononly`, and a configurable boost factor.
- The `boostFactor` approach is elegant -- a single numeric parameter covers the spectrum from "always local" to "always builder."
- The formula `100*100/(100+premium%)` is useful for operator UX.

### Role-Based BN Assignment (from Nimbus)
- The URL-fragment approach (`#roles=`) is clever for not requiring config file changes.
- The sentry node pattern (separate IPs for block production vs attestation) is a real privacy concern worth addressing.
- Consider at minimum supporting `block` vs `everything-else` separation.

### Registration Batching (from Lighthouse)
- Default batch size of 500 is well-tested at scale.
- Sequential batching with no artificial delay is the right approach.
- Registration failures should NOT mark a BN as offline.

### Pre-Signed Exits (from Teku)
- The `SignedVoluntaryExit` JSON format is standardized -- follow the Beacon API schema exactly.
- EIP-7044's Capella domain lock makes this a one-time operation, which is a major UX improvement.
- A BN is still needed at sign-time for validation, but not at submission-time.

### Health-Based BN Selection (from Lighthouse)
- The 4-tier system with configurable thresholds is the most sophisticated approach in the ecosystem.
- The three health dimensions (sync distance, EL health, optimistic status) should all be tracked.
- Per-slot health checks enable fast failover.
- User-specified order as tie-breaker preserves operator intent.
