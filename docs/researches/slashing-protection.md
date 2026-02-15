# Research: Slashing Protection for Ethereum Validator Client

## Summary

Slashing protection is the most safety-critical component of a validator client. It prevents validators from signing conflicting messages (double proposals, double votes, surround votes) that would result in slashing penalties. The implementation must be crash-safe, thoroughly tested, and fail-closed — if the slashing DB is unreadable, the VC must refuse to sign, never ignore the error. EIP-3076 defines a standard interchange format for safe migration between clients.

## Key Concepts

### Slashing Conditions

Two types of slashable offenses exist in Ethereum PoS [1]:

**1. Proposer Slashing (Double Proposal):**
A validator signs two different blocks for the same slot:
```
header_1.slot == header_2.slot AND header_1 != header_2
```

**2. Attester Slashing — Two sub-conditions [1][5]:**

**Double Vote:** Two attestations with the same target epoch but different data:
```
data_1.target.epoch == data_2.target.epoch AND data_1 != data_2
```

**Surround Vote:** One attestation "surrounds" another:
```
# data_1 surrounds data_2:
data_1.source.epoch < data_2.source.epoch < data_2.target.epoch < data_1.target.epoch

# OR data_2 surrounds data_1 (symmetric check)
```

From the consensus spec (`is_slashable_attestation_data`) [5]:
```python
def is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool:
    return (
        # Double vote
        (data_1 != data_2 and data_1.target.epoch == data_2.target.epoch) or
        # Surround vote
        (data_1.source.epoch < data_2.source.epoch and
         data_2.target.epoch < data_1.target.epoch)
    )
```

### Pre-Signing Checklist

Before every signing operation, the VC MUST:

**For blocks:**
1. Check that no block has been signed for this slot (or the same block is being re-signed)
2. Record the new block slot in the slashing DB
3. Ensure the record is fsynced to disk
4. Only THEN return the signature

**For attestations:**
1. Check that no attestation exists with the same target epoch (or same attestation is being re-signed)
2. Check that no existing attestation would be surrounded by the new one
3. Check that the new attestation does not surround any existing one
4. Record the new attestation (source, target) in the slashing DB
5. Ensure the record is fsynced to disk
6. Only THEN return the signature

## EIP-3076 Interchange Format

### Specification Details

EIP-3076 [2] defines a JSON format for exporting and importing slashing protection data between validator clients.

**JSON Schema:**
```json
{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7174d84453205b..."
  },
  "data": [
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc...",
      "signed_blocks": [
        { "slot": "81952", "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392..." }
      ],
      "signed_attestations": [
        {
          "source_epoch": "2290",
          "target_epoch": "3007",
          "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babdd..."
        }
      ]
    }
  ]
}
```

**Key fields:**
- `interchange_format_version`: Always "5" (current spec version) [2]
- `genesis_validators_root`: Prevents cross-chain imports — must match or be rejected
- `signing_root`: Optional. When present, allows re-signing the exact same message. When absent, any message at that slot/epoch is treated as conflicting.
- All numeric values are quoted strings

### Import Conditions

The spec defines five conditions that must be checked during import [2]:

1. `genesis_validators_root` must match the chain the VC is operating on
2. For blocks: imported slots must be checked against existing records for conflicts
3. For attestations: imported source/target epochs must be checked for double votes and surround votes
4. Records with no `signing_root` are treated conservatively — any new message at that slot/epoch is slashable
5. Duplicate records (same slot/epoch and signing_root) are idempotent

### Two Import Strategies

- **Complete strategy:** Keep all imported records alongside existing ones. More data, better forensic analysis.
- **Minimal strategy:** Only keep the most recent records (highest slot/epoch). Simpler, but less forensic data.

Both strategies must pass the EIP-3076 conformance tests [4].

## Database Best Practices

### SQLite Configuration (CRITICAL)

```rust
use rusqlite::Connection;

fn open_slashing_db(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    // WAL mode for concurrent reads during signing
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // CRITICAL: FULL synchronous — fsync on EVERY commit
    // NORMAL in WAL mode does NOT guarantee durability on crash [8][9]
    conn.pragma_update(None, "synchronous", "FULL")?;
    // Exclusive locking — only one VC instance can access
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    Ok(conn)
}
```

**Why `synchronous = FULL` is non-negotiable:**
- SQLite's default for WAL mode is `synchronous = NORMAL`, which does not fsync on every commit [8]
- On macOS, the system-provided SQLite may have different defaults [9]
- Using `bundled` rusqlite with explicit `FULL` eliminates platform variance
- This is the #1 most important configuration for slashing protection safety

### Schema Design

Based on Lighthouse's proven schema [7]:

```sql
CREATE TABLE validators (
    id INTEGER PRIMARY KEY,
    public_key BLOB NOT NULL UNIQUE
);

CREATE TABLE signed_blocks (
    validator_id INTEGER NOT NULL,
    slot INTEGER NOT NULL,
    signing_root BLOB,
    FOREIGN KEY (validator_id) REFERENCES validators(id),
    UNIQUE (validator_id, slot)  -- Schema-enforced uniqueness
);

CREATE TABLE signed_attestations (
    validator_id INTEGER NOT NULL,
    source_epoch INTEGER NOT NULL,
    target_epoch INTEGER NOT NULL,
    signing_root BLOB,
    FOREIGN KEY (validator_id) REFERENCES validators(id),
    UNIQUE (validator_id, target_epoch)  -- Prevents double votes at DB level
);
```

The UNIQUE constraints serve as defense-in-depth — even if application logic has a bug, the DB rejects conflicting entries.

### Signing Flow Pattern

```
1. Begin transaction
2. Check for conflicts (query existing records)
3. If no conflicts: INSERT new record
4. COMMIT (with PRAGMA synchronous = FULL, this fsyncs)
5. Only THEN return signature to caller
```

The signature MUST NOT be returned until step 4 completes. Deferred/batched writes create vulnerability windows.

### Pruning Safely

Old records can be pruned to keep the DB small, but ONLY with watermarks:
- Set a minimum slot floor for blocks (never sign below this slot)
- Set a minimum source/target epoch floor for attestations
- Delete records below the floor
- The watermarks themselves must persist
- Without watermarks, pruning creates gaps that defeat protection

### Handling Corruption

If the slashing DB is corrupted or unreadable:
- **REFUSE TO SIGN** — never ignore the error
- Log a critical error with clear instructions
- Run `PRAGMA integrity_check` at startup
- If integrity check fails, halt with a distinct exit code
- Do NOT attempt automatic repair — operator must intervene

## Historical Slashing Incidents

### Staked Incident (February 2021) — 75 Validators

**Root cause:** Prysm's slashing DB caused I/O overhead and attestation misses. Staked disabled slashing DB persistence because they had a separate Hashicorp Consul layer. When scaling up beacon nodes caused validators to restart more frequently, the non-persistent DBs allowed double signing [10][11].

**Financial impact:** ~18 ETH (~$30,000 at the time) [11]

**Lesson:** Never disable the local slashing DB. External protections are supplementary, not replacements. I/O performance of the slashing DB must be fast enough to not tempt operators to disable it.

### Prysm Medalla Testnet (August 2020) — 3000+ Slashings

**Root cause:** Time server bug caused mass confusion. Many validators ran in Docker without persistent volume mounts — slashing DB recreated on every restart [12][13].

**Lesson:** Docker volume configuration is safety-critical. The DB must write immediately and synchronously before returning a signature. Validate DB persistence on every startup.

### RockLogic/Lido (April 2023) — 11 Validators

**Root cause:** During migration, validator keys were "deleted" via Prysm's keymanager API but a bug (Issue #12281) caused them to be re-imported from disk on restart. Both clusters then attested simultaneously [14][15].

**Lesson:** Key deletion must be verified at the filesystem level. Enable doppelganger detection to catch duplicates.

### Launchnodes/Lido (October 2023) — 20 Validators

**Root cause:** During datacenter failover, the original VC was not fully decommissioned. Both VCs connected to the same Web3Signer without slashing protection enabled at the signer level [16].

**Financial impact:** ~28.677 ETH [16]

**Lesson:** Remote signers must have their own slashing protection. Failover procedures must confirm the original is stopped before activating the backup.

### SSV/Ankr (September 2025) — 39 Validators

**Root cause:** Ankr ran a parallel validator instance outside SSV infrastructure during maintenance. Same keys active in two different infrastructures simultaneously [17].

**Lesson:** DVT does not protect against external key mismanagement. Maintenance procedures must verify no parallel instances exist.

### Common Root Causes Summary

| Root Cause | Incidents | Prevention |
|-----------|-----------|------------|
| Duplicate key instances | All | Doppelganger detection, lock files, single-key-single-signer enforcement |
| Disabled or missing slashing DB | Staked, Medalla | Never disable; fail-safe on missing DB |
| Failover without confirmed decommission | Launchnodes, SSV/Ankr | Kill-before-activate procedures |
| Client bugs (key re-import, DB persistence) | RockLogic, Medalla | Defense-in-depth at multiple layers |
| Docker volume misconfiguration | Medalla | Documentation, startup validation |

## Testing Strategies

### EIP-3076 Conformance Tests

The [eth-clients/slashing-protection-interchange-tests](https://github.com/eth-clients/slashing-protection-interchange-tests) repository provides 38 standardized test cases [4]:

**Block tests:** single/multiple blocks, slashable blocks, re-signing, missing signing roots
**Attestation tests:** double votes, surround votes (both directions), out-of-order epochs, genesis attestation, re-signing
**Edge cases:** wrong genesis_validators_root, duplicate pubkeys, multi-import scenarios
**Multi-validator:** Cross-validator independence, same-slot different-validator blocks

### Property-Based Testing

Key properties to test with `proptest`:

1. **No double proposals:** Same (validator, slot) with different roots → exactly one succeeds
2. **No double votes:** Same (validator, target_epoch) with different roots → exactly one succeeds
3. **No surround votes:** Accepted attestations never form surround pairs
4. **Monotonicity:** After import, watermarks never decrease
5. **Import safety:** Imported records prevent conflicting signatures
6. **Re-signing safety:** Same message (same signing root) always succeeds
7. **Independence:** Validator A's operations don't affect validator B

### Fuzzing Targets

1. **EIP-3076 JSON parser** — Malformed, truncated, adversarial JSON
2. **Signing flow** — Random sequences of sign requests
3. **Database recovery** — Corrupted SQLite files at random offsets
4. **Import + sign sequences** — Random interchange files followed by random signings

### Integration Testing

1. **Round-trip EIP-3076:** Export → import into fresh instance → verify same rejections
2. **Crash recovery:** Kill process mid-transaction → restart → verify consistency
3. **Multi-validator load:** 1000+ validators simultaneously → no cross-contamination
4. **Adversarial BN mock:** Requests for past epochs, duplicate block requests

## Doppelganger Detection

### How It Works

1. VC starts and loads validator keys
2. Enters monitoring phase (does NOT sign)
3. For 2-3 epochs (~13-20 min), queries BN for validator liveness
4. If any validator is "live" (has attested/proposed), doppelganger detected
5. **On detection:** Shut down with distinct exit code
6. If clean after monitoring: begin normal operations

### Standardized API

`POST /eth/v1/validator/liveness/{epoch}` [18]:
```json
// Request body: list of validator indices
["0xpubkey1", "0xpubkey2"]

// Response:
{
  "data": [
    { "index": "1234", "epoch": "100", "is_live": true }
  ]
}
```

BN must support current and previous epoch; earlier epochs are optional [18].

### Implementation Comparison

| Client | Default | Period | Detection Response |
|--------|---------|--------|--------------------|
| Lighthouse | Opt-in | 2-3 epochs | Shuts down VC [3] |
| Nimbus | **On by default** | 2 epochs | Exit code 129 [19] |
| Teku | Opt-in | 2 epochs | Exit code 2 (startup) or reject key (API import) [20] |
| Prysm | Opt-in | 2 epochs | Logs alert |
| **Lodestar** | **Restart-aware** | Conditional | Skips if recently active [21] |

### Recommendations

1. **Enable by default** (follow Nimbus)
2. **Use standardized liveness API** for cross-client compatibility
3. **Wait one epoch before checking** to avoid false positives from own recent restart
4. **Monitor for 2 full epochs** after initial skip
5. **Shut down on detection** with distinct exit code — operator must intervene
6. **Implement restart-aware detection** (Lodestar pattern): skip DP for validators with recent slashing DB entries
7. **Also check on runtime key import** via Keymanager API

## Sources

[1] [Upgrading Ethereum: Slashing](https://eth2book.info/latest/part2/incentives/slashing/) — Ben Edgington. Slashing conditions overview.
[2] [EIP-3076: Slashing Protection Interchange Format](https://eips.ethereum.org/EIPS/eip-3076) — Official specification.
[3] [Doppelganger Protection — Lighthouse Book](https://lighthouse-book.sigmaprime.io/validator_doppelganger.html) — Sigma Prime.
[4] [slashing-protection-interchange-tests](https://github.com/eth-clients/slashing-protection-interchange-tests) — 38 conformance tests.
[5] [Beacon Chain Consensus Specs](https://ethereum.github.io/consensus-specs/specs/phase0/beacon-chain/) — `is_slashable_attestation_data`.
[7] [Slashing Protection — Lighthouse Book](https://lighthouse-book.sigmaprime.io/slashing-protection.html) — SQLite implementation details.
[8] [SQLite commits are not durable](https://avi.im/blag/2025/sqlite-fsync/) — Avi Wadhwa, 2025. NORMAL in WAL is not crash-safe.
[9] [SQLite's Durability Settings](https://www.agwa.name/blog/post/sqlite_durability) — Andrew Ayer. macOS quirks.
[10] [ETH2 Slashing Post-mortem](https://blog.staked.us/blog/eth2-post-mortem) — Staked, February 2021.
[11] [75 Eth2 validators slashed](https://www.theblock.co/post/93730/eth2-validators-slashed-staked-bug) — The Block, February 2021.
[12] [Validators Slashed With Local Protection — Issue #7076](https://github.com/prysmaticlabs/prysm/issues/7076) — Medalla incident.
[13] [Slashing Protection Hardening — Issue #6948](https://github.com/prysmaticlabs/prysm/issues/6948) — Docker volume concerns.
[14] [RockLogic Slashing Post-mortem](https://blog.lido.fi/loe-rocklogic-gmbh-slashing-incident/) — Lido Finance, April 2023.
[15] [Prysm key deletion bug — Issue #12281](https://github.com/prysmaticlabs/prysm/issues/12281) — Key deletion not persisted.
[16] [Launchnodes Slashing Post-mortem](https://blog.lido.fi/post-mortem-launchnodes-slashing-incident/) — Lido Finance, October 2023.
[17] [SSV Slashing Post-mortem](https://ssv.network/blog/slashing-post-mortem-september-2025) — SSV Network, September 2025.
[18] [Add liveness endpoint — PR #131](https://github.com/ethereum/beacon-APIs/pull/131) — Standardized doppelganger API.
[19] [Nimbus Doppelganger Detection](https://nimbus.guide/doppelganger-detection.html) — Status/Nimbus.
[20] [Teku Detect Doppelgangers](https://docs.teku.consensys.io/how-to/prevent-slashing/detect-doppelgangers) — ConsenSys.
[21] [Restart-aware doppelganger — Issue #5856](https://github.com/ChainSafe/lodestar/issues/5856) — ChainSafe.
