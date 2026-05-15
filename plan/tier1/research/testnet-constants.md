# Research: Testnet Genesis Constants Verification

## Summary

All genesis constants specified in the PRD for Holesky and Sepolia have been verified against multiple authoritative sources: the official eth-clients repositories [1][2], Lighthouse's built-in network configs [3][4], and public beacon chain explorers [5][6]. All values are correct.

## Verified Constants

### Holesky

| Constant | PRD Value | Verified Value | Status |
|----------|-----------|----------------|--------|
| `genesis_time` | `1695902400` | `1695902400` | Correct |
| `genesis_validators_root` | `0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1` | `0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1` | Correct |
| `genesis_fork_version` | `[0x01, 0x01, 0x70, 0x00]` | `0x01017000` | Correct |
| `capella_fork_version` | `[0x04, 0x01, 0x70, 0x00]` | `0x04017000` | Correct |

**Derivation of `genesis_time`:**
- `MIN_GENESIS_TIME` = 1695902100 [1][3]
- `GENESIS_DELAY` = 300 [1][3]
- Actual `genesis_time` = 1695902100 + 300 = **1695902400** (2023-09-28T12:00:00Z)
- Confirmed by Holesky beacon explorers [5]

**Holesky fork schedule:**

| Fork | Version | Epoch |
|------|---------|-------|
| Genesis | `0x01017000` | 0 |
| Altair | `0x02017000` | 0 |
| Bellatrix | `0x03017000` | 0 |
| Capella | `0x04017000` | 256 |
| Deneb | `0x05017000` | 29696 |
| Electra | `0x06017000` | 115968 |
| Fulu | `0x07017000` | 165120 |

---

### Sepolia

| Constant | PRD Value | Verified Value | Status |
|----------|-----------|----------------|--------|
| `genesis_time` | `1655733600` | `1655733600` | Correct |
| `genesis_validators_root` | `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078` | `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078` | Correct |
| `genesis_fork_version` | `[0x90, 0x00, 0x00, 0x69]` | `0x90000069` | Correct |
| `capella_fork_version` | `[0x90, 0x00, 0x00, 0x72]` | `0x90000072` | Correct |

**Derivation of `genesis_time`:**
- `MIN_GENESIS_TIME` = 1655647200 [2][4]
- `GENESIS_DELAY` = 86400 [2][4]
- Actual `genesis_time` = 1655647200 + 86400 = **1655733600** (2022-06-20T14:00:00Z)
- Confirmed by Sepolia beacon explorers [6]

**Sepolia fork schedule:**

| Fork | Version | Epoch |
|------|---------|-------|
| Genesis | `0x90000069` | 0 |
| Altair | `0x90000070` | 50 |
| Bellatrix | `0x90000071` | 100 |
| Capella | `0x90000072` | 56832 |
| Deneb | `0x90000073` | 132608 |
| Electra | `0x90000074` | 222464 |
| Fulu | `0x90000075` | 272640 |

---

## Cross-Reference with Lighthouse

Lighthouse stores network configs at `common/eth2_network_config/built_in_network_configs/{network}/config.yaml` [3][4]. The `genesis_validators_root` is stored separately (not in config.yaml) and loaded from genesis state SSZ files. The fork versions and timing parameters in Lighthouse's config files match the values from eth-clients repos exactly.

Both testnets use `PRESET_BASE: mainnet`, meaning they share the same `SECONDS_PER_SLOT` (12), `SLOTS_PER_EPOCH` (32), and other consensus parameters with mainnet. No special handling needed for slot timing.

## Additional Constants (informational)

| Parameter | Holesky | Sepolia |
|-----------|---------|---------|
| `DEPOSIT_CHAIN_ID` | 17000 | 11155111 |
| `DEPOSIT_CONTRACT_ADDRESS` | `0x4242...4242` | `0x7f02...295D` |
| `MIN_GENESIS_ACTIVE_VALIDATOR_COUNT` | 16384 | 1300 |
| `EJECTION_BALANCE` | 28 ETH | Standard |

These are not needed for rvc's `Network` enum (which only stores genesis_time and genesis_validators_root), but may be useful for future reference.

## Implementation Notes

- The `genesis_validators_root` values are **not** in the config.yaml files — they are derived from the genesis state SSZ. For rvc, they should be hardcoded constants (matching the pattern used for Mainnet and Hoodi).
- Fork versions are only needed in the keygen tool for BLS-to-execution-change signing. The main rvc binary fetches fork schedules dynamically from the beacon node.
- Both testnets are merged-from-genesis (or merged very early), so there are no pre-merge considerations.

## Sources

[1] [eth-clients/holesky](https://github.com/eth-clients/holesky) — Official Holesky testnet configuration repository. Config at `metadata/config.yaml`.
[2] [eth-clients/sepolia](https://github.com/eth-clients/sepolia) — Official Sepolia testnet configuration repository. Config at `metadata/config.yaml`.
[3] [Lighthouse Holesky config](https://raw.githubusercontent.com/sigp/lighthouse/stable/common/eth2_network_config/built_in_network_configs/holesky/config.yaml) — Lighthouse's built-in Holesky network configuration.
[4] [Lighthouse Sepolia config](https://raw.githubusercontent.com/sigp/lighthouse/stable/common/eth2_network_config/built_in_network_configs/sepolia/config.yaml) — Lighthouse's built-in Sepolia network configuration.
[5] [Holesky Beaconcha.in](https://holesky.beaconcha.in/) — Holesky beacon chain explorer confirming genesis parameters.
[6] [Sepolia Beaconcha.in](https://light-sepolia.beaconcha.in/) — Sepolia beacon chain explorer confirming genesis parameters.
