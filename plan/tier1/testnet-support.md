# Additional Testnet Support

## Problem

rvc only supports Mainnet, Hoodi, and Custom networks. Holesky and Sepolia — the two primary Ethereum testnets — are explicitly rejected. This prevents operators from testing rvc before deploying to mainnet, which is a significant barrier to adoption.

All other major clients (Lighthouse, Prysm, Teku, Nimbus, Lodestar) support both testnets.

## Current Architecture

### Network Enum

**File:** `crates/rvc/src/config/network.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Hoodi,
    Custom,
}
```

### Explicit Rejection

Tests actively block Sepolia and Holesky:

```rust
#[test]
fn test_network_from_str_deprecated_networks_rejected() {
    assert!("goerli".parse::<Network>().is_err());
    assert!("sepolia".parse::<Network>().is_err());
    assert!("holesky".parse::<Network>().is_err());
}

#[test]
fn test_network_serde_deprecated_networks_rejected() {
    assert!(serde_json::from_str::<Network>("\"goerli\"").is_err());
    assert!(serde_json::from_str::<Network>("\"sepolia\"").is_err());
    assert!(serde_json::from_str::<Network>("\"holesky\"").is_err());
}
```

### Per-Network Data Requirements

Each named network needs only two compile-time constants. Fork schedules are fetched dynamically from the beacon node at runtime.

| Field | Source | Example (Mainnet) |
|-------|--------|--------------------|
| `genesis_time` | Hardcoded constant | `1606824023` |
| `genesis_validators_root` | Hardcoded constant | `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95` |

### Config Resolution Chain

```
CLI args  →  Config file (TOML)  →  Network defaults  →  Error if missing
```

Methods on `Config`:
- `effective_genesis_time()` — returns CLI override > config file > network preset > error
- `effective_genesis_validators_root()` — same precedence chain

### Keygen Tool

`bin/rvc-keygen/src/network.rs` has a separate network registry with `MAINNET` and `HOODI` constants for key generation and BLS-to-execution-change signing.

## Testnet Constants

### Holesky

| Field | Value |
|-------|-------|
| Genesis time | `1695902400` (2023-09-28T12:00:00Z) |
| Genesis validators root | `0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1` |
| Genesis fork version | `[0x01, 0x01, 0x70, 0x00]` |
| Capella fork version | `[0x04, 0x01, 0x70, 0x00]` |

### Sepolia

| Field | Value |
|-------|-------|
| Genesis time | `1655733600` (2022-06-20T14:00:00Z) |
| Genesis validators root | `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078` |
| Genesis fork version | `[0x90, 0x00, 0x00, 0x69]` |
| Capella fork version | `[0x90, 0x00, 0x00, 0x72]` |

> Note: Genesis fork version and Capella fork version are needed only for the keygen tool's `exit_fork_schedule()`. The main rvc binary fetches fork versions dynamically from the beacon node.

## Implementation Plan

### Step 1: Extend Network Enum

**File:** `crates/rvc/src/config/network.rs`

```rust
pub enum Network {
    #[default]
    Mainnet,
    Hoodi,
    Holesky,
    Sepolia,
    Custom,
}
```

Update `FromStr`:
```rust
impl FromStr for Network {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "hoodi" => Ok(Self::Hoodi),
            "holesky" => Ok(Self::Holesky),
            "sepolia" => Ok(Self::Sepolia),
            "custom" => Ok(Self::Custom),
            _ => Err(format!("unknown network: {}", s)),
        }
    }
}
```

Update `Display` and serde similarly.

### Step 2: Add Genesis Constants

**File:** `crates/rvc/src/config/network.rs`

```rust
impl Network {
    pub fn genesis_time(&self) -> Option<u64> {
        match self {
            Self::Mainnet => Some(1_606_824_023),
            Self::Hoodi => Some(1_742_213_400),
            Self::Holesky => Some(1_695_902_400),
            Self::Sepolia => Some(1_655_733_600),
            Self::Custom => None,
        }
    }

    pub fn genesis_validators_root(&self) -> Option<&'static str> {
        match self {
            Self::Mainnet => Some("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
            Self::Hoodi => Some("0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"),
            Self::Holesky => Some("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"),
            Self::Sepolia => Some("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"),
            Self::Custom => None,
        }
    }
}
```

### Step 3: Update Keygen Tool

**File:** `bin/rvc-keygen/src/network.rs`

Add `HOLESKY` and `SEPOLIA` constants:

```rust
pub static HOLESKY: KeygenNetwork = KeygenNetwork {
    name: "holesky",
    genesis_fork_version: [0x01, 0x01, 0x70, 0x00],
    genesis_validators_root: hex!("9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"),
    capella_fork_version: [0x04, 0x01, 0x70, 0x00],
};

pub static SEPOLIA: KeygenNetwork = KeygenNetwork {
    name: "sepolia",
    genesis_fork_version: [0x90, 0x00, 0x00, 0x69],
    genesis_validators_root: hex!("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"),
    capella_fork_version: [0x90, 0x00, 0x00, 0x72],
};
```

Update `from_name()`:
```rust
pub fn from_name(name: &str) -> Result<&'static KeygenNetwork> {
    match name.to_lowercase().as_str() {
        "mainnet" => Ok(&MAINNET),
        "hoodi" => Ok(&HOODI),
        "holesky" => Ok(&HOLESKY),
        "sepolia" => Ok(&SEPOLIA),
        other => bail!("Unknown network: '{}'. Supported: mainnet, hoodi, holesky, sepolia", other),
    }
}
```

### Step 4: Fix Tests

**File:** `crates/rvc/src/config/network.rs`

Remove Holesky and Sepolia from rejection tests. Keep Goerli rejected (deprecated):

```rust
#[test]
fn test_network_from_str_deprecated_networks_rejected() {
    assert!("goerli".parse::<Network>().is_err());
}

#[test]
fn test_network_from_str_testnets_accepted() {
    assert_eq!("holesky".parse::<Network>().unwrap(), Network::Holesky);
    assert_eq!("sepolia".parse::<Network>().unwrap(), Network::Sepolia);
}
```

### Step 5: Update Documentation and Config Examples

- Update `config.example.toml` to list all supported networks
- Update CLI `--help` text for `--network` flag

## Key Files

| File | Change |
|------|--------|
| `crates/rvc/src/config/network.rs` | Add enum variants, constants, FromStr/Display/serde |
| `bin/rvc-keygen/src/network.rs` | Add keygen constants and `from_name()` entries |
| `config.example.toml` | Document new network options |

## Risks and Considerations

- **Constant accuracy** — genesis validators roots and fork versions must be byte-exact. Verify against official Ethereum specs or a running beacon node before shipping.
- **Goerli remains rejected** — Goerli is deprecated and should not be added. The existing rejection test stays.
- **seconds_per_slot and slots_per_epoch** — both testnets use the same values as mainnet (12s slots, 32 slots/epoch). No changes needed.
- **Custom network is unaffected** — the Custom variant continues to require explicit genesis parameters.
