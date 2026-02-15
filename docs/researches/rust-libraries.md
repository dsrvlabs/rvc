# Research: Rust Libraries Evaluation for Ethereum Validator Client

## Recommendation

Use `blst` 0.3.16 for BLS, `rusqlite` 0.38 (bundled) for slashing DB, custom consensus types with `ethereum_ssz` 0.10 + `ssz_types` 0.14 + `alloy-primitives` 1.4, and `reqwest` 0.13 with `reqwest-eventsource` 0.6 for HTTP/SSE. All supporting crates (tokio 1.49, serde 1.0, clap 4.5, tracing 0.1, prometheus 0.14) are industry-standard choices.

## 1. BLS Library

### Recommendation: `blst` 0.3.16

The `blst` crate from Supranational is the only serious choice for BLS12-381 in production Ethereum software [1][2].

| Criteria | blst | arkworks-bls12-381 |
|----------|------|-------------------|
| License | Apache-2.0 | MIT/Apache-2.0 |
| Downloads/month | ~300K [2] | ~50K |
| Production use | Lighthouse, Prysm, Teku, Nimbus, Lodestar | Research only |
| Performance | Fastest (optimized C + assembly) [1] | ~2-5x slower |
| Security audit | NCC Group (2021) [3] | Not audited for production |
| Platform support | x86_64, aarch64, wasm32 [3] | Broad |
| Rust bindings | First-class (`blst` crate) [2] | Native Rust |

**Why blst:**
- Fastest BLS12-381 implementation available — 2x faster than arkworks in pairing benchmarks [1]
- Used by every major Ethereum client (Lighthouse, Prysm, Teku, Nimbus, Lodestar) [3]
- NCC Group security audit completed [3]
- Supranational is a hardware security company — cryptography is their core business
- 227+ contributors on the main repo [3]

**Configuration:**
```toml
[dependencies]
blst = "0.3.16"
```

**Key operations needed:**
- Key pair generation from 32-byte secret
- BLS signing (attestations, blocks, sync committee messages, voluntary exits, builder registrations)
- Signature verification (for testing and import validation)
- Aggregate signatures (for aggregated attestations)

---

## 2. SQLite Library

### Recommendation: `rusqlite` 0.38 with `bundled` feature

| Criteria | rusqlite 0.38 | sqlx 0.8 |
|----------|--------------|----------|
| License | MIT | MIT/Apache-2.0 |
| Downloads/month | 4.3M [4] | 4.3M [5] |
| Async | No (synchronous) | Yes (native async) |
| Bundled SQLite | Yes (3.51.1) [4] | Yes (via libsqlite3-sys) |
| PRAGMA control | Full — direct `pragma_update()` [4] | Limited |
| Compile-time SQL | No | Yes (`query!` macro) |
| Connection pooling | No (not needed) | Built-in |
| Migration support | Via `rusqlite_migration` 2.4 [6] | Built-in `migrate!` macro |
| Production use (ETH) | Lighthouse slashing DB [7] | None for slashing |

**Why rusqlite:**
- **Synchronous is correct for slashing protection.** The signing operation MUST NOT proceed until the slashing check has been durably recorded. Async adds unnecessary complexity and makes reasoning about write ordering harder.
- **Bundled SQLite** eliminates system dependency issues and ensures consistent behavior across platforms [4]
- **Direct PRAGMA control** for fine-tuning durability (`synchronous`, `journal_mode`, `wal_checkpoint`)
- **Proven by Lighthouse** — 5+ years of production use for slashing protection [7]
- `rusqlite_migration` (v2.4) provides lightweight schema migration [6]

**Why NOT sqlx:**
- Async is unnecessary overhead for slashing protection — the DB must block the signer until the write is confirmed
- Much larger dependency tree
- The async layer adds complexity to reasoning about write durability
- Compile-time query checking requires a database at build time, complicating CI

**Critical SQLite configuration for slashing protection:**
```rust
use rusqlite::Connection;

fn open_slashing_db(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // CRITICAL: FULL synchronous for crash safety (NFR-7)
    conn.pragma_update(None, "synchronous", "FULL")?;
    // Exclusive locking — only one VC instance can access
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    Ok(conn)
}
```

**Configuration:**
```toml
[dependencies]
rusqlite = { version = "0.38", features = ["bundled"] }
rusqlite_migration = "2.4"
```

**Gotcha:** SQLite on macOS defaults to `synchronous=NORMAL` in WAL mode, which does NOT fsync on every commit [8]. Using `bundled` + explicit `PRAGMA synchronous = FULL` avoids this.

---

## 3. Ethereum Consensus Types

### Recommendation: Custom types with `ethereum_ssz` + `ssz_types` + `alloy-primitives`

| Criteria | ethereum_ssz (sigp) | ssz_rs (ralexstokes) | ethereum-consensus |
|----------|---------------------|---------------------|-------------------|
| License | Apache-2.0 | MIT/Apache-2.0 | MIT |
| Downloads/month | 227K [9] | ~15K | N/A (git dep only) |
| Production use | Lighthouse (5+ years) | None major | R&D only [10] |
| Security audit | Lighthouse audits cover this | Oak Security audit [11] | Not audited |
| Spec compliance | v0.12.1+ [9] | v0.12.1 | Full spec coverage |

**Approach: Custom types (recommended)**

A VC needs far fewer types than a full BN. Define custom types matching the Beacon API JSON schema directly:
- `BeaconBlockHeader`, `AttestationData`, `Checkpoint`
- `Slot`, `Epoch`, `CommitteeIndex`, `ValidatorIndex`
- `Root`, `Domain`, `SigningData`, `ForkInfo`
- `SyncCommitteeMessage`, `VoluntaryExit`
- Builder registration types

**Why custom:**
- **Decoupling** — No dependency on Lighthouse internals or R&D-grade crates
- **Minimal surface** — Only the types the VC actually needs
- **Control** — Exact serde behavior for Beacon API JSON + SSZ encoding
- The `ethereum-consensus` crate explicitly warns "primarily for R&D, not audited" [10]

**Crate stack:**
```toml
[dependencies]
# SSZ encoding/decoding
ethereum_ssz = "0.10"
ethereum_ssz_derive = "0.10"
ssz_types = "0.14"            # FixedVector, VariableList, BitVector, BitList

# Ethereum primitives
alloy-primitives = "1.4"      # Address, B256, U256, FixedBytes

# Serde utilities for Beacon API JSON
ethereum_serde_utils = "0.8"  # Hex encoding, quoted integers

# NOT recommended:
# ethereum-consensus — R&D only, not audited
# ethereum_types (ethcore/parity) — deprecated, replaced by alloy-primitives [12]
```

**Example custom type:**
```rust
use ethereum_ssz_derive::{Decode, Encode};
use ethereum_serde_utils::quoted_u64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationData {
    #[serde(with = "quoted_u64")]
    pub slot: u64,
    #[serde(with = "quoted_u64")]
    pub index: u64,
    pub beacon_block_root: [u8; 32],
    pub source: Checkpoint,
    pub target: Checkpoint,
}
```

---

## 4. HTTP Client

### Recommendation: `reqwest` 0.13 + `reqwest-eventsource` 0.6

| Criteria | reqwest 0.13 | hyper (direct) | surf |
|----------|-------------|----------------|------|
| Downloads/month | 22.7M [13] | 15M | ~50K |
| Abstraction | High-level | Low-level | High-level |
| Connection pooling | Automatic [13] | Manual | Automatic |
| TLS | rustls or native-tls [13] | Manual setup | Backend-dependent |
| SSE support | Via reqwest-eventsource [14] | Manual | No |

**SSE/EventSource options:**

| Criteria | reqwest-eventsource 0.6 | eventsource-client |
|----------|------------------------|-------------------|
| Downloads/month | 934K [14] | ~30K |
| Auto-reconnect | Yes [14] | Yes |
| reqwest integration | Native [14] | Separate HTTP layer |

**Configuration:**
```toml
[dependencies]
reqwest = { version = "0.13", default-features = false, features = [
    "rustls-tls",   # No OpenSSL dependency
    "json",         # .json() method
    "stream",       # Streaming bodies (SSE)
    "gzip",         # Compressed responses
] }
reqwest-eventsource = "0.6"
```

**Client setup:**
```rust
use reqwest::Client;
use std::time::Duration;

fn build_beacon_client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(5)
        .use_rustls_tls()
        .build()
        .expect("Failed to build HTTP client")
}
```

---

## 5. Other Key Crates

| Crate | Version | Downloads/month | Purpose |
|-------|---------|-----------------|---------|
| tokio | 1.49 | 31.8M [15] | Async runtime |
| serde | 1.0.228 | 41.5M [16] | Serialization |
| serde_json | 1.0 | ~30M | JSON |
| clap | 4.5.57 | 36.5M [17] | CLI parsing |
| tracing | 0.1.44 | 29.3M [18] | Structured logging |
| tracing-subscriber | 0.3.20 | ~20M | Log formatting |
| prometheus | 0.14.0 | 6.5M [19] | Metrics |
| toml | 0.8 | ~10M | Config file parsing |

### Key Notes

**tokio:** Use `features = ["full"]` for application crate. LTS release 1.47.x supported until September 2026 (MSRV 1.70) [15]. For library crates, depend on specific features only.

**serde/serde_json Gotcha:** The Beacon API serializes all integers as quoted strings (e.g., `"slot": "12345"`). Use `#[serde(with = "ethereum_serde_utils::quoted_u64")]` on all integer fields.

**clap:** Use derive API with `env` feature for environment variable support (CLI > env > config > defaults per FR-21).

**tracing:** Use `#[tracing::instrument]` on key functions for automatic span creation. Tracing spans model validator duty lifecycle naturally: `[slot=12345 validator=0xabcd duty=attestation]`.

**prometheus:** The `process` feature exposes CPU, memory, file descriptor metrics automatically [19]. Lighthouse uses the same crate, providing familiarity for operators.

### EIP-2335 Keystore Handling

No standalone EIP-2335 BLS keystore crate exists on crates.io. Options:

| Option | Source | Status |
|--------|--------|--------|
| Lighthouse `eth2_keystore` | git dep (not on crates.io) [20] | Production, but not published |
| `eth-keystore` 0.5.0 | crates.io | Wrong key type (secp256k1, not BLS) [21] |
| Custom implementation | Your code | Full control |

**Recommendation:** Implement EIP-2335 as a custom crate or vendor from Lighthouse (Apache-2.0). The spec [22] is straightforward: parse JSON, derive key via scrypt/PBKDF2, verify SHA-256 checksum, decrypt via AES-128-CTR.

```toml
# Dependencies for custom EIP-2335
aes = "0.8"
ctr = "0.9"
scrypt = "0.11"
sha2 = "0.10"
zeroize = { version = "1", features = ["derive"] }
```

---

## Complete Workspace Dependencies

```toml
[workspace.dependencies]
# Async runtime
tokio = { version = "1.49", features = ["full"] }

# HTTP
reqwest = { version = "0.13", default-features = false, features = ["rustls-tls", "json", "stream", "gzip"] }
reqwest-eventsource = "0.6"

# BLS cryptography
blst = "0.3.16"

# SQLite (slashing protection)
rusqlite = { version = "0.38", features = ["bundled"] }
rusqlite_migration = "2.4"

# SSZ / Ethereum types
ethereum_ssz = "0.10"
ethereum_ssz_derive = "0.10"
ssz_types = "0.14"
alloy-primitives = "1.4"
ethereum_serde_utils = "0.8"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# CLI
clap = { version = "4.5", features = ["derive", "env"] }

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["fmt", "env-filter", "json"] }

# Metrics
prometheus = { version = "0.14", features = ["process"] }

# Crypto (EIP-2335 keystore)
aes = "0.8"
ctr = "0.9"
scrypt = "0.11"
sha2 = "0.10"
zeroize = { version = "1", features = ["derive"] }

# Utilities
thiserror = "2"
anyhow = "1"
futures = "0.3"
hex = "0.4"
lazy_static = "1"
```

## Sources

[1] [Benchmarking pairing-friendly elliptic curve libraries](https://hackmd.io/@gnark/eccbench) — gnark team. BLS12-381 benchmark results.
[2] [blst crate](https://lib.rs/crates/blst) — Lib.rs. Version 0.3.16, download statistics.
[3] [supranational/blst](https://github.com/supranational/blst) — Supranational. Security audit, platform support.
[4] [rusqlite](https://lib.rs/crates/rusqlite) — Lib.rs. Version 0.38.0, bundled SQLite 3.51.1.
[5] [sqlx](https://lib.rs/crates/sqlx) — Lib.rs. Version 0.8.6 stable.
[6] [rusqlite_migration](https://lib.rs/crates/rusqlite_migration) — Version 2.4.1, user_version-based migrations.
[7] [Slashing Protection — Lighthouse Book](https://lighthouse-book.sigmaprime.io/slashing-protection.html) — Sigma Prime. SQLite slashing DB.
[8] [SQLite's Durability Settings](https://www.agwa.name/blog/post/sqlite_durability) — Andrew Ayer. Platform-specific fsync behavior.
[9] [ethereum_ssz](https://lib.rs/crates/ethereum_ssz) — Lib.rs. Version 0.10.1, Sigma Prime.
[10] [ethereum-consensus](https://github.com/ralexstokes/ethereum-consensus) — Alex Stokes. R&D-only warning.
[11] [ssz-rs](https://github.com/ralexstokes/ssz-rs) — Alex Stokes. Oak Security audit.
[12] [Introducing Alloy](https://www.paradigm.xyz/2023/06/alloy) — Paradigm. alloy-primitives replaces ethereum_types.
[13] [reqwest](https://lib.rs/crates/reqwest) — Lib.rs. Version 0.13.2.
[14] [reqwest-eventsource](https://lib.rs/crates/reqwest-eventsource) — Version 0.6.0, SSE with auto-retry.
[15] [tokio](https://lib.rs/crates/tokio) — Version 1.49.0, LTS releases.
[16] [serde](https://lib.rs/crates/serde) — Version 1.0.228.
[17] [clap](https://lib.rs/crates/clap) — Version 4.5.57, derive API.
[18] [tracing](https://lib.rs/crates/tracing) — Version 0.1.44, tokio-rs.
[19] [prometheus](https://lib.rs/crates/prometheus) — Version 0.14.0, TiKV.
[20] [Lighthouse Cargo.toml](https://github.com/sigp/lighthouse/blob/stable/Cargo.toml) — eth2_keystore path dependency.
[21] [eth-keystore](https://lib.rs/crates/eth-keystore) — Version 0.5.0. Web3 Secret Storage only (not BLS).
[22] [ERC-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335) — Full BLS keystore specification.
