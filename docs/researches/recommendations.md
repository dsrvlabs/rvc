# Research: Ethereum Validator Client PRD — Open Questions Recommendations

## Summary of Recommendations

| # | Question | Recommendation | Confidence |
|---|----------|----------------|------------|
| 1 | SQLite library | **rusqlite** with `bundled` feature | High — validated by Lighthouse production use |
| 2 | SSZ vs JSON | **JSON-only initially**, SSZ for block production in Phase 4 | High — follows ecosystem evolution path |
| 3 | Auth mechanism | **Bearer token** per Ethereum Keymanager API standard | Very High — it is the standard |
| 4 | Fork handling | **Compile-time `ForkName` enum** + runtime detection from BN | High — proven pattern in Lighthouse |
| 5 | MSRV | **Rust 1.85.0**, edition 2024 | High — minimum for edition 2024 |
| 6 | License | **Apache-2.0 OR MIT** (dual) | Very High — Rust ecosystem standard |

---

## 1. rusqlite vs sqlx for Slashing Protection DB

### Recommended Approach: `rusqlite` 0.38 with `bundled` feature

**How it works:** Synchronous SQLite access with bundled SQLite 3.51.1. Direct PRAGMA control for `synchronous = FULL`, `journal_mode = WAL`, and `locking_mode = EXCLUSIVE`.

**Why this one:**
- **Synchronous is correct for slashing protection.** The signing operation MUST NOT proceed until the slashing check is durably recorded. Async (sqlx) adds complexity and makes reasoning about write ordering harder [1].
- **Proven by Lighthouse.** 5+ years of production use with the same approach [2].
- **Bundled SQLite** eliminates system dependency issues across Linux distributions and macOS [1].
- **Full PRAGMA control** is essential — `synchronous = FULL` in WAL mode forces fsync on every commit, which is non-negotiable for slashing safety. sqlx's abstraction layer makes this less direct [3].
- `rusqlite_migration` (v2.4) provides lightweight schema migration using SQLite's `user_version` field [4].

**Trade-offs:** Not async-native. For the slashing DB this is fine — `tokio::task::spawn_blocking` bridges the gap when called from async context.

### Alternative: sqlx 0.8

**When to prefer:** Application databases with complex query patterns, high-concurrency reads, and compile-time SQL checking. NOT for slashing protection.

**Why not for slashing DB:** Async wrapping of synchronous SQLite adds unnecessary complexity [5]. Much larger dependency tree. Not used by any Ethereum client for slashing protection.

---

## 2. SSZ vs JSON-only for Beacon API Responses

### Recommended Approach: JSON-only initially, SSZ for block production in Phase 4

**How it works:** Use `serde` + `serde_json` for all beacon API communication in Phases 1-3. In Phase 4, add SSZ support for block production endpoints where the performance benefit is measurable.

**Why this one:**
- **JSON is the universal default.** Every beacon node supports JSON on every endpoint. Not all BNs support SSZ on all endpoints [6].
- **Performance difference matters only for block production.** Attestation data is small; JSON parsing adds negligible overhead. Block production (especially post-Deneb with blobs) benefits from SSZ — Lighthouse reported 200-250ms savings on `getPayload` [7].
- **Simpler initial implementation.** JSON parsing with `serde_json` is trivial. SSZ requires additional type definitions, content negotiation logic, and the `Eth-Consensus-Version` header for deserialization [6].
- **Follows the path other VCs took.** Lighthouse started JSON-only, added SSZ for block production later. Lodestar added SSZ as opt-in (`--http.requestWireFormat ssz`) [8].

**Phase 4 implementation plan:**
1. Set `Accept: application/octet-stream;q=1.0,application/json;q=0.9` on block requests
2. Parse `Content-Type` header to determine format
3. Fall back to JSON if BN returns JSON despite SSZ preference
4. Handle `Eth-Consensus-Version` header for SSZ deserialization

**Trade-offs:** Slightly higher latency on block proposals vs SSZ-native (estimated 200-250ms on large blocks [7]).

---

## 3. Auth Mechanism for Key Management API (FR-24)

### Recommended Approach: Bearer Token per Ethereum Keymanager API Standard

**How it works:** The VC exposes the standard [Ethereum Keymanager API](https://ethereum.github.io/keymanager-APIs/) [9] with Bearer token authentication. On first startup, generate a cryptographically random 256-bit token, write it hex-encoded to `api-token.txt`, and require it in the `Authorization: Bearer <token>` header [10].

**Why this one:**
- **It IS the standard.** The Keymanager API spec (`ethereum/keymanager-APIs`) mandates Bearer token authentication [9][10].
- **All major VCs implement it.** Lighthouse, Teku, Nimbus, Lodestar, Prysm all use the same mechanism [10][11].
- **Tooling expects it.** Staking management tools, DAppNode, and other infrastructure expect the standard auth mechanism.
- **Simple and sufficient.** The API should only be accessible on localhost. Bearer token over HTTPS is adequate for this threat model.

**Implementation:**
```rust
fn generate_api_token(data_dir: &Path) -> Result<String> {
    let token_path = data_dir.join("api-token.txt");
    if token_path.exists() {
        return std::fs::read_to_string(&token_path).map(|s| s.trim().to_string());
    }
    let mut token_bytes = [0u8; 32]; // 256 bits
    getrandom::getrandom(&mut token_bytes)?;
    let token = hex::encode(token_bytes);
    std::fs::write(&token_path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(token)
}
```

**Guidelines:**
- Bind to `127.0.0.1` by default — require explicit `--api-address` for other interfaces
- Validate token file permissions on startup (warn if world-readable, per NFR-9)
- Accept `--token-file` CLI parameter for custom token path
- Return 401 for missing/invalid tokens

### Alternative: mTLS

**When to prefer:** Institutional deployments where the API is exposed across a network. Can be added as an optional layer alongside Bearer token (FR-30 mentions mTLS for BN connections as P2).

---

## 4. Fork Handling Strategy

### Recommended Approach: Compile-time `ForkName` enum + runtime detection from BN

**How it works:** Define an exhaustive `ForkName` enum at compile time. At startup, query `/eth/v1/config/spec` for fork epochs and versions [12]. Map the BN's fork schedule to the compiled enum. Use fork name for signing domain dispatch.

**Why this one:**
- **Compile-time exhaustiveness checking.** Rust's `match` forces handling every fork variant. Adding a new fork to the enum produces compiler errors at every unhandled match point [13].
- **VC fork surface is small.** Unlike a BN, a VC only needs fork-aware logic for: signing domain computation, block structure differences, and duty API versioning.
- **Runtime detection ensures BN compatibility.** Different networks (mainnet, Holesky, Sepolia, devnets) have different fork schedules [12].
- **Proven by Lighthouse.** Uses `ForkName` enum with the `superstruct` crate for fork-versioned types [13][14].

**Design:**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForkName {
    Phase0, Altair, Bellatrix, Capella, Deneb, Electra,
}

impl ForkName {
    pub fn from_epoch(epoch: Epoch, schedule: &ForkSchedule) -> Self {
        if epoch >= schedule.electra_fork_epoch { ForkName::Electra }
        else if epoch >= schedule.deneb_fork_epoch { ForkName::Deneb }
        else if epoch >= schedule.capella_fork_epoch { ForkName::Capella }
        else if epoch >= schedule.bellatrix_fork_epoch { ForkName::Bellatrix }
        else if epoch >= schedule.altair_fork_epoch { ForkName::Altair }
        else { ForkName::Phase0 }
    }
}
```

**Handling unknown forks:**
- If BN reports an unknown fork epoch key that is NOT yet active: log a warning, continue
- If an unknown fork IS active (current epoch >= fork epoch): **refuse to start** — signing with wrong fork logic risks slashing
- Load fork schedule from `/eth/v1/config/spec` at startup [12]

**Do NOT use `superstruct` initially.** A VC can use simpler match-based dispatch. Consider `superstruct` only if fork-specific type variants become unwieldy.

---

## 5. MSRV (Minimum Supported Rust Version)

### Recommended Approach: Rust 1.85.0, edition 2024

**Rationale:**

| Project | MSRV | Edition |
|---------|------|---------|
| Reth | 1.88.0 | 2024 [15] |
| Lighthouse | ~1.88.0+ | 2024 [16] |
| Tokio LTS (1.47.x) | 1.70 | — [17] |
| This project (recommended) | **1.85.0** | **2024** |

**Why 1.85.0:**
- **Edition 2024 requires 1.85.0+.** The Rust 2024 edition was stabilized in 1.85.0. Both Reth and Lighthouse have adopted edition 2024 [15][16].
- **Not bleeding edge.** ~12 months old, giving operators time to update toolchains.
- **All key dependencies support it.** tokio, blst, reqwest, rusqlite all build with 1.85.0+.
- **Conservative relative to peers.** Reth and Lighthouse use 1.88.0+. Choosing 1.85.0 is the minimum for edition 2024.

**Implementation:**
```toml
[workspace.package]
edition = "2024"
rust-version = "1.85"
```

Add a CI job building with exactly Rust 1.85.0. Use `cargo msrv verify` [18].

---

## 6. License

### Recommended Approach: Dual-license `Apache-2.0 OR MIT`

**Ethereum client licensing landscape:**

| Client | License |
|--------|---------|
| Lighthouse | Apache-2.0 [16] |
| Reth | Apache-2.0 OR MIT [15] |
| Prysm | GPL-3.0 [19] |
| Teku | Apache-2.0 [20] |
| Nimbus | Apache-2.0 [20] |
| Lodestar | Apache-2.0 [20] |
| Vouch | Apache-2.0 [21] |

**Why dual Apache-2.0 OR MIT:**

- **Rust ecosystem convention.** Rust itself, the standard library, Cargo, and the vast majority of Rust crates use this dual license [22].
- **Apache-2.0 provides explicit patent protection.** Section 3 grants a patent license to users. MIT has no patent clause. For a validator client handling financial assets, this matters [22].
- **Apache-2.0 includes patent retaliation.** If a contributor sues users for patent infringement, they lose their patent license [22].
- **MIT enables GPL-2.0 compatibility.** Apache-2.0 is incompatible with GPL-2.0. Dual-licensing with MIT allows GPL-2.0 projects to use the code under MIT [22].
- **Reth sets the precedent** for dual licensing in Rust-Ethereum [15].

**Why NOT GPL-3.0:** Prysm's GPL-3.0 is the outlier. It prevents code sharing with Apache-2.0 projects. For a project motivated by client diversity and interoperability, copyleft creates friction.

**Implementation:**
```toml
# Every crate's Cargo.toml
[package]
license = "Apache-2.0 OR MIT"
```

Add `LICENSE-APACHE` and `LICENSE-MIT` files to repository root. Use SPDX identifiers in source file headers:
```rust
// Copyright 2026 [Project Name] Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
```

---

## Sources

[1] [rusqlite GitHub](https://github.com/rusqlite/rusqlite) — Bundled feature, MSRV policy.
[2] [Slashing Protection — Lighthouse Book](https://lighthouse-book.sigmaprime.io/slashing-protection.html) — SQLite/rusqlite usage confirmed.
[3] [Write-Ahead Logging — SQLite](https://sqlite.org/wal.html) — WAL mode, synchronous settings.
[4] [rusqlite_migration](https://github.com/cljoly/rusqlite_migration) — Schema migration for rusqlite.
[5] [sqlx SQLite Architecture — Issue #793](https://github.com/launchbadge/sqlx/issues/793) — spawn_blocking overhead discussion.
[6] [Provide first-class SSZ support — Issue #250](https://github.com/ethereum/beacon-APIs/issues/250) — SSZ performance, endpoint coverage.
[7] [Add SSZ for block production — Issue #4531](https://github.com/sigp/lighthouse/issues/4531) — 200-250ms savings.
[8] [A Lodestar for Consensus 2024](https://blog.chainsafe.io/a-lodestar-for-consensus-2024/) — SSZ wire format opt-in.
[9] [Ethereum Keymanager APIs](https://ethereum.github.io/keymanager-APIs/) — Official standard.
[10] [Keymanager APIs GitHub](https://github.com/ethereum/keymanager-APIs) — Bearer token specification.
[11] [Validator Client API — Lighthouse Book](https://lighthouse-book.sigmaprime.io/api-vc.html) — Bearer token implementation.
[12] [/eth/v1/config/spec documentation](https://www.quicknode.com/docs/ethereum/eth-v1-config-spec) — Fork epoch fields.
[13] [SuperStruct](https://github.com/sigp/superstruct) — Sigma Prime. Fork-versioned data types.
[14] [Lighthouse Update #35](https://blog.sigmaprime.io/update-35.html) — SuperStruct introduction for Altair.
[15] [Reth Build from Source](https://reth.rs/installation/source/) — MSRV 1.88, edition 2024, Apache-2.0 OR MIT.
[16] [Lighthouse Build from Source](https://lighthouse-book.sigmaprime.io/installation-source.html) — Build requirements, Apache-2.0.
[17] [tokio GitHub](https://github.com/tokio-rs/tokio) — LTS 1.47.x, MSRV 1.70.
[18] [cargo-msrv](https://github.com/foresterre/cargo-msrv) — MSRV verification tool.
[19] [prysmaticlabs/prysm](https://github.com/prysmaticlabs/prysm) — GPL-3.0 license.
[20] [Consensus Clients — EthStaker](https://docs.ethstaker.org/validator-clients/consensus-clients/) — License overview.
[21] [attestantio/vouch](https://github.com/attestantio/vouch) — Apache-2.0.
[22] [Rationale of Apache dual licensing — Rust Internals](https://internals.rust-lang.org/t/rationale-of-apache-dual-licensing/8952) — Patent protection rationale.
