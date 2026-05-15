# Tier 1 — Standards Compliance

> High impact, expected by the ecosystem. Should be prioritized.

## Overview

Tier 1 contains two feature gaps that block adoption and ecosystem integration:

| # | Feature | Effort | Impact |
|---|---------|--------|--------|
| 1 | [Extended Keymanager API](./keymanager-api.md) | Medium (~10 new endpoints) | Unblocks standard tooling integration |
| 2 | [Additional Testnet Support](./testnet-support.md) | Low (2 enum variants + constants) | Unblocks pre-mainnet testing |

## Current State Summary

**Keymanager API** — rvc implements 6 of 16 standard endpoints. Only `/eth/v1/keystores` and `/eth/v1/remotekeys` are available. The underlying domain logic (per-validator fee recipient, gas limit, graffiti, config updates) already exists in the `validator-store` crate. The missing endpoints are thin HTTP wrappers over existing functionality.

**Testnet Support** — rvc supports Mainnet, Hoodi, and Custom networks. Holesky and Sepolia are explicitly rejected. Adding them requires only genesis constants — fork schedules are already fetched dynamically from beacon nodes.

## Priority Order

1. **Holesky testnet** — unblocks all validator testing; mechanically trivial
2. **Extended Keymanager API** — unblocks ecosystem tooling (staking dashboards, Rocket Pool, etc.)
3. **Sepolia testnet** — secondary testnet; lower urgency but easy to bundle with Holesky
