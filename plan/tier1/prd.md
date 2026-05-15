# PRD: Tier 1 — Standards Compliance

## Overview

rvc (Rust Validator Client) is missing two features that are standard across all major Ethereum validator clients: full Keymanager API coverage and support for the Holesky and Sepolia testnets. Without these, rvc cannot integrate with ecosystem tooling (staking dashboards, Rocket Pool, automation platforms) and cannot be tested on public testnets before mainnet deployment. This PRD defines the requirements to close both gaps.

## Problem Statement

### Incomplete Keymanager API

The [Ethereum Keymanager API specification](https://github.com/ethereum/keymanager-APIs) defines 16 HTTP endpoints for managing validator keys and per-validator configuration. rvc implements only 6 of these — the `/eth/v1/keystores` and `/eth/v1/remotekeys` CRUD routes. The remaining 10 endpoints cover:

- **Per-validator fee recipient** management (GET/POST/DELETE) — required by staking dashboards and MEV-boost integrations to configure where execution-layer rewards are sent
- **Per-validator gas limit** management (GET/POST/DELETE) — required by operators running custom block-building strategies
- **Per-validator graffiti** management (GET/POST/DELETE) — used for validator identification and pool attribution
- **Voluntary exit** submission (POST) — enables programmatic validator exits, required by staking pools and automation tooling

All five major competing clients (Lighthouse, Prysm, Teku, Nimbus, Lodestar) implement the full specification. rvc's partial implementation prevents adoption by any tooling that assumes spec-complete clients.

### Missing Testnet Support

rvc supports only Mainnet, Hoodi, and Custom networks. Holesky and Sepolia — the two primary Ethereum testnets used for pre-mainnet validation — are explicitly rejected at the parsing layer. This means:

- Operators cannot test rvc before committing real ETH on mainnet
- CI/CD pipelines for staking operations cannot use rvc
- The client cannot participate in testnet-based ecosystem compatibility testing

All competing clients support both testnets.

## Goals & Success Metrics

| Goal | Success Metric |
|------|---------------|
| Full Keymanager API spec compliance | All 16 endpoints respond with correct status codes and JSON schemas per the OpenAPI spec |
| Testnet operability | `rvc --network holesky` and `rvc --network sepolia` start successfully and connect to respective beacon nodes |
| Ecosystem tooling compatibility | rvc integrates with at least one standard validator management tool (e.g., ethdo, Vouch, or a staking dashboard) without client-specific workarounds |
| Zero regressions | All existing 6 Keymanager API endpoints and 3 supported networks continue to function identically |
| Config persistence | Per-validator configuration changes made via API survive process restarts |

## Target Users

### Solo Staker
Runs 1–100 validators on personal hardware. Uses the Keymanager API via CLI tools (ethdo, ethstaker-deposit-cli) or lightweight web dashboards. Needs testnet support to validate their setup before depositing 32 ETH per validator on mainnet.

### Institutional Operator
Manages 100–10,000+ validators across infrastructure. Uses automation platforms (Ansible, Terraform, custom orchestration) that communicate with the Keymanager API programmatically. Requires fee recipient management for multi-entity setups and voluntary exit capability for offboarding validators.

### Staking Pool / Protocol Integrator
Builds software (Rocket Pool, Lido, SSV) that interacts with validator clients through the standardized Keymanager API. Requires full spec compliance — partial implementations cannot be special-cased. Testnet support is mandatory for integration testing.

### rvc Developer / Contributor
Needs testnet support for development and CI. Cannot run meaningful integration tests without connecting to a live testnet beacon node.

## User Stories

- As a **solo staker**, I want to run rvc on Holesky before mainnet so that I can verify my configuration without risking real ETH.
- As a **solo staker**, I want to set per-validator fee recipients via the API so that I can direct rewards to the correct wallet without editing config files.
- As an **institutional operator**, I want to programmatically trigger voluntary exits via the Keymanager API so that I can automate validator lifecycle management.
- As a **pool integrator**, I want rvc to implement all standard Keymanager API endpoints so that I can support it alongside Lighthouse, Prysm, Teku, and Nimbus without client-specific code paths.
- As an **rvc developer**, I want to run integration tests against Sepolia so that CI can validate consensus-layer behavior on a live testnet.
- As a **staking dashboard developer**, I want to GET/POST/DELETE gas limits and graffiti per-validator so that my dashboard works with rvc the same way it works with every other client.

## Functional Requirements

### Must Have (P0)

#### FR-1: Holesky Network Support
Add `Holesky` variant to the `Network` enum with correct genesis constants.

| Field | Value |
|-------|-------|
| `genesis_time` | `1695902400` (2023-09-28T12:00:00Z) |
| `genesis_validators_root` | `0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1` |

**Acceptance Criteria:**
- `"holesky".parse::<Network>()` returns `Ok(Network::Holesky)`
- `Network::Holesky.genesis_time()` returns `Some(1695902400)`
- `Network::Holesky.genesis_validators_root()` returns the correct root
- Serde round-trip works (`"holesky"` serializes and deserializes)
- `rvc --network holesky` starts and connects to a Holesky beacon node

#### FR-2: Sepolia Network Support
Add `Sepolia` variant to the `Network` enum with correct genesis constants.

| Field | Value |
|-------|-------|
| `genesis_time` | `1655733600` (2022-06-20T14:00:00Z) |
| `genesis_validators_root` | `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078` |

**Acceptance Criteria:**
- `"sepolia".parse::<Network>()` returns `Ok(Network::Sepolia)`
- `Network::Sepolia.genesis_time()` returns `Some(1655733600)`
- `Network::Sepolia.genesis_validators_root()` returns the correct root
- Serde round-trip works
- `rvc --network sepolia` starts and connects to a Sepolia beacon node

#### FR-3: Keygen Tool Testnet Support
Extend `rvc-keygen` to support Holesky and Sepolia with correct genesis fork versions and Capella fork versions for BLS-to-execution-change signing.

| Network | Genesis Fork Version | Capella Fork Version |
|---------|---------------------|---------------------|
| Holesky | `[0x01, 0x01, 0x70, 0x00]` | `[0x04, 0x01, 0x70, 0x00]` |
| Sepolia | `[0x90, 0x00, 0x00, 0x69]` | `[0x90, 0x00, 0x00, 0x72]` |

**Acceptance Criteria:**
- `from_name("holesky")` and `from_name("sepolia")` return valid `KeygenNetwork` structs
- `rvc-keygen --network holesky` and `rvc-keygen --network sepolia` work correctly

#### FR-4: Fee Recipient Endpoints (GET/POST/DELETE)
Implement three endpoints for per-validator fee recipient management.

| Method | Path | Request Body | Response | Status |
|--------|------|-------------|----------|--------|
| GET | `/eth/v1/validator/{pubkey}/feerecipient` | — | `{ "data": { "pubkey": "0x...", "ethaddress": "0x..." } }` | 200 |
| POST | `/eth/v1/validator/{pubkey}/feerecipient` | `{ "ethaddress": "0x..." }` | — | 202 |
| DELETE | `/eth/v1/validator/{pubkey}/feerecipient` | — | — | 204 |

**Behavior:**
- GET returns the effective fee recipient (per-validator override or global default)
- POST sets a per-validator override, persists to TOML config
- DELETE removes the per-validator override, reverting to global default; persists to TOML config

**Acceptance Criteria:**
- GET returns correct effective value (override or default)
- POST with valid 20-byte hex address updates and persists the fee recipient
- POST with invalid address returns 400
- DELETE resets to default and persists the change
- Unknown pubkey returns 404 for all methods
- Bearer token authentication required for all methods

#### FR-5: Gas Limit Endpoints (GET/POST/DELETE)
Implement three endpoints for per-validator gas limit management.

| Method | Path | Request Body | Response | Status |
|--------|------|-------------|----------|--------|
| GET | `/eth/v1/validator/{pubkey}/gas_limit` | — | `{ "data": { "pubkey": "0x...", "gas_limit": "30000000" } }` | 200 |
| POST | `/eth/v1/validator/{pubkey}/gas_limit` | `{ "gas_limit": "35000000" }` | — | 202 |
| DELETE | `/eth/v1/validator/{pubkey}/gas_limit` | — | — | 204 |

**Behavior:**
- GET returns effective gas limit (per-validator override or default 30,000,000)
- POST sets a per-validator override; `gas_limit` is a string-encoded u64 per spec
- DELETE removes the override, reverting to default

**Acceptance Criteria:**
- GET returns string-encoded gas limit (not JSON number)
- POST with valid numeric string updates and persists the gas limit
- POST with non-numeric string returns 400
- DELETE resets to default (30,000,000)
- Unknown pubkey returns 404

#### FR-6: Graffiti Endpoints (GET/POST/DELETE)
Implement three endpoints for per-validator graffiti management.

| Method | Path | Request Body | Response | Status |
|--------|------|-------------|----------|--------|
| GET | `/eth/v1/validator/{pubkey}/graffiti` | — | `{ "data": { "pubkey": "0x...", "graffiti": "..." } }` | 200 |
| POST | `/eth/v1/validator/{pubkey}/graffiti` | `{ "graffiti": "my-graffiti" }` | — | 202 |
| DELETE | `/eth/v1/validator/{pubkey}/graffiti` | — | — | 204 |

**Behavior:**
- GET returns effective graffiti (per-validator override or default; empty string if none set)
- POST sets graffiti; must be <= 32 bytes (ASCII)
- DELETE removes override, reverting to default

**Acceptance Criteria:**
- POST with > 32 bytes returns 400
- GET returns correct effective graffiti
- DELETE resets to default
- Unknown pubkey returns 404

#### FR-7: Voluntary Exit Endpoint (POST)
Implement one endpoint for submitting signed voluntary exits.

| Method | Path | Request Body | Response | Status |
|--------|------|-------------|----------|--------|
| POST | `/eth/v1/validator/{pubkey}/voluntary_exit` | `{ "epoch": "300000" }` (epoch optional) | `{ "data": { "message": { "epoch": "...", "validator_index": "..." }, "signature": "0x..." } }` | 200 |

**Behavior:**
- If `epoch` is omitted, use the current epoch calculated from the beacon node
- Resolve validator index from beacon node via pubkey
- Sign the voluntary exit using the validator's key
- Submit the signed exit to the beacon node
- Return the `SignedVoluntaryExit` in the response

**Acceptance Criteria:**
- POST with explicit epoch signs and submits exit at that epoch
- POST without epoch auto-detects current epoch from beacon node
- Response contains valid `SignedVoluntaryExit` with correct message and signature fields
- Unknown pubkey returns 404
- Beacon node unreachable returns 500 with descriptive error message
- WARN-level log emitted for every exit request (irreversible operation)

#### FR-8: Config Persistence
All POST and DELETE operations on fee recipient, gas limit, and graffiti endpoints must persist changes to the TOML config file so they survive process restarts.

**Acceptance Criteria:**
- Changes made via API are visible after restart without re-applying
- Atomic writes (temp file + rename) prevent corruption on crash
- Concurrent API requests do not clobber each other (write serialization via lock)
- Round-trip: load config → update via API → restart → load config → values match

#### FR-9: ValidatorConfigManager Trait
Define a `ValidatorConfigManager` trait in `crates/keymanager-api/src/traits.rs` with 9 methods (get/set/delete for each of fee_recipient, gas_limit, graffiti) to maintain the existing trait-based abstraction layer.

**Acceptance Criteria:**
- Trait compiles with `Send + Sync` bounds
- Adapter implementation in `crates/rvc/src/keymanager_adapters.rs` delegates to `ValidatorStore`
- Unknown pubkey returns appropriate error for 404 response

#### FR-10: VoluntaryExitManager Trait
Define a `VoluntaryExitManager` trait in `crates/keymanager-api/src/traits.rs` with a single `submit_voluntary_exit(pubkey, epoch) -> SignedVoluntaryExit` method.

**Acceptance Criteria:**
- Trait compiles with `Send + Sync` bounds
- Adapter wraps beacon client, signer, fork schedule, and genesis validators root
- Logic ported from `bin/rvc/src/commands/voluntary_exit.rs`

### Should Have (P1)

#### FR-11: Deprecation Test Cleanup
Update existing tests that explicitly reject Holesky and Sepolia. Keep Goerli rejection test (deprecated network).

**Acceptance Criteria:**
- `test_network_from_str_deprecated_networks_rejected` only asserts Goerli
- New `test_network_from_str_testnets_accepted` asserts Holesky and Sepolia
- `test_network_serde_deprecated_networks_rejected` only asserts Goerli

#### FR-12: API Error Type Extension
Add `ApiError::NotFound` variant to `crates/keymanager-api/src/error.rs` mapping to HTTP 404 for unknown validator pubkeys.

**Acceptance Criteria:**
- `ApiError::NotFound` returns 404 status code
- Consistent error response format: `{ "message": "..." }`

### Nice to Have (P2)

#### FR-13: Documentation Updates
Update `config.example.toml` to list all 5 supported networks. Update CLI `--help` text for `--network` flag.

**Acceptance Criteria:**
- Config example documents `mainnet`, `hoodi`, `holesky`, `sepolia`, `custom`
- CLI help text lists all network options

## Non-Functional Requirements

### Performance
- **NFR-1:** Config GET endpoints must respond within 1ms (in-memory lookup, no I/O on read path)
- **NFR-2:** Config POST/DELETE endpoints must complete within 50ms including disk persistence
- **NFR-3:** Voluntary exit endpoint latency is dominated by beacon node round-trips; the handler itself must not add > 10ms overhead

### Security
- **NFR-4:** All 10 new endpoints must require valid Bearer token authentication (consistent with existing 6 endpoints)
- **NFR-5:** Bearer token comparison must use constant-time equality (existing `auth` module already provides this)
- **NFR-6:** Voluntary exit is irreversible; every exit request must be logged at WARN level with pubkey and epoch
- **NFR-7:** Pubkey path parameters must be validated before any operation — reject malformed hex with 400, reject unknown validators with 404
- **NFR-8:** Config file writes must use atomic rename (write to temp file, then rename) to prevent corruption

### Compatibility
- **NFR-9:** All request and response schemas must conform to the [ethereum/keymanager-APIs](https://github.com/ethereum/keymanager-APIs) OpenAPI specification
- **NFR-10:** HTTP status codes must match the spec: 200 (GET success), 202 (POST success for config), 204 (DELETE success), 400 (bad input), 401 (unauthorized), 404 (unknown validator), 500 (server error)
- **NFR-11:** `gas_limit` must be string-encoded in JSON responses (not a JSON number), per spec
- **NFR-12:** Pubkeys in responses must be 0x-prefixed, lowercase hex

### Reliability
- **NFR-13:** Concurrent POST requests to the same validator must not produce inconsistent state (serialized writes via `RwLock`)
- **NFR-14:** Partial write failure must not corrupt the existing config file (atomic rename)
- **NFR-15:** The existing 6 Keymanager API endpoints must not regress in behavior, latency, or error handling

### Testability
- **NFR-16:** All new handlers must be testable via mock trait implementations (no concrete `ValidatorStore` dependency in handler code)
- **NFR-17:** Integration tests must cover full HTTP round-trips for all 10 new endpoints

## Technical Considerations

### Architecture

The existing codebase follows a clean trait-based architecture:

```
HTTP Layer (Axum)          Trait Layer              Implementation Layer
─────────────────          ───────────              ────────────────────
handlers.rs         →      traits.rs          →     keymanager_adapters.rs
  (request parsing,          (KeystoreManager,         (delegates to
   response formatting)       RemoteKeyManager,          ValidatorStore,
                              + new traits)              CompositeSigner,
                                                         BeaconClient)
```

New endpoints follow the same pattern:
1. Define `ValidatorConfigManager` and `VoluntaryExitManager` traits
2. Implement adapters that delegate to existing `ValidatorStore` and beacon client
3. Add Axum handlers that accept trait objects via `State`
4. Register routes in `server.rs`

### Key Integration Points

| Component | Crate | Role |
|-----------|-------|------|
| `ValidatorStore` | `validator-store` | Already has `effective_fee_recipient()`, `effective_gas_limit()`, `effective_graffiti()`, `update_config()`. Needs `save_config()` for persistence. |
| `ValidatorConfig` | `validator-store` | Already has `fee_recipient`, `gas_limit`, `graffiti` fields with `Option` semantics for override-or-default. |
| `ValidatorConfigUpdate` | `validator-store` | Already supports `Option<Option<T>>` pattern for set/delete operations. |
| `CompositeSigner` | `crypto` | Signs voluntary exits. Already used in CLI command. |
| `BeaconClient` | `beacon` | Resolves validator indices, fetches genesis/fork data, submits exits. Already used in CLI command. |
| `KeymanagerServer` | `keymanager-api` | Needs new trait objects added to its constructor and Axum state. |

### Dependencies

No new external crate dependencies are required. All functionality uses:
- `axum` (existing) — HTTP framework
- `serde` / `serde_json` (existing) — serialization
- `toml` (existing) — config persistence
- `parking_lot` (existing) — synchronization
- `hex` (existing) — pubkey encoding/decoding
- `tracing` (existing) — logging

### Config Persistence Design

The `ValidatorStore` already has `update_config()` for in-memory updates and `reload_config()` for hot-reloading from disk. A new `save_config()` method is needed that:
1. Acquires the write lock on the validators map
2. Serializes current state to TOML
3. Writes to a temporary file in the same directory
4. Atomically renames the temp file to the config path

This ensures the existing `reload_config()` flow remains compatible and crash-safe.

### Voluntary Exit Considerations

The existing CLI implementation in `bin/rvc/src/commands/voluntary_exit.rs` builds its own signer and beacon client from scratch. The API endpoint adapter will instead receive pre-constructed `Arc<CompositeSigner>` and `Arc<BeaconClient>` from the server's dependency injection, avoiding redundant initialization.

The CLI's interactive confirmation prompt (`--confirm`) does not apply to the API — the act of calling the endpoint is the confirmation. The API must still log at WARN level as the CLI does.

## Out of Scope

The following are explicitly **not** included in this PRD:

- **Builder proposal management endpoints** — `builder_proposals` and `builder_boost_factor` fields exist in `ValidatorConfig` but are not part of the standard Keymanager API spec
- **Goerli testnet support** — Goerli is deprecated and will remain rejected
- **Custom network enhancements** — the `Custom` variant continues to require explicit genesis parameters
- **Slashing protection import/export improvements** — the existing endpoints are sufficient
- **Web3Signer endpoint extensions** — the existing remote key CRUD is spec-complete
- **Keymanager API v2** — no breaking changes to existing endpoint contracts
- **Multi-beacon-node failover** — out of scope for this initiative
- **Metrics or monitoring endpoints** — not part of the Keymanager API spec
- **Rate limiting or request throttling** — not required by the spec
- **Doppelganger detection for voluntary exits** — the validator is exiting; doppelganger checks are irrelevant

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| **Genesis constant inaccuracy** — wrong genesis_validators_root or genesis_time for Holesky/Sepolia | Validators produce invalid signatures, fail attestations | Low | Verify constants against official Ethereum specs and a live beacon node before shipping |
| **Config persistence race condition** — concurrent POST requests clobber each other | Per-validator config corruption | Medium | Serialize writes through the existing `RwLock`; use atomic file rename |
| **Accidental voluntary exit** — API caller triggers irreversible exit unintentionally | Validator permanently exits the network | Medium | WARN-level logging on every exit; return the signed exit in the response so callers can verify before acting; document irreversibility in API docs |
| **Spec divergence** — response format doesn't match Keymanager API OpenAPI spec exactly | Tooling integration fails | Medium | Validate all response schemas against the OpenAPI spec during E2E testing; test with at least one external tool |
| **Regression in existing endpoints** — new code path or state changes break existing keystore/remotekey routes | Existing users impacted | Low | Maintain existing route registrations unchanged; run full existing test suite as part of CI |
| **Voluntary exit requires beacon node access** — Keymanager API server may not have direct beacon client access in all deployment topologies | Exit endpoint returns 500 | Low | Document that the voluntary exit endpoint requires beacon node connectivity; make the trait optional in server construction (degrade gracefully if not configured) |

## References

- [Ethereum Keymanager API Specification](https://github.com/ethereum/keymanager-APIs) — OpenAPI spec for all 16 endpoints
- [EIP-3076: Slashing Protection Interchange Format](https://eips.ethereum.org/EIPS/eip-3076) — referenced by existing slashing protection endpoints
- [Holesky Testnet Configuration](https://github.com/eth-clients/holesky) — genesis constants and fork schedule
- [Sepolia Testnet Configuration](https://github.com/eth-clients/sepolia) — genesis constants and fork schedule
- `plan/tier1/keymanager-api.md` — detailed gap analysis and implementation plan
- `plan/tier1/testnet-support.md` — detailed testnet analysis and implementation plan
- `plan/tier1/dev-plan.md` — phased development plan with 17 issues across 5 epics
