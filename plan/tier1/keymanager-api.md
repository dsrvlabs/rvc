# Extended Keymanager API

## Problem

rvc only implements `/eth/v1/keystores` and `/eth/v1/remotekeys` (6 routes). The [Ethereum Keymanager API spec](https://github.com/ethereum/keymanager-APIs) defines 10 additional endpoints for per-validator configuration and voluntary exit. All major clients (Lighthouse, Prysm, Teku, Nimbus, Lodestar) implement these. Without them, rvc cannot integrate with standard validator management tooling (staking dashboards, automation platforms, Rocket Pool, etc.).

## Current Architecture

### Existing Keymanager API

- **Framework:** Axum
- **Bind address:** `127.0.0.1:5062` (configurable via `--keymanager-address`)
- **Auth:** Bearer token (64 hex chars, constant-time comparison)
- **Body limit:** 10 MB
- **CORS:** Configurable origins

**Current routes** (`crates/keymanager-api/src/server.rs`):

| Method | Endpoint | Handler |
|--------|----------|---------|
| GET | `/eth/v1/keystores` | `list_keystores` |
| POST | `/eth/v1/keystores` | `import_keystores` |
| DELETE | `/eth/v1/keystores` | `delete_keystores` |
| GET | `/eth/v1/remotekeys` | `list_remote_keys` |
| POST | `/eth/v1/remotekeys` | `import_remote_keys` |
| DELETE | `/eth/v1/remotekeys` | `delete_remote_keys` |

### Existing Validator Store

The `validator-store` crate (`crates/validator-store/`) already has full per-validator config support:

```rust
// crates/validator-store/src/config.rs
pub struct ValidatorConfig {
    pub pubkey: [u8; 48],
    pub fee_recipient: Option<[u8; 20]>,
    pub gas_limit: Option<u64>,
    pub builder_proposals: bool,
    pub builder_boost_factor: u64,
    pub graffiti: Option<[u8; 32]>,
    pub enabled: bool,
}

pub struct ValidatorDefaults {
    pub fee_recipient: [u8; 20],
    pub gas_limit: u64,              // default: 30,000,000
    pub graffiti: Option<[u8; 32]>,
}
```

**Existing methods on `ValidatorStore`:**

| Method | Purpose |
|--------|---------|
| `effective_fee_recipient(pubkey)` | Returns per-validator override or default |
| `effective_gas_limit(pubkey)` | Returns per-validator override or default |
| `effective_graffiti(pubkey)` | Returns per-validator override or default |
| `update_config(pubkey, update)` | Updates validator config in-memory |
| `reload_config()` | Hot-reloads TOML file atomically |
| `is_builder_enabled(pubkey)` | Checks builder proposal status |
| `builder_boost_factor(pubkey)` | Returns boost factor |

### Existing Voluntary Exit

CLI command in `bin/rvc/src/commands/voluntary_exit.rs`:

1. Resolve validator index from beacon node via pubkey
2. Determine exit epoch (provided or current)
3. Build signer from keystore + password
4. Fetch fork schedule and genesis validators root
5. Create and sign `VoluntaryExit` message
6. Submit signed exit to beacon node

### Trait Abstraction Layer

The keymanager API uses trait-based abstraction (`crates/keymanager-api/src/traits.rs`):

| Trait | Purpose |
|-------|---------|
| `KeystoreManager` | Local key CRUD |
| `RemoteKeyManager` | Web3Signer key CRUD |
| `SlashingProtection` | Import/export slashing DB |
| `ValidatorManager` | Validator lifecycle |
| `DoppelgangerMonitor` | Doppelganger status |

Adapters in `crates/rvc/src/keymanager_adapters.rs` bridge these traits to concrete implementations.

## Missing Endpoints

### Fee Recipient (3 endpoints)

| Method | Endpoint | Behavior |
|--------|----------|----------|
| GET | `/eth/v1/validator/{pubkey}/feerecipient` | Return `ethaddress` (per-validator or default) |
| POST | `/eth/v1/validator/{pubkey}/feerecipient` | Set per-validator fee recipient |
| DELETE | `/eth/v1/validator/{pubkey}/feerecipient` | Remove override, revert to default |

**Request body (POST):**
```json
{ "ethaddress": "0x1234567890abcdef1234567890abcdef12345678" }
```

**Response body (GET):**
```json
{
  "data": {
    "pubkey": "0x...",
    "ethaddress": "0x..."
  }
}
```

**Maps to:** `effective_fee_recipient()` / `update_config()` with `fee_recipient = Some(addr)` or `fee_recipient = None`

### Gas Limit (3 endpoints)

| Method | Endpoint | Behavior |
|--------|----------|----------|
| GET | `/eth/v1/validator/{pubkey}/gas_limit` | Return gas limit (per-validator or default 30M) |
| POST | `/eth/v1/validator/{pubkey}/gas_limit` | Set per-validator gas limit |
| DELETE | `/eth/v1/validator/{pubkey}/gas_limit` | Remove override, revert to default |

**Request body (POST):**
```json
{ "gas_limit": "35000000" }
```

**Response body (GET):**
```json
{
  "data": {
    "pubkey": "0x...",
    "gas_limit": "30000000"
  }
}
```

**Maps to:** `effective_gas_limit()` / `update_config()` with `gas_limit = Some(val)` or `gas_limit = None`

### Graffiti (3 endpoints)

| Method | Endpoint | Behavior |
|--------|----------|----------|
| GET | `/eth/v1/validator/{pubkey}/graffiti` | Return graffiti (per-validator or default) |
| POST | `/eth/v1/validator/{pubkey}/graffiti` | Set per-validator graffiti |
| DELETE | `/eth/v1/validator/{pubkey}/graffiti` | Remove override, revert to default |

**Request body (POST):**
```json
{ "graffiti": "my-validator-graffiti" }
```

**Response body (GET):**
```json
{
  "data": {
    "pubkey": "0x...",
    "graffiti": "my-validator-graffiti"
  }
}
```

**Maps to:** `effective_graffiti()` / `update_config()` with `graffiti = Some(bytes)` or `graffiti = None`

### Voluntary Exit (1 endpoint)

| Method | Endpoint | Behavior |
|--------|----------|----------|
| POST | `/eth/v1/validator/{pubkey}/voluntary_exit` | Sign and submit voluntary exit |

**Request body (POST):**
```json
{ "epoch": "300000" }
```
`epoch` is optional. If omitted, use current epoch from beacon node.

**Response body:**
```json
{
  "data": {
    "message": {
      "epoch": "300000",
      "validator_index": "12345"
    },
    "signature": "0x..."
  }
}
```

**Implementation:** Port logic from `commands/voluntary_exit.rs` into a handler. Requires access to beacon client, signer, fork schedule, and genesis validators root — these must be injected into the keymanager server state.

## Implementation Plan

### Phase 1: Extend Traits and Adapters

1. **Add `ValidatorConfigManager` trait** to `crates/keymanager-api/src/traits.rs`:

```rust
#[async_trait]
pub trait ValidatorConfigManager: Send + Sync {
    fn get_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<[u8; 20], ApiError>;
    fn set_fee_recipient(&self, pubkey: &[u8; 48], addr: [u8; 20]) -> Result<(), ApiError>;
    fn delete_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<(), ApiError>;

    fn get_gas_limit(&self, pubkey: &[u8; 48]) -> Result<u64, ApiError>;
    fn set_gas_limit(&self, pubkey: &[u8; 48], limit: u64) -> Result<(), ApiError>;
    fn delete_gas_limit(&self, pubkey: &[u8; 48]) -> Result<(), ApiError>;

    fn get_graffiti(&self, pubkey: &[u8; 48]) -> Result<Option<[u8; 32]>, ApiError>;
    fn set_graffiti(&self, pubkey: &[u8; 48], graffiti: [u8; 32]) -> Result<(), ApiError>;
    fn delete_graffiti(&self, pubkey: &[u8; 48]) -> Result<(), ApiError>;
}
```

2. **Add `VoluntaryExitManager` trait**:

```rust
#[async_trait]
pub trait VoluntaryExitManager: Send + Sync {
    async fn submit_voluntary_exit(
        &self,
        pubkey: &[u8; 48],
        epoch: Option<u64>,
    ) -> Result<SignedVoluntaryExit, ApiError>;
}
```

3. **Implement adapters** in `crates/rvc/src/keymanager_adapters.rs` that delegate to `ValidatorStore` and beacon client.

### Phase 2: Add Route Handlers

4. **Add handlers** in `crates/keymanager-api/src/handlers.rs`:
   - `get_fee_recipient`, `set_fee_recipient`, `delete_fee_recipient`
   - `get_gas_limit`, `set_gas_limit`, `delete_gas_limit`
   - `get_graffiti`, `set_graffiti`, `delete_graffiti`
   - `submit_voluntary_exit`

5. **Register routes** in `crates/keymanager-api/src/server.rs`:

```rust
.route("/eth/v1/validator/:pubkey/feerecipient", get(get_fee_recipient).post(set_fee_recipient).delete(delete_fee_recipient))
.route("/eth/v1/validator/:pubkey/gas_limit", get(get_gas_limit).post(set_gas_limit).delete(delete_gas_limit))
.route("/eth/v1/validator/:pubkey/graffiti", get(get_graffiti).post(set_graffiti).delete(delete_graffiti))
.route("/eth/v1/validator/:pubkey/voluntary_exit", post(submit_voluntary_exit))
```

### Phase 3: Config Persistence

6. **Persist changes to TOML** — POST/DELETE operations should update both in-memory state and the TOML config file so changes survive restarts. The existing `reload_config()` provides the pattern; add a corresponding `save_config()` that serializes current state back to disk.

### Phase 4: Wire Into Main Binary

7. **Inject new dependencies** into `KeymanagerServer` constructor in `bin/rvc/src/main.rs`:
   - `ValidatorConfigManager` adapter (wraps `ValidatorStore`)
   - `VoluntaryExitManager` adapter (wraps beacon client + signer + fork schedule)

### Phase 5: Testing

8. **Unit tests** for each handler (mock traits)
9. **Integration tests** for full HTTP round-trip
10. **Spec conformance** — validate request/response formats against [keymanager-APIs](https://github.com/ethereum/keymanager-APIs) OpenAPI spec

## Key Files

| File | Role |
|------|------|
| `crates/keymanager-api/src/server.rs` | Route registration |
| `crates/keymanager-api/src/handlers.rs` | Request handlers |
| `crates/keymanager-api/src/traits.rs` | Trait definitions |
| `crates/keymanager-api/src/error.rs` | Error types |
| `crates/rvc/src/keymanager_adapters.rs` | Trait implementations |
| `crates/validator-store/src/store.rs` | Domain logic (already exists) |
| `crates/validator-store/src/config.rs` | Config structs (already exists) |
| `bin/rvc/src/main.rs` | Server wiring |
| `bin/rvc/src/commands/voluntary_exit.rs` | Exit logic to port |

## Risks and Considerations

- **Config persistence race conditions** — concurrent POST requests could clobber each other when writing TOML. Use a write lock or serialize writes through a channel.
- **Voluntary exit is irreversible** — the API endpoint should require explicit confirmation or at minimum log the operation at WARN level. Consider requiring a specific header or parameter to prevent accidental exits.
- **Pubkey validation** — all endpoints must validate that the pubkey is known to the validator store. Return 404 for unknown validators, not 500.
- **DELETE semantics** — DELETE resets to default, not removal. The validator continues operating with the default fee recipient/gas limit/graffiti. This matches the spec.
