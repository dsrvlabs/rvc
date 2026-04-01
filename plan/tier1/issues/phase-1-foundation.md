# Phase 1: Foundation — Traits, Error Types, Persistence, and Testnet Support

## Phase Overview

- **Goal:** Establish the trait interfaces, error handling, persistence layer, and testnet support that all subsequent work depends on.
- **Issue count:** 5 issues, 9 total points
- **Estimated duration:** 3 days (with 2 parallel streams)
- **Entry criteria:** `cargo check && cargo test` passes on current `develop` branch. PRD, architecture, and research documents reviewed.
- **Exit criteria:**
  - `ValidatorConfigManager` and `VoluntaryExitManager` traits compile with `Send + Sync` bounds
  - `ApiError::NotFound` returns HTTP 404 with `{ "message": "..." }` body
  - `save_config()` round-trip test passes (load → mutate → save → reload → verify)
  - `"holesky".parse::<Network>()` and `"sepolia".parse::<Network>()` succeed with correct genesis constants
  - `from_name("holesky")` and `from_name("sepolia")` return correct `KeygenNetwork` structs
  - All existing tests pass (`cargo test`)

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | Blocks | New Files | Modified Files |
|-------|-------|--------|--------|------------|--------|-----------|----------------|
| 1.1 | Define ValidatorConfigManager + VoluntaryExitManager traits | 2 | A | — | 2.1, 2.2, 3.1, 3.2 | — | `traits.rs`, `Cargo.toml` |
| 1.2 | Add ApiError::NotFound variant | 1 | A | — | 2.1, 2.3, 2.4, 2.5, 3.3 | — | `error.rs` |
| 1.3 | Implement save_config() and has_validator() | 3 | A | — | 2.2, 4.4 | — | `store.rs`, `Cargo.toml` |
| 1.4 | Add Holesky and Sepolia to Network enum | 2 | B | — | 4.5, 4.7 | — | `network.rs` |
| 1.5 | Add Holesky and Sepolia to rvc-keygen | 1 | B | — | 4.5 | — | `network.rs` (keygen) |

## Phase Parallel Plan

| Day | Stream A (Dev A) | Stream B (Dev B) |
|-----|-----------------|-----------------|
| 1 | 1.1 Traits (2pts) | 1.4 Networks (2pts) + 1.5 Keygen (1pt) |
| 2 | 1.2 NotFound (1pt) | 1.3 save_config (3pts) |
| 3 | (Phase 2 pull-ahead: 2.1) | 1.3 cont. |

---

## Issues

### Issue 1.1: Define ValidatorConfigManager and VoluntaryExitManager traits

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** None
- **Blocks:** 2.1, 2.2, 3.1, 3.2
- **Scope:** 1 day

**Description:**

Add two new traits to `crates/keymanager-api/src/traits.rs` that define the interface for per-validator config management and voluntary exit signing. These traits follow the existing pattern (e.g., `KeystoreManager`, `RemoteKeyManager`) — they use `Send + Sync` bounds and return `Result<T, ApiError>`.

`ValidatorConfigManager` has 9 synchronous methods (get/set/delete for fee_recipient, gas_limit, graffiti). `VoluntaryExitManager` has 1 async method (`sign_voluntary_exit`).

**Implementation Notes:**

- Files modified: `crates/keymanager-api/src/traits.rs`, `crates/keymanager-api/Cargo.toml`
- Add `async-trait.workspace = true` and `eth-types.workspace = true` to `crates/keymanager-api/Cargo.toml` — needed for `#[async_trait]` on `VoluntaryExitManager` and `SignedVoluntaryExit` return type
- `ValidatorConfigManager` is **not** async — all config operations are in-memory behind `parking_lot::RwLock` (synchronous). This matches existing traits like `KeystoreManager`.
- `VoluntaryExitManager` **is** async — it makes beacon node network calls. Use `#[async_trait]` for consistency with the signer traits.
- Method signatures per architecture doc section 1:
  - `get_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<[u8; 20], ApiError>`
  - `set_fee_recipient(&self, pubkey: &[u8; 48], address: [u8; 20]) -> Result<(), ApiError>`
  - `delete_fee_recipient(&self, pubkey: &[u8; 48]) -> Result<(), ApiError>`
  - Same pattern for `gas_limit` (returns `u64`) and `graffiti` (returns `String`)
  - `sign_voluntary_exit(&self, pubkey: &[u8; 48], epoch: Option<u64>) -> Result<SignedVoluntaryExit, ApiError>`
- Reuse existing `Pubkey` type alias (`[u8; 48]`) already in `traits.rs`
- Files NOT to modify: anything in `crates/rvc/` or `bin/` (owned by other issues)

**Acceptance Criteria:**

- [ ] `ValidatorConfigManager` trait defined with 9 methods, `Send + Sync` bounds
- [ ] `VoluntaryExitManager` trait defined with `sign_voluntary_exit`, `Send + Sync` bounds, `#[async_trait]`
- [ ] `async-trait` and `eth-types` added to `crates/keymanager-api/Cargo.toml`
- [ ] `cargo check -p keymanager-api` compiles without errors
- [ ] All existing tests pass (`cargo test`)

**Testing Requirements:**

- [ ] Compilation test — the traits compile and are importable
- [ ] No unit tests needed for trait definitions alone (implementations are tested in 2.2 and 3.2)

---

### Issue 1.2: Add ApiError::NotFound variant

- **Points:** 1
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** None
- **Blocks:** 2.1, 2.3, 2.4, 2.5, 3.3
- **Scope:** half day

**Description:**

Extend the `ApiError` enum in `crates/keymanager-api/src/error.rs` with a `NotFound(String)` variant that maps to HTTP 404. Currently the enum only has `BadRequest` and `Internal`. All new config and exit handlers need 404 for unknown validator pubkeys.

**Implementation Notes:**

- File modified: `crates/keymanager-api/src/error.rs`
- Add `NotFound(String)` variant between `BadRequest` and `Internal` (matching the architecture doc)
- Add `#[error("Not found: {0}")]` derive
- Update `IntoResponse` impl to map `NotFound` → `StatusCode::NOT_FOUND`
- Response format: `{ "message": "..." }` — consistent with existing variants and the Keymanager API `ErrorResponse` schema
- Files NOT to modify: `handlers.rs`, `server.rs` (those are later issues)

**Acceptance Criteria:**

- [ ] `ApiError::NotFound("msg".into())` compiles
- [ ] `ApiError::NotFound` produces HTTP 404 status code
- [ ] Response body is `{ "message": "Not found: <msg>" }` format
- [ ] All existing tests pass (`cargo test`)

**Testing Requirements:**

- [ ] Unit test: construct `ApiError::NotFound`, convert to response, assert status 404 and JSON body matches

---

### Issue 1.3: Implement save_config() and has_validator() on ValidatorStore

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Stream:** A
- **Blocked by:** None
- **Blocks:** 2.2, 4.4
- **Scope:** 1.5 days

**Description:**

Add two methods to `ValidatorStore` in `crates/validator-store/src/store.rs`:

1. `has_validator(&self, pubkey: &[u8; 48]) -> bool` — checks if a validator exists in the store (used by adapters for 404 checks).
2. `save_config(&self) -> Result<(), ValidatorStoreError>` — serializes current in-memory state to TOML and atomically writes to the config file using `tempfile::NamedTempFile` + `sync_all()` + `persist()`.

Also add a private `serialize_to_toml()` helper that produces TOML matching the format expected by `load_from_config()`.

**Implementation Notes:**

- Files modified: `crates/validator-store/src/store.rs`, `crates/validator-store/Cargo.toml`
- Move `tempfile` from `[dev-dependencies]` to `[dependencies]` in `crates/validator-store/Cargo.toml` (it's already a workspace dep)
- `has_validator()` is a simple `self.validators.read().contains_key(pubkey)` — trivial
- `save_config()` pattern per architecture doc section 4 and config-persistence research:
  1. Get `config_path` or return error
  2. Acquire read locks on `validators` and `defaults`, call `serialize_to_toml()`
  3. Create `NamedTempFile::new_in(parent_dir)` — same directory for atomic rename
  4. Write TOML bytes, `sync_all()`, `persist(path)`
- `serialize_to_toml()` must produce output compatible with the existing `TomlConfig` deserialization structs (`TomlDefaults`, `TomlValidator`). Key format requirements:
  - `[defaults]` section with `fee_recipient` (hex), `gas_limit` (integer), `graffiti` (string)
  - `[[validators]]` array entries with `pubkey` (hex), optional overrides
  - Pubkeys and fee recipients must be `0x`-prefixed hex strings
  - `gas_limit` is a TOML integer (not string — TOML format differs from API JSON format)
- **Critical:** Write the round-trip test first (TDD RED phase). Load a config, mutate it, save, reload, verify values match. This catches serialization mismatches early.
- Concurrency: `save_config()` acquires read locks only during serialization, releases before I/O. This is safe — see architecture doc section 4 for race analysis.
- Files NOT to modify: `crates/validator-store/src/config.rs`, `crates/validator-store/src/error.rs`

**Acceptance Criteria:**

- [ ] `has_validator()` returns `true` for known pubkeys, `false` for unknown
- [ ] `save_config()` writes valid TOML to the config path
- [ ] Round-trip test passes: `load_from_config()` → `update_config()` → `save_config()` → `load_from_config()` → values match
- [ ] Atomic write: temp file in same directory, `sync_all()` before rename
- [ ] `save_config()` returns error when `config_path` is `None`
- [ ] Concurrent `save_config()` calls don't corrupt the file
- [ ] All existing tests pass (`cargo test`)

**Testing Requirements:**

- [ ] Unit test: `test_save_config_round_trip` — load config, update fee_recipient, save, reload, verify
- [ ] Unit test: `test_save_config_no_path_returns_error` — store without config_path returns error
- [ ] Unit test: `test_has_validator` — true for known, false for unknown pubkey
- [ ] Unit test: `test_save_config_preserves_all_fields` — verify all fields (gas_limit, graffiti, builder_proposals, etc.) survive round-trip

---

### Issue 1.4: Add Holesky and Sepolia to Network enum

- **Points:** 2
- **Type:** feature
- **Priority:** P0
- **Stream:** B
- **Blocked by:** None
- **Blocks:** 4.5, 4.7
- **Scope:** 1 day

**Description:**

Add `Holesky` and `Sepolia` variants to the `Network` enum in `crates/rvc/src/config/network.rs` with verified genesis constants. Update `FromStr`, `Display`, serde, `genesis_time()`, and `genesis_validators_root()` implementations. Update existing tests that assert Holesky/Sepolia are rejected.

**Implementation Notes:**

- File modified: `crates/rvc/src/config/network.rs`
- Add `Holesky` and `Sepolia` to the enum (after `Hoodi`, before `Custom`)
- Update serde `rename_all = "lowercase"` — the derive handles this automatically
- Genesis constants (verified in `research/testnet-constants.md`):
  - Holesky: `genesis_time = 1695902400`, `genesis_validators_root = "0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"`
  - Sepolia: `genesis_time = 1655733600`, `genesis_validators_root = "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"`
- Update `FromStr` to accept `"holesky"` and `"sepolia"` (case-insensitive)
- Update `Display` to output `"holesky"` and `"sepolia"`
- **Test updates required** (existing tests will fail without these changes):
  - `test_network_from_str_deprecated_networks_rejected` (line 99–103): Remove `sepolia` and `holesky` assertions, keep only `goerli`
  - `test_network_serde_deprecated_networks_rejected` (line 133–137): Remove `sepolia` and `holesky` assertions, keep only `goerli`
  - Add new test: `test_network_from_str_testnets_accepted` — assert `"holesky"` and `"sepolia"` parse
  - Add new test: `test_network_genesis_constants_holesky` — verify genesis_time and genesis_validators_root
  - Add new test: `test_network_genesis_constants_sepolia` — same
  - Add new test: `test_network_serde_testnets` — round-trip `"holesky"` and `"sepolia"` through JSON
- Files NOT to modify: anything in `crates/keymanager-api/` or `bin/` (owned by Stream A / Issue 1.5)

**Acceptance Criteria:**

- [ ] `"holesky".parse::<Network>()` returns `Ok(Network::Holesky)`
- [ ] `"sepolia".parse::<Network>()` returns `Ok(Network::Sepolia)`
- [ ] `Network::Holesky.genesis_time()` returns `Some(1695902400)`
- [ ] `Network::Sepolia.genesis_time()` returns `Some(1655733600)`
- [ ] `Network::Holesky.genesis_validators_root()` returns correct root
- [ ] `Network::Sepolia.genesis_validators_root()` returns correct root
- [ ] Serde round-trip: `"holesky"` serializes and deserializes correctly
- [ ] `"goerli"` still rejected (deprecated)
- [ ] All existing tests pass after test updates (`cargo test`)

**Testing Requirements:**

- [ ] Update `test_network_from_str_deprecated_networks_rejected` — only assert Goerli
- [ ] Update `test_network_serde_deprecated_networks_rejected` — only assert Goerli
- [ ] New test: `test_network_from_str_testnets_accepted`
- [ ] New test: `test_network_genesis_constants_holesky`
- [ ] New test: `test_network_genesis_constants_sepolia`
- [ ] New test: `test_network_serde_testnets`
- [ ] Update `test_network_genesis_time` to include Holesky and Sepolia values

---

### Issue 1.5: Add Holesky and Sepolia to rvc-keygen

- **Points:** 1
- **Type:** feature
- **Priority:** P0
- **Stream:** B
- **Blocked by:** None
- **Blocks:** 4.5
- **Scope:** half day

**Description:**

Add `HOLESKY` and `SEPOLIA` `KeygenNetwork` constants to `bin/rvc-keygen/src/network.rs` with correct genesis fork versions and Capella fork versions. Update `from_name()` to accept `"holesky"` and `"sepolia"`.

**Implementation Notes:**

- File modified: `bin/rvc-keygen/src/network.rs`
- Add two new constants following the `MAINNET` and `HOODI` pattern:
  - `HOLESKY`: `genesis_fork_version = [0x01, 0x01, 0x70, 0x00]`, `capella_fork_version = [0x04, 0x01, 0x70, 0x00]`
  - `SEPOLIA`: `genesis_fork_version = [0x90, 0x00, 0x00, 0x69]`, `capella_fork_version = [0x90, 0x00, 0x00, 0x72]`
- `genesis_validators_root` byte arrays from research/testnet-constants.md:
  - Holesky: `0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1`
  - Sepolia: `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078`
- Update `from_name()` match arms to include `"holesky" => Ok(&HOLESKY)` and `"sepolia" => Ok(&SEPOLIA)`
- Update the error message in `from_name()` to list all supported networks
- Files NOT to modify: `crates/rvc/src/config/network.rs` (owned by Issue 1.4)

**Acceptance Criteria:**

- [ ] `from_name("holesky")` returns `Ok(&HOLESKY)` with correct fork versions
- [ ] `from_name("sepolia")` returns `Ok(&SEPOLIA)` with correct fork versions
- [ ] Genesis validator roots match verified values
- [ ] `exit_fork_schedule()` works correctly for both new networks (caps at Capella)
- [ ] All existing tests pass (`cargo test`)

**Testing Requirements:**

- [ ] New test: `test_from_name_holesky` — verify name, fork versions, genesis root
- [ ] New test: `test_from_name_sepolia` — same
- [ ] New test: `test_holesky_genesis_root` — verify byte-level match against hex
- [ ] New test: `test_sepolia_genesis_root` — same
- [ ] New test: `test_exit_fork_schedule_holesky` — verify caps at Capella
- [ ] New test: `test_exit_fork_schedule_sepolia` — same
- [ ] Update `test_from_name_unknown` error message if it asserts specific text
