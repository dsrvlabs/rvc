# Tier 5: Future / Experimental

## Tier Overview
- **Goal:** Explore experimental capabilities — verifying signer, native relay integration, Gnosis Chain support, and SSE log streaming
- **Issue count:** 15 issues, 39 total points
- **Estimated duration:** ~11 days (with 2 parallel streams)
- **Entry criteria:** Tiers 2-4 merged; circuit breakers stable (for FR-16); BnManager refactor complete (for Gnosis timing)
- **Exit criteria:** All 4 experimental features functional behind feature gates where appropriate; verifying signer rejects invalid proofs; native relay fetches bids directly; Gnosis chain connects with 5s slots; SSE logs stream in real-time

## Tier Summary

| Issue | Title | Points | Stream | Blocked by | New Files | Shared File Edits |
|-------|-------|--------|--------|------------|-----------|-------------------|
| T5.1 | Verifying signer: Merkle proof types | 2 | A | — | `crates/signer/src/verification.rs` | — |
| T5.2 | Verifying signer: proof generation in VC | 3 | A | T5.1 | — | `crates/block-service/src/service.rs` |
| T5.3 | Verifying signer: proof verification in signer | 3 | A | T5.1 | — | `crates/signer/src/lib.rs` |
| T5.4 | Verifying signer: config + feature gate | 1 | A | T5.1 | — | `crates/signer/Cargo.toml`, `crates/rvc/src/config/types.rs` |
| T5.5 | Native relay: relay client crate scaffold | 2 | B | — | `crates/relay-client/` (new crate) | `Cargo.toml` (workspace) |
| T5.6 | Native relay: registration + header endpoints | 3 | B | T5.5 | — | `crates/relay-client/src/` |
| T5.7 | Native relay: blinded block + bid selection | 3 | B | T5.6 | — | `crates/relay-client/src/` |
| T5.8 | Native relay: integration into BlockService | 3 | B | T5.7, T2.2 (circuit breaker) | — | `crates/block-service/src/service.rs`, `crates/builder/src/service.rs` |
| T5.9 | Native relay: CLI + config + mutual exclusivity | 1 | B | T5.5 | — | `crates/rvc/src/config/types.rs` |
| T5.10 | Gnosis Chain: network enum + constants | 2 | A | — | — | `crates/rvc/src/config/network.rs`, `bin/rvc-keygen/src/network.rs` |
| T5.11 | Gnosis Chain: slot time parameterization audit | 3 | A | T5.10 | — | Multiple files (timing, coordinator, bn-manager, builder) |
| T5.12 | SSE logs: tracing broadcast layer | 2 | B | — | `crates/telemetry/src/sse_layer.rs` | `crates/telemetry/src/lib.rs` |
| T5.13 | SSE logs: Axum endpoint + connection management | 2 | B | T5.12 | — | `crates/keymanager-api/src/server.rs`, `handlers.rs` |
| T5.14 | SSE logs: CLI flags + config | 1 | A | T5.12 | — | `crates/rvc/src/config/types.rs` |
| T5.15 | Tier 5 integration tests | 8 | both | T5.4, T5.8, T5.11, T5.13 | `tests/tier5_experimental.rs` | — |

## Tier Parallel Plan

| Day | Stream A | Stream B |
|-----|----------|----------|
| 1 | T5.1 Merkle proof types (2pts) | T5.5 Relay client scaffold (2pts) |
| 2 | T5.10 Gnosis network enum (2pts) | T5.12 SSE tracing layer (2pts) |
| 3 | T5.2 Proof generation (3pts) | T5.6 Relay registration + header (3pts) |
| 4 | T5.2 cont. | T5.6 cont. |
| 5 | T5.3 Proof verification (3pts) | T5.7 Relay blinded block + bids (3pts) |
| 6 | T5.3 cont. | T5.7 cont. |
| 7 | T5.11 Slot time audit (3pts) | T5.8 Relay BlockService integration (3pts) |
| 8 | T5.11 cont. + T5.4 Verifying config (1pt) | T5.8 cont. + T5.9 Relay CLI (1pt) |
| 9 | T5.14 SSE CLI (1pt) | T5.13 SSE Axum endpoint (2pts) |
| 10-11 | T5.15 Integration tests (8pts) | T5.15 Integration tests (8pts) |

---

## Issues

### Issue T5.1: Verifying signer — Merkle proof types

**Feature:** FR-15 Verifying Web3Signer
**Story Points:** 2
**Priority:** P2
**Depends On:** None
**Blocks:** T5.2, T5.3, T5.4
**Files Modified:**
- `crates/signer/src/verification.rs` — new file: `BlockProof` struct, `ProvenProperty` enum

**Description:**
Define types for Merkle proof verification of block properties. This includes the proof structure, verifiable property paths, and the verification function.

**Implementation Notes:**
- `ProvenProperty` paths: `.execution_payload.fee_recipient`, `.graffiti`
- `BlockProof` struct: `index` (generalized index), `proof` (Vec<[u8; 32]>), `value` (optional leaf)
- Verification uses `is_valid_merkle_branch()` from consensus spec
- Generalized indices change per fork — need a fork-aware mapping table
- Feature-gated behind `verifying-signer` Cargo feature

**Acceptance Criteria:**
- [ ] `BlockProof` type defined with index, proof, and optional value
- [ ] `ProvenProperty` enum covers fee_recipient and graffiti
- [ ] Fork-aware generalized index mapping for Capella, Deneb, Electra
- [ ] `is_valid_merkle_branch()` verification function implemented

**Testing Requirements:**
- [ ] Unit test: valid proof verification passes
- [ ] Unit test: invalid proof verification fails
- [ ] Unit test: generalized indices correct per fork

---

### Issue T5.2: Verifying signer — proof generation in validator client

**Feature:** FR-15 Verifying Web3Signer
**Story Points:** 3
**Priority:** P2
**Depends On:** T5.1
**Blocks:** T5.15
**Files Modified:**
- `crates/block-service/src/service.rs` — generate proofs when signing blocks for verifying signers
- `crates/eth-types/` — SSZ tree hash helpers for Merkle proof generation

**Description:**
When the verifying signer feature is enabled, generate Merkle proofs for configured block properties before sending the block to the signer. The proofs are generated against the `BeaconBlockBody` root.

**Implementation Notes:**
- Use `tree_hash` crate (already a dependency) for SSZ tree hash and proof generation
- Compute generalized index for the property path at the current fork
- Generate inclusion proof against `BeaconBlockBody` root
- Attach proofs to the signing request
- Only generate proofs when the signer is configured as verifying (check signer config)

**Acceptance Criteria:**
- [ ] Proofs generated for configured properties
- [ ] Proofs valid against BeaconBlockBody root
- [ ] Fork-aware index computation
- [ ] No proof generation when feature disabled

**Testing Requirements:**
- [ ] Unit test: proof generation for fee_recipient
- [ ] Unit test: proof generation for graffiti
- [ ] Unit test: proof valid against body root

---

### Issue T5.3: Verifying signer — proof verification in signer service

**Feature:** FR-15 Verifying Web3Signer
**Story Points:** 3
**Priority:** P2
**Depends On:** T5.1
**Blocks:** T5.15
**Files Modified:**
- `crates/signer/src/lib.rs` — add `sign_block_with_verification()` method to signer trait

**Description:**
Add verification logic to the signer service. When proofs are provided, verify them before signing. If verification fails, reject the signing request with a descriptive error.

**Implementation Notes:**
- Add `sign_block_with_verification()` to `ValidatorSigner` trait with default fallback to `sign_block()`
- For each proof: verify Merkle branch against block body root
- Compare verified values against expected values from signer config
- If fee_recipient doesn't match expected → reject with ERROR
- The gRPC signer protocol needs new optional fields for verification data
- Feature-gated: without `verifying-signer` feature, default impl skips verification

**Acceptance Criteria:**
- [ ] Valid proofs + matching values → signing proceeds
- [ ] Invalid proof → signing rejected with ERROR
- [ ] Mismatched fee_recipient → signing rejected
- [ ] Without feature gate → standard signing (no verification)

**Testing Requirements:**
- [ ] Unit test: valid proof accepted
- [ ] Unit test: invalid proof rejected
- [ ] Unit test: mismatched value rejected
- [ ] Unit test: feature gate disables verification

---

### Issue T5.4: Verifying signer — config and feature gate

**Feature:** FR-15 Verifying Web3Signer
**Story Points:** 1
**Priority:** P2
**Depends On:** T5.1
**Blocks:** T5.15
**Files Modified:**
- `crates/signer/Cargo.toml` — add `verifying-signer` feature flag
- `crates/rvc/src/config/types.rs` — verifying signer config fields

**Description:**
Add the Cargo feature flag and configuration for the verifying signer.

**Implementation Notes:**
- `verifying-signer` feature in `crates/signer/Cargo.toml`
- Config: `verifying_signer = true`, `proven_block_properties = [".execution_payload.fee_recipient", ".graffiti"]`
- Feature disabled by default — not included in default build
- Remote keystore file format v3 support for verifying-web3signer type

**Acceptance Criteria:**
- [ ] Feature flag off by default
- [ ] Config fields parsed when feature enabled
- [ ] Default build unaffected

**Testing Requirements:**
- [ ] Config parsing with feature on/off

---

### Issue T5.5: Native relay — relay client crate scaffold

**Feature:** FR-16 Native Relay Integration
**Story Points:** 2
**Priority:** P2
**Depends On:** None
**Blocks:** T5.6, T5.7, T5.9
**Files Modified:**
- `crates/relay-client/` — new crate: `Cargo.toml`, `src/lib.rs`, `src/types.rs`
- `Cargo.toml` (workspace) — add relay-client to workspace members

**Description:**
Create the new `relay-client` crate with builder API types and HTTP client scaffold. This crate implements direct communication with MEV relays (replacing mev-boost sidecar).

**Implementation Notes:**
- Dependencies: `reqwest`, `serde`, `serde_json`, `blst` (BLS verification), `eth-types`
- Types: `SignedBuilderBid`, `ValidatorRegistrationV1`, `ExecutionPayloadHeader`, `BlobsBundle`
- `RelayClient` struct with HTTP client, relay URL, relay public key
- Fork-versioned response types (Capella, Deneb, Electra, Fulu)
- Relay URL format: `https://<relay_pubkey>@relay.example.com/`

**Acceptance Criteria:**
- [ ] New crate compiles and is in workspace
- [ ] Builder API types defined
- [ ] Fork-versioned response enum
- [ ] Relay URL parsing with embedded pubkey

**Testing Requirements:**
- [ ] Type serialization/deserialization tests
- [ ] URL parsing test

---

### Issue T5.6: Native relay — registration and header endpoints

**Feature:** FR-16 Native Relay Integration
**Story Points:** 3
**Priority:** P2
**Depends On:** T5.5
**Blocks:** T5.7
**Files Modified:**
- `crates/relay-client/src/client.rs` — implement registration and bid endpoints

**Description:**
Implement the relay client methods for validator registration and bid (header) fetching.

**Implementation Notes:**
- `POST /eth/v1/builder/validators` — batch registration with BLS-signed messages
- `GET /eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}` — bid request
- `GET /eth/v1/builder/status` — relay health check
- Multi-relay: query all configured relays in parallel for bids, select highest value
- BLS verification: verify bid signatures against relay public key
- Timeouts: registration 10s, bid fetching 5s (matching Vouch defaults)

**Acceptance Criteria:**
- [ ] Validator registration submitted to relay
- [ ] Bid fetched with correct parameters
- [ ] BLS signature on bid verified
- [ ] Multi-relay parallel queries
- [ ] Relay health check implemented

**Testing Requirements:**
- [ ] Unit test: registration payload correct
- [ ] Unit test: bid deserialization for each fork version
- [ ] Unit test: BLS verification of bid signature

---

### Issue T5.7: Native relay — blinded block submission and bid selection

**Feature:** FR-16 Native Relay Integration
**Story Points:** 3
**Priority:** P2
**Depends On:** T5.6
**Blocks:** T5.8
**Files Modified:**
- `crates/relay-client/src/client.rs` — implement blinded block submission
- `crates/relay-client/src/selection.rs` — bid comparison and selection logic

**Description:**
Implement blinded block submission to relays and the bid selection logic. After selecting the best bid, construct a blinded block, sign it, submit to the winning relay, and receive the full execution payload.

**Implementation Notes:**
- `POST /eth/v1/builder/blinded_blocks` (v1) and v2 — submit signed blinded block
- Response: full `ExecutionPayload` + `BlobsBundle` (Deneb+)
- Bid selection: highest `value` in wei
- `Eth-Consensus-Version` header required for v2 endpoints
- Handle relay failure after blinding commitment (critical: must fall back to local block, but ONLY if no signature was committed)

**Acceptance Criteria:**
- [ ] Blinded block submitted to relay
- [ ] Full payload received and deserialized
- [ ] Highest-value bid selected from multiple relays
- [ ] Fork version header sent correctly
- [ ] Relay failure handled gracefully

**Testing Requirements:**
- [ ] Unit test: bid comparison selects highest value
- [ ] Unit test: blinded block submission and response parsing
- [ ] Unit test: relay failure handling

---

### Issue T5.8: Native relay — integration into BlockService

**Feature:** FR-16 Native Relay Integration
**Story Points:** 3
**Priority:** P2
**Depends On:** T5.7, T2.2 (circuit breaker integration)
**Blocks:** T5.15
**Files Modified:**
- `crates/block-service/src/service.rs` — alternative block production path using relay client
- `crates/builder/src/service.rs` — alternative registration path using relay client

**Description:**
Wire the relay client into the existing block production and registration paths. When `--relay-endpoints` is configured, use the relay client instead of mev-boost via the BN.

**Implementation Notes:**
- `BlockService` gets `Option<Arc<RelayClient>>` field
- If relay client present: fetch header from relay → construct blinded block → sign → submit to relay → receive payload
- Circuit breaker must respect relay path (if tripped, skip relay)
- `BuilderService`: registration goes directly to relays instead of via BN
- Mutual exclusivity: `--relay-endpoints` and `--builder-endpoint` cannot both be set

**Acceptance Criteria:**
- [ ] Block proposals use relay bids when relay-endpoints configured
- [ ] Registration goes directly to relays
- [ ] Circuit breaker respected on relay path
- [ ] Local fallback when relay fails
- [ ] Mutual exclusivity with builder-endpoint enforced

**Testing Requirements:**
- [ ] Unit test: relay path used when configured
- [ ] Unit test: circuit breaker on relay path
- [ ] Unit test: fallback to local on relay failure

---

### Issue T5.9: Native relay — CLI flags and config

**Feature:** FR-16 Native Relay Integration
**Story Points:** 1
**Priority:** P2
**Depends On:** T5.5
**Blocks:** T5.15
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `relay_endpoints`, `relay_secret_key`

**Description:**
Add CLI flags for native relay configuration and enforce mutual exclusivity with mev-boost.

**Implementation Notes:**
- `--relay-endpoints https://<pubkey>@relay1.example.com,https://<pubkey>@relay2.example.com`
- `--relay-secret-key <hex>` for signing relay registrations
- Both `--relay-endpoints` and `--builder-endpoint` → startup error
- TOML: `relay_endpoints = [...]`

**Acceptance Criteria:**
- [ ] CLI parses relay endpoints with embedded pubkeys
- [ ] Mutual exclusivity with builder-endpoint
- [ ] Config validation at startup

**Testing Requirements:**
- [ ] Config parsing test
- [ ] Mutual exclusivity validation test

---

### Issue T5.10: Gnosis Chain — network enum and constants

**Feature:** FR-17 Gnosis Chain Support
**Story Points:** 2
**Priority:** P2
**Depends On:** None
**Blocks:** T5.11
**Files Modified:**
- `crates/rvc/src/config/network.rs` — add `Gnosis` and `Chiado` variants
- `bin/rvc-keygen/src/network.rs` — add Gnosis keygen support

**Description:**
Add Gnosis mainnet and Chiado testnet to the Network enum with correct genesis constants, fork schedule, and network-specific parameters.

**Implementation Notes:**
- `seconds_per_slot()` returns 5 for Gnosis/Chiado (not 12)
- Fork versions: `0x0N000064` (mainnet), `0x0N00006f` (Chiado)
- Genesis time, genesis validators root for both networks
- Deposit contract addresses
- `SLOTS_PER_EPOCH` may be 16 (check latest Gnosis config)
- Update existing tests that assert Gnosis/Chiado are rejected

**Acceptance Criteria:**
- [ ] `Network::Gnosis` and `Network::Chiado` variants added
- [ ] `seconds_per_slot()` returns 5 for Gnosis
- [ ] Fork schedule correct for both networks
- [ ] Genesis constants correct
- [ ] rvc-keygen generates correct deposit data for Gnosis

**Testing Requirements:**
- [ ] Unit test: network constants
- [ ] Unit test: seconds_per_slot returns 5
- [ ] Update existing tests that assert rejection

---

### Issue T5.11: Gnosis Chain — slot time parameterization audit

**Feature:** FR-17 Gnosis Chain Support
**Story Points:** 3
**Priority:** P2
**Depends On:** T5.10
**Blocks:** T5.15
**Files Modified:**
- `crates/timing/` — verify `SlotClock` uses config, not hardcoded 12s
- `crates/rvc/src/orchestrator/coordinator.rs` — attestation deadline (slot/3), aggregation deadline (2*slot/3)
- `crates/bn-manager/src/manager.rs` — `DEFAULT_SYNC_CHECK_INTERVAL` (currently 384s = 32*12)
- `crates/builder/src/service.rs` — `jitter_seconds()` range
- `crates/eth-types/` — `SECONDS_PER_SLOT` constant usage

**Description:**
Audit and fix all hardcoded slot/epoch time assumptions across the codebase. Gnosis uses 5-second slots instead of 12. All timing must come from the network configuration.

**Implementation Notes:**
- HIGH RISK: slot-time assumptions spread across entire codebase
- `coordinator.rs:349-356` — attestation deadline `slot_duration / 3`
- `coordinator.rs:399-401` — aggregation offset `2 * slot_duration / 3`
- `bn-manager:39` — `DEFAULT_SYNC_CHECK_INTERVAL` hardcoded 384s → parameterize as `SLOTS_PER_EPOCH * seconds_per_slot`
- `builder:216-219` — `jitter_seconds()` range 0..30 → may need scaling for 5s slots
- Grep for `SECONDS_PER_SLOT`, `SLOTS_PER_EPOCH`, hardcoded `12`, hardcoded `384`, hardcoded `32`
- Replace all hardcoded values with config-derived values

**Acceptance Criteria:**
- [ ] No hardcoded 12-second slot assumptions remain
- [ ] Attestation timing correct for 5-second slots (deadline at 5/3 = ~1.67s)
- [ ] Sync check interval computed from network config
- [ ] Builder jitter scaled appropriately
- [ ] All existing tests still pass
- [ ] Gnosis testnet smoke test passes

**Testing Requirements:**
- [ ] Parameterized tests with both 12s and 5s slot times
- [ ] Regression: existing Ethereum tests still pass
- [ ] Gnosis timing correctness tests

---

### Issue T5.12: SSE logs — tracing broadcast layer

**Feature:** FR-18 SSE Log Streaming API
**Story Points:** 2
**Priority:** P2
**Depends On:** None
**Blocks:** T5.13, T5.14
**Files Modified:**
- `crates/telemetry/src/sse_layer.rs` — new file: custom `tracing::Layer` that broadcasts log events
- `crates/telemetry/src/lib.rs` — export SSE layer

**Description:**
Implement a custom `tracing::Layer` that captures log events and sends them to a `tokio::sync::broadcast` channel for SSE streaming.

**Implementation Notes:**
- Use `tokio::sync::broadcast::Sender<String>` — each event serialized to JSON
- Channel capacity: 2048 (following Lighthouse's experience with Issue #1464)
- `FieldVisitor` extracts message, level, target, timestamp, and contextual fields
- Filter: INFO and above (no DEBUG/TRACE streaming)
- JSON format: `{"timestamp": "...", "level": "...", "target": "...", "message": "...", "fields": {...}}`
- The layer never blocks — broadcast channel drops old messages for slow consumers
- Memory overhead: ~400 KB (2048 × ~200 bytes)

**Acceptance Criteria:**
- [ ] Layer captures INFO+ log events
- [ ] Events serialized to valid JSON
- [ ] Broadcast channel never blocks the logging pipeline
- [ ] 2048 capacity handles burst logging

**Testing Requirements:**
- [ ] Unit test: log event captured and serialized
- [ ] Unit test: channel overflow doesn't block
- [ ] Unit test: DEBUG events filtered out

---

### Issue T5.13: SSE logs — Axum endpoint and connection management

**Feature:** FR-18 SSE Log Streaming API
**Story Points:** 2
**Priority:** P2
**Depends On:** T5.12
**Blocks:** T5.15
**Files Modified:**
- `crates/keymanager-api/src/server.rs` — add `GET /rvc/v1/logs` route
- `crates/keymanager-api/src/handlers.rs` — SSE handler

**Description:**
Add the SSE endpoint to the Keymanager API server. Each client gets its own broadcast receiver. Maximum concurrent connections enforced.

**Implementation Notes:**
- Use `axum::response::sse::Sse<S>` for SSE streaming
- Each connection: `log_sender.subscribe()` creates new receiver
- `BroadcastStream::new(receiver)` for stream conversion
- Lagged receivers: filter out `RecvError::Lagged` (skip gaps)
- Max concurrent: 10 (default), enforced via `AtomicU32` counter
- 11th connection → 429 Too Many Requests
- Query params: `level=info|warn|error`, `target=<module_path>`
- Bearer token auth required

**Acceptance Criteria:**
- [ ] SSE endpoint streams live logs
- [ ] Events are valid JSON
- [ ] `level=error` filters to ERROR+
- [ ] 11th concurrent connection rejected with 429
- [ ] Slow clients dropped without affecting others
- [ ] Bearer token required

**Testing Requirements:**
- [ ] Integration test: SSE stream receives events
- [ ] Test: max connections enforced
- [ ] Test: level filtering
- [ ] Test: auth required

---

### Issue T5.14: SSE logs — CLI flags and config

**Feature:** FR-18 SSE Log Streaming API
**Story Points:** 1
**Priority:** P2
**Depends On:** T5.12
**Blocks:** T5.15
**Files Modified:**
- `crates/rvc/src/config/types.rs` — add `enable_sse_logging`, `sse_max_connections`

**Description:**
Add CLI flags and config for SSE log streaming.

**Implementation Notes:**
- `--enable-sse-logging` or `--gui` flag (matching Lighthouse)
- `--sse-max-connections <N>` (default: 10)
- Without the flag, the SSE endpoint is not available
- When enabled, broadcast layer is added to subscriber stack

**Acceptance Criteria:**
- [ ] Flag enables SSE endpoint
- [ ] Without flag, endpoint not available
- [ ] Max connections configurable

**Testing Requirements:**
- [ ] Config parsing test

---

### Issue T5.15: Tier 5 integration tests

**Feature:** All Tier 5 features (FR-15 through FR-18)
**Story Points:** 8
**Priority:** P2
**Depends On:** T5.4, T5.8, T5.11, T5.13
**Blocks:** None
**Files Modified:**
- `tests/tier5_experimental.rs` — new integration test file

**Description:**
End-to-end integration tests for all four Tier 5 experimental features.

**Implementation Notes:**
- Verifying signer: sign block with valid/invalid proofs → verify accept/reject
- Native relay: mock relay server → verify bid selection and block submission
- Gnosis Chain: configure 5s slots → verify timing correctness
- SSE logs: connect to endpoint → verify log events stream
- Feature-gated tests: verifying signer tests only run with `verifying-signer` feature
- Risk: Gnosis timing tests may require a dedicated test BN or careful mocking

**Acceptance Criteria:**
- [ ] Verifying signer accepts valid proofs, rejects invalid
- [ ] Native relay bid selection picks highest value
- [ ] Gnosis timing uses 5-second slots
- [ ] SSE endpoint streams logs to client
- [ ] Feature gates respected in test execution

**Testing Requirements:**
- [ ] Full integration test suite for all Tier 5 features
- [ ] Feature-gated test execution
- [ ] Mock relay server for native relay tests
