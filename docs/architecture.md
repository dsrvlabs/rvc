# Test Architecture: Audit Remediation

## Overview

This document defines the test architecture for resolving all 30 findings from the rs-vc test audit. The design extends existing codebase patterns — `CapturingSubmitter`, `Arc<Mutex<Vec<T>>>` capture, deterministic proof-finding — rather than introducing new abstractions. The architecture enables parallel implementation across five independent work streams while sharing a minimal set of new test infrastructure.

## Architecture Principles

- **Extend, don't replace** — All mock changes are additive. Existing tests continue to work without modification.
- **Capture-then-assert** — Follow the established `CapturingSubmitter` pattern: mocks capture full arguments during execution, tests assert on captured data after the fact.
- **Match existing mutex conventions** — Block-service uses `std::sync::Mutex` (sync traits). Sync-service uses `tokio::sync::Mutex` (async traits). Coordinator uses `parking_lot::Mutex`.
- **Deterministic by default** — Replace all probabilistic test inputs with deterministic proof-finding or known-value inputs.
- **No production code changes** — All modifications are in `#[cfg(test)]` modules, test files, or mock implementations.

---

## 1. Mock Infrastructure Refactoring

### 1.1 Capturing Pattern

The codebase has four capture patterns, ranked by fidelity:

| Pattern | Captures | Used In | Findings |
|---------|----------|---------|----------|
| **A: Full-object** | `Vec<T>` where T is the complete input | `CapturingSubmitter`, `MockBn` | Gold standard |
| **B: Tuple** | `Vec<(field1, field2)>` | Block-service `MockSigner` | #2-4 (partial) |
| **C: Count-only** | `AtomicUsize` | Sync-service mocks | #5-6 |
| **D: Closure** | `Arc<Mutex<Vec<T>>>` in closure | SSE tests | N/A |

**Decision:** Upgrade all mocks to Pattern A (full-object capture) using dedicated `CapturedCall` structs. Keep `AtomicUsize` counters alongside for backward compatibility — existing count-only assertions remain valid without rewriting.

### 1.2 Block-Service CapturedCall Structs

**File:** `crates/block-service/src/service.rs` (inside `#[cfg(test)]` module)

```rust
/// Captured arguments from produce_block_v3 calls (Finding #2)
#[derive(Debug, Clone)]
struct CapturedProduceCall {
    slot: Slot,
    randao_reveal: String,
    graffiti: Option<String>,
    builder_boost_factor: Option<u64>,
}

/// Captured arguments from publish_block / publish_blinded_block calls (Finding #3)
#[derive(Debug, Clone)]
struct CapturedPublishCall {
    consensus_version: String,
    slot: Slot,
    proposer_index: u64,
    // Store signature bytes rather than full SignedBeaconBlock (may not impl Clone)
    signature_bytes: Vec<u8>,
}

/// Captured arguments from sign_block calls (Finding #4)
#[derive(Debug, Clone)]
struct CapturedSignBlockCall {
    block_root: Root,
    slot: Slot,
    pubkey: PublicKey,
    fork_schedule: ForkSchedule,
    genesis_validators_root: Root,
}
```

**MockBeaconClient changes:**

```rust
struct MockBeaconClient {
    // EXISTING (keep for backward compat):
    produce_response: Option<ProduceBlockResponse>,
    fail_produce: bool,
    fail_publish: bool,
    publish_calls: Mutex<Vec<String>>,           // keep
    publish_blinded_calls: Mutex<Vec<String>>,   // keep
    publish_ssz_calls: Mutex<Vec<(Vec<u8>, String, bool)>>, // keep

    // NEW (Finding #2):
    produce_calls: Mutex<Vec<CapturedProduceCall>>,

    // NEW (Finding #3):
    publish_full_calls: Mutex<Vec<CapturedPublishCall>>,
    publish_blinded_full_calls: Mutex<Vec<CapturedPublishCall>>,
}
```

In `produce_block_v3`: push `CapturedProduceCall { slot, randao_reveal, graffiti, builder_boost_factor }` before returning.

In `publish_block`: extract `slot` and `proposer_index` from the `SignedBeaconBlock` parameter, push `CapturedPublishCall` alongside the existing `consensus_version` string push.

In `publish_blinded_block`: same pattern for `SignedBlindedBeaconBlock`.

**MockSigner changes:**

```rust
struct MockSigner {
    // EXISTING (keep):
    fail_randao: bool,
    fail_block: bool,
    randao_calls: Mutex<Vec<u64>>,

    // REPLACE block_calls: Mutex<Vec<(Root, Slot)>> with:
    block_calls: Mutex<Vec<CapturedSignBlockCall>>,
}
```

In `sign_block`: capture all five parameters instead of just `(block_root, slot)`.

### 1.3 Block-Service Assertion Helpers

```rust
impl MockBeaconClient {
    /// Assert the last produce_block_v3 call used the expected slot.
    fn assert_last_produce_slot(&self, expected: Slot) {
        let calls = self.produce_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no produce_block_v3 calls recorded");
        assert_eq!(calls.last().unwrap().slot, expected,
            "produce_block_v3 called with wrong slot");
    }

    /// Assert the last published block had the expected slot and proposer_index.
    fn assert_last_published_block(&self, expected_slot: Slot, expected_proposer: u64) {
        let calls = self.publish_full_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no publish_block calls recorded");
        let last = calls.last().unwrap();
        assert_eq!(last.slot, expected_slot);
        assert_eq!(last.proposer_index, expected_proposer);
    }
}

impl MockSigner {
    /// Assert the last sign_block call received the correct fork_schedule and genesis root.
    fn assert_last_sign_block_domain(&self, expected_fork: &ForkSchedule, expected_gvr: &Root) {
        let calls = self.block_calls.lock().unwrap();
        assert!(!calls.is_empty(), "no sign_block calls recorded");
        let last = calls.last().unwrap();
        assert_eq!(&last.fork_schedule, expected_fork,
            "sign_block called with wrong fork_schedule");
        assert_eq!(&last.genesis_validators_root, *expected_gvr,
            "sign_block called with wrong genesis_validators_root");
    }
}
```

### 1.4 Sync-Service CapturedCall Structs

**File:** `crates/sync-service/src/lib.rs` (inside `#[cfg(test)]` module)

```rust
/// Captured arguments from sign_sync_committee_message calls (Finding #6)
#[derive(Debug, Clone)]
struct CapturedSyncSignCall {
    beacon_block_root: Root,
    slot: Slot,
    pubkey: PublicKey,
    fork_schedule: ForkSchedule,
    genesis_validators_root: Root,
}

/// Captured arguments from sign_selection_proof calls (Finding #6)
#[derive(Debug, Clone)]
struct CapturedSelectionProofCall {
    slot: Slot,
    subcommittee_index: u64,
    pubkey: PublicKey,
}

/// Captured arguments from sign_contribution_and_proof calls (Finding #6)
#[derive(Debug, Clone)]
struct CapturedContributionSignCall {
    contribution_and_proof: ContributionAndProof,
    pubkey: PublicKey,
}

/// Captured submitted messages batch (Finding #5)
#[derive(Debug, Clone)]
struct CapturedSubmittedMessages {
    messages: Vec<SyncCommitteeMessage>,
}
```

**MockSigner changes:**

```rust
struct MockSigner {
    // EXISTING (keep for backward compat):
    sign_sync_result: tokio::sync::Mutex<Result<Signature, SyncServiceError>>,
    sign_selection_result: tokio::sync::Mutex<Result<Signature, SyncServiceError>>,
    sign_contribution_result: tokio::sync::Mutex<Result<Signature, SyncServiceError>>,
    sign_sync_call_count: AtomicUsize,           // keep
    sign_selection_call_count: AtomicUsize,       // keep
    sign_contribution_call_count: AtomicUsize,    // keep

    // NEW (Finding #6):
    sign_sync_calls: tokio::sync::Mutex<Vec<CapturedSyncSignCall>>,
    sign_selection_calls: tokio::sync::Mutex<Vec<CapturedSelectionProofCall>>,
    sign_contribution_calls: tokio::sync::Mutex<Vec<CapturedContributionSignCall>>,
}
```

**MockBeacon changes:**

```rust
struct MockBeacon {
    // EXISTING (keep):
    submit_messages_result: tokio::sync::Mutex<Result<(), SyncServiceError>>,
    get_contribution_result: tokio::sync::Mutex<Result<SyncCommitteeContribution, SyncServiceError>>,
    submit_proofs_result: tokio::sync::Mutex<Result<(), SyncServiceError>>,
    submit_messages_call_count: AtomicUsize,       // keep
    get_contribution_call_count: AtomicUsize,      // keep
    submit_proofs_call_count: AtomicUsize,         // keep

    // NEW (Finding #5):
    submitted_messages: tokio::sync::Mutex<Vec<Vec<SyncCommitteeMessage>>>,
    submitted_proofs: tokio::sync::Mutex<Vec<Vec<SignedContributionAndProof>>>,
}
```

In `submit_sync_committee_messages`: clone the messages slice into `submitted_messages` before returning.

In `submit_contribution_and_proofs`: clone the proofs slice into `submitted_proofs`.

### 1.5 Sync-Service Assertion Helpers

```rust
impl MockSigner {
    async fn assert_last_sync_sign_args(&self, expected_slot: Slot, expected_root: &Root) {
        let calls = self.sign_sync_calls.lock().await;
        assert!(!calls.is_empty(), "no sign_sync_committee_message calls");
        let last = calls.last().unwrap();
        assert_eq!(last.slot, expected_slot);
        assert_eq!(&last.beacon_block_root, expected_root);
    }
}

impl MockBeacon {
    async fn assert_last_submitted_messages(&self, expected_count: usize) -> Vec<SyncCommitteeMessage> {
        let batches = self.submitted_messages.lock().await;
        assert!(!batches.is_empty(), "no submit_sync_committee_messages calls");
        let last = batches.last().unwrap();
        assert_eq!(last.len(), expected_count);
        last.clone()
    }
}
```

---

## 2. Integration Test Framework

### 2.1 Slashing Protection Integration Test (#1 — Critical)

**File:** `crates/rvc/src/orchestrator/coordinator.rs` (add to existing `#[cfg(test)]` module)

**Approach:** Reuse the existing `build_fork_transition_orchestrator` pattern. The key difference: call `process_slot` twice against the **same** `SlashingDb` instance with conflicting attestation data.

**Test structure:**

```
┌─────────────────────────────────────────────────┐
│  Integration Test: Double-Vote Rejection        │
│                                                 │
│  1. SlashingDb::open_in_memory() (shared)       │
│  2. SignerService::new(composite, slashing_db)  │
│  3. DutyOrchestrator::new(... signer ...)       │
│  4. CapturingSubmitter::new()                   │
│                                                 │
│  Slot N:   duties → attest(source=5, target=6)  │
│            → SlashingDb records → submitter ✓    │
│                                                 │
│  Slot N+1: duties → attest(source=4, target=6)  │
│            → SlashingDb REJECTS (double vote)    │
│            → submitter NOT called ✓              │
│                                                 │
│  Assert: results_2 contains error               │
│  Assert: submitter.captured().len() == 1        │
│  Assert: slashing_db has exactly 1 record       │
└─────────────────────────────────────────────────┘
```

**Key implementation details:**

- **Wiremock differentiation:** Mount different attestation data responses per slot using `query_param("slot", slot_str)` matchers.
- **Conflicting data:** Same `target_epoch` (6), different `source_epoch` (5 vs 4) = double vote.
- **Error type assertion:** Verify the error is `SignerError::SlashingProtectionBlocked`, not a generic error.
- **No timing dependencies:** `process_slot` is deterministic from the caller's perspective.
- **Why it catches wiring bugs:** If someone accidentally creates a fresh `SlashingDb` per slot or bypasses the check, the second attestation succeeds and the test fails.

**Helper needed:** A `build_slashing_integration_orchestrator` function similar to `build_fork_transition_orchestrator` but accepting a pre-constructed `SlashingDb` and returning it for post-test queries.

### 2.2 Concurrent Conflicting Attestation (#7)

**File:** `crates/signer/src/lib.rs` (modify existing test)

**Current problem:** Both concurrent tasks sign identical `AttestationData(source=59, target=60)`. The idempotent re-sign path succeeds for both — test proves nothing about mutex serialization.

**Fix:** Change task B to use conflicting data: `AttestationData(source=58, target=60)` (same target, different source = double vote attempt).

```
                 ┌──────────────────────┐
  Task A ────────│ barrier.wait()       │
  (src=59,tgt=60)│                      │
                 │   ┌─ mutex lock ─┐   │
                 │   │ check: empty │   │
                 │   │ record: ok   │   │
                 │   │ sign: ok     │   │
                 │   └──────────────┘   │
                 │                      │
  Task B ────────│ barrier.wait()       │
  (src=58,tgt=60)│                      │
                 │   ┌─ mutex lock ─┐   │
                 │   │ check: DOUBLE│   │
                 │   │   VOTE!      │   │
                 │   │ → REJECT     │   │
                 │   └──────────────┘   │
                 └──────────────────────┘
```

**Assertion:** Exactly one task succeeds, one fails. Order is scheduling-dependent, so count successes/failures rather than asserting on specific tasks.

**Why it catches mutex removal:** Without the per-validator mutex, both tasks could read "no existing record" before either writes, potentially both succeeding.

### 2.3 Fail-Closed DB Error Test (#8)

**File:** `crates/signer/src/lib.rs` (new test in existing `#[cfg(test)]` module)

**Approach:** Use a file-backed `SlashingDb`, record one valid attestation, then corrupt the SQLite file on disk.

```rust
// 1. Create file-backed DB in tempdir
// 2. Record valid attestation via SignerService
// 3. Corrupt: std::fs::write(&db_path, b"corrupted")
// 4. Attempt second attestation via SignerService
// 5. Assert: result.is_err() — DB error must propagate, not be swallowed
```

**Alternative if file corruption doesn't trigger the right code path:** Use `DROP TABLE attestations` via raw SQL on the connection, then attempt `check_and_record_attestation`. This tests the SQLite error path more precisely.

**Note:** `SlashingDb` holds the connection in a `Mutex<Connection>`. To corrupt, we either:
- Use file corruption (preferred — tests the real I/O error path)
- Add a `#[cfg(test)]` method `fn execute_raw_sql(&self, sql: &str)` to `SlashingDb` for dropping tables

If neither is feasible due to `SlashingDb` not exposing its path or connection, use the `SlashingDb::open(path)` constructor with a `tempfile::tempdir()` path, then corrupt the file between operations.

### 2.4 Phantom Entry Verification (#17)

**File:** `crates/signer/src/lib.rs` (extend existing `test_signing_failure_after_recording_warns_phantom`)

**Current test** (lines 2054-2077) only checks the error type. Add DB query after the assertion:

```rust
// After asserting the error type...
let pubkey_hex = hex::encode(pubkey.to_bytes());
let records = slashing_db.get_attestations(&pubkey_hex).unwrap();
assert_eq!(records.len(), 1, "phantom entry must exist after signing failure");
assert_eq!(records[0].source_epoch, 59);
assert_eq!(records[0].target_epoch, 60);
```

This uses `SlashingDb::get_attestations()` (line 175 of `db.rs`), which already exists as a public method.

---

## 3. Test Organization

### 3.1 Finding-to-File Mapping

| # | Finding | Target File | Action |
|---|---------|-------------|--------|
| **1** | Slashing integration test | `crates/rvc/src/orchestrator/coordinator.rs` | Add new test + helper |
| **2** | MockBeaconClient ignores slot | `crates/block-service/src/service.rs` | Extend mock, add assertions to existing tests |
| **3** | publish_block discards block | `crates/block-service/src/service.rs` | Extend mock, add assertions to existing tests |
| **4** | MockSigner ignores fork_schedule | `crates/block-service/src/service.rs` | Extend mock, add assertions to existing tests |
| **5** | Sync MockBeacon discards messages | `crates/sync-service/src/lib.rs` | Extend mock, add assertions to existing tests |
| **6** | Sync MockSigner ignores inputs | `crates/sync-service/src/lib.rs` | Extend mock, add assertions to existing tests |
| **7** | Concurrent test uses identical data | `crates/signer/src/lib.rs` | Modify existing test |
| **8** | No fail-closed DB error test | `crates/signer/src/lib.rs` | Add new test |
| **9** | Probabilistic is_aggregator | `crates/rvc/src/orchestrator/coordinator.rs` | Replace random key with deterministic approach |
| **10** | is_aggregator discards result | `crates/crypto/src/aggregation_signing.rs` | Replace `let _ =` with assertions |
| **11** | Sync aggregator boundary | `crates/sync-service/src/lib.rs` | Add boundary-value tests |
| **12** | Subcommittee boundary positions | `crates/sync-service/src/lib.rs` | Add boundary tests for 127/128/384/511 |
| **13** | ElectraAttestation index: 1 | `crates/eth-types/src/aggregation.rs` | Fix fixture to `index: 0` |
| **14** | Propagator Electra no assertions | `crates/propagator/src/lib.rs` | Add field assertions + Fulu variant |
| **15** | No OOB committee index test | `crates/rvc/src/orchestrator/utils.rs` | Add boundary test |
| **16** | No epoch 0 / slot 0 slashing test | `crates/slashing/src/db.rs` | Add boundary tests |
| **17** | Phantom entry not queried | `crates/signer/src/lib.rs` | Extend existing test |
| **18** | Conformance re-implements watermarks | `crates/slashing/tests/conformance.rs` | Add parallel test using real watermark API |
| **19** | Orchestrator sync_committee untested | `crates/rvc/src/orchestrator/sync_committee.rs` | Add unit tests |
| **20** | No TreeHash tests for sync types | `crates/eth-types/src/sync_committee.rs` | Add TreeHash round-trip tests |
| **21** | SSZ vectors use 8-byte body | `crates/block-service/src/service.rs` | Add large-body + non-empty KZG tests |
| **22** | No fork-awareness for sign_contribution | `crates/crypto/src/sync_signing.rs` | Add fork-variant tests |
| **23** | No slot 0 block proposal test | `crates/block-service/src/service.rs` | Add slot 0 + epoch boundary tests |
| **24** | No BlockAndBlobs JSON parse test | `crates/block-service/src/service.rs` | Add JSON deserialization test |
| **25** | Tautological block root test | `crates/block-service/src/service.rs` | Rewrite to test production logic |
| **26** | Pre-Electra no absence check | `crates/rvc/src/orchestrator/coordinator.rs` | Add wiremock negative matcher |
| **27** | sample_aggregate_and_proof epoch | `crates/crypto/src/aggregation_signing.rs` | Fix fixture epoch relationship |
| **28** | sample_pubkeys wraps at 256 | `crates/sync-service/src/lib.rs` | Fix `i as u8` cast |
| **29** | Phase0 sync committee test | `crates/crypto/src/sync_signing.rs` | Move to Altair slot |
| **30** | No surrounded_vote test | `crates/slashing/src/db.rs` | Add surrounded-vote test |

### 3.2 Shared Test Utilities

No new shared utility crate is needed. Each crate's `#[cfg(test)]` module contains its own helpers. The following utilities are needed within their respective modules:

**Block-service** (`service.rs` test module):
- `CapturedProduceCall`, `CapturedPublishCall`, `CapturedSignBlockCall` structs
- Assertion helpers on `MockBeaconClient` and `MockSigner`

**Sync-service** (`lib.rs` test module):
- `CapturedSyncSignCall`, `CapturedSelectionProofCall`, `CapturedContributionSignCall`, `CapturedSubmittedMessages` structs
- `find_proof_with_modulo_result(modulo, target_remainder)` — generalized proof finder (extends existing `find_aggregator_proof` / `find_non_aggregator_proof`)
- Assertion helpers on `MockSigner` and `MockBeacon`

**Crypto** (`aggregation_signing.rs` test module):
- `find_aggregator_proof_for_modulo(modulo)` and `find_non_aggregator_proof_for_modulo(modulo)` — extracted from sync-service pattern

**Crypto** (`sync_signing.rs` test module):
- `compressed_test_fork_schedule()` — already exists in coordinator and sync-service; duplicate locally (keeping test modules self-contained per Rust convention) or reference via a shared test helper if one already exists

**Coordinator** (`coordinator.rs` test module):
- `build_slashing_integration_orchestrator()` — variant of `build_fork_transition_orchestrator` that accepts a pre-built `SlashingDb`

### 3.3 Module Boundaries

All test code stays within existing `#[cfg(test)]` modules. No new files are created except:

- **None.** All 30 findings are resolved by modifying existing test modules or adding tests to existing `#[cfg(test)]` blocks. The `crates/rvc/src/orchestrator/sync_committee.rs` finding (#19) adds a new `#[cfg(test)] mod tests` block at the bottom of that file (standard Rust pattern).

---

## 4. Dependency Graph

### 4.1 Infrastructure Dependencies

```
                    ┌─────────────────────────────────┐
                    │  Stream A: Block-Service Mocks   │
                    │  #2, #3, #4                      │
                    │  CapturedCall structs + mock      │
                    │  extensions + assertion helpers    │
                    └───────┬─────────────────────────┘
                            │ enables
                            ▼
                    ┌─────────────────────────────────┐
                    │  Stream A cont'd: Block Tests    │
                    │  #21, #23, #24, #25              │
                    │  (use upgraded mocks)             │
                    └─────────────────────────────────┘


                    ┌─────────────────────────────────┐
                    │  Stream B: Sync-Service Mocks    │
                    │  #5, #6                          │
                    │  CapturedCall structs + mock      │
                    │  extensions + assertion helpers    │
                    └───────┬─────────────────────────┘
                            │ enables
                            ▼
                    ┌─────────────────────────────────┐
                    │  Stream B cont'd: Sync Tests     │
                    │  #11, #12, #19, #28              │
                    │  (use upgraded mocks)             │
                    └─────────────────────────────────┘


                    ┌─────────────────────────────────┐
                    │  Stream C: Slashing Group        │
                    │  #16, #30 (db.rs unit tests)     │
                    │  #7, #8, #17 (signer tests)      │
                    │  #1 (coordinator integration)     │
                    │  #18 (conformance refactor)       │
                    │  Shared: SlashingDb + SignerService│
                    └─────────────────────────────────┘


                    ┌─────────────────────────────────┐
                    │  Stream D: Standalone Fixes       │
                    │  #9, #10 (aggregator determinism) │
                    │  #13 (Electra index fixture)      │
                    │  #14 (propagator assertions)      │
                    │  #15 (OOB committee index)        │
                    │  #20 (TreeHash tests)             │
                    │  #26 (wiremock negative matcher)  │
                    │  #27 (fixture epoch fix)           │
                    └─────────────────────────────────┘


                    ┌─────────────────────────────────┐
                    │  Stream E: Fork-Awareness         │
                    │  #22 (sign_contribution fork)     │
                    │  #29 (Phase0 → Altair slot)       │
                    └─────────────────────────────────┘
```

### 4.2 Implementation Order Within Streams

**Stream A: Block-Service (Findings #2, #3, #4 → #21, #23, #24, #25)**

```
Step 1: Define CapturedCall structs (#2, #3, #4)
Step 2: Extend MockBeaconClient + MockSigner with capture fields
Step 3: Update trait impls to capture arguments
Step 4: Add assertion helpers
Step 5: Add new assertions to existing block-service tests
Step 6: Add SSZ large-body + KZG tests (#21)
Step 7: Add slot 0 / epoch boundary tests (#23)
Step 8: Add BlockAndBlobs JSON parse test (#24)
Step 9: Rewrite tautological block root test (#25)
```

**Stream B: Sync-Service (Findings #5, #6 → #11, #12, #19, #28)**

```
Step 1: Define CapturedCall structs (#5, #6)
Step 2: Extend MockSigner + MockBeacon with capture fields
Step 3: Update trait impls to capture arguments
Step 4: Add assertion helpers
Step 5: Add new assertions to existing sync-service tests
Step 6: Add aggregator boundary tests (#11)
Step 7: Add subcommittee boundary tests (#12)
Step 8: Add orchestrator/sync_committee.rs tests (#19)
Step 9: Fix sample_pubkeys wrapping (#28)
```

**Stream C: Slashing Group (Findings #16, #30, #7, #8, #17, #1, #18)**

```
Step 1: Add epoch 0 / slot 0 tests to db.rs (#16)
Step 2: Add surrounded_vote test to db.rs (#30)
Step 3: Fix concurrent signer test with conflicting data (#7)
Step 4: Add fail-closed DB error test (#8)
Step 5: Extend phantom entry test with DB query (#17)
Step 6: Add slashing integration test to coordinator (#1) — depends on steps 1-2 proving db works
Step 7: Add conformance test using real watermarks (#18)
```

**Stream D: Standalone Fixes (Findings #9, #10, #13, #14, #15, #20, #26, #27)**

```
All items are independent — can be done in any order or in parallel.
```

**Stream E: Fork-Awareness (Findings #22, #29)**

```
Step 1: Move Phase0 sync test to Altair slot (#29)
Step 2: Add fork-variant tests for sign_contribution_and_proof (#22)
```

### 4.3 Cross-Stream Parallelism

All five streams can be worked **in parallel** by different developers. There are **no cross-stream dependencies**:

- Stream A touches only `crates/block-service/src/service.rs`
- Stream B touches only `crates/sync-service/src/lib.rs` and `crates/rvc/src/orchestrator/sync_committee.rs`
- Stream C touches `crates/slashing/src/db.rs`, `crates/signer/src/lib.rs`, `crates/rvc/src/orchestrator/coordinator.rs`, and `crates/slashing/tests/conformance.rs`
- Stream D touches `crates/crypto/src/aggregation_signing.rs`, `crates/eth-types/src/aggregation.rs`, `crates/propagator/src/lib.rs`, `crates/rvc/src/orchestrator/utils.rs`, `crates/eth-types/src/sync_committee.rs`, `crates/rvc/src/orchestrator/coordinator.rs` (#26 only)
- Stream E touches `crates/crypto/src/sync_signing.rs`

**Conflict point:** Stream C (#1) and Stream D (#26) both touch `coordinator.rs`. These tests are additive (new test functions), so they won't conflict unless they modify the same helper functions. Coordinate via separate test function names.

### 4.4 Summary Table

| Stream | Findings | Files Touched | Parallel? | Estimated Scope |
|--------|----------|---------------|-----------|-----------------|
| A: Block mocks | #2, #3, #4, #21, #23, #24, #25 | 1 file | Yes | Medium (mock refactor + 4 new tests) |
| B: Sync mocks | #5, #6, #11, #12, #19, #28 | 2 files | Yes | Medium (mock refactor + 4 new tests) |
| C: Slashing | #1, #7, #8, #16, #17, #18, #30 | 4 files | Yes | Large (integration test + 6 others) |
| D: Standalone | #9, #10, #13, #14, #15, #20, #26, #27 | 6 files | Yes | Small per item (8 independent fixes) |
| E: Fork-aware | #22, #29 | 1 file | Yes | Small (2 test additions) |

---

## 5. Design Decisions

### ADR-001: Extend Mocks With Capture Fields Rather Than Replacing Them

**Decision:** Add new `CapturedCall` structs and `Mutex<Vec<CapturedCall>>` fields alongside existing mock fields. Do not remove or rename existing fields.

**Rationale:** The codebase has ~1,100 existing tests. Many assert on current mock behavior (e.g., `publish_calls` as `Vec<String>`). Replacing these fields would require updating every existing test that touches them, increasing risk and scope.

**Alternatives considered:**
- **Replace entirely:** Simpler mock structs, but forces rewriting all existing assertions. High risk of breaking passing tests.
- **New mock types:** Create `CapturingMockSigner` alongside `MockSigner`. Duplicates code and makes it unclear which mock to use.

**Trade-offs:** Slightly larger mock structs (more fields). Acceptable — test code prioritizes clarity over minimalism.

### ADR-002: File Corruption for DB Error Testing (#8)

**Decision:** Use file-backed `SlashingDb` via `tempfile::tempdir()` and corrupt the SQLite file with `std::fs::write()` to test fail-closed behavior.

**Rationale:** Tests the real I/O error path that production code would encounter. No test hooks or `#[cfg(test)]` production code changes needed.

**Alternatives considered:**
- **`DROP TABLE` via raw SQL:** More precise, but requires exposing `SlashingDb`'s internal `Connection` or adding a test-only method. Breaks encapsulation.
- **Read-only file permissions:** `chmod 000` — platform-dependent, doesn't work on all CI environments, may not trigger the right error path if the connection is already open.
- **Mock `SlashingDb` trait:** `SlashingDb` is a concrete struct, not behind a trait. Adding a trait boundary would be a production code change.

**Trade-offs:** File corruption may produce different SQLite error messages across platforms. The test should assert `result.is_err()` broadly rather than matching specific error strings.

### ADR-003: Deterministic Aggregator Tests (#9, #10, #11)

**Decision:** Use SHA256 brute-force proof-finding helpers (already proven in sync-service) for deterministic aggregator boundary tests. For coordinator test #9, use `committee_length = u64::MAX` as a simpler alternative that makes flake probability unmeasurable (~5.4e-18).

**Rationale:** The sync-service already has `find_aggregator_proof()` and `find_non_aggregator_proof()` that iterate `0u64..` until they find a proof with the desired `value % modulo` result. This converges quickly (typically < 100 iterations for modulo=8). Extending this pattern to attestation aggregator tests is consistent and proven.

**Alternatives considered:**
- **Seed-controlled RNG:** Doesn't help — the output depends on BLS signing, not RNG.
- **Mocking `is_aggregator`:** Would bypass the actual function under test.
- **Pre-computed known values:** Fragile — changes to SHA256 library or proof format would break hardcoded values.

**Trade-offs:** `find_proof_with_modulo_result` has a tight loop but converges in microseconds. Acceptable for test setup.

### ADR-004: Keep Original Conformance Test Alongside Watermark Refactor (#18)

**Decision:** Add a new conformance test function using real `SlashingDb` watermark API alongside the existing test-local `HashMap` implementation. Rename the existing function to `run_minimal_conservative` for clarity.

**Rationale:** The existing "minimal strategy" is intentionally conservative (rejects more aggressively than the full history check). It tests a different property than the real watermark API. Replacing it would change the test's semantics.

**Alternatives considered:**
- **Replace entirely:** Loses coverage of the conservative strategy, which is a valid conformance approach.
- **Keep only original:** Doesn't address the finding — test-local watermark logic could diverge from production.

**Trade-offs:** Two conformance runners for the minimal strategy. The duplication is justified because they test different things.

### ADR-005: No Shared Test Utility Crate

**Decision:** Keep all test utilities within their respective crate `#[cfg(test)]` modules. Do not create a `test-utils` crate.

**Rationale:** The duplicated code is minimal (e.g., `test_fork_schedule()` appears in 3 places with identical content). Rust's `#[cfg(test)]` convention keeps test helpers local to the code they test. A shared crate would add a dependency and Cargo.toml changes across multiple crates.

**Alternatives considered:**
- **Shared `test-utils` crate:** Reduces duplication of `ForkSchedule` constructors and proof-finding helpers. But adds cross-crate dependency management and makes it harder to understand test setup by reading a single file.
- **`pub(crate)` test module:** Only works within a single crate, doesn't help across crates.

**Trade-offs:** Small amount of duplicated helper code (3-4 functions). Acceptable for test isolation.

### ADR-006: Integration Test in Coordinator vs Separate Integration Test File (#1)

**Decision:** Place the slashing integration test in `coordinator.rs`'s existing `#[cfg(test)]` module rather than creating a new integration test file in `tests/`.

**Rationale:** The test reuses `build_fork_transition_orchestrator`, `CapturingSubmitter`, `MockSlotClock`, and wiremock infrastructure — all defined inside `coordinator.rs`'s test module and not publicly accessible. Moving to `tests/` would require making these helpers public, which is a larger refactor.

**Alternatives considered:**
- **`tests/slashing_integration.rs`:** Cleaner separation, but requires exposing test helpers.
- **`bin/rvc/tests/`:** Already has integration tests, but they test the full binary, not the coordinator pipeline. Wrong abstraction level.

**Trade-offs:** The coordinator test module is already large (~2500 lines). One more test function is acceptable given the alternative of restructuring test visibility.

---

## 6. Data Flow: Critical Path (Finding #1)

```
User triggers attestation duty at slot N:

  BN API ──GET /duties──▶ DutyOrchestrator.process_slot(N)
  BN API ──GET /attestation_data──▶ AttestationData(source=5, target=6)
  DutyOrchestrator ──sign──▶ SignerService.sign_attestation()
    SignerService ──lock──▶ ValidatorLockMap (per-validator mutex)
    SignerService ──check──▶ SlashingDb.check_and_record_attestation("pk", 5, 6, root_a)
      SlashingDb: no existing records → INSERT → OK
    SignerService ──sign──▶ CompositeSigner.sign(signing_root, pubkey)
    SignerService ──return──▶ Ok(signature)
  DutyOrchestrator ──submit──▶ CapturingSubmitter (captured: [att_1])
  Result: Ok

User triggers attestation duty at slot N+1 (CONFLICTING):

  BN API ──GET /duties──▶ DutyOrchestrator.process_slot(N+1)
  BN API ──GET /attestation_data──▶ AttestationData(source=4, target=6)  ← SAME TARGET
  DutyOrchestrator ──sign──▶ SignerService.sign_attestation()
    SignerService ──lock──▶ ValidatorLockMap
    SignerService ──check──▶ SlashingDb.check_and_record_attestation("pk", 4, 6, root_b)
      SlashingDb: existing record (5, 6, root_a) → target=6 matches → root_b ≠ root_a
        → REJECT: DoubleVote { target_epoch: 6 }
    SignerService ──return──▶ Err(SlashingProtectionBlocked(DoubleVote))
  DutyOrchestrator: error propagated, submitter NOT called
  Result: Err (captured still: [att_1] — only 1 attestation submitted)
```

---

## 7. SSZ Test Vector Design (#21)

The existing `build_ssz_bytes` helper (block-service/service.rs:818-849) produces test vectors with empty KZG data, masking the body-bleed bug in `ssz_deser.rs:187-202`.

**New test vectors needed:**

| Test | Body Size | KZG Proofs | Blobs | Purpose |
|------|-----------|------------|-------|---------|
| Baseline (existing) | 8 bytes | empty | empty | Backward compat |
| Non-empty KZG | 128 bytes | 1 × 48 bytes | 1 × 131072 bytes | **Expose body-bleed bug** |
| Multiple blobs | 256 bytes | 4 × 48 bytes | 4 × 131072 bytes | Full Deneb format |
| Empty body | 0 bytes | empty | empty | `body_offset == end` edge case |
| Malformed offset | N/A | N/A | N/A | `body_offset > block_region` → error |

**Note:** Test 2 (non-empty KZG) **will fail with current production code** because `block_region_end = bytes.len()` includes KZG data in the body. This is the documented body-bleed bug. If the test is meant to document the bug (not fix it), annotate with a comment explaining the expected failure. If the test should pass, the production code in `ssz_deser.rs` needs a one-line fix: `let block_region_end = kzg_proofs_offset;`. This is the one finding that may require a production code change — flag in PR review.

**Helper to add:**

```rust
fn build_ssz_bytes_with_kzg(
    slot: Slot,
    proposer_index: u64,
    body: &[u8],
    kzg_proofs: &[u8],
    blobs: &[u8],
    consensus_version: &str,
) -> Vec<u8> { ... }
```

---

## 8. Fork-Awareness Test Pattern (#22, #29)

**Shared pattern for all fork-variant tests:**

```rust
fn compressed_test_fork_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
        altair_fork_epoch: 10,
        altair_fork_version: [0x01, 0x00, 0x00, 0x00],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
        capella_fork_epoch: 30,
        capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        deneb_fork_epoch: 40,
        deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
        electra_fork_epoch: 50,
        electra_fork_version: [0x05, 0x00, 0x00, 0x00],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
    }
}
```

This schedule is already used in both `block-service` and `sync-service` test modules (identical content). It's also used in coordinator tests via `create_test_fork_schedule()`.

**Finding #22 tests (add to `sync_signing.rs`):**
1. `test_sign_contribution_and_proof_altair` — slot at epoch 10
2. `test_sign_contribution_and_proof_electra` — slot at epoch 50
3. `test_sign_contribution_and_proof_fork_boundary` — last pre-Altair slot vs first Altair slot, assert different signatures

**Finding #29 fix (modify in `sync_signing.rs`):**
- Change `test_sign_sync_committee_message_valid` to use `altair_slot = 10 * SLOTS_PER_EPOCH` instead of slot 100 with mainnet schedule.

---

## 9. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| SSZ body-bleed test (#21) fails against current production code | Medium — may require production fix | Flag in PR. The fix is a one-line change in `ssz_deser.rs`. If test-only scope is strict, write the test as a documented known-failure. |
| Mock refactoring (#2-6) breaks existing tests due to constructor changes | Medium | Initialize all new capture fields to empty `Vec::new()` in existing constructors. No existing test needs updating. |
| File corruption for DB error test (#8) is platform-dependent | Low | Assert broadly on `is_err()` rather than specific error variants. Test works on macOS and Linux. |
| Concurrent test fix (#7) reveals a real mutex bug | High (positive) | This is a desirable outcome. If both tasks succeed with conflicting data, escalate immediately — it means the per-validator lock has a real TOCTOU issue. |
| `compressed_test_fork_schedule` duplicated across modules | Low | Acceptable per ADR-005. All copies are identical and co-located with tests that use them. |

---

## 10. Open Questions

1. **Finding #15 (OOB committee index):** Should `make_aggregation_bits` return an error or an empty bitlist for `validator_committee_index >= committee_length`? The test should document the current behavior with a comment explaining whether it's intentional. Confirm with the team.

2. **Finding #21 (SSZ body-bleed):** Is the body-bleed bug in `ssz_deser.rs` a known issue that should be fixed, or is it intentionally tolerated because the current block-building pipeline never produces blocks with non-empty KZG data in the SSZ path? This determines whether the test should assert on the correct behavior or document the known limitation.

3. **Finding #18 (conformance watermarks):** Does the existing `run_minimal` function need to stay as-is for EIP-3076 conformance certification, or can it be refactored to use real `SlashingDb` watermarks? ADR-004 proposes keeping both.
