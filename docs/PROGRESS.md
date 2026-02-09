# RVC Progress Tracker

## Overview

RVC is a Rust-based Ethereum Validator Client being built in 6 phases (A-F) plus testnet validation. The project follows a 2-stream parallel development model with 64 total issues across all phases.

**Total: 64 issues / 163 story points**

## Current Status

| Phase | Description | Issues | Points | Status |
|-------|------------|--------|--------|--------|
| **A** | Minimum Viable Block Proposer | 16/16 | 41 | **Complete** |
| **A-FU** | Phase A Follow-ups | 5/5 | 11 | **Complete** |
| **B** | Full Duties (aggregation, proposer prep, subscriptions) | 6/6 | 14 | **Complete** |
| C | Reliability & Safety (multi-BN, doppelganger, SSE) | 0/12 | 33 | Not started |
| D | MEV & Builder Integration | 0/7 | 16 | Not started |
| E | Key Management API (keymanager, Web3Signer) | 0/7 | 22 | Not started |
| F | Quality & Optimization (conformance, pruning, SSZ) | 0/5 | 15 | Not started |
| Testnet | Testnet Validation | 0/6 | 11 | Not started |

**Overall Progress: 27/64 issues (42%), 66/163 points (40%)**

---

## Phase A: Minimum Viable Block Proposer (Complete)

Block proposals, sync committee messages, and fork-aware signing working alongside attestations.

### Issues

| Issue | Description | Stream | Points | Status | Branch/Commit |
|-------|------------|--------|--------|--------|---------------|
| A-01 | ForkName enum and ForkSchedule in eth-types | A | 2 | Merged | `49116a4` |
| A-02 | Block types in eth-types | A | 3 | Merged | `b5d60d3` |
| A-03 | Sync committee and aggregation types in eth-types | A | 3 | Merged | `b426cd2` |
| A-04 | Proposer duty, voluntary exit, domain constants | A | 2 | Merged | `8e799f8` |
| A-05 | Quoted integer serde for Beacon API | B | 2 | Merged | `a7a01df` |
| A-06 | Block slashing protection per EIP-3076 | B | 3 | Merged | `a7ac4cc` |
| A-07 | Fork config and genesis endpoints in beacon | B | 2 | Merged | `fb81070` |
| A-08 | Block production endpoints in beacon | A | 3 | Merged | `997e669` |
| A-09 | Sync committee endpoints in beacon | B | 2 | Merged | `b712ae9` |
| A-10 | Block and RANDAO signing in crypto | A | 3 | Merged | `7e6c5fb` |
| A-11 | Sync committee signing in crypto | B | 2 | Merged | `9acc04f` |
| A-12 | ValidatorSigner trait and signer generalization | A | 3 | Merged | `78b0b46` |
| A-13 | rvc-validator-store crate | B | 2 | Merged | `4b74422` |
| A-14 | rvc-block-service crate | A | 3 | Merged | `42257c4` |
| A-15 | rvc-sync-service crate | B | 2 | Merged | `7c211ad`, `85a83b6` (fix) |
| A-16 | Orchestrator integration | Joint | 5 | Merged | `a08623a`..`205fdf7` |

### Crates Added in Phase A

| Crate | Layer | Description |
|-------|-------|------------|
| `rvc-eth-types` | Foundation | Fork, block, sync committee, aggregation, duty, domain types |
| `rvc-validator-store` | Foundation | Validator configuration storage (TOML-based) |
| `rvc-block-service` | Domain | Block proposal lifecycle (RANDAO, produce, sign, publish) |
| `rvc-sync-service` | Domain | Sync committee messages and contribution aggregation |

### Crates Extended in Phase A

| Crate | Changes |
|-------|---------|
| `beacon` | Config spec, genesis, fork, block production, sync committee endpoints |
| `rvc-crypto` | Block signing, RANDAO reveal, sync committee signing |
| `rvc-slashing` | Block slashing protection (is_safe_to_propose, record_block) |
| `rvc-signer` | ValidatorSigner trait, fork-aware block signing |
| `rvc-duty-tracker` | Proposer and sync committee duty caching with eviction |
| `rvc` (orchestrator) | 3-phase slot dispatch, fork-aware startup |

### Bugs Caught in Review

| Issue | Bug | Severity | Resolution |
|-------|-----|----------|------------|
| A-11 | Bare slot signed instead of `SyncAggregatorSelectionData{slot, subcommittee_index}` | Critical | Fixed: added struct, updated signing |
| A-15 | Raw committee positions (0-511) used as subcommittee indices (should divide by 128) | Critical | Fixed: derive `pos / 128`, deduplicate |
| A-16 | Sync contributions fetched but never signed/submitted | Critical | Fixed: complete aggregation flow |
| A-16 | Hardcoded committee scan limit of 64 | Warning | Fixed: query cache directly |
| A-16 | Unbounded duty caches | Warning | Fixed: epoch-based eviction |
| A-08 | produce_block_v3 stored envelope instead of extracting data | Warning | Fixed: extract `body["data"]` |
| A-08 | Missing Eth-Consensus-Version header on publish | Warning | Fixed: added header parameter |
| A-09 | Wrong response wrapper for sync duties (no dependent_root) | Warning | Fixed: ExecutionOptimisticResponse |

### Test Coverage

**682 tests passing, 0 failures, 6 ignored**

| Crate | Tests |
|-------|-------|
| rvc (orchestrator) | 149 |
| rvc-eth-types | 106 |
| rvc-duty-tracker | 86 |
| beacon | 75 |
| rvc-crypto | 62 |
| rvc-validator-store | 38 |
| rvc-slashing | 30 |
| rvc-signer | 28 |
| rvc-propagator | 28 |
| rvc-sync-service | 19 |
| rvc-block-service | 19 |
| rvc-timing | 27 |
| rvc-metrics | 10 |
| bin/rvc | 5 |

---

## Phase A Follow-ups (Complete)

5 follow-up issues identified during Phase A reviews, all resolved.

### Issues

| Issue | Description | Points | Status | Commit |
|-------|------------|--------|--------|--------|
| FU-01 | Hex serde for Root/Signature byte fields | 2 | Merged | `35d73c8` |
| FU-02 | Atomic check-and-record for slashing (TOCTOU) | 2 | Merged | `8bccc5e` |
| FU-03 | SSZ hash_tree_root for block root | 3 | Merged | `6569c7f` |
| FU-04 | Per-operation timeouts for beacon calls | 3 | Merged | `433fcb4` |
| FU-05 | gRPC default bind to 127.0.0.1 | 1 | Merged | `dcb5882` |

### Test Coverage

**695 tests passing, 0 failures, 6 ignored** (up from 682 in Phase A)

---

## Phase B: Full Duties (Complete)

Aggregation duties, proposer preparation, and beacon committee subscriptions integrated into the orchestrator.

### Issues

| Issue | Description | Points | Stream | Status | Commit |
|-------|------------|--------|--------|--------|--------|
| B-01 | Aggregation endpoints in beacon | 2 | A | Merged | `bea9827` |
| B-02 | Aggregation signing in signer | 3 | A | Merged | `6790966` |
| B-03 | Proposer preparation endpoint in beacon | 2 | B | Merged | `d0f6347` |
| B-04 | Beacon committee subscription endpoint | 1 | B | Merged | `d0f6347` |
| B-05 | Proposer prep + subscription in orchestrator | 3 | B | Merged | `92f17c5` |
| B-06 | Aggregation duty dispatch in orchestrator | 3 | A | Merged | `09fea6a` |

### Crates Extended in Phase B

| Crate | Changes |
|-------|---------|
| `beacon` | Aggregation endpoints, proposer preparation, committee subscriptions |
| `rvc-crypto` | Selection proof signing, aggregate_and_proof signing, is_aggregator |
| `rvc-signer` | ValidatorSigner trait extended with sign_selection_proof, sign_aggregate_and_proof |
| `rvc-eth-types` | TreeHash impls for Attestation/AggregateAndProof, TARGET_AGGREGATORS_PER_COMMITTEE |
| `rvc-metrics` | RVC_AGGREGATIONS_TOTAL counter |
| `rvc` (orchestrator) | Aggregation dispatch at t=2*slot/3, proposer preparation at epoch boundary, committee subscriptions |

### Bugs Caught in Review

| Issue | Bug | Severity | Resolution |
|-------|-----|----------|------------|
| B-02 | `is_aggregator` uses raw committee_length instead of `max(1, len/TARGET_AGGREGATORS_PER_COMMITTEE)` | Critical | Fixed: added modulo calculation with TARGET=16 |
| B-04 | Wrong API version `/eth/v2/` instead of `/eth/v1/` for committee subscriptions | Critical | Fixed: changed to v1 |
| B-01 | Out-of-scope orchestrator timeout removal bundled in commit | Warning | Accepted (safe, simplifies code) |
| B-03+B-04 | Branch not rebased on develop, would revert B-01 aggregation endpoints | Warning | Fixed: rebased onto develop |

### Test Coverage

**762 tests passing, 0 failures, 6 ignored** (up from 695 in Phase A follow-ups)

---

## Known Follow-ups

| ID | Description | Priority |
|----|------------|----------|
| FU-06 | Tighten None signing root comparison in atomic slashing methods | Low |
| FU-07 | Reduce visibility of is_safe_to_sign/is_safe_to_propose to pub(crate) | Low |
| FU-08 | Add warn! logging to silent parse continue paths in aggregation dispatch | Low |
| FU-09 | Add overall phase-3 deadline for sync contributions + aggregations | Medium |
| FU-10 | Concurrent/deferred epoch boundary operations to avoid blocking slot-0 proposal | Medium |
| FU-11 | Validator index cache to replace O(V*64*D) nested loop | Medium |

---

## Workspace Architecture

```
bin/rvc/                    # Binary entry point
crates/
  rvc/                      # Orchestrator (main loop, config, service builder)
  beacon/                   # Beacon node HTTP client
  eth-types/                # Ethereum consensus types
  crypto/                   # BLS signing (block, sync, RANDAO)
  slashing/                 # EIP-3076 slashing protection DB
  signer/                   # ValidatorSigner trait + SignerService
  duty-tracker/             # Duty caching (attester, proposer, sync committee)
  propagator/               # Attestation/aggregate propagation
  validator-store/          # Validator config storage
  block-service/            # Block proposal lifecycle
  sync-service/             # Sync committee message/contribution lifecycle
  metrics/                  # Prometheus metrics
  timing/                   # Slot clock
```

### 4-Layer Architecture

```
Binary          bin/rvc
Orchestrator    crates/rvc (service builder, main loop, config)
Domain          block-service, sync-service, signer, duty-tracker, propagator
Foundation      beacon, eth-types, crypto, slashing, validator-store, metrics, timing
```

---

## Phase Dependency Map

```
Phase A (41pts) COMPLETE ──┬──> Phase B (14pts) COMPLETE
                           ├──> Phase C (33pts) ──> Phase E (22pts)
                           ├──> Phase D (16pts)
                           ├──> Phase F (15pts)
                           └──> Testnet (11pts, ongoing)
```

---

## Git History

- **Branch:** develop
- **Develop HEAD:** `92f17c5`
- **Total Phase A commits:** 24 (16 feature + 8 fixes)
- **Total Follow-up commits:** 8 (5 feature + 2 fixes + 1 chore)
- **Total Phase B commits:** 6 (6 feature)
