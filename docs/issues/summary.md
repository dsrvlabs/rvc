# Issue Estimates: Code Review Remediation (MEDIUM & LOW)

## Estimation Approach
- Point scale: 1 (trivial, < 1 day) / 2 (moderate, 1 day) / 3 (complex, 1-2 days)
- Target scope: Every issue completable in 1-2 days. No issue exceeds 3 points.
- Points reflect relative effort including coding, testing, review, and integration
- Parallel workstreams: 2 streams (A and B) for concurrent development

## Phase Files

| File | Phase | Issue Count | Total Points |
|------|-------|-------------|-------------|
| [phase-1-security.md](./phase-1-security.md) | Phase 1: Security & Data Integrity (P0) | 12 | 24 |
| [phase-2-correctness.md](./phase-2-correctness.md) | Phase 2: Correctness & Reliability (P1) | 21 | 39 |
| [phase-3-quality.md](./phase-3-quality.md) | Phase 3: Code Quality & Hardening (P2) | 33 | 37 |
| **Total** | | **66** | **100** |

## Parallel Execution Plan

Shows how issues are distributed across workstreams over time. Each day-slot represents ~1 day of work.

### Phase 1 (5 days)

| Day | Stream A (crypto + slashing) | Stream B (keymanager-api) |
|-----|-----|-----|
| 1 | SEC-01 (1), SEC-02 (2) | SEC-04 (1), SEC-07 (1) |
| 2 | SEC-03 (2), SEC-08 (2) | SEC-05 (3) |
| 3 | DB-01 (2), DB-02 (2) | SEC-05 cont., SEC-06 (2) |
| 4 | DB-03 (3) | SEC-06 cont. |
| 5 | I-JOINT (3) | I-JOINT |

### Phase 2 (8 days)

| Day | Stream A (Correctness) | Stream B (Concurrency & Other) |
|-----|-----|-----|
| 1 | COR-01 (3) | OTH-01 (1), OTH-02 (1), OTH-04 (1) |
| 2 | COR-01 cont., COR-02 (1) | OTH-05 (2), CON-05 (1) |
| 3 | COR-03 (2), COR-04 (2) | CON-04 (2), CON-06 (2) |
| 4 | COR-06 (1), COR-07 (2) | CON-01 (2), CON-02 (1) |
| 5 | COR-08 (2), COR-09 (2) | CON-03 (3) |
| 6 | COR-05 (2) | CON-03 cont. |
| 7 | (buffer) | (buffer) |
| 8 | II-JOINT (3) | II-JOINT |

### Phase 3 (7 days)

| Day | Stream A (Types, Zeroization, Slashing) | Stream B (Async, Concurrency, API) |
|-----|-----|-----|
| 1 | LOW-01 (1), LOW-02 (1), LOW-04 (1) | LOW-06 (1), LOW-09 (1), LOW-10 (1) |
| 2 | LOW-03 (2), LOW-05 (1) | LOW-11 (1), LOW-12 (1), LOW-18 (1) |
| 3 | LOW-07 (1), LOW-08 (1), LOW-13 (1) | LOW-19 (1), LOW-20 (1), LOW-21 (1) |
| 4 | LOW-14 (1), LOW-15 (1), LOW-16 (1), LOW-17 (1) | LOW-25 (2), LOW-26 (1) |
| 5 | LOW-22 (1), LOW-23 (1), LOW-24 (1) | LOW-27 (1), LOW-28 (1), LOW-29 (1) |
| 6 | (buffer) | LOW-30 (1), LOW-31 (2), LOW-32 (1) |
| 7 | III-JOINT (2) | III-JOINT |

**Total estimated duration: 20 days** (with 2 parallel streams)

## Dependency Map

```text
Phase 1 (P0):
SEC-01 ─┐
SEC-02 ─┤
SEC-03 ─┼── Stream A (crypto + slashing) ──┐
SEC-08 ─┤                                   │
DB-01 ──┤                                   │
DB-02 ──┘ (depends on DB-01)                ├──▶ I-JOINT
SEC-04 ─┐                                   │
SEC-05 ─┤                                   │
SEC-06 ─┼── Stream B (keymanager-api) ──────┘
SEC-07 ─┘

Phase 2 (P1):
COR-01 ─┐
COR-02 ─┤
COR-03 ─┤ (COR-04 depends on COR-03)
COR-04 ─┤
COR-05 ─┼── Stream A (correctness) ────────┐
COR-06 ─┤                                   │
COR-07 ─┤                                   │
COR-08 ─┤                                   ├──▶ II-JOINT
COR-09 ─┘                                   │
OTH-01 ─┐                                   │
OTH-02 ─┤                                   │
OTH-04 ─┤                                   │
OTH-05 ─┤                                   │
CON-04 ─┼── Stream B (concurrency) ────────┘
CON-05 ─┤
CON-06 ─┤
CON-01 ─┤
CON-02 ─┤
CON-03 ─┘ (depends on COR-05 for trait changes)

Phase 3 (P2):
All LOW-* issues are independent. No inter-issue dependencies.
All can be freely distributed across streams.
```

## Risk Flags

| Issue | Risk | Mitigation |
|-------|------|------------|
| COR-01 | Per-validator mutex could introduce deadlock if held across .await of another mutex | Mutex only held for check-record-sign sequence; no nested locks |
| CON-03 | Dynamic pubkey_map race with duty polling during key import | Short-lived write lock (single insert); generation counter prevents stale reads |
| COR-04 | ValidatorStoreState refactor could break concurrent readers | Single RwLock swap is atomic by design; comprehensive test coverage |
| DB-03 | Reconciling slashing check logic could introduce subtle differences | Parameterized test matrix comparing both paths with identical inputs |
| SEC-05 | SSRF URL validation may be bypassed via DNS rebinding | Document as future work; current IP-literal check is baseline defense |
| LOW-03 | ProposerDuty.pubkey type change has ripple effect across crates | Grep all callers before changing; higher point estimate (2) accounts for this |
| LOW-25 | Async span audit may miss instances | Comprehensive grep for `.entered()` and `.enter()` in all async code |

## File Ownership Map

| Directory / Module | Owner Stream | Notes |
|--------------------|-------------|-------|
| `crates/crypto/` | A (Phase 1, 3) | All crypto: bls, keystore, key_manager, remote_signer |
| `crates/slashing/` | A (Phase 1, 3) | Slashing DB, EIP-3076, watermarks |
| `crates/eth-types/` | A (Phase 3) | Type definitions, tree hash |
| `crates/validator-store/` | A (Phase 2) | Config reload, validator state |
| `crates/block-service/` | A (Phase 2) | Block production |
| `bin/rvc-keygen/` | A (Phase 2, 3) | Key generation CLI |
| `crates/keymanager-api/` | B (Phase 1, 3) | API server, handlers, auth |
| `crates/bn-manager/` | B (Phase 2, 3) | BN health, SSE, query |
| `crates/timing/` | B (Phase 2) | Slot clock, metrics |
| `crates/secret-provider/` | B (Phase 2, 3) | GCP, format detection, refresh |
| `crates/duty-tracker/` | B (Phase 2) | Duty cache, dependent root |
| `crates/builder/` | B (Phase 3) | Builder registration |
| `crates/sync-service/` | B (Phase 3) | Sync committee messages |
| `crates/beacon/` | A (Phase 2), B (Phase 3) | HTTP client — COR-08/09 (A), LOW-28 (B) different methods |
| `crates/signer/` | A (Phase 2), B (Phase 3) | COR-01 (A), LOW-11/12 (B) different methods |
| `crates/rvc/` (orchestrator) | B (Phase 2, 3) | Slot loop, phase timing |
| `bin/rvc/` (main) | shared | CLI flags — append-only sections per stream |
| `crates/doppelganger/` | B (Phase 3) | Async span fix only |

## Merge Conflict Hotspots

| File / Module | Touched by | Strategy | Merge Order |
|---------------|------------|----------|-------------|
| `bin/rvc/src/main.rs` | SEC-05, SEC-06, SEC-07 (Phase 1 Stream B), CON-03 (Phase 2 Stream B) | Each issue adds CLI flags in separate clearly-commented sections; append-only | SEC-05 → SEC-06 → SEC-07 → CON-03 |
| `crates/slashing/src/db.rs` | DB-01, DB-02, DB-03 (Phase 1), LOW-13–LOW-17 (Phase 3) | DB-01 touches `open()`, DB-02 touches `import_interchange()`, DB-03 touches check functions, LOW-* touch different methods | DB-01 → DB-02 → DB-03 (Phase 1); LOW-13–17 sequential (Phase 3) |
| `crates/keymanager-api/src/server.rs` | SEC-06, SEC-07 | Both add `.layer()` calls to router — append-only | SEC-06 → SEC-07 |
| `crates/bn-manager/src/manager.rs` | COR-07, CON-04, CON-05 | COR-07 touches `health_scores()`, CON-04 touches `query_first()`, CON-05 touches `fallback_unsynced()` — different methods | Any order |
| `crates/beacon/src/client.rs` | COR-08, COR-09 (Phase 2), LOW-28 (Phase 3) | COR-08 touches retry loop, COR-09 touches `get_validators()`, LOW-28 touches `calculate_backoff()` — different methods | Any order |
| `crates/rvc/src/keymanager_adapters.rs` | COR-05, CON-03 | COR-05 adds new trait method impl, CON-03 adds pubkey_map wiring — different methods | COR-05 → CON-03 |

### Conflict Avoidance Patterns Applied

1. **Append-only sections** for `main.rs` CLI flags — each issue adds flags in its own section
2. **Method-level ownership** for `db.rs`, `manager.rs`, `client.rs` — issues touch different methods in the same file
3. **Sequential within stream** for `server.rs` — SEC-06 merges before SEC-07 (both Stream B)
4. **Phase separation** for `slashing/db.rs` — Phase 1 issues (DB-*) complete before Phase 3 issues (LOW-*)

## Key Technical Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Keep record-then-sign** (COR-01) | Ethereum consensus spec mandates save-before-sign. All major VCs follow this. |
| 2 | **Per-validator mutex** (COR-01) | Global mutex serializes all validators; per-validator is natural shard key. |
| 3 | **blst zeroization sufficient** (SEC-01) | blst >= 0.3.11 implements `#[zeroize(drop)]`. Document, don't reimplement. |
| 4 | **HTTPS required by default** (SEC-05) | Fail-closed. HTTP only with explicit `--allow-insecure-remote-signer`. |
| 5 | **tokio::sync::RwLock for pubkey_map** (CON-03) | Read-heavy workload; tokio RwLock needed since held across .await. |
| 6 | **Generation counter** (CON-03) | Simpler than channels; avoids unnecessary duty refreshes. |
| 7 | **synchronous=FULL** (DB-01) | Slashing protection: data loss = double-signing risk. 1-2 writes/slot → no perf concern. |
