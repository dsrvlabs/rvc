# Phase 4: M2 Fixes — Duty-Correctness Floor & Release Gate

## Phase Overview

- **Goal:** Close all 16 M2 findings (E-1, E-2, B-1/T-1+L-9, KG-1, aggregator cluster SS-2/SS-3+L-4, BN-1, BN-2, DT-1+S-2+C-1 runtime-import cluster, S-5, SSE-1, GVR-1+IMP-1, KG-2, EXIT-1, BLD-1, SYNC-1, KS-1). After this phase: block proposal succeeds end-to-end against a spec-compliant BN for all forks (Bellatrix, Capella, Deneb with/without blobs, Electra); aggregator duty succeeds for real-committee `aggregation_bits`; runtime keymanager import → orchestrator → duty → sign integration works; sync-committee participation succeeds at normal cadence. This phase satisfies PRD M2/M3/M7 and closes P0 + the M2-resident P1 findings (the four P1 findings deferred to Phase 6 — URL-1, URL-2, KM-3, VS-1 — must also land before release per DL-5).
- **Issue count:** 25 issues, 63 total points.
- **Estimated duration:** approximately 32 working days (single-stream).
- **Entry criteria:**
  - Phase 3 complete: all four spec-vector fixture sets landed (E-1 per-fork blocks, E-2 aggregate, B-1/T-1 Deneb block, KG-1 BLS-to-execution-change).
  - Phase 3 `eth-types::canonical::parse_gvr_hex` / `eq_gvr` promoted as the single hex/GVR parser used by `slashing::import` and `bin/rvc` exit subcommands.
  - Phase 2 complete: `signer::SigningGate`, `doppelganger::ForwardWindowMachine`, `slashing::PubkeyScopedDb`, `SigningEnablement`, `FailClosedDefault`, `SlashingDbReader` traits all shipped.
  - Phase 1 standing gates green: `tests/architecture_no_cycles.rs`, `bin/rvc-signer/tests/signing_path_enumeration.rs`.
  - Phase 1 Task 1.9 (Q7) resolved: B-1/T-1 actual landed state documented in the tracker so the RED test inverts the right baseline.
  - `develop` builds clean: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` all green.
- **Exit criteria:**
  - All 16 M2 fix branches merged FF-only to `develop`; CI four-gate suite green on each.
  - PRD M2 verified: block proposal against a spec-compliant BN succeeds for Bellatrix, Capella, Deneb (with and without blobs), Electra; spec-vector cross-checks green.
  - PRD M3 verified: aggregator duty succeeds for real-committee `aggregation_bits`; spec-vector cross-check green.
  - PRD M7 verified: runtime keymanager import → orchestrator → duty → sign integration test green.
  - PRD M5 verified: `cargo build` / `cargo test` / `cargo clippy -- -D warnings` / `cargo fmt --check` green on `develop`.
  - Tracker updated: every M2 finding row shows RED commit hash + GREEN commit hash + test file.
  - Standing CI gates from Phase 1 / Phase 2 (`tests/architecture_no_cycles.rs`, enumeration test) remain green.
  - Release branch unblocking confirmed: P0 + M2-resident P1 closed; the four P1 findings deferred to Phase 6 (URL-1, URL-2, KM-3, VS-1) are explicitly tracked as the remaining pre-release blockers per DL-5.

### Assumptions (recorded in this phase)

- **A1 — Estimation scale:** point scale is 1 / 2 / 3 / 5 with 1–3 as the target per-issue scope. Single 5-point issues are justified inline; nothing exceeds 5 points without being split.
- **A2 — Single-stream execution:** issues are sequenced for a single code-writer working in dependency order; no Stream A/Stream B, no file-ownership map, no scaffold issues.
- **A3 — TDD per-finding:** every issue lands as a RED → GREEN (→ REFACTOR) sequence per PRD §6.1; each issue's acceptance criteria call out the RED test explicitly. The "issue is done" point is the GREEN commit landing FF-only to `develop` with the four-gate CI green.
- **A4 — Phase 3 prerequisites:** spec-vector fixtures from `ethereum/consensus-spec-tests` (E-1, E-2, B-1/T-1) and `staking-deposit-cli` (KG-1) are committed under each consuming crate's `tests/fixtures/` with a provenance README. If a particular fork's fixture is unavailable the corresponding cross-check is filed as a follow-up and the fix lands with a self-consistent test.
- **A5 — Cluster branches mirror PRD §7.1:** B-1+T-1+L-9, SS-2+SS-3+L-4, DT-1+S-2+C-1, GVR-1+IMP-1 ship as single branches because GREEN diffs literally overlap. Their inner findings are broken into separate issues here so estimation stays 1–2 days each, but RED/GREEN commits land on the cluster branch.
- **A6 — Release gate per DL-5:** the release is **NOT** cut at Phase 4 exit; it is cut after Phase 6 Task 6.4 (VS-1) so URL-1/URL-2/KM-3/VS-1 are included. Phase 4 exit unblocks Phase 5 (net-policy) immediately.
- **A7 — Velocity baseline:** estimates assume one experienced Rust developer familiar with the rs-vc codebase. A 1-point issue is ~0.5 day; a 2-point issue is ~1 day; a 3-point issue is ~2 days; a 5-point issue is ~3 days including review.
- **A8 — Q7 / Research R2:** RED tests for B-1/T-1 are written against the actual landed state of the SSZ publish path (documented in tracker by Phase 1 Task 1.9); the RED test may need to invert a pinning test rather than asserting from-scratch.
- **A9 — `SigningGate` ownership:** `sign_aggregate_and_proof` lives on `SigningGate`'s non-slashable path (Phase 2 Task 2.6 already wired the gate); the aggregator fix moves the existing `bin/rvc-signer/src/service.rs` handler onto that path without re-implementing slashing protection.
- **A10 — Backwards-compat for KG-1:** prior `bls-to-execution-change` outputs from `rvc-keygen` are invalid (wrong fork version) and operators must regenerate. Release-notes carry this; no migration tool ships in Phase 4.

## Phase Summary

| Issue | Title | Points | Blocked by | Scope | Files |
|-------|-------|--------|------------|-------|-------|
| 4.1 | E-1 RED: BeaconBlock body container tree-hash regression test | 2 | Phase 3.1 | 1 day | `crates/eth-types/tests/spec_vector_block.rs`, `crates/eth-types/tests/fixtures/` |
| 4.2 | E-1 GREEN: rewrite tree_hash_utils with container helper + BodyHashRoot | 3 | 4.1 | 2 days | `crates/eth-types/src/{tree_hash_utils,block}.rs` |
| 4.3 | E-2 RED: aggregation Bitlist chunk-count regression test | 2 | Phase 3.2, 4.2 | 1 day | `crates/eth-types/tests/spec_vector_bitlist.rs`, `crates/eth-types/tests/fixtures/` |
| 4.4 | E-2 GREEN: const-generic bitlist_tree_hash_root<N> | 3 | 4.3 | 2 days | `crates/eth-types/src/{tree_hash_utils,aggregation}.rs` |
| 4.5 | B-1/T-1 RED: SignedBlockContents round-trip + bounded kzg_offset | 2 | Phase 3.3, Phase 1.9 | 1 day | `crates/block-service/tests/`, `crates/block-service/tests/fixtures/` |
| 4.6 | B-1/T-1 GREEN: bound published bytes + SignedBlockContents framing | 5 | 4.5 | 3 days | `crates/block-service/src/service.rs`, `crates/beacon/src/ssz_deser.rs` |
| 4.7 | L-9: un-ignore stale SSZ tests as positive regressions | 1 | 4.6, 4.2 | 0.5 day | `crates/block-service/src/service.rs` |
| 4.8 | KG-1: BLS-to-execution-change uses GENESIS_FORK_VERSION + invert tests | 3 | Phase 3.4 | 2 days | `bin/rvc-keygen/src/bls_to_execution.rs` |
| 4.9 | SS-2/SS-3: sign_aggregate_and_proof skips slashing DB stage | 3 | Phase 2.6, 4.4, SS-1 enumeration gate | 2 days | `bin/rvc-signer/src/service.rs`, `crates/signer/src/non_slashable.rs` |
| 4.10 | L-4: validate_attestation_data on aggregation BN response | 2 | 4.9, 4.4 | 1 day | `crates/rvc/src/orchestrator/aggregation.rs` |
| 4.11 | BN-1: optimistic BN tier cap + per-response gate | 3 | — | 2 days | `crates/bn-manager/src/sync_status.rs`, `crates/rvc/src/orchestrator/coordinator.rs` |
| 4.12 | BN-2: startup-window unknown-tier handling | 2 | 4.11 | 1 day | `crates/bn-manager/src/{sync_status,manager}.rs` |
| 4.13 | DT-1: runtime-mutable validator_indices in duty-tracker | 2 | — | 1 day | `crates/duty-tracker/src/tracker.rs` |
| 4.14 | C-1: borrow_and_update on key_gen_rx in orchestrator | 1 | — | 0.5 day | `crates/rvc/src/orchestrator/coordinator.rs` |
| 4.15 | S-2: wire key_gen channel + pubkey_map into adapters and orchestrator | 3 | 4.13, 4.14 | 2 days | `bin/rvc/src/main.rs`, `crates/rvc/src/{keymanager_adapters,orchestrator/coordinator}.rs` |
| 4.16 | Runtime-import end-to-end integration test (PRD M7) | 3 | 4.15, Phase 2.7 KM-2, Phase 2 ForwardWindowMachine | 2 days | `crates/keymanager-api/tests/`, `crates/rvc/tests/` |
| 4.17 | S-5: sync-committee head_root via get_block_root("head") with fallback | 2 | — (parallel-safe w/ 4.11, 4.12) | 1 day | `crates/rvc/src/orchestrator/{slot_context,sync_committee}.rs` |
| 4.18 | SSE-1: SSE consumer task re-created on reconnect / panic-isolated | 3 | — | 2 days | `crates/bn-manager/src/sse.rs` |
| 4.19 | GVR-1: canonical GVR comparison in slashing::import | 2 | Phase 3.5 | 1 day | `crates/slashing/src/db.rs`, new `crates/slashing/src/import.rs` |
| 4.20 | IMP-1: reject source>target + record conflicting-root rows | 3 | 4.19, Phase 2.3 | 2 days | `crates/slashing/src/{import,db}.rs` |
| 4.21 | KG-2: keygen self-verification failure is hard error | 2 | — | 1 day | `bin/rvc-keygen/src/new_mnemonic.rs` |
| 4.22 | EXIT-1: voluntary exit cross-checks effective GVR against BN | 3 | Phase 3.5 | 2 days | `bin/rvc/src/commands/{voluntary_exit,prepare_exit}.rs` |
| 4.23 | BLD-1: builder registration refresh cadence | 3 | — | 2 days | `crates/builder/src/service.rs` |
| 4.24 | SYNC-1: validate BN-returned contribution fields | 2 | — | 1 day | `crates/sync-service/src/lib.rs`, `crates/rvc/src/orchestrator/sync_committee.rs` |
| 4.25 | KS-1: effective-cost gate on keystore params before decrypt | 3 | — | 2 days | `crates/crypto/src/keystore.rs`, `crates/keymanager-api/src/keymanager_adapters.rs` |

> Issue 4.7 (L-9) is a tiny clean-up after 4.6; it stays a separate issue for tracker clarity. Issue 4.16 is the PRD M7 integration test that consumes 4.13 + 4.14 + 4.15 together — it is the safety net for the runtime-import cluster.

## Phase Execution Plan

| Day | Issue | Notes |
|-----|-------|-------|
| 1 | 4.1 (E-1 RED, 2pts) | Lands the spec-vector test; fails against the current `List[byte]` body leaf. |
| 2 | 4.2 (E-1 GREEN, 3pts) start | Rewrite `tree_hash_utils`; introduce `BodyHashRoot`. |
| 3 | 4.2 cont. | Wire `block::tree_hash_root` to the new container helper; RED test goes green. |
| 4 | 4.3 (E-2 RED, 2pts) | Bitlist chunk-count spec-vector test. |
| 5 | 4.4 (E-2 GREEN, 3pts) start | Const-generic `bitlist_tree_hash_root<N>`. |
| 6 | 4.4 cont. | Update `aggregation.rs` call sites to declare `MAX_VALIDATORS_PER_COMMITTEE`; RED → GREEN. |
| 7 | 4.5 (B-1/T-1 RED, 2pts) | RED inverts Q7-resolved state; round-trip + kzg-offset bound asserted. |
| 8 | 4.6 (B-1/T-1 GREEN, 5pts) start | Bound bytes at `kzg_offset`. |
| 9 | 4.6 cont. | Serialise as `SignedBlockContents` (three offsets, bounded block, kzg_proofs, blobs). |
| 10 | 4.6 cont. + 4.7 (L-9, 1pt) | Finish framing; un-ignore stale tests as positive regressions. |
| 11 | 4.8 (KG-1, 3pts) start | Domain via `GENESIS_FORK_VERSION`; invert the two pinning tests. |
| 12 | 4.8 cont. | Cross-check against `staking-deposit-cli` fixture. |
| 13 | 4.9 (SS-2/SS-3, 3pts) start | Move `sign_aggregate_and_proof` onto `SigningGate` non-slashable path. |
| 14 | 4.9 cont. | ADR-009 chain-of-custody comment block + integration test. |
| 15 | 4.10 (L-4, 2pts) | `validate_attestation_data` on aggregation BN response. |
| 16 | 4.11 (BN-1, 3pts) start | `tier()` caps optimistic at Unsynced. |
| 17 | 4.11 cont. | Coordinator per-response `execution_optimistic` gate. |
| 18 | 4.12 (BN-2, 2pts) | Startup-window Unknown handling. |
| 19 | 4.13 (DT-1, 2pts) | `RwLock<Vec<String>>` + setter. |
| 20 | 4.14 (C-1, 1pt) + 4.15 (S-2, 3pts) start | `borrow_and_update`; create real channel. |
| 21 | 4.15 cont. | Plumb `pubkey_map` + `key_gen_tx` into both adapters and orchestrator. |
| 22 | 4.16 (M7 e2e, 3pts) start | Wire integration test against in-process keymanager + orchestrator. |
| 23 | 4.16 cont. | Cross-validates DT-1 + S-2 + C-1 end-to-end. |
| 24 | 4.17 (S-5, 2pts) | `get_block_root("head")` + fallback. |
| 25 | 4.18 (SSE-1, 3pts) start | Channel + consumer task created inside reconnect path. |
| 26 | 4.18 cont. | Or wrap callback in `catch_unwind`; resume-after-panic test. |
| 27 | 4.19 (GVR-1, 2pts) | `canonical::eq_gvr`; mixed-case + 0x-prefix interchange compares equal. |
| 28 | 4.20 (IMP-1, 3pts) start | Reject `source>target` as `InvalidInterchangeFormat`. |
| 29 | 4.20 cont. | Detect conflicting-root rows; raise watermark / record marker. |
| 30 | 4.21 (KG-2, 2pts) | FAILED/MISMATCH → hard error; non-zero exit; no deposit data. |
| 31 | 4.22 (EXIT-1, 3pts) start | `beacon.get_genesis()` cross-check. |
| 32 | 4.22 cont. | Fail closed on mismatch; CLI surface error. |
| 33 | 4.23 (BLD-1, 3pts) start | Per-pubkey last-submitted timestamp; bounded cadence. |
| 34 | 4.23 cont. | Embedded `timestamp` refreshed each submission. |
| 35 | 4.24 (SYNC-1, 2pts) | Validate `subcommittee_index` / `slot` / `beacon_block_root`. |
| 36 | 4.25 (KS-1, 3pts) start | Effective-cost gate + per-field maxima. |
| 37 | 4.25 cont. | Gate applied **before** decrypt at the import path. |

(Estimate compressed to ~32 days excluding review; sequential-day totals above are a working-day budget including review touch-ups.)

## Dependency Map

```text
[Phase 3.1 fixtures] ──▶ 4.1 ──▶ 4.2 ─┬──▶ 4.4 ─┬──▶ 4.9 ──▶ 4.10
                                       │         │           ▲
[Phase 3.2 fixtures] ──▶ 4.3 ──────────┘         └───────────┘  (4.10 also blocked by 4.4)
                                       │
                                       └──▶ 4.7  (L-9 un-ignore: expected roots depend on 4.2)

[Phase 3.3 fixtures] ──▶ 4.5 ──▶ 4.6 ──▶ 4.7
[Phase 1.9 Q7 doc]   ──▶ 4.5
[Phase 3.4 fixtures] ──▶ 4.8

[Phase 2.6 SigningGate]             ──┐
[SS-1 enumeration gate (standing)]  ──┼──▶ 4.9
                                       │
                                       └ (4.9 also blocked by 4.4 above)

4.11 ──▶ 4.12         (BN tier coherence)
4.17  parallel-safe w/ 4.11, 4.12 (no build-time edge; mock-tier assumption documented)

4.13 ──┐
4.14 ──┼──▶ 4.15 ──▶ 4.16
       │
[Phase 2.7 KM-2 cancel]            ──┐
[Phase 2 ForwardWindowMachine]     ──┼──▶ 4.16  (e2e doppelganger window expiry)
                                      │
                                      └ (4.16 also blocked by 4.15)

[Phase 3.5 canonical promotion] ──▶ 4.19 ──▶ 4.20
                                ──▶ 4.22  (4.22 parallel-safe w/ 4.19; both consume eq_gvr)

[Phase 2.3 db.rs schema change] ──▶ 4.20  (rebase dependency: WHERE-clause keying overlap)

Independent (no intra-phase blockers): 4.18, 4.21, 4.23, 4.24, 4.25
(4.17 listed separately above with parallel-safety note vs 4.11/4.12.)
```

## Risk Flags

| Issue | Risk | Mitigation |
|-------|------|------------|
| 4.6 (B-1/T-1 GREEN) | 5-point issue with on-disk byte-format change; published bytes deserialisation is the gating contract. | RED test asserts round-trip first (4.5); split was considered but the framing change is one atomic edit — see "Why 5 points" below. Two integration tests cover Deneb-with-blobs and Deneb-without-blobs separately. |
| 4.8 (KG-1) | Inverts two existing passing tests; risk of churn if the existing tests have additional assertions not captured in the PRD. | RED commit lands the inverted tests first; the inversion plus the cross-check fixture must both go green together. |
| 4.9 (SS-2/SS-3) | Touches `bin/rvc-signer/src/service.rs` which the SS-1 enumeration test also gates; mis-routing the aggregate path will fail the standing CI gate. | The enumeration test catches a missed routing; the chain-of-custody integration test (ADR-009) catches a missed precondition. |
| 4.15 (S-2) | Touches `bin/rvc/src/main.rs` wire-up alongside `keymanager_adapters.rs` and `coordinator.rs` — three files, but the change is plumbing. | Issue 4.14 (C-1) lands first so `key_gen_rx` consumption is correct; 4.16 (M7 e2e) is the safety net. |
| 4.16 (M7 e2e) | Integration test setup requires running keymanager + orchestrator in-process; risk of flakiness. | Use existing test fixtures from `crates/rvc/tests/`; mock BN; assert observable side effects (duty fetch + signature). |
| 4.18 (SSE-1) | `catch_unwind` across async boundaries can be subtle; need to verify event delivery actually resumes. | Test asserts delivery after a single callback panic, not just "no panic"; per PRD acceptance criterion remove the legacy "second TCP connection only" assertion. |
| 4.20 (IMP-1) | Touches `slashing::import` which Phase 2 Task 2.3 also touched; rebase risk if Phase 2 churned the same lines. | 4.19 (GVR-1) lands the canonical helper plumbing first; 4.20 is a smaller atomic add on top. |
| 4.22 (EXIT-1) | New BN call (`get_genesis`) added to CLI exit subcommands; risk of breaking existing operator workflows. | Documented release-note item per PRD §12; operator can pass `--genesis-validators-root` to bypass network call if absolutely needed (only if PRD allows; default is fail closed). |
| 4.23 (BLD-1) | Bounded cadence drives more relay traffic; risk of unexpected operator complaint. | Cadence configurable; documented in release notes. |
| 4.25 (KS-1) | Gate must run **before** decrypt; risk of accidentally placing it after decrypt and missing the DoS class. | RED test loads a deliberately-oversized keystore and asserts rejection at the import API boundary, not at decrypt. |

### Why issue 4.6 is 5 points and not split

B-1/T-1 GREEN involves two atomically-paired changes inside `block-service::propose_block`: bounding the published `SignedBeaconBlock` bytes at `kzg_offset` AND serialising Deneb+ payloads as proper `SignedBlockContents` (three variable offsets, the bounded `SignedBeaconBlock`, `kzg_proofs`, `blobs`). Splitting these would leave an inconsistent intermediate where one is correct and the other is not (e.g. bounded block but no `SignedBlockContents` framing), and that intermediate cannot pass the RED test. The 5-point budget covers ~3 days of work including:

- Writing the bounded-encoder against Deneb spec.
- Adapting `crates/beacon/src/ssz_deser.rs` to round-trip the new framing.
- Updating any propagator publish-path consumers.
- Running both with-blobs and without-blobs integration paths.

A 5-point estimate is the smallest atomic step that produces a passing RED→GREEN sequence; 3+3 split would leave an intermediate state that does not deserialise.

---

## Issues

### Issue 4.1: E-1 RED — BeaconBlock body container tree-hash regression test

- **Points:** 2
- **Type:** test
- **Priority:** P0
- **Blocked by:** Phase 3 Task 3.1 (per-fork BeaconBlock fixtures in `crates/eth-types/tests/fixtures/`)
- **Blocks:** Issue 4.2
- **Scope:** 1 day

**Description:**
Land the spec-vector regression test that proves `BeaconBlock::tree_hash_root()` currently produces a wrong root because the body leaf is hashed as `List[byte]` rather than as the `BeaconBlockBody` container. The test must fail RED on `develop` for the right reason: comparing the rs-vc-produced root against a fixture sourced from `ethereum/consensus-spec-tests` (or Lighthouse/Lodestar) and observing inequality.

**Implementation Notes:**
- Files likely affected: `crates/eth-types/tests/spec_vector_block.rs` (new), `crates/eth-types/tests/fixtures/README.md` (provenance).
- Approach: deserialise each per-fork fixture via SSZ, compute `tree_hash_root()` via the current implementation, assert equality against the fixture's expected hash. Use `#[test]` per fork (Bellatrix, Capella, Deneb, Electra).
- Watch out for: fork-version routing inside `block.rs` — make sure the test exercises the active fork's schema. Use the project's existing fork-derived block type if available; otherwise drive directly through `Block::from_ssz_bytes(...)`.
- New files to create: `crates/eth-types/tests/spec_vector_block.rs`.
- Commit format: `test(eth-types): E-1 — RED test cross-checks BeaconBlock tree_hash_root against consensus-spec-tests fixture`.

**Acceptance Criteria:**
- [ ] One `#[test]` function per fork (Bellatrix, Capella, Deneb, Electra).
- [ ] Each test loads the fork's fixture, parses it via the existing SSZ deser, and asserts `block.tree_hash_root() == expected_root`.
- [ ] At least one test fails on `develop` HEAD before the GREEN commit (RED commit verified in CI as failing — manual run + tracker note).
- [ ] Provenance README (`crates/eth-types/tests/fixtures/README.md`) documents the fixture source (consensus-spec-tests tag, file path, hash).
- [ ] Commit message references `E-1`.

**Testing Notes:**
- Fixture loading: `include_bytes!("fixtures/bellatrix_block.ssz")`.
- Expected root comes from a sibling `.expected_root.txt` or const literal in the test file. Choose one and document.

---

### Issue 4.2: E-1 GREEN — rewrite tree_hash_utils with container helper + BodyHashRoot

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** Issue 4.1
- **Blocks:** Issue 4.4
- **Scope:** 2 days

**Description:**
Make the RED test from Issue 4.1 pass by rewriting `crates/eth-types/src/tree_hash_utils.rs` with a spec-correct `container_tree_hash_root<T: TreeHash>(value) -> Hash256` helper and introducing an internal `BodyHashRoot([u8; 32])` newtype. `BeaconBlock::tree_hash_root()` sets the body leaf from a `BodyHashRoot` only; the type system refuses to compile code that passes a `List[byte]` hash.

**Implementation Notes:**
- Files likely affected: `crates/eth-types/src/tree_hash_utils.rs`, `crates/eth-types/src/block.rs`.
- Approach:
  1. Add `pub fn container_tree_hash_root<T: TreeHash>(value: &T) -> Hash256` to `tree_hash_utils.rs`.
  2. Add internal `pub(crate) struct BodyHashRoot([u8; 32]);` with a `From<Hash256>` impl exposed only inside `eth-types`.
  3. Update `BeaconBlock::tree_hash_root` to construct the body leaf via `BodyHashRoot::from(container_tree_hash_root(&self.body))`.
  4. Delete the previous `List[byte]` body-leaf code path.
- Key decisions: the `BodyHashRoot` newtype is `pub(crate)` so external code cannot bypass; the body leaf can only be reached via `container_tree_hash_root`.
- Watch out for: `crates/block-service/src/service.rs:411` comment referenced in PRD acceptance criterion — update or remove. Search for other call sites with `grep -rn "next_power_of_two" crates/eth-types`.
- New files to create: none.
- Commit format: `fix(eth-types): E-1 — body leaf uses container_tree_hash_root via BodyHashRoot newtype`.

**Acceptance Criteria:**
- [ ] All four per-fork `spec_vector_block` tests pass (RED → GREEN).
- [ ] `container_tree_hash_root<T: TreeHash>` is the only path used by `BeaconBlock::tree_hash_root` for the body leaf.
- [ ] `BodyHashRoot` is `pub(crate)` and constructible only via `From<Hash256>` inside `eth-types`.
- [ ] Existing comment at `block-service/src/service.rs:411` removed or updated to reflect the fixed behaviour (per PRD acceptance criterion).
- [ ] `cargo test -p eth-types` green; `cargo clippy -p eth-types -- -D warnings` green.
- [ ] Commit message references `E-1`.

**Testing Notes:**
- The RED test from 4.1 becomes the GREEN regression.
- Add a property test if convenient (proptest) asserting `container_tree_hash_root(&block.body) != list_byte_root(block.body)` for arbitrary bodies; not strictly required but cheap.

---

### Issue 4.3: E-2 RED — aggregation Bitlist chunk-count regression test

- **Points:** 2
- **Type:** test
- **Priority:** P0
- **Blocked by:** Phase 3 Task 3.2 (real-committee `aggregation_bits` fixture), Issue 4.2 (tree_hash_utils rewrite landed first)
- **Blocks:** Issue 4.4
- **Scope:** 1 day

**Description:**
Land the spec-vector regression test that proves `bitlist_tree_hash_root` currently merkleizes to `next_power_of_two(bytes)` instead of the SSZ `Bitlist[N]` chunk-count `(N+255)/256`. For `Attestation.aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE=2048]` the correct chunk count is 8. The test must fail RED with a real-committee-size `aggregation_bits` (e.g. 63 bytes covering ~500 validators).

**Implementation Notes:**
- Files likely affected: `crates/eth-types/tests/spec_vector_bitlist.rs` (new), `crates/eth-types/tests/fixtures/aggregate_and_proof_real_committee.ssz`, `crates/eth-types/tests/fixtures/sync_contribution.ssz`.
- Approach: deserialise the `AggregateAndProof` fixture, compute `tree_hash_root()` via the current implementation, assert equality against the fixture's expected hash.
- Watch out for: the test must use a real-committee-size bitlist, not a 1-byte toy fixture. The bug is only observable when the bitlist crosses the `next_power_of_two` boundary differently from the chunk-count boundary.
- New files to create: `crates/eth-types/tests/spec_vector_bitlist.rs`.
- Commit format: `test(eth-types): E-2 — RED test cross-checks AggregateAndProof tree_hash_root with real-committee Bitlist`.

**Acceptance Criteria:**
- [ ] Test with `aggregation_bits` ~63 bytes (real-committee-size) loaded from fixture.
- [ ] Test asserts `aggregate_and_proof.tree_hash_root() == expected_root` — fails on `develop` HEAD.
- [ ] Sync `Contribution` fixture is also covered (per PRD §6.2 minimum coverage).
- [ ] Provenance documented in `crates/eth-types/tests/fixtures/README.md`.
- [ ] Commit message references `E-2`.

**Testing Notes:**
- A small unit test on `bitlist_tree_hash_root` directly (call with synthetic bytes whose `next_power_of_two(bytes)` and chunk-count `(N+255)/256` differ) makes the bug more obvious in the test failure message.

---

### Issue 4.4: E-2 GREEN — const-generic bitlist_tree_hash_root<N>

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** Issue 4.3
- **Blocks:** Issue 4.9 (aggregator depends on correct E-2 root)
- **Scope:** 2 days

**Description:**
Make the RED test from Issue 4.3 pass by rewriting `bitlist_tree_hash_root` as a const-generic `bitlist_tree_hash_root<const N: usize>(bytes: &[u8]) -> Result<Hash256>` using the SSZ chunk-count `(N+255)/256`. Every call site declares its bound: `MAX_VALIDATORS_PER_COMMITTEE = 2048` for attestation; `SYNC_COMMITTEE_SIZE = 512` for sync. Future bitlist additions cannot use a wrong bound silently because the bound is part of the type.

**Implementation Notes:**
- Files likely affected: `crates/eth-types/src/tree_hash_utils.rs`, `crates/eth-types/src/aggregation.rs`.
- Approach:
  1. Replace `bitlist_tree_hash_root(bytes)` with `pub fn bitlist_tree_hash_root<const N: usize>(bytes: &[u8]) -> Result<Hash256, TreeHashError>`.
  2. Chunk count: `(N + 255) / 256`.
  3. Update `aggregation.rs:20` and `:105` call sites to declare `MAX_VALIDATORS_PER_COMMITTEE`.
  4. Find any sync-committee call sites (`SYNC_COMMITTEE_SIZE`) and update.
- Key decisions: const-generic over runtime parameter so call sites are forced to declare a bound at compile time. Trade-off: each consumer must import/declare the const; mitigated by exporting the existing `MAX_VALIDATORS_PER_COMMITTEE` from `eth-types`.
- Watch out for: existing comments referring to `next_power_of_two` — remove.
- Commit format: `fix(eth-types): E-2 — const-generic bitlist_tree_hash_root<N> with SSZ chunk-count`.

**Acceptance Criteria:**
- [ ] RED test from 4.3 passes (GREEN).
- [ ] `bitlist_tree_hash_root` signature is `<const N: usize>(bytes) -> Result<Hash256, _>`.
- [ ] All call sites declare their bound explicitly (`MAX_VALIDATORS_PER_COMMITTEE`, `SYNC_COMMITTEE_SIZE`).
- [ ] `cargo test -p eth-types` green; `cargo clippy -p eth-types -- -D warnings` green.
- [ ] No `next_power_of_two` reference remains in `tree_hash_utils.rs`.
- [ ] Commit message references `E-2`.

**Testing Notes:**
- Add a small unit test with both `N=2048` and `N=512` over the same byte buffer; root differs as expected. Catches future regression where two call sites accidentally use the same wrong bound.

---

### Issue 4.5: B-1/T-1 RED — SignedBlockContents round-trip + bounded kzg_offset

- **Points:** 2
- **Type:** test
- **Priority:** P0
- **Blocked by:** Phase 3 Task 3.3 (Deneb block with ≥1 blob commitment fixture), Phase 1 Task 1.9 (Q7 resolution documented in tracker)
- **Blocks:** Issue 4.6
- **Scope:** 1 day

**Description:**
Land the regression test that proves the Deneb+ SSZ publish path currently splices `kzg_proofs`/`blobs` bytes into the signed `SignedBeaconBlock` (T-1) and that the framing is wrong for `SignedBlockContents` (B-1). Per Q7 resolution from Phase 1 Task 1.9, the RED test may need to invert an existing pinning test; reference the tracker note for the actual landed state.

**Implementation Notes:**
- Files likely affected: `crates/block-service/tests/spec_vector_blockcontents.rs` (new), `crates/block-service/tests/fixtures/`.
- Approach:
  1. Load the Deneb block fixture (≥1 blob commitment).
  2. Drive the propose pipeline to produce the published bytes.
  3. Assert the published bytes (a) are bounded at `kzg_offset` for the inner `SignedBeaconBlock`, AND (b) deserialise as a proper `SignedBlockContents` whose inner block tree-hashes to the signed root.
  4. If existing L-9 ignored tests at `crates/block-service/src/service.rs:2597-2622,2641-2661` pin the bug, invert them (per Research R3 pattern).
- Watch out for: Q7 documentation in tracker. If the bug is partially fixed, the RED test only needs to cover the remaining gap.
- New files to create: `crates/block-service/tests/spec_vector_blockcontents.rs`.
- Commit format: `test(block-service): B-1/T-1 — RED test asserts SignedBlockContents round-trip and kzg bound`.

**Acceptance Criteria:**
- [ ] Test loads the Deneb fixture and runs through the propose pipeline.
- [ ] Asserts published bytes deserialise to `SignedBlockContents`.
- [ ] Asserts inner `SignedBeaconBlock` tree-hashes to the signed root.
- [ ] Fails RED on `develop` HEAD (verified against Q7-documented state).
- [ ] Commit message references `B-1`, `T-1`.

**Testing Notes:**
- Use existing block-service test fixtures + harness if available; otherwise drive `propose_block` with a mock signer.
- A negative-control test (kzg_offset = 0, no blobs) should pass on both RED and GREEN — confirms the change does not regress the non-blob path.

---

### Issue 4.6: B-1/T-1 GREEN — bound published bytes + SignedBlockContents framing

- **Points:** 5
- **Type:** feature
- **Priority:** P0
- **Blocked by:** Issue 4.5
- **Blocks:** Issue 4.7
- **Scope:** 3 days

**Description:**
Make the RED test from Issue 4.5 pass by:
1. Bounding the published `SignedBeaconBlock` bytes at `kzg_offset` so kzg/blob bytes are no longer spliced into the signed block.
2. Serialising Deneb+ payloads as proper `SignedBlockContents` (three variable offsets, then the bounded `SignedBeaconBlock`, then `kzg_proofs`, then `blobs`).

Single atomic GREEN: splitting would leave an inconsistent intermediate. See "Why issue 4.6 is 5 points and not split" in the Risk Flags section above.

**Why this issue is KEPT atomic (adversarial-review confirmation):** bounding at `kzg_offset` AND `SignedBlockContents` framing must land in the same commit. Either change alone produces bytes that fail to deserialise — a bounded `SignedBeaconBlock` without the outer `SignedBlockContents` framing is not a valid Deneb publish payload, and a `SignedBlockContents` envelope around an unbounded (kzg-spliced) block fails the inner round-trip. The 5-point budget is the minimum atomic step; splitting was reviewed and rejected at the pre-review gate.

**Implementation Notes:**
- Files likely affected: `crates/block-service/src/service.rs` (`:287-385,370-382`), `crates/beacon/src/ssz_deser.rs`.
- Approach:
  1. In `block-service::propose_block`, bound the inner `SignedBeaconBlock` bytes at `kzg_offset` before signing/publishing.
  2. Encode the published payload as `SignedBlockContents`: three variable offsets, then bounded `SignedBeaconBlock`, then `kzg_proofs`, then `blobs`.
  3. Update `crates/beacon/src/ssz_deser.rs` to round-trip the new framing (the SSZ deser path used by `propagator`/test must accept the new bytes).
  4. If a Deneb-without-blobs case is hit, the three variable-offsets still apply with empty `kzg_proofs` and `blobs`.
- Key decisions: `SignedBlockContents` framing per Deneb spec (see ethereum/consensus-specs). The bounded block is the only payload that is signed; the kzg/blob bytes are co-published but not signed.
- Watch out for: `crates/propagator` consumers — any code path that publishes the SSZ bytes must handle the new framing. Search `grep -rn "publish_block_ssz" crates/`.
- New files to create: none.
- Commit format: `fix(block-service): B-1/T-1 — bound SignedBeaconBlock at kzg_offset and frame as SignedBlockContents`.

**Acceptance Criteria:**
- [ ] RED test from 4.5 passes (GREEN).
- [ ] Published bytes deserialise to `SignedBlockContents`.
- [ ] Inner `SignedBeaconBlock` tree-hashes to the signed root.
- [ ] Deneb-without-blobs case still publishes successfully (regression).
- [ ] Bellatrix/Capella (pre-Deneb) path unchanged — separate test asserts.
- [ ] `cargo test -p block-service -p beacon` green.
- [ ] Commit message references `B-1`, `T-1`.

**Testing Notes:**
- Run both Deneb-with-blobs and Deneb-without-blobs integration paths.
- A round-trip test (`encode_then_decode` against the spec-vector fixture) is the strongest regression catch.

---

### Issue 4.7: L-9 — un-ignore stale SSZ tests as positive regressions

- **Points:** 1
- **Type:** chore
- **Priority:** P2 (clusters with B-1/T-1)
- **Blocked by:** Issue 4.6, Issue 4.2 (E-1 tree_hash_root rewrite — declared per adversarial review: the previously-ignored tests at `crates/block-service/src/service.rs:2597-2622,2641-2661` assert expected root values; those expected roots are computed from `BeaconBlock::tree_hash_root()`, whose output changes when 4.2 lands the container-helper rewrite. Un-ignoring before 4.2 would either fail with the old (wrong) leaf or pass with the new leaf only if the expected values are recomputed first).
- **Blocks:** —
- **Scope:** 0.5 day

**Description:**
Remove `#[ignore]` annotations from `crates/block-service/src/service.rs:2597-2622,2641-2661` and update their comments. After the B-1/T-1 fix, these tests should pass and serve as positive regression coverage.

**Implementation Notes:**
- Files likely affected: `crates/block-service/src/service.rs`.
- Approach: `grep -n "#\[ignore\]" crates/block-service/src/service.rs`, remove the annotations and the comments referring to the alleged "SSZ body-bleed bug." Re-label the tests as positive regression tests.
- Watch out for: any test relying on specific bytes or roots from the pre-fix behaviour — update or remove.
- Commit format: `test(block-service): L-9 — un-ignore stale SSZ tests as positive regressions`.

**Acceptance Criteria:**
- [ ] No `#[ignore]` annotations remain at the two cited line ranges.
- [ ] Test comments updated to remove the false bug claim.
- [ ] `cargo test -p block-service` green (both previously-ignored tests now run and pass).
- [ ] Commit message references `L-9`.

**Testing Notes:**
- Confirm by `grep -c "#\[ignore\]" crates/block-service/src/service.rs` returning 0 or only legitimate remaining ignores.

---

### Issue 4.8: KG-1 — BLS-to-execution-change uses GENESIS_FORK_VERSION + invert tests

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** Phase 3 Task 3.4 (`staking-deposit-cli` fixture)
- **Blocks:** —
- **Scope:** 2 days

**Description:**
Fix `bin/rvc-keygen/src/bls_to_execution.rs` to build the signing domain with `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, network.genesis_fork_version, network.genesis_validators_root)` per EIP-7044. The existing two tests (`test_bls_to_execution_uses_capella_fork_version`, `test_bls_to_execution_uses_actual_genesis_root`) currently pin the bug and must be **inverted** to assert genesis-version behaviour. Cross-check against the `staking-deposit-cli` fixture.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/bls_to_execution.rs` (`:51-59`, `:144`).
- Approach:
  1. **RED commit:** invert the two existing tests so they assert `GENESIS_FORK_VERSION`. They fail on current `develop`.
  2. **GREEN commit:** replace `capella_fork_version` with `network.genesis_fork_version` in the domain construction.
  3. Cross-check against the Phase 3.4 fixture: produce a `SignedBLSToExecutionChange` and assert signing root + signature match.
- Key decisions: per PRD Assumption #10, prior outputs are invalid; release-notes carry this. No migration tool ships.
- Watch out for: any test fixture that captured the wrong signature — update.
- Commit format: `test(rvc-keygen): KG-1 — invert tests to assert GENESIS_FORK_VERSION` then `fix(rvc-keygen): KG-1 — build BLS-to-execution-change domain with GENESIS_FORK_VERSION`.

**Acceptance Criteria:**
- [ ] Inverted tests (`test_bls_to_execution_uses_genesis_fork_version`, `test_bls_to_execution_uses_actual_genesis_root`) pass after the GREEN commit.
- [ ] Cross-check against `staking-deposit-cli` fixture asserts equal signing root + signature.
- [ ] `cargo test -p rvc-keygen` green.
- [ ] Commit messages reference `KG-1`.

**Testing Notes:**
- The fixture is a `SignedBLSToExecutionChange` produced by `staking-deposit-cli`; commit it under `bin/rvc-keygen/tests/fixtures/` with provenance.
- If `staking-deposit-cli` is unreachable, document the workaround in tracker (Phase 3 fallback).

---

### Issue 4.9: SS-2/SS-3 — sign_aggregate_and_proof skips slashing DB stage

- **Points:** 3
- **Type:** feature
- **Priority:** P0
- **Blocked by:** Phase 2 Task 2.6 (`SigningGate` non-slashable path), Issue 4.4 (E-2: correct bitlist tree-hash for aggregator's signed root), the standing `bin/rvc-signer/tests/signing_path_enumeration.rs` enumeration gate (it asserts the actual routing of `sign_aggregate_and_proof` through `SigningGate`; the GREEN commit here must satisfy that gate, so the gate's enumeration vector must already encode the non-slashable path for the aggregate route — declared explicitly per adversarial review, previously only a phase entry-criterion).
- **Blocks:** Issue 4.10
- **Scope:** 2 days

**Description:**
Fix `bin/rvc-signer/src/service.rs:698-740` so `sign_aggregate_and_proof` no longer runs attestation slashing protection. Move the handler onto `SigningGate`'s non-slashable path (consult the gate, then sign without staging). Add ADR-009 chain-of-custody invariant comment block at the top of the handler stating that the inner Attestation must have been signed via `sign_attestation` first. Add an integration test that verifies the chain-of-custody invariant.

**Implementation Notes:**
- Files likely affected: `bin/rvc-signer/src/service.rs`, `crates/signer/src/non_slashable.rs`, optionally `bin/rvc-signer/tests/aggregate_no_slashing_db.rs` and `crates/signer/tests/chain_of_custody_aggregate.rs`.
- Approach:
  1. **RED commit:** add `bin/rvc-signer/tests/aggregate_no_slashing_db.rs` asserting that after a `sign_aggregate_and_proof` call, **no** attestation row is committed to the slashing DB. Fails on current `develop` because `sign_aggregate_and_proof` currently stages an attestation.
  2. **GREEN commit:** remove `require_db()` / `ScopedSlashingDb` / `stage_attestation` / commit calls from the handler; route through `SigningGate::sign_aggregate_and_proof` (gate-then-sign path).
  3. Add ADR-009 comment block + `crates/signer/tests/chain_of_custody_aggregate.rs` integration test: attest for (source, target) then aggregate for the same target — both succeed; attestation watermark unchanged by the aggregate call.
- Key decisions: ADR-009 chain-of-custody invariant is enforced by integration test, not by code; the comment is the contract documentation.
- Watch out for: the existing `tests/sign_aggregate_v2.rs` (per PRD acceptance criterion) must be updated to assert **no** attestation row is committed. Search the repo for that test file.
- Commit format: `test(rvc-signer): SS-2/SS-3 — RED test asserts aggregate path skips slashing DB`, then `fix(rvc-signer): SS-2/SS-3 — route sign_aggregate_and_proof through SigningGate non-slashable path`.

**Acceptance Criteria:**
- [ ] RED test confirms no attestation row committed by `sign_aggregate_and_proof`.
- [ ] GREEN test confirms gate consulted (returns BlockedByDoppelganger when gate off) but no DB stage.
- [ ] ADR-009 chain-of-custody integration test green: attest then aggregate for same target both succeed; attestation watermark untouched by aggregate.
- [ ] Existing `tests/sign_aggregate_v2.rs` updated per PRD acceptance criterion.
- [ ] `cargo test -p rvc-signer -p signer` green.
- [ ] SS-1 enumeration test (standing CI gate) confirms `sign_aggregate_and_proof` is routed through `SigningGate`.
- [ ] Commit messages reference `SS-2`, `SS-3`.

**Testing Notes:**
- Verify by inspecting `slashing.sqlite` (in-memory test DB) row counts before and after the aggregate call.

---

### Issue 4.10: L-4 — validate_attestation_data on aggregation BN response

- **Points:** 2
- **Type:** feature
- **Priority:** P2 (clusters with SS-2/SS-3)
- **Blocked by:** Issue 4.9, Issue 4.4 (E-2 const-generic `bitlist_tree_hash_root<N>` is required so the aggregation-root validation path computes correct roots against `MAX_VALIDATORS_PER_COMMITTEE`)
- **Blocks:** —
- **Scope:** 1 day

**Description:**
Apply `validate_attestation_data` to the BN's response in `crates/rvc/src/orchestrator/aggregation.rs:130-181` before computing the root and signing. If the BN response is invalid (target epoch beyond fork, malformed root, etc.), skip + warn — never sign.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/orchestrator/aggregation.rs`, validation helper at `crates/rvc/src/orchestrator/validation/attestation_data.rs`.
- Approach:
  1. Find the BN response path that returns `AttestationData`.
  2. Wrap the response in `validate_attestation_data(&data)?` (re-use existing helper from attestation path).
  3. On Err, log + return without signing.
- Key decisions: re-use existing validator; do not duplicate logic.
- Watch out for: missing pubkey / wrong slot in BN response — the existing helper should catch these; verify coverage.
- Commit format: `test(rvc): L-4 — RED test asserts invalid BN response is skipped` then `fix(rvc): L-4 — validate BN AttestationData before aggregating`.

**Acceptance Criteria:**
- [ ] RED test: invalid BN response (e.g. wrong slot) → no signature produced.
- [ ] GREEN: `validate_attestation_data` called before the sign path.
- [ ] `cargo test -p rvc` green.
- [ ] Commit messages reference `L-4`.

**Testing Notes:**
- Mock BN that returns malformed AttestationData; assert orchestrator skips and warns.

---

### Issue 4.11: BN-1 — optimistic BN tier cap + per-response gate

- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Blocked by:** —
- **Blocks:** Issue 4.12
- **Scope:** 2 days

**Description:**
Fix optimistic BNs being treated as fully Synced. Cap an optimistic node's `tier()` at Unsynced for EL-dependent duties. In the orchestrator, reject produce/attestation/duty responses whose `execution_optimistic` is true before signing. Two layers per architecture defense-in-depth.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/sync_status.rs` (`:65-83,155-178`), `crates/rvc/src/orchestrator/coordinator.rs`.
- Approach:
  1. `tier()` returns `Unsynced` when `is_optimistic == true`, regardless of `is_syncing` / `sync_distance`.
  2. In `coordinator.rs`, after the BN call returns, check `execution_optimistic` on the response; if true, reject before signing.
  3. Add a regression test with a mock BN returning `is_optimistic=true, is_syncing=false, sync_distance=0` — node is not selected.
- Key decisions: per architecture defense-in-depth, both checks run independently.
- Watch out for: `BN-2` (next issue) keeps the tier logic coherent — sequence with BN-1 first.
- Commit format: `test(bn-manager): BN-1 — RED test for optimistic-tier classification`, then `fix(bn-manager,rvc): BN-1 — cap optimistic tier and reject optimistic responses`.

**Acceptance Criteria:**
- [ ] RED test: mock BN with `is_optimistic=true` and otherwise-synced status is not selected by `synced_indices`.
- [ ] GREEN: `tier()` returns Unsynced for optimistic; coordinator per-response check rejects optimistic responses.
- [ ] `cargo test -p bn-manager -p rvc` green.
- [ ] Commit messages reference `BN-1`.

**Testing Notes:**
- Two separate tests: one at `bn-manager::tier()` boundary; one at `coordinator` per-response boundary.

---

### Issue 4.12: BN-2 — startup-window unknown-tier handling

- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** Issue 4.11
- **Blocks:** —
- **Scope:** 1 day

**Description:**
Before the first sync poll, all BNs are `Unknown` and currently fall through `synced_indices` as if synced. Either run a synchronous `check_sync_status()` before serving duties, or treat `Unknown` distinctly so `synced_indices` does not fall through to Unknown nodes until at least one poll succeeds.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/sync_status.rs` (`:90-92,65-67`), `crates/bn-manager/src/manager.rs` (`:257-338`).
- Approach: pick one strategy (per architecture, the "Unknown treated distinctly" approach is preferred because it avoids a startup latency hit).
  1. Add an `Unknown` variant that is excluded from `synced_indices`.
  2. After at least one poll, the variant transitions; until then, `synced_indices` returns empty (caller falls back to other selection logic or waits).
- Key decisions: align with BN-1's tier logic in one churn pass (DL-7).
- Commit format: `test(bn-manager): BN-2 — RED test for startup-window Unknown handling`, then `fix(bn-manager): BN-2 — treat Unknown distinctly in synced_indices`.

**Acceptance Criteria:**
- [ ] RED test: at startup before any poll, `synced_indices` returns empty (or a documented sentinel); BNs are not selected as synced.
- [ ] GREEN: Unknown is no longer treated as Synced; after a successful poll, the BN transitions to the correct tier.
- [ ] `cargo test -p bn-manager` green.
- [ ] Commit messages reference `BN-2`.

**Testing Notes:**
- Pair with a mock that delays the first poll; assert orchestrator does not produce duties against unknown-tier BNs.

---

### Issue 4.13: DT-1 — runtime-mutable validator_indices in duty-tracker

- **Points:** 2
- **Type:** feature
- **Priority:** P1
- **Blocked by:** —
- **Blocks:** Issue 4.15
- **Scope:** 1 day

**Description:**
`validator_indices` is currently frozen at construction; runtime-imported validators never get duties. Store the list behind `RwLock<Vec<String>>` (or `ArcSwap`) with an `update_validator_indices` setter. The setter is called by the keymanager import/delete path (wired in Issue 4.15).

**Implementation Notes:**
- Files likely affected: `crates/duty-tracker/src/tracker.rs` (`:63-82,91-95,181-185,297-301,419-423`).
- Approach:
  1. Wrap `validator_indices` in `RwLock<Vec<String>>` (or `ArcSwap` if read-mostly).
  2. Add `pub fn update_validator_indices(&self, new: Vec<String>)`.
  3. Update read sites to acquire the lock / load.
- Key decisions: `RwLock` is simpler; `ArcSwap` is faster but adds a tiny dep churn — `RwLock` is the default choice.
- Watch out for: lock-held-across-await deadlocks in async contexts — keep the locked section short.
- Commit format: `test(duty-tracker): DT-1 — RED test asserts setter updates index list`, then `fix(duty-tracker): DT-1 — RwLock<Vec<String>> + update_validator_indices setter`.

**Acceptance Criteria:**
- [ ] RED test: construct tracker; call `update_validator_indices(new)`; assert next read returns `new`.
- [ ] GREEN: setter implementation; all read sites updated.
- [ ] `cargo test -p duty-tracker` green; no deadlocks under `tokio::test`.
- [ ] Commit messages reference `DT-1`.

**Testing Notes:**
- Property test optional: any sequence of `update` + read returns the most recent value.

---

### Issue 4.14: C-1 — borrow_and_update on key_gen_rx in orchestrator

- **Points:** 1
- **Type:** bug
- **Priority:** P1
- **Blocked by:** —
- **Blocks:** Issue 4.15
- **Scope:** 0.5 day

**Description:**
`key_gen_rx.has_changed()` is used without consuming the signal; either it never fires (production) or it re-clears every slot (when wired). Use `borrow_and_update()` (or drive via `select!` on `changed()`). Wired together with S-2 (next issue) so a single import → exactly one `clear_cache()`.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/orchestrator/coordinator.rs` (`:317-320,147,181,211,278`).
- Approach: replace `has_changed()` with `borrow_and_update()` — or refactor to `select!` if the orchestrator loop allows.
- Key decisions: `borrow_and_update` is the minimal edit; refactor to `select!` is out of scope unless it falls out naturally.
- Commit format: `test(rvc): C-1 — RED test asserts single import triggers exactly one clear_cache`, then `fix(rvc): C-1 — borrow_and_update on key_gen_rx`.

**Acceptance Criteria:**
- [ ] RED test: simulate import (push signal); assert `clear_cache()` runs once and not again on next slot.
- [ ] GREEN: `borrow_and_update()` used; signal consumed.
- [ ] `cargo test -p rvc` green.
- [ ] Commit messages reference `C-1`.

**Testing Notes:**
- Combined with S-2 (4.15) the full path is testable; standalone, this issue tests the signal-consumption semantics.

---

### Issue 4.15: S-2 — wire key_gen channel + pubkey_map into adapters and orchestrator

- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Blocked by:** Issues 4.13, 4.14
- **Blocks:** Issue 4.16
- **Scope:** 2 days

**Description:**
Today the keymanager-imported keystores/remote keys are never added to the orchestrator's `pubkey_map`; the throwaway `key_gen_tx` is dropped. Create a real `(key_gen_tx, key_gen_rx)` channel, pass `pubkey_map.clone()` / `key_gen_tx.clone()` to both adapters via `.with_pubkey_map(...)`, and build the orchestrator with `new_with_key_gen(..., key_gen_rx, ...)`.

**Implementation Notes:**
- Files likely affected: `bin/rvc/src/main.rs` (`:1432-1435,1467-1470,1522-1536`), `crates/rvc/src/keymanager_adapters.rs` (`:46-54,442-450`), `crates/rvc/src/orchestrator/coordinator.rs` (`:167-197`), `crates/rvc/src/orchestrator/utils.rs` (`:198-227`).
- Approach:
  1. In `bin/rvc/src/main.rs` construct real `(key_gen_tx, key_gen_rx)` channel (`tokio::sync::watch::channel(())`).
  2. Pass `pubkey_map.clone()` + `key_gen_tx.clone()` to both keystore and remote-key adapters via `.with_pubkey_map(...)` / `.with_key_gen_tx(...)`.
  3. Build orchestrator via `new_with_key_gen(..., key_gen_rx, ...)`.
  4. Verify the adapter side actually inserts the pubkey on import + sends the signal.
- Key decisions: tokio `watch` channel is the existing pattern; do not introduce broadcast/mpsc unless required.
- Watch out for: `pubkey_map` clones must be `Arc<RwLock<...>>` to share write access. Verify the existing type and clone semantics.
- Commit format: `fix(rvc): S-2 — wire real key_gen channel and pubkey_map through keymanager adapters`.

**Acceptance Criteria:**
- [ ] After API import, `pubkey_map` contains the new pubkey.
- [ ] After API import, `key_gen_rx` receives a signal.
- [ ] Orchestrator clears cache once on the signal (via C-1 from 4.14).
- [ ] Compile-time: `bin/rvc/src/main.rs` no longer has a throwaway `key_gen_tx`.
- [ ] `cargo test -p rvc` green; new test in 4.16 covers e2e.
- [ ] Commit messages reference `S-2`.

**Testing Notes:**
- Use the existing keymanager adapter test fixtures; assert side effects on `pubkey_map`.

---

### Issue 4.16: Runtime-import end-to-end integration test (PRD M7)

- **Points:** 3
- **Type:** test
- **Priority:** P1
- **Blocked by:** Issue 4.15, Phase 2 Task 2.7 (KM-2 doppelganger-cancel coherence on import/delete), Phase 2 ForwardWindowMachine (e2e asserts a valid signature is produced *after* the doppelganger window expires, so the machine must be shipped and reachable from the orchestrator test harness)
- **Blocks:** —
- **Scope:** 2 days

**Description:**
Drive `POST /eth/v1/keystores` against an in-process keymanager + orchestrator; assert the imported pubkey appears in the duty fetch on the next refresh, the orchestrator selects it, and the signing path produces a valid signature within the configured doppelganger window expiry. This is the PRD M7 acceptance test for the runtime-import end-to-end loop.

**Implementation Notes:**
- Files likely affected: `crates/keymanager-api/tests/runtime_import_e2e.rs` (new), or `crates/rvc/tests/`.
- Approach:
  1. Build an in-process keymanager-API + orchestrator using existing test harness.
  2. Mock BN to serve duties on demand.
  3. Drive `POST /eth/v1/keystores` with a synthetic keystore.
  4. Tick the orchestrator slot loop.
  5. Assert: duty fetched for the new pubkey, doppelganger window completes, signing path returns a signature.
- Key decisions: use a short `monitoring_epochs` (e.g. 1) for test speed; document the override.
- Watch out for: doppelganger window can be slow if not configurable in tests; check `ForwardWindowMachine` config.
- Commit format: `test(rvc): M7 — runtime keymanager import e2e integration test`.

**Acceptance Criteria:**
- [ ] Test posts a keystore via the keymanager API.
- [ ] Asserts `pubkey_map` contains the new pubkey.
- [ ] Asserts the next duty fetch includes the new validator index.
- [ ] Asserts a valid signature is produced after the doppelganger window expires.
- [ ] `cargo test -p rvc --test runtime_import_e2e` green.
- [ ] Commit message references `M7`, `DT-1`, `S-2`, `C-1`, `KM-2`.

**Testing Notes:**
- Use a deterministic clock or time-warp shim if available; otherwise short `monitoring_epochs` and a real `sleep`.
- Flake-prevention: re-run 10x locally to confirm stability.

---

### Issue 4.17: S-5 — sync-committee head_root via get_block_root("head") with fallback

- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Blocked by:** — (parallel-safe with 4.11 / 4.12 — see Ordering note below)
- **Blocks:** —
- **Scope:** 1 day

**Ordering note (adversarial review):** the Implementation Notes call out BN-1/BN-2 tier interactions because the head fetch goes through the same tier-aware BN selection. This is **not** a hard build-time dependency: S-5 changes a single call site (`get_block_root(slot_id)` → `get_block_root("head")` with fallback) inside `sync_committee.rs`/`slot_context.rs`, and BN-1/BN-2 change `bn-manager`'s tier classification and coordinator response gating. The two diffs do not overlap. Required ordering: **S-5 may land in any order relative to 4.11 / 4.12**, but its acceptance test must mock the tier behaviour expected after 4.11+4.12 land (i.e. the mock BN serving `head` must be a fully Synced, non-optimistic node) so the test does not silently rely on the pre-BN-1 optimistic-as-Synced behaviour. If 4.17 lands first, the mock encodes "Synced & non-optimistic" explicitly; if 4.11+4.12 land first, the mock falls out naturally. Either ordering is correct; no hard `Blocked by` edge is needed.

**Description:**
Sync-committee `head_root` is currently captured via slot-qualified `get_block_root(N)` at t=0 — but block N does not exist yet. Capture via `get_block_root("head")`, or fall back to slot N-1 when slot N has no block. With a mock BN returning 404 for the current slot's `block_id`, sync messages/contributions should still be produced.

**Implementation Notes:**
- Files likely affected: `crates/rvc/src/orchestrator/slot_context.rs` (`:40-60`), `crates/rvc/src/orchestrator/sync_committee.rs` (`:62-71,145-154`).
- Approach: change `get_block_root(slot_id)` to `get_block_root("head")` — or on 404 fall back to `slot - 1`.
- Key decisions: `"head"` is the spec-preferred query; the fallback is defensive.
- Watch out for: BN-1 / BN-2 (optimistic + Unknown tier) interactions — make sure the head fetch goes through the same tier-aware selection.
- Commit format: `test(rvc): S-5 — RED test for missing slot N block`, then `fix(rvc): S-5 — capture head_root via head query with fallback`.

**Acceptance Criteria:**
- [ ] RED test: mock BN returns 404 for current slot's `block_id`; sync messages currently not produced.
- [ ] GREEN: sync messages still produced via `head` or fallback.
- [ ] `cargo test -p rvc` green.
- [ ] Commit messages reference `S-5`.

**Testing Notes:**
- Mock BN that returns 404 on `block_id = N` but 200 on `head` or `N-1`.

---

### Issue 4.18: SSE-1 — SSE consumer task re-created on reconnect / panic-isolated

- **Points:** 3
- **Type:** bug
- **Priority:** P1
- **Blocked by:** —
- **Blocks:** —
- **Scope:** 2 days

**Description:**
After an SSE callback panic, the consumer task is never re-created; all future events are silently dropped. Create the channel + consumer task **inside** the reconnect path (so a reconnect re-creates both), or wrap the callback in `catch_unwind` so a callback panic does not kill the consumer.

**Implementation Notes:**
- Files likely affected: `crates/bn-manager/src/sse.rs` (`:173-178,297-307`).
- Approach: pick one of the two strategies. The `catch_unwind` strategy is less invasive.
  1. Wrap each callback invocation in `std::panic::catch_unwind(AssertUnwindSafe(|| (cb)(event)))`.
  2. Or move channel + consumer task construction inside the reconnect loop body.
- Key decisions: `catch_unwind` requires the callback to be `RefUnwindSafe` or `AssertUnwindSafe`; verify the trait bounds.
- Watch out for: existing SSE-1 tests may assert "second TCP connection only" — per PRD acceptance criterion, remove that assertion.
- Commit format: `test(bn-manager): SSE-1 — RED test asserts delivery resumes after callback panic`, then `fix(bn-manager): SSE-1 — wrap SSE callback in catch_unwind`.

**Acceptance Criteria:**
- [ ] RED test: a callback panics; current implementation drops subsequent events.
- [ ] GREEN: delivery resumes; second event after the panic reaches the callback.
- [ ] Existing "second TCP connection only" assertion removed from any prior SSE tests.
- [ ] `cargo test -p bn-manager` green.
- [ ] Commit messages reference `SSE-1`.

**Testing Notes:**
- Use a callback that panics on the first event but not subsequent ones; assert subsequent events arrive.

---

### Issue 4.19: GVR-1 — canonical GVR comparison in slashing::import

- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Blocked by:** Phase 3 Task 3.5 (canonical promotion)
- **Blocks:** Issue 4.20
- **Scope:** 1 day

**Description:**
`slashing::import()` compares `genesis_validators_root` by raw string equality while the pinned GVR is normalised; this leads to two inconsistent schemes. Normalise both sides through `eth-types::canonical::parse_gvr_hex` / `eq_gvr` so a 0x-prefixed, mixed-case interchange compares equal against a stripped, lowercased pinned value for the same chain.

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (`:950-955,1562-1585,292-312`), `crates/slashing/src/startup.rs` if present (`:100-116`), and likely a new `crates/slashing/src/import.rs` per architecture module layout. Check current structure first.
- Approach:
  1. In `import()` (and any sibling GVR-comparison sites), call `canonical::eq_gvr(interchange_gvr_str, &pinned_gvr_bytes)`.
  2. Remove raw `==` comparisons against the raw interchange string.
- Key decisions: `eth-types::canonical::eq_gvr` is the single source of truth per Phase 3.5.
- Watch out for: any other site that compares GVR strings — `grep -rn "genesis_validators_root" crates/slashing/src/`.
- Commit format: `test(slashing): GVR-1 — RED test for mixed-case + 0x-prefix interchange comparison`, then `fix(slashing): GVR-1 — canonical GVR comparison via eq_gvr`.

**Acceptance Criteria:**
- [ ] RED test: import an interchange with a `0xABCD...` GVR against a pinned `abcd...` GVR — currently rejected.
- [ ] GREEN: same test passes; same chain compares equal.
- [ ] `cargo test -p slashing` green.
- [ ] Commit messages reference `GVR-1`.

**Testing Notes:**
- Cover four cases: same chain with (a) different case, (b) different `0x` prefix, (c) both, (d) genuinely different chain (must still reject).

---

### Issue 4.20: IMP-1 — reject source>target + record conflicting-root rows

- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Blocked by:** Issue 4.19, Phase 2 Task 2.3 (DVT-1+CN-1 `crates/slashing/src/db.rs` schema change — IMP-1's conflicting-root detection queries against the same WHERE-clause keying that Phase 2.3 reshapes; declared as a hard rebase dependency per adversarial review, previously only documented in "Watch out for").
- **Blocks:** —
- **Scope:** 2 days

**Description:**
`slashing::import()` does not validate `source_epoch <= target_epoch`; also, the `INSERT OR IGNORE` indices exclude `signing_root`, silently dropping conflicting-root rows. Reject `source > target` as `InvalidInterchangeFormat`. Before each `INSERT OR IGNORE`, detect an existing row at the same key with a differing `signing_root` and record it as a slashable-history marker (or raise the watermark).

**Implementation Notes:**
- Files likely affected: `crates/slashing/src/db.rs` (`:960-995,634-638`), `crates/slashing/src/import.rs` (new per architecture).
- Approach:
  1. **RED commit (inverted pair):** test that import of an interchange with `source > target` succeeds today — must fail RED. Add expectation that it returns `InvalidInterchangeFormat`.
  2. **RED commit (conflicting root):** test that a second `INSERT OR IGNORE` of a row with the same key but different `signing_root` is silently ignored today — assert it raises the watermark instead.
  3. **GREEN commit:**
     - Before parsing, validate every block/attestation row: `source <= target`. Reject the whole interchange on violation.
     - Before `INSERT OR IGNORE`, query for an existing row with the same `(pubkey, gvr, slot)` (blocks) or `(pubkey, gvr, target_epoch)` (attestations) and a *different* `signing_root`; mark it as a slashable-history marker.
- Key decisions: per PRD acceptance criterion, either raise the watermark or record a marker; pick one and document. The architecture row-pair resolution table prefers the marker.
- Watch out for: Phase 2 Task 2.3 (DVT-1+CN-1) also touched `db.rs` schema; ensure no merge conflict with the WHERE-clause keying change.
- Commit format: separate RED commits per case; GREEN commit covers both.

**Acceptance Criteria:**
- [ ] RED test 1: inverted pair (`source > target`) currently accepted — RED. GREEN: rejected as `InvalidInterchangeFormat`.
- [ ] RED test 2: conflicting-root second insert currently silent — RED. GREEN: watermark raised or marker recorded.
- [ ] `cargo test -p slashing` green.
- [ ] Commit messages reference `IMP-1`.

**Testing Notes:**
- Property test optional: any interchange with `source > target` is always rejected.

---

### Issue 4.21: KG-2 — keygen self-verification failure is hard error

- **Points:** 2
- **Type:** bug
- **Priority:** P1
- **Blocked by:** —
- **Blocks:** —
- **Scope:** 1 day

**Description:**
Currently keystore self-verification failure (`FAILED`/`MISMATCH`) is logged but ignored; deposit data is still written and the process exits 0. Treat `FAILED`/`MISMATCH` as a hard error: return `Err` before writing deposit data, or skip deposit-data emission and delete the bad keystore so the process exits non-zero.

**Implementation Notes:**
- Files likely affected: `bin/rvc-keygen/src/new_mnemonic.rs` (`:182-220`).
- Approach:
  1. After verification step, on `FAILED`/`MISMATCH` return `Err(KeygenError::SelfVerifyFailed)`.
  2. Do not write `deposit_data-*.json` for the affected validator.
  3. Either delete the bad keystore or leave it but log clearly that it is not paired with deposit data.
- Key decisions: per PRD acceptance criterion, either fail before writing or skip+delete. Choose fail-before-writing as simpler.
- Watch out for: existing tests that asserted the lenient behaviour — update.
- Commit format: `test(rvc-keygen): KG-2 — RED test asserts verification failure aborts with non-zero exit`, then `fix(rvc-keygen): KG-2 — return Err on self-verification mismatch`.

**Acceptance Criteria:**
- [ ] RED test: inject a verification failure; current process writes deposit data and exits 0.
- [ ] GREEN: process exits non-zero; no `deposit_data-*.json` written for the affected validator.
- [ ] `cargo test -p rvc-keygen` green.
- [ ] Commit messages reference `KG-2`.

**Testing Notes:**
- Inject failure via mocking the verifier function; assert exit code and absence of deposit-data file.

---

### Issue 4.22: EXIT-1 — voluntary exit cross-checks effective GVR against BN

- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Blocked by:** Phase 3 Task 3.5 (canonical GVR helper — both EXIT-1 and 4.19 (GVR-1) consume `eth-types::canonical::eq_gvr` from Phase 3.5).
- **Blocks:** —
- **Scope:** 2 days

**Ordering relative to 4.19 (GVR-1, adversarial review):** both issues consume `eth-types::canonical::eq_gvr` via the Phase 3.5 canonical promotion, and both touch *different* consumer crates (4.19 → `crates/slashing/src/`, 4.22 → `bin/rvc/src/commands/`). There is **no hard ordering** between 4.19 and 4.22 once Phase 3.5 is in. They may land in either order; both depend solely on Phase 3.5's API surface (`eth-types::canonical::{parse_gvr_hex, eq_gvr}`). The single rebase risk is if Phase 3.5's API signature changes between 4.19 landing and 4.22 landing — mitigated because Phase 3.5's API is frozen at its own GREEN commit. Documented ordering: 4.19 first by execution-plan convention (Day 27 vs Days 31-32) but no build-time edge.

**Description:**
Exit subcommands currently sign with an unvalidated GVR (defaults to Mainnet). Fetch `get_genesis()` from the connected BN and verify the effective GVR (and genesis time) before signing. Fail closed on mismatch with a clear error.

**Implementation Notes:**
- Files likely affected: `bin/rvc/src/commands/voluntary_exit.rs` (`:93-142`), `bin/rvc/src/commands/prepare_exit.rs` (`:76-125`).
- Approach:
  1. Before computing the signing domain, call `beacon.get_genesis().await?`.
  2. Compare returned `genesis_validators_root` against (a) `--genesis-validators-root` if user supplied, (b) the network's hardcoded GVR if `--network` supplied.
  3. On mismatch, return Err with a clear message.
- Key decisions: per PRD §6.3 fail-closed.
- Watch out for: BN must be reachable; per PRD §12 release notes call out the new precondition.
- Commit format: `test(rvc): EXIT-1 — RED test asserts mismatched GVR fails closed`, then `fix(rvc): EXIT-1 — cross-check effective GVR via beacon.get_genesis`.

**Acceptance Criteria:**
- [ ] RED test: exit against a non-mainnet BN without `--network`/`--genesis-validators-root` succeeds today (default Mainnet GVR) — RED.
- [ ] GREEN: same case fails with clear error citing GVR mismatch.
- [ ] If user passes `--genesis-validators-root` matching the BN, the command succeeds.
- [ ] `cargo test -p rvc` green.
- [ ] Commit messages reference `EXIT-1`.

**Testing Notes:**
- Mock BN that returns a specific genesis fixture; drive the CLI command with and without `--genesis-validators-root`.

---

### Issue 4.23: BLD-1 — builder registration refresh cadence

- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Blocked by:** —
- **Blocks:** —
- **Scope:** 2 days

**Description:**
Builder validator registrations are currently cached by content and never refreshed; relays drop them after expiry. Re-register on a bounded cadence regardless of content change (per-pubkey last-submitted timestamp inside relay TTL, or unconditional resubmit each epoch as within-epoch dedup). Refresh the embedded `timestamp` each time.

**Implementation Notes:**
- Files likely affected: `crates/builder/src/service.rs` (`:88-106,215-227`).
- Approach:
  1. Add per-pubkey last-submitted timestamp to the in-memory cache.
  2. On each tick (epoch / configurable cadence), find pubkeys whose last-submitted timestamp is older than `relay_ttl - margin` and re-register.
  3. Refresh the embedded `timestamp` field each submission.
- Key decisions: cadence configurable (default to ≈ relay TTL minus safety margin).
- Watch out for: registrations have a signature — re-signing is required for the refresh, so verify `BuilderRegistration` signing path.
- Commit format: `test(builder): BLD-1 — RED test asserts unchanged registration re-sent before TTL`, then `fix(builder): BLD-1 — bounded refresh cadence with timestamp refresh`.

**Acceptance Criteria:**
- [ ] RED test: unchanged `(fee_recipient, gas_limit)` validator currently not re-registered after TTL.
- [ ] GREEN: same validator re-registered before TTL elapses.
- [ ] Embedded `timestamp` is refreshed on each submission.
- [ ] `cargo test -p builder` green.
- [ ] Commit messages reference `BLD-1`.

**Testing Notes:**
- Use a virtual clock or `tokio::time::pause()` to fast-forward; assert refresh happens within configured cadence.

---

### Issue 4.24: SYNC-1 — validate BN-returned contribution fields

- **Points:** 2
- **Type:** bug
- **Priority:** P2 (in M2 per architecture order)
- **Blocked by:** —
- **Blocks:** —
- **Scope:** 1 day

**Description:**
`produce_contributions` does not validate BN-returned `subcommittee_index` / `slot` / `beacon_block_root` against requested values. Validate on every response; skip + warn on mismatch — never sign a contribution that does not match the request.

**Implementation Notes:**
- Files likely affected: `crates/sync-service/src/lib.rs` (`:251-260`), `crates/rvc/src/orchestrator/sync_committee.rs` (`:208-243`).
- Approach:
  1. After the BN call returns, compare `subcommittee_index` / `slot` / `beacon_block_root` against requested values.
  2. On mismatch, log + skip; do not call the sign path.
- Key decisions: fail-closed; never trust the BN to echo the request correctly.
- Watch out for: existing tests that assume the BN echoes — update if needed.
- Commit format: `test(sync-service): SYNC-1 — RED test for mismatched BN contribution`, then `fix(sync-service): SYNC-1 — validate BN contribution fields against request`.

**Acceptance Criteria:**
- [ ] RED test: mock BN returns mismatched contribution; current code signs.
- [ ] GREEN: same case skipped with a warn log; no signature.
- [ ] `cargo test -p sync-service -p rvc` green.
- [ ] Commit messages reference `SYNC-1`.

**Testing Notes:**
- Mock BN returns three flavours of mismatch (slot, subcommittee_index, beacon_block_root); each path skips.

---

### Issue 4.25: KS-1 — effective-cost gate on keystore params before decrypt

- **Points:** 3
- **Type:** feature
- **Priority:** P1
- **Blocked by:** —
- **Blocks:** —
- **Scope:** 2 days

**Description:**
Current Scrypt/PBKDF2 parameter ceiling permits ~8 GiB single-allocation DoS from untrusted keystore import. Reject when `n.saturating_mul(r).saturating_mul(128)` exceeds a hard cap (~1 GiB). Align per-field maxima to EIP-2335 defaults (n=2^18, r=8). Apply the effective-cost gate **before** decrypt on the import path. Correct the memory-estimate helper.

**Implementation Notes:**
- Files likely affected: `crates/crypto/src/keystore.rs` (`:41-44,198-251`), `crates/keymanager-api/src/keymanager_adapters.rs` (`:185-190`).
- Approach:
  1. Add `pub fn estimate_memory(n: u64, r: u64) -> u64 { n.saturating_mul(r).saturating_mul(128) }`.
  2. Define `pub const KEYSTORE_MAX_MEMORY_BYTES: u64 = 1 * 1024 * 1024 * 1024;`.
  3. Reject keystores at parse/decrypt time when `estimate_memory(n, r) > KEYSTORE_MAX_MEMORY_BYTES`.
  4. Per-field caps: n ≤ 2^18, r ≤ 8.
  5. Wire into `crates/keymanager-api/src/keymanager_adapters.rs` so the gate runs **before** decrypt at the import API path.
- Key decisions: "before decrypt" means the gate runs on the raw keystore JSON's params field, not after the user-supplied password is consumed.
- Watch out for: existing happy-path tests using non-default params — verify they stay under the cap.
- Commit format: `test(crypto,keymanager-api): KS-1 — RED test for oversized keystore params`, then `fix(crypto,keymanager-api): KS-1 — effective-cost gate before decrypt`.

**Acceptance Criteria:**
- [ ] RED test: a keystore at `n=4194304, r=16` is currently accepted at the import API.
- [ ] GREEN: same keystore rejected immediately, before decrypt, with a clear error.
- [ ] Per-field caps enforced (n ≤ 2^18, r ≤ 8).
- [ ] Memory-estimate helper corrected.
- [ ] `cargo test -p crypto -p keymanager-api` green.
- [ ] Commit messages reference `KS-1`.

**Testing Notes:**
- Construct an oversized keystore JSON in-memory; assert rejection at the import API boundary.
