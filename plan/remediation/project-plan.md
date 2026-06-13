# Project Plan: rs-vc Security & Correctness Remediation

**Owner:** rs-vc engineering
**Date:** 2026-06-13
**Status:** Draft, pre-review
**PRD:** `plan/remediation/prd.md` (46 findings: 1 Critical / 13 High / 13 Medium / 14 Low / 5 Info)
**Architecture:** `plan/remediation/architecture.md` (8 shared seams, level-graded DAG, 13 ADRs)
**Research:** `plan/remediation/research/00-overview.md`

---

## Summary

This plan operationalises the architecture's Rollout & Sequencing into six phases, aligned to the PRD's three milestones M1 (slashing-safety floor) / M2 (duty-correctness floor) / M3 (hardening + P2). Each milestone splits into (a) a **shared pre-work phase** that lands the seams, traits, fixtures, and gating checks the milestone's per-finding fixes consume, then (b) a **fixes phase** that lands one-finding-per-branch RED→GREEN→REFACTOR work in the architecture's prescribed order. **Release gate (resolved at the plan review, DL-5): P0 + ALL P1.** P0 closes at Phase 4 exit, but the four P1 findings the architecture defers to Phase 6 (URL-1, URL-2, KM-3, VS-1) must also land before release — so the release is cut after **Phase 6 Task 6.4**, not at Phase 4 exit. Only the pure-P2 Lows/Info (Tasks 6.5–6.18) are the deferrable tail per PRD §11.

The critical path runs through the centralised `signer::SigningGate` and `doppelganger::ForwardWindowMachine`: every M1 fix from D-3 onward depends on the SigningEnablement / SlashingDbReader traits landing in Phase 1, and every aggregator-correctness or runtime-import fix in M2 inherits the gate that Phase 2 ships. The hardest sequencing risks are the DVT-1/CN-1 schema migration (depends on confirming Q3 + capturing a pre-migration DB fixture) and the B-1/T-1 RED test (depends on resolving Q7 by running `cargo test -- --ignored` first).

---

## Prerequisites

Before Phase 1 starts, the following must be in place:

- The three approved artifacts (PRD, architecture, research overview) are merged on `develop` or the active feature branch.
- `develop` builds clean: `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` all green.
- The remediation tracker file `plan/remediation/tracker.md` is created (PRD §6.6) with one row per finding, initial state `Open`.
- Branch-naming convention agreed: `fix/<ID>-<short-slug>`, cluster branches per PRD §7.1 only where GREEN diffs literally overlap.
- Workspace dependency edge `signer → doppelganger` reviewed for cycle impact (architecture DAG already shows it is acyclic; the `tests/architecture_no_cycles.rs` gate is the standing enforcement).
- Reviewer Approve workflow agreed for P0 PRs (PRD §6.5).
- FF-only merge policy on `develop` confirmed (rebase feature branch onto `develop`, then `git merge --ff-only`).
- CI matrix on each fix branch runs the four-gate suite (build/test/clippy -D warnings/fmt) plus `tests/architecture_no_cycles.rs` and (once landed) the `signer-registry` enumeration test.

---

## Phase 1: M1 Shared Pre-Work — Slashing-Safety Seams & Traits

**Goal:** Land the traits, dep edges, and standing test gates that every M1 fix consumes, with zero behavior change on `develop`. Resolve M1-gating open questions (Q3, Q7) before per-finding fixes start.

**Duration estimate:** Small-Medium.

**Entry criteria:**
- Prerequisites above all satisfied.
- Tracker file initialised.

**Work items (no finding IDs — all pre-work; lands on `prep/M1-shared`):**

- [ ] Task 1.1 — Add `crates/eth-types::canonical` module skeleton (PubkeyHex, GvrHex, SigningRootHex newtypes + `parse_*` helpers); zero consumers.
  - Dependencies: none.
  - Complexity: low.
  - ADR ref: ADR-006.
- [ ] Task 1.2 — Add `crates/eth-types::insecure::InsecureGate` enum + `from_env` / `evaluate` helpers; zero consumers.
  - Dependencies: none.
  - Complexity: low.
  - ADR ref: ADR-003.
- [ ] Task 1.3 — Add `crates/signer::SigningEnablement` trait + `FailClosedDefault` trait; zero implementors.
  - Dependencies: none.
  - Complexity: low.
  - ADR ref: ADR-001, PRD §6.3.
- [ ] Task 1.4 — Add `crates/slashing::SlashingDbReader` read-only trait; existing `SlashingDb` implements it.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 1.5 — Add the `signer → doppelganger` Cargo dependency edge in `crates/signer/Cargo.toml`; verify `tests/architecture_no_cycles.rs` stays green.
  - Dependencies: Task 1.3.
  - Complexity: low.
- [ ] Task 1.6 — Author `tests/architecture_no_cycles.rs` (or extend if present) to parse `cargo metadata` and assert the level-graded DAG forbids the documented edges (`slashing → doppelganger`, `signer → keymanager-api`, `eth-types → anything`).
  - Dependencies: Task 1.5.
  - Complexity: medium.
- [ ] Task 1.7 — Add `crates/signer-registry` (dev-dependency-only) skeleton; will be populated with the SS-1 enumeration test in Phase 2.
  - Dependencies: none.
  - Complexity: low.
  - ADR ref: ADR-010.
- [ ] Task 1.8 — **Resolve PRD Q3** (production on-disk slashing DBs): poll operators / inspect deployment configs; if any exist, capture an anonymised pre-migration `slashing.sqlite` fixture into `crates/slashing/tests/fixtures/migration_v1.sqlite` and document provenance.
  - Dependencies: none.
  - Complexity: medium (operator coordination).
  - Gates: blocks Phase 2 Task DVT-1+CN-1 (cannot ship migration without a regression fixture).
- [ ] Task 1.9 — **Resolve PRD Q7 / Research R2**: run `cargo test -- --ignored` on `develop` and document the actual landed state of the B-1/T-1 / L-9 fix path. Record findings in tracker so the Phase 4 RED test for B-1/T-1 inverts a bug-pinning test (per Research R3 KG-1 pattern, transferred where applicable) rather than asserting already-green behavior.
  - Dependencies: none.
  - Complexity: low.
  - Gates: blocks Phase 4 Task B-1/T-1 RED test.

### Phase Exit Criteria

- `prep/M1-shared` merged FF-only to `develop`; CI green.
- `tests/architecture_no_cycles.rs` is a standing CI gate.
- All four traits compile with zero consumers; no behavior change observable in any existing test.
- Q3 resolved: either confirmed no production DBs (record in tracker, skip fixture) or pre-migration fixture committed.
- Q7 resolved: B-1/T-1 actual state documented in tracker.
- Tracker updated: each finding row notes which seam/trait it will consume.

---

## Phase 2: M1 Fixes — Slashing-Safety Floor

**Goal:** Close all 9 M1 findings (SS-1, KM-1, DVT-1+CN-1, D-1, D-2, D-3, KM-2, S-3). After this phase: no signing path on `rvc-signer` bypasses EIP-3076; doppelganger forward window is enforced at every signing entry point; DVT and non-DVT slashing namespacing scoped pubkey-only. Satisfies PRD M4 + M6.

**Duration estimate:** Large.

**Entry criteria:**
- Phase 1 complete (all four traits + dep edge + architecture-no-cycles gate landed on `develop`).
- Q3 + Q7 resolved.

**Work items (one finding per branch unless PRD §7.1 cluster overlaps; ordered per architecture Rollout & Sequencing M1 table):**

- [ ] Task 2.1 — **SS-1** (Critical, P0): `fix/SS-1-remove-v1-raw-root`. Unregister v1 raw-root `sign(signing_root, pubkey)` from the live listener; keep handler compiled returning `Status::unimplemented` per ADR-010; bind only via separately-bound off-by-default insecure listener (documented; not implemented this milestone). Populate `crates/signer-registry` with the enumeration metadata for every gRPC method. Add `bin/rvc-signer/tests/v1_unregistered.rs` and `bin/rvc-signer/tests/signing_path_enumeration.rs` (the PRD M4 enumeration test).
  - Files: `bin/rvc-signer/src/{main,service}.rs`, `crates/eth-types::insecure` (consumed), `crates/signer-registry/src/lib.rs`.
  - Dependencies: Phase 1 Tasks 1.2 (InsecureGate), 1.7 (signer-registry skeleton).
  - Complexity: medium.
  - Gates: the enumeration test becomes a standing CI gate alongside `tests/architecture_no_cycles.rs`.
- [ ] Task 2.2 — **KM-1** (High, P0): `fix/KM-1-delete-fail-closed`. Strengthen `slashing::export_interchange` to the atomic contract (ADR-008); rewrite DELETE `/eth/v1/keystores` to abort the whole request on export error with no deletions, no empty interchange.
  - Files: `crates/keymanager-api/src/handlers.rs`, `crates/slashing/src/db.rs`.
  - Dependencies: Phase 1 (SlashingDbReader trait optional here; the contract change is independent).
  - Complexity: medium.
- [ ] Task 2.3 — **DVT-1 + CN-1 cluster** (P0 + P1, PRD §7.1): `fix/DVT-1-CN-1-pubkey-scope`. Rekey slashing schema to `(pubkey, gvr, slot)` and `(pubkey, gvr, target_epoch)` UNIQUE indices with `client_cn` as audit-only column; implement `slashing::scoped::PubkeyScopedDb`; ship one-way idempotent transactional migration v1→v2 with the row-pair resolution table from the architecture; remove `client_cn` from `stage_block` / `stage_attestation` signatures; update DVT peer-service and main signer call sites. Add migration regression test on the captured pre-migration fixture from Task 1.8.
  - Files: `crates/slashing/src/{stage,db,migration,scoped}.rs`, `bin/rvc-signer/src/dvt/peer_service.rs`, `bin/rvc-signer/src/slashing/scope.rs`.
  - Dependencies: Task 1.8 (pre-migration fixture or Q3 confirmation); ADR-004, ADR-007.
  - Complexity: high.
  - Note: this is the highest-risk fix in M1 because it touches on-disk state.
- [ ] Task 2.4 — **D-1** (High, P0): `fix/D-1-forward-window`. Implement `crates/doppelganger::ForwardWindowMachine` (Lighthouse-style state machine per Research R8); forward-window state advances at the last slot of e+1; restart-aware safe-skip via `SlashingDbReader`.
  - Files: `crates/doppelganger/src/{forward_window,state,traits}.rs`.
  - Dependencies: Task 1.3 (SigningEnablement trait), Task 1.4 (SlashingDbReader trait).
  - Complexity: high.
- [ ] Task 2.5 — **D-2** (Low, but co-located with D-1 cluster per PRD §7.1): `fix/D-2-fail-closed-missing-liveness`. `LivenessChecker` requires every requested index in the response; missing index = inconclusive, no Safe transition.
  - Files: `crates/doppelganger/src/forward_window.rs`, `crates/doppelganger/src/traits.rs`.
  - Dependencies: Task 2.4.
  - Complexity: low.
- [ ] Task 2.6 — **D-3** (High, P0): `fix/D-3-centralize-gate`. Implement `crates/signer::SigningGate` composing `ForwardWindowMachine` + `PubkeyScopedDb` + `CompositeSigner` + `ValidatorLockMap`; rename `is_attesting_enabled` → `is_signing_enabled` and flip default for unknown pubkey to `false`; wire every slashable + non-slashable sign path through `SigningGate`; keep orchestrator-side fast-path consulting same trait per ADR-012.
  - Files: `crates/signer/src/{lib,gate,enablement,traits,slashable,non_slashable,locks}.rs`, `crates/validator-store/src/store.rs`, orchestrator call sites.
  - Dependencies: Tasks 2.3 (PubkeyScopedDb), 2.4 (ForwardWindowMachine).
  - Complexity: high.
  - Note: also wires SS-1's enumeration test to assert every registered handler routes through `SigningGate`.
- [ ] Task 2.7 — **KM-2** (Medium, but in M1 per architecture cluster): `fix/KM-2-cancel-token-race`. Replace keymanager cancel-token map with `ForwardWindowMachine::cancel` single implementation; the race becomes structurally impossible.
  - Files: `crates/keymanager-api/src/handlers.rs`, `crates/doppelganger/src/forward_window.rs`.
  - Dependencies: Task 2.6 (gate centralised).
  - Complexity: medium.
  - ADR ref: ADR-005.
- [ ] Task 2.8 — **S-3** (Low, in M1 per doppelganger cluster): `fix/S-3-epoch-0-dop`. `ForwardWindowMachine::register` always called; pre-genesis bypass logged explicitly.
  - Files: `bin/rvc/src/main.rs`, `crates/doppelganger/src/forward_window.rs` (pre-genesis branch).
  - Dependencies: Task 2.4.
  - Complexity: low.

### Phase Exit Criteria

- All 9 M1 findings closed; each tracker row shows RED commit hash + GREEN commit hash + test file.
- PRD M4 verified: `bin/rvc-signer/tests/signing_path_enumeration.rs` green; SS-1 v1 raw-root regression test green (two conflicting-root requests both fail closed).
- PRD M6 verified: doppelganger gate consulted at every signing entry point (per-path tests for block, attestation, sync, aggregate, contribution all assert fail-closed when gate is off).
- DVT-1/CN-1 migration regression test green against the captured pre-migration fixture (or Q3 documented as "no production DBs").
- `tests/architecture_no_cycles.rs` + `signer-registry` enumeration test both green as standing gates.
- All M1 fix branches merged FF-only to `develop`; CI four-gate suite green.

---

## Phase 3: M2 Shared Pre-Work — Spec-Vector Fixtures & Canonical Promotion

**Goal:** Land the spec-vector fixtures that the M2 SSZ/domain RED tests depend on, plus the canonical helper promotion that the GVR-1 / IMP-1 fix and EXIT-1 cross-check consume.

**Duration estimate:** Small-Medium.

**Entry criteria:**
- Phase 2 complete; M1 exit gates satisfied.
- `develop` CI green.

**Work items (lands on `prep/M2-shared`):**

- [ ] Task 3.1 — Source spec-vector fixtures for E-1 (one `BeaconBlock` per fork: Bellatrix, Capella, Deneb, Electra) from `ethereum/consensus-spec-tests` at the tag matching the active spec; commit to `crates/eth-types/tests/fixtures/` with provenance README.
  - Dependencies: none.
  - Complexity: medium.
  - PRD ref: §6.2, M2.
- [ ] Task 3.2 — Source spec-vector fixtures for E-2 (one `AggregateAndProof` with real-committee-size `aggregation_bits` ~63 bytes plus a `SyncCommitteeContribution`) from `consensus-spec-tests` or Lighthouse fixtures.
  - Dependencies: none.
  - Complexity: medium.
  - PRD ref: §6.2, M3.
- [ ] Task 3.3 — Source spec-vector fixture for B-1/T-1 (one Deneb+ block with ≥1 blob commitment plus the expected `SignedBlockContents` SSZ bytes); commit to `crates/block-service/tests/fixtures/`.
  - Dependencies: none.
  - Complexity: medium.
- [ ] Task 3.4 — Source spec-vector fixture for KG-1 (one `SignedBLSToExecutionChange` from `staking-deposit-cli`, with expected signing root + signature); commit to `bin/rvc-keygen/tests/fixtures/`.
  - Dependencies: none.
  - Complexity: medium.
- [ ] Task 3.5 — Promote `eth-types::canonical::parse_gvr_hex` + `eq_gvr` to be the single hex/GVR parser for `slashing::import` (used in Phase 4 GVR-1+IMP-1 fix) and `bin/rvc` exit subcommands (EXIT-1).
  - Files: `crates/eth-types/src/canonical/`, downstream `Cargo.toml` updates if needed.
  - Dependencies: Phase 1 Task 1.1.
  - Complexity: low.

### Phase Exit Criteria

- All four fixture sets committed with provenance README; each fixture loads from disk and decodes without panic in a smoke test.
- `eth-types::canonical` is the only hex/GVR parser path used by `slashing::import` and `bin/rvc` exit subcommands; no `hex::decode` calls remain in those call sites for pubkey/GVR/signing-root inputs.
- `prep/M2-shared` merged FF-only to `develop`; CI green.

---

## Phase 4: M2 Fixes — Duty-Correctness Floor & Release Gate

**Goal:** Close all 16 M2 findings (E-1, E-2, B-1/T-1+L-9, KG-1, aggregator cluster SS-2/3+L-4, BN-1, BN-2, DT-1+S-2+C-1, S-5, SSE-1, GVR-1+IMP-1, KG-2, EXIT-1, BLD-1, SYNC-1, KS-1). Block proposal succeeds end-to-end for all forks; aggregator duty succeeds for real-committee `aggregation_bits`; runtime keymanager import observably works; sync-committee participation works. **This phase's exit is the release gate**: P0+P1 closed.

**Duration estimate:** Large.

**Entry criteria:**
- Phase 3 complete; all four spec-vector fixture sets landed.
- Phase 2 complete; gate + ForwardWindowMachine + PubkeyScopedDb shipped.

**Work items (one finding per branch unless PRD §7.1 cluster overlaps; ordered per architecture Rollout & Sequencing M2 table):**

- [ ] Task 4.1 — **E-1** (High, P0): `fix/E-1-body-container-hash`. Rewrite `eth-types::tree_hash_utils` with spec-correct `container_tree_hash_root<T>` helper; introduce `BodyHashRoot` internal newtype; `BeaconBlock::tree_hash_root` body leaf uses container helper only. Spec-vector regression test cross-checks all four forks against the Phase 3.1 fixtures.
  - Files: `crates/eth-types/src/{block,tree_hash_utils}.rs`.
  - Dependencies: Task 3.1 (fixtures).
  - Complexity: medium.
- [ ] Task 4.2 — **E-2** (High, P0): `fix/E-2-bitlist-chunk-count`. Const-generic `bitlist_tree_hash_root<const N: usize>` using SSZ chunk-count `(N+255)/256`; every call site declares its bound (`MAX_VALIDATORS_PER_COMMITTEE`, `SYNC_COMMITTEE_SIZE`). Spec-vector regression test against Phase 3.2 fixture.
  - Files: `crates/eth-types/src/{tree_hash_utils,aggregation}.rs`.
  - Dependencies: Task 3.2 (fixtures); Task 4.1 (tree_hash_utils rewrite landed first).
  - Complexity: medium.
- [ ] Task 4.3 — **B-1 + T-1 + L-9 cluster** (High, P0, PRD §7.1): `fix/B-1-T-1-blockcontents`. Bound published block bytes at `kzg_offset`; Deneb+ payload serialises as proper `SignedBlockContents` (three variable offsets, bounded `SignedBeaconBlock`, `kzg_proofs`, `blobs`); un-ignore L-9 tests as positive regression tests. RED test inverts Q7-resolved state from Phase 1 Task 1.9.
  - Files: `crates/block-service/src/service.rs`, `crates/beacon/src/ssz_deser.rs`.
  - Dependencies: Task 3.3 (fixtures); Task 1.9 (Q7 state documented).
  - Complexity: high.
- [ ] Task 4.4 — **KG-1** (High, P0): `fix/KG-1-bls-to-execution-gvr`. Domain built with `GENESIS_FORK_VERSION` (per EIP-7044); **invert the two existing tests** (`test_bls_to_execution_uses_capella_fork_version`, `test_bls_to_execution_uses_actual_genesis_root`) per Research R3 — they currently pin the bug. Cross-check against Phase 3.4 fixture.
  - Files: `bin/rvc-keygen/src/bls_to_execution.rs`.
  - Dependencies: Task 3.4 (fixture).
  - Complexity: low-medium.
- [ ] Task 4.5 — **SS-2 + SS-3 + L-4 aggregator cluster** (P0 + P0 + P2, PRD §7.1): `fix/aggregator-correctness`. `sign_aggregate_and_proof` skips slashing DB stage (uses `SigningGate` non-slashable path); add ADR-009 chain-of-custody invariant comment block + `signer/tests/chain_of_custody_aggregate.rs` integration test; aggregation path applies `validate_attestation_data` to BN response before computing root.
  - Files: `bin/rvc-signer/src/service.rs`, `crates/signer/src/non_slashable.rs`, `crates/rvc/src/orchestrator/aggregation.rs`.
  - Dependencies: Task 2.6 (SigningGate landed); Task 4.2 (E-2 fixes the aggregation_bits tree hash that the aggregator produces).
  - Complexity: medium.
  - ADR ref: ADR-009.
- [ ] Task 4.6 — **BN-1** (High, P1): `fix/BN-1-optimistic-tier`. `tier()` caps optimistic BN at Unsynced for EL-dependent duties; orchestrator rejects produce/attestation/duty responses with `execution_optimistic=true` before signing.
  - Files: `crates/bn-manager/src/sync_status.rs`, `crates/rvc/src/orchestrator/coordinator.rs`.
  - Dependencies: none beyond Phase 2.
  - Complexity: medium.
- [ ] Task 4.7 — **BN-2** (Medium, P1): `fix/BN-2-startup-sync`. Synchronous `check_sync_status()` before serving duties OR `Unknown` treated distinctly so `synced_indices` does not fall through to Unknown nodes until at least one poll succeeds.
  - Files: `crates/bn-manager/src/{sync_status,manager}.rs`.
  - Dependencies: Task 4.6 (BN-1 first to keep the tier logic coherent).
  - Complexity: medium.
- [ ] Task 4.8 — **DT-1 + S-2 + C-1 runtime-import cluster** (P1 + P1 + P1, PRD §7.1): `fix/runtime-import`. `validator_indices` behind `RwLock` with `update_validator_indices` setter; real `(key_gen_tx, key_gen_rx)` channel created and passed to both adapters via `.with_pubkey_map(...)`; orchestrator built with `new_with_key_gen(...)`; `key_gen_rx.borrow_and_update()` (or `select!` on `changed()`) consumes the signal so a single import = exactly one `clear_cache()`. End-to-end test: import via API → orchestrator sees the key → duty fetched → signing path produces a valid signature within doppelganger window expiry (PRD M7).
  - Files: `crates/duty-tracker/src/tracker.rs`, `bin/rvc/src/main.rs`, `crates/rvc/src/orchestrator/coordinator.rs`, `crates/rvc/src/keymanager_adapters.rs`.
  - Dependencies: Task 2.7 (KM-2 cancel-token race closed so doppelganger state is consistent).
  - Complexity: high.
- [ ] Task 4.9 — **S-5** (High, P1): `fix/S-5-sync-head-root`. `head_root` captured via `get_block_root("head")` or falls back to slot N-1 when current slot has no block.
  - Files: `crates/rvc/src/orchestrator/{slot_context,sync_committee}.rs`.
  - Dependencies: none beyond Phase 2.
  - Complexity: low.
- [ ] Task 4.10 — **SSE-1** (High, P1): `fix/SSE-1-callback-isolation`. Channel + consumer task created inside the reconnect path (or callback wrapped in `catch_unwind`); regression test asserts delivery resumes after a single callback panic.
  - Files: `crates/bn-manager/src/sse.rs`.
  - Dependencies: none beyond Phase 2.
  - Complexity: medium.
- [ ] Task 4.11 — **GVR-1 + IMP-1 cluster** (P1 + P1, PRD §7.1): `fix/slashing-import`. Both sides of GVR comparison normalised through `canonical::eq_gvr`; `InterchangeImporter` rejects `source>target` as `InvalidInterchangeFormat`; detect existing row with differing `signing_root` and record as slashable-history marker (or raise watermark).
  - Files: `crates/slashing/src/{import,db}.rs`.
  - Dependencies: Task 3.5 (canonical helper promoted).
  - Complexity: medium.
- [ ] Task 4.12 — **KG-2** (Medium, P1): `fix/KG-2-verify-hard-fail`. Self-verification FAILED/MISMATCH is a hard error: return Err before writing deposit data; non-zero exit; no `deposit_data-*.json` written for the affected validator.
  - Files: `bin/rvc-keygen/src/new_mnemonic.rs`.
  - Dependencies: none beyond Phase 2.
  - Complexity: low.
- [ ] Task 4.13 — **EXIT-1** (Medium, P1): `fix/EXIT-1-gvr-cross-check`. Voluntary exit subcommands fetch `get_genesis()` from the connected BN and verify effective GVR + genesis time before signing; fail closed on mismatch.
  - Files: `bin/rvc/src/commands/{voluntary_exit,prepare_exit}.rs`.
  - Dependencies: Task 3.5 (canonical GVR helper).
  - Complexity: medium.
- [ ] Task 4.14 — **BLD-1** (Medium, P1): `fix/BLD-1-refresh-cadence`. Builder validator re-registrations on a bounded cadence regardless of content change (per-pubkey last-submitted timestamp inside relay TTL); refresh embedded `timestamp` each time.
  - Files: `crates/builder/src/service.rs`.
  - Dependencies: none beyond Phase 2.
  - Complexity: medium.
- [ ] Task 4.15 — **SYNC-1** (Low, in M2 per architecture order): `fix/SYNC-1-validate-contribution`. `produce_contributions` validates BN-returned `subcommittee_index`/`slot`/`beacon_block_root` against requested values; skip+warn on mismatch.
  - Files: `crates/sync-service/src/lib.rs`, `crates/rvc/src/orchestrator/sync_committee.rs`.
  - Dependencies: none beyond Phase 2.
  - Complexity: low.
- [ ] Task 4.16 — **KS-1** (Medium, P1): `fix/KS-1-effective-cost-gate`. Reject when `n.saturating_mul(r).saturating_mul(128)` exceeds ~1 GiB; per-field maxima aligned to EIP-2335 defaults; gate applied **before** decrypt at the import path.
  - Files: `crates/crypto/src/keystore.rs`, `crates/keymanager-api/src/keymanager_adapters.rs`.
  - Dependencies: none beyond Phase 2.
  - Complexity: medium.

### Phase Exit Criteria

- All 16 M2 fix branches merged FF-only to `develop`; CI four-gate suite green on each.
- PRD M2 verified: block proposal succeeds against a spec-compliant BN for Bellatrix, Capella, Deneb (with and without blobs), Electra; spec-vector cross-checks green.
- PRD M3 verified: aggregator duty succeeds for real-committee `aggregation_bits`; spec-vector cross-check green.
- PRD M7 verified: runtime keymanager import → orchestrator → duty → sign integration test green.
- PRD M5 verified: `cargo build` / `cargo test` / `cargo clippy -- -D warnings` / `cargo fmt --check` green.
- **P0 + M2-resident P1 closed.** The remaining four P1 findings (URL-1, URL-2, KM-3, VS-1) are completed in Phase 6 (Tasks 6.1–6.4). Per the approved DL-5 resolution the release gate is **P0 + ALL P1**, so the release is cut after **Phase 6 Task 6.4**, not at Phase 4 exit. Phase 4 exit unblocks Phase 5 (net-policy) immediately.

---

## Phase 5: M3 Shared Pre-Work — net-policy Crate

**Goal:** Land the `crates/net-policy` crate the URL-1+URL-2 cluster and the remote-signer transport-hardening sequence consume.

**Duration estimate:** Small.

**Entry criteria:**
- Phase 4 complete (release gate); the release branch may be cut in parallel with Phase 5 starting.

**Work items (lands on `prep/M3-shared`):**

- [ ] Task 5.1 — Add `crates/net-policy` skeleton: `DenyList` (IPv4 + IPv6 reserved ranges per RFC 6890 + IANA registries; concrete ranges per architecture module detail), `UrlPolicy`, `validate_url` (mixed-case scheme via normalised `url::Url`), `PinnedResolver` (plug into `reqwest::dns::Resolve`). Zero consumers initially.
  - Files: `crates/net-policy/src/{lib,deny_list,url_policy,pinned_resolver,error}.rs`.
  - Dependencies: none beyond Phase 4.
  - Complexity: medium.
  - ADR ref: ADR-002.

### Phase Exit Criteria

- `crates/net-policy` compiles; unit tests for DenyList IPv4/IPv6 + mixed-case scheme + reserved-ranges property test all green; zero consumers in production code.
- `prep/M3-shared` merged FF-only to `develop`; CI green; `tests/architecture_no_cycles.rs` still green with the new crate at Level 2.

---

## Phase 6: M3 Fixes — Hardening + P2 Cleanup

**Goal:** Close all remaining P2 findings (17 entries covering 25 findings: Lows + Info + the architecture-promoted-to-M3 items VS-1, KM-3, URL-1, URL-2). Satisfies PRD M1 (all 46 findings closed) and PRD M8 (full closeout).

**Duration estimate:** Medium-Large (many small fixes; parallelisable).

**Entry criteria:**
- Phase 5 complete; `net-policy` available.
- Release from Phase 4 either cut or in progress.

**Work items (ordered per architecture Rollout & Sequencing M3 table; one finding per branch):**

- [ ] Task 6.1 — **KM-3** (Medium, in M3 per architecture): `fix/KM-3-keymanager-insecure-gate`. Apply `InsecureGate(Refuse)` opt-in (`RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true`); regression test: non-loopback bind without opt-in fails closed at startup.
  - Files: `bin/rvc/src/main.rs`, consumed `eth-types::insecure`.
  - Dependencies: Phase 1 Task 1.2 (InsecureGate landed).
  - Complexity: low.
- [ ] Task 6.2 — **URL-1 + URL-2 cluster** (P1 + P1, PRD §7.1, in M3 per architecture): `fix/URL-1-URL-2-net-policy`. `keymanager-api` consumes `net-policy::validate_url` + `PinnedResolver`; `crypto::remote_signer` pins IP and re-checks deny-list on every connect.
  - Files: `crates/keymanager-api/src/url_validator.rs`, `crates/crypto/src/remote_signer.rs`.
  - Dependencies: Task 5.1.
  - Complexity: medium.
- [ ] Task 6.3 — **GRPC-1/2/3 + L-1 cluster** (P2, PRD §7.1 remote-signer hardening): `fix/grpc-tls-deadlines`. `tls_enabled` log reflects actual branch; require all three TLS fields together or error; `connect_timeout` + per-RPC deadline below slot deadline; case-insensitive scheme compare.
  - Files: `crates/grpc-signer/src/client.rs`, `crates/crypto/src/remote_signer.rs` (L-1 portion).
  - Dependencies: Task 5.1 (URL-1+URL-2 ideally landed first for shared test matrix).
  - Complexity: medium.
- [ ] Task 6.4 — **VS-1** (Medium, in M3 per architecture): `fix/VS-1-fsync-parent`. After `persist`, `File::open(parent)?.sync_all()?`.
  - Files: `crates/validator-store/src/store.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.5 — **L-2** (P2): `fix/L-2-pubkey-parse-strict`. Strict pubkey hex via `canonical::parse_pubkey_hex`; reject double `0x`.
  - Files: `crates/crypto/src/pubkey.rs` (call site), `crates/eth-types/src/canonical/`.
  - Dependencies: Phase 1 Task 1.1.
  - Complexity: low.
- [ ] Task 6.6 — **L-3** (P2): `fix/L-3-all-zeros-gvr`. `SlashingDb::pinned_gvr` treats all-zeros as `None`; or validate at pin time.
  - Files: `crates/slashing/src/db.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.7 — **L-5** (P2): `fix/L-5-rss-overflow`. Check `>0` before casting; `saturating_mul`; apply to `_SC_CLK_TCK`.
  - Files: `crates/rvc/src/monitoring.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.8 — **DVT-2** (P2): `fix/DVT-2-v2-only`. Migrate DVT aggregator to v2 typed PartialSign RPCs; delete v1 raw-root server impl + `lib.rs` export.
  - Files: `bin/rvc-signer/src/dvt/peer_client.rs`, `bin/rvc-signer/src/main.rs`, `bin/rvc-signer/src/lib.rs`.
  - Dependencies: Task 2.1 (SS-1 v1 removal pattern established).
  - Complexity: medium.
- [ ] Task 6.9 — **DVT-3** (P2): `fix/DVT-3-partial-verify`. Verify each partial against share pubkey before inclusion; combine over a chosen valid threshold-sized subset; drop and retry on failure.
  - Files: `bin/rvc-signer/src/backend/dvt.rs`.
  - Dependencies: none.
  - Complexity: medium.
- [ ] Task 6.10 — **DVT-4** (P2): `fix/DVT-4-share-index-pin`. Pin expected `share_index` per peer; reject mismatches before combining.
  - Files: `bin/rvc-signer/src/dvt/peer_client.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.11 — **DVT-5** (P2): `fix/DVT-5-lagrange-zero`. Reject `index == 0` in combine; validate non-zero at load/allow-list time.
  - Files: `bin/rvc-signer/src/dvt/lagrange.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.12 — **KG-3** (P2): `fix/KG-3-dir-mode-0700`. `DirBuilder::new().recursive(true).mode(0o700)` for keygen output dirs.
  - Files: `bin/rvc-keygen/src/{new_mnemonic,bls_to_execution,exit}.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.13 — **SIG-1** (P2): `fix/SIG-1-password-dir`. Per-keystore lookup `<dir>/<pubkey>.txt` per PRD Assumption #5; fail closed on missing file.
  - Files: `bin/rvc-signer/src/main.rs`, consumed `eth-types::insecure`.
  - Dependencies: Phase 1 Task 1.2.
  - Complexity: low.
- [ ] Task 6.14 — **SP-1** (P2): `fix/SP-1-refresh-dedupe`. Drop name-derived early-skip; always fetch, dedupe by derived pubkey.
  - Files: `crates/secret-provider/src/refresh.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.15 — **TIM-1** (P2): `fix/TIM-1-ms-precision`. Mirror ms arithmetic used by `time_until_attestation`.
  - Files: `crates/timing/src/clock.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.16 — **CLI-1** (P2): `fix/CLI-1-token-file`. `*-token-file` / env intake mirroring `--password-file`; documentation discourages inline form.
  - Files: `bin/rvc/src/main.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.17 — **TEL-1** (P2): `fix/TEL-1-redact`. Parse with `url::Url`; strip username/password; redact known-sensitive query keys.
  - Files: `crates/telemetry/src/config.rs`.
  - Dependencies: none.
  - Complexity: low.
- [ ] Task 6.18 — **Info-1 through Info-5** (P2, each individually): five separate branches.
  - Info-1: `fix/Info-1-no-duplicate-eip3076-paths` — delete or reimplement `is_safe_to_propose`/`is_safe_to_sign` to delegate to one source.
  - Info-2: `fix/Info-2-per-row-gvr-column` — drop or assert per-row `genesis_validators_root`.
  - Info-3: `fix/Info-3-rss-parsing` — macOS current RSS; split after last `)`.
  - Info-4: `fix/Info-4-boundary-hex` — validate 32-byte/4-byte hex at the boundary; validate `Eth-Consensus-Version` against known fork names.
  - Info-5: `fix/Info-5-{ssz-dead,gcp-zeroize,metrics-bind,insecure-env-mutex}` — four sub-items per architecture's per-tracker-row policy. Env-mutex uses `std::sync::Mutex<()>` (ADR-011), no `serial_test`.
  - Files: per finding (see PRD §5 / architecture mapping).
  - Dependencies: none.
  - Complexity: low each.

### Phase Exit Criteria

- All 46 findings closed; tracker artifact shows commit hashes + test file for every entry (PRD M1, M8).
- `cargo build` / `cargo test` / `cargo clippy -- -D warnings` / `cargo fmt --check` green on `develop` and on the release branch (PRD M5).
- Release notes drafted per PRD §12: SS-1 v1 removal, KG-1 regeneration call-out, DVT-1/CN-1 schema migration call-out, KM-3 env-var opt-in, SIG-1 password semantics, EXIT-1 BN reachability requirement, BLD-1 increased relay traffic, URL-2 IP-pinning escape note.
- Final release cut (combining P0+P1+P2) OR P2 carry-over to follow-up release explicitly documented in the tracker.

---

## Dependency Graph

Phase-level dependency chain:

```
Phase 1 (M1 pre-work) ──► Phase 2 (M1 fixes) ──► Phase 3 (M2 pre-work) ──► Phase 4 (M2 fixes) ──► [RELEASE GATE]
                                                                                   │
                                                                                   ▼
                                                          Phase 5 (M3 pre-work) ──► Phase 6 (M3 fixes)
```

Critical-path task dependencies (intra-phase + inter-phase):

```
Task 1.1 canonical module ─────────────────────────► Task 3.5 canonical promotion ──► Task 4.11 GVR-1+IMP-1
                                                                                  └──► Task 4.13 EXIT-1
Task 1.2 InsecureGate ─────────────► Task 2.1 SS-1 ─────────────► Task 6.8 DVT-2 (pattern reused)
                              └────► Task 6.1 KM-3
                              └────► Task 6.13 SIG-1
Task 1.3 SigningEnablement + FailClosedDefault ─────► Task 2.4 D-1 ────► Task 2.6 D-3 ────► Task 4.5 SS-2/3+L-4
                                                                                       └──► Task 2.7 KM-2 ──► Task 4.8 runtime-import
Task 1.4 SlashingDbReader ─────────► Task 2.4 D-1 (restart-aware safe-skip)
Task 1.5 signer→doppelganger dep edge ─────────────► Task 2.6 D-3
Task 1.6 architecture_no_cycles.rs ────────────────► standing gate (every phase)
Task 1.7 signer-registry skeleton ─────────────────► Task 2.1 SS-1 (enumeration metadata)
Task 1.8 Q3 / pre-migration fixture ───────────────► Task 2.3 DVT-1+CN-1 (schema migration regression test)
Task 1.9 Q7 / cargo test --ignored ────────────────► Task 4.3 B-1+T-1+L-9 (RED test inversion)

Task 2.3 DVT-1+CN-1 (PubkeyScopedDb) ──────────────► Task 2.6 D-3 (SigningGate composes PubkeyScopedDb)
Task 2.4 D-1 (ForwardWindowMachine) ───────────────► Task 2.5 D-2
                                              └────► Task 2.6 D-3
                                              └────► Task 2.8 S-3

Task 3.1–3.4 spec-vector fixtures ─────────────────► Tasks 4.1, 4.2, 4.3, 4.4 (RED tests source from fixtures)
Task 4.1 E-1 (tree_hash_utils rewrite) ────────────► Task 4.2 E-2 (extends same module)
Task 4.2 E-2 (correct bitlist tree hash) ──────────► Task 4.5 SS-2/3+L-4 (aggregator depends on correct E-2 root)
Task 4.6 BN-1 ─────────────────────────────────────► Task 4.7 BN-2 (tier logic shared)

Task 5.1 net-policy ───────────────────────────────► Task 6.2 URL-1+URL-2
                                              └────► Task 6.3 GRPC-1/2/3+L-1
```

Standing gates (active from the phase they land onwards):
- `tests/architecture_no_cycles.rs` — from Phase 1 Task 1.6.
- `bin/rvc-signer/tests/signing_path_enumeration.rs` — from Phase 2 Task 2.1.

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| DVT-1+CN-1 schema migration corrupts a production slashing DB | Catastrophic | Low (Q3-dependent) | Phase 1 Task 1.8 captures pre-migration fixture; migration is idempotent + transactional; row-pair resolution table is the explicit policy; release notes mandate backup. |
| B-1/T-1 RED test is already green (fix partially landed per Research R2) | Medium | Medium | Phase 1 Task 1.9 runs `cargo test -- --ignored` before the RED test; tracker records actual state; RED test inverts pinning tests if found. |
| Spec-vector fixtures for a particular fork unavailable at Phase 3 ship time | Medium | Low | Self-consistent fallback test; cross-check fixture lands in a follow-up branch; PRD M2 sign-off blocked until cross-check lands. |
| `SigningGate` centralisation requires touching every signing call site; misses leave a bypass | High | Medium | Pre-work: grep all `CompositeSigner::sign` / `crypto::sign` / `Signer::sign` call sites before the GREEN commit; `signer-registry` enumeration test is the standing catch. |
| Two-layer defense (orchestrator fast-path + SignerService gate) diverges later | Medium | Medium | Both consume same `Arc<dyn SigningEnablement>`; orchestrator fast-path is `==` against the same trait method. |
| KM-1 fail-closed DELETE breaks an operator workflow that relied on partial-success | Medium | Low | PRD Assumption #9 commits to the simpler atomic abort; release notes call out the behavior change. |
| SS-1 v1 raw-root removal breaks an unknown integrator | Medium | Low | ADR-010 keeps handler compiled returning `Unimplemented`; insecure-gate opt-in documented; release notes call out the removal. |
| Per-finding RED-first discipline erodes for "obvious" small fixes | Medium | Medium | Pre-review gate (PRD §6.5) checks RED commit existed and failed before GREEN; reviewer responsibility. |
| URL-2 IP pinning breaks a deployment with legitimately-rotating DNS A records | Medium | Low | Documented operator escape; release-notes call-out. |
| EXIT-1 BN unreachable at exit time blocks exit | Low | Medium | Documented fail-closed; operator can run BN locally for exit ceremony. |
| `crates/rvc` orchestrator remains a wide hub; touching it for D-3 / runtime-import has wide blast radius | Low | Medium | Acknowledged (pre-existing); architecture Q8 surfaces a post-remediation split. The remediation does not worsen the situation. |
| CI throughput bottlenecks with ~30+ separate fix branches | Medium | Medium | Per PRD §7.2: batch P2 fixes touching the same file where review trail still per-finding-traces commits; parallelise Phase 6 task assignment. |
| Aggregator cluster (Task 4.5) lands SS-2/SS-3 without chain-of-custody invariant being visible | High | Low | ADR-009 mandates comment + integration test; reviewer confirms both present in GREEN commit. |

---

## Technical Spikes / Open Questions

Carried from PRD §10 and architecture Open Questions; defaults applied. These need active resolution at the gates noted.

- **Q1** (SS-1 v1 raw-root delete vs `Unimplemented`): architecture default applied (ADR-010); revisit only if a downstream integrator surfaces. Resolution gate: pre-Phase 2.
- **Q2** (DVT-1 per-CN audit-only vs operator-relied per-CN watermark): architecture default applied (ADR-004); audit column exposed via `slashing::audit`. Resolution gate: pre-Phase 2 Task 2.3.
- **Q3** (production on-disk slashing DBs exist): **must resolve before Phase 2 Task 2.3 ships.** Phase 1 Task 1.8 owns this. If "no production DBs," the migration test still ships but is exercised against a synthetic fixture.
- **Q4** (D-3 centralisation in `crates/signer`): decided yes per ADR-001.
- **Q5** (`--password-dir` semantics): architecture default applied (per-keystore `<dir>/<pubkey>.txt`).
- **Q6** (P2 inclusion vs deferral): architecture default — all P2 fixes ship in the release after the gate unless individually deferred with rationale.
- **Q7** (B-1/T-1 actual landed state): **must resolve before Phase 4 Task 4.3 RED test.** Phase 1 Task 1.9 owns this.
- **Q8** (orchestrator split): out of scope per PRD §2; surfaced as post-remediation follow-on.
- **Q9** (`SigningGate` sub-responsibility extraction): out of scope; current sub-modules within `crates/signer` are the natural seams.

Research follow-ups (from `plan/remediation/research/00-overview.md`):
- R6 — fix SSRF deny-list citations (IPv6 multicast registry, RFC 5735→6890, single-source SSRF advisories) at Phase 5 Task 5.1 README/comments.
- R7 — downgrade EIP-7657 status everywhere (architecture/PRD copy) and beacon-API liveness MUST→SHOULD wording at touch sites.

---

## Decision Log

Key decisions made by this plan (architecture decisions reside in the architecture's ADRs):

- **DL-1.** Six phases, not eight: pre-work folds into a dedicated phase per milestone so the per-finding fixes phase stays narrow. Splitting each milestone into pre-work + fixes phases keeps each phase's exit criterion crisp and a downstream issue-estimation tool can fan out the parsed phase headings cleanly.
- **DL-2.** Release gate is **P0 + ALL P1**, cut after Phase 6 Task 6.4 (see DL-5 as resolved). Pure-P2 Lows/Info (Tasks 6.5–6.18) are the deferrable tail per PRD §11.
- **DL-3.** D-2 and S-3 placed in Phase 2 (M1) despite being Low severity, because PRD §7.1 clusters them with the doppelganger end-to-end fix (D-1+D-3+D-2+S-3 must all land for the window to be unbypassable). Architecture Rollout & Sequencing agrees.
- **DL-4.** KM-2 placed in Phase 2 (M1) despite being Medium severity, because PRD §7.1 clusters it with KM-1/D-3 and the cancel-token race becomes structurally impossible only once `ForwardWindowMachine` owns the gate (ADR-005).
- **DL-5 (RESOLVED at plan review).** URL-1, URL-2, KM-3, VS-1 stay physically in Phase 6 (M3) per architecture Rollout & Sequencing — they are gated on the `net-policy` crate landing first — **but they are release-blockers.** The user resolved the release-scope question in favor of honoring the PRD's "release gates on P0+P1": the release is **held until Phase 6 Task 6.4 completes** (option (b)), so the release covers P0 + ALL P1. Only the pure-P2 Lows/Info (Tasks 6.5–6.18) may roll to a follow-up. Sequencing implication: Phase 5 (net-policy) and Phase 6 Tasks 6.1–6.4 are on the pre-release critical path and should be prioritized immediately after Phase 4 exit.
- **DL-6.** Tasks 4.1 and 4.2 ordered with E-1 first then E-2 because both edit `eth-types/src/tree_hash_utils.rs`; E-1 lands the rewrite scaffold (`container_tree_hash_root`), E-2 extends it with `bitlist_tree_hash_root<N>`.
- **DL-7.** Task 4.7 BN-2 sequenced after Task 4.6 BN-1 to keep the tier logic coherent in one churn pass on `crates/bn-manager/src/sync_status.rs`.
- **DL-8.** Phase 1 Task 1.8 (Q3 resolution + fixture capture) is treated as a hard blocker for Phase 2 Task 2.3, not a parallel workstream. The schema migration is the highest-stakes change in M1; shipping it without a regression fixture against a real on-disk DB is the catastrophic-failure risk in the risk register.
- **DL-9.** Phase 1 Task 1.9 (Q7 resolution) is treated as a hard blocker for Phase 4 Task 4.3, per Research R2 — writing a RED test against an already-green state wastes a cycle and pollutes the tracker.
- **DL-10.** Cluster branches (DVT-1+CN-1, B-1+T-1+L-9, SS-2+SS-3+L-4, DT-1+S-2+C-1, GVR-1+IMP-1, URL-1+URL-2, GRPC-1/2/3+L-1) preserved as single branches per PRD §7.1 because GREEN diffs literally overlap. All other findings stay one-finding-per-branch per principle P8.

---

## Assumptions

Derived from the three approved artifacts; recorded for review at the Phase 1 entry gate.

1. **PRD §8 assumptions are carried in full.** This plan does not re-litigate severity mapping (Assumption #1), spec-vector sources (Assumption #2), one-finding-one-branch FF-only (Assumption #3), no SS-1 deprecation period (Assumption #4), forward-only DVT-1/CN-1 migration (Assumption #5), D-3 centralisation (Assumption #6), `is_signing_enabled` rename (Assumption #7), unchanged doppelganger window length (Assumption #8), KM-1 atomic abort (Assumption #9), no release until P0+P1 closed (Assumption #10), TDD-by-commit-history not CI (Assumption #11), tracker location (Assumption #12), no new public crate API outside workspace (Assumption #13), clippy -D warnings standard (Assumption #14), no release-signing changes (Assumption #15), Info-5 sub-items individually closed (Assumption #16), no formal external audit during remediation (Assumption #17).
2. **Architecture ADRs are carried in full.** This plan does not re-open ADR-001 through ADR-013; specifically, the SigningGate location (signer), the net-policy crate, the InsecureGate inlining, pubkey-scoped slashing with audit-only CN, ForwardWindowMachine ownership, canonical helper ownership, defense-in-depth at SQLite UNIQUE, atomic export contract, chain-of-custody invariant, SS-1 compiled-but-Unimplemented, env-mutex over serial_test, two-layer doppelganger check, and per-crate fixture co-location.
3. **Estimates are relative (small/medium/high), not time-based**, per PRD §11 milestones being un-dated. Time estimates can be added at Phase-Plan-to-Issues handoff if the issue-estimation tool requires.
4. **Phase 5 + Phase 6 can run concurrently with the release cut** from Phase 4 exit. The plan assumes the release branch can be cut at the Phase 4 exit gate while M3 work proceeds on `develop`, then either be re-cut to include M3 or M3 ships as a point release. The user decides at Phase 4 exit (Decision DL-5).
5. **CI capacity assumption.** The four-gate suite (build/test/clippy -D warnings/fmt) plus the two standing tests runs in under 30 minutes per branch; if CI is slower than this, Phase 6 may need batched-branch optimisation per PRD §7.2 mitigation.
6. **No new external dependencies are needed for any fix**, per PRD §2 and architecture P6. If a fix proves otherwise mid-execution, it goes through normal Cargo workspace review and is flagged as a deviation in the tracker.
7. **The `signer-registry` enumeration test becomes a standing CI gate** from the moment Phase 2 Task 2.1 lands; future contributors adding a signing handler without a matching `signer-registry` entry will see a CI failure.
8. **`tests/architecture_no_cycles.rs` becomes a standing CI gate** from the moment Phase 1 Task 1.6 lands. The forbidden edges asserted at minimum: `slashing → doppelganger`, `signer → keymanager-api`, `eth-types → anything`.
