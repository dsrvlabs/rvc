# Phase 3: Spec-Correct Block Root (audit #7)

> The single largest estimate in the plan, and the one correctness bug that blocks real proposals. The
> block root rs-vc signs for **every** proposal is computed non-spec, so a spec-compliant beacon node
> re-deriving the true root rejects the proposer signature → missed proposals. This is the repo's own
> C-2, unfixed. Milestone **M3**.
>
> Authoritative inputs: [`../prd.md`](../prd.md), [`../project-plan.md`](../project-plan.md), the audit.
> All file:line references verified against HEAD `develop` v0.6.0 (`ffdb49b`).

## The bug, verified

- `BeaconBlockBody = Vec<u8>` (`crates/eth-types/src/block.rs:173`); `BlindedBeaconBlockBody = Vec<u8>`
  (`:174`). The body field genuinely holds the *serialized* body bytes (the blob-KZG-commitment extractor
  reads deep into them — `block.rs:60-129`), not a 32-byte root.
- `BeaconBlock::tree_hash_root` (`block.rs:384-391`) hand-merkleizes 5 leaves and folds the body leaf via
  `vec_u8_tree_hash_root(&self.body)` (`crates/eth-types/src/tree_hash_utils.rs:9-14`) — a plain
  merkleization of the serialized bytes with **no length mix-in**, which is **not** the SSZ container
  `hash_tree_root(BeaconBlockBody)`. `BlindedBeaconBlock::tree_hash_root` (`block.rs:410+`) has the same
  non-spec body leaf.
- `compute_block_root` (`crates/block-service/src/service.rs:526`) and `compute_blinded_block_root`
  (`:530`) are `block.tree_hash_root().0` — the exact root signed for every proposal. The production
  proposal path signs a **blinded** block (`service.rs:516` `publish_blinded_block`), so
  `BlindedBeaconBlock`'s body leaf is the one actually signed on the MEV path; both must be fixed.
- The inline comment "block_root already opaquely covers the body bytes" (`service.rs:407-411`) shows the
  shortcut was intentional but is non-spec.

## What already exists (the foundation)

- The repo vendors `ssz` / `ssz_derive` / `tree_hash` / `tree_hash_derive` (`crates/eth-types/Cargo.toml:14-19`)
  and has **proven SSZ competence**: hand-written `bitlist_tree_hash_root` and `kzg_commitment_list_root`
  (`tree_hash_utils.rs`, `block.rs:151-171`) validated against **external `remerkleable` known-answer
  vectors** (`tree_hash_utils.rs:132-321`), and a spec-correct `BeaconBlockHeader` via
  `#[derive(TreeHash)]` (`block.rs:204-226`).
- `body_fork_layout` (`block.rs:52-58`) already classifies `deneb` / `electra` / `fulu` and the fixed
  offsets of the trailing variable fields are known (`block.rs:60-129`).
- **No typed `BeaconBlockBody` container exists** (grep returned nothing) — that is the work.

## Why this is a range, not a point

A spec-correct `hash_tree_root(BeaconBlockBody)` needs the body's **field schema** per fork. Two designs:
1. **Maintained SSZ types library** (e.g. a consensus-types crate compatible with the vendored
   `ssz`/`tree_hash` versions) — smallest code, a real dependency-vetting task.
2. **Hand-typed per-fork containers** using `ssz_derive`/`tree_hash_derive` — no new heavy dep, but a
   large type surface: **four body variants** (full + blinded × Deneb + Electra; Fulu shares the Electra
   layout) plus shared sub-containers (`ExecutionPayload` / `ExecutionPayloadHeader`, the
   attestation/deposit/etc. lists, `SyncAggregate`, `ExecutionRequests`, `blob_kzg_commitments`).

The **SEC-6a spike is a go/no-go on which design**, and it fixes the container inventory. That decision
is the estimate: library ≈ the low end (11 pts total), hand-typed all four variants ≈ the high end
(16 pts). The phase is sized at **11** as the expected value (the per-issue floors — 3+3+3+2 — sum to
11; the ceiling — 3+6+3+4 — sums to 16).

## Phase Overview

- **Goal:** Compute the true SSZ `hash_tree_root(BeaconBlockBody)` for the active fork and use it as the
  body leaf, so `compute_block_root`/`compute_blinded_block_root` produce a root identical to what a
  spec-compliant beacon node derives — proven against an **external** known-good vector.
- **Issue count:** 4 issues, 11 points (range 11–16).
- **Estimated duration:** ~7–12 days single-stream. On the 2-dev critical path this is the long pole.
- **Entry criteria:** Phases 1–2 merged and green (soft; SEC-6 touches `eth-types`/`block-service`, not
  the Phase 1/2 files).
- **Exit criteria (M3):**
  - [ ] Block root for at least one external known-good vector matches exactly for the current
        production fork (Electra-family).
  - [ ] Blob-KZG-commitment extraction still works (its tests pass).
  - [ ] Changed fixtures (the old non-spec root was hard-coded somewhere) are updated and documented.
  - [ ] Workspace green on the standing invariant.

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| SEC-6a | **Spike** — body `hash_tree_root` design go/no-go + inventory + prototype | 3 | spike | — | A |
| SEC-6b | Typed per-fork `BeaconBlockBody` container(s) + sub-containers | 3 | feature | SEC-6a | A |
| SEC-6c | Wire `compute_block_root`/`compute_blinded_block_root` + external-vector test | 3 | feature | SEC-6b | A |
| SEC-6d | Blinded-body variants + Deneb-fork coverage | 2 | feature | SEC-6b | A |

**Total: 4 issues, 11 points (range 11–16 — SEC-6b/6c/6d widen if the spike returns "hand-typed").**

## Dependency Map

```text
SEC-6a (spike: library vs hand-typed + inventory + one-fork prototype vs external vector)
   │
   └──▶ SEC-6b (typed Electra body container + shared sub-containers)
            ├──▶ SEC-6c (wire compute_block_root/compute_blinded_block_root + ext-vector regression)
            └──▶ SEC-6d (blinded variants + Deneb fork)
```

## Phase Risk Flags

- **Do not band-aid with a config flag** — the audit is explicit this must be fixed properly before real
  proposals work.
- **The root CHANGES for identical inputs.** Any fixture that hard-coded the old non-spec root breaks;
  SEC-6c updates them in the same commit and the summary lists which. Expected, not a regression.
- **Justify any new dependency** (prefer small, audited crates; check `cargo tree` impact). `eth-types`
  carries a zero-workspace-out-edge invariant (external crates are fine; a workspace edge is not).
- **No network in tests** — vendor the external fixture files (consensus-spec-tests SSZ static vectors,
  or a real block + its known root fetched once and committed).

---

## Issues

### Issue SEC-6a: Spike — block-body `hash_tree_root` design go/no-go + inventory + prototype

- **Points:** 3
- **Type:** spike
- **Priority:** P1 (CRITICAL-correctness)
- **Audit source:** #7 = repo C-2 (orchestrator-verified mechanism)
- **Blocked by:** none
- **Blocks:** SEC-6b, SEC-6c, SEC-6d
- **Scope:** ~2 days
- **Stream:** A

**Description:**
Resolve the one decision that sizes the whole cluster: **maintained SSZ types library vs hand-typed
per-fork containers.** Produce (1) a go/no-go recommendation with a `cargo tree` impact assessment and a
dependency-vetting note for any candidate library; (2) the exact container inventory needed (the four
body variants and their shared sub-containers, with field lists per fork); and (3) a working
**prototype** that computes `hash_tree_root(BeaconBlockBody)` for the current production fork (Electra)
and matches an **external** known-good vector — the de-risking proof that the chosen design is correct.
The spike output is a short decision note committed under this plan dir plus the passing prototype test.

**Files to touch (verified):**
- Read-only: `crates/eth-types/src/block.rs` (`:173-174`, `:384-391`, `:60-129`),
  `crates/eth-types/src/tree_hash_utils.rs` (the merkleization helpers + external-vector test pattern
  `:132-321`), `crates/eth-types/Cargo.toml` (`:14-19` vendored ssz/tree_hash),
  `crates/block-service/src/service.rs:405-530`.
- New (spike deliverables): a decision note `plan/security-2026-07-18/spike-sec6-block-body-htr.md`; a
  throwaway/foundational prototype test in `crates/eth-types` (kept if it becomes the SEC-6b seed).
- External fixture: one Electra block + its known-good body root / block root (consensus-spec-tests SSZ
  static vector, or a real testnet/mainnet block fetched once), vendored as a test file.

**Implementation outline:**
1. Enumerate the Electra `BeaconBlockBody` field schema (13 fields) and the sub-containers
   (`ExecutionPayload`, `SyncAggregate`, `ExecutionRequests`, the `Attestation`/`Deposit`/… lists,
   `blob_kzg_commitments`). Do the same for the blinded body (`ExecutionPayloadHeader` in place of
   `ExecutionPayload`) and note the Deneb deltas.
2. Evaluate candidate maintained SSZ types crates for version-compatibility with the vendored
   `ssz`/`tree_hash`; run `cargo tree` on a candidate; write the go/no-go.
3. Build the prototype for the chosen design (library import *or* a hand-typed Electra body via
   `ssz_derive`/`tree_hash_derive`) and match it against the external vector.
4. Write the decision note: recommendation, inventory, the point re-estimate for 6b/6c/6d (confirm or
   revise the 11–16 range), and the fixture source.

**Test plan:**
- `test_electra_body_htr_matches_external_vector` (the prototype proof — must match exactly).

**Acceptance criteria:**
- [x] A committed decision note recommends library-vs-hand-typed with a `cargo tree`/dep-vetting
      rationale and the full container inventory (four variants + sub-containers).
- [x] A prototype computes `hash_tree_root(BeaconBlockBody)` for Electra and matches an external
      known-good vector exactly.
- [x] The note re-confirms or revises the SEC-6b/6c/6d point estimates (the 11–16 range).
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green (prototype test included).

**Risks / unknowns:**
- A candidate library may pin incompatible `ssz`/`tree_hash` versions → forces hand-typed → pushes the
  cluster toward the 16-pt end. Naming this risk and pricing it is the *point* of the spike.

---

### Issue SEC-6b: Typed per-fork `BeaconBlockBody` container(s) + shared sub-containers

- **Points:** 3 (range 3–6 if hand-typed all sub-containers)
- **Type:** feature
- **Priority:** P1 (CRITICAL-correctness)
- **Audit source:** #7
- **Blocked by:** SEC-6a
- **Blocks:** SEC-6c, SEC-6d
- **Scope:** ~2 days
- **Stream:** A

**Description:**
Implement the design the spike chose for the **current production fork (Electra)**: either import the
library's Electra body type, or hand-build the typed `BeaconBlockBodyElectra` container + its shared
sub-containers (`ExecutionPayload`, `SyncAggregate`, `ExecutionRequests`, the lists, `blob_kzg_commitments`)
with `#[derive(ssz_derive::Decode, tree_hash_derive::TreeHash)]`, plus a `Vec<u8> → typed body`
deserializer. Sub-containers are shared with SEC-6d (blinded/Deneb), so build them once here.

**Files to touch (verified):**
- `crates/eth-types/src/block.rs` — new typed body container(s); keep the `Vec<u8>` wire field for
  serialization but add the typed decode + `hash_tree_root` path.
- `crates/eth-types/src/` — new module(s) for the sub-containers if hand-typed (mirror the existing
  `BeaconBlockHeader` derive pattern `:204-226`).
- Reuse `tree_hash_utils.rs` helpers (`bitlist_tree_hash_root`, `kzg_commitment_list_root`) where the
  library path doesn't apply.

**Implementation outline (hand-typed branch; the library branch is a subset):**
1. **RED:** per-container `hash_tree_root` tests against external sub-vectors (e.g. `ExecutionPayload`
   root, `SyncAggregate` root) where available.
2. Define `BeaconBlockBodyElectra` + sub-containers with the derives; implement the `Vec<u8> → typed`
   decode.
3. Verify each sub-container root against a vector; assemble the body root.
4. **GREEN/REFACTOR.**

**Test plan:**
- `test_execution_payload_htr_matches_vector`
- `test_sync_aggregate_htr_matches_vector`
- `test_beacon_block_body_electra_decode_roundtrip`
- `test_beacon_block_body_electra_htr_matches_external_vector` (reuses the SEC-6a vector)

**Acceptance criteria:**
- [x] `hash_tree_root(BeaconBlockBodyElectra)` matches the external vector exactly.
- [x] The `Vec<u8>` body deserializes into the typed container losslessly (round-trip test).
- [x] Any new dependency is justified in the summary with `cargo tree` impact.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- Sub-container breadth is the swing factor. If the spike chose a library, this is small (import +
  decode); if hand-typed, `ExecutionPayload` alone (~17 fields incl. transactions/withdrawals lists) is
  meaningful — the point range reflects this.

---

### Issue SEC-6c: Wire `compute_block_root`/`compute_blinded_block_root` + external-vector regression

- **Points:** 3
- **Type:** feature
- **Priority:** P1 (CRITICAL-correctness)
- **Audit source:** #7
- **Blocked by:** SEC-6b
- **Blocks:** none
- **Scope:** ~2 days
- **Stream:** A

**Description:**
Replace the non-spec body leaf: make `BeaconBlock::tree_hash_root` (and `BlindedBeaconBlock` if not
covered by SEC-6d) use `hash_tree_root(typed body)` for the body leaf instead of
`vec_u8_tree_hash_root(&self.body)`, so `compute_block_root`/`compute_blinded_block_root` produce a
spec-correct root. Add the external-vector regression test at the block level and update any fixtures
that hard-coded the old root.

**Files to touch (verified):**
- `crates/eth-types/src/block.rs` — `BeaconBlock::tree_hash_root` `:384-391` (body leaf at `:390`);
  `BlindedBeaconBlock::tree_hash_root` `:410+` (coordinated with SEC-6d). Deserialize `self.body` into
  the typed container (SEC-6b) and use its `hash_tree_root` as the leaf.
- `crates/eth-types/src/tree_hash_utils.rs` — `vec_u8_tree_hash_root` `:9` stays only where genuinely
  spec-correct (it is `pub(crate)`; remove its use for the body leaf).
- `crates/block-service/src/service.rs` — `compute_block_root` `:526`, `compute_blinded_block_root`
  `:530`; the `service.rs:407-411` "opaquely covers the body bytes" comment is now stale — update it.
- Fixture files anywhere a hard-coded block/body root exists (search `crates/block-service`,
  `crates/eth-types` tests) — update in this commit.

**Implementation outline:**
1. **RED:** a block-level test asserting `compute_block_root` matches the external known-good block root
   for the Electra vector (currently fails — the body leaf is wrong).
2. Change the body leaf to the typed `hash_tree_root`; deserialize `self.body` once (handle a malformed
   body as an error, not a panic — mirror the KZG extractor's defensive style `:82-129`).
3. Run the full suite; update fixtures that hard-coded the old non-spec root; list them in the summary.
4. Confirm blob-KZG-commitment extraction tests still pass (the body bytes are still available).
5. **GREEN/REFACTOR.**

**Test plan:**
- `test_compute_block_root_matches_external_electra_vector`
- `test_compute_blinded_block_root_matches_external_vector` (coordinated with SEC-6d)
- existing blob-KZG extraction tests still pass
- `test_malformed_body_returns_error_not_panic`

**Acceptance criteria:**
- [x] `compute_block_root` (and the blinded root) match the external vector exactly for the production
      fork.
- [x] Blob-KZG extraction tests pass; a malformed body errors rather than panics.
- [x] Fixtures that hard-coded the old root are updated and enumerated in the summary.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- The blinded path shares this issue's edit surface with SEC-6d; if the blinded body's typed container
  isn't ready, SEC-6c lands the full-block root first and SEC-6d completes the blinded root — flagged.

---

### Issue SEC-6d: Blinded-body variants + Deneb-fork coverage

- **Points:** 2 (range 2–4 if hand-typed)
- **Type:** feature
- **Priority:** P1 (CRITICAL-correctness)
- **Audit source:** #7
- **Blocked by:** SEC-6b
- **Blocks:** none
- **Scope:** ~1.5 days
- **Stream:** A

**Description:**
Complete the body-variant matrix: the **blinded** body (`ExecutionPayloadHeader` in place of
`ExecutionPayload`) — which is what the production MEV proposal path actually signs
(`service.rs:516`) — and the **Deneb** fork layout (`blob_kzg_commitments` as the trailing field, no
`execution_requests`), reusing the sub-containers built in SEC-6b. Add external-vector tests for each.

**Files to touch (verified):**
- `crates/eth-types/src/block.rs` — the blinded body typed container; the Deneb-layout body; the
  `BlindedBeaconBlock::tree_hash_root` `:410+` body leaf.
- Reuse SEC-6b sub-containers; add `ExecutionPayloadHeader` (blinded) and the Deneb field ordering.
- External fixtures: a blinded block vector and a Deneb block vector (vendored).

**Implementation outline:**
1. **RED:** external-vector tests for the blinded Electra body root and a Deneb body root.
2. Add `ExecutionPayloadHeader` + the blinded body; add the Deneb layout (fewer trailing fields).
3. Wire `BlindedBeaconBlock::tree_hash_root` to the typed blinded body.
4. **GREEN/REFACTOR.**

**Test plan:**
- `test_blinded_beacon_block_body_htr_matches_external_vector`
- `test_deneb_body_htr_matches_external_vector`
- `test_blinded_and_full_bodies_share_subcontainers` (no duplication)

**Acceptance criteria:**
- [ ] Blinded body root and Deneb body root match external vectors exactly.
- [ ] Sub-containers are shared with SEC-6b (no duplicated type definitions).
- [ ] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Risks / unknowns:**
- If the spike scoped only Electra and Deneb coverage is deferred as "cheap if fixtures exist," and the
  Deneb fixture is hard to source offline, this may drop to blinded-Electra only + a documented Deneb
  follow-up — noted so it is deferred-not-dropped.
