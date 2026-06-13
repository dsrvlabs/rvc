# Phase 3: M2 Shared Pre-Work — Spec-Vector Fixtures & Canonical Promotion

## Phase Overview

- **Goal:** Land the spec-vector fixtures the M2 SSZ/domain RED tests depend on (E-1, E-2, B-1/T-1, KG-1), and promote `eth-types::canonical` helpers to be the single hex/GVR parser path consumed by `slashing::import` (Phase 4 Task 4.11) and `bin/rvc` exit subcommands (Phase 4 Task 4.13). Zero production behavior change on `develop`; this phase ships dev-only assets (test fixtures + provenance docs) and a refactor that swaps ad-hoc hex parsing for the canonical helpers behind a green test surface.
- **Issue count:** 7 issues, 12 total points.
- **Estimated duration:** 9 days (single-stream; updated from 8 after sequencing 3.6 and 3.7 across two day-slots per the 1-2 day-per-issue scope rule).
- **Entry criteria:**
  - Phase 2 complete; PRD M4 + M6 verified on `develop`.
  - `develop` CI four-gate suite (build / test / clippy `-D warnings` / fmt) green.
  - `tests/architecture_no_cycles.rs` standing gate green (Phase 1 Task 1.6).
  - `signer-registry` enumeration test standing gate green (Phase 2 Task 2.1).
  - Phase 1 Task 1.1 landed: `eth-types::canonical` module exists with `PubkeyHex`, `GvrHex`, `SigningRootHex` newtypes and `parse_*` helpers, with zero production consumers.
- **Exit criteria:**
  - Four fixture sets committed under per-crate `tests/fixtures/` with provenance README + each fixture loads from disk and decodes without panic in a smoke test.
  - `eth-types::canonical::{parse_gvr_hex, eq_gvr}` is the only hex/GVR parser path used by `crates/slashing/src/db.rs::import()` and `bin/rvc/src/commands/{voluntary_exit,prepare_exit}.rs`; no remaining `hex::decode` / `from_hex` calls for pubkey, GVR, or signing-root inputs in those call sites.
  - `prep/M2-shared` branch merged FF-only to `develop`; CI green.
  - Tracker updated: each Phase 4 finding row (E-1, E-2, B-1/T-1, KG-1, GVR-1, IMP-1, EXIT-1) records the fixture path / canonical helper it consumes.

### Assumptions Recorded

These assumptions are made by this phase breakdown and should be flagged at the Phase 3 entry gate if any are wrong.

1. **PRD §8 + project-plan assumptions carry.** Specifically: spec-vector fixtures are sourced from `ethereum/consensus-spec-tests` at the tag matching the active spec, with Lighthouse / Lodestar / `staking-deposit-cli` as secondary or specialised sources (PRD Assumption #2 + Phase 3 task descriptions in project plan).
2. **Each fixture sourcing task is 2 points.** Per the project plan ("Complexity: medium" for Tasks 3.1–3.4), a fixture-sourcing issue includes: (a) locating an authoritative fixture in `consensus-spec-tests` or named secondary source, (b) committing the binary asset under the consuming crate's `tests/fixtures/`, (c) writing a README documenting provenance (source repo, tag/commit, file path within the source tree, what it represents), and (d) writing a tiny smoke test that loads the file from disk and decodes it without panic. The smoke test does NOT verify spec-correctness (the Phase 4 RED test does that against the same fixture); it only proves the fixture is well-formed and discoverable from `cargo test`.
3. **Pre-fixture scaffold issue (Issue 3.1) is 1 point and split from fixture work.** Defining the provenance README format, the per-crate `tests/fixtures/` directory convention, and a shared loader helper used by all four smoke tests is a separate 1-point issue so the four fixture issues (3.2–3.5) each land a homogeneous, reviewable diff.
4. **Canonical promotion is split into two issues (3.6 + 3.7).** The project plan groups `slashing::import` and `bin/rvc` exit subcommands as one task (3.5); this breakdown splits them: Issue 3.6 promotes the helpers in `crates/slashing/src/db.rs::import()` (consumed by Phase 4 Task 4.11 GVR-1 + IMP-1), Issue 3.7 promotes them in `bin/rvc/src/commands/{voluntary_exit,prepare_exit}.rs` (consumed by Phase 4 Task 4.13 EXIT-1). They touch different crates with different blast radii; splitting keeps each issue at 1-2 days with a focused PR.
5. **All fixture files are checked into the repo.** No `build.rs` downloading at compile time; PRD §6.2 mandates fixtures-in-repo with provenance. This adds binary assets to the repo (a handful of small `.ssz` and `.json` files — well under 100 KiB per fixture per spec-test convention).
6. **Provenance README format is uniform across crates.** A single template documents: source repo URL, exact git tag/commit, source path inside that tree, fixture purpose, and the consuming Phase 4 RED test. Issue 3.1 codifies the template.
7. **Smoke tests live alongside Phase 4 RED tests but are independent.** Smoke tests assert "the file at `tests/fixtures/<name>` exists and decodes." Phase 4 RED tests assert spec-correctness. This separation lets Phase 3 ship green even before Phase 4 starts; if a fixture turns out to be malformed, the smoke test catches it in Phase 3, not in Phase 4 under tighter pressure.
8. **No new external Rust crates added.** Per architecture P6. Fixtures are loaded via existing `std::fs::read` + the consuming crate's existing SSZ decoder.
9. **No production code path consumes the fixtures.** Fixtures live under `tests/fixtures/` (cargo's test-binary-only directory); production builds do not include them.
10. **The phase is single-stream.** One code-writer works issues in dependency order; no parallel streams, no file-ownership map.

## Phase Summary

| Issue | Title | Points | Blocked by | Scope | Files |
|-------|-------|--------|------------|-------|-------|
| 3.1 | Fixture provenance scaffold & shared loader | 1 | — | 1 day | `crates/eth-types/tests/fixtures/README.template.md` (new), `crates/eth-types/tests/common/mod.rs` (new) — or per-crate equivalent |
| 3.2 | E-1 fixtures: per-fork `BeaconBlock` spec vectors | 2 | 3.1 | 1-2 days | `crates/eth-types/tests/fixtures/{bellatrix,capella,deneb,electra}_block.ssz`, `crates/eth-types/tests/fixtures/README.md`, `crates/eth-types/tests/spec_vector_block_smoke.rs` (new) |
| 3.3 | E-2 fixtures: real-committee `AggregateAndProof` + `SyncCommitteeContribution` | 2 | 3.1 | 1-2 days | `crates/eth-types/tests/fixtures/aggregate_and_proof_real_committee.ssz`, `crates/eth-types/tests/fixtures/sync_contribution.ssz`, `crates/eth-types/tests/fixtures/README.md` (extended), `crates/eth-types/tests/spec_vector_bitlist_smoke.rs` (new) |
| 3.4 | B-1/T-1 fixture: Deneb+ block with blobs + `SignedBlockContents` SSZ | 2 | 3.1, **Phase 1 Task 1.9** (Q7) | 1-2 days | `crates/block-service/tests/fixtures/deneb_block_with_blobs.ssz`, `crates/block-service/tests/fixtures/signed_block_contents.ssz`, `crates/block-service/tests/fixtures/README.md` (new), `crates/block-service/tests/blockcontents_fixture_smoke.rs` (new) |
| 3.5 | KG-1 fixture: `SignedBLSToExecutionChange` from `staking-deposit-cli` | 2 | 3.1 | 1-2 days | `bin/rvc-keygen/tests/fixtures/signed_bls_to_execution_change.json`, `bin/rvc-keygen/tests/fixtures/README.md` (new), `bin/rvc-keygen/tests/bls_to_execution_fixture_smoke.rs` (new) |
| 3.6 | Promote `canonical::{parse_gvr_hex, eq_gvr}` in `slashing::import` | 2 | **Phase 1 Task 1.1** | 1-2 days | `crates/slashing/src/db.rs`, `crates/slashing/src/lib.rs`, `crates/slashing/Cargo.toml` (eth-types path dep already present), `crates/slashing/tests/fixtures/import_parity_baseline.json` (new — captured pre-refactor), `crates/slashing/tests/normalize_parity.rs` (extended or asserts new path) |
| 3.7 | Promote `canonical::{parse_gvr_hex, GvrHex}` in `bin/rvc` exit subcommands | 1 | **Phase 1 Task 1.1** | 1 day | `bin/rvc/src/commands/voluntary_exit.rs`, `bin/rvc/src/commands/prepare_exit.rs`, `bin/rvc/Cargo.toml` (eth-types path dep verified) |

**Phase totals:** 7 issues, 12 points.

## Phase Execution Plan

Single-stream; each day-slot is one day of work for one code-writer. Issues 3.6 and 3.7 are independent of the fixture chain and are placed at the end for a clean CI signal between the two halves of the phase. Day 8 (3.6) and Day 9 (3.7) are explicitly two separate day-slots — 3pts in one day violates the 1-2 day-per-issue scope rule, and 3.6 has a non-trivial prerequisite step (capture pre-refactor baseline fixture from unmodified `develop`) that wants its own day.

| Day | Issue | Notes |
|-----|-------|-------|
| 1 | 3.1 Provenance scaffold & shared loader (1pt) | Sets the convention every fixture issue follows. No external blockers. |
| 2 | 3.2 E-1 per-fork BeaconBlock fixtures (2pts, day 1 of 2) | Source from consensus-spec-tests (Bellatrix, Capella, Deneb, Electra). Verify implicit prerequisites (`decode_beacon_block_ssz`, `ForkName::*`) exist on `develop` at start. |
| 3 | 3.2 cont. | Provenance README + smoke test green. |
| 4 | 3.3 E-2 AggregateAndProof + SyncCommitteeContribution (2pts, day 1 of 2) | Real-committee `aggregation_bits` (~63 bytes) is the load-bearing fixture; sync contribution is the secondary one. Verify implicit prerequisites (`decode_sync_committee_contribution_ssz`, `AggregateAndProof: ssz::Decode`) exist on `develop` at start. |
| 5 | 3.3 cont. | |
| 6 | 3.4 B-1/T-1 Deneb+ block with blobs + SignedBlockContents (2pts) | Single day if a single Deneb fixture covers both; second day reserved as buffer because B-1/T-1 is **hard-blocked on Phase 1 Task 1.9** (Q7 — landed-state of `ssz_deser::resolve_block_region_end` and L-9 ignored tests must be in the tracker). |
| 7 | 3.5 KG-1 staking-deposit-cli fixture (2pts) | Sourced from `staking-deposit-cli` (per project plan Task 3.4); single fixture file. |
| 8 | 3.6 canonical promotion in `slashing::import` (2pts) | Day 1 of canonical-promotion work. Includes the prerequisite step: capture pre-refactor behaviour baseline as `import_parity_baseline.json` from unmodified `develop` (separate commit) BEFORE the parser-swap commit. The parity test then asserts post-refactor `import()` against the baseline, not against itself. |
| 9 | 3.7 canonical promotion in `bin/rvc` exit subcommands (1pt) | Day 2 of canonical-promotion work. Independent of 3.6; intentionally on its own day-slot rather than crammed onto day 8. Buffer between 3.6 and 3.7 also lets 3.6's parity test CI signal clear before 3.7 lands. |

> **Buffer note:** Issues 3.2–3.5 are each estimated at 2 points (1-2 days). If sourcing a particular fork's fixture from `consensus-spec-tests` takes longer than expected (e.g. tag mismatch, fixture path moved between releases), the buffer comes from the days budgeted for 3.4 and 3.5, both of which have natural one-day execution paths. If a buffer is needed and not available, surface immediately — splitting a single fixture across days is acceptable; quietly slipping the phase is not.
>
> **Sequencing rationale for days 8 and 9:** Previous draft scheduled 3.6 (2pt) + 3.7 (1pt) on day 8, which is 3 points in one day and contradicts the issue-estimation principle that an issue should be completable in 1-2 days. 3.6 also has the pre-refactor baseline-capture step (a separate commit from a clean `develop` checkout) that wants the full day rather than being squeezed alongside 3.7's parser swap. Sequencing them across two day-slots gives 3.6 the day it needs for the baseline-capture + parser-swap + parity-test sequence, lets the CI signal clear, then 3.7 lands on day 9 against a known-green `develop`.

---

## Issues

### Issue 3.1: Fixture provenance scaffold & shared loader

- **Points:** 1
- **Type:** chore
- **Priority:** P0 (phase-blocking — gates 3.2–3.5)
- **Blocked by:** none
- **Blocks:** Issue 3.2, 3.3, 3.4, 3.5
- **Scope:** 1 day

**Description:**

Define the per-crate `tests/fixtures/` directory convention, the provenance README template, and a tiny shared loader helper that the four fixture smoke tests (3.2–3.5) reuse. The intent is that every fixture issue lands a homogeneous, reviewable diff: a `.ssz` (or `.json`) binary, a README block following the template, and a smoke test calling the shared loader.

**Implementation Notes:**

- Files to create:
  - `crates/eth-types/tests/fixtures/README.md` (instantiated template; per PRD §6.2 each fixture's provenance is documented here).
  - `crates/eth-types/tests/common/mod.rs` — a small loader helper:
    ```rust
    pub fn load_fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("fixture {:?} not loadable: {}", path, e))
    }
    ```
  - `crates/block-service/tests/fixtures/README.md` and `crates/block-service/tests/common/mod.rs` — same template / helper, scoped to that crate.
  - `bin/rvc-keygen/tests/fixtures/README.md` and `bin/rvc-keygen/tests/common/mod.rs` — same template / helper, scoped to that binary's integration tests.
- Provenance README template (each fixture entry must include):
  - Fixture filename.
  - Source repo URL (e.g. `https://github.com/ethereum/consensus-spec-tests`).
  - Exact git tag or commit SHA the fixture was sourced from.
  - Source path inside that repo (e.g. `tests/mainnet/deneb/ssz_static/BeaconBlock/ssz_random/case_0/serialized.ssz_snappy` — snappy-decoded to raw SSZ if applicable).
  - Fixture purpose (e.g. "E-1 RED test: per-fork BeaconBlock tree_hash_root cross-check").
  - Consuming Phase 4 RED test path (e.g. `crates/eth-types/tests/spec_vector_block.rs`).
- Loader helper is intentionally trivial; it exists so every smoke / RED test in 3.2–3.5 uses the same path-resolution and the same error message format. Avoids three copies of the same boilerplate across crates.
- No production code touched. No new dependencies.

**Acceptance Criteria:**

- [ ] `crates/eth-types/tests/fixtures/README.md` exists with the template's required-fields section, plus a "Fixtures" section that is initially empty (each fixture issue appends its own entry).
- [ ] `crates/eth-types/tests/common/mod.rs`, `crates/block-service/tests/common/mod.rs`, `bin/rvc-keygen/tests/common/mod.rs` exist with the `load_fixture` helper compiling and callable from a test in the same crate.
- [ ] A trivial test in each crate (e.g. `crates/eth-types/tests/common_smoke.rs`) calls `load_fixture("nonexistent")` and asserts it panics with the expected error format — proves the helper is reachable from `cargo test`.
- [ ] `cargo test --workspace` green.
- [ ] `cargo fmt --check` and `cargo clippy -- -D warnings` green.
- [ ] No production code or `Cargo.toml` `[dependencies]` section changed.

**Testing Notes:**

- The "loader panics on missing fixture" test does not need a real fixture; it's a structural test that the helper is wired into the test target. Each crate gets one such test.
- This issue is intentionally low-risk and small so it can be reviewed and merged the same day, unblocking 3.2–3.5 in parallel.

---

### Issue 3.2: E-1 fixtures — per-fork `BeaconBlock` spec vectors

- **Points:** 2
- **Type:** chore
- **Priority:** P0 (Phase 4 Task 4.1 / PRD M2 dependency)
- **Blocked by:** Issue 3.1
- **Blocks:** Phase 4 Task 4.1 (E-1 RED test)
- **Scope:** 1-2 days

**Implicit prerequisites (must already exist on `develop` — verify at issue start):**

The smoke test imports the following from `eth-types`. If any is absent from `develop` at issue start, flag the discovered dependency in the tracker BEFORE sourcing fixtures (the smoke test would not compile) and surface to the phase owner — these are not authored by this issue or any other Phase 3 issue:

- `eth_types::decode_beacon_block_ssz(bytes, fork)` — per-fork SSZ decoder for `BeaconBlock` / `SignedBeaconBlock`. The smoke test calls this directly; without it, no per-fork decode path exists.
- `eth_types::ForkName::{Bellatrix, Capella, Deneb, Electra}` — fork enum variants used to drive the decoder. The fixture set covers exactly these four forks; if any variant is missing the corresponding smoke test cannot be written.

If either is absent on `develop` at issue start: do NOT in-scope adding them here (out of scope for a fixture-sourcing issue); instead, file a tracker entry "discovered Phase 3 dependency: `eth_types::<symbol>` missing on `develop`" and pause the issue until the dependency is resolved (most likely as an emergent Phase 1 follow-up). Per Phase 3 Assumption #8, this issue does not add new external Rust crates; per architecture P7, this issue does not move types between crates.

**Description:**

Source one `BeaconBlock` SSZ fixture per fork (Bellatrix, Capella, Deneb, Electra) from `ethereum/consensus-spec-tests`, commit them under `crates/eth-types/tests/fixtures/`, and write a smoke test that loads each and decodes it via the existing `decode_beacon_block_ssz` without panic. The Phase 4 Task 4.1 RED test will reuse these fixtures to cross-check `BeaconBlock::tree_hash_root()` against the expected root captured from the fixture's metadata.

**Implementation Notes:**

- Files to create:
  - `crates/eth-types/tests/fixtures/bellatrix_block.ssz` (raw SSZ, snappy-decoded if necessary).
  - `crates/eth-types/tests/fixtures/capella_block.ssz`.
  - `crates/eth-types/tests/fixtures/deneb_block.ssz`.
  - `crates/eth-types/tests/fixtures/electra_block.ssz`.
  - `crates/eth-types/tests/fixtures/bellatrix_block.root.txt` (and per-fork siblings) — hex-encoded expected `tree_hash_root` from the spec-test's `roots.yaml`. Stored as text so the Phase 4 RED test can read it without an extra dep.
  - `crates/eth-types/tests/spec_vector_block_smoke.rs` — smoke test:
    ```rust
    mod common;
    #[test]
    fn bellatrix_block_fixture_loads() {
        let bytes = common::load_fixture("bellatrix_block.ssz");
        let _ = eth_types::decode_beacon_block_ssz(&bytes, eth_types::ForkName::Bellatrix)
            .expect("bellatrix fixture must decode");
    }
    // ... and one test per fork
    ```
- Sourcing approach:
  - Use the latest `consensus-spec-tests` release tag whose fork coverage matches `develop`'s spec target (research overview §6.2). Document the tag in `README.md`.
  - Prefer `tests/mainnet/<fork>/ssz_static/BeaconBlock/ssz_random/case_0/` for a deterministic, well-known fixture. If snappy-compressed, decompress before committing (use the official `snappy` decoder or a one-shot Python script; do not add a runtime snappy dep).
  - Capture the expected `tree_hash_root` from the sibling `roots.yaml` and commit as `<fork>_block.root.txt` (hex string, lowercase, no `0x`).
- Update `crates/eth-types/tests/fixtures/README.md` with one entry per fixture (provenance template per Issue 3.1).
- Files NOT to modify: `crates/eth-types/src/{block,tree_hash_utils}.rs` — Phase 4 Task 4.1 owns those edits.

**Acceptance Criteria:**

- [ ] Four `.ssz` fixture files committed; each is a valid raw SSZ payload for the named fork's `BeaconBlock`.
- [ ] Four `.root.txt` sibling files committed; each contains the lowercase hex of the expected `tree_hash_root` (32 bytes / 64 hex chars).
- [ ] `crates/eth-types/tests/fixtures/README.md` updated with provenance for each fixture (source repo URL, tag, source path, purpose, consuming RED test path).
- [ ] `crates/eth-types/tests/spec_vector_block_smoke.rs` exists with one `#[test]` per fork that decodes the fixture without panic.
- [ ] `cargo test -p eth-types --test spec_vector_block_smoke` green.
- [ ] `cargo test --workspace` green; `cargo clippy -- -D warnings`, `cargo fmt --check` green.
- [ ] Total binary size added under 200 KiB across the four fixtures (sanity bound; spec-test cases are small).

**Testing Notes:**

- The smoke test does NOT assert the tree-hash root matches `bellatrix_block.root.txt` — it only proves the fixture loads and decodes. Phase 4 Task 4.1 owns the tree-hash assertion (currently RED on `develop`).
- If `decode_beacon_block_ssz` on `develop` fails for a particular fixture for reasons unrelated to E-1 (e.g. a downstream parser bug uncovered by a real fixture), document it in the tracker and surface to the Phase 4 task — do NOT paper over by trimming or hand-editing the fixture.
- Snappy decompression, if needed, is a one-time author-side step; the committed bytes are raw SSZ.

---

### Issue 3.3: E-2 fixtures — real-committee `AggregateAndProof` + `SyncCommitteeContribution`

- **Points:** 2
- **Type:** chore
- **Priority:** P0 (Phase 4 Task 4.2 / PRD M3 dependency)
- **Blocked by:** Issue 3.1
- **Blocks:** Phase 4 Task 4.2 (E-2 RED test)
- **Scope:** 1-2 days

**Implicit prerequisites (must already exist on `develop` — verify at issue start):**

The smoke test imports the following from `eth-types`. If any is absent from `develop` at issue start, flag the discovered dependency in the tracker BEFORE sourcing fixtures and surface to the phase owner — these are not authored by this issue or any other Phase 3 issue:

- `eth_types::decode_sync_committee_contribution_ssz(bytes)` — SSZ decoder for `SyncCommitteeContribution`. The smoke test calls this directly to validate the sync-contribution fixture decodes.
- `ssz::Decode` impl for `eth_types::AggregateAndProof` — the smoke test relies on the existing `ssz`-derive on the type. If the type is not currently SSZ-decodable on `develop`, the smoke test cannot be written.

If either is absent on `develop` at issue start: do NOT in-scope adding them here (out of scope for a fixture-sourcing issue); instead, file a tracker entry "discovered Phase 3 dependency: `eth_types::<symbol>` missing on `develop`" and pause the issue until the dependency is resolved. Per Phase 3 Assumption #8, this issue does not add new external Rust crates; per architecture P7, this issue does not move types between crates.

**Description:**

Source one `AggregateAndProof` SSZ fixture with a real-committee-size `aggregation_bits` (~63 bytes, ~500 validators) and one `SyncCommitteeContribution` fixture from `consensus-spec-tests` (or Lighthouse fixtures as secondary source). Commit under `crates/eth-types/tests/fixtures/` with expected `tree_hash_root`s in sibling `.root.txt` files. Write a smoke test that loads and decodes both without panic.

**Implementation Notes:**

- Files to create:
  - `crates/eth-types/tests/fixtures/aggregate_and_proof_real_committee.ssz`.
  - `crates/eth-types/tests/fixtures/aggregate_and_proof_real_committee.root.txt`.
  - `crates/eth-types/tests/fixtures/sync_contribution.ssz`.
  - `crates/eth-types/tests/fixtures/sync_contribution.root.txt`.
  - `crates/eth-types/tests/spec_vector_bitlist_smoke.rs` — smoke test loading + decoding each via the existing `eth-types` decoders (`AggregateAndProof` via `ssz::Decode`; `SyncCommitteeContribution` via `decode_sync_committee_contribution_ssz`).
- Sourcing approach:
  - For `AggregateAndProof`: the load-bearing constraint is **real-committee-size `aggregation_bits`** — the chunk-count bug (E-2) only manifests when `bits.len()` crosses `next_power_of_two(bytes)` boundaries for non-trivial bitlists. Aim for ~63 bytes (~500 bits), ideally sourced from a `consensus-spec-tests` aggregate fixture or — if unavailable — captured from a Lighthouse `tree_hash` unit test fixture and cross-cited. Document the size choice in the README.
  - For `SyncCommitteeContribution`: any non-trivial spec-test fixture (sync committee size is fixed at 512, so a single fixture covers the bitlist bound `SYNC_COMMITTEE_SIZE`).
- Update `crates/eth-types/tests/fixtures/README.md` with two new entries (provenance per Issue 3.1's template).
- Files NOT to modify: `crates/eth-types/src/{aggregation,sync_committee,tree_hash_utils}.rs` — Phase 4 Task 4.2 owns those edits.

**Acceptance Criteria:**

- [ ] `aggregate_and_proof_real_committee.ssz` committed; the embedded `aggregation_bits` Bitlist serialises to at least 32 bytes (verified by reading the SSZ payload and locating the variable-length section). Document the exact size in the README.
- [ ] `sync_contribution.ssz` committed.
- [ ] Both `.root.txt` siblings committed with the expected `tree_hash_root` for the outer container (`AggregateAndProof` / `SyncCommitteeContribution`).
- [ ] `crates/eth-types/tests/fixtures/README.md` updated with provenance entries for both fixtures.
- [ ] `crates/eth-types/tests/spec_vector_bitlist_smoke.rs` exists with two `#[test]`s, each decoding its fixture without panic.
- [ ] `cargo test -p eth-types --test spec_vector_bitlist_smoke` green.
- [ ] `cargo test --workspace` green; clippy, fmt green.

**Testing Notes:**

- The smoke test does NOT cross-check the tree-hash root — that's Phase 4 Task 4.2's RED test. The smoke test just proves the fixtures load.
- Spec-test fixtures usually ship with snappy compression; decompress before committing (see Issue 3.2 note).
- If `consensus-spec-tests` does not ship a `AggregateAndProof` fixture at the chosen committee size, fall back to capturing from a Lighthouse `tree_hash_test_vectors` entry and document the source in the README. Note this as a deviation in the tracker if used.

---

### Issue 3.4: B-1/T-1 fixture — Deneb+ block with blobs + `SignedBlockContents` SSZ

- **Points:** 2
- **Type:** chore
- **Priority:** P0 (Phase 4 Task 4.3 / PRD M2 dependency)
- **Blocked by:** Issue 3.1; **Phase 1 Task 1.9** (Q7 — landed-state of `ssz_deser::resolve_block_region_end` and L-9 ignored tests must be documented in the tracker before this fixture is sourced, because the production decoder shape determines what the smoke test asserts and what bytes the fixture must contain).
- **Blocks:** Phase 4 Task 4.3 (B-1/T-1 RED test)
- **Scope:** 1-2 days

**Description:**

Source one Deneb (or later) block with ≥1 blob commitment plus the expected `SignedBlockContents` SSZ bytes (three variable offsets, bounded `SignedBeaconBlock`, then `kzg_proofs`, then `blobs`). Commit under `crates/block-service/tests/fixtures/`. Write a smoke test that loads both and decodes the inner `SignedBeaconBlock` via the existing `decode_beacon_block_ssz`-equivalent path without panic.

Phase 1 Task 1.9 is a **hard prerequisite**: it documents the actual landed state of `ssz_deser::resolve_block_region_end` and the L-9 ignored tests on `develop`. If Q7's resolution has not landed in the tracker before this issue starts, the fixture's decoder-shape assumptions may diverge from production (the smoke test would pass against an assumed decoder while the Phase 4 RED test fails against the real one). Do not source the fixture until the Q7 tracker entry exists.

**Implementation Notes:**

- Files to create:
  - `crates/block-service/tests/fixtures/deneb_block_with_blobs.ssz` — the inner `SignedBeaconBlock` (bounded by `kzg_offset`).
  - `crates/block-service/tests/fixtures/signed_block_contents.ssz` — the full `SignedBlockContents` (the outer wrapper with three variable offsets + the inner block + `kzg_proofs` + `blobs`).
  - `crates/block-service/tests/fixtures/deneb_block_with_blobs.root.txt` — expected `tree_hash_root` of the inner `SignedBeaconBlock`.
  - `crates/block-service/tests/fixtures/README.md` — provenance per Issue 3.1's template.
  - `crates/block-service/tests/blockcontents_fixture_smoke.rs` — two `#[test]`s: one decoding the inner block, one decoding the wrapper into its three regions.
- Sourcing approach:
  - Use a `consensus-spec-tests` Deneb fixture with non-zero blob commitments. If the spec-test repo's Deneb suite does not ship a `SignedBlockContents` fixture (it ships `BeaconBlock` and `BlobSidecar` separately), construct the `SignedBlockContents` payload by concatenating per the spec layout (3× 4-byte offsets, then the inner SSZ, then the `kzg_proofs` array, then the `blobs` array) — but **only** with raw bytes captured from the spec-test fixture, never hand-fabricated. Document the construction in the README.
  - Alternatively (preferred when available): use a Lighthouse or Lodestar `block_contents_test_vectors` fixture and cite it.
- The smoke test only proves the fixture loads; the Phase 4 RED test asserts that publishing the fixture's inner `SignedBeaconBlock` through `block-service::publish_block_ssz` produces bytes that round-trip back to the same inner block (per B-1/T-1 acceptance criterion c).
- Files NOT to modify: `crates/block-service/src/service.rs`, `crates/beacon/src/ssz_deser.rs` — Phase 4 Task 4.3 owns the GREEN diff.

**Acceptance Criteria:**

- [ ] `deneb_block_with_blobs.ssz` committed; SSZ-decodes as a `SignedBeaconBlock` whose body has `blob_kzg_commitments.len() >= 1`.
- [ ] `signed_block_contents.ssz` committed; the three leading variable offsets parse and point to (a) a valid inner `SignedBeaconBlock` region whose decoded bytes equal `deneb_block_with_blobs.ssz`, (b) a non-empty `kzg_proofs` region, (c) a non-empty `blobs` region.
- [ ] `deneb_block_with_blobs.root.txt` committed.
- [ ] `crates/block-service/tests/fixtures/README.md` exists with provenance per template.
- [ ] `crates/block-service/tests/blockcontents_fixture_smoke.rs` exists with the two `#[test]`s described above; both pass.
- [ ] `cargo test -p block-service --test blockcontents_fixture_smoke` green.
- [ ] `cargo test --workspace` green; clippy, fmt green.
- [ ] If Phase 1 Task 1.9 documented a partially-landed L-9 fix, the smoke test references the tracker note in a comment so the Phase 4 author knows which RED-test inversion strategy to apply.

**Testing Notes:**

- This is the highest-risk fixture issue in the phase because (a) `SignedBlockContents` is constructed (3 offsets + 3 regions) rather than served as a single spec-test artifact, and (b) Phase 1 Task 1.9 may have surfaced an already-partially-landed fix.
- If the consensus-spec-tests repo ships `SignedBlockContents` directly under a later release, prefer that over hand-constructing.
- Fixture bytes are immutable once committed; if the Phase 4 RED test reveals a fixture defect, fix in a follow-up commit with `chore(block-service): regenerate B-1/T-1 fixture (...)`.

---

### Issue 3.5: KG-1 fixture — `SignedBLSToExecutionChange` from `staking-deposit-cli`

- **Points:** 2
- **Type:** chore
- **Priority:** P0 (Phase 4 Task 4.4 / PRD M2 dependency)
- **Blocked by:** Issue 3.1
- **Blocks:** Phase 4 Task 4.4 (KG-1 RED test)
- **Scope:** 1-2 days

**Description:**

Source one `SignedBLSToExecutionChange` produced by `staking-deposit-cli` with the corresponding expected signing root and signature, and commit under `bin/rvc-keygen/tests/fixtures/`. `consensus-spec-tests` does not ship signed-message fixtures (per PRD Assumption #2), so the only correct source is `staking-deposit-cli`. The Phase 4 Task 4.4 RED test will reuse this fixture to assert that the `rvc-keygen` `bls-to-execution-change` path produces a signing root + signature matching the fixture when given the same input and `GENESIS_FORK_VERSION`-built domain.

**Implementation Notes:**

- Files to create:
  - `bin/rvc-keygen/tests/fixtures/signed_bls_to_execution_change.json` — the cli's output JSON, containing at minimum `message` (validator_index, from_bls_pubkey, to_execution_address), `signature`, `genesis_validators_root`, and the `fork_version` used. The fixture must have been produced for a known testnet (Holesky/Sepolia) with a known `GENESIS_FORK_VERSION` and `genesis_validators_root` so the Phase 4 RED test has concrete inputs.
  - `bin/rvc-keygen/tests/fixtures/signed_bls_to_execution_change.signing_root.txt` — the expected signing root (32-byte hex), captured separately because `staking-deposit-cli` output does not include it.
  - `bin/rvc-keygen/tests/fixtures/README.md` — provenance per Issue 3.1's template, including `staking-deposit-cli` version, network selected, and inputs used.
  - `bin/rvc-keygen/tests/bls_to_execution_fixture_smoke.rs` — smoke test:
    ```rust
    mod common;
    #[test]
    fn bls_to_execution_fixture_parses() {
        let bytes = common::load_fixture("signed_bls_to_execution_change.json");
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("fixture must parse as JSON");
        // Assert minimum schema: message + signature present; fork_version is 4-byte hex.
        let _ = v["message"].as_object().expect("message field");
        let _ = v["signature"].as_str().expect("signature field");
    }
    ```
- Sourcing approach:
  - Run `staking-deposit-cli generate-bls-to-execution-change` against a published testnet (Holesky preferred — has a well-known, stable GVR). Use a deterministic test mnemonic so the fixture can be reproduced from the README's "how to regenerate" section if needed.
  - The expected signing root is computed once by hand (or by a spec-compliant library like Lighthouse) and committed alongside.
  - Document everything in the README including the exact CLI command, the testnet, and the mnemonic-source (a known-disclosed test mnemonic from the cli's test fixtures, never a private one).
- Files NOT to modify: `bin/rvc-keygen/src/bls_to_execution.rs` — Phase 4 Task 4.4 owns that diff (including inverting the two bug-pinning tests per Research R3).

**Acceptance Criteria:**

- [ ] `signed_bls_to_execution_change.json` committed; parses as a JSON object with at minimum `message`, `signature`, `metadata.fork_version` (or equivalent) fields.
- [ ] `signed_bls_to_execution_change.signing_root.txt` committed (lowercase 64-char hex, no `0x` prefix).
- [ ] `bin/rvc-keygen/tests/fixtures/README.md` exists with the provenance template fully populated, including a "How to regenerate this fixture" section listing the exact `staking-deposit-cli` command, version, network, and mnemonic source.
- [ ] `bin/rvc-keygen/tests/bls_to_execution_fixture_smoke.rs` exists with the parse test; passes.
- [ ] `cargo test -p rvc-keygen --test bls_to_execution_fixture_smoke` green.
- [ ] `cargo test --workspace` green; clippy, fmt green.
- [ ] The fixture's embedded `genesis_validators_root` matches a published value for the chosen testnet (cross-check at sourcing time; document the lookup in the README).

**Testing Notes:**

- This is the only fixture not sourced from `consensus-spec-tests`; the README's provenance section must therefore be especially clear about `staking-deposit-cli` version and inputs.
- If `staking-deposit-cli` output formats differ subtly between versions, pin the version in the README and prefer the most recent release with a clean BLS-to-execution-change subcommand.
- Do NOT include a real operator's mnemonic. Use a published test mnemonic.

---

### Issue 3.6: Promote `canonical::{parse_gvr_hex, eq_gvr}` in `slashing::import`

- **Points:** 2
- **Type:** refactor
- **Priority:** P1 (Phase 4 Task 4.11 dependency — GVR-1 + IMP-1)
- **Blocked by:** **Phase 1 Task 1.1** (canonical module — `PubkeyHex`, `GvrHex`, `SigningRootHex` newtypes and `parse_*` helpers — must have shipped on `develop`; this issue is its first consumer in `crates/slashing/`).
- **Blocks:** Phase 4 Task 4.11 (GVR-1 + IMP-1 cluster)
- **Scope:** 1-2 days

**Description:**

Replace ad-hoc hex parsing and string-equality GVR comparisons inside `crates/slashing/src/db.rs::import()` with calls to `eth_types::canonical::{parse_gvr_hex, eq_gvr}`. Behaviour is preserved exactly — this is a refactor, not a fix. The Phase 4 Task 4.11 GREEN diff will then be a minimal change inside `eq_gvr`'s call path (lowercase-normalising both sides) without having to also rewrite the parser in the same churn pass.

This issue lands a refactor commit with no behaviour change, gated by a parity test that exercises the existing `slashing::import` paths against the existing test surface to confirm no regression.

**Prerequisite step (must run before the refactor commit):** capture the pre-refactor behaviour as a fixture from the unmodified `develop` branch. Concretely: on a clean `develop` checkout (no canonical-promotion edits), run `cargo test -p slashing` against the representative interchange JSON used in the parity test and record (a) the row counts written to the slashing DB, (b) the `Result` variants returned by `import()` for each input, and (c) any error message text the parity test will assert on. Serialise these to `crates/slashing/tests/fixtures/import_parity_baseline.json` (or equivalent) and commit BEFORE the parser-swap commit. The parity test then asserts post-refactor `import()` produces byte-identical row counts and Result variants against this baseline. Without this step the parity test is comparing post-refactor against itself.

**Implementation Notes:**

- Files affected:
  - `crates/slashing/src/db.rs` — the body of `import()` and any helpers it calls (e.g. GVR comparison). Swap raw `hex::decode` / `String::eq` patterns for `eth_types::canonical::parse_gvr_hex` and `eth_types::canonical::eq_gvr`.
  - `crates/slashing/src/lib.rs` — may need to re-export `eth_types::canonical` as a convenience re-export, or callers update imports.
  - `crates/slashing/Cargo.toml` — verify `eth-types = { path = "../eth-types" }` is already present; if not, add (Phase 1 Task 1.1 likely added it but confirm before editing).
- Approach:
  - Grep for `hex::decode`, `from_hex`, `from_str` patterns in `db.rs::import()`; replace each pubkey / GVR / signing-root parse with the matching `eth_types::canonical::parse_*` call. Leave non-canonical fields (e.g. epoch ints) untouched.
  - Where the existing code compares two GVR strings or a string-vs-bytes pair, route through `canonical::eq_gvr`.
  - Do NOT change the comparison semantics in this issue. If the current code compares case-sensitively, `eq_gvr` preserves that semantic for now; Phase 4 Task 4.11 (GVR-1) is the one that fixes the bug by making both sides go through `parse_gvr_hex`'s normalised path.
  - Do NOT change the `InvalidInterchangeFormat` error message text — Phase 4 Task 4.11 (IMP-1) will extend the validations and may want the existing messages stable for its RED test diff.
- Extend `crates/slashing/tests/normalize_parity.rs` (or add a new test file `tests/canonical_import_parity.rs`) with a parity test: load a representative interchange JSON and assert `import()` succeeds, producing the same row counts and same error states as before. The parity test is documentation that the refactor is behaviour-preserving.
- Watch out for: `db.rs` is large; restrict edits to the call sites of canonical parsers. Do NOT touch the slashing WHERE clauses, schema, or migration logic — those are owned by Phase 2 Task 2.3 (already landed) and any further changes belong to Phase 4 Task 4.11.

**Acceptance Criteria:**

- [ ] **Prerequisite landed (separate commit, before the parser swap):** `crates/slashing/tests/fixtures/import_parity_baseline.json` (or equivalent) committed, capturing row counts and `Result` variants observed when `import()` runs against the parity test's interchange JSON on **unmodified `develop`**. The fixture file's commit message documents the `develop` commit SHA it was captured from.
- [ ] `crates/slashing/src/db.rs::import()` has zero direct `hex::decode` / `from_hex` / `from_str` calls for pubkey, GVR, or signing-root inputs; every such input flows through `eth_types::canonical::parse_*`.
- [ ] GVR comparisons inside `import()` flow through `eth_types::canonical::eq_gvr` (not a raw `==` on strings or bytes).
- [ ] Existing tests under `crates/slashing/tests/` all pass without modification.
- [ ] A new or extended parity test asserts that `import()` against a representative interchange JSON produces row counts and `Result` variants byte-identical to the prerequisite baseline fixture (not asserted against itself).
- [ ] `cargo test -p slashing` green; `cargo test --workspace` green; clippy `-D warnings`, fmt green.
- [ ] Diff is reviewable as a refactor — no logic changes outside parser swaps and the parity test.

**Testing Notes:**

- The parity test's job is to PROVE no behaviour change. If a Phase 4 task wants to change the behaviour (e.g. GVR-1 says GVR comparison should normalise both sides), the test gets updated as part of that task's GREEN diff — not in this issue.
- If the refactor surfaces a subtle bug (e.g. the existing `hex::decode` accepts inputs `parse_gvr_hex` rejects), capture the divergence in the tracker as input to Phase 4 Task 4.11; do NOT swallow it.

---

### Issue 3.7: Promote `canonical::{parse_gvr_hex, GvrHex}` in `bin/rvc` exit subcommands

- **Points:** 1
- **Type:** refactor
- **Priority:** P1 (Phase 4 Task 4.13 dependency — EXIT-1)
- **Blocked by:** **Phase 1 Task 1.1** (canonical module — `PubkeyHex`, `GvrHex`, `SigningRootHex` newtypes and `parse_*` helpers — must have shipped on `develop`; this issue's parser swap depends on `parse_gvr_hex` being importable from `eth-types`).
- **Blocks:** Phase 4 Task 4.13 (EXIT-1)
- **Scope:** 1 day

**Description:**

Replace ad-hoc `genesis_validators_root` parsing in `bin/rvc/src/commands/{voluntary_exit,prepare_exit}.rs` with calls to `eth_types::canonical::parse_gvr_hex`. Behaviour is preserved exactly — this is a refactor that lets the Phase 4 Task 4.13 EXIT-1 GREEN diff be a focused change: insert a `get_genesis()` BN call and `eq_gvr` cross-check against the canonical-parsed value, without also rewriting the parser in the same churn pass.

**Implementation Notes:**

- Files affected:
  - `bin/rvc/src/commands/voluntary_exit.rs` — at the call site for `parse_genesis_validators_root` (referenced in the file at the existing `genesis_validators_root` field handling).
  - `bin/rvc/src/commands/prepare_exit.rs` — analogous call site.
  - `bin/rvc/Cargo.toml` — verify `eth-types = { path = "../../crates/eth-types" }` (or equivalent path) is present.
- Approach:
  - Grep both files for `hex::decode` / `from_hex` / `from_str` of the `genesis_validators_root` field.
  - Swap to `eth_types::canonical::parse_gvr_hex(s)` which returns `Result<Root, ParseError>`.
  - Keep error mapping behaviour identical (the existing error variant or `anyhow::Error` mapping is preserved; only the parser changes).
- Watch out for: both commands have integration tests under `bin/rvc/tests/` or inline `#[cfg(test)]`; preserve their `None` / `Some(...)` arg-handling shape.
- Files NOT to modify: `crates/eth-types/src/canonical/*` (Phase 1 owned), any other `bin/rvc` command file (out of scope), any orchestrator code (Phase 4 Task 4.13 only adds the `get_genesis()` cross-check at the same call site).

**Acceptance Criteria:**

- [ ] `bin/rvc/src/commands/voluntary_exit.rs` and `bin/rvc/src/commands/prepare_exit.rs` route every `genesis_validators_root` parse through `eth_types::canonical::parse_gvr_hex`; zero direct hex decoders remain for this field.
- [ ] All existing tests in both files (including the inline `#[cfg(test)]` cases for missing `genesis_validators_root: None`) pass unchanged.
- [ ] `cargo build` and `cargo test -p rvc` green; `cargo test --workspace` green; clippy, fmt green.
- [ ] Diff is reviewable as a focused refactor (parser swap only, no behaviour change).

**Testing Notes:**

- This is the smallest issue in the phase by design; it pairs with Issue 3.6 as the two-half canonical promotion the project plan describes as Task 3.5. Splitting them avoids a single PR touching both `crates/slashing/` and `bin/rvc/src/commands/` with two different review surfaces.
- If `bin/rvc` does not currently depend on `eth-types` directly (it does through the workspace, but the `Cargo.toml` may or may not list it explicitly), add the path dep as part of this issue. Verify `tests/architecture_no_cycles.rs` stays green afterwards (this edge is allowed: `bin/rvc → eth-types` is the workspace pattern).
- If, while editing, a non-`genesis_validators_root` hex input is discovered (e.g. an `--epoch` or fork-version arg), do NOT in-scope it. File a Phase 6 follow-up issue; this phase is only the GVR promotion path needed by EXIT-1.

---
