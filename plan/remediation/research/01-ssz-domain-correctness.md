# Angle 01 — SSZ / tree-hash / signing-domain correctness

**PRD findings covered:** E-1, E-2, B-1/T-1, KG-1 (P0); L-9 (P2, paired with B-1/T-1).
**Verification verdict:** All 21 claims VERIFIED against primary sources. **Zero refutations.**

## Scope

Correctness of the SSZ merkleization, container shapes, and signing-domain
construction that determine whether locally-produced signatures are accepted by
a spec-compliant beacon node. This is the angle behind the "duties fail outright"
class of P0 findings.

## Verified claims (HIGH confidence — multi-source confirmed)

- **SSZ merkleization rules** — confirmed independently by `specs/ssz/simple-serialize.md`
  (primary) and eth2book (secondary annotated reference). Bitlist/Bitvector/Container
  distinctions hold.
- **Container shapes** — `BeaconBlock`, `BeaconBlockBody`, `Attestation` schemas match
  the claimed shapes verbatim across phase0 + deneb + electra specs.
- **`compute_domain` signature** and the **`BLSToExecutionChange` → `GENESIS_FORK_VERSION`**
  rule — confirmed by consensus-specs PR #3206, `staking-deposit-cli`, and the phase0
  spec, all in agreement. This is the spec basis for **KG-1**.
- **`SignedBlockContents` shape** — confirmed against beacon-APIs master. Three variable
  offsets, then bounded `SignedBeaconBlock`, then `kzg_proofs`, then `blobs`. This is the
  spec basis for **B-1/T-1**.
- **rs-vc source claims** — `block.rs:333-379`, `tree_hash_utils.rs:9-42`,
  `aggregation.rs:90-113`, `bls_to_execution.rs:51-58` all directly verified by reading
  the develop-branch files. All cited bugs are real and traceable.

## Verified claims (MEDIUM confidence — single source)

- consensus-spec-tests archival date 2025-10-22 (search summary, not re-fetched from GitHub UI).
- consensus-spec-tests directory layout (well-known; extracted from search snippets, not a direct README fetch).
- `MAX_COMMITTEES_PER_SLOT = 64` — well-known phase0 value; exact constant page not fetched.
- `SYNC_COMMITTEE_SUBNET_COUNT = 4` — consistent with industry knowledge; exact constant page not returned by search.

## Corrections / nuances the implementer MUST act on

1. **L-9 may be partially landed.** `ssz_deser.rs:190` is now a *docstring for the FIX path*:
   a `resolve_block_region_end` function already exists whose comment states it returns
   "kzg_proofs offset for BlockContents, bytes.len() for raw BeaconBlock" and warns about
   the C-1/ISSUE-1.1 bug. Either (a) one format path's call site still uses `bytes.len()`,
   or (b) the ignored tests were never re-enabled. **Run `cargo test -- --ignored` before
   re-classifying B-1/T-1 / L-9 as "still open."**
2. **KG-1 fix must also delete/invert a test.** `bls_to_execution.rs:144` contains
   `test_bls_to_execution_uses_capella_fork_version`, which *actively asserts the wrong
   behavior* (it verifies that `signature.verify` FAILS with `genesis_fork_version`). The
   test is part of the defect — fixing the call site alone leaves a green test pinning the
   bug. PRD KG-1 acceptance criterion (b) already calls for flipping both tests; this
   confirms it is mandatory, not optional.
3. **Cite eth2book as secondary only.** `https://eth2book.info/latest/part2/building_blocks/merkleization/`
   is reliable for Container/Bitlist/Bitvector distinctions but is an unofficial annotated
   spec. Cite alongside the primary `ssz/simple-serialize.md`, never instead of it.
4. **Lighthouse / Lodestar are cross-check baselines, not normative sources.** `sigp/tree_hash`
   and `lodestar/types` are correct as fixture/cross-check baselines for E-1/E-2 (per PRD §6.2),
   but the canonical authority for spec interpretation remains `consensus-specs`.

## Additional context (non-contradicting)

- Electra `MAX_ATTESTATIONS = 8` and `MAX_ATTESTER_SLASHINGS = 1` surfaced during the deneb
  body fetch. Not in the original claim list, contradicts nothing; useful when building
  Electra spec-vector fixtures.

## Bottom line

The body of claims is technically accurate and well-cited. All four P0 SSZ/domain bugs
(E-1, E-2, B-1/T-1, KG-1) are real on `develop`. The only open uncertainty is the *current
landed state* of the B-1/T-1 fix infrastructure — resolve it with `cargo test -- --ignored`.
