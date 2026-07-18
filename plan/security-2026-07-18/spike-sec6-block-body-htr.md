# SEC-6a Spike — block-body `hash_tree_root` design go/no-go

**Date:** 2026-07-18  
**Issue:** SEC-6a (Phase 3)  
**Status:** Complete — **GO on hand-typed per-fork containers** (+ small `ssz_types` dep)

---

## 1. Decision

| Option | Verdict | Why |
|--------|---------|-----|
| **Hand-typed per-fork containers** with existing `tree_hash` / `tree_hash_derive` + **`ssz_types` 0.10.1** (`VariableList` / `FixedVector` / `BitList` / `BitVector`) | **GO** | Spec-correct Electra body root proven against external `remerkleable` KAT; stays on workspace `tree_hash` 0.9; type surface is ownable and fork-diffable |
| Full consensus-types library (Lighthouse `types`, `ethereum-consensus` / `ssz_rs`) | **NO-GO** | Version / stack mismatch and dep weight (see §2) |

**Recommendation:** Implement SEC-6b/6c/6d on the hand-typed path seeded by `crates/eth-types/src/block_body.rs`. Do **not** pull a full beacon-types crate.

---

## 2. Library evaluation + dep-vetting

### 2.1 Candidates

| Candidate | SSZ / HTR stack | Electra body? | Fit for rvc |
|-----------|-----------------|---------------|-------------|
| **Lighthouse `types`** | `ethereum_ssz` + `tree_hash` + `ssz_types` (workspace pins; current stable pulls newer `tree_hash`/`ssz_types` than rvc 0.9) | Yes | **No** — pulls milhouse, bls, kzg, superstruct, state machinery; not a leaf-friendly dep for `rvc-eth-types` (zero workspace out-edge leaf) |
| **`ethereum-consensus` (ralexstokes)** | **`ssz_rs`** (different SSZ stack) | Yes | **No** — incompatible with vendored `ethereum_ssz` / `tree_hash`; would dual-implement HTR oracles |
| **`ssz_types` alone** (SigP) | Companion to `tree_hash` / `ethereum_ssz` | List primitives only | **Yes (subset)** — provides limit-aware lists/bitfields without a full consensus crate |
| Hand-typed containers | Workspace `tree_hash` 0.9 + `ssz_types` 0.10.1 | Built here | **Yes** |

### 2.2 `ssz_types` version pin

| Version | `tree_hash` | `ethereum_ssz` | Notes |
|---------|-------------|----------------|-------|
| **0.10.1** (chosen) | **0.9** | 0.8 | Last line on tree_hash 0.9; matches workspace HTR crate |
| 0.11–0.12 | 0.10 | — | Forces tree_hash upgrade |
| 0.13–0.14 | 0.11–0.12 | 0.10 | Forces both ssz + tree_hash upgrade |

**`cargo tree` impact (`rvc-eth-types` after adding `ssz_types` 0.10.1):**

```text
rvc-eth-types
├── ethereum_ssz v0.9.1          # existing direct (Encode/Decode on other types)
├── tree_hash v0.9.1             # existing; already pulled ethereum_ssz 0.8 for Bitfield
└── ssz_types v0.10.1            # NEW
    ├── ethereum_ssz v0.8.3      # already present via tree_hash 0.9 — not a new dual
    └── tree_hash v0.9.1
```

- **No new major dual** beyond what `tree_hash` 0.9 already required (`ethereum_ssz` 0.8 + 0.9).
- **External crate only** — does not violate the `rvc-eth-types` zero *workspace* out-edge invariant.
- Authors: SigP (same lineage as `ethereum_ssz` / `tree_hash`); Apache-2.0.

### 2.3 Encode/Decode note for SEC-6b

`VariableList` / `BitVector` implement `ethereum_ssz` **0.8** `Encode`/`Decode`, while the rest of eth-types uses **0.9** derives. Prototype uses **`TreeHash` only**.

SEC-6b decode of wire `Vec<u8>` → typed body options (pick one in 6b):

1. Hand-written / shared SSZ decode over the typed fields (mirror `ssz_helpers` style), or  
2. Decode via the 0.8 trait impls in a narrow body module, or  
3. Workspace-wide upgrade of `ethereum_ssz`/`tree_hash`/`ssz_types` (out of SEC-6 scope).

None of these reopen the library-vs-hand-typed go/no-go.

---

## 3. Container inventory

### 3.1 Four body variants

| # | Variant | Fork layout | Body fields (count) | Notes |
|---|---------|-------------|---------------------|--------|
| 1 | `BeaconBlockBodyElectra` | Electra / Fulu | **13** | Production full block; **prototype done** |
| 2 | `BlindedBeaconBlockBodyElectra` | Electra / Fulu | **13** | `execution_payload` → `ExecutionPayloadHeader`; MEV sign path; type seeded |
| 3 | `BeaconBlockBodyDeneb` | Deneb | **12** | No `execution_requests`; same payload shape as Electra |
| 4 | `BlindedBeaconBlockBodyDeneb` | Deneb | **12** | Blinded + no `execution_requests` |

Fulu shares Electra body layout (already classified in `body_fork_layout`).

### 3.2 Electra full body field list (spec order)

```text
BeaconBlockBodyElectra
  0  randao_reveal:              BLSSignature                          // Bytes96
  1  eth1_data:                  Eth1Data
  2  graffiti:                   Bytes32
  3  proposer_slashings:         List[ProposerSlashing, 16]
  4  attester_slashings:         List[AttesterSlashing, 1]              // Electra limit
  5  attestations:               List[Attestation, 8]                   // Electra limit
  6  deposits:                   List[Deposit, 16]
  7  voluntary_exits:            List[SignedVoluntaryExit, 16]
  8  sync_aggregate:             SyncAggregate
  9  execution_payload:          ExecutionPayload                       // full
 10  bls_to_execution_changes:   List[SignedBLSToExecutionChange, 16]
 11  blob_kzg_commitments:       List[KZGCommitment, 4096]
 12  execution_requests:         ExecutionRequests                      // Electra+
```

Blinded Electra: field 9 is `ExecutionPayloadHeader` instead of `ExecutionPayload`.

Deneb: drop field 12; attester/attestation list limits are pre-Electra (`MAX_ATTESTER_SLASHINGS=2`, `MAX_ATTESTATIONS=128`) and attestation container lacks `committee_bits`.

### 3.3 Shared sub-containers

| Container | Fields (summary) | Used by |
|-----------|------------------|---------|
| `Eth1Data` | deposit_root, deposit_count, block_hash | all bodies |
| `ProposerSlashing` | 2× `SignedBeaconBlockHeader` | all |
| `SignedBeaconBlockHeader` / `BeaconBlockHeader` | 5-field header + sig | slashings |
| `AttesterSlashingElectra` | 2× `IndexedAttestationElectra` | Electra bodies |
| `IndexedAttestationElectra` | List[u64, 131072], data, sig | Electra slashings |
| `AttestationElectra` | Bitlist[131072], data, sig, Bitvector[64] | Electra bodies |
| `AttestationData` / `Checkpoint` | phase0 attestation data | attestations |
| `Deposit` / `DepositData` | proof Vector[33], data | all |
| `SignedVoluntaryExit` / `VoluntaryExit` | epoch, index + sig | all |
| `SyncAggregate` | Bitvector[512], BLSSignature | all |
| `ExecutionPayload` | 17 fields incl. txs/withdrawals/blob gas | full bodies |
| `ExecutionPayloadHeader` | 17 fields; txs/withdrawals → roots | blinded bodies |
| `Withdrawal` | index, validator_index, address, amount | payload |
| `Transaction` | ByteList[2^30] | payload |
| `SignedBlsToExecutionChange` / `BLSToExecutionChange` | Capella change + sig | all |
| `KZGCommitment` | Bytes48 | Deneb+ |
| `ExecutionRequests` | deposits / withdrawals / consolidations lists | Electra+ |
| `DepositRequest` | pubkey, creds, amount, sig, index | requests |
| `WithdrawalRequest` | address, pubkey, amount | requests |
| `ConsolidationRequest` | address, source/target pubkey | requests |

### 3.4 Mainnet limits (typenum)

| Limit | Value |
|-------|------:|
| MAX_PROPOSER_SLASHINGS | 16 |
| MAX_ATTESTER_SLASHINGS_ELECTRA | 1 |
| MAX_ATTESTATIONS_ELECTRA | 8 |
| MAX_DEPOSITS | 16 |
| MAX_VOLUNTARY_EXITS | 16 |
| MAX_BLS_TO_EXECUTION_CHANGES | 16 |
| MAX_BLOB_COMMITMENTS_PER_BLOCK | 4096 |
| SYNC_COMMITTEE_SIZE | 512 |
| MAX_TRANSACTIONS_PER_PAYLOAD | 1_048_576 |
| MAX_BYTES_PER_TRANSACTION | 1_073_741_824 |
| MAX_WITHDRAWALS_PER_PAYLOAD | 16 |
| MAX_DEPOSIT_REQUESTS_PER_PAYLOAD | 8192 |
| MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD | 16 |
| MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD | 2 |
| MAX_VALIDATORS_PER_COMMITTEE × MAX_COMMITTEES_PER_SLOT | 131_072 |

---

## 4. Prototype proof

**Module:** [`crates/eth-types/src/block_body.rs`](../../crates/eth-types/src/block_body.rs)

**Test:** `test_electra_body_htr_matches_external_vector`

| Item | Value |
|------|--------|
| Oracle | **`remerkleable`** (Python SSZ reference; independent of rvc) |
| Object | Electra `BeaconBlockBody`, deterministic fields (empty op lists; fixed graffiti / eth1 / payload scalars) |
| Expected root | `0x58953d11e9b51a6e95c8c70ca51b7ad6b6e557a91caab298a71688dfab9e4870` |
| Result | **Exact match** |
| Network in tests | **None** — root + field construction vendored in the test |

Supporting KATs (same oracle): empty list roots at limits 16/1/8/4096; `Eth1Data`, `SyncAggregate`, `ExecutionPayload`, `ExecutionRequests` component roots.

---

## 5. Point re-estimate (SEC-6b / 6c / 6d)

Spike **narrowed** the range: type surface for Electra full + blinded is already seeded; remaining work is decode, wiring, Deneb deltas, fixtures.

| Issue | Plan floor | Plan ceiling | **Spike re-estimate** | Rationale |
|-------|----------:|-------------:|----------------------:|-----------|
| SEC-6b | 3 | 6 | **3** | Containers largely written; focus = `Vec<u8>` → typed decode + polish / non-empty list vectors |
| SEC-6c | 3 | 3 | **3** | Wire body leaf in `BeaconBlock`/`BlindedBeaconBlock` + block-level external vector + fixture updates |
| SEC-6d | 2 | 4 | **2–3** | Blinded type exists; Deneb = drop `execution_requests` + pre-Electra attestation limits/types + fixtures |
| **Cluster** | **11** | **16** | **11–12** | Stay at plan expected value; ceiling only if Decode path is painful or Deneb attestation types bloat |

**Do not** reopen library adoption mid-phase without a separate spike: upgrading to unified `ssz`/`tree_hash` 0.10+ is a workspace dependency project, not SEC-6.

---

## 6. SEC-6b entry checklist

- [x] Design go/no-go committed (this note)
- [x] Container inventory (four variants + sub-containers)
- [x] Electra full body HTR matches external vector
- [x] `Vec<u8>` SSZ decode → `BeaconBlockBodyElectra` (round-trip) — SEC-6b
- [x] Replace `vec_u8_tree_hash_root(&body)` body leaf (SEC-6c)
- [x] Blinded + Deneb external vectors (SEC-6d)

---

## 7. Risks carried forward

1. **Decode vs dual `ethereum_ssz` 0.8/0.9** — see §2.3; schedule inside SEC-6b, not a design flip.  
2. **Root changes for identical inputs** — any fixture hard-coding the old non-spec root breaks in SEC-6c (expected).  
3. **Deneb attestation schema** differs (no `committee_bits`, different list limits) — inventory above; implement in 6d, not by forking Electra types incorrectly.
