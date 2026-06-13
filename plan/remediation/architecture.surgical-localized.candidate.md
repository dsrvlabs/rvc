# Software Architecture: rs-vc Remediation (Surgical-Localized Candidate)

**Optimization target:** SURGICAL-LOCALIZED — minimal blast radius per finding.
**Source PRD:** `plan/remediation/prd.md` (46 verified findings, 1 Critical / 13 High / 13 Medium / 14 Low / 5 Info).
**Source research:** `plan/remediation/research/{00-overview,01-ssz-domain-correctness,02-slashing-remote-signer-dvt,03-doppelganger-protection,04-bn-trust-boundary}.md`.
**Date:** 2026-06-13.
**Status:** Candidate, pre-review.

---

## Overview

This architecture is a **remediation overlay** on the existing 23-crate Rust validator-client workspace, not a new design. The PRD's non-goals (§2) explicitly forbid broad rearchitecture; the optimization target ("surgical-localized") forbids it twice. The existing module boundaries (each crate already a single-responsibility unit, owning its data, communicating through typed Rust APIs and tokio channels) are treated as load-bearing and preserved verbatim. Every one of the 46 findings is mapped to the smallest possible edit set inside the crate(s) the PRD already identifies as the defect owner. The architecture's job here is not to redraw module boundaries — it is to **prove that the boundaries are already correct**, to **forbid any cross-cutting refactor that would inflate blast radius**, and to **justify each shared-helper introduction explicitly** against a single-crate-edit baseline.

Three shared-helper introductions are justified inline against the surgical baseline (a GVR canonicalizer for GVR-1, the `IsSigningEnabled` trait centralization for D-3, and an `update_validator_indices` setter for DT-1). Three more (KS-1 effective-cost gate, URL-1 deny-list extension, URL-2 pinned-resolver pattern) are kept inside their existing owner crates with no new shared module. Everything else is a pure intra-crate edit. The rollout is keyed to PRD milestones M1 (slashing-safety floor), M2 (duty correctness floor), M3 (hardening + P2 cleanup), with ADRs documenting where the surgical baseline was deliberately overridden and why.

---

## Architecture Principles

In addition to the project defaults, these principles drive every design decision in this candidate. They are listed first because they are the load-bearing decision criteria for every "small fix vs new module" trade-off below.

- **P1 — Smallest patch wins.** For each finding, the baseline option is an intra-crate edit inside the file(s) the PRD already names. A shared helper, new module, or new trait is introduced **only** when the same fix must land in two or more crates' code paths to be correct. This is logged as an ADR with the "small patch" alternative explicitly listed and rejected.
- **P2 — Crate boundaries are sacred during remediation.** No finding may move a type or function from one crate to another, even if the new home looks "cleaner." Boundary changes are deferred to a post-remediation pass.
- **P3 — One finding, one branch, one focused diff.** The PRD's TDD discipline (§6.1) already requires RED+GREEN+REFACTOR per finding. Architecturally, this means each finding's blast radius is bounded by the smallest reviewable diff that closes the finding's RED test. Refactor commits are **forbidden** from touching unrelated code.
- **P4 — Cluster fixes share a branch only when the cluster's fixes share a file or function.** PRD §7.1 clusters are honored, but they only justify combining commits onto one branch when the GREEN diffs literally overlap (e.g. GVR-1 + IMP-1 both edit `SlashingDb::import`). Otherwise the cluster is a *sequencing* hint, not a *combine-the-diffs* mandate.
- **P5 — Fail-closed is a property of the edit, not a new module.** PRD §6.3's fail-closed discipline lands as a one-line change inside each owner crate, not as a new "policy" module. A reviewer must be able to locate every fail-closed gate in the diff of the owning crate.
- **P6 — Spec-vector fixtures live with their consuming crate.** E-1 / E-2 / B-1 / KG-1 fixtures land in the crate that contains the failing function, not in a new shared `fixtures/` crate. Cross-checking against Lighthouse/Lodestar is a CI/test artifact, not an API surface.
- **P7 — No new workspace dependencies.** PRD §2 forbids new deps unless a fix has no in-tree alternative. Architecturally, this means every fix must be expressible with the existing `Cargo.toml` graph; the `serial_test` for Info-5 is the only candidate even worth proposing, and the alternative (env-mutex) is preferred per ADR-009.
- **P8 — No circular dependencies, full stop.** Every proposed change is checked against the current crate-dependency DAG (Section "Module Dependency Graph") before landing. If a fix would induce a cycle, the fix is redesigned, not the DAG.

---

## System Context Diagram

The remediation does not change the system's external surface except where a finding explicitly requires it (SS-1, KM-3, EXIT-1). The context diagram below is therefore the **post-remediation** diagram; deltas from today are flagged inline.

```text
                ┌──────────────────────────────────────────┐
                │       rs-vc validator-client workspace    │
                │                                           │
   Validator    │  ┌────────────┐    ┌────────────┐         │     ┌──────────────┐
   operator ───▶│  │  bin/rvc   │───▶│ orchestr.  │────────▶│────▶│  Beacon node │
   (CLI)        │  │ main loop  │    │ (crates/rvc)│        │     │  (untrusted) │
                │  └─────┬──────┘    └──────┬─────┘         │     └──────┬───────┘
                │        │                  │               │            │
                │   Keymgr-API (axum)   slot loop / duties  │            │
                │        │                  │               │       SSE events
                │        ▼                  ▼               │            ▼
   Operator ───▶│  ┌────────────┐    ┌────────────┐         │    ┌──────────────┐
   tooling      │  │ keymanager │    │bn-manager  │◀────────│────│  Beacon node │
   (POST keys) ─▶│  │  -api      │    │ (sync/SSE) │         │   │  (multi-BN)  │
                │  └─────┬──────┘    └────────────┘         │   └──────────────┘
                │        │                                  │
                │        ▼                                  │
                │  ┌────────────┐    ┌────────────┐         │    ┌──────────────┐
                │  │ slashing   │◀───│  signer    │◀────────│────│ rvc-signer   │
                │  │  DB (SQLite│    │ (typed)    │  gRPC   │    │  (standalone │
                │  │ owned by 1 │    │ owned by 1 │ (mTLS)  │    │ signer bin)  │
                │  │ crate)     │    │ crate)     │         │    └──────┬───────┘
                │  └────────────┘    └────────────┘         │           │ BLS sign
                │                                           │           ▼
                └───────────────────────────────────────────┘   ┌──────────────┐
                                                                │ Remote KMS / │
                                                                │  HSM / DVT   │
                                                                │  peers       │
                                                                └──────────────┘
```

Deltas the remediation introduces, all behavior-only, no shape change:

- **SS-1:** `rvc-signer` no longer registers the v1 raw-root `SignerServiceServer` on the live listener. The arrow from "external gRPC client → rvc-signer" loses its v1 endpoint; the v2 typed-RPC endpoint is unchanged.
- **KM-3:** `keymanager-api` non-loopback bind requires `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true` (same gate shape as the existing metrics-server gate).
- **EXIT-1:** Voluntary-exit CLI subcommands gain a precondition arrow to the Beacon node (`get_genesis()`) before any signing occurs.

Everything else — module count, transport choices, persistence boundaries — is preserved.

---

## Module Overview

The workspace already contains exactly the module boundaries this remediation needs. The table below lists every crate touched by at least one finding, with a column showing how many findings each crate owns and the maximum-blast-radius for any single fix inside that crate. **No new crates are created.**

| Module (crate)              | Responsibility (one-sentence)                                                                 | Owns Data                                          | Depends On (workspace)                                | Findings owned        | Max blast radius per fix              |
|-----------------------------|-----------------------------------------------------------------------------------------------|----------------------------------------------------|-------------------------------------------------------|-----------------------|---------------------------------------|
| `eth-types`                 | SSZ container types, fork constants, tree-hash helpers, domain types                          | none (pure types)                                  | (workspace root)                                      | E-1, E-2, Info-4 (partial) | 1 file (`tree_hash_utils.rs` or `block.rs`) |
| `crypto`                    | BLS keys, keystore, signing primitives, remote-signer client, insecure-mode gate              | none (in-memory key material; zeroized)            | `eth-types`                                            | L-1, L-2, KS-1 (helper), URL-2 (signer side), Info-5 (insecure tests) | 1 file per finding                    |
| `slashing`                  | EIP-3076 slashing-DB, interchange import/export, staging API                                  | `slashing.sqlite` (SOT)                            | `crypto`, `eth-types`, `metrics`                       | DVT-1 (schema), CN-1, GVR-1, IMP-1, L-3, Info-1, Info-2 | 1 function (`SlashingDb::import` or `stage::*`) |
| `signer` (lib)              | Typed `SignerService` with stage→sign→commit                                                  | none (delegates to `slashing`, `crypto`)           | `slashing`, `crypto`, `eth-types`, `metrics`           | (consumer of D-3 centralization) | 1 method (or 1 trait impl)            |
| `doppelganger`              | Forward-window detection + liveness consultation                                              | none (queries `slashing` for past attestations)    | `crypto`, `eth-types`                                  | D-1, D-2 (+ S-3 wiring) | `service.rs` only                     |
| `validator-store`           | Per-validator enable gate, config persistence                                                 | per-validator config file                          | `crypto`, `eth-types`                                  | D-3 (gate semantics + rename), VS-1 (fsync) | 1 function                            |
| `keymanager-api`            | HTTP keymanager (POST/DELETE/LIST keys; remote keys; URL validation)                          | keystore files; remote-key registry                | `crypto`, `slashing`, `eth-types`, `metrics`           | KM-1, KM-2, URL-1, URL-2 (validator side), KS-1 (gate) | 1 handler or 1 helper file            |
| `bn-manager`                | Multi-BN sync status, SSE, broadcast                                                          | per-BN in-memory state                             | `beacon`, `crypto`, `eth-types`                        | BN-1, BN-2, SSE-1     | 1 method (`tier`, `check_sync_status`, `sse.rs`) |
| `beacon`                    | Beacon-node HTTP client, SSZ deserialization                                                  | none                                               | `eth-types`                                            | Info-4 (boundary validation), Info-5 (dead API delete) | 1 function                            |
| `block-service`             | Block proposal pipeline (assembly, signing, publish)                                          | none                                               | `beacon`, `builder`, `crypto`, `eth-types`, `signer`, `validator-store` | B-1/T-1, L-9 (un-ignore tests) | 1 function (`publish`)                |
| `sync-service`              | Sync-committee message + contribution production                                              | none                                               | `beacon`, `crypto`, `eth-types`                        | SYNC-1                | 1 method                              |
| `builder`                   | Builder-API registration cache + refresh                                                      | in-memory registration cache                       | `crypto`, `eth-types`                                  | BLD-1                 | 1 method                              |
| `duty-tracker`              | Attester/proposer/sync duty cache; refreshable indices                                        | duty caches                                        | `beacon`, `eth-types`                                  | DT-1                  | constructor + 1 setter                |
| `rvc` (lib)                 | Orchestrator (slot loop, duty management, signing dispatch); keymanager adapters; startup     | none (composes services)                           | almost all `crates/*`                                  | S-2, S-5, C-1, L-4    | wire-up sites only (no new logic)     |
| `grpc-signer`               | gRPC remote-signer client (Web3Signer-compatible)                                             | none                                               | `crypto`, `eth-types`                                  | GRPC-1/2/3            | 1 file (`client.rs`)                  |
| `telemetry`                 | OTLP endpoint config + secret redaction                                                       | none                                               | (none)                                                 | TEL-1                 | 1 function                            |
| `timing`                    | Slot-clock arithmetic                                                                          | none                                               | `eth-types`                                            | TIM-1                 | 1 function                            |
| `secret-provider`           | GCP/file secret backend                                                                       | none                                               | `crypto`                                               | SP-1, Info-5 (GCP zeroize) | 1 method per finding                  |
| `bin/rvc-signer`            | Standalone signer process (gRPC server, DVT, audit, slashing-scope, TLS)                      | composes `slashing`, `crypto`                      | `crypto`, `slashing`, `eth-types`                      | **SS-1, SS-2/SS-3, DVT-1 (call site), DVT-2..5, SIG-1** | 1 file per finding                    |
| `bin/rvc-keygen`            | Key-generation CLI (mnemonics, deposit, BLS-to-execution, exit)                               | output files                                        | `crypto`, `eth-types`                                  | KG-1, KG-2, KG-3      | 1 file per finding                    |
| `bin/rvc`                   | Main VC process (orchestrator wiring, HTTP keymanager bind, monitoring)                       | composes the workspace                              | almost all `crates/*`                                  | KM-3, EXIT-1, S-2, S-3, S-5 (wire), L-5, Info-3, Info-5 | wire-up sites only                    |
| `metrics`                   | Prometheus metric definitions                                                                  | none                                                | (workspace root)                                       | (no findings; recipients of new counters) | — |
| `propagator`                | Beacon broadcast / re-broadcast (publish helpers)                                              | none                                                | `beacon`, `eth-types`                                  | (no findings)         | —                                     |

Crates not appearing above (`metrics`, `propagator`) are untouched by any finding and are listed for completeness only.

**Surgical observation:** 16 of the 22 crates that own at least one finding own ≤ 2 findings and the fix for each lives in **one file**. The remaining 6 (`slashing`, `keymanager-api`, `bin/rvc-signer`, `bin/rvc`, `bin/rvc-keygen`, `bn-manager`) each own several findings but the findings inside a crate are themselves independent files, so the per-fix blast radius is still bounded by one file.

---

## Module Dependency Graph

The current crate-dependency DAG (derived from each `Cargo.toml`) is reproduced verbatim and annotated with the findings that touch each edge or node. The graph has no cycles today; this remediation introduces no new edges and therefore preserves the acyclic property.

```text
                                  eth-types  (E-1, E-2, Info-4)
                                      ▲
                                      │ (used by every consumer crate below)
                                      │
                                  crypto    (L-1, L-2, KS-1 helper, URL-2 signer)
                                      ▲
              ┌────────────────────┬──┴───┬───────────────────────┬────────────────────┐
              │                    │      │                       │                    │
          slashing             timing   secret-provider        beacon            keymanager-api
   (DVT-1, CN-1, GVR-1,         (TIM-1) (SP-1, Info-5 GCP)   (Info-4, Info-5)   (KM-1, KM-2,
   IMP-1, L-3, Info-1/2)            │                              │              URL-1, URL-2,
              ▲                     │                              │              KS-1 gate)
              │                     │                              │
          signer  ────────► validator-store          builder    bn-manager   doppelganger
        (D-3 trait                  (D-3 gate,        (BLD-1)    (BN-1,         (D-1, D-2,
         centralization)             VS-1 fsync)                 BN-2,SSE-1)    S-3 wiring)
              ▲                                                       ▲
              │                                                       │
        block-service                                              sync-service
        (B-1/T-1, L-9)                                              (SYNC-1)
              ▲
              │
              │  (consumed by orchestrator crate "rvc" which sits above all of the above)
              ▼
            rvc lib  (S-2, S-5, C-1, L-4)
              ▲
              │
              │  (composed by binaries)
              │
       ┌──────┴──────────────┐
       │                     │
   bin/rvc                bin/rvc-signer            bin/rvc-keygen
   (KM-3, EXIT-1,         (SS-1, SS-2/3,            (KG-1, KG-2, KG-3)
   S-2 wire,              DVT-1 call site,
   S-3, L-5, Info-3)      DVT-2..5, SIG-1)

         grpc-signer (GRPC-1/2/3)
         telemetry   (TEL-1)
         (both leaf nodes consumed by bin/rvc; no findings introduce edges)
```

**Cycle check:** None. Every arrow points from a higher-level crate (consumer) down to a lower-level crate (provider). No remediation edge in this candidate (the D-3 trait, the GVR canonicalizer, the `update_validator_indices` setter) reverses or shortcuts an arrow.

**Specifically, the three new shared elements:**

1. **`crypto::canonicalize_gvr` (or `slashing::canonical::parse_gvr_hex` re-exported)** — used by `slashing` (already there as `parse_gvr_hex`) and consumed by `bin/rvc` exit subcommands (EXIT-1) and by `keymanager-api` import path (GVR-1's case-equality fix). The function lives in the lowest-level crate that already needs it (`slashing`, since `parse_gvr_hex` is already there). Consumers reach it through the existing `slashing` dep edges. No new edge.
2. **`signer::IsSigningEnabled` trait (or `validator_store::SigningGate` trait) for D-3** — defined in the crate that already owns the gate's data (`validator-store`), consumed by `signer` (which already depends on `validator-store` transitively through `crates/rvc` orchestrator; we add a direct `validator-store` dep to `signer` to make it explicit — this is allowed, no cycle is created). The orchestrator no longer re-checks the gate; it trusts the signer's centralized check. **One new edge introduced: `signer → validator-store`.** This edge is verified acyclic: `validator-store` depends on `crypto + eth-types` and nothing above it.
3. **`duty-tracker::DutyTracker::update_validator_indices` setter** — pure intra-crate API addition. No new edge. Wired from `bin/rvc` keymanager-import code path (which already depends on `duty-tracker`).

The single edge addition (`signer → validator-store`) is the only graph mutation in this candidate. It is justified in ADR-002 below.

---

## Module Details

For each crate that owns at least one finding, the details below specify: (a) the data it owns, (b) the public API change (if any) the remediation introduces, (c) the new events / signals (almost always: none — this is a remediation, not a feature add), (d) the per-finding edit locations, and (e) the failure modes around each edit. Crates that own a single finding with a one-file edit are described compactly; crates that own a cluster or a centralization move are detailed.

---

### Module: `eth-types`

**Responsibility:** SSZ types, fork constants, tree-hash helpers, domain constants.

**Data Store:** none — pure types.

**Public API change (remediation only):** none. All fixes are internal corrections to existing functions.

**Per-finding edits:**

| ID  | File / function                                      | Edit                                                                                                              | Blast radius |
|-----|------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|--------------|
| E-1 | `src/block.rs:333-379`, `src/tree_hash_utils.rs`      | Replace the `List[byte]`-style body leaf with the real `hash_tree_root(BeaconBlockBody)` per active fork.          | 1 file       |
| E-2 | `src/tree_hash_utils.rs:16-42`, `src/aggregation.rs:20,105` | Replace `next_power_of_two(bytes)` with the SSZ chunk-count limit `(N+255)/256` for `Bitlist[N]`.            | 1 file       |
| Info-4 | `src/...` boundary types                            | Add 32-byte/4-byte hex validation to GVR / fork-version deserializers.                                            | 1 file       |

**Spec-vector fixtures:** `crates/eth-types/tests/fixtures/{bellatrix,capella,deneb,electra}/...` per PRD §6.2. Fixtures sourced from `ethereum/consensus-spec-tests` at the active spec tag.

**Failure modes:**
- An `E-1` regression would land if a future fork-name table addition forgets to call the new container hasher. Mitigation: the spec-vector test runs `BeaconBlock::tree_hash_root()` per fork; new forks must add a fixture.
- An `E-2` regression would land if a new `Bitlist[N]` is introduced with the wrong `N`. Mitigation: the chunk-count is a function of `N` at the type level; a `static_assert`-style proptest is added.

---

### Module: `slashing`

**Responsibility:** EIP-3076 slashing DB, interchange import/export, the `stage`/`commit` API used by the typed `signer`.

**Data Store:** SQLite at `slashing.sqlite` (workspace SOT for EIP-3076 watermarks and per-row signed roots). Schema: `metadata`, `attestations(client_cn, pubkey, source_epoch, target_epoch, signing_root)`, `blocks(client_cn, pubkey, slot, signing_root)`. **Schema migration required by DVT-1 + CN-1** (see below).

**Public API change (remediation only):** Three small public additions; no removals.

1. **`SlashingDb::canonical_gvr_hex(&str) -> Result<Root, SlashingError>`** — promote the existing crate-private `parse_gvr_hex` to a public, re-exportable function. **This is the GVR canonicalizer the PRD §7.1 cluster (GVR-1 + IMP-1) requires.** The function already exists; only its visibility changes (from `pub(crate)` to `pub`). No new file.
2. **`SlashingDb::pubkey_scope()` (DVT-1 + CN-1 schema move):** the existing `stage_block` / `stage_attestation` keep their signatures, but the WHERE clauses in `stage.rs:340-378` and `stage.rs:500-510` drop the `client_cn` predicate. The `client_cn` column is retained (audit-trail only); SELECT-existence and watermark queries scope by `pubkey + genesis_validators_root` only. An idempotent migration runs at `SlashingDb::open` if the legacy `(client_cn, pubkey, slot)` row pattern is detected.
3. **`SlashingDb::import` (GVR-1 + IMP-1):** the body of `import()` (lines 938-1005) gains (a) GVR canonicalization both sides before string comparison, (b) `source_epoch <= target_epoch` validation, (c) conflicting-root detection that raises the watermark instead of silently dropping (`INSERT OR IGNORE` → `INSERT…ON CONFLICT…DO UPDATE` with a slashable-history marker).

**Events published:** none (slashing is a pure datastore; no async events emitted).
**Events consumed:** none.

**Per-finding edit map:**

| ID    | File / function                            | Edit                                                                                              | Blast radius |
|-------|--------------------------------------------|---------------------------------------------------------------------------------------------------|--------------|
| DVT-1 | `src/stage.rs:340-378, 500-510`, `src/db.rs` migration | Drop `client_cn` from WHERE; add open-time migration; preserve column for audit.                   | 2 functions + migration |
| CN-1  | (same as DVT-1)                            | Same physical edit; CN-1 is the non-DVT analogue closed by the same WHERE-clause change.           | (shared with DVT-1) |
| GVR-1 | `src/db.rs:950-955`                        | Replace string equality with `Self::canonical_gvr_hex(...)` on both sides.                         | 1 function   |
| IMP-1 | `src/db.rs:960-995`                        | Add `source>target` reject; replace `INSERT OR IGNORE` with conflict-aware upsert.                 | 1 function   |
| L-3   | `src/db.rs:292-312, 1562-1585`             | Validate at pin time; document all-zeros sentinel handling.                                        | 1 function   |
| Info-1 | `src/db.rs:769-870, 1036-1095`            | Delete or delegate `is_safe_to_propose`/`is_safe_to_sign` to the production stage path.            | 2 functions  |
| Info-2 | `src/db.rs:1222-1226, 1481-1486`          | Drop or assert per-row `genesis_validators_root` column.                                           | 1 schema change |

**Schema migration design (DVT-1 + CN-1, sequenced first inside this crate):**

A single `SlashingDb::open` startup step runs once: detect legacy schema by querying for any row whose `client_cn != 'local-vc'` (i.e. a per-CN namespaced row from the multi-tenant signer path). If such rows exist, rewrite their `client_cn` to a deterministic marker (`'pre-cn1-migration'`) and ensure the new pubkey-only uniqueness invariant holds (insert new aggregate watermark rows from the most-extreme legacy row per pubkey). Migration is idempotent (a marker row in `metadata` records that migration ran). Regression test: a captured pre-migration DB fixture is migrated and the new WHERE clause correctly rejects a double-sign across the legacy CN boundary.

**Failure modes:**
- If migration fails partway, the transaction rolls back; `open()` returns an error. Operators get a clear "schema migration failed" message and the DB is unchanged.
- If GVR canonicalization rejects a valid interchange (e.g. an unexpected hex variant), import fails closed (per §6.3) and the operator must re-emit the interchange with a normalized GVR. This matches the PRD KM-1 fail-closed posture.

---

### Module: `signer` (library crate)

**Responsibility:** typed `SignerService` with the stage→sign→commit pattern; the centralization point for D-3 in this candidate.

**Data Store:** none (delegates to `slashing`).

**Public API change (remediation only):**

1. **New trait `IsSigningEnabled`** (D-3 centralization):
   ```rust
   pub trait IsSigningEnabled: Send + Sync {
       fn is_signing_enabled(&self, pubkey: &[u8; 48]) -> bool;
   }
   ```
   Lives in `crates/signer/src/traits.rs` (the file already exists). Default-deny for unknown pubkeys is enforced by every implementor; the trait's contract documents this.
2. **`SignerService::with_gate(self, gate: Arc<dyn IsSigningEnabled>)`** builder method. Every slashable-message sign method (attestation, block, aggregate-and-proof, sync-committee message, sync-committee selection-proof, contribution-and-proof) checks `gate.is_signing_enabled(&pubkey_bytes)` **before** the stage→sign→commit triple. The check returns `Err(SignerError::SigningDisabledByDoppelganger)` if false.
3. **Non-slashable methods (randao-reveal, voluntary-exit, builder-registration, selection-proof) skip the gate check** by default; an operator-facing flag (or a per-method override in the trait) can opt them in if Teku-parity gating across all classes is desired. Current PRD acceptance criterion D-3(a) names four paths (`maybe_propose_block`, `filter_sync_duties`, `maybe_produce_aggregations`, attestation), so the candidate gates exactly those at this layer.

**Why centralize here, not in the orchestrator?** PRD assumption #6 prefers centralization; research §03 confirms Lighthouse centralizes in `validator_store + doppelganger_service` (analogous layer). The surgical argument: 4 orchestrator entry points × N future-added paths = N future regressions if the gate is scattered. One central check in `SignerService` = one place to add a future signing path. This is the *only* place in the candidate where centralization is preferred to a scatter-fix, and the trade-off is logged in ADR-002.

**Per-finding edit map:**

| ID  | File / function                                                    | Edit                                                                  | Blast radius |
|-----|--------------------------------------------------------------------|------------------------------------------------------------------------|--------------|
| D-3 | `src/lib.rs` (sign_attestation, sign_block, sign_aggregate_and_proof, sign_sync_committee_message, sign_sync_committee_selection_proof, sign_contribution_and_proof), `src/traits.rs` | Add `IsSigningEnabled` check at the head of each method. | 6 methods + 1 trait |

**Failure modes:** if the gate panics (it must not — implementors are required to be infallible), the panic is caught by `tokio::task::spawn_blocking`'s join-error path and the sign request returns `Err`. Fail-closed.

---

### Module: `doppelganger`

**Responsibility:** forward-window detection + liveness consultation against the Beacon node, with restart-awareness.

**Data Store:** none.

**Public API change (remediation only):**

1. `DoppelgangerService::run_monitoring` (line 166-258) gains a **forward** epoch range. Current code observes only past epochs (`base_epoch = current_epoch.saturating_sub(1)`); D-1 requires also blocking signing until `monitoring_epochs` future epochs pass without `is_live`. The forward window is tracked by adding a `forward_window_end: Option<Epoch>` to the per-pubkey state and returning `DetectionInProgress` until `current_epoch >= forward_window_end`.
2. `LivenessChecker` trait remains; D-2 lands inside `run_monitoring` (lines 207-242) by treating any missing index in the response as "inconclusive → keep blocked" (fail-closed).

**Per-finding edit map:**

| ID  | File / function                  | Edit                                                                                          | Blast radius |
|-----|----------------------------------|-----------------------------------------------------------------------------------------------|--------------|
| D-1 | `src/service.rs:166-258`         | Add forward-window state + epoch check.                                                       | 1 method     |
| D-2 | `src/service.rs:207-242`         | Replace fail-open on missing entries with fail-closed.                                        | 1 block      |

S-3 (P2) is closed at the **call site** in `bin/rvc/src/main.rs:1264-1287` by removing the `if current_epoch > 0` guard; this crate's pre-genesis logic at `service.rs:130` already handles epoch 0 safely. S-3 is therefore a 1-line edit in `bin/rvc`, not in `doppelganger`.

**Failure modes:** liveness query failure → fail-closed (validator stays blocked, error logged). Network partition during the forward window → forward window does not advance, validator stays blocked until liveness resumes.

---

### Module: `validator-store`

**Responsibility:** per-validator runtime state (enable flag, fee recipient, gas limit, block-selection mode); persists per-validator config to disk.

**Data Store:** per-validator config files in the configured store dir; in-memory `HashMap<[u8; 48], ValidatorConfig>`.

**Public API change (remediation only):**

1. **Rename `is_attesting_enabled` → `is_signing_enabled`** (PRD assumption #7). The old name remains as a `#[deprecated]` re-export for one release to ease the in-tree rename diff; the new name is the trait-impl method for `IsSigningEnabled`.
2. **Flip default for unknown pubkeys to `false`** (line 218-220): `unwrap_or(true)` → `unwrap_or(false)`. PRD acceptance criterion D-3(b) requires fail-closed.
3. **Implement `signer::IsSigningEnabled` for `ValidatorStore`**: trivial wrapper around the new `is_signing_enabled`. This is the single new edge `signer → validator-store` is created to support; see ADR-002.

**Per-finding edit map:**

| ID  | File / function                  | Edit                                                                          | Blast radius |
|-----|----------------------------------|-------------------------------------------------------------------------------|--------------|
| D-3 | `src/store.rs:218-220`           | Rename + flip default + impl `IsSigningEnabled`.                              | 1 method + 1 trait impl |
| VS-1 | `src/store.rs:343-346`          | After atomic rename, `File::open(parent)?.sync_all()?`.                       | 1 function   |

**Failure modes:**
- Fail-closed flip: any orchestrator path that signed for an "unknown" pubkey today (no real path should — the orchestrator only sees keys from its `pubkey_map`) would now fail. Per S-2's fix, the orchestrator's `pubkey_map` is the source of truth and is populated at startup + on keymanager import.
- VS-1 fsync failure: `persist()` returns `Err`, the in-memory state remains correct, operator sees the error. Acceptable per fail-closed discipline.

---

### Module: `keymanager-api`

**Responsibility:** HTTP keymanager (POST/DELETE/LIST keys; remote keys; URL validation for remote signers).

**Data Store:** keystore files; in-memory remote-key registry. Slashing-protection data lives in `slashing` crate's SQLite DB (we never store it here).

**Public API change (remediation only):** none on the HTTP surface; behavior changes inside existing handlers.

**Per-finding edit map:**

| ID    | File / function                                | Edit                                                                                                                 | Blast radius |
|-------|------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|--------------|
| KM-1  | `src/handlers.rs:244-313`                      | Replace `unwrap_or_else(|e| empty_interchange())` with a hard error: return 500, **no deletions performed**.         | 1 handler    |
| KM-2  | `src/handlers.rs:160-195, 259-272`             | `map.insert` cancels displaced token; one lock across delete's two steps; prune on window-elapse.                     | 1 file       |
| URL-1 | `src/url_validator.rs:84-121`                  | Extend deny-list with 0.0.0.0/8, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, multicast; IPv6 normalize IPv4-compat. | 1 function   |
| URL-2 | `src/url_validator.rs:29-70` + `crypto/remote_signer.rs:157` | Validated IP pinned via `reqwest::resolve_to_addrs` for the long-lived signing connection. The crypto side is part of the same fix unit; see §7.1 cluster. | 2 files in 2 crates (URL-1+URL-2 share a branch) |
| KS-1  | `src/keymanager_adapters.rs:185-190` (gate call site) | Add the effective-cost gate before decrypt: reject when `n * r * 128` exceeds 1 GiB; per-field maxima aligned to EIP-2335. Gate helper lives in `crypto::keystore` (see crypto entry below). | 1 call site  |

**Why URL-2 sits across two crates:** the validation lives here, but the long-lived `reqwest::Client` that uses the resolved IP is in `crypto/remote_signer.rs`. The fix has to land in both for the pinning to be effective. The shared element is *configuration data passed in*, not a new module. The two edits land on one branch per PRD §7.1 cluster "Remote signer transport hardening".

**Failure modes:**
- KM-1 hard error: a transient SQLite error during export now fails the entire DELETE; operator can retry. Compared to current behavior (silently lose slashing protection), this is strictly safer.
- URL-1 / URL-2 reject a legitimate but unusual deployment (e.g. an internal IPv6 ULA): the operator must update their allow-list. Documented in operator release notes (PRD §12).

---

### Module: `bn-manager`

**Responsibility:** multi-BN sync status, SSE event stream, broadcast helpers.

**Data Store:** per-BN in-memory state (`sync_distance`, `is_optimistic`, `is_syncing`, last poll timestamp).

**Per-finding edit map:**

| ID   | File / function                                | Edit                                                                                              | Blast radius |
|------|------------------------------------------------|---------------------------------------------------------------------------------------------------|--------------|
| BN-1 | `src/sync_status.rs:65-83, 155-178`            | `tier()` caps optimistic node at Unsynced for EL-dependent duties; orchestrator-side reject of optimistic produce/attestation responses (the orchestrator side is wired in `bin/rvc`). | 1 method     |
| BN-2 | `src/sync_status.rs:90-92, 65-67`, `manager.rs:257-338` | Synchronous `check_sync_status()` before serving duties; `Unknown` no longer falls through to `synced_indices`. | 2 methods    |
| SSE-1 | `src/sse.rs:173-178, 297-307`                 | Channel + consumer task created inside the reconnect path **or** callback wrapped in `catch_unwind`. | 1 file       |

**Failure modes:**
- BN-1 / BN-2 reject during startup: orchestrator waits for first successful sync poll; PRD M2 covers the startup-window regression test.
- SSE-1 callback panic: caught, logged, channel reconstructed; events resume on the next reconnect.

---

### Module: `bin/rvc-signer` (standalone signer binary)

**Responsibility:** standalone gRPC signing process (BLS sign for any caller with mTLS); composes `slashing`, `crypto`, optional DVT peer service. This binary owns the largest number of P0 findings (SS-1, SS-2/SS-3, DVT-1 call site).

**Data Store:** none (delegates to `slashing`).

**Per-finding edit map:**

| ID    | File / function                                                   | Edit                                                                                                                                       | Blast radius |
|-------|-------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| SS-1  | `src/main.rs:439, 507`, `src/service.rs:234-312`                  | Remove `add_service(SignerServiceServer::new(svc_v1))`. The v1 service impl stays compiled but returns `Status::unimplemented()` unless an opt-in legacy-bind flag is set. | 1 call site + 1 service impl |
| SS-2/SS-3 | `src/service.rs:698-740`                                     | `sign_aggregate_and_proof` no longer calls `require_db()`/`ScopedSlashingDb`/`stage_attestation`; signs directly via `backend.sign`.        | 1 handler    |
| DVT-1 | `src/dvt/peer_service.rs:244, 377`, **+ `crates/slashing/src/stage.rs` schema move** | Call sites updated to pass pubkey-scope only; the actual WHERE-clause change lives in `crates/slashing` (see slashing entry).        | 2 call sites + slashing change |
| DVT-2 | `src/dvt/peer_client.rs:217, 276-280`, `src/main.rs:506-520`      | Migrate to v2 typed RPCs; delete v1 raw-root server impl.                                                                                  | 1 file       |
| DVT-3 | `src/backend/dvt.rs:166-244`                                      | Verify each partial against its share pubkey before inclusion; combine over a chosen valid threshold subset; drop and retry on failure.   | 1 function   |
| DVT-4 | `src/dvt/peer_client.rs:227-237, 287-293`                         | Pin expected `share_index` per peer; reject mismatches.                                                                                    | 1 file       |
| DVT-5 | `src/dvt/lagrange.rs:25-45, 58-92`                                | Reject `index == 0` in combine; validate at load/allow-list time.                                                                          | 1 file       |
| SIG-1 | `src/main.rs:666-678`                                             | Implement per-keystore `<dir>/<pubkey>.txt` lookup; or shared file with `trim_end_matches('\n')`. PRD assumption #5 picks per-keystore.    | 1 function   |

**SS-1 design note (per PRD §10 Q1):** the v1 service impl in `service.rs:234-312` is **not deleted**; only the `add_service` call is removed. The impl's handlers are rewritten to return `Status::unimplemented()` so that any compiled but never-registered reference is safe. An optional opt-in flag (`RVC_SIGNER_ENABLE_LEGACY_V1=true` + a separate-bind requirement) is documented as the operator escape hatch, **off by default**. This matches PRD acceptance criterion SS-1(b).

**SS-2/SS-3 chain-of-custody (per research §02 R5):** the safety of removing slashing-DB consultation from `sign_aggregate_and_proof` rests on the assumption that the inner `Attestation` was already signed via `sign_attestation` through the slashing-DB path. A comment block at the top of the rewritten handler restates this invariant, and the integration test (PRD M3 aggregator flow) attests-then-aggregates and asserts the attestation row exists in the DB before the aggregate is signed.

**Failure modes:**
- SS-1: if a stale v1 client tries to call `sign(signing_root, pubkey)`, it gets `Unimplemented` and must upgrade to v2.
- DVT-1: the schema migration in `slashing` is a hard dependency; if migration fails, the signer fails to start. Acceptable.

---

### Module: `bin/rvc-keygen`

**Responsibility:** key-generation CLI (mnemonics, deposit data, BLS-to-execution-change, voluntary exit).

**Per-finding edit map:**

| ID   | File / function                              | Edit                                                                                                                    | Blast radius |
|------|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|--------------|
| KG-1 | `src/bls_to_execution.rs:51-59, 144`         | Build domain with `GENESIS_FORK_VERSION`. **Delete or invert the test** `test_bls_to_execution_uses_capella_fork_version` (research §01 R3 — it pins the bug). | 1 file (call + tests) |
| KG-2 | `src/new_mnemonic.rs:182-220`                | Treat `FAILED`/`MISMATCH` as a hard error; skip deposit-data emission for the affected validator.                       | 1 function   |
| KG-3 | `src/new_mnemonic.rs:123-127`, `src/bls_to_execution.rs:67`, `src/exit.rs:42` | All three call sites use `DirBuilder::new().recursive(true).mode(0o700)`.                                              | 3 call sites (1-line each) |

**Failure modes:**
- KG-1: previous outputs from `rvc-keygen` for `bls-to-execution-change` are invalid (wrong fork version) and **must be regenerated**. Release-notes call-out (PRD §12).
- KG-2: a verification failure now exits non-zero. Operator must investigate before continuing.

---

### Module: `bin/rvc`

**Responsibility:** main VC process — orchestrator wiring, keymanager-API bind, monitoring/RSS, voluntary-exit subcommands.

**Per-finding edit map:**

| ID   | File / function                                                                  | Edit                                                                                                                                  | Blast radius |
|------|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|--------------|
| KM-3 | `src/main.rs:1417-1429`                                                          | Apply the same `InsecureGate(Refuse)` pattern used by metrics: `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true` required for non-loopback.    | 1 wire site  |
| EXIT-1 | `src/commands/voluntary_exit.rs:93-142`, `src/commands/prepare_exit.rs:76-125` | Fetch `get_genesis()` from connected BN; verify GVR + genesis time before signing.                                                    | 2 commands   |
| S-2  | `src/main.rs:1432-1435, 1467-1470, 1522-1536`                                    | Create real `(key_gen_tx, key_gen_rx)`; pass `pubkey_map.clone()` + `key_gen_tx.clone()` to both keymanager adapters.                  | wire-up only |
| S-3  | `src/main.rs:1264-1287`                                                          | Remove `if current_epoch > 0` guard.                                                                                                  | 1 line       |
| L-5  | `crates/rvc/monitoring.rs:88-90`                                                 | (lives in `crates/rvc`) Check `> 0` before casting; `saturating_mul`; apply to `_SC_CLK_TCK`.                                          | 1 function   |
| Info-3 | `crates/rvc/monitoring.rs:104-109, 77-90`                                       | macOS query current RSS; `/proc/self/stat` split after last `)`.                                                                       | 1 file       |
| Info-5 (metrics bind) | `src/main.rs:1629-1634`                                             | Log + surface metrics bind/serve error instead of silently swallowing.                                                                 | 1 line       |
| CLI-1 | `src/main.rs:280-299`                                                            | Add `*-token-file` / env intake mirroring `--password-file`.                                                                          | 1 arg group  |

**Failure modes:**
- KM-3 startup fail-closed: operators relying on a non-loopback bind must set the env var. Documented in release notes.
- EXIT-1 BN reach: voluntary-exit subcommands now require BN reachability. Acceptable per PRD assumption (operator runs the BN they're exiting against).

---

### Module: `crates/rvc` (lib)

**Responsibility:** orchestrator (slot loop, duty management, attestation/aggregation/sync-committee dispatch); keymanager adapters; startup.

**Per-finding edit map:**

| ID  | File / function                                                                       | Edit                                                                                                       | Blast radius |
|-----|---------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|--------------|
| S-5 | `src/orchestrator/slot_context.rs:40-60`, `src/orchestrator/sync_committee.rs:62-71, 145-154` | `get_block_root("head")` or fallback to slot N-1.                                                          | 1 method     |
| C-1 | `src/orchestrator/coordinator.rs:317-320, 147, 181, 211, 278`                         | Replace `has_changed()` without consume with `borrow_and_update()`; or drive via `select!` on `changed()`. | 1 function   |
| L-4 | `src/orchestrator/aggregation.rs:130-181`                                             | Apply `validate_attestation_data` before computing root and signing.                                       | 1 function   |
| (D-3 wire — no new code here) | (every orchestrator entry point that today calls `is_attesting_enabled`)      | Update to call `is_signing_enabled` if the orchestrator-side check is kept as a defense-in-depth; otherwise rely on the centralized `SignerService` gate (ADR-002). | rename only |

**Note on D-3 in the orchestrator:** PRD acceptance criterion D-3(a) "preferably centralized in the signer/typed-signer layer." The candidate's ADR-002 chooses centralization. The orchestrator still calls `is_signing_enabled` as a fast-path skip-the-RPC optimization, but the **authoritative** gate is in `SignerService`. Removing the orchestrator-side check entirely is a possible follow-up; for the surgical-localized optimization target, we keep both as belt-and-suspenders — the orchestrator-side check is renamed (`is_attesting_enabled` → `is_signing_enabled`) but not deleted.

---

### Modules with single-finding, one-file edits (compact entries)

| Crate            | ID(s)                  | File / function                                                  | Edit                                                                                                                |
|------------------|------------------------|------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| `crypto`         | L-1                    | `src/remote_signer.rs:35-42`                                     | Compare normalized `parsed.scheme()` against `"https"`.                                                              |
| `crypto`         | L-2                    | `src/pubkey.rs:54-58`                                            | `strip_prefix_strict`, validate even-length hex, real error type.                                                    |
| `crypto`         | KS-1 (helper)          | `src/keystore.rs:41-44, 198-251`                                 | Memory-estimate helper corrected; effective-cost gate exposed for `keymanager-api` to call before decrypt.           |
| `crypto`         | URL-2 (signer side)    | `src/remote_signer.rs:157`                                       | Use IP-pinned `reqwest::Client` (via `resolve_to_addrs`); re-validate deny-list inside connection path on every sign.|
| `crypto`         | Info-5 (insecure tests)| `src/insecure.rs:249-330`                                        | Serialize env-mutating tests with an env-mutex (no new dep).                                                         |
| `block-service`  | B-1/T-1, L-9           | `src/service.rs:287-385, 370-382, 2597-2622, 2641-2661`          | Bound published bytes at `kzg_offset`; serialize Deneb+ as proper `SignedBlockContents`; un-ignore L-9 tests.        |
| `beacon`         | Info-4 (boundary)      | `src/client.rs:250-256, 338-343, 402-435`                        | Validate 32-byte / 4-byte hex at the boundary; validate `Eth-Consensus-Version` against known fork names.            |
| `beacon`         | Info-5 (dead API)      | `src/ssz_deser.rs:115-143`                                       | Delete dead `extract_block_header_from_ssz` or bound it at `kzg_offset`.                                             |
| `secret-provider`| SP-1                   | `src/refresh.rs:54-67`                                           | Drop name-derived early-skip; dedupe by derived pubkey; validate `pubkey_hex`.                                       |
| `secret-provider`| Info-5 (GCP zeroize)   | `src/gcp.rs:49-62`                                               | Zeroize the SDK-buffered payload after extracting the secret.                                                        |
| `duty-tracker`   | DT-1                   | `src/tracker.rs:63-82, 91-95, 181-185, 297-301, 419-423`         | `RwLock<Vec<String>>` (or `ArcSwap`); add `update_validator_indices` setter wired from `bin/rvc` keymanager paths.   |
| `builder`        | BLD-1                  | `src/service.rs:88-106, 215-227`                                 | Re-register on bounded cadence regardless of content change; refresh embedded `timestamp` each time.                 |
| `sync-service`   | SYNC-1                 | `src/lib.rs:251-260`                                             | Validate BN-returned `subcommittee_index`/`slot`/`beacon_block_root`; skip+warn on mismatch.                          |
| `grpc-signer`    | GRPC-1/2/3             | `src/client.rs:115-159, 183-188, 124-159, 291-302`               | `tls_enabled` computed from actual branch; require all three TLS fields together; add `connect_timeout` + per-RPC deadline. |
| `telemetry`      | TEL-1                  | `src/config.rs:95-108`                                           | Parse with `url::Url`; strip user info; redact known-sensitive query keys.                                           |
| `timing`         | TIM-1                  | `src/clock.rs:52-54, 97-106`                                     | Mirror `as_millis()` arithmetic from `time_until_attestation`.                                                       |

**Each row above is exactly one branch, one finding, one file, one RED+GREEN+REFACTOR triple, per principle P3.**

---

## Cross-Cutting Concerns

The remediation does not introduce any new cross-cutting subsystem. The PRD's cross-cutting requirements (§6) land as discipline applied at the per-fix branch level, not as architectural mechanisms.

### Authentication & Authorization
Unchanged by the remediation, with two behavior-only deltas:
- **KM-3:** keymanager-API non-loopback bind requires explicit env-var opt-in (no new authn/authz code; the existing `InsecureGate(Refuse)` pattern from the metrics-server bind is reused at the bind site).
- **SS-1:** v1 raw-root gRPC sign endpoint is **unregistered** (not made authenticated; removed). The v2 typed endpoint's mTLS authn is unchanged.

### Logging & Observability
Structured logging via `tracing` is the existing standard; no change. Minor metric additions per fix (e.g. KM-1 export-error counter, BN-1 optimistic-rejection counter) live inside the owning crate's existing metrics definitions in `crates/metrics`.

### Error Handling
The PRD §6.3 fail-closed discipline lands as **per-fix one-liners** inside each owning crate, not as a new error infrastructure. The Rust `Result<T, E>` propagation pattern already in use is sufficient. No new error wrapper crates or error-conversion helpers are introduced.

### Configuration
Existing config plumbing is preserved. Two env vars added (`RVC_KEYMANAGER_ALLOW_NON_LOOPBACK`, optional `RVC_SIGNER_ENABLE_LEGACY_V1`); both follow the existing `RVC_*_ALLOW_*` naming convention.

### TDD discipline & spec-vector fixtures
Cross-cutting per PRD §6.1 and §6.2. Fixtures live in the consuming crate's `tests/fixtures/` directory; no new central fixtures crate (per principle P6).

---

## Data Flow Diagrams

Three flows where the remediation changes data flow are below. All other flows are unchanged.

### Flow 1 — Block proposal (E-1 + B-1/T-1 corrected path, post-M2)

```text
slot loop ─▶ orchestrator.maybe_propose_block(slot)
              ├─ SignerService.is_signing_enabled(pubkey)? ──no──▶ skip (D-3)
              ▼ yes
            beacon.produce_block_v3(slot) ──▶ BlockContents { block, kzg_proofs, blobs }
              ▼
            block-service.assemble(block) ──▶ BeaconBlock with corrected body leaf (E-1)
              ▼
            signer.sign_block(block_root, slot, ...)
              ├─ slashing.stage_block(...)
              ├─ crypto.sign(signing_root, pubkey)
              └─ stage.commit()
              ▼
            block-service.publish(signed_block, kzg, blobs)
              ├─ Deneb+: serialize as SignedBlockContents (3 offsets, bounded block, kzg, blobs) (B-1/T-1)
              └─ pre-Deneb: serialize signed block, bounded at end-of-block
              ▼
            beacon.publish(bytes) ──▶ Beacon node
```

### Flow 2 — Runtime keymanager import (S-2 + DT-1 + C-1 + KM-2 wired)

```text
POST /eth/v1/keystores ─▶ keymanager-api.import_keystores
              ▼
            keystore_manager.add_keystore(decrypted)
              ▼
            doppelganger_monitor.start_monitoring(pubkey)  (KM-2: cancel any stale token)
              ▼
            validator_manager.add_validator(pubkey, enabled=false)  (D-3: starts disabled inside window)
              ▼
            key_gen_tx.send(pubkey)  ──▶  (real channel, S-2)
              ▼
            orchestrator.coordinator: key_gen_rx.borrow_and_update()  (C-1)
              ├─ clear_cache() once (no re-clear next slot)
              └─ duty_tracker.update_validator_indices(new_indices)  (DT-1)
              ▼
            on next refresh: duty_tracker.fetch_duties_for_epoch(epoch)
              └─ duties include the new validator's index
              ▼
            doppelganger.run_monitoring(pubkey, ...) (D-1 forward window)
              └─ after window elapses with no liveness:
                 validator_manager.set_enabled(pubkey, true)
              ▼
            next slot signs with the new key
```

### Flow 3 — Voluntary exit with GVR validation (EXIT-1)

```text
CLI: rvc voluntary-exit --validator-pubkey 0xab... (--network optional)
              ▼
            commands/voluntary_exit.rs::run
              ├─ beacon.get_genesis()  (NEW; was missing)
              │   ├─ effective_gvr      ──▶ canonicalize_gvr(gvr) (uses slashing::parse_gvr_hex)
              │   └─ effective_genesis_time
              │
              ├─ if user supplied --genesis-validators-root, compare; mismatch ──▶ Err (fail-closed)
              ▼
            signer.sign_voluntary_exit(exit, pubkey, fork_schedule, effective_gvr)
              ▼
            propagator.submit_voluntary_exit(...) ──▶ Beacon node
```

---

## Infrastructure & Deployment

### Deployment Model

Unchanged. The workspace remains a Cargo workspace with three binaries (`bin/rvc`, `bin/rvc-keygen`, `bin/rvc-signer`). The deployment target is unchanged (operator-managed processes; no container/serverless changes implied by any finding). The "monolith vs services" trade-off is **out of scope** per PRD §2.

### Scaling Strategy

No scaling changes. Every fix is a behavior change inside an existing module; the throughput characteristics of the validator client are preserved.

### Rollout & Sequencing (replaces "Service Extraction Path")

The PRD's milestones M1 / M2 / M3 already define a phased rollout; this section maps every finding to the milestone it ships in and lists the **per-milestone "shared work" that must land first** so subsequent branches don't churn.

#### M1 — Slashing-safety floor (PRD §11)

**Shared pre-work (lands on a `prep/M1-shared` branch before any fix branch):**
- Promote `slashing::parse_gvr_hex` to `pub` (1-line visibility change) — needed by GVR-1 and EXIT-1 even though EXIT-1 is M2 (we still want the helper public from M1 to keep the EXIT-1 diff trivial).
- Add the `signer::IsSigningEnabled` trait (compiles to zero behavior change; no consumers yet).
- Add the `signer → validator-store` Cargo dep (one line in `crates/signer/Cargo.toml`).

**Fix branches (one branch per finding):**

| Order | Finding | Branch                                       | Files touched (max blast radius)                              |
|-------|---------|----------------------------------------------|---------------------------------------------------------------|
| 1     | SS-1    | `fix/SS-1-remove-v1-raw-root`                | `bin/rvc-signer/src/{main,service}.rs`                        |
| 2     | KM-1    | `fix/KM-1-delete-fail-closed`                | `crates/keymanager-api/src/handlers.rs`                       |
| 3     | DVT-1+CN-1 (combined per §7.1 cluster) | `fix/DVT-1-CN-1-pubkey-scope` | `crates/slashing/src/{stage,db}.rs`, `bin/rvc-signer/src/dvt/peer_service.rs` |
| 4     | D-1     | `fix/D-1-forward-window`                     | `crates/doppelganger/src/service.rs`                          |
| 5     | D-2     | `fix/D-2-fail-closed-missing-liveness`       | `crates/doppelganger/src/service.rs`                          |
| 6     | D-3     | `fix/D-3-centralize-gate`                    | `crates/signer/src/{lib,traits}.rs`, `crates/validator-store/src/store.rs` |
| 7     | KM-2    | `fix/KM-2-cancel-token-race`                 | `crates/keymanager-api/src/handlers.rs`                       |
| 8     | S-3     | `fix/S-3-epoch-0-dop`                        | `bin/rvc/src/main.rs`                                         |

**M1 exit gate:** all of the above merged FF-only to `develop`; CI green; `cargo test` covers each RED→GREEN; an EIP-3076 enumeration test (PRD M4) on the registered gRPC methods is included in `bin/rvc-signer` test suite.

#### M2 — Duty correctness floor (PRD §11)

**Shared pre-work:**
- Land spec-vector fixtures under `crates/eth-types/tests/fixtures/` and `crates/block-service/tests/fixtures/` (sourced from `consensus-spec-tests` per PRD §6.2). One commit per fork; deliberately separate from any fix branch.

**Fix branches:**

| Order | Finding(s)         | Branch                                       | Files touched (max blast radius)                              |
|-------|--------------------|----------------------------------------------|---------------------------------------------------------------|
| 1     | E-1                | `fix/E-1-body-container-hash`                | `crates/eth-types/src/{block,tree_hash_utils}.rs`             |
| 2     | E-2                | `fix/E-2-bitlist-chunk-count`                | `crates/eth-types/src/{tree_hash_utils,aggregation}.rs`       |
| 3     | B-1+T-1+L-9 (cluster) | `fix/B-1-T-1-blockcontents`               | `crates/block-service/src/service.rs`, `crates/beacon/src/ssz_deser.rs` |
| 4     | KG-1               | `fix/KG-1-bls-to-execution-gvr`              | `bin/rvc-keygen/src/bls_to_execution.rs`                      |
| 5     | SS-2+SS-3 + L-4 (cluster — aggregator correctness) | `fix/aggregator-correctness` | `bin/rvc-signer/src/service.rs`, `crates/rvc/src/orchestrator/aggregation.rs` |
| 6     | BN-1               | `fix/BN-1-optimistic-tier`                   | `crates/bn-manager/src/sync_status.rs`                        |
| 7     | BN-2               | `fix/BN-2-startup-sync`                      | `crates/bn-manager/src/{sync_status,manager}.rs`              |
| 8     | DT-1 + S-2 + C-1 (cluster — runtime import) | `fix/runtime-import`        | `crates/duty-tracker/src/tracker.rs`, `bin/rvc/src/main.rs`, `crates/rvc/src/orchestrator/coordinator.rs` |
| 9     | S-5                | `fix/S-5-sync-head-root`                     | `crates/rvc/src/orchestrator/{slot_context,sync_committee}.rs`|
| 10    | SSE-1              | `fix/SSE-1-callback-isolation`               | `crates/bn-manager/src/sse.rs`                                |
| 11    | GVR-1 + IMP-1 (cluster — slashing import) | `fix/slashing-import`         | `crates/slashing/src/db.rs`                                   |
| 12    | KG-2               | `fix/KG-2-verify-hard-fail`                  | `bin/rvc-keygen/src/new_mnemonic.rs`                          |
| 13    | EXIT-1             | `fix/EXIT-1-gvr-cross-check`                 | `bin/rvc/src/commands/{voluntary_exit,prepare_exit}.rs`       |
| 14    | BLD-1              | `fix/BLD-1-refresh-cadence`                  | `crates/builder/src/service.rs`                               |
| 15    | SYNC-1             | `fix/SYNC-1-validate-contribution`           | `crates/sync-service/src/lib.rs`                              |
| 16    | KS-1               | `fix/KS-1-effective-cost-gate`               | `crates/crypto/src/keystore.rs`, `crates/keymanager-api/src/keymanager_adapters.rs` |

**M2 exit gate:** block proposal succeeds end-to-end against a spec-compliant BN for every fork (PRD M2); aggregator duty succeeds for real-committee `aggregation_bits` (PRD M3); runtime import is observably end-to-end working (PRD M7).

#### M3 — Hardening + P2 cleanup (PRD §11)

**Shared pre-work:** none.

**Fix branches:** all remaining P2 findings (KM-3, URL-1+URL-2 cluster, VS-1, plus L-1, L-2, L-3, L-4 [already in M2 via aggregator cluster — re-confirm], L-5, DVT-2, DVT-3, DVT-4, DVT-5, KG-3, SIG-1, SP-1, TIM-1, GRPC-1/2/3, CLI-1, TEL-1, and the four Info-5 sub-items). Each on its own branch per principle P3, except clusters per PRD §7.1 (URL-1+URL-2; remote-signer transport-hardening sequence).

**M3 exit gate:** all 46 findings closed (PRD M1, M8); release notes drafted (PRD §12).

### Per-module readiness for service extraction

Out of scope. The PRD non-goals (§2) forbid microservice extraction; this section is replaced by the rollout above per the task brief.

---

## Technology Choices

No changes. All choices below are inherited from the existing workspace and are not revisited in this remediation. The table is included only because the architect template requires it.

| Concern              | Choice                                          | Rationale (unchanged from current workspace)                                                 |
|----------------------|-------------------------------------------------|----------------------------------------------------------------------------------------------|
| Language             | Rust 2021, edition `2021`, MSRV 1.92            | Existing workspace.                                                                          |
| Async runtime        | Tokio 1                                         | Existing workspace.                                                                          |
| HTTP framework       | Axum 0.7 (keymanager-API)                       | Existing.                                                                                    |
| gRPC                 | Tonic 0.12 + Prost 0.13                         | Existing (rvc-signer + rvc orchestrator).                                                    |
| HTTP client          | reqwest 0.12 (rustls)                           | Existing; URL-2 leverages `resolve_to_addrs` for IP pinning.                                 |
| Persistence          | SQLite (rusqlite 0.32 bundled) — slashing only  | Existing; PRD §9 forbids slashing-DB format changes; we add a forward-only migration.        |
| Per-validator config | atomic file rename + new VS-1 parent fsync      | Existing pattern; VS-1 corrects a durability gap.                                             |
| BLS                  | blst 0.3                                         | Existing.                                                                                    |
| SSZ                  | ethereum_ssz 0.9 + ssz_derive 0.9               | Existing.                                                                                    |
| Tree hash            | tree_hash 0.9 + tree_hash_derive 0.9            | Existing; E-1 and E-2 stay inside the existing helper module.                                |
| Telemetry            | tracing + opentelemetry                         | Existing.                                                                                    |
| Metrics              | prometheus 0.14                                  | Existing.                                                                                    |
| DVT                  | vsss-rs 5.3 + bls12_381_plus 0.8 (`dvt` feature) | Existing; DVT-1..5 stay inside `bin/rvc-signer`.                                              |
| CLI                  | clap 4                                           | Existing.                                                                                    |

**Net new dependencies introduced by this candidate: zero.** The PRD §2 non-goal "Adding new dependencies unless a fix has no in-tree alternative" is satisfied without exception.

---

## ADRs (Architecture Decision Records)

Each ADR records a place where the surgical-localized default was deliberately overridden, or a where a non-trivial choice was made between equally surgical alternatives.

### ADR-001: Promote `parse_gvr_hex` to a public canonicalizer instead of duplicating it
- **Status:** Accepted.
- **Context:** GVR-1 (`slashing::import` string-equality bug) and EXIT-1 (`bin/rvc` voluntary-exit BN cross-check) both need to canonicalize a GVR before comparing it to a pinned value. The function already exists as `parse_gvr_hex` at `crates/slashing/src/db.rs:292-312`.
- **Decision:** Change visibility from `pub(crate)` to `pub`. Re-export from `crates/slashing/src/lib.rs`. `bin/rvc` exit subcommands call `slashing::parse_gvr_hex(...)`; `keymanager-api` does **not** import it directly (it stays inside `slashing::import` via the change there).
- **Alternatives considered:**
  - **Duplicate the function** in `crates/crypto` or `bin/rvc`. Rejected: two implementations of the same canonicalization is exactly the GVR-1 bug, restated.
  - **Move to `eth-types`.** Rejected: violates principle P2 (no cross-crate type moves during remediation).
  - **Create a new `gvr-canonical` crate.** Rejected as cartoonish blast-radius inflation: a 21-line function does not need a crate.
- **Consequences:** the function becomes part of `slashing`'s public API; future schema changes that touch GVR storage still go through one function. Maintenance cost: zero.

### ADR-002: Centralize the doppelganger signing gate in `crates/signer` via a new `IsSigningEnabled` trait
- **Status:** Accepted.
- **Context:** D-3 closure requires every slashable-message signing path to consult the doppelganger gate. PRD §10 Q4 and PRD assumption #6 prefer centralization in the signer layer. The orchestrator-level "scatter the check at every entry point" alternative is more surgical per fix but multiplies regression risk every time a new signing path is added.
- **Decision:** Introduce `signer::IsSigningEnabled` trait (one trait, one method, in `crates/signer/src/traits.rs`). Implement it for `validator_store::ValidatorStore` (in `crates/validator-store/src/store.rs`). Add a `signer → validator-store` Cargo dep edge. Every slashable-message sign method in `SignerService` checks the gate at the head of the method. The orchestrator-side check is **renamed** but not removed (defense in depth; fast-path skip).
- **Alternatives considered:**
  - **Scatter the check in 4 orchestrator paths only.** Rejected per research §03: Lighthouse centralizes in `validator_store`; future paths (sync-committee selection-proof was not on the PRD's enumerated list of four but is slashable-adjacent) would silently bypass a scattered gate.
  - **Put the trait in `eth-types`.** Rejected: trait depends on `[u8; 48]` only; living in `signer` is correct since `signer` already imports `validator-store` for type definitions in some test paths.
  - **Use a function pointer instead of a trait.** Rejected: less testable; `IsSigningEnabled` is mockable.
- **Consequences:** one new Cargo edge (`signer → validator-store`). DAG checked acyclic above. Future signing paths added to `SignerService` get the check for free (they call the trait method or fail to compile).

### ADR-003: Run DVT-1 + CN-1 as a single forward-only schema migration with an idempotent open-time step
- **Status:** Accepted.
- **Context:** PRD §7.2 calls out the schema-migration risk: changing the WHERE clauses from `(client_cn, pubkey, ...)` to `(pubkey, ...)` interacts with existing on-disk DBs. PRD §10 Q3 leaves the production-DB assumption open.
- **Decision:** Assume production DBs exist (the safer assumption). Implement an idempotent open-time migration inside `SlashingDb::open`: detect legacy rows (`client_cn != 'local-vc'`), rewrite to `'pre-cn1-migration'`, insert aggregate watermarks per pubkey, mark `metadata.migrated_cn1 = true`. Backup is the operator's responsibility; release notes call this out.
- **Alternatives considered:**
  - **Force the operator to re-import from interchange.** Rejected: defeats forward-only goal; operators would face downtime.
  - **Keep the per-CN namespace and add a pubkey-global override check.** Rejected: extra schema complexity; future maintenance cost; doesn't actually shrink blast radius (we'd still need a WHERE-clause change).
- **Consequences:** the `slashing` crate's `open` path gains one new code path that runs once per DB lifetime. Regression test uses a captured pre-migration DB fixture.

### ADR-004: Keep the SS-1 v1 service compiled but unregistered (return `Unimplemented`)
- **Status:** Accepted (matches PRD §10 Q1 default).
- **Context:** PRD asks whether to delete the v1 raw-root impl entirely or leave it compiled returning `Unimplemented`. Deletion is surgically purest; leaving it compiled is the recommended fix per the source review.
- **Decision:** Remove the `add_service` call. Rewrite the v1 handlers in `service.rs:234-312` to return `Status::unimplemented`. Document an off-by-default operator opt-in (`RVC_SIGNER_ENABLE_LEGACY_V1=true` + a separately-bound, loopback-only listener) for emergency rollback; this opt-in is **not implemented** in M1; it is only documented.
- **Alternatives considered:**
  - **Delete the v1 impl entirely.** Rejected: leaves the operator no escape hatch if an unknown integrator depends on v1; the `Unimplemented` path is reviewable.
- **Consequences:** the v1 code lives on as ~30 lines of `Status::unimplemented`. Negligible maintenance.

### ADR-005: DT-1 `update_validator_indices` lives inside `duty-tracker`, no shared "key registry" crate
- **Status:** Accepted.
- **Context:** S-2 + DT-1 + C-1 + KM-2 form a cluster (PRD §7.1) for "dynamic key import end-to-end." A naive design might consolidate the in-memory pubkey/index registry into a new shared crate.
- **Decision:** Add `DutyTracker::update_validator_indices(&self, new_indices: Vec<String>)` (and switch the field to `RwLock<Vec<String>>` or `ArcSwap`). The keymanager-import path in `bin/rvc` calls this setter directly. No new crate; no new shared module.
- **Alternatives considered:**
  - **New `validator-registry` crate** wrapping `pubkey_map` + `validator_indices` + `validator-store`. Rejected: three crates already own pieces of this state coherently; consolidating them is a P2 refactor, not a P0 fix.
- **Consequences:** the new setter is one of two public additions in `duty-tracker` from this remediation (the other is internal). Reviewable in one file.

### ADR-006: URL-1 + URL-2 fix lives in two existing files (no new SSRF crate)
- **Status:** Accepted.
- **Context:** SSRF deny-list and DNS-rebinding pinning are conceptually shared concerns. A maximalist design might introduce a `crates/url-policy` crate.
- **Decision:** URL-1 stays in `keymanager-api::url_validator`. URL-2's pinning state crosses into `crypto::remote_signer`, but the validated `SocketAddr` is passed as configuration data into the existing `reqwest::Client` builder — no new shared validation module. Per PRD §7.1, the two findings land on one branch.
- **Alternatives considered:**
  - **New `crates/url-policy` crate** with a `UrlPolicy` trait. Rejected: only two call sites; the indirection cost dwarfs the benefit.
- **Consequences:** the URL-1 deny-list logic stays alongside the URL-1 test fixtures inside `keymanager-api`. URL-2's pinning logic stays alongside the long-lived remote-signer client in `crypto`.

### ADR-007: Keep the orchestrator-side `is_signing_enabled` check as defense-in-depth
- **Status:** Accepted.
- **Context:** ADR-002 centralizes the gate in `SignerService`. PRD acceptance criterion D-3(a) says "preferably centralized" — open whether the orchestrator-side check is then deleted.
- **Decision:** Rename only (orchestrator-side `is_attesting_enabled` calls become `is_signing_enabled`). Don't delete: a fast-path skip in the orchestrator saves an RPC/sign round-trip per slot when the gate is off, and provides defense-in-depth if a future contributor adds a signing path that bypasses `SignerService`.
- **Alternatives considered:**
  - **Delete every orchestrator-side check.** Rejected: increases per-slot RPC cost when the gate is off; removes a layer of safety.
- **Consequences:** two checks at two layers; both must agree to sign; either can independently reject.

### ADR-008: Spec-vector fixtures live with the consuming crate, not in a shared crate
- **Status:** Accepted (matches principle P6).
- **Context:** PRD §6.2 specifies fixture sources. A natural-looking design could put all fixtures in `crates/test-fixtures`.
- **Decision:** Each consuming crate owns its `tests/fixtures/`. E-1 fixtures live in `crates/eth-types/tests/fixtures/`; B-1 fixtures in `crates/block-service/tests/fixtures/`; KG-1 fixtures in `bin/rvc-keygen/tests/fixtures/`.
- **Alternatives considered:**
  - **`crates/spec-fixtures` shared crate.** Rejected: needless coupling; cross-crate test artifact ownership is harder to reason about; per principle P6.
- **Consequences:** some fixture content (e.g. a `BeaconBlockBody` byte vector) may exist in two crates' fixture dirs. Acceptable; the bytes are not large.

### ADR-009: Use a process-global env-mutex (no `serial_test`) for Info-5 insecure-tests
- **Status:** Accepted.
- **Context:** Info-5 (insecure.rs tests) mutates process-global env; tests race. `serial_test` is the natural fix but is a new workspace dependency.
- **Decision:** Add a `std::sync::Mutex<()>` at module scope in `crates/crypto/src/insecure.rs`'s test module; every env-mutating test acquires it. Zero new deps.
- **Alternatives considered:**
  - **`serial_test` crate.** Rejected per principle P7 (no new deps unless mandatory).
- **Consequences:** the test mutex is one line, plus a `lock` call at the head of each affected test. Future Info-5-style fixes use the same pattern.

### ADR-010: SS-2/SS-3 chain-of-custody invariant restated in code, not enforced by type
- **Status:** Accepted.
- **Context:** Research §02 R5 flags that removing slashing-DB consultation from `sign_aggregate_and_proof` is correct *only* because the inner attestation was already signed via `sign_attestation`. The invariant is implicit in EIP-3076 scoping and easy to lose to a future contributor.
- **Decision:** Restate the invariant as a top-of-function comment block + an integration test that attests-then-aggregates and asserts the attestation row exists in the DB before the aggregate sign.
- **Alternatives considered:**
  - **Type-level enforcement** (e.g. a `AggregateAndProof<Witnessed>` newtype proving an attestation has been signed). Rejected: scope creep; new type plumbed across many call sites.
- **Consequences:** the invariant is documented and tested but not type-checked. Acceptable; a future-pass invariant-typing exercise is out of scope.

---

## Assumptions

Recorded so a reviewer can correct any without re-deriving the candidate.

1. **PRD §10 Q1 — SS-1 v1 service kept compiled returning `Unimplemented`.** Matches PRD default. ADR-004.
2. **PRD §10 Q2 — DVT-1 pubkey-global slashing scope is primary; CN secondary as an audit-trail column.** Matches PRD default.
3. **PRD §10 Q3 — production on-disk slashing DBs exist; migration is automatic and idempotent.** Safer assumption. ADR-003.
4. **PRD §10 Q4 — D-3 gate centralized in `crates/signer`.** Matches PRD default. ADR-002.
5. **PRD §10 Q5 — `--password-dir` semantic is per-keystore `<dir>/<pubkey>.txt`.** Matches PRD default for SIG-1.
6. **PRD §10 Q6 — all P2 fixes ship in the same release as P0+P1 unless explicitly deferred.** Matches PRD default.
7. **PRD assumption #7 — rename `is_attesting_enabled` → `is_signing_enabled`; default-deny for unknown pubkeys.** Adopted in `validator-store` and propagated to all call sites via ADR-002.
8. **Research §00 R2 — the B-1/T-1 / L-9 fix may be partially landed.** The candidate's M2 branch sequence runs `cargo test -- --ignored` as the **first** step on `fix/B-1-T-1-blockcontents`; if the test is already green, the branch becomes a one-commit "un-ignore the test" change instead.
9. **Spec vectors from `ethereum/consensus-spec-tests`** at the active spec tag; cross-checked against Lighthouse/Lodestar for at least one fixture per fork (PRD §6.2). One commit per fork's fixture set.
10. **No new workspace deps.** Verified — every fix maps to existing deps.
11. **Doppelganger forward-window length unchanged** (~2 epochs); the configured value applies to D-1's forward window unchanged.
12. **KM-1 fixed by aborting the whole DELETE** (PRD assumption #9, re-anchored to `local_keystores.yaml` + EIP-3076 per research §02 R4 — *not* to the keymanager-APIs flows README's "atomicity" wording).
13. **Operator-facing release notes** (PRD §12) are drafted at M3 exit; the architecture itself does not produce them.

---

## Open Questions

Carried forward unchanged from PRD §10; this candidate does not resolve them.

- **Q1 (PRD §10 Q1)** — keep v1 compiled returning `Unimplemented` vs delete? Default applied (ADR-004); revisit if a downstream integrator surfaces.
- **Q3 (PRD §10 Q3)** — confirm production DB existence before M1 ships, so the ADR-003 migration is validated against a real captured fixture.
- **Q4 (PRD §10 Q4)** — confirm reviewer is comfortable with the `signer → validator-store` dep added in ADR-002 (the candidate's only new edge).
- **R7-related** — confirm "EIP-7657 Stagnant" downstream wording is updated wherever it appears in code comments and doc-strings during the relevant fix branches.

---

## Risks

| Risk                                                                                  | Likelihood | Impact | Mitigation                                                                                                       |
|---------------------------------------------------------------------------------------|------------|--------|------------------------------------------------------------------------------------------------------------------|
| Schema migration (ADR-003) fails on an operator's production DB                       | Low        | High   | Captured fixture-based regression test; release notes recommend backup; transactional rollback on failure.       |
| Centralized gate in `SignerService` (ADR-002) is bypassed by a future contributor adding a new sign method | Medium | High | Trait check at method head is the convention; PR template + CI lint suggested as follow-up (out of scope).     |
| Spec-vector fixtures (PRD §6.2) for a particular fork unavailable at M2 ship time     | Low        | Medium | Self-consistent test as fallback; cross-check fixture lands in a follow-up branch; PRD M2 not signed off until cross-check lands. |
| `signer → validator-store` dep added in ADR-002 creates a future cycle if `validator-store` adopts a `signer` type | Low | Medium | Documented in this architecture; reviewer enforces principle P8 on future PRs.                                  |
| Per-finding RED-first discipline (PRD §6.1) erodes if a fix is small enough to feel "obvious" | Medium | Medium | The pre-review gate (PRD §6.5) checks the RED commit existed and failed; this is the explicit reviewer responsibility. |
| URL-2 IP pinning breaks a deployment with a legitimately-rotating DNS A record (rare in this domain but possible) | Low | Medium | URL-1+URL-2 cluster ships with a documented operator escape (re-import remote-signer URL); release-notes call-out. |
| EXIT-1 BN unreachable at exit time (network partition) blocks exit                    | Medium | Low    | Documented as fail-closed posture; operator can run BN locally for exit ceremony.                                |
| Aggregator correctness cluster (M2 step 5) lands SS-2/SS-3 without the chain-of-custody invariant being visible to future maintainers | Low | High | ADR-010 mandates the comment + integration test; reviewer confirms both present in the GREEN commit.            |

---

## Architecture Quality Checklist (final pass)

- [x] **No circular dependencies between modules** — verified; only one new edge (`signer → validator-store`), DAG re-checked acyclic.
- [x] **Each module has a single, clear responsibility** — preserved from the existing workspace; no boundary moved.
- [x] **No shared databases** — `slashing.sqlite` is owned by exactly one crate (`slashing`); every other crate consumes through `SlashingDb` API.
- [x] **All inter-module communication goes through defined interfaces** — preserved; new `IsSigningEnabled` trait is the only new interface.
- [x] **Every module can be tested in isolation with mocked dependencies** — preserved; the new trait is `dyn`-friendly and mockable.
- [x] **Cross-cutting concerns are standardized, not reimplemented per module** — fail-closed is a per-fix discipline, not a new module; the GVR canonicalizer is reused across `slashing::import` and `bin/rvc` exit paths.
- [x] **Failure modes are defined** — per-module entries above and the Risks section.
- [x] **Service extraction path is clear** — replaced by Rollout & Sequencing per task brief.
- [x] **Data flow is traceable** — three changed flows are diagrammed; all other flows unchanged.
- [x] **Module count is justified** — 23 crates kept verbatim; zero added; zero removed.
- [x] **Each finding maps to the smallest possible edit set** — verified in Module Details tables (max blast radius column).
- [x] **Shared-helper introductions are explicitly justified** — three ADRs (ADR-001 GVR canonicalizer; ADR-002 `IsSigningEnabled`; ADR-005 `update_validator_indices`).
- [x] **All PRD §7.1 clusters reflected** — see Rollout & Sequencing per-milestone branch tables.
- [x] **Rollout keyed to PRD milestones M1-M3** — yes, with per-branch ordering and per-cluster shared pre-work.
