# Software Architecture: rs-vc Remediation — Defense-in-Depth Candidate

**Status:** Draft candidate, pre-review
**Date:** 2026-06-13
**Optimization goal:** Defense-in-depth — every safety invariant enforced at multiple independent
layers so that a single future regression cannot re-open a slashing or key-confidentiality hole.
**Source of truth:** `plan/remediation/prd.md` (46 findings); `plan/remediation/research/00-overview.md`
(verified consolidation); `docs/2026-06-13-adversarial-code-review.md` (review).
**Scope discipline:** This is a *remediation* architecture for an existing 23-crate workspace,
not a green-field design. Module boundaries reflect the current codebase. The architectural
move is to add **redundant safety enforcement layers** at the seams that matter, and to
promote the **test architecture** to a first-class concern. PRD §2 non-goals (no new RPCs, no
new key formats, no broad rearchitecture) are honored.

---

## Overview

rs-vc today has a single guarding layer at most safety boundaries. The 46 findings show that
when that single layer has a bug, the system silently produces (or could produce) a slashable
signature. The remediation does not move every responsibility into a single class; instead it
**adds at least one additional, independently-failing layer** at each safety-critical seam, so
that the simultaneous failure of two independent components is required to violate an invariant.

The two binding invariants are:

- **C1 — No slashable signature.** For every block/attestation signing path that reaches a
  private key, EIP-3076 must be consulted *and* the result of that consultation must be
  durable before the signature is released.
- **C2 — No key-confidentiality bypass.** Key-bearing code paths (keystore import/delete,
  remote-signer transport, password loading) must fail closed on any error.

The defense-in-depth instrument is a small set of typed **gate** abstractions (`SafetyGate`,
`SigningGate`, `ScopedSlashingDb`, `FailClosedDefault`) plus a **test architecture** that
*proves* via an enumeration test (SS-1 / PRD M4) that every registered signing path passes
through every required gate. The test architecture is its own module set, with its own
dependency graph, and no circular dependencies into the production graph.

---

## Architecture Principles

Beyond the defaults in the architect template:

- **P1 — Multiple independent enforcement per invariant.** Every safety invariant is enforced
  at ≥ 2 independent layers (logical check + structural guarantee, or runtime check + DB
  constraint). A bug in one layer leaves the other intact.
- **P2 — Fail-closed by construction.** Default values, `unwrap_or`, missing-key paths, and
  error returns on safety boundaries must encode the safe answer, not the permissive one.
  Encoded as the `FailClosedDefault` trait in `crates/signer`.
- **P3 — Single source of truth, multiple verifiers.** EIP-3076 logic lives in
  `crates/slashing` only; callers verify their use of it via spec-vector tests and via a
  registry-enumeration test. No second EIP-3076 implementation is reintroduced (Info-1
  acceptance).
- **P4 — Test code is architecture.** Spec-vector fixtures, the signer-path enumeration test,
  the fail-closed property suite, and the slashing-DB migration fixture are modules with
  defined responsibilities, owners, and a dependency graph.
- **P5 — Minimum behavioral surface change.** Only the behaviors mandated by findings change.
  No new public APIs, no new RPC surface, no rearchitected DBs (PRD §2 non-goals).
- **P6 — Scope by domain, not by binary.** A "safety invariant" is owned by exactly one
  module (slashing, doppelganger, key-confidentiality, transport-trust). Each binary
  (`rvc`, `rvc-signer`, `rvc-keygen`) re-uses, but does not re-implement, those modules.

---

## System Context Diagram

```text
                                  ┌──────────────────────────────────┐
                                  │      Validator operator (CLI)    │
                                  │  (rvc, rvc-signer, rvc-keygen)   │
                                  └──────────────┬───────────────────┘
                                                 │
                                                 ▼
┌────────────┐    keymanager-API (HTTPS)  ┌────────────────────────────┐  EIP-3076 import   ┌─────────────────┐
│  Operator  │ ──────────────────────────▶│            rvc             │ ◀───────────────── │  External VC    │
│   tools    │ ◀──────────────────────────│ (orchestrator + duty paths)│ ──────────────────▶│  (migration in) │
└────────────┘                            └───────┬──────────┬─────────┘                    └─────────────────┘
                                                  │          │
                                  Beacon-API      │          │  gRPC (mTLS, IP-pinned)
                                  (REST + SSE)    │          │
                                                  ▼          ▼
                                ┌────────────────────────┐  ┌──────────────────────────┐
                                │      Beacon Node       │  │     rvc-signer            │
                                │  (untrusted boundary)  │  │ (standalone signer with   │
                                │  - sync status         │  │  slashing DB + DVT peers) │
                                │  - liveness            │  └─────────────┬─────────────┘
                                │  - duty publication    │                │
                                └────────────────────────┘                │ peer mTLS (DVT)
                                                                          ▼
                                                          ┌──────────────────────────────┐
                                                          │   DVT peer rvc-signer nodes  │
                                                          └──────────────────────────────┘
```

External trust boundaries (each *must* be fail-closed):

- **Operator → keymanager-API:** TLS + bearer token + IP allow-list (KM-3).
- **rvc ↔ Beacon Node:** treat as untrusted (BN-1/2, S-5, SYNC-1, EXIT-1).
- **rvc ↔ rvc-signer:** mTLS, IP-pinned, deny-list scrubbed (URL-1/2, GRPC-1/2/3, L-1).
- **rvc-signer ↔ DVT peer:** mTLS with SNI pinning; threshold partial bound to share pubkey
  (DVT-3/4/5).

---

## Module Overview

The workspace already has 23 crates. This section *does not introduce new ones*; it
re-states the responsibility of each crate that the remediation touches, plus three
*new logical modules* (`crates/test-vectors`, `crates/signer-registry`, `crates/safety-gate`)
that are extracted as small, single-responsibility crates because the defense-in-depth design
requires shared abstractions and shared fixtures.

| Module | Responsibility | Owns Data | Depends On | Communication |
|---|---|---|---|---|
| `crates/eth-types` | Pure SSZ schemas, container shapes, tree-hash, domain constants. Single source of truth for spec types. | — (pure types) | — | sync (in-process) |
| `crates/crypto` | BLS keys, signing primitives, keystore, remote-signer transport. | secret-key bytes in memory | `eth-types` | sync (in-process) |
| `crates/slashing` | EIP-3076 logic + persistent DB (SQLite). Sole owner of slashing-protection invariants. | `slashing.db` (per VC instance, per signer instance) | `eth-types`, `crypto` (pubkey type only) | sync (in-process); never imported by `eth-types`/`crypto` |
| `crates/safety-gate` *(new, extracted from `crates/signer`)* | `SafetyGate` and `FailClosedDefault` traits + a per-pubkey gate registry. Single point that all signing paths consult before calling crypto. | gate state (in-process) | `crypto` (PublicKey), `slashing` (error type re-export) | sync trait dispatch |
| `crates/doppelganger` | Forward-window observation, liveness polling, per-validator safe/blocked state. | per-validator state + cancel tokens (in-process) | `crypto`, `eth-types`, beacon-API client trait (defined locally) | async polling; publishes gate transitions |
| `crates/signer` | High-level `SignerService` that wraps `CompositeSigner` + `SlashingDb` + `SafetyGate`. The *only* in-process surface that issues signatures for slashable messages. | — (holds Arc handles) | `crypto`, `slashing`, `safety-gate`, `eth-types` | async trait `ValidatorSigner` |
| `crates/grpc-signer` | gRPC *client* used by `rvc` to talk to a remote `rvc-signer`. TLS, deadlines, IP pin. | — | `crypto` (pubkey/signature) | network (mTLS) |
| `crates/validator-store` | On-disk validator config (fee-recipient, gas-limit, enabled flag). | `validator_definitions.yaml`, `validator-store.toml` | `crypto`, `safety-gate` (read enabled-flag in fail-closed form) | sync |
| `crates/keymanager-api` | HTTPS keymanager endpoints (import/export/delete keystores; remote-keys). | — (delegates to crypto + slashing) | `crypto`, `slashing`, `validator-store`, `safety-gate` | network (HTTPS) |
| `crates/duty-tracker` | Polls BN for proposer/attester duties; runtime-mutable validator index list. | per-epoch duty maps (in-process) | `crypto`, `eth-types`, beacon-API client trait | async (interval + channel) |
| `crates/bn-manager` | Multi-BN failover, sync-status polling, SSE consumer. Treats every BN as untrusted. | per-BN status + SSE consumer state | `eth-types`, `crypto` (URL/IP types) | network (REST + SSE) |
| `crates/block-service` | Validates incoming BN block proposals + assembles `SignedBeaconBlock`/`SignedBlockContents` bytes. | — | `eth-types`, `crypto`, `signer` | sync (in-process) |
| `crates/sync-service` | Sync-committee message + contribution paths. | — | `eth-types`, `signer`, `bn-manager`, `safety-gate` | sync (in-process) |
| `crates/builder` | MEV-builder validator-registration cadence. | per-pubkey last-submitted timestamp (in-process) | `signer`, `bn-manager` | network |
| `crates/propagator` | Re-publishes signed messages to multiple BNs. | — | `bn-manager`, `eth-types` | network |
| `crates/timing` | Slot/epoch clock arithmetic. | — | `eth-types` | sync |
| `crates/metrics` | Prometheus metrics. | metric registry (in-process) | — | sync |
| `crates/telemetry` | Structured logging + OTLP redaction. | — | `metrics`, `crypto` (pubkey truncation) | sync + network (OTLP) |
| `crates/secret-provider` | Pluggable secret backends (file, GCP). | — | `crypto` | network |
| `crates/beacon` | Beacon-API client (REST + SSE codec). | — | `eth-types`, `crypto` | network |
| `crates/rvc` | Orchestrator: per-slot context, calls signer paths. | per-slot mut state (in-process) | every module above except `signer-registry`, `test-vectors` | sync + channel |
| `crates/test-vectors` *(new)* | Spec-vector fixtures (E-1/E-2/B-1/T-1/KG-1), interchange-import fixtures (GVR-1/IMP-1), DB migration fixtures (DVT-1/CN-1). Documented provenance. Test-only crate (`[lib] doctest=false; path = ...`). | fixture binary blobs + `provenance.json` | `eth-types` (for typing only) | dev-only |
| `crates/signer-registry` *(new)* | A const-evaluated registry of every signing entry point on every binary surface (rvc-signer gRPC v2 service methods, keymanager HTTPS routes, in-process `ValidatorSigner` methods). Used solely by the enumeration test (PRD M4). | static metadata | — | dev-only |
| `bin/rvc` | Validator client binary. Wires `rvc` orchestrator + `keymanager-api` + `bn-manager` + remote/local signer. | — | many | binary |
| `bin/rvc-signer` | Standalone signer binary. Wires `signer` + `slashing` + gRPC v2 service + DVT. | `slashing.db` | `signer`, `slashing`, `safety-gate`, `crypto`, `eth-types` | binary |
| `bin/rvc-keygen` | Keygen/CLI tool (deposit data, exit messages, BLS→exec changes). | local files | `crypto`, `eth-types` | binary |

The **three new test-architecture-relevant logical modules** (`safety-gate`, `test-vectors`,
`signer-registry`) are the only structural additions. Two of them (`test-vectors`,
`signer-registry`) are `dev-dependency`-only crates and do not appear in any production
dependency edge. `safety-gate` is a small extraction from today's `crates/signer` so that
`validator-store`, `keymanager-api`, and the orchestrator can all consume the same
`FailClosedDefault` trait without `crates/signer` becoming a god-crate (it already houses
`SignerService`; extraction keeps each module small per the architect principles).

---

## Module Dependency Graph

```text
                       ┌──────────────┐
                       │  eth-types   │  (pure SSZ + spec constants; no Rust async deps)
                       └──────┬───────┘
                              │
                              ▼
                       ┌──────────────┐
                       │   crypto     │  (BLS, keystore, remote-signer transport)
                       └──┬───┬───┬───┘
                          │   │   │
              ┌───────────┘   │   └─────────────────┐
              ▼               ▼                     ▼
       ┌──────────────┐ ┌─────────────────┐ ┌──────────────┐
       │   slashing   │ │  safety-gate    │ │  beacon      │
       │ (EIP-3076 DB)│ │ (gate traits)   │ │ (BN client)  │
       └──────┬───────┘ └───┬─────────────┘ └──────────────┘
              │             │
              │   ┌─────────┘
              │   │
              ▼   ▼
       ┌─────────────────┐    ┌──────────────────────┐
       │     signer      │◀──┤   doppelganger       │ (publishes gate transitions)
       │ (SignerService) │    └──────────────────────┘
       └────────┬────────┘
                │
   ┌────────────┼────────────┬─────────────┬──────────────┬────────────┬───────────┐
   ▼            ▼            ▼             ▼              ▼            ▼           ▼
block-svc  sync-svc      builder      validator-     keymanager-  duty-     bn-manager
                                       store          api          tracker
   │            │            │             │              │            │           │
   └────────────┴────────────┴─────────────┴──────────────┴────────────┴───────────┘
                                       │
                                       ▼
                                ┌──────────────┐
                                │    rvc       │  (orchestrator binary lib)
                                └──────┬───────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
       bin/rvc                   bin/rvc-signer            bin/rvc-keygen
                                       │
                                       ▼
                              ┌─────────────────┐
                              │ grpc-signer     │  (rvc-side client; depended on by bin/rvc only)
                              └─────────────────┘

   Dev-dependency-only crates (no production edge):
       crates/test-vectors  ──────►  used by enumeration / spec-vector tests only
       crates/signer-registry ──────►  used by the SS-1 / PRD M4 enumeration test only
```

**Cycle verification.** Reading the graph top-down, every edge flows downward. The
candidate adds two new edges only:

- `slashing → safety-gate`: refused. (Would create a cycle: `signer → safety-gate → slashing
  → safety-gate`.) Resolved by having `safety-gate` re-export the slashing error type rather
  than import it; `slashing` does not depend on `safety-gate`.
- `safety-gate → slashing`: refused for the same reason. Instead `safety-gate` defines an
  abstract `SlashingProtection` trait and `crates/signer` is responsible for plugging a
  `slashing::SlashingDb`-backed implementation into the gate at construction time.

After this resolution, the graph is a DAG. The verification rule "every module's transitive
deps must form a DAG" is checked by `cargo deps` (see Cross-Cutting §3.6) and also by the
enumeration test which fails the build if a forbidden edge is introduced.

---

## Module Details

The full module-detail template (Responsibility / Domain Entities / Data Store / Public API /
Events / Internal Structure / Key Design Decisions / Failure Modes) is below for **each
module the remediation actually touches**. Modules untouched by any of the 46 findings
(`metrics`, `telemetry`, `propagator`, `timing`, `secret-provider`) are listed in the table
above but not re-detailed here, since restating their structure would inflate the document
without adding architectural information. Their failure modes are the existing ones; the
remediation does not change them.

---

### Module: `crates/slashing`

**Responsibility:** Single source of truth for EIP-3076 slashing-protection logic and the
on-disk SQLite watermark database. *Everything* that needs to know "is this signature safe to
release?" goes through this crate.

**Domain Entities:**
- `SlashingDb` — handle to the SQLite DB; owns connection.
- `StagedAttestation`, `StagedBlock` — two-phase commit handles that hold a transaction open
  across the actual sign call.
- `SignedBlock`, `SignedAttestation`, `ValidatorRecord` — historical rows.
- `InterchangeFormat` — EIP-3076 v5 import/export shape.

**Data Store:**
- SQLite file `slashing.db` (per `rvc` instance and per `rvc-signer` instance).
- Source of truth for the watermark across all signing paths in its process.

**Public API (interface to other modules):**

| Method | Input | Output | Description |
|---|---|---|---|
| `stage_attestation(scope, pubkey_hex, source, target, signing_root, gvr)` | scope-scope key + att data | `StagedAttestation<'_>` | EIP-3076 attestation check; transaction held until commit/discard. |
| `stage_block(scope, pubkey_hex, slot, signing_root, gvr)` | scope key + slot | `StagedBlock<'_>` | EIP-3076 block check; transaction held until commit/discard. |
| `import(interchange, expected_gvr)` | EIP-3076 interchange JSON + normalized GVR | `Result<ImportStats, SlashingError>` | EIP-3076 import with `source≤target` validation, GVR canonicalization (GVR-1), conflicting-root detection (IMP-1). |
| `export_interchange(pubkeys, gvr)` | list of pubkeys + GVR | `Result<InterchangeFormat, SlashingError>` | EIP-3076 export. *Never* returns Ok on partial failure (KM-1 fix anchor). |
| `migrate_scope_from_cn_to_pubkey(...)` | — | `Result<MigrationReport, SlashingError>` | One-shot startup migration (DVT-1/CN-1). Idempotent. |
| `pinned_gvr() / set_pinned_gvr(canonical)` | — | `Result<Option<Root>, SlashingError>` | GVR pinning with canonicalization (GVR-1, L-3). |

**Defense-in-depth seams owned by this module:**
- **Layer A (logic):** `stage_attestation` / `stage_block` validate against EIP-3076 rules.
- **Layer B (DB constraint):** a `UNIQUE(scope_key, pubkey, slot)` index on the blocks table
  and a `UNIQUE(scope_key, pubkey, target_epoch)` index on attestations. This makes
  double-block / double-vote unrepresentable at the storage layer; a logic-layer bug that
  miscomputes the slashable condition still hits the index and fails. CN-1/DVT-1 changes
  `scope_key` from "(cn,)" to "(pubkey,)" so the unique index *actually* fires across
  tenants.
- **Layer C (migration fixture):** a captured pre-migration DB (held in
  `crates/test-vectors/migrations/slashing-pre-cn-to-pubkey.db`) is run through
  `migrate_scope_from_cn_to_pubkey()` in a test, asserting that the post-migration DB
  rejects the same cross-CN double-block that the pre-migration DB silently accepted.

**Events Published:** none (synchronous library).
**Events Consumed:** none.

**Internal Structure:**
```
slashing/src/
├── db.rs            # SQLite handle + table layout + UNIQUE indices (defense-in-depth Layer B)
├── stage.rs         # StagedAttestation/StagedBlock (defense-in-depth Layer A)
├── error.rs         # SlashingError enum (used by signer + keymanager-api)
├── types.rs         # Interchange types
└── lib.rs           # Re-exports
```

**Key Design Decisions:**
- **A-S1.** EIP-3076 logic is *not* re-implemented anywhere else. Info-1's "duplicate
  `is_safe_to_propose`/`is_safe_to_sign` paths" are deleted or made to delegate. Verified by
  a `grep`-style integration test that fails if any non-`slashing` crate contains a function
  named like `is_safe_to_*` (TEST-1, see Test Architecture).
- **A-S2.** Scope key migrates from "(client_cn)" to "(pubkey)". DVT-1 + CN-1 are *the same
  fix* applied to two callers of `stage.rs`. Per-CN auditing is preserved by adding a
  *non-keying* `audit_cn` column.
- **A-S3.** Unique indices on `(scope_key, pubkey, slot)` (blocks) and `(scope_key, pubkey,
  target_epoch)` (attestations) are **kept even if redundant with the staging logic** —
  this is Layer B of the defense-in-depth. The index is what makes the "double-block can be
  inserted" failure mode unrepresentable at the storage layer.
- **A-S4.** `import()` rejects `source>target` (IMP-1) and conflicting-root duplicate keys
  (IMP-1). GVR comparison is normalized through a single `parse_gvr_hex` canonicalizer
  (GVR-1).
- **A-S5.** `export_interchange()` is atomic: either every requested pubkey exports
  successfully, or the whole call returns Err. KM-1's fail-closed posture in the
  keymanager-api caller depends on this contract.

**Failure Modes:**
- DB locked or corrupted → every `stage_*` call returns Err; SignerService propagates as
  `SlashingProtectionBlocked` → no signature released. (Fail-closed.)
- DB file deleted at runtime → next `stage_*` returns Err; not silently recreated.
- Process killed mid-`StagedBlock`: rolled back on next open (SQLite WAL semantics).

---

### Module: `crates/safety-gate` (new, extracted from `crates/signer`)

**Responsibility:** A typed, single-point gate that every signing path consults *before*
calling `crypto`. This is the **second independent layer** of defense for the doppelganger
window, the validator-disabled flag, and the unknown-pubkey rejection. The gate is *not* a
substitute for EIP-3076; it is a structurally separate barrier that fires earlier and on a
broader class of conditions.

**Why a separate crate (not just a module inside `crates/signer`):**
- `validator-store` needs `FailClosedDefault` (D-3 mandates `is_signing_enabled` defaults to
  `false` for unknown pubkeys; cannot be inside `crates/signer` without `validator-store →
  signer` adding an edge to a much heavier crate).
- `keymanager-api` needs the gate to insert a "blocked-until-doppelganger-elapsed" state at
  the moment a key is imported (KM-2 cancel-token map must be lock-ordered with gate inserts).
- The enumeration test (PRD M4 / SS-1) needs to inspect "did this signer entrypoint actually
  consult the gate?" without depending on `crates/signer`.

**Domain Entities:**
- `SafetyGate` — handle wrapping a thread-safe per-pubkey state map.
- `GateDecision` — `Allow | DenyDoppelganger | DenyDisabled | DenyUnknownKey`.
- `FailClosedDefault<T>` trait — `fn default_when_unknown() -> T` where `T` is the gate's
  decision type for one boundary (e.g. `bool` for `is_signing_enabled` returns `false`).
- `GateTransition` event — `{ pubkey, from, to, reason }` for audit logging.

**Data Store:** in-process. `DashMap<[u8; 48], GateState>`. Per-process; per-signer-binary
and per-rvc-binary have independent gate states (correct — the binaries are independent
trust domains).

**Public API:**

| Method | Input | Output | Description |
|---|---|---|---|
| `check(pubkey) -> GateDecision` | pubkey | decision | The only thing signing-path code is allowed to call before invoking crypto. |
| `mark_doppelganger_blocked(pubkey, until_slot)` | — | — | Called by `crates/doppelganger` when monitoring is in progress. |
| `mark_doppelganger_safe(pubkey)` | — | — | Called by `crates/doppelganger` when forward-window elapses. |
| `set_enabled(pubkey, bool)` | — | — | Called by `validator-store` on config change. |
| `register_new_validator(pubkey, monitoring_epochs, current_slot)` | — | — | Sets "blocked-until-window-elapsed" state at import time. Replaces (and *cancels*) any prior token (KM-2). |

**Events Published:** `GateTransition` to a `broadcast::channel<GateTransition>` — observed
by audit log and by Prometheus metrics. Not used for control flow (control flow is sync
`check()` calls).

**Events Consumed:** none.

**Internal Structure:**
```
safety-gate/src/
├── lib.rs           # Re-exports
├── gate.rs          # SafetyGate + GateState
├── decision.rs      # GateDecision + FailClosedDefault trait
└── transition.rs    # GateTransition event + broadcast channel
```

**Key Design Decisions:**
- **A-G1.** `check()` returns `DenyUnknownKey` for any pubkey that is not in the map. This
  is the fail-closed default for D-3 (unknown pubkey → not enabled). It cannot be configured
  to return `Allow` — there is no `set_unknown_default` API.
- **A-G2.** The gate is **not** the place where EIP-3076 runs. EIP-3076 runs in
  `crates/slashing`. The gate's `Allow` decision is a *necessary but not sufficient*
  condition for releasing a slashable signature; the signer must still consult slashing.
  This separation is the defense-in-depth: the gate catches "should this key be signing at
  all?" and slashing catches "is this *specific* signature safe?" — neither subsumes the
  other.
- **A-G3.** `register_new_validator` *always* cancels a displaced token before installing a
  new one. KM-2's race is closed at the type level: the API does not expose the underlying
  map.
- **A-G4.** `FailClosedDefault<bool>` for the signing-enabled boundary returns `false`.
  `validator-store::ValidatorStore::is_signing_enabled(&self, pubkey)` is rewritten to
  consult the gate (fail-closed default) instead of the previous `unwrap_or(true)`.

**Failure Modes:**
- Channel lag on `GateTransition` → metrics may miss a transition, but control flow is
  unaffected (it's sync `check()`).
- Memory pressure → gate map is bounded by validator count; not adversarially growable.
- Process restart → in-memory state lost. On restart, every monitored validator is
  re-marked `DenyDoppelganger` until the window re-elapses (restart-aware; mirrors
  Lighthouse v5.3.0 behavior — Angle 03).

---

### Module: `crates/signer`

**Responsibility:** The *only* in-process surface that produces signatures for slashable
messages, anywhere in the workspace. Combines `crypto::CompositeSigner` + `slashing::SlashingDb` +
`safety-gate::SafetyGate` into one `SignerService` and enforces the full layered check.

**Domain Entities:**
- `SignerService` — wraps signer + slashing + gate.
- `ValidatorSigner` trait — the in-process API used by orchestrator and tooling.
- `ValidatorLockMap` — per-pubkey serialization (prevents TOCTOU).

**Data Store:** none owned; holds `Arc<CompositeSigner>`, `Arc<SlashingDb>`,
`Arc<SafetyGate>`.

**Public API (interface to other modules):**

The full `ValidatorSigner` trait surface (already exists). Defense-in-depth contract: every
method that signs a *slashable* message must, in order:
1. Acquire per-pubkey lock.
2. Consult `SafetyGate::check(pubkey)`. Returning `Allow` is required.
3. Stage the EIP-3076 row (`stage_attestation` / `stage_block`).
4. Call `crypto::CompositeSigner::sign(signing_root, pubkey)`.
5. Commit the staged row on success; discard on signer failure.

Every method that signs a *non-slashable* message (RANDAO reveal, voluntary exit, builder
registration, aggregate-and-proof, sync committee, selection proofs) must:
1. Consult `SafetyGate::check(pubkey)`. Returning `Allow` is required. (D-3: gate applies to
   *all* signing paths, not just slashable ones.)
2. Call `crypto::CompositeSigner::sign(signing_root, pubkey)`.

**Defense-in-depth contract for slashable messages:**

| Layer | Where | What it catches | What it does *not* catch |
|---|---|---|---|
| 1. Gate check | `safety-gate::check()` | doppelganger window, disabled, unknown pubkey | a slashable signature within the same key+epoch |
| 2. Staging (EIP-3076 logic) | `slashing::stage_*` | double-block, double-vote, surround | a logic bug that miscomputes "surround" |
| 3. SQLite UNIQUE index | DB schema | a literal duplicate row regardless of logic | semantically-different slashable cases |
| 4. Per-pubkey async lock | `ValidatorLockMap` | TOCTOU between concurrent paths to the same key | nothing on its own — necessary support |

A bug in any one layer is caught by the others. Specifically: a bug in slashing's surround
logic still hits the UNIQUE index on (pubkey, target_epoch) for any "same target_epoch"
case; a bug in the gate logic does not allow a slashable signature because slashing's
staging still rejects.

**Events Published:** none.
**Events Consumed:** `GateTransition` (only for `info!`-level logging).

**Internal Structure:**
```
signer/src/
├── lib.rs           # SignerService struct
├── traits.rs        # ValidatorSigner trait
├── slashable.rs     # sign_attestation, sign_block (gate + slash + commit)
├── non_slashable.rs # randao, sync, agg, exit, builder, selection (gate + sign)
└── locks.rs         # ValidatorLockMap
```
(Splits the existing 2300-line `lib.rs` into smaller files per "small modules" principle;
behavior is unchanged.)

**Key Design Decisions:**
- **A-Sg1.** Removing the gate consultation from a *non-slashable* method is the same kind of
  bug as removing it from a slashable method. D-3 broadens the gate to every signing path
  (Teku also does this); the enumeration test enforces it.
- **A-Sg2.** `SignerService` is the *only* type with both an `Arc<CompositeSigner>` and an
  `Arc<SlashingDb>`. No other code path can hold both. This is what makes the SS-1
  enumeration test tractable: enumerate every type that holds an `Arc<CompositeSigner>`, and
  prove each one wraps it in a `SignerService` or is in the explicit allow-list (builder
  registrations, etc., which are non-slashable).
- **A-Sg3.** SS-2/SS-3 fix: `sign_aggregate_and_proof` and
  `sign_electra_aggregate_and_proof` do *not* call `stage_attestation`. They *do* still call
  `SafetyGate::check`. The chain-of-custody precondition (Angle 02 R5) is enforced by the
  orchestrator: aggregate is produced *after* the corresponding attestation was signed
  through `sign_attestation`; this precondition is asserted in a test
  (`tests/sign_aggregate_chain_of_custody.rs`).

**Failure Modes:**
- `SlashingDb` errors → fail-closed via `SignerError::SlashingProtectionBlocked`.
- Gate `DenyDoppelganger` / `DenyDisabled` / `DenyUnknownKey` → `SignerError::SigningBlocked(kind)`.
- `CompositeSigner` failure → `SignerError::SigningFailed`; any staged slashing row is
  discarded (M-1 invariant). Per-pubkey lock is released.

---

### Module: `crates/doppelganger`

**Responsibility:** Forward-window observation of every monitored validator: poll liveness
for `monitoring_epochs` future epochs and mark validators safe only after the full window
elapses with no unexplained `is_live`. Publishes gate transitions to `safety-gate`.

**Domain Entities:**
- `DoppelgangerService` — orchestrates the per-validator state machine.
- `DoppelgangerStatus` — `Safe | DetectionInProgress | DoppelgangerDetected`.
- `MonitoringEpoch` — per-validator epoch counter.

**Data Store:** in-process. Per-process; lost on restart (restart-aware skip is
acknowledged in service.rs:122-150).

**Public API:**

| Method | Input | Output | Description |
|---|---|---|---|
| `register_validators(pubkeys, current_slot)` | new validator set | `()` | Marks every new pubkey as `DenyDoppelganger` in the gate, sets per-validator monitoring deadlines. |
| `tick(current_slot, liveness_response)` | slot + BN liveness response | `Vec<GateTransition>` | Drives the state machine; emits gate transitions for any validator that *exited* DetectionInProgress. |
| `status(pubkey) -> DoppelgangerStatus` | pubkey | status | Read-only inspection (used by metrics/diagnostics). |

**Defense-in-depth contract:**
- **Layer 1 (per-validator state machine):** D-1's forward-window logic — mark
  DetectionInProgress on register, only transition to Safe at the end of the configured
  window.
- **Layer 2 (gate publication):** every transition is published to `safety-gate` via
  `mark_doppelganger_safe` / `mark_doppelganger_blocked`. The signer (which is the *actual*
  signature-issuing surface) consults the gate, not the doppelganger service directly. If
  the doppelganger service crashes, the gate retains `DenyDoppelganger` (fail-closed).
- **Layer 3 (missing-liveness fail-closed):** D-2 mandates that an incomplete liveness
  response keeps the validator blocked. This is implemented by *not* publishing a Safe
  transition when any requested pubkey is absent from the response. The gate stays in
  `DenyDoppelganger`.

**Events Published:** `GateTransition` (via `safety-gate`).
**Events Consumed:** liveness polling response from `crates/bn-manager`.

**Key Design Decisions:**
- **A-D1.** The doppelganger module *publishes* gate transitions; it does not directly own
  the "should I sign?" decision. The decision is owned by `crates/safety-gate`. Two
  independent layers: a bug in doppelganger's state machine that publishes a premature
  `Safe` is *not* sufficient on its own to release a slashable signature, because the
  signer still consults slashing.
- **A-D2.** Pre-genesis bypass (S-3): the service still runs at `current_epoch == 0`. The
  state machine *handles* epoch 0 conservatively (no transitions to Safe before genesis +
  forward window). Removing the `if current_epoch > 0` guard at the call site is the fix;
  the service-level logic is the second layer.
- **A-D3.** Restart-aware skip is preserved (Lodestar pattern, service.rs:122-150 already
  implements). If the slashing DB shows the validator already signed at slot S in this
  window, doppelganger marks Safe immediately. The slashing DB is the second source of
  truth.

**Failure Modes:**
- Liveness RPC timeout → no Safe transition emitted; gate stays `DenyDoppelganger`.
- BN returns incomplete liveness response → same (D-2 fail-closed).
- Service task crashes (panic) → restart-aware logic re-engages; gate stays
  `DenyDoppelganger` until restart finishes its window.

---

### Module: `crates/keymanager-api`

**Responsibility:** EIP-3076-aware keystore lifecycle (import/export/delete), remote-key
lifecycle, and SSRF-safe URL validation. Sole HTTP-facing crate that holds key material in
memory.

**Domain Entities:**
- `KeystoreImport`, `KeystoreExport`, `KeystoreDelete` — request/response shapes per
  keymanager-API spec.
- `UrlValidator` — IP deny-list (URL-1) and DNS pin (URL-2).
- `CancelTokenMap` — per-pubkey doppelganger window cancel tokens (KM-2).

**Data Store:** delegates to `crypto` (keystore files) and `slashing` (EIP-3076 import).

**Public API:** HTTPS endpoints per the keymanager-API spec; surface is unchanged (PRD §2
non-goal). The KM-3 change is a *bind-time* refusal of non-loopback addresses without an
explicit opt-in.

**Defense-in-depth contract:**
- **Layer 1 (transport):** TLS + bearer token + KM-3 loopback gate at bind time.
- **Layer 2 (URL validation):** every URL going out of this crate (remote-signer URL,
  remote-key URL) is passed through `UrlValidator::validate(url, dns_results)` *and* the
  resulting IP is pinned for the long-lived signing connection (URL-2). The deny-list
  catches static IPs; the pin catches DNS rebinding.
- **Layer 3 (keystore semantics):** DELETE is atomic with export (KM-1). On export failure,
  no keystore is deleted, no empty interchange is returned. This is implemented by ordering
  the operations: export *first*, only on success proceed to delete. Failure of export
  raises an error response; no `unwrap_or_else(|e| empty_interchange())`.
- **Layer 4 (gate insert/cancel):** every import inserts a `DenyDoppelganger` gate state
  through `SafetyGate::register_new_validator` (which itself cancels any prior token, KM-2).
  Every delete cancels the corresponding gate state. Both operations are inside one mutex
  scope (KM-2 acceptance).

**Internal Structure:**
```
keymanager-api/src/
├── handlers.rs      # axum routes (DELETE / POST keystores + remote-keys)
├── url_validator.rs # SSRF deny-list (URL-1)
├── cancel_tokens.rs # KM-2 lock-ordering wrapper
└── lib.rs           # axum router build
```

**Key Design Decisions:**
- **A-K1.** KM-3 reuses the existing `InsecureGate(Refuse)` pattern from the metrics server.
  No new bind-time framework.
- **A-K2.** URL deny-list includes `0.0.0.0/8`, `192.0.2.0/24`, `198.18.0.0/15`,
  `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, IPv4 multicast,
  IPv6 reserved unicast, `ff00::/8` multicast (cited to RFC 6890 + IANA IPv4 Special-Purpose
  + IANA IPv6 Multicast Address Space — per Angle 04 R6).
- **A-K3.** KM-1 chooses the simpler "abort whole DELETE on export error" (PRD assumption
  #9, re-framed per Angle 02 R4 as "fail-closed consistent with `local_keystores.yaml`,
  not a literal flows-README MUST").

**Failure Modes:**
- Export error during DELETE → 500, no deletion. (KM-1 fail-closed.)
- Concurrent delete + re-import on same pubkey → second op cancels first via
  `SafetyGate::register_new_validator` (which cancels the displaced token under a single
  lock). (KM-2 fail-closed.)
- DNS resolves to a pinned IP then changes → pinned `SocketAddr` ignores the change.
  (URL-2.)
- KM bind to non-loopback without `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true` → process exits
  at startup. (KM-3.)

---

### Module: `crates/bn-manager`

**Responsibility:** Untrusted-boundary BN client. Multi-BN failover, sync-status
classification (synced / unknown / unsynced / optimistic), SSE consumer.

**Domain Entities:**
- `Tier` — `Synced | Unknown | Unsynced | Optimistic`.
- `SyncStatus` — per-BN classification.
- `SseConsumer` — reconnect-aware SSE stream wrapper.

**Defense-in-depth contract:**
- **Layer 1 (per-BN sync classification):** an `Optimistic` BN is *never* tiered as
  `Synced`. (BN-1.) `Unknown` (pre-first-poll) is *not* the same as `Synced`
  for routing decisions. (BN-2.)
- **Layer 2 (per-response check):** every produce/attestation/duty response is inspected
  for `execution_optimistic == true` *before* signing. Even if a Synced-tiered BN
  momentarily returns optimistic (race), the orchestrator-side check fires. (BN-1
  acceptance criterion b.)
- **Layer 3 (SSE consumer isolation):** every callback is wrapped in `catch_unwind`; if the
  callback panics, the consumer task is *re-created* inside the reconnect loop. SSE-1
  acceptance.

**Failure Modes:**
- All BNs Unsynced/Optimistic → no duties produced; gate state unaffected.
- SSE callback panic → caught + logged; consumer task restarts. (SSE-1 fail-safe.)
- First poll not yet completed → tier is `Unknown`; orchestrator does *not* fall through to
  Synced. (BN-2.)

---

### Module: `crates/duty-tracker`

**Responsibility:** Per-epoch proposer/attester duty cache with runtime-mutable validator
index list.

**Defense-in-depth contract:**
- **Layer 1 (mutable index list):** validator-index list stored behind `ArcSwap` or
  `RwLock`. Setter `update_validator_indices` is callable from `keymanager-api` on import.
  (DT-1.)
- **Layer 2 (orchestrator consume):** `key_gen_rx` watch channel is consumed with
  `borrow_and_update()` so a single import → exactly one `clear_cache()`. (C-1, S-2.)

**Failure Modes:**
- Setter not called → next refresh has no duties for the new key; key never produces.
  (Caught by integration test M7.)
- `key_gen_rx` consumed with stale `has_changed()` → re-clears every slot. (C-1
  regression test.)

---

### Module: `crates/block-service`

**Responsibility:** Validates BN-provided block proposals; assembles the published
`SignedBeaconBlock` or `SignedBlockContents` bytes.

**Defense-in-depth contract:**
- **Layer 1 (tree-hash root):** the body leaf is the real `hash_tree_root(BeaconBlockBody)`
  per fork (E-1). Spec-vector test cross-checks against `consensus-spec-tests` (PRD M2).
- **Layer 2 (SSZ serialization):** the published bytes are bounded at `kzg_offset`; Deneb+
  blocks serialize as proper `SignedBlockContents`. B-1/T-1 fix. The L-9 ignored tests are
  un-ignored as positive regressions. (R2 from research: verify with `cargo test --
  --ignored` first — fix may be partially landed.)

---

### Module: `crates/sync-service`

**Responsibility:** Sync-committee message and contribution paths.

**Defense-in-depth contract:**
- **Layer 1 (head-root capture):** `head_root` captured via `get_block_root("head")` with
  fallback to slot N-1 when slot N has no block. (S-5.)
- **Layer 2 (BN response validation):** `produce_contributions` validates
  `subcommittee_index`/`slot`/`beacon_block_root` against the requested values. (SYNC-1.)

---

### Module: `crates/builder`

**Responsibility:** MEV-builder validator registration cadence.

**Defense-in-depth contract:**
- **Layer 1 (per-pubkey cadence):** unconditional re-registration per epoch (or
  per-bounded-cadence) with refreshed embedded timestamp. (BLD-1.)
- **Layer 2 (TTL test):** regression test asserts a registration is re-sent within relay TTL
  even if `(fee_recipient, gas_limit)` is unchanged. (BLD-1.)

---

### Module: `crates/grpc-signer` (rvc-side gRPC client)

**Responsibility:** rvc-side gRPC client used by `rvc` to talk to a remote `rvc-signer`.

**Defense-in-depth contract:**
- **Layer 1 (TLS branch consistency):** `tls_enabled` log derived from the branch actually
  taken. (GRPC-1.)
- **Layer 2 (TLS-field completeness):** require all three TLS fields together or hard-error.
  No silent degrade to plaintext. (GRPC-2.)
- **Layer 3 (deadlines):** `connect_timeout` + per-RPC deadline below slot deadline. (GRPC-3.)
- **Layer 4 (URL validation):** every remote-signer URL passes through `UrlValidator` from
  `keymanager-api::url_validator` (which is the same code, used by both crates). (URL-1,
  URL-2, L-1.)

---

### Module: `bin/rvc-signer`

**Responsibility:** Standalone signer binary. Wires `signer` + `slashing` + gRPC v2 service.

**Defense-in-depth contract:**
- **Layer 1 (no v1 raw-root sign on the live listener):** the v1
  `SignerServiceServer::sign(signing_root, pubkey)` is *not* added to the live listener
  router (SS-1 acceptance criterion a). If the v1 service impl remains compiled, its
  handler returns `Status::unimplemented` (criterion b) — and the only way to bind it is
  through a separately-bound, off-by-default insecure opt-in. (PRD Q1 default assumption.)
- **Layer 2 (enumeration test):** `tests/signing_path_enumeration.rs` reads
  `crates/signer-registry` and asserts that for every entry whose `message_type` is
  slashable, the registered handler routes through `crates/signer::SignerService`. The test
  is RED if a future commit re-adds a v1 raw-root handler to the live router. (PRD M4.)
- **Layer 3 (DVT pubkey-scoped slashing):** DVT partial signing uses
  `ScopedSlashingDb::scope_by_pubkey` (not `scope_by_cn`). The slashing UNIQUE index on
  `(pubkey, slot)` catches the cross-CN double-block. (DVT-1, CN-1.)
- **Layer 4 (DVT pubkey-binding & share index):** `aggregator` verifies each peer's partial
  against its share pubkey *before* combine (DVT-3); rejects partials with mismatched
  `share_index` (DVT-4) and `index == 0` (DVT-5).
- **Layer 5 (transport):** mTLS with SNI pinning for DVT peers (DVT-2 v1-to-v2 migration).

**Internal structure (selected):**
```
bin/rvc-signer/src/
├── main.rs              # binds router; SS-1: no v1 add_service
├── service.rs           # V2 SignerService impl; consults SignerService trait
├── slashing/scope.rs    # CN-1: scope_by_pubkey (NOT scope_by_cn) for non-DVT
├── dvt/
│   ├── peer_service.rs  # DVT-1: scope_by_pubkey for partials
│   ├── peer_client.rs   # DVT-2: v2 typed RPC; DVT-4: pinned share_index
│   ├── lagrange.rs      # DVT-5: reject index 0
│   └── ...
└── backend/dvt.rs       # DVT-3: per-partial pubkey verify before combine
```

---

### Module: `bin/rvc`

**Responsibility:** Validator client binary. Wires `rvc` (lib) + `bn-manager` +
`keymanager-api` + remote/local signer client.

**Defense-in-depth contract:**
- **Layer 1 (KM-3 bind gate):** keymanager bind to non-loopback requires
  `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK=true`. Same `InsecureGate(Refuse)` pattern as metrics.
- **Layer 2 (S-2 wiring):** real `(key_gen_tx, key_gen_rx)` channel created; the orchestrator
  is built with `new_with_key_gen(...)`; both keymanager adapters get
  `.with_pubkey_map(...)`. The throwaway tx is gone. Integration test (M7) is the binding
  check.
- **Layer 3 (S-3 doppelganger always-on):** doppelganger detection invoked at startup
  regardless of `current_epoch == 0`; the service handles epoch 0 conservatively.

---

### Module: `bin/rvc-keygen`

**Responsibility:** Keygen / CLI tool.

**Defense-in-depth contract:**
- **Layer 1 (KG-1 domain):** `bls-to-execution-change` signed under
  `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, network.genesis_fork_version,
  network.genesis_validators_root)`. Spec-vector test cross-checks against
  `staking-deposit-cli`. (PRD M2/M3/M4 family.)
- **Layer 2 (KG-2 verify):** keystore self-verification `FAILED`/`MISMATCH` is a hard
  error; deposit data not written. Regression test injects a verification failure.
- **Layer 3 (KG-3 dir perms):** output directories created with `0o700`.

---

## Test Architecture (first-class)

The test architecture is part of the architecture, not a bag of tests appended at the end.
It has four sub-modules, each with a single responsibility and a defined dependency.

```text
       ┌────────────────────────────────────────────────────────────────────┐
       │                       Test architecture                            │
       │                                                                    │
       │   crates/test-vectors  (fixtures + provenance)                     │
       │        │                                                           │
       │        ├─►  spec-vector tests (E-1, E-2, B-1/T-1, KG-1)            │
       │        │     in eth-types/tests/, block-service/tests/,            │
       │        │        bin/rvc-keygen/tests/                              │
       │        │                                                           │
       │        ├─►  interchange-import tests (GVR-1, IMP-1)                │
       │        │     in slashing/tests/                                    │
       │        │                                                           │
       │        └─►  slashing-DB migration tests (DVT-1, CN-1)              │
       │              in slashing/tests/, bin/rvc-signer/tests/             │
       │                                                                    │
       │   crates/signer-registry  (static metadata of every signing path)  │
       │        │                                                           │
       │        └─►  enumeration test (SS-1, PRD M4)                        │
       │              in bin/rvc-signer/tests/                              │
       │                                                                    │
       │   safety-gate fail-closed property tests                           │
       │        │                                                           │
       │        └─►  in safety-gate/tests/, signer/tests/                   │
       │              proptest: for every (pubkey, decision) input, gate    │
       │              never returns Allow when underlying state is invalid  │
       │                                                                    │
       │   per-finding RED-then-GREEN tests (one per PRD acceptance)        │
       │        │                                                           │
       │        └─►  in the crate the fix lands in                          │
       └────────────────────────────────────────────────────────────────────┘
```

### Test sub-module: `crates/test-vectors`

Test-only crate. Holds:
- `fixtures/spec-vectors/{bellatrix,capella,deneb,electra}/beacon_block.ssz` + expected
  `tree_hash_root` from `consensus-spec-tests`.
- `fixtures/spec-vectors/aggregate_and_proof_real_committee.ssz` + expected
  `AggregateAndProof::tree_hash_root` for `aggregation_bits` ≈ 63 bytes.
- `fixtures/spec-vectors/signed_block_contents_deneb_with_blob.ssz` + expected inner block
  root.
- `fixtures/spec-vectors/bls_to_execution_signed.json` from `staking-deposit-cli` with
  expected signing root and signature.
- `fixtures/interchange/gvr_normalization.json` + variants (mixed case, 0x-prefixed,
  stripped).
- `fixtures/interchange/source_gt_target.json` (must be rejected).
- `fixtures/interchange/conflicting_signing_root_same_target.json` (watermark must raise).
- `fixtures/migrations/slashing-pre-cn-to-pubkey.db` (captured pre-migration SQLite file).
- `fixtures/provenance.json` — provenance of every fixture (source repo URL, commit/tag,
  fetch date).

Dependencies: `eth-types` *for typing only* (no production-crate dep). Used as a
`[dev-dependencies]` entry in `eth-types`, `block-service`, `bin/rvc-keygen`, `slashing`,
`bin/rvc-signer`.

### Test sub-module: `crates/signer-registry`

Test-only crate. Holds a compile-time constant `SIGNING_PATHS: &[SigningPathEntry]` where
each entry is `{ binary, surface_kind, method_name, message_type, expected_gate, expected_slashing }`.
The entries are *generated* from the wire-protocol (the `signer_v2.proto` and the
`signer.proto`) — one entry per gRPC method, plus one entry per in-process
`ValidatorSigner` trait method, plus one entry per keymanager-API HTTPS route.

The enumeration test (SS-1 / PRD M4) reads `SIGNING_PATHS` and asserts:
- Every `message_type ∈ {Block, Attestation}` entry's `expected_slashing` is `Required`.
- Every `expected_slashing == Required` entry has a registered handler in the live router
  that routes through `crates/signer::SignerService` (verified by reflecting on the type of
  the registered handler, *or* by asserting at the call site via a const-eval marker —
  whichever the toolchain allows; the cleaner version is a single `const _: () = ...;` in
  each handler that fails compilation if the signing path is not wrapped).
- The legacy v1 `sign(signing_root, pubkey)` entry has `expected_gate ==
  SeparatelyBoundInsecureOptIn` *and* the production router does not bind it.

Dependencies: none on production crates; consumed by `bin/rvc-signer/tests/`.

### Test sub-module: fail-closed property tests

In `crates/safety-gate/tests/` and `crates/signer/tests/`:
- `proptest!(... |pubkey: [u8; 48], state: GateState| { /* never returns Allow when state is invalid */ })`.
- `proptest!(... |slot, source, target| { /* stage_attestation rejects source > target */ })`.
- `proptest!(... |scope_a, scope_b, pubkey, slot| { /* DVT scope keying never permits double-block across CN */ })`.

### Test sub-module: per-finding RED→GREEN tests

One test per acceptance criterion in PRD §5. Each lives in the crate of the fix. PRD §6.1
TDD cycle is enforced via commit-history review (PRD §6.5 pre-merge gate); the tracker
file (`plan/remediation/tracker.md`) records the RED-commit hash.

### No circular dependencies in the test graph

- `test-vectors`: depends on `eth-types` (types) only.
- `signer-registry`: depends on nothing.
- Production crates: do not depend on either test crate.
- Test files: depend on both, plus the crate-under-test.

`cargo deps --no-default-features` produces a DAG.

---

## Cross-Cutting Concerns

### Authentication & Authorization

- **rvc-signer ↔ rvc:** mTLS with client-CN audit only (CN-1: client_cn is *not* a
  slashing-protection scope key). The Common-Name is recorded in the audit log.
- **keymanager-API:** bearer token + TLS + (KM-3) loopback gate.
- **DVT peers:** mTLS with SNI pinning; share index pinned per peer (DVT-4).

### Logging & Observability

- Structured `tracing` with one span per signing path (`rvc.sign.attestation`,
  `rvc.sign.block`, …). Slashing-DB transaction holds emit `rvc.slashing.check` spans.
- Pubkey logged only via `crypto::logging::TruncatedPubkey`.
- Metrics: `RVC_SLASHING_PROTECTION_CHECKS_TOTAL{result}` and
  `RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS{kind}` already exist; the remediation reuses
  them for the new gate transitions (`RVC_GATE_TRANSITIONS_TOTAL{from,to,reason}`).
- Telemetry: `redact_endpoint` URL parsing fixed (TEL-1). OTLP endpoint passwords stripped.

### Error Handling

- `thiserror` for libraries; `anyhow` only at binary main.
- `SignerError`, `SlashingError`, `DoppelgangerError`, `SafetyGateError` are the four
  safety-relevant error types. None ever Implement `Default`; an absent error value cannot
  be confused with "safe".
- Convention: any function returning `Result<bool, _>` where `bool` represents "is safe to
  sign" must return `Ok(false)` on inconclusive states. `FailClosedDefault` codifies this.

### Configuration

- Env vars: `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK` (KM-3), `RVC_INSECURE_GATE_*` (existing).
- Config files: `validator_definitions.yaml`, `slashing.db`, `validator-store.toml`,
  `signer.toml`.
- Slashing-DB schema migrations are run idempotently at startup and gated by a single
  `migration_state` row.

### Dependency-graph enforcement

A `tests/architecture_no_cycles.rs` (or `cargo deps`-based CI step) parses the workspace
manifest and asserts:
- No edge from `slashing` to `safety-gate`.
- No edge from `safety-gate` to `slashing`.
- No edge from any production crate to `test-vectors` or `signer-registry`.
- The transitive-dep graph is a DAG.

---

## Data Flow Diagrams

### Local-signer attestation sign (defense-in-depth in action)

```text
Orchestrator (rvc)
       │  produce_attestation_data() ──► BN  (BN-1: reject if execution_optimistic)
       │  validate_attestation_data()
       ▼
SignerService::sign_attestation
       │ Layer 1 ── ValidatorLockMap::get(pubkey).lock()  (TOCTOU guard)
       │ Layer 2 ── SafetyGate::check(pubkey)  must be Allow  (D-3, D-2 fail-closed)
       │ Layer 3 ── slashing::stage_attestation(scope_by_pubkey, ...)  (EIP-3076)
       │ Layer 4 ── SQLite UNIQUE(scope_key, pubkey, target_epoch) catches index dup
       │          ─ CompositeSigner::sign(signing_root, pubkey)
       │ Layer 3' ── staged.commit() on success; staged.discard() on signer error (M-1)
       ▼
       signature → Orchestrator → Propagator → BN
```

### Remote-signer block sign (defense-in-depth across binaries)

```text
Orchestrator (rvc)
       │ SafetyGate::check(pubkey)  Allow  (rvc-side gate)
       ▼
grpc-signer client  (mTLS, IP-pinned, per-RPC deadline)
       │
       ▼
rvc-signer (binary)
       │ V2 service handler (no v1 raw-root on live router — SS-1)
       │ SignerService::sign_block  (signer-binary-local gate + slashing)
       │   Layer 1 ── SafetyGate::check(pubkey)  Allow
       │   Layer 2 ── slashing::stage_block(scope_by_pubkey, ...)  (CN-1: not by CN)
       │   Layer 3 ── SQLite UNIQUE(pubkey, slot) catches dup across CNs
       │   Layer 4 ── crypto sign + commit/discard
       ▼
       signature → grpc client → Orchestrator → Propagator
```

### Keystore import + doppelganger window

```text
Operator → POST /eth/v1/keystores
       │
       ▼
keymanager-API::handlers::import
       │ scrypt/PBKDF2 param ceiling check  (KS-1 reject oversized)
       │ keystore decrypt
       │ slashing::import(interchange, expected_gvr)  (GVR-1 canonicalize; IMP-1 source<=target)
       │ SafetyGate::register_new_validator(pubkey, monitoring_epochs, current_slot)
       │         ── cancels any displaced cancel token (KM-2)
       │         ── inserts DenyDoppelganger gate state
       │ duty-tracker::update_validator_indices(...)  (DT-1)
       │ orchestrator::clear_cache via key_gen_tx  (S-2; consumed via borrow_and_update — C-1)
       ▼
       …window elapses, doppelganger publishes GateTransition Safe…
       ▼
Orchestrator's next attestation: SignerService::sign_attestation succeeds
       (PRD M7 verifies the full path)
```

### DELETE keystore (KM-1 fail-closed)

```text
Operator → DELETE /eth/v1/keystores
       │
       ▼
keymanager-API::handlers::delete
       │ slashing::export_interchange(pubkeys, gvr)  ──► OK?  ── No ──► 500, no deletion
       │                                                  │
       │                                                  Yes
       │                                                  │
       │ SafetyGate::cancel_validator(pubkey)             │
       │ remove keystore from disk                        │
       │ duty-tracker::update_validator_indices(...)      │
       │                                                  ▼
       │                                            200 + interchange
```

If `export_interchange` errors, nothing is deleted (KM-1) and no empty interchange is
returned. The two layers are: (a) the explicit error-propagation in the handler, (b) the
`slashing::export_interchange` contract that it is *atomic* (A-S5).

---

## Infrastructure & Deployment

### Deployment Model

- Monorepo (already). Three binaries: `bin/rvc` (VC), `bin/rvc-signer` (standalone signer),
  `bin/rvc-keygen` (CLI tool). Each is a deployable unit; `rvc-signer` may run on a
  separate host (typical) or co-located.
- The standalone signer **already exists as a separate process** — this is the strongest
  available cross-process boundary for slashing protection (a slashing DB in a separate
  process resists a VC compromise). The remediation keeps it that way and *adds* layered
  enforcement inside the signer binary so that even a VC that becomes malicious cannot
  produce a slashable signature.

### Scaling Strategy

Out of scope for the remediation (PRD §2 non-goals). Existing scaling is unchanged.

### Service Extraction Path

The architecture's modular boundaries already match the existing extraction. The
remediation does *not* split or merge any binary. The `crates/safety-gate` extraction is a
small internal split that does *not* create a new binary; it is consumed by multiple
existing crates.

| Module | Already extracted? | Reason to extract further? |
|---|---|---|
| `crates/signer` | Yes (separate `rvc-signer` binary) | None during remediation. |
| `crates/slashing` | Yes (library; consumed by signer binary) | None. |
| `crates/safety-gate` | Being extracted *as part of this candidate* | Required: `validator-store` and `keymanager-api` need `FailClosedDefault` without depending on the heavier `crates/signer`. |
| `crates/test-vectors`, `crates/signer-registry` | Being added *as part of this candidate* | First-class test architecture (P4). |

No other extraction is necessary or warranted during remediation.

---

## Technology Choices

Unchanged from the existing workspace (per PRD §2 non-goal "no new dependencies"). The
remediation does *not* introduce a new crate dependency. The architectural moves
(`safety-gate`, `test-vectors`, `signer-registry`) are pure Rust intra-workspace splits
using already-present dependencies (`parking_lot`, `tokio`, `dashmap`-not-required since
`parking_lot::Mutex<HashMap<...>>` suffices).

| Concern | Choice | Rationale |
|---|---|---|
| Language | Rust | Existing. |
| Async runtime | `tokio` | Existing. |
| Slashing DB | SQLite + WAL via `rusqlite` | Existing; PRD non-goal. |
| Trait dispatch | `async_trait(?Send)` for `ValidatorSigner` | Existing; consistent with `Send`-bound limits of `parking_lot::MutexGuard`. |
| Property tests | `proptest` | Already in workspace dev-deps. |
| Test fixtures | `consensus-spec-tests` + `staking-deposit-cli` | PRD §6.2 mandates external cross-check. |

---

## ADRs (Architecture Decision Records)

### ADR-001: Extract `crates/safety-gate` from `crates/signer`

- **Status:** Accepted (part of this candidate).
- **Context:** D-3 mandates the signing gate consulted at every entry point. `validator-store`
  and `keymanager-api` need the `FailClosedDefault` trait. Putting these consumers behind
  `crates/signer` would either (a) inflate `crates/signer` with non-signing logic, or (b)
  create awkward edges like `validator-store → signer → slashing → crypto` for a simple
  fail-closed default lookup.
- **Decision:** Extract `SafetyGate`, `FailClosedDefault`, and `GateTransition` into a small
  new crate `crates/safety-gate`. `crates/signer` and `crates/doppelganger` depend on it;
  `validator-store` and `keymanager-api` depend on it. `crates/slashing` does *not* depend on
  it (refused edge); the gate is a separate concern from EIP-3076 logic.
- **Alternatives Considered:**
  - Keep everything in `crates/signer`: rejected — causes the import-edge issue above and
    makes `crates/signer` too large.
  - Put gate types in `crates/eth-types`: rejected — gate is behavior, not pure types.
- **Consequences:** One small new crate. Single edge added. No circular deps. Modularity
  matches the architect template's "small modules" principle.

### ADR-002: Defense-in-depth at the slashing-DB UNIQUE index

- **Status:** Accepted.
- **Context:** SS-1's bypass shows that a single-layer logical check is fragile. Even with the
  fix, a future bug in `stage_attestation` could in principle reintroduce a hole.
- **Decision:** Keep (and document) the SQLite UNIQUE indices `(scope_key, pubkey, slot)` and
  `(scope_key, pubkey, target_epoch)` *as a structural barrier independent of the staging
  logic*. The two layers are: (1) staging logic correctness, (2) DB rejects the literal
  duplicate row. Per CN-1/DVT-1, `scope_key` collapses to pubkey-only, which is what makes
  the unique index *catch* the cross-CN double-block case the staging logic might miss.
- **Alternatives Considered:**
  - Rely on staging logic only: rejected — that is exactly what failed in the SS-1 scenario.
  - Add a third layer via trigger: rejected — SQLite triggers are an extra dependency
    surface and offer no additional invariant the UNIQUE index doesn't already provide.
- **Consequences:** One INSERT failure path (constraint violation) becomes the explicit
  defense-in-depth signal. The test architecture asserts the indices exist (`PRAGMA
  index_list`).

### ADR-003: Centralize doppelganger gate in `safety-gate`, not orchestrator

- **Status:** Accepted (matches PRD assumption #6).
- **Context:** D-3 acceptance criterion (a) prefers centralizing the gate in the
  signer/typed-signer layer. The alternative — gate calls scattered across orchestrator
  entry points — is more error-prone.
- **Decision:** The gate is a separate crate (ADR-001), and the signer consults it. The
  orchestrator *may* consult it as well for early rejection (latency win), but the
  authoritative check is at the signer layer. Doppelganger publishes transitions; the
  signer reads them via `SafetyGate::check`.
- **Alternatives Considered:**
  - Orchestrator-scattered: rejected per the PRD assumption.
  - Inside `crates/signer` without extraction: rejected per ADR-001.
- **Consequences:** Future signing entry points cannot accidentally bypass the gate. The
  enumeration test catches anyone who does.

### ADR-004: First-class test architecture (`crates/test-vectors`, `crates/signer-registry`)

- **Status:** Accepted.
- **Context:** PRD §6.2 mandates externally-sourced spec vectors; PRD M4 mandates an
  enumeration test that proves no signing path bypasses protection.
- **Decision:** Two test-only crates. `crates/test-vectors` holds binary fixtures and a
  `provenance.json` documenting source/commit/date. `crates/signer-registry` holds the
  compile-time list of every signing entrypoint, consumed only by the enumeration test.
- **Alternatives Considered:**
  - Inline fixtures in each crate's `tests/`: rejected — duplicates provenance docs and
    makes cross-crate fixture sharing painful.
  - Generate the signer registry at runtime via reflection: rejected — Rust does not
    support cleanly; compile-time list is verifiable.
- **Consequences:** Two new dev-only crates. Test files import from these crates without
  introducing production-edge dependencies.

### ADR-005: Scope by pubkey (not CN) for slashing watermarks (DVT-1 + CN-1)

- **Status:** Accepted.
- **Context:** Two distinct findings (DVT-1, CN-1) have the same root cause:
  `client_cn`/peer-CN in the slashing-DB WHERE clause makes the cross-CN double-block
  unobservable.
- **Decision:** Slashing-DB scope key is `(pubkey,)`. The `client_cn` column is retained as
  a *non-keying* audit column for forensics. A startup migration converts existing rows.
- **Alternatives Considered:**
  - Keep per-CN namespacing as primary, add a secondary pubkey-global check: rejected —
    two-layer-but-still-CN-primary design is harder to reason about and the secondary
    check is the *actual* invariant we want.
  - Drop the CN column entirely: rejected — operators want it for audit trails.
- **Consequences:** Migration code in `crates/slashing/src/db.rs` with a captured-fixture
  test. PRD §10 Q3 is gated on operator confirmation that migration is acceptable.

### ADR-006: SS-1 v1 raw-root handler — present but Unimplemented, not deleted

- **Status:** Accepted (matches PRD §10 Q1 default assumption).
- **Context:** SS-1's acceptance criterion offers two strategies: delete the v1 handler
  entirely, or keep it compiled returning `Status::unimplemented` (with a separately-bound
  insecure opt-in).
- **Decision:** Keep the v1 handler compiled, returning `Unimplemented`. Bind only via the
  separately-bound, off-by-default insecure listener.
- **Alternatives Considered:**
  - Delete: rejected — leaves no path for a deliberate, audited operator override during
    incident response or migration.
- **Consequences:** Enumeration test asserts the v1 handler is *not* on the live router.
  Operator-facing release note (PRD §12 SS-1 line) calls this out.

### ADR-007: Atomic export in `slashing::export_interchange`

- **Status:** Accepted.
- **Context:** KM-1 mandates that DELETE on export error must not silently delete keys.
- **Decision:** `slashing::export_interchange` is atomic: succeeds for every requested
  pubkey or returns Err with no partial state. This is the contract that
  `keymanager-api::handlers::delete` relies on.
- **Alternatives Considered:**
  - Per-key partial export with status field: rejected (PRD assumption #9 default; the
    simpler atomic version is preferred).
- **Consequences:** The `unwrap_or_else(|e| empty_interchange())` line is *deleted*;
  caller-side handling is a clean `?` or hard-error.

### ADR-008: No new external dependencies

- **Status:** Accepted (PRD §2 non-goal).
- **Context:** The remediation must not introduce new crates.
- **Decision:** All architectural moves use already-present workspace deps.
- **Consequences:** `safety-gate` uses `parking_lot` (already present) for its map;
  `test-vectors` uses `serde_json` (already present) for provenance.

---

## Open Questions

(Carried forward from PRD §10; this architecture does not add new ones.)

- **Q1.** SS-1 v1 raw-root handler: present but Unimplemented (ADR-006 default), or fully
  deleted?
- **Q3.** Production on-disk slashing DBs exist? Determines whether ADR-005's migration is
  exercised in the field on first start.
- **Q4.** D-3 gate in `crates/safety-gate` (this candidate's choice) vs. orchestrator-scattered.
  This candidate goes with `safety-gate` (ADR-001 + ADR-003); PRD assumption #6 default.

---

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| `safety-gate` extraction touches every signing-call site and could regress something subtle. | Medium | Land it as a no-behavior-change refactor commit *before* any finding-fix commit. CI gate: `cargo test` must pass after extraction. The enumeration test (initially without behavior change) is the structural check. |
| Slashing-DB schema migration (ADR-005) on a production DB risks data loss. | Medium-Low | Idempotent migration; captured-fixture test (`fixtures/migrations/slashing-pre-cn-to-pubkey.db`) asserts the pre-state survives. Operator-facing release note (PRD §12) advises a backup. |
| Spec-vector fixtures sourced from `consensus-spec-tests` may not be available for every fork at remediation time. | Low-Medium | Per PRD §7.2 mitigation: sourcing fixtures is the first work item of each P0 SSZ/domain finding. A fixture missing for one fork does not block the others. |
| Enumeration test is incomplete (misses a new signing path added later). | Low | The test fails closed: any handler not in `SIGNING_PATHS` triggers a test failure when the handler is added. The compile-time list is checked in `bin/rvc-signer/build.rs` against the registered routes. |
| `crates/safety-gate`'s `FailClosedDefault<bool>` returning `false` breaks an existing call site that assumed `unwrap_or(true)`. | Medium | Audit every `is_attesting_enabled` caller during the D-3 GREEN commit. Test M6 (every signing entry point) is the verification. |
| Defense-in-depth adds latency to every sign call (gate + slashing + lock). | Low | Existing latency budget already includes per-pubkey lock + slashing. The added `SafetyGate::check` is a `DashMap` lookup (~10 ns); negligible against the BLS sign cost (~1 ms). Metrics: `RVC_SIGNING_DURATION_SECONDS` is already wired. |
| Two-layer defense leads operators to mis-diagnose failures (was it the gate or slashing?). | Low | Structured errors: `SignerError::SigningBlocked(GateDecision)` vs.
  `SignerError::SlashingProtectionBlocked(SlashingError)` are distinct. The audit log
  records the layer that fired. |

---

## Assumptions

This candidate inherits PRD §8's 17 assumptions verbatim. The candidate-specific assumptions
are:

- **AA-1.** `crates/safety-gate` is a *new internal crate*, not a refactor of an existing
  module. (Net add: 1 crate.)
- **AA-2.** `crates/test-vectors` and `crates/signer-registry` are dev-dependency-only
  crates. They do not appear in any production dependency edge.
- **AA-3.** The slashing-DB UNIQUE-index defense (ADR-002) does not require schema changes
  beyond the CN→pubkey scope key migration (ADR-005); the relevant indices either already
  exist or are added alongside the migration. *To be verified by the M1 GREEN commit
  reading `crates/slashing/src/db.rs`.*
- **AA-4.** The enumeration test (PRD M4) can be expressed as a single Rust test that reads
  `crates/signer-registry::SIGNING_PATHS` and asserts each entry's runtime registration. If
  Rust's available reflection is insufficient, the alternative is a `const _: () = ...;`
  marker per handler. The candidate accepts either form; the simpler one wins.
- **AA-5.** PRD §10 Q3 (existence of production on-disk slashing DBs) is answered "yes;
  migrate" at the review gate. If the answer is "no production DBs," the migration code
  still lands (idempotent, harmless) but the captured-fixture test becomes the only
  exercise of it.
- **AA-6.** The doppelganger gate publishes `GateTransition` via a Tokio `broadcast`
  channel for audit-log/metrics consumption only. It is *not* used for control-flow
  decisions; control flow is sync `SafetyGate::check()`. This avoids a channel-lag induced
  fail-open.
- **AA-7.** `slashing::export_interchange` already (or can easily be made to) provide
  atomic semantics — A-S5. If atomic semantics are not currently provided, the contract
  change is *part of* the KM-1 GREEN commit, not an out-of-scope refactor.
- **AA-8.** The v1 raw-root sign handler's `Status::unimplemented` posture (ADR-006) is
  satisfactory to the auditor at re-verification. If the auditor prefers full deletion,
  ADR-006 flips with no other change.
- **AA-9.** The `cargo deps`-based DAG check (Cross-Cutting "Dependency-graph
  enforcement") is implementable as a Rust test that parses `Cargo.lock` or via a CI script
  using `cargo metadata`. The candidate does not mandate which.
- **AA-10.** Per PRD assumption #14, `cargo clippy -- -D warnings` is the standard. The
  new crates (`safety-gate`, `test-vectors`, `signer-registry`) inherit this standard.

---

## Architecture Quality Checklist

- [x] **No circular dependencies between modules.** Verified by the dependency graph above
  and by the `cargo deps` enforcement step. `slashing ↔ safety-gate` edge refused.
- [x] **Each module has a single, clear responsibility.** Stated in one sentence per
  module-detail entry. The largest module is `crates/rvc` (orchestrator) which already
  exists and is not part of the architectural change.
- [x] **No shared databases.** `slashing.db` is owned by either the rvc binary's process
  or the rvc-signer binary's process. Within a process, only `crates/slashing` accesses
  it.
- [x] **All inter-module communication goes through defined interfaces.** Trait surfaces:
  `ValidatorSigner`, `SafetyGate`, `LivenessChecker`, `SlashingDbReader`,
  `FailClosedDefault`.
- [x] **Every module can be tested in isolation with mocked dependencies.** Existing crates
  already follow this pattern; the new `safety-gate` is trivially mockable.
- [x] **Cross-cutting concerns are standardized.** `tracing`, `metrics`, `thiserror`,
  `tokio` runtime — uniform across the workspace.
- [x] **Failure modes are defined.** Each module-detail entry lists what happens when the
  module fails or a dependency fails. Defense-in-depth invariant: every failure mode is
  *fail-closed* on safety-relevant paths.
- [x] **Service extraction path is clear.** The two binaries (`rvc`, `rvc-signer`) are
  *already* extracted; the candidate adds defense-in-depth without changing the extraction
  topology.
- [x] **Data flow is traceable.** Three Data Flow Diagrams (attestation sign, remote-signer
  block sign, keystore import) above.
- [x] **Module count is justified.** Net: +3 crates (`safety-gate`, `test-vectors`,
  `signer-registry`). Each has a single, defensible responsibility and either a clear
  consumer (safety-gate) or is dev-only (test-vectors, signer-registry).

---

## Where defense-in-depth is worth its cost — and where it is not

A candid statement of the trade-offs.

| Boundary | Layers | Worth it? | Why |
|---|---|---|---|
| Slashable signing path (block / attestation) | Gate + EIP-3076 staging + DB UNIQUE + per-pubkey lock | **Yes** | Failure = lost stake. Each layer catches a structurally different class of bug. |
| Doppelganger window | DoppelgangerService state machine + SafetyGate transitions + signer-side gate check | **Yes** | D-3 showed that a single layer (orchestrator-side check) was bypassed by three out of four signing paths. Two layers + central gate fixes the structural issue. |
| Key-confidentiality on DELETE | Atomic `export_interchange` + handler-side ordering (export-then-delete) | **Yes** | KM-1's silent fail-open was exactly the case where two independent layers (one in slashing, one in keymanager) would have caught the bug independently. |
| SSRF / DNS rebinding | URL deny-list + IP pin + re-validation on every connection | **Yes** | URL-1 alone or URL-2 alone is insufficient (Angle 04). |
| Sync-committee message signing (not slashable) | Single layer (signer-side gate) | **No additional layer** | Sync-committee messages are not slashable on mainnet (EIP-7657 Stagnant; Angle 02 + Angle 03). The gate is sufficient; adding a second layer (e.g. sync-committee-message DB) would add complexity with no slashing invariant to protect. The gate broadens to all signing paths per D-3 (Teku precedent) but that *is* the single layer; no additional layer is justified. |
| Voluntary exit signing | Single layer (signer-side gate + EIP-7044 fork-version check) | **No additional layer** | Voluntary exits are not slashable. EIP-7044 fork-version capping (already implemented in signer's `sign_voluntary_exit`) is the only correctness concern. EXIT-1's BN-side GVR cross-check is a single, sufficient guard at the CLI boundary. |
| RANDAO reveal | Single layer (signer-side gate) | **No additional layer** | Not slashable. |
| Builder registration | Single layer (cadence + signer-side gate; no slashing) | **No additional layer** | Not slashable. BLD-1's cadence fix is correctness, not safety. |
| BN trust boundary (`execution_optimistic`) | Per-BN tier + per-response check | **Yes** | BN-1 showed a single-layer-only design (tier) silently accepted optimistic responses; the per-response check is independent. |
| DVT threshold partial | mTLS + share-pubkey verify + pinned share_index + index ≠ 0 + pubkey-scoped slashing | **Yes** | DVT widens the attack surface (multiple coordinators); each layer is independently motivated by a finding (DVT-1, DVT-3, DVT-4, DVT-5, DVT-2 transport). |

The general rule: **add a redundant layer when each layer catches a structurally different
class of bug.** Adding two layers that fail the same way (e.g. two logical checks of
EIP-3076) is duplication, not defense-in-depth; that is what Info-1 calls out and what this
architecture explicitly forbids (A-S1). Defense-in-depth is two layers that *would not fail
together*: a logical check and a DB constraint; a process boundary and a transport
deny-list; a state machine and a gate publication.

---

## Final correspondence to PRD acceptance criteria

| PRD §4 metric | Architectural support |
|---|---|
| **M1** (all 46 findings closed RED+GREEN) | Per-finding RED→GREEN tests in the crate of the fix; tracker file. |
| **M2** (block proposal succeeds for all forks) | `crates/test-vectors` spec vectors (E-1, B-1/T-1); block-service Layer 1+2. |
| **M3** (aggregator real-committee `aggregation_bits`) | `crates/test-vectors` aggregate fixture (E-2); SS-2/3 fix in `crates/signer`. |
| **M4** (no signing path bypasses EIP-3076) | `crates/signer-registry` + enumeration test (SS-1 acceptance d); ADR-006. |
| **M5** (cargo {build,test,clippy,fmt} green) | Cross-cutting standard; no new external deps. |
| **M6** (doppelganger window at every signing entry point) | `crates/safety-gate` consulted at every `SignerService::sign_*` method; ADR-003. |
| **M7** (runtime keymanager import wired end-to-end) | Data flow diagram "Keystore import + doppelganger window"; ADR-001 for safety-gate; DT-1 + S-2 + C-1 + KM-2 wiring. |
| **M8** (P0/P1 closed before release) | PRD §11 milestones; this architecture does not change phasing. |
