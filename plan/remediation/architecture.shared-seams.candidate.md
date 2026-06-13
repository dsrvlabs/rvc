# Software Architecture: rs-vc Remediation — Shared-Seams Candidate

**Status:** Draft, pre-review
**Date:** 2026-06-13
**PRD:** `plan/remediation/prd.md` (46 verified findings; 11 P0 / 19 P1 / 25 P2)
**Research:** `plan/remediation/research/{00-overview,01-ssz-domain-correctness,02-slashing-remote-signer-dvt,03-doppelganger-protection,04-bn-trust-boundary}.md`
**Optimisation axis:** **shared seams / structural enforcement.**

> This document is a remediation architecture, not a green-field design. It assumes the existing 23-crate
> Rust validator client on `develop` and respects PRD §2 non-goals: no new features, no new RPCs, no broad
> rearchitecture of crates not implicated by a finding, no new dependencies unless a fix has no in-tree
> alternative.

---

## Overview

rs-vc today exposes 46 verified defects that cluster around a small number of root causes: ad-hoc per-call-site enforcement of slashing-protection, doppelganger gating, GVR / pubkey / hex normalisation, URL/IP validation, and SSZ container/Bitlist tree-hash construction. Each cluster is reimplemented (and broken) at several sites — the v1 raw-root signer bypasses EIP-3076 (SS-1); `sign_aggregate_and_proof` re-implements (incorrectly) attestation slashing protection (SS-2/SS-3); the doppelganger gate is consulted only on attestation (D-3); the slashing watermark is keyed by client CN, not pubkey (DVT-1, CN-1); GVR string comparison happens twice with two normalisation policies (GVR-1); SSRF deny-lists are partial and not pinned for the signing connection (URL-1/2); Bitlist and `BeaconBlockBody` are tree-hashed with hand-rolled wrong implementations (E-1, E-2).

The remediation architecture introduces **eight cross-cutting "shared seams"** — small, focused, interface-first modules that each own ONE correct, tested implementation of a previously-duplicated concern. Every finding-cluster collapses onto one seam; every signing entry point routes through that seam; every future regression is structurally prevented by the type system, the API shape, or a single test fixture set. The seams are placed at existing crate boundaries (no new top-level crates except where strictly required by the duty-correctness fixtures), they form a strict DAG with no circular dependencies, and each is unit-testable in isolation behind a small trait/struct surface.

Key architectural decisions:

1. **Centralised signing gate.** All slashable signing entry points go through one `SigningGate` API inside `crates/signer` that consults the slashing DB *and* the doppelganger window before delegating to the backend. No orchestrator code may compute a signing root and call the BLS backend directly; this is enforced by reducing the orchestrator's public dependency on `crypto::sign_*` and routing through `SignerService`.
2. **Pubkey-scoped slashing keying.** The SlashingDb `client_cn` namespace becomes an *audit column*, never a `WHERE`-clause discriminator. All EIP-3076 row uniqueness is `(pubkey, gvr, slot|target_epoch)`. DVT-1 and CN-1 close as one schema-level fix with an in-place migration.
3. **Doppelganger forward-window state machine.** A new `ForwardWindowMachine` inside `crates/doppelganger` mirrors Lighthouse `doppelganger_service.rs`: register-on-startup, observe `monitoring_epochs` forward epochs, fail-closed on missing-liveness entries (D-2), satisfaction at the last slot of `e+1` (D-1), pre-genesis bypass (S-3). Its `is_signing_enabled(pubkey)` is the *only* answer the `SigningGate` consults.
4. **Canonical helper crates.** `crates/eth-types` grows a `canonical` module owning `parse_pubkey_hex`, `parse_gvr_hex`, `parse_signing_root_hex` (L-2, L-3, GVR-1). `crates/eth-types::tree_hash_utils` is rewritten with spec-correct `Bitlist[N]` and `Container` helpers (E-1, E-2). All call sites collapse to one entry point each.
5. **SSRF / IP-pin module.** A new `crates/net-policy` crate owns the reserved-range deny-list, IP pinning, and DNS-rebinding protection, consumed by both `crates/keymanager-api` (URL-1) and `crates/crypto::remote_signer` (URL-2).
6. **Insecure-gate normalisation.** A new `crates/insecure-gate` crate (or `bin/rvc-signer::insecure_startup` promoted) owns the `Refuse | Warn | Allow` semantics consumed by SS-1's legacy-opt-in, KM-3's keymanager non-loopback bind, L-1's mixed-case scheme handling, and SIG-1's `--password-dir` fallback policy.

Together these seams cover every P0 and every P1 cluster from PRD §7.1. P2 findings inherit correctness from the seams (e.g. L-2/L-3 just become tests against the canonical helpers).

---

## Architecture Principles

Beyond the defaults in the architect template:

- **One correct implementation per concern.** If two sites enforce the same invariant, one must call the other. The shared-seam optimisation goal is that *each finding-cluster collapses onto exactly one module*.
- **Fail-closed by default at every seam.** Per PRD §6.3: on error, refuse to sign / refuse to delete / refuse to load. Each seam's public API returns `Result<T, E>` with the error type chosen so a propagating `?` aborts the caller.
- **Type-level enforcement over runtime checks where possible.** E.g. the `BodyHashRoot` newtype prevents passing a `List[byte]` hash where a `Container` hash is required (E-1); `ScopedSlashingDb` is replaced with a `PubkeyScoped<'_>` view that has no `client_cn` accessor (DVT-1, CN-1).
- **Seam ownership = crate ownership.** Every seam has exactly one owning crate. Other crates depend on the seam via its public trait, never via the implementation. This is what guarantees the no-circular-dependency property and the testability-in-isolation property.
- **No new top-level crate unless a fix demands one.** Per PRD §2 non-goals. `net-policy` and `insecure-gate` are the only proposed new crates; both are small (≈ 1 file + tests) and exist because their consumers (`keymanager-api`, `crypto`, `bin/rvc`, `bin/rvc-signer`) currently span the dependency tree such that putting the helper in any one of them creates a cycle. (See ADR-002, ADR-003.)
- **Regression encoded in the seam's test suite, not just in the consumer.** Every finding ID's RED test lives in the seam's own crate's `tests/` or `#[cfg(test)]` module so future refactors of the seam can never silently un-fix a finding.

---

## System Context Diagram

```text
                          ┌──────────────────────────────────────────┐
                          │                rs-vc                     │
                          │   (3 bins: rvc, rvc-signer, rvc-keygen)  │
                          │                                          │
   ┌──────────┐   HTTP    │   ┌───────────────────────────────────┐  │
   │ Operator │──────────▶│   │      keymanager-api (Axum)        │  │
   │  / DVT   │   POST    │   │      keystores / remotekeys       │  │
   │  Coord   │   /eth/v1 │   └────────────────┬──────────────────┘  │
   └──────────┘   /keys.. │                    │ key import          │
                          │                    ▼                     │
   ┌──────────┐   gRPC    │   ┌───────────────────────────────────┐  │   ┌──────────────┐
   │ rs-vc    │──────────▶│   │      rvc-signer (gRPC server)     │──┼──▶│ Remote BLS   │
   │  (VC)    │   sign_*  │   │      [v2 typed only; v1 gated]    │  │   │  backend     │
   └──────────┘   typed   │   └────────────────┬──────────────────┘  │   └──────────────┘
                          │                    │ Signer trait        │
                          │                    ▼                     │
                          │   ┌───────────────────────────────────┐  │   ┌──────────────┐
                          │   │      orchestrator (crates/rvc)    │──┼──▶│ Beacon Node  │
                          │   │      slot loop, duty fan-out      │  │   │  (multi-BN)  │
                          │   └────────────────┬──────────────────┘  │   └──────────────┘
                          │                    │ duty fan-out         │
                          │                    ▼                     │   ┌──────────────┐
                          │   ┌───────────────────────────────────┐  │   │ MEV Builder  │
                          │   │  block / sync / aggregation /     │──┼──▶│  relay       │
                          │   │  attestation services             │  │   └──────────────┘
                          │   └───────────────────────────────────┘  │
                          └──────────────────────────────────────────┘
                                              │
                                              ▼
                                    ┌──────────────────┐
                                    │ slashing DB      │
                                    │ (SQLite, EIP-3076)│
                                    └──────────────────┘
```

The seams introduced by this remediation are *internal*; the external interfaces (Beacon API, gRPC sign surface modulo SS-1, keymanager HTTP API, builder relay HTTP, slashing-DB interchange) are unchanged except where a finding explicitly requires it (SS-1 removes v1 from the live listener; KM-3 adds an insecure-gate).

---

## Module Overview (post-remediation)

Existing crate names are kept. New seams are **bolded**. The "Owned data" column lists the *concept the seam now uniquely owns* — not necessarily a database. Dependencies are listed in DAG order (each row only depends on rows above it).

| # | Crate / Module | Responsibility (one sentence) | Owns | Depends on | Status |
|---|---|---|---|---|---|
| 1 | `crates/eth-types` | SSZ-derived consensus types, canonical hex/GVR/pubkey parsers, **correct `Bitlist[N]` / `Container` tree-hash helpers.** | Domain types, **canonical helpers** (NEW seam: `canonical::{parse_pubkey_hex, parse_gvr_hex, parse_signing_root_hex}`), corrected `tree_hash_utils` (E-1, E-2). | (workspace leaf — no internal deps) | EXTENDED |
| 2 | `crates/metrics` | Prometheus metric registration / counter helpers. | metric names + counters. | (none — `lazy_static`). | UNCHANGED |
| 3 | `crates/telemetry` | OTLP / logging config; **endpoint-redaction helper.** | TEL-1 redaction (parsed `url::Url`). | `eth-types::canonical` (optional, for hex token detection). | EXTENDED |
| 4 | `crates/timing` | `SlotClock` with ms-precision (TIM-1). | slot/epoch arithmetic. | `eth-types`. | EXTENDED |
| 5 | **`crates/net-policy`** | **Reserved-range deny-list + IP pinning + DNS-rebinding seam** (URL-1, URL-2). | IPv4/IPv6 deny-list; `resolve_to_addrs` adapter; runtime re-check API. | `eth-types::canonical` (parsing); `reqwest` (build-time only). | **NEW** |
| 6 | **`crates/insecure-gate`** | **`Refuse | Warn | Allow` decision seam** consumed by SS-1, KM-3, L-1, SIG-1. | `InsecureGate` enum + `apply_to(&str env)` helper. | (workspace leaf). | **NEW** |
| 7 | `crates/secret-provider` | GCP / local secret provider for BLS keys. | secret refresh policy (SP-1). | `crypto`. | EXTENDED |
| 8 | `crates/crypto` | BLS primitives, `KeyManager`, `LocalSigner`, `RemoteSigner`, keystore decryption. | BLS sign/verify, keystore EIP-2335, remote-signer client. | `eth-types::canonical` (L-2 pubkey parsing); `net-policy` (URL-2 IP pin on every sign). | EXTENDED |
| 9 | `crates/slashing` | EIP-3076 SQLite DB, staged guards, interchange import/export. | DB schema, `(pubkey, gvr, slot|target_epoch)` keying, GVR canonicalisation at the boundary. | `eth-types::canonical` (GVR-1); `crypto` (pubkey type). | EXTENDED + SCHEMA MIGRATION |
| 10 | **`crates/doppelganger`** | **Forward-window state machine + `is_signing_enabled` gate.** | Per-validator state (`Unmonitored | Pending | Safe | Detected`), forward-window epoch tracking. | `eth-types`; `slashing` (read-only `SlashingDbReader`); `crypto::PublicKey`. | EXTENDED → owns D-1, D-2, D-3, S-3, KM-2 state-coordination. |
| 11 | **`crates/signer`** | **The single signing seam.** All slashable signs route through here; consults slashing DB + doppelganger gate before signing. | `SigningGate` (NEW seam), `SignerService` (existing), per-validator mutex map. | `crypto`, `eth-types`, `slashing`, `doppelganger`. | EXTENDED (broadens existing role — already the canonical Validator Client signing wrapper). |
| 12 | `crates/beacon` | Beacon-API HTTP client, SSZ deser. | endpoint set, response parsing, **GVR/fork-version validation at boundary (Info-4).** | `eth-types::canonical`, `telemetry`, `crypto`. | EXTENDED |
| 13 | `crates/bn-manager` | Multi-BN failover, sync status, SSE event consumer. | tier policy (BN-1, BN-2), SSE reconnect (SSE-1). | `beacon`, `eth-types`, `crypto`. | EXTENDED |
| 14 | `crates/duty-tracker` | Duty refresh, **runtime validator-index update API (DT-1).** | duty fetch + index list. | `bn-manager`, `eth-types`. | EXTENDED |
| 15 | `crates/builder` | Builder validator registration cache + relay client. | registration cache + TTL refresh (BLD-1). | `bn-manager`, `crypto`, `signer`, `validator-store`. | EXTENDED |
| 16 | `crates/validator-store` | Per-validator config + atomic persist (VS-1). | TOML config + fsync-on-rename. | `crypto::canonical`. | EXTENDED |
| 17 | `crates/sync-service` | Sync-committee message production. | sync-committee BN-response validation (SYNC-1). | `eth-types`, `signer` (via trait). | EXTENDED |
| 18 | `crates/block-service` | Block proposal pipeline + SSZ publish bytes assembly (B-1/T-1, L-9). | encoded block bytes; offset tables; `SignedBlockContents` shape. | `eth-types`, `beacon`, `signer`, `builder`, `crypto`, `validator-store`. | EXTENDED (delete unvalidated `propose_block`; correct kzg offset; remove false `#[ignore]`). |
| 19 | `crates/propagator` | Multi-BN block/attestation publish fan-out. | publish retry policy. | `bn-manager`, `eth-types`. | UNCHANGED |
| 20 | `crates/keymanager-api` | `/eth/v1/keystores`, `/eth/v1/remotekeys` HTTP. | import/delete handlers (KM-1, KM-2), URL validation (delegated to `net-policy`), `DoppelgangerGate` adapter (becomes a thin shim over `doppelganger::ForwardWindowMachine`). | `signer`, `slashing`, `crypto`, `doppelganger`, `net-policy`, `insecure-gate`, `eth-types::canonical`. | EXTENDED |
| 21 | `crates/grpc-signer` | gRPC client to standalone signer (timeouts, TLS). | connect/RPC timeouts (GRPC-1/2/3). | `crypto`, `eth-types::canonical`, `net-policy` (optional). | EXTENDED |
| 22 | `crates/rvc` | Orchestrator (slot loop, attestation/aggregation/sync/block fan-out, doppelganger startup wiring, keymanager adapters). | duty scheduling, **no direct BLS sign calls.** | crates 1-21 (except `bin/*`). | EXTENDED (all sign sites route through `signer::SigningGate`). |
| 23 | `bin/rvc` | VC binary entrypoint + flag wiring. | CLI surface (CLI-1, KM-3 wiring). | `rvc`, `signer`, `bn-manager`, `keymanager-api`, `metrics`, `telemetry`, `insecure-gate`. | EXTENDED |
| 24 | `bin/rvc-signer` | Standalone signer binary (gRPC server, v2 typed, optional DVT). | RPC handlers; **per-pubkey slashing scope** (replaces `ScopedSlashingDb` per-CN; DVT-1, CN-1); legacy v1 disabled (SS-1). | `signer`, `slashing`, `crypto`, `insecure-gate`, `eth-types::canonical`. | EXTENDED + LEGACY-GATE |
| 25 | `bin/rvc-keygen` | Keystore generation + BLS-to-execution-change signer (KG-1, KG-2, KG-3). | output dir mode 0700; `compute_domain(BLS_TO_EXEC, GENESIS_FORK_VERSION, GVR)`. | `crypto`, `eth-types::canonical`. | EXTENDED |

**Net change:** 2 new small crates (`net-policy`, `insecure-gate`), 1 module promotion inside `eth-types` (`canonical`), 1 new module inside `doppelganger` (`forward_window`), 1 new module inside `signer` (`gate`). No existing crate is removed. No crate boundary is moved.

---

## Module Dependency Graph

```text
LEVEL 0  (workspace leaves)
  metrics       insecure-gate

LEVEL 1
  eth-types ─────► (uses ssz, tree_hash, hex)
  timing   ─────► eth-types
  telemetry ────► eth-types (optional)
  net-policy ──► eth-types (canonical helpers only)

LEVEL 2
  crypto      ──► eth-types, net-policy
  secret-provider ──► crypto

LEVEL 3
  slashing    ──► eth-types, crypto, metrics
  beacon      ──► eth-types, crypto, telemetry

LEVEL 4
  doppelganger ──► eth-types, crypto, slashing (READ-ONLY trait)
  bn-manager   ──► beacon, eth-types, crypto

LEVEL 5
  signer       ──► crypto, eth-types, slashing, doppelganger, metrics
                                      ▲
                                      │  consults via traits ONLY
                                      │  (no direct DB or service struct)

LEVEL 6
  builder           ──► bn-manager, crypto, signer, validator-store
  duty-tracker      ──► bn-manager, eth-types, metrics
  validator-store   ──► crypto
  sync-service      ──► eth-types, signer (trait)
  block-service     ──► eth-types, beacon, signer, builder, crypto, validator-store
  propagator        ──► bn-manager, eth-types
  grpc-signer       ──► crypto, eth-types, net-policy
  keymanager-api    ──► signer, slashing, crypto, doppelganger, net-policy,
                       insecure-gate, eth-types

LEVEL 7
  rvc (lib)         ──► all of levels 0..6, except bin/*

LEVEL 8
  bin/rvc           ──► rvc, signer, bn-manager, keymanager-api, metrics, telemetry,
                        insecure-gate, grpc-signer (when remote signer)
  bin/rvc-signer    ──► signer, slashing, crypto, insecure-gate, eth-types
  bin/rvc-keygen    ──► crypto, eth-types
```

**Verification (no cycles):** every arrow points strictly from a higher-numbered level to a lower-numbered level. The doppelganger crate's read-only dependency on `slashing` is acyclic because `slashing` itself does NOT depend on `doppelganger` — it only emits last-signed-epoch data through `SlashingDbReader`, which the signer crate wires together. `signer` depends on both `slashing` and `doppelganger`, and that is the only place those two meet. `keymanager-api` depends on `doppelganger` directly only for the time-based `DoppelgangerGate` thin shim (today it owns its own gate; post-remediation it delegates to `doppelganger::ForwardWindowMachine`), which is acyclic because `doppelganger` does not know about keymanager.

```text
Seam ownership cross-reference:

  SigningGate                  → signer            (D-3, SS-1, SS-2/3, CN-1)
  PubkeyScopedSlashing         → slashing          (DVT-1, CN-1, GVR-1, IMP-1)
  ForwardWindowMachine         → doppelganger      (D-1, D-2, D-3, S-3, KM-2)
  canonical::{pubkey,gvr,...}  → eth-types         (L-2, L-3, GVR-1, IMP-1, Info-4)
  bitlist_tree_hash_root       → eth-types         (E-2)
  BodyHashRoot newtype + helpers → eth-types       (E-1)
  net-policy::deny_list        → net-policy        (URL-1)
  net-policy::pinned_resolver  → net-policy        (URL-2, GRPC misc)
  InsecureGate                 → insecure-gate     (SS-1, KM-3, L-1, SIG-1)
  TEL-1 redactor               → telemetry         (TEL-1)
  ForwardWindowAdapter         → keymanager-api    (thin shim only; logic in doppelganger)
```

---

## Module Details

The modules below are the *seam-bearing* ones; modules that merely receive small fixes (e.g. `validator-store::store::persist` adding a `sync_all` on the parent dir for VS-1) are not expanded here.

### Module: `eth-types` (extended)

**Responsibility:** Owns the SSZ-derived consensus types, the canonical hex parsers, the canonical GVR canonicaliser, and the spec-correct `tree_hash` helpers.

**Domain Entities (new/changed):**
- `canonical::PubkeyHex` — newtype around `[u8; 48]` with `from_str()` validating ASCII hex, even length, strict single `0x` prefix (L-2).
- `canonical::GvrHex` — newtype around `Root` with lowercase-normalised string view; `parse_gvr_hex(s) -> Result<Root, _>` for all callers including `slashing::db::import()` (GVR-1).
- `canonical::SigningRootHex` — newtype around `[u8; 32]`; used by SS-1 audit logs.
- `tree_hash_utils::bitlist_tree_hash_root<const N: usize>(bytes) -> Result<Hash256>` — generic over the SSZ type's `N` bound; computes `chunk_count = (N + 255) / 256` (E-2). Replaces the current `next_power_of_two(bytes.len())` bug.
- `tree_hash_utils::container_tree_hash_root<T: TreeHash>(value) -> Hash256` — explicit helper to compile-error if the caller passes a `Vec<u8>` (E-1). Combined with a `BodyHashRoot([u8;32])` newtype that `BeaconBlock::tree_hash_root` requires.

**Data Store:** none. Pure type/algorithm crate.

**Public API (interface to other modules):**

| Function | Input | Output | Description |
|---|---|---|---|
| `canonical::parse_pubkey_hex(&str)` | hex string (optionally `0x`-prefixed) | `Result<PubkeyHex, ParseError>` | Single source of truth (L-2). |
| `canonical::parse_gvr_hex(&str)` | hex string | `Result<Root, ParseError>` | Single source of truth (GVR-1). |
| `canonical::eq_gvr(&str, &Root)` | string, pinned bytes | `bool` | Convenience equality helper for `slashing::db::import` (GVR-1). |
| `tree_hash_utils::bitlist_tree_hash_root<N>(&[u8])` | SSZ-encoded bitlist | `Result<Hash256, TreeHashError>` | E-2. |
| `tree_hash_utils::container_tree_hash_root::<T: TreeHash>(&T)` | container value | `Hash256` | Indirection that prevents the E-1 mistake (passing `List[byte]` where `Container` is required). |
| `BeaconBlockBody::tree_hash_root()` (existing) | `&Self` | `Hash256` | After E-1 fix, this is what `BeaconBlock` body leaf uses. |

**Events:** none.

**Internal Structure (after fix):**
```
eth-types/
├── src/
│   ├── lib.rs
│   ├── canonical/          # NEW — L-2, L-3, GVR-1, Info-4
│   │   ├── mod.rs
│   │   ├── pubkey_hex.rs
│   │   ├── gvr_hex.rs
│   │   └── signing_root_hex.rs
│   ├── tree_hash_utils.rs  # REWRITTEN — E-1, E-2
│   ├── ssz_helpers.rs
│   ├── block.rs            # uses container_tree_hash_root for body leaf (E-1)
│   ├── aggregation.rs      # uses bitlist_tree_hash_root::<MAX_VALIDATORS_PER_COMMITTEE> (E-2)
│   └── ...
└── tests/
    ├── fixtures/           # spec-vector fixtures (PRD §6.2)
    │   ├── README.md       # provenance
    │   ├── bellatrix_block.ssz
    │   ├── capella_block.ssz
    │   ├── deneb_block.ssz
    │   ├── deneb_block_contents.ssz
    │   ├── electra_block.ssz
    │   ├── aggregate_and_proof_real_committee.ssz
    │   ├── sync_contribution.ssz
    │   └── signed_bls_to_execution_change.ssz
    ├── spec_vector_block.rs       # E-1 regression
    ├── spec_vector_bitlist.rs     # E-2 regression
    └── canonical_helpers.rs       # L-2, L-3, GVR-1, IMP-1
```

**Key Design Decisions:**
- The `BodyHashRoot` newtype is *not* exposed to consumers; it is internal so the only callers of `tree_hash_root` for the body are `BeaconBlock::tree_hash_root` itself and the spec-vector test. This means a future refactor that re-introduces "tree-hash the body as `List[byte]`" will refuse to compile.
- `bitlist_tree_hash_root` takes `N` as a const-generic so each call site declares its bound explicitly (`MAX_VALIDATORS_PER_COMMITTEE = 2048`, `SYNC_COMMITTEE_SIZE = 512`, etc.). The compiler rejects callers that forget the bound.
- `parse_gvr_hex` always lowercases. All comparisons go through `eq_gvr` or `Root` direct compare; never `String == String`.

**Failure Modes:**
- Pure functions; failures are returned values, not panics. Property tests (existing in `tree_hash_utils::fuzz`) extended to cover the new helpers' no-panic invariant.

---

### Module: `slashing` (extended + schema migration)

**Responsibility:** The EIP-3076 SQLite DB. After remediation, the DB row uniqueness is **`(pubkey_hex, gvr, slot|target_epoch)`** — **`client_cn` becomes a non-key audit column**. (DVT-1, CN-1.)

**Domain Entities:**
- `SlashingDb` — existing.
- `StagedBlock<'_>`, `StagedAttestation<'_>` — existing RAII guards.
- `PubkeyScopedDb<'a>` — NEW thin view; replaces `bin/rvc-signer::ScopedSlashingDb` at every call site that today threads a `(client_cn, gvr)` pair. Its constructor records `client_cn` for audit-logging only; it has no API that lets the caller key by CN.
- `InterchangeImporter` — extracted from `db.rs::import()` for testability; uses `canonical::parse_gvr_hex` (GVR-1) and validates `source_epoch <= target_epoch` plus conflicting-root detection (IMP-1).

**Data Store:** SQLite, schema versioned. Migration from `(client_cn, pubkey, ...)` to `(pubkey, ...)` is an idempotent step that:
1. Drops any unique index that mentions `client_cn`.
2. Adds a unique index `(pubkey, gvr, slot)` for blocks and `(pubkey, gvr, target_epoch)` for attestations.
3. Resolves duplicates that existed under the old keying by raising the watermark (worst-case epoch/slot) so the resulting DB is at least as conservative as either pre-migration row.

(Per PRD Assumption #5 and Open Q3, migration is automatic but documented; a captured pre-migration DB fixture exercises this in tests.)

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `SlashingDb::stage_block` (changed signature) | `pubkey_hex, slot, signing_root_hex, gvr` *(no `client_cn` arg)* | `StagedBlock<'_>` | `client_cn` moves out of the slashing API into an *audit-only* parameter on a sibling `audit_log` call. |
| `SlashingDb::stage_attestation` (changed signature) | `pubkey_hex, src, tgt, signing_root_hex, gvr` | `StagedAttestation<'_>` | Same change. |
| `PubkeyScopedDb::new(db, gvr)` | `Arc<SlashingDb>, Root` | `Self` | Replaces `ScopedSlashingDb`. |
| `InterchangeImporter::import(&self, json) -> Result<ImportSummary, _>` | interchange JSON | summary | GVR normalised via `eth-types::canonical::eq_gvr` (GVR-1); validates `src <= tgt` and conflicting-root rows (IMP-1). |
| `SlashingDb::pinned_gvr()` | `&self` | `Option<Root>` | Treats all-zeros as `None` (L-3). |

**Events:** none.

**Internal Structure (after fix):**
```
slashing/
├── src/
│   ├── lib.rs
│   ├── db.rs               # WHERE-clause keying scrubbed of client_cn
│   ├── stage.rs            # stage_* signatures lose client_cn
│   ├── scoped.rs           # NEW — PubkeyScopedDb (replaces bin/rvc-signer ScopedSlashingDb)
│   ├── import.rs           # NEW — InterchangeImporter (extracted from db.rs::import)
│   ├── migration.rs        # NEW — v_n → v_{n+1} migration with captured-DB tests
│   ├── audit.rs            # NEW — audit_log(client_cn, pubkey, outcome) — non-EIP-3076 audit trail
│   ├── types.rs
│   └── error.rs
└── tests/
    ├── interchange_import.rs   # GVR-1, IMP-1
    ├── pubkey_scope.rs         # DVT-1, CN-1
    └── migration_v1_to_v2.rs   # captured pre-migration DB fixture
```

**Key Design Decisions:**
- The schema migration is the *only* one-way change in this remediation. It is deliberately concentrated in `slashing` so other crates remain unaware of the historical CN-keying.
- The `client_cn` is preserved on disk as an audit column; reports that previously discriminated by CN can still join against it, but the safety property no longer depends on it.

**Failure Modes:**
- Migration failure on first start = startup refuses to begin (fail-closed). Operators are asked to back up before upgrading (release-note checklist, PRD §12).
- Import failure on conflicting-root = `InvalidInterchangeFormat` returned to API caller; for KM-1 this means the keymanager DELETE refuses to proceed.

---

### Module: `doppelganger` (extended — forward window state machine)

**Responsibility:** Owns the *only* implementation of doppelganger state. Holds per-validator state across the entire signing lifecycle. Provides the *only* answer to "is this pubkey allowed to sign right now?"

**Domain Entities (new):**
- `ForwardWindowMachine` — Lighthouse-style state machine (Research Angle 03):
  ```text
  Unmonitored ──register_at(epoch)──▶ Pending {
                                        start_epoch,
                                        end_epoch = start_epoch + monitoring_epochs,
                                        observed: Vec<LivenessSample>,
                                      }
  Pending ──last slot of e+1 + clean──▶ Safe
  Pending ──unexplained is_live──▶ Detected (terminal)
  Pending ──missing liveness entry──▶ Pending (no transition, fail-closed)
  ```
- `SigningGateOutcome` — `{ Allowed, BlockedDoppelganger, BlockedUnknownPubkey, BlockedPreGenesis }`. Default for unknown pubkey is `BlockedUnknownPubkey` (D-3 fail-closed; PRD Assumption #7).
- `LivenessChecker` (existing trait) — extended to require an entry for every requested index; missing index → `DoppelgangerError::IncompleteLiveness` (D-2).

**Data Store:** in-memory `HashMap<Pubkey, ValidatorState>` behind `parking_lot::Mutex`.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `ForwardWindowMachine::register(&self, pubkey, current_epoch)` | pubkey, epoch | `()` | Called at startup for each managed validator, AND from keymanager on import (KM-2). Idempotent. |
| `ForwardWindowMachine::is_signing_enabled(&self, pubkey)` | pubkey | `bool` | The ONLY answer the `SigningGate` consults. Default `false` for unknown (D-3 fail-closed). |
| `ForwardWindowMachine::tick(&self, current_epoch, slot_in_epoch)` | epoch, slot | `Vec<DoppelgangerStatus>` | Driven by orchestrator slot loop; advances state at the last slot of `e+1`. |
| `ForwardWindowMachine::observe_liveness(&self, epoch, samples)` | epoch, `Vec<ValidatorLivenessData>` | `Result<(), DoppelgangerError>` | Fails closed on missing entries (D-2). |
| `ForwardWindowMachine::cancel(&self, pubkey)` | pubkey | `()` | For KM-2: delete cancels any pending monitoring; re-import re-registers fresh. |

**Events:** none directly. The orchestrator may listen for `Detected → CRITICAL log + shutdown` per the Lighthouse pattern.

**Internal Structure (after fix):**
```
doppelganger/
├── src/
│   ├── lib.rs
│   ├── service.rs                  # legacy "look at past epochs" code; kept for backward-compat tests but no longer the gate
│   ├── forward_window.rs           # NEW — D-1, D-2, D-3, S-3, KM-2
│   ├── state.rs                    # NEW — per-validator state enum
│   ├── traits.rs                   # extended LivenessChecker, SlashingDbReader
│   └── error.rs
└── tests/
    ├── forward_window_satisfaction.rs   # D-1 (last slot of e+1)
    ├── forward_window_missing_liveness.rs  # D-2 fail-closed
    ├── forward_window_unknown_pubkey.rs    # D-3 fail-closed default
    ├── forward_window_pre_genesis.rs       # S-3 (epoch 0)
    └── forward_window_km2_race.rs          # KM-2 cancel-then-reimport
```

**Key Design Decisions:**
- The `ForwardWindowMachine` does NOT know about `SignerService`; the *dependency goes the other way*. `signer::SigningGate` depends on `doppelganger::ForwardWindowMachine` via a trait `SigningEnablement`. This means:
  - `doppelganger` is testable in isolation against a mock `LivenessChecker`.
  - `signer` is testable against a mock `SigningEnablement`.
  - `keymanager-api`'s existing `DoppelgangerGate` becomes a 30-line shim that delegates to `ForwardWindowMachine` — no behaviour code in `keymanager-api` (KM-2 race no longer reachable from the API surface).

**Failure Modes:**
- Liveness checker error → state stays `Pending` (fail-closed; PRD §6.3).
- BN unreachable for the full forward window → validator stays `Pending`, signing remains blocked. Operator-facing CRITICAL log after `2 * monitoring_epochs` to surface stuck state.

---

### Module: `signer` (extended — the SigningGate seam)

**Responsibility:** **The only place a slashable BLS sign can happen.** Every signing path — local-VC `signer::SignerService`, standalone `bin/rvc-signer` typed handlers, and `block-service` block-proposal path — routes through `SigningGate::sign_*`.

**Domain Entities (new):**
- `SigningGate` — composes:
  - `Arc<SlashingDb>` (or `PubkeyScopedDb<'_>`)
  - `Arc<dyn SigningEnablement>` (concrete: `ForwardWindowMachine`)
  - `Arc<CompositeSigner>` (existing BLS backend)
  - per-validator `ValidatorLockMap` (existing).
- `SigningGateError` — `BlockedByDoppelganger | BlockedBySlashingDb | SigningFailed | KeyNotFound | UnknownPubkey`.
- `SigningEnablement` (NEW trait) — implemented by `doppelganger::ForwardWindowMachine`; mocked in tests.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `SigningGate::sign_attestation(att, pk, fork, gvr)` | as today | `Result<Signature>` | Doppelganger gate → slashing stage → sign → commit. |
| `SigningGate::sign_block(root, slot, pk, fork, gvr)` | as today | `Result<Signature>` | Doppelganger gate → slashing stage → sign → commit. |
| `SigningGate::sign_sync_committee_message(...)` | as today | `Result<Signature>` | Doppelganger gate → sign (no DB stage; sync is not slashable but is gated — Teku pattern, Research Angle 03). |
| `SigningGate::sign_aggregate_and_proof(...)` | `AggregateAndProof` | `Result<Signature>` | **Doppelganger gate → sign** — no slashing-DB stage (SS-2/SS-3 fix; PRD §6 chain-of-custody note from R5). |
| `SigningGate::sign_contribution_and_proof(...)` | as today | `Result<Signature>` | Doppelganger gate → sign. |
| `SigningGate::sign_selection_proof(...)` | as today | `Result<Signature>` | Doppelganger gate → sign. |
| `SigningGate::sign_randao_reveal(...)`, `sign_voluntary_exit(...)`, `sign_builder_registration(...)` | as today | `Result<Signature>` | Today's behaviour preserved — no slashing-DB (correct per EIP-3076 scope). Builder registration still bypasses doppelganger (fixed timestamp; non-slashable). |

**Events:** none — synchronous.

**Internal Structure (after fix):**
```
signer/
├── src/
│   ├── lib.rs              # SignerService (kept) — now wraps SigningGate
│   ├── gate.rs             # NEW — SigningGate is the seam
│   ├── enablement.rs       # NEW — trait SigningEnablement (mocked in tests)
│   ├── traits.rs           # ValidatorSigner trait (existing) — implemented on SigningGate
│   └── error.rs            # NEW — SigningGateError
└── tests/
    ├── gate_attestation_doppelganger_blocked.rs   # D-3 attestation
    ├── gate_block_doppelganger_blocked.rs         # D-3 block
    ├── gate_sync_doppelganger_blocked.rs          # D-3 sync
    ├── gate_aggregate_no_slashing_db.rs           # SS-2/SS-3
    ├── gate_per_validator_lock.rs                 # existing TOCTOU
    └── gate_unknown_pubkey_fails_closed.rs        # D-3 default
```

**Key Design Decisions:**
- `bin/rvc-signer`'s typed handlers, today scattered across `service.rs` with hand-rolled `require_db()/stage_attestation/commit` patterns, are migrated to call `SigningGate` methods directly. The handler shrinks to: deserialise request → fork-info validate → `gate.sign_*` → serialise response.
- v1 raw-root `sign(signing_root, pubkey)` is *gone* from the live listener (SS-1). If a legacy listener is requested, it is a separate `tonic::transport::Server` instance behind an `InsecureGate::Allow` opt-in, with NO `SigningGate`-routed path — its handler unconditionally returns `Status::unimplemented`.
- The `SigningGate` is built once at process start; all crates that need to sign hold an `Arc<SigningGate>` (typed via `dyn ValidatorSigner` from `signer::traits`).

**Failure Modes:**
- Doppelganger gate refuses → return `BlockedByDoppelganger`, never delegate to backend.
- Slashing DB stage fails → return `BlockedBySlashingDb`, never delegate.
- Backend sign fails → discard staged DB row (existing behaviour preserved).

---

### Module: `net-policy` (NEW seam)

**Responsibility:** Single source of truth for "is this URL/IP safe to talk to over the network?" Owns the SSRF deny-list (URL-1) and the IP pinning / DNS-rebinding protection (URL-2). Consumed by `crates/keymanager-api` (`/eth/v1/remotekeys` import URL) and `crates/crypto::remote_signer` (every long-lived signing connection).

**Domain Entities:**
- `DenyList` — IPv4 + IPv6 reserved ranges. Per Research Angle 04 corrections: `0.0.0.0/8`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, IPv4 multicast; IPv6 normalises IPv4-mapped/`::a.b.c.d` and rejects multicast (`ff00::/8`), link-local, ULA. Cited to RFC 6890 + IANA registries, NOT RFC 5735.
- `UrlPolicy { allow_http: bool, allow_loopback: bool }` — the scheme/host policy.
- `PinnedResolver` — wraps `reqwest::dns::Resolve` and `reqwest::resolve_to_addrs`. Once an import-time IP is validated, the same `SocketAddr` is reused by the signing connection (URL-2). On every connect, the resolved IP is re-checked against `DenyList`.
- `validate_url(url, &UrlPolicy) -> Result<ValidatedUrl, NetPolicyError>` — case-insensitive scheme compare (L-1) using normalised `url::Url`.

**Data Store:** none.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `validate_url(s, &UrlPolicy)` | URL string | `Result<ValidatedUrl, NetPolicyError>` | URL-1 + L-1 (mixed-case `https://`). |
| `validate_url_runtime(s, &UrlPolicy)` | URL string | `Result<(ValidatedUrl, Vec<SocketAddr>), _>` | DNS-resolve + deny-list check on every resolved IP. |
| `PinnedResolver::pin(validated_url)` | `ValidatedUrl` | `PinnedResolver` | Returns a resolver that can be plugged into `reqwest::Client::builder().dns_resolver(...)`. |
| `PinnedResolver::recheck(&self)` | `&self` | `Result<(), NetPolicyError>` | Called inside `remote_signer.rs` before every sign (URL-2). |

**Events:** none.

**Internal Structure:**
```
net-policy/
├── src/
│   ├── lib.rs
│   ├── deny_list.rs       # URL-1 — ipnet-style match; well-known reserved ranges
│   ├── url_policy.rs      # UrlPolicy struct + validate_url + L-1
│   ├── pinned_resolver.rs # URL-2 IP pinning, reqwest integration
│   └── error.rs
└── tests/
    ├── deny_list_ipv4.rs    # 0.0.0.0/8, 192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24, 240/4, multicast
    ├── deny_list_ipv6.rs    # ff00::/8 (multicast), fe80::/10, fc00::/7, IPv4-mapped variants
    ├── mixed_case_scheme.rs # L-1
    ├── rebinding_recheck.rs # URL-2 — DNS returns allowed IP then rebinds to private
    └── reserved_ranges_property.rs
```

**Key Design Decisions:**
- Lives in its own crate because both `keymanager-api` and `crypto::remote_signer` depend on it, but neither depends on the other. Placing it in either would create a cycle.
- Uses only stdlib `IpAddr` + `url` + `reqwest`. No new third-party deps (PRD §2 non-goal).
- The const tables of reserved ranges are private; tests access via the public `validate_url` only, so future range edits live in one file and are covered by one test suite.

**Failure Modes:**
- Any deny-list match or unresolvable host = `Err(NetPolicyError::Denied { reason })`. Callers MUST propagate (fail-closed; PRD §6.3).

---

### Module: `insecure-gate` (NEW small seam)

**Responsibility:** Provides the `Refuse | Warn | Allow` decision pattern with consistent env-variable opt-in semantics, consumed by SS-1 (legacy v1 listener), KM-3 (keymanager non-loopback), L-1 (mixed-case scheme), SIG-1 (`--password-dir` fallback).

**Domain Entities:**
- `InsecureGate { Refuse, Warn, Allow }` — enum.
- `Decision::evaluate(env_var, default) -> Decision` — reads `RVC_*` env var, returns `Continue | RefuseStartup(reason)`.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `InsecureGate::from_env(var)` | `&str` | `Self` | Reads e.g. `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK`. |
| `Decision::evaluate(gate, condition_is_insecure)` | gate, bool | `Decision` | Logs `warn!` on `Warn`; returns refuse on `Refuse`. |

**Internal Structure:**
```
insecure-gate/
├── src/
│   ├── lib.rs
│   └── env.rs
└── tests/
    ├── refuse_default.rs
    └── env_parse.rs
```

**Key Design Decisions:**
- Today, `bin/rvc-signer/src/insecure_startup.rs` and `bin/rvc/src/main.rs` each implement their own variant. Promoting to a shared crate guarantees that SS-1's "off-by-default insecure opt-in" matches KM-3's exactly. The seam is small (≈ 60 LoC) but structurally prevents the "metrics is hard-refuse, keymanager is just `warn!`" inconsistency the review found.

**Failure Modes:**
- `Refuse` decision = startup aborts with `Err(...)`. Bins propagate with `anyhow`.

---

### Module: `keymanager-api` (extended — thin shim)

**Responsibility:** HTTP API for keystore import/delete and remote-key import. After remediation, **all heavy logic moves out of this crate**:
- URL validation → `net-policy`.
- Time-based doppelganger gate → `doppelganger::ForwardWindowMachine` (the existing `gate.rs` becomes a 30-line shim).
- DELETE export semantics (KM-1) → `slashing::InterchangeImporter` returns hard error → handler aborts the DELETE before any keystore is removed.
- Cancel-token concurrency (KM-2) → handled by `ForwardWindowMachine::cancel`, which is single-implementation; the keymanager-API's `concurrent delete+re-import` race becomes impossible because there is no API on `ForwardWindowMachine` that can return `Some(old_token)` without cancelling it.
- KS-1 keystore-import param ceiling → enforced at the `crypto::Keystore::decrypt_with_caps` boundary (existing) and called *before* decrypt at the handler.
- KM-3 non-loopback bind → routed through `insecure-gate`.

**Public API:** unchanged (RESTful endpoints). Handler internals shrink significantly.

**Internal Structure:**
```
keymanager-api/
├── src/
│   ├── lib.rs
│   ├── server.rs
│   ├── handlers.rs            # MUCH SMALLER — delegates to seams
│   ├── url_validator.rs       # → REMOVED; replaced by net-policy
│   ├── gate.rs                # → SHIM over doppelganger::ForwardWindowMachine
│   ├── auth.rs
│   ├── types.rs
│   └── error.rs
└── tests/
    ├── delete_export_failure_aborts.rs   # KM-1 — no key deleted on export error
    ├── concurrent_delete_reimport.rs     # KM-2 — race no longer reachable
    ├── import_url_ssrf_rejected.rs       # URL-1 — delegates to net-policy
    ├── import_url_rebinding_rejected.rs  # URL-2
    ├── keystore_oversized_params_rejected.rs # KS-1
    └── non_loopback_bind_refuses.rs      # KM-3
```

**Failure Modes:**
- DELETE with export error → 500, no deletion, no slashing-protection rows removed.
- Concurrent delete+re-import → second import waits for the cancellation handshake from `ForwardWindowMachine::cancel`.

---

### Module: `bin/rvc-signer` (extended + legacy gate)

**Responsibility:** Standalone signer binary. Post-remediation:
- v1 raw-root `sign(signing_root, pubkey)` gRPC service is **NOT** registered on the live `tonic::Server` (SS-1).
- v2 typed handlers route through `signer::SigningGate` (the existing `SignerService` + `ScopedSlashingDb` duo is replaced by `SigningGate` + `PubkeyScopedDb`).
- `bin/rvc-signer/src/slashing/scope.rs` is **deleted**; its 3 call sites switch to `slashing::PubkeyScopedDb` (DVT-1, CN-1).
- DVT partial-sign path (`bin/rvc-signer/src/dvt/peer_service.rs`) keys by validator aggregate pubkey + GVR; CN survives only as an audit field.
- DVT aggregator v1 raw-root path (DVT-2) is removed; only v2 typed PartialSign remains.

**Internal Structure (key changes):**
```
bin/rvc-signer/
├── src/
│   ├── main.rs                  # SS-1: v1 SignerServiceServer NOT add_service'd on live listener.
│   │                             # InsecureGate-gated legacy listener (if compiled) returns Unimplemented.
│   ├── service.rs               # v2 handlers route through SigningGate.
│   │                             # sign_aggregate_and_proof: no DB consult (SS-2/SS-3).
│   ├── slashing/
│   │   ├── scope.rs             # → DELETED. Uses slashing::PubkeyScopedDb.
│   │   └── config.rs
│   ├── dvt/
│   │   ├── peer_service.rs      # DVT-1: pubkey-scoped slashing (no per-peer CN).
│   │   ├── peer_client.rs       # DVT-2: v1 raw-root deleted.
│   │   ├── lagrange.rs          # DVT-5: reject share_index == 0.
│   │   └── allow_list.rs
│   └── insecure_startup.rs      # → replaced by insecure-gate crate use.
```

---

### Module: `crates/rvc` (orchestrator, extended)

**Responsibility:** Slot loop, duty fan-out, doppelganger startup wiring, keymanager adapters. Post-remediation:
- **No direct calls to `crypto::sign_*`** from any orchestrator path. All signs go through `signer::SigningGate`.
- `is_attesting_enabled` is **deleted** from `validator-store::store` (PRD Assumption #7). The orchestrator at every signing entry point holds an `Arc<dyn ValidatorSigner>` from `signer`, and the gate inside that trait answers the question.
- Doppelganger startup detection is wired through `ForwardWindowMachine::register` for each managed pubkey (D-1) and `tick` on each slot boundary; `if current_epoch > 0` guard in `main.rs:1264-1287` is removed (S-3).
- Keymanager adapters (KM-2 cancel-token race) delegate to `ForwardWindowMachine::cancel`.
- `aggregation.rs`: `validate_attestation_data` runs on BN responses (L-4); `sync_committee.rs`: `head_root` captured via `get_block_root("head")` with fallback (S-5).
- Optimistic-BN response gate: `coordinator` consults `bn_manager::tier()` and refuses to sign on `execution_optimistic = true` responses (BN-1).
- `key_gen_rx` consumed via `borrow_and_update` (C-1); wired to keymanager imports so an import triggers exactly one `clear_cache()` (S-2).

**Internal Structure (key changes):**
```
crates/rvc/
└── src/
    ├── orchestrator/
    │   ├── coordinator.rs      # SigningGate routing; C-1 borrow_and_update; S-2 wired key_gen.
    │   ├── attestation.rs      # routes via signer::SigningGate.
    │   ├── aggregation.rs      # L-4 validate_attestation_data; SS-2/SS-3 path.
    │   ├── sync_committee.rs   # SigningGate.sign_sync_committee_message; S-5 head_root fallback.
    │   ├── duty_management.rs
    │   └── slot_context.rs
    └── keymanager_adapters.rs  # KM-2 single-implementation via ForwardWindowMachine.
```

---

## Cross-Cutting Concerns

### Authentication & Authorization

Unchanged in surface — keymanager-API token auth, gRPC mTLS (with `tls_enabled` log fixed per GRPC-1), BN bearer token.

Post-remediation, all "is this key allowed to sign right now?" questions go through `signer::SigningGate`, which composes:
1. `ForwardWindowMachine::is_signing_enabled(pubkey)` — fail-closed on unknown pubkey.
2. `PubkeyScopedDb` stage (only for slashable message classes).
3. Backend signature.

This is the structural enforcement that prevents D-3 from regressing: the orchestrator simply has no API surface to bypass the gate, because `crypto::Signer::sign` is not held by any orchestrator code — only by `SigningGate`.

### Logging & Observability

- Structured `tracing` spans on every `SigningGate::sign_*` method (existing pattern in `signer/src/lib.rs` preserved).
- `rvc.slashing.result` field on every slashable sign.
- `rvc.doppelganger.gate_outcome` field on every sign (NEW seam-level observation).
- `telemetry::redact_endpoint` (TEL-1 fix) used by all telemetry exports.
- Metrics (`rvc-metrics`) extended with `rvc_doppelganger_gate_total{outcome}` per pubkey-class.

### Error Handling

- Common `thiserror`-derived enums per crate; `?`-propagation across boundaries.
- Seam-level errors are *terminal* at the orchestrator; no fallback retry on `BlockedByDoppelganger` or `BlockedBySlashingDb`.
- BN response validation (`validate_attestation_data`, `validate_attestation_data` for aggregation L-4, sync-committee SYNC-1) returns `Err` → skip + warn, never sign.

### Configuration

- `insecure-gate` env vars: `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK`, `RVC_SIGNER_LEGACY_V1` (NEW; off by default), etc.
- `--token-file` / `--token-env` for bearer tokens (CLI-1).
- `--password-dir` semantic finalised (per-keystore file `<dir>/<pubkey>.txt`, SIG-1).

---

## Data Flow Diagrams

### Doppelganger-gated attestation

```text
Slot tick (orchestrator)
   │
   ▼
duty-tracker ──fetch──▶ bn-manager ──HTTP──▶ Beacon Node
                                  ◀── attestation duty
   │
   ▼
orchestrator::attestation
   │
   ▼  attest_data, pubkey, fork_schedule, gvr
signer::SigningGate::sign_attestation
   │
   ├──▶ ForwardWindowMachine::is_signing_enabled(pubkey)
   │      └── false (still in window) ──▶ BlockedByDoppelganger ──▶ SKIP + warn!, NO signature
   │      └── true ──▶ continue
   │
   ├──▶ PubkeyScopedDb::stage_attestation(pubkey, src, tgt, root, gvr)
   │      └── slashable ──▶ BlockedBySlashingDb ──▶ discard guard, NO signature
   │      └── safe ──▶ continue (transaction held)
   │
   ├──▶ CompositeSigner::sign(signing_root, pubkey_bytes)
   │      └── err ──▶ guard.discard() ──▶ propagate
   │      └── ok ──▶ guard.commit()
   │
   ▼
propagator::publish ──▶ multi-BN fan-out
```

### Keymanager import wires through to ForwardWindowMachine

```text
POST /eth/v1/keystores  ──▶ keymanager-api::handlers::import
   │
   ├──▶ crypto::Keystore::decrypt_with_caps (KS-1)
   │
   ├──▶ slashing::InterchangeImporter::import (GVR-1, IMP-1)
   │       └── err ──▶ 400 (failed-closed; key NOT loaded)
   │
   ├──▶ ValidatorManager::insert_local_key
   │
   ├──▶ ForwardWindowMachine::register(pubkey, current_epoch)   ◀── KM-2 single-implementation
   │
   └──▶ key_gen_tx.send(())                                     ◀── S-2 wires to orchestrator
            │
            ▼
       orchestrator::coordinator::key_gen_rx.borrow_and_update  ◀── C-1
            │
            ▼
       duty-tracker::update_validator_indices                   ◀── DT-1
```

Any sign request for the new pubkey is blocked by `ForwardWindowMachine::is_signing_enabled == false` for the next `monitoring_epochs` epochs.

### DELETE /eth/v1/keystores fails closed on export error

```text
DELETE /eth/v1/keystores  ──▶ keymanager-api::handlers::delete
   │
   ├──▶ slashing::InterchangeImporter::export(pubkeys)
   │       ├── ok(interchange) ──▶ continue
   │       └── err ──▶ 500, NO KEY DELETED        ◀── KM-1 fail-closed
   │
   ├──▶ for each pubkey:
   │       ├── ValidatorManager::remove(pubkey)
   │       └── ForwardWindowMachine::cancel(pubkey)
   │
   └──▶ 200 { data, slashing_protection: interchange }
```

### Block proposal SSZ publish (B-1/T-1)

```text
SigningGate::sign_block(block_root, slot, ...)
   │  block_root = container_tree_hash_root(BeaconBlockBody)   ◀── E-1
   │
   ▼
block-service::propose_block
   │
   ├──▶ encode_signed_block_contents:
   │      - serialise SignedBeaconBlock with three variable offsets
   │      - bound at kzg_offset
   │      - append kzg_proofs, then blobs                       ◀── B-1/T-1
   │
   └──▶ propagator::publish_block_ssz (bytes pass deserialise round-trip)
```

---

## Infrastructure & Deployment

### Deployment Model

Unchanged: Cargo workspace, three bins (`rvc`, `rvc-signer`, `rvc-keygen`). All three build from the same workspace; `rvc-signer` is a separate process that the VC talks to over gRPC. No new bins; no new processes.

### Scaling Strategy

Unchanged. The shared seams are in-process libraries; no new network hops are introduced. The `SigningGate`'s per-validator mutex map is the existing one from `signer/src/lib.rs`.

### Service Extraction Path

The remediation does NOT change the existing extraction path. For completeness, the new shared seams' extraction-readiness:

| Seam | Owning crate | Extraction readiness | Notes |
|---|---|---|---|
| `eth-types::canonical` | eth-types | **Keep together** — type helpers, no state, no benefit to extracting. |
| `eth-types::tree_hash_utils` | eth-types | **Keep together** — pure functions over types defined in same crate. |
| `net-policy` | net-policy (new) | **Already extracted** as a small crate; could become a workspace package or even an external crate later. |
| `insecure-gate` | insecure-gate (new) | **Already extracted**; same as above. |
| `SigningGate` | signer | **Keep together** with `crypto`, `slashing`, `doppelganger` — the seam IS the boundary between orchestrator and BLS backend; splitting it further would just push the same composition out one level. |
| `ForwardWindowMachine` | doppelganger | **Ready now** — already an independent crate with trait-mocked dependencies. Could be a sidecar service in a future architecture (one `ForwardWindowMachine` per cluster). |
| `PubkeyScopedDb` + `InterchangeImporter` | slashing | **Ready now** — `slashing` is already a candidate for the "remote slashing service" pattern that operators sometimes deploy. Post-remediation it is more so, because the API surface is smaller (no `client_cn` arg). |

---

## Technology Choices

No technology choices change. Per PRD §2 non-goal: "No new dependencies unless a fix has no in-tree alternative."

| Concern | Choice (unchanged) | Why preserved |
|---|---|---|
| Language | Rust 2021, MSRV 1.92 | workspace pin |
| Async runtime | Tokio | existing |
| HTTP server | Axum | keymanager-api |
| gRPC | tonic + prost | rvc-signer |
| HTTP client | reqwest (rustls) | BN + keymanager + remote-signer; `net-policy` plugs in via `reqwest::dns::Resolve`. |
| SSZ | `ethereum_ssz` + `tree_hash` | E-1/E-2 fix uses existing primitives |
| BLS | `blst` | existing |
| Slashing DB | SQLite (`rusqlite`) | existing; schema migration only |
| Error model | `thiserror` per crate, `anyhow` at bin level | existing |

---

## ADRs (Architecture Decision Records)

### ADR-001: Centralise the slashing-protection + doppelganger signing gate in `crates/signer`

- **Status:** Accepted
- **Context:** D-3 (P0) found that the doppelganger enable-gate is only consulted on attestation; block proposal, sync, and aggregation paths sign fail-open. The review's PRD assumption #6 prefers centralisation. SS-2/SS-3 (P0) and DVT-1/CN-1 (P0/P1) found that EIP-3076 consultation is reimplemented (incorrectly) at multiple sites.
- **Decision:** Introduce `SigningGate` in `crates/signer` as the *only* code path that takes a slashable message and produces a BLS signature. Compose `ForwardWindowMachine` (doppelganger) + `PubkeyScopedDb` (slashing) + `CompositeSigner` (BLS). All orchestrator paths, all `bin/rvc-signer` typed handlers, all DVT partial-sign sites depend on `SigningGate`.
- **Alternatives Considered:**
  - *Scatter the gate across orchestrator entry points*: the PRD-rejected alternative. More invasive over time; every new signing path becomes a regression risk.
  - *Put the gate in `bin/rvc-signer` only*: leaves the in-process VC sign path (local-VC mode) ungated. Would require duplicating the logic in `crates/signer`.
  - *Put the gate in `crates/rvc` (orchestrator)*: the orchestrator is already the largest crate; adding gating logic there does not actually reduce duplication for `bin/rvc-signer`.
- **Consequences:** The orchestrator becomes structurally unable to bypass the gate (no more direct `crypto::sign_*` calls). `bin/rvc-signer`'s handler code shrinks by ~30%. Future signing paths (e.g. EIP-7657 if it ever revives) automatically inherit the gate by virtue of using the `SigningGate` API.

### ADR-002: Introduce `crates/net-policy` as a new small crate

- **Status:** Accepted (proposed)
- **Context:** URL-1 (deny-list) and URL-2 (IP pinning + DNS rebinding) are needed by both `keymanager-api` and `crypto::remote_signer`. Today, `keymanager-api/src/url_validator.rs` owns deny-list logic; `crypto::remote_signer` has its own (incomplete) check. Placing the helper in either creates a dependency from the other towards a crate that should not export it.
- **Decision:** Extract to a new `crates/net-policy` crate at workspace level. Both consumers depend on it.
- **Alternatives Considered:**
  - *Put it in `crypto`*: makes `keymanager-api` depend on a crate that already pulls in BLS, which it does anyway but for a narrower purpose. Acceptable fallback if "no new crates" becomes a constraint.
  - *Put it in `eth-types`*: violates eth-types' "no network" boundary.
  - *Leave it duplicated*: violates the shared-seams optimisation goal; URL-1 + URL-2 regress easily.
- **Consequences:** One new tiny crate (~ 400 LoC). One new entry in `Cargo.toml [workspace.dependencies]`. Cleaner extraction story: `net-policy` could become a public crate later if other Rust validator stacks want it.

### ADR-003: Introduce `crates/insecure-gate` as a new small crate

- **Status:** Accepted (proposed)
- **Context:** SS-1 (legacy v1 listener gate), KM-3 (keymanager non-loopback gate), L-1 (mixed-case scheme), SIG-1 (`--password-dir` fallback policy) all want the same `Refuse | Warn | Allow` semantics with `RVC_*_ALLOW_*` env vars. Today, `bin/rvc-signer/src/insecure_startup.rs` and `bin/rvc/src/main.rs` each implement it separately. The review found the keymanager-API today is just `warn!` while metrics is hard-refuse (KM-3); SS-1 needs a similar opt-in.
- **Decision:** Extract to a new `crates/insecure-gate` crate. All bins (and `keymanager-api` for the bind decision) depend on it.
- **Alternatives Considered:**
  - *Inline a function in each bin*: cheaper, but the review explicitly cited the inconsistency as a finding; correctness depends on the implementations matching exactly.
  - *Put it in `crates/rvc`*: pulls a heavy dep into bins that don't otherwise need it (`rvc-signer` doesn't depend on `rvc`).
- **Consequences:** One new tiny crate (~ 100 LoC). Makes future "insecure opt-in" additions trivial and consistent.

### ADR-004: Pubkey-scoped slashing keying with `client_cn` as audit-only column

- **Status:** Accepted
- **Context:** DVT-1 (P0) and CN-1 (P1) share a root cause: the slashing DB's `WHERE`-clauses include `client_cn`, so two clients/peers using the same pubkey end up with independent watermarks and can each sign a conflicting message.
- **Decision:** Change the SQLite uniqueness indices to `(pubkey, gvr, slot|target_epoch)`. Keep `client_cn` as a non-key audit column. Migrate existing DBs by raising the watermark of any pre-migration duplicates.
- **Alternatives Considered:**
  - *Enforce pubkey→CN binding*: still leaves the DB unable to detect cross-CN double-sign without an explicit cross-CN check on every call.
  - *Per-CN multi-tenancy as primary key with a separate cross-CN sentinel table*: more moving parts; defers the actual safety property to a secondary mechanism.
- **Consequences:** One-way schema migration on first start after upgrade. Documented in release notes. Backup recommended. Captured pre-migration DB fixture in `slashing/tests/migration_v1_to_v2.rs` verifies the migration is correct.

### ADR-005: `ForwardWindowMachine` is the source of truth for doppelganger state, not `keymanager-api::gate`

- **Status:** Accepted
- **Context:** Today `keymanager-api/src/gate.rs` owns a time-based `DoppelgangerGate` map, which is the lever for KM-2's cancel-token race. The actual doppelganger detection runs in `crates/doppelganger`, but only at startup, and only on attestation (D-3).
- **Decision:** The state machine moves to `crates/doppelganger::forward_window`. `keymanager-api::gate` becomes a shim that delegates `start_monitoring`, `is_doppelganger_safe`, and `cancel` to `ForwardWindowMachine`. The signer's `SigningGate` consults the same `ForwardWindowMachine` instance.
- **Alternatives Considered:**
  - *Keep two implementations and sync them*: KM-2 race is exactly the kind of bug this re-introduces.
  - *Put everything in `keymanager-api`*: violates separation of concerns (the gate must be queried by the orchestrator and the signer, not just the keymanager).
- **Consequences:** `keymanager-api::gate` shrinks to a 30-line shim. `crates/doppelganger` grows by the forward-window module. KM-2 race becomes structurally impossible because there is no `insert` API that can return an un-cancelled old token.

### ADR-006: `eth-types::canonical` owns ALL hex/GVR/pubkey parsing

- **Status:** Accepted
- **Context:** L-2 (pubkey hex parsing), L-3 (all-zeros GVR), GVR-1 (mixed-case GVR import), IMP-1 (interchange validation), Info-4 (BN GVR/fork-version validation) all do hex/format parsing in different crates with different rules.
- **Decision:** Add a `canonical` module to `eth-types`. Every call site that today calls `hex::decode` on a pubkey, GVR, or signing root switches to `canonical::parse_pubkey_hex`, `canonical::parse_gvr_hex`, `canonical::parse_signing_root_hex`. The slashing DB's `import()` uses `canonical::eq_gvr`. The beacon client's response parser uses the canonical parsers for any 32-byte or 4-byte hex field.
- **Alternatives Considered:**
  - *Per-crate helpers*: today's state; the findings prove it doesn't hold up.
  - *Put in `crypto`*: works, but `slashing` would gain a transitive `crypto` dep just for hex parsing. `eth-types` is the natural home.
- **Consequences:** A handful of `hex::decode` call sites collapse to one each. L-2 and L-3 close as one test suite in `eth-types/tests/canonical_helpers.rs`.

### ADR-007: SSZ tree-hash correctness is enforced at the helper level, not at the call site

- **Status:** Accepted
- **Context:** E-1 (BeaconBlock body tree-hashed as `List[byte]`) and E-2 (Bitlist merkleized to `next_power_of_two(bytes)`) are call-site mistakes that could not be caught by any cross-call-site test because each call site computes its own root.
- **Decision:** Rewrite `eth-types::tree_hash_utils` so that:
  - `bitlist_tree_hash_root<const N: usize>(bytes)` requires the caller to pass `N` as a const-generic, with the chunk-count computed as `(N + 255) / 256`.
  - `container_tree_hash_root::<T: TreeHash>(value)` is the only "tree-hash a container" function; a `BodyHashRoot([u8; 32])` newtype is the parameter type of `BeaconBlock::body_root` setter, so passing a `List[byte]` root refuses to compile.
- **Alternatives Considered:**
  - *Fix E-1 / E-2 in-place at the call sites*: passes the test, leaves the root cause (no helper-level enforcement) intact.
- **Consequences:** Spec-vector fixtures live in `eth-types/tests/fixtures/` and are the regression test for both findings. Future refactors that re-introduce the bug refuse to compile.

### ADR-008: Aggregator path signs without slashing DB consult; chain-of-custody is documented

- **Status:** Accepted
- **Context:** SS-2/SS-3 (P0) found that `sign_aggregate_and_proof` runs attestation slashing protection (incorrectly polluting the watermark and breaking aggregator duty when the aggregator also attests for the same target). Research §R5 (Angle 02) clarified that aggregate-and-proof is correctly *out of* EIP-3076 scope **only because** the inner Attestation was already signed via `sign_attestation` through the slashing-DB path.
- **Decision:** `SigningGate::sign_aggregate_and_proof` consults `ForwardWindowMachine` but NOT `PubkeyScopedDb`. A module-level comment in `signer/src/gate.rs` cites the chain-of-custody precondition (the Attestation inner-message must have been signed via `sign_attestation`). The orchestrator's aggregation flow (`crates/rvc::orchestrator::aggregation`) is documented to require attestation-first ordering; an integration test exercises attest → aggregate for the same target and asserts both succeed (M3, PRD §4).
- **Consequences:** Removes the SS-2/SS-3 break for the aggregator's duty. Closes the L-9 mistaken `#[ignore]` together with B-1/T-1.

---

## Open Questions

These remain unresolved by both the PRD and the research overview; the architecture defers to runtime defaults.

- **Q1 (PRD §10):** Is a v1 raw-root legacy gRPC service compiled-but-`Unimplemented`, or deleted? *Architecture default:* compiled, gated by `insecure-gate::RVC_SIGNER_LEGACY_V1=true`, returns `Status::unimplemented` unconditionally even when allowed (so the only difference is whether the service is registered at all). Open for review-gate decision.
- **Q2 (PRD §10):** DVT-1 per-CN audit column — is the audit-log enough or do operators rely on a per-CN watermark for compliance? *Architecture default:* audit-only; the `slashing::audit` module records every (pubkey, cn, outcome) tuple.
- **Q3 (PRD §10):** Production on-disk slashing DBs — assumed yes; migration is automatic. If `no`, the migration step is a no-op.
- **Q4 (PRD §10):** Gate centralisation in `signer` vs orchestrator — **decided: signer** (ADR-001).
- **Q5 (PRD §10):** `--password-dir` semantics (SIG-1) — *architecture default:* per-keystore `<dir>/<pubkey>.txt` (PRD Assumption); routes through `insecure-gate` for the shared-file fallback.
- **Q6 (PRD §10):** P2 inclusion vs deferral — *architecture default:* P2 fixes that ride on the seams (L-1, L-2, L-3, D-2, S-3, L-4, SYNC-1) are included; the rest can defer.
- **Q7 (NEW from R2):** B-1/T-1 / L-9 actual landed state — must run `cargo test -- --ignored` before writing the RED test for B-1/T-1. The architecture is unchanged either way; only the test order changes.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Slashing DB migration corrupts a production DB | Low | Catastrophic (operator loses watermark) | Captured fixture in `slashing/tests/migration_v1_to_v2.rs`; release notes mandate backup before upgrade; migration is idempotent and refuses to run twice. |
| `ForwardWindowMachine` introduces a startup-time delay for managed validators (~12 min mainnet) | High (this is the intended behaviour) | Medium (operator-visible) | Documented in release notes (PRD §12); behaviour already documented in existing `keymanager-api/src/gate.rs`. |
| `SigningGate` centralisation increases mean signing latency | Low | Low | Per-validator mutex map preserved; the only added per-sign work is one `HashMap::get` on the `ForwardWindowMachine` — negligible. |
| `net-policy` and `insecure-gate` as new crates inflate workspace `Cargo.toml` and compile time | Low | Low | Both are ~ 400 LoC and ~ 100 LoC respectively; tree-shaking and incremental compile keep cost minimal. |
| `eth-types::tree_hash_utils` rewrite breaks an unrelated consumer | Medium | High | Spec-vector fixtures (PRD §6.2) cross-check against Lighthouse/Lodestar; full existing test suite remains green as the RED→GREEN gate. |
| KM-1 fail-closed DELETE breaks an existing operator workflow that relied on partial-success | Low | Medium | Per PRD Assumption #9: simpler abort-on-error is preferred. Release notes call this out. |
| ADR-001 (centralised gate) requires touching every signing call site | Medium | High effort | Pre-work: list every call site (grep `CompositeSigner::sign`, `crypto::sign`, `Signer::sign`) before the GREEN commit; migrate in one PR per crate with a checklist. |
| DVT-1 schema migration breaks a multi-tenant operator's audit story | Low | Medium | Audit column preserved; `slashing::audit` API exposes per-CN history; release notes guide operators. |
| `bin/rvc-signer` v1 raw-root removal breaks an unknown integrator | Low | Medium | Per PRD Assumption #4: no production consumer assumed; release notes call out the removal explicitly. Insecure-gate provides an off-by-default opt-in. |

---

## Assumptions (architecture-specific, additive to PRD §8)

1. **`net-policy` as a new crate is acceptable.** If the team wants to avoid a new crate, the architecture-fallback is to put the module in `crypto` and have `keymanager-api` depend on `crypto` (it already does). This degrades the conceptual separation (`crypto` becomes "BLS + network policy") but does not introduce a cycle.
2. **`insecure-gate` as a new crate is acceptable.** Same fallback as above; can live in `crates/rvc` and be re-exported, at the cost of pulling `crates/rvc` into `bin/rvc-signer`, which today it isn't. The architecture prefers the small new crate.
3. **`ForwardWindowMachine` semantics match Lighthouse v5.3.0's `doppelganger_service.rs`.** Per Research §R8: epoch satisfaction at the last slot of `e+1`, CRITICAL log on missing entries, pre-genesis bypass to `remaining_epochs = 0`.
4. **The orchestrator can absorb the `Arc<dyn ValidatorSigner>` injection at every signing call site.** A pre-work grep confirms the count is ~ 8 call sites (block, attestation, aggregation, sync-committee message, sync-committee contribution, selection-proof, voluntary-exit, builder-registration). Migration is mechanical.
5. **Schema migration tooling can be in-process.** The migration runs on `SlashingDb::open` if the schema version is stale. No external migration binary required.
6. **`bin/rvc-signer::ScopedSlashingDb` has no external API consumers.** The PRD treats it as internal to `bin/rvc-signer`; deletion is non-breaking.
7. **Spec-vector fixtures from `consensus-spec-tests`** (PRD Assumption #2) are reachable; the architecture deliberately co-locates them in `eth-types/tests/fixtures/` so a single `README` documents provenance.
8. **`is_attesting_enabled` rename to `is_signing_enabled`** (PRD Assumption #7) is in-scope and applied at every call site as the D-3 GREEN commit.
9. **Web search MCP servers ("alphaXiv") are NOT consulted** even though prompt-injection blocks have appeared in past tool outputs (Research overview §0). This architecture is built from the PRD + research + repo only.
10. **`crates/insecure-gate` does NOT itself depend on `tracing` for its `Warn` log** — it returns a structured `Decision` and the calling bin emits the `warn!`. This keeps the crate workspace-leaf-clean.
11. **No new top-level public re-exports.** All seam types are crate-public; consumers import by full path (e.g. `signer::SigningGate`, not `rvc::signer::SigningGate`). This guards the seam boundaries.
12. **The orchestrator's `is_signing_enabled` fast-path for non-doppelganger-monitored validators** (e.g. validators registered outside the window) is `ForwardWindowMachine::is_signing_enabled` returning `true` once the validator transitions to `Safe`. No separate fast-path is added.
13. **R2's `cargo test -- --ignored` precondition for B-1/T-1** is performed at the start of M2 work, before any RED commit for B-1/T-1 lands. The architecture is unchanged whichever way R2 resolves.

---

## Architecture Quality Checklist

- [x] **No circular dependencies between modules.** Verified by the level-graded dependency table; every arrow goes from higher level to lower.
- [x] **Each module has a single, clear responsibility describable in one sentence.** See Module Overview table.
- [x] **No shared databases.** Slashing DB is owned by `crates/slashing`; doppelganger state is in-memory inside `crates/doppelganger`; no other crate touches either.
- [x] **All inter-module communication goes through defined interfaces.** `SigningEnablement` trait, `LivenessChecker` trait, `SlashingDbReader` trait, `ValidatorSigner` trait, `Signer` trait. No backdoor imports.
- [x] **Every module can be tested in isolation with mocked dependencies.** `signer::SigningGate` against mock `SigningEnablement`; `doppelganger::ForwardWindowMachine` against mock `LivenessChecker`; `slashing::InterchangeImporter` against fixture JSON; `net-policy::validate_url` against parameterised cases.
- [x] **Cross-cutting concerns are standardised.** Auth (`auth.rs`), logging (`tracing` spans on every gate method), errors (`thiserror` per crate), config (`insecure-gate`).
- [x] **Failure modes are defined.** Every seam's section lists what happens on failure; PRD §6.3 fail-closed discipline is the cross-cutting rule.
- [x] **Service extraction path is clear.** ADR table above; `slashing` and `doppelganger` are extraction-ready first.
- [x] **Data flow is traceable.** Three diagrams above cover the three main slashable-action flows + the keymanager import flow.
- [x] **Module count is justified.** Two new crates and three new in-crate modules. No tiny "one-helper-per-crate" anti-pattern; every new seam has a coherent ownership story.

---

## Mapping: PRD Finding → Seam → Owning Crate → Test File

| Finding | Seam | Owning crate | Test file |
|---|---|---|---|
| SS-1 | InsecureGate-gated legacy v1 | `bin/rvc-signer` + `insecure-gate` | `bin/rvc-signer/tests/v1_unregistered.rs` |
| E-1 | `container_tree_hash_root` + `BodyHashRoot` | `eth-types` | `eth-types/tests/spec_vector_block.rs` |
| E-2 | `bitlist_tree_hash_root<N>` | `eth-types` | `eth-types/tests/spec_vector_bitlist.rs` |
| B-1/T-1 | `encode_signed_block_contents` | `eth-types::ssz_helpers` + `block-service` | `block-service/tests/publish_signed_block_contents.rs` |
| KG-1 | (no seam — fix `compute_domain` arg) | `bin/rvc-keygen` | `bin/rvc-keygen/tests/bls_to_execution_genesis_version.rs` |
| SS-2 / SS-3 | `SigningGate::sign_aggregate_and_proof` (no DB consult) | `signer` | `signer/tests/gate_aggregate_no_slashing_db.rs` |
| DVT-1 | `PubkeyScopedDb` | `slashing` | `slashing/tests/pubkey_scope.rs`, `bin/rvc-signer/tests/dvt_pubkey_scope.rs` |
| D-1 | `ForwardWindowMachine` | `doppelganger` | `doppelganger/tests/forward_window_satisfaction.rs` |
| D-2 | `LivenessChecker` fail-closed | `doppelganger` | `doppelganger/tests/forward_window_missing_liveness.rs` |
| D-3 | `SigningGate` + `SigningEnablement` | `signer` + `doppelganger` | `signer/tests/gate_*_doppelganger_blocked.rs` |
| KM-1 | Fail-closed DELETE | `keymanager-api` + `slashing::InterchangeImporter` | `keymanager-api/tests/delete_export_failure_aborts.rs` |
| KM-2 | `ForwardWindowMachine::cancel` (single impl) | `doppelganger` | `keymanager-api/tests/concurrent_delete_reimport.rs` |
| KM-3 | `InsecureGate` | `insecure-gate` + `bin/rvc` | `bin/rvc/tests/keymanager_non_loopback_refuses.rs` |
| BN-1 | `bn-manager::tier()` + orchestrator gate | `bn-manager` + `crates/rvc` | `bn-manager/tests/optimistic_unsynced.rs` |
| BN-2 | First-poll fail-closed | `bn-manager` | `bn-manager/tests/startup_window.rs` |
| DT-1 | `update_validator_indices` | `duty-tracker` | `duty-tracker/tests/runtime_index_update.rs` |
| S-2 | Wired `pubkey_map` + `key_gen_tx` | `crates/rvc` | `crates/rvc/tests/keymanager_import_wires_orchestrator.rs` |
| SSE-1 | Reconnect-creates-channel | `bn-manager` | `bn-manager/tests/sse_resumes_after_callback_panic.rs` |
| S-5 | `head_root` fallback | `crates/rvc::orchestrator::sync_committee` | `crates/rvc/tests/sync_committee_head_root_fallback.rs` |
| KS-1 | Effective-cost gate at decrypt | `crypto::keystore` + `keymanager-api` | `keymanager-api/tests/keystore_oversized_params_rejected.rs` |
| URL-1 | `net-policy::deny_list` | `net-policy` | `net-policy/tests/deny_list_*.rs` |
| URL-2 | `net-policy::pinned_resolver` | `net-policy` | `net-policy/tests/rebinding_recheck.rs` |
| GVR-1 | `eth-types::canonical::parse_gvr_hex` + slashing import | `eth-types` + `slashing` | `eth-types/tests/canonical_helpers.rs`, `slashing/tests/interchange_import.rs` |
| IMP-1 | `InterchangeImporter` | `slashing` | `slashing/tests/interchange_import.rs` |
| CN-1 | `PubkeyScopedDb` | `slashing` | `slashing/tests/pubkey_scope.rs`, `bin/rvc-signer/tests/cn_pubkey_scope.rs` |
| C-1 | `borrow_and_update` | `crates/rvc::orchestrator::coordinator` | `crates/rvc/tests/coordinator_key_gen_consume.rs` |
| L-1 | `net-policy::validate_url` (mixed-case scheme) | `net-policy` | `net-policy/tests/mixed_case_scheme.rs` |
| L-2 | `eth-types::canonical::parse_pubkey_hex` | `eth-types` | `eth-types/tests/canonical_helpers.rs` |
| L-3 | `slashing::SlashingDb::pinned_gvr` (zeros → None) | `slashing` | `slashing/tests/all_zeros_gvr.rs` |
| L-4 | `validate_attestation_data` on aggregation path | `crates/rvc::orchestrator::aggregation` | `crates/rvc/tests/aggregation_validates_bn_response.rs` |
| L-9 | (closed with B-1/T-1) | `block-service` | un-ignored existing tests |
| S-3 | `ForwardWindowMachine::register` always called | `doppelganger` + `crates/rvc` | `doppelganger/tests/forward_window_pre_genesis.rs` |
| KG-2 | hard-error on self-verify failure | `bin/rvc-keygen` | `bin/rvc-keygen/tests/self_verify_hard_error.rs` |
| KG-3 | dir mode 0700 | `bin/rvc-keygen` | `bin/rvc-keygen/tests/dir_mode_0700.rs` |
| VS-1 | fsync parent dir | `validator-store` | `validator-store/tests/persist_fsync_parent.rs` |
| BLD-1 | TTL refresh | `builder` | `builder/tests/registration_ttl_refresh.rs` |
| SIG-1 | `--password-dir` per-keystore | `bin/rvc-signer` + `insecure-gate` | `bin/rvc-signer/tests/password_dir.rs` |
| EXIT-1 | BN GVR cross-check | `bin/rvc::commands::voluntary_exit` | `bin/rvc/tests/exit_validates_gvr.rs` |
| TIM-1 | ms-precision SlotClock | `timing` | `timing/tests/sub_second.rs` |
| SYNC-1 | sync-contribution validation | `sync-service` | `sync-service/tests/contribution_validation.rs` |
| GRPC-1/2/3 | timeouts, TLS-fields-together, log-correctness | `grpc-signer` | `grpc-signer/tests/*` |
| CLI-1 | token-file/env intake | `bin/rvc` | `bin/rvc/tests/cli_token_file.rs` |
| TEL-1 | `telemetry::redact_endpoint` | `telemetry` | `telemetry/tests/redact.rs` |
| DVT-2 | v2-only PartialSign | `bin/rvc-signer` | `bin/rvc-signer/tests/dvt_v1_removed.rs` |
| DVT-3 | per-share verification before combine | `bin/rvc-signer::backend::dvt` | `bin/rvc-signer/tests/dvt_partial_verification.rs` |
| DVT-4 | per-peer share_index pin | `bin/rvc-signer::dvt::peer_client` | `bin/rvc-signer/tests/dvt_share_index_pin.rs` |
| DVT-5 | reject share_index == 0 | `bin/rvc-signer::dvt::lagrange` | `bin/rvc-signer/tests/dvt_lagrange_zero.rs` |
| SP-1 | drop name-derived early-skip | `secret-provider` | `secret-provider/tests/refresh.rs` |
| Info-1/2/3/4/5 | various (see PRD §5 P2) | various | see PRD |

---

## Summary

The shared-seams candidate replaces 46 individually-located findings with **eight cross-cutting seams** owned by clearly-identified crates:

1. `signer::SigningGate` — the only path that produces a slashable signature.
2. `doppelganger::ForwardWindowMachine` — the only source of truth for "is this validator allowed to sign?"
3. `slashing::PubkeyScopedDb` + `InterchangeImporter` — pubkey-keyed slashing with CN as audit-only.
4. `eth-types::canonical` — the only hex/GVR/pubkey/signing-root parsers.
5. `eth-types::tree_hash_utils` — spec-correct `Bitlist[N]` + `Container` helpers with compile-time enforcement.
6. `net-policy` (new crate) — the only SSRF deny-list + IP pinning + DNS-rebinding gate.
7. `insecure-gate` (new crate) — the only `Refuse | Warn | Allow` decision.
8. `telemetry::redact_endpoint` — the only redaction helper.

Each seam owns one correct, tested implementation; every consumer depends on the seam via a small, type-safe interface; every dependency arrow goes strictly down the level table, so the workspace has no cycles; every finding-cluster maps onto exactly one seam and one test fixture set. Future regressions are structurally prevented: the orchestrator cannot bypass `SigningGate` (it has no `Signer` handle); call sites cannot mis-tree-hash a Bitlist (the const-generic refuses to compile); two CNs cannot double-sign the same key (the schema's unique index forbids it); a missing liveness entry cannot fail-open (the state machine has no transition for it).
