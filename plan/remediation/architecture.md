# Software Architecture: rs-vc Security & Correctness Remediation

**Status:** Final, pre-review
**Date:** 2026-06-13
**PRD:** `plan/remediation/prd.md` (46 verified findings; 1 Critical / 13 High / 13 Medium / 14 Low / 5 Info)
**Research:** `plan/remediation/research/{00-overview,01-ssz-domain-correctness,02-slashing-remote-signer-dvt,03-doppelganger-protection,04-bn-trust-boundary}.md`
**Optimisation axis:** **Shared seams with surgical discipline + targeted defense-in-depth.**

> This document is a **remediation architecture for an existing 23-crate Rust validator client on `develop`**, not a green-field design. PRD §2 non-goals are honored: no new features, no new RPCs, no broad rearchitecture of crates not implicated by a finding, **no new external dependencies**. Module boundaries are preserved verbatim wherever a finding does not require change; the architectural moves consist of (a) introducing a small number of **shared seams** that collapse duplicated-and-broken logic onto one correct implementation, (b) **type-level enforcement** where it structurally prevents regression, and (c) **independent defense-in-depth layers** where the cost is low and each layer catches a structurally different class of bug.

---

## Overview

rs-vc today has 46 verified defects clustering around a small number of root causes that are reimplemented (and broken) at multiple sites:

- EIP-3076 consultation is ad-hoc per call site; the v1 raw-root signer bypasses it entirely (SS-1).
- `sign_aggregate_and_proof` reimplements (incorrectly) attestation slashing protection (SS-2/SS-3).
- The doppelganger gate is consulted only on attestation (D-3).
- The slashing watermark is keyed by client CN, not pubkey (DVT-1, CN-1).
- GVR string comparison happens twice with two normalisation policies (GVR-1).
- SSRF deny-lists are partial and not pinned for the signing connection (URL-1, URL-2).
- `Bitlist` and `BeaconBlockBody` are tree-hashed with hand-rolled wrong implementations (E-1, E-2).

The remediation introduces **eight cross-cutting "shared seams"** — small, focused, interface-first modules that each own one correct, tested implementation. Every finding-cluster collapses onto one seam; every signing entry point routes through that seam; every future regression is structurally prevented by the type system, the API shape, the SQLite schema, or a single test fixture set.

The architecture binds itself to two invariants from PRD §1:

- **C1 — No slashable signature.** For every block/attestation signing path that reaches a private key, EIP-3076 must be consulted *and* the result must be durable before the signature is released. Enforced by (a) the centralised `SigningGate` API, (b) the SQLite UNIQUE indices on `(pubkey, gvr, slot)` and `(pubkey, gvr, target_epoch)`, and (c) the type-level absence of `crypto::Signer` handles outside `crates/signer`.
- **C2 — No key-confidentiality bypass.** Key-bearing code paths (keystore import/delete, remote-signer transport, password loading) fail closed on any error. Enforced by the per-fix `Result<T, E>` propagation pattern; codified by the `FailClosedDefault` trait for boundary booleans.

Key architectural moves:

1. **Centralised `SigningGate` in `crates/signer`.** All slashable signing entry points go through one API that consults the slashing DB *and* the doppelganger gate before delegating to the BLS backend. The orchestrator structurally cannot bypass it (no `crypto::sign_*` handle held outside the signer crate).
2. **`ForwardWindowMachine` in `crates/doppelganger`.** The only source of truth for "is this validator allowed to sign right now?" Mirrors the Lighthouse `doppelganger_service.rs` pattern (Research Angle 03).
3. **Pubkey-scoped slashing.** The SlashingDb `client_cn` namespace becomes an *audit column*, never a `WHERE`-clause discriminator. Defense-in-depth: SQLite UNIQUE indices on `(pubkey, gvr, slot)` and `(pubkey, gvr, target_epoch)` catch a logic-bug double-block at the storage layer. DVT-1 and CN-1 close as one schema-level fix with a captured-fixture migration.
4. **Canonical helpers in `crates/eth-types`.** `canonical::{parse_pubkey_hex, parse_gvr_hex, parse_signing_root_hex}` (L-2, L-3, GVR-1, IMP-1, Info-4). `tree_hash_utils` is rewritten with spec-correct `Bitlist[N]` (const-generic) and `Container` helpers (E-1, E-2).
5. **`crates/net-policy`.** SSRF deny-list, IP pinning, and DNS-rebinding protection. Consumed by both `keymanager-api` (URL-1) and `crypto::remote_signer` (URL-2). New crate is justified because both consumers must agree and neither can host the other (ADR-002).
6. **`InsecureGate` in `crates/eth-types::insecure`.** Inline as a small module rather than a new crate (ADR-003 — surgical override). Reused by SS-1, KM-3, L-1, SIG-1.
7. **First-class test architecture.** Spec-vector fixtures live in the consuming crate's `tests/fixtures/`; a small `crates/signer-registry` (dev-only) implements the PRD M4 enumeration test. The `cargo metadata`-based DAG check runs in CI.
8. **Surgical per-finding rollout keyed to PRD M1/M2/M3.** Every finding maps to the smallest possible edit set with an explicit "max blast radius" and an ADR for every shared-helper introduction.

The combination of (1)+(2)+(3) collapses every P0 slashing-safety hazard onto three seams. The combination of (4)+(5)+(6) collapses every P1 correctness-and-confidentiality hazard onto five additional seams. P2 findings inherit correctness from the seams (e.g. L-2 / L-3 become tests against the canonical helpers).

---

## Architecture Principles

Beyond the defaults in the architect template:

- **P1 — One correct implementation per concern.** If two sites enforce the same invariant, one must call the other. Each finding-cluster collapses onto exactly one module.
- **P2 — Smallest patch wins; shared seams justified inline.** For each finding the baseline is an intra-crate edit. A shared helper, new module, or new trait is introduced *only* when the same fix must land in two or more crates' code paths to be correct, and is logged as an ADR with the small-patch alternative explicitly rejected.
- **P3 — Fail-closed at every safety boundary.** Per PRD §6.3. Encoded as the `FailClosedDefault` trait for boundary booleans (replaces `unwrap_or(true)`).
- **P4 — Type-level enforcement where it structurally prevents regression.** `BodyHashRoot` newtype for E-1, const-generic `bitlist_tree_hash_root<N>` for E-2, no `crypto::Signer` handle outside `crates/signer` for SS-1.
- **P5 — Defense-in-depth only when layers fail independently.** Two logical checks of the same EIP-3076 rule is duplication (Info-1 forbids it). Two layers that catch structurally different bug classes (gate + slashing logic + SQLite UNIQUE + per-pubkey lock) is defense-in-depth.
- **P6 — No new external dependencies.** PRD §2. Every fix maps to existing workspace deps. The one tempting candidate (`serial_test` for Info-5) is rejected in favour of an env-mutex (ADR-009).
- **P7 — Crate boundaries are sacred during remediation.** No finding moves a type or function from one crate to another. Two new crates are added (`net-policy`, `signer-registry`) because their consumer-graphs forbid placement in any existing crate; both are <500 LoC and justified per ADR.
- **P8 — One finding, one branch, one focused diff (RED→GREEN→REFACTOR).** Cluster branches per PRD §7.1 only when GREEN diffs literally overlap.
- **P9 — Spec-vector fixtures co-locate with the consuming crate.** No central `crates/test-fixtures` (per surgical principle P6).
- **P10 — Dependency graph is mechanically checked acyclic.** A `tests/architecture_no_cycles.rs` parses `cargo metadata` and enforces the level-graded DAG. Forbidden edges (e.g. `slashing → doppelganger`, `eth-types → anything`) are asserted absent.

---

## System Context Diagram

```text
                          ┌──────────────────────────────────────────┐
                          │                rs-vc                     │
                          │   (3 bins: rvc, rvc-signer, rvc-keygen)  │
                          │                                          │
   ┌──────────┐   HTTPS   │   ┌───────────────────────────────────┐  │
   │ Operator │──────────▶│   │      keymanager-api (Axum)        │  │
   │  / DVT   │   POST    │   │      keystores / remotekeys       │  │
   │  Coord   │   /eth/v1 │   └────────────────┬──────────────────┘  │
   └──────────┘   /keys.. │                    │ key import          │
                          │                    ▼                     │
   ┌──────────┐   gRPC    │   ┌───────────────────────────────────┐  │   ┌──────────────┐
   │   rvc    │──────────▶│   │      rvc-signer (gRPC server)     │──┼──▶│ Remote BLS   │
   │  (VC)    │  mTLS,    │   │      [v2 typed only; v1 gated]    │  │   │  backend     │
   └──────────┘  IP-pin   │   └────────────────┬──────────────────┘  │   └──────────────┘
                          │                    │ Signer trait        │
                          │                    ▼                     │
                          │   ┌───────────────────────────────────┐  │   ┌──────────────┐
                          │   │  orchestrator (crates/rvc)        │──┼──▶│ Beacon Node  │
                          │   │  slot loop, duty fan-out          │  │   │  (multi-BN,  │
                          │   └────────────────┬──────────────────┘  │   │   untrusted) │
                          │                    │ duty fan-out         │   └──────────────┘
                          │                    ▼                     │
                          │   ┌───────────────────────────────────┐  │   ┌──────────────┐
                          │   │  block / sync / aggregation /     │──┼──▶│ MEV Builder  │
                          │   │  attestation services             │  │   │  relay       │
                          │   └───────────────────────────────────┘  │   └──────────────┘
                          └──────────────────────────────────────────┘
                                              │
                                              ▼
                                    ┌──────────────────┐
                                    │ slashing DB      │
                                    │ (SQLite,EIP-3076)│
                                    └──────────────────┘
```

External trust boundaries (each fail-closed):

- **Operator → keymanager-API:** TLS + bearer token + KM-3 loopback gate at bind.
- **rvc ↔ Beacon Node:** untrusted (BN-1/2, S-5, SYNC-1, EXIT-1, Info-4).
- **rvc ↔ rvc-signer:** mTLS, IP-pinned, deny-list scrubbed (URL-1/2, GRPC-1/2/3, L-1).
- **rvc-signer ↔ DVT peer:** mTLS with SNI pinning; threshold partial bound to share pubkey (DVT-3/4/5).

The remediation introduces *no* new external surfaces. Behavior deltas: SS-1 unregisters v1 raw-root; KM-3 requires explicit opt-in for non-loopback keymanager bind; EXIT-1 adds a precondition arrow from CLI exit subcommands to the BN.

---

## Module Overview

The existing 23 crates are preserved verbatim. Two **new crates** are added:

- `crates/net-policy` — SSRF + IP-pin seam (consumed by both `keymanager-api` and `crypto`).
- `crates/signer-registry` — dev-dependency-only; static metadata for the PRD M4 enumeration test.

Existing crates gain new modules where a seam has a natural owner: `eth-types::canonical`, `eth-types::insecure`, `eth-types::tree_hash_utils` (rewritten), `doppelganger::forward_window`, `signer::gate`, `slashing::scoped`, `slashing::import`, `slashing::migration`.

| # | Crate / Module | Responsibility (one sentence) | Owns Data | Depends On | Findings Owned | Max Blast Radius per Fix | Status |
|---|---|---|---|---|---|---|---|
| 1 | `crates/eth-types` | SSZ-derived consensus types; canonical hex/GVR/pubkey parsers; spec-correct `Bitlist[N]` / `Container` tree-hash helpers; **`InsecureGate` decision module**. | — (pure types) | (workspace leaf) | E-1, E-2, L-2, L-3 (helper), GVR-1 (helper), IMP-1 (helper), Info-4 (boundary), SS-1 (gate decision module), KM-3 (gate), L-1 (gate), SIG-1 (gate) | 1 file | EXTENDED |
| 2 | `crates/metrics` | Prometheus metric registration. | metric names | (none) | (no findings) | — | UNCHANGED |
| 3 | `crates/timing` | `SlotClock` with ms-precision. | slot/epoch arithmetic | `eth-types` | TIM-1 | 1 function | EXTENDED |
| 4 | `crates/telemetry` | OTLP/logging config; endpoint redaction. | TEL-1 redaction | `eth-types::canonical` (token detection) | TEL-1 | 1 function | EXTENDED |
| 5 | **`crates/net-policy`** *(NEW)* | **Reserved-range deny-list + IP pinning + DNS-rebinding seam.** | IPv4/IPv6 deny-list; `PinnedResolver` | `eth-types::canonical`, `reqwest` (build-only) | URL-1, URL-2 | 1 file per finding | **NEW** |
| 6 | `crates/crypto` | BLS primitives, `KeyManager`, `LocalSigner`, `RemoteSigner`, keystore (EIP-2335). | in-memory key bytes (zeroized) | `eth-types`, `net-policy` (URL-2) | L-1, L-2, KS-1 (helper), URL-2 (signer side), Info-5 (insecure tests) | 1 file per finding | EXTENDED |
| 7 | `crates/secret-provider` | GCP/local secret backend for BLS keys. | — | `crypto` | SP-1, Info-5 (GCP zeroize) | 1 method per finding | EXTENDED |
| 8 | `crates/slashing` | EIP-3076 SQLite DB, staged guards, interchange import/export; **pubkey-scoped keying with `client_cn` audit column**; schema migration. | `slashing.sqlite` (per process; SOT for EIP-3076 watermarks) | `eth-types::canonical`, `crypto` (pubkey type), `metrics` | DVT-1, CN-1, GVR-1, IMP-1, L-3, Info-1, Info-2 | 1 function or 1 schema change | EXTENDED + SCHEMA MIGRATION |
| 9 | `crates/beacon` | Beacon-API HTTP client; SSZ deser; GVR/fork-version boundary validation. | — | `eth-types::canonical`, `telemetry`, `crypto` | Info-4 (boundary), Info-5 (dead API delete) | 1 function | EXTENDED |
| 10 | **`crates/doppelganger`** | **Forward-window state machine + `is_signing_enabled` gate.** | per-validator state (in-memory) | `eth-types`, `slashing` (read-only via `SlashingDbReader`), `crypto::PublicKey` | D-1, D-2, D-3 (gate state), S-3, KM-2 (cancel) | `service.rs` only | EXTENDED → owns D-1/D-2/D-3/S-3/KM-2 state-coordination |
| 11 | **`crates/signer`** | **The single signing seam.** All slashable signs route through `SigningGate`. | per-validator mutex map (in-memory) | `crypto`, `eth-types`, `slashing`, `doppelganger`, `metrics` | SS-1 (handler shim), SS-2/SS-3, D-3 (gate enforcement) | 1 method per finding | EXTENDED (broadens existing role) |
| 12 | `crates/bn-manager` | Multi-BN failover, sync status, SSE consumer. | per-BN status + SSE state | `beacon`, `eth-types`, `crypto` | BN-1, BN-2, SSE-1 | 1 method or 1 file | EXTENDED |
| 13 | `crates/duty-tracker` | Duty refresh; runtime-mutable validator index list. | duty caches | `bn-manager`, `eth-types`, `metrics` | DT-1 | constructor + 1 setter | EXTENDED |
| 14 | `crates/validator-store` | Per-validator config + atomic persist. | `validator-store.toml`, per-validator config | `crypto::canonical` | VS-1 | 1 function | EXTENDED |
| 15 | `crates/sync-service` | Sync-committee message production. | — | `eth-types`, `signer` (trait) | SYNC-1 | 1 method | EXTENDED |
| 16 | `crates/block-service` | Block proposal pipeline + SSZ publish bytes. | — | `eth-types`, `beacon`, `signer`, `builder`, `crypto`, `validator-store` | B-1/T-1, L-9 (un-ignore) | 1 file | EXTENDED |
| 17 | `crates/builder` | Builder validator registration cache + TTL refresh. | in-memory cache | `bn-manager`, `crypto`, `signer`, `validator-store` | BLD-1 | 1 method | EXTENDED |
| 18 | `crates/propagator` | Multi-BN publish fan-out. | — | `bn-manager`, `eth-types` | (no findings) | — | UNCHANGED |
| 19 | `crates/keymanager-api` | `/eth/v1/keystores` + `/eth/v1/remotekeys` HTTP. | keystore files; remote-key registry | `signer`, `slashing`, `crypto`, `doppelganger`, `net-policy`, `eth-types` (canonical + insecure-gate) | KM-1, KM-2, URL-1, URL-2 (validator side), KS-1 (gate) | 1 handler or 1 helper file | EXTENDED (shrinks: URL → `net-policy`, gate → `doppelganger::ForwardWindowMachine`) |
| 20 | `crates/grpc-signer` | gRPC client to standalone signer. | — | `crypto`, `eth-types::canonical`, `net-policy` (optional) | GRPC-1/2/3 | 1 file | EXTENDED |
| 21 | `crates/rvc` (lib) | Orchestrator (slot loop, duty fan-out, doppelganger startup wiring, keymanager adapters); **no direct BLS sign calls**. | per-slot mut state | crates 1-20 (composed) | S-2, S-5, C-1, L-4 | wire-up sites only | EXTENDED |
| 22 | `bin/rvc` | VC binary entrypoint + flag wiring. | — | `rvc`, `signer`, `bn-manager`, `keymanager-api`, `metrics`, `telemetry`, `eth-types::insecure`, `grpc-signer` | KM-3, EXIT-1, S-2 wire, S-3, L-5, Info-3, Info-5 (metrics bind), CLI-1 | wire-up only | EXTENDED |
| 23 | `bin/rvc-signer` | Standalone signer binary. | `slashing.sqlite` (per process) | `signer`, `slashing`, `crypto`, `eth-types::insecure`, `eth-types::canonical` | SS-1 (registration), DVT-1 (call site), DVT-2..5, SIG-1 | 1 file per finding | EXTENDED + LEGACY-GATE |
| 24 | `bin/rvc-keygen` | Keystore generation + BLS-to-execution + exit signing. | output files | `crypto`, `eth-types::canonical` | KG-1, KG-2, KG-3 | 1 file per finding | EXTENDED |
| 25 | **`crates/signer-registry`** *(NEW, dev-only)* | Compile-time static metadata for every signing entry point. | static metadata | (none) | (supports SS-1 enumeration test / PRD M4) | — | **NEW (dev-only)** |

**Net change:** 2 new crates (`net-policy`, `signer-registry`), 0 crates removed. The signer-registry is dev-dependency-only — it has no production-edge. The `InsecureGate` decision is a small module *inside* `eth-types` rather than a separate crate (surgical override of the original shared-seams plan; see ADR-003).

**Surgical observation:** 17 of 23 crates that own ≥ 1 finding own ≤ 2 findings with one-file edits. The remaining 6 (`slashing`, `keymanager-api`, `bin/rvc-signer`, `bin/rvc`, `bin/rvc-keygen`, `bn-manager`) own several findings each, but the findings inside a crate are independent files, so per-fix blast radius is still one file or one function.

---

## Module Dependency Graph

Strict level-graded DAG. Every arrow points from a higher-numbered level to a lower-numbered level. **No forbidden edges exist; the `tests/architecture_no_cycles.rs` test asserts this from `cargo metadata`.**

```text
LEVEL 0  (workspace leaves)
  metrics

LEVEL 1
  eth-types ─────► (uses ssz, tree_hash, hex)
                 └─ submodules: canonical, tree_hash_utils, insecure
  timing    ─────► eth-types
  telemetry ─────► eth-types::canonical (optional, for token detection)

LEVEL 2
  net-policy ────► eth-types::canonical

LEVEL 3
  crypto         ────► eth-types, net-policy
  secret-provider ───► crypto

LEVEL 4
  slashing       ────► eth-types::canonical, crypto, metrics
  beacon         ────► eth-types::canonical, crypto, telemetry

LEVEL 5
  doppelganger   ────► eth-types, crypto, slashing (READ-ONLY via SlashingDbReader trait)
  bn-manager     ────► beacon, eth-types, crypto

LEVEL 6
  signer         ────► crypto, eth-types, slashing, doppelganger, metrics
                                                  ▲
                                                  │  consults via traits ONLY
                                                  │  (no direct DB or service struct)

LEVEL 7
  builder           ────► bn-manager, crypto, signer, validator-store
  duty-tracker      ────► bn-manager, eth-types, metrics
  validator-store   ────► crypto, eth-types::canonical
  sync-service      ────► eth-types, signer (trait)
  block-service     ────► eth-types, beacon, signer, builder, crypto, validator-store
  propagator        ────► bn-manager, eth-types
  grpc-signer       ────► crypto, eth-types::canonical, net-policy
  keymanager-api    ────► signer, slashing, crypto, doppelganger, net-policy,
                          eth-types (canonical + insecure)

LEVEL 8
  rvc (lib)         ────► all of levels 0..7 (composes services)

LEVEL 9
  bin/rvc           ────► rvc, signer, bn-manager, keymanager-api, metrics,
                          telemetry, eth-types::insecure, grpc-signer
  bin/rvc-signer    ────► signer, slashing, crypto, eth-types (insecure + canonical)
  bin/rvc-keygen    ────► crypto, eth-types::canonical

DEV-ONLY (no production edges)
  signer-registry   ────► (none); consumed by tests in bin/rvc-signer/tests/
  consensus-spec-tests fixtures in each consuming crate's tests/fixtures/
```

**Cycle verification — every refused edge is documented:**

- `slashing → doppelganger`: **refused**. Would create cycle `signer → doppelganger → slashing → doppelganger`. Resolution: `slashing` exposes `SlashingDbReader` (a read-only trait) that `doppelganger` *imports*; `slashing` does not know `doppelganger` exists.
- `slashing → eth-types::insecure`: **refused**. The insecure-gate is for bind-time decisions, not slashing logic.
- `doppelganger → keymanager-api`: **refused**. The keymanager-API consumes `doppelganger::ForwardWindowMachine` via the existing 30-line shim; not the other way around.
- `signer → keymanager-api`: **refused**. The signer must not know about HTTP surfaces.
- `eth-types → anything`: **refused**. Workspace leaf invariant; the canonical submodule lives here precisely so every consumer can depend on it without inducing cycles.

**Seam ownership cross-reference:**

```text
  SigningGate                  → signer            (D-3, SS-1, SS-2/3, CN-1 enforcement)
  PubkeyScopedDb               → slashing          (DVT-1, CN-1, GVR-1, IMP-1)
  InterchangeImporter          → slashing          (GVR-1, IMP-1)
  Schema migration v1→v2       → slashing          (DVT-1+CN-1 keying)
  ForwardWindowMachine         → doppelganger      (D-1, D-2, D-3, S-3, KM-2)
  canonical::{pubkey,gvr,...}  → eth-types         (L-2, L-3, GVR-1, IMP-1, Info-4)
  tree_hash_utils (rewritten)  → eth-types         (E-1, E-2)
  insecure::InsecureGate       → eth-types         (SS-1, KM-3, L-1, SIG-1)
  net-policy::deny_list        → net-policy        (URL-1)
  net-policy::PinnedResolver   → net-policy        (URL-2, GRPC misc)
  TEL-1 redactor               → telemetry         (TEL-1)
  ForwardWindowAdapter         → keymanager-api    (thin shim; logic in doppelganger)
  Spec-vector fixtures         → each consuming crate's tests/fixtures/
  signer-registry              → dev-only crate (PRD M4 enumeration test)
```

---

## Module Details

The modules below are the *seam-bearing* ones. Modules with single-finding one-file edits (e.g. `validator-store::store::persist` adding `sync_all` on parent dir for VS-1) appear in the compact entries table at the end.

---

### Module: `eth-types` (extended)

**Responsibility:** SSZ-derived consensus types; canonical hex/GVR/pubkey parsers; spec-correct `tree_hash` helpers; **`InsecureGate` decision module**.

**Domain Entities (new/changed):**

- `canonical::PubkeyHex` — newtype around `[u8; 48]` with `from_str()` validating ASCII hex, even length, strict single `0x` prefix (L-2).
- `canonical::GvrHex` — newtype around `Root` with lowercase-normalised string view; `parse_gvr_hex(s) -> Result<Root, _>` (GVR-1).
- `canonical::SigningRootHex` — newtype around `[u8; 32]`.
- `tree_hash_utils::bitlist_tree_hash_root<const N: usize>(bytes) -> Result<Hash256>` — generic over the SSZ type's `N`; chunk count `(N + 255) / 256` (E-2).
- `tree_hash_utils::container_tree_hash_root<T: TreeHash>(value) -> Hash256` — explicit helper that the body-leaf code path *must* use.
- `BodyHashRoot([u8; 32])` newtype — internal to `eth-types`; `BeaconBlock::tree_hash_root()` sets the body leaf from this newtype only. Passing a `List[byte]` hash refuses to compile (E-1).
- `insecure::InsecureGate { Refuse, Warn, Allow }` — enum + `apply_to(env_var: &str, default: Self) -> Decision` helper. **New small module, not a new crate** (ADR-003).

**Data Store:** none. Pure type/algorithm/helper crate.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `canonical::parse_pubkey_hex(&str)` | hex | `Result<PubkeyHex, ParseError>` | L-2; single source of truth. |
| `canonical::parse_gvr_hex(&str)` | hex | `Result<Root, ParseError>` | GVR-1; lowercase-normalised. |
| `canonical::eq_gvr(&str, &Root)` | string + bytes | `bool` | Comparison helper for `slashing::import` (GVR-1). |
| `tree_hash_utils::bitlist_tree_hash_root<N>(&[u8])` | SSZ bitlist bytes | `Result<Hash256, _>` | E-2; const-generic over the bound. |
| `tree_hash_utils::container_tree_hash_root<T: TreeHash>(&T)` | container | `Hash256` | E-1; indirection that prevents `List[byte]` mistake. |
| `insecure::InsecureGate::from_env(var: &str, default: Self)` | env var | `Self` | Reads e.g. `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK`. |
| `insecure::Decision::evaluate(gate, condition_is_insecure)` | gate, bool | `Decision` | Logs `warn!` on `Warn`; aborts on `Refuse`. |

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
│   ├── insecure.rs         # NEW — SS-1, KM-3, L-1, SIG-1 gate decision
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
    │   ├── electra_block.ssz
    │   ├── aggregate_and_proof_real_committee.ssz
    │   └── sync_contribution.ssz
    ├── spec_vector_block.rs       # E-1 regression
    ├── spec_vector_bitlist.rs     # E-2 regression
    ├── canonical_helpers.rs       # L-2, L-3, GVR-1, IMP-1
    └── insecure_gate.rs           # gate semantics
```

**Key Design Decisions:**

- `BodyHashRoot` newtype is internal: only `BeaconBlock::tree_hash_root` constructs it; consumers cannot bypass.
- `bitlist_tree_hash_root` takes `N` as const-generic so every call site declares its bound (`MAX_VALIDATORS_PER_COMMITTEE = 2048`, `SYNC_COMMITTEE_SIZE = 512`). Future bitlist additions cannot use a wrong bound silently.
- `insecure::InsecureGate` lives in `eth-types` rather than its own crate to avoid the workspace-noise cost of a ~100 LoC crate; `eth-types` is the only workspace leaf every consumer already imports, and the gate is pure types + env reads with no other deps. **Surgical override of the original shared-seams plan; see ADR-003.**

**Failure Modes:**

- Pure functions; failures returned as `Result`. Existing property tests in `tree_hash_utils::fuzz` extended to cover new helpers' no-panic invariant.
- `InsecureGate::Refuse` decision = startup aborts in the calling bin with `anyhow::Error`.

---

### Module: `slashing` (extended + schema migration)

**Responsibility:** The EIP-3076 SQLite DB. Single source of truth for slashing-protection logic. After remediation: row uniqueness is `(pubkey_hex, gvr, slot)` / `(pubkey_hex, gvr, target_epoch)`; `client_cn` is an audit column.

**Domain Entities:**

- `SlashingDb` — existing handle.
- `StagedBlock<'_>`, `StagedAttestation<'_>` — existing RAII guards. **Signatures change**: no more `client_cn` parameter.
- `PubkeyScopedDb<'a>` — NEW thin view. Replaces `bin/rvc-signer::ScopedSlashingDb`. Constructor records `client_cn` for audit-log only; has no API that lets the caller key by CN.
- `InterchangeImporter` — extracted from `db.rs::import()` for testability. Uses `eth-types::canonical::eq_gvr` (GVR-1); validates `source ≤ target` plus conflicting-root rows (IMP-1).
- `SlashingDbReader` (NEW trait) — read-only interface consumed by `doppelganger` for the restart-aware safe-skip.
- `Migration` — single-shot startup step.

**Defense-in-depth layers:**

| Layer | Where | What it catches | What it does NOT catch |
|---|---|---|---|
| 1. Gate (D-3) | `signer::SigningGate.gate.is_signing_enabled(pubkey)` | doppelganger window, unknown pubkey, disabled | a slashable signature within the same key+epoch |
| 2. Staging logic (EIP-3076) | `slashing::stage_*` | double-block, double-vote, surround | a logic bug that miscomputes "surround" |
| 3. SQLite UNIQUE indices | `(pubkey, gvr, slot)`, `(pubkey, gvr, target_epoch)` | literal duplicate row regardless of logic | semantically-different slashable cases |
| 4. Per-pubkey async lock | `signer::ValidatorLockMap` | TOCTOU between concurrent same-key paths | nothing on its own — support layer |

The UNIQUE indices catch any "same target_epoch, same pubkey" double-vote even if the staging logic has a bug. This is the structural barrier per ADR-007 (defense-in-depth at the storage layer).

**Data Store:**

- SQLite `slashing.sqlite` (per process). Schema-versioned via `metadata` table.
- **Schema migration v1→v2** is idempotent, transactional, one-way:
  1. Drop unique indices that mention `client_cn`.
  2. Add unique indices `(pubkey, gvr, slot)` (blocks) and `(pubkey, gvr, target_epoch)` (attestations).
  3. Resolve duplicates under the old keying by raising the watermark to the worst-case (most-conservative) value. **Migration property guaranteed:** post-migration DB rejects every message the pre-migration DB rejected, plus the cross-CN double-sign cases the pre-migration DB silently accepted.
  4. Set `metadata.migration_v2_applied_at`.

**Migration row-pair resolution table** (the concrete policy):

| Pre-migration row pair | Post-migration result |
|---|---|
| Two block rows with same `(pubkey, gvr, slot)` differing only in `client_cn` | Keep one row; `client_cn` becomes the earlier of the two (audit). |
| Two block rows with same `(pubkey, gvr, slot)`, differing `signing_root` | Keep row with the lexicographically smaller `signing_root` and mark `slashing_history_marker = true` (the watermark is the slot itself; the marker is informational). |
| Two attestation rows with same `(pubkey, gvr, target_epoch)` differing only in `client_cn` | Keep one row. |
| Two attestation rows with same `(pubkey, gvr, target_epoch)`, differing `source_epoch` | Keep the row with the **larger** `source_epoch` (more conservative against surround); mark `slashing_history_marker = true`. |
| Two attestation rows with same `(pubkey, gvr, target_epoch)`, differing `signing_root` | Keep one; mark `slashing_history_marker = true`. |

Invariant the migration preserves: for every message `m` that the pre-migration DB rejected as slashable, the post-migration DB also rejects `m`. The captured-fixture test exercises this property.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `SlashingDb::stage_block` *(signature change)* | `pubkey_hex, slot, signing_root_hex, gvr` | `StagedBlock<'_>` | No more `client_cn` arg. |
| `SlashingDb::stage_attestation` *(signature change)* | `pubkey_hex, src, tgt, signing_root_hex, gvr` | `StagedAttestation<'_>` | No more `client_cn` arg. |
| `PubkeyScopedDb::new(db, gvr)` | `Arc<SlashingDb>, Root` | `Self` | Replaces `bin/rvc-signer::ScopedSlashingDb`. |
| `InterchangeImporter::import(&self, json)` | interchange JSON | `Result<ImportSummary, _>` | GVR-1 + IMP-1. |
| `SlashingDb::export_interchange(pubkeys, gvr)` *(contract strengthened)* | pubkeys, GVR | `Result<InterchangeFormat, _>` | **Atomic**: every pubkey or none. KM-1's safety relies on this contract (ADR-008). |
| `SlashingDb::pinned_gvr()` | `&self` | `Option<Root>` | Treats all-zeros as `None` (L-3). |
| `SlashingDb::audit_log(client_cn, pubkey, outcome)` | audit fields | `()` | Non-EIP-3076 audit trail; preserves operator visibility into per-CN behavior. |
| `SlashingDbReader::last_signed_attestation(&self, pubkey, gvr)` | pubkey, GVR | `Option<TargetEpoch>` | Read-only trait consumed by `doppelganger` for restart-aware safe-skip. |

**Events:** none.

**Internal Structure:**
```
slashing/
├── src/
│   ├── lib.rs
│   ├── db.rs               # WHERE-clause keying scrubbed of client_cn; UNIQUE indices
│   ├── stage.rs            # stage_* signatures lose client_cn
│   ├── scoped.rs           # NEW — PubkeyScopedDb (replaces bin/rvc-signer::ScopedSlashingDb)
│   ├── import.rs           # NEW — InterchangeImporter
│   ├── migration.rs        # NEW — v1→v2 migration; captured-fixture tests
│   ├── audit.rs            # NEW — audit_log(client_cn, pubkey, outcome)
│   ├── reader.rs           # NEW — SlashingDbReader trait
│   ├── types.rs
│   └── error.rs
└── tests/
    ├── interchange_import.rs   # GVR-1, IMP-1
    ├── pubkey_scope.rs         # DVT-1, CN-1
    ├── migration_v1_to_v2.rs   # captured pre-migration DB fixture
    ├── unique_index_blocks_double.rs  # defense-in-depth Layer 3
    └── export_interchange_atomic.rs   # KM-1 contract
```

**Key Design Decisions:**

- Schema migration is the only one-way change. Idempotent; gated on `metadata.migration_v2_applied_at`.
- `client_cn` preserved on disk; reports that previously discriminated by CN still join against it.
- UNIQUE indices kept even though staging logic also enforces the rule — this is the structural defense-in-depth per ADR-007.

**Failure Modes:**

- Migration failure on first start: transaction rolls back; `open()` returns Err. Operators see a clear "schema migration failed" message; DB unchanged.
- Conflicting-root row at import: `InvalidInterchangeFormat`; for KM-1 this means the keymanager DELETE refuses to proceed.
- DB locked/corrupt at runtime: every `stage_*` returns Err; `SigningGate` propagates as `BlockedBySlashingDb`; no signature released.

---

### Module: `doppelganger` (extended — forward-window state machine)

**Responsibility:** The *only* source of truth for "is this pubkey allowed to sign right now?" Holds per-validator state across the signing lifecycle.

**Domain Entities:**

- `ForwardWindowMachine` — Lighthouse-style state machine (Research Angle 03):
  ```text
  Unmonitored ──register_at(epoch)──▶ Pending {
                                        start_epoch,
                                        end_epoch = start_epoch + monitoring_epochs,
                                        observed: Vec<LivenessSample>,
                                      }
  Pending ──last slot of e+1 + clean──▶ Safe
  Pending ──unexplained is_live──▶ Detected (terminal)
  Pending ──missing liveness entry──▶ Pending (no transition; fail-closed)
  ```
- `SigningEnablement` (NEW trait) — implemented by `ForwardWindowMachine`; consumed by `signer::SigningGate`. Mockable in tests.
- `LivenessChecker` (extended trait) — every requested index must appear in the response; missing index → `DoppelgangerError::IncompleteLiveness` (D-2).

**Data Store:** in-memory `HashMap<Pubkey, ValidatorState>` behind `parking_lot::Mutex`.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `ForwardWindowMachine::register(&self, pubkey, current_epoch)` | pubkey, epoch | `()` | Called at startup for each managed validator AND from keymanager on import (KM-2). Idempotent. |
| `ForwardWindowMachine::is_signing_enabled(&self, pubkey)` | pubkey | `bool` | The ONLY answer `SigningGate` consults. Default `false` for unknown (D-3 fail-closed). |
| `ForwardWindowMachine::tick(&self, current_epoch, slot_in_epoch)` | epoch, slot | `Vec<DoppelgangerStatus>` | Driven by orchestrator slot loop; advances state at the last slot of `e+1`. |
| `ForwardWindowMachine::observe_liveness(&self, epoch, samples)` | epoch, samples | `Result<(), DoppelgangerError>` | Fails closed on missing entries (D-2). |
| `ForwardWindowMachine::cancel(&self, pubkey)` | pubkey | `()` | For KM-2: delete cancels pending monitoring; re-import re-registers fresh. |
| `ForwardWindowMachine::status(&self, pubkey)` | pubkey | `DoppelgangerStatus` | Read-only inspection (metrics/diagnostics). |

**Defense-in-depth contract:**

- **Layer 1 (state machine):** D-1 forward-window logic — only transition to Safe at the end of the configured window.
- **Layer 2 (gate publication):** `signer::SigningGate` consults `is_signing_enabled`. If the doppelganger service crashes, the gate retains the previous decision; on restart, every monitored validator is re-marked `Pending`.
- **Layer 3 (missing-liveness fail-closed):** D-2 implemented as "no Safe transition emitted when any requested pubkey is absent from the response."
- **Layer 4 (restart-aware safe-skip):** consults `SlashingDbReader::last_signed_attestation` — if the validator already signed in this window, mark Safe immediately (Lodestar pattern, existing).

**Internal Structure:**
```
doppelganger/
├── src/
│   ├── lib.rs
│   ├── service.rs              # legacy "look at past epochs" code; kept for backward-compat tests but no longer the gate
│   ├── forward_window.rs       # NEW — D-1, D-2, D-3, S-3, KM-2
│   ├── state.rs                # NEW — per-validator state enum
│   ├── traits.rs               # extended LivenessChecker, new SigningEnablement
│   └── error.rs
└── tests/
    ├── forward_window_satisfaction.rs       # D-1 (last slot of e+1)
    ├── forward_window_missing_liveness.rs   # D-2 fail-closed
    ├── forward_window_unknown_pubkey.rs     # D-3 fail-closed default
    ├── forward_window_pre_genesis.rs        # S-3 (epoch 0)
    └── forward_window_km2_race.rs           # KM-2 cancel-then-reimport
```

**Key Design Decisions:**

- `ForwardWindowMachine` does NOT know about `SignerService`; the dependency goes the other way (`signer → doppelganger`). This makes `doppelganger` testable against a mock `LivenessChecker` and `signer` testable against a mock `SigningEnablement`.
- `keymanager-api::gate` shrinks to a 30-line shim delegating to `ForwardWindowMachine`. The KM-2 race is structurally impossible because there is no `insert` API that returns an un-cancelled old token.

**Failure Modes:**

- Liveness checker error → state stays `Pending` (fail-closed).
- BN unreachable for the full forward window → validator stays `Pending`; operator-facing CRITICAL log after `2 * monitoring_epochs`.
- Service task crashes → restart-aware logic re-engages; gate retains `DenyDoppelganger` until restart finishes its window.

---

### Module: `signer` (extended — the SigningGate seam)

**Responsibility:** The **only** place a slashable BLS sign can happen. Every signing path — local-VC `SignerService`, standalone `bin/rvc-signer` typed handlers, `block-service` block-proposal path — routes through `SigningGate::sign_*`.

**Sub-responsibilities (potential future splits noted explicitly):** per-validator mutex map, slashing stage, doppelganger gate, BLS dispatch, audit log. Each is a separate file inside the crate (see Internal Structure); if `crates/signer` ever needs further extraction, these are the seams. For this remediation they stay together because they share state via the `SigningGate` struct.

**Domain Entities:**

- `SigningGate` composes:
  - `Arc<SlashingDb>` (or `PubkeyScopedDb<'_>`)
  - `Arc<dyn SigningEnablement>` (concrete: `ForwardWindowMachine`)
  - `Arc<CompositeSigner>` (BLS backend)
  - `Arc<ValidatorLockMap>` (per-pubkey mutexes — TOCTOU guard)
- `SigningGateError` — `BlockedByDoppelganger | BlockedBySlashingDb | SigningFailed | KeyNotFound | UnknownPubkey`.
- `FailClosedDefault<T>` (NEW trait) — `fn default_when_unknown() -> T`. Implementor for `bool` returns `false`. Codifies PRD §6.3 for boundary booleans.

**Defense-in-depth contract (per slashable message):**

1. Acquire per-pubkey lock from `ValidatorLockMap`.
2. Consult `SigningEnablement::is_signing_enabled(pubkey)` → must be `true`. (D-3 layer 1.)
3. Stage the EIP-3076 row via `PubkeyScopedDb::stage_*`. (Slashing logic layer.)
4. The SQLite UNIQUE index fires as the storage barrier. (Layer 3.)
5. Call `CompositeSigner::sign(signing_root, pubkey)`.
6. Commit the staged row on success; discard on signer failure.

Per non-slashable message (RANDAO, voluntary exit, builder reg, aggregate-and-proof, sync committee, selection proof):

1. Consult `SigningEnablement::is_signing_enabled(pubkey)` → must be `true`.
2. Sign.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `SigningGate::sign_attestation(att, pk, fork, gvr)` | … | `Result<Signature>` | Gate → stage → sign → commit. |
| `SigningGate::sign_block(root, slot, pk, fork, gvr)` | … | `Result<Signature>` | Gate → stage → sign → commit. |
| `SigningGate::sign_sync_committee_message(...)` | … | `Result<Signature>` | Gate → sign (no DB stage; non-slashable). |
| `SigningGate::sign_aggregate_and_proof(...)` | `AggregateAndProof` | `Result<Signature>` | **Gate → sign** — no DB stage (SS-2/SS-3). |
| `SigningGate::sign_contribution_and_proof(...)` | … | `Result<Signature>` | Gate → sign. |
| `SigningGate::sign_selection_proof(...)` | … | `Result<Signature>` | Gate → sign. |
| `SigningGate::sign_randao_reveal(...)`, `sign_voluntary_exit(...)`, `sign_builder_registration(...)` | … | `Result<Signature>` | Today's behaviour preserved — no slashing-DB. |

**Events:** none — synchronous trait dispatch.

**Internal Structure:**
```
signer/
├── src/
│   ├── lib.rs              # SignerService (kept) — now wraps SigningGate
│   ├── gate.rs             # NEW — SigningGate composes slashing + enablement + BLS + locks
│   ├── enablement.rs       # NEW — trait SigningEnablement (mocked in tests)
│   ├── fail_closed.rs      # NEW — FailClosedDefault trait
│   ├── slashable.rs        # sign_attestation, sign_block (gate + slash + commit)
│   ├── non_slashable.rs    # randao, sync, agg, exit, builder, selection (gate + sign)
│   ├── locks.rs            # ValidatorLockMap
│   ├── traits.rs           # ValidatorSigner trait — implemented on SigningGate
│   └── error.rs            # SigningGateError
└── tests/
    ├── gate_attestation_doppelganger_blocked.rs   # D-3 attestation
    ├── gate_block_doppelganger_blocked.rs         # D-3 block
    ├── gate_sync_doppelganger_blocked.rs          # D-3 sync
    ├── gate_aggregate_no_slashing_db.rs           # SS-2/SS-3
    ├── gate_per_validator_lock.rs                 # TOCTOU
    ├── gate_unknown_pubkey_fails_closed.rs        # D-3 default
    └── chain_of_custody_aggregate.rs              # ADR-009: attest-then-aggregate invariant
```

**Key Design Decisions:**

- **No orchestrator code holds a `Signer` trait.** Compile-time enforcement that the orchestrator cannot bypass the gate. The `signer-registry` enumeration test (PRD M4) asserts that every registered handler routes through `SigningGate`.
- v1 raw-root `sign(signing_root, pubkey)` is gone from the live listener (SS-1). If a legacy listener is bound via opt-in (`InsecureGate::Allow`), its handler unconditionally returns `Status::unimplemented` — no `SigningGate` path.
- `bin/rvc-signer`'s typed handlers shrink dramatically: deserialise → fork validate → `gate.sign_*` → serialise.
- SS-2/SS-3 chain-of-custody: `sign_aggregate_and_proof` skips the slashing DB stage. A top-of-function comment block + integration test enforce the precondition that the inner Attestation was signed via `sign_attestation` first (ADR-009).

**Failure Modes:**

- Gate `Deny*` → `BlockedByDoppelganger` etc; backend never invoked.
- Slashing stage Err → `BlockedBySlashingDb`; backend never invoked.
- Backend sign Err → staged row discarded; per-pubkey lock released.

---

### Module: `net-policy` (NEW)

**Responsibility:** Single source of truth for "is this URL/IP safe to talk to over the network?" Owns the SSRF deny-list (URL-1) and IP pinning / DNS-rebinding (URL-2).

**Domain Entities:**

- `DenyList` — IPv4 + IPv6 reserved ranges per RFC 6890 + IANA registries (Research Angle 04). Concrete ranges:
  - IPv4: `0.0.0.0/8`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, IPv4 multicast (`224.0.0.0/4`).
  - IPv6: normalize IPv4-mapped/`::a.b.c.d` to IPv4; reject `fe80::/10`, `fc00::/7`, `ff00::/8` (multicast), `::1/128`, `::/128`.
- `UrlPolicy { allow_http: bool, allow_loopback: bool }`.
- `PinnedResolver` — wraps `reqwest::dns::Resolve`. Once an import-time IP is validated, the same `SocketAddr` is reused by the signing connection. Re-checks deny-list on every connect.
- `validate_url(url, &UrlPolicy) -> Result<ValidatedUrl, NetPolicyError>` — case-insensitive scheme compare (L-1) using normalised `url::Url`.

**Data Store:** none.

**Public API:**

| Function | Input | Output | Description |
|---|---|---|---|
| `validate_url(s, &UrlPolicy)` | URL string | `Result<ValidatedUrl, _>` | URL-1 + L-1. |
| `validate_url_runtime(s, &UrlPolicy)` | URL string | `Result<(ValidatedUrl, Vec<SocketAddr>), _>` | DNS resolve + deny-list check on every resolved IP. |
| `PinnedResolver::pin(validated_url)` | `ValidatedUrl` | `PinnedResolver` | Plug into `reqwest::Client::builder().dns_resolver(...)`. |
| `PinnedResolver::recheck(&self)` | `&self` | `Result<(), _>` | Called inside `remote_signer.rs` before every sign (URL-2). |

**Events:** none.

**Internal Structure:**
```
net-policy/
├── src/
│   ├── lib.rs
│   ├── deny_list.rs       # URL-1
│   ├── url_policy.rs      # UrlPolicy + validate_url + L-1
│   ├── pinned_resolver.rs # URL-2
│   └── error.rs
└── tests/
    ├── deny_list_ipv4.rs
    ├── deny_list_ipv6.rs
    ├── mixed_case_scheme.rs
    ├── rebinding_recheck.rs
    └── reserved_ranges_property.rs
```

**Key Design Decisions:**

- New crate because both `keymanager-api` and `crypto::remote_signer` depend on it, but neither depends on the other; placing it in either would create a cycle (ADR-002).
- Uses only stdlib `IpAddr` + `url` + `reqwest`. **Zero new external deps.**

**Failure Modes:**

- Any deny-list match or unresolvable host → `Err(NetPolicyError::Denied { reason })`. Callers MUST propagate (PRD §6.3 fail-closed).

---

### Module: `keymanager-api` (extended — thin shim)

**Responsibility:** HTTP API for keystore import/delete and remote-key import. After remediation, all heavy logic moves out:

- URL validation → `net-policy`.
- Time-based doppelganger gate → `doppelganger::ForwardWindowMachine` (existing `gate.rs` is a 30-line shim).
- DELETE export semantics (KM-1) → `slashing::SlashingDb::export_interchange` is atomic (ADR-008); handler aborts the DELETE before any keystore is removed if export fails.
- Cancel-token concurrency (KM-2) → `ForwardWindowMachine::cancel` is single-implementation; the race is structurally impossible.
- KS-1 keystore-import param ceiling → `crypto::Keystore::decrypt_with_caps` enforced *before* decrypt.
- KM-3 non-loopback bind → routed through `eth-types::insecure::InsecureGate`.

**Public API:** unchanged (RESTful endpoints).

**Defense-in-depth contract:**

| Layer | Where | What it catches |
|---|---|---|
| 1. Transport | TLS + bearer token + KM-3 loopback gate | unauthenticated access; non-local exposure |
| 2. URL validation | `net-policy::validate_url + PinnedResolver` | SSRF + DNS rebinding |
| 3. Keystore semantics | KM-1 atomic export-then-delete; KS-1 param ceiling | silent slashing-protection loss; resource DoS |
| 4. Gate insert/cancel | `ForwardWindowMachine::register + cancel` (one lock; one impl) | KM-2 race |

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
    ├── delete_export_failure_aborts.rs   # KM-1
    ├── concurrent_delete_reimport.rs     # KM-2
    ├── import_url_ssrf_rejected.rs       # URL-1
    ├── import_url_rebinding_rejected.rs  # URL-2
    ├── keystore_oversized_params_rejected.rs # KS-1
    └── non_loopback_bind_refuses.rs      # KM-3
```

**Failure Modes:**

- DELETE with export error → 500, no deletion, no slashing-protection rows removed.
- Concurrent delete + re-import → second import waits for the cancellation handshake.
- DNS resolves to allowed IP then rebinds → pinned `SocketAddr` ignored at signing time.
- KM bind to non-loopback without env opt-in → process exits at startup.

---

### Module: `bin/rvc-signer` (extended + legacy gate)

**Responsibility:** Standalone signer binary. Post-remediation:

- v1 raw-root `sign(signing_root, pubkey)` gRPC service is **NOT** registered on the live `tonic::Server` (SS-1).
- v2 typed handlers route through `signer::SigningGate`.
- `bin/rvc-signer/src/slashing/scope.rs` is **deleted**; call sites use `slashing::PubkeyScopedDb` (DVT-1, CN-1).
- DVT partial-sign keys by validator aggregate pubkey + GVR; CN audit-only.
- DVT-2 v1 raw-root path removed; only v2 typed PartialSign remains.
- `bin/rvc-signer/src/insecure_startup.rs` → replaced by `eth-types::insecure::InsecureGate` usage.

**Defense-in-depth contract:**

| Layer | What it catches |
|---|---|
| 1. v1 not on live router | SS-1 bypass |
| 2. Enumeration test (PRD M4) | a future commit re-adding a v1 handler |
| 3. DVT pubkey-scoped slashing + UNIQUE index | cross-CN double-block |
| 4. DVT share-pubkey verify + pinned share-index + index ≠ 0 | malicious partial; share confusion (DVT-3/4/5) |
| 5. mTLS with SNI pinning | DVT peer impersonation |

**Internal Structure (key changes):**
```
bin/rvc-signer/
├── src/
│   ├── main.rs                  # SS-1: v1 SignerServiceServer NOT add_service'd
│   │                              # InsecureGate-gated legacy listener (if compiled) returns Unimplemented
│   ├── service.rs               # v2 handlers route through SigningGate
│   │                              # sign_aggregate_and_proof: no DB consult (SS-2/SS-3)
│   ├── slashing/
│   │   ├── scope.rs             # → DELETED. Uses slashing::PubkeyScopedDb
│   │   └── config.rs
│   ├── dvt/
│   │   ├── peer_service.rs      # DVT-1: pubkey-scoped slashing
│   │   ├── peer_client.rs       # DVT-2: v1 raw-root deleted; DVT-4: pinned share_index
│   │   ├── lagrange.rs          # DVT-5: reject share_index == 0
│   │   └── allow_list.rs
│   └── insecure_startup.rs      # → REPLACED by eth-types::insecure usage
└── tests/
    ├── signing_path_enumeration.rs   # PRD M4 — consumes crates/signer-registry
    ├── v1_unregistered.rs            # SS-1
    ├── aggregate_no_slashing_db.rs   # SS-2/SS-3
    ├── dvt_pubkey_scope.rs           # DVT-1
    ├── dvt_v1_removed.rs             # DVT-2
    ├── dvt_partial_verification.rs   # DVT-3
    ├── dvt_share_index_pin.rs        # DVT-4
    ├── dvt_lagrange_zero.rs          # DVT-5
    └── password_dir.rs               # SIG-1
```

---

### Module: `crates/rvc` (orchestrator, extended)

**Responsibility:** Slot loop, duty fan-out, doppelganger startup wiring, keymanager adapters. Post-remediation:

- **No direct calls to `crypto::sign_*`.** All signs go through `signer::SigningGate`.
- `is_attesting_enabled` is renamed `is_signing_enabled` (PRD Assumption #7). Fast-path skip preserved as defense-in-depth (orchestrator-side check is a perf optimisation; the authoritative gate is `SigningGate`).
- Doppelganger startup detection wired through `ForwardWindowMachine::register` for each managed pubkey (D-1) and `tick` on each slot boundary; `if current_epoch > 0` guard removed (S-3).
- Keymanager adapters (KM-2 race) delegate to `ForwardWindowMachine::cancel`.
- `aggregation.rs`: `validate_attestation_data` on BN responses (L-4); `sync_committee.rs`: `head_root` via `get_block_root("head")` with fallback (S-5).
- Optimistic-BN response gate (BN-1): `coordinator` consults `bn_manager::tier()` AND rejects responses with `execution_optimistic = true` (two layers).
- `key_gen_rx` consumed via `borrow_and_update` (C-1); wired to keymanager imports so one import triggers exactly one `clear_cache()` (S-2).

**Internal Structure (key changes):**
```
crates/rvc/
└── src/
    ├── orchestrator/
    │   ├── coordinator.rs      # SigningGate routing; C-1 borrow_and_update; S-2 wired key_gen
    │   ├── attestation.rs      # routes via signer::SigningGate
    │   ├── aggregation.rs      # L-4 validate_attestation_data; SS-2/SS-3 path
    │   ├── sync_committee.rs   # SigningGate.sign_sync_committee_message; S-5 head_root fallback
    │   ├── duty_management.rs
    │   └── slot_context.rs
    └── keymanager_adapters.rs  # KM-2 single-implementation via ForwardWindowMachine
```

---

### Modules with single-finding, one-file edits (compact entries)

| Crate | ID(s) | File / function | Edit | Failure mode |
|---|---|---|---|---|
| `crypto` | L-1 | `src/remote_signer.rs:35-42` | Compare normalised `parsed.scheme()` against `"https"`. | Reject mixed-case HTTPS rejected today → accepted. Reject other schemes still. |
| `crypto` | L-2 | `src/pubkey.rs:54-58` | `strip_prefix_strict`, validate even-length hex, real error type. | Double-`0x` or odd-length hex → `Err`. |
| `crypto` | KS-1 (helper) | `src/keystore.rs:41-44, 198-251` | Memory-estimate helper corrected; effective-cost gate exposed. | Oversized params → reject at decrypt; keymanager-api calls gate before decrypt. |
| `crypto` | URL-2 (signer side) | `src/remote_signer.rs:157` | IP-pinned `reqwest::Client` via `net-policy::PinnedResolver`; deny-list re-validated on every sign. | Rebinding rejected; sign fails closed. |
| `crypto` | Info-5 (insecure tests) | `src/insecure.rs:249-330` | Serialise env-mutating tests with `std::sync::Mutex<()>` (ADR-009). | Test parallelism preserved without `serial_test` dep. |
| `block-service` | B-1/T-1, L-9 | `src/service.rs:287-385, 370-382, 2597-2622, 2641-2661` | Bound published bytes at `kzg_offset`; serialise Deneb+ as proper `SignedBlockContents`; un-ignore L-9 tests. | Published bytes deserialise back to `SignedBlockContents` whose inner block tree-hashes to signed root. |
| `beacon` | Info-4 | `src/client.rs:250-256, 338-343, 402-435` | Validate 32-byte / 4-byte hex at the boundary; validate `Eth-Consensus-Version` against known fork names. | Malformed BN payload rejected at boundary. |
| `beacon` | Info-5 (dead API) | `src/ssz_deser.rs:115-143` | Delete dead `extract_block_header_from_ssz` or bound at `kzg_offset`. | Dead code removed. |
| `secret-provider` | SP-1 | `src/refresh.rs:54-67` | Drop name-derived early-skip; dedupe by derived pubkey; validate `pubkey_hex`. | Name-collision but different payload → loaded (not silently dropped). |
| `secret-provider` | Info-5 (GCP zeroize) | `src/gcp.rs:49-62` | Zeroize SDK-buffered payload after extracting secret. | Reduces memory residency of secret bytes. |
| `duty-tracker` | DT-1 | `src/tracker.rs:63-82, 91-95, 181-185, 297-301, 419-423` | `RwLock<Vec<String>>` (or `ArcSwap`); `update_validator_indices` setter. | Setter not called → no duties for new key (caught by M7). |
| `builder` | BLD-1 | `src/service.rs:88-106, 215-227` | Re-register on bounded cadence; refresh embedded `timestamp`. | Registration sent within relay TTL even if `(fee_recipient, gas_limit)` unchanged. |
| `sync-service` | SYNC-1 | `src/lib.rs:251-260` | Validate BN-returned `subcommittee_index`/`slot`/`beacon_block_root`; skip+warn on mismatch. | Mismatched contribution → skipped; no signature. |
| `grpc-signer` | GRPC-1/2/3 | `src/client.rs:115-159, 183-188, 124-159, 291-302` | `tls_enabled` from actual branch; require all three TLS fields together; `connect_timeout` + per-RPC deadline. | Partial TLS → hard error. Sign deadline below slot deadline. |
| `telemetry` | TEL-1 | `src/config.rs:95-108` | Parse with `url::Url`; strip user info; redact known-sensitive query keys. | OTLP endpoint passwords / tokens stripped. |
| `timing` | TIM-1 | `src/clock.rs:52-54, 97-106` | Mirror `as_millis()` arithmetic. | Sub-second offset preserved. |
| `validator-store` | VS-1 | `src/store.rs:343-346` | After `persist`, `File::open(parent)?.sync_all()?`. | Crash-durable rename. |
| `crates/rvc` | L-5 | `monitoring.rs:88-90` | Check `> 0` before casting; `saturating_mul`. | sysconf failure no longer panics. |
| `crates/rvc` | Info-3 | `monitoring.rs:104-109, 77-90` | macOS query current RSS; `/proc/self/stat` split after last `)`. | Accurate RSS; comm-containing-parens handled. |
| `bin/rvc-keygen` | KG-1 | `bls_to_execution.rs:51-59, 144` | Build domain with `GENESIS_FORK_VERSION`. **Delete or invert** `test_bls_to_execution_uses_capella_fork_version`. | Previous outputs invalid — release-notes call-out. |
| `bin/rvc-keygen` | KG-2 | `new_mnemonic.rs:182-220` | Treat `FAILED`/`MISMATCH` as hard error; skip deposit-data. | Non-zero exit; no bad keystore persisted. |
| `bin/rvc-keygen` | KG-3 | `new_mnemonic.rs:123-127`, `bls_to_execution.rs:67`, `exit.rs:42` | `DirBuilder::new().recursive(true).mode(0o700)`. | Output dirs world-unreadable. |
| `bin/rvc` | CLI-1 | `main.rs:280-299` | `*-token-file` / env intake mirroring `--password-file`. | Bearer tokens no longer visible via `/proc/<pid>/cmdline`. |
| `bin/rvc` | Info-5 (metrics bind) | `main.rs:1629-1634` | Log + surface metrics bind/serve error. | Silent swallow eliminated. |

---

## Cross-Cutting Concerns

### Authentication & Authorization

| Surface | Auth | Authz | Defense-in-depth |
|---|---|---|---|
| Operator → keymanager-API | TLS + bearer token (`CLI-1` token-file/env intake) | route-level | + KM-3 loopback gate at bind |
| rvc ↔ rvc-signer (gRPC) | mTLS (`grpc-signer` requires all three TLS fields per GRPC-2); CN audit-only (CN-1) | client CN allow-list at signer | + IP-pinned `PinnedResolver`; URL deny-list; per-RPC deadline (GRPC-3) |
| rvc ↔ BN (HTTP) | bearer token (BN auth header) | none (BN trusts all callers) | + treat BN as untrusted (BN-1/2, S-5, SYNC-1, EXIT-1, Info-4 boundary validation) |
| rvc-signer ↔ DVT peer (gRPC) | mTLS + SNI pinning | per-peer share-index pin (DVT-4); aggregate-pubkey-scoped slashing | + Lagrange `index ≠ 0` (DVT-5); per-partial pubkey verify (DVT-3) |

All "is this key allowed to sign right now?" questions go through `signer::SigningGate`, which composes:

1. `ForwardWindowMachine::is_signing_enabled(pubkey)` — fail-closed on unknown pubkey.
2. `PubkeyScopedDb` stage (slashable only).
3. `CompositeSigner::sign`.

The orchestrator structurally cannot bypass this because `crypto::Signer::sign` is not held by any orchestrator code — only by `SigningGate`. The `signer-registry` enumeration test verifies this invariant.

### Logging & Observability

- Structured `tracing` spans on every `SigningGate::sign_*` method (one span per signing path: `rvc.sign.attestation`, `rvc.sign.block`, …).
- `rvc.slashing.result` field on every slashable sign.
- `rvc.doppelganger.gate_outcome` field on every sign (new seam-level observation).
- Pubkey logged only via `crypto::logging::TruncatedPubkey`.
- `telemetry::redact_endpoint` (TEL-1) used by all telemetry exports.
- Metrics:
  - `rvc_slashing_protection_checks_total{result}` (existing).
  - `rvc_signer_slashing_tx_hold_duration_ms{kind}` (existing).
  - `rvc_doppelganger_gate_total{outcome}` (new).
  - `rvc_gate_transitions_total{from,to,reason}` (new).

### Error Handling

- `thiserror` per library crate; `anyhow` at bin-`main`.
- Seam-level errors are *terminal* at the orchestrator; no fallback retry on `BlockedByDoppelganger` or `BlockedBySlashingDb`.
- BN response validation (`validate_attestation_data` for aggregation L-4; sync-committee SYNC-1) → `Err` → skip+warn, never sign.
- `FailClosedDefault<bool>` is the convention for boundary booleans: returns `false` for unknown inputs. Replaces every `unwrap_or(true)` on a safety boundary.

### Configuration

- `eth-types::insecure::InsecureGate` env vars: `RVC_KEYMANAGER_ALLOW_NON_LOOPBACK` (KM-3), `RVC_SIGNER_ENABLE_LEGACY_V1` (SS-1; off by default; documented but not implemented in M1).
- `--token-file` / `--token-env` for bearer tokens (CLI-1).
- `--password-dir` semantic: per-keystore `<dir>/<pubkey>.txt` (SIG-1; PRD Assumption #5).
- Slashing-DB schema migrations idempotent, gated by `metadata.migration_v2_applied_at`.

### Dependency-graph enforcement

A `tests/architecture_no_cycles.rs` parses `cargo metadata` (no new dep — `cargo` is the toolchain) and asserts:

- No edge from `slashing` to `doppelganger`.
- No edge from `doppelganger` to `keymanager-api`.
- No edge from `signer` to `keymanager-api`.
- No edge from any production crate to `signer-registry` (dev-only).
- The transitive-dep graph is a DAG.

---

## Data Flow Diagrams

### Doppelganger-gated attestation

```text
Slot tick (orchestrator)
   │
   ▼
duty-tracker ──fetch──▶ bn-manager ──HTTP──▶ Beacon Node
                                  ◀── attestation duty (rejected if optimistic; BN-1)
   │
   ▼
orchestrator::attestation (validates BN response; L-4)
   │
   ▼  attest_data, pubkey, fork_schedule, gvr
signer::SigningGate::sign_attestation
   │
   ├──▶ ValidatorLockMap::get(pubkey).lock()  (TOCTOU guard)
   │
   ├──▶ SigningEnablement::is_signing_enabled(pubkey)
   │      └── false (still in window) ──▶ BlockedByDoppelganger ──▶ SKIP + warn, NO signature
   │      └── true ──▶ continue
   │
   ├──▶ PubkeyScopedDb::stage_attestation(pubkey, src, tgt, root, gvr)
   │      └── slashable ──▶ BlockedBySlashingDb ──▶ discard guard
   │      └── safe ──▶ continue (transaction held; SQLite UNIQUE index is Layer 3)
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
   ├──▶ crypto::Keystore::decrypt_with_caps (KS-1 effective-cost gate)
   │
   ├──▶ slashing::InterchangeImporter::import (GVR-1 canonicalize; IMP-1 source≤target)
   │       └── err ──▶ 400, key NOT loaded
   │
   ├──▶ ValidatorManager::insert_local_key
   │
   ├──▶ ForwardWindowMachine::register(pubkey, current_epoch)  ◀── KM-2 single-implementation
   │       (cancels any displaced cancel token under one lock)
   │
   └──▶ key_gen_tx.send(())                                    ◀── S-2 wires to orchestrator
            │
            ▼
       orchestrator::coordinator::key_gen_rx.borrow_and_update ◀── C-1
            │
            ▼
       duty-tracker::update_validator_indices                  ◀── DT-1
```

Any sign request for the new pubkey is blocked by `ForwardWindowMachine::is_signing_enabled == false` for the next `monitoring_epochs` epochs.

### DELETE /eth/v1/keystores fails closed on export error

```text
DELETE /eth/v1/keystores  ──▶ keymanager-api::handlers::delete
   │
   ├──▶ slashing::SlashingDb::export_interchange(pubkeys, gvr)   ◀── ATOMIC contract (ADR-008)
   │       ├── ok(interchange) ──▶ continue
   │       └── err ──▶ 500, NO KEY DELETED                        ◀── KM-1 fail-closed
   │
   ├──▶ for each pubkey:
   │       ├── ValidatorManager::remove(pubkey)
   │       └── ForwardWindowMachine::cancel(pubkey)
   │
   └──▶ 200 { data, slashing_protection: interchange }
```

### Block proposal SSZ publish (B-1/T-1 + E-1)

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
   └──▶ propagator::publish_block_ssz (bytes deserialise round-trip in test)
```

### Voluntary exit with GVR validation (EXIT-1)

```text
CLI: rvc voluntary-exit --validator-pubkey 0xab... [--network optional]
   │
   ▼
commands/voluntary_exit.rs::run
   ├─ beacon.get_genesis()  (NEW; was missing)
   │   ├─ effective_gvr  ──▶ eth-types::canonical::parse_gvr_hex (GVR-1 helper)
   │   └─ effective_genesis_time
   │
   ├─ if user supplied --genesis-validators-root, compare; mismatch ──▶ Err (fail-closed)
   │
   ▼
SigningGate::sign_voluntary_exit(exit, pubkey, fork_schedule, effective_gvr)
   ▼
propagator::submit_voluntary_exit(...) ──▶ Beacon node
```

---

## Test Architecture (first-class)

Test infrastructure is part of the architecture, not an afterthought. It has four sub-modules with defined responsibilities:

```text
       ┌────────────────────────────────────────────────────────────────────┐
       │                       Test architecture                            │
       │                                                                    │
       │   Spec-vector fixtures (per consuming crate's tests/fixtures/)     │
       │        │                                                           │
       │        ├─►  E-1/E-2 in crates/eth-types/tests/                     │
       │        ├─►  B-1/T-1 in crates/block-service/tests/                 │
       │        └─►  KG-1 in bin/rvc-keygen/tests/                          │
       │                                                                    │
       │   crates/signer-registry (dev-only)                                │
       │        │                                                           │
       │        └─►  enumeration test (SS-1 / PRD M4)                       │
       │              in bin/rvc-signer/tests/                              │
       │              Asserts: every slashable handler routes through       │
       │              signer::SigningGate; v1 handler is NOT on live router │
       │                                                                    │
       │   FailClosedDefault property tests                                 │
       │        │                                                           │
       │        └─►  in signer/tests/                                       │
       │              proptest: for every (pubkey, decision) input,         │
       │              gate never returns Allow when underlying state is     │
       │              invalid                                               │
       │                                                                    │
       │   tests/architecture_no_cycles.rs (workspace root)                 │
       │        │                                                           │
       │        └─►  cargo metadata DAG check (Cross-Cutting §)             │
       │                                                                    │
       │   per-finding RED-then-GREEN tests (one per PRD acceptance)        │
       │        │                                                           │
       │        └─►  in the crate the fix lands in                          │
       └────────────────────────────────────────────────────────────────────┘
```

**Spec-vector fixtures (PRD §6.2):** per-consuming-crate `tests/fixtures/` with a sibling `README.md` documenting provenance. Sourced from `ethereum/consensus-spec-tests` at the active spec tag; KG-1 from `staking-deposit-cli`. Minimum coverage:

- E-1: one `BeaconBlock` per fork (Bellatrix, Capella, Deneb, Electra).
- E-2: one `AggregateAndProof` with real-committee-size `aggregation_bits` (e.g. 63 bytes ≈ 500 validators); one sync `Contribution`.
- B-1/T-1: one Deneb+ block with ≥1 blob commitment + expected `SignedBlockContents` SSZ bytes.
- KG-1: one `SignedBLSToExecutionChange` from `staking-deposit-cli` with expected signing root + signature.

**`crates/signer-registry` (dev-only):** compile-time constant `SIGNING_PATHS: &[SigningPathEntry]` where each entry is `{ binary, surface_kind, method_name, message_type, expected_gate, expected_slashing }`. Entries generated from `signer_v2.proto` + in-process `ValidatorSigner` trait + keymanager-API routes. The enumeration test (SS-1 / PRD M4) reads `SIGNING_PATHS` and asserts:

- Every `message_type ∈ {Block, Attestation}` entry's `expected_slashing == Required`.
- Every `Required` entry has a registered handler routed through `signer::SigningGate`. Verified via a `const _: () = ...;` marker at each handler that compile-fails if the signing path is not wrapped.
- The legacy v1 `sign(signing_root, pubkey)` entry has `expected_gate == SeparatelyBoundInsecureOptIn` AND the production router does not bind it.

**`tests/architecture_no_cycles.rs`:** at workspace root; uses `cargo metadata --format-version 1` to dump the dep graph and asserts the level-graded DAG. Refused edges enumerated in the test.

**No circular dependencies in the test graph.**

---

## Infrastructure & Deployment

### Deployment Model

Unchanged. Cargo workspace, three bins (`rvc`, `rvc-signer`, `rvc-keygen`). `rvc-signer` is a separate process that the VC talks to over gRPC. No new bins; no new processes.

The standalone signer **already exists as a separate process** — this is the strongest available cross-process boundary for slashing protection. The remediation keeps it that way and adds layered enforcement inside the signer binary so that even a VC that becomes malicious cannot produce a slashable signature.

### Scaling Strategy

Unchanged. Shared seams are in-process libraries; no new network hops. `SigningGate`'s per-validator mutex map preserves the existing per-validator throughput characteristics.

### Rollout & Sequencing (replaces "Service Extraction Path")

The PRD's milestones M1 / M2 / M3 define the rollout. Per-finding branch ordering with shared pre-work factored out so per-fix branches stay narrow.

#### M1 — Slashing-safety floor (PRD §11)

**Shared pre-work** (lands on `prep/M1-shared` before any fix branch):

- Add `eth-types::canonical` module (no consumers yet; compiles to zero behavior change).
- Add `eth-types::insecure::InsecureGate` enum (no consumers yet).
- Add `signer::SigningEnablement` trait + `FailClosedDefault` trait (no consumers yet).
- Add `slashing::SlashingDbReader` trait (read-only).
- Add `signer → doppelganger` Cargo dep edge.

**Fix branches** (one per finding except where PRD §7.1 clusters overlap):

| Order | Finding | Branch | Files touched |
|---|---|---|---|
| 1 | SS-1 | `fix/SS-1-remove-v1-raw-root` | `bin/rvc-signer/src/{main,service}.rs` |
| 2 | KM-1 | `fix/KM-1-delete-fail-closed` | `crates/keymanager-api/src/handlers.rs`, `crates/slashing/src/db.rs` (atomic export contract) |
| 3 | DVT-1 + CN-1 (PRD §7.1) | `fix/DVT-1-CN-1-pubkey-scope` | `crates/slashing/src/{stage,db,migration,scoped}.rs`, `bin/rvc-signer/src/dvt/peer_service.rs` |
| 4 | D-1 | `fix/D-1-forward-window` | `crates/doppelganger/src/forward_window.rs` |
| 5 | D-2 | `fix/D-2-fail-closed-missing-liveness` | `crates/doppelganger/src/forward_window.rs` |
| 6 | D-3 | `fix/D-3-centralize-gate` | `crates/signer/src/{lib,gate,enablement,traits}.rs`, `crates/validator-store/src/store.rs` |
| 7 | KM-2 | `fix/KM-2-cancel-token-race` | `crates/keymanager-api/src/handlers.rs`, `crates/doppelganger/src/forward_window.rs` |
| 8 | S-3 | `fix/S-3-epoch-0-dop` | `bin/rvc/src/main.rs` |

**M1 exit gate:** all merged FF-only to `develop`; CI green; the `signer-registry` enumeration test (PRD M4) on registered gRPC methods is included in `bin/rvc-signer` test suite; `tests/architecture_no_cycles.rs` green.

#### M2 — Duty correctness floor (PRD §11)

**Shared pre-work:**

- Land spec-vector fixtures under each consuming crate's `tests/fixtures/` (one commit per fork; PRD §6.2).
- Promote `eth-types::canonical::parse_gvr_hex` for use by `slashing::import` and `bin/rvc` exit subcommands.

**Fix branches:**

| Order | Finding(s) | Branch | Files touched |
|---|---|---|---|
| 1 | E-1 | `fix/E-1-body-container-hash` | `crates/eth-types/src/{block,tree_hash_utils}.rs` |
| 2 | E-2 | `fix/E-2-bitlist-chunk-count` | `crates/eth-types/src/{tree_hash_utils,aggregation}.rs` |
| 3 | B-1+T-1+L-9 (PRD §7.1) | `fix/B-1-T-1-blockcontents` | `crates/block-service/src/service.rs`, `crates/beacon/src/ssz_deser.rs` |
| 4 | KG-1 | `fix/KG-1-bls-to-execution-gvr` | `bin/rvc-keygen/src/bls_to_execution.rs` |
| 5 | SS-2+SS-3 + L-4 (PRD §7.1 aggregator cluster) | `fix/aggregator-correctness` | `bin/rvc-signer/src/service.rs`, `crates/signer/src/non_slashable.rs`, `crates/rvc/src/orchestrator/aggregation.rs` |
| 6 | BN-1 | `fix/BN-1-optimistic-tier` | `crates/bn-manager/src/sync_status.rs`, `crates/rvc/src/orchestrator/coordinator.rs` (per-response check) |
| 7 | BN-2 | `fix/BN-2-startup-sync` | `crates/bn-manager/src/{sync_status,manager}.rs` |
| 8 | DT-1 + S-2 + C-1 (PRD §7.1) | `fix/runtime-import` | `crates/duty-tracker/src/tracker.rs`, `bin/rvc/src/main.rs`, `crates/rvc/src/orchestrator/coordinator.rs` |
| 9 | S-5 | `fix/S-5-sync-head-root` | `crates/rvc/src/orchestrator/{slot_context,sync_committee}.rs` |
| 10 | SSE-1 | `fix/SSE-1-callback-isolation` | `crates/bn-manager/src/sse.rs` |
| 11 | GVR-1 + IMP-1 (PRD §7.1) | `fix/slashing-import` | `crates/slashing/src/{import,db}.rs` |
| 12 | KG-2 | `fix/KG-2-verify-hard-fail` | `bin/rvc-keygen/src/new_mnemonic.rs` |
| 13 | EXIT-1 | `fix/EXIT-1-gvr-cross-check` | `bin/rvc/src/commands/{voluntary_exit,prepare_exit}.rs` |
| 14 | BLD-1 | `fix/BLD-1-refresh-cadence` | `crates/builder/src/service.rs` |
| 15 | SYNC-1 | `fix/SYNC-1-validate-contribution` | `crates/sync-service/src/lib.rs` |
| 16 | KS-1 | `fix/KS-1-effective-cost-gate` | `crates/crypto/src/keystore.rs`, `crates/keymanager-api/src/keymanager_adapters.rs` |

**M2 exit gate:** PRD M2/M3/M7 verified; spec-vector cross-checks against Lighthouse/Lodestar landed.

#### M3 — Hardening + P2 cleanup (PRD §11)

**Shared pre-work** (lands on `prep/M3-shared`):

- Add `crates/net-policy` (URL-1/URL-2 cluster needs it).

**Fix branches:** all remaining P2 findings, each on its own branch per principle P8, except clusters per PRD §7.1 (URL-1+URL-2; remote-signer transport-hardening sequence including GRPC-1/2/3 and L-1).

| Order | Finding(s) | Branch |
|---|---|---|
| 1 | KM-3 | `fix/KM-3-keymanager-insecure-gate` |
| 2 | URL-1 + URL-2 (PRD §7.1) | `fix/URL-1-URL-2-net-policy` |
| 3 | GRPC-1/2/3 + L-1 (PRD §7.1 remote-signer hardening) | `fix/grpc-tls-deadlines` |
| 4 | VS-1 | `fix/VS-1-fsync-parent` |
| 5 | L-1 (if not merged above) | (subsumed) |
| 6 | L-2 | `fix/L-2-pubkey-parse-strict` |
| 7 | L-3 | `fix/L-3-all-zeros-gvr` |
| 8 | L-5 | `fix/L-5-rss-overflow` |
| 9 | DVT-2 | `fix/DVT-2-v2-only` |
| 10 | DVT-3 | `fix/DVT-3-partial-verify` |
| 11 | DVT-4 | `fix/DVT-4-share-index-pin` |
| 12 | DVT-5 | `fix/DVT-5-lagrange-zero` |
| 13 | KG-3 | `fix/KG-3-dir-mode-0700` |
| 14 | SIG-1 | `fix/SIG-1-password-dir` |
| 15 | SP-1 | `fix/SP-1-refresh-dedupe` |
| 16 | TIM-1 | `fix/TIM-1-ms-precision` |
| 17 | CLI-1 | `fix/CLI-1-token-file` |
| 18 | TEL-1 | `fix/TEL-1-redact` |
| 19 | Info-1..5 (each individually) | `fix/Info-*` |

**M3 exit gate:** all 46 findings closed (PRD M1, M8); release notes drafted (PRD §12).

### Per-module readiness for service extraction

Out of scope per PRD §2. Existing extraction (`rvc-signer` already a separate process) preserved. New crates (`net-policy`, `signer-registry`) are in-process libraries.

For completeness, post-remediation extraction-readiness of the new seams:

| Seam | Owning crate | Extraction readiness | Notes |
|---|---|---|---|
| `eth-types::canonical` | eth-types | Keep together | Type helpers; no state. |
| `eth-types::tree_hash_utils` | eth-types | Keep together | Pure functions over local types. |
| `eth-types::insecure::InsecureGate` | eth-types | Keep together | Pure types + env reads. |
| `net-policy` | net-policy | Already extracted | Could become a public crate later. |
| `signer-registry` | signer-registry (dev-only) | Already extracted | No production edge; could grow into a release-time invariant checker. |
| `SigningGate` | signer | Keep together with crypto/slashing/doppelganger | The seam IS the orchestrator↔BLS boundary. |
| `ForwardWindowMachine` | doppelganger | Ready now | Trait-mocked deps; sidecar-extractable. |
| `PubkeyScopedDb` + `InterchangeImporter` | slashing | Ready now | Smaller API surface post-remediation (no `client_cn` arg). |

---

## Technology Choices

**Net new external dependencies introduced by this architecture: zero.** PRD §2 satisfied without exception.

| Concern | Choice (unchanged) | Rationale |
|---|---|---|
| Language | Rust 2021, MSRV 1.92 | Existing workspace pin. |
| Async runtime | Tokio | Existing. |
| HTTP server | Axum | keymanager-api. |
| gRPC | tonic + prost | rvc-signer. |
| HTTP client | reqwest (rustls) | BN + keymanager + remote-signer; `net-policy` plugs in via `reqwest::dns::Resolve`. |
| SSZ | `ethereum_ssz` + `tree_hash` | E-1/E-2 fix uses existing primitives. |
| BLS | `blst` | Existing. |
| Slashing DB | SQLite (`rusqlite`) | Existing; schema migration only. |
| Error model | `thiserror` per crate; `anyhow` at bin | Existing. |
| Tests | `proptest` (already in dev-deps); `std::sync::Mutex<()>` env-mutex for Info-5 (ADR-009) | No `serial_test` added. |

---

## ADRs (Architecture Decision Records)

### ADR-001: Centralise the slashing-protection + doppelganger signing gate in `crates/signer`

- **Status:** Accepted.
- **Context:** D-3 (P0) found that the doppelganger enable-gate is consulted only on attestation. PRD assumption #6 prefers centralisation. SS-2/SS-3 (P0) and DVT-1/CN-1 (P0/P1) found EIP-3076 consultation reimplemented (incorrectly) at multiple sites.
- **Decision:** `SigningGate` in `crates/signer` is the *only* code path producing a slashable signature. Composes `ForwardWindowMachine` (doppelganger) + `PubkeyScopedDb` (slashing) + `CompositeSigner` (BLS). All orchestrator paths, all `bin/rvc-signer` typed handlers, all DVT partial-sign sites depend on `SigningGate`.
- **Alternatives considered:**
  - Scatter the gate across orchestrator entry points (PRD-rejected alternative). More invasive over time; every new signing path is a regression risk.
  - Put the gate in `bin/rvc-signer` only. Leaves the in-process VC sign path ungated; would require duplicating logic.
  - Put the gate in `crates/rvc`. The orchestrator is already the largest crate; adding gating logic there doesn't reduce duplication for `bin/rvc-signer`.
- **Consequences:** Orchestrator structurally unable to bypass the gate (no `crypto::sign_*` calls). `bin/rvc-signer` handler code shrinks ~30%. Future signing paths inherit the gate by using the `SigningGate` API.

### ADR-002: Introduce `crates/net-policy` as a new small crate

- **Status:** Accepted.
- **Context:** URL-1 (deny-list) and URL-2 (IP pinning + DNS rebinding) are needed by both `keymanager-api` and `crypto::remote_signer`. Placing the helper in either creates a dependency from the other towards a crate that should not export it.
- **Decision:** New `crates/net-policy` at workspace level. Both consumers depend on it.
- **Alternatives considered:**
  - Put it in `crypto`. Acceptable fallback if "no new crates" hardens.
  - Put it in `eth-types`. Violates eth-types' "no network" boundary.
  - Leave it duplicated. Violates the shared-seams optimisation goal.
- **Consequences:** One new tiny crate (~400 LoC). One new entry in `Cargo.toml [workspace.dependencies]`.

### ADR-003: Inline `InsecureGate` inside `eth-types`, not as a new crate

- **Status:** Accepted. **Override of the original shared-seams plan.**
- **Context:** SS-1, KM-3, L-1, SIG-1 all want the same `Refuse | Warn | Allow` semantics. A separate `crates/insecure-gate` (~100 LoC) was originally proposed. Surgical critique: a 100-LoC crate is workspace-noise overhead when the module has no per-crate deps that would induce a cycle.
- **Decision:** Place `InsecureGate` as a small module inside `eth-types::insecure`. `eth-types` is the only workspace leaf every consumer (including `bin/rvc-signer`, `bin/rvc`, `keymanager-api`) already imports. The module has no other deps.
- **Alternatives considered:**
  - Separate crate `crates/insecure-gate`. Rejected as cartoonish blast-radius inflation for ~100 LoC.
  - Inline a function in each bin. Rejected — review explicitly cited the inconsistency as a finding.
- **Consequences:** No new crate. The module lives in `eth-types/src/insecure.rs`. Future "insecure opt-in" additions are trivial and consistent.

### ADR-004: Pubkey-scoped slashing keying with `client_cn` as audit-only column

- **Status:** Accepted.
- **Context:** DVT-1 (P0) and CN-1 (P1) share a root cause: the slashing DB's `WHERE` clauses include `client_cn`, so two clients/peers using the same pubkey end up with independent watermarks.
- **Decision:** SQLite UNIQUE indices become `(pubkey, gvr, slot)` and `(pubkey, gvr, target_epoch)`. `client_cn` is a non-key audit column. Migrate existing DBs per the row-pair resolution table in the slashing module detail; migration is idempotent and transactional. Invariant preserved: post-migration DB rejects every message the pre-migration DB rejected.
- **Alternatives considered:**
  - Enforce pubkey→CN binding. Still leaves the DB unable to detect cross-CN double-sign without an explicit cross-CN check on every call.
  - Per-CN multi-tenancy with a separate cross-CN sentinel table. More moving parts; defers safety property to a secondary mechanism.
- **Consequences:** One-way schema migration on first start after upgrade. Documented in release notes. Backup recommended. Captured pre-migration DB fixture verifies the migration.

### ADR-005: `ForwardWindowMachine` is the source of truth for doppelganger state

- **Status:** Accepted.
- **Context:** Today `keymanager-api/src/gate.rs` owns a time-based `DoppelgangerGate` map (KM-2 race surface). The actual detection runs in `crates/doppelganger` but only at startup and only on attestation (D-3).
- **Decision:** State machine in `crates/doppelganger::forward_window`. `keymanager-api::gate` is a 30-line shim delegating to `ForwardWindowMachine`. `signer::SigningGate` consults the same `ForwardWindowMachine` instance.
- **Alternatives considered:**
  - Keep two implementations and sync them. KM-2 race is exactly that bug class.
  - Put everything in `keymanager-api`. Violates separation; the gate must be queryable from orchestrator + signer + keymanager.
- **Consequences:** `keymanager-api::gate` shrinks. `crates/doppelganger` grows by the forward-window module. KM-2 race becomes structurally impossible (no `insert` API can return an un-cancelled old token).

### ADR-006: `eth-types::canonical` owns ALL hex/GVR/pubkey parsing

- **Status:** Accepted.
- **Context:** L-2, L-3, GVR-1, IMP-1, Info-4 all do hex/format parsing in different crates with different rules.
- **Decision:** `canonical` module in `eth-types`. Every call site that today calls `hex::decode` on a pubkey/GVR/signing-root switches to `canonical::parse_pubkey_hex` / `parse_gvr_hex` / `parse_signing_root_hex`. The slashing DB's `import()` uses `canonical::eq_gvr`.
- **Alternatives considered:**
  - Per-crate helpers (today's state; findings prove it doesn't hold up).
  - Put in `crypto`. Works, but `slashing` would gain a transitive `crypto` dep just for hex parsing.
- **Consequences:** Hex-decode call sites collapse to one each. L-2 and L-3 close as one test suite.

### ADR-007: Defense-in-depth at the SQLite UNIQUE index

- **Status:** Accepted.
- **Context:** SS-1's bypass shows that single-layer logical checks are fragile. Even with the staging-logic fix, a future bug could reintroduce a hole.
- **Decision:** Keep (and document) SQLite UNIQUE indices `(pubkey, gvr, slot)` and `(pubkey, gvr, target_epoch)` as a structural barrier independent of staging logic. Two layers: (1) staging logic correctness, (2) DB rejects literal duplicate row. The CN-1/DVT-1 scope-key collapse to pubkey-only is what makes the unique index *catch* cross-CN double-block cases.
- **Alternatives considered:**
  - Rely on staging logic only. Exactly what failed in SS-1.
  - Add SQLite triggers as a third layer. Extra dependency surface; no additional invariant.
- **Consequences:** One INSERT failure path (constraint violation) becomes the explicit defense-in-depth signal. Test asserts the indices exist (`PRAGMA index_list`).

### ADR-008: Atomic export contract in `slashing::export_interchange`

- **Status:** Accepted.
- **Context:** KM-1 mandates that DELETE on export error must not silently delete keys.
- **Decision:** `slashing::export_interchange` is **atomic**: succeeds for every requested pubkey or returns `Err` with no partial state. `keymanager-api::handlers::delete` relies on this contract.
- **Alternatives considered:**
  - Per-key partial export with status field. Rejected (PRD assumption #9 default; simpler atomic version preferred).
- **Consequences:** The `unwrap_or_else(|e| empty_interchange())` line is deleted; caller-side handling is a clean `?` or hard-error.

### ADR-009: SS-2/SS-3 chain-of-custody invariant restated in code + integration test

- **Status:** Accepted.
- **Context:** Research §02 R5 flags that removing slashing-DB consultation from `sign_aggregate_and_proof` is correct *only* because the inner attestation was already signed via `sign_attestation`. The invariant is easy to lose to a future contributor.
- **Decision:** Restate as a top-of-function comment block + an integration test (`signer/tests/chain_of_custody_aggregate.rs`) that attests-then-aggregates and asserts the attestation row exists in the DB before the aggregate sign.
- **Alternatives considered:**
  - Type-level enforcement (e.g. `AggregateAndProof<Witnessed>` newtype proving an attestation was signed). Rejected: scope creep; new type plumbed across many call sites.
- **Consequences:** Invariant documented and tested but not type-checked. Future-pass invariant-typing is out of scope.

### ADR-010: SS-1 v1 raw-root handler kept compiled but unregistered

- **Status:** Accepted (matches PRD §10 Q1 default).
- **Context:** SS-1's acceptance criterion offers two strategies: delete the v1 handler entirely, or keep it compiled returning `Status::unimplemented` (with a separately-bound insecure opt-in).
- **Decision:** Keep the v1 handler compiled, returning `Status::unimplemented`. Bind only via a separately-bound, off-by-default insecure listener (documented; not implemented in M1).
- **Alternatives considered:**
  - Delete entirely. Rejected — leaves no audited path for a deliberate operator override during incident response.
- **Consequences:** ~30 lines of `Status::unimplemented` live on. Enumeration test asserts the v1 handler is NOT on the live router.

### ADR-011: Use a process-global env-mutex (no `serial_test`) for Info-5 insecure tests

- **Status:** Accepted.
- **Context:** Info-5 tests mutate process-global env; tests race. `serial_test` is the natural fix but a new workspace dependency.
- **Decision:** `std::sync::Mutex<()>` at module scope in `crates/crypto/src/insecure.rs`; every env-mutating test acquires it. Zero new deps.
- **Alternatives considered:**
  - `serial_test` crate. Rejected per principle P6.
- **Consequences:** One line + a `lock` call at the head of each affected test.

### ADR-012: Keep the orchestrator-side `is_signing_enabled` check as defense-in-depth

- **Status:** Accepted.
- **Context:** ADR-001 centralises the gate in `SignerService`. PRD criterion D-3(a) says "preferably centralized" — open whether the orchestrator-side check is then deleted.
- **Decision:** Rename only (orchestrator-side `is_attesting_enabled` → `is_signing_enabled`). Don't delete: a fast-path skip saves an RPC/sign round-trip per slot when the gate is off, and provides defense-in-depth if a future contributor adds a signing path that bypasses `SignerService`. Risk of the two layers disagreeing is mitigated by a sealed-trait pattern on `SigningEnablement` so both layers must consult the same implementor.
- **Alternatives considered:**
  - Delete every orchestrator-side check. Rejected: increases per-slot RPC cost when the gate is off; removes a layer.
- **Consequences:** Two checks at two layers; both must agree to sign.

### ADR-013: Spec-vector fixtures live with the consuming crate

- **Status:** Accepted (matches principle P9).
- **Context:** PRD §6.2 specifies fixture sources. A natural design could centralise in `crates/test-fixtures`.
- **Decision:** Each consuming crate owns its `tests/fixtures/`. E-1 in `crates/eth-types/tests/fixtures/`; B-1 in `crates/block-service/tests/fixtures/`; KG-1 in `bin/rvc-keygen/tests/fixtures/`.
- **Alternatives considered:**
  - `crates/test-fixtures` shared crate. Rejected — needless coupling; per principle P9.
- **Consequences:** Some fixture content may exist in two crates' fixture dirs. Bytes are small; acceptable.

---

## Open Questions

Carried forward from PRD §10 plus architecture-specific items. Defaults applied where the architecture commits to a path.

- **Q1 (PRD §10 Q1):** SS-1 v1 raw-root handler — compiled-but-Unimplemented (ADR-010 default) vs deleted. *Architecture default applied*; revisit if a downstream integrator surfaces.
- **Q2 (PRD §10 Q2):** DVT-1 per-CN audit column — audit-only suffices vs operators rely on per-CN watermark. *Architecture default: audit-only* (ADR-004); `slashing::audit` module records every `(pubkey, cn, outcome)` tuple.
- **Q3 (PRD §10 Q3):** Production on-disk slashing DBs exist — confirm before M1 ships so ADR-004 migration is validated against a real captured fixture.
- **Q4 (PRD §10 Q4):** D-3 gate centralisation in `crates/signer` — *decided: yes* (ADR-001).
- **Q5 (PRD §10 Q5):** `--password-dir` semantics — *architecture default: per-keystore* `<dir>/<pubkey>.txt` (PRD Assumption #5).
- **Q6 (PRD §10 Q6):** P2 inclusion vs deferral — *architecture default: all P2 fixes ship in the same release as P0+P1 unless individually deferred with rationale*.
- **Q7 (NEW from Research §00 R2):** B-1/T-1 / L-9 actual landed state — must run `cargo test -- --ignored` before writing the RED test for B-1/T-1. Architecture unchanged either way; only test order changes.
- **Q8 (NEW):** Should `crates/rvc` orchestrator be split (duty-orchestrator vs keymanager-adapters vs slot-loop)? *Out of scope per PRD §2; surfaced as a follow-on risk in the Risks table.*
- **Q9 (NEW):** Should the `SigningGate` sub-responsibilities (per-validator mutex map, slashing stage, doppelganger gate, BLS dispatch, audit log) be extracted into smaller crates post-remediation? *Out of scope; sub-modules within `crates/signer` are the natural extraction seams.*

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Slashing DB migration corrupts a production DB | Low | Catastrophic | Captured pre-migration fixture in `slashing/tests/migration_v1_to_v2.rs`; release notes mandate backup; idempotent + transactional; refuses to run twice. Row-pair resolution table is the explicit policy. |
| `ForwardWindowMachine` introduces startup-time delay for managed validators (~12 min mainnet) | High (intended) | Medium (operator-visible) | Documented in release notes (PRD §12); behavior already documented in existing `keymanager-api/src/gate.rs`. |
| `SigningGate` centralisation increases mean signing latency | Low | Low | Per-validator mutex map preserved; added per-sign work is one `HashMap::get` on `ForwardWindowMachine` — negligible against ~1 ms BLS sign. Metrics `rvc_signing_duration_seconds` already wired. Benchmark target: p99 sign latency must not regress >5% vs baseline. |
| Per-validator async lock contention at high validator counts | Medium | Medium | The lock map is per-pubkey; concurrent signs for different pubkeys are independent. Within a pubkey, serialisation is required for TOCTOU safety. Operators running >1000 validators should monitor `rvc_signer_slashing_tx_hold_duration_ms` p99. |
| `net-policy` as a new crate inflates workspace `Cargo.toml` and compile time | Low | Low | ~400 LoC; tree-shaking and incremental compile keep cost minimal. |
| `eth-types::tree_hash_utils` rewrite breaks an unrelated consumer | Medium | High | Spec-vector fixtures cross-check against Lighthouse/Lodestar; full existing test suite remains the RED→GREEN gate. |
| KM-1 fail-closed DELETE breaks an operator workflow that relied on partial-success | Low | Medium | Per PRD Assumption #9: simpler abort-on-error preferred. Release notes call this out. |
| ADR-001 centralised gate requires touching every signing call site | Medium | High effort | Pre-work: grep `CompositeSigner::sign`, `crypto::sign`, `Signer::sign` before the GREEN commit; migrate in one PR per crate with a checklist. The enumeration test catches misses. |
| DVT-1 schema migration breaks a multi-tenant operator's audit story | Low | Medium | Audit column preserved; `slashing::audit` API exposes per-CN history; release notes guide operators. |
| `bin/rvc-signer` v1 raw-root removal breaks an unknown integrator | Low | Medium | Per PRD Assumption #4: no production consumer assumed; release notes call out the removal; insecure-gate opt-in documented. |
| Two-layer defense (orchestrator fast-path + SignerService authoritative gate) disagrees if future contributor edits one but not the other | Medium | Medium | Both consume the same `SigningEnablement` trait via `Arc<dyn SigningEnablement>`; impossible to point at different state. The orchestrator fast-path is a `==` check against the same trait method the gate calls. |
| Centralised gate bypassed by a future contributor adding a new sign method | Medium | High | `signer-registry` enumeration test fails the build if a handler is added without a `const _: () = ...;` marker proving `SigningGate` routing. PR template + CI lint is a follow-up. |
| Per-finding RED-first discipline erodes if a fix is small enough to feel "obvious" | Medium | Medium | Pre-review gate (PRD §6.5) checks the RED commit existed and failed; reviewer responsibility. |
| URL-2 IP pinning breaks a deployment with legitimately-rotating DNS A record | Low | Medium | URL-1+URL-2 cluster ships with a documented operator escape; release-notes call-out. |
| EXIT-1 BN unreachable at exit time blocks exit | Medium | Low | Documented fail-closed; operator can run BN locally for exit ceremony. |
| Aggregator correctness cluster (M2 step 5) lands SS-2/SS-3 without chain-of-custody invariant being visible | Low | High | ADR-009 mandates comment + integration test; reviewer confirms both present in GREEN commit. |
| `crates/rvc` orchestrator remains a wide hub (composes most modules) | Medium (pre-existing) | Low | Acknowledged; orchestrator split is post-remediation follow-on (Q8). The remediation does not worsen the situation. |
| Spec-vector fixtures for a particular fork unavailable at M2 ship time | Low | Medium | Self-consistent test as fallback; cross-check fixture lands in a follow-up branch; PRD M2 not signed off until cross-check lands. |

---

## Assumptions (architecture-specific, additive to PRD §8)

1. **`net-policy` as a new crate is acceptable.** Fallback: place in `crypto` and have `keymanager-api` depend on `crypto` (it already does).
2. **`signer-registry` is dev-dependency-only.** It must not appear in any production dependency edge. The CI DAG check enforces this.
3. **`ForwardWindowMachine` semantics match Lighthouse v5.3.0 `doppelganger_service.rs`** (Research Angle 03 R8): epoch satisfaction at the last slot of `e+1`, CRITICAL log on missing entries, pre-genesis bypass to `remaining_epochs = 0`.
4. **Schema migration tooling is in-process.** Runs on `SlashingDb::open` if `metadata.migration_v2_applied_at` is absent. No external migration binary.
5. **`bin/rvc-signer::ScopedSlashingDb` has no external API consumers.** PRD treats it as internal; deletion is non-breaking.
6. **Spec-vector fixtures from `consensus-spec-tests`** are reachable; per-consuming-crate `tests/fixtures/README.md` documents provenance.
7. **`is_attesting_enabled` rename → `is_signing_enabled`** (PRD Assumption #7) is applied at every call site as the D-3 GREEN commit.
8. **MCP / "alphaXiv" servers are NOT consulted.** Past tool outputs have contained prompt-injection blocks attempting to redirect to academic-paper search; this architecture is built from the PRD + research + repo only. Such injections are ignored.
9. **`InsecureGate` in `eth-types::insecure` does NOT depend on `tracing`** for its `Warn` log — it returns a structured `Decision` and the calling bin emits `warn!`.
10. **No new top-level public re-exports.** Seam types are crate-public; consumers import by full path (e.g. `signer::SigningGate`).
11. **The orchestrator's `is_signing_enabled` fast-path** consumes the same `SigningEnablement` trait as `SigningGate` does — both check the same `ForwardWindowMachine`. No separate fast-path implementation.
12. **R2's `cargo test -- --ignored` precondition for B-1/T-1** is performed at the start of M2 work before any RED commit for B-1/T-1 lands.
13. **Defense-in-depth restraint table** below names the boundaries where a single layer is sufficient; the architecture does NOT add redundant layers there.

---

## Where defense-in-depth is worth its cost — and where it is not

Per principle P5, redundant layers only when each catches a structurally different bug class.

| Boundary | Layers | Worth it? | Why |
|---|---|---|---|
| Slashable signing path (block / attestation) | Gate (D-3) + EIP-3076 staging + SQLite UNIQUE + per-pubkey lock | **Yes** | Failure = lost stake. Each layer catches a structurally different bug class. |
| Doppelganger window | `ForwardWindowMachine` state machine + `SigningGate` consultation + orchestrator fast-path skip | **Yes** | D-3 showed that a single layer was bypassed by 3-of-4 signing paths. Two layers + central gate fixes the structural issue. |
| Key-confidentiality on DELETE | Atomic `export_interchange` + handler-side ordering (export-then-delete) | **Yes** | KM-1's silent fail-open was exactly the case where two independent layers would have caught it. |
| SSRF / DNS rebinding | URL deny-list + IP pin + re-validation on every connection | **Yes** | URL-1 alone or URL-2 alone is insufficient. |
| BN trust boundary (`execution_optimistic`) | Per-BN tier + per-response check | **Yes** | BN-1 showed single-layer-only (tier) silently accepted optimistic responses. |
| DVT threshold partial | mTLS + share-pubkey verify + pinned share_index + index ≠ 0 + pubkey-scoped slashing | **Yes** | Each layer independently motivated by a finding. |
| Sync-committee message signing (not slashable) | Single layer (gate consultation) | **No additional layer** | Sync-committee not slashable on mainnet (EIP-7657 Stagnant; Research Angle 02). |
| Voluntary exit | Single layer (gate + EIP-7044 fork-version cap + EXIT-1 BN cross-check) | **No additional layer** | Not slashable. The three above are independent checks, not duplicate layers. |
| RANDAO reveal | Single layer (gate) | **No additional layer** | Not slashable. |
| Builder registration | Single layer (cadence + gate; no slashing) | **No additional layer** | Not slashable. BLD-1 is correctness, not safety. |

If EIP-7657 ever moves out of "Stagnant", the sync-committee row gains a slashing DB layer; the `SigningGate::sign_sync_committee_message` API is already shaped to accept a `PubkeyScopedDb` if needed.

---

## Architecture Quality Checklist

- [x] **No circular dependencies between modules.** Verified by the level-graded dependency table; every arrow goes higher-level → lower-level. Refused edges enumerated. `tests/architecture_no_cycles.rs` mechanically asserts.
- [x] **Each module has a single, clear responsibility describable in one sentence.** Module Overview table.
- [x] **No shared databases.** `slashing.sqlite` is owned by exactly one crate (`slashing`) per process. The signer crate consults the DB *through the `PubkeyScopedDb` API*; `slashing` owns the schema and migration. The fact that the DB is consulted by both signer (via the API) and slashing (its owner) is internal-only — no other crate touches the file. Doppelganger reads `slashing` via the `SlashingDbReader` trait, not the DB directly.
- [x] **All inter-module communication goes through defined interfaces.** Traits: `SigningEnablement`, `LivenessChecker`, `SlashingDbReader`, `ValidatorSigner`, `FailClosedDefault`. No backdoor imports.
- [x] **Every module can be tested in isolation with mocked dependencies.** `signer::SigningGate` against mock `SigningEnablement`; `doppelganger::ForwardWindowMachine` against mock `LivenessChecker`; `slashing::InterchangeImporter` against fixture JSON; `net-policy::validate_url` against parameterised cases.
- [x] **Cross-cutting concerns are standardised.** Auth (`auth.rs`), logging (`tracing` spans on every gate method), errors (`thiserror` per crate; `FailClosedDefault` trait), config (`eth-types::insecure::InsecureGate`).
- [x] **Failure modes are defined.** Every seam's section lists failure modes; PRD §6.3 fail-closed is the cross-cutting rule.
- [x] **Service extraction path is clear.** Replaced by the M1/M2/M3 Rollout & Sequencing per task brief; new seams' extraction-readiness tabulated.
- [x] **Data flow is traceable.** Five diagrams cover slashable signing, keymanager import, fail-closed DELETE, block proposal, voluntary exit.
- [x] **Module count is justified.** Two new crates (`net-policy` justified per ADR-002; `signer-registry` dev-only). One *avoided* new crate (`InsecureGate` moved inside `eth-types` per ADR-003 surgical override). No tiny one-helper-per-crate anti-pattern.
- [x] **Each finding maps to the smallest possible edit set.** Max blast radius column in Module Overview; compact entries table for single-file fixes.
- [x] **Shared-helper introductions are explicitly justified.** Thirteen ADRs.
- [x] **PRD §7.1 clusters reflected.** Rollout & Sequencing per-milestone branch tables.
- [x] **Rollout keyed to PRD milestones M1-M3.** Yes, with per-branch ordering and per-cluster shared pre-work.

---

## Mapping: PRD Finding → Seam → Owning Crate → Test File

| Finding | Seam | Owning crate | Test file |
|---|---|---|---|
| SS-1 | InsecureGate-gated legacy v1 + `signer-registry` enumeration | `bin/rvc-signer` + `eth-types::insecure` | `bin/rvc-signer/tests/v1_unregistered.rs`, `bin/rvc-signer/tests/signing_path_enumeration.rs` |
| E-1 | `container_tree_hash_root` + `BodyHashRoot` | `eth-types` | `eth-types/tests/spec_vector_block.rs` |
| E-2 | `bitlist_tree_hash_root<N>` | `eth-types` | `eth-types/tests/spec_vector_bitlist.rs` |
| B-1/T-1 | `encode_signed_block_contents` | `eth-types::ssz_helpers` + `block-service` | `block-service/tests/publish_signed_block_contents.rs` |
| KG-1 | `compute_domain` with GENESIS_FORK_VERSION | `bin/rvc-keygen` | `bin/rvc-keygen/tests/bls_to_execution_genesis_version.rs` |
| SS-2 / SS-3 | `SigningGate::sign_aggregate_and_proof` (no DB consult; ADR-009) | `signer` | `signer/tests/gate_aggregate_no_slashing_db.rs`, `signer/tests/chain_of_custody_aggregate.rs` |
| DVT-1 | `PubkeyScopedDb` + schema migration | `slashing` | `slashing/tests/pubkey_scope.rs`, `slashing/tests/migration_v1_to_v2.rs`, `bin/rvc-signer/tests/dvt_pubkey_scope.rs` |
| D-1 | `ForwardWindowMachine` | `doppelganger` | `doppelganger/tests/forward_window_satisfaction.rs` |
| D-2 | `LivenessChecker` fail-closed | `doppelganger` | `doppelganger/tests/forward_window_missing_liveness.rs` |
| D-3 | `SigningGate` + `SigningEnablement` | `signer` + `doppelganger` | `signer/tests/gate_*_doppelganger_blocked.rs` |
| KM-1 | Fail-closed DELETE + atomic export contract (ADR-008) | `keymanager-api` + `slashing` | `keymanager-api/tests/delete_export_failure_aborts.rs`, `slashing/tests/export_interchange_atomic.rs` |
| KM-2 | `ForwardWindowMachine::cancel` (single impl) | `doppelganger` | `keymanager-api/tests/concurrent_delete_reimport.rs` |
| KM-3 | `InsecureGate` | `eth-types::insecure` + `bin/rvc` | `bin/rvc/tests/keymanager_non_loopback_refuses.rs` |
| BN-1 | `bn-manager::tier()` + per-response gate | `bn-manager` + `crates/rvc` | `bn-manager/tests/optimistic_unsynced.rs`, `crates/rvc/tests/orchestrator_rejects_optimistic.rs` |
| BN-2 | First-poll fail-closed | `bn-manager` | `bn-manager/tests/startup_window.rs` |
| DT-1 | `update_validator_indices` | `duty-tracker` | `duty-tracker/tests/runtime_index_update.rs` |
| S-2 | Wired `pubkey_map` + `key_gen_tx` | `crates/rvc` + `bin/rvc` | `crates/rvc/tests/keymanager_import_wires_orchestrator.rs` |
| SSE-1 | Reconnect-creates-channel | `bn-manager` | `bn-manager/tests/sse_resumes_after_callback_panic.rs` |
| S-5 | `head_root` fallback | `crates/rvc::orchestrator::sync_committee` | `crates/rvc/tests/sync_committee_head_root_fallback.rs` |
| KS-1 | Effective-cost gate at decrypt | `crypto::keystore` + `keymanager-api` | `keymanager-api/tests/keystore_oversized_params_rejected.rs` |
| URL-1 | `net-policy::deny_list` | `net-policy` | `net-policy/tests/deny_list_*.rs` |
| URL-2 | `net-policy::PinnedResolver` | `net-policy` | `net-policy/tests/rebinding_recheck.rs` |
| GVR-1 | `eth-types::canonical::parse_gvr_hex` + slashing import | `eth-types` + `slashing` | `eth-types/tests/canonical_helpers.rs`, `slashing/tests/interchange_import.rs` |
| IMP-1 | `InterchangeImporter` | `slashing` | `slashing/tests/interchange_import.rs` |
| CN-1 | `PubkeyScopedDb` + schema migration (with DVT-1) | `slashing` | `slashing/tests/pubkey_scope.rs`, `bin/rvc-signer/tests/cn_pubkey_scope.rs` |
| C-1 | `borrow_and_update` | `crates/rvc::orchestrator::coordinator` | `crates/rvc/tests/coordinator_key_gen_consume.rs` |
| L-1 | `net-policy::validate_url` (mixed-case scheme) | `net-policy` | `net-policy/tests/mixed_case_scheme.rs` |
| L-2 | `eth-types::canonical::parse_pubkey_hex` | `eth-types` | `eth-types/tests/canonical_helpers.rs` |
| L-3 | `slashing::SlashingDb::pinned_gvr` (zeros → None) | `slashing` | `slashing/tests/all_zeros_gvr.rs` |
| L-4 | `validate_attestation_data` on aggregation path | `crates/rvc::orchestrator::aggregation` | `crates/rvc/tests/aggregation_validates_bn_response.rs` |
| L-9 | (closed with B-1/T-1) | `block-service` | un-ignored existing tests |
| S-3 | `ForwardWindowMachine::register` always called | `doppelganger` + `bin/rvc` | `doppelganger/tests/forward_window_pre_genesis.rs` |
| KG-2 | hard-error on self-verify failure | `bin/rvc-keygen` | `bin/rvc-keygen/tests/self_verify_hard_error.rs` |
| KG-3 | dir mode 0700 | `bin/rvc-keygen` | `bin/rvc-keygen/tests/dir_mode_0700.rs` |
| VS-1 | fsync parent dir | `validator-store` | `validator-store/tests/persist_fsync_parent.rs` |
| BLD-1 | TTL refresh | `builder` | `builder/tests/registration_ttl_refresh.rs` |
| SIG-1 | `--password-dir` per-keystore | `bin/rvc-signer` + `eth-types::insecure` | `bin/rvc-signer/tests/password_dir.rs` |
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
| Info-1 | delete duplicate EIP-3076 paths | `slashing` | `slashing/tests/no_duplicate_safe_to_*.rs` |
| Info-2 | drop or assert per-row GVR column | `slashing` | `slashing/tests/per_row_gvr.rs` |
| Info-3 | macOS / proc parsing | `crates/rvc::monitoring` | `crates/rvc/tests/rss_parsing.rs` |
| Info-4 | boundary hex validation | `beacon` + `eth-types::canonical` | `beacon/tests/boundary_hex_validation.rs` |
| Info-5 | dead API delete; GCP zeroize; metrics bind error; env-mutex | `beacon`, `secret-provider`, `bin/rvc`, `crypto` | individual tests in each crate |

---

## Final correspondence to PRD acceptance criteria

| PRD §4 metric | Architectural support |
|---|---|
| **M1** (all 46 findings closed RED+GREEN) | Per-finding RED→GREEN tests in the crate of the fix; tracker file. |
| **M2** (block proposal succeeds for all forks) | Spec vectors (E-1, B-1/T-1) in `crates/eth-types/tests/fixtures/` and `crates/block-service/tests/fixtures/`. |
| **M3** (aggregator real-committee `aggregation_bits`) | `crates/eth-types/tests/fixtures/aggregate_and_proof_real_committee.ssz` (E-2); SS-2/3 fix in `crates/signer`. |
| **M4** (no signing path bypasses EIP-3076) | `crates/signer-registry` (dev-only) + enumeration test in `bin/rvc-signer/tests/`; ADR-010. |
| **M5** (cargo {build,test,clippy,fmt} green) | Cross-cutting standard; no new external deps. |
| **M6** (doppelganger window at every signing entry point) | `signer::SigningGate` consults `ForwardWindowMachine` at every `sign_*`; ADR-001. |
| **M7** (runtime keymanager import wired end-to-end) | Data flow diagram + DT-1 + S-2 + C-1 + KM-2 wiring; `crates/rvc/tests/keymanager_import_wires_orchestrator.rs`. |
| **M8** (P0/P1 closed before release) | PRD §11 milestones M1/M2 maps to the Rollout & Sequencing tables. |

---

## Summary

The final architecture replaces 46 individually-located findings with **eight cross-cutting seams** owned by clearly-identified crates, plus four targeted defense-in-depth layers where each layer catches a structurally different bug class:

**Seams (one correct implementation each):**

1. `signer::SigningGate` — the only path that produces a slashable signature.
2. `doppelganger::ForwardWindowMachine` — the only source of truth for "is this validator allowed to sign?"
3. `slashing::PubkeyScopedDb` + `InterchangeImporter` + schema migration — pubkey-keyed slashing with CN as audit-only.
4. `eth-types::canonical` — the only hex/GVR/pubkey/signing-root parsers.
5. `eth-types::tree_hash_utils` — spec-correct `Bitlist[N]` (const-generic) + `Container` helpers with compile-time enforcement.
6. `eth-types::insecure::InsecureGate` — the only `Refuse | Warn | Allow` decision (inline module, not a new crate).
7. `net-policy` (new crate) — the only SSRF deny-list + IP pinning + DNS-rebinding gate.
8. `telemetry::redact_endpoint` — the only redaction helper.

**Defense-in-depth layers (independently-failing):**

- Slashable signing: gate + EIP-3076 staging + SQLite UNIQUE + per-pubkey lock.
- Doppelganger: state machine + gate consultation + orchestrator fast-path (same trait).
- DELETE key: atomic `export_interchange` contract + handler-side ordering.
- BN trust boundary: per-BN tier + per-response `execution_optimistic` check.

**Structural-correctness guarantees:**

- The orchestrator structurally cannot bypass `SigningGate` (no `crypto::Signer` handle held outside `crates/signer`); the `signer-registry` enumeration test enforces this.
- Call sites cannot mis-tree-hash a Bitlist (const-generic refuses to compile a wrong bound).
- Two CNs cannot double-sign the same key (the schema's UNIQUE index forbids it).
- A missing liveness entry cannot fail-open (the state machine has no transition for it).
- The `tests/architecture_no_cycles.rs` mechanical check forbids circular dependencies.

**Surgical discipline:** Two new crates (`net-policy`, `signer-registry`), one *avoided* new crate (`InsecureGate` inlined into `eth-types`), zero new external dependencies. Per-finding max-blast-radius justified inline; ADRs document every shared-helper introduction. The rollout is keyed to PRD M1/M2/M3 with per-branch ordering.
