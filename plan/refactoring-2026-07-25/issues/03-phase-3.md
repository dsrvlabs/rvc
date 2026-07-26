# Refactoring Phase 3 — Foundations (Themes C + G quick wins)

> Build the shared homes — logging, network presets, fork identity, proto, wire contract, pubkey
> parsing, GVR — so Phase 4's consolidations have somewhere to point. Wide but mechanical.
>
> Authoritative inputs: [`../refactoring-plan.md`](../refactoring-plan.md) §3 Themes C/G,
> §4 Phase 3, §6 Validation Strategy; [`../refactoring-findings.json`](../refactoring-findings.json)
> F16, F32, F39, F45, F53, F73, F74, F82, F85, F86, F88, F89, F90, F99, F105, F106, F107, F110, F116.
> All file:line references re-verified against HEAD `develop` (`a7f8cdf`) on 2026-07-25.

## Phase Overview

- **Goal:** every duplicated foundation in the workspace gets exactly one home *below* the crates
  that duplicate it. After this phase: `crypto` is no longer the workspace logging commons; network
  presets and fork identity live once in `eth-types`; the Web3Signer wire contract and the signer
  proto are each compiled/defined once; pubkey-hex parsing has one engine; GVR is typed in slashing.
- **Issue count:** 20 issues, 51 points.
- **Estimated duration:** ~26–51 days single-stream; ~14–26 days with 2 developers.
- **Entry criteria:** Phase 2 complete and merged (B10 v1-proto retirement is a hard prerequisite for
  RF3-14; B1 sync-service shrink pairs with RF3-19); workspace green on the standing invariant
  (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo nextest run --workspace`, `cargo test -p rvc-architecture-tests`).
- **Exit criteria (phase gate):**
  - [ ] Workspace green on the standing invariant.
  - [ ] `crates/architecture-tests` green with `rvc-observability` added to `ZERO_OUT_EDGE_IF_PRESENT`
        and its own `crypto` dev-dependency replaced.
  - [ ] `beacon`, `bn-manager`, `validator-store`, `propagator`, `keymanager-api` no longer declare a
        production `crypto` dependency; `cargo tree -p rvc-beacon` shows no `blst`/`scrypt`/`reqwest`
        arriving via `crypto`.
  - [ ] The mainnet GVR literal appears exactly once in non-test workspace source.
  - [ ] `tonic_build` compiles `signer.v2.proto` exactly once in the workspace.
  - [ ] Web3Signer serde round-trip conformance test green against recorded production bodies.
  - [ ] `cargo machete` (or `cargo udeps`) clean for the crates listed in RF3-06.

## Assumptions (recorded; not separately approved — autonomous run)

- **A1 — New crate naming follows the workspace convention.** Directory `crates/<name>`, package
  `rvc-<name>`, workspace alias `<name>` (`Cargo.toml:15-35`). The three new crates are
  `crates/observability` (`rvc-observability`), `crates/signer-proto` (`rvc-signer-proto`),
  `crates/web3signer-wire` (`rvc-web3signer-wire`).
- **A2 — `web3signer-wire` is its own crate, not a module inside `signer-proto`.** The plan offers
  both. `signer-proto` pulls `tonic`/`prost`; folding the HTTP wire types there would drag gRPC into
  `crypto`'s dependency tree, which is the exact failure mode C1 exists to undo.
- **A3 — The unified pubkey-hex policy is the superset already implemented in
  `crypto::hex::strip_prefix_strict`:** strip at most one leading `0x` *or* `0X`, reject a doubled
  prefix, accept mixed-case hex. `eth_types::canonical::pubkey_hex::strip_prefix`
  (`crates/eth-types/src/canonical/pubkey_hex.rs:57-68`) currently refuses to strip `0X`, while
  `bin/rvc-signer/src/http_api/pubkey.rs:47-56` accepts it under FR-18 and
  `crypto::pubkey::CanonicalPubkey` accepts it in its own doctest. Unifying **down** to the stricter
  policy would be an API regression on a documented requirement, so canonical is widened.
- **A4 — Electra SSZ dispatch resolves as "explicit typed rejection of Electra-shaped buffers",
  not "blanket reject `fork_id >= 5`".** See RF3-09's rationale: a blanket reject breaks the live
  mainnet Electra aggregate path.
- **A5 — `crypto`'s dead `test-utils` feature is deleted, not populated.** Populating it is H2's job
  in Phase 6; carrying a dead flag through three more phases is the worse option.

## Citation corrections (found while grounding — the plan/findings are stale here)

1. **F107 / C2 "different network sets" is stale.** `crates/rvc/src/config/network.rs:17-43` now
   carries all four networks (mainnet, hoodi, holesky, sepolia) plus `Custom`, not "mainnet/hoodi
   only". The duplication and the format split (bytes vs hex strings) are real; the coverage gap is
   not. C2 is correspondingly a little smaller than billed.
2. **C4's acceptance criterion "one `tonic_build` invocation in the workspace" is not achievable.**
   `crates/rvc/build.rs:7` compiles `proto/duty_tracker.proto`, an unrelated service. The criterion
   is restated as "`signer.v2.proto` is compiled exactly once".
3. **C8 does not need a new newtype.** `eth_types::canonical::gvr_hex::{GvrHex, parse_gvr_hex}`
   already exists (`crates/eth-types/src/canonical/gvr_hex.rs:11-61`) with exactly the semantics C8
   describes. C8 becomes *adoption*, which is why it splits into two 3-point issues rather than a
   build-plus-adopt sequence.

Also confirmed rather than corrected: C1's "~20 dependents" is 16 distinct crates/bins referencing
`crypto::logging` across 69 call sites; `crates/telemetry`'s two hits are comments only (no dep), and
`crates/architecture-tests` holds `crypto` as a **dev**-dependency, so neither is a production edge.

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| RF3-01 | Create `crates/observability`; move logging/hex/pubkey behind a `crypto` facade | 3 | refactor | — | A |
| RF3-02 | Repoint all 16 dependents; drop the crypto edge; delete the facade and `redact_url` | 3 | refactor | RF3-01 | A |
| RF3-03 | `eth_types::networks` preset table + byte/hex cross-check KATs | 2 | refactor | — | B |
| RF3-04 | `KeygenNetwork` and rvc `Network` delegate to the preset table | 2 | refactor | RF3-03 | B |
| RF3-05 | `ForkName` gains `FromStr`/`id()`/`try_from(u32)`/`body_layout()`; `ForkSchedule::entries()` | 3 | refactor | — | B |
| RF3-06 | Workspace dependency hygiene (unused deps, dead feature, workspace pins) | 2 | chore | RF3-02 | A |
| RF3-07 | Repoint `body_fork_layout` + `validate_fork_id` onto `ForkName` | 2 | refactor | RF3-05 | B |
| RF3-08 | grpc-signer carries `ForkName` in `SignContext` (no silent `_ => Deneb`) | 3 | bugfix | RF3-05 | B |
| RF3-09 | `ssz_helpers` rejects Electra-shaped attestations with a typed error | 3 | bugfix | RF3-05 | B |
| RF3-10 | Create `crates/web3signer-wire`: one type set, both derives, frozen round-trip fixtures | 3 | refactor | — | A |
| RF3-11 | `crypto::remote_signer` consumes the wire crate; split into `wire.rs` + `client.rs` | 3 | refactor | RF3-10, RF3-02 | A |
| RF3-12 | rvc-signer `http_api` consumes the wire crate; `request.rs` twins deleted | 2 | refactor | RF3-10 | A |
| RF3-13 | `eth_types::canonical` becomes the single hex decode engine (`0X` accepted) | 2 | refactor | — | B |
| RF3-14 | Create `crates/signer-proto`; both consumers use it | 3 | refactor | B10 (P2) | A |
| RF3-15 | Route the 6 hand-rolled pubkey parse sites through `parse_pubkey_hex` | 2 | refactor | RF3-13 | B |
| RF3-16 | `SyncCommitteeDuty.pubkey` becomes `[u8; 48]` | 2 | refactor | RF3-13 | B |
| RF3-17 | Typed GVR at the slashing metadata boundary, with upgrade compatibility | 3 | refactor | — | A |
| RF3-18 | Typed GVR through rows, import/export, and interchange comparison | 3 | bugfix | RF3-17 | A |
| RF3-19 | G5+G6: eth-types fixtures behind `test-fixtures`; constant-echo tests replaced | 3 | chore | — | B |
| RF3-20 | G7: sync-committee constants + aggregator predicate move to eth-types | 2 | refactor | B1 (P2) | B |

**Total: 20 issues, 51 points.** RF3-19 deliberately carries both G5 and G6 (same crate, conflicting
diffs if split), which is why the plan's eleven Theme-C/G items expand to twenty issues rather than
twenty-two.

## Execution Plan

Two streams with disjoint file ownership.

- **Stream A (25 pts)** owns `crates/crypto`, `crates/observability`, `crates/web3signer-wire`,
  `crates/signer-proto`, `crates/slashing`, and `bin/rvc-signer/src/{lib.rs,http_api/request.rs}`.
  Order: `RF3-01 → RF3-02` first (it is a workspace-wide `use`-path sweep and must not race anything
  else), then `RF3-06` (Cargo.toml sweep, same reason — it shares `bn-manager` and `keymanager-api`
  manifests with RF3-02), then `RF3-10 → RF3-11 → RF3-12`, with `RF3-14` and `RF3-17 → RF3-18`
  slotted around them.
- **Stream B (26 pts)** owns `crates/eth-types`, `bin/rvc-keygen`, `crates/rvc/src/config/network.rs`,
  `crates/grpc-signer/src/client.rs`, and the pubkey parse sites. Order:
  `RF3-05 → {RF3-07, RF3-08, RF3-09}` and `RF3-13 → {RF3-15, RF3-16}` in parallel with
  `RF3-03 → RF3-04`; `RF3-19` and `RF3-20` are unblocked filler.

**One coordination point:** RF3-02 rewrites `use crypto::logging::…` lines in 16 crates including
several Stream B files. Land RF3-01+RF3-02 in the first two days of the phase and hold Stream B to
`crates/eth-types`-internal work (RF3-05, RF3-13, RF3-19) until RF3-02 merges. After that the streams
never touch the same file.

## Dependency Map

```text
Stream A:
  RF3-01 ──▶ RF3-02 ──┬──▶ RF3-06
                      └──▶ RF3-11 ──▶ (Phase 4 D1/D2)
  RF3-10 ──────────┬─────▶ RF3-11
                   └─────▶ RF3-12
  RF3-17 ──▶ RF3-18
  B10 (Phase 2) ──▶ RF3-14 ──▶ (Phase 4 D4/D5)

Stream B:
  RF3-03 ──▶ RF3-04
  RF3-05 ──┬──▶ RF3-07
           ├──▶ RF3-08
           └──▶ RF3-09
  RF3-13 ──┬──▶ RF3-15
           └──▶ RF3-16
  B1 (Phase 2) ──▶ RF3-20
  RF3-19  (no deps)
```

**Critical path:** `RF3-01 → RF3-02 → RF3-11` (9 pts, with RF3-10 as a parallel prerequisite of
RF3-11) in Stream A; `RF3-05 → RF3-08` (6 pts) in Stream B. Neither chain is the binding
constraint — Stream B's total serial length (26 pts) sets the phase duration.

## Phase Risk Flags

- **RF3-02 is a merge-conflict magnet** (69 call sites, 16 crates). Land it as a single
  `use`-path-only PR early; nothing else in the phase should be in flight against those files.
- **RF3-08 and RF3-18 are deliberate behavior changes on non-mainnet / on upgrade.** Both need
  release notes. RF3-18 in particular can make an *existing* node fail to start if the metadata
  encoding flips without a compatibility read path — that is why RF3-17 exists as a separate,
  earlier issue.
- **RF3-09 must not blanket-reject `fork_id >= 5`.** The live VC path
  (`crates/grpc-signer/src/client.rs:216-232`) sends `fork_id = 5` on mainnet Electra with a
  *pre-Electra-shaped* buffer. Rejecting the id would break mainnet aggregation.
- **RF3-10/11/12 are contract-frozen.** The client (`Serialize`) and server (`Deserialize`) type sets
  are not symmetric today — the server has an extra `AGGREGATE_AND_PROOF_V2` variant. Merging them
  must not silently add or remove a wire variant on either side.
- **Feature unification in RF3-14.** `bin/rvc-signer` builds the proto server (client only under the
  `dvt` feature) while `crates/grpc-signer` builds both. The shared crate needs additive
  `server`/`client` features; when both crates are in one build graph cargo unifies them, which is
  correct but grows codegen — check compile-time impact before merging.

---

## Issues

### Issue RF3-01: Create `crates/observability` and move logging/hex/pubkey behind a `crypto` facade

- **Points:** 3
- **Type:** refactor
- **Scope:** ~1.5–2 days
- **Stream:** A
- **Plan item:** C1 · **Findings:** F39, F105
- **Blocked by:** none · **Blocks:** RF3-02, RF3-11

**What / why.** `crates/crypto` is the workspace's logging commons as well as its BLS/KDF/HTTP crate.
`crypto::logging` (638 lines) is referenced by 16 crates and binaries across 69 sites, which forces
`beacon` — the low-level HTTP client — to pull `blst`, `scrypt`, `reqwest`, `rayon`, `bip39`,
`num-bigint` and friends in production just to format a redacted URL
(`crates/beacon/src/client.rs:7`, `crates/beacon/Cargo.toml:14`). This issue creates the new leaf
crate and moves the code; it changes no call sites, because `crypto` re-exports the moved modules as
a temporary facade. Splitting it this way is what lets RF3-02 be a pure `use`-path diff.

**Files to touch (verified).**
- New `crates/observability/{Cargo.toml,src/lib.rs}`; `Cargo.toml:14-35` (workspace alias),
  `Cargo.toml:2` (members list).
- Move verbatim: `crates/crypto/src/logging.rs` (638 lines), `crates/crypto/src/hex.rs` (148),
  `crates/crypto/src/pubkey.rs` (189). All three are self-contained — their only non-`std` imports
  are `thiserror` (`hex.rs:25`) and `tracing`/`uuid` inside `logging.rs`, plus one intra-move
  reference `crate::hex::strip_prefix_strict` at `logging.rs:19`. No `eth-types` use, so the new
  crate genuinely has zero workspace-internal out-edges.
- `crates/crypto/src/lib.rs` — `pub use observability::{logging, hex, pubkey};` facade, marked
  `#[doc(hidden)]` with a "removed in RF3-02" note.
- `crates/architecture-tests/tests/architecture_no_cycles.rs:58-59` — add `"rvc-observability"` to
  `ZERO_OUT_EDGE_IF_PRESENT`.
- `crates/architecture-tests/tests/no_rvc_prefix.rs:19-21` — the `EXCLUDE` list names
  `"crates/crypto/src/logging.rs"` by path; update it to the new location or the gate silently stops
  excluding the conformance fixture and starts failing.

**Implementation sketch.**
1. `git mv` the three files so the diff registers as a move.
2. New crate `Cargo.toml`: `tracing`, `uuid`, `thiserror`, `url`, `hex` — nothing internal.
3. Re-export from `crypto` so the workspace still compiles unchanged.
4. Update the two architecture-test tables.

**Acceptance criteria.**
- [ ] `crates/observability` exists with `logging`, `hex`, `pubkey` and no workspace-internal
      dependency (`cargo tree -p rvc-observability --edges normal` shows no `rvc-*`).
- [ ] `rvc-observability` is pinned in `ZERO_OUT_EDGE_IF_PRESENT` and the acyclicity gate is green.
- [ ] `no_rvc_prefix` gate green with the corrected `EXCLUDE` path.
- [ ] Zero call sites changed outside the moved files, the two Cargo.tomls, and the two gate tables.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `observability_crate_has_no_workspace_internal_out_edges` — the new crate is added
  to `ZERO_OUT_EDGE_IF_PRESENT` *before* the crate exists is a no-op (the list is
  "if present"), so the meaningful RED is `no_rvc_prefix`'s `EXCLUDE` path: point it at
  `crates/observability/src/logging.rs` before the move and watch the gate fail on the stale
  `crates/crypto/src/logging.rs`, then move the file to green it.
- Existing `field_name_conformance` Gate-5 suite must stay green unchanged (it reads the registry
  through the facade in this issue).
- `redaction_conformance_matches_pre_move` — snapshot `RedactedUrl`, `TruncatedPubkey`,
  `TruncatedRoot` output for a fixed input set, asserted identical to the current literals.

**Risks.** The move itself is safe; the trap is the two hard-coded *paths* in the architecture-test
tables, which the compiler cannot catch.

---

### Issue RF3-02: Repoint all 16 dependents; drop the crypto edge; delete the facade and `redact_url`

- **Points:** 3
- **Type:** refactor
- **Scope:** ~1.5–2 days
- **Stream:** A
- **Plan item:** C1 · **Findings:** F39, F105
- **Blocked by:** RF3-01 · **Blocks:** RF3-11

**What / why.** This is the payoff PR and, by design, contains nothing but `use`-path changes,
`Cargo.toml` edits, and two deletions. Verified consumer counts (`crypto::logging` references):
`signer` 13, `architecture-tests` 13 (dev-dep), `rvc` 9, `bin/rvc-signer` 7, `doppelganger` 6,
`bn-manager` 4, `slashing` 3, `secret-provider` 2, `validator-store`/`propagator`/`keymanager-api`/
`grpc-signer`/`block-service`/`beacon`/`bin/rvc-keygen`/`bin/rvc` 1 each.

**Crates that lose their `crypto` dependency entirely** (verified: their *only* `crypto::` reference
is `logging`, or `logging` + `CanonicalPubkey` which also moves): `beacon` (1 ref),
`bn-manager` (4), `validator-store` (1), `propagator` (1), `keymanager-api` (1),
`slashing` (3 logging + 4 `CanonicalPubkey`), plus `architecture-tests` (dev-dep, 13).
Crates that keep `crypto` for real crypto: `doppelganger` (`PublicKey`/`SecretKey`),
`secret-provider` (`KeyManager`/`Keystore`/`SecretKey`), `block-service` (`PublicKey`), `signer`,
`rvc`, and the three binaries.

**Files to touch (verified).**
- 69 `use crypto::logging::…` / `crypto::pubkey::CanonicalPubkey` sites across the crates above.
- `Cargo.toml` of `beacon` (`:14`), `bn-manager`, `validator-store`, `propagator`, `keymanager-api`,
  `slashing`, `architecture-tests` (`crypto.workspace = true` in `[dev-dependencies]`) — replace
  `crypto` with `observability`.
- `crates/crypto/src/lib.rs` — delete the facade re-exports added in RF3-01.
- `crates/crypto/src/remote_signer.rs:54-64` — delete the private `redact_url`, replacing its two
  call sites with `observability::logging::RedactedUrl`.

**Acceptance criteria.**
- [x] No `crypto::logging`, `crypto::hex`, or `crypto::pubkey` path remains in the workspace
      (`rg 'crypto::(logging|hex|pubkey)'` returns nothing).
- [x] The seven crates listed above have no `crypto` entry in any dependency table.
- [x] `cargo tree -p rvc-beacon --edges normal | rg 'blst|scrypt|bip39'` is empty.
- [x] `redact_url` is gone from `remote_signer.rs`; `RedactedUrl` is the only redaction path.
- [x] Diff contains no logic change (reviewable as import rewrites + Cargo edits + one deletion).
- [x] `field_name_conformance` Gate-5 and `no_rvc_prefix` both green.

**TDD test plan.**
- **RED first:** `no_crypto_logging_paths_remain` — a source-scanning test in `architecture-tests`
  (same hand-rolled matcher style as `no_rvc_prefix.rs`, no new dependency) asserting zero
  `crypto::logging` occurrences under `crates/*/src` and `bin/*/src`. It fails on the pre-repoint
  tree; it is the gate that makes the sweep complete rather than approximate.
- `beacon_has_no_crypto_production_edge` — assert the edge map built by
  `architecture_no_cycles.rs::build_edge_map` has no `rvc-beacon -> rvc-crypto` entry.
- `redact_url_behavior_unchanged` — the URL-redaction cases previously covered by the private
  `redact_url` tests, re-asserted against `RedactedUrl` before the deletion.

**Risks.** Wide diff, but compiler-verified end to end. The one non-compiler-checked change is
`redact_url` → `RedactedUrl`: confirm the two implementations agree on the no-credentials and
unparseable-URL cases before deleting (they differ in structure — `redact_url` returns `String`
eagerly, `RedactedUrl` is a lazy `Display`).

---

### Issue RF3-03: `eth_types::networks` preset table + byte/hex cross-check KATs

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** B
- **Plan item:** C2 · **Findings:** F16, F107
- **Blocked by:** none · **Blocks:** RF3-04

**What / why.** Genesis fork version, GVR, Capella fork version and genesis time are defined twice in
incompatible formats: `bin/rvc-keygen/src/network.rs:12-54` as `[u8; 4]`/`[u8; 32]` byte arrays,
`crates/rvc/src/config/network.rs:17-52` as `&'static str` hex plus `genesis_time`. Both hand-roll
case-insensitive name parsing with different error text. A drift between them produces invalid
signatures or deposits — the bug class commit `0fa0a42` already patched once. `eth-types` is the
natural home: it is a zero-out-edge sink already depended on by both binaries.

Per §6, this issue only *adds* the table and pins it; consumers move in RF3-04.

**Files to touch.**
- New `crates/eth-types/src/networks.rs`; `crates/eth-types/src/lib.rs:5-21` (module + re-export).
- Read-only sources of truth: `bin/rvc-keygen/src/network.rs:12-54`,
  `crates/rvc/src/config/network.rs:17-52`.

**Implementation sketch.**
`pub struct NetworkPreset { name, genesis_fork_version: [u8;4], genesis_validators_root: Root,
capella_fork_version: [u8;4], genesis_time: u64 }` with `const MAINNET/HOODI/HOLESKY/SEPOLIA`,
`ALL: &[&NetworkPreset]`, `from_name(&str) -> Option<&'static NetworkPreset>` (lowercase-insensitive),
plus `genesis_validators_root_hex()` / `genesis_fork_version_hex()` accessors that format the byte
form so no hex literal is ever written twice. `Custom` is *not* modelled here — it is a
`crates/rvc`-side `Option`-returning concern and stays there (RF3-04).

**Acceptance criteria.**
- [ ] All four networks present with all five fields; no consumer changed in this issue.
- [ ] Every hex accessor is derived from the byte constant (no second literal in the file).
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_preset_hex_accessor_matches_keygen_byte_literal` — for each network, assert
  `NetworkPreset::genesis_validators_root()` equals the byte array copied verbatim from
  `bin/rvc-keygen/src/network.rs`, and `…_hex()` equals the string copied verbatim from
  `crates/rvc/src/config/network.rs`. This is the KAT pin required by §6.4; it fails until the table
  is populated correctly and is the only defense against a transcription typo.
- `test_genesis_time_matches_rvc_config_literals` (four values).
- `test_from_name_is_case_insensitive_and_rejects_unknown`.
- `test_all_networks_have_distinct_gvr`.

**Risks.** Pure transcription. The KAT test *is* the mitigation; write it by copy-paste from both
existing files, never by retyping.

---

### Issue RF3-04: `KeygenNetwork` and rvc `Network` delegate to the preset table

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** B
- **Plan item:** C2 · **Findings:** F16, F107
- **Blocked by:** RF3-03 · **Blocks:** none

**What / why.** Collapse the two copies onto RF3-03's table so adding a network is one table row.

**Files to touch (verified).**
- `bin/rvc-keygen/src/network.rs:4-61` — `KeygenNetwork` becomes a thin wrapper (or a type alias for
  `&'static NetworkPreset`); `from_name` (`:57`) delegates; `exit_fork_schedule` (`:68-`) keeps its
  EIP-7044 Capella-cap logic but reads versions from the preset.
- `crates/rvc/src/config/network.rs:17-84` — `genesis_time`, `genesis_validators_root`,
  `FromStr`, `Display` delegate; `Network::Custom` keeps returning `None`.
- `crates/rvc/src/config/builder.rs:1063` — the inline mainnet GVR string literal becomes
  `NetworkPreset::MAINNET.genesis_validators_root_hex()`.
- `crates/rvc/src/startup.rs:604-662` — five test literals; leave as test-side KAT anchors (they are
  the independent check that delegation did not change the value) but add a comment saying so.

**Acceptance criteria.**
- [ ] `rg '4b363db94e286120' crates bin --glob '!*test*'` matches exactly one non-test line
      (the `eth-types` table).
- [ ] Both binaries' network resolution is byte-identical to before (proven by the tests below).
- [ ] `Network::Custom` still yields `None` for `genesis_time`/`genesis_validators_root`.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_keygen_network_values_unchanged_after_delegation` — assert
  `from_name("mainnet")?.genesis_validators_root` equals the byte literal that used to live in
  `network.rs`, for all four networks and all three byte fields. Fails while the delegation is
  half-wired.
- `test_rvc_network_hex_unchanged_after_delegation` (four networks × two accessors).
- `test_builder_default_gvr_is_mainnet_preset`.
- `test_unknown_network_error_text_preserved_for_both_binaries` — the two error strings differ today;
  pick one, assert it, and note the CLI-visible change in the PR body.

**Risks.** The error-text unification is user-visible in `rvc-keygen`'s CLI output. Low impact, but
mention it in the PR; do not silently change the exit code.

---

### Issue RF3-05: `ForkName` gains `FromStr`/`id()`/`try_from(u32)`/`body_layout()`; `ForkSchedule::entries()`

- **Points:** 3
- **Type:** refactor
- **Scope:** ~1.5–2 days
- **Stream:** B
- **Plan item:** C3 · **Findings:** F82, F89
- **Blocked by:** none · **Blocks:** RF3-07, RF3-08, RF3-09

**What / why.** Four parallel fork encodings exist with no conversion point (F82). Shipping a fork
today means coordinated edits to `ForkName`'s enum + `as_ref` + `from_epoch` + `fork_version` +
`activation_epoch`, `ForkSchedule`'s 13 flat fields, `body_fork_layout`'s string match,
`validate_fork_id`'s bound, and grpc-signer's byte match — five sites in three crates that the
compiler does not link. This issue builds the single source of truth inside `eth-types`; the three
follow-on issues repoint each consumer.

**Files to touch (verified).**
- `crates/eth-types/src/fork.rs` — `ForkName` enum `:4-12`, `AsRef<str>` `:31-42`, `from_epoch`
  `:46-67` (descending if-else chain + a `tracing::trace!` at `:66` inside a pure lookup),
  `fork_version` `:69-80`, `activation_epoch` `:82-93`, `previous_fork` `:95-102`;
  `ForkSchedule`'s 13 fields `:14-28`.
- `crates/eth-types/src/lib.rs:55` — extend the `fork::{…}` re-export.
- `crates/eth-types/src/block.rs:44-51` — `BodyForkLayout` is the return type of `body_layout()`;
  read-only here.

**Implementation sketch.**
1. `ForkSchedule::entries(&self) -> [(ForkName, Epoch, Version); 7]` in ascending activation order.
2. Reimplement `from_epoch` / `fork_version` / `activation_epoch` / `previous_fork` as iterations
   over `entries()`. `from_epoch` scans in reverse for the first entry with `activation <= epoch`.
3. `impl FromStr for ForkName` (inverse of `AsRef<str>`, exhaustive so a new variant is a compile
   error), `fn id(self) -> u32` and `impl TryFrom<u32> for ForkName`, `fn body_layout(self) ->
   Option<BodyForkLayout>` (`Deneb => Deneb`, `Electra | Fulu => Electra`, else `None` — matching
   `block.rs:56-62` exactly).
4. Move the `tracing::trace!` out of `from_epoch` per F89; drop `tracing` from `eth-types` only if
   `insecure.rs` is already gone (B6, Phase 2) — otherwise leave the dependency and note it.

**Acceptance criteria.**
- [ ] `from_epoch`, `fork_version`, `activation_epoch`, `previous_fork` all read `entries()`; no
      per-fork match arm remains outside `entries()`, `AsRef<str>`, `FromStr`, `id()`, `body_layout()`.
- [ ] `ForkName::from_str(name.as_ref()) == Ok(name)` for all seven variants (round-trip).
- [ ] `ForkName::try_from(name.id()) == Ok(name)` for all seven; `try_from(7)` is an error.
- [ ] `from_epoch` is free of `tracing` calls.
- [ ] No consumer changed in this issue; standing invariant green.

**TDD test plan.**
- **RED first:** `test_from_epoch_table_matches_legacy_if_else_for_every_boundary` — a table of
  (epoch, expected `ForkName`) covering each activation epoch and `activation - 1` across a
  realistic schedule *and* a degenerate schedule where several forks activate at the same epoch
  (which the descending if-else resolves to the latest — the table iteration must agree). Written
  against the current behavior first, so it fails the moment `entries()` reorders anything.
- `test_fork_name_str_roundtrip_all_variants`
- `test_fork_name_id_roundtrip_all_variants` / `test_fork_id_7_is_rejected`
- `test_body_layout_matches_body_fork_layout_string_mapping` — assert
  `ForkName::from_str(s)?.body_layout() == body_fork_layout(s)` for `"deneb"`, `"electra"`, `"fulu"`,
  and a pre-Deneb name.
- `test_fork_version_and_activation_epoch_unchanged_for_all_seven` against the existing
  `test_schedule()` fixture (`fork.rs:105-`).

**Risks.** Consensus-adjacent. The degenerate-schedule case is the real trap: `rvc-keygen`'s
`exit_fork_schedule` (`bin/rvc-keygen/src/network.rs:68-`) deliberately sets several forks to epoch 0
and post-Capella ones to `u64::MAX`, so `entries()` must resolve ties the same way the descending
chain does (latest wins). That schedule is a required case in the RED test.

---

### Issue RF3-06: Workspace dependency hygiene

- **Points:** 2
- **Type:** chore
- **Scope:** ~1 day
- **Stream:** A
- **Plan item:** C7 · **Finding:** F110
- **Blocked by:** RF3-02 (shares the `bn-manager` and `keymanager-api` manifests) · **Blocks:** none

**What / why.** Four dependencies are provably unused, one feature flag is dead but requested by
three crates, and several version pins bypass `[workspace.dependencies]`. Independently verified at
HEAD: `crypto`'s `ssz_derive` and `tree_hash_derive` (0 source references each),
`metrics`' `serde_json` (0), `grpc-signer`'s `thiserror` (0 — it reuses `crypto::SigningError`).

**Files to touch (verified).**
- `crates/crypto/Cargo.toml:25,31` (`ssz_derive`, `tree_hash_derive`), `:41` (`test-utils = []`).
- `crates/metrics/Cargo.toml:14` (`serde_json`), `crates/grpc-signer/Cargo.toml:15` (`thiserror`).
- Dead-feature consumers: `crates/signer/Cargo.toml:29`, `crates/rvc/Cargo.toml:55`,
  `crates/doppelganger/Cargo.toml:23`, `crates/block-service/Cargo.toml:26` — all request
  `crypto = { features = ["test-utils"] }` against an empty flag.
- Feature-name split: `crates/signer/Cargo.toml:13` declares `test-helpers`, consumed at
  `crates/rvc/Cargo.toml:59`. Rename to `test-utils` (matching `crypto` and `secret-provider`) and
  update the `#[cfg(feature = "test-helpers")]` attributes in `crates/signer/src`.
- Workspace promotion: `crates/bn-manager/Cargo.toml:17` (`futures = "0.3"`),
  `crates/grpc-signer/Cargo.toml:23` + `bin/rvc-signer/Cargo.toml:109` (`rcgen = "0.13"`),
  `crates/keymanager-api/Cargo.toml:34-35` + `bin/rvc-signer/Cargo.toml:80-81,124` (`hyper`,
  `http-body-util`), `bin/rvc/Cargo.toml:61,63` (`toml`, `libc` — both already workspace deps).
- Leave alone: the `rustls`/`tokio-rustls` pins in `bin/rvc-signer` are deliberate and documented
  (`Cargo.toml:50-58`).

**Acceptance criteria.**
- [x] The four unused dependencies are gone; `cargo machete` (or `cargo udeps --workspace`) reports
      clean for `crypto`, `metrics`, `grpc-signer`, `bn-manager`.
- [x] `crypto`'s `test-utils = []` and its three downstream feature requests are deleted (per
      assumption A5 — H2 reintroduces a real one in Phase 6 if needed).
- [x] `signer`'s feature is named `test-utils`; no `test-helpers` string remains in any Cargo.toml
      or `cfg` attribute.
- [x] `futures`, `rcgen`, `hyper`, `http-body-util` are declared in `[workspace.dependencies]` and
      consumed via `.workspace = true`; `bin/rvc-signer`'s prod (`server,http1`) vs dev (`client`)
      `hyper` feature split is preserved.
- [x] `Cargo.lock` shows no new or changed resolved versions.

**TDD test plan.**
- **RED first:** `cargo machete` (or `cargo udeps`) run recorded in the PR showing the four findings
  before and zero after — the tool output is the failing "test".
- `cargo tree --duplicates` before/after diff attached, proving the workspace promotion did not
  introduce a second copy of `hyper` or `rcgen`.
- `cargo nextest run --workspace --all-features` green (catches a `cfg(feature = "test-helpers")`
  attribute missed by the rename).

**Risks.** Feature renames are not compiler-checked in the *removal* direction: a stale
`#[cfg(feature = "test-helpers")]` block silently compiles out and takes its tests with it. Run the
workspace test count before and after and explain any delta.

---

### Issue RF3-07: Repoint `body_fork_layout` and `validate_fork_id` onto `ForkName`

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** B
- **Plan item:** C3 · **Findings:** F82, F85
- **Blocked by:** RF3-05 · **Blocks:** none

**What / why.** Two of the four fork encodings become delegates, so a new fork stops requiring an
edit to a string match and a magic-number bound.

**Files to touch (verified).**
- `crates/eth-types/src/block.rs:56-62` — `body_fork_layout` becomes
  `ForkName::from_str(consensus_version).ok().and_then(ForkName::body_layout)`. Keep the function
  and its signature: it is publicly re-exported (`lib.rs:27`) and used by beacon-response handling.
- `crates/eth-types/src/ssz_helpers.rs:237-244` — `validate_fork_id`'s `fork_id > 6` magic bound
  becomes `ForkName::try_from(fork_id)`, mapping the error to the existing
  `SszDecodeError::UnknownForkId`.
- `crates/eth-types/src/ssz_helpers.rs:1-6` — the module doc re-documents the id list; replace with a
  pointer to `ForkName::id`.

**Acceptance criteria.**
- [ ] `body_fork_layout` contains no string literal fork name.
- [ ] `validate_fork_id` contains no numeric bound.
- [ ] Behavior identical: same `Some`/`None` and same `Ok`/`Err` for every input the old code saw.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_body_fork_layout_unchanged_for_all_known_and_unknown_versions` — a table over
  `"phase0" … "fulu"` plus `"electra "` (trailing space), `"Deneb"` (wrong case), `""`, and a
  garbage string, pinning the *current* `Option<BodyForkLayout>` for each. `FromStr` derived from
  `AsRef<str>` is exact-match and case-sensitive, matching today's behavior — this test is what
  proves the delegation did not accidentally become lenient.
- `test_validate_fork_id_accepts_0_through_6_rejects_7_and_max`.

**Risks.** `body_fork_layout` currently returns `None` for anything unrecognised, including case
variants. `FromStr` must preserve that exactly — no `to_lowercase()`. The RED table is the guard.

---

### Issue RF3-08: grpc-signer carries `ForkName` in `SignContext` (no silent `_ => Deneb`)

- **Points:** 3
- **Type:** bugfix
- **Scope:** ~1.5–2 days
- **Stream:** B
- **Plan item:** C3 · **Findings:** F74, F82
- **Blocked by:** RF3-05 · **Blocks:** none

**What / why.** `GrpcRemoteSigner::fork_id` (`crates/grpc-signer/src/client.rs:216-233`) re-derives a
fork id by matching hardcoded *mainnet* version bytes and falls through to `_ => 4 // default to
Deneb` for everything else, with the comment "Testnet and devnet fork versions all map to Deneb or
latest". `fork_id` drives the SSZ encoding sent to the remote signer, so on Hoodi, Holesky, Sepolia
or any custom network every fork — Electra included — is tagged Deneb. `eth-types` already owns the
version→fork mapping via `ForkSchedule`, so this is duplicated consensus knowledge with strictly
weaker coverage.

**Files to touch (verified).**
- `crates/grpc-signer/src/client.rs:216-233` (`fork_id`), `:203-214` (`make_fork_info`), and the
  `SignContext` construction sites that reach it.
- `crates/crypto/src/signer_trait.rs` — `SignContext` definition (add the resolved fork or the
  schedule). Confirm whether `ForkInfo` already travels with enough context before widening the
  struct.

**Implementation sketch.**
Resolve `ForkName` where the schedule is known (the caller already has a `ForkSchedule` to compute
the domain) and carry it on `SignContext`; `fork_id()` becomes `ctx.fork_name.id()`. If threading the
resolved name proves invasive, the fallback within budget is
`schedule.entries().find(|(_, _, v)| *v == ctx.fork_info.current_version).map(|(f, _, _)| f.id())`
with an explicit `warn!` + typed error (never a silent `4`) when the version is unknown.

**Acceptance criteria.**
- [ ] No hardcoded mainnet version bytes remain in `grpc-signer`.
- [ ] A non-mainnet Electra fork version yields `id() == 5`, not `4`.
- [ ] An unresolvable fork version produces a `warn!`-logged, typed outcome — never a silent Deneb
      default.
- [ ] Mainnet behavior byte-identical for all seven forks.
- [ ] Release note: non-mainnet SSZ fork tagging changes. Standing invariant green.

**TDD test plan.**
- **RED first:** `test_hoodi_electra_fork_version_maps_to_electra_not_deneb` — build a `SignContext`
  with Hoodi's Electra fork version and assert the derived id is `5`. Fails today (returns `4`);
  this is the finding, expressed as a test.
- `test_mainnet_fork_ids_unchanged_for_all_seven_versions` (the KAT that pins the working path).
- `test_unknown_fork_version_is_warned_not_silently_defaulted`.
- `test_sign_context_carries_resolved_fork_name` (wiring assertion).

**Risks.** Behavior change on every non-mainnet deployment: an operator on Hoodi who is today
receiving Deneb-tagged aggregates will start receiving Electra-tagged ones. That is the fix, but it
changes bytes on the wire to the remote signer — flag it prominently and verify against a real
`rvc-signer` in the integration harness before merge.

---

### Issue RF3-09: `ssz_helpers` rejects Electra-shaped attestations with a typed error

- **Points:** 3
- **Type:** bugfix
- **Scope:** ~1.5–2 days
- **Stream:** B
- **Plan item:** C3 · **Finding:** F85
- **Blocked by:** RF3-05 · **Blocks:** none

**What / why.** The `ssz_helpers` module doc promises fork dispatch; nothing dispatches. All four
encoders take `_fork_id` and ignore it (`ssz_helpers.rs:52`), and `decode_attestation_ssz`
(`:128-140`) accepts `fork_id` 5/6 while always decoding the pre-Electra three-field layout.
`ElectraAttestation` (`crates/eth-types/src/aggregation.rs:100-108`, four fields, adds
`committee_bits`) has no SSZ codec at all, so the rvc-signer aggregate path
(`bin/rvc-signer/src/service.rs:750`) would **misparse** an Electra-shaped aggregate rather than
reject it.

**Why "reject Electra-shaped buffers" and not "reject `fork_id >= 5`"** (assumption A4): the live VC
path sends `fork_id = 5` on mainnet Electra — `crates/grpc-signer/src/client.rs:216-233` maps
`[0x05,0,0,0] => 5` — while encoding the *pre-Electra* `Attestation` shape via
`encode_attestation_ssz`. Blanket-rejecting the id would break mainnet aggregation. The correct
minimal fix is a structural check: keep decoding the legacy layout, and return a typed error when the
buffer is not that layout. Implementing a real `ElectraAttestation` SSZ codec is explicitly **out of
scope** here — it is a feature that belongs with D4's transport unification in Phase 4, and it would
change `decode_attestation_ssz`'s return type into an enum, rippling through rvc-signer's
`AggregateAndProof` construction.

**Files to touch (verified).**
- `crates/eth-types/src/ssz_helpers.rs:128-160` (`decode_attestation_ssz`), `:29-42`
  (`SszDecodeError` — add a variant), `:1-20` (module doc: say what `fork_id` actually means now).
- `bin/rvc-signer/src/service.rs:750` — the call site; map the new error through the existing
  `ssz_err` helper so it surfaces as a clean `invalid_argument` rather than a garbage aggregate.
- Read-only: `crates/eth-types/src/aggregation.rs:100-124` for the Electra field layout.

**Implementation sketch.**
The legacy layout is `offset_data(4) | data(128) | offset_sig(4) | aggregation_bits | signature`
(`ssz_helpers.rs:110-124`). Validate the two offsets are internally consistent and that the trailing
regions have the expected sizes; on mismatch — which is what an `ElectraAttestation` encoding
produces, since it carries a fourth `committee_bits` region — return
`SszDecodeError::ElectraLayoutUnsupported { fork_id }` instead of a structurally-plausible-but-wrong
`Attestation`. Document the parameter's real contract in the module doc.

**Acceptance criteria.**
- [x] An Electra-shaped attestation buffer decoded at any `fork_id` returns the new typed error, not
      an `Ok(Attestation)`.
- [x] A legacy-shaped buffer at `fork_id = 5` still decodes successfully (the live mainnet path).
- [x] The module doc no longer claims dispatch it does not do.
- [x] `bin/rvc-signer/src/service.rs:750` surfaces the error as a client error, not a panic or a
      wrong signature.
- [x] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_electra_shaped_aggregate_is_not_silently_misparsed` — construct an
  `ElectraAttestation`, SSZ-encode it by hand (four-field container with `committee_bits`), pass it
  to `decode_attestation_ssz(bytes, 5)`, and assert the typed error. Today this returns `Ok(...)`
  with garbage, which is exactly the finding.
- `test_legacy_attestation_at_fork_id_5_still_decodes` — the regression guard for mainnet.
- `test_legacy_attestation_roundtrip_all_fork_ids_0_to_6`.
- `test_service_aggregate_path_returns_invalid_argument_for_electra_buffer` (rvc-signer side).

**Risks.** The structural check must not reject any buffer the VC legitimately sends. Derive the
check from `encode_attestation_ssz`'s own layout and round-trip every existing test vector through it
before merging. If a legitimate buffer is ambiguous between the two layouts, prefer accepting (log a
warning) over rejecting — a false rejection is a missed duty.

---

### Issue RF3-10: Create `crates/web3signer-wire` — one type set, both derives, frozen round-trip fixtures

- **Points:** 3
- **Type:** refactor
- **Scope:** ~1.5–2 days
- **Stream:** A
- **Plan item:** C5 · **Findings:** F45, F106
- **Blocked by:** none · **Blocks:** RF3-11, RF3-12

**What / why.** The Web3Signer HTTP contract is defined twice. `crates/crypto/src/remote_signer.rs`
holds the `Serialize` side (`WireForkInfo` `:137`, `Web3SignerPayload` `:192` with ten type-tagged
variants, `Web3SignerSignRequest` `:245`) with the literal comment "Shape mirrors
`bin/rvc-signer/src/http_api/request.rs` (read-only reference)"; `bin/rvc-signer/src/http_api/request.rs`
holds an independent `Deserialize` twin (`WireForkInfo` `:30`, `SignPayload` `:80`). Both duplicate
the `type_name()` discriminator match (`remote_signer.rs:224-247` vs `request.rs:139-158`). Nothing
but a comment keeps them in sync, and commit `424a1a7` ("send Web3Signer-compliant client request
bodies") shows the contract has already drifted once.

**The two sets are not symmetric.** The server has an eleventh variant the client lacks:
`AGGREGATE_AND_PROOF_V2` (`ElectraAggregateAndProof`, `request.rs:120-133`), documented as FROZEN by
Issue 5.3/FR-31. The unified type set must keep all eleven and must not add a variant to the client's
*serialize* capability without a deliberate decision — record which side each variant is reachable
from in the new crate's module doc.

**Files to touch.**
- New `crates/web3signer-wire/{Cargo.toml,src/lib.rs,src/hex_serde.rs}`; `Cargo.toml` members +
  alias.
- Read-only sources: `crates/crypto/src/remote_signer.rs:130-282`,
  `bin/rvc-signer/src/http_api/request.rs:26-234`.

**Implementation sketch.**
1. One type set deriving `Serialize + Deserialize`. `eth-types` payload types
   (`AttestationData`, `AggregateAndProof`, `ContributionAndProof`, `SyncCommitteeMessage`,
   `ValidatorRegistrationV1`, `VoluntaryExit`, `ElectraAggregateAndProof`, `Fork`,
   `BeaconBlockHeader`) already carry both derives and are reused verbatim.
2. Merge the serde helpers: `serialize_root_hex`/`serialize_quoted_u64`
   (`remote_signer.rs:275-281`) and `hex32`/`opt_hex32`/`quoted_u64` (`request.rs:180-234`) become
   bidirectional `mod`s usable with `#[serde(with = …)]`.
3. Preserve every server-side leniency exactly: `signingRoot` with `alias = "signing_root"`,
   empty/`"0x"` → `None` (Prysm), `fork_info` optional at the serde layer, unknown `type` fails to
   decode.
4. One `type_name()`.

**Acceptance criteria.**
- [ ] All eleven variants present; each serializes and deserializes.
- [ ] `type_name()` exists once and matches every `#[serde(rename)]` tag.
- [ ] Server leniency preserved (alias, empty-root, optional fork_info, unknown-type rejection).
- [ ] No consumer changed in this issue; the crate depends only on `eth-types`, `serde`, `hex`.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_recorded_production_bodies_roundtrip_byte_identical` — take the recorded JSON
  bodies from the existing suites on **both** sides (`request.rs:236-` decoder fixtures, including
  `fork_info_json()` at `:239`, and the `electra_v2_frozen_fixture` referenced from `routes.rs`, plus
  the client-side serialization assertions in `remote_signer.rs`'s test module at `:767+`), decode
  each with the new type set, re-encode, and assert the JSON value is equal to the input. This is the
  §6.4 contract pin and it fails until every field name, casing and quoting convention matches both
  originals.
- `test_all_eleven_type_discriminators_roundtrip`
- `test_signing_root_alias_and_empty_are_accepted` (`signingRoot`, `signing_root`, `""`, `"0x"`)
- `test_unknown_type_fails_to_decode`
- `test_validator_registration_omits_fork_info`

**Risks.** Highest-consequence issue in the phase after RF3-18: a silent field-name or quoting change
breaks the rvc ↔ rvc-signer HTTP path at runtime with no compile error. The frozen-fixture test is
the only real defense — build it from recorded bodies, never from the new types' own output.

---

### Issue RF3-11: `crypto::remote_signer` consumes the wire crate; split into `wire.rs` + `client.rs`

- **Points:** 3
- **Type:** refactor
- **Scope:** ~1.5–2 days
- **Stream:** A
- **Plan item:** C5 · **Findings:** F45, F106
- **Blocked by:** RF3-10, RF3-02 · **Blocks:** Phase 4 D1/D2

**What / why.** Delete the client's half of the duplicated contract and break up the 1,551-line
`remote_signer.rs`, which currently mixes URL gating, config, wire types, eleven request builders,
the HTTP client, `Signer` + `TypedSigner` impls, and ~800 lines of tests.

**Files to touch (verified).**
- `crates/crypto/src/remote_signer.rs` — delete the `Serialize` twins at `:130-282`; keep the eleven
  request builders and move them plus the config into `wire.rs`; the `reqwest` client and the trait
  impls go to `client.rs`. The `~800`-line test module (`:767-1551`) splits to follow its subject.
- `crates/crypto/src/lib.rs` — module declarations and re-exports (keep the public path
  `crypto::remote_signer::…` stable so Phase 4 does not have to chase it).
- `crates/crypto/Cargo.toml` — add `web3signer-wire`.

**Acceptance criteria.**
- [ ] `remote_signer.rs` no longer defines any wire type; all come from `web3signer-wire`.
- [ ] The file is split into `wire.rs` and `client.rs`, each under ~800 lines including tests.
- [ ] The public API path used by `crates/signer` and `crates/rvc` is unchanged (no consumer edits).
- [ ] Serialized request bodies byte-identical to pre-split (test below).
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_request_bodies_byte_identical_after_wire_extraction` — snapshot the serialized
  JSON for one request of each of the ten client-reachable types *before* the change (recording the
  current output as fixture files), then assert equality after. Fails if any serde attribute shifted
  during the merge.
- Existing `remote_signer` test module passes unchanged after relocation (test count diff = 0, or
  explained).
- `test_wire_and_client_modules_have_no_circular_use` (compile-level; the split is only real if
  `wire.rs` does not import `client.rs`).

**Risks.** Depends on RF3-02 having already removed the `redact_url` duplicate from this file —
otherwise the split has to carry it. Sequence accordingly.

---

### Issue RF3-12: rvc-signer `http_api` consumes the wire crate; `request.rs` twins deleted

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** A
- **Plan item:** C5 · **Findings:** F45, F106
- **Blocked by:** RF3-10 · **Blocks:** none

**What / why.** The server half of the same deletion. After this, the contract exists once and
drift is a compile error rather than a runtime 400.

**Files to touch (verified).**
- `bin/rvc-signer/src/http_api/request.rs` (387 lines) — delete `WireForkInfo` `:30`,
  `BeaconBlockEnvelope` `:38`, the four payload wrappers `:48-72`, `SignPayload` `:80-133`,
  `SignRequest` `:162-178`, `type_name()` `:139-158`, and the three serde helper mods `:180-234`;
  re-export from `web3signer-wire`. The `#[cfg(test)]` decoder suite `:236-387` stays and becomes the
  server-side conformance check against the shared types.
- `bin/rvc-signer/src/http_api/dispatch.rs`, `routes.rs` — `use` paths only; the dispatcher's
  per-type `fork_info` enforcement and the `AGGREGATE_AND_PROOF_V2` handling are unchanged.
- `bin/rvc-signer/Cargo.toml` — add `web3signer-wire`.

**Acceptance criteria.**
- [ ] `request.rs` defines no wire type (it may remain as a re-export + test module, or be deleted
      with its tests moved).
- [ ] Every existing `http_api` decoder test passes unmodified except for import paths.
- [ ] The `electra_v2_frozen_fixture` (FR-31) still decodes and produces the same signing root.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_lighthouse_and_prysm_bodies_still_decode` — the existing recorded bodies from
  `request.rs`'s test module, run against the shared types before the local definitions are deleted.
  It fails while any field name or leniency differs, which is the whole risk.
- `test_electra_v2_frozen_fixture_signing_root_unchanged`
- `test_unknown_type_still_yields_400`

**Risks.** Low, given RF3-10's fixtures. The one thing to watch is `pub(super)` visibility on
`type_name()` (`request.rs:139`) — it is used by the audit path; the shared version must be `pub`.

---

### Issue RF3-13: `eth_types::canonical` becomes the single hex decode engine

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** B
- **Plan item:** C6 · **Findings:** F88, F116
- **Blocked by:** none · **Blocks:** RF3-15, RF3-16

**What / why.** `eth-types` carries two hex stacks with different policies plus a third partial copy:
`hex_fixed`'s `bytes_hex_mod!` macro (`crates/eth-types/src/hex_fixed.rs`, requires `0x`, does not
reject `0x0x`), `canonical::pubkey_hex` (`:57-68`, accepts bare hex, rejects `0x0x`, scrubs raw
characters from error messages), and `serde_signature.rs` (a third decode-and-length-check).
`canonical/mod.rs` says later issues "will migrate existing ad-hoc parsing onto these seams";
adoption stalled at two call sites.

**Policy decision (assumption A3):** widen `canonical::strip_prefix` to accept a single `0X` as well
as `0x`, still rejecting a doubled prefix. This makes canonical a strict superset of every existing
in-tree policy — `crypto::hex::strip_prefix_strict` (moved to `observability` in RF3-01) already
accepts `0X`, `crypto::pubkey::CanonicalPubkey`'s doctest asserts `"0XABCD"` parses, and
`bin/rvc-signer/src/http_api/pubkey.rs:47-56` accepts `0X` under FR-18. Narrowing instead would break
a documented requirement.

**Files to touch (verified).**
- `crates/eth-types/src/canonical/pubkey_hex.rs:57-68` (`strip_prefix`), `:73-90` (`decode_hex`).
- `crates/eth-types/src/hex_fixed.rs` — the macro's `deserialize` delegates to canonical, keeping the
  stricter `0x`-required policy where the Beacon API contract demands it (document which).
- `crates/eth-types/src/serde_signature.rs:16-` — delegate.
- `crates/eth-types/src/canonical/mod.rs:1-43` — close or update the stalled migration note.

**Acceptance criteria.**
- [ ] `canonical` is the only place performing prefix-strip + hex-decode in `eth-types`.
- [ ] `0X`-prefixed input is accepted uniformly; `0x0x`/`0x0X` still rejected as `DoublePrefix`.
- [ ] `hex_fixed`'s API-facing strictness (`0x` required) is preserved and documented as a deliberate
      per-seam policy, not an accident.
- [ ] Error messages still omit the raw offending character (the existing scrubbing behavior).
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_canonical_accepts_uppercase_0x_prefix` — `parse_pubkey_hex("0X" + 96 hex)`
  must succeed. It fails today: `strip_prefix` only recognises a lowercase `0x`, so the `0X` falls
  through to `decode_hex` and surfaces as `InvalidHex`.
- `test_double_prefix_still_rejected_both_cases` (`0x0x`, `0x0X`, `0X0x`)
- `test_hex_fixed_still_requires_0x_prefix`
- `test_error_messages_contain_no_raw_input_characters`
- `test_serde_signature_delegates_and_length_check_unchanged`

**Risks.** Widening acceptance is a behavior change in the permissive direction — it cannot break a
caller that was succeeding, but it can accept input a caller previously rejected. Enumerate the
`hex_fixed` seams that must stay strict in the PR body.

---

### Issue RF3-14: Create `crates/signer-proto`; both consumers use it

- **Points:** 3
- **Type:** refactor
- **Scope:** ~1.5–2 days
- **Stream:** A
- **Plan item:** C4 · **Finding:** F32
- **Blocked by:** **B10 (Phase 2)** · **Blocks:** Phase 4 D4/D5

**What / why.** `bin/rvc-signer/build.rs` and `crates/grpc-signer/build.rs` each run `tonic_build`
over the same protos, producing two structurally-identical-but-distinct Rust type sets. Because
`bin/rvc-signer`'s dev-dependencies pull in `grpc-signer` for integration tests, any end-to-end test
crossing the client/server boundary juggles two `SignRequest` types.

**Hard prerequisite:** B10 must have landed. Both `build.rs` files still compile `signer.proto` (v1)
solely because `GrpcRemoteSigner::connect` uses v1 `ListPublicKeys` — both files say so in comments
(`crates/grpc-signer/build.rs:6-12`). Building the shared crate before v1 is retired means compiling
and re-exporting a v1 surface that is about to be deleted.

**Correction to the plan's acceptance criterion:** "one `tonic_build` invocation in the workspace" is
unachievable — `crates/rvc/build.rs:7` compiles the unrelated `proto/duty_tracker.proto`. The
criterion below is restated for `signer.v2.proto` only.

**Files to touch (verified).**
- New `crates/signer-proto/{Cargo.toml,build.rs,src/lib.rs}` with additive `server` / `client`
  features; `Cargo.toml` members + alias.
- `bin/rvc-signer/build.rs` — delete; `bin/rvc-signer/src/lib.rs:25-31` (`pub mod proto { … }`) —
  re-export from the new crate.
- `crates/grpc-signer/build.rs` — delete; `crates/grpc-signer/src/lib.rs:3-8,26-28` — the `proto`
  module and the `SignerServiceClientV2` / server re-exports repoint.
- `bin/rvc-signer/src/service.rs`, `crates/grpc-signer/src/client.rs` — generated-type import paths.

**Acceptance criteria.**
- [ ] `signer.v2.proto` is compiled exactly once (`rg 'compile_protos' --glob 'build.rs'` shows the
      new crate and `crates/rvc/build.rs`'s duty_tracker only).
- [ ] Both consumers use the same generated types; a cross-crate test can pass a `SignRequest` from
      the client to the server without conversion.
- [ ] `bin/rvc-signer`'s `dvt`-gated client build still works (`--features dvt` and default both
      compile).
- [ ] Compile-time impact measured and recorded (feature unification builds both stubs when both
      crates are in one graph).
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_client_and_server_share_one_sign_request_type` — an integration test that
  constructs a `SignRequest` via `grpc_signer::proto` and passes it directly to the `rvc-signer`
  service handler's request type. It does not compile today (two distinct types), which is the
  finding stated as a test.
- `test_v2_proto_compiled_once` — a build-script-scanning test in `architecture-tests`, same style as
  `no_rvc_prefix.rs`.
- Existing `crates/grpc-signer/tests/proto_v2_contract.rs` passes unchanged.

**Risks.** Cargo feature unification: with both crates in one graph, `server` and `client` are both
on, growing codegen. Also `prost`/`tonic` version alignment must be identical to what both crates
resolve today, or the wire types shift subtly. Check `Cargo.lock` for zero version changes.

---

### Issue RF3-15: Route the hand-rolled pubkey parse sites through `parse_pubkey_hex`

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** B
- **Plan item:** C6 · **Findings:** F73, F116
- **Blocked by:** RF3-13 · **Blocks:** none

**What / why.** Strip-`0x` + `hex::decode` + 48-byte-length-check is hand-rolled in six places while
`eth_types::canonical::parse_pubkey_hex` sits unused. The copies have already diverged: the
keymanager and secret-provider copies accept only lowercase `0x`, while `rvc-signer`'s accepts `0X`
too, and `crates/rvc/src/orchestrator/attestation.rs:602` carries a comment documenting a past bug
caused by exactly this drift.

**Files to touch (verified).**
- `crates/keymanager-api/src/handlers.rs:831-840` (`parse_pubkey`).
- `crates/validator-store/src/store.rs:47-51` (`parse_hex_bytes<N>`) — keep the generic for the
  20-byte fee-recipient case; delegate the 48-byte case.
- `crates/secret-provider/src/key_source_manager.rs:120-126` (inline).
- `crates/secret-provider/src/refresh.rs:78-84` (inline).
- `crates/rvc/src/deletion_denylist.rs:159-171` (`parse_pubkey_line`).
- `bin/rvc-signer/src/http_api/pubkey.rs:47-56` (`parse_pubkey_bytes`) — the `0X`-accepting one; safe
  to migrate only because RF3-13 widened canonical.

**Acceptance criteria.**
- [ ] All six sites call `eth_types::canonical::parse_pubkey_hex`; no local strip+decode+length
      pattern remains at those sites.
- [ ] `0X` prefix and mixed case are accepted uniformly at every site.
- [ ] `rvc-signer`'s FR-18 case-insensitivity behavior is unchanged (still accepts what it accepted).
- [ ] The keymanager and secret-provider sites now accept `0X` — a documented, deliberate widening.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_keymanager_accepts_uppercase_0x_pubkey` — post a `0X`-prefixed pubkey to the
  keymanager parse path and assert success. Fails today (`handlers.rs:832` strips only `0x`), which
  is the drift F73 describes.
- `test_all_parse_sites_agree_on_a_shared_case_table` — one table of inputs (bare, `0x`, `0X`,
  mixed case, `0x0x`, wrong length, non-hex) asserted identical across all six call sites.
- `test_denylist_line_parse_unchanged_for_comments_and_blanks`
- `test_validator_store_20_byte_path_unaffected`

**Risks.** Widening only. The one place to double-check is the deletion denylist: it must keep
treating `#` comments and blank lines as skips (that logic is around, not inside, the parse).

---

### Issue RF3-16: `SyncCommitteeDuty.pubkey` becomes `[u8; 48]`

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** B
- **Plan item:** C6 · **Finding:** F88
- **Blocked by:** RF3-13 · **Blocks:** none

**What / why.** `eth-types` carries three pubkey representations: a validated `[u8; 48]` via
`hex_fixed` (`ProposerDuty`), the `PubkeyHex` newtype (`canonical`), and a completely unvalidated
`pub pubkey: String` on `SyncCommitteeDuty` (`crates/eth-types/src/sync_committee.rs:22`). The
unvalidated one flows straight into duty processing.

**Files to touch (verified).** 35 references across 7 files:
`crates/eth-types/src/sync_committee.rs:21-27`, `crates/beacon/src/types.rs`,
`crates/duty-tracker/src/tracker.rs`, `crates/rvc/src/orchestrator/sync_committee.rs`,
`crates/rvc/src/orchestrator/coordinator.rs`, `crates/sync-service/src/lib.rs`, and two test files
(`crates/rvc/tests/sync_independent_of_attesting.rs`,
`crates/sync-service/tests/per_validator_isolation.rs`).

**Implementation sketch.** Change the field to `[u8; 48]` with the same `bytes_48_hex` serde
`ProposerDuty` already uses, so the JSON wire form is unchanged. Then follow the compiler: every
consumer that did `format!("0x{}", …)` or a hand comparison gets the bytes directly.

**Acceptance criteria.**
- [x] `SyncCommitteeDuty.pubkey` is `[u8; 48]`; JSON serialization/deserialization byte-identical.
- [x] A malformed pubkey in a BN duties response is now a decode error, not a silently-carried string.
- [x] No consumer re-encodes to `String` except at a genuine display/log boundary.
- [x] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_sync_committee_duty_rejects_malformed_pubkey` — deserialize a duties response
  whose `pubkey` is `"0xzz…"` or the wrong length and assert a serde error. Today it deserializes
  happily into a `String`, which is the finding.
- `test_sync_committee_duty_json_wire_form_unchanged` — a recorded BN response decodes and re-encodes
  identically.
- `test_orchestrator_sync_duty_matching_unchanged` — the pubkey-matching logic in
  `orchestrator/sync_committee.rs` produces the same duty set as before.

**Risks.** Compiler-driven, so the surface is bounded, but it does change a public `eth-types` type.
Coordinate with anyone holding a branch that constructs `SyncCommitteeDuty` literals in tests.

---

### Issue RF3-17: Typed GVR at the slashing metadata boundary, with upgrade compatibility

- **Points:** 3
- **Type:** refactor
- **Scope:** ~1.5–2 days
- **Stream:** A
- **Plan item:** C8 · **Finding:** F53
- **Blocked by:** none · **Blocks:** RF3-18

**What / why.** The genesis validators root crosses the slashing API as `&str` in
`set_genesis_validators_root`/`export`/`import` but as `&Root` in `stage_*`/`record_*`, and the
textual forms diverge across three encodings. `crates/rvc/src/startup.rs:115-116` writes metadata in
"lowercase, no `0x` prefix" form; runtime row inserts use `SlashingDb::root_to_hex`
(`crates/slashing/src/db.rs:377-379`), which is `0x`-prefixed lowercase.

**The upgrade hazard that makes this a separate, earlier issue:**
`set_genesis_validators_root` (`db.rs:1804-1826`) compares the stored metadata value to the incoming
string with **raw `!=`**. An existing node has bare-hex metadata on disk. If a release starts passing
the canonical `0x`-prefixed form, that comparison fails and the node exits with
`GenesisValidatorsRootMismatch` — a fail-to-start regression on upgrade, on the safety-critical
path. This issue fixes the comparison *first*, before RF3-18 changes any encoding.

**Note:** C8 does not need a new newtype. `eth_types::canonical::gvr_hex::{GvrHex, parse_gvr_hex}`
(`crates/eth-types/src/canonical/gvr_hex.rs:11-61`) already implements exactly the described
semantics — parse once, `0x`-prefixed lowercase normalised view, rejects double prefix / wrong
length / all-zeros is handled separately in slashing. This is adoption, not construction.

**Files to touch (verified).**
- `crates/slashing/src/db.rs:1798-1826` (`set_genesis_validators_root`), `:385-405`
  (`parse_gvr_hex` — the local copy, which also rejects the all-zeros builder sentinel; preserve that
  check when delegating to `eth-types`), `:407-425` (`read_metadata_gvr`), `:377-379`
  (`root_to_hex`).
- `crates/rvc/src/startup.rs:105-119` — the normalization comment and the call.
- `crates/slashing/Cargo.toml` — the `crypto` → `observability` swap already happened in RF3-02;
  `eth-types` is already a dependency.

**Implementation sketch.** `set_genesis_validators_root` takes `GvrHex` (or `&Root`), reads the
stored value, parses **both** sides to bytes, and compares bytes. On a first-run insert, write the
canonical `0x`-lowercase form. On a match where the stored form is non-canonical, rewrite it to
canonical in the same transaction (idempotent, one-time). Keep the all-zeros rejection.

**Acceptance criteria.**
- [ ] Comparison is byte-based; `0x`-prefixed, bare, and mixed-case stored values all match the same
      chain.
- [ ] An existing DB with bare-hex metadata boots successfully and ends up with canonical metadata.
- [ ] A genuinely different chain still produces `GenesisValidatorsRootMismatch`.
- [ ] All-zeros is still rejected.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_existing_bare_hex_metadata_matches_canonical_prefixed_root` — open a DB whose
  `metadata.genesis_validators_root` is bare lowercase hex (exactly what
  `startup.rs` writes today), then call `set_genesis_validators_root` with the `0x`-prefixed form and
  assert `Ok`. Fails today with `GenesisValidatorsRootMismatch` — this is the upgrade regression,
  caught before it ships.
- `test_metadata_normalised_to_canonical_on_first_match`
- `test_different_chain_still_rejected`
- `test_all_zero_gvr_still_rejected`
- `test_mixed_case_stored_value_matches`

**Risks.** Touches the boot path of the most safety-critical component. The one-time metadata
rewrite must be inside the same transaction as the read, and must never run on a mismatch.

---

### Issue RF3-18: Typed GVR through rows, import/export, and interchange comparison

- **Points:** 3
- **Type:** bugfix
- **Scope:** ~1.5–2 days
- **Stream:** A
- **Plan item:** C8 · **Finding:** F53
- **Blocked by:** RF3-17 · **Blocks:** none

**What / why.** Two live defects follow from the stringly-typed GVR. `import()` compares interchange
metadata by exact string equality (`crates/slashing/src/db.rs:1136-1141`), so a case or `0x`-prefix
difference **spuriously rejects a valid import**. And `import()` writes the caller's raw config string
verbatim into every row (`db.rs:1148`: `let gvr_hex = expected_genesis_validators_root.to_owned()`),
while runtime inserts write `root_to_hex`'s `0x`-prefixed form — so import-written and
runtime-written rows for the same chain can carry different GVR strings. Because the v3 unique
indexes compare GVR as TEXT (`(pubkey, genesis_validators_root, target_epoch)`), those rows **escape
the uniqueness backstop silently**. That is a slashing-protection hole, not just untidiness.

**Files to touch (verified).**
- `crates/slashing/src/db.rs:1130-1160` (`import` metadata comparison + `gvr_hex` assignment),
  `:775, :814, :880, :1235, :1362, :1543` (the six runtime `root_to_hex` sites), and the export path.
- `crates/slashing/src/stage.rs:334, :471` — the two staging call sites that already use
  `root_to_hex`.
- `crates/slashing/src/reader.rs`, `crates/slashing/src/scoped.rs` — signature ripple.
- 85 `genesis_validators_root` references in `db.rs` overall; most are SQL literals unaffected by the
  type change.

**Acceptance criteria.**
- [ ] `import`/`export`/`set_genesis_validators_root` take a typed GVR.
- [ ] Interchange metadata comparison is byte-based: a `0x`-prefixed interchange imports against a
      bare-hex config (and vice versa) without error.
- [ ] Every row written — by import or at runtime — carries the identical canonical encoding, so the
      v3 unique index actually fires across both paths.
- [ ] A row-encoding normalization test proves import-written and runtime-written rows for the same
      chain collide on the unique index.
- [ ] Release note: previously-rejected interchange files now import. Standing invariant green.

**TDD test plan.**
- **RED first:** `test_import_with_0x_prefixed_metadata_against_bare_config_succeeds` — the
  spurious-rejection bug. Fails today at `db.rs:1136`.
- `test_import_and_runtime_rows_share_one_gvr_encoding` — import an attestation for pubkey P at
  target epoch E, then attempt a runtime insert for the same (P, E) and assert the unique index
  rejects it. Today the differing GVR strings let it through, which is the silent-backstop-escape.
- `test_export_roundtrips_through_import`
- `test_existing_rows_with_legacy_encoding_still_readable` (no migration is performed; the read path
  must tolerate what is already on disk)
- Existing slashing conformance + proptest suites (retargeted at the stage path by Phase 1's A2) stay
  green.

**Risks.** DB-visible. The plan states no schema migration is needed (the column stays TEXT), which
holds — but rows already written with a legacy encoding remain, so the *read* path must stay
tolerant even though the *write* path becomes canonical. Do not add a bulk row rewrite in this issue;
if one is wanted, it is a separate, explicitly-versioned migration.

---

### Issue RF3-19: eth-types fixtures behind `test-fixtures`; constant-echo tests replaced

- **Points:** 3
- **Type:** chore
- **Scope:** ~1.5–2 days
- **Stream:** B
- **Plan items:** G5, G6 · **Findings:** F86, F90
- **Blocked by:** none · **Blocks:** none

**What / why.** Two independent eth-types quick wins that touch the same crate, batched to avoid two
conflicting PRs.

*G5:* roughly 300 lines of test fixtures and KAT constants ship in the production library and are
re-exported from `lib.rs` — `external_vector_deneb_body`, `external_vector_electra_body`, their
blinded variants, four block-level builders, `external_vector_execution_payload_header`, and six
`EXTERNAL_*_ROOT_HEX` constants (`crates/eth-types/src/lib.rs:26-45`). Verified: every external
consumer uses them exclusively from `#[cfg(test)]` modules or `tests/` directories — the twelve
consumer files across `crypto`, `beacon`, `block-service`, `grpc-signer`, and `bin/rvc-signer` all
have their first fixture reference *after* their first `#[cfg(test)]`, and
`bin/rvc-signer/src/cross_transport.rs` (which has no inline `cfg(test)`) is declared
`#[cfg(test)] mod cross_transport;` at `bin/rvc-signer/src/lib.rs:12-13`. So no production code
breaks.

*G6:* `crates/eth-types/src/domains.rs:20-82` spends twelve tests re-asserting each `DOMAIN_*`
constant against the same literal written a few lines above; `lib.rs:197-205` and `:336-340` do the
same for `SLOTS_PER_EPOCH`, `SECONDS_PER_SLOT`, and `CONSENSUS_SPEC_VERSION`. These tautologies fail
only if someone edits both sites. The genuinely useful invariants — `test_all_domains_are_unique`
(`domains.rs:84-105`) and the size check (`:107`) — are buried among them.

**Files to touch (verified).**
- `crates/eth-types/Cargo.toml` — new `test-fixtures` feature.
- `crates/eth-types/src/lib.rs:26-45` — move the fixture re-exports into
  `#[cfg(feature = "test-fixtures")] pub mod fixtures`.
- `crates/eth-types/src/block_body.rs:893-` and `crates/eth-types/src/block.rs:354-400` — gate the
  fixture constructors and constants.
- Consumer dev-dependencies: `crates/crypto`, `crates/beacon`, `crates/block-service`,
  `crates/grpc-signer`, `bin/rvc-signer` each add
  `eth-types = { workspace = true, features = ["test-fixtures"] }` under `[dev-dependencies]`.
- `crates/eth-types/src/domains.rs:20-82`, `lib.rs:197-205,336-340` — delete the echo tests.

**Acceptance criteria.**
- [ ] `cargo build -p rvc-eth-types` (no features) compiles no fixture code; the symbols are absent
      from the default public API.
- [ ] All five consumer crates' tests pass with the dev-dependency feature.
- [ ] `cargo build --release --workspace` produces no fixture symbols (spot-check with `nm`/`strings`
      on one binary, or assert the module is `cfg`-gated).
- [ ] The twelve per-domain echo tests and the three constant echoes are gone; uniqueness and size
      invariants remain; one table-driven spec-pin test replaces them.
- [ ] Test-count delta explained in the PR (≈15 removed, 1 added).

**TDD test plan.**
- **RED first:** `test_fixtures_absent_without_feature` — a compile-fail check (a `trybuild`-style
  case, or simply `cargo build -p rvc-eth-types --no-default-features` in CI asserting the symbol is
  unresolvable). It fails before the gating exists.
- `test_domains_table_matches_spec` — the one replacement test: a single array of
  `(name, expected_bytes)` cited to the consensus spec, iterated. One edit point per legitimate
  change instead of two.
- `test_all_domains_are_unique` and the 4-byte size check kept verbatim.
- Every consumer crate's existing test suite passes unmodified except for the import path change.

**Risks.** Cargo feature unification: adding `test-fixtures` as a dev-dependency feature on a crate
that also has `eth-types` as a normal dependency means the feature is on when building that crate's
tests — which is exactly what is wanted — but it will also be on for any crate that transitively
dev-depends. Confirm with `cargo tree -e features` that no *production* build turns it on.

---

### Issue RF3-20: Sync-committee constants and aggregator predicate move to eth-types

- **Points:** 2
- **Type:** refactor
- **Scope:** ~1 day
- **Stream:** B
- **Plan item:** G7 · **Finding:** F99
- **Blocked by:** **B1 (Phase 2)** · **Blocks:** none

**What / why.** `SYNC_COMMITTEE_SIZE = 512` and `SYNC_COMMITTEE_SUBNET_COUNT = 4` are defined
independently in `crates/sync-service/src/lib.rs:23-25` (plus
`TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE = 16`) and in
`crates/rvc/src/orchestrator/sync_committee.rs:19-23`, and the subnet-mapping expression
`pos / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT)` is duplicated verbatim at
`sync-service/src/lib.rs:211` and `orchestrator/sync_committee.rs:170`. The KAT test in sync-service
exists *specifically* because the two copies can drift — it pins the mapping "against the
byte-identical orchestrator closure".

**Pairs with B1**, which shrinks `sync-service` to the aggregator predicate + subnet mapping + error
type. This issue is what gives those survivors their new home, so it should land immediately after
B1 (or as its follow-up PR).

**Files to touch (verified).**
- New constants + `pub fn subcommittee_index(pos: u64) -> u64` + `is_sync_committee_aggregator` in
  `crates/eth-types/src/sync_committee.rs` (which already hosts the sync types).
- `crates/sync-service/src/lib.rs:23-25` (constants), `:86-94`
  (`is_sync_committee_aggregator` — uses `Sha256`), `:211` (mapping) — delete, re-export or drop.
- `crates/rvc/src/orchestrator/sync_committee.rs:19-23,170` — delete the local copies; `:12` and
  `:198,:1008` already import `is_sync_committee_aggregator` from `sync-service` and repoint to
  `eth-types`.
- `crates/sync-service/tests/per_validator_isolation.rs:47` — import path.
- `crates/eth-types/Cargo.toml` — add `sha2` (external, so the zero-workspace-out-edge pin holds).

**Acceptance criteria.**
- [ ] The three constants and both helpers exist only in `eth-types`.
- [ ] `rg 'SYNC_COMMITTEE_SIZE'` shows one definition.
- [ ] `eth-types` still has zero workspace-internal out-edges (`sha2` is external) and the
      architecture gate is green.
- [ ] The sync-service KAT collapses to one canonical location with no loss of coverage.
- [ ] Standing invariant green.

**TDD test plan.**
- **RED first:** `test_subcommittee_index_matches_both_legacy_closures` — placed in `eth-types`,
  iterating positions `0..512` and asserting the new `subcommittee_index` equals the expression
  copied verbatim from *both* old sites. It fails until the helper is written, and it is the direct
  successor to the drift-detection KAT that motivated the finding.
- `test_is_sync_committee_aggregator_kat` — the existing sync-service vectors
  (`sync-service/src/lib.rs:605-642`) moved verbatim.
- `test_orchestrator_aggregator_selection_unchanged` — the orchestrator path yields the same
  aggregator set for a fixed selection proof.

**Risks.** Adding `sha2` to `eth-types` widens a foundation crate's dependency set slightly. It is
external so the architecture pin is unaffected, and `sha2` is already in the workspace graph.

---

## Validation Summary (phase gate detail)

Per §6.4, the ordering discipline for this phase is **pin, then repoint**. Every "create the shared
home" issue lands its KAT/round-trip/characterization test *before* the corresponding "repoint the
consumers" issue starts:

| Shared home (pin first) | Consumers repointed |
|---|---|
| RF3-01 observability | RF3-02 |
| RF3-03 network presets | RF3-04 |
| RF3-05 ForkName API | RF3-07, RF3-08, RF3-09 |
| RF3-10 web3signer-wire | RF3-11, RF3-12 |
| RF3-13 canonical hex | RF3-15, RF3-16 |
| RF3-17 GVR metadata compat | RF3-18 |

Deliberate behavior changes requiring release notes: **RF3-08** (non-mainnet SSZ fork tagging),
**RF3-13/RF3-15** (`0X` prefix accepted at previously-strict sites), **RF3-18** (previously-rejected
interchange files now import), and **RF3-04**'s unified unknown-network error text.
