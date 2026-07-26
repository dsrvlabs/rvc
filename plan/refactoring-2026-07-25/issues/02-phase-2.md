# Phase 2: Dead-Code Purge (Theme B, items B1–B11)

> Delete the twins before anyone refactors them. Phases 3–6 restructure the signing stack, the
> beacon access layer, the composition roots and the god-files; every hour spent restructuring
> code that is scheduled for deletion is wasted, and every dead copy of a consensus rule is a
> place the next fix can land in by mistake — which is exactly how the EIP-3076 watermark drift
> that Phase 1 (A1) repairs came to exist.
>
> Authoritative inputs: [`../refactoring-plan.md`](../refactoring-plan.md) §3 Theme B, §4
> Phase 2, §6 Validation Strategy; [`../refactoring-findings.json`](../refactoring-findings.json)
> F2, F3, F12, F35, F42, F43, F49, F52, F56, F57, F64, F79, F84, F92, F94, F102.
> All file:line references re-verified against HEAD `develop` (`a7f8cdf`) while writing this
> document; corrections to the plan's citations are called out inline and summarised under
> "Plan corrections found during grounding".

## Phase Overview

- **Goal:** every later phase operates on code that is actually alive. Eleven plan items become
  seventeen landable PRs: fifteen deletions, one wiring decision that the plan pre-committed to
  (B5 watermarks), and one protocol migration that turned out to be a hard prerequisite for
  retiring the v1 proto (RF2-16).
- **Issue count:** 17 issues, 38 points.
- **Estimated duration:** ~19–38 days single-stream; **~12–18 days with 2 developers** (bounded by
  Stream A, the longer stream at 21 points — not by total/2).
- **Entry criteria:**
  - **A1** (stage-path watermark `<=`) and **A2** (conformance + proptest suites retargeted at
    `stage_* → commit/discard`) from Phase 1, merged. This gates **only the five slashing issues**
    RF2-09/10/11/12/13: deleting the legacy rule generations before the conformance suite certifies
    the production path would leave EIP-3076 uncovered. All of Stream B and the crypto issues
    (RF2-06/07/08) plus RF2-14 can start on day one, in parallel with the tail of Phase 1.
  - Working tree green on the standing invariant: `cargo fmt --all -- --check`,
    `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`,
    `crates/architecture-tests`.
- **Exit criteria (phase gate):**
  - [ ] Workspace green on the standing invariant; `cargo build --release` succeeds and the
        dependency graph is reviewed (`cargo tree` diff: grpc-signer loses the v1 proto module,
        crypto loses `decryption_tracker`).
  - [ ] Slashing conformance + proptest suites green **on the stage path** (unchanged from the
        Phase 1 gate — these suites are the oracle for every slashing deletion here).
  - [ ] Every deletion PR carries an `rg` zero-caller proof in its description and an explained
        test-count delta (ported vs deleted-with-the-dead-code).
  - [ ] `ARCHITECTURE.md` no longer advertises `SyncService`, `DecryptionAttemptTracker` as a live
        loader feature, and records the B5 wire-not-delete decision.
  - [ ] `rg "proto::signer::signer_service_server"` returns zero hits workspace-wide (verified: the
        v1 trait is imported unaliased at `bin/rvc-signer/src/service.rs:58` and implemented at
        `:460`, while the v2 impl at `:485` uses the `SignerServiceV2` alias from `:65` — so the v1
        surface is greppable without false positives); neither `build.rs` compiles
        `proto/signer.proto`.

## Assumptions (verified against HEAD)

- **P2-A1 — The zero-caller claims hold.** Re-ran the analyzers' `rg` proofs for every deletion
  target. All held except two (see "Plan corrections"). Concretely: `build_all` has zero callers
  *including tests*; `AttestationTimer`/`run_slot_loop` are referenced only by `crates/timing`'s own
  `lib.rs` re-export; `eth_types::insecure` is referenced only by a code comment at
  `bin/rvc-signer/src/service.rs:452`; `load_from_directory_with_tracker` and
  `DecryptionAttemptTracker` have no callers outside `crates/crypto`; the ten crypto free `sign_*`
  functions have no callers outside `crates/crypto` except `sign_voluntary_exit`
  (`bin/rvc-keygen/src/exit.rs:6,36`), which survives.
- **P2-A2 — The slashing legacy API is test-only but huge.** No production caller of
  `is_safe_to_sign` / `is_safe_to_propose` / `record_attestation` / `record_block` /
  `check_and_record_*` exists; every call site is a test. But there are ~230 of them:
  `is_safe_to_sign` 22, `is_safe_to_propose` 14, `record_attestation` 29+7 external,
  `record_block` 32+1 external, `check_and_record_block` 25+24 external, `check_and_record_attestation`
  62+15 external. This test-fallout, not the deletion, is what B4 costs.
- **P2-A3 — The watermark subsystem is intact and untouched.** `set_block_watermark`
  (`db.rs:1832`), `get_block_watermark` (`:1866`), `set_attestation_watermark` (`:1882`),
  `get_attestation_watermark` (`:1943`), `prune_below_watermarks` (`:1976`) exist with zero callers
  outside `crates/slashing`; `RVC_SLASHING_DB_PRUNE_TOTAL` is defined at
  `crates/metrics/src/definitions.rs:135` and incremented only at `db.rs:2012-2017`. B5 wires them;
  deletion is off the table per the plan's pre-commitment.
- **P2-A4 — `SlashingDb::open_with_create_info` (`db.rs:110`) reports fresh creation.** The
  `rvc slashing prune` subcommand (RF2-13) uses it to refuse to operate on a path that did not
  already hold a DB, mirroring `reject_accidental_fresh_create`
  (`crates/rvc/src/config/builder.rs:81`).
- **P2-A5 — The v2 `PeerSignerService` is the only one registered.** `bin/rvc-signer/src/main.rs:795`
  registers `PeerSignerServiceServerV2`; no v1 `PeerSignerService` server impl exists anywhere.
- **P2-A6 — `no_raw_root_path.rs` is the standing raw-root guard, and it is v2-only.** It greps the
  generated `signer.v2.rs` for a `signing_root` field
  (`bin/rvc-signer/tests/no_raw_root_path.rs:11-31`). It does not depend on v1 and survives the
  proto retirement, so deleting `v1_raw_root_bypass.rs` (whose only assertion is "the v1 handler
  returns `Unimplemented`") drops no security coverage.

## Plan corrections found during grounding

Four citations in `refactoring-plan.md` / `refactoring-findings.json` are stale or shuffled. None
invalidates an item; two change its size.

1. **B10's stated prerequisite is already done.** The plan opens B10 with "implement v2
   `ListPublicKeys` in `GrpcRemoteSigner::connect` (ISSUE-1.9), then delete v1…". `connect` already
   uses v2: `crates/grpc-signer/src/client.rs:161-168` calls
   `client.list_public_keys(crate::proto::signer_v2::ListPublicKeysRequest {})` under an "SS-1
   (Issue 2.2)" comment. B10 is pure retirement work; the migration step is complete.
2. **B10 has an unlisted blocker on the client side.** `bin/rvc-signer/src/dvt/peer_client.rs:10-11`
   imports the **v1** `peer_signer_service_client::PeerSignerServiceClient` and `PartialSignRequest`,
   and `GrpcPeerRequester::request_partial` (`:263-294`) calls `client.partial_sign(req)` on it.
   `GrpcPeerRequester::connect` is wired in production at `bin/rvc-signer/src/main.rs:943`. So v1
   proto compilation cannot leave `bin/rvc-signer/build.rs` until this is ported — and, separately,
   the DVT client is dialling `/signer.PeerSignerService/PartialSign` while the server only serves
   `/signer.v2.PeerSignerService/*` (P2-A5). This becomes RF2-16; it is a **liveness** defect (DVT
   partial signing gets `Unimplemented`), not a slashing defect.
3. **B2 is smaller than the plan implies.** "port their unit tests to individual `build_*` methods"
   overstates the work: `build_all`, `BuiltServices` and `orchestrator_factory` have **zero test
   callers**. Only `build_doppelganger_service` has one test
   (`crates/rvc/src/config/builder.rs:1166`), and it dies with the method. Also the plan's symbol→line
   mapping is shuffled: `:126` is `BuiltServices`, `:269` is `build_doppelganger_service`, `:703` is
   `build_all` (the lines are right, the labels are swapped).
4. **B1's "constants move in D3" is a typo for G7.** D3 is the error-taxonomy item (Phase 4). G7
   ("Sync-committee constants + `subcommittee_index` + `is_sync_committee_aggregator` move to
   eth-types … pairs with B1") is the item meant, and it sits in **Phase 3**. RF2-01 therefore leaves
   `SYNC_COMMITTEE_SIZE` / `SYNC_COMMITTEE_SUBNET_COUNT` / `is_sync_committee_aggregator` in place
   and G7 relocates them one phase later.

## Phase Summary

| Issue | Title | Pts | Days | Type | Blocked by | Stream |
|-------|-------|----:|------|------|------------|--------|
| RF2-01 | Delete the `sync_service::SyncService` twin; purge dead `OrchestratorError` variants | 2 | 1–1.5 | deletion | — | B |
| RF2-02 | Delete `ServiceBuilder::build_all`, `BuiltServices`, `build_doppelganger_service` | 2 | 1–1.5 | deletion | — | B |
| RF2-03 | Delete `timing::timer.rs`, its three metrics, dead `TimingError` variants and BPS constants | 1 | 0.5–1 | deletion | — | B |
| RF2-04 | Delete the `eth-types` `insecure` module and its gate test | 1 | 0.5 | deletion | — | B |
| RF2-05 | Purge dead `bn-manager` configuration (`BnSelectionStrategy`, `head_slot`, SSE cap, `latency`) | 2 | 1–1.5 | deletion | — | B |
| RF2-06 | Delete the second keystore-directory loader and `DecryptionAttemptTracker` | 2 | 1–1.5 | deletion | — | A |
| RF2-07 | Re-home crypto signing KATs onto `compute_domain` / `compute_signing_root` | 3 | 1.5–2 | testing | — | A |
| RF2-08 | Delete the crypto free `sign_*` functions, `RawSigner`, shadowed `DOMAIN_BEACON_ATTESTER` | 2 | 1–1.5 | deletion | RF2-07 | A |
| RF2-09 | Delete slashing generation 1: `is_safe_to_sign` / `is_safe_to_propose` | 3 | 1.5–2 | deletion | A2 (P1) | A |
| RF2-10 | Reduce `check_and_record_*` to a thin `stage + commit` wrapper; drop `_client_cn` | 3 | 1.5–2 | refactor | RF2-09 | A |
| RF2-11 | Demote `record_attestation` / `record_block` to documented test-seeding helpers | 2 | 1–1.5 | refactor | RF2-10 | A |
| RF2-12 | Set watermarks from interchange maxima on import | 3 | 1.5–2 | feature | A1+A2 (P1) | A |
| RF2-13 | `rvc slashing prune` subcommand; record the wire-not-delete decision | 2 | 1–1.5 | feature | RF2-12 | A |
| RF2-14 | Micro-deletions in slashing: `MigrationError`; reader delegates to SQL `MAX` | 1 | 0.5 | deletion | — | A |
| RF2-15 | Retire the v1 proto from `crates/grpc-signer`; port `tonic_limits_m10` to v2 | 3 | 1.5–2 | deletion | — | B |
| RF2-16 | Port the DVT peer client to the v2 `PeerSignerService` | 3 | 1.5–2 | bugfix | — | B |
| RF2-17 | Retire the v1 proto from `bin/rvc-signer`; delete `proto/signer.proto` | 3 | 1.5–2 | deletion | RF2-15, RF2-16 | B |

**Total: 17 issues, 38 points. Stream A: 21 points (9 issues). Stream B: 17 points (8 issues).**

## Execution Plan

Two streams, split by ownership of the two big shared files.

- **Stream A — safety-critical cores (`crates/slashing`, `crates/crypto`), 21 points.**
  Order: the crypto pair RF2-06, then RF2-07 → RF2-08, then the slashing chain
  RF2-09 → RF2-10 → RF2-11 → RF2-12 → RF2-13. RF2-14 is independent of everything and may land
  anywhere in the stream — including first, as a warm-up, which is why its ID sits last without
  implying it runs last.
  **The slashing chain must be strictly sequential**: RF2-09/10/11/12 all edit
  `crates/slashing/src/db.rs`, a 5,466-line file, in overlapping regions (the rule generations at
  `:805-1714` and the watermark block at `:1832-2031`). Parallelising them buys nothing and costs a
  merge nightmare. RF2-14 is the one slashing issue safe to land out of band — it touches only
  `error.rs` and `reader.rs`.
- **Stream B — everything else (`crates/rvc`, `crates/timing`, `crates/eth-types`,
  `crates/bn-manager`, `crates/grpc-signer`, `bin/rvc-signer`), 17 points.**
  Order: the five independent deletions RF2-01 … RF2-05 in any order (they are mutually disjoint),
  then the proto chain RF2-15 → RF2-16 → RF2-17. RF2-15 and RF2-16 are themselves independent of
  each other and can be swapped or overlapped; only RF2-17 needs both.

**Shared-file coordination.** The streams touch disjoint source files with two exceptions,
handled the way Phase 1 handles `bin/rvc/src/main.rs`:

- `ARCHITECTURE.md` — RF2-01 edits the sequence-diagram participant (`:257`) and the `SyncService`
  component entry (`:488`); RF2-06 edits the `DecryptionAttemptTracker` claim (`:534`); RF2-13 edits
  the "Pruning — Watermark-based pruning" claim (`:552`). Distinct sections, no semantic overlap.
  Agree the edit order once at kickoff and rebase rather than merge.
- `bin/rvc/src/main.rs` — touched **only** by RF2-13 (the new `Commands::Slashing` variant). No
  Stream B issue touches it. Flagged because it is the workspace's hottest file and Phase 5's F1/F3
  will rewrite it.

Within Stream A, RF2-06 and RF2-08 both edit `crates/crypto/src/lib.rs` (the
`decryption_tracker` re-export at `:35` and the signing re-exports at `:25-61` respectively) — land
them in numeric order. Within Stream B, RF2-04 and RF2-17 both edit the ADR-010 comment block around
`bin/rvc-signer/src/service.rs:444-457`; whichever lands second finds the other's edit already
applied and should verify rather than reapply.

## Dependency Map

```text
Phase 1 A1 + A2 ─┐
                 ├─▶ RF2-09 ──▶ RF2-10 ──▶ RF2-11                       [Stream A, slashing]
                 └─▶ RF2-12 ──▶ RF2-13
RF2-14 (independent)                                                    [Stream A, slashing]
RF2-06 (independent)                                                    [Stream A, crypto]
RF2-07 ──▶ RF2-08                                                       [Stream A, crypto]

RF2-01, RF2-02, RF2-03, RF2-04, RF2-05 (mutually independent)           [Stream B]
RF2-15 ─┐
        ├─▶ RF2-17                                                      [Stream B, proto]
RF2-16 ─┘
```

**Cross-phase dependencies (in and out):**

| Edge | Direction | Detail |
|---|---|---|
| A2 (P1) → RF2-09/10/11 | in | Conformance + proptests must certify `stage_*` before the legacy rule generations are removed. |
| A1+A2 (P1) → RF2-12 | in | Watermark equality semantics must be pinned on the stage path before import starts populating watermarks. |
| RF2-09/10/11 → **E1** (P4) | out | E1 extracts `rules.rs` and has "all surviving entry points (`stage_*` after B4) delegate" — B4 defines what survives. |
| RF2-02 → **F1** (P5) | out | F1 extracts `run_validator` into a bootstrap module; the second composition root must be gone first or F1 has two targets. |
| RF2-15/16/17 → **C4** (P3) and **D4** (P4) | out | C4 creates `crates/signer-proto` compiling signer.v2.proto once; it cannot be "once" while two crates also compile v1. D4's transport unification assumes a single proto surface. **This is the phase's critical path.** |
| RF2-13 → **F3** (P5) | out | F3 restructures the rvc CLI into `Start(StartArgs)` with flatten groups; it must carry the new `Slashing` subcommand. |
| RF2-01 → **G7** (P3) | out | G7 moves the sync-committee constants and `is_sync_committee_aggregator` into eth-types; RF2-01 deliberately leaves them where they are. |
| RF2-08 → **D1** (P4) | out | D1's `signing_root_for` re-homes the KATs that RF2-07 parks on `compute_domain`/`compute_signing_root`. |
| RF2-02 ↔ **E8c** (P4) | note | E8c retires the legacy `DoppelgangerService` from the startup path (gated on SEC-2). RF2-02 deletes only the *builder factory*, not `crates/doppelganger`'s service or `rvc::startup::run_doppelganger_detection`. |

## Phase Risk Flags

- **RF2-12 (watermarks from interchange import) is the highest-risk issue in the phase**, despite
  being neither the largest nor on the critical path. It is the only issue that changes what the
  production signing path *rejects*: today the per-sign watermark queries at `stage.rs:348-362` and
  `:482-512` always return `None`, so watermarks never block anything. After RF2-12 they can. In
  particular, combining an `att_target` watermark set to the interchange maximum with A1's `<=`
  equality blocking means a validator cannot sign at the maximum target epoch present in its own
  imported interchange. That is very likely correct minimal-strategy EIP-3076 — but it must be
  *demonstrated* against the conformance suite's minimal-strategy cases, not asserted.
- **RF2-13's prune subcommand must never create a slashing DB.** A `prune` that silently creates an
  empty DB on a typo'd path is a slashing footgun of the same class as `--init-slashing-db`. Use
  `open_with_create_info` and hard-error on `created_fresh`.
- **RF2-16 is a real defect, correctly scoped.** DVT partial signing against an rvc-signer peer
  currently returns `Unimplemented`. It is behind the `dvt` feature and is a liveness failure, not a
  safety one — it ranks below RF2-12 in this phase's risk order, and it is included here only
  because RF2-17 cannot land without it.
- **Public API removals.** RF2-05 deletes `BnSelectionStrategy` from `crates/bn-manager/src/lib.rs:20`;
  RF2-15/17 delete the v1 proto types from two crates' public APIs; RF2-08 removes ten `pub` functions
  and a `pub trait` from `crates/crypto`. Internal-consumer-only crates, so no semver ceremony, but
  each PR states the removed surface explicitly.
- **Test-count arithmetic is the phase gate, not a formality.** This phase deletes roughly 1,100
  lines of sync-service test code, ~500 lines of timing/insecure tests, several hundred crypto KAT
  lines that must be *ported not dropped*, and a large fraction of `db.rs`'s test module. Every PR
  states expected delta and classifies it (ported / deleted-with-the-dead-code / newly added).
  A deletion PR whose delta is unexplained does not merge.
- **`clippy -D warnings` will surface cascade dead-code.** Deleting a public function frequently
  orphans a private helper. Budgeted inside each issue; do not chase orphans into a neighbouring
  issue's files.

---

## Issues

### Issue RF2-01: Delete the `sync_service::SyncService` twin; purge dead `OrchestratorError` variants

- **Points:** 2
- **Scope:** 1–1.5 days
- **Type:** deletion
- **Plan item:** B1, plus the `OrchestratorError` half of B11
- **Findings:** F2, F92, F102 (resolves itself), F12 (error variants)
- **Blocked by:** none
- **Blocks:** G7 (P3) touches the same constants one phase later
- **Stream:** B

**Description:**
`crates/sync-service` ships a fully implemented, fully tested `SyncService` that no production code
calls. The orchestrator's `SyncCommitteeService`
(`crates/rvc/src/orchestrator/sync_committee.rs`, 1,080 lines) reimplements the same
message + contribution pipeline against `SignerService`/`BeaconNodeClient`, adding timeouts and the
D-3 doppelganger gate. Safety fixes now exist in two places — sync-service's own KAT test
(`lib.rs:605-610`) even documents that it mirrors "the byte-identical orchestrator closure at
`crates/rvc/src/orchestrator/sync_committee.rs:170`". Shrink the crate to the three symbols the
workspace actually imports and delete the twin, so the ~1,100 lines of tests covering the dead copy
stop giving false confidence.

Fold in the `OrchestratorError` micro-deletions from B11 because they live in the same file
(`crates/rvc/src/orchestrator/error.rs`) as the dead `SyncService` variant this issue must remove —
splitting them would create a needless conflict between two PRs on a 116-line file.

**Files to touch (verified):**
- `crates/sync-service/src/lib.rs` — delete `SyncSigner` (`:28`), `SyncBeaconClient` (`:57`),
  `SyncMessagesResult` (`:77`), `ContributionsResult` (`:82`), `SyncService` (`:97`, through the
  end of production code at `:306`), and the `Signature`/`PublicKey` `Vec<u8>` aliases (`:20-21`,
  F102). Keep `is_sync_committee_aggregator` (`:86`), the three constants (`:23-25`) and the
  `SyncServiceError` re-export (`:18`). Keep the surviving unit tests (`:571-600`).
- `crates/sync-service/tests/per_validator_isolation.rs` — delete (415 lines; every test constructs
  `SyncService::new`, lines `:192`, `:300`, `:389`).
- `crates/sync-service/Cargo.toml` — drop `async-trait` and `tokio` once the traits and async
  methods are gone; keep `eth-types`, `sha2`, `thiserror`, `tracing`.
- `crates/rvc/src/orchestrator/error.rs` — delete `SyncService(#[from] SyncServiceError)` (`:44`)
  and the now-unused `use sync_service::SyncServiceError` (`:10`); delete `Shutdown` (`:35`),
  `InvalidPubkey` (`:51`) and `BeaconTimeout` (`:54`), plus their display tests (`:75`, `:93`, `:99`).
- `crates/rvc/Cargo.toml` — keep `sync-service.workspace = true` (`:35`);
  `is_sync_committee_aggregator` still comes from there until G7.
- `ARCHITECTURE.md:257` (sequence-diagram participant `Sync as SyncService`) and `:488`
  (`**SyncService<S, B>** — Generic over SyncSigner and SyncBeaconClient`) — correct both to name
  the orchestrator's `SyncCommitteeService` as the production path.

**Implementation sketch:**
1. **RED (deletion form):** capture the `rg` zero-caller proof for `SyncService`, `SyncSigner`,
   `SyncBeaconClient`, `SyncMessagesResult`, `ContributionsResult` across `crates/` and `bin/`,
   excluding `crates/sync-service` itself; paste it into the PR description. Expected: no hits.
2. Delete the integration test file, then the production symbols, then the in-file tests that
   exercised them. Compiler-driven: `crates/rvc` must still build with only the
   `is_sync_committee_aggregator` and `SyncServiceError` imports.
3. Delete the four dead `OrchestratorError` variants and their tests; `clippy -D warnings` confirms
   nothing else constructed them.
4. Trim `crates/sync-service/Cargo.toml`.
5. Fix the two `ARCHITECTURE.md` claims.
6. **GREEN:** workspace green; sync-committee behaviour unchanged (no orchestrator code was edited).

**Acceptance criteria:**
- [x] `crates/sync-service` exports exactly `is_sync_committee_aggregator`, `SyncServiceError` and
      the three sync-committee constants; the crate is under ~150 lines of production code.
- [x] `rg "SyncService\b" crates bin -g '*.rs'` returns only `SyncServiceError` hits.
- [x] `rg "OrchestratorError::(Shutdown|InvalidPubkey|BeaconTimeout|SyncService)"` returns zero hits.
- [x] Orchestrator sync-committee **production** behaviour is unchanged — only H-6 isolation unit
      tests were added under `crates/rvc/src/orchestrator/sync_committee.rs` (no production edits).
- [x] `ARCHITECTURE.md` `:257`/`:488` name `SyncCommitteeService`, not `SyncService`.
- [x] **Test-count delta stated and justified:** twin deleted ≈ −22 tests (*deleted-with-the-dead-code*:
      lib −16, isolation −3, error display −3); **+2 ported** H-6 multi-validator isolation tests on
      production `SyncCommitteeService`:
      `test_h6_one_signer_failure_does_not_abort_sync_messages`,
      `test_h6_one_signer_failure_does_not_abort_sync_contributions`
      (one of three validators KeyNotFound; others still produce). Net ≈ −20.
- [x] Standing invariant green (fmt; clippy on affected crates; nextest rvc + sync-service +
      architecture-tests). Workspace clippy pre-existing keygen lint left alone.

**Risks:**
- The one genuinely load-bearing test in the deleted file is the H-6 "signing failure must not abort
  the loop" per-validator isolation case. Before deleting, confirm by name that
  `crates/rvc/src/orchestrator/sync_committee.rs` has an equivalent; if it does not, **port it**
  rather than delete it, and say so in the delta. This is the only outcome that could push this
  issue to 3 points.

---

### Issue RF2-02: Delete `ServiceBuilder::build_all`, `BuiltServices`, `build_doppelganger_service`

- **Points:** 2
- **Scope:** 1–1.5 days
- **Type:** deletion
- **Plan item:** B2
- **Findings:** F3, half of F13
- **Blocked by:** none
- **Blocks:** F1 (P5)
- **Stream:** B

**Description:**
Two composition roots exist and only one is real. `ServiceBuilder::build_all`
(`crates/rvc/src/config/builder.rs:703`) returns an unusual
`(BuiltServices, FnOnce(BuiltServices) -> (DutyOrchestrator, Handle))` tuple, wires the single-BN
`BeaconClient` instead of `BnManager`, hard-codes a non-zero epoch to dodge the doppelganger
epoch-0 bypass (`:739`), and builds the legacy one-shot doppelganger service its own doc comment
calls "tests / non-production" (`:264`). Meanwhile `bin/rvc`'s `run_validator` hand-wires the same
services from the individual `build_*` methods in a different order. The fake root is what the
builder's public API advertises — `BuiltServices` is re-exported from `config/mod.rs:8`. Delete it,
so Phase 5's F1 has exactly one thing to extract.

**Files to touch (verified):**
- `crates/rvc/src/config/builder.rs`
  - `BuiltServices<C, S>` struct `:126-147` (the `doppelganger_service` field is at `:143`).
  - `build_doppelganger_service` `:269-285` and its `DoppelgangerService::new` call `:281`.
  - `build_all` `:703-817`, including the `orchestrator_factory` closure `:793-815`.
  - the `DoppelgangerService` import in the `use` block at `:23`.
  - test `test_build_doppelganger_service` at `:1166` — dies with the method it tests.
- `crates/rvc/src/config/mod.rs:8` — `pub use builder::{BuiltServices, ServiceBuilder};` becomes
  `pub use builder::ServiceBuilder;`.

**Explicitly out of scope:** `crates/doppelganger`'s `DoppelgangerService` itself and
`crates/rvc/src/startup.rs:138` `run_doppelganger_detection` (plus its tests at `:895-950`). Those
are E8c's business in Phase 4, gated on SEC-2. This issue removes only the *builder factory*.

**Implementation sketch:**
1. **RED (deletion form):** `rg "build_all|BuiltServices|orchestrator_factory|build_doppelganger_service" crates bin -g '*.rs'`
   → expect hits only inside `builder.rs` plus the single `config/mod.rs:8` re-export. Paste into
   the PR. Note in the description that unlike the plan's wording there are **no** unit tests to
   port off `build_all`.
2. Delete `build_all` and its closure, then `BuiltServices`, then `build_doppelganger_service` and
   its test, then the orphaned import and re-export.
3. `clippy -D warnings` catches any helper that only `build_all` used.
4. **GREEN:** `bin/rvc` builds and starts unchanged; the individual `build_*` methods and their
   tests (`test_build_beacon`, `test_build_signer`, `test_build_bn_manager_*`, … at `:837+`) are
   untouched and still green.

**Acceptance criteria:**
- [x] `crates/rvc/src/config/builder.rs` contains no `build_all`, `BuiltServices`,
      `orchestrator_factory` or `build_doppelganger_service`.
- [x] `crates/rvc/src/config/mod.rs` no longer re-exports `BuiltServices`.
- [x] Every remaining `build_*` method retains its unit test; the count of `build_*` methods is
      unchanged minus one.
- [x] `crates/doppelganger` and `crates/rvc/src/startup.rs` are not modified.
- [x] **Test-count delta stated and justified:** expected exactly **−1** test
      (`test_build_doppelganger_service`), classified *deleted-with-the-dead-code*. Any other delta
      is a bug in the PR.
- [x] Standing invariant green.

**Risks:**
- `run_doppelganger_detection` becomes production-unreachable once its only builder-side constructor
  is gone; its own tests construct `DoppelgangerService` directly (`startup.rs:926-934`) so they stay
  green. Do **not** opportunistically delete it here — E8c owns that decision and it is SEC-2-gated.
  Note the newly-orphaned state in the PR so E8c inherits the context.

---

### Issue RF2-03: Delete `timing::timer.rs`, its three metrics, dead `TimingError` variants and BPS constants

- **Points:** 1
- **Scope:** 0.5–1 day
- **Type:** deletion
- **Plan item:** B3
- **Findings:** F94
- **Blocked by:** none
- **Stream:** B

**Description:**
`crates/timing/src/timer.rs` (333 lines) implements `AttestationTimer` / `run_slot_loop` /
`wait_for_slot_start` / `wait_for_attestation_time`, none of which anything calls — the rvc
coordinator drives its own slot loop from `SlotClock` + `due_ms`. Worse, the file self-registers
three Prometheus metrics (`rvc_slot_timing_current_slot`, `rvc_slot_timing_drift_seconds`,
`rvc_slot_timing_attestation_delay_seconds`) that can never update, which actively misleads
operators building dashboards. Delete the timer, its metrics, the two `TimingError` variants only it
could reach, and the four BPS constants with no consumers.

**Files to touch (verified):**
- `crates/timing/src/timer.rs` — delete the whole file.
- `crates/timing/src/lib.rs` — `mod timer;` (`:11`), `pub use timer::{AttestationTimer, AttestationTimerHandle};`
  (`:15`), and the `AttestationTimer` bullet in the module doc (`:6-7`). Delete the four constants
  with zero external consumers: `SYNC_MESSAGE_DUE_BPS` (`:35`), `CONTRIBUTION_DUE_BPS` (`:46`),
  `ATTESTATION_DUE_BPS_GLOAS` (`:52`), `AGGREGATE_DUE_BPS_GLOAS` (`:58`).
  **Keep** `BASIS_POINTS` (`:24`), `ATTESTATION_DUE_BPS` (`:30`), `AGGREGATE_DUE_BPS` (`:41`) and
  `due_ms` (`:74`) — verified in use outside the crate.
- `crates/timing/src/error.rs` — delete `SlotNotStarted { slot }` (`:11`) and `Cancelled` (`:14`),
  plus `test_slot_not_started_display` (`:34`) and `test_cancelled_display` (`:40`).

**Implementation sketch:**
1. **RED (deletion form):** `rg "AttestationTimer|run_slot_loop|wait_for_slot_start|wait_for_attestation_time|rvc_slot_timing" crates bin -g '*.rs'`
   → expect hits only in `timer.rs` and the `lib.rs` re-export/doc. Repeat per-constant for the four
   BPS constants (verified zero files outside `crates/timing`).
2. Delete the file, the re-exports, the constants, the error variants and their tests.
3. **GREEN:** `crates/timing` = `SlotClock` + `SystemSlotClock` + `MockSlotClock` + constants +
   `due_ms` + a two-variant `TimingError`.

**Acceptance criteria:**
- [x] `crates/timing/src/timer.rs` does not exist; `crates/timing` is under ~300 production lines.
- [x] No `rvc_slot_timing_*` metric is registered anywhere — verified by grepping a running
      `/metrics` scrape or `crates/metrics/src/definitions.rs`, whichever the timer used.
- [x] `TimingError` has exactly `BeforeGenesis` and `InvalidSlotDuration`.
- [x] `ATTESTATION_DUE_BPS`, `AGGREGATE_DUE_BPS`, `BASIS_POINTS`, `due_ms` survive; the coordinator's
      slot timing is byte-identical (no `crates/rvc` file is modified).
- [x] **Test-count delta stated and justified:** expected ≈ −20 (timer.rs's own module, ~200 test
      lines, plus 2 error-display tests), all *deleted-with-the-dead-code*; zero ported.
- [x] Standing invariant green.

**Risks:**
- The Gloas BPS constants encode a real future fork requirement. The plan permits keeping them "next
  to a TODO in the coordinator" — do not; delete them and let C3/Phase 3's `ForkSchedule::entries()`
  work reintroduce fork-specific timing where it belongs. State this choice in the PR.

---

### Issue RF2-04: Delete the `eth-types` `insecure` module and its gate test

- **Points:** 1
- **Scope:** 0.5 days
- **Type:** deletion
- **Plan item:** B6
- **Findings:** F84
- **Blocked by:** none
- **Stream:** B

**Description:**
`crates/eth-types/src/insecure.rs` (98 lines) states in its own module doc that it has zero callers
outside its tests, and that is still true: every production `InsecureGate` use resolves to the
richer, diverged implementation in `crates/crypto/src/insecure.rs` (closure-predicate design, env
var + predicate conjunction, `InsecureMode::Refuse`/`Warn`). Two gates with different semantics —
`Decision` enum versus `Result`-based `check()` — is a trap for the next caller. It also contradicts
`ARCHITECTURE.md`'s contract that eth-types is pure data types with no business logic.

**Files to touch (verified):**
- `crates/eth-types/src/insecure.rs` — delete.
- `crates/eth-types/src/lib.rs:17` — `pub mod insecure;` — delete.
- `crates/eth-types/tests/insecure_gate.rs` (142 lines) — delete.
- `bin/rvc-signer/src/service.rs:452` — the comment reads "…would require
  `eth_types::insecure::InsecureGate::Allow`"; repoint it to `crypto::InsecureGate`.
  (Note for RF2-17: this comment sits inside the v1 ADR-010 block that RF2-17 deletes wholesale. If
  RF2-17 lands first, this bullet is a no-op — check before writing.)

**Implementation sketch:**
1. **RED (deletion form):** `rg "eth_types::insecure|eth-types.*InsecureGate" crates bin` → expect
   exactly one hit, the comment at `service.rs:452`.
2. Delete module, export and test file; fix the comment.
3. **GREEN:** `crypto::InsecureGate` remains the single gate; `bin/rvc-signer`'s
   `insecure_startup.rs` and `bin/rvc`'s metrics gate (`main.rs:1822`) are untouched.

**Acceptance criteria:**
- [x] `rg "insecure" crates/eth-types` returns zero hits.
- [x] Exactly one `InsecureGate` implementation exists workspace-wide, in `crates/crypto`.
- [x] The `bin/rvc-signer/src/service.rs` comment references the surviving gate.
- [x] **Test-count delta stated and justified:** expected ≈ −8 (the whole `insecure_gate.rs`
      integration file), all *deleted-with-the-dead-code*. The behaviour those tests covered is
      already covered by `crates/crypto`'s own insecure-gate tests and
      `bin/rvc-signer/tests/insecure_refuse_mode.rs` / `insecure_flag_h9.rs` — name them in the PR.
- [x] Standing invariant green.

**Risks:** none identified.

---

### Issue RF2-05: Purge dead `bn-manager` configuration

- **Points:** 2
- **Scope:** 1–1.5 days
- **Type:** deletion
- **Plan item:** B9
- **Findings:** F64
- **Blocked by:** none
- **Stream:** B

**Description:**
Four knobs in bn-manager exist, are publicly configurable, are tested — and are never read. The
worst is `BnSelectionStrategy`: an operator setting `selection_strategy = Best` is silently ignored,
because strategy is hard-coded per endpoint method in `manager.rs`. Delete the dead configuration
and document the real (per-operation) policy on `BnManager` instead, so the type system stops
advertising a control that does not exist.

**Files to touch (verified):**
- `crates/bn-manager/src/traits.rs`
  - `BnSelectionStrategy` enum `:200` and `BnManagerConfig.selection_strategy` `:232` (default set
    at `:253`); the five `test_selection_strategy_*` tests `:320-350` and the two config-test
    assertions `:360`, `:385`.
  - `BnHealthScore.head_slot` `:288` — hardwired to `None` at `manager.rs:194` while tests at
    `:406`, `:425`, `:445`, `:463`, `:480` assert `Some` values. **Decision: populate it** from
    `BnSyncDetail` rather than delete — the tests already encode the intended contract and a health
    score without head slot is genuinely less useful for failover diagnostics. If `BnSyncDetail`
    does not carry it at `manager.rs:194`, fall back to deleting the field and its test assertions;
    record which branch was taken in the PR.
- `crates/bn-manager/src/lib.rs:20` — drop `BnSelectionStrategy` from the public re-export list.
- `crates/beacon/src/http_caps.rs:18,25,32` — `ResponseCaps.max_sse_event_bytes` and
  `DEFAULT_MAX_SSE_EVENT_BYTES` are unused outside their own module; `crates/bn-manager/src/sse.rs:102`
  defines its own identical 64 KiB constant. Delete the `http_caps` copy and make `sse.rs:102` the
  single source; fix `http_caps.rs:100,112` tests accordingly.
- `crates/bn-manager/src/broadcast.rs:10` — `BnOutcome.latency` is `#[allow(dead_code)]`. **Decision:
  use it** in `log_partial_failure` rather than delete; it is already populated at `:61`, `:69`,
  `:130`, `:135` and a partial-failure log without latency is strictly worse for operators.
- `crates/bn-manager/src/manager.rs:194,240` — `head_slot` population and `SseConfig::new`.

**Implementation sketch:**
1. **RED:** `rg "selection_strategy|BnSelectionStrategy" crates bin -g '*.rs'` → confirm zero
   reads in `manager.rs`. Add a doc-test-style assertion or a doc comment on `BnManager` stating the
   per-operation strategy (broadcast for submissions, query-first for reads) so the knowledge the
   deleted enum implied is not lost.
2. Delete the enum, field, default, re-export and its five tests.
3. Resolve `head_slot` (populate preferred) and `latency` (use in `log_partial_failure`).
4. Collapse the duplicated SSE cap to one constant.
5. **GREEN:** failover behaviour unchanged — the existing manager strategy tests are the oracle.

**Acceptance criteria:**
- [x] `rg "BnSelectionStrategy|selection_strategy"` returns zero hits workspace-wide.
- [x] `BnManager`'s doc comment states the per-operation selection policy explicitly.
- [x] `head_slot` is either populated (tests asserting `Some` now pass against real data) or removed
      along with those assertions — one branch, stated in the PR.
- [x] Exactly one 64 KiB SSE-event-size constant exists workspace-wide.
- [x] `BnOutcome.latency` carries no `#[allow(dead_code)]`.
- [x] **Test-count delta stated and justified:** expected ≈ −5 to −7 (the `test_selection_strategy_*`
      cluster plus config-field assertions), *deleted-with-the-dead-code*; +0 to +2 if the `head_slot`
      population branch needs a new test.
- [x] Standing invariant green; bn-manager failover/strategy tests unchanged and green.

**Risks:**
- `BnSelectionStrategy` is in the public API (`lib.rs:20`). No external consumer exists in-workspace,
  but if a TOML config file in `docs/` or a fixture sets `selection_strategy`, serde will now reject
  it. Grep `docs/` and any `*.toml` fixture and add `#[serde(deny_unknown_fields)]`-compatible
  handling or a documented breaking-change note.

---

### Issue RF2-06: Delete the second keystore-directory loader and `DecryptionAttemptTracker`

- **Points:** 2
- **Scope:** 1–1.5 days
- **Type:** deletion
- **Plan item:** B8
- **Findings:** F43
- **Blocked by:** none
- **Stream:** A

**Description:**
`crates/crypto/src/key_manager.rs` has two ~110-line directory-scan loops that have drifted, and the
drift is security-relevant in the wrong direction: `load_from_directory_with_tracker` (`:376`) skips
the `validate_key_path` traversal check that the filtered variant performs, does no
declared-vs-derived pubkey verification (the surviving path rejects mismatches at `:300-311`), and
logs full untruncated pubkeys (`:437`, `:463`) where the rest of the crate uses `TruncatedPubkey`.
It and `DecryptionAttemptTracker` have no callers outside `crates/crypto` — the only production
loader call is `crates/rvc/src/config/builder.rs:301` using the filtered variant — yet
`ARCHITECTURE.md:534` advertises the tracker as a live brute-force protection. Delete the weaker
loop and correct the doc.

**Files to touch (verified):**
- `crates/crypto/src/key_manager.rs` — delete `load_from_directory_with_tracker` `:376-~490` and its
  `use super::decryption_tracker::DecryptionAttemptTracker` `:11`; delete the in-file tracker tests
  (from `:799`). Keep `load_from_directory` `:81`, `load_from_directory_with_threads` `:98`,
  `load_from_directory_with_threads_filtered` `:110`.
- `crates/crypto/src/decryption_tracker.rs` (193 lines) — delete the file.
- `crates/crypto/src/lib.rs:35` — `pub use decryption_tracker::DecryptionAttemptTracker;` — delete.
- `ARCHITECTURE.md:534` — remove the `DecryptionAttemptTracker for brute-force protection` claim;
  keep `Zeroize` on drop and `SecretString` for passwords, which are real.

**Implementation sketch:**
1. **RED (deletion form):** `rg "load_from_directory_with_tracker|DecryptionAttemptTracker" crates bin -g '*.rs'`
   → expect hits only inside `crates/crypto`. Paste into the PR.
2. **Before deleting, add a positive test on the surviving loader** proving it retains all three
   security properties the deleted one lacked: rejects a traversal path, rejects a keystore whose
   declared pubkey does not match the derived one, and logs truncated pubkeys. If any of these has
   no existing test, write it — this is the guard that the "weaker copy" analysis was right.
3. Delete the loader, the tracker module, the export and the tracker tests.
4. Fix `ARCHITECTURE.md:534`.
5. **GREEN:** boot key loading through `builder.rs:301` is unchanged.

**Acceptance criteria:**
- [x] Exactly one directory-scan loop remains in `key_manager.rs` (the three surviving entry points
      share it), with traversal check + declared-vs-derived pubkey verification + truncated logging
      applied.
- [x] `rg "DecryptionAttemptTracker"` returns zero hits workspace-wide, `ARCHITECTURE.md` included.
- [x] Named tests exist and pass on the surviving loader for all three security properties.
- [x] **Test-count delta stated and justified:** expected ≈ −15 (tracker module tests + in-file
      tracker loader tests), *deleted-with-the-dead-code*, offset by up to +3 *newly added*
      security-property tests on the surviving loader.
- [x] Standing invariant green.

**Risks:**
- If a reviewer wants rate limiting preserved rather than deleted, the plan permits folding it into
  the single pipeline as an optional parameter. That is the 3-point branch. Resolve at kickoff: the
  recommendation is delete — nothing wires it, and rate-limiting a local filesystem scan of the
  operator's own keystore directory protects against a threat model (repeated online decryption
  attempts) that the boot-time loader does not have.

---

### Issue RF2-07: Re-home crypto signing KATs onto `compute_domain` / `compute_signing_root`

- **Points:** 3
- **Scope:** 1.5–2 days
- **Type:** testing
- **Plan item:** B7 (first half)
- **Findings:** F42
- **Blocked by:** none
- **Blocks:** RF2-08
- **Stream:** A

**Description:**
The ten crypto free `sign_*` functions RF2-08 deletes carry the workspace's fork-boundary and
known-answer-vector coverage for domain and signing-root derivation. Deleting the functions would
delete the KATs with them, which is exactly the failure the plan's H5 "KAT-first" policy exists to
prevent. This issue moves that coverage first, onto the helpers that survive
(`compute_domain` `signing.rs:19`, `compute_signing_root` `signing.rs:31`), so RF2-08 is a pure
deletion with nothing to justify. D1 in Phase 4 re-homes these same KATs a second time onto
`signing_root_for` — write them so that second move is a call-site change, not a rewrite.

**Files to touch (verified):** test modules only.
- `crates/crypto/src/signing.rs` (tests from `:67`, 476 test lines) — `sign_attestation` KATs.
- `crates/crypto/src/block_signing.rs` (tests from `:56`, 331 lines) — `sign_block`,
  `sign_randao_reveal`.
- `crates/crypto/src/sync_signing.rs` (tests from `:77`, 404 lines) — `sign_sync_committee_message`,
  `sign_contribution_and_proof`, `sign_sync_committee_selection_proof`.
- `crates/crypto/src/aggregation_signing.rs` (tests from `:89`, 378 lines) — `sign_selection_proof`,
  `sign_aggregate_and_proof`, `sign_electra_aggregate_and_proof`. **Do not touch the
  `is_aggregator` tests** — that function survives.
- `crates/crypto/src/builder_signing.rs` (tests from `:22`, 117 lines) — `sign_builder_registration`.
- New or extended: a single `crates/crypto/tests/signing_root_kat.rs` is preferred over five scattered
  in-file modules, because D1 then has one file to repoint.

**Implementation sketch:**
1. Triage every test in the five modules into three buckets, and record the classification table in
   the PR description (this table *is* the test-count-delta justification for RF2-08):
   - **(a) domain/root KATs** — assert a `compute_domain` output or a signing root against a
     reference vector. **Port**: drop the BLS `sign` step, assert the root directly.
   - **(b) full-signature KATs** — assert a 96-byte signature against a reference vector. **Port**
     via `LocalSigner`/`TypedSigner`, which is the surviving path that actually signs; the vector is
     unchanged.
   - **(c) self-consistency tests** — sign then verify with the same code. **Drop**, citing H5's
     "forbid self-consistency-only assertions". These are the ones a naive port would preserve and
     H5 explicitly does not want.
2. Port buckets (a) and (b) into `crates/crypto/tests/signing_root_kat.rs`, one test per
   (duty type × fork boundary) with the vector inline and its provenance in a comment.
3. Include the EIP-7044 Capella-cap boundary cases — `capella_capped_fork_version`
   (`typed_signer.rs`) is what D1 consolidates, so its boundary vectors must survive this phase.
4. **GREEN:** the new file passes *while the old functions still exist* — that is the proof the
   vectors were transcribed correctly, not re-derived from the new code path.

**Acceptance criteria:**
- [x] `crates/crypto/tests/signing_root_kat.rs` exists and covers every duty type the ten free
      `sign_*` functions covered, at every fork boundary they covered, including the EIP-7044
      Capella cap.
- [x] Every ported assertion uses the *same literal vector bytes* as the test it replaces — a
      reviewer can diff the constants.
- [x] The classification table (port-as-root / port-as-signature / drop-as-self-consistency) appears
      in the PR description with a line per source test.
- [x] The suite is green **before** any production code is deleted (this PR deletes none).
- [x] **Test-count delta stated and justified:** net positive or neutral; new KAT file adds tests,
      no existing test is removed in this PR.
- [x] Standing invariant green.

**Risks:**
- The triage is the work, and bucket (c) is where a reviewer will push back — dropping a test always
  looks like losing coverage. Mitigate by quoting H5 in the PR and by showing that each dropped test
  asserts only `verify(sign(x)) == true`, which the BLS library's own tests already cover.
- If a full-signature KAT cannot be reproduced through `LocalSigner` because the free function had a
  different argument shape, keep the free function alive for that one case and hand RF2-08 a
  documented exception rather than dropping the vector.

---

### Issue RF2-08: Delete the crypto free `sign_*` functions, `RawSigner`, shadowed `DOMAIN_BEACON_ATTESTER`

- **Points:** 2
- **Scope:** 1–1.5 days
- **Type:** deletion
- **Plan item:** B7 (second half)
- **Findings:** F42
- **Blocked by:** RF2-07
- **Blocks:** D1 (P4) re-homes RF2-07's KATs
- **Stream:** A

**Description:**
Ten free functions in crypto sign with a raw `&SecretKey`, bypassing `CompositeSigner` and slashing
protection by design — which is precisely what
`crates/signer/tests/no_direct_composite_signer_outside_signer.rs:60-62` polices against. Every duty
path goes through `SignerService`/`SigningGate`/`TypedSigner` instead. The `RawSigner` trait
(`typed_signer.rs:32`) is exported with zero users outside its own file, and `signing.rs:8`
redefines `DOMAIN_BEACON_ATTESTER` even though `eth_types` already exports it (and crypto imports
the eth-types one elsewhere, e.g. `typed_signer.rs:12`). Delete the lot; keep the four symbols with
real consumers.

**Files to touch (verified):**
- Delete: `sign_attestation` (`signing.rs:49`), `sign_block` + `sign_randao_reveal`
  (`block_signing.rs:19,42`), `sign_selection_proof` + `sign_aggregate_and_proof` +
  `sign_electra_aggregate_and_proof` (`aggregation_signing.rs:19,40,61`),
  `sign_sync_committee_message` + `sign_contribution_and_proof` +
  `sign_sync_committee_selection_proof` (`sync_signing.rs:15,36,57`), `sign_builder_registration`
  (`builder_signing.rs:11`), `RawSigner` (`typed_signer.rs:32`), and the shadowed
  `DOMAIN_BEACON_ATTESTER` const (`signing.rs:8`) — replace its uses with the `eth_types` one.
- **Keep:** `compute_domain` (`signing.rs:19`), `compute_signing_root` (`signing.rs:31`),
  `is_aggregator` (`aggregation_signing.rs:82`, re-exported by signer and used by the orchestrator),
  `sign_voluntary_exit` (`voluntary_exit_signing.rs:15`, used by `bin/rvc-keygen/src/exit.rs:6,36`),
  `capella_capped_fork_version` (D1's target in Phase 4).
- `crates/crypto/src/lib.rs` — prune the re-export lines `:25-28`, `:33`, `:54`, `:58`, `:61`;
  `block_signing.rs` and `builder_signing.rs` become empty and are deleted, `aggregation_signing.rs`
  keeps only `is_aggregator`, `sync_signing.rs` is deleted.
- `crates/signer/tests/no_direct_composite_signer_outside_signer.rs:33,60-62` — **keep the FORBIDDEN
  symbol list as a tripwire.** It is a string-grep guard; after deletion it still passes and now
  additionally prevents reintroduction. Update its doc comment (`:33`) to say the symbols no longer
  exist and the entries are reintroduction guards.

**Implementation sketch:**
1. **RED (deletion form):** `rg "crypto::sign_|crypto::signing::sign_|crypto::RawSigner" crates bin -g '*.rs'`
   excluding `crates/crypto` → the only hits are the three FORBIDDEN string literals in the guard
   test, which are data, not calls. Paste into the PR.
2. Delete the functions and the trait; delete the in-file test modules that RF2-07's classification
   table marked *drop* or *ported*.
3. Replace `signing.rs:8`'s local `DOMAIN_BEACON_ATTESTER` with the `eth_types` import; verify the
   byte values are identical (`[0x01,0,0,0]`) before deleting.
4. Prune `lib.rs` re-exports; delete now-empty modules.
5. Update the guard test's doc comment.
6. **GREEN:** RF2-07's KAT file is untouched and still green — that is the proof no coverage was lost.

**Acceptance criteria:**
- [ ] `rg "^pub fn sign_" crates/crypto/src` returns exactly one hit: `sign_voluntary_exit`.
- [ ] `rg "RawSigner"` returns zero hits workspace-wide.
- [ ] Exactly one `DOMAIN_BEACON_ATTESTER` definition exists workspace-wide, in `eth_types`.
- [ ] `is_aggregator`, `compute_domain`, `compute_signing_root`, `sign_voluntary_exit`,
      `capella_capped_fork_version` all still exported; `bin/rvc-keygen` builds unchanged.
- [ ] `no_direct_composite_signer_outside_signer.rs` is green with its symbol list intact and its
      doc comment updated to describe the tripwire role.
- [ ] **Test-count delta stated and justified:** expected ≈ −60 to −90, every one of them appearing
      in RF2-07's classification table as either *ported* (already re-added in RF2-07, so the net
      across the two PRs is ≈ 0) or *dropped-as-self-consistency*. No test disappears without a row
      in that table.
- [ ] Standing invariant green.

**Risks:**
- Any exception RF2-07 handed over (a KAT that could not be reproduced through `LocalSigner`) keeps
  its free function alive. Enumerate exceptions explicitly; more than one or two means RF2-07 was
  under-done and this issue should bounce back rather than delete a vector.

---

### Issue RF2-09: Delete slashing generation 1 — `is_safe_to_sign` / `is_safe_to_propose`

- **Points:** 3
- **Scope:** 1.5–2 days
- **Type:** deletion
- **Plan item:** B4 (first third)
- **Findings:** F49, F127
- **Blocked by:** **A2 (Phase 1)** — conformance + proptests must already drive `stage_* → commit/discard`
- **Blocks:** RF2-10; E1 (P4)
- **Stream:** A

**Description:**
Three public generations of the most safety-critical logic in the workspace coexist, and that is the
direct cause of the drift Phase 1's A1 repaired: the EIP-3076 watermark-equality fix landed in the
dead check paths and not in production `stage_*`. Generation 1 is `is_safe_to_sign` (`db.rs:934`)
and `is_safe_to_propose` (`db.rs:1257`) — pure rule evaluation with no write, and a complete second
implementation of the attestation and block rules. Every caller is a test (36 sites, all inside
`db.rs`'s own test module). Delete both, and with them one of the three rule copies E1 would
otherwise have to reconcile in Phase 4.

**Files to touch (verified):**
- `crates/slashing/src/db.rs`
  - `is_safe_to_sign` `:934-~1070` and `is_safe_to_propose` `:1257-~1320` — delete.
  - the `test_is_safe_to_sign_*` / `test_is_safe_to_propose_*` cluster (from `:2565`, ~36 call
    sites) — see the porting rule below.
  - any private helper that only these two used (`clippy -D warnings` will name them).

**Implementation sketch:**
1. **RED (deletion form):** `rg "is_safe_to_sign|is_safe_to_propose" crates bin -g '*.rs'` → all hits
   inside `crates/slashing/src/db.rs`, all inside `#[cfg(test)]`. Paste into the PR **together with
   the A2 conformance run output** showing the production stage path green — that is the evidence
   this deletion is safe, not the caller count.
2. Walk the ~36 test cases and classify each against the A2 conformance suite:
   - covered by a conformance case → **delete**, citing the conformance case name;
   - not covered → **port to `stage_*` + `discard`** in `crates/slashing/tests/stage.rs` (a check
     without a write is `stage` followed by `discard`), because an uncovered EIP-3076 rule case is a
     coverage gap regardless of which API expressed it.
   The classification table goes in the PR description.
3. Delete the two functions and their tests.
4. **GREEN:** conformance + proptests + `tests/stage.rs` green.

**Acceptance criteria:**
- [x] `rg "is_safe_to_sign|is_safe_to_propose"` returns zero hits workspace-wide.
- [x] Every deleted test case is either named against a covering conformance case or has a ported
      equivalent in `crates/slashing/tests/stage.rs` — one table row each.
- [x] The EIP-3076 conformance suite and `proptest_slashing.rs` are green on the stage path and
      **unmodified by this PR** (if they needed changing, generation 1 was load-bearing and this
      issue must stop).
- [x] Two rule implementations remain (`stage_*` and `check_and_record_*`), down from three; RF2-10
      removes the second.
- [x] **Test-count delta stated and justified:** expected ≈ −25 to −36 *deleted-because-covered*,
      plus *ported* additions in `tests/stage.rs`. Net delta near zero is the healthy outcome; a
      large negative delta with few ports means the classification was too generous.
- [x] Standing invariant green.

**Risks:**
- If A2 has not actually retargeted the conformance suite (e.g. it landed partially), this issue
  deletes rule coverage. The entry check is mechanical: `crates/slashing/tests/conformance.rs` must
  contain no `check_and_record` calls (currently 2) and no test-local watermark `HashMap`. Verify
  before starting; if it fails, this issue is blocked, not adjustable.

---

### Issue RF2-10: Reduce `check_and_record_*` to a thin `stage + commit` wrapper; drop `_client_cn`

- **Points:** 3
- **Scope:** 1.5–2 days
- **Type:** refactor
- **Plan item:** B4 (second third)
- **Findings:** F49
- **Blocked by:** RF2-09
- **Blocks:** RF2-11; E1 (P4)
- **Stream:** A

**Description:**
`check_and_record_block` (`db.rs:1341`) and `check_and_record_attestation` (`db.rs:1523`) are
generation 2: a third full copy of the EIP-3076 rules, wrapped in one SQLite transaction. They also
carry a dead `_client_cn` parameter kept "for call-site compatibility with the … test harness"
(`db.rs:1325`, `:1494`), and `check_and_record_attestation`'s FU-32/FU-33 doc block is
copy-pasted twice (`:1468-1490` and `:1491-1521`).

**Decision (made, not deferred): reimplement as a thin `stage_* → commit` wrapper rather than
delete.** Deletion would force rewriting ~127 call sites into two-step stage/commit sequences, which
is a large mechanical diff with real transcription risk in the safety-critical test corpus, and it
would split this issue again. A wrapper deletes the rule copy — the actual goal — while keeping the
call sites compiling. Drop `_client_cn` from the signature in the same PR: it is one argument
removed at ~127 sites, and leaving it means the next reader still has to ask what it does.

**Files to touch (verified):**
- `crates/slashing/src/db.rs`
  - `check_and_record_block` `:1341-~1466` → `stage_block(...)?.commit()`; signature loses
    `_client_cn: &str` (`:1343`).
  - `check_and_record_attestation` `:1523-~1714` → `stage_attestation(...)?.commit()`; signature
    loses `_client_cn` (`:1525`); delete the duplicated doc block, keeping one copy.
  - the doc note at `:1325`/`:1494` explaining `_client_cn`, and the related note at `:5381`.
  - call sites inside `db.rs`'s test module: 25 (`check_and_record_block`) + 62
    (`check_and_record_attestation`).
- `crates/slashing/tests/` call sites: `gvr_recheck_m6.rs` (21), `conformance.rs` (2 — should already
  be zero after A2; if not, this issue is blocked, see RF2-09's risk), `migration.rs` (8),
  `proptest_slashing.rs` (16), `stage.rs` (15).
- External call sites: `crates/signer/src/lib.rs:2904` (test).

**Implementation sketch:**
1. **RED:** add a test asserting the wrapper is *behaviourally identical* to the old implementation
   on a matrix of cases — same accept/reject decision, same error variant, same rows written, same
   single-transaction atomicity. Run it against the old implementation first (it must pass), then
   against the wrapper.
2. Replace both bodies with `stage + commit`. Preserve the transaction semantics exactly: the old
   functions took one `Immediate` transaction covering check-and-write, and `stage_*` + `commit`
   must give the same guarantee. **This is the one place in the issue where a semantics change would
   be a slashing bug** — verify the staged-row lifetime holds the same lock.
3. Mechanically drop `_client_cn` at every call site (`sed`-able; review the diff as a pure argument
   removal).
4. Delete the duplicated doc block.
5. **GREEN:** conformance + proptests + `gvr_recheck_m6` + `migration` + `stage` all green with no
   assertion changes — only argument-list edits.

**Acceptance criteria:**
- [ ] `check_and_record_block` / `check_and_record_attestation` bodies are each under ~15 lines and
      contain no rule logic — a reviewer can see they only call `stage_*` and `commit`.
- [ ] Exactly **one** EIP-3076 rule implementation remains in `crates/slashing` (`stage.rs`),
      demonstrated by grep for the surround/surrounded/double-vote SQL.
- [ ] `rg "_client_cn"` returns zero hits in `crates/slashing`.
- [ ] The FU-32/FU-33 doc block appears once.
- [ ] Transaction atomicity is unchanged — named test asserting check-and-write remain a single
      `Immediate` transaction.
- [ ] **Test-count delta stated and justified:** expected ≈ 0 (call-site argument edits only), plus
      +1 to +3 *newly added* equivalence/atomicity tests. Any negative delta must be justified
      individually.
- [ ] Standing invariant green.

**Risks:**
- **Atomicity regression is the failure mode to fear.** If `stage_* → commit` does not hold the same
  lock across the check and the write, this "pure refactor" opens a double-sign window under
  concurrency. Phase 1's A3 pipeline tests (concurrent-signer with conflicting data) are the
  guardrail — they must be green, and the PR must say so explicitly.
- ~127 call-site edits invite a mis-paste. Do the `_client_cn` removal as a separate commit within
  the PR so the reviewer can read it as a mechanical diff.

---

### Issue RF2-11: Demote `record_attestation` / `record_block` to documented test-seeding helpers

- **Points:** 2
- **Scope:** 1–1.5 days
- **Type:** refactor
- **Plan item:** B4 (final third)
- **Findings:** F49
- **Blocked by:** RF2-10
- **Stream:** A

**Description:**
`record_attestation` (`db.rs:805`) and `record_block` (`db.rs:1227`) are generation 1's write half:
unconditional INSERTs with no rule check. They contain no rule logic, so they are not a correctness
risk the way RF2-09/10's targets were — but they are a public API that writes slashing history
*without checking it*, which is a footgun sitting in the crate's front door. Every caller is a test:
29 + 7 external for attestations, 32 + 1 external for blocks, where the external ones
(`crates/rvc/src/doppelganger_adapter.rs:124-136`, `crates/rvc/src/config/builder.rs:1018`,
`crates/rvc/src/keymanager_adapters.rs:2708-2709`, `crates/signer/src/lib.rs:1883`) all seed history
for a test fixture.

**Decision (made, not deferred): keep them callable but rename and mark them as seeding-only**, via
`#[doc(hidden)]` plus a `seed_` prefix (`seed_attestation` / `seed_block`) and a doc comment stating
they bypass all EIP-3076 checks and exist for test fixtures. Do **not** introduce a `test-utils`
Cargo feature here: that means Cargo.toml edits in `crates/rvc` and `crates/signer`, and C7 in
Phase 3 is the item that standardises the feature name workspace-wide. If a feature gate is wanted
later, C7 adds it using its own name.

**Files to touch (verified):**
- `crates/slashing/src/db.rs` — rename `record_attestation` `:805` → `seed_attestation`,
  `record_block` `:1227` → `seed_block`; add `#[doc(hidden)]` and the bypass warning to both;
  update the 61 in-file test call sites.
- `crates/rvc/src/doppelganger_adapter.rs:124,134,135,136` — test seeding, rename call sites.
- `crates/rvc/src/config/builder.rs:1018` — test seeding, rename call site.
- `crates/rvc/src/keymanager_adapters.rs:2708,2709` — test seeding, rename call sites; also the
  prose reference at `:528`.
- `crates/signer/src/lib.rs:1883` — test seeding, rename call site.
- `crates/slashing/src/db.rs:1068-1069` — doc comment referencing "concurrent `record_attestation`
  or `record_block` write"; update the names.

**Implementation sketch:**
1. **RED:** none needed beyond the existing suite — this is a rename plus a documentation contract.
   Add one test asserting the seeding helpers *do not* perform rule checks (seed a double vote
   successfully), pinning the documented contract so nobody later "fixes" them into checking.
2. Rename, add `#[doc(hidden)]` and the warning doc.
3. Update all 69 call sites.
4. **GREEN:** unchanged behaviour; `cargo doc` no longer advertises the helpers on the public page.

**Acceptance criteria:**
- [ ] `rg "\brecord_attestation\b|\brecord_block\b"` returns zero hits workspace-wide (comments
      included).
- [ ] `seed_attestation` / `seed_block` carry `#[doc(hidden)]` and a doc comment stating they bypass
      EIP-3076 checks and are for test fixtures only.
- [ ] A named test pins the no-check contract.
- [ ] The **documented** `SlashingDb` surface for writing history is `stage_* → commit` and
      `check_and_record_*`. `seed_attestation`/`seed_block` remain `pub` (callers in `crates/rvc` and
      `crates/signer` tests need them) but are `#[doc(hidden)]` with the stated bypass contract, so
      they do not appear in `cargo doc` — they are the only other row-writing entry points and are
      test-fixture-only by contract.
- [ ] **Test-count delta stated and justified:** expected ≈ 0 (renames only) plus +1 *newly added*
      contract test.
- [ ] Standing invariant green.

**Risks:**
- Low. The main hazard is a missed call site in a `#[cfg(test)]` block that only compiles under a
  feature combination CI does not run; `cargo clippy --workspace --all-targets --all-features`
  covers it.

---

### Issue RF2-12: Set watermarks from interchange maxima on import

- **Points:** 3
- **Scope:** 1.5–2 days
- **Type:** feature
- **Plan item:** B5 (first half)
- **Findings:** F52, F127
- **Blocked by:** **A1 + A2 (Phase 1)**
- **Blocks:** RF2-13
- **Stream:** A

**Description:**
The plan pre-commits to wiring the watermark subsystem rather than deleting it: Phase 1's A1/A2
test-pin stage-path watermark semantics, and the 38 minimal-strategy conformance cases depend on
watermark maxima — deleting would invalidate those tests and weaken minimal-format EIP-3076
interchange import safety. Today `set_block_watermark` (`db.rs:1832`), `set_attestation_watermark`
(`:1882`) and their getters have zero non-test callers, so the watermark queries the production
signing path runs on **every single sign** (`stage.rs:348-362`, `:482-512`) always return `None`.
This issue makes interchange import populate them from the imported maxima — the "minimal" strategy
the conformance suite currently simulates by hand.

**This is the phase's highest-risk issue**: it is the only one that changes what production refuses
to sign.

**Files to touch (verified):**
- `crates/slashing/src/db.rs`
  - `import` `:1124-…` — after the rows are inserted, for each pubkey set the block watermark to
    `MAX(slot)` and the attestation watermark to `(MAX(source_epoch), MAX(target_epoch))` from the
    imported data, inside the same transaction as the import so a partial import cannot leave
    watermarks ahead of rows.
  - `set_block_watermark` `:1832`, `set_attestation_watermark` `:1882` — these already enforce
    raise-only; confirm the import path handles `WatermarkLowered` (re-importing an older
    interchange must not error the whole import, or must, by an explicit documented choice).
- `crates/slashing/src/error.rs:50` — `WatermarkLowered`, `NoWatermarksSet`, `BelowBlockWatermark`,
  `BelowAttestation*Watermark` become reachable; ensure their messages are operator-legible.
- `crates/slashing/tests/conformance.rs` — the minimal-strategy cases are the oracle. After A2 they
  drive the real DB; this issue must not need to modify them.
- `crates/rvc/src/keymanager_adapters.rs:511` (`import_interchange`) — no signature change expected;
  confirm the keymanager import path reaches `SlashingDb::import`.

**Implementation sketch:**
1. **RED:** a test that imports a minimal-format interchange and asserts (a) the watermarks are set
   to the maxima, and (b) a subsequent `stage_attestation` at or below the target watermark is
   blocked while one above is allowed. Both must fail before the change.
2. **Before writing the implementation, run the 38 minimal-strategy conformance cases and record
   which ones currently pass by accident** (because watermarks are always `None`). That list is the
   real specification for this issue.
3. Populate watermarks inside the import transaction.
4. Decide and document the re-import-older-interchange policy (recommend: watermarks stay raised,
   the import succeeds, matching raise-only semantics; a lowered maximum is not an error because
   EIP-3076 import is additive).
5. **GREEN:** conformance suite green *without modification*; the new tests pass.

**Acceptance criteria:**
- [ ] Importing an EIP-3076 interchange sets block and attestation watermarks from the imported
      maxima, atomically with the row inserts.
- [ ] The 38 minimal-strategy conformance cases pass against real watermark code with **no changes
      to `conformance.rs`**.
- [ ] A named test proves the A1 interaction explicitly: after importing an interchange whose
      maximum target epoch is `T`, signing an attestation with target epoch `T` is **blocked**
      (watermark equality, per A1's `<=`) and target `T+1` is allowed.
- [ ] Re-importing an older interchange does not lower watermarks and does not fail the import (or
      fails with a documented, tested error — one branch, stated).
- [ ] The `WatermarkLowered` / `BelowBlockWatermark` / `BelowAttestation*Watermark` error messages
      name the pubkey and the offending value.
- [ ] **Test-count delta stated and justified:** expected +4 to +8 *newly added*; zero deletions.
- [ ] Standing invariant green; Phase 1's A3 pipeline tests green.

**Risks:**
- **The A1 interaction is the thing to get right.** Setting `att_target` to the interchange maximum,
  combined with A1's `<=` equality blocking, means a validator cannot sign at the maximum target
  epoch present in its own imported interchange. This is very likely correct minimal-strategy
  EIP-3076 — an imported interchange is a claim about what was already signed — but it is a real
  behaviour change for an operator who imports and immediately expects to attest in the same epoch.
  **Demonstrate it against the conformance suite's minimal-strategy cases; do not assert it.** If
  the conformance cases disagree, that is signal: triage the divergence before changing production
  code, exactly as A2's guidance says.
- Release-note this: interchange import now constrains signing more tightly than before.
- If the minimal-strategy conformance cases turn out to require a strategy the current watermark
  schema cannot express, this issue rises to 5 and should be split (import-side vs enforcement-side).

---

### Issue RF2-13: `rvc slashing prune` subcommand; record the wire-not-delete decision

- **Points:** 2
- **Scope:** 1–1.5 days
- **Type:** feature
- **Plan item:** B5 (second half)
- **Findings:** F52
- **Blocked by:** RF2-12
- **Blocks:** F3 (P5) must carry the new subcommand
- **Stream:** A

**Description:**
With watermarks populated (RF2-12), `prune_below_watermarks` (`db.rs:1976`) becomes meaningful and
`RVC_SLASHING_DB_PRUNE_TOTAL` (`crates/metrics/src/definitions.rs:135`) can finally increment. Add an
operator-facing `rvc slashing prune` subcommand so the pruning `ARCHITECTURE.md:552` advertises is
actually reachable, and record in `ARCHITECTURE.md` why the subsystem was wired rather than deleted.

**Files to touch (verified):**
- `bin/rvc/src/main.rs` — add a `Slashing { #[command(subcommand)] … }` variant to `Commands`
  (`:41`, alongside `Start` `:43`, `VoluntaryExit` `:394`, `PrepareExit` `:437`, `SubmitExit` `:480`)
  with a `Prune` subcommand taking `--slashing-db-path` and a `--dry-run` flag.
- New `bin/rvc/src/commands/slashing.rs` (next to the existing command modules) implementing the
  handler.
- `crates/slashing/src/db.rs:1976` — `prune_below_watermarks` is called as-is; add nothing.
- `ARCHITECTURE.md:552` — keep the "Pruning — Watermark-based pruning" claim but make it accurate
  (name the subcommand), and add a short rationale paragraph: the subsystem was wired rather than
  deleted because Phase 1's A1/A2 test-pin stage-path watermark semantics and the 38
  minimal-strategy conformance cases depend on watermark maxima.

**Implementation sketch:**
1. **RED:** a CLI-level test (`assert_cmd` / `CARGO_BIN_EXE`) asserting (a) `rvc slashing prune`
   against a **missing** path exits non-zero and creates no file, and (b) against a seeded DB with
   watermarks, deletes the expected rows and prints the counts.
2. Implement the handler using `SlashingDb::open_with_create_info` (`db.rs:110`) and **hard-error
   when `created_fresh` is true** — mirroring `reject_accidental_fresh_create`
   (`crates/rvc/src/config/builder.rs:81`). Delete the accidentally created file on that path, as
   `remove_accidental_fresh_db` (`builder.rs:102`) does.
3. Surface `SlashingError::NoWatermarksSet` as a clear operator message ("no watermarks set — import
   an interchange first"), not a stack trace.
4. Implement `--dry-run` by counting without deleting.
5. Update `ARCHITECTURE.md:552` with the rationale.
6. **GREEN:** the prune metric increments in a scrape after a real prune.

**Acceptance criteria:**
- [ ] `rvc slashing prune --slashing-db-path <p>` prunes rows below watermarks and reports counts.
- [ ] **Running prune against a path with no existing DB is a hard error and leaves no file behind**
      — named test.
- [ ] `--dry-run` reports what would be deleted and deletes nothing — named test.
- [ ] `RVC_SLASHING_DB_PRUNE_TOTAL` is non-zero after a real prune (scrape assertion).
- [ ] `NoWatermarksSet` produces an actionable operator message.
- [ ] `ARCHITECTURE.md` records the wire-not-delete decision with the A1/A2 dependency as its stated
      rationale.
- [ ] **Test-count delta stated and justified:** expected +4 to +6 *newly added*; zero deletions.
- [ ] Standing invariant green.

**Risks:**
- **A prune that creates a DB is a slashing footgun** of the same class as `--init-slashing-db`; the
  hard-error acceptance criterion above is the mitigation and must not be softened for convenience.
- Pruning is destructive and irreversible. Recommend the handler print the row counts and require
  either `--dry-run` first or a `--yes` confirmation; pick one at kickoff and document it.
- Phase 5's F3 restructures `Commands` into `Start(StartArgs)` with flatten groups — keep the new
  variant's shape simple (an args struct, not 10 inline fields) so F3 inherits something it can move
  without redesigning.

---

### Issue RF2-14: Micro-deletions in slashing — `MigrationError`; reader delegates to SQL `MAX`

- **Points:** 1
- **Scope:** 0.5 days
- **Type:** deletion
- **Plan item:** B11 (slashing half; the `OrchestratorError` half is folded into RF2-01)
- **Findings:** F56, F57
- **Blocked by:** none — safe to land out of band, ahead of the RF2-09 chain
- **Stream:** A

**Description:**
Two independent small fixes. (1) `SlashingError` defines both `MigrationError(String)` and
`MigrationFailed(String)`; every construction site in the crate uses `MigrationFailed` exclusively,
and `MigrationError` is fabricated only inside `bin/rvc-signer`'s test module as a stand-in generic
DB error — yet downstream code must reason about both (`bin/rvc-signer/src/service.rs:410` comments
"DatabaseError, MigrationError, etc."). (2) `SlashingDbReader::last_signed_attestation`
(`reader.rs:80`) materialises every attestation row for a validator and computes the max in Rust,
while `SlashingDb::last_signed_attestation_epoch` (`db.rs:1745`) already does it with
`SELECT MAX(target_epoch) … WHERE pubkey = ?1` against the covering index. The doppelganger crate
calls this on startup for every monitored validator.

**Files to touch (verified):**
- `crates/slashing/src/error.rs:13` — delete `MigrationError(String)`.
- `bin/rvc-signer/src/http_api/response.rs:266,278` — switch the two test constructions to
  `MigrationFailed` (or `DatabaseError`).
- `bin/rvc-signer/src/service.rs:410` — fix the comment listing the variants.
- `crates/slashing/src/reader.rs:80-88` — replace the `get_attestations(...)` fetch-and-fold with a
  delegation to `self.last_signed_attestation_epoch(pubkey)`, **after** the existing pinned-GVR
  fail-closed gate (`:56-78`) which must be preserved verbatim.

**Implementation sketch:**
1. **RED (deletion form):** `rg "MigrationError" crates bin -g '*.rs'` → hits only the definition,
   the two rvc-signer test constructions and the one comment.
2. Delete the variant; repoint the two tests; fix the comment.
3. Replace the reader's fold with the delegation; the fail-closed GVR gate and its four `return None`
   paths stay byte-identical.
4. Add a test that the reader returns the same value as before on a multi-row history, and that a
   DB error still yields `None` (fail-closed).
5. **GREEN.**

**Acceptance criteria:**
- [x] `SlashingError` has exactly one migration-failure variant, `MigrationFailed`.
- [x] `SlashingDbReader::last_signed_attestation` issues one `MAX` query and fetches no rows —
      verifiable by reading the diff.
- [x] The pinned-GVR fail-closed gate is unchanged (diff shows no edit above `reader.rs:79`).
- [x] Named tests: equivalent result on multi-row history; `None` on DB error.
- [x] **Test-count delta stated and justified:** expected ≈ 0, plus +2 *newly added* reader tests.
- [x] Standing invariant green.

**Risks:** none identified. The GVR gate is the only sensitive part and it is explicitly untouched.

---

### Issue RF2-15: Retire the v1 proto from `crates/grpc-signer`; port `tonic_limits_m10` to v2

- **Points:** 3
- **Scope:** 1.5–2 days
- **Type:** deletion
- **Plan item:** B10 (first third)
- **Findings:** F79, F35
- **Blocked by:** none — **the plan's stated prerequisite is already satisfied** (see Plan
  correction 1: `GrpcRemoteSigner::connect` already uses the v2 `ListPublicKeys` at
  `client.rs:161-168`)
- **Blocks:** RF2-17; C4 (P3); D4 (P4)
- **Stream:** B — **on the phase critical path**

**Description:**
`crates/grpc-signer/src/lib.rs:18-23` re-exports the full v1 surface — `SignerServiceClient`,
`SignerService`/`SignerServiceServer`, `SignRequest`/`SignResponse`,
`PartialSignRequest`/`PartialSignResponse` — under a comment saying it is "kept for the v1
server/trait types used in tests and downstream". Production no longer uses it. Keeping the raw-root
`SignRequest` client in the default public API of the production client crate re-opens the C-2/C-3
oracle path for accidental use, which is the very thing `client.rs`'s compile-time test exists to
prevent. Delete it, and drop the v1 `tonic_build` invocation from the crate's `build.rs`.

**Files to touch (verified):**
- `bin/rvc-signer/tests/tonic_limits_m10.rs` — **port this first, and port it to v2, not to
  `bin/rvc-signer`'s v1 stubs.** It currently uses `grpc_signer::{SignerServiceClient, SignRequest}`
  (`:23`, `:31`, `:162`, `:200`, `:269`) *and* `rvc_signer_bin::{SignerService, SignerServiceServer}`
  (`:25`, `:128`). Porting it onto v1 stubs here would make RF2-17 pay the same cost again. The test
  asserts tonic decode-size limits; rebuild it on a v2 RPC with an oversized payload
  (`SignBeaconBlockRequest` with a large body is the natural substitute).
- `crates/grpc-signer/src/lib.rs` — delete the `pub mod signer` arm inside `pub mod proto` (`:3-5`)
  and the v1 re-export block (`:16-23`); delete the v1-accessibility unit tests in the `#[cfg(test)]`
  module
  (`:33+`, e.g. `test_v1_list_public_keys_request_accessible`).
- `crates/grpc-signer/build.rs` — delete the v1 `tonic_build::configure()…compile_protos(&[proto_v1])`
  block (lines 7-18) and its stale ISSUE-1.9 comment; keep the v2 block.
- `crates/grpc-signer/src/client.rs:30-31` — the comment noting v1 removal from the connect path can
  be simplified now that v1 is gone entirely.

**Implementation sketch:**
1. **RED:** port `tonic_limits_m10.rs` to v2 in its own commit and prove it still fails for the right
   reason (oversized payload rejected by the decode limit) before touching `grpc-signer`.
2. `rg "grpc_signer::(SignerServiceClient|SignerService|SignerServiceServer|SignRequest|SignResponse|PartialSign)" crates bin`
   → after the port, expect zero hits. Paste into the PR.
3. Delete the re-exports, the `proto::signer` module and the v1 tests.
4. Delete the v1 compilation from `build.rs`; confirm `crates/grpc-signer`'s `OUT_DIR` no longer
   contains `signer.rs`.
5. **GREEN:** `crates/grpc-signer` compiles one proto; `GrpcRemoteSigner::connect` and all v2 signing
   RPCs unchanged.

**Acceptance criteria:**
- [ ] `crates/grpc-signer` compiles exactly one proto file (`signer.v2.proto`); `build.rs` has one
      `tonic_build` invocation.
- [ ] `rg "grpc_signer::.*Sign(Request|Response)\b"` returns zero hits workspace-wide.
- [ ] `tonic_limits_m10.rs` exercises a v2 RPC and still asserts the decode-size limit; it no longer
      references `grpc_signer`'s v1 exports **or** `rvc_signer_bin`'s v1 `SignerService`/`Server`
      (so RF2-17 does not have to touch it).
- [ ] `GrpcRemoteSigner::connect` behaviour is unchanged — existing connect tests green, unmodified.
- [ ] **Test-count delta stated and justified:** expected ≈ −3 (the v1 type-accessibility unit tests
      in `lib.rs`, *deleted-with-the-dead-code*) and ≈ 0 for `tonic_limits_m10` (ported, same
      assertion count).
- [ ] Standing invariant green.

**Risks:**
- The v2 substitute for the decode-limit test must actually exceed the limit at the same layer.
  If the v2 request types cap payload size earlier (via typed SSZ fields), the test may need a
  different oversized field; budgeted, but if no v2 RPC can express the oversized case the test's
  intent changes and that needs calling out rather than quietly weakening the assertion.

---

### Issue RF2-16: Port the DVT peer client to the v2 `PeerSignerService`

- **Points:** 3
- **Scope:** 1.5–2 days
- **Type:** bugfix
- **Plan item:** B10 (unlisted prerequisite — see Plan correction 2)
- **Findings:** F35 (adjacent)
- **Blocked by:** none
- **Blocks:** RF2-17; C4 (P3)
- **Stream:** B — **on the phase critical path**

**Description:**
Discovered while grounding B10: `bin/rvc-signer/src/dvt/peer_client.rs:10-11` imports the **v1**
`peer_signer_service_client::PeerSignerServiceClient` and the untyped `PartialSignRequest`, and
`GrpcPeerRequester::request_partial` (`:263-294`) calls `client.partial_sign(req)` on it. But the
server side registers only the **v2** peer service (`bin/rvc-signer/src/main.rs:795`,
`PeerSignerServiceServerV2`), and `peer_service.rs:40-44` implements only v2. No v1
`PeerSignerService` server impl exists anywhere in the workspace.

Two consequences. First, v1 proto compilation cannot leave `bin/rvc-signer/build.rs` until this is
ported, so RF2-17 is blocked. Second, DVT partial-signing requests dial
`/signer.PeerSignerService/PartialSign` against a server that serves only
`/signer.v2.PeerSignerService/*` — a real defect, though a **liveness** one (partial signing returns
`Unimplemented`) rather than a safety one, and confined to the `dvt` feature.

**Files to touch (verified):**
- `bin/rvc-signer/src/dvt/peer_client.rs`
  - imports `:10-11` → `crate::proto::signer_v2::peer_signer_service_client::PeerSignerServiceClient`
    and the typed request types.
  - `GrpcPeerRequester` struct `:110`, `connect` `:115`, `PeerRequester for GrpcPeerRequester`
    `:263-294` — `request_partial` currently takes `signing_root: &[u8;32]` + `pubkey: &[u8;48]` and
    builds a raw-root `PartialSignRequest`. The v2 service takes **typed** duty payloads
    (`PartialSignBeaconBlockRequest` / `PartialSignAttestationDataRequest` /
    `PartialSignSyncCommitteeRequest`, `proto/signer.v2.proto:138-140`), so the `PeerRequester` trait
    signature must carry the duty, not a precomputed root.
- `bin/rvc-signer/src/backend/dvt.rs:18` — `PeerRequester` trait definition; `:48`, `:74` — the
  `Option<Arc<dyn PeerRequester>>` holders. The trait's `request_partial` signature changes.
- `bin/rvc-signer/src/main.rs:933-948` — `build_peer_connect_infos` / `GrpcPeerRequester::connect`
  wiring; expected to be signature-compatible.
- `bin/rvc-signer/src/dvt/peer_service.rs:196-500` — read-only reference for the v2 server contract
  each request type must satisfy.
- `bin/rvc-signer/tests/dvt_partial_sign_v2.rs` and `dvt_sni_pinning_l1.rs` — the v2 server-side
  tests; extend `dvt_sni_pinning_l1.rs`'s harness (it already stands up
  `PeerSignerServiceServerV2`, `:156`) into an end-to-end client→server round trip.

**Implementation sketch:**
1. **RED:** an end-to-end test standing up the v2 peer server (reuse `dvt_sni_pinning_l1.rs`'s
   harness) and driving it through `GrpcPeerRequester::request_partial`. It must fail today with
   `Unimplemented` — that failure is the proof the defect is real, and it belongs in the PR
   description.
2. Widen `PeerRequester::request_partial` to carry the duty payload rather than a precomputed root
   (block / attestation data / sync-committee), matching the three v2 RPCs. This is the design
   decision in the issue: the v2 peer service computes the root server-side by design (the same
   C-2/C-3 fix as the main signing path), so a raw-root client API cannot be preserved.
3. Update `GrpcPeerRequester` to select the right v2 RPC per duty type.
4. Update the DVT backend call sites in `backend/dvt.rs`.
5. **GREEN:** the round-trip test passes; existing DVT server-side tests unchanged.

**Acceptance criteria:**
- [ ] `rg "proto::signer::" bin/rvc-signer/src` returns zero hits (all DVT code on v2).
- [ ] An end-to-end test drives `GrpcPeerRequester` against a v2 `PeerSignerServiceServerV2` and gets
      a valid partial signature — the test that fails with `Unimplemented` before this change.
- [ ] `PeerRequester::request_partial` carries a typed duty payload; no raw 32-byte signing root
      crosses the DVT client API.
- [ ] `cargo build --features dvt` and `cargo test --features dvt` green.
- [ ] SNI pinning (`dvt_sni_pinning_l1.rs`) and allow-list behaviour unchanged.
- [ ] **Test-count delta stated and justified:** expected +2 to +4 *newly added* round-trip tests;
      zero deletions.
- [ ] Standing invariant green (including `--all-features`).

**Risks:**
- This is scope the plan did not list, and it is a behaviour fix inside a deletion phase. It is here
  only because RF2-17 and C4 cannot proceed without it. If the team prefers, it can be split out as
  its own tracked bug — but then RF2-17 and C4 inherit the block.
- The `PeerRequester` signature change ripples into `backend/dvt.rs`'s threshold-signing logic.
  If that logic assumes a precomputed root shared across peers (likely, for threshold consistency),
  reconciling it with server-side root computation is the part that could push this to 5 points.
  **Check `backend/dvt.rs:48-100` at kickoff**; if the threshold logic needs the root, the honest
  answer may be that each peer must derive the identical root from the identical typed payload,
  which is fine but needs an explicit equality test across peers.
- DVT is behind a non-default feature; confirm CI runs `--all-features` or this lands untested.

---

### Issue RF2-17: Retire the v1 proto from `bin/rvc-signer`; delete `proto/signer.proto`

- **Points:** 3
- **Scope:** 1.5–2 days
- **Type:** deletion
- **Plan item:** B10 (final third)
- **Findings:** F35, F79
- **Blocked by:** RF2-15, RF2-16
- **Blocks:** C4 (P3), D4 (P4)
- **Stream:** B — **critical path terminus**

**Description:**
The v1 `SignerService` impl (`bin/rvc-signer/src/service.rs:459-478`) returns
`Status::unimplemented` from all three methods and is not registered on the live listener (the SS-1
fix), yet the trait impl, the `lib.rs` v1 re-exports, ~90 lines of v1 unit tests asserting
`Unimplemented` (`service.rs:1252-1289`, `:1596-1620`), the `audit/mod.rs` "backward-compat
re-exports for the v1 handler", and the v1 proto compilation all remain. The stated justification is
a hypothetical future off-by-default insecure listener (ADR-010) that is explicitly "NOT implemented
here". With RF2-15 and RF2-16 done, nothing in the workspace needs v1 — delete it and the proto file
itself, so C4 can compile signer.v2.proto exactly once.

**Files to touch (verified):**
- `bin/rvc-signer/src/service.rs` — the v1 `impl SignerService` block `:459-478` and its ADR-010
  comment block `:444-457` (which also carries the `eth_types::insecure` reference RF2-04 fixes —
  coordinate: whichever lands second finds the other's edit already applied); v1 unit tests
  `:1252-1289` and `:1596-1620`.
- `bin/rvc-signer/src/lib.rs:37` — `pub use proto::signer::peer_signer_service_server::{PeerSignerService, PeerSignerServiceServer};`
  and the v1 `SignerService`/`SignerServiceServer` re-exports — delete; keep the v2 exports at
  `:49-50`.
- `bin/rvc-signer/src/audit/mod.rs:5-13,19-24` — the "Backward-compatibility re-exports" section
  exists for the v1 handler. Keep any re-export that a v2 path still uses (`extract_client_cn`,
  `log_audit`, `AuditEntry`, `now_rfc3339` are used by the v2 handlers too — **verify each before
  deleting**); delete only the ones that fall to zero callers, and rewrite the module doc so it stops
  citing v1 as the reason.
- `bin/rvc-signer/tests/v1_raw_root_bypass.rs` — delete. Its only assertion is that the v1 handler
  returns `Unimplemented`; with v1 gone there is nothing to assert. The standing guard against
  raw-root RPCs is `bin/rvc-signer/tests/no_raw_root_path.rs`, which greps the generated
  `signer.v2.rs` for a `signing_root` field (`:11-31`) and is unaffected — cite it in the PR so the
  reviewer can see no security coverage is lost.
- `bin/rvc-signer/build.rs` — delete the v1 `compile_protos(&[proto_v1])` block and the `proto_v1`
  binding; keep the v2 block.
- `proto/signer.proto` — delete the file (both `build.rs` references are now gone).
- `bin/rvc-signer/src/lib.rs` `proto` module — drop the `pub mod signer { tonic::include_proto!("signer"); }`
  arm.

**Implementation sketch:**
1. **RED (deletion form):** `rg "proto::signer::|include_proto!\(\"signer\"\)|signer\.proto" crates bin`
   → after RF2-15 and RF2-16, expect hits only in the files listed above. Paste into the PR. If any
   hit is outside that list, stop — a consumer was missed.
2. Delete the v1 trait impl, its comment block and its tests.
3. Prune `lib.rs` re-exports and the `proto::signer` module arm.
4. Audit `audit/mod.rs` re-export by re-export; keep the ones v2 uses, delete the rest, rewrite the
   doc.
5. Delete `v1_raw_root_bypass.rs`, citing `no_raw_root_path.rs`.
6. Delete the v1 block from `build.rs`, then `proto/signer.proto`.
7. **GREEN:** `cargo build --release --all-features`; the server starts and serves v2 only.

**Acceptance criteria:**
- [ ] `proto/` contains exactly `duty_tracker.proto` and `signer.v2.proto`.
- [ ] Neither `build.rs` in the workspace references `signer.proto`; each has one `tonic_build`
      invocation per proto it still compiles.
- [ ] `rg "proto::signer::signer_service_server"` returns zero hits; `service.rs` retains exactly one
      `impl … for SignerServiceImpl` gRPC trait block, the v2 one at `:485` (`SignerServiceV2`).
- [ ] `no_raw_root_path.rs` is green and unmodified — the raw-root guard survives the deletion.
- [ ] `audit/mod.rs`'s module doc no longer cites the v1 handler; every surviving re-export has a
      named v2 consumer listed in the PR.
- [ ] The server starts and all v2 signing integration tests (`sign_*_v2.rs`, nine files) pass
      unchanged.
- [ ] **Test-count delta stated and justified:** expected ≈ −8 to −12 — the v1 `Unimplemented`
      assertions in `service.rs` and the whole of `v1_raw_root_bypass.rs`, all
      *deleted-with-the-dead-code*, with `no_raw_root_path.rs` named as the surviving guard for the
      security intent.
- [ ] Standing invariant green, including `--all-features`.

**Risks:**
- ADR-010 is the stated reason v1 was kept. Deleting it is a documented decision reversal, not an
  oversight — reference ADR-010 in the PR and state that the insecure listener it anticipated was
  never built and can be rebuilt on v2 if it ever is. Get that acknowledged rather than discovered.
- `audit/mod.rs`'s re-exports are the likely trap: they read as "v1 compatibility" but several are
  used by v2 handlers. Deleting the whole section breaks the build; the per-symbol audit is the work.
