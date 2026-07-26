# Phase 4 — Core Consolidation (Themes D + E)

> The largest and highest-risk phase of the workspace refactoring plan: exactly one implementation each
> of EIP-3076 rules, signing-root derivation, the safe-signing flow, the gate error taxonomy, the
> rvc-signer sign policy, the grpc RPC pipeline, the beacon retry loop, and the beacon mock.
>
> Authoritative inputs: [`../refactoring-plan.md`](../refactoring-plan.md) §3 Themes D/E, §4 Phase 4,
> §6 Validation Strategy; [`../refactoring-findings.json`](../refactoring-findings.json).
> All `file:line` references verified against HEAD `develop` (`a7f8cdf`) on 2026-07-25.

---

## Phase Overview

- **Goal:** collapse the consensus-critical duplication. After this phase a slashing-rule fix touches
  one site, a signing-root change touches one function, a beacon endpoint addition touches two places,
  and the two safe-signing stacks are one core with one (fail-closed) timeout policy.
- **Issue count:** 30 issues, **73 points**.
- **Estimated duration:** ~55 working days single-stream; **~28–30 days with 2 developers**
  (Stream A 37 pts, Stream B 36 pts). Critical path is Stream A at 21 points (~16 days).
- **Entry criteria:**
  - Phases 1–3 complete. Specifically: **A1/A2/A3** (stage-path watermark fix + retargeted conformance
    and proptest suites + pipeline slashing tests) are the guardrails this entire phase leans on;
    **B4** (slashing gen-1/2 API deletion), **B7** (crypto free `sign_*` deletion + KAT migration),
    **B10** (v1 proto retirement) and **B2** (`build_all` deletion) are hard prerequisites named per issue.
  - Workspace green on the standing invariant: `cargo fmt --all -- --check`,
    `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`,
    `crates/architecture-tests`.
- **Exit criteria — the phase gate is a named-oracle checklist, each mapped to the issue that delivers it:**

| Phase-gate oracle (plan §4 Phase 4) | Delivered by |
|---|---|
| Slashing conformance suite green **on the stage path** (post-E1, post-E2, post-E3) | RF4-16, RF4-17, RF4-19, RF4-20 |
| Old-vs-new SQL equivalence proptest green on random histories | RF4-18 |
| A3 pipeline slashing tests (double-vote across two `process_slot`s, fail-closed DB error) still green | RF4-06 (and every Stream A issue as a standing gate) |
| **D2 late-completion double-sign test**: timeout fires, remote sign completes late, subsequent conflicting sign for the same slot/epoch is blocked | RF4-06 |
| Cross-transport signature-equality test: identical request over gRPC / HTTP / DVT → identical signature | RF4-10 |
| Signing KATs incl. fork boundaries + EIP-7044 Capella cap, green against the shared helper | RF4-01, RF4-02 |
| Metric-scrape smoke test: `sign_total` / `sign_duration_seconds` / `sign_errors_total` non-zero after a sign (A7's helper survives absorption) | RF4-09 |
| Beacon wiremock suites green incl. the 400-partial-failure path | RF4-21 |
| `rg "impl BeaconNodeClient for" \| wc -l` == 3 (BnManager, BeaconClient, shared mock) | RF4-25 |
| Full workspace green on the standing invariant | all |

---

## Plan Corrections (verified against HEAD — read before scoping)

These are places where the plan text or a cited finding no longer matches the tree. Each is folded into
the issue that owns it; they are listed here so the phase is not scoped off stale text.

1. **E5's "blanket impl" is not implementable as written.** The plan says "role traits … with blanket
   impl" and "blanket impl keeps `Arc<dyn BeaconNodeClient>` users compiling; delete mocks incrementally
   per crate". A blanket `impl<T: DutiesProvider + …> BeaconNodeClient for T` overlaps every existing
   `impl BeaconNodeClient for X` (coherence error E0119), including the two real impls at
   `crates/bn-manager/src/manager.rs:1238` (BeaconClient) and the BnManager impl — which would force all
   16 conversions into a single PR. **RF4-23 uses supertrait composition instead**
   (`trait BeaconNodeClient: DutiesProvider + BlockProducer + … {}` plus an empty
   `impl BeaconNodeClient for X {}` per type). `dyn BeaconNodeClient` stays object-safe, and the
   per-crate incremental deletion the plan asks for actually works. This is what makes RF4-24 and RF4-25
   separable issues.
2. **F104's "51-method god-trait" is wrong.** `crates/bn-manager/src/traits.rs:22-166` declares **25**
   async methods. F59's "26-method" is essentially right. Scope E5 to 25.
3. **E4's "add jitter, uniform 429/Retry-After" is already done.** `calculate_backoff`
   (`crates/beacon/src/client.rs:1294-1309`) applies ±25% jitter, and `retry_after_delay` (`:1283`) is
   already called by all four loops (`:849`, `:969`, `:1097`, `:1216`). E4's real remainder is loop
   unification, the `traced()` helper for the 7 `telemetry::inject_trace_context` sites, URL encoding,
   and `monitoring.rs:170` sharing the policy. Points reduced accordingly (RF4-21 + RF4-22 = 5, not 8).
4. **E1's "EIP-3076 rules ×3" is down to one live copy by the time Phase 4 starts.** B4 deletes
   `db.rs:934` (`is_safe_to_sign`), `:1257` (`is_safe_to_propose`), `:1341`/`:1523`
   (`check_and_record_*`). E1's **L** rating is therefore carried by the **18 watermark SQL literals**
   and the **seam design**, not by deduplication — which is why RF4-16/17 split cleanly at 3 + 2.
   (The plan's E1 text says 15 literals; `rg "watermark_type = '" crates/slashing/src` measures **18**
   at HEAD. Measured, not transcribed — scope RF4-17 to 18.)
5. **F60 is deliberately absent from this phase.** The brief lists F60 (beacon `client.rs` 75% inline
   tests) among Phase 4's findings, but the plan's appendix dispositions it to **H1 (Phase 6)** — test
   relocation, not consolidation. No RF4 issue owns it; that is correct, not an omission. RF4-21/22 touch
   `client.rs` production code only and must not move its test module (doing so would collide with H1).
6. **SEC-2 has already landed on `develop`; E8c is not blocked.** The team-lead brief marks E8c
   "gated on SEC-2". Verified landed: `crates/rvc/src/liveness_loop.rs` exists and
   `bin/rvc/src/main.rs:1421` calls `rvc::liveness_loop::spawn_liveness_loop`;
   `main.rs:1346-1421` constructs `ForwardWindowMachine`; `main.rs:1355` states the one-shot
   `DoppelgangerService` "is no longer the production mechanism";
   `crates/rvc/src/config/builder.rs:264-273` documents `build_doppelganger_service` as legacy/tests-only.
   (SEC-1b also landed: `crates/rvc/src/deletion_denylist.rs`.) E8c's residue is therefore only the
   single `MonotonicEpochClock`, the shared restart-skip predicate, and `startup.rs:139` — see RF4-30.
7. **D7's package rename is deferred, not omitted.** `crates/signer` is package `rvc-signer`;
   `bin/rvc-signer` is package `rvc-signer-bin` with a *binary* named `rvc-signer`. Renaming ripples
   across the workspace and is naturally resolved by Phase 5's **F2**, which promotes the bin's lib to
   `crates/signer-server`. RF4-13 deletes the re-export modules and documents the collision; the rename
   itself is explicitly out of Phase 4 scope.

---

## Assumptions

- **P4-A1 — Point scale.** 1/2/3 points; ~1 point ≈ 0.5–1 working day; points cover coding + tests +
  review. No issue exceeds 3. Plan items rated **L** (D2, E1, E2, E5) are split into ordered chains.
- **P4-A2 — TDD per CLAUDE.md.** Every issue names its RED test first. For consolidation issues the
  RED case is usually a *characterization* test that pins current behavior before the move.
- **P4-A3 — Streams are file-disjoint.** Stream A owns `crates/crypto`, `crates/signer`,
  `bin/rvc-signer`, `crates/grpc-signer`, `crates/secret-provider`, `crates/timing`. Stream B owns
  `crates/slashing`, `crates/beacon`, `crates/bn-manager`, `crates/rvc`, `crates/builder`,
  `crates/duty-tracker`, `crates/doppelganger`, `bin/rvc` + `bin/rvc/tests`. The one contract between
  them is the `SlashingDb::stage_block` / `stage_attestation` **signature**, which Stream B must not
  change (RF4-16/17/18 are internal-only rewrites).
- **P4-A4 — Per-pubkey backend resolution already exists.** `CompositeSigner::has_local_key`
  (`crates/crypto/src/composite_signer.rs:130`) and `has_grpc_remote` (`:72`) let RF4-06 resolve the
  timeout policy per pubkey without a new API. This is why RF4-06 stays at 3 points.
- **P4-A5 — Metrics continuity.** A7 (Phase 1) delivers a shared gRPC sign-metrics recording helper.
  Phase 4 **absorbs** it into the SignPlan dispatcher; it is never deleted and its scrape test never
  goes red (RF4-09 acceptance criterion).

---

## Phase Summary

| Issue | Title | Pts | Type | Plan item | Blocked by | Stream |
|-------|-------|----:|------|-----------|------------|--------|
| RF4-01 | `signing_root_for` core in crypto (Capella cap inside) | 3 | refactor | D1 | B7 (P2), C3 (P3) | A |
| RF4-02 | Repoint all signing-root consumers; delete capped-fork call sites | 3 | refactor | D1 | RF4-01 | A |
| RF4-03 | Signing error taxonomy: `SlashingBlocked` vs `CommitFailed` | 3 | refactor | D3 | — | A |
| RF4-04 | `sign_nonslashable` helper in `SignerService` (7 methods → wrappers) | 2 | refactor | D2 | RF4-02 | A |
| RF4-05 | Extract `sign_slashable` core + `TimeoutPolicy`; `SigningGate` delegates | 3 | refactor | D2 | RF4-03, RF4-04 | A |
| RF4-06 | `SignerService` on the shared core; fail-closed remote timeout | 3 | refactor | D2 | RF4-05 | A |
| RF4-07 | Shared `classify()` for both rvc-signer mappers; re-home `SigningError` | 2 | refactor | D3 | RF4-03, RF4-06 | A |
| RF4-08 | `grpc_common`: 5 duplicated validators + proto decode blocks | 3 | refactor | D4 | B10 (P2) | A |
| RF4-09 | Transport-neutral SignPlan engine; gRPC/HTTP/DVT consume it | 3 | refactor | D4 | RF4-06, RF4-07, RF4-08 | A |
| RF4-10 | Builder fork-version divergence fix + cross-transport equality test | 2 | bugfix | D4 | RF4-09, RF4-02 | A |
| RF4-11 | grpc-signer `sign_rpc` helper + `connect()` channel dedupe | 3 | refactor | D5 | RF4-02 | A |
| RF4-12 | `ValidatorSigner` returns `crypto::Signature`; delete delegation impl | 2 | refactor | D6 | RF4-06 | A |
| RF4-13 | Naming cleanup: delete re-export modules, signer-hierarchy doc | 1 | chore | D7 | RF4-05 | A |
| RF4-14 | secret-provider shared `fetch_provider_keys` pipeline | 3 | refactor | E9 | — | A |
| RF4-15 | `SlotClock` derived methods become default trait methods | 1 | refactor | E8d | — | A |
| RF4-16 | `rules.rs` pure checks + history query seam; `stage_*` delegates | 3 | refactor | E1 | A2 (P1), B4 (P2) | B |
| RF4-17 | `WatermarkKind` + `read_watermark`/`raise_watermark` helpers | 2 | refactor | E1 | RF4-16 | B |
| RF4-18 | Targeted SQL history impl + old-vs-new equivalence proptest | 3 | perf | E3 | RF4-16, RF4-17 | B |
| RF4-19 | `db/` split part 1: `open.rs` + `migrations.rs` | 3 | refactor | E2 | RF4-18 | B |
| RF4-20 | `db/` split part 2: `interchange.rs`, `watermarks.rs`, `records.rs` | 3 | refactor | E2 | RF4-19 | B |
| RF4-21 | Beacon single retry engine (4 loops → 1) | 3 | refactor | E4 | — | B |
| RF4-22 | `traced()` helper + URL encoding + monitoring shares retry policy | 2 | refactor | E4 | RF4-21 | B |
| RF4-23 | Role traits + supertrait `BeaconNodeClient` + shared configurable mock | 3 | refactor | E5 | RF4-21 | B |
| RF4-24 | Delete the 9 hand-rolled mocks in `crates/rvc` | 2 | testing | E5 | RF4-23 | B |
| RF4-25 | Delete remaining hand mocks; kill default-impl footgun; passthrough macro | 2 | testing | E5 | RF4-24, RF4-28 | B |
| RF4-26 | BnManager `submit()` helper + batched `record_outcomes` | 2 | refactor | E6 | RF4-23 | B |
| RF4-27 | Proposer failover: `BeaconBlockAdapter` takes `Arc<dyn BeaconNodeClient>` | 3 | bugfix | E7 | RF4-23 | B |
| RF4-28 | Builder seam: 2-method BN trait + 1-method registration signer trait | 2 | refactor | E8a | RF4-23 | B |
| RF4-29 | duty-tracker `from_response` constructors + `clear_cache` sync coverage | 1 | bugfix | E8b | — | B |
| RF4-30 | Doppelganger: single `MonotonicEpochClock` + shared restart-skip predicate | 2 | refactor | E8c | B2 (P2) | B |

**Total: 30 issues, 73 points. Stream A = 37, Stream B = 36.**

## Execution Plan

Two streams run concurrently on disjoint files. IDs ascend in **per-stream execution order**
(RF4-01…15 = Stream A, RF4-16…30 = Stream B); the two sequences are independent.

**Stream A (signing stack)** — one root derivation, then one safe-signing core, then one transport
policy. The ordering is deliberate: the error taxonomy (RF4-03) lands **before** the shared signing core
(RF4-05/06) because D2's fail-closed remote-timeout semantics are expressed in terms of D3's
`CommitFailed` variant. `crates/secret-provider` (RF4-14) and `crates/timing` (RF4-15) are unrelated to
the signer files and are the stream's slack work — schedule them whenever a signer PR is in review.

**Stream B (slashing / beacon / duty crates)** — the slashing chain (RF4-16 → RF4-20) is strictly
serial and is the stream's spine; the beacon chain (RF4-21 → RF4-27) can start immediately in parallel
if a third developer is available, but with two developers Stream B interleaves them.

**Critical path (21 pts, ~16 days):**
`RF4-01 → RF4-02 → RF4-04 → RF4-05 → RF4-06 → RF4-07 → RF4-09 → RF4-10`

## Dependency Map

```text
Stream A ─────────────────────────────────────────────────────────────────────────
  RF4-01 ──▶ RF4-02 ──┬──▶ RF4-04 ──▶ RF4-05 ──▶ RF4-06 ──┬──▶ RF4-07 ──▶ RF4-09 ──▶ RF4-10
   (D1a)      (D1b)   │      (D2a)      (D2b)      (D2c)  │     (D3b)      (D4b)      (D4c)
                      │                   ▲               ├──▶ RF4-12 (D6)
       RF4-03 (D3a) ──┴───────────────────┘               └──▶ RF4-13 (D7)
                      └──▶ RF4-11 (D5)
       RF4-08 (D4a) ─────────────────────────────────────────▶ RF4-09
       RF4-14 (E9)   RF4-15 (E8d)          [independent — stream slack]

Stream B ─────────────────────────────────────────────────────────────────────────
  RF4-16 ──▶ RF4-17 ──▶ RF4-18 ──▶ RF4-19 ──▶ RF4-20        [slashing spine, serial]
   (E1a)      (E1b)      (E3)       (E2a)      (E2b)

  RF4-21 ──▶ RF4-22                                          [beacon retry]
   (E4a)      (E4b)
     └──▶ RF4-23 ──┬──▶ RF4-24 ──▶ RF4-25                    [BN trait split]
          (E5a)    │     (E5b)      (E5c)  ▲
                   ├──▶ RF4-26 (E6)        │
                   ├──▶ RF4-27 (E7)        │
                   └──▶ RF4-28 (E8a) ──────┘
  RF4-29 (E8b)   RF4-30 (E8c)              [independent]

Cross-phase: RF4-01←B7 · RF4-08←B10 · RF4-16←A2+B4 · RF4-30←B2 · all←A1/A3
```

## Phase Risk Flags

- **RF4-06 is the single most dangerous change in the whole plan.** Porting `SigningGate`'s
  discard-staged-row-on-timeout (`gate.rs:292-302`, `:434-444`) verbatim to `SignerService`'s remote
  backends creates a double-sign path: the remote may already have signed when the timeout fires, and a
  discarded row lets a *conflicting* retry through. The shared core must default to **retain/commit on
  timeout**, with discard permitted only when the pubkey resolves to a provably in-process backend.
- **`crates/signer/src/lib.rs` is a Stream A hotspot** (RF4-02, RF4-04, RF4-05, RF4-06, RF4-12 all edit
  it). Land them strictly in order; do not parallelize within the stream.
- **`crates/slashing/src/db.rs` is a Stream B hotspot** and RF4-19/20 are pure code motion — any other
  slashing PR in flight will conflict irreconcilably. Freeze the slashing spine while E2 lands.
- **RF4-10 and RF4-27 are deliberate behavior changes** (builder fork version on non-mainnet; proposer
  block production now honoring failover). Both need release notes.
- **RF4-18 changes SQL under the signing mutex.** The equivalence proptest is not optional — it is the
  only thing standing between a query rewrite and a missed surround.

---

## Issues

### Issue RF4-01: `signing_root_for` core in crypto with the Capella cap inside

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** D1 · **Findings:** F38, F128-adjacent L-11 (from F127)
- **Blocked by:** B7 (P2 — crypto free `sign_*` deletion, KATs migrated to `compute_domain`/
  `compute_signing_root`), C3 (P3 — `ForkName` as single fork source)
- **Blocks:** RF4-02, RF4-11

**Files:**
- new `crates/crypto/src/signing_root.rs` (module `signing_root_for`)
- `crates/crypto/src/typed_signer.rs:171`, `:330` — the two existing derivation copies
- `crates/crypto/src/voluntary_exit_signing.rs:15` — the EIP-7044 Capella cap and its
  caller-obligation doc block
- `crates/crypto/src/lib.rs` — re-export

**What / why:** Domain + signing-root derivation exists in 3+ live copies and the EIP-7044 Capella
fork-version cap for voluntary exits in 4 (F38). Every fork rollout has to find all of them. This issue
builds the single function — `signing_root_for(duty: &DutyRef<'_>, ctx: &SigningCtx) -> Root` — with the
Capella cap applied **inside** it, so the cap can never be forgotten by a caller. No consumer is
repointed here; that is RF4-02, kept separate so the KATs prove the new function is byte-identical to the
old sites *before* anything moves.

**Implementation sketch:**
1. Define `SigningCtx { fork_schedule, genesis_validators_root }` and a `DutyRef` enum covering the ten
   duties (attestation, block, blinded block, randao, sync message, sync selection, aggregate-and-proof,
   Electra aggregate-and-proof, contribution-and-proof, voluntary exit, builder registration).
2. `signing_root_for` resolves `ForkName::from_epoch` → `fork_version` (via C3's `ForkSchedule::entries()`),
   applies the EIP-7044 cap for `VoluntaryExit` only, computes the domain, and returns
   `compute_signing_root(object, domain)`.
3. Builder registration keeps its genesis-fork-version rule (the divergence RF4-10 resolves) as an
   explicit, documented arm — not an accident of which transport called it.
4. Re-home B7's migrated KATs onto `signing_root_for`; each asserts the same byte vector it asserted
   against `compute_domain`/`compute_signing_root`.

**Acceptance criteria:**
- [x] `signing_root_for` covers all ten duties and is the only place `capella_capped_fork_version` logic
      lives inside `crates/crypto`.
- [x] EIP-7044 KATs (pre-Capella, Capella, Deneb, Electra epochs) produce byte-identical roots to the
      current `voluntary_exit_signing.rs` output.
- [x] Fork-boundary KATs for attestation and block roots are byte-identical to
      `crates/signer/src/lib.rs:265-283` / `:496-503` output at each fork transition epoch.
- [x] The caller-obligation doc block on the old cap helper is deleted (the obligation no longer exists).
- [x] Standing invariant green.

**TDD test plan** (`crates/crypto/src/signing_root.rs` `#[cfg(test)]`):
- **RED first:** `test_signing_root_for_voluntary_exit_deneb_epoch_uses_capella_fork_version` — fails
  until the cap is inside the new function.
- `test_signing_root_for_matches_legacy_attestation_derivation_at_every_fork_boundary`
- `test_signing_root_for_matches_legacy_block_derivation_at_every_fork_boundary`
- `test_signing_root_for_voluntary_exit_pre_capella_uses_actual_fork_version`
- `test_signing_root_for_builder_registration_uses_genesis_fork_version`
- `test_eip7044_kat_vectors_unchanged` (table-driven, reference-client vectors per H5 policy)

**Risks:** If C3 has not delivered `ForkSchedule::entries()`, the fork resolution has to be hand-written
here and re-pointed later — confirm C3 landed before starting, otherwise this is a 5.

---

### Issue RF4-02: Repoint every signing-root consumer; delete the capped-fork call sites

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** D1 · **Findings:** F38
- **Blocked by:** RF4-01 · **Blocks:** RF4-04, RF4-10, RF4-11

**Files:**
- `crates/signer/src/lib.rs:262` (attestation domain block), `:496-503` (block), and the derivation
  blocks inside the other 8 sign methods (`:627`, `:680`, `:732`, `:786`, `:841`, `:907`, `:969`,
  `:1016`, `:1073`)
- `crates/crypto/src/typed_signer.rs:171`, `:330`
- `crates/crypto/src/remote_signer.rs:326` (Web3Signer request builders)
- `crates/grpc-signer/src/client.rs:207` (`make_fork_info`), `:216` (`fork_id`)
- `bin/rvc-keygen/src/exit.rs:127`
- test mocks that derive roots independently

**What / why:** Makes RF4-01's function the only derivation in the workspace. This is the issue where
the duplication actually disappears, so it is where `rg` proves it.

**Implementation sketch:**
1. Replace each consumer's inline `ForkName::from_epoch` → `fork_version` → `compute_domain` →
   `compute_signing_root` sequence with one `signing_root_for` call.
2. Delete `capella_capped_fork_version` call sites; keep the helper only if C3/eth-types still needs it.
3. Update test mocks to call the shared helper so a mock can no longer disagree with production.

**Acceptance criteria:**
- [x] `rg 'compute_domain\(' crates/ bin/ --type rust` returns only `signing_root.rs` and its tests
      (plus any deliberate non-signing use, enumerated in the PR).
- [x] `rg 'capella_capped_fork_version'` returns zero production call sites.
- [x] All existing signer tests pass **unchanged** — no test may be edited to accommodate a new root.
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_all_sign_methods_derive_roots_via_signing_root_for` — an assertion-by-construction
  test that injects a `SigningCtx` whose fork schedule differs from the default and asserts every
  `SignerService` method's root matches `signing_root_for`'s output (fails while any method derives inline).
- `test_grpc_signer_fork_info_matches_shared_derivation`
- `test_web3signer_request_root_matches_shared_derivation`
- `test_keygen_exit_root_unchanged_after_repoint` (KAT)

**Risks:** Mechanical but wide; compiler-driven. The one judgement call is builder registration —
leave its current per-transport behavior **unchanged** here and fix it deliberately in RF4-10.

---

### Issue RF4-03: Signing error taxonomy — `SlashingBlocked` vs `CommitFailed`

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** D3 · **Findings:** F41, F36
- **Blocked by:** none · **Blocks:** RF4-05, RF4-07

**Files:**
- `crates/signer/src/error.rs` (74 lines — `SigningGateError`)
- `crates/signer/src/lib.rs:48` (`SignerError`), `:395-406` and `:558`-region commit-failure arms
- `crates/crypto/src/signer_trait.rs:9`

**What / why:** `SignerService` currently maps a **commit** failure to
`SignerError::SlashingProtectionBlocked` (`lib.rs:405`) — the same variant it uses when the slashing DB
*rejected* the sign. Those two have opposite retry semantics: a slashing rejection must never be retried,
while a commit failure means nothing was written and a retry **with the same signing root** is safe.
`SigningGate` already distinguishes them (`BlockedBySlashingDb` vs `SlashingDbCommitFailed`,
`gate.rs:283`/`:313`). This issue makes the distinction exist on both sides, because RF4-06 expresses the
fail-closed remote-timeout rule in terms of it.

**Implementation sketch:**
1. Give `SignerError` distinct variants: `SlashingBlocked(#[source] SlashingError)` (never retry) and
   `CommitFailed { signing_root: Root, #[source] source: SlashingError }` (same-root retry safe).
2. Fix the commit-failure arms at `lib.rs:395-406` (attestation) and the block equivalent to return
   `CommitFailed`, carrying the signing root so a caller can enforce the same-root restriction.
3. Align `SigningGateError` naming with the same two concepts; document the retry contract on both enums
   in one place.
4. Update every caller that matches on the old variants in the same PR.

**Acceptance criteria:**
- [x] A commit failure and a slashing rejection are distinguishable at the VC call site by variant, and a
      test asserts the retry semantics of each (blocked → refuse retry; commit-failed → same-root retry
      permitted, different-root retry refused).
- [x] `CommitFailed` carries the signing root.
- [x] No call site matches on a removed variant (compiler-enforced).
- [x] Standing invariant green.

**TDD test plan** (`crates/signer/src/lib.rs` `#[cfg(test)]`):
- **RED first:** `test_commit_failure_is_not_reported_as_slashing_blocked` — fails today because
  `lib.rs:405` returns `SlashingProtectionBlocked`.
- `test_slashing_rejection_maps_to_slashing_blocked`
- `test_commit_failed_carries_signing_root_for_same_root_retry`
- `test_gate_and_service_error_taxonomies_agree` (table-driven over both enums)

**Risks:** Callers in `crates/rvc/src/orchestrator` and `bin/rvc-signer` match on these variants; the
compiler finds them all, but the PR is wider than the signer crate. Coordinate the touch on
`bin/rvc-signer/src/http_api/response.rs:59,81` with RF4-07 (same file) by landing RF4-03 first.

---

### Issue RF4-04: `sign_nonslashable` helper in `SignerService`

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** D2 (the non-slashable half) · **Findings:** F37, F40 partial
- **Blocked by:** RF4-02 · **Blocks:** RF4-05

**Files:**
- `crates/signer/src/lib.rs:627` (`sign_randao_reveal`), `:680`, `:732`, `:786`, `:841`, `:969`,
  `:1016`, `:1073` — the non-slashable methods
- `crates/signer/src/gate.rs:529` — the reference implementation to mirror

**What / why:** `SigningGate` already has one `sign_nonslashable` helper (`gate.rs:529-...`) that owns
the gate check, the timeout, and uniform error mapping for all 7 non-slashable operations.
`SignerService` has none: each of its non-slashable methods repeats the enablement check, the sign call
(**without a timeout** — the F37 divergence), and its own error mapping. This is the low-risk half of D2
and it lands first so the high-risk slashable core (RF4-05/06) is reviewed on its own.

**Implementation sketch:**
1. Add `SignerService::sign_nonslashable(&self, pubkey, signing_root, op_name) -> Result<Signature, SignerError>`
   mirroring `gate.rs:529`: enablement check → `tokio::time::timeout(self.sign_timeout, signer.sign(..))`
   → uniform mapping. Carry over the gate's documented no-lock / TOCTOU rationale verbatim
   (`gate.rs:508-528`) — non-slashable ops must not take the per-validator lock.
2. Add the `sign_timeout` field + `with_sign_timeout` builder to `SignerService` (default 4s, matching
   `gate.rs:101`). **This closes the "VC path has no sign timeout" half of F37.**
3. Reduce each non-slashable method to root derivation (via RF4-02's helper) + one call.

**Acceptance criteria:**
- [x] All 8 non-slashable `SignerService` methods are ≤ ~10 lines over the shared helper.
- [x] A hung backend causes a non-slashable sign to fail after the configured timeout instead of hanging
      (test with a sleeping mock signer).
- [x] The helper takes no per-validator lock and touches no slashing DB (asserted by a test that would
      deadlock or write a row otherwise).
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_nonslashable_sign_times_out_against_hung_backend` — fails today (no timeout on the
  VC path).
- `test_nonslashable_helper_takes_no_validator_lock`
- `test_nonslashable_helper_writes_no_slashing_row`
- `test_each_nonslashable_method_delegates_to_helper` (error-mapping parity table)

**Risks:** Introducing a timeout on the VC non-slashable path is a real behavior change under a slow
remote signer — release-note it.

---

### Issue RF4-05: Extract the `sign_slashable` core with an explicit `TimeoutPolicy`; `SigningGate` delegates

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** D2 · **Findings:** F37, F40 partial
- **Blocked by:** RF4-03, RF4-04 · **Blocks:** RF4-06, RF4-13

**Files:**
- new `crates/signer/src/core.rs`
- `crates/signer/src/gate.rs:225-344` (`sign_block`), `:371-491` (`sign_attestation`) — the two bodies
  being replaced by delegation
- `crates/signer/src/locks.rs` (per-validator lock map)

**What / why:** The stage → sign → commit/discard triple exists twice with divergent safety features
(F37): the gate has the timeout and `PubkeyScopedDb` auditing, the service has the metrics. This issue
builds the one core — `sign_slashable(stage_fn, signing_root, pubkey, hooks, policy)` owning the
per-validator lock, `spawn_blocking`, `Handle::block_on(timeout(...))`, and the commit/discard decision —
and converts `SigningGate` to it **with its existing semantics preserved bit-for-bit**. The service
conversion is RF4-06, deliberately separate because that is where the semantics change.

The core's timeout behavior is a parameter, not a constant:

```rust
enum TimeoutPolicy {
    /// In-process backend: dropping the future proves no signature was produced.
    DiscardStagedRow,
    /// Remote backend: the signer may already have signed. Retain/commit the
    /// staged row so a conflicting retry is impossible (D3 CommitFailed governs
    /// same-root retry).
    RetainStagedRow,
}
```

**Implementation sketch:**
1. Define the core signature with a `SignHooks` trait (or struct of closures) for the metrics/log
   callbacks so the gate can pass no-ops and the service can pass its `RVC_*` recorders.
2. Move the gate's body into the core, parameterized on `TimeoutPolicy`.
3. `SigningGate::sign_block` / `sign_attestation` become gate-check + one core call with
   `TimeoutPolicy::DiscardStagedRow` — **their observable behavior must not change at all.**
4. Gate gains the metrics hook (the F37 feature it was missing) and the re-check-enablement-under-lock
   the service already has (`lib.rs:300-303`).

**Acceptance criteria:**
- [ ] Every existing `SigningGate` test passes **without modification** — this is the characterization
      oracle for the extraction.
- [ ] The gate's timeout path still discards the staged row, and a test asserts no phantom row remains.
- [ ] The gate now records the same metric families the service records (feature-parity table in the PR
      description, per the plan's acceptance criteria).
- [ ] The gate re-checks enablement under the per-validator lock.
- [ ] `TimeoutPolicy` is an explicit parameter with no default — a new call site cannot get it by accident.
- [ ] Standing invariant green.

**TDD test plan** (`crates/signer/src/core.rs` + existing `gate.rs` tests as characterization):
- **RED first:** `test_core_retain_policy_keeps_staged_row_on_timeout` — the new behavior the core must
  support; fails until `TimeoutPolicy` exists.
- `test_core_discard_policy_rolls_back_staged_row_on_timeout` (gate parity)
- `test_gate_metrics_recorded_on_success_and_on_block` (the F37 gap)
- `test_gate_reenables_check_under_lock`
- `test_gate_behavior_unchanged_full_suite` (existing suite, unmodified)

**Risks:** `Staged*` guards hold a `!Send` `parking_lot::MutexGuard`, so the core must keep everything
inside `spawn_blocking` — the extraction must not accidentally make the closure `async`. If the hook
type forces a lifetime fight, prefer a small `dyn Fn` struct over a generic parameter.

---

### Issue RF4-06: `SignerService` on the shared core with fail-closed remote-backend timeout semantics

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor (safety-critical) · **Stream:** A
- **Plan item:** D2 · **Findings:** F37, F40
- **Blocked by:** RF4-05 · **Blocks:** RF4-07, RF4-09, RF4-12

**Files:**
- `crates/signer/src/lib.rs:238-465` (`sign_attestation`), `:473-626` (`sign_block`)
- `crates/crypto/src/composite_signer.rs:72` (`has_grpc_remote`), `:130` (`has_local_key`)
- `crates/signer/src/core.rs` (from RF4-05)

**What / why:** This is the phase's highest-risk change and its most important safety property.
`SignerService` gains the sign timeout it lacks (F37) by delegating to RF4-05's core — but its backend is
a `CompositeSigner` that routes **some pubkeys to a local key and others to a remote Web3Signer/gRPC
signer**. Porting the gate's discard-on-timeout to a remote backend is a double-sign path: the remote may
already have produced a signature when the 4-second timeout fires, and a discarded staged row would let a
*conflicting* attestation or block through on retry.

The rule this issue implements: **the timeout policy is resolved per pubkey, and the default is
fail-closed.** `TimeoutPolicy::DiscardStagedRow` is used only when `composite_signer.has_local_key(pubkey)`
is true *and* the key is not also served by a remote backend; every other case — including "cannot
determine" — uses `RetainStagedRow`. A post-timeout retry is then either blocked outright (the staged row
is now committed history) or, where the caller can prove it, permitted only for the **same signing root**
via RF4-03's `CommitFailed`.

**Implementation sketch:**
1. Add a small `backend_kind(&self, pubkey) -> BackendKind` resolver over
   `has_local_key` / `has_grpc_remote` / the remote-key map, returning `Unknown` when ambiguous.
2. Map `BackendKind::InProcess → DiscardStagedRow`; everything else (`Remote`, `Unknown`) →
   `RetainStagedRow`. Document the fail-closed direction at the mapping site.
3. Convert `sign_attestation` and `sign_block` to `sign_slashable` calls with the existing metric hooks
   (`RVC_SLASHING_PROTECTION_CHECKS_TOTAL`, `RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS`,
   `RVC_ATTESTATIONS_TOTAL`, `RVC_SIGNING_DURATION_SECONDS`) passed as hooks — no metric may be lost.
4. The service also gains `PubkeyScopedDb` auditing, which the gate already had.

**Acceptance criteria:**
- [ ] **Late-completion test (phase-gate criterion):** with a remote-backed pubkey and a mock signer that
      completes *after* the timeout expires, the first sign returns a timeout error, and a **subsequent
      conflicting sign for the same slot / target epoch is blocked**. This test must be named in the PR
      and must fail if `DiscardStagedRow` is ever used for a remote pubkey.
- [ ] A same-root retry after a timeout is permitted; a different-root retry after a timeout is blocked.
- [ ] An in-process pubkey still discards on timeout (no phantom row) — gate parity preserved.
- [ ] `BackendKind::Unknown` resolves to `RetainStagedRow` (fail-closed), asserted by test.
- [ ] Every metric the service recorded before is still recorded, with identical label values
      (before/after scrape comparison in the PR).
- [ ] **A3's pipeline slashing tests are green**, unmodified.
- [ ] Standing invariant green.

**TDD test plan** (`crates/signer/src/lib.rs` `#[cfg(test)]`):
- **RED first:** `test_remote_backend_timeout_then_late_completion_blocks_conflicting_sign` — the
  phase-gate late-completion test; fails against any discard-on-timeout implementation.
- `test_remote_backend_timeout_retains_staged_row`
- `test_local_backend_timeout_discards_staged_row`
- `test_unknown_backend_kind_defaults_to_retain`
- `test_same_root_retry_after_timeout_permitted`
- `test_different_root_retry_after_timeout_blocked`
- `test_all_signer_metrics_still_recorded_after_core_delegation`

**Risks:** The retain-on-timeout policy costs a missed duty (the slot/epoch is consumed) where the old
service behavior would have retried. That is the correct trade — a missed attestation versus a slashing —
and it must be in the release notes with the operator-visible symptom described.

---

### Issue RF4-07: Shared `classify()` for both rvc-signer error mappers; re-home `SigningError`

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** D3 · **Findings:** F36, F41
- **Blocked by:** RF4-03, RF4-06 · **Blocks:** RF4-09

**Files:**
- `bin/rvc-signer/src/service.rs:399`-region (gRPC `Status` mapping)
- `bin/rvc-signer/src/http_api/response.rs:59`, `:81` (HTTP status mapping)
- `crates/crypto/src/error.rs` (destination for `SigningError`)
- `crates/signer/src/error.rs`

**What / why:** Gate-error sanitization is duplicated between the gRPC and HTTP transports (F36); the two
can drift so the same failure returns different sanitization on different transports. One
`classify(&SigningGateError) -> GateErrClass` in the library, consumed by both mappers, makes drift
impossible. Moving `SigningError` into `crypto/src/error.rs` puts the error next to the trait that
produces it.

**Implementation sketch:**
1. Add `GateErrClass { BlockedByDoppelganger, SlashingBlocked, CommitFailed, KeyNotFound, Internal }`
   and `classify()` in `crates/signer`.
2. Both transports map `GateErrClass` → their status code + sanitized message; neither matches on the
   error enum directly.
3. Move `SigningError` to `crypto/src/error.rs` with a deprecated re-export for one release.

**Acceptance criteria:**
- [ ] Both transport mappers consume `classify()`; neither matches `SigningGateError` variants directly
      (`rg` proof in PR).
- [ ] A table-driven test asserts gRPC and HTTP return *corresponding* statuses for every `GateErrClass`,
      and that no message leaks slashing-DB internals (the existing leak-free assertions in
      `dispatch.rs:395` stay green).
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_grpc_and_http_agree_on_every_gate_error_class` — fails today where the two mappers
  diverge.
- `test_classify_is_exhaustive_over_gate_errors` (compile-time exhaustive match)
- `test_sanitized_messages_are_static_and_leak_free`

**Risks:** Low. The only judgement call is which HTTP status `CommitFailed` maps to; document the choice.

---

### Issue RF4-08: `grpc_common` module — 5 duplicated validators + proto decode blocks

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** D4 · **Findings:** F27
- **Blocked by:** B10 (P2 — v1 proto retirement) · **Blocks:** RF4-09

**Files:**
- `bin/rvc-signer/src/service.rs:324` (`validate_pubkey`), `:332` (`validate_fork_version`),
  `:340` (`validate_gvr`), `:357` (`validate_selection_proof`)
- `bin/rvc-signer/src/dvt/peer_service.rs:105`, `:112`, `:119` — verbatim copies
- new `bin/rvc-signer/src/grpc_common.rs`

**What / why:** `validate_pubkey`, `validate_fork_version` and `validate_gvr` are copy-pasted
character-for-character between `service.rs` and `dvt/peer_service.rs` (F27), together with the proto
decode blocks that follow them. A validation tightening applied to one and not the other is a silent
authorization gap on the other transport.

**Implementation sketch:**
1. Move the validators into `grpc_common.rs`; both services import them. Keep the `Status` return type so
   no call site changes shape.
2. Extract the repeated proto→typed decode blocks (fork info, SSZ body, signing root) into
   `grpc_common::decode_*` functions returning the same `Status` errors.
3. Delete the duplicates; `rg` proves single definition.

**Acceptance criteria:**
- [x] Each validator is defined exactly once (`rg 'fn validate_pubkey'` == 1).
- [x] Existing rejection tests for both `service.rs` and `peer_service.rs` pass unchanged, including the
      length-boundary cases (`test_validate_selection_proof_rejects_short/long/empty`,
      `service.rs:1137-1150`).
- [x] Error strings are byte-identical to the current ones (asserted) so clients see no change.
- [x] Standing invariant green.

**TDD test plan** (`bin/rvc-signer/src/grpc_common.rs` `#[cfg(test)]`):
- **RED first:** `test_dvt_and_signer_service_share_one_pubkey_validator` — a test asserting a single
  definition/behavior; fails while two copies exist.
- `test_validator_error_messages_unchanged` (table of inputs → exact `Status` message)
- `test_decode_fork_info_rejects_short_fork_version`
- `test_decode_rejects_oversized_ssz_body`

**Risks:** B10 must have landed; if the v1 `SignerService` impl (`service.rs:460`) is still compiled it
also carries validator copies and this issue grows.

---

### Issue RF4-09: Transport-neutral SignPlan engine consumed by gRPC, HTTP and DVT

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** D4 · **Findings:** F26, F28
- **Blocked by:** RF4-06, RF4-07, RF4-08 · **Blocks:** RF4-10

**Files:**
- `bin/rvc-signer/src/http_api/dispatch.rs:54` (`Slashing`), `:67` (`SignPlan`), `:82` (`plan_sign`),
  `:198`, `:206` — the engine being promoted
- `bin/rvc-signer/src/service.rs:490-1097` — the 10 v2 handlers
- `bin/rvc-signer/src/dvt/peer_service.rs:236`, `:336`
- `bin/rvc-signer/src/metrics.rs:20`, `:193`; `service.rs:123`, `:210` — A7's metrics helper

**What / why:** The 10 v2 gRPC handlers each repeat a ~55-line prelude + dispatch (F26), and the sign
policy (type → domain → root → slashable?) exists in three transports (F28). `dispatch.rs` already has
the right abstraction — `SignPlan` — but it is HTTP-private. Promoting it to a transport-neutral module
and giving the handlers a `sign_prelude`/`RequestCtx` helper collapses each handler to
request-construction plus one dispatch call, and makes the policy single-sourced.

**Implementation sketch:**
1. Move `SignPlan` / `Slashing` / `plan_sign` into a transport-neutral module; HTTP keeps a thin adapter
   from its `SignRequest` to the neutral input type.
2. Add `RequestCtx` (client CN, fork info, gvr, pubkey) built once by `sign_prelude`, plus
   `dispatch_slashable` / `dispatch_non_slashable` entry points that call RF4-06's core.
3. Convert the 10 v2 handlers and the DVT peer paths to the shared dispatcher.
4. **Absorb A7's metrics recording helper into the dispatcher** so every transport records
   `sign_total` / `sign_duration_seconds` / `sign_errors_total` with the same type×outcome labels — the
   helper moves, it is not reimplemented per transport.

**Acceptance criteria:**
- [ ] Each v2 handler is request-construction + one dispatcher call (target ≤ ~15 lines).
- [ ] gRPC, HTTP and DVT all route through one `plan_sign`; `rg` shows no second domain/root policy in
      `bin/rvc-signer`.
- [ ] **A7's metric-scrape test is green unmodified** — `sign_total`, `sign_duration_seconds` and
      `sign_errors_total` are non-zero after a sign on *each* transport, with identical label sets.
- [ ] Existing v2 handler tests (`service.rs:1296-1628`) pass unchanged.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_grpc_handler_records_sign_metrics_via_shared_helper` — asserts the dispatcher (not
  per-handler code) is the recording site; fails while handlers record inline.
- `test_all_three_transports_produce_identical_sign_plan_for_equivalent_requests`
- `test_dispatcher_preserves_slashable_vs_nonslashable_classification` (table over all 10 duties)
- `test_a7_scrape_test_still_green` (the existing A7 test, re-run in CI as a named gate)

**Risks:** The biggest diff in Stream A. Land it *after* RF4-06 so the dispatcher targets the final core
API, not an intermediate one.

---

### Issue RF4-10: Resolve the builder fork-version divergence + cross-transport signature-equality test

- **Points:** 2 · **Scope:** ~1 day · **Type:** bugfix (deliberate behavior change) · **Stream:** A
- **Plan item:** D4 · **Findings:** F28
- **Blocked by:** RF4-09, RF4-02 · **Blocks:** none

**Files:**
- `bin/rvc-signer/src/service.rs:982`-region (`sign_builder_registration`)
- `bin/rvc-signer/src/http_api/dispatch.rs` (builder arm)
- `bin/rvc-signer/src/dvt/peer_service.rs`
- `crates/crypto/src/signing_root.rs` (RF4-01's builder-registration arm)

**What / why:** The three transports disagree on which fork version a builder registration is signed
with (F28). Per spec, `ValidatorRegistrationV1` is signed with the **genesis** fork version and a zero
genesis-validators-root, independent of the current fork — so at most one of the three is right. This
issue threads the network genesis fork version through all three and pins the result with the phase's
cross-transport oracle.

**Implementation sketch:**
1. Thread the network genesis fork version (from C2's `NetworkPreset`) into `RequestCtx`.
2. `signing_root_for`'s builder arm uses it unconditionally; the transports stop supplying their own.
3. Write the cross-transport equality test as a first-class integration test, not a unit test.

**Acceptance criteria:**
- [ ] **Cross-transport signature-equality test (phase-gate criterion):** the same builder registration
      submitted over gRPC, HTTP and DVT yields byte-identical signatures — and the same test covers at
      least one slashable duty (attestation) and one other non-slashable duty.
- [ ] Mainnet builder-registration signatures are unchanged (KAT); non-mainnet networks change
      deliberately and the change is release-noted.
- [ ] `rg` shows exactly one source for the builder fork version.
- [ ] Standing invariant green.

**TDD test plan** (`bin/rvc-signer/tests/cross_transport.rs`, extending the existing
`bin/rvc-signer/src/cross_transport.rs` harness):
- **RED first:** `test_builder_registration_signature_identical_across_transports` — fails today on
  non-mainnet because of the divergence.
- `test_attestation_signature_identical_across_transports`
- `test_randao_signature_identical_across_transports`
- `test_mainnet_builder_registration_kat_unchanged`

**Risks:** Behavior-visible on testnets — operators running builder registrations on a non-mainnet
network will see different signatures after this lands. Release note required.

---

### Issue RF4-11: grpc-signer `sign_rpc` helper + `connect()` channel dedupe

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** D5 · **Findings:** F70
- **Blocked by:** RF4-02 · **Blocks:** none

**Files:**
- `crates/grpc-signer/src/client.rs:109` (`connect` — TLS/non-TLS channel build),
  `:264-822` — the 10 `TypedSigner` methods (~55 lines each)
- `:207` (`make_fork_info`), `:216` (`fork_id`), `:234` (`ensure_pubkey`), `:242` (`extract_signature`)

**What / why:** Ten near-identical RPC pipelines (F70): each does `ensure_pubkey` → build fork info →
build request → call → `extract_signature` → map error. Adding an eleventh duty means copying 55 lines.
One generic `sign_rpc` helper collapses each method to request construction plus one call.

**Implementation sketch:**
1. `async fn sign_rpc<Req, F, Fut>(&self, ctx, build_req, call) -> Result<Signature, SigningError>`
   owning `ensure_pubkey`, fork-info construction (via RF4-02's shared derivation where applicable),
   the tonic call, `extract_signature` and error mapping.
2. Each `TypedSigner` method becomes request construction + one `sign_rpc` call.
3. Dedupe the TLS and non-TLS channel construction in `connect()` into one builder that applies TLS
   config conditionally.

**Acceptance criteria:**
- [ ] Each of the 10 methods is ≤ ~15 lines.
- [ ] `connect()` has one channel-construction path.
- [ ] Existing grpc-signer tests pass unchanged, including
      `test_grpc_remote_signer_not_implements_raw_signer` (`client.rs:873`) and the redaction tests
      (`:849-866`).
- [ ] Wire-level integration test green against the existing harness.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_all_typed_signer_methods_route_through_sign_rpc` — behavioral proxy: inject a
  failing transport and assert all 10 methods produce the *same* error mapping (fails while each maps
  independently).
- `test_connect_tls_and_plaintext_share_channel_builder`
- `test_ensure_pubkey_rejected_before_rpc_issued` (no network call on unknown key)
- `test_signature_extraction_rejects_wrong_length`

**Risks:** Generic-heavy; if the `Fut` lifetime fight gets expensive, fall back to a macro. Diff size is
the main cost, not conceptual difficulty.

---

### Issue RF4-12: `ValidatorSigner` returns `crypto::Signature`; delete the 200-line delegation impl

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** A
- **Plan item:** D6 · **Findings:** F44
- **Blocked by:** RF4-06 · **Blocks:** none

**Files:**
- `crates/signer/src/traits.rs:17` (trait; `Vec<u8>` returns at `:25`, `:35` and 9 more)
- `crates/signer/src/lib.rs:1138-1337` — the `impl ValidatorSigner for SignerService` delegation block
- orchestrator consumers in `crates/rvc/src/orchestrator/`

**What / why:** Every `ValidatorSigner` method returns `Vec<u8>` while the inherent `SignerService`
method it wraps returns `Signature`, so `lib.rs:1138-1337` is 200 lines of `.to_bytes().to_vec()`
adapters (F44). Typing the trait to `Signature` deletes the whole block; conversion happens once at the
wire boundary.

**Implementation sketch:**
1. Change the trait's 11 return types to `Result<Signature, SignerError>`.
2. Delete the delegation impl; the inherent methods satisfy the trait directly.
3. Add `.to_bytes()` at the actual wire boundaries (beacon submission, gRPC/HTTP response building).
4. Evaluate dropping `#[async_trait(?Send)]` — if the `!Send` constraint is no longer required after
   RF4-06's core owns `spawn_blocking`, drop it; if it still is, document why in one place.

**Acceptance criteria:**
- [ ] `crates/signer/src/lib.rs:1138-1337` is gone; no delegation impl remains.
- [ ] `.to_bytes()` appears only at wire boundaries (enumerated in PR).
- [ ] The `?Send` decision is made and documented either way.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_validator_signer_trait_returns_typed_signature` — a compile-level test
  (`fn _assert<T: ValidatorSigner>()` with a typed binding) that fails while the trait returns `Vec<u8>`.
- `test_trait_and_inherent_methods_are_the_same_function` (behavioral: same input → same signature)
- Existing `test_trait_sign_block_safe_proposal` / `test_trait_sign_attestation_still_works`
  (`lib.rs:2178`, `:2205`) pass with only the type adjusted.

**Risks:** Mechanical and compiler-driven. Consumer count is the only variable.

---

### Issue RF4-13: Naming cleanup — delete the re-export modules, add the signer-hierarchy doc

- **Points:** 1 · **Scope:** ~0.5 day · **Type:** chore · **Stream:** A
- **Plan item:** D7 · **Findings:** F47
- **Blocked by:** RF4-05 · **Blocks:** none

**Files:**
- `crates/signer/src/slashable.rs` (20 lines — doc + `pub use crate::gate::SigningGate;`)
- `crates/signer/src/non_slashable.rs` (25 lines — same shape)
- `crates/signer/src/lib.rs:10-11` (the `pub mod` lines)
- new doc section in `crates/crypto` (signer hierarchy)

**What / why:** `slashable.rs` and `non_slashable.rs` contain no code — only a doc comment and a
re-export of the same `SigningGate` (F47). They read like two modules but are one, and their flow
documentation now duplicates what RF4-05's core owns.

**Scoping decision (recorded per plan-correction #7):** the `rvc-signer` (crates/signer) vs
`rvc-signer-bin` (bin/rvc-signer, binary `rvc-signer`) package-name collision is **not** resolved here.
Phase 5's F2 promotes the bin's lib to `crates/signer-server` and resolves it naturally; renaming twice
is churn. This issue documents the collision instead.

**Implementation sketch:**
1. Fold the useful flow documentation from both modules into the `gate.rs` / `core.rs` module docs
   (RF4-05 already owns the authoritative flow description).
2. Delete both files and the `pub mod` lines; fix any `use rvc_signer::slashable::…` imports.
3. Add a signer-hierarchy doc in `crates/crypto` (`Signer` → `TypedSigner` → `CompositeSigner` →
   `SignerService` / `SigningGate`) and a one-line note on the package-name collision pointing at F2.

**Acceptance criteria:**
- [ ] Both modules deleted; no import breaks.
- [ ] No flow documentation is lost (it moves, verified by reviewer diff).
- [ ] Signer-hierarchy doc exists and names every layer.
- [ ] Standing invariant green.

**TDD test plan:** documentation change — the gate is `cargo doc` building without broken intra-doc
links plus `cargo test --doc`. **RED first:** add `#![deny(rustdoc::broken_intra_doc_links)]` to the
crate and confirm it fails against the stale links before fixing them.

**Risks:** None beyond import churn.

---

### Issue RF4-14: secret-provider shared `fetch_provider_keys` pipeline

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** A
- **Plan item:** E9 · **Findings:** F72
- **Blocked by:** none · **Blocks:** none

**Files:**
- `crates/secret-provider/src/key_source_manager.rs:117-137` (denylist precheck), `:145-155`
  (`JoinSet` spawn — **no per-fetch timeout**), `:157-230` (result handling + metrics)
- `crates/secret-provider/src/refresh.rs:51-91` (the refresh loop), `:88-92` (30s timeout,
  **no metrics at all**)
- `crates/secret-provider/src/metrics.rs`

**What / why:** Boot and refresh implement the same fetch pipeline with **complementary gaps** (F72):
boot has concurrency (`JoinSet`), spans and the `RVC_SECRET_PROVIDER_*` metrics but **no per-fetch
timeout** — a hung provider stalls startup indefinitely; refresh has a 30-second timeout but records
**zero metrics**, so a silently failing refresh is invisible. One instrumented function closes both.
Verified: `rg 'RVC_SECRET_PROVIDER' crates/secret-provider/src/refresh.rs` returns nothing.

**Implementation sketch:**
1. `async fn fetch_provider_keys(provider, denylist, timeout, concurrency) -> ProviderFetchSummary`
   owning: the hex precheck + denylist skip, the `JoinSet` fan-out, the per-fetch
   `tokio::time::timeout`, the `secret_provider.fetch_key` span, and all three metric families.
2. `KeySourceManager::load_all` and `RefreshLoop::refresh` both call it; each keeps only its own
   post-processing (insert into `KeyManager` vs. return new keys).
3. Keep the denylist semantics identical — both the `pubkey_hex` early skip and the post-fetch
   `public_key()` check (boot has both; refresh has only the early skip today, so refresh gains the
   post-fetch check — a fail-closed improvement worth its own test).

**Acceptance criteria:**
- [x] Boot fetch has a per-key timeout: a hung mock provider fails that key and startup continues
      (test asserts bounded wall-clock).
- [x] Refresh emits `RVC_SECRET_PROVIDER_KEYS_LOADED`, `RVC_SECRET_PROVIDER_ERRORS_TOTAL` and
      `RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS` (test asserts counters move).
- [x] Refresh performs the post-fetch denylist check (a key whose listed `pubkey_hex` is absent but whose
      fetched material is denylisted is not returned).
- [x] Existing boot metrics tests (`key_source_manager.rs:835-913`) pass unchanged.
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_boot_fetch_times_out_on_hung_provider` — fails today (no boot timeout).
- `test_refresh_emits_secret_provider_metrics`
- `test_refresh_applies_post_fetch_denylist_check`
- `test_boot_and_refresh_share_one_fetch_pipeline` (both paths produce identical summaries for the same
  provider fixture)
- `test_denylisted_key_skipped_before_fetch_issued` (no provider call made)

**Risks:** The refresh loop's key-set bookkeeping (`known_pubkeys`) differs from boot's; keep that
outside the shared function.

---

### Issue RF4-15: `SlotClock` derived methods become default trait methods

- **Points:** 1 · **Scope:** ~0.5 day · **Type:** refactor · **Stream:** A
- **Plan item:** E8d · **Findings:** F98
- **Blocked by:** none · **Blocks:** none

**Files:**
- `crates/timing/src/clock.rs:10-21` (trait), `:57-140` (`SystemSlotClock` impl),
  `:176-...` (`MockSlotClock` impl)

**What / why:** Both `SlotClock` impls duplicate ~90 lines of identical derived slot math (F98):
`slot_start_time`, `slot_end_time`, `attestation_time`, `time_until_slot`, `time_until_attestation`,
`slot_to_epoch`, `epoch_start_slot` are all pure functions of `genesis_time`, `slot_duration`,
`slots_per_epoch` and `current_time_secs`. A bug fixed in one impl silently persists in the other — and
`MockSlotClock` is what the tests use.

**Implementation sketch:**
1. Keep only `genesis_time`, `slot_duration`, `slots_per_epoch`, `current_time_secs`, `current_slot` as
   required methods.
2. Make the other 7 default methods computed from those.
3. Delete the per-impl duplicates.

**Acceptance criteria:**
- [x] Only the primitive accessors are required trait methods.
- [x] Both impls lose their duplicated math; existing timing tests pass unchanged.
- [x] A single test exercised against **both** impls proves identical derived results for the same inputs.
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_system_and_mock_clocks_agree_on_all_derived_methods` — a table-driven test run
  against both impls; fails if the two ever diverge (write it before the refactor to prove they agree now).
- `test_default_methods_used_when_impl_omits_them`
- Existing `crates/timing` tests pass unchanged.

**Risks:** None. Compiler-driven.

---

### Issue RF4-16: `rules.rs` pure EIP-3076 checks behind a history query seam; `stage_*` delegates

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor (safety-critical) · **Stream:** B
- **Plan item:** E1 · **Findings:** F48, F55
- **Blocked by:** A2 (P1 — conformance/proptests retargeted at `stage_*`), B4 (P2 — gen-1/2 API deleted)
- **Blocks:** RF4-17, RF4-18

**Files:**
- new `crates/slashing/src/rules.rs`
- `crates/slashing/src/stage.rs:347-412` (block rule closure), `:481-618` (attestation rule closure)
- `crates/slashing/src/stage.rs:514-530` (the full-history scan)

**What / why:** With B4 done, `stage_block`/`stage_attestation` hold the only live copy of the EIP-3076
rules — but they are inline closures that interleave SQL with rule decisions, so the rules cannot be
tested or reasoned about apart from a live SQLite connection.

**The seam shape is the load-bearing design decision, and it is made here, not in E3.** The pure
functions must **not** take a materialized `Vec<Row>`, because RF4-18 replaces the full scan with
`EXISTS`/`MIN` queries and would otherwise have to rewrite them. Instead the rules take a query trait:

```rust
trait AttestationHistory {
    fn conflicting_at_target(&self, target: Epoch) -> Result<Option<ExistingAtt>, SlashingError>;
    fn surrounding_exists(&self, source: Epoch, target: Epoch) -> Result<bool, SlashingError>;
    fn surrounded_exists(&self, source: Epoch, target: Epoch) -> Result<bool, SlashingError>;
    fn min_target(&self) -> Result<Option<Epoch>, SlashingError>;
}
trait BlockHistory {
    fn signing_root_at_slot(&self, slot: Slot) -> Result<Option<Option<String>>, SlashingError>;
    fn min_slot(&self) -> Result<Option<Slot>, SlashingError>;
}
```

This issue ships the **full-scan implementation** of those traits — behavior-preserving against
`stage.rs:514-618` — so RF4-18 becomes a pure impl swap and the mandated old-vs-new equivalence proptest
is simply "two impls of one trait, same verdict".

**Implementation sketch:**
1. Define `check_attestation(history, watermarks, candidate) -> Result<AttestationVerdict, SlashingError>`
   and `check_block(...)`, moving the rule logic (double vote, surround, surrounded, target-below-minimum,
   resign/duplicate detection, strict-semantics handling) verbatim.
2. Implement `FullScanAttestationHistory` / `FullScanBlockHistory` over the existing SQL.
3. `stage_block` / `stage_attestation` read watermarks, build the history impl over the open transaction,
   call the rule function, and translate the verdict — **their public signatures do not change** (the
   Stream A contract).
4. Preserve every existing `tracing::debug!(rejection_reason = …)` event; the conformance suite and the
   operator runbooks depend on those exact reason strings.

**Acceptance criteria:**
- [x] `rules.rs` functions are pure over the traits — no `rusqlite` import in `rules.rs` (`rg` proof).
- [x] The seam is the query-trait shape above (not `Vec<Row>`), so RF4-18 can swap implementations without
      touching `rules.rs`.
- [x] **A2's conformance suite (all 76 cases) and the proptests are green on the stage path, unmodified.**
- [x] `rejection_reason` values and the strict-semantics behavior are byte-identical to today.
- [x] Watermark equality (A1's `<=`) is preserved in the extracted rules.
- [x] Standing invariant green.

**TDD test plan** (`crates/slashing/src/rules.rs` `#[cfg(test)]` + existing conformance as oracle):
- **RED first:** `test_check_attestation_is_pure_over_history_trait` — construct an in-memory fake
  history with no database and assert a double vote is detected; fails until the rules are extracted.
- `test_check_attestation_double_vote_surround_surrounded_matrix` (table-driven, mirrors the conformance
  cases)
- `test_check_block_double_proposal_and_resign`
- `test_check_attestation_watermark_equality_blocks` (pins A1)
- `test_rules_verdicts_match_stage_path_on_conformance_corpus` (differential against the pre-refactor
  behavior, run over the A2 corpus)

**Risks:** The highest-stakes refactor in the phase. The conformance suite is the oracle — **if a case
fails, triage the divergence before touching production code** (plan §4 Phase 1 guidance applies here
too). Do not combine with RF4-17.

---

### Issue RF4-17: `WatermarkKind` enum + `read_watermark`/`raise_watermark` helpers

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** E1 · **Findings:** F55
- **Blocked by:** RF4-16 · **Blocks:** RF4-18

**Files:**
- `crates/slashing/src/stage.rs:348-354` (`'block'`), `:482-488` (`'att_source'`), `:498-504`
  (`'att_target'`)
- `crates/slashing/src/db.rs:1832` (`set_block_watermark`), `:1866` (`get_block_watermark`),
  `:1882` (`set_attestation_watermark`), `:1943` (`get_attestation_watermark`), `:1976`
  (`prune_below_watermarks`)

**What / why:** The watermark table is addressed by magic string in **18 places**
(`rg "watermark_type = '"` == 18). A typo in any of them silently disables a watermark check — a
fail-open in the most safety-critical table in the workspace. A `WatermarkKind` enum with
`read_watermark(conn, pubkey, kind)` / `raise_watermark(conn, pubkey, kind, value)` makes the typo
unrepresentable and gives B5's interchange-import wiring one place to call.

**Implementation sketch:**
1. `enum WatermarkKind { Block, AttestationSource, AttestationTarget }` with `as_sql_str()`.
2. Two helpers owning the SELECT and the monotonic-raise UPSERT (raise-only: a watermark must never
   move backwards — assert it).
3. Replace all 18 literal sites.

**Acceptance criteria:**
- [x] `rg "watermark_type = '"` returns exactly one site (inside `as_sql_str`).
- [x] `raise_watermark` is monotonic: a lower value is a no-op (or a typed error), asserted by test.
- [x] Watermark behavior (including A1's `<=` equality blocking) is unchanged; the A2 conformance suite is
      green.
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_raise_watermark_rejects_backwards_move` — fails today (raw SQL will happily lower
  a watermark).
- `test_watermark_kind_round_trips_all_three_kinds`
- `test_no_raw_watermark_type_literals_remain` (grep-style guard test, mirroring the existing
  `no_direct_composite_signer` guard convention)
- Existing watermark + conformance tests pass unchanged.

**Risks:** Low, but touches the same file region as RF4-16 — land strictly after it.

---

### Issue RF4-18: Targeted SQL history implementation + old-vs-new equivalence proptest

- **Points:** 3 · **Scope:** ~2 days · **Type:** perf (safety-critical) · **Stream:** B
- **Plan item:** E3 · **Findings:** F54
- **Blocked by:** RF4-16, RF4-17 · **Blocks:** RF4-19

**Files:**
- `crates/slashing/src/stage.rs:514-530` — the full-history `SELECT … WHERE pubkey = ?1` scan
- `crates/slashing/src/rules.rs` (RF4-16's traits — **not modified**, only a new impl added)
- `crates/slashing/src/db.rs:977`-region, `:1598`-region (any surviving scan callers)

**What / why:** Every single sign loads the validator's **entire** attestation history into memory while
holding the SQLite write lock (F54). At 225 epochs/day the per-sign work grows without bound, and the
lock is the workspace's global signing bottleneck. RF4-16's seam makes this a drop-in swap: a
`TargetedSqlAttestationHistory` answers each rule question with an indexed query
(`SELECT … WHERE pubkey = ?1 AND target_epoch = ?2` for double vote; `SELECT EXISTS(…)` for surround and
surrounded; `SELECT MIN(target_epoch) …`) instead of materializing rows.

**Implementation sketch:**
1. Add indexes if the query plans need them (`EXPLAIN QUERY PLAN` output goes in the PR); the v3
   unique indexes may already cover the double-vote lookup.
2. Implement the traits with targeted queries; the block side gets the existing `signing_root at slot`
   point lookup plus `MIN(slot)`.
3. Keep the full-scan impl behind `cfg(test)` for one release as the equivalence oracle.
4. Swap `stage_*` to the targeted impl.

**Acceptance criteria:**
- [x] **Old-vs-new equivalence proptest (phase-gate criterion):** on randomly generated histories and
      candidate attestations, `FullScan` and `TargetedSql` impls produce **identical verdicts**,
      including the exact violation variant.
- [x] `EXPLAIN QUERY PLAN` shows index use (no `SCAN TABLE attestations`) for every per-sign query.
- [x] A timing test shows per-sign work is bounded as history grows (e.g. 10 vs 10,000 rows within a
      stated factor).
- [x] The full-scan impl remains available under `cfg(test)` as the oracle.
- [x] A2 conformance suite green.
- [x] Standing invariant green.

**TDD test plan** (`crates/slashing/tests/proptest_slashing.rs` extension):
- **RED first:** `proptest_full_scan_and_targeted_sql_agree_on_random_histories` — written against the
  trait before the targeted impl exists, so it fails to compile/run until the impl lands.
- `test_targeted_double_vote_lookup_uses_unique_index` (query-plan assertion)
- `test_targeted_surround_detection_matches_full_scan_on_conformance_corpus`
- `test_per_sign_work_bounded_as_history_grows`

**Risks:** A subtly wrong `EXISTS` predicate is a missed surround — i.e. a slashing. The proptest is the
only defense and must run enough cases (≥ 10k) to be meaningful. Do not skip the `cfg(test)` oracle.

---

### Issue RF4-19: `db/` module split part 1 — `open.rs` + `migrations.rs`

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor (pure code motion) · **Stream:** B
- **Plan item:** E2 · **Findings:** F51
- **Blocked by:** RF4-18 · **Blocks:** RF4-20

**Files:**
- `crates/slashing/src/db.rs` (5,466 lines today; ~2,122 production + ~3,344 test — production shrinks
  substantially once B4's `is_safe_to_sign` `:934`, `is_safe_to_propose` `:1257`,
  `check_and_record_block` `:1341`, `check_and_record_attestation` `:1523` are gone)
- `crates/slashing/src/migration.rs:25` (absorbed)
- new `crates/slashing/src/db/open.rs`, `crates/slashing/src/db/migrations.rs`

**What / why:** `db.rs` is the workspace's second-largest file. This issue moves the two most
self-contained clusters out: connection opening (`open` `:100`, `open_with_create_info` `:110`,
`preflight_path` `:186`, `chmod_main_file` `:222`, `chmod_sidecars` `:240`, `configure_pragmas` `:271`,
`open_in_memory` `:341`, the permission checks `:2035-2103`) and migrations (`migrate` `:473`,
`read_schema_version` `:515`, `column_exists` `:528`, `migrate_to_v2` `:644`, `migrate_to_v3` `:700`,
`run_v2_migration_transaction` `:711`, plus all of `migration.rs`).

**This is pure code motion. The diff must read as moves.**

**Implementation sketch:**
1. Create `db/mod.rs` re-exporting the public surface unchanged; `crates/slashing/src/lib.rs` is untouched.
2. Move the open cluster and its test cluster together into `open.rs`.
3. Move the migration cluster + `migration.rs` into `migrations.rs`, sharing the single
   `read_schema_version` (today `migration.rs` and `db.rs` each have one).
4. Delete `migration.rs`.

**Acceptance criteria:**
- [ ] Git move detection (`git diff -M`) shows the change as renames/moves; **no behavioral edit** other
      than the `read_schema_version` deduplication, which is called out explicitly in the PR.
- [ ] `crates/slashing`'s public API is byte-identical (`cargo public-api` diff or an explicit
      re-export audit).
- [ ] Test count is unchanged (CI test-count diff attached, per plan §6.7).
- [ ] One `read_schema_version` remains (`rg` proof).
- [ ] A2 conformance suite green.
- [ ] Standing invariant green.

**TDD test plan:** code motion — the existing suite is the oracle. **RED first:** before moving anything,
add `test_schema_version_readers_agree` asserting `db.rs`'s and `migration.rs`'s readers return the same
value for a v1/v2/v3 database; it fails or is trivially true, and it is what licenses deleting one.
- Existing open/migration tests move with their code and pass unchanged.
- `test_public_api_surface_unchanged` (re-export audit).

**Risks:** Merge conflicts with any other slashing work. **Freeze the slashing spine for the duration of
RF4-19 + RF4-20.**

---

### Issue RF4-20: `db/` module split part 2 — `interchange.rs`, `watermarks.rs`, `records.rs`

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor (pure code motion) · **Stream:** B
- **Plan item:** E2 · **Findings:** F51
- **Blocked by:** RF4-19 · **Blocks:** none

**Files:**
- `crates/slashing/src/db.rs` — `export` `:1073`, `import` `:1124`, `parse_gvr_hex` `:385`,
  `read_metadata_gvr` `:411`, `genesis_validators_root` `:1788`, `set_genesis_validators_root` `:1804`
  → `interchange.rs`
- `:1832`, `:1866`, `:1882`, `:1943`, `:1976` (watermarks + prune) → `watermarks.rs`
- `:805` (`record_attestation`), `:829`/`:840` (`get_attestations`/`read_attestations`),
  `:891`/`:902` (`get_blocks`/`read_blocks`), `:1227` (`record_block`), `:1745`, `:1765`
  → `records.rs`
- test clusters move alongside their code

**What / why:** Completes the split so each file has one job and the remaining `db/mod.rs` is the struct,
its accessors, and the rules delegation. This is where the bulk of the 3,344 test lines relocate — the
part of E2 that makes it an **L** rather than an **M**.

**Implementation sketch:**
1. Move each cluster with its tests in one commit per cluster (three commits, one PR) so the reviewer can
   verify each as a move.
2. `db/mod.rs` retains `SlashingDb` (`:56`), the accessors, `set_strict_semantics` (`:370`),
   `check_integrity` (`:1778`), `normalize_pubkey`, `root_to_hex`, and the delegation to `rules.rs`.
3. `watermarks.rs` absorbs RF4-17's helpers so `WatermarkKind` lives next to its table.

**Acceptance criteria:**
- [ ] `git diff -M` reads as moves; no behavioral change.
- [ ] `db/mod.rs` production code is under ~400 lines.
- [ ] Every test moved with its code; total test count unchanged (CI diff attached).
- [ ] Public API byte-identical.
- [ ] A2 conformance suite + RF4-18's proptests green.
- [ ] Standing invariant green.

**TDD test plan:** code motion — existing suite is the oracle.
- **RED first:** `test_public_api_surface_unchanged` extended to enumerate every `pub fn` on `SlashingDb`
  before the split; it is the guard that the move loses nothing.
- All moved test clusters pass unchanged in their new homes.

**Risks:** Same freeze requirement as RF4-19. If review bandwidth is short, split into two PRs
(interchange+watermarks, then records) — the point estimate already assumes reviewer time for a large
move diff.

---

### Issue RF4-21: Beacon single retry engine — four loops collapse to one

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** B
- **Plan item:** E4 · **Findings:** F58, F108, F131
- **Blocked by:** none · **Blocks:** RF4-22, RF4-23

**Files:**
- `crates/beacon/src/client.rs:759-901` (`submit_attestation`, incl. the 400-partial-failure hook),
  `:902-1034` (`execute_with_retry`), `:1035-1162` (`post_empty_with_headers`),
  `:1163-1282` (`execute_with_retry_raw`)
- `:1283` (`retry_after_delay`), `:1294` (`calculate_backoff`) — already shared, keep as-is

**What / why:** Four copy-pasted retry loops, ~500 lines (F58). They already share `calculate_backoff`
(with ±25% jitter) and `retry_after_delay`, so **the jitter/Retry-After items in the plan's E4 text are
already done** (plan-correction #3) — the remaining duplication is the loop bodies themselves: attempt
counting, status classification, body-size limiting, and error mapping, each subtly different. Making
`execute_with_retry_raw` the one loop and rebuilding the other three on it means a retry-policy fix lands
once.

**Implementation sketch:**
1. Generalize `execute_with_retry_raw` to take a response-handling closure so a caller can inspect the
   raw response (which is what `submit_attestation` needs for its 400-partial-failure handling and what
   `post_empty_with_headers` needs for its empty-body case).
2. Rebuild `execute_with_retry` (JSON deserialization), `post_empty_with_headers` and
   `submit_attestation` as thin callers.
3. Preserve the 400-partial-failure semantics exactly — a 400 with a partial-failure body must still be
   parsed and reported per-index, not retried.

**Acceptance criteria:**
- [x] One retry loop remains (`rg 'for attempt in'` in `client.rs` == 1).
- [x] **The wiremock suite is green unmodified**, specifically the 400-partial-failure tests, the
      client-error-no-retry test (`:1516`), the server-error-retry test (`:1541`), the
      retry-success-after-failures test (`:1567`) and the timeout-retry test (`:1617`).
- [x] Retry counts and backoff timings are unchanged (asserted by request-count assertions in the
      wiremock tests).
- [x] Body-size limiting (`max_body_bytes`) applies uniformly on every path.
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_all_request_paths_share_one_retry_loop` — a behavioral test asserting the same
  retry count and backoff sequence for a GET, a POST-with-body, an empty POST and an attestation submit
  against a wiremock returning 503 (fails today where the loops differ).
- `test_400_partial_failure_still_parsed_per_index_and_not_retried`
- `test_max_body_bytes_enforced_on_every_path`
- Existing wiremock suite unchanged.

**Risks:** `submit_attestation`'s 400 handling is the one genuinely different behavior — treat it as a
callback, not a special case inside the loop.

---

### Issue RF4-22: `traced()` helper, URL encoding, and shared retry policy for monitoring

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** E4 · **Findings:** F66, F131, F108
- **Blocked by:** RF4-21 · **Blocks:** none

**Files:**
- `crates/beacon/src/client.rs:130`, `:159`, `:320`, `:535`, `:772`, `:1050` (+1) —
  `telemetry::inject_trace_context` copies
- `:128`, `:148`, `:317`, `:532`, `:763`, `:1041` — `format!("{}{}", endpoint, path)` URL construction
- `crates/rvc/src/monitoring.rs:170` (`push_with_retry`, its own 3-attempt loop)

**What / why:** Trace-header injection is copy-pasted 7 times (F66) and URLs are built by string
concatenation with un-encoded path/query components (F131) — a validator index or state id containing a
reserved character produces a malformed request. Separately, `monitoring.rs:170` has a fourth,
independent retry loop that does not share the beacon policy (F108).

**Implementation sketch:**
1. `fn traced(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder` applying
   `inject_trace_context`; replace all 7 sites.
2. Build URLs with `Url::join` + `query_pairs_mut` so path segments and query values are percent-encoded;
   keep the produced URLs byte-identical for all current inputs (asserted).
3. Point `monitoring.rs`'s `push_with_retry` at the shared backoff/Retry-After policy (extract it into a
   small `RetryPolicy` type if `beacon` cannot be a dependency of `rvc::monitoring` — check the
   architecture-tests edge rules first).

**Acceptance criteria:**
- [x] `rg 'inject_trace_context' crates/beacon/src` == 1 (inside `traced`).
- [x] Query values are percent-encoded; a test with a reserved character in a state id produces a
      correctly-escaped URL.
- [x] Current URLs are byte-identical for all existing inputs (table-driven regression).
- [x] `monitoring.rs` uses the shared policy; its 4xx-no-retry behavior is preserved.
- [x] architecture-tests green (no new forbidden edge).
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_state_id_with_reserved_characters_is_percent_encoded` — fails today.
- `test_all_current_urls_unchanged_after_encoding_change` (KAT table)
- `test_every_request_carries_trace_headers` (wiremock header assertion across all paths)
- `test_monitoring_push_uses_shared_backoff_policy`

**Risks:** URL encoding can change a working URL if a component was previously double-encoded — the KAT
table is the guard.

---

### Issue RF4-23: Role traits + supertrait `BeaconNodeClient` + one shared configurable mock

- **Points:** 3 · **Scope:** ~2 days · **Type:** refactor · **Stream:** B
- **Plan item:** E5 · **Findings:** F59, F104, F7, F63
- **Blocked by:** RF4-21 · **Blocks:** RF4-24, RF4-26, RF4-27, RF4-28

**Files:**
- `crates/bn-manager/src/traits.rs:22-166` (the 25-method trait), `:156`
  (`post_validator_liveness` — check for an error-returning default impl)
- `crates/bn-manager/src/traits.rs:525` (the existing `#[cfg(test)]`-only `MockBeaconNodeClient`)
- `crates/bn-manager/Cargo.toml` (new `test-utils` feature)

**What / why:** A 25-method trait (**not 51** — plan-correction #2) forces every consumer that needs two
methods to implement all 25, which is why 13 hand-rolled mocks exist. Role traits let a test implement
only what it uses.

**Composition mechanism (plan-correction #1):** use **supertrait composition**, not a blanket impl:

```rust
pub trait BeaconNodeClient:
    DutiesProvider + BlockProducer + AttestationApi + SyncCommitteeApi + LivenessApi + NodeStatusApi
{}
impl BeaconNodeClient for BnManager {}   // empty impls, added per type
```

A blanket `impl<T: …> BeaconNodeClient for T` would overlap the existing `impl BeaconNodeClient for
BnManager` / `for BeaconClient` (coherence error E0119) and force all 16 conversions into one PR.
Supertrait composition keeps `dyn BeaconNodeClient` object-safe, keeps every current
`Arc<dyn BeaconNodeClient>` user compiling, and is what makes RF4-24/RF4-25 separable.

**Implementation sketch:**
1. Split the 25 methods into the six role traits by domain.
2. Redefine `BeaconNodeClient` as the empty supertrait; add empty impls for `BnManager` and
   `BeaconClient` (their method bodies move to the role-trait impls unchanged).
3. Add a `test-utils` feature (the workspace-standard name, per C7) exporting `MockBeaconNodeClient`:
   **erroring by default**, with per-method builder overrides and call capture (aligning with H4's
   mock-fidelity direction).
4. Do **not** delete any hand mock here — that is RF4-24/25.

**Acceptance criteria:**
- [ ] Six role traits exist; `BeaconNodeClient` is their empty supertrait and remains object-safe
      (`fn _assert(_: &dyn BeaconNodeClient)` compiles, per `traits.rs:311`).
- [ ] Every existing `Arc<dyn BeaconNodeClient>` call site compiles **unchanged**.
- [ ] The shared mock is exported behind `test-utils`, errors by default, supports per-method overrides
      and captures call arguments.
- [ ] `post_validator_liveness`'s error-returning default impl (if present) is removed so an unimplemented
      method is a compile error, not a runtime failure.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_mock_with_only_duties_role_compiles_and_serves_duties` — a test implementing only
  `DutiesProvider`; fails to compile against today's monolithic trait.
- `test_shared_mock_errors_by_default_for_unconfigured_methods`
- `test_shared_mock_captures_call_arguments`
- `test_dyn_beacon_node_client_still_object_safe`

**Risks:** `#[async_trait]` across six traits adds boxing at each layer — measure once; if it matters,
keep the role traits `#[async_trait]` and the supertrait bare (it has no methods, so it costs nothing).

---

### Issue RF4-24: Delete the nine hand-rolled `BeaconNodeClient` mocks in `crates/rvc`

- **Points:** 2 · **Scope:** ~1 day · **Type:** testing · **Stream:** B
- **Plan item:** E5 · **Findings:** F7, F104
- **Blocked by:** RF4-23 · **Blocks:** RF4-25

**Files (all verified `impl BeaconNodeClient for` sites in `crates/rvc`):**
- `crates/rvc/src/startup.rs` (`MockBeacon`), `crates/rvc/src/slashing_monitor.rs` (`MockBeacon`)
- `crates/rvc/src/orchestrator/sync_committee.rs` (`ToctouBeacon`, `ContribGateBeacon`)
- `crates/rvc/src/orchestrator/slot_context.rs` (`SlotVsHeadBeacon`, `ErrorBeacon`)
- `crates/rvc/src/liveness_loop.rs` (`MockLivenessBn`, `FailoverLivenessClient`)
- `crates/rvc/tests/sync_independent_of_attesting.rs` (`SyncTestBeacon`)

**What / why:** Nine mocks, each implementing 25 methods, each free to drift from the real client's
behavior. Replacing them with the shared configurable mock deletes roughly a thousand lines of test
scaffolding and makes every mock's behavior come from one place.

**Implementation sketch:**
1. Add `bn-manager = { workspace = true, features = ["test-utils"] }` to `crates/rvc`'s dev-dependencies.
2. Convert one mock per commit; each keeps its *behavior* (`ToctouBeacon`'s ordering, `ErrorBeacon`'s
   failures, `FailoverLivenessClient`'s failover sequence) expressed as mock configuration rather than a
   bespoke impl.
3. Delete the hand impls.

**Acceptance criteria:**
- [ ] `rg 'impl BeaconNodeClient for' crates/rvc` == 0.
- [ ] Every converted test asserts the **same behavior** as before — no test weakened to fit the mock
      (reviewer checks each conversion; the TOCTOU and failover tests are the ones to scrutinize).
- [ ] Test count unchanged.
- [ ] Standing invariant green.

**TDD test plan:** conversion — the existing tests are the oracle.
- **RED first:** for each mock, run the existing test against the shared mock *before* deleting the hand
  impl and confirm it passes for the same reason (documented per conversion in the PR).
- `test_toctou_ordering_preserved_with_shared_mock`
- `test_liveness_failover_sequence_preserved_with_shared_mock`

**Risks:** The TOCTOU and failover mocks encode *sequencing*, not just return values. If the shared mock
cannot express a per-call sequence, extend it (a `VecDeque` of responses per method) — budgeted here.

---

### Issue RF4-25: Delete the remaining hand mocks; remove the default-impl footgun; macro the passthrough

- **Points:** 2 · **Scope:** ~1 day · **Type:** testing · **Stream:** B
- **Plan item:** E5 · **Findings:** F63, F104
- **Blocked by:** RF4-24, RF4-28 · **Blocks:** none

**Files:**
- `bin/rvc/tests/tier2_safety.rs` (2 × `MockBeacon`), `bin/rvc/tests/tier4_advanced.rs` (`MockBn`)
- `crates/builder/src/service.rs:339` (`MockBn` — may already be gone via RF4-28)
- `crates/bn-manager/src/manager.rs:1238` — the 165-line `impl BeaconNodeClient for BeaconClient`
  passthrough

**What / why:** Finishes E5 and delivers the phase-gate count. The passthrough impl at `manager.rs:1238`
is 165 lines of `self.method().await` (F63) — generating it with a macro (or `delegate`) means a new
endpoint touches the trait and the macro list, not 165 hand-written lines.

**Implementation sketch:**
1. Convert the three `bin/rvc` test mocks to the shared mock.
2. If RF4-28 has not already removed `crates/builder`'s `MockBn`, do it here.
3. Replace the `BeaconClient` passthrough with a macro over the method list (or `delegate::delegate!`),
   keeping the generated signatures identical.

**Acceptance criteria:**
- [ ] **`rg "impl BeaconNodeClient for" | wc -l` == 3** — BnManager, BeaconClient, shared mock
      (phase-gate criterion; the empty supertrait impls from RF4-23 are counted and named in the PR so the
      number is unambiguous).
- [ ] The passthrough is macro-generated; adding a trait method fails to compile until the macro list is
      updated (demonstrated in the PR).
- [ ] All `bin/rvc` tier tests pass unchanged.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_beacon_client_passthrough_covers_every_trait_method` — a test that fails if any
  method is missing from the generated impl (write it before macro-izing).
- `test_tier2_and_tier4_suites_pass_with_shared_mock`

**Risks:** The `rg` count must be interpreted carefully after RF4-23 introduces empty supertrait impls —
state the exact grep and expected matches in the PR so the gate is unambiguous.

---

### Issue RF4-26: BnManager `submit()` helper + batched health-tracker updates

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** E6 · **Findings:** F61, F68
- **Blocked by:** RF4-23 · **Blocks:** none

**Files:**
- `crates/bn-manager/src/manager.rs:925` (`publish_block`), `:951` (`publish_blinded_block`),
  `:1001` (`submit_attestation`), `:1072` (`submit_sync_committee_messages`),
  `:1166` (`submit_beacon_committee_subscriptions`) — the 5 broadcast-vs-`query_first` blocks
- `:366` (`query_first`), `:668` (`broadcast`), `:567`/`:634`-region (per-result write-lock churn)

**What / why:** Five submission methods each contain the same
`if self.broadcast_topics.X { broadcast(...) } else { query_first(..., BnRole::Submission, ...) }`
branch wrapped in `with_op_timeout` (F61). Separately, `query_best`/`fallback_unsynced` take the health
tracker's write lock once per result (F68) instead of batching.

**Implementation sketch:**
1. `async fn submit(&self, op_name, topic_enabled: bool, role, min_tier, timeout, op) -> Result<(), BeaconError>`
   encapsulating the branch and the timeout; the five methods become one call each.
2. Add `record_outcomes(&self, outcomes: &[(usize, BnOutcome)])` taking the write lock once; call it from
   `query_best` and `fallback_unsynced`.

**Acceptance criteria:**
- [ ] The five submission methods are ≤ ~10 lines each and share one dispatch helper.
- [ ] Broadcast-vs-query_first behavior per topic is unchanged (existing multi-BN tests green:
      `test_multi_query_first_uses_primary` `:1912`, `..._failover_on_error` `:1938`,
      `..._all_fail` `:1965`, `..._failover_three_bns` `:2020`).
- [ ] The health write lock is taken once per selection round, asserted by a test or a documented
      lock-count instrument.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_health_tracker_write_lock_taken_once_per_selection_round` — fails today
  (per-result locking).
- `test_submit_helper_respects_each_broadcast_topic_flag` (table over the 5 ops × topic on/off)
- Existing multi-BN failover tests unchanged.

**Risks:** Low. Watch that `with_op_timeout`'s per-op timeout selection stays per-operation.

---

### Issue RF4-27: Proposer failover — `BeaconBlockAdapter` accepts `Arc<dyn BeaconNodeClient>`

- **Points:** 3 · **Scope:** ~2 days · **Type:** bugfix (behavior change) · **Stream:** B
- **Plan item:** E7 · **Findings:** F19, F62
- **Blocked by:** RF4-23 · **Blocks:** none

**Files:**
- `bin/rvc/src/main.rs:1525-1560` — builds the proposer `BnManager`, logs
  "block production will use dedicated pool", then **constructs a fresh single `BeaconClient` from
  `config.proposer_nodes[0]`** and uses that instead
- `crates/rvc/src/beacon_adapter.rs` (`BeaconBlockAdapter`, wraps a concrete `BeaconClient`)
- `crates/rvc/src/config/builder.rs:208` (`build_beacon`), `:244` (`build_proposer_bn_manager`)

**What / why:** The proposer `BnManager` is built, logged about, and then discarded (F19): block
production goes to `proposer_nodes[0]` directly, so a down first proposer node means **no block**, even
with a healthy second one configured. The operator sees a log line promising failover they do not have.
The fix is small once `BeaconBlockAdapter` accepts the trait object instead of a concrete client.

**Implementation sketch:**
1. Change `BeaconBlockAdapter` to hold `Arc<dyn BeaconNodeClient>` (RF4-23's supertrait keeps this
   compiling everywhere).
2. In `main.rs`, pass the proposer `BnManager` itself when configured, falling back to the main
   `BnManager` when `proposer_nodes` is empty. Delete the ad-hoc `BeaconClient` construction.
3. Document the retries=0-under-failover policy in one place (today it is implied in several).
4. Narrow `build_beacon` (`builder.rs:208`) to the exit-tooling paths that genuinely need a single client.

**Acceptance criteria:**
- [ ] Block production routes through the proposer `BnManager`; no `BeaconClient` is constructed from
      `proposer_nodes[0]` (`rg` proof).
- [ ] **Integration test: first proposer node down → the second is used and a block is produced.**
- [ ] With `proposer_nodes` empty, behavior is unchanged (main pool used).
- [ ] The retries-under-failover policy is documented once and referenced from the other sites.
- [ ] Release note: proposer block production now honors failover.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_block_production_fails_over_to_second_proposer_node` — fails today (the adapter
  only knows node 0).
- `test_empty_proposer_nodes_uses_main_bn_manager`
- `test_proposer_pool_used_when_configured` (assert the request went to a proposer endpoint, not a
  main-pool endpoint)
- `test_build_beacon_only_used_by_exit_tooling` (call-site guard test)

**Risks:** Behavior-visible. An operator who (knowingly or not) depended on "proposals only ever go to
node 0" sees a change; release-note it. Also confirm the proposer pool's `BnRole::Proposal` health tier
matches the previous single-client behavior.

---

### Issue RF4-28: Builder seam — 2-method BN trait + 1-method registration signer trait

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** E8a (+ F101 rider) · **Findings:** F97 part, F101
- **Blocked by:** RF4-23 · **Blocks:** RF4-25

**Files:**
- `crates/builder/src/service.rs:31` (`BuilderService`), `:71` (`register_validators`),
  `:233` (`prepare_proposers`), `:302-480` (the ~180-line `MockBn` + a second mock at `:486`)
- `crates/block-service/src/service.rs:106` (`propose_block_with_mode` — the F101 rider)

**What / why:** `BuilderService` uses exactly two beacon methods (`register_validators`,
`prepare_beacon_proposer`) but its tests implement all 25 (F97). A 2-method `BuilderBeaconClient` trait
plus a 1-method registration-signer trait lets the tests stub what they use and deletes ~250 lines of
mock. With RF4-23's role traits in place, `BnManager` satisfies the narrow trait for free.

**F101 rider:** `block-service`'s `propose_block_with_mode` (`service.rs:106`) is `pub`, letting callers
bypass the validation that `propose_block` performs. Demote it to `pub(crate)` and extend the existing
symbol-grep guard test to cover it. (Note: the plan files this under E8a, but the symbol lives in
`crates/block-service`, not `crates/builder` — call that out in the PR.)

**Implementation sketch:**
1. Define `trait BuilderBeaconClient { register_validators; prepare_beacon_proposer }` and
   `trait RegistrationSigner { sign_builder_registration }` in `crates/builder`.
2. `BuilderService` takes the narrow traits; a blanket-free impl for `Arc<dyn BeaconNodeClient>` bridges
   production (this one **is** safe — it targets the narrow trait, which has no other impls).
3. Delete both mocks; tests implement the 2-method trait inline.
4. Demote `propose_block_with_mode`; extend the guard test.

**Acceptance criteria:**
- [ ] `crates/builder` no longer references `BeaconNodeClient` in its tests; the ~250 mock lines are gone.
- [ ] All existing builder tests pass unchanged, including the batching and error-on-call-index cases
      (`service.rs:322-338`).
- [ ] `propose_block_with_mode` is `pub(crate)`; the symbol-grep guard covers it; the four existing
      call sites (`block-service/src/service.rs:2161`, `:2180`, `:2200`, `:2221` — all tests) still compile.
- [ ] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_builder_service_compiles_against_two_method_stub` — a test implementing only the
  narrow trait; fails today.
- `test_propose_block_with_mode_not_publicly_reachable` (guard test extension)
- Existing builder registration/prepare tests unchanged.

**Risks:** A5 (Phase 1) already removed the `unsafe` pointer downcast in `service.rs:669`; confirm that
landed before touching this file, or the mock deletion collides with it.

---

### Issue RF4-29: duty-tracker `from_response` constructors + `clear_cache` covers the sync cache

- **Points:** 1 · **Scope:** ~0.5 day · **Type:** bugfix · **Stream:** B
- **Plan item:** E8b · **Findings:** F96
- **Blocked by:** none · **Blocks:** none

**Files:**
- `crates/duty-tracker/src/tracker.rs:29` (`EpochDutyCache`), `:49` (`ProposerEpochDutyCache`),
  `:85` (`fetch_duties_for_epoch`), `:316` (`fetch_proposer_duties`), `:414`
  (`fetch_sync_committee_duties`) — the four parse loops
- `:293` (`clear_epoch_cache`), `:299` (`clear_cache`)

**What / why:** The same "iterate the response, parse each duty, insert into the cache" loop is written
four times (F96), and `clear_cache` (`:299`) clears the attester caches but **not** the sync-committee
cache — so a key removal or a reorg leaves stale sync duties live. That is a small correctness bug, not
just duplication.

**Implementation sketch:**
1. Add `EpochDutyCache::from_response(dependent_root, duties)` and the proposer/sync equivalents; the
   fetch methods construct via them.
2. Extend `clear_cache` to clear the sync cache too.

**Acceptance criteria:**
- [x] The four parse loops are replaced by `from_response` constructors.
- [x] **`clear_cache` clears the sync-committee cache** (test asserts `get_sync_committee_duties`
      returns empty afterwards).
- [x] Existing duty-tracker tests pass unchanged.
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_clear_cache_clears_sync_committee_cache` — fails today. ✅
- `test_from_response_constructors_produce_identical_caches` (differential against the old loops) ✅
- `test_clear_epoch_cache_still_scoped_to_one_epoch` ✅

**Risks:** None.

---

### Issue RF4-30: Doppelganger — single `MonotonicEpochClock` + shared restart-skip predicate

- **Points:** 2 · **Scope:** ~1 day · **Type:** refactor · **Stream:** B
- **Plan item:** E8c · **Findings:** F93
- **Blocked by:** B2 (P2 — `build_doppelganger_service` deletion) · **Blocks:** none
- **SEC dependency:** SEC-2a/2b/2c — **verified landed on `develop`**, not blocking (see below)

**Files:**
- `crates/doppelganger/src/epoch_clock.rs:23` (`MonotonicEpochClock`), `:57` (`current_epoch`)
- `crates/doppelganger/src/service.rs:96` (a second `current_epoch` implementation)
- `crates/doppelganger/src/forward_window.rs:128` (restart-skip logic)
- `crates/rvc/src/startup.rs:139` (still takes `&doppelganger::DoppelgangerService`)

**What / why — with the plan's SEC-2 gate re-checked against HEAD:** the brief marks E8c "gated on
SEC-2". **SEC-2 has landed.** Verified: `crates/rvc/src/liveness_loop.rs` exists;
`bin/rvc/src/main.rs:1421` calls `rvc::liveness_loop::spawn_liveness_loop`; `main.rs:1346-1421`
constructs `ForwardWindowMachine`; `main.rs:1355` records that the one-shot `DoppelgangerService` "is no
longer the production mechanism"; `crates/rvc/src/config/builder.rs:264-273` documents
`build_doppelganger_service` as legacy/tests-only. So "retire the legacy service from the startup path"
is **already done**, and B2 (Phase 2) deletes `build_doppelganger_service` itself.

E8c's remaining scope is therefore the duplication, not the wiring: two `current_epoch` implementations
(`epoch_clock.rs:57` vs `service.rs:96`) that can disagree at an epoch boundary, a restart-skip predicate
that exists in the forward-window machine but not as a shared, testable unit, and `startup.rs:139` still
typed against the legacy service.

**Implementation sketch:**
1. Make `MonotonicEpochClock` the only epoch source; `service.rs:96` delegates or is deleted with the
   service.
2. Extract the restart-skip predicate (`forward_window.rs:128`) into a named function with its own tests.
3. Re-type `startup.rs:139` against the enablement trait (or the forward-window machine) so the legacy
   service is not in any production signature.

**Acceptance criteria:**
- [x] One `current_epoch` implementation in `crates/doppelganger` (`rg` proof).
- [x] The restart-skip predicate is a named, separately tested function.
- [x] `crates/rvc/src/startup.rs` has no `DoppelgangerService` in a production signature.
- [x] **Lifecycle test: an imported or restarted key does not attest until its window clears** (the
      plan's E8c acceptance criterion — assert via the enablement gate, not via HTTP).
- [x] Standing invariant green.

**TDD test plan:**
- **RED first:** `test_single_epoch_clock_used_by_all_doppelganger_paths` — a test asserting both paths
  report the same epoch at a boundary; fails while two implementations exist.
- `test_restart_skip_predicate_skips_only_restarted_keys`
- `test_imported_key_does_not_attest_until_window_clears`
- `test_restarted_key_does_not_attest_until_window_clears`

**Risks:** If B2 has not landed, `build_doppelganger_service` still exists and this issue must either wait
or absorb its deletion (+1 point). Re-verify before starting.

---

## Coordination Notes

- **Stream contract:** Stream B must not change the `SlashingDb::stage_block` / `stage_attestation`
  public signatures (RF4-16/17/18 are internal-only). Stream A's RF4-05/06 call them. Any signature
  change requires a joint PR.
- **Slashing freeze:** RF4-19 and RF4-20 are pure code motion over `db.rs`; no other slashing PR may be
  open while they land.
- **Signer serialization:** RF4-02, RF4-04, RF4-05, RF4-06 and RF4-12 all edit
  `crates/signer/src/lib.rs`. They are strictly ordered; do not parallelize within Stream A.
- **Release notes required** (plan §6.5 names four deliberate behavior changes; each gets a test **and** a
  note): RF4-04 (VC non-slashable sign timeout), **RF4-05 (`SigningGate` now emits sign metrics — new
  series appear on the remote-signer scrape)**, RF4-06 (retain-on-timeout costs a missed duty instead of
  retrying), RF4-10 (non-mainnet builder fork version), RF4-27 (proposer failover).
- **Phase 5 hand-off:** F5 (keymanager assembly) sequences after SEC-1 — which has landed
  (`crates/rvc/src/deletion_denylist.rs`); F2 resolves the `rvc-signer` package-name collision that
  RF4-13 deliberately defers.
