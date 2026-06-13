# Remediation Issue Breakdown — Cross-Phase Summary

This document summarizes the per-phase issue breakdowns for the rs-vc security
remediation. It is the index over the six phase files; each row links to the phase
that owns the detail.

- [Phase 1 — M1 Shared Pre-Work: Slashing-Safety Seams & Traits](./01-phase-1.md)
- [Phase 2 — M1 Fixes: Slashing-Safety Floor](./02-phase-2.md)
- [Phase 3 — M2 Shared Pre-Work: Spec-Vector Fixtures & Canonical Promotion](./03-phase-3.md)
- [Phase 4 — M2 Fixes: Duty-Correctness Floor & Release Gate](./04-phase-4.md)
- [Phase 5 — M3 Shared Pre-Work: `net-policy` Crate](./05-phase-5.md)
- [Phase 6 — M3 Fixes: Hardening + P2 Cleanup](./06-phase-6.md)

---

## Estimation Approach

- **Point scale.** A single uniform scale across all six phases: `1` = trivial (≤½
  day), `2` = small (~1 day), `3` = medium (~1.5–2 days), `5` = large (~2.5–3 days,
  rare and justified inline). No issue exceeds 5 points; the only 5-point issues are
  the DVT-1+CN-1 slashing-schema migration (Phase 2 / 2.4) and the B-1/T-1
  `SignedBlockContents` framing GREEN (Phase 4 / 4.6) — each kept atomic because
  splitting would leave an inconsistent intermediate that cannot pass its own RED
  test. The previously-clustered URL-1+URL-2 5-pointer was split into 6.2a (3pt) +
  6.2b (3pt) after a refinement pass; see the per-issue split table below.
- **Velocity baseline.** Estimates assume one experienced Rust developer familiar with
  the rs-vc codebase: 1 pt ≈ ½ day, 2 pt ≈ 1 day, 3 pt ≈ 2 days, 5 pt ≈ 3 days,
  inclusive of review touch-ups. Day-budgets in each phase's execution plan are
  working-day slots, not idealized point-days, so they run slightly longer than a raw
  points-to-days conversion.
- **TDD per finding (PRD §6.1).** Every fix-bearing issue lands as a RED → GREEN
  (→ optional REFACTOR) sequence; the "issue is done" milestone is the GREEN commit
  merged FF-only to `develop` with the four-gate CI suite green
  (`cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`).
- **Pre-work vs. fix phases.** Odd-after-1 pattern: each "fix" phase (2, 4, 6) is
  preceded by a "shared pre-work" phase (1, 3, 5) that lands the traits, seams,
  fixtures, and new crates the fixes consume — each pre-work phase is purely additive
  with **zero observable behavior change** on `develop`.
- **Standing CI gates.** Two gates are authored in pre-work and tightened in fixes:
  `tests/architecture_no_cycles.rs` (Phase 1 / 1.6) and
  `bin/rvc-signer/tests/signing_path_enumeration.rs` (Phase 2 / 2.1, flipped strict in
  2.13). Every later phase re-asserts both stay green.
- **Cluster branches (PRD §7.1).** Findings whose GREEN diffs literally overlap ship on
  one branch (DVT-1+CN-1, B-1+T-1+L-9, SS-2+SS-3+L-4, DT-1+S-2+C-1, GVR-1+IMP-1,
  GRPC-1/2/3+L-1). URL-1+URL-2 was split into 6.2a+6.2b for reviewability; Info-5 was
  split into 6.22a–6.22d (one crate per branch) because four crates on one branch
  violates the architecture's max-2-file blast-radius rule. They are broken into
  separate issues here so each stays a 1–2 day reviewable unit, but RED/GREEN commits
  land on a shared branch where the cluster persists.
- **Refinement splits.** Several originally-larger issues were split during refinement
  to keep each diff at 1–2 days: 1.8 → 1.8a (operator-poll spike) + 1.8b
  (anonymized-fixture capture); 2.9 → 2.9a (slashable paths + lock map) + 2.9b
  (non-slashable paths + `FailClosedDefault`); 2.10 → 2.10a (signer-side wrapper) +
  2.10b (validator-store + orchestrator + grep-gate); 6.2 → 6.2a (URL-1) + 6.2b
  (URL-2); 6.8 → 6.8a (DVT-2 client migration) + 6.8b (DVT-2 server removal); 6.22 →
  6.22a/6.22b/6.22c/6.22d (Info-5 sub-items, one crate each). The Phase 1 1.8
  split preserved its original 3pt budget as 1+2 (1.8a=1pt, 1.8b=2pt); Phase 1's
  per-issue point sum therefore totals 22, not 23.

---

## Phase Table

| Phase | Title | Issues | Points | Est. duration (single-stream) | Behavior change |
|-------|-------|--------|--------|-------------------------------|-----------------|
| [1](./01-phase-1.md) | M1 Shared Pre-Work — slashing-safety seams & traits | 12 | 22 | ~13–14 days | None (additive) |
| [2](./02-phase-2.md) | M1 Fixes — slashing-safety floor | 15 | 36 | ~18 days | Yes (9 findings) |
| [3](./03-phase-3.md) | M2 Shared Pre-Work — spec-vector fixtures & canonical promotion | 7 | 12 | ~9 days | None (additive) |
| [4](./04-phase-4.md) | M2 Fixes — duty-correctness floor & release gate | 25 | 63 | ~32 days | Yes (16 findings) |
| [5](./05-phase-5.md) | M3 Shared Pre-Work — `net-policy` crate | 7 | 12 | ~7 days | None (additive) |
| [6](./06-phase-6.md) | M3 Fixes — hardening + P2 cleanup | 27 | 44 | ~22 days | Yes (remaining P1 + all P2) |
| **Total** | | **93** | **189** | **~101 working days** | |

> The 46 findings (1 Critical + 13 High + 13 Medium + 14 Low + 5 Info) are closed
> across the three fix phases (2, 4, 6); the three pre-work phases (1, 3, 5) land the
> seams those fixes consume. Issue counts exceed finding counts because each finding is
> typically a RED issue plus a GREEN issue (and pre-work / scaffold / exit-gate issues
> plus the refinement splits noted in the Estimation Approach add more).

---

## Single-Stream Execution Plan

One code-writer works all 93 issues sequentially in phase order, respecting the
dependency map below. There is **no Stream A / Stream B**, no file-ownership map, and no
parallel-agent split — the plan is deliberately serial so the FF-only merge discipline
and the per-finding RED→GREEN gate stay legible.

| Order | Phase | Span (days) | Gate at phase exit |
|-------|-------|-------------|--------------------|
| 1 | Phase 1 pre-work | ~13–14 | Four traits + dep edge + `architecture_no_cycles` gate + `signer-registry` skeleton + Q3/Q7 resolved (Q3 via 1.8a + conditional 1.8b), FF-merged to `develop` |
| 2 | Phase 2 M1 fixes | ~18 | PRD M4 + M6 verified; enumeration gate flipped strict (D-3 split landed across 2.9a/2.9b + 2.10a/2.10b) |
| 3 | Phase 3 pre-work | ~9 | Four fixture sets committed; `canonical` helpers are the only hex/GVR parser in `slashing::import` + `bin/rvc` exits |
| 4 | Phase 4 M2 fixes | ~32 | PRD M2/M3/M5/M7 verified; **release branch cut deferred to Phase 6 per DL-5** |
| 5 | Phase 5 pre-work | ~7 | `crates/net-policy` Level-2 crate landed, zero production consumers |
| 6 | Phase 6 M3 fixes | ~22 | All 46 findings closed (PRD M1, M8); **release cut after 6.1, 6.2a, 6.2b, 6.3, 6.4** |

**Sequencing notes**

- **Pre-work phases gate their fix phase.** Phase 1 → 2, Phase 3 → 4, Phase 5 → 6 are
  hard ordering edges: each fix phase's entry criteria require its pre-work landed on
  `develop`.
- **Release is NOT cut at Phase 4 exit** (DL-5). Phase 4 closes P0 + all M2-resident
  P1, but four P1 findings (URL-1, URL-2, KM-3, VS-1) are M3-promoted release blockers
  that land in the Phase 6 release-blocking subset (6.1 / 6.2a / 6.2b / 6.3 / 6.4). The
  release cut happens after **6.4**, totalling **12 points / ~5–6 days** for the
  release-blocking subset (6.1 = 2pt KM-3, 6.2a = 3pt URL-1, 6.2b = 3pt URL-2, 6.3 =
  3pt GRPC+L-1, 6.4 = 1pt VS-1).
- **Phase 5 may start in parallel with the Phase 4 release-prep tail** on the calendar
  (it is on the pre-release critical path because it unblocks 6.1–6.4), but within the
  single-stream model it is sequenced after Phase 4 exit.
- **Deferrable P2 tail.** Phase 6 Issues 6.5–6.22d are pure-P2 and may roll to a
  follow-up release at the user's discretion (PRD §11); only 6.1, 6.2a, 6.2b, 6.3,
  6.4 (12 points, ~5–6 days) are release-blocking.

---

## Dependency Map

```text
Phase 1 (pre-work) ──────────────────────────────► Phase 2 (M1 fixes)
  1.1 canonical ────► 3.6/3.7 (promote) ──► 4.11/4.19/4.20 (GVR-1/IMP-1), 4.22 (EXIT-1), 6.5 (L-2), 6.21 (Info-4)
  1.2 InsecureGate ─────────────────────────────► 2.1/2.2 (SS-1), 6.1 (KM-3), 6.13 (SIG-1), 6.3 (L-1)
  1.3 SigningEnablement + FailClosedDefault ────► 1.5 dep edge ──► 2.4/2.6 (D-1), 2.9a/2.9b (D-3 gate)
  1.4 SlashingDbReader ─────────────────────────► 2.6 (D-1 restart-aware safe-skip)
  1.6 architecture_no_cycles gate (standing) ───► re-asserted every later phase
  1.7 signer-registry skeleton ─────────────────► 2.2 (SS-1 enumeration), 2.13 strict flip
  1.8a Q3 spike + 1.8b conditional fixture ─────► 2.4 (DVT-1+CN-1 migration test)
  1.9 Q7 resolution ────────────────────────────► 3.4 + 4.5 (B-1/T-1 RED baseline)

Phase 2 (M1 fixes)
  2.4 PubkeyScopedDb ──┐
  2.6 ForwardWindowMachine ──┼──► 2.9a SigningGate slashable ──► 2.9b non-slashable + FailClosedDefault
                              │                                    │
                              │                                    ▼
                              └─────────────────────────────► 2.10a signer-side wrapper ──► 2.10b validator-store + grep-gate ──► 2.11/2.12 ──► 2.13 exit gate
  2.2 SS-1 unregister ─────────────────────────► 4.9 (SS-2/SS-3 reuse), 6.8a/6.8b (DVT-2 reuse)

Phase 3 (pre-work) ──────────────────────────────► Phase 4 (M2 fixes)
  3.1 fixture scaffold ──► 3.2/3.3/3.4/3.5 fixtures ──► 4.1/4.3/4.5/4.8 RED tests
  3.6/3.7 canonical promotion ─────────────────► 4.19/4.20 (GVR-1+IMP-1), 4.22 (EXIT-1)

Phase 4 (M2 fixes)
  4.1 ─► 4.2 ─┐
              ├─► 4.4 ─► 4.9 ─► 4.10        (E-1/E-2 → aggregator chain)
  4.3 ────────┘
  4.5 ─► 4.6 ─► 4.7                          (B-1/T-1 → L-9)
  4.11 ─► 4.12                               (BN tier coherence)
  4.13 ─┐
  4.14 ─┼─► 4.15 ─► 4.16                     (runtime-import cluster → M7 e2e)
  4.19 ─► 4.20                               (GVR-1 → IMP-1)
  Independent: 4.17, 4.18, 4.21, 4.23, 4.24, 4.25

Phase 5 (pre-work) ──────────────────────────────► Phase 6 (M3 fixes)
  5.1 scaffold ─► 5.2 IPv4 deny ─► 5.3 IPv6 deny ─► 5.4 UrlPolicy ─► 5.5 runtime ─► 5.6 PinnedResolver ─► 5.7 property+gate
  net-policy crate ────────────────────────────► 6.2a (URL-1), 6.2b (URL-2), 6.3 (GRPC+L-1)

Phase 6 (M3 fixes — release-blocking subset first)
  6.1 KM-3 ──► 6.2a URL-1 ──► 6.2b URL-2 ──► 6.3 GRPC+L-1 ──► 6.4 VS-1 ──► RELEASE CUT (per DL-5)
  6.5 … 6.22d  (deferrable P2 tail; DVT findings 6.8a→6.8b enforce client-before-server delete; Info-5 split across 6.22a/6.22b/6.22c/6.22d for per-crate branch hygiene)
```

**Cross-phase critical edges**

- `eth-types::canonical` (1.1) and `eth-types::insecure::InsecureGate` (1.2) are the
  highest fan-out seams — consumed in Phases 2, 3, 4, and 6.
- The Phase 1 → Phase 2 → Phase 4 → Phase 6 chain for the SigningGate / enumeration
  pattern is the load-bearing spine: SS-1's unregistration pattern (2.2) is reused by
  SS-2/SS-3 (4.9) and DVT-2 (6.8a/6.8b); the standing enumeration gate (1.7/2.13)
  re-validates each.
- The Phase 5 `net-policy` crate is a hard prerequisite for the five Phase 6
  release-blockers (6.1, 6.2a, 6.2b, 6.3, 6.4); the release cannot cut until it lands.

---

## Risk Flags

| Risk | Phase / Issue | Why it is risky | Mitigation |
|------|---------------|-----------------|------------|
| On-disk slashing-schema migration (5 pt) | [2 / 2.4](./02-phase-2.md) | Re-keys SQLite UNIQUE indices from per-CN to per-pubkey; a partial migration creates a **worse** double-sign hazard than the bug it closes. Highest-stakes change in M1. | Atomic, idempotent, transactional migration; row-pair resolution unit-tested per case; regression replays the captured pre-migration fixture; kept one branch (no split). |
| Q3 unresolved (production slashing DBs) | [1 / 1.8a → 1.8b](./01-phase-1.md) | Gates 2.4's migration test surface; blocked on operator response latency. The 1.8a → 1.8b split isolates the operator-poll-bound spike (1.8a, 1pt) from the conditional anonymized-fixture work (1.8b, 2pt, Outcome-B only). | 2-day SLA on 1.8a then escalate with a recommendation to proceed under "no production DBs" (synthetic fixture, 1.8b skipped); the gate is not a perpetual blocker. |
| Q7 ambiguity (B-1/T-1 partially landed) | [1 / 1.9](./01-phase-1.md) → [4 / 4.5](./04-phase-4.md) | Research suggests the SSZ publish fix is partially landed; writing a from-scratch RED test against an already-green state wastes a cycle. | Phase 1 spike documents the actual landed state (X1/X2/X3); Phase 4 RED inverts the right pinning baseline. |
| `SignedBlockContents` framing GREEN (5 pt) | [4 / 4.6](./04-phase-4.md) | On-disk byte-format change; bounding at `kzg_offset` AND `SignedBlockContents` framing must land atomically or the intermediate fails to deserialize. | RED asserts round-trip first (4.5); two integration tests cover Deneb-with-blobs and without-blobs; `crates/beacon/ssz_deser.rs` round-trip updated in the same edit. |
| KG-1 test inversion | [4 / 4.8](./04-phase-4.md) | Inverts two existing **passing** tests that pin the bug; risk of churn if those tests carry assertions not captured in the PRD. Prior keygen outputs become invalid (operators must regenerate). | RED lands inverted tests first; cross-check against `staking-deposit-cli` fixture; release-note call-out (no migration tool ships). |
| SS-2/SS-3 aggregate re-routing | [4 / 4.9](./04-phase-4.md) | Touches `bin/rvc-signer/src/service.rs` which the standing enumeration gate also gates; mis-routing fails CI. | Enumeration gate catches missed routing; ADR-009 chain-of-custody integration test catches a missed precondition. |
| Runtime-import M7 e2e flakiness | [4 / 4.15–4.16](./04-phase-4.md) | In-process keymanager + orchestrator integration; doppelganger window timing can flake. | C-1 (4.14) lands first for correct signal consumption; short `monitoring_epochs` override; re-run 10× locally; mock BN. |
| SSE reconnect / `catch_unwind` | [4 / 4.18](./04-phase-4.md) | `catch_unwind` across async boundaries is subtle; must verify event delivery actually resumes, not just "no panic." | Test asserts delivery after a callback panic; removes the legacy "second TCP connection only" assertion. |
| EXIT-1 new BN call in CLI | [4 / 4.22](./04-phase-4.md) | Adds a `get_genesis()` BN call to exit subcommands; risk of breaking offline operator workflows. | Fail-closed default with documented release-note; `--genesis-validators-root` bypass only if PRD allows. |
| KS-1 gate-before-decrypt ordering | [4 / 4.25](./04-phase-4.md) | Effective-cost gate must run **before** decrypt or the DoS class is missed. | RED loads an oversized keystore and asserts rejection at the import API boundary, not at decrypt. |
| URL-1 / URL-2 net-policy consumer wiring | [6 / 6.2a + 6.2b](./06-phase-6.md) | Two distinct production consumers (keymanager-api + crypto::remote_signer) wiring against the same shared `net-policy` surface; 6.2a establishes the dep edge and validator pattern, 6.2b's rebinding mock + per-connect recheck is non-trivial to author. The previously-clustered 5pt issue was split into 6.2a (3pt) + 6.2b (3pt) so each has its own RED→GREEN→REFACTOR cycle. | Sequence 6.2a then 6.2b on adjacent days; `architecture_no_cycles` re-checked after each new dep edge; rebinding mock driven via a fake `reqwest::dns::Resolve` implementation. |
| Release-gate timing (DL-5) | [4 → 6](./04-phase-4.md) | Release is **not** cut at Phase 4 exit; five Phase 6 issues remain blockers (6.1 / 6.2a / 6.2b / 6.3 / 6.4 covering KM-3 / URL-1 / URL-2 / GRPC+L-1 / VS-1). Misreading this risks shipping before the P1 tail. | Plan explicitly cuts the release after 6.4; the five blockers are sequenced first in Phase 6 (~12 points, ~5–6 days). |
| Info-5d env-mutation flake | [6 / 6.22d](./06-phase-6.md) | Process-global env mutation in tests flakes under parallel `cargo test`. The original single-branch Info-5 was split into 6.22a–6.22d (one per crate) to fit the architecture's max-2-file blast-radius rule. | `std::sync::Mutex<()>` env-mutex per ADR-011 (not `serial_test`, rejected per P6); flake-detection test runs in a loop first. |
| DVT-2 v1-removal sequencing | [6 / 6.8a → 6.8b](./06-phase-6.md) | Server-side delete is only safe after the last client caller is gone; original single 3pt issue collapsed client + server. | Split into 6.8a (client migration, 2pt) → 6.8b (server removal, 1pt); branch ordering structurally enforces "no callers left" before the server impl is removed. |
| Info-4 / Phase 1 scope addition (discovered) | [6 / 6.21](./06-phase-6.md) | `canonical::parse_fork_version_hex` is **not** among the three helpers Phase 1 Task 1.1 ships (it ships `parse_pubkey_hex`, `parse_gvr_hex`, `parse_signing_root_hex` only). Info-4's BN-boundary fork-version validation needs the 4-byte-hex variant. **Resolve at execution time:** either land a tiny Phase 1 retroactive extension adding `parse_fork_version_hex`, or implement inline in 6.21 with a TODO to promote later. Flag the chosen path at the 6.21 review gate. | Flagged in 6.21 Implementation Notes with both resolution paths documented; scope estimate is 1 day if added in Phase 1 retroactively, 2 days (3pt) if implemented inline. |
| Standing-gate regression | All phases | New dep edges or new crates can silently re-introduce a forbidden architecture edge. | `tests/architecture_no_cycles.rs` + enumeration gate are re-asserted at every phase exit; new crates (signer-registry, net-policy) verified to add no cycle. |

---

## Totals

- **Total issues:** 93
- **Total points:** 189
- **Total estimated duration:** ~101 working days (single-stream, one experienced Rust
  developer; sum of per-phase execution-plan day budgets: 13 + 18 + 9 + 32 + 7 + 22)
- **Release-blocking subset:** 6.1, 6.2a, 6.2b, 6.3, 6.4 → 12 points, ~5–6 working
  days. Release cut happens after 6.4 per DL-5.
- **Findings closed:** 46 (1 Critical + 13 High + 13 Medium + 14 Low + 5 Info)
- **Deferrable P2 tail:** 6.5 through 6.22d (~32 points, ~16 working days) — may roll
  to a follow-up release at the user's discretion (PRD §11).
