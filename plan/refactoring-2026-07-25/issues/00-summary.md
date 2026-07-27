# rvc Refactoring — Cross-Phase Issue Summary

> Engineering-lead roll-up across the six phase breakdowns of the workspace refactoring driven by
> [`../refactoring-plan.md`](../refactoring-plan.md) (itself synthesized from 131 analyzer
> findings in [`../refactoring-findings.json`](../refactoring-findings.json)). Each phase file
> is self-contained; this summary is the planning index — total scope, point totals, execution
> order, and cross-phase dependencies.
>
> Phase files: [Phase 1](01-phase-1.md) · [Phase 2](02-phase-2.md) · [Phase 3](03-phase-3.md) ·
> [Phase 4](04-phase-4.md) · [Phase 5](05-phase-5.md) · [Phase 6](06-phase-6.md)

## Estimation Approach

Same conventions as the security remediation track (`plan/security-2026-07-18/issues/`):

- **Point scale:** 1 (trivial) / 2 (small) / 3 (medium). **Every issue is completable in 1–2 days =
  1–3 points**; the plan's L/XL items are split into ordered chains of sub-issues — no final issue
  exceeds 3 points.
- **Day-rate:** ~1 point ≈ 0.5–1 working day for one developer; points include coding + tests +
  review + integration.
- **Grounded against HEAD** (`develop` v0.6.0, `a7f8cdf`): estimators re-verified the plan's
  file:line citations by reading the cited files; stale citations and rating corrections are flagged
  inline in the phase files.
- **Two parallel streams (A/B)** per phase for 2 developers, chosen for disjoint files.
- **TDD:** every issue's test plan names its RED case first (CLAUDE.md convention); for pure
  deletions the proof is an `rg` zero-caller audit + green suite; for pure code motion, a
  moves-only diff + unchanged test count.

## Phase Table

| File | Phase | Plan items | Issues | Points | 2-dev duration |
|------|-------|-----------|--------|--------|----------------|
| [01-phase-1.md](01-phase-1.md) | 1: Correctness fixes & safety nets | A1–A7 | 12 | 26 | ~14 days |
| [02-phase-2.md](02-phase-2.md) | 2: Dead-code purge | B1–B11 | 17 | 38 | ~12–18 days |
| [03-phase-3.md](03-phase-3.md) | 3: Foundations | C1–C8, G5–G7 | 20 | 51 | ~14–26 days |
| [04-phase-4.md](04-phase-4.md) | 4: Core consolidation | D1–D7, E1–E7, E8a–d, E9 | 30 | 73 | ~28–30 days |
| [05-phase-5.md](05-phase-5.md) | 5: Composition roots & config | F1–F7 | 32 | 80 | ~21–41 days |
| [06-phase-6.md](06-phase-6.md) | 6: Structure, tests & docs | G1–G4, H1–H7 | 32 | 78 | ~22–34 days |
| **Total** | | | **143** | **346** | **~111–163 working days** |

Phases are strictly sequential (each phase gate must pass before the next begins); streams A/B run
in parallel within a phase. With 2 developers the full program is roughly **5–8 calendar months**.
Phases 1–2 alone (the correctness fixes plus dead-code purge, ~26–32 days) deliver the highest
risk-reduction per day and are a defensible stopping point if priorities shift.

## Execution Order & Cross-Phase Dependencies

Sequential phase gates, with these hard cross-phase edges (each also marked in the affected issues):

| Edge | Constraint |
|------|-----------|
| A2 (P1) → B4 (P2) | Slashing conformance suite must be retargeted at `stage_*` before the gen-1/2 APIs are deleted |
| A1/A2 (P1) → B5 (P2) | Watermark subsystem is **wired, not deleted** — P1's stage-path watermark tests depend on it |
| B7 (P2) → D1 (P4) | Crypto KATs migrate to surviving helpers in P2, re-home onto `signing_root_for` in P4 |
| B10 (P2) → C4 (P3), D4 (P4) | v1 proto retirement precedes the shared signer-proto crate and transport unification |
| A7 (P1) → D4 (P4) | gRPC metrics recording helper is absorbed by the SignPlan dispatcher; scrape test stays green |
| C1–C8 (P3) → D/E (P4) | Consolidations point at the P3 foundations (observability crate, ForkName, wire types) |
| P1–P5 → P6 | File splits/test relocation last — they conflict with every earlier diff |

**External coordination (in-flight tracks, not duplicated here):**

- `plan/security-2026-07-18/` — SEC-1 precedes F5 (P5); SEC-2 gates E8c (P4); SEC-6 typed-SSZ work
  serializes with G1/G2 (P6); SEC-5 owns the hot-path unwrap DoS case.
- `docs/issues/` test-audit track — H4 mock-fidelity work (P6) aligns with its phase 2; fuzz
  coverage stays owned by its phase 3.

## Safety-Critical Constraints (binding, from the plan's adversarial review)

- **D2 (P4):** sign-timeout semantics are backend-dependent and fail-closed — the staged slashing
  row is retained/committed on timeout against remote backends, never discarded; the
  late-completion double-sign test is a phase-gate criterion.
- **Phase 1's retargeted conformance suite** is the master oracle for all later slashing work; the
  pipeline double-vote test guards the orchestrator→signer→slashing wiring through P4–P5.
- Deliberate behavior changes (watermark equality, `--password-dir`, builder fork version, VC sign
  timeout, proposer failover, config precedence, hex-parse policy) each carry an explicit test and
  a release-note flag in their issue.

## Standing Invariant (every PR, every phase)

`cargo fmt --check` · `cargo clippy --workspace` (warnings addressed) · `cargo test --workspace` ·
`cargo test -p rvc-architecture-tests` — plus the per-phase gates listed in each phase file.
