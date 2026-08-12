# Architecture measurements (Phase 0 baselines)

Checked-in baselines for success metrics that Phase 3+ must improve against.
Recorded under **ARCH-7c** on harness commit `92d9bbde0aedec10dce43db20fd8c51bea8dd8e2` (ARCH-7a metric + ARCH-7b harness).

| File | Metric | Phase-0 role |
|---|---|---|
| [`m1-missed-proposals.md`](./m1-missed-proposals.md) | **M1** miss rate under duty-fetch stall | ~100 % cold×60 s miss is **expected**; ADR-004 / Phase 3 owns 0 % |
| [`m2-slot-phase0-offset.md`](./m2-slot-phase0-offset.md) | **M2** `rvc_slot_phase_block_start_offset_ms` p99 warm/cold | Separate warm/cold p99 for A-5 targets (≤1 s / ≤2 s) |

Future scale baseline (not this task): `m3-scale-200keys-200ms.md` (ARCH-7m / Phase 5–7).

---

## Re-run commands (one per metric)

From the repository root, on a clean tree at or after the harness commit:

### M1 — missed proposals

```bash
cargo test -p rvc --test proposal_under_duty_stall -- --nocapture --test-threads=1
```

Capture lines matching `ARCH-7b M1 cell` and `ARCH-7b RED baseline`.
Primary RED cell: **duty_cache=cold, stall=60s** → expect **miss_rate=100.0%** at Phase 0.
Contrast cell: **duty_cache=warm, stall=60s** → expect **miss_rate=0.0%** (harness soundness).

### M2 — slot phase-0 offset

```bash
# Multi-slot sample counts + MockSlotClock offsets (co-measured by M1 harness)
cargo test -p rvc --test proposal_under_duty_stall -- --nocapture --test-threads=1

# Instrument credibility (SystemSlotClock + injected duty delay ≥ D)
cargo test -p rvc --lib orchestrator::coordinator::tests::phase_block_offset -- --nocapture --test-threads=1
```

Histogram values: process-local `get_sample_sum` / `get_sample_count` on
`metrics::definitions::RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS` with labels
`cache=cold` / `cache=warm`. Under the current M1 fixture (`MockSlotClock` +
`advance_time(9)`), means are **9000 ms** (second resolution). For wall-clock
duty reflection, use the ARCH-7a `test_offset_reflects_pre_proposal_work` path
(D = 2 s → cold mean ≥ 2000 ms; observed baseline mean **8000 ms**).

---

## Reproducibility / tolerance

| Metric | Surface | Independent runs (ARCH-7c) | Stated tolerance |
|---|---|---|---|
| M1 miss rate | virtual-time matrix | exact match both runs | **±0 slots / ±0.0 %** |
| M2 offset | MockSlotClock multi-slot | exact 9000 ms both runs | **±0 ms** |
| M2 offset | SystemSlotClock + D=2 s | exact 8000 ms mean both runs | **±2000 ms** mean; must stay **≥ D** |

**RED (reproducibility):** hand this README to a second person (or clean clone), re-run both commands, and compare against the tables in `m1-*.md` / `m2-*.md`. If numbers fall outside the tolerance band, fix the README (or document a harness/fixture change) — do not silently “fix” a baseline by reordering the slot loop (that is Phase 3 / ADR-004).

---

## Environment template (fill when re-baselining)

```
harness commit:  <git rev-parse HEAD of ARCH-7b-capable tree>
rustc:           <rustc --version>
cargo:           <cargo --version>
host:            <cpu / cores / RAM / OS>
date (UTC):      <date -u +%Y-%m-%dT%H:%M:%SZ>
```
