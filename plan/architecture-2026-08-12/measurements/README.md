# Architecture measurements (Phase 0 baselines + Phase 5 M3)

Checked-in baselines for success metrics that later phases must improve against.

- **M1 / M2 (Phase 0):** recorded under **ARCH-7c** on harness commit
  `92d9bbde0aedec10dce43db20fd8c51bea8dd8e2` (ARCH-7a metric + ARCH-7b harness).
- **M3 (Phase 5 entry E2):** recorded under **ARCH-5b** against the ARCH-5a
  `signer-server` load harness on develop `11bb569` (architecture baseline name
  `0ae9a09`). Gates every issue from `ARCH-5i` onward.

| File | Metric | Role |
|---|---|---|
| [`m1-missed-proposals.md`](./m1-missed-proposals.md) | **M1** miss rate under duty-fetch stall | ~100 % cold×60 s miss is **expected**; ADR-004 / Phase 3 owns 0 % |
| [`m2-slot-phase0-offset.md`](./m2-slot-phase0-offset.md) | **M2** `rvc_slot_phase_block_start_offset_ms` p99 warm/cold | Separate warm/cold p99 for A-5 targets (≤1 s / ≤2 s) |
| [`m1-m2-post-phase3.md`](./m1-m2-post-phase3.md) | **M1/M2 after ADR-004** (ARCH-3k) | M1 = 0 at 60 s and 80 s; M2 p99 0 ms at slot start (≤1 s / ≤2 s) |
| [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md) | **M3** slashing tx-hold (ARCH-5a / ARCH-5b) | Three-run median; concurrency = 1; observation-window decision (keep current series, add reserve-tx in 5l); per-sign budget = 3999/200 = 19.995 ms |

Post-ADR-005 counterpart (not this task): `m3-post-adr005.md` (**ARCH-5m**). That
file must cite the measured commit hash recorded in `m3-baseline-0ae9a09.md`.

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

### M3 — slashing tx-hold (signer-server load profile)

The 200-key / 200 ms run is `#[ignore]`d. Full A-9 profile (what ARCH-5b recorded):

```bash
# JSON on stdout; --output also writes the same document (libtest only)
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/m3-baseline-run.json
```

nextest equivalent (stdout only; nextest 0.9 does not forward `--output`):

```bash
cargo nextest run -p rvc-signer-server --run-ignored ignored-only --no-capture \
  -E 'test(test_load_profile_reports_p99_above_serialized_floor)'
```

Run **three** times. Record all three plus the median; do not keep a single run.
Compare against [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md). Capture
`achieved_concurrency`, `effective_concurrency`, wall and
`rvc_signer_slashing_tx_hold_duration_ms` p50/p95/p99/max, and the DB pragmas
object. A p99 spread **> 20 %** across the three runs is a harness defect
(reopen ARCH-5a), not a number to average.

This profile targets **`signer-server` / `SigningGate`**, not the VC
attestation loop (X8).

---

## Reproducibility / tolerance

| Metric | Surface | Independent runs | Stated tolerance |
|---|---|---|---|
| M1 miss rate | virtual-time matrix | exact match both runs (ARCH-7c) | **±0 slots / ±0.0 %** |
| M2 offset | MockSlotClock multi-slot | exact 9000 ms both runs | **±0 ms** |
| M2 offset | SystemSlotClock + D=2 s | exact 8000 ms mean both runs | **±2000 ms** mean; must stay **≥ D** |
| M3 tx-hold p99 | ARCH-5a 200×200 ms, `test` profile | three runs, 0.209 % p99 spread (ARCH-5b) | **±5 %** on this host; **> 20 %** reopens ARCH-5a |

**RED (reproducibility):** hand this README to a second person (or clean clone), re-run the commands, and compare against the tables in `m1-*.md` / `m2-*.md` / `m3-baseline-0ae9a09.md`. If numbers fall outside the tolerance band, fix the README (or document a harness/fixture change) — do not silently “fix” a baseline by reordering the slot loop (that is Phase 3 / ADR-004) or by redefining the M3 observation window (that is ARCH-5b's recorded decision; the series add is ARCH-5l).

---

## Environment template (fill when re-baselining)

```
harness commit:  <git rev-parse HEAD of ARCH-7b-capable / ARCH-5a-capable tree>
rustc:           <rustc --version>
cargo:           <cargo --version>
host:            <cpu / cores / RAM / OS>
date (UTC):      <date -u +%Y-%m-%dT%H:%M:%SZ>
profile:         test | release   (M3 baseline is test)
```
