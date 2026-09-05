# Glamsterdam measurements

Checked-in baselines for NFRs that later phases must not regress.

- **P1 signing latency + slot processing (issue 1.1 / #207, D32):** recorded on
  develop `8e908a56c6f1d5de1e92afbcb7222e47551019f5` (post-#205 group-commit,
  **before** any Phase 1/2/3 code). Gates Phase 6 issue **6.14** (three-run
  median p99 within +10 % of this file, same fixtures).

| File | Metric | Role |
|---|---|---|
| [`p1-baseline-8e908a5.md`](./p1-baseline-8e908a5.md) | A-9 `signer-server` load profile (wall / tx-hold / reserve-tx) **and** `rvc_orchestrator_slot_processing_duration_seconds` via `pipeline_fixture` | Three-run median; SHA is an ancestor of every Phase 1/2/3 commit; 6.14 +10 % ceilings derived in-file |

---

## Re-run commands

From the repository root, on a clean tree at the measured commit (or later,
for a comparison run — never as a replacement baseline):

### Sign path (ARCH-5a load profile, `#[ignore]`)

```bash
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/p1-baseline/runN.json
```

Run **three** times. Record all three plus the median. nextest 0.9 does not
forward `--output`.

### Slot processing (`pipeline_fixture`)

The load harness does **not** populate
`RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS`. Method (no checked-in
driver; 1.1 touches only `plan/`):

See [`p1-baseline-8e908a5.md`](./p1-baseline-8e908a5.md) § *Exact invocation
(slot processing)*. Recreate a one-off `pipeline_fixture` driver: 200
unique-epoch `process_slot` calls, drain exact `sample_sum` / `sample_count`
after each, three process invocations. Do not use `histogram_quantile` (first
bucket is 0.01 s; samples are ~3 ms).

---

## Environment template (fill when re-baselining)

```
harness commit:  <git rev-parse HEAD — must predate Phase 1/2/3 for a P1 baseline>
rustc:           <rustc --version>
cargo:           <cargo --version>
host:            <cpu / cores / RAM / OS>
date (UTC):      <date -u +%Y-%m-%dT%H:%M:%SZ>
profile:         test | release   (P1 baseline is test)
```
