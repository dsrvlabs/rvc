//! ARCH-5a load harness: latency-injecting BLS backend + concurrent signer-server driver.
//!
//! **This is not a VC-path profile.** The VC attestation loop is sequential
//! (`crates/rvc/src/orchestrator/attestation.rs`), so 200 keys × 200 ms = 40 s
//! even with a free slashing DB (X8). The mutex only binds where requests
//! arrive concurrently — `signer-server` / `SigningGate`.
//!
//! # Profile (A-9)
//!
//! | | |
//! |---|---|
//! | Target | `signer-server` (`SignerServiceImpl::sign_attestation_data`) |
//! | Keys | 200 (distinct pubkeys, one attestation each) |
//! | Injected BLS latency | 200 ms `tokio::time::sleep` on [`helpers::SlowSigner`] |
//! | DB | real [`slashing::SlashingDb::open`] temp file |
//! | Pragmas in force | `journal_mode=WAL`, `synchronous=EXTRA`, `fullfsync=ON` (macOS) |
//! | Metric | `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}` |
//!
//! # Invocation
//!
//! The 200-key run is `#[ignore]`d so `cargo nextest run --workspace` stays
//! fast. ARCH-5b / operators run:
//!
//! ```text
//! cargo nextest run -p rvc-signer-server --run-ignored ignored-only --no-capture \
//!   -E 'test(test_load_profile_reports_p99_above_serialized_floor)'
//! ```
//!
//! nextest 0.9 only emulates `--ignored` / `--exact` / `--skip` and does not
//! forward arbitrary test-binary args. To also write the JSON to a file, pass
//! the env-free `--output` CLI arg through libtest:
//!
//! ```text
//! cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
//!   --exact test_load_profile_reports_p99_above_serialized_floor \
//!   -- --output path/to/summary.json
//! ```
//!
//! The machine-readable summary is always printed to stdout; `--output PATH`
//! additionally writes that same JSON for ARCH-5b to commit verbatim.
//!
//! Do **not** name any test in this file `*_root` (KAT scanner, A-5.10).

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use metrics::definitions::{tx_hold_kind, RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS};
use tonic::Request;

use signer_server::proto::signer_v2 as sv2;
use signer_server::proto::signer_v2::signer_service_server::SignerService;

mod helpers;
use helpers::{
    make_load_fixture, make_load_fixture_with, sample_fork_info, LOAD_PROFILE_INJECTED_LATENCY,
    LOAD_PROFILE_KEY_COUNT,
};

// ── Summary types ─────────────────────────────────────────────────────────────

/// Percentile bundle for one latency series (milliseconds).
#[derive(Clone, Debug, PartialEq)]
struct Percentiles {
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

/// Machine-readable load-profile result (stdout + optional `--output` file).
#[derive(Clone, Debug)]
struct LoadSummary {
    keys: usize,
    injected_latency_ms: f64,
    achieved_concurrency: usize,
    effective_concurrency: f64,
    successes: usize,
    failures: usize,
    total_wall_ms: f64,
    wall: Percentiles,
    tx_hold: Percentiles,
    tx_hold_count: u64,
    tx_hold_sum_ms: f64,
}

impl LoadSummary {
    fn to_json(&self) -> String {
        format!(
            "{{\n  \"issue\": \"ARCH-5a\",\n  \"target\": \"signer-server\",\n  \
             \"target_reason\": \"VC path wall is its sequential attestation loop, not the slashing mutex (X8)\",\n  \
             \"keys\": {keys},\n  \"injected_latency_ms\": {inj},\n  \
             \"db_pragmas\": {{\n    \"journal_mode\": \"wal\",\n    \"synchronous\": \"EXTRA\",\n    \
             \"fullfsync\": \"{fsync}\"\n  }},\n  \
             \"achieved_concurrency\": {achieved},\n  \"effective_concurrency\": {effective:.3},\n  \
             \"successes\": {ok},\n  \"failures\": {fail},\n  \"total_wall_ms\": {total:.3},\n  \
             \"wall_ms\": {{ \"p50\": {wp50:.3}, \"p95\": {wp95:.3}, \"p99\": {wp99:.3}, \"max\": {wmax:.3} }},\n  \
             \"tx_hold_ms\": {{ \"p50\": {hp50:.3}, \"p95\": {hp95:.3}, \"p99\": {hp99:.3}, \"max\": {hmax:.3}, \
             \"count\": {hcount}, \"sum\": {hsum:.3} }}\n}}\n",
            keys = self.keys,
            inj = self.injected_latency_ms,
            fsync = if cfg!(target_os = "macos") { "ON" } else { "n/a" },
            achieved = self.achieved_concurrency,
            effective = self.effective_concurrency,
            ok = self.successes,
            fail = self.failures,
            total = self.total_wall_ms,
            wp50 = self.wall.p50,
            wp95 = self.wall.p95,
            wp99 = self.wall.p99,
            wmax = self.wall.max,
            hp50 = self.tx_hold.p50,
            hp95 = self.tx_hold.p95,
            hp99 = self.tx_hold.p99,
            hmax = self.tx_hold.max,
            hcount = self.tx_hold_count,
            hsum = self.tx_hold_sum_ms,
        )
    }
}

/// Nearest-rank percentile on a **sorted** sample slice. `p` in `[0, 1]`.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(!sorted.is_empty(), "percentile of empty sample");
    assert!((0.0..=1.0).contains(&p), "percentile p must be in [0, 1]");
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn percentiles_of(mut samples: Vec<f64>) -> Percentiles {
    assert!(!samples.is_empty(), "percentiles of empty sample");
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Percentiles {
        p50: percentile(&samples, 0.50),
        p95: percentile(&samples, 0.95),
        p99: percentile(&samples, 0.99),
        max: samples[samples.len() - 1],
    }
}

fn output_path_from_cli() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(path) = arg.strip_prefix("--output=") {
            return Some(PathBuf::from(path));
        }
        if arg == "--output" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

fn emit_summary(summary: &LoadSummary) {
    let json = summary.to_json();
    print!("{json}");
    let _ = std::io::stdout().flush();
    if let Some(path) = output_path_from_cli() {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|e| panic!("create parent dir {}: {e}", parent.display()));
            }
        }
        std::fs::write(&path, json.as_bytes())
            .unwrap_or_else(|e| panic!("write summary {}: {e}", path.display()));
    }
}

fn sample_attestation_data(source_epoch: u64, target_epoch: u64) -> sv2::AttestationData {
    sv2::AttestationData {
        slot: target_epoch * 32,
        index: 0,
        beacon_block_root: vec![0x33u8; 32],
        source: Some(sv2::Checkpoint { epoch: source_epoch, root: vec![0x44u8; 32] }),
        target: Some(sv2::Checkpoint { epoch: target_epoch, root: vec![0x55u8; 32] }),
    }
}

fn attestation_request(pubkey: [u8; 48]) -> Request<sv2::SignAttestationDataRequest> {
    Request::new(sv2::SignAttestationDataRequest {
        pubkey: pubkey.to_vec(),
        fork_info: Some(sample_fork_info()),
        data: Some(sample_attestation_data(1, 2)),
        fork_id: 4,
    })
}

/// Serialized-floor p99 must clear `(n × injected) / concurrency` minus one
/// injected quantum (nearest-rank p99 of a perfect 200-wide wave is the 199th
/// completion, not the last).
fn p99_meets_serialized_floor(
    p99_ms: f64,
    keys: usize,
    injected_ms: f64,
    concurrency: usize,
) -> bool {
    let conc = concurrency.max(1) as f64;
    let floor = (keys as f64) * injected_ms / conc;
    p99_ms + injected_ms + 1e-9 >= floor
}

async fn drive_concurrent_attestations(
    service: signer_server::service::SignerServiceImpl,
    pubkeys: &[[u8; 48]],
    injected_latency_ms: f64,
    slow: &helpers::SlowSigner,
) -> LoadSummary {
    let hist =
        RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS.with_label_values(&[tx_hold_kind::ATTESTATION]);
    let start_count = hist.get_sample_count();
    let start_sum = hist.get_sample_sum();
    let mut prev_count = start_count;
    let mut prev_sum = start_sum;

    let svc = Arc::new(service);
    let mut set = tokio::task::JoinSet::new();
    let total_start = Instant::now();
    for pk in pubkeys.iter().copied() {
        let svc = Arc::clone(&svc);
        set.spawn(async move {
            let start = Instant::now();
            let result = svc.sign_attestation_data(attestation_request(pk)).await;
            let wall_ms = start.elapsed().as_secs_f64() * 1000.0;
            match result {
                Ok(_) => (true, wall_ms, None),
                Err(status) => (false, wall_ms, Some(status.to_string())),
            }
        });
    }

    let mut walls = Vec::with_capacity(pubkeys.len());
    let mut holds = Vec::with_capacity(pubkeys.len());
    let mut successes = 0usize;
    let mut first_error: Option<String> = None;
    while let Some(joined) = set.join_next().await {
        let (ok, wall_ms, err) = joined.expect("load-profile task panicked");
        walls.push(wall_ms);
        if ok {
            successes += 1;
        } else if first_error.is_none() {
            first_error = err;
        }

        let count = hist.get_sample_count();
        let sum = hist.get_sample_sum();
        let delta_n = count.saturating_sub(prev_count);
        if delta_n == 1 {
            holds.push(sum - prev_sum);
        } else if delta_n > 1 {
            let avg = (sum - prev_sum) / delta_n as f64;
            holds.extend(std::iter::repeat_n(avg, delta_n as usize));
        }
        prev_count = count;
        prev_sum = sum;
    }

    let total_wall_ms = total_start.elapsed().as_secs_f64() * 1000.0;
    let failures = pubkeys.len() - successes;
    if let Some(ref err) = first_error {
        eprintln!("load-profile first error ({failures} failures): {err}");
    }

    let wall = percentiles_of(walls);
    let tx_hold = if holds.is_empty() {
        Percentiles { p50: 0.0, p95: 0.0, p99: 0.0, max: 0.0 }
    } else {
        percentiles_of(holds)
    };
    let tx_hold_count = hist.get_sample_count().saturating_sub(start_count);
    let tx_hold_sum_ms = hist.get_sample_sum() - start_sum;
    let effective_concurrency = if total_wall_ms > 0.0 {
        (pubkeys.len() as f64) * injected_latency_ms / total_wall_ms
    } else {
        0.0
    };

    LoadSummary {
        keys: pubkeys.len(),
        injected_latency_ms,
        achieved_concurrency: slow.max_in_flight(),
        effective_concurrency,
        successes,
        failures,
        total_wall_ms,
        wall,
        tx_hold,
        tx_hold_count,
        tx_hold_sum_ms,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Fast non-vacuity of the floor check: a free-DB / no-mutex wave (every call
/// ≈ injected latency) must **not** clear the serialized floor.
#[test]
fn test_serialized_floor_rejects_free_db_latencies() {
    let keys = LOAD_PROFILE_KEY_COUNT;
    let injected = LOAD_PROFILE_INJECTED_LATENCY.as_secs_f64() * 1000.0;
    let free_db = vec![injected; keys];
    let p99 = percentile(&free_db, 0.99);
    assert!(
        !p99_meets_serialized_floor(p99, keys, injected, 1),
        "artificially free DB (p99={p99}) must fail the serialized floor"
    );
}

#[test]
fn test_percentile_nearest_rank_on_known_samples() {
    let samples = [1.0, 2.0, 3.0, 4.0];
    assert_eq!(percentile(&samples, 0.0), 1.0);
    assert_eq!(percentile(&samples, 1.0), 4.0);
    assert_eq!(percentile(&[7.0], 0.99), 7.0);
    let p = percentiles_of(vec![10.0, 20.0, 30.0]);
    assert_eq!(p.max, 30.0);
    assert!(p.p50 >= 10.0 && p.p50 <= 30.0);
}

/// 1 key, 200 ms injected: the tx-hold histogram must record ≥ 200 ms so the
/// injector is not being bypassed by `spawn_blocking`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_slow_signer_delays_are_observed_through_the_blocking_bridge() {
    let fixture = make_load_fixture_with(1, LOAD_PROFILE_INJECTED_LATENCY);
    let injected_ms = fixture.injected_latency.as_secs_f64() * 1000.0;
    let hist =
        RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS.with_label_values(&[tx_hold_kind::ATTESTATION]);
    let count_before = hist.get_sample_count();
    let sum_before = hist.get_sample_sum();

    let start = Instant::now();
    let pubkey = fixture.pubkeys[0];
    fixture
        .service
        .sign_attestation_data(attestation_request(pubkey))
        .await
        .expect("single-key load sign must succeed");
    let wall_ms = start.elapsed().as_secs_f64() * 1000.0;

    let count_after = hist.get_sample_count();
    let sum_after = hist.get_sample_sum();
    assert!(
        count_after > count_before,
        "tx-hold histogram must be observed through the blocking bridge; before={count_before} after={count_after}"
    );
    let hold_ms = (sum_after - sum_before) / (count_after - count_before) as f64;
    assert!(
        hold_ms + 1e-9 >= injected_ms,
        "recorded hold {hold_ms} ms must be ≥ injected {injected_ms} ms (spawn_blocking must not drop the async sleep)"
    );
    assert!(
        wall_ms + 1e-9 >= injected_ms,
        "client wall {wall_ms} ms must be ≥ injected {injected_ms} ms"
    );
}

/// 200 concurrent `sign_attestation` calls. Ignored so workspace nextest stays
/// fast. Asserts the harness detects full slashing-mutex serialization.
#[ignore = "ARCH-5a load profile (~40s+); see file header for nextest invocation"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_load_profile_reports_p99_above_serialized_floor() {
    let fixture = make_load_fixture();
    let injected_ms = fixture.injected_latency.as_secs_f64() * 1000.0;
    let keys = fixture.key_count;
    assert_eq!(keys, LOAD_PROFILE_KEY_COUNT);
    assert_eq!(fixture.pubkeys.len(), keys);

    let slow = Arc::clone(&fixture.slow);
    let service = fixture.service;
    let pubkeys = fixture.pubkeys;
    let summary =
        drive_concurrent_attestations(service, &pubkeys, injected_ms, slow.as_ref()).await;
    emit_summary(&summary);

    assert_eq!(
        summary.successes, keys,
        "every load-profile sign must succeed; failures={}",
        summary.failures
    );
    assert!(
        summary.achieved_concurrency <= 2,
        "harness must observe slashing-mutex serialization (SlowSigner max_in_flight ≤ 2); got {}",
        summary.achieved_concurrency
    );
    assert!(
        p99_meets_serialized_floor(
            summary.wall.p99,
            keys,
            injected_ms,
            summary.achieved_concurrency
        ),
        "wall p99 {} ms must be ≥ ({} × {} ms) / {} minus one injected quantum",
        summary.wall.p99,
        keys,
        injected_ms,
        summary.achieved_concurrency
    );
    assert!(
        p99_meets_serialized_floor(
            summary.tx_hold.p99,
            keys,
            injected_ms,
            summary.achieved_concurrency
        ),
        "tx-hold p99 {} ms must be ≥ serialized floor (histogram must not look like a free DB)",
        summary.tx_hold.p99
    );
    assert!(
        summary.tx_hold_count >= keys as u64,
        "histogram must record one observation per sign; count={}",
        summary.tx_hold_count
    );
}
