//! Latency-sanity bench for the orchestrator per-slot logging (issue 2.13).
//!
//! Companion to `crates/rvc/tests/zero_alloc.rs`. It times the disabled-able
//! per-slot `debug!` decision statements under three subscriber regimes:
//!
//! - `no_subscriber`: no dispatcher installed.
//! - `subscriber_info`: info level over a consuming `fmt`→`io::sink` layer, so
//!   debug is filtered and no event fires.
//! - `subscriber_trace`: trace level over the SAME layer, so events fire AND are
//!   rendered.
//!
//! The info/trace regimes share an identical layer stack (`fmt::layer()` writing
//! to `io::sink`) and differ ONLY by level. The sanity it asserts by eye:
//! `subscriber_info ≈ no_subscriber` — an `info`-default VC pays nothing per slot
//! for the debug/trace instrumentation, while `subscriber_trace` is materially
//! higher. Non-blocking; run via `cargo bench`, NOT under `nextest`/CI.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use crypto::logging::TruncatedRoot;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

/// Mirrors the representative disabled-able per-slot `debug!` decision lines in
/// the coordinator, plus a `%`-formatted-field line.
fn emit_per_slot_logs(head: &[u8; 32]) {
    tracing::debug!(slot = 1000u64, "No duties for slot");
    tracing::debug!(slot = 1000u64, wait_ms = 4000u128, "Waiting for attestation time");
    tracing::debug!(slot = 1000u64, wait_ms = 8000u128, "Waiting for 2/3 slot time");
    tracing::debug!(
        slot = 1000u64,
        epoch = 31u64,
        head = %TruncatedRoot::new(head),
        "per-slot %-field probe"
    );
}

fn bench_per_slot_logging(c: &mut Criterion) {
    let head = [0xcd_u8; 32];

    let mut group = c.benchmark_group("per_slot_logging");

    // MUST stay lexically first: tracing's max-level hint is process-global and
    // is NOT lowered when a `set_default` guard drops, so running this after the
    // `trace` regime would inflate it. No dispatcher installed here.
    group.bench_function("no_subscriber", |b| {
        b.iter(|| emit_per_slot_logs(black_box(&head)));
    });

    {
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::INFO)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink));
        let _guard = tracing::subscriber::set_default(subscriber);
        group.bench_function("subscriber_info", |b| {
            b.iter(|| emit_per_slot_logs(black_box(&head)));
        });
    }

    {
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::TRACE)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink));
        let _guard = tracing::subscriber::set_default(subscriber);
        group.bench_function("subscriber_trace", |b| {
            b.iter(|| emit_per_slot_logs(black_box(&head)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_per_slot_logging);
criterion_main!(benches);
