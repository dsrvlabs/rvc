//! Latency-sanity bench for the sign-path logging (issue 2.13).
//!
//! Companion to the precise Gate-4 zero-alloc test
//! (`crates/signer/tests/zero_alloc.rs`). It times the disabled-able sign-path
//! `debug!`/`trace!` statements under three subscriber regimes:
//!
//! - `no_subscriber`: no dispatcher installed.
//! - `subscriber_info`: info level over a consuming `fmt`→`io::sink` layer, so
//!   debug/trace are filtered and no event fires.
//! - `subscriber_trace`: trace level over the SAME layer, so every event fires
//!   AND is rendered — the lazy `%TruncatedRoot`/`%TruncatedPubkey` args are
//!   actually formatted.
//!
//! The info/trace regimes share an identical layer stack (`fmt::layer()` writing
//! to `io::sink`) and differ ONLY by level, so the contrast isolates the cost of
//! the logging itself — dispatch plus the field rendering a real subscriber pays.
//!
//! The sanity it asserts by eye: `subscriber_info ≈ no_subscriber` — the disabled
//! hot-path logging is free, so an `info`-default production VC pays nothing for
//! the debug/trace instrumentation, while `subscriber_trace` (events fired +
//! rendered) is materially higher. A ~1 ns span is below criterion's noise floor
//! next to a real BLS sign, which is exactly why the allocator test (2.12) is the
//! precise gate and this is only a non-blocking `cargo bench` regression guard —
//! it is NOT run under `nextest` or CI.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use crypto::logging::{TruncatedPubkey, TruncatedRoot};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

/// Mirrors the representative disabled-able `debug!`/`trace!` statements on the
/// `sign_attestation` / `sign_block` hot path (and the `compute_signing_root`
/// trace), including the heaviest domain line (3x `%TruncatedRoot`). Their
/// `%TruncatedRoot` / `%TruncatedPubkey` arguments are lazy.
fn emit_sign_path_logs(pubkey_hex: &str, root: &[u8; 32]) {
    tracing::debug!(
        pubkey = %TruncatedPubkey::new(pubkey_hex),
        slot = 1000u64,
        source_epoch = 100u64,
        target_epoch = 101u64,
        signing_type = "attestation",
        "Signing attestation"
    );
    tracing::debug!(
        pubkey = %TruncatedPubkey::new(pubkey_hex),
        fork_version_used = %TruncatedRoot::new(root),
        genesis_validators_root = %TruncatedRoot::new(root),
        domain = %TruncatedRoot::new(root),
        target_epoch = 101u64,
        "Computed attestation domain"
    );
    tracing::debug!(
        pubkey = %TruncatedPubkey::new(pubkey_hex),
        signing_root = %TruncatedRoot::new(root),
        slot = 1000u64,
        index = 5u64,
        source_epoch = 100u64,
        target_epoch = 101u64,
        "Computed attestation signing root"
    );
    tracing::trace!(
        domain = %TruncatedRoot::new(root),
        signing_root = %TruncatedRoot::new(root),
        "Computed signing root"
    );
    tracing::debug!(duration_ms = 5u64, signing_type = "attestation", "Signing completed");
}

fn bench_sign_path_logging(c: &mut Criterion) {
    let pubkey_hex = "ab".repeat(48);
    let root = [0xcd_u8; 32];

    let mut group = c.benchmark_group("sign_path_logging");

    // MUST stay lexically first: tracing's max-level hint is process-global and
    // is NOT lowered when a `set_default` guard drops, so running this after the
    // `trace` regime would inflate it. No dispatcher installed here.
    group.bench_function("no_subscriber", |b| {
        b.iter(|| emit_sign_path_logs(black_box(pubkey_hex.as_str()), black_box(&root)));
    });

    {
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::INFO)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink));
        let _guard = tracing::subscriber::set_default(subscriber);
        group.bench_function("subscriber_info", |b| {
            b.iter(|| emit_sign_path_logs(black_box(pubkey_hex.as_str()), black_box(&root)));
        });
    }

    {
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::TRACE)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink));
        let _guard = tracing::subscriber::set_default(subscriber);
        group.bench_function("subscriber_trace", |b| {
            b.iter(|| emit_sign_path_logs(black_box(pubkey_hex.as_str()), black_box(&root)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_sign_path_logging);
criterion_main!(benches);
