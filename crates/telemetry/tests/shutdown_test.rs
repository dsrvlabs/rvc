use std::time::{Duration, Instant};

use rvc_telemetry::config::TelemetryConfig;
use rvc_telemetry::init::init_tracing;
use rvc_telemetry::shutdown::shutdown_tracing;
use tracing_subscriber::prelude::*;

/// Creates a subscriber with the OTel layer, runs a closure under it,
/// then shuts down the guard.  Returns the wall-clock shutdown duration.
async fn run_and_shutdown(config: TelemetryConfig, f: impl FnOnce()) -> Duration {
    let (otel_layer, guard) = init_tracing(&config).expect("init_tracing should succeed");

    // Install subscriber scoped to this test (not global)
    let subscriber = tracing_subscriber::registry().with(otel_layer);
    let _default = tracing::subscriber::set_default(subscriber);

    f();

    // Drop the subscriber guard so the OTel layer is no longer active,
    // allowing the provider to flush.
    drop(_default);

    let start = Instant::now();
    shutdown_tracing(guard).await;
    start.elapsed()
}

#[tokio::test]
async fn test_shutdown_with_no_spans_completes_quickly() {
    let config = TelemetryConfig {
        endpoint: "http://localhost:1".to_string(), // unreachable
        ..Default::default()
    };

    let elapsed = run_and_shutdown(config, || {
        // No spans created
    })
    .await;

    assert!(
        elapsed < Duration::from_secs(6),
        "Shutdown with no spans should complete within timeout, took {elapsed:?}"
    );
}

#[tokio::test]
async fn test_shutdown_with_many_spans_completes_within_timeout() {
    let config = TelemetryConfig {
        endpoint: "http://localhost:1".to_string(), // unreachable — forces span accumulation
        sample_rate: 1.0,
        ..Default::default()
    };

    let elapsed = run_and_shutdown(config, || {
        // Create 1000+ spans rapidly
        for i in 0..1100 {
            let _span = tracing::info_span!("rvc.test.burst", iteration = i).entered();
            tracing::info!("span event {i}");
        }
    })
    .await;

    // 5s timeout + 1s buffer
    assert!(
        elapsed < Duration::from_secs(6),
        "Shutdown with 1100 in-flight spans should complete within 6s, took {elapsed:?}"
    );
}

#[tokio::test]
async fn test_shutdown_does_not_panic_with_unreachable_endpoint() {
    let config = TelemetryConfig {
        endpoint: "http://localhost:1".to_string(),
        sample_rate: 1.0,
        ..Default::default()
    };

    // This should not panic regardless of exporter state
    let (otel_layer, guard) = init_tracing(&config).expect("init_tracing should succeed");
    let subscriber = tracing_subscriber::registry().with(otel_layer);
    let _default = tracing::subscriber::set_default(subscriber);

    for i in 0..500 {
        let _span = tracing::info_span!("rvc.test.unreachable", i = i).entered();
    }

    drop(_default);
    shutdown_tracing(guard).await;
    // If we reach here, no panic occurred
}
