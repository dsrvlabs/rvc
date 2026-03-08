use std::time::Duration;

use crate::TracingGuard;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Shut down the tracing pipeline, flushing any pending spans.
///
/// Consumes the [`TracingGuard`] and calls `shutdown()` on the
/// underlying trace provider with a 5-second timeout. All error
/// paths are logged as warnings — this function never panics.
pub async fn shutdown_tracing(guard: TracingGuard) {
    tracing::info!("Flushing OpenTelemetry traces");

    let result = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        tokio::task::spawn_blocking(move || guard.provider.shutdown()),
    )
    .await;

    match result {
        Ok(Ok(Ok(()))) => tracing::info!("OpenTelemetry traces flushed"),
        Ok(Ok(Err(e))) => tracing::warn!(error = %e, "OpenTelemetry shutdown error"),
        Ok(Err(e)) => tracing::warn!(error = %e, "OpenTelemetry shutdown task panicked"),
        Err(_) => tracing::warn!("OpenTelemetry shutdown timed out after 5s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelemetryConfig;
    use crate::init::init_tracing;

    #[tokio::test]
    async fn test_shutdown_after_init() {
        let config = TelemetryConfig::default();
        let (_layer, guard) = init_tracing(&config).expect("init should succeed");
        shutdown_tracing(guard).await;
    }

    #[tokio::test]
    async fn test_shutdown_does_not_panic() {
        let config = TelemetryConfig {
            endpoint: "http://unreachable:4318".to_string(),
            sample_rate: 0.0,
            ..Default::default()
        };
        let (_layer, guard) = init_tracing(&config).expect("init should succeed");
        shutdown_tracing(guard).await;
    }
}
