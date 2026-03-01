use anyhow::Result;

use crate::config::TelemetryConfig;
use crate::TracingGuard;

/// Initialize the tracing pipeline with the given configuration.
///
/// Returns a [`TracingGuard`] that must be held for the lifetime of the
/// application. Dropping the guard shuts down the trace provider.
pub fn init_tracing(_config: &TelemetryConfig) -> Result<TracingGuard> {
    todo!("H-02: implement OTLP/HTTP exporter pipeline")
}
