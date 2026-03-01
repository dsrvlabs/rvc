use crate::TracingGuard;

/// Shut down the tracing pipeline, flushing any pending spans.
///
/// Consumes the [`TracingGuard`] and calls `shutdown()` on the
/// underlying trace provider.
pub fn shutdown_tracing(_guard: TracingGuard) {
    todo!("H-03: implement graceful shutdown with timeout")
}
