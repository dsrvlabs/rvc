//! Telemetry subsystem for the validator client.
//!
//! Provides OpenTelemetry-based distributed tracing with OTLP/HTTP
//! export and optional GCP Cloud Trace support.
//!
//! The normative logging & observability contract for the whole workspace —
//! level taxonomy, the canonical structured-field registry, the secret-redaction
//! policy, and the `#[instrument]` idioms every crate codes against — is defined in
//! [`plan/logging/STANDARD.md`](https://github.com/dsrvlabs/rvc/blob/develop/plan/logging/STANDARD.md)
//! (also available in-tree at `plan/logging/STANDARD.md`).

pub mod config;
pub mod file_appender;
pub mod init;
pub mod propagation;
pub mod shutdown;

pub use config::{ExporterKind, TelemetryConfig};
pub use file_appender::{create_file_layer, FileAppenderConfig};
pub use init::{env_filter_or, init_tracing};
pub use propagation::{inject_trace_context, set_parent_from_headers};
pub use shutdown::shutdown_tracing;

/// Guard that keeps the tracing pipeline alive.
///
/// Must be held for the lifetime of the application. When dropped or
/// passed to [`shutdown_tracing`], the underlying trace provider is
/// shut down and pending spans are flushed.
#[must_use = "dropping TracingGuard shuts down the tracing pipeline"]
pub struct TracingGuard {
    /// The SDK tracer provider backing the pipeline.
    pub(crate) provider: opentelemetry_sdk::trace::SdkTracerProvider,
}
