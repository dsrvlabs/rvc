use anyhow::Result;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::Registry;

use crate::config::{ExporterKind, TelemetryConfig};
use crate::TracingGuard;

const SERVICE_NAME: &str = "rvc";

/// Initialize the tracing pipeline with the given configuration.
///
/// Returns a tuple of:
/// - An [`OpenTelemetryLayer`] to be composed into a `tracing_subscriber`
/// - A [`TracingGuard`] that must be held for the lifetime of the application
///
/// The caller is responsible for composing the layer into their subscriber.
pub fn init_tracing(
    config: &TelemetryConfig,
) -> Result<(Box<dyn Layer<Registry> + Send + Sync>, TracingGuard)> {
    config.validate()?;

    global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = build_exporter(config)?;

    let resource = Resource::builder()
        .with_service_name(SERVICE_NAME)
        .with_attributes([
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_string()),
            KeyValue::new("network.name", config.network.clone()),
        ])
        .build();

    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sample_rate)));

    let provider = SdkTracerProvider::builder()
        .with_sampler(sampler)
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer(SERVICE_NAME);
    let layer = OpenTelemetryLayer::new(tracer).boxed();

    Ok((layer, TracingGuard { provider }))
}

fn build_exporter(config: &TelemetryConfig) -> Result<opentelemetry_otlp::SpanExporter> {
    match config.exporter {
        ExporterKind::Otlp => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(&config.endpoint)
                .build()?;
            Ok(exporter)
        }
        #[cfg(feature = "gcp-trace")]
        ExporterKind::Gcp => {
            todo!("GCP exporter implementation in Phase 3")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_tracing_valid_config() {
        let config = TelemetryConfig::default();
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_custom_endpoint() {
        let config = TelemetryConfig {
            endpoint: "http://otel-collector:4318".to_string(),
            sample_rate: 0.5,
            network: "hoodi".to_string(),
            ..Default::default()
        };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_sample_rate_nan() {
        let config = TelemetryConfig { sample_rate: f64::NAN, ..Default::default() };
        let err = init_tracing(&config).err().expect("should fail");
        assert!(err.to_string().contains("sample_rate"));
    }

    #[test]
    fn test_init_tracing_sample_rate_negative() {
        let config = TelemetryConfig { sample_rate: -0.5, ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_sample_rate_too_high() {
        let config = TelemetryConfig { sample_rate: 2.0, ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_invalid_endpoint() {
        let config = TelemetryConfig { endpoint: "ftp://bad:21".to_string(), ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_endpoint_no_scheme() {
        let config =
            TelemetryConfig { endpoint: "localhost:4318".to_string(), ..Default::default() };
        assert!(init_tracing(&config).is_err());
    }

    #[test]
    fn test_init_tracing_https_endpoint() {
        let config = TelemetryConfig {
            endpoint: "https://collector.example.com:4318".to_string(),
            ..Default::default()
        };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_zero_sample_rate() {
        let config = TelemetryConfig { sample_rate: 0.0, ..Default::default() };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_build_exporter_otlp() {
        let config = TelemetryConfig::default();
        let result = build_exporter(&config);
        assert!(result.is_ok());
    }
}
