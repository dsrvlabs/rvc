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

    let version =
        config.service_version.clone().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    let resource = Resource::builder()
        .with_service_name(SERVICE_NAME)
        .with_attributes([
            KeyValue::new("service.version", version),
            KeyValue::new("network.name", config.network.clone()),
        ])
        .build();

    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sample_rate)));

    let provider = build_provider(config, resource, sampler)?;

    let tracer = provider.tracer(SERVICE_NAME);
    let layer = OpenTelemetryLayer::new(tracer).boxed();

    Ok((layer, TracingGuard { provider }))
}

fn build_provider(
    config: &TelemetryConfig,
    resource: Resource,
    sampler: Sampler,
) -> Result<SdkTracerProvider> {
    match config.exporter {
        ExporterKind::Otlp => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(&config.endpoint)
                .build()?;
            Ok(SdkTracerProvider::builder()
                .with_sampler(sampler)
                .with_resource(resource)
                .with_batch_exporter(exporter)
                .build())
        }
        #[cfg(feature = "gcp-trace")]
        ExporterKind::Gcp => build_gcp_provider(resource, sampler),
    }
}

#[cfg(feature = "gcp-trace")]
fn build_gcp_provider(resource: Resource, sampler: Sampler) -> Result<SdkTracerProvider> {
    let handle = tokio::runtime::Handle::current();

    tokio::task::block_in_place(|| {
        let gcp_builder = handle
            .block_on(
                opentelemetry_gcloud_trace::GcpCloudTraceExporterBuilder::for_default_project_id(),
            )
            .map_err(|e| anyhow::anyhow!("GCP project ID detection failed: {e}"))?;

        let provider_builder =
            SdkTracerProvider::builder().with_sampler(sampler).with_resource(resource.clone());

        let provider = handle
            .block_on(
                gcp_builder.with_resource(resource).create_provider_from_builder(provider_builder),
            )
            .map_err(|e| anyhow::anyhow!("GCP Cloud Trace exporter initialization failed: {e}"))?;

        Ok(provider)
    })
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
    fn test_build_provider_otlp() {
        let config = TelemetryConfig::default();
        let resource = Resource::builder().with_service_name("test").build();
        let sampler =
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sample_rate)));
        let result = build_provider(&config, resource, sampler);
        assert!(result.is_ok());
        result.unwrap().shutdown().ok();
    }

    #[test]
    fn test_init_tracing_with_service_version() {
        let config =
            TelemetryConfig { service_version: Some("0.99.0".to_string()), ..Default::default() };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[cfg(feature = "gcp-trace")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_init_tracing_gcp_does_not_panic() {
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            ..Default::default()
        };
        match init_tracing(&config) {
            Ok((_layer, guard)) => {
                guard.provider.shutdown().ok();
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("GCP") || msg.contains("project") || msg.contains("gcloud"),
                    "GCP error should reference GCP/project: {msg}"
                );
            }
        }
    }

    #[cfg(feature = "gcp-trace")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_init_tracing_gcp_respects_sample_rate_validation() {
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            sample_rate: f64::NAN,
            ..Default::default()
        };
        let err = init_tracing(&config).err().expect("NaN sample_rate should fail");
        assert!(err.to_string().contains("sample_rate"));
    }

    #[cfg(feature = "gcp-trace")]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_init_tracing_gcp_custom_network() {
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            sample_rate: 0.5,
            network: "hoodi".to_string(),
            ..Default::default()
        };
        match init_tracing(&config) {
            Ok((_layer, guard)) => {
                guard.provider.shutdown().ok();
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(!msg.contains("sample_rate"), "Should not fail on sample_rate: {msg}");
                assert!(!msg.contains("network"), "Should not fail on network: {msg}");
            }
        }
    }
}
