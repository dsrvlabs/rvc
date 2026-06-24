use anyhow::Result;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider,
};
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

            let mut batch_config = BatchConfigBuilder::default();
            if let Some(queue_size) = config.max_queue_size {
                batch_config = batch_config.with_max_queue_size(queue_size);
            }
            if let Some(batch_size) = config.max_export_batch_size {
                batch_config = batch_config.with_max_export_batch_size(batch_size);
            }
            let processor = BatchSpanProcessor::builder(exporter)
                .with_batch_config(batch_config.build())
                .build();

            Ok(SdkTracerProvider::builder()
                .with_sampler(sampler)
                .with_resource(resource)
                .with_span_processor(processor)
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

/// Build an [`EnvFilter`](tracing_subscriber::EnvFilter) honoring the rs-vc
/// logging precedence (ADR-003): if `RUST_LOG` is set to one or more valid
/// directives, it wins entirely; otherwise the filter falls back to
/// `default_level`.
///
/// The fallback deliberately covers every case that would otherwise leave the
/// process with no logging, so "verbose off" never means "silent":
/// - `RUST_LOG` unset (or non-UTF-8),
/// - a malformed directive (e.g. an invalid level like `rvc=notalevel`), and
/// - a set-but-empty value (`""`, `","`, whitespace) — which `tracing-subscriber`
///   would otherwise parse into an all-`OFF` filter (a real `RUST_LOG=` /
///   `value: ""` misconfig in a Dockerfile or k8s manifest).
///
/// This never panics: `default_level` is fed through the lossy
/// [`EnvFilter::new`], which *ignores* an invalid directive (printing a warning)
/// rather than panicking. Callers pass a static `"info"`. This is the single
/// shared implementation both `bin/rvc` and `bin/rvc-signer` route their
/// subscriber init through, so the two binaries cannot drift on default level
/// or precedence.
///
/// # Example
/// ```
/// use rvc_telemetry::env_filter_or;
/// // With `RUST_LOG` unset, empty, or malformed, the filter defaults to `info`.
/// let _filter = env_filter_or("info");
/// ```
pub fn env_filter_or(default_level: &str) -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;
    match std::env::var("RUST_LOG") {
        // `RUST_LOG` carries at least one non-empty directive: it wins, falling
        // back only if the directives fail to parse (e.g. an invalid level).
        Ok(v) if v.split(',').any(|d| !d.trim().is_empty()) => {
            EnvFilter::try_new(v).unwrap_or_else(|_| EnvFilter::new(default_level))
        }
        // Unset, non-UTF-8, or set-but-effectively-empty ("", ",", "   ") — the
        // latter would parse to an all-`OFF` filter and silence the process.
        _ => EnvFilter::new(default_level),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializes the `RUST_LOG`-mutating `env_filter_or` tests. `nextest` runs
    // each test in its own process, but guard anyway so the suite stays correct
    // under any runner that threads tests in one process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_rust_log<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("RUST_LOG").ok();
        match value {
            Some(v) => unsafe { std::env::set_var("RUST_LOG", v) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }
        let out = f();
        match prev {
            Some(p) => unsafe { std::env::set_var("RUST_LOG", p) },
            None => unsafe { std::env::remove_var("RUST_LOG") },
        }
        out
    }

    #[test]
    fn env_filter_or_unset_defaults_to_info() {
        let rendered = with_rust_log(None, || format!("{}", env_filter_or("info")));
        assert_eq!(rendered, "info", "expected info default, got: {rendered}");
    }

    #[test]
    fn env_filter_or_set_but_empty_falls_back_to_default() {
        // A present-but-empty RUST_LOG ("", ",", whitespace) would otherwise
        // parse to an all-OFF filter and silence the process; treat it as unset
        // so logging never goes dark on a `RUST_LOG=` style misconfig.
        for v in ["", ",", ",,,", "   "] {
            let rendered = with_rust_log(Some(v), || format!("{}", env_filter_or("info")));
            assert_eq!(
                rendered, "info",
                "RUST_LOG={v:?} should fall back to info, got: {rendered}"
            );
        }
    }

    #[test]
    fn env_filter_or_respects_rust_log() {
        let rendered = with_rust_log(Some("debug"), || format!("{}", env_filter_or("info")));
        assert!(rendered.contains("debug"), "env RUST_LOG=debug should win, got: {rendered}");
    }

    #[test]
    fn env_filter_or_malformed_falls_back_to_default() {
        // A *syntactically invalid* directive — here an unknown level after `=`
        // (a realistic operator typo) — fails to parse, so the helper falls back
        // to the default rather than panicking or going silent. (A bare junk
        // token like "garbage" would instead parse as a valid *target* directive,
        // not an error, so it is not the malformed case this guards.)
        let rendered =
            with_rust_log(Some("rvc=invalidlevel"), || format!("{}", env_filter_or("info")));
        assert_eq!(
            rendered, "info",
            "malformed RUST_LOG should fall back to info, got: {rendered}"
        );
    }

    #[test]
    fn env_filter_or_preserves_per_module_directive() {
        let rendered = with_rust_log(Some("warn,rvc_signer_bin::http_api=trace"), || {
            format!("{}", env_filter_or("info"))
        });
        assert!(rendered.contains("warn"), "global directive missing: {rendered}");
        assert!(
            rendered.contains("rvc_signer_bin::http_api"),
            "per-module target missing: {rendered}"
        );
        assert!(rendered.contains("trace"), "per-module level missing: {rendered}");
    }

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

    #[test]
    fn test_init_tracing_with_custom_batch_config() {
        let config = TelemetryConfig {
            max_queue_size: Some(4096),
            max_export_batch_size: Some(1024),
            ..Default::default()
        };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_with_partial_batch_config() {
        let config = TelemetryConfig { max_queue_size: Some(8192), ..Default::default() };
        let result = init_tracing(&config);
        assert!(result.is_ok());
        let (_layer, guard) = result.unwrap();
        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_init_tracing_batch_size_one() {
        let config = TelemetryConfig {
            max_queue_size: Some(1),
            max_export_batch_size: Some(1),
            ..Default::default()
        };
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
