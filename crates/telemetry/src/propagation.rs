use opentelemetry::global;
use opentelemetry::propagation::Injector;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Adapter that implements [`Injector`] for [`reqwest::header::HeaderMap`].
struct HeaderInjector<'a>(&'a mut reqwest::header::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&value) {
                self.0.insert(name, val);
            }
        }
    }
}

/// Inject the current trace context as W3C `traceparent` / `tracestate`
/// headers into an HTTP header map.
///
/// This is used to propagate trace context across service boundaries,
/// for example when calling a remote signer or beacon node.
///
/// If no OTel layer is active, this is a no-op — no headers are added.
pub fn inject_trace_context(headers: &mut reqwest::header::HeaderMap) {
    let context = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut HeaderInjector(headers));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelemetryConfig;
    use crate::init::init_tracing;

    #[test]
    fn test_inject_without_otel_layer_is_noop() {
        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);
        // Without an active OTel layer, no traceparent header should be
        // injected (the default NoopTextMapPropagator injects nothing, or
        // the propagator injects a root with all-zero trace ID which is
        // considered invalid).
        let has_valid_trace = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.contains("00000000000000000000000000000000"))
            .unwrap_or(false);
        assert!(!has_valid_trace);
    }

    #[test]
    fn test_inject_with_otel_layer() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Registry;

        let config = TelemetryConfig::default();
        let (layer, guard) = init_tracing(&config).expect("init should succeed");

        let subscriber = Registry::default().with(layer);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("test_span");
        let _enter = span.enter();

        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);

        let traceparent = headers.get("traceparent").expect("traceparent should be present");
        let value = traceparent.to_str().expect("should be valid string");
        assert!(value.starts_with("00-"), "traceparent should start with version 00");
        assert!(!value.contains("00000000000000000000000000000000"), "trace ID should not be zero");

        guard.provider.shutdown().ok();
    }

    #[test]
    fn test_header_injector_invalid_name() {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut injector = HeaderInjector(&mut headers);
        // Header names with spaces are invalid
        injector.set("invalid header", "value".to_string());
        assert!(headers.is_empty());
    }

    #[test]
    fn test_header_injector_invalid_value() {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut injector = HeaderInjector(&mut headers);
        // Header values with newlines are invalid
        injector.set("valid-name", "invalid\nvalue".to_string());
        assert!(headers.is_empty());
    }

    #[test]
    fn test_header_injector_valid() {
        let mut headers = reqwest::header::HeaderMap::new();
        let mut injector = HeaderInjector(&mut headers);
        injector.set("traceparent", "00-abc-def-01".to_string());
        assert_eq!(headers.get("traceparent").unwrap(), "00-abc-def-01");
    }
}
