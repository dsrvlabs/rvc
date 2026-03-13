use std::net::SocketAddr;

use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use tokio::task::JoinHandle;
use tracing::info;

pub struct SignerMetrics {
    pub registry: Registry,
    pub sign_total: IntCounterVec,
    pub sign_duration_seconds: HistogramVec,
    pub sign_errors_total: IntCounterVec,
    pub keys_loaded: GaugeVec,
}

impl Default for SignerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SignerMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let sign_total = IntCounterVec::new(
            Opts::new("rvc_signer_sign_total", "Total number of signing requests"),
            &["backend", "result"],
        )
        .expect("failed to create rvc_signer_sign_total");
        registry
            .register(Box::new(sign_total.clone()))
            .expect("failed to register rvc_signer_sign_total");

        let sign_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "rvc_signer_sign_duration_seconds",
                "Duration of signing operations in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["backend"],
        )
        .expect("failed to create rvc_signer_sign_duration_seconds");
        registry
            .register(Box::new(sign_duration_seconds.clone()))
            .expect("failed to register rvc_signer_sign_duration_seconds");

        let sign_errors_total = IntCounterVec::new(
            Opts::new("rvc_signer_sign_errors_total", "Total number of signing errors"),
            &["backend", "error_type"],
        )
        .expect("failed to create rvc_signer_sign_errors_total");
        registry
            .register(Box::new(sign_errors_total.clone()))
            .expect("failed to register rvc_signer_sign_errors_total");

        let keys_loaded = GaugeVec::new(
            Opts::new("rvc_signer_keys_loaded", "Number of keys currently loaded"),
            &["backend"],
        )
        .expect("failed to create rvc_signer_keys_loaded");
        registry
            .register(Box::new(keys_loaded.clone()))
            .expect("failed to register rvc_signer_keys_loaded");

        Self { registry, sign_total, sign_duration_seconds, sign_errors_total, keys_loaded }
    }

    pub fn encode(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(buffer)
    }
}

pub fn classify_error(err: &crate::backend::SigningBackendError) -> &'static str {
    match err {
        crate::backend::SigningBackendError::KeyNotFound(_) => "key_not_found",
        crate::backend::SigningBackendError::SigningFailed(_) => "internal",
        crate::backend::SigningBackendError::KeystoreLoadFailed(_) => "internal",
    }
}

pub async fn serve_metrics(
    addr: SocketAddr,
    metrics: std::sync::Arc<SignerMetrics>,
) -> Result<(JoinHandle<()>, SocketAddr), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    info!(address = %local_addr, "Metrics server listening");

    let handle = tokio::spawn(async move {
        serve_metrics_loop(listener, metrics).await;
    });

    Ok((handle, local_addr))
}

async fn serve_metrics_loop(
    listener: tokio::net::TcpListener,
    metrics: std::sync::Arc<SignerMetrics>,
) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept metrics connection");
                continue;
            }
        };

        let body = match metrics.encode() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "Failed to encode metrics");
                continue;
            }
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        use tokio::io::AsyncWriteExt;
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new_creates_all_metrics() {
        let m = SignerMetrics::new();
        // Touch each metric so gather() returns them
        m.sign_total.with_label_values(&["basic", "success"]).inc();
        m.sign_duration_seconds.with_label_values(&["basic"]).observe(0.0);
        m.sign_errors_total.with_label_values(&["basic", "internal"]).inc();
        m.keys_loaded.with_label_values(&["basic"]).set(0.0);

        let gathered = m.registry.gather();
        let names: Vec<&str> = gathered.iter().map(|mf| mf.name()).collect();
        assert!(names.contains(&"rvc_signer_sign_total"));
        assert!(names.contains(&"rvc_signer_sign_duration_seconds"));
        assert!(names.contains(&"rvc_signer_sign_errors_total"));
        assert!(names.contains(&"rvc_signer_keys_loaded"));
    }

    #[test]
    fn test_sign_total_counter_increments() {
        let m = SignerMetrics::new();
        m.sign_total.with_label_values(&["basic", "success"]).inc();
        assert_eq!(m.sign_total.with_label_values(&["basic", "success"]).get(), 1);
    }

    #[test]
    fn test_sign_duration_histogram_records() {
        let m = SignerMetrics::new();
        m.sign_duration_seconds.with_label_values(&["basic"]).observe(0.05);
        assert_eq!(m.sign_duration_seconds.with_label_values(&["basic"]).get_sample_count(), 1);
        assert!(
            (m.sign_duration_seconds.with_label_values(&["basic"]).get_sample_sum() - 0.05).abs()
                < 1e-9
        );
    }

    #[test]
    fn test_sign_errors_total_increments() {
        let m = SignerMetrics::new();
        m.sign_errors_total.with_label_values(&["basic", "key_not_found"]).inc();
        assert_eq!(m.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(), 1);
    }

    #[test]
    fn test_keys_loaded_gauge_sets() {
        let m = SignerMetrics::new();
        m.keys_loaded.with_label_values(&["basic"]).set(5.0);
        assert_eq!(m.keys_loaded.with_label_values(&["basic"]).get(), 5.0);
    }

    #[test]
    fn test_encode_returns_prometheus_text() {
        let m = SignerMetrics::new();
        m.sign_total.with_label_values(&["basic", "success"]).inc();
        let output = m.encode().unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("rvc_signer_sign_total"));
        assert!(text.contains("basic"));
        assert!(text.contains("success"));
    }

    #[test]
    fn test_classify_error_key_not_found() {
        let err = crate::backend::SigningBackendError::KeyNotFound([0u8; 48]);
        assert_eq!(classify_error(&err), "key_not_found");
    }

    #[test]
    fn test_classify_error_signing_failed() {
        let err = crate::backend::SigningBackendError::SigningFailed("test".to_string());
        assert_eq!(classify_error(&err), "internal");
    }

    #[test]
    fn test_classify_error_keystore_load_failed() {
        let err = crate::backend::SigningBackendError::KeystoreLoadFailed("test".to_string());
        assert_eq!(classify_error(&err), "internal");
    }

    #[test]
    fn test_different_backends_independent() {
        let m = SignerMetrics::new();
        m.sign_total.with_label_values(&["basic", "success"]).inc();
        m.sign_total.with_label_values(&["dvt", "success"]).inc();
        m.sign_total.with_label_values(&["dvt", "success"]).inc();
        assert_eq!(m.sign_total.with_label_values(&["basic", "success"]).get(), 1);
        assert_eq!(m.sign_total.with_label_values(&["dvt", "success"]).get(), 2);
    }

    #[tokio::test]
    async fn test_serve_metrics_responds_to_http() {
        let m = std::sync::Arc::new(SignerMetrics::new());
        m.sign_total.with_label_values(&["basic", "success"]).inc();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (handle, bound_addr) = serve_metrics(addr, std::sync::Arc::clone(&m)).await.unwrap();

        let mut stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

        // Wait for full response
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200 OK"), "response: {response}");
        assert!(response.contains("rvc_signer_sign_total"), "response: {response}");

        handle.abort();
    }
}
