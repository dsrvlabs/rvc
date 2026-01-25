//! HTTP server for exposing Prometheus metrics.
//!
//! Provides a `/metrics` endpoint that returns metrics in Prometheus text format.

use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use prometheus::Encoder;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use super::REGISTRY;

/// Creates an axum Router with the `/metrics` endpoint.
pub fn create_metrics_router() -> Router {
    Router::new().route("/metrics", get(metrics_handler))
}

/// Starts the metrics HTTP server on the specified port.
///
/// # Arguments
/// * `port` - The port number to listen on
///
/// # Errors
/// Returns an error if the server fails to bind or serve.
pub async fn serve_metrics(port: u16) -> Result<(), std::io::Error> {
    let router = create_metrics_router();
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Metrics server listening on {}", addr);
    axum::serve(listener, router).await
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(()) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
            buffer,
        ),
        Err(e) => {
            tracing::error!("Failed to encode metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!("Failed to encode metrics: {}", e).into_bytes(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_metrics_endpoint_returns_200() {
        let router = create_metrics_router();

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_prometheus_format() {
        let router = create_metrics_router();

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header should be present");

        assert!(
            content_type.to_str().unwrap().starts_with("text/plain"),
            "Content-Type should be text/plain for Prometheus format"
        );
    }

    #[tokio::test]
    async fn test_registered_metrics_appear_in_output() {
        use crate::metrics::register_counter;

        let counter = register_counter("test_server_counter", "A test counter for server tests")
            .expect("Failed to register counter");
        counter.inc();

        let router = create_metrics_router();

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            body_str.contains("test_server_counter"),
            "Response should contain registered metric. Body: {}",
            body_str
        );
    }
}
