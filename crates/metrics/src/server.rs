//! HTTP server for exposing Prometheus metrics and health checks.
//!
//! Provides:
//! - `/metrics` endpoint that returns metrics in Prometheus text format
//! - `/health` endpoint that returns service health status

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use prometheus::Encoder;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::REGISTRY;

/// Health status of the validator client.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub beacon_connected: bool,
    pub validators_loaded: usize,
    pub slashing_db_initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HealthStatus {
    pub fn update_healthy(&mut self) {
        self.healthy =
            self.beacon_connected && self.validators_loaded > 0 && self.slashing_db_initialized;
    }
}

/// Shared state for health status.
pub type SharedHealthStatus = Arc<RwLock<HealthStatus>>;

/// Creates a new shared health status.
pub fn new_health_status() -> SharedHealthStatus {
    Arc::new(RwLock::new(HealthStatus::default()))
}

/// Creates an axum Router with the `/metrics` endpoint (without health).
pub fn create_metrics_router() -> Router {
    Router::new().route("/metrics", get(metrics_handler))
}

/// Creates an axum Router with both `/metrics` and `/health` endpoints.
pub fn create_metrics_router_with_health(health_status: SharedHealthStatus) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler))
        .with_state(health_status)
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

/// Starts the metrics HTTP server with health endpoint on the specified port.
///
/// # Arguments
/// * `port` - The port number to listen on
/// * `health_status` - Shared health status for the health endpoint
///
/// # Errors
/// Returns an error if the server fails to bind or serve.
pub async fn serve_metrics_with_health(
    port: u16,
    health_status: SharedHealthStatus,
) -> Result<(), std::io::Error> {
    let router = create_metrics_router_with_health(health_status);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Metrics server with health endpoint listening on {}", addr);
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

async fn health_handler(State(health_status): State<SharedHealthStatus>) -> impl IntoResponse {
    let status = health_status.read().await;
    let http_status = if status.healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };

    (http_status, Json(status.clone()))
}

async fn livez_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz_handler(State(health_status): State<SharedHealthStatus>) -> impl IntoResponse {
    let status = health_status.read().await;
    if status.healthy {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
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
        use crate::register_counter;

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

    #[test]
    fn test_health_status_default() {
        let status = HealthStatus::default();
        assert!(!status.healthy);
        assert!(!status.beacon_connected);
        assert_eq!(status.validators_loaded, 0);
        assert!(!status.slashing_db_initialized);
        assert!(status.current_slot.is_none());
        assert!(status.error.is_none());
    }

    #[test]
    fn test_health_status_update_healthy() {
        let mut status = HealthStatus {
            beacon_connected: true,
            validators_loaded: 5,
            slashing_db_initialized: true,
            ..Default::default()
        };
        status.update_healthy();

        assert!(status.healthy);
    }

    #[test]
    fn test_health_status_update_unhealthy_no_beacon() {
        let mut status = HealthStatus {
            beacon_connected: false,
            validators_loaded: 5,
            slashing_db_initialized: true,
            ..Default::default()
        };
        status.update_healthy();

        assert!(!status.healthy);
    }

    #[test]
    fn test_health_status_update_unhealthy_no_validators() {
        let mut status = HealthStatus {
            beacon_connected: true,
            validators_loaded: 0,
            slashing_db_initialized: true,
            ..Default::default()
        };
        status.update_healthy();

        assert!(!status.healthy);
    }

    #[tokio::test]
    async fn test_health_endpoint_unhealthy() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_health_endpoint_healthy() {
        let health_status = new_health_status();

        {
            let mut status = health_status.write().await;
            status.beacon_connected = true;
            status.validators_loaded = 5;
            status.slashing_db_initialized = true;
            status.update_healthy();
        }

        let router = create_metrics_router_with_health(health_status);
        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_json() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("\"healthy\""));
        assert!(body_str.contains("\"beacon_connected\""));
        assert!(body_str.contains("\"validators_loaded\""));
    }

    #[tokio::test]
    async fn test_livez_endpoint() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/livez").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_endpoint_not_ready() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/readyz").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_readyz_endpoint_ready() {
        let health_status = new_health_status();

        {
            let mut status = health_status.write().await;
            status.beacon_connected = true;
            status.validators_loaded = 5;
            status.slashing_db_initialized = true;
            status.update_healthy();
        }

        let router = create_metrics_router_with_health(health_status);
        let request = Request::builder().uri("/readyz").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_with_health_router_has_metrics() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
