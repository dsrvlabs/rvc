//! Router tests: bearer auth, CORS, and body-size limits.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::*;
use tower::ServiceExt;

// --- Auth middleware tests ---

#[tokio::test]
async fn test_auth_middleware_rejects_unauthenticated_get() {
    let app = TestApp::new();
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_middleware_allows_valid_token() {
    let app = TestApp::new();
    let token = "test_token";

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_auth_middleware_rejects_unauthenticated_post() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "keystores": [],
        "passwords": []
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_middleware_rejects_unauthenticated_delete() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "pubkeys": []
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/keystores")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

// --- Auth tests for remote key endpoints ---

#[tokio::test]
async fn test_auth_rejects_unauthenticated_get_remotekeys() {
    let app = TestApp::new();
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/remotekeys")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_rejects_unauthenticated_post_remotekeys() {
    let app = TestApp::new();
    let request_body = serde_json::json!({"remote_keys": []});

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_rejects_unauthenticated_delete_remotekeys() {
    let app = TestApp::new();
    let request_body = serde_json::json!({"pubkeys": []});

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/remotekeys")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_allows_valid_token_remotekeys() {
    let app = TestApp::new();
    let token = "test_token";

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

// --- SEC-07: Body size limit tests ---

#[tokio::test]
async fn test_body_limit_rejects_oversized_payload() {
    let app = TestApp::new().with_body_limit(1024);
    let big_body = "x".repeat(2048); // 2 KB > 1 KB limit
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", "Bearer test_token")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(big_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_body_limit_allows_normal_payload() {
    let app = TestApp::new();
    let body = serde_json::json!({
        "keystores": [],
        "passwords": []
    })
    .to_string();

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/keystores")
                .header("Authorization", "Bearer test_token")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

// --- SEC-06: CORS tests ---

#[tokio::test]
async fn test_cors_no_origins_no_header() {
    let app = TestApp::new();
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .header("Authorization", "Bearer test_token")
                .header("Origin", "http://evil.com")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.headers().get("access-control-allow-origin").is_none(),
        "No CORS headers should be set when no origins configured"
    );
}

#[tokio::test]
async fn test_cors_with_allowed_origin() {
    let app = TestApp::new().with_cors_origins(vec!["http://localhost:3000".to_string()]);
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .header("Authorization", "Bearer test_token")
                .header("Origin", "http://localhost:3000")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("access-control-allow-origin").map(|v| v.to_str().unwrap()),
        Some("http://localhost:3000"),
    );
}

#[tokio::test]
async fn test_cors_preflight_options() {
    let app = TestApp::new().with_cors_origins(vec!["http://localhost:3000".to_string()]);
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("OPTIONS")
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "POST")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert!(response.headers().get("access-control-allow-origin").is_some());
}

#[tokio::test]
async fn test_fee_recipient_auth_required() {
    let pk = test_pubkey(1);
    let (router, _token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/feerecipient");

    let resp = router.oneshot(TestApp::new().unauthenticated("GET", &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_graffiti_auth_required() {
    let pk = test_pubkey(1);
    let (router, _token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(None)
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/graffiti");

    let resp = router.oneshot(TestApp::new().unauthenticated("GET", &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_voluntary_exit_auth_required_integration() {
    let pk = test_pubkey(1);
    let exit_mgr = Arc::new(MockVoluntaryExitManager::with_validator(pk));
    let (router, _token) = {
        let app = TestApp::with_config_manager(MockValidatorConfigManager::with_validator(pk))
            .with_exit_manager(Some(exit_mgr))
            .with_token("test_integration_token_1234567890abcdef");
        (app.router(), app.token.clone())
    };
    let pubkey_hex = format!("0x{}", test_pubkey_hex(1));
    let uri = format!("/eth/v1/validator/{pubkey_hex}/voluntary_exit");

    let resp = router.oneshot(TestApp::new().unauthenticated("POST", &uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
