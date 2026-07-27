//! Router tests: `/eth/v1/remotekeys` and remote-key URL validation.

mod common;

use std::sync::Arc;

use common::*;
use http_body_util::BodyExt;
use rvc_keymanager_api::traits::RemoteKeyManager;
use rvc_keymanager_api::types::{
    DeleteRemoteKeyResult, DeleteRemoteKeyStatus, DeleteRemoteKeysResponse, ImportRemoteKeyResult,
    ImportRemoteKeyStatus, ImportRemoteKeysResponse, ListKeystoresResponse, ListRemoteKeysResponse,
};
use tower::ServiceExt;

// --- GET /eth/v1/remotekeys tests ---

#[tokio::test]
async fn test_list_remote_keys_empty() {
    let app = TestApp::new();
    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ListRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert!(resp.data.is_empty());
}

#[tokio::test]
async fn test_list_remote_keys_with_entries() {
    let app = TestApp::with_remote_keys(vec![
        (test_pubkey(1), "https://8.8.8.8:9001".into()),
        (test_pubkey(2), "https://8.8.8.8:9002".into()),
    ]);

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ListRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 2);
    assert_eq!(resp.data[0].pubkey, format!("0x{}", test_pubkey_hex(1)));
    assert_eq!(resp.data[0].url, "https://8.8.8.8:9001");
    assert!(!resp.data[0].readonly);
    assert_eq!(resp.data[1].pubkey, format!("0x{}", test_pubkey_hex(2)));
    assert_eq!(resp.data[1].url, "https://8.8.8.8:9002");
}

// --- POST /eth/v1/remotekeys tests ---

#[tokio::test]
async fn test_import_single_remote_key() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "remote_keys": [{
            "pubkey": format!("0x{}", test_pubkey_hex(1)),
            "url": "https://8.8.8.8:9000"
        }]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Imported);

    assert!(app.remote_key_manager.has_remote_key(&test_pubkey(1)));
}

#[tokio::test]
async fn test_import_multiple_remote_keys() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "remote_keys": [
            {"pubkey": format!("0x{}", test_pubkey_hex(1)), "url": "https://8.8.8.8:9001"},
            {"pubkey": format!("0x{}", test_pubkey_hex(2)), "url": "https://8.8.8.8:9002"}
        ]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 2);
    assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Imported);
    assert_eq!(resp.data[1].status, ImportRemoteKeyStatus::Imported);
}

#[tokio::test]
async fn test_import_duplicate_remote_key() {
    let app = TestApp::with_remote_keys(vec![(test_pubkey(1), "https://8.8.8.8:9000".into())]);
    let request_body = serde_json::json!({
        "remote_keys": [{
            "pubkey": format!("0x{}", test_pubkey_hex(1)),
            "url": "https://8.8.8.8:9000"
        }]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Duplicate);
}

#[tokio::test]
async fn test_import_remote_key_invalid_pubkey() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "remote_keys": [{
            "pubkey": "not_valid_hex!",
            "url": "https://8.8.8.8:9000"
        }]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
}

// --- DELETE /eth/v1/remotekeys tests ---

#[tokio::test]
async fn test_delete_existing_remote_key() {
    let app = TestApp::with_remote_keys(vec![(test_pubkey(1), "https://8.8.8.8:9000".into())]);
    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(1))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteRemoteKeyStatus::Deleted);
    assert!(!app.remote_key_manager.has_remote_key(&test_pubkey(1)));
}

#[tokio::test]
async fn test_delete_nonexistent_remote_key() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "pubkeys": [format!("0x{}", test_pubkey_hex(99))]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteRemoteKeyStatus::NotFound);
}

#[tokio::test]
async fn test_delete_remote_key_invalid_pubkey() {
    let app = TestApp::new();
    let request_body = serde_json::json!({
        "pubkeys": ["not_valid_hex!"]
    });

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: DeleteRemoteKeysResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp.data.len(), 1);
    assert_eq!(resp.data[0].status, DeleteRemoteKeyStatus::Error);
}

// --- Remote key readonly in list_keystores ---

#[tokio::test]
async fn test_list_keystores_remote_keys_readonly() {
    let mut app = TestApp::with_keys(vec![test_pubkey(1)]);
    app.remote_key_manager = Arc::new(MockRemoteKeyManager::with_keys(vec![(
        test_pubkey(2),
        "https://8.8.8.8:9000".into(),
    )]));

    let response = app
        .router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/eth/v1/keystores")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resp: ListKeystoresResponse = serde_json::from_slice(&body).unwrap();
    // COR-05: list_keystores now returns only local keys
    assert_eq!(resp.data.len(), 1);
    // Only local key present
    assert_eq!(resp.data[0].validating_pubkey, format!("0x{}", test_pubkey_hex(1)));
    assert!(!resp.data[0].readonly);
}

// --- Import remote key result message omission ---

#[test]
fn test_import_remote_key_success_omits_empty_message() {
    let result =
        ImportRemoteKeyResult { status: ImportRemoteKeyStatus::Imported, message: String::new() };
    let json = serde_json::to_value(&result).unwrap();
    assert!(
        json.get("message").is_none(),
        "success result should not have 'message' key, got: {json}"
    );
}

#[test]
fn test_delete_remote_key_success_omits_empty_message() {
    let result =
        DeleteRemoteKeyResult { status: DeleteRemoteKeyStatus::Deleted, message: String::new() };
    let json = serde_json::to_value(&result).unwrap();
    assert!(
        json.get("message").is_none(),
        "success result should not have 'message' key, got: {json}"
    );
}

// --- SEC-05: URL validation in import_remote_keys ---

#[tokio::test]
async fn test_import_remote_key_rejects_http_without_flag() {
    let app = TestApp::new().with_allow_insecure_remote_signer(false);
    let router = app.router();

    let body = serde_json::json!({
        "remote_keys": [{
            "pubkey": format!("0x{}", test_pubkey_hex(1)),
            "url": "http://signer.example.com:9000"
        }]
    })
    .to_string();

    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes =
        http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
    let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
    assert!(resp.data[0].message.contains("HTTP not allowed"));
}

#[tokio::test]
async fn test_import_remote_key_rejects_file_scheme() {
    let app = TestApp::new().with_allow_insecure_remote_signer(false);
    let router = app.router();

    let body = serde_json::json!({
        "remote_keys": [{
            "pubkey": format!("0x{}", test_pubkey_hex(1)),
            "url": "file:///etc/passwd"
        }]
    })
    .to_string();

    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes =
        http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
    let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
    assert!(resp.data[0].message.contains("Unsupported URL scheme"));
}

#[tokio::test]
async fn test_import_remote_key_rejects_private_ip() {
    let app = TestApp::new().with_allow_insecure_remote_signer(false);
    let router = app.router();

    let body = serde_json::json!({
        "remote_keys": [{
            "pubkey": format!("0x{}", test_pubkey_hex(1)),
            "url": "https://127.0.0.1:9000"
        }]
    })
    .to_string();

    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/eth/v1/remotekeys")
                .header("Authorization", format!("Bearer {}", common::DEFAULT_TEST_TOKEN))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes =
        http_body_util::BodyExt::collect(response.into_body()).await.unwrap().to_bytes();
    let resp: ImportRemoteKeysResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp.data[0].status, ImportRemoteKeyStatus::Error);
    assert!(resp.data[0].message.contains("Private/reserved IP"));
}
