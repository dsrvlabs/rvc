/// Review fix: BnManager must propagate `max_body_bytes` to each BeaconClient.
///
/// Before the fix, `BnManager::new()` built each per-BN `BeaconClient` without
/// `.with_max_body_bytes()`, making `--beacon-max-body-bytes` dead config for
/// most validator traffic.
use std::time::Duration;

use rvc_bn_manager::{BnManager, BnManagerConfig};

/// BnManagerConfig must carry a `max_body_bytes` field defaulting to 32 MiB.
#[test]
fn test_bn_manager_config_has_max_body_bytes() {
    let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
    // Default must be the same constant used by BeaconClientConfig.
    // Default must match ResponseCaps::DEFAULT_MAX_BODY_BYTES (32 MiB)
    assert_eq!(
        config.max_body_bytes,
        beacon::ResponseCaps::DEFAULT_MAX_BODY_BYTES,
        "BnManagerConfig.max_body_bytes default must match ResponseCaps::DEFAULT_MAX_BODY_BYTES"
    );
}

/// BnManagerConfig must expose a builder-style setter for max_body_bytes.
#[test]
fn test_bn_manager_config_with_max_body_bytes() {
    let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()])
        .with_max_body_bytes(64 * 1024 * 1024);
    assert_eq!(config.max_body_bytes, 64 * 1024 * 1024);
}

/// When `BnManager` is constructed with a custom `max_body_bytes`, it must
/// honour that cap in practice.  We verify end-to-end by constructing a
/// manager, standing up a mock server that returns a large body, and asserting
/// that the response fails with `BodyTooLarge`.
///
/// Because `BnManager` implements `BeaconNodeClient` via delegation to the
/// per-BN `BeaconClient`, if the manager passes the cap through correctly the
/// client-level cap will fire.
#[tokio::test]
async fn test_bn_manager_applies_cap_to_clients() {
    use beacon::BeaconError;
    use rvc_bn_manager::BeaconNodeClient;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // Start a server that streams 100 KiB — more than our 32 KiB test cap.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                let body = vec![b'x'; 100 * 1024]; // 100 KiB
                let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
                let _ = stream.write_all(header.as_bytes()).await;
                let chunk_header = format!("{:x}\r\n", body.len());
                let _ = stream.write_all(chunk_header.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
        }
    });

    let config = BnManagerConfig::new(vec![format!("http://127.0.0.1:{port}")])
        .with_max_body_bytes(32 * 1024); // 32 KiB cap
    let manager = BnManager::new(config).expect("manager creation should succeed");

    let result = manager.get_genesis().await;
    server.abort();

    assert!(
        matches!(result, Err(BeaconError::BodyTooLarge { .. })),
        "BnManager must apply max_body_bytes cap; got {result:?}"
    );
}

/// BnManagerConfig must be cloneable and the max_body_bytes survives a clone.
#[test]
fn test_bn_manager_config_clone_preserves_cap() {
    let config =
        BnManagerConfig::new(vec!["http://localhost:5052".to_string()]).with_max_body_bytes(1024);
    let cloned = config.clone();
    assert_eq!(cloned.max_body_bytes, 1024);
}
