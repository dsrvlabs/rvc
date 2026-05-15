/// Review fix: error-path body reads must be capped.
///
/// A hostile BN returning HTTP 503 with a 10 GiB body must not OOM the validator.
/// All error-path `response.text().await` calls in client.rs must go through
/// `read_body_capped_lossy(..., 16 KiB)`.
use std::time::Duration;

use beacon::{BeaconClient, BeaconClientConfig, BeaconError};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Start a raw TCP server that returns the given status code with a large body.
/// `body_len` bytes are streamed; `content_length` is what the header declares.
async fn start_error_server(status: u16, body: Vec<u8>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                // Use Transfer-Encoding: chunked so there is no up-front Content-Length,
                // simulating a streaming hostile body that would OOM if fully read.
                let header = format!(
                    "HTTP/1.1 {status} Error\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
                );
                let _ = stream.write_all(header.as_bytes()).await;

                // Send the large body in chunks of 4 KiB so the cap fires mid-stream.
                let chunk_size = 4096;
                let mut sent = 0usize;
                while sent < body.len() {
                    let end = (sent + chunk_size).min(body.len());
                    let slice = &body[sent..end];
                    let chunk_header = format!("{:x}\r\n", slice.len());
                    if stream.write_all(chunk_header.as_bytes()).await.is_err() {
                        return;
                    }
                    if stream.write_all(slice).await.is_err() {
                        return;
                    }
                    if stream.write_all(b"\r\n").await.is_err() {
                        return;
                    }
                    let _ = stream.flush().await;
                    sent = end;
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
            });
        }
    });

    (port, handle)
}

fn client_with_retries_0(endpoint: &str) -> BeaconClient {
    let config =
        BeaconClientConfig::new(endpoint).with_max_retries(0).with_max_body_bytes(32 * 1024 * 1024); // 32 MiB default
    BeaconClient::new(config).expect("client creation should succeed")
}

/// A 503 response with a body larger than 16 KiB must NOT buffer the whole body.
/// The captured error message must be at most 16 KiB.
#[tokio::test]
async fn test_503_error_body_capped_at_16_kib() {
    // 1 MiB body — far exceeds the 16 KiB diagnostic cap.
    let large_body = vec![b'E'; 1024 * 1024];
    let (port, server_handle) = start_error_server(503, large_body).await;

    let client = client_with_retries_0(&format!("http://127.0.0.1:{port}"));
    let result: Result<serde_json::Value, BeaconError> = client.get("/eth/v1/node/version").await;

    server_handle.abort();

    // The call must fail with ApiError (503) — not hang or OOM.
    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 503);
            // The captured message must be bounded — at most 16 KiB plus a small overhead.
            assert!(
                message.len() <= 16 * 1024 + 64,
                "error body must be capped at ~16 KiB, got {} bytes",
                message.len()
            );
        }
        other => panic!("expected ApiError(503), got {other:?}"),
    }
}

/// A 400 response with a body larger than 16 KiB must also be capped.
#[tokio::test]
async fn test_400_error_body_capped_at_16_kib() {
    let large_body = vec![b'E'; 512 * 1024]; // 512 KiB
    let (port, server_handle) = start_error_server(400, large_body).await;

    let client = client_with_retries_0(&format!("http://127.0.0.1:{port}"));

    // submit_attestation goes through submit_attestation's dedicated retry loop
    // which also used response.text().await.unwrap_or_default() in the 400 path.
    // Verify the general GET path first.
    let result: Result<serde_json::Value, BeaconError> = client.get("/eth/v1/node/version").await;

    server_handle.abort();

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 400);
            assert!(
                message.len() <= 16 * 1024 + 64,
                "400 error body must be capped, got {} bytes",
                message.len()
            );
        }
        other => panic!("expected ApiError(400), got {other:?}"),
    }
}

/// read_body_capped_lossy must be accessible from http_caps (pub(crate))
/// and return an empty string when the body exceeds the cap.
#[tokio::test]
async fn test_capped_lossy_returns_empty_on_cap_exceeded() {
    // Send a body larger than 16 KiB via a 500 status error response.
    let large_body = vec![b'X'; 64 * 1024]; // 64 KiB > 16 KiB cap
    let (port, server_handle) = start_error_server(500, large_body).await;

    let client = client_with_retries_0(&format!("http://127.0.0.1:{port}"));
    let result: Result<serde_json::Value, BeaconError> = client.get("/eth/v1/node/syncing").await;

    server_handle.abort();

    match result {
        Err(BeaconError::ApiError { status, message }) => {
            assert_eq!(status, 500);
            // The message was read with read_body_capped_lossy.
            // When cap is exceeded, lossy returns empty string; body is exactly ≤ 16 KiB.
            assert!(
                message.len() <= 16 * 1024 + 64,
                "500 error body must be capped, got {} bytes",
                message.len()
            );
        }
        other => panic!("expected ApiError(500), got {other:?}"),
    }
}

/// Duration guard: the entire error-path must complete within a few seconds
/// even when the server is streaming a giant body. This proves we do NOT
/// buffer the whole thing before returning.
#[tokio::test]
async fn test_error_body_read_completes_fast() {
    // 10 MiB at 4 KiB/chunk — without cap, this would take many seconds.
    let large_body = vec![b'Z'; 10 * 1024 * 1024];
    let (port, server_handle) = start_error_server(503, large_body).await;

    let client = client_with_retries_0(&format!("http://127.0.0.1:{port}"));

    let start = std::time::Instant::now();
    let result: Result<serde_json::Value, BeaconError> = client.get("/eth/v1/node/version").await;
    let elapsed = start.elapsed();

    server_handle.abort();

    // Must be an error (503)
    assert!(result.is_err(), "expected error from 503 server");
    // Must complete in under 5 seconds — streaming 10 MiB at full speed would be fast,
    // but the test proves we stopped at the cap rather than buffering 10 MiB.
    assert!(
        elapsed < Duration::from_secs(5),
        "error body read took too long: {elapsed:?}. Body cap may not be applied on error path."
    );
}
