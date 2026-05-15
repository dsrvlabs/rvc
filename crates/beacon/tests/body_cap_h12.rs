/// H-12: JSON body cap integration tests.
///
/// Uses raw TCP servers to simulate beacon-node responses because we need
/// to send HTTP responses with mismatched or deliberately large Content-Length
/// headers that real HTTP frameworks would reject.
use std::time::Duration;

use beacon::{BeaconClient, BeaconClientConfig, BeaconError};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

// ── helper ────────────────────────────────────────────────────────────────────

/// Start a raw TCP server that serves exactly one response per connection.
///
/// `header_content_length` overrides the Content-Length header value (can
/// be larger than `body.len()` to simulate a lying server).
async fn start_http_server(
    body: Vec<u8>,
    header_content_length: usize,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let body = body.clone();
            let cl = header_content_length;
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {cl}\r\n\r\n"
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.flush().await;
                // Hold the connection so the client can read
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
        }
    });

    (port, handle)
}

/// Start a raw TCP server that serves a chunked (no Content-Length) response.
async fn start_chunked_http_server(body: Vec<u8>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                let header =
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
                let _ = stream.write_all(header.as_bytes()).await;

                // Send body as a single chunk
                let chunk_header = format!("{:x}\r\n", body.len());
                let _ = stream.write_all(chunk_header.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.write_all(b"\r\n").await;
                let _ = stream.flush().await;

                tokio::time::sleep(Duration::from_secs(2)).await;
                // Terminating chunk
                let _ = stream.write_all(b"0\r\n\r\n").await;
            });
        }
    });

    (port, handle)
}

fn client_with_cap(endpoint: &str, cap: usize) -> BeaconClient {
    let config = BeaconClientConfig::new(endpoint).with_max_retries(0).with_max_body_bytes(cap);
    BeaconClient::new(config).expect("client creation should succeed")
}

const DEFAULT_CAP: usize = 32 * 1024 * 1024; // 32 MiB

// ── H-12 test 1: Content-Length exceeds cap → reject before allocating body ──

#[tokio::test]
async fn test_oversized_response_rejected_before_alloc() {
    // Server advertises 100 MB via Content-Length, but sends only 1 byte.
    // The client should reject based on the header alone.
    let (port, server_handle) = start_http_server(b"x".to_vec(), 100 * 1024 * 1024).await;

    let client = client_with_cap(&format!("http://127.0.0.1:{port}"), DEFAULT_CAP);
    let result: Result<serde_json::Value, BeaconError> = client.get("/eth/v1/node/version").await;

    server_handle.abort();

    match result {
        Err(BeaconError::BodyTooLarge { expected, got_so_far }) => {
            assert_eq!(expected, DEFAULT_CAP);
            assert!(got_so_far > DEFAULT_CAP, "Content-Length was 100 MiB > cap");
        }
        other => panic!("expected BodyTooLarge, got {other:?}"),
    }
}

// ── H-12 test 2: Streaming response exceeds cap → error at cap+1 bytes ──────

#[tokio::test]
async fn test_streaming_response_rejected_at_cap() {
    let cap = 64 * 1024; // 64 KiB test cap
    let oversize_body = vec![b'x'; cap + 1];

    // Use chunked encoding (no Content-Length) so the client must stream
    let (port, server_handle) = start_chunked_http_server(oversize_body).await;

    let client = client_with_cap(&format!("http://127.0.0.1:{port}"), cap);
    let result: Result<serde_json::Value, BeaconError> = client.get("/eth/v1/node/version").await;

    server_handle.abort();

    match result {
        Err(BeaconError::BodyTooLarge { expected, .. }) => {
            assert_eq!(expected, cap);
        }
        other => panic!("expected BodyTooLarge, got {other:?}"),
    }
}

// ── H-12 test 3: 32 MiB response succeeds; 33 MiB rejected ──────────────────

#[tokio::test]
async fn test_default_cap_32_mib() {
    // ── part a: exactly 32 MiB body succeeds ──────────────────────────────
    {
        // Build a minimal valid JSON object padded to exactly 32 MiB with whitespace.
        let padding = DEFAULT_CAP - 2; // "{" + padding + "}"
        let mut body = Vec::with_capacity(DEFAULT_CAP);
        body.push(b'{');
        body.extend(vec![b' '; padding]);
        body.push(b'}');
        assert_eq!(body.len(), DEFAULT_CAP);

        let (port, server_handle) = start_chunked_http_server(body).await;
        let client = client_with_cap(&format!("http://127.0.0.1:{port}"), DEFAULT_CAP);
        let result: Result<serde_json::Value, BeaconError> =
            client.get("/eth/v1/node/version").await;
        server_handle.abort();

        assert!(
            !matches!(result, Err(BeaconError::BodyTooLarge { .. })),
            "32 MiB body should not be rejected by default cap: {result:?}"
        );
    }

    // ── part b: 33 MiB body is rejected ──────────────────────────────────
    {
        let over = DEFAULT_CAP + 1024 * 1024; // 33 MiB
        let body = vec![b'x'; over];

        let (port, server_handle) = start_chunked_http_server(body).await;
        let client = client_with_cap(&format!("http://127.0.0.1:{port}"), DEFAULT_CAP);
        let result: Result<serde_json::Value, BeaconError> =
            client.get("/eth/v1/node/version").await;
        server_handle.abort();

        assert!(
            matches!(result, Err(BeaconError::BodyTooLarge { .. })),
            "33 MiB body should be rejected: {result:?}"
        );
    }
}

// ── H-12 test 4: configurable cap — 64 MiB passes ───────────────────────────

#[tokio::test]
async fn test_configurable_cap() {
    let cap_64_mib = 64 * 1024 * 1024;

    // Body just under the 64 MiB cap — valid JSON whitespace-padded object.
    let padding = cap_64_mib - 2;
    let mut body = Vec::with_capacity(cap_64_mib);
    body.push(b'{');
    body.extend(vec![b' '; padding]);
    body.push(b'}');

    let (port, server_handle) = start_chunked_http_server(body).await;
    let client = client_with_cap(&format!("http://127.0.0.1:{port}"), cap_64_mib);
    let result: Result<serde_json::Value, BeaconError> = client.get("/eth/v1/node/version").await;
    server_handle.abort();

    assert!(
        !matches!(result, Err(BeaconError::BodyTooLarge { .. })),
        "64 MiB body with 64 MiB cap should not be rejected: {result:?}"
    );
}
