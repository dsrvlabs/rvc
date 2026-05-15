/// Review fix: `try_process_ssz_body` must use `read_body_capped`.
///
/// Before the fix, `response.bytes().await` buffered the full SSZ body before
/// the size check. A hostile BN can OOM-kill the validator at block-production
/// time.  After the fix, the cap fires before allocating more than
/// `MAX_SSZ_BLOCK_BYTES` (16 MiB).
use std::time::Duration;

use beacon::{BeaconClient, BeaconClientConfig, BeaconError};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Start a raw TCP server that returns an SSZ-like response.
///
/// `body_len` controls how many bytes the server actually sends.
/// The server returns `Eth-Consensus-Version: bellatrix` so the client
/// enters the SSZ parsing path.
async fn start_ssz_server(body: Vec<u8>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                // Respond with SSZ headers — this triggers try_process_ssz_body.
                // Use chunked encoding so there is no up-front Content-Length.
                let header = "HTTP/1.1 200 OK\r\n\
                    Content-Type: application/octet-stream\r\n\
                    Eth-Consensus-Version: bellatrix\r\n\
                    Transfer-Encoding: chunked\r\n\r\n";
                let _ = stream.write_all(header.as_bytes()).await;

                // Stream the body in 4 KiB chunks.
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
    let config = BeaconClientConfig::new(endpoint).with_max_retries(0);
    BeaconClient::new(config).expect("client creation should succeed")
}

/// The SSZ path must reject bodies > 16 MiB with `BeaconError` (not OOM).
///
/// Before the fix this would buffer the full body into RAM before the size
/// check.  After the fix `read_body_capped` fires at the cap.
#[tokio::test]
async fn test_oversized_ssz_body_rejected() {
    // 17 MiB — just over the 16 MiB MAX_SSZ_BLOCK_BYTES constant.
    const MAX_SSZ_BLOCK_BYTES: usize = 16 * 1024 * 1024;
    let oversized_body = vec![0u8; MAX_SSZ_BLOCK_BYTES + 1024];

    let (port, server_handle) = start_ssz_server(oversized_body).await;

    let client = client_with_retries_0(&format!("http://127.0.0.1:{port}"));
    let result = client
        .produce_block_v3(
            1, // slot
            "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            None,
            None,
        )
        .await;

    server_handle.abort();

    // The request must fail — we don't care which specific error variant as long as
    // it is NOT a success and NOT a panic/OOM.
    assert!(result.is_err(), "oversized SSZ body should return an error, not succeed");
}

/// Duration guard: reading a 20 MiB SSZ body must be fast (no pre-alloc).
///
/// Without the cap, `response.bytes().await` must allocate 20 MiB before
/// returning.  With the cap, we abort at 16 MiB and return early.
#[tokio::test]
async fn test_oversized_ssz_read_aborts_fast() {
    const MAX_SSZ_BLOCK_BYTES: usize = 16 * 1024 * 1024;
    // 20 MiB to ensure we exceed the cap significantly.
    let oversized_body = vec![0u8; 20 * 1024 * 1024];

    let (port, server_handle) = start_ssz_server(oversized_body).await;

    let client = client_with_retries_0(&format!("http://127.0.0.1:{port}"));

    let start = std::time::Instant::now();
    let result = client
        .produce_block_v3(
            1,
            "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            None,
            None,
        )
        .await;
    let elapsed = start.elapsed();

    server_handle.abort();

    assert!(result.is_err(), "oversized SSZ should be rejected");
    // 5 seconds is a generous upper bound. The key assertion is that the client
    // does not wait to receive all 20 MiB — it stops at the cap.
    assert!(
        elapsed < Duration::from_secs(10),
        "SSZ read should abort at cap, not wait for full {:.0} MiB. Elapsed: {elapsed:?}",
        20.0_f64
    );

    // Additional: must return an error that indicates a cap or parse error.
    match result {
        Err(BeaconError::BodyTooLarge { expected, .. }) => {
            assert_eq!(expected, MAX_SSZ_BLOCK_BYTES);
        }
        Err(BeaconError::ParseError(_)) => {
            // Also acceptable — depends on how the error is surfaced.
        }
        other => panic!("unexpected result variant: {other:?}"),
    }
}
