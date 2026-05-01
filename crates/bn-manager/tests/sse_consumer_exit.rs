/// Review fix: on `TrySendError::Closed`, the SSE loop must emit a warn log,
/// increment `consecutive_failures`, close the event source, and `break` to
/// force reconnect.
///
/// Before the fix the handler was `// Consumer task exited; nothing to do.`
/// The SSE loop would continue indefinitely reading events from the open stream,
/// silently dropping all of them, never reconnecting.
///
/// After the fix, when the consumer task dies (channel closed), the loop must
/// `break` — causing the reconnect logic to re-create `tx`/`rx`.  We verify
/// this by holding the SSE connection open indefinitely and checking that a
/// *second* connection arrives at the server within a bounded time window.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use rvc_bn_manager::sse::{subscribe_events, SseConfig, SseEvent};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;

// ── helpers ───────────────────────────────────────────────────────────────────

fn head_event_json(slot: u64) -> String {
    format!(
        "{{\"slot\":\"{slot}\",\"block\":\"0xa\",\"state\":\"0xb\",\
         \"epoch_transition\":false,\"previous_duty_dependent_root\":\"0xc\",\
         \"current_duty_dependent_root\":\"0xd\",\"execution_optimistic\":false}}"
    )
}

fn sse_event_line(event_type: &str, data: &str) -> String {
    format!("event: {event_type}\ndata: {data}\n\n")
}

/// Spawn a SSE server that:
/// - Sends one event immediately upon connection, then keeps streaming more
///   events every 100 ms — keeping the SSE stream open indefinitely.
/// - Tracks how many times a new connection is accepted.
///
/// This simulates a healthy BN that keeps sending events after the consumer dies.
async fn start_persistent_sse_server(
    connection_count: Arc<AtomicUsize>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let cc = connection_count.clone();
            tokio::spawn(async move {
                cc.fetch_add(1, Ordering::Relaxed);

                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n";
                let _ = stream.write_all(header.as_bytes()).await;

                // Stream events every 100 ms without ever closing the connection.
                // This ensures the SSE inner loop would keep running indefinitely
                // (without the fix) instead of ending due to a stream closure.
                let mut slot = 0u64;
                loop {
                    let event = sse_event_line("head", &head_event_json(slot));
                    let chunk = format!("{:x}\r\n{}\r\n", event.len(), event);
                    if stream.write_all(chunk.as_bytes()).await.is_err() {
                        break;
                    }
                    if stream.flush().await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    slot += 1;
                }
            });
        }
    });

    (port, handle)
}

/// When the consumer task dies (panics), `tx.try_send` returns `TrySendError::Closed`.
///
/// The fix must: emit warn, break inner loop → outer reconnect logic fires.
/// This creates a new connection to the server (connection_count >= 2).
///
/// Without the fix the inner loop continues reading events forever from the
/// persistent stream, connection_count stays at 1 for the test duration.
#[tokio::test]
async fn test_closed_channel_triggers_reconnect() {
    let connection_count = Arc::new(AtomicUsize::new(0));
    let (port, server_handle) = start_persistent_sse_server(connection_count.clone()).await;

    let (tx_shutdown, rx_shutdown) = watch::channel(false);

    // Callback that panics on first invocation to kill the consumer task.
    let panicked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let panicked_clone = panicked.clone();

    let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

    let handle = tokio::spawn(async move {
        subscribe_events(
            vec![config],
            move |_event: SseEvent| {
                // Panic exactly once to kill the consumer task.
                if !panicked_clone.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    panic!("intentional panic to kill consumer task");
                }
                // If the consumer was re-created (fix applied), subsequent events land here.
            },
            rx_shutdown,
        )
        .await;
    });

    // The persistent server never closes the connection, so without the fix the
    // inner loop keeps running after the panic (silently dropping events).
    // With the fix, it breaks → 500 ms reconnect sleep → new connection.
    // Allow 5 s total (500 ms reconnect + overhead).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if connection_count.load(Ordering::Relaxed) >= 2 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tx_shutdown.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
    server_handle.abort();

    let connections = connection_count.load(Ordering::Relaxed);
    assert!(
        connections >= 2,
        "SSE loop must reconnect after TrySendError::Closed (consumer exited). \
         Expected >= 2 connections to server, got {connections}. \
         Without the fix, the loop keeps reading the persistent stream forever \
         and never reconnects."
    );
}
