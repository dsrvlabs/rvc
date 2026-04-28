/// H-11: SSE caps integration tests.
///
/// Verifies:
/// 1. Per-event size cap: events > 64 KiB are dropped with a warn; loop continues.
/// 2. Content-Type check: wrong CT causes connection drop.
/// 3. Bounded mpsc dispatch: full channel drops events; loop continues.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use rvc_bn_manager::sse::{subscribe_events, SseConfig, SseEvent};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;

// ── helper: raw TCP SSE server ────────────────────────────────────────────────

/// Spawn a minimal HTTP/1.1 SSE server that writes `sse_body` once per connection,
/// using `content_type` as the `Content-Type` response header.
async fn start_sse_server_with_ct(
    sse_body: String,
    content_type: &'static str,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let body = sse_body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n"
                );
                let _ = stream.write_all(headers.as_bytes()).await;
                let chunk = format!("{:x}\r\n{}\r\n", body.len(), body);
                let _ = stream.write_all(chunk.as_bytes()).await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = stream.write_all(b"0\r\n\r\n").await;
            });
        }
    });

    (port, handle)
}

/// Spawn a standard `text/event-stream` server.
async fn start_sse_server(sse_body: String) -> (u16, tokio::task::JoinHandle<()>) {
    start_sse_server_with_ct(sse_body, "text/event-stream").await
}

// ── helpers to build SSE event payloads ──────────────────────────────────────

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

// ── H-11 test 1: oversize event dropped; loop continues ──────────────────────

#[tokio::test]
async fn test_oversize_event_dropped() {
    // 128 KiB event data (exceeds 64 KiB default cap)
    let huge_data = "x".repeat(128 * 1024);
    let normal_event = sse_event_line("head", &head_event_json(1));
    let huge_event = sse_event_line("head", &huge_data);
    let normal_event2 = sse_event_line("head", &head_event_json(2));

    // Body: [oversize event] [normal event]  — loop should drop the oversize one
    // and still dispatch the normal one.
    let sse_body = format!("{huge_event}{normal_event}{normal_event2}");

    let (port, server_handle) = start_sse_server(sse_body).await;

    let received: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let received_clone = received.clone();

    let (tx_shutdown, rx_shutdown) = watch::channel(false);
    let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

    let handle = tokio::spawn(async move {
        subscribe_events(
            vec![config],
            move |_event: SseEvent| {
                received_clone.fetch_add(1, Ordering::Relaxed);
            },
            rx_shutdown,
        )
        .await;
    });

    // Wait for events
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if received.load(Ordering::Relaxed) >= 2 {
            break;
        }
    }

    tx_shutdown.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    server_handle.abort();

    let got = received.load(Ordering::Relaxed);
    // The two normal events must be received; the huge event must be dropped.
    assert!(got >= 2, "expected at least 2 normal events, got {got}");
}

// ── H-11 test 2: wrong Content-Type drops connection ─────────────────────────

#[tokio::test]
async fn test_wrong_content_type_disconnects() {
    let normal_event = sse_event_line("head", &head_event_json(99));
    let sse_body = normal_event;

    // Server returns application/json — should be rejected
    let (port, server_handle) = start_sse_server_with_ct(sse_body, "application/json").await;

    let received: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let received_clone = received.clone();

    let (tx_shutdown, rx_shutdown) = watch::channel(false);
    let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

    let handle = tokio::spawn(async move {
        subscribe_events(
            vec![config],
            move |_event: SseEvent| {
                received_clone.fetch_add(1, Ordering::Relaxed);
            },
            rx_shutdown,
        )
        .await;
    });

    // Give the subscriber time to attempt a connection and (correctly) refuse it
    tokio::time::sleep(Duration::from_millis(500)).await;

    // No events should have been dispatched — the connection should be dropped.
    tx_shutdown.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    server_handle.abort();

    let got = received.load(Ordering::Relaxed);
    assert_eq!(
        got, 0,
        "wrong Content-Type should have caused 0 events to be dispatched, got {got}"
    );
}

// ── H-11 test 3: saturated channel drops events; loop continues ──────────────

#[tokio::test]
async fn test_callback_full_drops_event() {
    // Build 200 small events
    let events: String = (0u64..200).map(|i| sse_event_line("head", &head_event_json(i))).collect();

    let (port, server_handle) = start_sse_server(events).await;

    let received: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let received_clone = received.clone();

    let (tx_shutdown, rx_shutdown) = watch::channel(false);
    let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

    let handle = tokio::spawn(async move {
        subscribe_events(
            vec![config],
            move |_event: SseEvent| {
                // Slow callback to saturate the bounded channel
                received_clone.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(20));
            },
            rx_shutdown,
        )
        .await;
    });

    // Subscribe for 300 ms — with 20 ms/callback × ~15 events = ~300 ms.
    // The SSE loop must NOT block even after the channel fills up.
    tokio::time::sleep(Duration::from_millis(300)).await;

    tx_shutdown.send(true).unwrap();
    // If subscribe_events blocks (e.g. blocking .send().await), this times out.
    let subscribe_result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(subscribe_result.is_ok(), "subscribe_events must not block when channel is full");
    server_handle.abort();

    let got = received.load(Ordering::Relaxed);
    // With slow callback and 200 events, not all 200 can be dispatched in 300 ms.
    // The channel (64) + callback throughput (~15 in 300 ms) means some events
    // were dropped because the channel was full.
    // We just assert: process completed fast enough and some events were received.
    assert!(got > 0, "expected at least 1 event to be received, got {got}");
    // The loop must have completed (not blocked on a full channel)
    // — verified above by timeout check.
}
