use serde::Deserialize;

/// Data from a `head` SSE event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HeadEvent {
    pub slot: String,
    pub block: String,
    pub state: String,
    pub epoch_transition: bool,
    pub previous_duty_dependent_root: String,
    pub current_duty_dependent_root: String,
    pub execution_optimistic: bool,
}

/// Data from a `block` SSE event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockEvent {
    pub slot: String,
    pub block: String,
    pub execution_optimistic: bool,
}

/// Data from a `chain_reorg` SSE event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChainReorgEvent {
    pub slot: String,
    pub depth: String,
    pub old_head_block: String,
    pub new_head_block: String,
    pub old_head_state: String,
    pub new_head_state: String,
    pub epoch: String,
    pub execution_optimistic: bool,
}

/// Data from a `finalized_checkpoint` SSE event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FinalizedCheckpointEvent {
    pub block: String,
    pub state: String,
    pub epoch: String,
    pub execution_optimistic: bool,
}

/// Parsed SSE event from the beacon node event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseEvent {
    Head(HeadEvent),
    Block(BlockEvent),
    ChainReorg(ChainReorgEvent),
    FinalizedCheckpoint(FinalizedCheckpointEvent),
}

/// Errors from SSE event parsing.
#[derive(Debug, thiserror::Error)]
pub enum SseError {
    #[error("unknown event type: {0}")]
    UnknownEvent(String),
    #[error("failed to parse event data: {0}")]
    ParseError(String),
    #[error("connection error: {0}")]
    ConnectionError(String),
}

/// Parse a raw SSE event type and JSON data into an `SseEvent`.
pub fn parse_sse_event(event_type: &str, data: &str) -> Result<SseEvent, SseError> {
    match event_type {
        "head" => {
            let head: HeadEvent = serde_json::from_str(data)
                .map_err(|e| SseError::ParseError(format!("head: {e}")))?;
            Ok(SseEvent::Head(head))
        }
        "block" => {
            let block: BlockEvent = serde_json::from_str(data)
                .map_err(|e| SseError::ParseError(format!("block: {e}")))?;
            Ok(SseEvent::Block(block))
        }
        "chain_reorg" => {
            let reorg: ChainReorgEvent = serde_json::from_str(data)
                .map_err(|e| SseError::ParseError(format!("chain_reorg: {e}")))?;
            Ok(SseEvent::ChainReorg(reorg))
        }
        "finalized_checkpoint" => {
            let checkpoint: FinalizedCheckpointEvent = serde_json::from_str(data)
                .map_err(|e| SseError::ParseError(format!("finalized_checkpoint: {e}")))?;
            Ok(SseEvent::FinalizedCheckpoint(checkpoint))
        }
        other => Err(SseError::UnknownEvent(other.to_string())),
    }
}

/// Default SSE topics for event subscription.
pub const DEFAULT_SSE_TOPICS: &[&str] = &["head", "block", "chain_reorg", "finalized_checkpoint"];

/// Maximum consecutive connection failures before falling back to polling.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Configuration for the SSE event subscriber.
#[derive(Debug, Clone)]
pub struct SseConfig {
    /// Beacon node endpoint URL (base URL, e.g., "http://localhost:5052").
    pub endpoint: String,
    /// Topics to subscribe to.
    pub topics: Vec<String>,
}

impl SseConfig {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint, topics: DEFAULT_SSE_TOPICS.iter().map(|s| s.to_string()).collect() }
    }
}

/// State of the SSE connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseConnectionState {
    Connected,
    Reconnecting,
    PollingFallback,
    Disconnected,
}

/// Subscribes to beacon node SSE events. Calls `callback` for each parsed event.
///
/// - Auto-reconnects on connection drop.
/// - Supports failover to secondary endpoints when multiple configs are provided.
/// - Falls back to polling after `MAX_CONSECUTIVE_FAILURES` consecutive connection failures
///   on the current endpoint before switching to the next one.
/// - Stops when `shutdown` resolves.
pub async fn subscribe_events<F>(
    configs: Vec<SseConfig>,
    callback: F,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) where
    F: Fn(SseEvent) + Send + Sync + 'static,
{
    use reqwest_eventsource::{Event, EventSource};
    use tracing::{debug, info, warn};

    if configs.is_empty() {
        warn!("No SSE endpoints configured");
        return;
    }

    let mut current_idx = 0;
    let mut consecutive_failures: u32 = 0;

    loop {
        if *shutdown.borrow() {
            info!("SSE subscriber shutting down");
            return;
        }

        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            // Try failover to next endpoint if available
            if configs.len() > 1 {
                let next_idx = (current_idx + 1) % configs.len();
                warn!(
                    from = %configs[current_idx].endpoint,
                    to = %configs[next_idx].endpoint,
                    "SSE failover to secondary endpoint"
                );
                current_idx = next_idx;
                consecutive_failures = 0;
                continue;
            }

            // Only one endpoint, fall back to polling
            warn!(
                failures = consecutive_failures,
                "SSE max failures reached, falling back to polling"
            );
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("SSE subscriber shutting down during polling fallback");
                    return;
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(12)) => {
                    consecutive_failures = 0;
                    continue;
                }
            }
        }

        let config = &configs[current_idx];
        let topics = config.topics.join(",");
        let url =
            format!("{}/eth/v1/events?topics={}", config.endpoint.trim_end_matches('/'), topics);

        debug!(url = %url, "connecting to SSE stream");

        let mut es = EventSource::get(&url);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("SSE subscriber shutting down");
                    es.close();
                    return;
                }
                event = futures::StreamExt::next(&mut es) => {
                    match event {
                        Some(Ok(Event::Open)) => {
                            info!("SSE connection established");
                            consecutive_failures = 0;
                        }
                        Some(Ok(Event::Message(msg))) => {
                            match parse_sse_event(&msg.event, &msg.data) {
                                Ok(sse_event) => {
                                    debug!(event_type = %msg.event, "SSE event received");
                                    callback(sse_event);
                                }
                                Err(SseError::UnknownEvent(evt)) => {
                                    debug!(event_type = %evt, "ignoring unknown SSE event type");
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to parse SSE event");
                                }
                            }
                        }
                        Some(Err(err)) => {
                            warn!(error = %err, "SSE stream error");
                            consecutive_failures += 1;
                            es.close();
                            break;
                        }
                        None => {
                            warn!("SSE stream ended");
                            consecutive_failures += 1;
                            break;
                        }
                    }
                }
            }
        }

        // Brief delay before reconnecting
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_sse_event: Head --

    #[test]
    fn test_parse_head_event() {
        let data = r#"{
            "slot": "1234",
            "block": "0xabcdef",
            "state": "0x123456",
            "epoch_transition": false,
            "previous_duty_dependent_root": "0xaaa",
            "current_duty_dependent_root": "0xbbb",
            "execution_optimistic": false
        }"#;
        let event = parse_sse_event("head", data).unwrap();
        match event {
            SseEvent::Head(h) => {
                assert_eq!(h.slot, "1234");
                assert_eq!(h.block, "0xabcdef");
                assert_eq!(h.state, "0x123456");
                assert!(!h.epoch_transition);
                assert_eq!(h.previous_duty_dependent_root, "0xaaa");
                assert_eq!(h.current_duty_dependent_root, "0xbbb");
                assert!(!h.execution_optimistic);
            }
            _ => panic!("expected Head event"),
        }
    }

    #[test]
    fn test_parse_head_event_epoch_transition() {
        let data = r#"{
            "slot": "31",
            "block": "0xabc",
            "state": "0xdef",
            "epoch_transition": true,
            "previous_duty_dependent_root": "0x111",
            "current_duty_dependent_root": "0x222",
            "execution_optimistic": true
        }"#;
        let event = parse_sse_event("head", data).unwrap();
        match event {
            SseEvent::Head(h) => {
                assert!(h.epoch_transition);
                assert!(h.execution_optimistic);
            }
            _ => panic!("expected Head event"),
        }
    }

    // -- parse_sse_event: Block --

    #[test]
    fn test_parse_block_event() {
        let data = r#"{
            "slot": "5678",
            "block": "0xdeadbeef",
            "execution_optimistic": false
        }"#;
        let event = parse_sse_event("block", data).unwrap();
        match event {
            SseEvent::Block(b) => {
                assert_eq!(b.slot, "5678");
                assert_eq!(b.block, "0xdeadbeef");
                assert!(!b.execution_optimistic);
            }
            _ => panic!("expected Block event"),
        }
    }

    // -- parse_sse_event: ChainReorg --

    #[test]
    fn test_parse_chain_reorg_event() {
        let data = r#"{
            "slot": "100",
            "depth": "2",
            "old_head_block": "0xold",
            "new_head_block": "0xnew",
            "old_head_state": "0xoldstate",
            "new_head_state": "0xnewstate",
            "epoch": "3",
            "execution_optimistic": false
        }"#;
        let event = parse_sse_event("chain_reorg", data).unwrap();
        match event {
            SseEvent::ChainReorg(r) => {
                assert_eq!(r.slot, "100");
                assert_eq!(r.depth, "2");
                assert_eq!(r.old_head_block, "0xold");
                assert_eq!(r.new_head_block, "0xnew");
                assert_eq!(r.old_head_state, "0xoldstate");
                assert_eq!(r.new_head_state, "0xnewstate");
                assert_eq!(r.epoch, "3");
                assert!(!r.execution_optimistic);
            }
            _ => panic!("expected ChainReorg event"),
        }
    }

    // -- parse_sse_event: FinalizedCheckpoint --

    #[test]
    fn test_parse_finalized_checkpoint_event() {
        let data = r#"{
            "block": "0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf",
            "state": "0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9",
            "epoch": "2",
            "execution_optimistic": false
        }"#;
        let event = parse_sse_event("finalized_checkpoint", data).unwrap();
        match event {
            SseEvent::FinalizedCheckpoint(f) => {
                assert_eq!(
                    f.block,
                    "0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf"
                );
                assert_eq!(
                    f.state,
                    "0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9"
                );
                assert_eq!(f.epoch, "2");
                assert!(!f.execution_optimistic);
            }
            _ => panic!("expected FinalizedCheckpoint event"),
        }
    }

    // -- parse_sse_event: errors --

    #[test]
    fn test_parse_unknown_event_type() {
        let result = parse_sse_event("unknown_topic", "{}");
        assert!(result.is_err());
        match result.unwrap_err() {
            SseError::UnknownEvent(t) => assert_eq!(t, "unknown_topic"),
            other => panic!("expected UnknownEvent, got: {other}"),
        }
    }

    #[test]
    fn test_parse_invalid_json_head() {
        let result = parse_sse_event("head", "not json");
        assert!(result.is_err());
        match result.unwrap_err() {
            SseError::ParseError(msg) => assert!(msg.contains("head")),
            other => panic!("expected ParseError, got: {other}"),
        }
    }

    #[test]
    fn test_parse_invalid_json_block() {
        let result = parse_sse_event("block", "{invalid}");
        assert!(result.is_err());
        match result.unwrap_err() {
            SseError::ParseError(msg) => assert!(msg.contains("block")),
            other => panic!("expected ParseError, got: {other}"),
        }
    }

    #[test]
    fn test_parse_invalid_json_chain_reorg() {
        let result = parse_sse_event("chain_reorg", "");
        assert!(result.is_err());
        match result.unwrap_err() {
            SseError::ParseError(msg) => assert!(msg.contains("chain_reorg")),
            other => panic!("expected ParseError, got: {other}"),
        }
    }

    #[test]
    fn test_parse_invalid_json_finalized_checkpoint() {
        let result = parse_sse_event("finalized_checkpoint", "[]");
        assert!(result.is_err());
        match result.unwrap_err() {
            SseError::ParseError(msg) => assert!(msg.contains("finalized_checkpoint")),
            other => panic!("expected ParseError, got: {other}"),
        }
    }

    #[test]
    fn test_parse_head_missing_field() {
        let data = r#"{"slot": "1"}"#;
        let result = parse_sse_event("head", data);
        assert!(result.is_err());
    }

    // -- SseEvent variants --

    #[test]
    fn test_sse_event_debug() {
        let head = SseEvent::Head(HeadEvent {
            slot: "0".to_string(),
            block: "0x00".to_string(),
            state: "0x00".to_string(),
            epoch_transition: false,
            previous_duty_dependent_root: "0x00".to_string(),
            current_duty_dependent_root: "0x00".to_string(),
            execution_optimistic: false,
        });
        let debug = format!("{:?}", head);
        assert!(debug.contains("Head"));
    }

    #[test]
    fn test_sse_event_clone() {
        let event = SseEvent::Block(BlockEvent {
            slot: "1".to_string(),
            block: "0xabc".to_string(),
            execution_optimistic: false,
        });
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    // -- SseError display --

    #[test]
    fn test_sse_error_unknown_display() {
        let err = SseError::UnknownEvent("foo".to_string());
        assert_eq!(err.to_string(), "unknown event type: foo");
    }

    #[test]
    fn test_sse_error_parse_display() {
        let err = SseError::ParseError("bad json".to_string());
        assert_eq!(err.to_string(), "failed to parse event data: bad json");
    }

    #[test]
    fn test_sse_error_connection_display() {
        let err = SseError::ConnectionError("timeout".to_string());
        assert_eq!(err.to_string(), "connection error: timeout");
    }

    // -- SseConfig --

    #[test]
    fn test_sse_config_new_defaults() {
        let config = SseConfig::new("http://localhost:5052".to_string());
        assert_eq!(config.endpoint, "http://localhost:5052");
        assert_eq!(config.topics.len(), 4);
        assert!(config.topics.contains(&"head".to_string()));
        assert!(config.topics.contains(&"block".to_string()));
        assert!(config.topics.contains(&"chain_reorg".to_string()));
        assert!(config.topics.contains(&"finalized_checkpoint".to_string()));
    }

    #[test]
    fn test_sse_config_clone() {
        let config = SseConfig::new("http://localhost:5052".to_string());
        let cloned = config.clone();
        assert_eq!(cloned.endpoint, config.endpoint);
        assert_eq!(cloned.topics, config.topics);
    }

    // -- SseConnectionState --

    #[test]
    fn test_connection_state_variants() {
        assert_eq!(SseConnectionState::Connected, SseConnectionState::Connected);
        assert_ne!(SseConnectionState::Connected, SseConnectionState::Disconnected);
        assert_ne!(SseConnectionState::Reconnecting, SseConnectionState::PollingFallback);
    }

    // -- DEFAULT_SSE_TOPICS --

    #[test]
    fn test_default_topics() {
        assert_eq!(DEFAULT_SSE_TOPICS.len(), 4);
        assert_eq!(DEFAULT_SSE_TOPICS[0], "head");
        assert_eq!(DEFAULT_SSE_TOPICS[1], "block");
        assert_eq!(DEFAULT_SSE_TOPICS[2], "chain_reorg");
        assert_eq!(DEFAULT_SSE_TOPICS[3], "finalized_checkpoint");
    }

    // -- Integration: subscribe_events --

    #[tokio::test]
    async fn test_subscribe_events_shutdown_immediately() {
        let (tx, rx) = tokio::sync::watch::channel(true);
        let config = SseConfig::new("http://localhost:1".to_string());
        let callback = |_event: SseEvent| {};

        subscribe_events(vec![config], callback, rx).await;
        drop(tx);
    }

    /// Helper: start a TCP-based SSE server that writes raw SSE frames.
    async fn start_sse_server(sse_body: &str) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = sse_body.to_string();

        let handle = tokio::spawn(async move {
            // Accept multiple connections (for reconnect tests)
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    // Read the HTTP request (discard it)
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                    // Send chunked HTTP response with SSE content-type
                    let headers = "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Cache-Control: no-cache\r\n\
                         Transfer-Encoding: chunked\r\n\
                         \r\n"
                        .to_string();
                    let _ = stream.write_all(headers.as_bytes()).await;

                    // Send body as a single chunk
                    let chunk = format!("{:x}\r\n{}\r\n", body.len(), body);
                    let _ = stream.write_all(chunk.as_bytes()).await;
                    let _ = stream.flush().await;

                    // Keep connection open for a bit so client can read events
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                    // Send terminating chunk
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                });
            }
        });

        (port, handle)
    }

    #[tokio::test]
    async fn test_subscribe_events_receives_head_event() {
        use std::sync::{Arc, Mutex};

        let sse_body = "event: head\ndata: {\"slot\":\"999\",\"block\":\"0xabc\",\"state\":\"0xdef\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0x111\",\"current_duty_dependent_root\":\"0x222\",\"execution_optimistic\":false}\n\n";

        let (port, server_handle) = start_sse_server(sse_body).await;

        let events: Arc<Mutex<Vec<SseEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

        let handle = tokio::spawn(async move {
            subscribe_events(
                vec![config],
                move |event| {
                    events_clone.lock().unwrap().push(event);
                },
                rx,
            )
            .await;
        });

        // Wait for events to arrive
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if !events.lock().unwrap().is_empty() {
                break;
            }
        }

        tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        server_handle.abort();

        let received = events.lock().unwrap();
        assert!(!received.is_empty(), "should have received at least one event");
        match &received[0] {
            SseEvent::Head(h) => {
                assert_eq!(h.slot, "999");
                assert_eq!(h.block, "0xabc");
            }
            other => panic!("expected Head event, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_subscribe_events_receives_multiple_events() {
        use std::sync::{Arc, Mutex};

        let sse_body = concat!(
            "event: head\n",
            "data: {\"slot\":\"100\",\"block\":\"0xa\",\"state\":\"0xb\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0xc\",\"current_duty_dependent_root\":\"0xd\",\"execution_optimistic\":false}\n\n",
            "event: block\n",
            "data: {\"slot\":\"100\",\"block\":\"0xa\",\"execution_optimistic\":false}\n\n",
            "event: finalized_checkpoint\n",
            "data: {\"block\":\"0xe\",\"state\":\"0xf\",\"epoch\":\"3\",\"execution_optimistic\":false}\n\n",
        );

        let (port, server_handle) = start_sse_server(sse_body).await;

        let events: Arc<Mutex<Vec<SseEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

        let handle = tokio::spawn(async move {
            subscribe_events(
                vec![config],
                move |event| {
                    events_clone.lock().unwrap().push(event);
                },
                rx,
            )
            .await;
        });

        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if events.lock().unwrap().len() >= 3 {
                break;
            }
        }

        tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        server_handle.abort();

        let received = events.lock().unwrap();
        assert!(received.len() >= 3, "expected at least 3 events, got {}", received.len());
        assert!(matches!(&received[0], SseEvent::Head(_)));
        assert!(matches!(&received[1], SseEvent::Block(_)));
        assert!(matches!(&received[2], SseEvent::FinalizedCheckpoint(_)));
    }

    #[tokio::test]
    async fn test_subscribe_events_ignores_unknown_event_types() {
        use std::sync::{Arc, Mutex};

        let sse_body = concat!(
            "event: attestation\n",
            "data: {\"some\":\"data\"}\n\n",
            "event: head\n",
            "data: {\"slot\":\"50\",\"block\":\"0xa\",\"state\":\"0xb\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0xc\",\"current_duty_dependent_root\":\"0xd\",\"execution_optimistic\":false}\n\n",
        );

        let (port, server_handle) = start_sse_server(sse_body).await;

        let events: Arc<Mutex<Vec<SseEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

        let handle = tokio::spawn(async move {
            subscribe_events(
                vec![config],
                move |event| {
                    events_clone.lock().unwrap().push(event);
                },
                rx,
            )
            .await;
        });

        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if !events.lock().unwrap().is_empty() {
                break;
            }
        }

        tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        server_handle.abort();

        let received = events.lock().unwrap();
        assert_eq!(received.len(), 1, "expected exactly 1 event, got {}", received.len());
        assert!(matches!(&received[0], SseEvent::Head(_)));
    }

    #[tokio::test]
    async fn test_subscribe_events_reconnects_on_connection_drop() {
        use std::sync::{Arc, Mutex};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connect_count: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let connect_count_clone = connect_count.clone();

        let server_handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let count_clone = connect_count_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                    let n = {
                        let mut count = count_clone.lock().unwrap();
                        *count += 1;
                        *count
                    };

                    let sse_body = format!(
                        "event: head\ndata: {{\"slot\":\"{}\",\"block\":\"0xa\",\"state\":\"0xb\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0xc\",\"current_duty_dependent_root\":\"0xd\",\"execution_optimistic\":false}}\n\n",
                        n
                    );

                    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n";
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let chunk = format!("{:x}\r\n{}\r\n", sse_body.len(), sse_body);
                    let _ = stream.write_all(chunk.as_bytes()).await;
                    let _ = stream.flush().await;

                    // Close immediately to simulate drop
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                });
            }
        });

        let events: Arc<Mutex<Vec<SseEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

        let handle = tokio::spawn(async move {
            subscribe_events(
                vec![config],
                move |event| {
                    events_clone.lock().unwrap().push(event);
                },
                rx,
            )
            .await;
        });

        // Wait for at least 2 connections (reconnect happened)
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if events.lock().unwrap().len() >= 2 {
                break;
            }
        }

        tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
        server_handle.abort();

        let received = events.lock().unwrap();
        assert!(
            received.len() >= 2,
            "expected at least 2 events from reconnects, got {}",
            received.len()
        );

        let total_connects = *connect_count.lock().unwrap();
        assert!(total_connects >= 2, "expected at least 2 connections, got {}", total_connects);
    }

    #[tokio::test]
    async fn test_subscribe_events_empty_configs() {
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let callback = |_event: SseEvent| {};
        // Should return immediately without panic
        subscribe_events(vec![], callback, rx).await;
    }

    #[tokio::test]
    async fn test_subscribe_events_failover_to_secondary() {
        use std::sync::{Arc, Mutex};

        // Primary endpoint: always refuses connections (port with no listener)
        // Secondary endpoint: serves events
        let sse_body = "event: head\ndata: {\"slot\":\"42\",\"block\":\"0xa\",\"state\":\"0xb\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0xc\",\"current_duty_dependent_root\":\"0xd\",\"execution_optimistic\":false}\n\n";

        let (secondary_port, server_handle) = start_sse_server(sse_body).await;

        let events: Arc<Mutex<Vec<SseEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let (tx, rx) = tokio::sync::watch::channel(false);

        // Primary: unreachable port, secondary: our server
        let configs = vec![
            SseConfig::new("http://127.0.0.1:1".to_string()),
            SseConfig::new(format!("http://127.0.0.1:{secondary_port}")),
        ];

        let handle = tokio::spawn(async move {
            subscribe_events(
                configs,
                move |event| {
                    events_clone.lock().unwrap().push(event);
                },
                rx,
            )
            .await;
        });

        // Wait for failover and event reception
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if !events.lock().unwrap().is_empty() {
                break;
            }
        }

        tx.send(true).unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
        server_handle.abort();

        let received = events.lock().unwrap();
        assert!(
            !received.is_empty(),
            "should have received events from secondary endpoint after failover"
        );
        match &received[0] {
            SseEvent::Head(h) => assert_eq!(h.slot, "42"),
            other => panic!("expected Head event, got: {:?}", other),
        }
    }
}
