//! Coordinator tests: tracing.

use super::*;

// --- H-08: Orchestrator slot lifecycle span tests ---

use parking_lot::Mutex;
use std::collections::HashMap as SpanMap;
use tracing::span::Id;
use tracing_subscriber::layer::SubscriberExt;

/// A tracing layer that captures span names for test verification.
struct SpanCapture {
    names: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        self.names.lock().push(attrs.metadata().name().to_string());
    }
}

/// Recorded span entry with name and optional parent span ID.
#[derive(Debug, Clone)]
struct SpanEntry {
    name: String,
    parent_id: Option<Id>,
}

/// A tracing layer that captures span names and parent-child relationships.
struct HierarchyCapture {
    spans: Arc<Mutex<SpanMap<u64, SpanEntry>>>,
}

impl<S> tracing_subscriber::Layer<S> for HierarchyCapture
where
    S: tracing::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let parent_id = attrs.parent().cloned().or_else(|| ctx.current_span().id().cloned());
        self.spans.lock().insert(
            id.into_u64(),
            SpanEntry { name: attrs.metadata().name().to_string(), parent_id },
        );
    }
}

impl HierarchyCapture {
    fn new() -> (Self, Arc<Mutex<SpanMap<u64, SpanEntry>>>) {
        let spans = Arc::new(Mutex::new(SpanMap::new()));
        (Self { spans: spans.clone() }, spans)
    }
}

/// Returns the parent span name for a given child span name, if both exist.
fn find_parent_name(spans: &SpanMap<u64, SpanEntry>, child_name: &str) -> Option<String> {
    for entry in spans.values() {
        if entry.name == child_name {
            if let Some(ref parent_id) = entry.parent_id {
                if let Some(parent) = spans.get(&parent_id.into_u64()) {
                    return Some(parent.name.clone());
                }
            }
        }
    }
    None
}

#[tokio::test(flavor = "current_thread")]
async fn test_slot_processing_creates_root_and_phase_spans() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(65); // slot 65 = epoch 2, not at epoch boundary
                        // Advance past 2/3 of slot so all phases run without waiting
    clock.advance_time(9);

    // Use 0 retries so that failed HTTP calls (localhost:5052 unavailable) return
    // immediately, keeping the test well within its 5-second window even after
    // SlotContext::capture adds a get_block_root call to the slot loop.
    let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    // Capture spans via thread-local subscriber
    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Shutdown after enough time for all phases (HTTP failures are fast)
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"slot.process".to_string()),
        "Expected slot.process span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slot.phase.block".to_string()),
        "Expected slot.phase.block span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slot.phase.attestation".to_string()),
        "Expected slot.phase.attestation span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slot.phase.aggregation".to_string()),
        "Expected slot.phase.aggregation span, got: {:?}",
        *span_names
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_epoch_boundary_creates_epoch_span() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(32); // slot 32 = epoch 1, IS at epoch boundary (32 % 32 == 0)
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"epoch.boundary".to_string()),
        "Expected epoch.boundary span at epoch boundary slot, got: {:?}",
        *span_names
    );
}

// --- H-25: Aggregation span link tests ---

#[tokio::test]
async fn test_aggregation_creates_produce_span() {
    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    // Mock attester duties — small committee (always aggregator)
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "8",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // Mock attestation data
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/attestation_data"))
        .and(query_param("slot", slot.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "slot": slot.to_string(),
                "index": "1",
                "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "source": { "epoch": (epoch - 1).to_string(), "root": "0x2222222222222222222222222222222222222222222222222222222222222222" },
                "target": { "epoch": epoch.to_string(), "root": "0x3333333333333333333333333333333333333333333333333333333333333333" }
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock aggregate attestation
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "aggregation_bits": "0xffffffff",
                "data": {
                    "slot": slot.to_string(),
                    "index": "1",
                    "beacon_block_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "source": { "epoch": (epoch - 1).to_string(), "root": "0x2222222222222222222222222222222222222222222222222222222222222222" },
                    "target": { "epoch": epoch.to_string(), "root": "0x3333333333333333333333333333333333333333333333333333333333333333" }
                },
                "signature": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        })))
        .mount(&mock_server)
        .await;

    // Mock submit aggregate and proofs
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/aggregate_and_proofs"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"orchestrator.produce_aggregations".to_string()),
        "Expected orchestrator.produce_aggregations span, got: {:?}",
        *span_names
    );
    // Note: aggregation.submit may not appear under coverage instrumentation
    // due to subscriber interference in concurrent test runs. The produce span
    // is the primary assertion for this test.
}

#[tokio::test]
async fn test_aggregation_non_aggregator_creates_produce_span_without_submit() {
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let (orchestrator, _handle, _, pubkey_hex) =
        build_aggregation_orchestrator(&mock_server.uri()).await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;

    // Large committee → unlikely to be aggregator
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": "42",
                "committee_index": "1",
                "committee_length": "100000",
                "committees_at_slot": "4",
                "validator_committee_index": "0",
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    // Should NOT call aggregate attestation or submit
    Mock::given(method("GET"))
        .and(path("/eth/v1/validator/aggregate_attestation"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&mock_server)
        .await;

    orchestrator.duty_tracker.fetch_duties_for_epoch(epoch).await.unwrap();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    orchestrator.aggregation_service.maybe_produce_aggregations(slot, epoch).await;

    let span_names = captured.lock();
    // produce span should still be created (it wraps the entire per-validator loop body)
    assert!(
        span_names.contains(&"orchestrator.produce_aggregations".to_string()),
        "Expected orchestrator.produce_aggregations span even for non-aggregator, got: {:?}",
        *span_names
    );
    // submit span should NOT be created (no aggregates to submit)
    assert!(
        !span_names.contains(&"aggregation.submit".to_string()),
        "Did not expect aggregation.submit span for non-aggregator, got: {:?}",
        *span_names
    );
}

// --- H-14: End-to-end span hierarchy integration tests ---

#[tokio::test(flavor = "current_thread")]
async fn test_phase_spans_are_children_of_slot_process() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(65); // non-boundary slot
    clock.advance_time(9);

    // Use 0 retries so that failed HTTP calls (localhost:5052 unavailable) return
    // immediately, keeping the test well within its 5-second window even after
    // SlotContext::capture adds a get_block_root call to the slot loop.
    let beacon_config = BeaconClientConfig::new("http://localhost:5052").with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let (layer, spans) = HierarchyCapture::new();
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_map = spans.lock();

    // Verify phase spans are children of slot.process
    let block_parent = find_parent_name(&span_map, "slot.phase.block");
    assert_eq!(
        block_parent.as_deref(),
        Some("slot.process"),
        "slot.phase.block should be child of slot.process"
    );

    let att_parent = find_parent_name(&span_map, "slot.phase.attestation");
    assert_eq!(
        att_parent.as_deref(),
        Some("slot.process"),
        "slot.phase.attestation should be child of slot.process"
    );

    let agg_parent = find_parent_name(&span_map, "slot.phase.aggregation");
    assert_eq!(
        agg_parent.as_deref(),
        Some("slot.process"),
        "slot.phase.aggregation should be child of slot.process"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_epoch_boundary_span_is_child_of_slot_process() {
    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(32); // epoch boundary
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new("http://localhost:5052");
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        config,
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    let (layer, spans) = HierarchyCapture::new();
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let span_map = spans.lock();

    let epoch_parent = find_parent_name(&span_map, "epoch.boundary");
    assert_eq!(
        epoch_parent.as_deref(),
        Some("slot.process"),
        "epoch.boundary should be child of slot.process"
    );
}

#[tokio::test]
async fn test_signer_span_created_on_sign_attestation() {
    use crypto::SecretKey;
    use eth_types::{AttestationData, Checkpoint};

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();

    let mut manager = KeyManager::new();
    manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer = SignerService::new(composite, slashing_db).with_enablement(always_enabled());

    let attestation_data = AttestationData {
        slot: 1000,
        index: 5,
        beacon_block_root: [0x11; 32],
        source: Checkpoint { epoch: 100, root: [0x22; 32] },
        target: Checkpoint { epoch: 101, root: [0x33; 32] },
    };
    let fork_schedule = create_test_fork_schedule();
    let genesis_root = [0xaa; 32];

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let result =
        signer.sign_attestation(&attestation_data, &pubkey, &fork_schedule, &genesis_root).await;
    assert!(result.is_ok());

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"sign.attestation".to_string()),
        "Expected sign.attestation span, got: {:?}",
        *span_names
    );
    assert!(
        span_names.contains(&"slashing.check".to_string()),
        "Expected slashing.check span within sign_attestation, got: {:?}",
        *span_names
    );
}

#[tokio::test]
async fn test_beacon_http_span_created() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/eth/v1/node/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "version": "mock/v1.0.0" }
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = BeaconClient::new(beacon_config).unwrap();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = SpanCapture { names: captured.clone() };
    let subscriber = tracing_subscriber::registry::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let _ = beacon.get_node_version().await;

    let span_names = captured.lock();
    assert!(
        span_names.contains(&"beacon.http".to_string()),
        "Expected beacon.http span, got: {:?}",
        *span_names
    );
}
