//! ARCH-7a / M2: `rvc_slot_phase_block_start_offset_ms` histogram.

use super::*;
use metrics::definitions::{slot_phase_cache, RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS};
use std::sync::OnceLock;
use timing::SystemSlotClock;
use tokio::sync::{Mutex, MutexGuard};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Global histogram counters are process-wide; serialize these tests so
/// sample-count deltas are not raced by sibling cases.
async fn m2_metric_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

fn empty_duty_body() -> serde_json::Value {
    serde_json::json!({
        "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "execution_optimistic": false,
        "data": []
    })
}

fn block_root_body() -> serde_json::Value {
    serde_json::json!({
        "execution_optimistic": false,
        "data": { "root": "0x0000000000000000000000000000000000000000000000000000000000000001" }
    })
}

/// Mount empty attester/proposer duty responses and a block-root for `SlotContext`.
async fn mount_slot_loop_mocks(
    mock_server: &MockServer,
    duty_delay: Option<Duration>,
    root_delay: Option<Duration>,
) {
    let mut attester = ResponseTemplate::new(200).set_body_json(empty_duty_body());
    let mut proposer = ResponseTemplate::new(200).set_body_json(empty_duty_body());
    if let Some(d) = duty_delay {
        attester = attester.set_delay(d);
        proposer = proposer.set_delay(d);
    }

    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/attester/.*"))
        .respond_with(attester)
        .mount(mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/validator/duties/proposer/.*"))
        .respond_with(proposer)
        .mount(mock_server)
        .await;

    // Sync committee duties (empty) so the fetch path completes quickly.
    Mock::given(method("POST"))
        .and(path_regex(r"/eth/v1/validator/duties/sync/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_duty_body()))
        .mount(mock_server)
        .await;

    let mut root = ResponseTemplate::new(200).set_body_json(block_root_body());
    if let Some(d) = root_delay {
        root = root.set_delay(d);
    }
    Mock::given(method("GET"))
        .and(path_regex(r"/eth/v1/beacon/blocks/.*/root"))
        .respond_with(root)
        .mount(mock_server)
        .await;
}

fn histogram_count(cache: &str) -> u64 {
    RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).get_sample_count()
}

fn histogram_sum(cache: &str) -> f64 {
    RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS.with_label_values(&[cache]).get_sample_sum()
}

/// Drive one slot through `run()` and assert the M2 histogram records a sample.
#[tokio::test(flavor = "current_thread")]
async fn test_slot_phase_block_start_offset_is_recorded_each_slot() {
    let _guard = m2_metric_lock().await;

    let mock_server = MockServer::start().await;
    mount_slot_loop_mocks(&mock_server, None, None).await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    // Non-boundary slot; past 2/3 so phase waits are zero.
    clock.set_slot(65);
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let cold_before = histogram_count(slot_phase_cache::COLD);
    let warm_before = histogram_count(slot_phase_cache::WARM);
    let cold_sum_before = histogram_sum(slot_phase_cache::COLD);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config().with_timeouts(fast_timeouts()),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    // First slot after boot is cold. Global registry may receive concurrent
    // samples from sibling tests; under the metric lock among M2 cases we
    // still require exactly one new sample from this single-slot drive when
    // no other slot-loop test races us.
    let cold_after = histogram_count(slot_phase_cache::COLD);
    let warm_after = histogram_count(slot_phase_cache::WARM);
    let cold_added = cold_after - cold_before;
    let warm_added = warm_after - warm_before;
    let samples = cold_added + warm_added;
    assert!(
        samples >= 1,
        "at least one sample per driven slot; cold+{cold_added}/warm+{warm_added}"
    );
    assert!(cold_added >= 1, "first slot after boot must be labelled cache=cold");
    // When isolation holds, the single-slot drive records exactly one cold sample.
    if samples == 1 {
        assert_eq!(cold_added, 1);
        assert_eq!(warm_added, 0);
    }

    let cold_sum_after = histogram_sum(slot_phase_cache::COLD);
    let observed = cold_sum_after - cold_sum_before;
    assert!(observed >= 0.0, "offset must be >= 0, got {observed}");
}

/// Mock BN parent-root delay must appear in the recorded offset (instrument credibility).
#[tokio::test(flavor = "current_thread")]
async fn test_offset_reflects_pre_proposal_work() {
    let _guard = m2_metric_lock().await;

    let mock_server = MockServer::start().await;
    // Wall-clock delay large enough for second-resolution SystemSlotClock.
    let delay = Duration::from_secs(2);
    mount_slot_loop_mocks(&mock_server, None, Some(delay)).await;

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let slot = 1_000u64;
    let slot_secs = 12u64;
    // Genesis so wall "now" sits near the start of `slot`.
    let genesis = now.saturating_sub(slot * slot_secs);
    let clock =
        Arc::new(SystemSlotClock::new(genesis, Duration::from_secs(slot_secs), 32).unwrap());

    let beacon_config = BeaconClientConfig::new(mock_server.uri())
        .with_timeout(Duration::from_secs(30))
        .with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["0x01".to_string()]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    // Deadline must exceed the injected parent-root delay so capture completes.
    let timeouts = OperationTimeouts { duty_fetch: Duration::from_secs(10), ..fast_timeouts() };

    let cold_sum_before = histogram_sum(slot_phase_cache::COLD);
    let cold_count_before = histogram_count(slot_phase_cache::COLD);
    let warm_count_before = histogram_count(slot_phase_cache::WARM);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        create_mock_validator_store(),
        create_test_config()
            .with_timeouts(timeouts)
            .with_pre_proposal_deadline(Duration::from_secs(10)),
        Arc::new(parking_lot::RwLock::new(HashMap::new())),
    ));

    // Parent-root delay can be multi-second; allow headroom then shut down.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(15)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let cold_count_after = histogram_count(slot_phase_cache::COLD);
    let warm_count_after = histogram_count(slot_phase_cache::WARM);
    let samples = (cold_count_after - cold_count_before) + (warm_count_after - warm_count_before);
    assert!(samples >= 1, "expected at least one offset sample, got {samples}");

    // First sample is cold (post-boot); its contribution is the delta on cold sum
    // when only one cold sample was added.
    let cold_added = cold_count_after - cold_count_before;
    assert!(cold_added >= 1, "post-boot sample must be labelled cold");
    let cold_sum_after = histogram_sum(slot_phase_cache::COLD);
    // Lower-bound the newest cold observations: total cold sum increase / cold samples
    // is at least the injected delay (sequential fetches often exceed D).
    let sum_delta = cold_sum_after - cold_sum_before;
    let min_per_sample = sum_delta / cold_added as f64;
    assert!(
        min_per_sample >= delay.as_millis() as f64,
        "offset must reflect pre-proposal parent-root delay D={}ms; got avg cold offset {min_per_sample}ms \
         (sum_delta={sum_delta}, cold_added={cold_added})",
        delay.as_millis()
    );
}

/// After a key_gen invalidation the next slot's offset is labelled `cache=cold`.
#[tokio::test(flavor = "current_thread")]
async fn test_offset_labels_cold_after_key_gen_invalidation() {
    let _guard = m2_metric_lock().await;

    let mock_server = MockServer::start().await;
    mount_slot_loop_mocks(&mock_server, None, None).await;

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(65);
    clock.advance_time(9);

    let beacon_config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(0);
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![]));

    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));
    let propagator = Arc::new(Propagator::new(Arc::new(MockSubmitter::new())));

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);

    let cold_before = histogram_count(slot_phase_cache::COLD);
    let warm_before = histogram_count(slot_phase_cache::WARM);

    let (mut orchestrator, handle) = DutyOrchestrator::new(OrchestratorDeps {
        key_gen_rx,
        ..OrchestratorDeps::for_test(
            clock.clone(),
            duty_tracker,
            signer,
            propagator,
            beacon,
            create_mock_block_beacon(),
            None,
            create_mock_validator_store(),
            create_test_config().with_timeouts(fast_timeouts()),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
        )
    });

    // Drain the initial watch "changed" so only a real bump re-marks cold via key_gen.
    orchestrator.apply_key_gen_cache_invalidation().await;
    // Boot flag is still cold until the first offset sample; first slot → cold.

    let clock_adv = clock.clone();
    tokio::spawn(async move {
        // Slot 65 (cold / post-boot). time_until next ≈ 3 s after advance_time(9).
        tokio::time::sleep(Duration::from_millis(500)).await;
        clock_adv.set_slot(66);
        clock_adv.advance_time(9);

        // Slot 66 (warm): wait for processing after the ~3 s next-slot wait.
        tokio::time::sleep(Duration::from_millis(3500)).await;
        key_gen_tx.send_modify(|gen| *gen += 1);
        clock_adv.set_slot(67);
        clock_adv.advance_time(9);

        // Slot 67 (cold / post-key_gen).
        tokio::time::sleep(Duration::from_millis(3500)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    let cold_added = histogram_count(slot_phase_cache::COLD) - cold_before;
    let warm_added = histogram_count(slot_phase_cache::WARM) - warm_before;

    assert!(warm_added >= 1, "steady-state slot after boot must be warm; warm_added={warm_added}");
    assert!(
        cold_added >= 2,
        "post-boot and post-key_gen slots must both be cold; cold_added={cold_added}"
    );
}
