//! Coordinator tests: block proposal gating and doppelganger.

use super::*;

/// H-4 coordinator integration test: when the BN returns a block whose
/// `proposer_index` does not match the duty's `validator_index`, the duty
/// must be silently dropped — no signer call and no publish call.
///
/// RED against d490044: `propose_block` (unvalidated) ignores the
/// `proposer_index` and proceeds to sign + publish, so `publish_called`
/// becomes `true` → assertion fails.
///
/// GREEN after CQ-3.2: the validated `propose_block` is the only entry point;
/// the mismatch is caught before signing, `publish_called` stays `false`.
#[tokio::test]
async fn test_maybe_propose_block_bad_proposer_index_drops_duty() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let slot = 100u64;
    let epoch = slot / SLOTS_PER_EPOCH;
    // The duty says this validator should propose at slot 100.
    let expected_validator_index = 42u64;
    // The BN returns a block with a different (forged) proposer_index.
    let bad_proposer_index = 99u64;

    // Generate a real key so RANDAO signing succeeds and we reach the
    // proposer_index validation step.
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

    // Beacon client for duty fetching (backed by wiremock).
    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    // Serve proposer duties for the epoch.
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": expected_validator_index.to_string(),
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    // Pre-populate the proposer duty cache before calling maybe_propose_block.
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    // Block beacon: returns a block with wrong proposer_index; tracks publish.
    let publish_called = Arc::new(AtomicBool::new(false));
    let block_beacon = Arc::new(BadProposerBlockBeacon {
        slot,
        bad_proposer_index,
        publish_called: publish_called.clone(),
    });

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    let config = create_test_config();
    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey_hex.clone(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
        None,
        create_mock_validator_store(),
        config,
        pubkey_map,
    ));

    // Invoke the proposer path directly.
    let ctx = SlotContext { slot, epoch, head_root: None };
    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    // H-4: a forged proposer_index must drop the duty before any
    // signing or publishing occurs.
    assert!(
        !publish_called.load(Ordering::SeqCst),
        "publish_block must NOT be called when proposer_index mismatches the duty"
    );
}

/// When a validator's `enabled` flag is `false` in `ValidatorStore` (i.e.
/// it is still inside the post-import doppelganger window), the attestation
/// service must skip the duty and return `NoDutiesForSlot` rather than
/// attempting to sign.
///
/// Verifies the fix for ISSUE-3.11 Critical #1: "gate is never consulted
/// by the attestation path".
#[tokio::test]
async fn test_orchestrator_skips_duty_during_doppelganger_window() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    // 0x + 96 hex chars = 48 bytes (one 'd' nibble-pair per byte × 48)
    let duty_pubkey_hex =
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    // Slot 64 is in epoch 2 (64 / 32 = 2); mock duties endpoint for epoch 2.
    Mock::given(method("POST"))
        .and(path("/eth/v1/validator/duties/attester/2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": duty_pubkey_hex,
                "validator_index": "42",
                "committee_index": "0",
                "committee_length": "128",
                "committees_at_slot": "1",
                "validator_committee_index": "5",
                "slot": "64"
            }]
        })))
        .mount(&mock_server)
        .await;

    // Signer call count — must be zero while validator is disabled.
    let submitter = Arc::new(MockSubmitter::new());
    let submit_count = submitter.call_count.load(Ordering::SeqCst);

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 64));
    clock.set_slot(64);

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());
    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["42".to_string()]));

    // Pre-populate the duty cache so process_slot can find the duty.
    duty_tracker.fetch_duties_for_epoch(2).await.unwrap();

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let propagator = Arc::new(Propagator::new(submitter.clone()));
    let config = create_test_config();

    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(duty_pubkey_hex.to_string(), pubkey.clone());
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    // --- Critical: add the DUTY pubkey as DISABLED (inside doppelganger window).
    // D-3 (FUP-6): the gate now resolves the duty pubkey via `find_pubkey`
    // and gates on the RESOLVED typed pubkey's infallible `to_bytes()` — it
    // no longer re-decodes the raw `0xdddd...` duty string.  The store must
    // therefore track the SAME bytes the `pubkey_map` resolves the duty to
    // (`pubkey.to_bytes()`), not the literal `0xdddd...` byte pattern.
    let duty_pk_bytes: [u8; 48] = pubkey.to_bytes();
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 30_000_000));
    {
        let mut config = validator_store::ValidatorConfig::new(duty_pk_bytes);
        config.enabled = false;
        validator_store.add_validator(config);
    }

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        create_mock_block_beacon(),
        None,
        validator_store.clone(),
        config,
        pubkey_map,
    ));

    // Phase 1 (RED → GREEN): process_slot must return NoDutiesForSlot
    // because the validator is inside the doppelganger window (enabled=false).
    let result = orchestrator.attestation_service.process_slot(64).await;
    assert!(
        matches!(result, Err(OrchestratorError::NoDutiesForSlot { slot: 64 })),
        "duty must be filtered out while validator is in doppelganger window; got: {result:?}"
    );
    assert_eq!(
        submitter.call_count.load(Ordering::SeqCst),
        submit_count,
        "signer must NOT be called while validator is in doppelganger window"
    );

    // Phase 2: enable the validator (simulates window elapsed).
    validator_store.set_enabled(&duty_pk_bytes, true);

    // Now process_slot should proceed past the gate (will fail further on
    // because no beacon attestation-data mock is set up, but the important
    // thing is the duty is NOT filtered by the doppelganger check).
    let result2 = orchestrator.attestation_service.process_slot(64).await;
    assert!(
        !matches!(result2, Err(OrchestratorError::NoDutiesForSlot { .. })),
        "after enabling the validator, duty must NOT be filtered by doppelganger gate; \
         got: {result2:?}"
    );
}

// ── D-3: block proposal gate ─────────────────────────────────────────────

/// D-3: a validator whose `is_signing_enabled = false` must NOT propose a block.
///
/// The test uses wiremock to serve a proposer duty, then checks that
/// `publish_block` is never called when the validator is disabled.
///
/// RED: `maybe_propose_block` does not check `is_signing_enabled` →
///      the block_service is called (RANDAO sign, produce, publish).
///      The `BadProposerBlockBeacon` sets `publish_called = true` via
///      `produce_block_v3` returning a block with `proposer_index="1"`.
///      Actually `BadProposerBlockBeacon` calls `produce_block_v3` which
///      would attempt RANDAO sign first — the D-3 gate must fire before any
///      signer call, so the RANDAO sign never happens if the gate is correct.
///
/// GREEN: D-3 gate in `maybe_propose_block` returns early before
///        `block_service.propose_block`, so `publish_called` stays `false`.
#[tokio::test]
async fn test_block_proposal_skipped_when_validator_disabled() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    let slot: Slot = 10;
    let epoch = slot / SLOTS_PER_EPOCH;
    let validator_index = 1u64;

    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let pk_bytes: [u8; 48] = pubkey.to_bytes();

    // Serve proposer duties from wiremock.
    Mock::given(method("GET"))
        .and(path(format!("/eth/v1/validator/duties/proposer/{}", epoch)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "execution_optimistic": false,
            "data": [{
                "pubkey": pubkey_hex,
                "validator_index": validator_index.to_string(),
                "slot": slot.to_string()
            }]
        })))
        .mount(&mock_server)
        .await;

    let beacon_config = BeaconClientConfig::new(mock_server.uri());
    let beacon = Arc::new(BeaconClient::new(beacon_config).unwrap());

    let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec![pubkey_hex.clone()]));
    duty_tracker.fetch_proposer_duties(epoch).await.unwrap();

    // BadProposerBlockBeacon is already defined above; it returns a block
    // with a non-matching proposer_index which would also cause a drop.
    // Use a matching proposer_index (validator_index) so the only gate is D-3.
    let publish_called = Arc::new(AtomicBool::new(false));
    let block_beacon = Arc::new(BadProposerBlockBeacon {
        slot,
        bad_proposer_index: validator_index, // matching index → no H-4 drop
        publish_called: publish_called.clone(),
    });

    let mut key_manager = KeyManager::new();
    key_manager.insert(secret_key);
    let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
    let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
    let signer =
        Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

    let submitter = Arc::new(MockSubmitter::new());
    let propagator = Arc::new(Propagator::new(submitter));

    // Validator store with this validator DISABLED (doppelganger window).
    let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 0));
    {
        let mut config = validator_store::ValidatorConfig::new(pk_bytes);
        config.enabled = false;
        validator_store.add_validator(config);
    }

    let mut pubkey_map_inner = HashMap::new();
    pubkey_map_inner.insert(pubkey_hex, pubkey);
    let pubkey_map = Arc::new(parking_lot::RwLock::new(pubkey_map_inner));

    let clock = Arc::new(MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32));
    clock.set_slot(slot);

    let (orchestrator, _handle) = DutyOrchestrator::new(OrchestratorDeps::for_test(
        clock,
        duty_tracker,
        signer,
        propagator,
        beacon,
        block_beacon,
        None,
        validator_store,
        create_test_config(),
        pubkey_map,
    ));

    let ctx = SlotContext { slot, epoch, head_root: None };
    orchestrator.maybe_propose_block(slot, epoch, &ctx).await;

    // D-3: the block must NOT be proposed when is_signing_enabled=false.
    // publish_called stays false because the gate returns early before
    // block_service.propose_block (which would call produce_block_v3).
    assert!(
        !publish_called.load(Ordering::SeqCst),
        "D-3: block must NOT be proposed when is_signing_enabled=false"
    );
}
