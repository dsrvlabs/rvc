//! Slot-scoped context captured once per slot in the coordinator.
//!
//! `SlotContext` is constructed at the start of phase 1 (t=0) and passed by
//! reference to attestation, block-proposal, and sync-committee phases. This
//! prevents TOCTOU races where independent fetches of the head block root can
//! observe different values across the slot's three phases (H-5).
//!
//! The head root is queried via `get_block_root(slot=current_slot)` rather
//! than the literal string `"head"`, incorporating the L-5 fix.

use tracing::warn;

use bn_manager::BeaconNodeClient;
use eth_types::{Epoch, Root, Slot};

use super::utils::parse_hex_root;

/// Immutable snapshot of chain context captured at slot start.
pub(crate) struct SlotContext {
    /// The slot this context was captured for.
    pub slot: Slot,
    /// The epoch this slot belongs to.
    pub epoch: Epoch,
    /// Head block root at slot start, queried slot-qualified (not `"head"`).
    ///
    /// `None` when the beacon node query failed; downstream phases handle
    /// this gracefully (e.g. sync committee skips signing without the root).
    pub head_root: Option<Root>,
}

impl SlotContext {
    /// Captures the slot context by querying the beacon node.
    ///
    /// Uses `get_block_root(slot=slot)` — **not** the literal `"head"` — to
    /// obtain a deterministic, slot-qualified root (L-5 fix rolled in here).
    ///
    /// On any BN error the context is returned with `head_root = None` so the
    /// slot loop can continue. The caller is responsible for handling `None`
    /// gracefully.
    pub(crate) async fn capture(beacon: &dyn BeaconNodeClient, slot: Slot, epoch: Epoch) -> Self {
        let block_id = slot.to_string();
        let head_root = match beacon.get_block_root(&block_id).await {
            Ok(response) => match parse_hex_root(&response.data.root) {
                Ok(root) => Some(root),
                Err(e) => {
                    warn!(slot, error = %e, "Failed to parse block root for slot context");
                    None
                }
            },
            Err(e) => {
                warn!(
                    slot,
                    error = %e,
                    "Failed to fetch block root for slot context; continuing without head_root"
                );
                None
            }
        };
        Self { slot, epoch, head_root }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon::{BlockRootData, DataResponse};
    use bn_manager::MockBeaconNodeClient;

    fn slot_vs_head_beacon(slot_root: String, head_root: String) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_block_root(move |block_id| {
            let root = if block_id == "head" { head_root.clone() } else { slot_root.clone() };
            Ok(DataResponse { data: BlockRootData { root } })
        })
    }

    fn error_beacon() -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_block_root(|_| {
            Err(beacon::BeaconError::HttpError("simulated BN error".to_string()))
        })
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// `SlotContext::capture` must use `get_block_root(slot=N)` — NOT `"head"`.
    ///
    /// The mock returns distinct roots for the two query forms; the assertion
    /// verifies that the slot-qualified root was captured.
    #[tokio::test]
    async fn test_capture_uses_slot_qualified_query() {
        let slot_root =
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let head_root =
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string();

        let beacon = slot_vs_head_beacon(slot_root.clone(), head_root);

        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;

        let ctx = SlotContext::capture(&beacon, slot, epoch).await;

        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);

        let expected = parse_hex_root(&slot_root).unwrap();
        assert_eq!(
            ctx.head_root,
            Some(expected),
            "capture must use slot-qualified query, not 'head'"
        );
    }

    /// When the beacon node returns an error, `head_root` must be `None` and
    /// the slot loop must not be aborted (no panic, no propagated error).
    #[tokio::test]
    async fn test_capture_handles_bn_error() {
        let beacon = error_beacon();

        let slot: Slot = 200;
        let epoch: Epoch = slot / 32;

        let ctx = SlotContext::capture(&beacon, slot, epoch).await;

        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);
        assert!(
            ctx.head_root.is_none(),
            "BN error must yield head_root = None, not a panic or propagated error"
        );
    }

    /// ARCH-3a defect pin (green against HEAD, red against intent).
    ///
    /// A spec-conformant BN 404s `get_block_root(<current slot>)` at t=0.
    /// Today's `capture` collapses that to `head_root = None`, and the
    /// sync-committee message phase therefore produces **zero** messages.
    ///
    /// ARCH-3c **replaces** this pin rather than inverting these assertions.
    /// The split keeps t=0 `head_root` unset (`capture_parent` / `slot-1`);
    /// messages are unblocked by a later phase-2 `capture_head`, covered by
    /// new 3c tests (`test_capture_parent_leaves_head_unset_until_phase_two`,
    /// `test_sync_messages_are_produced_when_bn_404s_the_current_slot`). Do
    /// not stuff a root into `head_root` at t=0 to make this test submit.
    #[tokio::test]
    async fn test_capture_yields_no_context_when_bn_404s_current_slot() {
        use std::sync::{Arc, Mutex};

        use beacon::{BeaconClient, BeaconClientConfig, ExecutionOptimisticResponse};
        use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
        use duty_tracker::DutyTracker;
        use eth_types::SyncCommitteeDuty;
        use signer::{always_enabled, SignerService};
        use slashing::SlashingDb;
        use validator_store::{ValidatorConfig, ValidatorStore};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::orchestrator::coordinator::tests::create_test_config;
        use crate::orchestrator::sync_committee::SyncCommitteeService;

        let slot: Slot = 1000;
        let epoch: Epoch = slot / 32;
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/beacon/blocks/{slot}/root")))
            .respond_with(ResponseTemplate::new(404).set_body_string(
                r#"{"code":404,"message":"NOT_FOUND: beacon block at slot 1000"}"#,
            ))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Real HTTP client (not MockBeaconNodeClient): 404 is what capture sees.
        let client =
            BeaconClient::new(BeaconClientConfig::new(mock_server.uri()).with_max_retries(0))
                .unwrap();
        let ctx = SlotContext::capture(&client, slot, epoch).await;
        assert!(
            ctx.head_root.is_none(),
            "spec-conformant 404 for the current slot must collapse to head_root = None"
        );

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let submitted = Arc::new(Mutex::new(Vec::<Root>::new()));
        let submitted_for_hook = Arc::clone(&submitted);
        let duty_pk = pk.to_bytes();

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties(move |_epoch, _indices| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                })
                .with_submit_sync_committee_messages(move |messages| {
                    submitted_for_hook
                        .lock()
                        .unwrap()
                        .extend(messages.iter().map(|m| m.beacon_block_root));
                    Ok(())
                }),
        );

        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        store.add_validator(ValidatorConfig::new(pk.to_bytes()));
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let signer = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                Arc::new(SlashingDb::open_in_memory().unwrap()),
            )
            .with_enablement(always_enabled()),
        );
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();
        assert!(
            !duty_tracker.get_sync_committee_duties(slot).await.is_empty(),
            "harness must have sync duties for slot {slot}; empty-duty skip is not this pin"
        );
        assert!(
            store.is_signing_enabled(&pk.to_bytes()),
            "harness validator must be signing-enabled"
        );

        let mut map = std::collections::HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let service = SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            create_test_config(),
            store,
        );

        service.maybe_produce_sync_messages(slot, epoch, &ctx).await;
        assert!(
            submitted.lock().unwrap().is_empty(),
            "ARCH-3a defect: capture 404 → head_root=None → zero sync committee messages"
        );
    }
}
