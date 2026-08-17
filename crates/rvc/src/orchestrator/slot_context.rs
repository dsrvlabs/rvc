//! Slot-scoped context with two chain positions, captured at two times.
//!
//! `parent_root` is captured at t=0 via `get_block_root(slot - 1)` and is
//! the expected parent of a block proposed for this slot. `head_root` is
//! captured at phase 2 (t=slot/3) via the slot-qualified current slot and
//! reused at phase 3 so messages and contributions agree (H-5).
//!
//! Both queries are slot-qualified. The literal `"head"` block_id is not
//! used (L-5). Do not repair the t=0 query to return the current slot's
//! root: that value is never a valid parent of a slot-N block (ADR-003).

use tracing::warn;

use bn_manager::BeaconNodeClient;
use eth_types::{Epoch, Root, Slot};

use super::utils::parse_hex_root;

/// Per-slot chain context. `parent_root` and `head_root` are different
/// positions, captured at different times.
pub(crate) struct SlotContext {
    /// The slot this context was captured for.
    pub slot: Slot,
    /// The epoch this slot belongs to.
    pub epoch: Epoch,
    /// Parent of a block proposed for `slot`. Captured at t=0 from
    /// `get_block_root(slot - 1)`. `None` if that query failed.
    pub parent_root: Option<Root>,
    /// Canonical head as of phase 2. Captured once at t=slot/3 and reused
    /// at phase 3 (H-5). Left `None` at t=0 — a current-slot 404 then is
    /// the normal path, not an exception. `None` after phase 2 means the
    /// head query failed and sync duties skip.
    pub head_root: Option<Root>,
}

impl SlotContext {
    /// Captures `parent_root` at t=0 from `get_block_root(slot - 1)`.
    ///
    /// Walk-back over skipped slots is ARCH-3d. `head_root` stays `None`.
    pub(crate) async fn capture_parent(
        beacon: &dyn BeaconNodeClient,
        slot: Slot,
        epoch: Epoch,
    ) -> Self {
        let parent_slot = slot.saturating_sub(1);
        let parent_root = fetch_slot_qualified_root(beacon, &parent_slot.to_string(), slot).await;
        Self { slot, epoch, parent_root, head_root: None }
    }

    /// Captures `head_root` at phase 2 from the slot-qualified current slot.
    ///
    /// When that slot has no block yet (spec-conformant 404), the chain head
    /// is the parent already captured at t=0. Phase 3 must reuse this value
    /// and must not call this again.
    pub(crate) async fn capture_head(&mut self, beacon: &dyn BeaconNodeClient) {
        self.head_root = fetch_slot_qualified_root(beacon, &self.slot.to_string(), self.slot).await;
        if self.head_root.is_none() {
            self.head_root = self.parent_root;
        }
    }
}

async fn fetch_slot_qualified_root(
    beacon: &dyn BeaconNodeClient,
    block_id: &str,
    slot: Slot,
) -> Option<Root> {
    match beacon.get_block_root(block_id).await {
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
                "Failed to fetch block root for slot context"
            );
            None
        }
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

    /// Both captures must be slot-qualified — NOT the literal `"head"`.
    ///
    /// The mock returns distinct roots for `"head"` vs any other id; the
    /// assertions verify that neither capture used `"head"`.
    #[tokio::test]
    async fn test_capture_uses_slot_qualified_query() {
        let slot_root =
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let head_root =
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string();

        let beacon = slot_vs_head_beacon(slot_root.clone(), head_root);

        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;

        let mut ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);

        let expected = parse_hex_root(&slot_root).unwrap();
        assert_eq!(
            ctx.parent_root,
            Some(expected),
            "capture_parent must use slot-qualified slot-1, not 'head'"
        );
        assert!(ctx.head_root.is_none());

        ctx.capture_head(&beacon).await;
        assert_eq!(
            ctx.head_root,
            Some(expected),
            "capture_head must use slot-qualified current slot, not 'head'"
        );
    }

    /// When the beacon node returns an error, both roots stay `None` and
    /// the slot loop must not be aborted (no panic, no propagated error).
    #[tokio::test]
    async fn test_capture_handles_bn_error() {
        let beacon = error_beacon();

        let slot: Slot = 200;
        let epoch: Epoch = slot / 32;

        let mut ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);
        assert!(
            ctx.parent_root.is_none(),
            "BN error must yield parent_root = None, not a panic or propagated error"
        );
        assert!(ctx.head_root.is_none());

        ctx.capture_head(&beacon).await;
        assert!(
            ctx.head_root.is_none(),
            "BN error must yield head_root = None, not a panic or propagated error"
        );
    }

    /// ARCH-3a pin, kept after the 3c split (do not invert).
    ///
    /// A spec-conformant BN 404s `get_block_root(<current slot>)`. t=0
    /// `capture_parent` queries slot-1 and must leave `head_root` unset;
    /// the message phase on that t=0 context still produces **zero**
    /// messages. Messages after phase-2 `capture_head` are covered by
    /// `test_sync_messages_are_produced_when_bn_404s_the_current_slot`.
    /// Do not stuff a root into `head_root` at t=0 to make this test submit.
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
            .expect(0)
            .mount(&mock_server)
            .await;

        let parent_slot = slot - 1;
        let parent_hex = format!("0x{}", "11".repeat(32));
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/beacon/blocks/{parent_slot}/root")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "execution_optimistic": false,
                "finalized": false,
                "data": { "root": parent_hex }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Real HTTP client (not MockBeaconNodeClient): t=0 queries slot-1.
        let client =
            BeaconClient::new(BeaconClientConfig::new(mock_server.uri()).with_max_retries(0))
                .unwrap();
        let ctx = SlotContext::capture_parent(&client, slot, epoch).await;
        assert!(
            ctx.head_root.is_none(),
            "t=0 capture_parent must leave head_root unset even when slot-1 succeeds"
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

    /// t=0 `capture_parent` must leave `head_root` unset. A later
    /// `capture_head` fills it from the slot-qualified current slot — not
    /// by stuffing a parent into `head_root` at t=0.
    #[tokio::test]
    async fn test_capture_parent_leaves_head_unset_until_phase_two() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let parent_hex =
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let current_hex =
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let head_hex =
            "0x3333333333333333333333333333333333333333333333333333333333333333".to_string();

        let beacon = MockBeaconNodeClient::new().with_get_block_root({
            let parent_hex = parent_hex.clone();
            let current_hex = current_hex.clone();
            let head_hex = head_hex.clone();
            move |block_id| {
                let root = if block_id == "head" {
                    head_hex.clone()
                } else if block_id == slot.to_string() {
                    current_hex.clone()
                } else if block_id == (slot - 1).to_string() {
                    parent_hex.clone()
                } else {
                    return Err(beacon::BeaconError::HttpError(format!(
                        "unexpected block_id {block_id}"
                    )));
                };
                Ok(DataResponse { data: BlockRootData { root } })
            }
        });

        let mut ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;
        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);
        assert_eq!(
            ctx.parent_root,
            Some(parse_hex_root(&parent_hex).unwrap()),
            "t=0 must capture slot-1, not the current slot or \"head\""
        );
        assert!(
            ctx.head_root.is_none(),
            "t=0 must leave head_root unset; do not stuff a root into head_root at capture_parent"
        );

        ctx.capture_head(&beacon).await;
        assert_eq!(
            ctx.head_root,
            Some(parse_hex_root(&current_hex).unwrap()),
            "phase-2 capture_head must use the slot-qualified current slot, not \"head\""
        );
        assert_ne!(
            ctx.head_root, ctx.parent_root,
            "head and parent name different chain positions; copying parent is not capture_head"
        );
    }
}
