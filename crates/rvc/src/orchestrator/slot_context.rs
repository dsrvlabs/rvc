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
}
