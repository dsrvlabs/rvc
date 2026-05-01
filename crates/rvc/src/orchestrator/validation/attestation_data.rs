//! Local sanity checks for [`AttestationData`] received from the beacon node.
//!
//! A confused or malicious BN may return attestation data that violates basic
//! protocol invariants.  Running these checks before signing prevents the
//! validator from producing a slashable or invalid attestation.
//!
//! # Checks (M-2)
//!
//! 1. `target.epoch == data.slot / SLOTS_PER_EPOCH` — the target epoch must be
//!    consistent with the slot.
//! 2. `source.epoch <= target.epoch` — the source checkpoint cannot be after
//!    the target.
//! 3. `data.slot` is within ±2 slots of `current_clock_slot` — guards against
//!    far-future or far-past attestation data caused by BN clock skew or a
//!    malicious BN.

use eth_types::{AttestationData, Epoch, Slot, SLOTS_PER_EPOCH};
use thiserror::Error;

/// Errors emitted by [`validate_attestation_data`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestationServiceError {
    #[error(
        "target epoch mismatch: slot {slot} is in epoch {expected_epoch}, \
         but target.epoch = {got_epoch}"
    )]
    TargetEpochMismatch { slot: Slot, expected_epoch: Epoch, got_epoch: Epoch },

    #[error(
        "source epoch {source_epoch} is after target epoch {target_epoch}: \
         impossible checkpoint ordering"
    )]
    SourceAfterTarget { source_epoch: Epoch, target_epoch: Epoch },

    #[error(
        "attestation slot {data_slot} is outside the ±2-slot window of \
         local clock slot {clock_slot}"
    )]
    SlotOutOfWindow { data_slot: Slot, clock_slot: Slot },
}

/// Validates [`AttestationData`] fetched from the beacon node before signing.
///
/// Returns `Ok(())` when all invariants hold, or the first violated invariant
/// as an [`AttestationServiceError`].
///
/// # Parameters
///
/// * `data` — the [`AttestationData`] returned by `produce_attestation_data`.
/// * `expected_slot` — the duty slot the BN was asked to produce data for;
///   used to anchor the target-epoch consistency check.
/// * `current_clock_slot` — the local slot clock's view of the current slot;
///   used for the ±2-slot window check.
pub fn validate_attestation_data(
    data: &AttestationData,
    expected_slot: Slot,
    current_clock_slot: Slot,
) -> Result<(), AttestationServiceError> {
    // Check 1: target.epoch must equal data.slot / SLOTS_PER_EPOCH.
    // We derive the expected epoch from the duty slot, not from data.slot, so
    // a BN that returns an inconsistent (slot, target.epoch) pair is rejected.
    let expected_target_epoch = expected_slot / SLOTS_PER_EPOCH;
    if data.target.epoch != expected_target_epoch {
        return Err(AttestationServiceError::TargetEpochMismatch {
            slot: data.slot,
            expected_epoch: expected_target_epoch,
            got_epoch: data.target.epoch,
        });
    }

    // Check 2: source.epoch <= target.epoch.
    if data.source.epoch > data.target.epoch {
        return Err(AttestationServiceError::SourceAfterTarget {
            source_epoch: data.source.epoch,
            target_epoch: data.target.epoch,
        });
    }

    // Check 3: data.slot within ±2 slots of the local clock.
    let lower = current_clock_slot.saturating_sub(2);
    let upper = current_clock_slot.saturating_add(2);
    if data.slot < lower || data.slot > upper {
        return Err(AttestationServiceError::SlotOutOfWindow {
            data_slot: data.slot,
            clock_slot: current_clock_slot,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::Checkpoint;

    fn make_data(slot: u64, target_epoch: u64, source_epoch: u64) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: [0u8; 32],
            source: Checkpoint { epoch: source_epoch, root: [0u8; 32] },
            target: Checkpoint { epoch: target_epoch, root: [1u8; 32] },
        }
    }

    fn valid(slot: u64) -> AttestationData {
        let epoch = slot / SLOTS_PER_EPOCH;
        let source = if epoch > 0 { epoch - 1 } else { 0 };
        make_data(slot, epoch, source)
    }

    // ── Check 1: target.epoch == expected_slot / SLOTS_PER_EPOCH ─────────────

    #[test]
    fn test_target_epoch_mismatch_rejected() {
        let slot = 64u64; // epoch 2
        let mut data = valid(slot);
        data.target.epoch = 5; // wrong — BN returned epoch 5 instead of 2
        assert!(matches!(
            validate_attestation_data(&data, slot, slot),
            Err(AttestationServiceError::TargetEpochMismatch {
                expected_epoch: 2,
                got_epoch: 5,
                ..
            })
        ));
    }

    #[test]
    fn test_target_epoch_match_accepted() {
        let slot = 64u64; // epoch 2
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, slot).is_ok());
    }

    #[test]
    fn test_target_epoch_boundary_slot_accepted() {
        // First slot of an epoch (slot 32 → epoch 1)
        let slot = 32u64;
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, slot).is_ok());
    }

    #[test]
    fn test_target_epoch_last_slot_of_epoch_accepted() {
        // Last slot of epoch 1 (slot 63 → epoch 1)
        let slot = 63u64;
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, slot).is_ok());
    }

    // ── Check 2: source.epoch <= target.epoch ────────────────────────────────

    #[test]
    fn test_source_after_target_rejected() {
        let slot = 96u64; // epoch 3
        let mut data = valid(slot);
        data.source.epoch = data.target.epoch + 1; // impossible
        assert!(matches!(
            validate_attestation_data(&data, slot, slot),
            Err(AttestationServiceError::SourceAfterTarget { .. })
        ));
    }

    #[test]
    fn test_source_equal_to_target_accepted() {
        let slot = 96u64; // epoch 3
        let mut data = valid(slot);
        data.source.epoch = data.target.epoch; // source == target is valid (genesis)
        assert!(validate_attestation_data(&data, slot, slot).is_ok());
    }

    #[test]
    fn test_source_before_target_accepted() {
        let slot = 96u64;
        let data = valid(slot); // source = epoch - 1 < target
        assert!(validate_attestation_data(&data, slot, slot).is_ok());
    }

    // ── Check 3: data.slot within ±2 of current_clock_slot ──────────────────

    #[test]
    fn test_slot_within_window_accepted_exact() {
        let slot = 100u64;
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, slot).is_ok());
    }

    #[test]
    fn test_slot_within_window_plus_one_accepted() {
        let slot = 101u64;
        let clock = 100u64;
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, clock).is_ok());
    }

    #[test]
    fn test_slot_within_window_plus_two_accepted() {
        let slot = 102u64;
        let clock = 100u64;
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, clock).is_ok());
    }

    #[test]
    fn test_slot_within_window_minus_two_accepted() {
        let slot = 98u64;
        let clock = 100u64;
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, clock).is_ok());
    }

    #[test]
    fn test_slot_far_from_clock_rejected() {
        let clock = 100u64;
        let far_slot = clock + 100;
        let data = valid(far_slot);
        assert!(matches!(
            validate_attestation_data(&data, far_slot, clock),
            Err(AttestationServiceError::SlotOutOfWindow { data_slot: 200, clock_slot: 100 })
        ));
    }

    #[test]
    fn test_slot_three_ahead_rejected() {
        let clock = 100u64;
        let slot = clock + 3; // just outside the +2 window
        let data = valid(slot);
        assert!(matches!(
            validate_attestation_data(&data, slot, clock),
            Err(AttestationServiceError::SlotOutOfWindow { .. })
        ));
    }

    #[test]
    fn test_slot_three_behind_rejected() {
        let clock = 100u64;
        let slot = clock - 3;
        let data = valid(slot);
        assert!(matches!(
            validate_attestation_data(&data, slot, clock),
            Err(AttestationServiceError::SlotOutOfWindow { .. })
        ));
    }

    #[test]
    fn test_slot_window_saturates_at_zero() {
        // clock_slot = 1; slot = 0 is within the window (1 - 2 saturates to 0)
        let clock = 1u64;
        let slot = 0u64;
        let data = valid(slot);
        assert!(validate_attestation_data(&data, slot, clock).is_ok());
    }
}
