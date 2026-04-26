use eth_types::{BeaconBlock, BlindedBeaconBlock, Root, Slot};

use crate::BlockServiceError;

/// Validates a beacon block returned by the BN against the proposer duty.
///
/// Checks:
/// - `proposer_index` matches the expected duty validator index (H-4).
/// - `parent_root` matches the expected head root when provided (H-4).
///
/// Both `validate_full` (unblinded) and `validate_blinded` paths apply the same
/// logic so the builder and non-builder code paths are symmetric.
pub(crate) struct BlockResponseValidator {
    pub expected_proposer_index: u64,
    pub expected_parent_root: Option<Root>,
    pub expected_slot: Slot,
}

impl BlockResponseValidator {
    /// Validate an unblinded [`BeaconBlock`] returned from the beacon node.
    pub fn validate_full(&self, block: &BeaconBlock) -> Result<(), BlockServiceError> {
        self.check_slot(block.slot)?;
        self.check_proposer_index(block.proposer_index)?;
        self.check_parent_root(block.parent_root)?;
        Ok(())
    }

    /// Validate a blinded [`BlindedBeaconBlock`] returned from the beacon node.
    pub fn validate_blinded(&self, block: &BlindedBeaconBlock) -> Result<(), BlockServiceError> {
        self.check_slot(block.slot)?;
        self.check_proposer_index(block.proposer_index)?;
        self.check_parent_root(block.parent_root)?;
        Ok(())
    }

    fn check_slot(&self, got: Slot) -> Result<(), BlockServiceError> {
        if got != self.expected_slot {
            return Err(BlockServiceError::SlotMismatch { requested: self.expected_slot, got });
        }
        Ok(())
    }

    fn check_proposer_index(&self, got: u64) -> Result<(), BlockServiceError> {
        if got != self.expected_proposer_index {
            return Err(BlockServiceError::ProposerIndexMismatch {
                expected: self.expected_proposer_index,
                got,
            });
        }
        Ok(())
    }

    fn check_parent_root(&self, got: Root) -> Result<(), BlockServiceError> {
        if let Some(expected) = self.expected_parent_root {
            if got != expected {
                return Err(BlockServiceError::ParentRootMismatch { expected, got });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{BeaconBlock, BlindedBeaconBlock};

    fn full_block(proposer_index: u64, parent_root: Root) -> BeaconBlock {
        BeaconBlock { slot: 100, proposer_index, parent_root, state_root: [0u8; 32], body: vec![] }
    }

    fn blinded_block(proposer_index: u64, parent_root: Root) -> BlindedBeaconBlock {
        BlindedBeaconBlock {
            slot: 100,
            proposer_index,
            parent_root,
            state_root: [0u8; 32],
            body: vec![],
        }
    }

    fn validator(
        expected_proposer_index: u64,
        expected_parent_root: Option<Root>,
    ) -> BlockResponseValidator {
        BlockResponseValidator { expected_proposer_index, expected_parent_root, expected_slot: 100 }
    }

    // --- Full block tests: slot ---

    #[test]
    fn test_slot_mismatch_rejected() {
        // validator expects slot 100, block has slot 101
        let v = BlockResponseValidator {
            expected_proposer_index: 42,
            expected_parent_root: None,
            expected_slot: 100,
        };
        let mut block = full_block(42, [0u8; 32]);
        block.slot = 101;
        let result = v.validate_full(&block);
        assert!(matches!(
            result,
            Err(BlockServiceError::SlotMismatch { requested: 100, got: 101 })
        ));
    }

    #[test]
    fn test_slot_checked_before_proposer_index() {
        // When both slot and proposer_index are wrong, slot error comes first
        let v = BlockResponseValidator {
            expected_proposer_index: 42,
            expected_parent_root: None,
            expected_slot: 100,
        };
        let mut block = full_block(99, [0u8; 32]); // wrong proposer_index
        block.slot = 200; // also wrong slot
        let result = v.validate_full(&block);
        assert!(matches!(result, Err(BlockServiceError::SlotMismatch { .. })));
    }

    // --- Full block tests: proposer_index ---

    #[test]
    fn test_proposer_index_mismatch_rejected() {
        let v = validator(42, None);
        let block = full_block(43, [0u8; 32]);
        let result = v.validate_full(&block);
        assert!(matches!(
            result,
            Err(BlockServiceError::ProposerIndexMismatch { expected: 42, got: 43 })
        ));
    }

    #[test]
    fn test_proposer_index_match_accepted() {
        let v = validator(42, None);
        let block = full_block(42, [0u8; 32]);
        assert!(v.validate_full(&block).is_ok());
    }

    #[test]
    fn test_parent_root_mismatch_rejected() {
        let expected_root: Root = [1u8; 32];
        let actual_root: Root = [2u8; 32];
        let v = validator(42, Some(expected_root));
        let block = full_block(42, actual_root);
        let result = v.validate_full(&block);
        assert!(matches!(
            result,
            Err(BlockServiceError::ParentRootMismatch { expected, got })
            if expected == expected_root && got == actual_root
        ));
    }

    #[test]
    fn test_parent_root_none_skips_check() {
        let v = validator(42, None);
        // Any parent_root is fine when expected is None
        let block = full_block(42, [0xff; 32]);
        assert!(v.validate_full(&block).is_ok());
    }

    #[test]
    fn test_parent_root_match_accepted() {
        let root: Root = [5u8; 32];
        let v = validator(42, Some(root));
        let block = full_block(42, root);
        assert!(v.validate_full(&block).is_ok());
    }

    #[test]
    fn test_proposer_index_checked_before_parent_root() {
        // When both are wrong, proposer_index error is returned first
        let v = validator(42, Some([1u8; 32]));
        let block = full_block(99, [2u8; 32]);
        let result = v.validate_full(&block);
        assert!(matches!(result, Err(BlockServiceError::ProposerIndexMismatch { .. })));
    }

    // --- Blinded block tests ---

    #[test]
    fn test_blinded_validation_symmetric_proposer_mismatch() {
        let v = validator(42, None);
        let block = blinded_block(43, [0u8; 32]);
        let result = v.validate_blinded(&block);
        assert!(matches!(
            result,
            Err(BlockServiceError::ProposerIndexMismatch { expected: 42, got: 43 })
        ));
    }

    #[test]
    fn test_blinded_validation_symmetric_parent_root_mismatch() {
        let expected_root: Root = [1u8; 32];
        let actual_root: Root = [3u8; 32];
        let v = validator(42, Some(expected_root));
        let block = blinded_block(42, actual_root);
        let result = v.validate_blinded(&block);
        assert!(matches!(
            result,
            Err(BlockServiceError::ParentRootMismatch { expected, got })
            if expected == expected_root && got == actual_root
        ));
    }

    #[test]
    fn test_blinded_validation_symmetric_none_skips_parent_check() {
        let v = validator(42, None);
        let block = blinded_block(42, [0xff; 32]);
        assert!(v.validate_blinded(&block).is_ok());
    }

    #[test]
    fn test_blinded_validation_symmetric_all_match() {
        let root: Root = [7u8; 32];
        let v = validator(42, Some(root));
        let block = blinded_block(42, root);
        assert!(v.validate_blinded(&block).is_ok());
    }
}
