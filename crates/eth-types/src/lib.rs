use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

pub type Slot = u64;
pub type Epoch = u64;
pub type CommitteeIndex = u64;
pub type Version = [u8; 4];
pub type Root = [u8; 32];
pub type Domain = [u8; 32];
pub type DomainType = [u8; 4];

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SECONDS_PER_SLOT: u64 = 12;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash)]
pub struct AttestationData {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub beacon_block_root: Root,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    pub epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash)]
pub struct ForkData {
    pub current_version: Version,
    pub genesis_validators_root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TreeHash)]
pub struct SigningData {
    pub object_root: Root,
    pub domain: Domain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode;

    #[test]
    fn test_checkpoint_ssz_encode() {
        let checkpoint = Checkpoint { epoch: 100, root: [0u8; 32] };
        let encoded = checkpoint.as_ssz_bytes();
        assert_eq!(encoded.len(), 8 + 32);
    }

    #[test]
    fn test_attestation_data_ssz_encode() {
        let data = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let encoded = data.as_ssz_bytes();
        assert_eq!(encoded.len(), 8 + 8 + 32 + 40 + 40);
    }

    #[test]
    fn test_fork_ssz_encode() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let encoded = fork.as_ssz_bytes();
        assert_eq!(encoded.len(), 4 + 4 + 8);
    }

    #[test]
    fn test_fork_data_ssz_encode() {
        let fork_data =
            ForkData { current_version: [1, 0, 0, 0], genesis_validators_root: [0u8; 32] };
        let encoded = fork_data.as_ssz_bytes();
        assert_eq!(encoded.len(), 4 + 32);
    }

    #[test]
    fn test_signing_data_ssz_encode() {
        let signing_data = SigningData { object_root: [0u8; 32], domain: [1u8; 32] };
        let encoded = signing_data.as_ssz_bytes();
        assert_eq!(encoded.len(), 32 + 32);
    }

    #[test]
    fn test_slots_per_epoch() {
        assert_eq!(SLOTS_PER_EPOCH, 32);
    }

    #[test]
    fn test_seconds_per_slot() {
        assert_eq!(SECONDS_PER_SLOT, 12);
    }
}
