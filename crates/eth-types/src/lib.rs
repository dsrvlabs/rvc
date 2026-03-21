use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

mod aggregation;
mod attestation;
mod block;
mod builder;
mod deposit;
mod domains;
mod duties;
mod fork;
pub(crate) mod hex_fixed;
pub(crate) mod serde_signature;
mod sync_committee;
pub(crate) mod tree_hash_utils;
pub use aggregation::{
    AggregateAndProof, Attestation, ElectraAggregateAndProof, ElectraAttestation,
    SignedAggregateAndProof, SignedElectraAggregateAndProof,
};
pub use attestation::SingleAttestation;
pub use block::{
    BeaconBlock, BeaconBlockBody, BlindedBeaconBlock, BlindedBeaconBlockBody, BlobSidecar,
    BlockContents, ProducedBlock, SignedBeaconBlock, SignedBlindedBeaconBlock,
};
pub use builder::{SignedValidatorRegistration, ValidatorRegistrationV1};
pub use deposit::{BLSToExecutionChange, DepositData, DepositMessage, SignedBLSToExecutionChange};
pub use domains::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_DEPOSIT, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
pub use duties::{ProposerDuty, SignedVoluntaryExit, VoluntaryExit};
pub use fork::{ForkName, ForkSchedule};
pub use sync_committee::{
    ContributionAndProof, SignedContributionAndProof, SyncAggregatorSelectionData,
    SyncCommitteeContribution, SyncCommitteeDuty, SyncCommitteeMessage,
};
pub use tree_hash_utils::TreeHashError;

pub type Slot = u64;
pub type Epoch = u64;
pub type CommitteeIndex = u64;
pub type Version = [u8; 4];
pub type Root = [u8; 32];
pub type Domain = [u8; 32];
pub type DomainType = [u8; 4];
pub type Signature = Vec<u8>;

/// Expected length of a BLS signature in bytes.
pub const SIGNATURE_BYTES_LEN: usize = 96;

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SECONDS_PER_SLOT: u64 = 12;
pub const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;

/// Consensus specification version this client implements.
pub const CONSENSUS_SPEC_VERSION: &str = "v1.5.0-alpha.12";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: Epoch,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct AttestationData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: CommitteeIndex,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub beacon_block_root: Root,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Fork {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub previous_version: Version,
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: Version,
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ForkData {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: Version,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub genesis_validators_root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SigningData {
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub object_root: Root,
    #[serde(with = "hex_fixed::bytes_32_hex")]
    pub domain: Domain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

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

    #[test]
    fn test_checkpoint_quoted_epoch_serialization() {
        let checkpoint = Checkpoint { epoch: 100, root: [0u8; 32] };
        let json = serde_json::to_string(&checkpoint).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["epoch"], serde_json::Value::String("100".to_string()));
    }

    #[test]
    fn test_checkpoint_root_hex_serialization() {
        let checkpoint = Checkpoint { epoch: 100, root: [0xab; 32] };
        let json = serde_json::to_string(&checkpoint).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected_hex = format!("0x{}", "ab".repeat(32));
        assert_eq!(parsed["root"], serde_json::Value::String(expected_hex));
    }

    #[test]
    fn test_checkpoint_root_hex_deserialization() {
        let hex_root = format!("0x{}", "ab".repeat(32));
        let json = format!(r#"{{"epoch":"100","root":"{}"}}"#, hex_root);
        let checkpoint: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(checkpoint.epoch, 100);
        assert_eq!(checkpoint.root, [0xab; 32]);
    }

    #[test]
    fn test_checkpoint_json_roundtrip() {
        let original = Checkpoint { epoch: 42, root: [0xab; 32] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_attestation_data_quoted_integers_serialization() {
        let data = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let json = serde_json::to_string(&data).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("1000".to_string()));
        assert_eq!(parsed["index"], serde_json::Value::String("5".to_string()));
        assert_eq!(parsed["source"]["epoch"], serde_json::Value::String("99".to_string()));
        assert_eq!(parsed["target"]["epoch"], serde_json::Value::String("100".to_string()));
    }

    #[test]
    fn test_attestation_data_json_roundtrip() {
        let original = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: AttestationData = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_fork_quoted_epoch_serialization() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let json = serde_json::to_string(&fork).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["epoch"], serde_json::Value::String("100".to_string()));
    }

    #[test]
    fn test_fork_json_roundtrip() {
        let original =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Fork = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_fork_version_hex_serialization() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let json = serde_json::to_string(&fork).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["previous_version"], serde_json::Value::String("0x00000000".to_string()));
        assert_eq!(parsed["current_version"], serde_json::Value::String("0x01000000".to_string()));
    }

    #[test]
    fn test_checkpoint_ssz_unaffected_by_serde() {
        let checkpoint = Checkpoint { epoch: 100, root: [0u8; 32] };
        let encoded = checkpoint.as_ssz_bytes();
        assert_eq!(encoded.len(), 8 + 32);
        let decoded = Checkpoint::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(checkpoint, decoded);
    }

    #[test]
    fn test_attestation_data_ssz_unaffected_by_serde() {
        let data = AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [1u8; 32],
            source: Checkpoint { epoch: 99, root: [2u8; 32] },
            target: Checkpoint { epoch: 100, root: [3u8; 32] },
        };
        let encoded = data.as_ssz_bytes();
        let decoded = AttestationData::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_fork_ssz_unaffected_by_serde() {
        let fork =
            Fork { previous_version: [0, 0, 0, 0], current_version: [1, 0, 0, 0], epoch: 100 };
        let encoded = fork.as_ssz_bytes();
        let decoded = Fork::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(fork, decoded);
    }

    #[test]
    fn test_consensus_spec_version_exists_and_starts_with_v() {
        assert!(CONSENSUS_SPEC_VERSION.starts_with('v'));
    }

    #[test]
    fn test_consensus_spec_version_value() {
        assert_eq!(CONSENSUS_SPEC_VERSION, "v1.5.0-alpha.12");
    }
}
