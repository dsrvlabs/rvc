use serde::{Deserialize, Serialize};

use crate::{Root, Signature, Slot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeMessage {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeDuty {
    pub pubkey: String,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub validator_sync_committee_indices: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeContribution {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
    pub aggregation_bits: Vec<u8>,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub contribution: SyncCommitteeContribution,
    pub selection_proof: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContributionAndProof {
    pub message: ContributionAndProof,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sync_committee_message() -> SyncCommitteeMessage {
        SyncCommitteeMessage {
            slot: 100,
            beacon_block_root: [1u8; 32],
            validator_index: 42,
            signature: vec![0xaa; 96],
        }
    }

    fn sample_sync_committee_duty() -> SyncCommitteeDuty {
        SyncCommitteeDuty {
            pubkey: "0xabcd".to_string(),
            validator_index: 42,
            validator_sync_committee_indices: vec![0, 128, 256],
        }
    }

    fn sample_contribution() -> SyncCommitteeContribution {
        SyncCommitteeContribution {
            slot: 100,
            beacon_block_root: [1u8; 32],
            subcommittee_index: 2,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xbb; 96],
        }
    }

    fn sample_contribution_and_proof() -> ContributionAndProof {
        ContributionAndProof {
            aggregator_index: 42,
            contribution: sample_contribution(),
            selection_proof: vec![0xcc; 96],
        }
    }

    #[test]
    fn test_sync_committee_message_serde_roundtrip() {
        let msg = sample_sync_committee_message();
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: SyncCommitteeMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_sync_committee_message_quoted_integers() {
        let msg = sample_sync_committee_message();
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_sync_committee_duty_serde_roundtrip() {
        let duty = sample_sync_committee_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let deserialized: SyncCommitteeDuty = serde_json::from_str(&json).unwrap();
        assert_eq!(duty, deserialized);
    }

    #[test]
    fn test_sync_committee_duty_quoted_validator_index() {
        let duty = sample_sync_committee_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_sync_committee_duty_empty_indices() {
        let duty = SyncCommitteeDuty {
            pubkey: "0x1234".to_string(),
            validator_index: 0,
            validator_sync_committee_indices: vec![],
        };
        let json = serde_json::to_string(&duty).unwrap();
        let deserialized: SyncCommitteeDuty = serde_json::from_str(&json).unwrap();
        assert_eq!(duty, deserialized);
    }

    #[test]
    fn test_sync_committee_contribution_serde_roundtrip() {
        let contribution = sample_contribution();
        let json = serde_json::to_string(&contribution).unwrap();
        let deserialized: SyncCommitteeContribution = serde_json::from_str(&json).unwrap();
        assert_eq!(contribution, deserialized);
    }

    #[test]
    fn test_sync_committee_contribution_quoted_integers() {
        let contribution = sample_contribution();
        let json = serde_json::to_string(&contribution).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["subcommittee_index"], serde_json::Value::String("2".to_string()));
    }

    #[test]
    fn test_contribution_and_proof_serde_roundtrip() {
        let proof = sample_contribution_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: ContributionAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_contribution_and_proof_quoted_aggregator_index() {
        let proof = sample_contribution_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["aggregator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_signed_contribution_and_proof_serde_roundtrip() {
        let signed = SignedContributionAndProof {
            message: sample_contribution_and_proof(),
            signature: vec![0xdd; 96],
        };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedContributionAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }
}
