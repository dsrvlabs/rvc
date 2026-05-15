use serde::{Deserialize, Serialize};
use tree_hash::{Hash256, MerkleHasher, TreeHash, TreeHashType};

use crate::hex_fixed::bytes_32_hex;
use crate::tree_hash_utils::vec_u8_tree_hash_root;
use crate::{Root, Signature, Slot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeMessage {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "bytes_32_hex")]
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeDuty {
    pub pubkey: String,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub validator_sync_committee_indices: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeContribution {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "bytes_32_hex")]
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
    #[serde(with = "serde_utils::hex_vec")]
    pub aggregation_bits: Vec<u8>,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

impl TreeHash for SyncCommitteeContribution {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("containers cannot be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        let mut hasher = MerkleHasher::with_leaves(5);
        hasher.write(self.slot.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.beacon_block_root.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.subcommittee_index.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(vec_u8_tree_hash_root(&self.aggregation_bits).as_slice()).expect("valid leaf");
        hasher.write(vec_u8_tree_hash_root(&self.signature).as_slice()).expect("valid leaf");
        hasher.finish().expect("valid root")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregatorSelectionData {
    pub slot: Slot,
    pub subcommittee_index: u64,
}

impl TreeHash for SyncAggregatorSelectionData {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("containers cannot be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        let mut hasher = MerkleHasher::with_leaves(2);
        hasher.write(self.slot.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.subcommittee_index.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.finish().expect("valid root")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub contribution: SyncCommitteeContribution,
    #[serde(with = "crate::serde_signature")]
    pub selection_proof: Signature,
}

impl TreeHash for ContributionAndProof {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("containers cannot be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        let mut hasher = MerkleHasher::with_leaves(3);
        hasher.write(self.aggregator_index.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.contribution.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(vec_u8_tree_hash_root(&self.selection_proof).as_slice()).expect("valid leaf");
        hasher.finish().expect("valid root")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContributionAndProof {
    pub message: ContributionAndProof,
    #[serde(with = "crate::serde_signature")]
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
    fn test_sync_committee_duty_quoted_indices() {
        let duty = sample_sync_committee_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let indices = parsed["validator_sync_committee_indices"].as_array().unwrap();
        assert_eq!(indices[0], serde_json::Value::String("0".to_string()));
        assert_eq!(indices[1], serde_json::Value::String("128".to_string()));
        assert_eq!(indices[2], serde_json::Value::String("256".to_string()));
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

    // -- TreeHash tests (Finding #20) --

    #[test]
    fn test_sync_committee_contribution_tree_hash_deterministic() {
        let contrib = sample_contribution();
        let hash1 = contrib.tree_hash_root();
        let hash2 = contrib.tree_hash_root();
        assert_eq!(hash1, hash2, "tree hash must be deterministic for identical input");
    }

    #[test]
    fn test_sync_committee_contribution_tree_hash_field_sensitivity_slot() {
        let contrib1 = sample_contribution();
        let mut contrib2 = contrib1.clone();
        contrib2.slot += 1;
        assert_ne!(
            contrib1.tree_hash_root(),
            contrib2.tree_hash_root(),
            "different slot must produce different tree hash"
        );
    }

    #[test]
    fn test_sync_committee_contribution_tree_hash_field_sensitivity_subcommittee() {
        let contrib1 = sample_contribution();
        let mut contrib2 = contrib1.clone();
        contrib2.subcommittee_index += 1;
        assert_ne!(
            contrib1.tree_hash_root(),
            contrib2.tree_hash_root(),
            "different subcommittee_index must produce different tree hash"
        );
    }

    #[test]
    fn test_sync_committee_contribution_tree_hash_field_sensitivity_block_root() {
        let contrib1 = sample_contribution();
        let mut contrib2 = contrib1.clone();
        contrib2.beacon_block_root = [2u8; 32];
        assert_ne!(
            contrib1.tree_hash_root(),
            contrib2.tree_hash_root(),
            "different beacon_block_root must produce different tree hash"
        );
    }

    #[test]
    fn test_sync_committee_contribution_tree_hash_leaf_count() {
        use crate::tree_hash_utils::vec_u8_tree_hash_root;

        let contrib = sample_contribution();
        let actual_hash = contrib.tree_hash_root();

        // Manually compute with 5 leaves to lock in the correct leaf count
        let mut hasher = MerkleHasher::with_leaves(5);
        hasher.write(contrib.slot.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.beacon_block_root.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.subcommittee_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&contrib.aggregation_bits).as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&contrib.signature).as_slice()).unwrap();
        let expected_hash = hasher.finish().unwrap();

        assert_eq!(
            actual_hash, expected_hash,
            "tree_hash_root must match manual computation with 5 leaves"
        );
    }

    #[test]
    fn test_sync_committee_contribution_wrong_leaf_count_differs() {
        use crate::tree_hash_utils::vec_u8_tree_hash_root;

        let contrib = sample_contribution();
        let correct_hash = contrib.tree_hash_root();

        // Compute with wrong leaf count (4 instead of 5) — must produce a different hash.
        // with_leaves(4) only accepts 4 writes, so the 5th write will error.
        // This proves the leaf count matters: changing with_leaves(5) to with_leaves(4)
        // would break the implementation.
        let mut hasher = MerkleHasher::with_leaves(4);
        hasher.write(contrib.slot.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.beacon_block_root.tree_hash_root().as_slice()).unwrap();
        hasher.write(contrib.subcommittee_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&contrib.aggregation_bits).as_slice()).unwrap();
        // 5th write would fail with 4 leaves — the hash from 4 leaves differs from 5
        let wrong_hash = hasher.finish().unwrap();

        assert_ne!(
            correct_hash, wrong_hash,
            "with_leaves(4) must produce different hash than with_leaves(5)"
        );
    }

    #[test]
    fn test_contribution_and_proof_tree_hash_deterministic() {
        let proof = sample_contribution_and_proof();
        let hash1 = proof.tree_hash_root();
        let hash2 = proof.tree_hash_root();
        assert_eq!(hash1, hash2, "ContributionAndProof tree hash must be deterministic");
    }

    #[test]
    fn test_contribution_and_proof_tree_hash_field_sensitivity() {
        let proof1 = sample_contribution_and_proof();
        let mut proof2 = proof1.clone();
        proof2.aggregator_index += 1;
        assert_ne!(
            proof1.tree_hash_root(),
            proof2.tree_hash_root(),
            "different aggregator_index must produce different tree hash"
        );
    }

    #[test]
    fn test_contribution_and_proof_tree_hash_leaf_count() {
        use crate::tree_hash_utils::vec_u8_tree_hash_root;

        let proof = sample_contribution_and_proof();
        let actual_hash = proof.tree_hash_root();

        // Manually compute with 3 leaves to lock in the correct leaf count
        let mut hasher = MerkleHasher::with_leaves(3);
        hasher.write(proof.aggregator_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(proof.contribution.tree_hash_root().as_slice()).unwrap();
        hasher.write(vec_u8_tree_hash_root(&proof.selection_proof).as_slice()).unwrap();
        let expected_hash = hasher.finish().unwrap();

        assert_eq!(
            actual_hash, expected_hash,
            "tree_hash_root must match manual computation with 3 leaves"
        );
    }

    #[test]
    fn test_contribution_and_proof_wrong_leaf_count_differs() {
        let proof = sample_contribution_and_proof();
        let correct_hash = proof.tree_hash_root();

        // Compute with wrong leaf count (2 instead of 3) — must produce different hash
        let mut hasher = MerkleHasher::with_leaves(2);
        hasher.write(proof.aggregator_index.tree_hash_root().as_slice()).unwrap();
        hasher.write(proof.contribution.tree_hash_root().as_slice()).unwrap();
        let wrong_hash = hasher.finish().unwrap();

        assert_ne!(
            correct_hash, wrong_hash,
            "with_leaves(2) must produce different hash than with_leaves(3)"
        );
    }
}
