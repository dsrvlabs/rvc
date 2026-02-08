use serde::{Deserialize, Serialize};
use tree_hash::{Hash256, MerkleHasher, TreeHash, TreeHashType};

use crate::{AttestationData, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(with = "serde_utils::hex_vec")]
    pub aggregation_bits: Vec<u8>,
    pub data: AttestationData,
    #[serde(with = "serde_utils::hex_vec")]
    pub signature: Signature,
}

impl TreeHash for Attestation {
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
        hasher.write(vec_u8_tree_hash_root(&self.aggregation_bits).as_slice()).expect("valid leaf");
        hasher.write(self.data.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(vec_u8_tree_hash_root(&self.signature).as_slice()).expect("valid leaf");
        hasher.finish().expect("valid root")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: Attestation,
    #[serde(with = "serde_utils::hex_vec")]
    pub selection_proof: Signature,
}

impl TreeHash for AggregateAndProof {
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
        hasher.write(self.aggregate.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(vec_u8_tree_hash_root(&self.selection_proof).as_slice()).expect("valid leaf");
        hasher.finish().expect("valid root")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    #[serde(with = "serde_utils::hex_vec")]
    pub signature: Signature,
}

fn vec_u8_tree_hash_root(bytes: &[u8]) -> Hash256 {
    let num_leaves = bytes.len().div_ceil(32);
    let mut hasher = MerkleHasher::with_leaves(num_leaves.max(1));
    hasher.write(bytes).expect("valid bytes");
    hasher.finish().expect("valid root")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Checkpoint;

    fn sample_attestation() -> Attestation {
        Attestation {
            aggregation_bits: vec![0xff; 4],
            data: AttestationData {
                slot: 100,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: Checkpoint { epoch: 3, root: [2u8; 32] },
                target: Checkpoint { epoch: 4, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
        }
    }

    fn sample_aggregate_and_proof() -> AggregateAndProof {
        AggregateAndProof {
            aggregator_index: 42,
            aggregate: sample_attestation(),
            selection_proof: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_attestation_serde_roundtrip() {
        let att = sample_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_aggregate_and_proof_serde_roundtrip() {
        let proof = sample_aggregate_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: AggregateAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_aggregate_and_proof_quoted_aggregator_index() {
        let proof = sample_aggregate_and_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["aggregator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_signed_aggregate_and_proof_serde_roundtrip() {
        let signed = SignedAggregateAndProof {
            message: sample_aggregate_and_proof(),
            signature: vec![0xcc; 96],
        };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedAggregateAndProof = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_attestation_empty_aggregation_bits() {
        let att = Attestation {
            aggregation_bits: vec![],
            data: AttestationData {
                slot: 0,
                index: 0,
                beacon_block_root: [0u8; 32],
                source: Checkpoint { epoch: 0, root: [0u8; 32] },
                target: Checkpoint { epoch: 0, root: [0u8; 32] },
            },
            signature: vec![0; 96],
        };
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_attestation_tree_hash_deterministic() {
        let att = sample_attestation();
        let root1 = att.tree_hash_root();
        let root2 = att.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_attestation_tree_hash_different_data_different_root() {
        let att1 = sample_attestation();
        let mut att2 = sample_attestation();
        att2.data.slot = 999;
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_aggregate_and_proof_tree_hash_deterministic() {
        let proof = sample_aggregate_and_proof();
        let root1 = proof.tree_hash_root();
        let root2 = proof.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_aggregate_and_proof_tree_hash_different_index_different_root() {
        let proof1 = sample_aggregate_and_proof();
        let mut proof2 = sample_aggregate_and_proof();
        proof2.aggregator_index = 99;
        assert_ne!(proof1.tree_hash_root(), proof2.tree_hash_root());
    }
}
