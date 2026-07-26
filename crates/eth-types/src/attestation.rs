use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

use crate::tree_hash_utils::{impl_container_tree_hash, vec_u8_tree_hash_root};
use crate::{AttestationData, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleAttestation {
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attester_index: u64,
    pub data: AttestationData,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

// Leaf order: committee_index, attester_index, data, signature
impl_container_tree_hash!(
    SingleAttestation,
    "valid SingleAttestation",
    [
        |s| Ok(s.committee_index.tree_hash_root()),
        |s| Ok(s.attester_index.tree_hash_root()),
        |s| Ok(s.data.tree_hash_root()),
        |s| Ok(vec_u8_tree_hash_root(&s.signature)),
    ]
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Checkpoint;

    fn sample_single_attestation() -> SingleAttestation {
        SingleAttestation {
            committee_index: 5,
            attester_index: 42,
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

    #[test]
    fn test_single_attestation_serde_roundtrip() {
        let att = sample_single_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let deserialized: SingleAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, deserialized);
    }

    #[test]
    fn test_single_attestation_quoted_u64_fields() {
        let att = sample_single_attestation();
        let json = serde_json::to_string(&att).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["committee_index"], serde_json::Value::String("5".to_string()));
        assert_eq!(parsed["attester_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_single_attestation_tree_hash_deterministic() {
        let att = sample_single_attestation();
        let root1 = att.tree_hash_root();
        let root2 = att.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_single_attestation_tree_hash_sensitive_to_committee_index() {
        let att1 = sample_single_attestation();
        let mut att2 = sample_single_attestation();
        att2.committee_index = 99;
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_single_attestation_tree_hash_sensitive_to_attester_index() {
        let att1 = sample_single_attestation();
        let mut att2 = sample_single_attestation();
        att2.attester_index = 999;
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_single_attestation_tree_hash_sensitive_to_data() {
        let att1 = sample_single_attestation();
        let mut att2 = sample_single_attestation();
        att2.data.slot = 999;
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }

    #[test]
    fn test_single_attestation_tree_hash_sensitive_to_signature() {
        let att1 = sample_single_attestation();
        let mut att2 = sample_single_attestation();
        att2.signature = vec![0xbb; 96];
        assert_ne!(att1.tree_hash_root(), att2.tree_hash_root());
    }
}
