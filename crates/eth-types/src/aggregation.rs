use serde::{Deserialize, Serialize};

use crate::{AttestationData, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub aggregation_bits: Vec<u8>,
    pub data: AttestationData,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: Attestation,
    pub selection_proof: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAggregateAndProof {
    pub message: AggregateAndProof,
    pub signature: Signature,
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
}
