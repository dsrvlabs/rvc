//! Slashing protection types for EIP-3076 interchange format and internal records.

use serde::{Deserialize, Serialize};

use eth_types::{Epoch, Slot};

/// Internal record of a signed attestation for slashing protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttestation {
    pub pubkey: String,
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Option<String>,
}

/// Internal record of a signed block for slashing protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlock {
    pub pubkey: String,
    pub slot: Slot,
    pub signing_root: Option<String>,
}

/// EIP-3076 interchange format root container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeFormat {
    pub metadata: InterchangeMetadata,
    pub data: Vec<ValidatorRecord>,
}

/// Metadata for the EIP-3076 interchange format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeMetadata {
    pub interchange_format_version: String,
    pub genesis_validators_root: String,
}

/// Validator signing history record in EIP-3076 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub pubkey: String,
    pub signed_blocks: Vec<InterchangeBlock>,
    pub signed_attestations: Vec<InterchangeAttestation>,
}

/// Block signing record in EIP-3076 format.
/// Note: slot is serialized as string per EIP-3076 specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeBlock {
    pub slot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

/// Attestation signing record in EIP-3076 format.
/// Note: epoch values are serialized as strings per EIP-3076 specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeAttestation {
    pub source_epoch: String,
    pub target_epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_attestation_creation() {
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: Some("0xabcd".to_string()),
        };

        assert_eq!(attestation.pubkey, "0x1234");
        assert_eq!(attestation.source_epoch, 100);
        assert_eq!(attestation.target_epoch, 101);
        assert_eq!(attestation.signing_root, Some("0xabcd".to_string()));
    }

    #[test]
    fn test_signed_attestation_without_signing_root() {
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };

        assert!(attestation.signing_root.is_none());
    }

    #[test]
    fn test_signed_block_creation() {
        let block = SignedBlock {
            pubkey: "0x1234".to_string(),
            slot: 1000,
            signing_root: Some("0xabcd".to_string()),
        };

        assert_eq!(block.pubkey, "0x1234");
        assert_eq!(block.slot, 1000);
        assert_eq!(block.signing_root, Some("0xabcd".to_string()));
    }

    #[test]
    fn test_interchange_metadata_json_roundtrip() {
        let metadata = InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root:
                "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673".to_string(),
        };

        let json = serde_json::to_string(&metadata).expect("serialization should succeed");
        let deserialized: InterchangeMetadata =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_interchange_block_json_roundtrip() {
        let block = InterchangeBlock {
            slot: "81952".to_string(),
            signing_root: Some(
                "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b".to_string(),
            ),
        };

        let json = serde_json::to_string(&block).expect("serialization should succeed");
        let deserialized: InterchangeBlock =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_interchange_block_without_signing_root() {
        let block = InterchangeBlock { slot: "81952".to_string(), signing_root: None };

        let json = serde_json::to_string(&block).expect("serialization should succeed");

        assert!(!json.contains("signing_root"));

        let deserialized: InterchangeBlock =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_interchange_attestation_json_roundtrip() {
        let attestation = InterchangeAttestation {
            source_epoch: "2290".to_string(),
            target_epoch: "3007".to_string(),
            signing_root: Some(
                "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d".to_string(),
            ),
        };

        let json = serde_json::to_string(&attestation).expect("serialization should succeed");
        let deserialized: InterchangeAttestation =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_interchange_attestation_without_signing_root() {
        let attestation = InterchangeAttestation {
            source_epoch: "2290".to_string(),
            target_epoch: "3007".to_string(),
            signing_root: None,
        };

        let json = serde_json::to_string(&attestation).expect("serialization should succeed");

        assert!(!json.contains("signing_root"));

        let deserialized: InterchangeAttestation =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_validator_record_json_roundtrip() {
        let record = ValidatorRecord {
            pubkey: "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                .to_string(),
            signed_blocks: vec![InterchangeBlock {
                slot: "81952".to_string(),
                signing_root: Some(
                    "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                        .to_string(),
                ),
            }],
            signed_attestations: vec![InterchangeAttestation {
                source_epoch: "2290".to_string(),
                target_epoch: "3007".to_string(),
                signing_root: Some(
                    "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                        .to_string(),
                ),
            }],
        };

        let json = serde_json::to_string(&record).expect("serialization should succeed");
        let deserialized: ValidatorRecord =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_full_interchange_format_json_roundtrip() {
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root:
                    "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
                        .to_string(),
            },
            data: vec![
                ValidatorRecord {
                    pubkey: "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                        .to_string(),
                    signed_blocks: vec![
                        InterchangeBlock {
                            slot: "81952".to_string(),
                            signing_root: Some(
                                "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                                    .to_string(),
                            ),
                        },
                    ],
                    signed_attestations: vec![
                        InterchangeAttestation {
                            source_epoch: "2290".to_string(),
                            target_epoch: "3007".to_string(),
                            signing_root: Some(
                                "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                                    .to_string(),
                            ),
                        },
                    ],
                },
            ],
        };

        let json =
            serde_json::to_string_pretty(&interchange).expect("serialization should succeed");
        let deserialized: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(interchange, deserialized);
    }

    #[test]
    fn test_interchange_format_eip3076_example() {
        let json = r#"{
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
            },
            "data": [
                {
                    "pubkey": "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed",
                    "signed_blocks": [
                        {
                            "slot": "81952",
                            "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                        }
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                        }
                    ]
                }
            ]
        }"#;

        let interchange: InterchangeFormat =
            serde_json::from_str(json).expect("deserialization should succeed");

        assert_eq!(interchange.metadata.interchange_format_version, "5");
        assert_eq!(
            interchange.metadata.genesis_validators_root,
            "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
        );
        assert_eq!(interchange.data.len(), 1);

        let validator = &interchange.data[0];
        assert_eq!(
            validator.pubkey,
            "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
        );
        assert_eq!(validator.signed_blocks.len(), 1);
        assert_eq!(validator.signed_attestations.len(), 1);

        let block = &validator.signed_blocks[0];
        assert_eq!(block.slot, "81952");
        assert_eq!(
            block.signing_root,
            Some("0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b".to_string())
        );

        let attestation = &validator.signed_attestations[0];
        assert_eq!(attestation.source_epoch, "2290");
        assert_eq!(attestation.target_epoch, "3007");
        assert_eq!(
            attestation.signing_root,
            Some("0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d".to_string())
        );
    }

    #[test]
    fn test_interchange_format_empty_data() {
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root:
                    "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673".to_string(),
            },
            data: vec![],
        };

        let json = serde_json::to_string(&interchange).expect("serialization should succeed");
        let deserialized: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(interchange, deserialized);
        assert!(deserialized.data.is_empty());
    }

    #[test]
    fn test_validator_record_empty_blocks_and_attestations() {
        let record = ValidatorRecord {
            pubkey: "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                .to_string(),
            signed_blocks: vec![],
            signed_attestations: vec![],
        };

        let json = serde_json::to_string(&record).expect("serialization should succeed");
        let deserialized: ValidatorRecord =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(record, deserialized);
        assert!(deserialized.signed_blocks.is_empty());
        assert!(deserialized.signed_attestations.is_empty());
    }

    #[test]
    fn test_multiple_validators_in_interchange() {
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root:
                    "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673".to_string(),
            },
            data: vec![
                ValidatorRecord {
                    pubkey: "0xaaa".to_string(),
                    signed_blocks: vec![InterchangeBlock {
                        slot: "100".to_string(),
                        signing_root: None,
                    }],
                    signed_attestations: vec![],
                },
                ValidatorRecord {
                    pubkey: "0xbbb".to_string(),
                    signed_blocks: vec![],
                    signed_attestations: vec![InterchangeAttestation {
                        source_epoch: "10".to_string(),
                        target_epoch: "11".to_string(),
                        signing_root: None,
                    }],
                },
            ],
        };

        let json = serde_json::to_string(&interchange).expect("serialization should succeed");
        let deserialized: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(interchange, deserialized);
        assert_eq!(deserialized.data.len(), 2);
    }
}
