use serde::{Deserialize, Serialize};

/// A checkpoint in the beacon chain consisting of an epoch and block root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub epoch: String,
    pub root: String,
}

/// Data for an attestation, containing the vote information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationData {
    pub slot: String,
    pub index: String,
    pub beacon_block_root: String,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

/// A signed attestation containing aggregation bits, data, and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub aggregation_bits: String,
    pub data: AttestationData,
    pub signature: String,
}

/// Header of a beacon block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    pub slot: String,
    pub proposer_index: String,
    pub parent_root: String,
    pub state_root: String,
    pub body_root: String,
}

/// Attester duty information for a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttesterDuty {
    pub pubkey: String,
    pub validator_index: String,
    pub committee_index: String,
    pub committee_length: String,
    pub committees_at_slot: String,
    pub validator_committee_index: String,
    pub slot: String,
}

/// Wrapper for beacon API data responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResponse<T> {
    pub data: T,
}

/// Wrapper for beacon API data responses with dependent root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependentRootResponse<T> {
    pub dependent_root: String,
    pub execution_optimistic: bool,
    pub data: T,
}

/// Response type for attester duties endpoint.
pub type AttesterDutiesResponse = DependentRootResponse<Vec<AttesterDuty>>;

/// Response type for attestation data endpoint.
pub type AttestationDataResponse = DataResponse<AttestationData>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_deserialize() {
        let json = r#"{
            "epoch": "123456",
            "root": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        }"#;

        let checkpoint: Checkpoint = serde_json::from_str(json).unwrap();
        assert_eq!(checkpoint.epoch, "123456");
        assert_eq!(
            checkpoint.root,
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn test_checkpoint_serialize() {
        let checkpoint = Checkpoint { epoch: "123456".to_string(), root: "0x1234".to_string() };

        let json = serde_json::to_string(&checkpoint).unwrap();
        assert!(json.contains("\"epoch\":\"123456\""));
        assert!(json.contains("\"root\":\"0x1234\""));
    }

    #[test]
    fn test_attestation_data_deserialize() {
        let json = r#"{
            "slot": "1000",
            "index": "1",
            "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "source": {
                "epoch": "100",
                "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
            },
            "target": {
                "epoch": "101",
                "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
            }
        }"#;

        let data: AttestationData = serde_json::from_str(json).unwrap();
        assert_eq!(data.slot, "1000");
        assert_eq!(data.index, "1");
        assert_eq!(data.source.epoch, "100");
        assert_eq!(data.target.epoch, "101");
    }

    #[test]
    fn test_attestation_deserialize() {
        let json = r#"{
            "aggregation_bits": "0x01",
            "data": {
                "slot": "1000",
                "index": "1",
                "beacon_block_root": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "source": {
                    "epoch": "100",
                    "root": "0x1111111111111111111111111111111111111111111111111111111111111111"
                },
                "target": {
                    "epoch": "101",
                    "root": "0x2222222222222222222222222222222222222222222222222222222222222222"
                }
            },
            "signature": "0xsignature"
        }"#;

        let attestation: Attestation = serde_json::from_str(json).unwrap();
        assert_eq!(attestation.aggregation_bits, "0x01");
        assert_eq!(attestation.data.slot, "1000");
        assert_eq!(attestation.signature, "0xsignature");
    }

    #[test]
    fn test_beacon_block_header_deserialize() {
        let json = r#"{
            "slot": "5000",
            "proposer_index": "123",
            "parent_root": "0xparentroot",
            "state_root": "0xstateroot",
            "body_root": "0xbodyroot"
        }"#;

        let header: BeaconBlockHeader = serde_json::from_str(json).unwrap();
        assert_eq!(header.slot, "5000");
        assert_eq!(header.proposer_index, "123");
        assert_eq!(header.parent_root, "0xparentroot");
        assert_eq!(header.state_root, "0xstateroot");
        assert_eq!(header.body_root, "0xbodyroot");
    }

    #[test]
    fn test_attester_duty_deserialize() {
        let json = r#"{
            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
            "validator_index": "1234",
            "committee_index": "1",
            "committee_length": "128",
            "committees_at_slot": "64",
            "validator_committee_index": "25",
            "slot": "10000"
        }"#;

        let duty: AttesterDuty = serde_json::from_str(json).unwrap();
        assert_eq!(duty.validator_index, "1234");
        assert_eq!(duty.committee_index, "1");
        assert_eq!(duty.committee_length, "128");
        assert_eq!(duty.committees_at_slot, "64");
        assert_eq!(duty.validator_committee_index, "25");
        assert_eq!(duty.slot, "10000");
    }

    #[test]
    fn test_data_response_deserialize() {
        let json = r#"{
            "data": {
                "epoch": "123",
                "root": "0xroot"
            }
        }"#;

        let response: DataResponse<Checkpoint> = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.epoch, "123");
        assert_eq!(response.data.root, "0xroot");
    }

    #[test]
    fn test_dependent_root_response_deserialize() {
        let json = r#"{
            "dependent_root": "0xdeproot",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xpubkey",
                "validator_index": "1",
                "committee_index": "0",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "10",
                "slot": "100"
            }]
        }"#;

        let response: DependentRootResponse<Vec<AttesterDuty>> =
            serde_json::from_str(json).unwrap();
        assert_eq!(response.dependent_root, "0xdeproot");
        assert!(!response.execution_optimistic);
        assert_eq!(response.data.len(), 1);
        assert_eq!(response.data[0].validator_index, "1");
    }
}
