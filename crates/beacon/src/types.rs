use std::collections::HashMap;

use eth_types::{
    BlindedBeaconBlock, BlockContents, Epoch, ForkSchedule, SyncCommitteeContribution,
    SyncCommitteeDuty, Version,
};
use serde::{Deserialize, Serialize};

use crate::BeaconError;

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

/// A single attestation in the Electra (v2) `SingleAttestation` format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub committee_index: u64,
    pub attester_index: u64,
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

/// Wrapper for beacon API responses with execution optimistic flag (no dependent root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionOptimisticResponse<T> {
    pub execution_optimistic: bool,
    pub data: T,
}

/// Response type for attester duties endpoint.
pub type AttesterDutiesResponse = DependentRootResponse<Vec<AttesterDuty>>;

/// Proposer duty information for a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerDuty {
    pub pubkey: String,
    pub validator_index: String,
    pub slot: String,
}

/// Response type for proposer duties endpoint.
pub type ProposerDutiesResponse = DependentRootResponse<Vec<ProposerDuty>>;

/// Response from the produce block v3 endpoint, including header metadata.
#[derive(Debug, Clone)]
pub struct ProduceBlockResponse {
    pub data: serde_json::Value,
    pub is_blinded: bool,
    pub consensus_version: String,
    pub execution_payload_value: Option<String>,
}

impl ProduceBlockResponse {
    /// Parses the raw `data` field into a full block with blob sidecars.
    pub fn parse_full_block(&self) -> Result<BlockContents, BeaconError> {
        serde_json::from_value(self.data.clone())
            .map_err(|e| BeaconError::ParseError(format!("invalid block contents: {}", e)))
    }

    /// Parses the raw `data` field into a blinded block.
    pub fn parse_blinded_block(&self) -> Result<BlindedBeaconBlock, BeaconError> {
        serde_json::from_value(self.data.clone())
            .map_err(|e| BeaconError::ParseError(format!("invalid blinded block: {}", e)))
    }
}

/// Response type for attestation data endpoint.
pub type AttestationDataResponse = DataResponse<AttestationData>;

/// Response type for sync committee duties endpoint.
pub type SyncCommitteeDutiesResponse = ExecutionOptimisticResponse<Vec<SyncCommitteeDuty>>;

/// Response type for sync committee contribution endpoint.
pub type SyncCommitteeContributionResponse = DataResponse<SyncCommitteeContribution>;

pub use eth_types::SignedContributionAndProof;
pub use eth_types::SyncCommitteeMessage;

/// Validator information from the beacon state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorData {
    pub index: String,
    pub status: String,
    pub validator: ValidatorInfo,
}

/// Public key information for a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub pubkey: String,
}

/// Response type for the validators state endpoint.
pub type ValidatorsResponse = DataResponse<Vec<ValidatorData>>;

/// Genesis information from the beacon chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisData {
    pub genesis_time: String,
    pub genesis_validators_root: String,
    pub genesis_fork_version: String,
}

/// Response type for the genesis endpoint.
pub type GenesisResponse = DataResponse<GenesisData>;

/// Response type for the config spec endpoint.
pub type ConfigSpecResponse = DataResponse<HashMap<String, String>>;

/// Fork information from the beacon state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFork {
    pub previous_version: String,
    pub current_version: String,
    pub epoch: String,
}

/// Wrapper for beacon API state responses with execution optimistic and finalized flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateResponse<T> {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: T,
}

/// Response type for the beacon state fork endpoint.
pub type StateForkResponse = StateResponse<StateFork>;

/// Parses a config/spec response into a `ForkSchedule`.
///
/// Extracts fork epoch and version fields from the config spec map.
/// Version fields are hex-encoded (e.g., "0x00000000") and epoch fields
/// are decimal strings (e.g., "74240").
pub fn parse_fork_schedule(spec: &HashMap<String, String>) -> Result<ForkSchedule, BeaconError> {
    Ok(ForkSchedule {
        genesis_fork_version: parse_version(spec, "GENESIS_FORK_VERSION")?,
        altair_fork_epoch: parse_epoch(spec, "ALTAIR_FORK_EPOCH")?,
        altair_fork_version: parse_version(spec, "ALTAIR_FORK_VERSION")?,
        bellatrix_fork_epoch: parse_epoch(spec, "BELLATRIX_FORK_EPOCH")?,
        bellatrix_fork_version: parse_version(spec, "BELLATRIX_FORK_VERSION")?,
        capella_fork_epoch: parse_epoch(spec, "CAPELLA_FORK_EPOCH")?,
        capella_fork_version: parse_version(spec, "CAPELLA_FORK_VERSION")?,
        deneb_fork_epoch: parse_epoch(spec, "DENEB_FORK_EPOCH")?,
        deneb_fork_version: parse_version(spec, "DENEB_FORK_VERSION")?,
        electra_fork_epoch: parse_epoch(spec, "ELECTRA_FORK_EPOCH")?,
        electra_fork_version: parse_version(spec, "ELECTRA_FORK_VERSION")?,
    })
}

fn parse_epoch(spec: &HashMap<String, String>, key: &str) -> Result<Epoch, BeaconError> {
    let value = spec
        .get(key)
        .ok_or_else(|| BeaconError::ParseError(format!("missing config key: {}", key)))?;
    value
        .parse::<u64>()
        .map_err(|e| BeaconError::ParseError(format!("invalid epoch for {}: {}", key, e)))
}

fn parse_version(spec: &HashMap<String, String>, key: &str) -> Result<Version, BeaconError> {
    let value = spec
        .get(key)
        .ok_or_else(|| BeaconError::ParseError(format!("missing config key: {}", key)))?;
    let hex_str = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(hex_str)
        .map_err(|e| BeaconError::ParseError(format!("invalid hex for {}: {}", key, e)))?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| BeaconError::ParseError(format!("version must be 4 bytes for {}", key)))?;
    Ok(arr)
}

/// Error details for a single attestation that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedAttestationError {
    pub index: u32,
    pub message: String,
}

/// Result of submitting attestations to the beacon node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitAttestationResult {
    Success,
    PartialFailure { failures: Vec<IndexedAttestationError> },
}

impl SubmitAttestationResult {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn failures(&self) -> &[IndexedAttestationError] {
        match self {
            Self::Success => &[],
            Self::PartialFailure { failures } => failures,
        }
    }
}

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
            "committee_index": 1,
            "attester_index": 42,
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
        assert_eq!(attestation.committee_index, 1);
        assert_eq!(attestation.attester_index, 42);
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

    #[test]
    fn test_indexed_attestation_error_deserialize() {
        let json = r#"{
            "index": 0,
            "message": "Invalid signature"
        }"#;

        let error: IndexedAttestationError = serde_json::from_str(json).unwrap();
        assert_eq!(error.index, 0);
        assert_eq!(error.message, "Invalid signature");
    }

    #[test]
    fn test_submit_attestation_result_success() {
        let result = SubmitAttestationResult::Success;
        assert!(result.is_success());
        assert!(result.failures().is_empty());
    }

    #[test]
    fn test_genesis_data_deserialize() {
        let json = r#"{
            "genesis_time": "1606824023",
            "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            "genesis_fork_version": "0x00000000"
        }"#;

        let genesis: GenesisData = serde_json::from_str(json).unwrap();
        assert_eq!(genesis.genesis_time, "1606824023");
        assert_eq!(
            genesis.genesis_validators_root,
            "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
        );
        assert_eq!(genesis.genesis_fork_version, "0x00000000");
    }

    #[test]
    fn test_genesis_data_serialize() {
        let genesis = GenesisData {
            genesis_time: "1606824023".to_string(),
            genesis_validators_root:
                "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95".to_string(),
            genesis_fork_version: "0x00000000".to_string(),
        };
        let json = serde_json::to_string(&genesis).unwrap();
        assert!(json.contains("\"genesis_time\":\"1606824023\""));
        assert!(json.contains("\"genesis_fork_version\":\"0x00000000\""));
    }

    #[test]
    fn test_genesis_response_deserialize() {
        let json = r#"{
            "data": {
                "genesis_time": "1606824023",
                "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
                "genesis_fork_version": "0x00000000"
            }
        }"#;

        let response: GenesisResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.genesis_time, "1606824023");
    }

    #[test]
    fn test_config_spec_response_deserialize() {
        let json = r#"{
            "data": {
                "GENESIS_FORK_VERSION": "0x00000000",
                "ALTAIR_FORK_EPOCH": "74240",
                "ALTAIR_FORK_VERSION": "0x01000000",
                "SECONDS_PER_SLOT": "12",
                "SLOTS_PER_EPOCH": "32"
            }
        }"#;

        let response: ConfigSpecResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.data.get("GENESIS_FORK_VERSION").unwrap(), "0x00000000");
        assert_eq!(response.data.get("ALTAIR_FORK_EPOCH").unwrap(), "74240");
        assert_eq!(response.data.get("SECONDS_PER_SLOT").unwrap(), "12");
        assert_eq!(response.data.get("SLOTS_PER_EPOCH").unwrap(), "32");
        assert_eq!(response.data.len(), 5);
    }

    #[test]
    fn test_state_fork_deserialize() {
        let json = r#"{
            "previous_version": "0x00000000",
            "current_version": "0x04000000",
            "epoch": "269568"
        }"#;

        let fork: StateFork = serde_json::from_str(json).unwrap();
        assert_eq!(fork.previous_version, "0x00000000");
        assert_eq!(fork.current_version, "0x04000000");
        assert_eq!(fork.epoch, "269568");
    }

    #[test]
    fn test_state_fork_response_deserialize() {
        let json = r#"{
            "execution_optimistic": false,
            "finalized": true,
            "data": {
                "previous_version": "0x03000000",
                "current_version": "0x04000000",
                "epoch": "269568"
            }
        }"#;

        let response: StateForkResponse = serde_json::from_str(json).unwrap();
        assert!(!response.execution_optimistic);
        assert!(response.finalized);
        assert_eq!(response.data.previous_version, "0x03000000");
        assert_eq!(response.data.current_version, "0x04000000");
        assert_eq!(response.data.epoch, "269568");
    }

    fn mainnet_config_spec() -> HashMap<String, String> {
        let mut spec = HashMap::new();
        spec.insert("GENESIS_FORK_VERSION".to_string(), "0x00000000".to_string());
        spec.insert("ALTAIR_FORK_EPOCH".to_string(), "74240".to_string());
        spec.insert("ALTAIR_FORK_VERSION".to_string(), "0x01000000".to_string());
        spec.insert("BELLATRIX_FORK_EPOCH".to_string(), "144896".to_string());
        spec.insert("BELLATRIX_FORK_VERSION".to_string(), "0x02000000".to_string());
        spec.insert("CAPELLA_FORK_EPOCH".to_string(), "194048".to_string());
        spec.insert("CAPELLA_FORK_VERSION".to_string(), "0x03000000".to_string());
        spec.insert("DENEB_FORK_EPOCH".to_string(), "269568".to_string());
        spec.insert("DENEB_FORK_VERSION".to_string(), "0x04000000".to_string());
        spec.insert("ELECTRA_FORK_EPOCH".to_string(), "364544".to_string());
        spec.insert("ELECTRA_FORK_VERSION".to_string(), "0x05000000".to_string());
        spec
    }

    #[test]
    fn test_parse_fork_schedule_mainnet() {
        let spec = mainnet_config_spec();
        let schedule = parse_fork_schedule(&spec).unwrap();

        assert_eq!(schedule.genesis_fork_version, [0, 0, 0, 0]);
        assert_eq!(schedule.altair_fork_epoch, 74240);
        assert_eq!(schedule.altair_fork_version, [1, 0, 0, 0]);
        assert_eq!(schedule.bellatrix_fork_epoch, 144896);
        assert_eq!(schedule.bellatrix_fork_version, [2, 0, 0, 0]);
        assert_eq!(schedule.capella_fork_epoch, 194048);
        assert_eq!(schedule.capella_fork_version, [3, 0, 0, 0]);
        assert_eq!(schedule.deneb_fork_epoch, 269568);
        assert_eq!(schedule.deneb_fork_version, [4, 0, 0, 0]);
        assert_eq!(schedule.electra_fork_epoch, 364544);
        assert_eq!(schedule.electra_fork_version, [5, 0, 0, 0]);
    }

    #[test]
    fn test_parse_fork_schedule_unscheduled_forks() {
        let mut spec = mainnet_config_spec();
        spec.insert("ELECTRA_FORK_EPOCH".to_string(), "18446744073709551615".to_string());
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.electra_fork_epoch, u64::MAX);
    }

    #[test]
    fn test_parse_fork_schedule_missing_key() {
        let mut spec = mainnet_config_spec();
        spec.remove("ALTAIR_FORK_EPOCH");
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ALTAIR_FORK_EPOCH"));
    }

    #[test]
    fn test_parse_fork_schedule_invalid_epoch() {
        let mut spec = mainnet_config_spec();
        spec.insert("DENEB_FORK_EPOCH".to_string(), "not_a_number".to_string());
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DENEB_FORK_EPOCH"));
    }

    #[test]
    fn test_parse_fork_schedule_invalid_version_hex() {
        let mut spec = mainnet_config_spec();
        spec.insert("CAPELLA_FORK_VERSION".to_string(), "0xZZZZZZZZ".to_string());
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("CAPELLA_FORK_VERSION"));
    }

    #[test]
    fn test_parse_fork_schedule_wrong_version_length() {
        let mut spec = mainnet_config_spec();
        spec.insert("GENESIS_FORK_VERSION".to_string(), "0x0000".to_string());
        let result = parse_fork_schedule(&spec);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("GENESIS_FORK_VERSION"));
    }

    #[test]
    fn test_parse_fork_schedule_version_without_0x_prefix() {
        let mut spec = mainnet_config_spec();
        spec.insert("GENESIS_FORK_VERSION".to_string(), "00000000".to_string());
        let schedule = parse_fork_schedule(&spec).unwrap();
        assert_eq!(schedule.genesis_fork_version, [0, 0, 0, 0]);
    }

    #[test]
    fn test_submit_attestation_result_partial_failure() {
        let result = SubmitAttestationResult::PartialFailure {
            failures: vec![
                IndexedAttestationError { index: 0, message: "Invalid signature".to_string() },
                IndexedAttestationError {
                    index: 2,
                    message: "Attestation already known".to_string(),
                },
            ],
        };
        assert!(!result.is_success());
        assert_eq!(result.failures().len(), 2);
        assert_eq!(result.failures()[0].index, 0);
        assert_eq!(result.failures()[1].index, 2);
    }

    #[test]
    fn test_proposer_duty_deserialize() {
        let json = r#"{
            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
            "validator_index": "1234",
            "slot": "320000"
        }"#;

        let duty: ProposerDuty = serde_json::from_str(json).unwrap();
        assert_eq!(duty.validator_index, "1234");
        assert_eq!(duty.slot, "320000");
    }

    #[test]
    fn test_proposer_duties_response_deserialize() {
        let json = r#"{
            "dependent_root": "0xdeproot",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0xpubkey",
                "validator_index": "1",
                "slot": "100"
            }]
        }"#;

        let response: ProposerDutiesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.dependent_root, "0xdeproot");
        assert_eq!(response.data.len(), 1);
        assert_eq!(response.data[0].slot, "100");
    }

    #[test]
    fn test_produce_block_response_parse_full_block() {
        let parent_root: Vec<u8> = vec![1u8; 32];
        let state_root: Vec<u8> = vec![2u8; 32];
        let block_json = serde_json::json!({
            "slot": "100",
            "proposer_index": "42",
            "parent_root": parent_root,
            "state_root": state_root,
            "body": [0xde, 0xad]
        });

        let response = ProduceBlockResponse {
            data: block_json,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("12345".to_string()),
        };

        let block = response.parse_full_block().unwrap();
        assert_eq!(block.block().slot, 100);
        assert_eq!(block.block().proposer_index, 42);
    }

    #[test]
    fn test_produce_block_response_parse_blinded_block() {
        let parent_root: Vec<u8> = vec![3u8; 32];
        let state_root: Vec<u8> = vec![4u8; 32];
        let block_json = serde_json::json!({
            "slot": "200",
            "proposer_index": "99",
            "parent_root": parent_root,
            "state_root": state_root,
            "body": [0xbe, 0xef]
        });

        let response = ProduceBlockResponse {
            data: block_json,
            is_blinded: true,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
        };

        let block = response.parse_blinded_block().unwrap();
        assert_eq!(block.slot, 200);
        assert_eq!(block.proposer_index, 99);
    }

    #[test]
    fn test_produce_block_response_parse_invalid_data() {
        let response = ProduceBlockResponse {
            data: serde_json::json!({"invalid": "data"}),
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
        };

        assert!(response.parse_full_block().is_err());
    }
}
