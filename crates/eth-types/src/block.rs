use serde::{Deserialize, Serialize};

use crate::hex_fixed::bytes_32_hex;
use crate::{Root, Signature, Slot};

pub type BeaconBlockBody = Vec<u8>;
pub type BlindedBeaconBlockBody = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlock {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub state_root: Root,
    #[serde(with = "serde_utils::hex_vec")]
    pub body: BeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedBeaconBlock {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub state_root: Root,
    #[serde(with = "serde_utils::hex_vec")]
    pub body: BlindedBeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSidecar {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::hex_vec")]
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockContents {
    BlockAndBlobs { block: BeaconBlock, blob_sidecars: Vec<BlobSidecar> },
    Block(BeaconBlock),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProducedBlock {
    Full(BlockContents),
    Blinded(BlindedBeaconBlock),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    #[serde(with = "serde_utils::hex_vec")]
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlindedBeaconBlock {
    pub message: BlindedBeaconBlock,
    #[serde(with = "serde_utils::hex_vec")]
    pub signature: Signature,
}

impl BlockContents {
    pub fn block(&self) -> &BeaconBlock {
        match self {
            Self::Block(block) => block,
            Self::BlockAndBlobs { block, .. } => block,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block() -> BeaconBlock {
        BeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xde, 0xad],
        }
    }

    fn sample_blinded_block() -> BlindedBeaconBlock {
        BlindedBeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xbe, 0xef],
        }
    }

    fn sample_blob_sidecar() -> BlobSidecar {
        BlobSidecar { index: 0, blob: vec![0xab; 8] }
    }

    #[test]
    fn test_beacon_block_serde_roundtrip() {
        let block = sample_block();
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: BeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_beacon_block_quoted_integers() {
        let block = sample_block();
        let json = serde_json::to_string(&block).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["proposer_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_blinded_beacon_block_serde_roundtrip() {
        let block = sample_blinded_block();
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: BlindedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_blinded_beacon_block_quoted_integers() {
        let block = sample_blinded_block();
        let json = serde_json::to_string(&block).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["proposer_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_blob_sidecar_serde_roundtrip() {
        let sidecar = sample_blob_sidecar();
        let json = serde_json::to_string(&sidecar).unwrap();
        let deserialized: BlobSidecar = serde_json::from_str(&json).unwrap();
        assert_eq!(sidecar, deserialized);
    }

    #[test]
    fn test_blob_sidecar_quoted_index() {
        let sidecar = sample_blob_sidecar();
        let json = serde_json::to_string(&sidecar).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["index"], serde_json::Value::String("0".to_string()));
    }

    #[test]
    fn test_block_contents_block_only_serde_roundtrip() {
        let contents = BlockContents::Block(sample_block());
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_block_contents_with_blobs_serde_roundtrip() {
        let contents = BlockContents::BlockAndBlobs {
            block: sample_block(),
            blob_sidecars: vec![sample_blob_sidecar()],
        };
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_block_contents_block_accessor() {
        let block = sample_block();
        let contents_block = BlockContents::Block(block.clone());
        assert_eq!(contents_block.block(), &block);

        let contents_blobs = BlockContents::BlockAndBlobs {
            block: block.clone(),
            blob_sidecars: vec![sample_blob_sidecar()],
        };
        assert_eq!(contents_blobs.block(), &block);
    }

    #[test]
    fn test_block_contents_empty_blobs() {
        let contents =
            BlockContents::BlockAndBlobs { block: sample_block(), blob_sidecars: vec![] };
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_signed_beacon_block_serde_roundtrip() {
        let signed = SignedBeaconBlock { message: sample_block(), signature: vec![0xaa; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_signed_blinded_beacon_block_serde_roundtrip() {
        let signed =
            SignedBlindedBeaconBlock { message: sample_blinded_block(), signature: vec![0xbb; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedBlindedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_produced_block_full_variant() {
        let produced = ProducedBlock::Full(BlockContents::Block(sample_block()));
        assert!(matches!(produced, ProducedBlock::Full(_)));
    }

    #[test]
    fn test_produced_block_blinded_variant() {
        let produced = ProducedBlock::Blinded(sample_blinded_block());
        assert!(matches!(produced, ProducedBlock::Blinded(_)));
    }

    #[test]
    fn test_beacon_block_fields() {
        let block = sample_block();
        assert_eq!(block.slot, 100);
        assert_eq!(block.proposer_index, 42);
        assert_eq!(block.parent_root, [1u8; 32]);
        assert_eq!(block.state_root, [2u8; 32]);
    }
}
