use async_trait::async_trait;

use eth_types::{
    BlindedBeaconBlock, BlockContents, SignedBeaconBlock, SignedBlindedBeaconBlock, Slot,
};

use crate::BlockServiceError;

/// Minimal beacon client trait for block production and publication.
///
/// Defined locally for testability; the real `beacon::BeaconClient`
/// can be adapted to implement this trait.
#[async_trait(?Send)]
pub trait BeaconBlockClient {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError>;

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError>;

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError>;
}

/// Response from block production, mirroring beacon API metadata.
///
/// Supports both JSON and SSZ content types. When the BN responds with SSZ,
/// `is_ssz` is `true` and `ssz_bytes` contains the raw SSZ-encoded block.
/// When JSON, `data` contains the parsed JSON value.
#[derive(Debug, Clone)]
pub struct ProduceBlockResponse {
    pub data: serde_json::Value,
    pub is_blinded: bool,
    pub consensus_version: String,
    pub execution_payload_value: Option<String>,
    /// Whether the response was received as SSZ (`application/octet-stream`).
    pub is_ssz: bool,
    /// Raw SSZ bytes when the BN responded with SSZ content type.
    pub ssz_bytes: Option<Vec<u8>>,
}

impl ProduceBlockResponse {
    pub fn parse_full_block(&self) -> Result<BlockContents, BlockServiceError> {
        serde_json::from_value(self.data.clone())
            .map_err(|e| BlockServiceError::Parse(format!("invalid block contents: {}", e)))
    }

    pub fn parse_blinded_block(&self) -> Result<BlindedBeaconBlock, BlockServiceError> {
        serde_json::from_value(self.data.clone())
            .map_err(|e| BlockServiceError::Parse(format!("invalid blinded block: {}", e)))
    }
}
