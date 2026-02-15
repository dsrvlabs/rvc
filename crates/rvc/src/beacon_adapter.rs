//! Adapter implementations for beacon client traits.
//!
//! Bridges the concrete `BeaconClient` to the trait interfaces required by
//! `BlockService` via newtype wrappers (orphan rule compliance).

use std::sync::Arc;

use async_trait::async_trait;

use beacon::BeaconClient;
use block_service::{BeaconBlockClient, BlockServiceError, ProduceBlockResponse};
use eth_types::{SignedBeaconBlock, SignedBlindedBeaconBlock, Slot};

/// Newtype adapter that implements `BeaconBlockClient` for `BeaconClient`.
pub struct BeaconBlockAdapter(pub Arc<BeaconClient>);

#[async_trait(?Send)]
impl BeaconBlockClient for BeaconBlockAdapter {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        let response = self
            .0
            .produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor)
            .await
            .map_err(|e| BlockServiceError::Beacon(e.to_string()))?;

        Ok(ProduceBlockResponse {
            data: response.data,
            is_blinded: response.is_blinded,
            consensus_version: response.consensus_version,
            execution_payload_value: response.execution_payload_value,
            is_ssz: response.is_ssz,
            ssz_bytes: response.ssz_bytes,
        })
    }

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.0
            .publish_block(signed_block, consensus_version)
            .await
            .map_err(|e| BlockServiceError::Beacon(e.to_string()))
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        self.0
            .publish_blinded_block(signed_block, consensus_version)
            .await
            .map_err(|e| BlockServiceError::Beacon(e.to_string()))
    }

    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BlockServiceError> {
        self.0
            .publish_block_ssz(ssz_bytes, consensus_version, is_blinded)
            .await
            .map_err(|e| BlockServiceError::Beacon(e.to_string()))
    }
}
