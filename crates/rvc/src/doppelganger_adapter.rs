//! Adapter implementations bridging production types to doppelganger detection traits.

use std::sync::Arc;

use async_trait::async_trait;
use beacon::BeaconClient;
use doppelganger::{DoppelgangerError, LivenessChecker, SlashingDbReader, ValidatorLivenessData};
use eth_types::Epoch;
use slashing::SlashingDb;

/// Adapter implementing [`LivenessChecker`] via [`BeaconClient::post_validator_liveness`].
pub struct BeaconLivenessAdapter {
    beacon: Arc<BeaconClient>,
}

impl BeaconLivenessAdapter {
    pub fn new(beacon: Arc<BeaconClient>) -> Self {
        Self { beacon }
    }
}

#[async_trait]
impl LivenessChecker for BeaconLivenessAdapter {
    async fn check_liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[String],
    ) -> Result<Vec<ValidatorLivenessData>, DoppelgangerError> {
        let response = self
            .beacon
            .post_validator_liveness(epoch, validator_indices)
            .await
            .map_err(|e| DoppelgangerError::LivenessCheckFailed(e.to_string()))?;

        Ok(response
            .data
            .into_iter()
            .map(|v| ValidatorLivenessData { index: v.index, is_live: v.is_live })
            .collect())
    }
}

/// Adapter implementing [`SlashingDbReader`] via [`SlashingDb::last_signed_attestation_epoch`].
pub struct SlashingDbReaderAdapter {
    db: Arc<SlashingDb>,
}

impl SlashingDbReaderAdapter {
    pub fn new(db: Arc<SlashingDb>) -> Self {
        Self { db }
    }
}

impl SlashingDbReader for SlashingDbReaderAdapter {
    fn last_signed_attestation_epoch(
        &self,
        pubkey: &str,
    ) -> Result<Option<Epoch>, DoppelgangerError> {
        self.db
            .last_signed_attestation_epoch(pubkey)
            .map_err(|e| DoppelgangerError::SlashingDbError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slashing_db_reader_adapter_no_attestations() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let adapter = SlashingDbReaderAdapter::new(db);
        let result = adapter.last_signed_attestation_epoch("0xabc").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_slashing_db_reader_adapter_with_attestation() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        db.record_attestation("0xabc", 5, 10, None).unwrap();
        let adapter = SlashingDbReaderAdapter::new(db);
        let result = adapter.last_signed_attestation_epoch("0xabc").unwrap();
        assert_eq!(result, Some(10));
    }

    #[test]
    fn test_slashing_db_reader_adapter_returns_max_epoch() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        db.record_attestation("0xabc", 1, 5, None).unwrap();
        db.record_attestation("0xabc", 5, 10, None).unwrap();
        db.record_attestation("0xabc", 10, 15, None).unwrap();
        let adapter = SlashingDbReaderAdapter::new(db);
        let result = adapter.last_signed_attestation_epoch("0xabc").unwrap();
        assert_eq!(result, Some(15));
    }

    #[test]
    fn test_beacon_liveness_adapter_construction() {
        let config = beacon::BeaconClientConfig::new("http://localhost:5052");
        let client = Arc::new(BeaconClient::new(config).unwrap());
        let _adapter = BeaconLivenessAdapter::new(client);
    }
}
