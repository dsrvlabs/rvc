//! Adapter implementations bridging production types to doppelganger detection traits.
//!
//! SEC-2c: [`BeaconLivenessAdapter`] queries liveness through
//! [`bn_manager::BeaconNodeClient`] (production: `BnManager` with multi-BN
//! `query_first` failover) and translates numeric validator indices to bare
//! pubkey-hex before returning samples for [`ForwardWindowMachine::observe_liveness`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bn_manager::BeaconNodeClient;
use doppelganger::{
    DoppelgangerError, LegacySlashingHistoryReader, LivenessChecker, ValidatorLivenessData,
};
use eth_types::Epoch;
use parking_lot::RwLock;
use slashing::SlashingDb;

/// Adapter implementing [`LivenessChecker`] via
/// [`BeaconNodeClient::post_validator_liveness`] (bn-manager failover in production).
///
/// # Pubkey-hex translation (SEC-001)
///
/// Beacon nodes return **numeric** validator indices. The machine keys state by
/// bare lowercase `hex::encode(pubkey.to_bytes())`. This adapter translates
/// using `index_to_pubkey_hex` and **omits** untranslatable indices (fail-closed).
pub struct BeaconLivenessAdapter {
    beacon: Arc<dyn BeaconNodeClient>,
    /// Numeric index string → bare pubkey hex (machine state key).
    index_to_pubkey_hex: Arc<RwLock<HashMap<String, String>>>,
}

impl BeaconLivenessAdapter {
    /// Construct with an empty translation map.
    pub fn new(beacon: Arc<dyn BeaconNodeClient>) -> Self {
        Self { beacon, index_to_pubkey_hex: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Construct with a pre-built numeric-index → bare-pubkey-hex map (SEC-2c).
    pub fn with_index_map(
        beacon: Arc<dyn BeaconNodeClient>,
        index_to_pubkey_hex: Arc<RwLock<HashMap<String, String>>>,
    ) -> Self {
        Self { beacon, index_to_pubkey_hex }
    }

    /// Shared handle so keymanager / index refresh can update the map.
    pub fn index_map(&self) -> Arc<RwLock<HashMap<String, String>>> {
        Arc::clone(&self.index_to_pubkey_hex)
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

        let map = self.index_to_pubkey_hex.read();
        let samples: Vec<ValidatorLivenessData> = response
            .data
            .into_iter()
            .filter_map(|v| {
                // Prefer translation map; if map is empty (legacy), pass index through.
                let index = if map.is_empty() { v.index } else { map.get(&v.index)?.clone() };
                Some(ValidatorLivenessData { index, is_live: v.is_live })
            })
            .collect();

        Ok(samples)
    }
}

/// Adapter implementing [`LegacySlashingHistoryReader`] via
/// [`SlashingDb::last_signed_attestation_epoch`].
///
/// Used by [`doppelganger::DoppelgangerService`] (the GVR-blind service).
/// [`ForwardWindowMachine`] uses `slashing::SlashingDbReader` directly.
pub struct SlashingDbReaderAdapter {
    db: Arc<SlashingDb>,
}

impl SlashingDbReaderAdapter {
    pub fn new(db: Arc<SlashingDb>) -> Self {
        Self { db }
    }
}

impl LegacySlashingHistoryReader for SlashingDbReaderAdapter {
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
        let gvr = [0u8; 32];
        db.seed_attestation("0xabc", 5, 10, None, &gvr).unwrap();
        let adapter = SlashingDbReaderAdapter::new(db);
        let result = adapter.last_signed_attestation_epoch("0xabc").unwrap();
        assert_eq!(result, Some(10));
    }

    #[test]
    fn test_slashing_db_reader_adapter_returns_max_epoch() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let gvr = [0u8; 32];
        db.seed_attestation("0xabc", 1, 5, None, &gvr).unwrap();
        db.seed_attestation("0xabc", 5, 10, None, &gvr).unwrap();
        db.seed_attestation("0xabc", 10, 15, None, &gvr).unwrap();
        let adapter = SlashingDbReaderAdapter::new(db);
        let result = adapter.last_signed_attestation_epoch("0xabc").unwrap();
        assert_eq!(result, Some(15));
    }

    #[test]
    fn test_beacon_liveness_adapter_construction() {
        let config = beacon::BeaconClientConfig::new("http://localhost:5052");
        let client = Arc::new(beacon::BeaconClient::new(config).unwrap());
        let beacon: Arc<dyn BeaconNodeClient> = client;
        let _adapter = BeaconLivenessAdapter::new(beacon);
    }
}
