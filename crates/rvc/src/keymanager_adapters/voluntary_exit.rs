//! Voluntary-exit signing adapter for the Keymanager API.

use std::sync::Arc;

use async_trait::async_trait;
use beacon::BeaconClient;
use crypto::PublicKey;
use eth_types::{
    ForkSchedule, Root, SignedVoluntaryExit, VoluntaryExit, SLOTS_PER_EPOCH, SLOT_DURATION_MS,
};
use keymanager_api::error::ApiError;
use keymanager_api::traits::{Pubkey, VoluntaryExitManager};
use signer::{SignerService, ValidatorSigner};
use tracing::info;

use super::notifier::pubkey_hex;

pub struct VoluntaryExitManagerAdapter {
    beacon_client: Arc<BeaconClient>,
    signer: Arc<SignerService>,
    fork_schedule: Arc<ForkSchedule>,
    genesis_validators_root: Root,
}

impl VoluntaryExitManagerAdapter {
    pub fn new(
        beacon_client: Arc<BeaconClient>,
        signer: Arc<SignerService>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self { beacon_client, signer, fork_schedule, genesis_validators_root }
    }
}

#[async_trait]
impl VoluntaryExitManager for VoluntaryExitManagerAdapter {
    async fn sign_voluntary_exit(
        &self,
        pubkey: &Pubkey,
        epoch: Option<u64>,
    ) -> Result<SignedVoluntaryExit, ApiError> {
        let pubkey_hex = pubkey_hex(pubkey);

        // Resolve validator index from beacon node
        let validators_response = self
            .beacon_client
            .get_validators(std::slice::from_ref(&pubkey_hex))
            .await
            .map_err(|e| ApiError::Internal(format!("beacon node error: {e}")))?;

        let validator = validators_response.data.first().ok_or_else(|| {
            ApiError::NotFound(format!("validator {pubkey_hex} not found on beacon node"))
        })?;

        let validator_index: u64 = validator
            .index
            .parse()
            .map_err(|e| ApiError::Internal(format!("failed to parse validator index: {e}")))?;

        // Determine epoch
        let epoch = match epoch {
            Some(e) => e,
            None => {
                let genesis = self
                    .beacon_client
                    .get_genesis()
                    .await
                    .map_err(|e| ApiError::Internal(format!("failed to get genesis: {e}")))?;

                let genesis_time: u64 = genesis.data.genesis_time.parse().map_err(|e| {
                    ApiError::Internal(format!("failed to parse genesis time: {e}"))
                })?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time before UNIX epoch")
                    .as_secs();

                current_epoch_at(now, genesis_time)
            }
        };

        info!(epoch, validator_index, pubkey = %pubkey_hex, "Signing voluntary exit");

        // Construct and sign
        let voluntary_exit = VoluntaryExit { epoch, validator_index };

        let pk = PublicKey::from_bytes(pubkey)
            .map_err(|e| ApiError::Internal(format!("invalid public key: {e:?}")))?;

        let signature = self
            .signer
            .sign_voluntary_exit(
                &voluntary_exit,
                &pk,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("signing failed: {e}")))?;

        Ok(SignedVoluntaryExit {
            message: voluntary_exit,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

/// Current epoch at `now_unix_secs` given genesis, using millisecond slot duration.
fn current_epoch_at(now_unix_secs: u64, genesis_time: u64) -> u64 {
    let elapsed_ms = now_unix_secs.saturating_sub(genesis_time).saturating_mul(1000);
    elapsed_ms / SLOT_DURATION_MS / SLOTS_PER_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_epoch_at_genesis_is_zero() {
        let genesis = 1_606_824_023_u64;
        assert_eq!(current_epoch_at(genesis, genesis), 0);
    }

    #[test]
    fn test_current_epoch_after_one_epoch_is_one() {
        let genesis = 1_606_824_023_u64;
        let epoch_secs = SLOT_DURATION_MS / 1000 * SLOTS_PER_EPOCH;
        assert_eq!(epoch_secs, 384, "one epoch is 384 s");
        assert_eq!(current_epoch_at(genesis + epoch_secs, genesis), 1);
        assert_eq!(current_epoch_at(genesis + epoch_secs - 1, genesis), 0);
    }
}
