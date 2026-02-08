use async_trait::async_trait;

use crypto::PublicKey;
use eth_types::{AttestationData, Epoch, ForkSchedule, Root, Slot};

use crate::SignerError;

/// Trait for signing validator duties with slashing protection.
///
/// Implementations must ensure that slashing-protected operations
/// (attestation signing, block signing) perform the appropriate
/// checks before producing a signature.
#[async_trait(?Send)]
pub trait ValidatorSigner {
    /// Sign an attestation after checking slashing protection.
    async fn sign_attestation(
        &self,
        data: &AttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError>;

    /// Sign a block after checking slashing protection.
    async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError>;

    /// Sign a RANDAO reveal for the given epoch.
    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError>;

    /// Sign a sync committee message for the given beacon block root and slot.
    async fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError>;
}
