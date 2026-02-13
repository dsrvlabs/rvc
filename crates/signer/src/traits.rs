use async_trait::async_trait;

use crypto::PublicKey;
use eth_types::{
    AggregateAndProof, AttestationData, Epoch, ForkSchedule, Root, Slot, ValidatorRegistrationV1,
    VoluntaryExit,
};

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

    /// Sign a slot with DOMAIN_SELECTION_PROOF to produce a selection proof.
    async fn sign_selection_proof(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError>;

    /// Sign an AggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    async fn sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError>;

    /// Sign a voluntary exit with DOMAIN_VOLUNTARY_EXIT.
    async fn sign_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError>;

    /// Sign a builder registration with DOMAIN_APPLICATION_BUILDER.
    ///
    /// No slashing check is needed — builder registrations are not slashable.
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Vec<u8>, SignerError>;
}
