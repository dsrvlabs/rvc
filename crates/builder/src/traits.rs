//! Narrow traits for the builder registration / prepare-proposer path.
//!
//! `BuilderService` depends only on these surfaces so unit tests can stub two
//! beacon methods and one sign method instead of the full BN / signer traits.

use std::sync::Arc;

use async_trait::async_trait;
use bn_manager::{BeaconError, BeaconNodeClient, ProposerPreparation, SignedValidatorRegistration};
use crypto::PublicKey;
use eth_types::ValidatorRegistrationV1;
use signer::{SignerError, ValidatorSigner};

/// Beacon methods used by [`crate::BuilderService`].
#[async_trait]
pub trait BuilderBeaconClient: Send + Sync {
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError>;

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError>;
}

/// Production bridge: full BN trait object satisfies the narrow builder surface.
///
/// Targets the narrow trait only (no other impls), so this is coherence-safe.
#[async_trait]
impl BuilderBeaconClient for Arc<dyn BeaconNodeClient> {
    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        (**self).register_validators(registrations).await
    }

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        (**self).prepare_beacon_proposer(preparations).await
    }
}

/// Signer methods used by [`crate::BuilderService`] for builder registrations.
#[async_trait(?Send)]
pub trait RegistrationSigner {
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Vec<u8>, SignerError>;
}

/// Production bridge: full signer trait object satisfies the registration surface.
#[async_trait(?Send)]
impl RegistrationSigner for Arc<dyn ValidatorSigner> {
    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Vec<u8>, SignerError> {
        (**self).sign_builder_registration(registration, pubkey, fork_version).await
    }
}
