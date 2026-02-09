//! Beacon node manager with multi-BN support, failover, and health tracking.

mod error;
mod manager;
mod traits;

pub use error::BnManagerError;
pub use manager::BnManager;
pub use traits::{BeaconNodeClient, BnHealthScore, BnManagerConfig, BnSelectionStrategy};

// Re-export types used in trait signatures so downstream crates
// don't need to depend on `beacon` directly.
pub use beacon::{
    AggregateAttestationResponse, Attestation, AttestationDataResponse, AttesterDutiesResponse,
    BeaconCommitteeSubscription, BeaconError, BlockRootResponse, ConfigSpecResponse,
    GenesisResponse, ProduceBlockResponse, ProposerDutiesResponse, ProposerPreparation,
    SignedAggregateAndProof, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, ValidatorsResponse,
};
pub use eth_types::{ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock};
