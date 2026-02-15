//! Beacon node manager with multi-BN support, failover, and health tracking.

mod error;
mod health;
mod manager;
pub mod sse;
mod sync_status;
mod traits;

pub use error::BnManagerError;
pub use manager::BnManager;
pub use sse::{
    parse_sse_event, BlockEvent, ChainReorgEvent, FinalizedCheckpointEvent, HeadEvent, SseConfig,
    SseConnectionState, SseError, SseEvent, DEFAULT_SSE_TOPICS,
};
pub use sync_status::{BnSyncStatus, SharedSyncStatuses};
pub use traits::{BeaconNodeClient, BnHealthScore, BnManagerConfig, BnSelectionStrategy};

// Re-export types used in trait signatures so downstream crates
// don't need to depend on `beacon` directly.
pub use beacon::{
    AggregateAttestationResponse, Attestation, AttestationData, AttestationDataResponse,
    AttesterDutiesResponse, AttesterDuty, BeaconCommitteeSubscription, BeaconError,
    BlockRootResponse, Checkpoint, ConfigSpecResponse, GenesisResponse, IndexedAttestationError,
    LegacyAttestation, ProduceBlockResponse, ProposerDutiesResponse, ProposerDuty,
    ProposerPreparation, SignedAggregateAndProof, SignedContributionAndProof, SingleAttestation,
    StateForkResponse, SubmitAttestationResult, SyncCommitteeContributionResponse,
    SyncCommitteeDutiesResponse, SyncCommitteeMessage, SyncingData, SyncingResponse,
    ValidatorsResponse, VersionedAttestation, VersionedSignedAggregateAndProof,
};
pub use eth_types::{
    ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedValidatorRegistration,
    ValidatorRegistrationV1,
};
