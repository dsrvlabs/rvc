//! HTTP client for Ethereum Beacon Node API
//!
//! Provides async HTTP client with retry logic for beacon node communication.

mod client;
mod error;
mod types;

pub use client::{BeaconClient, BeaconClientConfig};
pub use error::BeaconError;
pub use types::{
    parse_fork_schedule, AggregateAttestationResponse, Attestation, AttestationData,
    AttestationDataResponse, AttesterDutiesResponse, AttesterDuty, BeaconBlockHeader,
    BeaconCommitteeSubscription, BlockRootData, BlockRootResponse, Checkpoint, ConfigSpecResponse,
    DataResponse, DependentRootResponse, ExecutionOptimisticResponse, GenesisData, GenesisResponse,
    IndexedAttestationError, ProduceBlockResponse, ProposerDutiesResponse, ProposerDuty,
    ProposerPreparation, SignedAggregateAndProof, SignedContributionAndProof, StateFork,
    StateForkResponse, StateResponse, SubmitAttestationResult, SyncCommitteeContributionResponse,
    SyncCommitteeDutiesResponse, SyncCommitteeMessage, SyncingData, SyncingResponse, ValidatorData,
    ValidatorInfo, ValidatorLiveness, ValidatorLivenessResponse, ValidatorsResponse,
};
