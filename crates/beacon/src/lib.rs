//! HTTP client for Ethereum Beacon Node API
//!
//! Provides async HTTP client with retry logic for beacon node communication.

mod client;
mod error;
mod types;

pub use client::{BeaconClient, BeaconClientConfig};
pub use error::BeaconError;
pub use types::{
    parse_fork_schedule, Attestation, AttestationData, AttestationDataResponse,
    AttesterDutiesResponse, AttesterDuty, BeaconBlockHeader, Checkpoint, ConfigSpecResponse,
    DataResponse, DependentRootResponse, GenesisData, GenesisResponse, IndexedAttestationError,
    ProduceBlockResponse, ProposerDutiesResponse, ProposerDuty, StateFork, StateForkResponse,
    StateResponse, SubmitAttestationResult, ValidatorData, ValidatorInfo, ValidatorsResponse,
};
