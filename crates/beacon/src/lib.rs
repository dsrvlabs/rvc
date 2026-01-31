//! HTTP client for Ethereum Beacon Node API
//!
//! Provides async HTTP client with retry logic for beacon node communication.

mod client;
mod error;
mod types;

pub use client::{BeaconClient, BeaconClientConfig};
pub use error::BeaconError;
pub use types::{
    Attestation, AttestationData, AttestationDataResponse, AttesterDutiesResponse, AttesterDuty,
    BeaconBlockHeader, Checkpoint, DataResponse, DependentRootResponse, IndexedAttestationError,
    SubmitAttestationResult, ValidatorData, ValidatorInfo, ValidatorsResponse,
};
