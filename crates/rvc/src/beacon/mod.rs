mod client;
mod error;
mod types;

pub use client::{BeaconClient, BeaconClientConfig};
pub use error::BeaconError;
pub use types::{
    Attestation, AttestationData, AttestationDataResponse, AttesterDutiesResponse, AttesterDuty,
    BeaconBlockHeader, Checkpoint, DataResponse, DependentRootResponse,
};
