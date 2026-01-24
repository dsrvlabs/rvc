mod error;
mod types;

pub use error::BeaconError;
pub use types::{
    Attestation, AttestationData, AttesterDuty, BeaconBlockHeader, Checkpoint, DataResponse,
    DependentRootResponse,
};
