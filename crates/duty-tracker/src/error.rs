use thiserror::Error;

use bn_manager::BeaconError;

#[derive(Error, Debug)]
pub enum DutyTrackerError {
    #[error("Beacon client error: {0}")]
    BeaconError(#[from] BeaconError),

    #[error("No duties found for slot {slot}, committee index {committee_index}, validator index {validator_index}")]
    DutyNotFound { slot: u64, committee_index: u64, validator_index: u64 },

    #[error("Invalid epoch: {0}")]
    InvalidEpoch(u64),
}
