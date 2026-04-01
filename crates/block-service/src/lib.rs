//! rvc-block-service - Block proposal lifecycle orchestration.
//!
//! Orchestrates RANDAO reveal signing, block production, block signing,
//! and block publication through the beacon node API.

mod error;
mod service;
mod traits;
mod types;

pub use error::BlockServiceError;
pub use service::{BlockProposalResult, BlockService};
pub use traits::{BeaconBlockClient, ProduceBlockResponse};
pub use types::BlockSelectionMode;
