//! Beacon node manager with multi-BN support, failover, and health tracking.

mod traits;

pub use traits::{BeaconNodeClient, BnHealthScore, BnManagerConfig, BnSelectionStrategy};
