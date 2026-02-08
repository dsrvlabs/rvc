//! rvc - Rust Validator Client

pub mod config;
pub mod crypto;
pub mod duty_tracker;
pub mod orchestrator;

pub use metrics;
pub mod propagator;
pub mod signer;
pub mod slashing;
pub mod timing;

pub mod proto {
    pub mod duty_tracker {
        tonic::include_proto!("duty_tracker");
    }
}

pub use proto::duty_tracker::duty_tracker_server::DutyTrackerServer;
