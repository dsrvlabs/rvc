//! rvc - Rust Validator Client

pub mod config;
pub mod duty_tracker;
pub mod orchestrator;

pub use crypto;
pub use metrics;
pub use propagator;
pub use signer;
pub use slashing;
pub use timing;

pub mod proto {
    pub mod duty_tracker {
        tonic::include_proto!("duty_tracker");
    }
}

pub use proto::duty_tracker::duty_tracker_server::DutyTrackerServer;
