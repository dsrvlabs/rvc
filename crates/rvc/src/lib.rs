//! rvc - Rust Validator Client

pub mod beacon_adapter;
pub mod config;
pub mod duty_tracker;
pub mod orchestrator;

pub mod proto {
    pub mod duty_tracker {
        tonic::include_proto!("duty_tracker");
    }
}

pub use proto::duty_tracker::duty_tracker_server::DutyTrackerServer;
