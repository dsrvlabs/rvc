//! rvc - Rust Validator Client

pub mod beacon_adapter;
pub mod config;
pub mod doppelganger_adapter;
pub mod duty_tracker;
pub mod keymanager_adapters;
pub mod orchestrator;
pub mod slashing_monitor;
pub mod startup;

pub mod proto {
    pub mod duty_tracker {
        tonic::include_proto!("duty_tracker");
    }
}

pub use proto::duty_tracker::duty_tracker_server::DutyTrackerServer;
