//! rvc - Rust Validator Client

pub mod background_tasks;
pub mod beacon_adapter;
pub mod bootstrap;
pub mod config;
pub mod deletion_denylist;
pub mod doppelganger_adapter;
pub mod grpc_health;
pub mod key_admission;
pub mod keymanager_adapters;
pub mod liveness_loop;
pub mod metrics;
pub mod orchestrator;
pub mod pubkey_index;
pub mod slashing_monitor;
pub mod startup;

pub mod proto {
    pub mod duty_tracker {
        tonic::include_proto!("duty_tracker");
    }
}

pub use proto::duty_tracker::duty_tracker_server::DutyTrackerServer;
