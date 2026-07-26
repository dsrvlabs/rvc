//! Configuration module for the validator client.

mod builder;
mod error;
mod network;
mod types;

pub use bn_manager::BnRole;
pub use builder::ServiceBuilder;
pub use error::ConfigError;
pub use network::Network;
pub use types::{
    redact_url, BeaconNodeEntry, BroadcastTopic, CliOverrides, Config, GcpSecretConfig,
    SecretProviderConfig, SlashedAction, TracingExporter,
};
pub use validator_store::BlockSelectionMode;
