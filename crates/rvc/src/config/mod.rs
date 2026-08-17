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
    redact_url, BeaconNodeEntry, BroadcastTopic, BuilderLimits, BuilderLimitsArgs, CliOverrides,
    Config, GcpSecretArgs, GcpSecretConfig, GrpcSignerArgs, GrpcSignerConfig, KeymanagerArgs,
    KeymanagerConfig, KeysArgs, LogfileArgs, LogfileConfig, MonitoringArgs, MonitoringConfig,
    ProposerConfigArgs, ProposerConfigSource, SecretProviderArgs, SecretProviderConfig,
    SlashedAction, TracingArgs, TracingConfig, TracingExporter,
};
pub use validator_store::BlockSelectionMode;
