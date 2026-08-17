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
    redact_url, BeaconArgs, BeaconConfig, BeaconNodeEntry, BroadcastTopic, BuilderLimits,
    BuilderLimitsArgs, CliOverrides, Config, GcpSecretArgs, GcpSecretConfig, GrpcSignerArgs,
    GrpcSignerConfig, KeymanagerArgs, KeymanagerConfig, KeysArgs, KeysConfig, LogfileArgs,
    LogfileConfig, MonitoringArgs, MonitoringConfig, NetworkArgs, NetworkConfig,
    ProposerConfigArgs, ProposerConfigSource, SafetyArgs, SafetyConfig, SecretProviderArgs,
    SecretProviderConfig, ServerArgs, ServerConfig, SlashedAction, SlashingArgs, SlashingConfig,
    TracingArgs, TracingConfig, TracingExporter,
};
pub use validator_store::BlockSelectionMode;
