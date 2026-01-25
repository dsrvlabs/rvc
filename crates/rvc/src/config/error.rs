//! Configuration error types.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    FileNotFound(PathBuf),

    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("invalid beacon URL: {0}")]
    InvalidBeaconUrl(String),

    #[error("keystore path does not exist: {0}")]
    KeystorePathNotFound(PathBuf),

    #[error("slashing db path parent directory does not exist: {0}")]
    SlashingDbPathInvalid(PathBuf),

    #[error("invalid network: {0}")]
    InvalidNetwork(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid port number: {0}")]
    InvalidPort(u16),

    #[error("password file not found: {0}")]
    PasswordFileNotFound(PathBuf),

    #[error("failed to read password file: {0}")]
    PasswordReadError(String),

    #[error("key manager error: {0}")]
    KeyManagerError(#[from] crate::crypto::KeyManagerError),

    #[error("slashing db error: {0}")]
    SlashingDbError(#[from] crate::slashing::SlashingError),

    #[error("beacon client error: {0}")]
    BeaconClientError(#[from] crate::beacon::BeaconError),
}
