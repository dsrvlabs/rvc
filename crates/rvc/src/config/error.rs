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

    #[error("invalid graffiti: {0}")]
    InvalidGraffiti(String),

    #[error("password file not found: {0}")]
    PasswordFileNotFound(PathBuf),

    #[error("failed to read password file: {0}")]
    PasswordReadError(String),

    #[error("key manager error: {0}")]
    KeyManagerError(#[from] crypto::KeyManagerError),

    #[error("slashing db error: {0}")]
    SlashingDbError(#[from] slashing::SlashingError),

    #[error("beacon client error: {0}")]
    BeaconClientError(#[from] beacon::BeaconError),

    #[error("feature not enabled: {0}")]
    FeatureNotEnabled(String),

    #[error("secret provider error: {0}")]
    SecretProviderError(String),

    #[error(
        "--allow-insecure-remote-signer requires RVC_ALLOW_INSECURE=true environment variable"
    )]
    InsecureFlagRequiresEnvVar,

    /// Returned when the effective default fee recipient is the zero address.
    ///
    /// All EL fees and MEV rewards would be silently routed to the burn
    /// address.  Operators must set a non-zero address in their validators
    /// config file:
    ///
    /// ```toml
    /// [defaults]
    /// fee_recipient = "0x<your-fee-address>"
    /// ```
    #[error(
        "default_fee_recipient is the zero address \
         (0x0000000000000000000000000000000000000000), which routes all EL \
         fees and MEV rewards to the burn address.\n\
         Set a non-zero fee_recipient in your validators config file:\n\
         \n\
         [defaults]\n\
         fee_recipient = \"0x<your-fee-address>\"\n\
         \n\
         Pass the file with --validators-config <path>."
    )]
    ZeroFeeRecipient,

    /// Wraps a `ValidatorStoreError` that occurs during validator store construction.
    #[error("validator store error: {0}")]
    ValidatorStoreError(String),
}
