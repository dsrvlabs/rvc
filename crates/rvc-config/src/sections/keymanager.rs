//! Keymanager API section (ARCH-4f).
//!
//! Clap group, TOML `[keymanager]` table, and `Config.keymanager` share this module.
//! Valued knobs are `Option<T>` with no clap `default_value` (ADR-009).
//! `--no-keymanager` is CLI-only and is skipped on the serde wire.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn default_keymanager_body_limit() -> usize {
    10 * 1024 * 1024 // 10 MB
}

/// Clap + serde declaration for the keymanager knobs (ADR-008).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]`.
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeymanagerArgs {
    /// Enable the Keymanager API server
    #[arg(
        id = "keymanager_enabled",
        long = "keymanager-enabled",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(alias = "keymanager_enabled", skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Disable the Keymanager API server (overrides config file)
    #[arg(long = "no-keymanager", conflicts_with = "keymanager_enabled")]
    #[serde(skip)]
    pub no_keymanager: bool,

    /// Bind address for the Keymanager API server (default: 127.0.0.1:5062)
    #[arg(id = "keymanager_address", long = "keymanager-address")]
    #[serde(alias = "keymanager_address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// Path to the Keymanager API bearer token file
    #[arg(id = "keymanager_token_file", long = "keymanager-token-file")]
    #[serde(alias = "keymanager_token_file", skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,

    /// Remote signer (Web3Signer) URL
    #[arg(long = "remote-signer-url")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signer_url: Option<String>,

    /// Comma-separated list of allowed remote signer hostnames
    #[arg(long = "remote-signer-allowed-hosts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_signer_allowed_hosts: Option<String>,

    /// Allow HTTP (non-TLS) URLs for remote signer imports
    #[arg(
        long = "allow-insecure-remote-signer",
        num_args = 0,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure_remote_signer: Option<bool>,

    /// Comma-separated list of allowed CORS origins for the Keymanager API
    #[arg(id = "keymanager_cors_origins", long = "keymanager-cors-origins", value_delimiter = ',')]
    #[serde(alias = "keymanager_cors_origins", skip_serializing_if = "Option::is_none")]
    pub cors_origins: Option<Vec<String>>,

    /// Maximum request body size in bytes for the Keymanager API (default: 10 MB)
    #[arg(id = "keymanager_body_limit", long = "keymanager-body-limit")]
    #[serde(alias = "keymanager_body_limit", skip_serializing_if = "Option::is_none")]
    pub body_limit: Option<usize>,
}

impl KeymanagerArgs {
    /// Fold this declaration into a [`KeymanagerConfig`].
    ///
    /// Defaults live on `KeymanagerConfig`; load overlays Option fields.
    pub fn resolved(&self) -> KeymanagerConfig {
        let enabled = if self.no_keymanager { false } else { self.enabled.unwrap_or(false) };
        KeymanagerConfig {
            enabled,
            address: self.address.clone(),
            token_file: self.token_file.clone(),
            remote_signer_url: self.remote_signer_url.clone(),
            remote_signer_allowed_hosts: self.remote_signer_allowed_hosts.as_ref().map(|csv| {
                csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
            }),
            allow_insecure_remote_signer: self.allow_insecure_remote_signer.unwrap_or(false),
            cors_origins: self.cors_origins.clone().unwrap_or_default(),
            body_limit: self.body_limit.unwrap_or_else(default_keymanager_body_limit),
        }
    }
}

/// Keymanager API and remote-signer settings (resolved / `Config` field).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeymanagerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_insecure_remote_signer: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cors_origins: Vec<String>,
    #[serde(default = "default_keymanager_body_limit")]
    pub body_limit: usize,
}

impl Default for KeymanagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: None,
            token_file: None,
            remote_signer_url: None,
            remote_signer_allowed_hosts: None,
            allow_insecure_remote_signer: false,
            cors_origins: Vec::new(),
            body_limit: default_keymanager_body_limit(),
        }
    }
}
