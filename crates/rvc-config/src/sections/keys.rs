//! Keys clap group (ARCH-4g).
//!
//! Created here so [`KeysArgs`] can flatten [`SecretProviderArgs`] (A-4.5).
//! Nested flatten is clap-supported; the sibling-group fallback is not taken.
//!
//! The five remaining bare knobs (`keystore_path`, `password_file`,
//! `key_decrypt_threads`, `disable_keystore_locking`, `validators_config`)
//! already live on this clap group. ARCH-4h will add a `[keys]` TOML table
//! for them; this issue must not invent that table (Config still has them
//! top-level).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::secret_provider::SecretProviderArgs;

/// Clap group for keystore paths plus flattened [`SecretProviderArgs`] (A-4.5).
///
/// Not a Config / TOML section in ARCH-4g — `[secret_provider]` stays its own
/// table. `#[serde(deny_unknown_fields)]` applies only if this type is
/// deserialized standalone.
#[derive(Debug, Clone, PartialEq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysArgs {
    /// Path to the keystore directory
    #[arg(long = "keystore-path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore_path: Option<PathBuf>,

    /// Path to the password file for keystore decryption
    #[arg(long = "password-file")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_file: Option<PathBuf>,

    /// Number of threads for parallel keystore decryption (default: auto-detect)
    #[arg(long = "key-decrypt-threads")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_decrypt_threads: Option<usize>,

    /// Disable keystore file locking (for DVT setups with shared key material)
    #[arg(long = "disable-keystore-locking")]
    #[serde(skip)]
    pub disable_keystore_locking: bool,

    /// Path to a TOML file containing per-validator fee_recipient and gas_limit overrides.
    /// rvc refuses to start if default_fee_recipient is the zero address (0x000…000).
    ///
    /// Example file:
    ///   [defaults]
    ///   fee_recipient = "0xYourAddress"
    ///   gas_limit = 30000000
    #[arg(long = "validators-config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validators_config: Option<PathBuf>,

    /// `[secret_provider]` knobs (A-4.5). Clap-flattened so `--gcp-project-id`
    /// stays a top-level flag.
    #[command(flatten)]
    #[serde(default)]
    pub secret_provider: SecretProviderArgs,
}
