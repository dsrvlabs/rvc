//! Slashing protection configuration for rvc-signer.
//!
//! `ScopedSlashingDb` has been removed (Issue 2.5).  Call sites now use
//! `slashing::PubkeyScopedDb` directly.  This module is kept for the
//! `SlashingDbConfig` / `SlashingProtectionMode` configuration types.

pub mod config;

pub use config::{SlashingDbConfig, SlashingProtectionMode};
