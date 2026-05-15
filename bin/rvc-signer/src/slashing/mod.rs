//! Per-`client_cn` slashing protection wrapper for rvc-signer.
//!
//! This module is **internal to `bin/rvc-signer`**.  Do not re-export from a
//! public crate.  The `ScopedSlashingDb` type captures a `(client_cn, gvr)`
//! pair so individual call sites don't have to thread those arguments through
//! every signing RPC.

pub mod config;
pub mod scope;

pub use config::{SlashingDbConfig, SlashingProtectionMode};
pub use scope::ScopedSlashingDb;
