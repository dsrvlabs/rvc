//! Validator-client bootstrap phases.
//!
//! Each phase is a free function that takes [`Config`](crate::config::Config) (and
//! explicit parameters) and returns a small named output struct. A future
//! `run()` will move those outputs into [`BootstrapCtx`]. Phases never take
//! `&mut BootstrapCtx`.
//!
//! # Health-status policy
//!
//! Health-status updates stay in `bin/rvc` for now: phase functions return
//! `Result` only. Callers mark `slashing_db_initialized` (and similar) after a
//! successful phase. This keeps `crates/rvc` free of binary-only health plumbing
//! while unit tests can exercise phases without a metrics server.

mod slashing;

pub use slashing::{open_slashing_db, KeystoreLockGuard, SlashingDbHandles};

use std::sync::Arc;

// `::slashing` is the external crate; submodule `slashing` would otherwise shadow it.
use ::slashing::SlashingDb;

use crate::config::ConfigError;
use crate::deletion_denylist::{DeletionDenylist, DeletionDenylistError};
use crate::startup::StartupError;

/// Values produced by bootstrap phases and consumed by later ones.
///
/// # Invariant
///
/// Every field is populated by exactly one phase and never reassigned. Fields are
/// never an `Option<T>` used as a phase-ordering flag; optional values represent
/// genuine runtime configuration (for example, keystore locking disabled by the
/// operator).
///
/// # Growth rule
///
/// Each subsequent phase may add **at most three** named, doc-commented fields.
/// Prefer returning a small phase-output struct and moving it into this context
/// from `run()` rather than growing a god-blob of interdependent locals.
pub struct BootstrapCtx {
    /// Opened, integrity-checked slashing protection database
    /// (`open_slashing_db`).
    pub slashing_db: Arc<SlashingDb>,
    /// Exclusive keystore-dir lock. `None` only when `disable_keystore_locking`
    /// is set — not a phase-ordering flag.
    pub keystore_lock: Option<KeystoreLockGuard>,
    /// Persistent Keymanager deletion denylist (SEC-1b) (`open_slashing_db`).
    pub deletion_denylist: Arc<DeletionDenylist>,
}

impl BootstrapCtx {
    /// Seed the context from the first phase output.
    pub fn from_slashing_handles(handles: SlashingDbHandles) -> Self {
        Self {
            slashing_db: handles.db,
            keystore_lock: handles.keystore_lock,
            deletion_denylist: handles.denylist,
        }
    }
}

/// Errors from bootstrap phase functions.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Startup(#[from] StartupError),

    #[error(transparent)]
    Denylist(#[from] DeletionDenylistError),

    #[error(transparent)]
    Slashing(#[from] ::slashing::SlashingError),
}

impl BootstrapError {
    /// Process exit code for this failure (matches prior `run_validator` behavior).
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Startup(e) => e.exit_code(),
            _ => 1,
        }
    }

    /// Whether this is a keystore lock contention / acquisition failure.
    pub fn is_keystore_locked(&self) -> bool {
        matches!(self, Self::Startup(StartupError::KeystoreLocked(_)))
    }
}
