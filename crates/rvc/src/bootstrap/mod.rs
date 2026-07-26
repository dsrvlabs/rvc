//! Validator-client bootstrap phases and composition root.
//!
//! Each phase is a free function that takes [`Config`](crate::config::Config) (and
//! explicit parameters) and returns a small named output struct. [`run`] composes
//! the phases, owns the duty-loop `select!`, and performs graceful shutdown.
//!
//! Phases never take `&mut BootstrapCtx`. Health-status updates for the production
//! path live inside [`run`]; individual phase functions still return `Result` only
//! so unit tests can exercise them without a metrics server.

mod beacon;
mod enablement;
mod keys;
mod run;
mod services;
mod slashing;
mod tasks;

pub use beacon::{connect_beacon, BeaconHandles};
pub use enablement::{wire_signing_enablement, EnablementHandles};
pub use keys::{load_signing_keys, LoadedKeys};
pub use run::{run, RunOptions};
pub use services::{build_services, ServiceHandles};
pub use slashing::{open_slashing_db, KeystoreLockGuard, SlashingDbHandles};
pub use tasks::{
    check_metrics_bind_gate, spawn_background_tasks, BackgroundTasks,
    METRICS_ALLOW_NON_LOOPBACK_ENV, METRICS_SHUTDOWN_TIMEOUT,
};

use std::sync::Arc;

// `::slashing` is the external crate; submodule `slashing` would otherwise shadow it.
use ::slashing::SlashingDb;

use crate::config::ConfigError;
use crate::deletion_denylist::{DeletionDenylist, DeletionDenylistError};
use crate::keymanager_adapters::SpawnKeymanagerApiError;
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

/// Errors from bootstrap phase functions and [`run`].
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

    /// Validator index resolution failed while doppelganger detection is on.
    #[error("validator index resolution failed; doppelganger detection requires indices: {0}")]
    IndexResolution(String),

    #[error(transparent)]
    Keymanager(#[from] SpawnKeymanagerApiError),

    #[error(transparent)]
    MetricsBind(#[from] crypto::InsecureGateError),

    /// Invalid runtime configuration (e.g. slashed action string, gRPC address).
    #[error("{0}")]
    InvalidConfig(String),
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
