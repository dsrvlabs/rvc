//! Slashing protection error types.

use thiserror::Error;

/// Errors that can occur during slashing protection operations.
#[derive(Debug, Error)]
pub enum SlashingError {
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("migration error: {0}")]
    MigrationError(String),
}
