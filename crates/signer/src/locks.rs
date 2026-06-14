//! Per-validator async lock map for serializing signing operations.
//!
//! Prevents TOCTOU races where two concurrent sign requests for the same
//! validator could both pass the slashing check before either records.
//! Different validators are NOT blocked by each other.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::OwnedMutexGuard;

/// A map of per-pubkey async mutexes.
///
/// The outer map is protected by a short-held `parking_lot::Mutex` (sync,
/// non-async) used only to get-or-insert an `Arc<tokio::sync::Mutex<()>>`.
/// The per-pubkey async lock is then acquired with `lock_owned().await`,
/// which is `Send` and can be held across `.await` points.
///
/// This serializes concurrent signs for the **same** pubkey while allowing
/// different pubkeys to proceed in parallel.
pub struct ValidatorLockMap {
    locks: parking_lot::Mutex<HashMap<[u8; 48], Arc<tokio::sync::Mutex<()>>>>,
}

impl ValidatorLockMap {
    /// Create a new, empty lock map.
    pub fn new() -> Self {
        Self { locks: parking_lot::Mutex::new(HashMap::new()) }
    }

    /// Get the `Arc<tokio::sync::Mutex<()>>` for a pubkey, inserting a new one
    /// if it does not yet exist.  The outer map lock is released before returning.
    pub fn get(&self, pubkey: &[u8; 48]) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .entry(*pubkey)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Acquire the per-pubkey async lock, returning an `OwnedMutexGuard` that
    /// is `Send` and can be held across `.await` points.
    ///
    /// The outer map lock is held only briefly during the get-or-insert; the
    /// async lock acquisition happens after it is released.
    pub async fn lock(&self, pubkey: &[u8; 48]) -> OwnedMutexGuard<()> {
        self.get(pubkey).lock_owned().await
    }
}

impl Default for ValidatorLockMap {
    fn default() -> Self {
        Self::new()
    }
}
