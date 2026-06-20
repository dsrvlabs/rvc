//! Slashable-signing wrappers for `SigningGate`.
//!
//! This module groups the two slashable signing operations — block proposals
//! and attestations — exposing them as thin re-exports for documentation and
//! import convenience.  All slashing protection logic lives in
//! [`SigningGate::sign_block`] and [`SigningGate::sign_attestation`].
//!
//! # Slashable-signing flow (summary)
//!
//! 1. Acquire per-validator async lock.
//! 2. Check `SigningEnablement::is_signing_enabled` (doppelganger gate).
//! 3. Run `stage → sign (with timeout) → commit/discard` inside
//!    `tokio::task::spawn_blocking` because the `Staged*` guard holds a
//!    `parking_lot::MutexGuard` (`!Send`).
//! 4. On sign success: commit slashing-DB row.
//! 5. On any failure: discard staged row (no phantom row, M-1 fix).
//!
//! See [`crate::gate`] for the complete implementation.

pub use crate::gate::SigningGate;
