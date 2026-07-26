//! Slashable-signing wrappers for `SigningGate`.
//!
//! This module groups the two slashable signing operations — block proposals
//! and attestations — exposing them as thin re-exports for documentation and
//! import convenience.  Gate entry points are [`SigningGate::sign_block`] and
//! [`SigningGate::sign_attestation`]; the stage → sign → commit/discard core
//! lives in [`crate::core::sign_slashable`].
//!
//! # Slashable-signing flow (summary)
//!
//! 1. Outer enablement check (cheap reject).
//! 2. Per-validator async lock + enablement re-check under the lock.
//! 3. `stage → sign (with timeout) → commit/discard` inside
//!    `tokio::task::spawn_blocking` (`Staged*` is `!Send`).
//! 4. Timeout policy is explicit ([`crate::TimeoutPolicy`]); the gate uses
//!    [`TimeoutPolicy::DiscardStagedRow`] (timeout arm only; non-timeout sign
//!    errors still discard today — RF4-06 extends retain for remote ambiguity).
//! 5. Standard RVC slashable metrics via [`crate::StandardSlashableHooks`].
//!
//! See [`crate::core`] and [`crate::gate`] for the complete implementation.

pub use crate::gate::SigningGate;
