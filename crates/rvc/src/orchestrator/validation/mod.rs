//! Local validation helpers for BN-supplied consensus objects.
//!
//! This module mirrors `crates/block-service/src/validation.rs` for the
//! attestation path.  All validators run synchronously before any signing call
//! and return typed errors so the caller can log and drop the duty cleanly.

pub mod attestation_data;
