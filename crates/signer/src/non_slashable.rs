//! Non-slashable signing wrappers for `SigningGate`.
//!
//! This module groups all signing operations that do NOT require slashing
//! protection: sync committee messages, aggregate-and-proof, contribution-and-proof,
//! selection proofs, RANDAO reveals, voluntary exits, and builder registrations.
//!
//! # Non-slashable signing flow (summary)
//!
//! 1. Check `SigningEnablement::is_signing_enabled` (doppelganger gate).
//! 2. Call the BLS backend `sign(signing_root, pubkey)` with a timeout.
//!    No slashing-DB staging or committing occurs.
//!
//! Because there is no `!Send` staging guard, these are plain `async` methods
//! with a direct `.await` — no `spawn_blocking` needed.
//!
//! # SS-2/SS-3 invariant (aggregate-and-proof)
//!
//! `sign_aggregate_and_proof` is explicitly **NOT** slashable: the inner
//! attestation is slashable and MUST have already been committed by
//! `sign_attestation`.  Running attestation-slashing staging for an aggregate
//! would be wrong (double-staging and mis-attribution).
//!
//! See [`crate::gate`] for the complete implementation.

pub use crate::gate::SigningGate;
