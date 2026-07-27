//! Shared helpers for slashing integration tests.
//!
//! Stage-path harnesses introduced by RF1-03 and reused by RF1-05 so
//! conformance and property tests drive the production
//! `stage_* → commit()/discard()` path rather than `check_and_record_*`.

use rvc_slashing::{SlashingDb, SlashingError};

/// Stage a block via the production path and commit on success.
///
/// On rejection, `stage_block` rolls back before returning `Err` (no guard is
/// handed out). On accept, the guard is committed so the row is durable.
///
/// **Guard lifetime:** this helper always resolves the staged guard (commit or
/// early `Err`) before returning, so callers can issue the next `stage_*`
/// without deadlock from holding the connection mutex across iterations.
pub fn stage_and_commit_block(
    db: &SlashingDb,
    pubkey: &str,
    slot: u64,
    signing_root: Option<String>,
    gvr: &[u8; 32],
) -> Result<(), SlashingError> {
    let staged = db.stage_block(pubkey, slot, signing_root, gvr)?;
    staged.commit()
}

/// Stage an attestation via the production path and commit on success.
///
/// See [`stage_and_commit_block`] for success/rejection and guard-lifetime
/// semantics.
pub fn stage_and_commit_attestation(
    db: &SlashingDb,
    pubkey: &str,
    source_epoch: u64,
    target_epoch: u64,
    signing_root: Option<String>,
    gvr: &[u8; 32],
) -> Result<(), SlashingError> {
    let staged = db.stage_attestation(pubkey, source_epoch, target_epoch, signing_root, gvr)?;
    staged.commit()
}
