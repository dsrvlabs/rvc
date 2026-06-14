//! `SigningGate` — the central signing seam for validator operations.
//!
//! Composes slashing protection, doppelganger detection, BLS signing, and
//! per-validator serialization into a single, defense-in-depth gate.
//!
//! # Slashable-signing flow
//!
//! For each slashable operation (`sign_block`, `sign_attestation`):
//!
//! 1. Acquire the per-pubkey async lock from `ValidatorLockMap` (held for the
//!    entire operation).
//! 2. Check `is_signing_enabled` — if false, return
//!    `Err(SigningGateError::BlockedByDoppelganger)` immediately; no staging or
//!    signing occurs.
//! 3. Stage → sign → commit/discard — run inside `tokio::task::spawn_blocking`
//!    because `StagedBlock`/`StagedAttestation` hold a `parking_lot::MutexGuard`
//!    (`!Send`) and must not cross a real `.await`.  The async sign call is
//!    driven via `Handle::current().block_on(...)` on the same blocking thread.
//!    On sign success the staged row is committed; on sign failure the staged row
//!    is discarded so no phantom row is left in the DB (M-1 property).
//!
//! # Non-slashable methods
//!
//! Stubbed with `todo!()` — filled by Issue 2.9b.

use std::sync::Arc;

use crypto::{CompositeSigner, PublicKey, Signer, SigningError};
use doppelganger::SigningEnablement;
use eth_types::Root;
use slashing::{PubkeyScopedDb, SlashingDb};

use crate::error::SigningGateError;
use crate::locks::ValidatorLockMap;

/// Central signing gate with slashing protection and doppelganger detection.
///
/// # Signature contract
///
/// `sign_block` / `sign_attestation` receive a **pre-computed** `signing_root`
/// and `gvr` from the caller (the v2 handler computes domain + signing root
/// before calling the gate).  The gate stages `pubkey / slot|epochs /
/// signing_root_hex` in the slashing DB, then signs `signing_root` via the
/// BLS backend.
pub struct SigningGate {
    slashing_db: Arc<SlashingDb>,
    enablement: Arc<dyn SigningEnablement>,
    signer: Arc<CompositeSigner>,
    locks: Arc<ValidatorLockMap>,
}

impl SigningGate {
    /// Construct a new `SigningGate`.
    pub fn new(
        slashing_db: Arc<SlashingDb>,
        enablement: Arc<dyn SigningEnablement>,
        signer: Arc<CompositeSigner>,
        locks: Arc<ValidatorLockMap>,
    ) -> Self {
        Self { slashing_db, enablement, signer, locks }
    }

    /// Sign a beacon block proposal.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `slot`: The slot being proposed.
    /// - `signing_root`: The pre-computed signing root (caller applies domain).
    /// - `gvr`: Genesis validators root — passed to `PubkeyScopedDb` for the
    ///   M-6 GVR pinning check.
    ///
    /// # Defense-in-depth
    ///
    /// 1. Acquire per-pubkey async lock.
    /// 2. `is_signing_enabled` gate — fails closed on false.
    /// 3. Stage → sign → commit/discard (spawn_blocking + Handle::block_on).
    pub async fn sign_block(
        &self,
        pubkey: &PublicKey,
        slot: u64,
        signing_root: Root,
        gvr: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_bytes = pubkey.to_bytes();

        // Step 1: per-pubkey async lock (Send-safe OwnedMutexGuard).
        let _guard = self.locks.lock(&pubkey_bytes).await;

        // Step 2: doppelganger gate.
        if !self.enablement.is_signing_enabled(pubkey) {
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        // Step 3: stage → sign → commit/discard inside spawn_blocking.
        //
        // `StagedBlock<'_>` holds a `parking_lot::MutexGuard` (`!Send`).
        // Keeping everything inside `spawn_blocking` ensures the guard never
        // crosses a real `.await`.  The async sign call is driven via
        // `Handle::current().block_on(...)` on the same blocking thread —
        // the canonical pattern for calling async code from spawn_blocking.
        let db = Arc::clone(&self.slashing_db);
        let signer = Arc::clone(&self.signer);
        let handle = tokio::runtime::Handle::current();
        let pubkey_hex = hex::encode(pubkey_bytes);

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SigningGateError> {
            let signing_root_hex = hex::encode(signing_root);
            let scoped = PubkeyScopedDb::new(Arc::clone(&db), "signing-gate".to_string(), gvr);

            let staged = scoped
                .stage_block(&pubkey_hex, slot, Some(signing_root_hex))
                .map_err(SigningGateError::BlockedBySlashingDb)?;

            let sign_result = handle.block_on(signer.sign(&signing_root, &pubkey_bytes));

            match sign_result {
                Ok(sig) => {
                    staged.commit().map_err(SigningGateError::BlockedBySlashingDb)?;
                    Ok(sig.to_bytes().to_vec())
                }
                Err(SigningError::KeyNotFound(_)) => {
                    staged.discard();
                    Err(SigningGateError::KeyNotFound)
                }
                Err(e) => {
                    staged.discard();
                    Err(SigningGateError::SigningFailed(e.to_string()))
                }
            }
        })
        .await
        .map_err(|e| SigningGateError::SigningFailed(format!("sign_block task panicked: {e}")))?
    }

    /// Sign an attestation.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `source_epoch`: The attestation source epoch (for slashing check).
    /// - `target_epoch`: The attestation target epoch (for slashing check).
    /// - `signing_root`: The pre-computed signing root (caller applies domain).
    /// - `gvr`: Genesis validators root — passed to `PubkeyScopedDb` for the
    ///   M-6 GVR pinning check.
    ///
    /// # Defense-in-depth
    ///
    /// Identical flow to `sign_block`: lock → enablement gate →
    /// stage + sign + commit/discard (spawn_blocking + Handle::block_on).
    pub async fn sign_attestation(
        &self,
        pubkey: &PublicKey,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: Root,
        gvr: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_bytes = pubkey.to_bytes();

        // Step 1: per-pubkey async lock.
        let _guard = self.locks.lock(&pubkey_bytes).await;

        // Step 2: doppelganger gate.
        if !self.enablement.is_signing_enabled(pubkey) {
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        // Step 3: stage → sign → commit/discard inside spawn_blocking.
        let db = Arc::clone(&self.slashing_db);
        let signer = Arc::clone(&self.signer);
        let handle = tokio::runtime::Handle::current();
        let pubkey_hex = hex::encode(pubkey_bytes);

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SigningGateError> {
            let signing_root_hex = hex::encode(signing_root);
            let scoped = PubkeyScopedDb::new(Arc::clone(&db), "signing-gate".to_string(), gvr);

            let staged = scoped
                .stage_attestation(&pubkey_hex, source_epoch, target_epoch, Some(signing_root_hex))
                .map_err(SigningGateError::BlockedBySlashingDb)?;

            let sign_result = handle.block_on(signer.sign(&signing_root, &pubkey_bytes));

            match sign_result {
                Ok(sig) => {
                    staged.commit().map_err(SigningGateError::BlockedBySlashingDb)?;
                    Ok(sig.to_bytes().to_vec())
                }
                Err(SigningError::KeyNotFound(_)) => {
                    staged.discard();
                    Err(SigningGateError::KeyNotFound)
                }
                Err(e) => {
                    staged.discard();
                    Err(SigningGateError::SigningFailed(e.to_string()))
                }
            }
        })
        .await
        .map_err(|e| {
            SigningGateError::SigningFailed(format!("sign_attestation task panicked: {e}"))
        })?
    }

    // ── Non-slashable stubs (Issue 2.9b) ─────────────────────────────────────

    /// Sign a sync committee message. (Issue 2.9b stub)
    pub async fn sign_sync_committee_message(&self) -> ! {
        todo!("sign_sync_committee_message: implemented in Issue 2.9b")
    }

    /// Sign an aggregate-and-proof. (Issue 2.9b stub)
    pub async fn sign_aggregate_and_proof(&self) -> ! {
        todo!("sign_aggregate_and_proof: implemented in Issue 2.9b")
    }

    /// Sign a contribution-and-proof. (Issue 2.9b stub)
    pub async fn sign_contribution_and_proof(&self) -> ! {
        todo!("sign_contribution_and_proof: implemented in Issue 2.9b")
    }

    /// Sign a sync committee selection proof. (Issue 2.9b stub)
    pub async fn sign_selection_proof(&self) -> ! {
        todo!("sign_selection_proof: implemented in Issue 2.9b")
    }

    /// Sign a RANDAO reveal. (Issue 2.9b stub)
    pub async fn sign_randao_reveal(&self) -> ! {
        todo!("sign_randao_reveal: implemented in Issue 2.9b")
    }

    /// Sign a voluntary exit. (Issue 2.9b stub)
    pub async fn sign_voluntary_exit(&self) -> ! {
        todo!("sign_voluntary_exit: implemented in Issue 2.9b")
    }

    /// Sign a builder registration. (Issue 2.9b stub)
    pub async fn sign_builder_registration(&self) -> ! {
        todo!("sign_builder_registration: implemented in Issue 2.9b")
    }
}
