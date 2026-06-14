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
//!    signing occurs, and no slashing-DB row is written.
//! 3. Stage → sign → commit/discard — run inside `tokio::task::spawn_blocking`
//!    because `StagedBlock`/`StagedAttestation` hold a `parking_lot::MutexGuard`
//!    (`!Send`) and must not cross a real `.await`.  The async sign call is
//!    driven via `Handle::current().block_on(timeout(dur, signer.sign(...)))` on
//!    the same blocking thread; a timeout maps to `SigningFailed` with an
//!    immediate `discard()` so the staged row is rolled back (no phantom row).
//!    On sign success the staged row is committed; on sign failure it is
//!    discarded (M-1 property — no phantom row on signer error).
//!
//! # Cancellation safety and the true double-sign authoritative lock
//!
//! The per-pubkey `OwnedMutexGuard` (tokio async lock) is held on the *async*
//! task until `spawn_blocking(...).await` completes.  **If the caller drops the
//! future mid-flight at that `.await` point, the tokio lock is released while
//! the blocking task continues to run.**
//!
//! This is safe because the AUTHORITATIVE double-sign serializer is the
//! `parking_lot::MutexGuard<Connection>` held inside the `StagedBlock` /
//! `StagedAttestation` guard: it owns a `BEGIN IMMEDIATE` SQLite transaction that
//! keeps all other writers out of the database until `commit()` or `discard()` is
//! called.  The blocked task therefore still has exclusive DB access; it will
//! complete (commit or rollback) atomically regardless of the caller's state.
//! The per-pubkey tokio lock provides an *additional* latency benefit — it avoids
//! queuing multiple blocking tasks for the same pubkey — but the no-double-sign
//! invariant is upheld by SQLite even if that outer lock is lost to cancellation.
//!
//! # Signer timeout (BUG-003)
//!
//! The staging guard holds the SQLite single-writer `parking_lot::MutexGuard`
//! across the stage→sign→commit window.  A wedged remote signer would hold this
//! write lock indefinitely, causing a signing blackout for ALL validators (they
//! queue behind the same lock).  The gate therefore wraps the sign call in a
//! `tokio::time::timeout`; on expiry the staged guard is discarded (ROLLBACK) and
//! `Err(SigningFailed("signer timed out"))` is returned.  The default is 4 seconds
//! (well under a 12-second Ethereum slot).  Configure with `with_sign_timeout`.
//!
//! # Non-slashable methods
//!
//! Stubs returning `Err(SigningGateError::SigningFailed("not yet implemented"))`.
//! Issue 2.9b will fill the bodies; the signatures here are fixed so callers can
//! compile today.

use std::sync::Arc;
use std::time::Duration;

use crypto::{logging::TruncatedPubkey, CompositeSigner, PublicKey, Signer, SigningError};
use doppelganger::SigningEnablement;
use eth_types::Root;
use slashing::{PubkeyScopedDb, SlashingDb};
use tracing::{error, warn};

use crate::error::SigningGateError;
use crate::locks::ValidatorLockMap;

/// Audit CN recorded in `PubkeyScopedDb` for all gate-originated staging calls.
const AUDIT_CN: &str = "signing-gate";

/// Default per-sign timeout: 4 seconds — well under a 12-second Ethereum slot.
///
/// Bounding the signer call is mandatory because the staging guard holds the
/// SQLite single-writer connection mutex.  See module doc for BUG-003 analysis.
const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(4);

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
    /// BLS signing backend.  Stored as `Arc<dyn Signer>` so tests can inject
    /// a slow/failing backend without changing production APIs.
    signer: Arc<dyn Signer>,
    locks: Arc<ValidatorLockMap>,
    /// Maximum wall-clock duration allowed for a single BLS sign call.
    ///
    /// Expiry triggers `discard()` on the staged guard (ROLLBACK) and returns
    /// `Err(SigningFailed("signer timed out"))`.  Defaults to 4 seconds.
    sign_timeout: Duration,
}

impl SigningGate {
    /// Construct a new `SigningGate` with the default 4-second sign timeout.
    pub fn new(
        slashing_db: Arc<SlashingDb>,
        enablement: Arc<dyn SigningEnablement>,
        signer: Arc<CompositeSigner>,
        locks: Arc<ValidatorLockMap>,
    ) -> Self {
        Self {
            slashing_db,
            enablement,
            signer: signer as Arc<dyn Signer>,
            locks,
            sign_timeout: DEFAULT_SIGN_TIMEOUT,
        }
    }

    /// Override the per-sign timeout (builder style).
    ///
    /// Issue 2.10 wiring uses this to pass the operator-configured timeout.
    pub fn with_sign_timeout(mut self, timeout: Duration) -> Self {
        self.sign_timeout = timeout;
        self
    }

    /// Constructor accepting any `Signer` implementation.
    ///
    /// Intended primarily for integration tests that need to inject slow or
    /// failing backends (e.g. to exercise the sign timeout).  Production code
    /// should use `new()` which constrains the signer to `CompositeSigner`.
    pub fn new_with_raw_signer(
        slashing_db: Arc<SlashingDb>,
        enablement: Arc<dyn SigningEnablement>,
        signer: Arc<dyn Signer>,
        locks: Arc<ValidatorLockMap>,
        sign_timeout: Duration,
    ) -> Self {
        Self { slashing_db, enablement, signer, locks, sign_timeout }
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
    /// # Returns
    ///
    /// On success: the raw BLS signature bytes (96 bytes).
    ///
    /// # Defense-in-depth
    ///
    /// 1. Acquire per-pubkey async lock (see module doc on cancellation).
    /// 2. `is_signing_enabled` gate — fails closed on false.
    /// 3. Stage → sign (with timeout) → commit/discard (spawn_blocking +
    ///    Handle::block_on).  On stage error → `BlockedBySlashingDb` (slot
    ///    consumed).  On commit error → `SlashingDbCommitFailed` (nothing written;
    ///    same-root retry safe).  On sign error → `discard()` (no phantom row).
    pub async fn sign_block(
        &self,
        pubkey: &PublicKey,
        slot: u64,
        signing_root: Root,
        gvr: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_bytes = pubkey.to_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        // Step 1: per-pubkey async lock (Send-safe OwnedMutexGuard).
        //
        // CANCELLATION NOTE: if the caller drops this future at the
        // `spawn_blocking(...).await` below, this guard is released while the
        // blocking task keeps running.  The authoritative double-sign serializer
        // is the SQLite `BEGIN IMMEDIATE` lock held by `StagedBlock`; see module
        // doc for the full analysis.
        let _guard = self.locks.lock(&pubkey_bytes).await;

        // Step 2: doppelganger gate.
        if !self.enablement.is_signing_enabled(pubkey) {
            warn!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                slot,
                "SigningGate: sign_block blocked by doppelganger gate"
            );
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        // Step 3: stage → sign (with timeout) → commit/discard inside spawn_blocking.
        //
        // `StagedBlock<'_>` holds a `parking_lot::MutexGuard` (`!Send`).
        // Keeping everything inside `spawn_blocking` ensures the guard never
        // crosses a real `.await`.  The async sign call is driven via
        // `Handle::current().block_on(timeout(..., signer.sign(...)))` on the
        // same blocking thread — the canonical pattern for calling async code from
        // spawn_blocking.  The timeout bounds the write-lock hold duration.
        let db = Arc::clone(&self.slashing_db);
        let signer = Arc::clone(&self.signer);
        let handle = tokio::runtime::Handle::current();
        let sign_timeout = self.sign_timeout;
        let pubkey_hex_clone = pubkey_hex.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SigningGateError> {
            let signing_root_hex = hex::encode(signing_root);
            let scoped = PubkeyScopedDb::new(Arc::clone(&db), AUDIT_CN.to_string(), gvr);

            let staged = scoped
                .stage_block(&pubkey_hex_clone, slot, Some(signing_root_hex))
                .map_err(|e| {
                    error!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        slot,
                        rejection_reason = %e,
                        "SigningGate: sign_block blocked by slashing protection"
                    );
                    SigningGateError::BlockedBySlashingDb(e)
                })?;

            let sign_result = handle.block_on(tokio::time::timeout(
                sign_timeout,
                signer.sign(&signing_root, &pubkey_bytes),
            ));

            match sign_result {
                // Timeout — discard staged row (no phantom) and return error.
                Err(_elapsed) => {
                    staged.discard();
                    error!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        slot,
                        timeout_secs = sign_timeout.as_secs_f64(),
                        "SigningGate: sign_block signer timed out; staged row discarded"
                    );
                    Err(SigningGateError::SigningFailed("signer timed out".to_string()))
                }

                // Sign succeeded — commit the staged row.
                Ok(Ok(sig)) => {
                    staged.commit().map_err(|e| {
                        error!(
                            pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                            slot,
                            error = %e,
                            "SigningGate: sign_block commit failed after successful sign"
                        );
                        SigningGateError::SlashingDbCommitFailed(e)
                    })?;
                    Ok(sig.to_bytes().to_vec())
                }

                // Key not found — discard staged row (no phantom).
                Ok(Err(SigningError::KeyNotFound(_))) => {
                    staged.discard();
                    warn!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        slot,
                        "SigningGate: sign_block key not found; staged row discarded"
                    );
                    Err(SigningGateError::KeyNotFound)
                }

                // Other signer error — discard staged row (no phantom).
                Ok(Err(e)) => {
                    staged.discard();
                    error!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        slot,
                        error = %e,
                        "SigningGate: sign_block signer error; staged row discarded"
                    );
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
    /// # Returns
    ///
    /// On success: the raw BLS signature bytes (96 bytes).
    ///
    /// # Defense-in-depth
    ///
    /// Identical flow to `sign_block`: lock → enablement gate →
    /// stage + sign (with timeout) + commit/discard (spawn_blocking + Handle::block_on).
    /// On stage error → `BlockedBySlashingDb` (epoch consumed).
    /// On commit error → `SlashingDbCommitFailed` (nothing written; same-root retry safe).
    /// On sign error → `discard()` (no phantom row).
    pub async fn sign_attestation(
        &self,
        pubkey: &PublicKey,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: Root,
        gvr: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_bytes = pubkey.to_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        // Step 1: per-pubkey async lock (see CANCELLATION NOTE in sign_block).
        let _guard = self.locks.lock(&pubkey_bytes).await;

        // Step 2: doppelganger gate.
        if !self.enablement.is_signing_enabled(pubkey) {
            warn!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                source_epoch,
                target_epoch,
                "SigningGate: sign_attestation blocked by doppelganger gate"
            );
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        // Step 3: stage → sign (with timeout) → commit/discard inside spawn_blocking.
        let db = Arc::clone(&self.slashing_db);
        let signer = Arc::clone(&self.signer);
        let handle = tokio::runtime::Handle::current();
        let sign_timeout = self.sign_timeout;
        let pubkey_hex_clone = pubkey_hex.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SigningGateError> {
            let signing_root_hex = hex::encode(signing_root);
            let scoped = PubkeyScopedDb::new(Arc::clone(&db), AUDIT_CN.to_string(), gvr);

            let staged = scoped
                .stage_attestation(
                    &pubkey_hex_clone,
                    source_epoch,
                    target_epoch,
                    Some(signing_root_hex),
                )
                .map_err(|e| {
                    error!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        source_epoch,
                        target_epoch,
                        rejection_reason = %e,
                        "SigningGate: sign_attestation blocked by slashing protection"
                    );
                    SigningGateError::BlockedBySlashingDb(e)
                })?;

            let sign_result = handle.block_on(tokio::time::timeout(
                sign_timeout,
                signer.sign(&signing_root, &pubkey_bytes),
            ));

            match sign_result {
                // Timeout — discard staged row (no phantom) and return error.
                Err(_elapsed) => {
                    staged.discard();
                    error!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        source_epoch,
                        target_epoch,
                        timeout_secs = sign_timeout.as_secs_f64(),
                        "SigningGate: sign_attestation signer timed out; staged row discarded"
                    );
                    Err(SigningGateError::SigningFailed("signer timed out".to_string()))
                }

                // Sign succeeded — commit the staged row.
                Ok(Ok(sig)) => {
                    staged.commit().map_err(|e| {
                        error!(
                            pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                            source_epoch,
                            target_epoch,
                            error = %e,
                            "SigningGate: sign_attestation commit failed after successful sign"
                        );
                        SigningGateError::SlashingDbCommitFailed(e)
                    })?;
                    Ok(sig.to_bytes().to_vec())
                }

                // Key not found — discard staged row (no phantom).
                Ok(Err(SigningError::KeyNotFound(_))) => {
                    staged.discard();
                    warn!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        source_epoch,
                        target_epoch,
                        "SigningGate: sign_attestation key not found; staged row discarded"
                    );
                    Err(SigningGateError::KeyNotFound)
                }

                // Other signer error — discard staged row (no phantom).
                Ok(Err(e)) => {
                    staged.discard();
                    error!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex_clone),
                        source_epoch,
                        target_epoch,
                        error = %e,
                        "SigningGate: sign_attestation signer error; staged row discarded"
                    );
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
    //
    // These stubs return `Err(SigningFailed("not yet implemented"))` rather than
    // panicking, so a stray call during the 2.9a window returns a well-formed
    // error rather than crashing a tokio worker.  Issue 2.9b replaces the bodies.

    /// Sign a sync committee message. (Issue 2.9b stub)
    pub async fn sign_sync_committee_message(&self) -> Result<Vec<u8>, SigningGateError> {
        Err(SigningGateError::SigningFailed(
            "sign_sync_committee_message not yet implemented (Issue 2.9b)".to_string(),
        ))
    }

    /// Sign an aggregate-and-proof. (Issue 2.9b stub)
    pub async fn sign_aggregate_and_proof(&self) -> Result<Vec<u8>, SigningGateError> {
        Err(SigningGateError::SigningFailed(
            "sign_aggregate_and_proof not yet implemented (Issue 2.9b)".to_string(),
        ))
    }

    /// Sign a contribution-and-proof. (Issue 2.9b stub)
    pub async fn sign_contribution_and_proof(&self) -> Result<Vec<u8>, SigningGateError> {
        Err(SigningGateError::SigningFailed(
            "sign_contribution_and_proof not yet implemented (Issue 2.9b)".to_string(),
        ))
    }

    /// Sign a sync committee selection proof. (Issue 2.9b stub)
    pub async fn sign_selection_proof(&self) -> Result<Vec<u8>, SigningGateError> {
        Err(SigningGateError::SigningFailed(
            "sign_selection_proof not yet implemented (Issue 2.9b)".to_string(),
        ))
    }

    /// Sign a RANDAO reveal. (Issue 2.9b stub)
    pub async fn sign_randao_reveal(&self) -> Result<Vec<u8>, SigningGateError> {
        Err(SigningGateError::SigningFailed(
            "sign_randao_reveal not yet implemented (Issue 2.9b)".to_string(),
        ))
    }

    /// Sign a voluntary exit. (Issue 2.9b stub)
    pub async fn sign_voluntary_exit(&self) -> Result<Vec<u8>, SigningGateError> {
        Err(SigningGateError::SigningFailed(
            "sign_voluntary_exit not yet implemented (Issue 2.9b)".to_string(),
        ))
    }

    /// Sign a builder registration. (Issue 2.9b stub)
    pub async fn sign_builder_registration(&self) -> Result<Vec<u8>, SigningGateError> {
        Err(SigningGateError::SigningFailed(
            "sign_builder_registration not yet implemented (Issue 2.9b)".to_string(),
        ))
    }
}
