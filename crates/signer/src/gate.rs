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
//! 2. Check `gate_decision` — if false, return
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
//! # Non-slashable signing flow
//!
//! For each non-slashable operation (`sign_sync_committee_message`,
//! `sign_aggregate_and_proof`, `sign_contribution_and_proof`,
//! `sign_selection_proof`, `sign_randao_reveal`, `sign_voluntary_exit`,
//! `sign_builder_registration`):
//!
//! 1. Check `gate_decision` — if false, return
//!    `Err(SigningGateError::BlockedByDoppelganger)` immediately.
//! 2. Call the BLS backend `sign(signing_root, pubkey)` wrapped in the gate's
//!    `tokio::time::timeout` (same duration as slashable, for consistency).
//!    No slashing-DB staging or committing occurs — these operations are not
//!    slashable by the Ethereum consensus spec.
//!
//! Because non-slashable signs carry no `!Send` staging guard, they are plain
//! `async` with a direct `.await` on the signer — no `spawn_blocking` needed.
//!
//! # Gate decision and fail-closed default
//!
//! The single `gate_decision` helper centralises the doppelganger check for
//! all paths (slashable and non-slashable).  It calls `is_signing_enabled` and
//! returns the result.  For unknown pubkeys the `SigningEnablement`
//! implementation (e.g. `ForwardWindowMachine`) returns `false`, matching the
//! fail-closed default `<bool as FailClosedDefault>::default_when_unknown()` = `false`.
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

use std::sync::Arc;
use std::time::Duration;

use crypto::{logging::TruncatedPubkey, CompositeSigner, PublicKey, Signer, SigningError};
use doppelganger::SigningEnablement;
use eth_types::Root;
use slashing::{PubkeyScopedDb, SlashingDb};
use tracing::{error, warn};

use crate::error::SigningGateError;
use crate::fail_closed::FailClosedDefault;
use crate::locks::ValidatorLockMap;

/// Audit CN used in `PubkeyScopedDb` when no caller-supplied CN is available.
///
/// Slashable handlers pass the real mTLS client CN via the `client_cn` parameter
/// of `sign_block` / `sign_attestation`; this constant is the fallback for any
/// call site that does not have an mTLS context (e.g. crate-internal callers and
/// integration tests).
pub const AUDIT_CN_DEFAULT: &str = "signing-gate";

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
///
/// Non-slashable methods receive a **pre-computed** `signing_root`; they
/// gate-check the pubkey and call the BLS backend directly — no slashing DB.
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

    /// Evaluate the doppelganger gate for `pubkey`.
    ///
    /// Returns `true` when signing is permitted, `false` when it is denied.
    ///
    /// # Fail-closed default (PRD §6.3 — unknown → denied)
    ///
    /// For any pubkey that the `SigningEnablement` implementation does not
    /// recognise (e.g. an unregistered validator in `ForwardWindowMachine`),
    /// `is_signing_enabled` returns `false`.  This matches the explicit
    /// fail-closed default `<bool as FailClosedDefault>::default_when_unknown()` = `false`.
    ///
    /// The `debug_assert_eq!` below makes this codification executable: in debug
    /// and test builds it fires if the `FailClosedDefault` contract is ever
    /// changed to a non-false value without updating the gate logic.
    ///
    /// This helper is the single gate-decision point for BOTH slashable and
    /// non-slashable signing paths, ensuring the fail-closed semantics are
    /// applied uniformly.
    fn gate_decision(&self, pubkey: &PublicKey) -> bool {
        let enabled = self.enablement.is_signing_enabled(pubkey);
        // Codify PRD §6.3: when the enablement returns false (unknown or blocked),
        // the gate decision must equal the fail-closed default.  This assert fires
        // in debug/test builds if `FailClosedDefault::default_when_unknown()` is
        // ever changed to a non-false value without a corresponding gate update.
        debug_assert!(
            !<bool as FailClosedDefault>::default_when_unknown(),
            "FailClosedDefault::default_when_unknown() must remain false (PRD §6.3)"
        );
        enabled
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
    /// - `client_cn`: mTLS client CN for the audit-log origin field.  Pass the CN
    ///   extracted by the gRPC handler, or `AUDIT_CN_DEFAULT` when no mTLS context
    ///   is available.
    ///
    /// # Returns
    ///
    /// On success: the raw BLS signature bytes (96 bytes).
    ///
    /// # Defense-in-depth
    ///
    /// 1. Acquire per-pubkey async lock (see module doc on cancellation).
    /// 2. `gate_decision` — fails closed on false (unknown pubkey → denied).
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
        client_cn: &str,
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

        // Step 2: doppelganger gate (single gate-decision point for all paths).
        if !self.gate_decision(pubkey) {
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
        let client_cn_owned = client_cn.to_string();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SigningGateError> {
            let signing_root_hex = hex::encode(signing_root);
            let scoped = PubkeyScopedDb::new(Arc::clone(&db), client_cn_owned, gvr);

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
    /// - `client_cn`: mTLS client CN for the audit-log origin field.  Pass the CN
    ///   extracted by the gRPC handler, or `AUDIT_CN_DEFAULT` when no mTLS context
    ///   is available.
    ///
    /// # Returns
    ///
    /// On success: the raw BLS signature bytes (96 bytes).
    ///
    /// # Defense-in-depth
    ///
    /// Identical flow to `sign_block`: lock → gate_decision →
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
        client_cn: &str,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_bytes = pubkey.to_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        // Step 1: per-pubkey async lock (see CANCELLATION NOTE in sign_block).
        let _guard = self.locks.lock(&pubkey_bytes).await;

        // Step 2: doppelganger gate (single gate-decision point for all paths).
        if !self.gate_decision(pubkey) {
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
        let client_cn_owned = client_cn.to_string();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SigningGateError> {
            let signing_root_hex = hex::encode(signing_root);
            let scoped = PubkeyScopedDb::new(Arc::clone(&db), client_cn_owned, gvr);

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

    // ── Non-slashable signing methods ─────────────────────────────────────────
    //
    // All 7 non-slashable methods share the same 2-step flow:
    //   1. `gate_decision(pubkey)` — fail-closed on false (unknown → denied).
    //   2. `timeout(sign_timeout, signer.sign(...)).await` — no slashing DB,
    //      no spawn_blocking (no !Send guard), no commit/discard.
    //
    // Error mapping is uniform: timeout/generic → SigningFailed,
    // KeyNotFound → KeyNotFound.

    /// Execute the non-slashable signing flow: gate check → BLS sign with timeout.
    ///
    /// Shared by all 7 non-slashable methods so the error-mapping logic lives
    /// in one place.
    ///
    /// # No-lock invariant
    ///
    /// This helper deliberately does **NOT** acquire the per-pubkey
    /// `ValidatorLockMap` lock and does **NOT** call any of
    /// `PubkeyScopedDb`, `stage_block`, `stage_attestation`, or `commit`.
    /// Non-slashable operations have no slashing-DB transaction to serialize,
    /// so the lock is unnecessary overhead.
    ///
    /// **If a future variant of this helper needs to write to the slashing DB,
    /// it MUST add the per-pubkey lock and the staging/commit/discard pattern
    /// used by `sign_block` / `sign_attestation`.**
    ///
    /// # TOCTOU note
    ///
    /// There is a micro-window between `gate_decision` returning `true` and
    /// `signer.sign().await` completing during which the doppelganger state
    /// could theoretically change.  This window is intentionally accepted:
    /// these operations are **not slashable**, so the worst case is a
    /// signature produced for a pubkey that was concurrently disabled — a
    /// tolerable transient condition.  No additional synchronization is needed
    /// to shrink this window.
    async fn sign_nonslashable(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
        op_name: &str,
    ) -> Result<Vec<u8>, SigningGateError> {
        let pubkey_bytes = pubkey.to_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        // Step 1: doppelganger gate (same gate_decision point as slashable paths).
        if !self.gate_decision(pubkey) {
            warn!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                op = op_name,
                "SigningGate: non-slashable sign blocked by doppelganger gate"
            );
            return Err(SigningGateError::BlockedByDoppelganger);
        }

        // Step 2: BLS sign with timeout — no slashing DB, no spawn_blocking.
        let sign_result =
            tokio::time::timeout(self.sign_timeout, self.signer.sign(&signing_root, &pubkey_bytes))
                .await;

        match sign_result {
            Err(_elapsed) => {
                error!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    timeout_secs = self.sign_timeout.as_secs_f64(),
                    "SigningGate: non-slashable signer timed out"
                );
                Err(SigningGateError::SigningFailed("signer timed out".to_string()))
            }
            Ok(Ok(sig)) => Ok(sig.to_bytes().to_vec()),
            Ok(Err(SigningError::KeyNotFound(_))) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    "SigningGate: non-slashable key not found"
                );
                Err(SigningGateError::KeyNotFound)
            }
            Ok(Err(e)) => {
                error!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    op = op_name,
                    error = %e,
                    "SigningGate: non-slashable signer error"
                );
                Err(SigningGateError::SigningFailed(e.to_string()))
            }
        }
    }

    /// Sign a sync committee message.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_SYNC_COMMITTEE` domain).
    pub async fn sign_sync_committee_message(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_sync_committee_message").await
    }

    /// Sign an aggregate-and-proof.
    ///
    /// # Chain-of-custody invariant (SS-2 / SS-3)
    ///
    /// An `AggregateAndProof` is **NOT** itself slashable; its inner
    /// `Attestation` is, and the caller MUST have already signed that inner
    /// attestation via `sign_attestation` (which staged the slashing watermark).
    ///
    /// This method therefore does **NOT** touch the slashing DB.  Running
    /// attestation-slashing staging here would be wrong on two counts:
    ///   a) it would double-stage the attestation rows (the inner attestation
    ///      was already committed by `sign_attestation`), breaking the
    ///      EIP-3076 replay-detection logic; and
    ///   b) it would re-interpret the outer `AggregateAndProof` as an
    ///      independent attestation, mis-attributing epochs/roots.
    ///
    /// The SS-2/SS-3 core fix — removing the erroneous attestation-staging from
    /// `bin/rvc-signer/src/service.rs` — landed in Issue 2.10a by routing every
    /// aggregate handler through this method.  Phase 4 Issue 4.9 covers the
    /// end-to-end aggregator flow + orchestrator side.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_AGGREGATE_AND_PROOF` domain).
    pub async fn sign_aggregate_and_proof(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_aggregate_and_proof").await
    }

    /// Sign a contribution-and-proof.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_CONTRIBUTION_AND_PROOF` domain).
    pub async fn sign_contribution_and_proof(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_contribution_and_proof").await
    }

    /// Sign a sync committee selection proof.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` domain).
    pub async fn sign_selection_proof(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_selection_proof").await
    }

    /// Sign a RANDAO reveal.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_RANDAO` domain over the epoch SSZ-encoded as `Epoch`).
    pub async fn sign_randao_reveal(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_randao_reveal").await
    }

    /// Sign a voluntary exit.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_VOLUNTARY_EXIT` domain, capped at Capella per EIP-7044).
    pub async fn sign_voluntary_exit(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_voluntary_exit").await
    }

    /// Sign a builder registration.
    ///
    /// Non-slashable: gate check → BLS sign, NO slashing-DB staging.
    ///
    /// # Parameters
    ///
    /// - `pubkey`: The validator's BLS public key.
    /// - `signing_root`: The pre-computed signing root (caller applies
    ///   `DOMAIN_APPLICATION_BUILDER` domain with zeroed genesis root).
    pub async fn sign_builder_registration(
        &self,
        pubkey: &PublicKey,
        signing_root: Root,
    ) -> Result<Vec<u8>, SigningGateError> {
        self.sign_nonslashable(pubkey, signing_root, "sign_builder_registration").await
    }
}
