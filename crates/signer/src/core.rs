//! Shared signing core: slashable (`sign_slashable`) and non-slashable
//! (`sign_nonslashable_core`).
//!
//! Both `SigningGate` (remote-signer path) and `SignerService` (VC path)
//! delegate here so timeout, enablement, and (on the slashable path) the
//! stage → sign → commit/discard triple stay in one place.
//!
//! # Timeout policy (fail-closed for remote backends)
//!
//! [`TimeoutPolicy`] is an **explicit** parameter with **no** `Default`. Call sites
//! must choose:
//!
//! - [`TimeoutPolicy::DiscardStagedRow`] — intended for **in-process** backends where
//!   cancelling/dropping the sign future means no externally durable slashable
//!   signature was produced; discard (ROLLBACK) the staged row on **timeout**.
//! - [`TimeoutPolicy::RetainStagedRow`] — remote / unknown backends: the signer may
//!   already have signed when the client times out; **commit** the staged row so a
//!   conflicting retry is impossible. The error is still
//!   `SigningFailed("signer timed out")` — history is **retained**, not discarded
//!   (see [`SigningGateError::SigningFailed`] docs).
//!
//! ## Scope of `TimeoutPolicy`
//!
//! [`TimeoutPolicy`] is consulted on:
//!
//! 1. **Client-side timeout** (`tokio::time::timeout` elapsed).
//! 2. **Ambiguous non-timeout signer errors** (e.g. `RemoteSignerError`,
//!    transport/HTTP failures, invalid remote signature) — outcomes where the
//!    remote **may** already have signed. Under
//!    [`TimeoutPolicy::RetainStagedRow`] the staged row is **committed**
//!    (fail-closed). Under [`TimeoutPolicy::DiscardStagedRow`] it is rolled back.
//!
//! Unambiguous **no-signature** outcomes always discard regardless of policy:
//! `KeyNotFound`, `LocalRejected` (e.g. gRPC raw-root without remote I/O), and
//! `UnsupportedSigningType`.
//!
//! # `!Send` staging guards
//!
//! `StagedBlock` / `StagedAttestation` hold a `parking_lot::MutexGuard` and must not
//! cross a real `.await`. The core therefore runs stage + sign + finish inside
//! `tokio::task::spawn_blocking`, driving the async sign via
//! `Handle::block_on(timeout(...))` on that same thread.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto::{PublicKey, Signature, Signer, SigningError};
use doppelganger::SigningEnablement;
use eth_types::Root;
use metrics::definitions::{
    attestation_status, slashing_result, tx_hold_kind, RVC_ATTESTATIONS_TOTAL,
    RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS, RVC_SIGNING_DURATION_SECONDS,
    RVC_SLASHING_PROTECTION_CHECKS_TOTAL,
};
use observability::logging::TruncatedPubkey;
use slashing::{PendingAudit, SlashingError, StagedAttestation, StagedBlock};
use tracing::{error, warn};

use crate::error::SigningGateError;
use crate::locks::ValidatorLockMap;

/// Default per-sign timeout: 4 seconds — well under a 12-second Ethereum slot.
///
/// Bounding the signer call is mandatory because slashable staging holds the
/// SQLite single-writer connection mutex, and a wedged remote backend must not
/// hang the VC duty loop indefinitely (F37). Shared by `SigningGate` and
/// `SignerService` (ARCH-P1-6).
pub const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(4);

// ── Non-slashable core ────────────────────────────────────────────────────────

/// Neutral failure of [`sign_nonslashable_core`].
///
/// Wrappers map this onto [`SigningGateError`] or [`crate::SignerError`] so the
/// two crate boundaries keep their own error types (ARCH-5c / ARCH-P1-6).
#[derive(Debug)]
pub enum NonSlashableFailure {
    /// Client-side `tokio::time::timeout` elapsed before the backend returned.
    TimedOut {
        /// Configured timeout that elapsed.
        after: Duration,
    },
    /// Backend reported [`SigningError::KeyNotFound`].
    KeyNotFound,
    /// Any other backend [`SigningError`].
    Backend(SigningError),
    /// [`SigningEnablement::is_signing_enabled`] returned `false`.
    Blocked,
}

/// Shared non-slashable signing flow: enablement → BLS sign with timeout.
///
/// `SigningGate` and `SignerService` supply policy inputs (enablement impl,
/// backend, timeout) and map [`NonSlashableFailure`] onto their own error type.
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
/// There is a micro-window between `SigningEnablement::is_signing_enabled`
/// returning `true` and `signer.sign().await` completing during which the
/// doppelganger state could theoretically change.  This window is
/// intentionally accepted: these operations are **not slashable**, so the
/// worst case is a signature produced for a pubkey that was concurrently
/// disabled — a tolerable transient condition.  No additional
/// synchronization is needed to shrink this window.
pub async fn sign_nonslashable_core(
    enablement: &dyn SigningEnablement,
    signer: &dyn Signer,
    pubkey: &PublicKey,
    signing_root: Root,
    sign_timeout: Duration,
) -> Result<Signature, NonSlashableFailure> {
    if !enablement.is_signing_enabled(pubkey) {
        return Err(NonSlashableFailure::Blocked);
    }

    let pubkey_bytes = pubkey.to_bytes();
    let sign_result =
        tokio::time::timeout(sign_timeout, signer.sign(&signing_root, &pubkey_bytes)).await;

    match sign_result {
        Err(_elapsed) => Err(NonSlashableFailure::TimedOut { after: sign_timeout }),
        Ok(Ok(sig)) => Ok(sig),
        Ok(Err(SigningError::KeyNotFound(_))) => Err(NonSlashableFailure::KeyNotFound),
        Ok(Err(e)) => Err(NonSlashableFailure::Backend(e)),
    }
}

// ── TimeoutPolicy ─────────────────────────────────────────────────────────────

/// What to do with a staged slashing-DB row when the BLS sign **times out**.
///
/// **No [`Default`] implementation** — every call site must pick a policy
/// explicitly so a new remote-backend path cannot accidentally inherit
/// discard-on-timeout (a double-sign hazard).
///
/// # When this policy is applied
///
/// - **Timeout** (`tokio::time::timeout` elapses).
/// - **Ambiguous non-timeout signer errors** (`RemoteSignerError`,
///   `InvalidRemoteSignature`, …) — remote may already have signed. Under
///   [`TimeoutPolicy::RetainStagedRow`] these **commit** the staged row.
///
/// Unambiguous no-signature errors always discard (`KeyNotFound`,
/// `LocalRejected`, `UnsupportedSigningType`).
///
/// # Error surface on retain
///
/// After a successful retain-commit the core still returns
/// [`SigningGateError::SigningFailed`] (e.g. `"signer timed out"`). That does
/// **not** mean the row was discarded — see that variant’s docs. Callers must
/// not treat timeout / remote error as “slot free.”
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutPolicy {
    /// In-process backend: dropping the timed-out future is treated as “no
    /// signature produced.” Discard (ROLLBACK) the staged row so the slot/epoch
    /// remains free. Only sound when the backend cannot complete a durable
    /// slashable sign after the client future is dropped (pure in-process BLS).
    DiscardStagedRow,
    /// Remote / unknown backend: the signer may already have signed when the
    /// timeout fires. **Commit** the staged row so a conflicting retry is
    /// impossible; the caller receives `SigningFailed("signer timed out")` with
    /// **history retained** (not discarded).
    RetainStagedRow,
}

/// How [`sign_slashable`] obtains [`TimeoutPolicy`].
///
/// Prefer [`TimeoutPolicySource::ResolveUnderLock`] on paths whose registry can
/// change concurrently (VC `SignerService` + keymanager remote import) so
/// policy is not snapshotted as InProcess while the live route becomes remote.
pub enum TimeoutPolicySource {
    /// Fixed policy chosen at the call site (gate / pure in-process backends).
    Fixed(TimeoutPolicy),
    /// Evaluated **under** the per-validator lock immediately before stage, and
    /// re-checked immediately before BLS sign (fail-closed: Retain wins).
    ResolveUnderLock(Arc<dyn Fn() -> TimeoutPolicy + Send + Sync>),
}

impl TimeoutPolicySource {
    /// Fail-closed merge: if either side is Retain, use Retain.
    fn fail_closed_max(a: TimeoutPolicy, b: TimeoutPolicy) -> TimeoutPolicy {
        match (a, b) {
            (TimeoutPolicy::RetainStagedRow, _) | (_, TimeoutPolicy::RetainStagedRow) => {
                TimeoutPolicy::RetainStagedRow
            }
            _ => TimeoutPolicy::DiscardStagedRow,
        }
    }
}

// ── Staged row trait ──────────────────────────────────────────────────────────

/// Minimal commit/discard surface shared by [`StagedBlock`] and [`StagedAttestation`].
pub trait StagedRow {
    /// Persist the staged row (or close an idempotent re-sign txn).
    fn commit_row(self) -> Result<(), SlashingError>;
    /// Roll back the staged transaction (no phantom row).
    fn discard_row(self);
}

impl StagedRow for StagedBlock<'_> {
    fn commit_row(self) -> Result<(), SlashingError> {
        self.commit()
    }
    fn discard_row(self) {
        self.discard();
    }
}

impl StagedRow for StagedAttestation<'_> {
    fn commit_row(self) -> Result<(), SlashingError> {
        self.commit()
    }
    fn discard_row(self) {
        self.discard();
    }
}

/// ARCH-1a compile bridge: `PubkeyScopedDb::stage_*` returns `(staged, PendingAudit)`.
/// Emit the deferred audit only after commit/discard releases the connection mutex
/// so a DB-reading tracing subscriber cannot deadlock (ADR-006 / C2).
impl<S: StagedRow> StagedRow for (S, PendingAudit) {
    fn commit_row(self) -> Result<(), SlashingError> {
        let result = self.0.commit_row();
        self.1.emit();
        result
    }
    fn discard_row(self) {
        self.0.discard_row();
        self.1.emit();
    }
}

// ── Sign hooks (metrics) ──────────────────────────────────────────────────────

/// Metrics / observability callbacks invoked from the slashable core.
///
/// Implemented as a trait object so the gate and (later) the VC service can
/// share the same stage/sign/commit path while recording their preferred labels.
pub trait SignHooks: Send + Sync {
    /// Stage accepted the request (EIP-3076 check passed).
    fn on_stage_safe(&self);
    /// Stage rejected the request (slashable / I/O).
    fn on_stage_blocked(&self);
    /// Wall-clock hold of the SQLite write txn in milliseconds.
    fn on_tx_hold_ms(&self, ms: f64);
    /// Successful sign + commit completed; `duration` is the full outer op time.
    fn on_success(&self, duration: Duration);
}

/// No-op hooks (tests / call sites that record metrics elsewhere).
pub struct NoopSignHooks;

impl SignHooks for NoopSignHooks {
    fn on_stage_safe(&self) {}
    fn on_stage_blocked(&self) {}
    fn on_tx_hold_ms(&self, _ms: f64) {}
    fn on_success(&self, _duration: Duration) {}
}

/// Standard RVC metric families used by `SignerService` and now by `SigningGate`.
///
/// | Family | Labels |
/// |---|---|
/// | `rvc_slashing_protection_checks_total` | `result=safe\|blocked` |
/// | `rvc_signer_slashing_tx_hold_duration_ms` | `kind=block\|attestation` |
/// | `rvc_signing_duration_seconds` | (none) |
/// | `rvc_attestations_total` | `status=success\|failed` (attestation only) |
pub struct StandardSlashableHooks {
    tx_kind: &'static str,
    is_attestation: bool,
}

impl StandardSlashableHooks {
    /// Hooks for block-proposal signs.
    #[must_use]
    pub fn block() -> Self {
        Self { tx_kind: tx_hold_kind::BLOCK, is_attestation: false }
    }

    /// Hooks for attestation signs.
    #[must_use]
    pub fn attestation() -> Self {
        Self { tx_kind: tx_hold_kind::ATTESTATION, is_attestation: true }
    }
}

impl SignHooks for StandardSlashableHooks {
    fn on_stage_safe(&self) {
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();
    }

    fn on_stage_blocked(&self) {
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::BLOCKED]).inc();
        if self.is_attestation {
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).inc();
        }
    }

    fn on_tx_hold_ms(&self, ms: f64) {
        RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS.with_label_values(&[self.tx_kind]).observe(ms);
    }

    fn on_success(&self, duration: Duration) {
        RVC_SIGNING_DURATION_SECONDS
            .with_label_values(&[] as &[&str])
            .observe(duration.as_secs_f64());
        if self.is_attestation {
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::SUCCESS]).inc();
        }
    }
}

// ── Session (runs on the blocking thread) ─────────────────────────────────────

/// State for finishing a staged sign inside `spawn_blocking`.
///
/// Created by [`sign_slashable`] and handed to the caller's body closure so the
/// caller can build a `PubkeyScopedDb` / stage locally (keeping `!Send` guards
/// on this thread) then call [`SlashableSignSession::stage_then_sign`].
pub struct SlashableSignSession {
    handle: tokio::runtime::Handle,
    signer: Arc<dyn Signer>,
    pubkey_bytes: [u8; 48],
    pubkey_hex: String,
    signing_root: Root,
    sign_timeout: Duration,
    /// Mutable so a fail-closed recheck immediately before sign can upgrade
    /// Discard → Retain (SEC-1 concurrent remote import).
    policy: TimeoutPolicy,
    /// When present, re-evaluated immediately before BLS sign; Retain wins.
    policy_recheck: Option<Arc<dyn Fn() -> TimeoutPolicy + Send + Sync>>,
    hooks: Arc<dyn SignHooks>,
    op_name: &'static str,
}

impl SlashableSignSession {
    /// Run `stage`, then sign with timeout, then commit/discard per [`TimeoutPolicy`].
    ///
    /// `stage` is invoked on this blocking thread and must return a staged guard
    /// that lives only for the duration of this call (the `!Send` constraint).
    pub fn stage_then_sign<S, F>(mut self, stage: F) -> Result<Vec<u8>, SigningGateError>
    where
        S: StagedRow,
        F: FnOnce() -> Result<S, SlashingError>,
    {
        let tx_start = Instant::now();
        let staged = match stage() {
            Ok(s) => {
                self.hooks.on_stage_safe();
                s
            }
            Err(e) => {
                self.hooks.on_stage_blocked();
                self.hooks.on_tx_hold_ms(tx_start.elapsed().as_secs_f64() * 1000.0);
                return Err(SigningGateError::SlashingBlocked(e));
            }
        };

        // SEC-1: re-resolve policy immediately before contacting the backend so a
        // concurrent remote import after lock acquisition still fail-closes.
        if let Some(ref recheck) = self.policy_recheck {
            self.policy = TimeoutPolicySource::fail_closed_max(self.policy, recheck());
        }

        let sign_result = self.handle.block_on(tokio::time::timeout(
            self.sign_timeout,
            self.signer.sign(&self.signing_root, &self.pubkey_bytes),
        ));
        let tx_hold_ms = tx_start.elapsed().as_secs_f64() * 1000.0;

        match sign_result {
            // Timeout — policy decides discard vs retain/commit.
            Err(_elapsed) => self.finish_timeout(staged, tx_hold_ms),

            // Sign succeeded — commit the staged row.
            Ok(Ok(sig)) => match staged.commit_row() {
                Ok(()) => {
                    self.hooks.on_tx_hold_ms(tx_hold_ms);
                    Ok(sig.to_bytes().to_vec())
                }
                Err(e) => {
                    error!(
                        pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                        op = self.op_name,
                        error = %e,
                        "sign_slashable: commit failed after successful sign"
                    );
                    self.hooks.on_tx_hold_ms(tx_hold_ms);
                    Err(SigningGateError::CommitFailed {
                        signing_root: self.signing_root,
                        source: e,
                    })
                }
            },

            // Unambiguous no-signature outcomes — always discard (local-safe).
            Ok(Err(e)) if e.is_unambiguous_no_signature() => {
                staged.discard_row();
                self.hooks.on_tx_hold_ms(tx_hold_ms);
                match e {
                    SigningError::KeyNotFound(_) => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                            op = self.op_name,
                            "sign_slashable: key not found; staged row discarded"
                        );
                        Err(SigningGateError::KeyNotFound)
                    }
                    other => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                            op = self.op_name,
                            error = %other,
                            "sign_slashable: local/no-remote-contact error; staged row discarded"
                        );
                        Err(SigningGateError::SigningFailed(other.to_string()))
                    }
                }
            }

            // Ambiguous signer errors — policy decides discard vs retain.
            // Remote may already have signed (transport/HTTP after possible sign).
            Ok(Err(e)) => self.finish_ambiguous_error(staged, tx_hold_ms, e),
        }
    }

    fn finish_timeout<S: StagedRow>(
        self,
        staged: S,
        tx_hold_ms: f64,
    ) -> Result<Vec<u8>, SigningGateError> {
        match self.policy {
            TimeoutPolicy::DiscardStagedRow => {
                staged.discard_row();
                self.hooks.on_tx_hold_ms(tx_hold_ms);
                error!(
                    pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                    op = self.op_name,
                    timeout_secs = self.sign_timeout.as_secs_f64(),
                    "sign_slashable: signer timed out; staged row discarded"
                );
                Err(SigningGateError::SigningFailed("signer timed out".to_string()))
            }
            TimeoutPolicy::RetainStagedRow => {
                // Fail-closed for remote backends: keep history so a conflicting
                // retry cannot pass stage. Same-root re-sign remains an EIP-3076 path.
                // Error is still SigningFailed — docs on that variant note retained history.
                self.retain_staged_row(
                    staged,
                    tx_hold_ms,
                    "signer timed out",
                    "sign_slashable: signer timed out; staged row retained (committed)",
                    true,
                )
            }
        }
    }

    /// Ambiguous non-timeout signer failure: discard or retain per policy.
    fn finish_ambiguous_error<S: StagedRow>(
        self,
        staged: S,
        tx_hold_ms: f64,
        err: SigningError,
    ) -> Result<Vec<u8>, SigningGateError> {
        match self.policy {
            TimeoutPolicy::DiscardStagedRow => {
                staged.discard_row();
                self.hooks.on_tx_hold_ms(tx_hold_ms);
                error!(
                    pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                    op = self.op_name,
                    error = %err,
                    "sign_slashable: signer error; staged row discarded"
                );
                Err(SigningGateError::SigningFailed(err.to_string()))
            }
            TimeoutPolicy::RetainStagedRow => {
                // Fail-closed: remote may already have signed. Do not claim "discarded".
                let msg = err.to_string();
                self.retain_staged_row(
                    staged,
                    tx_hold_ms,
                    &msg,
                    "sign_slashable: signer error; staged row retained (committed)",
                    false,
                )
            }
        }
    }

    /// Commit staged row then return `SigningFailed` (history retained, not discarded).
    fn retain_staged_row<S: StagedRow>(
        self,
        staged: S,
        tx_hold_ms: f64,
        failed_msg: &str,
        retain_log: &str,
        is_timeout: bool,
    ) -> Result<Vec<u8>, SigningGateError> {
        if let Err(e) = staged.commit_row() {
            error!(
                pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                op = self.op_name,
                error = %e,
                "sign_slashable: retain commit failed"
            );
            self.hooks.on_tx_hold_ms(tx_hold_ms);
            return Err(SigningGateError::CommitFailed {
                signing_root: self.signing_root,
                source: e,
            });
        }
        self.hooks.on_tx_hold_ms(tx_hold_ms);
        if is_timeout {
            error!(
                pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                op = self.op_name,
                timeout_secs = self.sign_timeout.as_secs_f64(),
                "{retain_log}"
            );
        } else {
            error!(
                pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                op = self.op_name,
                "{retain_log}"
            );
        }
        // History committed — not discarded. See SigningFailed rustdoc (S1).
        Err(SigningGateError::SigningFailed(failed_msg.to_string()))
    }
}

// ── Public core entry ─────────────────────────────────────────────────────────

/// Inputs for [`sign_slashable`] (bundled to keep the call surface explicit).
///
/// Policy is required with **no default** — every call site must choose
/// [`TimeoutPolicySource`] deliberately (fixed or resolve-under-lock).
pub struct SignSlashableRequest<'a> {
    pub locks: &'a ValidatorLockMap,
    pub pubkey: &'a PublicKey,
    pub enablement: &'a dyn SigningEnablement,
    pub signer: Arc<dyn Signer>,
    pub signing_root: Root,
    pub sign_timeout: Duration,
    /// Explicit policy source — no `Default` (see [`TimeoutPolicy`] / [`TimeoutPolicySource`]).
    pub policy: TimeoutPolicySource,
    pub hooks: Arc<dyn SignHooks>,
    pub op_name: &'static str,
}

/// Shared slashable-signing core.
///
/// 1. Acquire the per-validator async lock.
/// 2. Re-check `enablement` **under the lock** (closes Safe→Detected TOCTOU).
/// 3. Resolve [`TimeoutPolicy`] under the lock (and re-check before sign when
///    using [`TimeoutPolicySource::ResolveUnderLock`] — SEC-1).
/// 4. `spawn_blocking`: caller `body` stages, then
///    [`SlashableSignSession::stage_then_sign`] signs with timeout and
///    commit/discards per policy.
///
/// # Errors
///
/// Propagates [`SigningGateError`] variants from enablement, stage, sign, commit,
/// and join failures. On success, records `hooks.on_success` with the full
/// wall-clock duration of the operation.
pub async fn sign_slashable<F>(
    req: SignSlashableRequest<'_>,
    body: F,
) -> Result<Vec<u8>, SigningGateError>
where
    F: FnOnce(SlashableSignSession) -> Result<Vec<u8>, SigningGateError> + Send + 'static,
{
    let start = Instant::now();
    let pubkey_bytes = req.pubkey.to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);
    let op_name = req.op_name;

    // Step 1: per-pubkey async lock.
    //
    // CANCELLATION NOTE: if the caller drops this future at the
    // `spawn_blocking(...).await` below, this guard is released while the
    // blocking task keeps running. The authoritative double-sign serializer is
    // the SQLite `BEGIN IMMEDIATE` lock held by the staged guard.
    let _guard = req.locks.lock(&pubkey_bytes).await;

    // Step 2: re-check enablement under the lock (SigningGate / SignerService parity).
    if !req.enablement.is_signing_enabled(req.pubkey) {
        warn!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            op = op_name,
            "sign_slashable: blocked by doppelganger gate (under lock)"
        );
        return Err(SigningGateError::BlockedByDoppelganger);
    }

    // Step 3: resolve policy under the lock (SEC-1). Keep Arc recheck for pre-sign.
    let (policy, policy_recheck) = match req.policy {
        TimeoutPolicySource::Fixed(p) => (p, None),
        TimeoutPolicySource::ResolveUnderLock(f) => {
            let policy = f();
            (policy, Some(f))
        }
    };

    // Step 4: stage → sign → commit/discard inside spawn_blocking.
    let handle = tokio::runtime::Handle::current();
    let hooks_for_success = Arc::clone(&req.hooks);
    let session = SlashableSignSession {
        handle,
        signer: req.signer,
        pubkey_bytes,
        pubkey_hex: pubkey_hex.clone(),
        signing_root: req.signing_root,
        sign_timeout: req.sign_timeout,
        policy,
        policy_recheck,
        hooks: req.hooks,
        op_name,
    };

    let result = tokio::task::spawn_blocking(move || body(session)).await.map_err(|e| {
        error!(
            pubkey = %TruncatedPubkey::new(&pubkey_hex),
            op = op_name,
            error = %e,
            "sign_slashable: blocking task panicked"
        );
        SigningGateError::SigningFailed(format!("{op_name} task panicked: {e}"))
    })?;

    if result.is_ok() {
        hooks_for_success.on_success(start.elapsed());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey, Signature, Signer, SigningError};
    use slashing::{PubkeyScopedDb, SlashingDb};

    const GVR: Root = [0xc0; 32];
    const TEST_TIMEOUT: Duration = Duration::from_millis(50);
    const SIGNER_SLEEP: Duration = Duration::from_millis(400);

    // Prefer the crate test helper (AlwaysEnabled) over a local twin.
    use crate::AlwaysEnabled;

    struct FlipEnablement {
        enabled: AtomicBool,
    }
    impl SigningEnablement for FlipEnablement {
        fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
            self.enabled.load(Ordering::SeqCst)
        }
    }

    /// Counts hook invocations for assertions.
    struct CountingHooks {
        safe: AtomicU64,
        blocked: AtomicU64,
        tx_hold: AtomicU64,
        success: AtomicU64,
    }
    impl CountingHooks {
        fn new() -> Self {
            Self {
                safe: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
                tx_hold: AtomicU64::new(0),
                success: AtomicU64::new(0),
            }
        }
    }
    impl SignHooks for CountingHooks {
        fn on_stage_safe(&self) {
            self.safe.fetch_add(1, Ordering::SeqCst);
        }
        fn on_stage_blocked(&self) {
            self.blocked.fetch_add(1, Ordering::SeqCst);
        }
        fn on_tx_hold_ms(&self, _ms: f64) {
            self.tx_hold.fetch_add(1, Ordering::SeqCst);
        }
        fn on_success(&self, _d: Duration) {
            self.success.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct SlowSigner {
        inner: LocalSigner,
        sleep: Duration,
    }
    #[async_trait]
    impl Signer for SlowSigner {
        async fn sign(
            &self,
            signing_root: &Root,
            pubkey: &[u8; 48],
        ) -> Result<Signature, SigningError> {
            tokio::time::sleep(self.sleep).await;
            self.inner.sign(signing_root, pubkey).await
        }
        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.inner.public_keys()
        }
    }

    fn make_local(sk: SecretKey) -> (PublicKey, Arc<dyn Signer>) {
        let pubkey = sk.public_key();
        let mut km = KeyManager::new();
        km.insert(sk);
        (pubkey, Arc::new(LocalSigner::new(km)) as Arc<dyn Signer>)
    }

    fn make_slow(sk: SecretKey, sleep: Duration) -> (PublicKey, Arc<dyn Signer>) {
        let pubkey = sk.public_key();
        let mut km = KeyManager::new();
        km.insert(sk);
        let slow = SlowSigner { inner: LocalSigner::new(km), sleep };
        (pubkey, Arc::new(slow) as Arc<dyn Signer>)
    }

    /// RED→GREEN: retain policy must keep a staged row after sign timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_core_retain_policy_keeps_staged_row_on_timeout() {
        let sk = SecretKey::generate();
        let (pubkey, signer) = make_slow(sk, SIGNER_SLEEP);
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
        let locks = ValidatorLockMap::new();
        let hooks = Arc::new(NoopSignHooks);
        let signing_root: Root = [0x11; 32];

        let db_c = Arc::clone(&db);
        let pk_hex = pubkey_hex.clone();
        let result = sign_slashable(
            SignSlashableRequest {
                locks: &locks,
                pubkey: &pubkey,
                enablement: &AlwaysEnabled,
                signer,
                signing_root,
                sign_timeout: TEST_TIMEOUT,
                policy: TimeoutPolicySource::Fixed(TimeoutPolicy::RetainStagedRow),
                hooks,
                op_name: "test_retain",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    let (staged, audit) =
                        scoped.stage_block(&pk_hex, 7, Some(hex::encode(signing_root)))?;
                    Ok((staged, audit))
                })
            },
        )
        .await;

        assert!(
            matches!(result, Err(SigningGateError::SigningFailed(ref m)) if m.contains("timed out")),
            "expected timeout error, got {result:?}"
        );
        let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
        assert_eq!(
            blocks.len(),
            1,
            "RetainStagedRow must commit the staged row on timeout; found {blocks:?}"
        );
        assert_eq!(blocks[0].slot, 7);
    }

    /// Backend that fails with a remote transport error (S2 ambiguous failure).
    struct RemoteFailSigner;
    #[async_trait]
    impl Signer for RemoteFailSigner {
        async fn sign(
            &self,
            _signing_root: &Root,
            _pubkey: &[u8; 48],
        ) -> Result<Signature, SigningError> {
            Err(SigningError::RemoteSignerError("http 502 after possible sign".into()))
        }
        fn public_keys(&self) -> Vec<[u8; 48]> {
            vec![]
        }
    }

    /// LocalRejected always discards even under Retain (MAJOR-2 / no remote I/O).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_core_local_rejected_always_discards_under_retain() {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
        let locks = ValidatorLockMap::new();
        let hooks = Arc::new(NoopSignHooks);
        let signing_root: Root = [0x55; 32];

        struct LocalReject;
        #[async_trait]
        impl Signer for LocalReject {
            async fn sign(
                &self,
                _signing_root: &Root,
                _pubkey: &[u8; 48],
            ) -> Result<Signature, SigningError> {
                Err(SigningError::LocalRejected("gRPC raw-root".into()))
            }
            fn public_keys(&self) -> Vec<[u8; 48]> {
                vec![]
            }
        }
        let signer: Arc<dyn Signer> = Arc::new(LocalReject);

        let db_c = Arc::clone(&db);
        let pk_hex = pubkey_hex.clone();
        let result = sign_slashable(
            SignSlashableRequest {
                locks: &locks,
                pubkey: &pubkey,
                enablement: &AlwaysEnabled,
                signer,
                signing_root,
                sign_timeout: Duration::from_secs(4),
                policy: TimeoutPolicySource::Fixed(TimeoutPolicy::RetainStagedRow),
                hooks,
                op_name: "test_local_rejected",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    let (staged, audit) =
                        scoped.stage_block(&pk_hex, 15, Some(hex::encode(signing_root)))?;
                    Ok((staged, audit))
                })
            },
        )
        .await;

        assert!(
            matches!(result, Err(SigningGateError::SigningFailed(_))),
            "expected SigningFailed, got {result:?}"
        );
        let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
        assert!(blocks.is_empty(), "LocalRejected must discard under Retain; found {blocks:?}");
    }

    /// Retain policy must commit on ambiguous non-timeout remote errors (S2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_core_retain_policy_keeps_staged_row_on_remote_error() {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
        let locks = ValidatorLockMap::new();
        let hooks = Arc::new(NoopSignHooks);
        let signing_root: Root = [0x44; 32];
        let signer: Arc<dyn Signer> = Arc::new(RemoteFailSigner);

        let db_c = Arc::clone(&db);
        let pk_hex = pubkey_hex.clone();
        let result = sign_slashable(
            SignSlashableRequest {
                locks: &locks,
                pubkey: &pubkey,
                enablement: &AlwaysEnabled,
                signer,
                signing_root,
                sign_timeout: Duration::from_secs(4),
                policy: TimeoutPolicySource::Fixed(TimeoutPolicy::RetainStagedRow),
                hooks,
                op_name: "test_retain_remote_err",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    let (staged, audit) =
                        scoped.stage_block(&pk_hex, 13, Some(hex::encode(signing_root)))?;
                    Ok((staged, audit))
                })
            },
        )
        .await;

        assert!(
            matches!(result, Err(SigningGateError::SigningFailed(_))),
            "expected SigningFailed, got {result:?}"
        );
        // Error text must not claim the row was discarded (S1 residual).
        if let Err(SigningGateError::SigningFailed(ref m)) = result {
            assert!(
                !m.to_lowercase().contains("discard"),
                "retain path must not surface 'discarded' in error: {m}"
            );
        }
        let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
        assert_eq!(
            blocks.len(),
            1,
            "RetainStagedRow must commit on ambiguous remote error; found {blocks:?}"
        );
    }

    /// Discard policy rolls back the staged row on timeout (gate parity).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_core_discard_policy_rolls_back_staged_row_on_timeout() {
        let sk = SecretKey::generate();
        let (pubkey, signer) = make_slow(sk, SIGNER_SLEEP);
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
        let locks = ValidatorLockMap::new();
        let hooks = Arc::new(NoopSignHooks);
        let signing_root: Root = [0x22; 32];

        let db_c = Arc::clone(&db);
        let pk_hex = pubkey_hex.clone();
        let result = sign_slashable(
            SignSlashableRequest {
                locks: &locks,
                pubkey: &pubkey,
                enablement: &AlwaysEnabled,
                signer,
                signing_root,
                sign_timeout: TEST_TIMEOUT,
                policy: TimeoutPolicySource::Fixed(TimeoutPolicy::DiscardStagedRow),
                hooks,
                op_name: "test_discard",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    let (staged, audit) =
                        scoped.stage_block(&pk_hex, 9, Some(hex::encode(signing_root)))?;
                    Ok((staged, audit))
                })
            },
        )
        .await;

        assert!(
            matches!(result, Err(SigningGateError::SigningFailed(ref m)) if m.contains("timed out")),
            "expected timeout error, got {result:?}"
        );
        let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
        assert!(
            blocks.is_empty(),
            "DiscardStagedRow must leave no row on timeout; found {blocks:?}"
        );
    }

    /// Happy path records stage-safe + tx-hold + success hooks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_core_hooks_on_success() {
        let sk = SecretKey::generate();
        let (pubkey, signer) = make_local(sk);
        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
        let locks = ValidatorLockMap::new();
        let hooks = Arc::new(CountingHooks::new());
        let signing_root: Root = [0x33; 32];

        let db_c = Arc::clone(&db);
        let pk_hex = pubkey_hex.clone();
        let hooks_c = Arc::clone(&hooks);
        let result = sign_slashable(
            SignSlashableRequest {
                locks: &locks,
                pubkey: &pubkey,
                enablement: &AlwaysEnabled,
                signer,
                signing_root,
                sign_timeout: Duration::from_secs(4),
                policy: TimeoutPolicySource::Fixed(TimeoutPolicy::DiscardStagedRow),
                hooks: hooks_c,
                op_name: "test_hooks",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    let (staged, audit) =
                        scoped.stage_block(&pk_hex, 11, Some(hex::encode(signing_root)))?;
                    Ok((staged, audit))
                })
            },
        )
        .await;

        assert!(result.is_ok(), "sign must succeed: {result:?}");
        assert_eq!(hooks.safe.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.blocked.load(Ordering::SeqCst), 0);
        assert_eq!(hooks.tx_hold.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.success.load(Ordering::SeqCst), 1);
    }

    /// Enablement re-check under the lock: a concurrent flip to disabled must refuse.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_core_enablement_recheck_under_lock() {
        let sk = SecretKey::generate();
        let (pubkey, signer) = make_local(sk);
        let pubkey_bytes = pubkey.to_bytes();
        let db = Arc::new(SlashingDb::open_in_memory().expect("db"));
        let locks = Arc::new(ValidatorLockMap::new());
        let enablement = Arc::new(FlipEnablement { enabled: AtomicBool::new(true) });

        // Hold the per-pubkey lock so sign_slashable blocks before recheck.
        let held = locks.lock(&pubkey_bytes).await;

        let locks_c = Arc::clone(&locks);
        let en_c = Arc::clone(&enablement);
        let db_c = Arc::clone(&db);
        let pk = pubkey.clone();
        let pk_for_stage = pubkey.clone();
        let join = tokio::spawn(async move {
            sign_slashable(
                SignSlashableRequest {
                    locks: locks_c.as_ref(),
                    pubkey: &pk,
                    enablement: en_c.as_ref(),
                    signer,
                    signing_root: [0x44; 32],
                    sign_timeout: Duration::from_secs(4),
                    policy: TimeoutPolicySource::Fixed(TimeoutPolicy::DiscardStagedRow),
                    hooks: Arc::new(NoopSignHooks),
                    op_name: "test_recheck",
                },
                move |session| {
                    let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                    let pk_hex = hex::encode(pk_for_stage.to_bytes());
                    session.stage_then_sign(|| {
                        let (staged, audit) =
                            scoped.stage_block(&pk_hex, 13, Some(hex::encode([0x44; 32])))?;
                        Ok((staged, audit))
                    })
                },
            )
            .await
        });

        // Give the spawned task time to block on the lock, then flip closed and release.
        tokio::time::sleep(Duration::from_millis(20)).await;
        enablement.enabled.store(false, Ordering::SeqCst);
        drop(held);

        let result = join.await.expect("join");
        assert!(
            matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
            "recheck under lock must refuse after flip; got {result:?}"
        );
    }

    /// TimeoutPolicy has no Default (compile-time contract documented via explicit use).
    #[test]
    fn test_timeout_policy_variants_are_distinct() {
        assert_ne!(TimeoutPolicy::DiscardStagedRow, TimeoutPolicy::RetainStagedRow);
    }
}
