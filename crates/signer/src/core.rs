//! Shared slashable-signing core (`sign_slashable`) with explicit [`TimeoutPolicy`].
//!
//! Both `SigningGate` (remote-signer path) and, in RF4-06, `SignerService` (VC path)
//! delegate the stage → sign → commit/discard triple here so timeout, per-validator
//! lock, enablement re-check under lock, and metrics hooks stay in one place.
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
//! ## Scope of `TimeoutPolicy` (RF4-05 vs RF4-06)
//!
//! **Today the policy is consulted only on the client-side timeout arm**
//! (`tokio::time::timeout` elapsed). Non-timeout `SigningError` outcomes
//! (`KeyNotFound`, `RemoteSignerError`, transport/HTTP failures, etc.) **always
//! discard** the staged row, regardless of policy.
//!
//! That is correct for proven local backends (gate production path). It is **not**
//! sufficient for remote backends: a post-sign connection reset or 5xx can be as
//! ambiguous as a timeout. **RF4-06 must choose retain/fail-closed for ambiguous
//! remote errors**, not only for timeout — do not assume timeout is the sole
//! late-completion window.
//!
//! # `!Send` staging guards
//!
//! `StagedBlock` / `StagedAttestation` hold a `parking_lot::MutexGuard` and must not
//! cross a real `.await`. The core therefore runs stage + sign + finish inside
//! `tokio::task::spawn_blocking`, driving the async sign via
//! `Handle::block_on(timeout(...))` on that same thread.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto::{PublicKey, Signer, SigningError};
use doppelganger::SigningEnablement;
use eth_types::Root;
use metrics::definitions::{
    attestation_status, slashing_result, tx_hold_kind, RVC_ATTESTATIONS_TOTAL,
    RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS, RVC_SIGNING_DURATION_SECONDS,
    RVC_SLASHING_PROTECTION_CHECKS_TOTAL,
};
use observability::logging::TruncatedPubkey;
use slashing::{SlashingError, StagedAttestation, StagedBlock};
use tracing::{error, warn};

use crate::error::SigningGateError;
use crate::locks::ValidatorLockMap;

// ── TimeoutPolicy ─────────────────────────────────────────────────────────────

/// What to do with a staged slashing-DB row when the BLS sign **times out**.
///
/// **No [`Default`] implementation** — every call site must pick a policy
/// explicitly so a new remote-backend path cannot accidentally inherit
/// discard-on-timeout (a double-sign hazard).
///
/// # Timeout-only (RF4-05)
///
/// This enum is applied **only** when `tokio::time::timeout` elapses. Other
/// `SigningError` arms currently **always discard** the staged row. RF4-06 must
/// extend fail-closed retain to ambiguous remote non-timeout failures (transport
/// errors after a possible remote sign), not only timeouts.
///
/// # Error surface on retain
///
/// After a successful retain-commit on timeout the core still returns
/// [`SigningGateError::SigningFailed`] (`"signer timed out"`). That does **not**
/// mean the row was discarded — see that variant’s docs. Callers must not treat
/// timeout as “slot free.”
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
    policy: TimeoutPolicy,
    hooks: Arc<dyn SignHooks>,
    op_name: &'static str,
}

impl SlashableSignSession {
    /// Run `stage`, then sign with timeout, then commit/discard per [`TimeoutPolicy`].
    ///
    /// `stage` is invoked on this blocking thread and must return a staged guard
    /// that lives only for the duration of this call (the `!Send` constraint).
    pub fn stage_then_sign<S, F>(self, stage: F) -> Result<Vec<u8>, SigningGateError>
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

            // Key not found — always discard today (local-safe: no signature).
            // TimeoutPolicy is not consulted here (timeout-only in RF4-05).
            Ok(Err(SigningError::KeyNotFound(_))) => {
                staged.discard_row();
                self.hooks.on_tx_hold_ms(tx_hold_ms);
                warn!(
                    pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                    op = self.op_name,
                    "sign_slashable: key not found; staged row discarded"
                );
                Err(SigningGateError::KeyNotFound)
            }

            // Other signer errors — always discard today, regardless of policy.
            // RF4-06: ambiguous remote outcomes (transport/HTTP after a possible
            // remote sign) must not blindly discard when policy is Retain.
            Ok(Err(e)) => {
                staged.discard_row();
                self.hooks.on_tx_hold_ms(tx_hold_ms);
                error!(
                    pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                    op = self.op_name,
                    error = %e,
                    "sign_slashable: signer error; staged row discarded"
                );
                Err(SigningGateError::SigningFailed(e.to_string()))
            }
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
                if let Err(e) = staged.commit_row() {
                    error!(
                        pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                        op = self.op_name,
                        error = %e,
                        "sign_slashable: retain-on-timeout commit failed"
                    );
                    self.hooks.on_tx_hold_ms(tx_hold_ms);
                    return Err(SigningGateError::CommitFailed {
                        signing_root: self.signing_root,
                        source: e,
                    });
                }
                self.hooks.on_tx_hold_ms(tx_hold_ms);
                error!(
                    pubkey = %TruncatedPubkey::new(&self.pubkey_hex),
                    op = self.op_name,
                    timeout_secs = self.sign_timeout.as_secs_f64(),
                    "sign_slashable: signer timed out; staged row retained (committed)"
                );
                // History committed — not discarded. See SigningFailed rustdoc (S1).
                Err(SigningGateError::SigningFailed("signer timed out".to_string()))
            }
        }
    }
}

// ── Public core entry ─────────────────────────────────────────────────────────

/// Inputs for [`sign_slashable`] (bundled to keep the call surface explicit).
///
/// [`TimeoutPolicy`] is required with **no default** — every call site must
/// choose discard vs retain deliberately.
pub struct SignSlashableRequest<'a> {
    pub locks: &'a ValidatorLockMap,
    pub pubkey: &'a PublicKey,
    pub enablement: &'a dyn SigningEnablement,
    pub signer: Arc<dyn Signer>,
    pub signing_root: Root,
    pub sign_timeout: Duration,
    /// Explicit timeout policy — no `Default` (see [`TimeoutPolicy`]).
    pub policy: TimeoutPolicy,
    pub hooks: Arc<dyn SignHooks>,
    pub op_name: &'static str,
}

/// Shared slashable-signing core.
///
/// 1. Acquire the per-validator async lock.
/// 2. Re-check `enablement` **under the lock** (closes Safe→Detected TOCTOU).
/// 3. `spawn_blocking`: caller `body` stages, then
///    [`SlashableSignSession::stage_then_sign`] signs with timeout and
///    commit/discards per `req.policy`.
///
/// `req.policy` has **no default** — it must be set explicitly at every site.
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

    // Step 3: stage → sign → commit/discard inside spawn_blocking.
    let handle = tokio::runtime::Handle::current();
    let hooks_for_success = Arc::clone(&req.hooks);
    let session = SlashableSignSession {
        handle,
        signer: req.signer,
        pubkey_bytes,
        pubkey_hex: pubkey_hex.clone(),
        signing_root: req.signing_root,
        sign_timeout: req.sign_timeout,
        policy: req.policy,
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

    struct AlwaysAllowed;
    impl SigningEnablement for AlwaysAllowed {
        fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
            true
        }
    }

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
                enablement: &AlwaysAllowed,
                signer,
                signing_root,
                sign_timeout: TEST_TIMEOUT,
                policy: TimeoutPolicy::RetainStagedRow,
                hooks,
                op_name: "test_retain",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    scoped.stage_block(&pk_hex, 7, Some(hex::encode(signing_root)))
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
                enablement: &AlwaysAllowed,
                signer,
                signing_root,
                sign_timeout: TEST_TIMEOUT,
                policy: TimeoutPolicy::DiscardStagedRow,
                hooks,
                op_name: "test_discard",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    scoped.stage_block(&pk_hex, 9, Some(hex::encode(signing_root)))
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
                enablement: &AlwaysAllowed,
                signer,
                signing_root,
                sign_timeout: Duration::from_secs(4),
                policy: TimeoutPolicy::DiscardStagedRow,
                hooks: hooks_c,
                op_name: "test_hooks",
            },
            move |session| {
                let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                session.stage_then_sign(|| {
                    scoped.stage_block(&pk_hex, 11, Some(hex::encode(signing_root)))
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
                    policy: TimeoutPolicy::DiscardStagedRow,
                    hooks: Arc::new(NoopSignHooks),
                    op_name: "test_recheck",
                },
                move |session| {
                    let scoped = PubkeyScopedDb::new(db_c, "test".into(), GVR);
                    let pk_hex = hex::encode(pk_for_stage.to_bytes());
                    session.stage_then_sign(|| {
                        scoped.stage_block(&pk_hex, 13, Some(hex::encode([0x44; 32])))
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
