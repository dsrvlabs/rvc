//! BUG-003 regression: a signer that stalls past the sign timeout must not hold
//! the SQLite write lock indefinitely, and must leave no phantom slashing row.
//!
//! The gate wraps the sign call in `tokio::time::timeout`.  When the backend
//! exceeds that budget:
//! - The staged slashing-DB guard is discarded (ROLLBACK — no phantom row).
//! - The call returns `Err(SigningGateError::SigningFailed("signer timed out"))`.
//!
//! We simulate a slow signer with a custom `Signer` impl that sleeps longer
//! than the configured timeout, injected via `SigningGate::new_with_raw_signer`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey, Signature, Signer, SigningError};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb;

const GVR: Root = [0xd3; 32];
/// Gate timeout: 50 ms — fast for tests, still a meaningful bound.
const TEST_TIMEOUT: Duration = Duration::from_millis(50);
/// Signer delay: much longer than `TEST_TIMEOUT`.
const SIGNER_SLEEP: Duration = Duration::from_millis(400);

struct AlwaysAllowed;
impl SigningEnablement for AlwaysAllowed {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

/// A signer that sleeps `sleep` before delegating to a real local signer.
///
/// If the sleep completes the signature would be valid — but `TEST_TIMEOUT`
/// cuts it off first.
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

fn make_gate(
    sk: SecretKey,
    db: Arc<SlashingDb>,
    timeout: Duration,
    sleep: Duration,
) -> SigningGate {
    let mut km = KeyManager::new();
    km.insert(sk);
    let slow: Arc<dyn Signer> = Arc::new(SlowSigner { inner: LocalSigner::new(km), sleep });
    SigningGate::new_with_raw_signer(
        Arc::clone(&db),
        Arc::new(AlwaysAllowed),
        slow,
        Arc::new(ValidatorLockMap::new()),
        timeout,
    )
}

/// BUG-003 regression — block: a stalled signer must not commit a phantom row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_block_timeout_discards_staged_row() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));

    let gate = make_gate(sk, Arc::clone(&db), TEST_TIMEOUT, SIGNER_SLEEP);

    let result = gate.sign_block(&pubkey, 42, [0xde; 32], GVR, "test").await;

    assert!(
        matches!(result, Err(SigningGateError::SigningFailed(ref msg)) if msg.contains("timed out")),
        "expected SigningFailed containing 'timed out', got: {result:?}"
    );

    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks");
    assert!(blocks.is_empty(), "timeout must not commit a slashing-DB row; found: {blocks:?}");
}

/// BUG-003 regression — attestation: a stalled signer must not commit a phantom row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_attestation_timeout_discards_staged_row() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));

    let gate = make_gate(sk, Arc::clone(&db), TEST_TIMEOUT, SIGNER_SLEEP);

    let result = gate.sign_attestation(&pubkey, 10, 11, [0xde; 32], GVR, "test").await;

    assert!(
        matches!(result, Err(SigningGateError::SigningFailed(ref msg)) if msg.contains("timed out")),
        "expected SigningFailed containing 'timed out', got: {result:?}"
    );

    let attestations = db.get_attestations(&pubkey_hex).expect("get_attestations");
    assert!(
        attestations.is_empty(),
        "timeout must not commit a slashing-DB row; found: {attestations:?}"
    );
}

/// Non-slashable timeout: a stalled signer on a non-slashable path must return
/// `Err(SigningFailed("signer timed out"))`.
///
/// Non-slashable paths have no staged slashing-DB row to discard, but the sign
/// timeout still applies for consistency (BUG-003 hygiene: a wedged remote
/// signer must not stall callers indefinitely on any path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_sync_committee_message_timeout() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));

    let gate = make_gate(sk, Arc::clone(&db), TEST_TIMEOUT, SIGNER_SLEEP);

    let result = gate.sign_sync_committee_message(&pubkey, [0xde; 32]).await;

    assert!(
        matches!(result, Err(SigningGateError::SigningFailed(ref msg)) if msg.contains("timed out")),
        "expected SigningFailed containing 'timed out' on non-slashable path, got: {result:?}"
    );
}
