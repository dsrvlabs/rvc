//! Shared gate / enablement fixtures for `rvc-signer` integration tests.
//!
//! Each top-level `tests/*.rs` binary is a separate crate; this module is the
//! single home for `AlwaysAllowed` / `AlwaysDenied` and the
//! `KeyManager → LocalSigner → CompositeSigner → SigningGate` builder so gate
//! suites stop re-implementing the same mocks.
//!
//! `dead_code` is allowed: each binary only exercises a subset of the helpers.

#![allow(dead_code)]

use std::sync::Arc;

use crypto::{CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey, Signature, Signer};
use doppelganger::SigningEnablement;
use rvc_signer::{SigningGate, ValidatorLockMap};
use slashing::SlashingDb;

// ── Enablement mocks (sole definitions in crates/signer) ─────────────────────

/// Permits every pubkey. Integration-test twin of [`rvc_signer::AlwaysEnabled`]
/// (that helper stays behind `test-utils` / unit-test `cfg(test)` for cross-crate
/// use; unit tests and `rvc` already consume it).
pub struct AlwaysAllowed;

impl SigningEnablement for AlwaysAllowed {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

/// Denies every pubkey (active doppelganger window or fail-closed unknown key).
pub struct AlwaysDenied;

impl SigningEnablement for AlwaysDenied {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

#[must_use]
pub fn always_allowed() -> Arc<dyn SigningEnablement> {
    Arc::new(AlwaysAllowed)
}

#[must_use]
pub fn always_denied() -> Arc<dyn SigningEnablement> {
    Arc::new(AlwaysDenied)
}

// ── Composite signer builders ────────────────────────────────────────────────

/// Insert `sk` into a fresh [`KeyManager`] and wrap as [`CompositeSigner`].
#[must_use]
pub fn composite_with_key(sk: SecretKey) -> (PublicKey, Arc<CompositeSigner>) {
    let pubkey = sk.public_key();
    let mut km = KeyManager::new();
    km.insert(sk);
    (pubkey, Arc::new(CompositeSigner::new(LocalSigner::new(km))))
}

/// Empty key manager — every sign fails with key-not-found.
#[must_use]
pub fn empty_composite() -> Arc<CompositeSigner> {
    Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
}

// ── Gate fixture ─────────────────────────────────────────────────────────────

/// Build `KeyManager → LocalSigner → CompositeSigner → SigningGate` for `sk`.
#[must_use]
pub fn gate_fixture(
    sk: SecretKey,
    db: Arc<SlashingDb>,
    enablement: Arc<dyn SigningEnablement>,
) -> (PublicKey, SigningGate) {
    let (pubkey, signer) = composite_with_key(sk);
    let gate = SigningGate::new(db, enablement, signer, Arc::new(ValidatorLockMap::new()));
    (pubkey, gate)
}

/// Gate with [`AlwaysAllowed`] enablement and a real local key.
#[must_use]
pub fn gate_allowed(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
    gate_fixture(sk, db, always_allowed())
}

/// Gate with [`AlwaysDenied`] enablement and a real local key.
#[must_use]
pub fn gate_denied(sk: SecretKey, db: Arc<SlashingDb>) -> (PublicKey, SigningGate) {
    gate_fixture(sk, db, always_denied())
}

/// Gate whose BLS backend holds no keys (enablement still open).
#[must_use]
pub fn gate_empty_signer(db: Arc<SlashingDb>) -> SigningGate {
    SigningGate::new(db, always_allowed(), empty_composite(), Arc::new(ValidatorLockMap::new()))
}

/// Gate with a custom raw [`Signer`] backend (timeout / fault injection).
#[must_use]
pub fn gate_with_raw_signer(
    db: Arc<SlashingDb>,
    enablement: Arc<dyn SigningEnablement>,
    signer: Arc<dyn Signer>,
    sign_timeout: std::time::Duration,
) -> SigningGate {
    SigningGate::new_with_raw_signer(
        db,
        enablement,
        signer,
        Arc::new(ValidatorLockMap::new()),
        sign_timeout,
    )
}

/// In-memory slashing DB for a single test.
#[must_use]
pub fn open_db() -> Arc<SlashingDb> {
    Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"))
}

/// Valid-curve mock BLS signature (bytes not stable across calls).
#[must_use]
pub fn mock_sig(tag: &[u8]) -> Signature {
    SecretKey::generate().sign(tag)
}
