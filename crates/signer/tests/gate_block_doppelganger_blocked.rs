//! RED test: sign_block returns BlockedByDoppelganger and commits NO slashing row.
//!
//! The gate calls is_signing_enabled first.  When the mock returns false,
//! no stage call must happen and no slashing-DB row may be written.

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, PublicKey, SecretKey};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{SigningGate, SigningGateError, ValidatorLockMap};
use slashing::SlashingDb;

const GVR: Root = [0xd3; 32];

struct AlwaysDenied;
impl SigningEnablement for AlwaysDenied {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }
}

fn make_signer_with_key(sk: SecretKey) -> Arc<crypto::CompositeSigner> {
    let mut km = KeyManager::new();
    km.insert(sk);
    Arc::new(crypto::CompositeSigner::new(LocalSigner::new(km)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sign_block_blocked_by_doppelganger_no_row_committed() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let signer = make_signer_with_key(sk);
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));

    let gate = SigningGate::new(
        Arc::clone(&db),
        Arc::new(AlwaysDenied),
        Arc::clone(&signer),
        Arc::new(ValidatorLockMap::new()),
    );

    let signing_root: Root = [0xbe; 32];
    let slot = 42u64;

    let result = gate.sign_block(&pubkey, slot, signing_root, GVR, "test").await;

    // Must be blocked.
    assert!(
        matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
        "expected BlockedByDoppelganger, got: {result:?}"
    );

    // No phantom slashing row must be committed.
    let blocks = db.get_blocks(&pubkey_hex).expect("get_blocks must not fail");
    assert!(
        blocks.is_empty(),
        "doppelganger block must not commit any slashing-DB row; found: {blocks:?}"
    );
}
