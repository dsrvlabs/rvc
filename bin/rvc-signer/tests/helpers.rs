//! Shared test helpers for v2 RPC integration tests.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use crypto::{KeyManager, SecretKey};
use eth_types::encode_beacon_block_ssz;
use slashing::SlashingDb;

use rvc_signer_bin::backend::{SigningBackend, SigningBackendError};
use rvc_signer_bin::proto::signer_v2::ForkInfo;
use rvc_signer_bin::service::SignerServiceImpl;

/// The BLS secret key used in all happy-path tests.
/// Derived via EIP-2333 from a fixed seed for reproducibility.
pub fn known_secret_key() -> SecretKey {
    use crypto::eip2333::derive_master_sk;
    let seed = [0x42u8; 32];
    derive_master_sk(&seed).expect("derive master sk")
}

/// The public key bytes for `known_secret_key()`.
pub fn known_pubkey_bytes() -> [u8; 48] {
    known_secret_key().public_key().to_bytes()
}

/// The `KNOWN_PUBKEY_BYTES` static — lazily computed on first access.
pub static KNOWN_PUBKEY_BYTES: std::sync::LazyLock<[u8; 48]> =
    std::sync::LazyLock::new(known_pubkey_bytes);

/// Build a `SignerServiceImpl` backed by an in-memory key manager and an
/// on-disk slashing DB (tempfile, caller gets the path to re-open for assertions).
pub fn make_service_with_db() -> (SignerServiceImpl, PathBuf) {
    let sk = known_secret_key();
    let db_path = make_temp_db_path();

    let mut km = KeyManager::new();
    km.insert(sk);

    let backend = Arc::new(TestBackend { km: Arc::new(km) });
    let db = Arc::new(SlashingDb::open(&db_path).expect("open test DB"));

    let svc = SignerServiceImpl::new_v2(backend as Arc<dyn SigningBackend>, "test".to_string(), db);
    (svc, db_path)
}

/// Same as `make_service_with_db` but the backend has no keys loaded.
/// Calls to `backend.sign()` will return `KeyNotFound`.
pub fn make_service_with_db_unknown_key() -> (SignerServiceImpl, PathBuf) {
    let db_path = make_temp_db_path();
    let backend = Arc::new(TestBackend { km: Arc::new(KeyManager::new()) });
    let db = Arc::new(SlashingDb::open(&db_path).expect("open test DB"));
    let svc = SignerServiceImpl::new_v2(backend as Arc<dyn SigningBackend>, "test".to_string(), db);
    (svc, db_path)
}

/// Create a temporary file path for a slashing DB.
/// The file is kept alive by leaking the `NamedTempFile` handle.
fn make_temp_db_path() -> PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp); // keep file alive for the test
    path
}

// ── TestBackend ───────────────────────────────────────────────────────────────

struct TestBackend {
    km: Arc<KeyManager>,
}

#[async_trait::async_trait]
impl SigningBackend for TestBackend {
    async fn sign(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<[u8; 96], SigningBackendError> {
        let pk = crypto::PublicKey::from_bytes(pubkey)
            .map_err(|_| SigningBackendError::KeyNotFound(*pubkey))?;
        let sk = self.km.get_secret_key(&pk).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;
        let sig = sk.sign(signing_root);
        Ok(sig.to_bytes())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
    }
}

// ── SSZ helpers ───────────────────────────────────────────────────────────────

/// Minimal valid SSZ-encoded `BeaconBlock` for testing.
pub fn sample_block_ssz(slot: u64) -> Vec<u8> {
    use eth_types::BeaconBlock;
    let block = BeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: vec![0xde, 0xad, 0xbe, 0xef],
    };
    encode_beacon_block_ssz(&block, 4)
}

/// Minimal valid SSZ-encoded `BlindedBeaconBlock` for testing.
pub fn sample_blinded_block_ssz(slot: u64) -> Vec<u8> {
    use eth_types::{encode_blinded_beacon_block_ssz, BlindedBeaconBlock};
    let block = BlindedBeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0x33; 32],
        state_root: [0x44; 32],
        body: vec![0xca, 0xfe],
    };
    encode_blinded_beacon_block_ssz(&block, 4)
}

/// A `ForkInfo` proto message for testing (Deneb fork version, zero GVR).
pub fn sample_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: vec![0x04, 0x00, 0x00, 0x00],
        current_version: vec![0x04, 0x00, 0x00, 0x00],
        epoch: 0,
        genesis_validators_root: vec![0x00; 32],
    }
}
