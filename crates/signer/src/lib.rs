//! rvc-signer - Validator signing with slashing protection.
//!
//! This module provides a signing service that ensures all validator
//! signatures are checked against slashing protection rules before signing.

mod traits;

pub use crypto::is_aggregator;
pub use traits::ValidatorSigner;

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use thiserror::Error;

use crypto::{sign_attestation, KeyManager, PublicKey, Signature};
use eth_types::{
    AggregateAndProof, AttestationData, Epoch, Fork, ForkSchedule, Root, Slot,
    DOMAIN_SYNC_COMMITTEE, SLOTS_PER_EPOCH,
};
use metrics::definitions::{
    slashing_result, RVC_ATTESTATIONS_TOTAL, RVC_SIGNING_DURATION_SECONDS,
    RVC_SLASHING_PROTECTION_CHECKS_TOTAL,
};
use slashing::{SlashingDb, SlashingError};

/// Errors that can occur during signing operations.
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("key not found for pubkey: {0}")]
    KeyNotFound(String),

    #[error("slashing protection blocked signing: {0}")]
    SlashingProtectionBlocked(#[from] SlashingError),
}

/// Service that combines key management with slashing protection for signing.
pub struct SignerService {
    key_manager: Arc<KeyManager>,
    slashing_db: Arc<SlashingDb>,
}

impl SignerService {
    /// Creates a new SignerService with the provided key manager and slashing database.
    pub fn new(key_manager: Arc<KeyManager>, slashing_db: Arc<SlashingDb>) -> Self {
        Self { key_manager, slashing_db }
    }

    /// Signs an attestation after checking slashing protection.
    ///
    /// This method:
    /// 1. Computes the signing root
    /// 2. Atomically checks and records the attestation (prevents TOCTOU)
    /// 3. If blocked, increments metrics and returns an error
    /// 4. If safe, retrieves the secret key and signs the attestation
    /// 5. Updates metrics for signing duration and success count
    pub fn sign_attestation(
        &self,
        attestation_data: &AttestationData,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Root,
    ) -> Result<Signature, SignerError> {
        let start = Instant::now();

        let pubkey_hex = hex::encode(pubkey.to_bytes());

        let source_epoch = attestation_data.source.epoch;
        let target_epoch = attestation_data.target.epoch;

        let signing_root = hex::encode(crypto::compute_signing_root(
            attestation_data,
            crypto::compute_domain(
                crypto::DOMAIN_BEACON_ATTESTER,
                if target_epoch >= fork.epoch {
                    fork.current_version
                } else {
                    fork.previous_version
                },
                genesis_validators_root,
            ),
        ));

        if let Err(e) = self.slashing_db.check_and_record_attestation(
            &pubkey_hex,
            source_epoch,
            target_epoch,
            Some(signing_root),
        ) {
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL
                .with_label_values(&[slashing_result::BLOCKED])
                .inc();
            RVC_ATTESTATIONS_TOTAL.with_label_values(&["failed"]).inc();
            return Err(SignerError::SlashingProtectionBlocked(e));
        }

        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();

        let secret_key = self
            .key_manager
            .get_secret_key(pubkey)
            .ok_or_else(|| SignerError::KeyNotFound(pubkey_hex.clone()))?;

        let signature =
            sign_attestation(attestation_data, secret_key, fork, genesis_validators_root);

        let duration = start.elapsed().as_secs_f64();
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[]).observe(duration);
        RVC_ATTESTATIONS_TOTAL.with_label_values(&["success"]).inc();

        Ok(signature)
    }

    /// Signs a block after checking slashing protection.
    ///
    /// This method:
    /// 1. Computes the signing root
    /// 2. Atomically checks and records the block (prevents TOCTOU)
    /// 3. If blocked, increments metrics and returns an error
    /// 4. If safe, retrieves the secret key and signs the block
    pub fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let start = Instant::now();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            eth_types::DOMAIN_BEACON_PROPOSER,
            fork_version,
            *genesis_validators_root,
        );
        let signing_root = crypto::compute_signing_root(block_root, domain);
        let signing_root_hex = hex::encode(signing_root);

        if let Err(e) =
            self.slashing_db.check_and_record_block(&pubkey_hex, slot, Some(signing_root_hex))
        {
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL
                .with_label_values(&[slashing_result::BLOCKED])
                .inc();
            return Err(SignerError::SlashingProtectionBlocked(e));
        }

        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();

        let secret_key = self
            .key_manager
            .get_secret_key(pubkey)
            .ok_or_else(|| SignerError::KeyNotFound(pubkey_hex.clone()))?;

        let signature = crypto::sign_block(
            block_root,
            slot,
            secret_key,
            fork_schedule,
            genesis_validators_root,
        );

        let duration = start.elapsed().as_secs_f64();
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[]).observe(duration);

        Ok(signature)
    }

    /// Signs a RANDAO reveal for the given epoch.
    pub fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        let secret_key = self
            .key_manager
            .get_secret_key(pubkey)
            .ok_or_else(|| SignerError::KeyNotFound(pubkey_hex))?;

        let signature =
            crypto::sign_randao_reveal(epoch, secret_key, fork_schedule, genesis_validators_root);

        Ok(signature)
    }

    /// Signs a sync committee message for the given beacon block root and slot.
    pub fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        let secret_key = self
            .key_manager
            .get_secret_key(pubkey)
            .ok_or_else(|| SignerError::KeyNotFound(pubkey_hex))?;

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain =
            crypto::compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, *genesis_validators_root);
        let signing_root = crypto::compute_signing_root(beacon_block_root, domain);

        Ok(secret_key.sign(&signing_root))
    }

    /// Signs a slot with DOMAIN_SELECTION_PROOF to produce a selection proof.
    pub fn sign_selection_proof(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        let secret_key = self
            .key_manager
            .get_secret_key(pubkey)
            .ok_or_else(|| SignerError::KeyNotFound(pubkey_hex))?;

        Ok(crypto::sign_selection_proof(slot, secret_key, fork_schedule, *genesis_validators_root))
    }

    /// Signs an AggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    pub fn sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        let secret_key = self
            .key_manager
            .get_secret_key(pubkey)
            .ok_or_else(|| SignerError::KeyNotFound(pubkey_hex))?;

        Ok(crypto::sign_aggregate_and_proof(
            aggregate_and_proof,
            secret_key,
            fork_schedule,
            *genesis_validators_root,
        ))
    }

    /// Returns a reference to the underlying key manager.
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Returns a reference to the underlying slashing database.
    pub fn slashing_db(&self) -> &SlashingDb {
        &self.slashing_db
    }
}

#[async_trait(?Send)]
impl ValidatorSigner for SignerService {
    async fn sign_attestation(
        &self,
        data: &AttestationData,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let target_epoch = data.target.epoch;
        let epoch = target_epoch;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let prior_fork_name = if epoch > 0 {
            eth_types::ForkName::from_epoch(epoch - 1, fork_schedule)
        } else {
            eth_types::ForkName::from_epoch(0, fork_schedule)
        };
        let prior_fork_version = prior_fork_name.fork_version(fork_schedule);

        let fork = Fork {
            previous_version: prior_fork_version,
            current_version: fork_version,
            epoch: if fork_version != prior_fork_version { epoch } else { 0 },
        };

        let signature =
            SignerService::sign_attestation(self, data, pubkey, &fork, *genesis_validators_root)?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_block(
            self,
            block_root,
            slot,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_randao_reveal(
            self,
            epoch,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_sync_committee_message(
            self,
            beacon_block_root,
            slot,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_selection_proof(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_selection_proof(
            self,
            slot,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_aggregate_and_proof(
            self,
            aggregate_and_proof,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )?;
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{compute_domain, compute_signing_root, SecretKey, DOMAIN_BEACON_ATTESTER};
    use eth_types::Checkpoint;

    fn create_test_key_manager_with_key(secret_key: SecretKey) -> KeyManager {
        let mut manager = KeyManager::new();
        manager.insert(secret_key);
        manager
    }

    fn create_test_attestation_data(source_epoch: u64, target_epoch: u64) -> AttestationData {
        AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: source_epoch, root: [0x22; 32] },
            target: Checkpoint { epoch: target_epoch, root: [0x33; 32] },
        }
    }

    fn create_test_fork() -> Fork {
        Fork {
            previous_version: [0x00, 0x00, 0x00, 0x01],
            current_version: [0x00, 0x00, 0x00, 0x02],
            epoch: 50,
        }
    }

    #[test]
    fn test_signer_service_creation() {
        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager.clone(), slashing_db.clone());

        assert!(service.key_manager().is_empty());
    }

    #[test]
    fn test_sign_attestation_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db.clone());

        let attestation_data = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result = service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root);

        assert!(result.is_ok());
        let signature = result.unwrap();

        let fork_version = fork.current_version;
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&pubkey, &signing_root).is_ok());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert!(attestations[0].signing_root.is_some());
    }

    #[test]
    fn test_sign_attestation_success_uses_previous_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let fork = Fork {
            previous_version: [0x00, 0x00, 0x00, 0x01],
            current_version: [0x00, 0x00, 0x00, 0x02],
            epoch: 100,
        };
        let attestation_data = create_test_attestation_data(50, 51);
        let genesis_root = [0xaa; 32];

        let result = service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root);

        assert!(result.is_ok());
        let signature = result.unwrap();

        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork.previous_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_attestation_records_in_slashing_db() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db.clone());

        let attestation_data = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        service
            .sign_attestation(&attestation_data, &pubkey, &fork, genesis_root)
            .expect("signing should succeed");

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].pubkey, pubkey_hex);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
    }

    #[test]
    fn test_sign_attestation_prevents_double_vote_after_signing() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let attestation_data1 = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result1 = service.sign_attestation(&attestation_data1, &pubkey, &fork, genesis_root);
        assert!(result1.is_ok());

        let attestation_data2 = create_test_attestation_data(99, 101);
        let result2 = service.sign_attestation(&attestation_data2, &pubkey, &fork, genesis_root);

        assert!(result2.is_err());
        match result2.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            _ => panic!("expected SlashingProtectionBlocked error"),
        }
    }

    #[test]
    fn test_sign_attestation_allows_multiple_non_conflicting() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db.clone());

        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let attestation_data1 = create_test_attestation_data(100, 101);
        let result1 = service.sign_attestation(&attestation_data1, &pubkey, &fork, genesis_root);
        assert!(result1.is_ok());

        let attestation_data2 = create_test_attestation_data(101, 102);
        let result2 = service.sign_attestation(&attestation_data2, &pubkey, &fork, genesis_root);
        assert!(result2.is_ok());

        let attestation_data3 = create_test_attestation_data(102, 103);
        let result3 = service.sign_attestation(&attestation_data3, &pubkey, &fork, genesis_root);
        assert!(result3.is_ok());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("failed to get");
        assert_eq!(attestations.len(), 3);
    }

    #[test]
    fn test_sign_attestation_key_not_found() {
        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(key_manager, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let attestation_data = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result = service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(pk) => {
                assert_eq!(pk, hex::encode(pubkey.to_bytes()));
            }
            _ => panic!("expected KeyNotFound error"),
        }
    }

    #[test]
    fn test_sign_attestation_slashing_blocked_double_vote() {
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        slashing_db.record_attestation(&pubkey_hex, 100, 101, None).expect("record should succeed");

        let key_manager = Arc::new(KeyManager::new());
        let service = SignerService::new(key_manager, slashing_db);

        let attestation_data = create_test_attestation_data(99, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result = service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            _ => panic!("expected SlashingProtectionBlocked error"),
        }
    }

    #[test]
    fn test_sign_attestation_slashing_blocked_surrounding_vote() {
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        slashing_db.record_attestation(&pubkey_hex, 5, 10, None).expect("record should succeed");

        let key_manager = Arc::new(KeyManager::new());
        let service = SignerService::new(key_manager, slashing_db);

        let attestation_data = create_test_attestation_data(4, 11);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result = service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            _ => panic!("expected SlashingProtectionBlocked error"),
        }
    }

    #[test]
    fn test_sign_attestation_slashing_blocked_surrounded_vote() {
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        slashing_db.record_attestation(&pubkey_hex, 4, 11, None).expect("record should succeed");

        let key_manager = Arc::new(KeyManager::new());
        let service = SignerService::new(key_manager, slashing_db);

        let attestation_data = create_test_attestation_data(5, 10);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result = service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root);

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            _ => panic!("expected SlashingProtectionBlocked error"),
        }
    }

    #[test]
    fn test_sign_attestation_different_validators_isolated() {
        let secret_key1 = SecretKey::generate();
        let secret_key2 = SecretKey::generate();
        let pubkey1 = secret_key1.public_key();
        let pubkey2 = secret_key2.public_key();

        let mut key_manager = KeyManager::new();
        key_manager.insert(secret_key1);
        key_manager.insert(secret_key2);
        let key_manager = Arc::new(key_manager);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(key_manager, slashing_db);

        let attestation_data = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result1 = service.sign_attestation(&attestation_data, &pubkey1, &fork, genesis_root);
        assert!(result1.is_ok());

        let result2 = service.sign_attestation(&attestation_data, &pubkey2, &fork, genesis_root);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_signer_error_display() {
        let err = SignerError::KeyNotFound("abc123".to_string());
        assert_eq!(err.to_string(), "key not found for pubkey: abc123");

        use slashing::AttestationSlashingViolation;
        let slashing_err =
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch: 100,
            });
        let err = SignerError::SlashingProtectionBlocked(slashing_err);
        assert!(err.to_string().contains("slashing protection blocked"));
    }

    #[test]
    fn test_signer_service_accessors() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        assert!(!service.key_manager().is_empty());
        assert_eq!(service.key_manager().len(), 1);

        let keys = service.key_manager().list_public_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].to_bytes(), pubkey.to_bytes());
    }

    // --- Block signing tests ---

    fn create_test_fork_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 30,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 40,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 50,
            electra_fork_version: [5, 0, 0, 0],
        }
    }

    #[test]
    fn test_sign_block_safe_proposal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db.clone());

        let block_root = [0x11; 32];
        let slot = 5;
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root);
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_version = schedule.genesis_fork_version;
        let domain = compute_domain(eth_types::DOMAIN_BEACON_PROPOSER, fork_version, genesis_root);
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 5);
        assert!(blocks[0].signing_root.is_some());
    }

    #[test]
    fn test_sign_block_double_proposal_rejected() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result1 = service.sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root);
        assert!(result1.is_ok());

        let result2 = service.sign_block(&[0x22; 32], 5, &pubkey, &schedule, &genesis_root);
        assert!(result2.is_err());
        match result2.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            other => panic!("expected SlashingProtectionBlocked, got: {other:?}"),
        }
    }

    #[test]
    fn test_sign_block_idempotent_resign() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db.clone());

        let block_root = [0x11; 32];
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result1 = service.sign_block(&block_root, 5, &pubkey, &schedule, &genesis_root);
        assert!(result1.is_ok());

        let result2 = service.sign_block(&block_root, 5, &pubkey, &schedule, &genesis_root);
        assert!(result2.is_ok());

        let sig1 = result1.unwrap();
        let sig2 = result2.unwrap();
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_sign_block_key_not_found() {
        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(key_manager, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn test_sign_block_fork_aware() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let block_root = [0x11; 32];
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        // Slot in Altair epoch (epoch 15, slot 480)
        let altair_slot = SLOTS_PER_EPOCH * 15;
        let result =
            service.sign_block(&block_root, altair_slot, &pubkey, &schedule, &genesis_root);
        assert!(result.is_ok());

        let signature = result.unwrap();

        let domain = compute_domain(
            eth_types::DOMAIN_BEACON_PROPOSER,
            schedule.altair_fork_version,
            genesis_root,
        );
        let signing_root = compute_signing_root(&block_root, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- RANDAO signing tests ---

    #[test]
    fn test_sign_randao_reveal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let epoch = 5_u64;

        let result = service.sign_randao_reveal(epoch, &pubkey, &schedule, &genesis_root);
        assert!(result.is_ok());

        let signature = result.unwrap();

        let domain =
            compute_domain(eth_types::DOMAIN_RANDAO, schedule.genesis_fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_randao_reveal_key_not_found() {
        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(key_manager, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn test_sign_randao_reveal_fork_aware() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let epoch = 45_u64; // Deneb

        let result = service.sign_randao_reveal(epoch, &pubkey, &schedule, &genesis_root);
        assert!(result.is_ok());

        let signature = result.unwrap();
        let domain =
            compute_domain(eth_types::DOMAIN_RANDAO, schedule.deneb_fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- Sync committee signing tests ---

    #[test]
    fn test_sign_sync_committee_message() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let beacon_block_root = [0x11; 32];
        let slot = SLOTS_PER_EPOCH * 15; // Altair epoch
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_sync_committee_message(
            &beacon_block_root,
            slot,
            &pubkey,
            &schedule,
            &genesis_root,
        );
        assert!(result.is_ok());

        let signature = result.unwrap();

        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&beacon_block_root, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_sync_committee_message_key_not_found() {
        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(key_manager, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_sync_committee_message(
            &[0x11; 32],
            SLOTS_PER_EPOCH * 15,
            &pubkey,
            &schedule,
            &genesis_root,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    // --- ValidatorSigner trait tests ---

    #[tokio::test]
    async fn test_trait_sign_block_safe_proposal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db.clone());
        let signer: &dyn ValidatorSigner = &service;

        let block_root = [0x11; 32];
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = signer.sign_block(&block_root, 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[tokio::test]
    async fn test_trait_sign_randao_reveal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);
        let signer: &dyn ValidatorSigner = &service;

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = signer.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);
    }

    #[tokio::test]
    async fn test_trait_sign_sync_committee_message() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);
        let signer: &dyn ValidatorSigner = &service;

        let beacon_block_root = [0x11; 32];
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = signer
            .sign_sync_committee_message(
                &beacon_block_root,
                SLOTS_PER_EPOCH * 15,
                &pubkey,
                &schedule,
                &genesis_root,
            )
            .await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);
    }

    #[tokio::test]
    async fn test_trait_sign_attestation_still_works() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db.clone());
        let signer: &dyn ValidatorSigner = &service;

        let attestation_data = create_test_attestation_data(100, 101);
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result =
            signer.sign_attestation(&attestation_data, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    // --- Aggregation signing tests ---

    fn create_test_aggregate_and_proof(slot: Slot) -> eth_types::AggregateAndProof {
        eth_types::AggregateAndProof {
            aggregator_index: 42,
            aggregate: eth_types::Attestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot,
                    index: 1,
                    beacon_block_root: [1u8; 32],
                    source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [2u8; 32] },
                    target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH + 1, root: [3u8; 32] },
                },
                signature: vec![0xaa; 96],
            },
            selection_proof: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_sign_selection_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let slot: Slot = 100;

        let result = service.sign_selection_proof(slot, &pubkey, &schedule, &genesis_root);
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(eth_types::DOMAIN_SELECTION_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&slot, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_selection_proof_key_not_found() {
        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(key_manager, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_selection_proof(100, &pubkey, &schedule, &genesis_root);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn test_sign_aggregate_and_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let agg_and_proof = create_test_aggregate_and_proof(100);

        let result =
            service.sign_aggregate_and_proof(&agg_and_proof, &pubkey, &schedule, &genesis_root);
        assert!(result.is_ok());

        let signature = result.unwrap();

        let slot = agg_and_proof.aggregate.data.slot;
        let fork_name = eth_types::ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain =
            compute_domain(eth_types::DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&agg_and_proof, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_sign_aggregate_and_proof_key_not_found() {
        let key_manager = Arc::new(KeyManager::new());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(key_manager, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let agg_and_proof = create_test_aggregate_and_proof(100);

        let result =
            service.sign_aggregate_and_proof(&agg_and_proof, &pubkey, &schedule, &genesis_root);
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn test_is_aggregator_reexported() {
        // Verify that is_aggregator is accessible from signer crate
        // committee_length=0 → modulo=max(1,0/16)=1 → always aggregator
        assert!(is_aggregator(0, &[0xaa; 96]));
        // committee_length=1 → modulo=max(1,1/16)=1 → always aggregator
        assert!(is_aggregator(1, &[0xaa; 96]));
    }

    // --- Aggregation trait tests ---

    #[tokio::test]
    async fn test_trait_sign_selection_proof() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);
        let signer: &dyn ValidatorSigner = &service;

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = signer.sign_selection_proof(100, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);
    }

    #[tokio::test]
    async fn test_trait_sign_aggregate_and_proof() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let key_manager = Arc::new(create_test_key_manager_with_key(secret_key));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(key_manager, slashing_db);
        let signer: &dyn ValidatorSigner = &service;

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let agg_and_proof = create_test_aggregate_and_proof(100);

        let result = signer
            .sign_aggregate_and_proof(&agg_and_proof, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);
    }
}
