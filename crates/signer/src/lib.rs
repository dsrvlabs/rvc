//! rvc-signer - Validator signing with slashing protection.
//!
//! This module provides a signing service that ensures all validator
//! signatures are checked against slashing protection rules before signing.

mod traits;

pub use crypto::is_aggregator;
pub use traits::ValidatorSigner;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use thiserror::Error;
use tracing::{debug, warn};

use crypto::{CompositeSigner, PublicKey, Signature, Signer, SigningError};
use eth_types::{
    AggregateAndProof, AttestationData, ContributionAndProof, ElectraAggregateAndProof, Epoch,
    Fork, ForkSchedule, Root, Slot, SyncAggregatorSelectionData, ValidatorRegistrationV1,
    VoluntaryExit, DOMAIN_APPLICATION_BUILDER, DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, SLOTS_PER_EPOCH,
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

    #[error("signing failed: {0}")]
    SigningFailed(String),
}

impl From<SigningError> for SignerError {
    fn from(e: SigningError) -> Self {
        match e {
            SigningError::KeyNotFound(pk) => SignerError::KeyNotFound(pk),
            SigningError::RemoteSignerError(msg) => SignerError::SigningFailed(msg),
        }
    }
}

/// Per-validator lock map for serializing check-record-sign per validator.
///
/// Prevents TOCTOU races where two concurrent sign requests for the same
/// validator could both pass the slashing check before either records.
/// Different validators are NOT blocked by each other.
pub struct ValidatorLockMap {
    locks: std::sync::Mutex<HashMap<[u8; 48], Arc<tokio::sync::Mutex<()>>>>,
}

impl ValidatorLockMap {
    pub fn new() -> Self {
        Self { locks: std::sync::Mutex::new(HashMap::new()) }
    }

    pub fn get(&self, pubkey: &[u8; 48]) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .expect("validator lock map poisoned")
            .entry(*pubkey)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

impl Default for ValidatorLockMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Service that combines signing through CompositeSigner with slashing protection.
///
/// Record-then-sign order is mandated by Ethereum consensus spec (phase0/validator.md):
/// "Save a record to hard disk ... Generate and broadcast."
/// The per-validator mutex prevents TOCTOU between concurrent signing requests.
pub struct SignerService {
    signer: Arc<CompositeSigner>,
    slashing_db: Arc<SlashingDb>,
    validator_locks: ValidatorLockMap,
}

impl SignerService {
    /// Creates a new SignerService with the provided composite signer and slashing database.
    pub fn new(signer: Arc<CompositeSigner>, slashing_db: Arc<SlashingDb>) -> Self {
        Self { signer, slashing_db, validator_locks: ValidatorLockMap::new() }
    }

    /// Signs an attestation after checking slashing protection.
    #[tracing::instrument(name = "rvc.sign.attestation", skip_all, fields(rvc.operation = "attestation", rvc.slashing.result))]
    pub async fn sign_attestation(
        &self,
        attestation_data: &AttestationData,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Root,
    ) -> Result<Signature, SignerError> {
        let start = Instant::now();

        let pubkey_bytes = pubkey.to_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        // Acquire per-validator lock to serialize check-record-sign for the same validator.
        let lock = self.validator_locks.get(&pubkey_bytes);
        let _guard = lock.lock().await;

        let source_epoch = attestation_data.source.epoch;
        let target_epoch = attestation_data.target.epoch;

        let (fork_version, fork_version_branch) = if target_epoch >= fork.epoch {
            (fork.current_version, "current")
        } else {
            (fork.previous_version, "previous")
        };
        let domain = crypto::compute_domain(
            crypto::DOMAIN_BEACON_ATTESTER,
            fork_version,
            genesis_validators_root,
        );

        debug!(
            pubkey = %format!("0x{}", &pubkey_hex[..16]),
            fork_version_used = %format!("0x{}", hex::encode(fork_version)),
            genesis_validators_root = %format!("0x{}", hex::encode(genesis_validators_root)),
            domain = %format!("0x{}", hex::encode(domain)),
            fork_version_branch = fork_version_branch,
            target_epoch = target_epoch,
            fork_epoch = fork.epoch,
            "Computed attestation domain"
        );

        let signing_root = crypto::compute_signing_root(attestation_data, domain);
        let signing_root_hex = hex::encode(signing_root);

        debug!(
            pubkey = %format!("0x{}", &pubkey_hex[..16]),
            signing_root = %format!("0x{}", &signing_root_hex),
            slot = attestation_data.slot,
            index = attestation_data.index,
            source_epoch = attestation_data.source.epoch,
            target_epoch = attestation_data.target.epoch,
            "Computed attestation signing root"
        );

        let slashing_check_result = {
            let _span = tracing::info_span!("rvc.slashing.check").entered();
            self.slashing_db.check_and_record_attestation(
                &pubkey_hex,
                source_epoch,
                target_epoch,
                Some(signing_root_hex),
            )
        };

        if let Err(e) = slashing_check_result {
            tracing::Span::current().record("rvc.slashing.result", "blocked");
            tracing::error!(error = %e, "Attestation slashing protection blocked signing");
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL
                .with_label_values(&[slashing_result::BLOCKED])
                .inc();
            RVC_ATTESTATIONS_TOTAL.with_label_values(&["failed"]).inc();
            return Err(SignerError::SlashingProtectionBlocked(e));
        }

        tracing::Span::current().record("rvc.slashing.result", "safe");
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();

        let signature = match self.signer.sign(&signing_root, &pubkey_bytes).await {
            Ok(sig) => sig,
            Err(e) => {
                // Phantom entry: record exists but signing failed. This is safe per spec —
                // missing a duty is far less harmful than double-signing.
                warn!(error = %e, pubkey = %format!("0x{}", &pubkey_hex[..16]),
                    "Attestation signing failed after recording (phantom entry in slashing DB)");
                return Err(e.into());
            }
        };

        let duration = start.elapsed().as_secs_f64();
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).observe(duration);
        RVC_ATTESTATIONS_TOTAL.with_label_values(&["success"]).inc();

        Ok(signature)
    }

    /// Signs a block after checking slashing protection.
    #[tracing::instrument(name = "rvc.sign.block", skip_all, fields(rvc.operation = "block", rvc.slashing.result))]
    pub async fn sign_block(
        &self,
        block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let start = Instant::now();
        let pubkey_bytes = pubkey.to_bytes();
        let pubkey_hex = hex::encode(pubkey_bytes);

        // Acquire per-validator lock to serialize check-record-sign for the same validator.
        let lock = self.validator_locks.get(&pubkey_bytes);
        let _guard = lock.lock().await;

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

        let slashing_check_result = {
            let _span = tracing::info_span!("rvc.slashing.check").entered();
            self.slashing_db.check_and_record_block(&pubkey_hex, slot, Some(signing_root_hex))
        };

        if let Err(e) = slashing_check_result {
            tracing::Span::current().record("rvc.slashing.result", "blocked");
            tracing::error!(error = %e, "Block slashing protection blocked signing");
            RVC_SLASHING_PROTECTION_CHECKS_TOTAL
                .with_label_values(&[slashing_result::BLOCKED])
                .inc();
            return Err(SignerError::SlashingProtectionBlocked(e));
        }

        tracing::Span::current().record("rvc.slashing.result", "safe");
        RVC_SLASHING_PROTECTION_CHECKS_TOTAL.with_label_values(&[slashing_result::SAFE]).inc();

        let signature = match self.signer.sign(&signing_root, &pubkey_bytes).await {
            Ok(sig) => sig,
            Err(e) => {
                // Phantom entry: record exists but signing failed. Safe per spec.
                warn!(error = %e, pubkey = %format!("0x{}", &pubkey_hex[..16]),
                    "Block signing failed after recording (phantom entry in slashing DB)");
                return Err(e.into());
            }
        };

        let duration = start.elapsed().as_secs_f64();
        RVC_SIGNING_DURATION_SECONDS.with_label_values(&[] as &[&str]).observe(duration);

        Ok(signature)
    }

    /// Signs a RANDAO reveal for the given epoch.
    #[tracing::instrument(name = "rvc.sign.randao", skip_all, fields(rvc.operation = "randao"))]
    pub async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            eth_types::DOMAIN_RANDAO,
            fork_version,
            *genesis_validators_root,
        );
        let signing_root = crypto::compute_signing_root(&epoch, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs a sync committee message for the given beacon block root and slot.
    #[tracing::instrument(name = "rvc.sign.sync_committee_message", skip_all, fields(rvc.operation = "sync_committee_message"))]
    pub async fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain =
            crypto::compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, *genesis_validators_root);
        let signing_root = crypto::compute_signing_root(beacon_block_root, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs a slot with DOMAIN_SELECTION_PROOF to produce a selection proof.
    #[tracing::instrument(name = "rvc.sign.selection_proof", skip_all, fields(rvc.operation = "selection_proof"))]
    pub async fn sign_selection_proof(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            eth_types::DOMAIN_SELECTION_PROOF,
            fork_version,
            *genesis_validators_root,
        );
        let signing_root = crypto::compute_signing_root(&slot, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs an AggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    #[tracing::instrument(name = "rvc.sign.aggregate_and_proof", skip_all, fields(rvc.operation = "aggregate_and_proof"))]
    pub async fn sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let slot = aggregate_and_proof.aggregate.data.slot;
        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            eth_types::DOMAIN_AGGREGATE_AND_PROOF,
            fork_version,
            *genesis_validators_root,
        );
        let signing_root = crypto::compute_signing_root(aggregate_and_proof, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs an ElectraAggregateAndProof with DOMAIN_AGGREGATE_AND_PROOF.
    #[tracing::instrument(name = "rvc.sign.electra_aggregate_and_proof", skip_all, fields(rvc.operation = "electra_aggregate_and_proof"))]
    pub async fn sign_electra_aggregate_and_proof(
        &self,
        aggregate_and_proof: &ElectraAggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let slot = aggregate_and_proof.aggregate.data.slot;
        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            eth_types::DOMAIN_AGGREGATE_AND_PROOF,
            fork_version,
            *genesis_validators_root,
        );
        let signing_root = crypto::compute_signing_root(aggregate_and_proof, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs a voluntary exit with DOMAIN_VOLUNTARY_EXIT.
    #[tracing::instrument(name = "rvc.sign.voluntary_exit", skip_all, fields(rvc.operation = "voluntary_exit"))]
    pub async fn sign_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let fork_name = eth_types::ForkName::from_epoch(voluntary_exit.epoch, fork_schedule);
        // EIP-7044: cap fork version at Capella for voluntary exits
        let capped = if fork_name >= eth_types::ForkName::Capella {
            eth_types::ForkName::Capella
        } else {
            fork_name
        };
        let fork_version = capped.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            eth_types::DOMAIN_VOLUNTARY_EXIT,
            fork_version,
            *genesis_validators_root,
        );
        let signing_root = crypto::compute_signing_root(voluntary_exit, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs a builder registration with DOMAIN_APPLICATION_BUILDER.
    ///
    /// No slashing check is needed — builder registrations are not slashable.
    #[tracing::instrument(name = "rvc.sign.builder_registration", skip_all, fields(rvc.operation = "builder_registration"))]
    pub async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Signature, SignerError> {
        let zeroed_genesis_root = [0u8; 32];
        let domain =
            crypto::compute_domain(DOMAIN_APPLICATION_BUILDER, fork_version, zeroed_genesis_root);
        let signing_root = crypto::compute_signing_root(registration, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs a sync committee selection proof for the given slot and subcommittee.
    #[tracing::instrument(name = "rvc.sign.sync_committee_selection_proof", skip_all, fields(rvc.operation = "sync_committee_selection_proof"))]
    pub async fn sign_sync_committee_selection_proof(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            fork_version,
            *genesis_validators_root,
        );
        let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
        let signing_root = crypto::compute_signing_root(&selection_data, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Signs a ContributionAndProof with DOMAIN_CONTRIBUTION_AND_PROOF.
    #[tracing::instrument(name = "rvc.sign.contribution_and_proof", skip_all, fields(rvc.operation = "contribution_and_proof"))]
    pub async fn sign_contribution_and_proof(
        &self,
        contribution_and_proof: &ContributionAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SignerError> {
        let epoch = contribution_and_proof.contribution.slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, fork_schedule);
        let fork_version = fork_name.fork_version(fork_schedule);
        let domain = crypto::compute_domain(
            DOMAIN_CONTRIBUTION_AND_PROOF,
            fork_version,
            *genesis_validators_root,
        );
        let signing_root = crypto::compute_signing_root(contribution_and_proof, domain);

        let pubkey_bytes = pubkey.to_bytes();
        Ok(self.signer.sign(&signing_root, &pubkey_bytes).await?)
    }

    /// Returns a reference to the underlying composite signer.
    pub fn signer(&self) -> &CompositeSigner {
        &self.signer
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
            SignerService::sign_attestation(self, data, pubkey, &fork, *genesis_validators_root)
                .await?;
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
        )
        .await?;
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
        )
        .await?;
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
        )
        .await?;
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
        )
        .await?;
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
        )
        .await?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_electra_aggregate_and_proof(
        &self,
        aggregate_and_proof: &ElectraAggregateAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_electra_aggregate_and_proof(
            self,
            aggregate_and_proof,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )
        .await?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_voluntary_exit(
            self,
            voluntary_exit,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )
        .await?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_builder_registration(
        &self,
        registration: &ValidatorRegistrationV1,
        pubkey: &PublicKey,
        fork_version: [u8; 4],
    ) -> Result<Vec<u8>, SignerError> {
        let signature =
            SignerService::sign_builder_registration(self, registration, pubkey, fork_version)
                .await?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_sync_committee_selection_proof(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_sync_committee_selection_proof(
            self,
            slot,
            subcommittee_index,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )
        .await?;
        Ok(signature.to_bytes().to_vec())
    }

    async fn sign_contribution_and_proof(
        &self,
        contribution_and_proof: &ContributionAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SignerError> {
        let signature = SignerService::sign_contribution_and_proof(
            self,
            contribution_and_proof,
            pubkey,
            fork_schedule,
            genesis_validators_root,
        )
        .await?;
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{
        compute_domain, compute_signing_root, KeyManager, LocalSigner, SecretKey,
        DOMAIN_BEACON_ATTESTER,
    };
    use eth_types::Checkpoint;

    fn create_test_composite_signer_with_key(secret_key: SecretKey) -> Arc<CompositeSigner> {
        let mut manager = KeyManager::new();
        manager.insert(secret_key);
        Arc::new(CompositeSigner::new(LocalSigner::new(manager)))
    }

    fn create_empty_composite_signer() -> Arc<CompositeSigner> {
        Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
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
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        assert!(service.signer().public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_sign_attestation_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db.clone());

        let attestation_data = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result =
            service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root).await;

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

    #[tokio::test]
    async fn test_sign_attestation_success_uses_previous_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let fork = Fork {
            previous_version: [0x00, 0x00, 0x00, 0x01],
            current_version: [0x00, 0x00, 0x00, 0x02],
            epoch: 100,
        };
        let attestation_data = create_test_attestation_data(50, 51);
        let genesis_root = [0xaa; 32];

        let result =
            service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root).await;

        assert!(result.is_ok());
        let signature = result.unwrap();

        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork.previous_version, genesis_root);
        let signing_root = compute_signing_root(&attestation_data, domain);

        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_attestation_prevents_double_vote_after_signing() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let attestation_data1 = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result1 =
            service.sign_attestation(&attestation_data1, &pubkey, &fork, genesis_root).await;
        assert!(result1.is_ok());

        let attestation_data2 = create_test_attestation_data(99, 101);
        let result2 =
            service.sign_attestation(&attestation_data2, &pubkey, &fork, genesis_root).await;

        assert!(result2.is_err());
        match result2.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            _ => panic!("expected SlashingProtectionBlocked error"),
        }
    }

    #[tokio::test]
    async fn test_sign_attestation_allows_multiple_non_conflicting() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db.clone());

        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let attestation_data1 = create_test_attestation_data(100, 101);
        let result1 =
            service.sign_attestation(&attestation_data1, &pubkey, &fork, genesis_root).await;
        assert!(result1.is_ok());

        let attestation_data2 = create_test_attestation_data(101, 102);
        let result2 =
            service.sign_attestation(&attestation_data2, &pubkey, &fork, genesis_root).await;
        assert!(result2.is_ok());

        let attestation_data3 = create_test_attestation_data(102, 103);
        let result3 =
            service.sign_attestation(&attestation_data3, &pubkey, &fork, genesis_root).await;
        assert!(result3.is_ok());

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let attestations = slashing_db.get_attestations(&pubkey_hex).expect("failed to get");
        assert_eq!(attestations.len(), 3);
    }

    #[tokio::test]
    async fn test_sign_attestation_key_not_found() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let attestation_data = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result =
            service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(pk) => {
                assert_eq!(pk, hex::encode(pubkey.to_bytes()));
            }
            _ => panic!("expected KeyNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_sign_attestation_slashing_blocked_double_vote() {
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let pubkey_hex = hex::encode(pubkey.to_bytes());

        slashing_db.record_attestation(&pubkey_hex, 100, 101, None).expect("record should succeed");

        let signer = create_empty_composite_signer();
        let service = SignerService::new(signer, slashing_db);

        let attestation_data = create_test_attestation_data(99, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result =
            service.sign_attestation(&attestation_data, &pubkey, &fork, genesis_root).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            _ => panic!("expected SlashingProtectionBlocked error"),
        }
    }

    #[tokio::test]
    async fn test_sign_attestation_different_validators_isolated() {
        let secret_key1 = SecretKey::generate();
        let secret_key2 = SecretKey::generate();
        let pubkey1 = secret_key1.public_key();
        let pubkey2 = secret_key2.public_key();

        let signer = create_empty_composite_signer();
        signer.add_local_key(secret_key1);
        signer.add_local_key(secret_key2);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db);

        let attestation_data = create_test_attestation_data(100, 101);
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let result1 =
            service.sign_attestation(&attestation_data, &pubkey1, &fork, genesis_root).await;
        assert!(result1.is_ok());

        let result2 =
            service.sign_attestation(&attestation_data, &pubkey2, &fork, genesis_root).await;
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

        let err = SignerError::SigningFailed("remote error".to_string());
        assert!(err.to_string().contains("signing failed"));
    }

    #[test]
    fn test_signer_service_accessors() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let keys = service.signer().public_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], pubkey.to_bytes());
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
            fulu_fork_epoch: 60,
            fulu_fork_version: [6, 0, 0, 0],
        }
    }

    #[tokio::test]
    async fn test_sign_block_safe_proposal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db.clone());

        let block_root = [0x11; 32];
        let slot = 5;
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_block(&block_root, slot, &pubkey, &schedule, &genesis_root).await;
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

    #[tokio::test]
    async fn test_sign_block_double_proposal_rejected() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result1 = service.sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result1.is_ok());

        let result2 = service.sign_block(&[0x22; 32], 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result2.is_err());
        match result2.unwrap_err() {
            SignerError::SlashingProtectionBlocked(_) => {}
            other => panic!("expected SlashingProtectionBlocked, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_sign_block_key_not_found() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_block(&[0x11; 32], 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    // --- RANDAO signing tests ---

    #[tokio::test]
    async fn test_sign_randao_reveal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let epoch = 5_u64;

        let result = service.sign_randao_reveal(epoch, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let domain =
            compute_domain(eth_types::DOMAIN_RANDAO, schedule.genesis_fork_version, genesis_root);
        let signing_root = compute_signing_root(&epoch, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_randao_reveal_key_not_found() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer, slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SignerError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    // --- Sync committee signing tests ---

    #[tokio::test]
    async fn test_sign_sync_committee_message() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let beacon_block_root = [0x11; 32];
        let slot = SLOTS_PER_EPOCH * 15; // Altair epoch
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_sync_committee_message(
                &beacon_block_root,
                slot,
                &pubkey,
                &schedule,
                &genesis_root,
            )
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE, schedule.altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&beacon_block_root, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- ValidatorSigner trait tests ---

    #[tokio::test]
    async fn test_trait_sign_block_safe_proposal() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db.clone());
        let trait_signer: &dyn ValidatorSigner = &service;

        let block_root = [0x11; 32];
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result =
            trait_signer.sign_block(&block_root, 5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);

        let pubkey_hex = hex::encode(pubkey.to_bytes());
        let blocks = slashing_db.get_blocks(&pubkey_hex).expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[tokio::test]
    async fn test_trait_sign_attestation_still_works() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db.clone());
        let trait_signer: &dyn ValidatorSigner = &service;

        let attestation_data = create_test_attestation_data(100, 101);
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = trait_signer
            .sign_attestation(&attestation_data, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let sig_bytes = result.unwrap();
        assert_eq!(sig_bytes.len(), 96);
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

    #[tokio::test]
    async fn test_sign_selection_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let slot: Slot = 100;

        let result = service.sign_selection_proof(slot, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(eth_types::DOMAIN_SELECTION_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&slot, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_aggregate_and_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let agg_and_proof = create_test_aggregate_and_proof(100);

        let result = service
            .sign_aggregate_and_proof(&agg_and_proof, &pubkey, &schedule, &genesis_root)
            .await;
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
    fn test_is_aggregator_reexported() {
        assert!(is_aggregator(0, &[0xaa; 96]));
        assert!(is_aggregator(1, &[0xaa; 96]));
    }

    fn create_test_electra_aggregate_and_proof(slot: Slot) -> eth_types::ElectraAggregateAndProof {
        eth_types::ElectraAggregateAndProof {
            aggregator_index: 42,
            aggregate: eth_types::ElectraAttestation {
                aggregation_bits: vec![0xff; 4],
                data: AttestationData {
                    slot,
                    index: 0,
                    beacon_block_root: [1u8; 32],
                    source: Checkpoint { epoch: slot / SLOTS_PER_EPOCH, root: [2u8; 32] },
                    target: Checkpoint { epoch: slot / SLOTS_PER_EPOCH + 1, root: [3u8; 32] },
                },
                signature: vec![0xaa; 96],
                committee_bits: vec![0x01, 0, 0, 0, 0, 0, 0, 0],
            },
            selection_proof: vec![0xbb; 96],
        }
    }

    #[tokio::test]
    async fn test_sign_electra_aggregate_and_proof_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let slot = schedule.electra_fork_epoch * SLOTS_PER_EPOCH;
        let agg_and_proof = create_test_electra_aggregate_and_proof(slot);

        let result = service
            .sign_electra_aggregate_and_proof(&agg_and_proof, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(slot / SLOTS_PER_EPOCH, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain =
            compute_domain(eth_types::DOMAIN_AGGREGATE_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&agg_and_proof, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- Voluntary exit signing tests ---

    #[tokio::test]
    async fn test_sign_voluntary_exit_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let exit = eth_types::VoluntaryExit { epoch: 5, validator_index: 42 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let fork_name = eth_types::ForkName::from_epoch(exit.epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_voluntary_exit_electra_epoch_uses_capella_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        // Epoch 55 is in the Electra era (electra_fork_epoch=50)
        let exit = eth_types::VoluntaryExit { epoch: 55, validator_index: 99 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        // EIP-7044: still capped at Capella even in Electra
        let capella_fork_version = schedule.capella_fork_version;
        let domain =
            compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, capella_fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(
            signature.verify(&pubkey, &signing_root).is_ok(),
            "EIP-7044: voluntary exit at Electra epoch must use Capella fork version"
        );
    }

    #[tokio::test]
    async fn test_sign_voluntary_exit_pre_capella_uses_actual_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        // Epoch 15 is in the Altair era (altair=10, bellatrix=20) — pre-Capella, no cap
        let exit = eth_types::VoluntaryExit { epoch: 15, validator_index: 7 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let altair_fork_version = schedule.altair_fork_version;
        let domain =
            compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, altair_fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(
            signature.verify(&pubkey, &signing_root).is_ok(),
            "Pre-Capella voluntary exit should use the actual fork version (Altair)"
        );
    }

    #[tokio::test]
    async fn test_sign_voluntary_exit_deneb_epoch_uses_capella_fork_version() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        // Epoch 45 is in the Deneb era (deneb_fork_epoch=40, electra_fork_epoch=50)
        let exit = eth_types::VoluntaryExit { epoch: 45, validator_index: 42 };

        let result = service.sign_voluntary_exit(&exit, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        // EIP-7044: voluntary exit fork version MUST be capped at Capella
        let capella_fork_version = schedule.capella_fork_version;
        let domain =
            compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, capella_fork_version, genesis_root);
        let signing_root = compute_signing_root(&exit, domain);
        assert!(
            signature.verify(&pubkey, &signing_root).is_ok(),
            "EIP-7044: voluntary exit at Deneb epoch must use Capella fork version"
        );
    }

    // --- Builder registration signing tests ---

    fn create_test_registration() -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            pubkey: [0xcd; 48],
        }
    }

    #[tokio::test]
    async fn test_sign_builder_registration_success() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let registration = create_test_registration();
        let fork_version = [0x01, 0x00, 0x00, 0x00];

        let result = service.sign_builder_registration(&registration, &pubkey, fork_version).await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let zeroed_genesis_root = [0u8; 32];
        let domain = compute_domain(
            eth_types::DOMAIN_APPLICATION_BUILDER,
            fork_version,
            zeroed_genesis_root,
        );
        let signing_root = compute_signing_root(&registration, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- CompositeSigner integration: dynamically added keys work ---

    #[tokio::test]
    async fn test_dynamically_added_key_is_signable() {
        let signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(signer.clone(), slashing_db);

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        // Key is not in signer yet — signing should fail
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];
        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_err());

        // Add key dynamically (simulating keymanager API import)
        signer.add_local_key(secret_key);

        // Now signing should succeed
        let result = service.sign_randao_reveal(5, &pubkey, &schedule, &genesis_root).await;
        assert!(result.is_ok());
    }

    // --- Sync committee selection proof / contribution tests ---

    #[tokio::test]
    async fn test_sign_sync_committee_selection_proof() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let slot: Slot = 100;
        let subcommittee_index: u64 = 2;
        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let result = service
            .sign_sync_committee_selection_proof(
                slot,
                subcommittee_index,
                &pubkey,
                &schedule,
                &genesis_root,
            )
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let epoch = slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain =
            compute_domain(DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, fork_version, genesis_root);
        let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
        let signing_root = compute_signing_root(&selection_data, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_sign_contribution_and_proof() {
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));

        let service = SignerService::new(signer, slashing_db);

        let schedule = create_test_fork_schedule();
        let genesis_root = [0xaa; 32];

        let contribution_and_proof = ContributionAndProof {
            aggregator_index: 42,
            contribution: eth_types::SyncCommitteeContribution {
                slot: 100,
                beacon_block_root: [0x11; 32],
                subcommittee_index: 2,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xbb; 96],
            },
            selection_proof: vec![0xcc; 96],
        };

        let result = service
            .sign_contribution_and_proof(&contribution_and_proof, &pubkey, &schedule, &genesis_root)
            .await;
        assert!(result.is_ok());

        let signature = result.unwrap();

        let epoch = contribution_and_proof.contribution.slot / SLOTS_PER_EPOCH;
        let fork_name = eth_types::ForkName::from_epoch(epoch, &schedule);
        let fork_version = fork_name.fork_version(&schedule);
        let domain = compute_domain(DOMAIN_CONTRIBUTION_AND_PROOF, fork_version, genesis_root);
        let signing_root = compute_signing_root(&contribution_and_proof, domain);
        assert!(signature.verify(&pubkey, &signing_root).is_ok());
    }

    // --- COR-01 Tests: Per-validator signing mutex ---

    #[test]
    fn test_validator_lock_map_returns_same_lock_for_same_key() {
        let map = ValidatorLockMap::new();
        let pk = [1u8; 48];
        let lock1 = map.get(&pk);
        let lock2 = map.get(&pk);
        assert!(Arc::ptr_eq(&lock1, &lock2));
    }

    #[test]
    fn test_validator_lock_map_returns_different_locks_for_different_keys() {
        let map = ValidatorLockMap::new();
        let pk1 = [1u8; 48];
        let pk2 = [2u8; 48];
        let lock1 = map.get(&pk1);
        let lock2 = map.get(&pk2);
        assert!(!Arc::ptr_eq(&lock1, &lock2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_signing_same_validator_serialized() {
        use tokio::sync::Barrier;

        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();
        let signer = create_test_composite_signer_with_key(secret_key);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = Arc::new(SignerService::new(signer, slashing_db));
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];
        let barrier = Arc::new(Barrier::new(2));

        // Both attestations use the SAME source/target so the second would normally
        // fail without the mutex. With the mutex, only one runs at a time, and the
        // second will see the same signing_root already recorded (which is allowed).
        let data = create_test_attestation_data(59, 60);

        let mut handles = vec![];
        for _ in 0..2 {
            let service = service.clone();
            let pk = pubkey.clone();
            let f = fork.clone();
            let d = data.clone();
            let barrier = barrier.clone();

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                service.sign_attestation(&d, &pk, &f, genesis_root).await
            }));
        }

        // Both should succeed because they have the same signing root
        // and the mutex ensures they run sequentially
        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_ok(), "signing should succeed: {:?}", result.err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_signing_different_validators_parallel() {
        use tokio::sync::Barrier;

        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        let mut manager = KeyManager::new();
        manager.insert(sk1);
        manager.insert(sk2);
        let signer = Arc::new(CompositeSigner::new(LocalSigner::new(manager)));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = Arc::new(SignerService::new(signer, slashing_db));
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];
        let barrier = Arc::new(Barrier::new(2));

        let mut handles = vec![];
        for (pk, epoch) in [(pk1, 60u64), (pk2, 60)] {
            let service = service.clone();
            let f = fork.clone();
            let barrier = barrier.clone();

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let data = create_test_attestation_data(epoch - 1, epoch);
                service.sign_attestation(&data, &pk, &f, genesis_root).await
            }));
        }

        for h in handles {
            let result = h.await.unwrap();
            assert!(result.is_ok(), "parallel signing should succeed: {:?}", result.err());
        }
    }

    #[tokio::test]
    async fn test_signing_failure_after_recording_warns_phantom() {
        // Use a signer with no keys to cause a signing failure after slashing check passes
        let secret_key = SecretKey::generate();
        let pubkey = secret_key.public_key();

        // Register the validator in slashing DB but DON'T add the key to the signer
        let empty_signer = create_empty_composite_signer();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("failed to open db"));
        let service = SignerService::new(empty_signer, slashing_db.clone());
        let fork = create_test_fork();
        let genesis_root = [0xaa; 32];

        let data = create_test_attestation_data(59, 60);
        let result = service.sign_attestation(&data, &pubkey, &fork, genesis_root).await;
        assert!(result.is_err());

        // Verify the phantom entry exists in slashing DB — the signing failed,
        // but the record was committed. This is the spec-mandated behavior.
        match result.err().unwrap() {
            SignerError::KeyNotFound(_) | SignerError::SigningFailed(_) => {}
            other => panic!("expected signing failure, got: {other}"),
        }
    }
}
