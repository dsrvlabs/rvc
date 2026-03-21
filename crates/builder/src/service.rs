use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{debug, error, info, warn};

use bn_manager::{
    BeaconError, BeaconNodeClient, ProposerPreparation, SignedValidatorRegistration,
    ValidatorRegistrationV1,
};
use signer::{SignerError, ValidatorSigner};
use validator_store::ValidatorStore;

#[derive(Debug, Error)]
pub enum BuilderServiceError {
    #[error("beacon node error: {0}")]
    BeaconError(#[from] BeaconError),

    #[error("signer error: {0}")]
    SignerError(#[from] SignerError),
}

/// Cached registration data for change detection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedRegistration {
    fee_recipient: [u8; 20],
    gas_limit: u64,
}

pub struct BuilderService {
    signer: Arc<dyn ValidatorSigner>,
    bn: Arc<dyn BeaconNodeClient>,
    validator_store: Arc<ValidatorStore>,
    genesis_fork_version: [u8; 4],
    cache: tokio::sync::RwLock<HashMap<[u8; 48], CachedRegistration>>,
}

impl BuilderService {
    pub fn new(
        signer: Arc<dyn ValidatorSigner>,
        bn: Arc<dyn BeaconNodeClient>,
        validator_store: Arc<ValidatorStore>,
        genesis_fork_version: [u8; 4],
    ) -> Self {
        Self {
            signer,
            bn,
            validator_store,
            genesis_fork_version,
            cache: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    #[tracing::instrument(name = "rvc.builder.register", skip_all, fields(rvc.builder.batch_size))]
    pub async fn register_validators(&self) -> Result<(), BuilderServiceError> {
        let enabled_pubkeys = self.validator_store.list_enabled_pubkeys();
        let builder_pubkeys: Vec<[u8; 48]> = enabled_pubkeys
            .into_iter()
            .filter(|pk| self.validator_store.is_builder_enabled(pk))
            .collect();

        if builder_pubkeys.is_empty() {
            debug!("no builder-enabled validators to register");
            return Ok(());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();

        // Collect candidates that need (re-)registration by checking
        // the cache under a read lock, then release the lock before
        // performing any async signing.
        let candidates: Vec<([u8; 48], [u8; 20], u64)> = {
            let cache = self.cache.read().await;
            builder_pubkeys
                .iter()
                .filter_map(|pubkey| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(pubkey);
                    let gas_limit = self.validator_store.effective_gas_limit(pubkey);
                    let new_cached = CachedRegistration { fee_recipient, gas_limit };
                    if cache.get(pubkey) == Some(&new_cached) {
                        None
                    } else {
                        Some((*pubkey, fee_recipient, gas_limit))
                    }
                })
                .collect()
        };

        let mut registrations = Vec::new();

        for (pubkey, fee_recipient, gas_limit) in &candidates {
            let registration = ValidatorRegistrationV1 {
                fee_recipient: *fee_recipient,
                gas_limit: *gas_limit,
                timestamp,
                pubkey: *pubkey,
            };

            let pk = match crypto::PublicKey::from_bytes(pubkey) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!(pubkey = hex::encode(pubkey), error = %e, "skipping invalid pubkey");
                    continue;
                }
            };

            match self
                .signer
                .sign_builder_registration(&registration, &pk, self.genesis_fork_version)
                .await
            {
                Ok(signature) => {
                    registrations
                        .push(SignedValidatorRegistration { message: registration, signature });
                }
                Err(e) => {
                    error!(
                        pubkey = hex::encode(pubkey),
                        error = %e,
                        "failed to sign builder registration"
                    );
                }
            }
        }

        if registrations.is_empty() {
            debug!("no new registrations to submit");
            return Ok(());
        }

        let batch_size = registrations.len();
        tracing::Span::current().record("rvc.builder.batch_size", batch_size);
        debug!(count = batch_size, "submitting builder registrations");

        let start = Instant::now();
        match self.bn.register_validators(&registrations).await {
            Ok(()) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                info!(
                    batch_size = batch_size,
                    duration_ms = duration_ms,
                    "registration batch sent"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    batch_size = batch_size,
                    "registration failure"
                );
                return Err(e.into());
            }
        }

        // Update cache after successful submission
        {
            let mut cache = self.cache.write().await;
            for reg in &registrations {
                cache.insert(
                    reg.message.pubkey,
                    CachedRegistration {
                        fee_recipient: reg.message.fee_recipient,
                        gas_limit: reg.message.gas_limit,
                    },
                );
            }
        }

        Ok(())
    }

    #[tracing::instrument(name = "rvc.builder.prepare_proposers", skip_all)]
    pub async fn prepare_proposers(
        &self,
        validator_indices: &HashMap<[u8; 48], u64>,
    ) -> Result<(), BuilderServiceError> {
        let enabled_pubkeys = self.validator_store.list_enabled_pubkeys();

        let preparations: Vec<ProposerPreparation> = enabled_pubkeys
            .iter()
            .filter_map(|pk| {
                validator_indices.get(pk).map(|index| {
                    let fee_recipient = self.validator_store.effective_fee_recipient(pk);
                    ProposerPreparation {
                        validator_index: index.to_string(),
                        fee_recipient: format!("0x{}", hex::encode(fee_recipient)),
                    }
                })
            })
            .collect();

        if preparations.is_empty() {
            debug!("no proposer preparations to submit");
            return Ok(());
        }

        let count = preparations.len();
        debug!(count = count, "submitting proposer preparations");
        match self.bn.prepare_beacon_proposer(&preparations).await {
            Ok(()) => {
                info!(count = count, "proposer preparation sent");
            }
            Err(e) => {
                warn!(error = %e, "proposer preparation failure");
                return Err(e.into());
            }
        }

        Ok(())
    }

    pub fn jitter_seconds() -> u64 {
        use rand::Rng;
        rand::thread_rng().gen_range(0..30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    use async_trait::async_trait;
    use bn_manager::{
        AttestationDataResponse, AttesterDutiesResponse, BeaconCommitteeSubscription,
        BlockRootResponse, ConfigSpecResponse, ForkSchedule, GenesisResponse, ProduceBlockResponse,
        ProposerDutiesResponse, SignedBeaconBlock, SignedBlindedBeaconBlock,
        SignedContributionAndProof, StateForkResponse, SubmitAttestationResult,
        SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse, SyncCommitteeMessage,
        SyncingResponse, ValidatorsResponse, VersionedAggregateAttestation, VersionedAttestation,
        VersionedSignedAggregateAndProof,
    };
    use crypto::PublicKey;
    use eth_types::{
        AggregateAndProof, AttestationData, ElectraAggregateAndProof, Epoch, Root, Slot,
        VoluntaryExit,
    };
    use validator_store::ValidatorConfig;

    // --- Mock BN ---

    struct MockBn {
        register_calls: Mutex<Vec<Vec<SignedValidatorRegistration>>>,
        prepare_calls: Mutex<Vec<Vec<ProposerPreparation>>>,
        fail_register: bool,
        fail_prepare: bool,
    }

    impl MockBn {
        fn new() -> Self {
            Self {
                register_calls: Mutex::new(Vec::new()),
                prepare_calls: Mutex::new(Vec::new()),
                fail_register: false,
                fail_prepare: false,
            }
        }

        fn with_register_error(mut self) -> Self {
            self.fail_register = true;
            self
        }

        fn with_prepare_error(mut self) -> Self {
            self.fail_prepare = true;
            self
        }
    }

    #[async_trait]
    impl BeaconNodeClient for MockBn {
        async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_fork(&self, _: &str) -> Result<StateForkResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_validators(&self, _: &[String]) -> Result<ValidatorsResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_attester_duties(
            &self,
            _: u64,
            _: &[String],
        ) -> Result<AttesterDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_proposer_duties(&self, _: u64) -> Result<ProposerDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn post_sync_committee_duties(
            &self,
            _: u64,
            _: &[String],
        ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn produce_block_v3(
            &self,
            _: u64,
            _: &str,
            _: Option<&str>,
            _: Option<u64>,
        ) -> Result<ProduceBlockResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn publish_block(&self, _: &SignedBeaconBlock, _: &str) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn publish_blinded_block(
            &self,
            _: &SignedBlindedBeaconBlock,
            _: &str,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_attestation_data(
            &self,
            _: u64,
            _: u64,
        ) -> Result<AttestationDataResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_attestation(
            &self,
            _: &VersionedAttestation,
        ) -> Result<SubmitAttestationResult, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_aggregate_attestation(
            &self,
            _: u64,
            _: &str,
            _: Option<u64>,
        ) -> Result<VersionedAggregateAttestation, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_aggregate_and_proofs(
            &self,
            _: &VersionedSignedAggregateAndProof,
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_sync_committee_messages(
            &self,
            _: &[SyncCommitteeMessage],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_sync_committee_contribution(
            &self,
            _: u64,
            _: u64,
            _: &str,
        ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn submit_contribution_and_proofs(
            &self,
            _: &[SignedContributionAndProof],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_block_root(&self, _: &str) -> Result<BlockRootResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn prepare_beacon_proposer(
            &self,
            preparations: &[ProposerPreparation],
        ) -> Result<(), BeaconError> {
            if self.fail_prepare {
                return Err(BeaconError::HttpError("mock prepare failure".into()));
            }
            self.prepare_calls.lock().push(preparations.to_vec());
            Ok(())
        }
        async fn submit_beacon_committee_subscriptions(
            &self,
            _: &[BeaconCommitteeSubscription],
        ) -> Result<(), BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn register_validators(
            &self,
            registrations: &[SignedValidatorRegistration],
        ) -> Result<(), BeaconError> {
            if self.fail_register {
                return Err(BeaconError::HttpError("mock register failure".into()));
            }
            self.register_calls.lock().push(registrations.to_vec());
            Ok(())
        }
        async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
        async fn get_node_version(&self) -> Result<String, BeaconError> {
            Err(BeaconError::HttpError("mock".into()))
        }
    }

    // --- Mock Signer ---

    struct MockSigner {
        fail_sign: bool,
        sign_calls: Mutex<Vec<[u8; 48]>>,
    }

    impl MockSigner {
        fn new() -> Self {
            Self { fail_sign: false, sign_calls: Mutex::new(Vec::new()) }
        }

        fn with_sign_error(mut self) -> Self {
            self.fail_sign = true;
            self
        }
    }

    #[async_trait(?Send)]
    impl ValidatorSigner for MockSigner {
        async fn sign_attestation(
            &self,
            _: &AttestationData,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_block(
            &self,
            _: &Root,
            _: Slot,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_randao_reveal(
            &self,
            _: Epoch,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_sync_committee_message(
            &self,
            _: &Root,
            _: Slot,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_selection_proof(
            &self,
            _: Slot,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_aggregate_and_proof(
            &self,
            _: &AggregateAndProof,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_electra_aggregate_and_proof(
            &self,
            _: &ElectraAggregateAndProof,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_voluntary_exit(
            &self,
            _: &VoluntaryExit,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_builder_registration(
            &self,
            _registration: &ValidatorRegistrationV1,
            pubkey: &PublicKey,
            _fork_version: [u8; 4],
        ) -> Result<Vec<u8>, SignerError> {
            if self.fail_sign {
                return Err(SignerError::KeyNotFound("mock sign failure".into()));
            }
            self.sign_calls.lock().push(pubkey.to_bytes());
            Ok(vec![0xaa; 96])
        }
        async fn sign_sync_committee_selection_proof(
            &self,
            _: Slot,
            _: u64,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
        async fn sign_contribution_and_proof(
            &self,
            _: &eth_types::ContributionAndProof,
            _: &PublicKey,
            _: &eth_types::ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::KeyNotFound("mock".into()))
        }
    }

    // --- Helpers ---

    fn gen_pubkey_bytes() -> [u8; 48] {
        let sk = crypto::SecretKey::generate();
        sk.public_key().to_bytes()
    }

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    type ValidatorEntry = ([u8; 48], bool, Option<[u8; 20]>, Option<u64>);

    fn test_store_with_builder_validators(validators: &[ValidatorEntry]) -> ValidatorStore {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        for (pk, builder_enabled, fee_recipient, gas_limit) in validators {
            let mut config = ValidatorConfig::new(*pk);
            config.builder_proposals = *builder_enabled;
            config.fee_recipient = *fee_recipient;
            config.gas_limit = *gas_limit;
            store.add_validator(config);
        }
        store
    }

    fn build_service(signer: MockSigner, bn: MockBn, store: ValidatorStore) -> BuilderService {
        BuilderService::new(
            Arc::new(signer),
            Arc::new(bn),
            Arc::new(store),
            [0x00, 0x00, 0x00, 0x00],
        )
    }

    // --- register_validators tests ---

    #[tokio::test]
    async fn test_register_validators_no_builder_enabled() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);
        let service = build_service(MockSigner::new(), MockBn::new(), store);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let bn = service.bn.as_ref() as *const dyn BeaconNodeClient as *const MockBn;
        let calls = unsafe { &*bn }.register_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_register_validators_empty_store() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let service = build_service(MockSigner::new(), MockBn::new(), store);

        let result = service.register_validators().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_register_validators_submits_for_builder_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);
        let store = test_store_with_builder_validators(&[
            (pk1, true, Some(fr), Some(35_000_000)),
            (pk2, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(
            signer.clone(),
            bn.clone(),
            Arc::new(store),
            [0x00, 0x00, 0x00, 0x00],
        );

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].message.pubkey, pk1);
        assert_eq!(calls[0][0].message.fee_recipient, fr);
        assert_eq!(calls[0][0].message.gas_limit, 35_000_000);
        assert_eq!(calls[0][0].signature, vec![0xaa; 96]);

        let sign_calls = signer.sign_calls.lock();
        assert_eq!(sign_calls.len(), 1);
    }

    #[tokio::test]
    async fn test_register_validators_uses_default_fee_recipient() {
        let pk = gen_pubkey_bytes();
        let default_fr = test_fee_recipient(0xdd);
        let store = ValidatorStore::new(default_fr, 25_000_000);
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        store.add_validator(config);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls[0][0].message.fee_recipient, default_fr);
        assert_eq!(calls[0][0].message.gas_limit, 25_000_000);
    }

    #[tokio::test]
    async fn test_register_validators_multiple_builder_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let pk3 = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[
            (pk1, true, Some(test_fee_recipient(1)), Some(30_000_000)),
            (pk2, true, Some(test_fee_recipient(2)), Some(31_000_000)),
            (pk3, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);

        let pubkeys: Vec<[u8; 48]> = calls[0].iter().map(|r| r.message.pubkey).collect();
        assert!(pubkeys.contains(&pk1));
        assert!(pubkeys.contains(&pk2));
        assert!(!pubkeys.contains(&pk3));
    }

    #[tokio::test]
    async fn test_register_validators_beacon_error_propagates() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);

        let bn = Arc::new(MockBn::new().with_register_error());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(signer, bn, Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let result = service.register_validators().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("beacon node error"));
    }

    #[tokio::test]
    async fn test_register_validators_sign_error_skips_validator() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let store =
            test_store_with_builder_validators(&[(pk1, true, None, None), (pk2, true, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new().with_sign_error());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let result = service.register_validators().await;
        assert!(result.is_ok());

        // No registrations submitted since signing failed
        let calls = bn.register_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_register_validators_caches_and_skips_unchanged() {
        let pk = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);
        let store = test_store_with_builder_validators(&[(pk, true, Some(fr), Some(35_000_000))]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        // First call should register
        let result = service.register_validators().await;
        assert!(result.is_ok());
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Second call should skip (cached)
        let result = service.register_validators().await;
        assert!(result.is_ok());
        assert_eq!(bn.register_calls.lock().len(), 1); // Still 1, no new call
    }

    #[tokio::test]
    async fn test_register_validators_reregisters_on_fee_recipient_change() {
        let pk = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0xab);
        let fr2 = test_fee_recipient(0xcd);

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr1);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), store.clone(), [0x00, 0x00, 0x00, 0x00]);

        // First registration
        service.register_validators().await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Change fee_recipient
        store.update_config(
            &pk,
            validator_store::ValidatorConfigUpdate {
                fee_recipient: Some(Some(fr2)),
                ..Default::default()
            },
        );

        // Should re-register
        service.register_validators().await.unwrap();
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.fee_recipient, fr2);
    }

    #[tokio::test]
    async fn test_register_validators_reregisters_on_gas_limit_change() {
        let pk = gen_pubkey_bytes();
        let fr = test_fee_recipient(0xab);

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(0xff), 30_000_000));
        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        config.fee_recipient = Some(fr);
        config.gas_limit = Some(30_000_000);
        store.add_validator(config);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), store.clone(), [0x00, 0x00, 0x00, 0x00]);

        service.register_validators().await.unwrap();
        assert_eq!(bn.register_calls.lock().len(), 1);

        // Change gas_limit
        store.update_config(
            &pk,
            validator_store::ValidatorConfigUpdate {
                gas_limit: Some(Some(50_000_000)),
                ..Default::default()
            },
        );

        service.register_validators().await.unwrap();
        let calls = bn.register_calls.lock();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][0].message.gas_limit, 50_000_000);
    }

    #[tokio::test]
    async fn test_register_validators_timestamp_is_reasonable() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, true, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        service.register_validators().await.unwrap();
        let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let calls = bn.register_calls.lock();
        let timestamp = calls[0][0].message.timestamp;
        assert!(timestamp >= before);
        assert!(timestamp <= after);
    }

    // --- prepare_proposers tests ---

    #[tokio::test]
    async fn test_prepare_proposers_submits_for_all_enabled() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let fr1 = test_fee_recipient(0x01);
        let fr2 = test_fee_recipient(0x02);
        let store = test_store_with_builder_validators(&[
            (pk1, false, Some(fr1), None),
            (pk2, false, Some(fr2), None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let mut indices = HashMap::new();
        indices.insert(pk1, 100u64);
        indices.insert(pk2, 200u64);

        let result = service.prepare_proposers(&indices).await;
        assert!(result.is_ok());

        let calls = bn.prepare_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 2);

        let preps = &calls[0];
        let indices_submitted: Vec<&str> =
            preps.iter().map(|p| p.validator_index.as_str()).collect();
        assert!(indices_submitted.contains(&"100"));
        assert!(indices_submitted.contains(&"200"));
    }

    #[tokio::test]
    async fn test_prepare_proposers_uses_effective_fee_recipient() {
        let pk = gen_pubkey_bytes();
        let default_fr = test_fee_recipient(0xdd);
        let store = ValidatorStore::new(default_fr, 30_000_000);
        store.add_validator(ValidatorConfig::new(pk));

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let mut indices = HashMap::new();
        indices.insert(pk, 42u64);

        service.prepare_proposers(&indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        let expected_fr = format!("0x{}", hex::encode(default_fr));
        assert_eq!(calls[0][0].fee_recipient, expected_fr);
        assert_eq!(calls[0][0].validator_index, "42");
    }

    #[tokio::test]
    async fn test_prepare_proposers_skips_unknown_indices() {
        let pk1 = gen_pubkey_bytes();
        let pk2 = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[
            (pk1, false, None, None),
            (pk2, false, None, None),
        ]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        // Only provide index for pk1
        let mut indices = HashMap::new();
        indices.insert(pk1, 100u64);

        service.prepare_proposers(&indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].validator_index, "100");
    }

    #[tokio::test]
    async fn test_prepare_proposers_empty_indices() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);

        let bn = Arc::new(MockBn::new());
        let signer = Arc::new(MockSigner::new());
        let service =
            BuilderService::new(signer, bn.clone(), Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let indices = HashMap::new();
        service.prepare_proposers(&indices).await.unwrap();

        let calls = bn.prepare_calls.lock();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn test_prepare_proposers_beacon_error_propagates() {
        let pk = gen_pubkey_bytes();
        let store = test_store_with_builder_validators(&[(pk, false, None, None)]);

        let bn = Arc::new(MockBn::new().with_prepare_error());
        let signer = Arc::new(MockSigner::new());
        let service = BuilderService::new(signer, bn, Arc::new(store), [0x00, 0x00, 0x00, 0x00]);

        let mut indices = HashMap::new();
        indices.insert(pk, 100u64);

        let result = service.prepare_proposers(&indices).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("beacon node error"));
    }

    // --- jitter tests ---

    #[test]
    fn test_jitter_is_in_range() {
        for _ in 0..100 {
            let jitter = BuilderService::jitter_seconds();
            assert!(jitter < 30);
        }
    }

    // --- Error display tests ---

    #[test]
    fn test_builder_service_error_display_beacon() {
        let err = BuilderServiceError::BeaconError(BeaconError::HttpError("test".into()));
        assert!(err.to_string().contains("beacon node error"));
    }

    #[test]
    fn test_builder_service_error_display_signer() {
        let err = BuilderServiceError::SignerError(SignerError::KeyNotFound("test".into()));
        assert!(err.to_string().contains("signer error"));
    }

    // --- Construction test ---

    #[test]
    fn test_builder_service_new() {
        let store = ValidatorStore::new(test_fee_recipient(0xff), 30_000_000);
        let _service = BuilderService::new(
            Arc::new(MockSigner::new()),
            Arc::new(MockBn::new()),
            Arc::new(store),
            [0x01, 0x00, 0x00, 0x00],
        );
    }
}
