//! Sync committee message and contribution lifecycle service.

mod error;

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use eth_types::{
    ContributionAndProof, ForkSchedule, Root, SignedContributionAndProof, Slot,
    SyncCommitteeContribution, SyncCommitteeDuty, SyncCommitteeMessage,
};

pub use error::SyncServiceError;

type Signature = Vec<u8>;
type PublicKey = Vec<u8>;

const SYNC_COMMITTEE_SIZE: u64 = 512;
const SYNC_COMMITTEE_SUBNET_COUNT: u64 = 4;
const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: u64 = 16;

#[async_trait]
pub trait SyncSigner: Send + Sync {
    async fn sign_sync_committee_message(
        &self,
        beacon_block_root: &Root,
        slot: Slot,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SyncServiceError>;

    async fn sign_selection_proof(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SyncServiceError>;

    async fn sign_contribution_and_proof(
        &self,
        contribution_and_proof: &ContributionAndProof,
        pubkey: &PublicKey,
        fork_schedule: &ForkSchedule,
        genesis_validators_root: &Root,
    ) -> Result<Signature, SyncServiceError>;
}

#[async_trait]
pub trait SyncBeaconClient: Send + Sync {
    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), SyncServiceError>;

    async fn get_sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: &Root,
    ) -> Result<SyncCommitteeContribution, SyncServiceError>;

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), SyncServiceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncMessagesResult {
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionsResult {
    pub count: usize,
}

pub fn is_sync_committee_aggregator(selection_proof: &[u8]) -> bool {
    let modulo = (SYNC_COMMITTEE_SIZE
        / SYNC_COMMITTEE_SUBNET_COUNT
        / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
        .max(1);

    let hash = Sha256::digest(selection_proof);
    let value = u64::from_le_bytes(hash[0..8].try_into().expect("sha256 output is 32 bytes"));
    value % modulo == 0
}

pub struct SyncService<S: SyncSigner, B: SyncBeaconClient> {
    signer: Arc<S>,
    beacon: Arc<B>,
    fork_schedule: Arc<ForkSchedule>,
    genesis_validators_root: Root,
}

impl<S: SyncSigner, B: SyncBeaconClient> SyncService<S, B> {
    pub fn new(
        signer: Arc<S>,
        beacon: Arc<B>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self { signer, beacon, fork_schedule, genesis_validators_root }
    }

    #[tracing::instrument(name = "rvc.sync.produce_messages", skip_all, fields(rvc.slot = slot, rvc.duty_count = duties.len()))]
    pub async fn produce_sync_messages(
        &self,
        slot: Slot,
        duties: &[SyncCommitteeDuty],
        head_root: &Root,
        pubkeys: &[PublicKey],
    ) -> Result<SyncMessagesResult, SyncServiceError> {
        if duties.len() != pubkeys.len() {
            return Err(SyncServiceError::InvalidInput(
                "duties and pubkeys must have the same length".to_string(),
            ));
        }

        if duties.is_empty() {
            return Ok(SyncMessagesResult { count: 0 });
        }

        let mut messages = Vec::new();
        for (duty, pubkey) in duties.iter().zip(pubkeys.iter()) {
            let sig = self
                .signer
                .sign_sync_committee_message(
                    head_root,
                    slot,
                    pubkey,
                    &self.fork_schedule,
                    &self.genesis_validators_root,
                )
                .await?;

            messages.push(SyncCommitteeMessage {
                slot,
                beacon_block_root: *head_root,
                validator_index: duty.validator_index,
                signature: sig,
            });
        }

        debug!(count = messages.len(), slot, "Submitting sync committee messages");
        self.beacon.submit_sync_committee_messages(&messages).await?;
        info!(count = messages.len(), slot, "Submitted sync committee messages");

        Ok(SyncMessagesResult { count: messages.len() })
    }

    #[tracing::instrument(name = "rvc.sync.produce_contributions", skip_all, fields(rvc.slot = slot, rvc.duty_count = duties.len()))]
    pub async fn produce_contributions(
        &self,
        slot: Slot,
        duties: &[SyncCommitteeDuty],
        head_root: &Root,
        pubkeys: &[PublicKey],
    ) -> Result<ContributionsResult, SyncServiceError> {
        if duties.len() != pubkeys.len() {
            return Err(SyncServiceError::InvalidInput(
                "duties and pubkeys must have the same length".to_string(),
            ));
        }

        let mut signed_proofs = Vec::new();

        for (duty, pubkey) in duties.iter().zip(pubkeys.iter()) {
            let subcommittee_indices: BTreeSet<u64> = duty
                .validator_sync_committee_indices
                .iter()
                .map(|&pos| pos / (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT))
                .collect();

            for subcommittee_index in subcommittee_indices {
                let selection_proof = self
                    .signer
                    .sign_selection_proof(
                        slot,
                        subcommittee_index,
                        pubkey,
                        &self.fork_schedule,
                        &self.genesis_validators_root,
                    )
                    .await?;

                if !is_sync_committee_aggregator(&selection_proof) {
                    debug!(
                        validator_index = duty.validator_index,
                        subcommittee_index, "Not selected as sync committee aggregator"
                    );
                    continue;
                }

                debug!(
                    validator_index = duty.validator_index,
                    subcommittee_index, "Selected as sync committee aggregator"
                );

                let contribution = self
                    .beacon
                    .get_sync_committee_contribution(slot, subcommittee_index, head_root)
                    .await?;

                let proof = ContributionAndProof {
                    aggregator_index: duty.validator_index,
                    contribution,
                    selection_proof: selection_proof.clone(),
                };

                let sig = self
                    .signer
                    .sign_contribution_and_proof(
                        &proof,
                        pubkey,
                        &self.fork_schedule,
                        &self.genesis_validators_root,
                    )
                    .await?;

                signed_proofs.push(SignedContributionAndProof { message: proof, signature: sig });
            }
        }

        if !signed_proofs.is_empty() {
            debug!(count = signed_proofs.len(), slot, "Submitting contribution and proofs");
            self.beacon.submit_contribution_and_proofs(&signed_proofs).await?;
            info!(count = signed_proofs.len(), slot, "Submitted contribution and proofs");
        } else {
            debug!(slot, "No validators selected as sync committee aggregator");
        }

        Ok(ContributionsResult { count: signed_proofs.len() })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct MockSigner {
        sign_sync_result: tokio::sync::Mutex<Result<Signature, SyncServiceError>>,
        sign_selection_result: tokio::sync::Mutex<Result<Signature, SyncServiceError>>,
        sign_contribution_result: tokio::sync::Mutex<Result<Signature, SyncServiceError>>,
        sign_sync_call_count: AtomicUsize,
        sign_selection_call_count: AtomicUsize,
        sign_contribution_call_count: AtomicUsize,
    }

    impl MockSigner {
        fn new() -> Self {
            Self {
                sign_sync_result: tokio::sync::Mutex::new(Ok(vec![0xaa; 96])),
                sign_selection_result: tokio::sync::Mutex::new(Ok(vec![0xbb; 96])),
                sign_contribution_result: tokio::sync::Mutex::new(Ok(vec![0xcc; 96])),
                sign_sync_call_count: AtomicUsize::new(0),
                sign_selection_call_count: AtomicUsize::new(0),
                sign_contribution_call_count: AtomicUsize::new(0),
            }
        }

        fn with_sync_error(mut self, err: SyncServiceError) -> Self {
            self.sign_sync_result = tokio::sync::Mutex::new(Err(err));
            self
        }

        fn with_selection_proof(mut self, proof: Signature) -> Self {
            self.sign_selection_result = tokio::sync::Mutex::new(Ok(proof));
            self
        }

        fn with_selection_error(mut self, err: SyncServiceError) -> Self {
            self.sign_selection_result = tokio::sync::Mutex::new(Err(err));
            self
        }
    }

    #[async_trait]
    impl SyncSigner for MockSigner {
        async fn sign_sync_committee_message(
            &self,
            _beacon_block_root: &Root,
            _slot: Slot,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Signature, SyncServiceError> {
            self.sign_sync_call_count.fetch_add(1, Ordering::SeqCst);
            let result = self.sign_sync_result.lock().await;
            match &*result {
                Ok(sig) => Ok(sig.clone()),
                Err(e) => Err(SyncServiceError::Signer(e.to_string())),
            }
        }

        async fn sign_selection_proof(
            &self,
            _slot: Slot,
            _subcommittee_index: u64,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Signature, SyncServiceError> {
            self.sign_selection_call_count.fetch_add(1, Ordering::SeqCst);
            let result = self.sign_selection_result.lock().await;
            match &*result {
                Ok(sig) => Ok(sig.clone()),
                Err(e) => Err(SyncServiceError::Signer(e.to_string())),
            }
        }

        async fn sign_contribution_and_proof(
            &self,
            _contribution_and_proof: &ContributionAndProof,
            _pubkey: &PublicKey,
            _fork_schedule: &ForkSchedule,
            _genesis_validators_root: &Root,
        ) -> Result<Signature, SyncServiceError> {
            self.sign_contribution_call_count.fetch_add(1, Ordering::SeqCst);
            let result = self.sign_contribution_result.lock().await;
            match &*result {
                Ok(sig) => Ok(sig.clone()),
                Err(e) => Err(SyncServiceError::Signer(e.to_string())),
            }
        }
    }

    struct MockBeacon {
        submit_messages_result: tokio::sync::Mutex<Result<(), SyncServiceError>>,
        get_contribution_result:
            tokio::sync::Mutex<Result<SyncCommitteeContribution, SyncServiceError>>,
        submit_proofs_result: tokio::sync::Mutex<Result<(), SyncServiceError>>,
        submit_messages_call_count: AtomicUsize,
        get_contribution_call_count: AtomicUsize,
        submit_proofs_call_count: AtomicUsize,
    }

    impl MockBeacon {
        fn new() -> Self {
            Self {
                submit_messages_result: tokio::sync::Mutex::new(Ok(())),
                get_contribution_result: tokio::sync::Mutex::new(Ok(sample_contribution())),
                submit_proofs_result: tokio::sync::Mutex::new(Ok(())),
                submit_messages_call_count: AtomicUsize::new(0),
                get_contribution_call_count: AtomicUsize::new(0),
                submit_proofs_call_count: AtomicUsize::new(0),
            }
        }

        fn with_get_contribution_error(mut self, err: SyncServiceError) -> Self {
            self.get_contribution_result = tokio::sync::Mutex::new(Err(err));
            self
        }
    }

    #[async_trait]
    impl SyncBeaconClient for MockBeacon {
        async fn submit_sync_committee_messages(
            &self,
            _messages: &[SyncCommitteeMessage],
        ) -> Result<(), SyncServiceError> {
            self.submit_messages_call_count.fetch_add(1, Ordering::SeqCst);
            let result = self.submit_messages_result.lock().await;
            match &*result {
                Ok(()) => Ok(()),
                Err(e) => Err(SyncServiceError::Beacon(e.to_string())),
            }
        }

        async fn get_sync_committee_contribution(
            &self,
            _slot: Slot,
            _subcommittee_index: u64,
            _beacon_block_root: &Root,
        ) -> Result<SyncCommitteeContribution, SyncServiceError> {
            self.get_contribution_call_count.fetch_add(1, Ordering::SeqCst);
            let result = self.get_contribution_result.lock().await;
            match &*result {
                Ok(c) => Ok(c.clone()),
                Err(e) => Err(SyncServiceError::Beacon(e.to_string())),
            }
        }

        async fn submit_contribution_and_proofs(
            &self,
            _proofs: &[SignedContributionAndProof],
        ) -> Result<(), SyncServiceError> {
            self.submit_proofs_call_count.fetch_add(1, Ordering::SeqCst);
            let result = self.submit_proofs_result.lock().await;
            match &*result {
                Ok(()) => Ok(()),
                Err(e) => Err(SyncServiceError::Beacon(e.to_string())),
            }
        }
    }

    fn sample_contribution() -> SyncCommitteeContribution {
        SyncCommitteeContribution {
            slot: 100,
            beacon_block_root: [0x11; 32],
            subcommittee_index: 0,
            aggregation_bits: vec![0xff; 16],
            signature: vec![0xdd; 96],
        }
    }

    fn test_fork_schedule() -> ForkSchedule {
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

    fn create_service(
        signer: MockSigner,
        beacon: MockBeacon,
    ) -> SyncService<MockSigner, MockBeacon> {
        SyncService::new(
            Arc::new(signer),
            Arc::new(beacon),
            Arc::new(test_fork_schedule()),
            [0xaa; 32],
        )
    }

    fn sample_duties(count: usize) -> Vec<SyncCommitteeDuty> {
        (0..count)
            .map(|i| SyncCommitteeDuty {
                pubkey: format!("0x{:048x}", i),
                validator_index: i as u64,
                validator_sync_committee_indices: vec![i as u64],
            })
            .collect()
    }

    fn sample_pubkeys(count: usize) -> Vec<PublicKey> {
        (0..count).map(|i| vec![i as u8; 48]).collect()
    }

    /// Find a selection proof that passes the aggregator check.
    fn find_aggregator_proof() -> Signature {
        let modulo = (SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            if value % modulo == 0 {
                return proof;
            }
        }
        unreachable!()
    }

    /// Find a selection proof that does NOT pass the aggregator check.
    fn find_non_aggregator_proof() -> Signature {
        let modulo = (SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
            .max(1);
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            if value % modulo != 0 {
                return proof;
            }
        }
        unreachable!()
    }

    // --- is_sync_committee_aggregator tests ---

    #[test]
    fn test_is_sync_committee_aggregator_with_known_aggregator() {
        let proof = find_aggregator_proof();
        assert!(is_sync_committee_aggregator(&proof));
    }

    #[test]
    fn test_is_sync_committee_aggregator_with_known_non_aggregator() {
        let proof = find_non_aggregator_proof();
        assert!(!is_sync_committee_aggregator(&proof));
    }

    #[test]
    fn test_is_sync_committee_aggregator_modulo_correctness() {
        let modulo = SYNC_COMMITTEE_SIZE
            / SYNC_COMMITTEE_SUBNET_COUNT
            / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE;
        // 512 / 4 / 16 = 8
        assert_eq!(modulo, 8);
    }

    #[test]
    fn test_is_sync_committee_aggregator_empty_proof() {
        // Empty proof should still produce a deterministic result
        let result = is_sync_committee_aggregator(&[]);
        // SHA256 of empty input is known: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // First 8 bytes as LE u64: 0xc8f4fb9a14_1cfc98 => check modulo 8
        let hash = Sha256::digest([]);
        let value = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        assert_eq!(result, value % 8 == 0);
    }

    // --- produce_sync_messages tests ---

    #[tokio::test]
    async fn test_produce_sync_messages_success() {
        let signer = MockSigner::new();
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let duties = sample_duties(3);
        let pubkeys = sample_pubkeys(3);
        let head_root = [0x11; 32];

        let result = service.produce_sync_messages(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.count, 3);

        assert_eq!(service.signer.sign_sync_call_count.load(Ordering::SeqCst), 3);
        assert_eq!(service.beacon.submit_messages_call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_produce_sync_messages_empty_duties() {
        let signer = MockSigner::new();
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let head_root = [0x11; 32];

        let result = service.produce_sync_messages(100, &[], &head_root, &[]).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.count, 0);
        // Early return — no beacon call for empty duties
        assert_eq!(service.beacon.submit_messages_call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_produce_sync_messages_signing_failure() {
        let signer =
            MockSigner::new().with_sync_error(SyncServiceError::Signer("key not found".into()));
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let duties = sample_duties(1);
        let pubkeys = sample_pubkeys(1);
        let head_root = [0x11; 32];

        let result = service.produce_sync_messages(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncServiceError::Signer(_)));
        assert_eq!(service.beacon.submit_messages_call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_produce_sync_messages_mismatched_lengths() {
        let signer = MockSigner::new();
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let duties = sample_duties(2);
        let pubkeys = sample_pubkeys(3);
        let head_root = [0x11; 32];

        let result = service.produce_sync_messages(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncServiceError::InvalidInput(_)));
    }

    // --- produce_contributions tests ---

    #[tokio::test]
    async fn test_produce_contributions_aggregator_selected() {
        let aggregator_proof = find_aggregator_proof();
        let signer = MockSigner::new().with_selection_proof(aggregator_proof);
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let duties = vec![SyncCommitteeDuty {
            pubkey: "0x00".to_string(),
            validator_index: 42,
            validator_sync_committee_indices: vec![0],
        }];
        let pubkeys = vec![vec![0u8; 48]];
        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.count, 1);

        assert_eq!(service.signer.sign_selection_call_count.load(Ordering::SeqCst), 1);
        assert_eq!(service.beacon.get_contribution_call_count.load(Ordering::SeqCst), 1);
        assert_eq!(service.signer.sign_contribution_call_count.load(Ordering::SeqCst), 1);
        assert_eq!(service.beacon.submit_proofs_call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_produce_contributions_not_aggregator() {
        let non_agg_proof = find_non_aggregator_proof();
        let signer = MockSigner::new().with_selection_proof(non_agg_proof);
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let duties = vec![SyncCommitteeDuty {
            pubkey: "0x00".to_string(),
            validator_index: 42,
            validator_sync_committee_indices: vec![0],
        }];
        let pubkeys = vec![vec![0u8; 48]];
        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.count, 0);

        assert_eq!(service.signer.sign_selection_call_count.load(Ordering::SeqCst), 1);
        assert_eq!(service.beacon.get_contribution_call_count.load(Ordering::SeqCst), 0);
        assert_eq!(service.signer.sign_contribution_call_count.load(Ordering::SeqCst), 0);
        assert_eq!(service.beacon.submit_proofs_call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_produce_contributions_beacon_failure() {
        let aggregator_proof = find_aggregator_proof();
        let signer = MockSigner::new().with_selection_proof(aggregator_proof);
        let beacon = MockBeacon::new()
            .with_get_contribution_error(SyncServiceError::Beacon("beacon unavailable".into()));
        let service = create_service(signer, beacon);

        let duties = vec![SyncCommitteeDuty {
            pubkey: "0x00".to_string(),
            validator_index: 42,
            validator_sync_committee_indices: vec![0],
        }];
        let pubkeys = vec![vec![0u8; 48]];
        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncServiceError::Beacon(_)));
    }

    #[tokio::test]
    async fn test_produce_contributions_selection_signing_failure() {
        let signer = MockSigner::new()
            .with_selection_error(SyncServiceError::Signer("signing failed".into()));
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let duties = vec![SyncCommitteeDuty {
            pubkey: "0x00".to_string(),
            validator_index: 42,
            validator_sync_committee_indices: vec![0],
        }];
        let pubkeys = vec![vec![0u8; 48]];
        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncServiceError::Signer(_)));
    }

    #[tokio::test]
    async fn test_produce_contributions_multiple_subcommittees() {
        let aggregator_proof = find_aggregator_proof();
        let signer = MockSigner::new().with_selection_proof(aggregator_proof);
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        // Positions 0, 128, 256 map to subcommittees 0, 1, 2 respectively
        let duties = vec![SyncCommitteeDuty {
            pubkey: "0x00".to_string(),
            validator_index: 42,
            validator_sync_committee_indices: vec![0, 128, 256],
        }];
        let pubkeys = vec![vec![0u8; 48]];
        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.count, 3);

        assert_eq!(service.signer.sign_selection_call_count.load(Ordering::SeqCst), 3);
        assert_eq!(service.beacon.get_contribution_call_count.load(Ordering::SeqCst), 3);
        assert_eq!(service.signer.sign_contribution_call_count.load(Ordering::SeqCst), 3);
        assert_eq!(service.beacon.submit_proofs_call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_produce_contributions_deduplicates_same_subcommittee() {
        let aggregator_proof = find_aggregator_proof();
        let signer = MockSigner::new().with_selection_proof(aggregator_proof);
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        // Positions 5 and 10 both map to subcommittee 0 (5/128=0, 10/128=0)
        let duties = vec![SyncCommitteeDuty {
            pubkey: "0x00".to_string(),
            validator_index: 42,
            validator_sync_committee_indices: vec![5, 10],
        }];
        let pubkeys = vec![vec![0u8; 48]];
        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        // Should produce only 1 contribution since both positions are in subcommittee 0
        assert_eq!(result.count, 1);

        assert_eq!(service.signer.sign_selection_call_count.load(Ordering::SeqCst), 1);
        assert_eq!(service.beacon.get_contribution_call_count.load(Ordering::SeqCst), 1);
        assert_eq!(service.signer.sign_contribution_call_count.load(Ordering::SeqCst), 1);
        assert_eq!(service.beacon.submit_proofs_call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_produce_contributions_mismatched_lengths() {
        let signer = MockSigner::new();
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let duties = sample_duties(2);
        let pubkeys = sample_pubkeys(1);
        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncServiceError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn test_produce_contributions_empty_duties() {
        let signer = MockSigner::new();
        let beacon = MockBeacon::new();
        let service = create_service(signer, beacon);

        let head_root = [0x11; 32];

        let result = service.produce_contributions(100, &[], &head_root, &[]).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.count, 0);
        assert_eq!(service.beacon.submit_proofs_call_count.load(Ordering::SeqCst), 0);
    }
}
