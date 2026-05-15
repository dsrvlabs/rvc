//! Integration tests for per-validator failure isolation in the sync-service contribution loop.
//!
//! Regression test for H-6: one validator's signing failure must not abort the slot for all
//! remaining validators.  The loop must `warn!` and `continue` on signing errors rather than
//! propagating them with `?`.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use eth_types::{
    ContributionAndProof, ForkSchedule, Root, SignedContributionAndProof, Slot,
    SyncCommitteeContribution, SyncCommitteeDuty, SyncCommitteeMessage,
};
use rvc_sync_service::{
    ContributionsResult, SyncBeaconClient, SyncService, SyncServiceError, SyncSigner,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Find the first raw bytes that pass the aggregator-selection check exposed by the crate.
fn find_aggregator_proof() -> Vec<u8> {
    for i in 0u64.. {
        let proof = i.to_le_bytes().to_vec();
        if rvc_sync_service::is_sync_committee_aggregator(&proof) {
            return proof;
        }
    }
    unreachable!()
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

// ---------------------------------------------------------------------------
// Per-call mock signer
// ---------------------------------------------------------------------------

/// Signs successfully for all calls *except* the one at `fail_selection_on_call`
/// (0-based index into `sign_selection_proof` calls).  A known aggregator proof
/// is returned on success so that is_sync_committee_aggregator() returns `true`.
struct PerCallSelectionSigner {
    selection_call_count: AtomicUsize,
    contribution_call_count: AtomicUsize,
    fail_selection_on_call: usize,
    aggregator_proof: Vec<u8>,
}

impl PerCallSelectionSigner {
    fn new(fail_on: usize) -> Self {
        Self {
            selection_call_count: AtomicUsize::new(0),
            contribution_call_count: AtomicUsize::new(0),
            fail_selection_on_call: fail_on,
            aggregator_proof: find_aggregator_proof(),
        }
    }
}

#[async_trait]
impl SyncSigner for PerCallSelectionSigner {
    async fn sign_sync_committee_message(
        &self,
        _beacon_block_root: &Root,
        _slot: Slot,
        _pubkey: &Vec<u8>,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SyncServiceError> {
        Ok(vec![0xaa; 96])
    }

    async fn sign_selection_proof(
        &self,
        _slot: Slot,
        _subcommittee_index: u64,
        _pubkey: &Vec<u8>,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SyncServiceError> {
        let idx = self.selection_call_count.fetch_add(1, Ordering::SeqCst);
        if idx == self.fail_selection_on_call {
            Err(SyncServiceError::Signer(format!("mock failure on call {idx}")))
        } else {
            Ok(self.aggregator_proof.clone())
        }
    }

    async fn sign_contribution_and_proof(
        &self,
        _contribution_and_proof: &ContributionAndProof,
        _pubkey: &Vec<u8>,
        _fork_schedule: &ForkSchedule,
        _genesis_validators_root: &Root,
    ) -> Result<Vec<u8>, SyncServiceError> {
        self.contribution_call_count.fetch_add(1, Ordering::SeqCst);
        Ok(vec![0xcc; 96])
    }
}

// ---------------------------------------------------------------------------
// Simple always-succeeding beacon mock with counters
// ---------------------------------------------------------------------------

struct CountingBeacon {
    get_contribution_call_count: AtomicUsize,
    submit_proofs_call_count: AtomicUsize,
    submit_messages_call_count: AtomicUsize,
}

impl CountingBeacon {
    fn new() -> Self {
        Self {
            get_contribution_call_count: AtomicUsize::new(0),
            submit_proofs_call_count: AtomicUsize::new(0),
            submit_messages_call_count: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl SyncBeaconClient for CountingBeacon {
    async fn submit_sync_committee_messages(
        &self,
        _messages: &[SyncCommitteeMessage],
    ) -> Result<(), SyncServiceError> {
        self.submit_messages_call_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn get_sync_committee_contribution(
        &self,
        _slot: Slot,
        _subcommittee_index: u64,
        _beacon_block_root: &Root,
    ) -> Result<SyncCommitteeContribution, SyncServiceError> {
        self.get_contribution_call_count.fetch_add(1, Ordering::SeqCst);
        Ok(sample_contribution())
    }

    async fn submit_contribution_and_proofs(
        &self,
        _proofs: &[SignedContributionAndProof],
    ) -> Result<(), SyncServiceError> {
        self.submit_proofs_call_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// H-6 regression: three validators A, B, C where B's `sign_selection_proof` fails.
/// After the fix A and C must produce contributions; B must be skipped; the function
/// must return `Ok` (not propagate B's error).
#[tokio::test]
async fn test_one_signer_failure_does_not_abort_others() {
    // Validator B is the second validator (call index 1).
    let signer = Arc::new(PerCallSelectionSigner::new(1));
    let beacon = Arc::new(CountingBeacon::new());

    let service = SyncService::new(
        Arc::clone(&signer),
        Arc::clone(&beacon),
        Arc::new(test_fork_schedule()),
        [0u8; 32],
    );

    // Three validators, each in a distinct subcommittee (positions 0, 128, 256).
    let duties = vec![
        SyncCommitteeDuty {
            pubkey: "0x010101".to_string(),
            validator_index: 0,
            validator_sync_committee_indices: vec![0],
        },
        SyncCommitteeDuty {
            pubkey: "0x020202".to_string(),
            validator_index: 1,
            validator_sync_committee_indices: vec![128],
        },
        SyncCommitteeDuty {
            pubkey: "0x030303".to_string(),
            validator_index: 2,
            validator_sync_committee_indices: vec![256],
        },
    ];
    let pubkeys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];
    let head_root = [0x42u8; 32];

    let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

    // The slot loop must complete — no error propagated.
    assert!(result.is_ok(), "Expected Ok but slot loop aborted: {:?}", result.err());

    let ContributionsResult { count } = result.unwrap();
    // A (index 0) and C (index 2) succeed; B (index 1) is skipped.
    assert_eq!(count, 2, "Expected contributions from A and C only");

    // sign_selection_proof was attempted for all three validators.
    assert_eq!(signer.selection_call_count.load(Ordering::SeqCst), 3);
    // sign_contribution_and_proof was only called for A and C.
    assert_eq!(signer.contribution_call_count.load(Ordering::SeqCst), 2);
    // Beacon fetched contribution for A and C; not for B.
    assert_eq!(beacon.get_contribution_call_count.load(Ordering::SeqCst), 2);
    // One batch submit with the two successful contributions.
    assert_eq!(beacon.submit_proofs_call_count.load(Ordering::SeqCst), 1);
}

/// H-6 regression (line 258): when `sign_contribution_and_proof` fails for one validator,
/// the others must still produce their contributions and the loop must not abort.
#[tokio::test]
async fn test_contribution_signing_failure_does_not_abort_others() {
    let aggregator_proof = find_aggregator_proof();

    // The signer returns an aggregator proof for `sign_selection_proof` always, but
    // fails on the second call to `sign_contribution_and_proof` (validator B).
    struct ContribFailSigner {
        contrib_call: AtomicUsize,
        fail_contrib_on: usize,
        aggregator_proof: Vec<u8>,
    }

    #[async_trait]
    impl SyncSigner for ContribFailSigner {
        async fn sign_sync_committee_message(
            &self,
            _: &Root,
            _: Slot,
            _: &Vec<u8>,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SyncServiceError> {
            Ok(vec![0xaa; 96])
        }

        async fn sign_selection_proof(
            &self,
            _: Slot,
            _: u64,
            _: &Vec<u8>,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SyncServiceError> {
            Ok(self.aggregator_proof.clone())
        }

        async fn sign_contribution_and_proof(
            &self,
            _: &ContributionAndProof,
            _: &Vec<u8>,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SyncServiceError> {
            let idx = self.contrib_call.fetch_add(1, Ordering::SeqCst);
            if idx == self.fail_contrib_on {
                Err(SyncServiceError::Signer(format!("contrib failure on call {idx}")))
            } else {
                Ok(vec![0xcc; 96])
            }
        }
    }

    let signer = Arc::new(ContribFailSigner {
        contrib_call: AtomicUsize::new(0),
        fail_contrib_on: 1, // validator B (second contribution call)
        aggregator_proof,
    });
    let beacon = Arc::new(CountingBeacon::new());

    let service = SyncService::new(
        Arc::clone(&signer),
        Arc::clone(&beacon),
        Arc::new(test_fork_schedule()),
        [0u8; 32],
    );

    let duties = vec![
        SyncCommitteeDuty {
            pubkey: "0x010101".to_string(),
            validator_index: 0,
            validator_sync_committee_indices: vec![0],
        },
        SyncCommitteeDuty {
            pubkey: "0x020202".to_string(),
            validator_index: 1,
            validator_sync_committee_indices: vec![128],
        },
        SyncCommitteeDuty {
            pubkey: "0x030303".to_string(),
            validator_index: 2,
            validator_sync_committee_indices: vec![256],
        },
    ];
    let pubkeys = vec![vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]];
    let head_root = [0x42u8; 32];

    let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

    assert!(
        result.is_ok(),
        "Contribution signing failure must not abort the slot loop: {:?}",
        result.err()
    );

    let ContributionsResult { count } = result.unwrap();
    // A (call 0) and C (call 2) succeed; B (call 1) is skipped.
    assert_eq!(count, 2, "Expected contributions from A and C only");

    // Beacon fetched contributions for all three (selection succeeded), but B's
    // signed proof was discarded.
    assert_eq!(beacon.get_contribution_call_count.load(Ordering::SeqCst), 3);
    // One batch submit with the two successful proofs.
    assert_eq!(beacon.submit_proofs_call_count.load(Ordering::SeqCst), 1);
}

/// Complementary check: when ALL validators' selection signing fails, the function
/// must still return `Ok` with count=0 (no panic, no error propagation).
#[tokio::test]
async fn test_all_selection_failures_return_ok_with_zero_count() {
    // Fail on every call (fail_on=0 only fails the first, but we chain the same signer
    // logic differently).  Use a signer that always errors on selection.
    struct AlwaysFailSigner;

    #[async_trait]
    impl SyncSigner for AlwaysFailSigner {
        async fn sign_sync_committee_message(
            &self,
            _: &Root,
            _: Slot,
            _: &Vec<u8>,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SyncServiceError> {
            Ok(vec![0xaa; 96])
        }

        async fn sign_selection_proof(
            &self,
            _: Slot,
            _: u64,
            _: &Vec<u8>,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SyncServiceError> {
            Err(SyncServiceError::Signer("always fails".into()))
        }

        async fn sign_contribution_and_proof(
            &self,
            _: &ContributionAndProof,
            _: &Vec<u8>,
            _: &ForkSchedule,
            _: &Root,
        ) -> Result<Vec<u8>, SyncServiceError> {
            unreachable!("should not be called when selection proof fails")
        }
    }

    let service = SyncService::new(
        Arc::new(AlwaysFailSigner),
        Arc::new(CountingBeacon::new()),
        Arc::new(test_fork_schedule()),
        [0u8; 32],
    );

    let duties = vec![
        SyncCommitteeDuty {
            pubkey: "0x01".to_string(),
            validator_index: 0,
            validator_sync_committee_indices: vec![0],
        },
        SyncCommitteeDuty {
            pubkey: "0x02".to_string(),
            validator_index: 1,
            validator_sync_committee_indices: vec![128],
        },
    ];
    let pubkeys = vec![vec![1u8; 48], vec![2u8; 48]];
    let head_root = [0u8; 32];

    let result = service.produce_contributions(100, &duties, &head_root, &pubkeys).await;

    assert!(result.is_ok(), "All-failure should still return Ok: {:?}", result.err());
    assert_eq!(result.unwrap().count, 0);
}
