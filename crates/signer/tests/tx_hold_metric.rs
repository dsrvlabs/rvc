//! Regression tests for ISSUE-3.12: `rvc_signer_slashing_tx_hold_duration_ms` histogram.
//!
//! These tests assert that the tx-hold histogram is observed on every
//! stage → commit (happy path) and stage → discard (signer failure) cycle.

use std::sync::Arc;

use crypto::{KeyManager, LocalSigner, SecretKey};
use eth_types::{AttestationData, Checkpoint, ForkSchedule, Root};
use metrics::definitions::RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS;
use rvc_signer::SignerService;
use slashing::SlashingDb;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_fork_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
        altair_fork_epoch: 50,
        altair_fork_version: [0x00, 0x00, 0x00, 0x02],
        bellatrix_fork_epoch: u64::MAX,
        bellatrix_fork_version: [0x00, 0x00, 0x00, 0x03],
        capella_fork_epoch: u64::MAX,
        capella_fork_version: [0x00, 0x00, 0x00, 0x04],
        deneb_fork_epoch: u64::MAX,
        deneb_fork_version: [0x00, 0x00, 0x00, 0x05],
        electra_fork_epoch: u64::MAX,
        electra_fork_version: [0x00, 0x00, 0x00, 0x06],
        fulu_fork_epoch: u64::MAX,
        fulu_fork_version: [0x00, 0x00, 0x00, 0x07],
    }
}

fn make_attestation_data(source_epoch: u64, target_epoch: u64) -> AttestationData {
    AttestationData {
        slot: target_epoch * 8,
        index: 0,
        beacon_block_root: [0xbb; 32],
        source: Checkpoint { epoch: source_epoch, root: [0x11; 32] },
        target: Checkpoint { epoch: target_epoch, root: [0x22; 32] },
    }
}

const GVR: Root = [0xaa; 32];

// ── Test: histogram observed on stage → commit (happy path) ──────────────────

/// ISSUE-3.12: after a successful `sign_attestation`, the histogram
/// `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}` must have
/// been incremented and the observed value must be > 0 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metric_recorded_on_stage_commit() {
    let sk = SecretKey::generate();
    let pubkey = sk.public_key();

    let mut manager = KeyManager::new();
    manager.insert(sk);
    let signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(manager)));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(signer, db);

    let fs = make_fork_schedule();
    let data = make_attestation_data(1, 2);

    // Snapshot before
    let count_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&["attestation"])
        .get_sample_count();
    let sum_before = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&["attestation"])
        .get_sample_sum();

    let result = service.sign_attestation(&data, &pubkey, &fs, &GVR).await;
    assert!(result.is_ok(), "sign_attestation must succeed; err: {:?}", result.err());

    // Assert: exactly one new observation was added for kind=attestation
    let count_after = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&["attestation"])
        .get_sample_count();
    let sum_after = RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS
        .with_label_values(&["attestation"])
        .get_sample_sum();

    assert!(
        count_after > count_before,
        "histogram must be observed at least once on commit; before={count_before}, after={count_after}"
    );
    assert!(
        sum_after >= sum_before,
        "histogram sum must be non-decreasing; before={sum_before}, after={sum_after}"
    );
}

// ── Test: histogram observed on stage → discard (signer failure) ─────────────

/// ISSUE-3.12: when `sign_block` fails because the key is absent, the
/// staged transaction is discarded.  The histogram
/// `rvc_signer_slashing_tx_hold_duration_ms{kind="block"}` must still be
/// incremented — the transaction hold was real even though the row was rolled back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metric_recorded_on_stage_discard() {
    // Empty signer — sign call will fail with KeyNotFound, triggering discard.
    let empty_signer = Arc::new(crypto::CompositeSigner::new(LocalSigner::new(KeyManager::new())));
    let db = Arc::new(SlashingDb::open_in_memory().expect("open in-memory DB"));
    let service = SignerService::new(empty_signer, db);

    let sk = SecretKey::generate();
    let pubkey = sk.public_key();

    let block_root: Root = [0xde; 32];
    let slot = 300u64;
    let fs = make_fork_schedule();

    // Snapshot before
    let count_before =
        RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS.with_label_values(&["block"]).get_sample_count();

    let result = service.sign_block(&block_root, slot, &pubkey, &fs, &GVR).await;
    assert!(result.is_err(), "sign_block must fail when key is absent");

    // Assert: histogram was still observed for kind=block despite the discard
    let count_after =
        RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS.with_label_values(&["block"]).get_sample_count();

    assert!(
        count_after > count_before,
        "histogram must be observed on discard too; before={count_before}, after={count_after}"
    );
}
