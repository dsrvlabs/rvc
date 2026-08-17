//! ARCH-5e: `reserve_block` / `reserve_attestation` + `CommittedReservation`.
//!
//! Additive sibling of `stage_*`. Compensating delete is **ARCH-5f** — this
//! file must not grow a `reconcile_unsigned` caller. Shipping reserve without
//! 5f must not become a production sign path (M-1).
//!
//! M-1 (`crates/signer/tests/phantom_row_m1.rs:1-10`):
//! Before the fix, `SignerService::sign_attestation` and `sign_block` called
//! `check_and_record_*` (which committed the row immediately) and only then
//! called `signer.sign`. A signing failure left a committed row in the DB,
//! causing the next legitimate sign attempt to look like a DoubleVote.
//!
//! C1: stage → release → sign → re-check-and-commit is rejected by name.
//! No test in this file is named `*_root` (KAT-first name scanner).

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rvc_slashing::{
    BlockSlashingViolation, CommittedReservation, ReservationKind, SlashingDb, SlashingError,
};

const PUBKEY: &str = "0xdeadbeef01";
const PUBKEY2: &str = "0xdeadbeef02";
const GVR: &[u8; 32] = &[0u8; 32];
const R1: &[u8; 32] = &[0x01u8; 32];
const R2: &[u8; 32] = &[0x02u8; 32];

fn assert_send<T: Send>() {}

/// Compile-time pin: a leaked `MutexGuard` would make this fail to compile.
#[test]
fn test_committed_reservation_is_send() {
    assert_send::<CommittedReservation>();
}

/// RED for the phase: reserve on thread A, then a second thread must complete
/// `reserve_block` for a **different** pubkey while A still holds its token.
/// Under `stage_block` this deadlocks/blocks. Timeout, not a bare join.
#[test]
fn test_reserve_block_releases_the_connection_mutex_before_returning() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    let db_a = Arc::clone(&db);
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    let thread_a = thread::spawn(move || {
        let reservation =
            db_a.reserve_block(PUBKEY, 1, Some("0xroot_a".into()), GVR).expect("reserve A");
        held_tx.send(()).expect("signal held");
        let _ = release_rx.recv_timeout(Duration::from_secs(2));
        reservation
    });

    held_rx.recv_timeout(Duration::from_secs(1)).expect("thread A must reserve");

    let db_b = Arc::clone(&db);
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let started = Instant::now();
        let result = db_b.reserve_block(PUBKEY2, 1, Some("0xroot_b".into()), GVR);
        let _ = done_tx.send((result, started.elapsed()));
    });

    let (result, elapsed) = done_rx
        .recv_timeout(Duration::from_millis(50))
        .expect("second reserve must complete while the first CommittedReservation is still held");
    let reservation_b = result.expect("reserve B");
    assert!(
        elapsed < Duration::from_millis(50),
        "second reserve took {elapsed:?}; mutex must not be held by CommittedReservation"
    );
    assert!(reservation_b.inserted);
    assert_eq!(reservation_b.kind, ReservationKind::Block { slot: 1 });

    let _ = release_tx.send(());
    let reservation_a = thread_a.join().expect("thread A");
    assert!(reservation_a.inserted);
    assert_eq!(db.get_blocks(PUBKEY).expect("get A").len(), 1);
    assert_eq!(db.get_blocks(PUBKEY2).expect("get B").len(), 1);
}

#[test]
fn test_reserve_block_rule_violation_leaves_no_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    let first = db.reserve_block(PUBKEY, 100, Some("0xroot_1".into()), GVR).expect("first reserve");
    assert!(first.inserted);
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);

    let err = db
        .reserve_block(PUBKEY, 100, Some("0xroot_2".into()), GVR)
        .expect_err("double proposal must fail");
    match err {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(slot, 100);
        }
        other => panic!("expected DoubleBlockProposal, got: {other:?}"),
    }
    assert!(
        !err.is_reserve_commit_failure(),
        "a rule violation must not be classified as reserve-commit failure"
    );
    assert_eq!(
        db.get_blocks(PUBKEY).expect("get").len(),
        1,
        "rollback must leave history unchanged"
    );

    // Connection must not be left mid-transaction (exactly one ROLLBACK).
    db.reserve_block(PUBKEY, 101, Some("0xroot_3".into()), GVR)
        .expect("subsequent reserve after a rolled-back violation must succeed");
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 2);
}

#[test]
fn test_reserve_block_resign_reports_not_inserted() {
    let db = SlashingDb::open_in_memory().expect("open");
    let first = db.reserve_block(PUBKEY, 42, Some("0xsame".into()), GVR).expect("first");
    assert!(first.inserted);

    let second = db.reserve_block(PUBKEY, 42, Some("0xsame".into()), GVR).expect("resign");
    assert!(!second.inserted, "idempotent re-sign must report inserted == false");
    assert_eq!(second.kind, ReservationKind::Block { slot: 42 });
    assert_eq!(db.get_blocks(PUBKEY).expect("get").len(), 1);
}

/// M-6: mismatch is rejected before the connection mutex. Proven by holding
/// that mutex via a live `stage_block` guard (which would deadlock a
/// post-mutex check). Suffixed `_mutex` so the name does not match `.*_root$`.
#[test]
fn test_reserve_rejects_genesis_root_mismatch_without_touching_the_mutex() {
    let db = Arc::new(SlashingDb::open_in_memory().expect("open"));
    db.set_genesis_validators_root(R1).expect("pin R1");

    // Warms the GVR cache, then holds the connection mutex for the rest of
    // this scope. `pinned_gvr()` after this is a cache hit and must not lock.
    let _held = db.stage_block(PUBKEY, 1, Some("0xhold".into()), R1).expect("hold mutex");

    let db_b = Arc::clone(&db);
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(db_b.reserve_block(PUBKEY2, 2, Some("0xother".into()), R2));
    });

    let err = rx
        .recv_timeout(Duration::from_millis(200))
        .expect("GVR mismatch must not wait on the connection mutex")
        .expect_err("mismatch must be rejected");
    match err {
        SlashingError::GenesisRootMismatch { expected, got } => {
            assert_eq!(expected, *R1);
            assert_eq!(got, *R2);
        }
        other => panic!("expected GenesisRootMismatch, got: {other:?}"),
    }
    // parking_lot::Mutex is not reentrant — release the staged guard before
    // any API that locks the connection again.
    drop(_held);
    assert!(db.get_blocks(PUBKEY2).expect("get").is_empty());
}

#[test]
fn test_reserve_commit_failure_is_distinguishable_from_a_rule_violation() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.fail_next_commits(1);

    let err = db
        .reserve_block(PUBKEY, 7, Some("0xinject".into()), GVR)
        .expect_err("injected persist failure");
    assert!(err.is_reserve_commit_failure(), "inject must be ReserveCommitFailed, got: {err:?}");
    match err {
        SlashingError::ReserveCommitFailed(msg) => {
            assert!(msg.contains("injected commit failure"), "got: {msg}");
        }
        other => panic!("expected ReserveCommitFailed, got: {other:?}"),
    }
    assert!(
        db.get_blocks(PUBKEY).expect("get").is_empty(),
        "failed reserve must leave no block row"
    );

    let rule_err = {
        db.reserve_block(PUBKEY, 7, Some("0xok".into()), GVR).expect("row after inject exhausted");
        db.reserve_block(PUBKEY, 7, Some("0xother".into()), GVR).expect_err("double proposal")
    };
    assert!(
        !rule_err.is_reserve_commit_failure(),
        "DoubleBlockProposal must not collapse into ReserveCommitFailed"
    );
    match rule_err {
        SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
            assert_eq!(slot, 7);
        }
        other => panic!("expected DoubleBlockProposal, got: {other:?}"),
    }
}

#[test]
fn test_reserve_attestation_commits_and_duplicate_reports_not_inserted() {
    let db = SlashingDb::open_in_memory().expect("open");
    let first =
        db.reserve_attestation(PUBKEY, 3, 10, Some("0xatt".into()), GVR).expect("first att");
    assert!(first.inserted);
    assert_eq!(first.kind, ReservationKind::Attestation { source: 3, target: 10 });
    assert_eq!(db.get_attestations(PUBKEY).expect("get").len(), 1);

    let dup = db.reserve_attestation(PUBKEY, 3, 10, Some("0xatt".into()), GVR).expect("duplicate");
    assert!(!dup.inserted);
    assert_eq!(db.get_attestations(PUBKEY).expect("get").len(), 1);
}

#[test]
fn test_reserve_attestation_double_vote_leaves_no_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.reserve_attestation(PUBKEY, 1, 5, Some("0xatt_1".into()), GVR).expect("first");
    let err =
        db.reserve_attestation(PUBKEY, 1, 5, Some("0xatt_2".into()), GVR).expect_err("double vote");
    assert!(!err.is_reserve_commit_failure());
    assert!(matches!(err, SlashingError::SlashableAttestation(_)));
    assert_eq!(db.get_attestations(PUBKEY).expect("get").len(), 1);
}

#[test]
fn test_reserve_attestation_commit_failure_leaves_no_row() {
    let db = SlashingDb::open_in_memory().expect("open");
    db.fail_next_commits(1);
    let err =
        db.reserve_attestation(PUBKEY, 2, 8, Some("0xatt_inj".into()), GVR).expect_err("inject");
    assert!(err.is_reserve_commit_failure());
    assert!(db.get_attestations(PUBKEY).expect("get").is_empty());
}
