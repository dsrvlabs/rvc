//! Integration tests for M-7: BN-derived clock anchored on genesis_time.
//!
//! Verifies that `DoppelgangerService::current_epoch()` is immune to NTP wall-clock
//! steps by anchoring the epoch computation on a monotonic `Instant` elapsed
//! plus a `start_unix_time` captured once at construction.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rvc_doppelganger::{
    DoppelgangerError, DoppelgangerService, LivenessChecker, SlashingDbReader,
    ValidatorLivenessData,
};

// Epoch length in seconds: SECONDS_PER_SLOT * SLOTS_PER_EPOCH = 12 * 32 = 384
const SECONDS_PER_EPOCH: u64 = 12 * 32;

// --- Minimal mock implementations ---

struct EmptySlashingDb;

impl SlashingDbReader for EmptySlashingDb {
    fn last_signed_attestation_epoch(
        &self,
        _pubkey: &str,
    ) -> Result<Option<u64>, DoppelgangerError> {
        Ok(None)
    }
}

struct EmptyLivenessChecker;

#[async_trait::async_trait]
impl LivenessChecker for EmptyLivenessChecker {
    async fn check_liveness(
        &self,
        _epoch: u64,
        _validator_indices: &[String],
    ) -> Result<Vec<ValidatorLivenessData>, DoppelgangerError> {
        Ok(vec![])
    }
}

fn mock_service(
    genesis_time: u64,
    start_unix_time: u64,
    start_instant: Instant,
) -> DoppelgangerService {
    let liveness: Arc<dyn LivenessChecker> = Arc::new(EmptyLivenessChecker);
    let slashing_db: Arc<dyn SlashingDbReader> = Arc::new(EmptySlashingDb);
    DoppelgangerService::new(liveness, slashing_db, genesis_time)
        .with_start_time(start_instant, start_unix_time)
}

/// M-7: A wall-clock step (NTP jump) must NOT shift the computed epoch.
///
/// The epoch is computed from `start_unix_time + Instant::elapsed()`, not from
/// `SystemTime::now()`. So even if the wall clock jumps, the monotonic elapsed
/// is unaffected and the epoch stays consistent.
#[test]
fn test_wall_clock_jump_does_not_shift_epoch() {
    // Scenario:
    //   genesis_time  = 0
    //   start_unix    = 384 * 5 = 1920  (service "started" 5 epochs after genesis)
    //   start_instant = Instant::now()  (zero elapsed so far)
    //
    // current_epoch() = (start_unix + elapsed - genesis) / SECONDS_PER_EPOCH
    //                 = (1920 + ~0 - 0) / 384 = 5

    let genesis_time = 0_u64;
    let start_unix_time = SECONDS_PER_EPOCH * 5; // 1920s => epoch 5
    let start_instant = Instant::now();

    let service = mock_service(genesis_time, start_unix_time, start_instant);

    let epoch = service.current_epoch();
    assert_eq!(epoch, 5, "epoch should be anchored at 5 epochs past genesis");

    // Simulate a "wall-clock jump" by observing that our formula does NOT use
    // SystemTime::now().  We verify by cross-checking with the manual formula:
    //   expected = (start_unix + elapsed - genesis) / SECONDS_PER_EPOCH
    let elapsed_secs = start_instant.elapsed().as_secs();
    let expected = (start_unix_time + elapsed_secs - genesis_time) / SECONDS_PER_EPOCH;
    assert_eq!(
        service.current_epoch(),
        expected,
        "epoch must equal the monotonic-elapsed formula, not SystemTime::now()"
    );

    // Additionally verify that even after a small real-world sleep the epoch is
    // still derived from monotonic elapsed, not from a wall-clock re-read.
    // (No sleep needed: the formula itself is the proof.)
    // The key property: if we had used SystemTime::now() and NTP stepped the clock
    // forward by hours, current_epoch() would jump. With Instant, it cannot.
}

/// M-7: Two services with different genesis_times must produce epochs that differ
/// by exactly `(genesis_time_diff / SECONDS_PER_EPOCH)`.
#[test]
fn test_genesis_time_anchored() {
    // Both services start at the same unix time and same instant.
    let start_instant = Instant::now();
    let start_unix_time = 2_000_000_u64;

    let genesis1 = 1_000_000_u64;
    // genesis2 is 1_000 epochs later: 1_000 * 384 = 384_000 seconds
    let genesis2 = genesis1 + SECONDS_PER_EPOCH * 1_000; // 1_384_000

    let service1 = mock_service(genesis1, start_unix_time, start_instant);
    let service2 = mock_service(genesis2, start_unix_time, start_instant);

    let epoch1 = service1.current_epoch();
    let epoch2 = service2.current_epoch();

    // service1: (2_000_000 - 1_000_000) / 384 = 2_604 epochs
    // service2: (2_000_000 - 1_384_000) / 384 = 1_604 epochs
    // Difference: 1_000 epochs
    assert_eq!(
        epoch1.saturating_sub(epoch2),
        1_000,
        "epoch diff should be genesis_time_diff / SECONDS_PER_EPOCH"
    );
}

/// Sanity-check: epoch advances monotonically as elapsed increases.
#[test]
fn test_epoch_advances_with_elapsed() {
    let genesis_time = 0_u64;
    // Pin start_instant to appear 384 seconds in the past (one epoch elapsed)
    let one_epoch_ago = Instant::now() - Duration::from_secs(SECONDS_PER_EPOCH);
    let start_unix_time = SECONDS_PER_EPOCH; // started 1 epoch after genesis

    let service = mock_service(genesis_time, start_unix_time, one_epoch_ago);

    // elapsed ≈ 384s, start_unix = 384, genesis = 0
    // now_unix ≈ 384 + 384 = 768, epoch ≈ 768 / 384 = 2
    let epoch = service.current_epoch();
    assert!(epoch >= 2, "with ~1 epoch elapsed the computed epoch should be ≥ 2, got {epoch}");
}
