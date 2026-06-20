//! Regression tests for M-11: attestation timing rounding.
//!
//! Verifies that `time_until_attestation` uses the spec basis-points formula
//! `due_ms = ATTESTATION_DUE_BPS * slot_duration_ms / BASIS_POINTS` (floor) in
//! millisecond arithmetic rather than integer seconds, so attestation fires at the
//! exact spec mark even for non-12 s slot durations. On mainnet this is
//! `3333 * 12000 / 10000 = 3999 ms` (not 4000), per report §4.3.

use rvc_timing::{
    due_ms, MockSlotClock, SlotClock, AGGREGATE_DUE_BPS_GLOAS, ATTESTATION_DUE_BPS_GLOAS,
};
use std::time::Duration;

const TEST_GENESIS: u64 = 1_606_824_023;

// -- 7 s slot via the BPS formula. 3333 * 7000 / 10000 = 2333.1, floor = 2333 ms.
// The intended 3334→3333 bps shift leaves this value unchanged here: the legacy
// `7000 / 3 = 2333` and the spec `3333 * 7000 / 10000 = 2333` both floor to 2333.
#[test]
fn test_attestation_fires_at_one_third_of_7s_slot_non_divisible() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(7), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(time_until, Duration::from_millis(2333), "7 s slot: 3333 * 7000 / 10000 = 2333 ms");
}

// -- 6 s slot via the BPS formula. 3333 * 6000 / 10000 = 1999.8, floor = 1999 ms.
// Intended 3334→3333 bps shift: 2000→1999 (NOT a regression; the legacy 6000/3
// rounded to 2000, but the spec uses 3333 bps).
#[test]
fn test_attestation_fires_at_one_third_of_6s_slot() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(6), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(time_until, Duration::from_millis(1999), "6 s slot: 3333 * 6000 / 10000 = 1999 ms");
}

// -- Regression guard: 12 s slot fires at the spec BPS mark 3333 * 12000 / 10000 = 3999 ms.
#[test]
fn test_attestation_fires_at_one_third_of_12s_slot() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(12), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(
        time_until,
        Duration::from_millis(3999),
        "12 s slot must fire at 3333 * 12000 / 10000 = 3999 ms"
    );
}

// -- Default-bps (3333) vector: mainnet 12 s slot via `time_until_attestation`.
// 3333 * 12000 / 10000 = 3999 ms (floor). Explicit BPS restatement of the 12 s lock-in.
#[test]
fn test_attestation_default_bps_12s_slot_is_3999ms() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(12), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(
        time_until,
        Duration::from_millis(3999),
        "12 s slot: 3333 * 12000 / 10000 = 3999 ms"
    );
}

// -- Default-bps (3333) vector: non-12 s 5 s slot via `time_until_attestation`.
// 3333 * 5000 / 10000 = 1666 ms (floor), proving correctness for non-12 s networks.
#[test]
fn test_attestation_default_bps_5s_slot_is_1666ms() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(5), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(time_until, Duration::from_millis(1666), "5 s slot: 3333 * 5000 / 10000 = 1666 ms");
}

// -- Verify `attestation_time` (slot_start + offset in whole seconds) is consistent.
// Seconds API floors (slot_start_ms + due_ms) / 1000; for a 12 s slot due_ms = 3999.
// Intended 3334→3333 bps shift: genesis+4→genesis+3 and genesis+16→genesis+15
// (NOT a regression; the legacy 4000 ms floored to +4, the spec 3999 ms floors to +3).
#[test]
fn test_attestation_time_offset_consistent_with_slot_start() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(12), 32);
    // Slot 0 starts at genesis; (0 + 3999) / 1000 = genesis + 3.
    assert_eq!(clock.attestation_time(0), TEST_GENESIS + 3);
    // Slot 1 starts at genesis + 12; (12000 + 3999) / 1000 = genesis + 15.
    assert_eq!(clock.attestation_time(1), TEST_GENESIS + 15);
}

// -- After the attestation moment has passed, time_until_attestation returns zero.
#[test]
fn test_attestation_time_past_returns_zero() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(6), 32);
    // Advance time well past the 2 s attestation window for slot 0.
    clock.set_current_time(TEST_GENESIS + 5);
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(time_until, Duration::ZERO);
}

// -- Whole-slot edge: bps == BASIS_POINTS yields the full slot duration.
// 10000 * 12000 / 10000 = 12000 ms.
#[test]
fn test_due_ms_whole_slot_edge() {
    assert_eq!(due_ms(10000, 12000), 12000);
}

// -- Tiny-bps floor: proves multiply-before-divide.
// 1 * 12000 / 10000 = 1 ms (whereas 1 / 10000 * 12000 would floor to 0).
#[test]
fn test_due_ms_tiny_bps_floor() {
    assert_eq!(due_ms(1, 12000), 1);
}

// -- Gloas 1/4 attestation deadline on a 12 s slot: 2500 * 12000 / 10000 = 3000 ms.
// The legacy integer `/3` model could only produce 4000 ms; it could not express 1/4.
#[test]
fn test_due_ms_gloas_attestation_quarter_12s() {
    assert_eq!(due_ms(ATTESTATION_DUE_BPS_GLOAS, 12000), 3000);
}

// -- Gloas 1/2 aggregate deadline on a 12 s slot: 5000 * 12000 / 10000 = 6000 ms.
// The legacy `*2/3` model could only produce 8000 ms; it could not express 1/2.
#[test]
fn test_due_ms_gloas_aggregate_half_12s() {
    assert_eq!(due_ms(AGGREGATE_DUE_BPS_GLOAS, 12000), 6000);
}

// -- Gloas 1/4 attestation deadline on a non-12 s 8 s slot: 2500 * 8000 / 10000 = 2000 ms.
// Proves the formula generalizes across slot durations (legacy /3 would give ~2666).
#[test]
fn test_due_ms_gloas_attestation_quarter_8s() {
    assert_eq!(due_ms(ATTESTATION_DUE_BPS_GLOAS, 8000), 2000);
}
