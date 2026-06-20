//! Regression tests for M-11: attestation timing rounding.
//!
//! Verifies that `time_until_attestation` uses the spec basis-points formula
//! `due_ms = ATTESTATION_DUE_BPS * slot_duration_ms / BASIS_POINTS` (floor) in
//! millisecond arithmetic rather than integer seconds, so attestation fires at the
//! exact spec mark even for non-12 s slot durations. On mainnet this is
//! `3333 * 12000 / 10000 = 3999 ms` (not 4000), per report §4.3.

use rvc_timing::{due_ms, MockSlotClock, SlotClock};
use std::time::Duration;

const TEST_GENESIS: u64 = 1_606_824_023;

// -- RED test: 7 s slot is NOT divisible by 3, so integer-second division truncates.
// With buggy code: 7 / 3 = 2 s  →  Duration::from_secs(2) = Duration::from_millis(2000)
// With fixed code: 7000 / 3 = 2333 ms  →  Duration::from_millis(2333)
#[test]
fn test_attestation_fires_at_one_third_of_7s_slot_non_divisible() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(7), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(
        time_until,
        Duration::from_millis(7000 / 3),
        "7 s slot must fire at 7000/3 = 2333 ms, not at the truncated 2 s"
    );
}

// -- Regression guard: 6 s slot fires at exactly 2.000 s (6000 ms / 3 = 2000 ms).
#[test]
fn test_attestation_fires_at_one_third_of_6s_slot() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(6), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(
        time_until,
        Duration::from_millis(2000),
        "6 s slot must fire at exactly 2.000 s (2000 ms)"
    );
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
#[test]
fn test_attestation_time_offset_consistent_with_slot_start() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(12), 32);
    // Slot 0 starts at genesis; attestation fires at genesis + 4 s.
    assert_eq!(clock.attestation_time(0), TEST_GENESIS + 4);
    // Slot 1 starts at genesis + 12; attestation fires at genesis + 16.
    assert_eq!(clock.attestation_time(1), TEST_GENESIS + 16);
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
