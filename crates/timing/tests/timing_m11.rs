//! Regression tests for M-11: attestation timing rounding.
//!
//! Verifies that `time_until_attestation` uses millisecond arithmetic (slot_duration_ms / 3)
//! rather than integer seconds (slot_duration_secs / 3), so attestation fires at the
//! exact one-third mark even for non-12 s slot durations.

use rvc_timing::{MockSlotClock, SlotClock};
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

// -- Regression guard: 12 s slot fires at exactly 4.000 s (12000 ms / 3 = 4000 ms).
#[test]
fn test_attestation_fires_at_one_third_of_12s_slot() {
    let clock = MockSlotClock::new(TEST_GENESIS, Duration::from_secs(12), 32);
    clock.set_current_time(TEST_GENESIS); // at exact slot start
    let time_until = clock.time_until_attestation(0).unwrap();
    assert_eq!(
        time_until,
        Duration::from_millis(4000),
        "12 s slot must fire at exactly 4.000 s (4000 ms)"
    );
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
