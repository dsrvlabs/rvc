//! Slot clock implementations for Ethereum consensus timing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::crypto::Slot;

use super::error::TimingError;
use super::{SECONDS_PER_SLOT, SLOTS_PER_EPOCH};

pub trait SlotClock: Send + Sync {
    fn genesis_time(&self) -> u64;
    fn slot_duration(&self) -> Duration;
    fn current_slot(&self) -> Result<Slot, TimingError>;
    fn slot_start_time(&self, slot: Slot) -> u64;
    fn slot_end_time(&self, slot: Slot) -> u64;
    fn attestation_time(&self, slot: Slot) -> u64;
    fn time_until_slot(&self, slot: Slot) -> Result<Duration, TimingError>;
    fn time_until_attestation(&self, slot: Slot) -> Result<Duration, TimingError>;
    fn slot_to_epoch(&self, slot: Slot) -> u64;
    fn epoch_start_slot(&self, epoch: u64) -> Slot;
}

pub struct SystemSlotClock {
    genesis_time: u64,
    slot_duration: Duration,
    slots_per_epoch: u64,
}

impl SystemSlotClock {
    pub fn new(genesis_time: u64, slot_duration: Duration, slots_per_epoch: u64) -> Self {
        Self { genesis_time, slot_duration, slots_per_epoch }
    }

    pub fn new_mainnet(genesis_time: u64) -> Self {
        Self::new(genesis_time, Duration::from_secs(SECONDS_PER_SLOT), SLOTS_PER_EPOCH)
    }

    fn current_unix_time(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).expect("time went backwards").as_secs()
    }
}

impl SlotClock for SystemSlotClock {
    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    fn current_slot(&self) -> Result<Slot, TimingError> {
        let current_time = self.current_unix_time();
        if current_time < self.genesis_time {
            return Err(TimingError::BeforeGenesis {
                current_time,
                genesis_time: self.genesis_time,
            });
        }
        let seconds_since_genesis = current_time - self.genesis_time;
        Ok(seconds_since_genesis / self.slot_duration.as_secs())
    }

    fn slot_start_time(&self, slot: Slot) -> u64 {
        self.genesis_time + (slot * self.slot_duration.as_secs())
    }

    fn slot_end_time(&self, slot: Slot) -> u64 {
        self.slot_start_time(slot + 1)
    }

    fn attestation_time(&self, slot: Slot) -> u64 {
        self.slot_start_time(slot) + (self.slot_duration.as_secs() / 3)
    }

    fn time_until_slot(&self, slot: Slot) -> Result<Duration, TimingError> {
        let current_time = self.current_unix_time();
        let slot_start = self.slot_start_time(slot);

        if current_time >= slot_start {
            return Ok(Duration::ZERO);
        }

        Ok(Duration::from_secs(slot_start - current_time))
    }

    fn time_until_attestation(&self, slot: Slot) -> Result<Duration, TimingError> {
        let current_time = self.current_unix_time();
        let attestation_time = self.attestation_time(slot);

        if current_time >= attestation_time {
            return Ok(Duration::ZERO);
        }

        Ok(Duration::from_secs(attestation_time - current_time))
    }

    fn slot_to_epoch(&self, slot: Slot) -> u64 {
        slot / self.slots_per_epoch
    }

    fn epoch_start_slot(&self, epoch: u64) -> Slot {
        epoch * self.slots_per_epoch
    }
}

pub struct MockSlotClock {
    genesis_time: u64,
    slot_duration: Duration,
    slots_per_epoch: u64,
    current_time: std::sync::atomic::AtomicU64,
}

impl MockSlotClock {
    pub fn new(genesis_time: u64, slot_duration: Duration, slots_per_epoch: u64) -> Self {
        Self {
            genesis_time,
            slot_duration,
            slots_per_epoch,
            current_time: std::sync::atomic::AtomicU64::new(genesis_time),
        }
    }

    pub fn set_current_time(&self, time: u64) {
        self.current_time.store(time, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn advance_time(&self, seconds: u64) {
        self.current_time.fetch_add(seconds, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_slot(&self, slot: Slot) {
        let slot_start = self.genesis_time + (slot * self.slot_duration.as_secs());
        self.set_current_time(slot_start);
    }

    fn get_current_time(&self) -> u64 {
        self.current_time.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SlotClock for MockSlotClock {
    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    fn slot_duration(&self) -> Duration {
        self.slot_duration
    }

    fn current_slot(&self) -> Result<Slot, TimingError> {
        let current_time = self.get_current_time();
        if current_time < self.genesis_time {
            return Err(TimingError::BeforeGenesis {
                current_time,
                genesis_time: self.genesis_time,
            });
        }
        let seconds_since_genesis = current_time - self.genesis_time;
        Ok(seconds_since_genesis / self.slot_duration.as_secs())
    }

    fn slot_start_time(&self, slot: Slot) -> u64 {
        self.genesis_time + (slot * self.slot_duration.as_secs())
    }

    fn slot_end_time(&self, slot: Slot) -> u64 {
        self.slot_start_time(slot + 1)
    }

    fn attestation_time(&self, slot: Slot) -> u64 {
        self.slot_start_time(slot) + (self.slot_duration.as_secs() / 3)
    }

    fn time_until_slot(&self, slot: Slot) -> Result<Duration, TimingError> {
        let current_time = self.get_current_time();
        let slot_start = self.slot_start_time(slot);

        if current_time >= slot_start {
            return Ok(Duration::ZERO);
        }

        Ok(Duration::from_secs(slot_start - current_time))
    }

    fn time_until_attestation(&self, slot: Slot) -> Result<Duration, TimingError> {
        let current_time = self.get_current_time();
        let attestation_time = self.attestation_time(slot);

        if current_time >= attestation_time {
            return Ok(Duration::ZERO);
        }

        Ok(Duration::from_secs(attestation_time - current_time))
    }

    fn slot_to_epoch(&self, slot: Slot) -> u64 {
        slot / self.slots_per_epoch
    }

    fn epoch_start_slot(&self, epoch: u64) -> Slot {
        epoch * self.slots_per_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GENESIS_TIME: u64 = 1606824023; // Mainnet genesis

    fn create_mock_clock() -> MockSlotClock {
        MockSlotClock::new(TEST_GENESIS_TIME, Duration::from_secs(12), 32)
    }

    #[test]
    fn test_slot_clock_genesis_time() {
        let clock = create_mock_clock();
        assert_eq!(clock.genesis_time(), TEST_GENESIS_TIME);
    }

    #[test]
    fn test_slot_clock_slot_duration() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_duration(), Duration::from_secs(12));
    }

    #[test]
    fn test_current_slot_at_genesis() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        assert_eq!(clock.current_slot().unwrap(), 0);
    }

    #[test]
    fn test_current_slot_after_one_slot() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 12);
        assert_eq!(clock.current_slot().unwrap(), 1);
    }

    #[test]
    fn test_current_slot_mid_slot() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 6);
        assert_eq!(clock.current_slot().unwrap(), 0);
    }

    #[test]
    fn test_current_slot_multiple_slots() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + (100 * 12));
        assert_eq!(clock.current_slot().unwrap(), 100);
    }

    #[test]
    fn test_current_slot_before_genesis() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME - 100);
        let result = clock.current_slot();
        assert!(matches!(result, Err(TimingError::BeforeGenesis { .. })));
    }

    #[test]
    fn test_slot_start_time() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_start_time(0), TEST_GENESIS_TIME);
        assert_eq!(clock.slot_start_time(1), TEST_GENESIS_TIME + 12);
        assert_eq!(clock.slot_start_time(100), TEST_GENESIS_TIME + 1200);
    }

    #[test]
    fn test_slot_end_time() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_end_time(0), TEST_GENESIS_TIME + 12);
        assert_eq!(clock.slot_end_time(1), TEST_GENESIS_TIME + 24);
    }

    #[test]
    fn test_attestation_time() {
        let clock = create_mock_clock();
        assert_eq!(clock.attestation_time(0), TEST_GENESIS_TIME + 4);
        assert_eq!(clock.attestation_time(1), TEST_GENESIS_TIME + 16);
    }

    #[test]
    fn test_time_until_slot_in_future() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        let time_until = clock.time_until_slot(10).unwrap();
        assert_eq!(time_until, Duration::from_secs(120));
    }

    #[test]
    fn test_time_until_slot_already_started() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 100);
        let time_until = clock.time_until_slot(5).unwrap();
        assert_eq!(time_until, Duration::ZERO);
    }

    #[test]
    fn test_time_until_attestation_in_future() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        let time_until = clock.time_until_attestation(0).unwrap();
        assert_eq!(time_until, Duration::from_secs(4));
    }

    #[test]
    fn test_time_until_attestation_already_passed() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME + 10);
        let time_until = clock.time_until_attestation(0).unwrap();
        assert_eq!(time_until, Duration::ZERO);
    }

    #[test]
    fn test_slot_to_epoch() {
        let clock = create_mock_clock();
        assert_eq!(clock.slot_to_epoch(0), 0);
        assert_eq!(clock.slot_to_epoch(31), 0);
        assert_eq!(clock.slot_to_epoch(32), 1);
        assert_eq!(clock.slot_to_epoch(64), 2);
        assert_eq!(clock.slot_to_epoch(100), 3);
    }

    #[test]
    fn test_epoch_start_slot() {
        let clock = create_mock_clock();
        assert_eq!(clock.epoch_start_slot(0), 0);
        assert_eq!(clock.epoch_start_slot(1), 32);
        assert_eq!(clock.epoch_start_slot(2), 64);
        assert_eq!(clock.epoch_start_slot(10), 320);
    }

    #[test]
    fn test_mock_clock_set_slot() {
        let clock = create_mock_clock();
        clock.set_slot(50);
        assert_eq!(clock.current_slot().unwrap(), 50);
    }

    #[test]
    fn test_mock_clock_advance_time() {
        let clock = create_mock_clock();
        clock.set_current_time(TEST_GENESIS_TIME);
        assert_eq!(clock.current_slot().unwrap(), 0);
        clock.advance_time(12);
        assert_eq!(clock.current_slot().unwrap(), 1);
        clock.advance_time(24);
        assert_eq!(clock.current_slot().unwrap(), 3);
    }

    #[test]
    fn test_system_slot_clock_new_mainnet() {
        let clock = SystemSlotClock::new_mainnet(TEST_GENESIS_TIME);
        assert_eq!(clock.genesis_time(), TEST_GENESIS_TIME);
        assert_eq!(clock.slot_duration(), Duration::from_secs(12));
        assert_eq!(clock.slots_per_epoch, 32);
    }
}
