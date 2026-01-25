//! Slot timing service for Ethereum consensus.
//!
//! This module provides slot timing functionality including:
//! - `SlotClock` trait for slot time calculations
//! - `SystemSlotClock` implementation using system time
//! - `AttestationTimer` for triggering attestations at 1/3 slot time

mod clock;
mod error;
mod timer;

pub use clock::{MockSlotClock, SlotClock, SystemSlotClock};
pub use error::TimingError;
pub use timer::{AttestationTimer, AttestationTimerHandle};

pub const SECONDS_PER_SLOT: u64 = 12;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const ATTESTATION_DELAY_FRACTION: u64 = 3;
