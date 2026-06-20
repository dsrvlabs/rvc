//! Slot timing service for Ethereum consensus.
//!
//! This module provides slot timing functionality including:
//! - `SlotClock` trait for slot time calculations
//! - `SystemSlotClock` implementation using system time
//! - `AttestationTimer` for triggering attestations at the spec basis-points
//!   deadline (`ATTESTATION_DUE_BPS` of the slot; 3999 ms on mainnet)

mod clock;
mod error;
mod timer;

pub use clock::{MockSlotClock, SlotClock, SystemSlotClock};
pub use error::TimingError;
pub use timer::{AttestationTimer, AttestationTimerHandle};

pub use eth_types::{SECONDS_PER_SLOT, SLOTS_PER_EPOCH};

/// Denominator for the intra-slot basis-points timing model (report §4.3).
///
/// Intra-slot deadlines are expressed as `bps * slot_duration_ms / BASIS_POINTS`
/// (floor), so non-12 s and Gloas slot durations are exact rather than truncated
/// by an integer `/3` / `*2/3`.
pub const BASIS_POINTS: u64 = 10000;

/// Attestation broadcast deadline in basis points of the slot (report §4.3).
///
/// 3333 bps of a 12 s slot is `3333 * 12000 / 10000 = 3999 ms`, the spec 1/3
/// mark (not the legacy `12000 / 3 = 4000 ms`).
pub const ATTESTATION_DUE_BPS: u64 = 3333;

/// Sync-committee message broadcast deadline in basis points (report §4.3).
///
/// Shares the 1/3 mark with attestations (3333 bps).
pub const SYNC_MESSAGE_DUE_BPS: u64 = 3333;

/// Aggregate (attestation) broadcast deadline in basis points (report §4.3).
///
/// 6667 bps of a 12 s slot is `6667 * 12000 / 10000 = 8000 ms`, the spec 2/3
/// mark (matching the legacy `12000 * 2 / 3 = 8000 ms`).
pub const AGGREGATE_DUE_BPS: u64 = 6667;

/// Sync-committee contribution broadcast deadline in basis points (report §4.3).
///
/// Shares the 2/3 mark with aggregates (6667 bps).
pub const CONTRIBUTION_DUE_BPS: u64 = 6667;

/// Gloas attestation broadcast deadline in basis points (report §4.3, Gloas).
///
/// Fork-specific override: 2500 bps = 1/4 of the slot (`2500 * 12000 / 10000 =
/// 3000 ms`), a fraction the legacy integer `/3` model could not express.
pub const ATTESTATION_DUE_BPS_GLOAS: u64 = 2500;

/// Gloas aggregate broadcast deadline in basis points (report §4.3, Gloas).
///
/// Fork-specific override: 5000 bps = 1/2 of the slot (`5000 * 12000 / 10000 =
/// 6000 ms`), a fraction the legacy integer `*2/3` model could not express.
pub const AGGREGATE_DUE_BPS_GLOAS: u64 = 5000;

/// Intra-slot deadline in milliseconds for a basis-points fraction of the slot.
///
/// Computes `bps * slot_duration_ms / BASIS_POINTS` with floor (integer)
/// division, matching the spec `//`. Multiply-before-divide so the floor matches
/// the spec exactly (report §4.3): `due_ms(3333, 12000) == 3999`, never
/// `3333 / 10000 * 12000 == 0`.
///
/// # Examples
///
/// ```
/// use rvc_timing::{due_ms, ATTESTATION_DUE_BPS, AGGREGATE_DUE_BPS};
/// assert_eq!(due_ms(ATTESTATION_DUE_BPS, 12000), 3999);
/// assert_eq!(due_ms(AGGREGATE_DUE_BPS, 12000), 8000);
/// ```
pub fn due_ms(bps: u64, slot_duration_ms: u64) -> u64 {
    bps * slot_duration_ms / BASIS_POINTS
}
