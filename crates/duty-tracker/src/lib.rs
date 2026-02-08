//! rvc-duty-tracker - Ethereum validator duty tracking and caching.

pub mod error;
pub mod tracker;

pub use error::DutyTrackerError;
pub use tracker::{DutyCacheKey, DutyTracker};
