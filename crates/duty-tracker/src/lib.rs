//! rvc-duty-tracker - Ethereum validator duty tracking and caching.

mod error;
mod tracker;

pub use error::DutyTrackerError;
pub use tracker::{DutyCacheKey, DutyTracker};
