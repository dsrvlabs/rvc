//! Sync committee residual surface after RF2-01 / RF3-20.
//!
//! Production aggregator selection and subnet mapping now live in
//! `eth_types::{is_sync_committee_aggregator, subcommittee_index, SYNC_COMMITTEE_*}`.
//! This crate retains only `SyncServiceError` for any remaining import sites.

mod error;

pub use error::SyncServiceError;
