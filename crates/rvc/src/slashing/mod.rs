//! Slashing protection module for validator client.
//!
//! This module provides types and functionality for slashing protection
//! as specified in EIP-3076.

mod db;
mod error;
mod types;

pub use db::SlashingDb;
pub use error::SlashingError;
pub use types::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata,
    SignedAttestation, SignedBlock, ValidatorRecord,
};
