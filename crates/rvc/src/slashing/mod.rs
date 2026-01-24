//! Slashing protection module for validator client.
//!
//! This module provides types and functionality for slashing protection
//! as specified in EIP-3076.

mod types;

pub use types::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata,
    SignedAttestation, SignedBlock, ValidatorRecord,
};
