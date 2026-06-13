//! Canonical hex-parsing primitives — single source of truth for hex/GVR parsing.
//!
//! This module provides strict, well-typed constructors for hex-encoded
//! Ethereum values. Later remediation issues (L-2, GVR-1, IMP-1, EXIT-1)
//! will migrate existing ad-hoc parsing onto these seams.
//!
//! # Strict-prefix rules
//! - Bare even-length hex (no `0x`) is accepted.
//! - A single `0x` prefix is accepted.
//! - A double `0x0x` prefix is rejected as [`ParseError::DoublePrefix`].

pub mod gvr_hex;
pub mod pubkey_hex;
pub mod signing_root_hex;

/// Errors that can occur when parsing a canonical hex value.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The string contained a character that is not valid hexadecimal,
    /// or has an odd number of hex digits.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// The decoded byte slice has the wrong length for this type.
    #[error("invalid length: expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// The string starts with `0x0x`, which is a double-prefix and is rejected.
    #[error("double 0x prefix detected")]
    DoublePrefix,
}
