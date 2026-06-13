//! Canonical hex-parsing primitives — single source of truth for hex/GVR parsing.
//!
//! This module provides strict, well-typed constructors for hex-encoded
//! Ethereum values. Later remediation issues (L-2, GVR-1, IMP-1, EXIT-1)
//! will migrate existing ad-hoc parsing onto these seams.
//!
//! # Accepted and rejected inputs
//!
//! | Input form                     | Result                              |
//! |--------------------------------|-------------------------------------|
//! | Bare even-length hex (`abcd…`) | Accepted                            |
//! | `0x`-prefixed (`0xabcd…`)      | Accepted                            |
//! | `0X`-prefixed (`0Xabcd…`)      | `InvalidHex` (only `0x` stripped)   |
//! | `0x0x…` double prefix          | `DoublePrefix`                      |
//! | `0x0X…` mixed double prefix    | `DoublePrefix`                      |
//! | Empty string `""`              | `InvalidLength { got: 0 }`          |
//! | Lone prefix `"0x"`             | `InvalidLength { got: 0 }`          |
//! | Odd-length hex digits          | `InvalidHex`                        |
//! | Non-hex character              | `InvalidHex`                        |
//! | Wrong decoded byte count       | `InvalidLength`                     |
//! | Whitespace                     | `InvalidHex`                        |

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

    /// The string starts with `0x0x` or `0x0X`, which is a double-prefix and
    /// is rejected.
    #[error("double 0x prefix detected")]
    DoublePrefix,
}
