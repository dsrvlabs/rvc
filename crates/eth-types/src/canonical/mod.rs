//! Canonical hex-parsing primitives — single source of truth for hex/GVR parsing.
//!
//! This module is the **only** place in `eth-types` that performs prefix-strip
//! and hex-decode. [`pubkey_hex::strip_prefix`] and [`pubkey_hex::decode_hex`]
//! are the engine; typed constructors ([`parse_pubkey_hex`](pubkey_hex::parse_pubkey_hex),
//! [`parse_gvr_hex`](gvr_hex::parse_gvr_hex),
//! [`parse_signing_root_hex`](signing_root_hex::parse_signing_root_hex)) and
//! the Beacon-API serde helpers (`hex_fixed`, `serde_signature`) all delegate
//! here.
//!
//! Call-site migration of hand-rolled parse sites outside this crate is
//! tracked separately (RF3-15).
//!
//! # Accepted and rejected inputs
//!
//! | Input form                     | Result                              |
//! |--------------------------------|-------------------------------------|
//! | Bare even-length hex (`abcd…`) | Accepted                            |
//! | `0x`-prefixed (`0xabcd…`)      | Accepted                            |
//! | `0X`-prefixed (`0Xabcd…`)      | Accepted                            |
//! | `0x0x…` / `0x0X…` / `0X0x…` / `0X0X…` | `DoublePrefix`               |
//! | Empty string `""`              | `InvalidLength { got: 0 }`          |
//! | Lone prefix `"0x"` / `"0X"`    | `InvalidLength { got: 0 }`          |
//! | Odd-length hex digits          | `InvalidHex`                        |
//! | Non-hex character              | `InvalidHex`                        |
//! | Wrong decoded byte count       | `InvalidLength`                     |
//! | Whitespace                     | `InvalidHex`                        |
//!
//! # Per-seam strictness
//!
//! The permissive policy above (optional single `0x`/`0X`) applies to the
//! typed constructors. Beacon-API serde seams (`hex_fixed`, `serde_signature`)
//! deliberately **require** a leading `0x`/`0X` and reject bare hex — that is
//! a contract requirement of the wire format, not a second decode engine.

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

    /// The string starts with a doubled `0x`/`0X` prefix
    /// (e.g. `0x0x`, `0x0X`, `0X0x`, `0X0X`).
    #[error("double 0x prefix detected")]
    DoublePrefix,
}
