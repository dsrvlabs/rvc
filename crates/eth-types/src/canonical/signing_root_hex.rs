//! [`SigningRootHex`] — a validated signing root parsed from hex.

use super::{
    pubkey_hex::{decode_hex, strip_prefix},
    ParseError,
};

/// A validated signing root stored as raw bytes.
///
/// Construct via [`parse_signing_root_hex`].
///
/// # Derives
/// `Clone`, `PartialEq`, `Eq`, `Hash` — no `Copy` to stay consistent with
/// the `Root` usage convention in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SigningRootHex([u8; 32]);

impl SigningRootHex {
    /// Returns the underlying 32-byte signing root.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Parse a signing root from a hex string.
///
/// Accepts a bare 64-character hex string or a `0x`-prefixed one.
/// Rejects double `0x0x` prefix, odd-length hex, non-hex characters,
/// and any decoded byte length other than 32.
///
/// # Errors
/// Returns [`ParseError::DoublePrefix`] for a `0x0x…` input, [`ParseError::InvalidHex`]
/// for non-hex or odd-length input, and [`ParseError::InvalidLength`] when the
/// decoded byte count is not 32.
///
/// # Examples
/// ```
/// use rvc_eth_types::canonical::signing_root_hex::parse_signing_root_hex;
/// let sr = parse_signing_root_hex(&format!("0x{}", "de".repeat(32))).unwrap();
/// assert_eq!(sr.as_bytes(), &[0xdeu8; 32]);
/// ```
pub fn parse_signing_root_hex(s: &str) -> Result<SigningRootHex, ParseError> {
    let hex = strip_prefix(s)?;
    let bytes = decode_hex(hex)?;
    if bytes.len() != 32 {
        return Err(ParseError::InvalidLength { expected: 32, got: bytes.len() });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningRootHex(arr))
}
