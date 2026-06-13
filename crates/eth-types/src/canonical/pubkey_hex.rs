//! [`PubkeyHex`] — a validated BLS public key parsed from hex.

use super::ParseError;

/// A validated BLS public key stored as raw bytes.
///
/// Construct via [`parse_pubkey_hex`]. Newtypes around `[u8; 48]` so callers
/// receive bytes directly without re-parsing.
///
/// # Derives
/// `Clone`, `PartialEq`, `Eq`, `Hash` — no `Copy` to stay consistent with
/// the `Root` usage convention in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PubkeyHex([u8; 48]);

impl PubkeyHex {
    /// Returns the underlying 48-byte public key.
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

/// Parse a BLS public key from a hex string.
///
/// Accepts a bare 96-character hex string or a `0x`-prefixed one.
/// Rejects a double `0x0x` prefix, odd-length hex, non-hex characters,
/// and any decoded byte length other than 48.
///
/// # Errors
/// Returns [`ParseError::DoublePrefix`] for a `0x0x…` input, [`ParseError::InvalidHex`]
/// for non-hex or odd-length input, and [`ParseError::InvalidLength`] when the
/// decoded byte count is not 48.
///
/// # Examples
/// ```
/// use rvc_eth_types::canonical::pubkey_hex::parse_pubkey_hex;
/// let pk = parse_pubkey_hex(&format!("0x{}", "ab".repeat(48))).unwrap();
/// assert_eq!(pk.as_bytes(), &[0xabu8; 48]);
/// ```
pub fn parse_pubkey_hex(s: &str) -> Result<PubkeyHex, ParseError> {
    let hex = strip_prefix(s)?;
    let bytes = decode_hex(hex)?;
    if bytes.len() != 48 {
        return Err(ParseError::InvalidLength { expected: 48, got: bytes.len() });
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(PubkeyHex(arr))
}

/// Strip a single optional `0x` prefix, rejecting a double `0x0x` prefix.
pub(super) fn strip_prefix(s: &str) -> Result<&str, ParseError> {
    if let Some(rest) = s.strip_prefix("0x") {
        if rest.starts_with("0x") {
            return Err(ParseError::DoublePrefix);
        }
        Ok(rest)
    } else {
        Ok(s)
    }
}

/// Decode a hex string (no prefix) into bytes, returning `InvalidHex` on failure.
pub(super) fn decode_hex(hex: &str) -> Result<Vec<u8>, ParseError> {
    hex::decode(hex).map_err(|e| ParseError::InvalidHex(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_prefix_no_prefix() {
        assert_eq!(strip_prefix("abcd").unwrap(), "abcd");
    }

    #[test]
    fn test_strip_prefix_single() {
        assert_eq!(strip_prefix("0xabcd").unwrap(), "abcd");
    }

    #[test]
    fn test_strip_prefix_double_rejected() {
        assert!(matches!(strip_prefix("0x0xabcd"), Err(ParseError::DoublePrefix)));
    }
}
