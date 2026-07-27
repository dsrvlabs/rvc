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
/// Accepts a bare 96-character hex string or a single `0x`/`0X`-prefixed one.
/// Rejects a doubled prefix (`0x0x` / `0x0X` / `0X0x` / `0X0X`), odd-length
/// hex, non-hex characters, and any decoded byte length other than 48.
///
/// # Errors
/// Returns [`ParseError::DoublePrefix`] for a doubled `0x`/`0X` prefix,
/// [`ParseError::InvalidHex`] for non-hex or odd-length input, and
/// [`ParseError::InvalidLength`] when the decoded byte count is not 48.
///
/// # Examples
/// ```
/// use rvc_eth_types::canonical::pubkey_hex::parse_pubkey_hex;
/// let pk = parse_pubkey_hex(&format!("0x{}", "ab".repeat(48))).unwrap();
/// assert_eq!(pk.as_bytes(), &[0xabu8; 48]);
/// let pk_upper = parse_pubkey_hex(&format!("0X{}", "ab".repeat(48))).unwrap();
/// assert_eq!(pk_upper.as_bytes(), &[0xabu8; 48]);
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

/// Strip a single optional `0x` or `0X` prefix, rejecting a doubled prefix
/// (`0x0x` / `0x0X` / `0X0x` / `0X0X`) as [`ParseError::DoublePrefix`].
///
/// This is the single prefix-strip engine for `eth-types`. Policy matches
/// `observability::hex::strip_prefix_strict`: at most one leading `0x`/`0X`, mixed
/// case accepted, doubled prefixes rejected.
pub(crate) fn strip_prefix(s: &str) -> Result<&str, ParseError> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if rest.starts_with("0x") || rest.starts_with("0X") {
            return Err(ParseError::DoublePrefix);
        }
        Ok(rest)
    } else {
        Ok(s)
    }
}

/// Decode a hex string (no prefix) into bytes.
///
/// Maps each `hex::FromHexError` variant to a message that omits the raw
/// offending character, preventing latent secret-byte leakage into logs if
/// a secret value were ever misrouted through these parsers.
///
/// This is the single hex-decode engine for `eth-types`.
pub(crate) fn decode_hex(hex: &str) -> Result<Vec<u8>, ParseError> {
    hex::decode(hex).map_err(|e| {
        let msg = match e {
            hex::FromHexError::OddLength => "odd number of hex digits".to_owned(),
            hex::FromHexError::InvalidHexCharacter { index, .. } => {
                format!("non-hex character at index {index}")
            }
            hex::FromHexError::InvalidStringLength => "invalid string length".to_owned(),
        };
        ParseError::InvalidHex(msg)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_prefix_no_prefix() {
        assert_eq!(strip_prefix("abcd").unwrap(), "abcd");
    }

    #[test]
    fn test_strip_prefix_single_lowercase() {
        assert_eq!(strip_prefix("0xabcd").unwrap(), "abcd");
    }

    #[test]
    fn test_strip_prefix_single_uppercase() {
        assert_eq!(strip_prefix("0Xabcd").unwrap(), "abcd");
    }

    #[test]
    fn test_strip_prefix_double_lower_lower_rejected() {
        assert!(matches!(strip_prefix("0x0xabcd"), Err(ParseError::DoublePrefix)));
    }

    #[test]
    fn test_strip_prefix_double_lower_upper_rejected() {
        assert!(matches!(strip_prefix("0x0Xabcd"), Err(ParseError::DoublePrefix)));
    }

    #[test]
    fn test_strip_prefix_double_upper_lower_rejected() {
        assert!(matches!(strip_prefix("0X0xabcd"), Err(ParseError::DoublePrefix)));
    }

    #[test]
    fn test_strip_prefix_double_upper_upper_rejected() {
        assert!(matches!(strip_prefix("0X0Xabcd"), Err(ParseError::DoublePrefix)));
    }

    #[test]
    fn test_decode_hex_odd_length_message_omits_raw_bytes() {
        let err = decode_hex("abc").unwrap_err();
        let ParseError::InvalidHex(msg) = err else { panic!("expected InvalidHex") };
        assert_eq!(msg, "odd number of hex digits");
    }

    #[test]
    fn test_decode_hex_non_hex_char_message_omits_raw_char() {
        let err = decode_hex("zz").unwrap_err();
        let ParseError::InvalidHex(msg) = err else { panic!("expected InvalidHex") };
        // Message contains only the index, not the raw character value.
        assert!(msg.starts_with("non-hex character at index"));
        assert!(!msg.contains('z'));
    }
}
