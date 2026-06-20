//! [`GvrHex`] — a validated genesis-validators-root with normalised hex view.

use super::{
    pubkey_hex::{decode_hex, strip_prefix},
    ParseError,
};
use crate::Root;

/// A validated genesis-validators-root that keeps a lowercase-normalised hex
/// representation alongside the raw bytes.
///
/// Construct via [`parse_gvr_hex`] (which returns a [`Root`]) then wrap with
/// [`GvrHex::from_root`] to get the normalised-string view.
///
/// # Derives
/// `Clone`, `PartialEq`, `Eq`, `Hash` — no `Copy` to stay consistent with
/// the `Root` usage convention in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GvrHex {
    bytes: Root,
    normalised: String,
}

impl GvrHex {
    /// Create a `GvrHex` from a raw [`Root`] byte array.
    ///
    /// The normalised hex representation is computed once at construction time.
    pub fn from_root(root: Root) -> Self {
        let normalised = format!("0x{}", hex::encode(root));
        Self { bytes: root, normalised }
    }

    /// Returns the underlying 32-byte root.
    pub fn as_bytes(&self) -> &Root {
        &self.bytes
    }

    /// Returns the lowercase `0x`-prefixed hex representation of the root.
    pub fn as_normalised_hex(&self) -> &str {
        &self.normalised
    }
}

/// Parse a genesis-validators-root from a hex string, returning the raw [`Root`].
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
/// use rvc_eth_types::canonical::gvr_hex::parse_gvr_hex;
/// let root = parse_gvr_hex(&format!("0x{}", "cd".repeat(32))).unwrap();
/// assert_eq!(root, [0xcdu8; 32]);
/// ```
pub fn parse_gvr_hex(s: &str) -> Result<Root, ParseError> {
    let hex = strip_prefix(s)?;
    let bytes = decode_hex(hex)?;
    if bytes.len() != 32 {
        return Err(ParseError::InvalidLength { expected: 32, got: bytes.len() });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Compare a hex-encoded string against a [`Root`] byte array.
///
/// Returns `true` if and only if `hex_str` parses successfully as a 32-byte
/// root and those bytes equal `root`. Returns `false` on any parse error or
/// value mismatch, making this safe to call in security-sensitive comparisons
/// where an invalid input must never be treated as a match.
///
/// # Security note — not constant-time
///
/// This function is **not** constant-time. The genesis-validators-root is a
/// public value so timing leakage is not a concern here, but do **not** use
/// this function to compare secret material (private keys, signing nonces,
/// passwords, etc.).
///
/// # Examples
/// ```
/// use rvc_eth_types::canonical::gvr_hex::eq_gvr;
/// let bytes = [0xabu8; 32];
/// assert!(eq_gvr(&format!("0x{}", "ab".repeat(32)), &bytes));
/// assert!(!eq_gvr("not-hex", &bytes));
/// ```
pub fn eq_gvr(hex_str: &str, root: &Root) -> bool {
    match parse_gvr_hex(hex_str) {
        Ok(parsed) => &parsed == root,
        Err(_) => false,
    }
}
