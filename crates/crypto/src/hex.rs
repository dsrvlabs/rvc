//! Hex prefix utilities for consistent `0x` handling across the codebase.
//!
//! # Overview
//!
//! Multiple call sites historically used different idioms to strip a `0x`
//! prefix from hex strings (`trim_start_matches`, `strip_prefix`, mixed
//! forms).  [`strip_prefix_strict`] replaces all of them with a single
//! well-specified rule: strip **at most one** leading `0x`/`0X`; reject any
//! input that carries the prefix twice.
//!
//! # Examples
//!
//! ```
//! use rvc_crypto::hex::{strip_prefix_strict, HexError};
//!
//! assert_eq!(strip_prefix_strict("0xabcd"), Ok("abcd"));
//! assert_eq!(strip_prefix_strict("0Xabcd"), Ok("abcd"));
//! assert_eq!(strip_prefix_strict("abcd"),   Ok("abcd"));
//! assert!(matches!(
//!     strip_prefix_strict("0x0xabcd"),
//!     Err(HexError::DoubleZeroXPrefix)
//! ));
//! ```

use thiserror::Error;

/// Error type for hex-prefix operations.
#[derive(Error, Debug, PartialEq)]
pub enum HexError {
    /// The input carries a `0x`/`0X` prefix more than once (e.g. `0x0x…`).
    #[error("hex string has a double `0x` prefix")]
    DoubleZeroXPrefix,
}

/// Strip exactly one leading `0x` or `0X` prefix from `input`.
///
/// | Input form        | Result                     |
/// |-------------------|----------------------------|
/// | `"0xABCD"`        | `Ok("ABCD")`               |
/// | `"0XABCD"`        | `Ok("ABCD")`               |
/// | `"ABCD"`          | `Ok("ABCD")`               |
/// | `"0x0xABCD"`      | `Err(DoubleZeroXPrefix)`   |
/// | `"0X0XABCD"`      | `Err(DoubleZeroXPrefix)`   |
/// | `""`              | `Ok("")`                   |
///
/// The content of the string (case, encoding) is not validated or changed.
/// For canonical pubkey normalization use [`crate::pubkey::CanonicalPubkey`].
///
/// # Errors
///
/// Returns [`HexError::DoubleZeroXPrefix`] when `input` begins with two
/// consecutive `0x`/`0X` markers (in any combination of case).
pub fn strip_prefix_strict(input: &str) -> Result<&str, HexError> {
    if let Some(rest) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
        if rest.starts_with("0x") || rest.starts_with("0X") {
            return Err(HexError::DoubleZeroXPrefix);
        }
        Ok(rest)
    } else {
        Ok(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── unit tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_bare_hex_unchanged() {
        assert_eq!(strip_prefix_strict("abcdef1234567890"), Ok("abcdef1234567890"));
    }

    #[test]
    fn test_lowercase_0x_prefix_stripped() {
        assert_eq!(strip_prefix_strict("0xabcdef"), Ok("abcdef"));
    }

    #[test]
    fn test_uppercase_0x_prefix_stripped() {
        assert_eq!(strip_prefix_strict("0Xabcdef"), Ok("abcdef"));
    }

    #[test]
    fn test_double_lowercase_prefix_rejected() {
        assert_eq!(strip_prefix_strict("0x0xabcdef"), Err(HexError::DoubleZeroXPrefix));
    }

    #[test]
    fn test_double_uppercase_prefix_rejected() {
        assert_eq!(strip_prefix_strict("0X0Xabcdef"), Err(HexError::DoubleZeroXPrefix));
    }

    #[test]
    fn test_empty_string_unchanged() {
        assert_eq!(strip_prefix_strict(""), Ok(""));
    }

    #[test]
    fn test_single_char_zero_unchanged() {
        assert_eq!(strip_prefix_strict("0"), Ok("0"));
    }

    #[test]
    fn test_single_char_x_unchanged() {
        assert_eq!(strip_prefix_strict("x"), Ok("x"));
    }

    #[test]
    fn test_uppercase_content_preserved() {
        // strip_prefix_strict does NOT lowercase — that is CanonicalPubkey's job.
        assert_eq!(strip_prefix_strict("0xABCDEF"), Ok("ABCDEF"));
    }

    // ── property tests ──────────────────────────────────────────────────────

    proptest! {
        /// Identity: for any string that does not start with `0x` or `0X`
        /// the helper returns the string unchanged.
        #[test]
        fn prop_identity_on_no_prefix(s in any::<String>()) {
            prop_assume!(!s.starts_with("0x") && !s.starts_with("0X"));
            prop_assert_eq!(strip_prefix_strict(&s), Ok(s.as_str()));
        }

        /// Idempotence: applying the helper twice yields the same `&str` as
        /// applying it once, for all inputs the helper accepts (non-error).
        #[test]
        fn prop_idempotent_on_accepted_inputs(s in any::<String>()) {
            if let Ok(once) = strip_prefix_strict(&s) {
                let twice = strip_prefix_strict(once)
                    .expect("second application of strip_prefix_strict must succeed");
                prop_assert_eq!(once, twice);
            }
        }
    }
}
