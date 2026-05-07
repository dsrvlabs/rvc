//! Canonical public key representation for consistent cross-crate pubkey handling.
//!
//! # Overview
//!
//! Different crates historically produced different canonical forms for the same
//! BLS public key (bare lowercase vs. `0x`-prefixed lowercase), causing silent
//! lookup misses when keys were used as map or database keys across crate
//! boundaries.  [`CanonicalPubkey`] fixes this by defining a single canonical
//! form: **`0x`-prefixed, lowercase hex**.
//!
//! # Examples
//!
//! ```
//! use rvc_crypto::pubkey::CanonicalPubkey;
//!
//! let a: CanonicalPubkey = "0xABCD".parse().unwrap();
//! let b: CanonicalPubkey = "abcd".parse().unwrap();
//! let c: CanonicalPubkey = "0XABCD".parse().unwrap();
//! assert_eq!(a, b);
//! assert_eq!(b, c);
//! assert_eq!(a.to_string(), "0xabcd");
//! ```

use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

/// A public key normalized to `0x`-prefixed lowercase hex.
///
/// Construct via [`str::parse`] (i.e., `s.parse::<CanonicalPubkey>()`).
/// Two `CanonicalPubkey` values are equal if and only if their underlying hex
/// digits are identical (case-insensitive on input; always lowercase in
/// storage).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalPubkey(String);

impl FromStr for CanonicalPubkey {
    type Err = Infallible;

    /// Normalise `s` to `0x`-prefixed lowercase hex.
    ///
    /// Strips at most one leading `0x` or `0X` prefix, converts the remaining
    /// hex digits to lowercase, and prepends `0x`.  The conversion is
    /// infallible; any string is accepted.
    ///
    /// # Examples
    ///
    /// ```
    /// use rvc_crypto::pubkey::CanonicalPubkey;
    ///
    /// let pk: CanonicalPubkey = "0XDeAdBeEf".parse().unwrap();
    /// assert_eq!(pk.to_string(), "0xdeadbeef");
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        Ok(Self(format!("0x{}", stripped.to_lowercase())))
    }
}

impl fmt::Display for CanonicalPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CanonicalPubkey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn parse(s: &str) -> CanonicalPubkey {
        s.parse().expect("infallible")
    }

    /// Assert that `input` collapses to `expected` canonical form.
    fn assert_canonical(input: &str, expected: &str) {
        assert_eq!(parse(input).to_string(), expected);
    }

    // ── unit tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_prefixed_lowercase_unchanged() {
        assert_canonical("0xabcdef012345", "0xabcdef012345");
    }

    #[test]
    fn test_prefixed_uppercase_lowercased() {
        assert_canonical("0xABCDEF012345", "0xabcdef012345");
    }

    #[test]
    fn test_bare_lowercase_gets_prefix() {
        assert_canonical("abcdef012345", "0xabcdef012345");
    }

    #[test]
    fn test_bare_uppercase_lowercased_and_prefixed() {
        assert_canonical("ABCDEF012345", "0xabcdef012345");
    }

    #[test]
    fn test_uppercase_0x_prefix() {
        assert_canonical("0XABCDEF012345", "0xabcdef012345");
    }

    #[test]
    fn test_mixed_case_with_prefix() {
        assert_canonical("0xAbCdEf012345", "0xabcdef012345");
    }

    #[test]
    fn test_already_canonical_is_identity() {
        let canonical = "0xabcdef012345";
        assert_canonical(canonical, canonical);
    }

    #[test]
    fn test_equality_across_representations() {
        let a = parse("0xABCDEF");
        let b = parse("abcdef");
        let c = parse("0Xabcdef");
        let d = parse("ABCDEF");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(c, d);
    }

    #[test]
    fn test_display_matches_as_ref() {
        let pk = parse("0xDeAdBeEf");
        assert_eq!(pk.to_string(), pk.as_ref());
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashMap;
        let mut map: HashMap<CanonicalPubkey, u32> = HashMap::new();
        let key = parse("0xdeadbeef");
        map.insert(key.clone(), 42);
        // An equivalent key produced from a different input form must map to
        // the same slot.
        let key2 = parse("DEADBEEF");
        assert_eq!(map.get(&key2), Some(&42));
    }

    // ── property tests ──────────────────────────────────────────────────────

    /// Generate hex strings of exactly 96 hex characters (BLS pubkey length).
    fn hex96() -> impl Strategy<Value = String> {
        proptest::string::string_regex("[0-9a-fA-F]{96}").unwrap()
    }

    proptest! {
        /// Idempotence: applying `parse` twice yields the same result as once.
        #[test]
        fn prop_idempotent_bare(s in hex96()) {
            let once = parse(&s);
            let twice = parse(&once.to_string());
            prop_assert_eq!(once, twice);
        }

        /// Idempotence holds when input already carries a `0x` prefix.
        #[test]
        fn prop_idempotent_prefixed(s in hex96()) {
            let prefixed = format!("0x{s}");
            let once = parse(&prefixed);
            let twice = parse(&once.to_string());
            prop_assert_eq!(once, twice);
        }

        /// Idempotence holds when input carries an upper-case `0X` prefix.
        #[test]
        fn prop_idempotent_uppercase_prefix(s in hex96()) {
            let prefixed = format!("0X{s}");
            let once = parse(&prefixed);
            let twice = parse(&once.to_string());
            prop_assert_eq!(once, twice);
        }
    }
}
