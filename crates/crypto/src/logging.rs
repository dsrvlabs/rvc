/// Displays a public key hex string as `0x{first10}...{last8}`.
///
/// Implements `Display` for zero-allocation use with tracing's `%` specifier.
/// When tracing level is disabled, `Display::fmt` is never called.
pub struct TruncatedPubkey<'a>(pub &'a str);

impl<'a> TruncatedPubkey<'a> {
    pub fn new(hex: &'a str) -> Self {
        Self(hex)
    }
}

impl std::fmt::Display for TruncatedPubkey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Defense-in-depth: strip at most one `0x`/`0X` prefix.
        // On `DoubleZeroXPrefix` emit a warning and fall back to the raw input
        // as-is so that the log line is not garbled and no panic occurs.
        // Callers should supply canonical pubkeys; this path indicates a bug upstream.
        let hex = match crate::hex::strip_prefix_strict(self.0) {
            Ok(s) => s,
            Err(crate::hex::HexError::DoubleZeroXPrefix) => {
                tracing::warn!(
                    pubkey = self.0,
                    "TruncatedPubkey: double 0x prefix detected, falling back to raw input"
                );
                return write!(f, "{}", self.0);
            }
        };
        if hex.len() > 18 && hex.is_ascii() {
            write!(f, "0x{}...{}", &hex[..10], &hex[hex.len() - 8..])
        } else {
            write!(f, "0x{hex}")
        }
    }
}

/// Displays a URL with username/password replaced by `***`.
///
/// Uses `url::Url::parse` internally. If parsing fails, displays the raw string.
pub struct RedactedUrl<'a>(pub &'a str);

impl std::fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(mut parsed) = url::Url::parse(self.0) {
            if parsed.password().is_some() || !parsed.username().is_empty() {
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            write!(f, "{parsed}")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Displays a 32-byte root / signature / hash as `0x{first10hex}...{last8hex}`.
///
/// Zero-allocation `Display` wrapper for tracing's `%` specifier: the hex is written
/// byte-by-byte directly into the `Formatter` (no `hex::encode` / `format!` / `to_string`),
/// so nothing is heap-allocated and `fmt` only runs when the log level is enabled. This is
/// the sanctioned way to render a block / head / signing root, hash, or signature in a log
/// line (ADR-005); a full root or signature is never logged.
///
/// Wraps a **non-secret** root / signature only — a `Display` impl is never added to a
/// secret type.
///
/// Inputs shorter than 9 bytes render their full lower-hex (`0x{all-bytes}`) instead of
/// slicing out of bounds, and `fmt` never panics.
pub struct TruncatedRoot<'a>(pub &'a [u8]);

impl<'a> TruncatedRoot<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for TruncatedRoot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        f.write_str("0x")?;
        // Short input (< 9 bytes): the 5 leading + 4 trailing slices would overlap, so
        // render the full lower-hex rather than slice out of bounds. Never panics.
        if bytes.len() < 9 {
            for b in bytes {
                write!(f, "{b:02x}")?;
            }
            return Ok(());
        }
        // 5 leading bytes (10 hex chars) + "..." + 4 trailing bytes (8 hex chars).
        // Written byte-by-byte: zero heap allocation, and lazy under `%`.
        for b in &bytes[..5] {
            write!(f, "{b:02x}")?;
        }
        f.write_str("...")?;
        for b in &bytes[bytes.len() - 4..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TruncatedPubkey tests ---

    #[test]
    fn test_truncated_pubkey_long_with_prefix() {
        let pubkey = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        assert_eq!(result, "0x93247f2209...611df74a");
    }

    #[test]
    fn test_truncated_pubkey_long_without_prefix() {
        let pubkey = "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        assert_eq!(result, "0x93247f2209...611df74a");
    }

    #[test]
    fn test_truncated_pubkey_short_with_prefix() {
        let result = TruncatedPubkey::new("0xabcdef").to_string();
        assert_eq!(result, "0xabcdef");
    }

    #[test]
    fn test_truncated_pubkey_short_without_prefix() {
        let result = TruncatedPubkey::new("abcdef").to_string();
        assert_eq!(result, "0xabcdef");
    }

    #[test]
    fn test_truncated_pubkey_exactly_18_chars() {
        let result = TruncatedPubkey::new("0x123456789012345678").to_string();
        assert_eq!(result, "0x123456789012345678");
    }

    #[test]
    fn test_truncated_pubkey_19_chars_truncated() {
        let result = TruncatedPubkey::new("0x1234567890123456789").to_string();
        assert_eq!(result, "0x1234567890...23456789");
    }

    #[test]
    fn test_truncated_pubkey_empty() {
        let result = TruncatedPubkey::new("").to_string();
        assert_eq!(result, "0x");
    }

    #[test]
    fn test_truncated_pubkey_non_ascii_falls_back() {
        let input = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74à";
        let result = TruncatedPubkey::new(input).to_string();
        assert_eq!(result, "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74à");
    }

    // -- CQ-2.5: strip_prefix_strict adoption test --

    /// TruncatedPubkey must warn and fall back to the raw input when given a double-0x prefix.
    /// Behavior: no panic, the raw string is emitted as-is, and a warn! log fires.
    #[test]
    #[tracing_test::traced_test]
    fn test_truncated_pubkey_double_0x_prefix_warns_and_falls_back() {
        let pubkey = "0x0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        // Must not panic; raw input is emitted as-is
        assert_eq!(result, pubkey, "double-0x input must be returned verbatim");
        assert!(logs_contain("double 0x prefix"), "expected warn log about double prefix");
    }

    // --- RedactedUrl tests ---

    #[test]
    fn test_redacted_url_with_credentials() {
        let url = "http://user:pass@example.com/path";
        let result = RedactedUrl(url).to_string();
        assert!(result.contains("***:***@"));
        assert!(result.contains("example.com/path"));
    }

    #[test]
    fn test_redacted_url_without_credentials() {
        let url = "http://example.com/path";
        let result = RedactedUrl(url).to_string();
        assert_eq!(result, "http://example.com/path");
    }

    #[test]
    fn test_redacted_url_invalid() {
        let url = "not a url";
        let result = RedactedUrl(url).to_string();
        assert_eq!(result, "not a url");
    }

    #[test]
    fn test_redacted_url_username_only() {
        let url = "http://user@example.com/path";
        let result = RedactedUrl(url).to_string();
        assert!(result.contains("***"));
        assert!(!result.contains("user@"));
    }

    // --- TruncatedRoot tests ---

    #[test]
    fn test_truncated_root_32_bytes() {
        let result = TruncatedRoot::new(&[0xab; 32]).to_string();
        assert_eq!(result, "0xababababab...abababab");
        // 0x (2) + 10 leading hex + "..." (3) + 8 trailing hex = 23 chars.
        // NOTE: Issue 1.2's acceptance text "exactly 22" is a miscount of this same
        // breakdown (0x + 10 + ... + 8 = 23); the canonical rendering is 23 chars.
        assert_eq!(result.len(), 23);
    }

    #[test]
    fn test_truncated_root_distinct_bytes() {
        // 0x00,0x01,...,0x1f — first 5 bytes -> 0001020304, last 4 -> 1c1d1e1f.
        let root: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(TruncatedRoot::new(&root).to_string(), "0x0001020304...1c1d1e1f");
    }

    /// Redaction (Gate-3 style): the FULL hex of a 32-byte root MUST be absent from a
    /// `trace`-level log line that renders it via `%TruncatedRoot`; only the truncated
    /// form appears.
    #[test]
    #[tracing_test::traced_test]
    fn test_truncated_root_full_hex_absent_at_trace() {
        let root: [u8; 32] = std::array::from_fn(|i| i as u8);
        tracing::trace!(root = %TruncatedRoot::new(&root), "computed signing root");
        let full_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert!(logs_contain("0x0001020304...1c1d1e1f"), "truncated form must be present");
        assert!(!logs_contain(full_hex), "full 32-byte hex must NOT appear");
        // A middle slice that exists only in the full encoding must be absent too.
        assert!(!logs_contain("0a0b0c0d"), "middle bytes must be truncated away");
    }

    #[test]
    fn test_truncated_root_empty_no_panic() {
        assert_eq!(TruncatedRoot::new(&[]).to_string(), "0x");
    }

    #[test]
    fn test_truncated_root_one_byte() {
        assert_eq!(TruncatedRoot::new(&[0xab]).to_string(), "0xab");
    }

    #[test]
    fn test_truncated_root_eight_bytes_full() {
        // 8 bytes (< 9): full lower-hex, not truncated.
        assert_eq!(TruncatedRoot::new(&[0xab; 8]).to_string(), "0xabababababababab");
    }

    #[test]
    fn test_truncated_root_nine_bytes_truncates() {
        // 9 bytes is the threshold: 5 leading + 4 trailing exactly cover it, no overlap.
        let bytes: [u8; 9] = std::array::from_fn(|i| i as u8);
        assert_eq!(TruncatedRoot::new(&bytes).to_string(), "0x0001020304...05060708");
    }
}
