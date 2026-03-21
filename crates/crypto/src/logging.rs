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
        let hex = self.0.strip_prefix("0x").unwrap_or(self.0);
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
}
