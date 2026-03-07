use std::fmt;

use zeroize::Zeroizing;

use crate::SecretProviderError;

/// Detected format of secret data fetched from a provider.
pub enum SecretDataFormat {
    /// Raw 32-byte BLS secret key decoded from hex.
    RawHex(Zeroizing<[u8; 32]>),
    /// EIP-2335 keystore JSON blob.
    KeystoreJson(String),
}

impl fmt::Debug for SecretDataFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawHex(_) => f.debug_tuple("RawHex").field(&"<redacted>").finish(),
            Self::KeystoreJson(_) => f.debug_tuple("KeystoreJson").field(&"<redacted>").finish(),
        }
    }
}

/// Parse raw bytes from a cloud secret into a detected format.
///
/// Detection order:
/// 1. Try JSON parse — if valid JSON object, return `KeystoreJson`
/// 2. Trim whitespace, strip optional `0x` prefix, try hex decode — if 32 bytes, return `RawHex`
/// 3. Otherwise return `InvalidKeyMaterial`
pub fn parse_secret_data(data: &[u8]) -> Result<SecretDataFormat, SecretProviderError> {
    let text = std::str::from_utf8(data)
        .map_err(|_| SecretProviderError::InvalidKeyMaterial("data is not valid UTF-8".into()))?;

    if text.trim().is_empty() {
        return Err(SecretProviderError::InvalidKeyMaterial("empty input".into()));
    }

    // Try JSON first.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) {
        if value.is_object() {
            return Ok(SecretDataFormat::KeystoreJson(text.trim().to_string()));
        }
    }

    // Try hex decode.
    let trimmed = text.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    let decoded = hex::decode(hex_str).map_err(|e| {
        SecretProviderError::InvalidKeyMaterial(format!(
            "data is neither valid JSON nor valid hex: {e}"
        ))
    })?;

    let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
        SecretProviderError::InvalidKeyMaterial(format!(
            "hex decodes to {} bytes, expected 32",
            v.len()
        ))
    })?;

    Ok(SecretDataFormat::RawHex(Zeroizing::new(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_64_char_hex() {
        let hex = "a".repeat(64);
        let result = parse_secret_data(hex.as_bytes()).unwrap();
        match result {
            SecretDataFormat::RawHex(key) => {
                assert_eq!(key.len(), 32);
                assert!(key.iter().all(|&b| b == 0xaa));
            }
            _ => panic!("expected RawHex"),
        }
    }

    #[test]
    fn test_valid_0x_prefixed_hex() {
        let hex = format!("0x{}", "bb".repeat(32));
        let result = parse_secret_data(hex.as_bytes()).unwrap();
        match result {
            SecretDataFormat::RawHex(key) => {
                assert_eq!(key.len(), 32);
                assert!(key.iter().all(|&b| b == 0xbb));
            }
            _ => panic!("expected RawHex"),
        }
    }

    #[test]
    fn test_valid_keystore_json() {
        let json = r#"{"crypto":{"kdf":{"function":"scrypt"}},"version":4}"#;
        let result = parse_secret_data(json.as_bytes()).unwrap();
        match result {
            SecretDataFormat::KeystoreJson(s) => {
                assert!(s.contains("\"version\":4"));
            }
            _ => panic!("expected KeystoreJson"),
        }
    }

    #[test]
    fn test_invalid_hex_length_63() {
        let hex = "a".repeat(63);
        let err = parse_secret_data(hex.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("invalid"), "got: {err}");
    }

    #[test]
    fn test_non_utf8_bytes() {
        let data = [0xff, 0xfe, 0xfd];
        let err = parse_secret_data(&data).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "got: {err}");
    }

    #[test]
    fn test_random_string() {
        let data = b"hello world this is not hex or json";
        let err = parse_secret_data(data).unwrap_err();
        assert!(err.to_string().contains("neither valid JSON nor valid hex"), "got: {err}");
    }

    #[test]
    fn test_empty_input() {
        let err = parse_secret_data(b"").unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn test_hex_with_whitespace() {
        let hex = format!("  {}  \n", "cc".repeat(32));
        let result = parse_secret_data(hex.as_bytes()).unwrap();
        match result {
            SecretDataFormat::RawHex(key) => {
                assert!(key.iter().all(|&b| b == 0xcc));
            }
            _ => panic!("expected RawHex"),
        }
    }

    #[test]
    fn test_uppercase_hex() {
        let hex = "AB".repeat(32);
        let result = parse_secret_data(hex.as_bytes()).unwrap();
        match result {
            SecretDataFormat::RawHex(key) => {
                assert!(key.iter().all(|&b| b == 0xab));
            }
            _ => panic!("expected RawHex"),
        }
    }
}
