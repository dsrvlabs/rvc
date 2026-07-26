//! BLS signature hex serde (`0x`-prefixed, 96 bytes).
//!
//! # Prefix policy (deliberate per-seam strictness)
//!
//! Like [`crate::hex_fixed`], this module **requires** a leading `0x`/`0X`
//! prefix (Beacon API wire contract). Bare hex is rejected. Prefix-strip and
//! hex-decode are delegated to [`crate::canonical::pubkey_hex`].

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

use crate::canonical::pubkey_hex::{decode_hex, strip_prefix};
use crate::canonical::ParseError;
use crate::SIGNATURE_BYTES_LEN;

pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex_string = String::with_capacity(2 + bytes.len() * 2);
    hex_string.push_str("0x");
    hex_string.push_str(&hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // Beacon API: require a 0x/0X prefix (bare hex rejected).
    if !s.starts_with("0x") && !s.starts_with("0X") {
        return Err(D::Error::custom("missing 0x prefix"));
    }
    let hex = strip_prefix(&s).map_err(|e: ParseError| D::Error::custom(e.to_string()))?;
    let decoded = decode_hex(hex).map_err(|e: ParseError| D::Error::custom(e.to_string()))?;
    if decoded.len() != SIGNATURE_BYTES_LEN {
        return Err(D::Error::custom(format!(
            "invalid signature length: expected {} bytes, got {}",
            SIGNATURE_BYTES_LEN,
            decoded.len()
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct SigWrapper {
        #[serde(with = "super")]
        sig: Vec<u8>,
    }

    #[test]
    fn test_signature_roundtrip_96_bytes() {
        let w = SigWrapper { sig: vec![0xaa; 96] };
        let json = serde_json::to_string(&w).unwrap();
        let decoded: SigWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(w, decoded);
    }

    #[test]
    fn test_signature_rejects_95_bytes() {
        let hex = format!("0x{}", "aa".repeat(95));
        let json = format!(r#"{{"sig":"{}"}}"#, hex);
        let err = serde_json::from_str::<SigWrapper>(&json).unwrap_err();
        assert!(err.to_string().contains("expected 96 bytes"));
    }

    #[test]
    fn test_signature_rejects_97_bytes() {
        let hex = format!("0x{}", "aa".repeat(97));
        let json = format!(r#"{{"sig":"{}"}}"#, hex);
        let err = serde_json::from_str::<SigWrapper>(&json).unwrap_err();
        assert!(err.to_string().contains("expected 96 bytes"));
    }

    #[test]
    fn test_signature_rejects_empty() {
        let json = r#"{"sig":"0x"}"#;
        let err = serde_json::from_str::<SigWrapper>(json).unwrap_err();
        assert!(err.to_string().contains("expected 96 bytes"));
    }

    #[test]
    fn test_signature_rejects_missing_0x_prefix() {
        let hex = "aa".repeat(96);
        let json = format!(r#"{{"sig":"{}"}}"#, hex);
        assert!(serde_json::from_str::<SigWrapper>(&json).is_err());
    }

    #[test]
    fn test_serde_signature_delegates_and_length_check_unchanged() {
        // Happy path still works with lowercase 0x.
        let hex = format!("0x{}", "aa".repeat(96));
        let json = format!(r#"{{"sig":"{}"}}"#, hex);
        let decoded: SigWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sig, vec![0xaa; 96]);

        // 0X prefix accepted via canonical strip_prefix.
        let hex_upper = format!("0X{}", "bb".repeat(96));
        let json_upper = format!(r#"{{"sig":"{}"}}"#, hex_upper);
        let decoded_upper: SigWrapper = serde_json::from_str(&json_upper).unwrap();
        assert_eq!(decoded_upper.sig, vec![0xbb; 96]);

        // Length check message shape preserved.
        let short = format!("0x{}", "aa".repeat(95));
        let json_short = format!(r#"{{"sig":"{}"}}"#, short);
        let err = serde_json::from_str::<SigWrapper>(&json_short).unwrap_err();
        assert!(err.to_string().contains("expected 96 bytes"));
    }
}
