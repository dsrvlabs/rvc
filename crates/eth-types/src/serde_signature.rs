use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

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
    let s = s.strip_prefix("0x").ok_or_else(|| D::Error::custom("missing 0x prefix"))?;
    let decoded = hex::decode(s).map_err(D::Error::custom)?;
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
}
