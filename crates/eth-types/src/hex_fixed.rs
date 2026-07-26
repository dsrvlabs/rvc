//! Fixed-length hex serde helpers for Beacon API wire types.
//!
//! # Prefix policy (deliberate per-seam strictness)
//!
//! Unlike [`crate::canonical`]'s typed constructors (which accept bare hex
//! and an optional single `0x`/`0X` prefix), this module **requires** a
//! leading `0x` or `0X` prefix. Bare hex is rejected. That matches the Beacon
//! API contract for hex-encoded roots, pubkeys, and similar fields — it is
//! intentional, not a second decode engine.
//!
//! All prefix-strip and hex-decode work is delegated to
//! [`crate::canonical::pubkey_hex`]; this module only enforces the
//! "prefix required" gate and the fixed length.

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

use crate::canonical::pubkey_hex::{decode_hex, strip_prefix};
use crate::canonical::ParseError;

/// Map a canonical [`ParseError`] into a serde custom error.
fn map_parse_err<E: Error>(err: ParseError) -> E {
    E::custom(err.to_string())
}

macro_rules! bytes_hex_mod {
    ($mod_name:ident, $len:expr) => {
        pub mod $mod_name {
            use super::*;

            const BYTES_LEN: usize = $len;

            pub fn serialize<S>(bytes: &[u8; BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut hex_string = String::with_capacity(2 + BYTES_LEN * 2);
                hex_string.push_str("0x");
                hex_string.push_str(&hex::encode(bytes));
                serializer.serialize_str(&hex_string)
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; BYTES_LEN], D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                // Beacon API: require a 0x/0X prefix (bare hex rejected).
                if !s.starts_with("0x") && !s.starts_with("0X") {
                    return Err(D::Error::custom("missing 0x prefix"));
                }
                let hex = strip_prefix(&s).map_err(map_parse_err)?;
                let decoded = decode_hex(hex).map_err(map_parse_err)?;
                if decoded.len() != BYTES_LEN {
                    return Err(D::Error::custom(format!(
                        "expected {} bytes, got {}",
                        BYTES_LEN,
                        decoded.len()
                    )));
                }
                let mut array = [0u8; BYTES_LEN];
                array.copy_from_slice(&decoded);
                Ok(array)
            }
        }
    };
}

bytes_hex_mod!(bytes_20_hex, 20);
bytes_hex_mod!(bytes_32_hex, 32);
bytes_hex_mod!(bytes_48_hex, 48);
bytes_hex_mod!(bytes_96_hex, 96);

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wrapper32 {
        #[serde(with = "super::bytes_32_hex")]
        val: [u8; 32],
    }

    #[test]
    fn test_bytes_32_hex_serialize_zeros() {
        let w = Wrapper32 { val: [0u8; 32] };
        let json = serde_json::to_string(&w).unwrap();
        let expected = format!("0x{}", "00".repeat(32));
        assert!(json.contains(&expected));
    }

    #[test]
    fn test_bytes_32_hex_serialize_nonzero() {
        let w = Wrapper32 { val: [0xab; 32] };
        let json = serde_json::to_string(&w).unwrap();
        let expected = format!("0x{}", "ab".repeat(32));
        assert!(json.contains(&expected));
    }

    #[test]
    fn test_bytes_32_hex_roundtrip() {
        let original = Wrapper32 { val: [0xcd; 32] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Wrapper32 = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_hex_fixed_still_requires_0x_prefix() {
        let hex = "ab".repeat(32);
        let json = format!(r#"{{"val":"{}"}}"#, hex);
        let err = serde_json::from_str::<Wrapper32>(&json).unwrap_err();
        assert!(
            err.to_string().contains("missing 0x prefix"),
            "bare hex must stay rejected: {err}"
        );
    }

    #[test]
    fn test_bytes_32_hex_deserialize_requires_0x_prefix() {
        let hex = "ab".repeat(32);
        let json = format!(r#"{{"val":"{}"}}"#, hex);
        assert!(serde_json::from_str::<Wrapper32>(&json).is_err());
    }

    #[test]
    fn test_bytes_32_hex_accepts_uppercase_0x_prefix() {
        let hex = format!("0X{}", "ab".repeat(32));
        let json = format!(r#"{{"val":"{}"}}"#, hex);
        let decoded: Wrapper32 = serde_json::from_str(&json).expect("0X prefix accepted");
        assert_eq!(decoded.val, [0xab; 32]);
    }

    #[test]
    fn test_bytes_32_hex_rejects_double_prefix() {
        let hex = format!("0x0x{}", "ab".repeat(32));
        let json = format!(r#"{{"val":"{}"}}"#, hex);
        let err = serde_json::from_str::<Wrapper32>(&json).unwrap_err();
        assert!(
            err.to_string().contains("double 0x prefix"),
            "double prefix must be rejected via canonical: {err}"
        );
    }

    #[test]
    fn test_bytes_32_hex_deserialize_wrong_length() {
        let json = r#"{"val":"0xabcd"}"#;
        assert!(serde_json::from_str::<Wrapper32>(json).is_err());
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wrapper20 {
        #[serde(with = "super::bytes_20_hex")]
        val: [u8; 20],
    }

    #[test]
    fn test_bytes_20_hex_roundtrip() {
        let original = Wrapper20 { val: [0xab; 20] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Wrapper20 = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bytes_20_hex_deserialize_wrong_length() {
        let json = r#"{"val":"0xabcd"}"#;
        assert!(serde_json::from_str::<Wrapper20>(json).is_err());
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wrapper48 {
        #[serde(with = "super::bytes_48_hex")]
        val: [u8; 48],
    }

    #[test]
    fn test_bytes_48_hex_roundtrip() {
        let original = Wrapper48 { val: [0xcd; 48] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Wrapper48 = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bytes_48_hex_deserialize_wrong_length() {
        let json = r#"{"val":"0xabcd"}"#;
        assert!(serde_json::from_str::<Wrapper48>(json).is_err());
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wrapper96 {
        #[serde(with = "super::bytes_96_hex")]
        val: [u8; 96],
    }

    #[test]
    fn test_bytes_96_hex_roundtrip() {
        let original = Wrapper96 { val: [0xef; 96] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Wrapper96 = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bytes_96_hex_deserialize_wrong_length() {
        let json = r#"{"val":"0xabcd"}"#;
        assert!(serde_json::from_str::<Wrapper96>(json).is_err());
    }
}
