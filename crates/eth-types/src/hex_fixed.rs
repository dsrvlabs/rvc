use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};

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
                let s =
                    s.strip_prefix("0x").ok_or_else(|| D::Error::custom("missing 0x prefix"))?;
                let decoded = hex::decode(s).map_err(D::Error::custom)?;
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
    fn test_bytes_32_hex_deserialize_requires_0x_prefix() {
        let hex = "ab".repeat(32);
        let json = format!(r#"{{"val":"{}"}}"#, hex);
        assert!(serde_json::from_str::<Wrapper32>(&json).is_err());
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
}
