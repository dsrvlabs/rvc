//! Bidirectional serde helpers for Web3Signer wire encoding.
//!
//! Merges the client-side (`crypto::remote_signer`) serialize helpers and the
//! server-side (`rvc-signer` `http_api::request`) deserialize helpers into
//! modules usable with `#[serde(with = …)]`.

/// Required `0x`-prefixed 32-byte hex ↔ `[u8; 32]`.
pub mod hex32 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(root: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&format!("0x{}", hex::encode(root)))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut out)
            .map_err(|e| de::Error::custom(format!("invalid 32-byte hex: {e}")))?;
        Ok(out)
    }
}

/// Optional `signingRoot` / `signing_root`.
///
/// - Absent / `null` / empty / `"0x"` → `None` (Prysm sends empty).
/// - Present `0x`-prefixed 32-byte hex → `Some`.
/// - Wrong length or bad hex → error (→ HTTP 400 on the server).
pub mod opt_hex32 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(root: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match root {
            Some(r) => s.serialize_str(&format!("0x{}", hex::encode(r))),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(d)?;
        let Some(s) = opt else {
            return Ok(None);
        };
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        if hex_str.is_empty() {
            return Ok(None);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut out)
            .map_err(|e| de::Error::custom(format!("invalid signingRoot hex: {e}")))?;
        Ok(Some(out))
    }
}

/// Quoted (`"123"`) unsigned integer, matching Beacon API / eth-types convention.
pub mod quoted_u64 {
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &u64, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        s.parse::<u64>().map_err(|e| de::Error::custom(format!("invalid quoted u64: {e}")))
    }
}
