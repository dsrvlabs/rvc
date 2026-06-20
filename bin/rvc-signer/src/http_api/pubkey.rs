//! `{identifier}` path-parameter parsing + the `404` pre-check (FR-18, FR-21).
//!
//! Resolving the identifier is a cheap pre-check on the shared key set: an
//! unknown/unloaded key short-circuits to `404` *before* any signing root is
//! computed or any gate call is made.
//!
//! NOTE: landed ahead of its consumer — the sign handler / dispatcher (Issue
//! 2.6) calls `resolve_identifier`. Until then it is exercised only by this
//! module's tests, hence the transitional `allow(dead_code)`; remove it in 2.6.
#![allow(dead_code)]

use crate::backend::SigningBackend;

/// Why a `{identifier}` could not be resolved to a loaded signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubkeyError {
    /// Not a 48-byte hex pubkey (bad hex, wrong length, or an invalid BLS
    /// point). Maps to HTTP `400`.
    Malformed,
    /// A well-formed pubkey that is not loaded in the backend. Maps to `404`.
    NotLoaded,
}

/// Resolve a `{identifier}` to a loaded BLS public key.
///
/// Per FR-18 the match is case-insensitive on the hex and tolerant of a `0x`
/// prefix (both clients emit `0x`+lowercase, but we parse defensively). The
/// membership check runs on the raw 48 bytes against `backend.public_keys()`, so
/// an unloaded key returns [`PubkeyError::NotLoaded`] (`404`) without parsing a
/// BLS point or touching the gate. A loaded key is then materialized as a
/// [`crypto::PublicKey`] for the dispatcher to hand to the gate.
pub fn resolve_identifier(
    identifier: &str,
    backend: &dyn SigningBackend,
) -> Result<crypto::PublicKey, PubkeyError> {
    let bytes = parse_pubkey_bytes(identifier).ok_or(PubkeyError::Malformed)?;
    // Cheap `404` pre-check on the shared key set — raw bytes, no BLS parse.
    if !backend.public_keys().contains(&bytes) {
        return Err(PubkeyError::NotLoaded);
    }
    // A loaded key is a valid BLS point, so this effectively never fails; a
    // failure still maps to `400` rather than panicking.
    crypto::PublicKey::from_bytes(&bytes).map_err(|_| PubkeyError::Malformed)
}

/// Parse a `{identifier}` into 48 raw bytes: strip an optional `0x`/`0X`,
/// require exactly 96 hex chars, decode (case-insensitive). Returns `None` on
/// any malformation.
fn parse_pubkey_bytes(identifier: &str) -> Option<[u8; 48]> {
    let stripped = identifier
        .strip_prefix("0x")
        .or_else(|| identifier.strip_prefix("0X"))
        .unwrap_or(identifier);
    if stripped.len() != 96 {
        return None;
    }
    let mut out = [0u8; 48];
    // `hex::decode_to_slice` accepts mixed-case hex (FR-18 case-insensitivity).
    hex::decode_to_slice(stripped, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::backend::SigningBackend;
    use crate::http_api::test_support::MockBackend;

    /// Deterministic real BLS pubkey bytes (valid point), via EIP-2333.
    fn real_pubkey(seed_byte: u8) -> [u8; 48] {
        let sk = crypto::eip2333::derive_master_sk(&[seed_byte; 32]).expect("derive sk");
        sk.public_key().to_bytes()
    }

    fn backend_with(keys: Vec<[u8; 48]>) -> Arc<dyn SigningBackend> {
        Arc::new(MockBackend::with_keys(keys))
    }

    #[test]
    fn resolves_loaded_key_in_all_case_and_prefix_forms() {
        let pk = real_pubkey(0x11);
        let backend = backend_with(vec![pk]);
        let lower = hex::encode(pk);
        let upper = lower.to_uppercase();

        for id in [
            format!("0x{lower}"),
            lower.clone(),        // bare, no prefix
            format!("0x{upper}"), // uppercase hex
            format!("0X{lower}"), // uppercase prefix
            format!("0x{}", mixed_case(&lower)),
        ] {
            let resolved = resolve_identifier(&id, backend.as_ref())
                .unwrap_or_else(|e| panic!("{id} should resolve, got {e:?}"));
            assert_eq!(resolved.to_bytes(), pk, "all forms resolve to the same key");
        }
    }

    fn mixed_case(s: &str) -> String {
        s.chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c })
            .collect()
    }

    #[test]
    fn well_formed_but_unloaded_key_is_not_loaded_404() {
        let loaded = real_pubkey(0x11);
        let other = real_pubkey(0x22);
        assert_ne!(loaded, other);
        let backend = backend_with(vec![loaded]);
        let err =
            resolve_identifier(&format!("0x{}", hex::encode(other)), backend.as_ref()).unwrap_err();
        assert_eq!(err, PubkeyError::NotLoaded);
    }

    #[test]
    fn malformed_identifiers_are_400() {
        let backend = backend_with(vec![real_pubkey(0x11)]);
        // non-hex
        assert_eq!(
            resolve_identifier(&format!("0x{}", "zz".repeat(48)), backend.as_ref()).unwrap_err(),
            PubkeyError::Malformed
        );
        // too short (94 hex chars)
        assert_eq!(
            resolve_identifier(&format!("0x{}", "ab".repeat(47)), backend.as_ref()).unwrap_err(),
            PubkeyError::Malformed
        );
        // too long (98 hex chars)
        assert_eq!(
            resolve_identifier(&format!("0x{}", "ab".repeat(49)), backend.as_ref()).unwrap_err(),
            PubkeyError::Malformed
        );
        // empty
        assert_eq!(resolve_identifier("", backend.as_ref()).unwrap_err(), PubkeyError::Malformed);
    }

    #[test]
    fn malformed_is_checked_before_membership() {
        // A malformed identifier is rejected (400) regardless of the key set; the
        // backend's keys are never consulted for a parse failure.
        let backend = backend_with(vec![]);
        assert_eq!(
            resolve_identifier("not-hex", backend.as_ref()).unwrap_err(),
            PubkeyError::Malformed
        );
    }
}
