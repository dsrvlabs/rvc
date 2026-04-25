//! mTLS client Common Name (CN) extraction.
//!
//! This module houses the legacy hand-rolled DER scanner originally in
//! `bin/rvc-signer/src/audit.rs`.  ISSUE-3.4 (M-4) will swap the implementation
//! to `x509-parser`; the public function signature is kept stable.
//!
//! # Note on last-match semantics
//!
//! The scanner returns the **last** CN OID match found in the DER bytes.
//! This is a known limitation documented here for M-4.  `x509-parser` will
//! return the **first** CN per RDN rules.

use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

/// Extract the Common Name (CN) from the peer's mTLS certificate.
///
/// Returns `"unknown"` if TLS info is not available, the peer has no certificate,
/// or the CN cannot be parsed from the DER encoding.
///
/// The CN is used to namespace slashing-protection records per client
/// (`client_cn` column in the SlashingDb).
pub fn extract_client_cn<T>(request: &tonic::Request<T>) -> String {
    let Some(tls_info) = request.extensions().get::<TlsConnectInfo<TcpConnectInfo>>() else {
        return "unknown".to_string();
    };

    let Some(certs) = tls_info.peer_certs() else {
        return "unknown".to_string();
    };

    if certs.is_empty() {
        return "unknown".to_string();
    }

    // The first certificate is the leaf (client) certificate.
    let der: &[u8] = &certs[0];
    extract_cn_from_der(der).unwrap_or_else(|| "unknown".to_string())
}

/// Extract the CN from a DER-encoded X.509 certificate.
///
/// Searches for the CN OID (2.5.4.3 = `[0x55, 0x04, 0x03]`) and reads
/// the following UTF8String, PrintableString, or IA5String value.
///
/// Returns the **last** occurrence (legacy behavior — not fixed until M-4).
pub(crate) fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // CN OID: 2.5.4.3 encoded as 0x06 0x03 0x55 0x04 0x03
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

    // Find the last occurrence (Subject CN typically appears after Issuer CN).
    // NOTE: M-4 (ISSUE-3.4) will change this to first-match via x509-parser.
    let mut last_pos = None;
    for i in 0..der.len().saturating_sub(cn_oid.len()) {
        if der[i..].starts_with(cn_oid) {
            last_pos = Some(i);
        }
    }

    let pos = last_pos?;
    let after_oid = pos + cn_oid.len();

    if after_oid >= der.len() {
        return None;
    }

    // The value follows: tag byte + length + value
    let tag = der[after_oid];
    // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
    if tag != 0x0C && tag != 0x13 && tag != 0x16 {
        return None;
    }

    let length_pos = after_oid + 1;
    if length_pos >= der.len() {
        return None;
    }

    let (len, value_start) = parse_der_length(&der[length_pos..])?;
    let value_start = length_pos + value_start;

    if value_start + len > der.len() {
        return None;
    }

    String::from_utf8(der[value_start..value_start + len].to_vec()).ok()
}

/// Parse a DER length encoding. Returns `(length, bytes_consumed)`.
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x80 {
        None // Indefinite length — not valid in DER
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || num_bytes + 1 > data.len() {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = len.checked_shl(8)?.checked_add(data[1 + i] as usize)?;
        }
        Some((len, 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_client_cn_no_tls_returns_unknown() {
        let request = tonic::Request::new(());
        assert_eq!(extract_client_cn(&request), "unknown");
    }

    #[test]
    fn test_extract_cn_from_der_empty() {
        assert_eq!(extract_cn_from_der(&[]), None);
    }

    #[test]
    fn test_extract_cn_from_der_garbage() {
        assert_eq!(extract_cn_from_der(&[0xFF; 64]), None);
    }

    #[test]
    fn test_extract_cn_from_der_truncated_after_oid() {
        let data = [0x06, 0x03, 0x55, 0x04, 0x03];
        assert_eq!(extract_cn_from_der(&data), None);
    }

    #[test]
    fn test_extract_cn_from_der_bad_tag_after_oid() {
        let data = [0x06, 0x03, 0x55, 0x04, 0x03, 0x30, 0x03, b'a', b'b', b'c'];
        assert_eq!(extract_cn_from_der(&data), None);
    }

    #[test]
    fn test_extract_cn_from_der_utf8string() {
        let data = [0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x03, b'a', b'b', b'c'];
        assert_eq!(extract_cn_from_der(&data), Some("abc".to_string()));
    }

    #[test]
    fn test_extract_cn_from_der_printable_string() {
        let data = [0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, b't', b'e', b's', b't'];
        assert_eq!(extract_cn_from_der(&data), Some("test".to_string()));
    }

    #[test]
    fn test_extract_cn_from_der_with_known_cert() {
        use rcgen::DnType;

        let mut params =
            rcgen::CertificateParams::new(vec!["test-client.example.com".to_string()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "my-validator-client");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().as_ref();

        let cn = extract_cn_from_der(der);
        assert_eq!(cn, Some("my-validator-client".to_string()));
    }

    #[test]
    fn test_parse_der_length_short_form() {
        assert_eq!(parse_der_length(&[0x03]), Some((3, 1)));
        assert_eq!(parse_der_length(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn test_parse_der_length_long_form() {
        assert_eq!(parse_der_length(&[0x81, 0x80]), Some((128, 2)));
    }

    #[test]
    fn test_parse_der_length_empty() {
        assert_eq!(parse_der_length(&[]), None);
    }

    #[test]
    fn test_parse_der_length_indefinite() {
        assert_eq!(parse_der_length(&[0x80]), None);
    }
}
