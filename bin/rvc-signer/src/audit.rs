use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

/// Structured audit log entry for a signing request.
///
/// Contains only non-sensitive metadata. No key material (secret keys,
/// signing roots, or signatures) is ever included.
pub struct AuditEntry {
    pub timestamp: String,
    pub pubkey_hex: String,
    pub client_cn: String,
    pub backend: String,
    pub result: String,
    pub duration_ms: u64,
}

/// Emit a structured audit log entry.
///
/// Success entries are logged at `info` level; errors at `warn`.
pub fn log_audit(entry: &AuditEntry) {
    if entry.result == "success" {
        tracing::info!(
            audit = true,
            timestamp = %entry.timestamp,
            pubkey = %entry.pubkey_hex,
            client_cn = %entry.client_cn,
            backend = %entry.backend,
            result = %entry.result,
            duration_ms = entry.duration_ms,
            "sign request audit"
        );
    } else {
        tracing::warn!(
            audit = true,
            timestamp = %entry.timestamp,
            pubkey = %entry.pubkey_hex,
            client_cn = %entry.client_cn,
            backend = %entry.backend,
            result = %entry.result,
            duration_ms = entry.duration_ms,
            "sign request audit"
        );
    }
}

/// Extract the Common Name (CN) from the peer's mTLS certificate.
///
/// Returns `"unknown"` if TLS info is not available or the CN cannot be parsed.
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
    // Parse the CN from DER-encoded X.509.
    let der: &[u8] = &certs[0];
    extract_cn_from_der(der).unwrap_or_else(|| "unknown".to_string())
}

/// Extract the CN from a DER-encoded X.509 certificate.
///
/// Searches for the CN OID (2.5.4.3 = `[0x55, 0x04, 0x03]`) and reads
/// the following UTF8String or PrintableString value.
fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // CN OID: 2.5.4.3 encoded as 0x06 0x03 0x55 0x04 0x03
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

    // Find the last occurrence (Subject CN typically appears after Issuer CN)
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

/// Parse a DER length encoding. Returns (length, bytes_consumed).
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first < 0x80 {
        // Short form: length is the byte itself
        Some((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite length — not expected in DER
        None
    } else {
        // Long form: first byte encodes number of length bytes
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

/// Return the current UTC timestamp in RFC 3339 format.
pub fn now_rfc3339() -> String {
    // Use std::time for a simple UTC timestamp without external deps.
    // Format: seconds since epoch (not RFC 3339, but structured and parseable).
    // For proper RFC 3339 we'd need chrono; use a simple ISO-like format instead.
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();

    // Convert epoch seconds to a simple UTC date-time string.
    // This avoids adding chrono as a dependency.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since epoch (1970-01-01).
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_extract_cn_from_der_empty() {
        assert_eq!(extract_cn_from_der(&[]), None);
    }

    #[test]
    fn test_extract_cn_from_der_garbage() {
        assert_eq!(extract_cn_from_der(&[0xFF; 64]), None);
    }

    #[test]
    fn test_extract_cn_from_der_truncated_after_oid() {
        // CN OID bytes then truncated
        let data = [0x06, 0x03, 0x55, 0x04, 0x03];
        assert_eq!(extract_cn_from_der(&data), None);
    }

    #[test]
    fn test_extract_cn_from_der_bad_tag_after_oid() {
        // CN OID bytes then an unexpected tag (SEQUENCE)
        let data = [0x06, 0x03, 0x55, 0x04, 0x03, 0x30, 0x03, b'a', b'b', b'c'];
        assert_eq!(extract_cn_from_der(&data), None);
    }

    #[test]
    fn test_extract_cn_from_der_utf8string() {
        // OID + UTF8String tag (0x0C) + length 3 + "abc"
        let data = [0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x03, b'a', b'b', b'c'];
        assert_eq!(extract_cn_from_der(&data), Some("abc".to_string()));
    }

    #[test]
    fn test_extract_cn_from_der_printable_string() {
        // OID + PrintableString tag (0x13) + length 4 + "test"
        let data = [0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, b't', b'e', b's', b't'];
        assert_eq!(extract_cn_from_der(&data), Some("test".to_string()));
    }

    #[test]
    fn test_parse_der_length_short_form() {
        assert_eq!(parse_der_length(&[0x03]), Some((3, 1)));
        assert_eq!(parse_der_length(&[0x7F]), Some((127, 1)));
        assert_eq!(parse_der_length(&[0x00]), Some((0, 1)));
    }

    #[test]
    fn test_parse_der_length_long_form() {
        // 0x81 0x80 = 128
        assert_eq!(parse_der_length(&[0x81, 0x80]), Some((128, 2)));
        // 0x82 0x01 0x00 = 256
        assert_eq!(parse_der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[test]
    fn test_parse_der_length_empty() {
        assert_eq!(parse_der_length(&[]), None);
    }

    #[test]
    fn test_parse_der_length_indefinite() {
        assert_eq!(parse_der_length(&[0x80]), None);
    }

    #[test]
    fn test_now_rfc3339_format() {
        let ts = now_rfc3339();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        // 1970-01-01
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-01 is day 19723 since epoch
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn test_audit_entry_creation() {
        let entry = AuditEntry {
            timestamp: "2026-03-14T12:00:00Z".to_string(),
            pubkey_hex: "0x0102030405060708".to_string(),
            client_cn: "validator-client.example.com".to_string(),
            backend: "basic".to_string(),
            result: "success".to_string(),
            duration_ms: 42,
        };
        assert_eq!(entry.timestamp, "2026-03-14T12:00:00Z");
        assert_eq!(entry.pubkey_hex, "0x0102030405060708");
        assert_eq!(entry.client_cn, "validator-client.example.com");
        assert_eq!(entry.backend, "basic");
        assert_eq!(entry.result, "success");
        assert_eq!(entry.duration_ms, 42);
    }

    #[test]
    fn test_log_audit_success_does_not_panic() {
        let entry = AuditEntry {
            timestamp: now_rfc3339(),
            pubkey_hex: "0xabcdef".to_string(),
            client_cn: "test-client".to_string(),
            backend: "basic".to_string(),
            result: "success".to_string(),
            duration_ms: 10,
        };
        log_audit(&entry);
    }

    #[test]
    fn test_log_audit_error_does_not_panic() {
        let entry = AuditEntry {
            timestamp: now_rfc3339(),
            pubkey_hex: "0xabcdef".to_string(),
            client_cn: "test-client".to_string(),
            backend: "basic".to_string(),
            result: "key_not_found".to_string(),
            duration_ms: 5,
        };
        log_audit(&entry);
    }

    #[test]
    fn test_extract_client_cn_no_tls_returns_unknown() {
        // A plain request without TLS extensions should return "unknown"
        let request = tonic::Request::new(());
        assert_eq!(extract_client_cn(&request), "unknown");
    }
}
