//! mTLS client Common Name (CN) extraction — M-4 (ISSUE-3.4).
//!
//! This module extracts the Common Name from a peer's mTLS certificate using
//! the `x509-parser` crate.  The previous hand-rolled DER scanner returned the
//! **last** CN OID match, which allowed a crafted certificate with multiple CN
//! RDN entries (e.g. `CN=peer-A, CN=admin`) to be logged as `admin`.
//!
//! The `x509-parser`-based implementation returns the **first** CN match per
//! RDN rules — the standard-compliant behaviour.

use x509_parser::prelude::{FromDer, X509Certificate};

use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

/// Extract the Common Name (CN) from the peer's mTLS certificate.
///
/// Returns `"unknown"` if TLS info is not available, the peer has no
/// certificate, or no CN can be found in the Subject.
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

    // The first certificate in the chain is the leaf (client) certificate.
    let der: &[u8] = &certs[0];
    extract_cn_from_der(der).unwrap_or_else(|| "unknown".to_string())
}

/// Extract the CN from a DER-encoded X.509 certificate using `x509-parser`.
///
/// Iterates the Subject's RDN sequence in order and returns the string value
/// of the **first** attribute with OID 2.5.4.3 (id-at-commonName).
///
/// Returns `None` if the DER is invalid, the Subject contains no CN, or the
/// CN value cannot be decoded as a UTF-8 / printable string.
pub fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // Parse the full certificate; x509-parser handles all ASN.1 complexity.
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    // OID 2.5.4.3 (id-at-commonName) in raw DER bytes (without tag/length).
    const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03];

    // Iterate RDNs in Subject in the order they appear in the DER SEQUENCE.
    // For each RDN, iterate its attributes.  Return the **first** CN found.
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type().as_bytes() == CN_OID_BYTES {
                if let Ok(val) = attr.as_str() {
                    return Some(val.to_owned());
                }
            }
        }
    }

    None
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
}
