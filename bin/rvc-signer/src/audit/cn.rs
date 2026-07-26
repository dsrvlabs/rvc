//! mTLS client Common Name (CN) extraction — M-4 (ISSUE-3.4).
//!
//! This module extracts the Common Name from a peer's mTLS certificate using
//! the `x509-parser` crate.  The previous hand-rolled DER scanner returned the
//! **last** CN OID match, which allowed a crafted certificate with multiple CN
//! RDN entries (e.g. `CN=peer-A, CN=admin`) to be logged as `admin`.
//!
//! The `x509-parser`-based implementation returns the **first** CN match per
//! RDN rules — the standard-compliant behaviour.
//!
//! # Primary signer CN allow-list (SEC-4)
//!
//! [`ClientCnAllowList`] is the optional authorization layer for the primary
//! (non-DVT) signer.  It reuses the DVT allow-list's exact, case-sensitive CN
//! match semantics (`lookup_by_cn` / `contains_cn`); when configured, CNs that
//! are not listed — including the `"unknown"` fallback from
//! [`extract_client_cn`] — are rejected before any signing logic runs. mTLS
//! remains mandatory.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::Status;
use x509_parser::prelude::{FromDer, X509Certificate};

// ─────────────────────────────────────────────────────────────────────────────
// Client CN allow-list (SEC-4)
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by the primary client-CN allow-list loader.
#[derive(Debug, Error)]
pub enum ClientAllowListError {
    /// The file could not be read (missing, permissions, etc.).
    #[error("failed to read client-CN allow-list at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The TOML content could not be parsed.
    #[error("failed to parse client-CN allow-list: {0}")]
    Parse(#[from] toml::de::Error),

    /// The file was parsed successfully but the `[[client]]` list is empty.
    #[error("client-CN allow-list must contain at least one [[client]] entry")]
    Empty,
}

/// A single entry in the primary client-CN allow-list file.
///
/// # File format
///
/// ```toml
/// [[client]]
/// client_cn = "validator-client-1.local"
///
/// [[client]]
/// client_cn = "validator-client-2.local"
/// ```
///
/// Matches mirror the DVT `[[peer]] peer_cn = ...` pattern (exact,
/// case-sensitive string equality).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AllowedClient {
    /// The mTLS Common Name of an authorized client.
    pub client_cn: String,
}

#[derive(Debug, Deserialize)]
struct ClientCnAllowListRaw {
    #[serde(rename = "client", default)]
    clients: Vec<AllowedClient>,
}

/// Parsed primary-signer client-CN allow-list (SEC-4).
///
/// When present on [`crate::service::SignerServiceImpl`], only listed CNs may
/// invoke signing RPCs. Absence is backward-compatible (startup warns; all
/// mTLS clients are accepted).
#[derive(Debug, Clone)]
pub struct ClientCnAllowList {
    cns: HashSet<String>,
}

impl ClientCnAllowList {
    /// Build an allow-list from an iterator of CN strings (tests / in-process).
    pub fn from_cns(cns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { cns: cns.into_iter().map(Into::into).collect() }
    }

    /// Load and parse the allow-list from `path`.
    ///
    /// # Errors
    ///
    /// - [`ClientAllowListError::Io`] — file cannot be read.
    /// - [`ClientAllowListError::Parse`] — TOML syntax error or wrong schema.
    /// - [`ClientAllowListError::Empty`] — the `[[client]]` list has zero entries.
    pub fn load_from_path(path: &Path) -> Result<Self, ClientAllowListError> {
        let content = std::fs::read_to_string(path).map_err(|source| ClientAllowListError::Io {
            path: path.display().to_string(),
            source,
        })?;

        let raw: ClientCnAllowListRaw = toml::from_str(&content)?;
        if raw.clients.is_empty() {
            return Err(ClientAllowListError::Empty);
        }

        Ok(Self::from_cns(raw.clients.into_iter().map(|c| c.client_cn)))
    }

    /// Exact, case-sensitive CN membership check (same rule as DVT `lookup_by_cn`).
    pub fn contains(&self, client_cn: &str) -> bool {
        self.cns.contains(client_cn)
    }

    /// Number of allowed CNs.
    pub fn len(&self) -> usize {
        self.cns.len()
    }

    /// True when no CNs are listed (should not occur after a successful load).
    pub fn is_empty(&self) -> bool {
        self.cns.is_empty()
    }
}

/// Authorize `client_cn` against an optional primary-signer allow-list (SEC-4).
///
/// - `None` allow-list → accept (backward compatible; caller logs startup warn).
/// - `Some` allow-list → accept only listed CNs; `"unknown"` is never special-
///   cased and is rejected unless explicitly listed.
///
/// Returns [`Status::unauthenticated`] when the CN is not listed — matching the
/// DVT `authenticate_peer` status for an unlisted CN.
#[allow(clippy::result_large_err)]
pub fn authorize_client_cn(
    allow_list: Option<&ClientCnAllowList>,
    client_cn: &str,
) -> Result<(), Status> {
    let Some(list) = allow_list else {
        return Ok(());
    };
    if list.contains(client_cn) {
        return Ok(());
    }
    Err(Status::unauthenticated(format!("client CN '{client_cn}' is not on the allow-list")))
}

/// Loud startup warning when the primary path has no client-CN allow-list (SEC-4).
///
/// Extracted so unit tests can assert the warning without driving `run_serve`.
pub fn log_missing_client_cn_allow_list_warning() {
    tracing::warn!(
        "No client-CN allow-list configured (--allowed-client-cns): any mTLS \
         client presenting a CA-issued certificate can request signatures for \
         any loaded key. Configure a client-CN allow-list for production (SEC-4)."
    );
}

/// Extract the Common Name (CN) from the peer's mTLS certificate.
///
/// Returns `"unknown"` if TLS info is not available, the peer has no
/// certificate, or no CN can be found in the Subject.
///
/// The CN is used to namespace slashing-protection records per client
/// (`client_cn` column in the SlashingDb). When a primary client-CN allow-list
/// is configured, `"unknown"` is rejected like any other unlisted CN (SEC-4).
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
    extract_cn_from_der(der).unwrap_or_else(|| {
        // Operators must be able to detect misconfigured certs that fall back
        // to the shared "unknown" namespace — co-mingling slashing-protection
        // records is a serious safety issue.
        tracing::warn!(
            "TLS client certificate has no parseable CN; using 'unknown' \
             namespace — slashing-protection records will be co-mingled with \
             other unparseable-CN clients"
        );
        "unknown".to_string()
    })
}

/// Derive the audit CN for a request from an optional leaf client-certificate
/// DER (Issue 3.4, FR-33 CN portion, R9).
///
/// Reuses [`extract_cn_from_der`] (first-CN-wins — identical CN semantics to the
/// gRPC path) and degrades to `default` (`signer::AUDIT_CN_DEFAULT`) when there
/// is no client cert (Prysm / server-TLS-only) or the leaf carries no parseable
/// CN.
///
/// When no primary client-CN allow-list is configured, the CN remains audit-only
/// (a missing CN still signs). When `--allowed-client-cns` is set (SEC-4), the
/// sign handler authorizes this CN against the shared list before any signing
/// work — including the default fallback CN.
///
/// Moved here from the former `http_api::tls` grab-bag (RF5-22) so CN extraction
/// lives next to the rest of the audit CN helpers.
pub fn audit_cn(leaf_der: Option<&[u8]>, default: &str) -> String {
    leaf_der.and_then(extract_cn_from_der).unwrap_or_else(|| default.to_string())
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
    use std::io::Write;

    use super::*;

    fn write_toml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

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

    /// A self-signed leaf carrying CN = `cn` (or no CN when `None`), as DER.
    fn self_signed_with_cn(cn: Option<&str>) -> Vec<u8> {
        use rcgen::DnType;

        let mut params = rcgen::CertificateParams::new(vec!["host.example".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        if let Some(cn) = cn {
            params.distinguished_name.push(DnType::CommonName, cn);
        }
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().as_ref().to_vec()
    }

    #[test]
    fn audit_cn_reads_the_leaf_common_name() {
        let der = self_signed_with_cn(Some("lighthouse-vc-1"));
        assert_eq!(audit_cn(Some(&der), "signing-gate"), "lighthouse-vc-1");
    }

    #[test]
    fn audit_cn_none_falls_back_to_default() {
        assert_eq!(audit_cn(None, "signing-gate"), "signing-gate");
    }

    #[test]
    fn audit_cn_cert_without_cn_falls_back_to_default() {
        let der = self_signed_with_cn(None);
        assert_eq!(audit_cn(Some(&der), "signing-gate"), "signing-gate");
    }

    // ── SEC-4: ClientCnAllowList ──────────────────────────────────────────────

    #[test]
    fn test_client_allow_list_load_happy_path() {
        let f = write_toml(
            r#"
[[client]]
client_cn = "vc-A"

[[client]]
client_cn = "vc-B"
"#,
        );
        let list = ClientCnAllowList::load_from_path(f.path()).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains("vc-A"));
        assert!(list.contains("vc-B"));
        assert!(!list.contains("vc-X"));
    }

    #[test]
    fn test_client_allow_list_empty_is_error() {
        let f = write_toml("");
        let err = ClientCnAllowList::load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, ClientAllowListError::Empty));
    }

    #[test]
    fn test_client_allow_list_case_sensitive() {
        let list = ClientCnAllowList::from_cns(["Peer-A"]);
        assert!(list.contains("Peer-A"));
        assert!(!list.contains("peer-a"));
    }

    #[test]
    fn test_authorize_client_cn_none_allowlist_accepts() {
        authorize_client_cn(None, "anyone").expect("no allow-list must accept");
        authorize_client_cn(None, "unknown").expect("no allow-list must accept unknown");
    }

    #[test]
    fn test_authorize_client_cn_rejects_unlisted_and_unknown() {
        let list = ClientCnAllowList::from_cns(["vc-A"]);
        let err = authorize_client_cn(Some(&list), "vc-X").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert!(err.message().contains("not on the allow-list"));

        let err = authorize_client_cn(Some(&list), "unknown").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_authorize_client_cn_accepts_listed() {
        let list = ClientCnAllowList::from_cns(["vc-A", "unknown"]);
        authorize_client_cn(Some(&list), "vc-A").unwrap();
        authorize_client_cn(Some(&list), "unknown").unwrap();
    }
}
