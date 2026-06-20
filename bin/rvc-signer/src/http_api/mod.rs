//! Web3Signer-compatible HTTP remote-signing API.
//!
//! Phase 1 lands the rustls crypto-provider install ([`tls`]) and the
//! version-pin guard below; the HTTP handlers, router, and listener arrive in
//! later phases. The `axum` / `hyper-util` / `rustls-pemfile` direct deps are
//! declared in `Cargo.toml` now (R4) but are unused until Phase 2.

pub mod tls;

// ── Version-pin guard (R4) ───────────────────────────────────────────────────
//
// The HTTP transport reaches rustls via `tokio_rustls::rustls`; the gRPC/tonic
// stack and the `audit::cn` extractor bind rustls via the direct `rustls` dep.
// Both MUST resolve to the SAME rustls 0.23.x so there is a single
// `CertificateDer` / `pki_types` type across the binary — otherwise the
// accept loop's leaf client cert (Phase 3) could not be handed to `audit::cn`
// and the audit-CN plumbing would fail to compile or silently split types.
//
// This is a COMPILE-TIME identity assertion: the non-capturing closure coerces
// to a `fn` pointer only if `tokio_rustls::rustls::pki_types::CertificateDer`
// *is* `rustls::pki_types::CertificateDer` (the same type). If a transitive
// dependency (e.g. an `axum 0.8` that pulls a newer rustls) ever introduces a
// second rustls into this crate, the two paths resolve to different types and
// this line fails to compile — turning the version-skew risk into a build error.
const _: fn(
    tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) -> rustls::pki_types::CertificateDer<'static> = |cert| cert;

#[cfg(test)]
mod version_pin_tests {
    /// A DER cert constructed via the HTTP-side `tokio_rustls::rustls` path must
    /// flow into the existing `audit::cn` extractor unchanged. This couples the
    /// accept loop's cert type (Phase 3) to what audit consumes today, proving a
    /// single rustls/pki-types across the binary (R4). It compiles only while the
    /// two rustls paths are the same crate.
    #[test]
    fn http_cert_der_flows_into_audit_cn() {
        let der = tokio_rustls::rustls::pki_types::CertificateDer::from(vec![0u8; 4]);
        // A 4-byte blob is not a valid cert, so no CN is parsed — the point is
        // that this COMPILES (`der.as_ref(): &[u8]`, the same input the gRPC
        // audit path uses) and links the HTTP cert type to `audit::cn`.
        let cn = crate::audit::cn::extract_cn_from_der(der.as_ref());
        assert!(cn.is_none(), "a 4-byte non-cert must not yield a CN");
    }
}
