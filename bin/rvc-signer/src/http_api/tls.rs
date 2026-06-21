//! rustls crypto-provider install for the HTTP signing transport.
//!
//! rustls 0.23 resolves a process-global default
//! [`CryptoProvider`](rustls::crypto::CryptoProvider) when
//! [`rustls::ServerConfig::builder`] is called. Its automatic resolution
//! `panic!`s when the number of provider features compiled into the shared
//! `rustls` crate is **not exactly one** — i.e. with **zero or ≥2** providers.
//!
//! In the committed build the shared `rustls` carries **exactly one** provider
//! (`ring`, see the dependency notes below), so `builder()` auto-resolves it and
//! does **not** panic today. We still install an explicit default once at
//! startup as **forward-defense (ADR-006, R1)**: if a future dependency ever
//! unifies a second provider (`aws_lc_rs`) onto the shared `rustls` crate, the
//! automatic resolution becomes ambiguous and `ServerConfig::builder()` would
//! panic — an installed default keeps provider selection deterministic and the
//! Phase-3 HTTP builder path panic-free regardless of how the feature graph
//! evolves. tonic sidesteps the same trap via explicit-provider paths; the HTTP
//! server's plain `ServerConfig::builder()` (Phase 3) does not.
//!
//! ## Provider choice — `ring`, not `aws_lc_rs` (deviation from ADR-006)
//!
//! ADR-006 names the `aws_lc_rs` provider. We install **`ring`** instead, for a
//! reason discovered while implementing this issue and verified against the
//! suite:
//!
//! The workspace already builds the shared `rustls` crate with **only** the
//! `ring` provider feature enabled (it reaches `rustls` via rcgen / quinn /
//! reqwest, none of which turn on rustls's `aws_lc_rs` feature). To call
//! `rustls::crypto::aws_lc_rs::default_provider()` we would have to enable
//! rustls's `aws_lc_rs` feature here — and because Cargo unifies features across
//! the workspace, that would turn on **both** providers on the single shared
//! `rustls` crate. Automatic provider detection then becomes ambiguous, and
//! every gRPC mTLS path that lets tonic build a rustls config *without* an
//! installed default would panic. (Verified empirically while implementing this
//! issue: declaring `rustls`/`tokio-rustls` with default features broke the
//! `rvc-grpc-signer` integration and `rvc-signer-bin` `dvt` mTLS tests on a
//! `--workspace` run.) It would also violate this issue's "existing suite stays
//! green / no graph perturbation / zero net-new compiled crates" exit criteria
//! and add `aws-lc-rs` / `aws-lc-sys` / `cmake` to this crate's build graph.
//!
//! Installing the **`ring`** provider achieves ADR-006's actual goal — a single
//! deterministic installed default — while keeping the shared rustls feature set
//! byte-identical to `develop`. The `aws_lc_rs` vs `ring` choice is immaterial
//! to the install-default purpose; `ring` is the backend the rest of the
//! workspace already uses. (Flag for reviewer: this deviates from the literal
//! ADR-006 wording; recommend updating the ADR.)
//!
//! rustls types are reached through the `tokio_rustls::rustls` re-export so the
//! HTTP transport binds the *same* rustls as the gRPC/tonic stack.

use std::sync::Arc;

use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{VerifierBuilderError, WebPkiClientVerifier},
    RootCertStore, ServerConfig,
};

use crate::config::HttpTlsMode;

/// Errors building the HTTP listener's rustls `ServerConfig` (Issue 3.1).
///
/// PEM→DER file loading and its richer, path-naming errors are Issue 3.2; this
/// covers only the in-memory build from already-decoded DER.
#[derive(Debug, thiserror::Error)]
pub enum HttpTlsError {
    /// No client-CA trust anchor was provided. The CA is **required in both**
    /// modes (mTLS and server-TLS-only) — only the client-auth *requirement*
    /// differs, never the CA. Refusing an empty CA prevents a silent
    /// no-client-auth posture.
    #[error("a client CA certificate is required (none provided)")]
    NoCa,
    /// A client-CA certificate could not be added to the trust-anchor store.
    #[error("invalid client CA certificate: {0}")]
    CaCert(rustls::Error),
    /// The client-cert verifier could not be built.
    #[error("client verifier build failed: {0}")]
    Verifier(VerifierBuilderError),
    /// The server cert chain / private key was rejected (e.g. cert/key mismatch).
    #[error("invalid server certificate or key: {0}")]
    ServerCert(rustls::Error),
}

/// Build the HTTP listener's rustls `ServerConfig` in one of two modes (FR-28,
/// FR-29, FR-30, ADR-004).
///
/// Both modes verify a presented client cert against `client_ca` and **require**
/// the CA; the only difference is whether a client cert is *mandatory*:
/// - [`HttpTlsMode::Mtls`] → `WebPkiClientVerifier::builder(roots).build()`
///   (client cert required — Lighthouse).
/// - [`HttpTlsMode::ServerTlsOnly`] →
///   `…builder(roots).allow_unauthenticated().build()` (client cert requested +
///   validated if present, absence allowed — Prysm).
///
/// `NoClientAuth` is deliberately NOT used: it never requests a cert, so a
/// cert-bearing client would yield no audit CN even on the server-TLS-only
/// listener. This `ServerConfig` is independent of the gRPC tonic config
/// (FR-30). rustls types are bound via the `tokio_rustls::rustls` re-export so
/// the HTTP and gRPC paths share one `CertificateDer` type (R4).
pub fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_ca: Vec<CertificateDer<'static>>,
    mode: HttpTlsMode,
) -> Result<Arc<ServerConfig>, HttpTlsError> {
    let verifier = client_verifier(client_ca, mode)?;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(HttpTlsError::ServerCert)?;
    // HTTP/1.1 only — the Web3Signer API needs no HTTP/2.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Build the client-cert verifier for `mode`, with the CA required in both.
///
/// Split out so the mandatory-vs-optional client-auth behavior is unit-testable
/// via [`client_auth_mandatory`](rustls::server::danger::ClientCertVerifier::client_auth_mandatory)
/// without a full handshake.
fn client_verifier(
    client_ca: Vec<CertificateDer<'static>>,
    mode: HttpTlsMode,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, HttpTlsError> {
    let mut roots = RootCertStore::empty();
    for ca in client_ca {
        roots.add(ca).map_err(HttpTlsError::CaCert)?;
    }
    // Refuse an empty CA explicitly (the builder would also error
    // `NoRootAnchors`, but a typed `NoCa` is clearer and keeps the "CA required
    // in both modes" invariant obvious).
    if roots.is_empty() {
        return Err(HttpTlsError::NoCa);
    }
    let roots = Arc::new(roots);

    let builder = WebPkiClientVerifier::builder(roots);
    let builder = match mode {
        HttpTlsMode::Mtls => builder,
        HttpTlsMode::ServerTlsOnly => builder.allow_unauthenticated(),
    };
    builder.build().map_err(HttpTlsError::Verifier)
}

/// Install the `ring` rustls provider as the process-global default.
///
/// Idempotent: [`install_default`](rustls::crypto::CryptoProvider::install_default)
/// returns `Err` once a provider is already installed, which we deliberately
/// ignore so this is safe to call from both `run_serve` and tests without
/// ordering constraints.
///
/// See the module docs for why this installs `ring` rather than the
/// ADR-006-named `aws_lc_rs` provider.
pub fn install_crypto_provider() {
    // `install_default` returns `Err` if a provider is already installed; we
    // ignore it for idempotency. After this call a default is guaranteed to
    // exist (ours, or one a prior caller installed) — assert that invariant in
    // debug builds so a future regression that leaves no default is caught.
    let _ = rustls::crypto::ring::default_provider().install_default();
    debug_assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "a default CryptoProvider must be installed after install_crypto_provider()"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::CryptoProvider;

    // ── build_server_config / client_verifier (Issue 3.1) ────────────────────

    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::ClientConfig;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    /// rcgen-minted PKI: a trusted CA, a `localhost` server cert + key, a
    /// CA-signed client cert + key, and a ROGUE client signed by a different CA.
    struct Pki {
        ca: CertificateDer<'static>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: Vec<u8>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: Vec<u8>,
        rogue_chain: Vec<CertificateDer<'static>>,
        rogue_key: Vec<u8>,
    }

    fn leaf(
        name: &str,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
    ) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
        let params = CertificateParams::new(vec![name.to_string()]).unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, ca, ca_key).unwrap();
        (vec![cert.der().clone()], key.serialize_der())
    }

    fn test_pki() -> Pki {
        let ca_params = CertificateParams::new(vec!["test-ca".to_string()]).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let (server_chain, server_key) = leaf("localhost", &ca, &ca_key);
        let (client_chain, client_key) = leaf("client", &ca, &ca_key);

        // A rogue CA + client the server's CA does NOT trust.
        let rogue_ca_params = CertificateParams::new(vec!["rogue-ca".to_string()]).unwrap();
        let rogue_ca_key = KeyPair::generate().unwrap();
        let rogue_ca = rogue_ca_params.self_signed(&rogue_ca_key).unwrap();
        let (rogue_chain, rogue_key) = leaf("rogue", &rogue_ca, &rogue_ca_key);

        Pki {
            ca: ca.der().clone(),
            server_chain,
            server_key,
            client_chain,
            client_key,
            rogue_chain,
            rogue_key,
        }
    }

    fn key_of(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(der.to_vec()).into()
    }

    fn server_cfg(pki: &Pki, mode: HttpTlsMode) -> Arc<ServerConfig> {
        build_server_config(
            pki.server_chain.clone(),
            key_of(&pki.server_key),
            vec![pki.ca.clone()],
            mode,
        )
        .expect("server config builds")
    }

    /// A client config trusting the CA (to validate the server cert), optionally
    /// presenting a client identity.
    fn client_cfg(
        pki: &Pki,
        client: Option<(&[CertificateDer<'static>], &[u8])>,
    ) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca.clone()).unwrap();
        let b = ClientConfig::builder().with_root_certificates(roots);
        let cfg = match client {
            Some((chain, key)) => b.with_client_auth_cert(chain.to_vec(), key_of(key)).unwrap(),
            None => b.with_no_client_auth(),
        };
        Arc::new(cfg)
    }

    /// Drive one loopback TLS handshake; `Ok` iff BOTH sides complete.
    async fn handshake(server: Arc<ServerConfig>, client: Arc<ClientConfig>) -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server);
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await.map(|_| ()).map_err(|e| e.to_string())
        });
        let connector = TlsConnector::from(client);
        let stream = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let cli = connector.connect(name, stream).await.map(|_| ()).map_err(|e| e.to_string());
        srv.await.unwrap().and(cli)
    }

    #[test]
    fn mtls_verifier_is_mandatory() {
        install_crypto_provider();
        let pki = test_pki();
        let v = client_verifier(vec![pki.ca.clone()], HttpTlsMode::Mtls).unwrap();
        assert!(v.client_auth_mandatory(), "mTLS verifier must require a client cert");
    }

    #[test]
    fn server_tls_only_verifier_is_not_mandatory() {
        install_crypto_provider();
        let pki = test_pki();
        let v = client_verifier(vec![pki.ca.clone()], HttpTlsMode::ServerTlsOnly).unwrap();
        assert!(!v.client_auth_mandatory(), "server-TLS-only verifier must not require a cert");
    }

    #[test]
    fn empty_ca_is_a_hard_error_in_both_modes() {
        let pki = test_pki();
        for mode in [HttpTlsMode::Mtls, HttpTlsMode::ServerTlsOnly] {
            let err = build_server_config(
                pki.server_chain.clone(),
                key_of(&pki.server_key),
                vec![],
                mode,
            )
            .unwrap_err();
            assert!(matches!(err, HttpTlsError::NoCa), "empty CA must be NoCa, got {err:?}");
        }
    }

    #[tokio::test]
    async fn mtls_rejects_client_without_cert() {
        install_crypto_provider();
        let pki = test_pki();
        let res = handshake(server_cfg(&pki, HttpTlsMode::Mtls), client_cfg(&pki, None)).await;
        assert!(res.is_err(), "mTLS must reject a client presenting no cert");
    }

    #[tokio::test]
    async fn mtls_accepts_client_with_valid_cert() {
        install_crypto_provider();
        let pki = test_pki();
        let client = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
        let res = handshake(server_cfg(&pki, HttpTlsMode::Mtls), client).await;
        assert!(res.is_ok(), "mTLS must accept a CA-signed client cert: {res:?}");
    }

    #[tokio::test]
    async fn server_tls_only_accepts_client_without_cert() {
        install_crypto_provider();
        let pki = test_pki();
        let res =
            handshake(server_cfg(&pki, HttpTlsMode::ServerTlsOnly), client_cfg(&pki, None)).await;
        assert!(res.is_ok(), "server-TLS-only must accept a no-cert client: {res:?}");
    }

    #[tokio::test]
    async fn server_tls_only_still_validates_a_presented_cert() {
        install_crypto_provider();
        let pki = test_pki();
        // Presents a cert, but one signed by an untrusted CA — server-TLS-only
        // relaxes "client cert required", NOT "client cert must be valid".
        let rogue = client_cfg(&pki, Some((&pki.rogue_chain, &pki.rogue_key)));
        let res = handshake(server_cfg(&pki, HttpTlsMode::ServerTlsOnly), rogue).await;
        assert!(res.is_err(), "a presented but untrusted client cert must be rejected");
    }

    /// After the install a process-global default provider is available.
    ///
    /// Weaker than [`install_selects_the_ring_provider`]: under a single-process
    /// test runner this assertion can pass even if the install is a no-op,
    /// because `ServerConfig::builder()`'s own auto-resolution (run by any other
    /// test in the process) installs a default as a side effect. It is the
    /// ring-provider coupling test that actually pins the function body; this one
    /// documents the post-install invariant the call site relies on.
    #[test]
    fn install_makes_provider_default_available() {
        install_crypto_provider();
        assert!(
            CryptoProvider::get_default().is_some(),
            "a default CryptoProvider must be installed after install_crypto_provider()"
        );
    }

    /// Calling the install twice runs without panicking or aborting the process.
    ///
    /// The second call's [`install_default`](CryptoProvider::install_default)
    /// returns `Err` (a default is already set) and the function discards it, so
    /// the fn is safe to call from both `run_serve` and tests without ordering
    /// constraints. (This is a cheap smoke test; it cannot fail on an empty body
    /// either, so it is not a coupling test.)
    #[test]
    fn install_is_idempotent() {
        install_crypto_provider();
        install_crypto_provider();
    }

    /// Smoke test of the Phase-3 `ServerConfig::builder()` path after the install.
    ///
    /// NOTE: this is *not* a panic-proof for R1 in the committed build. With only
    /// the `ring` provider compiled in, `builder()` auto-resolves that single
    /// provider and does not panic whether or not the install ran — the panic
    /// only fires with **zero or ≥2** providers compiled. It guards that the
    /// downstream builder chain stays usable after the install; the R1 forward-
    /// defense (deterministic provider selection) is exercised by
    /// [`install_selects_the_ring_provider`].
    #[test]
    fn server_config_builder_is_usable_after_install() {
        install_crypto_provider();
        let builder = rustls::ServerConfig::builder();
        let _ = builder.with_no_client_auth();
    }

    /// Couples directly to `install_crypto_provider()`'s body: it must install
    /// the **ring** provider as the process-global default.
    ///
    /// This is the test that fails if the function is gutted. nextest runs each
    /// test in its own process and this test calls `install_crypto_provider()`
    /// as its first action, so the install (first-wins) decides the default here
    /// — nothing else has run to set it. If the body is a no-op,
    /// [`CryptoProvider::get_default`] is `None` and the `expect` fails; if the
    /// body installed a *different* provider, the cipher-suite identities would
    /// diverge from `ring::default_provider()` and the comparison fails. (The
    /// `aws_lc_rs` provider module is not even compiled in this `ring`-only
    /// build, so the realistic regressions are "no install" or "wrong config".)
    #[test]
    fn install_selects_the_ring_provider() {
        install_crypto_provider();

        let installed =
            CryptoProvider::get_default().expect("install_crypto_provider must install a default");
        let ring = rustls::crypto::ring::default_provider();

        let installed_suites: Vec<_> = installed.cipher_suites.iter().map(|s| s.suite()).collect();
        let ring_suites: Vec<_> = ring.cipher_suites.iter().map(|s| s.suite()).collect();

        assert_eq!(
            installed_suites, ring_suites,
            "the installed default provider must be ring (cipher-suite set diverged)"
        );
    }
}
