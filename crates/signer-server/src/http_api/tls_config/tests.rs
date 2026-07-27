use super::*;
use rustls::crypto::CryptoProvider;

// ── build_server_config / client_verifier (Issue 3.1) ────────────────────

use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::ClientConfig;
use rvc_test_support::{TestPki, TestPkiParams};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Shared-harness PKI: a trusted CA, a `localhost` server cert + key, a
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

fn test_pki() -> Pki {
    let good = TestPki::generate(TestPkiParams {
        ca_name: "test-ca".to_string(),
        server_sans: vec!["localhost".to_string()],
        client_name: "client".to_string(),
    });
    // A rogue CA + client the server's CA does NOT trust.
    let rogue = TestPki::generate(TestPkiParams {
        ca_name: "rogue-ca".to_string(),
        server_sans: vec!["localhost".to_string()],
        client_name: "rogue".to_string(),
    });

    Pki {
        ca: CertificateDer::from(good.ca_cert_der),
        server_chain: vec![CertificateDer::from(good.server_cert_der)],
        server_key: good.server_key_der,
        client_chain: vec![CertificateDer::from(good.client_cert_der)],
        client_key: good.client_key_der,
        rogue_chain: vec![CertificateDer::from(rogue.client_cert_der)],
        rogue_key: rogue.client_key_der,
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
fn client_cfg(pki: &Pki, client: Option<(&[CertificateDer<'static>], &[u8])>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    let b = ClientConfig::builder().with_root_certificates(roots);
    let cfg = match client {
        Some((chain, key)) => b.with_client_auth_cert(chain.to_vec(), key_of(key)).unwrap(),
        None => b.with_no_client_auth(),
    };
    Arc::new(cfg)
}

/// Drive one loopback TLS handshake, returning `(server_result,
/// client_result)` so a test can assert which side rejected (SEC-001, 3.1
/// review). Each side is bounded by a 5s timeout so a future regression in
/// the early-error path fails CI instead of hanging (3.1 review).
async fn handshake(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
) -> (Result<(), String>, Result<(), String>) {
    use tokio::time::{timeout, Duration};
    const T: Duration = Duration::from_secs(5);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server);
    let srv = tokio::spawn(async move {
        let accept = async {
            let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            acceptor.accept(stream).await.map(|_| ()).map_err(|e| e.to_string())
        };
        timeout(T, accept).await.unwrap_or_else(|_| Err("server handshake timeout".into()))
    });

    let connector = TlsConnector::from(client);
    let connect = async {
        let stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let name = ServerName::try_from("localhost").unwrap();
        connector.connect(name, stream).await.map(|_| ()).map_err(|e| e.to_string())
    };
    let cli = timeout(T, connect).await.unwrap_or_else(|_| Err("client handshake timeout".into()));
    (srv.await.unwrap(), cli)
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
        let err =
            build_server_config(pki.server_chain.clone(), key_of(&pki.server_key), vec![], mode)
                .unwrap_err();
        assert!(matches!(err, HttpTlsError::NoCa), "empty CA must be NoCa, got {err:?}");
    }
}

#[tokio::test]
async fn mtls_rejects_client_without_cert() {
    install_crypto_provider();
    let pki = test_pki();
    let (srv, _) = handshake(server_cfg(&pki, HttpTlsMode::Mtls), client_cfg(&pki, None)).await;
    assert!(srv.is_err(), "mTLS server must reject a client presenting no cert: {srv:?}");
}

#[tokio::test]
async fn mtls_accepts_client_with_valid_cert() {
    install_crypto_provider();
    let pki = test_pki();
    let client = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
    let (srv, cli) = handshake(server_cfg(&pki, HttpTlsMode::Mtls), client).await;
    assert!(
        srv.is_ok() && cli.is_ok(),
        "mTLS must accept a CA-signed client cert: {srv:?} {cli:?}"
    );
}

#[tokio::test]
async fn server_tls_only_accepts_client_without_cert() {
    install_crypto_provider();
    let pki = test_pki();
    let (srv, cli) =
        handshake(server_cfg(&pki, HttpTlsMode::ServerTlsOnly), client_cfg(&pki, None)).await;
    assert!(
        srv.is_ok() && cli.is_ok(),
        "server-TLS-only must accept a no-cert client: {srv:?} {cli:?}"
    );
}

#[tokio::test]
async fn server_tls_only_still_validates_a_presented_cert() {
    install_crypto_provider();
    let pki = test_pki();
    // Presents a cert, but one signed by an untrusted CA — server-TLS-only
    // relaxes "client cert required", NOT "client cert must be valid".
    let rogue = client_cfg(&pki, Some((&pki.rogue_chain, &pki.rogue_key)));
    let (srv, _) = handshake(server_cfg(&pki, HttpTlsMode::ServerTlsOnly), rogue).await;
    // Assert the SERVER side rejected (SEC-001): the failure must be the
    // server validating the client cert, not an unrelated client-side error.
    assert!(srv.is_err(), "the server must reject a presented but untrusted client cert: {srv:?}");
}

// ── PEM→DER loading (Issue 3.2) ──────────────────────────────────────────

use std::io::Write;
use tempfile::TempDir;

/// Write `pem` to `dir/name` and return the path.
fn write_pem(dir: &TempDir, name: &str, pem: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(pem).unwrap();
    path
}

/// CA + `localhost` server cert/key as PEM bytes (PKCS#8 key).
fn server_pems() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let pki = TestPki::generate(TestPkiParams {
        ca_name: "test-ca".to_string(),
        server_sans: vec!["localhost".to_string()],
        client_name: "client".to_string(),
    });
    (pki.server_cert_pem, pki.server_key_pem, pki.ca_cert_pem)
}

#[test]
fn loads_pkcs8_cert_key_ca_and_builds_config() {
    install_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert, key, ca) = server_pems();
    let cert_p = write_pem(&dir, "server.pem", &cert);
    let key_p = write_pem(&dir, "server.key", &key);
    let ca_p = write_pem(&dir, "ca.pem", &ca);
    // Both modes load the same material.
    for mode in [HttpTlsMode::Mtls, HttpTlsMode::ServerTlsOnly] {
        load_server_config(&cert_p, &key_p, &ca_p, mode).expect("PKCS#8 material loads");
    }
}

#[test]
fn read_key_handles_rsa_pkcs1_and_sec1_encodings() {
    // rustls-pemfile routes by PEM tag; assert the loader surfaces each
    // encoding as the right `PrivateKeyDer` variant. (Cryptographic validity
    // is enforced by webpki/with_single_cert, not the PEM loader.)
    // The body need only be valid base64 — rustls-pemfile dispatches the
    // variant from the PEM tag and does not parse the DER here.
    let dir = TempDir::new().unwrap();
    let rsa = b"-----BEGIN RSA PRIVATE KEY-----\nQUJDRUZHSElK\n-----END RSA PRIVATE KEY-----\n";
    let sec1 = b"-----BEGIN EC PRIVATE KEY-----\nS0xNTk9QUVJT\n-----END EC PRIVATE KEY-----\n";
    let rsa_p = write_pem(&dir, "rsa.key", rsa);
    let sec1_p = write_pem(&dir, "sec1.key", sec1);
    assert!(matches!(read_key(&rsa_p).unwrap(), PrivateKeyDer::Pkcs1(_)), "RSA PKCS#1 → Pkcs1");
    assert!(matches!(read_key(&sec1_p).unwrap(), PrivateKeyDer::Sec1(_)), "SEC1 EC → Sec1");
}

#[test]
fn missing_path_is_a_hard_error_naming_the_path() {
    let p = std::path::Path::new("/nonexistent/rvc-http-tls/server.pem");
    let err = read_certs(p).unwrap_err();
    assert!(format!("{err}").contains("server.pem"), "error must name the path: {err}");
}

#[test]
fn malformed_pem_has_no_certs() {
    let dir = TempDir::new().unwrap();
    let p = write_pem(&dir, "junk.pem", b"not a pem file at all\n");
    assert!(matches!(read_certs(&p).unwrap_err(), HttpTlsError::NoCertificates(_)));
}

#[test]
fn encrypted_key_fails_closed() {
    // An encrypted PKCS#8 key carries the "ENCRYPTED PRIVATE KEY" tag, which
    // rustls-pemfile does NOT treat as a usable private key → fail closed
    // (no passphrase support for the HTTP listener in MVP).
    let dir = TempDir::new().unwrap();
    let enc =
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB...\n-----END ENCRYPTED PRIVATE KEY-----\n";
    let p = write_pem(&dir, "enc.key", enc);
    assert!(matches!(read_key(&p).unwrap_err(), HttpTlsError::NoPrivateKey(_)));
}

#[test]
fn cert_key_mismatch_is_rejected_at_build_time() {
    install_crypto_provider();
    let dir = TempDir::new().unwrap();
    let (cert, _key, ca) = server_pems();
    // A DIFFERENT key that does not match the server cert (client key from a
    // freshly minted PKI — same algorithm, unrelated keypair).
    let wrong_key = TestPki::new().client_key_pem;
    let cert_p = write_pem(&dir, "server.pem", &cert);
    let key_p = write_pem(&dir, "wrong.key", &wrong_key);
    let ca_p = write_pem(&dir, "ca.pem", &ca);
    let err = load_server_config(&cert_p, &key_p, &ca_p, HttpTlsMode::Mtls).unwrap_err();
    assert!(
        matches!(err, HttpTlsError::ServerCert(_)),
        "cert/key mismatch must be rejected at build time, got {err:?}"
    );
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
