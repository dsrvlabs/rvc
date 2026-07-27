//! HTTP TLS configuration: crypto-provider install, PEM→DER loading, and rustls `ServerConfig` build.
//!
//! Split from the former grab-bag `http_api::tls` (RF5-22 / F34). Accept-loop
//! concerns live in [`super::accept_loop`]; audit CN derivation lives in
//! [`crate::audit::cn::audit_cn`]. Shared path-preserving file I/O is
//! [`crate::tls_io`].
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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{VerifierBuilderError, WebPkiClientVerifier},
    RootCertStore, ServerConfig,
};

use crate::config::HttpTlsMode;
use crate::tls_io::{read_tls_file, TlsFileError};

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
    /// A cert/key/CA file could not be read (missing, unreadable). Names the path
    /// via the shared [`TlsFileError`] representation.
    #[error(transparent)]
    Read(#[from] TlsFileError),
    /// A PEM file failed to decode. Names the path.
    #[error("malformed PEM in {0}: {1}")]
    Pem(PathBuf, std::io::Error),
    /// A PEM file contained no certificates where some were required.
    #[error("no certificates found in {0}")]
    NoCertificates(PathBuf),
    /// A PEM file contained no usable (unencrypted PKCS#8/PKCS#1/SEC1) private key.
    #[error("no usable private key found in {0} (encrypted keys are not supported)")]
    NoPrivateKey(PathBuf),
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

/// Load the server cert chain, server private key, and client CA from the
/// configured PEM paths and build the `ServerConfig` (Issue 3.2, R2/R3).
///
/// Genuinely new code: the gRPC `TlsConfig` hands raw PEM to tonic and never
/// produces DER. Fails **closed** — a missing, malformed, or encrypted file is a
/// hard error naming the path, consistent with the binary's "refuse to start
/// without valid TLS" posture; there is no plaintext fallback. A cert/key
/// mismatch is rejected here (build time), not at first connection.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
    mode: HttpTlsMode,
) -> Result<Arc<ServerConfig>, HttpTlsError> {
    let cert_chain = read_certs(cert_path)?;
    let key = read_key(key_path)?;
    let client_ca = read_certs(ca_path)?;
    build_server_config(cert_chain, key, client_ca, mode)
}

/// Read all PEM certificates from `path` (a server chain or a CA bundle).
fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, HttpTlsError> {
    let pem = read_tls_file(path)?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| HttpTlsError::Pem(path.to_path_buf(), e))?;
    if certs.is_empty() {
        return Err(HttpTlsError::NoCertificates(path.to_path_buf()));
    }
    Ok(certs)
}

/// Read the first PEM private key from `path`, accepting PKCS#8, PKCS#1 (RSA),
/// and SEC1 (EC) encodings (rustls-pemfile dispatches by tag). An encrypted key
/// carries an unsupported tag and yields [`HttpTlsError::NoPrivateKey`].
fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, HttpTlsError> {
    let pem = read_tls_file(path)?;
    rustls_pemfile::private_key(&mut pem.as_slice())
        .map_err(|e| HttpTlsError::Pem(path.to_path_buf(), e))?
        .ok_or_else(|| HttpTlsError::NoPrivateKey(path.to_path_buf()))
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
mod tests;
