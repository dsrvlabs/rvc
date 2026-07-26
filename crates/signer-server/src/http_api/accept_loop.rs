//! Hardened HTTPS accept loop for the Web3Signer HTTP API.
//!
//! Split from the former grab-bag `http_api::tls` (RF5-22 / F34). TLS material
//! loading and rustls `ServerConfig` construction live in
//! [`super::tls_config`]; audit CN derivation lives in
//! [`crate::audit::cn::audit_cn`].

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::rustls::{pki_types::CertificateDer, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use super::tls_config::load_server_config;
use crate::config::HttpTlsMode;

/// The leaf client certificate from the TLS handshake, injected as a request
/// extension so the audit layer (Issue 3.4) can derive the client CN. `None` on
/// a server-TLS-only / no-cert connection (→ `AUDIT_CN_DEFAULT`).
#[derive(Clone, Debug)]
pub struct PeerCert(pub Option<CertificateDer<'static>>);

impl PeerCert {
    /// Borrow the leaf DER when a client certificate was presented.
    pub fn leaf_der(&self) -> Option<&[u8]> {
        self.0.as_ref().map(|c| c.as_ref())
    }
}

/// Per-connection handshake timeout: a stalled client cannot hold a task open.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Slow-header (slowloris) bound on each accepted connection (SEC-2.11-01, the
/// Phase-2 request-hardening carry-forward).
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Max concurrently-served connections. Bounds per-connection-task fan-out so a
/// connection flood cannot exhaust memory/fds (3.3 review). Sensible default;
/// promoting it to a `[signer.http]` knob is a follow-up.
pub(crate) const MAX_CONCURRENT_CONNECTIONS: usize = 1024;
/// Backoff after an `accept()` error. EMFILE/ENFILE (fd exhaustion) leaves the
/// listener readable, so a bare `continue` busy-spins at 100% CPU; this yields
/// the task and bounds the spin (3.3 review).
pub(crate) const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
/// Upper bound on draining in-flight connections at shutdown, so SIGTERM cannot
/// hang on an idle keep-alive client.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve the Web3Signer HTTP API over TLS on `listener` (ADR-005, R7).
///
/// Per accepted connection: complete the rustls handshake (bounded by
/// [`HANDSHAKE_TIMEOUT`]), extract the leaf client cert into a [`PeerCert`]
/// request extension, and serve the **opaque** `router` over HTTP/1.1 via hyper
/// `serve_connection` (no upgrades — research R6). Each connection runs in its
/// own task, so one bad client (handshake failure or a panicking handler) never
/// wedges the accept loop or the process. A `header_read_timeout` bounds
/// slow-header (slowloris) connections.
///
/// Hardening (3.3 review):
/// - a [`Semaphore`] caps concurrency at [`MAX_CONCURRENT_CONNECTIONS`] —
///   acquired before each accept, so a flood applies backpressure rather than
///   spawning unbounded tasks;
/// - an `accept()` error backs off [`ACCEPT_ERROR_BACKOFF`] so EMFILE/ENFILE
///   cannot busy-spin the loop;
/// - on `shutdown`, the loop stops accepting and drains in-flight connections
///   (bounded by [`DRAIN_TIMEOUT`]) so an in-progress `/sign` completes.
///
/// `router` is taken as an opaque [`axum::Router`]; this module stays ignorant
/// of `/sign` and the gate (extraction-readiness). Unlike `serve_metrics` (which
/// handles connections serially, inline), this fans connections out across tasks.
pub async fn serve_https(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    router: Router,
    shutdown: CancellationToken,
) {
    serve_https_inner(listener, tls, router, shutdown, MAX_CONCURRENT_CONNECTIONS, DRAIN_TIMEOUT)
        .await
}

/// [`serve_https`] with the connection cap and drain timeout injected, so tests
/// can saturate the cap and assert prompt shutdown.
async fn serve_https_inner(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    router: Router,
    shutdown: CancellationToken,
    max_connections: usize,
    drain_timeout: Duration,
) {
    let acceptor = TlsAcceptor::from(tls);
    let limit = Arc::new(Semaphore::new(max_connections));
    let mut conns: JoinSet<()> = JoinSet::new();

    loop {
        // Backpressure: do not accept a new connection until a serving slot is
        // free. The acquire is RACED against `shutdown` — when the cap is
        // saturated the loop must still observe cancellation promptly rather than
        // park on the permit until an in-flight connection frees one (3.5 review).
        // `acquire_owned`'s future is cancel-safe (dropping it just deregisters
        // the waiter), so losing the race leaks no permit.
        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            permit = Arc::clone(&limit).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };

        let (tcp, _peer) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            res = listener.accept() => match res {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "HTTP listener: accept failed");
                    drop(permit);
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            },
        };

        let acceptor = acceptor.clone();
        let router = router.clone();
        conns.spawn(async move {
            serve_one(acceptor, tcp, router).await;
            drop(permit); // release the serving slot when the connection ends
        });

        // Reap finished connection tasks so the JoinSet does not grow unbounded.
        while conns.try_join_next().is_some() {}
    }

    // Graceful shutdown: stop accepting (listener dropped) and drain in-flight
    // connections, bounded so an idle keep-alive client cannot hang exit.
    drop(listener);
    let _ =
        tokio::time::timeout(drain_timeout, async { while conns.join_next().await.is_some() {} })
            .await;
}

/// Build the HTTP listener's TLS config + router from already-loaded paths and
/// the shared application state, bind `listen_address`, and spawn
/// [`serve_https`] (Issue 3.5). Returns the bound address + the listener task.
///
/// `run_serve` calls this when `[signer.http].enabled`; the `state` carries the
/// SAME `Arc<SigningGate>` injected into the gRPC service (FR-26).
#[allow(clippy::too_many_arguments)]
pub async fn spawn_https_listener(
    listen_address: &str,
    tls_cert: &Path,
    tls_key: &Path,
    tls_ca_cert: &Path,
    tls_mode: HttpTlsMode,
    state: super::Web3SignerState,
    shutdown: CancellationToken,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let tls = load_server_config(tls_cert, tls_key, tls_ca_cert, tls_mode)?;
    let router = super::router(state);
    let listener = TcpListener::bind(listen_address).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(serve_https(listener, tls, router, shutdown));
    Ok((addr, handle))
}

/// Handshake one connection, inject [`PeerCert`], and serve `router` over it.
async fn serve_one(acceptor: TlsAcceptor, tcp: TcpStream, router: Router) {
    serve_one_with_timeout(acceptor, tcp, router, HANDSHAKE_TIMEOUT).await
}

/// [`serve_one`] with an injectable handshake timeout for unit tests.
async fn serve_one_with_timeout(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    router: Router,
    handshake_timeout: Duration,
) {
    let tls_stream = match tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            // Handshake failure (e.g. an mTLS client with no/invalid cert) drops
            // this connection only; the accept loop keeps serving others.
            tracing::debug!(error = %e, "TLS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!("TLS handshake timed out");
            return;
        }
    };

    // Leaf client cert (owned so it outlives the borrow); `None` in
    // server-TLS-only / no-cert connections.
    let leaf = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|cert| cert.clone().into_owned());
    let peer = PeerCert(leaf);

    // Inject the per-connection PeerCert into every request, then serve the
    // opaque Router (tower) via hyper. `oneshot` drives poll_ready + call.
    let service = service_fn(move |mut req: Request<Incoming>| {
        req.extensions_mut().insert(peer.clone());
        router.clone().oneshot(req)
    });

    let mut builder = http1::Builder::new();
    builder.timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
    if let Err(e) = builder.serve_connection(TokioIo::new(tls_stream), service).await {
        tracing::debug!(error = %e, "HTTP connection closed with error");
    }
}

#[cfg(test)]
mod tests {
    use super::super::tls_config::{build_server_config, install_crypto_provider};
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use axum::routing::get;
    use axum::Extension;
    use axum::Router;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::ClientConfig;
    use rustls::RootCertStore;
    use rvc_test_support::{TestPki, TestPkiParams};
    use tempfile::TempDir;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tokio_util::sync::CancellationToken;

    use crate::config::HttpTlsMode;

    struct Pki {
        ca: CertificateDer<'static>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: Vec<u8>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: Vec<u8>,
    }

    fn test_pki() -> Pki {
        let pki = TestPki::generate(TestPkiParams {
            ca_name: "test-ca".to_string(),
            server_sans: vec!["localhost".to_string()],
            client_name: "client".to_string(),
        });
        Pki {
            ca: CertificateDer::from(pki.ca_cert_der),
            server_chain: vec![CertificateDer::from(pki.server_cert_der)],
            server_key: pki.server_key_der,
            client_chain: vec![CertificateDer::from(pki.client_cert_der)],
            client_key: pki.client_key_der,
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

    use std::io::Write;

    fn write_pem(dir: &TempDir, name: &str, pem: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(pem).unwrap();
        path
    }

    fn server_pems() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let pki = TestPki::generate(TestPkiParams {
            ca_name: "test-ca".to_string(),
            server_sans: vec!["localhost".to_string()],
            client_name: "client".to_string(),
        });
        (pki.server_cert_pem, pki.server_key_pem, pki.ca_cert_pem)
    }

    async fn peer_handler(Extension(PeerCert(leaf)): Extension<PeerCert>) -> &'static str {
        if leaf.is_some() {
            "some"
        } else {
            "none"
        }
    }

    async fn panic_handler() -> &'static str {
        panic!("intentional handler panic")
    }

    /// Reflects the audit CN derived from the connection's `PeerCert` (Issue 3.4).
    async fn cn_handler(Extension(peer): Extension<PeerCert>) -> String {
        crate::audit::cn::audit_cn(peer.leaf_der(), signer::AUDIT_CN_DEFAULT)
    }

    /// An OPAQUE test router (no gate/state) with a route that reflects the
    /// injected `PeerCert`, the derived audit CN, a panicking route, and a
    /// liveness route.
    fn serve_test_router() -> Router {
        Router::new()
            .route("/peer", get(peer_handler))
            .route("/cn", get(cn_handler))
            .route("/ok", get(|| async { "ok" }))
            .route("/panic", get(panic_handler))
    }

    /// Spawn `serve_https` on an ephemeral loopback port; return its address.
    async fn start_server(mode: HttpTlsMode, pki: &Pki) -> std::net::SocketAddr {
        install_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_https(
            listener,
            server_cfg(pki, mode),
            serve_test_router(),
            CancellationToken::new(),
        ));
        addr
    }

    /// One real HTTPS GET over a fresh TLS connection (raw hyper client), using
    /// `client` (with or without a client identity). `Err` if the TLS handshake
    /// or the request fails.
    async fn https_get(
        addr: std::net::SocketAddr,
        client: Arc<ClientConfig>,
        path: &str,
    ) -> Result<(axum::http::StatusCode, String), String> {
        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let connector = TlsConnector::from(client);
        let name = ServerName::try_from("localhost").unwrap();
        let tls = connector.connect(name, tcp).await.map_err(|e| e.to_string())?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .uri(path)
            .header("host", "localhost")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let bytes = axum::body::to_bytes(axum::body::Body::new(resp.into_body()), usize::MAX)
            .await
            .map_err(|e| e.to_string())?;
        Ok((status, String::from_utf8(bytes.to_vec()).unwrap()))
    }

    #[tokio::test]
    async fn mtls_client_cert_is_injected_as_peer_cert_some() {
        let pki = test_pki();
        let addr = start_server(HttpTlsMode::Mtls, &pki).await;
        let client = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
        let (status, body) = https_get(addr, client, "/peer").await.expect("mTLS request succeeds");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "some", "the leaf client cert must reach the handler as PeerCert(Some)");
    }

    #[tokio::test]
    async fn server_tls_only_no_cert_is_peer_cert_none() {
        let pki = test_pki();
        let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
        let client = client_cfg(&pki, None);
        let (status, body) = https_get(addr, client, "/peer").await.expect("no-cert request ok");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "none", "a no-cert connection must yield PeerCert(None)");
    }

    #[tokio::test]
    async fn handshake_failure_does_not_wedge_the_loop() {
        let pki = test_pki();
        let addr = start_server(HttpTlsMode::Mtls, &pki).await;
        // A no-cert client against mTLS fails the handshake — its connection dies.
        let bad = https_get(addr, client_cfg(&pki, None), "/ok").await;
        assert!(bad.is_err(), "no-cert client must be rejected at handshake");
        // The loop must still serve a subsequent good client.
        let good = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
        let (status, body) = https_get(addr, good, "/ok").await.expect("loop still serves");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn handler_panic_does_not_take_down_the_listener() {
        let pki = test_pki();
        let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
        // Trigger a handler panic on one connection (the request errors as the
        // connection task aborts) — the spawned-task panic is isolated by tokio.
        let _ = https_get(addr, client_cfg(&pki, None), "/panic").await;
        // A new connection must still be served.
        let (status, body) =
            https_get(addr, client_cfg(&pki, None), "/ok").await.expect("listener survived");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "ok");
    }

    // ── audit CN via accept loop (Issue 3.4) ──────────────────────────────

    #[tokio::test]
    async fn server_tls_only_cert_bearing_client_yields_its_real_cn() {
        // AC: a client that DOES present a cert on a server-TLS-only listener
        // still has its CN extracted (allow_unauthenticated relaxes "required",
        // not the cert's CA-validation or its CN).
        let pki = test_pki();
        let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
        let client = client_cfg(&pki, Some((&pki.client_chain, &pki.client_key)));
        let (status, body) = https_get(addr, client, "/cn").await.expect("request ok");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "client", "the leaf CN must reach the audit layer");
    }

    #[tokio::test]
    async fn server_tls_only_no_cert_yields_default_cn() {
        let pki = test_pki();
        let addr = start_server(HttpTlsMode::ServerTlsOnly, &pki).await;
        let (status, body) =
            https_get(addr, client_cfg(&pki, None), "/cn").await.expect("no-cert request ok");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, signer::AUDIT_CN_DEFAULT, "no client cert → default audit CN");
    }

    // ── run_serve wiring: spawn_https_listener + graceful shutdown (Issue 3.5) ─

    /// A client config trusting `ca_pem` (to validate the server cert), no client cert.
    fn client_trusting(ca_pem: &[u8]) -> Arc<ClientConfig> {
        let ca = rustls_pemfile::certs(&mut &ca_pem[..]).next().unwrap().unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
    }

    #[tokio::test]
    async fn spawn_https_listener_serves_upcheck_over_tls() {
        install_crypto_provider();
        let dir = TempDir::new().unwrap();
        let (cert, key, ca) = server_pems();
        let cert_p = write_pem(&dir, "c.pem", &cert);
        let key_p = write_pem(&dir, "k.pem", &key);
        let ca_p = write_pem(&dir, "ca.pem", &ca);

        // The state carries a real shared SigningGate — the exact wiring
        // `run_serve` performs (the gate is cloned from the gRPC service's gate).
        let state = crate::http_api::test_support::test_state(Arc::new(
            crate::http_api::test_support::MockBackend::empty(),
        ));
        let (addr, _handle) = spawn_https_listener(
            "127.0.0.1:0",
            &cert_p,
            &key_p,
            &ca_p,
            HttpTlsMode::ServerTlsOnly,
            state,
            CancellationToken::new(),
        )
        .await
        .expect("HTTP listener spawns");

        let (status, body) =
            https_get(addr, client_trusting(&ca), "/upcheck").await.expect("upcheck over TLS");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "OK", "the full 3.1–3.4 path serves /upcheck over TLS");
    }

    #[tokio::test]
    async fn serve_https_exits_promptly_on_shutdown() {
        install_crypto_provider();
        let pki = test_pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = CancellationToken::new();
        let handle = tokio::spawn(serve_https(
            listener,
            server_cfg(&pki, HttpTlsMode::ServerTlsOnly),
            serve_test_router(),
            token.clone(),
        ));
        token.cancel();
        // The loop must break on cancellation and the drain must complete.
        let exited = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(exited.is_ok(), "serve_https must exit promptly after cancellation");
    }

    /// The carry-forward #3 proof (3.5 review): shutdown must be prompt even when
    /// the connection cap is SATURATED. Pre-fix, the loop parked on the permit
    /// acquire (outside the select) and ignored cancellation until an in-flight
    /// connection freed a permit (~HEADER_READ_TIMEOUT). This holds the only
    /// permit and asserts exit well under that stall.
    #[tokio::test]
    async fn shutdown_is_prompt_even_when_connection_cap_is_saturated() {
        install_crypto_provider();
        let pki = test_pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        // cap = 1 so a single held connection saturates the loop's permit;
        // a short drain timeout keeps the test fast.
        let handle = tokio::spawn(serve_https_inner(
            listener,
            server_cfg(&pki, HttpTlsMode::ServerTlsOnly),
            serve_test_router(),
            token.clone(),
            1,
            Duration::from_millis(200),
        ));

        // Finish the TLS handshake but send NO request: this connection's
        // serve_one task holds the only permit (parked in header-read), so the
        // accept loop is parked acquiring the next permit.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(client_cfg(&pki, None));
        let _held =
            connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        token.cancel();
        // With the acquire raced against shutdown the loop breaks promptly and
        // the bounded drain finishes — far under HEADER_READ_TIMEOUT (30s), the
        // pre-fix stall point.
        let exited = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            exited.is_ok(),
            "shutdown must be prompt even when the connection cap is saturated"
        );
    }

    #[test]
    fn test_accept_loop_hardening_constants() {
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(HEADER_READ_TIMEOUT, Duration::from_secs(30));
        assert_eq!(MAX_CONCURRENT_CONNECTIONS, 1024);
        assert_eq!(DRAIN_TIMEOUT, Duration::from_secs(10));
        assert_eq!(ACCEPT_ERROR_BACKOFF, Duration::from_millis(50));
    }

    /// With cap = 1, a second concurrent request cannot complete until the first
    /// connection releases its semaphore permit (backpressure, not hard reject).
    #[tokio::test]
    async fn test_accept_loop_rejects_beyond_semaphore_limit() {
        install_crypto_provider();
        let pki = test_pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let handle = tokio::spawn(serve_https_inner(
            listener,
            server_cfg(&pki, HttpTlsMode::ServerTlsOnly),
            serve_test_router(),
            token.clone(),
            1,
            Duration::from_secs(2),
        ));

        // Hold the only permit with a finished TLS handshake that never sends a request.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(client_cfg(&pki, None));
        let _held =
            connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A second client should not complete while the cap is saturated.
        let pending = tokio::spawn({
            let pki_ca = pki.ca.clone();
            let client = client_cfg(&pki, None);
            async move {
                let _ = pki_ca;
                https_get(addr, client, "/ok").await
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !pending.is_finished(),
            "second connection must wait while the semaphore is saturated"
        );

        drop(_held);
        let (status, body) = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .expect("join timeout")
            .expect("task join")
            .expect("second request after release");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "ok");

        token.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// A client that opens TCP but never completes the TLS handshake is closed
    /// after the handshake timeout (injected short value for the test).
    #[tokio::test]
    async fn test_handshake_timeout_closes_connection() {
        install_crypto_provider();
        let pki = test_pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Manually accept + serve_one_with_timeout with a short handshake budget.
        let acceptor = TlsAcceptor::from(server_cfg(&pki, HttpTlsMode::ServerTlsOnly));
        let router = serve_test_router();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            serve_one_with_timeout(acceptor, tcp, router, Duration::from_millis(200)).await;
        });

        // Open TCP but do not speak TLS.
        let _raw = TcpStream::connect(addr).await.unwrap();
        let finished = tokio::time::timeout(Duration::from_secs(3), server).await;
        assert!(finished.is_ok(), "handshake timeout must close the connection task");
        finished.unwrap().unwrap();
    }
}
