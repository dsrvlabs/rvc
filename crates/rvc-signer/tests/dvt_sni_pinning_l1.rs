//! Regression tests for ISSUE-4.1 / L-1: per-peer SNI pinning in DVT TLS.
//!
//! # Background
//!
//! Before this fix, `GrpcPeerRequester::connect` applied the same
//! `ClientTlsConfig` (no `domain_name`) to every peer endpoint.  A
//! certificate valid for `peer-A` under the shared CA was therefore accepted
//! when the client thought it was connecting to `peer-B`, breaking the
//! separate-identity guarantee that mTLS is meant to provide.
//!
//! # Fix
//!
//! Each `PeerConnectInfo` carries an `sni_cn` field.  `connect` now calls
//! `.domain_name(&peer.sni_cn)` on the per-peer `ClientTlsConfig` clone before
//! dialling.  rustls then verifies that the server certificate is issued for
//! that exact hostname — rejecting any cert issued for a different peer.
//!
//! # Test strategy
//!
//! - `test_wrong_peer_cert_refused` — server holds a cert for `peer-a.local`;
//!   client expects `peer-b.local`; handshake must fail.  This was the RED
//!   test before `PeerConnectInfo` existed (compile-time failure), and is now
//!   GREEN with the fix.
//!
//! - `test_correct_peer_cert_accepted` — same server; client expects
//!   `peer-a.local`; handshake must succeed.
//!
//! - `test_lookup_by_addr_roundtrip` / `test_lookup_by_addr_missing` — unit
//!   tests for the new `AllowedPeers::lookup_by_addr` helper.

#![cfg(feature = "dvt")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use tempfile::TempDir;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use rvc_signer_bin::dvt::allow_list::{AllowedPeer, AllowedPeers};
use rvc_signer_bin::dvt::peer_client::{
    build_peer_connect_infos, GrpcPeerRequester, PeerConnectInfo,
};
use rvc_signer_bin::dvt::peer_service::PeerSignerServiceImpl;
use rvc_signer_bin::dvt::types::ShareInfo;
use rvc_signer_bin::tls::TlsConfig;
use rvc_signer_bin::PeerSignerServiceServerV2;

// ─────────────────────────────────────────────────────────────────────────────
// Cert / TLS helpers
// ─────────────────────────────────────────────────────────────────────────────

/// All cert artifacts for one test run.
struct TestCerts {
    /// PEM of the shared CA.
    ca_pem: Vec<u8>,
    /// PEM of the server cert (SANs: DNS:`sni_name`).
    server_cert_pem: Vec<u8>,
    /// PEM of the server private key.
    server_key_pem: Vec<u8>,
    /// `TlsConfig` that the client passes to `GrpcPeerRequester::connect`.
    /// Points to temp files on disk (kept alive by `_dir`).
    client_tls_config: TlsConfig,
    /// Temp directory owning the client cert files; must outlive the test.
    _dir: TempDir,
}

/// Generate CA → server cert (DNS SAN = `sni_name`) → client cert.
///
/// The server cert has DNS SAN = `sni_name` and IP SAN = `127.0.0.1`.
/// The IP SAN is required to make `test_wrong_peer_cert_refused` a genuine
/// RED→GREEN regression test (see the inline comment in the function body
/// for the full reasoning).
fn generate_test_certs(sni_name: &str) -> TestCerts {
    // CA
    let ca_params = CertificateParams::new(vec!["test-ca.internal".to_string()]).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();

    // Server cert: DNS SAN = sni_name + IP SAN = 127.0.0.1.
    //
    // The IP SAN is critical for making the test a genuine RED→GREEN.  Without
    // it, tonic falls back to verifying the URI host (`127.0.0.1`) against the
    // cert, which fails for missing IP SAN on BOTH old code (no domain_name)
    // AND new code — making the assertion vacuously true.
    //
    // With the IP SAN present:
    //   - Old code (no domain_name): URI host `127.0.0.1` → cert has IP SAN →
    //     connection SUCCEEDS → `test_wrong_peer_cert_refused` FAILS (RED).
    //   - New code (domain_name("peer-b.local")): cert has `peer-a.local` SAN,
    //     NOT `peer-b.local` → rustls rejects → FAILS → assertion passes (GREEN).
    let server_params =
        CertificateParams::new(vec![sni_name.to_string(), "127.0.0.1".to_string()]).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();
    let server_cert_pem = server_cert.pem().into_bytes();
    let server_key_pem = server_key.serialize_pem().into_bytes();

    // Client cert (signed by the same CA; used for mTLS)
    let client_params = CertificateParams::new(vec!["test-client.internal".to_string()]).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();
    let client_cert_pem = client_cert.pem().into_bytes();
    let client_key_pem = client_key.serialize_pem().into_bytes();

    // Write client-side files to a temp dir
    let dir = TempDir::new().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");

    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&cert_path, &client_cert_pem).unwrap();
    std::fs::write(&key_path, &client_key_pem).unwrap();

    let client_tls_config = TlsConfig::new(cert_path, key_path, ca_path);

    TestCerts { ca_pem, server_cert_pem, server_key_pem, client_tls_config, _dir: dir }
}

/// Spin up a tonic gRPC server with mTLS on `127.0.0.1:0`.
///
/// The server presents `server_cert_pem` / `server_key_pem` and requires
/// clients to authenticate with a cert signed by `ca_pem`.
///
/// Returns the bound port.  The server task runs until dropped.
async fn start_mtls_server(
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(&server_cert_pem, &server_key_pem))
        .client_ca_root(Certificate::from_pem(&ca_pem));

    // Minimal DVT peer service — no real shares, but the TLS handshake and
    // HTTP/2 settings exchange happen before any RPC is dispatched.
    let share_map: Arc<HashMap<[u8; 48], ShareInfo>> = Arc::new(HashMap::new());
    let allow_list = Arc::new(AllowedPeers {
        peers: vec![AllowedPeer { peer_cn: "test".to_string(), share_index: 1, addr: None }],
    });
    let peer_svc = PeerSignerServiceImpl::new(share_map, allow_list, None);

    tokio::spawn(async move {
        use tokio_stream::wrappers::TcpListenerStream;

        let incoming = TcpListenerStream::new(listener);
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(PeerSignerServiceServerV2::new(peer_svc))
            .serve_with_incoming(incoming)
            .await
            .ok();
    });

    // Yield so the spawned task has a chance to bind before we return.
    tokio::task::yield_now().await;

    port
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 (RED → GREEN): wrong SNI — server cert for peer-A rejected for peer-B
// ─────────────────────────────────────────────────────────────────────────────

/// Regression test for L-1 SNI pinning.
///
/// The server holds a cert valid for `peer-a.local`.  The client connects
/// with `sni_cn = "peer-b.local"` (wrong peer identity).  After the fix,
/// rustls rejects the handshake because the cert is not issued for
/// `peer-b.local`.
///
/// **RED before fix**: `PeerConnectInfo` did not exist — this test did not
/// compile, proving the API did not support per-peer SNI at all.
/// **GREEN after fix**: test compiles, connection fails as required.
#[tokio::test]
async fn test_wrong_peer_cert_refused() {
    let certs = generate_test_certs("peer-a.local");
    let port = start_mtls_server(
        certs.server_cert_pem.clone(),
        certs.server_key_pem.clone(),
        certs.ca_pem.clone(),
    )
    .await;

    // Client expects peer-b.local, but server holds a cert for peer-a.local.
    let peer =
        PeerConnectInfo { addr: format!("127.0.0.1:{}", port), sni_cn: "peer-b.local".to_string() };

    let result =
        GrpcPeerRequester::connect(&[peer], Some(&certs.client_tls_config), Duration::from_secs(5))
            .await;

    assert!(
        result.is_err(),
        "connecting with wrong SNI must fail — cert is for peer-a.local, not peer-b.local"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: correct SNI — server cert for peer-A accepted for peer-A
// ─────────────────────────────────────────────────────────────────────────────

/// Sanity check: connecting with the matching SNI must succeed.
#[tokio::test]
async fn test_correct_peer_cert_accepted() {
    let certs = generate_test_certs("peer-a.local");
    let port = start_mtls_server(
        certs.server_cert_pem.clone(),
        certs.server_key_pem.clone(),
        certs.ca_pem.clone(),
    )
    .await;

    let peer =
        PeerConnectInfo { addr: format!("127.0.0.1:{}", port), sni_cn: "peer-a.local".to_string() };

    let result =
        GrpcPeerRequester::connect(&[peer], Some(&certs.client_tls_config), Duration::from_secs(5))
            .await;

    assert!(result.is_ok(), "connecting with correct SNI must succeed; error: {:?}", result.err());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: unit — lookup_by_addr found
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lookup_by_addr_found() {
    let peers = AllowedPeers {
        peers: vec![
            AllowedPeer {
                peer_cn: "peer-a.local".to_string(),
                share_index: 1,
                addr: Some("127.0.0.1:50051".to_string()),
            },
            AllowedPeer {
                peer_cn: "peer-b.local".to_string(),
                share_index: 2,
                addr: Some("127.0.0.1:50052".to_string()),
            },
        ],
    };

    let hit = peers.lookup_by_addr("127.0.0.1:50051").unwrap();
    assert_eq!(hit.peer_cn, "peer-a.local");
    assert_eq!(hit.share_index, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: unit — lookup_by_addr missing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lookup_by_addr_missing() {
    let peers = AllowedPeers {
        peers: vec![AllowedPeer {
            peer_cn: "peer-a.local".to_string(),
            share_index: 1,
            addr: Some("127.0.0.1:50051".to_string()),
        }],
    };

    assert!(peers.lookup_by_addr("10.0.0.1:50051").is_none());
    assert!(peers.lookup_by_addr("127.0.0.1:50099").is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: unit — lookup_by_addr when addr field is None
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lookup_by_addr_no_addr_field() {
    let peers = AllowedPeers {
        peers: vec![AllowedPeer {
            peer_cn: "peer-a.local".to_string(),
            share_index: 1,
            addr: None, // no addr configured
        }],
    };

    // Should not match anything if addr is None
    assert!(peers.lookup_by_addr("127.0.0.1:50051").is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 (RED → GREEN): startup fails when peer addr not in allow-list
//
// Verifies Must-Fix #1: `build_peer_connect_infos` with TLS enabled must
// return an error when a dvt_peer address has no matching `addr=` entry in
// the allow-list, rather than silently falling back to no-SNI pinning.
//
// RED before fix: `build_peer_connect_infos` did not exist.
// GREEN after fix: returns Err with a clear message; L-1 bypass closed.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_startup_fails_when_peer_addr_missing_from_allowlist() {
    // Allow-list covers peer-a only; peer-b has no `addr=` entry.
    let allow_list = AllowedPeers {
        peers: vec![AllowedPeer {
            peer_cn: "peer-a.local".to_string(),
            share_index: 1,
            addr: Some("peer-a.local:50051".to_string()),
        }],
    };

    let peer_addrs = vec![
        "peer-a.local:50051".to_string(),
        "peer-b.local:50052".to_string(), /* no entry */
    ];

    let result = build_peer_connect_infos(&peer_addrs, Some(&allow_list), true /* TLS on */);

    assert!(
        result.is_err(),
        "startup must fail when a DVT peer addr is missing from the allow-list under TLS"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("peer-b.local:50052"),
        "error message must name the offending peer; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: build_peer_connect_infos — no allow-list with TLS fails at startup
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_startup_fails_without_allowlist_when_tls_enabled() {
    let peer_addrs = vec!["peer-a.local:50051".to_string()];
    let result =
        build_peer_connect_infos(&peer_addrs, None /* no allow-list */, true /* TLS */);
    assert!(result.is_err(), "startup must fail when TLS is enabled and no allow-list is provided");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: build_peer_connect_infos — no TLS, any addr is accepted without SNI
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_no_tls_accepts_any_addr() {
    let peer_addrs = vec!["peer-a.local:50051".to_string(), "peer-b.local:50052".to_string()];
    let result = build_peer_connect_infos(&peer_addrs, None, false /* TLS off */);
    assert!(result.is_ok());
    let infos = result.unwrap();
    assert_eq!(infos.len(), 2);
    // sni_cn should be empty when TLS is disabled
    assert!(infos.iter().all(|p| p.sni_cn.is_empty()));
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: build_peer_connect_infos — happy path with full allow-list match
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_dvt_startup_succeeds_when_all_addrs_in_allowlist() {
    let allow_list = AllowedPeers {
        peers: vec![
            AllowedPeer {
                peer_cn: "peer-a.local".to_string(),
                share_index: 1,
                addr: Some("peer-a.local:50051".to_string()),
            },
            AllowedPeer {
                peer_cn: "peer-b.local".to_string(),
                share_index: 2,
                addr: Some("peer-b.local:50052".to_string()),
            },
        ],
    };

    let peer_addrs = vec!["peer-a.local:50051".to_string(), "peer-b.local:50052".to_string()];

    let result = build_peer_connect_infos(&peer_addrs, Some(&allow_list), true);
    assert!(result.is_ok(), "all addrs covered → must succeed; err: {:?}", result.err());

    let infos = result.unwrap();
    assert_eq!(infos[0].sni_cn, "peer-a.local");
    assert_eq!(infos[1].sni_cn, "peer-b.local");
}
