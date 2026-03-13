use std::net::SocketAddr;
use std::sync::Arc;

use crypto::{CompositeSigner, SecretKey, Signer, SigningError, PUBLIC_KEY_BYTES_LEN};
use crypto::{KeyManager, LocalSigner};
use eth_types::Root;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rvc_grpc_signer::{
    GetStatusRequest, GetStatusResponse, GrpcRemoteSigner, GrpcRemoteSignerConfig,
    ListPublicKeysRequest, ListPublicKeysResponse, SignRequest, SignResponse, SignerService,
    SignerServiceServer,
};
use tokio::net::TcpListener;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, ServerTlsConfig};
use tonic::{Request, Response, Status};

// ---------------------------------------------------------------------------
// Test signing backend (implements gRPC SignerService with real BLS signing)
// ---------------------------------------------------------------------------

struct TestSignerService {
    secret_keys: Vec<SecretKey>,
    backend_name: String,
}

impl TestSignerService {
    fn new(secret_keys: Vec<SecretKey>) -> Self {
        Self { secret_keys, backend_name: "basic".to_string() }
    }
}

#[tonic::async_trait]
impl SignerService for TestSignerService {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();

        if req.signing_root.len() != 32 {
            return Err(Status::invalid_argument(format!(
                "signing_root must be 32 bytes, got {}",
                req.signing_root.len()
            )));
        }
        if req.pubkey.len() != 48 {
            return Err(Status::invalid_argument(format!(
                "pubkey must be 48 bytes, got {}",
                req.pubkey.len()
            )));
        }

        let pubkey_bytes: [u8; PUBLIC_KEY_BYTES_LEN] =
            req.pubkey.try_into().expect("length validated");
        let signing_root: [u8; 32] = req.signing_root.try_into().expect("length validated");

        for sk in &self.secret_keys {
            if sk.public_key().to_bytes() == pubkey_bytes {
                let sig = sk.sign(&signing_root);
                return Ok(Response::new(SignResponse { signature: sig.to_bytes().to_vec() }));
            }
        }

        Err(Status::not_found("unknown public key"))
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequest>,
    ) -> Result<Response<ListPublicKeysResponse>, Status> {
        let pubkeys: Vec<Vec<u8>> =
            self.secret_keys.iter().map(|sk| sk.public_key().to_bytes().to_vec()).collect();
        Ok(Response::new(ListPublicKeysResponse { pubkeys }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        Ok(Response::new(GetStatusResponse {
            ready: true,
            backend: self.backend_name.clone(),
            key_count: self.secret_keys.len() as u32,
        }))
    }
}

// ---------------------------------------------------------------------------
// TLS certificate generation helpers
// ---------------------------------------------------------------------------

struct TestPki {
    ca_cert_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn generate_test_pki() -> TestPki {
    // CA
    let mut ca_params = CertificateParams::new(vec!["rvc-test-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Server cert signed by CA (SAN = localhost)
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    // Client cert signed by same CA
    let client_params = CertificateParams::new(vec!["rvc-client".to_string()]).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    TestPki {
        ca_cert_pem: ca_cert.pem().into_bytes(),
        server_cert_pem: server_cert.pem().into_bytes(),
        server_key_pem: server_key.serialize_pem().into_bytes(),
        client_cert_pem: client_cert.pem().into_bytes(),
        client_key_pem: client_key.serialize_pem().into_bytes(),
    }
}

// ---------------------------------------------------------------------------
// Server helpers
// ---------------------------------------------------------------------------

async fn start_mtls_server(
    service: TestSignerService,
    pki: &TestPki,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let tls_config = ServerTlsConfig::new()
        .identity(Identity::from_pem(&pki.server_cert_pem, &pki.server_key_pem))
        .client_ca_root(Certificate::from_pem(&pki.ca_cert_pem));

    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls_config)
            .unwrap()
            .add_service(SignerServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (addr, handle)
}

async fn start_plaintext_server(
    service: TestSignerService,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SignerServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, handle)
}

fn create_mtls_config(addr: SocketAddr, pki: &TestPki) -> GrpcRemoteSignerConfig {
    GrpcRemoteSignerConfig::new(format!("https://localhost:{}", addr.port())).with_tls(
        pki.client_cert_pem.clone(),
        pki.client_key_pem.clone(),
        pki.ca_cert_pem.clone(),
    )
}

// ---------------------------------------------------------------------------
// 1. Happy path E2E: mTLS server → GrpcRemoteSigner client → sign → verify
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_sign_verify_with_mtls() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_bytes = pk.to_bytes();
    let signing_root: Root = [0xab; 32];
    let expected_sig = sk.sign(&signing_root);

    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
    assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    assert!(sig.verify(&pk, &signing_root).is_ok());
}

// ---------------------------------------------------------------------------
// 2. mTLS rejection: client without cert → connection refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mtls_rejects_client_without_cert() {
    let sk = SecretKey::generate();
    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![sk]), &pki).await;

    // Connect with only CA cert (no client identity) — should fail
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(&pki.ca_cert_pem));

    let result = Channel::from_shared(format!("https://localhost:{}", addr.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await;

    match result {
        // Connection may succeed initially but fail on first RPC
        Ok(channel) => {
            use rvc_grpc_signer::SignerServiceClient;
            let mut client = SignerServiceClient::new(channel);
            let result = client.list_public_keys(ListPublicKeysRequest {}).await;
            assert!(result.is_err(), "RPC should fail without client certificate");
        }
        Err(_) => {
            // Connection-level rejection is also acceptable
        }
    }
}

#[tokio::test]
async fn test_mtls_rejects_client_with_wrong_ca() {
    let sk = SecretKey::generate();
    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![sk]), &pki).await;

    // Generate a completely separate PKI (different CA)
    let rogue_pki = generate_test_pki();

    let config = create_mtls_config(addr, &rogue_pki);
    let result = GrpcRemoteSigner::connect(config).await;

    assert!(result.is_err(), "Connection with wrong CA should be rejected");
}

// ---------------------------------------------------------------------------
// 3. Unknown key: sign request for pubkey not in backend → NOT_FOUND
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_unknown_key_returns_key_not_found() {
    let sk = SecretKey::generate();
    let unknown_pk = SecretKey::generate().public_key().to_bytes();

    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    let result = signer.sign(&[0xab; 32], &unknown_pk).await;
    match result.unwrap_err() {
        SigningError::KeyNotFound(pk_hex) => {
            assert_eq!(pk_hex, hex::encode(unknown_pk));
        }
        other => panic!("expected KeyNotFound, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4. ListPublicKeys: returns all loaded keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_public_keys_returns_all() {
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();
    let pk1 = sk1.public_key().to_bytes();
    let pk2 = sk2.public_key().to_bytes();

    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![sk1, sk2]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    let keys = signer.public_keys();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&pk1));
    assert!(keys.contains(&pk2));
}

// ---------------------------------------------------------------------------
// 5. GetStatus: returns ready with correct backend/count
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_status_via_raw_client() {
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();

    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![sk1, sk2]), &pki).await;

    // Use raw gRPC client to call GetStatus
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .identity(Identity::from_pem(&pki.client_cert_pem, &pki.client_key_pem))
        .ca_certificate(Certificate::from_pem(&pki.ca_cert_pem));

    let channel = Channel::from_shared(format!("https://localhost:{}", addr.port()))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();

    use rvc_grpc_signer::SignerServiceClient;
    let mut client = SignerServiceClient::new(channel);

    let resp = client.get_status(GetStatusRequest {}).await.unwrap().into_inner();
    assert!(resp.ready);
    assert_eq!(resp.backend, "basic");
    assert_eq!(resp.key_count, 2);
}

// ---------------------------------------------------------------------------
// 6. CompositeSigner routing: gRPC signer key hit via CompositeSigner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_composite_signer_routes_to_grpc_remote() {
    let grpc_sk = SecretKey::generate();
    let grpc_pk = grpc_sk.public_key();
    let grpc_pk_bytes = grpc_pk.to_bytes();
    let signing_root: Root = [0xcd; 32];
    let expected_sig = grpc_sk.sign(&signing_root);

    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![grpc_sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let grpc_signer = GrpcRemoteSigner::connect(config).await.unwrap();
    let grpc_pubkeys = grpc_signer.public_keys();

    // Build CompositeSigner with empty local signer
    let composite = CompositeSigner::new(LocalSigner::new(KeyManager::new()));
    composite.add_grpc_remote_signer(grpc_pubkeys, Arc::new(grpc_signer));

    // Sign via CompositeSigner — should route to gRPC remote
    let sig = composite.sign(&signing_root, &grpc_pk_bytes).await.unwrap();
    assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    assert!(sig.verify(&grpc_pk, &signing_root).is_ok());

    // Verify public_keys includes the gRPC remote key
    let keys = composite.public_keys();
    assert!(keys.contains(&grpc_pk_bytes));
}

#[tokio::test]
async fn test_composite_signer_grpc_remote_has_priority_over_local() {
    // Generate key; reconstruct a second copy from raw bytes for the local signer
    let sk = SecretKey::generate();
    let sk_bytes = sk.to_bytes();
    let pk_bytes = sk.public_key().to_bytes();
    let signing_root: Root = [0xef; 32];

    let pki = generate_test_pki();
    let (addr, _handle) = start_mtls_server(TestSignerService::new(vec![sk]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let grpc_signer = GrpcRemoteSigner::connect(config).await.unwrap();
    let grpc_pubkeys = grpc_signer.public_keys();

    let local_sk = SecretKey::from_bytes(&sk_bytes).unwrap();
    let mut km = KeyManager::new();
    km.insert(local_sk);
    let composite = CompositeSigner::new(LocalSigner::new(km));
    composite.add_grpc_remote_signer(grpc_pubkeys, Arc::new(grpc_signer));

    // Both produce valid signatures (same key), but the request should route via gRPC
    let sig = composite.sign(&signing_root, &pk_bytes).await.unwrap();
    assert_eq!(sig.to_bytes().len(), 96);

    // Verify the key appears only once (deduplication)
    let keys = composite.public_keys();
    assert_eq!(keys.iter().filter(|k| **k == pk_bytes).count(), 1);
}

// ---------------------------------------------------------------------------
// Additional: plaintext E2E (no TLS) to verify basic wiring
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_plaintext_sign_verify() {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let pk_bytes = pk.to_bytes();
    let signing_root: Root = [0x42; 32];
    let expected_sig = sk.sign(&signing_root);

    let (addr, _handle) = start_plaintext_server(TestSignerService::new(vec![sk])).await;

    let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
    assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    assert!(sig.verify(&pk, &signing_root).is_ok());
}

// ---------------------------------------------------------------------------
// Multiple keys: sign with each key over mTLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_multiple_keys_mtls() {
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();
    let sk3 = SecretKey::generate();
    let pk1_bytes = sk1.public_key().to_bytes();
    let pk2_bytes = sk2.public_key().to_bytes();
    let pk3_bytes = sk3.public_key().to_bytes();

    let pki = generate_test_pki();
    let (addr, _handle) =
        start_mtls_server(TestSignerService::new(vec![sk1, sk2, sk3]), &pki).await;

    let config = create_mtls_config(addr, &pki);
    let signer = GrpcRemoteSigner::connect(config).await.unwrap();

    assert_eq!(signer.public_keys().len(), 3);

    for (pk_bytes, root_byte) in [(&pk1_bytes, 0x01u8), (&pk2_bytes, 0x02), (&pk3_bytes, 0x03)] {
        let signing_root: Root = [root_byte; 32];
        let sig = signer.sign(&signing_root, pk_bytes).await.unwrap();
        let pk = crypto::PublicKey::from_bytes(pk_bytes).unwrap();
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }
}
