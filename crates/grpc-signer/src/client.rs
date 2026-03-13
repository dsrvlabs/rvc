use async_trait::async_trait;
use tonic::transport::Channel;
use tracing::Instrument;
use url::Url;

use crypto::{PublicKey, Signature, PUBLIC_KEY_BYTES_LEN};
use crypto::{Signer, SigningError};
use eth_types::Root;

use crate::proto::signer::signer_service_client::SignerServiceClient;

fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        if parsed.password().is_some() || !parsed.username().is_empty() {
            let _ = parsed.set_username("***");
            let _ = parsed.set_password(Some("***"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct GrpcRemoteSignerConfig {
    pub url: String,
    pub tls_cert: Option<Vec<u8>>,
    pub tls_key: Option<Vec<u8>>,
    pub tls_ca_cert: Option<Vec<u8>>,
}

impl GrpcRemoteSignerConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), tls_cert: None, tls_key: None, tls_ca_cert: None }
    }

    pub fn with_tls(mut self, cert: Vec<u8>, key: Vec<u8>, ca_cert: Vec<u8>) -> Self {
        self.tls_cert = Some(cert);
        self.tls_key = Some(key);
        self.tls_ca_cert = Some(ca_cert);
        self
    }
}

pub struct GrpcRemoteSigner {
    client: SignerServiceClient<Channel>,
    pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    url: String,
}

impl GrpcRemoteSigner {
    pub async fn connect(config: GrpcRemoteSignerConfig) -> Result<Self, SigningError> {
        let url = config.url.trim_end_matches('/').to_string();

        let channel = if let (Some(cert), Some(key), Some(ca_cert)) =
            (config.tls_cert, config.tls_key, config.tls_ca_cert)
        {
            let tls = tonic::transport::ClientTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(cert, key))
                .ca_certificate(tonic::transport::Certificate::from_pem(ca_cert));

            Channel::from_shared(url.clone())
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid endpoint URL: {e}")))?
                .tls_config(tls)
                .map_err(|e| {
                    SigningError::RemoteSignerError(format!("TLS configuration error: {e}"))
                })?
                .connect()
                .await
                .map_err(|e| {
                    SigningError::RemoteSignerError(format!(
                        "failed to connect to {}: {e}",
                        redact_url(&url)
                    ))
                })?
        } else {
            Channel::from_shared(url.clone())
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid endpoint URL: {e}")))?
                .connect()
                .await
                .map_err(|e| {
                    SigningError::RemoteSignerError(format!(
                        "failed to connect to {}: {e}",
                        redact_url(&url)
                    ))
                })?
        };

        let mut client = SignerServiceClient::new(channel);

        let response =
            client.list_public_keys(crate::ListPublicKeysRequest {}).await.map_err(|e| {
                SigningError::RemoteSignerError(format!("failed to list public keys: {e}"))
            })?;

        let pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]> = response
            .into_inner()
            .pubkeys
            .into_iter()
            .filter_map(|pk_bytes| pk_bytes.try_into().ok())
            .collect();

        tracing::info!(
            url = %redact_url(&url),
            key_count = pubkeys.len(),
            "Connected to gRPC remote signer"
        );

        Ok(Self { client, pubkeys, url })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

#[async_trait]
impl Signer for GrpcRemoteSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        if !self.pubkeys.contains(pubkey) {
            return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
        }

        let span = tracing::info_span!(
            "rvc.sign.grpc_remote",
            rvc.signer_type = "grpc_remote",
            grpc.url = %redact_url(&self.url),
            grpc.status_code = tracing::field::Empty,
        );

        async {
            let request =
                crate::SignRequest { signing_root: signing_root.to_vec(), pubkey: pubkey.to_vec() };

            let mut client = self.client.clone();
            let response = client.sign(request).await.map_err(|status| {
                tracing::Span::current().record("grpc.status_code", status.code() as i32);
                SigningError::RemoteSignerError(format!(
                    "gRPC sign failed ({}): {}",
                    status.code(),
                    status.message()
                ))
            })?;

            tracing::Span::current().record("grpc.status_code", 0i32);

            let sig_bytes = response.into_inner().signature;
            let signature = Signature::from_bytes(&sig_bytes).map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid BLS signature: {e}"))
            })?;

            let pk = PublicKey::from_bytes(pubkey)
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid public key: {e}")))?;
            if signature.verify(&pk, signing_root).is_err() {
                tracing::error!(
                    pubkey = %hex::encode(pubkey),
                    "gRPC remote signer returned invalid signature"
                );
                return Err(SigningError::InvalidRemoteSignature);
            }

            Ok(signature)
        }
        .instrument(span)
        .await
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.pubkeys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::signer::signer_service_server::{SignerService, SignerServiceServer};
    use crate::{
        GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
        SignRequest as ProtoSignRequest, SignResponse as ProtoSignResponse,
    };
    use crypto::SecretKey;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tonic::{Request, Response, Status};
    use tracing_subscriber::layer::SubscriberExt;

    struct MockSignerService {
        secret_keys: Vec<SecretKey>,
        fail_sign: Arc<Mutex<bool>>,
    }

    impl MockSignerService {
        fn new(secret_keys: Vec<SecretKey>) -> Self {
            Self { secret_keys, fail_sign: Arc::new(Mutex::new(false)) }
        }

        fn with_fail_sign(secret_keys: Vec<SecretKey>, fail_sign: Arc<Mutex<bool>>) -> Self {
            Self { secret_keys, fail_sign }
        }
    }

    #[tonic::async_trait]
    impl SignerService for MockSignerService {
        async fn sign(
            &self,
            request: Request<ProtoSignRequest>,
        ) -> Result<Response<ProtoSignResponse>, Status> {
            if *self.fail_sign.lock().unwrap() {
                return Err(Status::internal("mock internal error"));
            }

            let req = request.into_inner();
            let pubkey_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = req
                .pubkey
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid pubkey length"))?;

            for sk in &self.secret_keys {
                if sk.public_key().to_bytes() == pubkey_bytes {
                    let signing_root: [u8; 32] = req
                        .signing_root
                        .try_into()
                        .map_err(|_| Status::invalid_argument("invalid signing root length"))?;
                    let sig = sk.sign(&signing_root);
                    return Ok(Response::new(ProtoSignResponse {
                        signature: sig.to_bytes().to_vec(),
                    }));
                }
            }

            Err(Status::not_found("key not found"))
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
                backend: "mock".to_string(),
                key_count: self.secret_keys.len() as u32,
            }))
        }
    }

    async fn start_mock_server(
        service: MockSignerService,
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

    #[tokio::test]
    async fn test_connect_caches_public_keys() {
        let sk = SecretKey::generate();
        let expected_pk = sk.public_key().to_bytes();
        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let keys = signer.public_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], expected_pk);
    }

    #[tokio::test]
    async fn test_connect_empty_keys() {
        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        assert!(signer.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_sign_success() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];
        let expected_sig = sk.sign(&signing_root);

        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_sign_unknown_key_returns_key_not_found() {
        let sk = SecretKey::generate();
        let unknown_pk = SecretKey::generate().public_key().to_bytes();

        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let result = signer.sign(&[0xab; 32], &unknown_pk).await;
        match result.unwrap_err() {
            SigningError::KeyNotFound(pk_hex) => {
                assert_eq!(pk_hex, hex::encode(unknown_pk));
            }
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_sign_grpc_error_maps_to_remote_signer_error() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let fail_sign = Arc::new(Mutex::new(true));

        let (addr, _handle) =
            start_mock_server(MockSignerService::with_fail_sign(vec![sk], fail_sign)).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("Internal"), "Expected Internal status, got: {msg}");
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_sign_signature_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xcd; 32];

        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_object_safety() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer: Box<dyn Signer> = Box::new(GrpcRemoteSigner::connect(config).await.unwrap());

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
        assert_eq!(signer.public_keys().len(), 1);
    }

    #[tokio::test]
    async fn test_connect_strips_trailing_slash() {
        let sk = SecretKey::generate();
        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}/"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        assert!(!signer.url().ends_with('/'));
    }

    #[tokio::test]
    async fn test_multiple_keys() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk1_bytes = sk1.public_key().to_bytes();
        let pk2_bytes = sk2.public_key().to_bytes();

        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk1, sk2])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        assert_eq!(signer.public_keys().len(), 2);

        let sig1 = signer.sign(&[0xab; 32], &pk1_bytes).await.unwrap();
        assert_eq!(sig1.to_bytes().len(), 96);

        let sig2 = signer.sign(&[0xcd; 32], &pk2_bytes).await.unwrap();
        assert_eq!(sig2.to_bytes().len(), 96);
    }

    struct SpanCapture {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.spans.lock().unwrap().push(attrs.metadata().name().to_string());
        }
    }

    #[tokio::test]
    async fn test_sign_creates_grpc_remote_span() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());

        let captured = spans.lock().unwrap();
        assert!(
            captured.contains(&"rvc.sign.grpc_remote".to_string()),
            "Expected rvc.sign.grpc_remote span, got: {captured:?}",
        );
    }

    struct FieldCapture {
        fields: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
        tracing_subscriber::Layer<S> for FieldCapture
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor(self.fields.clone());
            attrs.record(&mut visitor);
        }

        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor(self.fields.clone());
            values.record(&mut visitor);
        }
    }

    struct FieldVisitor(Arc<Mutex<Vec<(String, String)>>>);

    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.lock().unwrap().push((field.name().to_string(), format!("{:?}", value)));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
        }

        fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
            self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
        }
    }

    #[tokio::test]
    async fn test_sign_span_records_signer_type() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let (addr, _handle) = start_mock_server(MockSignerService::new(vec![sk])).await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(k, v)| k == "rvc.signer_type" && v == "grpc_remote"),
            "Expected rvc.signer_type=grpc_remote, got: {captured:?}",
        );
    }

    #[test]
    fn test_config_new() {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        assert_eq!(config.url, "http://localhost:50051");
        assert!(config.tls_cert.is_none());
        assert!(config.tls_key.is_none());
        assert!(config.tls_ca_cert.is_none());
    }

    #[test]
    fn test_config_with_tls() {
        let config = GrpcRemoteSignerConfig::new("https://localhost:50051").with_tls(
            b"cert".to_vec(),
            b"key".to_vec(),
            b"ca".to_vec(),
        );
        assert!(config.tls_cert.is_some());
        assert!(config.tls_key.is_some());
        assert!(config.tls_ca_cert.is_some());
    }

    enum BadSignMode {
        WrongKey,
        GarbageBytes,
    }

    struct BadSignerService {
        legit_keys: Vec<SecretKey>,
        mode: BadSignMode,
    }

    #[tonic::async_trait]
    impl SignerService for BadSignerService {
        async fn sign(
            &self,
            request: Request<ProtoSignRequest>,
        ) -> Result<Response<ProtoSignResponse>, Status> {
            let req = request.into_inner();
            let signing_root: [u8; 32] = req
                .signing_root
                .try_into()
                .map_err(|_| Status::invalid_argument("invalid signing root length"))?;

            let signature_bytes = match &self.mode {
                BadSignMode::WrongKey => {
                    let wrong_sk = SecretKey::generate();
                    wrong_sk.sign(&signing_root).to_bytes().to_vec()
                }
                BadSignMode::GarbageBytes => vec![0xffu8; 96],
            };

            Ok(Response::new(ProtoSignResponse { signature: signature_bytes }))
        }

        async fn list_public_keys(
            &self,
            _request: Request<ListPublicKeysRequest>,
        ) -> Result<Response<ListPublicKeysResponse>, Status> {
            let pubkeys: Vec<Vec<u8>> =
                self.legit_keys.iter().map(|sk| sk.public_key().to_bytes().to_vec()).collect();
            Ok(Response::new(ListPublicKeysResponse { pubkeys }))
        }

        async fn get_status(
            &self,
            _request: Request<GetStatusRequest>,
        ) -> Result<Response<GetStatusResponse>, Status> {
            Ok(Response::new(GetStatusResponse {
                ready: true,
                backend: "bad_mock".to_string(),
                key_count: self.legit_keys.len() as u32,
            }))
        }
    }

    async fn start_bad_server(
        service: BadSignerService,
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

    #[tokio::test]
    async fn test_sign_wrong_key_signature_rejected() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        let (addr, _handle) = start_bad_server(BadSignerService {
            legit_keys: vec![sk],
            mode: BadSignMode::WrongKey,
        })
        .await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        match result.unwrap_err() {
            SigningError::InvalidRemoteSignature => {}
            other => panic!("expected InvalidRemoteSignature, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_sign_garbage_bytes_rejected() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        let (addr, _handle) = start_bad_server(BadSignerService {
            legit_keys: vec![sk],
            mode: BadSignMode::GarbageBytes,
        })
        .await;

        let config = GrpcRemoteSignerConfig::new(format!("http://{addr}"));
        let signer = GrpcRemoteSigner::connect(config).await.unwrap();

        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        assert!(result.is_err(), "garbage signature bytes should be rejected");
    }

    #[test]
    fn test_redact_url_hides_credentials() {
        let url = "http://user:pass@example.com:50051";
        let redacted = redact_url(url);
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(redacted.contains("***"));
        assert!(redacted.contains("example.com"));
    }

    #[test]
    fn test_redact_url_preserves_url_without_credentials() {
        let url = "http://example.com:50051";
        let redacted = redact_url(url);
        assert_eq!(redacted, "http://example.com:50051/");
    }

    #[test]
    fn test_redact_url_handles_invalid_url() {
        let url = "not-a-url";
        let redacted = redact_url(url);
        assert_eq!(redacted, "not-a-url");
    }
}
