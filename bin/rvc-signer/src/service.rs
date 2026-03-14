use std::sync::Arc;
use std::time::Instant;

use tonic::{Request, Response, Status};
use tracing::Span;

use crate::audit;
use crate::backend::SigningBackend;
use crate::metrics::SignerMetrics;
use crate::proto::signer::signer_service_server::SignerService;
use crate::proto::signer::{
    GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
    SignRequest, SignResponse,
};

pub struct SignerServiceImpl {
    backend: Arc<dyn SigningBackend>,
    backend_name: String,
    metrics: Option<Arc<SignerMetrics>>,
}

impl SignerServiceImpl {
    pub fn new(backend: Arc<dyn SigningBackend>, backend_name: String) -> Self {
        Self { backend, backend_name, metrics: None }
    }

    pub fn with_metrics(mut self, metrics: Arc<SignerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

#[tonic::async_trait]
impl SignerService for SignerServiceImpl {
    #[tracing::instrument(name = "rvc.signer.sign", skip_all, fields(pubkey))]
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let client_cn = audit::extract_client_cn(&request);
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

        let pubkey_hex = format!("0x{}", hex::encode(&req.pubkey));
        Span::current().record("pubkey", pubkey_hex.as_str());

        let signing_root: [u8; 32] = req.signing_root.try_into().expect("length already validated");
        let pubkey: [u8; 48] = req.pubkey.try_into().expect("length already validated");

        let start = Instant::now();
        let result = self.backend.sign(&signing_root, &pubkey).await;
        let elapsed = start.elapsed();

        if let Some(ref m) = self.metrics {
            m.sign_duration_seconds
                .with_label_values(&[&self.backend_name])
                .observe(elapsed.as_secs_f64());
        }

        let (grpc_result, audit_result) = match result {
            Ok(signature) => {
                if let Some(ref m) = self.metrics {
                    m.sign_total.with_label_values(&[self.backend_name.as_str(), "success"]).inc();
                }
                (
                    Ok(Response::new(SignResponse { signature: signature.to_vec() })),
                    "success".to_string(),
                )
            }
            Err(ref e) => {
                if let Some(ref m) = self.metrics {
                    m.sign_total.with_label_values(&[self.backend_name.as_str(), "error"]).inc();
                    let error_type = crate::metrics::classify_error(e);
                    m.sign_errors_total
                        .with_label_values(&[self.backend_name.as_str(), error_type])
                        .inc();
                }
                let (status, audit_result) = match e {
                    crate::backend::SigningBackendError::KeyNotFound(_) => {
                        (Status::not_found("unknown public key"), "key_not_found".to_string())
                    }
                    _ => {
                        tracing::error!(error = %e, "signing backend error");
                        (Status::internal("internal signing error"), "error".to_string())
                    }
                };
                (Err(status), audit_result)
            }
        };

        audit::log_audit(&audit::AuditEntry {
            timestamp: audit::now_rfc3339(),
            pubkey_hex,
            client_cn,
            backend: self.backend_name.clone(),
            result: audit_result,
            duration_ms: elapsed.as_millis() as u64,
        });

        grpc_result
    }

    async fn list_public_keys(
        &self,
        _request: Request<ListPublicKeysRequest>,
    ) -> Result<Response<ListPublicKeysResponse>, Status> {
        let pubkeys = self.backend.public_keys().into_iter().map(|pk| pk.to_vec()).collect();
        Ok(Response::new(ListPublicKeysResponse { pubkeys }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let key_count = self.backend.public_keys().len() as u32;
        Ok(Response::new(GetStatusResponse {
            ready: true,
            backend: self.backend_name.clone(),
            key_count,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SigningBackendError;
    use async_trait::async_trait;
    use std::sync::Arc;

    struct MockBackend {
        keys: Vec<[u8; 48]>,
    }

    impl MockBackend {
        fn new(keys: Vec<[u8; 48]>) -> Self {
            Self { keys }
        }

        fn empty() -> Self {
            Self { keys: vec![] }
        }
    }

    #[async_trait]
    impl SigningBackend for MockBackend {
        async fn sign(
            &self,
            _signing_root: &[u8; 32],
            pubkey: &[u8; 48],
        ) -> Result<[u8; 96], SigningBackendError> {
            if self.keys.contains(pubkey) {
                Ok([0xABu8; 96])
            } else {
                Err(SigningBackendError::KeyNotFound(*pubkey))
            }
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.keys.clone()
        }
    }

    fn make_service(backend: MockBackend) -> SignerServiceImpl {
        SignerServiceImpl::new(Arc::new(backend), "basic".to_string())
    }

    // --- Sign RPC tests ---

    #[tokio::test]
    async fn test_sign_valid_request() {
        let pubkey = [1u8; 48];
        let svc = make_service(MockBackend::new(vec![pubkey]));

        let req =
            Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: pubkey.to_vec() });
        let resp = svc.sign(req).await.unwrap();
        assert_eq!(resp.into_inner().signature.len(), 96);
    }

    #[tokio::test]
    async fn test_sign_unknown_key_returns_not_found() {
        let svc = make_service(MockBackend::new(vec![[1u8; 48]]));

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![2u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_sign_invalid_signing_root_length() {
        let svc = make_service(MockBackend::empty());

        let req = Request::new(SignRequest { signing_root: vec![0u8; 16], pubkey: vec![1u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("signing_root"));
    }

    #[tokio::test]
    async fn test_sign_invalid_pubkey_length() {
        let svc = make_service(MockBackend::empty());

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![1u8; 32] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("pubkey"));
    }

    #[tokio::test]
    async fn test_sign_empty_signing_root() {
        let svc = make_service(MockBackend::empty());

        let req = Request::new(SignRequest { signing_root: vec![], pubkey: vec![1u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_sign_empty_pubkey() {
        let svc = make_service(MockBackend::empty());

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // --- ListPublicKeys RPC tests ---

    #[tokio::test]
    async fn test_list_public_keys_returns_all() {
        let keys = vec![[1u8; 48], [2u8; 48]];
        let svc = make_service(MockBackend::new(keys.clone()));

        let resp = svc.list_public_keys(Request::new(ListPublicKeysRequest {})).await.unwrap();
        let pubkeys = resp.into_inner().pubkeys;
        assert_eq!(pubkeys.len(), 2);
        for key in &keys {
            assert!(pubkeys.contains(&key.to_vec()));
        }
    }

    #[tokio::test]
    async fn test_list_public_keys_empty() {
        let svc = make_service(MockBackend::empty());

        let resp = svc.list_public_keys(Request::new(ListPublicKeysRequest {})).await.unwrap();
        assert!(resp.into_inner().pubkeys.is_empty());
    }

    // --- GetStatus RPC tests ---

    #[tokio::test]
    async fn test_get_status_ready() {
        let svc = make_service(MockBackend::new(vec![[1u8; 48], [2u8; 48], [3u8; 48]]));

        let resp = svc.get_status(Request::new(GetStatusRequest {})).await.unwrap();
        let status = resp.into_inner();
        assert!(status.ready);
        assert_eq!(status.backend, "basic");
        assert_eq!(status.key_count, 3);
    }

    #[tokio::test]
    async fn test_get_status_empty_backend() {
        let svc = make_service(MockBackend::empty());

        let resp = svc.get_status(Request::new(GetStatusRequest {})).await.unwrap();
        let status = resp.into_inner();
        assert!(status.ready);
        assert_eq!(status.key_count, 0);
    }

    // --- SigningBackendError propagation ---

    struct FailingBackend;

    #[async_trait]
    impl SigningBackend for FailingBackend {
        async fn sign(
            &self,
            _signing_root: &[u8; 32],
            _pubkey: &[u8; 48],
        ) -> Result<[u8; 96], SigningBackendError> {
            Err(SigningBackendError::SigningFailed("hardware error".to_string()))
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            vec![]
        }
    }

    #[tokio::test]
    async fn test_sign_backend_error_returns_internal() {
        let svc = SignerServiceImpl::new(Arc::new(FailingBackend), "test".to_string());

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![1u8; 48] });
        let err = svc.sign(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    // --- Metrics tests ---

    fn make_service_with_metrics(backend: MockBackend) -> (SignerServiceImpl, Arc<SignerMetrics>) {
        let metrics = Arc::new(SignerMetrics::new());
        let svc = SignerServiceImpl::new(Arc::new(backend), "basic".to_string())
            .with_metrics(Arc::clone(&metrics));
        (svc, metrics)
    }

    #[tokio::test]
    async fn test_sign_success_increments_counter() {
        let pubkey = [1u8; 48];
        let (svc, metrics) = make_service_with_metrics(MockBackend::new(vec![pubkey]));

        let req =
            Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: pubkey.to_vec() });
        svc.sign(req).await.unwrap();

        assert_eq!(metrics.sign_total.with_label_values(&["basic", "success"]).get(), 1);
        assert_eq!(metrics.sign_total.with_label_values(&["basic", "error"]).get(), 0);
    }

    #[tokio::test]
    async fn test_sign_success_records_duration() {
        let pubkey = [1u8; 48];
        let (svc, metrics) = make_service_with_metrics(MockBackend::new(vec![pubkey]));

        let req =
            Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: pubkey.to_vec() });
        svc.sign(req).await.unwrap();

        assert_eq!(
            metrics.sign_duration_seconds.with_label_values(&["basic"]).get_sample_count(),
            1
        );
        assert!(
            metrics.sign_duration_seconds.with_label_values(&["basic"]).get_sample_sum() >= 0.0
        );
    }

    #[tokio::test]
    async fn test_sign_error_increments_error_counter() {
        let (svc, metrics) = make_service_with_metrics(MockBackend::new(vec![[1u8; 48]]));

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![2u8; 48] });
        let _ = svc.sign(req).await;

        assert_eq!(metrics.sign_total.with_label_values(&["basic", "error"]).get(), 1);
        assert_eq!(
            metrics.sign_errors_total.with_label_values(&["basic", "key_not_found"]).get(),
            1
        );
    }

    #[tokio::test]
    async fn test_sign_internal_error_increments_internal_error_counter() {
        let metrics = Arc::new(SignerMetrics::new());
        let svc = SignerServiceImpl::new(Arc::new(FailingBackend), "basic".to_string())
            .with_metrics(Arc::clone(&metrics));

        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![1u8; 48] });
        let _ = svc.sign(req).await;

        assert_eq!(metrics.sign_errors_total.with_label_values(&["basic", "internal"]).get(), 1);
    }

    #[tokio::test]
    async fn test_sign_without_metrics_does_not_panic() {
        let svc = make_service(MockBackend::new(vec![[1u8; 48]]));
        let req = Request::new(SignRequest { signing_root: vec![0u8; 32], pubkey: vec![1u8; 48] });
        svc.sign(req).await.unwrap();
    }
}
