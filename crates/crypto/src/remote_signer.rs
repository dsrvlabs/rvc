use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use url::Url;

use super::bls::{PublicKey, Signature, PUBLIC_KEY_BYTES_LEN};
use super::insecure::{InsecureGate, InsecureMode};
use super::signer_trait::{Signer, SigningError};
use crate::logging::TruncatedPubkey;
use eth_types::Root;

/// Environment variable that must be set to `"true"` to allow plaintext
/// `http://` remote-signer URLs.  `https://` URLs always pass without
/// consulting this variable.
pub const REMOTE_SIGNER_INSECURE_ENV_VAR: &str = "RVC_REMOTE_SIGNER_ALLOW_INSECURE";

/// Gate `url` against the plaintext-URL policy.
///
/// - `https://` URLs pass immediately — no env-var check, no log.
/// - Any other scheme (e.g. `http://`) is evaluated by [`InsecureGate`]:
///   - `mode = Warn` (Phase 2 default): emits an `error!`-level log and
///     returns `Ok(())` so existing deployments are not hard-broken.
///   - `mode = Refuse` (Phase 3, ISSUE-3.13): returns
///     `Err(SigningError::RemoteSignerError(...))` unless the operator has set
///     `RVC_REMOTE_SIGNER_ALLOW_INSECURE=true`.
///
/// The predicate passed to the gate is `|| true`: the scheme check is already
/// done above, so the remaining question is purely "has the operator opted
/// in via the env var?".  Predicate `true` means the gate's combined
/// condition (`env_ok && pred_ok`) becomes `env_ok`, giving clean opt-in
/// semantics.
pub fn check_remote_signer_url(url: &str, mode: InsecureMode) -> Result<(), SigningError> {
    if url.trim_end_matches('/').starts_with("https://") {
        return Ok(());
    }
    InsecureGate::with_predicate(REMOTE_SIGNER_INSECURE_ENV_VAR, mode, || true)
        .check()
        .map_err(|e| SigningError::RemoteSignerError(e.to_string()))
}

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

const DEFAULT_TIMEOUT_SECS: u64 = 12;

#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    pub url: String,
    pub timeout: Duration,
}

impl RemoteSignerConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

pub struct RemoteSigner {
    client: Client,
    url: String,
    pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
}

impl RemoteSigner {
    pub fn new(
        config: RemoteSignerConfig,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    ) -> Result<Self, SigningError> {
        let url = config.url.trim_end_matches('/').to_string();

        // Gate plaintext URLs. Per NFR-10 / ISSUE-3.13 (GA) the gate refuses
        // http:// URLs unless RVC_REMOTE_SIGNER_ALLOW_INSECURE=true is set.
        check_remote_signer_url(&url, InsecureMode::Refuse)?;

        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| SigningError::RemoteSignerError(e.to_string()))?;

        Ok(Self { client, url, pubkeys })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Creates a `RemoteSigner` without running the insecure-URL gate check.
    ///
    /// **For unit tests only.**  Production callers must use [`Self::new`],
    /// which enforces the `InsecureMode::Refuse` gate (ISSUE-3.13 / NFR-10).
    #[cfg(test)]
    pub(crate) fn new_unchecked(
        config: RemoteSignerConfig,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    ) -> Self {
        let url = config.url.trim_end_matches('/').to_string();
        let client =
            Client::builder().timeout(config.timeout).build().expect("test http client build");
        Self { client, url, pubkeys }
    }
}

#[derive(Serialize)]
struct SignRequest {
    signing_root: String,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

#[async_trait]
impl Signer for RemoteSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        if !self.pubkeys.contains(pubkey) {
            return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
        }

        let identifier = format!("0x{}", hex::encode(pubkey));
        let url = format!("{}/api/v1/eth2/sign/{}", self.url, identifier);

        // The logged URL truncates the pubkey path segment (pubkeys are truncated
        // at every level per STANDARD.md) and redacts any credentials; the real
        // request below still uses the full `url`.
        let log_url =
            format!("{}/api/v1/eth2/sign/{}", self.url, TruncatedPubkey::new(&identifier));

        let span = tracing::info_span!(
            "sign.remote",
            http.method = "POST",
            http.url = %redact_url(&log_url),
            http.status_code = tracing::field::Empty,
            signer_type = "remote",
        );

        async {
            let request_body =
                SignRequest { signing_root: format!("0x{}", hex::encode(signing_root)) };

            let response =
                self.client.post(&url).json(&request_body).send().await.map_err(|e| {
                    SigningError::RemoteSignerError(format!("HTTP request failed: {e}"))
                })?;

            let status = response.status();
            tracing::Span::current().record("http.status_code", status.as_u16());

            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(SigningError::RemoteSignerError(format!(
                    "Web3Signer returned {status}: {body}"
                )));
            }

            let sign_response: SignResponse = response.json().await.map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid response body: {e}"))
            })?;

            let sig_hex =
                sign_response.signature.strip_prefix("0x").unwrap_or(&sign_response.signature);
            let sig_bytes = hex::decode(sig_hex).map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid signature hex: {e}"))
            })?;

            let signature = Signature::from_bytes(&sig_bytes).map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid BLS signature: {e}"))
            })?;

            let pk = PublicKey::from_bytes(pubkey)
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid public key: {e}")))?;
            if signature.verify(&pk, signing_root).is_err() {
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                    "Remote signer returned invalid signature"
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
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;
    use crate::SecretKey;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Serialise tests in this module that read or mutate
    /// `RVC_REMOTE_SIGNER_ALLOW_INSECURE`.  Without this lock, parallel
    /// cargo-test execution can race a sibling test setting the var while
    /// `test_remote_signer_refuses_http_url_without_env_var` is running and
    /// silently weaken the GA Refuse contract guard (review MF-3).
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_remote_signer_config_defaults() {
        let config = RemoteSignerConfig::new("http://localhost:9000");
        assert_eq!(config.url, "http://localhost:9000");
        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    #[test]
    fn test_remote_signer_config_custom_timeout() {
        let config =
            RemoteSignerConfig::new("http://localhost:9000").with_timeout(Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_remote_signer_public_keys_returns_configured_keys() {
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![pk]);

        let keys = signer.public_keys();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], pk);
    }

    #[tokio::test]
    async fn test_remote_signer_sign_success() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xab; 32];

        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());

        let sig = result.unwrap();
        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_remote_signer_sign_server_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "internal"})),
            )
            .mount(&mock_server)
            .await;

        let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("500"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_key_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"error": "Key not found"})),
            )
            .mount(&mock_server)
            .await;

        let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("404"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_invalid_signature_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"signature": "0xinvalid"})),
            )
            .mount(&mock_server)
            .await;

        let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("invalid signature hex"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_connection_refused() {
        let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://127.0.0.1:1");
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("HTTP request failed"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_unknown_pubkey_returns_key_not_found() {
        let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let unknown_pk = [0xbb; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&[0xab; 32], &unknown_pk).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::KeyNotFound(pk_hex) => {
                assert_eq!(pk_hex, hex::encode(unknown_pk));
            }
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_object_safety() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer: Box<dyn Signer> = Box::new(RemoteSigner::new_unchecked(config, vec![pk_bytes]));

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
        assert_eq!(signer.public_keys().len(), 1);
    }

    #[tokio::test]
    async fn test_remote_signer_strips_trailing_slash_from_url() {
        let config = RemoteSignerConfig::new("http://localhost:9000/");
        let signer = RemoteSigner::new_unchecked(config, vec![]);
        assert_eq!(signer.url(), "http://localhost:9000");
    }

    #[tokio::test]
    async fn test_remote_signer_empty_public_keys() {
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![]);
        assert!(signer.public_keys().is_empty());
    }

    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;

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
    async fn test_sign_creates_remote_span() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xab; 32];

        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());

        let captured = spans.lock().unwrap();
        assert!(
            captured.contains(&"sign.remote".to_string()),
            "Expected sign.remote span, got: {:?}",
            *captured
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
    }

    #[tokio::test]
    async fn test_sign_span_records_status_code() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xab; 32];

        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(k, v)| k == "http.method" && v == "POST"),
            "Expected http.method=POST, got: {:?}",
            *captured
        );
        assert!(
            captured.iter().any(|(k, v)| k == "signer_type" && v == "remote"),
            "Expected signer_type=remote, got: {:?}",
            *captured
        );
        assert!(
            captured.iter().any(|(k, v)| k == "http.status_code" && v == "200"),
            "Expected http.status_code=200, got: {:?}",
            *captured
        );
    }

    /// Gate 3: the `rvc.sign.remote` span carries the validator pubkey only in
    /// its truncated form. The pubkey is the Web3Signer endpoint's path segment
    /// (`/api/v1/eth2/sign/0x<pubkey>`), so the leak surface is `http.url`; the
    /// full 96-char pubkey hex must never reach the span even though the real
    /// request uses the full URL.
    #[tokio::test]
    async fn test_sign_span_url_truncates_pubkey() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let full_pubkey_hex = hex::encode(pk_bytes);
        let signing_root: Root = [0xab; 32];

        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());

        let captured = fields.lock().unwrap();
        let http_url = captured.iter().find(|(k, _)| k == "http.url");
        assert!(http_url.is_some(), "Expected http.url span field, got: {:?}", *captured);
        let (_, url_value) = http_url.unwrap();
        // Truncated marker present...
        assert!(url_value.contains("..."), "pubkey in URL must be truncated: {url_value}");
        // ...and the full pubkey hex absent — from http.url and from every field.
        assert!(
            !url_value.contains(&full_pubkey_hex),
            "full pubkey hex must never appear in http.url: {url_value}"
        );
        assert!(
            !captured.iter().any(|(_, v)| v.contains(&full_pubkey_hex)),
            "full pubkey hex leaked into a span field: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_sign_span_records_error_status_code() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "internal"})),
            )
            .mount(&mock_server)
            .await;

        let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = signer.sign(&[0xab; 32], &pk_bytes).await;
        assert!(result.is_err());

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(k, v)| k == "http.status_code" && v == "500"),
            "Expected http.status_code=500, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_sign_span_redacts_url_credentials() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xab; 32];

        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        // Use mock server URI but construct a URL with credentials for redaction test
        // We test the redact_url function directly since wiremock uses http://127.0.0.1:PORT
        let url_with_creds = "http://user:secret@signer.example.com:9000";
        let config = RemoteSignerConfig::new(url_with_creds);
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        // This will fail to connect but we just want to check the span field
        let _ = signer.sign(&signing_root, &pk_bytes).await;

        let captured = fields.lock().unwrap();
        let http_url = captured.iter().find(|(k, _)| k == "http.url");
        assert!(http_url.is_some(), "Expected http.url field, got: {:?}", *captured);
        let (_, url_value) = http_url.unwrap();
        assert!(!url_value.contains("user"), "URL should not contain username: {url_value}");
        assert!(!url_value.contains("secret"), "URL should not contain password: {url_value}");
        assert!(url_value.contains("***"), "URL should contain redacted marker: {url_value}");
    }

    #[test]
    fn test_redact_url_hides_credentials() {
        let url = "http://user:pass@example.com:9000/api";
        let redacted = redact_url(url);
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(redacted.contains("***"));
        assert!(redacted.contains("example.com"));
    }

    #[test]
    fn test_redact_url_preserves_url_without_credentials() {
        let url = "http://example.com:9000/api";
        let redacted = redact_url(url);
        assert_eq!(redacted, "http://example.com:9000/api");
    }

    #[test]
    fn test_redact_url_handles_invalid_url() {
        let url = "not-a-url";
        let redacted = redact_url(url);
        assert_eq!(redacted, "not-a-url");
    }

    /// GA regression: `http://` without env var must be refused (ISSUE-3.13 / NFR-10).
    ///
    /// In Phase 2 this returned `Ok` with a log warning.  At GA it must `Err`.
    #[test]
    fn test_remote_signer_refuses_http_url_without_env_var() {
        let _lock = env_lock();
        // Ensure the env var is not set so the gate is in full-Refuse path.
        unsafe { std::env::remove_var(REMOTE_SIGNER_INSECURE_ENV_VAR) };
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://signer.example.com:9000");
        let result = RemoteSigner::new(config, vec![pk]);
        assert!(result.is_err(), "http:// without env var must fail in GA (Refuse mode)");
    }

    #[test]
    fn test_remote_signer_no_warn_on_https_url() {
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("https://signer.example.com:9000");
        let signer = RemoteSigner::new(config, vec![pk]);
        assert!(signer.is_ok());
    }

    #[tokio::test]
    async fn test_remote_signer_sign_sends_correct_request() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xcd; 32];

        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        let expected_path = format!("/api/v1/eth2/sign/0x{}", hex::encode(pk_bytes));
        Mock::given(method("POST"))
            .and(wiremock::matchers::path(expected_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remote_signer_rejects_wrong_key_signature() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        // Sign with a different key
        let wrong_sk = SecretKey::generate();
        let wrong_sig = wrong_sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(wrong_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::InvalidRemoteSignature => {}
            other => panic!("expected InvalidRemoteSignature, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_accepts_correct_signature() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let correct_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(correct_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_bytes(), correct_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_remote_signer_rejects_garbage_signature_bytes() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        // Return valid-length but garbage signature bytes
        let garbage_bytes = [0xffu8; 96];
        let sig_hex = format!("0x{}", hex::encode(garbage_bytes));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_err());
    }
}
