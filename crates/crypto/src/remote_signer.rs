use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::bls::{Signature, PUBLIC_KEY_BYTES_LEN};
use super::signer_trait::{Signer, SigningError};
use eth_types::Root;

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

        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| SigningError::RemoteSignerError(e.to_string()))?;

        Ok(Self { client, url, pubkeys })
    }

    pub fn url(&self) -> &str {
        &self.url
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

        let request_body = SignRequest { signing_root: format!("0x{}", hex::encode(signing_root)) };

        let response =
            self.client.post(&url).json(&request_body).send().await.map_err(|e| {
                SigningError::RemoteSignerError(format!("HTTP request failed: {e}"))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SigningError::RemoteSignerError(format!(
                "Web3Signer returned {status}: {body}"
            )));
        }

        let sign_response: SignResponse = response
            .json()
            .await
            .map_err(|e| SigningError::RemoteSignerError(format!("invalid response body: {e}")))?;

        let sig_hex =
            sign_response.signature.strip_prefix("0x").unwrap_or(&sign_response.signature);
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| SigningError::RemoteSignerError(format!("invalid signature hex: {e}")))?;

        Signature::from_bytes(&sig_bytes)
            .map_err(|e| SigningError::RemoteSignerError(format!("invalid BLS signature: {e}")))
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.pubkeys.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
        let signer = RemoteSigner::new(config, vec![pk]).unwrap();

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
        let signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

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
        let signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

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
        let signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

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
        let signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

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
        let signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

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
        let signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

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
        let signer: Box<dyn Signer> = Box::new(RemoteSigner::new(config, vec![pk_bytes]).unwrap());

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
        assert_eq!(signer.public_keys().len(), 1);
    }

    #[tokio::test]
    async fn test_remote_signer_strips_trailing_slash_from_url() {
        let config = RemoteSignerConfig::new("http://localhost:9000/");
        let signer = RemoteSigner::new(config, vec![]).unwrap();
        assert_eq!(signer.url(), "http://localhost:9000");
    }

    #[tokio::test]
    async fn test_remote_signer_empty_public_keys() {
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new(config, vec![]).unwrap();
        assert!(signer.public_keys().is_empty());
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
        let signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

        let result = signer.sign(&signing_root, &pk_bytes).await;
        assert!(result.is_ok());
    }
}
