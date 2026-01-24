use std::time::Duration;

use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, warn};

use super::types::AttesterDutiesResponse;
use super::BeaconError;

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_INITIAL_BACKOFF_MS: u64 = 100;

/// Configuration for the beacon node HTTP client.
#[derive(Debug, Clone)]
pub struct BeaconClientConfig {
    pub endpoint: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub initial_backoff: Duration,
}

impl BeaconClientConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff: Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MS),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }
}

/// Async HTTP client wrapper for beacon node communication.
pub struct BeaconClient {
    client: Client,
    config: BeaconClientConfig,
}

impl BeaconClient {
    /// Creates a new BeaconClient with the given configuration.
    pub fn new(config: BeaconClientConfig) -> Result<Self, BeaconError> {
        let endpoint = config.endpoint.trim_end_matches('/');
        if endpoint.is_empty() {
            return Err(BeaconError::InvalidUrl("endpoint URL cannot be empty".to_string()));
        }

        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            return Err(BeaconError::InvalidUrl(format!(
                "endpoint must start with http:// or https://: {}",
                endpoint
            )));
        }

        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| BeaconError::HttpError(e.to_string()))?;

        let config = BeaconClientConfig { endpoint: endpoint.to_string(), ..config };

        Ok(Self { client, config })
    }

    /// Returns the configured endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Returns the configured timeout.
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Performs a GET request with retry logic.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, BeaconError> {
        let url = format!("{}{}", self.config.endpoint, path);
        self.execute_with_retry(|| async { self.client.get(&url).send().await }).await
    }

    /// Performs a POST request with retry logic.
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, BeaconError> {
        let url = format!("{}{}", self.config.endpoint, path);
        self.execute_with_retry(|| async { self.client.post(&url).json(body).send().await }).await
    }

    /// Fetches attester duties for the given epoch and validator indices.
    ///
    /// Returns duties with a dependent root that can be used for cache invalidation.
    /// If the dependent root changes, cached duties should be invalidated.
    pub async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        let path = format!("/eth/v1/validator/duties/attester/{}", epoch);
        self.post(&path, &validator_indices).await
    }

    async fn execute_with_retry<F, Fut, T>(&self, request_fn: F) -> Result<T, BeaconError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
        T: DeserializeOwned,
    {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                let backoff = self.calculate_backoff(attempt - 1);
                debug!(attempt = attempt, backoff_ms = ?backoff.as_millis(), "Retrying request");
                tokio::time::sleep(backoff).await;
            }

            match request_fn().await {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        return response
                            .json::<T>()
                            .await
                            .map_err(|e| BeaconError::ParseError(e.to_string()));
                    }

                    if status.is_client_error() {
                        let message = response.text().await.unwrap_or_default();
                        return Err(BeaconError::ApiError { status: status.as_u16(), message });
                    }

                    if status.is_server_error() {
                        let message = response.text().await.unwrap_or_default();
                        last_error =
                            Some(BeaconError::ApiError { status: status.as_u16(), message });
                        warn!(
                            attempt = attempt,
                            status = status.as_u16(),
                            "Server error, will retry"
                        );
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(BeaconError::ApiError { status: status.as_u16(), message });
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(BeaconError::Timeout);
                        warn!(attempt = attempt, "Request timeout, will retry");
                        continue;
                    }

                    if e.is_connect() || e.is_request() {
                        last_error = Some(BeaconError::HttpError(e.to_string()));
                        warn!(attempt = attempt, error = %e, "Connection error, will retry");
                        continue;
                    }

                    return Err(BeaconError::HttpError(e.to_string()));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| BeaconError::HttpError("Unknown error".to_string())))
    }

    fn calculate_backoff(&self, attempt: u32) -> Duration {
        self.config.initial_backoff * 2u32.pow(attempt)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        value: String,
    }

    #[test]
    fn test_config_default_values() {
        let config = BeaconClientConfig::new("http://localhost:5052");
        assert_eq!(config.endpoint, "http://localhost:5052");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_config_builder_pattern() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_timeout(Duration::from_secs(60))
            .with_max_retries(5)
            .with_initial_backoff(Duration::from_millis(200));

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff, Duration::from_millis(200));
    }

    #[test]
    fn test_client_creation_with_valid_url() {
        let config = BeaconClientConfig::new("http://localhost:5052");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_client_creation_strips_trailing_slash() {
        let config = BeaconClientConfig::new("http://localhost:5052/");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_client_creation_with_https() {
        let config = BeaconClientConfig::new("https://beacon.example.com");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "https://beacon.example.com");
    }

    #[test]
    fn test_client_creation_with_empty_url() {
        let config = BeaconClientConfig::new("");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_client_creation_with_invalid_scheme() {
        let config = BeaconClientConfig::new("ftp://localhost:5052");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_client_creation_without_scheme() {
        let config = BeaconClientConfig::new("localhost:5052");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_timeout_accessor() {
        let config =
            BeaconClientConfig::new("http://localhost:5052").with_timeout(Duration::from_secs(60));
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_calculate_backoff() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_initial_backoff(Duration::from_millis(100));
        let client = BeaconClient::new(config).unwrap();

        assert_eq!(client.calculate_backoff(0), Duration::from_millis(100));
        assert_eq!(client.calculate_backoff(1), Duration::from_millis(200));
        assert_eq!(client.calculate_backoff(2), Duration::from_millis(400));
        assert_eq!(client.calculate_backoff(3), Duration::from_millis(800));
    }

    #[tokio::test]
    async fn test_get_request_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(TestData { value: "success".to_string() }),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: TestData = client.get("/eth/v1/test").await.unwrap();
        assert_eq!(result.value, "success");
    }

    #[tokio::test]
    async fn test_post_request_success() {
        let mock_server = MockServer::start().await;

        let request_body = TestData { value: "request".to_string() };
        let response_body = TestData { value: "response".to_string() };

        Mock::given(method("POST"))
            .and(path("/eth/v1/test"))
            .and(body_json(&request_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: TestData = client.post("/eth/v1/test", &request_body).await.unwrap();
        assert_eq!(result.value, "response");
    }

    #[tokio::test]
    async fn test_client_error_no_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri()).with_max_retries(3);
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 404);
                assert_eq!(message, "Not Found");
            }
            _ => panic!("Expected ApiError with status 404"),
        }
    }

    #[tokio::test]
    async fn test_server_error_triggers_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(4)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        match result {
            Err(BeaconError::ApiError { status, .. }) => {
                assert_eq!(status, 500);
            }
            _ => panic!("Expected ApiError with status 500"),
        }
    }

    #[tokio::test]
    async fn test_retry_success_after_failures() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(2)
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(TestData { value: "recovered".to_string() }),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result: TestData = client.get("/eth/v1/test").await.unwrap();
        assert_eq!(result.value, "recovered");
    }

    #[tokio::test]
    async fn test_parse_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        assert!(matches!(result, Err(BeaconError::ParseError(_))));
    }

    #[tokio::test]
    async fn test_timeout_error_triggers_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/test"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .expect(4)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_timeout(Duration::from_millis(50))
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let result: Result<TestData, _> = client.get("/eth/v1/test").await;

        assert!(matches!(result, Err(BeaconError::Timeout)));
    }

    #[tokio::test]
    async fn test_get_attester_duties_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": false,
            "data": [
                {
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                    "validator_index": "1234",
                    "committee_index": "1",
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "25",
                    "slot": "10000"
                },
                {
                    "pubkey": "0xa1234f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b",
                    "validator_index": "5678",
                    "committee_index": "2",
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "50",
                    "slot": "10001"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .and(body_json(&["1234", "5678"]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string(), "5678".to_string()];
        let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_eq!(
            result.dependent_root,
            "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
        assert!(!result.execution_optimistic);
        assert_eq!(result.data.len(), 2);
        assert_eq!(result.data[0].validator_index, "1234");
        assert_eq!(result.data[0].slot, "10000");
        assert_eq!(result.data[1].validator_index, "5678");
        assert_eq!(result.data[1].slot, "10001");
    }

    #[tokio::test]
    async fn test_get_attester_duties_empty_indices() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": false,
            "data": []
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .and(body_json::<Vec<String>>(vec![]))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices: Vec<String> = vec![];
        let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_eq!(
            result.dependent_root,
            "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
        assert!(result.data.is_empty());
    }

    #[tokio::test]
    async fn test_get_attester_duties_with_execution_optimistic() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": true,
            "data": [
                {
                    "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                    "validator_index": "1234",
                    "committee_index": "1",
                    "committee_length": "128",
                    "committees_at_slot": "64",
                    "validator_committee_index": "25",
                    "slot": "10000"
                }
            ]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/200"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string()];
        let result = client.get_attester_duties(200, &validator_indices).await.unwrap();

        assert!(result.execution_optimistic);
    }

    #[tokio::test]
    async fn test_get_attester_duties_api_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/999"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Invalid epoch"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string()];
        let result = client.get_attester_duties(999, &validator_indices).await;

        match result {
            Err(BeaconError::ApiError { status, message }) => {
                assert_eq!(status, 400);
                assert_eq!(message, "Invalid epoch");
            }
            _ => panic!("Expected ApiError with status 400"),
        }
    }

    #[tokio::test]
    async fn test_get_attester_duties_server_error_with_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(2)
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        let response_body = serde_json::json!({
            "dependent_root": "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "execution_optimistic": false,
            "data": []
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri())
            .with_max_retries(3)
            .with_initial_backoff(Duration::from_millis(1));
        let client = BeaconClient::new(config).unwrap();

        let validator_indices: Vec<String> = vec![];
        let result = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_eq!(
            result.dependent_root,
            "0xdeproot1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        );
    }

    #[tokio::test]
    async fn test_get_attester_duties_dependent_root_changes() {
        let mock_server = MockServer::start().await;

        let response_body_1 = serde_json::json!({
            "dependent_root": "0xroot_a_1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "committee_index": "1",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "25",
                "slot": "10000"
            }]
        });

        let response_body_2 = serde_json::json!({
            "dependent_root": "0xroot_b_1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "execution_optimistic": false,
            "data": [{
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "validator_index": "1234",
                "committee_index": "2",
                "committee_length": "128",
                "committees_at_slot": "64",
                "validator_committee_index": "30",
                "slot": "10001"
            }]
        });

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body_1))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body_2))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = BeaconClientConfig::new(mock_server.uri());
        let client = BeaconClient::new(config).unwrap();

        let validator_indices = vec!["1234".to_string()];

        let result_1 = client.get_attester_duties(100, &validator_indices).await.unwrap();
        let result_2 = client.get_attester_duties(100, &validator_indices).await.unwrap();

        assert_ne!(result_1.dependent_root, result_2.dependent_root);
        assert_eq!(
            result_1.dependent_root,
            "0xroot_a_1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
        assert_eq!(
            result_2.dependent_root,
            "0xroot_b_1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }
}
