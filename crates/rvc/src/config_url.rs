//! Proposer configuration from URL with auto-refresh.
//!
//! Implements Prysm/Teku-compatible JSON schema for proposer configuration
//! fetched from a remote URL. Supports per-epoch refresh.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Top-level proposer config response from URL endpoint.
///
/// Compatible with both Prysm (`--proposer-settings-url`) and
/// Teku (`--validators-proposer-config`) JSON schemas.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerConfigResponse {
    #[serde(default)]
    pub proposer_config: HashMap<String, ProposerEntry>,
    pub default_config: Option<ProposerEntry>,
}

/// Per-validator proposer configuration entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerEntry {
    pub fee_recipient: Option<String>,
    #[serde(default)]
    pub builder: Option<BuilderEntry>,
}

/// Builder configuration within a proposer entry.
#[derive(Debug, Clone, Deserialize)]
pub struct BuilderEntry {
    pub enabled: Option<bool>,
    pub gas_limit: Option<String>,
}

/// Parsed proposer configuration update for a single validator.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorConfigUpdate {
    pub pubkey: String,
    pub fee_recipient: Option<String>,
    pub builder_enabled: Option<bool>,
    pub gas_limit: Option<u64>,
}

/// Configuration for the proposer config URL refresh task.
#[derive(Debug, Clone)]
pub struct ProposerConfigUrlSettings {
    pub url: String,
    pub refresh_interval: Duration,
    pub token: Option<String>,
    pub insecure: bool,
}

/// Fetches proposer configuration from the given URL.
///
/// Returns a list of per-validator config updates and an optional default config.
/// Supports Bearer token authentication and HTTPS enforcement.
pub async fn fetch_proposer_config(
    url: &str,
    token: Option<&str>,
    insecure: bool,
) -> Result<(Vec<ValidatorConfigUpdate>, Option<ValidatorConfigUpdate>), String> {
    if !insecure && !url.starts_with("https://") {
        return Err(
            "proposer config URL requires HTTPS; use --proposer-config-url-insecure for HTTP"
                .to_string(),
        );
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))?;

    let mut request = client.get(url);
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }

    let response =
        request.send().await.map_err(|e| format!("failed to fetch proposer config: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("proposer config URL returned HTTP {}", response.status()));
    }

    let body: ProposerConfigResponse =
        response.json().await.map_err(|e| format!("failed to parse proposer config JSON: {e}"))?;

    let mut updates = Vec::new();
    for (pubkey, entry) in &body.proposer_config {
        updates.push(entry_to_update(pubkey.clone(), entry));
    }

    let default_update =
        body.default_config.as_ref().map(|entry| entry_to_update("default".to_string(), entry));

    Ok((updates, default_update))
}

fn entry_to_update(pubkey: String, entry: &ProposerEntry) -> ValidatorConfigUpdate {
    let (builder_enabled, gas_limit) = match &entry.builder {
        Some(b) => (b.enabled, b.gas_limit.as_deref().and_then(|g| g.parse::<u64>().ok())),
        None => (None, None),
    };

    ValidatorConfigUpdate {
        pubkey,
        fee_recipient: entry.fee_recipient.clone(),
        builder_enabled,
        gas_limit,
    }
}

/// Starts the background proposer config refresh task.
///
/// Fetches proposer config from URL at the configured interval and
/// calls `apply_fn` with the parsed updates. On failure, retains existing
/// config and logs at WARN level.
pub async fn start_proposer_config_refresh(
    settings: ProposerConfigUrlSettings,
    shutdown: CancellationToken,
    apply_fn: impl Fn(Vec<ValidatorConfigUpdate>, Option<ValidatorConfigUpdate>) + Send + 'static,
) {
    // Initial fetch at startup
    match fetch_proposer_config(&settings.url, settings.token.as_deref(), settings.insecure).await {
        Ok((updates, default_update)) => {
            let count = updates.len();
            apply_fn(updates, default_update);
            info!(count, "Initial proposer config loaded from URL");
            metrics::definitions::RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL.inc();
        }
        Err(e) => {
            warn!(error = %e, "Failed to load initial proposer config from URL");
            metrics::definitions::RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.inc();
        }
    }

    let mut interval = tokio::time::interval(settings.refresh_interval);
    // Skip the immediate first tick (we already did the initial fetch)
    interval.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                debug!("Proposer config refresh task shutting down");
                return;
            }
            _ = interval.tick() => {
                match fetch_proposer_config(
                    &settings.url,
                    settings.token.as_deref(),
                    settings.insecure,
                ).await {
                    Ok((updates, default_update)) => {
                        let count = updates.len();
                        apply_fn(updates, default_update);
                        debug!(count, "Proposer config refreshed from URL");
                        metrics::definitions::RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL.inc();
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to refresh proposer config from URL, retaining existing config");
                        metrics::definitions::RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.inc();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prysm_compatible_json() {
        let json = r#"{
            "proposer_config": {
                "0x98765": {
                    "fee_recipient": "0xabcd",
                    "builder": {
                        "enabled": true,
                        "gas_limit": "30000000"
                    }
                }
            },
            "default_config": {
                "fee_recipient": "0x1234",
                "builder": {
                    "enabled": true,
                    "gas_limit": "30000000"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.proposer_config.len(), 1);
        assert!(response.default_config.is_some());

        let entry = &response.proposer_config["0x98765"];
        assert_eq!(entry.fee_recipient.as_deref(), Some("0xabcd"));
        assert_eq!(entry.builder.as_ref().unwrap().enabled, Some(true));
        assert_eq!(entry.builder.as_ref().unwrap().gas_limit.as_deref(), Some("30000000"));
    }

    #[test]
    fn test_parse_teku_compatible_json() {
        let json = r#"{
            "proposer_config": {
                "0x98765": {
                    "fee_recipient": "0xabcd",
                    "builder": {
                        "enabled": true,
                        "gas_limit": "36000000"
                    }
                }
            },
            "default_config": {
                "fee_recipient": "0x1234",
                "builder": {
                    "enabled": true,
                    "gas_limit": "36000000"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        let entry = &response.proposer_config["0x98765"];
        assert_eq!(entry.builder.as_ref().unwrap().gas_limit.as_deref(), Some("36000000"));
    }

    #[test]
    fn test_entry_to_update_full() {
        let entry = ProposerEntry {
            fee_recipient: Some("0xabcd".to_string()),
            builder: Some(BuilderEntry {
                enabled: Some(true),
                gas_limit: Some("30000000".to_string()),
            }),
        };

        let update = entry_to_update("0x98765".to_string(), &entry);
        assert_eq!(update.pubkey, "0x98765");
        assert_eq!(update.fee_recipient.as_deref(), Some("0xabcd"));
        assert_eq!(update.builder_enabled, Some(true));
        assert_eq!(update.gas_limit, Some(30000000));
    }

    #[test]
    fn test_entry_to_update_no_builder() {
        let entry = ProposerEntry { fee_recipient: Some("0x1234".to_string()), builder: None };

        let update = entry_to_update("0xabc".to_string(), &entry);
        assert_eq!(update.builder_enabled, None);
        assert_eq!(update.gas_limit, None);
    }

    #[test]
    fn test_entry_to_update_invalid_gas_limit() {
        let entry = ProposerEntry {
            fee_recipient: None,
            builder: Some(BuilderEntry {
                enabled: Some(false),
                gas_limit: Some("not_a_number".to_string()),
            }),
        };

        let update = entry_to_update("0xdef".to_string(), &entry);
        assert_eq!(update.gas_limit, None);
    }

    #[test]
    fn test_parse_empty_proposer_config() {
        let json = r#"{
            "proposer_config": {},
            "default_config": {
                "fee_recipient": "0x1234"
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert!(response.proposer_config.is_empty());
        assert!(response.default_config.is_some());
    }

    #[test]
    fn test_parse_no_default_config() {
        let json = r#"{
            "proposer_config": {
                "0x111": {
                    "fee_recipient": "0x222"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.proposer_config.len(), 1);
        assert!(response.default_config.is_none());
    }

    #[tokio::test]
    async fn test_fetch_rejects_http_without_insecure() {
        let result = fetch_proposer_config("http://example.com/config", None, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[tokio::test]
    async fn test_fetch_success_with_mock() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let body = r#"{
            "proposer_config": {
                "0xaaa": {
                    "fee_recipient": "0xbbb",
                    "builder": { "enabled": true, "gas_limit": "30000000" }
                }
            },
            "default_config": {
                "fee_recipient": "0xccc",
                "builder": { "enabled": false }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, default_update) =
            fetch_proposer_config(&mock_server.uri(), None, true).await.unwrap();

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].pubkey, "0xaaa");
        assert_eq!(updates[0].fee_recipient.as_deref(), Some("0xbbb"));
        assert_eq!(updates[0].builder_enabled, Some(true));
        assert_eq!(updates[0].gas_limit, Some(30000000));

        let default = default_update.unwrap();
        assert_eq!(default.fee_recipient.as_deref(), Some("0xccc"));
        assert_eq!(default.builder_enabled, Some(false));
    }

    #[tokio::test]
    async fn test_fetch_with_bearer_token() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":{}}"#))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (updates, _) =
            fetch_proposer_config(&mock_server.uri(), Some("test-token"), true).await.unwrap();

        assert!(updates.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_http_error_returns_err() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_proposer_config(&mock_server.uri(), None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    #[tokio::test]
    async fn test_refresh_clean_shutdown() {
        let settings = ProposerConfigUrlSettings {
            url: "http://nonexistent.invalid/config".to_string(),
            refresh_interval: Duration::from_millis(50),
            token: None,
            insecure: true,
        };

        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();

        let handle = tokio::spawn(async move {
            start_proposer_config_refresh(settings, shutdown_clone, |_, _| {}).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown.cancel();
        handle.await.unwrap();
    }
}
