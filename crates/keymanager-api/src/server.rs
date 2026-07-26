use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::header;
use axum::http::Method;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use zeroize::Zeroizing;

use crate::auth;
use crate::handlers::{self, AppState};
use crate::traits::{
    DoppelgangerMonitor, KeystoreManager, RemoteKeyManager, SlashingProtection,
    ValidatorConfigManager, ValidatorManager, VoluntaryExitManager,
};

pub const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 5062);

pub const DEFAULT_BODY_LIMIT: usize = 10 * 1024 * 1024; // 10 MB

/// Trait-object dependencies required to assemble a [`KeymanagerServer`].
///
/// Field order matches the former positional parameter list of
/// `KeymanagerServer::new` for reviewability.
pub struct KeymanagerDeps {
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    pub doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
    pub remote_key_manager: Arc<dyn RemoteKeyManager>,
    pub config_manager: Arc<dyn ValidatorConfigManager>,
    pub exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
}

/// Transport and policy settings for a [`KeymanagerServer`].
///
/// Field order matches the former positional parameter list of
/// `KeymanagerServer::new` for reviewability.
pub struct KeymanagerSettings {
    pub token: String,
    pub addr: SocketAddr,
    pub cors_origins: Vec<String>,
    pub body_limit: usize,
    pub allow_insecure_remote_signer: bool,
    pub attesting_enabled: Arc<AtomicBool>,
    pub doppelganger_window: Duration,
}

impl Default for KeymanagerSettings {
    fn default() -> Self {
        Self {
            token: String::new(),
            addr: DEFAULT_ADDR,
            cors_origins: Vec::new(),
            body_limit: DEFAULT_BODY_LIMIT,
            allow_insecure_remote_signer: false,
            attesting_enabled: Arc::new(AtomicBool::new(true)),
            doppelganger_window: Duration::ZERO,
        }
    }
}

pub struct KeymanagerServer {
    state: Arc<AppState>,
    token: Arc<Zeroizing<String>>,
    addr: SocketAddr,
    cors_origins: Vec<String>,
    body_limit: usize,
}

impl KeymanagerServer {
    pub fn new(deps: KeymanagerDeps, settings: KeymanagerSettings) -> Self {
        Self {
            state: Arc::new(AppState {
                keystore_manager: deps.keystore_manager,
                slashing_protection: deps.slashing_protection,
                validator_manager: deps.validator_manager,
                doppelganger_monitor: deps.doppelganger_monitor,
                remote_key_manager: deps.remote_key_manager,
                config_manager: deps.config_manager,
                exit_manager: deps.exit_manager,
                allow_insecure_remote_signer: settings.allow_insecure_remote_signer,
                attesting_enabled: settings.attesting_enabled,
                last_set_attesting_enabled: std::sync::Mutex::new(None),
                import_keystores_rate: std::sync::Mutex::new(std::collections::HashMap::new()),
                doppelganger_window: settings.doppelganger_window,
                cancel_tokens: std::sync::Mutex::new(std::collections::HashMap::new()),
                doppelganger_state_lock: std::sync::Mutex::new(()),
            }),
            token: Arc::new(Zeroizing::new(settings.token)),
            addr: settings.addr,
            cors_origins: settings.cors_origins,
            body_limit: settings.body_limit,
        }
    }

    pub fn router(&self) -> Router {
        let cors = if self.cors_origins.is_empty() {
            CorsLayer::new()
        } else {
            let origins: Vec<_> = self.cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        };

        let api = Router::new()
            .route(
                "/eth/v1/keystores",
                get(handlers::list_keystores)
                    .post(handlers::import_keystores)
                    .delete(handlers::delete_keystores),
            )
            .route(
                "/eth/v1/remotekeys",
                get(handlers::list_remote_keys)
                    .post(handlers::import_remote_keys)
                    .delete(handlers::delete_remote_keys),
            )
            .route(
                "/eth/v1/validator/:pubkey/feerecipient",
                get(handlers::get_fee_recipient)
                    .post(handlers::set_fee_recipient)
                    .delete(handlers::delete_fee_recipient),
            )
            .route(
                "/eth/v1/validator/:pubkey/gas_limit",
                get(handlers::get_gas_limit)
                    .post(handlers::set_gas_limit)
                    .delete(handlers::delete_gas_limit),
            )
            .route(
                "/eth/v1/validator/:pubkey/graffiti",
                get(handlers::get_graffiti)
                    .post(handlers::set_graffiti)
                    .delete(handlers::delete_graffiti),
            )
            .route("/eth/v1/validator/:pubkey/voluntary_exit", post(handlers::sign_voluntary_exit))
            .route("/rvc/v1/validator/:pubkey/prepare_exit", post(handlers::prepare_exit))
            .route("/rvc/v1/attesting", post(handlers::set_attesting_enabled))
            .layer(DefaultBodyLimit::max(self.body_limit))
            .with_state(self.state.clone());

        // CORS wraps outside auth so preflight OPTIONS is handled before token check
        auth::with_auth(api, self.token.clone()).layer(cors)
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        let router = self.router();
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        tracing::info!(addr = %self.addr, "Starting Keymanager API server");
        axum::serve(listener, router).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ApiError;
    use crate::traits::{
        DeleteKeystoreError, DeleteRemoteKeyError, ImportKeystoreError, ImportRemoteKeyError,
        Pubkey,
    };
    use axum::http::StatusCode;
    use tower::ServiceExt;

    /// Path templates registered by [`KeymanagerServer::router`]. Source of truth
    /// for construction tests — probes are derived from this list so a
    /// removed/renamed `.route(...)` fails the live oneshot checks below.
    const REGISTERED_ROUTE_PATHS: &[&str] = &[
        "/eth/v1/keystores",
        "/eth/v1/remotekeys",
        "/eth/v1/validator/:pubkey/feerecipient",
        "/eth/v1/validator/:pubkey/gas_limit",
        "/eth/v1/validator/:pubkey/graffiti",
        "/eth/v1/validator/:pubkey/voluntary_exit",
        "/rvc/v1/validator/:pubkey/prepare_exit",
        "/rvc/v1/attesting",
    ];

    /// Expand an axum path template into a concrete URI for oneshot probing.
    fn concrete_uri(template: &str) -> String {
        template.replace(":pubkey", "0x00")
    }

    /// Method used by the primary handler for each registered path template.
    fn primary_method(template: &str) -> &'static str {
        if template.contains("voluntary_exit")
            || template.contains("prepare_exit")
            || template.ends_with("/attesting")
        {
            "POST"
        } else {
            "GET"
        }
    }

    #[test]
    fn test_default_addr() {
        assert_eq!(DEFAULT_ADDR, SocketAddr::from(([127, 0, 0, 1], 5062)));
    }

    #[test]
    fn test_default_body_limit() {
        assert_eq!(DEFAULT_BODY_LIMIT, 10 * 1024 * 1024);
    }

    #[test]
    fn test_keymanager_settings_default_uses_declared_constants() {
        let settings = KeymanagerSettings::default();
        assert_eq!(settings.addr, DEFAULT_ADDR);
        assert_eq!(settings.body_limit, DEFAULT_BODY_LIMIT);
        assert!(settings.cors_origins.is_empty());
        assert!(!settings.allow_insecure_remote_signer);
        assert_eq!(settings.doppelganger_window, Duration::ZERO);
    }

    struct StubKeystore;
    impl KeystoreManager for StubKeystore {
        fn list_keys(&self) -> Vec<Pubkey> {
            vec![]
        }
        fn has_key(&self, _pubkey: &Pubkey) -> bool {
            false
        }
        fn import_keystore(
            &self,
            _keystore_json: &str,
            _password: &str,
        ) -> Result<Pubkey, ImportKeystoreError> {
            Err(ImportKeystoreError::InvalidKeystore("stub".into()))
        }
        fn delete_keystore(&self, _pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
            Ok(false)
        }
    }

    struct StubSlashing;
    impl SlashingProtection for StubSlashing {
        fn import_interchange(&self, _interchange_json: &str) -> Result<(), String> {
            Ok(())
        }
        fn export_interchange(&self, _pubkeys: &[Pubkey]) -> Result<String, String> {
            Ok(String::new())
        }
    }

    struct StubValidator;
    impl ValidatorManager for StubValidator {
        fn add_validator(&self, _pubkey: Pubkey, _enabled: bool) {}
        fn remove_validator(&self, _pubkey: &Pubkey) -> bool {
            false
        }
        fn set_validator_enabled(&self, _pubkey: &Pubkey, _enabled: bool) {}
    }

    struct StubDoppelganger;
    impl DoppelgangerMonitor for StubDoppelganger {
        fn start_monitoring(&self, _pubkey: Pubkey) {}
        fn stop_monitoring(&self, _pubkey: &Pubkey) {}
        fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool {
            true
        }
    }

    struct StubRemote;
    impl RemoteKeyManager for StubRemote {
        fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
            vec![]
        }
        fn has_remote_key(&self, _pubkey: &Pubkey) -> bool {
            false
        }
        fn import_remote_key(
            &self,
            _pubkey: Pubkey,
            _url: String,
        ) -> Result<(), ImportRemoteKeyError> {
            Ok(())
        }
        fn delete_remote_key(&self, _pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
            Ok(false)
        }
    }

    struct StubConfig;
    impl ValidatorConfigManager for StubConfig {
        fn get_fee_recipient(&self, _pubkey: &Pubkey) -> Result<[u8; 20], ApiError> {
            Ok([0u8; 20])
        }
        fn set_fee_recipient(&self, _pubkey: &Pubkey, _address: [u8; 20]) -> Result<(), ApiError> {
            Ok(())
        }
        fn delete_fee_recipient(&self, _pubkey: &Pubkey) -> Result<(), ApiError> {
            Ok(())
        }
        fn get_gas_limit(&self, _pubkey: &Pubkey) -> Result<u64, ApiError> {
            Ok(0)
        }
        fn set_gas_limit(&self, _pubkey: &Pubkey, _limit: u64) -> Result<(), ApiError> {
            Ok(())
        }
        fn delete_gas_limit(&self, _pubkey: &Pubkey) -> Result<(), ApiError> {
            Ok(())
        }
        fn get_graffiti(&self, _pubkey: &Pubkey) -> Result<String, ApiError> {
            Ok(String::new())
        }
        fn set_graffiti(&self, _pubkey: &Pubkey, _graffiti: &str) -> Result<(), ApiError> {
            Ok(())
        }
        fn delete_graffiti(&self, _pubkey: &Pubkey) -> Result<(), ApiError> {
            Ok(())
        }
    }

    fn stub_deps() -> KeymanagerDeps {
        KeymanagerDeps {
            keystore_manager: Arc::new(StubKeystore),
            slashing_protection: Arc::new(StubSlashing),
            validator_manager: Arc::new(StubValidator),
            doppelganger_monitor: Arc::new(StubDoppelganger),
            remote_key_manager: Arc::new(StubRemote),
            config_manager: Arc::new(StubConfig),
            exit_manager: None,
        }
    }

    /// Builds the server from deps+settings and asserts every snapshot path is
    /// registered on the live router. Probes use a valid Bearer token so the
    /// auth layer is not the discriminator: unregistered paths return 404;
    /// registered paths return any non-404 status from the handler.
    #[tokio::test]
    async fn test_server_new_from_deps_and_settings_builds_same_router() {
        assert_eq!(
            REGISTERED_ROUTE_PATHS.len(),
            8,
            "snapshot must list all eight keymanager routes"
        );

        let token = "test_token".to_string();
        let settings = KeymanagerSettings { token: token.clone(), ..KeymanagerSettings::default() };
        let server = KeymanagerServer::new(stub_deps(), settings);
        let router = server.router();

        let auth_header = format!("Bearer {token}");

        // Control: an unregistered path yields 404 so "not 404" below is meaningful.
        let missing = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/eth/v1/does-not-exist")
                    .header("Authorization", auth_header.as_str())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            missing.status(),
            StatusCode::NOT_FOUND,
            "control path must 404 so registration probes are meaningful"
        );

        for template in REGISTERED_ROUTE_PATHS {
            let uri = concrete_uri(template);
            let method = primary_method(template);
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(&uri)
                        .header("Authorization", auth_header.as_str())
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "router must register template {template} (probed {method} {uri}); got 404"
            );
        }
    }
}
