use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

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

pub struct KeymanagerServer {
    state: Arc<AppState>,
    token: Arc<Zeroizing<String>>,
    addr: SocketAddr,
    cors_origins: Vec<String>,
    body_limit: usize,
}

impl KeymanagerServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keystore_manager: Arc<dyn KeystoreManager>,
        slashing_protection: Arc<dyn SlashingProtection>,
        validator_manager: Arc<dyn ValidatorManager>,
        doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
        remote_key_manager: Arc<dyn RemoteKeyManager>,
        config_manager: Arc<dyn ValidatorConfigManager>,
        exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
        token: String,
        addr: SocketAddr,
        cors_origins: Vec<String>,
        body_limit: usize,
        allow_insecure_remote_signer: bool,
        attesting_enabled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            state: Arc::new(AppState {
                keystore_manager,
                slashing_protection,
                validator_manager,
                doppelganger_monitor,
                remote_key_manager,
                config_manager,
                exit_manager,
                allow_insecure_remote_signer,
                attesting_enabled,
            }),
            token: Arc::new(Zeroizing::new(token)),
            addr,
            cors_origins,
            body_limit,
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

    #[test]
    fn test_default_addr() {
        assert_eq!(DEFAULT_ADDR, SocketAddr::from(([127, 0, 0, 1], 5062)));
    }

    #[test]
    fn test_default_body_limit() {
        assert_eq!(DEFAULT_BODY_LIMIT, 10 * 1024 * 1024);
    }
}
