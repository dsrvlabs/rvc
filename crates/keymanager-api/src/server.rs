use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::header;
use axum::http::Method;
use axum::routing::get;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::auth;
use crate::handlers::{self, AppState};
use crate::traits::{
    DoppelgangerMonitor, KeystoreManager, RemoteKeyManager, SlashingProtection, ValidatorManager,
};

pub const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 5062);

pub const DEFAULT_BODY_LIMIT: usize = 10 * 1024 * 1024; // 10 MB

pub struct KeymanagerServer {
    state: Arc<AppState>,
    token: Arc<String>,
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
        token: String,
        addr: SocketAddr,
        cors_origins: Vec<String>,
        body_limit: usize,
        allow_insecure_remote_signer: bool,
    ) -> Self {
        Self {
            state: Arc::new(AppState {
                keystore_manager,
                slashing_protection,
                validator_manager,
                doppelganger_monitor,
                remote_key_manager,
                allow_insecure_remote_signer,
            }),
            token: Arc::new(token),
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
