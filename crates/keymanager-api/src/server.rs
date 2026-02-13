use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::auth;
use crate::handlers::{self, AppState};
use crate::traits::{
    DoppelgangerMonitor, KeystoreManager, RemoteKeyManager, SlashingProtection, ValidatorManager,
};

pub const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 5062);

pub struct KeymanagerServer {
    state: Arc<AppState>,
    token: Arc<String>,
    addr: SocketAddr,
}

impl KeymanagerServer {
    pub fn new(
        keystore_manager: Arc<dyn KeystoreManager>,
        slashing_protection: Arc<dyn SlashingProtection>,
        validator_manager: Arc<dyn ValidatorManager>,
        doppelganger_monitor: Arc<dyn DoppelgangerMonitor>,
        remote_key_manager: Arc<dyn RemoteKeyManager>,
        token: String,
        addr: SocketAddr,
    ) -> Self {
        Self {
            state: Arc::new(AppState {
                keystore_manager,
                slashing_protection,
                validator_manager,
                doppelganger_monitor,
                remote_key_manager,
            }),
            token: Arc::new(token),
            addr,
        }
    }

    pub fn router(&self) -> Router {
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
            .with_state(self.state.clone());

        auth::with_auth(api, self.token.clone())
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
}
