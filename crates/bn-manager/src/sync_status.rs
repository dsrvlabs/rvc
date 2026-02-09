use std::sync::Arc;
use std::time::Duration;

use beacon::BeaconClient;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Sync status of a single beacon node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BnSyncStatus {
    /// Node is fully synced and ready for queries.
    Synced,
    /// Node is still syncing (head behind chain tip).
    Syncing,
    /// Node is unreachable (network error, timeout, etc.).
    Unreachable,
}

impl BnSyncStatus {
    /// Returns `true` if the BN is usable for validator duties.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Synced)
    }
}

/// Shared sync status tracker for all configured beacon nodes.
pub type SharedSyncStatuses = Arc<RwLock<Vec<BnSyncStatus>>>;

/// Creates a new shared sync status vector, initially marking all BNs as synced.
pub fn new_shared_sync_statuses(count: usize) -> SharedSyncStatuses {
    Arc::new(RwLock::new(vec![BnSyncStatus::Synced; count]))
}

/// Polls the sync status of all beacon nodes and updates the shared state.
pub async fn check_all_sync_statuses(clients: &[BeaconClient], statuses: &SharedSyncStatuses) {
    let mut new_statuses = Vec::with_capacity(clients.len());

    for (i, client) in clients.iter().enumerate() {
        let status = check_single_sync_status(client).await;
        match status {
            BnSyncStatus::Synced => {
                info!(bn_index = i, endpoint = client.endpoint(), "BN is synced");
            }
            BnSyncStatus::Syncing => {
                warn!(
                    bn_index = i,
                    endpoint = client.endpoint(),
                    "BN is still syncing, will be skipped for duties"
                );
            }
            BnSyncStatus::Unreachable => {
                warn!(bn_index = i, endpoint = client.endpoint(), "BN is unreachable");
            }
        }
        new_statuses.push(status);
    }

    let mut guard = statuses.write().await;
    *guard = new_statuses;
}

/// Checks the sync status of a single beacon node.
async fn check_single_sync_status(client: &BeaconClient) -> BnSyncStatus {
    match client.get_node_syncing().await {
        Ok(response) => {
            if response.data.is_syncing {
                BnSyncStatus::Syncing
            } else {
                BnSyncStatus::Synced
            }
        }
        Err(_) => BnSyncStatus::Unreachable,
    }
}

/// Starts a background task that periodically polls sync status of all BNs.
///
/// The task runs until the shutdown signal fires.
pub fn start_sync_monitor(
    clients: Vec<BeaconClient>,
    statuses: SharedSyncStatuses,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            check_all_sync_statuses(&clients, &statuses).await;

            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    info!("sync monitor shutting down");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- BnSyncStatus unit tests --

    #[test]
    fn test_sync_status_synced_is_usable() {
        assert!(BnSyncStatus::Synced.is_usable());
    }

    #[test]
    fn test_sync_status_syncing_not_usable() {
        assert!(!BnSyncStatus::Syncing.is_usable());
    }

    #[test]
    fn test_sync_status_unreachable_not_usable() {
        assert!(!BnSyncStatus::Unreachable.is_usable());
    }

    #[test]
    fn test_sync_status_eq() {
        assert_eq!(BnSyncStatus::Synced, BnSyncStatus::Synced);
        assert_ne!(BnSyncStatus::Synced, BnSyncStatus::Syncing);
        assert_ne!(BnSyncStatus::Syncing, BnSyncStatus::Unreachable);
    }

    #[test]
    fn test_sync_status_clone() {
        let s = BnSyncStatus::Syncing;
        let c = s;
        assert_eq!(s, c);
    }

    #[test]
    fn test_sync_status_debug() {
        let s = BnSyncStatus::Synced;
        assert!(format!("{:?}", s).contains("Synced"));
    }

    #[test]
    fn test_new_shared_sync_statuses_initial() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let statuses = new_shared_sync_statuses(3);
            let guard = statuses.read().await;
            assert_eq!(guard.len(), 3);
            assert!(guard.iter().all(|s| *s == BnSyncStatus::Synced));
        });
    }

    #[tokio::test]
    async fn test_is_usable_filter_all_synced() {
        let statuses = new_shared_sync_statuses(3);
        let guard = statuses.read().await;
        let usable: Vec<usize> =
            guard.iter().enumerate().filter(|(_, s)| s.is_usable()).map(|(i, _)| i).collect();
        assert_eq!(usable, vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn test_is_usable_filter_some_syncing() {
        let statuses = Arc::new(RwLock::new(vec![
            BnSyncStatus::Synced,
            BnSyncStatus::Syncing,
            BnSyncStatus::Synced,
        ]));
        let guard = statuses.read().await;
        let usable: Vec<usize> =
            guard.iter().enumerate().filter(|(_, s)| s.is_usable()).map(|(i, _)| i).collect();
        assert_eq!(usable, vec![0, 2]);
    }

    #[tokio::test]
    async fn test_is_usable_filter_all_unreachable() {
        let statuses =
            Arc::new(RwLock::new(vec![BnSyncStatus::Unreachable, BnSyncStatus::Unreachable]));
        let guard = statuses.read().await;
        let usable: Vec<usize> =
            guard.iter().enumerate().filter(|(_, s)| s.is_usable()).map(|(i, _)| i).collect();
        assert!(usable.is_empty());
    }

    #[tokio::test]
    async fn test_is_usable_filter_mixed() {
        let statuses = Arc::new(RwLock::new(vec![
            BnSyncStatus::Syncing,
            BnSyncStatus::Synced,
            BnSyncStatus::Unreachable,
            BnSyncStatus::Synced,
        ]));
        let guard = statuses.read().await;
        let usable: Vec<usize> =
            guard.iter().enumerate().filter(|(_, s)| s.is_usable()).map(|(i, _)| i).collect();
        assert_eq!(usable, vec![1, 3]);
    }

    // -- Integration tests with wiremock --

    use beacon::BeaconClientConfig;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SYNCED_RESPONSE: &str = r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#;
    const SYNCING_RESPONSE: &str = r#"{"data":{"head_slot":"500","sync_distance":"500","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;

    fn make_client(endpoint: &str) -> BeaconClient {
        let config = BeaconClientConfig::new(endpoint).with_max_retries(0);
        BeaconClient::new(config).unwrap()
    }

    #[tokio::test]
    async fn test_check_all_sync_statuses_all_synced() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server2)
            .await;

        let clients = vec![make_client(&server1.uri()), make_client(&server2.uri())];
        let statuses = new_shared_sync_statuses(2);

        check_all_sync_statuses(&clients, &statuses).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0], BnSyncStatus::Synced);
        assert_eq!(guard[1], BnSyncStatus::Synced);
    }

    #[tokio::test]
    async fn test_check_all_sync_statuses_one_syncing() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_RESPONSE))
            .mount(&server2)
            .await;

        let clients = vec![make_client(&server1.uri()), make_client(&server2.uri())];
        let statuses = new_shared_sync_statuses(2);

        check_all_sync_statuses(&clients, &statuses).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0], BnSyncStatus::Synced);
        assert_eq!(guard[1], BnSyncStatus::Syncing);
    }

    #[tokio::test]
    async fn test_check_all_sync_statuses_unreachable() {
        let server1 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&server1)
            .await;

        let clients = vec![make_client(&server1.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0], BnSyncStatus::Unreachable);
    }

    #[tokio::test]
    async fn test_sync_monitor_runs_and_shuts_down() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle =
            start_sync_monitor(clients, statuses.clone(), Duration::from_millis(50), shutdown_rx);

        // Wait a bit for at least one poll
        tokio::time::sleep(Duration::from_millis(100)).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0], BnSyncStatus::Synced);
        drop(guard);

        // Shut down
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_sync_monitor_detects_status_change() {
        let server = MockServer::start().await;

        // Initially syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_RESPONSE))
            .expect(1..)
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle =
            start_sync_monitor(clients, statuses.clone(), Duration::from_millis(50), shutdown_rx);

        // Wait for initial poll
        tokio::time::sleep(Duration::from_millis(100)).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0], BnSyncStatus::Syncing);
        drop(guard);

        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();
    }
}
