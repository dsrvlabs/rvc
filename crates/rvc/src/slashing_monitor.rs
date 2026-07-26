//! Background task that monitors validators for slashing events.

use std::sync::Arc;
use std::time::Duration;

use bn_manager::BeaconNodeClient;
use metrics::definitions::RVC_VALIDATORS_SLASHED_TOTAL;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use validator_store::ValidatorStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashedAction {
    DisableOnly,
    Shutdown,
    None,
}

impl std::str::FromStr for SlashedAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disable-only" => Ok(Self::DisableOnly),
            "shutdown" => Ok(Self::Shutdown),
            "none" => Ok(Self::None),
            other => Err(format!(
                "invalid slashed-validators-action '{}': must be one of disable-only, shutdown, none",
                other
            )),
        }
    }
}

/// Result of a single slashed-validator check pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashedOutcome {
    /// No configured shutdown action was taken (including disable-only success).
    NoAction,
    /// A slashed validator was found and the action is [`SlashedAction::Shutdown`].
    ShutdownRequested,
}

/// Epoch interval between slashing checks (`SECONDS_PER_SLOT * SLOTS_PER_EPOCH`).
pub fn epoch_check_interval() -> Duration {
    Duration::from_secs(eth_types::SECONDS_PER_SLOT.saturating_mul(eth_types::SLOTS_PER_EPOCH))
}

/// Query enabled validators and apply the configured slashed action.
///
/// Returns [`SlashedOutcome::ShutdownRequested`] when a slashed validator is
/// found and `action` is [`SlashedAction::Shutdown`]; otherwise
/// [`SlashedOutcome::NoAction`]. Beacon errors fail open.
pub async fn check_slashed_validators(
    beacon: &dyn BeaconNodeClient,
    validator_store: &ValidatorStore,
    action: SlashedAction,
) -> SlashedOutcome {
    if action == SlashedAction::None {
        return SlashedOutcome::NoAction;
    }

    let pubkeys: Vec<String> = validator_store
        .list_enabled_pubkeys()
        .iter()
        .map(|pk| format!("0x{}", hex::encode(pk)))
        .collect();

    if pubkeys.is_empty() {
        debug!("No enabled validators to check for slashing");
        return SlashedOutcome::NoAction;
    }

    let validators = match beacon.get_validators(&pubkeys).await {
        Ok(resp) => resp.data,
        Err(e) => {
            warn!(error = %e, "Failed to query beacon node for validator statuses (fail-open)");
            return SlashedOutcome::NoAction;
        }
    };

    for v in &validators {
        if v.status.contains("slashed") {
            error!(
                pubkey = %v.validator.pubkey,
                status = %v.status,
                index = %v.index,
                "SLASHED VALIDATOR DETECTED"
            );

            RVC_VALIDATORS_SLASHED_TOTAL.inc();

            match action {
                SlashedAction::DisableOnly => {
                    let pk_hex =
                        v.validator.pubkey.strip_prefix("0x").unwrap_or(&v.validator.pubkey);
                    if let Ok(pk_bytes) = hex::decode(pk_hex) {
                        if let Ok(pk) = <[u8; 48]>::try_from(pk_bytes.as_slice()) {
                            validator_store.set_enabled(&pk, false);
                            if let Err(e) = validator_store.save_config() {
                                error!(error = %e, "Failed to persist disabled state for slashed validator");
                            }
                        }
                    }
                }
                SlashedAction::Shutdown => {
                    error!("Shutting down due to slashed validator detection");
                    return SlashedOutcome::ShutdownRequested;
                }
                SlashedAction::None => unreachable!(),
            }
        }
    }

    SlashedOutcome::NoAction
}

/// Spawn the background epoch-tick slashing monitor.
///
/// When a check returns [`SlashedOutcome::ShutdownRequested`], cancels
/// `shutdown_token` so the main runtime `select!` can exit cleanly.
///
/// Does nothing (returns a finished handle) when `action` is
/// [`SlashedAction::None`].
pub fn spawn(
    beacon: Arc<dyn BeaconNodeClient>,
    store: Arc<ValidatorStore>,
    action: SlashedAction,
    shutdown_token: CancellationToken,
) -> JoinHandle<()> {
    spawn_with_interval(beacon, store, action, shutdown_token, epoch_check_interval())
}

fn spawn_with_interval(
    beacon: Arc<dyn BeaconNodeClient>,
    store: Arc<ValidatorStore>,
    action: SlashedAction,
    shutdown_token: CancellationToken,
    interval: Duration,
) -> JoinHandle<()> {
    if action == SlashedAction::None {
        return tokio::spawn(async {});
    }

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown_token.cancelled() => {
                    debug!("Slashing monitor shutting down");
                    break;
                }
            }

            let outcome = check_slashed_validators(beacon.as_ref(), store.as_ref(), action).await;

            if outcome == SlashedOutcome::ShutdownRequested {
                info!("Slashing monitor requested process shutdown");
                shutdown_token.cancel();
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon::{ValidatorData, ValidatorInfo, ValidatorsResponse};
    use bn_manager::MockBeaconNodeClient;

    fn mock_with_validators(validators: Vec<ValidatorData>) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_validators(move |_pubkeys| {
            Ok(ValidatorsResponse { data: validators.clone() })
        })
    }

    fn mock_failing() -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_validators(|_| {
            Err(beacon::BeaconError::HttpError("mock failure".to_string()))
        })
    }

    fn test_pubkey() -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = 0xab;
        pk[1] = 0xcd;
        pk
    }

    fn make_validator_data(pubkey: &[u8; 48], status: &str) -> ValidatorData {
        ValidatorData {
            index: "123".to_string(),
            status: status.to_string(),
            validator: ValidatorInfo { pubkey: format!("0x{}", hex::encode(pubkey)) },
        }
    }

    #[tokio::test]
    async fn test_slashed_validator_disables() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(!store.list_enabled_pubkeys().contains(&pk));
        assert_eq!(outcome, SlashedOutcome::NoAction);
    }

    #[tokio::test]
    async fn test_healthy_status_no_action() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_ongoing")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(store.list_enabled_pubkeys().contains(&pk));
        assert_eq!(outcome, SlashedOutcome::NoAction);
    }

    #[tokio::test]
    async fn test_beacon_error_fail_open() {
        let pk = test_pubkey();
        let beacon = mock_failing();
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly).await;

        assert!(store.list_enabled_pubkeys().contains(&pk));
        assert_eq!(outcome, SlashedOutcome::NoAction);
    }

    #[tokio::test]
    async fn test_check_slashed_validators_returns_shutdown_requested_for_configured_action() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "exited_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::Shutdown).await;

        assert_eq!(outcome, SlashedOutcome::ShutdownRequested);
    }

    #[tokio::test]
    async fn test_check_slashed_validators_returns_no_action_when_none_slashed() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_ongoing")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::Shutdown).await;

        assert_eq!(outcome, SlashedOutcome::NoAction);
        assert!(store.list_enabled_pubkeys().contains(&pk));
    }

    #[tokio::test]
    async fn test_none_action_no_op() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let outcome = check_slashed_validators(&beacon, &store, SlashedAction::None).await;

        assert!(store.list_enabled_pubkeys().contains(&pk));
        assert_eq!(outcome, SlashedOutcome::NoAction);
    }

    #[test]
    fn test_slashed_action_from_str() {
        assert_eq!("disable-only".parse::<SlashedAction>().unwrap(), SlashedAction::DisableOnly);
        assert_eq!("shutdown".parse::<SlashedAction>().unwrap(), SlashedAction::Shutdown);
        assert_eq!("none".parse::<SlashedAction>().unwrap(), SlashedAction::None);
        assert!("invalid".parse::<SlashedAction>().is_err());
    }

    #[test]
    fn test_spawn_uses_epoch_tick_from_eth_types_constants() {
        let interval = epoch_check_interval();
        assert_eq!(
            interval,
            Duration::from_secs(eth_types::SECONDS_PER_SLOT * eth_types::SLOTS_PER_EPOCH)
        );
        // Guard against accidental reintroduction of a hardcoded 12s * 32 loop.
        assert_eq!(interval, Duration::from_secs(12 * 32));
        assert_eq!(eth_types::SECONDS_PER_SLOT, 12);
        assert_eq!(eth_types::SLOTS_PER_EPOCH, 32);
    }

    #[tokio::test]
    async fn test_spawn_cancels_shutdown_token_on_shutdown_requested() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let token = CancellationToken::new();
        let handle = spawn_with_interval(
            Arc::new(beacon),
            Arc::new(store),
            SlashedAction::Shutdown,
            token.clone(),
            Duration::from_millis(5),
        );

        // Wait until the monitor cancels the token (or time out).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !token.is_cancelled() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        assert!(token.is_cancelled(), "spawn must cancel shutdown token on ShutdownRequested");
        handle.await.expect("slashing monitor task should complete");
    }

    #[tokio::test]
    async fn test_spawn_exits_when_shutdown_token_cancelled_externally() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_ongoing")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let token = CancellationToken::new();
        let handle = spawn_with_interval(
            Arc::new(beacon),
            Arc::new(store),
            SlashedAction::DisableOnly,
            token.clone(),
            Duration::from_secs(3600),
        );

        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("slashing monitor task should exit promptly on token cancel")
            .expect("slashing monitor task should complete");
    }
}
