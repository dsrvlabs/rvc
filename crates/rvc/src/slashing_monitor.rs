//! Background task that monitors validators for slashing events.

use bn_manager::BeaconNodeClient;
use metrics::definitions::RVC_VALIDATORS_SLASHED_TOTAL;
use tokio::sync::watch;
use tracing::{debug, error, warn};
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

pub async fn check_slashed_validators(
    beacon: &dyn BeaconNodeClient,
    validator_store: &ValidatorStore,
    action: SlashedAction,
    shutdown_tx: &watch::Sender<bool>,
) {
    if action == SlashedAction::None {
        return;
    }

    let pubkeys: Vec<String> = validator_store
        .list_enabled_pubkeys()
        .iter()
        .map(|pk| format!("0x{}", hex::encode(pk)))
        .collect();

    if pubkeys.is_empty() {
        debug!("No enabled validators to check for slashing");
        return;
    }

    let validators = match beacon.get_validators(&pubkeys).await {
        Ok(resp) => resp.data,
        Err(e) => {
            warn!(error = %e, "Failed to query beacon node for validator statuses (fail-open)");
            return;
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
                    let _ = shutdown_tx.send(true);
                    return;
                }
                SlashedAction::None => unreachable!(),
            }
        }
    }
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

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly, &shutdown_tx).await;

        assert!(!store.list_enabled_pubkeys().contains(&pk));
        assert!(!*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn test_healthy_status_no_action() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_ongoing")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly, &shutdown_tx).await;

        assert!(store.list_enabled_pubkeys().contains(&pk));
    }

    #[tokio::test]
    async fn test_beacon_error_fail_open() {
        let pk = test_pubkey();
        let beacon = mock_failing();
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        check_slashed_validators(&beacon, &store, SlashedAction::DisableOnly, &shutdown_tx).await;

        assert!(store.list_enabled_pubkeys().contains(&pk));
    }

    #[tokio::test]
    async fn test_shutdown_mode_sends_signal() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "exited_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        check_slashed_validators(&beacon, &store, SlashedAction::Shutdown, &shutdown_tx).await;

        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn test_none_action_no_op() {
        let pk = test_pubkey();
        let beacon = mock_with_validators(vec![make_validator_data(&pk, "active_slashed")]);
        let store = ValidatorStore::new([0u8; 20], 100);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        check_slashed_validators(&beacon, &store, SlashedAction::None, &shutdown_tx).await;

        assert!(store.list_enabled_pubkeys().contains(&pk));
        assert!(!*shutdown_rx.borrow());
    }

    #[test]
    fn test_slashed_action_from_str() {
        assert_eq!("disable-only".parse::<SlashedAction>().unwrap(), SlashedAction::DisableOnly);
        assert_eq!("shutdown".parse::<SlashedAction>().unwrap(), SlashedAction::Shutdown);
        assert_eq!("none".parse::<SlashedAction>().unwrap(), SlashedAction::None);
        assert!("invalid".parse::<SlashedAction>().is_err());
    }
}
