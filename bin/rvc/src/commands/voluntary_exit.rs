use std::path::PathBuf;

use tracing::info;

use super::signed_exit::{build_signed_exit, BuiltSignedExit, ExitCommonArgs};

pub struct VoluntaryExitArgs {
    pub pubkey: String,
    pub epoch: Option<u64>,
    pub confirm: bool,
    pub beacon_url: String,
    pub keystore_path: PathBuf,
    pub password_file: PathBuf,
    pub slashing_db_path: Option<PathBuf>,
    pub network: Option<String>,
    pub genesis_validators_root: Option<String>,
}

pub async fn execute(args: VoluntaryExitArgs) -> anyhow::Result<()> {
    let VoluntaryExitArgs {
        pubkey,
        epoch,
        confirm,
        beacon_url,
        keystore_path,
        password_file,
        slashing_db_path,
        network,
        genesis_validators_root,
    } = args;

    let BuiltSignedExit { signed_exit, validator_index, epoch, beacon_client, .. } =
        build_signed_exit(ExitCommonArgs {
            pubkey,
            epoch,
            beacon_url,
            keystore_path,
            password_file,
            slashing_db_path,
            network,
            genesis_validators_root,
            confirm: Some(confirm),
        })
        .await?;

    beacon_client
        .submit_voluntary_exit(&signed_exit)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to submit voluntary exit to beacon node: {e}"))?;

    info!(validator_index, epoch, "Voluntary exit submitted successfully");
    eprintln!("Voluntary exit submitted successfully for validator {}", validator_index);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voluntary_exit_args_defaults() {
        let args = VoluntaryExitArgs {
            pubkey: "0xabcdef".to_string(),
            epoch: None,
            confirm: false,
            beacon_url: "http://localhost:5052".to_string(),
            keystore_path: PathBuf::from("/tmp/keys"),
            password_file: PathBuf::from("/tmp/password"),
            slashing_db_path: None,
            network: None,
            genesis_validators_root: None,
        };

        assert_eq!(args.pubkey, "0xabcdef");
        assert!(args.epoch.is_none());
        assert!(!args.confirm);
    }

    #[test]
    fn test_voluntary_exit_args_with_epoch() {
        let args = VoluntaryExitArgs {
            pubkey: "0xabcdef".to_string(),
            epoch: Some(100),
            confirm: true,
            beacon_url: "http://localhost:5052".to_string(),
            keystore_path: PathBuf::from("/tmp/keys"),
            password_file: PathBuf::from("/tmp/password"),
            slashing_db_path: None,
            network: None,
            genesis_validators_root: None,
        };

        assert_eq!(args.epoch, Some(100));
        assert!(args.confirm);
    }

    #[test]
    fn test_invalid_network_returns_error() {
        use rvc::config::Network;

        let result = "invalid_network".parse::<Network>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown network"));
    }

    #[test]
    fn test_valid_networks_parse_ok() {
        use rvc::config::Network;

        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("hoodi".parse::<Network>().unwrap(), Network::Hoodi);
        assert_eq!("custom".parse::<Network>().unwrap(), Network::Custom);
    }
}
