use std::path::PathBuf;

use anyhow::{bail, Context};
use beacon::{BeaconClient, BeaconClientConfig};
use tracing::info;

use eth_types::{SignedVoluntaryExit, VoluntaryExit, SLOTS_PER_EPOCH};
use rvc::config::{Config, ServiceBuilder};
use signer::SignerService;

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
    let beacon_config = BeaconClientConfig::new(&args.beacon_url);
    let beacon_client =
        BeaconClient::new(beacon_config).context("Failed to create beacon client")?;

    // Resolve validator index from beacon node
    let pubkey_with_prefix = if args.pubkey.starts_with("0x") {
        args.pubkey.clone()
    } else {
        format!("0x{}", args.pubkey)
    };

    let validators_response = beacon_client
        .get_validators(std::slice::from_ref(&pubkey_with_prefix))
        .await
        .context("Failed to look up validator index from beacon node")?;

    let validator = validators_response
        .data
        .first()
        .ok_or_else(|| anyhow::anyhow!("Validator not found for pubkey: {}", pubkey_with_prefix))?;

    let validator_index: u64 =
        validator.index.parse().context("Failed to parse validator index")?;

    info!(validator_index, pubkey = %pubkey_with_prefix, "Resolved validator index");

    // Determine epoch: use provided or get current from BN
    let epoch = match args.epoch {
        Some(e) => e,
        None => {
            let genesis = beacon_client
                .get_genesis()
                .await
                .context("Failed to get genesis info from beacon node")?;

            let genesis_time: u64 =
                genesis.data.genesis_time.parse().context("Failed to parse genesis time")?;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before UNIX epoch")
                .as_secs();

            let current_slot = now.saturating_sub(genesis_time) / eth_types::SECONDS_PER_SLOT;
            current_slot / SLOTS_PER_EPOCH
        }
    };

    info!(epoch, validator_index, "Preparing voluntary exit");

    // Confirmation
    if !args.confirm {
        eprintln!();
        eprintln!("WARNING: THIS ACTION IS IRREVERSIBLE.");
        eprintln!();
        eprintln!("You are about to submit a voluntary exit for:");
        eprintln!("  Validator index: {}", validator_index);
        eprintln!("  Public key:      {}", pubkey_with_prefix);
        eprintln!("  Exit epoch:      {}", epoch);
        eprintln!();
        eprintln!(
            "The validator will no longer be able to perform duties after the exit is processed."
        );
        eprintln!("Use --confirm to skip this prompt.");
        eprintln!();
        bail!("Voluntary exit aborted: --confirm flag not provided");
    }

    // Build signer
    let mut config = Config {
        beacon_url: args.beacon_url.clone(),
        keystore_path: args.keystore_path,
        password_file: Some(args.password_file),
        genesis_validators_root: args.genesis_validators_root,
        ..Default::default()
    };
    if let Some(db_path) = args.slashing_db_path {
        config.slashing_db_path = db_path;
    }
    if let Some(network) = args.network {
        if let Ok(n) = network.parse() {
            config.network = n;
        }
    }

    let builder = ServiceBuilder::new(config);

    let key_manager = builder.build_key_manager().context("Failed to load validator keys")?;

    let slashing_db = builder.build_slashing_db().context("Failed to open slashing database")?;

    let signer = SignerService::new(key_manager.clone(), slashing_db);

    // Find the pubkey in the key manager
    let pubkey_hex = pubkey_with_prefix.strip_prefix("0x").unwrap_or(&pubkey_with_prefix);
    let pubkey_bytes = hex::decode(pubkey_hex).context("Invalid pubkey hex")?;
    let pubkey = crypto::PublicKey::from_bytes(&pubkey_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {:?}", e))?;

    // Get fork schedule and genesis validators root
    let fork_schedule = builder
        .build_fork_schedule(&beacon_client)
        .await
        .context("Failed to fetch fork schedule")?;

    let genesis_validators_root = builder
        .parse_genesis_validators_root()
        .context("Failed to parse genesis validators root")?;

    // Construct and sign the voluntary exit
    let voluntary_exit = VoluntaryExit { epoch, validator_index };

    let signature = signer
        .sign_voluntary_exit(&voluntary_exit, &pubkey, &fork_schedule, &genesis_validators_root)
        .map_err(|e| anyhow::anyhow!("Failed to sign voluntary exit: {}", e))?;

    let signed_exit =
        SignedVoluntaryExit { message: voluntary_exit, signature: signature.to_bytes().to_vec() };

    // Submit to beacon node
    beacon_client
        .submit_voluntary_exit(&signed_exit)
        .await
        .context("Failed to submit voluntary exit to beacon node")?;

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
    fn test_pubkey_prefix_normalization() {
        let pubkey_no_prefix = "abcdef1234567890";
        let pubkey_with_prefix = "0xabcdef1234567890";

        let normalized1 = if pubkey_no_prefix.starts_with("0x") {
            pubkey_no_prefix.to_string()
        } else {
            format!("0x{}", pubkey_no_prefix)
        };

        let normalized2 = if pubkey_with_prefix.starts_with("0x") {
            pubkey_with_prefix.to_string()
        } else {
            format!("0x{}", pubkey_with_prefix)
        };

        assert_eq!(normalized1, "0xabcdef1234567890");
        assert_eq!(normalized2, "0xabcdef1234567890");
    }
}
