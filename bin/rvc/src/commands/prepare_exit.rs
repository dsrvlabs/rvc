use std::path::PathBuf;

use anyhow::Context;
use beacon::{BeaconClient, BeaconClientConfig};
use tracing::info;

use eth_types::{SignedVoluntaryExit, VoluntaryExit, SLOTS_PER_EPOCH};
use rvc::config::{Config, ServiceBuilder};
use rvc::prepare_exit::write_exit_to_file;
use signer::SignerService;

pub struct PrepareExitArgs {
    pub pubkey: String,
    pub epoch: Option<u64>,
    pub output: PathBuf,
    pub beacon_url: String,
    pub keystore_path: PathBuf,
    pub password_file: PathBuf,
    pub slashing_db_path: Option<PathBuf>,
    pub network: Option<String>,
    pub genesis_validators_root: Option<String>,
}

pub async fn execute(args: PrepareExitArgs) -> anyhow::Result<()> {
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

    info!(epoch, validator_index, "Preparing pre-signed voluntary exit");

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
        config.network = network.parse().map_err(|e: String| anyhow::anyhow!("{}", e))?;
    }

    let builder = ServiceBuilder::new(config);

    let key_manager = builder.build_key_manager().context("Failed to load validator keys")?;

    let slashing_db = builder.build_slashing_db().context("Failed to open slashing database")?;

    let key_manager_owned = std::sync::Arc::try_unwrap(key_manager)
        .unwrap_or_else(|_| panic!("single reference to key_manager"));
    let composite_signer = std::sync::Arc::new(crypto::CompositeSigner::new(
        crypto::LocalSigner::new(key_manager_owned),
    ));
    let signer = SignerService::new(composite_signer, slashing_db);

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
        .await
        .map_err(|e| anyhow::anyhow!("Failed to sign voluntary exit: {}", e))?;

    let signed_exit =
        SignedVoluntaryExit { message: voluntary_exit, signature: signature.to_bytes().to_vec() };

    // Write to file instead of submitting
    let output_path = write_exit_to_file(&signed_exit, &args.output, &pubkey_with_prefix)
        .map_err(|e| anyhow::anyhow!("Failed to write exit file: {}", e))?;

    eprintln!(
        "Pre-signed voluntary exit for validator {} written to: {}",
        validator_index,
        output_path.display()
    );
    eprintln!("Use 'rvc submit-exit --file {}' to submit when ready.", output_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_exit_args_defaults() {
        let args = PrepareExitArgs {
            pubkey: "0xabcdef".to_string(),
            epoch: None,
            output: PathBuf::from("/tmp/exits"),
            beacon_url: "http://localhost:5052".to_string(),
            keystore_path: PathBuf::from("/tmp/keys"),
            password_file: PathBuf::from("/tmp/password"),
            slashing_db_path: None,
            network: None,
            genesis_validators_root: None,
        };

        assert_eq!(args.pubkey, "0xabcdef");
        assert!(args.epoch.is_none());
        assert_eq!(args.output, PathBuf::from("/tmp/exits"));
    }

    #[test]
    fn test_prepare_exit_args_with_all_options() {
        let args = PrepareExitArgs {
            pubkey: "0xabcdef".to_string(),
            epoch: Some(100),
            output: PathBuf::from("/custom/dir"),
            beacon_url: "http://bn:5052".to_string(),
            keystore_path: PathBuf::from("/keys"),
            password_file: PathBuf::from("/pass"),
            slashing_db_path: Some(PathBuf::from("/slashing.db")),
            network: Some("mainnet".to_string()),
            genesis_validators_root: Some("0xaabb".to_string()),
        };

        assert_eq!(args.epoch, Some(100));
        assert_eq!(args.output, PathBuf::from("/custom/dir"));
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
