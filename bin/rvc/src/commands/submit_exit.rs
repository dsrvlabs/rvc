use std::path::PathBuf;

use anyhow::Context;
use beacon::{BeaconClient, BeaconClientConfig};
use tracing::info;

use rvc::submit_exit::read_exit_from_file;

pub struct SubmitExitArgs {
    pub file: PathBuf,
    pub beacon_url: String,
}

pub async fn execute(args: SubmitExitArgs) -> anyhow::Result<()> {
    let signed_exit = read_exit_from_file(&args.file)
        .map_err(|e| anyhow::anyhow!("Failed to read exit file: {}", e))?;

    info!(
        epoch = signed_exit.message.epoch,
        validator_index = signed_exit.message.validator_index,
        file = %args.file.display(),
        "Submitting pre-signed voluntary exit"
    );

    let beacon_config = BeaconClientConfig::new(&args.beacon_url);
    let beacon_client =
        BeaconClient::new(beacon_config).context("Failed to create beacon client")?;

    beacon_client
        .submit_voluntary_exit(&signed_exit)
        .await
        .context("Failed to submit voluntary exit to beacon node")?;

    info!(
        validator_index = signed_exit.message.validator_index,
        epoch = signed_exit.message.epoch,
        "Voluntary exit submitted successfully"
    );

    eprintln!(
        "Voluntary exit submitted successfully for validator {} (epoch {})",
        signed_exit.message.validator_index, signed_exit.message.epoch
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_exit_args() {
        let args = SubmitExitArgs {
            file: PathBuf::from("/tmp/exit.json"),
            beacon_url: "http://localhost:5052".to_string(),
        };

        assert_eq!(args.file, PathBuf::from("/tmp/exit.json"));
        assert_eq!(args.beacon_url, "http://localhost:5052");
    }
}
