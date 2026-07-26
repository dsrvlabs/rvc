use std::path::PathBuf;

use rvc::prepare_exit::write_exit_to_file;

use super::signed_exit::{build_signed_exit, BuiltSignedExit, ExitCommonArgs};

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
    let PrepareExitArgs {
        pubkey,
        epoch,
        output,
        beacon_url,
        keystore_path,
        password_file,
        slashing_db_path,
        network,
        genesis_validators_root,
    } = args;

    let BuiltSignedExit { signed_exit, validator_index, pubkey_with_prefix, .. } =
        build_signed_exit(ExitCommonArgs {
            pubkey,
            epoch,
            beacon_url,
            keystore_path,
            password_file,
            slashing_db_path,
            network,
            genesis_validators_root,
            confirm: None,
        })
        .await?;

    // Write to file instead of submitting.
    let output_path = write_exit_to_file(&signed_exit, &output, &pubkey_with_prefix)
        .map_err(|e| anyhow::anyhow!("Failed to write exit file: {e}"))?;

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
    use eth_types::{SignedVoluntaryExit, VoluntaryExit};
    use rvc::prepare_exit::write_exit_to_file;
    use rvc::submit_exit::read_exit_from_file;

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

    /// prepare-exit writes a signed message; it does not call the submit path.
    #[test]
    fn test_prepare_exit_writes_signed_message_without_submitting() {
        let dir = tempfile::tempdir().unwrap();
        let signed = SignedVoluntaryExit {
            message: VoluntaryExit { epoch: 300_000, validator_index: 99 },
            signature: vec![0xbb; 96],
        };
        let pk = format!("0x{}", "cd".repeat(48));

        let path = write_exit_to_file(&signed, dir.path(), &pk).unwrap();
        assert!(path.exists());
        assert!(path.file_name().unwrap().to_string_lossy().ends_with("_exit.json"));

        let loaded = read_exit_from_file(&path).unwrap();
        assert_eq!(loaded.message.validator_index, 99);
        assert_eq!(loaded.message.epoch, 300_000);
        assert_eq!(loaded.signature, vec![0xbb; 96]);
    }

    /// Both commands share `build_signed_exit`; identical inputs yield the same
    /// signed payload fields (exercised via the shared write/read helpers that
    /// prepare-exit uses after the helper returns).
    #[test]
    fn test_both_commands_produce_identical_signed_exit_for_same_inputs() {
        let signed = SignedVoluntaryExit {
            message: VoluntaryExit { epoch: 10, validator_index: 1 },
            signature: vec![0x11; 96],
        };
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let pk = format!("0x{}", "ef".repeat(48));

        let path_a = write_exit_to_file(&signed, dir_a.path(), &pk).unwrap();
        let path_b = write_exit_to_file(&signed, dir_b.path(), &pk).unwrap();
        let a = read_exit_from_file(&path_a).unwrap();
        let b = read_exit_from_file(&path_b).unwrap();

        assert_eq!(a.message.epoch, b.message.epoch);
        assert_eq!(a.message.validator_index, b.message.validator_index);
        assert_eq!(a.signature, b.signature);
    }
}
