//! Pre-signed voluntary exit submission (`submit-exit` CLI).
//!
//! Reads a stored `SignedVoluntaryExit` JSON file and submits it to a beacon
//! node. No signing keys are required — only the pre-signed exit file and a
//! beacon node endpoint.

use std::path::{Path, PathBuf};

use anyhow::Context;
use beacon::{BeaconClient, BeaconClientConfig};
use eth_types::SignedVoluntaryExit;
use tracing::info;

// ---------------------------------------------------------------------------
// File I/O (formerly crates/rvc/src/submit_exit.rs)
// ---------------------------------------------------------------------------

/// Reads a `SignedVoluntaryExit` from a JSON file.
pub fn read_exit_from_file(path: &Path) -> Result<SignedVoluntaryExit, SubmitExitError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| SubmitExitError::Io(format!("failed to read {}: {}", path.display(), e)))?;

    let signed_exit: SignedVoluntaryExit = serde_json::from_str(&content).map_err(|e| {
        SubmitExitError::Deserialize(format!(
            "failed to parse {} as SignedVoluntaryExit: {}",
            path.display(),
            e
        ))
    })?;

    Ok(signed_exit)
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitExitError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("deserialization error: {0}")]
    Deserialize(String),
}

// ---------------------------------------------------------------------------
// CLI command
// ---------------------------------------------------------------------------

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
    use eth_types::VoluntaryExit;

    fn sample_signed_exit() -> SignedVoluntaryExit {
        SignedVoluntaryExit {
            message: VoluntaryExit { epoch: 300_000, validator_index: 12345 },
            signature: vec![0xaa; 96],
        }
    }

    #[test]
    fn test_submit_exit_args() {
        let args = SubmitExitArgs {
            file: PathBuf::from("/tmp/exit.json"),
            beacon_url: "http://localhost:5052".to_string(),
        };

        assert_eq!(args.file, PathBuf::from("/tmp/exit.json"));
        assert_eq!(args.beacon_url, "http://localhost:5052");
    }

    #[test]
    fn test_read_exit_from_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exit.json");

        let json = serde_json::to_string_pretty(&sample_signed_exit()).unwrap();
        std::fs::write(&path, &json).unwrap();

        let result = read_exit_from_file(&path).unwrap();
        assert_eq!(result.message.epoch, 300_000);
        assert_eq!(result.message.validator_index, 12345);
    }

    #[test]
    fn test_read_exit_from_file_not_found() {
        let result = read_exit_from_file(Path::new("/nonexistent/file.json"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("I/O error"));
    }

    #[test]
    fn test_read_exit_from_file_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not valid json").unwrap();

        let result = read_exit_from_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("deserialization error"));
    }

    #[test]
    fn test_read_exit_from_file_wrong_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong.json");
        std::fs::write(&path, r#"{"foo": "bar"}"#).unwrap();

        let result = read_exit_from_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_exit_roundtrip_with_prepare_exit() {
        use super::super::prepare_exit::write_exit_to_file;

        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let written_path = write_exit_to_file(&signed, dir.path(), "0xdeadbeef").unwrap();
        let loaded = read_exit_from_file(&written_path).unwrap();

        assert_eq!(loaded.message.epoch, signed.message.epoch);
        assert_eq!(loaded.message.validator_index, signed.message.validator_index);
        assert_eq!(loaded.signature, signed.signature);
    }

    #[test]
    fn test_submit_exit_error_display() {
        let err = SubmitExitError::Io("disk failure".into());
        assert_eq!(err.to_string(), "I/O error: disk failure");

        let err = SubmitExitError::Deserialize("missing field".into());
        assert_eq!(err.to_string(), "deserialization error: missing field");
    }
}
