//! Pre-signed voluntary exit preparation.
//!
//! Signs a voluntary exit for a validator and writes the `SignedVoluntaryExit`
//! JSON to a file without submitting it to the beacon node. The exit can later
//! be submitted via the `submit-exit` command or any Beacon API client.

use std::path::{Path, PathBuf};

use eth_types::SignedVoluntaryExit;
use tracing::info;

/// Writes a `SignedVoluntaryExit` to `<output_dir>/<pubkey_hex>_exit.json`
/// with 0o600 permissions (Unix) and returns the output path.
pub fn write_exit_to_file(
    signed_exit: &SignedVoluntaryExit,
    output_dir: &Path,
    pubkey_hex: &str,
) -> Result<PathBuf, PrepareExitError> {
    let json = serde_json::to_string_pretty(signed_exit)
        .map_err(|e| PrepareExitError::Serialize(e.to_string()))?;

    std::fs::create_dir_all(output_dir).map_err(|e| {
        PrepareExitError::Io(format!(
            "failed to create output directory {}: {}",
            output_dir.display(),
            e
        ))
    })?;

    // Strip 0x prefix if present for the filename
    let pubkey_clean = pubkey_hex.strip_prefix("0x").unwrap_or(pubkey_hex);
    let filename = format!("{}_exit.json", pubkey_clean);
    let output_path = output_dir.join(filename);

    write_file_with_permissions(&output_path, json.as_bytes())?;

    info!(path = %output_path.display(), "Pre-signed voluntary exit written");

    Ok(output_path)
}

#[cfg(unix)]
fn write_file_with_permissions(path: &Path, data: &[u8]) -> Result<(), PrepareExitError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file =
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| {
            PrepareExitError::Io(format!("failed to create {}: {}", path.display(), e))
        })?;

    file.write_all(data)
        .map_err(|e| PrepareExitError::Io(format!("failed to write {}: {}", path.display(), e)))?;

    Ok(())
}

#[cfg(not(unix))]
fn write_file_with_permissions(path: &Path, data: &[u8]) -> Result<(), PrepareExitError> {
    std::fs::write(path, data)
        .map_err(|e| PrepareExitError::Io(format!("failed to write {}: {}", path.display(), e)))?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PrepareExitError {
    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("I/O error: {0}")]
    Io(String),
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
    fn test_write_exit_creates_file_with_correct_name() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, dir.path(), "0xabcdef1234567890").unwrap();

        assert_eq!(path.file_name().unwrap(), "abcdef1234567890_exit.json");
        assert!(path.exists());
    }

    #[test]
    fn test_write_exit_json_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, dir.path(), "0xdeadbeef").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: SignedVoluntaryExit = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed.message.epoch, 300_000);
        assert_eq!(parsed.message.validator_index, 12345);
    }

    #[test]
    fn test_write_exit_json_structure() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, dir.path(), "abc123").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert!(json.get("message").is_some());
        assert!(json.get("signature").is_some());
        assert_eq!(json["message"]["epoch"], "300000");
        assert_eq!(json["message"]["validator_index"], "12345");

        let sig_str = json["signature"].as_str().unwrap();
        assert!(sig_str.starts_with("0x"));
        assert_eq!(sig_str.len(), 194); // 0x + 192 hex chars = 96 bytes
    }

    #[cfg(unix)]
    #[test]
    fn test_write_exit_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, dir.path(), "abc").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_write_exit_creates_output_directory() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("exits");
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, &nested, "pk1").unwrap();

        assert!(path.exists());
        assert!(nested.exists());
    }

    #[test]
    fn test_write_exit_duplicate_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        write_exit_to_file(&signed, dir.path(), "dup").unwrap();
        let result = write_exit_to_file(&signed, dir.path(), "dup");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("I/O error"));
    }

    #[test]
    fn test_write_exit_strips_0x_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sample_signed_exit();

        let path = write_exit_to_file(&signed, dir.path(), "0xabcd").unwrap();
        assert_eq!(path.file_name().unwrap(), "abcd_exit.json");

        // Without prefix should also work
        let dir2 = tempfile::tempdir().unwrap();
        let path2 = write_exit_to_file(&signed, dir2.path(), "efgh").unwrap();
        assert_eq!(path2.file_name().unwrap(), "efgh_exit.json");
    }

    #[test]
    fn test_prepare_exit_error_display() {
        let err = PrepareExitError::Serialize("bad json".into());
        assert_eq!(err.to_string(), "serialization error: bad json");

        let err = PrepareExitError::Io("disk full".into());
        assert_eq!(err.to_string(), "I/O error: disk full");
    }
}
