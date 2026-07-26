//! Atomic create-new file writes with restrictive permissions.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Create a new file at `path` with mode `0o600` (Unix) and write `bytes`.
///
/// Uses [`OpenOptions::create_new`] on **all** platforms so an existing path is
/// never silently overwritten. On Unix the file is created with owner-read/write
/// only (`0o600`).
pub fn write_new_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file =
        options.open(path).with_context(|| format!("Failed to create file: {}", path.display()))?;

    file.write_all(bytes).with_context(|| format!("Failed to write file: {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn test_write_new_0600_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.json");
        std::fs::write(&path, b"prior content").unwrap();

        let err = write_new_0600(&path, b"new content").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("existing.json") || msg.contains(&path.display().to_string()),
            "error should include path: {msg}"
        );
        // Context is path-bearing only; "already exists" comes from the OS error, not a guess.
        assert!(
            !format!("{err}").contains("already exists?"),
            "must not hardcode already-exists guess: {err}"
        );
        let io_err = err
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .expect("root cause should be io::Error");
        assert_eq!(io_err.kind(), ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"prior content");
    }

    #[cfg(unix)]
    #[test]
    fn test_write_new_0600_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        write_new_0600(&path, b"payload").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }

    #[test]
    fn test_write_new_0600_error_includes_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unique-path-marker-xyz.json");
        std::fs::write(&path, b"old").unwrap();

        let err = write_new_0600(&path, b"new").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unique-path-marker-xyz.json"), "error must include path: {msg}");
    }

    #[test]
    fn test_write_new_0600_missing_parent_does_not_claim_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no_such_dir").join("file.json");

        let err = write_new_0600(&path, b"x").unwrap_err();
        let display = format!("{err}");
        let full = format!("{err:#}");
        assert!(
            !display.contains("already exists?") && !full.contains("already exists?"),
            "must not claim already-exists for missing parent: {full}"
        );
        assert!(
            full.contains("file.json") || full.contains(&path.display().to_string()),
            "error must include path: {full}"
        );
        let io_err = err
            .root_cause()
            .downcast_ref::<std::io::Error>()
            .expect("root cause should be io::Error");
        assert_ne!(io_err.kind(), ErrorKind::AlreadyExists);
    }

    #[test]
    fn test_write_new_0600_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.json");
        write_new_0600(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }
}
