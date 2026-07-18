//! Persistent deletion denylist for Keymanager API deletes (SEC-1b).
//!
//! Keys deleted via the Keymanager API are recorded here so a subsequent boot
//! does not re-activate them from keystore-dir or secret-provider sources
//! (RockLogic restart-resurrection pattern).
//!
//! # Storage
//!
//! Path: `<data_dir>/.rvc.deleted_keys` (typically the keystore directory,
//! sharing the operator's durable volume with `.rvc.lock`).
//!
//! Format: one `0x`-prefixed lowercase 48-byte pubkey hex per line
//! (96 hex chars after optional `0x`). Blank lines and `#` comments are ignored.
//! File mode: `0o600` on Unix. Rewrite uses sibling `.rvc.deleted_keys.tmp`.
//!
//! # Break-glass recovery
//!
//! To force-denylist a pubkey without the API (e.g. after a partial failure):
//! append a line `0x<96-hex>` to `.rvc.deleted_keys` as the process owner,
//! then restart. Malformed lines cause startup load to fail closed.
//!
//! # Semantics
//!
//! - **insert** on `DELETE` before registry removal (additive; retry-safe).
//! - **remove** only after successful intentional re-import via the Keymanager API.
//! - Loaders consult [`DeletionDenylist::contains`] and skip matching keys.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use thiserror::Error;
use tracing::{info, warn};

/// Filename under the data directory for the denylist.
pub const DELETED_KEYS_FILENAME: &str = ".rvc.deleted_keys";

/// Absolute path of the denylist file for `data_dir`.
pub fn deleted_keys_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DELETED_KEYS_FILENAME)
}

/// Errors reading or writing the deletion denylist.
#[derive(Debug, Error)]
pub enum DeletionDenylistError {
    #[error("deletion denylist IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("deletion denylist contains invalid pubkey line in {path}: {line}")]
    InvalidLine { path: PathBuf, line: String },
}

/// Durable set of pubkeys that must not be loaded from any key source.
///
/// Thread-safe: `insert` / `remove` / `contains` may be called from the
/// Keymanager handler and (read-only) from loaders under a shared `Arc`.
pub struct DeletionDenylist {
    path: PathBuf,
    keys: Mutex<HashSet<[u8; 48]>>,
}

impl DeletionDenylist {
    /// Load (or create empty) denylist at `<data_dir>/.rvc.deleted_keys`.
    ///
    /// Missing file is treated as an empty denylist (first boot / no deletes yet).
    pub fn load(data_dir: &Path) -> Result<Self, DeletionDenylistError> {
        let path = deleted_keys_path(data_dir);
        let keys = if path.exists() { load_keys_from_file(&path)? } else { HashSet::new() };
        let count = keys.len();
        if count > 0 {
            info!(
                path = %path.display(),
                count,
                "Loaded deletion denylist"
            );
        }
        Ok(Self { path, keys: Mutex::new(keys) })
    }

    /// Construct an in-memory denylist bound to `path` without reading disk.
    ///
    /// Intended for tests that control persistence explicitly.
    #[cfg(test)]
    pub fn empty_at(path: PathBuf) -> Self {
        Self { path, keys: Mutex::new(HashSet::new()) }
    }

    /// Path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether `pubkey` is denylisted.
    pub fn contains(&self, pubkey: &[u8; 48]) -> bool {
        self.keys.lock().contains(pubkey)
    }

    /// Snapshot of all denylisted pubkeys (for loaders that need a `HashSet`).
    pub fn snapshot(&self) -> HashSet<[u8; 48]> {
        self.keys.lock().clone()
    }

    /// Number of denylisted pubkeys.
    pub fn len(&self) -> usize {
        self.keys.lock().len()
    }

    /// Whether the denylist is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.lock().is_empty()
    }

    /// Record a deleted pubkey. Idempotent; persists immediately.
    pub fn insert(&self, pubkey: &[u8; 48]) -> Result<(), DeletionDenylistError> {
        let mut keys = self.keys.lock();
        if !keys.insert(*pubkey) {
            // Already present — file already has the line.
            return Ok(());
        }
        // Drop the set mutation intent only after durable write succeeds: if
        // append fails, roll back the in-memory insert so state stays consistent.
        if let Err(e) = append_pubkey(&self.path, pubkey) {
            keys.remove(pubkey);
            return Err(e);
        }
        info!(
            pubkey = %format!("0x{}", hex::encode(pubkey)),
            path = %self.path.display(),
            "Recorded key in deletion denylist"
        );
        Ok(())
    }

    /// Clear a denylist entry (intentional re-import). Idempotent; persists.
    pub fn remove(&self, pubkey: &[u8; 48]) -> Result<(), DeletionDenylistError> {
        let mut keys = self.keys.lock();
        if !keys.remove(pubkey) {
            return Ok(());
        }
        if let Err(e) = rewrite_file(&self.path, &keys) {
            // Restore in-memory membership so callers can retry.
            keys.insert(*pubkey);
            return Err(e);
        }
        info!(
            pubkey = %format!("0x{}", hex::encode(pubkey)),
            path = %self.path.display(),
            "Cleared key from deletion denylist (re-import)"
        );
        Ok(())
    }
}

fn parse_pubkey_line(line: &str) -> Option<[u8; 48]> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 48 {
        return None;
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn load_keys_from_file(path: &Path) -> Result<HashSet<[u8; 48]>, DeletionDenylistError> {
    let file = File::open(path)
        .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
    let reader = BufReader::new(file);
    let mut keys = HashSet::new();
    for line_res in reader.lines() {
        let line = line_res
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_pubkey_line(trimmed) {
            Some(pk) => {
                keys.insert(pk);
            }
            None => {
                warn!(
                    path = %path.display(),
                    line = %trimmed,
                    "Skipping invalid denylist line"
                );
                // Fail closed on clearly malformed non-comment content so an
                // operator typo does not silently drop protection. Blank/comment
                // already skipped above; anything else with wrong length/hex is
                // an error.
                return Err(DeletionDenylistError::InvalidLine {
                    path: path.to_path_buf(),
                    line: trimmed.to_string(),
                });
            }
        }
    }
    Ok(keys)
}

fn format_pubkey_line(pubkey: &[u8; 48]) -> String {
    format!("0x{}\n", hex::encode(pubkey))
}

fn set_owner_only_perms(path: &Path) -> Result<(), DeletionDenylistError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
    }
    let _ = path;
    Ok(())
}

fn append_pubkey(path: &Path, pubkey: &[u8; 48]) -> Result<(), DeletionDenylistError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|source| DeletionDenylistError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
        file.write_all(format_pubkey_line(pubkey).as_bytes())
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
        file.sync_all()
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
    }

    #[cfg(not(unix))]
    {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
        file.write_all(format_pubkey_line(pubkey).as_bytes())
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
        file.sync_all()
            .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
    }

    // Ensure mode even if the file already existed with looser perms.
    set_owner_only_perms(path)?;
    Ok(())
}

fn rewrite_file(path: &Path, keys: &HashSet<[u8; 48]>) -> Result<(), DeletionDenylistError> {
    if keys.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(DeletionDenylistError::Io { path: path.to_path_buf(), source });
            }
        }
    }

    // Explicit sibling name (not `with_extension("tmp")` which yields `.rvc.tmp`).
    let tmp_path = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or(DELETED_KEYS_FILENAME)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|source| DeletionDenylistError::Io { path: tmp_path.clone(), source })?;
        for pk in keys {
            file.write_all(format_pubkey_line(pk).as_bytes())
                .map_err(|source| DeletionDenylistError::Io { path: tmp_path.clone(), source })?;
        }
        file.sync_all()
            .map_err(|source| DeletionDenylistError::Io { path: tmp_path.clone(), source })?;
    }

    #[cfg(not(unix))]
    {
        let mut file =
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|source| DeletionDenylistError::Io { path: tmp_path.clone(), source })?;
        for pk in keys {
            file.write_all(format_pubkey_line(pk).as_bytes())
                .map_err(|source| DeletionDenylistError::Io { path: tmp_path.clone(), source })?;
        }
        file.sync_all()
            .map_err(|source| DeletionDenylistError::Io { path: tmp_path.clone(), source })?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|source| DeletionDenylistError::Io { path: path.to_path_buf(), source })?;
    set_owner_only_perms(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_pubkey(seed: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = seed;
        pk[47] = seed.wrapping_add(1);
        pk
    }

    #[test]
    fn test_denylist_persists_across_reload() {
        let dir = TempDir::new().unwrap();
        let path = deleted_keys_path(dir.path());
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        let pk = sample_pubkey(0xAB);
        assert!(!denylist.contains(&pk));
        denylist.insert(&pk).unwrap();
        assert!(denylist.contains(&pk));
        assert!(path.exists());

        // Drop and reload from disk
        drop(denylist);
        let reloaded = DeletionDenylist::load(dir.path()).unwrap();
        assert!(reloaded.contains(&pk), "denylist must survive process restart");
        assert_eq!(reloaded.len(), 1);
    }

    #[test]
    fn test_never_deleted_key_not_in_denylist() {
        let dir = TempDir::new().unwrap();
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        let deleted = sample_pubkey(1);
        let never = sample_pubkey(2);
        denylist.insert(&deleted).unwrap();
        assert!(denylist.contains(&deleted));
        assert!(!denylist.contains(&never));
    }

    #[test]
    fn test_remove_clears_entry_and_persists() {
        let dir = TempDir::new().unwrap();
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        let pk = sample_pubkey(0xCD);
        denylist.insert(&pk).unwrap();
        denylist.remove(&pk).unwrap();
        assert!(!denylist.contains(&pk));

        let reloaded = DeletionDenylist::load(dir.path()).unwrap();
        assert!(!reloaded.contains(&pk));
        assert!(reloaded.is_empty());
    }

    #[test]
    fn test_insert_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        let pk = sample_pubkey(0x11);
        denylist.insert(&pk).unwrap();
        denylist.insert(&pk).unwrap();
        assert_eq!(denylist.len(), 1);

        let reloaded = DeletionDenylist::load(dir.path()).unwrap();
        assert_eq!(reloaded.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_denylist_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        denylist.insert(&sample_pubkey(0x60)).unwrap();

        let meta = fs::metadata(denylist.path()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "denylist file must be 0o600, got {:o}", mode);
    }

    #[test]
    fn test_load_missing_file_is_empty() {
        let dir = TempDir::new().unwrap();
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        assert!(denylist.is_empty());
        assert!(!denylist.path().exists());
    }

    #[test]
    fn test_snapshot_matches_contains() {
        let dir = TempDir::new().unwrap();
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        let a = sample_pubkey(1);
        let b = sample_pubkey(2);
        denylist.insert(&a).unwrap();
        denylist.insert(&b).unwrap();
        let snap = denylist.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains(&a));
        assert!(snap.contains(&b));
    }

    #[test]
    fn test_invalid_line_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = deleted_keys_path(dir.path());
        fs::write(&path, "not-a-pubkey\n").unwrap();
        match DeletionDenylist::load(dir.path()) {
            Err(DeletionDenylistError::InvalidLine { .. }) => {}
            other => panic!("expected InvalidLine, got: {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn test_rewrite_uses_deleted_keys_tmp_sibling() {
        let dir = TempDir::new().unwrap();
        let denylist = DeletionDenylist::load(dir.path()).unwrap();
        let a = sample_pubkey(1);
        let b = sample_pubkey(2);
        denylist.insert(&a).unwrap();
        denylist.insert(&b).unwrap();
        denylist.remove(&a).unwrap(); // triggers rewrite_file

        let bad_tmp = dir.path().join(".rvc.tmp");
        let good_tmp = dir.path().join(".rvc.deleted_keys.tmp");
        assert!(!bad_tmp.exists(), "must not use with_extension tmp name .rvc.tmp");
        // tmp is renamed away on success
        assert!(!good_tmp.exists());
        assert!(denylist.contains(&b));
        assert!(!denylist.contains(&a));
    }
}
