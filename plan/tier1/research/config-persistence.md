# Research: Config Persistence Patterns

## Summary

rvc needs atomic TOML config persistence for POST/DELETE operations on fee recipient, gas limit, and graffiti endpoints. The recommended approach uses the `tempfile` crate (already a workspace dependency) with `NamedTempFile::new_in()` + `sync_all()` + `persist()`, serialized through the existing `RwLock`. This is crash-safe, handles concurrent writes, and requires no new dependencies.

## Current State

### Existing Load/Reload Patterns (`store.rs`)

The `ValidatorStore` has two existing methods:

**`load_from_config(path)`** — Reads TOML, parses all validators, creates the store:
```rust
pub fn load_from_config(path: &Path) -> Result<Self, ValidatorStoreError> {
    let content = std::fs::read_to_string(path)?;
    let toml_config: TomlConfig = toml::from_str(&content)?;
    // ... parse defaults and validators ...
    Ok(Self {
        validators: RwLock::new(validators),
        defaults: RwLock::new(defaults),
        config_path: Some(path.to_path_buf()),
    })
}
```

**`reload_config()`** — Hot-reloads from disk, merges new validators:
```rust
pub fn reload_config(&self) -> Result<(), ValidatorStoreError> {
    let path = self.config_path.as_ref().ok_or_else(|| ...)?;
    let content = std::fs::read_to_string(path)?;
    let toml_config: TomlConfig = toml::from_str(&content)?;
    // Parse-first: compute all new values before any mutation
    // Apply-second: all parsing succeeded, now mutate atomically
    *self.defaults.write() = new_defaults;
    let mut validators = self.validators.write();
    for config in &parsed_validators {
        validators.insert(config.pubkey, config.clone());
    }
    Ok(())
}
```

**Key design:** `reload_config()` uses a parse-first, apply-second pattern to avoid partial state corruption. The new `save_config()` should follow a similar philosophy.

### Existing In-Memory Update (`update_config`)

```rust
pub fn update_config(&self, pubkey: &[u8; 48], update: ValidatorConfigUpdate) {
    if let Some(config) = self.validators.write().get_mut(pubkey) {
        if let Some(fr) = update.fee_recipient { config.fee_recipient = fr; }
        if let Some(gl) = update.gas_limit { config.gas_limit = gl; }
        if let Some(g) = update.graffiti { config.graffiti = g; }
        // ...
    }
}
```

This only updates memory. No persistence.

### `ValidatorConfigUpdate` Type

```rust
pub struct ValidatorConfigUpdate {
    pub fee_recipient: Option<Option<[u8; 20]>>,  // None=no change, Some(None)=delete, Some(Some(v))=set
    pub gas_limit: Option<Option<u64>>,
    pub graffiti: Option<Option<[u8; 32]>>,
    pub builder_proposals: Option<bool>,
    pub builder_boost_factor: Option<u64>,
}
```

The `Option<Option<T>>` pattern already supports the three-way semantics needed by the API:
- `None` → no change
- `Some(None)` → DELETE (remove override, revert to default)
- `Some(Some(value))` → POST (set override)

---

## Recommended Approach: `save_config()`

### Dependencies

The `tempfile` crate is already a workspace dependency:
```toml
# Cargo.toml (workspace root)
tempfile = "3"
# crates/validator-store/Cargo.toml
tempfile.workspace = true
```

No new dependencies needed.

### Implementation

```rust
use std::io::Write;

impl ValidatorStore {
    /// Persists the current in-memory state to the TOML config file.
    /// Uses atomic write (temp file + rename) for crash safety.
    pub fn save_config(&self) -> Result<(), ValidatorStoreError> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ValidatorStoreError::Config("no config path set for save".to_string())
        })?;

        let parent = path.parent().unwrap_or(std::path::Path::new("."));

        // Serialize current state while holding read lock
        let toml_content = {
            let defaults = self.defaults.read();
            let validators = self.validators.read();
            serialize_to_toml(&defaults, &validators)?
        };

        // Write to temp file in same directory (same filesystem = rename is atomic)
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| ValidatorStoreError::Io(e))?;

        tmp.write_all(toml_content.as_bytes())
            .map_err(|e| ValidatorStoreError::Io(e))?;

        // Flush to disk before rename for crash safety
        tmp.as_file().sync_all()
            .map_err(|e| ValidatorStoreError::Io(e))?;

        // Atomic rename — replaces the original file
        tmp.persist(path)
            .map_err(|e| ValidatorStoreError::Io(e.error))?;

        Ok(())
    }
}
```

### Serialization Helper

```rust
fn serialize_to_toml(
    defaults: &ValidatorDefaults,
    validators: &HashMap<[u8; 48], ValidatorConfig>,
) -> Result<String, ValidatorStoreError> {
    let mut doc = toml::map::Map::new();

    // Serialize defaults
    let mut defaults_map = toml::map::Map::new();
    defaults_map.insert(
        "fee_recipient".to_string(),
        toml::Value::String(format!("0x{}", hex::encode(defaults.fee_recipient))),
    );
    defaults_map.insert(
        "gas_limit".to_string(),
        toml::Value::Integer(defaults.gas_limit as i64),
    );
    if let Some(graffiti) = &defaults.graffiti {
        let s = std::str::from_utf8(graffiti)
            .unwrap_or("")
            .trim_end_matches('\0');
        if !s.is_empty() {
            defaults_map.insert(
                "graffiti".to_string(),
                toml::Value::String(s.to_string()),
            );
        }
    }
    doc.insert("defaults".to_string(), toml::Value::Table(defaults_map));

    // Serialize validators
    let mut validators_array = Vec::new();
    for config in validators.values() {
        let mut v = toml::map::Map::new();
        v.insert(
            "pubkey".to_string(),
            toml::Value::String(format!("0x{}", hex::encode(config.pubkey))),
        );
        if let Some(fr) = &config.fee_recipient {
            v.insert(
                "fee_recipient".to_string(),
                toml::Value::String(format!("0x{}", hex::encode(fr))),
            );
        }
        if let Some(gl) = config.gas_limit {
            v.insert("gas_limit".to_string(), toml::Value::Integer(gl as i64));
        }
        if config.builder_proposals {
            v.insert("builder_proposals".to_string(), toml::Value::Boolean(true));
        }
        if config.builder_boost_factor != 100 {
            v.insert(
                "builder_boost_factor".to_string(),
                toml::Value::Integer(config.builder_boost_factor as i64),
            );
        }
        if let Some(graffiti) = &config.graffiti {
            let s = std::str::from_utf8(graffiti)
                .unwrap_or("")
                .trim_end_matches('\0');
            if !s.is_empty() {
                v.insert("graffiti".to_string(), toml::Value::String(s.to_string()));
            }
        }
        if !config.enabled {
            v.insert("enabled".to_string(), toml::Value::Boolean(false));
        }
        validators_array.push(toml::Value::Table(v));
    }
    doc.insert(
        "validators".to_string(),
        toml::Value::Array(validators_array),
    );

    toml::to_string_pretty(&toml::Value::Table(doc))
        .map_err(|e| ValidatorStoreError::Config(format!("TOML serialization failed: {e}")))
}
```

### Combined Update + Save Method

For the API handlers, a combined method ensures atomicity:

```rust
impl ValidatorStore {
    /// Updates a validator's config in memory and persists to disk.
    /// Holds the write lock for the entire duration to prevent races.
    pub fn update_and_save(&self, pubkey: &[u8; 48], update: ValidatorConfigUpdate) -> Result<(), ValidatorStoreError> {
        // Check validator exists
        {
            let validators = self.validators.read();
            if !validators.contains_key(pubkey) {
                return Err(ValidatorStoreError::NotFound(
                    format!("validator {} not found", hex::encode(pubkey))
                ));
            }
        }

        // Update in-memory
        self.update_config(pubkey, update);

        // Persist to disk
        self.save_config()?;

        Ok(())
    }
}
```

---

## Concurrency Safety

### Write Serialization

The `ValidatorStore` uses `parking_lot::RwLock` for both `validators` and `defaults`. The `save_config()` method:
1. Acquires read locks on both `validators` and `defaults` to serialize
2. Writes to a temp file (no locks held during I/O — this is fine because we're writing a snapshot)
3. Atomically renames

**Concern:** If two API requests update config concurrently:
- Request A: `update_config()` → `save_config()`
- Request B: `update_config()` → `save_config()`

Both updates are applied to memory (serialized by the write lock), but `save_config()` could interleave such that Request A's save includes Request B's update. This is actually fine — the final state on disk matches the final state in memory.

**If a save fails:** The in-memory state has already been updated but the disk state is stale. On restart, the TOML reload would revert to the old state. To handle this, the `update_and_save()` method could roll back the in-memory change on save failure. However, this adds complexity — for the initial implementation, logging a warning on save failure is sufficient.

### Alternative: Serialize All Writes Through a Single Method

A stronger approach is to hold the write lock across both update and save:

```rust
pub fn update_and_save(&self, pubkey: &[u8; 48], update: ValidatorConfigUpdate) -> Result<(), ValidatorStoreError> {
    let mut validators = self.validators.write();

    // Apply update while holding write lock
    if let Some(config) = validators.get_mut(pubkey) {
        // ... apply update fields ...
    } else {
        return Err(ValidatorStoreError::NotFound(...));
    }

    // Save while still holding write lock — prevents interleaving
    let defaults = self.defaults.read();
    let toml_content = serialize_to_toml(&defaults, &validators)?;
    drop(defaults);

    // Write + persist (still holding validators write lock)
    self.atomic_write_toml(&toml_content)?;

    Ok(())
}
```

This ensures that no other write can interleave between the in-memory update and the disk persist. The trade-off is that the write lock is held during I/O, which could block other reads temporarily. Given that config updates are infrequent (human-initiated, not per-slot), this trade-off is acceptable.

---

## Crash Recovery

### Scenario Analysis

| Scenario | Before rename | After rename | Result |
|----------|--------------|-------------|--------|
| Normal operation | Temp file written + synced | Rename succeeds | Config updated |
| Crash before sync_all | Temp file may be partial | — | Original config intact, temp file cleaned up by OS |
| Crash after sync_all, before rename | Temp file complete on disk | — | Original config intact, temp file remains (harmless) |
| Crash during rename | Rename is atomic on modern filesystems | — | Either old or new config, never a mix |
| Crash after rename | — | New config in place | Config updated |

The `NamedTempFile::new_in()` creates the temp file in the same directory as the config, ensuring they are on the same filesystem (required for atomic rename).

### File Permissions

On Unix, the temp file created by `NamedTempFile` has default permissions (typically 0o600). If the original config file has custom permissions, they may not be preserved after the rename. To preserve permissions:

```rust
// Read original permissions before rename
let original_perms = std::fs::metadata(path)
    .ok()
    .map(|m| m.permissions());

tmp.persist(path)?;

// Restore permissions after rename
if let Some(perms) = original_perms {
    let _ = std::fs::set_permissions(path, perms);
}
```

This is a nice-to-have, not critical. The existing `auth.rs` `write_token_file()` already uses the same tempfile+rename pattern and does not preserve permissions.

---

## `tempfile` Crate API Reference

Key methods from the `tempfile` crate [1]:

```rust
// Create temp file in same directory as target
let tmp = NamedTempFile::new_in(parent_dir)?;

// Write content
tmp.write_all(content.as_bytes())?;

// Flush to disk (critical for crash safety)
tmp.as_file().sync_all()?;

// Atomic rename (replaces existing file at target path)
tmp.persist(target_path)?;
```

**Limitations:**
- Cannot persist across filesystems (temp file and target must be on same FS)
- `persist()` replaces existing files atomically; `persist_noclobber()` fails if target exists
- Neither `persist()` nor `persist_noclobber()` syncs the directory entry — this means on crash, the rename itself may not be durable. For maximum safety, `fsync` the parent directory after rename. In practice, this is rarely needed for config files.

---

## Existing Precedent in rvc

The `auth.rs` module already implements atomic file writes:

```rust
// auth.rs:write_token_file()
let tmp_path = parent.join(format!(".api-token.{}.tmp", std::process::id()));
file.write_all(token.as_bytes())?;
file.sync_all()?;
std::fs::rename(&tmp_path, path)?;
```

This is a manual version of the same pattern. The `save_config()` method should use `tempfile::NamedTempFile` instead, which:
- Automatically generates unique temp file names (no PID collision risk)
- Cleans up temp files on error (Drop impl)
- Provides `persist()` which handles rename + error recovery

## Sources

[1] [tempfile::NamedTempFile documentation](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html) — Official docs for the NamedTempFile struct.
[2] [Rust forum: How to write/replace files atomically](https://users.rust-lang.org/t/how-to-write-replace-files-atomically/42821) — Community discussion on atomic file write patterns.
[3] [atomic_write_file crate](https://docs.rs/atomic-write-file) — Alternative crate (not recommended; tempfile is already a dependency).
[4] [ELL Blog: Avoid Data Corruption by Syncing to Disk](https://blog.elijahlopez.ca/posts/data-corruption-atomic-writing/) — Explains why sync_all() before rename is critical for crash safety.
