use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use async_trait::async_trait;
use beacon::BeaconClient;
use crypto::logging::TruncatedPubkey;
use crypto::{CompositeSigner, Keystore, PublicKey, RemoteSigner, RemoteSignerConfig};
use doppelganger::{ForwardWindowMachine, SigningEnablement};
use eth_types::{
    Epoch, ForkSchedule, Root, SignedVoluntaryExit, VoluntaryExit, SECONDS_PER_SLOT,
    SLOTS_PER_EPOCH,
};
use keymanager_api::error::ApiError;
use keymanager_api::traits::{
    DeleteKeystoreError, DeleteRemoteKeyError, DoppelgangerMonitor, ImportKeystoreError,
    ImportRemoteKeyError, KeystoreManager, Pubkey, RemoteKeyManager, SlashingProtection,
    ValidatorConfigManager, ValidatorManager, VoluntaryExitManager,
};
use signer::SignerService;
use slashing::SlashingDb;
use tokio::sync::watch;
use tracing::{error, info, warn};
use validator_store::{ValidatorConfigUpdate, ValidatorStore};

use crate::deletion_denylist::DeletionDenylist;
use crate::orchestrator::PubkeyMap;

/// Adapts `CompositeSigner` local keys to the Keymanager `KeystoreManager` trait.
///
/// # Canonical registry
///
/// The source of truth for "which local keys can this VC sign with" is
/// [`CompositeSigner::local_public_keys`] / [`CompositeSigner::has_local_key`] —
/// the union of boot-loaded keys (keystore-dir / secret-provider in
/// `LocalSigner`) and keys added via `add_local_key` (API import, secret-provider
/// refresh). `list_keys` / `has_key` / `delete_keystore` all consult that set.
///
/// `tracked_keys` is retained only as an import serialization lock and a record of
/// keys imported through this adapter (for concurrent import TOCTOU safety); it is
/// **not** the registry for list/has/delete.
///
/// # Deletion denylist (SEC-1b)
///
/// On successful `delete_keystore`, the pubkey is recorded in
/// [`DeletionDenylist`] so keystore-dir / secret-provider loaders skip it on
/// the next boot. Intentional re-import via `import_keystore` clears the entry.
pub struct KeystoreManagerAdapter {
    keystore_dir: PathBuf,
    composite_signer: Arc<CompositeSigner>,
    /// API-imported keys; also serializes concurrent `import_keystore` / `delete_keystore`.
    tracked_keys: Mutex<Vec<Pubkey>>,
    /// Shared duty-matching map; always updated on import/delete (RF1-06).
    pubkey_map: PubkeyMap,
    /// Notifies the orchestrator that the key set changed (RF1-06 / RF1-07).
    key_gen_tx: watch::Sender<u64>,
    /// Durable deletion denylist; `None` disables persistence (tests).
    denylist: Option<Arc<DeletionDenylist>>,
}

impl KeystoreManagerAdapter {
    pub fn new(
        keystore_dir: PathBuf,
        composite_signer: Arc<CompositeSigner>,
        pubkey_map: PubkeyMap,
        key_gen_tx: watch::Sender<u64>,
    ) -> Self {
        Self {
            keystore_dir,
            composite_signer,
            tracked_keys: Mutex::new(Vec::new()),
            pubkey_map,
            key_gen_tx,
            denylist: None,
        }
    }

    /// Attach the process-wide deletion denylist (SEC-1b).
    pub fn with_denylist(mut self, denylist: Arc<DeletionDenylist>) -> Self {
        self.denylist = Some(denylist);
        self
    }

    fn notify_key_change(&self) {
        self.key_gen_tx.send_modify(|gen| *gen += 1);
    }
}

/// Returns the path for the M-12 import-time metadata sidecar for `pubkey`.
///
/// Format: `<keystore_dir>/0x<hex_pubkey>.import_meta.json`
fn import_meta_path(keystore_dir: &Path, pubkey: &Pubkey) -> PathBuf {
    keystore_dir.join(format!("0x{}.import_meta.json", hex::encode(pubkey)))
}

/// Unlink every keystore JSON under `keystore_dir` whose EIP-2335 `pubkey`
/// field matches `pubkey` (plus the canonical API-import name
/// `0x{hex}.json`).
///
/// Boot load accepts any `*.json` name (`KeyManager::load_from_directory`);
/// DELETE must therefore not rely solely on the API-import filename
/// convention. Secret-provider keys with no on-disk file are fine — this
/// returns `Ok` when nothing matches.
///
/// Path-traversal: each candidate is canonicalized and required to stay
/// under `keystore_dir` before unlink (same rule as key load).
fn remove_matching_keystore_files(
    keystore_dir: &Path,
    pubkey: &Pubkey,
) -> Result<(), DeleteKeystoreError> {
    let target_hex = hex::encode(pubkey);
    let canonical_name = format!("0x{target_hex}.json");
    let canonical_path = keystore_dir.join(&canonical_name);

    match std::fs::remove_file(&canonical_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
    }

    let entries = match std::fs::read_dir(keystore_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
    };

    let canonical_dir = match keystore_dir.canonicalize() {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Only keystore JSON; never the import-meta sidecar (handled separately).
        if !name.ends_with(".json") || name.ends_with(".import_meta.json") {
            continue;
        }
        // Already attempted above; skip re-stat of the canonical name.
        if name == canonical_name {
            continue;
        }

        let canonical_file = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !canonical_file.starts_with(&canonical_dir) {
            warn!(
                path = %path.display(),
                "Skipping keystore candidate outside keystore directory during delete"
            );
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        let Some(pk_str) = value.get("pubkey").and_then(|v| v.as_str()) else {
            continue;
        };
        let pk_norm =
            pk_str.strip_prefix("0x").or_else(|| pk_str.strip_prefix("0X")).unwrap_or(pk_str);
        if !pk_norm.eq_ignore_ascii_case(&target_hex) {
            continue;
        }

        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    pubkey = %TruncatedPubkey::new(&target_hex),
                    "Removed non-canonical keystore file on delete"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
        }
    }

    Ok(())
}

/// Scan `keystore_dir` for `*.import_meta.json` sidecars and re-arm the
/// doppelganger `gate` for any key whose import timestamp is recent enough
/// that the doppelganger window (`window_secs`) has not yet elapsed.
///
/// Called once at startup after the `DoppelgangerGate` is created to restore
/// in-memory monitoring state that was lost when the process was restarted.
///
/// # Safety guarantee
/// If the `now - imported_unix < window_secs` check passes, the key is added
/// to the gate's `pending` map with the *current* instant so the residual
/// window is honoured.  This means the gate will still block attestation for
/// the full configured window from the perspective of the restarted process,
/// which is slightly more conservative than replaying the exact residual but
/// is safe.
pub fn scan_and_rearm_gate(
    keystore_dir: &std::path::Path,
    gate: &dyn DoppelgangerMonitor,
    window_secs: u64,
) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entries = match std::fs::read_dir(keystore_dir) {
        Ok(e) => e,
        Err(err) => {
            warn!(
                error = %err,
                dir = %keystore_dir.display(),
                "Could not read keystore directory when scanning import-meta sidecars"
            );
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };

        if !name.ends_with(".import_meta.json") {
            continue;
        }

        // Parse the pubkey hex from the filename: `0x<hex>.import_meta.json`
        let hex_part =
            name.strip_prefix("0x").and_then(|s| s.strip_suffix(".import_meta.json")).unwrap_or("");

        let pubkey_bytes = match hex::decode(hex_part) {
            Ok(b) if b.len() == 48 => {
                let mut pk = [0u8; 48];
                pk.copy_from_slice(&b);
                pk
            }
            _ => continue,
        };

        // Read the sidecar JSON
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) => {
                warn!(
                    error = %err,
                    path = %path.display(),
                    "Failed to read import_meta sidecar; skipping"
                );
                continue;
            }
        };

        let imported_unix: u64 = match serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|v| v["imported_unix_seconds"].as_u64())
        {
            Some(t) => t,
            None => {
                warn!(
                    path = %path.display(),
                    "import_meta sidecar has unexpected format; skipping"
                );
                continue;
            }
        };

        let elapsed = now_unix.saturating_sub(imported_unix);
        if elapsed < window_secs {
            let residual = window_secs - elapsed;
            warn!(
                pubkey = %hex::encode(pubkey_bytes),
                residual_secs = residual,
                "Key was imported {elapsed}s ago; doppelganger window has {residual}s remaining \
                 — re-arming gate after restart"
            );
            gate.start_monitoring(pubkey_bytes);
        }
    }
}

impl KeystoreManager for KeystoreManagerAdapter {
    /// Local keys the VC can sign with (`CompositeSigner::local_public_keys`).
    fn list_keys(&self) -> Vec<Pubkey> {
        self.composite_signer.local_public_keys()
    }

    /// Whether `pubkey` is a local signing key (boot-loaded or API-imported).
    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.composite_signer.has_local_key(pubkey)
    }

    fn import_keystore(
        &self,
        keystore_json: &str,
        password: &str,
    ) -> Result<Pubkey, ImportKeystoreError> {
        let keystore: Keystore = serde_json::from_str(keystore_json)
            .map_err(|e| ImportKeystoreError::InvalidKeystore(e.to_string()))?;

        let secret_key = keystore
            .decrypt(password.as_bytes())
            .map_err(|e| ImportKeystoreError::DecryptionFailed(e.to_string()))?;

        let pubkey_bytes = secret_key.public_key().to_bytes();

        // Hold lock for the entire check-and-insert to prevent TOCTOU race.
        // Duplicate check uses the real local registry (not only API-tracked keys).
        let mut keys = self.tracked_keys.lock();
        if self.composite_signer.has_local_key(&pubkey_bytes) {
            return Err(ImportKeystoreError::Duplicate);
        }

        // Save keystore file to disk with restricted permissions (0o600)
        let filename = format!("0x{}.json", hex::encode(pubkey_bytes));
        let file_path = self.keystore_dir.join(&filename);

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&file_path)
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
            file.write_all(keystore_json.as_bytes())
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&file_path, keystore_json)
                .map_err(|e| ImportKeystoreError::Io(e.to_string()))?;
        }

        // M-12 (Critical #2): persist the import timestamp so that after a
        // restart the doppelganger gate can detect keys whose window is still
        // active and re-arm monitoring rather than treating them as safe.
        let meta_path = import_meta_path(&self.keystore_dir, &pubkey_bytes);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let meta_json = format!("{{\"imported_unix_seconds\":{}}}", now_unix);

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            if let Ok(mut f) = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&meta_path)
            {
                let _ = f.write_all(meta_json.as_bytes());
            }
        }

        #[cfg(not(unix))]
        {
            let _ = std::fs::write(&meta_path, meta_json.as_bytes());
        }

        // Add to composite signer for signing
        let public_key = secret_key.public_key();
        self.composite_signer.add_local_key(secret_key);

        // Track the key (lock still held)
        keys.push(pubkey_bytes);

        // Update shared pubkey_map and notify orchestrator (required at construction).
        let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));
        self.pubkey_map.write().insert(pubkey_hex, public_key);
        self.notify_key_change();

        // SEC-1b: clear denylist only *after* successful persistence + registry
        // add so a mid-import IO failure cannot un-delete a previously deleted
        // key (restart would otherwise re-load it from secret-provider).
        if let Some(ref denylist) = self.denylist {
            if let Err(e) = denylist.remove(&pubkey_bytes) {
                // Key is already loaded and signable; surface IO so operators
                // can repair the denylist file. Do not roll back the import.
                return Err(ImportKeystoreError::Io(e.to_string()));
            }
        }

        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey_bytes)),
            "Imported keystore"
        );
        Ok(pubkey_bytes)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        // Serialize with import via the same lock so concurrent import/delete
        // cannot race. Registry membership is the real local signing set.
        let mut keys = self.tracked_keys.lock();
        if !self.composite_signer.has_local_key(pubkey) {
            // Retry / break-glass: a prior DELETE may have removed the key from
            // the registry before denylist durability failed. Allow authenticated
            // DELETE of a non-local pubkey to force-insert the denylist entry so
            // secret-provider keys cannot resurrect on the next boot.
            if let Some(ref denylist) = self.denylist {
                denylist.insert(pubkey).map_err(|e| DeleteKeystoreError::Io(e.to_string()))?;
            }
            return Ok(false);
        }

        // Order (SEC-1b fail-closed for durability):
        //   1. Unlink keystore files (IO failure leaves memory intact)
        //   2. Durable denylist.insert (IO failure leaves key still local → retryable)
        //   3. Remove from signing registry
        //
        // Writing the denylist *before* remove_local_key ensures a failed
        // insert does not leave a non-signable key that cannot be re-deleted.

        // Matches any `*.json` whose EIP-2335 pubkey field equals this key
        // (API-import `0x{hex}.json` and boot-loaded names like `validator1.json`).
        // No matching file is OK (secret-provider / already removed).
        remove_matching_keystore_files(&self.keystore_dir, pubkey)?;

        // M-12 (Critical #2): remove the import-time sidecar so a
        // subsequent re-import starts with a clean timestamp.
        let meta_path = import_meta_path(&self.keystore_dir, pubkey);
        let _ = std::fs::remove_file(&meta_path);

        // SEC-1b: persist deletion *before* registry removal so durability
        // failure leaves the key still present for DELETE retry.
        if let Some(ref denylist) = self.denylist {
            denylist.insert(pubkey).map_err(|e| DeleteKeystoreError::Io(e.to_string()))?;
        }

        // Drop bookkeeping after denylist succeeds (lock still held for
        // remove_local_key + map update so concurrent deletes/imports serialize).
        if let Some(pos) = keys.iter().position(|k| k == pubkey) {
            keys.remove(pos);
        }

        // Remove from the real signing registry (dynamic + boot-loaded).
        let removed = self.composite_signer.remove_local_key(pubkey);

        // Map remove + notify under the same `tracked_keys` lock as registry
        // mutation (S1). If we released the lock first, a concurrent re-import
        // could re-insert the map entry and then be erased by our late remove.
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        self.pubkey_map.write().remove(&pubkey_hex);
        self.notify_key_change();
        drop(keys);

        // After a positive membership check under this lock, `!removed` is an
        // inconsistency (or an external concurrent remover). Disk side effects
        // already happened — do not map this to dishonest `not_found`.
        if !removed {
            debug_assert!(removed, "remove_local_key returned false after has_local_key was true");
            error!(
                pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                "remove_local_key returned false after positive membership; \
                 treating delete as success (key is not signable)"
            );
        }

        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            "Deleted keystore"
        );
        Ok(true)
    }
}

pub struct SlashingProtectionAdapter {
    slashing_db: Arc<SlashingDb>,
    genesis_validators_root: String,
}

impl SlashingProtectionAdapter {
    pub fn new(slashing_db: Arc<SlashingDb>, genesis_validators_root: String) -> Self {
        Self { slashing_db, genesis_validators_root }
    }
}

impl SlashingProtection for SlashingProtectionAdapter {
    fn import_interchange(&self, interchange_json: &str) -> Result<(), String> {
        let interchange: slashing::InterchangeFormat =
            serde_json::from_str(interchange_json).map_err(|e| format!("invalid JSON: {e}"))?;
        self.slashing_db
            .import(&interchange, &self.genesis_validators_root)
            .map_err(|e| e.to_string())
    }

    /// Export an EIP-3076 interchange blob for the specified public keys.
    ///
    /// # Atomicity contract (ADR-008 / KM-1)
    ///
    /// This function is all-or-nothing: either the interchange for every
    /// requested key is returned, or `Err` is returned and no partial
    /// interchange is emitted.  The underlying `SlashingDb::export` holds a
    /// single `Mutex<Connection>` lock for the entire read — `read_all_pubkeys`,
    /// `read_attestations`, and `read_blocks` all execute under that one held
    /// guard — so no concurrent `seed_attestation`/`seed_block` write can
    /// interleave and produce a stale snapshot.
    ///
    /// # Completeness (KM-1(a))
    ///
    /// Every requested pubkey is represented in the output.  Keys with no
    /// slashing rows in the DB receive an explicit empty
    /// `ValidatorRecord { signed_blocks: [], signed_attestations: [] }` so
    /// that a re-importing node sees a clean (rather than absent) record.
    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, String> {
        let interchange =
            self.slashing_db.export(&self.genesis_validators_root).map_err(|e| e.to_string())?;

        // Build a canonical hex-string set for fast membership lookup.
        let requested: std::collections::HashSet<String> =
            pubkeys.iter().map(|pk| format!("0x{}", hex::encode(pk))).collect();

        // Collect DB records for requested keys.
        let mut filtered_data: Vec<_> = interchange
            .data
            .into_iter()
            .filter(|record| requested.contains(&record.pubkey))
            .collect();

        // KM-1(a): append an explicit empty record for every requested key
        // absent from the DB export, so the interchange covers all deleted keys.
        // Collect the keys to add first to avoid holding a shared borrow of
        // filtered_data while also pushing into it.
        let exported_pubkeys: std::collections::HashSet<String> =
            filtered_data.iter().map(|r| r.pubkey.clone()).collect();
        let missing: Vec<String> =
            requested.into_iter().filter(|pk| !exported_pubkeys.contains(pk)).collect();
        for pk_hex in missing {
            filtered_data.push(slashing::ValidatorRecord {
                pubkey: pk_hex,
                signed_blocks: vec![],
                signed_attestations: vec![],
            });
        }

        let filtered =
            slashing::InterchangeFormat { metadata: interchange.metadata, data: filtered_data };

        serde_json::to_string(&filtered).map_err(|e| format!("serialization failed: {e}"))
    }
}

pub struct ValidatorManagerAdapter {
    validator_store: Arc<ValidatorStore>,
}

impl ValidatorManagerAdapter {
    pub fn new(validator_store: Arc<ValidatorStore>) -> Self {
        Self { validator_store }
    }
}

impl ValidatorManager for ValidatorManagerAdapter {
    fn add_validator(&self, pubkey: Pubkey, enabled: bool) {
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let mut config = validator_store::ValidatorConfig::new(pubkey);
        config.enabled = enabled;
        self.validator_store.add_validator(config);
        info!(pubkey = %pubkey_hex, enabled, "Added validator to store");
    }

    fn remove_validator(&self, pubkey: &Pubkey) -> bool {
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        let removed = self.validator_store.remove_validator(pubkey).is_some();
        if removed {
            info!(pubkey = %pubkey_hex, "Removed validator from store");
        } else {
            warn!(pubkey = %pubkey_hex, "Validator not found in store for removal");
        }
        removed
    }

    fn set_validator_enabled(&self, pubkey: &Pubkey, enabled: bool) {
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));
        self.validator_store.set_enabled(pubkey, enabled);
        info!(pubkey = %pubkey_hex, enabled, "Validator enabled state updated");
    }
}

#[derive(Default)]
pub struct DoppelgangerMonitorAdapter;

impl DoppelgangerMonitorAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl DoppelgangerMonitor for DoppelgangerMonitorAdapter {
    fn start_monitoring(&self, pubkey: Pubkey) {
        info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Doppelganger monitoring requested for new key");
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Doppelganger monitoring stop requested");
    }

    fn is_doppelganger_safe(&self, _pubkey: &Pubkey) -> bool {
        true
    }
}

/// [`DoppelgangerMonitor`] that registers keymanager-imported keys with a
/// production [`ForwardWindowMachine`] (SEC-2b).
///
/// | Call | Machine effect |
/// |------|----------------|
/// | `start_monitoring` | [`ForwardWindowMachine::register_for_import`] (always Pending) |
/// | `stop_monitoring` | **no-op** — M-12 wall-clock elapsed must not cancel machine state |
/// | `cancel_monitoring` | [`ForwardWindowMachine::cancel`] — DELETE / re-import fresh window |
///
/// Safety is the machine's `SigningEnablement` status (fail-closed for
/// Pending/Detected/Unmonitored).
pub struct ForwardWindowMonitor {
    machine: Arc<ForwardWindowMachine>,
    /// Supplies the current epoch for `register_for_import` (prefer
    /// [`doppelganger::MonotonicEpochClock`] shared with boot registration).
    epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync>,
}

impl ForwardWindowMonitor {
    pub fn new(
        machine: Arc<ForwardWindowMachine>,
        epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync>,
    ) -> Self {
        Self { machine, epoch_provider }
    }

    /// Shared handle to the underlying machine (for tests / advanced wiring).
    pub fn machine(&self) -> &Arc<ForwardWindowMachine> {
        &self.machine
    }

    /// Register a newly discovered local key (secret-provider refresh, etc.)
    /// with the same import-strict rules as keymanager import.
    pub fn register_local_key(&self, pubkey: &PublicKey) {
        let epoch = (self.epoch_provider)();
        self.machine.register_for_import(pubkey, epoch);
        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey.to_bytes())),
            epoch,
            "Registered dynamically discovered local key with ForwardWindowMachine (SEC-2b)"
        );
    }
}

impl DoppelgangerMonitor for ForwardWindowMonitor {
    fn start_monitoring(&self, pubkey: Pubkey) {
        match PublicKey::from_bytes(&pubkey) {
            Ok(pk) => {
                let epoch = (self.epoch_provider)();
                // Import-strict: no restart safe-skip, no epoch-0 Safe bypass.
                self.machine.register_for_import(&pk, epoch);
                info!(
                    pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                    epoch,
                    "Registered keymanager-imported key with ForwardWindowMachine (SEC-2b)"
                );
            }
            Err(e) => {
                warn!(
                    pubkey = %hex::encode(pubkey),
                    error = %e,
                    "ForwardWindowMonitor: invalid pubkey on start_monitoring; key left unmonitored (fail-closed)"
                );
            }
        }
    }

    fn stop_monitoring(&self, pubkey: &Pubkey) {
        // SEC-2b review Finding 1: M-12 wall-clock elapsed calls stop_monitoring.
        // That must NOT map to machine.cancel (which would drop Pending/Safe →
        // Unmonitored and fight "window done → may sign" once SEC-2c opens).
        // Validator-store enable is handled separately by the import handler.
        info!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            "ForwardWindowMonitor: stop_monitoring is a no-op for machine state \
             (M-12 wall-clock ≠ forward-window cancel; use cancel_monitoring on DELETE)"
        );
    }

    fn cancel_monitoring(&self, pubkey: &Pubkey) {
        match PublicKey::from_bytes(pubkey) {
            Ok(pk) => {
                self.machine.cancel(&pk);
                info!(
                    pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                    "Cancelled ForwardWindowMachine monitoring for deleted key"
                );
            }
            Err(e) => {
                warn!(
                    pubkey = %hex::encode(pubkey),
                    error = %e,
                    "ForwardWindowMonitor: invalid pubkey on cancel_monitoring"
                );
            }
        }
    }

    fn is_doppelganger_safe(&self, pubkey: &Pubkey) -> bool {
        match PublicKey::from_bytes(pubkey) {
            Ok(pk) => self.machine.is_signing_enabled(&pk),
            // Invalid encoding → fail closed.
            Err(_) => false,
        }
    }
}

/// Wall-clock epoch from genesis.
///
/// Prefer [`doppelganger::MonotonicEpochClock`] for production register paths
/// (M-7). Kept for tests and non-critical fallbacks.
pub fn wall_clock_epoch(genesis_time: u64) -> Epoch {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(genesis_time) / SECONDS_PER_SLOT / SLOTS_PER_EPOCH
}

pub struct RemoteKeyManagerAdapter {
    composite_signer: Arc<CompositeSigner>,
    tracked_keys: Mutex<Vec<(Pubkey, String)>>,
    allowed_hosts: Option<Vec<String>>,
    warned_no_allowlist: AtomicBool,
    /// Shared duty-matching map; always updated on import/delete (RF1-06).
    pubkey_map: PubkeyMap,
    /// Notifies the orchestrator that the key set changed (RF1-06 / RF1-07).
    key_gen_tx: watch::Sender<u64>,
}

impl RemoteKeyManagerAdapter {
    pub fn new(
        composite_signer: Arc<CompositeSigner>,
        allowed_hosts: Option<Vec<String>>,
        pubkey_map: PubkeyMap,
        key_gen_tx: watch::Sender<u64>,
    ) -> Self {
        Self {
            composite_signer,
            tracked_keys: Mutex::new(Vec::new()),
            allowed_hosts,
            warned_no_allowlist: AtomicBool::new(false),
            pubkey_map,
            key_gen_tx,
        }
    }

    fn notify_key_change(&self) {
        self.key_gen_tx.send_modify(|gen| *gen += 1);
    }
}

impl RemoteKeyManager for RemoteKeyManagerAdapter {
    fn list_remote_keys(&self) -> Vec<(Pubkey, String)> {
        self.tracked_keys.lock().clone()
    }

    fn has_remote_key(&self, pubkey: &Pubkey) -> bool {
        self.tracked_keys.lock().iter().any(|(pk, _)| pk == pubkey)
    }

    fn import_remote_key(&self, pubkey: Pubkey, url: String) -> Result<(), ImportRemoteKeyError> {
        let parsed = url::Url::parse(&url)
            .map_err(|e| ImportRemoteKeyError::Other(format!("invalid remote signer URL: {e}")))?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(ImportRemoteKeyError::Other(format!(
                    "invalid URL scheme: must be http:// or https://, got: {scheme}://"
                )));
            }
        }

        if let Some(ref allowed) = self.allowed_hosts {
            let host = parsed.host_str().unwrap_or("");
            if !allowed.iter().any(|h| h == host) {
                return Err(ImportRemoteKeyError::Other(format!(
                    "remote signer host '{}' is not in the allowed hosts list",
                    host
                )));
            }
        } else if !self.warned_no_allowlist.swap(true, Ordering::Relaxed) {
            warn!(
                "No remote signer host allowlist configured; all HTTP/HTTPS hosts are accepted. \
                 Consider setting --remote-signer-allowed-hosts for production use"
            );
        }

        let mut keys = self.tracked_keys.lock();
        if keys.iter().any(|(pk, _)| *pk == pubkey) {
            return Err(ImportRemoteKeyError::Duplicate);
        }

        let config = RemoteSignerConfig::new(url.clone());
        let remote_signer = RemoteSigner::new(config, vec![pubkey])
            .map_err(|e| ImportRemoteKeyError::Other(e.to_string()))?;

        self.composite_signer.add_remote_key(pubkey, remote_signer);
        keys.push((pubkey, url));

        // Update shared pubkey_map and notify under `tracked_keys` (same lock
        // as registry mutation). Invalid BLS bytes skip the map entry but still
        // advance the generation counter; RF1-07 wires the orchestrator receiver
        // that will clear the duty cache on this notification.
        if let Ok(pk) = PublicKey::from_bytes(&pubkey) {
            let pubkey_hex = format!("0x{}", hex::encode(pubkey));
            self.pubkey_map.write().insert(pubkey_hex, pk);
        }
        self.notify_key_change();

        info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Imported remote key");
        Ok(())
    }

    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        let mut keys = self.tracked_keys.lock();
        if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
            keys.remove(pos);
            self.composite_signer.remove_remote_key(pubkey);

            // Map remove + notify under the same lock as registry mutation (S1).
            let pubkey_hex = format!("0x{}", hex::encode(pubkey));
            self.pubkey_map.write().remove(&pubkey_hex);
            self.notify_key_change();
            drop(keys);

            info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Deleted remote key");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct ValidatorConfigManagerAdapter {
    validator_store: Arc<ValidatorStore>,
}

impl ValidatorConfigManagerAdapter {
    pub fn new(validator_store: Arc<ValidatorStore>) -> Self {
        Self { validator_store }
    }

    fn ensure_validator_exists(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        if !self.validator_store.has_validator(pubkey) {
            return Err(ApiError::NotFound(format!(
                "validator 0x{} not found",
                hex::encode(pubkey)
            )));
        }
        Ok(())
    }

    fn update_and_save(
        &self,
        pubkey: &Pubkey,
        update: ValidatorConfigUpdate,
    ) -> Result<(), ApiError> {
        self.validator_store.update_config(pubkey, update);
        self.validator_store.save_config().map_err(|e| ApiError::Internal(e.to_string()))
    }
}

impl ValidatorConfigManager for ValidatorConfigManagerAdapter {
    fn get_fee_recipient(&self, pubkey: &Pubkey) -> Result<[u8; 20], ApiError> {
        self.ensure_validator_exists(pubkey)?;
        Ok(self.validator_store.effective_fee_recipient(pubkey))
    }

    fn set_fee_recipient(&self, pubkey: &Pubkey, address: [u8; 20]) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { fee_recipient: Some(Some(address)), ..Default::default() },
        )
    }

    fn delete_fee_recipient(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { fee_recipient: Some(None), ..Default::default() },
        )
    }

    fn get_gas_limit(&self, pubkey: &Pubkey) -> Result<u64, ApiError> {
        self.ensure_validator_exists(pubkey)?;
        Ok(self.validator_store.effective_gas_limit(pubkey))
    }

    fn set_gas_limit(&self, pubkey: &Pubkey, limit: u64) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { gas_limit: Some(Some(limit)), ..Default::default() },
        )
    }

    fn delete_gas_limit(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { gas_limit: Some(None), ..Default::default() },
        )
    }

    fn get_graffiti(&self, pubkey: &Pubkey) -> Result<String, ApiError> {
        self.ensure_validator_exists(pubkey)?;
        let graffiti = self.validator_store.effective_graffiti(pubkey);
        Ok(match graffiti {
            Some(g) => {
                let end = g.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
                String::from_utf8_lossy(&g[..end]).into_owned()
            }
            None => String::new(),
        })
    }

    fn set_graffiti(&self, pubkey: &Pubkey, graffiti: &str) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        let mut bytes = [0u8; 32];
        let src = graffiti.as_bytes();
        let len = src.len().min(32);
        bytes[..len].copy_from_slice(&src[..len]);
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { graffiti: Some(Some(bytes)), ..Default::default() },
        )
    }

    fn delete_graffiti(&self, pubkey: &Pubkey) -> Result<(), ApiError> {
        self.ensure_validator_exists(pubkey)?;
        self.update_and_save(
            pubkey,
            ValidatorConfigUpdate { graffiti: Some(None), ..Default::default() },
        )
    }
}

pub struct VoluntaryExitManagerAdapter {
    beacon_client: Arc<BeaconClient>,
    signer: Arc<SignerService>,
    fork_schedule: Arc<ForkSchedule>,
    genesis_validators_root: Root,
}

impl VoluntaryExitManagerAdapter {
    pub fn new(
        beacon_client: Arc<BeaconClient>,
        signer: Arc<SignerService>,
        fork_schedule: Arc<ForkSchedule>,
        genesis_validators_root: Root,
    ) -> Self {
        Self { beacon_client, signer, fork_schedule, genesis_validators_root }
    }
}

#[async_trait]
impl VoluntaryExitManager for VoluntaryExitManagerAdapter {
    async fn sign_voluntary_exit(
        &self,
        pubkey: &Pubkey,
        epoch: Option<u64>,
    ) -> Result<SignedVoluntaryExit, ApiError> {
        let pubkey_hex = format!("0x{}", hex::encode(pubkey));

        // Resolve validator index from beacon node
        let validators_response = self
            .beacon_client
            .get_validators(std::slice::from_ref(&pubkey_hex))
            .await
            .map_err(|e| ApiError::Internal(format!("beacon node error: {e}")))?;

        let validator = validators_response.data.first().ok_or_else(|| {
            ApiError::NotFound(format!("validator {pubkey_hex} not found on beacon node"))
        })?;

        let validator_index: u64 = validator
            .index
            .parse()
            .map_err(|e| ApiError::Internal(format!("failed to parse validator index: {e}")))?;

        // Determine epoch
        let epoch = match epoch {
            Some(e) => e,
            None => {
                let genesis = self
                    .beacon_client
                    .get_genesis()
                    .await
                    .map_err(|e| ApiError::Internal(format!("failed to get genesis: {e}")))?;

                let genesis_time: u64 = genesis.data.genesis_time.parse().map_err(|e| {
                    ApiError::Internal(format!("failed to parse genesis time: {e}"))
                })?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time before UNIX epoch")
                    .as_secs();

                let current_slot = now.saturating_sub(genesis_time) / SECONDS_PER_SLOT;
                current_slot / SLOTS_PER_EPOCH
            }
        };

        info!(epoch, validator_index, pubkey = %pubkey_hex, "Signing voluntary exit");

        // Construct and sign
        let voluntary_exit = VoluntaryExit { epoch, validator_index };

        let pk = PublicKey::from_bytes(pubkey)
            .map_err(|e| ApiError::Internal(format!("invalid public key: {e:?}")))?;

        let signature = self
            .signer
            .sign_voluntary_exit(
                &voluntary_exit,
                &pk,
                &self.fork_schedule,
                &self.genesis_validators_root,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("signing failed: {e}")))?;

        Ok(SignedVoluntaryExit {
            message: voluntary_exit,
            signature: signature.to_bytes().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{KeyManager, LocalSigner, SecretKey, Signer};
    use signer::always_enabled;
    use tempfile::TempDir;

    fn test_pubkey(id: u8) -> Pubkey {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    fn create_empty_composite_signer() -> Arc<CompositeSigner> {
        Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
    }

    fn create_pubkey_map() -> PubkeyMap {
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()))
    }

    /// Shared test helper: build a KeystoreManagerAdapter with required map + channel.
    fn test_keystore_adapter(
        dir: PathBuf,
        signer: Arc<CompositeSigner>,
    ) -> (KeystoreManagerAdapter, PubkeyMap, watch::Receiver<u64>) {
        let (tx, rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter = KeystoreManagerAdapter::new(dir, signer, pubkey_map.clone(), tx);
        (adapter, pubkey_map, rx)
    }

    /// Shared test helper: build a RemoteKeyManagerAdapter with required map + channel.
    fn test_remote_adapter(
        signer: Arc<CompositeSigner>,
        allowed_hosts: Option<Vec<String>>,
    ) -> (RemoteKeyManagerAdapter, PubkeyMap, watch::Receiver<u64>) {
        let (tx, rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter = RemoteKeyManagerAdapter::new(signer, allowed_hosts, pubkey_map.clone(), tx);
        (adapter, pubkey_map, rx)
    }

    // --- KeystoreManagerAdapter tests ---

    #[test]
    fn test_keystore_manager_adapter_empty_list() {
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) =
            test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(adapter.list_keys().is_empty());
    }

    #[test]
    fn test_keystore_manager_adapter_has_key_false() {
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) =
            test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(!adapter.has_key(&test_pubkey(1)));
    }

    #[test]
    fn test_keystore_manager_adapter_delete_nonexistent() {
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) =
            test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(!adapter.delete_keystore(&test_pubkey(1)).unwrap());
    }

    #[test]
    fn test_keystore_manager_adapter_import_invalid_json() {
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) =
            test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());
        let result = adapter.import_keystore("not valid json", "password");
        assert!(matches!(result, Err(ImportKeystoreError::InvalidKeystore(_))));
    }

    // --- SlashingProtectionAdapter tests ---

    #[test]
    fn test_slashing_adapter_import_invalid_json() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let adapter = SlashingProtectionAdapter::new(
            db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        let result = adapter.import_interchange("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_slashing_adapter_import_valid() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let adapter = SlashingProtectionAdapter::new(
            db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        let interchange = serde_json::json!({
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "data": []
        });
        let result = adapter.import_interchange(&interchange.to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_slashing_adapter_export_empty() {
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let adapter = SlashingProtectionAdapter::new(
            db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        let result = adapter.export_interchange(&[]);
        assert!(result.is_ok());
        let export: serde_json::Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert!(export["data"].as_array().unwrap().is_empty());
    }

    // --- ValidatorManagerAdapter tests ---

    #[test]
    fn test_validator_manager_adapter_add_remove() {
        let store = Arc::new(ValidatorStore::new([0u8; 20], 100));
        let adapter = ValidatorManagerAdapter::new(store.clone());
        adapter.add_validator(test_pubkey(1), true);

        // Verify the validator was actually added to the store
        assert!(store.get_config(&test_pubkey(1)).is_some());

        // Remove and verify
        assert!(adapter.remove_validator(&test_pubkey(1)));
        assert!(store.get_config(&test_pubkey(1)).is_none());

        // Removing non-existent returns false
        assert!(!adapter.remove_validator(&test_pubkey(99)));
    }

    // --- DoppelgangerMonitorAdapter tests ---

    #[test]
    fn test_doppelganger_adapter_start_stop() {
        let adapter = DoppelgangerMonitorAdapter::new();
        adapter.start_monitoring(test_pubkey(1));
        adapter.stop_monitoring(&test_pubkey(1));
    }

    // --- SEC-2b: ForwardWindowMonitor (keymanager import → machine) ---

    /// Keymanager import path registers the key with ForwardWindowMachine so
    /// the production signing enablement gate applies to API-imported keys.
    #[test]
    fn test_keymanager_imported_key_registers_with_machine() {
        use doppelganger::ForwardWindowStatus;

        struct NoPrior;
        impl slashing::SlashingDbReader for NoPrior {
            fn last_signed_attestation(
                &self,
                _pubkey: &str,
                _gvr: &Root,
            ) -> Option<slashing::TargetEpoch> {
                None
            }
        }

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();

        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPrior);
        let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xabu8; 32]));
        let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 42);
        let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);

        // Before import registration: unmonitored → not safe.
        assert!(!monitor.is_doppelganger_safe(&pk_bytes));
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Unmonitored);

        // Import handler calls start_monitoring → register_for_import at epoch 42.
        monitor.start_monitoring(pk_bytes);

        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Pending,
            "imported key must be Pending on the ForwardWindowMachine"
        );
        assert!(
            !monitor.is_doppelganger_safe(&pk_bytes),
            "imported key must not be signing-safe until the window elapses"
        );
        assert!(!machine.is_signing_enabled(&pk));

        // M-12 window elapsed: stop_monitoring must NOT cancel machine state.
        monitor.stop_monitoring(&pk_bytes);
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Pending,
            "stop_monitoring (M-12 elapsed) must leave machine Pending"
        );

        // DELETE path: cancel_monitoring drops state for re-import freshness.
        monitor.cancel_monitoring(&pk_bytes);
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Unmonitored);
    }

    /// Import path never applies epoch-0 Safe bypass (SEC-2b Finding 2).
    #[test]
    fn test_keymanager_import_epoch0_stays_pending() {
        use doppelganger::ForwardWindowStatus;

        struct NoPrior;
        impl slashing::SlashingDbReader for NoPrior {
            fn last_signed_attestation(
                &self,
                _pubkey: &str,
                _gvr: &Root,
            ) -> Option<slashing::TargetEpoch> {
                None
            }
        }

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();

        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPrior);
        let machine = Arc::new(ForwardWindowMachine::new(reader, 2, [0xacu8; 32]));
        let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 0);
        let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);

        monitor.start_monitoring(pk_bytes);
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Pending,
            "import at epoch 0 must stay Pending (no pre-genesis Safe bypass on import path)"
        );
        assert!(!monitor.is_doppelganger_safe(&pk_bytes));
    }

    /// Import + recent slashing history must NOT Safe-skip (interchange hazard).
    #[test]
    fn test_import_with_recent_history_stays_pending() {
        use doppelganger::ForwardWindowStatus;

        struct RecentPrior;
        impl slashing::SlashingDbReader for RecentPrior {
            fn last_signed_attestation(
                &self,
                _pubkey: &str,
                _gvr: &Root,
            ) -> Option<slashing::TargetEpoch> {
                Some(98) // recent relative to epoch 100, monitoring=2
            }
        }

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let gvr = [0xadu8; 32];

        let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(RecentPrior);
        let machine = Arc::new(ForwardWindowMachine::new(reader, 2, gvr));
        // Boot-style register WOULD safe-skip:
        machine.register(&pk, 100);
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Safe,
            "control: boot register with recent history is Safe"
        );
        machine.cancel(&pk);

        let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = Arc::new(|| 100);
        let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);
        monitor.start_monitoring(pk_bytes);
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Pending,
            "import must not Safe-skip even with recent interchange history"
        );
        assert!(!machine.is_signing_enabled(&pk));
    }

    // --- RemoteKeyManagerAdapter tests ---

    #[test]
    fn test_remote_key_adapter_empty_list() {
        let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
        assert!(adapter.list_remote_keys().is_empty());
    }

    #[test]
    fn test_remote_key_adapter_has_key_false() {
        let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
        assert!(!adapter.has_remote_key(&test_pubkey(1)));
    }

    #[test]
    fn test_remote_key_adapter_import_and_list() {
        let composite = create_empty_composite_signer();
        let (adapter, _, _) = test_remote_adapter(composite.clone(), None);

        let pk = test_pubkey(1);
        let url = "https://signer.example.com".to_string();
        adapter.import_remote_key(pk, url.clone()).unwrap();

        let keys = adapter.list_remote_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, pk);
        assert_eq!(keys[0].1, url);
        assert!(adapter.has_remote_key(&pk));

        assert!(composite.public_keys().contains(&pk));
    }

    #[test]
    fn test_remote_key_adapter_import_duplicate() {
        let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
        let result = adapter.import_remote_key(pk, "https://signer.example.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)));
    }

    #[test]
    fn test_remote_key_adapter_delete() {
        let composite = create_empty_composite_signer();
        let (adapter, _, _) = test_remote_adapter(composite.clone(), None);

        let pk = test_pubkey(1);
        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
        assert!(adapter.has_remote_key(&pk));

        let deleted = adapter.delete_remote_key(&pk).unwrap();
        assert!(deleted);
        assert!(!adapter.has_remote_key(&pk));
        assert!(!composite.public_keys().contains(&pk));
    }

    #[test]
    fn test_remote_key_adapter_delete_nonexistent() {
        let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
        assert!(!adapter.delete_remote_key(&test_pubkey(99)).unwrap());
    }

    #[test]
    fn test_remote_key_adapter_import_rejects_invalid_url_scheme() {
        let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);

        // file:// scheme — SSRF risk
        let result = adapter.import_remote_key(pk, "file:///etc/passwd".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));

        // ftp:// scheme
        let result = adapter.import_remote_key(pk, "ftp://evil.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));

        // No scheme
        let result = adapter.import_remote_key(pk, "signer.example.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));

        // Valid schemes should be accepted
        let pk2 = test_pubkey(2);
        let result = adapter.import_remote_key(pk2, "https://signer.example.com".to_string());
        assert!(result.is_ok());
    }

    // --- Keystore import with real secret key ---

    #[test]
    fn test_keystore_manager_tracks_imported_key_in_composite_signer() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        // Manually add key (simulating what would happen with a real keystore)
        composite.add_local_key(sk);
        adapter.tracked_keys.lock().push(pk_bytes);

        assert!(adapter.has_key(&pk_bytes));
        assert!(composite.public_keys().contains(&pk_bytes));

        // Delete
        let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
        assert!(deleted);
        assert!(!adapter.has_key(&pk_bytes));
        assert!(!composite.public_keys().contains(&pk_bytes));
    }

    // --- Full lifecycle: adapters wired into KeymanagerServer ---

    fn build_test_server() -> keymanager_api::KeymanagerServer {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 100));

        let keystore_mgr = Arc::new(test_keystore_adapter(dir.keep(), composite.clone()).0);
        let slashing_prot = Arc::new(SlashingProtectionAdapter::new(
            slashing_db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
        let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
        let doppelganger_mon = Arc::new(DoppelgangerMonitorAdapter::new());
        let remote_key_mgr = Arc::new(test_remote_adapter(composite, None).0);
        let config_mgr = Arc::new(ValidatorConfigManagerAdapter::new(validator_store));

        let token = "deadbeef".repeat(8);
        let addr = "127.0.0.1:0".parse().unwrap();

        keymanager_api::KeymanagerServer::new(
            keystore_mgr,
            slashing_prot,
            validator_mgr,
            doppelganger_mon,
            remote_key_mgr,
            config_mgr,
            None,
            token,
            addr,
            vec![],
            keymanager_api::DEFAULT_BODY_LIMIT,
            true,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            std::time::Duration::ZERO,
        )
    }

    #[test]
    fn test_keymanager_server_builds_with_adapters() {
        let _server = build_test_server();
    }

    #[test]
    fn test_keymanager_server_router_builds() {
        let server = build_test_server();
        let _router = server.router();
    }

    #[tokio::test]
    async fn test_keymanager_server_list_keystores_requires_auth() {
        use tower::ServiceExt;

        let server = build_test_server();
        let router = server.router();

        // Request without auth token should be rejected
        let request = axum::http::Request::builder()
            .uri("/eth/v1/keystores")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_keymanager_server_list_keystores_empty() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let server = build_test_server();
        let router = server.router();
        let token = "deadbeef".repeat(8);

        let request = axum::http::Request::builder()
            .uri("/eth/v1/keystores")
            .header("Authorization", format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_keymanager_server_list_remote_keys_empty() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let server = build_test_server();
        let router = server.router();
        let token = "deadbeef".repeat(8);

        let request = axum::http::Request::builder()
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_keymanager_server_import_remote_key_lifecycle() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let validator_store = Arc::new(ValidatorStore::new([0u8; 20], 100));

        let keystore_mgr = Arc::new(test_keystore_adapter(dir.keep(), composite.clone()).0);
        let slashing_prot = Arc::new(SlashingProtectionAdapter::new(
            slashing_db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
        let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
        let doppelganger_mon = Arc::new(DoppelgangerMonitorAdapter::new());
        let remote_key_mgr = Arc::new(test_remote_adapter(composite.clone(), None).0);
        let config_mgr = Arc::new(ValidatorConfigManagerAdapter::new(validator_store));

        let token = "deadbeef".repeat(8);
        let addr = "127.0.0.1:0".parse().unwrap();

        let server = keymanager_api::KeymanagerServer::new(
            keystore_mgr,
            slashing_prot,
            validator_mgr,
            doppelganger_mon,
            remote_key_mgr,
            config_mgr,
            None,
            token.clone(),
            addr,
            vec![],
            keymanager_api::DEFAULT_BODY_LIMIT,
            true,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            std::time::Duration::ZERO,
        );

        // 1. Import a remote key
        let pk = test_pubkey(42);
        let pk_hex = format!("0x{}", hex::encode(pk));
        // ISSUE-4.9 / L-9: import_remote_keys re-resolves the host via DNS
        // and validates against the private/reserved deny-list. Use a public
        // IP literal so this test does not depend on a CI DNS resolver.
        let import_body = serde_json::json!({
            "remote_keys": [{
                "pubkey": pk_hex,
                "url": "https://8.8.8.8:9000"
            }]
        });

        let router = server.router();
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(import_body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let statuses = json["data"].as_array().unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["status"], "imported");

        // 2. Verify composite signer has the key
        assert!(composite.public_keys().contains(&pk));

        // 3. List remote keys - should contain the imported key
        let router = server.router();
        let request = axum::http::Request::builder()
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let keys = json["data"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["pubkey"], pk_hex);

        // 4. Delete the remote key
        let delete_body = serde_json::json!({
            "pubkeys": [pk_hex]
        });

        let router = server.router();
        let request = axum::http::Request::builder()
            .method("DELETE")
            .uri("/eth/v1/remotekeys")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(delete_body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let statuses = json["data"].as_array().unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0]["status"], "deleted");

        // 5. Verify composite signer no longer has the key
        assert!(!composite.public_keys().contains(&pk));
    }

    // --- Remote signer host allowlist tests ---

    #[test]
    fn test_import_remote_key_allowed_host_accepted() {
        let (adapter, _, _) = test_remote_adapter(
            create_empty_composite_signer(),
            Some(vec!["signer.example.com".to_string()]),
        );
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://signer.example.com/api".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_remote_key_blocked_host_rejected() {
        let (adapter, _, _) = test_remote_adapter(
            create_empty_composite_signer(),
            Some(vec!["trusted.host".to_string()]),
        );
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://evil.attacker.com/api".to_string());
        assert!(
            matches!(result, Err(ImportRemoteKeyError::Other(ref msg)) if msg.contains("not in the allowed hosts list"))
        );
    }

    #[test]
    fn test_import_remote_key_no_allowlist_allows_all() {
        let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://any.host.com".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_remote_key_allowlist_multiple_hosts() {
        let (adapter, _, _) = test_remote_adapter(
            create_empty_composite_signer(),
            Some(vec!["signer1.example.com".to_string(), "signer2.example.com".to_string()]),
        );
        let pk1 = test_pubkey(1);
        assert!(adapter.import_remote_key(pk1, "https://signer1.example.com".to_string()).is_ok());

        let pk2 = test_pubkey(2);
        assert!(adapter.import_remote_key(pk2, "https://signer2.example.com".to_string()).is_ok());

        let pk3 = test_pubkey(3);
        let result = adapter.import_remote_key(pk3, "https://signer3.example.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Other(_))));
    }

    #[test]
    fn test_import_remote_key_invalid_url_parse_error() {
        let (adapter, _, _) = test_remote_adapter(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "not a valid url".to_string());
        assert!(
            matches!(result, Err(ImportRemoteKeyError::Other(ref msg)) if msg.contains("invalid remote signer URL"))
        );
    }

    #[test]
    fn test_import_remote_key_allowlist_with_port() {
        let (adapter, _, _) = test_remote_adapter(
            create_empty_composite_signer(),
            Some(vec!["signer.example.com".to_string()]),
        );
        let pk = test_pubkey(1);
        // host_str() returns the host without port
        let result =
            adapter.import_remote_key(pk, "https://signer.example.com:9000/api".to_string());
        assert!(result.is_ok());
    }

    // --- CON-03 / RF1-06: Dynamic pubkey_map + generation counter tests ---

    #[test]
    fn test_import_updates_shared_pubkey_map_and_notifies() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (adapter, pubkey_map, mut rx) =
            test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let keystore_json = serde_json::to_string(&keystore).unwrap();
        let pk_bytes = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk_bytes));

        // Mark changed so the next has_changed() reflects only this import.
        rx.borrow_and_update();
        assert!(!rx.has_changed().unwrap());

        adapter.import_keystore(&keystore_json, "testpass").unwrap();

        assert!(
            pubkey_map.read().contains_key(&pubkey_hex),
            "import must update the shared PubkeyMap"
        );
        assert!(rx.has_changed().unwrap(), "import must notify via key_gen_tx");
        assert_eq!(*rx.borrow(), 1);
    }

    #[test]
    fn test_delete_removes_from_shared_pubkey_map_and_notifies() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (adapter, pubkey_map, mut rx) =
            test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let keystore_json = serde_json::to_string(&keystore).unwrap();
        let pk_bytes = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk_bytes));

        adapter.import_keystore(&keystore_json, "testpass").unwrap();
        assert!(pubkey_map.read().contains_key(&pubkey_hex));
        rx.borrow_and_update();
        assert!(!rx.has_changed().unwrap());

        let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
        assert!(deleted);
        assert!(
            !pubkey_map.read().contains_key(&pubkey_hex),
            "delete must remove the key from the shared PubkeyMap"
        );
        assert!(rx.has_changed().unwrap(), "delete must notify via key_gen_tx");
        assert_eq!(*rx.borrow(), 2);
    }

    #[test]
    fn test_remote_adapter_import_notifies_key_change() {
        let composite = create_empty_composite_signer();
        let (adapter, pubkey_map, mut rx) = test_remote_adapter(composite, None);

        // Valid BLS pubkey so map insert and notify are both exercised.
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk));

        rx.borrow_and_update();
        assert!(!rx.has_changed().unwrap());
        assert_eq!(*rx.borrow(), 0);

        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();

        assert!(
            pubkey_map.read().contains_key(&pubkey_hex),
            "remote import of a valid BLS key must update the shared PubkeyMap"
        );
        assert!(rx.has_changed().unwrap(), "remote import must notify via key_gen_tx");
        assert_eq!(*rx.borrow(), 1);
        assert!(adapter.has_remote_key(&pk));
    }

    #[test]
    fn test_keystore_adapter_delete_removes_from_pubkey_map() {
        // Regression: delete of a boot/manual-loaded local key clears the map entry.
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (adapter, pubkey_map, mut rx) =
            test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk_bytes));
        let pk = crypto::PublicKey::from_bytes(&pk_bytes).unwrap();

        composite.add_local_key(sk);
        adapter.tracked_keys.lock().push(pk_bytes);
        pubkey_map.write().insert(pubkey_hex.clone(), pk);

        rx.borrow_and_update();
        let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
        assert!(deleted);
        assert!(!pubkey_map.read().contains_key(&pubkey_hex));
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn test_remote_key_adapter_delete_removes_from_pubkey_map() {
        let composite = create_empty_composite_signer();
        let (adapter, pubkey_map, mut rx) = test_remote_adapter(composite, None);

        // Use a real BLS pubkey so the map entry is written on import.
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk));

        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
        assert!(pubkey_map.read().contains_key(&pubkey_hex));
        rx.borrow_and_update();

        let deleted = adapter.delete_remote_key(&pk).unwrap();
        assert!(deleted);
        assert!(!adapter.has_remote_key(&pk));
        assert!(!pubkey_map.read().contains_key(&pubkey_hex));
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn test_generation_counter_increments_on_keystore_delete() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (adapter, _map, rx) =
            test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        composite.add_local_key(sk);
        adapter.tracked_keys.lock().push(pk_bytes);

        assert_eq!(*rx.borrow(), 0);
        adapter.delete_keystore(&pk_bytes).unwrap();
        assert_eq!(*rx.borrow(), 1);
    }

    #[test]
    fn test_generation_counter_increments_on_remote_key_import() {
        let composite = create_empty_composite_signer();
        let (adapter, _map, rx) = test_remote_adapter(composite, None);

        assert_eq!(*rx.borrow(), 0);
        adapter
            .import_remote_key(test_pubkey(1), "https://signer.example.com".to_string())
            .unwrap();
        assert_eq!(*rx.borrow(), 1);
    }

    // --- TOCTOU fix tests ---

    fn setup_adapter_with_key(
        dir: &std::path::Path,
    ) -> (Arc<KeystoreManagerAdapter>, Pubkey, Arc<CompositeSigner>) {
        let composite = create_empty_composite_signer();
        let adapter = Arc::new(test_keystore_adapter(dir.to_path_buf(), composite.clone()).0);

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        // Write a dummy keystore file
        let filename = format!("0x{}.json", hex::encode(pk_bytes));
        let file_path = dir.join(&filename);
        std::fs::write(&file_path, "{}").unwrap();

        // Register in tracked_keys and composite signer
        composite.add_local_key(sk);
        adapter.tracked_keys.lock().push(pk_bytes);

        (adapter, pk_bytes, composite)
    }

    #[test]
    fn test_delete_missing_file_succeeds() {
        let dir = TempDir::new().unwrap();
        let (adapter, pk_bytes, _composite) = setup_adapter_with_key(dir.path());

        // Manually remove the file to simulate external deletion
        let filename = format!("0x{}.json", hex::encode(pk_bytes));
        let file_path = dir.path().join(&filename);
        std::fs::remove_file(&file_path).unwrap();
        assert!(!file_path.exists());

        // delete_keystore should succeed (not error) even though file is gone
        let result = adapter.delete_keystore(&pk_bytes);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(!adapter.has_key(&pk_bytes));
    }

    #[test]
    fn test_concurrent_delete_same_key() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let composite = create_empty_composite_signer();
        let adapter =
            Arc::new(test_keystore_adapter(dir.path().to_path_buf(), composite.clone()).0);

        // Set up N keys, each will be deleted by two threads simultaneously
        let n = 10;
        let mut keys = Vec::new();
        for _ in 0..n {
            let sk = SecretKey::generate();
            let pk_bytes = sk.public_key().to_bytes();
            let filename = format!("0x{}.json", hex::encode(pk_bytes));
            std::fs::write(dir.path().join(&filename), "{}").unwrap();
            composite.add_local_key(sk);
            adapter.tracked_keys.lock().push(pk_bytes);
            keys.push(pk_bytes);
        }

        let mut handles = Vec::new();
        for key in &keys {
            let key = *key;
            // Two threads race to delete the same key
            for _ in 0..2 {
                let adapter = adapter.clone();
                handles.push(thread::spawn(move || adapter.delete_keystore(&key)));
            }
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // All calls should succeed (no panic, no error)
        for result in &results {
            assert!(result.is_ok());
        }
        // For each key, exactly one thread should return true, the other false
        for key in &keys {
            let key_results: Vec<bool> = results
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    let key_idx = keys.iter().position(|k| k == key).unwrap();
                    *i / 2 == key_idx
                })
                .map(|(_, r)| *r.as_ref().unwrap())
                .collect();
            assert_eq!(
                key_results.iter().filter(|&&v| v).count(),
                1,
                "exactly one delete should return true for each key"
            );
        }
        assert!(adapter.list_keys().is_empty());
    }

    #[test]
    fn test_concurrent_import_same_key() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let composite = create_empty_composite_signer();
        let adapter =
            Arc::new(test_keystore_adapter(dir.path().to_path_buf(), composite.clone()).0);

        let sk = SecretKey::generate();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let keystore_json = serde_json::to_string(&keystore).unwrap();

        let n = 10;
        let mut handles = Vec::new();
        for _ in 0..n {
            let adapter = adapter.clone();
            let json = keystore_json.clone();
            handles.push(thread::spawn(move || adapter.import_keystore(&json, "testpass")));
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let duplicates =
            results.iter().filter(|r| matches!(r, Err(ImportKeystoreError::Duplicate))).count();
        assert_eq!(successes, 1, "exactly one import should succeed");
        assert_eq!(duplicates, n - 1, "all others should be Duplicate");
        assert_eq!(adapter.list_keys().len(), 1);
    }

    #[test]
    fn test_concurrent_import_delete_same_key() {
        use std::sync::Barrier;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let composite = create_empty_composite_signer();
        let (adapter, pubkey_map, _rx) =
            test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
        let adapter = Arc::new(adapter);

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk_bytes));
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let keystore_json = serde_json::to_string(&keystore).unwrap();

        // Import the key first
        adapter.import_keystore(&keystore_json, "testpass").unwrap();
        assert!(adapter.has_key(&pk_bytes));

        // Now race: half delete, half try to re-import
        let n = 10;
        let barrier = Arc::new(Barrier::new(n));
        let mut handles = Vec::new();
        for i in 0..n {
            let adapter = adapter.clone();
            let json = keystore_json.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                if i % 2 == 0 {
                    let _ = adapter.delete_keystore(&pk_bytes);
                } else {
                    let _ = adapter.import_keystore(&json, "testpass");
                }
            }));
        }

        // No thread should panic
        for h in handles {
            h.join().expect("thread should not panic");
        }

        // Final state should be consistent: list_keys and has_key agree on
        // registry membership (CompositeSigner local set, not tracked_keys).
        let keys = adapter.list_keys();
        let has_key = adapter.has_key(&pk_bytes);
        assert_eq!(keys.contains(&pk_bytes), has_key);

        // S1: PubkeyMap must stay in sync with the signing registry after concurrent
        // delete vs re-import (map remove runs under the same lock as registry ops).
        let in_map = pubkey_map.read().contains_key(&pubkey_hex);
        assert_eq!(
            in_map, has_key,
            "PubkeyMap membership must match CompositeSigner after concurrent delete/import"
        );
    }

    // --- ValidatorConfigManagerAdapter tests ---

    fn create_config_adapter_with_store() -> (ValidatorConfigManagerAdapter, Arc<ValidatorStore>) {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(
            &config_path,
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
        )
        .unwrap();
        let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
        // Keep TempDir alive by leaking it — tests are short-lived
        std::mem::forget(dir);
        let adapter = ValidatorConfigManagerAdapter::new(store.clone());
        (adapter, store)
    }

    fn add_test_validator(store: &ValidatorStore, id: u8) -> Pubkey {
        let pk = test_pubkey(id);
        store.add_validator(validator_store::ValidatorConfig::new(pk));
        pk
    }

    #[test]
    fn test_config_adapter_unknown_pubkey_returns_not_found() {
        let (adapter, _store) = create_config_adapter_with_store();
        let pk = test_pubkey(99);

        assert!(matches!(adapter.get_fee_recipient(&pk), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.get_gas_limit(&pk), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.get_graffiti(&pk), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.set_fee_recipient(&pk, [0u8; 20]), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.set_gas_limit(&pk, 100), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.set_graffiti(&pk, "test"), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.delete_fee_recipient(&pk), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.delete_gas_limit(&pk), Err(ApiError::NotFound(_))));
        assert!(matches!(adapter.delete_graffiti(&pk), Err(ApiError::NotFound(_))));
    }

    #[test]
    fn test_config_adapter_get_fee_recipient_returns_default() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        let fee = adapter.get_fee_recipient(&pk).unwrap();
        // Default from config: 0x0000000000000000000000000000000000000001
        let mut expected = [0u8; 20];
        expected[19] = 1;
        assert_eq!(fee, expected);
    }

    #[test]
    fn test_config_adapter_fee_recipient_set_get_roundtrip() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        let new_fee = [0xABu8; 20];
        adapter.set_fee_recipient(&pk, new_fee).unwrap();

        let got = adapter.get_fee_recipient(&pk).unwrap();
        assert_eq!(got, new_fee);
    }

    #[test]
    fn test_config_adapter_fee_recipient_delete_resets_to_default() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        let new_fee = [0xABu8; 20];
        adapter.set_fee_recipient(&pk, new_fee).unwrap();
        adapter.delete_fee_recipient(&pk).unwrap();

        let got = adapter.get_fee_recipient(&pk).unwrap();
        // Should be back to default
        let mut expected = [0u8; 20];
        expected[19] = 1;
        assert_eq!(got, expected);
    }

    #[test]
    fn test_config_adapter_get_gas_limit_returns_default() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        let limit = adapter.get_gas_limit(&pk).unwrap();
        assert_eq!(limit, 30_000_000);
    }

    #[test]
    fn test_config_adapter_gas_limit_set_get_roundtrip() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        adapter.set_gas_limit(&pk, 50_000_000).unwrap();
        let got = adapter.get_gas_limit(&pk).unwrap();
        assert_eq!(got, 50_000_000);
    }

    #[test]
    fn test_config_adapter_gas_limit_delete_resets_to_default() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        adapter.set_gas_limit(&pk, 50_000_000).unwrap();
        adapter.delete_gas_limit(&pk).unwrap();
        let got = adapter.get_gas_limit(&pk).unwrap();
        assert_eq!(got, 30_000_000);
    }

    #[test]
    fn test_config_adapter_get_graffiti_returns_empty_when_none() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        let graffiti = adapter.get_graffiti(&pk).unwrap();
        assert_eq!(graffiti, "");
    }

    #[test]
    fn test_config_adapter_graffiti_set_get_roundtrip() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        adapter.set_graffiti(&pk, "hello world").unwrap();
        let got = adapter.get_graffiti(&pk).unwrap();
        assert_eq!(got, "hello world");
    }

    #[test]
    fn test_config_adapter_graffiti_delete_resets_to_default() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        adapter.set_graffiti(&pk, "hello").unwrap();
        adapter.delete_graffiti(&pk).unwrap();
        let got = adapter.get_graffiti(&pk).unwrap();
        assert_eq!(got, "");
    }

    #[test]
    fn test_config_adapter_save_persists_to_file() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(
            &config_path,
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n",
        )
        .unwrap();
        let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
        let adapter = ValidatorConfigManagerAdapter::new(store.clone());

        let pk = test_pubkey(1);
        store.add_validator(validator_store::ValidatorConfig::new(pk));

        let fee = [0xFFu8; 20];
        adapter.set_fee_recipient(&pk, fee).unwrap();

        // Reload from disk and verify
        let store2 = ValidatorStore::load_from_config(&config_path).unwrap();
        let loaded_fee = store2.effective_fee_recipient(&pk);
        assert_eq!(loaded_fee, fee);
    }

    #[test]
    fn test_config_adapter_graffiti_truncates_long_input() {
        let (adapter, store) = create_config_adapter_with_store();
        let pk = add_test_validator(&store, 1);

        let long_graffiti = "a".repeat(64);
        adapter.set_graffiti(&pk, &long_graffiti).unwrap();
        let got = adapter.get_graffiti(&pk).unwrap();
        assert_eq!(got.len(), 32);
        assert_eq!(got, "a".repeat(32));
    }

    // --- VoluntaryExitManagerAdapter tests ---

    fn create_exit_adapter(beacon_url: &str, secret_key: SecretKey) -> VoluntaryExitManagerAdapter {
        let beacon_config = beacon::BeaconClientConfig::new(beacon_url);
        let beacon_client = Arc::new(BeaconClient::new(beacon_config).expect("test beacon client"));

        let key_manager = crypto::KeyManager::new();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(key_manager)));
        composite.add_local_key(secret_key);

        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let signer =
            Arc::new(SignerService::new(composite, slashing_db).with_enablement(always_enabled()));

        let fork_schedule = Arc::new(ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 20,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 30,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 40,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 50,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: 60,
            fulu_fork_version: [6, 0, 0, 0],
        });

        let genesis_validators_root = [0xaa; 32];

        VoluntaryExitManagerAdapter::new(
            beacon_client,
            signer,
            fork_schedule,
            genesis_validators_root,
        )
    }

    #[test]
    fn test_exit_adapter_struct_construction() {
        let sk = SecretKey::generate();
        let _adapter = create_exit_adapter("http://localhost:5052", sk);
    }

    #[tokio::test]
    async fn test_exit_adapter_validator_not_found() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&mock_server)
            .await;

        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let adapter = create_exit_adapter(&mock_server.uri(), sk);

        let result = adapter.sign_voluntary_exit(&pubkey, Some(100)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::NotFound(msg) => assert!(msg.contains("not found")),
            other => panic!("expected NotFound, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_exit_adapter_sign_with_explicit_epoch() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let sk = SecretKey::generate();
        let pubkey_bytes = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));

        Mock::given(method("GET"))
            .and(path_regex("/eth/v1/beacon/states/head/validators.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "index": "42",
                    "status": "active_ongoing",
                    "validator": {
                        "pubkey": pubkey_hex,
                        "withdrawal_credentials": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "effective_balance": "32000000000",
                        "slashed": false,
                        "activation_eligibility_epoch": "0",
                        "activation_epoch": "0",
                        "exit_epoch": "18446744073709551615",
                        "withdrawable_epoch": "18446744073709551615"
                    }
                }]
            })))
            .mount(&mock_server)
            .await;

        let adapter = create_exit_adapter(&mock_server.uri(), sk);

        let result = adapter.sign_voluntary_exit(&pubkey_bytes, Some(100)).await;
        assert!(result.is_ok());

        let signed = result.unwrap();
        assert_eq!(signed.message.epoch, 100);
        assert_eq!(signed.message.validator_index, 42);
        assert_eq!(signed.signature.len(), 96);
    }

    #[tokio::test]
    async fn test_exit_adapter_beacon_unreachable() {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key().to_bytes();
        let adapter = create_exit_adapter("http://127.0.0.1:1", sk);

        let result = adapter.sign_voluntary_exit(&pubkey, Some(100)).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Internal(msg) => assert!(msg.contains("beacon node error")),
            other => panic!("expected Internal, got: {:?}", other),
        }
    }

    // --- Issue 4.4: Config persistence integration tests ---

    fn create_persistence_adapter(
        dir: &std::path::Path,
    ) -> (ValidatorConfigManagerAdapter, std::path::PathBuf) {
        let config_path = dir.join("validators.toml");
        let pubkey_hex = format!("0x{}", hex::encode(test_pubkey(1)));
        let toml = format!(
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"{}\"\n",
            pubkey_hex,
        );
        std::fs::write(&config_path, &toml).unwrap();
        let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
        let adapter = ValidatorConfigManagerAdapter::new(store);
        (adapter, config_path)
    }

    #[test]
    fn test_config_persistence_fee_recipient() {
        let dir = TempDir::new().unwrap();
        let (adapter, config_path) = create_persistence_adapter(dir.path());
        let pk = test_pubkey(1);

        let fee = [0xABu8; 20];
        adapter.set_fee_recipient(&pk, fee).unwrap();

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(reloaded.effective_fee_recipient(&pk), fee);
    }

    #[test]
    fn test_config_persistence_gas_limit() {
        let dir = TempDir::new().unwrap();
        let (adapter, config_path) = create_persistence_adapter(dir.path());
        let pk = test_pubkey(1);

        adapter.set_gas_limit(&pk, 50_000_000).unwrap();

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(reloaded.effective_gas_limit(&pk), 50_000_000);
    }

    #[test]
    fn test_config_persistence_graffiti() {
        let dir = TempDir::new().unwrap();
        let (adapter, config_path) = create_persistence_adapter(dir.path());
        let pk = test_pubkey(1);

        adapter.set_graffiti(&pk, "persist me").unwrap();

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
        let graffiti = reloaded.effective_graffiti(&pk).unwrap();
        let end = graffiti.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let s = std::str::from_utf8(&graffiti[..end]).unwrap();
        assert_eq!(s, "persist me");
    }

    #[test]
    fn test_config_persistence_delete_reverts() {
        let dir = TempDir::new().unwrap();
        let (adapter, config_path) = create_persistence_adapter(dir.path());
        let pk = test_pubkey(1);

        adapter.set_fee_recipient(&pk, [0xBBu8; 20]).unwrap();
        adapter.delete_fee_recipient(&pk).unwrap();

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
        let mut expected_default = [0u8; 20];
        expected_default[19] = 1;
        assert_eq!(reloaded.effective_fee_recipient(&pk), expected_default);

        adapter.set_gas_limit(&pk, 99_000_000).unwrap();
        adapter.delete_gas_limit(&pk).unwrap();

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(reloaded.effective_gas_limit(&pk), 30_000_000);

        adapter.set_graffiti(&pk, "temporary").unwrap();
        adapter.delete_graffiti(&pk).unwrap();

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(reloaded.effective_graffiti(&pk).is_none());
    }

    #[test]
    fn test_config_persistence_concurrent_writes() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut toml = String::from(
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n",
        );
        for i in 0..10u8 {
            let pk_hex = format!("0x{}", hex::encode(test_pubkey(i)));
            toml.push_str(&format!("[[validators]]\npubkey = \"{}\"\n\n", pk_hex));
        }
        std::fs::write(&config_path, &toml).unwrap();
        let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
        let adapter = Arc::new(ValidatorConfigManagerAdapter::new(store));

        let mut handles = vec![];
        for i in 0..10u8 {
            let adapter = adapter.clone();
            handles.push(thread::spawn(move || {
                let pk = test_pubkey(i);
                let mut fr = [0u8; 20];
                fr[0] = i;
                adapter.set_fee_recipient(&pk, fr).unwrap();
                adapter.set_gas_limit(&pk, 30_000_000 + i as u64 * 1_000_000).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();
        for i in 0..10u8 {
            let pk = test_pubkey(i);
            let fr = reloaded.effective_fee_recipient(&pk);
            assert_eq!(fr[0], i);
            // Gas limit should be one of the written values for this validator
            let gl = reloaded.effective_gas_limit(&pk);
            assert_eq!(gl, 30_000_000 + i as u64 * 1_000_000);
        }
    }

    // ── M-12 Critical #2: import_meta sidecar persistence ────────────────

    /// Importing a keystore must write a `0x<pubkey>.import_meta.json` sidecar
    /// with the current Unix timestamp.
    #[test]
    fn test_import_keystore_writes_import_meta_sidecar() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let keystore_json = serde_json::to_string(&keystore).unwrap();

        let before =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        adapter.import_keystore(&keystore_json, "testpass").unwrap();

        let after =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        // The sidecar must exist
        let meta_path = import_meta_path(dir.path(), &pk_bytes);
        assert!(meta_path.exists(), "import_meta sidecar must be written on import");

        // The sidecar must contain a valid timestamp
        let content = std::fs::read_to_string(&meta_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        let ts = v["imported_unix_seconds"].as_u64().expect("timestamp missing");
        assert!(
            ts >= before && ts <= after,
            "sidecar timestamp must be within the import window: before={before} ts={ts} after={after}"
        );
    }

    /// Deleting a keystore must remove the corresponding sidecar.
    #[test]
    fn test_delete_keystore_removes_import_meta_sidecar() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let keystore_json = serde_json::to_string(&keystore).unwrap();
        adapter.import_keystore(&keystore_json, "testpass").unwrap();

        let meta_path = import_meta_path(dir.path(), &pk_bytes);
        assert!(meta_path.exists(), "sidecar should exist after import");

        adapter.delete_keystore(&pk_bytes).unwrap();
        assert!(!meta_path.exists(), "sidecar must be removed after delete");
    }

    /// `scan_and_rearm_gate` must call `start_monitoring` for any key whose
    /// sidecar shows an import timestamp within the configured window.
    #[test]
    fn test_scan_and_rearm_gate_rearms_recent_keys() {
        use keymanager_api::gate::DoppelgangerGate;
        use keymanager_api::traits::DoppelgangerMonitor;
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        let pk: Pubkey = [0xABu8; 48];

        // Write a sidecar with import time = now (very recent → still in window)
        let now_unix =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let meta_path = import_meta_path(dir.path(), &pk);
        std::fs::write(&meta_path, format!("{{\"imported_unix_seconds\":{}}}", now_unix)).unwrap();

        let window_secs = 768u64; // 2 epochs on mainnet
        let gate = DoppelgangerGate::new(Duration::from_secs(window_secs));

        // Before rearm: key is not monitored → safe by default
        assert!(gate.is_doppelganger_safe(&pk), "key must be safe before monitoring starts");

        scan_and_rearm_gate(dir.path(), &gate, window_secs);

        // After rearm: key is monitored → not safe yet (just started)
        assert!(!gate.is_doppelganger_safe(&pk), "key must be blocked after gate is re-armed");
    }

    /// `scan_and_rearm_gate` must NOT re-arm keys whose window has already elapsed.
    #[test]
    fn test_scan_and_rearm_gate_skips_expired_keys() {
        use keymanager_api::gate::DoppelgangerGate;
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        let pk: Pubkey = [0xCDu8; 48];
        let window_secs = 768u64;

        // Write a sidecar with import time = now - window - 100s (already expired)
        let old_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(window_secs + 100);
        let meta_path = import_meta_path(dir.path(), &pk);
        std::fs::write(&meta_path, format!("{{\"imported_unix_seconds\":{}}}", old_unix)).unwrap();

        let gate = DoppelgangerGate::new(Duration::from_secs(window_secs));
        scan_and_rearm_gate(dir.path(), &gate, window_secs);

        // Key should NOT be re-armed because window has expired
        assert!(gate.is_doppelganger_safe(&pk), "expired key must remain safe (not re-armed)");
    }

    // ── SEC-1a: real signing registry for list/has/delete ─────────────────

    /// Simulate a boot-loaded keystore-dir key: present in `LocalSigner` /
    /// `KeyManager`, never registered via `import_keystore` / `tracked_keys`.
    fn boot_load_keystore_dir_key() -> (TempDir, Arc<CompositeSigner>, Pubkey) {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let mut km = KeyManager::new();
        km.insert(sk);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
        let dir = TempDir::new().unwrap();
        // Optional on-disk keystore file (as `--keystore-path` would leave behind)
        let filename = format!("0x{}.json", hex::encode(pk_bytes));
        std::fs::write(dir.path().join(&filename), "{}").unwrap();
        (dir, composite, pk_bytes)
    }

    #[test]
    fn test_list_keys_includes_boot_loaded_keystore_dir_key() {
        let (dir, composite, pk) = boot_load_keystore_dir_key();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);

        let keys = adapter.list_keys();
        assert!(
            keys.contains(&pk),
            "boot-loaded keystore-dir key must appear in list_keys (real registry)"
        );
    }

    #[test]
    fn test_has_key_true_for_boot_loaded_key() {
        let (dir, composite, pk) = boot_load_keystore_dir_key();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);

        assert!(
            adapter.has_key(&pk),
            "has_key must be true for a boot-loaded key even without import_keystore"
        );
    }

    #[tokio::test]
    async fn test_delete_boot_loaded_key_returns_ok_true_and_stops_signing() {
        let (dir, composite, pk) = boot_load_keystore_dir_key();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
        let signing_root: eth_types::Root = [0x11; 32];

        assert!(composite.sign(&signing_root, &pk).await.is_ok(), "precondition: key can sign");

        let deleted = adapter.delete_keystore(&pk).expect("delete must not IO-error");
        assert!(deleted, "delete_keystore must return Ok(true) for boot-loaded keys");
        assert!(!adapter.has_key(&pk));
        assert!(!composite.has_local_key(&pk));
        assert!(
            matches!(
                composite.sign(&signing_root, &pk).await,
                Err(crypto::SigningError::KeyNotFound(_))
            ),
            "signing must fail after delete (key removed from real registry)"
        );

        // Keystore-dir file removed
        let filename = format!("0x{}.json", hex::encode(pk));
        assert!(!dir.path().join(&filename).exists());
    }

    #[test]
    fn test_delete_returns_real_eip3076_interchange_for_key_with_history() {
        // Mirrors the DELETE handler: has_key gates export of existing keys, so a
        // boot-loaded key with real slashing rows must yield a non-empty history
        // in the interchange (not the empty interchange used for never-known keys).
        let (dir, composite, pk) = boot_load_keystore_dir_key();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);

        let gvr_hex = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let gvr_root = [0u8; 32];
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let pk_hex = format!("0x{}", hex::encode(pk));
        db.seed_attestation(&pk_hex, 10, 11, None, &gvr_root).expect("seed history");
        db.seed_block(&pk_hex, 42, None, &gvr_root).expect("seed block history");

        let slashing = SlashingProtectionAdapter::new(db, gvr_hex.to_string());

        assert!(
            adapter.has_key(&pk),
            "handler only exports interchange for keys where has_key is true"
        );

        let export = slashing.export_interchange(&[pk]).expect("export");
        let v: serde_json::Value = serde_json::from_str(&export).unwrap();
        let data = v["data"].as_array().expect("data array");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["pubkey"], pk_hex);
        assert!(
            !data[0]["signed_attestations"].as_array().unwrap().is_empty(),
            "interchange must carry the key's real attestation history"
        );
        assert!(
            !data[0]["signed_blocks"].as_array().unwrap().is_empty(),
            "interchange must carry the key's real block history"
        );

        assert!(adapter.delete_keystore(&pk).unwrap());
        assert!(!adapter.has_key(&pk));
    }

    #[test]
    fn test_delete_never_known_pubkey_returns_not_found_no_side_effects() {
        let (dir, composite, boot_pk) = boot_load_keystore_dir_key();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        let unknown = test_pubkey(0xEE);
        let before_keys = adapter.list_keys();
        let before_signable = composite.local_public_keys();

        let result = adapter.delete_keystore(&unknown).expect("never-known must not IO-error");
        assert!(!result, "never-known pubkey must return Ok(false) → handler not_found");

        assert_eq!(adapter.list_keys(), before_keys);
        assert_eq!(composite.local_public_keys(), before_signable);
        assert!(adapter.has_key(&boot_pk), "unrelated boot-loaded key must remain");
        assert!(composite.has_local_key(&boot_pk));
    }

    /// Secret-provider-style keys land in the same LocalSigner / KeyManager set
    /// (or later via `add_local_key` on refresh). Confirm list/has/delete cover them.
    #[test]
    fn test_list_has_delete_secret_provider_style_local_key() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        // Refresh path uses add_local_key; initial load uses KeyManager — both are local.
        let composite = create_empty_composite_signer();
        composite.add_local_key(sk);
        let dir = TempDir::new().unwrap();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());

        assert!(adapter.has_key(&pk));
        assert!(adapter.list_keys().contains(&pk));
        assert!(adapter.delete_keystore(&pk).unwrap());
        assert!(!adapter.has_key(&pk));
        assert!(!composite.has_local_key(&pk));
    }

    /// Boot-loaded keystore under a non-canonical name (`validator1.json`).
    /// DELETE must unlink that file and stop signing (review Finding 1).
    #[tokio::test]
    async fn test_delete_removes_non_canonical_boot_loaded_keystore_file() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();

        let mut km = KeyManager::new();
        km.insert(sk);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));

        let dir = TempDir::new().unwrap();
        // Deposit-cli / operator style name — not `0x{pubkey}.json`.
        // Delete matches on the EIP-2335 `pubkey` JSON field (no secret material needed).
        let file_path = dir.path().join("validator1.json");
        let keystore_json = serde_json::json!({
            "crypto": {
                "kdf": {"function": "scrypt", "params": {"dklen": 32, "n": 2, "p": 1, "r": 8, "salt": "aa"}, "message": ""},
                "checksum": {"function": "sha256", "params": {}, "message": "00"},
                "cipher": {"function": "aes-128-ctr", "params": {"iv": "00"}, "message": "00"}
            },
            "pubkey": hex::encode(pk),
            "path": "m/12381/3600/0/0/0",
            "uuid": "00000000-0000-0000-0000-000000000001",
            "version": 4
        });
        std::fs::write(&file_path, keystore_json.to_string()).unwrap();
        assert!(file_path.exists());

        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
        let signing_root: eth_types::Root = [0x22; 32];
        assert!(composite.sign(&signing_root, &pk).await.is_ok());

        let deleted = adapter.delete_keystore(&pk).expect("delete");
        assert!(deleted);
        assert!(!file_path.exists(), "non-canonical keystore file must be unlinked");
        assert!(!adapter.has_key(&pk));
        assert!(matches!(
            composite.sign(&signing_root, &pk).await,
            Err(crypto::SigningError::KeyNotFound(_))
        ));
        // Canonical name must not have been created as a side effect
        assert!(!dir.path().join(format!("0x{}.json", hex::encode(pk))).exists());
    }

    // ── SEC-1b: persistent deletion denylist ──────────────────────────────

    #[test]
    fn test_delete_writes_denylist_entry() {
        use crate::deletion_denylist::{deleted_keys_path, DeletionDenylist};

        let (dir, composite, pk) = boot_load_keystore_dir_key();
        let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);
        let adapter = adapter.with_denylist(Arc::clone(&denylist));

        assert!(adapter.delete_keystore(&pk).unwrap());
        assert!(denylist.contains(&pk));
        assert!(deleted_keys_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn test_deleted_keystore_dir_key_not_resurrected_on_restart() {
        use std::collections::HashMap;

        use crate::deletion_denylist::DeletionDenylist;
        use crypto::EncryptionKdf;
        use secrecy::SecretString;

        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");

        let dir = TempDir::new().unwrap();
        let filename = format!("0x{}.json", hex::encode(pk));
        std::fs::write(dir.path().join(&filename), serde_json::to_string(&keystore).unwrap())
            .unwrap();

        // Boot load into composite + KeyManager
        let mut passwords = HashMap::new();
        passwords.insert("*".to_string(), SecretString::from("testpass".to_string()));
        let km = KeyManager::load_from_directory(dir.path(), &passwords).unwrap();
        assert!(km.contains(&pk));
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));

        let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
        let adapter = adapter.with_denylist(Arc::clone(&denylist));

        // DELETE via API — file gone, denylist written, signing stopped
        assert!(adapter.delete_keystore(&pk).unwrap());
        assert!(!composite.has_local_key(&pk));
        assert!(denylist.contains(&pk));

        // Operator (or residual file) puts the keystore back — RockLogic pattern
        std::fs::write(dir.path().join(&filename), serde_json::to_string(&keystore).unwrap())
            .unwrap();

        // Simulated restart: load_from_directory with denylist must skip the key
        let deny_set = denylist.snapshot();
        let km2 = KeyManager::load_from_directory_with_threads_filtered(
            dir.path(),
            &passwords,
            Some(1),
            Some(&deny_set),
        )
        .unwrap();
        assert!(!km2.contains(&pk), "denylisted keystore-dir key must not resurrect on restart");
        assert_eq!(km2.len(), 0);
    }

    #[test]
    fn test_reimport_clears_denylist_and_allows_key_again() {
        use crate::deletion_denylist::DeletionDenylist;
        use crypto::EncryptionKdf;

        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
        let adapter = adapter.with_denylist(Arc::clone(&denylist));

        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let keystore_json = serde_json::to_string(&keystore).unwrap();

        adapter.import_keystore(&keystore_json, "testpass").unwrap();
        assert!(adapter.delete_keystore(&pk).unwrap());
        assert!(denylist.contains(&pk), "delete must denylist");

        // Intentional re-import clears denylist so the key is allowed again
        adapter.import_keystore(&keystore_json, "testpass").unwrap();
        assert!(!denylist.contains(&pk), "re-import must clear denylist entry");
        assert!(adapter.has_key(&pk));
        assert!(composite.has_local_key(&pk));

        // Persist across reload
        let reloaded = DeletionDenylist::load(dir.path()).unwrap();
        assert!(!reloaded.contains(&pk));
    }

    #[test]
    fn test_delete_without_denylist_still_stops_signing() {
        // SEC-1a preserved when denylist is not wired (unit tests / no data dir).
        let (dir, composite, pk) = boot_load_keystore_dir_key();
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
        assert!(adapter.delete_keystore(&pk).unwrap());
        assert!(!composite.has_local_key(&pk));
        assert!(!crate::deletion_denylist::deleted_keys_path(dir.path()).exists());
    }

    /// Denylist is written *before* registry removal: a failed insert leaves the
    /// key still local so DELETE is retryable (Finding 1).
    #[test]
    fn test_delete_denylist_before_registry_removal_order() {
        use crate::deletion_denylist::DeletionDenylist;

        let (dir, composite, pk) = boot_load_keystore_dir_key();
        let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite.clone());
        let adapter = adapter.with_denylist(Arc::clone(&denylist));

        assert!(adapter.delete_keystore(&pk).unwrap());
        // After success both hold: denylist has key and registry does not.
        assert!(denylist.contains(&pk));
        assert!(!composite.has_local_key(&pk));

        // Retry DELETE of non-local key still force-inserts denylist (idempotent)
        // and returns Ok(false) → handler not_found.
        assert!(!adapter.delete_keystore(&pk).unwrap());
        assert!(denylist.contains(&pk));
    }

    /// Failed re-import must not clear the denylist (Finding 2).
    #[test]
    fn test_failed_reimport_leaves_denylist_intact() {
        use crate::deletion_denylist::DeletionDenylist;

        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let denylist = Arc::new(DeletionDenylist::load(dir.path()).unwrap());
        let (adapter, _, _) = test_keystore_adapter(dir.path().to_path_buf(), composite);
        let adapter = adapter.with_denylist(Arc::clone(&denylist));

        let pk = test_pubkey(0xF1);
        denylist.insert(&pk).unwrap();
        assert!(denylist.contains(&pk));

        // Invalid keystore JSON fails before any denylist mutation.
        let err = adapter.import_keystore("not-valid-json", "password");
        assert!(matches!(err, Err(ImportKeystoreError::InvalidKeystore(_))));

        assert!(denylist.contains(&pk), "failed import must not clear denylist");
        let reloaded = DeletionDenylist::load(dir.path()).unwrap();
        assert!(
            reloaded.contains(&pk),
            "denylist on disk must still contain key after failed import"
        );
    }

    /// SEC-5 / H-5: correctly-passworded keystore with a truncated IV must
    /// surface as a per-item import error (`DecryptionFailed`), not panic.
    /// The adapter stays usable afterward (service keeps running).
    #[test]
    fn test_keymanager_import_iv_corrupted_keystore_returns_item_error() {
        use crypto::EncryptionKdf;

        let dir = TempDir::new().unwrap();
        let (adapter, _, _) =
            test_keystore_adapter(dir.path().to_path_buf(), create_empty_composite_signer());

        let sk = SecretKey::generate();
        let password = "sec5-import-password";
        let mut keystore = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        // Corrupt IV to 8 bytes (16 hex chars). Checksum still matches so
        // decrypt reaches the former panic site in decrypt_ciphertext.
        keystore.crypto.cipher.params.iv = hex::encode([0u8; 8]);
        let json = keystore.to_json().expect("serialize");

        let err = adapter.import_keystore(&json, password);
        match err {
            Err(ImportKeystoreError::DecryptionFailed(msg)) => {
                assert!(
                    msg.contains("invalid cipher IV length") || msg.contains("IV length"),
                    "expected InvalidIvLength surfaced as DecryptionFailed, got: {msg}"
                );
            }
            other => panic!("expected DecryptionFailed item error, got: {other:?}"),
        }

        // Service/adapter still responsive after the failed item.
        assert!(adapter.list_keys().is_empty());
        assert!(!adapter.has_key(&sk.public_key().to_bytes()));
    }
}
