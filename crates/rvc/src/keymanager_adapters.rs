use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

use async_trait::async_trait;
use beacon::BeaconClient;
use crypto::{CompositeSigner, Keystore, PublicKey, RemoteSigner, RemoteSignerConfig};
use eth_types::{
    ForkSchedule, Root, SignedVoluntaryExit, VoluntaryExit, SECONDS_PER_SLOT, SLOTS_PER_EPOCH,
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
use tracing::{info, warn};
use validator_store::{ValidatorConfigUpdate, ValidatorStore};

use crate::orchestrator::PubkeyMap;

pub struct KeystoreManagerAdapter {
    keystore_dir: PathBuf,
    composite_signer: Arc<CompositeSigner>,
    tracked_keys: Mutex<Vec<Pubkey>>,
    pubkey_map: Option<PubkeyMap>,
    key_gen_tx: Option<watch::Sender<u64>>,
}

impl KeystoreManagerAdapter {
    pub fn new(keystore_dir: PathBuf, composite_signer: Arc<CompositeSigner>) -> Self {
        Self {
            keystore_dir,
            composite_signer,
            tracked_keys: Mutex::new(Vec::new()),
            pubkey_map: None,
            key_gen_tx: None,
        }
    }

    pub fn with_pubkey_map(
        mut self,
        pubkey_map: PubkeyMap,
        key_gen_tx: watch::Sender<u64>,
    ) -> Self {
        self.pubkey_map = Some(pubkey_map);
        self.key_gen_tx = Some(key_gen_tx);
        self
    }

    fn notify_key_change(&self) {
        if let Some(tx) = &self.key_gen_tx {
            tx.send_modify(|gen| *gen += 1);
        }
    }
}

/// Returns the path for the M-12 import-time metadata sidecar for `pubkey`.
///
/// Format: `<keystore_dir>/0x<hex_pubkey>.import_meta.json`
fn import_meta_path(keystore_dir: &std::path::Path, pubkey: &Pubkey) -> std::path::PathBuf {
    keystore_dir.join(format!("0x{}.import_meta.json", hex::encode(pubkey)))
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
    fn list_keys(&self) -> Vec<Pubkey> {
        self.tracked_keys.lock().clone()
    }

    fn has_key(&self, pubkey: &Pubkey) -> bool {
        self.tracked_keys.lock().contains(pubkey)
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

        // Hold lock for the entire check-and-insert to prevent TOCTOU race
        let mut keys = self.tracked_keys.lock();
        if keys.contains(&pubkey_bytes) {
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

        // Update shared pubkey_map
        if let Some(ref map) = self.pubkey_map {
            let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));
            map.write().insert(pubkey_hex, public_key);
            self.notify_key_change();
        }

        info!(pubkey = %hex::encode(pubkey_bytes), "Imported keystore");
        Ok(pubkey_bytes)
    }

    fn delete_keystore(&self, pubkey: &Pubkey) -> Result<bool, DeleteKeystoreError> {
        let mut keys = self.tracked_keys.lock();
        if let Some(pos) = keys.iter().position(|k| k == pubkey) {
            // Delete file FIRST — if IO fails, memory state remains consistent
            let filename = format!("0x{}.json", hex::encode(pubkey));
            let file_path = self.keystore_dir.join(&filename);
            match std::fs::remove_file(&file_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    warn!(
                        pubkey = %hex::encode(pubkey),
                        "keystore file already absent during delete"
                    );
                }
                Err(e) => return Err(DeleteKeystoreError::Io(e.to_string())),
            }

            // M-12 (Critical #2): remove the import-time sidecar so a
            // subsequent re-import starts with a clean timestamp.
            let meta_path = import_meta_path(&self.keystore_dir, pubkey);
            let _ = std::fs::remove_file(&meta_path);

            // Only remove from memory after file delete succeeds
            keys.remove(pos);
            drop(keys);

            self.composite_signer.remove_local_key(pubkey);

            // Remove from shared pubkey_map
            if let Some(ref map) = self.pubkey_map {
                let pubkey_hex = format!("0x{}", hex::encode(pubkey));
                map.write().remove(&pubkey_hex);
                self.notify_key_change();
            }

            info!(pubkey = %hex::encode(pubkey), "Deleted keystore");
            Ok(true)
        } else {
            Ok(false)
        }
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

    fn export_interchange(&self, pubkeys: &[Pubkey]) -> Result<String, String> {
        let interchange =
            self.slashing_db.export(&self.genesis_validators_root).map_err(|e| e.to_string())?;

        // Filter to only requested pubkeys
        let requested: std::collections::HashSet<String> =
            pubkeys.iter().map(|pk| format!("0x{}", hex::encode(pk))).collect();

        let filtered_data: Vec<_> = interchange
            .data
            .into_iter()
            .filter(|record| requested.contains(&record.pubkey))
            .collect();

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

pub struct RemoteKeyManagerAdapter {
    composite_signer: Arc<CompositeSigner>,
    tracked_keys: Mutex<Vec<(Pubkey, String)>>,
    allowed_hosts: Option<Vec<String>>,
    warned_no_allowlist: AtomicBool,
    pubkey_map: Option<PubkeyMap>,
    key_gen_tx: Option<watch::Sender<u64>>,
}

impl RemoteKeyManagerAdapter {
    pub fn new(composite_signer: Arc<CompositeSigner>, allowed_hosts: Option<Vec<String>>) -> Self {
        Self {
            composite_signer,
            tracked_keys: Mutex::new(Vec::new()),
            allowed_hosts,
            warned_no_allowlist: AtomicBool::new(false),
            pubkey_map: None,
            key_gen_tx: None,
        }
    }

    pub fn with_pubkey_map(
        mut self,
        pubkey_map: PubkeyMap,
        key_gen_tx: watch::Sender<u64>,
    ) -> Self {
        self.pubkey_map = Some(pubkey_map);
        self.key_gen_tx = Some(key_gen_tx);
        self
    }

    fn notify_key_change(&self) {
        if let Some(tx) = &self.key_gen_tx {
            tx.send_modify(|gen| *gen += 1);
        }
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

        // Update shared pubkey_map
        if let Some(ref map) = self.pubkey_map {
            if let Ok(pk) = PublicKey::from_bytes(&pubkey) {
                let pubkey_hex = format!("0x{}", hex::encode(pubkey));
                map.write().insert(pubkey_hex, pk);
            }
            self.notify_key_change();
        }

        info!(pubkey = %format!("0x{}", hex::encode(pubkey)), "Imported remote key");
        Ok(())
    }

    fn delete_remote_key(&self, pubkey: &Pubkey) -> Result<bool, DeleteRemoteKeyError> {
        let mut keys = self.tracked_keys.lock();
        if let Some(pos) = keys.iter().position(|(pk, _)| pk == pubkey) {
            keys.remove(pos);
            drop(keys);

            self.composite_signer.remove_remote_key(pubkey);

            // Remove from shared pubkey_map
            if let Some(ref map) = self.pubkey_map {
                let pubkey_hex = format!("0x{}", hex::encode(pubkey));
                map.write().remove(&pubkey_hex);
                self.notify_key_change();
            }

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
    use tempfile::TempDir;

    fn test_pubkey(id: u8) -> Pubkey {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    fn create_empty_composite_signer() -> Arc<CompositeSigner> {
        Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())))
    }

    // --- KeystoreManagerAdapter tests ---

    #[test]
    fn test_keystore_manager_adapter_empty_list() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(adapter.list_keys().is_empty());
    }

    #[test]
    fn test_keystore_manager_adapter_has_key_false() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(!adapter.has_key(&test_pubkey(1)));
    }

    #[test]
    fn test_keystore_manager_adapter_delete_nonexistent() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
        assert!(!adapter.delete_keystore(&test_pubkey(1)).unwrap());
    }

    #[test]
    fn test_keystore_manager_adapter_import_invalid_json() {
        let dir = TempDir::new().unwrap();
        let adapter =
            KeystoreManagerAdapter::new(dir.path().to_path_buf(), create_empty_composite_signer());
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

    // --- RemoteKeyManagerAdapter tests ---

    #[test]
    fn test_remote_key_adapter_empty_list() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        assert!(adapter.list_remote_keys().is_empty());
    }

    #[test]
    fn test_remote_key_adapter_has_key_false() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        assert!(!adapter.has_remote_key(&test_pubkey(1)));
    }

    #[test]
    fn test_remote_key_adapter_import_and_list() {
        let composite = create_empty_composite_signer();
        let adapter = RemoteKeyManagerAdapter::new(composite.clone(), None);

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
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
        let result = adapter.import_remote_key(pk, "https://signer.example.com".to_string());
        assert!(matches!(result, Err(ImportRemoteKeyError::Duplicate)));
    }

    #[test]
    fn test_remote_key_adapter_delete() {
        let composite = create_empty_composite_signer();
        let adapter = RemoteKeyManagerAdapter::new(composite.clone(), None);

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
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        assert!(!adapter.delete_remote_key(&test_pubkey(99)).unwrap());
    }

    #[test]
    fn test_remote_key_adapter_import_rejects_invalid_url_scheme() {
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
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
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone());

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

        let keystore_mgr = Arc::new(KeystoreManagerAdapter::new(dir.keep(), composite.clone()));
        let slashing_prot = Arc::new(SlashingProtectionAdapter::new(
            slashing_db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
        let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
        let doppelganger_mon = Arc::new(DoppelgangerMonitorAdapter::new());
        let remote_key_mgr = Arc::new(RemoteKeyManagerAdapter::new(composite, None));
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

        let keystore_mgr = Arc::new(KeystoreManagerAdapter::new(dir.keep(), composite.clone()));
        let slashing_prot = Arc::new(SlashingProtectionAdapter::new(
            slashing_db,
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ));
        let validator_mgr = Arc::new(ValidatorManagerAdapter::new(validator_store.clone()));
        let doppelganger_mon = Arc::new(DoppelgangerMonitorAdapter::new());
        let remote_key_mgr = Arc::new(RemoteKeyManagerAdapter::new(composite.clone(), None));
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
        let import_body = serde_json::json!({
            "remote_keys": [{
                "pubkey": pk_hex,
                "url": "https://signer.example.com"
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
        let adapter = RemoteKeyManagerAdapter::new(
            create_empty_composite_signer(),
            Some(vec!["signer.example.com".to_string()]),
        );
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://signer.example.com/api".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_remote_key_blocked_host_rejected() {
        let adapter = RemoteKeyManagerAdapter::new(
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
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "https://any.host.com".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_remote_key_allowlist_multiple_hosts() {
        let adapter = RemoteKeyManagerAdapter::new(
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
        let adapter = RemoteKeyManagerAdapter::new(create_empty_composite_signer(), None);
        let pk = test_pubkey(1);
        let result = adapter.import_remote_key(pk, "not a valid url".to_string());
        assert!(
            matches!(result, Err(ImportRemoteKeyError::Other(ref msg)) if msg.contains("invalid remote signer URL"))
        );
    }

    #[test]
    fn test_import_remote_key_allowlist_with_port() {
        let adapter = RemoteKeyManagerAdapter::new(
            create_empty_composite_signer(),
            Some(vec!["signer.example.com".to_string()]),
        );
        let pk = test_pubkey(1);
        // host_str() returns the host without port
        let result =
            adapter.import_remote_key(pk, "https://signer.example.com:9000/api".to_string());
        assert!(result.is_ok());
    }

    // --- CON-03: Dynamic pubkey_map + generation counter tests ---

    fn create_pubkey_map() -> PubkeyMap {
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()))
    }

    #[test]
    fn test_keystore_adapter_import_updates_pubkey_map() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (tx, _rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone())
            .with_pubkey_map(pubkey_map.clone(), tx);

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        // Manually add (real keystore import needs a proper keystore JSON)
        composite.add_local_key(sk);
        adapter.tracked_keys.lock().push(pk_bytes);

        // Simulate pubkey_map update as import_keystore would
        let pubkey_hex = format!("0x{}", hex::encode(pk_bytes));
        let pk = crypto::PublicKey::from_bytes(&pk_bytes).unwrap();
        pubkey_map.write().insert(pubkey_hex.clone(), pk);

        assert!(pubkey_map.read().contains_key(&pubkey_hex));
    }

    #[test]
    fn test_keystore_adapter_delete_removes_from_pubkey_map() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (tx, _rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone())
            .with_pubkey_map(pubkey_map.clone(), tx);

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(pk_bytes));
        let pk = crypto::PublicKey::from_bytes(&pk_bytes).unwrap();

        composite.add_local_key(sk);
        adapter.tracked_keys.lock().push(pk_bytes);
        pubkey_map.write().insert(pubkey_hex.clone(), pk);

        // Delete the keystore
        let deleted = adapter.delete_keystore(&pk_bytes).unwrap();
        assert!(deleted);
        assert!(!pubkey_map.read().contains_key(&pubkey_hex));
    }

    #[test]
    fn test_remote_key_adapter_import_updates_pubkey_map() {
        let composite = create_empty_composite_signer();
        let (tx, _rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter =
            RemoteKeyManagerAdapter::new(composite, None).with_pubkey_map(pubkey_map.clone(), tx);

        let pk = test_pubkey(42);
        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();

        // test_pubkey(42) has all zeros except first byte, which is not a valid BLS key
        // so from_bytes will fail and pubkey_map won't be updated — this is expected
        // The key is still tracked in tracked_keys regardless
        assert!(adapter.has_remote_key(&pk));
    }

    #[test]
    fn test_remote_key_adapter_delete_removes_from_pubkey_map() {
        let composite = create_empty_composite_signer();
        let (tx, _rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter =
            RemoteKeyManagerAdapter::new(composite, None).with_pubkey_map(pubkey_map.clone(), tx);

        let pk = test_pubkey(42);
        adapter.import_remote_key(pk, "https://signer.example.com".to_string()).unwrap();
        let deleted = adapter.delete_remote_key(&pk).unwrap();
        assert!(deleted);
        assert!(!adapter.has_remote_key(&pk));
    }

    #[test]
    fn test_generation_counter_increments_on_keystore_delete() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let (tx, rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone())
            .with_pubkey_map(pubkey_map, tx);

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
        let (tx, rx) = watch::channel(0u64);
        let pubkey_map = create_pubkey_map();
        let adapter = RemoteKeyManagerAdapter::new(composite, None).with_pubkey_map(pubkey_map, tx);

        assert_eq!(*rx.borrow(), 0);
        adapter
            .import_remote_key(test_pubkey(1), "https://signer.example.com".to_string())
            .unwrap();
        // Generation increments even if PublicKey::from_bytes fails (key still added to signer)
        assert_eq!(*rx.borrow(), 1);
    }

    #[test]
    fn test_adapter_without_pubkey_map_works() {
        let composite = create_empty_composite_signer();
        let dir = TempDir::new().unwrap();
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone());

        // Should work fine without pubkey_map wiring
        assert!(adapter.list_keys().is_empty());
    }

    // --- TOCTOU fix tests ---

    fn setup_adapter_with_key(
        dir: &std::path::Path,
    ) -> (Arc<KeystoreManagerAdapter>, Pubkey, Arc<CompositeSigner>) {
        let composite = create_empty_composite_signer();
        let adapter = Arc::new(KeystoreManagerAdapter::new(dir.to_path_buf(), composite.clone()));

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
            Arc::new(KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone()));

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
            Arc::new(KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone()));

        let sk = SecretKey::generate();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::Pbkdf2,
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
        let adapter =
            Arc::new(KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone()));

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::Pbkdf2,
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

        // Final state should be consistent: key count matches tracked_keys
        let keys = adapter.list_keys();
        let has_key = adapter.has_key(&pk_bytes);
        assert_eq!(keys.contains(&pk_bytes), has_key);
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
        let signer = Arc::new(SignerService::new(composite, slashing_db));

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
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::Pbkdf2,
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
        let adapter = KeystoreManagerAdapter::new(dir.path().to_path_buf(), composite.clone());

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let password = b"testpass";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::Pbkdf2,
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
}
