//! Shared key-set change notification for keymanager key adapters.
//!
//! Both [`super::KeystoreManagerAdapter`] and [`super::RemoteKeyManagerAdapter`]
//! update the orchestrator's duty-matching map and bump a generation counter on
//! import/delete. That pair is one concept — [`KeyChangeNotifier`].

use crypto::PublicKey;
use tokio::sync::watch;

use crate::orchestrator::PubkeyMap;

/// Formats a BLS pubkey as `0x`-prefixed lowercase hex.
///
/// Single helper for map keys, logging, and filenames under `keymanager_adapters/`.
#[inline]
pub(crate) fn pubkey_hex(pubkey: impl AsRef<[u8]>) -> String {
    // Avoid the hand-rolled 0x+hex::encode format macro so call sites stay uniform (RF6-26).
    let bytes = pubkey.as_ref();
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    out.push_str(&hex::encode(bytes));
    out
}

/// Shared `PubkeyMap` update + generation-counter bump for key import/delete.
///
/// Required construction parameter (via its two fields) of both local and remote
/// key adapters so the duty orchestrator observes runtime key-set changes.
pub struct KeyChangeNotifier {
    pubkey_map: PubkeyMap,
    key_gen_tx: watch::Sender<u64>,
}

impl KeyChangeNotifier {
    /// Create a notifier bound to the process-wide map and generation channel.
    pub fn new(pubkey_map: PubkeyMap, key_gen_tx: watch::Sender<u64>) -> Self {
        Self { pubkey_map, key_gen_tx }
    }

    /// Access the shared duty-matching map.
    pub fn pubkey_map(&self) -> &PubkeyMap {
        &self.pubkey_map
    }

    /// Bump the key-generation counter (orchestrator clears duty caches).
    pub fn notify(&self) {
        self.key_gen_tx.send_modify(|gen| *gen += 1);
    }

    /// Insert `public_key` under the canonical hex map key and notify.
    pub fn insert_and_notify(&self, pubkey: &[u8; 48], public_key: PublicKey) {
        self.pubkey_map.write().insert(pubkey_hex(pubkey), public_key);
        self.notify();
    }

    /// Remove the map entry for `pubkey` and notify.
    pub fn remove_and_notify(&self, pubkey: &[u8; 48]) {
        self.pubkey_map.write().remove(&pubkey_hex(pubkey));
        self.notify();
    }
}
