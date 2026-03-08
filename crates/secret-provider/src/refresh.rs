use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::key_source_manager::convert_key_material;
use crate::SecretProvider;
use crypto::SecretKey;

pub struct RefreshService {
    providers: Vec<Arc<dyn SecretProvider>>,
    known_pubkeys: HashSet<[u8; 48]>,
    interval: Duration,
    cancel_token: CancellationToken,
}

impl RefreshService {
    pub fn new(
        providers: Vec<Arc<dyn SecretProvider>>,
        known_pubkeys: HashSet<[u8; 48]>,
        interval: Duration,
        cancel_token: CancellationToken,
    ) -> Self {
        Self { providers, known_pubkeys, interval, cancel_token }
    }

    pub async fn refresh(&mut self) -> Vec<SecretKey> {
        let mut new_keys = Vec::new();

        for provider in &self.providers {
            let provider_name = provider.name().to_string();

            let entries = match provider.list_keys().await {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(
                        provider = %provider_name,
                        error = %e,
                        "Failed to list keys during refresh"
                    );
                    continue;
                }
            };

            for entry in &entries {
                // Skip entries whose pubkey_hex is already known (avoids unnecessary fetch)
                if let Some(ref hex_str) = entry.pubkey_hex {
                    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
                    if let Ok(bytes) = hex::decode(hex_str) {
                        if bytes.len() == 48 {
                            let mut arr = [0u8; 48];
                            arr.copy_from_slice(&bytes);
                            if self.known_pubkeys.contains(&arr) {
                                continue;
                            }
                        }
                    }
                }

                let material = match provider.fetch_key(&entry.id).await {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(
                            provider = %provider_name,
                            key_id = %entry.id,
                            error = %e,
                            "Failed to fetch key during refresh"
                        );
                        continue;
                    }
                };

                let sk = match convert_key_material(&entry.id, material) {
                    Ok(sk) => sk,
                    Err(e) => {
                        warn!(
                            provider = %provider_name,
                            key_id = %entry.id,
                            error = %e,
                            "Failed to convert key material during refresh"
                        );
                        continue;
                    }
                };

                let pubkey = sk.public_key().to_bytes();
                if self.known_pubkeys.contains(&pubkey) {
                    continue;
                }

                let pubkey_hex = format!("0x{}", hex::encode(pubkey));
                warn!(
                    provider = %provider_name,
                    pubkey = %pubkey_hex,
                    "Discovered new key during refresh"
                );

                self.known_pubkeys.insert(pubkey);
                new_keys.push(sk);
            }
        }

        let total = self.known_pubkeys.len();
        let new_count = new_keys.len();
        info!(
            new_count = new_count,
            total = total,
            "Secret provider refresh: {new_count} new keys, {total} total"
        );

        new_keys
    }

    pub async fn run<F>(mut self, on_new_key: F)
    where
        F: Fn(SecretKey),
    {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {
                    let new_keys = self.refresh().await;
                    for sk in new_keys {
                        on_new_key(sk);
                    }
                }
                _ = self.cancel_token.cancelled() => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use zeroize::Zeroizing;

    use super::*;
    use crate::key_source_manager::mock::MockSecretProvider;
    use crate::{KeyMaterial, SecretKeyEntry, SecretProviderError};

    fn make_raw_key_entry(
        id: &str,
        sk: &SecretKey,
    ) -> (SecretKeyEntry, Result<KeyMaterial, SecretProviderError>) {
        let bytes: [u8; 32] = sk.to_bytes();
        (
            SecretKeyEntry { id: id.to_string(), pubkey_hex: None },
            Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
        )
    }

    fn make_raw_key_entry_with_pubkey(
        id: &str,
        sk: &SecretKey,
    ) -> (SecretKeyEntry, Result<KeyMaterial, SecretProviderError>) {
        let bytes: [u8; 32] = sk.to_bytes();
        let pubkey_hex = format!("0x{}", hex::encode(sk.public_key().to_bytes()));
        (
            SecretKeyEntry { id: id.to_string(), pubkey_hex: Some(pubkey_hex) },
            Ok(KeyMaterial::RawKey(Zeroizing::new(bytes))),
        )
    }

    #[tokio::test]
    async fn test_refresh_detects_new_key() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1), make_raw_key_entry("key-2", &sk2)],
            list_error: None,
        };

        // Only key-1 is known; key-2 should be detected as new
        let mut known = HashSet::new();
        known.insert(sk1.public_key().to_bytes());

        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 1);
        assert_eq!(new_keys[0].public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[tokio::test]
    async fn test_refresh_same_keys_returns_empty() {
        let sk1 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1)],
            list_error: None,
        };

        let mut known = HashSet::new();
        known.insert(sk1.public_key().to_bytes());

        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_refresh_updates_known_set() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1), make_raw_key_entry("key-2", &sk2)],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let mut service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_secs(60),
            cancel,
        );

        // First refresh: both keys are new
        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 2);

        // Second refresh: no new keys
        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_cancellation_stops_refresh_loop() {
        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_secs(3600), // very long interval
            cancel,
        );

        let call_count = Arc::new(Mutex::new(0u32));
        let call_count_clone = call_count.clone();

        let handle = tokio::spawn(async move {
            service
                .run(move |_| {
                    *call_count_clone.lock().unwrap() += 1;
                })
                .await;
        });

        // Cancel immediately
        cancel_clone.cancel();

        // The task should complete quickly
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "refresh loop should have stopped on cancellation");

        assert_eq!(*call_count.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_refresh_with_no_providers() {
        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![], HashSet::new(), Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert!(new_keys.is_empty());
    }

    #[tokio::test]
    async fn test_refresh_provider_list_error_continues() {
        let sk = SecretKey::generate();

        let failing_provider = MockSecretProvider {
            name: "failing".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("forbidden".into())),
        };

        let good_provider = MockSecretProvider {
            name: "good".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk)],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let mut service = RefreshService::new(
            vec![Arc::new(failing_provider), Arc::new(good_provider)],
            HashSet::new(),
            Duration::from_secs(60),
            cancel,
        );

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_run_calls_callback_for_new_keys() {
        let sk = SecretKey::generate();
        let expected_pubkey = sk.public_key().to_bytes();

        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk)],
            list_error: None,
        };

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let service = RefreshService::new(
            vec![Arc::new(provider)],
            HashSet::new(),
            Duration::from_millis(10), // very short interval for test
            cancel,
        );

        let captured_keys = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured_keys.clone();

        let handle = tokio::spawn(async move {
            service
                .run(move |sk| {
                    captured_clone.lock().unwrap().push(sk.public_key().to_bytes());
                })
                .await;
        });

        // Wait for at least one refresh cycle
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel_clone.cancel();

        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        let keys = captured_keys.lock().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], expected_pubkey);
    }

    #[tokio::test]
    async fn test_refresh_skips_known_pubkey_hex_early() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        // sk1 has pubkey_hex set and is already known — should be skipped without fetch
        // sk2 has no pubkey_hex — will be fetched but is also known, skipped after fetch
        let provider = MockSecretProvider {
            name: "test-provider".to_string(),
            keys: vec![
                make_raw_key_entry_with_pubkey("key-1", &sk1),
                make_raw_key_entry("key-2", &sk2),
            ],
            list_error: None,
        };

        let mut known = HashSet::new();
        known.insert(sk1.public_key().to_bytes());
        known.insert(sk2.public_key().to_bytes());

        let cancel = CancellationToken::new();
        let mut service =
            RefreshService::new(vec![Arc::new(provider)], known, Duration::from_secs(60), cancel);

        let new_keys = service.refresh().await;
        assert_eq!(new_keys.len(), 0);
    }
}
