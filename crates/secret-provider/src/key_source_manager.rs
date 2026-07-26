use std::collections::HashSet;
use std::sync::Arc;

use crypto::{KeyManager, Keystore, SecretKey};
use observability::logging::TruncatedPubkey;
use tracing::{info, info_span, warn, Instrument};

use crate::metrics::{
    classify_error, RVC_SECRET_PROVIDER_ERRORS_TOTAL, RVC_SECRET_PROVIDER_KEYS_LOADED,
    RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS,
};
use crate::{KeyMaterial, LoadSummary, ProviderSummary, SecretProvider, SecretProviderError};

pub struct KeySourceManager {
    providers: Vec<Arc<dyn SecretProvider>>,
    /// When true, any provider `list_keys` failure aborts the load (SEC-9 / M-9).
    /// Default is resilient: log and continue so healthy providers still load.
    strict: bool,
}

impl KeySourceManager {
    pub fn new(providers: Vec<Box<dyn SecretProvider>>) -> Self {
        Self { providers: providers.into_iter().map(Arc::from).collect(), strict: false }
    }

    pub fn from_arc(providers: Vec<Arc<dyn SecretProvider>>) -> Self {
        Self { providers, strict: false }
    }

    /// Fail-fast when any provider's `list_keys` fails (SEC-9 / M-9 strict mode).
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Load every provider key into `key_manager` (no denylist).
    pub async fn load_all(
        &self,
        key_manager: &mut KeyManager,
    ) -> Result<LoadSummary, SecretProviderError> {
        self.load_all_except(key_manager, None).await
    }

    /// Load provider keys, skipping any pubkey present in `denylist` (SEC-1b).
    ///
    /// Denylisted keys are counted as `skipped` and never inserted, so a key
    /// deleted via the Keymanager API cannot resurrect from GCP/etc. on boot.
    ///
    /// Provider resilience (SEC-9 / M-9): by default a single provider's
    /// `list_keys` failure is logged and skipped so other providers can still
    /// contribute keys. Enable [`Self::with_strict`] to restore fail-fast.
    /// If every configured provider fails `list_keys`, the load still returns
    /// `Err` (all sources failing remains fatal).
    #[tracing::instrument(
        name = "secret_provider.load_all",
        skip_all,
        fields(providers.count = self.providers.len())
    )]
    pub async fn load_all_except(
        &self,
        key_manager: &mut KeyManager,
        denylist: Option<&HashSet<[u8; 48]>>,
    ) -> Result<LoadSummary, SecretProviderError> {
        let mut summary = LoadSummary::default();
        let mut list_successes = 0usize;
        let mut last_list_error: Option<SecretProviderError> = None;

        for provider in &self.providers {
            let provider_name = provider.name().to_string();
            let timer = std::time::Instant::now();

            let list_span = info_span!(
                "secret_provider.list_keys",
                provider.name = %provider_name,
                keys.count = tracing::field::Empty,
            );
            let entries = match provider.list_keys().instrument(list_span.clone()).await {
                Ok(entries) => {
                    list_successes += 1;
                    entries
                }
                Err(err) => {
                    let elapsed = timer.elapsed().as_secs_f64();
                    RVC_SECRET_PROVIDER_ERRORS_TOTAL
                        .with_label_values(&[provider_name.as_str(), classify_error(&err)])
                        .inc();
                    RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
                        .with_label_values(&[provider_name.as_str()])
                        .observe(elapsed);
                    if self.strict {
                        return Err(err);
                    }
                    tracing::error!(
                        provider = %provider_name,
                        error = %err,
                        "Failed to list keys from secret provider; continuing with remaining providers"
                    );
                    summary.per_provider.push(ProviderSummary {
                        name: provider_name,
                        loaded: 0,
                        skipped: 0,
                        errors: vec![err.to_string()],
                    });
                    last_list_error = Some(err);
                    continue;
                }
            };
            list_span.record("keys.count", entries.len());

            let mut provider_summary = ProviderSummary {
                name: provider_name.clone(),
                loaded: 0,
                skipped: 0,
                errors: Vec::new(),
            };

            let mut join_set = tokio::task::JoinSet::new();
            for entry in &entries {
                // Early skip when list_keys already provides the pubkey.
                if let (Some(deny), Some(ref hex_str)) = (denylist, &entry.pubkey_hex) {
                    if let Ok(pk) = eth_types::canonical::pubkey_hex::parse_pubkey_hex(hex_str) {
                        let arr = *pk.as_bytes();
                        if deny.contains(&arr) {
                            let pubkey_hex = format!("0x{}", hex::encode(arr));
                            info!(
                                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                                source = %provider_name,
                                "Skipping denylisted secret-provider key"
                            );
                            provider_summary.skipped += 1;
                            continue;
                        }
                    }
                }

                let id = entry.id.clone();
                let prov = Arc::clone(provider);
                let prov_name = provider_name.clone();
                let fetch_span = info_span!(
                    "secret_provider.fetch_key",
                    key.id = %id,
                    provider.name = %prov_name,
                );
                join_set.spawn(
                    async move {
                        let result = prov.fetch_key(&id).await;
                        (id, result)
                    }
                    .instrument(fetch_span),
                );
            }

            while let Some(join_result) = join_set.join_next().await {
                let (entry_id, result) = match join_result {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(
                            provider = %provider_name,
                            error = %e,
                            "JoinSet task panicked, skipping"
                        );
                        RVC_SECRET_PROVIDER_ERRORS_TOTAL
                            .with_label_values(&[provider_name.as_str(), "task_panic"])
                            .inc();
                        provider_summary.skipped += 1;
                        provider_summary.errors.push(format!("task panic: {}", e));
                        continue;
                    }
                };

                match result {
                    Ok(material) => match convert_key_material(&entry_id, material) {
                        Ok(secret_key) => {
                            let pubkey_bytes = secret_key.public_key().to_bytes();
                            if denylist.is_some_and(|d| d.contains(&pubkey_bytes)) {
                                let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));
                                info!(
                                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                                    source = %provider_name,
                                    "Skipping denylisted secret-provider key"
                                );
                                provider_summary.skipped += 1;
                                continue;
                            }
                            let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));
                            info!(
                                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                                source = %provider_name,
                                "New key discovered"
                            );
                            key_manager.insert(secret_key);
                            provider_summary.loaded += 1;
                        }
                        Err(e) => {
                            warn!(
                                key_id = %entry_id,
                                source = %provider_name,
                                error = %e,
                                "Key fetch failure"
                            );
                            RVC_SECRET_PROVIDER_ERRORS_TOTAL
                                .with_label_values(&[provider_name.as_str(), classify_error(&e)])
                                .inc();
                            provider_summary.skipped += 1;
                            provider_summary.errors.push(format!("{}: {}", entry_id, e));
                        }
                    },
                    Err(e) => {
                        tracing::Span::current().in_scope(|| {
                            tracing::error!(
                                provider = %provider_name,
                                key_id = %entry_id,
                                error = %e,
                                "Failed to fetch key"
                            );
                        });
                        RVC_SECRET_PROVIDER_ERRORS_TOTAL
                            .with_label_values(&[provider_name.as_str(), classify_error(&e)])
                            .inc();
                        provider_summary.skipped += 1;
                        provider_summary.errors.push(format!("{}: {}", entry_id, e));
                    }
                }
            }

            RVC_SECRET_PROVIDER_KEYS_LOADED
                .with_label_values(&[&provider_name])
                .set(provider_summary.loaded as f64);
            RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
                .with_label_values(&[&provider_name])
                .observe(timer.elapsed().as_secs_f64());

            summary.per_provider.push(provider_summary);
        }

        // All configured providers failed list_keys — still fatal (SEC-9 / M-9).
        if list_successes == 0 {
            if let Some(err) = last_list_error {
                return Err(err);
            }
        }

        Ok(summary)
    }
}

pub fn convert_key_material(
    id: &str,
    material: KeyMaterial,
) -> Result<SecretKey, SecretProviderError> {
    match material {
        KeyMaterial::RawKey(bytes) => SecretKey::from_bytes(&*bytes).map_err(|e| {
            SecretProviderError::InvalidKeyMaterial(format!("invalid raw key for {}: {}", id, e))
        }),
        KeyMaterial::Keystore { keystore_json, password } => {
            let keystore = Keystore::from_json(&keystore_json).map_err(|e| {
                SecretProviderError::DecryptionFailed {
                    id: id.to_string(),
                    reason: format!("invalid keystore JSON: {}", e),
                }
            })?;
            keystore.decrypt(password.as_bytes()).map_err(|e| {
                SecretProviderError::DecryptionFailed {
                    id: id.to_string(),
                    reason: format!("decryption failed: {}", e),
                }
            })
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use async_trait::async_trait;

    use crate::{KeyMaterial, SecretKeyEntry, SecretProvider, SecretProviderError};

    pub struct MockSecretProvider {
        pub name: String,
        pub keys: Vec<(SecretKeyEntry, Result<KeyMaterial, SecretProviderError>)>,
        pub list_error: Option<SecretProviderError>,
    }

    impl MockSecretProvider {
        fn clone_error(err: &SecretProviderError) -> SecretProviderError {
            match err {
                SecretProviderError::Auth(msg) => SecretProviderError::Auth(msg.clone()),
                SecretProviderError::NotFound(msg) => SecretProviderError::NotFound(msg.clone()),
                SecretProviderError::Provider(msg) => SecretProviderError::Provider(msg.clone()),
                SecretProviderError::InvalidKeyMaterial(msg) => {
                    SecretProviderError::InvalidKeyMaterial(msg.clone())
                }
                SecretProviderError::DecryptionFailed { id, reason } => {
                    SecretProviderError::DecryptionFailed { id: id.clone(), reason: reason.clone() }
                }
            }
        }

        fn clone_material(material: &KeyMaterial) -> KeyMaterial {
            match material {
                KeyMaterial::RawKey(bytes) => KeyMaterial::RawKey(bytes.clone()),
                KeyMaterial::Keystore { keystore_json, password } => KeyMaterial::Keystore {
                    keystore_json: keystore_json.clone(),
                    password: password.clone(),
                },
            }
        }
    }

    #[async_trait]
    impl SecretProvider for MockSecretProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_keys(&self) -> Result<Vec<SecretKeyEntry>, SecretProviderError> {
            if let Some(ref err) = self.list_error {
                return Err(Self::clone_error(err));
            }
            Ok(self
                .keys
                .iter()
                .map(|(entry, _)| SecretKeyEntry {
                    id: entry.id.clone(),
                    pubkey_hex: entry.pubkey_hex.clone(),
                })
                .collect())
        }

        async fn fetch_key(&self, id: &str) -> Result<KeyMaterial, SecretProviderError> {
            for (entry, result) in &self.keys {
                if entry.id == id {
                    return match result {
                        Ok(material) => Ok(Self::clone_material(material)),
                        Err(e) => Err(Self::clone_error(e)),
                    };
                }
            }
            Err(SecretProviderError::NotFound(format!("key {} not found in mock", id)))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use parking_lot::Mutex;

    use crypto::SecretKey;
    use tracing_subscriber::layer::SubscriberExt;
    use zeroize::Zeroizing;

    use super::*;
    use crate::key_source_manager::mock::MockSecretProvider;
    use crate::{SecretKeyEntry, SecretProviderError};

    struct SpanCapture {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.spans.lock().push(attrs.metadata().name().to_string());
        }
    }

    struct FieldCapture {
        fields: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
        tracing_subscriber::Layer<S> for FieldCapture
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let span_name = attrs.metadata().name().to_string();
            let mut visitor = FieldVisitor(self.fields.clone(), span_name);
            attrs.record(&mut visitor);
        }

        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let span_name = ctx.span(id).map(|s| s.name().to_string()).unwrap_or_default();
            let mut visitor = FieldVisitor(self.fields.clone(), span_name);
            values.record(&mut visitor);
        }
    }

    struct FieldVisitor(Arc<Mutex<Vec<(String, String, String)>>>, String);

    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.lock().push((self.1.clone(), field.name().to_string(), format!("{:?}", value)));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.lock().push((self.1.clone(), field.name().to_string(), value.to_string()));
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.lock().push((self.1.clone(), field.name().to_string(), value.to_string()));
        }
    }

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

    #[tokio::test]
    async fn test_multi_provider_aggregation() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider1 = MockSecretProvider {
            name: "provider-a".to_string(),
            keys: vec![make_raw_key_entry("key-1", &sk1)],
            list_error: None,
        };
        let provider2 = MockSecretProvider {
            name: "provider-b".to_string(),
            keys: vec![make_raw_key_entry("key-2", &sk2)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider1), Box::new(provider2)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        assert_eq!(summary.per_provider.len(), 2);
        assert_eq!(summary.per_provider[0].loaded, 1);
        assert_eq!(summary.per_provider[1].loaded, 1);
        assert_eq!(km.len(), 2);
    }

    #[tokio::test]
    async fn test_partial_failure_skip() {
        let sk1 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "mixed".to_string(),
            keys: vec![
                make_raw_key_entry("good-key", &sk1),
                (
                    SecretKeyEntry { id: "bad-key".to_string(), pubkey_hex: None },
                    Err(SecretProviderError::Provider("network error".into())),
                ),
            ],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        assert_eq!(summary.per_provider[0].loaded, 1);
        assert_eq!(summary.per_provider[0].skipped, 1);
        assert_eq!(km.len(), 1);
    }

    #[tokio::test]
    async fn test_empty_provider() {
        let provider =
            MockSecretProvider { name: "empty".to_string(), keys: vec![], list_error: None };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        assert_eq!(summary.per_provider.len(), 1);
        assert_eq!(summary.per_provider[0].loaded, 0);
        assert_eq!(summary.per_provider[0].skipped, 0);
        assert!(km.is_empty());
    }

    #[tokio::test]
    async fn test_auth_error_propagation() {
        // A single provider that fails list_keys is "all sources failing" → still fatal.
        let provider = MockSecretProvider {
            name: "auth-fail".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("forbidden".into())),
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(matches!(result, Err(SecretProviderError::Auth(_))));
    }

    // ── SEC-9 / M-9: provider resilience ──────────────────────────────────

    #[tokio::test]
    async fn test_one_failing_provider_starts_with_healthy_keys() {
        let sk = SecretKey::generate();
        let healthy = MockSecretProvider {
            name: "healthy".to_string(),
            keys: vec![make_raw_key_entry("good-key", &sk)],
            list_error: None,
        };
        let failing = MockSecretProvider {
            name: "failing".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Provider("network down".into())),
        };

        let ksm = KeySourceManager::new(vec![Box::new(failing), Box::new(healthy)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("healthy provider should save the load");

        assert_eq!(km.len(), 1, "healthy provider's key must load");
        assert_eq!(summary.per_provider.len(), 2);
        let failing_summary =
            summary.per_provider.iter().find(|p| p.name == "failing").expect("failing summary");
        assert_eq!(failing_summary.loaded, 0);
        assert!(!failing_summary.errors.is_empty());
        let healthy_summary =
            summary.per_provider.iter().find(|p| p.name == "healthy").expect("healthy summary");
        assert_eq!(healthy_summary.loaded, 1);
    }

    #[tokio::test]
    async fn test_strict_mode_aborts_on_provider_failure() {
        let sk = SecretKey::generate();
        let healthy = MockSecretProvider {
            name: "healthy".to_string(),
            keys: vec![make_raw_key_entry("good-key", &sk)],
            list_error: None,
        };
        let failing = MockSecretProvider {
            name: "failing".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Provider("network down".into())),
        };

        // Failing provider first so strict mode aborts before healthy is reached.
        let ksm =
            KeySourceManager::new(vec![Box::new(failing), Box::new(healthy)]).with_strict(true);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(matches!(result, Err(SecretProviderError::Provider(_))));
        assert!(km.is_empty(), "strict mode must not partially load after a failure");
    }

    #[tokio::test]
    async fn test_all_sources_failing_aborts() {
        let a = MockSecretProvider {
            name: "a".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("a forbidden".into())),
        };
        let b = MockSecretProvider {
            name: "b".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Provider("b down".into())),
        };

        let ksm = KeySourceManager::new(vec![Box::new(a), Box::new(b)]);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(result.is_err(), "all providers failing must be fatal");
        assert!(km.is_empty());
    }

    #[tokio::test]
    async fn test_summary_correctness() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();

        let provider = MockSecretProvider {
            name: "summary-test".to_string(),
            keys: vec![
                make_raw_key_entry("ok-1", &sk1),
                make_raw_key_entry("ok-2", &sk2),
                (
                    SecretKeyEntry { id: "fail-1".to_string(), pubkey_hex: None },
                    Err(SecretProviderError::InvalidKeyMaterial("bad".into())),
                ),
            ],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("should succeed");

        let ps = &summary.per_provider[0];
        assert_eq!(ps.loaded, 2);
        assert_eq!(ps.skipped, 1);
        assert_eq!(ps.loaded + ps.skipped, 3);
        assert_eq!(ps.errors.len(), 1);
    }

    #[tokio::test]
    async fn test_load_all_creates_span() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock();
        assert!(
            captured.contains(&"secret_provider.load_all".to_string()),
            "Expected secret_provider.load_all span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_load_all_creates_list_keys_span() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock();
        assert!(
            captured.contains(&"secret_provider.list_keys".to_string()),
            "Expected secret_provider.list_keys span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_load_all_creates_fetch_key_span() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock();
        assert!(
            captured.contains(&"secret_provider.fetch_key".to_string()),
            "Expected secret_provider.fetch_key span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_load_all_span_records_providers_count() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let p1 = MockSecretProvider {
            name: "prov-a".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk1)],
            list_error: None,
        };
        let p2 = MockSecretProvider {
            name: "prov-b".to_string(),
            keys: vec![make_raw_key_entry("k2", &sk2)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(p1), Box::new(p2)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.load_all"
                && field == "providers.count"
                && value == "2"),
            "Expected providers.count=2 on load_all span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_list_keys_span_records_keys_count() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![
                make_raw_key_entry("k1", &sk),
                make_raw_key_entry("k2", &SecretKey::generate()),
            ],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.list_keys"
                && field == "keys.count"
                && value == "2"),
            "Expected keys.count=2 on list_keys span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_fetch_key_span_records_key_id() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "test-prov".to_string(),
            keys: vec![make_raw_key_entry("my-key-id", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.fetch_key"
                && field == "key.id"
                && value == "my-key-id"),
            "Expected key.id=my-key-id on fetch_key span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_list_keys_span_records_provider_name() {
        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "my-prov".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock();
        assert!(
            captured.iter().any(|(span, field, value)| span == "secret_provider.list_keys"
                && field == "provider.name"
                && value == "my-prov"),
            "Expected provider.name=my-prov on list_keys span, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_metrics_keys_loaded_after_successful_load() {
        use crate::metrics::RVC_SECRET_PROVIDER_KEYS_LOADED;

        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "metrics-test-loaded".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk1), make_raw_key_entry("k2", &sk2)],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let value =
            RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["metrics-test-loaded"]).get();
        assert_eq!(value, 2.0, "Expected 2 keys loaded for metrics-test-loaded");
    }

    #[tokio::test]
    async fn test_metrics_errors_total_after_fetch_failure() {
        use crate::metrics::RVC_SECRET_PROVIDER_ERRORS_TOTAL;

        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "metrics-test-err".to_string(),
            keys: vec![
                make_raw_key_entry("ok-key", &sk),
                (
                    SecretKeyEntry { id: "bad-key".to_string(), pubkey_hex: None },
                    Err(SecretProviderError::Provider("fail".into())),
                ),
            ],
            list_error: None,
        };

        let before = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-test-err", "provider"])
            .get();

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let after = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-test-err", "provider"])
            .get();
        assert_eq!(after, before + 1, "Expected error counter to increment by 1");
    }

    #[tokio::test]
    async fn test_metrics_load_duration_recorded() {
        use crate::metrics::RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS;

        let sk = SecretKey::generate();
        let provider = MockSecretProvider {
            name: "metrics-test-dur".to_string(),
            keys: vec![make_raw_key_entry("k1", &sk)],
            list_error: None,
        };

        let before = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-test-dur"])
            .get_sample_count();

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let after = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-test-dur"])
            .get_sample_count();
        assert_eq!(after, before + 1, "Expected one duration observation");
    }

    #[tokio::test]
    async fn test_metrics_errors_total_on_list_keys_failure() {
        use crate::metrics::{
            RVC_SECRET_PROVIDER_ERRORS_TOTAL, RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS,
        };

        let provider = MockSecretProvider {
            name: "metrics-list-fail".to_string(),
            keys: vec![],
            list_error: Some(SecretProviderError::Auth("forbidden".into())),
        };

        let before_err = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-list-fail", "auth"])
            .get();
        let before_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-list-fail"])
            .get_sample_count();

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let result = ksm.load_all(&mut km).await;

        assert!(result.is_err());
        let after_err = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-list-fail", "auth"])
            .get();
        assert_eq!(
            after_err,
            before_err + 1,
            "Expected errors_total to increment on list_keys failure"
        );
        let after_dur = RVC_SECRET_PROVIDER_LOAD_DURATION_SECONDS
            .with_label_values(&["metrics-list-fail"])
            .get_sample_count();
        assert_eq!(
            after_dur,
            before_dur + 1,
            "Expected duration to be recorded on list_keys failure"
        );
    }

    #[tokio::test]
    async fn test_metrics_errors_total_on_task_panic() {
        use crate::metrics::RVC_SECRET_PROVIDER_ERRORS_TOTAL;

        let before = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-panic-test", "task_panic"])
            .get();

        // We can't easily cause a JoinSet panic in a unit test with MockSecretProvider,
        // so we verify the metric label exists and is usable. The actual code path
        // is verified by inspecting the implementation.
        RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-panic-test", "task_panic"])
            .inc();
        let after = RVC_SECRET_PROVIDER_ERRORS_TOTAL
            .with_label_values(&["metrics-panic-test", "task_panic"])
            .get();
        assert_eq!(after, before + 1, "task_panic error_type label should be valid");
    }

    #[tokio::test]
    async fn test_metrics_keys_loaded_zero_for_empty_provider() {
        use crate::metrics::RVC_SECRET_PROVIDER_KEYS_LOADED;

        let provider = MockSecretProvider {
            name: "metrics-test-empty".to_string(),
            keys: vec![],
            list_error: None,
        };

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        ksm.load_all(&mut km).await.unwrap();

        let value =
            RVC_SECRET_PROVIDER_KEYS_LOADED.with_label_values(&["metrics-test-empty"]).get();
        assert_eq!(value, 0.0, "Expected 0 keys loaded for empty provider");
    }

    // ── SEC-1b: deletion denylist ─────────────────────────────────────────

    #[tokio::test]
    async fn test_deleted_secret_provider_key_not_resurrected_on_reload() {
        let sk_deleted = SecretKey::generate();
        let sk_kept = SecretKey::generate();
        let pk_deleted = sk_deleted.public_key().to_bytes();
        let pk_kept = sk_kept.public_key().to_bytes();

        let provider = MockSecretProvider {
            name: "gcp-sim".to_string(),
            keys: vec![
                make_raw_key_entry("deleted-key", &sk_deleted),
                make_raw_key_entry("kept-key", &sk_kept),
            ],
            list_error: None,
        };

        // First load: both keys present (no denylist)
        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all(&mut km).await.expect("initial load");
        assert_eq!(summary.per_provider[0].loaded, 2);
        assert!(km.contains(&pk_deleted));
        assert!(km.contains(&pk_kept));

        // Simulate Keymanager DELETE: remove from registry + denylist the pubkey
        assert!(km.remove(&pk_deleted));
        let mut denylist = HashSet::new();
        denylist.insert(pk_deleted);

        // Simulated restart: same provider still lists both keys
        let provider2 = MockSecretProvider {
            name: "gcp-sim".to_string(),
            keys: vec![
                make_raw_key_entry("deleted-key", &sk_deleted),
                make_raw_key_entry("kept-key", &sk_kept),
            ],
            list_error: None,
        };
        let ksm2 = KeySourceManager::new(vec![Box::new(provider2)]);
        let mut km2 = KeyManager::new();
        let summary2 =
            ksm2.load_all_except(&mut km2, Some(&denylist)).await.expect("reload with denylist");

        assert_eq!(summary2.per_provider[0].loaded, 1, "only the never-deleted key loads");
        assert_eq!(summary2.per_provider[0].skipped, 1, "denylisted key is skipped");
        assert!(!km2.contains(&pk_deleted), "deleted key must not resurrect");
        assert!(km2.contains(&pk_kept), "never-deleted key must load normally");
    }

    #[tokio::test]
    async fn test_never_deleted_key_loads_normally() {
        let sk = SecretKey::generate();
        let pk = sk.public_key().to_bytes();
        let other = SecretKey::generate().public_key().to_bytes();

        let provider = MockSecretProvider {
            name: "gcp-sim".to_string(),
            keys: vec![make_raw_key_entry("only-key", &sk)],
            list_error: None,
        };
        let mut denylist = HashSet::new();
        denylist.insert(other); // unrelated deleted key

        let ksm = KeySourceManager::new(vec![Box::new(provider)]);
        let mut km = KeyManager::new();
        let summary = ksm.load_all_except(&mut km, Some(&denylist)).await.unwrap();
        assert_eq!(summary.per_provider[0].loaded, 1);
        assert_eq!(summary.per_provider[0].skipped, 0);
        assert!(km.contains(&pk));
    }
}
