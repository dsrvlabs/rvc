use std::sync::Arc;

use crypto::{KeyManager, Keystore, SecretKey};
use tracing::{info_span, warn, Instrument};

use crate::{KeyMaterial, LoadSummary, ProviderSummary, SecretProvider, SecretProviderError};

pub struct KeySourceManager {
    providers: Vec<Arc<dyn SecretProvider>>,
}

impl KeySourceManager {
    pub fn new(providers: Vec<Box<dyn SecretProvider>>) -> Self {
        Self { providers: providers.into_iter().map(Arc::from).collect() }
    }

    #[tracing::instrument(
        name = "rvc.secret_provider.load_all",
        skip_all,
        fields(providers.count = self.providers.len())
    )]
    pub async fn load_all(
        &self,
        key_manager: &mut KeyManager,
    ) -> Result<LoadSummary, SecretProviderError> {
        let mut summary = LoadSummary::default();

        for provider in &self.providers {
            let provider_name = provider.name().to_string();

            let list_span = info_span!(
                "rvc.secret_provider.list_keys",
                provider.name = %provider_name,
                keys.count = tracing::field::Empty,
            );
            let entries = provider.list_keys().instrument(list_span.clone()).await?;
            list_span.record("keys.count", entries.len());

            let mut provider_summary = ProviderSummary {
                name: provider_name.clone(),
                loaded: 0,
                skipped: 0,
                errors: Vec::new(),
            };

            let mut join_set = tokio::task::JoinSet::new();
            for entry in &entries {
                let id = entry.id.clone();
                let prov = Arc::clone(provider);
                let prov_name = provider_name.clone();
                let fetch_span = info_span!(
                    "rvc.secret_provider.fetch_key",
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
                        provider_summary.skipped += 1;
                        provider_summary.errors.push(format!("task panic: {}", e));
                        continue;
                    }
                };

                match result {
                    Ok(material) => match convert_key_material(&entry_id, material) {
                        Ok(secret_key) => {
                            key_manager.insert(secret_key);
                            provider_summary.loaded += 1;
                        }
                        Err(e) => {
                            warn!(
                                provider = %provider_name,
                                key_id = %entry_id,
                                error = %e,
                                "Failed to convert key material, skipping"
                            );
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
                        provider_summary.skipped += 1;
                        provider_summary.errors.push(format!("{}: {}", entry_id, e));
                    }
                }
            }

            summary.per_provider.push(provider_summary);
        }

        Ok(summary)
    }
}

fn convert_key_material(id: &str, material: KeyMaterial) -> Result<SecretKey, SecretProviderError> {
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
    use std::sync::Mutex;

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
            self.spans.lock().unwrap().push(attrs.metadata().name().to_string());
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
            self.0.lock().unwrap().push((
                self.1.clone(),
                field.name().to_string(),
                format!("{:?}", value),
            ));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.lock().unwrap().push((
                self.1.clone(),
                field.name().to_string(),
                value.to_string(),
            ));
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.lock().unwrap().push((
                self.1.clone(),
                field.name().to_string(),
                value.to_string(),
            ));
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

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock().unwrap();
        assert!(
            captured.contains(&"rvc.secret_provider.load_all".to_string()),
            "Expected rvc.secret_provider.load_all span, got: {:?}",
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

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock().unwrap();
        assert!(
            captured.contains(&"rvc.secret_provider.list_keys".to_string()),
            "Expected rvc.secret_provider.list_keys span, got: {:?}",
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

        ksm.load_all(&mut km).await.unwrap();

        let captured = spans.lock().unwrap();
        assert!(
            captured.contains(&"rvc.secret_provider.fetch_key".to_string()),
            "Expected rvc.secret_provider.fetch_key span, got: {:?}",
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

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(span, field, value)| span == "rvc.secret_provider.load_all"
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

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(span, field, value)| span == "rvc.secret_provider.list_keys"
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

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(span, field, value)| span == "rvc.secret_provider.fetch_key"
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

        ksm.load_all(&mut km).await.unwrap();

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(span, field, value)| span == "rvc.secret_provider.list_keys"
                && field == "provider.name"
                && value == "my-prov"),
            "Expected provider.name=my-prov on list_keys span, got: {:?}",
            *captured
        );
    }
}
