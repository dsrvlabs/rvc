use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use super::bls::{SecretKey, Signature, PUBLIC_KEY_BYTES_LEN};
use super::remote_signer::RemoteSigner;
use super::signer_trait::{LocalSigner, Signer, SigningError};
use eth_types::Root;

pub struct CompositeSigner {
    local: LocalSigner,
    remote: RwLock<HashMap<[u8; PUBLIC_KEY_BYTES_LEN], Arc<RemoteSigner>>>,
    dynamic_local: RwLock<HashMap<[u8; PUBLIC_KEY_BYTES_LEN], SecretKey>>,
}

impl CompositeSigner {
    pub fn new(local: LocalSigner) -> Self {
        Self {
            local,
            remote: RwLock::new(HashMap::new()),
            dynamic_local: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_remote_key(&self, pubkey: [u8; PUBLIC_KEY_BYTES_LEN], signer: RemoteSigner) {
        self.remote.write().expect("remote lock poisoned").insert(pubkey, Arc::new(signer));
    }

    pub fn remove_remote_key(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        self.remote.write().expect("remote lock poisoned").remove(pubkey).is_some()
    }

    pub fn add_local_key(&self, secret_key: SecretKey) {
        let pubkey = secret_key.public_key().to_bytes();
        self.dynamic_local.write().expect("dynamic_local lock poisoned").insert(pubkey, secret_key);
    }

    pub fn remove_local_key(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        self.dynamic_local.write().expect("dynamic_local lock poisoned").remove(pubkey).is_some()
    }
}

#[async_trait]
impl Signer for CompositeSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        // Check remote signers first — clone Arc to release the lock before await
        let remote_signer = {
            let remote = self.remote.read().expect("remote lock poisoned");
            remote.get(pubkey).cloned()
        };
        if let Some(signer) = remote_signer {
            return signer.sign(signing_root, pubkey).await;
        }

        // Check dynamically-added local keys
        {
            let dynamic = self.dynamic_local.read().expect("dynamic_local lock poisoned");
            if let Some(sk) = dynamic.get(pubkey) {
                return Ok(sk.sign(signing_root));
            }
        }

        // Fall through to the base local signer
        self.local.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        let mut keys = self.local.public_keys();

        let dynamic = self.dynamic_local.read().expect("dynamic_local lock poisoned");
        keys.extend(dynamic.keys());

        let remote = self.remote.read().expect("remote lock poisoned");
        for signer in remote.values() {
            keys.extend(signer.public_keys());
        }

        keys.sort();
        keys.dedup();
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::KeyManager;
    use crate::remote_signer::RemoteSignerConfig;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_empty_local_signer() -> LocalSigner {
        LocalSigner::new(KeyManager::new())
    }

    fn create_local_signer_with_key(sk: SecretKey) -> LocalSigner {
        let mut km = KeyManager::new();
        km.insert(sk);
        LocalSigner::new(km)
    }

    #[tokio::test]
    async fn test_composite_signer_local_sign() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];
        let expected_sig = sk.sign(&signing_root);

        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        let sig = composite.sign(&signing_root, &pk_bytes).await.unwrap();

        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_composite_signer_remote_sign() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];
        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let remote_signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_remote_key(pk_bytes, remote_signer);

        let sig = composite.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_composite_signer_unknown_key_returns_error() {
        let composite = CompositeSigner::new(create_empty_local_signer());

        let unknown_sk = SecretKey::generate();
        let unknown_pk = unknown_sk.public_key().to_bytes();
        let result = composite.sign(&[0xab; 32], &unknown_pk).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_composite_signer_public_keys_union() {
        let sk1 = SecretKey::generate();
        let pk1 = sk1.public_key().to_bytes();

        let sk2 = SecretKey::generate();
        let pk2 = sk2.public_key().to_bytes();

        let mock_server = MockServer::start().await;
        let config = RemoteSignerConfig::new(mock_server.uri());
        let remote_signer = RemoteSigner::new(config, vec![pk2]).unwrap();

        let composite = CompositeSigner::new(create_local_signer_with_key(sk1));
        composite.add_remote_key(pk2, remote_signer);

        let keys = composite.public_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&pk1));
        assert!(keys.contains(&pk2));
    }

    #[tokio::test]
    async fn test_composite_signer_dynamic_local_key() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];
        let expected_sig = sk.sign(&signing_root);

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_local_key(sk);

        let sig = composite.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());

        assert_eq!(composite.public_keys().len(), 1);
        assert!(composite.public_keys().contains(&pk_bytes));
    }

    #[tokio::test]
    async fn test_composite_signer_remove_remote_key() {
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let mock_server = MockServer::start().await;
        let config = RemoteSignerConfig::new(mock_server.uri());
        let remote_signer = RemoteSigner::new(config, vec![pk]).unwrap();

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_remote_key(pk, remote_signer);
        assert_eq!(composite.public_keys().len(), 1);

        let removed = composite.remove_remote_key(&pk);
        assert!(removed);
        assert!(composite.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_composite_signer_remove_local_key() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();

        let composite = CompositeSigner::new(create_empty_local_signer());
        composite.add_local_key(sk);
        assert_eq!(composite.public_keys().len(), 1);

        let removed = composite.remove_local_key(&pk_bytes);
        assert!(removed);
        assert!(composite.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_composite_signer_remove_nonexistent_key() {
        let composite = CompositeSigner::new(create_empty_local_signer());
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        assert!(!composite.remove_remote_key(&pk));
        assert!(!composite.remove_local_key(&pk));
    }

    #[tokio::test]
    async fn test_composite_signer_remote_takes_priority_over_local() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        // Use the same key so the remote signature is valid for this pubkey
        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .expect(1) // Verifies the remote signer was called (not local)
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let remote_signer = RemoteSigner::new(config, vec![pk_bytes]).unwrap();

        // Same key in both local and remote
        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        composite.add_remote_key(pk_bytes, remote_signer);

        let sig = composite.sign(&signing_root, &pk_bytes).await.unwrap();
        // Mock expectation (expect(1)) verifies remote path was used
        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_composite_signer_object_safety() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let composite = CompositeSigner::new(create_local_signer_with_key(sk));
        let signer: Box<dyn Signer> = Box::new(composite);

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
        assert_eq!(signer.public_keys().len(), 1);
    }
}
