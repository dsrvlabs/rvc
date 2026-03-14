use async_trait::async_trait;
use thiserror::Error;

use super::bls::{PublicKey, Signature, PUBLIC_KEY_BYTES_LEN};
use super::key_manager::KeyManager;
use eth_types::Root;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("remote signer error: {0}")]
    RemoteSignerError(String),

    #[error("remote signer returned invalid signature")]
    InvalidRemoteSignature,
}

#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError>;

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]>;
}

pub struct LocalSigner {
    key_manager: KeyManager,
}

impl LocalSigner {
    pub fn new(key_manager: KeyManager) -> Self {
        Self { key_manager }
    }
}

#[async_trait]
impl Signer for LocalSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        let pk = PublicKey::from_bytes(pubkey)
            .map_err(|_| SigningError::KeyNotFound(hex::encode(pubkey)))?;
        let sk = self
            .key_manager
            .get_secret_key(&pk)
            .ok_or_else(|| SigningError::KeyNotFound(hex::encode(pubkey)))?;
        Ok(sk.sign(signing_root))
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.key_manager.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    fn create_local_signer_with_key(sk: SecretKey) -> LocalSigner {
        let mut km = KeyManager::new();
        km.insert(sk);
        LocalSigner::new(km)
    }

    #[tokio::test]
    async fn test_signer_trait_local_signer_public_keys_returns_loaded_keys() {
        let sk = SecretKey::generate();
        let expected_pubkey = sk.public_key().to_bytes();
        let signer = create_local_signer_with_key(sk);

        let keys = signer.public_keys();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], expected_pubkey);
    }

    #[tokio::test]
    async fn test_signer_trait_local_signer_sign_matches_direct_signing() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xab; 32];

        let direct_sig = sk.sign(&signing_root);

        let signer = create_local_signer_with_key(sk);
        let trait_sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();

        assert_eq!(direct_sig.to_bytes(), trait_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_signer_trait_local_signer_sign_unknown_key_returns_error() {
        let sk = SecretKey::generate();
        let signer = create_local_signer_with_key(sk);

        let unknown_sk = SecretKey::generate();
        let unknown_pk_bytes = unknown_sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let result = signer.sign(&signing_root, &unknown_pk_bytes).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::KeyNotFound(pk_hex) => {
                assert_eq!(pk_hex, hex::encode(unknown_pk_bytes));
            }
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_signer_trait_local_signer_signature_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let signing_root: Root = [0xab; 32];

        let signer = create_local_signer_with_key(sk);
        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();

        assert!(sig.verify(&pk, &signing_root).is_ok());
    }

    #[tokio::test]
    async fn test_signer_trait_local_signer_empty_public_keys() {
        let signer = LocalSigner::new(KeyManager::new());
        assert!(signer.public_keys().is_empty());
    }

    #[tokio::test]
    async fn test_signer_trait_object_safety() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let signing_root: Root = [0xab; 32];

        let signer: Box<dyn Signer> = Box::new(create_local_signer_with_key(sk));

        let sig = signer.sign(&signing_root, &pk_bytes).await.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
        assert_eq!(signer.public_keys().len(), 1);
    }
}
