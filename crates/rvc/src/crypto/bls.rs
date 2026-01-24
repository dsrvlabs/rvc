use std::fmt;

use blst::min_pk::{
    AggregateSignature, PublicKey as BlstPublicKey, SecretKey as BlstSecretKey,
    Signature as BlstSignature,
};
use blst::BLST_ERROR;
use rand::RngCore;

use super::error::BlsError;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub const PUBLIC_KEY_BYTES_LEN: usize = 48;
pub const SECRET_KEY_BYTES_LEN: usize = 32;
pub const SIGNATURE_BYTES_LEN: usize = 96;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(BlstPublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        BlstPublicKey::from_bytes(bytes)
            .map(PublicKey)
            .map_err(|e| BlsError::InvalidPublicKey(format!("{:?}", e)))
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0.to_bytes()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self)
    }
}

#[derive(Clone)]
pub struct SecretKey(BlstSecretKey);

impl SecretKey {
    pub fn generate() -> Self {
        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        SecretKey(
            BlstSecretKey::key_gen(&ikm, &[])
                .expect("key generation should not fail with valid IKM"),
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        BlstSecretKey::from_bytes(bytes)
            .map(SecretKey)
            .map_err(|e| BlsError::InvalidSecretKey(format!("{:?}", e)))
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.sk_to_pk())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, DST, &[]))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Signature(BlstSignature);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        BlstSignature::from_bytes(bytes)
            .map(Signature)
            .map_err(|e| BlsError::InvalidSignature(format!("{:?}", e)))
    }

    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0.to_bytes()
    }

    pub fn verify(&self, public_key: &PublicKey, message: &[u8]) -> Result<(), BlsError> {
        let result = self.0.verify(true, message, DST, &[], &public_key.0, true);
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(BlsError::SignatureVerificationFailed)
        }
    }

    pub fn aggregate(signatures: &[&Signature]) -> Result<Self, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::InvalidSignature("cannot aggregate empty list".to_string()));
        }

        let blst_sigs: Vec<&BlstSignature> = signatures.iter().map(|s| &s.0).collect();
        let agg = AggregateSignature::aggregate(&blst_sigs, true)
            .map_err(|e| BlsError::InvalidSignature(format!("{:?}", e)))?;

        Ok(Signature(agg.to_signature()))
    }

    pub fn verify_aggregate(
        &self,
        public_keys: &[&PublicKey],
        message: &[u8],
    ) -> Result<(), BlsError> {
        if public_keys.is_empty() {
            return Err(BlsError::InvalidPublicKey(
                "cannot verify with empty public key list".to_string(),
            ));
        }

        let blst_pks: Vec<&BlstPublicKey> = public_keys.iter().map(|pk| &pk.0).collect();
        let msgs: Vec<&[u8]> = vec![message; public_keys.len()];

        let result = self.0.aggregate_verify(true, &msgs, DST, &blst_pks, true);
        if result == BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(BlsError::SignatureVerificationFailed)
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.to_bytes()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_generation() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_secret_key_bytes_roundtrip() {
        let sk = SecretKey::generate();
        let bytes = sk.to_bytes();
        let sk_restored = SecretKey::from_bytes(&bytes).expect("valid bytes");
        assert_eq!(sk.to_bytes(), sk_restored.to_bytes());
    }

    #[test]
    fn test_public_key_bytes_roundtrip() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        let pk_restored = PublicKey::from_bytes(&bytes).expect("valid bytes");
        assert_eq!(pk.to_bytes(), pk_restored.to_bytes());
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let sk = SecretKey::generate();
        let message = b"test message";
        let sig = sk.sign(message);
        let bytes = sig.to_bytes();
        let sig_restored = Signature::from_bytes(&bytes).expect("valid bytes");
        assert_eq!(sig.to_bytes(), sig_restored.to_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let message = b"test message";
        let sig = sk.sign(message);
        assert!(sig.verify(&pk, message).is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let message = b"test message";
        let wrong_message = b"wrong message";
        let sig = sk.sign(message);
        assert!(sig.verify(&pk, wrong_message).is_err());
    }

    #[test]
    fn test_verify_wrong_public_key_fails() {
        let sk = SecretKey::generate();
        let wrong_sk = SecretKey::generate();
        let wrong_pk = wrong_sk.public_key();
        let message = b"test message";
        let sig = sk.sign(message);
        assert!(sig.verify(&wrong_pk, message).is_err());
    }

    #[test]
    fn test_public_key_hex_display() {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let display = format!("{}", pk);
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 2 + PUBLIC_KEY_BYTES_LEN * 2);
    }

    #[test]
    fn test_signature_hex_display() {
        let sk = SecretKey::generate();
        let sig = sk.sign(b"test");
        let display = format!("{}", sig);
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 2 + SIGNATURE_BYTES_LEN * 2);
    }

    #[test]
    fn test_secret_key_debug_redacted() {
        let sk = SecretKey::generate();
        let debug = format!("{:?}", sk);
        assert_eq!(debug, "SecretKey([REDACTED])");
    }

    #[test]
    fn test_invalid_public_key_bytes() {
        let invalid_bytes = vec![0u8; 10];
        let result = PublicKey::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_secret_key_bytes() {
        let invalid_bytes = vec![0u8; 10];
        let result = SecretKey::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_bytes() {
        let invalid_bytes = vec![0u8; 10];
        let result = Signature::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_signatures() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let message = b"aggregate test";

        let sig1 = sk1.sign(message);
        let sig2 = sk2.sign(message);

        let agg_sig = Signature::aggregate(&[&sig1, &sig2]).expect("aggregation should succeed");
        assert!(agg_sig.verify_aggregate(&[&pk1, &pk2], message).is_ok());
    }

    #[test]
    fn test_aggregate_empty_fails() {
        let result = Signature::aggregate(&[]);
        assert!(result.is_err());
    }
}
