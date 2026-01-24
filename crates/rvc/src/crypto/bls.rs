use std::fmt;
use std::hash::{Hash, Hasher};

use blst::min_pk::{
    AggregateSignature, PublicKey as BlstPublicKey, SecretKey as BlstSecretKey,
    Signature as BlstSignature,
};
use blst::BLST_ERROR;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

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
            .map_err(|_| BlsError::InvalidPublicKey("invalid public key bytes".to_string()))
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

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

pub struct SecretKey {
    inner: BlstSecretKey,
    raw_bytes: [u8; SECRET_KEY_BYTES_LEN],
}

impl SecretKey {
    pub fn generate() -> Self {
        let mut ikm = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(ikm.as_mut());

        let inner = BlstSecretKey::key_gen(ikm.as_ref(), &[])
            .expect("key generation should not fail with valid IKM");
        let raw_bytes = inner.to_bytes();

        Self { inner, raw_bytes }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let inner = BlstSecretKey::from_bytes(bytes)
            .map_err(|_| BlsError::InvalidSecretKey("invalid secret key bytes".to_string()))?;

        let mut raw_bytes = [0u8; SECRET_KEY_BYTES_LEN];
        if bytes.len() == SECRET_KEY_BYTES_LEN {
            raw_bytes.copy_from_slice(bytes);
        } else {
            raw_bytes = inner.to_bytes();
        }

        Ok(Self { inner, raw_bytes })
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        self.inner.to_bytes()
    }

    pub fn raw_bytes(&self) -> &[u8; SECRET_KEY_BYTES_LEN] {
        &self.raw_bytes
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.inner.sk_to_pk())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.inner.sign(message, DST, &[]))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.raw_bytes.zeroize();
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
            .map_err(|_| BlsError::InvalidSignature("invalid signature bytes".to_string()))
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
            .map_err(|_| BlsError::InvalidSignature("signature aggregation failed".to_string()))?;

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

    #[test]
    fn test_secret_key_has_raw_bytes() {
        let sk = SecretKey::generate();
        let raw = sk.raw_bytes();
        let expected = sk.to_bytes();
        assert_eq!(raw, &expected);
    }

    #[test]
    fn test_secret_key_zeroized_on_drop() {
        use std::ptr;

        let raw_ptr: *const [u8; SECRET_KEY_BYTES_LEN];
        {
            let sk = SecretKey::generate();
            raw_ptr = sk.raw_bytes() as *const [u8; SECRET_KEY_BYTES_LEN];
            let bytes_before_drop = sk.to_bytes();
            assert_ne!(bytes_before_drop, [0u8; SECRET_KEY_BYTES_LEN]);
        }
        // After drop, the memory at raw_ptr should be zeroed
        // Note: This is a best-effort test - memory may be reused
        // The actual zeroization happens via the Zeroize trait
        unsafe {
            let zeroed = ptr::read_volatile(raw_ptr);
            assert_eq!(zeroed, [0u8; SECRET_KEY_BYTES_LEN]);
        }
    }

    #[test]
    fn test_secret_key_from_bytes_stores_raw() {
        let original = SecretKey::generate();
        let bytes = original.to_bytes();
        let restored = SecretKey::from_bytes(&bytes).expect("valid bytes");
        assert_eq!(restored.raw_bytes(), &bytes);
    }

    #[test]
    fn test_secret_key_error_uses_generic_message() {
        let invalid_bytes = vec![0u8; 10];
        let result = SecretKey::from_bytes(&invalid_bytes);
        let err = result.unwrap_err();
        match err {
            BlsError::InvalidSecretKey(msg) => {
                assert_eq!(msg, "invalid secret key bytes");
            }
            _ => panic!("Expected InvalidSecretKey error"),
        }
    }

    #[test]
    fn test_public_key_error_uses_generic_message() {
        let invalid_bytes = vec![0u8; 10];
        let result = PublicKey::from_bytes(&invalid_bytes);
        let err = result.unwrap_err();
        match err {
            BlsError::InvalidPublicKey(msg) => {
                assert_eq!(msg, "invalid public key bytes");
            }
            _ => panic!("Expected InvalidPublicKey error"),
        }
    }

    #[test]
    fn test_signature_error_uses_generic_message() {
        let invalid_bytes = vec![0u8; 10];
        let result = Signature::from_bytes(&invalid_bytes);
        let err = result.unwrap_err();
        match err {
            BlsError::InvalidSignature(msg) => {
                assert_eq!(msg, "invalid signature bytes");
            }
            _ => panic!("Expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_signature_aggregate_error_uses_generic_message() {
        let sk = SecretKey::generate();
        let message = b"test message";
        let sig = sk.sign(message);
        let mut corrupted_bytes = sig.to_bytes();
        corrupted_bytes[0] ^= 0xff;
        let corrupted_sig = Signature::from_bytes(&corrupted_bytes);
        if corrupted_sig.is_err() {
            return;
        }
        let corrupted_sig = corrupted_sig.unwrap();
        let result = Signature::aggregate(&[&corrupted_sig, &corrupted_sig]);
        if let Err(BlsError::InvalidSignature(msg)) = result {
            assert_eq!(msg, "signature aggregation failed");
        }
    }
}
