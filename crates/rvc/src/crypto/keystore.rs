use std::fs;
use std::path::Path;

use aes::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::bls::SecretKey;
use super::error::KeystoreError;

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

const KEYSTORE_VERSION: u32 = 4;
const KDF_SCRYPT: &str = "scrypt";
const KDF_PBKDF2: &str = "pbkdf2";
const CIPHER_AES_128_CTR: &str = "aes-128-ctr";
const CHECKSUM_SHA256: &str = "sha256";
const DERIVED_KEY_LEN: usize = 32;
const AES_KEY_LEN: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub crypto: Crypto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    pub path: String,
    pub uuid: Uuid,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfModule {
    pub function: String,
    pub params: KdfParams,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParams {
    Scrypt(ScryptParams),
    Pbkdf2(Pbkdf2Params),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2Params {
    pub dklen: u32,
    pub c: u32,
    pub prf: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumModule {
    pub function: String,
    pub params: ChecksumParams,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumParams {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherModule {
    pub function: String,
    pub params: CipherParams,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

impl Keystore {
    pub fn from_json(json: &str) -> Result<Self, KeystoreError> {
        let keystore: Keystore = serde_json::from_str(json)?;
        keystore.validate()?;
        Ok(keystore)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let json = fs::read_to_string(path)?;
        Self::from_json(&json)
    }

    fn validate(&self) -> Result<(), KeystoreError> {
        if self.version != KEYSTORE_VERSION {
            return Err(KeystoreError::UnsupportedVersion(self.version));
        }

        match self.crypto.kdf.function.as_str() {
            KDF_SCRYPT | KDF_PBKDF2 => {}
            other => return Err(KeystoreError::UnsupportedKdf(other.to_string())),
        }

        if self.crypto.cipher.function != CIPHER_AES_128_CTR {
            return Err(KeystoreError::UnsupportedCipher(self.crypto.cipher.function.clone()));
        }

        if self.crypto.checksum.function != CHECKSUM_SHA256 {
            return Err(KeystoreError::UnsupportedChecksum(self.crypto.checksum.function.clone()));
        }

        Ok(())
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<SecretKey, KeystoreError> {
        let derived_key = self.derive_key(password)?;
        let ciphertext = hex::decode(&self.crypto.cipher.message)?;
        self.verify_checksum(&derived_key, &ciphertext)?;
        let plaintext = self.decrypt_ciphertext(&derived_key, &ciphertext)?;
        SecretKey::from_bytes(&plaintext).map_err(KeystoreError::from)
    }

    fn derive_key(&self, password: &[u8]) -> Result<[u8; DERIVED_KEY_LEN], KeystoreError> {
        match self.crypto.kdf.function.as_str() {
            KDF_SCRYPT => self.derive_key_scrypt(password),
            KDF_PBKDF2 => self.derive_key_pbkdf2(password),
            other => Err(KeystoreError::UnsupportedKdf(other.to_string())),
        }
    }

    fn derive_key_scrypt(&self, password: &[u8]) -> Result<[u8; DERIVED_KEY_LEN], KeystoreError> {
        let params = match &self.crypto.kdf.params {
            KdfParams::Scrypt(p) => p,
            _ => {
                return Err(KeystoreError::InvalidScryptParams(
                    "expected scrypt params".to_string(),
                ))
            }
        };

        if params.n == 0 || !params.n.is_power_of_two() {
            return Err(KeystoreError::InvalidScryptParams(
                "n must be a positive power of 2".to_string(),
            ));
        }

        let salt = hex::decode(&params.salt)?;
        let log_n = params.n.trailing_zeros() as u8;

        let scrypt_params = scrypt::Params::new(log_n, params.r, params.p, params.dklen as usize)
            .map_err(|e| KeystoreError::InvalidScryptParams(e.to_string()))?;

        let mut derived_key = [0u8; DERIVED_KEY_LEN];
        scrypt::scrypt(password, &salt, &scrypt_params, &mut derived_key)
            .map_err(|e| KeystoreError::KeyDerivationFailed(e.to_string()))?;

        Ok(derived_key)
    }

    fn derive_key_pbkdf2(&self, password: &[u8]) -> Result<[u8; DERIVED_KEY_LEN], KeystoreError> {
        let params = match &self.crypto.kdf.params {
            KdfParams::Pbkdf2(p) => p,
            _ => {
                return Err(KeystoreError::KeyDerivationFailed(
                    "expected pbkdf2 params".to_string(),
                ))
            }
        };

        if params.prf != "hmac-sha256" {
            return Err(KeystoreError::KeyDerivationFailed(format!(
                "unsupported PRF: {}",
                params.prf
            )));
        }

        let salt = hex::decode(&params.salt)?;
        let mut derived_key = [0u8; DERIVED_KEY_LEN];

        pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, params.c, &mut derived_key);

        Ok(derived_key)
    }

    fn verify_checksum(
        &self,
        derived_key: &[u8; DERIVED_KEY_LEN],
        ciphertext: &[u8],
    ) -> Result<(), KeystoreError> {
        let expected_checksum = hex::decode(&self.crypto.checksum.message)?;

        let mut hasher = Sha256::new();
        hasher.update(&derived_key[AES_KEY_LEN..DERIVED_KEY_LEN]);
        hasher.update(ciphertext);
        let computed_checksum = hasher.finalize();

        if computed_checksum.as_slice() != expected_checksum {
            return Err(KeystoreError::ChecksumMismatch);
        }

        Ok(())
    }

    fn decrypt_ciphertext(
        &self,
        derived_key: &[u8; DERIVED_KEY_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeystoreError> {
        let iv = hex::decode(&self.crypto.cipher.params.iv)?;
        let aes_key = &derived_key[..AES_KEY_LEN];

        let mut cipher = Aes128Ctr::new(aes_key.into(), iv.as_slice().into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }

    pub fn pubkey_bytes(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        match &self.pubkey {
            Some(pk) => Ok(Some(hex::decode(pk)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EIP-2335 official test vectors from https://eips.ethereum.org/EIPS/eip-2335
    // Password: 0x7465737470617373776f7264f09f9491 (UTF-8: test password with emoji)
    // Secret: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    const EIP2335_PASSWORD: &[u8] = &[
        0x74, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xf0, 0x9f, 0x94,
        0x91,
    ];
    const EIP2335_SECRET_HEX: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    const EIP2335_SCRYPT_TEST_VECTOR: &str = r#"
    {
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
        },
        "description": "This is a test keystore that uses scrypt to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/3141592653/589793238",
        "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
        "version": 4
    }
    "#;

    const EIP2335_PBKDF2_TEST_VECTOR: &str = r#"
    {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32,
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
            }
        },
        "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }
    "#;

    #[test]
    fn test_parse_scrypt_keystore() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "scrypt");
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(keystore.crypto.checksum.function, "sha256");
        assert_eq!(keystore.path, "m/12381/60/3141592653/589793238");
    }

    #[test]
    fn test_parse_pbkdf2_keystore() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "pbkdf2");
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(keystore.crypto.checksum.function, "sha256");
        assert_eq!(keystore.path, "m/12381/60/0/0");
    }

    #[test]
    fn test_scrypt_params_extraction() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Scrypt(params) => {
                assert_eq!(params.dklen, 32);
                assert_eq!(params.n, 262144);
                assert_eq!(params.p, 1);
                assert_eq!(params.r, 8);
            }
            _ => panic!("expected scrypt params"),
        }
    }

    #[test]
    fn test_pbkdf2_params_extraction() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Pbkdf2(params) => {
                assert_eq!(params.dklen, 32);
                assert_eq!(params.c, 262144);
                assert_eq!(params.prf, "hmac-sha256");
            }
            _ => panic!("expected pbkdf2 params"),
        }
    }

    #[test]
    fn test_unsupported_version() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 3
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedVersion(3))));
    }

    #[test]
    fn test_unsupported_kdf() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "argon2id", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedKdf(_))));
    }

    #[test]
    fn test_unsupported_cipher() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-256-gcm", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedCipher(_))));
    }

    #[test]
    fn test_unsupported_checksum() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha512", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedChecksum(_))));
    }

    #[test]
    fn test_uuid_parsing() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        assert_eq!(keystore.uuid.to_string(), "1d85ae20-35c5-4611-98e8-aa14a633906f");
    }

    #[test]
    fn test_pubkey_extraction() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let pubkey_bytes = keystore.pubkey_bytes().expect("should decode").unwrap();
        assert_eq!(pubkey_bytes.len(), 48);
    }

    #[test]
    fn test_optional_fields() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        assert!(keystore.description.is_none());
        assert!(keystore.pubkey.is_none());
    }

    #[test]
    fn test_scrypt_key_derivation() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let derived_key = keystore.derive_key(EIP2335_PASSWORD).expect("should derive key");
        assert_eq!(derived_key.len(), 32);
    }

    #[test]
    fn test_pbkdf2_key_derivation() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        let derived_key = keystore.derive_key(EIP2335_PASSWORD).expect("should derive key");
        assert_eq!(derived_key.len(), 32);
    }

    #[test]
    fn test_scrypt_decrypt_eip2335_test_vector() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let expected_secret = hex::decode(EIP2335_SECRET_HEX).expect("valid hex");
        assert_eq!(secret_key.to_bytes().to_vec(), expected_secret);
    }

    #[test]
    fn test_pbkdf2_decrypt_eip2335_test_vector() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let expected_secret = hex::decode(EIP2335_SECRET_HEX).expect("valid hex");
        assert_eq!(secret_key.to_bytes().to_vec(), expected_secret);
    }

    #[test]
    fn test_checksum_verification_failure_wrong_password() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let wrong_password = "wrongpassword".as_bytes();
        let result = keystore.decrypt(wrong_password);
        assert!(matches!(result, Err(KeystoreError::ChecksumMismatch)));
    }

    #[test]
    fn test_checksum_verification_failure_empty_password() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let result = keystore.decrypt(&[]);
        assert!(matches!(result, Err(KeystoreError::ChecksumMismatch)));
    }

    #[test]
    fn test_serialize_keystore() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let serialized = serde_json::to_string(&keystore).expect("should serialize");
        let reparsed: Keystore = serde_json::from_str(&serialized).expect("should reparse");
        assert_eq!(reparsed.version, keystore.version);
        assert_eq!(reparsed.uuid, keystore.uuid);
    }

    #[test]
    fn test_invalid_json() {
        let result = Keystore::from_json("not valid json");
        assert!(matches!(result, Err(KeystoreError::InvalidJson(_))));
    }

    #[test]
    fn test_scrypt_n_zero_returns_error() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 0, "p": 1, "r": 8, "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "264daa3f303d7259501c93d997d84fe6" }, "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(msg)) if msg.contains("power of 2"))
        );
    }

    #[test]
    fn test_scrypt_n_not_power_of_two_returns_error() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 3, "p": 1, "r": 8, "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "264daa3f303d7259501c93d997d84fe6" }, "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(msg)) if msg.contains("power of 2"))
        );
    }

    #[test]
    fn test_scrypt_n_valid_power_of_two() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Scrypt(params) => {
                assert_eq!(params.n, 262144);
                assert!(params.n.is_power_of_two());
            }
            _ => panic!("expected scrypt params"),
        }
        let result = keystore.decrypt(EIP2335_PASSWORD);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_hex_in_salt() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "not_hex!" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(matches!(result, Err(KeystoreError::InvalidHex(_))));
    }

    #[test]
    fn test_decrypted_key_can_sign() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let message = b"test message";
        let signature = secret_key.sign(message);
        let public_key = secret_key.public_key();
        assert!(signature.verify(&public_key, message).is_ok());
    }
}
