use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::bls::SecretKey;

#[derive(Debug, thiserror::Error)]
pub enum Eip2333Error {
    #[error("Invalid seed length: expected >= 32 bytes, got {0}")]
    InvalidSeedLength(usize),
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),
    #[error("HKDF expand failed: {0}")]
    HkdfError(String),
    #[error("Invalid secret key bytes: {0}")]
    InvalidSecretKey(#[from] super::error::BlsError),
}

/// BLS12-381 subgroup order r.
const BLS_ORDER: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

/// HKDF-SHA256 extract+expand, 48-byte OKM reduced mod r.
///
/// Implements the `HKDF_mod_r` function from EIP-2333.
fn hkdf_mod_r(ikm: &[u8], key_info: &[u8]) -> Result<Zeroizing<[u8; 32]>, Eip2333Error> {
    let r = BigUint::from_bytes_be(&hex::decode(BLS_ORDER).expect("valid hex constant"));

    let mut salt = Sha256::digest(b"BLS-SIG-KEYGEN-SALT-").to_vec();

    // info = key_info || I2OSP(L, 2), where L=48
    let mut info = key_info.to_vec();
    info.extend_from_slice(&[0x00, 0x30]); // 48 as big-endian u16

    // IKM' = IKM || I2OSP(0, 1)
    let mut ikm_prime = Zeroizing::new(ikm.to_vec());
    ikm_prime.push(0x00);

    loop {
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm_prime);
        let mut okm = Zeroizing::new([0u8; 48]);
        hk.expand(&info, okm.as_mut()).map_err(|e| Eip2333Error::HkdfError(e.to_string()))?;

        let sk_int = BigUint::from_bytes_be(okm.as_ref()) % &r;
        if sk_int != BigUint::ZERO {
            let mut bytes = Zeroizing::new(sk_int.to_bytes_be());
            let mut buf = Zeroizing::new([0u8; 32]);
            buf[32 - bytes.len()..].copy_from_slice(&bytes);
            // Best-effort zeroize: BigUint does not implement Zeroize (upstream limitation),
            // but we zeroize its exported byte representation immediately after use.
            bytes.iter_mut().for_each(|b| *b = 0);
            return Ok(buf);
        }

        // Rehash salt and try again (astronomically unlikely)
        salt = Sha256::digest(&salt).to_vec();
    }
}

/// Derives a Lamport secret key from IKM and salt.
///
/// Returns 8160 bytes (255 * 32 chunks).
fn ikm_to_lamport_sk(ikm: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, Eip2333Error> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new(vec![0u8; 8160]);
    hk.expand(&[], okm.as_mut_slice()).map_err(|e| Eip2333Error::HkdfError(e.to_string()))?;
    Ok(okm)
}

/// Derives a compressed Lamport public key from a parent secret key and child index.
fn parent_sk_to_lamport_pk(
    parent_sk: &SecretKey,
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, Eip2333Error> {
    let salt = index.to_be_bytes();

    // Parent SK as 32-byte big-endian
    let ikm = Zeroizing::new(parent_sk.to_bytes());

    // lamport_0 = IKM_to_lamport_SK(IKM, salt)
    let lamport_0 = ikm_to_lamport_sk(ikm.as_ref(), &salt)?;

    // not_IKM = bitwise NOT of IKM
    let mut not_ikm = Zeroizing::new(ikm.to_vec());
    for byte in not_ikm.iter_mut() {
        *byte = !*byte;
    }

    // lamport_1 = IKM_to_lamport_SK(not_IKM, salt)
    let lamport_1 = ikm_to_lamport_sk(&not_ikm, &salt)?;

    // Hash each 32-byte chunk and concatenate
    let mut lamport_pk = Zeroizing::new(vec![0u8; 510 * 32]); // 255 * 2 * 32
    for i in 0..255 {
        let hash = Sha256::digest(&lamport_0[i * 32..(i + 1) * 32]);
        lamport_pk[i * 32..(i + 1) * 32].copy_from_slice(&hash);
    }
    for i in 0..255 {
        let hash = Sha256::digest(&lamport_1[i * 32..(i + 1) * 32]);
        lamport_pk[(255 + i) * 32..(256 + i) * 32].copy_from_slice(&hash);
    }

    // Compress: SHA-256 of the full lamport_PK
    let compressed = Sha256::digest(lamport_pk.as_slice());
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&compressed);
    Ok(result)
}

/// Derives a master secret key from a seed (>= 32 bytes).
pub fn derive_master_sk(seed: &[u8]) -> Result<SecretKey, Eip2333Error> {
    if seed.len() < 32 {
        return Err(Eip2333Error::InvalidSeedLength(seed.len()));
    }
    let sk_bytes = hkdf_mod_r(seed, &[])?;
    SecretKey::from_bytes(sk_bytes.as_ref()).map_err(Eip2333Error::from)
}

/// Derives a child secret key from a parent secret key and index.
pub fn derive_child_sk(parent_sk: &SecretKey, index: u32) -> Result<SecretKey, Eip2333Error> {
    let compressed_pk = parent_sk_to_lamport_pk(parent_sk, index)?;
    let sk_bytes = hkdf_mod_r(compressed_pk.as_ref(), &[])?;
    SecretKey::from_bytes(sk_bytes.as_ref()).map_err(Eip2333Error::from)
}

/// Derives a key from a BIP-44-style path string (e.g. "m/12381/3600/0/0/0").
pub fn derive_key_from_path(seed: &[u8], path: &str) -> Result<SecretKey, Eip2333Error> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty() || parts[0] != "m" {
        return Err(Eip2333Error::InvalidPath(format!("path must start with 'm', got '{}'", path)));
    }

    let mut sk = derive_master_sk(seed)?;
    for part in &parts[1..] {
        let index: u32 = part.parse().map_err(|_| {
            Eip2333Error::InvalidPath(format!("invalid path component: '{}'", part))
        })?;
        sk = derive_child_sk(&sk, index)?;
    }
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: convert a decimal string to 32-byte big-endian bytes.
    fn decimal_to_bytes(decimal: &str) -> [u8; 32] {
        let n = BigUint::parse_bytes(decimal.as_bytes(), 10).expect("valid decimal");
        let bytes = n.to_bytes_be();
        let mut buf = [0u8; 32];
        buf[32 - bytes.len()..].copy_from_slice(&bytes);
        buf
    }

    // ---- Test Case 0 ----

    #[test]
    fn test_vector_0_master_sk() {
        let seed = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();
        let expected = decimal_to_bytes(
            "6083874454709270928345386274498605044986640685124978867557563392430687146096",
        );
        let master = derive_master_sk(&seed).unwrap();
        assert_eq!(master.to_bytes(), expected);
    }

    #[test]
    fn test_vector_0_child_sk() {
        let seed = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();
        let expected = decimal_to_bytes(
            "20397789859736650942317412262472558107875392172444076792671091975210932703118",
        );
        let master = derive_master_sk(&seed).unwrap();
        let child = derive_child_sk(&master, 0).unwrap();
        assert_eq!(child.to_bytes(), expected);
    }

    // ---- Test Case 1 ----

    #[test]
    fn test_vector_1_master_sk() {
        let seed = hex::decode("3141592653589793238462643383279502884197169399375105820974944592")
            .unwrap();
        let expected = decimal_to_bytes(
            "29757020647961307431480504535336562678282505419141012933316116377660817309383",
        );
        let master = derive_master_sk(&seed).unwrap();
        assert_eq!(master.to_bytes(), expected);
    }

    #[test]
    fn test_vector_1_child_sk() {
        let seed = hex::decode("3141592653589793238462643383279502884197169399375105820974944592")
            .unwrap();
        let expected = decimal_to_bytes(
            "25457201688850691947727629385191704516744796114925897962676248250929345014287",
        );
        let master = derive_master_sk(&seed).unwrap();
        let child = derive_child_sk(&master, 3141592653).unwrap();
        assert_eq!(child.to_bytes(), expected);
    }

    // ---- Test Case 2 ----

    #[test]
    fn test_vector_2_master_sk() {
        let seed = hex::decode("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00")
            .unwrap();
        let expected = decimal_to_bytes(
            "27580842291869792442942448775674722299803720648445448686099262467207037398656",
        );
        let master = derive_master_sk(&seed).unwrap();
        assert_eq!(master.to_bytes(), expected);
    }

    #[test]
    fn test_vector_2_child_sk() {
        let seed = hex::decode("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00")
            .unwrap();
        let expected = decimal_to_bytes(
            "29358610794459428860402234341874281240803786294062035874021252734817515685787",
        );
        let master = derive_master_sk(&seed).unwrap();
        let child = derive_child_sk(&master, 4294967295).unwrap();
        assert_eq!(child.to_bytes(), expected);
    }

    // ---- Test Case 3 ----

    #[test]
    fn test_vector_3_master_sk() {
        let seed = hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
            .unwrap();
        let expected = decimal_to_bytes(
            "19022158461524446591288038168518313374041767046816487870552872741050760015818",
        );
        let master = derive_master_sk(&seed).unwrap();
        assert_eq!(master.to_bytes(), expected);
    }

    #[test]
    fn test_vector_3_child_sk() {
        let seed = hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
            .unwrap();
        let expected = decimal_to_bytes(
            "31372231650479070279774297061823572166496564838472787488249775572789064611981",
        );
        let master = derive_master_sk(&seed).unwrap();
        let child = derive_child_sk(&master, 42).unwrap();
        assert_eq!(child.to_bytes(), expected);
    }

    // ---- Error cases ----

    #[test]
    fn test_seed_too_short() {
        let seed = vec![0u8; 16];
        let result = derive_master_sk(&seed);
        assert!(result.is_err());
        match result.unwrap_err() {
            Eip2333Error::InvalidSeedLength(len) => assert_eq!(len, 16),
            other => panic!("expected InvalidSeedLength, got {:?}", other),
        }
    }

    #[test]
    fn test_seed_exactly_32_bytes() {
        let seed = vec![0xab; 32];
        let result = derive_master_sk(&seed);
        assert!(result.is_ok());
    }

    // ---- Path derivation tests ----

    #[test]
    fn test_derive_key_from_path_master_only() {
        let seed = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();
        let expected = decimal_to_bytes(
            "6083874454709270928345386274498605044986640685124978867557563392430687146096",
        );
        let key = derive_key_from_path(&seed, "m").unwrap();
        assert_eq!(key.to_bytes(), expected);
    }

    #[test]
    fn test_derive_key_from_path_single_child() {
        let seed = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();
        let expected = decimal_to_bytes(
            "20397789859736650942317412262472558107875392172444076792671091975210932703118",
        );
        let key = derive_key_from_path(&seed, "m/0").unwrap();
        assert_eq!(key.to_bytes(), expected);
    }

    #[test]
    fn test_derive_key_from_path_invalid_no_m() {
        let seed = vec![0xab; 32];
        let result = derive_key_from_path(&seed, "0/1/2");
        assert!(result.is_err());
        match result.unwrap_err() {
            Eip2333Error::InvalidPath(_) => {}
            other => panic!("expected InvalidPath, got {:?}", other),
        }
    }

    #[test]
    fn test_derive_key_from_path_invalid_component() {
        let seed = vec![0xab; 32];
        let result = derive_key_from_path(&seed, "m/abc");
        assert!(result.is_err());
        match result.unwrap_err() {
            Eip2333Error::InvalidPath(_) => {}
            other => panic!("expected InvalidPath, got {:?}", other),
        }
    }

    #[test]
    fn test_derive_key_from_path_eth2_signing_key() {
        // m/12381/3600/0/0/0 — standard signing key path
        let seed = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();
        let key = derive_key_from_path(&seed, "m/12381/3600/0/0/0");
        assert!(key.is_ok());
        // Verify it produces a valid key that can generate a public key
        let pk = key.unwrap().public_key();
        assert_eq!(pk.to_bytes().len(), 48);
    }

    // ---- Zeroization ----

    #[test]
    fn test_derived_key_produces_valid_signature() {
        let seed = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();
        let sk = derive_master_sk(&seed).unwrap();
        let pk = sk.public_key();
        let msg = b"test message";
        let sig = sk.sign(msg);
        assert!(sig.verify(&pk, msg).is_ok());
    }

    // ---- Error Display ----

    #[test]
    fn test_error_display() {
        let e = Eip2333Error::InvalidSeedLength(16);
        assert_eq!(e.to_string(), "Invalid seed length: expected >= 32 bytes, got 16");

        let e = Eip2333Error::InvalidPath("bad".to_string());
        assert_eq!(e.to_string(), "Invalid derivation path: bad");

        let e = Eip2333Error::HkdfError("expand failed".to_string());
        assert_eq!(e.to_string(), "HKDF expand failed: expand failed");
    }
}
