use bls12_381_plus::Scalar;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("invalid scalar bytes: not a valid field element")]
    InvalidScalar,

    #[error("invalid blst secret key bytes")]
    InvalidBlstKey,
}

/// Convert a blst SecretKey to a bls12_381_plus Scalar.
///
/// blst serializes secret keys as big-endian 32-byte arrays.
/// bls12_381_plus Scalar has `from_be_bytes` which expects the same format.
pub fn blst_sk_to_scalar(sk: &blst::min_pk::SecretKey) -> Result<Scalar, BridgeError> {
    let bytes = sk.to_bytes();
    Option::from(Scalar::from_be_bytes(&bytes)).ok_or(BridgeError::InvalidScalar)
}

/// Convert a bls12_381_plus Scalar back to a blst SecretKey.
///
/// Outputs big-endian bytes matching blst's expected input format.
pub fn scalar_to_blst_sk(scalar: &Scalar) -> Result<blst::min_pk::SecretKey, BridgeError> {
    let bytes = scalar.to_be_bytes();
    blst::min_pk::SecretKey::from_bytes(&bytes).map_err(|_| BridgeError::InvalidBlstKey)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;

    #[test]
    fn test_blst_sk_to_scalar_roundtrip() {
        let sk = crypto::SecretKey::generate();
        let blst_bytes = sk.to_bytes();

        let blst_sk = blst::min_pk::SecretKey::from_bytes(&blst_bytes).unwrap();
        let scalar = blst_sk_to_scalar(&blst_sk).expect("conversion should succeed");
        let roundtripped = scalar_to_blst_sk(&scalar).expect("round-trip should succeed");

        assert_eq!(blst_bytes, roundtripped.to_bytes());
    }

    #[test]
    fn test_scalar_to_blst_sk_roundtrip() {
        let sk = crypto::SecretKey::generate();
        let original_bytes = sk.to_bytes();

        let blst_sk = blst::min_pk::SecretKey::from_bytes(&original_bytes).unwrap();
        let scalar = blst_sk_to_scalar(&blst_sk).unwrap();
        let recovered = scalar_to_blst_sk(&scalar).unwrap();

        assert_eq!(original_bytes, recovered.to_bytes());
    }

    #[test]
    fn test_converted_scalar_signs_same() {
        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key();
        let message = b"test message for bridge";

        let sig = sk.sign(message);
        assert!(sig.verify(&pk, message).is_ok());

        let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
        let scalar = blst_sk_to_scalar(&blst_sk).unwrap();
        let recovered_sk = scalar_to_blst_sk(&scalar).unwrap();
        let recovered = crypto::SecretKey::from_bytes(&recovered_sk.to_bytes()).unwrap();

        let sig2 = recovered.sign(message);
        assert!(sig2.verify(&pk, message).is_ok());
        assert_eq!(sig.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_zero_scalar_rejected_by_blst() {
        let zero = Scalar::ZERO;
        let result = scalar_to_blst_sk(&zero);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_keys_roundtrip() {
        for _ in 0..20 {
            let sk = crypto::SecretKey::generate();
            let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
            let scalar = blst_sk_to_scalar(&blst_sk).unwrap();
            let recovered = scalar_to_blst_sk(&scalar).unwrap();
            assert_eq!(sk.to_bytes(), recovered.to_bytes());
        }
    }

    #[test]
    fn test_split_reconstruct_via_vsss() {
        use rand::rngs::OsRng;
        use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField, ReadableShareSet};

        type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key();
        let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
        let secret_scalar = blst_sk_to_scalar(&blst_sk).unwrap();

        // Split into 3 shares, threshold 2
        let shares: Vec<BlsShare> =
            shamir::split_secret::<BlsShare>(2, 3, &IdentifierPrimeField(secret_scalar), OsRng)
                .expect("split should succeed");

        assert_eq!(shares.len(), 3);

        // Reconstruct from first 2 shares (threshold)
        let subset: Vec<BlsShare> = shares[..2].to_vec();
        let reconstructed: IdentifierPrimeField<Scalar> =
            subset.combine().expect("combine should succeed");
        let recovered_scalar = reconstructed.0;

        // Convert back to blst and verify
        let recovered_blst = scalar_to_blst_sk(&recovered_scalar).unwrap();
        let recovered_sk = crypto::SecretKey::from_bytes(&recovered_blst.to_bytes()).unwrap();
        assert_eq!(recovered_sk.public_key().to_bytes(), pk.to_bytes());

        // Verify signature with recovered key
        let msg = b"shamir test";
        let sig = recovered_sk.sign(msg);
        assert!(sig.verify(&pk, msg).is_ok());
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_roundtrip_any_key(seed in any::<[u8; 32]>()) {
                // Use the seed to generate a deterministic key
                let blst_sk = match blst::min_pk::SecretKey::key_gen(&seed, &[]) {
                    Ok(sk) => sk,
                    Err(_) => return Ok(()),
                };
                let scalar = blst_sk_to_scalar(&blst_sk).unwrap();
                let recovered = scalar_to_blst_sk(&scalar).unwrap();
                prop_assert_eq!(blst_sk.to_bytes(), recovered.to_bytes());
            }

            #[test]
            fn prop_t_of_n_reconstructs(
                t in 2u64..6,
                extra in 0u64..4,
                seed in any::<[u8; 32]>(),
            ) {
                use rand::rngs::OsRng;
                use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField, ReadableShareSet};

                type BlsShare = DefaultShare<
                    IdentifierPrimeField<Scalar>,
                    IdentifierPrimeField<Scalar>,
                >;

                let n = t + extra;
                if n > 255 || t < 2 {
                    return Ok(());
                }

                let blst_sk = match blst::min_pk::SecretKey::key_gen(&seed, &[]) {
                    Ok(sk) => sk,
                    Err(_) => return Ok(()),
                };
                let secret = blst_sk_to_scalar(&blst_sk).unwrap();

                let shares: Vec<BlsShare> = shamir::split_secret::<BlsShare>(
                    t as usize,
                    n as usize,
                    &IdentifierPrimeField(secret),
                    OsRng,
                )
                .expect("split should succeed");

                // Take exactly t shares
                let subset: Vec<BlsShare> = shares[..t as usize].to_vec();
                let reconstructed: IdentifierPrimeField<Scalar> =
                    subset.combine().expect("combine should succeed");

                let recovered = scalar_to_blst_sk(&reconstructed.0).unwrap();
                prop_assert_eq!(blst_sk.to_bytes(), recovered.to_bytes());
            }
        }
    }

    #[test]
    fn test_any_threshold_subset_reconstructs() {
        use rand::rngs::OsRng;
        use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField, ReadableShareSet};

        type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

        let sk = crypto::SecretKey::generate();
        let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
        let secret_scalar = blst_sk_to_scalar(&blst_sk).unwrap();

        // 3-of-5 split
        let shares: Vec<BlsShare> =
            shamir::split_secret::<BlsShare>(3, 5, &IdentifierPrimeField(secret_scalar), OsRng)
                .expect("split should succeed");

        // Try all 3-element subsets (10 subsets for 5 choose 3)
        let indices: Vec<Vec<usize>> = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for subset_idx in &indices {
            let subset: Vec<BlsShare> = subset_idx.iter().map(|&i| shares[i]).collect();
            let reconstructed: IdentifierPrimeField<Scalar> =
                subset.combine().expect("combine should succeed");
            let recovered_blst = scalar_to_blst_sk(&reconstructed.0).unwrap();
            assert_eq!(
                sk.to_bytes(),
                recovered_blst.to_bytes(),
                "subset {:?} should reconstruct the same key",
                subset_idx
            );
        }
    }
}
