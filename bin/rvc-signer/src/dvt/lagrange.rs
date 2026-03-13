use thiserror::Error;

#[cfg(feature = "dvt")]
use bls12_381_plus::Scalar;

#[derive(Error, Debug)]
pub enum LagrangeError {
    #[error("duplicate index found: {0}")]
    DuplicateIndex(u64),

    #[error("empty partials list")]
    EmptyPartials,

    #[error("invalid partial signature at index {0}")]
    InvalidPartialSignature(u64),

    #[error("combined signature verification failed")]
    VerificationFailed,
}

/// Compute the Lagrange coefficient λ_i for participant x_i given participant indices.
///
/// λ_i = ∏(j≠i) x_j / (x_j - x_i) computed in the BLS12-381 scalar field (Fr).
#[cfg(feature = "dvt")]
pub fn lagrange_coefficient(x_i: u64, indices: &[u64]) -> Result<Scalar, LagrangeError> {
    let mut result = Scalar::ONE;

    for &x_j in indices {
        if x_j == x_i {
            continue;
        }

        let num = Scalar::from(x_j);
        let x_j_scalar = Scalar::from(x_j);
        let x_i_scalar = Scalar::from(x_i);
        let denom = x_j_scalar - x_i_scalar;

        let denom_inv: Scalar =
            Option::from(denom.invert()).ok_or(LagrangeError::DuplicateIndex(x_i))?;

        result *= num * denom_inv;
    }

    Ok(result)
}

/// Combine partial BLS signatures using Lagrange interpolation.
///
/// Each partial is a (share_index, 96-byte compressed G2 signature).
/// The share indices must match the x-coordinates used during Shamir secret sharing.
///
/// Uses low-level blst FFI for P2 point operations:
/// - Decompress partial signatures to affine P2 points
/// - Convert to projective coordinates for scalar multiplication
/// - Accumulate λ_i · σ_i in projective space
/// - Compress the result back to 96 bytes
#[cfg(feature = "dvt")]
pub fn combine_partial_signatures(partials: &[(u64, [u8; 96])]) -> Result<[u8; 96], LagrangeError> {
    if partials.is_empty() {
        return Err(LagrangeError::EmptyPartials);
    }

    // Check for duplicate indices
    let indices: Vec<u64> = partials.iter().map(|(idx, _)| *idx).collect();
    for i in 0..indices.len() {
        for j in (i + 1)..indices.len() {
            if indices[i] == indices[j] {
                return Err(LagrangeError::DuplicateIndex(indices[i]));
            }
        }
    }

    use blst::{
        blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_affine_compress,
        blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress, blst_scalar,
        blst_scalar_from_bendian, BLST_ERROR,
    };

    let mut accumulator = blst_p2::default();
    let mut first = true;

    for &(idx, ref sig_bytes) in partials {
        // Compute Lagrange coefficient for this index
        let coeff = lagrange_coefficient(idx, &indices)?;
        let coeff_be = coeff.to_be_bytes();

        // Decompress the partial signature (96 bytes → blst_p2_affine)
        let mut sig_affine = blst_p2_affine::default();
        let err = unsafe { blst_p2_uncompress(&mut sig_affine, sig_bytes.as_ptr()) };
        if err != BLST_ERROR::BLST_SUCCESS {
            return Err(LagrangeError::InvalidPartialSignature(idx));
        }

        // Convert affine → projective for scalar multiplication
        let mut sig_proj = blst_p2::default();
        unsafe { blst_p2_from_affine(&mut sig_proj, &sig_affine) };

        // Convert Lagrange coefficient to blst scalar (big-endian)
        let mut blst_coeff = blst_scalar::default();
        unsafe { blst_scalar_from_bendian(&mut blst_coeff, coeff_be.as_ptr()) };

        // Scalar multiply: λ_i · σ_i
        let mut scaled = blst_p2::default();
        unsafe { blst_p2_mult(&mut scaled, &sig_proj, blst_coeff.b.as_ptr(), 256) };

        // Accumulate
        if first {
            accumulator = scaled;
            first = false;
        } else {
            let mut sum = blst_p2::default();
            unsafe { blst_p2_add_or_double(&mut sum, &accumulator, &scaled) };
            accumulator = sum;
        }
    }

    // Convert result back to compressed 96-byte signature
    let mut result_affine = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut result_affine, &accumulator) };

    let mut result_bytes = [0u8; 96];
    unsafe { blst_p2_affine_compress(result_bytes.as_mut_ptr(), &result_affine) };

    Ok(result_bytes)
}

/// Verify a combined BLS signature against a public key and message.
#[cfg(feature = "dvt")]
pub fn verify_combined_signature(
    sig_bytes: &[u8; 96],
    pubkey_bytes: &[u8; 48],
    message: &[u8],
) -> Result<(), LagrangeError> {
    let sig =
        crypto::Signature::from_bytes(sig_bytes).map_err(|_| LagrangeError::VerificationFailed)?;
    let pk = crypto::PublicKey::from_bytes(pubkey_bytes)
        .map_err(|_| LagrangeError::VerificationFailed)?;
    sig.verify(&pk, message).map_err(|_| LagrangeError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dvt")]
    mod dvt_tests {
        use super::*;
        use bls12_381_plus::Scalar;
        use rand::rngs::OsRng;
        use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField};

        use crate::dvt::bridge::blst_sk_to_scalar;

        type BlsShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

        /// Helper: split a secret key into Shamir shares and return share indices + scalar bytes
        fn split_key(
            sk: &crypto::SecretKey,
            threshold: usize,
            total: usize,
        ) -> Vec<(u64, [u8; 32])> {
            let blst_sk = blst::min_pk::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
            let secret = blst_sk_to_scalar(&blst_sk).unwrap();

            let shares: Vec<BlsShare> = shamir::split_secret::<BlsShare>(
                threshold,
                total,
                &IdentifierPrimeField(secret),
                OsRng,
            )
            .unwrap();

            shares
                .iter()
                .map(|share| {
                    use vsss_rs::Share;
                    let idx_field: &IdentifierPrimeField<Scalar> = share.identifier();
                    let val_field: &IdentifierPrimeField<Scalar> = share.value();
                    let idx_bytes = idx_field.0.to_be_bytes();
                    let idx = u64::from_be_bytes(idx_bytes[24..32].try_into().unwrap());
                    let val_bytes = val_field.0.to_be_bytes();
                    (idx, val_bytes)
                })
                .collect()
        }

        /// Helper: sign a message with a share's scalar bytes
        fn partial_sign(scalar_bytes: &[u8; 32], message: &[u8]) -> [u8; 96] {
            let sk = blst::min_pk::SecretKey::from_bytes(scalar_bytes).unwrap();
            let blst_sig = sk.sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);
            blst_sig.to_bytes()
        }

        #[test]
        fn test_lagrange_coefficient_two_of_three() {
            // For indices {1, 2} evaluating at x=0:
            // λ_1 = 2/(2-1) = 2
            // λ_2 = 1/(1-2) = -1
            let indices = [1u64, 2];
            let l1 = lagrange_coefficient(1, &indices).unwrap();
            let l2 = lagrange_coefficient(2, &indices).unwrap();

            let expected_l1 = Scalar::from(2u64);
            assert_eq!(l1, expected_l1);

            let expected_l2 = -Scalar::ONE;
            assert_eq!(l2, expected_l2);
        }

        #[test]
        fn test_lagrange_coefficient_three_of_five() {
            // For indices {1, 3, 5}:
            // λ_1 = (3*5)/((3-1)*(5-1)) = 15/8
            let indices = [1u64, 3, 5];
            let l1 = lagrange_coefficient(1, &indices).unwrap();

            let fifteen = Scalar::from(15u64);
            let eight_inv: Scalar = Option::from(Scalar::from(8u64).invert()).unwrap();
            let expected = fifteen * eight_inv;
            assert_eq!(l1, expected);
        }

        #[test]
        fn test_lagrange_coefficient_duplicate_detected_in_combine() {
            let result = combine_partial_signatures(&[(1, [0u8; 96]), (1, [0u8; 96])]);
            assert!(matches!(result, Err(LagrangeError::DuplicateIndex(1))));
        }

        #[test]
        fn test_lagrange_coefficient_single_participant() {
            let indices = [1u64];
            let l1 = lagrange_coefficient(1, &indices).unwrap();
            assert_eq!(l1, Scalar::ONE);
        }

        #[test]
        fn test_combine_empty_partials() {
            let result = combine_partial_signatures(&[]);
            assert!(matches!(result, Err(LagrangeError::EmptyPartials)));
        }

        #[test]
        fn test_combine_invalid_signature_bytes() {
            let result = combine_partial_signatures(&[(1, [0u8; 96])]);
            assert!(matches!(result, Err(LagrangeError::InvalidPartialSignature(1))));
        }

        #[test]
        fn test_roundtrip_2_of_3() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key();
            let message = b"test 2-of-3 lagrange";

            let direct_sig = sk.sign(message);
            let shares = split_key(&sk, 2, 3);

            let partials: Vec<(u64, [u8; 96])> = shares[..2]
                .iter()
                .map(|(idx, scalar)| (*idx, partial_sign(scalar, message)))
                .collect();

            let combined = combine_partial_signatures(&partials).unwrap();
            assert_eq!(combined, direct_sig.to_bytes());
            verify_combined_signature(&combined, &pk.to_bytes(), message).unwrap();
        }

        #[test]
        fn test_roundtrip_3_of_5() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key();
            let message = b"test 3-of-5 lagrange";

            let direct_sig = sk.sign(message);
            let shares = split_key(&sk, 3, 5);

            let partials: Vec<(u64, [u8; 96])> = [0, 2, 4]
                .iter()
                .map(|&i| (shares[i].0, partial_sign(&shares[i].1, message)))
                .collect();

            let combined = combine_partial_signatures(&partials).unwrap();
            assert_eq!(combined, direct_sig.to_bytes());
            verify_combined_signature(&combined, &pk.to_bytes(), message).unwrap();
        }

        #[test]
        fn test_roundtrip_2_of_2() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key();
            let message = b"test 2-of-2 lagrange";

            let direct_sig = sk.sign(message);
            let shares = split_key(&sk, 2, 2);

            let partials: Vec<(u64, [u8; 96])> =
                shares.iter().map(|(idx, scalar)| (*idx, partial_sign(scalar, message))).collect();

            let combined = combine_partial_signatures(&partials).unwrap();
            assert_eq!(combined, direct_sig.to_bytes());
            verify_combined_signature(&combined, &pk.to_bytes(), message).unwrap();
        }

        #[test]
        fn test_insufficient_shares_does_not_verify() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key();
            let message = b"test insufficient";

            let shares = split_key(&sk, 3, 5);

            // Only 2 shares (threshold is 3)
            let partials: Vec<(u64, [u8; 96])> = shares[..2]
                .iter()
                .map(|(idx, scalar)| (*idx, partial_sign(scalar, message)))
                .collect();

            let combined = combine_partial_signatures(&partials).unwrap();
            let result = verify_combined_signature(&combined, &pk.to_bytes(), message);
            assert!(result.is_err());
        }

        #[test]
        fn test_any_threshold_subset_produces_same_signature() {
            let sk = crypto::SecretKey::generate();
            let message = b"any subset test";
            let direct_sig = sk.sign(message);

            let shares = split_key(&sk, 2, 3);

            let subsets: Vec<Vec<usize>> = vec![vec![0, 1], vec![0, 2], vec![1, 2]];

            for subset_idx in &subsets {
                let partials: Vec<(u64, [u8; 96])> = subset_idx
                    .iter()
                    .map(|&i| (shares[i].0, partial_sign(&shares[i].1, message)))
                    .collect();

                let combined = combine_partial_signatures(&partials).unwrap();
                assert_eq!(
                    combined,
                    direct_sig.to_bytes(),
                    "subset {:?} should produce same signature",
                    subset_idx
                );
            }
        }

        #[test]
        fn test_verify_combined_signature_wrong_message() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key();
            let message = b"correct message";
            let wrong_message = b"wrong message";

            let shares = split_key(&sk, 2, 3);

            let partials: Vec<(u64, [u8; 96])> = shares[..2]
                .iter()
                .map(|(idx, scalar)| (*idx, partial_sign(scalar, message)))
                .collect();

            let combined = combine_partial_signatures(&partials).unwrap();
            let result = verify_combined_signature(&combined, &pk.to_bytes(), wrong_message);
            assert!(result.is_err());
        }

        #[test]
        fn test_verify_combined_signature_wrong_pubkey() {
            let sk = crypto::SecretKey::generate();
            let wrong_pk = crypto::SecretKey::generate().public_key();
            let message = b"wrong pubkey test";

            let shares = split_key(&sk, 2, 3);

            let partials: Vec<(u64, [u8; 96])> = shares[..2]
                .iter()
                .map(|(idx, scalar)| (*idx, partial_sign(scalar, message)))
                .collect();

            let combined = combine_partial_signatures(&partials).unwrap();
            let result = verify_combined_signature(&combined, &wrong_pk.to_bytes(), message);
            assert!(result.is_err());
        }

        #[test]
        fn test_duplicate_indices_in_combine() {
            let sk = crypto::SecretKey::generate();
            let message = b"duplicate test";

            let shares = split_key(&sk, 2, 3);
            let sig = partial_sign(&shares[0].1, message);

            let partials = vec![(shares[0].0, sig), (shares[0].0, sig)];
            let result = combine_partial_signatures(&partials);
            assert!(matches!(result, Err(LagrangeError::DuplicateIndex(_))));
        }

        #[test]
        fn test_roundtrip_different_messages() {
            let sk = crypto::SecretKey::generate();
            let pk = sk.public_key();
            let shares = split_key(&sk, 2, 3);

            for msg in [b"msg1".as_slice(), b"msg2", b"msg3", b""] {
                let direct_sig = sk.sign(msg);
                let partials: Vec<(u64, [u8; 96])> = shares[..2]
                    .iter()
                    .map(|(idx, scalar)| (*idx, partial_sign(scalar, msg)))
                    .collect();

                let combined = combine_partial_signatures(&partials).unwrap();
                assert_eq!(combined, direct_sig.to_bytes());
                verify_combined_signature(&combined, &pk.to_bytes(), msg).unwrap();
            }
        }
    }
}
