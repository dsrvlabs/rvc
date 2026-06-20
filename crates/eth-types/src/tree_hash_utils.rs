use tree_hash::{mix_in_length, Hash256, MerkleHasher};

#[derive(Debug, thiserror::Error)]
pub enum TreeHashError {
    #[error("invalid SSZ bitlist: {reason}")]
    InvalidBitlist { reason: String },
}

pub(crate) fn vec_u8_tree_hash_root(bytes: &[u8]) -> Hash256 {
    let num_leaves = bytes.len().div_ceil(32);
    let mut hasher = MerkleHasher::with_leaves(num_leaves.max(1));
    hasher.write(bytes).expect("valid bytes");
    hasher.finish().expect("valid root")
}

/// Number of 32-byte chunks an SSZ `Bitlist[N]` is merkleized over:
/// `chunk_count(Bitlist[N]) = ceil(N / 256)` (256 bits pack into one 32-byte chunk).
fn bitlist_chunk_count(max_bits: u64) -> usize {
    (max_bits.div_ceil(256) as usize).max(1)
}

/// Merkleize `clean_bytes` (the sentinel-stripped, packed bits) over a chunk tree padded to
/// `chunk_count` leaves, matching SSZ `merkleize(pack_bits(value), limit = chunk_count(Bitlist[N]))`.
///
/// `MerkleHasher::with_leaves(chunk_count)` rounds the leaf count up to the next power of two and
/// zero-pads any unwritten leaves in `finish()`, which is exactly the SSZ merkleize-with-limit rule.
///
/// Returns `Err` if `clean_bytes` overflows the chunk tree. Callers MUST length-validate against
/// the `Bitlist[N]` limit first (see `bitlist_tree_hash_root`); a within-limit bitlist always fits.
fn merkleize_to_chunk_count(
    clean_bytes: &[u8],
    chunk_count: usize,
) -> Result<Hash256, TreeHashError> {
    let mut hasher = MerkleHasher::with_leaves(chunk_count);
    if !clean_bytes.is_empty() {
        hasher.write(clean_bytes).map_err(|e| TreeHashError::InvalidBitlist {
            reason: format!("bitlist data overflows chunk tree: {e:?}"),
        })?;
    }
    hasher.finish().map_err(|e| TreeHashError::InvalidBitlist {
        reason: format!("bitlist merkleization failed: {e:?}"),
    })
}

/// Maximum SSZ-encoded byte length of a `Bitlist[max_bits]`: up to `max_bits` data bits plus one
/// sentinel bit, i.e. `ceil((max_bits + 1) / 8) = max_bits / 8 + 1` bytes (the +1 holds the
/// sentinel, which sits in a fresh byte only when `max_bits` is a multiple of 8 — the realistic case).
fn bitlist_max_ssz_len(max_bits: u64) -> usize {
    (max_bits / 8 + 1) as usize
}

/// Tree-hash an SSZ `Bitlist[max_bits]` from its raw SSZ encoding (data bits + sentinel bit).
///
/// `hash_tree_root(Bitlist[N]) = mix_in_length(merkleize(pack_bits(value), chunk_count(N)), len)`.
/// The chunk tree MUST be padded to `chunk_count(N) = ceil(N / 256)` leaves before mixing in the
/// length; sizing it to only the populated data chunks yields a spec-divergent root.
///
/// Rejects an input longer than a `Bitlist[max_bits]` can encode with `Err`: such input is invalid
/// (an attacker-influenced over-length `aggregation_bits` from the beacon node would otherwise
/// overflow the fixed chunk tree and panic the signing path).
pub(crate) fn bitlist_tree_hash_root(
    bytes: &[u8],
    max_bits: u64,
) -> Result<Hash256, TreeHashError> {
    let chunk_count = bitlist_chunk_count(max_bits);

    let max_len = bitlist_max_ssz_len(max_bits);
    if bytes.len() > max_len {
        return Err(TreeHashError::InvalidBitlist {
            reason: format!(
                "bitlist length {} bytes exceeds Bitlist[{}] limit of {} bytes",
                bytes.len(),
                max_bits,
                max_len
            ),
        });
    }

    if bytes.is_empty() {
        let root = merkleize_to_chunk_count(&[], chunk_count)?;
        return Ok(mix_in_length(&root, 0));
    }

    let last_byte = *bytes.last().expect("non-empty");
    if last_byte == 0 {
        return Err(TreeHashError::InvalidBitlist {
            reason: "last byte is zero, missing sentinel bit".to_string(),
        });
    }

    let sentinel_bit_pos = 7 - last_byte.leading_zeros() as usize;
    let bit_length = (bytes.len() - 1) * 8 + sentinel_bit_pos;

    let mut clean_bytes = bytes.to_vec();
    let last_idx = clean_bytes.len() - 1;
    clean_bytes[last_idx] &= !(1u8 << sentinel_bit_pos);

    // Remove trailing zero byte if sentinel was the only bit in last byte
    if clean_bytes[last_idx] == 0 && clean_bytes.len() > 1 {
        clean_bytes.truncate(last_idx);
    }

    let root = merkleize_to_chunk_count(&clean_bytes, chunk_count)?;
    Ok(mix_in_length(&root, bit_length))
}

#[cfg(test)]
mod tests {
    use super::*;

    // SSZ `Bitlist[N]` limits used for the known-answer vectors below.
    //   PRE_ELECTRA = MAX_VALIDATORS_PER_COMMITTEE = 2048   -> chunk_count = ceil(2048/256)   = 8
    //   ELECTRA     = 2048 * MAX_COMMITTEES_PER_SLOT = 131072 -> chunk_count = ceil(131072/256) = 512
    const PRE_ELECTRA_LIMIT: u64 = 2048;
    const ELECTRA_LIMIT: u64 = 2048 * 64;

    fn hex32(s: &str) -> Hash256 {
        Hash256::from_slice(&hex::decode(s.trim_start_matches("0x")).expect("hex"))
    }

    #[test]
    fn test_bitlist_chunk_count_matches_spec() {
        // chunk_count(Bitlist[N]) = ceil(N / 256)
        assert_eq!(bitlist_chunk_count(PRE_ELECTRA_LIMIT), 8);
        assert_eq!(bitlist_chunk_count(ELECTRA_LIMIT), 512);
        assert_eq!(bitlist_chunk_count(0), 1);
        assert_eq!(bitlist_chunk_count(1), 1);
        assert_eq!(bitlist_chunk_count(256), 1);
        assert_eq!(bitlist_chunk_count(257), 2);
    }

    // Known-answer vectors derived from an INDEPENDENT consensus-spec oracle (`remerkleable`),
    // modelling `Bitlist[N]` with the explicit limit N. These are NOT recomputed from rvc's own
    // helpers; they pin rvc's output to the external SSZ spec.
    //   remerkleable: Bitlist[N](*bits).hash_tree_root(); bits decoded from the SSZ encoding below.

    #[test]
    fn test_bitlist_tree_hash_empty_pre_electra() {
        // Empty Bitlist[2048] (SSZ 0x01 / len 0): all-zero tree of 8 chunks, mix_in_length(_, 0).
        let root = bitlist_tree_hash_root(&[], PRE_ELECTRA_LIMIT).unwrap();
        assert_eq!(
            root,
            hex32("0xe8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6"),
        );
    }

    #[test]
    fn test_bitlist_tree_hash_empty_electra() {
        // Empty Bitlist[131072]: all-zero tree of 512 chunks (depth 9), mix_in_length(_, 0).
        // Differs from the pre-Electra empty root precisely because the chunk_count limit differs.
        let root = bitlist_tree_hash_root(&[], ELECTRA_LIMIT).unwrap();
        assert_eq!(
            root,
            hex32("0x8d88050ac84001d0796fc9de86de5768a435c21150ee647c28e02118ef69cd8e"),
        );
    }

    #[test]
    fn test_bitlist_tree_hash_known_vector_pre_electra() {
        // SSZ 0x0d -> data bits [1,0,1] (len 3). remerkleable Bitlist[2048].
        let root = bitlist_tree_hash_root(&[0x0d], PRE_ELECTRA_LIMIT).unwrap();
        assert_eq!(
            root,
            hex32("0x8e67833502313f86bb672bbf94fd3904995a799dd856005e75d69e5e93be0433"),
        );
    }

    #[test]
    fn test_bitlist_tree_hash_known_vector_electra() {
        // Same 3-bit value under the Electra limit (chunk_count 512). remerkleable Bitlist[131072].
        let root = bitlist_tree_hash_root(&[0x0d], ELECTRA_LIMIT).unwrap();
        assert_eq!(
            root,
            hex32("0x168377853ab4adf4be6dd5589a8953cc6f347a3fe807f16dc3bbd777c0c9023d"),
        );
    }

    #[test]
    fn test_bitlist_tree_hash_five_bits_pre_electra() {
        // SSZ 0x25 -> data bits of 0x05 = [1,0,1,0,0] (len 5). remerkleable Bitlist[2048].
        let root = bitlist_tree_hash_root(&[0x25], PRE_ELECTRA_LIMIT).unwrap();
        assert_eq!(
            root,
            hex32("0x44b6726e4b6ff83b78451d8e3d7cce7097de1e73bd4cda7eca933d75074981d9"),
        );
    }

    #[test]
    fn test_bitlist_tree_hash_multibyte_pre_electra() {
        // SSZ [0x01;8] as a Bitlist[2048]: last byte 0x01 -> sentinel at pos 0 -> len 56,
        // data bits set at indices 0,8,16,24,32,40,48. remerkleable Bitlist[2048].
        let root = bitlist_tree_hash_root(&[0x01; 8], PRE_ELECTRA_LIMIT).unwrap();
        assert_eq!(
            root,
            hex32("0x9323c3726e122b978183f102ebb97d8f9439e52a9b584be031503dd891f26486"),
        );
    }

    #[test]
    fn test_bitlist_different_lengths_different_roots() {
        let root_3bits = bitlist_tree_hash_root(&[0x0d], PRE_ELECTRA_LIMIT).unwrap();
        let root_5bits = bitlist_tree_hash_root(&[0x25], PRE_ELECTRA_LIMIT).unwrap();
        assert_ne!(root_3bits, root_5bits);
    }

    #[test]
    fn test_bitlist_limit_changes_root() {
        // The same SSZ bits hash to different roots under different `Bitlist[N]` limits, because
        // the chunk tree is padded to a different chunk_count. This is the bug this fix closes.
        let pre = bitlist_tree_hash_root(&[0x0d], PRE_ELECTRA_LIMIT).unwrap();
        let electra = bitlist_tree_hash_root(&[0x0d], ELECTRA_LIMIT).unwrap();
        assert_ne!(pre, electra);
    }

    #[test]
    fn test_vec_u8_tree_hash_root_unchanged_for_bitvector() {
        let bytes = vec![0x01; 8];
        let root1 = vec_u8_tree_hash_root(&bytes);
        let root2 = vec_u8_tree_hash_root(&bytes);
        assert_eq!(root1, root2);

        let bitlist_root = bitlist_tree_hash_root(&bytes, PRE_ELECTRA_LIMIT).unwrap();
        assert_ne!(root1, bitlist_root);
    }

    #[test]
    fn test_bitlist_tree_hash_returns_err_on_zero_last_byte() {
        let result = bitlist_tree_hash_root(&[0x00], PRE_ELECTRA_LIMIT);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("missing sentinel bit"));
    }

    #[test]
    fn test_bitlist_tree_hash_returns_err_on_trailing_zero() {
        let result = bitlist_tree_hash_root(&[0xff, 0x00], PRE_ELECTRA_LIMIT);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitlist_max_ssz_len_matches_spec() {
        // Bitlist[N] encodes <= N data bits + 1 sentinel => N/8 + 1 bytes (N a multiple of 8).
        assert_eq!(bitlist_max_ssz_len(PRE_ELECTRA_LIMIT), 257);
        assert_eq!(bitlist_max_ssz_len(ELECTRA_LIMIT), 16385);
    }

    #[test]
    fn test_bitlist_oversized_input_returns_err_not_panic() {
        // An over-length aggregation_bits (e.g. a hostile/buggy beacon node) must be rejected with
        // an error, NOT panic the signing path by overflowing the fixed chunk tree. Pre-Electra
        // rejects > 257 bytes; Electra > 16385 bytes.
        let too_long_pre = vec![0xff; 258];
        let err = bitlist_tree_hash_root(&too_long_pre, PRE_ELECTRA_LIMIT).unwrap_err();
        assert!(err.to_string().contains("exceeds Bitlist[2048] limit"), "got: {err}");

        let too_long_electra = vec![0xff; 16386];
        assert!(bitlist_tree_hash_root(&too_long_electra, ELECTRA_LIMIT).is_err());
    }

    #[test]
    fn test_bitlist_max_valid_length_succeeds() {
        // The largest VALID bitlist (all N data bits set, sentinel in a fresh byte) must still hash:
        // 257 bytes for Bitlist[2048] (256 data bytes + sentinel byte), 16385 for Bitlist[131072].
        let mut full_pre = vec![0xff; 257];
        full_pre[256] = 0x01; // sentinel just past the last data bit
        assert!(bitlist_tree_hash_root(&full_pre, PRE_ELECTRA_LIMIT).is_ok());

        let mut full_electra = vec![0xff; 16385];
        full_electra[16384] = 0x01;
        assert!(bitlist_tree_hash_root(&full_electra, ELECTRA_LIMIT).is_ok());
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn fuzz_bitlist_tree_hash_root_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                let _ = bitlist_tree_hash_root(&bytes, ELECTRA_LIMIT);
            }

            #[test]
            fn fuzz_vec_u8_tree_hash_root_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
                let _ = vec_u8_tree_hash_root(&bytes);
            }

            #[test]
            fn fuzz_bitlist_tree_hash_root_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
                let r1 = bitlist_tree_hash_root(&bytes, ELECTRA_LIMIT);
                let r2 = bitlist_tree_hash_root(&bytes, ELECTRA_LIMIT);
                prop_assert_eq!(r1.is_ok(), r2.is_ok());
                if let (Ok(a), Ok(b)) = (r1, r2) {
                    prop_assert_eq!(a, b);
                }
            }

            #[test]
            fn fuzz_valid_bitlist_has_nonzero_last_byte(
                prefix in proptest::collection::vec(any::<u8>(), 0..64),
                last_byte in 1u8..=255u8
            ) {
                let mut bytes = prefix;
                bytes.push(last_byte);
                let result = bitlist_tree_hash_root(&bytes, ELECTRA_LIMIT);
                prop_assert!(result.is_ok(), "valid bitlist (non-zero last byte) should succeed");
            }
        }
    }

    #[test]
    fn test_bitlist_sentinel_only() {
        // SSZ 0x01 -> empty bitlist (len 0). Identical to the empty-input root under the same limit.
        let root = bitlist_tree_hash_root(&[0x01], PRE_ELECTRA_LIMIT).unwrap();
        let empty = bitlist_tree_hash_root(&[], PRE_ELECTRA_LIMIT).unwrap();
        assert_eq!(root, empty);
        assert_eq!(
            root,
            hex32("0xe8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6"),
        );
    }
}
