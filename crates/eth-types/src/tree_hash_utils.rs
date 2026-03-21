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

pub(crate) fn bitlist_tree_hash_root(bytes: &[u8]) -> Result<Hash256, TreeHashError> {
    if bytes.is_empty() {
        return Ok(mix_in_length(&Hash256::ZERO, 0));
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

    let root = vec_u8_tree_hash_root(&clean_bytes);
    Ok(mix_in_length(&root, bit_length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitlist_tree_hash_empty() {
        let result = bitlist_tree_hash_root(&[]).unwrap();
        let expected = mix_in_length(&Hash256::ZERO, 0);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bitlist_tree_hash_known_vector() {
        let ssz_bytes = vec![0x0d];
        let root = bitlist_tree_hash_root(&ssz_bytes).unwrap();

        let inner_root = vec_u8_tree_hash_root(&[0x05]);
        let expected = mix_in_length(&inner_root, 3);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_bitlist_different_lengths_different_roots() {
        let root_3bits = bitlist_tree_hash_root(&[0x0d]).unwrap();
        let root_5bits = bitlist_tree_hash_root(&[0x25]).unwrap();
        assert_ne!(root_3bits, root_5bits);
    }

    #[test]
    fn test_vec_u8_tree_hash_root_unchanged_for_bitvector() {
        let bytes = vec![0x01; 8];
        let root1 = vec_u8_tree_hash_root(&bytes);
        let root2 = vec_u8_tree_hash_root(&bytes);
        assert_eq!(root1, root2);

        let bitlist_root = bitlist_tree_hash_root(&bytes).unwrap();
        assert_ne!(root1, bitlist_root);
    }

    #[test]
    fn test_bitlist_tree_hash_returns_err_on_zero_last_byte() {
        let result = bitlist_tree_hash_root(&[0x00]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("missing sentinel bit"));
    }

    #[test]
    fn test_bitlist_tree_hash_returns_err_on_trailing_zero() {
        let result = bitlist_tree_hash_root(&[0xff, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitlist_sentinel_only() {
        let root = bitlist_tree_hash_root(&[0x01]).unwrap();
        let inner_root = vec_u8_tree_hash_root(&[0x00]);
        let expected = mix_in_length(&inner_root, 0);
        assert_eq!(root, expected);
    }
}
