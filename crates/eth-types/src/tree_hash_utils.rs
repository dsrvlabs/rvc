use tree_hash::{mix_in_length, Hash256, MerkleHasher};

pub(crate) fn vec_u8_tree_hash_root(bytes: &[u8]) -> Hash256 {
    let num_leaves = bytes.len().div_ceil(32);
    let mut hasher = MerkleHasher::with_leaves(num_leaves.max(1));
    hasher.write(bytes).expect("valid bytes");
    hasher.finish().expect("valid root")
}

pub(crate) fn bitlist_tree_hash_root(bytes: &[u8]) -> Hash256 {
    if bytes.is_empty() {
        return mix_in_length(&Hash256::ZERO, 0);
    }

    let last_byte = *bytes.last().expect("non-empty");
    assert!(last_byte != 0, "SSZ bitlist must have a sentinel bit in the last byte");

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
    mix_in_length(&root, bit_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitlist_tree_hash_empty() {
        let result = bitlist_tree_hash_root(&[]);
        let expected = mix_in_length(&Hash256::ZERO, 0);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bitlist_tree_hash_known_vector() {
        // Bitlist [1,0,1] (3 bits) has SSZ encoding [0x0d]:
        // bits: 1,0,1 + sentinel = 1101 = 0x0d
        // Strip sentinel -> 0x05, bit_length = 3
        let ssz_bytes = vec![0x0d];
        let root = bitlist_tree_hash_root(&ssz_bytes);

        // Manually compute: merkleize([0x05]) then mix_in_length(_, 3)
        let inner_root = vec_u8_tree_hash_root(&[0x05]);
        let expected = mix_in_length(&inner_root, 3);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_bitlist_different_lengths_different_roots() {
        // Bitlist [1,0,1] (3 bits): SSZ = [0x0d]
        let root_3bits = bitlist_tree_hash_root(&[0x0d]);
        // Bitlist [1,0,1,0,0] (5 bits): SSZ = [0x25]
        // bits: 1,0,1,0,0 + sentinel = 00100101 = 0x25
        let root_5bits = bitlist_tree_hash_root(&[0x25]);
        assert_ne!(root_3bits, root_5bits);
    }

    #[test]
    fn test_vec_u8_tree_hash_root_unchanged_for_bitvector() {
        // Bitvector-style input: no sentinel, no mix_in_length
        let bytes = vec![0x01; 8];
        let root1 = vec_u8_tree_hash_root(&bytes);
        let root2 = vec_u8_tree_hash_root(&bytes);
        assert_eq!(root1, root2);

        // Confirm it does NOT equal bitlist_tree_hash_root
        // (which would add mix_in_length)
        let bitlist_root = bitlist_tree_hash_root(&bytes);
        assert_ne!(root1, bitlist_root);
    }

    #[test]
    #[should_panic(expected = "SSZ bitlist must have a sentinel bit")]
    fn test_bitlist_tree_hash_panics_on_zero_last_byte() {
        bitlist_tree_hash_root(&[0x00]);
    }

    #[test]
    fn test_bitlist_sentinel_only() {
        // Bitlist with 0 data bits: just the sentinel [0x01]
        let root = bitlist_tree_hash_root(&[0x01]);
        let inner_root = vec_u8_tree_hash_root(&[0x00]);
        let expected = mix_in_length(&inner_root, 0);
        assert_eq!(root, expected);
    }
}
