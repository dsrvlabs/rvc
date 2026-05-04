use serde::{Deserialize, Serialize};
use tree_hash::{mix_in_length, Hash256, MerkleHasher, TreeHash, TreeHashType};

use crate::hex_fixed::bytes_32_hex;
use crate::tree_hash_utils::vec_u8_tree_hash_root;
use crate::{Root, Signature, Slot};

/// Fixed-portion length of a Deneb/Electra `BeaconBlockBody` SSZ encoding.
///
/// Layout (cumulative bytes):
/// - `randao_reveal`: 96 bytes (fixed)
/// - `eth1_data`: 72 bytes (fixed)
/// - `graffiti`: 32 bytes (fixed)
/// - 5 variable-field offsets × 4 bytes: 20 bytes
/// - `sync_aggregate`: 160 bytes (fixed)
/// - 3 variable-field offsets × 4 bytes: 12 bytes  (execution_payload,
///   bls_to_execution_changes, blob_kzg_commitments)
/// - **Total**: 392 bytes
const DENEB_BODY_FIXED_LEN: usize = 392;

/// Byte offset within the body fixed portion where the `blob_kzg_commitments`
/// variable-field offset is stored (bytes 388–391, u32 LE).
const KZG_COMMIT_OFFSET_POS: usize = 388;

/// Size of a single KZG commitment: BLS12-381 G1 compressed point (48 bytes).
const KZG_COMMITMENT_BYTES: usize = 48;

/// Extract blob KZG commitments from a raw SSZ-encoded `BeaconBlockBody`.
///
/// Returns the parsed list on success; returns an empty vector when the body is
/// shorter than the 392-byte Deneb fixed portion, the stored offset is out of
/// range, or the commitment region length is not a multiple of 48 bytes.
///
/// # Spec reference
///
/// Deneb `BeaconBlockBody` (EIP-4844): `blob_kzg_commitments` is field 12 of
/// the Container, with its SSZ offset recorded at bytes 388–391 of the fixed
/// portion. Each `KZGCommitment` is a `Bytes48` (48-byte BLS12-381 G1 point).
pub(crate) fn extract_blob_kzg_commitments(body: &[u8]) -> Vec<[u8; 48]> {
    if body.len() < DENEB_BODY_FIXED_LEN {
        return vec![];
    }

    let kzg_start = u32::from_le_bytes(
        body[KZG_COMMIT_OFFSET_POS..KZG_COMMIT_OFFSET_POS + 4]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    ) as usize;

    // The offset must point into the variable region.
    if kzg_start < DENEB_BODY_FIXED_LEN || kzg_start > body.len() {
        return vec![];
    }

    let kzg_bytes = &body[kzg_start..];
    if !kzg_bytes.len().is_multiple_of(KZG_COMMITMENT_BYTES) {
        return vec![];
    }

    kzg_bytes
        .chunks_exact(KZG_COMMITMENT_BYTES)
        .map(|chunk| chunk.try_into().expect("chunk is exactly 48 bytes"))
        .collect()
}

/// Compute the canonical SSZ list root of a slice of KZG commitments.
///
/// Each 48-byte commitment is packed into two 32-byte chunks (bytes 0–31 as
/// the first chunk, bytes 32–47 zero-padded to 32 bytes as the second). The
/// resulting chunks are merkleized and the element count is mixed in, producing
/// a root that is deterministic, collision-resistant, and length-sensitive.
///
/// This root is used as a **defense-in-depth commitment binding** (ISSUE-4.3,
/// L-3): it makes `blob_kzg_commitments` canonically addressable within rvc
/// without altering the BN-facing signing scope.
pub(crate) fn kzg_commitment_list_root(commitments: &[[u8; 48]]) -> [u8; 32] {
    // Each KZGCommitment (48 bytes) packs into two 32-byte chunks.
    let num_chunks = commitments.len().saturating_mul(2);
    let mut hasher = MerkleHasher::with_leaves(num_chunks.max(1));

    for commitment in commitments {
        // First chunk: bytes 0–31.
        hasher.write(&commitment[..32]).expect("valid first chunk");
        // Second chunk: bytes 32–47 zero-padded to 32 bytes.
        let mut second = [0u8; 32];
        second[..16].copy_from_slice(&commitment[32..]);
        hasher.write(&second).expect("valid second chunk");
    }

    let root = hasher.finish().expect("valid merkle root");
    // Mix in the element count for length-sensitivity (SSZ List semantics).
    mix_in_length(&root, commitments.len())
        .as_slice()
        .try_into()
        .expect("Hash256 is always 32 bytes")
}

pub type BeaconBlockBody = Vec<u8>;
pub type BlindedBeaconBlockBody = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlock {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub state_root: Root,
    #[serde(with = "serde_utils::hex_vec")]
    pub body: BeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedBeaconBlock {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "bytes_32_hex")]
    pub parent_root: Root,
    #[serde(with = "bytes_32_hex")]
    pub state_root: Root,
    #[serde(with = "serde_utils::hex_vec")]
    pub body: BlindedBeaconBlockBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSidecar {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::hex_vec")]
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum BlockContents {
    BlockAndBlobs { block: BeaconBlock, blob_sidecars: Vec<BlobSidecar> },
    Block(BeaconBlock),
}

impl<'de> serde::Deserialize<'de> for BlockContents {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        // Try BlockAndBlobs first (has both "block" and "blob_sidecars" keys)
        if value.get("blob_sidecars").is_some() {
            #[derive(Deserialize)]
            struct BlockAndBlobsHelper {
                block: BeaconBlock,
                blob_sidecars: Vec<BlobSidecar>,
            }
            return serde_json::from_value::<BlockAndBlobsHelper>(value.clone())
                .map(|h| BlockContents::BlockAndBlobs {
                    block: h.block,
                    blob_sidecars: h.blob_sidecars,
                })
                .map_err(|e| {
                    serde::de::Error::custom(format!("invalid BlockAndBlobs variant: {e}"))
                });
        }

        // Fall back to Block (bare BeaconBlock)
        serde_json::from_value::<BeaconBlock>(value)
            .map(BlockContents::Block)
            .map_err(|e| serde::de::Error::custom(format!("invalid Block variant: {e}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProducedBlock {
    Full(BlockContents),
    Blinded(BlindedBeaconBlock),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlindedBeaconBlock {
    pub message: BlindedBeaconBlock,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

impl BlockContents {
    pub fn block(&self) -> &BeaconBlock {
        match self {
            Self::Block(block) => block,
            Self::BlockAndBlobs { block, .. } => block,
        }
    }

    /// Extract blob KZG commitments from the `BeaconBlockBody` SSZ bytes.
    ///
    /// Returns an empty vector for the `Block` variant (pre-Deneb blocks carry
    /// no blob commitments) and for bodies shorter than the 392-byte Deneb
    /// fixed portion.
    ///
    /// This is the ISSUE-4.3 (L-3) defense-in-depth accessor: blob commitments
    /// are already opaquely bound via the block body tree hash; exposing them
    /// canonically allows callers to verify counts and compute a structured root
    /// before signing without changing the BN-facing signing scope.
    pub fn blob_kzg_commitments(&self) -> Vec<[u8; 48]> {
        match self {
            Self::BlockAndBlobs { block, .. } => extract_blob_kzg_commitments(&block.body),
            Self::Block(_) => vec![],
        }
    }

    /// Compute the canonical KZG commitment list root (ISSUE-4.3, L-3).
    ///
    /// Each 48-byte commitment is packed into two 32-byte chunks, merkleized,
    /// and the element count is mixed in. Returns the empty-list root for
    /// `Block` or for `BlockAndBlobs` with no blobs.
    ///
    /// This root is **separate from and does not change the block signing scope**.
    /// It is logged by the block service as a structured commitment binding.
    pub fn kzg_commitment_root(&self) -> [u8; 32] {
        kzg_commitment_list_root(&self.blob_kzg_commitments())
    }
}

impl BeaconBlock {
    /// Compute the canonical KZG commitment list root from this block's body SSZ.
    ///
    /// Equivalent to `BlockContents::kzg_commitment_root()` for the SSZ signing
    /// path where a bare `BeaconBlock` is available instead of `BlockContents`.
    pub fn kzg_commitment_root(&self) -> [u8; 32] {
        kzg_commitment_list_root(&extract_blob_kzg_commitments(&self.body))
    }

    /// Return the number of blob KZG commitments in this block's body SSZ.
    ///
    /// Returns 0 for pre-Deneb blocks (body shorter than the 392-byte fixed
    /// portion) or when the commitment region is malformed.
    pub fn blob_kzg_count(&self) -> usize {
        extract_blob_kzg_commitments(&self.body).len()
    }
}

impl TreeHash for BeaconBlock {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("containers cannot be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        let mut hasher = MerkleHasher::with_leaves(5);
        hasher.write(self.slot.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.proposer_index.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.parent_root.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.state_root.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(vec_u8_tree_hash_root(&self.body).as_slice()).expect("valid leaf");
        hasher.finish().expect("valid root")
    }
}

impl TreeHash for BlindedBeaconBlock {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("containers cannot be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        let mut hasher = MerkleHasher::with_leaves(5);
        hasher.write(self.slot.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.proposer_index.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.parent_root.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(self.state_root.tree_hash_root().as_slice()).expect("valid leaf");
        hasher.write(vec_u8_tree_hash_root(&self.body).as_slice()).expect("valid leaf");
        hasher.finish().expect("valid root")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    fn sample_block() -> BeaconBlock {
        BeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xde, 0xad],
        }
    }

    fn sample_blinded_block() -> BlindedBeaconBlock {
        BlindedBeaconBlock {
            slot: 100,
            proposer_index: 42,
            parent_root: [1u8; 32],
            state_root: [2u8; 32],
            body: vec![0xbe, 0xef],
        }
    }

    fn sample_blob_sidecar() -> BlobSidecar {
        BlobSidecar { index: 0, blob: vec![0xab; 8] }
    }

    #[test]
    fn test_beacon_block_serde_roundtrip() {
        let block = sample_block();
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: BeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_beacon_block_quoted_integers() {
        let block = sample_block();
        let json = serde_json::to_string(&block).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["proposer_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_blinded_beacon_block_serde_roundtrip() {
        let block = sample_blinded_block();
        let json = serde_json::to_string(&block).unwrap();
        let deserialized: BlindedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_blinded_beacon_block_quoted_integers() {
        let block = sample_blinded_block();
        let json = serde_json::to_string(&block).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["slot"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["proposer_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_blob_sidecar_serde_roundtrip() {
        let sidecar = sample_blob_sidecar();
        let json = serde_json::to_string(&sidecar).unwrap();
        let deserialized: BlobSidecar = serde_json::from_str(&json).unwrap();
        assert_eq!(sidecar, deserialized);
    }

    #[test]
    fn test_blob_sidecar_quoted_index() {
        let sidecar = sample_blob_sidecar();
        let json = serde_json::to_string(&sidecar).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["index"], serde_json::Value::String("0".to_string()));
    }

    #[test]
    fn test_block_contents_block_only_serde_roundtrip() {
        let contents = BlockContents::Block(sample_block());
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_block_contents_with_blobs_serde_roundtrip() {
        let contents = BlockContents::BlockAndBlobs {
            block: sample_block(),
            blob_sidecars: vec![sample_blob_sidecar()],
        };
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_block_contents_block_accessor() {
        let block = sample_block();
        let contents_block = BlockContents::Block(block.clone());
        assert_eq!(contents_block.block(), &block);

        let contents_blobs = BlockContents::BlockAndBlobs {
            block: block.clone(),
            blob_sidecars: vec![sample_blob_sidecar()],
        };
        assert_eq!(contents_blobs.block(), &block);
    }

    #[test]
    fn test_block_contents_empty_blobs() {
        let contents =
            BlockContents::BlockAndBlobs { block: sample_block(), blob_sidecars: vec![] };
        let json = serde_json::to_string(&contents).unwrap();
        let deserialized: BlockContents = serde_json::from_str(&json).unwrap();
        assert_eq!(contents, deserialized);
    }

    #[test]
    fn test_signed_beacon_block_serde_roundtrip() {
        let signed = SignedBeaconBlock { message: sample_block(), signature: vec![0xaa; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_signed_blinded_beacon_block_serde_roundtrip() {
        let signed =
            SignedBlindedBeaconBlock { message: sample_blinded_block(), signature: vec![0xbb; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedBlindedBeaconBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_produced_block_full_variant() {
        let produced = ProducedBlock::Full(BlockContents::Block(sample_block()));
        assert!(matches!(produced, ProducedBlock::Full(_)));
    }

    #[test]
    fn test_produced_block_blinded_variant() {
        let produced = ProducedBlock::Blinded(sample_blinded_block());
        assert!(matches!(produced, ProducedBlock::Blinded(_)));
    }

    #[test]
    fn test_beacon_block_fields() {
        let block = sample_block();
        assert_eq!(block.slot, 100);
        assert_eq!(block.proposer_index, 42);
        assert_eq!(block.parent_root, [1u8; 32]);
        assert_eq!(block.state_root, [2u8; 32]);
    }

    #[test]
    fn test_beacon_block_tree_hash_root_deterministic() {
        let block = sample_block();
        let root1 = block.tree_hash_root();
        let root2 = block.tree_hash_root();
        assert_eq!(root1, root2);
        assert_ne!(root1.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn test_beacon_block_tree_hash_root_differs_for_different_blocks() {
        let block1 = sample_block();
        let mut block2 = sample_block();
        block2.slot = 200;
        assert_ne!(block1.tree_hash_root(), block2.tree_hash_root());
    }

    #[test]
    fn test_blinded_beacon_block_tree_hash_root_deterministic() {
        let block = sample_blinded_block();
        let root1 = block.tree_hash_root();
        let root2 = block.tree_hash_root();
        assert_eq!(root1, root2);
        assert_ne!(root1.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn test_blinded_beacon_block_tree_hash_root_differs_for_different_blocks() {
        let block1 = sample_blinded_block();
        let mut block2 = sample_blinded_block();
        block2.slot = 200;
        assert_ne!(block1.tree_hash_root(), block2.tree_hash_root());
    }

    #[test]
    fn test_block_contents_invalid_json_error_has_context() {
        let json = r#"{"blob_sidecars": "not-an-array"}"#;
        let err = serde_json::from_str::<BlockContents>(json).unwrap_err();
        assert!(
            err.to_string().contains("BlockAndBlobs"),
            "expected error to mention BlockAndBlobs variant, got: {}",
            err
        );
    }

    #[test]
    fn test_block_contents_completely_invalid_json_error() {
        let json = r#"{"random_field": 42}"#;
        let err = serde_json::from_str::<BlockContents>(json).unwrap_err();
        assert!(
            err.to_string().contains("Block variant"),
            "expected error to mention Block variant, got: {}",
            err
        );
    }

    #[test]
    fn test_beacon_block_and_blinded_differ() {
        let block = sample_block();
        let blinded = sample_blinded_block();
        assert_ne!(block.tree_hash_root(), blinded.tree_hash_root());
    }

    // ── ISSUE-4.3 (L-3): extract_blob_kzg_commitments unit tests ────────────

    /// Build a minimal body SSZ with `commitments` placed at the correct Deneb
    /// fixed-portion offset (bytes 388–391 point to byte 392).
    fn body_with_kzg_commitments(commitments: &[[u8; 48]]) -> Vec<u8> {
        let mut body = vec![0u8; DENEB_BODY_FIXED_LEN];
        // blob_kzg_commitments offset = start of variable data
        let kzg_offset = DENEB_BODY_FIXED_LEN as u32;
        body[KZG_COMMIT_OFFSET_POS..KZG_COMMIT_OFFSET_POS + 4]
            .copy_from_slice(&kzg_offset.to_le_bytes());
        for c in commitments {
            body.extend_from_slice(c.as_slice());
        }
        body
    }

    #[test]
    fn test_extract_kzg_commitments_two_blobs() {
        let c0 = [0x11; 48];
        let c1 = [0x22; 48];
        let body = body_with_kzg_commitments(&[c0, c1]);
        let parsed = extract_blob_kzg_commitments(&body);
        assert_eq!(parsed, vec![c0, c1]);
    }

    #[test]
    fn test_extract_kzg_commitments_empty() {
        let body = body_with_kzg_commitments(&[]);
        let parsed = extract_blob_kzg_commitments(&body);
        assert_eq!(parsed, Vec::<[u8; 48]>::new());
    }

    #[test]
    fn test_extract_kzg_commitments_body_too_short() {
        // Anything shorter than DENEB_BODY_FIXED_LEN must yield an empty vec.
        let body = vec![0u8; DENEB_BODY_FIXED_LEN - 1];
        assert_eq!(extract_blob_kzg_commitments(&body), Vec::<[u8; 48]>::new());
    }

    #[test]
    fn test_extract_kzg_commitments_invalid_offset_zero() {
        // Offset 0 points inside the fixed portion — must be rejected.
        let mut body = vec![0u8; DENEB_BODY_FIXED_LEN + 48];
        // leave bytes 388-391 as zero (offset = 0 < DENEB_BODY_FIXED_LEN)
        assert_eq!(extract_blob_kzg_commitments(&body), Vec::<[u8; 48]>::new());
        // Also test offset == DENEB_BODY_FIXED_LEN - 1 (one byte inside fixed)
        let bad_offset = (DENEB_BODY_FIXED_LEN - 1) as u32;
        body[KZG_COMMIT_OFFSET_POS..KZG_COMMIT_OFFSET_POS + 4]
            .copy_from_slice(&bad_offset.to_le_bytes());
        assert_eq!(extract_blob_kzg_commitments(&body), Vec::<[u8; 48]>::new());
    }

    #[test]
    fn test_extract_kzg_commitments_misaligned_data_rejected() {
        // Trailing bytes that are not divisible by 48 must be rejected.
        let mut body = body_with_kzg_commitments(&[[0xaa; 48]]);
        body.push(0xff); // make length non-divisible by 48
        assert_eq!(extract_blob_kzg_commitments(&body), Vec::<[u8; 48]>::new());
    }

    // ── ISSUE-4.3 (L-3): kzg_commitment_list_root unit tests ────────────────

    #[test]
    fn test_kzg_commitment_list_root_deterministic() {
        let commitments = [[0xab; 48], [0xcd; 48]];
        assert_eq!(kzg_commitment_list_root(&commitments), kzg_commitment_list_root(&commitments));
    }

    #[test]
    fn test_kzg_commitment_list_root_nonzero_for_nonempty() {
        let root = kzg_commitment_list_root(&[[0x42; 48]]);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_kzg_commitment_list_root_length_sensitive() {
        let c = [0xff; 48];
        let root_one = kzg_commitment_list_root(&[c]);
        let root_two = kzg_commitment_list_root(&[c, c]);
        assert_ne!(root_one, root_two, "root must be length-sensitive");
    }

    #[test]
    fn test_kzg_commitment_list_root_empty_deterministic() {
        let r1 = kzg_commitment_list_root(&[]);
        let r2 = kzg_commitment_list_root(&[]);
        assert_eq!(r1, r2, "empty root must be deterministic");
    }

    // ── ISSUE-4.3 (L-3): BlockContents methods ──────────────────────────────

    #[test]
    fn test_block_contents_blob_kzg_commitments_extracted() {
        let c = [0x77; 48];
        let body = body_with_kzg_commitments(&[c]);
        let contents = BlockContents::BlockAndBlobs {
            block: BeaconBlock {
                slot: 1,
                proposer_index: 0,
                parent_root: [0; 32],
                state_root: [0; 32],
                body,
            },
            blob_sidecars: vec![],
        };
        assert_eq!(contents.blob_kzg_commitments(), vec![c]);
    }

    #[test]
    fn test_block_contents_kzg_root_changes_with_commitment_mutation() {
        let original = [0xde; 48];
        let body_orig = body_with_kzg_commitments(&[original]);
        let make_block = |body: Vec<u8>| BlockContents::BlockAndBlobs {
            block: BeaconBlock {
                slot: 10,
                proposer_index: 1,
                parent_root: [0; 32],
                state_root: [0; 32],
                body,
            },
            blob_sidecars: vec![],
        };

        let root_orig = make_block(body_orig).kzg_commitment_root();

        let mut mutated = original;
        mutated[0] ^= 0x01;
        let body_mut = body_with_kzg_commitments(&[mutated]);
        let root_mut = make_block(body_mut).kzg_commitment_root();

        assert_ne!(root_orig, root_mut, "mutated commitment must change root");
    }

    #[test]
    fn test_block_variant_has_no_blob_kzg_commitments() {
        let body = body_with_kzg_commitments(&[[0xff; 48]]);
        let contents = BlockContents::Block(BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body,
        });
        assert_eq!(
            contents.blob_kzg_commitments(),
            Vec::<[u8; 48]>::new(),
            "Block variant must return empty commitments"
        );
    }
}
