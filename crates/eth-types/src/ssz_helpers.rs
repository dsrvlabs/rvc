//! SSZ encode/decode helpers for consensus objects.
//!
//! These helpers dispatch by `fork_id` (PHASE0=0, ALTAIR=1, BELLATRIX=2,
//! CAPELLA=3, DENEB=4, ELECTRA=5, FULU=6) and provide unified entry points
//! that the signer service can use to deserialize SSZ bytes from proto fields
//! without inspecting the bytes directly.
//!
//! The `BeaconBlock` and related types use a `body: Vec<u8>` representation
//! internally. Their SSZ layout is a simple 5-field container with one
//! variable-length field (`body`):
//!
//! | field          | type      | size                  |
//! |----------------|-----------|-----------------------|
//! | slot           | uint64    | 8 bytes (fixed)       |
//! | proposer_index | uint64    | 8 bytes (fixed)       |
//! | parent_root    | bytes32   | 32 bytes (fixed)      |
//! | state_root     | bytes32   | 32 bytes (fixed)      |
//! | body           | List[...]  | 4-byte offset + data  |
//!
//! The fixed part (including the 4-byte offset for `body`) is 84 bytes.

use thiserror::Error;

use crate::{
    Attestation, AttestationData, BeaconBlock, BlindedBeaconBlock, SyncCommitteeContribution,
};

/// Errors that can occur when decoding SSZ bytes into a consensus type.
#[derive(Debug, Error)]
pub enum SszDecodeError {
    #[error("SSZ buffer too short: need at least {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("SSZ offset out of range: offset {offset} > buffer length {len}")]
    OffsetOutOfRange { offset: usize, len: usize },

    #[error("unknown fork_id: {0}")]
    UnknownForkId(u32),

    #[error("invalid SSZ encoding: {0}")]
    InvalidEncoding(String),
}

// ============================================================
// BeaconBlock
// ============================================================

/// SSZ-encode a [`BeaconBlock`] to bytes.
///
/// The layout mirrors the Ethereum consensus specification SSZ container
/// with one variable-length field (`body`).
pub fn encode_beacon_block_ssz(block: &BeaconBlock, _fork_id: u32) -> Vec<u8> {
    encode_beacon_block_inner(
        &block.slot,
        block.proposer_index,
        &block.parent_root,
        &block.state_root,
        &block.body,
    )
}

/// SSZ-decode bytes into a [`BeaconBlock`], dispatching by `fork_id`.
///
/// All forks share the same `BeaconBlock` SSZ container layout (the fork
/// is encoded in the body, not in the outer wrapper). The `fork_id` is
/// accepted for forward compatibility and validated to be a known value.
pub fn decode_beacon_block_ssz(bytes: &[u8], fork_id: u32) -> Result<BeaconBlock, SszDecodeError> {
    validate_fork_id(fork_id)?;
    let (slot, proposer_index, parent_root, state_root, body) = decode_block_container(bytes)?;
    Ok(BeaconBlock { slot, proposer_index, parent_root, state_root, body })
}

// ============================================================
// BlindedBeaconBlock
// ============================================================

/// SSZ-encode a [`BlindedBeaconBlock`] to bytes.
pub fn encode_blinded_beacon_block_ssz(block: &BlindedBeaconBlock, _fork_id: u32) -> Vec<u8> {
    encode_beacon_block_inner(
        &block.slot,
        block.proposer_index,
        &block.parent_root,
        &block.state_root,
        &block.body,
    )
}

/// SSZ-decode bytes into a [`BlindedBeaconBlock`], dispatching by `fork_id`.
pub fn decode_blinded_beacon_block_ssz(
    bytes: &[u8],
    fork_id: u32,
) -> Result<BlindedBeaconBlock, SszDecodeError> {
    validate_fork_id(fork_id)?;
    let (slot, proposer_index, parent_root, state_root, body) = decode_block_container(bytes)?;
    Ok(BlindedBeaconBlock { slot, proposer_index, parent_root, state_root, body })
}

// ============================================================
// Attestation
// ============================================================

/// SSZ-encode an [`Attestation`] to bytes.
///
/// Layout: aggregation_bits (variable) | data (fixed, 128 bytes) | signature (variable, 96 bytes fixed)
///
/// Actually: two variable-length fields (aggregation_bits, signature) + one fixed-length field (data).
/// SSZ layout for a 3-field container where fields 1 and 3 are variable:
/// offset1(4) + data(128) + offset3(4) + aggregation_bits_data + signature_data
pub fn encode_attestation_ssz(att: &Attestation, _fork_id: u32) -> Vec<u8> {
    // data is fixed-length (128 bytes: 8+8+32+40+40)
    use ssz::Encode;
    let data_bytes = att.data.as_ssz_bytes();

    let fixed_size = 4 + data_bytes.len() + 4; // offset1 + data + offset3
    let offset1: u32 = fixed_size as u32; // aggregation_bits starts here
    let offset3: u32 = offset1 + att.aggregation_bits.len() as u32; // signature starts here

    let mut out = Vec::with_capacity(fixed_size + att.aggregation_bits.len() + att.signature.len());
    out.extend_from_slice(&offset1.to_le_bytes());
    out.extend_from_slice(&data_bytes);
    out.extend_from_slice(&offset3.to_le_bytes());
    out.extend_from_slice(&att.aggregation_bits);
    out.extend_from_slice(&att.signature);
    out
}

/// SSZ-decode bytes into an [`Attestation`], dispatching by `fork_id`.
pub fn decode_attestation_ssz(bytes: &[u8], fork_id: u32) -> Result<Attestation, SszDecodeError> {
    validate_fork_id(fork_id)?;

    use ssz::Decode;

    // Layout: offset1(4) + data(128) + offset3(4) + aggregation_bits + signature
    const DATA_SSZ_LEN: usize = 128; // 8+8+32+40+40
    const FIXED_LEN: usize = 4 + DATA_SSZ_LEN + 4;

    if bytes.len() < FIXED_LEN {
        return Err(SszDecodeError::TooShort { need: FIXED_LEN, got: bytes.len() });
    }

    let offset1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let data_bytes = &bytes[4..4 + DATA_SSZ_LEN];
    let offset3 =
        u32::from_le_bytes(bytes[4 + DATA_SSZ_LEN..FIXED_LEN].try_into().unwrap()) as usize;

    if offset1 < FIXED_LEN || offset1 > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset1, len: bytes.len() });
    }
    if offset3 < offset1 || offset3 > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset3, len: bytes.len() });
    }

    let aggregation_bits = bytes[offset1..offset3].to_vec();
    let signature = bytes[offset3..].to_vec();
    let data = AttestationData::from_ssz_bytes(data_bytes)
        .map_err(|e| SszDecodeError::InvalidEncoding(format!("AttestationData: {:?}", e)))?;

    Ok(Attestation { aggregation_bits, data, signature })
}

// ============================================================
// SyncCommitteeContribution
// ============================================================

/// SSZ-encode a [`SyncCommitteeContribution`] to bytes.
///
/// Layout: slot(8) + beacon_block_root(32) + subcommittee_index(8) + offset_aggbits(4) + offset_sig(4)
///         + aggregation_bits + signature
pub fn encode_sync_committee_contribution_ssz(
    contrib: &SyncCommitteeContribution,
    _fork_id: u32,
) -> Vec<u8> {
    // Fixed fields: slot(8) + beacon_block_root(32) + subcommittee_index(8) = 48 bytes
    // Two variable fields: aggregation_bits, signature → 2 × 4-byte offsets
    let fixed_size = 8 + 32 + 8 + 4 + 4; // 56
    let offset_aggbits: u32 = fixed_size as u32;
    let offset_sig: u32 = offset_aggbits + contrib.aggregation_bits.len() as u32;

    let mut out =
        Vec::with_capacity(fixed_size + contrib.aggregation_bits.len() + contrib.signature.len());
    out.extend_from_slice(&contrib.slot.to_le_bytes());
    out.extend_from_slice(&contrib.beacon_block_root);
    out.extend_from_slice(&contrib.subcommittee_index.to_le_bytes());
    out.extend_from_slice(&offset_aggbits.to_le_bytes());
    out.extend_from_slice(&offset_sig.to_le_bytes());
    out.extend_from_slice(&contrib.aggregation_bits);
    out.extend_from_slice(&contrib.signature);
    out
}

/// SSZ-decode bytes into a [`SyncCommitteeContribution`], dispatching by `fork_id`.
pub fn decode_sync_committee_contribution_ssz(
    bytes: &[u8],
    fork_id: u32,
) -> Result<SyncCommitteeContribution, SszDecodeError> {
    validate_fork_id(fork_id)?;

    // Fixed: slot(8) + beacon_block_root(32) + subcommittee_index(8) + offset_aggbits(4) + offset_sig(4) = 56
    const FIXED_LEN: usize = 56;
    if bytes.len() < FIXED_LEN {
        return Err(SszDecodeError::TooShort { need: FIXED_LEN, got: bytes.len() });
    }

    let slot = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let beacon_block_root: [u8; 32] = bytes[8..40].try_into().unwrap();
    let subcommittee_index = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
    let offset_aggbits = u32::from_le_bytes(bytes[48..52].try_into().unwrap()) as usize;
    let offset_sig = u32::from_le_bytes(bytes[52..56].try_into().unwrap()) as usize;

    if offset_aggbits < FIXED_LEN || offset_aggbits > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset_aggbits, len: bytes.len() });
    }
    if offset_sig < offset_aggbits || offset_sig > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: offset_sig, len: bytes.len() });
    }

    let aggregation_bits = bytes[offset_aggbits..offset_sig].to_vec();
    let signature = bytes[offset_sig..].to_vec();

    Ok(SyncCommitteeContribution {
        slot,
        beacon_block_root,
        subcommittee_index,
        aggregation_bits,
        signature,
    })
}

// ============================================================
// Internal helpers
// ============================================================

/// Decoded inner fields of a block container:
/// (slot, proposer_index, parent_root, state_root, body)
type BlockFields = (u64, u64, [u8; 32], [u8; 32], Vec<u8>);

/// Validate that a `fork_id` is a known value (0..=6).
fn validate_fork_id(fork_id: u32) -> Result<(), SszDecodeError> {
    if fork_id > 6 {
        return Err(SszDecodeError::UnknownForkId(fork_id));
    }
    Ok(())
}

/// SSZ encode the inner block fields (shared by BeaconBlock and BlindedBeaconBlock).
///
/// Layout: slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_offset(4) + body
fn encode_beacon_block_inner(
    slot: &u64,
    proposer_index: u64,
    parent_root: &[u8; 32],
    state_root: &[u8; 32],
    body: &[u8],
) -> Vec<u8> {
    // Fixed: 8 + 8 + 32 + 32 + 4 (offset for body) = 84
    const FIXED: u32 = 84;
    let mut out = Vec::with_capacity(84 + body.len());
    out.extend_from_slice(&slot.to_le_bytes());
    out.extend_from_slice(&proposer_index.to_le_bytes());
    out.extend_from_slice(parent_root.as_ref());
    out.extend_from_slice(state_root.as_ref());
    out.extend_from_slice(&FIXED.to_le_bytes()); // body offset = 84
    out.extend_from_slice(body);
    out
}

/// SSZ decode the inner block fields.
fn decode_block_container(bytes: &[u8]) -> Result<BlockFields, SszDecodeError> {
    const FIXED: usize = 84;
    if bytes.len() < FIXED {
        return Err(SszDecodeError::TooShort { need: FIXED, got: bytes.len() });
    }

    let slot = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let proposer_index = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let parent_root: [u8; 32] = bytes[16..48].try_into().unwrap();
    let state_root: [u8; 32] = bytes[48..80].try_into().unwrap();
    let body_offset = u32::from_le_bytes(bytes[80..84].try_into().unwrap()) as usize;

    if body_offset < FIXED || body_offset > bytes.len() {
        return Err(SszDecodeError::OffsetOutOfRange { offset: body_offset, len: bytes.len() });
    }

    let body = bytes[body_offset..].to_vec();
    Ok((slot, proposer_index, parent_root, state_root, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestationData, Checkpoint};

    fn sample_beacon_block() -> BeaconBlock {
        BeaconBlock {
            slot: 12345,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    fn sample_blinded_block() -> BlindedBeaconBlock {
        BlindedBeaconBlock {
            slot: 12345,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: vec![0xca, 0xfe],
        }
    }

    fn sample_attestation() -> Attestation {
        Attestation {
            aggregation_bits: vec![0xff, 0x01],
            data: AttestationData {
                slot: 100,
                index: 1,
                beacon_block_root: [0x33; 32],
                source: Checkpoint { epoch: 9, root: [0x44; 32] },
                target: Checkpoint { epoch: 10, root: [0x55; 32] },
            },
            signature: vec![0xaa; 96],
        }
    }

    fn sample_contribution() -> SyncCommitteeContribution {
        SyncCommitteeContribution {
            slot: 200,
            beacon_block_root: [0x66; 32],
            subcommittee_index: 3,
            aggregation_bits: vec![0x0f; 16],
            signature: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_encode_decode_beacon_block_roundtrip_all_fork_ids() {
        let block = sample_beacon_block();
        for fork_id in 0u32..=6 {
            let encoded = encode_beacon_block_ssz(&block, fork_id);
            let decoded = decode_beacon_block_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(block, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    #[test]
    fn test_encode_decode_blinded_beacon_block_roundtrip_all_fork_ids() {
        let block = sample_blinded_block();
        for fork_id in 0u32..=6 {
            let encoded = encode_blinded_beacon_block_ssz(&block, fork_id);
            let decoded =
                decode_blinded_beacon_block_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(block, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    #[test]
    fn test_encode_decode_attestation_roundtrip_all_fork_ids() {
        let att = sample_attestation();
        for fork_id in 0u32..=6 {
            let encoded = encode_attestation_ssz(&att, fork_id);
            let decoded = decode_attestation_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(att, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    #[test]
    fn test_encode_decode_sync_committee_contribution_roundtrip_all_fork_ids() {
        let contrib = sample_contribution();
        for fork_id in 0u32..=6 {
            let encoded = encode_sync_committee_contribution_ssz(&contrib, fork_id);
            let decoded =
                decode_sync_committee_contribution_ssz(&encoded, fork_id).expect("decode failed");
            assert_eq!(contrib, decoded, "roundtrip failed for fork_id={fork_id}");
        }
    }

    #[test]
    fn test_decode_beacon_block_unknown_fork_id_rejected() {
        let block = sample_beacon_block();
        let encoded = encode_beacon_block_ssz(&block, 0);
        let result = decode_beacon_block_ssz(&encoded, 7);
        assert!(matches!(result, Err(SszDecodeError::UnknownForkId(7))));
    }

    #[test]
    fn test_decode_beacon_block_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_beacon_block_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_blinded_beacon_block_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_blinded_beacon_block_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_attestation_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_attestation_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_contribution_too_short_returns_error() {
        let short = vec![0u8; 10];
        let result = decode_sync_committee_contribution_ssz(&short, 0);
        assert!(matches!(result, Err(SszDecodeError::TooShort { .. })));
    }

    #[test]
    fn test_decode_attestation_unknown_fork_id_rejected() {
        let att = sample_attestation();
        let encoded = encode_attestation_ssz(&att, 0);
        let result = decode_attestation_ssz(&encoded, 99);
        assert!(matches!(result, Err(SszDecodeError::UnknownForkId(99))));
    }

    #[test]
    fn test_decode_contribution_unknown_fork_id_rejected() {
        let contrib = sample_contribution();
        let encoded = encode_sync_committee_contribution_ssz(&contrib, 0);
        let result = decode_sync_committee_contribution_ssz(&encoded, 99);
        assert!(matches!(result, Err(SszDecodeError::UnknownForkId(99))));
    }

    #[test]
    fn test_beacon_block_encoded_length() {
        let block = sample_beacon_block();
        let encoded = encode_beacon_block_ssz(&block, 0);
        // 84 bytes fixed + body.len()
        assert_eq!(encoded.len(), 84 + block.body.len());
    }

    #[test]
    fn test_beacon_block_empty_body_roundtrip() {
        let block = BeaconBlock {
            slot: 0,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: vec![],
        };
        let encoded = encode_beacon_block_ssz(&block, 4); // Deneb
        let decoded = decode_beacon_block_ssz(&encoded, 4).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn test_attestation_empty_bits_roundtrip() {
        let att = Attestation {
            aggregation_bits: vec![],
            data: AttestationData {
                slot: 0,
                index: 0,
                beacon_block_root: [0u8; 32],
                source: Checkpoint { epoch: 0, root: [0u8; 32] },
                target: Checkpoint { epoch: 0, root: [0u8; 32] },
            },
            signature: vec![0u8; 96],
        };
        let encoded = encode_attestation_ssz(&att, 0);
        let decoded = decode_attestation_ssz(&encoded, 0).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn test_contribution_large_aggregation_bits_roundtrip() {
        let contrib = SyncCommitteeContribution {
            slot: 999,
            beacon_block_root: [0x77; 32],
            subcommittee_index: 7,
            aggregation_bits: vec![0xff; 64],
            signature: vec![0xcc; 96],
        };
        let encoded = encode_sync_committee_contribution_ssz(&contrib, 5); // Electra
        let decoded = decode_sync_committee_contribution_ssz(&encoded, 5).unwrap();
        assert_eq!(contrib, decoded);
    }
}
