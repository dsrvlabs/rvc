use crate::BeaconError;

/// Minimal block header extracted from raw SSZ-encoded `BeaconBlock` bytes.
///
/// The SSZ layout of `BeaconBlock` always starts with `slot` (8 bytes LE)
/// followed by `proposer_index` (8 bytes LE) at a fixed offset, across all
/// fork variants (Phase0 through Electra).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SszBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
}

/// SSZ wire format returned by the `/eth/v3/validator/blocks/{slot}` endpoint.
///
/// The SSZ layout differs between forks and block types:
/// - **`BeaconBlock`**: Pre-Deneb unblinded and all blinded blocks. `slot` is
///   at byte offset 0.
/// - **`BlockContents`**: Deneb+ unblinded blocks. The first 12 bytes are three
///   4-byte LE offsets (block, kzg_proofs, blobs). The `BeaconBlock` data (and
///   thus `slot`) lives at the offset given by the first 4 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SszBlockFormat {
    /// Raw `BeaconBlock` — slot at byte 0 (pre-Deneb unblinded, all blinded).
    BeaconBlock,
    /// `BlockContents` wrapper — first 4 bytes = LE offset to inner `BeaconBlock`.
    BlockContents,
}

/// Minimum number of bytes required to extract the block header from a `BeaconBlock`.
const MIN_BEACON_BLOCK_HEADER_LEN: usize = 16;

/// Minimum size of the `BlockContents` fixed portion (3 × 4-byte offsets).
const BLOCK_CONTENTS_FIXED_LEN: usize = 12;

/// Extracts slot and proposer_index from raw SSZ bytes.
///
/// The `format` parameter determines how to locate the `BeaconBlock` within
/// the SSZ payload. See [`SszBlockFormat`] for details.
///
/// # Errors
///
/// Returns `BeaconError::ParseError` if the input is too short or the
/// offset within a `BlockContents` payload points outside the buffer.
pub fn extract_block_header_from_ssz(
    bytes: &[u8],
    format: SszBlockFormat,
) -> Result<SszBlockHeader, BeaconError> {
    let block_offset = match format {
        SszBlockFormat::BeaconBlock => 0,
        SszBlockFormat::BlockContents => {
            if bytes.len() < BLOCK_CONTENTS_FIXED_LEN {
                return Err(BeaconError::ParseError(format!(
                    "SSZ BlockContents too short: {} bytes, need at least {}",
                    bytes.len(),
                    BLOCK_CONTENTS_FIXED_LEN,
                )));
            }
            let offset =
                u32::from_le_bytes(bytes[0..4].try_into().expect("slice length verified above"))
                    as usize;
            if offset < BLOCK_CONTENTS_FIXED_LEN {
                return Err(BeaconError::ParseError(format!(
                    "SSZ BlockContents block offset {} is inside the fixed portion (< {})",
                    offset, BLOCK_CONTENTS_FIXED_LEN,
                )));
            }
            offset
        }
    };

    let end = block_offset
        .checked_add(MIN_BEACON_BLOCK_HEADER_LEN)
        .ok_or_else(|| BeaconError::ParseError("SSZ offset overflow".to_string()))?;

    if bytes.len() < end {
        return Err(BeaconError::ParseError(format!(
            "SSZ block too short: {} bytes, need at least {} (offset {} + header {})",
            bytes.len(),
            end,
            block_offset,
            MIN_BEACON_BLOCK_HEADER_LEN,
        )));
    }

    let slot = u64::from_le_bytes(
        bytes[block_offset..block_offset + 8].try_into().expect("slice length verified above"),
    );
    let proposer_index = u64::from_le_bytes(
        bytes[block_offset + 8..block_offset + 16].try_into().expect("slice length verified above"),
    );

    Ok(SszBlockHeader { slot, proposer_index })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BeaconBlock format tests ---

    #[test]
    fn test_beacon_block_empty_input_returns_error() {
        let result = extract_block_header_from_ssz(&[], SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
    }

    #[test]
    fn test_beacon_block_short_input_8_bytes_returns_error() {
        let bytes = vec![0u8; 8];
        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
    }

    #[test]
    fn test_beacon_block_short_input_15_bytes_returns_error() {
        let bytes = vec![0u8; 15];
        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock);
        assert!(result.is_err());
    }

    #[test]
    fn test_beacon_block_exactly_16_bytes_succeeds() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u64.to_le_bytes());
        bytes.extend_from_slice(&42u64.to_le_bytes());
        assert_eq!(bytes.len(), 16);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, 100);
        assert_eq!(header.proposer_index, 42);
    }

    #[test]
    fn test_beacon_block_zero_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, 0);
        assert_eq!(header.proposer_index, 0);
    }

    #[test]
    fn test_beacon_block_max_u64_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, u64::MAX);
        assert_eq!(header.proposer_index, u64::MAX);
    }

    #[test]
    fn test_beacon_block_typical_mainnet_values() {
        let slot: u64 = 9_000_000;
        let proposer_index: u64 = 500_000;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&proposer_index.to_le_bytes());
        bytes.extend_from_slice(&[0xab; 128]);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, slot);
        assert_eq!(header.proposer_index, proposer_index);
    }

    #[test]
    fn test_beacon_block_ignores_trailing_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&42u64.to_le_bytes());
        bytes.extend_from_slice(&99u64.to_le_bytes());
        bytes.extend_from_slice(&[0xff; 1024]);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BeaconBlock).unwrap();
        assert_eq!(header.slot, 42);
        assert_eq!(header.proposer_index, 99);
    }

    // --- BlockContents format tests ---

    /// Build a minimal BlockContents SSZ payload:
    /// [block_offset(4) | kzg_offset(4) | blobs_offset(4) | ... | BeaconBlock at block_offset]
    fn build_block_contents_ssz(slot: u64, proposer_index: u64) -> Vec<u8> {
        // 3 offsets × 4 bytes = 12 bytes fixed portion
        // BeaconBlock data starts immediately after at offset 12
        let block_offset: u32 = 12;
        let kzg_offset: u32 = 12 + 16 + 64; // block data + padding
        let blobs_offset: u32 = kzg_offset + 48; // kzg proof placeholder

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&block_offset.to_le_bytes());
        bytes.extend_from_slice(&kzg_offset.to_le_bytes());
        bytes.extend_from_slice(&blobs_offset.to_le_bytes());

        // BeaconBlock data at offset 12
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&proposer_index.to_le_bytes());
        // Simulated remaining block fields (parent_root, state_root, body offset, body...)
        bytes.extend_from_slice(&[0xcc; 128]);

        bytes
    }

    #[test]
    fn test_block_contents_extracts_slot_and_proposer() {
        let bytes = build_block_contents_ssz(9_000_000, 500_000);
        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, 9_000_000);
        assert_eq!(header.proposer_index, 500_000);
    }

    #[test]
    fn test_block_contents_zero_values() {
        let bytes = build_block_contents_ssz(0, 0);
        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, 0);
        assert_eq!(header.proposer_index, 0);
    }

    #[test]
    fn test_block_contents_max_u64_values() {
        let bytes = build_block_contents_ssz(u64::MAX, u64::MAX);
        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, u64::MAX);
        assert_eq!(header.proposer_index, u64::MAX);
    }

    #[test]
    fn test_block_contents_empty_input_returns_error() {
        let result = extract_block_header_from_ssz(&[], SszBlockFormat::BlockContents);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("BlockContents"), "error should mention BlockContents: {err}");
    }

    #[test]
    fn test_block_contents_short_input_returns_error() {
        let bytes = vec![0u8; 8]; // less than 12 bytes needed for offsets
        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_contents_offset_beyond_buffer_returns_error() {
        // Valid 12-byte fixed portion, but offset points past end of buffer
        let mut bytes = Vec::new();
        let huge_offset: u32 = 10_000;
        bytes.extend_from_slice(&huge_offset.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        // Only 12 bytes total — block_offset 10000 is way out of bounds

        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_contents_offset_inside_fixed_portion_returns_error() {
        // Offset = 4, which points inside the fixed portion (< 12)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes()); // offset inside fixed portion
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]); // padding

        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("fixed portion"), "error should mention fixed portion: {err}");
    }

    #[test]
    fn test_block_contents_buffer_too_short_for_header_at_offset() {
        // Offset = 12 but buffer only has 20 bytes total (need 12 + 16 = 28)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]); // only 8 bytes after offset, need 16

        let result = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_contents_minimum_valid_payload() {
        // Exactly 12 (offsets) + 16 (slot + proposer_index) = 28 bytes
        let slot: u64 = 42;
        let proposer_index: u64 = 99;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12u32.to_le_bytes()); // block at offset 12
        bytes.extend_from_slice(&28u32.to_le_bytes()); // kzg_proofs (end of block)
        bytes.extend_from_slice(&28u32.to_le_bytes()); // blobs (same, empty)
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&proposer_index.to_le_bytes());
        assert_eq!(bytes.len(), 28);

        let header = extract_block_header_from_ssz(&bytes, SszBlockFormat::BlockContents).unwrap();
        assert_eq!(header.slot, 42);
        assert_eq!(header.proposer_index, 99);
    }
}
