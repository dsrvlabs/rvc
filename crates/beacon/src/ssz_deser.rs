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

/// Minimum number of bytes required to extract the block header.
const MIN_SSZ_HEADER_LEN: usize = 16;

/// Extracts slot and proposer_index from raw SSZ-encoded `BeaconBlock` bytes.
///
/// # Errors
///
/// Returns `BeaconError::ParseError` if the input is shorter than 16 bytes.
pub fn extract_block_header_from_ssz(bytes: &[u8]) -> Result<SszBlockHeader, BeaconError> {
    if bytes.len() < MIN_SSZ_HEADER_LEN {
        return Err(BeaconError::ParseError(format!(
            "SSZ block too short: {} bytes, need at least {}",
            bytes.len(),
            MIN_SSZ_HEADER_LEN,
        )));
    }

    let slot = u64::from_le_bytes(bytes[0..8].try_into().expect("slice length verified above"));
    let proposer_index =
        u64::from_le_bytes(bytes[8..16].try_into().expect("slice length verified above"));

    Ok(SszBlockHeader { slot, proposer_index })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_empty_input_returns_error() {
        let result = extract_block_header_from_ssz(&[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("16"), "error should mention minimum length: {err}");
    }

    #[test]
    fn test_extract_short_input_8_bytes_returns_error() {
        let bytes = vec![0u8; 8];
        let result = extract_block_header_from_ssz(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_short_input_15_bytes_returns_error() {
        let bytes = vec![0u8; 15];
        let result = extract_block_header_from_ssz(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_exactly_16_bytes_succeeds() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u64.to_le_bytes()); // slot
        bytes.extend_from_slice(&42u64.to_le_bytes()); // proposer_index
        assert_eq!(bytes.len(), 16);

        let header = extract_block_header_from_ssz(&bytes).unwrap();
        assert_eq!(header.slot, 100);
        assert_eq!(header.proposer_index, 42);
    }

    #[test]
    fn test_extract_zero_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let header = extract_block_header_from_ssz(&bytes).unwrap();
        assert_eq!(header.slot, 0);
        assert_eq!(header.proposer_index, 0);
    }

    #[test]
    fn test_extract_max_u64_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());

        let header = extract_block_header_from_ssz(&bytes).unwrap();
        assert_eq!(header.slot, u64::MAX);
        assert_eq!(header.proposer_index, u64::MAX);
    }

    #[test]
    fn test_extract_typical_mainnet_values() {
        let slot: u64 = 9_000_000;
        let proposer_index: u64 = 500_000;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&proposer_index.to_le_bytes());
        // Simulate trailing block body data
        bytes.extend_from_slice(&[0xab; 128]);

        let header = extract_block_header_from_ssz(&bytes).unwrap();
        assert_eq!(header.slot, slot);
        assert_eq!(header.proposer_index, proposer_index);
    }

    #[test]
    fn test_extract_ignores_trailing_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&42u64.to_le_bytes());
        bytes.extend_from_slice(&99u64.to_le_bytes());
        bytes.extend_from_slice(&[0xff; 1024]);

        let header = extract_block_header_from_ssz(&bytes).unwrap();
        assert_eq!(header.slot, 42);
        assert_eq!(header.proposer_index, 99);
    }
}
