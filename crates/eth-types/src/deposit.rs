use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct DepositMessage {
    #[serde(with = "crate::hex_fixed::bytes_48_hex")]
    pub pubkey: [u8; 48],
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub withdrawal_credentials: [u8; 32],
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct DepositData {
    #[serde(with = "crate::hex_fixed::bytes_48_hex")]
    pub pubkey: [u8; 48],
    #[serde(with = "crate::hex_fixed::bytes_32_hex")]
    pub withdrawal_credentials: [u8; 32],
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    #[serde(with = "crate::hex_fixed::bytes_96_hex")]
    pub signature: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct BLSToExecutionChange {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "crate::hex_fixed::bytes_48_hex")]
    pub from_bls_pubkey: [u8; 48],
    #[serde(with = "crate::hex_fixed::bytes_20_hex")]
    pub to_execution_address: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBLSToExecutionChange {
    pub message: BLSToExecutionChange,
    #[serde(with = "serde_utils::hex_vec")]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};
    use tree_hash::TreeHash;

    fn sample_deposit_message() -> DepositMessage {
        DepositMessage {
            pubkey: [0xaa; 48],
            withdrawal_credentials: [0xbb; 32],
            amount: 32_000_000_000,
        }
    }

    fn sample_deposit_data() -> DepositData {
        DepositData {
            pubkey: [0xaa; 48],
            withdrawal_credentials: [0xbb; 32],
            amount: 32_000_000_000,
            signature: [0xcc; 96],
        }
    }

    fn sample_bls_to_execution_change() -> BLSToExecutionChange {
        BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: [0xdd; 48],
            to_execution_address: [0xee; 20],
        }
    }

    // --- DepositMessage SSZ tests ---

    #[test]
    fn test_deposit_message_ssz_encode_length() {
        let msg = sample_deposit_message();
        let encoded = msg.as_ssz_bytes();
        // 48 (pubkey) + 32 (withdrawal_credentials) + 8 (amount) = 88
        assert_eq!(encoded.len(), 88);
    }

    #[test]
    fn test_deposit_message_ssz_roundtrip() {
        let original = sample_deposit_message();
        let encoded = original.as_ssz_bytes();
        let decoded = DepositMessage::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_deposit_message_tree_hash_produces_32_bytes() {
        let msg = sample_deposit_message();
        let root = msg.tree_hash_root();
        assert_eq!(root.0.len(), 32);
    }

    // --- DepositData SSZ tests ---

    #[test]
    fn test_deposit_data_ssz_encode_length() {
        let data = sample_deposit_data();
        let encoded = data.as_ssz_bytes();
        // 48 (pubkey) + 32 (withdrawal_credentials) + 8 (amount) + 96 (signature) = 184
        assert_eq!(encoded.len(), 184);
    }

    #[test]
    fn test_deposit_data_ssz_roundtrip() {
        let original = sample_deposit_data();
        let encoded = original.as_ssz_bytes();
        let decoded = DepositData::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_deposit_data_tree_hash_produces_32_bytes() {
        let data = sample_deposit_data();
        let root = data.tree_hash_root();
        assert_eq!(root.0.len(), 32);
    }

    // --- BLSToExecutionChange SSZ tests ---

    #[test]
    fn test_bls_to_execution_change_ssz_encode_length() {
        let change = sample_bls_to_execution_change();
        let encoded = change.as_ssz_bytes();
        // 8 (validator_index) + 48 (from_bls_pubkey) + 20 (to_execution_address) = 76
        assert_eq!(encoded.len(), 76);
    }

    #[test]
    fn test_bls_to_execution_change_ssz_roundtrip() {
        let original = sample_bls_to_execution_change();
        let encoded = original.as_ssz_bytes();
        let decoded = BLSToExecutionChange::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bls_to_execution_change_tree_hash_produces_32_bytes() {
        let change = sample_bls_to_execution_change();
        let root = change.tree_hash_root();
        assert_eq!(root.0.len(), 32);
    }

    // --- DepositMessage serde JSON tests ---

    #[test]
    fn test_deposit_message_json_roundtrip() {
        let original = sample_deposit_message();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: DepositMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_deposit_message_json_hex_pubkey() {
        let msg = sample_deposit_message();
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected_pubkey = format!("0x{}", "aa".repeat(48));
        assert_eq!(parsed["pubkey"], serde_json::Value::String(expected_pubkey));
    }

    #[test]
    fn test_deposit_message_json_quoted_amount() {
        let msg = sample_deposit_message();
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["amount"], serde_json::Value::String("32000000000".to_string()));
    }

    // --- DepositData serde JSON tests ---

    #[test]
    fn test_deposit_data_json_roundtrip() {
        let original = sample_deposit_data();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: DepositData = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_deposit_data_json_hex_signature() {
        let data = sample_deposit_data();
        let json = serde_json::to_string(&data).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected_sig = format!("0x{}", "cc".repeat(96));
        assert_eq!(parsed["signature"], serde_json::Value::String(expected_sig));
    }

    // --- BLSToExecutionChange serde JSON tests ---

    #[test]
    fn test_bls_to_execution_change_json_roundtrip() {
        let original = sample_bls_to_execution_change();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: BLSToExecutionChange = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bls_to_execution_change_json_quoted_validator_index() {
        let change = sample_bls_to_execution_change();
        let json = serde_json::to_string(&change).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_bls_to_execution_change_json_hex_address() {
        let change = sample_bls_to_execution_change();
        let json = serde_json::to_string(&change).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected_addr = format!("0x{}", "ee".repeat(20));
        assert_eq!(parsed["to_execution_address"], serde_json::Value::String(expected_addr));
    }

    // --- SignedBLSToExecutionChange serde JSON tests ---

    #[test]
    fn test_signed_bls_to_execution_change_json_roundtrip() {
        let original = SignedBLSToExecutionChange {
            message: sample_bls_to_execution_change(),
            signature: vec![0xff; 96],
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SignedBLSToExecutionChange = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_signed_bls_to_execution_change_json_hex_signature() {
        let signed = SignedBLSToExecutionChange {
            message: sample_bls_to_execution_change(),
            signature: vec![0xff; 96],
        };
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected_sig = format!("0x{}", "ff".repeat(96));
        assert_eq!(parsed["signature"], serde_json::Value::String(expected_sig));
    }

    // --- Tree hash determinism ---

    #[test]
    fn test_deposit_message_tree_hash_deterministic() {
        let msg = sample_deposit_message();
        let root1 = msg.tree_hash_root();
        let root2 = msg.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_deposit_data_tree_hash_deterministic() {
        let data = sample_deposit_data();
        let root1 = data.tree_hash_root();
        let root2 = data.tree_hash_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_different_deposit_messages_have_different_roots() {
        let msg1 = sample_deposit_message();
        let msg2 = DepositMessage {
            pubkey: [0x11; 48],
            withdrawal_credentials: [0xbb; 32],
            amount: 32_000_000_000,
        };
        assert_ne!(msg1.tree_hash_root(), msg2.tree_hash_root());
    }
}
