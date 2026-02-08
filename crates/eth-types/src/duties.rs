use serde::{Deserialize, Serialize};

use crate::{Epoch, Signature, Slot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerDuty {
    pub pubkey: String,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: Slot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoluntaryExit {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    #[serde(with = "serde_utils::hex_vec")]
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proposer_duty() -> ProposerDuty {
        ProposerDuty { pubkey: "0xabcdef1234567890".to_string(), validator_index: 42, slot: 1000 }
    }

    fn sample_voluntary_exit() -> VoluntaryExit {
        VoluntaryExit { epoch: 100, validator_index: 42 }
    }

    #[test]
    fn test_proposer_duty_serde_roundtrip() {
        let duty = sample_proposer_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let deserialized: ProposerDuty = serde_json::from_str(&json).unwrap();
        assert_eq!(duty, deserialized);
    }

    #[test]
    fn test_proposer_duty_quoted_integers() {
        let duty = sample_proposer_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
        assert_eq!(parsed["slot"], serde_json::Value::String("1000".to_string()));
    }

    #[test]
    fn test_proposer_duty_pubkey_is_string() {
        let duty = sample_proposer_duty();
        let json = serde_json::to_string(&duty).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["pubkey"], serde_json::Value::String("0xabcdef1234567890".to_string()));
    }

    #[test]
    fn test_voluntary_exit_serde_roundtrip() {
        let exit = sample_voluntary_exit();
        let json = serde_json::to_string(&exit).unwrap();
        let deserialized: VoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(exit, deserialized);
    }

    #[test]
    fn test_voluntary_exit_quoted_integers() {
        let exit = sample_voluntary_exit();
        let json = serde_json::to_string(&exit).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["epoch"], serde_json::Value::String("100".to_string()));
        assert_eq!(parsed["validator_index"], serde_json::Value::String("42".to_string()));
    }

    #[test]
    fn test_signed_voluntary_exit_serde_roundtrip() {
        let signed =
            SignedVoluntaryExit { message: sample_voluntary_exit(), signature: vec![0xaa; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedVoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }

    #[test]
    fn test_voluntary_exit_zero_values() {
        let exit = VoluntaryExit { epoch: 0, validator_index: 0 };
        let json = serde_json::to_string(&exit).unwrap();
        let deserialized: VoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(exit, deserialized);
    }

    #[test]
    fn test_voluntary_exit_max_values() {
        let exit = VoluntaryExit { epoch: u64::MAX, validator_index: u64::MAX };
        let json = serde_json::to_string(&exit).unwrap();
        let deserialized: VoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(exit, deserialized);
    }

    #[test]
    fn test_signed_voluntary_exit_empty_signature() {
        let signed = SignedVoluntaryExit { message: sample_voluntary_exit(), signature: vec![] };
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedVoluntaryExit = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, deserialized);
    }
}
