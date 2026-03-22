use beacon::AttesterDuty;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{Root, Slot};
use timing::SLOTS_PER_EPOCH;
use tracing::warn;

use super::error::OrchestratorError;
use super::service::PubkeyMap;

/// Constructs a hex-encoded SSZ bitlist where only the validator's position
/// in the committee is set (pre-Electra aggregation_bits format).
pub(crate) fn make_aggregation_bits(duty: &AttesterDuty) -> Option<String> {
    let committee_length: usize = match duty.committee_length.parse() {
        Ok(0) => {
            warn!(
                validator_index = %duty.validator_index,
                "committee_length is 0, cannot produce aggregation bits"
            );
            return None;
        }
        Ok(v) => v,
        Err(e) => {
            warn!(
                validator_index = %duty.validator_index,
                raw_value = %duty.committee_length,
                error = %e,
                "failed to parse committee_length, skipping duty"
            );
            return None;
        }
    };

    let validator_committee_index: usize = match duty.validator_committee_index.parse() {
        Ok(v) => v,
        Err(e) => {
            warn!(
                validator_index = %duty.validator_index,
                raw_value = %duty.validator_committee_index,
                error = %e,
                "failed to parse validator_committee_index, skipping duty"
            );
            return None;
        }
    };

    // SSZ bitlist: ceil((committee_length + 1) / 8) bytes
    // The "+1" is for the length bit at position committee_length
    let byte_count = (committee_length + 8) / 8;
    let mut bits = vec![0u8; byte_count];

    // Set the validator's bit
    if validator_committee_index < committee_length {
        bits[validator_committee_index / 8] |= 1 << (validator_committee_index % 8);
    }

    // Set the length bit (sentinel) at position committee_length
    bits[committee_length / 8] |= 1 << (committee_length % 8);

    Some(format!("0x{}", hex::encode(bits)))
}

/// Finds a public key by matching against duty pubkey.
///
/// Pubkeys are matched case-insensitively and with/without "0x" prefix.
pub(crate) fn find_pubkey(pubkey_map: &PubkeyMap, duty_pubkey: &str) -> Option<PublicKey> {
    let pubkey_map = pubkey_map.read();

    // Try exact match first
    if let Some(pk) = pubkey_map.get(duty_pubkey) {
        return Some(pk.clone());
    }

    // Try with/without 0x prefix
    let normalized_pubkey = if duty_pubkey.starts_with("0x") {
        duty_pubkey.to_string()
    } else {
        format!("0x{}", duty_pubkey)
    };

    if let Some(pk) = pubkey_map.get(&normalized_pubkey) {
        return Some(pk.clone());
    }

    // Normalize for case-insensitive matching
    let duty_normalized = normalize_pubkey(duty_pubkey);

    for (key, pk) in pubkey_map.iter() {
        if normalize_pubkey(key) == duty_normalized {
            return Some(pk.clone());
        }
    }

    None
}

/// Normalizes a pubkey to lowercase without 0x/0X prefix for comparison.
pub(crate) fn normalize_pubkey(pubkey: &str) -> String {
    let without_prefix =
        pubkey.strip_prefix("0x").or_else(|| pubkey.strip_prefix("0X")).unwrap_or(pubkey);
    without_prefix.to_lowercase()
}

pub(crate) fn convert_attestation_data(
    beacon_data: &beacon::AttestationData,
) -> Result<eth_types::AttestationData, OrchestratorError> {
    let slot: u64 = beacon_data
        .slot
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid slot".to_string()))?;

    let index: u64 = beacon_data
        .index
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid index".to_string()))?;

    let beacon_block_root = parse_hex_root(&beacon_data.beacon_block_root)?;

    let source_epoch: u64 = beacon_data
        .source
        .epoch
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid source epoch".to_string()))?;

    let source_root = parse_hex_root(&beacon_data.source.root)?;

    let target_epoch: u64 = beacon_data
        .target
        .epoch
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid target epoch".to_string()))?;

    let target_root = parse_hex_root(&beacon_data.target.root)?;

    Ok(eth_types::AttestationData {
        slot,
        index,
        beacon_block_root,
        source: eth_types::Checkpoint { epoch: source_epoch, root: source_root },
        target: eth_types::Checkpoint { epoch: target_epoch, root: target_root },
    })
}

pub(crate) fn parse_hex_root(hex_str: &str) -> Result<Root, OrchestratorError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    let bytes = hex::decode(hex_str)
        .map_err(|e| OrchestratorError::ParseError(format!("Invalid hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(OrchestratorError::ParseError(format!(
            "Invalid root length: expected 32, got {}",
            bytes.len()
        )));
    }

    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Ok(root)
}

pub(crate) async fn get_duties_for_slot(
    pubkey_map: &PubkeyMap,
    duty_tracker: &DutyTracker,
    slot: Slot,
) -> Result<Vec<AttesterDuty>, OrchestratorError> {
    let pubkey_snapshot = pubkey_map.read().clone();
    if pubkey_snapshot.is_empty() {
        return Ok(Vec::new());
    }

    let epoch = slot / SLOTS_PER_EPOCH;

    if !duty_tracker.is_epoch_cached(epoch).await {
        duty_tracker.fetch_duties_for_epoch(epoch).await?;
    }

    let normalized_pubkeys: std::collections::HashSet<String> =
        pubkey_snapshot.keys().map(|k| normalize_pubkey(k)).collect();

    let all_duties = duty_tracker.get_duties_for_slot(slot).await;
    let duties: Vec<AttesterDuty> = all_duties
        .into_iter()
        .filter(|duty| {
            let normalized_duty_pubkey = normalize_pubkey(&duty.pubkey);
            normalized_pubkeys.contains(&normalized_duty_pubkey)
        })
        .collect();

    Ok(duties)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_root_with_prefix() {
        let root =
            parse_hex_root("0x1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        assert_eq!(root, [0x11; 32]);
    }

    #[test]
    fn test_parse_hex_root_without_prefix() {
        let root =
            parse_hex_root("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        assert_eq!(root, [0x22; 32]);
    }

    #[test]
    fn test_parse_hex_root_invalid_length() {
        let result = parse_hex_root("0x1111111111");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_root_invalid_hex() {
        let result = parse_hex_root("0xgggggggg");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_attestation_data_success() {
        let beacon_data = beacon::AttestationData {
            slot: "1000".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let crypto_data = convert_attestation_data(&beacon_data).unwrap();

        assert_eq!(crypto_data.slot, 1000);
        assert_eq!(crypto_data.index, 5);
        assert_eq!(crypto_data.beacon_block_root, [0x11; 32]);
        assert_eq!(crypto_data.source.epoch, 100);
        assert_eq!(crypto_data.source.root, [0x22; 32]);
        assert_eq!(crypto_data.target.epoch, 101);
        assert_eq!(crypto_data.target.root, [0x33; 32]);
    }

    #[test]
    fn test_convert_attestation_data_invalid_slot() {
        let beacon_data = beacon::AttestationData {
            slot: "invalid".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let result = convert_attestation_data(&beacon_data);
        assert!(result.is_err());
    }
}
