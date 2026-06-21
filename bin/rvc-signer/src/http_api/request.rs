//! Web3Signer `POST /api/v1/eth2/sign/{identifier}` request envelope (FR-3, FR-15/16).
//!
//! One `serde` model decodes both Lighthouse and Prysm bodies for the four P0
//! `type` values. The shape is intentionally lenient (research R5): a
//! SCREAMING_SNAKE_CASE `type` discriminator, snake_case payload fields,
//! `fork_info` as `Option` (per-type enforcement lives in the dispatcher, not
//! here — `VALIDATOR_REGISTRATION` will omit it), and `signingRoot` accepted from
//! both `signingRoot` and `signing_root`, treated as absent when empty/zero.
//!
//! This module only *decodes*; the dispatcher (Issue 2.6) computes the domain +
//! signing root and enforces the per-type `fork_info` requirement.
//!
//! Consumed by `dispatch.rs` and the live `routes::sign` handler. The only
//! decoded-but-unread field is `BeaconBlockEnvelope::version` (the block signing
//! root comes from `block_header` + the `fork_info` domain), which carries a
//! narrow `allow(dead_code)`.

use serde::Deserialize;

use eth_types::{
    AggregateAndProof, AttestationData, BeaconBlockHeader, ContributionAndProof, Fork, Root,
    SyncCommitteeMessage,
};

/// `fork_info` wire object: `{ fork: { previous_version, current_version, epoch },
/// genesis_validators_root }`. Distinct from `eth_types::ForkInfo` (which
/// flattens differently); the inner `fork` reuses `eth_types::Fork` verbatim.
#[derive(Debug, Clone, Deserialize)]
pub struct WireForkInfo {
    pub fork: Fork,
    #[serde(deserialize_with = "hex32::deserialize")]
    pub genesis_validators_root: Root,
}

/// `beacon_block` payload (Bellatrix+): a `version` fork-name string plus the
/// `block_header`. Only `block_header` is hashed for the signing root; `version`
/// is decoded but not part of the root (the domain comes from `fork_info`).
#[derive(Debug, Clone, Deserialize)]
pub struct BeaconBlockEnvelope {
    /// Decoded for forward-compat but not hashed — the block signing root uses
    /// `block_header` + the `fork_info` domain, never `version`.
    #[allow(dead_code)]
    pub version: String,
    pub block_header: BeaconBlockHeader,
}

/// `randao_reveal` payload: a single quoted `epoch`.
#[derive(Debug, Clone, Deserialize)]
pub struct RandaoRevealPayload {
    #[serde(deserialize_with = "quoted_u64::deserialize")]
    pub epoch: u64,
}

/// `aggregation_slot` payload: a single quoted `slot`.
#[derive(Debug, Clone, Deserialize)]
pub struct AggregationSlotPayload {
    #[serde(deserialize_with = "quoted_u64::deserialize")]
    pub slot: u64,
}

/// The per-`type` payload, internally tagged by the `type` field. Only the four
/// P0 variants are defined here; P1/P2 add variants in later phases. An unknown
/// `type` fails to decode (no `#[serde(other)]`), surfacing as a `400`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum SignPayload {
    #[serde(rename = "BLOCK_V2")]
    BlockV2 { beacon_block: BeaconBlockEnvelope },
    #[serde(rename = "ATTESTATION")]
    Attestation { attestation: AttestationData },
    #[serde(rename = "RANDAO_REVEAL")]
    RandaoReveal { randao_reveal: RandaoRevealPayload },
    #[serde(rename = "AGGREGATION_SLOT")]
    AggregationSlot { aggregation_slot: AggregationSlotPayload },
    // ── P1 non-slashable arms (Issue 4.1) — existing eth-types objects ────────
    #[serde(rename = "AGGREGATE_AND_PROOF")]
    AggregateAndProof { aggregate_and_proof: AggregateAndProof },
    #[serde(rename = "SYNC_COMMITTEE_MESSAGE")]
    SyncCommitteeMessage { sync_committee_message: SyncCommitteeMessage },
    #[serde(rename = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF")]
    SyncCommitteeContributionAndProof { contribution_and_proof: ContributionAndProof },
}

/// The decoded sign request: common fields (`fork_info`, `signingRoot`) plus the
/// type-tagged payload flattened in, mirroring the flat wire object where
/// `type`, `fork_info`, `signingRoot`, and the payload key are all siblings.
#[derive(Debug, Clone, Deserialize)]
pub struct SignRequest {
    /// Optional at the serde layer; the dispatcher requires it for every P0 type.
    #[serde(default)]
    pub fork_info: Option<WireForkInfo>,
    /// `signingRoot` (camelCase) or `signing_root`. Absent or empty/`0x` → `None`
    /// (Prysm sends empty); a present 32-byte value is verified by the dispatcher
    /// only when non-zero (ADR-007).
    #[serde(
        default,
        rename = "signingRoot",
        alias = "signing_root",
        deserialize_with = "opt_hex32::deserialize"
    )]
    pub signing_root: Option<Root>,
    #[serde(flatten)]
    pub payload: SignPayload,
}

/// Deserialize a required `0x`-prefixed 32-byte hex string into `[u8; 32]`.
mod hex32 {
    use serde::{de, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut out)
            .map_err(|e| de::Error::custom(format!("invalid 32-byte hex: {e}")))?;
        Ok(out)
    }
}

/// Deserialize an optional `signingRoot`. Absent / empty / `"0x"` → `None`;
/// a present `0x`-prefixed 32-byte hex → `Some`; any other (wrong length, bad
/// hex) is an error (→ `400`). Distinguishing zero from absent is the
/// dispatcher's job (it skips verification when the value is all-zero).
mod opt_hex32 {
    use serde::{de, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(d: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(d)?;
        let Some(s) = opt else { return Ok(None) };
        let hex_str = s.strip_prefix("0x").unwrap_or(&s);
        if hex_str.is_empty() {
            return Ok(None); // Prysm may send an empty signingRoot.
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut out)
            .map_err(|e| de::Error::custom(format!("invalid signingRoot hex: {e}")))?;
        Ok(Some(out))
    }
}

/// Deserialize a quoted (`"123"`) unsigned integer, matching the `quoted_u64`
/// convention used across `eth-types` / the Beacon API.
mod quoted_u64 {
    use serde::{de, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(d: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        s.parse::<u64>().map_err(|e| de::Error::custom(format!("invalid quoted u64: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fork_info_json() -> &'static str {
        r#"{ "fork": { "previous_version": "0x03000000",
                       "current_version": "0x04000000",
                       "epoch": "100" },
             "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }"#
    }

    #[test]
    fn decodes_block_v2() {
        let body = format!(
            r#"{{ "type": "BLOCK_V2",
                  "fork_info": {fi},
                  "signingRoot": "0x{root}",
                  "beacon_block": {{ "version": "DENEB",
                                     "block_header": {{ "slot": "3000000",
                                                        "proposer_index": "12345",
                                                        "parent_root": "0x{r1}",
                                                        "state_root": "0x{r2}",
                                                        "body_root": "0x{r3}" }} }} }}"#,
            fi = fork_info_json(),
            root = "11".repeat(32),
            r1 = "aa".repeat(32),
            r2 = "bb".repeat(32),
            r3 = "cc".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert!(req.fork_info.is_some());
        assert_eq!(req.signing_root, Some([0x11u8; 32]));
        match req.payload {
            SignPayload::BlockV2 { beacon_block } => {
                assert_eq!(beacon_block.version, "DENEB");
                assert_eq!(beacon_block.block_header.slot, 3_000_000);
                assert_eq!(beacon_block.block_header.proposer_index, 12_345);
                assert_eq!(beacon_block.block_header.parent_root, [0xaau8; 32]);
            }
            other => panic!("expected BlockV2, got {other:?}"),
        }
    }

    #[test]
    fn decodes_attestation() {
        let body = format!(
            r#"{{ "type": "ATTESTATION",
                  "fork_info": {fi},
                  "signingRoot": "0x{root}",
                  "attestation": {{ "slot": "5",
                                    "index": "0",
                                    "beacon_block_root": "0x{r}",
                                    "source": {{ "epoch": "1", "root": "0x{r}" }},
                                    "target": {{ "epoch": "2", "root": "0x{r}" }} }} }}"#,
            fi = fork_info_json(),
            root = "22".repeat(32),
            r = "00".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.signing_root, Some([0x22u8; 32]));
        match req.payload {
            SignPayload::Attestation { attestation } => {
                assert_eq!(attestation.slot, 5);
                assert_eq!(attestation.source.epoch, 1);
                assert_eq!(attestation.target.epoch, 2);
            }
            other => panic!("expected Attestation, got {other:?}"),
        }
    }

    #[test]
    fn decodes_randao_reveal_and_aggregation_slot() {
        let randao = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "randao_reveal": {{ "epoch": "42" }} }}"#,
            fi = fork_info_json()
        );
        let req: SignRequest = serde_json::from_str(&randao).unwrap();
        assert!(req.signing_root.is_none(), "absent signingRoot decodes to None");
        match req.payload {
            SignPayload::RandaoReveal { randao_reveal } => assert_eq!(randao_reveal.epoch, 42),
            other => panic!("expected RandaoReveal, got {other:?}"),
        }

        let agg = format!(
            r#"{{ "type": "AGGREGATION_SLOT", "fork_info": {fi},
                  "aggregation_slot": {{ "slot": "77" }} }}"#,
            fi = fork_info_json()
        );
        let req: SignRequest = serde_json::from_str(&agg).unwrap();
        match req.payload {
            SignPayload::AggregationSlot { aggregation_slot } => {
                assert_eq!(aggregation_slot.slot, 77)
            }
            other => panic!("expected AggregationSlot, got {other:?}"),
        }
    }

    #[test]
    fn signing_root_accepts_snake_case_alias() {
        let body = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "signing_root": "0x{root}",
                  "randao_reveal": {{ "epoch": "1" }} }}"#,
            fi = fork_info_json(),
            root = "33".repeat(32),
        );
        let req: SignRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.signing_root, Some([0x33u8; 32]));
    }

    #[test]
    fn empty_signing_root_is_none_not_error() {
        // Prysm may send an empty signingRoot — must NOT fail to parse.
        for empty in ["\"\"", "\"0x\""] {
            let body = format!(
                r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                      "signingRoot": {empty},
                      "randao_reveal": {{ "epoch": "1" }} }}"#,
                fi = fork_info_json(),
            );
            let req: SignRequest = serde_json::from_str(&body).unwrap();
            assert!(req.signing_root.is_none(), "empty signingRoot {empty} must decode to None");
        }
    }

    #[test]
    fn unknown_type_fails_to_decode() {
        let body = r#"{ "type": "DEPOSIT", "deposit": {} }"#;
        let err = serde_json::from_str::<SignRequest>(body).unwrap_err();
        // Surfaces as a parse error the handler maps to 400.
        assert!(err.to_string().to_lowercase().contains("variant") || !err.to_string().is_empty());
    }

    #[test]
    fn malformed_signing_root_hex_errors() {
        let body = format!(
            r#"{{ "type": "RANDAO_REVEAL", "fork_info": {fi},
                  "signingRoot": "0xZZ",
                  "randao_reveal": {{ "epoch": "1" }} }}"#,
            fi = fork_info_json(),
        );
        assert!(serde_json::from_str::<SignRequest>(&body).is_err());
    }

    #[test]
    fn fork_info_optional_absent_decodes() {
        // fork_info absent is allowed at the serde layer (dispatcher enforces it).
        let body = r#"{ "type": "RANDAO_REVEAL", "randao_reveal": { "epoch": "1" } }"#;
        let req: SignRequest = serde_json::from_str(body).unwrap();
        assert!(req.fork_info.is_none());
    }
}
