//! Per-type signing-root computation engine (Issue 2.6 — FR-15, FR-16, ADR-007).
//!
//! The dispatcher turns a decoded [`SignRequest`] into a server-computed signing
//! root and the slashing-protection inputs the gate needs — **without** calling
//! the gate. For each `type` it selects the domain, computes
//! `compute_domain(domain_type, current_version, gvr)` then
//! `compute_signing_root(&msg, domain)` (the *dispatcher* owns the domain, not the
//! gate), and applies the `signingRoot` verification policy. The live `gate.sign_*`
//! call per type is wired in Issues 2.8–2.10, which consume the [`SignPlan`] this
//! produces.
//!
//! `signingRoot` policy (ADR-007): verify only when the client supplied a present,
//! non-zero 32-byte value; on mismatch return `400` and sign nothing. Absent or
//! all-zero → accept the server-computed root (Prysm may omit or zero the field).
//!
//! Per-type `fork_info`: all four P0 types require it (`400` if missing). The
//! requirement is enforced per arm so a future `VALIDATOR_REGISTRATION` arm (P1),
//! which derives its domain from a fixed builder fork version with a zero gvr, can
//! opt out without weakening the others.
//!
//! Security (SEC-INFO-01): every `BadRequest` this module emits is a fixed,
//! enumerated string. It never interpolates request bytes, serde/SSZ decoder text,
//! or filesystem paths into a client-visible body.
//!
//! Consumed by the live `routes::sign` handler (Issue 2.8), which calls
//! `plan_sign` and forwards the `SignPlan` to the matching gate method.

use crypto::{compute_domain, compute_signing_root};
use eth_types::{
    Root, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
};

use super::request::{SignPayload, SignRequest, WireForkInfo};
use super::response::HttpSignError;

/// The 32-byte zero root — a present-but-zero `signingRoot` means "do not verify".
const ZERO_ROOT: Root = [0u8; 32];

/// Slashing-protection inputs the gate needs, keyed by signing class. The live
/// `gate.sign_*` call per type is wired in Issues 2.8–2.10; this engine only
/// derives the inputs (its fields are read there, hence the transitional allow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Slashing {
    /// `sign_block` — slashable on `slot` (from the block header).
    Block { slot: u64, gvr: Root },
    /// `sign_attestation` — slashable on `(source_epoch, target_epoch)`.
    Attestation { source_epoch: u64, target_epoch: u64, gvr: Root },
    /// Non-slashable (`sign_randao_reveal`, `sign_selection_proof`): gate-check
    /// then sign the pre-computed root, no slashing DB.
    NonSlashable,
}

/// The dispatcher's output: the verified signing root the gate must sign, plus
/// the slashing inputs the per-type arm forwards to the matching `sign_*` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SignPlan {
    /// Server-computed signing root (equal to the client's `signingRoot` when one
    /// was supplied, non-zero, and verified).
    pub signing_root: Root,
    /// Slashing-protection inputs by class.
    pub slashing: Slashing,
}

/// Compute the server-side signing root for `req`, enforce the per-type
/// `fork_info` requirement, and apply the `signingRoot` verification policy
/// (FR-15, FR-16, ADR-007).
///
/// Returns the [`SignPlan`] for the gate (Issues 2.8–2.10), or a pre-gate
/// `400` ([`HttpSignError::BadRequest`]) that never reaches the gate. Every
/// `BadRequest` body is a fixed string (SEC-INFO-01).
pub(super) fn plan_sign(req: &SignRequest) -> Result<SignPlan, HttpSignError> {
    let (server_root, slashing) = match &req.payload {
        SignPayload::BlockV2 { beacon_block } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            let domain = compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, gvr);
            let root = compute_signing_root(&beacon_block.block_header, domain);
            (root, Slashing::Block { slot: beacon_block.block_header.slot, gvr })
        }
        SignPayload::Attestation { attestation } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            let domain = compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, gvr);
            let root = compute_signing_root(attestation, domain);
            let slashing = Slashing::Attestation {
                source_epoch: attestation.source.epoch,
                target_epoch: attestation.target.epoch,
                gvr,
            };
            (root, slashing)
        }
        SignPayload::RandaoReveal { randao_reveal } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            let domain = compute_domain(DOMAIN_RANDAO, fork_version, gvr);
            let root = compute_signing_root(&randao_reveal.epoch, domain);
            (root, Slashing::NonSlashable)
        }
        SignPayload::AggregationSlot { aggregation_slot } => {
            let (fork_version, gvr) = require_fork_info(req)?;
            let domain = compute_domain(DOMAIN_SELECTION_PROOF, fork_version, gvr);
            let root = compute_signing_root(&aggregation_slot.slot, domain);
            (root, Slashing::NonSlashable)
        }
    };

    verify_client_signing_root(req.signing_root, server_root)?;
    Ok(SignPlan { signing_root: server_root, slashing })
}

/// Require `fork_info` and return `(current_version, gvr)`. All four P0 types
/// require it; a future `VALIDATOR_REGISTRATION` arm computes its domain from a
/// fixed builder fork version with a zero gvr and does NOT call this.
fn require_fork_info(req: &SignRequest) -> Result<([u8; 4], Root), HttpSignError> {
    let fi: &WireForkInfo = req.fork_info.as_ref().ok_or_else(|| {
        HttpSignError::BadRequest("fork_info is required for this request type".to_string())
    })?;
    Ok((fi.fork.current_version, fi.genesis_validators_root))
}

/// Apply the `signingRoot` verification policy (FR-16, ADR-007).
fn verify_client_signing_root(
    client: Option<Root>,
    server_root: Root,
) -> Result<(), HttpSignError> {
    if let Some(client_root) = client {
        if client_root != ZERO_ROOT && client_root != server_root {
            return Err(HttpSignError::BadRequest(
                "signingRoot does not match the server-computed signing root".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn fork_info_json() -> &'static str {
        r#"{ "fork": { "previous_version": "0x03000000",
                       "current_version": "0x04000000",
                       "epoch": "100" },
             "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }"#
    }

    fn parse(body: &str) -> SignRequest {
        serde_json::from_str(body).expect("request fixture decodes")
    }

    fn block_v2(signing_root: Option<&str>) -> SignRequest {
        let sr = signing_root.map(|r| format!(r#""signingRoot": "{r}","#)).unwrap_or_default();
        parse(&format!(
            r#"{{ "type": "BLOCK_V2", "fork_info": {fi}, {sr}
                  "beacon_block": {{ "version": "DENEB",
                                     "block_header": {{ "slot": "3000000",
                                                        "proposer_index": "12345",
                                                        "parent_root": "0x{r1}",
                                                        "state_root": "0x{r2}",
                                                        "body_root": "0x{r3}" }} }} }}"#,
            fi = fork_info_json(),
            r1 = "aa".repeat(32),
            r2 = "bb".repeat(32),
            r3 = "cc".repeat(32),
        ))
    }

    fn attestation() -> SignRequest {
        parse(&format!(
            r#"{{ "type": "ATTESTATION", "fork_info": {fi},
                  "attestation": {{ "slot": "5", "index": "0",
                                    "beacon_block_root": "0x{r}",
                                    "source": {{ "epoch": "1", "root": "0x{r}" }},
                                    "target": {{ "epoch": "2", "root": "0x{r}" }} }} }}"#,
            fi = fork_info_json(),
            r = "00".repeat(32),
        ))
    }

    fn randao(with_fork_info: bool) -> SignRequest {
        let fi = if with_fork_info {
            format!(r#""fork_info": {},"#, fork_info_json())
        } else {
            String::new()
        };
        parse(&format!(
            r#"{{ "type": "RANDAO_REVEAL", {fi} "randao_reveal": {{ "epoch": "42" }} }}"#
        ))
    }

    fn aggregation_slot() -> SignRequest {
        parse(&format!(
            r#"{{ "type": "AGGREGATION_SLOT", "fork_info": {fi},
                  "aggregation_slot": {{ "slot": "77" }} }}"#,
            fi = fork_info_json(),
        ))
    }

    // Expected fork inputs from `fork_info_json()`.
    const CURRENT_VERSION: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
    fn expected_gvr() -> Root {
        let mut g = [0u8; 32];
        g[..16].copy_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);
        g[16..].copy_from_slice(&[
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);
        g
    }

    #[test]
    fn block_v2_uses_proposer_domain_and_block_header_root() {
        let req = block_v2(None);
        let plan = plan_sign(&req).expect("block plan");

        // Independently recompute the expected root from the header + proposer domain.
        let SignPayload::BlockV2 { beacon_block } = &req.payload else { panic!("block payload") };
        let domain = compute_domain(DOMAIN_BEACON_PROPOSER, CURRENT_VERSION, expected_gvr());
        let want = compute_signing_root(&beacon_block.block_header, domain);

        assert_eq!(plan.signing_root, want);
        assert_eq!(plan.slashing, Slashing::Block { slot: 3_000_000, gvr: expected_gvr() });
    }

    #[test]
    fn attestation_uses_attester_domain_and_carries_epochs() {
        let req = attestation();
        let plan = plan_sign(&req).expect("attestation plan");

        let SignPayload::Attestation { attestation } = &req.payload else { panic!("att payload") };
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, CURRENT_VERSION, expected_gvr());
        let want = compute_signing_root(attestation, domain);

        assert_eq!(plan.signing_root, want);
        assert_eq!(
            plan.slashing,
            Slashing::Attestation { source_epoch: 1, target_epoch: 2, gvr: expected_gvr() }
        );
    }

    #[test]
    fn randao_and_aggregation_slot_are_nonslashable_with_distinct_domains() {
        let randao_plan = plan_sign(&randao(true)).expect("randao plan");
        assert_eq!(randao_plan.slashing, Slashing::NonSlashable);
        let randao_want = compute_signing_root(
            &42u64,
            compute_domain(DOMAIN_RANDAO, CURRENT_VERSION, expected_gvr()),
        );
        assert_eq!(randao_plan.signing_root, randao_want);

        let agg_plan = plan_sign(&aggregation_slot()).expect("aggregation plan");
        assert_eq!(agg_plan.slashing, Slashing::NonSlashable);
        let agg_want = compute_signing_root(
            &77u64,
            compute_domain(DOMAIN_SELECTION_PROOF, CURRENT_VERSION, expected_gvr()),
        );
        assert_eq!(agg_plan.signing_root, agg_want);

        // RANDAO and AGGREGATION_SLOT must NOT collide on domain even for equal scalars.
        let r = compute_signing_root(
            &7u64,
            compute_domain(DOMAIN_RANDAO, CURRENT_VERSION, expected_gvr()),
        );
        let a = compute_signing_root(
            &7u64,
            compute_domain(DOMAIN_SELECTION_PROOF, CURRENT_VERSION, expected_gvr()),
        );
        assert_ne!(r, a, "different domains must yield different signing roots");
    }

    #[test]
    fn matching_signing_root_proceeds() {
        // Compute the true server root first, then resubmit it as the client's.
        let server_root = plan_sign(&block_v2(None)).unwrap().signing_root;
        let req = block_v2(Some(&format!("0x{}", hex::encode(server_root))));
        let plan = plan_sign(&req).expect("matching signingRoot proceeds");
        assert_eq!(plan.signing_root, server_root);
    }

    #[test]
    fn mismatching_signing_root_is_400_and_no_plan() {
        let bad = format!("0x{}", "ff".repeat(32));
        let err = plan_sign(&block_v2(Some(&bad))).expect_err("mismatch must 400");
        let (status, _) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn absent_or_zero_signing_root_proceeds() {
        // Absent.
        assert!(plan_sign(&block_v2(None)).is_ok(), "absent signingRoot proceeds");
        // Present but all-zero → treated as "do not verify" (Prysm may zero it).
        let zero = format!("0x{}", "00".repeat(32));
        assert!(plan_sign(&block_v2(Some(&zero))).is_ok(), "zero signingRoot proceeds");
    }

    #[test]
    fn missing_fork_info_is_400() {
        let err = plan_sign(&randao(false)).expect_err("missing fork_info must 400");
        let (status, _) = err.status_and_body();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// SEC-INFO-01: `BadRequest` bodies are fixed, enumerated strings — never
    /// interpolating request-derived data (the supplied bad root, decoder text).
    #[test]
    fn bad_request_bodies_are_static_and_leak_free() {
        let bad_hex = "ff".repeat(32);
        let (_, mismatch_body) =
            plan_sign(&block_v2(Some(&format!("0x{bad_hex}")))).unwrap_err().status_and_body();
        assert_eq!(mismatch_body, "signingRoot does not match the server-computed signing root");
        assert!(!mismatch_body.contains(&bad_hex), "must not echo the supplied root");
        assert!(!mismatch_body.contains("0x"), "no hex/material in the body");

        let (_, missing_body) = plan_sign(&randao(false)).unwrap_err().status_and_body();
        assert_eq!(missing_body, "fork_info is required for this request type");
    }
}
