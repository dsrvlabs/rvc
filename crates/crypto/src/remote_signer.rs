use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize, Serializer};
use tracing::Instrument;

use url::Url;

use super::bls::{PublicKey, Signature, PUBLIC_KEY_BYTES_LEN};
use super::insecure::{InsecureGate, InsecureMode};
use super::signer_trait::{Signer, SigningError};
use super::signing::{compute_domain, compute_signing_root};
use super::typed_signer::{SignContext, TypedSigner};
use crate::logging::TruncatedPubkey;
use eth_types::{
    blinded_body_tree_hash_root, body_tree_hash_root, AggregateAndProof, AttestationData,
    BeaconBlock, BeaconBlockHeader, BlindedBeaconBlock, ContributionAndProof, Epoch, Fork, Root,
    Slot, SyncCommitteeMessage, ValidatorRegistrationV1, VoluntaryExit, DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};

/// Environment variable that must be set to `"true"` to allow plaintext
/// `http://` remote-signer URLs.  `https://` URLs always pass without
/// consulting this variable.
pub const REMOTE_SIGNER_INSECURE_ENV_VAR: &str = "RVC_REMOTE_SIGNER_ALLOW_INSECURE";

/// Gate `url` against the plaintext-URL policy.
///
/// - `https://` URLs pass immediately — no env-var check, no log.
/// - Any other scheme (e.g. `http://`) is evaluated by [`InsecureGate`]:
///   - `mode = Warn` (Phase 2 default): emits an `error!`-level log and
///     returns `Ok(())` so existing deployments are not hard-broken.
///   - `mode = Refuse` (Phase 3, ISSUE-3.13): returns
///     `Err(SigningError::RemoteSignerError(...))` unless the operator has set
///     `RVC_REMOTE_SIGNER_ALLOW_INSECURE=true`.
///
/// The predicate passed to the gate is `|| true`: the scheme check is already
/// done above, so the remaining question is purely "has the operator opted
/// in via the env var?".  Predicate `true` means the gate's combined
/// condition (`env_ok && pred_ok`) becomes `env_ok`, giving clean opt-in
/// semantics.
pub fn check_remote_signer_url(url: &str, mode: InsecureMode) -> Result<(), SigningError> {
    if url.trim_end_matches('/').starts_with("https://") {
        return Ok(());
    }
    InsecureGate::with_predicate(REMOTE_SIGNER_INSECURE_ENV_VAR, mode, || true)
        .check()
        .map_err(|e| SigningError::RemoteSignerError(e.to_string()))
}

fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        if parsed.password().is_some() || !parsed.username().is_empty() {
            let _ = parsed.set_username("***");
            let _ = parsed.set_password(Some("***"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

const DEFAULT_TIMEOUT_SECS: u64 = 12;

#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    pub url: String,
    pub timeout: Duration,
}

impl RemoteSignerConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

pub struct RemoteSigner {
    client: Client,
    url: String,
    pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
}

impl RemoteSigner {
    pub fn new(
        config: RemoteSignerConfig,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    ) -> Result<Self, SigningError> {
        let url = config.url.trim_end_matches('/').to_string();

        // Gate plaintext URLs. Per NFR-10 / ISSUE-3.13 (GA) the gate refuses
        // http:// URLs unless RVC_REMOTE_SIGNER_ALLOW_INSECURE=true is set.
        check_remote_signer_url(&url, InsecureMode::Refuse)?;

        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| SigningError::RemoteSignerError(e.to_string()))?;

        Ok(Self { client, url, pubkeys })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Creates a `RemoteSigner` without running the insecure-URL gate check.
    ///
    /// **For unit tests only.**  Production callers must use [`Self::new`],
    /// which enforces the `InsecureMode::Refuse` gate (ISSUE-3.13 / NFR-10).
    #[cfg(test)]
    pub(crate) fn new_unchecked(
        config: RemoteSignerConfig,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    ) -> Self {
        let url = config.url.trim_end_matches('/').to_string();
        let client =
            Client::builder().timeout(config.timeout).build().expect("test http client build");
        Self { client, url, pubkeys }
    }
}

// ── Web3Signer HTTP request body (serialize side of rvc-signer request.rs) ──
//
// SEC-8: the Consensys / ethereum remote-signing-api contract requires a
// `type`-tagged body with camelCase `signingRoot` plus the per-type payload.
// A bare `{signing_root}` is rejected by every real Web3Signer. Shape mirrors
// `bin/rvc-signer/src/http_api/request.rs` (read-only reference).

/// Wire `fork_info` object: `{ fork: { previous_version, current_version, epoch },
/// genesis_validators_root }`.
#[derive(Debug, Clone, Serialize)]
pub struct WireForkInfo {
    pub fork: Fork,
    #[serde(serialize_with = "serialize_root_hex")]
    pub genesis_validators_root: Root,
}

impl WireForkInfo {
    /// Build from a signing [`SignContext`]'s fork versions + gvr.
    ///
    /// `fork.epoch` is not carried on [`eth_types::ForkInfo`]; the server only
    /// uses `current_version` + gvr for domain computation, so epoch is `0`.
    pub fn from_sign_context(ctx: &SignContext) -> Self {
        Self {
            fork: Fork {
                previous_version: ctx.fork_info.previous_version,
                current_version: ctx.fork_info.current_version,
                epoch: 0,
            },
            genesis_validators_root: ctx.fork_info.genesis_validators_root,
        }
    }
}

/// `beacon_block` payload for `BLOCK_V2`.
#[derive(Debug, Clone, Serialize)]
pub struct BeaconBlockEnvelope {
    pub version: String,
    pub block_header: BeaconBlockHeader,
}

/// `randao_reveal` payload: a single quoted `epoch`.
#[derive(Debug, Clone, Serialize)]
pub struct RandaoRevealPayload {
    #[serde(serialize_with = "serialize_quoted_u64")]
    pub epoch: u64,
}

/// `aggregation_slot` payload: a single quoted `slot`.
#[derive(Debug, Clone, Serialize)]
pub struct AggregationSlotPayload {
    #[serde(serialize_with = "serialize_quoted_u64")]
    pub slot: u64,
}

/// `sync_aggregator_selection_data` payload: `{slot, subcommittee_index}`.
#[derive(Debug, Clone, Serialize)]
pub struct SyncSelectionPayload {
    #[serde(serialize_with = "serialize_quoted_u64")]
    pub slot: u64,
    #[serde(serialize_with = "serialize_quoted_u64")]
    pub subcommittee_index: u64,
}

/// Per-`type` payload, internally tagged — matches server `SignPayload`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Web3SignerPayload {
    #[serde(rename = "BLOCK_V2")]
    BlockV2 { beacon_block: BeaconBlockEnvelope },
    #[serde(rename = "ATTESTATION")]
    Attestation { attestation: AttestationData },
    #[serde(rename = "RANDAO_REVEAL")]
    RandaoReveal { randao_reveal: RandaoRevealPayload },
    #[serde(rename = "AGGREGATION_SLOT")]
    AggregationSlot { aggregation_slot: AggregationSlotPayload },
    #[serde(rename = "AGGREGATE_AND_PROOF")]
    AggregateAndProof { aggregate_and_proof: AggregateAndProof },
    #[serde(rename = "SYNC_COMMITTEE_MESSAGE")]
    SyncCommitteeMessage { sync_committee_message: SyncCommitteeMessage },
    #[serde(rename = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF")]
    SyncCommitteeContributionAndProof { contribution_and_proof: ContributionAndProof },
    #[serde(rename = "SYNC_COMMITTEE_SELECTION_PROOF")]
    SyncCommitteeSelectionProof { sync_aggregator_selection_data: SyncSelectionPayload },
    #[serde(rename = "VALIDATOR_REGISTRATION")]
    ValidatorRegistration { validator_registration: ValidatorRegistrationV1 },
    #[serde(rename = "VOLUNTARY_EXIT")]
    VoluntaryExit { voluntary_exit: VoluntaryExit },
    // Electra aggregate is not on TypedSigner yet; builders for future use.
    // Raw-root and any other unlisted duty return UnsupportedSigningType.
}

impl Web3SignerPayload {
    /// Web3Signer `type` discriminator (e.g. `"ATTESTATION"`).
    pub fn type_name(&self) -> &'static str {
        match self {
            Web3SignerPayload::BlockV2 { .. } => "BLOCK_V2",
            Web3SignerPayload::Attestation { .. } => "ATTESTATION",
            Web3SignerPayload::RandaoReveal { .. } => "RANDAO_REVEAL",
            Web3SignerPayload::AggregationSlot { .. } => "AGGREGATION_SLOT",
            Web3SignerPayload::AggregateAndProof { .. } => "AGGREGATE_AND_PROOF",
            Web3SignerPayload::SyncCommitteeMessage { .. } => "SYNC_COMMITTEE_MESSAGE",
            Web3SignerPayload::SyncCommitteeContributionAndProof { .. } => {
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
            }
            Web3SignerPayload::SyncCommitteeSelectionProof { .. } => {
                "SYNC_COMMITTEE_SELECTION_PROOF"
            }
            Web3SignerPayload::ValidatorRegistration { .. } => "VALIDATOR_REGISTRATION",
            Web3SignerPayload::VoluntaryExit { .. } => "VOLUNTARY_EXIT",
        }
    }
}

/// Fully-formed Web3Signer sign request: `type` + optional `fork_info` +
/// camelCase `signingRoot` + per-type payload (siblings on the wire object).
#[derive(Debug, Clone, Serialize)]
pub struct Web3SignerSignRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_info: Option<WireForkInfo>,
    #[serde(rename = "signingRoot")]
    pub signing_root: String,
    #[serde(flatten)]
    pub payload: Web3SignerPayload,
}

impl Web3SignerSignRequest {
    fn with_fork(fork_info: WireForkInfo, signing_root: &Root, payload: Web3SignerPayload) -> Self {
        Self { fork_info: Some(fork_info), signing_root: root_hex(signing_root), payload }
    }

    fn without_fork(signing_root: &Root, payload: Web3SignerPayload) -> Self {
        Self { fork_info: None, signing_root: root_hex(signing_root), payload }
    }

    /// Exact JSON body for contract tests / wire inspection.
    pub fn to_json_value(&self) -> Result<serde_json::Value, SigningError> {
        serde_json::to_value(self)
            .map_err(|e| SigningError::RemoteSignerError(format!("serialize sign body: {e}")))
    }
}

fn root_hex(root: &Root) -> String {
    format!("0x{}", hex::encode(root))
}

fn serialize_root_hex<S: Serializer>(root: &Root, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&root_hex(root))
}

fn serialize_quoted_u64<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

fn fork_version_label(version: [u8; 4]) -> &'static str {
    // Label only — not hashed. Matches common mainnet/testnet version bytes.
    match version {
        [0, 0, 0, 0] => "PHASE0",
        [1, 0, 0, 0] => "ALTAIR",
        [2, 0, 0, 0] => "BELLATRIX",
        [3, 0, 0, 0] => "CAPELLA",
        [4, 0, 0, 0] => "DENEB",
        [5, 0, 0, 0] => "ELECTRA",
        [6, 0, 0, 0] => "FULU",
        _ => "UNKNOWN",
    }
}

fn header_from_beacon_block(block: &BeaconBlock) -> Result<BeaconBlockHeader, SigningError> {
    let body_root = body_tree_hash_root(&block.body).map_err(|e| {
        SigningError::RemoteSignerError(format!("invalid beacon block body for BLOCK_V2: {e}"))
    })?;
    Ok(BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root: body_root.0,
    })
}

fn header_from_blinded_block(
    block: &BlindedBeaconBlock,
) -> Result<BeaconBlockHeader, SigningError> {
    let body_root = blinded_body_tree_hash_root(&block.body).map_err(|e| {
        SigningError::RemoteSignerError(format!("invalid blinded block body for BLOCK_V2: {e}"))
    })?;
    Ok(BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body_root: body_root.0,
    })
}

/// Build a `BLOCK_V2` request for a full beacon block.
pub fn build_block_v2_request(
    block: &BeaconBlock,
    ctx: &SignContext,
) -> Result<(Web3SignerSignRequest, Root), SigningError> {
    let header = header_from_beacon_block(block)?;
    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&header, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::BlockV2 {
            beacon_block: BeaconBlockEnvelope {
                version: fork_version_label(ctx.fork_info.current_version).to_string(),
                block_header: header,
            },
        },
    );
    Ok((req, signing_root))
}

/// Build a `BLOCK_V2` request for a blinded beacon block.
pub fn build_blinded_block_v2_request(
    block: &BlindedBeaconBlock,
    ctx: &SignContext,
) -> Result<(Web3SignerSignRequest, Root), SigningError> {
    let header = header_from_blinded_block(block)?;
    let domain = compute_domain(
        DOMAIN_BEACON_PROPOSER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&header, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::BlockV2 {
            beacon_block: BeaconBlockEnvelope {
                version: fork_version_label(ctx.fork_info.current_version).to_string(),
                block_header: header,
            },
        },
    );
    Ok((req, signing_root))
}

/// Build an `ATTESTATION` request.
pub fn build_attestation_request(
    data: &AttestationData,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        DOMAIN_BEACON_ATTESTER,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(data, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::Attestation { attestation: data.clone() },
    );
    (req, signing_root)
}

/// Build a `RANDAO_REVEAL` request.
pub fn build_randao_reveal_request(
    epoch: Epoch,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        DOMAIN_RANDAO,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&epoch, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::RandaoReveal { randao_reveal: RandaoRevealPayload { epoch } },
    );
    (req, signing_root)
}

/// Build an `AGGREGATE_AND_PROOF` request.
pub fn build_aggregate_and_proof_request(
    agg: &AggregateAndProof,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        DOMAIN_AGGREGATE_AND_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(agg, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::AggregateAndProof { aggregate_and_proof: agg.clone() },
    );
    (req, signing_root)
}

/// Build a `SYNC_COMMITTEE_MESSAGE` request.
pub fn build_sync_committee_message_request(
    slot: Slot,
    beacon_block_root: Root,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    // Server signs the block root itself (not the message container).
    let signing_root = compute_signing_root(&beacon_block_root, domain);
    let msg = SyncCommitteeMessage {
        slot,
        beacon_block_root,
        // Not part of the signed object; placeholder for the wire envelope.
        validator_index: 0,
        signature: vec![0u8; 96],
    };
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::SyncCommitteeMessage { sync_committee_message: msg },
    );
    (req, signing_root)
}

/// Build a `SYNC_COMMITTEE_SELECTION_PROOF` request.
pub fn build_sync_selection_proof_request(
    slot: Slot,
    subcommittee_index: u64,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let selection = eth_types::SyncAggregatorSelectionData { slot, subcommittee_index };
    let signing_root = compute_signing_root(&selection, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::SyncCommitteeSelectionProof {
            sync_aggregator_selection_data: SyncSelectionPayload { slot, subcommittee_index },
        },
    );
    (req, signing_root)
}

/// Build a `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` request.
pub fn build_contribution_and_proof_request(
    c: &ContributionAndProof,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        DOMAIN_CONTRIBUTION_AND_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(c, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::SyncCommitteeContributionAndProof { contribution_and_proof: c.clone() },
    );
    (req, signing_root)
}

/// Build a `VALIDATOR_REGISTRATION` request (no `fork_info` — ADR-008).
pub fn build_validator_registration_request(
    reg: &ValidatorRegistrationV1,
    genesis_fork_version: [u8; 4],
) -> (Web3SignerSignRequest, Root) {
    let zero_gvr = [0u8; 32];
    let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_gvr);
    let signing_root = compute_signing_root(reg, domain);
    let req = Web3SignerSignRequest::without_fork(
        &signing_root,
        Web3SignerPayload::ValidatorRegistration { validator_registration: reg.clone() },
    );
    (req, signing_root)
}

/// Build a `VOLUNTARY_EXIT` request.
pub fn build_voluntary_exit_request(
    exit: &VoluntaryExit,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        DOMAIN_VOLUNTARY_EXIT,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(exit, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::VoluntaryExit { voluntary_exit: exit.clone() },
    );
    (req, signing_root)
}

/// Build an `AGGREGATION_SLOT` request (attestation selection proof).
pub fn build_aggregation_slot_request(
    slot: Slot,
    ctx: &SignContext,
) -> (Web3SignerSignRequest, Root) {
    let domain = compute_domain(
        eth_types::DOMAIN_SELECTION_PROOF,
        ctx.fork_info.current_version,
        ctx.fork_info.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&slot, domain);
    let req = Web3SignerSignRequest::with_fork(
        WireForkInfo::from_sign_context(ctx),
        &signing_root,
        Web3SignerPayload::AggregationSlot { aggregation_slot: AggregationSlotPayload { slot } },
    );
    (req, signing_root)
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

impl RemoteSigner {
    /// POST a fully-typed Web3Signer body and re-verify the returned signature
    /// against `signing_root` (SEC-8). Never sends a bare `{signing_root}` body.
    pub async fn sign_request(
        &self,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
        request: &Web3SignerSignRequest,
        signing_root: &Root,
    ) -> Result<Signature, SigningError> {
        if !self.pubkeys.contains(pubkey) {
            return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
        }

        let identifier = format!("0x{}", hex::encode(pubkey));
        let url = format!("{}/api/v1/eth2/sign/{}", self.url, identifier);

        // Logged URL truncates the pubkey path segment; the real request uses `url`.
        let log_url =
            format!("{}/api/v1/eth2/sign/{}", self.url, TruncatedPubkey::new(&identifier));

        let span = tracing::info_span!(
            "sign.remote",
            http.method = "POST",
            http.url = %redact_url(&log_url),
            http.status_code = tracing::field::Empty,
            signer_type = "remote",
            web3signer_type = request.payload.type_name(),
        );

        async {
            let response = self.client.post(&url).json(request).send().await.map_err(|e| {
                SigningError::RemoteSignerError(format!("HTTP request failed: {e}"))
            })?;

            let status = response.status();
            tracing::Span::current().record("http.status_code", status.as_u16());

            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(SigningError::RemoteSignerError(format!(
                    "Web3Signer returned {status}: {body}"
                )));
            }

            let sign_response: SignResponse = response.json().await.map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid response body: {e}"))
            })?;

            let sig_hex =
                sign_response.signature.strip_prefix("0x").unwrap_or(&sign_response.signature);
            let sig_bytes = hex::decode(sig_hex).map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid signature hex: {e}"))
            })?;

            let signature = Signature::from_bytes(&sig_bytes).map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid BLS signature: {e}"))
            })?;

            let pk = PublicKey::from_bytes(pubkey)
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid public key: {e}")))?;
            if signature.verify(&pk, signing_root).is_err() {
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                    "Remote signer returned invalid signature"
                );
                return Err(SigningError::InvalidRemoteSignature);
            }

            Ok(signature)
        }
        .instrument(span)
        .await
    }
}

#[async_trait]
impl Signer for RemoteSigner {
    /// Raw-root signing is intentionally unsupported for Web3Signer HTTP
    /// (SEC-8). A bare root cannot produce a type-tagged contract body — use
    /// [`TypedSigner`] methods (or [`RemoteSigner::sign_request`]) instead.
    async fn sign(
        &self,
        _signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        if !self.pubkeys.contains(pubkey) {
            return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
        }
        Err(SigningError::UnsupportedSigningType(
            "raw-root signing is not supported for Web3Signer HTTP; \
             use TypedSigner::sign_block / sign_attestation / etc."
                .to_string(),
        ))
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.pubkeys.clone()
    }
}

#[async_trait]
impl TypedSigner for RemoteSigner {
    async fn sign_block(
        &self,
        block: &BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_block_v2_request(block, ctx)?;
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_blinded_block(
        &self,
        block: &BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_blinded_block_v2_request(block, ctx)?;
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_attestation_request(data, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_aggregate_and_proof_request(agg, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_sync_committee_message(
        &self,
        slot: Slot,
        beacon_block_root: Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) =
            build_sync_committee_message_request(slot, beacon_block_root, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_sync_selection_proof_request(slot, subcommittee_index, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_contribution_and_proof_request(c, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_validator_registration_request(reg, genesis_fork_version);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_randao_reveal_request(epoch, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_voluntary_exit_request(exit, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }
}

#[cfg(test)]
// RF1-12: unit tests mutate env via unsafe set_var/remove_var.
#[allow(unsafe_code)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;
    use crate::SecretKey;
    use eth_types::{Checkpoint, ForkInfo};
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Serialise tests in this module that read or mutate
    /// `RVC_REMOTE_SIGNER_ALLOW_INSECURE`.  Without this lock, parallel
    /// cargo-test execution can race a sibling test setting the var while
    /// `test_remote_signer_refuses_http_url_without_env_var` is running and
    /// silently weaken the GA Refuse contract guard (review MF-3).
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn test_fork_info() -> ForkInfo {
        ForkInfo {
            previous_version: [0x03, 0x00, 0x00, 0x00],
            current_version: [0x04, 0x00, 0x00, 0x00], // DENEB
            genesis_validators_root: [0xaa; 32],
        }
    }

    fn test_ctx(sk: &SecretKey) -> SignContext {
        SignContext { pubkey: sk.public_key(), fork_info: test_fork_info() }
    }

    fn sample_attestation() -> AttestationData {
        AttestationData {
            slot: 5,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 1, root: [0x22; 32] },
            target: Checkpoint { epoch: 2, root: [0x33; 32] },
        }
    }

    /// Mock Web3Signer that returns a valid BLS sig for the attestation root.
    async fn mock_attestation_signer(
        sk: &SecretKey,
    ) -> (MockServer, RemoteSigner, AttestationData, SignContext, Root) {
        let pk_bytes = sk.public_key().to_bytes();
        let ctx = test_ctx(sk);
        let data = sample_attestation();
        let (req, signing_root) = build_attestation_request(&data, &ctx);
        let _ = req; // body asserted in dedicated contract tests
        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        (mock_server, signer, data, ctx, signing_root)
    }

    #[test]
    fn test_remote_signer_config_defaults() {
        let config = RemoteSignerConfig::new("http://localhost:9000");
        assert_eq!(config.url, "http://localhost:9000");
        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    #[test]
    fn test_remote_signer_config_custom_timeout() {
        let config =
            RemoteSignerConfig::new("http://localhost:9000").with_timeout(Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_remote_signer_public_keys_returns_configured_keys() {
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![pk]);

        let keys = signer.public_keys();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], pk);
    }

    #[tokio::test]
    async fn test_remote_signer_sign_success() {
        let sk = SecretKey::generate();
        let (_mock, signer, data, ctx, signing_root) = mock_attestation_signer(&sk).await;
        let expected_sig = sk.sign(&signing_root);

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_bytes(), expected_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_remote_signer_sign_server_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "internal"})),
            )
            .mount(&mock_server)
            .await;

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("500"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_key_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"error": "Key not found"})),
            )
            .mount(&mock_server)
            .await;

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("404"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_invalid_signature_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"signature": "0xinvalid"})),
            )
            .mount(&mock_server)
            .await;

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("invalid signature hex"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_connection_refused() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let config = RemoteSignerConfig::new("http://127.0.0.1:1");
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("HTTP request failed"));
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_sign_unknown_pubkey_returns_key_not_found() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let unknown_sk = SecretKey::generate();
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        let ctx = SignContext { pubkey: unknown_sk.public_key(), fork_info: test_fork_info() };
        let data = sample_attestation();

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::KeyNotFound(pk_hex) => {
                assert_eq!(pk_hex, hex::encode(unknown_sk.public_key().to_bytes()));
            }
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_object_safety() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;
        // Rebuild as trait object — TypedSigner is the Web3Signer path (SEC-8).
        let config = RemoteSignerConfig::new(signer.url());
        let typed: Box<dyn TypedSigner> =
            Box::new(RemoteSigner::new_unchecked(config, vec![pk_bytes]));

        let sig = TypedSigner::sign_attestation(typed.as_ref(), &data, &ctx).await.unwrap();
        assert_eq!(sig.to_bytes().len(), 96);
    }

    #[tokio::test]
    async fn test_remote_signer_raw_sign_returns_unsupported() {
        let pk_bytes = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = Signer::sign(&signer, &[0xab; 32], &pk_bytes).await;
        match result.unwrap_err() {
            SigningError::UnsupportedSigningType(msg) => {
                assert!(msg.contains("TypedSigner"), "msg={msg}");
            }
            other => panic!("expected UnsupportedSigningType, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_strips_trailing_slash_from_url() {
        let config = RemoteSignerConfig::new("http://localhost:9000/");
        let signer = RemoteSigner::new_unchecked(config, vec![]);
        assert_eq!(signer.url(), "http://localhost:9000");
    }

    #[tokio::test]
    async fn test_remote_signer_empty_public_keys() {
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![]);
        assert!(signer.public_keys().is_empty());
    }

    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;

    struct SpanCapture {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpanCapture {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            self.spans.lock().unwrap().push(attrs.metadata().name().to_string());
        }
    }

    #[tokio::test]
    async fn test_sign_creates_remote_span() {
        let sk = SecretKey::generate();
        let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;

        let spans = Arc::new(Mutex::new(Vec::new()));
        let layer = SpanCapture { spans: spans.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_ok());

        let captured = spans.lock().unwrap();
        assert!(
            captured.contains(&"sign.remote".to_string()),
            "Expected sign.remote span, got: {:?}",
            *captured
        );
    }

    struct FieldCapture {
        fields: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
        tracing_subscriber::Layer<S> for FieldCapture
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor(self.fields.clone());
            attrs.record(&mut visitor);
        }

        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor(self.fields.clone());
            values.record(&mut visitor);
        }
    }

    struct FieldVisitor(Arc<Mutex<Vec<(String, String)>>>);

    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.lock().unwrap().push((field.name().to_string(), format!("{:?}", value)));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.lock().unwrap().push((field.name().to_string(), value.to_string()));
        }
    }

    #[tokio::test]
    async fn test_sign_span_records_status_code() {
        let sk = SecretKey::generate();
        let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_ok());

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(k, v)| k == "http.method" && v == "POST"),
            "Expected http.method=POST, got: {:?}",
            *captured
        );
        assert!(
            captured.iter().any(|(k, v)| k == "signer_type" && v == "remote"),
            "Expected signer_type=remote, got: {:?}",
            *captured
        );
        assert!(
            captured.iter().any(|(k, v)| k == "http.status_code" && v == "200"),
            "Expected http.status_code=200, got: {:?}",
            *captured
        );
    }

    /// Gate 3: the `rvc.sign.remote` span carries the validator pubkey only in
    /// its truncated form. The pubkey is the Web3Signer endpoint's path segment
    /// (`/api/v1/eth2/sign/0x<pubkey>`), so the leak surface is `http.url`; the
    /// full 96-char pubkey hex must never reach the span even though the real
    /// request uses the full URL.
    #[tokio::test]
    async fn test_sign_span_url_truncates_pubkey() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let full_pubkey_hex = hex::encode(pk_bytes);
        let (_mock, signer, data, ctx, _root) = mock_attestation_signer(&sk).await;

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_ok());

        let captured = fields.lock().unwrap();
        let http_url = captured.iter().find(|(k, _)| k == "http.url");
        assert!(http_url.is_some(), "Expected http.url span field, got: {:?}", *captured);
        let (_, url_value) = http_url.unwrap();
        // Truncated marker present...
        assert!(url_value.contains("..."), "pubkey in URL must be truncated: {url_value}");
        // ...and the full pubkey hex absent — from http.url and from every field.
        assert!(
            !url_value.contains(&full_pubkey_hex),
            "full pubkey hex must never appear in http.url: {url_value}"
        );
        assert!(
            !captured.iter().any(|(_, v)| v.contains(&full_pubkey_hex)),
            "full pubkey hex leaked into a span field: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_sign_span_records_error_status_code() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(500).set_body_json(serde_json::json!({"error": "internal"})),
            )
            .mount(&mock_server)
            .await;

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());

        let captured = fields.lock().unwrap();
        assert!(
            captured.iter().any(|(k, v)| k == "http.status_code" && v == "500"),
            "Expected http.status_code=500, got: {:?}",
            *captured
        );
    }

    #[tokio::test]
    async fn test_sign_span_redacts_url_credentials() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        // Construct a URL with credentials for redaction test. Connection will
        // fail; we only assert the span field is redacted.
        let url_with_creds = "http://user:secret@signer.example.com:9000";
        let config = RemoteSignerConfig::new(url_with_creds);
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let fields = Arc::new(Mutex::new(Vec::new()));
        let layer = FieldCapture { fields: fields.clone() };
        let subscriber = tracing_subscriber::registry().with(layer);

        let _guard = tracing::subscriber::set_default(subscriber);
        let _ = TypedSigner::sign_attestation(&signer, &data, &ctx).await;

        let captured = fields.lock().unwrap();
        let http_url = captured.iter().find(|(k, _)| k == "http.url");
        assert!(http_url.is_some(), "Expected http.url field, got: {:?}", *captured);
        let (_, url_value) = http_url.unwrap();
        assert!(!url_value.contains("user"), "URL should not contain username: {url_value}");
        assert!(!url_value.contains("secret"), "URL should not contain password: {url_value}");
        assert!(url_value.contains("***"), "URL should contain redacted marker: {url_value}");
    }

    #[test]
    fn test_redact_url_hides_credentials() {
        let url = "http://user:pass@example.com:9000/api";
        let redacted = redact_url(url);
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(redacted.contains("***"));
        assert!(redacted.contains("example.com"));
    }

    #[test]
    fn test_redact_url_preserves_url_without_credentials() {
        let url = "http://example.com:9000/api";
        let redacted = redact_url(url);
        assert_eq!(redacted, "http://example.com:9000/api");
    }

    #[test]
    fn test_redact_url_handles_invalid_url() {
        let url = "not-a-url";
        let redacted = redact_url(url);
        assert_eq!(redacted, "not-a-url");
    }

    /// GA regression: `http://` without env var must be refused (ISSUE-3.13 / NFR-10).
    ///
    /// In Phase 2 this returned `Ok` with a log warning.  At GA it must `Err`.
    #[test]
    fn test_remote_signer_refuses_http_url_without_env_var() {
        let _lock = env_lock();
        // Ensure the env var is not set so the gate is in full-Refuse path.
        unsafe { std::env::remove_var(REMOTE_SIGNER_INSECURE_ENV_VAR) };
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://signer.example.com:9000");
        let result = RemoteSigner::new(config, vec![pk]);
        assert!(result.is_err(), "http:// without env var must fail in GA (Refuse mode)");
    }

    #[test]
    fn test_remote_signer_no_warn_on_https_url() {
        let pk = [0xaa; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("https://signer.example.com:9000");
        let signer = RemoteSigner::new(config, vec![pk]);
        assert!(signer.is_ok());
    }

    #[tokio::test]
    async fn test_remote_signer_sign_sends_correct_request() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (_req, signing_root) = build_attestation_request(&data, &ctx);
        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        let expected_path = format!("/api/v1/eth2/sign/0x{}", hex::encode(pk_bytes));
        Mock::given(method("POST"))
            .and(wiremock::matchers::path(expected_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remote_signer_rejects_wrong_key_signature() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (_req, signing_root) = build_attestation_request(&data, &ctx);

        // Sign with a different key
        let wrong_sk = SecretKey::generate();
        let wrong_sig = wrong_sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(wrong_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::InvalidRemoteSignature => {}
            other => panic!("expected InvalidRemoteSignature, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_remote_signer_accepts_correct_signature() {
        let sk = SecretKey::generate();
        let (_mock, signer, data, ctx, signing_root) = mock_attestation_signer(&sk).await;
        let correct_sig = sk.sign(&signing_root);

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_bytes(), correct_sig.to_bytes());
    }

    #[tokio::test]
    async fn test_remote_signer_rejects_garbage_signature_bytes() {
        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();

        // Return valid-length but garbage signature bytes
        let garbage_bytes = [0xffu8; 96];
        let sig_hex = format!("0x{}", hex::encode(garbage_bytes));

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);

        let result = TypedSigner::sign_attestation(&signer, &data, &ctx).await;
        assert!(result.is_err());
    }

    // ── SEC-8 contract tests ──────────────────────────────────────────────────

    #[test]
    fn test_web3signer_client_attestation_body_matches_contract() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (req, signing_root) = build_attestation_request(&data, &ctx);
        let body = req.to_json_value().expect("serialize");

        // Discriminator + camelCase signingRoot (not snake_case bare root).
        assert_eq!(body["type"], "ATTESTATION");
        assert_eq!(body["signingRoot"], root_hex(&signing_root));
        assert!(body.get("signing_root").is_none(), "must not emit snake_case signing_root");

        // fork_info shape matches server WireForkInfo.
        assert_eq!(body["fork_info"]["fork"]["previous_version"], "0x03000000");
        assert_eq!(body["fork_info"]["fork"]["current_version"], "0x04000000");
        assert_eq!(body["fork_info"]["fork"]["epoch"], "0");
        assert_eq!(
            body["fork_info"]["genesis_validators_root"],
            format!("0x{}", hex::encode([0xaau8; 32]))
        );

        // Attestation payload (quoted u64s, 0x roots).
        assert_eq!(body["attestation"]["slot"], "5");
        assert_eq!(body["attestation"]["index"], "0");
        assert_eq!(
            body["attestation"]["beacon_block_root"],
            format!("0x{}", hex::encode([0x11u8; 32]))
        );
        assert_eq!(body["attestation"]["source"]["epoch"], "1");
        assert_eq!(body["attestation"]["target"]["epoch"], "2");
    }

    #[test]
    fn test_web3signer_client_block_body_matches_contract() {
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let block = BeaconBlock {
            slot: 3_000_000,
            proposer_index: 12_345,
            parent_root: [0xaa; 32],
            state_root: [0xbb; 32],
            body: eth_types::external_vector_electra_block().body.clone(),
        };
        let (req, signing_root) = build_block_v2_request(&block, &ctx).expect("build BLOCK_V2");
        let body = req.to_json_value().expect("serialize");

        assert_eq!(body["type"], "BLOCK_V2");
        assert_eq!(body["signingRoot"], root_hex(&signing_root));
        assert!(body.get("signing_root").is_none());

        assert_eq!(body["fork_info"]["fork"]["current_version"], "0x04000000");
        // ELECTRA body SSZ with DENEB version label from fork_info.current_version
        // — version is decorative; the header is what is hashed.
        assert_eq!(body["beacon_block"]["version"], "DENEB");
        assert_eq!(body["beacon_block"]["block_header"]["slot"], "3000000");
        assert_eq!(body["beacon_block"]["block_header"]["proposer_index"], "12345");
        assert_eq!(
            body["beacon_block"]["block_header"]["parent_root"],
            format!("0x{}", hex::encode([0xaau8; 32]))
        );
        assert_eq!(
            body["beacon_block"]["block_header"]["state_root"],
            format!("0x{}", hex::encode([0xbbu8; 32]))
        );
        // body_root is the typed SSZ HTR of the Electra body — non-zero, 0x-prefixed.
        let body_root = body["beacon_block"]["block_header"]["body_root"].as_str().unwrap();
        assert!(body_root.starts_with("0x") && body_root.len() == 66);
    }

    #[test]
    fn test_web3signer_client_unsupported_type_returns_error_not_malformed_body() {
        // Raw-root path is the unsupported case: must return a typed error and
        // never construct/send a bare `{signing_root}` body (SEC-8).
        let pk = [0xcc; PUBLIC_KEY_BYTES_LEN];
        let config = RemoteSignerConfig::new("http://localhost:9000");
        let signer = RemoteSigner::new_unchecked(config, vec![pk]);

        let err = futures_executor_block_on(Signer::sign(&signer, &[0xde; 32], &pk)).unwrap_err();
        match err {
            SigningError::UnsupportedSigningType(msg) => {
                assert!(
                    msg.contains("TypedSigner") || msg.contains("raw-root"),
                    "typed error must name the supported path, got: {msg}"
                );
            }
            other => {
                panic!("expected UnsupportedSigningType (not a malformed body), got: {other:?}")
            }
        }
    }

    /// Drive a future on a tiny current-thread runtime (avoids pulling tokio into
    /// a sync test helper dependency beyond what the crate already has).
    fn futures_executor_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    #[test]
    fn test_local_slashing_stage_ordering_unchanged() {
        // SEC-8 is client-body only: RemoteSigner must not own slashing stage /
        // commit. Staging remains the caller's job (SignerService / SigningGate
        // stage → sign → commit). This unit is a structural guard: the typed
        // builders only produce a body + signing root; they never touch a
        // slashing DB.
        let sk = SecretKey::generate();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (req, root) = build_attestation_request(&data, &ctx);
        assert_eq!(req.payload.type_name(), "ATTESTATION");
        assert_eq!(req.signing_root, root_hex(&root));
        // No stage/commit side effects — pure function.
        let (req2, root2) = build_attestation_request(&data, &ctx);
        assert_eq!(req.signing_root, req2.signing_root);
        assert_eq!(root, root2);
    }

    #[tokio::test]
    async fn test_web3signer_client_posts_typed_body_not_bare_root() {
        use wiremock::matchers::body_partial_json;

        let sk = SecretKey::generate();
        let pk_bytes = sk.public_key().to_bytes();
        let ctx = test_ctx(&sk);
        let data = sample_attestation();
        let (req, signing_root) = build_attestation_request(&data, &ctx);
        let expected_sig = sk.sign(&signing_root);
        let sig_hex = format!("0x{}", hex::encode(expected_sig.to_bytes()));

        let mock_server = MockServer::start().await;
        // Require type-tagged camelCase body; a bare signing_root would fail this match.
        Mock::given(method("POST"))
            .and(path_regex(r"/api/v1/eth2/sign/.*"))
            .and(body_partial_json(serde_json::json!({
                "type": "ATTESTATION",
                "signingRoot": req.signing_root,
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"signature": sig_hex})),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = RemoteSignerConfig::new(mock_server.uri());
        let signer = RemoteSigner::new_unchecked(config, vec![pk_bytes]);
        let sig = TypedSigner::sign_attestation(&signer, &data, &ctx).await.unwrap();
        assert_eq!(sig.to_bytes(), expected_sig.to_bytes());
    }
}
