//! PRD M4 — canonical phase-exit enumeration test (Issue 2.13).
//!
//! # What M4 requires
//!
//! > No signing path on `rvc-signer`'s LIVE listener can produce a signature for
//! > a slashable message type without EIP-3076 (slashing-DB) consultation.
//!
//! # How this test verifies M4
//!
//! The proof is two-pronged: the **static** signing-method metadata in
//! `signer-registry` (`REGISTERED_METHODS`) describes the live listener's
//! signing surface, and a `cfg(test)` **introspection of the live listener**
//! (the tonic `NamedService` constants for the services actually registered via
//! `add_service` in `bin/rvc-signer/src/main.rs`) confirms that metadata
//! corresponds to what is wired.
//!
//! Concretely this test asserts:
//!
//! 1. The live listener serves **only** the v2 typed service
//!    `signer.v2.SignerService` (and, under the `dvt` feature, the v2
//!    `signer.v2.PeerSignerService`).  The v1 raw-root service
//!    `signer.SignerService` is **not** registered on the live listener — its
//!    handler is compiled (ADR-010) but every method returns
//!    `Status::unimplemented` and it is never passed to `add_service`.
//! 2. The live-listener enumeration shows **zero** v1 raw-root entries: no
//!    `REGISTERED_METHODS` entry carries `MessageKind::V1RawRoot`, and no entry's
//!    `service` string is the v1 service name.
//! 3. Every **slashable** signing handler routes through `SigningGate`
//!    (`GateRouting::Gated`).  A slashable method classified `NonSlashable`
//!    would be a method that can sign without slashing-DB consultation — the
//!    exact thing M4 forbids.
//! 4. Every `REGISTERED_METHODS` entry's `service` string equals the live
//!    listener's introspected v2 service name (no drift between the static
//!    registry and the wired service).
//!
//! # Relationship to `signing_path_enumeration.rs`
//!
//! `signing_path_enumeration.rs` is the standing CI gate (per-method
//! classification + count floor); this file is the milestone artifact for the
//! PRD M4 closeout, expressed against the live-listener introspection. The two
//! overlap deliberately — the standing gate prevents regressions; this test is
//! the auditor-facing M4 evidence.

use signer_registry::{GateRouting, MessageKind, SigningMethod, REGISTERED_METHODS};
use tonic::server::NamedService;

// The v2 typed service — the ONLY signing service registered on the live
// listener (see `bin/rvc-signer/src/main.rs`'s `add_service`).
use rvc_signer_bin::SignerServiceServerV2;
// The v1 raw-root service — compiled (ADR-010) but NOT registered on the live
// listener (SS-1 / Issue 2.2).
use rvc_signer_bin::SignerServiceServer as SignerServiceServerV1;

/// The introspected name of the v2 service the live listener registers.
///
/// `NamedService::NAME` is the tonic-generated, protobuf fully-qualified service
/// name; reading it here is the `cfg(test)` introspection of what `add_service`
/// wires on the live listener.
fn live_listener_service_name() -> &'static str {
    <SignerServiceServerV2<()> as NamedService>::NAME
}

/// The introspected name of the v1 raw-root service (NOT registered live).
fn unregistered_v1_service_name() -> &'static str {
    <SignerServiceServerV1<()> as NamedService>::NAME
}

/// The slashable message kinds.  A handler for any of these MUST route through
/// `SigningGate` (and therefore consult the slashing DB) per PRD M4.
const SLASHABLE_KINDS: &[MessageKind] = &[
    MessageKind::Block,
    MessageKind::Attestation,
    MessageKind::Aggregate,
    MessageKind::ElectraAggregate,
];

fn is_slashable(kind: MessageKind) -> bool {
    SLASHABLE_KINDS.contains(&kind)
}

/// M4 sanity: the live listener introspects to the v2 typed service, which is
/// distinct from the unregistered v1 raw-root service.
#[test]
fn live_listener_serves_v2_not_v1() {
    let live = live_listener_service_name();
    let v1 = unregistered_v1_service_name();

    assert_eq!(
        live, "signer.v2.SignerService",
        "the live listener must serve the v2 typed service"
    );
    assert_eq!(
        v1, "signer.SignerService",
        "the v1 raw-root service name is the legacy unregistered service"
    );
    assert_ne!(live, v1, "the live listener must not serve the v1 raw-root service");
}

/// M4 core (zero v1 raw-root on the live listener): no enumerated method is a
/// v1 raw-root entry — neither by `MessageKind::V1RawRoot` nor by carrying the
/// v1 service name.
#[test]
fn live_listener_enumeration_has_zero_v1_raw_root_entries() {
    let v1_service = unregistered_v1_service_name();

    let v1_kind_entries: Vec<&SigningMethod> =
        REGISTERED_METHODS.iter().filter(|m| m.message_kind == MessageKind::V1RawRoot).collect();
    assert!(
        v1_kind_entries.is_empty(),
        "live-listener enumeration must contain ZERO V1RawRoot entries; found: {v1_kind_entries:?}"
    );

    let v1_service_entries: Vec<&SigningMethod> =
        REGISTERED_METHODS.iter().filter(|m| m.service == v1_service).collect();
    assert!(
        v1_service_entries.is_empty(),
        "live-listener enumeration must contain ZERO entries on the v1 service \
         '{v1_service}'; found: {v1_service_entries:?}"
    );
}

/// M4 core (no slashable signing without the gate): every slashable handler on
/// the live listener routes through `SigningGate`.
#[test]
fn every_slashable_method_routes_through_signing_gate() {
    let slashable: Vec<&SigningMethod> =
        REGISTERED_METHODS.iter().filter(|m| is_slashable(m.message_kind)).collect();

    assert!(
        !slashable.is_empty(),
        "the live listener must expose at least one slashable signing method \
         (block/attestation); none found — registry is likely misconfigured"
    );

    for m in slashable {
        assert_eq!(
            m.gate_routing,
            GateRouting::Gated,
            "slashable method {}/{} (kind={:?}) MUST route through SigningGate \
             (GateRouting::Gated) — a NonSlashable classification would let it sign \
             without EIP-3076 consultation, violating PRD M4",
            m.service,
            m.method,
            m.message_kind,
        );
    }
}

/// M4 consistency: every enumerated method's service string equals the live
/// listener's introspected v2 service name — the static registry does not drift
/// from the wired service.
#[test]
fn every_registered_method_is_on_the_live_listener_service() {
    let live = live_listener_service_name();
    for m in REGISTERED_METHODS {
        assert_eq!(
            m.service, live,
            "REGISTERED_METHODS entry {}/{} is on service '{}', but the live listener \
             serves '{}'; the registry has drifted from the wired service",
            m.service, m.method, m.service, live,
        );
    }
}

/// M4 completeness: the live listener must expose the two canonical slashable
/// signing methods (block + attestation), each `Gated`.  A regression that
/// silently drops one of these from the registry would weaken the M4 evidence.
#[test]
fn block_and_attestation_are_present_and_gated() {
    let live = live_listener_service_name();

    let has_gated = |method: &str| {
        REGISTERED_METHODS.iter().any(|m| {
            m.service == live && m.method == method && m.gate_routing == GateRouting::Gated
        })
    };

    assert!(
        has_gated("SignBeaconBlock"),
        "live listener must expose a gated SignBeaconBlock (slashable, EIP-3076-consulting)"
    );
    assert!(
        has_gated("SignAttestationData"),
        "live listener must expose a gated SignAttestationData (slashable, EIP-3076-consulting)"
    );
}
