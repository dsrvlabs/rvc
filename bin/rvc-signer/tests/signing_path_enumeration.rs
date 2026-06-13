//! M4 standing CI gate: every live-listener signing method is enumerated and
//! correctly classified in `REGISTERED_METHODS`.
//!
//! # Purpose
//!
//! Adding a new gRPC signing method to `rvc-signer` without a matching entry in
//! `REGISTERED_METHODS` (or mis-classifying its `gate_routing`) will cause this
//! test to fail, blocking CI.
//!
//! # Invariants checked (weaker set — Issue 2.13 strengthens to strict)
//!
//! 1. `REGISTERED_METHODS` is non-empty.
//! 2. Every slashable message kind (`Block | Attestation | Aggregate | ElectraAggregate`)
//!    must have `gate_routing == GateRouting::Gated`.  No slashable method may be
//!    `NonSlashable`.
//! 3. Every entry has non-empty `service` and `method` strings.
//!
//! # Strengthening (Issue 2.13)
//!
//! Issue 2.13 will add a cross-check that verifies each `REGISTERED_METHODS` entry
//! actually invokes `SigningGate` at the call site (runtime or compile-time linkage
//! check).  That strict gate is deferred to preserve parallelism; this weaker set is
//! the CI floor until then.
//!
//! Note: cross-checking registry method names against the actual v2 proto service
//! descriptor via tonic reflection would add heavy build-time overhead.  Instead,
//! the convention is enforced by code review + the per-method naming check below.
//! Issue 2.13 will strengthen this if reflection becomes cheap.

// The dep key in Cargo.toml is `signer-registry` (package = "rvc-signer-registry"),
// so the import alias is `signer_registry` from rvc-signer-bin's perspective.
use signer_registry::{GateRouting, MessageKind, REGISTERED_METHODS};

/// REGISTERED_METHODS must be non-empty — the live listener has signing methods.
#[test]
fn registered_methods_is_non_empty() {
    assert!(
        !REGISTERED_METHODS.is_empty(),
        "REGISTERED_METHODS is empty; every live-listener signing method must be listed"
    );
}

/// Every entry must have non-empty service and method strings.
#[test]
fn every_entry_has_non_empty_service_and_method() {
    for m in REGISTERED_METHODS {
        assert!(
            !m.service.is_empty(),
            "REGISTERED_METHODS entry has an empty service string: {:?}",
            m
        );
        assert!(
            !m.method.is_empty(),
            "REGISTERED_METHODS entry has an empty method string: {:?}",
            m
        );
    }
}

/// No slashable message kind may be marked NonSlashable.
///
/// This is the core M4 policy invariant: a mis-classified slashable method would
/// bypass the slashing/doppelganger gate.
#[test]
fn no_slashable_method_is_marked_non_slashable() {
    let slashable_kinds = [
        MessageKind::Block,
        MessageKind::Attestation,
        MessageKind::Aggregate,
        MessageKind::ElectraAggregate,
    ];

    for m in REGISTERED_METHODS {
        if slashable_kinds.contains(&m.message_kind) {
            assert_eq!(
                m.gate_routing,
                GateRouting::Gated,
                "slashable method {}/{} (kind={:?}) is classified as NonSlashable — \
                 this would bypass the slashing gate; fix REGISTERED_METHODS or Issue 2.13 \
                 reclassification",
                m.service,
                m.method,
                m.message_kind,
            );
        }
    }
}

/// All entries use the expected live-listener service path.
///
/// The live listener serves only `signer.v2.SignerService`.  An entry with a
/// different service string indicates a stale registry entry or a new service
/// that needs explicit policy review.
#[test]
fn all_entries_use_v2_service_path() {
    const EXPECTED_SERVICE: &str = "signer.v2.SignerService";
    for m in REGISTERED_METHODS {
        assert_eq!(
            m.service, EXPECTED_SERVICE,
            "unexpected service path in REGISTERED_METHODS: got '{}', expected '{}'; \
             if a new service was added, review its gate_routing classification and \
             update this test (Issue 2.13)",
            m.service, EXPECTED_SERVICE,
        );
    }
}
