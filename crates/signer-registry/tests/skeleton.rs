//! Standing invariant checks for REGISTERED_METHODS (SS-1/M4, Issue 2.2).
//!
//! Phase 1 asserted the array was empty (tripwire).  Phase 2 (Issue 2.2) populates
//! it; this test now asserts the populated invariants instead.  The M4 enumeration
//! gate in `bin/rvc-signer/tests/signing_path_enumeration.rs` contains the full
//! per-method policy check.
use rvc_signer_registry::{GateRouting, MessageKind, REGISTERED_METHODS};

/// REGISTERED_METHODS is non-empty after Phase 2 population (SS-1, Issue 2.2).
#[test]
fn registered_methods_is_populated() {
    assert!(
        !REGISTERED_METHODS.is_empty(),
        "REGISTERED_METHODS must be populated after Phase 2 (Issue 2.2)"
    );
}

/// Every entry has non-empty service and method strings.
#[test]
fn every_entry_has_non_empty_service_and_method() {
    for m in REGISTERED_METHODS {
        assert!(!m.service.is_empty(), "entry has empty service: {:?}", m);
        assert!(!m.method.is_empty(), "entry has empty method: {:?}", m);
    }
}

/// No slashable message kind is marked NonSlashable.
#[test]
fn no_slashable_method_is_marked_non_slashable() {
    let slashable = [
        MessageKind::Block,
        MessageKind::Attestation,
        MessageKind::Aggregate,
        MessageKind::ElectraAggregate,
    ];
    for m in REGISTERED_METHODS {
        if slashable.contains(&m.message_kind) {
            assert_eq!(
                m.gate_routing,
                GateRouting::Gated,
                "slashable method {}/{} must be GateRouting::Gated, got {:?}",
                m.service,
                m.method,
                m.gate_routing,
            );
        }
    }
}
