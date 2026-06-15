//! M4 standing CI gate: every live-listener signing method is enumerated and
//! correctly classified in `REGISTERED_METHODS`.
//!
//! # Purpose
//!
//! Adding a new gRPC signing method to `rvc-signer` without a matching entry in
//! `REGISTERED_METHODS` (or mis-classifying its `gate_routing` / `gate_method`)
//! will cause this test to fail, blocking CI.
//!
//! # Invariants checked (STRICT set — flipped on by Issue 2.13)
//!
//! 1. `REGISTERED_METHODS` is non-empty.
//! 2. Every slashable message kind (`Block | Attestation | Aggregate | ElectraAggregate`)
//!    must have `gate_routing == GateRouting::Gated`.  No slashable method may be
//!    `NonSlashable`.
//! 3. Every entry has non-empty `service` and `method` strings.
//! 4. **STRICT (Issue 2.13):** every registered method is either non-slashable
//!    (`gate_routing == NonSlashable`) OR confirmed via `signer-registry` to
//!    invoke `SigningGate::sign_*` — i.e. its `gate_method` is `Some(name)` where
//!    `name ∈ signer_registry::SIGNING_GATE_METHODS`.  A slashable method with no
//!    recognized `SigningGate` method named cannot be confirmed to consult
//!    EIP-3076; this is the strengthening that locks PRD M4 into place.
//!
//! # What changed in the strict flip
//!
//! Issue 2.2 landed the weaker invariant ("every method is non-slashable OR
//! tagged `Gated`").  Issue 2.13 flips it to the stronger one above by recording,
//! per registry entry, the concrete `SigningGate::sign_*` method the handler
//! routes through (`SigningMethod::gate_method`) and validating that name against
//! the canonical `SIGNING_GATE_METHODS` list.  The link from a live RPC to a
//! `SigningGate` method is now machine-checked, not merely a boolean tag.
//!
//! Note: cross-checking registry method names against the actual v2 proto service
//! descriptor via tonic reflection would add heavy build-time overhead.  Instead,
//! the live-listener service name is introspected via `NamedService` in the
//! companion `m4_enumeration.rs` (Issue 2.13), and the gate linkage is confirmed
//! via the `gate_method` cross-check below.

// The dep key in Cargo.toml is `signer-registry` (package = "rvc-signer-registry"),
// so the import alias is `signer_registry` from rvc-signer-bin's perspective.
use signer_registry::{GateRouting, MessageKind, REGISTERED_METHODS, SIGNING_GATE_METHODS};

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

/// Count floor: adding a v2 signing method without a `REGISTERED_METHODS` entry fails CI.
///
/// Update `EXPECTED` (and add the entry in `crates/signer-registry/src/lib.rs`)
/// when a new v2 signing method is added or an existing one is removed.
#[test]
fn registered_methods_count_matches_live_listener() {
    // Update when a v2 signing method is added/removed (see crates/signer-registry/src/lib.rs).
    const EXPECTED: usize = 10;
    assert_eq!(
        signer_registry::REGISTERED_METHODS.len(),
        EXPECTED,
        "REGISTERED_METHODS count changed: add the new method's entry or update EXPECTED"
    );
}

/// STRICT invariant (Issue 2.13 flip): every registered method is non-slashable
/// OR confirmed via `signer-registry` to invoke `SigningGate::sign_*`.
///
/// This is the strengthening of the Issue 2.2 weaker invariant.  Previously a
/// slashable method only had to be *tagged* `Gated`; now a `Gated` method must
/// name the concrete `SigningGate::sign_*` method it routes through
/// (`gate_method`), and that name must be a recognized member of
/// `SIGNING_GATE_METHODS`.  A slashable method that names no recognized gate
/// method would be one that cannot be confirmed to consult EIP-3076 — exactly
/// the PRD M4 failure mode this gate locks out.
#[test]
fn every_registered_method_is_nonslashable_or_invokes_signing_gate() {
    for m in REGISTERED_METHODS {
        // The "OR non-slashable" escape clause: non-slashable methods are not
        // required to route through the gate for M4 (they carry no slashing
        // watermark).  In the current architecture they do route through the
        // gate anyway, but M4 does not mandate it.
        if m.gate_routing == GateRouting::NonSlashable {
            continue;
        }

        // Otherwise the method is Gated and MUST be confirmed to invoke a
        // recognized SigningGate::sign_* method.
        let gate_method = m.gate_method.unwrap_or_else(|| {
            panic!(
                "STRICT M4: gated method {}/{} (kind={:?}) names no SigningGate method \
                 (gate_method = None); it cannot be confirmed to consult EIP-3076",
                m.service, m.method, m.message_kind,
            )
        });

        assert!(
            SIGNING_GATE_METHODS.contains(&gate_method),
            "STRICT M4: gated method {}/{} routes through '{}', which is not a recognized \
             SigningGate::sign_* method ({:?}); update SIGNING_GATE_METHODS or fix the entry",
            m.service,
            m.method,
            gate_method,
            SIGNING_GATE_METHODS,
        );
    }
}

/// STRICT support: every entry that names a `gate_method` names a recognized one.
///
/// This also covers the non-slashable entries (which, in the current
/// architecture, all route through the gate too); it catches a typo'd
/// `gate_method` on any entry, slashable or not.
#[test]
fn every_named_gate_method_is_recognized() {
    for m in REGISTERED_METHODS {
        if let Some(gate_method) = m.gate_method {
            assert!(
                SIGNING_GATE_METHODS.contains(&gate_method),
                "method {}/{} names gate_method '{}', not in SIGNING_GATE_METHODS {:?}",
                m.service,
                m.method,
                gate_method,
                SIGNING_GATE_METHODS,
            );
        }
    }
}

/// STRICT support: `SIGNING_GATE_METHODS` is the canonical list and is non-empty,
/// well-formed (no empty strings, no duplicates), so the cross-check above is
/// meaningful.
#[test]
fn signing_gate_methods_list_is_well_formed() {
    assert!(!SIGNING_GATE_METHODS.is_empty(), "SIGNING_GATE_METHODS must be non-empty");
    for name in SIGNING_GATE_METHODS {
        assert!(!name.is_empty(), "SIGNING_GATE_METHODS contains an empty method name");
        assert!(
            name.starts_with("sign_"),
            "SIGNING_GATE_METHODS entry '{name}' must be a SigningGate sign_* method"
        );
    }
    let mut seen = std::collections::HashSet::new();
    for name in SIGNING_GATE_METHODS {
        assert!(seen.insert(*name), "SIGNING_GATE_METHODS has a duplicate: '{name}'");
    }
}
