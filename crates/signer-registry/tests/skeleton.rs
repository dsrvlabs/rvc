//! Tripwire: REGISTERED_METHODS is empty until Phase 2 Task 2.1 populates it.
//! When 2.1 adds entries, this assertion flips to a non-empty + per-method check.
use rvc_signer_registry::REGISTERED_METHODS;

#[test]
fn registered_methods_is_empty_until_phase_2() {
    assert!(
        REGISTERED_METHODS.is_empty(),
        "REGISTERED_METHODS is empty in Phase 1; Phase 2 Task 2.1 populates it and flips this test"
    );
}
