/// Controls whether a validator is permitted to sign.
///
/// Implementations perform an in-memory lookup and return `false` for any
/// pubkey that is not explicitly enabled.  The fail-closed contract means that
/// an unknown pubkey **always** returns `false` — signing is never allowed by
/// default.
///
/// # Location note
///
/// This trait was relocated from `rvc-signer` to `rvc-doppelganger` (Issue 2.6)
/// so that `ForwardWindowMachine` can implement it without creating a
/// `doppelganger → signer` dependency cycle.  `rvc-signer` re-exports it as
/// `pub use doppelganger::SigningEnablement`.
pub trait SigningEnablement: Send + Sync {
    /// Returns whether signing is currently enabled for this validator.
    ///
    /// Fail-closed default: an unknown pubkey returns `false`.
    #[must_use = "is_signing_enabled gates signing; the returned bool must be checked before proceeding"]
    fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool;
}

/// Production opt-out of doppelganger protection (`--no-doppelganger-detection`).
///
/// Enables signing for every pubkey. This deliberately forgoes the forward-window
/// safety cost of roughly **2–3 epochs** of monitoring (~12.8–19.2 minutes on
/// mainnet with 12 s slots). Prefer leaving doppelganger on (the default).
///
/// Distinct from the test-only `AlwaysEnabled` helper in `rvc-signer`: this type
/// is the **documented operator opt-out** and is safe to wire on the production
/// path when the operator has explicitly disabled doppelganger detection.
pub struct DoppelgangerDisabledByOperator;

impl SigningEnablement for DoppelgangerDisabledByOperator {
    fn is_signing_enabled(&self, _pubkey: &crypto::PublicKey) -> bool {
        true
    }
}
