/// Controls whether a validator is permitted to sign.
///
/// Implementations perform an in-memory lookup and return `false` for any
/// pubkey that is not explicitly enabled.  The fail-closed contract means that
/// an unknown pubkey **always** returns `false` — signing is never allowed by
/// default.
pub trait SigningEnablement {
    /// Returns whether signing is currently enabled for this validator.
    ///
    /// Fail-closed default: an unknown pubkey returns `false`.
    #[must_use = "is_signing_enabled gates signing; the returned bool must be checked before proceeding"]
    fn is_signing_enabled(&self, pubkey: &crypto::PublicKey) -> bool;
}
