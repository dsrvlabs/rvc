//! Insecure-operation gate primitive (ADR-003).
//!
//! Provides a lightweight decision primitive that lets callers centralise
//! "what happens when an insecure operation is attempted" in one place.
//! Production consumers (SS-1, KM-3, SIG-1, L-1) are wired up in Phase 2/6;
//! this module is additive with zero callers outside its own tests.
//!
//! # Usage
//!
//! ```rust
//! use rvc_eth_types::insecure::{evaluate, from_env, Decision, InsecureGate};
//!
//! fn perform_operation(gate: InsecureGate) -> Result<(), &'static str> {
//!     match evaluate(gate, true, "plaintext key material detected") {
//!         Decision::Abort { reason } => Err(reason),
//!         Decision::ProceedWithWarning { .. } | Decision::Proceed => Ok(()),
//!     }
//! }
//! ```

/// Controls what happens when an insecure operation is attempted.
#[must_use = "InsecureGate is a security decision and must be passed to evaluate()"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsecureGate {
    /// Abort the operation; return an error to the caller.
    Refuse,
    /// Allow the operation but emit a `tracing::warn!` log.
    Warn,
    /// Allow the operation silently.
    Allow,
}

/// The outcome returned by [`evaluate`].
///
/// `reason` is `&'static str` so that every reason string is a grep-stable,
/// compile-time constant — consumers can search the source for exact strings
/// without worrying about runtime formatting.
#[must_use = "Decision must be matched; dropping it allows the insecure operation to proceed"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The operation may proceed without any concern.
    Proceed,
    /// The operation may proceed but is considered insecure; a warning has
    /// already been emitted via `tracing::warn!`.
    ProceedWithWarning { reason: &'static str },
    /// The operation must not proceed.
    Abort { reason: &'static str },
}

/// Evaluates whether an insecure operation should be allowed.
///
/// Returns [`Decision::Proceed`] when `condition_is_insecure` is `false`
/// regardless of the gate setting. When `condition_is_insecure` is `true`
/// the gate determines the outcome:
///
/// - [`InsecureGate::Refuse`] → [`Decision::Abort`]
/// - [`InsecureGate::Warn`]   → [`Decision::ProceedWithWarning`] (and emits `tracing::warn!`)
/// - [`InsecureGate::Allow`]  → [`Decision::Proceed`]
///
/// `reason` is `&'static str` so that every reason string is a grep-stable,
/// compile-time constant — no heap allocation on hot bind paths.
#[must_use = "Decision must be matched; dropping it allows the insecure operation to proceed"]
pub fn evaluate(gate: InsecureGate, condition_is_insecure: bool, reason: &'static str) -> Decision {
    if !condition_is_insecure {
        return Decision::Proceed;
    }
    match gate {
        InsecureGate::Refuse => Decision::Abort { reason },
        InsecureGate::Warn => {
            tracing::warn!("insecure operation permitted by gate: {reason}");
            Decision::ProceedWithWarning { reason }
        }
        InsecureGate::Allow => Decision::Proceed,
    }
}

/// Reads an environment variable to determine the gate setting.
///
/// | Value (case-insensitive) | Result                      |
/// |--------------------------|-----------------------------|
/// | `"true"`                 | [`InsecureGate::Allow`]     |
/// | `"false"`                | [`InsecureGate::Refuse`]    |
/// | unset or unrecognised    | `default`                   |
///
/// Unrecognised non-empty values (including `""`, `"1"`, `"0"`, whitespace-
/// padded strings) fall back to `default` — the safe choice, because silently
/// allowing an insecure operation on a typo would be worse than refusing it.
#[must_use = "the gate setting must be inspected before performing any insecure operation"]
pub fn from_env(var: &str, default: InsecureGate) -> InsecureGate {
    match std::env::var(var) {
        Ok(val) => match val.to_ascii_lowercase().as_str() {
            "true" => InsecureGate::Allow,
            "false" => InsecureGate::Refuse,
            _ => default,
        },
        Err(_) => default,
    }
}
