//! Insecure-mode gating for plaintext and non-loopback connections.
//!
//! [`InsecureGate`] centralises the "require explicit opt-in before allowing an
//! insecure code path" check used by:
//!
//! - **H-9** (`rvc-signer --insecure`): bind address must be loopback AND
//!   `RVC_SIGNER_ALLOW_INSECURE=true`.
//! - **H-10** (`GrpcRemoteSigner` / `RemoteSigner` plaintext URLs): URL scheme
//!   must be `https://` OR `RVC_REMOTE_SIGNER_ALLOW_INSECURE=true` with a custom
//!   predicate.
//! - **L-10** (`bin/rvc` metrics bind): same pattern, different env var.
//!
//! ## Design choice: closure-based predicate
//!
//! Rather than embedding a bare `SocketAddr` field, `InsecureGate` holds a
//! `predicate: Box<dyn Fn() -> bool + Send + Sync>` that returns `true` when
//! the insecure use is considered _conditionally acceptable_ (e.g., the bind
//! address is loopback, or the URL scheme is `https://`).  This allows H-9 and
//! H-10 to share one struct without dead fields or per-call-site newtypes.
//!
//! For the common bind-address case use [`InsecureGate::new`]; for a custom
//! predicate use [`InsecureGate::with_predicate`].
//!
//! ## Check logic
//!
//! ```text
//! env_ok  = env::var(env_var) == "true"
//! pred_ok = predicate()
//!
//! if env_ok && pred_ok  →  Ok(())            (silent — fully opted-in)
//! else, mode = Warn     →  error!(...); Ok(())
//! else, mode = Refuse   →  Err(InsecureGateError)
//! ```

use std::net::SocketAddr;

use thiserror::Error;

// ─── Public types ─────────────────────────────────────────────────────────

/// Mode controlling what happens when an insecure code path is attempted.
///
/// Per NFR-10 the default in the Phase 2 release tag is [`InsecureMode::Warn`].
/// The flip to [`InsecureMode::Refuse`] lands in Phase 3 ISSUE-3.13 (GA tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsecureMode {
    /// Emit an `error!`-level log and allow the operation to continue.
    ///
    /// This is the Phase-2 default: operators who haven't updated their
    /// configuration get a loud warning but are not broken.
    Warn,
    /// Return [`InsecureGateError`] with an actionable message.
    ///
    /// This will become the default at the mainnet GA tag (Phase 3 ISSUE-3.13).
    Refuse,
}

/// Error returned by [`InsecureGate::check`] in [`InsecureMode::Refuse`] mode.
///
/// The message is always actionable: it names the env var required and
/// suggests how to configure the bind address or URL scheme.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct InsecureGateError(pub String);

/// Gate that enforces an explicit env-var opt-in before permitting an insecure
/// code path.
///
/// See the [module documentation](self) for the full check logic.
///
/// # Example — bind-address gate (H-9)
///
/// ```no_run
/// use std::net::SocketAddr;
/// use rvc_crypto::insecure::{InsecureGate, InsecureMode};
///
/// let addr: SocketAddr = "0.0.0.0:50052".parse().unwrap();
/// let gate = InsecureGate::new("RVC_SIGNER_ALLOW_INSECURE", addr, InsecureMode::Warn);
/// // In Warn mode this always returns Ok but logs an error.
/// gate.check().expect("Warn mode is non-fatal");
/// ```
///
/// # Example — URL-scheme gate (H-10)
///
/// ```no_run
/// use rvc_crypto::insecure::{InsecureGate, InsecureMode};
///
/// let url = "http://signer.example.com:9000".to_string();
/// let gate = InsecureGate::with_predicate(
///     "RVC_REMOTE_SIGNER_ALLOW_INSECURE",
///     InsecureMode::Warn,
///     move || url.starts_with("https://"),
/// );
/// gate.check().expect("Warn mode is non-fatal");
/// ```
pub struct InsecureGate {
    /// Name of the environment variable the operator must set to `"true"` to
    /// opt in to the insecure code path.
    pub env_var: &'static str,
    /// Mode: warn and continue, or refuse with an error.
    pub mode: InsecureMode,
    /// Returns `true` when the insecure use is conditionally acceptable
    /// (e.g., bind addr is loopback, URL is https://).
    predicate: Box<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for InsecureGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InsecureGate")
            .field("env_var", &self.env_var)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl InsecureGate {
    /// Creates a gate that checks whether `bind_addr` is a loopback address.
    ///
    /// The predicate evaluates to `true` when `bind_addr.ip().is_loopback()`.
    /// Commonly used for H-9 (rvc-signer) and L-10 (metrics bind).
    pub fn new(env_var: &'static str, bind_addr: SocketAddr, mode: InsecureMode) -> Self {
        Self { env_var, mode, predicate: Box::new(move || bind_addr.ip().is_loopback()) }
    }

    /// Creates a gate with a custom predicate closure.
    ///
    /// Use this for non-bind-addr cases such as URL-scheme checks (H-10):
    ///
    /// ```no_run
    /// use rvc_crypto::insecure::{InsecureGate, InsecureMode};
    ///
    /// let url = "https://signer.example.com:9000".to_string();
    /// let gate = InsecureGate::with_predicate(
    ///     "RVC_REMOTE_SIGNER_ALLOW_INSECURE",
    ///     InsecureMode::Warn,
    ///     move || url.starts_with("https://"),
    /// );
    /// ```
    pub fn with_predicate(
        env_var: &'static str,
        mode: InsecureMode,
        predicate: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self { env_var, mode, predicate: Box::new(predicate) }
    }

    /// Checks whether the insecure code path is permitted.
    ///
    /// Returns `Ok(())` if:
    /// - `env_var` is set to `"true"` **and** the predicate returns `true`
    ///   (silent, fully opted-in), **or**
    /// - `mode` is [`InsecureMode::Warn`] (emits an `error!`-level log first).
    ///
    /// Returns `Err(`[`InsecureGateError`]`)` when `mode` is
    /// [`InsecureMode::Refuse`] and the opt-in conditions are not fully met.
    pub fn check(&self) -> Result<(), InsecureGateError> {
        let env_ok = std::env::var(self.env_var).as_deref() == Ok("true");
        let predicate_ok = (self.predicate)();

        if env_ok && predicate_ok {
            // Fully opted-in: both the explicit env var and the safer condition
            // (loopback / https) are satisfied.  No log needed.
            return Ok(());
        }

        let message = format!(
            "Insecure mode detected: {}=true must be set AND the predicate condition must be \
             met (e.g., bind address is loopback or URL scheme is https://). \
             Current state: {}={}, predicate_ok={}. \
             Hint: set {}=true and, for bind-address gating, use a loopback address \
             (e.g., 127.0.0.1) if you deliberately want an insecure connection.",
            self.env_var, self.env_var, env_ok, predicate_ok, self.env_var,
        );

        match self.mode {
            InsecureMode::Warn => {
                tracing::error!(env_var = self.env_var, env_ok, predicate_ok, "{}", message);
                Ok(())
            }
            InsecureMode::Refuse => Err(InsecureGateError(message)),
        }
    }
}

// ─── Standalone helper ────────────────────────────────────────────────────

/// Returns `true` if `addr` is a loopback address (IPv4 `127.x.x.x` or IPv6 `::1`).
///
/// Equivalent to `addr.ip().is_loopback()`, provided as a named helper for
/// use in higher-level gating code.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

// ─── Unit tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_addr() -> SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    fn non_loopback_addr() -> SocketAddr {
        "0.0.0.0:9000".parse().unwrap()
    }

    // ── is_loopback ────────────────────────────────────────────────────────

    #[test]
    fn test_is_loopback_ipv4_loopback_returns_true() {
        assert!(is_loopback(&"127.0.0.1:8080".parse().unwrap()));
    }

    #[test]
    fn test_is_loopback_ipv4_127_x_x_x_returns_true() {
        assert!(is_loopback(&"127.0.0.2:8080".parse().unwrap()));
    }

    #[test]
    fn test_is_loopback_ipv6_loopback_returns_true() {
        assert!(is_loopback(&"[::1]:8080".parse().unwrap()));
    }

    #[test]
    fn test_is_loopback_non_loopback_returns_false() {
        assert!(!is_loopback(&"0.0.0.0:8080".parse().unwrap()));
    }

    #[test]
    fn test_is_loopback_public_ip_returns_false() {
        assert!(!is_loopback(&"192.168.1.1:8080".parse().unwrap()));
    }

    // ── env var + predicate combinations ──────────────────────────────────

    #[test]
    fn test_gate_new_loopback_env_ok_returns_ok() {
        let var = "UTEST_INSECURE_LOOPBACK_OK";
        unsafe { std::env::set_var(var, "true") };
        let gate = InsecureGate::new(var, loopback_addr(), InsecureMode::Refuse);
        let result = gate.check();
        unsafe { std::env::remove_var(var) };
        assert!(result.is_ok());
    }

    #[test]
    fn test_gate_new_loopback_no_env_refuse_returns_err() {
        let var = "UTEST_INSECURE_LOOPBACK_NO_ENV_REFUSE";
        unsafe { std::env::remove_var(var) };
        let gate = InsecureGate::new(var, loopback_addr(), InsecureMode::Refuse);
        assert!(gate.check().is_err());
    }

    #[test]
    fn test_gate_new_non_loopback_env_ok_refuse_returns_err() {
        let var = "UTEST_INSECURE_NON_LOOPBACK_ENV_OK_REFUSE";
        unsafe { std::env::set_var(var, "true") };
        let gate = InsecureGate::new(var, non_loopback_addr(), InsecureMode::Refuse);
        let result = gate.check();
        unsafe { std::env::remove_var(var) };
        assert!(result.is_err());
    }

    #[test]
    fn test_gate_new_non_loopback_no_env_refuse_returns_err() {
        let var = "UTEST_INSECURE_NON_LOOPBACK_NO_ENV_REFUSE";
        unsafe { std::env::remove_var(var) };
        let gate = InsecureGate::new(var, non_loopback_addr(), InsecureMode::Refuse);
        assert!(gate.check().is_err());
    }

    #[test]
    fn test_gate_warn_mode_always_returns_ok() {
        let var = "UTEST_INSECURE_WARN_ALWAYS_OK";
        unsafe { std::env::remove_var(var) };
        let gate = InsecureGate::new(var, non_loopback_addr(), InsecureMode::Warn);
        assert!(gate.check().is_ok());
    }

    #[test]
    fn test_gate_error_message_contains_env_var_name() {
        let var = "UTEST_INSECURE_ERR_MSG";
        unsafe { std::env::remove_var(var) };
        let gate = InsecureGate::new(var, non_loopback_addr(), InsecureMode::Refuse);
        let err = gate.check().unwrap_err();
        assert!(err.to_string().contains(var));
    }

    #[test]
    fn test_gate_with_predicate_true_env_ok_returns_ok() {
        let var = "UTEST_INSECURE_PRED_TRUE_ENV_OK";
        unsafe { std::env::set_var(var, "true") };
        let gate = InsecureGate::with_predicate(var, InsecureMode::Refuse, || true);
        let result = gate.check();
        unsafe { std::env::remove_var(var) };
        assert!(result.is_ok());
    }

    #[test]
    fn test_gate_with_predicate_false_env_ok_refuse_returns_err() {
        let var = "UTEST_INSECURE_PRED_FALSE_ENV_OK_REFUSE";
        unsafe { std::env::set_var(var, "true") };
        let gate = InsecureGate::with_predicate(var, InsecureMode::Refuse, || false);
        let result = gate.check();
        unsafe { std::env::remove_var(var) };
        assert!(result.is_err());
    }

    #[test]
    fn test_gate_env_var_wrong_value_treated_as_unset() {
        let var = "UTEST_INSECURE_ENV_WRONG_VALUE";
        unsafe { std::env::set_var(var, "yes") }; // not "true"
        let gate = InsecureGate::new(var, loopback_addr(), InsecureMode::Refuse);
        let result = gate.check();
        unsafe { std::env::remove_var(var) };
        assert!(result.is_err(), "only 'true' is the accepted value");
    }

    // ── InsecureGateError ─────────────────────────────────────────────────

    #[test]
    fn test_insecure_gate_error_display() {
        let err = InsecureGateError("test message".to_string());
        assert_eq!(err.to_string(), "test message");
    }

    // ── Debug impl ────────────────────────────────────────────────────────

    #[test]
    fn test_gate_debug_does_not_panic() {
        let var = "UTEST_INSECURE_DEBUG";
        let gate = InsecureGate::new(var, loopback_addr(), InsecureMode::Warn);
        let _ = format!("{gate:?}");
    }
}
