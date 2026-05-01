//! Insecure-mode startup gate for `rvc-signer`.
//!
//! Per ISSUE-2.11 (H-9): when `--insecure` is passed on the CLI, the operator
//! must ALSO set `RVC_SIGNER_ALLOW_INSECURE=true` in the environment AND bind
//! to a loopback address.  The check uses [`InsecureGate`] from the `crypto`
//! crate, which provides the shared gating logic for all insecure code paths.
//!
//! ## GA behaviour (Phase 3 ISSUE-3.13 / current)
//!
//! The default mode is [`InsecureMode::Refuse`]: the gate hard-fails on any
//! non-loopback bind address or missing env var.  Operators who depended on the
//! Phase-2 warn-only behaviour must now set `RVC_SIGNER_ALLOW_INSECURE=true`
//! AND use a loopback bind address, or switch to TLS.

use std::net::SocketAddr;

use crypto::{InsecureGate, InsecureGateError, InsecureMode};

/// Environment variable that must be set to `"true"` to allow `--insecure` startup.
pub const INSECURE_ENV_VAR: &str = "RVC_SIGNER_ALLOW_INSECURE";

/// Check whether an `--insecure` startup is permitted.
///
/// - If `insecure` is `false`, returns `Ok(())` immediately (TLS path; no gate
///   needed).
/// - If `insecure` is `true`, constructs an [`InsecureGate`] using
///   [`INSECURE_ENV_VAR`] and `bind_addr`, then calls `gate.check()`.
///
/// # Parameters
///
/// - `insecure`: the value of the `--insecure` CLI flag.
/// - `bind_addr`: the address the server will bind to.
/// - `mode`: the gate mode.  Pass [`InsecureMode::Refuse`] (GA default per
///   NFR-10); [`InsecureMode::Warn`] is available for testing.
///
/// # Returns
///
/// - `Ok(())` when the gate permits startup (fully opted-in in Refuse mode; or
///   always in Warn mode — for tests only).
/// - `Err(`[`InsecureGateError`]`)` when `mode` is [`InsecureMode::Refuse`] and
///   the opt-in conditions are not met.
///
/// # Example
///
/// ```no_run
/// use std::net::SocketAddr;
/// use crypto::InsecureMode;
/// use rvc_signer_bin::insecure_startup::check_insecure_startup;
///
/// let addr: SocketAddr = "127.0.0.1:50052".parse().unwrap();
/// // GA default — Refuse mode; requires env var + loopback.
/// check_insecure_startup(true, addr, InsecureMode::Refuse).expect("fully opted-in");
/// ```
pub fn check_insecure_startup(
    insecure: bool,
    bind_addr: SocketAddr,
    mode: InsecureMode,
) -> Result<(), InsecureGateError> {
    if !insecure {
        return Ok(());
    }
    InsecureGate::new(INSECURE_ENV_VAR, bind_addr, mode).check()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> SocketAddr {
        "127.0.0.1:9000".parse().unwrap()
    }

    fn non_loopback() -> SocketAddr {
        "0.0.0.0:9000".parse().unwrap()
    }

    #[test]
    fn test_not_insecure_is_always_ok() {
        // insecure=false → gate not consulted → Ok regardless of bind addr
        assert!(check_insecure_startup(false, non_loopback(), InsecureMode::Refuse).is_ok());
        assert!(check_insecure_startup(false, loopback(), InsecureMode::Refuse).is_ok());
    }

    #[test]
    fn test_warn_mode_always_returns_ok() {
        unsafe { std::env::remove_var(INSECURE_ENV_VAR) };
        assert!(check_insecure_startup(true, non_loopback(), InsecureMode::Warn).is_ok());
        assert!(check_insecure_startup(true, loopback(), InsecureMode::Warn).is_ok());
    }

    #[test]
    fn test_refuse_non_loopback_no_env_returns_err() {
        unsafe { std::env::remove_var(INSECURE_ENV_VAR) };
        assert!(check_insecure_startup(true, non_loopback(), InsecureMode::Refuse).is_err());
    }

    #[test]
    fn test_refuse_loopback_no_env_returns_err() {
        unsafe { std::env::remove_var(INSECURE_ENV_VAR) };
        assert!(check_insecure_startup(true, loopback(), InsecureMode::Refuse).is_err());
    }

    #[test]
    fn test_refuse_non_loopback_with_env_returns_err() {
        unsafe { std::env::set_var(INSECURE_ENV_VAR, "true") };
        let result = check_insecure_startup(true, non_loopback(), InsecureMode::Refuse);
        unsafe { std::env::remove_var(INSECURE_ENV_VAR) };
        assert!(result.is_err(), "non-loopback predicate fails → Refuse");
    }

    #[test]
    fn test_refuse_loopback_with_env_returns_ok() {
        unsafe { std::env::set_var(INSECURE_ENV_VAR, "true") };
        let result = check_insecure_startup(true, loopback(), InsecureMode::Refuse);
        unsafe { std::env::remove_var(INSECURE_ENV_VAR) };
        assert!(result.is_ok(), "fully opted-in: loopback + env → Ok");
    }

    #[test]
    fn test_error_message_contains_env_var_name() {
        unsafe { std::env::remove_var(INSECURE_ENV_VAR) };
        let err = check_insecure_startup(true, non_loopback(), InsecureMode::Refuse).unwrap_err();
        assert!(err.to_string().contains(INSECURE_ENV_VAR), "got: {err}");
    }
}
