//! H-10 regression tests: GrpcRemoteSigner plaintext URL gating.
//!
//! Per ISSUE-2.12: `http://` URLs must be gated by `InsecureGate`.
//! `https://` URLs always pass. In `Warn` mode the gate returns `Ok`; in
//! `Refuse` mode it returns `Err` unless the operator has set the env var.
//!
//! # Env-var isolation
//!
//! Tests that mutate `RVC_REMOTE_SIGNER_ALLOW_INSECURE` hold `ENV_LOCK`
//! so parallel test threads don't race on this global.

use std::sync::Mutex;

use crypto::InsecureMode;
use rvc_grpc_signer::{GrpcRemoteSignerConfig, REMOTE_SIGNER_INSECURE_ENV_VAR};

/// Serialises access to `RVC_REMOTE_SIGNER_ALLOW_INSECURE` across the test
/// threads within this binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ─── helpers ───────────────────────────────────────────────────────────────

fn with_env_var<F: FnOnce()>(value: &str, f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe { std::env::set_var(REMOTE_SIGNER_INSECURE_ENV_VAR, value) };
    f();
    unsafe { std::env::remove_var(REMOTE_SIGNER_INSECURE_ENV_VAR) };
}

fn without_env_var<F: FnOnce()>(f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe { std::env::remove_var(REMOTE_SIGNER_INSECURE_ENV_VAR) };
    f();
}

// ─── https:// URLs always pass ─────────────────────────────────────────────

#[test]
fn test_https_url_always_passes_refuse_mode() {
    without_env_var(|| {
        let config = GrpcRemoteSignerConfig::new("https://signer.example.com:50051");
        assert!(
            config.check_url_security(InsecureMode::Refuse).is_ok(),
            "https:// must always pass, even in Refuse mode without env var"
        );
    });
}

#[test]
fn test_https_url_passes_without_env_var() {
    without_env_var(|| {
        let config = GrpcRemoteSignerConfig::new("https://signer.example.com:50051");
        assert!(config.check_url_security(InsecureMode::Warn).is_ok());
    });
}

// ─── http:// URLs in Refuse mode ───────────────────────────────────────────

#[test]
fn test_http_url_refused_without_env_var() {
    without_env_var(|| {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        assert!(
            config.check_url_security(InsecureMode::Refuse).is_err(),
            "http:// without env var must return Err in Refuse mode"
        );
    });
}

#[test]
fn test_http_url_allowed_with_env_var_in_refuse_mode() {
    with_env_var("true", || {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        assert!(
            config.check_url_security(InsecureMode::Refuse).is_ok(),
            "http:// with env var must return Ok in Refuse mode"
        );
    });
}

// ─── http:// URLs in Warn mode (Phase 2 production behaviour) ───────────────

#[test]
fn test_http_url_warns_with_env_var() {
    with_env_var("true", || {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        assert!(
            config.check_url_security(InsecureMode::Warn).is_ok(),
            "Warn mode always returns Ok (env var set silences the log)"
        );
    });
}

#[test]
fn test_http_url_warn_mode_always_ok_even_without_env_var() {
    without_env_var(|| {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        assert!(
            config.check_url_security(InsecureMode::Warn).is_ok(),
            "Warn mode must always return Ok — error is emitted as a log, not a hard failure"
        );
    });
}

// ─── Error message quality ─────────────────────────────────────────────────

#[test]
fn test_http_url_error_contains_env_var_name() {
    without_env_var(|| {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        let err = config.check_url_security(InsecureMode::Refuse).unwrap_err();
        assert!(
            err.to_string().contains(REMOTE_SIGNER_INSECURE_ENV_VAR),
            "Error must name the env var; got: {err}"
        );
    });
}

// ─── URL variants ──────────────────────────────────────────────────────────

#[test]
fn test_http_url_with_trailing_slash_refused() {
    without_env_var(|| {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051/");
        assert!(config.check_url_security(InsecureMode::Refuse).is_err());
    });
}

#[test]
fn test_https_url_with_trailing_slash_passes() {
    without_env_var(|| {
        let config = GrpcRemoteSignerConfig::new("https://localhost:50051/");
        assert!(config.check_url_security(InsecureMode::Refuse).is_ok());
    });
}
