//! H-9 regression tests: `--insecure` flag requires env-var double-confirm + loopback gate.
//!
//! Acceptance criteria (ISSUE-2.11):
//! - Gate uses `RVC_SIGNER_ALLOW_INSECURE=true` as the opt-in env var.
//! - In `Refuse` mode: non-loopback bind without env var → `Err`.
//! - In `Warn` mode: any bind with any env state → `Ok` (but error log emitted).
//! - Loopback + env var → silent `Ok` (fully opted-in).

use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crypto::InsecureMode;
use rvc_signer_bin::insecure_startup::check_insecure_startup;

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

/// `--insecure` is false → `check_insecure_startup` is a no-op regardless of
/// bind address or env var.
#[test]
fn test_no_insecure_flag_is_always_ok() {
    let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
    // env var absent; Refuse mode
    let result = check_insecure_startup(false, addr, InsecureMode::Refuse);
    assert!(result.is_ok(), "insecure=false must always pass");
}

/// Non-loopback bind, no env var, `Refuse` mode → `Err` with actionable message.
///
/// Corresponds to the test-plan entry
/// `test_refuse_non_loopback_without_env_var`.
#[test]
fn test_refuse_non_loopback_without_env_var() {
    let _lock = env_lock();
    let var = "RVC_SIGNER_ALLOW_INSECURE_H9_T1";
    // Temporarily shadow the real env var name inside the gate by providing a
    // unique var; we call the helper with a custom var via the lower-level gate
    // directly to keep tests hermetic.
    //
    // NOTE: `check_insecure_startup` always uses `RVC_SIGNER_ALLOW_INSECURE`.
    // Remove it for this test.
    let _guard = EnvGuard::remove("RVC_SIGNER_ALLOW_INSECURE");
    let _ = var; // unused — kept for documentation

    let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
    let result = check_insecure_startup(true, addr, InsecureMode::Refuse);
    assert!(result.is_err(), "Refuse mode + non-loopback + no env var must fail");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("RVC_SIGNER_ALLOW_INSECURE"),
        "error must name the required env var; got: {msg}"
    );
}

/// Non-loopback bind + env var set, `Warn` mode → `Ok` (Warn never blocks).
///
/// Corresponds to the test-plan entry
/// `test_warn_non_loopback_with_env_var_warn_mode`.
#[test]
fn test_warn_non_loopback_with_env_var_warn_mode() {
    let _lock = env_lock();
    let _guard = EnvGuard::set("RVC_SIGNER_ALLOW_INSECURE", "true");

    let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
    let result = check_insecure_startup(true, addr, InsecureMode::Warn);
    assert!(result.is_ok(), "Warn mode must always return Ok; got: {:?}", result.err());
}

/// Loopback bind + env var set → silent `Ok` (fully opted-in, predicate passes).
///
/// Corresponds to the test-plan entry
/// `test_loopback_bind_with_env_var_succeeds`.
#[test]
fn test_loopback_bind_with_env_var_succeeds() {
    let _lock = env_lock();
    let _guard = EnvGuard::set("RVC_SIGNER_ALLOW_INSECURE", "true");

    let addr: SocketAddr = "127.0.0.1:50051".parse().unwrap();
    let result = check_insecure_startup(true, addr, InsecureMode::Warn);
    assert!(result.is_ok(), "loopback + env var must succeed; got: {:?}", result.err());
}

/// Loopback bind, no env var, `Refuse` mode → `Err`.
/// BOTH conditions (env var AND loopback) must be satisfied.
#[test]
fn test_refuse_loopback_without_env_var() {
    let _lock = env_lock();
    let _guard = EnvGuard::remove("RVC_SIGNER_ALLOW_INSECURE");

    let addr: SocketAddr = "127.0.0.1:50051".parse().unwrap();
    let result = check_insecure_startup(true, addr, InsecureMode::Refuse);
    assert!(result.is_err(), "loopback without env var in Refuse mode must fail");
}

/// Non-loopback bind + env var set, `Refuse` mode → `Err`.
/// Loopback is required even when the env var is present.
#[test]
fn test_refuse_non_loopback_with_env_var() {
    let _lock = env_lock();
    let _guard = EnvGuard::set("RVC_SIGNER_ALLOW_INSECURE", "true");

    let addr: SocketAddr = "0.0.0.0:50051".parse().unwrap();
    let result = check_insecure_startup(true, addr, InsecureMode::Refuse);
    assert!(result.is_err(), "non-loopback with env var in Refuse mode must fail");
}

/// IPv6 loopback (`::1`) + env var + `Warn` mode → `Ok`.
#[test]
fn test_ipv6_loopback_with_env_var_warn_mode() {
    let _lock = env_lock();
    let _guard = EnvGuard::set("RVC_SIGNER_ALLOW_INSECURE", "true");

    let addr: SocketAddr = "[::1]:50051".parse().unwrap();
    let result = check_insecure_startup(true, addr, InsecureMode::Warn);
    assert!(result.is_ok(), "IPv6 loopback + env var in Warn mode must succeed");
}

// ─── env-var RAII guard ───────────────────────────────────────────────────────

/// RAII wrapper that restores (or removes) an env var when dropped.
/// This prevents test pollution when tests modify the environment.
struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        // SAFETY: env var access in tests is inherently single-threaded within
        // each test binary; unique var names prevent cross-test pollution.
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe { std::env::remove_var(key) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(v) => unsafe { std::env::set_var(self.key, v) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}
