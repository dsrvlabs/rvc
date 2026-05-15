//! Integration tests for [`InsecureGate`].
//!
//! Test plan (from ISSUE-2.10):
//! - `test_gate_warn_logs_and_returns_ok`     — env var set, mode=Warn; assert Ok + error log
//! - `test_gate_refuse_returns_err`            — env var unset, mode=Refuse; assert Err
//! - `test_gate_loopback_bind_allowed_with_env_var` — bind=127.0.0.1 + env var → silent Ok
//! - `test_gate_non_loopback_refused`          — bind=0.0.0.0, env var unset, Refuse → Err

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rvc_crypto::insecure::{InsecureGate, InsecureMode};
use tracing_subscriber::layer::SubscriberExt;

// ─── tracing event-capture helper ─────────────────────────────────────────

/// Shared buffer of `(level, message)` pairs captured from tracing events.
type CapturedEvents = Arc<Mutex<Vec<(tracing::Level, String)>>>;

/// Records the level and message of each tracing event.
struct EventCapture {
    events: CapturedEvents,
}

impl<S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>>
    tracing_subscriber::Layer<S> for EventCapture
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = *event.metadata().level();
        let mut visitor = MsgVisitor(String::new());
        event.record(&mut visitor);
        self.events.lock().unwrap().push((level, visitor.0));
    }
}

struct MsgVisitor(String);

impl tracing::field::Visit for MsgVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}

fn make_capture() -> (CapturedEvents, EventCapture) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let layer = EventCapture { events: events.clone() };
    (events, layer)
}

// ─── address helpers ──────────────────────────────────────────────────────

fn loopback() -> SocketAddr {
    "127.0.0.1:9000".parse().unwrap()
}

fn non_loopback() -> SocketAddr {
    "0.0.0.0:9000".parse().unwrap()
}

// ─── tests ────────────────────────────────────────────────────────────────

/// Env var set, non-loopback bind, mode=Warn.
/// Expected: gate returns Ok(()) AND emits an error-level log.
#[test]
fn test_gate_warn_logs_and_returns_ok() {
    let env_var = "INSECURE_GATE_TEST_WARN_LOGS";
    // SAFETY: unique env-var name; this test does not run concurrently with
    //         tests that share the same name.
    unsafe { std::env::set_var(env_var, "true") };

    let (events, layer) = make_capture();
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Non-loopback → predicate fails → Warn mode → log + Ok
    let gate = InsecureGate::new(env_var, non_loopback(), InsecureMode::Warn);
    let result = gate.check();

    unsafe { std::env::remove_var(env_var) };

    assert!(result.is_ok(), "Warn mode must return Ok(())");

    let captured = events.lock().unwrap();
    let has_error_event = captured.iter().any(|(lvl, _)| *lvl == tracing::Level::ERROR);
    assert!(has_error_event, "Warn mode must emit an error-level log; got: {captured:?}");
}

/// Env var unset, mode=Refuse.
/// Expected: gate returns Err with an actionable message mentioning the env var.
#[test]
fn test_gate_refuse_returns_err() {
    let env_var = "INSECURE_GATE_TEST_REFUSE_ERR";
    unsafe { std::env::remove_var(env_var) };

    let gate = InsecureGate::new(env_var, non_loopback(), InsecureMode::Refuse);
    let result = gate.check();

    assert!(result.is_err(), "Refuse mode with no env var must return Err");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains(env_var),
        "Error message must mention the env var name; got: {err_msg}"
    );
}

/// Loopback bind address with env var set.
/// Expected: gate returns Ok(()) silently (no warning needed — fully opted-in).
#[test]
fn test_gate_loopback_bind_allowed_with_env_var() {
    let env_var = "INSECURE_GATE_TEST_LOOPBACK_ALLOWED";
    unsafe { std::env::set_var(env_var, "true") };

    let (events, layer) = make_capture();
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let gate = InsecureGate::new(env_var, loopback(), InsecureMode::Warn);
    let result = gate.check();

    unsafe { std::env::remove_var(env_var) };

    assert!(result.is_ok(), "Loopback + env var must return Ok(())");

    // No warning should be emitted for the fully-opted-in case
    let captured = events.lock().unwrap();
    let has_error_event = captured.iter().any(|(lvl, _)| *lvl == tracing::Level::ERROR);
    assert!(!has_error_event, "Silent Ok must not emit an error log; got: {captured:?}");
}

/// Non-loopback bind address, env var unset, mode=Refuse.
/// Expected: gate returns Err.
#[test]
fn test_gate_non_loopback_refused() {
    let env_var = "INSECURE_GATE_TEST_NON_LOOPBACK_REFUSED";
    unsafe { std::env::remove_var(env_var) };

    let gate = InsecureGate::new(env_var, non_loopback(), InsecureMode::Refuse);
    let result = gate.check();

    assert!(result.is_err(), "Non-loopback without env var in Refuse mode must return Err");
}

/// Refuse mode with loopback but without env var — BOTH conditions required.
#[test]
fn test_gate_refuse_loopback_no_env_var() {
    let env_var = "INSECURE_GATE_TEST_LOOPBACK_NO_ENV";
    unsafe { std::env::remove_var(env_var) };

    let gate = InsecureGate::new(env_var, loopback(), InsecureMode::Refuse);
    let result = gate.check();

    assert!(result.is_err(), "Loopback without env var in Refuse mode must return Err");
}

/// Warn mode with no env var and non-loopback must still return Ok (Warn never blocks).
#[test]
fn test_gate_warn_mode_no_env_var_returns_ok() {
    let env_var = "INSECURE_GATE_TEST_WARN_NO_ENV";
    unsafe { std::env::remove_var(env_var) };

    let gate = InsecureGate::new(env_var, non_loopback(), InsecureMode::Warn);
    assert!(gate.check().is_ok(), "Warn mode must always return Ok");
}

/// Custom URL-scheme predicate: https:// passes silently with env var.
#[test]
fn test_gate_custom_predicate_https_with_env_var_ok() {
    let env_var = "INSECURE_GATE_TEST_PREDICATE_HTTPS";
    unsafe { std::env::set_var(env_var, "true") };

    let url = "https://signer.example.com:9000".to_string();
    let gate = InsecureGate::with_predicate(env_var, InsecureMode::Refuse, move || {
        url.starts_with("https://")
    });
    let result = gate.check();

    unsafe { std::env::remove_var(env_var) };
    assert!(result.is_ok(), "https:// with env var must be Ok");
}

/// Custom URL-scheme predicate: http:// fails predicate → Refuse.
#[test]
fn test_gate_custom_predicate_http_refused() {
    let env_var = "INSECURE_GATE_TEST_PREDICATE_HTTP";
    unsafe { std::env::set_var(env_var, "true") };

    let url = "http://signer.example.com:9000".to_string();
    let gate = InsecureGate::with_predicate(env_var, InsecureMode::Refuse, move || {
        url.starts_with("https://")
    });
    let result = gate.check();

    unsafe { std::env::remove_var(env_var) };
    assert!(result.is_err(), "http:// fails predicate → Refuse must return Err");
}

/// `InsecureGateError` implements `std::error::Error` and `Display`.
#[test]
fn test_insecure_gate_error_is_std_error() {
    use rvc_crypto::insecure::InsecureGateError;
    let err = InsecureGateError("some message".to_string());
    // The std::error::Error bound is checked at compile time; just verify Display.
    assert_eq!(err.to_string(), "some message");
    // Verify it can be used as Box<dyn std::error::Error>.
    let boxed: Box<dyn std::error::Error> = Box::new(InsecureGateError("boxed".to_string()));
    assert_eq!(boxed.to_string(), "boxed");
}

/// IPv6 loopback (::1) is also accepted when env var is set.
#[test]
fn test_gate_ipv6_loopback_with_env_var_ok() {
    let env_var = "INSECURE_GATE_TEST_IPV6_LOOPBACK";
    unsafe { std::env::set_var(env_var, "true") };

    let addr: SocketAddr = "[::1]:9000".parse().unwrap();
    let gate = InsecureGate::new(env_var, addr, InsecureMode::Refuse);
    let result = gate.check();

    unsafe { std::env::remove_var(env_var) };
    assert!(result.is_ok(), "IPv6 loopback + env var must be Ok");
}
