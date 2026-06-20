use rvc_eth_types::insecure::{evaluate, from_env, Decision, InsecureGate};

// ─── evaluate: condition_is_insecure = true ───────────────────────────────────

#[test]
fn test_evaluate_refuse_insecure_returns_abort() {
    let d = evaluate(InsecureGate::Refuse, true, "test reason");
    assert_eq!(d, Decision::Abort { reason: "test reason" });
}

#[test]
#[tracing_test::traced_test]
fn test_evaluate_warn_insecure_returns_proceed_with_warning_and_logs() {
    let d = evaluate(InsecureGate::Warn, true, "warn reason");
    assert_eq!(d, Decision::ProceedWithWarning { reason: "warn reason" });
    assert!(logs_contain("warn reason"));
}

#[test]
fn test_evaluate_allow_insecure_returns_proceed() {
    let d = evaluate(InsecureGate::Allow, true, "allow reason");
    assert_eq!(d, Decision::Proceed);
}

// ─── evaluate: condition_is_insecure = false ─────────────────────────────────

#[test]
fn test_evaluate_refuse_secure_returns_proceed() {
    let d = evaluate(InsecureGate::Refuse, false, "any reason");
    assert_eq!(d, Decision::Proceed);
}

#[test]
#[tracing_test::traced_test]
fn test_evaluate_warn_secure_no_log_emitted() {
    let d = evaluate(InsecureGate::Warn, false, "secure reason");
    assert_eq!(d, Decision::Proceed);
    assert!(!logs_contain("secure reason"), "warn must not fire on the secure path");
}

#[test]
fn test_evaluate_allow_secure_returns_proceed() {
    let d = evaluate(InsecureGate::Allow, false, "any reason");
    assert_eq!(d, Decision::Proceed);
}

// ─── from_env ────────────────────────────────────────────────────────────────

#[test]
fn test_from_env_unset_returns_default_refuse() {
    // Use a unique var name to avoid collision with other tests
    let gate = from_env("RVC_INSECURE_GATE_TEST_UNSET_A", InsecureGate::Refuse);
    assert_eq!(gate, InsecureGate::Refuse);
}

#[test]
fn test_from_env_unset_returns_default_allow() {
    let gate = from_env("RVC_INSECURE_GATE_TEST_UNSET_B", InsecureGate::Allow);
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_true_lowercase_returns_allow() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_TRUE_LC", "true") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_TRUE_LC", InsecureGate::Refuse);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_TRUE_LC") };
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_true_uppercase_returns_allow() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_TRUE_UC", "TRUE") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_TRUE_UC", InsecureGate::Refuse);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_TRUE_UC") };
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_true_mixed_case_returns_allow() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_TRUE_MC", "True") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_TRUE_MC", InsecureGate::Refuse);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_TRUE_MC") };
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_false_lowercase_returns_refuse() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_FALSE_LC", "false") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_FALSE_LC", InsecureGate::Allow);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_FALSE_LC") };
    assert_eq!(gate, InsecureGate::Refuse);
}

#[test]
fn test_from_env_false_uppercase_returns_refuse() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_FALSE_UC", "FALSE") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_FALSE_UC", InsecureGate::Allow);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_FALSE_UC") };
    assert_eq!(gate, InsecureGate::Refuse);
}

#[test]
fn test_from_env_unrecognized_value_returns_default() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_UNRECOG", "maybe") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_UNRECOG", InsecureGate::Warn);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_UNRECOG") };
    assert_eq!(gate, InsecureGate::Warn);
}

// ─── from_env edge cases: values that must never mean Allow ──────────────────

#[test]
fn test_from_env_empty_string_returns_default() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_EMPTY", "") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_EMPTY", InsecureGate::Refuse);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_EMPTY") };
    assert_eq!(gate, InsecureGate::Refuse);
}

#[test]
fn test_from_env_one_returns_default() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_ONE", "1") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_ONE", InsecureGate::Refuse);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_ONE") };
    assert_eq!(gate, InsecureGate::Refuse);
}

#[test]
fn test_from_env_zero_returns_default() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_ZERO", "0") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_ZERO", InsecureGate::Allow);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_ZERO") };
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_whitespace_padded_true_returns_default() {
    unsafe { std::env::set_var("RVC_INSECURE_GATE_TEST_WS_TRUE", "  true  ") };
    let gate = from_env("RVC_INSECURE_GATE_TEST_WS_TRUE", InsecureGate::Refuse);
    unsafe { std::env::remove_var("RVC_INSECURE_GATE_TEST_WS_TRUE") };
    assert_eq!(gate, InsecureGate::Refuse);
}
