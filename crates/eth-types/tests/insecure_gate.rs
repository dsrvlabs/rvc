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
fn test_evaluate_warn_secure_returns_proceed() {
    let d = evaluate(InsecureGate::Warn, false, "any reason");
    assert_eq!(d, Decision::Proceed);
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
    std::env::set_var("RVC_INSECURE_GATE_TEST_TRUE_LC", "true");
    let gate = from_env("RVC_INSECURE_GATE_TEST_TRUE_LC", InsecureGate::Refuse);
    std::env::remove_var("RVC_INSECURE_GATE_TEST_TRUE_LC");
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_true_uppercase_returns_allow() {
    std::env::set_var("RVC_INSECURE_GATE_TEST_TRUE_UC", "TRUE");
    let gate = from_env("RVC_INSECURE_GATE_TEST_TRUE_UC", InsecureGate::Refuse);
    std::env::remove_var("RVC_INSECURE_GATE_TEST_TRUE_UC");
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_true_mixed_case_returns_allow() {
    std::env::set_var("RVC_INSECURE_GATE_TEST_TRUE_MC", "True");
    let gate = from_env("RVC_INSECURE_GATE_TEST_TRUE_MC", InsecureGate::Refuse);
    std::env::remove_var("RVC_INSECURE_GATE_TEST_TRUE_MC");
    assert_eq!(gate, InsecureGate::Allow);
}

#[test]
fn test_from_env_false_lowercase_returns_refuse() {
    std::env::set_var("RVC_INSECURE_GATE_TEST_FALSE_LC", "false");
    let gate = from_env("RVC_INSECURE_GATE_TEST_FALSE_LC", InsecureGate::Allow);
    std::env::remove_var("RVC_INSECURE_GATE_TEST_FALSE_LC");
    assert_eq!(gate, InsecureGate::Refuse);
}

#[test]
fn test_from_env_false_uppercase_returns_refuse() {
    std::env::set_var("RVC_INSECURE_GATE_TEST_FALSE_UC", "FALSE");
    let gate = from_env("RVC_INSECURE_GATE_TEST_FALSE_UC", InsecureGate::Allow);
    std::env::remove_var("RVC_INSECURE_GATE_TEST_FALSE_UC");
    assert_eq!(gate, InsecureGate::Refuse);
}

#[test]
fn test_from_env_unrecognized_value_returns_default() {
    std::env::set_var("RVC_INSECURE_GATE_TEST_UNRECOG", "maybe");
    let gate = from_env("RVC_INSECURE_GATE_TEST_UNRECOG", InsecureGate::Warn);
    std::env::remove_var("RVC_INSECURE_GATE_TEST_UNRECOG");
    assert_eq!(gate, InsecureGate::Warn);
}
