# Test-Acceleration Baseline (pre-changes)

**Captured:** 2026-05-02
**Source HEAD:** `ec74f5c fix(rvc-signer,grpc-signer,crypto): test-isolation env-var mutexes for GA Refuse contract (ISSUE-3.13 review)` (base of `develop` and `perf/test-acceleration`).

**Command:** `( /usr/bin/time -p make test ) 2>&1 | tee /tmp/rvc-test-baseline.log`

## Wall and CPU

| Metric | Seconds |
|--------|--------:|
| `real` | 400.17 |
| `user` | 1573.66 |
| `sys`  | 59.16  |

CPU/wall ≈ 3.93×.

## Top 15 suites by wall time

| Wall (s) | Tests passed | Suite |
|---------:|-------------:|-------|
| 128.73 | 343 | unittests src/lib.rs (rvc_crypto) |
|  44.22 |  17 | tests/compatibility.rs (rvc_keygen) |
|  40.22 | 421 | unittests src/lib.rs (rvc) |
|  32.15 | 119 (3 ignored) | unittests src/lib.rs (rvc_signer_bin) |
|  29.62 | 107 | unittests src/main.rs (rvc_keygen) |
|  22.55 |   5 (3 ignored) | tests/integration_test.rs (rvc-bin) |
|  11.80 |   4 | tests/parallel_load.rs (rvc_crypto) |
|   6.09 |  45 | tests/tier3_operations.rs (rvc-bin) |
|   4.67 |   3 | tests/audit_log_m5.rs (rvc-signer) |
|   4.54 |   3 | tests/sse_oversize_h11.rs (beacon) |
|   2.43 |   4 | tests/body_cap_h12.rs (beacon) |
|   1.72 |   9 | tests/proptest_slashing.rs (slashing) |
|   1.56 | 238 | unittests src/lib.rs (rvc_bn_manager) |
|   1.12 |   1 | tests/sse_consumer_exit.rs (beacon) |
|   1.03 | 226 | unittests src/lib.rs (beacon) |

## Top per-test offenders (CPU s, captured via `cargo +nightly … --report-time`)

### rvc-crypto lib — keystore scrypt tests
- `test_encrypt_different_keys_produce_different_ciphertext` 70.86
- `test_decrypted_key_can_sign_after_encrypt` 66.75
- `test_encrypt_decrypt_roundtrip_scrypt` 66.31
- `test_encrypt_wrong_password_fails_decrypt` 62.38
- `test_to_file_creates_file_and_roundtrips` 52.06
- `test_encrypt_scrypt_params_correct` 40.77
- `test_encrypt_scrypt_produces_valid_keystore` 33.32
- `test_encrypt_iv_is_32_hex_chars` 33.24
- `test_decrypted_key_can_sign` 33.14
- `test_checksum_verification_failure_wrong_password` 33.13
- `test_encrypt_pubkey_matches` 33.01
- ~13 more keystore tests at 28-32 s each

### rvc lib — wiremock + tracing
- `test_check_reorg_at_epoch_boundary_timeout_bounds_slow_beacon` 40.01
- `test_duty_fetch_timeout` 10.00
- `test_concurrent_import_delete_same_key` 9.08
- `test_epoch_boundary_creates_epoch_span` 7.81
- `test_epoch_boundary_span_is_child_of_slot_process` 7.67

### rvc-signer-bin lib — keystore + reload
- `reload::tests::test_reloader_add_and_remove_multiple` 25.52
- `integration_polish::tests::test_hot_reload_multiple_keys_added_incrementally` 18.69
- `backend::basic::tests::test_public_keys_returns_loaded_keys` 13.29
- ~7 more reload/backend tests at 7-9 s each

### rvc-bin integration_test.rs — `build_binary()` redundancy
- `test_livez_endpoint_always_ok` 32.04
- `test_start_with_invalid_config` 21.76
- `test_version_command` 21.76
- `test_help_command` 21.76
- `test_start_help` 21.73

### rvc-keygen — mnemonic + scrypt
- `test_keystore_roundtrip_scrypt` 44.32
- `test_existing_mnemonic_start_index_offset` 29.42
- `test_existing_mnemonic_generates_same_keys_as_new_mnemonic` 20.10
- `test_existing_mnemonic_different_passphrase_different_keys` 19.45
- `test_generate_multiple_validators_with_start_index` 15.95

## Result

`make test` exits 0 — all suites green. Slowness, not correctness, is the issue.

## Goal

`make test` ≤ 2m30s and `make test-fast` (nextest) ≤ 1m30s after applying the plan.
