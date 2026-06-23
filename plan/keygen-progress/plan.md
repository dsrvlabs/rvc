# rvc-keygen Progress Messages — Lightweight Plan

**Status:** Draft
**Scope:** `new-mnemonic` and `existing-mnemonic` subcommands
**Out of scope:** `bls-to-execution`, `exit` (single-shot, fast)

---

## 1. Problem

Running `rvc-keygen new-mnemonic --num-validators 100` (or any non-trivial N) produces no output during the multi-second-per-validator Scrypt encryption phase. The user cannot distinguish a working tool from a hung one, and has no sense of remaining time. Existing `eprintln!` calls only cover the mnemonic banner, dry-run notices, and the final summary table.

The slowest steps today, in order of wall-time on a typical laptop:

| Step                                       | Cost (Scrypt default)             | Currently logged?           |
| ------------------------------------------ | --------------------------------- | --------------------------- |
| `mnemonic_to_seed` (PBKDF2-HMAC-SHA512)    | ~0.5s                             | no                          |
| Per-validator key derivation (EIP-2333)    | ~ms                               | no                          |
| Per-validator keystore encrypt (Scrypt)    | **~1–3s each** (the bottleneck)   | no                          |
| Per-validator verify (decrypt-roundtrip)   | **~1–3s each**                    | no                          |
| Deposit-data JSON write                    | ~ms                               | no                          |
| Final summary table                        | —                                 | yes (`verify::print_summary`) |

For `N = 100` validators this is roughly 200–600s with zero feedback.

## 2. Goals

- The user always knows what step is running and how far along they are.
- Per-validator messages include `[i/N]` so progress is obvious.
- All progress output goes to **stderr** (so stdout remains usable for the deposit JSON in `--dry-run`).
- No new dependencies.
- A `--quiet` flag silences progress but keeps warnings, the mnemonic banner, and the final summary.

## 3. Non-goals

- No animated spinner / TTY tricks. Plain stderr lines only. (Cheap, scriptable, log-friendly. If we later want a TTY spinner for interactive use we can add `indicatif` behind the same `--quiet` switch.)
- No structured logging (`tracing`/`log`). `eprintln!` matches the existing style in this binary.
- No changes to file outputs, exit codes, or the summary table.
- No timing measurements in messages (would be flaky on slow CI).

## 4. UX Design — Message Catalog

All output is **stderr** unless noted. Prefix-free, one fact per line. No emojis.

### 4.1 Pre-loop (in `run()`)

```
rvc-keygen: network=mainnet, validators=100, start_index=0, withdrawal=0xAbCd…1234
Generating mnemonic...                              ← new-mnemonic only
Validating mnemonic phrase...                       ← existing-mnemonic only
Deriving seed from mnemonic (PBKDF2)...
```

The mnemonic banner / backup-notice block (already present, lines 81–93 of `new_mnemonic.rs`) is kept as-is.

### 4.2 Per-validator loop (in `generate_from_seed()`)

For each `i` in `start_index..end_index`, one line per validator:

```
[ 1/100] Deriving keys and encrypting keystore for validator 0...
[ 2/100] Deriving keys and encrypting keystore for validator 1...
...
[100/100] Deriving keys and encrypting keystore for validator 99...
```

The counter width matches `N` (right-pad `i` so columns align). Each line is printed **before** the slow Scrypt encryption + verification for that index, so the user sees `[k/N]` *while* the tool is working on `k`, not after.

Existing `[DRY RUN] Would write keystore: …` lines are kept and emitted *after* the `[i/N]` line for that validator.

### 4.3 Post-loop (in `generate_from_seed()`)

```
Writing deposit data: <path>...
```

…followed by the existing `verify::print_summary` block. No change to summary.

### 4.4 `--quiet` flag

Suppresses §4.1 step labels and §4.2 `[i/N]` lines. Keeps:
- The mnemonic banner / backup notice (security-relevant).
- The dry-run `Would write …` lines (already user-requested output).
- `verify::print_summary` (the deliverable).
- All errors and `WARNING:` lines.

## 5. Code Changes (file-by-file)

### 5.1 `bin/rvc-keygen/src/main.rs`

- Add `#[arg(long)] quiet: bool` to both `NewMnemonic` and `ExistingMnemonic` subcommands.
- Thread `quiet` through to `new_mnemonic::run(...)` and `existing_mnemonic::run(...)`.

### 5.2 `bin/rvc-keygen/src/new_mnemonic.rs`

- Add `quiet: bool` parameter to `run()` and `generate_from_seed()`.
- Introduce a tiny helper at the top of the module:
  ```rust
  fn step(quiet: bool, msg: &str) {
      if !quiet { eprintln!("{msg}"); }
  }
  ```
- In `run()`, before `generate_mnemonic()` and `mnemonic_to_seed()`, emit the §4.1 lines (skip the existing-mnemonic-only line — that one lives in `existing_mnemonic.rs`).
- In `generate_from_seed()`:
  - Before the loop: emit the parameter summary line from §4.1 if not already emitted by the caller. (Decision: emit it in `run()`/`existing_mnemonic::run()`, not here, so each entrypoint shows its own context.)
  - Inside the loop: emit `[i_padded/N] Deriving keys and encrypting keystore for validator {i}...` before the `derive_key_from_path` call.
  - After the loop, before deposit JSON write: emit `Writing deposit data: <path>...`.

Pad-width formula: `let w = N.to_string().len();` then `format!("[{:>w$}/{N}]", i_in_batch, N = num_validators, w = w)`.

### 5.3 `bin/rvc-keygen/src/existing_mnemonic.rs`

- Add `quiet: bool` to `run()`. Thread to `new_mnemonic::generate_from_seed`.
- Emit §4.1 parameter line + `Validating mnemonic phrase...` + `Deriving seed from mnemonic (PBKDF2)...` (after the `prompt_mnemonic()` call returns).

### 5.4 No other crates touched

`crypto::Keystore::encrypt` is not modified; we wrap the call, not the implementation. This keeps the change shallow and avoids any progress-callback API surface.

## 6. Test Plan

Unit tests live alongside each file's existing `#[cfg(test)] mod tests`.

### 6.1 New unit tests

- `test_quiet_flag_suppresses_step_lines` — capture stderr via a temp file redirect (or use the existing `--quiet` flag semantics: assert that with `quiet = true`, `generate_from_seed` runs successfully and produces the same files; we cannot easily capture stderr in-process, so use a smoke approach: assert it runs without panic and produces expected files. The actual content assertion goes in an integration test below).
- `test_progress_counter_padding` — pure function test for the padding helper if extracted (e.g., `fn format_progress(i: u32, n: u32) -> String`). Asserts `format_progress(3, 100) == "[  3/100]"`, `format_progress(1, 5) == "[1/5]"`, `format_progress(99, 100) == "[ 99/100]"`.

### 6.2 New integration test

Add `bin/rvc-keygen/tests/progress_output.rs`:

- Spawn the binary with `std::process::Command` for `new-mnemonic --num-validators 2 --pbkdf2 --dry-run --password-file <tmp>` and `--backup-file <tmp>`.
- Capture stderr.
- Assert it contains:
  - `Generating mnemonic`
  - `Deriving seed from mnemonic`
  - `[1/2] Deriving keys and encrypting keystore for validator 0`
  - `[2/2] Deriving keys and encrypting keystore for validator 1`
- Run the same command with `--quiet` and assert stderr does **not** contain `Deriving seed from mnemonic` but **does** contain the mnemonic banner and the summary header (`Successfully generated`).

Use `--pbkdf2` so the test stays fast; use `--dry-run` so no files persist.

### 6.3 Regression coverage

All existing tests in `new_mnemonic.rs` and `existing_mnemonic.rs` continue to call `generate_from_seed(..., quiet=true, ...)` or are updated to pass the new arg. No behavior under test changes.

## 7. Rollout

Single PR against `develop`. Squash-merge. No flag gating — the flag is the user-facing surface itself (`--quiet`). Defaults are verbose; existing scripted callers that need silence can pass `--quiet`.

## 8. Open questions

1. Should the parameter-summary line (§4.1 first line) include the output directory? Probably yes — it's the most-common "did I run this in the right place" mistake.
2. Should `[i/N]` count be relative to the batch (1..=N) or absolute to the key index (start_index..end_index)? Plan above uses **batch-relative** for the counter and shows the absolute key index in the text (`for validator 0`, `for validator 99`). This avoids confusion when `--start-index` is non-zero.
3. `--quiet` vs `--verbose` default polarity: plan above defaults to verbose. Confirm before implementation.
