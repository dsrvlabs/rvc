//! G-2 / ARCH-P1-1 config-drift gate — clauses (ii), (iii), (iv).
//!
//! Seam α (`bin/rvc/src/cli.rs` group `Args` structs → `impl From<StartArgs> for CliOverrides`)
//! is the **one** seam in the five-site config pipeline that rustc does not guard: the destructure
//! at `cli.rs` is exhaustive over the 13 group *bindings*, but the 74 group *fields* are read by
//! field access, so a new field in e.g. `BeaconArgs` compiles silently and is ignored at runtime.
//!
//! ## Clause (i) is DROPPED, not forgotten
//!
//! "Every `CliOverrides` field is consumed in `merge_with_cli`" is **already enforced by rustc**:
//! `merge_cli_fields!` exhaustively destructures `CliOverrides`
//! (`crates/rvc/src/config/types.rs`). A scanner for it can only ever be green. Readers who do not
//! know this will think it was overlooked — hence this paragraph.
//!
//! ## Clause (ii) — seam α
//!
//! Every group-arg field must be read as `<binding>.<field>` in `From<StartArgs>`, unless listed
//! on the shrinking-only `BYPASS` table. `ALIASES` documents rename / 2:1 collapse only; sources
//! must still be read under the clap field name.
//!
//! ## Clause (iii) — validation coverage (descoped)
//!
//! Not "every `Config` field has a marker" (65 lines of noise). Instead: every `CliOverrides`
//! field name appears in `Config::validate`'s body (`types.rs`) **or** on the shrinking-only
//! [`UNVALIDATED`] list. Adding a knob without a check or a list entry fails CI.
//!
//! ## Clause (iv) — `CLAP_DEFAULT_CLOBBERS` (ADR-009 / F9)
//!
//! Formerly nine `CliOverrides` fields were populated with unconditional `Some(<clap field with
//! default_value>)` in `From<StartArgs>`. Clap's default is indistinguishable from an operator
//! flag, so `merge_with_cli`'s `set` arm overwrote a TOML value even when the flag was absent
//! (e.g. TOML `metrics_port = 9090` silently became 8080). ARCH-6b converted those clap fields to
//! `Option<T>` without `default_value`, so [`CLAP_DEFAULT_CLOBBERS`] is now **empty**. The list
//! remains **shrinking-only** (may not grow); the detector still flags a synthetic reintroduction
//! so an empty list is not a dead gate.
//!
//! ## Tests that *look* like precedence tests and are not
//!
//! No existing test catches the clap-default clobber:
//! - `test_start_args_convert_to_equivalent_cli_overrides` (`bin/rvc/src/cli.rs`) passes every flag
//!   **explicitly**, so it only exercises the operator-supplied branch.
//! - `test_start_help_lists_every_flag` compares a hand-maintained `START_FLAGS` array against
//!   `--help` text — a surface inventory, not a file-vs-CLI precedence check.
//!
//! ## Interim lifetime
//!
//! This gate is **interim by construction**. ADR-008 Phase 4 collapses seam α (group `Args` →
//! direct `Config` paths), at which point clauses (i)/(ii) and the `BYPASS` / `ALIASES` tables are
//! deleted with it; only clauses (iii)/(iv) survive (iv with an empty list after ARCH-6b).
//!
//! ## Non-vacuity
//!
//! `assert_eq!(bindings.len(), 13)` and `assert_eq!(checked, 74)` so a rename of `StartArgs` or a
//! group cannot turn the gate green forever. Field arithmetic: `74 − 8 − 1 = 65` (group fields
//! minus BYPASS minus the sole 2:1 alias collapse) equals `CliOverrides` field count.
//!
//! ## Matcher limits (clause ii is a presence scan)
//!
//! Field access matching is **identifier-bounded** (`binding.field` must not be a prefix of a
//! longer sibling such as `logfile` vs `logfile_max_size`) and runs on a **comment-stripped**
//! From body. It is still **presence-only**: a discarded read (`let _ = binding.field`) satisfies
//! the detector. Requiring RHS assignment into `CliOverrides { … }` is deferred (typed dataflow
//! is out of scope for this interim gate); treat green as necessary, not sufficient, against a
//! deliberate greenwash of that form.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as `kat_policy.rs`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

const CLI_RS: &str = "bin/rvc/src/cli.rs";
const TYPES_RS: &str = "crates/rvc/src/config/types.rs";

/// ARCH-4f: migrated clap groups live in `rvc-config` and are re-imported by `StartArgs`.
const MIGRATED_GROUP_SRCS: &[&str] = &[
    "crates/rvc-config/src/sections/tracing.rs",
    "crates/rvc-config/src/sections/keymanager.rs",
    "crates/rvc-config/src/sections/grpc_signer.rs",
    "crates/rvc-config/src/sections/monitoring.rs",
];

// ---------------------------------------------------------------------------
// Shrinking-only tables (reason string required per entry)
// ---------------------------------------------------------------------------

/// Group-struct fields that deliberately never reach `CliOverrides` / `Config`: they are read
/// straight off `StartArgs` at `cli.rs` into `bn_manager::OperationTimeouts` or run/logging options.
///
/// **Shrinking-only.** Entries may be **removed** (by giving the knob a `Config` field — ADR-008
/// Phase 4 shrinks the four BN timeouts), never **added**. Adding one hides a real drift.
///
/// Tuple: `(struct_name, field_name, reason)`.
const BYPASS: &[(&str, &str, &str)] = &[
    (
        "BeaconArgs",
        "aggregate_timeout",
        "routed to bn_manager::OperationTimeouts.aggregate_fetch/submit (cli.rs), not CliOverrides",
    ),
    (
        "BeaconArgs",
        "attestation_timeout",
        "routed to bn_manager::OperationTimeouts.attestation_fetch (cli.rs), not CliOverrides",
    ),
    (
        "BeaconArgs",
        "block_production_timeout",
        "routed to bn_manager::OperationTimeouts.block_production (cli.rs), not CliOverrides",
    ),
    (
        "BeaconArgs",
        "duty_fetch_timeout",
        "routed to bn_manager::OperationTimeouts.duty_fetch (cli.rs), not CliOverrides",
    ),
    ("LoggingArgs", "enable_log_reload", "run/logging init only (cli.rs); no Config field"),
    ("LoggingArgs", "log_format", "telemetry::LogFormat::resolve only (cli.rs); no Config field"),
    ("SlashingArgs", "strict_permissions", "run options only (cli.rs); no Config field"),
    ("SlashingArgs", "strict_slashing_semantics", "run options only (cli.rs); no Config field"),
];

/// Group fields whose `CliOverrides` name differs from the clap field name.
///
/// Two opposite shapes (F13):
/// - 1:1 negated rename: `no_doppelganger_detection` → `doppelganger_detection`
/// - 2:1 collapse: `no_keymanager` + `keymanager_enabled` → `keymanager_enabled` (the sole −1 in
///   `74 − 8 − 1 = 65`)
///
/// Tuple: `(struct_name, field_name, override_field, reason)`.
const ALIASES: &[(&str, &str, &str, &str)] = &[
    (
        "KeymanagerArgs",
        "no_keymanager",
        "keymanager_enabled",
        "2:1 collapse with keymanager_enabled (cli.rs From impl); sole −1 in 74−8−1=65",
    ),
    (
        "SafetyArgs",
        "no_doppelganger_detection",
        "doppelganger_detection",
        "1:1 negated rename: flag sets doppelganger_detection=Some(false) (cli.rs From impl)",
    ),
];

/// Clause (iv) / ADR-009 / F9: `CliOverrides` fields populated with unconditional
/// `Some(<binding>.<field>)` from a non-`Option` clap field that carries `default_value` /
/// `default_value_t`. Clap's default then clobbers a TOML value when the flag is absent.
///
/// **Shrinking-only.** Emptied by ARCH-6b (nine clap fields → `Option<T>` without defaults).
/// A new instance is a live defect and fails the gate. The synthetic RED in
/// `clap_default_clobber_detector_flags_a_tenth_instance` keeps an empty list falsifiable.
///
/// Tuple: `(cli_overrides_field, reason)`. Sorted by field name.
const CLAP_DEFAULT_CLOBBERS: &[(&str, &str)] = &[];

/// Clause (iii): `CliOverrides` fields whose names do **not** appear (identifier-bounded) in
/// `Config::validate`'s body. Most knobs legitimately have nothing to check at startup.
///
/// **Shrinking-only.** Entries may be **removed** (by adding a field-name check to `validate`),
/// never **added** without acknowledging a new unvalidated knob. A new `CliOverrides` field that
/// is neither mentioned in `validate` nor listed here fails the gate.
///
/// Tuple: `(cli_overrides_field, reason)`. Sorted by field name.
const UNVALIDATED: &[(&str, &str)] = &[
    ("allow_unsupported_fork", "no field-name check in Config::validate"),
    ("beacon_max_body_bytes", "no field-name check in Config::validate"),
    ("block_selection_mode", "no field-name check in Config::validate"),
    ("builder_circuit_breaker_consecutive_limit", "no field-name check in Config::validate"),
    ("builder_circuit_breaker_epoch_limit", "no field-name check in Config::validate"),
    ("disable_attesting", "no field-name check in Config::validate"),
    ("disable_keystore_locking", "no field-name check in Config::validate"),
    ("doppelganger_detection", "no field-name check in Config::validate"),
    ("gcp_secret_prefix", "no field-name check in Config::validate"),
    ("genesis_time", "checked via effective_genesis_time(); name not in validate body"),
    (
        "genesis_validators_root",
        "checked via effective_genesis_validators_root(); name not in validate body",
    ),
    ("grpc_address", "no field-name check in Config::validate"),
    ("grpc_signer_tls_ca_cert", "no field-name check in Config::validate"),
    ("grpc_signer_tls_cert", "no field-name check in Config::validate"),
    ("grpc_signer_tls_key", "no field-name check in Config::validate"),
    ("grpc_signer_url", "no field-name check in Config::validate"),
    ("init_slashing_db", "no field-name check in Config::validate"),
    ("key_decrypt_threads", "no field-name check in Config::validate"),
    ("keymanager_address", "no field-name check in Config::validate"),
    ("keymanager_body_limit", "no field-name check in Config::validate"),
    ("keymanager_cors_origins", "no field-name check in Config::validate"),
    ("keymanager_enabled", "no field-name check in Config::validate"),
    ("keymanager_token_file", "no field-name check in Config::validate"),
    ("keystore_path", "no field-name check in Config::validate"),
    ("log_level", "no field-name check in Config::validate"),
    ("logfile", "no field-name check in Config::validate"),
    ("logfile_compress", "no field-name check in Config::validate"),
    ("logfile_level", "no field-name check in Config::validate"),
    ("logfile_max_number", "no field-name check in Config::validate"),
    ("logfile_max_size", "no field-name check in Config::validate"),
    ("metrics_address", "no field-name check in Config::validate"),
    ("monitoring_endpoint", "no field-name check in Config::validate"),
    ("monitoring_endpoint_insecure", "no field-name check in Config::validate"),
    ("monitoring_interval", "no field-name check in Config::validate"),
    ("network", "no field-name check in Config::validate"),
    ("password_file", "no field-name check in Config::validate"),
    ("proposer_config_refresh_interval", "no field-name check in Config::validate"),
    ("proposer_config_url_insecure", "no field-name check in Config::validate"),
    ("proposer_config_url_token", "no field-name check in Config::validate"),
    ("remote_signer_allowed_hosts", "no field-name check in Config::validate"),
    ("remote_signer_url", "no field-name check in Config::validate"),
    ("secret_provider_strict", "no field-name check in Config::validate"),
    ("secret_refresh_interval", "no field-name check in Config::validate"),
    ("slashed_validators_action", "no field-name check in Config::validate"),
    ("slashing_db_path", "no field-name check in Config::validate"),
    ("tracing_endpoint", "no field-name check in Config::validate"),
    ("tracing_exporter", "no field-name check in Config::validate"),
    ("tracing_max_export_batch_size", "no field-name check in Config::validate"),
    ("tracing_max_queue_size", "no field-name check in Config::validate"),
    ("tracing_sample_rate", "no field-name check in Config::validate"),
    ("validator_registration_batch_delay", "no field-name check in Config::validate"),
    ("validator_registration_batch_size", "no field-name check in Config::validate"),
    ("validators_config", "no field-name check in Config::validate"),
];

// ---------------------------------------------------------------------------
// Workspace helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// `cli.rs` plus ARCH-4f section files so seam-α can see moved group structs.
fn group_args_source(root: &Path) -> String {
    let mut src =
        std::fs::read_to_string(root.join(CLI_RS)).expect("bin/rvc/src/cli.rs must exist");
    for rel in MIGRATED_GROUP_SRCS {
        let extra = std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("{rel} must exist after ARCH-4f: {e}"));
        src.push('\n');
        src.push_str(&extra);
    }
    src
}

/// Normalize whitespace for field-access matching:
/// - collapse whitespace around `.` so `builder\n    .field` → `builder.field`
/// - replace other whitespace runs with a single space so adjacent identifiers across
///   newlines do **not** fuse (`a.b\nc.d` → `a.b c.d`, not `a.bc.d`)
fn compact_ws(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            let mut j = i;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            let prev_is_dot = out.ends_with('.');
            let next_is_dot = j < chars.len() && chars[j] == '.';
            if !(prev_is_dot || next_is_dot) {
                // Token separator — prevents `no_keymanager` + `keymanager` from fusing.
                if !out.is_empty() && !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Strip `//` line comments and `/* … */` block comments; leave string literals intact so
/// `://` inside URLs is not treated as a line comment. String content is replaced with spaces
/// of equal length so comment-only and string-only mentions cannot satisfy field-access needles.
fn strip_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // String literal: blank it out (preserve length for simpler debugging; not required).
        if c == b'"' {
            out.push(b' ');
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i];
                out.push(b' ');
                i += 1;
                if ch == b'\\' && i < bytes.len() {
                    out.push(b' ');
                    i += 1;
                    continue;
                }
                if ch == b'"' {
                    break;
                }
            }
            continue;
        }
        // Line comment
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        // Block comment
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(b' ');
                out.push(b' ');
                i += 2;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

/// True if `compact` contains an identifier-bounded `{binding}.{field}` access.
///
/// Rejects prefix collisions: `logging.logfile_max_size` does **not** satisfy `logging.logfile`.
fn has_field_access(compact: &str, binding: &str, field: &str) -> bool {
    let needle = format!("{binding}.{field}");
    let n_bytes = needle.as_bytes();
    let hay = compact.as_bytes();
    let mut from = 0;
    while from + n_bytes.len() <= hay.len() {
        let Some(rel) = compact[from..].find(&needle) else {
            return false;
        };
        let at = from + rel;
        let after = at + n_bytes.len();
        let before_ok = at == 0 || !is_ident_char(hay[at - 1]);
        let after_ok = after >= hay.len() || !is_ident_char(hay[after]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// Compacted, comment-/string-stripped scan text for field-access matching.
fn scan_text(src: &str) -> String {
    compact_ws(&strip_comments_and_strings(src))
}

// ---------------------------------------------------------------------------
// Extraction — brace-aware, same technique as kat_policy::extract_tests
// ---------------------------------------------------------------------------

/// Body of `pub struct Name { … }` (outermost braces), or empty if not found.
fn struct_body<'a>(src: &'a str, struct_name: &str) -> Option<&'a str> {
    let needle = format!("struct {struct_name}");
    let mut from = 0;
    loop {
        let rel = src[from..].find(&needle)?;
        let at = from + rel;
        // Require word boundary before `struct` (avoid matching inside comments/identifiers).
        if at > 0 {
            let b = src.as_bytes()[at - 1];
            if b.is_ascii_alphanumeric() || b == b'_' {
                from = at + needle.len();
                continue;
            }
        }
        let after = &src[at + needle.len()..];
        let Some(brace_rel) = after.find('{') else {
            from = at + needle.len();
            continue;
        };
        // Reject `struct Foo;` / generics-before-brace mismatches: allow only whitespace between
        // name and `{` (no other struct name).
        let between = after[..brace_rel].trim();
        if !between.is_empty() {
            // e.g. `struct Foo<T>` — not present at HEAD for Args groups; skip.
            from = at + needle.len();
            continue;
        }
        let open = at + needle.len() + brace_rel;
        let mut depth = 0i32;
        for (i, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[open + 1..open + i]);
                    }
                }
                _ => {}
            }
        }
        return None;
    }
}

/// Field identifiers declared directly inside `pub struct Name { … }`.
///
/// Skips doc comments, attributes, and nested braces (depth tracking).
fn struct_fields(src: &str, struct_name: &str) -> Vec<String> {
    let Some(body) = struct_body(src, struct_name) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    let mut depth = 0i32;
    for line in body.lines() {
        let t = line.trim();
        // Track nested braces on the line (field types rarely nest; keep honest).
        for ch in t.chars() {
            match ch {
                '{' | '(' | '[' => depth += 1,
                '}' | ')' | ']' => depth -= 1,
                _ => {}
            }
        }
        if depth != 0 {
            continue;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with("///") || t.starts_with("#[") {
            continue;
        }
        // `pub field: Type` / `pub field: Type,`
        let mut rest = t;
        if let Some(r) = rest.strip_prefix("pub") {
            rest = r.trim_start();
            if let Some(r) = rest.strip_prefix('(') {
                // pub(crate) etc.
                let Some(close) = r.find(')') else {
                    continue;
                };
                rest = r[close + 1..].trim_start();
            }
        } else {
            continue;
        }
        let name: String =
            rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if name.is_empty() {
            continue;
        }
        // Must be followed by `:` after optional whitespace (not a method).
        let after_name = rest[name.len()..].trim_start();
        if after_name.starts_with(':') {
            fields.push(name);
        }
    }
    fields
}

/// `StartArgs`' `#[command(flatten)] pub <binding>: <XArgs>,` lines → binding → type.
fn flatten_bindings(src: &str) -> BTreeMap<String, String> {
    let Some(body) = struct_body(src, "StartArgs") else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    let lines: Vec<&str> = body.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        if t.starts_with("#[command(flatten)]") || t.starts_with("#[command(flatten,") {
            // Next non-empty / non-attr / non-comment line is the field.
            i += 1;
            while i < lines.len() {
                let l = lines[i].trim();
                if l.is_empty() || l.starts_with("//") || l.starts_with("#[") {
                    i += 1;
                    continue;
                }
                // `pub binding: Type,`
                let mut rest = l;
                if let Some(r) = rest.strip_prefix("pub") {
                    rest = r.trim_start();
                }
                let binding: String =
                    rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                let after = rest[binding.len()..].trim_start();
                if let Some(after_colon) = after.strip_prefix(':') {
                    let ty: String = after_colon
                        .trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !binding.is_empty() && !ty.is_empty() {
                        out.insert(binding, ty);
                    }
                }
                break;
            }
        }
        i += 1;
    }
    out
}

/// Body of `impl From<StartArgs> for CliOverrides { … }`.
fn from_impl_body(src: &str) -> String {
    let markers = [
        "impl From<StartArgs> for CliOverrides",
        "impl From<StartArgs> for crate::config::CliOverrides",
    ];
    let mut start = None;
    for m in markers {
        if let Some(at) = src.find(m) {
            start = Some(at);
            break;
        }
    }
    let Some(start) = start else {
        return String::new();
    };
    let rest = &src[start..];
    let Some(brace_rel) = rest.find('{') else {
        return String::new();
    };
    let open = start + brace_rel;
    let mut depth = 0i32;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open + 1..open + i].to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Seam-α detector (pure — synthetic tests feed crafted inputs)
// ---------------------------------------------------------------------------

/// Return unread group fields: each `(struct, field)` must appear as an identifier-bounded
/// `{binding}.{field}` in the From-impl body (comment-/string-stripped, whitespace-insensitive)
/// unless listed in `bypass`.
///
/// `ALIASES` sources are **not** skipped: the From impl still reads them under the clap field name
/// (`safety.no_doppelganger_detection`, `keymanager.no_keymanager`). The table documents the
/// override rename / 2:1 collapse for arithmetic and reviewers; dropping a read is still a
/// violation.
///
/// Presence-only: any non-comment occurrence of the access counts (including `let _ = …`).
///
/// `bindings`: binding name → struct type.
/// `fields_by_type`: struct type → field names.
/// `bypass`: `(struct_type, field_name)` set of intentional non-`CliOverrides` routes.
fn seam_alpha_unread(
    bindings: &BTreeMap<String, String>,
    fields_by_type: &BTreeMap<String, Vec<String>>,
    from_body: &str,
    bypass: &HashSet<(&str, &str)>,
) -> (usize, Vec<String>) {
    let compact = scan_text(from_body);
    let mut violations = Vec::new();
    let mut checked = 0usize;

    for (binding, ty) in bindings {
        let Some(fields) = fields_by_type.get(ty) else {
            violations.push(format!(
                "binding `{binding}: {ty}` has no extracted fields (struct parse failed?)"
            ));
            continue;
        };
        for field in fields {
            checked += 1;
            if bypass.contains(&(ty.as_str(), field.as_str())) {
                continue;
            }
            if !has_field_access(&compact, binding, field) {
                violations.push(format!(
                    "{ty}::{field} (--{}) is declared as a clap arg but never read by \
                     `impl From<StartArgs> for CliOverrides`; it is accepted on the command line \
                     and silently ignored. Add a `CliOverrides` field for it, or add it to BYPASS \
                     with a reason string (ALIASES only renames — the source field must still be \
                     read as `<binding>.<field>`).",
                    field.replace('_', "-")
                ));
            }
        }
    }
    violations.sort();
    (checked, violations)
}

fn bypass_set() -> HashSet<(&'static str, &'static str)> {
    BYPASS.iter().map(|&(ty, field, _)| (ty, field)).collect()
}

fn aliases_set() -> HashSet<(&'static str, &'static str)> {
    ALIASES.iter().map(|&(ty, field, _, _)| (ty, field)).collect()
}

// ---------------------------------------------------------------------------
// Clause (iv) — clap default clobber detector
// ---------------------------------------------------------------------------

/// Unconditional `field: Some(binding.source)` rows in a From-impl / struct-literal body.
///
/// Returns `(override_field, binding, source_field)`. Whitespace-tolerant; ignores comments
/// and string literals via [`scan_text`].
fn find_some_binding_wrappers(from_body: &str) -> Vec<(String, String, String)> {
    let compact = scan_text(from_body);
    let bytes = compact.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Identify a potential field name start.
        if !is_ident_start(bytes[i]) {
            i += 1;
            continue;
        }
        let name_start = i;
        i += 1;
        while i < bytes.len() && is_ident_char(bytes[i]) {
            i += 1;
        }
        let field = &compact[name_start..i];
        // Skip whitespace already collapsed to single spaces.
        let mut j = i;
        if j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            continue;
        }
        j += 1;
        if j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        // Some(
        if j + 5 > bytes.len() || &compact[j..j + 5] != "Some(" {
            continue;
        }
        j += 5;
        if j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        if j >= bytes.len() || !is_ident_start(bytes[j]) {
            continue;
        }
        let bind_start = j;
        j += 1;
        while j < bytes.len() && is_ident_char(bytes[j]) {
            j += 1;
        }
        let binding = &compact[bind_start..j];
        if j >= bytes.len() || bytes[j] != b'.' {
            continue;
        }
        j += 1;
        if j >= bytes.len() || !is_ident_start(bytes[j]) {
            continue;
        }
        let src_start = j;
        j += 1;
        while j < bytes.len() && is_ident_char(bytes[j]) {
            j += 1;
        }
        let source = &compact[src_start..j];
        if j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b')' {
            continue;
        }
        // Only count when override field name equals the clap source field (the F9 shape).
        if field == source {
            out.push((field.to_string(), binding.to_string(), source.to_string()));
        }
        i = j;
    }
    out.sort();
    out.dedup();
    out
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

/// Attributes text (joined) and type text for `pub field: Type` inside `struct_name`, if found.
fn field_attrs_and_type(src: &str, struct_name: &str, field: &str) -> Option<(String, String)> {
    let body = struct_body(src, struct_name)?;
    let lines: Vec<&str> = body.lines().collect();
    let mut pending_attrs: Vec<String> = Vec::new();
    let mut depth = 0i32;
    for line in lines {
        let t = line.trim();
        for ch in t.chars() {
            match ch {
                '{' | '(' | '[' => depth += 1,
                '}' | ')' | ']' => depth -= 1,
                _ => {}
            }
        }
        if depth != 0 {
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if t.starts_with("///") || t.starts_with("//") {
            continue;
        }
        if t.starts_with("#[") {
            pending_attrs.push(t.to_string());
            continue;
        }
        let mut rest = t;
        if let Some(r) = rest.strip_prefix("pub") {
            rest = r.trim_start();
            if let Some(r) = rest.strip_prefix('(') {
                let close = r.find(')')?;
                rest = r[close + 1..].trim_start();
            }
        } else {
            pending_attrs.clear();
            continue;
        }
        let name: String =
            rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if name.is_empty() {
            pending_attrs.clear();
            continue;
        }
        let after_name = rest[name.len()..].trim_start();
        if !after_name.starts_with(':') {
            pending_attrs.clear();
            continue;
        }
        let ty = after_name[1..].trim().trim_end_matches(',').trim().to_string();
        if name == field {
            return Some((pending_attrs.join(" "), ty));
        }
        pending_attrs.clear();
    }
    None
}

/// True when the clap field declaration is non-`Option` and carries `default_value` /
/// `default_value_t` (the ADR-009 clobber precondition).
fn clap_field_is_defaulted_non_option(src: &str, struct_name: &str, field: &str) -> bool {
    let Some((attrs, ty)) = field_attrs_and_type(src, struct_name, field) else {
        return false;
    };
    let is_option = ty.starts_with("Option<") || ty.starts_with("Option <");
    if is_option {
        return false;
    }
    attrs.contains("default_value")
}

/// Detect clap-default clobbers in a From-impl body.
///
/// A hit is `field: Some(binding.field)` where the clap field on `bindings[binding]` is
/// non-`Option` with a `default_value`. Returns sorted unique override field names.
fn detect_clap_default_clobbers(
    from_body: &str,
    cli_src: &str,
    bindings: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut hits = Vec::new();
    for (field, binding, source) in find_some_binding_wrappers(from_body) {
        if field != source {
            continue;
        }
        let Some(ty) = bindings.get(&binding) else {
            continue;
        };
        if clap_field_is_defaulted_non_option(cli_src, ty, &field) {
            hits.push(field);
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Clobber field names found by the detector that are **not** on the allow-list (growth).
fn clobber_growth(found: &[String], allowed: &HashSet<&str>) -> Vec<String> {
    found.iter().filter(|f| !allowed.contains(f.as_str())).cloned().collect()
}

/// Allow-list entries not present in the detector output (stale list / source drift).
fn clobber_stale(found: &[String], allowed: &[&str]) -> Vec<String> {
    let found_set: HashSet<&str> = found.iter().map(String::as_str).collect();
    allowed.iter().filter(|f| !found_set.contains(*f)).map(|s| (*s).to_string()).collect()
}

// ---------------------------------------------------------------------------
// Clause (iii) — validation coverage
// ---------------------------------------------------------------------------

/// Body of `pub fn validate(&self) -> Result<(), ConfigError>` (first match in `src`).
fn config_validate_body(src: &str) -> String {
    let markers = [
        "pub fn validate(&self) -> Result<(), ConfigError>",
        "fn validate(&self) -> Result<(), ConfigError>",
    ];
    let mut start = None;
    for m in markers {
        if let Some(at) = src.find(m) {
            start = Some(at);
            break;
        }
    }
    let Some(start) = start else {
        return String::new();
    };
    let rest = &src[start..];
    let Some(brace_rel) = rest.find('{') else {
        return String::new();
    };
    let open = start + brace_rel;
    let mut depth = 0i32;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open + 1..open + i].to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// Identifier-bounded presence of `name` in `text` (comments/strings kept — string error
/// messages and doc comments inside the method body are intentional signals).
fn has_ident(text: &str, name: &str) -> bool {
    let n_bytes = name.as_bytes();
    let hay = text.as_bytes();
    let mut from = 0;
    while from + n_bytes.len() <= hay.len() {
        let Some(rel) = text[from..].find(name) else {
            return false;
        };
        let at = from + rel;
        let after = at + n_bytes.len();
        let before_ok = at == 0 || !is_ident_char(hay[at - 1]);
        let after_ok = after >= hay.len() || !is_ident_char(hay[after]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

/// `CliOverrides` fields absent from both the validate body and the unvalidated allow-list.
fn unvalidated_violations(
    override_fields: &[String],
    validate_body: &str,
    unvalidated: &HashSet<&str>,
) -> Vec<String> {
    let mut missing = Vec::new();
    for f in override_fields {
        if has_ident(validate_body, f) {
            continue;
        }
        if unvalidated.contains(f.as_str()) {
            continue;
        }
        missing.push(format!(
            "CliOverrides::{f} is neither mentioned in Config::validate nor listed in UNVALIDATED; \
             add a validation check or a shrinking-only UNVALIDATED entry with a reason"
        ));
    }
    missing.sort();
    missing
}

// ---------------------------------------------------------------------------
// Live gate (clause ii)
// ---------------------------------------------------------------------------

#[test]
fn every_group_arg_field_is_read_by_the_from_impl() {
    let root = workspace_root();
    let cli = std::fs::read_to_string(root.join(CLI_RS)).expect("bin/rvc/src/cli.rs must exist");
    let groups = group_args_source(&root);

    let bindings = flatten_bindings(&cli);
    assert_eq!(
        bindings.len(),
        13,
        "expected 13 flattened Args groups on StartArgs; scanner or cli.rs changed"
    );

    let body = from_impl_body(&cli);
    let from_scan = scan_text(&body);
    assert!(
        has_field_access(&from_scan, "beacon", "beacon_url"),
        "From-impl body extraction broke (missing beacon.beacon_url)"
    );

    let mut fields_by_type: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for ty in bindings.values() {
        fields_by_type.entry(ty.clone()).or_insert_with(|| struct_fields(&groups, ty));
    }
    // Reverse map: struct type → binding name (for BYPASS second-leg needles).
    let ty_to_binding: BTreeMap<&str, &str> =
        bindings.iter().map(|(b, t)| (t.as_str(), b.as_str())).collect();

    let bypass = bypass_set();
    let aliases = aliases_set();
    assert_eq!(bypass.len(), BYPASS.len(), "duplicate BYPASS entries");
    assert_eq!(aliases.len(), ALIASES.len(), "duplicate ALIASES entries");
    assert_eq!(BYPASS.len(), 8, "BYPASS must have exactly 8 entries");
    assert_eq!(ALIASES.len(), 2, "ALIASES must have exactly 2 entries");

    // Table hygiene: every BYPASS/ALIASES source must exist on its group struct.
    for (ty, field, _reason) in BYPASS {
        let fs = fields_by_type.get(*ty).map(Vec::as_slice).unwrap_or(&[]);
        assert!(
            fs.iter().any(|f| f == field),
            "BYPASS entry {ty}::{field} not found on group struct"
        );
    }
    for (ty, field, _target, _reason) in ALIASES {
        let fs = fields_by_type.get(*ty).map(Vec::as_slice).unwrap_or(&[]);
        assert!(
            fs.iter().any(|f| f == field),
            "ALIASES source {ty}::{field} not found on group struct"
        );
    }

    // Second-leg: BYPASS fields must still be consumed outside From (timeouts / run options).
    // Scan the whole cli.rs (comment-stripped); From does not read these fields, so hits are
    // the Commands::Start routing path (e.g. args.beacon.block_production_timeout).
    let cli_scan = scan_text(&cli);
    for (ty, field, _reason) in BYPASS {
        let binding = ty_to_binding
            .get(ty)
            .unwrap_or_else(|| panic!("BYPASS type {ty} has no StartArgs flatten binding"));
        assert!(
            has_field_access(&cli_scan, binding, field),
            "BYPASS {ty}::{field} has no second-leg read as `{binding}.{field}` outside/alongside \
             From (timeouts/run options routing missing?)"
        );
    }

    let (checked, violations) = seam_alpha_unread(&bindings, &fields_by_type, &body, &bypass);

    assert_eq!(checked, 74, "expected 74 group-arg fields at HEAD; got {checked}");
    assert!(
        violations.is_empty(),
        "ARCH-P1-1 / G-2 seam α (clause ii):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn bypass_and_aliases_are_sorted_and_unique() {
    let mut seen_b = HashSet::new();
    let mut prev_b: Option<(&str, &str)> = None;
    for &(ty, field, reason) in BYPASS {
        assert!(!reason.trim().is_empty(), "BYPASS ({ty}, {field}) missing reason");
        assert!(seen_b.insert((ty, field)), "duplicate BYPASS: {ty}::{field}");
        if let Some(p) = prev_b {
            assert!(
                p < (ty, field),
                "BYPASS must stay sorted by (struct, field); {:?} precedes {ty}::{field}",
                p
            );
        }
        prev_b = Some((ty, field));
    }

    let mut seen_a = HashSet::new();
    let mut prev_a: Option<(&str, &str)> = None;
    for &(ty, field, target, reason) in ALIASES {
        assert!(!reason.trim().is_empty(), "ALIASES ({ty}, {field}) missing reason");
        assert!(!target.trim().is_empty(), "ALIASES ({ty}, {field}) missing override target");
        assert!(seen_a.insert((ty, field)), "duplicate ALIASES: {ty}::{field}");
        if let Some(p) = prev_a {
            assert!(
                p < (ty, field),
                "ALIASES must stay sorted by (struct, field); {:?} precedes {ty}::{field}",
                p
            );
        }
        prev_a = Some((ty, field));
    }
}

#[test]
fn every_bypass_and_alias_entry_carries_a_reason() {
    assert_eq!(BYPASS.len(), 8);
    assert_eq!(ALIASES.len(), 2);
    for &(ty, field, reason) in BYPASS {
        assert!(
            !reason.trim().is_empty(),
            "BYPASS entry {ty}::{field} must carry a non-empty reason string"
        );
    }
    for &(ty, field, target, reason) in ALIASES {
        assert!(
            !reason.trim().is_empty(),
            "ALIASES entry {ty}::{field}→{target} must carry a non-empty reason string"
        );
    }
}

#[test]
fn field_arithmetic_holds() {
    // 74 group fields − 8 BYPASS − 1 (2:1 no_keymanager collapse) = 65 CliOverrides fields.
    assert_eq!(74 - 8 - 1, 65);
    assert_eq!(BYPASS.len(), 8);
    // Exactly one ALIASES entry is the 2:1 collapse (the −1); the other is 1:1.
    let collapse = ALIASES
        .iter()
        .filter(|(_, _, target, reason)| *target == "keymanager_enabled" && reason.contains("2:1"))
        .count();
    assert_eq!(collapse, 1, "expected exactly one 2:1 collapse alias (the −1)");

    let root = workspace_root();
    let types =
        std::fs::read_to_string(root.join(TYPES_RS)).expect("crates/rvc/src/config/types.rs");
    let override_fields = struct_fields(&types, "CliOverrides");
    assert_eq!(
        override_fields.len(),
        65,
        "CliOverrides field count drifted; update arithmetic / seam α tables"
    );
}

// ---------------------------------------------------------------------------
// Non-vacuous matcher unit tests (synthetic RED / acceptance)
// ---------------------------------------------------------------------------

#[test]
fn struct_fields_extracts_and_skips_attributes() {
    let src = r#"
#[derive(Args, Debug)]
pub struct BeaconArgs {
    /// Beacon node URL
    #[arg(long)]
    pub beacon_url: Option<String>,

    #[arg(long, value_delimiter = ',')]
    pub beacon_nodes: Option<Vec<String>>,
}
"#;
    assert_eq!(struct_fields(src, "BeaconArgs"), vec!["beacon_url", "beacon_nodes"]);
}

#[test]
fn flatten_bindings_extracts_start_args_groups() {
    let src = r#"
pub struct StartArgs {
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub beacon: BeaconArgs,

    #[command(flatten)]
    pub keys: KeysArgs,
}
"#;
    let b = flatten_bindings(src);
    assert_eq!(b.len(), 2);
    assert_eq!(b.get("beacon").map(String::as_str), Some("BeaconArgs"));
    assert_eq!(b.get("keys").map(String::as_str), Some("KeysArgs"));
}

#[test]
fn seam_alpha_detector_flags_an_unread_field() {
    // Mandatory RED: synthetic group with a field the From impl ignores.
    let mut bindings = BTreeMap::new();
    bindings.insert("beacon".into(), "BeaconArgs".into());
    let mut fields = BTreeMap::new();
    fields.insert("BeaconArgs".into(), vec!["beacon_url".into(), "unread_field".into()]);
    let body = "beacon.beacon_url";
    let bypass = HashSet::new();
    let (checked, violations) = seam_alpha_unread(&bindings, &fields, body, &bypass);
    assert_eq!(checked, 2);
    assert!(
        violations.iter().any(|v| v.contains("unread_field")),
        "expected unread_field to be flagged, got {violations:?}"
    );
    assert!(!violations.iter().any(|v| v.contains("beacon_url")), "read field must not be flagged");
}

#[test]
fn seam_alpha_detector_accepts_a_bypassed_field() {
    let mut bindings = BTreeMap::new();
    bindings.insert("beacon".into(), "BeaconArgs".into());
    let mut fields = BTreeMap::new();
    fields
        .insert("BeaconArgs".into(), vec!["beacon_url".into(), "block_production_timeout".into()]);
    let body = "beacon.beacon_url";
    let mut bypass = HashSet::new();
    bypass.insert(("BeaconArgs", "block_production_timeout"));
    let (checked, violations) = seam_alpha_unread(&bindings, &fields, body, &bypass);
    assert_eq!(checked, 2);
    assert!(violations.is_empty(), "bypassed field must not be flagged: {violations:?}");
}

#[test]
fn seam_alpha_detector_accepts_an_aliased_field() {
    // 1:1 negated rename — source field is still read as binding.field (override name differs).
    let mut bindings = BTreeMap::new();
    bindings.insert("safety".into(), "SafetyArgs".into());
    let mut fields = BTreeMap::new();
    fields.insert("SafetyArgs".into(), vec!["no_doppelganger_detection".into()]);
    let body = "safety.no_doppelganger_detection";
    let bypass = HashSet::new();
    let (checked, violations) = seam_alpha_unread(&bindings, &fields, body, &bypass);
    assert_eq!(checked, 1);
    assert!(violations.is_empty(), "1:1 alias source read as binding.field: {violations:?}");
    // Override target name alone is not a substitute for the clap field access.
    let body_wrong = "safety.doppelganger_detection";
    let (_, violations) = seam_alpha_unread(&bindings, &fields, body_wrong, &bypass);
    assert!(
        violations.iter().any(|v| v.contains("no_doppelganger_detection")),
        "must require clap field name, not override name: {violations:?}"
    );

    // 2:1 collapse — both clap sources must appear; only no_keymanager is on ALIASES.
    let mut bindings = BTreeMap::new();
    bindings.insert("keymanager".into(), "KeymanagerArgs".into());
    let mut fields = BTreeMap::new();
    fields
        .insert("KeymanagerArgs".into(), vec!["no_keymanager".into(), "keymanager_enabled".into()]);
    let body = "keymanager.no_keymanager\nkeymanager.keymanager_enabled";
    let (checked, violations) = seam_alpha_unread(&bindings, &fields, body, &bypass);
    assert_eq!(checked, 2);
    assert!(violations.is_empty(), "2:1 collapse: both source fields read: {violations:?}");
    // Missing either half is a violation (ALIASES documents the rename; does not skip the read).
    let body_half = "keymanager.keymanager_enabled";
    let (_, violations) = seam_alpha_unread(&bindings, &fields, body_half, &bypass);
    assert!(
        violations.iter().any(|v| v.contains("no_keymanager")),
        "2:1 source no_keymanager must still be read: {violations:?}"
    );
}

/// Prefix collision false-green: longer sibling must not satisfy shorter field (M1 / H3).
#[test]
fn seam_alpha_detector_rejects_prefix_only_field_access() {
    let mut bindings = BTreeMap::new();
    bindings.insert("logging".into(), "LoggingArgs".into());
    let mut fields = BTreeMap::new();
    fields.insert("LoggingArgs".into(), vec!["logfile".into(), "logfile_max_size".into()]);
    // Only the longer access is present — `logfile` must still be flagged.
    let body = "logfile_max_size: logging.logfile_max_size,";
    let bypass = HashSet::new();
    let (checked, violations) = seam_alpha_unread(&bindings, &fields, body, &bypass);
    assert_eq!(checked, 2);
    assert!(
        violations.iter().any(|v| v.contains("LoggingArgs::logfile") || v.contains("logfile ")),
        "logfile must not be satisfied by logfile_max_size: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("logfile_max_size")),
        "longer sibling is present and must pass: {violations:?}"
    );

    // Same class: secret_provider vs secret_provider_strict.
    let mut bindings = BTreeMap::new();
    bindings.insert("keys".into(), "KeysArgs".into());
    let mut fields = BTreeMap::new();
    fields
        .insert("KeysArgs".into(), vec!["secret_provider".into(), "secret_provider_strict".into()]);
    let body = "keys.secret_provider_strict";
    let (_, violations) = seam_alpha_unread(&bindings, &fields, body, &bypass);
    assert!(
        violations.iter().any(|v| v.contains("secret_provider")),
        "secret_provider must not be satisfied by secret_provider_strict: {violations:?}"
    );
}

/// Comment-only / string-only mentions must not count as wiring (H2).
#[test]
fn seam_alpha_detector_ignores_comment_and_string_only_mentions() {
    let mut bindings = BTreeMap::new();
    bindings.insert("beacon".into(), "BeaconArgs".into());
    let mut fields = BTreeMap::new();
    fields.insert("BeaconArgs".into(), vec!["evil_timeout".into()]);
    let bypass = HashSet::new();

    let body_comment = "// remember to wire beacon.evil_timeout later\nSelf {}";
    let (_, violations) = seam_alpha_unread(&bindings, &fields, body_comment, &bypass);
    assert!(
        violations.iter().any(|v| v.contains("evil_timeout")),
        "comment-only mention must still be unread: {violations:?}"
    );

    let body_string = r#"let msg = "forgot beacon.evil_timeout"; Self {}"#;
    let (_, violations) = seam_alpha_unread(&bindings, &fields, body_string, &bypass);
    assert!(
        violations.iter().any(|v| v.contains("evil_timeout")),
        "string-only mention must still be unread: {violations:?}"
    );
}

#[test]
fn has_field_access_is_identifier_bounded() {
    let compact = compact_ws("logging.logfile_max_size, logging.logfile,");
    assert!(has_field_access(&compact, "logging", "logfile"));
    assert!(has_field_access(&compact, "logging", "logfile_max_size"));
    let prefix_only = compact_ws("logging.logfile_max_size");
    assert!(!has_field_access(&prefix_only, "logging", "logfile"));
    assert!(has_field_access(&prefix_only, "logging", "logfile_max_size"));
}

#[test]
fn from_impl_body_extracts_live_cli_rs() {
    let root = workspace_root();
    let cli = std::fs::read_to_string(root.join(CLI_RS)).unwrap();
    let body = from_impl_body(&cli);
    assert!(!body.is_empty());
    assert!(body.contains("beacon"));
    assert!(has_field_access(&scan_text(&body), "beacon", "beacon_url"));
}

// ---------------------------------------------------------------------------
// Live gate — clause (iv) CLAP_DEFAULT_CLOBBERS
// ---------------------------------------------------------------------------

#[test]
fn clap_default_clobbers_list_matches_the_source() {
    let root = workspace_root();
    let cli = std::fs::read_to_string(root.join(CLI_RS)).expect("bin/rvc/src/cli.rs");
    let groups = group_args_source(&root);
    let bindings = flatten_bindings(&cli);
    let body = from_impl_body(&cli);
    let found = detect_clap_default_clobbers(&body, &groups, &bindings);

    let allowed: Vec<&str> = CLAP_DEFAULT_CLOBBERS.iter().map(|&(f, _)| f).collect();
    let allowed_set: HashSet<&str> = allowed.iter().copied().collect();

    // ARCH-6b: list is empty; detector must find no live clobbers.
    assert!(
        CLAP_DEFAULT_CLOBBERS.is_empty(),
        "CLAP_DEFAULT_CLOBBERS must be empty after ARCH-6b; got {} entries",
        CLAP_DEFAULT_CLOBBERS.len()
    );
    assert!(
        found.is_empty(),
        "detector must find zero clap-default clobbers after ARCH-6b; got {found:?}"
    );

    let growth = clobber_growth(&found, &allowed_set);
    assert!(
        growth.is_empty(),
        "CLAP_DEFAULT_CLOBBERS is shrinking-only; new clobber(s) not on the list (ADR-009):\n  {}",
        growth.join("\n  ")
    );

    let stale = clobber_stale(&found, &allowed);
    assert!(
        stale.is_empty(),
        "CLAP_DEFAULT_CLOBBERS lists fields the detector no longer finds (list/source drift):\n  {}",
        stale.join("\n  ")
    );

    // Exact set equality (order independent).
    let found_set: HashSet<&str> = found.iter().map(String::as_str).collect();
    assert_eq!(
        found_set, allowed_set,
        "CLAP_DEFAULT_CLOBBERS must match detector output exactly;\n  found: {found:?}\n  list:  {allowed:?}"
    );
}

#[test]
fn every_clobber_entry_carries_a_reason() {
    // Empty list is valid post-ARCH-6b; non-empty entries still need reasons + sort order.
    let mut seen = HashSet::new();
    let mut prev: Option<&str> = None;
    for &(field, reason) in CLAP_DEFAULT_CLOBBERS {
        assert!(!reason.trim().is_empty(), "CLAP_DEFAULT_CLOBBERS::{field} missing reason");
        assert!(seen.insert(field), "duplicate CLAP_DEFAULT_CLOBBERS entry: {field}");
        if let Some(p) = prev {
            assert!(
                p < field,
                "CLAP_DEFAULT_CLOBBERS must stay sorted by field; {p:?} precedes {field}"
            );
        }
        prev = Some(field);
    }
}

#[test]
fn clap_default_clobber_detector_flags_a_tenth_instance() {
    // Mandatory synthetic RED: a new Some(binding.field) with default_value must be flagged
    // even when (especially when) the real list is empty after ARCH-6b.
    let cli_src = r#"
#[derive(Args, Debug)]
pub struct ServerArgs {
    #[arg(long, default_value_t = 8080)]
    pub metrics_port: u16,

    #[arg(long, default_value_t = 9999)]
    pub some_new_flag: u16,
}

pub struct StartArgs {
    #[command(flatten)]
    pub server: ServerArgs,
}
"#;
    let from_body = r#"
        Self {
            metrics_port: Some(server.metrics_port),
            some_new_flag: Some(server.some_new_flag),
        }
"#;
    let mut bindings = BTreeMap::new();
    bindings.insert("server".into(), "ServerArgs".into());
    let found = detect_clap_default_clobbers(from_body, cli_src, &bindings);
    assert!(
        found.iter().any(|f| f == "some_new_flag"),
        "synthetic tenth clobber must be flagged, got {found:?}"
    );
    assert!(
        found.iter().any(|f| f == "metrics_port"),
        "known clobber shape must still be detected, got {found:?}"
    );

    // With only the nine-name allow-list (no some_new_flag), growth must surface the tenth.
    let allowed: HashSet<&str> = CLAP_DEFAULT_CLOBBERS.iter().map(|&(f, _)| f).collect();
    let growth = clobber_growth(&found, &allowed);
    assert!(
        growth.iter().any(|f| f == "some_new_flag"),
        "tenth instance must appear as growth against CLAP_DEFAULT_CLOBBERS: {growth:?}"
    );

    // Empty allow-list (post-ARCH-6b shape) still flags reintroduction.
    let empty: HashSet<&str> = HashSet::new();
    let growth_empty = clobber_growth(&found, &empty);
    assert!(
        growth_empty.iter().any(|f| f == "some_new_flag"),
        "empty CLAP_DEFAULT_CLOBBERS must still flag synthetic reintroduction: {growth_empty:?}"
    );
}

// ---------------------------------------------------------------------------
// Live gate — clause (iii) UNVALIDATED
// ---------------------------------------------------------------------------

#[test]
fn every_cli_override_field_is_validated_or_listed() {
    let root = workspace_root();
    let types =
        std::fs::read_to_string(root.join(TYPES_RS)).expect("crates/rvc/src/config/types.rs");
    let override_fields = struct_fields(&types, "CliOverrides");
    assert_eq!(
        override_fields.len(),
        65,
        "CliOverrides field count drifted; update UNVALIDATED / clause iii"
    );

    let validate_body = config_validate_body(&types);
    assert!(!validate_body.is_empty(), "failed to extract Config::validate body from types.rs");
    assert!(
        has_ident(&validate_body, "metrics_port"),
        "validate body extraction broke (missing metrics_port)"
    );

    let unvalidated: HashSet<&str> = UNVALIDATED.iter().map(|&(f, _)| f).collect();
    assert_eq!(unvalidated.len(), UNVALIDATED.len(), "duplicate UNVALIDATED entries");

    // Hygiene: every UNVALIDATED entry must exist on CliOverrides.
    for &(field, _) in UNVALIDATED {
        assert!(
            override_fields.iter().any(|f| f == field),
            "UNVALIDATED entry `{field}` is not a CliOverrides field"
        );
    }

    // Hygiene: listed fields must NOT also appear in validate (list should shrink when checked).
    for &(field, _) in UNVALIDATED {
        assert!(
            !has_ident(&validate_body, field),
            "UNVALIDATED entry `{field}` appears in Config::validate — remove it from the list \
             (shrinking-only)"
        );
    }

    let violations = unvalidated_violations(&override_fields, &validate_body, &unvalidated);
    assert!(violations.is_empty(), "ARCH-P1-1 / G-2 clause (iii):\n  {}", violations.join("\n  "));
}

#[test]
fn unvalidated_list_is_shrinking_only() {
    let mut seen = HashSet::new();
    let mut prev: Option<&str> = None;
    for &(field, reason) in UNVALIDATED {
        assert!(!reason.trim().is_empty(), "UNVALIDATED::{field} missing reason");
        assert!(seen.insert(field), "duplicate UNVALIDATED entry: {field}");
        if let Some(p) = prev {
            assert!(p < field, "UNVALIDATED must stay sorted by field; {p:?} precedes {field}");
        }
        prev = Some(field);
    }
    // Non-vacuity: HEAD has many unvalidated knobs; an empty accidental wipe is a bug.
    assert!(
        UNVALIDATED.len() >= 40,
        "UNVALIDATED unexpectedly small ({}); table parse/seed failed?",
        UNVALIDATED.len()
    );
}

#[test]
fn unvalidated_detector_flags_an_unlist_field() {
    let override_fields = vec!["metrics_port".into(), "brand_new_knob".into(), "graffiti".into()];
    // metrics_port and graffiti appear; brand_new_knob does not.
    let validate_body =
        "if self.metrics_port == 0 { ... } if let Some(ref graffiti) = self.graffiti";
    let unvalidated: HashSet<&str> = HashSet::new();
    let violations = unvalidated_violations(&override_fields, validate_body, &unvalidated);
    assert!(
        violations.iter().any(|v| v.contains("brand_new_knob")),
        "unlist + unvalidated field must be flagged: {violations:?}"
    );
    assert!(
        !violations.iter().any(|v| v.contains("metrics_port")),
        "validated field must not be flagged: {violations:?}"
    );

    let mut listed = HashSet::new();
    listed.insert("brand_new_knob");
    let ok = unvalidated_violations(&override_fields, validate_body, &listed);
    assert!(ok.is_empty(), "listed field must pass: {ok:?}");
}
