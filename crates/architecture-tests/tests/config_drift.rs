//! G-2 / ARCH-P1-1 clause (ii): config-drift gate — seam-α scanner.
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
//! ## Interim lifetime
//!
//! This gate is **interim by construction**. ADR-008 Phase 4 collapses seam α (group `Args` →
//! direct `Config` paths), at which point clauses (i)/(ii) and the `BYPASS` / `ALIASES` tables are
//! deleted with it; only clauses (iii)/(iv) (ARCH-5b) survive. Until then, this file is the CI
//! fence on unread clap args.
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
//!
//! ARCH-5a only: clauses (iii) `UNVALIDATED` and (iv) `CLAP_DEFAULT_CLOBBERS` land in ARCH-5b.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

const CLI_RS: &str = "bin/rvc/src/cli.rs";
const TYPES_RS: &str = "crates/rvc/src/config/types.rs";

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

// ---------------------------------------------------------------------------
// Workspace helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
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
// Live gate (clause ii)
// ---------------------------------------------------------------------------

#[test]
fn every_group_arg_field_is_read_by_the_from_impl() {
    let root = workspace_root();
    let cli = std::fs::read_to_string(root.join(CLI_RS)).expect("bin/rvc/src/cli.rs must exist");

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
        fields_by_type.entry(ty.clone()).or_insert_with(|| struct_fields(&cli, ty));
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
