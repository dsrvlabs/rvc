//! G-3 / ARCH-4a: extract `std::env::var` / `var_os` call sites and `*_ENV` /
//! `*_ENV_VAR` constants. Classification (the four-class allow-list) is ARCH-4b.
//!
//! The gate scans **call sites and named constants**, not the `RVC_` prefix.
//! A prefix scan was measured at **438 hits across 57 files**, ~95 % Prometheus
//! metric-name constants, and it misses live reads of `RUST_LOG` and both
//! `OTEL_*` variables (ADR-010). That mechanism is rejected; do not "simplify"
//! this scanner back to a prefix match.
//!
//! Three shapes land in one [`EnvRead`]:
//!
//! * **literal** — `std::env::var("LITERAL")` / `env::var("LITERAL")` (and
//!   `var_os`);
//! * **dynamic** — `env::var(<anything else>)` as [`Shape::Dynamic`] `{ expr }`.
//!   Captured, never skipped (VD-4.5: the sanctioned opt-outs flow through
//!   `std::env::var(self.env_var)`). `env::vars` / `vars_os` are recorded as
//!   Dynamic so they are not silently dropped;
//! * **constant** — `const <NAME>_ENV: &str = "…"` / `<NAME>_ENV_VAR`.
//!
//! `env::set_var` / `remove_var` are scanned only so they can be excluded from
//! the read set (test scaffolding is not a read).
//!
//! Test-region partition is the **union** of:
//!
//! 1. **Path** — any `tests` path component or a `tests.rs` filename (crate-level
//!    `{bin,crates}/*/tests/**`, `src/**/tests/**`, `src/**/tests.rs`). G-4's
//!    `is_src_tests_path` is not enough: it requires a `src/` prefix and would
//!    miss `bin/rvc/tests` / `crates/*/tests`.
//! 2. **Item** — `#![cfg(test)]` takes the rest of the file; `#[cfg(test)]`
//!    applies to the **next item only** (brace-aware). A mid-file
//!    `#[cfg(test)] fn helper()` does not hide later production reads.
//!    `#[cfg(not(test))]` is not a test region.
//!
//! Remaining limitation: a `cfg(test)` *statement* inside a production function,
//! and `cfg_attr`, are not modelled. House style puts tests in `#[cfg(test)]
//! mod tests` or under a `tests/` path.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled walk, same idiom as
//! `kat_policy.rs`.
//!
//! Cross-ref: architecture §6 G-3; ADR-010; plan issue ARCH-4a / VD-4.4 / VD-4.5.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// This gate's own sources mention the needles inside synthetic fixtures.
// ---------------------------------------------------------------------------

const THIS_GATE: &str = "crates/architecture-tests/tests/env_allowlist.rs";

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnvRead {
    file: String,
    line: usize,
    shape: Shape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    Literal { name: String },
    Dynamic { expr: String },
    Constant { ident: String, value: String },
}

impl EnvRead {
    /// NFR-5 / R10: every diagnostic names file, line, and variable (or the
    /// dynamic expression).
    fn diagnostic(&self) -> String {
        match &self.shape {
            Shape::Literal { name } => format!("{}:{}: env read `{name}`", self.file, self.line),
            Shape::Dynamic { expr } => format!("{}:{}: env read `{expr}`", self.file, self.line),
            Shape::Constant { ident, value } => {
                format!("{}:{}: env constant `{ident}` = `{value}`", self.file, self.line)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Workspace walk (kat_policy.rs idiom)
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// Parse `members = [...]` from the workspace `Cargo.toml` (no TOML crate — P6).
fn workspace_member_dirs(root: &Path) -> Vec<PathBuf> {
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    let mut dirs = Vec::new();
    let Some(start) = cargo.find("members") else {
        return dirs;
    };
    let rest = &cargo[start..];
    let Some(bracket) = rest.find('[') else {
        return dirs;
    };
    let rest = &rest[bracket + 1..];
    let Some(end) = rest.find(']') else {
        return dirs;
    };
    for part in rest[..end].split(',') {
        let s = part.trim().trim_matches('"').trim_matches('\'').trim();
        if s.is_empty() {
            continue;
        }
        dirs.push(root.join(s));
    }
    dirs
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs(&path, out);
        } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// All `*.rs` under each workspace member (src + tests + benches + examples).
fn workspace_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for member in workspace_member_dirs(root) {
        if member.is_dir() {
            collect_rs(&member, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Source helpers
// ---------------------------------------------------------------------------

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn line_at(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

fn line_start(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

fn line_end(src: &str, byte: usize) -> usize {
    src[byte.min(src.len())..].find('\n').map(|i| byte + i).unwrap_or(src.len())
}

/// Best-effort: drop `//` line comments outside of strings.
fn code_portion(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            in_str = !in_str;
            i += 1;
            continue;
        }
        if !in_str && b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn is_comment_only_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("///") || t.starts_with("//!")
}

fn skip_ws(src: &str, mut i: usize) -> usize {
    while i < src.len() && src.as_bytes()[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn is_cfg_key_char(b: u8) -> bool {
    is_ident_char(b) || b == b'-'
}

/// `test` as a cfg key that is not the operand of `not`.
fn cfg_has_positive_test(inner: &str) -> bool {
    let bytes = inner.as_bytes();
    let mut from = 0;
    while let Some(rel) = inner[from..].find("test") {
        let at = from + rel;
        from = at + 4;
        // `test-utils` is one cfg key; hyphen stays inside the token.
        let before_ok = at == 0 || !is_cfg_key_char(bytes[at - 1]);
        let after_ok = from >= bytes.len() || !is_cfg_key_char(bytes[from]);
        if !before_ok || !after_ok {
            continue;
        }
        if !test_token_negated(inner, at) {
            return true;
        }
    }
    false
}

fn test_token_negated(inner: &str, at: usize) -> bool {
    let before = inner[..at].trim_end();
    let Some(rest) = before.strip_suffix('(') else {
        return false;
    };
    let rest = rest.trim_end();
    if !rest.ends_with("not") {
        return false;
    }
    let start = rest.len() - 3;
    start == 0 || !is_ident_char(rest.as_bytes()[start - 1])
}

/// True if `trimmed` is a positive `#[cfg(test)]` / `#![cfg(test)]` (not `not(test)`).
fn is_cfg_test_attr(trimmed: &str) -> bool {
    let t = trimmed.trim_end_matches(',').trim();
    if !(t.starts_with("#[cfg(") || t.starts_with("#![cfg(")) {
        return false;
    }
    let inner_start = t.find('(').map(|i| i + 1).unwrap_or(0);
    let inner_end = t.rfind(')').unwrap_or(t.len());
    if inner_start >= inner_end {
        return false;
    }
    cfg_has_positive_test(&t[inner_start..inner_end])
}

fn is_inner_cfg_test_attr(trimmed: &str) -> bool {
    is_cfg_test_attr(trimmed) && trimmed.trim_start().starts_with("#![cfg")
}

fn hit_is_in_comment(src: &str, at: usize) -> bool {
    let ls = line_start(src, at);
    let le = line_end(src, at);
    let line_text = &src[ls..le];
    if is_comment_only_line(line_text) {
        return true;
    }
    let code = code_portion(line_text);
    at - ls >= code.len()
}

// ---------------------------------------------------------------------------
// Test-region partition (path ∪ item-scoped cfg(test))
// ---------------------------------------------------------------------------

/// Crate-level `{bin,crates}/*/tests/**`, `src/**/tests/**`, or `tests.rs`.
///
/// Broader than G-4's `is_src_tests_path`: that helper requires a `src/`
/// component and would miss `bin/rvc/tests` / `crates/*/tests`.
fn is_tests_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split(['/', '\\']).collect();
    parts.contains(&"tests") || parts.last().is_some_and(|p| *p == "tests.rs")
}

fn close_matched(src: &str, open: usize, open_ch: u8, close_ch: u8) -> Option<usize> {
    let bytes = src.as_bytes();
    if open >= bytes.len() || bytes[open] != open_ch {
        return None;
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_str = true;
        } else if b == open_ch {
            depth += 1;
        } else if b == close_ch {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn close_paren(src: &str, open: usize) -> Option<usize> {
    close_matched(src, open, b'(', b')')
}

fn close_brace(src: &str, open: usize) -> Option<usize> {
    close_matched(src, open, b'{', b'}')
}

fn close_bracket(s: &str, open: usize) -> Option<usize> {
    close_matched(s, open, b'[', b']')
}

fn strip_leading_attrs(s: &str) -> &str {
    let mut t = s.trim_start();
    loop {
        let open = if t.starts_with("#![") {
            2
        } else if t.starts_with("#[") {
            1
        } else {
            return t;
        };
        let Some(close) = close_bracket(t, open) else {
            return t;
        };
        t = t[close + 1..].trim_start();
    }
}

fn is_attr_only_line(line: &str) -> bool {
    let code = code_portion(line).trim();
    !code.is_empty() && strip_leading_attrs(code).is_empty()
}

/// Byte offset of the first `{` or `;` outside strings and parentheses.
fn item_end_byte(src: &str, start: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut i = start;
    let mut in_str = false;
    let mut paren = 0i32;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'{' if paren == 0 => return close_brace(src, i),
            b';' if paren == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn line_byte_range(src: &str, line_0: usize) -> (usize, usize) {
    let mut start = 0;
    for _ in 0..line_0 {
        start = match src[start..].find('\n') {
            Some(rel) => start + rel + 1,
            None => return (src.len(), src.len()),
        };
    }
    let end = src[start..].find('\n').map(|rel| start + rel).unwrap_or(src.len());
    (start, end)
}

/// 1-based inclusive spans of `#[cfg(test)]` items (`#![cfg(test)]` → EOF).
fn cfg_test_item_spans(src: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if !is_cfg_test_attr(trimmed) {
            i += 1;
            continue;
        }
        let start_line = i + 1;
        if is_inner_cfg_test_attr(trimmed) {
            spans.push((start_line, lines.len().max(1)));
            break;
        }
        let Some(item_byte) = find_item_byte_after_cfg(src, &lines, i) else {
            spans.push((start_line, start_line));
            i += 1;
            continue;
        };
        let end_byte = item_end_byte(src, item_byte).unwrap_or(item_byte);
        let end_line = line_at(src, end_byte);
        spans.push((start_line, end_line));
        i = end_line;
    }
    spans
}

fn find_item_byte_after_cfg(src: &str, lines: &[&str], cfg_i: usize) -> Option<usize> {
    for k in cfg_i..lines.len() {
        let (ls, le) = line_byte_range(src, k);
        let line = &src[ls..le.min(src.len())];
        if is_comment_only_line(line) {
            continue;
        }
        let code = code_portion(line);
        let rest =
            if k == cfg_i { strip_leading_attrs(code).trim_start() } else { code.trim_start() };
        if rest.is_empty() {
            continue;
        }
        if k > cfg_i && is_attr_only_line(line) {
            continue;
        }
        let rel = line.find(rest).unwrap_or(0);
        return Some(ls + rel);
    }
    None
}

fn line_in_cfg_test_item(src: &str, line: usize) -> bool {
    cfg_test_item_spans(src).iter().any(|&(s, e)| line >= s && line <= e)
}

fn is_test_region(rel: &str, src: &str, line: usize) -> bool {
    is_tests_path(rel) || line_in_cfg_test_item(src, line)
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

fn parse_string_literal(s: &str) -> Option<&str> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        if inner.bytes().any(|b| b == b'"' || b == b'\n') {
            return None;
        }
        return Some(inner);
    }
    None
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_ident_at(src: &str, start: usize) -> &str {
    let bytes = src.as_bytes();
    let mut end = start;
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }
    &src[start..end]
}

/// `set_var` / `remove_var` are recognized here so they never enter the read set.
fn env_method_at(src: &str, env_at: usize) -> Option<(&str, usize)> {
    if env_at > 0 && is_ident_char(src.as_bytes()[env_at - 1]) {
        return None;
    }
    let method_start = env_at + "env::".len();
    if method_start > src.len() {
        return None;
    }
    let method = parse_ident_at(src, method_start);
    if method.is_empty() {
        return None;
    }
    Some((method, method_start + method.len()))
}

fn parse_env_constant(code: &str) -> Option<(String, String)> {
    let mut t = code.trim();
    if let Some(rest) = t.strip_prefix("pub") {
        let rest = rest.trim_start();
        if rest.starts_with('(') {
            let close = rest.find(')')?;
            t = rest[close + 1..].trim_start();
        } else {
            t = rest;
        }
    }
    t = t.strip_prefix("const ")?.trim_start();
    let ident_len = t.bytes().take_while(|&b| is_ident_char(b)).count();
    if ident_len == 0 {
        return None;
    }
    let ident = &t[..ident_len];
    if !(ident.ends_with("_ENV_VAR") || ident.ends_with("_ENV")) {
        return None;
    }
    t = t[ident_len..].trim_start();
    if let Some(rest) = t.strip_prefix(':') {
        t = rest.trim_start();
        let eq = t.find('=')?;
        t = t[eq + 1..].trim_start();
    } else {
        t = t.strip_prefix('=')?.trim_start();
    }
    t = t.trim_end().trim_end_matches(';').trim();
    let value = parse_string_literal(t)?;
    Some((ident.to_string(), value.to_string()))
}

fn extract_env_constants(file: &str, src: &str) -> Vec<EnvRead> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        if is_comment_only_line(line) {
            continue;
        }
        let Some((ident, value)) = parse_env_constant(code_portion(line)) else {
            continue;
        };
        out.push(EnvRead {
            file: file.to_string(),
            line: i + 1,
            shape: Shape::Constant { ident, value },
        });
    }
    out
}

fn push_call_read(out: &mut Vec<EnvRead>, file: &str, src: &str, at: usize, after_method: usize) {
    let open = skip_ws(src, after_method);
    if open >= src.len() || src.as_bytes()[open] != b'(' {
        return;
    }
    let Some(close) = close_paren(src, open) else {
        return;
    };
    let arg = src[open + 1..close].trim();
    if arg.is_empty() {
        return;
    }
    let shape = match parse_string_literal(arg) {
        Some(name) => Shape::Literal { name: name.to_string() },
        None => Shape::Dynamic { expr: collapse_ws(arg) },
    };
    out.push(EnvRead { file: file.to_string(), line: line_at(src, at), shape });
}

fn extract_env_reads(file: &str, src: &str) -> Vec<EnvRead> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = src[from..].find("env::") {
        let at = from + rel;
        from = at + "env::".len();
        if hit_is_in_comment(src, at) {
            continue;
        }
        let Some((method, after_method)) = env_method_at(src, at) else {
            continue;
        };
        // Writes are scanned so test scaffolding is not mistaken for a read.
        if method == "set_var" || method == "remove_var" {
            continue;
        }
        match method {
            "var" | "var_os" => push_call_read(&mut out, file, src, at, after_method),
            "vars" | "vars_os" => {
                let open = skip_ws(src, after_method);
                if open >= src.len() || src.as_bytes()[open] != b'(' {
                    continue;
                }
                out.push(EnvRead {
                    file: file.to_string(),
                    line: line_at(src, at),
                    shape: Shape::Dynamic { expr: format!("{method}()") },
                });
            }
            _ => {}
        }
    }
    out.extend(extract_env_constants(file, src));
    out
}

#[derive(Debug)]
struct Partitioned {
    production: Vec<EnvRead>,
    test: Vec<EnvRead>,
}

fn scan_source(file: &str, src: &str) -> Partitioned {
    let mut production = Vec::new();
    let mut test = Vec::new();
    for read in extract_env_reads(file, src) {
        if is_test_region(file, src, read.line) {
            test.push(read);
        } else {
            production.push(read);
        }
    }
    Partitioned { production, test }
}

struct WorkspaceScan {
    files: Vec<PathBuf>,
    production: Vec<EnvRead>,
}

fn scan_workspace() -> WorkspaceScan {
    let root = workspace_root();
    let files = workspace_rs_files(&root);
    let mut production = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if rel == THIS_GATE {
            continue;
        }
        let src = std::fs::read_to_string(file).unwrap_or_default();
        production.extend(scan_source(&rel, &src).production);
    }
    WorkspaceScan { files, production }
}

// ---------------------------------------------------------------------------
// Matcher unit tests (RED first on the dynamic shape)
// ---------------------------------------------------------------------------

#[test]
fn dynamic_env_read_is_captured_not_skipped() {
    let src = r#"
        let ok = std::env::var(self.env_var).as_deref() == Ok("true");
    "#;
    let reads = extract_env_reads("crates/crypto/src/insecure.rs", src);
    assert_eq!(
        reads.len(),
        1,
        "VD-4.5: dynamic env::var(self.env_var) must be a record, not a skip; got {reads:?}"
    );
    match &reads[0].shape {
        Shape::Dynamic { expr } => {
            assert_eq!(expr, "self.env_var", "dynamic expr must be the argument; got {expr:?}");
        }
        other => panic!("expected Shape::Dynamic, got {other:?}"),
    }
    let msg = reads[0].diagnostic();
    assert!(msg.contains("crates/crypto/src/insecure.rs"), "diagnostic must name file; got {msg}");
    assert!(msg.contains(&format!(":{}:", reads[0].line)), "diagnostic must name line; got {msg}");
    assert!(msg.contains("self.env_var"), "diagnostic must name the expression; got {msg}");
}

#[test]
fn cfg_test_region_reads_are_partitioned_out() {
    let src = r#"
fn production() {
    let _ = std::env::var("PROD_VAR");
}

#[cfg(test)]
mod tests {
    fn t() {
        let _ = std::env::var("TEST_VAR");
    }
}
"#;
    let scan = scan_source("crates/example/src/lib.rs", src);
    assert_eq!(scan.production.len(), 1, "one production read; got {scan:?}");
    assert_eq!(scan.test.len(), 1, "one test read; got {:?}", scan.test);
    match &scan.production[0].shape {
        Shape::Literal { name } => assert_eq!(name, "PROD_VAR"),
        other => panic!("expected literal PROD_VAR, got {other:?}"),
    }
    match &scan.test[0].shape {
        Shape::Literal { name } => assert_eq!(name, "TEST_VAR"),
        other => panic!("expected literal TEST_VAR, got {other:?}"),
    }
    let prod_msg = scan.production[0].diagnostic();
    assert!(
        prod_msg.contains("crates/example/src/lib.rs"),
        "diagnostic must name file; got {prod_msg}"
    );
    assert!(prod_msg.contains("PROD_VAR"), "diagnostic must name variable; got {prod_msg}");
}

#[test]
fn integration_test_path_reads_are_partitioned_out() {
    let src = "    let _ = std::env::var(\"X\");\n";
    assert!(!src.contains("cfg(test)"), "path rule must apply with no in-file #[cfg(test)]");
    for rel in ["bin/rvc/tests/foo.rs", "crates/foo/tests/bar.rs", "crates/rvc/src/foo/tests.rs"] {
        let scan = scan_source(rel, src);
        assert!(
            scan.production.is_empty(),
            "{rel}: integration/src tests path must not be production; got {scan:?}"
        );
        assert_eq!(scan.test.len(), 1, "{rel}: expected one test read; got {:?}", scan.test);
        match &scan.test[0].shape {
            Shape::Literal { name } => assert_eq!(name, "X"),
            other => panic!("{rel}: expected literal X, got {other:?}"),
        }
    }
}

#[test]
fn mid_file_cfg_test_helper_does_not_hide_later_production() {
    let src = r#"
fn before() {
    let _ = std::env::var("BEFORE");
}

#[cfg(test)]
fn helper() {
    let _ = std::env::var("HELPER");
}

fn after() {
    let _ = std::env::var("PROD");
}
"#;
    let scan = scan_source("crates/example/src/lib.rs", src);
    let prod: Vec<_> = scan
        .production
        .iter()
        .filter_map(|r| match &r.shape {
            Shape::Literal { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let test: Vec<_> = scan
        .test
        .iter()
        .filter_map(|r| match &r.shape {
            Shape::Literal { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(prod, ["BEFORE", "PROD"], "later production must stay production; got {scan:?}");
    assert_eq!(test, ["HELPER"], "cfg(test) helper is test-only; got {scan:?}");
}

#[test]
fn not_test_cfg_does_not_start_a_test_region() {
    let src = r#"
#[cfg(not(test))]
fn prod() {
    let _ = std::env::var("PROD_VAR");
}

fn also() {
    let _ = std::env::var("ALSO");
}
"#;
    let scan = scan_source("crates/example/src/lib.rs", src);
    assert_eq!(scan.test.len(), 0, "not(test) must not be a test region; got {scan:?}");
    assert_eq!(scan.production.len(), 2, "both reads stay production; got {scan:?}");
}

#[test]
fn cfg_test_attr_detection() {
    assert!(is_cfg_test_attr("#[cfg(test)]"));
    assert!(is_cfg_test_attr("#![cfg(test)]"));
    assert!(is_cfg_test_attr("#[cfg(all(test, feature = \"x\"))]"));
    assert!(!is_cfg_test_attr("#[cfg(feature = \"test-utils\")]"));
    assert!(!is_cfg_test_attr("#[test]"));
    assert!(!is_cfg_test_attr("#[cfg(not(test))]"));
    assert!(!is_cfg_test_attr("#[cfg(all(not(test), unix))]"));
}

#[test]
fn env_constant_declaration_is_extracted() {
    let src = r#"pub const LOG_FORMAT_ENV: &str = "RVC_LOG_FORMAT";"#;
    let reads = extract_env_reads("crates/telemetry/src/format.rs", src);
    assert_eq!(reads.len(), 1, "constant declaration must be a record; got {reads:?}");
    match &reads[0].shape {
        Shape::Constant { ident, value } => {
            assert_eq!(ident, "LOG_FORMAT_ENV");
            assert_eq!(value, "RVC_LOG_FORMAT");
        }
        other => panic!("expected Shape::Constant LOG_FORMAT_ENV → RVC_LOG_FORMAT, got {other:?}"),
    }
    let msg = reads[0].diagnostic();
    assert!(msg.contains("crates/telemetry/src/format.rs"), "diagnostic must name file; got {msg}");
    assert!(msg.contains(&format!(":{}:", reads[0].line)), "diagnostic must name line; got {msg}");
    assert!(msg.contains("LOG_FORMAT_ENV"), "diagnostic must name the ident; got {msg}");
    assert!(msg.contains("RVC_LOG_FORMAT"), "diagnostic must name the variable; got {msg}");

    let src = r#"pub const INSECURE_ENV_VAR: &str = "RVC_SIGNER_ALLOW_INSECURE";"#;
    let reads = extract_env_reads("crates/signer-server/src/insecure_startup.rs", src);
    assert_eq!(reads.len(), 1, "_ENV_VAR suffix must be a record; got {reads:?}");
    match &reads[0].shape {
        Shape::Constant { ident, value } => {
            assert_eq!(ident, "INSECURE_ENV_VAR");
            assert_eq!(value, "RVC_SIGNER_ALLOW_INSECURE");
        }
        other => panic!("expected INSECURE_ENV_VAR → RVC_SIGNER_ALLOW_INSECURE, got {other:?}"),
    }
}

#[test]
fn set_var_is_not_a_read() {
    let src = r#"
        std::env::set_var("FOO", "1");
        env::set_var("BAR", "2");
        std::env::remove_var("FOO");
        env::remove_var("BAR");
    "#;
    let reads = extract_env_reads("crates/example/src/lib.rs", src);
    assert!(reads.is_empty(), "set_var/remove_var must not produce EnvRead; got {reads:?}");
}

#[test]
fn var_os_is_captured_as_a_read() {
    let src = r#"
        let _ = std::env::var_os("RUST_LOG");
        let _ = env::var_os(self.env_var);
    "#;
    let reads = extract_env_reads("crates/example/src/lib.rs", src);
    assert_eq!(reads.len(), 2, "var_os is a read; got {reads:?}");
    match &reads[0].shape {
        Shape::Literal { name } => assert_eq!(name, "RUST_LOG"),
        other => panic!("expected literal RUST_LOG, got {other:?}"),
    }
    match &reads[1].shape {
        Shape::Dynamic { expr } => assert_eq!(expr, "self.env_var"),
        other => panic!("expected dynamic self.env_var, got {other:?}"),
    }
    let msg = reads[0].diagnostic();
    assert!(msg.contains("crates/example/src/lib.rs"), "diagnostic must name file; got {msg}");
    assert!(msg.contains("RUST_LOG"), "diagnostic must name the variable; got {msg}");
}

#[test]
fn vars_family_is_captured_not_skipped() {
    let src = r#"
        for (k, _) in std::env::vars() {}
        for (k, _) in env::vars_os() {}
    "#;
    let reads = extract_env_reads("crates/example/src/lib.rs", src);
    assert_eq!(reads.len(), 2, "vars/vars_os must be recorded, not dropped; got {reads:?}");
    match &reads[0].shape {
        Shape::Dynamic { expr } => assert_eq!(expr, "vars()"),
        other => panic!("expected Dynamic vars(), got {other:?}"),
    }
    match &reads[1].shape {
        Shape::Dynamic { expr } => assert_eq!(expr, "vars_os()"),
        other => panic!("expected Dynamic vars_os(), got {other:?}"),
    }
}

#[test]
fn scanner_is_non_vacuous_over_the_real_workspace() {
    let scan = scan_workspace();
    let files = &scan.files;
    assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke", files.len());
    let production_reads = scan.production.len();
    assert!(
        production_reads >= 8,
        "found only {production_reads} production env read(s); workspace walk likely broke"
    );
    assert!(
        scan.production.iter().all(|r| r.file != THIS_GATE),
        "{THIS_GATE} must not scan its own synthetic fixtures"
    );
    assert!(
        scan.production.iter().all(|r| !is_tests_path(&r.file)),
        "production set must not include tests/ paths: {:?}",
        scan.production.iter().filter(|r| is_tests_path(&r.file)).collect::<Vec<_>>()
    );
    assert!(
        scan.production.iter().any(|r| {
            r.file.ends_with("crates/crypto/src/insecure.rs")
                && matches!(&r.shape, Shape::Dynamic { expr } if expr == "self.env_var")
        }),
        "workspace walk must see insecure.rs self.env_var; got {:?}",
        scan.production
    );
    assert!(
        scan.production.iter().any(|r| {
            r.file.ends_with("crates/telemetry/src/init.rs")
                && matches!(&r.shape, Shape::Literal { name } if name == "RUST_LOG")
        }),
        "workspace walk must see init.rs RUST_LOG; got {:?}",
        scan.production
    );
}
