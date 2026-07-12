//! Console log-output format selector (issue 5.5 / P2-3).
//!
//! Both binaries render their **console** log stream through a single
//! `tracing_subscriber::fmt` layer. By default that layer emits the
//! human-readable *pretty* format (colorized, span-scoped lines) — the right
//! choice for interactive debugging and `grep`. An operator shipping logs to an
//! aggregation backend (Loki / Elasticsearch / a SIEM) can opt into a structured
//! **JSON** profile instead, where each event is one JSON object whose keys are
//! the canonical correlation fields (`request_id`, `slot`, …) so they are
//! machine-filterable.
//!
//! The selector is **opt-in and identical across both binaries** (consistent with
//! the Phase-3 [`env_filter_or`](crate::env_filter_or) /
//! [`reloadable_env_filter`](crate::reloadable_env_filter) shared-helper approach),
//! so an operator learns one knob, not two.
//!
//! ## Scope
//! This selector governs the **console** `fmt` layer only. It does **not** touch
//! the OTLP trace layer, the trace sampler, or the file appender's own format —
//! the on-disk file keeps its independent (pretty) rendering.
//!
//! ## Redaction is unaffected
//! Secret redaction happens at the **value** level: a `pubkey` is recorded as an
//! already-truncated `0x{first10}...{last8}` string (via
//! `crypto::logging::TruncatedPubkey`) and a URL via `RedactedUrl` *before* it is
//! handed to any layer. JSON serialization of an already-redacted value stays
//! redacted — selecting JSON is **not** a redaction bypass (proven by a captured
//! subscriber test, see this module's tests).

use tracing_subscriber::fmt::format::{DefaultFields, Format};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Selects how the **console** log stream is rendered (issue 5.5).
///
/// `Pretty` is the default and reproduces today's exact human-readable output;
/// `Json` emits one structured JSON object per event for log-aggregation
/// backends. Parsed from the `--log-format` CLI flag and/or the
/// `RVC_LOG_FORMAT` environment variable via [`LogFormat::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable, colorized, span-scoped lines (the default).
    #[default]
    Pretty,
    /// One JSON object per event, canonical fields flattened to top-level keys.
    Json,
}

/// The environment variable an operator may set to choose the console format,
/// mirroring how `RUST_LOG` selects the level. An explicit `--log-format` CLI
/// flag takes precedence over this (see [`LogFormat::resolve`]).
pub const LOG_FORMAT_ENV: &str = "RVC_LOG_FORMAT";

impl LogFormat {
    /// Parse a single textual token (`"pretty"` / `"json"`, case-insensitive,
    /// surrounding whitespace tolerated) into a [`LogFormat`].
    ///
    /// Returns `None` for anything unrecognized so a caller can decide whether an
    /// unknown value is a hard error (CLI, via `clap`'s `ValueEnum`) or a soft
    /// fall-back-to-default (the `RVC_LOG_FORMAT` env path — an accidental typo in
    /// a k8s manifest must never silence or crash logging).
    pub fn parse_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "pretty" => Some(Self::Pretty),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// Reconcile the console format from the optional CLI value and the
    /// `RVC_LOG_FORMAT` environment variable, with **pretty as the default**.
    ///
    /// Precedence (highest first), parallel to ADR-003's `RUST_LOG` precedence so
    /// the two knobs behave consistently:
    /// 1. an explicit, recognized `--log-format` CLI value wins entirely;
    /// 2. else a recognized `RVC_LOG_FORMAT` env value;
    /// 3. else (unset / empty / unrecognized) → [`LogFormat::Pretty`].
    ///
    /// Unrecognized values fall back rather than panicking, so a typo never takes
    /// logging dark — exactly the posture [`env_filter_or`](crate::env_filter_or)
    /// takes for the level.
    pub fn resolve(cli_value: Option<&str>) -> Self {
        if let Some(v) = cli_value {
            if let Some(fmt) = Self::parse_token(v) {
                return fmt;
            }
        }
        if let Ok(env) = std::env::var(LOG_FORMAT_ENV) {
            if let Some(fmt) = Self::parse_token(&env) {
                return fmt;
            }
        }
        Self::Pretty
    }

    /// The canonical lowercase token for this format (`"pretty"` / `"json"`),
    /// for echoing the resolved choice back to logs/help text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Json => "json",
        }
    }
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build the **console** `fmt` layer for the selected [`LogFormat`], type-erased to
/// `Box<dyn Layer<S>>` so a single variable holds either arm.
///
/// `fmt::layer()` (pretty) and `fmt::layer().json()` are **different types**, so
/// they cannot be assigned to one variable directly; boxing both behind
/// `dyn Layer<S>` lets each binary compose ONE console layer into its subscriber
/// stack identically, regardless of the format. This keeps the 5.4 reload
/// composition and the empty-`Vec` `Identity` padding byte-identical across both
/// arms — only the leaf console layer's *format* differs.
///
/// For `Json`, `flatten_event(true)` lifts the event's own fields to the top level
/// (no nested `fields` object) and `with_current_span(true)` attaches the current
/// span's fields, so the canonical correlation keys (`request_id`, `slot`, …) land
/// as top-level JSON keys that an aggregation backend can index directly.
///
/// The `make_writer` parameter is the destination (production passes
/// `std::io::stdout`); it is generic so tests can capture output into a buffer.
pub fn console_fmt_layer<S, W>(format: LogFormat, make_writer: W) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    match format {
        LogFormat::Pretty => fmt_layer_pretty(make_writer).boxed(),
        LogFormat::Json => json_layer::json_console_layer(make_writer).boxed(),
    }
}

/// The pretty (default) console layer — the exact `fmt::layer()` both binaries
/// built before issue 5.5, parameterized only by its writer.
fn fmt_layer_pretty<S, W>(
    make_writer: W,
) -> tracing_subscriber::fmt::Layer<S, DefaultFields, Format, W>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer().with_writer(make_writer)
}

/// Local sub-module so the JSON-layer type (`Format<Json>`) need not be named at
/// the call site — `.boxed()` erases it immediately in [`console_fmt_layer`].
mod json_layer {
    use super::*;

    /// The JSON console layer with canonical fields flattened to top-level keys.
    pub(super) fn json_console_layer<S, W>(make_writer: W) -> impl Layer<S> + Send + Sync
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_writer(make_writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::prelude::*;

    // Serializes the `RVC_LOG_FORMAT`-mutating `resolve` tests (process-global env).
    // nextest forks a process per test, but guard anyway so the suite is correct
    // under any runner that threads tests in one process.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_log_format_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(LOG_FORMAT_ENV).ok();
        match value {
            Some(v) => unsafe { std::env::set_var(LOG_FORMAT_ENV, v) },
            None => unsafe { std::env::remove_var(LOG_FORMAT_ENV) },
        }
        let out = f();
        match prev {
            Some(p) => unsafe { std::env::set_var(LOG_FORMAT_ENV, p) },
            None => unsafe { std::env::remove_var(LOG_FORMAT_ENV) },
        }
        out
    }

    /// A `MakeWriter` that captures everything written into a shared buffer, so a
    /// captured-subscriber test can inspect the rendered bytes.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl io::Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
    impl SharedBuf {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    // ── LogFormat::parse_token ────────────────────────────────────────────────

    #[test]
    fn parse_token_accepts_canonical_tokens_case_and_space_insensitively() {
        assert_eq!(LogFormat::parse_token("pretty"), Some(LogFormat::Pretty));
        assert_eq!(LogFormat::parse_token("json"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse_token("  JSON  "), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse_token("Pretty"), Some(LogFormat::Pretty));
    }

    #[test]
    fn parse_token_rejects_unknown() {
        assert_eq!(LogFormat::parse_token("logfmt"), None);
        assert_eq!(LogFormat::parse_token(""), None);
    }

    #[test]
    fn default_is_pretty() {
        assert_eq!(LogFormat::default(), LogFormat::Pretty);
    }

    // ── LogFormat::resolve precedence ────────────────────────────────────────

    /// With no CLI value and no env, the format defaults to pretty — the
    /// constraint that an unset selector reproduces today's exact output.
    #[test]
    fn resolve_unset_defaults_to_pretty() {
        let got = with_log_format_env(None, || LogFormat::resolve(None));
        assert_eq!(got, LogFormat::Pretty);
    }

    /// An explicit CLI value wins over both the env and the default.
    #[test]
    fn resolve_cli_value_wins_over_env() {
        let got = with_log_format_env(Some("pretty"), || LogFormat::resolve(Some("json")));
        assert_eq!(got, LogFormat::Json, "CLI --log-format must outrank RVC_LOG_FORMAT");
    }

    /// With no CLI value, a recognized env value selects the format.
    #[test]
    fn resolve_env_selects_when_no_cli() {
        let got = with_log_format_env(Some("json"), || LogFormat::resolve(None));
        assert_eq!(got, LogFormat::Json);
    }

    /// An unrecognized value (CLI or env) never panics and never silences logging:
    /// it falls back to pretty, exactly as `env_filter_or` falls back for the level.
    #[test]
    fn resolve_unrecognized_falls_back_to_pretty() {
        let got = with_log_format_env(Some("garbage"), || LogFormat::resolve(Some("nonsense")));
        assert_eq!(got, LogFormat::Pretty);
        // A bad env with no CLI value also falls back.
        let got = with_log_format_env(Some("xml"), || LogFormat::resolve(None));
        assert_eq!(got, LogFormat::Pretty);
    }

    // ── JSON profile: parses + canonical fields are top-level keys ────────────

    /// With the JSON profile selected, a representative event carrying canonical
    /// correlation fields serializes to ONE valid JSON object per line in which
    /// `slot`, `request_id`, and a (truncated) `pubkey` appear as TOP-LEVEL keys
    /// (thanks to `flatten_event`) — i.e. machine-filterable, not nested.
    #[test]
    fn json_profile_emits_parseable_object_with_canonical_top_level_keys() {
        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Json, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                slot = 7u64,
                request_id = "11111111-2222-3333-4444-555555555555",
                pubkey = "0x93247f2209...611df74a",
                "duty signed"
            );
        });

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("duty signed")).expect("event line present");
        let v: serde_json::Value = serde_json::from_str(line).expect("each JSON line must parse");

        assert_eq!(
            v["fields"],
            serde_json::Value::Null,
            "flatten_event must hoist fields to top level"
        );
        assert_eq!(v["slot"], 7, "slot must be a top-level JSON key");
        assert_eq!(v["request_id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(v["pubkey"], "0x93247f2209...611df74a");
        assert_eq!(v["message"], "duty signed");
        assert_eq!(v["level"], "INFO");
    }

    /// The current span's fields surface as top-level JSON keys too
    /// (`with_current_span(true)`), so a `request_id` set on the enclosing span is
    /// machine-filterable on every event emitted within it.
    #[test]
    fn json_profile_includes_current_span_fields() {
        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Json, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", request_id = "abc-123");
            let _e = span.enter();
            tracing::info!("inside span");
        });

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("inside span")).expect("event line present");
        let v: serde_json::Value = serde_json::from_str(line).expect("parses");
        // `with_current_span` records the span under `span` with its fields.
        assert_eq!(v["span"]["request_id"], "abc-123", "current span field must be present");
    }

    // ── Default (pretty) profile: NOT JSON, unchanged shape ───────────────────

    /// With the pretty profile (the default), output is the human-readable line
    /// format — it is NOT a parseable JSON object, and it contains the message and
    /// fields rendered the classic way. This pins that selecting nothing keeps
    /// today's behavior.
    #[test]
    fn pretty_profile_is_not_json() {
        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Pretty, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(slot = 7u64, "duty signed");
        });

        let out = buf.contents();
        let line = out.lines().find(|l| l.contains("duty signed")).expect("event line present");
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_err(),
            "pretty output must NOT be a JSON object; got: {line:?}"
        );
        // Strip ANSI styling so the pretty `key=value` rendering is greppable
        // (the colorized output interleaves escape sequences around the `=`).
        let plain = strip_ansi(line);
        assert!(plain.contains("INFO"), "pretty renders the level; got: {plain:?}");
        assert!(plain.contains("slot"), "pretty renders the field name; got: {plain:?}");
        assert!(plain.contains("slot=7"), "pretty renders fields key=value; got: {plain:?}");
    }

    /// Strip ANSI SGR escape sequences (`\x1b[...m`) so a pretty line's text can be
    /// asserted without the interleaved color codes.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // Consume up to and including the terminating 'm' of an SGR sequence.
                for n in chars.by_ref() {
                    if n == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    // ── SECURITY: JSON is not a redaction bypass ──────────────────────────────

    /// JSON serialization must NOT undo value-level redaction. Redaction happens
    /// BEFORE recording: a `pubkey` is recorded as the already-truncated
    /// `0x{first10}...{last8}` string and a URL via `RedactedUrl`, so the layer
    /// only ever sees redacted strings. This proves the JSON profile serializes
    /// those redacted values verbatim — the full 96-char pubkey and the URL
    /// credentials never appear in the JSON.
    #[test]
    fn json_profile_does_not_bypass_value_level_redaction() {
        // The full secret material an upstream call site would have held.
        let full_pubkey =
            "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        // The already-redacted values that actually get recorded (this is exactly
        // what `crypto::logging::TruncatedPubkey` / `RedactedUrl` produce at the
        // VALUE level before the field is handed to any layer).
        let redacted_pubkey = "0x93247f2209...611df74a";
        let redacted_url = "http://***:***@beacon.internal:5052/";

        let buf = SharedBuf::default();
        let layer =
            console_fmt_layer::<tracing_subscriber::Registry, _>(LogFormat::Json, buf.clone());
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                pubkey = redacted_pubkey,
                bn_url = redacted_url,
                "high-risk signing event"
            );
        });

        let out = buf.contents();
        let line =
            out.lines().find(|l| l.contains("high-risk signing event")).expect("event present");
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON parses");

        // The redacted values appear verbatim as JSON values…
        assert_eq!(v["pubkey"], redacted_pubkey, "pubkey must be the truncated form");
        assert_eq!(v["bn_url"], redacted_url, "bn_url must be the credential-stripped form");

        // …and the secrets NEVER appear anywhere in the serialized JSON.
        assert!(
            !line.contains(full_pubkey),
            "the full 96-char pubkey must NOT appear in JSON output; line: {line:?}"
        );
        assert!(
            !line.contains("hunter2") && !line.contains(":pass@"),
            "URL credentials must NOT appear in JSON output; line: {line:?}"
        );
        // The middle of the full pubkey (absent from the truncated form) must be gone.
        assert!(
            !line.contains("abcacf57b75a51"),
            "middle of the full pubkey must be truncated away; line: {line:?}"
        );
    }
}
