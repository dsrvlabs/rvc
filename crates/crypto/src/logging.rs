/// Displays a public key hex string as `0x{first10}...{last8}`.
///
/// Implements `Display` for zero-allocation use with tracing's `%` specifier.
/// When tracing level is disabled, `Display::fmt` is never called.
pub struct TruncatedPubkey<'a>(pub &'a str);

impl<'a> TruncatedPubkey<'a> {
    pub fn new(hex: &'a str) -> Self {
        Self(hex)
    }
}

impl std::fmt::Display for TruncatedPubkey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Defense-in-depth: strip at most one `0x`/`0X` prefix.
        // On `DoubleZeroXPrefix` emit a warning and fall back to the raw input
        // as-is so that the log line is not garbled and no panic occurs.
        // Callers should supply canonical pubkeys; this path indicates a bug upstream.
        let hex = match crate::hex::strip_prefix_strict(self.0) {
            Ok(s) => s,
            Err(crate::hex::HexError::DoubleZeroXPrefix) => {
                tracing::warn!(
                    pubkey = self.0,
                    "TruncatedPubkey: double 0x prefix detected, falling back to raw input"
                );
                return write!(f, "{}", self.0);
            }
        };
        if hex.len() > 18 && hex.is_ascii() {
            write!(f, "0x{}...{}", &hex[..10], &hex[hex.len() - 8..])
        } else {
            write!(f, "0x{hex}")
        }
    }
}

/// Displays a URL with username/password replaced by `***`.
///
/// Uses `url::Url::parse` internally. If parsing fails, displays the raw string.
pub struct RedactedUrl<'a>(pub &'a str);

impl std::fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(mut parsed) = url::Url::parse(self.0) {
            if parsed.password().is_some() || !parsed.username().is_empty() {
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            write!(f, "{parsed}")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Displays a 32-byte root / signature / hash as `0x{first10hex}...{last8hex}`.
///
/// Zero-allocation `Display` wrapper for tracing's `%` specifier: the hex is written
/// byte-by-byte directly into the `Formatter` (no `hex::encode` / `format!` / `to_string`),
/// so nothing is heap-allocated and `fmt` only runs when the log level is enabled. This is
/// the sanctioned way to render a block / head / signing root, hash, or signature in a log
/// line (ADR-005); a full root or signature is never logged.
///
/// Wraps a **non-secret** root / signature only — a `Display` impl is never added to a
/// secret type.
///
/// Inputs shorter than 9 bytes render their full lower-hex (`0x{all-bytes}`) instead of
/// slicing out of bounds, and `fmt` never panics.
pub struct TruncatedRoot<'a>(pub &'a [u8]);

impl<'a> TruncatedRoot<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for TruncatedRoot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        f.write_str("0x")?;
        // Short input (< 9 bytes): the 5 leading + 4 trailing slices would overlap, so
        // render the full lower-hex rather than slice out of bounds. Never panics.
        if bytes.len() < 9 {
            for b in bytes {
                write!(f, "{b:02x}")?;
            }
            return Ok(());
        }
        // 5 leading bytes (10 hex chars) + "..." + 4 trailing bytes (8 hex chars).
        // Written byte-by-byte: zero heap allocation, and lazy under `%`.
        for b in &bytes[..5] {
            write!(f, "{b:02x}")?;
        }
        f.write_str("...")?;
        for b in &bytes[bytes.len() - 4..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Canonical structured-field keys and `duty` value strings — the compile-checked,
/// greppable mirror of the field registry in `plan/logging/STANDARD.md`.
///
/// These consts are the single source of truth for field-key spellings so no crate can
/// invent a synonym (`val_idx`, `validator`, `rvc.slot`). They MUST stay in lockstep with
/// the STANDARD.md registry table; Gate 5 (Phase 4/5) diffs emitted field names against
/// them. `network` is intentionally **absent** — it is a resource attribute set once in
/// `telemetry::init`, never a per-event key.
pub mod fields {
    /// Slot number (`u64`). Lives on the duty / attestation / block / sign span.
    pub const SLOT: &str = "slot";
    /// Epoch number (`u64`). Lives on the duty span.
    pub const EPOCH: &str = "epoch";
    /// Validator index (`u64`).
    pub const VALIDATOR_INDEX: &str = "validator_index";
    /// Truncated public key (`0x{first10}...{last8}`, via `TruncatedPubkey`).
    pub const PUBKEY: &str = "pubkey";
    /// Duty kind string (see [`Duty`]).
    pub const DUTY: &str = "duty";
    /// Correlation id for one signing / API request (including the :9000 hop).
    pub const REQUEST_ID: &str = "request_id";
    /// Committee index (`u64`).
    pub const COMMITTEE_INDEX: &str = "committee_index";
    /// Subcommittee index (`u64`) — sync-committee contribution lines only.
    pub const SUBCOMMITTEE_INDEX: &str = "subcommittee_index";
    /// Redacted beacon-node URL (via `RedactedUrl`).
    pub const BN_URL: &str = "bn_url";
    /// Attested head root (truncated via `TruncatedRoot`).
    pub const HEAD: &str = "head";
    /// Proposed block root (truncated via `TruncatedRoot`).
    pub const BLOCK_ROOT: &str = "block_root";
    /// Time into slot (duration / ms) — operator timing signal.
    pub const TIME_INTO_SLOT: &str = "time_into_slot";

    /// Canonical `duty` value strings.
    ///
    /// `as_str()` returns a `&'static str` so it is `Copy`-cheap and safe to use inside an
    /// eagerly-evaluated `#[instrument(fields(duty = %Duty::….as_str()))]` (research R1).
    /// Spellings are normative — `sync_committee`, not the Prysm/Lodestar variants.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Duty {
        Attestation,
        Block,
        Aggregate,
        SyncCommittee,
        SyncContribution,
        ValidatorRegistration,
        VoluntaryExit,
    }

    impl Duty {
        /// Returns the normative `&'static str` spelling for this duty.
        pub fn as_str(&self) -> &'static str {
            match self {
                Duty::Attestation => "attestation",
                Duty::Block => "block",
                Duty::Aggregate => "aggregate",
                Duty::SyncCommittee => "sync_committee",
                Duty::SyncContribution => "sync_contribution",
                Duty::ValidatorRegistration => "validator_registration",
                Duty::VoluntaryExit => "voluntary_exit",
            }
        }
    }
}

/// Mints a fresh `request_id` (a v4 UUID) for one signing / API request.
///
/// Returns a [`uuid::Uuid`], **not** a pre-built `String`, so callers render it with `%`
/// and pay nothing when the span level is disabled (ADR-002). The id follows a single
/// request end to end, including across the :9000 Web3Signer hop.
pub fn new_request_id() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

/// Fills a deferred (`field::Empty`) span field with a `Display` value.
///
/// The target field **must** have been declared at span creation (e.g.
/// `request_id = tracing::field::Empty`); recording a field that was **not** declared is a
/// silent no-op — the #1 "vanishing attribute" bug. This helper exists because the `%`/`?`
/// sigils are macro sugar and are **not** available at a `span.record(...)` call site.
///
/// **Secret-safety (STANDARD.md §3):** `val` is rendered verbatim, so it MUST be
/// non-secret — wrap pubkeys in `TruncatedPubkey`, roots/signatures in `TruncatedRoot`, and
/// URLs in `RedactedUrl`; never pass key material, passwords, or mnemonics. The recorded
/// value surfaces only on events emitted **while the span is entered** (or via
/// `#[instrument]` / `.in_scope()`).
pub fn record_display(span: &tracing::Span, key: &'static str, val: impl std::fmt::Display) {
    span.record(key, tracing::field::display(val));
}

/// Fills a deferred (`field::Empty`) span field with a `Debug` value.
///
/// Same contract as [`record_display`], including its secret-safety rule: the field must be
/// declared at span creation or the record is silently dropped, and you must never
/// `?`-format secret-bearing data (e.g. a type that derives `Debug` over key material).
pub fn record_debug(span: &tracing::Span, key: &'static str, val: impl std::fmt::Debug) {
    span.record(key, tracing::field::debug(val));
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TruncatedPubkey tests ---

    #[test]
    fn test_truncated_pubkey_long_with_prefix() {
        let pubkey = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        assert_eq!(result, "0x93247f2209...611df74a");
    }

    #[test]
    fn test_truncated_pubkey_long_without_prefix() {
        let pubkey = "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        assert_eq!(result, "0x93247f2209...611df74a");
    }

    #[test]
    fn test_truncated_pubkey_short_with_prefix() {
        let result = TruncatedPubkey::new("0xabcdef").to_string();
        assert_eq!(result, "0xabcdef");
    }

    #[test]
    fn test_truncated_pubkey_short_without_prefix() {
        let result = TruncatedPubkey::new("abcdef").to_string();
        assert_eq!(result, "0xabcdef");
    }

    #[test]
    fn test_truncated_pubkey_exactly_18_chars() {
        let result = TruncatedPubkey::new("0x123456789012345678").to_string();
        assert_eq!(result, "0x123456789012345678");
    }

    #[test]
    fn test_truncated_pubkey_19_chars_truncated() {
        let result = TruncatedPubkey::new("0x1234567890123456789").to_string();
        assert_eq!(result, "0x1234567890...23456789");
    }

    #[test]
    fn test_truncated_pubkey_empty() {
        let result = TruncatedPubkey::new("").to_string();
        assert_eq!(result, "0x");
    }

    #[test]
    fn test_truncated_pubkey_non_ascii_falls_back() {
        let input = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74à";
        let result = TruncatedPubkey::new(input).to_string();
        assert_eq!(result, "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74à");
    }

    // -- CQ-2.5: strip_prefix_strict adoption test --

    /// TruncatedPubkey must warn and fall back to the raw input when given a double-0x prefix.
    /// Behavior: no panic, the raw string is emitted as-is, and a warn! log fires.
    #[test]
    #[tracing_test::traced_test]
    fn test_truncated_pubkey_double_0x_prefix_warns_and_falls_back() {
        let pubkey = "0x0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        // Must not panic; raw input is emitted as-is
        assert_eq!(result, pubkey, "double-0x input must be returned verbatim");
        assert!(logs_contain("double 0x prefix"), "expected warn log about double prefix");
    }

    // --- RedactedUrl tests ---

    #[test]
    fn test_redacted_url_with_credentials() {
        let url = "http://user:pass@example.com/path";
        let result = RedactedUrl(url).to_string();
        assert!(result.contains("***:***@"));
        assert!(result.contains("example.com/path"));
    }

    #[test]
    fn test_redacted_url_without_credentials() {
        let url = "http://example.com/path";
        let result = RedactedUrl(url).to_string();
        assert_eq!(result, "http://example.com/path");
    }

    #[test]
    fn test_redacted_url_invalid() {
        let url = "not a url";
        let result = RedactedUrl(url).to_string();
        assert_eq!(result, "not a url");
    }

    #[test]
    fn test_redacted_url_username_only() {
        let url = "http://user@example.com/path";
        let result = RedactedUrl(url).to_string();
        assert!(result.contains("***"));
        assert!(!result.contains("user@"));
    }

    // --- TruncatedRoot tests ---

    #[test]
    fn test_truncated_root_32_bytes() {
        let result = TruncatedRoot::new(&[0xab; 32]).to_string();
        assert_eq!(result, "0xababababab...abababab");
        // 0x (2) + 10 leading hex + "..." (3) + 8 trailing hex = 23 chars.
        // NOTE: Issue 1.2's acceptance text "exactly 22" is a miscount of this same
        // breakdown (0x + 10 + ... + 8 = 23); the canonical rendering is 23 chars.
        assert_eq!(result.len(), 23);
    }

    #[test]
    fn test_truncated_root_distinct_bytes() {
        // 0x00,0x01,...,0x1f — first 5 bytes -> 0001020304, last 4 -> 1c1d1e1f.
        let root: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(TruncatedRoot::new(&root).to_string(), "0x0001020304...1c1d1e1f");
    }

    /// Redaction (Gate-3 style): the FULL hex of a 32-byte root MUST be absent from a
    /// `trace`-level log line that renders it via `%TruncatedRoot`; only the truncated
    /// form appears.
    #[test]
    #[tracing_test::traced_test]
    fn test_truncated_root_full_hex_absent_at_trace() {
        let root: [u8; 32] = std::array::from_fn(|i| i as u8);
        tracing::trace!(root = %TruncatedRoot::new(&root), "computed signing root");
        let full_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert!(logs_contain("0x0001020304...1c1d1e1f"), "truncated form must be present");
        assert!(!logs_contain(full_hex), "full 32-byte hex must NOT appear");
        // A middle slice that exists only in the full encoding must be absent too.
        assert!(!logs_contain("0a0b0c0d"), "middle bytes must be truncated away");
    }

    #[test]
    fn test_truncated_root_empty_no_panic() {
        assert_eq!(TruncatedRoot::new(&[]).to_string(), "0x");
    }

    #[test]
    fn test_truncated_root_one_byte() {
        assert_eq!(TruncatedRoot::new(&[0xab]).to_string(), "0xab");
    }

    #[test]
    fn test_truncated_root_eight_bytes_full() {
        // 8 bytes (< 9): full lower-hex, not truncated.
        assert_eq!(TruncatedRoot::new(&[0xab; 8]).to_string(), "0xabababababababab");
    }

    #[test]
    fn test_truncated_root_nine_bytes_truncates() {
        // 9 bytes is the threshold: 5 leading + 4 trailing exactly cover it, no overlap.
        let bytes: [u8; 9] = std::array::from_fn(|i| i as u8);
        assert_eq!(TruncatedRoot::new(&bytes).to_string(), "0x0001020304...05060708");
    }

    // --- fields registry + Duty tests ---

    #[test]
    fn test_field_const_values_match_registry() {
        assert_eq!(fields::SLOT, "slot");
        assert_eq!(fields::EPOCH, "epoch");
        assert_eq!(fields::VALIDATOR_INDEX, "validator_index");
        assert_eq!(fields::PUBKEY, "pubkey");
        assert_eq!(fields::DUTY, "duty");
        assert_eq!(fields::REQUEST_ID, "request_id");
        assert_eq!(fields::COMMITTEE_INDEX, "committee_index");
        assert_eq!(fields::SUBCOMMITTEE_INDEX, "subcommittee_index");
        assert_eq!(fields::BN_URL, "bn_url");
        assert_eq!(fields::HEAD, "head");
        assert_eq!(fields::BLOCK_ROOT, "block_root");
        assert_eq!(fields::TIME_INTO_SLOT, "time_into_slot");
    }

    #[test]
    fn test_duty_as_str_pins_all_seven_variants() {
        use fields::Duty;
        assert_eq!(Duty::Attestation.as_str(), "attestation");
        assert_eq!(Duty::Block.as_str(), "block");
        assert_eq!(Duty::Aggregate.as_str(), "aggregate");
        assert_eq!(Duty::SyncCommittee.as_str(), "sync_committee");
        assert_eq!(Duty::SyncContribution.as_str(), "sync_contribution");
        assert_eq!(Duty::ValidatorRegistration.as_str(), "validator_registration");
        assert_eq!(Duty::VoluntaryExit.as_str(), "voluntary_exit");
    }

    // --- correlation kit tests ---

    #[test]
    fn test_new_request_id_is_v4_and_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_eq!(a.get_version(), Some(uuid::Version::Random));
        assert_ne!(a, b, "two successive request ids must differ");
    }

    /// A field declared `field::Empty` at span creation is filled by `record_display` and
    /// inherits to a child event under a capturing subscriber.
    #[test]
    #[tracing_test::traced_test]
    fn test_record_display_fills_declared_empty_field() {
        let span = tracing::info_span!("req", request_id = tracing::field::Empty);
        let _e = span.enter();
        let id = new_request_id();
        record_display(&span, fields::REQUEST_ID, id);
        tracing::info!("request handled");
        assert!(logs_contain(&id.to_string()), "recorded request_id must appear on the event");
    }

    /// Recording a field that was NOT declared at span creation is a silent no-op — this
    /// documents the foot-gun the helper guards against.
    #[test]
    #[tracing_test::traced_test]
    fn test_record_to_undeclared_field_is_silent_noop() {
        let span = tracing::info_span!("req"); // no fields declared
        let _e = span.enter();
        record_display(&span, "undeclared_key", "sentinel_value_xyz");
        tracing::info!("request handled");
        assert!(
            !logs_contain("sentinel_value_xyz"),
            "an undeclared field must be silently dropped"
        );
    }

    /// `record_debug` behaves identically to `record_display` for a `Debug` value.
    #[test]
    #[tracing_test::traced_test]
    fn test_record_debug_fills_declared_empty_field() {
        let span = tracing::info_span!("op", marker = tracing::field::Empty);
        let _e = span.enter();
        record_debug(&span, "marker", "dbg_sentinel_987");
        tracing::info!("done");
        assert!(logs_contain("dbg_sentinel_987"), "recorded debug value must appear on the event");
    }
}
