//! Audit logging utilities for rvc-signer.
//!
//! # Module layout
//!
//! - [`cn`]: mTLS client CN extraction (legacy DER scanner; swapped in M-4 / ISSUE-3.4)
//! - [`log`]: structured audit log emission with `TruncatedPubkey` hooks
//!
//! # Backward-compatibility re-exports
//!
//! The v1 service handler (`SignerService`) uses `audit::extract_client_cn`,
//! `audit::log_audit`, `audit::AuditEntry`, and `audit::now_rfc3339`.  These
//! are re-exported here so the v1 code compiles unchanged.

pub mod cn;
pub mod log;

// ── Backward-compat re-exports for the v1 handler ────────────────────────────

pub use cn::extract_client_cn;
pub use log::{log_audit, AuditEntry};

/// Return the current UTC timestamp as an ISO-8601 string.
///
/// Format: `YYYY-MM-DDTHH:MM:SSZ` (seconds precision, no sub-seconds).
///
/// This is a pure-std implementation that avoids adding `chrono` as a
/// dependency.  The implementation is moved from the legacy `audit.rs`.
pub fn now_rfc3339() -> String {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = duration.as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_now_rfc3339_format() {
        let ts = now_rfc3339();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-01 is day 19723 since epoch
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }
}
