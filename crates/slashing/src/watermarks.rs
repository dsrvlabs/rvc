//! Watermark kind + read/raise helpers for the slashing DB.
//!
//! The `watermarks` table is addressed by type string (`block`, `att_source`,
//! `att_target`). Magic string literals at call sites are a fail-open hazard
//! (a typo silently disables a check). [`WatermarkKind`] makes those strings
//! unrepresentable outside this module; [`read_watermark`] / [`raise_watermark`]
//! own the SELECT and the monotonic-raise UPSERT.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SlashingError;

/// Discriminant for a row in the `watermarks` table.
///
/// The SQL type column values live only in [`Self::as_sql_str`] so a typo in a
/// call site cannot silently disable a watermark check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatermarkKind {
    /// Block-proposal floor (`watermark_type = 'block'`).
    Block,
    /// Attestation source-epoch floor (`watermark_type = 'att_source'`).
    AttestationSource,
    /// Attestation target-epoch floor (`watermark_type = 'att_target'`).
    AttestationTarget,
}

impl WatermarkKind {
    /// SQL `watermark_type` column value. Sole definition of the three literals.
    pub const fn as_sql_str(self) -> &'static str {
        match self {
            // These three string literals are the only watermark type values in
            // the crate; every SQL site binds them via a parameter.
            Self::Block => "block",
            Self::AttestationSource => "att_source",
            Self::AttestationTarget => "att_target",
        }
    }

    /// All kinds, in a stable order for round-trip / exhaustiveness tests.
    pub const fn all() -> [Self; 3] {
        [Self::Block, Self::AttestationSource, Self::AttestationTarget]
    }
}

/// Read the watermark value for `(pubkey, kind)`, if present.
///
/// Returns the raw integer stored in the table (slot or epoch, depending on kind).
pub fn read_watermark(
    conn: &Connection,
    pubkey: &str,
    kind: WatermarkKind,
) -> Result<Option<u64>, SlashingError> {
    let result: Option<i64> = conn
        .query_row(
            "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = ?2",
            (pubkey, kind.as_sql_str()),
            |row| row.get(0),
        )
        .optional()?;
    Ok(result.map(|v| v as u64))
}

/// Raise a watermark monotonically.
///
/// - Missing row → INSERT.
/// - `value >= current` → UPDATE (same value is idempotent).
/// - `value < current` → [`SlashingError::WatermarkLowered`].
///
/// A watermark must never move backwards.
pub fn raise_watermark(
    conn: &Connection,
    pubkey: &str,
    kind: WatermarkKind,
    value: u64,
) -> Result<(), SlashingError> {
    let existing = read_watermark(conn, pubkey, kind)?;

    if let Some(current) = existing {
        if value < current {
            return Err(SlashingError::WatermarkLowered {
                pubkey: pubkey.to_string(),
                watermark_type: kind.as_sql_str().to_string(),
                current,
                attempted: value,
            });
        }
        conn.execute(
            "UPDATE watermarks SET value = ?1 WHERE pubkey = ?2 AND watermark_type = ?3",
            (value as i64, pubkey, kind.as_sql_str()),
        )?;
    } else {
        conn.execute(
            "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, ?2, ?3)",
            (pubkey, kind.as_sql_str(), value as i64),
        )?;
    }
    Ok(())
}

/// Raise a watermark with `MAX(existing, new)` semantics (silent no-op when lower).
///
/// Used by interchange import so re-importing older maxima never fails and never
/// lowers floors. Prefer [`raise_watermark`] for explicit set APIs that must
/// surface [`SlashingError::WatermarkLowered`].
pub(crate) fn raise_watermark_max(
    conn: &Connection,
    pubkey: &str,
    kind: WatermarkKind,
    value: u64,
) -> Result<(), SlashingError> {
    conn.execute(
        "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, ?2, ?3)
         ON CONFLICT(pubkey, watermark_type) DO UPDATE
         SET value = MAX(watermarks.value, excluded.value)",
        (pubkey, kind.as_sql_str(), value as i64),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SlashingDb;

    fn open() -> SlashingDb {
        SlashingDb::open_in_memory().expect("open_in_memory")
    }

    /// RED → GREEN: raise_watermark must reject a backwards move.
    #[test]
    fn test_raise_watermark_rejects_backwards_move() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";

        raise_watermark(&conn, pk, WatermarkKind::Block, 1000).expect("initial raise");
        let err = raise_watermark(&conn, pk, WatermarkKind::Block, 500)
            .expect_err("backwards move must fail");
        match err {
            SlashingError::WatermarkLowered {
                ref pubkey,
                ref watermark_type,
                current,
                attempted,
            } => {
                assert_eq!(pubkey, pk);
                assert_eq!(watermark_type, "block");
                assert_eq!(current, 1000);
                assert_eq!(attempted, 500);
            }
            other => panic!("expected WatermarkLowered, got {other:?}"),
        }
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::Block).unwrap(), Some(1000));
    }

    #[test]
    fn test_raise_watermark_same_value_is_idempotent() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";
        raise_watermark(&conn, pk, WatermarkKind::Block, 42).unwrap();
        raise_watermark(&conn, pk, WatermarkKind::Block, 42).unwrap();
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::Block).unwrap(), Some(42));
    }

    #[test]
    fn test_raise_watermark_can_raise() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";
        raise_watermark(&conn, pk, WatermarkKind::AttestationSource, 10).unwrap();
        raise_watermark(&conn, pk, WatermarkKind::AttestationSource, 20).unwrap();
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::AttestationSource).unwrap(), Some(20));
    }

    #[test]
    fn test_watermark_kind_round_trips_all_three_kinds() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xdead";

        for (i, kind) in WatermarkKind::all().into_iter().enumerate() {
            let value = (i as u64 + 1) * 100;
            raise_watermark(&conn, pk, kind, value).unwrap();
            assert_eq!(read_watermark(&conn, pk, kind).unwrap(), Some(value));
            assert!(!kind.as_sql_str().is_empty());
        }

        assert_eq!(read_watermark(&conn, "0xother", WatermarkKind::Block).unwrap(), None);
    }

    #[test]
    fn test_raise_watermark_max_is_silent_on_lower() {
        let db = open();
        let conn = db.conn.lock();
        let pk = "0xabc";
        raise_watermark_max(&conn, pk, WatermarkKind::Block, 9000).unwrap();
        raise_watermark_max(&conn, pk, WatermarkKind::Block, 100).unwrap();
        assert_eq!(read_watermark(&conn, pk, WatermarkKind::Block).unwrap(), Some(9000));
    }

    /// Grep-style guard: no raw SQL type literals of the form
    /// `watermark_type = '<value>'` remain outside doc comments.
    #[test]
    fn test_no_raw_watermark_type_literals_remain() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src_dir = std::path::Path::new(manifest_dir).join("src");
        // Build the needle without embedding the full forbidden pattern as a
        // contiguous string in this file (so this test does not flag itself).
        let needle = format!("watermark_type = {}", "'");
        let mut offenders = Vec::new();

        for path in walkdir_rs(&src_dir) {
            let text = std::fs::read_to_string(&path).expect("read source");
            for (idx, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                // Doc/comment lines may mention the SQL form for documentation.
                if trimmed.starts_with("//")
                    || trimmed.starts_with("///")
                    || trimmed.starts_with("//!")
                {
                    continue;
                }
                if line.contains(&needle) {
                    offenders.push(format!("{}:{}: {line}", path.display(), idx + 1));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "raw watermark type SQL literals must not remain in code; found:\n{}",
            offenders.join("\n")
        );
    }

    fn walkdir_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).expect("read_dir") {
                let entry = entry.expect("entry");
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        out
    }
}
