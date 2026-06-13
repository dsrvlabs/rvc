//! SQLite database layer for slashing protection.
//!
//! # Schema versions
//!
//! ## v1 (legacy)
//! Tables: `attestations`, `blocks`, `metadata`, `watermarks`.
//! Uniqueness: `(pubkey, target_epoch)` / `(pubkey, slot)`.
//!
//! ## v2 (current — ISSUE-1.2)
//! Added columns on `attestations` and `blocks`:
//! - `client_cn TEXT NOT NULL DEFAULT '__legacy__'` — per-client-CN namespace.
//!   Sentinel values: `'__legacy__'` for pre-migration rows; `'local-vc'` for VC-side
//!   runtime writes (`crates/signer`). DVT peers use their mTLS CN (ISSUE-1.7).
//! - `genesis_validators_root TEXT` — nullable; legacy rows = NULL.
//!
//! New uniqueness indexes: `(client_cn, pubkey, target_epoch)` / `(client_cn, pubkey, slot)`.
//! `metadata.schema_version = '2'` is set on every v2 open.
//!
//! Migration runs eagerly on `SlashingDb::open` and is idempotent.
//! A backup `<path>.bak.<UNIX_TS>` is written before any ALTER fires.

use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::error::{AttestationSlashingViolation, BlockSlashingViolation, SlashingError};
use crate::migration;
use crate::types::{
    InterchangeAttestation, InterchangeBlock, InterchangeFormat, InterchangeMetadata, PruneStats,
    SignedAttestation, SignedBlock, ValidatorRecord,
};
use crypto::logging::TruncatedPubkey;
use eth_types::{Epoch, Root, Slot};
use metrics::definitions as metrics;

/// Normalize a pubkey to lowercase with 0x prefix for consistent DB storage/lookup.
///
/// Delegates to [`crypto::pubkey::CanonicalPubkey`] — the single source of
/// truth for pubkey normalisation across all crates (CQ-2.4 / C1).
pub(crate) fn normalize_pubkey(pubkey: &str) -> String {
    pubkey.parse::<crypto::pubkey::CanonicalPubkey>().expect("infallible").to_string()
}

/// SQLite-backed database for storing slashing protection data.
pub struct SlashingDb {
    pub(crate) conn: Mutex<Connection>,
    path: Option<PathBuf>,
    pub(crate) strict_semantics: AtomicBool,
    /// One-time cache for `metadata.genesis_validators_root`.
    ///
    /// `None` means "no GVR pinned in metadata" (backward-compat: skip the per-call check).
    /// `Some(root)` means the pinned value has been loaded and every caller-supplied `gvr`
    /// will be compared against it.
    ///
    /// Populated only once a real `Root` is read from the metadata row.  Absence (no row
    /// pinned yet) is **not** cached — otherwise an early signing call could permanently
    /// disable the chain-swap check for a process whose GVR is pinned later (e.g. when
    /// `import()` opens the DB before startup pins the GVR).  Reset never happens within a
    /// process lifetime
    /// because the metadata GVR is immutable once set.  A race between two threads both
    /// writing to the `OnceLock` is harmless: both writers compute the same value (they both
    /// read the same DB row), and `OnceLock::set` silently discards the losing write.
    gvr_cache: OnceLock<Root>,
    /// Logged-once flag: emit an `error!` warning the first time a signing-path entry
    /// observes "no GVR pinned in metadata" so operators can detect a degraded
    /// chain-swap-protection state.
    gvr_skip_warned: OnceLock<()>,
}

impl SlashingDb {
    /// Open a database at the specified path.
    ///
    /// Creates the file and runs schema migrations if it doesn't exist or is at v1.
    /// Schema v2 migration runs **eagerly** and is idempotent (re-opening a v2 DB is a no-op).
    /// A backup `<path>.bak.<UNIX_TS>` is written before any ALTER fires.
    ///
    /// # Errors
    /// Returns `SlashingError::MigrationFailed` if the backup or migration fails.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SlashingError> {
        let path = path.as_ref();
        let conn = Connection::open(path)?;

        Self::configure_pragmas(&conn)?;

        // Set restrictive file permissions (owner-only read/write) on the
        // main DB file before any data is written.
        #[cfg(unix)]
        Self::chmod_main_file(path)?;

        let db = Self {
            conn: Mutex::new(conn),
            path: Some(path.to_path_buf()),
            strict_semantics: AtomicBool::new(false),
            gvr_cache: OnceLock::new(),
            gvr_skip_warned: OnceLock::new(),
        };

        // `migrate()` creates tables if they don't exist (v2-native CREATE TABLE).
        // Then `migrate_to_v2` checks if the existing schema is v1 and upgrades.
        // For a brand-new DB, `migrate()` creates v2 tables and `migrate_to_v2` will
        // set schema_version=2 without needing a backup (tables are fresh/empty).
        // Finally `migrate_to_v3` re-keys indices from CN-scoped to pubkey-scoped.
        db.migrate()?;
        db.migrate_to_v2(path)?;
        db.migrate_to_v3()?;

        // ISSUE-4.8 / L-8: chmod 0o600 on `<path>-wal` / `<path>-shm` sidecars.
        //
        // SQLite materialises the -shm when WAL mode is engaged and the -wal
        // when the first write transaction commits.  Both `migrate()` and
        // `migrate_to_v2` perform write transactions, so by this point the
        // sidecars exist.  Without this chmod they inherit the process umask
        // (typically 0o022), making them group/world-readable — an attacker
        // with read-only host access could exfiltrate the slashing journal,
        // defeating the 0o600 protection on the main file.
        //
        // SQLite WAL filenames use `-wal` / `-shm` suffixes (no separator dot)
        // — see https://www.sqlite.org/wal.html § "Activating and Configuring
        // WAL Mode".  This chmod is best-effort: missing sidecars (e.g. on
        // a pre-WAL fallback) and chmod errors are warn-logged, not fatal.
        #[cfg(unix)]
        Self::chmod_sidecars(path);

        tracing::info!(path = %path.display(), "slashing protection database opened");
        Ok(db)
    }

    /// Set 0o600 on the main slashing-DB file (Unix only). Failure is a
    /// fatal `SlashingError::UnsafePermissions` — the protection contract
    /// for the main journal must hold or startup aborts.
    #[cfg(unix)]
    fn chmod_main_file(path: &Path) -> Result<(), SlashingError> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| SlashingError::UnsafePermissions {
            path: path.display().to_string(),
            mode: format!("failed to set permissions: {}", e),
        })
    }

    /// Set 0o600 on the SQLite WAL/SHM sidecars (Unix only;
    /// ISSUE-4.8 / L-8).
    ///
    /// Best-effort: sidecars may not yet exist when this is called (e.g. on
    /// a pre-WAL fallback opened with `RVC_ALLOW_NON_WAL_SLASHING_DB=true`),
    /// and on some filesystems chmod is a no-op or unsupported. Missing
    /// sidecars are skipped silently; chmod errors are `warn!`-logged so
    /// operators can investigate without blocking startup.
    #[cfg(unix)]
    fn chmod_sidecars(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        for suffix in &["-wal", "-shm"] {
            let sidecar = parent.join(format!("{}{}", stem, suffix));
            if !sidecar.exists() {
                continue;
            }
            if let Err(e) = std::fs::set_permissions(&sidecar, perms.clone()) {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %e,
                    "failed to chmod 0o600 on slashing-db sidecar (ISSUE-4.8 / L-8); \
                     continuing — sidecar may be group/world-readable"
                );
            }
        }
    }

    /// Apply durability pragmas to an open SQLite connection.
    ///
    /// Pragma sequence (per architecture A4 §"Internal data flow"):
    /// 1. `journal_mode=wal` — attempt WAL. If the result is not "wal", check
    ///    `RVC_ALLOW_NON_WAL_SLASHING_DB`. Absent/false → fatal error. True → loud
    ///    `error!` log and continue (durability degraded).
    /// 2. `synchronous=EXTRA` — FULL + dir-fsync; belt-and-braces in case anything
    ///    ever falls through to DELETE journal mode.
    /// 3. `fullfsync=ON` (macOS only) — force F_FULLFSYNC so device caches are
    ///    flushed; macOS's `fsync(2)` does not guarantee this without F_FULLFSYNC.
    fn configure_pragmas(conn: &Connection) -> Result<(), SlashingError> {
        // --- 1. WAL mode ---
        let journal_mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            const HINT: &str = "Set RVC_ALLOW_NON_WAL_SLASHING_DB=true to override \
                (durability degraded), or move the DB to a WAL-capable filesystem \
                (avoid tmpfs / NFSv3 / SMB).";
            let allow = std::env::var("RVC_ALLOW_NON_WAL_SLASHING_DB")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow {
                return Err(SlashingError::JournalMode {
                    actual: journal_mode,
                    hint: HINT.to_owned(),
                });
            }
            tracing::error!(
                actual_mode = %journal_mode,
                "running without WAL — slashing protection durability degraded"
            );
        }

        // --- 2. synchronous=EXTRA ---
        conn.pragma_update(None, "synchronous", "EXTRA")?;

        // --- 3. fullfsync=ON (macOS only) ---
        #[cfg(target_os = "macos")]
        conn.pragma_update(None, "fullfsync", "ON")?;

        Ok(())
    }

    /// Open a database with a pre-configured connection.
    ///
    /// # Purpose
    /// Allows integration tests (and any code with access to a `Connection`) to inject
    /// a connection whose journal mode has been forced to a non-WAL value (e.g. an
    /// in-memory DB where WAL returns `"memory"`) in order to exercise the WAL hard-fail
    /// and env-var opt-out code paths.
    ///
    /// Runs `configure_pragmas` and the schema migration, but skips file-permission
    /// checks because the connection may not be backed by a file.
    ///
    /// # Note
    /// This is a test helper. Do not use it in production paths; prefer `open` or
    /// `open_in_memory` instead.
    #[doc(hidden)]
    pub fn open_with_conn_for_testing(conn: Connection) -> Result<Self, SlashingError> {
        Self::configure_pragmas(&conn)?;
        let db = Self {
            conn: Mutex::new(conn),
            path: None,
            strict_semantics: AtomicBool::new(false),
            gvr_cache: OnceLock::new(),
            gvr_skip_warned: OnceLock::new(),
        };
        db.migrate()?;
        {
            let mut conn = db.conn.lock();
            Self::run_v2_migration_transaction(&mut conn)
                .map_err(|e| SlashingError::MigrationFailed(format!("{e}")))?;
        }
        db.migrate_to_v3()?;
        Ok(db)
    }

    /// Open an in-memory database for testing.
    ///
    /// Creates the full v3 schema directly (no backup needed — there is no file).
    pub fn open_in_memory() -> Result<Self, SlashingError> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Mutex::new(conn),
            path: None,
            strict_semantics: AtomicBool::new(false),
            gvr_cache: OnceLock::new(),
            gvr_skip_warned: OnceLock::new(),
        };
        // Create tables (v2-native layout).
        db.migrate()?;
        // Set schema_version = 2 (CN-keyed indices are created transiently here
        // and immediately replaced by migrate_to_v3 below).
        // No backup is taken for in-memory DBs.
        {
            let mut conn = db.conn.lock();
            Self::run_v2_migration_transaction(&mut conn)
                .map_err(|e| SlashingError::MigrationFailed(format!("{e}")))?;
        }
        // Migrate to v3: replace CN-keyed indices with pubkey+gvr-scoped indices.
        db.migrate_to_v3()?;
        Ok(db)
    }

    /// Enable or disable strict slashing semantics.
    ///
    /// When enabled, `None == None` signing roots at the same target epoch
    /// (or slot for blocks) are rejected as potential double votes/proposals.
    /// Default is `false` (lenient: treats `None == None` as a re-sign).
    pub fn set_strict_semantics(&self, strict: bool) {
        self.strict_semantics.store(strict, Ordering::Relaxed);
    }

    // ── GVR per-call re-check helpers (M-6 / ISSUE-3.5) ─────────────────────

    /// Encode a `Root` ([u8; 32]) as a lowercase `0x`-prefixed hex string for DB storage.
    pub(crate) fn root_to_hex(root: &Root) -> String {
        format!("0x{}", hex::encode(root))
    }

    /// Parse a hex string (with or without `0x` prefix) into a `Root`.
    ///
    /// Returns `SlashingError::InvalidInterchangeFormat` if the string is not
    /// valid hex or not exactly 32 bytes.
    fn parse_gvr_hex(s: &str) -> Result<Root, SlashingError> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(stripped).map_err(|e| {
            SlashingError::InvalidInterchangeFormat(format!(
                "genesis_validators_root is not valid hex: {e}"
            ))
        })?;
        let root: Root = bytes.try_into().map_err(|_| {
            SlashingError::InvalidInterchangeFormat(
                "genesis_validators_root must be exactly 32 bytes".to_string(),
            )
        })?;
        // All-zeros is the builder-registration sentinel and never a real chain
        // identifier. Reject it to catch operator misconfiguration.
        if root == [0u8; 32] {
            return Err(SlashingError::InvalidInterchangeFormat(
                "genesis_validators_root must not be all zeros".to_string(),
            ));
        }
        Ok(root)
    }

    /// Read `metadata.genesis_validators_root` from the DB (acquires the mutex).
    ///
    /// Returns `Ok(None)` if no row is present (backward compat: skip the check).
    /// Returns `Ok(Some(root))` if the row is present and parseable.
    fn read_metadata_gvr(&self) -> Result<Option<Root>, SlashingError> {
        let conn = self.conn.lock();
        let hex_str: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'genesis_validators_root'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match hex_str {
            None => Ok(None),
            Some(s) => Ok(Some(Self::parse_gvr_hex(&s)?)),
        }
    }

    /// Return the metadata-pinned GVR, using the cache to avoid repeated DB reads.
    ///
    /// On the first call, reads from `metadata.genesis_validators_root` and populates
    /// the `gvr_cache`.  Subsequent calls return the cached value directly.
    ///
    /// Returns `Ok(None)` if no GVR is set in metadata (backward compat: the per-call
    /// check is skipped).  Returns `Ok(Some(root))` once GVR is pinned.
    ///
    /// Race safety: if two threads call this simultaneously on a cold cache, both read
    /// the same DB row and compute the same value.  `OnceLock::set` silently discards
    /// the losing write — both outcomes are identical.
    pub(crate) fn pinned_gvr(&self) -> Result<Option<Root>, SlashingError> {
        if let Some(cached) = self.gvr_cache.get() {
            return Ok(Some(*cached));
        }
        match self.read_metadata_gvr()? {
            Some(root) => {
                // Race-OK: if another thread wins the set, both wrote the same value.
                let _ = self.gvr_cache.set(root);
                Ok(Some(root))
            }
            None => {
                // Do NOT cache absence — the GVR may be pinned later (e.g. by
                // startup after an import() flow opened the DB).  Caching None
                // would permanently disable the chain-swap check.
                if self.gvr_skip_warned.set(()).is_ok() {
                    tracing::error!(
                        "genesis_validators_root not pinned in metadata; per-call \
                         chain-swap protection is disabled until set_genesis_validators_root \
                         is called.  This warning is emitted once per SlashingDb instance."
                    );
                }
                Ok(None)
            }
        }
    }

    /// Create the initial database schema.
    ///
    /// For a **brand-new** database, creates v2 tables directly (with `client_cn` and
    /// `genesis_validators_root` columns and CN-scoped unique indexes). For an existing v1
    /// database, the v1 tables already exist (the CREATE TABLE IF NOT EXISTS is a no-op for
    /// the old-style columns) and `migrate_to_v2` handles the upgrade.
    ///
    /// We use a v2-native CREATE TABLE so that fresh DBs start at v2 without going through
    /// the ALTER TABLE path. The inline `UNIQUE` constraints from v1 are absent here; the
    /// CN-scoped unique indexes are created by `run_v2_migration_transaction`.
    fn migrate(&self) -> Result<(), SlashingError> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS attestations (
                id INTEGER PRIMARY KEY,
                client_cn TEXT NOT NULL DEFAULT '__legacy__',
                pubkey TEXT NOT NULL,
                source_epoch INTEGER NOT NULL,
                target_epoch INTEGER NOT NULL,
                signing_root TEXT,
                genesis_validators_root TEXT
            );

            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY,
                client_cn TEXT NOT NULL DEFAULT '__legacy__',
                pubkey TEXT NOT NULL,
                slot INTEGER NOT NULL,
                signing_root TEXT,
                genesis_validators_root TEXT
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS watermarks (
                pubkey TEXT NOT NULL,
                watermark_type TEXT NOT NULL,
                value INTEGER NOT NULL,
                UNIQUE(pubkey, watermark_type)
            );
            ",
        )?;
        Ok(())
    }

    /// Read the `schema_version` integer from the `metadata` table.
    ///
    /// Returns `None` if the row is absent (database predates ISSUE-1.2 — treat as v1).
    fn read_schema_version(conn: &Connection) -> Result<Option<i64>, SlashingError> {
        let v: Option<String> = conn
            .query_row("SELECT value FROM metadata WHERE key = 'schema_version'", [], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(v.and_then(|s| s.parse().ok()))
    }

    /// Check whether a column exists in a table using `PRAGMA table_info`.
    ///
    /// Used for idempotent ALTER TABLE: SQLite 3.35 added `ADD COLUMN IF NOT EXISTS`,
    /// but we guard with a pragma check for maximum portability.
    fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, SlashingError> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let exists = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .any(|r| r.map(|name| name == column).unwrap_or(false));
        Ok(exists)
    }

    /// Create an atomic backup of the database file to `<path>.bak.<UNIX_TS>`.
    ///
    /// # Approach
    /// 1. Issue `PRAGMA wal_checkpoint(TRUNCATE)` to flush WAL into the main DB file
    ///    so the backup contains a clean, self-contained snapshot.
    /// 2. Copy `path` to `<path>.bak.<ts>` via a temp file in the same directory
    ///    (atomic on POSIX: write to temp, `sync_all`, rename).
    /// 3. Return the backup path on success.
    ///
    /// The WAL / SHM sidecar files are **not** separately copied: after a full WAL
    /// checkpoint the main file is self-consistent and the sidecars are empty/reset.
    /// Operators who want a byte-for-byte sidecar copy can use `sqlite3 .backup` instead.
    ///
    /// # Errors
    /// Returns `SlashingError::MigrationFailed` if the backup cannot be created.
    ///
    /// # Symlink note
    /// The backup destination uses a UNIX-timestamp suffix that is predictable
    /// to the second. A local attacker who can write to the parent directory
    /// could pre-create that path as a symlink. The temp-then-rename pattern
    /// limits the impact (the main DB file is never truncated), but a future
    /// hardening pass could open with `O_NOFOLLOW`.
    pub(crate) fn backup_before_migrate(
        conn: &Connection,
        path: &Path,
    ) -> Result<PathBuf, SlashingError> {
        // Checkpoint the WAL so the main file is self-consistent.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| SlashingError::MigrationFailed("DB path has no file name".into()))?;

        let parent = path
            .parent()
            .ok_or_else(|| SlashingError::MigrationFailed("DB path has no parent dir".into()))?;

        let backup_name = format!("{file_name}.bak.{ts}");
        let backup_path = parent.join(&backup_name);

        // Write to a temp file first, then rename (atomic on POSIX). The temp
        // name embeds the same UNIX_TS as the final backup so concurrent
        // migrations on different DB files in the same parent dir cannot
        // collide on the temp path.
        let tmp_name = format!("{file_name}.bak.{ts}.tmp");
        let tmp_path = parent.join(&tmp_name);

        std::fs::copy(path, &tmp_path).map_err(|e| {
            SlashingError::MigrationFailed(format!("failed to copy DB to temp file: {e}"))
        })?;

        // Match the main DB file's 0o600 mode so the backup is not
        // world-readable on hosts with a permissive umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    SlashingError::MigrationFailed(format!(
                        "failed to set 0o600 on backup file: {e}"
                    ))
                },
            )?;
        }

        {
            let f = std::fs::OpenOptions::new().write(true).open(&tmp_path).map_err(|e| {
                SlashingError::MigrationFailed(format!("failed to open temp backup for sync: {e}"))
            })?;
            f.sync_all().map_err(|e| {
                SlashingError::MigrationFailed(format!("sync_all on backup failed: {e}"))
            })?;
        }

        std::fs::rename(&tmp_path, &backup_path).map_err(|e| {
            // Clean up temp file on rename failure.
            let _ = std::fs::remove_file(&tmp_path);
            SlashingError::MigrationFailed(format!("failed to rename backup file: {e}"))
        })?;

        tracing::info!(
            backup = %backup_path.display(),
            "slashing DB backup created before schema migration"
        );
        Ok(backup_path)
    }

    /// Migrate the database to schema v2 if it is currently at v1.
    ///
    /// # Decision logic
    /// - `schema_version >= 2`: no-op (already at v2+).
    /// - `schema_version` absent AND `client_cn` column already exists on `attestations`:
    ///   the DB was just created by `migrate()` with the v2-native CREATE TABLE — set
    ///   `schema_version=2` without backing up (no v1 rows to preserve).
    /// - `schema_version` absent AND `client_cn` column **missing**: existing populated v1
    ///   DB — take a backup, run ALTER TABLE batch, set `schema_version=2`.
    ///
    /// Migration order for the v1→v2 path:
    /// 1. Read `schema_version`. If absent, check for `client_cn` column.
    /// 2. Backup `<path>.bak.<UNIX_TS>` (atomic copy + sync_all).
    /// 3. Begin immediate transaction.
    /// 4. Idempotent ALTER TABLE batch (guarded by `PRAGMA table_info`).
    /// 5. Drop old indexes; create CN-scoped ones.
    /// 6. UPSERT `schema_version=2`.
    /// 7. Commit. Any failure → `Err(SlashingError::MigrationFailed)`.
    fn migrate_to_v2(&self, path: &Path) -> Result<(), SlashingError> {
        let (schema_version, has_client_cn) = {
            let conn = self.conn.lock();
            let sv = Self::read_schema_version(&conn)?;
            let has_cn = Self::column_exists(&conn, "attestations", "client_cn")?;
            (sv, has_cn)
        };

        if schema_version.unwrap_or(0) >= 2 {
            // Already at v2 or newer; no migration needed.
            return Ok(());
        }

        if has_client_cn {
            // Fresh DB created by migrate() with v2-native CREATE TABLE.
            // Just set schema_version=2 — no backup needed (no v1 rows to preserve).
            let conn = self.conn.lock();
            conn.execute_batch(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '2')",
            )?;
            tracing::debug!(path = %path.display(), "fresh v2 DB: set schema_version=2");
            return Ok(());
        }

        // Existing v1 DB: take a backup, then migrate.
        {
            let conn = self.conn.lock();
            Self::backup_before_migrate(&conn, path)
                .map_err(|e| SlashingError::MigrationFailed(format!("backup failed: {e}")))?;
        }

        // Run migration in a single immediate transaction.
        let result = {
            let mut conn = self.conn.lock();
            Self::run_v2_migration_transaction(&mut conn)
        };

        result.map_err(|e| {
            tracing::error!(error = %e, "schema v2 migration failed; original DB is intact in backup");
            match e {
                SlashingError::MigrationFailed(_) => e,
                other => SlashingError::MigrationFailed(format!("{other}")),
            }
        })?;

        tracing::info!(path = %path.display(), "schema migrated to v2");
        Ok(())
    }

    /// Migrate the database to schema v3 (pubkey-scoped slashing indices).
    ///
    /// Gate: `schema_version >= 3` → no-op (idempotent).
    ///
    /// Delegates to [`migration::migrate_to_v3`] which runs all steps in a
    /// single `IMMEDIATE` transaction.  A failure rolls back completely so the
    /// DB remains at v2 with CN-scoped indices (degraded but safe).
    fn migrate_to_v3(&self) -> Result<(), SlashingError> {
        let mut conn = self.conn.lock();
        migration::migrate_to_v3(&mut conn).map_err(|e| {
            tracing::error!(
                error = %e,
                "schema v3 migration failed; database remains at v2 with CN-scoped indices"
            );
            e
        })
    }

    fn run_v2_migration_transaction(conn: &mut Connection) -> Result<(), SlashingError> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Add `client_cn` column to `attestations` if missing.
        if !Self::column_exists(&tx, "attestations", "client_cn")? {
            tx.execute_batch(
                "ALTER TABLE attestations ADD COLUMN client_cn TEXT NOT NULL DEFAULT '__legacy__'",
            )?;
        }

        // Add `genesis_validators_root` column to `attestations` if missing.
        if !Self::column_exists(&tx, "attestations", "genesis_validators_root")? {
            tx.execute_batch("ALTER TABLE attestations ADD COLUMN genesis_validators_root TEXT")?;
        }

        // Add `client_cn` column to `blocks` if missing.
        if !Self::column_exists(&tx, "blocks", "client_cn")? {
            tx.execute_batch(
                "ALTER TABLE blocks ADD COLUMN client_cn TEXT NOT NULL DEFAULT '__legacy__'",
            )?;
        }

        // Add `genesis_validators_root` column to `blocks` if missing.
        if !Self::column_exists(&tx, "blocks", "genesis_validators_root")? {
            tx.execute_batch("ALTER TABLE blocks ADD COLUMN genesis_validators_root TEXT")?;
        }

        // Drop old uniqueness indexes and create new CN-scoped ones.
        // `DROP INDEX IF EXISTS` is always safe.
        tx.execute_batch(
            "
            DROP INDEX IF EXISTS idx_attestations_pubkey_target;
            DROP INDEX IF EXISTS idx_blocks_pubkey_slot;

            CREATE UNIQUE INDEX IF NOT EXISTS idx_attestations_cn_pubkey_target
                ON attestations(client_cn, pubkey, target_epoch);

            CREATE UNIQUE INDEX IF NOT EXISTS idx_blocks_cn_pubkey_slot
                ON blocks(client_cn, pubkey, slot);
            ",
        )?;

        // Upsert schema_version = 2.
        tx.execute_batch(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', '2')",
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Insert a signed attestation record (test helper).
    ///
    /// Every row must carry a non-NULL `genesis_validators_root` so that the v3
    /// unique index `(pubkey, genesis_validators_root, target_epoch)` can enforce
    /// per-pubkey uniqueness.  SQLite treats NULL as DISTINCT from all values,
    /// including other NULLs, so a NULL gvr would silently bypass the index.
    #[cfg(test)]
    pub(crate) fn insert_attestation(
        &self,
        attestation: &SignedAttestation,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(&attestation.pubkey);
        let gvr_hex = Self::root_to_hex(gvr);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO attestations \
             (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
             VALUES ('local-vc', ?1, ?2, ?3, ?4, ?5)",
            (
                &pubkey,
                attestation.source_epoch as i64,
                attestation.target_epoch as i64,
                &attestation.signing_root,
                &gvr_hex,
            ),
        )?;
        Ok(())
    }

    /// Record a signed attestation with idempotent behavior.
    ///
    /// If an attestation with the same pubkey and target_epoch already exists,
    /// the operation silently succeeds without modifying the existing record.
    /// This makes the operation safe to retry.
    ///
    /// Every row carries a non-NULL `genesis_validators_root`.  The v3 unique index
    /// `(pubkey, genesis_validators_root, target_epoch)` only fires for non-NULL gvr
    /// values — SQLite treats NULL as DISTINCT, so a NULL gvr would bypass the
    /// index entirely.  Callers must supply the chain's pinned GVR.
    ///
    /// Idempotency is checked by `(pubkey, target_epoch)` — this is safe because the
    /// DB is single-chain: every row for a given pubkey has the same gvr.
    pub fn record_attestation(
        &self,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let gvr_hex = Self::root_to_hex(gvr);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO attestations \
             (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
             SELECT 'local-vc', ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (
                 SELECT 1 FROM attestations WHERE pubkey = ?1 AND target_epoch = ?3
             )",
            (&pubkey, source_epoch as i64, target_epoch as i64, &signing_root, &gvr_hex),
        )?;
        Ok(())
    }

    /// Get all attestations for a given public key.
    pub fn get_attestations(&self, pubkey: &str) -> Result<Vec<SignedAttestation>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();
        Self::read_attestations(&conn, &pubkey)
    }

    /// Read attestations for `pubkey` using a caller-held `Connection`.
    ///
    /// Private helper used by `export` to run all reads under a single held
    /// lock (KM-1/ADR-008 consistent-snapshot guarantee).  The public
    /// `get_attestations` is a thin wrapper that acquires the lock itself.
    fn read_attestations(
        conn: &Connection,
        pubkey: &str,
    ) -> Result<Vec<SignedAttestation>, SlashingError> {
        let mut stmt = conn.prepare(
            "SELECT pubkey, source_epoch, target_epoch, signing_root
             FROM attestations
             WHERE pubkey = ?1
             ORDER BY target_epoch ASC",
        )?;

        let rows = stmt.query_map([pubkey], |row| {
            Ok(SignedAttestation {
                pubkey: row.get(0)?,
                source_epoch: row.get::<_, i64>(1)? as Epoch,
                target_epoch: row.get::<_, i64>(2)? as Epoch,
                signing_root: row.get(3)?,
            })
        })?;

        let mut attestations = Vec::new();
        for row in rows {
            attestations.push(row?);
        }
        Ok(attestations)
    }

    /// Insert a signed block record (test helper).
    ///
    /// Every row must carry a non-NULL `genesis_validators_root` so that the v3
    /// unique index `(pubkey, genesis_validators_root, slot)` can enforce uniqueness.
    /// SQLite treats NULL as DISTINCT from all values including other NULLs, so a
    /// NULL gvr would silently bypass the index.
    #[cfg(test)]
    pub(crate) fn insert_block(
        &self,
        block: &SignedBlock,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(&block.pubkey);
        let gvr_hex = Self::root_to_hex(gvr);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             VALUES ('local-vc', ?1, ?2, ?3, ?4)",
            (&pubkey, block.slot as i64, &block.signing_root, &gvr_hex),
        )?;
        Ok(())
    }

    /// Get all blocks for a given public key.
    pub fn get_blocks(&self, pubkey: &str) -> Result<Vec<SignedBlock>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();
        Self::read_blocks(&conn, &pubkey)
    }

    /// Read blocks for `pubkey` using a caller-held `Connection`.
    ///
    /// Private helper used by `export` to run all reads under a single held
    /// lock (KM-1/ADR-008 consistent-snapshot guarantee).  The public
    /// `get_blocks` is a thin wrapper that acquires the lock itself.
    fn read_blocks(conn: &Connection, pubkey: &str) -> Result<Vec<SignedBlock>, SlashingError> {
        let mut stmt = conn.prepare(
            "SELECT pubkey, slot, signing_root
             FROM blocks
             WHERE pubkey = ?1
             ORDER BY slot ASC",
        )?;

        let rows = stmt.query_map([pubkey], |row| {
            Ok(SignedBlock {
                pubkey: row.get(0)?,
                slot: row.get::<_, i64>(1)? as u64,
                signing_root: row.get(2)?,
            })
        })?;

        let mut blocks = Vec::new();
        for row in rows {
            blocks.push(row?);
        }
        Ok(blocks)
    }

    /// Check if it is safe to sign an attestation with the given epochs.
    ///
    /// Returns `Ok(())` if safe, or `Err(SlashingError::SlashableAttestation(_))`
    /// with details about the violation type.
    ///
    /// Per EIP-3076, the following conditions are checked:
    /// - Double voting: signing two attestations for the same target epoch
    /// - Surrounding vote: new attestation surrounds an existing one
    /// - Surrounded vote: new attestation is surrounded by an existing one
    pub fn is_safe_to_sign(
        &self,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();

        // Check attestation watermarks (both source and target)
        let wm_source: Option<i64> = conn
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_source'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(ws) = wm_source {
            if (source_epoch as i64) < ws {
                return Err(SlashingError::BelowAttestationSourceWatermark {
                    source_epoch,
                    watermark_source: ws as Epoch,
                });
            }
        }

        let wm_target: Option<i64> = conn
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_target'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(wt) = wm_target {
            if (target_epoch as i64) < wt {
                return Err(SlashingError::BelowAttestationWatermark {
                    target_epoch,
                    watermark_target: wt as Epoch,
                });
            }
        }

        let mut stmt = conn.prepare(
            "SELECT source_epoch, target_epoch
             FROM attestations
             WHERE pubkey = ?1",
        )?;

        let rows = stmt.query_map([&pubkey], |row| {
            Ok((row.get::<_, i64>(0)? as Epoch, row.get::<_, i64>(1)? as Epoch))
        })?;

        let mut min_target: Option<Epoch> = None;

        for row in rows {
            let (existing_source, existing_target) = row?;

            min_target = Some(min_target.map_or(existing_target, |m| m.min(existing_target)));

            // Check for double voting (same target epoch)
            if target_epoch == existing_target {
                return Err(AttestationSlashingViolation::DoubleVote { target_epoch }.into());
            }

            // Check for surrounding vote: new attestation surrounds existing
            // new_source < existing_source AND new_target > existing_target
            if source_epoch < existing_source && target_epoch > existing_target {
                return Err(AttestationSlashingViolation::SurroundingVote {
                    new_source: source_epoch,
                    new_target: target_epoch,
                    existing_source,
                    existing_target,
                }
                .into());
            }

            // Check for surrounded vote: new attestation is surrounded by existing
            // existing_source < new_source AND existing_target > new_target
            if existing_source < source_epoch && existing_target > target_epoch {
                return Err(AttestationSlashingViolation::SurroundedVote {
                    new_source: source_epoch,
                    new_target: target_epoch,
                    existing_source,
                    existing_target,
                }
                .into());
            }
        }

        // Check target epoch is not below minimum existing target
        if let Some(min) = min_target {
            if target_epoch < min {
                return Err(AttestationSlashingViolation::TargetEpochBelowMinimum {
                    target_epoch,
                    min_target: min,
                }
                .into());
            }
        }

        Ok(())
    }

    /// Read all distinct pubkeys from the DB using a caller-held `Connection`.
    ///
    /// Private helper for `export` so the full export runs under one lock.
    fn read_all_pubkeys(conn: &Connection) -> Result<Vec<String>, SlashingError> {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT pubkey FROM attestations
             UNION
             SELECT DISTINCT pubkey FROM blocks",
        )?;

        let rows = stmt.query_map([], |row| row.get(0))?;

        let mut pubkeys = Vec::new();
        for row in rows {
            pubkeys.push(row?);
        }
        Ok(pubkeys)
    }

    /// Export all slashing-protection records as an EIP-3076 interchange.
    ///
    /// # Consistent-snapshot guarantee (KM-1/ADR-008)
    ///
    /// The lock on `self.conn` is acquired ONCE and held for the entire
    /// duration of the export — `read_all_pubkeys`, `read_attestations`, and
    /// `read_blocks` all operate on the already-borrowed `&Connection`.
    /// Because `parking_lot::Mutex` is NOT reentrant, calling the public
    /// `get_all_pubkeys`/`get_attestations`/`get_blocks` methods from here
    /// would deadlock; the private `read_*` helpers avoid re-locking.
    ///
    /// Holding a single lock = no concurrent `record_attestation` or
    /// `record_block` write can interleave between the pubkey scan and the
    /// per-pubkey row reads, so the exported interchange is an atomic,
    /// consistent snapshot of the DB at the moment of the call.
    #[tracing::instrument(name = "rvc.slashing.db.export", skip_all)]
    pub fn export(
        &self,
        genesis_validators_root: &str,
    ) -> Result<InterchangeFormat, SlashingError> {
        // KM-1/ADR-008: single held lock = consistent snapshot; no interleaved writes.
        let conn = self.conn.lock();

        let pubkeys = Self::read_all_pubkeys(&conn)?;

        let mut data = Vec::new();
        for pubkey in pubkeys {
            let attestations = Self::read_attestations(&conn, &pubkey)?;
            let blocks = Self::read_blocks(&conn, &pubkey)?;

            let signed_attestations: Vec<InterchangeAttestation> = attestations
                .into_iter()
                .map(|a| InterchangeAttestation {
                    source_epoch: a.source_epoch.to_string(),
                    target_epoch: a.target_epoch.to_string(),
                    signing_root: a.signing_root,
                })
                .collect();

            let signed_blocks: Vec<InterchangeBlock> = blocks
                .into_iter()
                .map(|b| InterchangeBlock {
                    slot: b.slot.to_string(),
                    signing_root: b.signing_root,
                })
                .collect();

            data.push(ValidatorRecord { pubkey, signed_blocks, signed_attestations });
        }

        let record_count = data.len();
        let result = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_validators_root.to_string(),
            },
            data,
        };
        tracing::info!(
            record_count,
            path = self.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            "slashing DB export completed"
        );
        Ok(result)
    }

    #[tracing::instrument(name = "rvc.slashing.db.import", skip_all)]
    pub fn import(
        &self,
        interchange: &InterchangeFormat,
        expected_genesis_validators_root: &str,
    ) -> Result<(), SlashingError> {
        if interchange.metadata.interchange_format_version != "5" {
            return Err(SlashingError::InvalidInterchangeFormat(format!(
                "unsupported interchange_format_version: expected \"5\", got \"{}\"",
                interchange.metadata.interchange_format_version
            )));
        }

        if interchange.metadata.genesis_validators_root != expected_genesis_validators_root {
            return Err(SlashingError::GenesisValidatorsRootMismatch {
                expected: expected_genesis_validators_root.to_string(),
                actual: interchange.metadata.genesis_validators_root.clone(),
            });
        }

        // The gvr is already validated above against interchange.metadata.genesis_validators_root.
        // Store it as a hex string to write into every inserted row.  Every row must carry a
        // non-NULL genesis_validators_root so the v3 unique index
        // (pubkey, genesis_validators_root, slot/target_epoch) actually fires — SQLite treats
        // NULL as DISTINCT from all values, so a NULL gvr bypasses the index silently.
        let gvr_hex = expected_genesis_validators_root.to_owned();

        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        for validator in &interchange.data {
            let pubkey = normalize_pubkey(&validator.pubkey);

            for attestation in &validator.signed_attestations {
                let source_epoch: Epoch = attestation.source_epoch.parse().map_err(|_| {
                    SlashingError::InvalidInterchangeFormat(format!(
                        "invalid source_epoch: {}",
                        attestation.source_epoch
                    ))
                })?;

                let target_epoch: Epoch = attestation.target_epoch.parse().map_err(|_| {
                    SlashingError::InvalidInterchangeFormat(format!(
                        "invalid target_epoch: {}",
                        attestation.target_epoch
                    ))
                })?;

                tx.execute(
                    "INSERT INTO attestations \
                     (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
                     SELECT 'local-vc', ?1, ?2, ?3, ?4, ?5
                     WHERE NOT EXISTS (
                         SELECT 1 FROM attestations WHERE pubkey = ?1 AND target_epoch = ?3
                     )",
                    (
                        &pubkey,
                        source_epoch as i64,
                        target_epoch as i64,
                        &attestation.signing_root,
                        &gvr_hex,
                    ),
                )?;
            }

            for block in &validator.signed_blocks {
                let slot: u64 = block.slot.parse().map_err(|_| {
                    SlashingError::InvalidInterchangeFormat(format!("invalid slot: {}", block.slot))
                })?;

                tx.execute(
                    "INSERT INTO blocks \
                     (client_cn, pubkey, slot, signing_root, genesis_validators_root)
                     SELECT 'local-vc', ?1, ?2, ?3, ?4
                     WHERE NOT EXISTS (
                         SELECT 1 FROM blocks WHERE pubkey = ?1 AND slot = ?2
                     )",
                    (&pubkey, slot as i64, &block.signing_root, &gvr_hex),
                )?;
            }
        }

        tx.commit()?;
        let record_count = interchange.data.len();
        tracing::info!(
            record_count,
            path = self.path.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            "slashing DB import completed"
        );
        Ok(())
    }

    /// Record a signed block with idempotent behavior.
    ///
    /// If a block with the same pubkey and slot already exists,
    /// the operation silently succeeds without modifying the existing record.
    ///
    /// Every row carries a non-NULL `genesis_validators_root`.  The v3 unique index
    /// `(pubkey, genesis_validators_root, slot)` only fires for non-NULL gvr values —
    /// SQLite treats NULL as DISTINCT, so a NULL gvr would bypass the index entirely.
    /// Callers must supply the chain's pinned GVR.
    ///
    /// Idempotency is checked by `(pubkey, slot)` — safe because the DB is
    /// single-chain: every row for a given pubkey has the same gvr.
    pub fn record_block(
        &self,
        pubkey: &str,
        slot: Slot,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let gvr_hex = Self::root_to_hex(gvr);
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             SELECT 'local-vc', ?1, ?2, ?3, ?4
             WHERE NOT EXISTS (
                 SELECT 1 FROM blocks WHERE pubkey = ?1 AND slot = ?2
             )",
            (&pubkey, slot as i64, &signing_root, &gvr_hex),
        )?;
        Ok(())
    }

    /// Check if it is safe to propose a block at the given slot.
    ///
    /// Returns `Ok(())` if safe, or `Err(SlashingError::SlashableBlock(_))`
    /// with details about the violation type.
    ///
    /// Per EIP-3076:
    /// - If no block exists for this (pubkey, slot): safe
    /// - If a block exists with the same signing_root: safe (idempotent re-signing)
    /// - If a block exists with a different signing_root: reject (double proposal)
    pub fn is_safe_to_propose(
        &self,
        pubkey: &str,
        slot: Slot,
        signing_root: Option<String>,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();

        // Check block watermark
        let watermark: Option<i64> = conn
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'block'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(wm) = watermark {
            if (slot as i64) < wm {
                return Err(SlashingError::BelowBlockWatermark {
                    slot,
                    watermark_slot: wm as Slot,
                });
            }
        }

        let existing: Option<Option<String>> = conn
            .query_row(
                "SELECT signing_root FROM blocks WHERE pubkey = ?1 AND slot = ?2",
                (&pubkey, slot as i64),
                |row| row.get(0),
            )
            .optional()?;

        if let Some(existing_root) = existing {
            if existing_root != signing_root {
                return Err(BlockSlashingViolation::DoubleBlockProposal { slot }.into());
            }
        } else {
            // No block at this slot — check that slot is not below the minimum
            let min_slot: Option<i64> = conn
                .query_row("SELECT MIN(slot) FROM blocks WHERE pubkey = ?1", [&pubkey], |row| {
                    row.get(0)
                })
                .optional()?
                .flatten();

            if let Some(min) = min_slot {
                if (slot as i64) < min {
                    return Err(BlockSlashingViolation::SlotBelowMinimum {
                        slot,
                        min_slot: min as Slot,
                    }
                    .into());
                }
            }
        }

        Ok(())
    }

    /// Atomically check and record a block proposal.
    ///
    /// Combines `is_safe_to_propose` and `record_block` in a single SQLite
    /// transaction with `IMMEDIATE` locking to prevent TOCTOU races.
    ///
    /// # Arguments
    /// - `_client_cn`: Accepted for call-site compatibility with the EIP-3076
    ///   conformance/test harness but **not written to the audit column**.
    ///   All rows inserted by this method carry [`crate::stage::AUDIT_ORIGIN`]
    ///   (`"local-vc"`) in the `client_cn` column, enforcing the post-2.5
    ///   invariant that every new row is canonical.  Per-CN audit visibility is
    ///   via [`crate::audit_log`] in [`crate::PubkeyScopedDb`].
    /// - `gvr`: Genesis validators root for this signing operation.  Compared
    ///   against `metadata.genesis_validators_root` (M-6 / ISSUE-3.5).
    ///   On mismatch, `Err(SlashingError::GenesisRootMismatch)` is returned.
    #[tracing::instrument(name = "rvc.slashing.db.block", skip_all, fields(rvc.slashing.result))]
    pub fn check_and_record_block(
        &self,
        _client_cn: &str,
        pubkey: &str,
        slot: Slot,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        // M-6: compare caller-supplied gvr against the metadata-pinned value.
        // This check is performed *before* acquiring the main mutex to avoid
        // a nested-lock pattern (pinned_gvr() may itself briefly take the lock).
        if let Some(pinned) = self.pinned_gvr()? {
            if pinned != *gvr {
                tracing::error!(
                    rejection_reason = "genesis_root_mismatch",
                    "block proposal rejected: genesis root mismatch"
                );
                return Err(SlashingError::GenesisRootMismatch { expected: pinned, got: *gvr });
            }
        }

        let gvr_hex = Self::root_to_hex(gvr);
        let pubkey = normalize_pubkey(pubkey);
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Check block watermark
        let watermark: Option<i64> = tx
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'block'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(wm) = watermark {
            if (slot as i64) < wm {
                tracing::Span::current().record("rvc.slashing.result", "blocked");
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pubkey),
                    slot,
                    rejection_reason = "below_block_watermark",
                    "block proposal rejected"
                );
                return Err(SlashingError::BelowBlockWatermark {
                    slot,
                    watermark_slot: wm as Slot,
                });
            }
        }

        let existing: Option<Option<String>> = tx
            .query_row(
                "SELECT signing_root FROM blocks WHERE pubkey = ?1 AND slot = ?2",
                (&pubkey, slot as i64),
                |row| row.get(0),
            )
            .optional()?;

        if let Some(existing_root) = existing {
            let is_resign = match (&existing_root, &signing_root) {
                (Some(er), Some(nr)) if er == nr => true,
                (None, None) if !self.strict_semantics.load(Ordering::Relaxed) => true,
                _ => false,
            };
            if !is_resign {
                tracing::Span::current().record("rvc.slashing.result", "blocked");
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pubkey),
                    slot,
                    rejection_reason = "double_block_proposal",
                    "block proposal rejected"
                );
                return Err(BlockSlashingViolation::DoubleBlockProposal { slot }.into());
            }
            // Same signing root — idempotent re-sign, commit without inserting
            tx.commit()?;
            tracing::Span::current().record("rvc.slashing.result", "safe");
            tracing::debug!(
                pubkey = %TruncatedPubkey::new(&pubkey),
                slot,
                "block proposal safe"
            );
            return Ok(());
        }

        // No block at this (pubkey, slot) — check that slot is not below the minimum.
        let min_slot: Option<i64> = tx
            .query_row("SELECT MIN(slot) FROM blocks WHERE pubkey = ?1", (&pubkey,), |row| {
                row.get(0)
            })
            .optional()?
            .flatten();

        if let Some(min) = min_slot {
            if (slot as i64) < min {
                tracing::Span::current().record("rvc.slashing.result", "blocked");
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pubkey),
                    slot,
                    rejection_reason = "slot_below_minimum",
                    "block proposal rejected"
                );
                return Err(BlockSlashingViolation::SlotBelowMinimum {
                    slot,
                    min_slot: min as Slot,
                }
                .into());
            }
        }

        tx.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (crate::stage::AUDIT_ORIGIN, &pubkey, slot as i64, &signing_root, &gvr_hex),
        )?;

        tx.commit()?;
        tracing::Span::current().record("rvc.slashing.result", "safe");
        tracing::debug!(
            pubkey = %TruncatedPubkey::new(&pubkey),
            slot,
            "block proposal safe"
        );
        Ok(())
    }

    /// Atomically check and record an attestation.
    ///
    /// Combines `is_safe_to_sign` and `record_attestation` in a single SQLite
    /// transaction with `IMMEDIATE` locking to prevent TOCTOU races.
    ///
    /// ## Edge Case Decisions (FU-32, FU-33)
    ///
    /// **FU-32 (same root, different source):**
    /// Per EIP-3076, `signing_root` = `hash_tree_root(AttestationData)`. Since
    /// `AttestationData` includes `source_epoch`, identical roots imply identical
    /// source epochs. If source differs with same root, we log a warning
    /// (signing pipeline bug indicator) but allow the attestation. This is
    /// defense-in-depth only — the invariant violation is physically impossible
    /// under correct SSZ serialization. See EIP-3076 Condition 5.
    ///
    /// **FU-33 (None==None signing root):**
    /// EIP-3076 recommends treating null roots as "unknown" and assigning a
    /// suitable dummy root internally. With `strict_semantics = false`
    /// (default): `None==None` is treated as a re-sign for backward
    /// compatibility with pre-existing records that lack roots. With
    /// `strict_semantics = true`: `None==None` is rejected as a potential
    /// double vote, matching Lighthouse/Prysm/Teku conservative behavior.
    /// See EIP-3076 §Conditions, note on `signing_root` handling.
    /// Atomically check and record an attestation.
    ///
    /// # Arguments
    /// - `_client_cn`: Accepted for call-site compatibility with the EIP-3076
    ///   conformance/test harness but **not written to the audit column**.
    ///   All rows inserted by this method carry [`crate::stage::AUDIT_ORIGIN`]
    ///   (`"local-vc"`) in the `client_cn` column, enforcing the post-2.5
    ///   invariant that every new row is canonical.  Per-CN audit visibility is
    ///   via [`crate::audit_log`] in [`crate::PubkeyScopedDb`].
    /// - `gvr`: Genesis validators root for this signing operation.  Compared
    ///   against `metadata.genesis_validators_root` (M-6 / ISSUE-3.5).
    ///   On mismatch, `Err(SlashingError::GenesisRootMismatch)` is returned.
    ///
    /// ## Edge Case Decisions (FU-32, FU-33)
    ///
    /// **FU-32 (same root, different source):**
    /// Per EIP-3076, `signing_root` = `hash_tree_root(AttestationData)`. Since
    /// `AttestationData` includes `source_epoch`, identical roots imply identical
    /// source epochs. If source differs with same root, we log a warning
    /// (signing pipeline bug indicator) but allow the attestation. This is
    /// defense-in-depth only — the invariant violation is physically impossible
    /// under correct SSZ serialization. See EIP-3076 Condition 5.
    ///
    /// **FU-33 (None==None signing root):**
    /// EIP-3076 recommends treating null roots as "unknown" and assigning a
    /// suitable dummy root internally. With `strict_semantics = false`
    /// (default): `None==None` is treated as a re-sign for backward
    /// compatibility with pre-existing records that lack roots. With
    /// `strict_semantics = true`: `None==None` is rejected as a potential
    /// double vote, matching Lighthouse/Prysm/Teku conservative behavior.
    /// See EIP-3076 §Conditions, note on `signing_root` handling.
    #[tracing::instrument(name = "rvc.slashing.db.attestation", skip_all, fields(rvc.slashing.result))]
    pub fn check_and_record_attestation(
        &self,
        _client_cn: &str,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: Option<String>,
        gvr: &Root,
    ) -> Result<(), SlashingError> {
        // M-6: compare caller-supplied gvr against the metadata-pinned value.
        if let Some(pinned) = self.pinned_gvr()? {
            if pinned != *gvr {
                tracing::error!(
                    rejection_reason = "genesis_root_mismatch",
                    "attestation rejected: genesis root mismatch"
                );
                return Err(SlashingError::GenesisRootMismatch { expected: pinned, got: *gvr });
            }
        }

        let gvr_hex = Self::root_to_hex(gvr);
        let pubkey = normalize_pubkey(pubkey);
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Check attestation watermarks (both source and target)
        let wm_source: Option<i64> = tx
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_source'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(ws) = wm_source {
            if (source_epoch as i64) < ws {
                tracing::Span::current().record("rvc.slashing.result", "blocked");
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pubkey),
                    source_epoch,
                    target_epoch,
                    rejection_reason = "below_attestation_source_watermark",
                    "attestation rejected"
                );
                return Err(SlashingError::BelowAttestationSourceWatermark {
                    source_epoch,
                    watermark_source: ws as Epoch,
                });
            }
        }

        let wm_target: Option<i64> = tx
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_target'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(wt) = wm_target {
            if (target_epoch as i64) < wt {
                tracing::Span::current().record("rvc.slashing.result", "blocked");
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pubkey),
                    source_epoch,
                    target_epoch,
                    rejection_reason = "below_attestation_target_watermark",
                    "attestation rejected"
                );
                return Err(SlashingError::BelowAttestationWatermark {
                    target_epoch,
                    watermark_target: wt as Epoch,
                });
            }
        }

        let existing: Vec<(Epoch, Epoch, Option<String>)> = {
            let mut stmt = tx.prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM attestations
                 WHERE pubkey = ?1",
            )?;
            let result = stmt
                .query_map((&pubkey,), |row| {
                    Ok((
                        row.get::<_, i64>(0)? as Epoch,
                        row.get::<_, i64>(1)? as Epoch,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            result
        };

        let mut is_duplicate = false;
        for (existing_source, existing_target, existing_root) in &existing {
            if target_epoch == *existing_target {
                let strict = self.strict_semantics.load(Ordering::Relaxed);
                match (existing_root, &signing_root) {
                    (Some(er), Some(nr)) if er == nr => {
                        // Genuine re-sign: identical known roots. Allow.
                        // FU-32: Defense-in-depth — verify source also matches.
                        if source_epoch != *existing_source {
                            tracing::warn!(
                                pubkey,
                                target_epoch,
                                existing_source = *existing_source,
                                new_source = source_epoch,
                                "same signing root but different source epoch — possible signing pipeline bug"
                            );
                        }
                        is_duplicate = true;
                        continue;
                    }
                    (None, None) if !strict => {
                        // Lenient mode (default): treat None==None as re-sign
                        is_duplicate = true;
                        continue;
                    }
                    _ => {
                        // Different roots, or None involved in strict mode
                        tracing::Span::current().record("rvc.slashing.result", "blocked");
                        tracing::error!(
                            pubkey = %TruncatedPubkey::new(&pubkey),
                            source_epoch,
                            target_epoch,
                            rejection_reason = "double_vote",
                            "attestation rejected"
                        );
                        return Err(
                            AttestationSlashingViolation::DoubleVote { target_epoch }.into()
                        );
                    }
                }
            }

            if source_epoch < *existing_source && target_epoch > *existing_target {
                tracing::Span::current().record("rvc.slashing.result", "blocked");
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pubkey),
                    source_epoch,
                    target_epoch,
                    rejection_reason = "surrounding_vote",
                    "attestation rejected"
                );
                return Err(AttestationSlashingViolation::SurroundingVote {
                    new_source: source_epoch,
                    new_target: target_epoch,
                    existing_source: *existing_source,
                    existing_target: *existing_target,
                }
                .into());
            }

            if *existing_source < source_epoch && *existing_target > target_epoch {
                tracing::Span::current().record("rvc.slashing.result", "blocked");
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&pubkey),
                    source_epoch,
                    target_epoch,
                    rejection_reason = "surrounded_vote",
                    "attestation rejected"
                );
                return Err(AttestationSlashingViolation::SurroundedVote {
                    new_source: source_epoch,
                    new_target: target_epoch,
                    existing_source: *existing_source,
                    existing_target: *existing_target,
                }
                .into());
            }
        }

        if !is_duplicate {
            // Check target epoch is not below minimum existing target (pubkey-scoped).
            let min_target = existing.iter().map(|(_, t, _)| *t).min();
            if let Some(min) = min_target {
                if target_epoch < min {
                    tracing::Span::current().record("rvc.slashing.result", "blocked");
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&pubkey),
                        source_epoch,
                        target_epoch,
                        rejection_reason = "target_epoch_below_minimum",
                        "attestation rejected"
                    );
                    return Err(AttestationSlashingViolation::TargetEpochBelowMinimum {
                        target_epoch,
                        min_target: min,
                    }
                    .into());
                }
            }

            tx.execute(
                "INSERT INTO attestations
                 (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    crate::stage::AUDIT_ORIGIN,
                    &pubkey,
                    source_epoch as i64,
                    target_epoch as i64,
                    &signing_root,
                    &gvr_hex,
                ),
            )?;
        }

        tx.commit()?;
        tracing::Span::current().record("rvc.slashing.result", "safe");
        tracing::debug!(
            pubkey = %TruncatedPubkey::new(&pubkey),
            source_epoch,
            target_epoch,
            "attestation safe"
        );
        Ok(())
    }

    /// Get the last signed attestation epoch for a given public key.
    ///
    /// Returns `None` if no attestations have been signed for this validator.
    pub fn last_signed_attestation_epoch(
        &self,
        pubkey: &str,
    ) -> Result<Option<Epoch>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();
        let result: Option<i64> = conn
            .query_row(
                "SELECT MAX(target_epoch) FROM attestations WHERE pubkey = ?1",
                [&pubkey],
                |row| row.get(0),
            )
            .map_err(SlashingError::from)?;

        Ok(result.map(|e| e as Epoch))
    }

    /// Get the last signed block slot for a given public key.
    ///
    /// Returns `None` if no blocks have been signed for this validator.
    pub fn last_signed_block_slot(&self, pubkey: &str) -> Result<Option<Slot>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();
        let result: Option<i64> = conn
            .query_row("SELECT MAX(slot) FROM blocks WHERE pubkey = ?1", [&pubkey], |row| {
                row.get(0)
            })
            .map_err(SlashingError::from)?;

        Ok(result.map(|s| s as Slot))
    }

    /// Run SQLite `PRAGMA integrity_check` and return an error if the database is corrupt.
    pub fn check_integrity(&self) -> Result<(), SlashingError> {
        let conn = self.conn.lock();
        let result: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if result != "ok" {
            return Err(SlashingError::IntegrityCheckFailed(result));
        }
        Ok(())
    }

    /// Read the stored genesis validators root from the metadata table.
    pub fn genesis_validators_root(&self) -> Result<Option<String>, SlashingError> {
        let conn = self.conn.lock();
        let result: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'genesis_validators_root'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    /// Store the genesis validators root in the metadata table.
    ///
    /// On first run, the root is stored. On subsequent runs, the stored root
    /// is compared against the provided root. If they differ, an error is returned.
    pub fn set_genesis_validators_root(&self, root: &str) -> Result<(), SlashingError> {
        let conn = self.conn.lock();
        let existing: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'genesis_validators_root'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(stored) if stored != root => Err(SlashingError::GenesisValidatorsRootMismatch {
                expected: stored,
                actual: root.to_string(),
            }),
            Some(_) => Ok(()),
            None => {
                conn.execute(
                    "INSERT INTO metadata (key, value) VALUES ('genesis_validators_root', ?1)",
                    [root],
                )?;
                Ok(())
            }
        }
    }

    /// Set a block watermark for a validator. Blocks below this slot will be rejected and can be pruned.
    ///
    /// Watermarks can only be raised, never lowered. Setting the same value is idempotent.
    pub fn set_block_watermark(&self, pubkey: &str, slot: Slot) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'block'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(current) = existing {
            if (slot as i64) < current {
                return Err(SlashingError::WatermarkLowered {
                    pubkey: pubkey.to_string(),
                    watermark_type: "block".to_string(),
                });
            }
            tx.execute(
                "UPDATE watermarks SET value = ?1 WHERE pubkey = ?2 AND watermark_type = 'block'",
                (slot as i64, &pubkey),
            )?;
        } else {
            tx.execute(
                "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, 'block', ?2)",
                (&pubkey, slot as i64),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get the block watermark for a validator.
    pub fn get_block_watermark(&self, pubkey: &str) -> Result<Option<Slot>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();
        let result: Option<i64> = conn
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'block'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result.map(|v| v as Slot))
    }

    /// Set an attestation watermark for a validator.
    ///
    /// Both source and target epoch watermarks can only be raised, never lowered.
    pub fn set_attestation_watermark(
        &self,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
    ) -> Result<(), SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing_source: Option<i64> = tx
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_source'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;

        let existing_target: Option<i64> = tx
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_target'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(current_source) = existing_source {
            if (source_epoch as i64) < current_source {
                return Err(SlashingError::WatermarkLowered {
                    pubkey: pubkey.clone(),
                    watermark_type: "att_source".to_string(),
                });
            }
        }
        if let Some(current_target) = existing_target {
            if (target_epoch as i64) < current_target {
                return Err(SlashingError::WatermarkLowered {
                    pubkey: pubkey.clone(),
                    watermark_type: "att_target".to_string(),
                });
            }
        }

        tx.execute(
            "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, 'att_source', ?2)
             ON CONFLICT(pubkey, watermark_type) DO UPDATE SET value = ?2",
            (&pubkey, source_epoch as i64),
        )?;
        tx.execute(
            "INSERT INTO watermarks (pubkey, watermark_type, value) VALUES (?1, 'att_target', ?2)
             ON CONFLICT(pubkey, watermark_type) DO UPDATE SET value = ?2",
            (&pubkey, target_epoch as i64),
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Get the attestation watermark for a validator.
    ///
    /// Returns `Some((source_epoch, target_epoch))` if both watermarks are set, `None` otherwise.
    pub fn get_attestation_watermark(
        &self,
        pubkey: &str,
    ) -> Result<Option<(Epoch, Epoch)>, SlashingError> {
        let pubkey = normalize_pubkey(pubkey);
        let conn = self.conn.lock();

        let source: Option<i64> = conn
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_source'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;

        let target: Option<i64> = conn
            .query_row(
                "SELECT value FROM watermarks WHERE pubkey = ?1 AND watermark_type = 'att_target'",
                [&pubkey],
                |row| row.get(0),
            )
            .optional()?;

        match (source, target) {
            (Some(s), Some(t)) => Ok(Some((s as Epoch, t as Epoch))),
            _ => Ok(None),
        }
    }

    /// Delete slashing protection records below all set watermarks.
    ///
    /// Returns an error if no watermarks are set (safety: prevents accidental deletion of all records).
    #[tracing::instrument(name = "rvc.slashing.db.prune", skip_all)]
    pub fn prune_below_watermarks(&self) -> Result<PruneStats, SlashingError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let watermark_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM watermarks", [], |row| row.get(0))?;

        if watermark_count == 0 {
            return Err(SlashingError::NoWatermarksSet);
        }

        // Delete blocks below each validator's block watermark
        let blocks_deleted = tx.execute(
            "DELETE FROM blocks WHERE EXISTS (
                SELECT 1 FROM watermarks w
                WHERE w.pubkey = blocks.pubkey
                  AND w.watermark_type = 'block'
                  AND blocks.slot < w.value
            )",
            [],
        )?;

        // Delete attestations below each validator's target epoch watermark
        let attestations_deleted = tx.execute(
            "DELETE FROM attestations WHERE EXISTS (
                SELECT 1 FROM watermarks w
                WHERE w.pubkey = attestations.pubkey
                  AND w.watermark_type = 'att_target'
                  AND attestations.target_epoch < w.value
            )",
            [],
        )?;

        tx.commit()?;

        // Increment prune metrics
        metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[metrics::prune_type::BLOCK])
            .inc_by(blocks_deleted as u64);
        metrics::RVC_SLASHING_DB_PRUNE_TOTAL
            .with_label_values(&[metrics::prune_type::ATTESTATION])
            .inc_by(attestations_deleted as u64);

        let pruned_count = blocks_deleted + attestations_deleted;
        tracing::info!(
            pruned_count,
            blocks_deleted,
            attestations_deleted,
            "slashing DB prune completed"
        );

        Ok(PruneStats {
            attestations_deleted: attestations_deleted as u64,
            blocks_deleted: blocks_deleted as u64,
        })
    }

    /// Check file permissions and warn if the slashing DB is group- or world-accessible (Unix only).
    #[cfg(unix)]
    pub fn check_file_permissions(&self) {
        use std::os::unix::fs::PermissionsExt;
        if let Some(path) = &self.path {
            if let Ok(metadata) = std::fs::metadata(path) {
                let mode = metadata.permissions().mode();
                let dangerous_bits = 0o077; // group + world bits
                if mode & dangerous_bits != 0 {
                    let mut issues = Vec::new();
                    if mode & 0o040 != 0 {
                        issues.push("group-readable");
                    }
                    if mode & 0o020 != 0 {
                        issues.push("group-writable");
                    }
                    if mode & 0o010 != 0 {
                        issues.push("group-executable");
                    }
                    if mode & 0o004 != 0 {
                        issues.push("world-readable");
                    }
                    if mode & 0o002 != 0 {
                        issues.push("world-writable");
                    }
                    if mode & 0o001 != 0 {
                        issues.push("world-executable");
                    }
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:o}", mode),
                        "slashing protection database is {}; consider restricting permissions to 0600",
                        issues.join(" and "),
                    );
                }
            }
        }
    }

    /// Check file permissions (no-op on non-Unix platforms).
    #[cfg(not(unix))]
    pub fn check_file_permissions(&self) {}

    /// Check file permissions and return an error if the slashing DB is group- or world-accessible (Unix only).
    ///
    /// Use this with the `--strict-permissions` CLI flag to make unsafe permissions fatal at startup.
    /// Unlike `check_file_permissions`, this also returns an error if file metadata cannot be read.
    #[cfg(unix)]
    pub fn check_file_permissions_strict(&self) -> Result<(), SlashingError> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(path) = &self.path {
            let metadata =
                std::fs::metadata(path).map_err(|e| SlashingError::UnsafePermissions {
                    path: path.display().to_string(),
                    mode: format!("unreadable: {}", e),
                })?;
            let mode = metadata.permissions().mode();
            let dangerous_bits = 0o077; // group + world bits
            if mode & dangerous_bits != 0 {
                return Err(SlashingError::UnsafePermissions {
                    path: path.display().to_string(),
                    mode: format!("{:o}", mode),
                });
            }
        }
        Ok(())
    }

    /// Check file permissions strictly (no-op on non-Unix platforms).
    #[cfg(not(unix))]
    pub fn check_file_permissions_strict(&self) -> Result<(), SlashingError> {
        Ok(())
    }

    /// Query a PRAGMA that returns a single integer value.
    ///
    /// Allows integration tests to verify connection-level pragma settings
    /// (e.g. `synchronous`, `fullfsync`) that cannot be read from a separate connection
    /// because they are per-connection settings that reset on every new open.
    ///
    /// # Note
    /// This is a test helper. Do not use it in production paths.
    #[doc(hidden)]
    pub fn query_pragma_i64(&self, name: &str) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();
        conn.pragma_query_value(None, name, |row| row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Zero GVR used as a test sentinel.  No GVR is pinned in metadata for these
    /// unit tests, so the M-6 per-call GVR check is skipped and this value is
    /// only written into the row's `genesis_validators_root` column.
    const TEST_GVR: Root = [0u8; 32];

    #[test]
    fn test_open_in_memory_database() {
        let db = SlashingDb::open_in_memory();
        assert!(db.is_ok());
    }

    #[test]
    fn test_open_file_database() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("test.db");

        let db = SlashingDb::open(&path);
        assert!(db.is_ok());
        assert!(path.exists());
    }

    #[test]
    fn test_migration_creates_tables() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let conn = db.conn.lock();
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('attestations', 'blocks')",
                [],
                |row| row.get(0),
            )
            .expect("failed to query tables");

        assert_eq!(table_count, 2);
    }

    #[test]
    fn test_migration_is_idempotent() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.migrate().is_ok());
        assert!(db.migrate().is_ok());
    }

    #[test]
    fn test_insert_and_get_attestation() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: Some("0xabcd".to_string()),
        };

        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0], attestation);
    }

    #[test]
    fn test_insert_attestation_without_signing_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };

        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].signing_root.is_none());
    }

    #[test]
    fn test_get_attestations_empty() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestations = db.get_attestations("0xnonexistent").expect("failed to get");
        assert!(attestations.is_empty());
    }

    #[test]
    fn test_get_attestations_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestations = vec![
            SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 100,
                target_epoch: 101,
                signing_root: None,
            },
            SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 101,
                target_epoch: 102,
                signing_root: None,
            },
        ];

        for a in &attestations {
            db.insert_attestation(a, &TEST_GVR).expect("failed to insert");
        }

        let result = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].target_epoch, 101);
        assert_eq!(result[1].target_epoch, 102);
    }

    #[test]
    fn test_attestation_unique_constraint() {
        // v3: uniqueness is enforced by (pubkey, gvr, target_epoch).
        // Raw inserts with NULL gvr bypass the index (SQLite treats NULLs as distinct).
        // The constraint is enforced at the slashing-check level (check_and_record_*).
        // Verify pubkey-scoped uniqueness via the staging API.
        let gvr = [0u8; 32];
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation("local-vc", "0x1234", 100, 101, None, &gvr)
            .expect("first attestation should succeed");

        // Same pubkey+target_epoch with a different signing_root must be rejected.
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            99,
            101,
            Some("0xdifferent".to_string()),
            &gvr,
        );
        assert!(result.is_err(), "duplicate target_epoch attestation must be rejected");
    }

    #[test]
    fn test_insert_and_get_block() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let block = SignedBlock {
            pubkey: "0x1234".to_string(),
            slot: 1000,
            signing_root: Some("0xabcd".to_string()),
        };

        db.insert_block(&block, &TEST_GVR).expect("failed to insert");

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], block);
    }

    #[test]
    fn test_insert_block_without_signing_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let block = SignedBlock { pubkey: "0x1234".to_string(), slot: 1000, signing_root: None };

        db.insert_block(&block, &TEST_GVR).expect("failed to insert");

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].signing_root.is_none());
    }

    #[test]
    fn test_get_blocks_empty() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let blocks = db.get_blocks("0xnonexistent").expect("failed to get");
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_get_blocks_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let blocks = vec![
            SignedBlock { pubkey: "0x1234".to_string(), slot: 1000, signing_root: None },
            SignedBlock { pubkey: "0x1234".to_string(), slot: 1001, signing_root: None },
        ];

        for b in &blocks {
            db.insert_block(b, &TEST_GVR).expect("failed to insert");
        }

        let result = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].slot, 1000);
        assert_eq!(result[1].slot, 1001);
    }

    #[test]
    fn test_block_unique_constraint() {
        // v3: uniqueness is enforced by (pubkey, gvr, slot).
        // Raw inserts with NULL gvr bypass the index (SQLite treats NULLs as distinct).
        // The constraint is enforced at the slashing-check level (check_and_record_*).
        // Verify pubkey-scoped uniqueness via the staging API.
        let gvr = [0u8; 32];
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_block("local-vc", "0x1234", 1000, None, &gvr)
            .expect("first block should succeed");

        // Same pubkey+slot with a different signing_root must be rejected.
        let result = db.check_and_record_block(
            "local-vc",
            "0x1234",
            1000,
            Some("0xdifferent".to_string()),
            &gvr,
        );
        assert!(result.is_err(), "duplicate slot block must be rejected");
    }

    /// Verify the v3 unique index `(pubkey, genesis_validators_root, slot)` fires
    /// for non-NULL gvr rows inserted via raw SQL.
    ///
    /// SQLite treats NULL as DISTINCT from all values (including other NULLs), so a
    /// NULL gvr bypasses a unique index silently.  This test proves the index works
    /// when gvr is non-NULL — which is the guaranteed post-fix state of every insert path.
    #[test]
    fn test_v3_block_unique_index_fires_for_non_null_gvr() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr_hex = SlashingDb::root_to_hex(&TEST_GVR);
        let conn = db.conn.lock();

        // Insert a block with non-NULL gvr directly.
        conn.execute(
            "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
             VALUES ('local-vc', '0xaaaa', 999, '0xroot_a', ?1)",
            [&gvr_hex],
        )
        .expect("first insert must succeed");

        // A second insert with the same (pubkey, gvr, slot) but different signing_root
        // must fail because the v3 UNIQUE index fires.
        let err = conn
            .execute(
                "INSERT INTO blocks (client_cn, pubkey, slot, signing_root, genesis_validators_root)
                 VALUES ('cn-B', '0xaaaa', 999, '0xroot_b', ?1)",
                [&gvr_hex],
            )
            .expect_err("duplicate (pubkey, gvr, slot) must violate unique index");

        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "expected UNIQUE constraint error, got: {err}"
        );
    }

    /// Verify the v3 unique index `(pubkey, genesis_validators_root, target_epoch)` fires
    /// for non-NULL gvr attestation rows.
    #[test]
    fn test_v3_attestation_unique_index_fires_for_non_null_gvr() {
        let db = SlashingDb::open_in_memory().expect("open");
        let gvr_hex = SlashingDb::root_to_hex(&TEST_GVR);
        let conn = db.conn.lock();

        conn.execute(
            "INSERT INTO attestations \
             (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
             VALUES ('local-vc', '0xbbbb', 10, 20, '0xatt_root_a', ?1)",
            [&gvr_hex],
        )
        .expect("first insert must succeed");

        let err = conn
            .execute(
                "INSERT INTO attestations \
                 (client_cn, pubkey, source_epoch, target_epoch, signing_root, genesis_validators_root)
                 VALUES ('cn-B', '0xbbbb', 11, 20, '0xatt_root_b', ?1)",
                [&gvr_hex],
            )
            .expect_err("duplicate (pubkey, gvr, target_epoch) must violate unique index");

        assert!(
            err.to_string().contains("UNIQUE constraint failed"),
            "expected UNIQUE constraint error, got: {err}"
        );
    }

    #[test]
    fn test_different_pubkeys_isolated() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation1 = SignedAttestation {
            pubkey: "0x1111".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };

        let attestation2 = SignedAttestation {
            pubkey: "0x2222".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };

        db.insert_attestation(&attestation1, &TEST_GVR).expect("failed to insert");
        db.insert_attestation(&attestation2, &TEST_GVR).expect("failed to insert");

        let result1 = db.get_attestations("0x1111").expect("failed to get");
        let result2 = db.get_attestations("0x2222").expect("failed to get");

        assert_eq!(result1.len(), 1);
        assert_eq!(result2.len(), 1);
        assert_eq!(result1[0].pubkey, "0x1111");
        assert_eq!(result2[0].pubkey, "0x2222");
    }

    #[test]
    fn test_persistence_across_connections() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("test.db");

        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            let attestation = SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 100,
                target_epoch: 101,
                signing_root: None,
            };
            db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");
        }

        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            let attestations = db.get_attestations("0x1234").expect("failed to get");
            assert_eq!(attestations.len(), 1);
            assert_eq!(attestations[0].target_epoch, 101);
        }
    }

    #[test]
    fn test_is_safe_to_sign_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let result = db.is_safe_to_sign("0x1234", 100, 101);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_safe_to_sign_no_conflict() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        let result = db.is_safe_to_sign("0x1234", 101, 102);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_safe_to_sign_double_vote() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        let result = db.is_safe_to_sign("0x1234", 99, 101);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::SlashableAttestation(violation) => {
                assert_eq!(
                    violation,
                    AttestationSlashingViolation::DoubleVote { target_epoch: 101 }
                );
            }
            _ => panic!("expected SlashableAttestation error"),
        }
    }

    #[test]
    fn test_is_safe_to_sign_surrounding_vote() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=5, target=10
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 5,
            target_epoch: 10,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // New: source=4, target=11 (surrounds existing)
        let result = db.is_safe_to_sign("0x1234", 4, 11);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::SlashableAttestation(violation) => {
                assert_eq!(
                    violation,
                    AttestationSlashingViolation::SurroundingVote {
                        new_source: 4,
                        new_target: 11,
                        existing_source: 5,
                        existing_target: 10,
                    }
                );
            }
            _ => panic!("expected SlashableAttestation error"),
        }
    }

    #[test]
    fn test_is_safe_to_sign_surrounded_vote() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=4, target=11
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 4,
            target_epoch: 11,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // New: source=5, target=10 (surrounded by existing)
        let result = db.is_safe_to_sign("0x1234", 5, 10);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::SlashableAttestation(violation) => {
                assert_eq!(
                    violation,
                    AttestationSlashingViolation::SurroundedVote {
                        new_source: 5,
                        new_target: 10,
                        existing_source: 4,
                        existing_target: 11,
                    }
                );
            }
            _ => panic!("expected SlashableAttestation error"),
        }
    }

    #[test]
    fn test_is_safe_to_sign_different_pubkey_no_conflict() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1111".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // Different pubkey should not conflict
        let result = db.is_safe_to_sign("0x2222", 100, 101);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_safe_to_sign_multiple_attestations_no_conflict() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestations = vec![
            SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 10,
                target_epoch: 11,
                signing_root: None,
            },
            SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 11,
                target_epoch: 12,
                signing_root: None,
            },
            SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 12,
                target_epoch: 13,
                signing_root: None,
            },
        ];

        for a in &attestations {
            db.insert_attestation(a, &TEST_GVR).expect("failed to insert");
        }

        // New attestation continuing the sequence
        let result = db.is_safe_to_sign("0x1234", 13, 14);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_safe_to_sign_edge_case_same_source_different_target() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // Same source, different target - should be safe if not surrounding/surrounded
        let result = db.is_safe_to_sign("0x1234", 100, 102);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_safe_to_sign_edge_case_boundary_not_surrounding() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=5, target=10
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 5,
            target_epoch: 10,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // New: source=5, target=11 - same source, not surrounding (need source < existing_source)
        let result = db.is_safe_to_sign("0x1234", 5, 11);
        assert!(result.is_ok());

        // New: source=4, target=10 - same target (double vote)
        let result = db.is_safe_to_sign("0x1234", 4, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_safe_to_sign_edge_case_boundary_not_surrounded() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=4, target=11
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 4,
            target_epoch: 11,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // New: source=4, target=10 - below min target (11), rejected per EIP-3076
        let result = db.is_safe_to_sign("0x1234", 4, 10);
        assert!(result.is_err());

        // New: source=5, target=11 - same target (double vote)
        let result = db.is_safe_to_sign("0x1234", 5, 11);
        assert!(result.is_err());

        // New: source=4, target=12 - above min target (11), safe
        let result = db.is_safe_to_sign("0x1234", 4, 12);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_safe_to_sign_surrounding_vote_minimal() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=5, target=6
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 5,
            target_epoch: 6,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // New: source=4, target=7 (minimal surrounding)
        let result = db.is_safe_to_sign("0x1234", 4, 7);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::SlashableAttestation(
                AttestationSlashingViolation::SurroundingVote { .. },
            ) => {}
            _ => panic!("expected SurroundingVote"),
        }
    }

    #[test]
    fn test_is_safe_to_sign_surrounded_vote_minimal() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=4, target=7
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 4,
            target_epoch: 7,
            signing_root: None,
        };
        db.insert_attestation(&attestation, &TEST_GVR).expect("failed to insert");

        // New: source=5, target=6 (minimal surrounded)
        let result = db.is_safe_to_sign("0x1234", 5, 6);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::SurroundedVote {
                ..
            }) => {}
            _ => panic!("expected SurroundedVote"),
        }
    }

    #[test]
    fn test_is_safe_to_sign_detects_first_violation_in_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestations = vec![
            SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 5,
                target_epoch: 10,
                signing_root: None,
            },
            SignedAttestation {
                pubkey: "0x1234".to_string(),
                source_epoch: 15,
                target_epoch: 20,
                signing_root: None,
            },
        ];

        for a in &attestations {
            db.insert_attestation(a, &TEST_GVR).expect("failed to insert");
        }

        // New: source=4, target=21 - surrounds both
        let result = db.is_safe_to_sign("0x1234", 4, 21);
        assert!(result.is_err());
    }

    #[test]
    fn test_export_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        let interchange = db.export(genesis_root).expect("export should succeed");

        assert_eq!(interchange.metadata.interchange_format_version, "5");
        assert_eq!(interchange.metadata.genesis_validators_root, genesis_root);
        assert!(interchange.data.is_empty());
    }

    #[test]
    fn test_export_with_attestations() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";
        db.record_attestation(pubkey, 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");
        db.record_attestation(pubkey, 101, 102, None, &TEST_GVR).expect("record should succeed");

        let interchange = db.export(genesis_root).expect("export should succeed");

        assert_eq!(interchange.data.len(), 1);
        let validator = &interchange.data[0];
        assert_eq!(validator.pubkey, pubkey);
        assert_eq!(validator.signed_attestations.len(), 2);
        assert_eq!(validator.signed_attestations[0].source_epoch, "100");
        assert_eq!(validator.signed_attestations[0].target_epoch, "101");
        assert_eq!(validator.signed_attestations[0].signing_root, Some("0xabcd".to_string()));
        assert_eq!(validator.signed_attestations[1].source_epoch, "101");
        assert_eq!(validator.signed_attestations[1].target_epoch, "102");
        assert!(validator.signed_attestations[1].signing_root.is_none());
    }

    #[test]
    fn test_export_with_blocks() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";
        let block = SignedBlock {
            pubkey: pubkey.to_string(),
            slot: 1000,
            signing_root: Some("0xefgh".to_string()),
        };
        db.insert_block(&block, &TEST_GVR).expect("insert should succeed");

        let interchange = db.export(genesis_root).expect("export should succeed");

        assert_eq!(interchange.data.len(), 1);
        let validator = &interchange.data[0];
        assert_eq!(validator.pubkey, pubkey);
        assert_eq!(validator.signed_blocks.len(), 1);
        assert_eq!(validator.signed_blocks[0].slot, "1000");
        assert_eq!(validator.signed_blocks[0].signing_root, Some("0xefgh".to_string()));
    }

    #[test]
    fn test_export_multiple_validators() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        let pubkey1 = "0x1111";
        let pubkey2 = "0x2222";

        db.record_attestation(pubkey1, 100, 101, None, &TEST_GVR).expect("record should succeed");
        db.record_attestation(pubkey2, 200, 201, None, &TEST_GVR).expect("record should succeed");

        let interchange = db.export(genesis_root).expect("export should succeed");

        assert_eq!(interchange.data.len(), 2);
    }

    #[test]
    fn test_import_empty_interchange() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![],
        };

        let result = db.import(&interchange, genesis_root);
        assert!(result.is_ok());
    }

    #[test]
    fn test_import_genesis_root_mismatch() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let expected_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let actual_root = "0xdifferent00000000000000000000000000000000000000000000000000000000";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: actual_root.to_string(),
            },
            data: vec![],
        };

        let result = db.import(&interchange, expected_root);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::GenesisValidatorsRootMismatch { expected, actual } => {
                assert_eq!(expected, expected_root);
                assert_eq!(actual, actual_root);
            }
            _ => panic!("expected GenesisValidatorsRootMismatch error"),
        }
    }

    #[test]
    fn test_import_with_attestations() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![
                    InterchangeAttestation {
                        source_epoch: "100".to_string(),
                        target_epoch: "101".to_string(),
                        signing_root: Some("0xabcd".to_string()),
                    },
                    InterchangeAttestation {
                        source_epoch: "101".to_string(),
                        target_epoch: "102".to_string(),
                        signing_root: None,
                    },
                ],
            }],
        };

        db.import(&interchange, genesis_root).expect("import should succeed");

        let attestations = db.get_attestations(pubkey).expect("get should succeed");
        assert_eq!(attestations.len(), 2);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[0].signing_root, Some("0xabcd".to_string()));
        assert_eq!(attestations[1].source_epoch, 101);
        assert_eq!(attestations[1].target_epoch, 102);
        assert!(attestations[1].signing_root.is_none());
    }

    #[test]
    fn test_import_with_blocks() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![InterchangeBlock {
                    slot: "1000".to_string(),
                    signing_root: Some("0xefgh".to_string()),
                }],
                signed_attestations: vec![],
            }],
        };

        db.import(&interchange, genesis_root).expect("import should succeed");

        let blocks = db.get_blocks(pubkey).expect("get should succeed");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
        assert_eq!(blocks[0].signing_root, Some("0xefgh".to_string()));
    }

    #[test]
    fn test_roundtrip_export_import() {
        let db1 = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        db1.record_attestation(pubkey, 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");
        db1.record_attestation(pubkey, 101, 102, None, &TEST_GVR).expect("record should succeed");

        let block = SignedBlock {
            pubkey: pubkey.to_string(),
            slot: 1000,
            signing_root: Some("0xefgh".to_string()),
        };
        db1.insert_block(&block, &TEST_GVR).expect("insert should succeed");

        let interchange = db1.export(genesis_root).expect("export should succeed");

        let json =
            serde_json::to_string_pretty(&interchange).expect("serialization should succeed");
        let parsed: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        let db2 = SlashingDb::open_in_memory().expect("failed to open db");
        db2.import(&parsed, genesis_root).expect("import should succeed");

        let attestations = db2.get_attestations(pubkey).expect("get should succeed");
        assert_eq!(attestations.len(), 2);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[1].source_epoch, 101);
        assert_eq!(attestations[1].target_epoch, 102);

        let blocks = db2.get_blocks(pubkey).expect("get should succeed");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
    }

    #[test]
    fn test_import_idempotent() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "100".to_string(),
                    target_epoch: "101".to_string(),
                    signing_root: None,
                }],
            }],
        };

        db.import(&interchange, genesis_root).expect("first import should succeed");
        db.import(&interchange, genesis_root).expect("second import should succeed");

        let attestations = db.get_attestations(pubkey).expect("get should succeed");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_import_invalid_epoch_format() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let pubkey = "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![ValidatorRecord {
                pubkey: pubkey.to_string(),
                signed_blocks: vec![],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: "not_a_number".to_string(),
                    target_epoch: "101".to_string(),
                    signing_root: None,
                }],
            }],
        };

        let result = db.import(&interchange, genesis_root);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::InvalidInterchangeFormat(_) => {}
            _ => panic!("expected InvalidInterchangeFormat error"),
        }
    }

    #[test]
    fn test_record_attestation_new() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].pubkey, "0x1234");
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[0].signing_root, Some("0xabcd".to_string()));
    }

    #[test]
    fn test_record_attestation_without_signing_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].signing_root.is_none());
    }

    #[test]
    fn test_record_attestation_idempotent_exact_duplicate() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("first record should succeed");

        db.record_attestation("0x1234", 100, 101, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("duplicate record should also succeed (idempotent)");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_record_attestation_idempotent_same_target_different_source() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, None, &TEST_GVR)
            .expect("first record should succeed");

        // Same pubkey and target_epoch but different source_epoch
        // Due to UNIQUE(pubkey, target_epoch), this should be ignored
        db.record_attestation("0x1234", 99, 101, None, &TEST_GVR)
            .expect("duplicate target should succeed (idempotent)");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        // Original source_epoch should be preserved
        assert_eq!(attestations[0].source_epoch, 100);
    }

    #[test]
    fn test_record_attestation_multiple_different_targets() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, None, &TEST_GVR)
            .expect("first record should succeed");
        db.record_attestation("0x1234", 101, 102, None, &TEST_GVR)
            .expect("second record should succeed");
        db.record_attestation("0x1234", 102, 103, None, &TEST_GVR)
            .expect("third record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 3);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[1].target_epoch, 102);
        assert_eq!(attestations[2].target_epoch, 103);
    }

    #[test]
    fn test_record_attestation_different_pubkeys() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1111", 100, 101, None, &TEST_GVR).expect("record should succeed");
        db.record_attestation("0x2222", 100, 101, None, &TEST_GVR).expect("record should succeed");

        let att1 = db.get_attestations("0x1111").expect("failed to get");
        let att2 = db.get_attestations("0x2222").expect("failed to get");

        assert_eq!(att1.len(), 1);
        assert_eq!(att2.len(), 1);
    }

    // --- Block slashing protection tests ---

    #[test]
    fn test_block_is_safe_to_propose_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let result = db.is_safe_to_propose("0x1234", 1000, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_is_safe_to_propose_first_proposal_for_slot() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 999, None, &TEST_GVR).expect("record should succeed");
        let result = db.is_safe_to_propose("0x1234", 1000, Some("0xroot1".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_is_safe_to_propose_idempotent_resign_same_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, Some("0xroot1".to_string()), &TEST_GVR)
            .expect("record should succeed");
        let result = db.is_safe_to_propose("0x1234", 1000, Some("0xroot1".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_is_safe_to_propose_double_proposal_different_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, Some("0xroot1".to_string()), &TEST_GVR)
            .expect("record should succeed");
        let result = db.is_safe_to_propose("0x1234", 1000, Some("0xroot2".to_string()));
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::SlashableBlock(violation) => {
                assert_eq!(violation, BlockSlashingViolation::DoubleBlockProposal { slot: 1000 });
            }
            other => panic!("expected SlashableBlock error, got: {other:?}"),
        }
    }

    #[test]
    fn test_block_is_safe_to_propose_double_proposal_existing_none_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("record should succeed");
        // Existing has no root, new has a root — different, should reject
        let result = db.is_safe_to_propose("0x1234", 1000, Some("0xroot1".to_string()));
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
                assert_eq!(slot, 1000)
            }
            other => panic!("expected DoubleBlockProposal, got: {other:?}"),
        }
    }

    #[test]
    fn test_block_is_safe_to_propose_both_none_roots_idempotent() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("record should succeed");
        // Both have None root — same, should be safe (idempotent)
        let result = db.is_safe_to_propose("0x1234", 1000, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_is_safe_to_propose_different_pubkey_no_conflict() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1111", 1000, Some("0xroot1".to_string()), &TEST_GVR)
            .expect("record should succeed");
        let result = db.is_safe_to_propose("0x2222", 1000, Some("0xroot2".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_record_block_new() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, Some("0xabcd".to_string()), &TEST_GVR)
            .expect("record should succeed");
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
        assert_eq!(blocks[0].signing_root, Some("0xabcd".to_string()));
    }

    #[test]
    fn test_block_record_block_idempotent() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("first record");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("duplicate record (idempotent)");
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_block_record_block_multiple_slots() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("record");
        db.record_block("0x1234", 1001, None, &TEST_GVR).expect("record");
        db.record_block("0x1234", 1002, None, &TEST_GVR).expect("record");
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 3);
    }

    #[test]
    fn test_block_last_signed_block_slot_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let result = db.last_signed_block_slot("0x1234").expect("query should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn test_block_last_signed_block_slot_single() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("record");
        let result = db.last_signed_block_slot("0x1234").expect("query should succeed");
        assert_eq!(result, Some(1000));
    }

    #[test]
    fn test_block_last_signed_block_slot_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("record");
        db.record_block("0x1234", 1002, None, &TEST_GVR).expect("record");
        db.record_block("0x1234", 1001, None, &TEST_GVR).expect("record");
        let result = db.last_signed_block_slot("0x1234").expect("query should succeed");
        assert_eq!(result, Some(1002));
    }

    #[test]
    fn test_block_last_signed_block_slot_different_pubkeys() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1111", 1000, None, &TEST_GVR).expect("record");
        db.record_block("0x2222", 2000, None, &TEST_GVR).expect("record");
        assert_eq!(db.last_signed_block_slot("0x1111").unwrap(), Some(1000));
        assert_eq!(db.last_signed_block_slot("0x2222").unwrap(), Some(2000));
    }

    #[test]
    fn test_block_is_safe_to_propose_multiple_existing_blocks() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_block("0x1234", 1000, None, &TEST_GVR).expect("record");
        db.record_block("0x1234", 1001, None, &TEST_GVR).expect("record");
        db.record_block("0x1234", 1002, None, &TEST_GVR).expect("record");
        // Proposing at unused slot should be safe
        let result = db.is_safe_to_propose("0x1234", 1003, None);
        assert!(result.is_ok());
        // Proposing at existing slot with different root should fail
        let result = db.is_safe_to_propose("0x1234", 1001, Some("0xnew".to_string()));
        assert!(result.is_err());
    }

    // --- Atomic check-and-record tests ---

    #[test]
    fn test_check_and_record_block_safe() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let result = db.check_and_record_block(
            "local-vc",
            "0x1234",
            1000,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok());

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].slot, 1000);
        assert_eq!(blocks[0].signing_root, Some("0xroot1".to_string()));
    }

    #[test]
    fn test_check_and_record_block_double_proposal_rejected() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_block(
            "local-vc",
            "0x1234",
            1000,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        let result = db.check_and_record_block(
            "local-vc",
            "0x1234",
            1000,
            Some("0xroot2".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
                assert_eq!(slot, 1000);
            }
            other => panic!("expected DoubleBlockProposal, got: {other:?}"),
        }

        // Verify no second record was inserted
        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_check_and_record_block_idempotent_resign() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_block(
            "local-vc",
            "0x1234",
            1000,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        let result = db.check_and_record_block(
            "local-vc",
            "0x1234",
            1000,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok());

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn test_check_and_record_attestation_safe() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok());

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].source_epoch, 100);
        assert_eq!(attestations[0].target_epoch, 101);
    }

    #[test]
    fn test_check_and_record_attestation_double_vote_rejected() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            99,
            101,
            Some("0xroot2".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch,
            }) => {
                assert_eq!(target_epoch, 101);
            }
            other => panic!("expected DoubleVote, got: {other:?}"),
        }

        // Verify no second record was inserted
        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_check_and_record_attestation_surrounding_vote_rejected() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation("local-vc", "0x1234", 5, 10, None, &[0u8; 32])
            .expect("first should succeed");

        let result = db.check_and_record_attestation("local-vc", "0x1234", 4, 11, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(
                AttestationSlashingViolation::SurroundingVote { .. },
            ) => {}
            other => panic!("expected SurroundingVote, got: {other:?}"),
        }

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_check_and_record_attestation_idempotent_resign() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        // Same signing root for same epoch should pass (idempotent)
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            100,
            101,
            Some("0xroot1".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok());

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_same_root_same_source_no_warning() {
        // Same signing_root + same source_epoch + same target_epoch → no warning, no error
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xABC".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        // Re-sign with identical source, target, root → should succeed silently
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xABC".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok());

        // Should not have inserted a duplicate
        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_same_root_different_source_warns_but_allows() {
        // Same signing_root + same target_epoch but different source_epoch
        // → should log warning but still allow (defense-in-depth, not a rejection)
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xABC".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        // Same root but different source → indicates possible signing pipeline bug
        // Should still succeed (is_duplicate = true) but log a warning
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            4,
            5,
            Some("0xABC".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_ok(), "same root with different source must still be allowed");

        // Should not have inserted a duplicate
        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_double_vote_rejection_unchanged() {
        // Different root + same target → must still be rejected as DoubleVote
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xABC".to_string()),
            &[0u8; 32],
        )
        .expect("first should succeed");

        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xDEF".to_string()),
            &[0u8; 32],
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("double vote"), "expected double vote error, got: {err}");
    }

    // ── FU-33 strict slashing semantics test matrix ──────────────────
    // 6 root combinations × 2 modes (lenient/strict) = 12 tests
    // Attestation tests:

    #[test]
    fn test_strict_att_some_same_lenient_allows() {
        // Some("0xA") vs Some("0xA"), lenient → allow (genuine re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xA".into()),
            &[0u8; 32],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_att_some_same_strict_allows() {
        // Some("0xA") vs Some("0xA"), strict → allow (genuine re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xA".into()),
            &[0u8; 32],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_att_some_diff_lenient_rejects() {
        // Some("0xA") vs Some("0xB"), lenient → reject (double vote)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xB".into()),
            &[0u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_some_diff_strict_rejects() {
        // Some("0xA") vs Some("0xB"), strict → reject (double vote)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xB".into()),
            &[0u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_some_none_lenient_rejects() {
        // Some("0xA") vs None, lenient → reject (different roots)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_some_none_strict_rejects() {
        // Some("0xA") vs None, strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_none_some_lenient_rejects() {
        // None vs Some("0xA"), lenient → reject (different roots)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xA".into()),
            &[0u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_none_some_strict_rejects() {
        // None vs Some("0xA"), strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xA".into()),
            &[0u8; 32],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_strict_att_none_none_lenient_allows() {
        // None vs None, lenient (default) → allow (treat as re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_att_none_none_strict_rejects() {
        // None vs None, strict → reject (unknown root = potential double vote)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32])
            .expect("first");
        let result = db.check_and_record_attestation("local-vc", "0x1234", 3, 5, None, &[0u8; 32]);
        assert!(result.is_err(), "strict mode should reject None==None as potential double vote");
    }

    #[test]
    fn test_strict_att_no_existing_lenient_inserts() {
        // No existing record, lenient → insert
        let db = SlashingDb::open_in_memory().expect("open");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xA".into()),
            &[0u8; 32],
        );
        assert!(result.is_ok());
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 1);
    }

    #[test]
    fn test_strict_att_no_existing_strict_inserts() {
        // No existing record, strict → insert
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        let result = db.check_and_record_attestation(
            "local-vc",
            "0x1234",
            3,
            5,
            Some("0xA".into()),
            &[0u8; 32],
        );
        assert!(result.is_ok());
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 1);
    }

    // Block proposal strict semantics tests (None==None case)

    #[test]
    fn test_strict_block_none_none_lenient_allows() {
        // None vs None block, lenient → allow
        let db = SlashingDb::open_in_memory().expect("open");
        db.check_and_record_block("local-vc", "0x1234", 100, None, &[0u8; 32]).expect("first");
        let result = db.check_and_record_block("local-vc", "0x1234", 100, None, &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_block_none_none_strict_rejects() {
        // None vs None block, strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_block("local-vc", "0x1234", 100, None, &[0u8; 32]).expect("first");
        let result = db.check_and_record_block("local-vc", "0x1234", 100, None, &[0u8; 32]);
        assert!(
            result.is_err(),
            "strict mode should reject None==None block as potential double proposal"
        );
    }

    #[test]
    fn test_strict_block_some_same_strict_allows() {
        // Some("0xA") vs Some("0xA") block, strict → allow (genuine re-sign)
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_block("local-vc", "0x1234", 100, Some("0xA".into()), &[0u8; 32])
            .expect("first");
        let result =
            db.check_and_record_block("local-vc", "0x1234", 100, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_strict_block_none_some_strict_rejects() {
        // None vs Some("0xA") block, strict → reject
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);
        db.check_and_record_block("local-vc", "0x1234", 100, None, &[0u8; 32]).expect("first");
        let result =
            db.check_and_record_block("local-vc", "0x1234", 100, Some("0xA".into()), &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_and_record_block_concurrent_double_proposal() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("concurrent_block.db");
        let db = Arc::new(SlashingDb::open(&path).expect("failed to open db"));

        let db1 = Arc::clone(&db);
        let db2 = Arc::clone(&db);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);

        let handle1 = thread::spawn(move || {
            b1.wait();
            db1.check_and_record_block(
                "local-vc",
                "0x1234",
                1000,
                Some("0xroot1".to_string()),
                &[0u8; 32],
            )
        });

        let handle2 = thread::spawn(move || {
            b2.wait();
            db2.check_and_record_block(
                "local-vc",
                "0x1234",
                1000,
                Some("0xroot2".to_string()),
                &[0u8; 32],
            )
        });

        let r1 = handle1.join().expect("thread panicked");
        let r2 = handle2.join().expect("thread panicked");

        // Exactly one should succeed, one should fail
        let successes = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(successes, 1, "exactly one concurrent block proposal should succeed");

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
    }

    // --- Liveness query tests ---

    #[test]
    fn test_liveness_last_signed_attestation_epoch_empty_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let result = db.last_signed_attestation_epoch("0x1234").expect("query should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn test_liveness_last_signed_attestation_epoch_single() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record");
        let result = db.last_signed_attestation_epoch("0x1234").expect("query should succeed");
        assert_eq!(result, Some(101));
    }

    #[test]
    fn test_liveness_last_signed_attestation_epoch_multiple() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record");
        db.record_attestation("0x1234", 103, 105, None, &TEST_GVR).expect("record");
        db.record_attestation("0x1234", 101, 103, None, &TEST_GVR).expect("record");
        let result = db.last_signed_attestation_epoch("0x1234").expect("query should succeed");
        assert_eq!(result, Some(105));
    }

    #[test]
    fn test_liveness_last_signed_attestation_epoch_different_pubkeys() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.record_attestation("0x1111", 100, 101, None, &TEST_GVR).expect("record");
        db.record_attestation("0x2222", 200, 201, None, &TEST_GVR).expect("record");
        assert_eq!(db.last_signed_attestation_epoch("0x1111").unwrap(), Some(101));
        assert_eq!(db.last_signed_attestation_epoch("0x2222").unwrap(), Some(201));
    }

    #[test]
    fn test_check_and_record_attestation_concurrent_double_vote() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("concurrent_attestation.db");
        let db = Arc::new(SlashingDb::open(&path).expect("failed to open db"));

        let db1 = Arc::clone(&db);
        let db2 = Arc::clone(&db);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);

        let handle1 = thread::spawn(move || {
            b1.wait();
            db1.check_and_record_attestation(
                "local-vc",
                "0x1234",
                100,
                101,
                Some("0xroot1".to_string()),
                &[0u8; 32],
            )
        });

        let handle2 = thread::spawn(move || {
            b2.wait();
            db2.check_and_record_attestation(
                "local-vc",
                "0x1234",
                99,
                101,
                Some("0xroot2".to_string()),
                &[0u8; 32],
            )
        });

        let r1 = handle1.join().expect("thread panicked");
        let r2 = handle2.join().expect("thread panicked");

        // Exactly one should succeed, one should fail
        let successes = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(successes, 1, "exactly one concurrent attestation should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    // --- Startup integrity check tests ---

    #[test]
    fn test_integrity_check_clean_db() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let result = db.check_integrity();
        assert!(result.is_ok());
    }

    #[test]
    fn test_integrity_check_clean_file_db() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("integrity.db");
        let db = SlashingDb::open(&path).expect("failed to open db");
        db.record_attestation("0x1234", 100, 101, None, &TEST_GVR).expect("record");
        let result = db.check_integrity();
        assert!(result.is_ok());
    }

    #[test]
    fn test_integrity_check_returns_error_variant() {
        let err = SlashingError::IntegrityCheckFailed("test failure".to_string());
        match err {
            SlashingError::IntegrityCheckFailed(msg) => assert_eq!(msg, "test failure"),
            _ => panic!("expected IntegrityCheckFailed"),
        }
    }

    #[test]
    fn test_integrity_genesis_validators_root_empty() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root = db.genesis_validators_root().expect("query should succeed");
        assert!(root.is_none());
    }

    #[test]
    fn test_integrity_set_genesis_validators_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        db.set_genesis_validators_root(root).expect("set should succeed");

        let stored = db.genesis_validators_root().expect("query should succeed");
        assert_eq!(stored, Some(root.to_string()));
    }

    #[test]
    fn test_integrity_genesis_validators_root_roundtrip() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        db.set_genesis_validators_root(root).expect("first set should succeed");
        db.set_genesis_validators_root(root).expect("same root should succeed");

        let stored = db.genesis_validators_root().expect("query should succeed");
        assert_eq!(stored, Some(root.to_string()));
    }

    #[test]
    fn test_integrity_genesis_validators_root_mismatch() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let root1 = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";
        let root2 = "0xdifferent00000000000000000000000000000000000000000000000000000000";

        db.set_genesis_validators_root(root1).expect("first set should succeed");
        let result = db.set_genesis_validators_root(root2);
        assert!(result.is_err());

        match result.unwrap_err() {
            SlashingError::GenesisValidatorsRootMismatch { expected, actual } => {
                assert_eq!(expected, root1);
                assert_eq!(actual, root2);
            }
            other => panic!("expected GenesisValidatorsRootMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn test_integrity_genesis_root_persists_across_connections() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("genesis.db");
        let root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            db.set_genesis_validators_root(root).expect("set should succeed");
        }

        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            let stored = db.genesis_validators_root().expect("query should succeed");
            assert_eq!(stored, Some(root.to_string()));
        }
    }

    #[test]
    fn test_integrity_metadata_table_created() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let conn = db.conn.lock();
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = 'metadata'",
                [],
                |row| row.get(0),
            )
            .expect("failed to query tables");
        assert_eq!(table_count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("failed to set permissions");

        // Should not panic, just log a warning
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_writable.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o602))
            .expect("failed to set permissions");

        // Should not panic, just log a warning about world-writable
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_world_readable_and_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_both.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o606))
            .expect("failed to set permissions");

        // Should not panic, just log a warning about both world-readable and world-writable
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_integrity_file_permission_check_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_restricted.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("failed to set permissions");

        // Should not warn
        db.check_file_permissions();
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_ok_for_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_safe.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("failed to set permissions");

        assert!(db.check_file_permissions_strict().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_err_for_0644() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_readable.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("failed to set permissions");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref path, ref mode } => {
                assert!(path.contains("strict_readable.db"));
                assert_eq!(mode, "100644");
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_err_for_0666() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_both.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("failed to set permissions");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref path, ref mode } => {
                assert!(path.contains("strict_both.db"));
                assert_eq!(mode, "100666");
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_returns_err_for_0660_group_access() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("strict_group.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("failed to set permissions");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref path, ref mode } => {
                assert!(path.contains("strict_group.db"));
                assert_eq!(mode, "100660");
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_in_memory_returns_ok() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.check_file_permissions_strict().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_strict_deleted_file_returns_err() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("deleted.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::remove_file(&path).expect("failed to delete file");

        let err = db.check_file_permissions_strict().unwrap_err();
        match err {
            SlashingError::UnsafePermissions { ref mode, .. } => {
                assert!(
                    mode.starts_with("unreadable:"),
                    "expected 'unreadable:' prefix, got: {}",
                    mode
                );
            }
            _ => panic!("expected UnsafePermissions, got {:?}", err),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_file_permissions_warn_detects_group_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("perms_group.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("failed to set permissions");

        // Should not panic, just log a warning about group-readable and group-writable
        db.check_file_permissions();
    }

    #[cfg(not(unix))]
    #[test]
    fn test_check_file_permissions_strict_returns_ok_on_non_unix() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.check_file_permissions_strict().is_ok());
    }

    // --- Watermark and pruning tests ---

    #[test]
    fn test_prune_set_and_get_block_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.get_block_watermark("0x1234").unwrap().is_none());

        db.set_block_watermark("0x1234", 1000).expect("set should succeed");
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(1000));
    }

    #[test]
    fn test_prune_block_watermark_raise_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 1000).expect("set should succeed");
        db.set_block_watermark("0x1234", 2000).expect("raise should succeed");
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(2000));
    }

    #[test]
    fn test_prune_block_watermark_lower_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 2000).expect("set should succeed");
        let result = db.set_block_watermark("0x1234", 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::WatermarkLowered { .. } => {}
            other => panic!("expected WatermarkLowered, got: {other:?}"),
        }
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(2000));
    }

    #[test]
    fn test_prune_block_watermark_same_value_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 1000).expect("set should succeed");
        db.set_block_watermark("0x1234", 1000).expect("same value should succeed");
        assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(1000));
    }

    #[test]
    fn test_prune_set_and_get_attestation_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        assert!(db.get_attestation_watermark("0x1234").unwrap().is_none());

        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((100, 101)));
    }

    #[test]
    fn test_prune_attestation_watermark_raise_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        db.set_attestation_watermark("0x1234", 200, 201).expect("raise should succeed");
        assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((200, 201)));
    }

    #[test]
    fn test_prune_attestation_watermark_lower_source_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 200, 201).expect("set should succeed");
        let result = db.set_attestation_watermark("0x1234", 100, 300);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::WatermarkLowered { .. } => {}
            other => panic!("expected WatermarkLowered, got: {other:?}"),
        }
    }

    #[test]
    fn test_prune_attestation_watermark_lower_target_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 200, 201).expect("set should succeed");
        let result = db.set_attestation_watermark("0x1234", 300, 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::WatermarkLowered { .. } => {}
            other => panic!("expected WatermarkLowered, got: {other:?}"),
        }
    }

    #[test]
    fn test_prune_attestation_watermark_same_value_succeeds() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        db.set_attestation_watermark("0x1234", 100, 101).expect("same should succeed");
        assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((100, 101)));
    }

    #[test]
    fn test_prune_watermarks_persist_across_connections() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("watermarks.db");

        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            db.set_block_watermark("0x1234", 1000).expect("set should succeed");
            db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");
        }

        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            assert_eq!(db.get_block_watermark("0x1234").unwrap(), Some(1000));
            assert_eq!(db.get_attestation_watermark("0x1234").unwrap(), Some((100, 101)));
        }
    }

    #[test]
    fn test_prune_watermarks_per_validator_isolated() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1111", 1000).expect("set should succeed");
        db.set_block_watermark("0x2222", 2000).expect("set should succeed");

        assert_eq!(db.get_block_watermark("0x1111").unwrap(), Some(1000));
        assert_eq!(db.get_block_watermark("0x2222").unwrap(), Some(2000));
        assert!(db.get_block_watermark("0x3333").unwrap().is_none());
    }

    #[test]
    fn test_prune_is_safe_to_propose_rejects_below_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 1000).expect("set should succeed");

        let result = db.is_safe_to_propose("0x1234", 999, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowBlockWatermark { slot: 999, watermark_slot: 1000 } => {}
            other => panic!("expected BelowBlockWatermark, got: {other:?}"),
        }

        // At watermark should be fine
        assert!(db.is_safe_to_propose("0x1234", 1000, None).is_ok());
        // Above watermark should be fine
        assert!(db.is_safe_to_propose("0x1234", 1001, None).is_ok());
    }

    #[test]
    fn test_prune_is_safe_to_sign_rejects_below_target_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");

        // source=100 is at source watermark, but target=100 < target watermark=101
        let result = db.is_safe_to_sign("0x1234", 100, 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowAttestationWatermark {
                target_epoch: 100,
                watermark_target: 101,
            } => {}
            other => panic!("expected BelowAttestationWatermark, got: {other:?}"),
        }

        // At watermark should be fine
        assert!(db.is_safe_to_sign("0x1234", 101, 102).is_ok());
    }

    #[test]
    fn test_prune_check_and_record_block_rejects_below_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_block_watermark("0x1234", 1000).expect("set should succeed");

        let result = db.check_and_record_block("local-vc", "0x1234", 999, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowBlockWatermark { .. } => {}
            other => panic!("expected BelowBlockWatermark, got: {other:?}"),
        }

        // Should not have recorded anything
        assert!(db.get_blocks("0x1234").unwrap().is_empty());
    }

    #[test]
    fn test_prune_check_and_record_attestation_rejects_below_target_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 100, 101).expect("set should succeed");

        // source=100 is at source watermark, but target=100 < target watermark=101
        let result =
            db.check_and_record_attestation("local-vc", "0x1234", 100, 100, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowAttestationWatermark { .. } => {}
            other => panic!("expected BelowAttestationWatermark, got: {other:?}"),
        }

        assert!(db.get_attestations("0x1234").unwrap().is_empty());
    }

    #[test]
    fn test_prune_is_safe_to_sign_rejects_below_source_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 20, 20).expect("set should succeed");

        // source=1 is below source watermark=20, even though target=31 is above target watermark
        let result = db.is_safe_to_sign("0x1234", 1, 31);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowAttestationSourceWatermark {
                source_epoch: 1,
                watermark_source: 20,
            } => {}
            other => panic!("expected BelowAttestationSourceWatermark, got: {other:?}"),
        }

        // At source watermark should be fine
        assert!(db.is_safe_to_sign("0x1234", 20, 31).is_ok());
    }

    #[test]
    fn test_prune_check_and_record_attestation_rejects_below_source_watermark() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        db.set_attestation_watermark("0x1234", 20, 20).expect("set should succeed");

        // source=1 is below source watermark=20
        let result = db.check_and_record_attestation("local-vc", "0x1234", 1, 31, None, &[0u8; 32]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::BelowAttestationSourceWatermark { .. } => {}
            other => panic!("expected BelowAttestationSourceWatermark, got: {other:?}"),
        }

        // Should not have recorded anything
        assert!(db.get_attestations("0x1234").unwrap().is_empty());
    }

    #[test]
    fn test_prune_below_watermarks_deletes_correct_records() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Insert blocks: 100, 200, 300, 400, 500
        for slot in [100, 200, 300, 400, 500] {
            db.record_block("0x1234", slot, None, &TEST_GVR).expect("record should succeed");
        }

        // Insert attestations: target epochs 10, 20, 30, 40, 50
        for (src, tgt) in [(5, 10), (10, 20), (20, 30), (30, 40), (40, 50)] {
            db.record_attestation("0x1234", src, tgt, None, &TEST_GVR)
                .expect("record should succeed");
        }

        // Set watermarks: block at 300, attestation at (20, 30)
        db.set_block_watermark("0x1234", 300).expect("set should succeed");
        db.set_attestation_watermark("0x1234", 20, 30).expect("set should succeed");

        let stats = db.prune_below_watermarks().expect("prune should succeed");

        // Blocks below 300: slots 100, 200 → 2 deleted
        assert_eq!(stats.blocks_deleted, 2);
        // Attestations below target 30: target epochs 10, 20 → 2 deleted
        assert_eq!(stats.attestations_deleted, 2);

        // Verify remaining records
        let blocks = db.get_blocks("0x1234").unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].slot, 300);

        let attestations = db.get_attestations("0x1234").unwrap();
        assert_eq!(attestations.len(), 3);
        assert_eq!(attestations[0].target_epoch, 30);
    }

    #[test]
    fn test_prune_without_watermarks_fails() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Insert some records but no watermarks
        db.record_block("0x1234", 100, None, &TEST_GVR).expect("record should succeed");
        db.record_attestation("0x1234", 5, 10, None, &TEST_GVR).expect("record should succeed");

        let result = db.prune_below_watermarks();
        assert!(result.is_err());
        match result.unwrap_err() {
            SlashingError::NoWatermarksSet => {}
            other => panic!("expected NoWatermarksSet, got: {other:?}"),
        }

        // Records should still be intact
        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 1);
        assert_eq!(db.get_attestations("0x1234").unwrap().len(), 1);
    }

    #[test]
    fn test_prune_multiple_validators() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Validator 1: blocks at 100, 200; watermark at 200
        db.record_block("0x1111", 100, None, &TEST_GVR).expect("record");
        db.record_block("0x1111", 200, None, &TEST_GVR).expect("record");
        db.set_block_watermark("0x1111", 200).expect("set");

        // Validator 2: blocks at 300, 400; watermark at 350
        db.record_block("0x2222", 300, None, &TEST_GVR).expect("record");
        db.record_block("0x2222", 400, None, &TEST_GVR).expect("record");
        db.set_block_watermark("0x2222", 350).expect("set");

        let stats = db.prune_below_watermarks().expect("prune should succeed");

        // V1: slot 100 < 200 → deleted; V2: slot 300 < 350 → deleted
        assert_eq!(stats.blocks_deleted, 2);

        assert_eq!(db.get_blocks("0x1111").unwrap().len(), 1);
        assert_eq!(db.get_blocks("0x2222").unwrap().len(), 1);
    }

    #[test]
    fn test_prune_nothing_to_prune() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // All records are at or above watermark
        db.record_block("0x1234", 200, None, &TEST_GVR).expect("record");
        db.record_block("0x1234", 300, None, &TEST_GVR).expect("record");
        db.set_block_watermark("0x1234", 100).expect("set");

        let stats = db.prune_below_watermarks().expect("prune should succeed");
        assert_eq!(stats.blocks_deleted, 0);
        assert_eq!(stats.attestations_deleted, 0);

        assert_eq!(db.get_blocks("0x1234").unwrap().len(), 2);
    }

    #[test]
    fn test_prune_watermarks_table_created_on_migration() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let conn = db.conn.lock();
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = 'watermarks'",
                [],
                |row| row.get(0),
            )
            .expect("failed to query tables");
        assert_eq!(table_count, 1);
    }

    #[test]
    fn test_open_sets_wal_journal_mode() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("wal_test.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        let conn = db.conn.lock();
        let mode: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0)).unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn test_open_sets_synchronous_extra() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("sync_test.db");
        let db = SlashingDb::open(&path).expect("failed to open db");

        let conn = db.conn.lock();
        let sync_mode: i64 =
            conn.pragma_query_value(None, "synchronous", |row| row.get(0)).unwrap();
        // EXTRA = 3 (belt-and-braces: FULL + dir-fsync on DELETE-mode journal unlink)
        assert_eq!(sync_mode, 3, "synchronous should be 3 (EXTRA), got {sync_mode}");
    }

    #[test]
    fn test_wal_crash_durability() {
        let dir = tempdir().expect("failed to create temp dir");
        let path = dir.path().join("durability_test.db");

        let pubkey = "0xabcdef1234567890";

        // Write a record, then drop without explicit close
        {
            let db = SlashingDb::open(&path).expect("failed to open db");
            db.record_attestation(pubkey, 1, 2, Some("0xroot".to_string()), &TEST_GVR)
                .expect("record failed");
            // Drop db without explicit close — WAL should ensure durability
        }

        // Reopen and verify the record persisted
        {
            let db = SlashingDb::open(&path).expect("failed to reopen db");
            let attestations = db.get_attestations(pubkey).expect("query failed");
            assert_eq!(attestations.len(), 1);
            assert_eq!(attestations[0].source_epoch, 1);
            assert_eq!(attestations[0].target_epoch, 2);
        }
    }

    #[test]
    fn test_import_atomic_success() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data: vec![
                ValidatorRecord {
                    pubkey: "0xaaa".to_string(),
                    signed_blocks: vec![InterchangeBlock {
                        slot: "10".to_string(),
                        signing_root: None,
                    }],
                    signed_attestations: vec![InterchangeAttestation {
                        source_epoch: "1".to_string(),
                        target_epoch: "2".to_string(),
                        signing_root: None,
                    }],
                },
                ValidatorRecord {
                    pubkey: "0xbbb".to_string(),
                    signed_blocks: vec![InterchangeBlock {
                        slot: "20".to_string(),
                        signing_root: Some("0xroot".to_string()),
                    }],
                    signed_attestations: vec![InterchangeAttestation {
                        source_epoch: "3".to_string(),
                        target_epoch: "4".to_string(),
                        signing_root: Some("0xroot2".to_string()),
                    }],
                },
            ],
        };

        db.import(&interchange, genesis_root).expect("import should succeed");

        let att_a = db.get_attestations("0xaaa").expect("query failed");
        assert_eq!(att_a.len(), 1);
        assert_eq!(att_a[0].source_epoch, 1);

        let blocks_b = db.get_blocks("0xbbb").expect("query failed");
        assert_eq!(blocks_b.len(), 1);
        assert_eq!(blocks_b[0].slot, 20);
    }

    #[test]
    fn test_import_atomic_rollback_on_error() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        // Validators 1-5 are valid, validator 6 has invalid epoch
        let mut data = Vec::new();
        for i in 0..5 {
            data.push(ValidatorRecord {
                pubkey: format!("0x{:04x}", i),
                signed_blocks: vec![InterchangeBlock {
                    slot: format!("{}", i * 100),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: format!("{}", i),
                    target_epoch: format!("{}", i + 1),
                    signing_root: None,
                }],
            });
        }
        // Validator 6 with invalid epoch
        data.push(ValidatorRecord {
            pubkey: "0xbad".to_string(),
            signed_blocks: vec![],
            signed_attestations: vec![InterchangeAttestation {
                source_epoch: "not_a_number".to_string(),
                target_epoch: "10".to_string(),
                signing_root: None,
            }],
        });

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data,
        };

        let result = db.import(&interchange, genesis_root);
        assert!(result.is_err());

        // All 5 valid validators should have zero records due to rollback
        for i in 0..5 {
            let pubkey = format!("0x{:04x}", i);
            let attestations = db.get_attestations(&pubkey).expect("query failed");
            assert_eq!(
                attestations.len(),
                0,
                "validator {} should have no attestations after rollback",
                i
            );
            let blocks = db.get_blocks(&pubkey).expect("query failed");
            assert_eq!(blocks.len(), 0, "validator {} should have no blocks after rollback", i);
        }
    }

    #[test]
    fn test_import_atomic_large_batch() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");
        let genesis_root = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

        let mut data = Vec::new();
        for i in 0..1000 {
            data.push(ValidatorRecord {
                pubkey: format!("0x{:06x}", i),
                signed_blocks: vec![InterchangeBlock {
                    slot: format!("{}", i * 10),
                    signing_root: None,
                }],
                signed_attestations: vec![InterchangeAttestation {
                    source_epoch: format!("{}", i),
                    target_epoch: format!("{}", i + 1),
                    signing_root: None,
                }],
            });
        }

        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: genesis_root.to_string(),
            },
            data,
        };

        db.import(&interchange, genesis_root).expect("large import should succeed");

        // Spot-check a few validators
        let att_0 = db.get_attestations("0x000000").expect("query failed");
        assert_eq!(att_0.len(), 1);
        let att_999 = db.get_attestations("0x0003e7").expect("query failed");
        assert_eq!(att_999.len(), 1);
        assert_eq!(att_999[0].source_epoch, 999);

        let blocks_500 = db.get_blocks("0x0001f4").expect("query failed");
        assert_eq!(blocks_500.len(), 1);
        assert_eq!(blocks_500[0].slot, 5000);
    }
}

/// Living documentation tests for EIP-3076 edge case decisions.
///
/// These tests codify the rationale behind FU-32 and FU-33 slashing
/// protection decisions. Each test documents a specific edge case with
/// references to the relevant EIP-3076 section. Future developers
/// should read these tests to understand *why* the code behaves this way.
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    const TEST_GVR: Root = [0u8; 32];

    // ── FU-32: Same signing_root but different source_epoch ──────────
    //
    // EIP-3076 defines signing_root as hash_tree_root(AttestationData).
    // AttestationData includes both source and target. Therefore, if two
    // attestations share the same signing_root, they MUST have identical
    // source_epoch, target_epoch, and beacon_block_root.
    //
    // If we ever see same root + different source, it indicates a bug in
    // the signing pipeline (e.g., incorrect root computation). We log a
    // warning but still allow the attestation because:
    //   1. The signing_root match means it's the same logical message.
    //   2. Rejecting would be overly strict — the validator already signed
    //      this exact data.
    //   3. The mismatch is physically impossible under correct SSZ, so
    //      rejection would only punish buggy-but-non-slashable clients.

    #[test]
    fn test_fu32_same_root_same_source_silent_pass() {
        // EIP-3076 Condition 5: re-signing the same attestation is safe.
        // When signing_root matches AND source matches, this is a genuine
        // idempotent re-sign. No warning, no rejection.
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation(
            "local-vc",
            "0xval",
            10,
            20,
            Some("0xdeadbeef".into()),
            &[0u8; 32],
        )
        .expect("initial attestation");

        // Identical re-sign: same source, same target, same root
        let result = db.check_and_record_attestation(
            "local-vc",
            "0xval",
            10,
            20,
            Some("0xdeadbeef".into()),
            &[0u8; 32],
        );
        assert!(result.is_ok(), "identical re-sign must be allowed silently");

        // Should not create a duplicate record
        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    #[test]
    fn test_fu32_same_root_different_source_warns_but_allows() {
        // EIP-3076 Condition 5 + FU-32 defense-in-depth:
        //
        // This scenario is physically impossible under correct SSZ because
        // signing_root = hash_tree_root(AttestationData) which includes
        // source_epoch. If it occurs, something is wrong in the signing
        // pipeline (e.g., root was copied from a different attestation).
        //
        // Decision: LOG WARNING but ALLOW the attestation.
        // Rationale: the root match proves it's the same data, so rejecting
        // would only hurt a client with a minor bookkeeping bug.
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation(
            "local-vc",
            "0xval",
            10,
            20,
            Some("0xdeadbeef".into()),
            &[0u8; 32],
        )
        .expect("initial attestation");

        // Same root but source_epoch differs (10 → 15): warns internally
        let result = db.check_and_record_attestation(
            "local-vc",
            "0xval",
            15,
            20,
            Some("0xdeadbeef".into()),
            &[0u8; 32],
        );
        assert!(
            result.is_ok(),
            "same root with different source must still be allowed (defense-in-depth warning only)"
        );

        // No duplicate inserted
        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    // ── FU-33: None==None signing root semantics ─────────────────────
    //
    // EIP-3076 notes that signing_root "can be missing for legacy records."
    // The spec recommends assigning a dummy root internally.
    //
    // Problem: if both the existing record and the new attestation have
    // None as signing_root, are they the same attestation (re-sign) or
    // different attestations (double vote)?
    //
    // We cannot know — hence the choice is a policy decision:
    //
    // - Lenient (default, strict_semantics=false): treat None==None as
    //   re-sign. This is safer for operators with legacy records that
    //   pre-date root recording. Avoids false-positive rejections.
    //
    // - Strict (strict_semantics=true): treat None==None as a potential
    //   double vote. This matches the conservative behavior of Lighthouse,
    //   Prysm, and Teku. Recommended for new deployments where all records
    //   should have roots.

    #[test]
    fn test_fu33_none_none_lenient_allows() {
        // Default (lenient) mode: None==None at same target is treated as
        // an idempotent re-sign. This preserves backward compatibility with
        // legacy slashing protection records that lack signing_root.
        //
        // EIP-3076 §Conditions: "If signing_root is not provided, the
        // implementation should treat it as 'unknown'."
        // Our lenient interpretation: unknown == unknown → same message.
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation("local-vc", "0xval", 10, 20, None, &[0u8; 32])
            .expect("initial attestation without root");

        let result = db.check_and_record_attestation("local-vc", "0xval", 10, 20, None, &[0u8; 32]);
        assert!(result.is_ok(), "lenient mode: None==None must be allowed as re-sign");
    }

    #[test]
    fn test_fu33_none_none_strict_rejects() {
        // Strict mode: None==None at same target is rejected as a potential
        // double vote. Without a signing_root, we cannot prove the two
        // attestations contain the same data.
        //
        // EIP-3076 §Conditions: "If signing_root is not provided, the
        // implementation should treat it as 'unknown'."
        // Our strict interpretation: unknown == unknown → could be different
        // messages → reject to be safe.
        //
        // This matches Lighthouse/Prysm/Teku conservative behavior and is
        // recommended for new deployments where all attestations should
        // have signing_root populated.
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);

        db.check_and_record_attestation("local-vc", "0xval", 10, 20, None, &[0u8; 32])
            .expect("initial attestation without root");

        let result = db.check_and_record_attestation("local-vc", "0xval", 10, 20, None, &[0u8; 32]);
        assert!(
            result.is_err(),
            "strict mode: None==None must be rejected as potential double vote"
        );
    }

    #[test]
    fn test_fu33_none_vs_some_always_rejects() {
        // Regardless of strict/lenient mode, None vs Some (or Some vs None)
        // at the same target epoch is ALWAYS rejected as a double vote.
        //
        // Rationale: if one attestation has a known root and the other doesn't,
        // we cannot prove they are the same message. The safe choice is to
        // reject. This is unambiguous in EIP-3076 — different roots (including
        // the absence of one) at the same target = double vote.
        let db = SlashingDb::open_in_memory().expect("open");

        // Case 1: existing=Some, new=None
        db.check_and_record_attestation(
            "local-vc",
            "0xval_a",
            10,
            20,
            Some("0xroot".into()),
            &[0u8; 32],
        )
        .expect("initial with root");
        let result =
            db.check_and_record_attestation("local-vc", "0xval_a", 10, 20, None, &[0u8; 32]);
        assert!(result.is_err(), "Some vs None must always reject");

        // Case 2: existing=None, new=Some
        db.check_and_record_attestation("local-vc", "0xval_b", 10, 20, None, &[0u8; 32])
            .expect("initial without root");
        let result = db.check_and_record_attestation(
            "local-vc",
            "0xval_b",
            10,
            20,
            Some("0xroot".into()),
            &[0u8; 32],
        );
        assert!(result.is_err(), "None vs Some must always reject");
    }

    #[test]
    fn test_fu33_strict_block_none_none_rejects() {
        // FU-33 strict semantics also applies to block proposals.
        //
        // EIP-3076 block signing_root = hash_tree_root(BeaconBlock).
        // Same policy: in strict mode, None==None at the same slot is
        // rejected because we cannot confirm it's the same block.
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_strict_semantics(true);

        db.check_and_record_block("local-vc", "0xval", 500, None, &[0u8; 32])
            .expect("initial block without root");

        let result = db.check_and_record_block("local-vc", "0xval", 500, None, &[0u8; 32]);
        assert!(
            result.is_err(),
            "strict mode: None==None block must be rejected as potential double proposal"
        );
    }

    // LOW-13: Validate interchange_format_version on import
    #[test]
    fn test_import_rejects_wrong_interchange_version() {
        let db = SlashingDb::open_in_memory().expect("open");
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "4".to_string(),
                genesis_validators_root: "0xroot".to_string(),
            },
            data: vec![],
        };
        let err = db.import(&interchange, "0xroot").unwrap_err();
        assert!(err.to_string().contains("unsupported interchange_format_version"));
        assert!(err.to_string().contains("\"4\""));
    }

    #[test]
    fn test_import_accepts_version_5() {
        let db = SlashingDb::open_in_memory().expect("open");
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: "0xroot".to_string(),
            },
            data: vec![],
        };
        assert!(db.import(&interchange, "0xroot").is_ok());
    }

    // LOW-14: Normalize pubkeys
    #[test]
    fn test_pubkey_normalization_case_insensitive() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.record_attestation("0xABCD", 1, 2, None, &TEST_GVR).expect("insert");
        let results = db.get_attestations("0xabcd").expect("get");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_pubkey_normalization_adds_prefix() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.record_block("ABCD", 100, None, &TEST_GVR).expect("insert");
        let results = db.get_blocks("0xabcd").expect("get");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_pubkey_normalization_already_normalized() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.record_block("0xabcd", 100, None, &TEST_GVR).expect("insert");
        let results = db.get_blocks("0xabcd").expect("get");
        assert_eq!(results.len(), 1);
    }

    // LOW-15: Transactional set_block_watermark
    #[test]
    fn test_set_block_watermark_is_transactional() {
        let db = SlashingDb::open_in_memory().expect("open");
        db.set_block_watermark("0xval", 100).expect("set");
        assert_eq!(db.get_block_watermark("0xval").expect("get"), Some(100));
        db.set_block_watermark("0xval", 200).expect("raise");
        assert_eq!(db.get_block_watermark("0xval").expect("get"), Some(200));
    }

    // Finding #16: Epoch 0 / Slot 0 slashing protection boundary tests

    #[test]
    fn test_attestation_at_epoch_zero() {
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_attestation(
            "local-vc",
            "0xval",
            0,
            0,
            Some("0xroot_a".into()),
            &[0u8; 32],
        )
        .expect("first attestation at epoch 0");

        let result = db.check_and_record_attestation(
            "local-vc",
            "0xval",
            0,
            0,
            Some("0xroot_b".into()),
            &[0u8; 32],
        );
        assert!(result.is_err(), "double vote at target epoch 0 must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::DoubleVote {
                target_epoch,
            }) => {
                assert_eq!(target_epoch, 0);
            }
            other => panic!("expected DoubleVote at epoch 0, got: {other:?}"),
        }

        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    #[test]
    fn test_surround_vote_at_epoch_zero_boundary() {
        let db = SlashingDb::open_in_memory().expect("open");

        // Wide attestation: source=0, target=2
        db.check_and_record_attestation(
            "local-vc",
            "0xval",
            0,
            2,
            Some("0xroot_wide".into()),
            &[0u8; 32],
        )
        .expect("wide attestation at epoch 0 boundary");

        // Narrow attestation: source=1, target=1 — surrounded by (0,2)
        // existing_source(0) < new_source(1) AND existing_target(2) > new_target(1)
        let result = db.check_and_record_attestation(
            "local-vc",
            "0xval",
            1,
            1,
            Some("0xroot_narrow".into()),
            &[0u8; 32],
        );
        assert!(result.is_err(), "surrounded vote at epoch 0 boundary must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::SurroundedVote {
                ..
            }) => {}
            other => panic!("expected SurroundedVote, got: {other:?}"),
        }

        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    #[test]
    fn test_block_proposal_at_slot_zero() {
        let db = SlashingDb::open_in_memory().expect("open");

        db.check_and_record_block("local-vc", "0xval", 0, Some("0xblock_a".into()), &[0u8; 32])
            .expect("first block at slot 0");

        let result =
            db.check_and_record_block("local-vc", "0xval", 0, Some("0xblock_b".into()), &[0u8; 32]);
        assert!(result.is_err(), "double proposal at slot 0 must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableBlock(BlockSlashingViolation::DoubleBlockProposal { slot }) => {
                assert_eq!(slot, 0);
            }
            other => panic!("expected DoubleBlockProposal at slot 0, got: {other:?}"),
        }

        assert_eq!(db.get_blocks("0xval").unwrap().len(), 1);
    }

    // Finding #30: Surrounded vote test at check_and_record level

    #[test]
    fn test_surrounded_vote_at_check_and_record_level() {
        let db = SlashingDb::open_in_memory().expect("open");

        // Wide attestation: source=2, target=10
        db.check_and_record_attestation(
            "local-vc",
            "0xval",
            2,
            10,
            Some("0xroot_wide".into()),
            &[0u8; 32],
        )
        .expect("wide attestation");

        // Narrow attestation: source=5, target=7 — surrounded by (2,10)
        // existing_source(2) < new_source(5) AND existing_target(10) > new_target(7)
        let result = db.check_and_record_attestation(
            "local-vc",
            "0xval",
            5,
            7,
            Some("0xroot_narrow".into()),
            &[0u8; 32],
        );
        assert!(result.is_err(), "surrounded vote must be rejected");
        match result.unwrap_err() {
            SlashingError::SlashableAttestation(AttestationSlashingViolation::SurroundedVote {
                ..
            }) => {}
            other => panic!("expected SurroundedVote, got: {other:?}"),
        }

        assert_eq!(db.get_attestations("0xval").unwrap().len(), 1);
    }

    // LOW-17: File permissions on DB creation
    #[cfg(unix)]
    #[test]
    fn test_open_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test_perms.db");
        let _db = SlashingDb::open(&path).expect("open");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "DB file should have 0o600 permissions, got {:o}",
            mode & 0o777
        );
    }

    /// Post-2.5 invariant: every new row written by `check_and_record_block`,
    /// `check_and_record_attestation`, AND the `PubkeyScopedDb`/`stage_*` path
    /// carries `AUDIT_ORIGIN` (`"local-vc"`) in the `client_cn` column, regardless
    /// of the `_client_cn` argument supplied by the caller.
    ///
    /// This pins the guarantee that the DB column is always canonical, so a future
    /// reader querying `SELECT client_cn …` sees a predictable value.
    #[test]
    fn test_new_rows_store_audit_origin() {
        use rusqlite::Connection;
        use tempfile::tempdir;

        const PUBKEY_BLOCK: &str =
            "0xabababababababababababababababababababababababababababababababababababababababababababababababababababab";
        const PUBKEY_ATT: &str =
            "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        const GVR: [u8; 32] = [0u8; 32];

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit_origin.db");
        let db = SlashingDb::open(&path).expect("open file db");

        // check_and_record_block: caller passes arbitrary CN, row must carry AUDIT_ORIGIN.
        db.check_and_record_block(
            "arbitrary-caller-cn",
            PUBKEY_BLOCK,
            500,
            Some("0xblockroot".to_string()),
            &GVR,
        )
        .expect("check_and_record_block must succeed");

        // check_and_record_attestation: same invariant.
        db.check_and_record_attestation(
            "another-arbitrary-cn",
            PUBKEY_ATT,
            10,
            20,
            Some("0xattroot".to_string()),
            &GVR,
        )
        .expect("check_and_record_attestation must succeed");

        // stage_block via PubkeyScopedDb (the RAII path).
        {
            use crate::PubkeyScopedDb;
            use std::sync::Arc;
            let db_arc = Arc::new(SlashingDb::open(&path).expect("open for scoped"));
            let scoped = PubkeyScopedDb::new(Arc::clone(&db_arc), "peer-dvt-x".to_string(), GVR);
            scoped
                .stage_block(PUBKEY_BLOCK, 501, Some("0xscopedroot".to_string()))
                .expect("scoped stage_block must succeed")
                .commit()
                .expect("commit");
        }

        drop(db);

        // Inspect the rows directly to confirm all client_cn values = AUDIT_ORIGIN.
        let conn = Connection::open(&path).expect("direct open");

        let block_cns: Vec<String> = {
            let mut stmt =
                conn.prepare("SELECT client_cn FROM blocks ORDER BY slot").expect("prepare");
            stmt.query_map([], |row| row.get(0))
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect")
        };

        assert!(
            block_cns.iter().all(|cn| cn == crate::stage::AUDIT_ORIGIN),
            "all block rows must carry AUDIT_ORIGIN; got: {block_cns:?}"
        );

        let att_cns: Vec<String> = {
            let mut stmt = conn.prepare("SELECT client_cn FROM attestations").expect("prepare");
            stmt.query_map([], |row| row.get(0))
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect")
        };

        assert!(
            att_cns.iter().all(|cn| cn == crate::stage::AUDIT_ORIGIN),
            "all attestation rows must carry AUDIT_ORIGIN; got: {att_cns:?}"
        );
    }
}
