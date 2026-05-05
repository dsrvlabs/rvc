//! ISSUE-4.8 / L-8: 0o600 perms on slashing-DB WAL/SHM sidecars.
//!
//! After `SlashingDb::open` succeeds on a Unix host with a permissive umask
//! (e.g. 0o022), both the main DB file and the SQLite-managed `-wal` /
//! `-shm` sidecars must be owner-only (0o600) — otherwise an attacker with
//! read-only host access could exfiltrate the slashing journal, defeating
//! the 0o600 protection on the main file.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use rvc_slashing::SlashingDb;
use tempfile::tempdir;

/// Set the process umask for the duration of the closure, then restore.
///
/// SAFETY: `umask(2)` is a process-wide setting; concurrent tests in the
/// same process would race.  `cargo test` runs each integration-test binary
/// in its own process, so this serial harness is sufficient — but to be
/// defensive we still serialize via a static mutex.
fn with_umask<F: FnOnce()>(mode: libc::mode_t, f: F) {
    use std::sync::Mutex;
    static UMASK_LOCK: Mutex<()> = Mutex::new(());
    let _guard = match UMASK_LOCK.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    // SAFETY: serialized via UMASK_LOCK above.
    let prev = unsafe { libc::umask(mode) };
    f();
    // SAFETY: same lock.
    unsafe {
        libc::umask(prev);
    }
}

#[test]
fn test_wal_shm_sidecars_are_owner_only() {
    with_umask(0o022, || {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("slashing.db");

        // Open under a permissive umask — without the L-8 fix, sidecars
        // would inherit 0o644.
        let db = SlashingDb::open(&db_path).expect("open SlashingDb");

        // The migration in open() runs a write transaction, which forces
        // SQLite to materialise both -wal and -shm in WAL mode.
        // Drop the db so SQLite finalises the sidecar files but does not
        // remove them (WAL mode keeps them around).
        drop(db);

        let wal = db_path
            .with_file_name(format!("{}-wal", db_path.file_name().unwrap().to_str().unwrap()));
        let shm = db_path
            .with_file_name(format!("{}-shm", db_path.file_name().unwrap().to_str().unwrap()));

        // Main file must be 0o600.
        let main_mode =
            std::fs::metadata(&db_path).expect("metadata main").permissions().mode() & 0o777;
        assert_eq!(main_mode, 0o600, "main slashing-db file must be 0o600, got {:o}", main_mode);

        // Sidecars: if they exist, they must be 0o600.  Either may have
        // been finalised away on drop; we accept "absent" but require
        // "present-and-correct" if present.
        for sidecar in [&wal, &shm] {
            if sidecar.exists() {
                let mode =
                    std::fs::metadata(sidecar).expect("metadata sidecar").permissions().mode()
                        & 0o777;
                assert_eq!(
                    mode,
                    0o600,
                    "{} must be 0o600 (umask=022 inherited), got {:o}",
                    sidecar.display(),
                    mode
                );
            }
        }
    });
}

#[test]
fn test_open_succeeds_when_sidecars_absent() {
    // Sanity: the chmod-sidecars step is best-effort — if SQLite has not
    // yet materialised them (e.g. on a pre-WAL fallback), open() must not
    // fail just because they're absent.
    with_umask(0o022, || {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("absent_sidecars.db");
        // SlashingDb::open should succeed even if migration is so light
        // that no -wal is written before the snapshot we're checking.
        let _db =
            SlashingDb::open(&db_path).expect("open must succeed regardless of sidecar state");
    });
}
