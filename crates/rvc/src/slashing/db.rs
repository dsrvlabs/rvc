//! SQLite database layer for slashing protection.

use std::path::Path;

use rusqlite::Connection;

use super::error::{AttestationSlashingViolation, SlashingError};
use super::types::{SignedAttestation, SignedBlock};
use crate::crypto::Epoch;

/// SQLite-backed database for storing slashing protection data.
pub struct SlashingDb {
    conn: Connection,
}

impl SlashingDb {
    /// Open a database at the specified path.
    /// Creates the file and runs migrations if it doesn't exist.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SlashingError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database for testing.
    pub fn open_in_memory() -> Result<Self, SlashingError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), SlashingError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS attestations (
                id INTEGER PRIMARY KEY,
                pubkey TEXT NOT NULL,
                source_epoch INTEGER NOT NULL,
                target_epoch INTEGER NOT NULL,
                signing_root TEXT,
                UNIQUE(pubkey, target_epoch)
            );

            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY,
                pubkey TEXT NOT NULL,
                slot INTEGER NOT NULL,
                signing_root TEXT,
                UNIQUE(pubkey, slot)
            );
            ",
        )?;
        Ok(())
    }

    /// Insert a signed attestation record.
    pub fn insert_attestation(&self, attestation: &SignedAttestation) -> Result<(), SlashingError> {
        self.conn.execute(
            "INSERT INTO attestations (pubkey, source_epoch, target_epoch, signing_root)
             VALUES (?1, ?2, ?3, ?4)",
            (
                &attestation.pubkey,
                attestation.source_epoch as i64,
                attestation.target_epoch as i64,
                &attestation.signing_root,
            ),
        )?;
        Ok(())
    }

    /// Record a signed attestation with idempotent behavior.
    ///
    /// If an attestation with the same pubkey and target_epoch already exists,
    /// the operation silently succeeds without modifying the existing record.
    /// This makes the operation safe to retry.
    pub fn record_attestation(
        &self,
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: Option<String>,
    ) -> Result<(), SlashingError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO attestations (pubkey, source_epoch, target_epoch, signing_root)
             VALUES (?1, ?2, ?3, ?4)",
            (pubkey, source_epoch as i64, target_epoch as i64, &signing_root),
        )?;
        Ok(())
    }

    /// Get all attestations for a given public key.
    pub fn get_attestations(&self, pubkey: &str) -> Result<Vec<SignedAttestation>, SlashingError> {
        let mut stmt = self.conn.prepare(
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

    /// Insert a signed block record.
    pub fn insert_block(&self, block: &SignedBlock) -> Result<(), SlashingError> {
        self.conn.execute(
            "INSERT INTO blocks (pubkey, slot, signing_root)
             VALUES (?1, ?2, ?3)",
            (&block.pubkey, block.slot as i64, &block.signing_root),
        )?;
        Ok(())
    }

    /// Get all blocks for a given public key.
    pub fn get_blocks(&self, pubkey: &str) -> Result<Vec<SignedBlock>, SlashingError> {
        let mut stmt = self.conn.prepare(
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
        let mut stmt = self.conn.prepare(
            "SELECT source_epoch, target_epoch
             FROM attestations
             WHERE pubkey = ?1",
        )?;

        let rows = stmt.query_map([pubkey], |row| {
            Ok((row.get::<_, i64>(0)? as Epoch, row.get::<_, i64>(1)? as Epoch))
        })?;

        for row in rows {
            let (existing_source, existing_target) = row?;

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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

        let table_count: i64 = db
            .conn
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

        db.insert_attestation(&attestation).expect("failed to insert");

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

        db.insert_attestation(&attestation).expect("failed to insert");

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
            db.insert_attestation(a).expect("failed to insert");
        }

        let result = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].target_epoch, 101);
        assert_eq!(result[1].target_epoch, 102);
    }

    #[test]
    fn test_attestation_unique_constraint() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };

        db.insert_attestation(&attestation).expect("first insert should succeed");

        let duplicate = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 99,
            target_epoch: 101,
            signing_root: Some("0xdifferent".to_string()),
        };

        let result = db.insert_attestation(&duplicate);
        assert!(result.is_err());
    }

    #[test]
    fn test_insert_and_get_block() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let block = SignedBlock {
            pubkey: "0x1234".to_string(),
            slot: 1000,
            signing_root: Some("0xabcd".to_string()),
        };

        db.insert_block(&block).expect("failed to insert");

        let blocks = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], block);
    }

    #[test]
    fn test_insert_block_without_signing_root() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let block = SignedBlock { pubkey: "0x1234".to_string(), slot: 1000, signing_root: None };

        db.insert_block(&block).expect("failed to insert");

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
            db.insert_block(b).expect("failed to insert");
        }

        let result = db.get_blocks("0x1234").expect("failed to get");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].slot, 1000);
        assert_eq!(result[1].slot, 1001);
    }

    #[test]
    fn test_block_unique_constraint() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let block = SignedBlock { pubkey: "0x1234".to_string(), slot: 1000, signing_root: None };

        db.insert_block(&block).expect("first insert should succeed");

        let duplicate = SignedBlock {
            pubkey: "0x1234".to_string(),
            slot: 1000,
            signing_root: Some("0xdifferent".to_string()),
        };

        let result = db.insert_block(&duplicate);
        assert!(result.is_err());
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

        db.insert_attestation(&attestation1).expect("failed to insert");
        db.insert_attestation(&attestation2).expect("failed to insert");

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
            db.insert_attestation(&attestation).expect("failed to insert");
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
        db.insert_attestation(&attestation).expect("failed to insert");

        let result = db.is_safe_to_sign("0x1234", 101, 102);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_safe_to_sign_double_vote() {
        use super::super::error::AttestationSlashingViolation;

        let db = SlashingDb::open_in_memory().expect("failed to open db");

        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 100,
            target_epoch: 101,
            signing_root: None,
        };
        db.insert_attestation(&attestation).expect("failed to insert");

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
        use super::super::error::AttestationSlashingViolation;

        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=5, target=10
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 5,
            target_epoch: 10,
            signing_root: None,
        };
        db.insert_attestation(&attestation).expect("failed to insert");

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
        use super::super::error::AttestationSlashingViolation;

        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=4, target=11
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 4,
            target_epoch: 11,
            signing_root: None,
        };
        db.insert_attestation(&attestation).expect("failed to insert");

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
        db.insert_attestation(&attestation).expect("failed to insert");

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
            db.insert_attestation(a).expect("failed to insert");
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
        db.insert_attestation(&attestation).expect("failed to insert");

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
        db.insert_attestation(&attestation).expect("failed to insert");

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
        db.insert_attestation(&attestation).expect("failed to insert");

        // New: source=4, target=10 - same source, not surrounded (need existing_source < new_source)
        let result = db.is_safe_to_sign("0x1234", 4, 10);
        assert!(result.is_ok());

        // New: source=5, target=11 - same target (double vote)
        let result = db.is_safe_to_sign("0x1234", 5, 11);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_safe_to_sign_surrounding_vote_minimal() {
        use super::super::error::AttestationSlashingViolation;

        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=5, target=6
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 5,
            target_epoch: 6,
            signing_root: None,
        };
        db.insert_attestation(&attestation).expect("failed to insert");

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
        use super::super::error::AttestationSlashingViolation;

        let db = SlashingDb::open_in_memory().expect("failed to open db");

        // Existing: source=4, target=7
        let attestation = SignedAttestation {
            pubkey: "0x1234".to_string(),
            source_epoch: 4,
            target_epoch: 7,
            signing_root: None,
        };
        db.insert_attestation(&attestation).expect("failed to insert");

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
            db.insert_attestation(a).expect("failed to insert");
        }

        // New: source=4, target=21 - surrounds both
        let result = db.is_safe_to_sign("0x1234", 4, 21);
        assert!(result.is_err());
    }

    #[test]
    fn test_record_attestation_new() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, Some("0xabcd".to_string()))
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

        db.record_attestation("0x1234", 100, 101, None).expect("record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].signing_root.is_none());
    }

    #[test]
    fn test_record_attestation_idempotent_exact_duplicate() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, Some("0xabcd".to_string()))
            .expect("first record should succeed");

        db.record_attestation("0x1234", 100, 101, Some("0xabcd".to_string()))
            .expect("duplicate record should also succeed (idempotent)");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
    }

    #[test]
    fn test_record_attestation_idempotent_same_target_different_source() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, None).expect("first record should succeed");

        // Same pubkey and target_epoch but different source_epoch
        // Due to UNIQUE(pubkey, target_epoch), this should be ignored
        db.record_attestation("0x1234", 99, 101, None)
            .expect("duplicate target should succeed (idempotent)");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 1);
        // Original source_epoch should be preserved
        assert_eq!(attestations[0].source_epoch, 100);
    }

    #[test]
    fn test_record_attestation_multiple_different_targets() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1234", 100, 101, None).expect("first record should succeed");
        db.record_attestation("0x1234", 101, 102, None).expect("second record should succeed");
        db.record_attestation("0x1234", 102, 103, None).expect("third record should succeed");

        let attestations = db.get_attestations("0x1234").expect("failed to get");
        assert_eq!(attestations.len(), 3);
        assert_eq!(attestations[0].target_epoch, 101);
        assert_eq!(attestations[1].target_epoch, 102);
        assert_eq!(attestations[2].target_epoch, 103);
    }

    #[test]
    fn test_record_attestation_different_pubkeys() {
        let db = SlashingDb::open_in_memory().expect("failed to open db");

        db.record_attestation("0x1111", 100, 101, None).expect("record should succeed");
        db.record_attestation("0x2222", 100, 101, None).expect("record should succeed");

        let att1 = db.get_attestations("0x1111").expect("failed to get");
        let att2 = db.get_attestations("0x2222").expect("failed to get");

        assert_eq!(att1.len(), 1);
        assert_eq!(att2.len(), 1);
    }
}
