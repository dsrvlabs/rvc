//! SQLite database layer for slashing protection.

use std::path::Path;

use rusqlite::Connection;

use super::error::SlashingError;
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
}
