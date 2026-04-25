//! RAII guard types for the "stage / commit on success" ordering API.
//!
//! # Design rationale
//!
//! The [`StagedBlock`] and [`StagedAttestation`] guards implement the A15
//! architecture pattern: *check first, commit only on signer success*.  This
//! eliminates phantom rows — rows that were committed before the sign call
//! and then left in the database when the sign call fails.
//!
//! ## Lock-holding strategy
//!
//! `rusqlite::Transaction<'conn>` holds `&'conn Connection`.  Because
//! `Connection: !Sync`, the borrow prevents `Transaction` from being `Send`.
//! Storing both `MutexGuard<Connection>` and `Transaction` in the same struct
//! would require a self-referential layout (`Transaction` borrowing from data
//! owned by `MutexGuard`), which is unsound in safe Rust without a crate like
//! `ouroboros`.
//!
//! We therefore avoid holding a `Transaction` object in the guard struct at
//! all.  Instead, the guard holds just the `parking_lot::MutexGuard<'db,
//! Connection>` and manages the SQLite transaction explicitly via raw
//! `execute_batch` calls:
//!
//! - `stage_*` issues `BEGIN IMMEDIATE`, runs the violation check, and on
//!   success returns a guard that owns the mutex lock (keeping all other
//!   writers out) and the planned INSERT parameters.
//! - `commit` issues the `INSERT` then `COMMIT`, then drops the guard (releases
//!   the lock).
//! - `discard` issues `ROLLBACK` then drops the guard.
//! - `Drop` (without an explicit commit/discard) issues `ROLLBACK` then drops.
//!
//! ## Trade-off: holding the mutex across the signer call
//!
//! The mutex is held for the entire stage → (signer call) → commit window.
//! This means concurrent sign requests for *different* (pubkey, slot) pairs
//! from the same client are serialised behind this lock.  In practice this is
//! acceptable because:
//!
//! 1. The existing per-validator mutex in `crates/signer/src/lib.rs` already
//!    serialises signs for the same validator.
//! 2. The SQLite WAL writer lock is coarse-grained anyway; there is at most
//!    one writer at a time regardless.
//! 3. Signer calls are fast (sub-millisecond BLS on a local key, or bounded
//!    by the network timeout for a remote signer).
//!
//! Callers **should** bound the signer call's wall-clock budget (e.g. a
//! `tokio::time::timeout`) so a stalled signer does not hold the lock
//! indefinitely.
//!
//! ## `!Send` guarantee
//!
//! `parking_lot::MutexGuard<'_, Connection>` is `!Send` (it must be released
//! on the same thread that acquired it).  Therefore `StagedBlock<'_>` and
//! `StagedAttestation<'_>` are also `!Send`.  Do **not** hold a staged guard
//! across an `.await` point unless the entire future is pinned to a single
//! thread (e.g. via `spawn_blocking`).

use parking_lot::MutexGuard;
use rusqlite::{Connection, OptionalExtension};

use crate::error::{AttestationSlashingViolation, BlockSlashingViolation, SlashingError};
use crate::SlashingDb;
use crypto::logging::TruncatedPubkey;
use eth_types::{Epoch, Root, Slot};

use std::sync::atomic::Ordering;

/// Result of the EIP-3076 violation check for a staged block.
///
/// `Stage` means the row is new and `commit()` will run the INSERT.
/// `Resign` means the row already exists with an identical signing root, so
/// `commit()` skips the INSERT and just closes the transaction.
enum BlockStageOutcome {
    Stage,
    Resign,
}

// ── BlockRow ──────────────────────────────────────────────────────────────────

/// Parameters for the staged block INSERT — stored in the guard so `commit` can
/// execute the INSERT without re-running any business logic.
struct BlockRow {
    client_cn: String,
    pubkey: String,
    slot: Slot,
    signing_root: Option<String>,
    /// When `true` the row already exists in the DB (idempotent re-sign).
    /// `commit()` skips the INSERT and issues `COMMIT` to close the transaction.
    is_resign: bool,
}

// ── AttestationRow ────────────────────────────────────────────────────────────

/// Parameters for the staged attestation INSERT.
struct AttestationRow {
    client_cn: String,
    pubkey: String,
    source_epoch: Epoch,
    target_epoch: Epoch,
    signing_root: Option<String>,
    is_duplicate: bool,
}

// ── StagedBlock ───────────────────────────────────────────────────────────────

/// RAII guard returned by [`SlashingDb::stage_block`].
///
/// The guard holds the database mutex for the lifetime of the staged operation.
/// Call [`commit`](StagedBlock::commit) after a successful sign to persist the
/// row, or [`discard`](StagedBlock::discard) (or just drop the guard) to roll
/// back.
///
/// # Drop behaviour
///
/// Dropping this guard without calling `commit()` issues a `ROLLBACK` and
/// releases the mutex.  An error during `ROLLBACK` at drop time is logged but
/// not propagated (panicking in `Drop` is unsound).
///
/// # `!Send`
///
/// This type is `!Send` because `parking_lot::MutexGuard` must be released on
/// the same thread.  Do **not** hold it across an `.await` unless you are on a
/// single-threaded runtime or inside `spawn_blocking`.
pub struct StagedBlock<'db> {
    guard: Option<MutexGuard<'db, Connection>>,
    row: BlockRow,
    committed: bool,
}

impl std::fmt::Debug for StagedBlock<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedBlock")
            .field("pubkey", &self.row.pubkey)
            .field("slot", &self.row.slot)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl<'db> StagedBlock<'db> {
    /// Execute the staged INSERT and commit the transaction.
    ///
    /// For idempotent re-signs (the row already exists with the same signing
    /// root) the INSERT is skipped and only `COMMIT` is issued.
    ///
    /// Consumes the guard and releases the database mutex.
    pub fn commit(mut self) -> Result<(), SlashingError> {
        let guard = self.guard.as_mut().expect("guard is always Some before Drop");

        if !self.row.is_resign {
            guard.execute(
                "INSERT INTO blocks (client_cn, pubkey, slot, signing_root) VALUES (?1, ?2, ?3, ?4)",
                (&self.row.client_cn, &self.row.pubkey, self.row.slot as i64, &self.row.signing_root),
            )?;
        }

        guard.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    /// Roll back the staged transaction without committing.
    ///
    /// Equivalent to dropping the guard.  Prefer calling this explicitly so
    /// the intent is visible at the call site.
    pub fn discard(self) {
        // Drop fires the ROLLBACK.
    }
}

impl Drop for StagedBlock<'_> {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(guard) = self.guard.as_mut() {
                if let Err(e) = guard.execute_batch("ROLLBACK") {
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&self.row.pubkey),
                        slot = self.row.slot,
                        error = %e,
                        "StagedBlock::drop: ROLLBACK failed (transaction may already be finished)"
                    );
                }
            }
        }
    }
}

// ── StagedAttestation ─────────────────────────────────────────────────────────

/// RAII guard returned by [`SlashingDb::stage_attestation`].
///
/// See [`StagedBlock`] for full documentation of the semantics.
pub struct StagedAttestation<'db> {
    guard: Option<MutexGuard<'db, Connection>>,
    row: AttestationRow,
    committed: bool,
}

impl std::fmt::Debug for StagedAttestation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedAttestation")
            .field("pubkey", &self.row.pubkey)
            .field("source_epoch", &self.row.source_epoch)
            .field("target_epoch", &self.row.target_epoch)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl<'db> StagedAttestation<'db> {
    /// Execute the staged INSERT (if not a duplicate re-sign) and commit the
    /// transaction.
    pub fn commit(mut self) -> Result<(), SlashingError> {
        let guard = self.guard.as_mut().expect("guard is always Some before Drop");

        if !self.row.is_duplicate {
            guard.execute(
                "INSERT INTO attestations \
                 (client_cn, pubkey, source_epoch, target_epoch, signing_root) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    &self.row.client_cn,
                    &self.row.pubkey,
                    self.row.source_epoch as i64,
                    self.row.target_epoch as i64,
                    &self.row.signing_root,
                ),
            )?;
        }

        guard.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    /// Roll back the staged transaction without committing.
    pub fn discard(self) {
        // Drop fires the ROLLBACK.
    }
}

impl Drop for StagedAttestation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(guard) = self.guard.as_mut() {
                if let Err(e) = guard.execute_batch("ROLLBACK") {
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&self.row.pubkey),
                        source_epoch = self.row.source_epoch,
                        target_epoch = self.row.target_epoch,
                        error = %e,
                        "StagedAttestation::drop: ROLLBACK failed"
                    );
                }
            }
        }
    }
}

// ── SlashingDb staging methods ────────────────────────────────────────────────

impl SlashingDb {
    /// Begin an immediate transaction, run the EIP-3076 violation check for a
    /// block proposal, and return a [`StagedBlock`] guard.
    ///
    /// The guard holds the database mutex until it is consumed by
    /// [`commit`](StagedBlock::commit) or dropped (which rolls back).
    ///
    /// # Arguments
    /// - `client_cn`: Per-client namespace (e.g. `"local-vc"` for VC-side,
    ///   or the mTLS peer CN for DVT).
    /// - `pubkey_hex`: Validator public key as a hex string.
    /// - `slot`: Beacon chain slot being proposed.
    /// - `signing_root_hex`: Optional signing root.
    /// - `gvr`: Genesis validators root.  **Not yet enforced** (M-6 / ISSUE-3.5);
    ///   accepted for API consistency.
    ///
    /// # Errors
    /// Returns `SlashingError::SlashableBlock` (specifically
    /// `BlockSlashingViolation::DoubleBlockProposal`) if a different signing
    /// root has already been committed for `(client_cn, pubkey, slot)`.
    ///
    /// # Trade-off: mutex held across signer call
    ///
    /// The returned guard holds the internal `Connection` mutex for its entire
    /// lifetime.  See the [module-level documentation](crate::stage) for a
    /// full analysis.  Callers should bound the signer call's wall-clock budget.
    pub fn stage_block<'db>(
        &'db self,
        client_cn: &str,
        pubkey_hex: &str,
        slot: Slot,
        signing_root_hex: Option<String>,
        _gvr: &Root,
    ) -> Result<StagedBlock<'db>, SlashingError> {
        let pubkey = crate::db::normalize_pubkey(pubkey_hex);
        let guard = self.conn.lock();

        guard.execute_batch("BEGIN IMMEDIATE")?;

        let strict = self.strict_semantics.load(Ordering::Relaxed);
        // Run violation checks inside a closure so any error — whether a SQL
        // I/O error from `?`-propagation or an EIP-3076 violation — funnels
        // through a single ROLLBACK before we return. Without this wrapper a
        // SQL error between `BEGIN IMMEDIATE` and the guard transfer would
        // drop the MutexGuard with the transaction still open, leaving the
        // connection in a broken "transaction within transaction" state.
        let outcome = (|| -> Result<BlockStageOutcome, SlashingError> {
            let watermark: Option<i64> = guard
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

            let existing: Option<Option<String>> = guard
                .query_row(
                    "SELECT signing_root FROM blocks \
                     WHERE client_cn = ?1 AND pubkey = ?2 AND slot = ?3",
                    (client_cn, &pubkey, slot as i64),
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(existing_root) = existing {
                let is_resign = match (&existing_root, &signing_root_hex) {
                    (Some(er), Some(nr)) if er == nr => true,
                    (None, None) if !strict => true,
                    _ => false,
                };
                if !is_resign {
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&pubkey),
                        slot,
                        rejection_reason = "double_block_proposal",
                        "stage_block rejected"
                    );
                    return Err(BlockSlashingViolation::DoubleBlockProposal { slot }.into());
                }
                return Ok(BlockStageOutcome::Resign);
            }

            let min_slot: Option<i64> = guard
                .query_row(
                    "SELECT MIN(slot) FROM blocks WHERE client_cn = ?1 AND pubkey = ?2",
                    (client_cn, &pubkey),
                    |row| row.get(0),
                )
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

            Ok(BlockStageOutcome::Stage)
        })();

        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                return Err(e);
            }
        };

        // Same signing root on a Resign — keep the transaction open and let
        // `commit()` skip the INSERT but still close the transaction. A
        // `discard()` or bare drop issues `ROLLBACK`, which is harmless on
        // a read-only transaction.
        Ok(StagedBlock {
            guard: Some(guard),
            row: BlockRow {
                client_cn: client_cn.to_owned(),
                pubkey,
                slot,
                signing_root: signing_root_hex,
                is_resign: matches!(outcome, BlockStageOutcome::Resign),
            },
            committed: false,
        })
    }

    /// Begin an immediate transaction, run the EIP-3076 violation check for an
    /// attestation, and return a [`StagedAttestation`] guard.
    ///
    /// See [`stage_block`](SlashingDb::stage_block) for the general contract.
    ///
    /// # Errors
    /// Returns `SlashingError::SlashableAttestation` (double vote, surrounding,
    /// or surrounded) if the new `(source, target)` pair conflicts with any
    /// existing attestation in `(client_cn, pubkey)` scope.
    pub fn stage_attestation<'db>(
        &'db self,
        client_cn: &str,
        pubkey_hex: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root_hex: Option<String>,
        _gvr: &Root,
    ) -> Result<StagedAttestation<'db>, SlashingError> {
        let pubkey = crate::db::normalize_pubkey(pubkey_hex);
        let guard = self.conn.lock();

        guard.execute_batch("BEGIN IMMEDIATE")?;

        let strict = self.strict_semantics.load(Ordering::Relaxed);
        // Wrap the violation-check phase so any error — SQL I/O or EIP-3076 —
        // funnels through a single ROLLBACK before we return.  See the
        // matching note in `stage_block`.
        let outcome = (|| -> Result<bool, SlashingError> {
            let wm_source: Option<i64> = guard
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

            let wm_target: Option<i64> = guard
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

            let existing: Vec<(Epoch, Epoch, Option<String>)> = {
                let mut stmt = guard.prepare(
                    "SELECT source_epoch, target_epoch, signing_root \
                     FROM attestations \
                     WHERE client_cn = ?1 AND pubkey = ?2",
                )?;
                let rows = stmt
                    .query_map((client_cn, &pubkey), |row| {
                        Ok((
                            row.get::<_, i64>(0)? as Epoch,
                            row.get::<_, i64>(1)? as Epoch,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };

            let mut is_duplicate = false;

            for (existing_source, existing_target, existing_root) in &existing {
                if target_epoch == *existing_target {
                    match (existing_root, &signing_root_hex) {
                        (Some(er), Some(nr)) if er == nr => {
                            if source_epoch != *existing_source {
                                tracing::warn!(
                                    pubkey,
                                    target_epoch,
                                    existing_source = *existing_source,
                                    new_source = source_epoch,
                                    "stage_attestation: same signing root but different source epoch"
                                );
                            }
                            is_duplicate = true;
                            continue;
                        }
                        (None, None) if !strict => {
                            is_duplicate = true;
                            continue;
                        }
                        _ => {
                            tracing::error!(
                                pubkey = %TruncatedPubkey::new(&pubkey),
                                source_epoch,
                                target_epoch,
                                rejection_reason = "double_vote",
                                "stage_attestation rejected"
                            );
                            return Err(
                                AttestationSlashingViolation::DoubleVote { target_epoch }.into()
                            );
                        }
                    }
                }

                if source_epoch < *existing_source && target_epoch > *existing_target {
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&pubkey),
                        source_epoch,
                        target_epoch,
                        rejection_reason = "surrounding_vote",
                        "stage_attestation rejected"
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
                    tracing::error!(
                        pubkey = %TruncatedPubkey::new(&pubkey),
                        source_epoch,
                        target_epoch,
                        rejection_reason = "surrounded_vote",
                        "stage_attestation rejected"
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
                let min_target = existing.iter().map(|(_, t, _)| *t).min();
                if let Some(min) = min_target {
                    if target_epoch < min {
                        return Err(AttestationSlashingViolation::TargetEpochBelowMinimum {
                            target_epoch,
                            min_target: min,
                        }
                        .into());
                    }
                }
            }

            Ok(is_duplicate)
        })();

        let is_duplicate = match outcome {
            Ok(d) => d,
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                return Err(e);
            }
        };

        Ok(StagedAttestation {
            guard: Some(guard),
            row: AttestationRow {
                client_cn: client_cn.to_owned(),
                pubkey,
                source_epoch,
                target_epoch,
                signing_root: signing_root_hex,
                is_duplicate,
            },
            committed: false,
        })
    }
}
